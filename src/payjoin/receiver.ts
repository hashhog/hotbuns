/**
 * BIP-78 PayJoin receiver (FIX-65).
 *
 * Implements the receiver side of the PayJoin protocol:
 *
 *   1. Sender POSTs the base64-encoded Original PSBT to /payjoin?v=1.
 *   2. Receiver parses + validates (finalized, funded, single version=1).
 *   3. Receiver picks one of its own UTXOs of the same script type as the
 *      sender's output (anti-snoop, BIP-78 §C.1).
 *   4. Receiver builds a NEW transaction:
 *        - all of the sender's inputs + 1 receiver input
 *        - receiver's output increased by (input_value - fee_share)
 *      and converts it to PSBT with the SENDER's existing scriptSigs /
 *      witnesses preserved (the Original is already finalized).
 *   5. Receiver signs only the receiver-added input (P2WPKH).
 *   6. Receiver returns the new base64-encoded PSBT with
 *      Content-Type: text/plain (per BIP-78).
 *
 * BIP-78 §G error map:
 *   - "unavailable"           — receiver not ready / no spendable UTXOs.
 *   - "not-enough-money"      — UTXO probe failed (e.g. all UTXOs too small).
 *   - "version-unsupported"   — query param v != 1.
 *   - "original-psbt-rejected" — any validation failure (bad PSBT, unfinalized,
 *                               output doesn't match receiver, etc).
 *
 * The receiver-side anti-replay window is a parallel Map to wallet's
 * outgoingTxs (added in FIX-61): pendingPayJoinRequests keyed by Original
 * PSBT hash (sha256 over the serialized PSBT bytes), with a TTL set when
 * the request first lands. Subsequent POSTs of the same Original PSBT
 * within the TTL are rejected with "original-psbt-rejected".
 *
 * Reference: https://github.com/bitcoin/bips/blob/master/bip-0078.mediawiki
 */

import { Wallet, type WalletUTXO, BIP125_RBF_SEQUENCE } from "../wallet/wallet.js";
import { AddressType, encodeAddress } from "../address/encoding.js";
import {
  type PSBT,
  type PSBTInput,
  encodePSBTBase64,
  decodePSBTBase64,
  createPSBT,
  isInputFinalized,
} from "../wallet/psbt.js";
import {
  type Transaction,
  type TxIn,
  type TxOut,
  sigHashWitnessV0,
  SIGHASH_ALL,
} from "../validation/tx.js";
import {
  hash160,
  sha256Hash,
  ecdsaSign,
} from "../crypto/primitives.js";

// ---------------------------------------------------------------------------
// BIP-78 error codes (BIP-78 §G).
// ---------------------------------------------------------------------------

export const PAYJOIN_ERROR_UNAVAILABLE = "unavailable" as const;
export const PAYJOIN_ERROR_NOT_ENOUGH_MONEY = "not-enough-money" as const;
export const PAYJOIN_ERROR_VERSION_UNSUPPORTED = "version-unsupported" as const;
export const PAYJOIN_ERROR_ORIGINAL_PSBT_REJECTED = "original-psbt-rejected" as const;

export type PayJoinErrorCode =
  | typeof PAYJOIN_ERROR_UNAVAILABLE
  | typeof PAYJOIN_ERROR_NOT_ENOUGH_MONEY
  | typeof PAYJOIN_ERROR_VERSION_UNSUPPORTED
  | typeof PAYJOIN_ERROR_ORIGINAL_PSBT_REJECTED;

/**
 * Typed error class produced by the receiver pipeline. Carries one of the
 * four canonical BIP-78 §G strings + a human-readable detail message. The
 * HTTP handler maps {@link errorCode} to BIP-78's JSON body shape:
 *   { "errorCode": "<code>", "message": "<detail>" }
 */
export class PayJoinError extends Error {
  readonly errorCode: PayJoinErrorCode;
  constructor(errorCode: PayJoinErrorCode, message: string) {
    super(message);
    this.name = "PayJoinError";
    this.errorCode = errorCode;
  }
}

// ---------------------------------------------------------------------------
// Pending request map (G18 TTL / G30 replay).
//
// Parallel to FIX-61 wallet.outgoingTxs (Map<txid, OutgoingTx>) but in the
// OPPOSITE direction: the receiver tracks Original PSBTs it has SEEN, keyed
// by sha256(serialized PSBT bytes). The key is the canonical Original PSBT
// hash so two POSTs of the same bytes collide regardless of base64
// whitespace / line-break differences (HTTP intermediaries are allowed to
// re-wrap base64).
// ---------------------------------------------------------------------------

/**
 * Default time-to-live for a pending PayJoin request (60 seconds).
 *
 * BIP-78 §F.1 does not mandate a specific window, but the ecosystem
 * (payjoin-cli, BTCPay Server) converges on ~60s to bound the
 * timing-correlation surface a snooping sender can probe.
 */
export const PAYJOIN_REQUEST_TTL_MS = 60_000;

export interface PendingPayJoinRequest {
  /** sha256 of the serialized Original PSBT bytes (hex). */
  originalPsbtHash: string;
  /** Original PSBT (parsed). Retained for G19 — receiver never broadcasts. */
  originalPsbt: PSBT;
  /** Outpoints (txid:vout, hex) of the sender's already-claimed UTXOs. */
  senderOutpoints: Set<string>;
  /** Unix ms when the request first arrived. */
  receivedAtMs: number;
  /** Unix ms after which the entry is considered expired. */
  expiresAtMs: number;
}

/**
 * In-memory map of pending PayJoin requests keyed by Original PSBT hash.
 * Used for G18 (TTL replay window) and G30 (input-reuse detection).
 *
 * Construct via {@link createPendingPayJoinRequestsMap}() — the function
 * shape (rather than module-level singleton) lets each Wallet / RPC server
 * pair have its own isolated map and lets tests instantiate fresh state.
 */
export type PendingPayJoinRequestsMap = Map<string, PendingPayJoinRequest>;

export function createPendingPayJoinRequestsMap(): PendingPayJoinRequestsMap {
  return new Map();
}

/**
 * Remove expired entries from the map. Called opportunistically at the top
 * of each request — cheap (Map iteration over a small in-memory set).
 *
 * @param now caller-supplied wall-clock (ms); injectable for tests.
 */
export function prunePendingPayJoinRequests(
  pending: PendingPayJoinRequestsMap,
  now: number = Date.now()
): void {
  for (const [hash, entry] of pending) {
    if (entry.expiresAtMs <= now) {
      pending.delete(hash);
    }
  }
}

// ---------------------------------------------------------------------------
// Request handling.
// ---------------------------------------------------------------------------

/**
 * Parsed BIP-78 query parameters. All optional except `v`.
 *
 * BIP-78 §D, case-insensitive keys:
 *   v                            (required, integer, currently 1)
 *   additionalfeeoutputindex     (optional)
 *   maxadditionalfeecontribution (optional, sat)
 *   disableoutputsubstitution    (optional, bool, default false)
 *   minfeerate                   (optional, decimal sat/vB)
 */
export interface PayJoinQueryParams {
  v: number;
  additionalFeeOutputIndex?: number;
  maxAdditionalFeeContribution?: bigint;
  disableOutputSubstitution?: boolean;
  minFeeRate?: number;
}

/**
 * Parse BIP-78 query string. Throws {@link PayJoinError} with code
 * "version-unsupported" if v != 1 (BIP-78 §G mandates this distinct from
 * other rejection reasons so the sender can decide whether to retry).
 *
 * All other malformed params yield "original-psbt-rejected".
 */
export function parsePayJoinQuery(query: URLSearchParams): PayJoinQueryParams {
  // BIP-78 query keys are documented as lower-case but real clients are
  // case-insensitive (e.g. payjoin-cli accepts V=1). Build a folded view
  // first to avoid 5 manual key probes.
  const folded = new Map<string, string>();
  for (const [k, v] of query.entries()) {
    folded.set(k.toLowerCase(), v);
  }

  const vRaw = folded.get("v");
  if (vRaw === undefined) {
    throw new PayJoinError(
      PAYJOIN_ERROR_ORIGINAL_PSBT_REJECTED,
      "missing required query parameter: v"
    );
  }
  // Spec is integer. Any non-int (e.g. "1.0", "0x1", "true") is rejected,
  // not silently coerced — Core's lexer is strict and so is BTCPay.
  if (!/^\d+$/.test(vRaw)) {
    throw new PayJoinError(
      PAYJOIN_ERROR_VERSION_UNSUPPORTED,
      `invalid v parameter: '${vRaw}'`
    );
  }
  const v = Number(vRaw);
  if (v !== 1) {
    throw new PayJoinError(
      PAYJOIN_ERROR_VERSION_UNSUPPORTED,
      `unsupported PayJoin version: ${v} (this receiver supports v=1 only)`
    );
  }

  const out: PayJoinQueryParams = { v };

  const afoiRaw = folded.get("additionalfeeoutputindex");
  if (afoiRaw !== undefined) {
    if (!/^\d+$/.test(afoiRaw)) {
      throw new PayJoinError(
        PAYJOIN_ERROR_ORIGINAL_PSBT_REJECTED,
        `invalid additionalfeeoutputindex: '${afoiRaw}'`
      );
    }
    out.additionalFeeOutputIndex = Number(afoiRaw);
  }

  const mafcRaw = folded.get("maxadditionalfeecontribution");
  if (mafcRaw !== undefined) {
    if (!/^\d+$/.test(mafcRaw)) {
      throw new PayJoinError(
        PAYJOIN_ERROR_ORIGINAL_PSBT_REJECTED,
        `invalid maxadditionalfeecontribution: '${mafcRaw}'`
      );
    }
    out.maxAdditionalFeeContribution = BigInt(mafcRaw);
  }

  const dosRaw = folded.get("disableoutputsubstitution");
  if (dosRaw !== undefined) {
    if (dosRaw !== "true" && dosRaw !== "false") {
      throw new PayJoinError(
        PAYJOIN_ERROR_ORIGINAL_PSBT_REJECTED,
        `invalid disableoutputsubstitution: '${dosRaw}' (must be 'true' or 'false')`
      );
    }
    out.disableOutputSubstitution = dosRaw === "true";
  }

  const mfrRaw = folded.get("minfeerate");
  if (mfrRaw !== undefined) {
    // Decimal sat/vB; the strict /^\d+(\.\d+)?$/ rejects "1e3" / negatives.
    if (!/^\d+(\.\d+)?$/.test(mfrRaw)) {
      throw new PayJoinError(
        PAYJOIN_ERROR_ORIGINAL_PSBT_REJECTED,
        `invalid minfeerate: '${mfrRaw}'`
      );
    }
    out.minFeeRate = Number(mfrRaw);
  }

  return out;
}

// ---------------------------------------------------------------------------
// Per-request hash key (G30 replay protection).
// ---------------------------------------------------------------------------

/**
 * Canonical hash of an Original PSBT. Uses sha256 over the binary
 * serialization (NOT base64) so that re-wrapped base64 collides.
 */
export function originalPsbtHashHex(originalPsbtBytes: Buffer): string {
  return sha256Hash(originalPsbtBytes).toString("hex");
}

// ---------------------------------------------------------------------------
// Original PSBT validation.
// ---------------------------------------------------------------------------

/**
 * Validate that the Original PSBT is "fit for receiver augmentation" per
 * BIP-78 §F.1:
 *   - At least one input.
 *   - Every input is FINALIZED (sender already signed everything).
 *   - At least one output whose scriptPubKey we recognize as belonging to
 *     this receiver (otherwise the sender pointed at the wrong endpoint).
 *
 * Throws {@link PayJoinError} on any failure.
 */
export function validateOriginalPsbt(
  psbt: PSBT,
  wallet: Wallet
): { receiverOutputIndex: number; receiverOutput: TxOut } {
  if (psbt.inputs.length === 0) {
    throw new PayJoinError(
      PAYJOIN_ERROR_ORIGINAL_PSBT_REJECTED,
      "Original PSBT has zero inputs"
    );
  }
  if (psbt.outputs.length === 0) {
    throw new PayJoinError(
      PAYJOIN_ERROR_ORIGINAL_PSBT_REJECTED,
      "Original PSBT has zero outputs"
    );
  }

  // Every input MUST be finalized — BIP-78 §F.1 calls this out explicitly.
  for (let i = 0; i < psbt.inputs.length; i++) {
    if (!isInputFinalized(psbt.inputs[i])) {
      throw new PayJoinError(
        PAYJOIN_ERROR_ORIGINAL_PSBT_REJECTED,
        `Original PSBT input ${i} is not finalized`
      );
    }
  }

  // Find the output that pays one of our addresses. We do this by extracting
  // the address from each output's scriptPubKey and checking against the
  // wallet's known keys. Receiver-side PayJoin only works if exactly one
  // output pays us — otherwise we can't disambiguate which to bump.
  let receiverOutputIndex = -1;
  for (let i = 0; i < psbt.tx.outputs.length; i++) {
    const output = psbt.tx.outputs[i];
    const addr = scriptPubKeyToWalletAddress(output.scriptPubKey, wallet);
    if (addr !== null) {
      if (receiverOutputIndex !== -1) {
        // Two of our outputs in one tx → ambiguous. Treat as rejection so
        // the sender re-builds rather than us picking the wrong one.
        throw new PayJoinError(
          PAYJOIN_ERROR_ORIGINAL_PSBT_REJECTED,
          "Original PSBT has multiple outputs paying this receiver"
        );
      }
      receiverOutputIndex = i;
    }
  }
  if (receiverOutputIndex === -1) {
    throw new PayJoinError(
      PAYJOIN_ERROR_ORIGINAL_PSBT_REJECTED,
      "Original PSBT does not pay this receiver"
    );
  }

  return {
    receiverOutputIndex,
    receiverOutput: psbt.tx.outputs[receiverOutputIndex],
  };
}

/**
 * Best-effort scriptPubKey → "is this owned by the receiver wallet?" check.
 * Iterates the wallet's key set (small — capped by the BIP-32 gap limit) and
 * compares each key's hash160(publicKey) against the script's payload bytes.
 *
 * Returns the matching wallet address, or null if no key in the wallet hashes
 * to this script. Only handles the script types this wallet generates.
 */
function scriptPubKeyToWalletAddress(spk: Buffer, wallet: Wallet): string | null {
  // Identify the script type + payload hash slot to compare against.
  let scriptHash: Buffer | null = null;
  let targetType: AddressType | null = null;

  // P2WPKH: OP_0 <20 bytes>
  if (spk.length === 22 && spk[0] === 0x00 && spk[1] === 0x14) {
    scriptHash = spk.subarray(2, 22);
    targetType = AddressType.P2WPKH;
  }
  // P2PKH: OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG
  else if (
    spk.length === 25 &&
    spk[0] === 0x76 &&
    spk[1] === 0xa9 &&
    spk[2] === 0x14 &&
    spk[23] === 0x88 &&
    spk[24] === 0xac
  ) {
    scriptHash = spk.subarray(3, 23);
    targetType = AddressType.P2PKH;
  }
  // P2TR: OP_1 <32 bytes>
  else if (spk.length === 34 && spk[0] === 0x51 && spk[1] === 0x20) {
    scriptHash = spk.subarray(2, 34);
    targetType = AddressType.P2TR;
  }
  if (scriptHash === null || targetType === null) return null;

  // Walk wallet keys. For P2WPKH/P2PKH compare against hash160(pubkey);
  // for P2TR the key.address itself is the canonical identifier (Taproot
  // x-only key tweak is non-trivial; we lean on the address string match).
  for (const key of wallet.listAddresses()) {
    if (key.addressType !== targetType) continue;
    if (targetType === AddressType.P2TR) {
      // Re-emit the address from the script via encodeAddress and compare,
      // which handles BIP-341 x-only encoding without re-implementing the
      // tweak math in this module.
      const fabricated = encodeAddress({
        type: AddressType.P2TR,
        hash: scriptHash,
        network: walletNetwork(wallet),
      });
      if (fabricated === key.address) return key.address;
      continue;
    }
    const pkh = hash160(key.publicKey);
    if (pkh.equals(scriptHash)) return key.address;
  }
  return null;
}

/**
 * Read the wallet's network without breaking encapsulation by reaching into
 * a private field. We can derive it deterministically from any existing
 * wallet address (mainnet bech32 hrp = "bc" / base58 versions 0x00 / 0x05;
 * testnet "tb" / 0x6f / 0xc4; regtest "bcrt"). Failing that, default to
 * mainnet — wrong network never matches a real P2PKH/P2WPKH anyway.
 */
function walletNetwork(wallet: Wallet): "mainnet" | "testnet" | "regtest" {
  const addrs = wallet.listAddresses();
  if (addrs.length === 0) return "mainnet";
  const a = addrs[0].address;
  if (a.startsWith("bcrt1")) return "regtest";
  if (a.startsWith("tb1") || a.startsWith("m") || a.startsWith("n") || a.startsWith("2")) {
    return "testnet";
  }
  return "mainnet";
}

// ---------------------------------------------------------------------------
// Receiver flow.
// ---------------------------------------------------------------------------

export interface PayJoinReceiverDeps {
  wallet: Wallet;
  pending: PendingPayJoinRequestsMap;
  /** Wall clock (ms). Defaulted to {@link Date.now} for production; injectable for tests. */
  now?: () => number;
  /** TTL window for pending request map (ms). Defaults to {@link PAYJOIN_REQUEST_TTL_MS}. */
  ttlMs?: number;
}

export interface PayJoinReceiverResult {
  /** Base64-encoded payjoin PSBT to return to the sender. */
  base64Psbt: string;
  /** sha256 of the Original PSBT (hex) — same key used in pending map. */
  originalPsbtHash: string;
  /** PSBT with the receiver-added input + bumped output. */
  payjoinPsbt: PSBT;
}

/**
 * Pure logic for handling a PayJoin POST. Separated from the HTTP layer so
 * that tests can drive the receiver without spinning up Bun.serve.
 *
 * Flow (BIP-78 §F):
 *   1. Parse and validate the query string (v=1).
 *   2. Deserialize the Original PSBT.
 *   3. Compute Original PSBT hash; replay-check the pending map.
 *   4. Validate Original PSBT (finalized, pays us, has inputs/outputs).
 *   5. Detect G30 replay by checking input outpoints against previous entries.
 *   6. Pick a wallet UTXO to contribute (anti-snoop: prefer same script type
 *      as the receiver output).
 *   7. Build the modified tx: sender's inputs + receiver input, sender's
 *      outputs with receiver-output bumped by (utxo.amount - feeShare).
 *   8. Convert to PSBT, preserving sender's finalScriptSig/Witness from
 *      Original. Sign only the receiver-added input.
 *   9. Register in pending map with TTL.
 */
export async function handlePayJoinRequest(
  originalPsbtBase64: string,
  query: PayJoinQueryParams,
  deps: PayJoinReceiverDeps
): Promise<PayJoinReceiverResult> {
  const now = (deps.now ?? Date.now)();
  const ttl = deps.ttlMs ?? PAYJOIN_REQUEST_TTL_MS;

  // Opportunistic prune. Cheap; bounded by recent request volume.
  prunePendingPayJoinRequests(deps.pending, now);

  // 1. Parse the Original PSBT.
  let originalPsbt: PSBT;
  let originalPsbtBytes: Buffer;
  try {
    // decodePSBTBase64 takes the base64 string and re-emits the byte buffer
    // as part of its parse step; we need both so we serialize the parsed
    // PSBT back ourselves to get the canonical bytes.
    originalPsbt = decodePSBTBase64(originalPsbtBase64);
    originalPsbtBytes = Buffer.from(originalPsbtBase64.trim(), "base64");
  } catch (err) {
    throw new PayJoinError(
      PAYJOIN_ERROR_ORIGINAL_PSBT_REJECTED,
      `failed to decode Original PSBT: ${(err as Error).message}`
    );
  }

  const psbtHash = originalPsbtHashHex(originalPsbtBytes);

  // 2. Validate Original PSBT.
  const { receiverOutputIndex, receiverOutput } = validateOriginalPsbt(
    originalPsbt,
    deps.wallet
  );

  // 3. G18 / G30 replay check.
  const existing = deps.pending.get(psbtHash);
  if (existing) {
    throw new PayJoinError(
      PAYJOIN_ERROR_ORIGINAL_PSBT_REJECTED,
      `Original PSBT already submitted (received ${now - existing.receivedAtMs}ms ago)`
    );
  }
  // Also reject if ANY of the Original's inputs collide with the input set
  // of a previously-seen request — that's a sender trying to vary one byte
  // to dodge the hash key.
  const senderOutpoints = new Set<string>();
  for (const input of originalPsbt.tx.inputs) {
    senderOutpoints.add(
      `${input.prevOut.txid.toString("hex")}:${input.prevOut.vout}`
    );
  }
  for (const e of deps.pending.values()) {
    for (const op of senderOutpoints) {
      if (e.senderOutpoints.has(op)) {
        throw new PayJoinError(
          PAYJOIN_ERROR_ORIGINAL_PSBT_REJECTED,
          `Original PSBT reuses outpoint ${op} from prior request`
        );
      }
    }
  }

  // 4. Pick a wallet UTXO. Prefer same script type as receiver output for
  //    anti-snoop; fall back to whatever's biggest if no same-type UTXO.
  const receiverAddressType = inferAddressTypeFromScript(receiverOutput.scriptPubKey);
  const candidate = pickReceiverUtxo(deps.wallet, receiverAddressType);
  if (!candidate) {
    throw new PayJoinError(
      PAYJOIN_ERROR_NOT_ENOUGH_MONEY,
      "no spendable UTXOs available for PayJoin contribution"
    );
  }

  // 5. Build the modified transaction.
  //    BIP-78 §F.3 says receiver "increases its own output by the input
  //    value minus its fee share". The "fee share" is what the receiver
  //    extracts to cover the cost of its extra input. Two policies are
  //    implemented based on sender's BIP-78 §D query params:
  //
  //    (a) Sender provided BOTH `additionalfeeoutputindex` (G6) AND
  //        `maxadditionalfeecontribution` (G9): receiver MAY shave up
  //        to `maxAdditionalFeeContribution` sats off the indicated
  //        sender output to cover its added-input vbyte cost. The
  //        receiver-output is bumped by (utxo_amount + fee_share_extracted).
  //        Equivalently: net fee delta to sender == feeShareExtracted ≤ cap.
  //
  //    (b) Otherwise (sender omitted either param): receiver does NOT
  //        extract a fee share — full UTXO value goes into the receiver
  //        output, sender keeps the same fee they originally allocated.
  //        This is the conservative default and trivially satisfies G9.
  //
  //    G8 (output substitution / pjos): the receiver only modifies its
  //    OWN output (bumping it by the contribution) and, optionally, the
  //    `additionalfeeoutputindex`-pointed sender output (reducing it by
  //    the fee share). When the sender set `disableOutputSubstitution=true`
  //    (pjos=0), the receiver MUST NOT reduce ANY sender output — so the
  //    fee-share extraction is forbidden in that case and the receiver
  //    falls back to policy (b) above.
  //
  //    G15 (minfeerate floor): if sender supplied minfeerate, the receiver
  //    MUST ensure the response tx's effective fee rate is ≥ that floor.
  //    Since policy (b) keeps the original fee unchanged AND adds a single
  //    input (~68 vB more), the effective rate DROPS. We compute the
  //    post-bump rate using the same vsize formula the sender uses
  //    (sender.ts validateMinFeeRate) and reject with NOT_ENOUGH_MONEY
  //    if it falls below the floor.

  // G6 + G9 fee-share extraction policy.
  let feeShareExtracted = 0n;
  if (
    query.additionalFeeOutputIndex !== undefined &&
    query.maxAdditionalFeeContribution !== undefined &&
    query.maxAdditionalFeeContribution > 0n &&
    !query.disableOutputSubstitution
  ) {
    const afoi = query.additionalFeeOutputIndex;
    if (
      afoi < 0 ||
      afoi >= originalPsbt.tx.outputs.length ||
      afoi === receiverOutputIndex
    ) {
      // Sender pointed at a nonexistent output OR at the receiver-owned
      // output. Both are invalid per BIP-78 §F.2 (the fee output must be
      // sender-owned). Reject so the sender re-builds rather than us
      // silently picking a wrong policy.
      throw new PayJoinError(
        PAYJOIN_ERROR_ORIGINAL_PSBT_REJECTED,
        `additionalfeeoutputindex=${afoi} is invalid (must point at a sender output)`
      );
    }
    // Cap the share at the cap AND at what the targeted output can spare
    // without going below dust (we use 546 sats as the universal dust
    // floor; BIP-78 doesn't specify but ecosystem clients converge here).
    const DUST = 546n;
    const targetOutput = originalPsbt.tx.outputs[afoi];
    const spareInTarget =
      targetOutput.value > DUST ? targetOutput.value - DUST : 0n;
    const cap = query.maxAdditionalFeeContribution;
    feeShareExtracted = spareInTarget < cap ? spareInTarget : cap;
  }

  const newInputs: TxIn[] = [
    ...originalPsbt.tx.inputs.map((i) => ({
      prevOut: { txid: Buffer.from(i.prevOut.txid), vout: i.prevOut.vout },
      // KEEP sender's signed scriptSig + witness (Original is finalized).
      scriptSig: Buffer.from(i.scriptSig),
      sequence: i.sequence,
      witness: i.witness.map((w) => Buffer.from(w)),
    })),
    {
      prevOut: {
        txid: Buffer.from(candidate.outpoint.txid),
        vout: candidate.outpoint.vout,
      },
      scriptSig: Buffer.alloc(0),
      // BIP-125 RBF on receiver input too — match sender's signaling rather
      // than disable it (a non-RBF receiver input would override sender's
      // RBF intent for the whole tx).
      sequence: BIP125_RBF_SEQUENCE,
      witness: [],
    },
  ];

  const newOutputs: TxOut[] = originalPsbt.tx.outputs.map((o, idx) => {
    if (idx === receiverOutputIndex) {
      // Receiver-owned output: bump by (full UTXO contribution + fee share).
      // The fee share is added back here so that
      //   (extra input value)
      //   minus (fee share moved into the fee bucket via reducing sender output)
      // ends up flowing into the receiver-owned output by the right amount.
      // Actually the simpler accounting is:
      //   Σ inputs delta  =  +candidate.amount
      //   Σ outputs delta =  +candidate.amount  (receiver-output bump)
      //                   +  -feeShareExtracted (sender fee-output reduction)
      //   ⇒ fee delta     =  +feeShareExtracted  (the extra fee bucket)
      // So the receiver-output is bumped by exactly candidate.amount (NOT
      // candidate.amount + feeShareExtracted) — the fee share comes from
      // the SENDER output, not from the receiver bump.
      return {
        value: o.value + candidate.amount,
        scriptPubKey: Buffer.from(o.scriptPubKey),
      };
    }
    if (idx === query.additionalFeeOutputIndex && feeShareExtracted > 0n) {
      // G6: reduce sender-indicated fee output by the extracted share.
      return {
        value: o.value - feeShareExtracted,
        scriptPubKey: Buffer.from(o.scriptPubKey),
      };
    }
    return { value: o.value, scriptPubKey: Buffer.from(o.scriptPubKey) };
  });

  const newTx: Transaction = {
    version: originalPsbt.tx.version,
    inputs: newInputs,
    outputs: newOutputs,
    lockTime: originalPsbt.tx.lockTime,
  };

  // G15 receiver-side minfeerate floor.
  //
  // BIP-78 §F: if sender supplied `minfeerate`, the receiver SHOULD only
  // return a tx whose effective fee rate is ≥ that floor. We compute the
  // post-bump fee rate using the same vsize formula sender.ts uses
  // (validateMinFeeRate); a stricter cross-impl might also include the
  // receiver-input's witness weight, but a single 68 vB segwit input
  // estimate keeps the two sides in lockstep.
  if (query.minFeeRate !== undefined) {
    let origInputTotal = 0n;
    let canCompute = true;
    for (const psbtIn of originalPsbt.inputs) {
      if (!psbtIn.witnessUtxo) { canCompute = false; break; }
      origInputTotal += psbtIn.witnessUtxo.value;
    }
    if (canCompute) {
      const inputTotal = origInputTotal + candidate.amount;
      let outputTotal = 0n;
      for (const o of newOutputs) outputTotal += o.value;
      const fee = inputTotal - outputTotal;
      if (fee < 0n) {
        throw new PayJoinError(
          PAYJOIN_ERROR_ORIGINAL_PSBT_REJECTED,
          `payjoin tx would have negative fee (${fee})`
        );
      }
      const vsize =
        10 + 68 * newInputs.length + 31 * newOutputs.length;
      const rate = Number(fee) / vsize;
      if (rate < query.minFeeRate) {
        throw new PayJoinError(
          PAYJOIN_ERROR_NOT_ENOUGH_MONEY,
          `payjoin effective fee rate ${rate.toFixed(3)} sat/vB < minfeerate ${query.minFeeRate}`
        );
      }
    }
  }

  // 6. Sign only the receiver-added input (last index). For this minimal
  //    receiver we only handle P2WPKH UTXOs; the wallet's main
  //    createTransaction code path uses the same constraint everywhere
  //    BIP-84 is in play.
  const receiverInputIndex = newInputs.length - 1;
  if (candidate.addressType !== AddressType.P2WPKH) {
    throw new PayJoinError(
      PAYJOIN_ERROR_UNAVAILABLE,
      `PayJoin receiver currently only supports P2WPKH UTXOs (have ${candidate.addressType})`
    );
  }
  signReceiverInputP2WPKH(newTx, receiverInputIndex, candidate, deps.wallet);

  // 7. Build PSBT preserving sender's finalScriptSig/Witness from the
  //    Original. The receiver-input is signed in-place on `newTx` but the
  //    returned PSBT must be in valid PSBT format — convert the signed
  //    receiver input into finalScriptWitness, leave sender inputs as
  //    already-finalized.
  const payjoinPsbt = buildPayJoinPsbtFromTx(
    newTx,
    originalPsbt,
    receiverInputIndex
  );

  // 8. Register in pending map.
  deps.pending.set(psbtHash, {
    originalPsbtHash: psbtHash,
    originalPsbt,
    senderOutpoints,
    receivedAtMs: now,
    expiresAtMs: now + ttl,
  });

  return {
    base64Psbt: encodePSBTBase64(payjoinPsbt),
    originalPsbtHash: psbtHash,
    payjoinPsbt,
  };
}

function inferAddressTypeFromScript(spk: Buffer): AddressType {
  if (spk.length === 22 && spk[0] === 0x00 && spk[1] === 0x14) {
    return AddressType.P2WPKH;
  }
  if (
    spk.length === 25 &&
    spk[0] === 0x76 &&
    spk[1] === 0xa9 &&
    spk[2] === 0x14
  ) {
    return AddressType.P2PKH;
  }
  if (spk.length === 23 && spk[0] === 0xa9) return AddressType.P2SH;
  if (spk.length === 34 && spk[0] === 0x51 && spk[1] === 0x20) {
    return AddressType.P2TR;
  }
  return AddressType.P2WPKH;
}

function pickReceiverUtxo(
  wallet: Wallet,
  preferType: AddressType
): WalletUTXO | null {
  const candidates = wallet
    .getUTXOs()
    .filter((u) => u.confirmations >= 1)
    .filter((u) => !u.isCoinbase || u.confirmations >= 100);

  if (candidates.length === 0) return null;

  // Prefer same address type as receiver output, then largest. Largest-first
  // is a deliberately simple heuristic — a richer impl would randomise per
  // BIP-78 §C.2 (G20). We retain that as a follow-up; the test for G20
  // remains skipped in the audit file.
  const sameType = candidates.filter((u) => u.addressType === preferType);
  const pool = sameType.length > 0 ? sameType : candidates;
  pool.sort((a, b) => (a.amount > b.amount ? -1 : a.amount < b.amount ? 1 : 0));
  return pool[0];
}

/**
 * Sign a P2WPKH input via the wallet's per-address key. We re-implement the
 * BIP-143 sighash path here rather than calling into the Wallet's private
 * signInput because the PayJoin context already has the full TX in hand and
 * doesn't need wallet-internal coin selection.
 */
function signReceiverInputP2WPKH(
  tx: Transaction,
  inputIndex: number,
  utxo: WalletUTXO,
  wallet: Wallet
): void {
  const key = wallet.getKey(utxo.address);
  if (!key) {
    throw new PayJoinError(
      PAYJOIN_ERROR_UNAVAILABLE,
      `wallet has no key for receiver UTXO address ${utxo.address}`
    );
  }
  const pubKeyHash = hash160(key.publicKey);
  const scriptCode = Buffer.concat([
    Buffer.from([0x76, 0xa9, 0x14]),
    pubKeyHash,
    Buffer.from([0x88, 0xac]),
  ]);
  const sighash = sigHashWitnessV0(
    tx,
    inputIndex,
    scriptCode,
    utxo.amount,
    SIGHASH_ALL
  );
  const signature = ecdsaSign(sighash, key.privateKey);
  const sigWithType = Buffer.concat([signature, Buffer.from([SIGHASH_ALL])]);

  tx.inputs[inputIndex].scriptSig = Buffer.alloc(0);
  tx.inputs[inputIndex].witness = [sigWithType, key.publicKey];
}

/**
 * Build a PSBT for the PayJoin response. Inputs that already had a witness
 * (sender's pre-signed inputs OR our newly-signed receiver input) are
 * preserved as finalScriptWitness; finalScriptSig follows the same shape.
 */
function buildPayJoinPsbtFromTx(
  signedTx: Transaction,
  originalPsbt: PSBT,
  receiverInputIndex: number
): PSBT {
  // Build the unsigned-tx scaffold the PSBT format requires (empty
  // scriptSig + empty witness on every input).
  const unsignedTx: Transaction = {
    version: signedTx.version,
    inputs: signedTx.inputs.map((i) => ({
      prevOut: { txid: Buffer.from(i.prevOut.txid), vout: i.prevOut.vout },
      scriptSig: Buffer.alloc(0),
      sequence: i.sequence,
      witness: [],
    })),
    outputs: signedTx.outputs.map((o) => ({
      value: o.value,
      scriptPubKey: Buffer.from(o.scriptPubKey),
    })),
    lockTime: signedTx.lockTime,
  };

  const psbt = createPSBT(unsignedTx);

  // Restore each sender input's finalization from the Original. PSBT inputs
  // are 1:1 ordered with tx inputs — we appended the receiver input at the
  // tail, so indices 0..origCount-1 map directly back to originalPsbt.inputs.
  for (let i = 0; i < originalPsbt.inputs.length; i++) {
    const origPsbtInput: PSBTInput = originalPsbt.inputs[i];
    const psbtInput = psbt.inputs[i];
    if (origPsbtInput.finalScriptSig) {
      psbtInput.finalScriptSig = Buffer.from(origPsbtInput.finalScriptSig);
    }
    if (origPsbtInput.finalScriptWitness) {
      psbtInput.finalScriptWitness = origPsbtInput.finalScriptWitness.map((w) =>
        Buffer.from(w)
      );
    }
    if (origPsbtInput.witnessUtxo) {
      psbtInput.witnessUtxo = {
        value: origPsbtInput.witnessUtxo.value,
        scriptPubKey: Buffer.from(origPsbtInput.witnessUtxo.scriptPubKey),
      };
    }
  }

  // Finalize the receiver-added input from the in-memory witness we just
  // produced via signReceiverInputP2WPKH.
  const recvInput = signedTx.inputs[receiverInputIndex];
  if (recvInput.witness.length > 0) {
    psbt.inputs[receiverInputIndex].finalScriptWitness = recvInput.witness.map(
      (w) => Buffer.from(w)
    );
  }
  if (recvInput.scriptSig.length > 0) {
    psbt.inputs[receiverInputIndex].finalScriptSig = Buffer.from(recvInput.scriptSig);
  }

  return psbt;
}
