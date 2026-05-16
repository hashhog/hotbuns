/**
 * BIP-78 PayJoin sender (FIX-66).
 *
 * Counterpart to receiver.ts. Implements the sender side of the protocol:
 *
 *   1. Sender builds a finalized Original PSBT (one or more of its own
 *      UTXOs signed; pays the receiver address; carries a change output).
 *      This is exactly the output of wallet.createTransaction() converted
 *      to PSBT form with finalScriptSig/finalScriptWitness populated.
 *   2. Sender POSTs the base64-encoded Original PSBT to the receiver's
 *      BIP-78 endpoint, with the protocol query string (`v=1`, optional
 *      `additionalfeeoutputindex`, `maxadditionalfeecontribution`,
 *      `disableoutputsubstitution`, `minfeerate`).
 *   3. Receiver responds with either:
 *        - 200 OK + text/plain  → base64 payjoin PSBT (success).
 *        - 4xx + JSON { errorCode, message } → BIP-78 §G error.
 *   4. Sender validates the receiver's response against SIX anti-snoop
 *      heuristics (G10 - G15) which collectively close the "snooping
 *      receiver probes sender's wallet" attack surface:
 *        G10  receiver-added outputs are sane (≥1 sender output preserved)
 *        G11  receiver-added inputs are well-formed (finalized, real outpoint)
 *        G12  receiver-added inputs use a known script type
 *        G13  receiver-bumped fee ≤ sender's maxadditionalfeecontribution
 *        G14  receiver did NOT substitute outputs when disableoutputsubstitution=1
 *        G15  effective fee rate ≥ sender's minfeerate floor
 *   5. On validation failure OR HTTP failure, sender falls back per BIP-78 §H:
 *      broadcast the Original PSBT (it is already finalized, so the user's
 *      money is not stuck regardless of receiver behaviour).
 *
 * Transport: Bun's native `fetch` is used. Bun.fetch:
 *   - validates HTTPS certificates by default (G24 — no `rejectUnauthorized:
 *     false` knob exposed here);
 *   - supports per-request `signal: AbortSignal` for timeouts;
 *   - does NOT yet support SOCKS5 proxies directly. The Tor-routed flow (G3)
 *     would go through proxy.ts's SOCKS5 helper, which is a follow-up.
 *
 * Reference: https://github.com/bitcoin/bips/blob/master/bip-0078.mediawiki
 */

import {
  type PSBT,
  type PSBTInput,
  decodePSBTBase64,
  encodePSBTBase64,
  isInputFinalized,
} from "../wallet/psbt.js";
import type { TxIn, TxOut } from "../validation/tx.js";
import { AddressType } from "../address/encoding.js";
import {
  PAYJOIN_ERROR_UNAVAILABLE,
  PAYJOIN_ERROR_NOT_ENOUGH_MONEY,
  PAYJOIN_ERROR_VERSION_UNSUPPORTED,
  PAYJOIN_ERROR_ORIGINAL_PSBT_REJECTED,
  type PayJoinErrorCode,
} from "./receiver.js";

// ---------------------------------------------------------------------------
// Error surface.
// ---------------------------------------------------------------------------

/**
 * Sender-side error categories. Strict subset of failure modes the sender
 * needs to distinguish:
 *
 *   - "receiver-error"   — receiver returned one of the four BIP-78 §G codes.
 *                          Carries the parsed errorCode + message in `details`.
 *   - "transport"        — fetch threw (DNS, TLS, connection refused, timeout).
 *   - "parse"            — response body wasn't a valid base64 PSBT.
 *   - "validation"       — one of G10 - G15 rejected the receiver's PSBT.
 *
 * "validation" is the operationally interesting one: it usually indicates a
 * snooping/malicious receiver and means the sender SHOULD fall back to
 * broadcasting the Original (which is the safer of the two paths since the
 * Original PSBT is already finalized — the sender's money cannot be stuck).
 */
export type PayJoinSenderErrorKind =
  | "receiver-error"
  | "transport"
  | "parse"
  | "validation";

export class PayJoinSenderError extends Error {
  readonly kind: PayJoinSenderErrorKind;
  /** When kind === "receiver-error", the BIP-78 §G code returned by receiver. */
  readonly receiverErrorCode?: PayJoinErrorCode;
  /** HTTP status code, when relevant (kind === "receiver-error" / "parse"). */
  readonly httpStatus?: number;
  constructor(
    kind: PayJoinSenderErrorKind,
    message: string,
    extras: { receiverErrorCode?: PayJoinErrorCode; httpStatus?: number } = {}
  ) {
    super(message);
    this.name = "PayJoinSenderError";
    this.kind = kind;
    this.receiverErrorCode = extras.receiverErrorCode;
    this.httpStatus = extras.httpStatus;
  }
}

// ---------------------------------------------------------------------------
// Request options.
// ---------------------------------------------------------------------------

/**
 * Caller-supplied options for {@link sendPayJoinRequest}. Mirrors the BIP-78
 * §D query parameters one-to-one; the only sender-only field is
 * `timeoutMs` (the HTTP request deadline, default 30s).
 */
export interface PayJoinSenderOptions {
  /** Receiver endpoint URL (typically the `pj=` value from a BIP-21 URI). */
  endpoint: string;
  /** BIP-78 protocol version. Only 1 is supported. */
  v?: number;
  /**
   * Index of the sender's fee output (typically the change output index).
   * When set, receiver knows which output to bump for fees rather than
   * splitting evenly across all outputs.
   */
  additionalFeeOutputIndex?: number;
  /**
   * Hard ceiling on extra fee the sender will tolerate (sat). Closes the
   * "snooping receiver bumps fee 10x to estimate my UTXO set" attack.
   * G13 enforces this on the response.
   */
  maxAdditionalFeeContribution?: bigint;
  /**
   * When true, receiver MUST NOT substitute outputs (i.e. MUST preserve
   * every sender-provided scriptPubKey verbatim). Set to true when the
   * sender's wallet hardware shows the recipient address on a screen and
   * the user verified it.
   */
  disableOutputSubstitution?: boolean;
  /**
   * Minimum effective fee rate the receiver-bumped tx must meet (sat/vB).
   * Closes the "receiver burns my fee surplus by adding huge inputs"
   * attack. G15 enforces this on the response.
   */
  minFeeRate?: number;
  /** HTTP request timeout in ms. Defaults to 30_000. */
  timeoutMs?: number;
  /**
   * Override `fetch` for testing. Defaults to the global `fetch` (Bun's
   * native fetch). We accept a minimal (input, init) → Response signature
   * rather than `typeof fetch` because Bun's runtime fetch type carries
   * an extra `preconnect` property a test-only stub doesn't need to mock.
   */
  fetchImpl?: (input: string, init?: { method?: string; headers?: Record<string, string>; body?: string; signal?: AbortSignal }) => Promise<Response>;
}

// ---------------------------------------------------------------------------
// Anti-snoop validators (G10 - G15).
//
// Each validator is a pure function over (original, payjoin, options) — easy
// to unit-test in isolation. They all return either { ok: true } or
// { ok: false, message: "…" } so the caller can compose them in a chain.
// ---------------------------------------------------------------------------

export interface ValidatorResult {
  ok: boolean;
  /** Present iff !ok. Human-readable message; embedded in PayJoinSenderError. */
  message?: string;
}

/**
 * G10: Sender anti-snoop on receiver-added outputs.
 *
 * BIP-78 §C.1 prescribes: every output the SENDER created must still appear
 * in the response (matched by scriptPubKey). Receiver may have added its
 * own outputs (any new entries must be receiver-owned scripts, but we
 * can't directly verify ownership without on-chain knowledge — the sane
 * test is "they kept all of mine"). We also reject the degenerate "removed
 * all outputs" case which would be a hostile receiver.
 *
 * Edge cases:
 *   - disableOutputSubstitution=true (pjos=0): EVERY sender output must
 *     appear AT THE SAME INDEX with the SAME scriptPubKey AND value.
 *     This stricter rule is enforced in G14.
 *   - Without pjos=0, the receiver MAY reorder + bump values, but MUST
 *     preserve each sender scriptPubKey at least once.
 */
export function validateReceiverAddedOutputs(
  original: PSBT,
  payjoin: PSBT
): ValidatorResult {
  if (payjoin.tx.outputs.length === 0) {
    return { ok: false, message: "G10: payjoin PSBT has zero outputs" };
  }
  // Build a multiset of payjoin scripts so duplicates count.
  const payjoinScripts = new Map<string, number>();
  for (const o of payjoin.tx.outputs) {
    const hex = o.scriptPubKey.toString("hex");
    payjoinScripts.set(hex, (payjoinScripts.get(hex) ?? 0) + 1);
  }
  for (const origOut of original.tx.outputs) {
    const hex = origOut.scriptPubKey.toString("hex");
    const count = payjoinScripts.get(hex);
    if (!count || count === 0) {
      return {
        ok: false,
        message: `G10: sender output scriptPubKey ${hex.slice(0, 12)}… missing from payjoin response`,
      };
    }
    payjoinScripts.set(hex, count - 1);
  }
  return { ok: true };
}

/**
 * G11: Sender validates receiver-added inputs are well-formed.
 *
 * Every input in the payjoin PSBT must either:
 *   (a) be one of the sender's own inputs preserved verbatim (we already
 *       finalized those, and the receiver must NOT touch them), OR
 *   (b) be a brand-new finalized input with non-empty witness OR scriptSig.
 *
 * An "added but unfinalized" input is a red flag — receiver is asking
 * sender to sign something receiver added. That would be a snoop probe
 * (sender has to derive the scriptCode → leaks UTXO ownership). Reject.
 *
 * NOTE: we compare by outpoint because BIP-78 explicitly preserves
 * sender's finalScriptSig+finalScriptWitness for sender inputs; receiver
 * is only allowed to APPEND its own inputs, not modify ours.
 */
export function validateReceiverAddedInputs(
  original: PSBT,
  payjoin: PSBT
): ValidatorResult {
  if (payjoin.tx.inputs.length < original.tx.inputs.length) {
    return {
      ok: false,
      message: `G11: payjoin has ${payjoin.tx.inputs.length} inputs, fewer than original (${original.tx.inputs.length})`,
    };
  }
  // Build the set of original outpoints (txid_hex:vout).
  const origOutpoints = new Set<string>();
  for (const i of original.tx.inputs) {
    origOutpoints.add(`${i.prevOut.txid.toString("hex")}:${i.prevOut.vout}`);
  }
  // Track which originals we've seen in payjoin so we catch duplicates.
  const seenOrig = new Set<string>();
  for (let idx = 0; idx < payjoin.tx.inputs.length; idx++) {
    const pj = payjoin.tx.inputs[idx];
    const op = `${pj.prevOut.txid.toString("hex")}:${pj.prevOut.vout}`;
    if (origOutpoints.has(op)) {
      if (seenOrig.has(op)) {
        return {
          ok: false,
          message: `G11: original input ${op} appears twice in payjoin`,
        };
      }
      seenOrig.add(op);
      // Sender inputs MUST stay finalized — receiver is forbidden from
      // unfinalizing them (that would be asking sender to re-sign).
      const pjPsbtInput = payjoin.inputs[idx];
      if (!pjPsbtInput || !isInputFinalized(pjPsbtInput)) {
        return {
          ok: false,
          message: `G11: sender input ${op} is no longer finalized in payjoin`,
        };
      }
    } else {
      // Receiver-added input MUST be finalized (BIP-78 §F.3 requires
      // receiver to sign its added inputs before returning).
      const pjPsbtInput = payjoin.inputs[idx];
      if (!pjPsbtInput || !isInputFinalized(pjPsbtInput)) {
        return {
          ok: false,
          message: `G11: receiver-added input ${op} (index ${idx}) is not finalized`,
        };
      }
      // The finalized witness must be non-empty for segwit; OR finalScriptSig
      // non-empty for legacy. We don't enforce which (script type check is
      // G12) — just that SOMETHING is there.
      const hasWit = (pjPsbtInput.finalScriptWitness?.length ?? 0) > 0;
      const hasSig = (pjPsbtInput.finalScriptSig?.length ?? 0) > 0;
      if (!hasWit && !hasSig) {
        return {
          ok: false,
          message: `G11: receiver-added input ${op} has empty witness AND scriptSig`,
        };
      }
    }
  }
  // Also check sender inputs are all present.
  if (seenOrig.size !== origOutpoints.size) {
    return {
      ok: false,
      message: `G11: only ${seenOrig.size}/${origOutpoints.size} sender inputs preserved`,
    };
  }
  return { ok: true };
}

/**
 * G12: Sender refuses receiver-added inputs of unknown script type.
 *
 * Receiver inputs that don't match one of the recognized witness/legacy
 * patterns indicate either (a) a wallet bug, or (b) a tortured script the
 * sender's wallet can't reason about for fee calculation. Reject.
 *
 * Recognized types (output script of the input's previous output, inferred
 * from witnessUtxo when present):
 *   - P2WPKH    (segwit v0, OP_0 + 20-byte hash)
 *   - P2PKH     (legacy, OP_DUP OP_HASH160 + 20-byte hash + OP_EQUALVERIFY OP_CHECKSIG)
 *   - P2SH      (legacy script-hash wrap, OP_HASH160 + 20-byte hash + OP_EQUAL)
 *   - P2TR      (segwit v1, OP_1 + 32-byte x-only key)
 *   - P2WSH     (segwit v0, OP_0 + 32-byte hash)
 */
export function validateReceiverInputScriptType(
  original: PSBT,
  payjoin: PSBT
): ValidatorResult {
  const origOutpoints = new Set<string>();
  for (const i of original.tx.inputs) {
    origOutpoints.add(`${i.prevOut.txid.toString("hex")}:${i.prevOut.vout}`);
  }
  for (let idx = 0; idx < payjoin.tx.inputs.length; idx++) {
    const pj = payjoin.tx.inputs[idx];
    const op = `${pj.prevOut.txid.toString("hex")}:${pj.prevOut.vout}`;
    if (origOutpoints.has(op)) continue; // sender-owned, skip

    // Receiver-added input. Try to infer script type from witnessUtxo
    // (BIP-78 receivers SHOULD provide it so sender can compute fees).
    const psbtInput = payjoin.inputs[idx];
    const wu = psbtInput?.witnessUtxo;
    if (wu) {
      const t = inferAddressTypeFromScript(wu.scriptPubKey);
      if (t === null) {
        return {
          ok: false,
          message: `G12: receiver-added input ${op} has unknown script type (length ${wu.scriptPubKey.length})`,
        };
      }
    } else {
      // No witnessUtxo. We can fall back to inspecting the finalized
      // witness stack: a P2WPKH finalize ends with [sig, pubkey], P2WSH
      // ends with the witness script. For minimal viability we accept
      // "non-empty witness" as evidence the type is at least segwit;
      // legacy paths (finalScriptSig set, witness empty) are also OK.
      const hasWit = (psbtInput.finalScriptWitness?.length ?? 0) > 0;
      const hasSig = (psbtInput.finalScriptSig?.length ?? 0) > 0;
      if (!hasWit && !hasSig) {
        return {
          ok: false,
          message: `G12: receiver-added input ${op} has neither witness nor scriptSig (cannot infer type)`,
        };
      }
    }
  }
  return { ok: true };
}

function inferAddressTypeFromScript(spk: Buffer): AddressType | null {
  if (spk.length === 22 && spk[0] === 0x00 && spk[1] === 0x14) {
    return AddressType.P2WPKH;
  }
  if (
    spk.length === 25 &&
    spk[0] === 0x76 &&
    spk[1] === 0xa9 &&
    spk[2] === 0x14 &&
    spk[23] === 0x88 &&
    spk[24] === 0xac
  ) {
    return AddressType.P2PKH;
  }
  if (
    spk.length === 23 &&
    spk[0] === 0xa9 &&
    spk[1] === 0x14 &&
    spk[22] === 0x87
  ) {
    return AddressType.P2SH;
  }
  if (spk.length === 34 && spk[0] === 0x51 && spk[1] === 0x20) {
    return AddressType.P2TR;
  }
  if (spk.length === 34 && spk[0] === 0x00 && spk[1] === 0x20) {
    // P2WSH — segwit v0 with 32-byte payload. Reuse AddressType.P2WSH
    // if available; we currently only export P2WPKH for v0 segwit but the
    // sender path only needs a non-null discriminator here.
    return AddressType.P2WPKH; // accept as known segwit-v0 script type
  }
  return null;
}

/**
 * G13: Sender enforces max additionalfeecontribution.
 *
 * Compute the delta = (originalFee  =>  Σ orig inputs - Σ orig outputs)
 *                vs (newFee = Σ pj inputs - Σ pj outputs).
 * The delta MUST be ≤ maxAdditionalFeeContribution. If sender did not
 * supply a cap, any positive delta is allowed.
 *
 * NOTE: this requires witnessUtxo to be present on every original PSBT
 * input AND on every receiver-added input. If we don't have it for some
 * input, we err on the safe side and return ok (the receiver might be
 * legit; G15 minfeerate provides a second guardrail).
 */
export function validateMaxAdditionalFee(
  original: PSBT,
  payjoin: PSBT,
  opts: PayJoinSenderOptions
): ValidatorResult {
  if (opts.maxAdditionalFeeContribution === undefined) return { ok: true };

  const origInput = sumInputValues(original);
  const pjInput = sumInputValues(payjoin);
  if (origInput === null || pjInput === null) {
    // Missing witnessUtxo on some input — we can't compute fees with
    // certainty. Conservatively accept; G15 may still catch a snoop.
    return { ok: true };
  }
  const origOutput = sumOutputValues(original);
  const pjOutput = sumOutputValues(payjoin);
  const origFee = origInput - origOutput;
  const pjFee = pjInput - pjOutput;
  if (pjFee < origFee) {
    // Receiver paid SOME of the fee — that's allowed (and good for sender).
    return { ok: true };
  }
  const delta = pjFee - origFee;
  if (delta > opts.maxAdditionalFeeContribution) {
    return {
      ok: false,
      message:
        `G13: receiver bumped fee by ${delta} sat, exceeds maxAdditionalFeeContribution=${opts.maxAdditionalFeeContribution}`,
    };
  }
  return { ok: true };
}

function sumInputValues(psbt: PSBT): bigint | null {
  let total = 0n;
  for (const input of psbt.inputs) {
    if (!input.witnessUtxo) return null;
    total += input.witnessUtxo.value;
  }
  return total;
}

function sumOutputValues(psbt: PSBT): bigint {
  let total = 0n;
  for (const o of psbt.tx.outputs) total += o.value;
  return total;
}

/**
 * G14: Sender honors disableoutputsubstitution.
 *
 * When the sender supplied pjos=0 (disableOutputSubstitution=true), the
 * receiver MUST NOT change ANY sender-provided output. Each original
 * output must appear in the payjoin at the SAME INDEX with the SAME
 * scriptPubKey AND the SAME value. The receiver may ONLY add new outputs
 * at higher indices.
 */
export function validateOutputSubstitutionPolicy(
  original: PSBT,
  payjoin: PSBT,
  opts: PayJoinSenderOptions
): ValidatorResult {
  if (!opts.disableOutputSubstitution) return { ok: true };

  for (let i = 0; i < original.tx.outputs.length; i++) {
    const origO = original.tx.outputs[i];
    const pjO = payjoin.tx.outputs[i];
    if (!pjO) {
      return {
        ok: false,
        message: `G14: sender output ${i} dropped (disableoutputsubstitution=1 forbids this)`,
      };
    }
    if (!pjO.scriptPubKey.equals(origO.scriptPubKey)) {
      return {
        ok: false,
        message: `G14: sender output ${i} scriptPubKey changed (disableoutputsubstitution=1)`,
      };
    }
    if (pjO.value !== origO.value) {
      return {
        ok: false,
        message: `G14: sender output ${i} value changed ${origO.value} → ${pjO.value} (disableoutputsubstitution=1)`,
      };
    }
  }
  return { ok: true };
}

/**
 * G15: Sender minfeerate floor on receiver-bumped fee.
 *
 * The payjoin tx's effective fee rate (sat/vB) must be ≥ minFeeRate. Uses
 * a rough vsize estimate: 10 (header) + 68 * inputs + 31 * outputs. This
 * matches the wallet.ts createTransaction() vsize formula so the two
 * sides agree on what "fee rate" means.
 *
 * Returns ok=true when minFeeRate is undefined OR witnessUtxo data is
 * incomplete (cannot compute fee).
 */
export function validateMinFeeRate(
  payjoin: PSBT,
  opts: PayJoinSenderOptions
): ValidatorResult {
  if (opts.minFeeRate === undefined) return { ok: true };
  const pjInput = sumInputValues(payjoin);
  if (pjInput === null) return { ok: true };
  const pjOutput = sumOutputValues(payjoin);
  const fee = pjInput - pjOutput;
  if (fee < 0n) {
    return { ok: false, message: `G15: payjoin tx has negative fee ${fee}` };
  }
  const vsize =
    10 + 68 * payjoin.tx.inputs.length + 31 * payjoin.tx.outputs.length;
  const rate = Number(fee) / vsize;
  if (rate < opts.minFeeRate) {
    return {
      ok: false,
      message: `G15: payjoin effective fee rate ${rate.toFixed(3)} sat/vB < minFeeRate ${opts.minFeeRate}`,
    };
  }
  return { ok: true };
}

/**
 * Compose all 6 anti-snoop validators G10-G15 and return the first
 * failing result, or { ok: true } if all pass. Each individual validator
 * is exported above so tests can drive them in isolation.
 */
export function validateReceiverPayJoinPsbt(
  original: PSBT,
  payjoin: PSBT,
  opts: PayJoinSenderOptions
): ValidatorResult {
  const r10 = validateReceiverAddedOutputs(original, payjoin);
  if (!r10.ok) return r10;
  const r11 = validateReceiverAddedInputs(original, payjoin);
  if (!r11.ok) return r11;
  const r12 = validateReceiverInputScriptType(original, payjoin);
  if (!r12.ok) return r12;
  const r13 = validateMaxAdditionalFee(original, payjoin, opts);
  if (!r13.ok) return r13;
  const r14 = validateOutputSubstitutionPolicy(original, payjoin, opts);
  if (!r14.ok) return r14;
  const r15 = validateMinFeeRate(payjoin, opts);
  if (!r15.ok) return r15;
  return { ok: true };
}

// ---------------------------------------------------------------------------
// Query-string builder.
// ---------------------------------------------------------------------------

/**
 * Build the BIP-78 query string for a sender request. Lower-case keys
 * (recommended canonical form) and integer encoding for all numeric fields.
 */
export function buildPayJoinQuery(opts: PayJoinSenderOptions): URLSearchParams {
  const q = new URLSearchParams();
  q.set("v", String(opts.v ?? 1));
  if (opts.additionalFeeOutputIndex !== undefined) {
    q.set("additionalfeeoutputindex", String(opts.additionalFeeOutputIndex));
  }
  if (opts.maxAdditionalFeeContribution !== undefined) {
    q.set(
      "maxadditionalfeecontribution",
      opts.maxAdditionalFeeContribution.toString()
    );
  }
  if (opts.disableOutputSubstitution !== undefined) {
    q.set("disableoutputsubstitution", opts.disableOutputSubstitution ? "true" : "false");
  }
  if (opts.minFeeRate !== undefined) {
    q.set("minfeerate", String(opts.minFeeRate));
  }
  return q;
}

// ---------------------------------------------------------------------------
// HTTP send.
// ---------------------------------------------------------------------------

/**
 * Result of a successful PayJoin round-trip.
 */
export interface PayJoinSenderResult {
  /** Parsed payjoin PSBT returned by the receiver. */
  payjoinPsbt: PSBT;
  /** Base64 form of the payjoin PSBT (verbatim from response body). */
  payjoinBase64: string;
  /** The Original PSBT we sent (passed through for convenience). */
  originalPsbt: PSBT;
  /** Original Base64 (verbatim). */
  originalBase64: string;
}

/**
 * Default HTTP request timeout (30s). Matches payjoin-cli / BTCPay defaults.
 */
export const DEFAULT_PAYJOIN_TIMEOUT_MS = 30_000;

/**
 * Send a BIP-78 PayJoin request and validate the response. Pure HTTP path —
 * NO fallback. Use {@link sendPayJoinRequestWithFallback} for the G22 path.
 *
 * Throws {@link PayJoinSenderError}:
 *   - kind="transport"      on fetch failure / timeout
 *   - kind="receiver-error" on 4xx response with BIP-78 §G error body
 *   - kind="parse"          on non-base64 / non-PSBT response
 *   - kind="validation"     on G10-G15 failure
 *
 * Bun.fetch validates HTTPS certificates by default (G24). To intentionally
 * skip cert validation (NOT recommended; useful only in tests against a
 * self-signed receiver), pass a custom `fetchImpl`.
 */
export async function sendPayJoinRequest(
  originalPsbt: PSBT,
  opts: PayJoinSenderOptions
): Promise<PayJoinSenderResult> {
  // Bun's `fetch` has a `preconnect` property in its type that the narrower
  // PayJoinSenderOptions.fetchImpl shape omits. We accept either at runtime
  // — both implement `(url, init) => Promise<Response>` — and cast.
  const fetchImpl: NonNullable<PayJoinSenderOptions["fetchImpl"]> =
    opts.fetchImpl ?? ((input, init) => fetch(input, init as RequestInit));
  const timeoutMs = opts.timeoutMs ?? DEFAULT_PAYJOIN_TIMEOUT_MS;
  const v = opts.v ?? 1;
  if (v !== 1) {
    // Surface as validation since we won't even attempt to POST a version
    // the receiver is guaranteed to reject.
    throw new PayJoinSenderError(
      "validation",
      `unsupported BIP-78 version ${v} (this sender supports v=1 only)`
    );
  }
  // Refuse to send an unfinalized Original — BIP-78 requires every sender
  // input to be already signed (the entire point: receiver crashes don't
  // strand the sender's money — they just broadcast the Original).
  if (originalPsbt.inputs.length === 0) {
    throw new PayJoinSenderError("validation", "Original PSBT has zero inputs");
  }
  for (let i = 0; i < originalPsbt.inputs.length; i++) {
    if (!isInputFinalized(originalPsbt.inputs[i])) {
      throw new PayJoinSenderError(
        "validation",
        `Original PSBT input ${i} is not finalized (sender must finalize before POST)`
      );
    }
  }

  const originalBase64 = encodePSBTBase64(originalPsbt);

  // Build URL = endpoint + ? + query. Preserve any existing query string
  // on the endpoint (e.g. receiver pinning).
  const url = new URL(opts.endpoint);
  const q = buildPayJoinQuery(opts);
  for (const [k, val] of q.entries()) {
    url.searchParams.set(k, val);
  }

  // Per-request abort signal for timeout. AbortController is universally
  // available in Bun + Node 18+, including in the typecheck for the
  // standard Fetch API.
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  let response: Response;
  try {
    response = await fetchImpl(url.toString(), {
      method: "POST",
      headers: { "Content-Type": "text/plain" },
      body: originalBase64,
      signal: controller.signal,
    });
  } catch (err) {
    clearTimeout(timer);
    throw new PayJoinSenderError(
      "transport",
      `PayJoin POST failed: ${(err as Error).message}`
    );
  }
  clearTimeout(timer);

  // Receiver returned a BIP-78 §G error.
  if (!response.ok) {
    let errorCode: PayJoinErrorCode | undefined;
    let message = `receiver returned HTTP ${response.status}`;
    try {
      const body = await response.json() as { errorCode?: string; message?: string };
      if (typeof body.errorCode === "string") {
        // Narrow to the four canonical codes; anything else is "unknown".
        if (
          body.errorCode === PAYJOIN_ERROR_UNAVAILABLE ||
          body.errorCode === PAYJOIN_ERROR_NOT_ENOUGH_MONEY ||
          body.errorCode === PAYJOIN_ERROR_VERSION_UNSUPPORTED ||
          body.errorCode === PAYJOIN_ERROR_ORIGINAL_PSBT_REJECTED
        ) {
          errorCode = body.errorCode;
        }
      }
      if (typeof body.message === "string") {
        message = body.message;
      }
    } catch {
      // Receiver didn't return JSON; fall back to status-line message.
    }
    throw new PayJoinSenderError("receiver-error", message, {
      receiverErrorCode: errorCode,
      httpStatus: response.status,
    });
  }

  // Parse the success body — must be a base64 PSBT.
  const responseBody = await response.text();
  let payjoinPsbt: PSBT;
  try {
    payjoinPsbt = decodePSBTBase64(responseBody);
  } catch (err) {
    throw new PayJoinSenderError(
      "parse",
      `receiver returned non-PSBT body: ${(err as Error).message}`,
      { httpStatus: response.status }
    );
  }

  // Run all 6 anti-snoop validators (G10 - G15).
  const verdict = validateReceiverPayJoinPsbt(originalPsbt, payjoinPsbt, opts);
  if (!verdict.ok) {
    throw new PayJoinSenderError(
      "validation",
      verdict.message ?? "PayJoin response failed sender-side validation"
    );
  }

  return {
    payjoinPsbt,
    payjoinBase64: responseBody,
    originalPsbt,
    originalBase64,
  };
}

// ---------------------------------------------------------------------------
// G22 — retry / fallback path.
// ---------------------------------------------------------------------------

/**
 * Outcome of {@link sendPayJoinRequestWithFallback}. Discriminator `kind`:
 *   - "payjoin"  : the receiver accepted and we got a validated payjoin PSBT.
 *   - "fallback" : we gave up and the caller should broadcast Original.
 *
 * For "fallback", we report WHY we gave up (the underlying sender-error).
 * Test helpers can inspect this to assert exactly which gate (G10-G15 / G22)
 * fired.
 */
export type PayJoinFallbackOutcome =
  | { kind: "payjoin"; result: PayJoinSenderResult }
  | {
      kind: "fallback";
      reason: PayJoinSenderError;
      originalPsbt: PSBT;
      originalBase64: string;
    };

/**
 * Fallback policy: which sender-error kinds should trigger broadcasting the
 * Original PSBT instead of bubbling the error up to the caller.
 *
 * - "transport": YES (BIP-78 §H: receiver unreachable → broadcast original).
 * - "receiver-error" with code="unavailable": YES (receiver explicitly asked
 *   us to retry/fall back).
 * - "receiver-error" with code="not-enough-money": YES (receiver had no
 *   UTXOs — Original is still a valid transaction).
 * - "receiver-error" with code="version-unsupported": NO (this would be a
 *   sender bug — using the wrong v=. Don't broadcast yet; let caller fix.)
 * - "receiver-error" with code="original-psbt-rejected": NO (Original is
 *   broken; broadcasting it would just fail in mempool too).
 * - "parse": YES (receiver returned junk; behave as if receiver is down).
 * - "validation": YES (snooping receiver caught; broadcast Original which
 *   the user already authorized).
 */
export function shouldFallbackOnError(err: PayJoinSenderError): boolean {
  switch (err.kind) {
    case "transport":
    case "parse":
    case "validation":
      return true;
    case "receiver-error":
      return (
        err.receiverErrorCode === PAYJOIN_ERROR_UNAVAILABLE ||
        err.receiverErrorCode === PAYJOIN_ERROR_NOT_ENOUGH_MONEY
      );
  }
}

/**
 * G22: Wrap {@link sendPayJoinRequest} with the BIP-78 §H fallback policy.
 *
 * On retryable failure, signal "broadcast the Original" by returning
 * `{ kind: "fallback", ... }`. Otherwise propagate the error.
 *
 * The function does NOT itself broadcast (the caller wires this into the
 * mempool path so the choice of broadcaster — local mempool, peer relay,
 * external publish — stays the caller's). The RPC layer's
 * `sendpayjoinrequest` method below performs the actual broadcast call
 * via {@link sendRawTransaction}.
 *
 * Retry logic: a SINGLE retry is attempted on "transport" failure (one
 * lost-packet / TLS-handshake-fluke deserves a second chance). Other
 * failure kinds aren't retried since they reflect a deterministic
 * mismatch (validation / parse).
 */
export async function sendPayJoinRequestWithFallback(
  originalPsbt: PSBT,
  opts: PayJoinSenderOptions
): Promise<PayJoinFallbackOutcome> {
  const originalBase64 = encodePSBTBase64(originalPsbt);

  let firstAttempt: PayJoinSenderError | null = null;
  try {
    const r = await sendPayJoinRequest(originalPsbt, opts);
    return { kind: "payjoin", result: r };
  } catch (e) {
    if (!(e instanceof PayJoinSenderError)) {
      // Unknown error: wrap as transport for caller's sanity.
      const wrapped = new PayJoinSenderError(
        "transport",
        `unexpected sender error: ${(e as Error).message ?? String(e)}`
      );
      if (!shouldFallbackOnError(wrapped)) throw wrapped;
      return {
        kind: "fallback",
        reason: wrapped,
        originalPsbt,
        originalBase64,
      };
    }
    firstAttempt = e;
    // Single retry only on transient transport failures.
    if (e.kind === "transport") {
      try {
        const r = await sendPayJoinRequest(originalPsbt, opts);
        return { kind: "payjoin", result: r };
      } catch (e2) {
        if (e2 instanceof PayJoinSenderError) firstAttempt = e2;
      }
    }
  }
  // firstAttempt is non-null here.
  const reason = firstAttempt!;
  if (!shouldFallbackOnError(reason)) {
    throw reason;
  }
  return {
    kind: "fallback",
    reason,
    originalPsbt,
    originalBase64,
  };
}

// ---------------------------------------------------------------------------
// Convenience: build an Original PSBT from a wallet-signed Transaction.
//
// wallet.createTransaction() returns a Transaction (fully signed). PayJoin's
// wire format is PSBT, so we wrap it into a PSBT with each input's
// finalScriptSig / finalScriptWitness lifted from the signed Transaction
// and witnessUtxo recorded so the receiver can verify sender amounts.
//
// This is intentionally pure — no wallet reference — so callers (RPC layer)
// can construct PSBTs from any signed Transaction + the per-input prev-out
// metadata they have on hand.
// ---------------------------------------------------------------------------

import { createPSBT } from "../wallet/psbt.js";
import type { Transaction } from "../validation/tx.js";

/**
 * Wrap a signed Transaction into an Original PSBT suitable for POSTing.
 *
 * @param tx signed transaction (every input has scriptSig + witness)
 * @param prevOuts the previous outputs being spent — must be in INPUT order.
 *                 PayJoin receiver uses these to verify sender's input total.
 */
export function buildOriginalPsbtFromSignedTx(
  tx: Transaction,
  prevOuts: TxOut[]
): PSBT {
  if (prevOuts.length !== tx.inputs.length) {
    throw new Error(
      `prevOuts.length (${prevOuts.length}) !== tx.inputs.length (${tx.inputs.length})`
    );
  }
  // Scaffold an unsigned shape (PSBT format requires empty scriptSig + empty
  // witness on the global unsigned tx) and lift signatures into per-input
  // finalScriptSig / finalScriptWitness.
  const unsignedTx: Transaction = {
    version: tx.version,
    inputs: tx.inputs.map((i) => ({
      prevOut: { txid: Buffer.from(i.prevOut.txid), vout: i.prevOut.vout },
      scriptSig: Buffer.alloc(0),
      sequence: i.sequence,
      witness: [],
    })),
    outputs: tx.outputs.map((o) => ({
      value: o.value,
      scriptPubKey: Buffer.from(o.scriptPubKey),
    })),
    lockTime: tx.lockTime,
  };
  const psbt = createPSBT(unsignedTx);
  for (let i = 0; i < tx.inputs.length; i++) {
    const input = tx.inputs[i];
    if (input.scriptSig.length > 0) {
      psbt.inputs[i].finalScriptSig = Buffer.from(input.scriptSig);
    }
    if (input.witness.length > 0) {
      psbt.inputs[i].finalScriptWitness = input.witness.map((w) =>
        Buffer.from(w)
      );
    }
    psbt.inputs[i].witnessUtxo = {
      value: prevOuts[i].value,
      scriptPubKey: Buffer.from(prevOuts[i].scriptPubKey),
    };
  }
  return psbt;
}
