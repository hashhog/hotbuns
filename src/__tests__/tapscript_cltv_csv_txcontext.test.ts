/**
 * Regression test for the mainnet-block-950149 consensus divergence.
 *
 * INCIDENT
 * --------
 * hotbuns rejected mainnet block 950149 (P0 consensus bug — would fork off
 * mainnet). The failing transaction is
 *   1b0d64e49b72ec3bbbbf54a4bc9124a316ce6159c1fff437e36cf36605e4f54d
 * (internal little-endian hash prefix 4df5e40566f36ce3…), input 0.
 *
 * That input is a Taproot SCRIPT-PATH (tapscript) spend whose leaf script is
 *   <32B pubkey> OP_CHECKSIGVERIFY <950148> OP_CHECKLOCKTIMEVERIFY
 * The spending tx has nLockTime=950148 and the input nSequence=0xfffffffd
 * (not SEQUENCE_FINAL). Per BIP-65/BIP-342 the CLTV check must PASS:
 *   - operand 950148 <= tx nLockTime 950148   ✓
 *   - both in block-height domain (< LOCKTIME_THRESHOLD 500000000)  ✓
 *   - input nSequence != 0xffffffff  ✓
 *
 * ROOT CAUSE
 * ----------
 * `src/validation/tx.ts` had two script-verify branches:
 *   - a dedicated P2TR branch that called `verifyTaproot(spk, witness, flags,
 *     taprootCtx)` with only 4 args — NO txContext;
 *   - a catch-all branch that built `{txVersion, txLockTime, txSequence}` and
 *     threaded it through `verifyScript`.
 * With txContext undefined, `executeTapscript`'s OP_CHECKLOCKTIMEVERIFY /
 * OP_CHECKSEQUENCEVERIFY handlers see `ctx.txLockTime === undefined` and
 * fail-safe with SCRIPT_ERR_UNSATISFIED_LOCKTIME — so EVERY tapscript
 * absolute/relative timelock spend was wrongly rejected at block validation.
 *
 * FIX
 * ---
 * The P2TR branch now builds the same txContext and passes it as
 * `verifyTaproot`'s 5th argument. `verifyTaproot` already forwards txContext
 * to `verifyTaprootScriptPath` → `executeTapscript`.
 *
 * These tests reproduce the scenario at the interpreter layer: a real
 * single-leaf tapscript tree with a tweaked output key, verified through
 * `verifyTaproot`. They assert (a) the bug — verifyTaproot WITHOUT txContext
 * fails a satisfiable CLTV/CSV with UNSATISFIED_LOCKTIME — and (b) the fix —
 * WITH txContext the same spend verifies. The leaf scripts avoid OP_CHECKSIG
 * so no Schnorr signing is needed; CLTV/CSV do not pop their operand, so
 * OP_DROP clears it and OP_1 leaves a clean `true`.
 *
 * Reference: bitcoin-core/src/script/interpreter.cpp
 *   - OP_CHECKLOCKTIMEVERIFY / OP_CHECKSEQUENCEVERIFY opcode cases
 *   - CheckLockTime() / CheckSequence()
 *   - ExecuteWitnessScript (tapscript path uses the same BaseSignatureChecker).
 */

import { describe, expect, test } from "bun:test";
import {
  Opcode,
  scriptNumEncode,
  verifyTaproot,
  type ScriptFlags,
  type TaprootContext,
} from "../script/interpreter.js";
import {
  taggedHash,
  privateKeyToXOnlyPubKey,
  tweakPublicKey,
} from "../crypto/primitives.js";
import {
  verifyInputSignature,
  ScriptFlags as TxScriptFlags,
  type Transaction,
} from "../validation/tx.js";
import type { UTXOEntry } from "../storage/database.js";

// BIP-342 tapscript leaf version.
const TAPROOT_LEAF_TAPSCRIPT = 0xc0;

// Exact values from mainnet block 950149 / tx 1b0d64e4…f54d input 0.
const BLOCK_950149_LOCKTIME = 950148; // tx nLockTime AND the CLTV operand
const SEQUENCE_NONFINAL = 0xfffffffd; // input 0 nSequence (not SEQUENCE_FINAL)

function consensusTaprootFlags(extra?: Partial<ScriptFlags>): ScriptFlags {
  return {
    verifyP2SH: true,
    verifyWitness: true,
    verifyTaproot: true,
    verifyStrictEncoding: false,
    verifyDERSignatures: true,
    verifyLowS: false,
    verifyNullDummy: true,
    verifyNullFail: true,
    verifyCheckLockTimeVerify: true,
    verifyCheckSequenceVerify: true,
    verifyWitnessPubkeyType: true,
    ...extra,
  };
}

function encodeCompactSize(n: number): Buffer {
  if (n < 0xfd) return Buffer.from([n]);
  if (n <= 0xffff) return Buffer.from([0xfd, n & 0xff, (n >> 8) & 0xff]);
  throw new Error("compact size > 0xffff not needed here");
}

function makeP2TR(xonly: Buffer): Buffer {
  if (xonly.length !== 32) throw new Error("expected 32B x-only key");
  return Buffer.concat([Buffer.from([0x51, 0x20]), xonly]);
}

const dummyTaprootCtx = (): TaprootContext => ({
  keyPathSigHasher: () => Buffer.alloc(32),
  scriptPathSigHasher: () => Buffer.alloc(32),
});

/**
 * Build a single-leaf P2TR commitment for `leafScript` and return the
 * scriptPubKey + a witness `[leafScript, controlBlock]` for the parity that
 * matches the tweaked output key. Tries both parities since `tweakPublicKey`
 * only yields the x-coordinate.
 */
function buildSingleLeafSpend(
  leafScript: Buffer,
  internalSeed: number
): { spk: Buffer; witnessFor: (parity: number) => Buffer[]; parities: number[] } {
  const internalPriv = Buffer.alloc(32, 0);
  internalPriv[31] = internalSeed;
  const internalPub = privateKeyToXOnlyPubKey(internalPriv);
  const lenPrefix = encodeCompactSize(leafScript.length);
  const leafHash = taggedHash(
    "TapLeaf",
    Buffer.concat([Buffer.from([TAPROOT_LEAF_TAPSCRIPT]), lenPrefix, leafScript])
  );
  const tweak = taggedHash("TapTweak", Buffer.concat([internalPub, leafHash]));
  const outputKey = tweakPublicKey(internalPub, tweak);
  const spk = makeP2TR(outputKey);
  const witnessFor = (parity: number): Buffer[] => [
    leafScript,
    Buffer.concat([Buffer.from([TAPROOT_LEAF_TAPSCRIPT | parity]), internalPub]),
  ];
  return { spk, witnessFor, parities: [0, 1] };
}

/**
 * Run verifyTaproot across both control-block parities; exactly one parity
 * matches the witness-program commitment (the other throws
 * WITNESS_PROGRAM_MISMATCH). Returns the result of the matching parity, or
 * rethrows the matching parity's error.
 */
function verifyAcrossParities(
  spend: ReturnType<typeof buildSingleLeafSpend>,
  flags: ScriptFlags,
  txContext?: { txVersion: number; txLockTime: number; txSequence: number }
): boolean {
  let lastNonMismatch: Error | undefined;
  for (const parity of spend.parities) {
    try {
      return verifyTaproot(
        spend.spk,
        spend.witnessFor(parity),
        flags,
        dummyTaprootCtx(),
        txContext
      );
    } catch (e) {
      const msg = (e as Error).message;
      if (msg.includes("WITNESS_PROGRAM_MISMATCH")) continue; // wrong parity
      lastNonMismatch = e as Error; // real failure on the committed leaf
    }
  }
  if (lastNonMismatch) throw lastNonMismatch;
  throw new Error("fixture broken: neither parity committed to the leaf");
}

describe("tapscript OP_CHECKLOCKTIMEVERIFY txContext threading (block 950149)", () => {
  // leaf: <950148> OP_CHECKLOCKTIMEVERIFY OP_DROP OP_1
  // CLTV does not pop its operand; OP_DROP clears it; OP_1 → clean true.
  const cltvLeaf = (): Buffer => {
    const operand = scriptNumEncode(BLOCK_950149_LOCKTIME);
    return Buffer.concat([
      Buffer.from([operand.length]), // push the operand
      operand,
      Buffer.from([
        Opcode.OP_CHECKLOCKTIMEVERIFY,
        Opcode.OP_DROP,
        Opcode.OP_1,
      ]),
    ]);
  };

  test("BUG: verifyTaproot WITHOUT txContext rejects a satisfiable tapscript CLTV", () => {
    const spend = buildSingleLeafSpend(cltvLeaf(), 0x11);
    // No txContext — the pre-fix tx.ts P2TR branch. executeTapscript sees
    // txLockTime === undefined and fail-safes.
    expect(() =>
      verifyAcrossParities(spend, consensusTaprootFlags(), undefined)
    ).toThrow(/UNSATISFIED_LOCKTIME/);
  });

  test("FIX: verifyTaproot WITH block-950149 txContext accepts the tapscript CLTV", () => {
    const spend = buildSingleLeafSpend(cltvLeaf(), 0x11);
    // Block-950149 shape: tx nLockTime 950148, input nSequence 0xfffffffd.
    const txContext = {
      txVersion: 1,
      txLockTime: BLOCK_950149_LOCKTIME,
      txSequence: SEQUENCE_NONFINAL,
    };
    const ok = verifyAcrossParities(spend, consensusTaprootFlags(), txContext);
    expect(ok).toBe(true);
  });

  test("CLTV still rejects when tx nLockTime is below the operand", () => {
    const spend = buildSingleLeafSpend(cltvLeaf(), 0x11);
    // operand 950148 > tx nLockTime 950147 → must fail (Core: nLockTime>txTo).
    const txContext = {
      txVersion: 1,
      txLockTime: BLOCK_950149_LOCKTIME - 1,
      txSequence: SEQUENCE_NONFINAL,
    };
    expect(() =>
      verifyAcrossParities(spend, consensusTaprootFlags(), txContext)
    ).toThrow(/UNSATISFIED_LOCKTIME/);
  });

  test("CLTV still rejects when the spending input is SEQUENCE_FINAL", () => {
    const spend = buildSingleLeafSpend(cltvLeaf(), 0x11);
    // nSequence 0xffffffff makes nLockTime ineffective → CLTV must fail
    // (Core: SEQUENCE_FINAL == txTo->vin[nIn].nSequence return false).
    const txContext = {
      txVersion: 1,
      txLockTime: BLOCK_950149_LOCKTIME,
      txSequence: 0xffffffff,
    };
    expect(() =>
      verifyAcrossParities(spend, consensusTaprootFlags(), txContext)
    ).toThrow(/UNSATISFIED_LOCKTIME/);
  });
});

describe("tapscript OP_CHECKSEQUENCEVERIFY txContext threading", () => {
  // leaf: <16> OP_CHECKSEQUENCEVERIFY OP_DROP OP_1
  // operand 16 = 16-block relative locktime, height-based (TYPE_FLAG clear).
  const CSV_OPERAND = 16;
  const csvLeaf = (): Buffer => {
    const operand = scriptNumEncode(CSV_OPERAND);
    return Buffer.concat([
      Buffer.from([operand.length]),
      operand,
      Buffer.from([
        Opcode.OP_CHECKSEQUENCEVERIFY,
        Opcode.OP_DROP,
        Opcode.OP_1,
      ]),
    ]);
  };

  test("BUG: verifyTaproot WITHOUT txContext rejects a satisfiable tapscript CSV", () => {
    const spend = buildSingleLeafSpend(csvLeaf(), 0x22);
    expect(() =>
      verifyAcrossParities(spend, consensusTaprootFlags(), undefined)
    ).toThrow(/UNSATISFIED_LOCKTIME/);
  });

  test("FIX: verifyTaproot WITH txContext (v2, seq>=operand) accepts the tapscript CSV", () => {
    const spend = buildSingleLeafSpend(csvLeaf(), 0x22);
    // CSV needs tx version >= 2; input nSequence (height-based) >= operand.
    const txContext = {
      txVersion: 2,
      txLockTime: 0,
      txSequence: 32, // height-based relative locktime 32 >= 16
    };
    const ok = verifyAcrossParities(spend, consensusTaprootFlags(), txContext);
    expect(ok).toBe(true);
  });

  test("CSV still rejects when tx version < 2", () => {
    const spend = buildSingleLeafSpend(csvLeaf(), 0x22);
    // BIP-68/112: CSV requires nVersion >= 2 unconditionally.
    const txContext = {
      txVersion: 1,
      txLockTime: 0,
      txSequence: 32,
    };
    expect(() =>
      verifyAcrossParities(spend, consensusTaprootFlags(), txContext)
    ).toThrow(/UNSATISFIED_LOCKTIME/);
  });

  test("CSV still rejects when the input nSequence is below the operand", () => {
    const spend = buildSingleLeafSpend(csvLeaf(), 0x22);
    // height-based relative locktime 8 < operand 16 → fail.
    const txContext = {
      txVersion: 2,
      txLockTime: 0,
      txSequence: 8,
    };
    expect(() =>
      verifyAcrossParities(spend, consensusTaprootFlags(), txContext)
    ).toThrow(/UNSATISFIED_LOCKTIME/);
  });
});

// ---------------------------------------------------------------------------
// End-to-end regression at the block-validation entry point.
//
// The two describe blocks above exercise `verifyTaproot` directly, which
// already threads txContext correctly — they prove the interpreter is sound.
// The actual block-950149 bug lived one layer up: `verifyInputSignature` in
// validation/tx.ts (the function the block connector calls per input) had a
// dedicated P2TR branch that invoked `verifyTaproot` WITHOUT building/passing
// txContext. These tests drive `verifyInputSignature` itself so a future
// regression that drops the txContext argument from the P2TR branch is caught.
// ---------------------------------------------------------------------------
describe("verifyInputSignature P2TR branch threads txContext (block 950149 regression)", () => {
  // Per-block consensus flag bitmask for height 950,149: every deployment is
  // active, so the mask carries each rule's OWN bit — exactly what
  // getScriptFlagsForBlock computes there (base P2SH|WITNESS|TAPROOT plus the
  // four height-gated ORs, Core validation.cpp:2262-2286).
  //
  // This previously passed only P2SH|WITNESS|TAPROOT and leaned on
  // scriptFlagsFromBitmask's "WITNESS implies CLTV/CSV/DERSIG/NULLDUMMY"
  // inference. That inference enforced BIP-66 from genesis and false-rejected
  // mainnet block 124276 on the AV=0 rig (SCRIPT_ERR_SIG_DER at height
  // 124,276; BIP-66 activates at 363,725), so it was removed — each rule is
  // honoured from its own bit only, and this fixture now names the bits the
  // real block-950149 mask carries.
  const CONSENSUS_FLAGS =
    TxScriptFlags.VERIFY_P2SH |
    TxScriptFlags.VERIFY_WITNESS |
    TxScriptFlags.VERIFY_TAPROOT |
    TxScriptFlags.VERIFY_DERSIG |
    TxScriptFlags.VERIFY_NULLDUMMY |
    TxScriptFlags.VERIFY_CHECKLOCKTIMEVERIFY |
    TxScriptFlags.VERIFY_CHECKSEQUENCEVERIFY;

  // tapscript leaf: <950148> OP_CHECKLOCKTIMEVERIFY OP_DROP OP_1
  const cltvLeafScript = (): Buffer => {
    const operand = scriptNumEncode(BLOCK_950149_LOCKTIME);
    return Buffer.concat([
      Buffer.from([operand.length]),
      operand,
      Buffer.from([Opcode.OP_CHECKLOCKTIMEVERIFY, Opcode.OP_DROP, Opcode.OP_1]),
    ]);
  };

  /**
   * Build a 1-in/1-out spending tx whose single input is a P2TR script-path
   * spend of `leafScript`, plus the matching prevout UTXOEntry. Picks the
   * control-block parity that commits to the leaf by trial-verifying.
   */
  function buildTapscriptSpend(
    leafScript: Buffer,
    nLockTime: number,
    nSequence: number,
    txVersion: number
  ): { tx: Transaction; utxo: UTXOEntry } {
    const internalPriv = Buffer.alloc(32, 0);
    internalPriv[31] = 0x33;
    const internalPub = privateKeyToXOnlyPubKey(internalPriv);
    const lenPrefix = encodeCompactSize(leafScript.length);
    const leafHash = taggedHash(
      "TapLeaf",
      Buffer.concat([
        Buffer.from([TAPROOT_LEAF_TAPSCRIPT]),
        lenPrefix,
        leafScript,
      ])
    );
    const tweak = taggedHash("TapTweak", Buffer.concat([internalPub, leafHash]));
    const outputKey = tweakPublicKey(internalPub, tweak);
    const spk = makeP2TR(outputKey);

    // Pick the parity whose control block commits to the leaf.
    let witness: Buffer[] | undefined;
    for (const parity of [0, 1]) {
      const w = [
        leafScript,
        Buffer.concat([
          Buffer.from([TAPROOT_LEAF_TAPSCRIPT | parity]),
          internalPub,
        ]),
      ];
      try {
        verifyTaproot(spk, w, consensusTaprootFlags(), dummyTaprootCtx(), {
          txVersion,
          txLockTime: nLockTime,
          txSequence: nSequence,
        });
        witness = w;
        break;
      } catch (e) {
        if ((e as Error).message.includes("WITNESS_PROGRAM_MISMATCH")) continue;
        // A non-mismatch error on the committed parity is still informative;
        // keep this witness so verifyInputSignature reproduces it.
        witness = w;
        break;
      }
    }
    if (!witness) throw new Error("fixture broken: no committing parity");

    const prevTxid = Buffer.alloc(32, 0xab);
    const tx: Transaction = {
      version: txVersion,
      inputs: [
        {
          prevOut: { txid: prevTxid, vout: 0 },
          scriptSig: Buffer.alloc(0), // P2TR: scriptSig MUST be empty
          sequence: nSequence >>> 0,
          witness,
        },
      ],
      outputs: [{ value: 1000n, scriptPubKey: Buffer.from([Opcode.OP_1]) }],
      lockTime: nLockTime >>> 0,
    };
    const utxo: UTXOEntry = {
      height: 700000,
      coinbase: false,
      amount: 10000n,
      scriptPubKey: spk,
    };
    return { tx, utxo };
  }

  test("accepts the block-950149 tapscript CLTV spend (operand == nLockTime, seq != FINAL)", () => {
    const { tx, utxo } = buildTapscriptSpend(
      cltvLeafScript(),
      BLOCK_950149_LOCKTIME,
      SEQUENCE_NONFINAL,
      1
    );
    const res = verifyInputSignature(
      tx,
      0,
      utxo,
      {},
      [utxo],
      {},
      CONSENSUS_FLAGS
    );
    // Pre-fix: { valid:false, error:"Taproot verify failed: ...UNSATISFIED_LOCKTIME" }
    // Post-fix: txContext is threaded → CLTV satisfied → valid.
    expect(res.error).toBeUndefined();
    expect(res.valid).toBe(true);
  });

  test("still rejects when the tapscript CLTV operand exceeds tx nLockTime", () => {
    // Sanity guard: the fix must not blanket-accept — an unsatisfied CLTV
    // (operand 950148 > nLockTime 950147) must still be rejected.
    const { tx, utxo } = buildTapscriptSpend(
      cltvLeafScript(),
      BLOCK_950149_LOCKTIME - 1,
      SEQUENCE_NONFINAL,
      1
    );
    const res = verifyInputSignature(
      tx,
      0,
      utxo,
      {},
      [utxo],
      {},
      CONSENSUS_FLAGS
    );
    expect(res.valid).toBe(false);
    expect(res.error).toMatch(/UNSATISFIED_LOCKTIME/);
  });
});
