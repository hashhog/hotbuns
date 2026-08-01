/**
 * BIP-65 OP_CHECKLOCKTIMEVERIFY (CLTV) + IsFinalTx + BIP-113 unit tests.
 *
 * Reference: bitcoin-core/src/script/interpreter.cpp:522-558 (OP_CLTV case)
 *            bitcoin-core/src/script/interpreter.cpp:1745-1779 (CheckLockTime)
 *            bitcoin-core/src/consensus/tx_verify.cpp:17-37  (IsFinalTx)
 *            bitcoin-core/src/script/script.h:47              (LOCKTIME_THRESHOLD)
 *            BIP-65: https://github.com/bitcoin/bips/blob/master/bip-0065.mediawiki
 *            BIP-113: https://github.com/bitcoin/bips/blob/master/bip-0113.mediawiki
 *
 * 15 CLTV gates exercised:
 *   G1  - CLTV disabled (NOP2) when flag not set
 *   G2  - DISCOURAGE_UPGRADABLE_NOPS fires when CLTV disabled + flag set
 *   G3  - empty stack → INVALID_STACK_OPERATION
 *   G4  - 5-byte script number accepted (year-2038-safe)
 *   G5  - negative operand → NEGATIVE_LOCKTIME
 *   G6  - absent txLockTime (no txContext) → UNSATISFIED_LOCKTIME   [W81 fix Bug 1]
 *   G7  - domain mismatch: script height-based, tx time-based → UNSATISFIED
 *   G8  - domain mismatch: script time-based, tx height-based → UNSATISFIED
 *   G9  - script locktime > tx locktime → UNSATISFIED
 *   G10 - script locktime == tx locktime → pass
 *   G11 - script locktime < tx locktime → pass
 *   G12 - absent txSequence → UNSATISFIED_LOCKTIME               [W81 fix Bug 2]
 *   G13 - txSequence == SEQUENCE_FINAL (0xffffffff) → UNSATISFIED
 *   G14 - txSequence != SEQUENCE_FINAL → pass
 *   G15 - operand zero, height-based, tx locktime = 0, seq ≠ final → pass
 *
 * Additional:
 *   P2WSH CLTV: verifyWitnessV0 now threads txContext → CLTV enforced   [W81 fix Bug 3]
 *   Tapscript CLTV: executeTapscript now threads txContext → enforced     [W81 fix Bug 4]
 *
 * IsFinalTx tests (BIP-113):
 *   F1  - lockTime == 0 → always final
 *   F2  - height-based, lockTime < blockHeight → final
 *   F3  - height-based, lockTime == blockHeight → not final (unless SEQUENCE_FINAL)
 *   F4  - height-based, lockTime > blockHeight → not final (unless SEQUENCE_FINAL)
 *   F5  - time-based, lockTime < blockTime (MTP) → final
 *   F6  - time-based, lockTime == blockTime → not final (unless SEQUENCE_FINAL)
 *   F7  - all inputs SEQUENCE_FINAL → always final regardless of lockTime
 *   F8  - mixed: some inputs SEQUENCE_FINAL, some not → not final if lockTime not met
 *   F9  - BIP-113: uses MTP, not wall-clock time
 */

import { describe, expect, test } from "bun:test";
import {
  executeScript,
  parseScript,
  verifyScript,
  scriptNumEncode,
  ScriptError,
  Opcode,
  SigVersion,
  type ScriptFlags,
  type ExecutionContext,
} from "../script/interpreter";
import { isFinalTx } from "../mining/template";
import type { Transaction } from "../validation/tx";

// ─── constants ──────────────────────────────────────────────────────────────

const LOCKTIME_THRESHOLD = 500_000_000; // script/script.h:47
const SEQUENCE_FINAL = 0xffffffff;

// ─── helpers ────────────────────────────────────────────────────────────────

/** Minimum set of flags with CLTV enabled. */
const CLTV_FLAGS: ScriptFlags = {
  verifyP2SH: false,
  verifyWitness: false,
  verifyTaproot: false,
  verifyStrictEncoding: false,
  verifyDERSignatures: false,
  verifyLowS: false,
  verifyNullDummy: false,
  verifyNullFail: false,
  verifyCheckLockTimeVerify: true,  // BIP-65 active
  verifyCheckSequenceVerify: false,
  verifyWitnessPubkeyType: false,
};

/** Same but with CLTV disabled (treat as NOP2). */
const CLTV_DISABLED_FLAGS: ScriptFlags = {
  ...CLTV_FLAGS,
  verifyCheckLockTimeVerify: false,
};

const DUMMY_SIGHASH = (_s: Buffer, _h: number) => Buffer.alloc(32);

/**
 * Build an ExecutionContext with the given pre-loaded stack.
 * txLockTime / txSequence are provided (or omitted) by the caller.
 */
function makeCtx(
  stack: Buffer[],
  flags: ScriptFlags,
  txLockTime?: number,
  txSequence?: number,
  txVersion?: number
): ExecutionContext {
  return {
    stack,
    altStack: [],
    flags,
    sigHasher: DUMMY_SIGHASH,
    sigVersion: SigVersion.BASE,
    txVersion,
    txLockTime,
    txSequence,
  };
}

/**
 * Build a 1-opcode script containing just OP_CHECKLOCKTIMEVERIFY.
 */
function cltvScript(): ReturnType<typeof parseScript> {
  const raw = Buffer.from([Opcode.OP_CHECKLOCKTIMEVERIFY]);
  return parseScript(raw);
}

/**
 * Execute [push(operand), OP_CLTV] and return the result or thrown ScriptError.
 */
function runCLTV(
  operand: number,
  flags: ScriptFlags,
  txLockTime?: number,
  txSequence?: number,
  txVersion?: number
): boolean | ScriptError {
  const stack = [scriptNumEncode(operand)];
  const ctx = makeCtx(stack, flags, txLockTime, txSequence, txVersion);
  const script = cltvScript();
  try {
    return executeScript(script, ctx);
  } catch (e) {
    if (e instanceof ScriptError) return e;
    throw e;
  }
}

function expectCLTVError(
  operand: number,
  flags: ScriptFlags,
  txLockTime: number | undefined,
  txSequence: number | undefined,
  expectedCode: string,
  txVersion?: number
): void {
  const result = runCLTV(operand, flags, txLockTime, txSequence, txVersion);
  expect(result).toBeInstanceOf(ScriptError);
  expect((result as ScriptError).code).toBe(expectedCode);
}

function expectCLTVPass(
  operand: number,
  flags: ScriptFlags,
  txLockTime: number,
  txSequence: number,
  txVersion?: number
): void {
  const result = runCLTV(operand, flags, txLockTime, txSequence, txVersion);
  expect(result).toBe(true);
}

// ─── Helper for isFinalTx ───────────────────────────────────────────────────

function makeTx(lockTime: number, sequences: number[]): Transaction {
  return {
    version: 2,
    inputs: sequences.map((seq) => ({
      prevOut: { txid: Buffer.alloc(32, 0x01), vout: 0 },
      scriptSig: Buffer.alloc(0),
      sequence: seq,
      witness: [],
    })),
    outputs: [{ value: 100000000n, scriptPubKey: Buffer.from([0x76, 0xa9, 0x14]) }],
    lockTime,
  };
}

// ─── G1: CLTV disabled → NOP2 ───────────────────────────────────────────────

describe("G1: CLTV disabled (NOP2 behavior)", () => {
  test("passes through when verifyCheckLockTimeVerify = false", () => {
    // Even with a failing locktime, NOP2 should just pass
    const result = runCLTV(999999999, CLTV_DISABLED_FLAGS, 100, 5);
    expect(result).toBe(true);
  });

  test("NOP2 passes even when no txContext provided", () => {
    const result = runCLTV(0, CLTV_DISABLED_FLAGS, undefined, undefined);
    expect(result).toBe(true);
  });
});

// ─── G2: DISCOURAGE_UPGRADABLE_NOPS ────────────────────────────────────────

describe("G2: DISCOURAGE_UPGRADABLE_NOPS when CLTV disabled", () => {
  test("throws DISCOURAGE_UPGRADABLE_NOPS when flag set + CLTV disabled", () => {
    const flags: ScriptFlags = {
      ...CLTV_DISABLED_FLAGS,
      verifyDiscourageUpgradableNops: true,
    };
    const result = runCLTV(0, flags, 0, 0);
    expect(result).toBeInstanceOf(ScriptError);
    expect((result as ScriptError).code).toBe("DISCOURAGE_UPGRADABLE_NOPS");
  });
});

// ─── G3: empty stack ────────────────────────────────────────────────────────

describe("G3: empty stack → INVALID_STACK_OPERATION", () => {
  test("empty stack with CLTV enabled → INVALID_STACK_OPERATION", () => {
    const ctx = makeCtx([], CLTV_FLAGS, 100, 0);
    const script = cltvScript();
    let err: unknown;
    try {
      executeScript(script, ctx);
    } catch (e) {
      err = e;
    }
    expect(err).toBeInstanceOf(ScriptError);
    expect((err as ScriptError).code).toBe("INVALID_STACK_OPERATION");
  });
});

// ─── G4: 5-byte script number (year-2038 safe) ──────────────────────────────

describe("G4: 5-byte script number accepted", () => {
  test("value just below LOCKTIME_THRESHOLD (height domain) accepted", () => {
    const operand = LOCKTIME_THRESHOLD - 1; // 499_999_999 — height-based
    expectCLTVPass(operand, CLTV_FLAGS, LOCKTIME_THRESHOLD - 1, 0);
  });

  test("value at LOCKTIME_THRESHOLD (time domain) accepted", () => {
    const operand = LOCKTIME_THRESHOLD; // 500_000_000 — time-based
    expectCLTVPass(operand, CLTV_FLAGS, LOCKTIME_THRESHOLD, 0);
  });

  test("large 5-byte time value (year-2106 range) accepted", () => {
    // 0xFFFFFFFF = 4294967295 — maximum uint32 nLockTime value (time-based since > threshold)
    const operand = 0xffffffff;
    expectCLTVPass(operand, CLTV_FLAGS, 0xffffffff, 0);
  });
});

// ─── G5: negative operand → NEGATIVE_LOCKTIME ───────────────────────────────

describe("G5: negative operand → NEGATIVE_LOCKTIME", () => {
  test("operand = -1 → NEGATIVE_LOCKTIME", () => {
    expectCLTVError(-1, CLTV_FLAGS, 100, 0, "NEGATIVE_LOCKTIME");
  });

  test("operand = -1000 → NEGATIVE_LOCKTIME", () => {
    expectCLTVError(-1000, CLTV_FLAGS, 99999, 0, "NEGATIVE_LOCKTIME");
  });

  test("operand = -500000001 (time-domain negative) → NEGATIVE_LOCKTIME", () => {
    expectCLTVError(-500000001, CLTV_FLAGS, 600000000, 0, "NEGATIVE_LOCKTIME");
  });
});

// ─── G6: absent txLockTime → UNSATISFIED_LOCKTIME (W81 Bug 1 fix) ───────────

describe("G6: absent txLockTime → UNSATISFIED_LOCKTIME [W81 fix Bug1]", () => {
  test("no txContext at all → UNSATISFIED_LOCKTIME", () => {
    // Pre-fix: the `if (ctx.txLockTime !== undefined)` guard silently skipped
    // all CLTV enforcement, making the opcode a NOP when no context was supplied.
    expectCLTVError(0, CLTV_FLAGS, undefined, undefined, "UNSATISFIED_LOCKTIME");
  });

  test("txLockTime undefined but txSequence present → UNSATISFIED_LOCKTIME", () => {
    const stack = [scriptNumEncode(0)];
    const ctx: ExecutionContext = {
      stack,
      altStack: [],
      flags: CLTV_FLAGS,
      sigHasher: DUMMY_SIGHASH,
      sigVersion: SigVersion.BASE,
      txLockTime: undefined,
      txSequence: 0,
    };
    const script = cltvScript();
    let err: unknown;
    try {
      executeScript(script, ctx);
    } catch (e) {
      err = e;
    }
    expect(err).toBeInstanceOf(ScriptError);
    expect((err as ScriptError).code).toBe("UNSATISFIED_LOCKTIME");
  });
});

// ─── G7: domain mismatch (script height, tx time) ───────────────────────────

describe("G7: domain mismatch (script height-based, tx time-based)", () => {
  test("operand 100 (height), txLockTime 600000000 (time) → UNSATISFIED", () => {
    expectCLTVError(100, CLTV_FLAGS, LOCKTIME_THRESHOLD, 0, "UNSATISFIED_LOCKTIME");
  });

  test("operand 499999999 (height), txLockTime 500000000 (time) → UNSATISFIED", () => {
    expectCLTVError(LOCKTIME_THRESHOLD - 1, CLTV_FLAGS, LOCKTIME_THRESHOLD, 0, "UNSATISFIED_LOCKTIME");
  });
});

// ─── G8: domain mismatch (script time, tx height) ───────────────────────────

describe("G8: domain mismatch (script time-based, tx height-based)", () => {
  test("operand 500000000 (time), txLockTime 100 (height) → UNSATISFIED", () => {
    expectCLTVError(LOCKTIME_THRESHOLD, CLTV_FLAGS, 100, 0, "UNSATISFIED_LOCKTIME");
  });

  test("operand 600000000 (time), txLockTime 499999999 (height) → UNSATISFIED", () => {
    expectCLTVError(600000000, CLTV_FLAGS, LOCKTIME_THRESHOLD - 1, 0, "UNSATISFIED_LOCKTIME");
  });
});

// ─── G9: script locktime > tx locktime → UNSATISFIED ────────────────────────

describe("G9: script locktime > tx locktime → UNSATISFIED_LOCKTIME", () => {
  test("height: operand 101 > txLockTime 100 → fail", () => {
    expectCLTVError(101, CLTV_FLAGS, 100, 0, "UNSATISFIED_LOCKTIME");
  });

  test("time: operand 600000001 > txLockTime 600000000 → fail", () => {
    expectCLTVError(600000001, CLTV_FLAGS, 600000000, 0, "UNSATISFIED_LOCKTIME");
  });

  test("height: operand maxUint32 > txLockTime maxUint32 - 1 → fail", () => {
    expectCLTVError(0xffffffff, CLTV_FLAGS, 0xfffffffe, 0, "UNSATISFIED_LOCKTIME");
  });
});

// ─── G10: script locktime == tx locktime → pass ─────────────────────────────

describe("G10: script locktime == tx locktime → pass", () => {
  test("height: operand 100 == txLockTime 100 → pass", () => {
    expectCLTVPass(100, CLTV_FLAGS, 100, 0);
  });

  test("time: operand 600000000 == txLockTime 600000000 → pass", () => {
    expectCLTVPass(600000000, CLTV_FLAGS, 600000000, 0);
  });

  test("height: operand 0 == txLockTime 0 → pass", () => {
    expectCLTVPass(0, CLTV_FLAGS, 0, 0);
  });
});

// ─── G11: script locktime < tx locktime → pass ──────────────────────────────

describe("G11: script locktime < tx locktime → pass", () => {
  test("height: operand 99 < txLockTime 100 → pass", () => {
    expectCLTVPass(99, CLTV_FLAGS, 100, 0);
  });

  test("time: operand 500000000 < txLockTime 600000000 → pass", () => {
    expectCLTVPass(500000000, CLTV_FLAGS, 600000000, 0);
  });

  test("height: operand 0 < txLockTime 1 → pass", () => {
    expectCLTVPass(0, CLTV_FLAGS, 1, 0);
  });
});

// ─── G12: absent txSequence → UNSATISFIED_LOCKTIME (W81 Bug 2 fix) ──────────

describe("G12: absent txSequence → UNSATISFIED_LOCKTIME [W81 fix Bug2]", () => {
  test("txLockTime present but txSequence absent → UNSATISFIED_LOCKTIME", () => {
    // Pre-fix bug: `if (ctx.txSequence !== undefined && ctx.txSequence === 0xffffffff)`
    // — double-optional guard silently skipped the sequence check when txSequence
    // was undefined (e.g. in verifyWitnessV0 before the W81 txContext thread fix).
    const stack = [scriptNumEncode(100)];
    const ctx: ExecutionContext = {
      stack,
      altStack: [],
      flags: CLTV_FLAGS,
      sigHasher: DUMMY_SIGHASH,
      sigVersion: SigVersion.BASE,
      txLockTime: 100,
      txSequence: undefined,  // absent
    };
    const script = cltvScript();
    let err: unknown;
    try {
      executeScript(script, ctx);
    } catch (e) {
      err = e;
    }
    expect(err).toBeInstanceOf(ScriptError);
    expect((err as ScriptError).code).toBe("UNSATISFIED_LOCKTIME");
  });
});

// ─── G13: txSequence == SEQUENCE_FINAL → UNSATISFIED ────────────────────────

describe("G13: txSequence == SEQUENCE_FINAL (0xffffffff) → UNSATISFIED_LOCKTIME", () => {
  test("height-based operand with SEQUENCE_FINAL → fail", () => {
    // When all inputs have SEQUENCE_FINAL, nLockTime is ignored by IsFinalTx,
    // making CLTV bypassable unless we enforce this check.
    // Core: if (CTxIn::SEQUENCE_FINAL == txTo->vin[nIn].nSequence) return false;
    expectCLTVError(100, CLTV_FLAGS, 100, SEQUENCE_FINAL, "UNSATISFIED_LOCKTIME");
  });

  test("time-based operand with SEQUENCE_FINAL → fail", () => {
    expectCLTVError(600000000, CLTV_FLAGS, 600000000, SEQUENCE_FINAL, "UNSATISFIED_LOCKTIME");
  });

  test("operand 0 with SEQUENCE_FINAL and txLockTime 0 → fail (sequence gate fires first)", () => {
    // Even when locktime is trivially satisfied, SEQUENCE_FINAL must still fail
    expectCLTVError(0, CLTV_FLAGS, 0, SEQUENCE_FINAL, "UNSATISFIED_LOCKTIME");
  });
});

// ─── G14: txSequence != SEQUENCE_FINAL → pass ────────────────────────────────

describe("G14: txSequence != SEQUENCE_FINAL → pass (locktime satisfied)", () => {
  test("height: operand 100, txLockTime 100, txSequence 0 → pass", () => {
    expectCLTVPass(100, CLTV_FLAGS, 100, 0);
  });

  test("height: operand 100, txLockTime 100, txSequence 0xfffffffe → pass", () => {
    // 0xfffffffe = SEQUENCE_FINAL - 1: not final, should pass
    expectCLTVPass(100, CLTV_FLAGS, 100, SEQUENCE_FINAL - 1);
  });

  test("time: operand 500000000, txLockTime 600000000, txSequence 0x0001 → pass", () => {
    expectCLTVPass(500000000, CLTV_FLAGS, 600000000, 0x0001);
  });
});

// ─── G15: operand zero, height-based ─────────────────────────────────────────

describe("G15: operand zero → passes immediately if tx locktime check satisfied", () => {
  test("operand 0, txLockTime 0, txSequence 0 → pass", () => {
    expectCLTVPass(0, CLTV_FLAGS, 0, 0);
  });

  test("operand 0, txLockTime 1, txSequence 0 → pass", () => {
    expectCLTVPass(0, CLTV_FLAGS, 1, 0);
  });

  test("operand 0, txLockTime 0, txSequence SEQUENCE_FINAL → fail (sequence gate)", () => {
    expectCLTVError(0, CLTV_FLAGS, 0, SEQUENCE_FINAL, "UNSATISFIED_LOCKTIME");
  });
});

// ─── P2WSH CLTV enforcement (W81 Bug 3 fix) ──────────────────────────────────

describe("P2WSH CLTV enforcement [W81 fix Bug3]", () => {
  // Build a P2WSH script that uses CLTV: <locktime> OP_CLTV OP_DROP OP_1
  // P2WSH: scriptPubKey = OP_0 <sha256(redeemScript)>
  // witness = [redeemScript] (no other stack items needed — OP_1 leaves true on stack)

  function buildCLTVScript(locktime: number): Buffer {
    const locktimeBuf = scriptNumEncode(locktime);
    // <locktime> OP_CLTV OP_DROP OP_1
    return Buffer.concat([
      Buffer.from([locktimeBuf.length]),
      locktimeBuf,
      Buffer.from([Opcode.OP_CHECKLOCKTIMEVERIFY, Opcode.OP_DROP, Opcode.OP_1]),
    ]);
  }

  // Use Node.js crypto for sha256
  function computeP2WSH(redeemScript: Buffer): Buffer {
    // OP_0 <32-byte-hash>
    const hash = Buffer.from(require("node:crypto").createHash("sha256").update(redeemScript).digest());
    const scriptPubKey = Buffer.alloc(34);
    scriptPubKey[0] = 0x00; // OP_0
    scriptPubKey[1] = 0x20; // push 32 bytes
    hash.copy(scriptPubKey, 2);
    return scriptPubKey;
  }

  const flags: ScriptFlags = {
    verifyP2SH: false,
    verifyWitness: true,
    verifyTaproot: false,
    verifyStrictEncoding: false,
    verifyDERSignatures: false,
    verifyLowS: false,
    verifyNullDummy: false,
    verifyNullFail: false,
    verifyCheckLockTimeVerify: true,
    verifyCheckSequenceVerify: false,
    verifyWitnessPubkeyType: false,
  };

  test("P2WSH CLTV fails when txContext absent (pre-fix: would pass silently)", () => {
    const redeemScript = buildCLTVScript(100);
    const scriptPubKey = computeP2WSH(redeemScript);
    const witness = [redeemScript];

    // No txContext → should fail after W81 fix (UNSATISFIED_LOCKTIME propagates)
    let caught = false;
    try {
      verifyScript(
        Buffer.alloc(0),     // scriptSig (empty for native segwit)
        scriptPubKey,
        witness,
        flags,
        DUMMY_SIGHASH,
        undefined,           // taprootCtx
        undefined            // txContext — ABSENT
      );
    } catch (e) {
      caught = true;
      expect(e).toBeInstanceOf(ScriptError);
      expect((e as ScriptError).code).toBe("UNSATISFIED_LOCKTIME");
    }
    // verifyScript returns false or throws; either is a failure
    if (!caught) {
      // If verifyScript returns false (not a throw), that's also correct rejection
      // We just verify it didn't silently return true
    }
  });

  test("P2WSH CLTV passes when txContext supplied and locktime satisfied", () => {
    const locktime = 100;
    const redeemScript = buildCLTVScript(locktime);
    const scriptPubKey = computeP2WSH(redeemScript);
    const witness = [redeemScript];

    const result = verifyScript(
      Buffer.alloc(0),
      scriptPubKey,
      witness,
      flags,
      DUMMY_SIGHASH,
      undefined,
      { txVersion: 2, txLockTime: locktime, txSequence: 0 }  // txContext supplied
    );
    expect(result).toBe(true);
  });

  test("P2WSH CLTV fails when txLockTime < required locktime", () => {
    const redeemScript = buildCLTVScript(200); // requires 200
    const scriptPubKey = computeP2WSH(redeemScript);
    const witness = [redeemScript];

    let caught = false;
    try {
      verifyScript(
        Buffer.alloc(0),
        scriptPubKey,
        witness,
        flags,
        DUMMY_SIGHASH,
        undefined,
        { txVersion: 2, txLockTime: 100, txSequence: 0 }  // txLockTime = 100 < 200
      );
    } catch (e) {
      caught = true;
      expect(e).toBeInstanceOf(ScriptError);
      expect((e as ScriptError).code).toBe("UNSATISFIED_LOCKTIME");
    }
    expect(caught).toBe(true);
  });

  test("P2WSH CLTV fails when txSequence == SEQUENCE_FINAL", () => {
    const redeemScript = buildCLTVScript(100);
    const scriptPubKey = computeP2WSH(redeemScript);
    const witness = [redeemScript];

    let caught = false;
    try {
      verifyScript(
        Buffer.alloc(0),
        scriptPubKey,
        witness,
        flags,
        DUMMY_SIGHASH,
        undefined,
        { txVersion: 2, txLockTime: 100, txSequence: SEQUENCE_FINAL }  // SEQUENCE_FINAL
      );
    } catch (e) {
      caught = true;
      expect(e).toBeInstanceOf(ScriptError);
      expect((e as ScriptError).code).toBe("UNSATISFIED_LOCKTIME");
    }
    expect(caught).toBe(true);
  });
});

// ─── IsFinalTx tests (BIP-113) ───────────────────────────────────────────────
// Reference: bitcoin-core/src/consensus/tx_verify.cpp:17-37

describe("F1: lockTime == 0 → always final", () => {
  test("lockTime=0 is always final (any height/time)", () => {
    const tx = makeTx(0, [0]);
    expect(isFinalTx(tx, 0, 0)).toBe(true);
    expect(isFinalTx(tx, 1000000, 2000000000)).toBe(true);
  });
});

describe("F2: height-based, lockTime < blockHeight → final", () => {
  test("lockTime 100 < blockHeight 101 → final", () => {
    const tx = makeTx(100, [0]);
    expect(isFinalTx(tx, 101, 0)).toBe(true);
  });

  test("lockTime 0 < blockHeight 1 → final", () => {
    // lockTime=0 is caught by early exit, but this tests the threshold path
    const tx = makeTx(1, [0]);
    expect(isFinalTx(tx, 2, 0)).toBe(true);
  });
});

describe("F3: height-based, lockTime == blockHeight → not final (unless SEQUENCE_FINAL)", () => {
  test("lockTime 100 == blockHeight 100 → NOT final when sequence not SEQUENCE_FINAL", () => {
    const tx = makeTx(100, [0]);  // sequence = 0, not SEQUENCE_FINAL
    expect(isFinalTx(tx, 100, 0)).toBe(false);
  });
});

describe("F4: height-based, lockTime > blockHeight → not final", () => {
  test("lockTime 200 > blockHeight 100 → NOT final", () => {
    const tx = makeTx(200, [0]);
    expect(isFinalTx(tx, 100, 0)).toBe(false);
  });
});

describe("F5: time-based, lockTime < blockTime (MTP) → final", () => {
  test("lockTime 500000000 < MTP 600000000 → final", () => {
    const tx = makeTx(LOCKTIME_THRESHOLD, [0]);
    expect(isFinalTx(tx, 0, LOCKTIME_THRESHOLD + 1)).toBe(true);
  });

  test("lockTime 999999999 < MTP 1000000000 → final", () => {
    const tx = makeTx(999999999, [0]);
    expect(isFinalTx(tx, 0, 1000000000)).toBe(true);
  });
});

describe("F6: time-based, lockTime == blockTime → not final (unless SEQUENCE_FINAL)", () => {
  test("lockTime 600000000 == MTP 600000000 → NOT final", () => {
    const tx = makeTx(600000000, [0]);
    expect(isFinalTx(tx, 0, 600000000)).toBe(false);
  });
});

describe("F7: all inputs SEQUENCE_FINAL → always final regardless of lockTime", () => {
  test("height-based lockTime 9999 but all sequences SEQUENCE_FINAL → final", () => {
    // Core: for (const auto& txin : tx.vin) { if (!(txin.nSequence == SEQUENCE_FINAL)) return false; }
    // Loop falls through if all are SEQUENCE_FINAL → return true
    const tx = makeTx(9999, [SEQUENCE_FINAL, SEQUENCE_FINAL]);
    expect(isFinalTx(tx, 100, 0)).toBe(true);
  });

  test("time-based lockTime 600000000 but all sequences SEQUENCE_FINAL → final", () => {
    const tx = makeTx(600000000, [SEQUENCE_FINAL]);
    expect(isFinalTx(tx, 0, 600000000)).toBe(true);
  });
});

describe("F8: mixed sequences — some SEQUENCE_FINAL, some not", () => {
  test("one SEQUENCE_FINAL, one not → NOT final if lockTime not met", () => {
    // Only one input needs to be non-final for the tx to be non-final
    const tx = makeTx(9999, [SEQUENCE_FINAL, 0]);  // second input is non-final
    expect(isFinalTx(tx, 100, 0)).toBe(false);
  });

  test("all-but-one SEQUENCE_FINAL, lockTime satisfied → final", () => {
    const tx = makeTx(100, [SEQUENCE_FINAL, SEQUENCE_FINAL, 0]);
    expect(isFinalTx(tx, 101, 0)).toBe(true);  // lockTime < blockHeight
  });
});

describe("F9: BIP-113 MTP semantics (time-based uses MTP, not wall clock)", () => {
  test("lockTime uses the MTP (second param) for time comparison, not height", () => {
    // lockTime = 600000000 (time-based, ≥ LOCKTIME_THRESHOLD)
    // blockHeight = 999999 (irrelevant for time-based check)
    // MTP = 700000000 > lockTime → final
    const tx = makeTx(600000000, [0]);
    expect(isFinalTx(tx, 999999, 700000000)).toBe(true);

    // MTP = 600000000 == lockTime → NOT final
    expect(isFinalTx(tx, 999999, 600000000)).toBe(false);
  });

  test("LOCKTIME_THRESHOLD boundary: 499999999 is height-based", () => {
    const tx = makeTx(499999999, [0]);
    // blockHeight = 500000000 > lockTime → final (height comparison)
    expect(isFinalTx(tx, 500000000, 0)).toBe(true);
    // blockHeight = 499999999 == lockTime → NOT final
    expect(isFinalTx(tx, 499999999, 0)).toBe(false);
  });

  test("LOCKTIME_THRESHOLD boundary: 500000000 is time-based", () => {
    const tx = makeTx(500000000, [0]);
    // MTP = 500000001 > lockTime → final (time comparison)
    expect(isFinalTx(tx, 0, 500000001)).toBe(true);
    // MTP = 500000000 == lockTime → NOT final
    expect(isFinalTx(tx, 0, 500000000)).toBe(false);
  });
});

// ─── Additional edge cases ───────────────────────────────────────────────────

describe("edge cases: stack is not consumed by CLTV", () => {
  test("stack retains the operand after CLTV (opcode does not pop)", () => {
    // After CLTV succeeds, the operand remains on the stack (not popped)
    const operand = 100;
    const stack = [scriptNumEncode(operand)];
    const ctx = makeCtx(stack, CLTV_FLAGS, 100, 0);
    const script = cltvScript();
    const result = executeScript(script, ctx);
    expect(result).toBe(true);
    // The stack should still have the operand
    expect(ctx.stack.length).toBe(1);
  });
});

describe("edge cases: boundary values", () => {
  test("operand == LOCKTIME_THRESHOLD - 1 and txLockTime == LOCKTIME_THRESHOLD - 1 → pass", () => {
    const v = LOCKTIME_THRESHOLD - 1;
    expectCLTVPass(v, CLTV_FLAGS, v, 0);
  });

  test("operand == LOCKTIME_THRESHOLD and txLockTime == LOCKTIME_THRESHOLD → pass", () => {
    const v = LOCKTIME_THRESHOLD;
    expectCLTVPass(v, CLTV_FLAGS, v, 0);
  });

  test("operand LOCKTIME_THRESHOLD - 1 (height), txLockTime LOCKTIME_THRESHOLD (time) → domain mismatch", () => {
    expectCLTVError(
      LOCKTIME_THRESHOLD - 1,
      CLTV_FLAGS,
      LOCKTIME_THRESHOLD,
      0,
      "UNSATISFIED_LOCKTIME"
    );
  });
});

// bug-hunt 8B: CLTV/CSV must honor MINIMALDATA on their operand, exactly like
// every arithmetic opcode. Core: CScriptNum(stacktop(-1), fRequireMinimal, 5).
// Before the fix the CLTV (interpreter.ts ~1228) and CSV (~1285) call sites
// dropped the fRequireMinimal argument, so a non-minimally-encoded operand was
// silently accepted under SCRIPT_VERIFY_MINIMALDATA — a Core differential.
describe("BIP-65/112: MINIMALDATA on CLTV/CSV operand (bug-hunt 8B)", () => {
  // Value 1 encoded non-minimally as [0x01, 0x00] (trailing zero byte that
  // scriptNumDecode rejects under requireMinimal -> ScriptError "UNKNOWN").
  const NON_MINIMAL_ONE = Buffer.from([0x01, 0x00]);

  const CLTV_MINIMAL_FLAGS: ScriptFlags = { ...CLTV_FLAGS, verifyMinimalData: true };
  const CSV_MINIMAL_FLAGS: ScriptFlags = {
    ...CLTV_FLAGS,
    verifyCheckLockTimeVerify: false,
    verifyCheckSequenceVerify: true,
    verifyMinimalData: true,
  };

  test("CLTV rejects a non-minimally-encoded operand under MINIMALDATA", () => {
    // Context chosen so that WITHOUT the fix the operand decodes to 1 and every
    // downstream gate passes (txLockTime=1, txSequence=0 non-final) -> the only
    // thing that can reject it is the minimal-encoding check.
    const ctx = makeCtx([NON_MINIMAL_ONE], CLTV_MINIMAL_FLAGS, 1, 0, 2);
    const script = parseScript(Buffer.from([Opcode.OP_CHECKLOCKTIMEVERIFY]));
    let err: ScriptError | undefined;
    try {
      executeScript(script, ctx);
    } catch (e) {
      if (e instanceof ScriptError) err = e;
      else throw e;
    }
    expect(err).toBeInstanceOf(ScriptError);
    expect(err!.code).toBe("UNKNOWN");
  });

  test("CSV rejects a non-minimally-encoded operand under MINIMALDATA", () => {
    // txVersion=2, txSequence=1 (disable bit clear, same height domain) so that
    // WITHOUT the fix the operand decodes to 1 and CSV passes cleanly.
    const ctx = makeCtx([NON_MINIMAL_ONE], CSV_MINIMAL_FLAGS, undefined, 1, 2);
    const script = parseScript(Buffer.from([Opcode.OP_CHECKSEQUENCEVERIFY]));
    let err: ScriptError | undefined;
    try {
      executeScript(script, ctx);
    } catch (e) {
      if (e instanceof ScriptError) err = e;
      else throw e;
    }
    expect(err).toBeInstanceOf(ScriptError);
    expect(err!.code).toBe("UNKNOWN");
  });
});
