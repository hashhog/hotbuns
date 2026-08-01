/**
 * BIP-112 OP_CHECKSEQUENCEVERIFY (CSV) opcode unit tests.
 *
 * Reference: bitcoin-core/src/script/interpreter.cpp:561-593 (OP_CSV case)
 *            bitcoin-core/src/script/interpreter.cpp:1782-1826 (CheckSequence)
 *            BIP-112: https://github.com/bitcoin/bips/blob/master/bip-0112.mediawiki
 *
 * 21 gates exercised:
 *   G1  - CSV disabled (NOP3) when flag not set
 *   G2  - empty stack → INVALID_STACK_OPERATION
 *   G3  - negative operand → NEGATIVE_LOCKTIME
 *   G4  - disable-flag (bit 31) on operand → NOP (pass through)
 *   G5  - tx version < 2 → UNSATISFIED_LOCKTIME
 *   G6  - absent txVersion → UNSATISFIED_LOCKTIME
 *   G7  - absent txSequence → UNSATISFIED_LOCKTIME
 *   G8  - input sequence has disable flag (bit 31) → UNSATISFIED_LOCKTIME
 *   G9  - type mismatch (operand height-based, input time-based) → UNSATISFIED
 *   G10 - type mismatch (operand time-based, input height-based) → UNSATISFIED
 *   G11 - operand masked value > input masked value → UNSATISFIED
 *   G12 - operand masked value == input masked value → pass
 *   G13 - operand masked value < input masked value → pass
 *   G14 - both time-based, operand == input → pass
 *   G15 - both time-based, operand > input → fail
 *   G16 - zero operand → pass (immediately spendable)
 *   G17 - max mask value (0xffff) height, input exactly matches → pass
 *   G18 - 5-byte operand with bit 31 set → NOP (disable flag)
 *   G19 - SEQUENCE_FINAL (0xffffffff) as input sequence → fail (disable flag set)
 *   G20 - tx v2, sequence 0x0000000a (10 blocks), operand 10 → pass
 *   G21 - tx v2, sequence 0x00400005 (5 * 512s), operand same → pass
 */

import { describe, expect, test } from "bun:test";
import {
  executeScript,
  parseScript,
  scriptNumEncode,
  ScriptError,
  Opcode,
  SigVersion,
  type ScriptFlags,
  type ExecutionContext,
} from "../script/interpreter";

// ─── helpers ────────────────────────────────────────────────────────────────

/** Minimum set of flags with CSV enabled. */
const CSV_FLAGS: ScriptFlags = {
  verifyP2SH: false,
  verifyWitness: false,
  verifyTaproot: false,
  verifyStrictEncoding: false,
  verifyDERSignatures: false,
  verifyLowS: false,
  verifyNullDummy: false,
  verifyNullFail: false,
  verifyCheckLockTimeVerify: false,
  verifyCheckSequenceVerify: true, // BIP-112 active
  verifyWitnessPubkeyType: false,
};

/** Same but with CSV disabled (treat as NOP3). */
const CSV_DISABLED_FLAGS: ScriptFlags = {
  ...CSV_FLAGS,
  verifyCheckSequenceVerify: false,
};

const DUMMY_SIGHASH = (_s: Buffer, _h: number) => Buffer.alloc(32);

/**
 * Build an ExecutionContext with the given pre-loaded stack.
 * txVersion/txSequence are provided (or omitted) by the caller.
 */
function makeCtx(
  stack: Buffer[],
  flags: ScriptFlags,
  txVersion?: number,
  txSequence?: number
): ExecutionContext {
  return {
    stack,
    altStack: [],
    flags,
    sigHasher: DUMMY_SIGHASH,
    sigVersion: SigVersion.BASE,
    txVersion,
    txSequence,
  };
}

/**
 * Build a 1-opcode script containing just OP_CHECKSEQUENCEVERIFY.
 */
function csvScript(): ReturnType<typeof parseScript> {
  const raw = Buffer.from([Opcode.OP_CHECKSEQUENCEVERIFY]);
  return parseScript(raw);
}

/**
 * Execute [push(operand), OP_CSV] with the given tx context.
 * Returns the executeScript result (true) or the thrown ScriptError.
 */
function runCSV(
  operand: number,
  flags: ScriptFlags,
  txVersion?: number,
  txSequence?: number
): boolean | ScriptError {
  // Build script: <operand> OP_CSV OP_1  (OP_1 so final stack top is truthy)
  // Actually executeScript just runs the given script and returns bool based on
  // whether execution completes without error. We just run OP_CSV directly.
  const stack = [scriptNumEncode(operand)];
  const ctx = makeCtx(stack, flags, txVersion, txSequence);
  const script = csvScript();
  try {
    const result = executeScript(script, ctx);
    return result;
  } catch (e) {
    if (e instanceof ScriptError) return e;
    throw e;
  }
}

/** Convenience: assert that runCSV throws a specific ScriptError code.
 *  ScriptError.code is the raw string (e.g. "UNSATISFIED_LOCKTIME");
 *  ScriptError.message is "SCRIPT_ERR_UNSATISFIED_LOCKTIME".
 */
function expectCSVError(
  operand: number,
  flags: ScriptFlags,
  txVersion: number | undefined,
  txSequence: number | undefined,
  expectedCode: string
): void {
  const result = runCSV(operand, flags, txVersion, txSequence);
  expect(result).toBeInstanceOf(ScriptError);
  expect((result as ScriptError).code).toBe(expectedCode);
}

// ─── constants ──────────────────────────────────────────────────────────────

const SEQUENCE_FINAL = 0xffffffff;
const SEQUENCE_LOCKTIME_DISABLE_FLAG = 0x80000000; // 1 << 31 (unsigned)
const SEQUENCE_LOCKTIME_TYPE_FLAG = 0x00400000;    // 1 << 22
const SEQUENCE_LOCKTIME_MASK = 0x0000ffff;

// ─── G1: CSV disabled → NOP3 ────────────────────────────────────────────────

describe("G1: CSV disabled (NOP3 behavior)", () => {
  test("passes through when verifyCheckSequenceVerify = false", () => {
    // Even with a v1 tx and failing operand, NOP3 should just pass
    const result = runCSV(100, CSV_DISABLED_FLAGS, 1, 5);
    // executeScript returns true (stack still has the operand on it, but we
    // don't check cleanstack here)
    expect(result).toBe(true);
  });

  test("respects discourageUpgradableNops when CSV disabled", () => {
    const flags: ScriptFlags = {
      ...CSV_DISABLED_FLAGS,
      verifyDiscourageUpgradableNops: true,
    };
    const result = runCSV(0, flags, 2, 0);
    expect(result).toBeInstanceOf(ScriptError);
    expect((result as ScriptError).code).toBe("DISCOURAGE_UPGRADABLE_NOPS");
  });
});

// ─── G2: empty stack ────────────────────────────────────────────────────────

describe("G2: empty stack → INVALID_STACK_OPERATION", () => {
  test("throws INVALID_STACK_OPERATION on empty stack", () => {
    const ctx = makeCtx([], CSV_FLAGS, 2, 0);
    const script = csvScript();
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

// ─── G3: negative operand ───────────────────────────────────────────────────

describe("G3: negative operand → NEGATIVE_LOCKTIME", () => {
  test("throws NEGATIVE_LOCKTIME for operand = -1", () => {
    expectCSVError(-1, CSV_FLAGS, 2, 10, "NEGATIVE_LOCKTIME");
  });

  test("throws NEGATIVE_LOCKTIME for operand = -1000", () => {
    expectCSVError(-1000, CSV_FLAGS, 2, 0x10000, "NEGATIVE_LOCKTIME");
  });
});

// ─── G4: operand has disable flag → NOP ─────────────────────────────────────

describe("G4: operand has bit 31 set → NOP (BIP-112 §3)", () => {
  test("operand 0x80000000 → NOP, passes even with v1 tx", () => {
    // 0x80000000 as a script number is 2147483648
    const result = runCSV(0x80000000, CSV_FLAGS, 1, 0);
    expect(result).toBe(true);
  });

  test("operand 0x80000001 → NOP", () => {
    const result = runCSV(0x80000001, CSV_FLAGS, 2, 0);
    expect(result).toBe(true);
  });

  test("operand SEQUENCE_FINAL (0xffffffff) → NOP (bit 31 set)", () => {
    // 0xffffffff has bit 31 set, so it's a NOP
    const result = runCSV(SEQUENCE_FINAL, CSV_FLAGS, 1, 0);
    expect(result).toBe(true);
  });
});

// ─── G5: tx version < 2 → UNSATISFIED_LOCKTIME ──────────────────────────────

describe("G5: tx version < 2 → UNSATISFIED_LOCKTIME", () => {
  test("v1 tx with height-based operand 0 → UNSATISFIED_LOCKTIME", () => {
    // Even operand=0 fails if tx is v1
    expectCSVError(0, CSV_FLAGS, 1, 0xffff, "UNSATISFIED_LOCKTIME");
  });

  test("v1 tx with time-based operand → UNSATISFIED_LOCKTIME", () => {
    const timeSeq = SEQUENCE_LOCKTIME_TYPE_FLAG | 10;
    expectCSVError(timeSeq, CSV_FLAGS, 1, SEQUENCE_FINAL - 1, "UNSATISFIED_LOCKTIME");
  });

  test("v0 tx fails (below v2 threshold)", () => {
    expectCSVError(0, CSV_FLAGS, 0, 0xffff, "UNSATISFIED_LOCKTIME");
  });

  test("negative version (-1) is uint32 0xffffffff in Core → version gate passes", () => {
    // Core's CTransaction::version is uint32_t (primitives/transaction.h:293),
    // so CheckSequence's `txTo->version < 2` is an UNSIGNED comparison
    // (interpreter.cpp:1790): a wire version of 0xffffffff — deserialized as
    // -1 by the signed readInt32LE — is 4294967295 >= 2 and does NOT trigger
    // UNSATISFIED_LOCKTIME. With a satisfiable operand (5 <= 0xffff) the CSV
    // then passes. (tx_valid.json vector 165 covers the 0xffffffff case.)
    expect(runCSV(5, CSV_FLAGS, -1, 0xffff)).toBe(true);
  });
});

// ─── G6: absent txVersion → UNSATISFIED_LOCKTIME ────────────────────────────

describe("G6: txVersion absent in context → UNSATISFIED_LOCKTIME", () => {
  test("no txContext at all → UNSATISFIED_LOCKTIME", () => {
    // This was the pre-fix bug: missing context silently passed
    expectCSVError(10, CSV_FLAGS, undefined, 0xffff, "UNSATISFIED_LOCKTIME");
  });

  test("txVersion undefined but txSequence present → UNSATISFIED_LOCKTIME", () => {
    expectCSVError(0, CSV_FLAGS, undefined, 0x00010000, "UNSATISFIED_LOCKTIME");
  });
});

// ─── G7: absent txSequence → UNSATISFIED_LOCKTIME ────────────────────────────

describe("G7: txSequence absent in context → UNSATISFIED_LOCKTIME", () => {
  test("txVersion=2 but no txSequence → UNSATISFIED_LOCKTIME", () => {
    // This was the pre-fix bug: missing sequence silently passed all comparisons
    expectCSVError(10, CSV_FLAGS, 2, undefined, "UNSATISFIED_LOCKTIME");
  });
});

// ─── G8: input sequence has disable flag → UNSATISFIED_LOCKTIME ─────────────

describe("G8: input sequence disable flag (bit 31) → UNSATISFIED_LOCKTIME", () => {
  test("txSeq = SEQUENCE_FINAL (0xffffffff) → UNSATISFIED_LOCKTIME", () => {
    // SEQUENCE_FINAL has bit 31 set
    expectCSVError(0, CSV_FLAGS, 2, SEQUENCE_FINAL, "UNSATISFIED_LOCKTIME");
  });

  test("txSeq = 0x80000000 → UNSATISFIED_LOCKTIME", () => {
    expectCSVError(0, CSV_FLAGS, 2, 0x80000000, "UNSATISFIED_LOCKTIME");
  });

  test("txSeq = 0x80000001 → UNSATISFIED_LOCKTIME", () => {
    expectCSVError(1, CSV_FLAGS, 2, 0x80000001, "UNSATISFIED_LOCKTIME");
  });
});

// ─── G9/G10: type mismatch ──────────────────────────────────────────────────

describe("G9/G10: type mismatch between operand and input sequence", () => {
  test("G9: operand height-based, input time-based → UNSATISFIED", () => {
    // operand: 10 (height, bit 22 clear)
    // txSeq: time-based (bit 22 set), value 10
    const txSeqTimeBased = SEQUENCE_LOCKTIME_TYPE_FLAG | 10;
    expectCSVError(10, CSV_FLAGS, 2, txSeqTimeBased, "UNSATISFIED_LOCKTIME");
  });

  test("G10: operand time-based, input height-based → UNSATISFIED", () => {
    // operand: time-based (bit 22 set), value 5
    const operandTimeBased = SEQUENCE_LOCKTIME_TYPE_FLAG | 5;
    // txSeq: height-based (bit 22 clear), value 0xffff
    expectCSVError(operandTimeBased, CSV_FLAGS, 2, 0x0000ffff, "UNSATISFIED_LOCKTIME");
  });
});

// ─── G11: operand > input (height-based) ────────────────────────────────────

describe("G11: operand value > input value → UNSATISFIED_LOCKTIME", () => {
  test("height: operand 11 > txSeq 10 → fail", () => {
    expectCSVError(11, CSV_FLAGS, 2, 10, "UNSATISFIED_LOCKTIME");
  });

  test("height: operand 0xffff > txSeq 0xfffe → fail", () => {
    expectCSVError(0xffff, CSV_FLAGS, 2, 0xfffe, "UNSATISFIED_LOCKTIME");
  });
});

// ─── G12: operand == input (height-based) ───────────────────────────────────

describe("G12: operand == input value → pass", () => {
  test("height: operand 10 == txSeq 10 → pass", () => {
    const result = runCSV(10, CSV_FLAGS, 2, 10);
    expect(result).toBe(true);
  });

  test("height: operand 0xffff == txSeq 0xffff → pass", () => {
    const result = runCSV(0xffff, CSV_FLAGS, 2, 0xffff);
    expect(result).toBe(true);
  });
});

// ─── G13: operand < input (height-based) ────────────────────────────────────

describe("G13: operand value < input value → pass", () => {
  test("height: operand 5 < txSeq 10 → pass", () => {
    const result = runCSV(5, CSV_FLAGS, 2, 10);
    expect(result).toBe(true);
  });

  test("height: operand 1 < txSeq 0xffff → pass", () => {
    const result = runCSV(1, CSV_FLAGS, 2, 0xffff);
    expect(result).toBe(true);
  });
});

// ─── G14/G15: time-based operand ────────────────────────────────────────────

describe("G14/G15: time-based sequences", () => {
  test("G14: time operand == input → pass", () => {
    const seq = SEQUENCE_LOCKTIME_TYPE_FLAG | 20;
    const result = runCSV(seq, CSV_FLAGS, 2, seq);
    expect(result).toBe(true);
  });

  test("G14b: time operand < input → pass", () => {
    const operand = SEQUENCE_LOCKTIME_TYPE_FLAG | 10;
    const txSeq   = SEQUENCE_LOCKTIME_TYPE_FLAG | 20;
    const result = runCSV(operand, CSV_FLAGS, 2, txSeq);
    expect(result).toBe(true);
  });

  test("G15: time operand > input → fail", () => {
    const operand = SEQUENCE_LOCKTIME_TYPE_FLAG | 20;
    const txSeq   = SEQUENCE_LOCKTIME_TYPE_FLAG | 10;
    expectCSVError(operand, CSV_FLAGS, 2, txSeq, "UNSATISFIED_LOCKTIME");
  });
});

// ─── G16: zero operand ──────────────────────────────────────────────────────

describe("G16: zero operand → immediately spendable", () => {
  test("operand 0, txSeq 0, v2 → pass", () => {
    const result = runCSV(0, CSV_FLAGS, 2, 0);
    expect(result).toBe(true);
  });

  test("operand 0, txSeq 1, v2 → pass (0 <= 1)", () => {
    const result = runCSV(0, CSV_FLAGS, 2, 1);
    expect(result).toBe(true);
  });
});

// ─── G17: max mask value ────────────────────────────────────────────────────

describe("G17: max 16-bit lock value (0xffff)", () => {
  test("height: operand 0xffff, txSeq 0xffff → pass", () => {
    const result = runCSV(0xffff, CSV_FLAGS, 2, 0xffff);
    expect(result).toBe(true);
  });

  test("time: operand TYPE|0xffff, txSeq TYPE|0xffff → pass", () => {
    const seq = SEQUENCE_LOCKTIME_TYPE_FLAG | 0xffff;
    const result = runCSV(seq, CSV_FLAGS, 2, seq);
    expect(result).toBe(true);
  });
});

// ─── G18: 5-byte operand with bit 31 set ────────────────────────────────────

describe("G18: 5-byte operand with bit 31 set → NOP", () => {
  test("operand = 0x1_8000_0000 (5-byte, bit 31 set) → NOP", () => {
    // This value sets bit 31 when truncated to 32 bits
    // 0x180000000 = 2^33 + 2^31; lower 32 bits = 0x80000000 (bit 31 set)
    const val = 0x180000000; // 6442450944
    const result = runCSV(val, CSV_FLAGS, 1, 0); // v1 tx, but NOP so no error
    expect(result).toBe(true);
  });
});

// ─── G19: SEQUENCE_FINAL as txSequence ──────────────────────────────────────

describe("G19: SEQUENCE_FINAL (0xffffffff) as input sequence → fail", () => {
  test("operand 0 with txSeq=SEQUENCE_FINAL fails (disable flag on input)", () => {
    // SEQUENCE_FINAL = 0xffffffff has bit 31 set → disable flag
    expectCSVError(0, CSV_FLAGS, 2, SEQUENCE_FINAL, "UNSATISFIED_LOCKTIME");
  });
});

// ─── G20: realistic height-based lock ───────────────────────────────────────

describe("G20: realistic height-based lock (10 blocks)", () => {
  test("operand 10, txSeq 0x0000000a (10 blocks), v2 → pass", () => {
    // 0x0000000a = 10 blocks, bit 22 clear, bit 31 clear
    const result = runCSV(10, CSV_FLAGS, 2, 0x0000000a);
    expect(result).toBe(true);
  });

  test("operand 10, txSeq 9 blocks → fail", () => {
    expectCSVError(10, CSV_FLAGS, 2, 9, "UNSATISFIED_LOCKTIME");
  });
});

// ─── G21: realistic time-based lock ─────────────────────────────────────────

describe("G21: realistic time-based lock (5 * 512s = 2560s)", () => {
  test("operand 5 time-units, txSeq same → pass", () => {
    const seq = SEQUENCE_LOCKTIME_TYPE_FLAG | 5;
    const result = runCSV(seq, CSV_FLAGS, 2, seq);
    expect(result).toBe(true);
  });

  test("operand 5 time-units, txSeq 6 time-units → pass", () => {
    const operand = SEQUENCE_LOCKTIME_TYPE_FLAG | 5;
    const txSeq   = SEQUENCE_LOCKTIME_TYPE_FLAG | 6;
    const result = runCSV(operand, CSV_FLAGS, 2, txSeq);
    expect(result).toBe(true);
  });

  test("operand 6 time-units, txSeq 5 time-units → fail", () => {
    const operand = SEQUENCE_LOCKTIME_TYPE_FLAG | 6;
    const txSeq   = SEQUENCE_LOCKTIME_TYPE_FLAG | 5;
    expectCSVError(operand, CSV_FLAGS, 2, txSeq, "UNSATISFIED_LOCKTIME");
  });
});

// ─── extra: v2 exactly passes, v3+ passes ───────────────────────────────────

describe("tx version boundary", () => {
  test("v2 tx (minimum) → pass", () => {
    const result = runCSV(0, CSV_FLAGS, 2, 0);
    expect(result).toBe(true);
  });

  test("v3 tx → pass (>= 2)", () => {
    const result = runCSV(0, CSV_FLAGS, 3, 0);
    expect(result).toBe(true);
  });

  test("v1 tx → fail", () => {
    expectCSVError(0, CSV_FLAGS, 1, 0xffff, "UNSATISFIED_LOCKTIME");
  });
});

// ─── extra: bits outside TYPE_FLAG | MASK are ignored in comparison ──────────

describe("bits outside nLockTimeMask are ignored in comparison", () => {
  test("extra bits in txSeq above bit 22 are masked out", () => {
    // txSeq = 0x00800010 (bit 23 set, not bit 22 — height-based, value 16)
    // operand = 16 (height-based, value 16)
    // nLockTimeMask = 0x004fffff would cover bit 22 and lower 16 bits
    // bit 23 is NOT in the mask, so txSeq masked = 0x0000010 = 16
    const txSeq = 0x00800010; // bit 23 set, value in lower 16 = 16
    const result = runCSV(16, CSV_FLAGS, 2, txSeq);
    expect(result).toBe(true);
  });
});
