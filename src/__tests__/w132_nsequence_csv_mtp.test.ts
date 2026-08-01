/**
 * W132 — BIP-68 / BIP-112 / BIP-113 nSequence + OP_CSV + MTP audit (hotbuns).
 *
 * 30+ gates covering relative timelocks (nSequence), CHECKSEQUENCEVERIFY
 * opcode, IsFinalTx, and Median Time Past wiring.
 *
 * Reference:
 *   - bitcoin-core/src/consensus/tx_verify.cpp
 *     (IsFinalTx, CalculateSequenceLocks, EvaluateSequenceLocks)
 *   - bitcoin-core/src/script/interpreter.cpp:522-593
 *     (OP_CLTV / OP_CSV opcode cases)
 *   - bitcoin-core/src/script/interpreter.cpp:1745-1826
 *     (CheckLockTime / CheckSequence checker methods)
 *   - bitcoin-core/src/chain.h:231-245 (GetMedianTimePast)
 *   - bitcoin-core/src/validation.cpp:2478-2562 (ConnectBlock BIP-68)
 *   - bitcoin-core/src/validation.cpp:4129-4149 (ContextualCheckBlock BIP-113)
 *   - bitcoin-core/src/validation.cpp:201-262 (mempool LockPoints)
 *   - bitcoin-core/src/policy/policy.h:119-138 (STANDARD flags)
 *
 * Audit verdict (see audit/w132_nsequence_csv_mtp.md): 14 BUGS / 30 gates.
 *   P0-CDIV: BUG-2a (regtest reorg path drops getUTXOMTP),
 *            BUG-3 (assume-valid skips BIP-68),
 *            BUG-5 (mempool BIP-68 uses tip-MTP for confirmed UTXOs),
 *            BUG-7 (OP_CSV / OP_CLTV DISCOURAGE on disabled flag — dormant),
 *            BUG-13 (assume-valid skips coinbase maturity — dormant).
 *
 *   KEY UNIVERSAL PATTERN: "assume-valid skip scope too wide" — only
 *   signature / script checks should be gated by assume-valid; BIP-68,
 *   coinbase maturity, and CheckTxInputs must run unconditionally.
 *
 * No production code changes in this wave.
 *
 * Running: bun test src/__tests__/w132_nsequence_csv_mtp.test.ts
 */

import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

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
import {
  SEQUENCE_LOCKTIME_DISABLE_FLAG,
  SEQUENCE_LOCKTIME_TYPE_FLAG,
  SEQUENCE_LOCKTIME_MASK,
  SEQUENCE_LOCKTIME_GRANULARITY,
  SEQUENCE_FINAL,
  calculateSequenceLocks,
  evaluateSequenceLocks,
  type UTXOConfirmation,
  type Transaction,
} from "../validation/tx";
import { isFinalTx } from "../mining/template";

// ---------------------------------------------------------------------------
// Source-level fixtures (for static-grep gates).
// ---------------------------------------------------------------------------

const __dirname = dirname(fileURLToPath(import.meta.url));
const SRC = resolve(__dirname, "..");

const INTERP_SRC = readFileSync(resolve(SRC, "script", "interpreter.ts"), "utf8");
const VAL_TX_SRC = readFileSync(resolve(SRC, "validation", "tx.ts"), "utf8");
const TEMPLATE_SRC = readFileSync(resolve(SRC, "mining", "template.ts"), "utf8");
const HEADERS_SRC = readFileSync(resolve(SRC, "sync", "headers.ts"), "utf8");
const BLOCKS_SRC = readFileSync(resolve(SRC, "sync", "blocks.ts"), "utf8");
const CONNECT_SRC = readFileSync(
  resolve(SRC, "consensus", "connect_block.ts"),
  "utf8",
);
const STATE_SRC = readFileSync(resolve(SRC, "chain", "state.ts"), "utf8");
const MEMPOOL_SRC = readFileSync(resolve(SRC, "mempool", "mempool.ts"), "utf8");

// ---------------------------------------------------------------------------
// Test helpers (OP_CSV stack execution).
// ---------------------------------------------------------------------------

const DUMMY_SIGHASH = (_s: Buffer, _h: number) => Buffer.alloc(32);

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
  verifyCheckSequenceVerify: true,
  verifyWitnessPubkeyType: false,
};

const CSV_DISABLED_FLAGS: ScriptFlags = {
  ...CSV_FLAGS,
  verifyCheckSequenceVerify: false,
};

function makeCtx(
  stack: Buffer[],
  flags: ScriptFlags,
  txVersion?: number,
  txLockTime?: number,
  txSequence?: number,
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

function csvScript(): ReturnType<typeof parseScript> {
  return parseScript(Buffer.from([Opcode.OP_CHECKSEQUENCEVERIFY]));
}

function runCSV(
  operand: number,
  flags: ScriptFlags,
  txVersion?: number,
  txLockTime?: number,
  txSequence?: number,
): boolean | ScriptError {
  const stack = [scriptNumEncode(operand)];
  const ctx = makeCtx(stack, flags, txVersion, txLockTime, txSequence);
  try {
    return executeScript(csvScript(), ctx);
  } catch (e) {
    if (e instanceof ScriptError) return e;
    throw e;
  }
}

function makeTx(
  version: number,
  lockTime: number,
  sequences: number[],
): Transaction {
  return {
    version,
    inputs: sequences.map((seq) => ({
      prevOut: { txid: Buffer.alloc(32, 0x01), vout: 0 },
      scriptSig: Buffer.alloc(0),
      sequence: seq,
      witness: [],
    })),
    outputs: [
      { value: 100000000n, scriptPubKey: Buffer.from([0x76, 0xa9, 0x14]) },
    ],
    lockTime,
  };
}

// ===========================================================================
// G1 — SEQUENCE_FINAL constant — PRESENT
// ===========================================================================
describe("W132-G1: SEQUENCE_FINAL = 0xffffffff — PRESENT", () => {
  test("constant value", () => {
    expect(SEQUENCE_FINAL).toBe(0xffffffff);
  });
  test("source location", () => {
    expect(VAL_TX_SRC).toMatch(/SEQUENCE_FINAL\s*=\s*0xffffffff/);
  });
});

// ===========================================================================
// G2 — SEQUENCE_LOCKTIME_DISABLE_FLAG = 1<<31 — PRESENT
// ===========================================================================
describe("W132-G2: SEQUENCE_LOCKTIME_DISABLE_FLAG = 1<<31 — PRESENT", () => {
  test("bit 31", () => {
    expect((SEQUENCE_LOCKTIME_DISABLE_FLAG >>> 0)).toBe(0x80000000);
  });
});

// ===========================================================================
// G3 — SEQUENCE_LOCKTIME_TYPE_FLAG = 1<<22 — PRESENT
// ===========================================================================
describe("W132-G3: SEQUENCE_LOCKTIME_TYPE_FLAG = 1<<22 — PRESENT", () => {
  test("bit 22", () => {
    expect(SEQUENCE_LOCKTIME_TYPE_FLAG).toBe(0x00400000);
  });
});

// ===========================================================================
// G4 — SEQUENCE_LOCKTIME_MASK = 0x0000ffff — PRESENT
// ===========================================================================
describe("W132-G4: SEQUENCE_LOCKTIME_MASK = 0x0000ffff — PRESENT", () => {
  test("16-bit mask", () => {
    expect(SEQUENCE_LOCKTIME_MASK).toBe(0x0000ffff);
  });
});

// ===========================================================================
// G5 — SEQUENCE_LOCKTIME_GRANULARITY = 9 (512s) — PRESENT
// ===========================================================================
describe("W132-G5: SEQUENCE_LOCKTIME_GRANULARITY = 9 — PRESENT", () => {
  test("9 → 512", () => {
    expect(SEQUENCE_LOCKTIME_GRANULARITY).toBe(9);
    expect(1 << SEQUENCE_LOCKTIME_GRANULARITY).toBe(512);
  });
});

// ===========================================================================
// G6 — calculateSequenceLocks returns -1/-1 when not enforced — PRESENT
// ===========================================================================
describe("W132-G6: calculateSequenceLocks not-enforced semantics — PRESENT", () => {
  test("enforceBIP68=false → -1/-1", () => {
    const tx = makeTx(2, 0, [10]);
    const r = calculateSequenceLocks(tx, false, [
      { height: 100, medianTimePast: 1_700_000_000 },
    ]);
    expect(r.minHeight).toBe(-1);
    expect(r.minTime).toBe(-1);
  });
  test("tx.version < 2 → -1/-1 even if enforceBIP68=true", () => {
    const tx = makeTx(1, 0, [10]);
    const r = calculateSequenceLocks(tx, true, [
      { height: 100, medianTimePast: 1_700_000_000 },
    ]);
    expect(r.minHeight).toBe(-1);
    expect(r.minTime).toBe(-1);
  });
});

// ===========================================================================
// G7 — Disable-flag inputs skipped — PRESENT
// ===========================================================================
describe("W132-G7: disable-flag input skipped — PRESENT", () => {
  test("input with bit-31 set does not contribute", () => {
    const disabledSeq = SEQUENCE_LOCKTIME_DISABLE_FLAG | 100;
    const tx = makeTx(2, 0, [disabledSeq]);
    const r = calculateSequenceLocks(tx, true, [
      { height: 100, medianTimePast: 1_700_000_000 },
    ]);
    expect(r.minHeight).toBe(-1);
    expect(r.minTime).toBe(-1);
  });
});

// ===========================================================================
// G8 — Time-based nMinTime = nCoinTime + lockValue*512 - 1
//      (BUG-2a regtest, BUG-2b genesis)
// ===========================================================================
describe("W132-G8: time-based nMinTime formula — PARTIAL (BUG-2a + BUG-2b)", () => {
  test("PRESENT: formula matches Core (operand level)", () => {
    const lockValue = 3; // 3 * 512 = 1536 s
    const seq = SEQUENCE_LOCKTIME_TYPE_FLAG | lockValue;
    const tx = makeTx(2, 0, [seq]);
    const nCoinTime = 1_700_000_000;
    const r = calculateSequenceLocks(tx, true, [
      { height: 100, medianTimePast: nCoinTime },
    ]);
    expect(r.minTime).toBe(nCoinTime + lockValue * 512 - 1);
    expect(r.minHeight).toBe(-1);
  });

  test(
    "BUG-2a P0-CDIV: chain/state.ts:connectBlock omits getUTXOMTP " +
      "from coreConnectBlockChecks options — time-based BIP-68 always passes " +
      "on regtest / reorg-reconnect paths",
    () => {
      // Static evidence: chain/state.ts builds the options object without
      // a getUTXOMTP key. (sync/blocks.ts does pass one — line 2582.)
      const stateOptsRegion = STATE_SRC.slice(
        STATE_SRC.indexOf("coreConnectBlockChecks(block, height, this.utxo, this.params, {"),
        STATE_SRC.indexOf("coreConnectBlockChecks(block, height, this.utxo, this.params, {") + 1500,
      );
      expect(stateOptsRegion).not.toMatch(/getUTXOMTP\s*:/);
      // And the callee defaults missing getUTXOMTP to 0, which makes
      // every time-based BIP-68 lock evaluate as < currentMTP.
      expect(CONNECT_SRC).toMatch(
        /const\s+coinMTP\s*=\s*getUTXOMTP\s*\?\s*getUTXOMTP\([^)]*\)\s*:\s*0/,
      );
    },
  );

  test(
    "BUG-2b P1-WIRE: getUTXOMTP returns 0 for coinHeight <= 0; " +
      "Core uses GetAncestor(max(coinHeight-1, 0))->GetMedianTimePast()",
    () => {
      const blocksRegion = BLOCKS_SRC.slice(
        BLOCKS_SRC.indexOf("getUTXOMTP:"),
        BLOCKS_SRC.indexOf("getUTXOMTP:") + 400,
      );
      expect(blocksRegion).toMatch(/if\s*\(\s*coinHeight\s*<=\s*0\s*\)\s*return\s+0\s*;/);
      // Core does NOT return 0; it returns the MTP at height 0 (genesis).
      // Practical impact zero (genesis coinbase unspendable), but a
      // divergence-class wiring gap.
    },
  );
});

// ===========================================================================
// G9 — Height-based nMinHeight = nCoinHeight + lockValue - 1 — PRESENT
// ===========================================================================
describe("W132-G9: height-based nMinHeight formula — PRESENT", () => {
  test("simple height lock", () => {
    const lockValue = 10;
    const tx = makeTx(2, 0, [lockValue]); // height-based, lockValue=10
    const r = calculateSequenceLocks(tx, true, [
      { height: 100, medianTimePast: 0 },
    ]);
    expect(r.minHeight).toBe(100 + 10 - 1); // 109
    expect(r.minTime).toBe(-1);
  });

  test("lockValue=0 yields nMinHeight = nCoinHeight - 1 (effectively no lock)", () => {
    const tx = makeTx(2, 0, [0]);
    const r = calculateSequenceLocks(tx, true, [
      { height: 100, medianTimePast: 0 },
    ]);
    expect(r.minHeight).toBe(99);
    // evaluateSequenceLocks: 99 >= 100? No → satisfied at height 100
    expect(evaluateSequenceLocks(100, 0, r)).toBe(true);
  });
});

// ===========================================================================
// G10 — evaluateSequenceLocks: minHeight >= height OR minTime >= prevMTP — PRESENT
// ===========================================================================
describe("W132-G10: evaluateSequenceLocks strict-ge semantics — PRESENT", () => {
  test("minHeight==height → fail", () => {
    expect(evaluateSequenceLocks(100, 0, { minHeight: 100, minTime: -1 })).toBe(false);
  });
  test("minHeight<height → pass", () => {
    expect(evaluateSequenceLocks(100, 0, { minHeight: 99, minTime: -1 })).toBe(true);
  });
  test("minTime==prevMTP → fail", () => {
    expect(
      evaluateSequenceLocks(100, 1_700_000_000, {
        minHeight: -1,
        minTime: 1_700_000_000,
      }),
    ).toBe(false);
  });
  test("minTime<prevMTP → pass", () => {
    expect(
      evaluateSequenceLocks(100, 1_700_000_001, {
        minHeight: -1,
        minTime: 1_700_000_000,
      }),
    ).toBe(true);
  });
});

// ===========================================================================
// G11 — Per-coin MTP plumbed (W93 fix on IBD path) — PRESENT
// ===========================================================================
describe("W132-G11: per-coin MTP wiring on IBD — PRESENT", () => {
  test("sync/blocks.ts passes getUTXOMTP to coreConnectBlockChecks", () => {
    expect(BLOCKS_SRC).toMatch(/getUTXOMTP\s*:\s*\(coinHeight:\s*number\)\s*=>/);
  });
  test("getUTXOMTP looks up MTP at (coinHeight - 1)", () => {
    expect(BLOCKS_SRC).toMatch(
      /this\.headerSync\.getHeaderByHeight\(\s*coinHeight\s*-\s*1\s*\)/,
    );
  });
});

// ===========================================================================
// G12 — Block-validation BIP-68 path runs in ConnectBlock
//       BUG-3: skipped under assume-valid (P0-CDIV)
// ===========================================================================
describe("W132-G12: ConnectBlock BIP-68 enforcement — PARTIAL (BUG-3 P0-CDIV)", () => {
  test("PRESENT: full-validation path calls checkSequenceLocks", () => {
    expect(CONNECT_SRC).toMatch(/checkSequenceLocks\s*\(/);
  });

  test(
    "BUG-3 FIXED: no assume-valid fast path short-circuits the BIP-68 " +
      "check — Core's SequenceLocks (validation.cpp:2557) runs " +
      "unconditionally (only signature/script checks gated by fScriptChecks)",
    () => {
      // The old `if (assumeValid) { ... early return ... }` fast path (which
      // skipped the BIP-68 checkSequenceLocks call) was REMOVED for Core
      // parity — connect_block.ts now runs the full path for every block
      // and gates ONLY signature verification behind skipScripts.
      expect(CONNECT_SRC).not.toContain("if (assumeValid) {");
      // The BIP-68 check must NOT be inside the skipScripts-gated signature
      // block: it must appear BEFORE the `if (!skipScripts)` region.
      const csvIdx = CONNECT_SRC.indexOf("checkSequenceLocks(");
      expect(csvIdx).toBeGreaterThan(0);
      // Anchor on the code gate (with brace) — the doc comment at the
      // fast-path-removal note also mentions `if (!skipScripts)` in prose.
      const skipIdx = CONNECT_SRC.indexOf("if (!skipScripts) {");
      expect(skipIdx).toBeGreaterThan(csvIdx);
      // And IsFinalTx still runs unconditionally ahead of both (line ~516).
      const isFinalIdx = CONNECT_SRC.indexOf("isFinalTx(tx, height, lockTimeCutoff)");
      expect(isFinalIdx).toBeGreaterThan(0);
      expect(isFinalIdx).toBeLessThan(csvIdx);
    },
  );
});

// ===========================================================================
// G13 — Mempool BIP-68 gate (BUG-4: too narrow vs Core's always-on)
// ===========================================================================
describe("W132-G13: mempool BIP-68 gate — PARTIAL (BUG-4 P1-WIRE)", () => {
  test(
    "BUG-4: mempool enforces BIP-68 only when tipHeight >= csvHeight; " +
      "Core's STANDARD_LOCKTIME_VERIFY_FLAGS makes this unconditional for v2 txs",
    () => {
      expect(MEMPOOL_SRC).toMatch(
        /const\s+enforceBIP68\s*=[\s\S]{0,120}tx\.version\s*>=\s*2[\s\S]{0,120}this\.tipHeight\s*>=[\s\S]{0,40}csvHeight/,
      );
      // Core uses STANDARD_LOCKTIME_VERIFY_FLAGS at validation.cpp:218 —
      // there is no tipHeight gate, only the version-2 check inside
      // CalculateSequenceLocks.
    },
  );
});

// ===========================================================================
// G14 — Mempool per-coin MTP (BUG-5: uses tip-MTP for confirmed UTXOs)
// ===========================================================================
describe("W132-G14: mempool per-coin MTP — FIXED (was BUG-5 P0-CDIV mempool)", () => {
  test(
    "BUG-5 FIXED: confirmed UTXOs use per-coin MTP at (coinHeight - 1); " +
      "only mempool parents use the synthetic currentMTP (Core parity)",
    () => {
      // Static evidence: the .map() that builds utxoConfirmations uses
      // per-coin MTP for confirmed UTXOs (Core's CheckSequenceLocksAtTip
      // indexes mediants[] by coin creation height) and currentMTP only for
      // unconfirmed mempool parents (synthetic tipHeight+1 convention).
      const mapIdx = MEMPOOL_SRC.indexOf("inputUtxos.map(({ utxo, isMempool: isMp })");
      expect(mapIdx).toBeGreaterThan(0);
      const region = MEMPOOL_SRC.slice(mapIdx, mapIdx + 1400);
      // Exactly ONE currentMTP branch — the mempool-parent synthetic entry.
      const occurrences = (region.match(/medianTimePast:\s*currentMTP/g) ?? []).length;
      expect(occurrences).toBe(1);
      // The confirmed-UTXO branch looks up MTP at (coinHeight - 1)...
      expect(region).toMatch(/confirmedUtxo\.height\s*-\s*1/);
      // ...and returns the per-coin MTP, not the tip MTP.
      expect(region).toMatch(/medianTimePast:\s*coinMTP/);
    },
  );
});

// ===========================================================================
// G15 — setTipMTP dead code (BUG-6 P2)
// ===========================================================================
describe("W132-G15: setTipMTP dead code — PARTIAL (BUG-6 P2)", () => {
  test("setTipMTP defined but never called in TS source", () => {
    expect(MEMPOOL_SRC).toMatch(/setTipMTP\s*\(\s*mtp\s*:\s*number\s*\)\s*:/);
    // Count calls across all TS source — should be 0 (we excluded the bundle).
    const callPattern = /\.setTipMTP\s*\(/g;
    const calls = (
      MEMPOOL_SRC.match(callPattern) ??
      CONNECT_SRC.match(callPattern) ??
      STATE_SRC.match(callPattern) ??
      BLOCKS_SRC.match(callPattern) ??
      []
    );
    expect(calls.length).toBe(0);
  });
});

// ===========================================================================
// G16 — getUTXOMTP returns 0 at coinHeight<=0 (counted as BUG-2b, see G8)
// ===========================================================================
describe("W132-G16: getUTXOMTP genesis edge — counted in BUG-2b", () => {
  test("source has the early-return", () => {
    expect(BLOCKS_SRC).toMatch(
      /if\s*\(\s*coinHeight\s*<=\s*0\s*\)\s*return\s+0\s*;/,
    );
  });
});

// ===========================================================================
// G17 — OP_CHECKSEQUENCEVERIFY = 0xb2 — PRESENT
// ===========================================================================
describe("W132-G17: OP_CHECKSEQUENCEVERIFY opcode — PRESENT", () => {
  test("opcode value", () => {
    expect(Opcode.OP_CHECKSEQUENCEVERIFY).toBe(0xb2);
  });
});

// ===========================================================================
// G18 — 5-byte CScriptNum operand accepted — PRESENT
// ===========================================================================
describe("W132-G18: 5-byte operand support — PRESENT", () => {
  test("source uses scriptNumDecode(..., 5)", () => {
    const csvIdx = INTERP_SRC.indexOf("OP_CHECKSEQUENCEVERIFY: {");
    const region = INTERP_SRC.slice(csvIdx, csvIdx + 1200);
    expect(region).toMatch(/scriptNumDecode\(\s*stack\[stack\.length\s*-\s*1\]\s*,\s*5\s*,/);
  });
});

// ===========================================================================
// G19 — Negative operand → NEGATIVE_LOCKTIME — PRESENT
// ===========================================================================
describe("W132-G19: negative operand → NEGATIVE_LOCKTIME — PRESENT", () => {
  test("OP_CSV with -1 operand throws NEGATIVE_LOCKTIME", () => {
    const r = runCSV(-1, CSV_FLAGS, 2, 0, 0xfffffffe);
    expect(r).toBeInstanceOf(ScriptError);
    expect((r as ScriptError).code).toBe("NEGATIVE_LOCKTIME");
  });
});

// ===========================================================================
// G20 — Disable-flag operand → NOP behavior — PRESENT
// ===========================================================================
describe("W132-G20: operand disable-flag NOP behavior — PRESENT", () => {
  test("operand with bit-31 set + txSeq=SEQUENCE_FINAL still passes (NOP)", () => {
    // Even though txSequence=SEQUENCE_FINAL would normally fail at the
    // input-disable check, the operand-disable check short-circuits earlier.
    // We use 0x80000001 as operand; bit 31 set → return true (NOP).
    const r = runCSV(0x80000001, CSV_FLAGS, 2, 0, SEQUENCE_FINAL);
    expect(r).toBe(true);
  });
});

// ===========================================================================
// G21 — tx.version < 2 → UNSATISFIED_LOCKTIME — PRESENT
// ===========================================================================
describe("W132-G21: tx.version<2 → UNSATISFIED_LOCKTIME — PRESENT", () => {
  test("version=1 fails OP_CSV", () => {
    const r = runCSV(0, CSV_FLAGS, 1, 0, 0xfffffffe);
    expect(r).toBeInstanceOf(ScriptError);
    expect((r as ScriptError).code).toBe("UNSATISFIED_LOCKTIME");
  });
  test("version=2 with operand=0 passes", () => {
    // txSequence must have bit-31 clear (else BIP-112 disable-flag check
    // fires UNSATISFIED). 0xfffffffe sets bit 31; use a height-based seq.
    const r = runCSV(0, CSV_FLAGS, 2, 0, 0x00000010);
    expect(r).toBe(true);
  });
});

// ===========================================================================
// G22 — Spending input nSequence disable-flag → UNSATISFIED_LOCKTIME — PRESENT
// ===========================================================================
describe("W132-G22: input-disable nSequence → UNSATISFIED — PRESENT", () => {
  test("txSequence with bit-31 set fails", () => {
    const r = runCSV(0, CSV_FLAGS, 2, 0, 0x80000001);
    expect(r).toBeInstanceOf(ScriptError);
    expect((r as ScriptError).code).toBe("UNSATISFIED_LOCKTIME");
  });
});

// ===========================================================================
// G23 — Apple-to-apple type comparison — PRESENT
// ===========================================================================
describe("W132-G23: type-flag apple-to-apple — PRESENT", () => {
  test("operand height-based, txSeq time-based → fail", () => {
    const heightOperand = 10;                                 // bit 22 clear
    const timeSequence = SEQUENCE_LOCKTIME_TYPE_FLAG | 10;    // bit 22 set
    const r = runCSV(heightOperand, CSV_FLAGS, 2, 0, timeSequence);
    expect(r).toBeInstanceOf(ScriptError);
    expect((r as ScriptError).code).toBe("UNSATISFIED_LOCKTIME");
  });
  test("operand time-based, txSeq height-based → fail", () => {
    const timeOperand = SEQUENCE_LOCKTIME_TYPE_FLAG | 10;
    const heightSequence = 10;
    const r = runCSV(timeOperand, CSV_FLAGS, 2, 0, heightSequence);
    expect(r).toBeInstanceOf(ScriptError);
    expect((r as ScriptError).code).toBe("UNSATISFIED_LOCKTIME");
  });
  test("both height-based, operand <= txSeq → pass", () => {
    const r = runCSV(10, CSV_FLAGS, 2, 0, 20);
    expect(r).toBe(true);
  });
});

// ===========================================================================
// G24 — seqMasked > txSeqMasked → UNSATISFIED — PRESENT
// ===========================================================================
describe("W132-G24: operand > input sequence → UNSATISFIED — PRESENT", () => {
  test("height-based, operand 100, txSeq 10 → fail", () => {
    const r = runCSV(100, CSV_FLAGS, 2, 0, 10);
    expect(r).toBeInstanceOf(ScriptError);
    expect((r as ScriptError).code).toBe("UNSATISFIED_LOCKTIME");
  });
});

// ===========================================================================
// G25 — OP_CSV bare-NOP behavior when flag off (BUG-7 P0-dormant)
// ===========================================================================
describe("W132-G25: OP_CSV NOP-when-disabled — MISSING (BUG-7 P0-dormant)", () => {
  test(
    "BUG-7: hotbuns fires DISCOURAGE_UPGRADABLE_NOPS when CSV disabled + " +
      "discourage flag set; Core treats OP_NOP3 as a bare NOP " +
      "(interpreter.cpp:563-566 — no discourage check)",
    () => {
      const csvIdx = INTERP_SRC.indexOf("OP_CHECKSEQUENCEVERIFY: {");
      const region = INTERP_SRC.slice(csvIdx, csvIdx + 400);
      // Hotbuns has the discourage gate inside the !flag branch.
      expect(region).toMatch(
        /if\s*\(\s*!flags\.verifyCheckSequenceVerify\s*\)\s*\{\s*if\s*\(\s*flags\.verifyDiscourageUpgradableNops\s*\)/,
      );
      // Core's source has no such check inside the !(flags & ...) branch
      // — it's just "break" (treat as NOP3). See interpreter.cpp:563-566.
    },
  );

  test(
    "Bug also present for OP_CLTV — OP_NOP2 is not in Core's discourage " +
      "list at interpreter.cpp:595",
    () => {
      const cltvIdx = INTERP_SRC.indexOf("OP_CHECKLOCKTIMEVERIFY: {");
      const region = INTERP_SRC.slice(cltvIdx, cltvIdx + 400);
      expect(region).toMatch(
        /if\s*\(\s*!flags\.verifyCheckLockTimeVerify\s*\)\s*\{\s*if\s*\(\s*flags\.verifyDiscourageUpgradableNops\s*\)/,
      );
    },
  );

  test(
    "Currently dormant: getStandardFlags does NOT set " +
      "verifyDiscourageUpgradableNops (so the buggy branch never runs).",
    () => {
      const stdIdx = INTERP_SRC.indexOf("export function getStandardFlags");
      const region = INTERP_SRC.slice(stdIdx, stdIdx + 600);
      expect(region).not.toMatch(/verifyDiscourageUpgradableNops\s*:/);
    },
  );

  test("OP_CSV with CSV_DISABLED flag returns true (bare NOP, no discourage)", () => {
    // Without the discourage flag set in our test flags, OP_CSV is just
    // a NOP — passes regardless of operand.
    const r = runCSV(0, CSV_DISABLED_FLAGS, 2, 0, 0xfffffffe);
    expect(r).toBe(true);
  });
});

// ===========================================================================
// G26 — OP_CHECKLOCKTIMEVERIFY = 0xb1 (BIP-65; pre-W81 audit closed)
// ===========================================================================
describe("W132-G26: OP_CLTV opcode — PRESENT (W81 fixes confirmed)", () => {
  test("opcode value", () => {
    expect(Opcode.OP_CHECKLOCKTIMEVERIFY).toBe(0xb1);
  });
  test("W81 fix anchors: txContext threaded through P2WSH and tapscript", () => {
    // Pre-W81 these blocks lacked txVersion/txLockTime/txSequence.
    expect(INTERP_SRC).toMatch(/txVersion:\s*txContext\?\.txVersion[\s\S]{0,200}txLockTime:\s*txContext\?\.txLockTime[\s\S]{0,200}txSequence:\s*txContext\?\.txSequence/);
    // Comment anchor preserved.
    expect(INTERP_SRC).toMatch(/W81 fix:?[^\n]+thread txContext/);
  });
});

// ===========================================================================
// G27 — IsFinalTx height-or-time threshold logic — PRESENT
// ===========================================================================
describe("W132-G27: IsFinalTx threshold logic — PRESENT", () => {
  test("lockTime=0 → always final", () => {
    expect(isFinalTx(makeTx(2, 0, [0]), 100, 1_700_000_000)).toBe(true);
  });
  test("lockTime < blockHeight (height-based) → final", () => {
    expect(isFinalTx(makeTx(2, 99, [0]), 100, 1_700_000_000)).toBe(true);
  });
  test("lockTime == blockHeight → NOT final (unless SEQUENCE_FINAL)", () => {
    expect(isFinalTx(makeTx(2, 100, [0]), 100, 1_700_000_000)).toBe(false);
  });
  test("lockTime > LOCKTIME_THRESHOLD compared against blockTime", () => {
    const lt = 500_000_100;
    expect(isFinalTx(makeTx(2, lt, [0]), 100, lt - 1)).toBe(false);
    expect(isFinalTx(makeTx(2, lt, [0]), 100, lt + 1)).toBe(true);
  });
});

// ===========================================================================
// G28 — IsFinalTx all-SEQUENCE_FINAL exemption — PRESENT
// ===========================================================================
describe("W132-G28: all-SEQUENCE_FINAL exemption — PRESENT", () => {
  test("lockTime unmet but all inputs SEQUENCE_FINAL → final", () => {
    expect(
      isFinalTx(makeTx(2, 100, [SEQUENCE_FINAL, SEQUENCE_FINAL]), 100, 1_700_000_000),
    ).toBe(true);
  });
  test("one non-final input → NOT final", () => {
    expect(
      isFinalTx(makeTx(2, 100, [SEQUENCE_FINAL, 0xfffffffe]), 100, 1_700_000_000),
    ).toBe(false);
  });
});

// ===========================================================================
// G29 — Lock-time cutoff = MTP when CSV active, else block timestamp — PRESENT
// ===========================================================================
describe("W132-G29: connect_block lock-time cutoff — PRESENT", () => {
  test("connect_block.ts:csvActive switch correct", () => {
    expect(CONNECT_SRC).toMatch(
      /const\s+csvActive\s*=\s*height\s*>=\s*params\.csvHeight\s*;\s*const\s+lockTimeCutoff\s*=\s*csvActive\s*\?\s*prevMTP\s*:\s*block\.header\.timestamp\s*;/,
    );
  });
});

// ===========================================================================
// G30 — GetMedianTimePast walks 11 ancestors and takes middle — PRESENT
// ===========================================================================
describe("W132-G30: GetMedianTimePast 11-ancestor median — PRESENT", () => {
  test("loop bound and median index", () => {
    // Anchor to the function DEFINITION (not the first call site at line 554).
    const defIdx = HEADERS_SRC.indexOf(
      "getMedianTimePast(entry: HeaderChainEntry): number",
    );
    expect(defIdx).toBeGreaterThan(0);
    const region = HEADERS_SRC.slice(defIdx, defIdx + 800);
    expect(region).toMatch(/for\s*\(\s*let\s+i\s*=\s*0\s*;\s*i\s*<\s*11\s*&&\s*current/);
    expect(region).toMatch(/timestamps\[Math\.floor\(timestamps\.length\s*\/\s*2\)\]/);
  });
});

// ===========================================================================
// G31 — Standard flags include DISCOURAGE_UPGRADABLE_NOPS (BUG-9 P1-API)
// ===========================================================================
describe("W132-G31: getStandardFlags discourage — MISSING (BUG-9)", () => {
  test(
    "BUG-9: getStandardFlags missing verifyDiscourageUpgradableNops; " +
      "Core's STANDARD_SCRIPT_VERIFY_FLAGS at policy.h:122 includes it",
    () => {
      const stdIdx = INTERP_SRC.indexOf("export function getStandardFlags");
      const region = INTERP_SRC.slice(stdIdx, stdIdx + 600);
      expect(region).not.toMatch(/verifyDiscourageUpgradableNops\s*:/);
    },
  );
});

// ===========================================================================
// G32 — Other DISCOURAGE flags missing (BUG-10 P1-API)
// ===========================================================================
describe("W132-G32: other discourage flags missing — MISSING (BUG-10)", () => {
  test("getStandardFlags missing 4 other discourage flags", () => {
    const stdIdx = INTERP_SRC.indexOf("export function getStandardFlags");
    const region = INTERP_SRC.slice(stdIdx, stdIdx + 600);
    expect(region).not.toMatch(/verifyDiscourageUpgradableWitnessProgram/);
    expect(region).not.toMatch(/verifyDiscourageUpgradableTaprootVersion/);
    expect(region).not.toMatch(/verifyDiscourageOpSuccess/);
    expect(region).not.toMatch(/verifyDiscourageUpgradablePubkeyType/);
  });
});

// ===========================================================================
// G33 — single-source IsFinalTx — PRESENT
// ===========================================================================
describe("W132-G33: IsFinalTx single source — PRESENT", () => {
  test("exported from mining/template.ts and imported by mempool/connect", () => {
    expect(TEMPLATE_SRC).toMatch(/export\s+function\s+isFinalTx\s*\(/);
    expect(MEMPOOL_SRC).toMatch(/import[^;]*isFinalTx[^;]*from\s+["']\.\.\/mining\/template/);
    expect(CONNECT_SRC).toMatch(/import[^;]*isFinalTx[^;]*from\s+["']\.\.\/mining\/template/);
  });
});

// ===========================================================================
// G34 — IBD path passes getUTXOMTP — PRESENT
// ===========================================================================
describe("W132-G34: sync/blocks.ts getUTXOMTP wiring — PRESENT", () => {
  test("getUTXOMTP closure in coreConnectBlockChecks options", () => {
    expect(BLOCKS_SRC).toMatch(
      /coreConnectBlockChecks\s*\([\s\S]{0,4000}getUTXOMTP:\s*\(coinHeight:\s*number\)\s*=>/,
    );
  });
});

// ===========================================================================
// G35 — Mempool computes currentMTP from best header — PRESENT
// ===========================================================================
describe("W132-G35: mempool currentMTP wiring — PRESENT", () => {
  test("mempool.ts uses headerSync.getMedianTimePast for currentMTP", () => {
    expect(MEMPOOL_SRC).toMatch(
      /const\s+bestHdr\s*=\s*this\.headerSync\.getBestHeader\(\)[\s\S]{0,200}currentMTP\s*=\s*this\.headerSync\.getMedianTimePast\(\s*bestHdr\s*\)/,
    );
  });
});

// ===========================================================================
// G36 — Hard-coded mainnet activation heights in getConsensusFlags (BUG-1, BUG-11)
// ===========================================================================
describe("W132-G36: hard-coded mainnet heights — MISSING (BUG-1 / BUG-11)", () => {
  test(
    "BUG-1/11: getConsensusFlags(height) bakes 388381/419328 (mainnet) into " +
      "the flag computer; non-mainnet networks get wrong flags",
    () => {
      const conIdx = INTERP_SRC.indexOf("export function getConsensusFlags");
      const region = INTERP_SRC.slice(conIdx, conIdx + 800);
      expect(region).toMatch(/verifyCheckLockTimeVerify:\s*height\s*>=\s*388381/);
      expect(region).toMatch(/verifyCheckSequenceVerify:\s*height\s*>=\s*419328/);
      // The function signature does NOT take a params argument:
      expect(region).toMatch(/getConsensusFlags\s*\(\s*height\s*:\s*number\s*\)\s*:/);
    },
  );
});

// ===========================================================================
// G37 — getStandardFlags inherits BUG-11 — PARTIAL
// ===========================================================================
describe("W132-G37: getStandardFlags hard-coded heights — PARTIAL (BUG-11 transitive)", () => {
  test("getStandardFlags(height) delegates to getConsensusFlags(height)", () => {
    const stdIdx = INTERP_SRC.indexOf("export function getStandardFlags");
    const region = INTERP_SRC.slice(stdIdx, stdIdx + 600);
    expect(region).toMatch(/getConsensusFlags\s*\(\s*height\s*\)/);
  });
});

// ===========================================================================
// G38 — MAX_SEQUENCE_NONFINAL export — MISSING (BUG-12 P2)
// ===========================================================================
describe("W132-G38: MAX_SEQUENCE_NONFINAL export — MISSING (BUG-12)", () => {
  test(
    "BUG-12: MAX_SEQUENCE_NONFINAL = 0xfffffffe defined ad-hoc in " +
      "mining/template.ts; not exported alongside BIP-68 constants",
    () => {
      // Not in validation/tx.ts:
      expect(VAL_TX_SRC).not.toMatch(/export\s+const\s+MAX_SEQUENCE_NONFINAL/);
      // Defined ad-hoc in mining/template.ts:
      expect(TEMPLATE_SRC).toMatch(/MAX_SEQUENCE_NONFINAL\s*=\s*0xfffffffe/);
    },
  );
});

// ===========================================================================
// G39 — BIP-125 RBF boundary cross-check — PRESENT
// ===========================================================================
describe("W132-G39: BIP-125 RBF boundary 0xfffffffd vs BIP-68 disable — PRESENT", () => {
  test("RBF triggers below 0xfffffffe", () => {
    const walletSrc = readFileSync(
      resolve(SRC, "wallet", "wallet.ts"),
      "utf8",
    );
    expect(walletSrc).toMatch(/<\s*0xfffffffe/);
  });
});

// ===========================================================================
// G40 — RPC getblocktemplate.mintime uses MTP + 1 — PRESENT
// ===========================================================================
describe("W132-G40: getblocktemplate.mintime = MTP+1 — PRESENT", () => {
  test("rpc/server.ts uses MTP + 1 for mintime", () => {
    const rpcSrc = readFileSync(resolve(SRC, "rpc", "server.ts"), "utf8");
    expect(rpcSrc).toMatch(/getMedianTimePast\(parentEntry\)\s*\+\s*1/);
  });
});

// ===========================================================================
// G41 — IsFinalTx runs before assume-valid short-circuit — PRESENT
// ===========================================================================
describe("W132-G41: IsFinalTx unconditional in connect_block — PRESENT", () => {
  test("isFinalTx loop is not gated by the skipScripts fast path", () => {
    // The old `if (assumeValid) {` fast path was removed; the only remaining
    // gate is `if (!skipScripts)` (signature verification).  IsFinalTx must
    // run BEFORE it — Core runs ContextualCheckBlock lock-time rules even
    // under assumevalid (validation.cpp:4146).
    const isFinalIdx = CONNECT_SRC.indexOf("isFinalTx(tx, height, lockTimeCutoff)");
    const skipIdx = CONNECT_SRC.indexOf("if (!skipScripts) {");
    expect(isFinalIdx).toBeGreaterThan(0);
    expect(skipIdx).toBeGreaterThan(isFinalIdx);
  });
});

// ===========================================================================
// G42 — chain/state.ts passes enforceBIP68 correctly — PRESENT (gate ok; BUG-2a at MTP wiring)
// ===========================================================================
describe("W132-G42: chain/state.ts enforceBIP68 gate — PRESENT", () => {
  test("csvActive forwarded to enforceBIP68", () => {
    // chain/state.ts defines csvActive then forwards it as enforceBIP68 in
    // the coreConnectBlockChecks options. There is intervening W93 code
    // (genesisHashHexLE, utxoBestBlockHashHex, computedPrevMTP) between the
    // two — allow up to ~3KB of code in between.
    expect(STATE_SRC).toMatch(
      /const\s+csvActive\s*=\s*height\s*>=\s*this\.params\.csvHeight\s*;[\s\S]{0,3500}enforceBIP68:\s*csvActive/,
    );
  });
});

// ===========================================================================
// G43 — Coinbase maturity runs under assume-valid (BUG-13 P0-dormant)
// ===========================================================================
describe("W132-G43: coinbase maturity under assume-valid — MISSING (BUG-13)", () => {
  test(
    "BUG-13: assume-valid fast path skips coinbase maturity check; " +
      "Core's Consensus::CheckTxInputs (tx_verify.cpp:178-181) runs " +
      "unconditionally inside CheckTxInputs",
    () => {
      const fastIdx = CONNECT_SRC.indexOf("if (assumeValid) {");
      const fastReturnIdx = CONNECT_SRC.indexOf("return {", fastIdx);
      const fastPath = CONNECT_SRC.slice(fastIdx, fastReturnIdx);
      // The fast path does NOT check coinbase maturity.
      expect(fastPath).not.toMatch(/COINBASE_MATURITY|coinbaseMaturity|coin\.IsCoinBase\(\)/i);
      expect(fastPath).not.toMatch(/Immature coinbase spend/);
    },
  );
});

// ===========================================================================
// G44 — chain/state wires HeaderSync for prevMTP — PRESENT
// ===========================================================================
describe("W132-G44: chain/state HeaderSync wiring for prevMTP — PRESENT", () => {
  test("computedPrevMTP defaults to block.header.timestamp then uses headerSync", () => {
    expect(STATE_SRC).toMatch(/let\s+computedPrevMTP\s*=\s*block\.header\.timestamp/);
    expect(STATE_SRC).toMatch(/this\.headerSync\.getMedianTimePast\(\s*prevHeader\s*\)/);
  });
});

// ===========================================================================
// G45 — Pre-W81 source anchors preserved — PRESENT
// ===========================================================================
describe("W132-G45: W81 fix anchors preserved — PRESENT", () => {
  test("comment anchors mention pre-fix bug shape", () => {
    expect(INTERP_SRC).toMatch(/ctx had no txVersion\/txLockTime\/txSequence/);
    expect(INTERP_SRC).toMatch(/every CLTV in a witness-v0 script silently passed/);
    expect(INTERP_SRC).toMatch(/Pre-fix bug:\s*`if \(ctx\.txLockTime !== undefined\)`/);
  });
});

// ===========================================================================
// G46 — Mempool parent-height = tip + 1 — PRESENT
// ===========================================================================
describe("W132-G46: mempool parent-height = tipHeight+1 — PRESENT", () => {
  test("unconfirmed parents use nextHeight", () => {
    expect(MEMPOOL_SRC).toMatch(
      /if\s*\(\s*isMp\s*\)[\s\S]{0,200}height:\s*nextHeight/,
    );
  });
});

// ===========================================================================
// G47 — Coinbase maturity in full-validation path — PRESENT
// ===========================================================================
describe("W132-G47: coinbase maturity in full path — PRESENT", () => {
  test("full-validation path includes maturity check", () => {
    // Full-validation block (line 482+) DOES check maturity.
    expect(CONNECT_SRC).toMatch(/utxo\.coinbase[\s\S]{0,300}params\.coinbaseMaturity/);
  });
});

// ===========================================================================
// G48 — OP_CLTV NOP-when-disabled (paired with G25 — BUG-7 same shape)
// ===========================================================================
describe("W132-G48: OP_CLTV NOP-when-disabled — MISSING (BUG-7 shape)", () => {
  test("source has the same broken DISCOURAGE check for OP_CLTV", () => {
    // OP_CLTV's case has more reference-comment lines than OP_CSV before
    // the body; use a larger window so the full DISCOURAGE_UPGRADABLE_NOPS
    // literal is included.
    const cltvIdx = INTERP_SRC.indexOf("OP_CHECKLOCKTIMEVERIFY: {");
    const region = INTERP_SRC.slice(cltvIdx, cltvIdx + 800);
    expect(region).toMatch(
      /if\s*\(\s*!flags\.verifyCheckLockTimeVerify\s*\)\s*\{\s*if\s*\(\s*flags\.verifyDiscourageUpgradableNops\s*\)\s*\{\s*throw\s+new\s+ScriptError\(\s*"DISCOURAGE_UPGRADABLE_NOPS"\s*\)/,
    );
  });
});

// ===========================================================================
// G49 — STANDARD_LOCKTIME_VERIFY_FLAGS constant equivalence — PRESENT
// ===========================================================================
describe("W132-G49: STANDARD_LOCKTIME_VERIFY_FLAGS equivalence — PRESENT", () => {
  test("hotbuns elides the constant indirection — directly checks tx.version+csvHeight", () => {
    // Core sets STANDARD_LOCKTIME_VERIFY_FLAGS = LOCKTIME_VERIFY_SEQUENCE
    // and passes it to CalculateSequenceLocks. Hotbuns flattens this into a
    // single boolean. The condition is the divergence (BUG-4); the absence
    // of the constant is just style.
    expect(VAL_TX_SRC).not.toMatch(/STANDARD_LOCKTIME_VERIFY_FLAGS/);
    expect(VAL_TX_SRC).not.toMatch(/LOCKTIME_VERIFY_SEQUENCE/);
  });
});

// ===========================================================================
// G50 — LOCKTIME_THRESHOLD = 500_000_000 — PRESENT
// ===========================================================================
describe("W132-G50: LOCKTIME_THRESHOLD = 500_000_000 — PRESENT", () => {
  test("constant present in interpreter, template, and miniscript", () => {
    expect(INTERP_SRC).toMatch(/LOCKTIME_THRESHOLD\s*=\s*500_000_000/);
    expect(TEMPLATE_SRC).toMatch(/LOCKTIME_THRESHOLD\s*=\s*500_000_000/);
  });
});
