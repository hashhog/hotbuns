import { describe, expect, test } from "bun:test";
import {
  SEQUENCE_LOCKTIME_DISABLE_FLAG,
  SEQUENCE_LOCKTIME_TYPE_FLAG,
  SEQUENCE_LOCKTIME_MASK,
  SEQUENCE_LOCKTIME_GRANULARITY,
  SEQUENCE_FINAL,
  calculateSequenceLocks,
  evaluateSequenceLocks,
  checkSequenceLocks,
  type UTXOConfirmation,
  type Transaction,
} from "../validation/tx";

/**
 * Helper to create a minimal transaction for testing.
 */
function createTestTx(version: number, sequences: number[]): Transaction {
  return {
    version,
    inputs: sequences.map((seq) => ({
      prevOut: {
        txid: Buffer.alloc(32, 0x01),
        vout: 0,
      },
      scriptSig: Buffer.alloc(0),
      sequence: seq,
      witness: [],
    })),
    outputs: [
      {
        value: 100000000n,
        scriptPubKey: Buffer.from([0x76, 0xa9, 0x14]),
      },
    ],
    lockTime: 0,
  };
}

describe("BIP68 constants", () => {
  test("SEQUENCE_LOCKTIME_DISABLE_FLAG is bit 31", () => {
    // In JS, 1 << 31 gives -2147483648 (signed), but >>> 0 gives unsigned
    expect(SEQUENCE_LOCKTIME_DISABLE_FLAG).toBe(1 << 31);
    expect((SEQUENCE_LOCKTIME_DISABLE_FLAG >>> 0) === 0x80000000).toBe(true);
  });

  test("SEQUENCE_LOCKTIME_TYPE_FLAG is bit 22", () => {
    expect(SEQUENCE_LOCKTIME_TYPE_FLAG).toBe(0x00400000);
    expect(SEQUENCE_LOCKTIME_TYPE_FLAG).toBe(4194304);
  });

  test("SEQUENCE_LOCKTIME_MASK is lower 16 bits", () => {
    expect(SEQUENCE_LOCKTIME_MASK).toBe(0x0000ffff);
    expect(SEQUENCE_LOCKTIME_MASK).toBe(65535);
  });

  test("SEQUENCE_LOCKTIME_GRANULARITY is 9 (512 seconds)", () => {
    expect(SEQUENCE_LOCKTIME_GRANULARITY).toBe(9);
    expect(1 << SEQUENCE_LOCKTIME_GRANULARITY).toBe(512);
  });

  test("SEQUENCE_FINAL is 0xffffffff", () => {
    expect(SEQUENCE_FINAL).toBe(0xffffffff);
  });
});

describe("calculateSequenceLocks", () => {
  test("returns -1/-1 when BIP68 not enforced", () => {
    const tx = createTestTx(2, [10]); // 10 blocks relative lock
    const confirmations: UTXOConfirmation[] = [{ height: 100, medianTimePast: 1000000 }];

    const locks = calculateSequenceLocks(tx, false, confirmations);

    expect(locks.minHeight).toBe(-1);
    expect(locks.minTime).toBe(-1);
  });

  test("returns -1/-1 for version 1 transactions", () => {
    const tx = createTestTx(1, [10]); // Version 1, 10 blocks relative lock
    const confirmations: UTXOConfirmation[] = [{ height: 100, medianTimePast: 1000000 }];

    const locks = calculateSequenceLocks(tx, true, confirmations);

    expect(locks.minHeight).toBe(-1);
    expect(locks.minTime).toBe(-1);
  });

  test("ignores inputs with disable flag set", () => {
    const disabledSeq = SEQUENCE_LOCKTIME_DISABLE_FLAG | 100;
    const tx = createTestTx(2, [disabledSeq]);
    const confirmations: UTXOConfirmation[] = [{ height: 100, medianTimePast: 1000000 }];

    const locks = calculateSequenceLocks(tx, true, confirmations);

    expect(locks.minHeight).toBe(-1);
    expect(locks.minTime).toBe(-1);
  });

  test("calculates height-based lock correctly", () => {
    // Relative lock of 10 blocks
    const relativeBlocks = 10;
    const tx = createTestTx(2, [relativeBlocks]);
    const utxoHeight = 100;
    const confirmations: UTXOConfirmation[] = [{ height: utxoHeight, medianTimePast: 1000000 }];

    const locks = calculateSequenceLocks(tx, true, confirmations);

    // minHeight uses nLockTime semantics (last invalid height)
    // So minHeight = utxoHeight + relativeBlocks - 1 = 100 + 10 - 1 = 109
    expect(locks.minHeight).toBe(109);
    expect(locks.minTime).toBe(-1);
  });

  test("calculates time-based lock correctly", () => {
    // Relative lock of 10 * 512 seconds
    const relative512Intervals = 10;
    const timeSeq = SEQUENCE_LOCKTIME_TYPE_FLAG | relative512Intervals;
    const tx = createTestTx(2, [timeSeq]);
    const coinMTP = 1000000;
    const confirmations: UTXOConfirmation[] = [{ height: 100, medianTimePast: coinMTP }];

    const locks = calculateSequenceLocks(tx, true, confirmations);

    // minTime = coinMTP + (relative512Intervals << 9) - 1
    // = 1000000 + (10 * 512) - 1 = 1000000 + 5120 - 1 = 1005119
    expect(locks.minHeight).toBe(-1);
    expect(locks.minTime).toBe(1005119);
  });

  test("takes maximum of multiple height locks", () => {
    const tx = createTestTx(2, [10, 20, 5]); // Three inputs with different locks
    const confirmations: UTXOConfirmation[] = [
      { height: 100, medianTimePast: 0 },
      { height: 100, medianTimePast: 0 },
      { height: 100, medianTimePast: 0 },
    ];

    const locks = calculateSequenceLocks(tx, true, confirmations);

    // Maximum relative lock is 20, so minHeight = 100 + 20 - 1 = 119
    expect(locks.minHeight).toBe(119);
    expect(locks.minTime).toBe(-1);
  });

  test("takes maximum of multiple time locks", () => {
    const seq1 = SEQUENCE_LOCKTIME_TYPE_FLAG | 10; // 10 * 512 = 5120 seconds
    const seq2 = SEQUENCE_LOCKTIME_TYPE_FLAG | 20; // 20 * 512 = 10240 seconds
    const tx = createTestTx(2, [seq1, seq2]);
    const coinMTP = 1000000;
    const confirmations: UTXOConfirmation[] = [
      { height: 100, medianTimePast: coinMTP },
      { height: 100, medianTimePast: coinMTP },
    ];

    const locks = calculateSequenceLocks(tx, true, confirmations);

    // Maximum is 20 * 512 = 10240 seconds
    // minTime = 1000000 + 10240 - 1 = 1010239
    expect(locks.minHeight).toBe(-1);
    expect(locks.minTime).toBe(1010239);
  });

  test("handles mixed height and time locks", () => {
    const heightSeq = 10; // 10 blocks
    const timeSeq = SEQUENCE_LOCKTIME_TYPE_FLAG | 5; // 5 * 512 = 2560 seconds
    const tx = createTestTx(2, [heightSeq, timeSeq]);
    const confirmations: UTXOConfirmation[] = [
      { height: 100, medianTimePast: 0 },
      { height: 100, medianTimePast: 1000000 },
    ];

    const locks = calculateSequenceLocks(tx, true, confirmations);

    // Height lock: 100 + 10 - 1 = 109
    // Time lock: 1000000 + 2560 - 1 = 1002559
    expect(locks.minHeight).toBe(109);
    expect(locks.minTime).toBe(1002559);
  });

  test("UTXO at different heights affects locks", () => {
    const relativeBlocks = 10;
    const tx = createTestTx(2, [relativeBlocks, relativeBlocks]);
    const confirmations: UTXOConfirmation[] = [
      { height: 100, medianTimePast: 0 },
      { height: 200, medianTimePast: 0 }, // This UTXO is newer
    ];

    const locks = calculateSequenceLocks(tx, true, confirmations);

    // Input 0: 100 + 10 - 1 = 109
    // Input 1: 200 + 10 - 1 = 209
    // Maximum is 209
    expect(locks.minHeight).toBe(209);
  });

  test("0xffffffff (SEQUENCE_FINAL) with disable flag is ignored", () => {
    // SEQUENCE_FINAL has bit 31 set, so BIP68 is disabled
    const tx = createTestTx(2, [SEQUENCE_FINAL]);
    const confirmations: UTXOConfirmation[] = [{ height: 100, medianTimePast: 1000000 }];

    const locks = calculateSequenceLocks(tx, true, confirmations);

    expect(locks.minHeight).toBe(-1);
    expect(locks.minTime).toBe(-1);
  });

  test("throws if confirmation count mismatches input count", () => {
    const tx = createTestTx(2, [10, 20]);
    const confirmations: UTXOConfirmation[] = [{ height: 100, medianTimePast: 0 }]; // Only 1!

    expect(() => calculateSequenceLocks(tx, true, confirmations)).toThrow(
      "UTXO confirmation count must match input count"
    );
  });
});

describe("evaluateSequenceLocks", () => {
  test("returns true when no locks (-1/-1)", () => {
    const result = evaluateSequenceLocks(100, 1000000, { minHeight: -1, minTime: -1 });
    expect(result).toBe(true);
  });

  test("returns true when block height > minHeight", () => {
    const result = evaluateSequenceLocks(110, 1000000, { minHeight: 109, minTime: -1 });
    expect(result).toBe(true);
  });

  test("returns false when block height <= minHeight", () => {
    const result = evaluateSequenceLocks(109, 1000000, { minHeight: 109, minTime: -1 });
    expect(result).toBe(false);
  });

  test("returns true when prevMTP > minTime", () => {
    const result = evaluateSequenceLocks(100, 1005120, { minHeight: -1, minTime: 1005119 });
    expect(result).toBe(true);
  });

  test("returns false when prevMTP <= minTime", () => {
    const result = evaluateSequenceLocks(100, 1005119, { minHeight: -1, minTime: 1005119 });
    expect(result).toBe(false);
  });

  test("requires both height and time conditions to be satisfied", () => {
    const locks = { minHeight: 109, minTime: 1005119 };

    // Height OK, time not OK
    expect(evaluateSequenceLocks(110, 1005119, locks)).toBe(false);

    // Height not OK, time OK
    expect(evaluateSequenceLocks(109, 1005120, locks)).toBe(false);

    // Both OK
    expect(evaluateSequenceLocks(110, 1005120, locks)).toBe(true);
  });
});

describe("checkSequenceLocks", () => {
  test("combines calculateSequenceLocks and evaluateSequenceLocks", () => {
    // 10 block relative lock on UTXO at height 100
    const tx = createTestTx(2, [10]);
    const confirmations: UTXOConfirmation[] = [{ height: 100, medianTimePast: 0 }];

    // Need block height > 109 (100 + 10 - 1)
    expect(checkSequenceLocks(tx, true, 109, 0, confirmations)).toBe(false);
    expect(checkSequenceLocks(tx, true, 110, 0, confirmations)).toBe(true);
    expect(checkSequenceLocks(tx, true, 111, 0, confirmations)).toBe(true);
  });

  test("returns true when BIP68 not enforced", () => {
    const tx = createTestTx(2, [10]);
    const confirmations: UTXOConfirmation[] = [{ height: 100, medianTimePast: 0 }];

    // Would fail if BIP68 enforced, but passes because it's not
    expect(checkSequenceLocks(tx, false, 100, 0, confirmations)).toBe(true);
  });

  test("returns true for version 1 tx even with relative locks", () => {
    const tx = createTestTx(1, [10]);
    const confirmations: UTXOConfirmation[] = [{ height: 100, medianTimePast: 0 }];

    // Would fail for v2 tx, but passes for v1
    expect(checkSequenceLocks(tx, true, 100, 0, confirmations)).toBe(true);
  });
});

describe("sequence_lock edge cases", () => {
  test("zero relative lock is immediately spendable", () => {
    const tx = createTestTx(2, [0]); // No relative lock
    const confirmations: UTXOConfirmation[] = [{ height: 100, medianTimePast: 0 }];

    // minHeight = 100 + 0 - 1 = 99
    // Block at height 100 is > 99, so valid
    expect(checkSequenceLocks(tx, true, 100, 0, confirmations)).toBe(true);
  });

  test("single block relative lock (relative = 1)", () => {
    const tx = createTestTx(2, [1]);
    const confirmations: UTXOConfirmation[] = [{ height: 100, medianTimePast: 0 }];

    // minHeight = 100 + 1 - 1 = 100
    // Need height > 100
    expect(checkSequenceLocks(tx, true, 100, 0, confirmations)).toBe(false);
    expect(checkSequenceLocks(tx, true, 101, 0, confirmations)).toBe(true);
  });

  test("maximum 16-bit lock value (65535 blocks)", () => {
    const tx = createTestTx(2, [SEQUENCE_LOCKTIME_MASK]);
    const confirmations: UTXOConfirmation[] = [{ height: 100, medianTimePast: 0 }];

    const locks = calculateSequenceLocks(tx, true, confirmations);
    // minHeight = 100 + 65535 - 1 = 65634
    expect(locks.minHeight).toBe(65634);
  });

  test("maximum 16-bit time lock (65535 * 512 seconds)", () => {
    const timeSeq = SEQUENCE_LOCKTIME_TYPE_FLAG | SEQUENCE_LOCKTIME_MASK;
    const tx = createTestTx(2, [timeSeq]);
    const coinMTP = 1000000;
    const confirmations: UTXOConfirmation[] = [{ height: 100, medianTimePast: coinMTP }];

    const locks = calculateSequenceLocks(tx, true, confirmations);
    // minTime = 1000000 + (65535 * 512) - 1 = 1000000 + 33553920 - 1 = 34553919
    expect(locks.minTime).toBe(34553919);
  });

  test("UTXO mined in same block as tx (height = current height) with 0 lock", () => {
    const tx = createTestTx(2, [0]);
    const currentHeight = 100;
    // UTXO was mined in this same block
    const confirmations: UTXOConfirmation[] = [{ height: currentHeight, medianTimePast: 0 }];

    // minHeight = 100 + 0 - 1 = 99
    // Current height 100 > 99, so valid
    expect(checkSequenceLocks(tx, true, currentHeight, 0, confirmations)).toBe(true);
  });

  test("intra-block spend with 1-block relative lock should fail", () => {
    const tx = createTestTx(2, [1]);
    const currentHeight = 100;
    // UTXO was mined in this same block
    const confirmations: UTXOConfirmation[] = [{ height: currentHeight, medianTimePast: 0 }];

    // minHeight = 100 + 1 - 1 = 100
    // Current height 100 is NOT > 100, so invalid
    expect(checkSequenceLocks(tx, true, currentHeight, 0, confirmations)).toBe(false);
  });
});
