/**
 * IsFinalTx consensus rule tests.
 * Reference: Bitcoin Core ContextualCheckBlock validation.cpp:4146
 */

import { describe, it, expect } from "bun:test";
import { isFinalTx } from "../src/mining/template.js";
import type { Transaction } from "../src/validation/tx.js";

const SEQUENCE_FINAL = 0xffffffff;
const LOCKTIME_THRESHOLD = 500_000_000;

function makeTx(lockTime: number, sequences: number[]): Transaction {
  return {
    version: 1,
    inputs: sequences.map((seq) => ({
      prevOut: { txid: Buffer.alloc(32, 0), vout: 0 },
      scriptSig: Buffer.alloc(0),
      sequence: seq,
      witness: [],
    })),
    outputs: [],
    lockTime,
  };
}

describe("isFinalTx (Core ContextualCheckBlock parity)", () => {
  it("zero locktime is always final", () => {
    const tx = makeTx(0, [0]);
    expect(isFinalTx(tx, 1000, 900_000_001)).toBe(true);
  });

  it("height-based locktime satisfied (lockTime < blockHeight)", () => {
    const tx = makeTx(100, [0]);
    expect(isFinalTx(tx, 101, 900_000_001)).toBe(true);
  });

  it("height-based locktime not satisfied, non-final sequence → non-final", () => {
    const tx = makeTx(200, [1]);  // sequence != SEQUENCE_FINAL
    expect(isFinalTx(tx, 100, 900_000_001)).toBe(false);
  });

  it("SEQUENCE_FINAL on all inputs overrides unsatisfied locktime", () => {
    const tx = makeTx(999_999_999, [SEQUENCE_FINAL]);
    expect(isFinalTx(tx, 100, 900_000_001)).toBe(true);
  });

  it("mixed inputs: one non-SEQUENCE_FINAL → non-final", () => {
    const tx = makeTx(500, [SEQUENCE_FINAL, 0]);
    expect(isFinalTx(tx, 100, 900_000_001)).toBe(false);
  });

  it("time-based locktime satisfied (lockTime < MTP)", () => {
    const tx = makeTx(500_000_001, [0]);  // time-based (>= threshold)
    expect(isFinalTx(tx, 100, 500_000_002)).toBe(true);
  });

  it("time-based locktime not satisfied, non-final sequence → non-final", () => {
    const tx = makeTx(500_000_002, [1]);
    expect(isFinalTx(tx, 100, 500_000_001)).toBe(false);
  });
});
