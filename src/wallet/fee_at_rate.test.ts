/**
 * feeAtRate: the wallet's per-tx fee, rounded up like Core's CFeeRate::GetFee
 * (policy/feerate.cpp, FeeFrac::EvaluateFeeUp) over an integer sat/kvB rate.
 */
import { describe, it, expect } from "bun:test";
import { feeAtRate } from "./wallet.js";

describe("feeAtRate rounds like CFeeRate::GetFee", () => {
  it("works in integer sat/kvB: 1.1 sat/vB * 100 vB = 110 sat (float ceil gives 111)", () => {
    expect(Math.ceil(100 * 1.1)).toBe(111); // the float trap this avoids
    expect(feeAtRate(100, 1.1)).toBe(110n);
    expect(feeAtRate(200, 1.1)).toBe(220n);
  });

  it("rounds a partial satoshi up", () => {
    expect(feeAtRate(141, 1.001)).toBe(142n); // 141.141 -> 142
    expect(feeAtRate(1, 0.1)).toBe(1n); // 0.1 -> 1
    expect(feeAtRate(10, 1)).toBe(10n);
  });

  it("evaluates fractional vbytes (weight / 4) over the weight", () => {
    // 273 WU at 1000 sat/kvB: ceil(273 * 1000 / 4000) = ceil(68.25) = 69
    expect(feeAtRate(273 / 4, 1)).toBe(69n);
  });

  it("zero rate is zero fee", () => {
    expect(feeAtRate(200, 0)).toBe(0n);
  });
});
