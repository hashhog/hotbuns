/**
 * W139 — Fee estimation engine (CBlockPolicyEstimator) — hotbuns
 *
 * Discovery audit. Each test either
 *   (a) PASSes today, documenting a Core-parity behavior to keep, OR
 *   (b) DOCUMENTS a bug by asserting the CURRENT divergent behavior
 *       and including a `// BUG-N` comment so a future fix wave can
 *       grep this file and invert the assertions.
 *
 * Reference:
 *   - bitcoin-core/src/policy/fees/block_policy_estimator.{h,cpp}
 *   - bitcoin-core/src/policy/feerate.{h,cpp}
 *   - bitcoin-core/src/rpc/fees.cpp
 *   - bitcoin-core/src/rpc/util.cpp (ParseConfirmTarget)
 *
 * Companion document: audit/w139_fee_estimation.md.
 *
 * Run: bun test src/__tests__/w139_fee_estimation.test.ts
 */

import { describe, it, expect } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

import {
  DECAY,
  SCALE,
  PERIODS,
  Horizon,
} from "../fees/estimator";

// =============================================================================
// Source-level helpers
// =============================================================================

const REPO_ROOT = join(import.meta.dirname, "..", "..");
const SRC_ROOT = join(REPO_ROOT, "src");

function readSrc(rel: string): string {
  return readFileSync(join(SRC_ROOT, rel), "utf8");
}

const ESTIMATOR_SRC = readSrc("fees/estimator.ts");
const RPC_SERVER_SRC = readSrc("rpc/server.ts");
const FEEFILTER_SRC = readSrc("p2p/feefilter.ts");

// =============================================================================
// G1 — Per-horizon decay constants (SHORT=.962 / MED=.9952 / LONG=.99931)
// =============================================================================

describe("W139-G1: per-horizon decay constants", () => {
  it("PRESENT: byte-identical to Core (block_policy_estimator.h:163-167)", () => {
    expect(DECAY[Horizon.Short]).toBe(0.962);
    expect(DECAY[Horizon.Medium]).toBe(0.9952);
    expect(DECAY[Horizon.Long]).toBe(0.99931);
  });
});

// =============================================================================
// G2 — DEFAULT_FEE_RATE = 20 sat/vB fallback (BUG-1, P2-CONSISTENCY)
// =============================================================================

describe("W139-G2: DEFAULT_FEE_RATE=20 fallback (BUG-1)", () => {
  it("BUG-1: hotbuns has a hardcoded 20 sat/vB fallback (Core returns CFeeRate(0))", () => {
    // Core returns CFeeRate(0) to signal error; hotbuns substitutes 20.
    // Source-level: DEFAULT_FEE_RATE constant exists at top of estimator.ts.
    expect(ESTIMATOR_SRC).toMatch(/const\s+DEFAULT_FEE_RATE\s*=\s*20\b/);
    // It is returned from estimateFee() and estimateSmartFee() fallbacks.
    expect(ESTIMATOR_SRC).toMatch(/return\s+DEFAULT_FEE_RATE\s*;/);
    expect(ESTIMATOR_SRC).toMatch(
      /return\s*\{\s*feeRate:\s*DEFAULT_FEE_RATE,\s*blocks:/
    );
  });

  it("BUG-1: RPC layer masks the bug via its own zero/falsy gate", () => {
    // server.ts:4045 — `if (!estimate.feeRate || estimate.feeRate <= 0)`.
    // But estimate.feeRate is NEVER <=0 because hotbuns always returns >=20.
    // So the masking branch is effectively dead — a future change to the
    // fallback semantics would expose the divergence.
    expect(RPC_SERVER_SRC).toMatch(/!estimate\.feeRate\s*\|\|\s*estimate\.feeRate\s*<=\s*0/);
  });
});

// =============================================================================
// G3 — Bucket boundaries (Core: 100..1e7 sat/kvB × 1.05; hotbuns: 41 sat/vB)
//      (BUG-2, P0-CDIV)
// =============================================================================

describe("W139-G3: bucket boundaries shape mismatch (BUG-2, P0-CDIV)", () => {
  it("BUG-2: hotbuns has ~41 hardcoded sat/vB buckets (Core has ~235 sat/kvB 1.05-spaced)", () => {
    // Source-level: BUCKET_BOUNDARIES is a fixed array literal.
    const m = ESTIMATOR_SRC.match(
      /const\s+BUCKET_BOUNDARIES[^=]*=\s*\[([^\]]+)\]/
    );
    expect(m).not.toBeNull();
    if (m) {
      const entries = m[1]
        .split(",")
        .map((s) => s.trim())
        .filter((s) => s.length > 0 && /^\d/.test(s));
      // Hotbuns: ~41 buckets, hand-picked.
      expect(entries.length).toBeGreaterThanOrEqual(35);
      expect(entries.length).toBeLessThanOrEqual(50);
      // Hand-picked, not 1.05-spaced — confirm by ratio test on a few pairs.
      const n0 = Number(entries[0]);
      const n1 = Number(entries[1]);
      // 1.05-spaced would give 100 * 1.05 = 105, not 1->2.
      expect(n0).toBe(1);
      expect(n1).toBe(2);
      // 2/1 = 2 ≠ 1.05.
      expect(n1 / n0).toBeGreaterThan(1.5);
    }
  });

  it("BUG-2: no INF_FEERATE / MIN_BUCKET_FEERATE / MAX_BUCKET_FEERATE constants", () => {
    expect(ESTIMATOR_SRC).not.toMatch(/INF_FEERATE/);
    expect(ESTIMATOR_SRC).not.toMatch(/MIN_BUCKET_FEERATE/);
    expect(ESTIMATOR_SRC).not.toMatch(/MAX_BUCKET_FEERATE/);
    expect(ESTIMATOR_SRC).not.toMatch(/FEE_SPACING/);
  });

  it("BUG-2: unit is sat/vB everywhere (Core uses sat/kvB internally)", () => {
    // Core's CFeeRate.GetFeePerK() returns sat/kvB; estimator stores them.
    // Hotbuns RPC explicitly divides by 100_000 to convert sat/vB → BTC/kvB
    // at the API boundary, confirming internal unit is sat/vB.
    expect(RPC_SERVER_SRC).toMatch(
      /feerate:\s*estimate\.feeRate\s*\/\s*100_000/
    );
    expect(RPC_SERVER_SRC).toMatch(/Convert sat\/vB to BTC\/kvB/);
  });
});

// =============================================================================
// G4 — Per-horizon scale (SHORT=1 / MED=2 / LONG=24) + periods (12/24/42)
// =============================================================================

describe("W139-G4: per-horizon scale + periods", () => {
  it("PRESENT: scale matches Core (block_policy_estimator.h:152,155,158)", () => {
    expect(SCALE[Horizon.Short]).toBe(1);
    expect(SCALE[Horizon.Medium]).toBe(2);
    expect(SCALE[Horizon.Long]).toBe(24);
  });

  it("PRESENT: periods matches Core (block_policy_estimator.h:151,154,157)", () => {
    expect(PERIODS[Horizon.Short]).toBe(12);
    expect(PERIODS[Horizon.Medium]).toBe(24);
    expect(PERIODS[Horizon.Long]).toBe(42);
  });

  it("PRESENT: max-confirms coverage = scale*periods (12/48/1008)", () => {
    expect(SCALE[Horizon.Short] * PERIODS[Horizon.Short]).toBe(12);
    expect(SCALE[Horizon.Medium] * PERIODS[Horizon.Medium]).toBe(48);
    expect(SCALE[Horizon.Long] * PERIODS[Horizon.Long]).toBe(1008);
  });
});

// =============================================================================
// G5 — Three-horizon partition (Short / Medium / Long)
// =============================================================================

describe("W139-G5: three-horizon partition", () => {
  it("PRESENT: Horizon enum has Short=0, Medium=1, Long=2", () => {
    expect(Horizon.Short).toBe(0);
    expect(Horizon.Medium).toBe(1);
    expect(Horizon.Long).toBe(2);
  });

  it("PRESENT: estimator constructor instantiates all three horizon-stats records", () => {
    // Source-level confirmation — `this.horizons = {[Horizon.Short]: ...,
    // [Horizon.Medium]: ..., [Horizon.Long]: ...}` literal.
    expect(ESTIMATOR_SRC).toMatch(/\[Horizon\.Short\]:\s*makeHorizonStats/);
    expect(ESTIMATOR_SRC).toMatch(/\[Horizon\.Medium\]:\s*makeHorizonStats/);
    expect(ESTIMATOR_SRC).toMatch(/\[Horizon\.Long\]:\s*makeHorizonStats/);
  });
});

// =============================================================================
// G6 — m_feerate_avg per-bucket sum (BUG-3, P0-CDIV)
// =============================================================================

describe("W139-G6: m_feerate_avg per-bucket sum (BUG-3, P0-CDIV)", () => {
  it("BUG-3: estimator does NOT track per-bucket decay-accumulated feerate sum", () => {
    // Core: m_feerate_avg[bucketindex] += feerate; median = sum/count.
    // Hotbuns: HorizonBucketStats has {confirmed, unconfirmed, confirmationBlocks}.
    // No `feeRateAvg` / `feerateSum` / `m_feerate_avg` field.
    expect(ESTIMATOR_SRC).not.toMatch(/m_feerate_avg/);
    expect(ESTIMATOR_SRC).not.toMatch(/feeRateSum/);
    expect(ESTIMATOR_SRC).not.toMatch(/feerateAvg/);
    // The HorizonBucketStats interface has only the three fields.
    const m = ESTIMATOR_SRC.match(
      /interface\s+HorizonBucketStats\s*\{([\s\S]*?)\n\}/
    );
    expect(m).not.toBeNull();
    if (m) {
      expect(m[1]).toMatch(/confirmed:\s*number/);
      expect(m[1]).toMatch(/unconfirmed:\s*number/);
      expect(m[1]).toMatch(/confirmationBlocks:\s*number\[\]/);
      // No 4th field for feerate-sum.
      const fieldCount = m[1].split(":").length - 1;
      expect(fieldCount).toBeLessThanOrEqual(3);
    }
  });

  it("BUG-3: estimateFee returns bucket.feeRateRange.min (Core returns avg via m_feerate_avg/txCtAvg)", () => {
    // Core: median = m_feerate_avg[j] / txCtAvg[j];
    // Hotbuns: return this.buckets[lowestBucketIndex].feeRateRange.min;
    expect(ESTIMATOR_SRC).toMatch(
      /return\s+this\.buckets\[lowestBucketIndex\]\.feeRateRange\.min/
    );
  });
});

// =============================================================================
// G7 — unconfTxs[Y][X] ring buffer + oldUnconfTxs (BUG-4, P1-API)
// =============================================================================

describe("W139-G7: unconfTxs ring buffer + oldUnconfTxs aging (BUG-4, P1-API)", () => {
  it("BUG-4: no per-height-modulo ring buffer for unconfirmed counts", () => {
    // Core: vector<vector<int>> unconfTxs;  // unconfTxs[Y][X]
    //       vector<int> oldUnconfTxs;        //   for txs aged > maxConfirms
    // Hotbuns: scalar `unconfirmed: number` per bucket per horizon, decayed.
    expect(ESTIMATOR_SRC).not.toMatch(/unconfTxs/);
    expect(ESTIMATOR_SRC).not.toMatch(/oldUnconfTxs/);
    expect(ESTIMATOR_SRC).not.toMatch(/ClearCurrent/);
  });

  it("BUG-4: applyDecay() decays `unconfirmed` exponentially (Core never decays unconfTxs)", () => {
    // Core's `unconfTxs[Y][X]` is rolled (zeroed) by ClearCurrent per new
    // block, NOT decayed. Hotbuns decays unconfirmed inline with confirmed.
    expect(ESTIMATOR_SRC).toMatch(/hb\.unconfirmed\s*\*=\s*hDecay/);
  });
});

// =============================================================================
// G8 — confAvg[Y][X] per-period confirmation matrix (BUG-5, P0-CDIV)
// =============================================================================

describe("W139-G8: confAvg[Y][X] per-period matrix (BUG-5, P0-CDIV)", () => {
  it("BUG-5: no confAvg[Y][X] matrix — raw confirmationBlocks: number[] instead", () => {
    expect(ESTIMATOR_SRC).not.toMatch(/confAvg/);
    expect(ESTIMATOR_SRC).toMatch(/confirmationBlocks:\s*number\[\]/);
  });

  it("BUG-5: estimate is O(N) per call via Array.filter (Core is O(1) lookup)", () => {
    // Hotbuns's estimateFee + estimateFeeWithData + estimateFeeForHorizon
    // all do `.filter((blocks) => blocks <= targetBlocks).length` on the
    // raw array. Core reads `confAvg[periodTarget-1][bucket]` directly.
    expect(ESTIMATOR_SRC).toMatch(
      /\.filter\(\s*\(blocks\)\s*=>\s*blocks\s*<=\s*targetBlocks\s*\)\.length/
    );
  });

  it("BUG-5: ad-hoc array trim at length>10000 (Core decays oldest-first naturally)", () => {
    // Hotbuns slices the array on overflow, abruptly forgetting the oldest
    // 5000 entries. Core's decay does this continuously and gracefully.
    expect(ESTIMATOR_SRC).toMatch(/confirmationBlocks\.length\s*>\s*10000/);
    expect(ESTIMATOR_SRC).toMatch(/\.slice\(-5000\)/);
  });
});

// =============================================================================
// G9 — failAvg[Y][X] per-period failure matrix (BUG-6, P0-CDIV)
// =============================================================================

describe("W139-G9: failAvg[Y][X] failure tracking (BUG-6, P0-CDIV)", () => {
  it("BUG-6: no failure tracking — txs evicted from mempool aren't recorded as failures", () => {
    expect(ESTIMATOR_SRC).not.toMatch(/failAvg/);
    expect(ESTIMATOR_SRC).not.toMatch(/leftMempool/);
    // Hotbuns's HorizonBucketStats has no `failed` counter.
    const m = ESTIMATOR_SRC.match(
      /interface\s+HorizonBucketStats\s*\{([\s\S]*?)\n\}/
    );
    if (m) {
      expect(m[1]).not.toMatch(/failed:/);
      expect(m[1]).not.toMatch(/fail:/);
    }
  });

  it("BUG-6: estimaterawfee returns leftmempool:0 unconditionally (Core uses failAvg)", () => {
    // server.ts:4153 — `leftmempool: 0,` — placeholder, never populated.
    expect(RPC_SERVER_SRC).toMatch(/leftmempool:\s*0,/);
  });
});

// =============================================================================
// G10 — processBlock side-chain / reorg skip (BUG-7, P2-CONSISTENCY)
// =============================================================================

describe("W139-G10: processBlock side-chain skip (BUG-7, P2)", () => {
  it("BUG-7: estimator has no `nBestSeenHeight` field — no side-chain guard", () => {
    // Core: `if (nBlockHeight <= nBestSeenHeight) return;`
    expect(ESTIMATOR_SRC).not.toMatch(/nBestSeenHeight/);
    expect(ESTIMATOR_SRC).not.toMatch(/bestSeenHeight/);
    // The processBlock function unconditionally calls applyDecay():
    const m = ESTIMATOR_SRC.match(
      /processBlock\(block:\s*Block,\s*height:\s*number\)\s*:\s*void\s*\{([\s\S]*?)\n\s*\}/
    );
    expect(m).not.toBeNull();
    if (m) {
      // No height < lastHeight guard at the top of processBlock.
      expect(m[1]).not.toMatch(/if\s*\(\s*height\s*<=?/);
    }
  });
});

// =============================================================================
// G11 — MaxUsableEstimate via BlockSpan / HistoricalBlockSpan (BUG-8, P1-API)
// =============================================================================

describe("W139-G11: MaxUsableEstimate clamp (BUG-8, P1-API)", () => {
  it("BUG-8: no BlockSpan / HistoricalBlockSpan / MaxUsableEstimate methods", () => {
    expect(ESTIMATOR_SRC).not.toMatch(/MaxUsableEstimate/);
    expect(ESTIMATOR_SRC).not.toMatch(/BlockSpan/);
    expect(ESTIMATOR_SRC).not.toMatch(/HistoricalBlockSpan/);
    expect(ESTIMATOR_SRC).not.toMatch(/firstRecordedHeight/);
    expect(ESTIMATOR_SRC).not.toMatch(/historicalFirst/);
    expect(ESTIMATOR_SRC).not.toMatch(/historicalBest/);
  });

  it("BUG-8: confTarget clamps only to [1, 1008] in RPC, not to data-span", () => {
    // server.ts:4041 — `Math.max(1, Math.min(1008, confTargetParam))`
    expect(RPC_SERVER_SRC).toMatch(
      /Math\.max\(\s*1,\s*Math\.min\(\s*1008,\s*confTargetParam\s*\)\s*\)/
    );
  });
});

// =============================================================================
// G12 — estimateCombinedFee cross-horizon downgrade (BUG-9, P1-API)
// =============================================================================

describe("W139-G12: estimateCombinedFee cross-horizon downgrade (BUG-9, P1-API)", () => {
  it("BUG-9: no cross-horizon min-over check in estimateSmartFee", () => {
    expect(ESTIMATOR_SRC).not.toMatch(/estimateCombinedFee/);
    expect(ESTIMATOR_SRC).not.toMatch(/checkShorterHorizon/);
    // selectHorizon picks ONE horizon and that's it — no min/max over horizons.
    const m = ESTIMATOR_SRC.match(/selectHorizon\([\s\S]*?\)\s*:\s*Horizon\s*\{([\s\S]*?)\n\s*\}/);
    expect(m).not.toBeNull();
    if (m) {
      // Only returns the single selected horizon; no Math.min over alternatives.
      expect(m[1]).toMatch(/return\s+Horizon\./);
      expect(m[1]).not.toMatch(/Math\.min/);
    }
  });
});

// =============================================================================
// G13 — estimate_mode parsing / conservative param (BUG-10, P2)
// =============================================================================

describe("W139-G13: estimate_mode parameter (BUG-10, P2)", () => {
  it("BUG-10: estimatesmartfee silently ignores the estimate_mode parameter", () => {
    // server.ts:4034 — destructures only `[confTargetParam]`, params[1] dropped.
    const m = RPC_SERVER_SRC.match(
      /private\s+async\s+estimateSmartFee\(params:[\s\S]*?\)\s*:[\s\S]*?\{([\s\S]*?)\n\s\s\}/
    );
    expect(m).not.toBeNull();
    if (m) {
      const body = m[1];
      // The first line destructures params[0] only.
      expect(body).toMatch(/const\s*\[\s*confTargetParam\s*\]\s*=\s*params/);
      // No `estimate_mode` / `conservative` parsing.
      expect(body).not.toMatch(/conservative/);
      expect(body).not.toMatch(/estimate_mode/);
      expect(body).not.toMatch(/economical/);
    }
  });

  it("BUG-10: feeEstimator.estimateSmartFee takes only targetBlocks (no conservative)", () => {
    expect(ESTIMATOR_SRC).toMatch(
      /estimateSmartFee\(targetBlocks:\s*number\)\s*:\s*\{\s*feeRate:\s*number;\s*blocks:\s*number\s*\}/
    );
  });
});

// =============================================================================
// G14 — 3-tier HALF/FULL/DOUBLE + max + conservative (BUG-11, P0-CDIV)
// =============================================================================

describe("W139-G14: HALF/FULL/DOUBLE 3-tier estimate (BUG-11, P0-CDIV)", () => {
  it("BUG-11: no 3-tier threshold algorithm — single CONFIDENCE_THRESHOLD = 0.85", () => {
    expect(ESTIMATOR_SRC).toMatch(/const\s+CONFIDENCE_THRESHOLD\s*=\s*0\.85/);
    // No HALF_SUCCESS_PCT / DOUBLE_SUCCESS_PCT constants.
    expect(ESTIMATOR_SRC).not.toMatch(/HALF_SUCCESS_PCT/);
    expect(ESTIMATOR_SRC).not.toMatch(/DOUBLE_SUCCESS_PCT/);
    expect(ESTIMATOR_SRC).not.toMatch(/0\.6\b/); // 60% threshold
    expect(ESTIMATOR_SRC).not.toMatch(/0\.95\b/); // 95% threshold (estimator side)
  });

  it("BUG-11: no FeeReason enum (Core has HALF/FULL/DOUBLE/CONSERVATIVE/FALLBACK/REQUIRED/MEMPOOL_MIN)", () => {
    expect(ESTIMATOR_SRC).not.toMatch(/FeeReason/);
    expect(ESTIMATOR_SRC).not.toMatch(/HALF_ESTIMATE/);
    expect(ESTIMATOR_SRC).not.toMatch(/FULL_ESTIMATE/);
    expect(ESTIMATOR_SRC).not.toMatch(/DOUBLE_ESTIMATE/);
  });

  it("BUG-11: no SUFFICIENT_FEETXS / SUFFICIENT_TXS_SHORT constants", () => {
    expect(ESTIMATOR_SRC).not.toMatch(/SUFFICIENT_FEETXS/);
    expect(ESTIMATOR_SRC).not.toMatch(/SUFFICIENT_TXS_SHORT/);
  });
});

// =============================================================================
// G15 — mempoolminfee / min_relay_feerate floor on smartfee (BUG-12, P1-API)
// =============================================================================

describe("W139-G15: smartfee mempoolminfee floor (BUG-12, P1-API)", () => {
  it("BUG-12: estimatesmartfee RPC does NOT floor by mempool.getMinFee()", () => {
    // server.ts:4034-4056 — no call to mempool.getMinFee() or
    // min_relay_feerate before returning.
    const m = RPC_SERVER_SRC.match(
      /estimatesmartfee:[\s\S]*?private\s+async\s+estimateSmartFee[\s\S]*?\n\s\s\}/
    );
    expect(m).not.toBeNull();
    if (m) {
      const body = m[0];
      expect(body).not.toMatch(/getMinFee\(\)/);
      expect(body).not.toMatch(/min_relay_feerate/);
      expect(body).not.toMatch(/minRelayFee/);
    }
  });
});

// =============================================================================
// G16 — desiredTarget vs returnedTarget distinction (BUG-13, P1-WIRE)
// =============================================================================

describe("W139-G16: desiredTarget vs returnedTarget (BUG-13, P1-WIRE)", () => {
  it("BUG-13: no FeeCalculation struct with desiredTarget / returnedTarget / best_height", () => {
    expect(ESTIMATOR_SRC).not.toMatch(/desiredTarget/);
    expect(ESTIMATOR_SRC).not.toMatch(/returnedTarget/);
    expect(ESTIMATOR_SRC).not.toMatch(/FeeCalculation\b/);
    expect(ESTIMATOR_SRC).not.toMatch(/best_height\b/);
  });

  it("BUG-13: estimateSmartFee returns only {feeRate, blocks} — no record of original target", () => {
    const m = ESTIMATOR_SRC.match(
      /estimateSmartFee\(targetBlocks:\s*number\)[\s\S]*?\n\s\s\}/
    );
    expect(m).not.toBeNull();
    if (m) {
      // Returns either {feeRate, blocks: targetBlocks} or
      // {feeRate, blocks: target}; the consumer can't tell which.
      expect(m[0]).toMatch(/blocks:\s*targetBlocks/);
      expect(m[0]).toMatch(/blocks:\s*target/);
    }
  });
});

// =============================================================================
// G17 — estimaterawfee per-horizon JSON shape
// =============================================================================

describe("W139-G17: estimaterawfee per-horizon JSON shape", () => {
  it("PRESENT: response shape is {short, medium, long}", () => {
    expect(RPC_SERVER_SRC).toMatch(
      /short:\s*computeHorizonResult\(Horizon\.Short\)/
    );
    expect(RPC_SERVER_SRC).toMatch(
      /medium:\s*computeHorizonResult\(Horizon\.Medium\)/
    );
    expect(RPC_SERVER_SRC).toMatch(
      /long:\s*computeHorizonResult\(Horizon\.Long\)/
    );
  });

  it("PRESENT: each horizon result includes {decay, scale} unconditionally", () => {
    // server.ts:4167-4170 — `decay: hStats.decay, scale: hStats.scale` set
    // before the pass/fail/errors branch.
    expect(RPC_SERVER_SRC).toMatch(/decay:\s*hStats\.decay/);
    expect(RPC_SERVER_SRC).toMatch(/scale:\s*hStats\.scale/);
  });
});

// =============================================================================
// G18 — FlushUnconfirmed on shutdown (BUG-14, P1-API)
// =============================================================================

describe("W139-G18: FlushUnconfirmed on shutdown (BUG-14, P1-API)", () => {
  it("BUG-14: no FlushUnconfirmed / removeTx-as-fail-on-shutdown helper", () => {
    expect(ESTIMATOR_SRC).not.toMatch(/FlushUnconfirmed/);
    expect(ESTIMATOR_SRC).not.toMatch(/flushUnconfirmed/);
    // No method that iterates txEntryHeights and bumps failure counters.
    // (removeTx would be the analog; absent here.)
    expect(ESTIMATOR_SRC).not.toMatch(/removeTx\(/);
  });
});

// =============================================================================
// G19 — FEE_FLUSH_INTERVAL = 1 hour scheduled flush (BUG-15, P1-API)
// =============================================================================

describe("W139-G19: FEE_FLUSH_INTERVAL scheduler (BUG-15, P1-API)", () => {
  it("BUG-15: no FEE_FLUSH_INTERVAL constant or scheduleEvery wiring", () => {
    expect(ESTIMATOR_SRC).not.toMatch(/FEE_FLUSH_INTERVAL/);
    expect(ESTIMATOR_SRC).not.toMatch(/scheduleEvery/);
    expect(ESTIMATOR_SRC).not.toMatch(/setInterval[\s\S]*?serialize/);
  });

  it("BUG-15: feeEstimator.serialize only runs on shutdown, not on a timer", () => {
    // cli.ts DOES call feeEstimator.serialize() ONCE at shutdown
    // (cli.ts:2275), but never on a recurring setInterval / setTimeout /
    // scheduleEvery loop. Crash-loss window = uptime since last
    // graceful shutdown.
    const cli = readSrc("cli/cli.ts");
    // The shutdown-time call exists:
    expect(cli).toMatch(/runningNode\.feeEstimator\.serialize\(\)/);
    // But no setInterval / setTimeout that periodically saves.
    // Search for any timer-driven save: must NOT find a setInterval whose
    // body references feeEstimator.serialize.
    const setIntervalSerializes = cli.match(
      /setInterval\([\s\S]{0,500}?feeEstimator\.serialize/
    );
    expect(setIntervalSerializes).toBeNull();
    // Search for scheduleEvery-like helpers too.
    expect(cli).not.toMatch(/scheduleEvery[\s\S]{0,200}?feeEstimator/);
  });
});

// =============================================================================
// G20 — MAX_FILE_AGE = 60 hours + accept-stale flag (BUG-16, P1-API)
// =============================================================================

describe("W139-G20: MAX_FILE_AGE staleness check (BUG-16, P1-API)", () => {
  it("BUG-16: no MAX_FILE_AGE / file-age check on loadState", () => {
    expect(ESTIMATOR_SRC).not.toMatch(/MAX_FILE_AGE/);
    expect(ESTIMATOR_SRC).not.toMatch(/DEFAULT_ACCEPT_STALE_FEE_ESTIMATES/);
    expect(ESTIMATOR_SRC).not.toMatch(/GetFeeEstimatorFileAge/);
    expect(ESTIMATOR_SRC).not.toMatch(/file_age/);
    expect(ESTIMATOR_SRC).not.toMatch(/lastWriteTime/);
  });

  it("BUG-16: loadState unconditionally accepts any caller-supplied bytes", () => {
    const m = ESTIMATOR_SRC.match(
      /loadState\(data:\s*Buffer\)\s*:\s*void\s*\{([\s\S]*?)\n\s\s\}/
    );
    expect(m).not.toBeNull();
    if (m) {
      expect(m[1]).not.toMatch(/age/i);
      expect(m[1]).not.toMatch(/stale/i);
    }
  });
});

// =============================================================================
// G21 — validForFeeEstimation filter (BUG-17, P1-API)
// =============================================================================

describe("W139-G21: validForFeeEstimation filter (BUG-17, P1-API)", () => {
  it("BUG-17: trackTransaction has no validForFeeEstimation gate", () => {
    // Core: skip if mempool_limit_bypassed || submitted_in_package ||
    // !chainstate_is_current || !has_no_mempool_parents.
    const m = ESTIMATOR_SRC.match(
      /trackTransaction\(txid:\s*Buffer,\s*height:\s*number\)\s*:\s*void\s*\{([\s\S]*?)\n\s\s\}/
    );
    expect(m).not.toBeNull();
    if (m) {
      expect(m[1]).not.toMatch(/validForFeeEstimation/);
      expect(m[1]).not.toMatch(/m_mempool_limit_bypassed/);
      expect(m[1]).not.toMatch(/m_submitted_in_package/);
      expect(m[1]).not.toMatch(/m_chainstate_is_current/);
      expect(m[1]).not.toMatch(/m_has_no_mempool_parents/);
      // No CPFP / parent-aware gating.
      expect(m[1]).not.toMatch(/dependsOn/);
      expect(m[1]).not.toMatch(/parents/);
    }
  });

  it("BUG-17: no trackedTxs / untrackedTxs counters (used by Core's logger + RPC)", () => {
    expect(ESTIMATOR_SRC).not.toMatch(/trackedTxs/);
    expect(ESTIMATOR_SRC).not.toMatch(/untrackedTxs/);
  });
});

// =============================================================================
// G22 — estimaterawfee inmempool semantics (BUG-18, P1-WIRE)
// =============================================================================

describe("W139-G22: estimaterawfee inmempool semantics (BUG-18, P1-WIRE)", () => {
  it("BUG-18: inmempool emits total unconfirmed (Core emits aged-at-least-confTarget)", () => {
    // server.ts:4152 — `inmempool: Math.round(hb.unconfirmed * 100) / 100,`
    // Core: extraNum = sum(unconfTxs[(h-confct) % bins][bucket]
    //                       for confct in [confTarget, maxConfirms))
    //                + oldUnconfTxs[bucket]
    // i.e., only txs aged >= confTarget. Hotbuns has no per-block-age info
    // (BUG-4), so the best it can do is the aggregate.
    expect(RPC_SERVER_SRC).toMatch(/inmempool:\s*Math\.round\(hb\.unconfirmed/);
    // Confirm there's no aged-walk loop in computeHorizonResult.
    const m = RPC_SERVER_SRC.match(
      /const\s+computeHorizonResult\s*=[\s\S]*?\n\s\s\s\s\};\s*$/m
    );
    if (m) {
      expect(m[0]).not.toMatch(/for\s*\(\s*let\s+confct/);
    }
  });
});

// =============================================================================
// G23 — ParseConfirmTarget throws on out-of-range (BUG-19, P0-CDIV)
// =============================================================================

describe("W139-G23: out-of-range conf_target silently clamps (BUG-19, P0-CDIV)", () => {
  it("BUG-19: estimatesmartfee Math.max/Math.min clamps instead of throwing", () => {
    // Core: throws RPC_INVALID_PARAMETER "Invalid conf_target, must be
    // between 1 and N". Hotbuns silently clamps.
    expect(RPC_SERVER_SRC).toMatch(
      /const\s+confTarget\s*=\s*Math\.max\(\s*1,\s*Math\.min\(\s*1008,\s*confTargetParam\s*\)\s*\)/
    );
  });

  it("BUG-19: estimaterawfee same silent-clamp pattern", () => {
    // server.ts:4081 — second occurrence in estimateRawFee body.
    const matches = RPC_SERVER_SRC.match(
      /Math\.max\(\s*1,\s*Math\.min\(\s*1008,\s*confTargetParam\s*\)\s*\)/g
    );
    expect(matches).not.toBeNull();
    if (matches) {
      expect(matches.length).toBeGreaterThanOrEqual(2);
    }
  });

  it("BUG-19: no Invalid-conf_target error path", () => {
    expect(RPC_SERVER_SRC).not.toMatch(/Invalid conf_target/);
    expect(RPC_SERVER_SRC).not.toMatch(/ParseConfirmTarget/);
  });
});

// =============================================================================
// G24 — FeeFilterRounder privacy quantization (BUG-20, P1-API)
// =============================================================================

describe("W139-G24: FeeFilterRounder privacy quantization (BUG-20, P1-API)", () => {
  it("BUG-20: no FeeFilterRounder / MAX_FILTER_FEERATE / FEE_FILTER_SPACING constants", () => {
    expect(FEEFILTER_SRC).not.toMatch(/FeeFilterRounder/);
    expect(FEEFILTER_SRC).not.toMatch(/MAX_FILTER_FEERATE/);
    expect(FEEFILTER_SRC).not.toMatch(/FEE_FILTER_SPACING/);
    // No m_fee_set / quantized rounding helper.
    expect(FEEFILTER_SRC).not.toMatch(/m_fee_set/);
  });

  it("BUG-20: setMinFeeRate / getFeeRateToAnnounce send raw values", () => {
    // p2p/feefilter.ts:82-98 — passes currentFeeRate without quantization.
    expect(FEEFILTER_SRC).toMatch(
      /setMinFeeRate\(feeRate:\s*bigint\)\s*:\s*void\s*\{/
    );
    // Raw assignment (with only a DEFAULT_MIN floor).
    expect(FEEFILTER_SRC).toMatch(
      /this\.currentFeeRate\s*=\s*feeRate\s*>\s*DEFAULT_MIN_RELAY_FEE_RATE/
    );
  });
});

// =============================================================================
// G25 — CURRENT_FEES_FILE_VERSION = 309900 constant (BUG-21, P1-WIRE)
// =============================================================================

describe("W139-G25: CURRENT_FEES_FILE_VERSION constant (BUG-21, P1-WIRE)", () => {
  it("BUG-21: no version constant in the serialized blob", () => {
    expect(ESTIMATOR_SRC).not.toMatch(/CURRENT_FEES_FILE_VERSION/);
    expect(ESTIMATOR_SRC).not.toMatch(/309900/);
    expect(ESTIMATOR_SRC).not.toMatch(/version/i);
    // The SerializedEstimatorState interface has no version field.
    const m = ESTIMATOR_SRC.match(
      /interface\s+SerializedEstimatorState\s*\{([\s\S]*?)\n\}/
    );
    if (m) {
      expect(m[1]).not.toMatch(/version/);
    }
  });
});

// =============================================================================
// G26 — fee_estimates.dat binary format (BUG-22, P1-WIRE)
// =============================================================================

describe("W139-G26: fee_estimates.dat binary format (BUG-22, P1-WIRE)", () => {
  it("BUG-22: serialize emits JSON.stringify(state), not binary AutoFile shape", () => {
    expect(ESTIMATOR_SRC).toMatch(/Buffer\.from\(JSON\.stringify\(state\)\)/);
    // No EncodedDoubleFormatter / no manual little-endian writes for
    // doubles or counts.
    expect(ESTIMATOR_SRC).not.toMatch(/EncodedDoubleFormatter/);
    expect(ESTIMATOR_SRC).not.toMatch(/writeDoubleLE/);
  });

  it("BUG-22: loadState parses JSON, not binary", () => {
    expect(ESTIMATOR_SRC).toMatch(/JSON\.parse\(data\.toString\(\)\)/);
  });

  it("BUG-22: no path-managed fee_estimates.dat (filename absent)", () => {
    // Core: fee_estimates.dat path managed via FeeestPath(argsman).
    expect(ESTIMATOR_SRC).not.toMatch(/fee_estimates\.dat/);
  });
});

// =============================================================================
// G27 — errors / fail shape (BUG-23, P1-WIRE)
// =============================================================================

describe("W139-G27: errors / fail shape (BUG-23, P1-WIRE)", () => {
  it("BUG-23: top-bucket endrange emits -1 sentinel when feeRateRange.max=Infinity", () => {
    // server.ts:4147-4149 — `endrange: Number.isFinite(...) ? max : -1,`
    // Core stores buckets[N+1]=1e99 INF_FEERATE so it emits a numeric value.
    expect(RPC_SERVER_SRC).toMatch(
      /endrange:\s*Number\.isFinite\(sharedBucket\.feeRateRange\.max\)\s*\?\s*sharedBucket\.feeRateRange\.max\s*:\s*-1/
    );
  });

  it("BUG-23: hotbuns BUCKET_BOUNDARIES has no INF_FEERATE 1e99 final sentinel", () => {
    // Core appends INF_FEERATE = 1e99. Hotbuns just uses Infinity for the top
    // open-ended bucket and converts to -1 at the RPC boundary.
    expect(ESTIMATOR_SRC).toMatch(/Infinity/); // top open bucket via max=Infinity
    expect(ESTIMATOR_SRC).not.toMatch(/1e99/);
    expect(ESTIMATOR_SRC).not.toMatch(/INF_FEERATE/);
  });

  it("PRESENT: when pass is null, errors message matches Core wording", () => {
    expect(RPC_SERVER_SRC).toMatch(
      /Insufficient data or no feerate found which meets threshold/
    );
  });
});

// =============================================================================
// G28 — Stale txEntryHeights cleanup
// =============================================================================

describe("W139-G28: stale txEntryHeights cleanup", () => {
  it("PRESENT: processBlock removes entries older than MAX_CONFIRMATION_BLOCKS*2", () => {
    expect(ESTIMATOR_SRC).toMatch(
      /const\s+maxAge\s*=\s*MAX_CONFIRMATION_BLOCKS\s*\*\s*2/
    );
    expect(ESTIMATOR_SRC).toMatch(
      /this\.txEntryHeights\.delete\(txidHex\)/
    );
  });

  it("PRESENT: MAX_CONFIRMATION_BLOCKS matches Core's long-horizon coverage (1008)", () => {
    expect(ESTIMATOR_SRC).toMatch(/MAX_CONFIRMATION_BLOCKS\s*=\s*1008/);
  });
});

// =============================================================================
// G29 — estimaterawfee withintarget rounding (note, subsumed under BUG-5)
// =============================================================================

describe("W139-G29: estimaterawfee withintarget rounding (note, subsumed)", () => {
  it("NOTE (BUG-5 surface): withintarget is rounded as if a float but is always an integer", () => {
    // server.ts:4150 — `withintarget: Math.round(within * 100) / 100`
    // where `within = filter().length`, an integer. Rounding *100/100
    // is a no-op on integers. Core's value IS a decay-accumulated float
    // (nConf in EstimateMedianVal). This is the surface of BUG-5
    // (no confAvg[Y][X] decay-accumulated counter).
    expect(RPC_SERVER_SRC).toMatch(
      /withintarget:\s*Math\.round\(within\s*\*\s*100\)\s*\/\s*100/
    );
    expect(RPC_SERVER_SRC).toMatch(
      /const\s+within\s*=\s*hb\.confirmationBlocks\.filter/
    );
  });
});

// =============================================================================
// G30 — recordConfirmation accepts untracked (note, subsumed under BUG-17)
// =============================================================================

describe("W139-G30: recordConfirmation untracked-tx behavior (note, subsumed)", () => {
  it("NOTE (BUG-17 surface): recordConfirmation does NOT gate on txEntryHeights presence", () => {
    // Core's processBlockTx short-circuits if !_removeTx(... inBlock=true).
    // Hotbuns's recordConfirmation increments unconditionally.
    const m = ESTIMATOR_SRC.match(
      /recordConfirmation\([\s\S]*?\)\s*:\s*void\s*\{([\s\S]*?)\n\s\s\}/
    );
    expect(m).not.toBeNull();
    if (m) {
      // The first guard checks blocksWaited bounds, not txEntryHeights presence.
      expect(m[1]).toMatch(/blocksWaited\s*<\s*0\s*\|\|\s*blocksWaited\s*>\s*MAX_CONFIRMATION_BLOCKS/);
      // No early-return on missing txEntryHeights entry.
      expect(m[1]).not.toMatch(/this\.txEntryHeights\.has/);
    }
  });

  it("PRESENT: the safe caller path is processBlock — which DOES guard", () => {
    // estimator.ts:341-344 — `if (entryHeight === undefined) continue;`
    expect(ESTIMATOR_SRC).toMatch(
      /if\s*\(\s*entryHeight\s*===\s*undefined\s*\)\s*\{[\s\S]{0,40}?continue/
    );
  });
});
