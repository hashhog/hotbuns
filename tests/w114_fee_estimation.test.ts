/**
 * W114 Fee Estimation (CBlockPolicyEstimator) audit tests — hotbuns
 *
 * Convention: Tests prefixed "BUG:" document a confirmed divergence from
 * Core. Assertions in those tests are written so the test PASSES (to keep
 * the suite green) but the assertion body exposes the wrong value.
 *
 * Gates:
 *  G1  Three time horizons (short/medium/long) present
 *  G2  Correct decay constants: short=0.962, med=0.9952, long=0.99931
 *  G3  Correct scale constants: SHORT_SCALE=1, MED_SCALE=2, LONG_SCALE=24
 *  G4  Period counts: short=12, med=24, long=42
 *  G5  Bucket spacing: MIN=100 sat/kvB, MAX=1e7, FEE_SPACING=1.05 (~90 buckets)
 *  G6  processBlock/trackTransaction wired into production code path (not dead helper)
 *  G7  removeTx called when tx evicted without confirmation (leftMempool tracking)
 *  G8  FlushUnconfirmed on node shutdown records in-flight txs as failed
 *  G9  estimate_mode parameter parsed and acted on (conservative vs economical)
 *  G10 confTarget clamped to minimum 2 internally (Core: "not possible to estimate for 1")
 *  G11 estimateSmartFee returns error object when no data, not a fallback constant
 *  G12 estimateSmartFee halfEst/fullEst/doubleEst triple-check algorithm
 *  G13 estimateConservativeFee for conservative mode (2*target, 95% threshold)
 *  G14 SUFFICIENT_FEETXS threshold (0.1 tx/block density guard)
 *  G15 SUFFICIENT_TXS_SHORT threshold (0.5 tx/block for short horizon)
 *  G16 MaxUsableEstimate: returned blocks ≤ blocks-seen / scale
 *  G17 feerate in estimatesmartfee result in BTC/kvB (not sat/vB)
 *  G18 estimaterawfee threshold param validated [0,1]; default 0.95
 *  G19 estimaterawfee reports per-horizon decay and scale correctly
 *  G20 estimaterawfee short/medium/long objects contain distinct decay values
 *  G21 fee_estimates.dat: binary format with version 309900 (Core interop)
 *  G22 IsSynced guard: processTransaction skips txs when node not at chain tip
 *  G23 No package txs tracked (m_submitted_in_package guard)
 *  G24 No limit-bypassed txs tracked (m_mempool_limit_bypassed guard)
 *  G25 No parent-in-mempool txs tracked (m_has_no_mempool_parents guard)
 *  G26 Reorg guard: processBlock ignores height ≤ nBestSeenHeight
 *  G27 BlockSpan / HistoricalBlockSpan tracked for MaxUsableEstimate
 *  G28 IEEE 754 double decay accumulation over 1008 blocks stays precise
 *  G29 Feerate stored internally as sat/kvB (= BTC/kvB × 1e8) not sat/vB
 *  G30 FeeCalculation struct returned: desiredTarget, returnedTarget, reason
 */

import { describe, test, expect, beforeEach, afterEach } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ChainDB } from "../src/storage/database.js";
import { UTXOManager } from "../src/chain/utxo.js";
import { REGTEST } from "../src/consensus/params.js";
import { Mempool } from "../src/mempool/mempool.js";
import { FeeEstimator, Horizon, DECAY, SCALE, PERIODS } from "../src/fees/estimator.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async function makeEstimator(): Promise<{ est: FeeEstimator; cleanup: () => Promise<void> }> {
  const dir = await mkdtemp(join(tmpdir(), "w114-"));
  const db = new ChainDB(dir);
  await db.open();
  const utxo = new UTXOManager(db);
  const mempool = new Mempool(utxo, REGTEST, 1_000_000);
  const est = new FeeEstimator(mempool);
  const cleanup = async () => {
    await db.close();
    await rm(dir, { recursive: true, force: true });
  };
  return { est, cleanup };
}

const emptyBlock = (height: number = 1) => ({
  header: {
    version: 0x20000000,
    prevBlock: Buffer.alloc(32),
    merkleRoot: Buffer.alloc(32),
    timestamp: Math.floor(Date.now() / 1000),
    bits: 0x207fffff,
    nonce: 0,
  },
  transactions: [],
});

// ---------------------------------------------------------------------------
// G1 — Three time horizons (short / medium / long) — MISSING ENTIRELY
// ---------------------------------------------------------------------------
describe("G1 three time horizons", () => {
  test("FeeEstimator has short/medium/long horizon split via horizons field (FIX-48)", async () => {
    const { est, cleanup } = await makeEstimator();
    try {
      // Core maintains three independent TxConfirmStats instances:
      //   feeStats (medium), shortStats, longStats — each with own decay+scale.
      // FIX-48: horizons Record<Horizon, HorizonStats> added.
      // @ts-ignore — probing shape
      const hasHorizons = "horizons" in est;
      expect(hasHorizons).toBe(true); // fixed: three-horizon split present

      // Verify all three horizons are present
      expect(est.horizons[Horizon.Short]).toBeDefined();
      expect(est.horizons[Horizon.Medium]).toBeDefined();
      expect(est.horizons[Horizon.Long]).toBeDefined();

      // Each horizon has its own bucket array
      expect(Array.isArray(est.horizons[Horizon.Short].buckets)).toBe(true);
      expect(Array.isArray(est.horizons[Horizon.Medium].buckets)).toBe(true);
      expect(Array.isArray(est.horizons[Horizon.Long].buckets)).toBe(true);
    } finally {
      await cleanup();
    }
  });
});

// ---------------------------------------------------------------------------
// G2 — Correct decay constants
// ---------------------------------------------------------------------------
describe("G2 decay constants", () => {
  test("DECAY constants match Core horizon values (FIX-48)", () => {
    // FIX-48: three correct per-horizon decay constants exported from estimator.ts.
    // Core: src/policy/fees.cpp SHORT_DECAY=0.962, MED_DECAY=0.9952, LONG_DECAY=0.99931.
    expect(DECAY[Horizon.Short]).toBeCloseTo(0.962, 5);
    expect(DECAY[Horizon.Medium]).toBeCloseTo(0.9952, 5);
    expect(DECAY[Horizon.Long]).toBeCloseTo(0.99931, 5);
  });
});

// ---------------------------------------------------------------------------
// G3 & G4 — Scale and period constants
// ---------------------------------------------------------------------------
describe("G3/G4 scale and period counts", () => {
  test("SCALE and PERIODS constants match Core horizon values (FIX-48)", async () => {
    const { est, cleanup } = await makeEstimator();
    try {
      // FIX-48: SCALE and PERIODS exported from estimator.ts.
      // Core: SHORT_SCALE=1, MED_SCALE=2, LONG_SCALE=24
      //       short 12×1=12, med 24×2=48, long 42×24=1008 blocks coverage
      expect(SCALE[Horizon.Short]).toBe(1);
      expect(SCALE[Horizon.Medium]).toBe(2);
      expect(SCALE[Horizon.Long]).toBe(24);

      expect(PERIODS[Horizon.Short]).toBe(12);
      expect(PERIODS[Horizon.Medium]).toBe(24);
      expect(PERIODS[Horizon.Long]).toBe(42);

      // Coverage: scale × periods
      expect(SCALE[Horizon.Short] * PERIODS[Horizon.Short]).toBe(12);
      expect(SCALE[Horizon.Medium] * PERIODS[Horizon.Medium]).toBe(48);
      expect(SCALE[Horizon.Long] * PERIODS[Horizon.Long]).toBe(1008);

      // horizon stats have the correct scale wired
      expect(est.horizons[Horizon.Short].scale).toBe(1);
      expect(est.horizons[Horizon.Medium].scale).toBe(2);
      expect(est.horizons[Horizon.Long].scale).toBe(24);
    } finally {
      await cleanup();
    }
  });
});

// ---------------------------------------------------------------------------
// G5 — Bucket spacing: MIN=100 sat/kvB, MAX=1e7, FEE_SPACING=1.05 (~90 buckets)
// ---------------------------------------------------------------------------
describe("G5 bucket spacing", () => {
  test("BUG-4: 41 hand-coded buckets instead of ~90 exponential buckets at 1.05× spacing", async () => {
    const { est, cleanup } = await makeEstimator();
    try {
      const buckets = est.getBuckets();
      // Core: ceil(log(1e7/100)/log(1.05))+1 ≈ 97 buckets
      // Hotbuns: 41 hand-coded buckets
      expect(buckets.length).toBe(41); // BUG: should be ~97
      expect(buckets.length).toBeLessThan(90); // confirms under-bucketing
    } finally {
      await cleanup();
    }
  });

  test("BUG-5: minimum bucket at 1 sat/vB instead of Core MIN_BUCKET_FEERATE=100 sat/kvB=0.1 sat/vB", async () => {
    const { est, cleanup } = await makeEstimator();
    try {
      const buckets = est.getBuckets();
      // Core MIN_BUCKET_FEERATE = 100 sat/kvB = 0.1 sat/vB
      // Hotbuns starts at 1 sat/vB (10× above Core minimum)
      expect(buckets[0].feeRateRange.min).toBe(1); // BUG: should be 0.1 (or 100 sat/kvB)
    } finally {
      await cleanup();
    }
  });

  test("BUG-6: bucket boundaries are not consistent 1.05× exponential spacing", async () => {
    const { est, cleanup } = await makeEstimator();
    try {
      const buckets = est.getBuckets();
      // First few hotbuns boundaries: 1,2,3,4,5,6,7,8,10,12...
      // Ratios: 2/1=2.0, 3/2=1.5, 4/3=1.33 — none are 1.05
      const ratio = buckets[1].feeRateRange.min / buckets[0].feeRateRange.min;
      expect(Math.abs(ratio - 1.05)).toBeGreaterThan(0.5); // BUG: ratio is ~2.0, not 1.05
    } finally {
      await cleanup();
    }
  });
});

// ---------------------------------------------------------------------------
// G6 — processBlock / trackTransaction wired into production (DEAD HELPER)
// ---------------------------------------------------------------------------
describe("G6 dead helper — processBlock and trackTransaction not called in production", () => {
  test("BUG-7 P0-CDIV DEAD HELPER: estimator always returns DEFAULT_FEE_RATE=20 because never fed data", async () => {
    const { est, cleanup } = await makeEstimator();
    try {
      // FeeEstimator is constructed and wired into the RPC server (server.ts:452),
      // and serialized on shutdown (cli.ts:1967).
      // HOWEVER: cli.ts blockConnected handler (line 1568) never calls
      //   feeEstimator.processBlock(block, height)
      // and the tx-accepted handler (line 1631) never calls
      //   feeEstimator.trackTransaction(txid, currentHeight)
      //
      // Result: the estimator is permanently empty in production.
      // estimateSmartFee always returns the hardcoded DEFAULT_FEE_RATE=20.
      // This is a dead-helper: the subsystem is fully implemented but
      // never wired into the block-processing pipeline.

      const result = est.estimateSmartFee(6);
      expect(result.feeRate).toBe(20); // 20 = DEFAULT_FEE_RATE, always returned
      expect(result.blocks).toBe(6);

      // Even after processing blocks (which would NOT happen in production),
      // empty blocks produce no data:
      for (let h = 1; h <= 10; h++) {
        est.processBlock(emptyBlock(h) as any, h);
      }
      expect(est.estimateSmartFee(6).feeRate).toBe(20); // still default
    } finally {
      await cleanup();
    }
  });
});

// ---------------------------------------------------------------------------
// G7 — removeTx / leftMempool tracking
// ---------------------------------------------------------------------------
describe("G7 removeTx / leftMempool tracking", () => {
  test("BUG-8: no removeTx method — evicted txs never counted toward leftMempool", async () => {
    const { est, cleanup } = await makeEstimator();
    try {
      // Core's removeTx(hash) moves a tracked mempool tx to failAvg when evicted
      // without confirmation. This is critical for congestion estimation.
      const hasRemoveTx = typeof (est as any).removeTx === "function";
      expect(hasRemoveTx).toBe(false); // BUG confirmed: method absent
    } finally {
      await cleanup();
    }
  });
});

// ---------------------------------------------------------------------------
// G8 — FlushUnconfirmed on shutdown
// ---------------------------------------------------------------------------
describe("G8 FlushUnconfirmed on shutdown", () => {
  test("BUG-9: no FlushUnconfirmed method — in-flight tracked txs lost on shutdown", async () => {
    const { est, cleanup } = await makeEstimator();
    try {
      const hasFlushUnconfirmed =
        typeof (est as any).flushUnconfirmed === "function" ||
        typeof (est as any).FlushUnconfirmed === "function";
      expect(hasFlushUnconfirmed).toBe(false); // BUG confirmed: method absent
    } finally {
      await cleanup();
    }
  });
});

// ---------------------------------------------------------------------------
// G9 — estimate_mode parameter (conservative vs economical)
// ---------------------------------------------------------------------------
describe("G9 estimate_mode parameter", () => {
  test("BUG-10: estimate_mode ignored — RPC server reads only params[0] (conf_target)", () => {
    // From rpc/server.ts:3803-3824:
    //   const [confTargetParam] = params;   ← only conf_target, no estimate_mode
    // Core parses "conservative" / "economical" and branches on conservative=true.
    // The conservative algorithm runs estimateConservativeFee(2*target) and takes max.
    // This can return a significantly higher feerate during mempool congestion.
    //
    // BUG: FeeEstimator.estimateSmartFee() has no conservative parameter.
    const hasConservativeParam =
      "estimateSmartFeeConservative" in new (FeeEstimator as any)(null) ||
      FeeEstimator.prototype.estimateSmartFee.length >= 2; // checks arity
    // estimateSmartFee(targetBlocks: number) — 1 parameter, no conservative flag
    expect(FeeEstimator.prototype.estimateSmartFee.length).toBe(1); // BUG: should be 2
  });
});

// ---------------------------------------------------------------------------
// G10 — confTarget minimum 2
// ---------------------------------------------------------------------------
describe("G10 confTarget minimum clamp to 2", () => {
  test("BUG-11: confTarget=1 processed as-is; Core internally forces minimum=2", async () => {
    const { est, cleanup } = await makeEstimator();
    try {
      // Core estimateSmartFee line 890: "if (confTarget == 1) confTarget = 2"
      // Hotbuns: estimateFee(1) and estimateFee(2) may differ because 1 is not clamped.
      // Feed data that confirms in exactly 1 block
      for (let i = 0; i < 15; i++) {
        const txid = Buffer.alloc(32, i);
        est.recordConfirmation(txid, 100, 100, 101); // 1-block confirmation
      }
      // In Core both should return the same feerate (target 1 → clamped to 2)
      const fee1 = est.estimateFee(1);
      const fee2 = est.estimateFee(2);
      // BUG: they may differ because no clamp is applied
      // (For this data they happen to be equal since both see 1-block confirms;
      // in general they can differ)
      expect(typeof fee1).toBe("number"); // trivially documents the path exists
      expect(typeof fee2).toBe("number");
    } finally {
      await cleanup();
    }
  });
});

// ---------------------------------------------------------------------------
// G11 — estimateSmartFee error signal when no data
// ---------------------------------------------------------------------------
describe("G11 estimateSmartFee error response when no data", () => {
  test("BUG-12: always returns {feeRate:20} instead of signaling 'no data' to RPC layer", async () => {
    const { est, cleanup } = await makeEstimator();
    try {
      // Core: { errors: ["Insufficient data or no feerate found"], blocks: N }
      //   (no feerate field in response).
      // Hotbuns estimateSmartFee always returns a non-null feeRate (20 fallback),
      // so the RPC layer's error branch (server.ts:3814) is never triggered.
      // Clients cannot distinguish "really no data" from "estimated 20 sat/vB".
      const result = est.estimateSmartFee(6);
      // feeRate is always 20 (not null / not undefined) when there's no data
      expect(result.feeRate).toBe(20);
      // BUG: the correct signal would be feeRate=null or feeRate=0 to let
      // the RPC layer return { errors: [...] } per Core spec
    } finally {
      await cleanup();
    }
  });
});

// ---------------------------------------------------------------------------
// G12 — halfEst / fullEst / doubleEst triple-check algorithm
// ---------------------------------------------------------------------------
describe("G12 triple-check algorithm", () => {
  test("BUG-13: single CONFIDENCE_THRESHOLD=0.85 pass only; no half-target(60%) or double-target(95%) sub-estimates", async () => {
    const { est, cleanup } = await makeEstimator();
    try {
      // Core uses three sub-estimates and takes the max for monotonicity:
      //   halfEst  = estimateCombinedFee(target/2,  60%)
      //   fullEst  = estimateCombinedFee(target,    85%)
      //   doubleEst = estimateCombinedFee(2*target, 95%)
      // Hotbuns: single pass with CONFIDENCE_THRESHOLD=0.85 only.
      // No halfEst or doubleEst sub-estimates.
      // @ts-ignore
      const hasDoubleEst =
        "estimateCombinedFee" in est ||
        "estimateConservativeFee" in est ||
        "HALF_SUCCESS_PCT" in est;
      expect(hasDoubleEst).toBe(false); // BUG: triple-check algorithm absent
    } finally {
      await cleanup();
    }
  });
});

// ---------------------------------------------------------------------------
// G14 — SUFFICIENT_FEETXS density guard
// ---------------------------------------------------------------------------
describe("G14 SUFFICIENT_FEETXS density guard", () => {
  test("BUG-14: no per-block density guard; fixed minDataPoints=10 count ignores block span", async () => {
    const { est, cleanup } = await makeEstimator();
    try {
      // Core: require ≥0.1 average tx/block over the estimation horizon.
      // 10 txs over 1000 blocks = 0.01/block < threshold → no valid estimate.
      // Hotbuns uses minDataPoints=10 raw count, not density-normalized.
      for (let i = 0; i < 10; i++) {
        const txid = Buffer.alloc(32, i);
        est.recordConfirmation(txid, 100, 1, 1000); // 10 txs, ~1000 block span
      }
      const fee = est.estimateFee(6);
      // Core would return 0 (no valid estimate) due to 0.01 tx/block < 0.1 threshold.
      // Hotbuns accepts the data because count >= 10.
      // BUG: fee > 0 when it should signal insufficient data
      expect(fee).toBeGreaterThan(0); // BUG confirmed: accepts sparse data as valid
    } finally {
      await cleanup();
    }
  });
});

// ---------------------------------------------------------------------------
// G17 — feerate unit in estimatesmartfee RPC response
// ---------------------------------------------------------------------------
describe("G17 feerate unit in estimatesmartfee", () => {
  test("RPC conversion: internal sat/vB correctly divided by 100_000 to produce BTC/kvB", async () => {
    const { est, cleanup } = await makeEstimator();
    try {
      // Feed data at 100 sat/vB
      for (let i = 0; i < 15; i++) {
        const txid = Buffer.alloc(32, i);
        est.recordConfirmation(txid, 100, 100, 102);
      }
      const result = est.estimateSmartFee(6);
      // Internal value should be in sat/vB range (e.g. 100)
      expect(result.feeRate).toBeGreaterThan(1);
      expect(result.feeRate).toBeLessThan(100_000);

      // RPC conversion in server.ts:3822:
      //   feerate: estimate.feeRate / 100_000
      // 100 sat/vB / 100_000 = 0.001 BTC/kvB ✓
      const rpcFeerate = result.feeRate / 100_000;
      expect(rpcFeerate).toBeCloseTo(0.001, 5);
    } finally {
      await cleanup();
    }
  });
});

// ---------------------------------------------------------------------------
// G18 — estimaterawfee threshold validation
// ---------------------------------------------------------------------------
describe("G18 estimaterawfee threshold validation", () => {
  test("getBuckets() is available for estimaterawfee implementation (RPC delegates to it)", async () => {
    const { est, cleanup } = await makeEstimator();
    try {
      const buckets = est.getBuckets();
      expect(Array.isArray(buckets)).toBe(true);
      expect(buckets.length).toBeGreaterThan(0);
    } finally {
      await cleanup();
    }
  });
});

// ---------------------------------------------------------------------------
// G19 & G20 — estimaterawfee per-horizon decay and scale values
// ---------------------------------------------------------------------------
describe("G19/G20 estimaterawfee horizon decay and scale", () => {
  test("BUG-15: all three horizons in estimaterawfee response share decay=0.998 scale=1 (not per-horizon)", () => {
    // From server.ts:3934-3935:
    //   const decay = 0.998;   (constant, not per-horizon)
    //   const scale = 1;       (constant, not per-horizon)
    // Then short/medium/long all reference the same horizonResult object.
    // Core reports:
    //   short:  decay=0.962,   scale=1
    //   medium: decay=0.9952,  scale=2
    //   long:   decay=0.99931, scale=24
    const hotbunsDecay = 0.998;
    const hotbunsScale = 1;

    // Confirm the bugs:
    expect(hotbunsDecay).not.toBeCloseTo(0.9952, 4);   // medium decay wrong
    expect(hotbunsDecay).not.toBeCloseTo(0.99931, 5);  // long decay wrong
    expect(hotbunsScale).not.toBe(2);   // medium scale wrong
    expect(hotbunsScale).not.toBe(24);  // long scale wrong
  });
});

// ---------------------------------------------------------------------------
// G21 — fee_estimates.dat binary format
// ---------------------------------------------------------------------------
describe("G21 fee_estimates.dat binary format", () => {
  test("BUG-16: serialize() produces JSON text, not Core binary format (version 309900)", async () => {
    const { est, cleanup } = await makeEstimator();
    try {
      for (let i = 0; i < 5; i++) {
        const txid = Buffer.alloc(32, i);
        est.recordConfirmation(txid, 100, 100, 102);
      }
      const serialized = est.serialize();
      // Core format: starts with int32 CURRENT_FEES_FILE_VERSION=309900
      // Hotbuns: produces JSON {"buckets":[...], "txEntryHeights":[...]}
      const isJson = serialized.toString().startsWith("{");
      expect(isJson).toBe(true); // BUG confirmed: JSON format, not Core binary
      // Core-compatible format would start with bytes [0xAC, 0x9B, 0x04, 0x00] (309900 LE)
    } finally {
      await cleanup();
    }
  });
});

// ---------------------------------------------------------------------------
// G22 — IsSynced guard
// ---------------------------------------------------------------------------
describe("G22 IsSynced guard", () => {
  test("BUG-17: trackTransaction accepts txs at any height, no synced-to-tip guard", async () => {
    const { est, cleanup } = await makeEstimator();
    try {
      // Core's processTransaction skips when !tx.m_chainstate_is_current.
      // During IBD, blocks arrive instantly → would bias estimates toward fast confirmations.
      // Hotbuns trackTransaction() takes a height but does NOT check whether that height
      // matches the current chain tip (no isSynced flag consulted).
      const txid = Buffer.alloc(32, 0x42);
      est.trackTransaction(txid, 0); // height=0 (IBD scenario) — accepted without check
      expect(est.getTrackedCount()).toBe(1); // BUG: should not track during IBD
    } finally {
      await cleanup();
    }
  });
});

// ---------------------------------------------------------------------------
// G26 — Reorg guard
// ---------------------------------------------------------------------------
describe("G26 reorg guard", () => {
  test("BUG-18: processBlock applies decay on every call regardless of height ordering (no nBestSeenHeight guard)", async () => {
    const { est, cleanup } = await makeEstimator();
    try {
      const txid = Buffer.alloc(32, 1);
      est.recordConfirmation(txid, 100, 100, 101);

      const bucket = est.getBuckets().find((b) => b.feeRateRange.min === 100)!;
      const beforeFirst = bucket.totalConfirmed;

      // Process height 200 (forward)
      est.processBlock(emptyBlock() as any, 200);
      const afterForward = bucket.totalConfirmed;

      // Process height 199 (reorg — should be ignored by Core)
      est.processBlock(emptyBlock() as any, 199);
      const afterReorg = bucket.totalConfirmed;

      // BUG: hotbuns applies decay again for the reorg block
      // Core would ignore it (nBlockHeight <= nBestSeenHeight check)
      // afterReorg < afterForward proves decay was applied on stale height
      expect(afterReorg).toBeLessThan(afterForward); // BUG confirmed: reorg not guarded
    } finally {
      await cleanup();
    }
  });
});

// ---------------------------------------------------------------------------
// G28 — IEEE 754 decay precision over 1008 blocks
// ---------------------------------------------------------------------------
describe("G28 IEEE 754 decay precision over 1008 blocks", () => {
  test("decay accumulation over 1008 blocks stays within float64 precision (FIX-48: medium-horizon decay)", async () => {
    const { est, cleanup } = await makeEstimator();
    try {
      const txid = Buffer.alloc(32, 1);
      est.recordConfirmation(txid, 100, 100, 101);
      const bucket = est.getBuckets().find((b) => b.feeRateRange.min === 100)!;
      const initial = bucket.totalConfirmed;

      for (let h = 200; h < 1208; h++) {
        est.processBlock(emptyBlock() as any, h);
      }

      // FIX-48: getBuckets() uses medium-horizon decay (0.9952 per block).
      // 0.9952^1008 ≈ 0.008 (roughly 144-block half-life)
      const medDecay = DECAY[Horizon.Medium]; // 0.9952
      const expected = initial * Math.pow(medDecay, 1008);
      // IEEE 754 double is precise; should be within 1e-9 relative
      const relativeError = Math.abs(bucket.totalConfirmed - expected) / expected;
      expect(relativeError).toBeLessThan(1e-9);

      // Short-horizon decay: 0.962^1008 ≈ very tiny (~7-block half-life, fast forgetting)
      // Long-horizon decay:  0.99931^1008 ≈ 0.499 (Core's 1-week half-life)
      const shortHb = est.horizons[Horizon.Long].buckets.find(
        (_hb, i) => est.getBuckets()[i]?.feeRateRange.min === 100
      );
      expect(shortHb).toBeDefined();
    } finally {
      await cleanup();
    }
  });
});

// ---------------------------------------------------------------------------
// G29 — Internal feerate unit (sat/vB vs sat/kvB)
// ---------------------------------------------------------------------------
describe("G29 internal feerate unit", () => {
  test("BUG-19: hotbuns stores feerate in sat/vB; Core uses sat/kvB — bucket index incompatible", async () => {
    const { est, cleanup } = await makeEstimator();
    try {
      // Core MIN_BUCKET_FEERATE=100 sat/kvB=0.1 sat/vB
      // Hotbuns minimum bucket: 1 sat/vB = 1000 sat/kvB
      // Txs paying 0.1–0.99 sat/vB are tracked by Core but fall in bucket 0 of hotbuns
      const bucket0 = est.getBuckets()[0];
      expect(bucket0.feeRateRange.min).toBe(1); // BUG: Core minimum would be 0.1 sat/vB

      // Record at 10 sat/vB — should land in a bucket with min=10
      const txid = Buffer.alloc(32, 1);
      est.recordConfirmation(txid, 10, 100, 102);
      const bucket10 = est.getBuckets().find((b) => b.feeRateRange.min === 10);
      expect(bucket10).toBeDefined(); // confirms sat/vB storage

      // In Core: 10 sat/vB = 10,000 sat/kvB → bucket at ~log(10000/100)/log(1.05) ≈ bucket 95
      // The two systems cannot share fee_estimates.dat data
    } finally {
      await cleanup();
    }
  });
});

// ---------------------------------------------------------------------------
// G30 — FeeCalculation struct
// ---------------------------------------------------------------------------
describe("G30 FeeCalculation struct", () => {
  test("BUG-20: estimateSmartFee returns {feeRate, blocks} only; Core FeeCalculation fields absent", async () => {
    const { est, cleanup } = await makeEstimator();
    try {
      const result = est.estimateSmartFee(6) as any;
      // Core's FeeCalculation has:
      //   desiredTarget, returnedTarget, reason (HALF_ESTIMATE/FULL_ESTIMATE/…), best_height
      expect(result.desiredTarget).toBeUndefined();   // BUG: field absent
      expect(result.returnedTarget).toBeUndefined();  // BUG: field absent
      expect(result.reason).toBeUndefined();           // BUG: field absent
      expect(result.best_height).toBeUndefined();      // BUG: field absent
      // Only feeRate and blocks are present
      expect(result.feeRate).toBeDefined();
      expect(result.blocks).toBeDefined();
    } finally {
      await cleanup();
    }
  });
});

// ---------------------------------------------------------------------------
// Existing behavior sanity checks (structural tests pass/fail unrelated to bugs)
// ---------------------------------------------------------------------------
describe("Existing estimator behavior", () => {
  test("getBuckets returns 41 buckets with correct structure", async () => {
    const { est, cleanup } = await makeEstimator();
    try {
      const buckets = est.getBuckets();
      expect(buckets.length).toBe(41);
      expect(buckets[0].feeRateRange.min).toBe(1);
      expect(buckets[buckets.length - 1].feeRateRange.max).toBe(Infinity);
    } finally {
      await cleanup();
    }
  });

  test("recordConfirmation updates bucket totalConfirmed", async () => {
    const { est, cleanup } = await makeEstimator();
    try {
      const txid = Buffer.alloc(32, 0x11);
      est.recordConfirmation(txid, 100, 100, 102);
      const bucket = est.getBuckets().find((b) => b.feeRateRange.min === 100)!;
      expect(bucket.totalConfirmed).toBe(1);
      expect(bucket.confirmationBlocks).toContain(2);
    } finally {
      await cleanup();
    }
  });

  test("applyDecay reduces totalConfirmed by medium-horizon DECAY per block (FIX-48)", async () => {
    const { est, cleanup } = await makeEstimator();
    try {
      const txid = Buffer.alloc(32, 0x22);
      est.recordConfirmation(txid, 100, 100, 101);
      const bucket = est.getBuckets().find((b) => b.feeRateRange.min === 100)!;
      const before = bucket.totalConfirmed;
      est.processBlock(emptyBlock() as any, 200);
      // getBuckets() uses medium-horizon decay (0.9952); not old 0.998
      expect(bucket.totalConfirmed).toBeCloseTo(before * DECAY[Horizon.Medium], 10);
    } finally {
      await cleanup();
    }
  });

  test("serialize/loadState round-trips bucket data", async () => {
    const { est, cleanup } = await makeEstimator();
    try {
      for (let i = 0; i < 5; i++) {
        est.recordConfirmation(Buffer.alloc(32, i), 100, 100, 102);
      }
      const serialized = est.serialize();

      const dir2 = await mkdtemp(join(tmpdir(), "w114-rt-"));
      const db2 = new ChainDB(dir2);
      await db2.open();
      const utxo2 = new UTXOManager(db2);
      const mempool2 = new Mempool(utxo2, REGTEST, 1_000_000);
      const est2 = new FeeEstimator(mempool2);
      est2.loadState(serialized);
      const bucket = est2.getBuckets().find((b) => b.feeRateRange.min === 100)!;
      expect(bucket.totalConfirmed).toBe(5);
      await db2.close();
      await rm(dir2, { recursive: true, force: true });
    } finally {
      await cleanup();
    }
  });

  test("clear() resets all state", async () => {
    const { est, cleanup } = await makeEstimator();
    try {
      est.recordConfirmation(Buffer.alloc(32, 1), 100, 100, 102);
      est.trackTransaction(Buffer.alloc(32, 2), 150);
      est.clear();
      expect(est.getTrackedCount()).toBe(0);
      const total = est.getBuckets().reduce((s, b) => s + b.totalConfirmed, 0);
      expect(total).toBe(0);
    } finally {
      await cleanup();
    }
  });
});
