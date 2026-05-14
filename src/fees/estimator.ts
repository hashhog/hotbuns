/**
 * Fee estimation based on historical confirmation data.
 *
 * Tracks how long transactions at various fee rates take to confirm,
 * then uses this data to estimate the fee rate needed to confirm
 * within a target number of blocks.
 *
 * Three time horizons mirror Bitcoin Core's CBlockPolicyEstimator:
 *   short  — decay 0.962,   scale 1,  periods 12  (≤12 blocks)
 *   medium — decay 0.9952,  scale 2,  periods 24  (≤48 blocks)
 *   long   — decay 0.99931, scale 24, periods 42  (≤1008 blocks)
 */

import type { Mempool, MempoolEntry } from "../mempool/mempool.js";
import type { Block } from "../validation/block.js";
import { getTxId, getTxVSize, isCoinbase } from "../validation/tx.js";

/**
 * A bucket tracking confirmation times for a range of fee rates.
 */
export interface ConfirmationBucket {
  /** Fee rate range in sat/vB. */
  feeRateRange: { min: number; max: number };
  /** Count of transactions that have confirmed. */
  totalConfirmed: number;
  /** Count of transactions still unconfirmed. */
  totalUnconfirmed: number;
  /** Array of how many blocks each confirmed tx waited. */
  confirmationBlocks: number[];
  /** Average blocks to confirm (computed from confirmationBlocks). */
  avgConfirmationBlocks: number;
}

/**
 * Serialized bucket data for persistence.
 */
interface SerializedBucket {
  feeRateRange: { min: number; max: number };
  totalConfirmed: number;
  totalUnconfirmed: number;
  confirmationBlocks: number[];
  avgConfirmationBlocks: number;
}

/**
 * Serialized estimator state for persistence.
 */
interface SerializedEstimatorState {
  buckets: SerializedBucket[];
  txEntryHeights: Array<[string, number]>;
}

/** Default conservative fee rate when no data is available (sat/vB). */
const DEFAULT_FEE_RATE = 20;

/** Required confidence threshold for fee estimation. */
const CONFIDENCE_THRESHOLD = 0.85;

/** Maximum blocks to track for confirmation time. */
const MAX_CONFIRMATION_BLOCKS = 1008;

/**
 * Time-horizon identifiers, matching Core's feeStats / shortStats / longStats.
 */
export const enum Horizon {
  Short = 0,
  Medium = 1,
  Long = 2,
}

/**
 * Per-horizon decay constants.
 * Core: src/policy/fees.cpp — SHORT_DECAY, MED_DECAY, LONG_DECAY.
 */
export const DECAY: Record<Horizon, number> = {
  [Horizon.Short]: 0.962,
  [Horizon.Medium]: 0.9952,
  [Horizon.Long]: 0.99931,
};

/**
 * Per-horizon period-scale multipliers (blocks per period).
 * Core: SHORT_SCALE=1, MED_SCALE=2, LONG_SCALE=24.
 */
export const SCALE: Record<Horizon, number> = {
  [Horizon.Short]: 1,
  [Horizon.Medium]: 2,
  [Horizon.Long]: 24,
};

/**
 * Number of tracking periods per horizon.
 * Coverage = SCALE × PERIODS blocks.
 *   short:  1  × 12 = 12 blocks
 *   medium: 2  × 24 = 48 blocks
 *   long:   24 × 42 = 1008 blocks
 */
export const PERIODS: Record<Horizon, number> = {
  [Horizon.Short]: 12,
  [Horizon.Medium]: 24,
  [Horizon.Long]: 42,
};

/**
 * Statistics kept per bucket per horizon.
 * Core's TxConfirmStats tracks a flat confirmed[period] array (decay-accumulated)
 * and an unconfirmed[period] ring-buffer. We keep the same approach per horizon.
 */
interface HorizonBucketStats {
  /** Decay-accumulated confirmed count. */
  confirmed: number;
  /** Decay-accumulated unconfirmed count. */
  unconfirmed: number;
  /** Raw confirmation wait times (blocks), kept for percentile estimates. */
  confirmationBlocks: number[];
}

/**
 * All data for a single time horizon.
 */
export interface HorizonStats {
  /** Decay constant for this horizon. */
  readonly decay: number;
  /** Blocks-per-period scale for this horizon. */
  readonly scale: number;
  /** Number of tracking periods for this horizon. */
  readonly periods: number;
  /** Per-bucket stats array, parallel to the shared BUCKET_BOUNDARIES. */
  buckets: HorizonBucketStats[];
}

/**
 * Fee rate bucket boundaries (sat/vB).
 * Exponential spacing to cover wide range from 1 to 10000 sat/vB.
 */
const BUCKET_BOUNDARIES: readonly number[] = [
  1, 2, 3, 4, 5, 6, 7, 8, 10, 12, 14, 17, 20, 25, 30, 40, 50, 60, 70, 80, 100,
  120, 140, 170, 200, 250, 300, 400, 500, 600, 700, 800, 1000, 1200, 1400, 1700,
  2000, 3000, 5000, 7000, 10000,
] as const;

/**
 * Fee estimator based on historical confirmation data.
 *
 * Tracks when transactions enter the mempool and when they confirm,
 * grouping them into fee rate buckets to estimate confirmation times.
 * Three independent time horizons (short/medium/long) mirror Core's
 * CBlockPolicyEstimator with distinct decay and scale constants.
 */
export class FeeEstimator {
  /**
   * Three independent TxConfirmStats-equivalent horizon trackers.
   * Keyed by Horizon enum value so property lookup is O(1).
   */
  readonly horizons: Record<Horizon, HorizonStats>;

  /** Confirmation buckets, one per fee rate range (medium horizon view). */
  private buckets: ConfirmationBucket[];

  /** Fee rate boundaries for bucket assignment. */
  private bucketBoundaries: number[];

  /** Reference to the mempool. */
  private mempool: Mempool;

  /** Map of txid hex -> height when first seen in mempool. */
  private txEntryHeights: Map<string, number>;

  constructor(mempool: Mempool) {
    this.mempool = mempool;
    this.bucketBoundaries = [...BUCKET_BOUNDARIES];
    this.txEntryHeights = new Map();
    this.buckets = this.initializeBuckets();

    // Initialize per-horizon stats arrays, one entry per bucket boundary.
    const makeHorizonStats = (h: Horizon): HorizonStats => ({
      decay: DECAY[h],
      scale: SCALE[h],
      periods: PERIODS[h],
      buckets: BUCKET_BOUNDARIES.map(() => ({
        confirmed: 0,
        unconfirmed: 0,
        confirmationBlocks: [],
      })),
    });

    this.horizons = {
      [Horizon.Short]: makeHorizonStats(Horizon.Short),
      [Horizon.Medium]: makeHorizonStats(Horizon.Medium),
      [Horizon.Long]: makeHorizonStats(Horizon.Long),
    };
  }

  /**
   * Initialize empty confirmation buckets based on boundaries.
   */
  private initializeBuckets(): ConfirmationBucket[] {
    const buckets: ConfirmationBucket[] = [];

    for (let i = 0; i < BUCKET_BOUNDARIES.length; i++) {
      const min = BUCKET_BOUNDARIES[i];
      const max =
        i + 1 < BUCKET_BOUNDARIES.length
          ? BUCKET_BOUNDARIES[i + 1]
          : Infinity;

      buckets.push({
        feeRateRange: { min, max },
        totalConfirmed: 0,
        totalUnconfirmed: 0,
        confirmationBlocks: [],
        avgConfirmationBlocks: 0,
      });
    }

    return buckets;
  }

  /**
   * Get the bucket index for a given fee rate.
   * Returns the index of the highest boundary <= feeRate.
   */
  private getBucketIndex(feeRate: number): number {
    // Binary search for the bucket
    let left = 0;
    let right = this.bucketBoundaries.length - 1;

    // Handle edge cases
    if (feeRate < this.bucketBoundaries[0]) {
      return 0;
    }
    if (feeRate >= this.bucketBoundaries[right]) {
      return right;
    }

    while (left < right) {
      const mid = Math.floor((left + right + 1) / 2);
      if (this.bucketBoundaries[mid] <= feeRate) {
        left = mid;
      } else {
        right = mid - 1;
      }
    }

    return left;
  }

  /**
   * Track a new mempool transaction for future confirmation tracking.
   */
  trackTransaction(txid: Buffer, height: number): void {
    const txidHex = txid.toString("hex");

    // Don't track if already tracking
    if (this.txEntryHeights.has(txidHex)) {
      return;
    }

    this.txEntryHeights.set(txidHex, height);

    // Get the transaction from mempool to record its fee rate bucket
    const entry = this.mempool.getTransaction(txid);
    if (entry) {
      const bucketIndex = this.getBucketIndex(entry.feeRate);
      this.buckets[bucketIndex].totalUnconfirmed += 1;
      // Update per-horizon unconfirmed counts
      for (const h of [Horizon.Short, Horizon.Medium, Horizon.Long] as Horizon[]) {
        this.horizons[h].buckets[bucketIndex].unconfirmed += 1;
      }
    }
  }

  /**
   * Record that a transaction was confirmed.
   * Updates the shared ConfirmationBucket (medium horizon) and all
   * three per-horizon HorizonBucketStats arrays.
   */
  recordConfirmation(
    txid: Buffer,
    feeRate: number,
    entryHeight: number,
    confirmHeight: number
  ): void {
    const blocksWaited = confirmHeight - entryHeight;

    // Only track reasonable confirmation times
    if (blocksWaited < 0 || blocksWaited > MAX_CONFIRMATION_BLOCKS) {
      return;
    }

    const bucketIndex = this.getBucketIndex(feeRate);
    const bucket = this.buckets[bucketIndex];

    // Update shared bucket statistics (medium-horizon view for getBuckets())
    bucket.totalConfirmed += 1;
    bucket.confirmationBlocks.push(blocksWaited);

    // Decrement unconfirmed count if we were tracking this tx
    if (bucket.totalUnconfirmed > 0) {
      bucket.totalUnconfirmed -= 1;
    }

    // Recompute average
    if (bucket.confirmationBlocks.length > 0) {
      const sum = bucket.confirmationBlocks.reduce((a, b) => a + b, 0);
      bucket.avgConfirmationBlocks = sum / bucket.confirmationBlocks.length;
    }

    // Update per-horizon stats
    for (const h of [Horizon.Short, Horizon.Medium, Horizon.Long] as Horizon[]) {
      const hb = this.horizons[h].buckets[bucketIndex];
      hb.confirmed += 1;
      hb.confirmationBlocks.push(blocksWaited);
      if (hb.unconfirmed > 0) {
        hb.unconfirmed -= 1;
      }
    }

    // Remove from tracking
    this.txEntryHeights.delete(txid.toString("hex"));
  }

  /**
   * Process a new block: record confirmations for all transactions in it.
   * Also applies per-horizon decay to old data.
   */
  processBlock(block: Block, height: number): void {
    // Apply per-horizon decay to all buckets
    this.applyDecay();

    // Process each transaction in the block
    for (const tx of block.transactions) {
      if (isCoinbase(tx)) {
        continue;
      }

      const txid = getTxId(tx);
      const txidHex = txid.toString("hex");

      // Only process transactions we were tracking (from our mempool)
      const entryHeight = this.txEntryHeights.get(txidHex);
      if (entryHeight === undefined) {
        continue;
      }

      // Calculate fee rate for this transaction
      // We need to know the fee, which requires knowing input values
      // For simplicity, use the mempool entry's fee rate if available
      const mempoolEntry = this.mempool.getTransaction(txid);
      if (mempoolEntry) {
        this.recordConfirmation(
          txid,
          mempoolEntry.feeRate,
          entryHeight,
          height
        );
      }
    }

    // Clean up entries that have been in the map too long (orphaned)
    const maxAge = MAX_CONFIRMATION_BLOCKS * 2;
    for (const [txidHex, entryHeight] of this.txEntryHeights) {
      if (height - entryHeight > maxAge) {
        this.txEntryHeights.delete(txidHex);
        // Don't decrement totalUnconfirmed here since decay handles old data
      }
    }
  }

  /**
   * Apply per-horizon decay factor to all bucket statistics.
   * Short horizon decays fastest (0.962), long horizon slowest (0.99931).
   * The shared ConfirmationBucket array uses the medium horizon decay.
   */
  private applyDecay(): void {
    // Apply medium-horizon decay to the shared bucket array (backward compat)
    const medDecay = DECAY[Horizon.Medium];
    for (const bucket of this.buckets) {
      bucket.totalConfirmed *= medDecay;
      bucket.totalUnconfirmed *= medDecay;

      // Trim very old confirmation data
      if (bucket.confirmationBlocks.length > 10000) {
        bucket.confirmationBlocks = bucket.confirmationBlocks.slice(-5000);

        // Recompute average
        if (bucket.confirmationBlocks.length > 0) {
          const sum = bucket.confirmationBlocks.reduce((a, b) => a + b, 0);
          bucket.avgConfirmationBlocks = sum / bucket.confirmationBlocks.length;
        }
      }
    }

    // Apply per-horizon decay to horizon-specific stats
    for (const h of [Horizon.Short, Horizon.Medium, Horizon.Long] as Horizon[]) {
      const hDecay = DECAY[h];
      for (const hb of this.horizons[h].buckets) {
        hb.confirmed *= hDecay;
        hb.unconfirmed *= hDecay;
        if (hb.confirmationBlocks.length > 10000) {
          hb.confirmationBlocks = hb.confirmationBlocks.slice(-5000);
        }
      }
    }
  }

  /**
   * Estimate the fee rate (sat/vB) needed to confirm within targetBlocks.
   *
   * Algorithm: For each bucket from highest fee rate downward, calculate
   * the probability of confirmation within targetBlocks as:
   *   P = confirmed_within_target / (confirmed_within_target + still_unconfirmed)
   *
   * Return the lowest fee rate bucket where P exceeds CONFIDENCE_THRESHOLD.
   */
  estimateFee(targetBlocks: number): number {
    // Validate target
    if (targetBlocks < 1) {
      targetBlocks = 1;
    }
    if (targetBlocks > MAX_CONFIRMATION_BLOCKS) {
      targetBlocks = MAX_CONFIRMATION_BLOCKS;
    }

    // Search from highest fee rate down
    for (let i = this.buckets.length - 1; i >= 0; i--) {
      const bucket = this.buckets[i];

      // Skip buckets with insufficient data
      if (bucket.totalConfirmed < 1 && bucket.totalUnconfirmed < 1) {
        continue;
      }

      // Count confirmations within target
      const confirmedWithinTarget = bucket.confirmationBlocks.filter(
        (blocks) => blocks <= targetBlocks
      ).length;

      // Calculate probability
      const total = confirmedWithinTarget + bucket.totalUnconfirmed;
      if (total < 1) {
        continue;
      }

      const probability = confirmedWithinTarget / total;

      // If this bucket has sufficient confidence, it's a candidate
      // But we want the LOWEST fee rate that meets the threshold,
      // so continue searching lower buckets
      if (probability >= CONFIDENCE_THRESHOLD) {
        // Found a bucket that meets threshold
        // Continue searching to find the lowest fee rate bucket that works
        let lowestBucketIndex = i;

        for (let j = i - 1; j >= 0; j--) {
          const lowerBucket = this.buckets[j];
          if (lowerBucket.totalConfirmed < 1 && lowerBucket.totalUnconfirmed < 1) {
            continue;
          }

          const lowerConfirmedWithinTarget = lowerBucket.confirmationBlocks.filter(
            (blocks) => blocks <= targetBlocks
          ).length;

          const lowerTotal = lowerConfirmedWithinTarget + lowerBucket.totalUnconfirmed;
          if (lowerTotal < 1) {
            continue;
          }

          const lowerProbability = lowerConfirmedWithinTarget / lowerTotal;
          if (lowerProbability >= CONFIDENCE_THRESHOLD) {
            lowestBucketIndex = j;
          }
        }

        return this.buckets[lowestBucketIndex].feeRateRange.min;
      }
    }

    // Fallback: use median fee rate of current mempool
    const mempoolMedian = this.getMempoolMedianFeeRate();
    if (mempoolMedian > 0) {
      return mempoolMedian;
    }

    // No data at all: return conservative default
    return DEFAULT_FEE_RATE;
  }

  /**
   * Select the appropriate horizon for a given target block count.
   * Mirrors Core's selection: short for ≤12 blocks, long for >48, medium otherwise.
   */
  private selectHorizon(targetBlocks: number): Horizon {
    const shortMax = SCALE[Horizon.Short] * PERIODS[Horizon.Short];   // 12
    const medMax   = SCALE[Horizon.Medium] * PERIODS[Horizon.Medium]; // 48
    if (targetBlocks <= shortMax) {
      return Horizon.Short;
    }
    if (targetBlocks <= medMax) {
      return Horizon.Medium;
    }
    return Horizon.Long;
  }

  /**
   * Estimate fee for a specific horizon's bucket stats.
   */
  private estimateFeeForHorizon(targetBlocks: number, horizon: Horizon): number | null {
    const hBuckets = this.horizons[horizon].buckets;
    const minDataPoints = 10;

    for (let i = hBuckets.length - 1; i >= 0; i--) {
      const hb = hBuckets[i];

      if (hb.confirmationBlocks.length < minDataPoints) {
        continue;
      }

      const confirmedWithinTarget = hb.confirmationBlocks.filter(
        (blocks) => blocks <= targetBlocks
      ).length;

      const total = confirmedWithinTarget + hb.unconfirmed;
      if (total < minDataPoints) {
        continue;
      }

      const probability = confirmedWithinTarget / total;

      if (probability >= CONFIDENCE_THRESHOLD) {
        let lowestBucketIndex = i;

        for (let j = i - 1; j >= 0; j--) {
          const lowerHb = hBuckets[j];
          if (lowerHb.confirmationBlocks.length < minDataPoints) {
            continue;
          }

          const lowerConfirmedWithinTarget = lowerHb.confirmationBlocks.filter(
            (blocks) => blocks <= targetBlocks
          ).length;

          const lowerTotal = lowerConfirmedWithinTarget + lowerHb.unconfirmed;
          if (lowerTotal < minDataPoints) {
            continue;
          }

          const lowerProbability = lowerConfirmedWithinTarget / lowerTotal;
          if (lowerProbability >= CONFIDENCE_THRESHOLD) {
            lowestBucketIndex = j;
          }
        }

        return this.buckets[lowestBucketIndex].feeRateRange.min;
      }
    }

    return null;
  }

  /**
   * Estimate fee for common targets with additional information.
   * Dispatches to the appropriate horizon (short/medium/long) based on target.
   * May return a longer target than requested if there isn't enough data.
   */
  estimateSmartFee(targetBlocks: number): { feeRate: number; blocks: number } {
    // Validate target
    if (targetBlocks < 1) {
      targetBlocks = 1;
    }
    if (targetBlocks > MAX_CONFIRMATION_BLOCKS) {
      targetBlocks = MAX_CONFIRMATION_BLOCKS;
    }

    // Select horizon based on target, then try the requested target
    const horizon = this.selectHorizon(targetBlocks);
    let feeRate = this.estimateFeeForHorizon(targetBlocks, horizon);
    if (feeRate !== null) {
      return { feeRate, blocks: targetBlocks };
    }

    // Fall back to estimateFeeWithData (uses shared medium buckets)
    feeRate = this.estimateFeeWithData(targetBlocks);
    if (feeRate !== null) {
      return { feeRate, blocks: targetBlocks };
    }

    // Not enough data - try progressively longer targets
    const longerTargets = [2, 3, 6, 12, 24, 48, 144, 504, 1008];

    for (const target of longerTargets) {
      if (target <= targetBlocks) {
        continue;
      }

      feeRate = this.estimateFeeWithData(target);
      if (feeRate !== null) {
        return { feeRate, blocks: target };
      }
    }

    // Fallback to mempool median or default
    const mempoolMedian = this.getMempoolMedianFeeRate();
    if (mempoolMedian > 0) {
      return { feeRate: mempoolMedian, blocks: targetBlocks };
    }

    return { feeRate: DEFAULT_FEE_RATE, blocks: targetBlocks };
  }

  /**
   * Try to estimate fee for a target, returning null if insufficient data.
   */
  private estimateFeeWithData(targetBlocks: number): number | null {
    // Require at least some data points for confidence
    const minDataPoints = 10;

    for (let i = this.buckets.length - 1; i >= 0; i--) {
      const bucket = this.buckets[i];

      // Check if this bucket has enough data
      if (bucket.confirmationBlocks.length < minDataPoints) {
        continue;
      }

      const confirmedWithinTarget = bucket.confirmationBlocks.filter(
        (blocks) => blocks <= targetBlocks
      ).length;

      const total = confirmedWithinTarget + bucket.totalUnconfirmed;
      if (total < minDataPoints) {
        continue;
      }

      const probability = confirmedWithinTarget / total;

      if (probability >= CONFIDENCE_THRESHOLD) {
        // Found a bucket - search for lowest
        let lowestBucketIndex = i;

        for (let j = i - 1; j >= 0; j--) {
          const lowerBucket = this.buckets[j];
          if (lowerBucket.confirmationBlocks.length < minDataPoints) {
            continue;
          }

          const lowerConfirmedWithinTarget = lowerBucket.confirmationBlocks.filter(
            (blocks) => blocks <= targetBlocks
          ).length;

          const lowerTotal = lowerConfirmedWithinTarget + lowerBucket.totalUnconfirmed;
          if (lowerTotal < minDataPoints) {
            continue;
          }

          const lowerProbability = lowerConfirmedWithinTarget / lowerTotal;
          if (lowerProbability >= CONFIDENCE_THRESHOLD) {
            lowestBucketIndex = j;
          }
        }

        return this.buckets[lowestBucketIndex].feeRateRange.min;
      }
    }

    return null;
  }

  /**
   * Get the median fee rate from the current mempool.
   */
  private getMempoolMedianFeeRate(): number {
    const entries = this.mempool.getTransactionsByFeeRate();
    if (entries.length === 0) {
      return 0;
    }

    // Already sorted by fee rate descending
    const midIndex = Math.floor(entries.length / 2);
    return entries[midIndex].feeRate;
  }

  /**
   * Get all buckets (for debugging/inspection).
   * Returns the medium-horizon view, which is the primary estimation surface.
   */
  getBuckets(): readonly ConfirmationBucket[] {
    return this.buckets;
  }

  /**
   * Get the number of transactions being tracked.
   */
  getTrackedCount(): number {
    return this.txEntryHeights.size;
  }

  /**
   * Serialize the estimator state for persistence.
   */
  serialize(): Buffer {
    const state: SerializedEstimatorState = {
      buckets: this.buckets.map((b) => ({
        feeRateRange: b.feeRateRange,
        totalConfirmed: b.totalConfirmed,
        totalUnconfirmed: b.totalUnconfirmed,
        confirmationBlocks: b.confirmationBlocks,
        avgConfirmationBlocks: b.avgConfirmationBlocks,
      })),
      txEntryHeights: Array.from(this.txEntryHeights.entries()),
    };

    return Buffer.from(JSON.stringify(state));
  }

  /**
   * Load estimator state from serialized data.
   */
  loadState(data: Buffer): void {
    try {
      const state = JSON.parse(data.toString()) as SerializedEstimatorState;

      // Validate and restore buckets
      if (Array.isArray(state.buckets) && state.buckets.length === this.buckets.length) {
        for (let i = 0; i < state.buckets.length; i++) {
          const saved = state.buckets[i];
          if (
            saved &&
            typeof saved.totalConfirmed === "number" &&
            typeof saved.totalUnconfirmed === "number" &&
            Array.isArray(saved.confirmationBlocks)
          ) {
            this.buckets[i].totalConfirmed = saved.totalConfirmed;
            this.buckets[i].totalUnconfirmed = saved.totalUnconfirmed;
            this.buckets[i].confirmationBlocks = saved.confirmationBlocks;
            this.buckets[i].avgConfirmationBlocks = saved.avgConfirmationBlocks || 0;
          }
        }
      }

      // Restore txEntryHeights
      if (Array.isArray(state.txEntryHeights)) {
        this.txEntryHeights = new Map(state.txEntryHeights);
      }
    } catch {
      // Invalid data - keep default state
    }
  }

  /**
   * Clear all historical data (useful for testing).
   */
  clear(): void {
    this.buckets = this.initializeBuckets();
    this.txEntryHeights.clear();

    // Reset horizon stats too
    for (const h of [Horizon.Short, Horizon.Medium, Horizon.Long] as Horizon[]) {
      for (const hb of this.horizons[h].buckets) {
        hb.confirmed = 0;
        hb.unconfirmed = 0;
        hb.confirmationBlocks = [];
      }
    }
  }
}
