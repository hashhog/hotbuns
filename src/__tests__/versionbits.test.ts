/**
 * Tests for BIP9 Version Bits Soft Fork Deployment
 *
 * Tests the state machine transitions:
 * DEFINED -> STARTED -> LOCKED_IN -> ACTIVE (or FAILED)
 *
 * Key understanding:
 * - State is computed for the block AFTER pindexPrev
 * - State transitions occur at period boundaries
 * - A period is 2016 blocks (heights 0-2015, 2016-4031, etc.)
 * - The state for a period is determined by what happened in the PREVIOUS period
 */

import { describe, it, expect, beforeEach } from "bun:test";
import {
  DeploymentState,
  VersionBitsCache,
  DeploymentParams,
  BlockIndex,
  getStateFor,
  getStateStatistics,
  versionSignals,
  createDeployment,
  VERSIONBITS_TOP_BITS,
  ALWAYS_ACTIVE,
  NEVER_ACTIVE,
  NO_TIMEOUT,
  MAINNET_THRESHOLD,
  MAINNET_THRESHOLD_DEFAULT,
  TESTNET_THRESHOLD,
  buildBlockIndex,
  type HeaderInfo,
} from "../consensus/versionbits";

/**
 * Helper to create a chain of block indices for testing.
 *
 * @param length - Number of blocks to create
 * @param options - Configuration options
 * @returns Array of block indices
 */
function createBlockChain(
  length: number,
  options: {
    startHeight?: number;
    startMTP?: bigint;
    versionFn?: (height: number) => number;
    mtpIncrement?: number;
  } = {}
): BlockIndex[] {
  const {
    startHeight = 0,
    startMTP = 0n,
    versionFn = () => VERSIONBITS_TOP_BITS,
    mtpIncrement = 600, // 10 minutes per block
  } = options;

  const blocks: BlockIndex[] = [];
  let prev: BlockIndex | null = null;

  for (let i = 0; i < length; i++) {
    const height = startHeight + i;
    const block: BlockIndex = {
      hash: `block_${height}`,
      height,
      version: versionFn(height),
      medianTimePast: startMTP + BigInt(i * mtpIncrement),
      prev,
    };
    blocks.push(block);
    prev = block;
  }

  return blocks;
}

/**
 * Extend a chain by creating new blocks linked to the tip.
 */
function extendChain(
  existingChain: BlockIndex[],
  additionalLength: number,
  options: {
    versionFn?: (height: number) => number;
    mtpIncrement?: number;
  } = {}
): BlockIndex[] {
  const tip = existingChain[existingChain.length - 1];
  const newBlocks = createBlockChain(additionalLength, {
    startHeight: tip.height + 1,
    startMTP: tip.medianTimePast + BigInt(options.mtpIncrement ?? 600),
    versionFn: options.versionFn,
    mtpIncrement: options.mtpIncrement,
  });

  // Link the first new block to the existing tip
  (newBlocks[0] as any).prev = tip;

  return newBlocks;
}

/**
 * Helper to get the last block in a chain.
 */
function tip(blocks: BlockIndex[]): BlockIndex {
  return blocks[blocks.length - 1];
}

describe("versionbits", () => {
  describe("versionSignals", () => {
    it("should detect signaling when top bits and signal bit are set", () => {
      const version = VERSIONBITS_TOP_BITS | (1 << 2);
      expect(versionSignals(version, 2)).toBe(true);
    });

    it("should reject signaling without top bits", () => {
      const version = 1 | (1 << 2); // Old-style version
      expect(versionSignals(version, 2)).toBe(false);
    });

    it("should reject signaling without signal bit", () => {
      const version = VERSIONBITS_TOP_BITS;
      expect(versionSignals(version, 2)).toBe(false);
    });

    it("should check correct bit position", () => {
      const version = VERSIONBITS_TOP_BITS | (1 << 5);
      expect(versionSignals(version, 5)).toBe(true);
      expect(versionSignals(version, 2)).toBe(false);
      expect(versionSignals(version, 0)).toBe(false);
    });

    it("should handle multiple bits in version", () => {
      const version = VERSIONBITS_TOP_BITS | (1 << 1) | (1 << 5) | (1 << 10);

      expect(versionSignals(version, 1)).toBe(true);
      expect(versionSignals(version, 5)).toBe(true);
      expect(versionSignals(version, 10)).toBe(true);
      expect(versionSignals(version, 2)).toBe(false);
      expect(versionSignals(version, 28)).toBe(false);
    });
  });

  describe("DeploymentState - special cases", () => {
    let cache: Map<string | null, DeploymentState>;

    beforeEach(() => {
      cache = new Map();
    });

    it("should start in DEFINED state for genesis", () => {
      const deployment = createDeployment({
        bit: 2,
        startTime: 1000000n,
        timeout: 2000000n,
      });

      const state = getStateFor(null, deployment, cache);
      expect(state).toBe(DeploymentState.Defined);
    });

    it("should return ACTIVE for ALWAYS_ACTIVE deployment", () => {
      const deployment = createDeployment({
        bit: 2,
        startTime: ALWAYS_ACTIVE,
        timeout: NO_TIMEOUT,
      });

      const state = getStateFor(null, deployment, cache);
      expect(state).toBe(DeploymentState.Active);
    });

    it("should return FAILED for NEVER_ACTIVE deployment", () => {
      const deployment = createDeployment({
        bit: 2,
        startTime: NEVER_ACTIVE,
        timeout: NO_TIMEOUT,
      });

      const state = getStateFor(null, deployment, cache);
      expect(state).toBe(DeploymentState.Failed);
    });
  });

  describe("DeploymentState transitions", () => {
    const period = 2016;
    const threshold = 1815; // 90%
    let cache: Map<string | null, DeploymentState>;

    beforeEach(() => {
      cache = new Map();
    });

    it("should remain DEFINED when MTP is before startTime", () => {
      // Set startTime far in the future
      const startTime = 10000000n;
      const deployment = createDeployment({
        bit: 2,
        startTime,
        timeout: 20000000n,
      });

      // Create chain with low MTP values
      const blocks = createBlockChain(period * 2, {
        startMTP: 0n,
        mtpIncrement: 600, // Each block adds 600 seconds
      });

      // MTP at tip = 0 + (period*2 - 1) * 600 = ~2,417,400 < 10,000,000
      expect(tip(blocks).medianTimePast).toBeLessThan(startTime);

      const state = getStateFor(tip(blocks), deployment, cache);
      expect(state).toBe(DeploymentState.Defined);
    });

    it("should transition to STARTED when MTP reaches startTime at period boundary", () => {
      const startTime = 1000n;
      const deployment = createDeployment({
        bit: 2,
        startTime,
        timeout: 10000000n,
      });

      // Period 0 (blocks 0-2015): MTP < startTime -> DEFINED
      // Period 1 (blocks 2016-4031): MTP >= startTime -> STARTED
      const blocks = createBlockChain(period * 2, {
        startMTP: 0n,
        mtpIncrement: 1, // Small increment so MTP passes startTime during period 1
      });

      // At end of period 0 (block 2015), next block will be in period 1
      const endPeriod0 = blocks[period - 1];
      // State for block 2016 (pindexPrev = block 2015)
      const state0 = getStateFor(endPeriod0, deployment, cache);
      // MTP of block 2015 = 2015, which is > 1000, so transitions to STARTED
      expect(state0).toBe(DeploymentState.Started);
    });

    it("should transition to LOCKED_IN when threshold is met", () => {
      const deployment = createDeployment({
        bit: 2,
        startTime: 0n,
        timeout: 10000000n,
        threshold,
      });

      // Create 4 periods of blocks, all signaling
      const blocks = createBlockChain(period * 4, {
        startMTP: 0n,
        versionFn: () => VERSIONBITS_TOP_BITS | (1 << 2),
      });

      // Period 0: DEFINED (before we can count signals)
      // Period 1: STARTED (MTP >= startTime, start counting)
      // Period 2: LOCKED_IN (period 1 had enough signals)
      // Period 3: ACTIVE

      // State at end of period 1 (for block 4032)
      const endPeriod1 = blocks[period * 2 - 1];
      expect(getStateFor(endPeriod1, deployment, cache)).toBe(DeploymentState.LockedIn);
    });

    it("should stay STARTED when threshold not met", () => {
      const deployment = createDeployment({
        bit: 2,
        startTime: 0n,
        timeout: 10000000n,
        threshold: 1815,
      });

      // Only 1000 signaling blocks (way under 1815 threshold)
      const signalingCount = 1000;
      const blocks = createBlockChain(period * 3, {
        startMTP: 0n,
        versionFn: (height) => {
          // Signal in period 1 (blocks 2016-4031), but only first 1000
          if (height >= period && height < period + signalingCount) {
            return VERSIONBITS_TOP_BITS | (1 << 2);
          }
          return VERSIONBITS_TOP_BITS;
        },
      });

      // At end of period 2, should still be STARTED (not locked in)
      const endPeriod2 = blocks[period * 3 - 1];
      expect(getStateFor(endPeriod2, deployment, cache)).toBe(DeploymentState.Started);
    });

    it("should transition to FAILED when timeout is reached without lock-in", () => {
      // FAILED can only be reached from STARTED state
      // So: DEFINED -> STARTED -> FAILED
      const startTime = 0n;
      const timeout = 3000n; // Timeout after period 1 starts but before period 2
      const deployment = createDeployment({
        bit: 2,
        startTime,
        timeout,
        threshold: 1815,
      });

      // Create chain with no signaling
      // Period 0 (blocks 0-2015): MTP 0-2015, DEFINED at start, STARTED at end (MTP >= startTime)
      // Period 1 (blocks 2016-4031): MTP 2016-4031, timeout at MTP 3000 (block 3000)
      // At end of period 1, MTP > timeout, so transitions to FAILED
      const blocks = createBlockChain(period * 3, {
        startMTP: 0n,
        mtpIncrement: 1,
        versionFn: () => VERSIONBITS_TOP_BITS, // No signaling
      });

      // At end of period 0, state becomes STARTED (MTP >= startTime)
      const endPeriod0 = blocks[period - 1];
      expect(getStateFor(endPeriod0, deployment, cache)).toBe(DeploymentState.Started);

      // At end of period 1, MTP = 4031 > 3000 = timeout, state becomes FAILED
      const endPeriod1 = blocks[period * 2 - 1];
      expect(getStateFor(endPeriod1, deployment, cache)).toBe(DeploymentState.Failed);
    });

    it("should transition from LOCKED_IN to ACTIVE after one period", () => {
      const deployment = createDeployment({
        bit: 2,
        startTime: 0n,
        timeout: 10000000n,
        threshold,
        minActivationHeight: 0,
      });

      // All blocks signal
      const blocks = createBlockChain(period * 5, {
        startMTP: 0n,
        versionFn: () => VERSIONBITS_TOP_BITS | (1 << 2),
      });

      // Period 0: DEFINED
      // Period 1: STARTED
      // Period 2: LOCKED_IN
      // Period 3: ACTIVE

      const endPeriod2 = blocks[period * 3 - 1];
      expect(getStateFor(endPeriod2, deployment, cache)).toBe(DeploymentState.Active);
    });

    it("should respect minActivationHeight and delay activation", () => {
      const minActivationHeight = period * 4; // Activate no earlier than block 8064
      const deployment = createDeployment({
        bit: 2,
        startTime: 0n,
        timeout: 10000000n,
        threshold,
        minActivationHeight,
      });

      // All blocks signal
      const blocks = createBlockChain(period * 6, {
        startMTP: 0n,
        versionFn: () => VERSIONBITS_TOP_BITS | (1 << 2),
      });

      // End of period 2 (block 6047): normally would be ACTIVE, but minActivationHeight delays
      // pindexPrev.height + 1 = 6048, which is < 8064, so stay LOCKED_IN
      const endPeriod2 = blocks[period * 3 - 1];
      expect(getStateFor(endPeriod2, deployment, cache)).toBe(DeploymentState.LockedIn);

      // End of period 3 (block 8063): height + 1 = 8064 >= minActivationHeight, now ACTIVE
      const endPeriod3 = blocks[period * 4 - 1];
      expect(getStateFor(endPeriod3, deployment, cache)).toBe(DeploymentState.Active);
    });

    it("should remain in terminal states (ACTIVE/FAILED)", () => {
      const deployment = createDeployment({
        bit: 2,
        startTime: 0n,
        timeout: 10000000n,
        threshold,
      });

      const blocks = createBlockChain(period * 5, {
        startMTP: 0n,
        versionFn: () => VERSIONBITS_TOP_BITS | (1 << 2),
      });

      // Once ACTIVE, stays ACTIVE
      const endPeriod3 = blocks[period * 4 - 1];
      expect(getStateFor(endPeriod3, deployment, cache)).toBe(DeploymentState.Active);

      const endPeriod4 = blocks[period * 5 - 1];
      expect(getStateFor(endPeriod4, deployment, cache)).toBe(DeploymentState.Active);
    });
  });

  describe("getStateStatistics", () => {
    it("should count signaling blocks correctly in partial period", () => {
      const deployment = createDeployment({
        bit: 2,
        startTime: 0n,
        timeout: 10000000n,
      });

      const signalingCount = 500;
      const elapsed = 1000;
      const blocks = createBlockChain(elapsed, {
        startMTP: 0n,
        versionFn: (height) =>
          height < signalingCount
            ? VERSIONBITS_TOP_BITS | (1 << 2)
            : VERSIONBITS_TOP_BITS,
      });

      const stats = getStateStatistics(tip(blocks), deployment);

      expect(stats.period).toBe(2016);
      // Default threshold is now MAINNET_THRESHOLD_DEFAULT (1916, Core default), not 1815.
      expect(stats.threshold).toBe(MAINNET_THRESHOLD_DEFAULT);
      expect(stats.elapsed).toBe(elapsed);
      expect(stats.count).toBe(signalingCount);
      // Need 1916 - 500 = 1416 more, have 2016 - 1000 = 1016 remaining
      // 1416 > 1016, so impossible
      expect(stats.possible).toBe(false);
    });

    it("should report possible when enough blocks remain", () => {
      const deployment = createDeployment({
        bit: 2,
        startTime: 0n,
        timeout: 10000000n,
        threshold: 1500, // Lower threshold
      });

      const signalingCount = 500;
      const elapsed = 1000;
      const blocks = createBlockChain(elapsed, {
        startMTP: 0n,
        versionFn: (height) =>
          height < signalingCount
            ? VERSIONBITS_TOP_BITS | (1 << 2)
            : VERSIONBITS_TOP_BITS,
      });

      const stats = getStateStatistics(tip(blocks), deployment);

      // Need 1500 - 500 = 1000 more, have 2016 - 1000 = 1016 remaining
      expect(stats.possible).toBe(true);
    });

    it("should return empty stats for null block", () => {
      const deployment = createDeployment({
        bit: 2,
        startTime: 0n,
        timeout: 10000000n,
      });

      const stats = getStateStatistics(null, deployment);

      expect(stats.elapsed).toBe(0);
      expect(stats.count).toBe(0);
      expect(stats.possible).toBe(false);
    });
  });

  describe("VersionBitsCache", () => {
    let cache: VersionBitsCache;

    beforeEach(() => {
      cache = new VersionBitsCache();
    });

    it("should cache deployment states", () => {
      const deployment = createDeployment({
        bit: 2,
        startTime: ALWAYS_ACTIVE,
        timeout: NO_TIMEOUT,
      });

      const state1 = cache.getState(null, deployment, "taproot");
      expect(state1).toBe(DeploymentState.Active);

      // Second call should use cache
      const state2 = cache.getState(null, deployment, "taproot");
      expect(state2).toBe(DeploymentState.Active);
    });

    it("should track different deployments separately", () => {
      const activeDeployment = createDeployment({
        bit: 2,
        startTime: ALWAYS_ACTIVE,
        timeout: NO_TIMEOUT,
      });

      const failedDeployment = createDeployment({
        bit: 3,
        startTime: NEVER_ACTIVE,
        timeout: NO_TIMEOUT,
      });

      expect(cache.getState(null, activeDeployment, "active")).toBe(DeploymentState.Active);
      expect(cache.getState(null, failedDeployment, "failed")).toBe(DeploymentState.Failed);
    });

    it("should check if deployment is active", () => {
      const deployment = createDeployment({
        bit: 2,
        startTime: ALWAYS_ACTIVE,
        timeout: NO_TIMEOUT,
      });

      expect(cache.isActiveAfter(null, deployment, "taproot")).toBe(true);
    });

    it("should clear all cached state", () => {
      const deployment = createDeployment({
        bit: 2,
        startTime: 0n,
        timeout: 10000000n,
      });

      const blocks = createBlockChain(2016);
      cache.getState(tip(blocks), deployment, "test");

      cache.clear();

      // Cache should be empty, but function should still work
      const state = cache.getState(tip(blocks), deployment, "test");
      expect(state).toBeDefined();
    });

    it("should compute block version with signal bits for STARTED deployments", () => {
      const deployments = new Map<string, DeploymentParams>([
        ["dep1", createDeployment({ bit: 1, startTime: 0n, timeout: 10000000n })],
        ["dep2", createDeployment({ bit: 5, startTime: 0n, timeout: 10000000n })],
      ]);

      // Create chain where deployments are in STARTED state
      const blocks = createBlockChain(2016 * 2, {
        startMTP: 0n,
      });

      const version = cache.computeBlockVersion(tip(blocks), deployments);

      // Should have top bits and signal bits
      expect(version & VERSIONBITS_TOP_BITS).toBe(VERSIONBITS_TOP_BITS);
      expect(version & (1 << 1)).toBe(1 << 1);
      expect(version & (1 << 5)).toBe(1 << 5);
    });

    it("should not set signal bits for DEFINED deployments", () => {
      const deployments = new Map<string, DeploymentParams>([
        ["future", createDeployment({ bit: 3, startTime: 999999999n, timeout: 9999999999n })],
      ]);

      const blocks = createBlockChain(2016, {
        startMTP: 0n,
      });

      const version = cache.computeBlockVersion(tip(blocks), deployments);

      expect(version & VERSIONBITS_TOP_BITS).toBe(VERSIONBITS_TOP_BITS);
      expect(version & (1 << 3)).toBe(0);
    });

    it("should set signal bits for LOCKED_IN deployments", () => {
      const period = 2016;
      const deployments = new Map<string, DeploymentParams>([
        ["locked", createDeployment({ bit: 4, startTime: 0n, timeout: 10000000n, threshold: 1815 })],
      ]);

      // Create chain that reaches LOCKED_IN
      const blocks = createBlockChain(period * 3, {
        startMTP: 0n,
        versionFn: () => VERSIONBITS_TOP_BITS | (1 << 4),
      });

      // At end of period 2, state should be LOCKED_IN
      const version = cache.computeBlockVersion(blocks[period * 2 - 1], deployments);

      // Should still signal during LOCKED_IN
      expect(version & (1 << 4)).toBe(1 << 4);
    });
  });

  describe("createDeployment", () => {
    it("should use default values", () => {
      const deployment = createDeployment({
        bit: 2,
        startTime: 1000n,
        timeout: 2000n,
      });

      expect(deployment.period).toBe(2016);
      // Default threshold is MAINNET_THRESHOLD_DEFAULT (1916 / 95%), matching Core's
      // BIP9Deployment::threshold default.  The old value of 1815 was wrong.
      expect(deployment.threshold).toBe(MAINNET_THRESHOLD_DEFAULT);
      expect(deployment.minActivationHeight).toBe(0);
    });

    it("should allow custom thresholds", () => {
      const deployment = createDeployment({
        bit: 2,
        startTime: 1000n,
        timeout: 2000n,
        threshold: TESTNET_THRESHOLD,
      });

      expect(deployment.threshold).toBe(1512);
    });

    it("should allow custom period", () => {
      const deployment = createDeployment({
        bit: 2,
        startTime: 1000n,
        timeout: 2000n,
        period: 144,
      });

      expect(deployment.period).toBe(144);
    });
  });

  describe("edge cases", () => {
    it("should handle state computation at exact period boundaries", () => {
      const deployment = createDeployment({
        bit: 2,
        startTime: 0n,
        timeout: 10000000n,
      });

      const cache = new Map<string | null, DeploymentState>();
      const period = 2016;

      // Chain ends exactly at period boundary (height 2015)
      const blocks = createBlockChain(period, {
        startMTP: 0n,
      });

      const state = getStateFor(tip(blocks), deployment, cache);
      expect(state).toBeDefined();
    });

    it("should handle chains shorter than one period", () => {
      const deployment = createDeployment({
        bit: 2,
        startTime: 1000000n, // Far future
        timeout: 10000000n,
      });

      const cache = new Map<string | null, DeploymentState>();

      const blocks = createBlockChain(100, {
        startMTP: 0n,
      });

      const state = getStateFor(tip(blocks), deployment, cache);
      expect(state).toBe(DeploymentState.Defined);
    });

    it("should correctly count signals at period boundaries", () => {
      const period = 2016;
      const threshold = 1815;
      const deployment = createDeployment({
        bit: 2,
        startTime: 0n,
        timeout: 10000000n,
        threshold,
      });

      // Create exactly threshold signaling blocks in period 1
      const blocks = createBlockChain(period * 3, {
        startMTP: 0n,
        versionFn: (height) => {
          // Period 1: blocks 2016-4031
          // Signal for exactly 1815 blocks (2016 to 3830)
          if (height >= period && height < period + threshold) {
            return VERSIONBITS_TOP_BITS | (1 << 2);
          }
          return VERSIONBITS_TOP_BITS;
        },
      });

      const cache = new Map<string | null, DeploymentState>();

      // At end of period 1, should lock in
      const endPeriod1 = blocks[period * 2 - 1];
      expect(getStateFor(endPeriod1, deployment, cache)).toBe(DeploymentState.LockedIn);
    });
  });
});

describe("BIP9 deployment scenarios", () => {
  const period = 2016;
  const threshold = 1815;

  it("should simulate a full deployment lifecycle", () => {
    const startTime = 1000n;
    const deployment = createDeployment({
      bit: 2,
      startTime,
      timeout: 10000000n,
      threshold,
    });

    const cache = new Map<string | null, DeploymentState>();

    // Period 0: MTP < startTime -> DEFINED
    const period0 = createBlockChain(period, {
      startMTP: 0n,
      mtpIncrement: 0, // Keep MTP at 0
    });

    const endPeriod0 = period0[period - 1];
    // MTP is 0, startTime is 1000, so still DEFINED
    expect(getStateFor(endPeriod0, deployment, cache)).toBe(DeploymentState.Defined);

    // Period 1: MTP >= startTime -> STARTED
    const period1 = createBlockChain(period, {
      startHeight: period,
      startMTP: startTime,
      mtpIncrement: 600,
    });
    (period1[0] as any).prev = endPeriod0;

    const endPeriod1 = period1[period - 1];
    expect(getStateFor(endPeriod1, deployment, cache)).toBe(DeploymentState.Started);

    // Period 2: All signaling -> LOCKED_IN at end
    const period2 = createBlockChain(period, {
      startHeight: period * 2,
      startMTP: endPeriod1.medianTimePast + 600n,
      versionFn: () => VERSIONBITS_TOP_BITS | (1 << 2),
    });
    (period2[0] as any).prev = endPeriod1;

    const endPeriod2 = period2[period - 1];
    expect(getStateFor(endPeriod2, deployment, cache)).toBe(DeploymentState.LockedIn);

    // Period 3: ACTIVE
    const period3 = createBlockChain(period, {
      startHeight: period * 3,
      startMTP: endPeriod2.medianTimePast + 600n,
    });
    (period3[0] as any).prev = endPeriod2;

    const endPeriod3 = period3[period - 1];
    expect(getStateFor(endPeriod3, deployment, cache)).toBe(DeploymentState.Active);
  });

  it("should simulate a failed deployment due to timeout", () => {
    const startTime = 0n;
    const timeout = 3000n; // Timeout after some blocks in period 1
    const deployment = createDeployment({
      bit: 2,
      startTime,
      timeout,
      threshold: 1815,
    });

    const cache = new Map<string | null, DeploymentState>();

    // Create chain where MTP exceeds timeout with no signaling
    // FAILED can only be reached from STARTED state
    const blocks = createBlockChain(period * 3, {
      startMTP: 0n,
      mtpIncrement: 1, // MTP increases by 1 per block
      versionFn: () => VERSIONBITS_TOP_BITS, // No signaling
    });

    // Period 0: STARTED (MTP >= startTime = 0)
    const endPeriod0 = blocks[period - 1];
    expect(getStateFor(endPeriod0, deployment, cache)).toBe(DeploymentState.Started);

    // Period 1: FAILED (MTP 2016-4031 > timeout 3000, no threshold reached)
    const endPeriod1 = blocks[period * 2 - 1];
    expect(getStateFor(endPeriod1, deployment, cache)).toBe(DeploymentState.Failed);

    // Stays FAILED in subsequent periods
    const endPeriod2 = blocks[period * 3 - 1];
    expect(getStateFor(endPeriod2, deployment, cache)).toBe(DeploymentState.Failed);
  });

  it("should handle just-under-threshold signaling", () => {
    const justUnderThreshold = threshold - 1;
    const deployment = createDeployment({
      bit: 2,
      startTime: 0n,
      timeout: 10000000n,
      threshold,
    });

    const cache = new Map<string | null, DeploymentState>();

    // Create chain with just under threshold signaling
    const blocks = createBlockChain(period * 3, {
      startMTP: 0n,
      versionFn: (height) => {
        // Signal for first (threshold - 1) blocks in period 1
        if (height >= period && height < period + justUnderThreshold) {
          return VERSIONBITS_TOP_BITS | (1 << 2);
        }
        return VERSIONBITS_TOP_BITS;
      },
    });

    // Should remain STARTED (not locked in)
    const endPeriod2 = blocks[period * 3 - 1];
    expect(getStateFor(endPeriod2, deployment, cache)).toBe(DeploymentState.Started);
  });

  it("should handle exact-threshold signaling", () => {
    const deployment = createDeployment({
      bit: 2,
      startTime: 0n,
      timeout: 10000000n,
      threshold,
    });

    const cache = new Map<string | null, DeploymentState>();

    // Create chain with exactly threshold signaling
    const blocks = createBlockChain(period * 3, {
      startMTP: 0n,
      versionFn: (height) => {
        // Signal for exactly threshold blocks in period 1
        if (height >= period && height < period + threshold) {
          return VERSIONBITS_TOP_BITS | (1 << 2);
        }
        return VERSIONBITS_TOP_BITS;
      },
    });

    // Should be LOCKED_IN
    const endPeriod2 = blocks[period * 3 - 1];
    expect(getStateFor(endPeriod2, deployment, cache)).toBe(DeploymentState.Active);
  });
});

// ============================================================================
// W91 Bug-fix regression tests
// ============================================================================

describe("W91 Bug 1: NO_TIMEOUT must be int64_t max (2^63 - 1), not Number.MAX_SAFE_INTEGER", () => {
  /**
   * Core: src/consensus/params.h:70
   *   static constexpr int64_t NO_TIMEOUT = std::numeric_limits<int64_t>::max();
   * = 9223372036854775807n
   *
   * Old value: BigInt(Number.MAX_SAFE_INTEGER) = 9007199254740991n (2^53 - 1).
   * A chain whose MTP crossed 9007199254740991 would erroneously FAIL a deployment
   * whose timeout was intended to be "never".
   */

  it("NO_TIMEOUT must equal 9223372036854775807n (int64_t max)", () => {
    expect(NO_TIMEOUT).toBe(9223372036854775807n);
  });

  it("NO_TIMEOUT must be strictly greater than Number.MAX_SAFE_INTEGER", () => {
    expect(NO_TIMEOUT).toBeGreaterThan(BigInt(Number.MAX_SAFE_INTEGER));
  });

  it("deployment with NO_TIMEOUT must not FAIL when MTP exceeds Number.MAX_SAFE_INTEGER", () => {
    // Simulate a scenario where medianTimePast exceeds the old (wrong) NO_TIMEOUT.
    // With the old value (2^53 - 1 = 9007199254740991), the STARTED→FAILED
    // transition fires when MTP >= timeout, making a permanent deployment fail.
    const oldWrongNoTimeout = BigInt(Number.MAX_SAFE_INTEGER); // 9007199254740991n
    const deployment = createDeployment({
      bit: 2,
      startTime: 0n,
      timeout: NO_TIMEOUT, // correct value (2^63 - 1)
      threshold: 1,
    });

    const period = 2016;
    // Build a chain whose MTP is just above the old wrong NO_TIMEOUT value.
    // Each block increments MTP by 1, so after ~9007199254740991 blocks we'd cross it.
    // We cheat: manually construct a minimal 2-period chain with elevated MTP.
    const bigMTP = oldWrongNoTimeout + 100n; // above old wrong limit

    const chain: BlockIndex[] = [];
    let prev: BlockIndex | null = null;
    // We only need 2 * period blocks to exercise the STARTED→LOCKED_IN path.
    for (let i = 0; i < period * 2; i++) {
      const block: BlockIndex = {
        hash: `h_${i}`,
        height: i,
        version: VERSIONBITS_TOP_BITS | (1 << 2), // all signal
        medianTimePast: bigMTP + BigInt(i),
        prev,
      };
      chain.push(block);
      prev = block;
    }

    const cache = new Map<string | null, DeploymentState>();
    // With startTime=0 and MTP >> 0, period 0 should be STARTED (not DEFINED).
    // All blocks signal, so period 1 should LOCK_IN.
    // If NO_TIMEOUT were still the old value (9007199254740991), the chain's MTP
    // (> 9007199254740991) would trigger FAILED during the STARTED count loop.
    const endPeriod1 = chain[period * 2 - 1];
    const state = getStateFor(endPeriod1, deployment, cache);
    // Must be LOCKED_IN or ACTIVE, NOT FAILED.
    expect(state).not.toBe(DeploymentState.Failed);
    expect([DeploymentState.LockedIn, DeploymentState.Active]).toContain(state);
  });
});

describe("W91 Bug 2: MAINNET_THRESHOLD_DEFAULT must be 1916 (95%), not 1815 (90%)", () => {
  /**
   * Core: src/consensus/params.h:67
   *   uint32_t threshold{1916};   // default BIP9 threshold = 95%
   *
   * Old code used MAINNET_THRESHOLD (1815, 90%) as the default in createDeployment().
   * Any deployment relying on the default would get a lower threshold than Core.
   */

  it("MAINNET_THRESHOLD_DEFAULT must be 1916", () => {
    expect(MAINNET_THRESHOLD_DEFAULT).toBe(1916);
  });

  it("MAINNET_THRESHOLD (taproot-specific) must remain 1815", () => {
    expect(MAINNET_THRESHOLD).toBe(1815);
  });

  it("createDeployment() default threshold is 1916 (Core BIP9 default)", () => {
    const dep = createDeployment({ bit: 3, startTime: 0n, timeout: NO_TIMEOUT });
    expect(dep.threshold).toBe(1916);
  });

  it("explicit threshold=1815 is preserved (taproot case)", () => {
    const dep = createDeployment({ bit: 2, startTime: 0n, timeout: NO_TIMEOUT, threshold: 1815 });
    expect(dep.threshold).toBe(1815);
  });

  it("deployment with default threshold requires 1916 signals (not 1815) to lock in", () => {
    // Under the old default (1815), 1816 signals would lock in.
    // Under the correct default (1916), 1816 signals would NOT lock in.
    const period = 2016;
    const deployment = createDeployment({
      bit: 3,
      startTime: 0n,
      timeout: NO_TIMEOUT,
      // Intentionally no threshold — should default to 1916
    });

    expect(deployment.threshold).toBe(1916); // guard

    const signalingCount = 1816; // between old (1815) and new (1916) thresholds
    const cache = new Map<string | null, DeploymentState>();
    const blocks = createBlockChain(period * 3, {
      startMTP: 0n,
      versionFn: (height) => {
        // Signal for exactly 1816 blocks in period 1 (2016..3831)
        if (height >= period && height < period + signalingCount) {
          return VERSIONBITS_TOP_BITS | (1 << 3);
        }
        return VERSIONBITS_TOP_BITS;
      },
    });

    const endPeriod1 = blocks[period * 2 - 1];
    // With threshold=1916, 1816 signals are NOT enough — stays STARTED.
    expect(getStateFor(endPeriod1, deployment, cache)).toBe(DeploymentState.Started);
  });

  it("deployment with default threshold locks in at exactly 1916 signals", () => {
    const period = 2016;
    const deployment = createDeployment({
      bit: 3,
      startTime: 0n,
      timeout: NO_TIMEOUT,
    });

    const signalingCount = 1916;
    const cache = new Map<string | null, DeploymentState>();
    const blocks = createBlockChain(period * 3, {
      startMTP: 0n,
      versionFn: (height) => {
        if (height >= period && height < period + signalingCount) {
          return VERSIONBITS_TOP_BITS | (1 << 3);
        }
        return VERSIONBITS_TOP_BITS;
      },
    });

    const endPeriod1 = blocks[period * 2 - 1];
    expect(getStateFor(endPeriod1, deployment, cache)).toBe(DeploymentState.LockedIn);
  });
});

describe("W91 Bug 3: computeBlockVersion must set signal bits for STARTED/LOCKED_IN deployments", () => {
  /**
   * Core: versionbits.cpp:265-279 ComputeBlockVersion
   *   for each deployment: if (STARTED || LOCKED_IN) nVersion |= Mask()
   *
   * Old code hardcoded version = 0x20000000 in template.ts and server.ts,
   * never actually signalling for any active BIP9 deployment.
   */

  it("computeBlockVersion sets bit for STARTED deployment", () => {
    const period = 2016;
    const bit = 4;
    const deployments = new Map<string, DeploymentParams>([
      ["testbit", createDeployment({ bit, startTime: 0n, timeout: NO_TIMEOUT })],
    ]);

    const cache = new VersionBitsCache();
    // Create a chain that is in STARTED state at end of period 0
    const blocks = createBlockChain(period * 2, {
      startMTP: 0n,
    });

    // pindexPrev = last block of period 0 → deployments are STARTED in period 1
    const version = cache.computeBlockVersion(blocks[period - 1], deployments);

    expect(version & (1 << bit)).not.toBe(0);
    expect(version & 0xe0000000).toBe(0x20000000); // top bits still 001
  });

  it("computeBlockVersion sets bit for LOCKED_IN deployment", () => {
    const period = 2016;
    const bit = 6;
    const deployments = new Map<string, DeploymentParams>([
      ["testbit", createDeployment({ bit, startTime: 0n, timeout: NO_TIMEOUT, threshold: 1916 })],
    ]);

    const cache = new VersionBitsCache();
    // All blocks signal → LOCKED_IN after period 1
    const blocks = createBlockChain(period * 3, {
      startMTP: 0n,
      versionFn: () => VERSIONBITS_TOP_BITS | (1 << bit),
    });

    // Period 1 end = blocks[period*2 - 1]; state at start of period 2 = LOCKED_IN
    const version = cache.computeBlockVersion(blocks[period * 2 - 1], deployments);
    expect(version & (1 << bit)).not.toBe(0);
  });

  it("computeBlockVersion does NOT set bit for ACTIVE deployment", () => {
    const bit = 7;
    const deployments = new Map<string, DeploymentParams>([
      ["always", createDeployment({ bit, startTime: ALWAYS_ACTIVE, timeout: NO_TIMEOUT })],
    ]);

    const cache = new VersionBitsCache();
    const version = cache.computeBlockVersion(null, deployments);

    // ALWAYS_ACTIVE → ACTIVE immediately; ACTIVE does NOT set a signal bit
    expect(version & (1 << bit)).toBe(0);
    expect(version).toBe(0x20000000); // only top bits
  });

  it("computeBlockVersion does NOT set bit for FAILED deployment", () => {
    const bit = 8;
    const deployments = new Map<string, DeploymentParams>([
      ["never", createDeployment({ bit, startTime: NEVER_ACTIVE, timeout: NO_TIMEOUT })],
    ]);

    const cache = new VersionBitsCache();
    const version = cache.computeBlockVersion(null, deployments);

    expect(version & (1 << bit)).toBe(0);
    expect(version).toBe(0x20000000);
  });

  it("computeBlockVersion does NOT set bit for DEFINED deployment", () => {
    const bit = 9;
    const deployments = new Map<string, DeploymentParams>([
      ["future", createDeployment({ bit, startTime: 9999999999n, timeout: NO_TIMEOUT })],
    ]);

    const cache = new VersionBitsCache();
    // Small chain, MTP well below startTime
    const blocks = createBlockChain(100, { startMTP: 0n });
    const version = cache.computeBlockVersion(tip(blocks), deployments);

    expect(version & (1 << bit)).toBe(0);
    expect(version).toBe(0x20000000);
  });

  it("computeBlockVersion sets bits for multiple simultaneously-STARTED deployments", () => {
    const deployments = new Map<string, DeploymentParams>([
      ["a", createDeployment({ bit: 1, startTime: 0n, timeout: NO_TIMEOUT })],
      ["b", createDeployment({ bit: 5, startTime: 0n, timeout: NO_TIMEOUT })],
      ["c", createDeployment({ bit: 12, startTime: 0n, timeout: NO_TIMEOUT })],
    ]);

    const cache = new VersionBitsCache();
    const blocks = createBlockChain(2016 * 2, { startMTP: 0n });
    const version = cache.computeBlockVersion(tip(blocks), deployments);

    expect(version & (1 << 1)).not.toBe(0);
    expect(version & (1 << 5)).not.toBe(0);
    expect(version & (1 << 12)).not.toBe(0);
    expect(version & 0xe0000000).toBe(0x20000000);
  });
});

describe("W91 Bug 3b: buildBlockIndex correctly maps HeaderInfo to BlockIndex", () => {
  /**
   * buildBlockIndex is the bridge used by computeNextBlockVersion() in server.ts and
   * by BlockTemplateBuilder when wired with getHeaderByHeight.
   */

  it("wraps a single block correctly", () => {
    const info: HeaderInfo = {
      hash: Buffer.from("aa".repeat(32), "hex"),
      height: 0,
      version: 0x20000000 | (1 << 3),
      medianTimePast: 1000,
    };

    const idx = buildBlockIndex(info, () => undefined);

    expect(idx.hash).toBe(info.hash.toString("hex"));
    expect(idx.height).toBe(0);
    expect(idx.version).toBe(info.version);
    expect(idx.medianTimePast).toBe(1000n);
    expect(idx.prev).toBeNull(); // height 0 has no parent
  });

  it("lazily links parent via getHeader callback", () => {
    const parentInfo: HeaderInfo = {
      hash: Buffer.from("bb".repeat(32), "hex"),
      height: 0,
      version: 0x20000000,
      medianTimePast: 500,
    };
    const childInfo: HeaderInfo = {
      hash: Buffer.from("cc".repeat(32), "hex"),
      height: 1,
      version: 0x20000000,
      medianTimePast: 1000,
    };

    const lookup = (h: number): HeaderInfo | undefined =>
      h === 0 ? parentInfo : h === 1 ? childInfo : undefined;

    const child = buildBlockIndex(childInfo, lookup);

    expect(child.prev).not.toBeNull();
    expect(child.prev!.height).toBe(0);
    expect(child.prev!.medianTimePast).toBe(500n);
    expect(child.prev!.prev).toBeNull(); // genesis has no parent
  });

  it("returns null for prev when parent lookup returns undefined", () => {
    const info: HeaderInfo = {
      hash: Buffer.from("dd".repeat(32), "hex"),
      height: 5,
      version: 0x20000000,
      medianTimePast: 3000,
    };

    // Lookup always returns undefined
    const idx = buildBlockIndex(info, () => undefined);
    expect(idx.prev).toBeNull();
  });

  it("feeds into getStateFor correctly", () => {
    // Build a small HeaderInfo-backed chain and verify state machine output
    const period = 2016;
    const headers: HeaderInfo[] = [];
    for (let i = 0; i < period * 2; i++) {
      headers.push({
        hash: Buffer.from(i.toString(16).padStart(64, "0"), "hex"),
        height: i,
        version: VERSIONBITS_TOP_BITS | (1 << 5), // always signal bit 5
        medianTimePast: i * 600,
      });
    }

    const lookup = (h: number): HeaderInfo | undefined => headers[h];
    const tip = buildBlockIndex(headers[period * 2 - 1], lookup);

    const deployment = createDeployment({ bit: 5, startTime: 0n, timeout: NO_TIMEOUT });
    const cache = new Map<string | null, DeploymentState>();

    const state = getStateFor(tip, deployment, cache);
    // All blocks signal; period 0 = STARTED, period 1 = LOCKED_IN
    expect(state).toBe(DeploymentState.LockedIn);
  });
});
