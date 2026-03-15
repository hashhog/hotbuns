/**
 * BIP9 Version Bits Soft Fork Deployment State Machine
 *
 * Implements the versionbits state machine for soft fork activation:
 * DEFINED -> STARTED -> LOCKED_IN -> ACTIVE (or FAILED)
 *
 * State transitions occur at retarget boundaries (every 2016 blocks).
 * During STARTED, blocks signal by setting their version bit.
 * If threshold is met, deployment locks in and activates after one more period.
 *
 * Reference: Bitcoin Core versionbits.cpp, versionbits_impl.h
 */

/**
 * BIP9 deployment states.
 */
export enum DeploymentState {
  /** First state - deployment not yet started */
  Defined = "defined",
  /** Signaling has begun, miners can vote */
  Started = "started",
  /** Threshold reached, will activate after one period */
  LockedIn = "locked_in",
  /** Deployment is active (final state) */
  Active = "active",
  /** Timeout reached without lock-in (final state) */
  Failed = "failed",
}

/**
 * Version bits constants from Bitcoin Core versionbits.h
 */
export const VERSIONBITS_TOP_BITS = 0x20000000;
export const VERSIONBITS_TOP_MASK = 0xe0000000;
export const VERSIONBITS_NUM_BITS = 29;
export const VERSIONBITS_LAST_OLD_BLOCK_VERSION = 4;

/**
 * Special values for deployment timing.
 */
export const ALWAYS_ACTIVE = -1n;
export const NEVER_ACTIVE = -2n;
export const NO_TIMEOUT = BigInt(Number.MAX_SAFE_INTEGER);

/**
 * Parameters for a single BIP9 deployment.
 */
export interface DeploymentParams {
  /** Bit position to signal (0-28) */
  readonly bit: number;
  /** Start time (MTP) for signaling, or ALWAYS_ACTIVE/NEVER_ACTIVE */
  readonly startTime: bigint;
  /** Timeout (MTP) for deployment attempt */
  readonly timeout: bigint;
  /** Minimum activation height (delays activation even after lock-in) */
  readonly minActivationHeight: number;
  /** Period for counting signals (default: 2016) */
  readonly period: number;
  /** Threshold for lock-in (default: 1815 for mainnet, 1512 for testnet) */
  readonly threshold: number;
}

/**
 * Block index entry for state computation.
 * Minimal interface matching what's needed for versionbits logic.
 */
export interface BlockIndex {
  /** Block hash as hex string (used as cache key) */
  readonly hash: string;
  /** Block height */
  readonly height: number;
  /** Block version (contains signaling bits) */
  readonly version: number;
  /** Median time past of this block */
  readonly medianTimePast: bigint;
  /** Previous block index, or null for genesis */
  readonly prev: BlockIndex | null;
}

/**
 * Statistics for an in-progress BIP9 deployment.
 */
export interface BIP9Stats {
  /** Length of the signaling period */
  readonly period: number;
  /** Number of blocks needed for activation */
  readonly threshold: number;
  /** Number of blocks elapsed in current period */
  readonly elapsed: number;
  /** Number of signaling blocks in current period */
  readonly count: number;
  /** Whether activation is still possible this period */
  readonly possible: boolean;
}

/**
 * Cache key for deployment state computations.
 * Maps block hash to computed state.
 */
type StateCache = Map<string | null, DeploymentState>;

/**
 * BIP9 Version Bits State Machine
 *
 * Tracks deployment states and caches computations for efficiency.
 * Each deployment has its own cache to avoid cross-contamination.
 */
export class VersionBitsCache {
  /** Per-deployment state caches */
  private readonly caches: Map<string, StateCache> = new Map();

  /**
   * Clear all cached state.
   */
  clear(): void {
    this.caches.clear();
  }

  /**
   * Get or create a cache for a specific deployment.
   */
  private getCache(deploymentName: string): StateCache {
    let cache = this.caches.get(deploymentName);
    if (!cache) {
      cache = new Map();
      this.caches.set(deploymentName, cache);
    }
    return cache;
  }

  /**
   * Get the deployment state for a block.
   *
   * @param pindexPrev - Parent of the block we're computing state for
   * @param deployment - Deployment parameters
   * @param deploymentName - Unique name for caching
   * @returns Deployment state
   */
  getState(
    pindexPrev: BlockIndex | null,
    deployment: DeploymentParams,
    deploymentName: string
  ): DeploymentState {
    const cache = this.getCache(deploymentName);
    return getStateFor(pindexPrev, deployment, cache);
  }

  /**
   * Get deployment statistics for the current period.
   *
   * @param pindex - Block to get stats for
   * @param deployment - Deployment parameters
   * @returns BIP9 statistics
   */
  getStats(pindex: BlockIndex | null, deployment: DeploymentParams): BIP9Stats {
    return getStateStatistics(pindex, deployment);
  }

  /**
   * Check if a deployment is active after a given block.
   *
   * @param pindexPrev - Parent of the block to check
   * @param deployment - Deployment parameters
   * @param deploymentName - Unique name for caching
   * @returns true if deployment is active
   */
  isActiveAfter(
    pindexPrev: BlockIndex | null,
    deployment: DeploymentParams,
    deploymentName: string
  ): boolean {
    return this.getState(pindexPrev, deployment, deploymentName) === DeploymentState.Active;
  }

  /**
   * Compute the block version for a new block, setting appropriate signal bits.
   *
   * @param pindexPrev - Parent of the new block
   * @param deployments - Map of deployment name to params
   * @returns Block version with signal bits set
   */
  computeBlockVersion(
    pindexPrev: BlockIndex | null,
    deployments: Map<string, DeploymentParams>
  ): number {
    let version = VERSIONBITS_TOP_BITS;

    for (const [name, deployment] of deployments) {
      const state = this.getState(pindexPrev, deployment, name);
      // Signal during STARTED and LOCKED_IN states
      if (state === DeploymentState.Started || state === DeploymentState.LockedIn) {
        version |= (1 << deployment.bit);
      }
    }

    return version;
  }

  /**
   * Get the height at which the current state began.
   *
   * @param pindexPrev - Parent of the block to check
   * @param deployment - Deployment parameters
   * @param deploymentName - Unique name for caching
   * @returns Height at which current state started
   */
  getStateSinceHeight(
    pindexPrev: BlockIndex | null,
    deployment: DeploymentParams,
    deploymentName: string
  ): number {
    const cache = this.getCache(deploymentName);
    return getStateSinceHeight(pindexPrev, deployment, cache);
  }
}

/**
 * Get the last block of the previous retarget period.
 *
 * In Bitcoin Core, state is computed based on a pindexPrev whose height
 * equals a multiple of nPeriod - 1. This is the last block of the previous
 * complete period, which serves as the basis for state computation.
 *
 * For pindexPrev at height H, we find ancestor at:
 *   height = H - ((H + 1) % period)
 *
 * This gives us the block at the end of the previous period.
 * Returns null for the genesis period.
 */
function getPeriodStart(
  pindexPrev: BlockIndex | null,
  period: number
): BlockIndex | null {
  if (pindexPrev === null) {
    return null;
  }

  // Walk back to the last block of the previous complete period
  // For height H, we want: H - ((H + 1) % period)
  const targetHeight = pindexPrev.height - ((pindexPrev.height + 1) % period);

  let current: BlockIndex | null = pindexPrev;
  while (current !== null && current.height > targetHeight) {
    current = current.prev;
  }

  return current;
}

/**
 * Get ancestor at a specific height.
 */
function getAncestor(pindex: BlockIndex | null, height: number): BlockIndex | null {
  if (pindex === null || height < 0) {
    return null;
  }

  let current: BlockIndex | null = pindex;
  while (current !== null && current.height > height) {
    current = current.prev;
  }

  return current?.height === height ? current : null;
}

/**
 * Check if a block version signals for a deployment.
 *
 * The version must have:
 * 1. Top 3 bits set to 001 (VERSIONBITS_TOP_BITS)
 * 2. The deployment's bit set
 */
export function versionSignals(version: number, bit: number): boolean {
  // Check top bits are 001xxxxx...
  if ((version & VERSIONBITS_TOP_MASK) !== VERSIONBITS_TOP_BITS) {
    return false;
  }
  // Check signal bit is set
  return (version & (1 << bit)) !== 0;
}

/**
 * Compute the deployment state for a block.
 *
 * This is the core BIP9 state machine implementation.
 * State is computed based on the parent block (pindexPrev).
 *
 * @param pindexPrev - Parent of the block to compute state for
 * @param deployment - Deployment parameters
 * @param cache - State cache to avoid recomputation
 * @returns Deployment state
 */
export function getStateFor(
  pindexPrev: BlockIndex | null,
  deployment: DeploymentParams,
  cache: StateCache
): DeploymentState {
  const { bit, startTime, timeout, minActivationHeight, period, threshold } = deployment;

  // Handle always/never active deployments
  if (startTime === ALWAYS_ACTIVE) {
    return DeploymentState.Active;
  }
  if (startTime === NEVER_ACTIVE) {
    return DeploymentState.Failed;
  }

  // Find the first block of this period
  // A block's state is the same as the first block of its period
  const periodStart = getPeriodStart(pindexPrev, period);

  // Walk backwards to find cached state
  const toCompute: BlockIndex[] = [];
  let current = periodStart;

  while (!cache.has(current?.hash ?? null)) {
    if (current === null) {
      // Genesis block is by definition DEFINED
      cache.set(null, DeploymentState.Defined);
      break;
    }

    // Optimization: if MTP is before start time, state is DEFINED
    if (current.medianTimePast < startTime) {
      cache.set(current.hash, DeploymentState.Defined);
      break;
    }

    toCompute.push(current);
    // Go back one period
    current = getAncestor(current, current.height - period);
  }

  // Get the known state
  let state = cache.get(current?.hash ?? null)!;

  // Walk forward computing states
  while (toCompute.length > 0) {
    const pindex = toCompute.pop()!;
    let nextState = state;

    switch (state) {
      case DeploymentState.Defined: {
        // Transition to STARTED when MTP passes start time
        if (pindex.medianTimePast >= startTime) {
          nextState = DeploymentState.Started;
        }
        break;
      }

      case DeploymentState.Started: {
        // Count signaling blocks in this period
        let count = 0;
        let countBlock: BlockIndex | null = pindex;

        for (let i = 0; i < period && countBlock !== null; i++) {
          if (versionSignals(countBlock.version, bit)) {
            count++;
          }
          countBlock = countBlock.prev;
        }

        if (count >= threshold) {
          // Threshold met, lock in
          nextState = DeploymentState.LockedIn;
        } else if (pindex.medianTimePast >= timeout) {
          // Timeout reached without lock-in
          nextState = DeploymentState.Failed;
        }
        break;
      }

      case DeploymentState.LockedIn: {
        // Progress to ACTIVE if activation height is reached
        // pindex.height + 1 is the height of the next block (first of next period)
        if (pindex.height + 1 >= minActivationHeight) {
          nextState = DeploymentState.Active;
        }
        break;
      }

      case DeploymentState.Failed:
      case DeploymentState.Active: {
        // Terminal states - no transition
        break;
      }
    }

    cache.set(pindex.hash, nextState);
    state = nextState;
  }

  return state;
}

/**
 * Get statistics for an in-progress deployment.
 *
 * @param pindex - Block to get stats for
 * @param deployment - Deployment parameters
 * @returns BIP9 statistics for the current period
 */
export function getStateStatistics(
  pindex: BlockIndex | null,
  deployment: DeploymentParams
): BIP9Stats {
  const { bit, period, threshold } = deployment;

  if (pindex === null) {
    return {
      period,
      threshold,
      elapsed: 0,
      count: 0,
      possible: false,
    };
  }

  // Find how many blocks are in the current period
  const blocksInPeriod = 1 + (pindex.height % period);

  // Count signaling blocks from current back to start of period
  let elapsed = 0;
  let count = 0;
  let currentBlock: BlockIndex | null = pindex;

  for (let i = 0; i < blocksInPeriod && currentBlock !== null; i++) {
    elapsed++;
    if (versionSignals(currentBlock.version, bit)) {
      count++;
    }
    currentBlock = currentBlock.prev;
  }

  // Is it still possible to reach threshold?
  const remaining = period - elapsed;
  const needed = threshold - count;
  const possible = needed <= remaining;

  return {
    period,
    threshold,
    elapsed,
    count,
    possible,
  };
}

/**
 * Get the height at which the current state began.
 *
 * @param pindexPrev - Parent of the block to check
 * @param deployment - Deployment parameters
 * @param cache - State cache
 * @returns Height at which current state started
 */
export function getStateSinceHeight(
  pindexPrev: BlockIndex | null,
  deployment: DeploymentParams,
  cache: StateCache
): number {
  const { startTime, period } = deployment;

  // Always/never active start from genesis
  if (startTime === ALWAYS_ACTIVE || startTime === NEVER_ACTIVE) {
    return 0;
  }

  const initialState = getStateFor(pindexPrev, deployment, cache);

  // DEFINED state starts from genesis
  if (initialState === DeploymentState.Defined) {
    return 0;
  }

  // Find the period start
  let periodStart = getPeriodStart(pindexPrev, period);
  if (periodStart === null) {
    return 0;
  }

  // Walk backwards to find when state changed
  let previousPeriodParent = getAncestor(periodStart, periodStart.height - period);

  while (
    previousPeriodParent !== null &&
    getStateFor(previousPeriodParent, deployment, cache) === initialState
  ) {
    periodStart = previousPeriodParent;
    previousPeriodParent = getAncestor(periodStart, periodStart.height - period);
  }

  // Return height + 1 (first block of the period with this state)
  return periodStart.height + 1;
}

/**
 * Default mainnet deployment thresholds.
 */
export const MAINNET_THRESHOLD = 1815; // 90% of 2016
export const TESTNET_THRESHOLD = 1512; // 75% of 2016

/**
 * Create deployment parameters with defaults.
 */
export function createDeployment(params: {
  bit: number;
  startTime: bigint;
  timeout: bigint;
  minActivationHeight?: number;
  period?: number;
  threshold?: number;
}): DeploymentParams {
  return {
    bit: params.bit,
    startTime: params.startTime,
    timeout: params.timeout,
    minActivationHeight: params.minActivationHeight ?? 0,
    period: params.period ?? 2016,
    threshold: params.threshold ?? MAINNET_THRESHOLD,
  };
}

/**
 * Known mainnet deployments with activation parameters.
 */
export const MAINNET_DEPLOYMENTS: Map<string, DeploymentParams> = new Map([
  // Taproot (BIP 341/342) - already active on mainnet
  [
    "taproot",
    createDeployment({
      bit: 2,
      startTime: 1619222400n, // April 24, 2021
      timeout: 1628640000n, // August 11, 2021
      minActivationHeight: 709632,
      threshold: 1815,
    }),
  ],
]);

/**
 * Testnet4 deployments - all active from genesis.
 */
export const TESTNET4_DEPLOYMENTS: Map<string, DeploymentParams> = new Map([
  [
    "taproot",
    createDeployment({
      bit: 2,
      startTime: ALWAYS_ACTIVE,
      timeout: NO_TIMEOUT,
    }),
  ],
]);

/**
 * Regtest deployments - all active from genesis.
 */
export const REGTEST_DEPLOYMENTS: Map<string, DeploymentParams> = new Map([
  [
    "taproot",
    createDeployment({
      bit: 2,
      startTime: ALWAYS_ACTIVE,
      timeout: NO_TIMEOUT,
    }),
  ],
]);
