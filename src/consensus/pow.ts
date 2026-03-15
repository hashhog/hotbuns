/**
 * Proof-of-work and difficulty adjustment.
 *
 * Implements Bitcoin's difficulty adjustment algorithm including:
 * - Mainnet: standard 2016-block retargeting
 * - Testnet3: 20-minute min-difficulty rule with walk-back
 * - Testnet4/BIP94: improved retargeting using first block of period
 * - Regtest: always minimum difficulty
 *
 * Reference: Bitcoin Core pow.cpp
 */

import {
  type ConsensusParams,
  compactToBigInt,
  bigIntToCompact,
} from "./params.js";

/**
 * Minimal block header interface for difficulty calculations.
 */
export interface DifficultyBlockHeader {
  readonly timestamp: number;
  readonly bits: number;
}

/**
 * Block info needed for difficulty adjustment.
 */
export interface BlockInfo {
  readonly height: number;
  readonly header: DifficultyBlockHeader;
}

/**
 * Function to retrieve a block by height, used for walk-back.
 */
export type BlockLookup = (height: number) => BlockInfo | undefined;

/**
 * Calculate the next required work target for a block.
 *
 * This is the main entry point for difficulty adjustment, implementing
 * all network-specific rules:
 * - Mainnet: retarget every 2016 blocks
 * - Testnet: 20-minute min-diff rule with walk-back
 * - Testnet4: BIP94 improved retargeting
 * - Regtest: always minimum difficulty
 *
 * @param parent - The parent block
 * @param blockTimestamp - Timestamp of the new block being validated
 * @param params - Network consensus parameters
 * @param getBlockByHeight - Function to look up blocks by height
 * @returns The required target as a bigint
 */
export function getNextWorkRequired(
  parent: BlockInfo,
  blockTimestamp: number,
  params: ConsensusParams,
  getBlockByHeight: BlockLookup
): bigint {
  const height = parent.height + 1;
  const interval = params.difficultyAdjustmentInterval;
  const powLimit = params.powLimit;
  const powLimitBits = params.powLimitBits;

  // Regtest: no retargeting, always return powLimit (if enabled)
  if (params.fPowNoRetargeting) {
    return powLimit;
  }

  // Non-adjustment block
  if (height % interval !== 0) {
    // Testnet/regtest special rules
    if (params.fPowAllowMinDifficultyBlocks) {
      // If the new block's timestamp is more than 2 * targetSpacing (20 min)
      // after the previous block, allow minimum difficulty
      const twiceTargetSpacing = params.targetSpacing * 2;
      if (blockTimestamp > parent.header.timestamp + twiceTargetSpacing) {
        return powLimit;
      }

      // Otherwise, return the last non-min-difficulty block's target
      // Walk back to find a block that doesn't have minimum difficulty
      let walkHeight = parent.height;
      let walkBits = parent.header.bits;

      while (
        walkHeight > 0 &&
        walkHeight % interval !== 0 &&
        walkBits === powLimitBits
      ) {
        const prevBlock = getBlockByHeight(walkHeight - 1);
        if (!prevBlock) {
          break;
        }
        walkHeight = prevBlock.height;
        walkBits = prevBlock.header.bits;
      }

      return compactToBigInt(walkBits);
    }

    // Mainnet: non-adjustment block uses parent's difficulty
    return compactToBigInt(parent.header.bits);
  }

  // Adjustment block: find first block of this difficulty period
  const firstHeight = height - interval;
  const firstBlock = getBlockByHeight(firstHeight);

  if (!firstBlock) {
    // Shouldn't happen if chain is consistent
    return compactToBigInt(parent.header.bits);
  }

  return calculateNextWorkRequired(
    parent,
    firstBlock.header.timestamp,
    params,
    getBlockByHeight
  );
}

/**
 * Calculate the new target for a difficulty adjustment block.
 *
 * This implements the core retargeting formula:
 *   new_target = old_target * actual_timespan / target_timespan
 *
 * With clamping to [targetTimespan/4, targetTimespan*4].
 *
 * @param parent - The parent block (last block of current period)
 * @param firstBlockTime - Timestamp of first block in current period
 * @param params - Network consensus parameters
 * @param getBlockByHeight - Function to look up blocks by height (for BIP94)
 * @returns The new target as a bigint
 */
export function calculateNextWorkRequired(
  parent: BlockInfo,
  firstBlockTime: number,
  params: ConsensusParams,
  getBlockByHeight: BlockLookup
): bigint {
  // If no retargeting, return current difficulty
  if (params.fPowNoRetargeting) {
    return compactToBigInt(parent.header.bits);
  }

  // Calculate actual timespan
  let actualTimespan = parent.header.timestamp - firstBlockTime;

  // Clamp timespan to [targetTimespan/4, targetTimespan*4]
  const targetTimespan = params.targetTimespan;
  const minTimespan = Math.floor(targetTimespan / 4);
  const maxTimespan = targetTimespan * 4;

  if (actualTimespan < minTimespan) {
    actualTimespan = minTimespan;
  }
  if (actualTimespan > maxTimespan) {
    actualTimespan = maxTimespan;
  }

  // Determine which block's difficulty to use as base
  let baseBits: number;

  if (params.enforce_BIP94) {
    // BIP94 (Testnet4): use the first block of the difficulty period
    // This preserves the real difficulty and prevents min-diff exceptions
    // from corrupting the difficulty history
    const interval = params.difficultyAdjustmentInterval;
    const firstHeight = parent.height - (interval - 1);
    const firstBlock = getBlockByHeight(firstHeight);

    if (firstBlock) {
      baseBits = firstBlock.header.bits;
    } else {
      // Fallback to parent's bits if lookup fails
      baseBits = parent.header.bits;
    }
  } else {
    // Standard behavior: use the last block of the period
    baseBits = parent.header.bits;
  }

  // Calculate new target
  const baseTarget = compactToBigInt(baseBits);
  let newTarget = (baseTarget * BigInt(actualTimespan)) / BigInt(targetTimespan);

  // Cap at powLimit
  if (newTarget > params.powLimit) {
    newTarget = params.powLimit;
  }

  return newTarget;
}

/**
 * Check that on difficulty adjustments, the new difficulty does not increase
 * or decrease beyond the permitted limits.
 *
 * @param params - Network consensus parameters
 * @param height - Block height
 * @param oldBits - Previous block's compact target
 * @param newBits - New block's compact target
 * @returns true if the transition is valid
 */
export function permittedDifficultyTransition(
  params: ConsensusParams,
  height: number,
  oldBits: number,
  newBits: number
): boolean {
  // Testnet/regtest: all transitions are permitted
  if (params.fPowAllowMinDifficultyBlocks) {
    return true;
  }

  const interval = params.difficultyAdjustmentInterval;

  if (height % interval === 0) {
    // At adjustment boundary: new target must be within [old/4, old*4]
    const targetTimespan = params.targetTimespan;
    const smallestTimespan = Math.floor(targetTimespan / 4);
    const largestTimespan = targetTimespan * 4;

    const powLimit = params.powLimit;
    const observedNewTarget = compactToBigInt(newBits);

    // Calculate largest allowed difficulty (easiest - multiply by largest timespan)
    const oldTarget = compactToBigInt(oldBits);
    let largestTarget = (oldTarget * BigInt(largestTimespan)) / BigInt(targetTimespan);
    if (largestTarget > powLimit) {
      largestTarget = powLimit;
    }

    // Round via compact encoding for comparison (Bitcoin Core does this)
    const maxTargetBits = bigIntToCompact(largestTarget);
    const maxTarget = compactToBigInt(maxTargetBits);
    if (maxTarget < observedNewTarget) {
      return false;
    }

    // Calculate smallest allowed difficulty (hardest - divide by largest timespan)
    let smallestTarget = (oldTarget * BigInt(smallestTimespan)) / BigInt(targetTimespan);
    if (smallestTarget > powLimit) {
      smallestTarget = powLimit;
    }

    // Round via compact encoding for comparison
    const minTargetBits = bigIntToCompact(smallestTarget);
    const minTarget = compactToBigInt(minTargetBits);
    if (minTarget > observedNewTarget) {
      return false;
    }
  } else {
    // Non-adjustment block: bits must be identical to parent
    if (oldBits !== newBits) {
      return false;
    }
  }

  return true;
}

/**
 * Check proof of work: block hash must be <= target.
 *
 * @param hash - Block hash as a buffer (little-endian, as stored)
 * @param bits - Compact target encoding
 * @param params - Network consensus parameters
 * @returns true if proof of work is valid
 */
export function checkProofOfWork(
  hash: Buffer,
  bits: number,
  params: ConsensusParams
): boolean {
  // Derive target and validate
  const target = deriveTarget(bits, params.powLimit);
  if (target === null) {
    return false;
  }

  // Convert hash to big-endian number for comparison
  const hashReversed = Buffer.from(hash).reverse();
  const hashValue = BigInt("0x" + hashReversed.toString("hex"));

  // Check proof of work matches claimed amount
  return hashValue <= target;
}

/**
 * Derive the target from compact encoding, validating it's within range.
 *
 * @param bits - Compact target encoding
 * @param powLimit - Network's maximum target
 * @returns The target or null if invalid
 */
export function deriveTarget(bits: number, powLimit: bigint): bigint | null {
  const target = compactToBigInt(bits);

  // Check for negative (handled by compactToBigInt returning 0) or zero target
  if (target === 0n) {
    return null;
  }

  // Check target doesn't exceed powLimit
  if (target > powLimit) {
    return null;
  }

  return target;
}

/**
 * Calculate chain work added by a header with given target bits.
 * Work = 2^256 / (target + 1)
 *
 * @param bits - Compact target encoding
 * @returns Chain work as bigint
 */
export function getBlockWork(bits: number): bigint {
  const target = compactToBigInt(bits);
  if (target <= 0n) {
    return 0n;
  }
  const TWO_256 = 2n ** 256n;
  return TWO_256 / (target + 1n);
}
