/**
 * BIP133 feefilter implementation.
 *
 * Peers announce their minimum fee rate, and senders skip relaying
 * transactions below that threshold. Includes Poisson-delayed sending
 * and hysteresis to avoid bandwidth waste.
 *
 * Reference: Bitcoin Core net_processing.cpp MaybeSendFeefilter()
 */

import type { Peer } from "./peer.js";
import type { NetworkMessage } from "./messages.js";

/**
 * Average delay between feefilter broadcasts (10 minutes).
 * Reference: Bitcoin Core AVG_FEEFILTER_BROADCAST_INTERVAL
 */
export const AVG_FEEFILTER_BROADCAST_INTERVAL_MS = 10 * 60 * 1000;

/**
 * Maximum feefilter broadcast delay after significant change (5 minutes).
 * Reference: Bitcoin Core MAX_FEEFILTER_CHANGE_DELAY
 */
export const MAX_FEEFILTER_CHANGE_DELAY_MS = 5 * 60 * 1000;

/**
 * Default minimum relay fee rate (1000 sat/kvB = 1 sat/vB).
 */
export const DEFAULT_MIN_RELAY_FEE_RATE = 1000n;

/**
 * Default incremental relay fee rate (1000 sat/kvB = 1 sat/vB).
 * For RBF, new fee must exceed old by at least this * newVsize.
 */
export const DEFAULT_INCREMENTAL_RELAY_FEE = 1000n;

/**
 * Maximum money value (used during IBD to tell peers not to send txs).
 */
export const MAX_MONEY = 2_100_000_000_000_000n; // 21M BTC in satoshis

/**
 * Minimum protocol version that supports feefilter (BIP 133).
 * All peers >= 70013 support feefilter.
 */
export const FEEFILTER_VERSION = 70013;

/**
 * FeeFilterManager handles BIP133 feefilter protocol:
 * - Tracks per-peer received feefilters
 * - Broadcasts our feefilter to peers with Poisson delays
 * - Applies hysteresis to avoid excessive updates
 */
export class FeeFilterManager {
  /** Current minimum fee rate (sat/kvB) to announce to peers. */
  private currentFeeRate: bigint;

  /** Callback to send a feefilter message to a peer. */
  private sendFeeFilter: (peer: Peer, feeRate: bigint) => void;

  /** Whether we're in initial block download (affects fee rate). */
  private inIBD: boolean;

  constructor(sendFeeFilter: (peer: Peer, feeRate: bigint) => void) {
    this.sendFeeFilter = sendFeeFilter;
    this.currentFeeRate = DEFAULT_MIN_RELAY_FEE_RATE;
    this.inIBD = false;
  }

  /**
   * Set whether we're in initial block download.
   * During IBD, we send MAX_MONEY as feefilter to tell peers not to send txs.
   */
  setInIBD(inIBD: boolean): void {
    this.inIBD = inIBD;
  }

  /**
   * Update our current minimum fee rate (from mempool).
   * @param feeRate - Fee rate in sat/kvB
   */
  setMinFeeRate(feeRate: bigint): void {
    // Ensure minimum is at least the default relay fee
    this.currentFeeRate = feeRate > DEFAULT_MIN_RELAY_FEE_RATE
      ? feeRate
      : DEFAULT_MIN_RELAY_FEE_RATE;
  }

  /**
   * Get the fee rate to announce to peers.
   * Returns MAX_MONEY during IBD to suppress tx relay.
   */
  getFeeRateToAnnounce(): bigint {
    if (this.inIBD) {
      return MAX_MONEY;
    }
    return this.currentFeeRate;
  }

  /**
   * Handle received feefilter message from a peer.
   * @param peer - The peer that sent the feefilter
   * @param feeRate - The fee rate from the feefilter message (sat/kvB)
   */
  handleFeeFilter(peer: Peer, feeRate: bigint): void {
    // Validate range (must be non-negative and within money range)
    if (feeRate < 0n || feeRate > MAX_MONEY) {
      return; // Invalid fee filter, ignore
    }
    peer.feeFilterReceived = feeRate;
  }

  /**
   * Maybe send a feefilter update to a peer.
   * Uses Poisson-delayed sending and hysteresis.
   *
   * @param peer - The peer to potentially send to
   * @param now - Current timestamp (ms)
   * @param isBlockRelayOnly - Whether this is a block-relay-only peer
   */
  maybeSendFeeFilter(peer: Peer, now: number, isBlockRelayOnly: boolean): void {
    // Don't send feefilter to block-relay-only peers
    if (isBlockRelayOnly) {
      return;
    }

    const filterToSend = this.getFeeRateToAnnounce();

    // Check if it's time to send
    if (now >= peer.nextFeeFilterSend) {
      // Only send if the value has changed
      if (filterToSend !== peer.feeFilterSent) {
        this.sendFeeFilter(peer, filterToSend);
        peer.feeFilterSent = filterToSend;
      }

      // Schedule next send with Poisson delay
      peer.nextFeeFilterSend = now + poissonDelay(AVG_FEEFILTER_BROADCAST_INTERVAL_MS);
    }
    // If fee filter changed substantially and we're not due to send soon,
    // move the broadcast earlier
    else if (
      peer.nextFeeFilterSend > now + MAX_FEEFILTER_CHANGE_DELAY_MS &&
      this.hasSubstantialChange(filterToSend, peer.feeFilterSent)
    ) {
      // Schedule within MAX_FEEFILTER_CHANGE_DELAY
      peer.nextFeeFilterSend = now + Math.floor(Math.random() * MAX_FEEFILTER_CHANGE_DELAY_MS);
    }
  }

  /**
   * Send initial feefilter to a newly connected peer.
   * @param peer - The newly connected peer
   */
  sendInitialFeeFilter(peer: Peer): void {
    const now = Date.now();
    const filterToSend = this.getFeeRateToAnnounce();

    this.sendFeeFilter(peer, filterToSend);
    peer.feeFilterSent = filterToSend;
    peer.nextFeeFilterSend = now + poissonDelay(AVG_FEEFILTER_BROADCAST_INTERVAL_MS);
  }

  /**
   * Check if fee filter has changed substantially (hysteresis).
   * Substantial change: new value < 3/4 old value or > 4/3 old value.
   */
  private hasSubstantialChange(newRate: bigint, oldRate: bigint): boolean {
    if (oldRate === 0n) {
      return newRate > 0n;
    }

    // newRate < 3/4 * oldRate  OR  newRate > 4/3 * oldRate
    return newRate * 4n < oldRate * 3n || newRate * 3n > oldRate * 4n;
  }
}

/**
 * Check if a transaction's fee rate meets a peer's feefilter threshold.
 *
 * @param txFeeRate - Transaction fee rate in sat/vB
 * @param peerFeeFilter - Peer's announced feefilter in sat/kvB
 * @returns true if the transaction meets the threshold
 */
export function meetsFeeFilter(txFeeRate: number, peerFeeFilter: bigint): boolean {
  // If peer hasn't sent a feefilter, relay all transactions
  if (peerFeeFilter === 0n) {
    return true;
  }

  // Convert tx fee rate (sat/vB) to sat/kvB for comparison
  const txFeeRateKvB = BigInt(Math.floor(txFeeRate * 1000));

  return txFeeRateKvB >= peerFeeFilter;
}

/**
 * Generate a Poisson-distributed delay.
 * Uses exponential distribution: -ln(U) * interval
 * where U is uniform random (0, 1].
 *
 * @param averageInterval - Average delay in milliseconds
 * @returns Delay in milliseconds
 */
export function poissonDelay(averageInterval: number): number {
  // Avoid log(0) by using 1 - random() instead of random()
  const u = 1 - Math.random();
  return Math.floor(-Math.log(u) * averageInterval);
}

/**
 * Check incremental relay fee for RBF.
 *
 * For a replacement transaction, the new fee must exceed the sum of
 * fees of all transactions being replaced by at least
 * (incrementalRelayFee * newVsize).
 *
 * @param newFee - Fee of the replacement transaction (satoshis)
 * @param newVsize - Virtual size of the replacement transaction
 * @param oldTotalFee - Sum of fees of all replaced transactions (satoshis)
 * @param incrementalRelayFee - Incremental relay fee rate (sat/kvB)
 * @returns Object with isValid flag and optional error message
 */
export function checkIncrementalRelayFee(
  newFee: bigint,
  newVsize: number,
  oldTotalFee: bigint,
  incrementalRelayFee: bigint = DEFAULT_INCREMENTAL_RELAY_FEE
): { isValid: boolean; error?: string } {
  // Additional fee paid over the replaced transactions
  const additionalFee = newFee - oldTotalFee;

  // Required additional fee = incrementalRelayFee (sat/kvB) * newVsize (vB) / 1000
  // But we must be careful with integer math: multiply first, then divide
  const requiredAdditionalFee = (incrementalRelayFee * BigInt(newVsize)) / 1000n;

  if (additionalFee < requiredAdditionalFee) {
    return {
      isValid: false,
      error: `Insufficient fee: ${additionalFee} < ${requiredAdditionalFee} ` +
        `(${incrementalRelayFee} sat/kvB * ${newVsize} vB)`,
    };
  }

  return { isValid: true };
}
