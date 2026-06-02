/**
 * Inventory trickling for transaction announcements.
 *
 * Instead of immediately announcing every new transaction to all peers,
 * batches and randomizes announcements to improve privacy and reduce bandwidth.
 *
 * Reference: Bitcoin Core net_processing.cpp, INVENTORY_BROADCAST_INTERVAL, SendMessages()
 */

import type { Peer } from "./peer.js";
import type { InvVector } from "./messages.js";
import { InvType } from "./messages.js";
import { meetsFeeFilter } from "./feefilter.js";

/**
 * Average delay between trickled inventory transmissions for inbound peers.
 * Blocks and peers with special permissions bypass this.
 * Bitcoin Core: INBOUND_INVENTORY_BROADCAST_INTERVAL = 5s
 */
export const INBOUND_INVENTORY_BROADCAST_INTERVAL = 5_000; // 5 seconds in ms

/**
 * Average delay between trickled inventory transmissions for outbound peers.
 * Use a smaller delay as there is less privacy concern for them.
 * Bitcoin Core: OUTBOUND_INVENTORY_BROADCAST_INTERVAL = 2s
 */
export const OUTBOUND_INVENTORY_BROADCAST_INTERVAL = 2_000; // 2 seconds in ms

/**
 * Maximum number of inventory items to send per transmission.
 * Bitcoin Core: INVENTORY_BROADCAST_MAX = 1000
 */
export const INVENTORY_BROADCAST_MAX = 1000;

/**
 * Maximum entries to batch per tick (per peer) for testing purposes.
 * In production, we batch up to INVENTORY_BROADCAST_MAX per interval.
 * Per the spec, batch up to 7 inv entries per peer per tick.
 */
export const INVENTORY_BATCH_SIZE = 7;

/**
 * Hard cap on the number of pending transaction announcements queued per peer.
 * Mirrors Bitcoin Core's `MAX_PEER_TX_ANNOUNCEMENTS` (net_processing.cpp).
 * The flush only drains {@link INVENTORY_BATCH_SIZE} (7) txids per Poisson
 * tick, so a peer that floods us with invs (or a stuck/slow peer whose queue
 * never drains) would otherwise let `pendingTxs` grow without bound. This is an
 * at-tip-only concern (the tx handler early-returns during IBD), but it is a
 * real bound: announcements past the cap are dropped/ignored. Dropping an
 * advisory inv announcement changes no consensus behaviour — the peer can
 * always re-announce, and we still serve the tx on `getdata`.
 */
export const MAX_PEER_TX_ANNOUNCEMENTS = 5000;

/**
 * Per-peer relay queue tracking pending transaction announcements.
 */
interface PeerRelayQueue {
  /** Peer this queue is for. */
  peer: Peer;
  /** Whether this is an inbound peer (determines delay). */
  isInbound: boolean;
  /**
   * Whether the remote peer sent us `wtxidrelay` during the handshake.
   * When true, inv announcements must use MSG_WTX (=5) + wtxid.
   * When false, inv announcements use MSG_TX (=1) + txid.
   * Reference: Bitcoin Core net_processing.cpp RelayTransaction,
   * protocol.h MSG_WTX = 5 (BIP-339).
   */
  wtxidRelay: boolean;
  /** Pending transaction hashes to announce (hex). */
  pendingTxs: Set<string>;
  /** Next scheduled flush time (ms since epoch). */
  nextFlushTime: number;
  /** Timer handle for the scheduled flush. */
  timer: ReturnType<typeof setTimeout> | null;
}

/**
 * Manages inventory trickling for transaction and block announcements.
 *
 * - Transactions are queued per-peer and flushed on a Poisson timer
 * - Blocks are always relayed immediately (no trickling)
 * - Randomizes the order of announced transactions (Fisher-Yates shuffle)
 */
export class InventoryRelay {
  /** Per-peer relay queues. Key is "host:port". */
  private queues: Map<string, PeerRelayQueue>;
  /** Callback to send an inv message to a peer. */
  private sendInv: (peer: Peer, inventory: InvVector[]) => void;
  /** Whether the relay manager is running. */
  private running: boolean;

  constructor(sendInv: (peer: Peer, inventory: InvVector[]) => void) {
    this.queues = new Map();
    this.sendInv = sendInv;
    this.running = true;
  }

  /**
   * Register a new peer for inventory trickling.
   *
   * @param peer - The peer to register
   * @param isInbound - Whether this is an inbound connection
   * @param wtxidRelay - Whether the remote peer sent `wtxidrelay` during
   *   handshake (BIP-339).  When true, flushes use MSG_WTX(5) + wtxid;
   *   when false, flushes use MSG_TX(1) + txid.
   */
  addPeer(peer: Peer, isInbound: boolean = false, wtxidRelay: boolean = false): void {
    const key = `${peer.host}:${peer.port}`;

    if (this.queues.has(key)) {
      return;
    }

    const interval = isInbound
      ? INBOUND_INVENTORY_BROADCAST_INTERVAL
      : OUTBOUND_INVENTORY_BROADCAST_INTERVAL;

    const queue: PeerRelayQueue = {
      peer,
      isInbound,
      wtxidRelay,
      pendingTxs: new Set(),
      nextFlushTime: Date.now() + this.poissonDelay(interval),
      timer: null,
    };

    this.queues.set(key, queue);
    this.scheduleFlush(queue);
  }

  /**
   * Remove a peer from inventory trickling.
   *
   * @param peer - The peer to remove
   */
  removePeer(peer: Peer): void {
    const key = `${peer.host}:${peer.port}`;
    const queue = this.queues.get(key);

    if (queue) {
      if (queue.timer !== null) {
        clearTimeout(queue.timer);
      }
      this.queues.delete(key);
    }
  }

  /**
   * Add a txid to a peer's pending-announcement set, enforcing the
   * {@link MAX_PEER_TX_ANNOUNCEMENTS} per-peer cap. Re-announcing an
   * already-queued txid is always allowed (Set.add is idempotent and does not
   * grow the set); only genuinely-new txids past the cap are dropped.
   * @returns true if the txid is now queued, false if dropped at the cap.
   */
  private enqueueTx(queue: PeerRelayQueue, txid: string): boolean {
    if (queue.pendingTxs.has(txid)) {
      return true;
    }
    if (queue.pendingTxs.size >= MAX_PEER_TX_ANNOUNCEMENTS) {
      // Queue is full (peer flood / stuck drain). Drop the announcement; the
      // tx is still served on getdata and can be re-announced later.
      return false;
    }
    queue.pendingTxs.add(txid);
    return true;
  }

  /**
   * Queue a transaction for announcement to a specific peer.
   * The transaction will be announced on the next scheduled flush.
   *
   * @param peer - The peer to announce to
   * @param txid - Transaction ID (hex string)
   */
  queueTx(peer: Peer, txid: string): void {
    const key = `${peer.host}:${peer.port}`;
    const queue = this.queues.get(key);

    if (queue) {
      this.enqueueTx(queue, txid);
    }
  }

  /**
   * Queue a transaction for announcement to a specific peer, respecting feefilter.
   * Only queues if the transaction's fee rate meets the peer's feefilter threshold.
   *
   * @param peer - The peer to announce to
   * @param txid - Transaction ID (hex string)
   * @param txFeeRate - Transaction fee rate in sat/vB
   * @returns true if queued, false if filtered out
   */
  queueTxFiltered(peer: Peer, txid: string, txFeeRate: number): boolean {
    // Check feefilter before queueing
    if (!meetsFeeFilter(txFeeRate, peer.feeFilterReceived)) {
      return false;
    }

    const key = `${peer.host}:${peer.port}`;
    const queue = this.queues.get(key);

    if (queue) {
      return this.enqueueTx(queue, txid);
    }
    return false;
  }

  /**
   * Queue a transaction for announcement to all registered peers.
   *
   * @param txid - Transaction ID (hex string)
   */
  queueTxToAll(txid: string): void {
    for (const queue of this.queues.values()) {
      this.enqueueTx(queue, txid);
    }
  }

  /**
   * Queue a transaction for announcement to all registered peers, respecting feefilter.
   * Only queues to peers where the transaction's fee rate meets their feefilter threshold.
   *
   * @param txid - Transaction ID (hex string)
   * @param txFeeRate - Transaction fee rate in sat/vB
   * @returns Number of peers the transaction was queued to
   */
  queueTxToAllFiltered(txid: string, txFeeRate: number): number {
    let count = 0;
    for (const queue of this.queues.values()) {
      // Check feefilter before queueing
      if (meetsFeeFilter(txFeeRate, queue.peer.feeFilterReceived)) {
        if (this.enqueueTx(queue, txid)) {
          count++;
        }
      }
    }
    return count;
  }

  /**
   * Immediately relay a block to a specific peer (no trickling).
   * Blocks are always announced immediately for network propagation.
   *
   * @param peer - The peer to announce to
   * @param blockHash - Block hash buffer
   */
  relayBlockNow(peer: Peer, blockHash: Buffer): void {
    const key = `${peer.host}:${peer.port}`;
    const queue = this.queues.get(key);

    if (queue && this.running) {
      const inv: InvVector = {
        type: InvType.MSG_BLOCK,
        hash: blockHash,
      };
      this.sendInv(peer, [inv]);
    }
  }

  /**
   * Immediately relay a block to all registered peers (no trickling).
   *
   * @param blockHash - Block hash buffer
   */
  relayBlockToAll(blockHash: Buffer): void {
    if (!this.running) return;

    const inv: InvVector = {
      type: InvType.MSG_BLOCK,
      hash: blockHash,
    };

    for (const queue of this.queues.values()) {
      this.sendInv(queue.peer, [inv]);
    }
  }

  /**
   * Stop the relay manager and cancel all pending timers.
   */
  stop(): void {
    this.running = false;

    for (const queue of this.queues.values()) {
      if (queue.timer !== null) {
        clearTimeout(queue.timer);
        queue.timer = null;
      }
    }

    this.queues.clear();
  }

  /**
   * Get the number of pending transactions for a peer.
   * Useful for testing.
   */
  getPendingCount(peer: Peer): number {
    const key = `${peer.host}:${peer.port}`;
    const queue = this.queues.get(key);
    return queue ? queue.pendingTxs.size : 0;
  }

  /**
   * Get the next scheduled flush time for a peer.
   * Useful for testing.
   */
  getNextFlushTime(peer: Peer): number | null {
    const key = `${peer.host}:${peer.port}`;
    const queue = this.queues.get(key);
    return queue ? queue.nextFlushTime : null;
  }

  /**
   * Force an immediate flush for testing purposes.
   */
  flushNow(peer: Peer): void {
    const key = `${peer.host}:${peer.port}`;
    const queue = this.queues.get(key);
    if (queue) {
      this.flush(queue);
    }
  }

  /**
   * Generate a Poisson-distributed delay.
   * Uses exponential distribution: -ln(U) * interval
   * where U is uniform random (0, 1].
   *
   * @param averageInterval - Average delay in milliseconds
   * @returns Delay in milliseconds
   */
  private poissonDelay(averageInterval: number): number {
    // Avoid log(0) by using 1 - random() instead of random()
    const u = 1 - Math.random();
    return Math.floor(-Math.log(u) * averageInterval);
  }

  /**
   * Schedule the next flush for a peer queue.
   */
  private scheduleFlush(queue: PeerRelayQueue): void {
    if (!this.running) return;

    const now = Date.now();
    const delay = Math.max(0, queue.nextFlushTime - now);

    queue.timer = setTimeout(() => {
      if (this.running) {
        this.flush(queue);
      }
    }, delay);
  }

  /**
   * Flush pending transactions to a peer.
   */
  private flush(queue: PeerRelayQueue): void {
    if (!this.running) return;

    const { peer, pendingTxs, isInbound } = queue;

    if (pendingTxs.size > 0) {
      // Collect txids to send (up to batch size or broadcast max)
      const txidsToSend: string[] = [];
      const maxToSend = Math.min(INVENTORY_BATCH_SIZE, INVENTORY_BROADCAST_MAX);

      for (const txid of pendingTxs) {
        if (txidsToSend.length >= maxToSend) break;
        txidsToSend.push(txid);
      }

      // Remove from pending set
      for (const txid of txidsToSend) {
        pendingTxs.delete(txid);
      }

      // Shuffle using Fisher-Yates for privacy
      this.shuffleArray(txidsToSend);

      // Build and send inv message.
      // Per BIP-339 / Core net_processing.cpp RelayTransaction:
      //   wtxid-relay peer → MSG_WTX (=5) + wtxid
      //   legacy peer      → MSG_TX  (=1) + txid
      // MSG_WITNESS_TX (0x40000001) is a BIP-144 *getdata flag*, not a
      // valid inv type — Core peers silently discard such inv entries.
      const invType = queue.wtxidRelay ? InvType.MSG_WTX : InvType.MSG_TX;
      const inventory: InvVector[] = txidsToSend.map((txid) => ({
        type: invType,
        hash: Buffer.from(txid, "hex"),
      }));

      if (inventory.length > 0) {
        this.sendInv(peer, inventory);
      }
    }

    // Schedule next flush with new Poisson delay
    const interval = isInbound
      ? INBOUND_INVENTORY_BROADCAST_INTERVAL
      : OUTBOUND_INVENTORY_BROADCAST_INTERVAL;

    queue.nextFlushTime = Date.now() + this.poissonDelay(interval);
    this.scheduleFlush(queue);
  }

  /**
   * Fisher-Yates shuffle for randomizing transaction order.
   * Modifies array in place.
   */
  private shuffleArray<T>(array: T[]): void {
    for (let i = array.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [array[i], array[j]] = [array[j], array[i]];
    }
  }
}
