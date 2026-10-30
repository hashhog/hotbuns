/**
 * Bounded, round-robin ingress queue for relayed `tx` messages.
 *
 * WHY. The p2p `tx` handler is async and used to be fired straight from the
 * socket's data callback: every transaction in a socket read started its own
 * acceptToMemoryPool immediately, so a burst of N transactions became N
 * concurrent validations whose continuations run back-to-back on the single
 * event loop. Nothing bounded how much of that work ran before a timer, a
 * socket read or an RPC request got a turn.
 *
 * Bitcoin Core bounds the same work structurally (net.cpp ThreadMessageHandler
 * + net_processing.cpp ProcessMessages): it processes at most ONE message per
 * peer per pass, round-robin across peers, and AcceptToMemoryPool runs under
 * cs_main so validations are serial. RPC runs on separate httpserver threads.
 *
 * This queue gives hotbuns the same shape for the one message type that
 * arrives in floods:
 *   - per-peer FIFO, so each peer's transactions keep their arrival order;
 *   - one transaction per peer per pass, round-robin, so one flooding peer
 *     cannot starve the others;
 *   - validations run one at a time (Core's cs_main serialization);
 *   - after every pass, and whenever `yieldEveryMs` of wall time has been
 *     spent since the last yield, control goes back to the event loop via
 *     setImmediate, so timers, socket I/O and RPC requests are served between
 *     transactions instead of after the whole burst.
 *
 * The processing callback is the unchanged handler; only WHEN it runs moves.
 *
 * Bounds (security audit 2026-10-29 H3). A count cap was tried and rejected:
 * a 50k-tx burst arrives in well under a second, so any cap below the burst
 * size silently discards valid transactions. Instead each peer's queued
 * bytes are counted, and once they exceed `maxPeerBytes` (default Core's
 * -maxreceivebuffer, 5 MB) `onPeerPause` asks the transport to stop
 * delivering that peer's messages; `onPeerResume` fires when its share falls
 * back under the limit. That is Core's fPauseRecv on the process queue
 * (net.cpp:4033,4045): backpressure, not loss. `drop(peer)` discards a
 * disconnected peer's queue, as Core's FinalizeNode does, so its
 * transactions are not validated after it has gone.
 */

export interface TxIngressOptions<P, M> {
  /** The per-transaction handler (validation, relay, orphan handling). */
  process: (peer: P, msg: M) => Promise<void>;
  /** Yield to the event loop after this much continuous work (ms). */
  yieldEveryMs?: number;
  /** Called if `process` throws (it is expected to catch internally). */
  onError?: (err: unknown) => void;
  /** Byte size of a queued message (serialized tx size). Default 0. */
  sizeOf?: (msg: M) => number;
  /** Per-peer queued-bytes limit. Default {@link TX_INGRESS_MAX_PEER_BYTES}. */
  maxPeerBytes?: number;
  /** The peer's queued bytes went over `maxPeerBytes`: stop reading it. */
  onPeerPause?: (peer: P) => void;
  /** A paused peer's queued bytes fell back under `maxPeerBytes`. */
  onPeerResume?: (peer: P) => void;
}

export const TX_INGRESS_DEFAULT_YIELD_MS = 10;

/** Core net.h DEFAULT_MAXRECEIVEBUFFER (5000 KB). */
export const TX_INGRESS_MAX_PEER_BYTES = 5000 * 1000;

const yieldToEventLoop = (): Promise<void> =>
  new Promise((resolve) => setImmediate(resolve));

export class TxIngressQueue<P, M> {
  private readonly queues = new Map<P, M[]>();
  private readonly process: (peer: P, msg: M) => Promise<void>;
  private readonly yieldEveryMs: number;
  private readonly onError?: (err: unknown) => void;
  private readonly sizeOf: (msg: M) => number;
  private readonly maxPeerBytes: number;
  private readonly onPeerPause?: (peer: P) => void;
  private readonly onPeerResume?: (peer: P) => void;
  /** Queued bytes per peer (only peers with something queued). */
  private readonly peerBytes = new Map<P, number>();
  /** Peers we have asked to pause. */
  private readonly pausedPeers = new Set<P>();
  private draining = false;
  private stopped = false;
  private queued = 0;
  /** Counters for logs/metrics/tests. */
  readonly stats = { enqueued: 0, processed: 0, yields: 0, maxQueued: 0, dropped: 0, pauses: 0 };

  constructor(opts: TxIngressOptions<P, M>) {
    this.process = opts.process;
    this.yieldEveryMs = opts.yieldEveryMs ?? TX_INGRESS_DEFAULT_YIELD_MS;
    this.onError = opts.onError;
    this.sizeOf = opts.sizeOf ?? (() => 0);
    this.maxPeerBytes = opts.maxPeerBytes ?? TX_INGRESS_MAX_PEER_BYTES;
    this.onPeerPause = opts.onPeerPause;
    this.onPeerResume = opts.onPeerResume;
  }

  /** Bytes queued for `peer` (not counting the one being validated). */
  peerQueuedBytes(peer: P): number {
    return this.peerBytes.get(peer) ?? 0;
  }

  /** True while `peer` is paused by this queue. */
  isPeerPaused(peer: P): boolean {
    return this.pausedPeers.has(peer);
  }

  /**
   * Discard everything queued for `peer` (it disconnected). Its paused state
   * is forgotten without calling onPeerResume: there is nobody to resume.
   */
  drop(peer: P): number {
    const q = this.queues.get(peer);
    const n = q?.length ?? 0;
    if (q !== undefined) {
      // Empty the array too: a drain pass may hold a reference to it.
      q.length = 0;
      this.queues.delete(peer);
    }
    this.queued -= n;
    this.stats.dropped += n;
    this.peerBytes.delete(peer);
    this.pausedPeers.delete(peer);
    return n;
  }

  /** Number of transactions waiting (not counting the one being validated). */
  size(): number {
    return this.queued;
  }

  /** True while a drain is scheduled or running. */
  isDraining(): boolean {
    return this.draining;
  }

  /** Queue a transaction; returns false only after stop(). */
  enqueue(peer: P, msg: M): boolean {
    if (this.stopped) return false;
    let q = this.queues.get(peer);
    if (q === undefined) {
      q = [];
      this.queues.set(peer, q);
    }
    q.push(msg);
    this.queued++;
    this.stats.enqueued++;
    const bytes = (this.peerBytes.get(peer) ?? 0) + this.sizeOf(msg);
    this.peerBytes.set(peer, bytes);
    if (bytes > this.maxPeerBytes && !this.pausedPeers.has(peer)) {
      this.pausedPeers.add(peer);
      this.stats.pauses++;
      this.notify(this.onPeerPause, peer);
    }
    if (this.queued > this.stats.maxQueued) this.stats.maxQueued = this.queued;
    if (!this.draining) {
      this.draining = true;
      // Start on a fresh macrotask: the socket callback that delivered this
      // message returns first, exactly as it did before the queue existed.
      setImmediate(() => void this.drain());
    }
    return true;
  }

  /** Discard everything queued and stop accepting (node shutdown). */
  stop(): void {
    this.stopped = true;
    this.queues.clear();
    this.queued = 0;
    this.peerBytes.clear();
    this.pausedPeers.clear();
  }

  /** Resolves once the queue is empty and no drain is running (tests). */
  async idle(): Promise<void> {
    while (this.draining) await yieldToEventLoop();
  }

  /** A message left the queue: update its peer's bytes, resume if under. */
  private release(peer: P, msg: M): void {
    const left = (this.peerBytes.get(peer) ?? 0) - this.sizeOf(msg);
    if (left > 0) this.peerBytes.set(peer, left);
    else this.peerBytes.delete(peer);
    if (left <= this.maxPeerBytes && this.pausedPeers.delete(peer)) {
      this.notify(this.onPeerResume, peer);
    }
  }

  /** Run a pause/resume callback; a throw must not abort the drain loop. */
  private notify(cb: ((peer: P) => void) | undefined, peer: P): void {
    try {
      cb?.(peer);
    } catch (err) {
      this.onError?.(err);
    }
  }

  private async drain(): Promise<void> {
    try {
      let sliceStart = performance.now();
      while (this.queued > 0 && !this.stopped) {
        // One pass = at most one transaction from each peer, in round-robin
        // order (Map iteration order; a peer that empties is removed and
        // re-appended at the back when it sends again).
        for (const [peer, q] of this.queues) {
          if (this.stopped) return;
          const msg = q.shift();
          if (q.length === 0) this.queues.delete(peer);
          if (msg === undefined) continue;
          this.queued--;
          this.release(peer, msg);
          try {
            await this.process(peer, msg);
          } catch (err) {
            this.onError?.(err);
          }
          this.stats.processed++;
          if (performance.now() - sliceStart >= this.yieldEveryMs) {
            this.stats.yields++;
            await yieldToEventLoop();
            sliceStart = performance.now();
          }
        }
        // End of a pass: let I/O and RPC in before the next one.
        this.stats.yields++;
        await yieldToEventLoop();
        sliceStart = performance.now();
      }
    } finally {
      this.draining = false;
      // A message enqueued while we were finishing up (after the last check)
      // must not be stranded.
      if (this.queued > 0 && !this.stopped) {
        this.draining = true;
        setImmediate(() => void this.drain());
      }
    }
  }
}
