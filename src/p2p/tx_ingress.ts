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
 * Nothing is dropped: the queue is unbounded, exactly as the set of
 * concurrently started handlers it replaces was. (A count cap was tried and
 * rejected — a 50k-tx burst arrives in well under a second, so any cap below
 * the burst size silently discards valid transactions. Core bounds this with
 * receive-side backpressure, -maxreceivebuffer, which pauses the socket; that
 * is the follow-up if queue memory ever matters.)
 */

export interface TxIngressOptions<P, M> {
  /** The per-transaction handler (validation, relay, orphan handling). */
  process: (peer: P, msg: M) => Promise<void>;
  /** Yield to the event loop after this much continuous work (ms). */
  yieldEveryMs?: number;
  /** Called if `process` throws (it is expected to catch internally). */
  onError?: (err: unknown) => void;
}

export const TX_INGRESS_DEFAULT_YIELD_MS = 10;

const yieldToEventLoop = (): Promise<void> =>
  new Promise((resolve) => setImmediate(resolve));

export class TxIngressQueue<P, M> {
  private readonly queues = new Map<P, M[]>();
  private readonly process: (peer: P, msg: M) => Promise<void>;
  private readonly yieldEveryMs: number;
  private readonly onError?: (err: unknown) => void;
  private draining = false;
  private stopped = false;
  private queued = 0;
  /** Counters for logs/metrics/tests. */
  readonly stats = { enqueued: 0, processed: 0, yields: 0, maxQueued: 0 };

  constructor(opts: TxIngressOptions<P, M>) {
    this.process = opts.process;
    this.yieldEveryMs = opts.yieldEveryMs ?? TX_INGRESS_DEFAULT_YIELD_MS;
    this.onError = opts.onError;
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
  }

  /** Resolves once the queue is empty and no drain is running (tests). */
  async idle(): Promise<void> {
    while (this.draining) await yieldToEventLoop();
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
