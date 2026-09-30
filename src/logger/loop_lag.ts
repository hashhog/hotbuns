/**
 * Event-loop lag monitor.
 *
 * hotbuns runs P2P, mempool acceptance and the RPC server on ONE JavaScript
 * thread. When that thread is busy, an RPC request is not refused — it just
 * waits, and an operator sees a 90 s timeout on `getblockcount` while the
 * process looks healthy. Bitcoin Core never has this failure mode because its
 * RPC runs on its own httpserver threads.
 *
 * This monitor makes that wait visible. It arms a timer every `intervalMs` and
 * measures how late it fires: lateness = actual fire time − scheduled time.
 * A timer can only fire late because the thread was busy (or the process was
 * descheduled), so the lateness is the delay any other callback — an RPC
 * request included — would have seen at that moment.
 *
 * Cost: one timer per `intervalMs` (default 500 ms). A line is logged only when
 * the lateness exceeds `warnMs` (default 2000 ms), rate-limited.
 */

export interface LoopLagStats {
  /** Lateness of the most recent tick (ms). */
  lastMs: number;
  /** Worst lateness observed since start (ms). */
  maxMs: number;
  /** Ticks whose lateness exceeded warnMs. */
  overThreshold: number;
  /** Ticks measured. */
  samples: number;
}

export interface LoopLagOptions {
  intervalMs?: number;
  warnMs?: number;
  /** Minimum ms between two warning lines (a stall is logged once, not per tick). */
  logEveryMs?: number;
  log?: (line: string) => void;
}

export class LoopLagMonitor {
  private readonly intervalMs: number;
  private readonly warnMs: number;
  private readonly logEveryMs: number;
  private readonly log: (line: string) => void;
  private timer: ReturnType<typeof setTimeout> | null = null;
  private lastLogAt = 0;
  private suppressed = 0;
  readonly stats: LoopLagStats = { lastMs: 0, maxMs: 0, overThreshold: 0, samples: 0 };

  constructor(opts: LoopLagOptions = {}) {
    this.intervalMs = opts.intervalMs ?? 500;
    this.warnMs = opts.warnMs ?? 2000;
    this.logEveryMs = opts.logEveryMs ?? 10_000;
    this.log = opts.log ?? ((line) => console.warn(line));
  }

  start(): void {
    if (this.timer !== null) return;
    this.arm();
  }

  stop(): void {
    if (this.timer !== null) clearTimeout(this.timer);
    this.timer = null;
  }

  private arm(): void {
    const scheduledAt = performance.now() + this.intervalMs;
    this.timer = setTimeout(() => {
      const lag = Math.max(0, performance.now() - scheduledAt);
      this.record(lag);
      if (this.timer !== null) this.arm();
    }, this.intervalMs);
    // Never keep the process alive just to measure it.
    (this.timer as { unref?: () => void }).unref?.();
  }

  /** Exposed for tests; normally driven by the timer. */
  record(lagMs: number): void {
    const s = this.stats;
    s.samples++;
    s.lastMs = lagMs;
    if (lagMs > s.maxMs) s.maxMs = lagMs;
    if (lagMs <= this.warnMs) return;
    s.overThreshold++;
    const now = Date.now();
    if (now - this.lastLogAt < this.logEveryMs) {
      this.suppressed++;
      return;
    }
    this.log(
      `[loop-lag] event loop blocked ${Math.round(lagMs)} ms (threshold ${this.warnMs} ms; ` +
        `max ${Math.round(s.maxMs)} ms; ${this.suppressed} more over threshold since last line)`
    );
    this.lastLogAt = now;
    this.suppressed = 0;
  }
}
