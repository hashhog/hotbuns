/**
 * Tip-change notification primitive for the wait-family RPCs
 * (waitfornewblock / waitforblock / waitforblockheight).
 *
 * Bitcoin Core registers a `WaitTipChanged` condition variable (the kernel
 * `KernelNotifications::blockTip` / `Mining::waitTipChanged` hook) that is
 * signalled on every active-chain tip update.  The three wait-family RPCs
 * (`rpc/blockchain.cpp` waitfornewblock@290 / waitforblock@349 /
 * waitforblockheight@410) block on it with a deadline, re-checking their
 * predicate (new tip / hash match / height >=) after each wake and returning
 * the current tip `{hash, height}` on match OR timeout.
 *
 * `TipNotifier` is the hotbuns analogue, mirroring the proven ouroboros pilot
 * (`ouroboros/src/ouroboros/tip_notifier.py`).  Bun/Node run a single-threaded
 * event loop, so there is no cross-thread memory visibility to worry about —
 * the only race to defend against is the classic lost-wakeup (a tip advance
 * landing *between* a waiter's predicate check and its `await`).
 *
 * Design notes
 * ------------
 * * The waiter's predicate is always evaluated against the **authoritative**
 *   chain-state tip (`ChainStateManager.getBestBlock()`), never against any
 *   value carried inside this object.  The notifier only provides a prompt
 *   wake-up; correctness does not depend on a notify ever firing for a
 *   specific tip value.  This makes the primitive robust to coalesced / missed
 *   notifications (e.g. two blocks connected back-to-back before a waiter
 *   wakes, or a notify fired from a chokepoint we forgot): the waiter re-reads
 *   the real tip after every wake and after the timeout, exactly like Core.
 *
 * * A monotonically increasing `generation` counter lets a waiter detect a tip
 *   change that happened *between* its predicate check and its `wait()` call
 *   (the lost-wakeup race).  A waiter captures the generation, checks its
 *   predicate, then awaits a generation bump — so a notify that races in after
 *   the check but before the await is observed, not lost.
 *
 * * The wake mechanism is a single shared, re-created `Promise`.  `notify()`
 *   bumps the generation and resolves the current promise (releasing every
 *   waiter parked on it), then installs a fresh promise for future waiters.
 *   This is the JS-idiomatic edge-triggered pulse: a *future* `wait()` parks on
 *   the new promise and must observe a generation bump to proceed.
 */

export class TipNotifier {
  /**
   * Monotonic counter bumped on every {@link notify}.  Waiters snapshot it
   * before checking their predicate so a notify that races in between the
   * check and the await is observed (no lost wakeup).
   */
  private generationCounter = 0;

  /** The promise current waiters park on; resolved + replaced by notify(). */
  private wakePromise: Promise<void>;
  private wakeResolve!: () => void;

  constructor() {
    this.wakePromise = this.makeWakePromise();
  }

  /** Current tip-change generation (bumped on every {@link notify}). */
  get generation(): number {
    return this.generationCounter;
  }

  private makeWakePromise(): Promise<void> {
    return new Promise<void>((resolve) => {
      this.wakeResolve = resolve;
    });
  }

  /**
   * Signal that the active-chain tip advanced.
   *
   * Bumps the generation counter and pulses the wake promise so every
   * coroutine currently in {@link wait} re-evaluates its predicate.  Safe to
   * call from any connect / disconnect / reorg chokepoint on the event loop;
   * a notify with no waiters parked is a cheap counter bump.
   */
  notify(): void {
    this.generationCounter += 1;
    // Resolve the promise the current waiters are parked on, then install a
    // fresh one so a *future* wait() blocks again (it must observe a
    // generation bump, not a stale resolved promise).
    const resolve = this.wakeResolve;
    this.wakePromise = this.makeWakePromise();
    resolve();
  }

  /**
   * Await the next tip change after `lastGeneration`.
   *
   * @param lastGeneration The generation observed by the caller *before* it
   *   last checked its predicate.  If the generation has already advanced past
   *   this (a notify raced in), this returns immediately.
   * @param timeoutMs Milliseconds to wait, or `null` to wait indefinitely.
   * @returns `true` if a tip change was observed within the deadline, `false`
   *   if the wait timed out.  Either way the caller MUST re-evaluate its
   *   predicate against the authoritative tip.
   */
  async wait(lastGeneration: number, timeoutMs: number | null): Promise<boolean> {
    // Fast path: a notify already raced in since the caller's snapshot.
    if (this.generationCounter !== lastGeneration) {
      return true;
    }

    if (timeoutMs === null) {
      await this.wakePromise;
      return true;
    }

    // Bounded wait: race the wake promise against a timer.  A `false` return
    // means the timer won (timeout); a `true` return means a notify woke us.
    let timer: ReturnType<typeof setTimeout> | undefined;
    const timeoutPromise = new Promise<boolean>((resolve) => {
      timer = setTimeout(() => resolve(false), timeoutMs);
    });
    try {
      // wakePromise resolves to void; map it to `true`.
      return await Promise.race([this.wakePromise.then(() => true), timeoutPromise]);
    } finally {
      if (timer !== undefined) clearTimeout(timer);
    }
  }
}
