/**
 * TxIngressQueue: the bound that keeps relayed-tx validation from starving
 * the event loop (and with it the RPC server).
 */
import { describe, test, expect } from "bun:test";
import { TxIngressQueue } from "./tx_ingress.js";

function busy(ms: number): void {
  const end = performance.now() + ms;
  while (performance.now() < end) {
    /* spin: stands in for synchronous validation work */
  }
}

describe("TxIngressQueue", () => {
  test("a timer armed during a burst fires long before the burst ends", async () => {
    // 150 items x 4 ms of synchronous work each = ~600 ms of work. The old
    // dispatch ran every validation back to back; a 0 ms timer (or an RPC
    // request) waited for all of it.
    const q = new TxIngressQueue<string, number>({
      process: async () => busy(4),
      yieldEveryMs: 10,
    });
    for (let i = 0; i < 150; i++) q.enqueue("peerA", i);
    const armed = performance.now();
    let firedAfter = -1;
    let processedWhenFired = -1;
    setTimeout(() => {
      firedAfter = performance.now() - armed;
      processedWhenFired = q.stats.processed;
    }, 0);
    await q.idle();
    const total = performance.now() - armed;
    expect(q.stats.processed).toBe(150);
    expect(firedAfter).toBeGreaterThanOrEqual(0);
    // Fired within a couple of slices, not after the whole burst.
    expect(firedAfter).toBeLessThan(100);
    expect(processedWhenFired).toBeLessThan(30);
    expect(total).toBeGreaterThan(500);
  });

  test("round-robin: one flooding peer cannot delay another peer's tx", async () => {
    const order: string[] = [];
    const q = new TxIngressQueue<string, string>({
      process: async (peer, msg) => {
        order.push(`${peer}:${msg}`);
      },
    });
    for (let i = 0; i < 100; i++) q.enqueue("flooder", String(i));
    q.enqueue("honest", "x");
    await q.idle();
    expect(order.length).toBe(101);
    expect(order.indexOf("honest:x")).toBe(1);
    // Per-peer FIFO is preserved.
    const flooder = order.filter((o) => o.startsWith("flooder:")).map((o) => Number(o.split(":")[1]));
    expect(flooder).toEqual([...Array(100).keys()]);
  });

  test("validations run one at a time (Core's cs_main serialization)", async () => {
    let inFlight = 0;
    let maxInFlight = 0;
    const q = new TxIngressQueue<string, number>({
      process: async () => {
        inFlight++;
        maxInFlight = Math.max(maxInFlight, inFlight);
        await new Promise((r) => setTimeout(r, 1));
        inFlight--;
      },
    });
    for (let i = 0; i < 20; i++) q.enqueue(i % 2 ? "a" : "b", i);
    await q.idle();
    expect(q.stats.processed).toBe(20);
    expect(maxInFlight).toBe(1);
  });

  test("a throwing handler does not stall the queue", async () => {
    const errors: unknown[] = [];
    let ok = 0;
    const q = new TxIngressQueue<string, number>({
      process: async (_p, m) => {
        if (m === 1) throw new Error("boom");
        ok++;
      },
      onError: (e) => errors.push(e),
    });
    for (let i = 0; i < 3; i++) q.enqueue("a", i);
    await q.idle();
    expect(ok).toBe(2);
    expect(errors.length).toBe(1);
  });

  test("items enqueued while draining are processed; stop() discards", async () => {
    let n = 0;
    const q = new TxIngressQueue<string, number>({
      process: async (_p, m) => {
        n++;
        if (m === 0) q.enqueue("late", 1);
      },
    });
    q.enqueue("a", 0);
    await q.idle();
    expect(n).toBe(2);
    q.stop();
    expect(q.enqueue("a", 2)).toBe(false);
    await q.idle();
    expect(n).toBe(2);
  });
});
