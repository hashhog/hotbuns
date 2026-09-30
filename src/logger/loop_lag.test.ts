import { describe, test, expect } from "bun:test";
import { LoopLagMonitor } from "./loop_lag.js";

describe("LoopLagMonitor", () => {
  test("measures a blocked event loop and logs past the threshold", async () => {
    const lines: string[] = [];
    const m = new LoopLagMonitor({ intervalMs: 20, warnMs: 100, log: (l) => lines.push(l) });
    m.start();
    await new Promise((r) => setTimeout(r, 50));
    const end = performance.now() + 300;
    while (performance.now() < end) {
      /* block the loop */
    }
    await new Promise((r) => setTimeout(r, 60));
    m.stop();
    expect(m.stats.maxMs).toBeGreaterThan(200);
    expect(m.stats.overThreshold).toBeGreaterThanOrEqual(1);
    expect(lines.length).toBe(1);
    expect(lines[0]).toContain("[loop-lag] event loop blocked");
  });

  test("quiet loop: no lines, small lag", async () => {
    const lines: string[] = [];
    const m = new LoopLagMonitor({ intervalMs: 10, warnMs: 1000, log: (l) => lines.push(l) });
    m.start();
    await new Promise((r) => setTimeout(r, 80));
    m.stop();
    expect(m.stats.samples).toBeGreaterThan(2);
    expect(lines.length).toBe(0);
  });

  test("rate-limits repeated warnings", () => {
    const lines: string[] = [];
    const m = new LoopLagMonitor({ warnMs: 10, logEveryMs: 60_000, log: (l) => lines.push(l) });
    m.record(50);
    m.record(60);
    m.record(70);
    expect(lines.length).toBe(1);
    expect(m.stats.overThreshold).toBe(3);
    expect(m.stats.maxMs).toBe(70);
  });
});
