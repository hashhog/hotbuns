/**
 * Supervisor must notice a hard process death (SIGSEGV/SIGILL) immediately
 * and call it CRASHED — not "behind" or a stall. A Bun 1.3.11 JSC GC
 * SIGSEGV (401723 / 340890) looks like slowness to anything that only
 * polls RPC.
 *
 * Control: HOTBUNS_UNIT_CHILD=1 bun test ./src/cli/supervisor.test.ts
 */
import { describe, expect, test } from "bun:test";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parseArgs } from "./cli.js";
import {
  FATAL_SIGNALS,
  childArgvFromSupervised,
  formatCrashLine,
  isHardCrash,
  superviseChild,
} from "./supervisor.js";

const sink = { write: (_: Uint8Array | string) => {} };

const PY_SEGV = [
  "python3",
  "-c",
  "import os,signal,resource; resource.setrlimit(resource.RLIMIT_CORE,(0,0)); os.kill(os.getpid(), signal.SIGSEGV)",
];

const PY_SLEEP = [
  "python3",
  "-c",
  "import time; print('ready', flush=True); time.sleep(30)",
];

describe("isHardCrash / formatCrashLine", () => {
  test("SIGSEGV is a hard crash", () => {
    expect(FATAL_SIGNALS.has("SIGSEGV")).toBe(true);
    expect(isHardCrash({ signalCode: "SIGSEGV", exitCode: null })).toBe(true);
  });

  test("SIGILL is a hard crash (Bun's handler turns SIGSEGV into SIGILL)", () => {
    expect(isHardCrash({ signalCode: "SIGILL", exitCode: null })).toBe(true);
    expect(isHardCrash({ signalCode: null, exitCode: 132 })).toBe(true);
  });

  test("clean exit and SIGTERM are not hard crashes", () => {
    expect(isHardCrash({ signalCode: null, exitCode: 0 })).toBe(false);
    expect(isHardCrash({ signalCode: "SIGTERM", exitCode: null })).toBe(false);
    expect(isHardCrash({ signalCode: "SIGINT", exitCode: null })).toBe(false);
  });

  test("Bun panic banner is a hard crash even without a signal", () => {
    expect(
      isHardCrash({
        signalCode: null,
        exitCode: 1,
        logSnippet: "panic: Segmentation fault at address 0x800000001A\noh no: Bun has crashed",
      }),
    ).toBe(true);
  });

  test("formatCrashLine says CRASHED and does not call it behind or a stall", () => {
    const line = formatCrashLine({
      pid: 42,
      signalCode: "SIGSEGV",
      exitCode: 139,
      logSnippet: "panic: Segmentation fault at address 0x800000001A",
    });
    expect(line.startsWith("CRASHED")).toBe(true);
    expect(line).toContain("SIGSEGV");
    expect(line).toContain("pid=42");
    expect(line).not.toMatch(/\bbehind\b/i);
    expect(line).not.toMatch(/stall/i);
  });
});

describe("parseArgs --supervise", () => {
  test("bare --supervise is on", () => {
    const parsed = parseArgs(["bun", "cli.ts", "start", "--supervise"]);
    expect(parsed.config.supervise).toBe(true);
  });

  test("--supervise-restarts=N is parsed", () => {
    const parsed = parseArgs([
      "bun",
      "cli.ts",
      "start",
      "--supervise",
      "--supervise-restarts=2",
    ]);
    expect(parsed.config.supervise).toBe(true);
    expect(parsed.config.superviseRestarts).toBe(2);
  });

  test("childArgvFromSupervised strips --supervise and pins the child flag", () => {
    const child = childArgvFromSupervised([
      "/home/work/.bun/bin/bun",
      "/tmp/index.ts",
      "--network=regtest",
      "--supervise",
      "--supervise-restarts=3",
    ]);
    expect(child[0]).toBe("/home/work/.bun/bin/bun");
    expect(child[1]).toBe("run");
    expect(child).toContain("/tmp/index.ts");
    expect(child).toContain("--network=regtest");
    expect(child).toContain("--internal-supervised-child");
    expect(child.some((a) => a === "--supervise" || a.startsWith("--supervise="))).toBe(
      false,
    );
    expect(child.some((a) => a.startsWith("--supervise-restarts"))).toBe(false);
  });
});

describe("superviseChild notices hard death", () => {
  test(
    "python SIGSEGV is CRASHED in under 2s, not behind",
    async () => {
      const lines: string[] = [];
      const t0 = Date.now();
      const code = await superviseChild({
        cmd: PY_SEGV,
        maxRestarts: 0,
        log: (l) => lines.push(l),
        forwardStdout: sink,
        forwardStderr: sink,
      });
      const elapsed = Date.now() - t0;
      const out = lines.join("\n");
      expect(elapsed).toBeLessThan(2000);
      expect(out).toMatch(/CRASHED/);
      expect(out).toMatch(/SIGSEGV|signal=11|exit 139/);
      expect(out).not.toMatch(/\bbehind\b/i);
      expect(out).not.toMatch(/stall/i);
      expect(code).not.toBe(0);
    },
    { timeout: 8_000 },
  );

  test(
    "external SIGSEGV on a live child is CRASHED, not a stall wait",
    async () => {
      const lines: string[] = [];
      let pid = 0;
      const t0 = Date.now();
      const done = superviseChild({
        cmd: PY_SLEEP,
        maxRestarts: 0,
        log: (l) => lines.push(l),
        forwardStdout: sink,
        forwardStderr: sink,
        onSpawn: (p) => {
          pid = p;
        },
      });
      const deadline = Date.now() + 3000;
      while (pid === 0 && Date.now() < deadline) await Bun.sleep(20);
      expect(pid).toBeGreaterThan(0);
      process.kill(pid, "SIGSEGV");
      const code = await done;
      const elapsed = Date.now() - t0;
      const out = lines.join("\n");
      expect(elapsed).toBeLessThan(2000);
      expect(out).toMatch(/CRASHED/);
      expect(out).not.toMatch(/\bbehind\b/i);
      expect(out).not.toMatch(/stall/i);
      expect(code).not.toBe(0);
    },
    { timeout: 8_000 },
  );

  test(
    "Bun child SIGSEGV is CRASHED even if wait() reports SIGILL",
    async () => {
      // Bun's crash handler swallows SIGSEGV and aborts as SIGILL, which is
      // how 401723 actually died (`oh no: Bun has crashed`). The supervisor
      // must still say CRASHED, not wait out a stall window.
      const dir = await mkdtemp(join(tmpdir(), "hotbuns-bun-segv-"));
      const script = join(dir, "sleep.ts");
      await writeFile(
        script,
        'console.log("ready"); setInterval(() => {}, 1000);\n',
      );
      const lines: string[] = [];
      let pid = 0;
      const t0 = Date.now();
      const done = superviseChild({
        cmd: [process.execPath, "run", script],
        maxRestarts: 0,
        log: (l) => lines.push(l),
        forwardStdout: sink,
        forwardStderr: sink,
        onSpawn: (p) => {
          pid = p;
        },
      });
      const deadline = Date.now() + 4000;
      while (pid === 0 && Date.now() < deadline) await Bun.sleep(20);
      expect(pid).toBeGreaterThan(0);
      await Bun.sleep(150);
      process.kill(pid, "SIGSEGV");
      const code = await done;
      const elapsed = Date.now() - t0;
      const out = lines.join("\n");
      expect(elapsed).toBeLessThan(5000);
      expect(out).toMatch(/CRASHED/);
      expect(out).toMatch(/SIGSEGV|SIGILL|Segmentation fault|Bun has crashed/);
      expect(out).not.toMatch(/\bbehind\b/i);
      expect(out).not.toMatch(/stall/i);
      expect(code).not.toBe(0);
      await rm(dir, { recursive: true, force: true });
    },
    { timeout: 10_000 },
  );

  test(
    "clean exit 0 is not CRASHED",
    async () => {
      const lines: string[] = [];
      const code = await superviseChild({
        cmd: ["python3", "-c", "raise SystemExit(0)"],
        maxRestarts: 0,
        log: (l) => lines.push(l),
        forwardStdout: sink,
        forwardStderr: sink,
      });
      expect(code).toBe(0);
      expect(lines.join("\n")).not.toMatch(/CRASHED/);
    },
    { timeout: 8_000 },
  );

  test(
    "hard crash with maxRestarts=1 respawns and the second child lives",
    async () => {
      const dir = await mkdtemp(join(tmpdir(), "hotbuns-sup-"));
      const marker = join(dir, "crashed-once");
      const script = join(dir, "child.py");
      await writeFile(
        script,
        [
          "import os, sys, time, signal, resource",
          "resource.setrlimit(resource.RLIMIT_CORE, (0, 0))",
          "marker = sys.argv[1]",
          "if not os.path.exists(marker):",
          "    open(marker, 'w').write('1')",
          "    os.kill(os.getpid(), signal.SIGSEGV)",
          "print('survived', flush=True)",
          "time.sleep(30)",
          "",
        ].join("\n"),
      );
      const lines: string[] = [];
      let spawns = 0;
      let secondPid = 0;
      const done = superviseChild({
        cmd: ["python3", script, marker],
        maxRestarts: 1,
        restartBackoffMs: 50,
        log: (l) => lines.push(l),
        forwardStdout: sink,
        forwardStderr: sink,
        onSpawn: (p) => {
          spawns++;
          if (spawns === 2) secondPid = p;
        },
      });
      const deadline = Date.now() + 4000;
      while (secondPid === 0 && Date.now() < deadline) await Bun.sleep(20);
      expect(spawns).toBe(2);
      expect(secondPid).toBeGreaterThan(0);
      process.kill(secondPid, "SIGTERM");
      const code = await done;
      const out = lines.join("\n");
      expect(out).toMatch(/CRASHED/);
      expect(out).toMatch(/restarting 1\/1/);
      expect(out).not.toMatch(/\bbehind\b/i);
      // SIGTERM of the surviving child is a stop, not a second crash.
      expect(code).not.toBeUndefined();
      await rm(dir, { recursive: true, force: true });
    },
    { timeout: 10_000 },
  );
});
