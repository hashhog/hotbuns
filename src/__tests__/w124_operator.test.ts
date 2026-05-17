/**
 * W124 — Operator-experience audit (hotbuns).
 *
 * Discovery wave. Locks in current behavior for every PARTIAL/MISSING
 * gate so a future drive-by stub trips a failing expect() before merge.
 *
 * Status legend at the foot of each test:
 *   PRESENT  — covered behavior matches expected Core-parity surface
 *   PARTIAL  — partially present (e.g. infrastructure exists, wiring missing)
 *   MISSING  — feature absent in production code
 *
 * Reference: bitcoin-core/src/init.cpp (CreatePidFile / RemovePidFile,
 *   LockDataDirectory, ShutdownNotify, -startupnotify, -shutdownnotify,
 *   -printtoconsole, -debuglogfile, -rpcbind, -rpcallowip),
 *   bitcoin-core/src/util/fs_helpers.cpp (LockDirectory),
 *   bitcoin-core/src/logging.{cpp,h} (-logips, -logtimestamps,
 *   -loglevel, per-category levels),
 *   root CLAUDE.md "Ops (mainnet fleet)" and hotbuns gotchas.
 *
 * Test file pairs with: audit/w124_operator_experience.md
 *
 * Run: bun test src/__tests__/w124_operator.test.ts
 */

import { describe, expect, test } from "bun:test";
import * as fs from "fs";
import * as path from "path";

import { Logger, getLogger, setLogger } from "../logger/logger.js";
import { parseArgs } from "../cli/cli.js";

// ---------------------------------------------------------------------------
// Helper: read the CLI module text once for static-analysis assertions.
// We use the .ts source because production code is what we audit; the
// compiled src/index.js is a build artifact that may lag.
// ---------------------------------------------------------------------------
const CLI_SRC = fs.readFileSync(
  path.resolve(__dirname, "..", "cli", "cli.ts"),
  "utf8"
);
const LOGGER_SRC = fs.readFileSync(
  path.resolve(__dirname, "..", "logger", "logger.ts"),
  "utf8"
);
const RPC_SRC = fs.readFileSync(
  path.resolve(__dirname, "..", "rpc", "server.ts"),
  "utf8"
);

// ===========================================================================
// G1-G5: Signal handling
// ===========================================================================

describe("W124 G1: SIGTERM triggers gracefulShutdown (PRESENT)", () => {
  test("cli.ts registers SIGTERM handler that calls gracefulShutdown", () => {
    expect(CLI_SRC.includes('process.on("SIGTERM"')).toBe(true);
    // The handler must call gracefulShutdown
    const sigtermBlock = CLI_SRC.split('process.on("SIGTERM"')[1] ?? "";
    expect(sigtermBlock.slice(0, 300).includes("gracefulShutdown(")).toBe(true);
  });
});

describe("W124 G2: SIGINT triggers gracefulShutdown (PRESENT)", () => {
  test("cli.ts registers SIGINT handler that calls gracefulShutdown", () => {
    expect(CLI_SRC.includes('process.on("SIGINT"')).toBe(true);
    const sigintBlock = CLI_SRC.split('process.on("SIGINT"')[1] ?? "";
    expect(sigintBlock.slice(0, 300).includes("gracefulShutdown(")).toBe(true);
  });
});

describe("W124 G3: SIGHUP triggers log reopen (PARTIAL)", () => {
  test("cli.ts registers SIGHUP handler that calls logger.reopenLog", () => {
    expect(CLI_SRC.includes('process.on("SIGHUP"')).toBe(true);
    const sighupBlock = CLI_SRC.split('process.on("SIGHUP"')[1] ?? "";
    expect(sighupBlock.slice(0, 300).includes("reopenLog()")).toBe(true);
  });

  test("PARTIAL: reopenLog is a no-op because logFilePath is never set (see G14 / BUG-5)", () => {
    // logger.ts:155 — `if (!this.logFilePath) return;`
    // logFilePath has no CLI flag wiring (G14), so reopenLog always returns early.
    // This test asserts the current dead-helper state. Fix BUG-5 first, then this flips.
    expect(LOGGER_SRC.includes("if (!this.logFilePath) return;")).toBe(true);
    // CLI does not set logFilePath when constructing the Logger:
    const loggerCtor = CLI_SRC.split("new Logger({")[1]?.split("});")[0] ?? "";
    expect(loggerCtor.includes("logFilePath")).toBe(false);
  });
});

describe("W124 G4: SIGUSR1/SIGUSR2/SIGQUIT operator-dump signals (MISSING)", () => {
  test("MISSING: no SIGUSR1 handler", () => {
    expect(CLI_SRC.includes('"SIGUSR1"')).toBe(false);
    expect(CLI_SRC.includes("'SIGUSR1'")).toBe(false);
  });
  test("MISSING: no SIGUSR2 handler", () => {
    expect(CLI_SRC.includes('"SIGUSR2"')).toBe(false);
    expect(CLI_SRC.includes("'SIGUSR2'")).toBe(false);
  });
  test("MISSING: no SIGQUIT handler", () => {
    expect(CLI_SRC.includes('"SIGQUIT"')).toBe(false);
  });
});

describe("W124 G5: re-entrant shutdown guard (MISSING — BUG-1 P0)", () => {
  test("MISSING: gracefulShutdown has no `if (shuttingDown) return` early-exit", () => {
    // Extract the gracefulShutdown body.
    const fnStart = CLI_SRC.indexOf("async function gracefulShutdown");
    expect(fnStart).toBeGreaterThanOrEqual(0);
    const body = CLI_SRC.slice(fnStart, fnStart + 4000);
    // No `shuttingDown` / `shutdownInProgress` / `isShuttingDown` guard
    expect(/shuttingDown|shutdownInProgress|isShuttingDown|shutdownStarted/.test(body)).toBe(
      false
    );
    // Second SIGTERM during in-flight stop races against db.close + mempool dump
    // + fee_estimates.json write. BUG-1 asserts this current state.
  });
});

// ===========================================================================
// G6-G7: PID file
// ===========================================================================

describe("W124 G6: PID file written + removed (PRESENT)", () => {
  test("cli.ts has writePidFile + removePidFileSync helpers", () => {
    expect(CLI_SRC.includes("async function writePidFile")).toBe(true);
    expect(CLI_SRC.includes("function removePidFileSync")).toBe(true);
  });

  test("startNode calls writePidFile, gracefulShutdown calls removePidFileSync", () => {
    expect(CLI_SRC.includes("await writePidFile(pidPath)")).toBe(true);
    expect(CLI_SRC.includes("removePidFileSync(activePidPath)")).toBe(true);
  });

  test("--pid CLI flag accepted (default <datadir>/hotbuns.pid)", () => {
    const parsed = parseArgs(["bun", "cli.ts", "start", "--pid=/tmp/x.pid"]);
    expect(parsed.config.pid).toBe("/tmp/x.pid");
  });

  test("--pid= (empty) disables PID-file writing (Core parity)", () => {
    const parsed = parseArgs(["bun", "cli.ts", "start", "--pid="]);
    // Note: cli parser stores undefined when value is undefined; explicit empty
    // sets it. The startup code branches on === "" to set pidPath = null.
    expect(parsed.config.pid).toBe("");
  });
});

describe("W124 G7: PID file stale-PID liveness check (MISSING — BUG-2 LOW)", () => {
  test("writePidFile uses truncating write with no stale-PID check", () => {
    const fnStart = CLI_SRC.indexOf("async function writePidFile");
    const fnBody = CLI_SRC.slice(fnStart, fnStart + 500);
    // Uses { flag: "w" } — truncates whatever was there
    expect(fnBody.includes('flag: "w"')).toBe(true);
    // No kill(0, prevPid) liveness probe before overwriting
    expect(fnBody.includes("kill(")).toBe(false);
    expect(fnBody.includes("ESRCH")).toBe(false);
  });
});

// ===========================================================================
// G8-G10: Datadir
// ===========================================================================

describe("W124 G8: datadir double-start lock (MISSING — BUG-3 P0)", () => {
  test("MISSING: no LockDirectory / .lock / flock primitive anywhere in cli.ts", () => {
    expect(/LockDirectory|LockDataDir|\.lock\b|flock\(/.test(CLI_SRC)).toBe(false);
  });
  test("MISSING: no O_EXCL exclusive-create on a sentinel lockfile", () => {
    expect(/O_EXCL|EEXIST.*throw|EEXIST.*Error/i.test(CLI_SRC)).toBe(false);
  });
});

describe("W124 G9: datadir mkdir -p (PRESENT)", () => {
  test("loadConfig + startNode mkdir(datadir, recursive: true)", () => {
    expect(CLI_SRC.includes("fs.promises.mkdir(datadir, { recursive: true })")).toBe(true);
    expect(
      CLI_SRC.includes("fs.promises.mkdir(mergedConfig.datadir, { recursive: true })")
    ).toBe(true);
  });
});

describe("W124 G10: datadir mode 0700 hardening (MISSING — BUG-4 MED-SEC)", () => {
  test("mkdir calls do not pass an explicit mode", () => {
    // Look for `mkdir(...{ ..., mode: 0o700 ... })` — should be absent.
    expect(/mkdir\([^)]*mode:\s*0o?7/.test(CLI_SRC)).toBe(false);
  });
});

// ===========================================================================
// G11-G19: Logger
// ===========================================================================

describe("W124 G11: Logger has Core-style debug categories (PRESENT)", () => {
  test("Logger exports DEBUG_CATEGORIES covering net/p2p/mempool/rpc/validation/wallet/...", () => {
    // Re-import and instantiate to assert the surface.
    const l = new Logger({ level: "info", debugCategories: ["net", "p2p", "mempool"] });
    expect(l.isCategoryEnabled("net")).toBe(true);
    expect(l.isCategoryEnabled("mempool")).toBe(true);
    expect(l.isCategoryEnabled("nonexistent-category-xyz")).toBe(false);
  });

  test("ALL token enables every category (Core parity)", () => {
    const l = new Logger({ debugCategories: ["all"] });
    expect(l.isCategoryEnabled("net")).toBe(true);
    expect(l.isCategoryEnabled("wallet")).toBe(true);
    // even an unknown name returns true because allEnabled gates first
    expect(l.isCategoryEnabled("future-category")).toBe(true);
  });

  test("NONE token clears all enabled categories (Core parity)", () => {
    const l = new Logger({ debugCategories: ["all", "none"] });
    expect(l.isCategoryEnabled("net")).toBe(false);
  });
});

describe("W124 G12: --debug=<cat> CLI flag wired into Logger (PRESENT)", () => {
  test("parseArgs collects --debug=net + --debug=mempool", () => {
    const parsed = parseArgs([
      "bun",
      "cli.ts",
      "start",
      "--debug=net",
      "--debug=mempool",
    ]);
    expect(parsed.config.debug).toEqual(["net", "mempool"]);
  });

  test("parseArgs handles bare --debug (treated as 'all' per Core)", () => {
    const parsed = parseArgs(["bun", "cli.ts", "start", "--debug"]);
    expect(parsed.config.debug).toEqual(["all"]);
  });
});

describe("W124 G13: --printtoconsole flag wired (PRESENT)", () => {
  test("parseArgs sets printToConsole=true for bare flag", () => {
    const parsed = parseArgs(["bun", "cli.ts", "start", "--printtoconsole"]);
    expect(parsed.config.printToConsole).toBe(true);
  });
  test("parseArgs sets printToConsole=false for --printtoconsole=0", () => {
    const parsed = parseArgs(["bun", "cli.ts", "start", "--printtoconsole=0"]);
    expect(parsed.config.printToConsole).toBe(false);
  });
});

describe("W124 G14: --debuglogfile flag (MISSING — BUG-5 P0)", () => {
  test("MISSING: parseArgs does not recognise --debuglogfile", () => {
    const parsed = parseArgs([
      "bun",
      "cli.ts",
      "start",
      "--debuglogfile=/tmp/hotbuns.log",
    ]);
    // The unknown flag is silently dropped; NodeConfig has no logFilePath field.
    expect((parsed.config as unknown as Record<string, unknown>).logFilePath).toBeUndefined();
    expect((parsed.config as unknown as Record<string, unknown>).debugLogFile).toBeUndefined();
  });

  test("MISSING: Logger constructor in cli.ts:startNode does not pass logFilePath", () => {
    const ctorBlock = CLI_SRC.split("const logger = new Logger({")[1]?.split("});")[0] ?? "";
    expect(ctorBlock.length).toBeGreaterThan(0);
    expect(ctorBlock.includes("logFilePath")).toBe(false);
  });

  test("cascade: SIGHUP reopenLog is dead code in production (no file to reopen)", () => {
    // The reopenLog method bails on null logFilePath. Since startNode never
    // sets logFilePath, the SIGHUP handler in cli.ts:1454 is unreachable
    // useful work.
    const l = new Logger({ level: "info" }); // no logFilePath
    // reopenLog is safe to call without a file — it no-ops.
    expect(() => l.reopenLog()).not.toThrow();
  });
});

describe("W124 G15: getLogger() consumed by production modules (MISSING — BUG-6 P0)", () => {
  test("MISSING: no production module imports getLogger from logger/logger", () => {
    const srcDir = path.resolve(__dirname, "..");
    // Collect every .ts file under src/ excluding test files and the logger
    // module itself. Walk the tree manually (no glob dep available).
    function walk(dir: string, out: string[]): void {
      for (const ent of fs.readdirSync(dir, { withFileTypes: true })) {
        const full = path.join(dir, ent.name);
        if (ent.isDirectory()) {
          if (ent.name === "node_modules" || ent.name === "__tests__") continue;
          walk(full, out);
        } else if (
          ent.isFile() &&
          ent.name.endsWith(".ts") &&
          !ent.name.endsWith(".test.ts") &&
          !ent.name.endsWith(".d.ts")
        ) {
          out.push(full);
        }
      }
    }
    const files: string[] = [];
    walk(srcDir, files);

    let getLoggerImporters = 0;
    for (const file of files) {
      // skip the logger module itself
      if (file.endsWith("/logger/logger.ts")) continue;
      const txt = fs.readFileSync(file, "utf8");
      // Match `import { ... getLogger ... } from "..logger/logger`
      if (/import\s*\{[^}]*\bgetLogger\b[^}]*\}\s*from\s*["'][^"']*logger\/logger/.test(txt)) {
        getLoggerImporters++;
      }
    }
    // BUG-6: zero production importers
    expect(getLoggerImporters).toBe(0);
  });

  test("MISSING: setLogger is called once (cli.ts startup) — no consumer reads the singleton", () => {
    // The singleton exists but nothing uses it. We don't break this by asserting
    // a specific count; just confirm the import chain is one-way.
    expect(CLI_SRC.includes("import { Logger, setLogger }")).toBe(true);
    expect(CLI_SRC.includes("getLogger(")).toBe(false);
  });
});

describe("W124 G16: timestamps on every log line (PARTIAL)", () => {
  test("Logger.format prepends ISO-8601 timestamp", () => {
    const l = new Logger({ level: "info" });
    // We can't easily intercept stdout; assert the format() helper signature
    // by checking the source.
    expect(LOGGER_SRC.includes("new Date().toISOString()")).toBe(true);
    // sanity: calling info doesn't throw
    expect(() => l.info("x")).not.toThrow();
  });

  test("PARTIAL: 500+ console.log call sites bypass the logger and emit no timestamp prefix", () => {
    // Count console.log/error/warn occurrences across the whole src tree
    // (excluding test files and the compiled index.js).
    const srcDir = path.resolve(__dirname, "..");
    function walk(dir: string, out: string[]): void {
      for (const ent of fs.readdirSync(dir, { withFileTypes: true })) {
        const full = path.join(dir, ent.name);
        if (ent.isDirectory()) {
          if (ent.name === "node_modules" || ent.name === "__tests__") continue;
          walk(full, out);
        } else if (
          ent.isFile() &&
          ent.name.endsWith(".ts") &&
          !ent.name.endsWith(".test.ts")
        ) {
          out.push(full);
        }
      }
    }
    const files: string[] = [];
    walk(srcDir, files);
    let count = 0;
    for (const file of files) {
      const txt = fs.readFileSync(file, "utf8");
      // Match console.log( / console.error( / console.warn( call sites.
      const m = txt.match(/console\.(log|error|warn)\(/g);
      if (m) count += m.length;
    }
    // Production code is dominated by console.* calls. The Logger is dead.
    // BUG-6 cascade — this assertion locks in the current count's order of
    // magnitude. If a future wave migrates everything to the logger,
    // the threshold drops and this test breaks (which is the point).
    expect(count).toBeGreaterThan(200);
  });
});

describe("W124 G17: log rotation via SIGHUP reopen (PARTIAL)", () => {
  test("SIGHUP handler exists and calls reopenLog (G3)", () => {
    expect(CLI_SRC.includes("logger.reopenLog()")).toBe(true);
  });
  test("PARTIAL: combined gate is non-functional because logFilePath never set (G14)", () => {
    // This is the BUG-5 cascade — SIGHUP is wired but reopenLog returns early.
    expect(LOGGER_SRC.includes("if (!this.logFilePath) return;")).toBe(true);
  });
});

describe("W124 G18: -logips flag for peer-address privacy (MISSING)", () => {
  test("MISSING: no --logips CLI flag", () => {
    const parsed = parseArgs(["bun", "cli.ts", "start", "--logips=1"]);
    expect((parsed.config as unknown as Record<string, unknown>).logIps).toBeUndefined();
  });
  test("MISSING: peer addresses currently appear unconditionally in some logs", () => {
    // cli.ts unsolicited-cfilter logs the host:port of the peer — no -logips gate.
    expect(CLI_SRC.includes("peer.host}:${peer.port}")).toBe(true);
  });
});

describe("W124 G19: --loglevel=<cat>:<level> per-category level (MISSING)", () => {
  test("MISSING: Logger has a single global level only", () => {
    // logger.ts exposes setLevel(level) but no setCategoryLevel.
    expect(LOGGER_SRC.includes("setLevel(")).toBe(true);
    expect(/setCategoryLevel|setCategoryLogLevel/.test(LOGGER_SRC)).toBe(false);
  });
});

// ===========================================================================
// G20-G24: RPC server (auth, bind, TLS)
// ===========================================================================

describe("W124 G20: cookie file written + removed (PRESENT)", () => {
  test("rpc/server.ts writes <datadir>/.cookie with __cookie__:<hex>", () => {
    expect(RPC_SRC.includes("`__cookie__:${this.cookiePassword}`")).toBe(true);
    expect(RPC_SRC.includes('".cookie"')).toBe(true);
  });
  test("stop() unlinks the cookie file", () => {
    // Look inside the `stop()` body.
    const stopBlock = RPC_SRC.split("  stop(): void {")[1]?.split("\n  }")[0] ?? "";
    expect(stopBlock.includes("unlink(this.cookiePath")).toBe(true);
  });
});

describe("W124 G21: cookie file 0600 mode (MISSING — BUG-7 HIGH-SEC)", () => {
  test("MISSING: Bun.write(cookiePath, ...) is not followed by chmod 0o600", () => {
    // Look at the cookie-write region in server.ts.
    const idx = RPC_SRC.indexOf("Bun.write(this.cookiePath");
    expect(idx).toBeGreaterThanOrEqual(0);
    const region = RPC_SRC.slice(idx, idx + 800);
    // No chmod / fchmod / mode option in this region.
    expect(/chmod\(|fs\.chmod|fchmod\(|mode:\s*0o?6/.test(region)).toBe(false);
  });
});

describe("W124 G22: RPC bind defaults to 127.0.0.1 (PRESENT)", () => {
  test("RPC server constructed with host='127.0.0.1'", () => {
    expect(CLI_SRC.includes('host: "127.0.0.1"')).toBe(true);
    expect(RPC_SRC.includes('host: config.host ?? "127.0.0.1"')).toBe(true);
  });
});

describe("W124 G23: --rpcbind / --rpcallowip operator surface (MISSING — BUG-8 LOW)", () => {
  test("MISSING: no --rpcbind CLI flag", () => {
    const parsed = parseArgs([
      "bun",
      "cli.ts",
      "start",
      "--rpcbind=10.0.0.1:8332",
    ]);
    expect((parsed.config as unknown as Record<string, unknown>).rpcBind).toBeUndefined();
    expect((parsed.config as unknown as Record<string, unknown>).rpcbind).toBeUndefined();
  });
  test("MISSING: no --rpcallowip CLI flag", () => {
    const parsed = parseArgs([
      "bun",
      "cli.ts",
      "start",
      "--rpcallowip=10.0.0.0/24",
    ]);
    expect((parsed.config as unknown as Record<string, unknown>).rpcAllowIp).toBeUndefined();
    expect((parsed.config as unknown as Record<string, unknown>).rpcallowip).toBeUndefined();
  });
});

describe("W124 G24: HTTPS RPC TLS termination (PRESENT — FIX-64)", () => {
  test("--rpc-tls-cert and --rpc-tls-key flags wired", () => {
    const parsed = parseArgs([
      "bun",
      "cli.ts",
      "start",
      "--rpc-tls-cert=/etc/ssl/c.pem",
      "--rpc-tls-key=/etc/ssl/k.pem",
    ]);
    expect(parsed.config.rpcTlsCert).toBe("/etc/ssl/c.pem");
    expect(parsed.config.rpcTlsKey).toBe("/etc/ssl/k.pem");
  });
  test("fail-loud on partial config (cert without key)", () => {
    // The fail-loud lives in RPCServer constructor.
    expect(RPC_SRC.includes("RPC TLS configuration error")).toBe(true);
    expect(RPC_SRC.includes("must both be provided")).toBe(true);
  });
});

// ===========================================================================
// G25-G27: Metrics + /health
// ===========================================================================

describe("W124 G25: /health liveness endpoint (PRESENT)", () => {
  test("metrics server fetch handler responds to /health with JSON status", () => {
    expect(CLI_SRC.includes('url.pathname === "/health"')).toBe(true);
    // Body must contain a status + pid for supervisor probes.
    const healthBlock = CLI_SRC.split('url.pathname === "/health"')[1]?.slice(0, 500) ?? "";
    expect(healthBlock.includes("status:")).toBe(true);
    expect(healthBlock.includes("pid: process.pid")).toBe(true);
  });
});

describe("W124 G26: Prometheus /metrics endpoint (PRESENT)", () => {
  test("metrics server emits text/plain Prometheus format", () => {
    expect(CLI_SRC.includes("bitcoin_blocks_total")).toBe(true);
    expect(CLI_SRC.includes("bitcoin_peers_connected")).toBe(true);
    expect(CLI_SRC.includes("bitcoin_mempool_size")).toBe(true);
    expect(
      CLI_SRC.includes(
        '"Content-Type": "text/plain; version=0.0.4; charset=utf-8"'
      )
    ).toBe(true);
  });
});

describe("W124 G27: metrics bind defaults to localhost (MISSING — BUG-9 LOW)", () => {
  test("MISSING: metrics server hardcodes hostname='0.0.0.0'", () => {
    // Anchor on the comment that precedes the metrics Bun.serve block and
    // walk forward 1500 chars to span the serve config object (includes
    // the hostname property at cli.ts:2164).
    const idx = CLI_SRC.indexOf("Start Prometheus metrics server");
    expect(idx).toBeGreaterThanOrEqual(0);
    const region = CLI_SRC.slice(idx, idx + 1500);
    expect(region.includes('hostname: "0.0.0.0"')).toBe(true);
    expect(region.includes('hostname: "127.0.0.1"')).toBe(false);
  });
});

// ===========================================================================
// G28-G30: Supervisor / external integration
// ===========================================================================

describe("W124 G28: --ready-fd supervisor handshake (PRESENT)", () => {
  test("parseArgs accepts --ready-fd=N", () => {
    const parsed = parseArgs(["bun", "cli.ts", "start", "--ready-fd=3"]);
    expect(parsed.config.readyFd).toBe(3);
  });
  test("startNode writes 'ready\\n' to the ready-fd after start completes", () => {
    expect(CLI_SRC.includes('fs.writeSync(mergedConfig.readyFd, "ready\\n")')).toBe(
      true
    );
  });
});

describe("W124 G29: --daemon fork-exit + re-exec child (PRESENT)", () => {
  test("--daemon CLI flag parsed", () => {
    const parsed = parseArgs(["bun", "cli.ts", "start", "--daemon"]);
    expect(parsed.config.daemon).toBe(true);
  });
  test("daemonizeAndExit re-execs self with --internal-daemon-child", () => {
    expect(CLI_SRC.includes("function daemonizeAndExit")).toBe(true);
    expect(CLI_SRC.includes('"--internal-daemon-child"')).toBe(true);
    expect(CLI_SRC.includes('stdio: ["ignore", "ignore", "ignore"]')).toBe(true);
  });
});

describe("W124 G30: -startupnotify / -shutdownnotify hooks (MISSING)", () => {
  test("MISSING: no --startupnotify CLI flag", () => {
    const parsed = parseArgs([
      "bun",
      "cli.ts",
      "start",
      "--startupnotify=/usr/bin/touch /tmp/hotbuns-up",
    ]);
    expect((parsed.config as unknown as Record<string, unknown>).startupNotify)
      .toBeUndefined();
  });
  test("MISSING: no --shutdownnotify CLI flag", () => {
    const parsed = parseArgs([
      "bun",
      "cli.ts",
      "start",
      "--shutdownnotify=/usr/bin/touch /tmp/hotbuns-down",
    ]);
    expect((parsed.config as unknown as Record<string, unknown>).shutdownNotify)
      .toBeUndefined();
  });
  test("MISSING: gracefulShutdown does not exec any operator hook", () => {
    const fnStart = CLI_SRC.indexOf("async function gracefulShutdown");
    const body = CLI_SRC.slice(fnStart, fnStart + 4000);
    expect(/spawn|exec|fork/.test(body.replace(/\/\/.*/g, ""))).toBe(false);
  });
});

// ===========================================================================
// CROSS-CUTTING: launcher mismatch documented in CLAUDE.md
// ===========================================================================

describe("W124 cross-cutting: launcher mismatch (testnet4 vs mainnet)", () => {
  test("hotbuns source uses Bun-specific APIs", () => {
    // Sanity: the production code is Bun-only, so node src/index.js (used
    // by start_testnet4.sh) would crash at first Bun.* call. We don't
    // fix the launcher here — this is the audit-recording test.
    expect(CLI_SRC.includes("Bun.spawn") || CLI_SRC.includes("Bun.serve")).toBe(true);
  });
});

// ===========================================================================
// Module sanity: avoid an unused-import warning.
// ===========================================================================
test("W124: getLogger + setLogger are exported (singleton wiring is still public API)", () => {
  // We don't call setLogger from here (it would clobber the singleton for
  // other tests). Just assert the imports resolved.
  expect(typeof getLogger).toBe("function");
  expect(typeof setLogger).toBe("function");
  expect(typeof Logger).toBe("function");
});
