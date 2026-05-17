# W124 — Operator-experience audit (hotbuns)

**Impl:** hotbuns (TypeScript / Bun)
**Date:** 2026-05-17
**Status:** DISCOVERY (no production code changes)
**Test file:** `src/__tests__/w124_operator.test.ts`
**Reference:** bitcoin-core `src/init.cpp`, `src/util/fs_helpers.cpp` (LockDirectory), `src/logging.{cpp,h}`

## Motivation

W124 is the project-wide W124 operator-experience audit. The goal is to
characterise how hotbuns behaves for the **node operator** — the person
running the process under systemd/docker/launchd or restarting it on
maxbox — independent of consensus correctness. Most consensus-correct
implementations still ship operator pitfalls (silent re-exec on stale
PID, double-launch races, log files that never rotate, signal handlers
that swallow exceptions in shutdown). hotbuns has a documented
cross-launcher mismatch in `CLAUDE.md` already; W124 maps the rest of
the surface.

The audit gates were derived from:

- `bitcoin-core/src/init.cpp` — `CreatePidFile`, `RemovePidFile`,
  `LockDataDirectory`, `-startupnotify` / `-shutdownnotify` hooks,
  `-printtoconsole` / `-debuglogfile` / `-shrinkdebugfile`,
  `-rpcallowip` / `-rpcbind`.
- `bitcoin-core/src/logging.{cpp,h}` — `-logips`, `-logtimestamps`,
  `-logthreadnames`, `-logsourcelocations`, `-loglevel` per-category.
- `bitcoin-core/src/util/fs_helpers.cpp` — `LockDirectory` /
  `UnlockDirectory` (the datadir `.lock` file double-start guard).
- root `CLAUDE.md` "Ops (mainnet fleet)" — the launcher /stopper
  helpers and the W10 beamchain SIGTERM lesson.
- root `CLAUDE.md` hotbuns gotchas — launcher mismatch + ZeroMQ NIF.

## Method

`grep -rn "shutdown|SIGTERM|process.on|pidfile|datadir|cookie|logger|log\." src/`
then read `src/cli/cli.ts` (startup + shutdown + daemonise + PID),
`src/logger/logger.ts` (Logger surface), `src/rpc/server.ts` (cookie +
bind + TLS + auth). Compared against the same paths in
`bitcoin-core/src/init.cpp` and the project ops conventions in
`CLAUDE.md`. Xfail-style tests in
`src/__tests__/w124_operator.test.ts` lock in current behavior for
every PARTIAL/MISSING gate so future drive-by stubs trip a failing
expect() before they merge.

## Gate matrix (30)

Status legend: P = PRESENT, p = PARTIAL, M = MISSING.

| # | Area | Gate | Status | Notes |
|---|------|------|--------|-------|
| G1 | Signals | SIGTERM handler invokes graceful shutdown | P | `cli.ts:2130-2133` |
| G2 | Signals | SIGINT handler invokes graceful shutdown | P | `cli.ts:2125-2128` |
| G3 | Signals | SIGHUP triggers log file reopen (logrotate parity) | P | `cli.ts:1454-1457` calls `logger.reopenLog()`; **but** logger.logFilePath is never set in production (G14), so it's a no-op |
| G4 | Signals | SIGQUIT or SIGUSR1/2 handled (e.g. crash dump, on-demand state dump) | M | No handler registered. Core's util/syserror does not register these either, but Core ships a wallet+block-state dump under SIGUSR1 in production deployments via shutdownnotify scripts |
| G5 | Signals | Re-entrant shutdown guard (double SIGTERM → only one gracefulShutdown runs) | M | `gracefulShutdown` has no `if (shuttingDown) return` early-exit; second signal during stop races against the in-flight DB close and mempool-dump (BUG-1 P0) |
| G6 | PID file | Written on start, removed on shutdown | P | `cli.ts:1265,1276` (writePidFile/removePidFileSync); honors `--pid=<path>` and empty-string-disables |
| G7 | PID file | Atomic write + stale-PID check (process not running) | M | `writeFile(..., flag: "w")` truncates on top of any existing file. **No check whether the existing PID is alive.** A crashed prior instance leaves a stale `hotbuns.pid` — the new node silently overwrites it (BUG-2 LOW; Core's `CreatePidFile` does no liveness check either but Core's `LockDataDirectory` catches this) |
| G8 | Datadir | Double-start guard via lockfile (`.lock` / flock) | M | hotbuns has **no datadir lock at all**. Two concurrent `hotbuns start --datadir=…` invocations on the same dir corrupt the LevelDB underneath (BUG-3 P0) |
| G9 | Datadir | mkdir -p on startup, recursive | P | `cli.ts:654` `fs.promises.mkdir(datadir, { recursive: true })` |
| G10 | Datadir | Datadir permissions tightened (0700) on creation | M | mkdir uses default umask — readable by other local users (BUG-4 MED-SECURITY: cookie + wallet.dat live there) |
| G11 | Logger | Logger class exists with Core-style debug categories | P | `logger/logger.ts:24-57`, 32 categories matching Core's LogFlags |
| G12 | Logger | `--debug=<cat>` repeatable flag wired into Logger | P | `cli.ts:480-491` (CLI) → `Logger.debugCategories` |
| G13 | Logger | `--printtoconsole` flag wired | P | `cli.ts:470-479` |
| G14 | Logger | `--debuglogfile=<path>` flag (logfile redirection) | M | Logger has `logFilePath` option (`logger.ts:71`) but **no CLI flag**. SIGHUP-reopen (G3) is therefore dead code in production (BUG-5 P0). 518 `console.log/error/warn` call sites bypass the Logger entirely |
| G15 | Logger | `getLogger()` consumed by production modules | M | Singleton exists (`logger.ts:224-233`) but **zero production callers** outside `cli.ts:setLogger`. Module count using `console.*`: 50+; modules using `getLogger`: 0 (BUG-6 P0). Two parallel logging systems |
| G16 | Logger | Timestamps on every line | p | `Logger.format()` prepends ISO-8601 timestamp — **but** 518 direct `console.log` calls have no timestamp prefix, so logs are unprefixed in practice |
| G17 | Logger | Log file rotation (`-shrinkdebugfile` / external logrotate via SIGHUP) | p | SIGHUP wired (G3) but logfile not wired (G14) — combined gate is non-functional |
| G18 | Logger | `-logips` Core-parity flag (default off) | M | No such flag. Peer addresses appear in some `console.log` lines unconditionally (e.g. `cli.ts:2027-2033` cfilter peer logs) — privacy-sensitive |
| G19 | Logger | `-loglevel=<cat>:<level>` per-category level | M | hotbuns has a single global level only (`Logger.level`) |
| G20 | RPC | Cookie auth file written + removed on shutdown | P | `rpc/server.ts:638-650` writes `__cookie__:<hex>` to `<datadir>/.cookie`; `stop()` unlinks it |
| G21 | RPC | Cookie file permissions tightened (0600) | M | Bun.write does not set explicit mode → falls back to umask default (0644). Other users on the host can read RPC creds (BUG-7 HIGH-SECURITY) |
| G22 | RPC | Bind defaults to 127.0.0.1 | P | `cli.ts:2039` hardcoded `host: "127.0.0.1"`. Cannot be overridden — no `--rpcbind` flag |
| G23 | RPC | `--rpcbind` + `--rpcallowip` operator surface | M | Neither flag exists. Operators wanting RPC bound to a private IP for a remote control client can't do it from CLI without editing source (BUG-8 LOW) |
| G24 | RPC | TLS termination (HTTPS RPC) | P | FIX-64 `--rpc-tls-cert` + `--rpc-tls-key` (cli.ts:570-582, server.ts:638-679). Fail-loud on partial config |
| G25 | Metrics | `/health` liveness probe | P | `cli.ts:2169-2184` JSON `{ status, network, height, peers, pid }` on metrics port |
| G26 | Metrics | Prometheus `/metrics` endpoint | P | `cli.ts:2188-2202` standard text/plain with `bitcoin_blocks_total`, `bitcoin_peers_connected`, `bitcoin_mempool_size` |
| G27 | Metrics | Metrics bind defaults to localhost | M | `cli.ts:2164` hardcoded `hostname: "0.0.0.0"`. Metrics + `/health` expose `pid` + node identity world-readable on default install (BUG-9 LOW; Core ships no built-in metrics, so this is a hotbuns addition that defaulted to public) |
| G28 | Supervisor | `--ready-fd` for sd_notify-style ready handshake | P | `cli.ts:2216-2225`, writes `"ready\n"` once start completes |
| G29 | Supervisor | `--daemon` fork-exit + re-exec child | P | `cli.ts:1232-1258` `daemonizeAndExit`; uses Bun.spawn detached |
| G30 | Supervisor | `-startupnotify` / `-shutdownnotify` external-command hooks | M | Core ships both (init.cpp:529-530). hotbuns has neither — operators wanting an "alert when shutdown begins" hook must wrap with systemd ExecStopPost or equivalent |

PRESENT: **15** / PARTIAL: **3** / MISSING: **12**

## Findings (9 bugs)

### BUG-1 (P0) Re-entrant shutdown race
`gracefulShutdown` (cli.ts:2237) has no `if (shuttingDown) return` guard.
Second SIGTERM during in-flight stop races against:
- `db.close()` (line 2299) — LevelDB double-close throws
- `dumpMempool` (line 2286) — duplicate write to `mempool.dat`
- `feeEstimator.serialize` (line 2275) — duplicate write
- `removePidFileSync` (line 2302) — second unlink is harmless

Operator impact: `bash tools/stop_mainnet.sh hotbuns` may double-fire on
a hung shutdown; this can leave a half-written mempool.dat or fee_estimates.json.

### BUG-2 (LOW) Stale PID file silently overwritten
`writePidFile` (cli.ts:1265) uses `flag: "w"` (truncate-create). If a
prior crashed instance left `hotbuns.pid` containing PID N, a fresh
start overwrites it without checking whether PID N is still alive.

Compounded by absence of a datadir lock (BUG-3), an operator can
unknowingly run two hotbuns instances pointing at the same datadir if
the first crashed without removing the PID file.

### BUG-3 (P0) No datadir lock — concurrent-start corruption
hotbuns has no equivalent of Core's `LockDataDirectory` (util/fs_helpers.cpp).
Two concurrent `hotbuns start --datadir=/foo` invocations both:
- open the same LevelDB at `/foo/blocks.db`
- write to the same `/foo/.cookie`
- attempt to bind the same RPC port (one will fail, but datadir is shared)

LevelDB's own lockfile catches the DB clobber, but the cookie+pid+log
file races still happen, and the second instance partially boots before
hitting the LevelDB lock. This is the operator footgun the start_mainnet.sh
"refuse if port bound" check exists to prevent (CLAUDE.md "Ops"), but
there is no in-process equivalent.

### BUG-4 (MED-SECURITY) Datadir mkdir default umask
`fs.promises.mkdir(datadir, { recursive: true })` (cli.ts:654, 1447)
uses default umask, typically `0755`. On multi-user hosts the
`<datadir>/wallet.dat`, `<datadir>/.cookie`, `<datadir>/hotbuns.conf`
(plaintext rpcpassword) are readable by every other local user.

Core does not chmod 0700 the datadir either; this is a "harden vs Core"
gate rather than a Core-parity gate, but every fleet impl on maxbox
shares the same single-user (`work`) so the gap is dormant in
production today.

### BUG-5 (P0) `--debuglogfile` flag is missing — logger.reopenLog is dead code
`Logger` accepts `logFilePath` (logger.ts:71) and implements SIGHUP
re-open (logger.ts:154). But **no CLI flag plumbs `logFilePath`**.
Result: SIGHUP handler (cli.ts:1454) calls `logger.reopenLog()`, which
returns at line 155 because `logFilePath` is null. logrotate-style log
rotation is unreachable in production.

This is a dead-helper-at-call-site pattern (W117/W121 universal):
infrastructure exists, the wiring step is missing.

### BUG-6 (P0) Logger singleton has zero production callers
`getLogger()` is exported (logger.ts:232) and unused. Production code
uses `console.log` / `console.error` / `console.warn` (518 call sites
across `src/`). Result:
- `--log-level` filters nothing in production
- `--debug=<cat>` enables nothing in production
- timestamps are missing from every line
- log file redirection (when wired per BUG-5) would still bypass the logger

Two parallel logging systems: a fully-Core-parity Logger class that no
one calls, and the de-facto `console.*` system that ignores every
operator flag.

### BUG-7 (HIGH-SECURITY) Cookie file 0644
`Bun.write(cookiePath, "__cookie__:<hex>")` (rpc/server.ts:646) does
not pass a mode option (Bun.write doesn't support one in the current
release). Result: cookie inherits default umask, typically world-readable.

Other local users on the host can read `<datadir>/.cookie`, present a
`Authorization: Basic __cookie__:<hex>` header, and issue full RPC
including `stop`, `sendrawtransaction`, wallet operations.

Mitigation today: `chmod 0600 .cookie` post-startup, but that's racy
against the cookie write.

### BUG-8 (LOW) `--rpcbind` / `--rpcallowip` operator surface absent
RPC server hardcodes `host: "127.0.0.1"` (cli.ts:2039). No CLI/config
override. Operators using a private NIC for control-plane RPC must
front the listener with nginx or socat. Acceptable hardening trade-off;
flagged for completeness.

### BUG-9 (LOW) Metrics binds `0.0.0.0` by default
`Bun.serve({ hostname: "0.0.0.0" })` at cli.ts:2164. `/health` exposes
PID + node identity (network + tip height + peer count), `/metrics`
exposes detailed counters. On a multi-host LAN this is a discoverability
liability — Core ships no built-in metrics endpoint, so this is a
hotbuns-only addition that defaulted to public. Compare ouroboros's
`127.0.0.1` default for the same endpoint.

## Universal patterns observed

1. **Dead-helper-at-call-site (W117/W121 universal, 33rd-wave streak):**
   - `Logger.logFilePath` exists, no CLI flag (BUG-5)
   - `logger.reopenLog` exists, called from SIGHUP, no-ops because
     logFilePath is null (BUG-5 cascade)
   - `getLogger()` exists, zero production callers (BUG-6)

2. **Well-engineered codec, gaps at system edges (W121 universal):**
   The Logger class itself is faithful to Core's LogFlags surface (32
   categories, level taxonomy, SIGHUP re-open semantics). The gap is
   not in the codec — it's in the wiring to the rest of the codebase.

3. **Comment-as-confession (W120 11th-wave streak):**
   - cli.ts:117 — `// equivalent to systemd's Type=notify ... but minimal`
     (this is fine, ready-fd is genuinely minimal)
   - cli.ts:1499-1511 — multi-line block comment explaining that
     `--prune=1` is "RPC-only" with no actual enforcement in
     ChainStateManager (RPC stub exists)

4. **Cross-launcher mismatch (CLAUDE.md gotchas, not new):**
   - `start_testnet4.sh:115` uses `node src/index.js` (broken — Bun
     APIs unavailable under Node)
   - `tools/start_mainnet.sh:61` uses `bun run src/index.ts` (correct)
   - `tools/smoke-harness.sh:311` uses `bun run src/index.ts` (correct)
   The testnet4 launcher would crash on first `Bun.connect` / `Bun.serve`
   call. Surfaced here as W124 audit context because the launcher
   inconsistency is an operator footgun (operator following README +
   running testnet4 wave gets different runtime than mainnet).

## Cross-impl reference (predictions)

W124 expected universal patterns based on prior W12x waves:
- **Re-entrant shutdown race (BUG-1):** likely fleet-wide. Signal handlers
  rarely include the `if (shuttingDown) return` guard.
- **Datadir lock missing (BUG-3):** ouroboros / lunarblock / nimrod likely.
  Core, rustoshi, blockbrew almost certainly have one.
- **Logger dead-helper (BUG-5/6):** likely 4-6 of 10 impls. Most languages
  ship a Logger, fewer ship `--debuglogfile`-equivalent CLI wiring.
- **Cookie 0644 (BUG-7):** likely 3-5 of 10. Depends on whether each impl's
  file-write API exposes mode (Bun does not in current release).

## Files

- `src/__tests__/w124_operator.test.ts` — xfail-style tests asserting
  every PARTIAL/MISSING gate's current behavior, so a future drive-by
  fix trips a failing `expect()` before merging.
- `audit/w124_operator_experience.md` — this file.

## Verification

Run: `bun test src/__tests__/w124_operator.test.ts`

All 9 BUGs are asserted as xfail (`expect(brokenBehavior).toBe(true)`).
When a future commit fixes BUG-N, the corresponding test flips to
`expect(...).toBe(false)` (or the assertion is removed entirely),
locking in the fix.

## References

- bitcoin-core `src/init.cpp` lines 183-209 (CreatePidFile / RemovePidFile)
- bitcoin-core `src/init.cpp` lines 252-264 (ShutdownNotify)
- bitcoin-core `src/init.cpp` lines 529-530 (-startupnotify / -shutdownnotify)
- bitcoin-core `src/util/fs_helpers.cpp` lines 38-45 (LockDirectory)
- bitcoin-core `src/logging.h` lines 27-32 (DEFAULT_LOG* defaults)
- CLAUDE.md "Ops (mainnet fleet)" — start_mainnet.sh / stop_mainnet.sh
- CLAUDE.md "Known Issues" — hotbuns launcher mismatch + ZeroMQ NIF
- src/cli/cli.ts startup pipeline (lines 1404-2232)
- src/cli/cli.ts shutdown pipeline (lines 2237-2308)
- src/logger/logger.ts (full file, 234 LOC)
- src/rpc/server.ts cookie+TLS plumbing (lines 638-710)
