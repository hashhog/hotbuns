/**
 * W140 — HTTP server + rpcauth + cookie auth + JSON-RPC dispatch audit (hotbuns).
 *
 * Discovery wave. Locks in current behavior for every PARTIAL/MISSING
 * gate so a future drive-by stub trips a failing expect() before merge.
 *
 * Status legend at the foot of each test:
 *   PRESENT  — covered behavior matches expected Core-parity surface
 *   PARTIAL  — partially present (e.g. infrastructure exists, wiring missing)
 *   MISSING  — feature absent in production code
 *
 * References:
 *   - bitcoin-core/src/httpserver.cpp + httpserver.h (HTTPBindAddresses,
 *     ClientAllowed, MAX_HEADERS_SIZE, MAX_SIZE, evhttp_set_timeout,
 *     -rpcthreads / -rpcworkqueue / -rpcservertimeout defaults)
 *   - bitcoin-core/src/httprpc.cpp (CheckUserAuthorized HMAC-SHA256,
 *     TimingResistantEqual, 250ms brute-force sleep, rpcauth/rpcwhitelist,
 *     WWW-Authenticate header, HTTP_NO_CONTENT for notifications)
 *   - bitcoin-core/src/rpc/request.cpp (COOKIEAUTH_USER `__cookie__`,
 *     GenerateAuthCookie, umask 0077, -rpccookieperms, DeleteAuthCookie)
 *   - bitcoin-core/share/rpcauth/rpcauth.py (HMAC-SHA256 salt+hash format
 *     `user:salt$hash`)
 *   - bitcoin-core/src/init.cpp (-rpcbind, -rpcallowip, -rpcauth,
 *     -rpcwhitelist, -rpccookiefile, -rpccookieperms)
 *
 * Test file pairs with: audit/w140_http_rpcauth.md
 *
 * Run: bun test src/__tests__/w140_http_rpcauth.test.ts
 */

import { describe, expect, test } from "bun:test";
import * as fs from "fs";
import * as path from "path";

import { parseArgs } from "../cli/cli.js";

// ---------------------------------------------------------------------------
// Read CLI + RPC server source for static-analysis assertions. We use the
// `.ts` source because production code is what we audit; the compiled
// `src/index.js` is a build artifact that may lag.
// ---------------------------------------------------------------------------
const RPC_SRC = fs.readFileSync(
  path.resolve(__dirname, "..", "rpc", "server.ts"),
  "utf8"
);
const CLI_SRC = fs.readFileSync(
  path.resolve(__dirname, "..", "cli", "cli.ts"),
  "utf8"
);

// ===========================================================================
// G1-G4: Bind + ACL surface
// ===========================================================================

describe("W140 G1: RPC default bind is 127.0.0.1 (PRESENT)", () => {
  test("RPCServer config default host is 127.0.0.1", () => {
    expect(RPC_SRC.includes('host: config.host ?? "127.0.0.1"')).toBe(true);
  });
  test("cli.ts constructs RPCServer with host: '127.0.0.1'", () => {
    expect(CLI_SRC.includes('host: "127.0.0.1"')).toBe(true);
  });
});

describe("W140 G2: --rpcbind operator surface (MISSING — BUG-1 LOW)", () => {
  test("MISSING: no --rpcbind CLI flag", () => {
    const parsed = parseArgs([
      "bun",
      "cli.ts",
      "start",
      "--rpcbind=10.0.0.1:8332",
    ]);
    expect(
      (parsed.config as unknown as Record<string, unknown>).rpcBind
    ).toBeUndefined();
    expect(
      (parsed.config as unknown as Record<string, unknown>).rpcbind
    ).toBeUndefined();
  });
  test("MISSING: cli.ts loadConfig does not parse rpcbind=", () => {
    expect(CLI_SRC.includes('case "rpcbind"')).toBe(false);
    expect(CLI_SRC.includes('case "rpc-bind"')).toBe(false);
  });
});

describe("W140 G3: --rpcallowip ACL list (MISSING — BUG-2 MED-SEC)", () => {
  test("MISSING: no --rpcallowip CLI flag", () => {
    const parsed = parseArgs([
      "bun",
      "cli.ts",
      "start",
      "--rpcallowip=10.0.0.0/24",
    ]);
    expect(
      (parsed.config as unknown as Record<string, unknown>).rpcAllowIp
    ).toBeUndefined();
    expect(
      (parsed.config as unknown as Record<string, unknown>).rpcallowip
    ).toBeUndefined();
  });
  test("MISSING: no ClientAllowed / subnet check in handleRequest", () => {
    // Look at handleRequest body for any subnet / CIDR / clientAllowed logic.
    const idx = RPC_SRC.indexOf("private async handleRequest");
    expect(idx).toBeGreaterThanOrEqual(0);
    const region = RPC_SRC.slice(idx, idx + 4000);
    expect(/ClientAllowed|allowSubnets|allowSubnet|isAllowed\(/i.test(region)).toBe(
      false
    );
  });
});

describe("W140 G4: rpcbind-without-rpcallowip rule (MISSING — neither flag exists)", () => {
  test("MISSING: no warning about --rpcbind without --rpcallowip", () => {
    // Core httpserver.cpp:319-327 logs a warning. hotbuns has neither flag
    // and therefore no warning logic.
    expect(CLI_SRC.includes("rpcbind without rpcallowip")).toBe(false);
    expect(CLI_SRC.includes("rpcallowip without rpcbind")).toBe(false);
  });
});

// ===========================================================================
// G5-G11: Cookie file surface
// ===========================================================================

describe("W140 G5: cookie file written with __cookie__:<hex> (PRESENT)", () => {
  test("rpc/server.ts writes <datadir>/.cookie with __cookie__:<hex>", () => {
    expect(RPC_SRC.includes("`__cookie__:${this.cookiePassword}`")).toBe(true);
    expect(RPC_SRC.includes('".cookie"')).toBe(true);
  });
  test("32 random bytes via crypto.getRandomValues + hex encoding", () => {
    expect(RPC_SRC.includes("crypto.getRandomValues(new Uint8Array(32))")).toBe(
      true
    );
    expect(RPC_SRC.includes('.toString("hex")')).toBe(true);
  });
});

describe("W140 G6: cookie file unlinked on shutdown (PRESENT)", () => {
  test("stop() unlinks the cookie file", () => {
    const stopBlock =
      RPC_SRC.split("  stop(): void {")[1]?.split("\n  }")[0] ?? "";
    expect(stopBlock.includes("unlink(this.cookiePath")).toBe(true);
  });
});

describe("W140 G7: cookie file 0600 mode (MISSING — BUG-3 HIGH-SEC)", () => {
  test("MISSING: Bun.write(cookiePath, ...) is not followed by chmod 0o600", () => {
    const idx = RPC_SRC.indexOf("Bun.write(this.cookiePath");
    expect(idx).toBeGreaterThanOrEqual(0);
    const region = RPC_SRC.slice(idx, idx + 800);
    // No chmod / fchmod / explicit mode option in this region.
    expect(/chmod\(|fs\.chmod|fchmod\(|mode:\s*0o?6/.test(region)).toBe(false);
  });
  test("MISSING: no fs.chmodSync(cookiePath, 0o600) anywhere in server.ts", () => {
    expect(/chmodSync\(\s*this\.cookiePath/.test(RPC_SRC)).toBe(false);
  });
});

describe("W140 G8: cookie write is atomic (.tmp + rename) (MISSING)", () => {
  test("MISSING: no .cookie.tmp + rename atomic pattern", () => {
    // Core writes to filepath_tmp then RenameOver. hotbuns writes directly.
    expect(RPC_SRC.includes(".cookie.tmp")).toBe(false);
    // The cookie write region should not contain a rename / renameSync call.
    const idx = RPC_SRC.indexOf("Bun.write(this.cookiePath");
    expect(idx).toBeGreaterThanOrEqual(0);
    const region = RPC_SRC.slice(idx, idx + 800);
    expect(/fs\.rename|renameSync\(/.test(region)).toBe(false);
  });
});

describe("W140 G9: --rpccookiefile=<path> override (MISSING — BUG-4 LOW)", () => {
  test("MISSING: no --rpccookiefile CLI flag", () => {
    const parsed = parseArgs([
      "bun",
      "cli.ts",
      "start",
      "--rpccookiefile=/tmp/x.cookie",
    ]);
    expect(
      (parsed.config as unknown as Record<string, unknown>).rpcCookieFile
    ).toBeUndefined();
    expect(
      (parsed.config as unknown as Record<string, unknown>).rpccookiefile
    ).toBeUndefined();
  });
});

describe("W140 G10: -norpccookiefile disable flag (MISSING)", () => {
  test("MISSING: cli.ts has no norpccookiefile parse path", () => {
    expect(CLI_SRC.includes("norpccookiefile")).toBe(false);
    expect(CLI_SRC.includes("no-rpc-cookie-file")).toBe(false);
  });
});

describe("W140 G11: -rpccookieperms={owner,group,all} (MISSING)", () => {
  test("MISSING: no --rpccookieperms CLI flag", () => {
    const parsed = parseArgs([
      "bun",
      "cli.ts",
      "start",
      "--rpccookieperms=owner",
    ]);
    expect(
      (parsed.config as unknown as Record<string, unknown>).rpcCookiePerms
    ).toBeUndefined();
    expect(
      (parsed.config as unknown as Record<string, unknown>).rpccookieperms
    ).toBeUndefined();
  });
});

// ===========================================================================
// G12-G17: rpcauth + rpcwhitelist + credential security
// ===========================================================================

describe("W140 G12: --rpcauth HMAC-SHA256 hashed creds (MISSING — BUG-5 HIGH-SEC)", () => {
  test("MISSING: no --rpcauth CLI flag", () => {
    const parsed = parseArgs([
      "bun",
      "cli.ts",
      "start",
      "--rpcauth=alice:abc$deadbeefcafef00d",
    ]);
    expect(
      (parsed.config as unknown as Record<string, unknown>).rpcAuth
    ).toBeUndefined();
    expect(
      (parsed.config as unknown as Record<string, unknown>).rpcauth
    ).toBeUndefined();
  });
  test("MISSING: authenticate() has no HMAC-SHA256 verify path", () => {
    const idx = RPC_SRC.indexOf("private authenticate(req: Request)");
    expect(idx).toBeGreaterThanOrEqual(0);
    const region = RPC_SRC.slice(idx, idx + 2000);
    expect(/HMAC|hmac\(|createHmac|sha256/i.test(region)).toBe(false);
  });
});

describe("W140 G13: share/rpcauth/rpcauth.py-equivalent generator (MISSING — BUG-6 LOW)", () => {
  test("MISSING: no rpcauth generator helper in tools/", () => {
    // The hotbuns checkout should not contain a generator script. If a future
    // change adds one, this test will need to be updated alongside the
    // verify-path implementation (BUG-5).
    const toolsDir = path.resolve(__dirname, "..", "..", "tools");
    let hasGenerator = false;
    if (fs.existsSync(toolsDir)) {
      const entries = fs.readdirSync(toolsDir);
      hasGenerator = entries.some((e) =>
        /rpcauth|rpc[-_]?auth/i.test(e)
      );
    }
    expect(hasGenerator).toBe(false);
  });
});

describe("W140 G14: constant-time credential compare (MISSING — BUG-7 HIGH-SEC)", () => {
  test("MISSING: authenticate() uses === for cookie password compare (timing oracle)", () => {
    // The exact compare lines we expect today.
    expect(RPC_SRC.includes("return password === this.cookiePassword")).toBe(
      true
    );
    expect(
      RPC_SRC.includes(
        "return user === this.config.rpcUser && password === this.config.rpcPassword"
      )
    ).toBe(true);
  });
  test("MISSING: no timingSafeEqual call inside authenticate()", () => {
    const idx = RPC_SRC.indexOf("private authenticate(req: Request)");
    expect(idx).toBeGreaterThanOrEqual(0);
    const region = RPC_SRC.slice(idx, idx + 2000);
    expect(/timingSafeEqual|TimingResistantEqual|constantTimeEqual/.test(region)).toBe(
      false
    );
  });
});

describe("W140 G15: 250ms wrong-password sleep (MISSING — BUG-8 MED-SEC)", () => {
  test("MISSING: no setTimeout(..., 250) / Bun.sleep(250) on the 401 path", () => {
    // The 401 response builder block.
    const idx = RPC_SRC.indexOf('"Authentication required"');
    expect(idx).toBeGreaterThanOrEqual(0);
    // Look 600 chars on either side for any sleep / setTimeout reference
    const region = RPC_SRC.slice(Math.max(0, idx - 600), idx + 600);
    expect(/Bun\.sleep|setTimeout\(.*250|delay\(250/.test(region)).toBe(false);
  });
});

describe("W140 G16: --rpcwhitelist per-user method filter (MISSING — BUG-9 LOW)", () => {
  test("MISSING: no --rpcwhitelist CLI flag", () => {
    const parsed = parseArgs([
      "bun",
      "cli.ts",
      "start",
      "--rpcwhitelist=alice:getblockcount,getmempoolinfo",
    ]);
    expect(
      (parsed.config as unknown as Record<string, unknown>).rpcWhitelist
    ).toBeUndefined();
  });
  test("MISSING: no per-method whitelist check in processRequest", () => {
    const idx = RPC_SRC.indexOf("private async processRequest");
    expect(idx).toBeGreaterThanOrEqual(0);
    const region = RPC_SRC.slice(idx, idx + 2000);
    expect(/whitelist|allowedMethods|RPC_FORBIDDEN/i.test(region)).toBe(false);
  });
});

describe("W140 G17: --rpcwhitelistdefault default-deny (MISSING)", () => {
  test("MISSING: no --rpcwhitelistdefault CLI flag", () => {
    expect(CLI_SRC.includes("rpcwhitelistdefault")).toBe(false);
    expect(CLI_SRC.includes("rpc-whitelist-default")).toBe(false);
  });
});

// ===========================================================================
// G18-G19: HTTP method handling
// ===========================================================================

describe("W140 G18: POST-only HTTP method (PRESENT)", () => {
  test("non-POST requests are rejected with 405", () => {
    expect(RPC_SRC.includes('if (req.method !== "POST")')).toBe(true);
    // The response body is the JSON-RPC error envelope (hotbuns deviation;
    // Core uses a plaintext body) but the status is 405 either way.
    const idx = RPC_SRC.indexOf('if (req.method !== "POST")');
    const region = RPC_SRC.slice(idx, idx + 600);
    expect(region.includes("status: 405")).toBe(true);
  });
});

describe("W140 G19: OPTIONS / preflight returns 405 (PRESENT — no CORS surface)", () => {
  test("OPTIONS / GET / HEAD / PUT all fall through to the same 405 branch", () => {
    // The non-POST check covers any other method; there is no special
    // handling for OPTIONS / CORS. That's correct behavior for an
    // authenticated admin RPC (Core does the same).
    const idx = RPC_SRC.indexOf('if (req.method !== "POST")');
    const region = RPC_SRC.slice(idx, idx + 400);
    expect(/OPTIONS|CORS|Access-Control/.test(region)).toBe(false);
  });
});

// ===========================================================================
// G20-G23: JSON-RPC dispatch semantics
// ===========================================================================

describe("W140 G20: single-request dispatch + structured error (PRESENT)", () => {
  test("processRequest returns { jsonrpc: '2.0', id, error: { code, message } }", () => {
    expect(RPC_SRC.includes("METHOD_NOT_FOUND: -32601")).toBe(true);
    expect(RPC_SRC.includes("INVALID_REQUEST: -32600")).toBe(true);
    expect(RPC_SRC.includes("PARSE_ERROR: -32700")).toBe(true);
  });
});

describe("W140 G21: batched dispatch + size cap (PARTIAL — BUG-10 MED-SEC)", () => {
  test("PRESENT: MAX_BATCH_SIZE=1000 cap exists", () => {
    expect(RPC_SRC.includes("MAX_BATCH_SIZE = 1000")).toBe(true);
    expect(RPC_SRC.includes("body.length > MAX_BATCH_SIZE")).toBe(true);
  });
  test("MISSING: body size cap is enforced AFTER await req.json() — too late", () => {
    // The cap check must come after the JSON parse. Locate the parse,
    // then locate the cap; the cap must appear later.
    const parseIdx = RPC_SRC.indexOf("body = await req.json()");
    const capIdx = RPC_SRC.indexOf("body.length > MAX_BATCH_SIZE");
    expect(parseIdx).toBeGreaterThanOrEqual(0);
    expect(capIdx).toBeGreaterThanOrEqual(0);
    // The cap is later in the file ⇒ the body was already buffered + parsed.
    expect(capIdx).toBeGreaterThan(parseIdx);
  });
  test("MISSING: no maxRequestBodySize set on Bun.serve options", () => {
    // The Bun.serve call should not configure maxRequestBodySize. If
    // someone adds it, this test will fail and we'll need to revisit BUG-10.
    const idx = RPC_SRC.indexOf("this.server = Bun.serve({");
    expect(idx).toBeGreaterThanOrEqual(0);
    const region = RPC_SRC.slice(idx, idx + 400);
    expect(region.includes("maxRequestBodySize")).toBe(false);
  });
});

describe("W140 G22: JSON-RPC 2.0 notification semantics (MISSING — BUG-11 LOW)", () => {
  test("MISSING: isValidRequest does not gate on `id === undefined`", () => {
    const idx = RPC_SRC.indexOf("private isValidRequest");
    expect(idx).toBeGreaterThanOrEqual(0);
    const region = RPC_SRC.slice(idx, idx + 800);
    // No "if (obj.id === undefined) return notification" path.
    expect(/notification|IsNotification|HTTP_NO_CONTENT|204/.test(region)).toBe(
      false
    );
  });
  test("MISSING: handleRequest never returns 204 No Content", () => {
    // A notification batch should return 204 per Core httprpc.cpp:221.
    expect(RPC_SRC.includes("status: 204")).toBe(false);
  });
});

describe("W140 G23: jsonrpc field version check (MISSING)", () => {
  test("MISSING: isValidRequest does not inspect obj.jsonrpc", () => {
    const idx = RPC_SRC.indexOf("private isValidRequest");
    expect(idx).toBeGreaterThanOrEqual(0);
    const region = RPC_SRC.slice(idx, idx + 800);
    // No version-field check. Both "2.0" and "1.0" get the same semantics.
    expect(/obj\.jsonrpc|version.*1\.0|version.*2\.0/.test(region)).toBe(false);
  });
});

// ===========================================================================
// G24-G28: HTTP limits + queue
// ===========================================================================

describe("W140 G24: max body size pre-parse cap (MISSING)", () => {
  test("MISSING: Bun.serve has no maxRequestBodySize / MAX_SIZE equivalent", () => {
    const idx = RPC_SRC.indexOf("this.server = Bun.serve({");
    expect(idx).toBeGreaterThanOrEqual(0);
    const region = RPC_SRC.slice(idx, idx + 400);
    expect(region.includes("maxRequestBodySize")).toBe(false);
  });
});

describe("W140 G25: max headers size cap (MISSING)", () => {
  test("MISSING: no MAX_HEADERS_SIZE / 8192 cap configured", () => {
    expect(RPC_SRC.includes("MAX_HEADERS_SIZE")).toBe(false);
    // Bun.serve has no public max-headers field as of Bun 1.3.
  });
});

describe("W140 G26: per-request idle timeout (MISSING — BUG-12 MED-SEC)", () => {
  test("MISSING: Bun.serve idleTimeout not set", () => {
    const idx = RPC_SRC.indexOf("this.server = Bun.serve({");
    expect(idx).toBeGreaterThanOrEqual(0);
    const region = RPC_SRC.slice(idx, idx + 400);
    expect(region.includes("idleTimeout")).toBe(false);
  });
  test("MISSING: no --rpcservertimeout CLI flag", () => {
    expect(CLI_SRC.includes("rpcservertimeout")).toBe(false);
    expect(CLI_SRC.includes("rpc-server-timeout")).toBe(false);
  });
});

describe("W140 G27: -rpcworkqueue depth + 503 backpressure (MISSING)", () => {
  test("MISSING: no work-queue / 503 ServiceUnavailable backpressure", () => {
    expect(RPC_SRC.includes("rpcworkqueue")).toBe(false);
    expect(RPC_SRC.includes("WorkQueue")).toBe(false);
    expect(RPC_SRC.includes("status: 503")).toBe(false);
  });
});

describe("W140 G28: -rpcthreads (N/A — Bun.serve is single-event-loop)", () => {
  test("N/A: no thread pool; Bun.serve is event-loop", () => {
    // Document this is intentional. If someone later adds a --rpc-threads
    // flag pointing at a worker thread pool, this test will fail and we
    // can revisit whether the equivalent semantics make sense in Bun.
    expect(CLI_SRC.includes("rpcthreads")).toBe(false);
    expect(CLI_SRC.includes("rpc-threads")).toBe(false);
  });
});

// ===========================================================================
// G29: Wallet routing — P0-SEC race condition
// ===========================================================================

describe("W140 G29: /wallet/<name> routing (PARTIAL — BUG-13 P0-SEC race)", () => {
  test("PRESENT: /wallet/<name> path parsing exists", () => {
    expect(RPC_SRC.includes('pathParts[0] === "wallet"')).toBe(true);
    expect(RPC_SRC.includes("decodeURIComponent(pathParts[1])")).toBe(true);
  });

  test("BUG-13: currentWalletName is a request-mutable class field", () => {
    // Core uses request-local state (JSONRPCRequest.URI on the stack).
    // hotbuns mutates a server-level field — race risk under concurrent
    // requests.
    expect(
      RPC_SRC.includes("private currentWalletName: string | null = null")
    ).toBe(true);
    expect(
      RPC_SRC.includes("this.currentWalletName = decodeURIComponent")
    ).toBe(true);
    expect(RPC_SRC.includes("this.currentWalletName = null")).toBe(true);
  });

  test("BUG-13: currentWalletName is mutated BEFORE await req.json()", () => {
    // The mutation site happens before any await, which means a second
    // concurrent request can clobber it during the first's awaited body
    // parse.
    const mutateIdx = RPC_SRC.indexOf(
      "this.currentWalletName = decodeURIComponent"
    );
    const awaitJsonIdx = RPC_SRC.indexOf("body = await req.json()");
    expect(mutateIdx).toBeGreaterThanOrEqual(0);
    expect(awaitJsonIdx).toBeGreaterThanOrEqual(0);
    // Mutation happens textually (and at runtime) before the await.
    expect(mutateIdx).toBeLessThan(awaitJsonIdx);
  });

  test("BUG-13: handlers READ currentWalletName after await — race window", () => {
    // The first read site for wallet routing is in getCurrentWallet /
    // wallet helpers, all of which are called from async handlers that
    // run AFTER processRequest awaits the handler.
    expect(RPC_SRC.includes("if (this.currentWalletName !== null)")).toBe(true);
    // There is no `const walletName = this.currentWalletName` snapshot
    // captured at the top of handleRequest — confirming the race.
    const handleIdx = RPC_SRC.indexOf("private async handleRequest");
    expect(handleIdx).toBeGreaterThanOrEqual(0);
    const handleBody = RPC_SRC.slice(handleIdx, handleIdx + 4000);
    expect(/const\s+walletName\s*=\s*this\.currentWalletName/.test(handleBody)).toBe(
      false
    );
  });

  test("BUG-13: no request-local wallet context (e.g. AsyncLocalStorage)", () => {
    expect(RPC_SRC.includes("AsyncLocalStorage")).toBe(false);
    expect(RPC_SRC.includes("requestContext")).toBe(false);
  });
});

// ===========================================================================
// G30: Host header validation (DNS-rebinding mitigation)
// ===========================================================================

describe("W140 G30: Host header validation (MISSING)", () => {
  test("MISSING: handleRequest does not inspect req.headers.get('Host')", () => {
    const idx = RPC_SRC.indexOf("private async handleRequest");
    expect(idx).toBeGreaterThanOrEqual(0);
    const region = RPC_SRC.slice(idx, idx + 4000);
    expect(/req\.headers\.get\("[Hh]ost"\)|hostHeader|host:.*Host/.test(region)).toBe(
      false
    );
  });
});

// ===========================================================================
// Source-level guards: pin existing security-sensitive shapes so a future
// edit that REMOVES them trips a failing expect() before merge.
// ===========================================================================

describe("W140 source-level guards", () => {
  test("guard: cookie auth user is '__cookie__' (Core COOKIEAUTH_USER)", () => {
    // Direct match against the literal in `authenticate()` — if a refactor
    // ever changes this, cookie auth silently breaks for every Core-compatible
    // cli tool.
    expect(RPC_SRC.includes('if (hasCookie && user === "__cookie__")')).toBe(
      true
    );
  });

  test("guard: WWW-Authenticate header is 'Basic realm=\"jsonrpc\"'", () => {
    // Core httprpc.cpp:33 — `WWW_AUTH_HEADER_DATA = "Basic realm=\"jsonrpc\""`.
    expect(RPC_SRC.includes('"WWW-Authenticate": \'Basic realm="jsonrpc"\'')).toBe(
      true
    );
  });

  test("guard: cookie generation uses 32 bytes (Core COOKIE_SIZE=32)", () => {
    expect(
      RPC_SRC.includes("crypto.getRandomValues(new Uint8Array(32))")
    ).toBe(true);
  });

  test("guard: cookie path is <datadir>/.cookie (Core COOKIEAUTH_FILE)", () => {
    expect(RPC_SRC.includes('path.join(this.config.datadir, ".cookie")')).toBe(
      true
    );
  });

  test("guard: cookie file removed on shutdown (Core DeleteAuthCookie)", () => {
    const stopBlock =
      RPC_SRC.split("  stop(): void {")[1]?.split("\n  }")[0] ?? "";
    expect(stopBlock.includes("unlink(this.cookiePath!)")).toBe(true);
  });

  test("guard: noAuth path bypasses cookie generation (test-only flag)", () => {
    // The dev-only `noAuth=true` config must skip cookie generation
    // entirely (a cookie + noAuth combination would be a footgun).
    expect(RPC_SRC.includes("if (!this.config.noAuth)")).toBe(true);
  });
});
