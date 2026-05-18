# W140 — HTTP server + rpcauth + cookie auth + JSON-RPC dispatch audit (hotbuns)

**Impl:** hotbuns (TypeScript / Bun)
**Date:** 2026-05-18
**Status:** DISCOVERY (no production code changes)
**Test file:** `src/__tests__/w140_http_rpcauth.test.ts`
**Reference:**
- `bitcoin-core/src/httpserver.cpp` + `httpserver.h` (HTTPBindAddresses, ClientAllowed, evhttp_set_max_headers_size / max_body_size, rpcthreads, rpcworkqueue, rpcservertimeout)
- `bitcoin-core/src/httprpc.cpp` (CheckUserAuthorized HMAC-SHA256, TimingResistantEqual, 250ms brute-force deterrent, rpcauth/rpcwhitelist, WWW-Authenticate, HTTP_NO_CONTENT for notifications)
- `bitcoin-core/src/rpc/request.cpp` (COOKIEAUTH_USER `__cookie__`, GenerateAuthCookie, umask 0077 + optional `-rpccookieperms`, DeleteAuthCookie)
- `bitcoin-core/share/rpcauth/rpcauth.py` (HMAC-SHA256 salt+hash format `user:salt$hash`)
- `bitcoin-core/src/init.cpp` (`-rpcbind`, `-rpcallowip`, `-rpcuser`, `-rpcpassword`, `-rpcauth`, `-rpcwhitelist`, `-rpcwhitelistdefault`, `-rpccookiefile`, `-rpccookieperms`, `-norpccookiefile`)

## Motivation

W124 surfaced two HTTP/auth findings (BUG-7 cookie 0644 / world-readable, BUG-8
`--rpcbind`/`--rpcallowip` missing). W140 is the full Core-parity sweep of the
HTTP + auth + JSON-RPC dispatch surface — it locks in the existing 0644 cookie
finding and characterises the rest of the surface (rpcauth HMAC support,
timing-safe compares, brute-force deterrent, body / header size caps,
worker-queue depth, JSON-RPC version & notification semantics, request-mutable
wallet routing under Bun's async concurrency, host header validation, etc.).

W124's audit framework explicitly carved out auth-level questions to a
follow-on wave because the operator surface is too broad. W140 is that
follow-on with a security-first lens — most findings here are P0-SEC or
HIGH-SEC because the RPC port can move coins from a loaded wallet, and the
cookie file IS the credential.

## Method

1. Read Core refs end-to-end (`httprpc.cpp`, `httpserver.cpp`,
   `rpc/request.cpp::GenerateAuthCookie`, `share/rpcauth/rpcauth.py`).
2. Synthesize a 30-gate matrix covering: bind/ACL, cookie file (write +
   permissions + remove), rpcauth HMAC-SHA256 hashed creds, timing-safe
   credential compare, brute-force deterrent, batched + notification
   semantics, dispatch correctness, body/header size caps, request-mutable
   state under concurrent requests.
3. Classify each gate against hotbuns refs:
   `src/rpc/server.ts` (RPCServer class, `handleRequest`, `authenticate`,
    `processRequest`, `start`, `stop`, `currentWalletName`),
   `src/cli/cli.ts` (CLI flag parsing, RPCServerConfig wiring,
   `host: "127.0.0.1"` hardcoded).
4. Catalogue 13 BUGs across P0-SEC, HIGH-SEC, MED, LOW tiers.
5. Lock in current behavior via `src/__tests__/w140_http_rpcauth.test.ts`
   so a future stub that adds a `--rpcauth` flag without the HMAC compare
   path trips a failing `expect()` before it merges.

## Gate matrix (30)

Status legend: P = PRESENT, p = PARTIAL, M = MISSING.

| #   | Area           | Gate                                                                              | Status | Notes |
|-----|----------------|-----------------------------------------------------------------------------------|--------|-------|
| G1  | Bind           | Default bind 127.0.0.1 only (loopback)                                            | P      | `cli.ts:2039` hardcoded `host: "127.0.0.1"`; `server.ts:522` default `"127.0.0.1"` |
| G2  | Bind           | `-rpcbind=<host:port>` operator surface                                           | M      | No CLI flag. Core init.cpp + httpserver.cpp:329 `HTTPBindAddresses` supports multiple. (BUG-1 LOW; W124 BUG-8) |
| G3  | ACL            | `-rpcallowip=<subnet>` ACL list (CIDR / netmask / IP)                             | M      | No CLI flag. **No `ClientAllowed` check at all** — any client that can connect to the bind socket gets past the ACL gate. Localhost is enforced only by the bind, not by ACL. (BUG-2 MED-SEC; W124 BUG-8) |
| G4  | ACL            | Both-or-neither rule: `-rpcbind` ignored without `-rpcallowip` (Core httpserver.cpp:319) | M | N/A — neither flag exists |
| G5  | Cookie         | `<datadir>/.cookie` written on startup with `__cookie__:<hex>` (Core COOKIEAUTH_USER) | P  | `server.ts:638-650`, 32 random bytes → hex, `__cookie__:` prefix |
| G6  | Cookie         | Cookie file unlinked on graceful shutdown                                         | P      | `server.ts:697-710`, `fsp.unlink(this.cookiePath)` in `stop()` |
| G7  | Cookie         | Cookie file mode 0600 (owner-only) — Core uses umask 0077 + optional `-rpccookieperms` | M | `Bun.write` uses default umask (0644 / world-readable on most Linux). **BUG-3 HIGH-SEC** (also W124 BUG-7; persisting here because it is the highest-impact finding in W140 too). Any other local user on the host can read the cookie + impersonate the operator → drain a loaded wallet |
| G8  | Cookie         | Cookie write is atomic (write to `.cookie.tmp` + rename — Core rpc/request.cpp:117/126) | M | Direct `Bun.write` to final path. A `ps` race that reads while write is in flight gets a partial line; legitimate clients can fail auth transiently |
| G9  | Cookie         | `-rpccookiefile=<path>` operator override                                         | M      | No flag; cookie path hardwired to `<datadir>/.cookie` (BUG-4 LOW) |
| G10 | Cookie         | `-norpccookiefile` (disable cookie generation) per Core rpc/request.cpp:88-90     | M      | No flag. Always-on cookie generation when not in `noAuth` mode |
| G11 | Cookie         | `-rpccookieperms={owner,group,all}` per Core httprpc.cpp:248                      | M      | No flag (related to BUG-3) |
| G12 | rpcauth        | `-rpcauth=<user>:<salt>$<hmac_sha256>` hashed credentials                         | M      | No flag, no HMAC code path in `authenticate()`. Operators MUST use plaintext `-rpcuser/-rpcpassword`. **BUG-5 HIGH-SEC**: plaintext creds in `hotbuns.conf` (mode 0644) → cleartext password readable by other local users. Core's deprecation warning (httprpc.cpp:270) directs operators to `share/rpcauth/rpcauth.py` precisely to avoid this — hotbuns ships no equivalent |
| G13 | rpcauth        | `share/rpcauth/rpcauth.py` (or equivalent) ships with the impl                    | M      | Not shipped (BUG-6 LOW — operators can't even generate a hash if hotbuns adds the verify path later) |
| G14 | Auth/CMP       | Constant-time credential comparison (Core TimingResistantEqual)                   | M      | `server.ts:1039,1044` uses plain `===` for cookie password and rpcUser/rpcPassword. **BUG-7 HIGH-SEC**: timing oracle on the 64-hex-char cookie. With low-latency localhost or shared-tenant cloud, char-by-char early-exit lets an attacker recover the cookie in O(N·16) requests instead of O(16^N). Bun's `===` short-circuits at the first mismatched byte |
| G15 | Auth/CMP       | Wrong-password 250ms sleep to deter brute-force (Core httprpc.cpp:128)            | M      | No `setTimeout(..., 250)` / `Bun.sleep(250)` in the 401 path. **BUG-8 MED-SEC**: lets an attacker make thousands of guesses per second against a (potentially weak) rpcpassword |
| G16 | rpcwhitelist   | `-rpcwhitelist=<user>:<methods>` per-user method filter                           | M      | No flag, no per-method ACL in dispatch (BUG-9 LOW) |
| G17 | rpcwhitelist   | `-rpcwhitelistdefault=1` default-deny                                             | M      | Same as G16 |
| G18 | HTTP method    | POST-only (Core httprpc.cpp:107-109 returns HTTP_BAD_METHOD for non-POST)          | P      | `server.ts:797-808` returns 405 for non-POST. But uses `INVALID_REQUEST` JSON-RPC error envelope where Core returns a plaintext body — sender-visible but functionally equivalent |
| G19 | HTTP method    | OPTIONS / preflight handling (CORS not in Core; hotbuns shouldn't ship it either) | P      | Treated as 405 — correct (no CORS surface; admin UI behind a same-origin reverse proxy) |
| G20 | JSON-RPC       | Single-request dispatch + structured error envelope                               | P      | `processRequest` returns canonical `{jsonrpc:"2.0", id, error:{code,message}}` |
| G21 | JSON-RPC       | Batched-request dispatch (array body) with size cap                               | p      | `server.ts:874-906` honours `MAX_BATCH_SIZE=1000` cap. **But cap is checked AFTER `await req.json()` fully parses the body**; an attacker can submit gigabytes that get fully buffered + parsed before rejection (BUG-10 MED-SEC; Core's `evhttp_set_max_body_size(http, MAX_SIZE)` rejects at libevent layer) |
| G22 | JSON-RPC       | Notification semantics: `id` absent → HTTP_NO_CONTENT, no response body (Core httprpc.cpp:168-170, 207-209) | M | hotbuns always returns a full response envelope even when `id` is undefined. JSON-RPC 2.0 notifications are not supported (BUG-11 LOW) |
| G23 | JSON-RPC       | `jsonrpc: "2.0"` version-field handling (Core m_json_version: 1.0 vs 2.0 error semantics differ; httprpc.cpp:160-165) | M | No version check; `RPCRequest.jsonrpc` declared `"2.0" \| "1.0"` but never inspected. Both versions get 2.0 semantics |
| G24 | HTTP limits    | Max body size (Core MAX_SIZE; libevent enforces pre-parse)                         | M      | No body-size cap before `req.json()` (related to BUG-10). Bun.serve has no built-in body cap unless `maxRequestBodySize` is set on serve options |
| G25 | HTTP limits    | Max headers size (Core MAX_HEADERS_SIZE=8192)                                      | M      | No header-size cap. Bun.serve enforces an internal cap but it is much higher than 8192 |
| G26 | HTTP limits    | `-rpcservertimeout` per-request idle timeout (Core default 30s)                    | M      | No timeout flag, no per-request deadline. Slow-Loris-style clients hold sockets open indefinitely (BUG-12 MED-SEC) |
| G27 | HTTP queue     | `-rpcworkqueue` queue-depth + 503 backpressure (Core httpserver.cpp:255-258)        | M      | No queue / no backpressure. All Bun.serve concurrency is implicit; a flood of slow handlers can OOM the process |
| G28 | HTTP queue     | `-rpcthreads` worker count                                                         | M      | N/A — Bun.serve is single-process event loop; no thread pool. Document that this is intentional |
| G29 | Wallet routing | `/wallet/<name>` URL prefix routes to the right wallet                             | p      | **BUG-13 P0-SEC: request-mutable `this.currentWalletName` class field mutated per-request, then awaited across `req.json()` and async handler.** Two concurrent requests trample each other's wallet routing → operator sends funds from wallet A but request was tagged for wallet B. JS event loop is single-threaded, but `await` yields the scheduler → race window is real. Core scopes the wallet identity to the request-local `JSONRPCRequest.URI` (httprpc.cpp:142), never to a server-level mutable |
| G30 | Host header    | Reject mismatched / unexpected Host header (DNS-rebinding mitigation)              | M      | No Host-header check. If an operator does eventually run with `--rpcbind=0.0.0.0`, a malicious LAN web page could DNS-rebind a user's browser to RPC localhost and submit JSON-RPC. Cookie auth + same-origin policy block the worst case today but the defense-in-depth gate is missing |

PRESENT: **5**  /  PARTIAL: **2**  /  MISSING: **23**

## Findings (13 bugs)

### BUG-13 (P0-SEC) Request-mutable wallet routing races across concurrent requests

`src/rpc/server.ts:462` — `private currentWalletName: string | null = null;`
`src/rpc/server.ts:828-833` — mutated per-request from URL pathname.
`src/rpc/server.ts:6133, 6176, 6383, 6395` — read inside async handlers
**after** the request awaits body parse + dispatch.

```ts
// server.ts:795-834
private async handleRequest(req: Request): Promise<Response> {
  ...
  if (pathParts.length >= 2 && pathParts[0] === "wallet") {
    this.currentWalletName = decodeURIComponent(pathParts[1]);  // ← mutate
  } else {
    this.currentWalletName = null;
  }
  if (!this.authenticate(req)) { ... }
  let body: unknown;
  body = await req.json();        // ← awaits the network read
  ...
  const response = await this.processRequest(body);  // ← async handler reads `currentWalletName`
```

Scenario:
1. Request A: `POST /wallet/A`, parsed → `currentWalletName = "A"`. Awaits `req.json()`.
2. Request B: `POST /wallet/B` arrives during A's await → `currentWalletName = "B"`.
3. A's handler resumes → reads `this.currentWalletName === "B"` → operates on wallet B even though the request was tagged for wallet A.

Impact: a multi-wallet operator running `bitcoin-cli -rpcwallet=cold sendtoaddress`
and `bitcoin-cli -rpcwallet=hot sendtoaddress` simultaneously can see the COLD
wallet sign + broadcast a tx the operator intended to come from the HOT wallet,
or vice versa. Since the wallet is the security boundary, this is **P0-SEC**.

Single-threaded JavaScript doesn't help here — `await` is a yield point and
Bun.serve services concurrent in-flight requests through the same handler
function on the same RPCServer instance.

Fix shape (NOT in this discovery wave): thread the wallet name through the
request stack as a function argument (request-local) instead of class state.
Core's equivalent is `JSONRPCRequest.URI` populated once per HTTPReq_JSONRPC
invocation; the URI lives only on the stack.

### BUG-3 / W140-G7 (HIGH-SEC) Cookie file is world-readable (0644)

Persists W124 BUG-7. `server.ts:646` —

```ts
Bun.write(this.cookiePath, `__cookie__:${this.cookiePassword}`).catch(...)
```

`Bun.write` honours the umask, which is typically `022` on Linux servers
(maxbox confirmed). Result: `<datadir>/.cookie` ends up 0644. Any other
unprivileged user on the host (`www-data`, an adjacent container sharing
a mount, a shared-CI worker) can `cat` it and impersonate the operator.

Core sets process umask to `0077` in `common/system.cpp` precisely so the
`std::ofstream file; file.open(filepath_tmp);` in `GenerateAuthCookie` lands
as `0600`, then optionally relaxes via `-rpccookieperms` (httprpc.cpp:248).

Fix shape: `fs.chmodSync(cookiePath, 0o600)` after the write, or
`fs.writeFileSync(cookiePath, ..., { mode: 0o600 })`. Bun.write does not
expose a mode argument as of Bun 1.3.

### BUG-5 / W140-G12 (HIGH-SEC) No `-rpcauth` HMAC-SHA256 path — plaintext password only

`authenticate()` (`server.ts:1043-1045`) only knows two creds:
1. `user === "__cookie__"` && `password === this.cookiePassword` (cookie)
2. `user === this.config.rpcUser` && `password === this.config.rpcPassword`
   (plaintext from config)

There is **no** code path that:
- iterates a list of `<user, salt, hmac_sha256_hex>` triples,
- computes `HMAC_SHA256(salt, submitted_password)`,
- compares the hex digest constant-time.

Consequence: operators wanting multi-user RPC or hashed-at-rest credentials
have no option but to put a plaintext password in `<datadir>/hotbuns.conf`
(also 0644 by default — see BUG-3 vector applied to the config file).

Core's `httprpc.cpp:64-82` `CheckUserAuthorized` is the canonical reference;
`bitcoin-core/share/rpcauth/rpcauth.py` ships the generator. hotbuns has
neither.

### BUG-7 / W140-G14 (HIGH-SEC) Timing-oracle on cookie + rpcpassword compare

`server.ts:1039,1044` —

```ts
if (hasCookie && user === "__cookie__") {
  return password === this.cookiePassword;        // ← non-constant-time
}
if (hasConfiguredCreds) {
  return user === this.config.rpcUser && password === this.config.rpcPassword;  // ← same
}
```

JS engines compare strings byte-by-byte with early-exit on first mismatch.
Over a localhost socket the per-request timing variance is small enough
(microseconds) that statistical analysis recovers the cookie one byte at
a time. Core uses `TimingResistantEqual` (see `httprpc.cpp:66,77` callsites)
which is `O(n)` regardless of mismatch position.

In hotbuns' default deployment (loopback + cookie) the practical attacker
has to be a local user, but BUG-3 (0644 cookie) is the easier vector for
that attacker. If the operator ever exposes RPC via `--rpcbind` on a
trusted LAN (BUG-1 follow-on), this becomes the primary attack.

Fix shape: `node:crypto` `timingSafeEqual(Buffer.from(a), Buffer.from(b))`
after a length-precheck (Bun supports it).

### BUG-8 / W140-G15 (MED-SEC) No 250ms wrong-password sleep

Core (`httprpc.cpp:128`):
```cpp
if (!RPCAuthorized(authHeader.second, jreq.authUser)) {
    ...
    UninterruptibleSleep(std::chrono::milliseconds{250});
    ...
}
```

hotbuns returns the 401 immediately. An attacker on loopback can attempt
4000 password guesses/sec instead of 4. Combined with BUG-5 (only plaintext
rpcpassword is supported) and BUG-7 (timing-leak on the compare itself),
this gates how quickly a weak rpcpassword falls.

### BUG-10 / W140-G21+G24 (MED-SEC) Body parsed before size cap enforced

`server.ts:856-872` reads the body via `await req.json()` before any size
check. The `MAX_BATCH_SIZE=1000` limit (server.ts:891) only kicks in
**after** the JSON parse completes. Bun.serve's default `maxRequestBodySize`
is 128 MiB; an attacker can send a 128 MiB JSON array of 999 entries and
hotbuns will JSON.parse the whole thing before the 1000-entry check fires.

Core enforces `MAX_SIZE` (~33 MiB) via `evhttp_set_max_body_size(http, MAX_SIZE)`
**at libevent layer** before any handler sees the body.

Fix shape: set `Bun.serve({ maxRequestBodySize: 33 * 1024 * 1024 })` and add
a pre-parse `Content-Length` check.

### BUG-12 / W140-G26 (MED-SEC) No per-request idle timeout

Core's `-rpcservertimeout` (default 30s) maps to `evhttp_set_timeout(http, ...)`.
Bun.serve has an `idleTimeout` field but `server.ts:681-686` doesn't set it.
Slow-loris-style clients can keep the socket open with trickle-byte requests
indefinitely; eventually the process exhausts FDs.

### BUG-2 / W140-G3 (MED-SEC) No `ClientAllowed` ACL check

Even though the default bind is `127.0.0.1` (G1 PRESENT), the **only** thing
preventing remote access is the kernel-level bind. There is no application-layer
`ClientAllowed(peer)` check (Core httpserver.cpp:137-145). If a future flag
relaxes the bind to `0.0.0.0` (BUG-1 / W124 BUG-8), there is no second line of
defense.

A separate operator footgun: localhost-only is enforced at the bind, so a
container with `bind: "0.0.0.0:8332"` (legitimate inside a sandbox network
namespace) ends up with the WORLD as the ACL.

### BUG-1 / W140-G2 (LOW) No `-rpcbind` flag

Persists W124 BUG-8. `cli.ts:2039` hardcodes `host: "127.0.0.1"` after
config-file load — even adding `rpcbind=` to `hotbuns.conf` won't help
because there is no parse rule for it (`cli.ts:loadConfig` doesn't handle
the key).

### BUG-4 / W140-G9 (LOW) No `-rpccookiefile` flag

Path hardwired to `<datadir>/.cookie`. Operators who want the cookie under
`/run` (a tmpfs that vanishes on reboot — useful for hardened deployments)
must symlink. Core's `-rpccookiefile=<path>` lets the operator just pass
the path.

### BUG-6 / W140-G13 (LOW) No `rpcauth.py`-equivalent generator shipped

Even if BUG-5 (the verify path) is fixed, operators need a way to GENERATE
`<user>:<salt>$<hmac>` lines without booting Python and using Core's tree.
Ship a `bun run rpcauth <user>` helper.

### BUG-9 / W140-G16+G17 (LOW) No per-user method whitelist

Core's `-rpcwhitelist`/`-rpcwhitelistdefault` lets ops give a watch-only
monitor user `getblockcount + getmempoolinfo + getpeerinfo` and nothing
else. hotbuns has no concept of per-method ACL. (Mitigation today is
front-of-server reverse proxy + path-based ACL.)

### BUG-11 / W140-G22+G23 (LOW) No JSON-RPC 2.0 notification or version handling

- Notifications (no `id` field) get a full response envelope instead of
  HTTP_NO_CONTENT. Spec violation but most clients tolerate it.
- The `jsonrpc` field is declared in the type but never inspected. 1.0
  clients get 2.0 error-shape semantics; not a security issue but a
  visible-to-clients deviation.

## Operator impact summary

| BUG  | Severity | Operator impact                                                                     |
|------|----------|-------------------------------------------------------------------------------------|
| 13   | P0-SEC   | Concurrent multi-wallet RPC requests trample each other's wallet routing → wrong wallet signs |
| 3    | HIGH-SEC | Any local user reads `.cookie` (0644) → impersonates operator → drains wallet      |
| 5    | HIGH-SEC | Only plaintext rpcpassword supported → 0644 `hotbuns.conf` leaks creds to local users |
| 7    | HIGH-SEC | Timing-oracle on cookie compare → cookie recovery via remote timing attack          |
| 8    | MED-SEC  | No 250ms wrong-pwd sleep → 1000× faster password brute-force                        |
| 10   | MED-SEC  | Body parsed before size cap → 128 MiB allocation DoS                                |
| 12   | MED-SEC  | No idle timeout → slow-loris FD exhaustion                                          |
| 2    | MED-SEC  | No `ClientAllowed` ACL → defence-in-depth gone if bind ever relaxes                 |
| 1, 4, 6, 9, 11 | LOW | Operator-experience gaps (flags + JSON-RPC spec compliance)                 |

## Out of scope

- BIP-78 PayJoin `/payjoin` endpoint — covered separately (FIX-65 + W### TBD).
- REST server (`src/rpc/rest.ts`) — separate audit surface (it's GET-only,
  no auth by design, default-bound 127.0.0.1 only).
- TLS termination — covered by FIX-64 (W124 G24).
- ZMQ notifications — covered by `src/rpc/zmq.ts` separately.

## Cross-impl notes

This wave is hotbuns-only by W140 scope. The same gates likely apply
fleet-wide (cookie 0600, timing-safe compare, rpcauth HMAC,
ClientAllowed ACL, idle timeout, body size cap). Recommend a follow-on
universal-correctness sweep across blockbrew / rustoshi / nimrod /
camlcoin (the 4 impls with the most operator surface).
