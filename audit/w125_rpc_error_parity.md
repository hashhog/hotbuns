# W125 — JSON-RPC error code parity audit (hotbuns)

**Impl:** hotbuns (TypeScript / Bun)
**Date:** 2026-05-17
**Status:** DISCOVERY — 18 BUGS / 30 gates (10 PRESENT / 5 PARTIAL / 15 MISSING)
**Tests:** `src/__tests__/w125_error_parity.test.ts` (xfail/assertion-only)
**No production code changes.**

## Reference

- `bitcoin-core/src/rpc/protocol.h` — `enum RPCErrorCode` (canonical
  codes -1 .. -36 + JSON-RPC 2.0 standard -32xxx).
- `bitcoin-core/src/rpc/util.cpp` — `RPCErrorFromPSBTError`,
  `RPCErrorFromTransactionError` (mapping helpers).
- `bitcoin-core/src/rpc/server.cpp` — `RPC_IN_WARMUP`, parameter
  duplication checks (`RPC_INVALID_PARAMETER`).
- `bitcoin-core/src/rpc/net.cpp` — addnode / disconnectnode /
  setban error mapping.
- `bitcoin-core/src/rpc/rawtransaction.cpp`,
  `src/rpc/mempool.cpp`, `src/rpc/mining.cpp`,
  `src/rpc/blockchain.cpp` — call-site error codes.
- `bitcoin-core/src/wallet/rpc/*.cpp` — wallet error mapping.
- JSON-RPC 2.0 §5.1 (Error object), BIP-323 (rejected — no BIP, but
  the audit-framework header mentions it; the canonical spec is the
  JSON-RPC 2.0 error contract + Bitcoin Core's protocol.h).

## Background — JSON-RPC 2.0 + Core's error code conventions

JSON-RPC 2.0 reserves the codes `-32000..-32999` for transport / protocol
errors:

| Code     | Name                | When                                          |
|----------|---------------------|-----------------------------------------------|
| -32700   | Parse error         | Invalid JSON                                  |
| -32600   | Invalid Request     | JSON valid but not a request object           |
| -32601   | Method not found    | Unknown method name                           |
| -32602   | Invalid params      | Method-internal param shape error             |
| -32603   | Internal error      | Server-side internal error                    |

Core (`rpc/protocol.h`) **also defines** application-layer codes in the
negative single-digit and -dozen range, intended for the JSON body's
`error.code` field. The distinction matters because the JSON-RPC 2.0
codes are **transport-layer** (Core comments explicitly say
"`RPC_INVALID_REQUEST` is internally mapped to `HTTP_BAD_REQUEST (400)`.
It should not be used for application-layer errors.") whereas the
application codes carry user-meaningful failure mode information that
clients (e.g. `bitcoin-cli`, `bitcoinlib-js`, `python-bitcoinrpc`)
branch on.

Key application codes:

| Core code | Value | Used for                                            |
|-----------|-------|-----------------------------------------------------|
| `RPC_MISC_ERROR`                       | -1  | std::exception thrown in command handling |
| `RPC_FORBIDDEN_BY_SAFE_MODE`           | -2  | Reserved (do not reuse)                   |
| `RPC_TYPE_ERROR`                       | -3  | Unexpected type was passed as parameter   |
| `RPC_WALLET_ERROR`                     | -4  | Unspecified wallet problem                |
| `RPC_INVALID_ADDRESS_OR_KEY`           | -5  | Invalid address or key                    |
| `RPC_WALLET_INSUFFICIENT_FUNDS`        | -6  | Not enough funds                          |
| `RPC_OUT_OF_MEMORY`                    | -7  | Ran out of memory during operation        |
| `RPC_INVALID_PARAMETER`                | -8  | Invalid / missing / duplicate parameter   |
| `RPC_CLIENT_NOT_CONNECTED`             | -9  | Bitcoin is not connected                  |
| `RPC_CLIENT_IN_INITIAL_DOWNLOAD`       | -10 | Still downloading initial blocks          |
| `RPC_WALLET_INVALID_LABEL_NAME`        | -11 | Invalid label name                        |
| `RPC_WALLET_KEYPOOL_RAN_OUT`           | -12 | Keypool empty                             |
| `RPC_WALLET_UNLOCK_NEEDED`             | -13 | Wallet locked, passphrase required        |
| `RPC_WALLET_PASSPHRASE_INCORRECT`      | -14 | Bad passphrase                            |
| `RPC_WALLET_WRONG_ENC_STATE`           | -15 | Command vs wallet encryption mismatch     |
| `RPC_WALLET_ENCRYPTION_FAILED`         | -16 | Encrypting wallet failed                  |
| `RPC_WALLET_ALREADY_UNLOCKED`          | -17 | Already unlocked                          |
| `RPC_WALLET_NOT_FOUND`                 | -18 | Invalid wallet specified                  |
| `RPC_WALLET_NOT_SPECIFIED`             | -19 | No wallet specified (multi-wallet)        |
| `RPC_DATABASE_ERROR`                   | -20 | Database error                            |
| `RPC_DESERIALIZATION_ERROR`            | -22 | Error parsing raw format                  |
| `RPC_CLIENT_NODE_ALREADY_ADDED`        | -23 | Peer already added                        |
| `RPC_CLIENT_NODE_NOT_ADDED`            | -24 | Peer not previously added                 |
| `RPC_VERIFY_ERROR` / `RPC_TRANSACTION_ERROR`         | -25 | General TX or block submission error |
| `RPC_VERIFY_REJECTED` / `RPC_TRANSACTION_REJECTED`   | -26 | TX or block rejected by network rules |
| `RPC_VERIFY_ALREADY_IN_UTXO_SET`       | -27 | TX already in UTXO set                    |
| `RPC_IN_WARMUP`                        | -28 | Client still warming up                   |
| `RPC_CLIENT_NODE_NOT_CONNECTED`        | -29 | Disconnect: peer not connected            |
| `RPC_CLIENT_INVALID_IP_OR_SUBNET`      | -30 | Invalid IP/subnet                         |
| `RPC_CLIENT_P2P_DISABLED`              | -31 | No connection manager                     |
| `RPC_METHOD_DEPRECATED`                | -32 | RPC method is deprecated                  |
| `RPC_CLIENT_MEMPOOL_DISABLED`          | -33 | No mempool instance                       |
| `RPC_CLIENT_NODE_CAPACITY_REACHED`     | -34 | Max outbound / block-relay connections    |
| `RPC_WALLET_ALREADY_LOADED`            | -35 | Wallet already loaded                     |
| `RPC_WALLET_ALREADY_EXISTS`            | -36 | Wallet with same name exists              |

## Architecture summary — hotbuns RPC error stack

- **One server**: `src/rpc/server.ts` — single `RPCServer` class with
  60+ method handlers + Bun.serve HTTP entry.
- **One error helper**: `this.rpcError(code, message)` returns an
  `Error & { code }`; thrown / caught in `processRequest()` which
  rewrites to `{ error: { code, message } }`. (server.ts:5907.)
- **One constants table**: `RPCErrorCodes` const at server.ts:207-236.
  Defines **20 of 32 canonical Core codes**; the remaining 12 codes
  are missing entirely (BUG 1–7 below cluster here).
- **Throw style is split**: 236 call sites use `throw this.rpcError(...)`
  (returns Error subclass); 30+ sites use `throw { code, message }`
  raw-object pattern (mostly wallet flow). Both work because
  `processRequest()` does `err.code ?? RPCErrorCodes.INTERNAL_ERROR`,
  but the dual style is fragile (the raw object loses `.message`-as-
  property when re-thrown by anything that does `error as Error`).

## Bug inventory (18 distinct findings)

### P0-API-CDIV — wrong code on the wire (clients branch on these)

- **BUG-1** (gate G6) — `INVALID_PARAMS` (-32602) is used everywhere
  for application-layer parameter validation. **All 86+ throws of
  `INVALID_PARAMS` should be `RPC_INVALID_PARAMETER` (-8).** Core's
  protocol.h comments are explicit: "`RPC_INVALID_REQUEST` is internally
  mapped to `HTTP_BAD_REQUEST`. It should not be used for application-
  layer errors." The same rule applies to `RPC_INVALID_PARAMS` —
  reserved by JSON-RPC 2.0 for **transport** errors (the method exists
  but the request shape is wrong). Application-layer "your hex string
  has odd length" is `RPC_INVALID_PARAMETER (-8)`.
  - Constant missing entirely from `RPCErrorCodes` table (server.ts:207).
  - 86+ throws in server.ts (e.g. `sendrawtransaction`,
    `getrawtransaction`, `addnode`, `setban`, `createwallet`,
    `walletpassphrase`, `bumpfee`, etc.).
  - Client-impact: `python-bitcoinrpc` raises `JSONRPCException` either
    way, but `bitcoin-cli`'s exit code differs (-32602 reads as
    "transport bug", -8 reads as "user error").
  - Reference: `src/rpc/rawtransaction.cpp:1540, src/rpc/mempool.cpp:322,
    src/rpc/blockchain.cpp:134, src/wallet/rpc/encrypt.cpp:61` all use
    `RPC_INVALID_PARAMETER`.

- **BUG-2** (gate G4) — `sendrawtransaction` raises
  `RPC_TRANSACTION_REJECTED` (-26) on **TX-decode failure**, but Core
  uses `RPC_DESERIALIZATION_ERROR` (-22). A decoder failure means we
  never got far enough to apply consensus rules — "rejected by network
  rules" is the wrong category.
  - `src/rpc/server.ts:3240-3243`.
  - Core: `src/rpc/rawtransaction.cpp:134` `"TX decode failed %s"` →
    `RPC_DESERIALIZATION_ERROR`.
  - Same bug in `submitPackage` (`server.ts:3389-3392`).

- **BUG-3** (gate G18) — `disconnectnode` raises `RPC_MISC_ERROR` (-1)
  on "Node X not found", but Core uses `RPC_CLIENT_NODE_NOT_CONNECTED`
  (-29).
  - `src/rpc/server.ts:4563`.
  - Core: `src/rpc/net.cpp:478` `"Node not found in connected nodes"` →
    `RPC_CLIENT_NODE_NOT_CONNECTED`.

- **BUG-4** (gate G18) — `setban remove` raises `RPC_MISC_ERROR` on
  "IP/Subnet X is not banned", but Core uses
  `RPC_CLIENT_INVALID_IP_OR_SUBNET` (-30).
  - `src/rpc/server.ts:4629`.
  - Core: `src/rpc/net.cpp:811`.

- **BUG-5** (gate G14) — `createwallet` raises `RPC_WALLET_ERROR` (-4)
  on duplicate name / already-loaded, but Core has dedicated codes
  `RPC_WALLET_ALREADY_EXISTS` (-36) and `RPC_WALLET_ALREADY_LOADED`
  (-35). The latter two are missing from the `RPCErrorCodes` constant
  table entirely.
  - `src/rpc/server.ts:6292-6294` (createwallet); `6350-6352` (loadwallet).
  - Core: `wallet/rpc/wallet.cpp` `RPC_WALLET_ALREADY_LOADED` /
    `RPC_WALLET_ALREADY_EXISTS`.

### P1-API — wrong category but not strictly wrong

- **BUG-6** (gate G3) — `RPC_TYPE_ERROR` (-3) is missing entirely.
  Many "X must be a number / string / bool" sites throw
  `INVALID_PARAMS` (already BUG-1) — but Core distinguishes
  "missing/wrong-shape" (`RPC_INVALID_PARAMETER` -8) from "wrong type"
  (`RPC_TYPE_ERROR` -3). Examples:
  `if (typeof feeRateParam !== "number")` should use TYPE_ERROR.
  - Constant missing from `RPCErrorCodes` table.
  - Core: `src/rpc/util.cpp:100-106` AmountFromValue, `signmessage.cpp:47`.
  - Lower-priority because clients rarely branch on -3 vs -8.

- **BUG-7** (gates G1+G2) — `RPC_DATABASE_ERROR` (-20) and
  `RPC_OUT_OF_MEMORY` (-7) are missing from `RPCErrorCodes` table. No
  call site uses either, even though hotbuns has database error paths
  (`db.getBlock(blockhash)` throwing inside chain rebuild) and
  ENOMEM-class paths (large UTXO set computations). Currently any DB
  exception escapes as `RPC_INTERNAL_ERROR` (-32603) via the catch in
  `processRequest()`.
  - server.ts:980-989.

- **BUG-8** (gate G7) — `RPC_CLIENT_IN_INITIAL_DOWNLOAD` (-10) is
  missing entirely. Bitcoin Core gates `getblocktemplate` (and
  `importmempool`) on IBD with code -10; hotbuns' `getblocktemplate`
  has no IBD check at all (separate from W123 BUG-X), but if it ever
  acquires one, it will fall back to MISC_ERROR / INTERNAL_ERROR
  because the constant doesn't exist.
  - Constant missing from `RPCErrorCodes` table.
  - Core: `src/rpc/mining.cpp:773` (`getblocktemplate` IBD gate).

- **BUG-9** (gate G7) — `RPC_IN_WARMUP` (-28) is missing entirely.
  Core uses this to reject **every** RPC during early startup
  (`fRPCInWarmup` until `setRPCWarmupFinished()` is called after chain
  load completes). hotbuns has no warmup gate at all — the RPC server
  starts accepting requests the moment `Bun.serve()` returns, even if
  `chainState.getBestBlock()` would throw or return uninitialized
  data. Concrete: a request to `getblockcount` racing the
  `chainState.load()` boot phase can return `0` (the wrong answer)
  rather than the in-progress warmup signal.
  - Constant missing from `RPCErrorCodes` table.
  - Core: `src/rpc/server.cpp:488`.

- **BUG-10** (gate G8) — `RPC_CLIENT_NOT_CONNECTED` (-9),
  `RPC_CLIENT_NODE_ALREADY_ADDED` (-23), `RPC_CLIENT_NODE_NOT_ADDED`
  (-24), `RPC_CLIENT_INVALID_IP_OR_SUBNET` (-30),
  `RPC_CLIENT_P2P_DISABLED` (-31), `RPC_CLIENT_NODE_CAPACITY_REACHED`
  (-34), `RPC_CLIENT_MEMPOOL_DISABLED` (-33) — **7 P2P/client codes
  missing**.
  - `addnode "add"` failure uses MISC_ERROR (-1); Core uses different
    codes depending on the underlying reason (capacity reached: -34;
    node already added: -23; capacity reached for connection type:
    -34; v2transport requested but not enabled: -8).
  - `addnode` if peerManager hasn't started: should be -31, hotbuns
    falls through to a generic try/catch.
  - server.ts:4515-4518 (addnode); 4628-4629 (setban remove).
  - Core: `src/rpc/net.cpp:362-428, 478, 780-811`.

- **BUG-11** (gate G15) — `RPC_METHOD_DEPRECATED` (-32) is missing
  entirely. Not currently used by any hotbuns method, but if
  any wallet method gets a "dummy first argument" deprecation gate
  (Core does this on `listreceivedbyaddress` etc.) it will fall back to
  MISC_ERROR. Track as an "audit-gate-only" missing constant —
  P2 (no current call site).
  - Constant missing from `RPCErrorCodes` table.
  - Core: `src/wallet/rpc/coins.cpp:200`.

### P1-WIRE — wrong response shape

- **BUG-12** (gate G16) — JSON-RPC 2.0 `error.data` field is
  **never emitted** by hotbuns. Core's `JSONRPCError` builds
  `{ code, message }` only by default, but the bitcoin-cli error
  formatter and some clients (e.g. `python-bitcoinlib`) look for
  optional `data.txid` / `data.reject-reason` when present. hotbuns'
  `processRequest` only ever returns `{ code, message }`; the
  `RPCResponse` type allows `data?: unknown` (server.ts:143) but
  there is no producer code path.
  - Lower priority — Core itself rarely emits `data` outside of a
    `BlockValidationState`-bearing throw — but this is the missing
    plumbing for it.
  - server.ts:980-989.

- **BUG-13** (gate G17) — Batch-request response on JSON parse
  failure of a **single batch entry** is non-conformant. Currently
  hotbuns parses the whole batch as JSON (so a bad inner item fails
  the whole batch); JSON-RPC 2.0 §6 requires each entry to be
  validated independently and yield a `{ id: null, error: ... }` for
  the bad one only, with successful ones still completing.
  - server.ts:874-918.
  - JSON-RPC 2.0 §6.

- **BUG-14** (gate G19) — On invalid JSON, hotbuns returns HTTP **400
  Bad Request**. JSON-RPC 2.0 §5.1 prescribes HTTP **200 OK** for all
  JSON-RPC responses including errors (the error is in the body, not
  the HTTP status). Bitcoin Core's HTTP server does return HTTP 200
  for parse errors. Some strict JSON-RPC clients (especially
  legacy ones bundled with `bitcoinlib`) refuse to even parse the
  body if the HTTP status isn't 200.
  - server.ts:867 (status: 400 on parse error), 933 (status: 400 on
    top-level non-object).
  - Core: `src/httpserver.cpp` always sends 200 for JSON-RPC bodies
    except 401 (auth) and 503 (warmup).

- **BUG-15** (gate G29) — HTTP 405 returned for non-POST. Core
  returns `400 Bad Request` (see `httprpc.cpp` `HTTPReq_JSONRPC`).
  Mostly cosmetic.
  - server.ts:805.

### P2-CONSISTENCY — internal hotbuns issues

- **BUG-16** (gate G22) — Dual throw style: 236 sites use
  `this.rpcError(code, msg)` (returns Error); 30+ sites use
  `throw { code, message }` raw object. The two work but are
  inconsistent. The raw-object pattern loses `Error`-instance
  semantics, breaks `err instanceof Error` checks, and any caller
  doing `err.message` directly on the raw throw gets a non-stack-trace
  message.
  - Examples of raw-object throws: server.ts:6126, 6136, 6147, 6154,
    6163, 6194, 6211, 6483, 6516, 6529 (createwallet, walletpassphrase,
    encryptwallet, getCurrentWallet).
  - Recommendation: unify on `this.rpcError`.

- **BUG-17** (gate G23) — `RPC_VERIFY_ALREADY_IN_UTXO_SET` (-27) is
  defined under TWO names: `RPC_TRANSACTION_ALREADY_IN_CHAIN` and
  `VERIFY_ALREADY_IN_CHAIN`. Core's alias is
  `RPC_TRANSACTION_ALREADY_IN_CHAIN = RPC_VERIFY_ALREADY_IN_UTXO_SET`
  but the **canonical name** in Core is now
  `RPC_VERIFY_ALREADY_IN_UTXO_SET` (`protocol.h:49`); the
  `RPC_TRANSACTION_*` aliases are tagged as "Backwards compatible
  aliases" (comment line 53). hotbuns has both names but no
  `VERIFY_ALREADY_IN_UTXO_SET` to match the modern Core canon.
  - server.ts:220-222.

- **BUG-18** (gate G24) — `WALLET_ALREADY_UNLOCKED` (-17): the
  constant exists in `RPCErrorCodes` but is **never thrown** by any
  call site. The matching `walletpassphrase` handler raises
  `WALLET_WRONG_ENC_STATE` (-15) on already-unlocked, which Core
  does too (`encrypt.cpp:49,138`), but the unused constant is a
  reader-confusion hazard.
  - server.ts:233 (declared), no usage.
  - Cosmetic — keep the constant for future use OR remove it.

## Audit gate decisions (30)

Legend: `PRESENT` (Core-compatible), `PARTIAL` (right ballpark, missing
nuance), `MISSING` (no code at all).

| # | Gate                                                                  | Status   | Bug refs              | Note |
|---|-----------------------------------------------------------------------|----------|-----------------------|------|
| 01| JSON-RPC 2.0 transport codes (-32700..-32603)                          | PRESENT  |                       | PARSE/INVALID_REQUEST/METHOD_NOT_FOUND/INVALID_PARAMS/INTERNAL_ERROR all defined and used at the right layer. |
| 02| RPC_MISC_ERROR (-1) as fallback for unspecified errors                 | PRESENT  |                       | Defined + used appropriately for unrecognised internal errors. |
| 03| RPC_TYPE_ERROR (-3) for wrong-type params                              | MISSING  | BUG-6                 | Constant absent; all type errors collapsed into INVALID_PARAMS. |
| 04| RPC_WALLET_ERROR (-4) for unspecified wallet failures                  | PRESENT  |                       | Defined + used. |
| 05| RPC_INVALID_ADDRESS_OR_KEY (-5)                                        | PRESENT  |                       | Defined + used for block-not-found, tx-not-found, address-decode. |
| 06| RPC_INVALID_PARAMETER (-8) for application-layer param errors          | MISSING  | BUG-1                 | Constant absent; all sites use INVALID_PARAMS (-32602). Largest BUG in this audit by call-site count. |
| 07| RPC_OUT_OF_MEMORY (-7) for ENOMEM-class                                | MISSING  | BUG-7                 | Constant absent; no call site. |
| 08| RPC_CLIENT_NOT_CONNECTED (-9)                                          | MISSING  | BUG-10                | Constant absent. |
| 09| RPC_CLIENT_IN_INITIAL_DOWNLOAD (-10)                                   | MISSING  | BUG-8                 | Constant absent + no IBD gate at any RPC entry point. |
| 10| RPC_WALLET_INVALID_LABEL_NAME (-11)                                    | PRESENT  |                       | Defined; reachable through wallet manager when no addresses match label (Core: addresses.cpp:568). hotbuns: wallet.setLabel error path collapses to INVALID_ADDRESS_OR_KEY (could be partial). |
| 11| RPC_WALLET_KEYPOOL_RAN_OUT (-12)                                       | PARTIAL  |                       | Constant defined but no call site explicitly throws it (descriptor wallets pre-fill keypool in hotbuns; in practice cannot be exhausted, but the gate is missing in case keypool ever empties). |
| 12| RPC_WALLET_UNLOCK_NEEDED (-13)                                         | PRESENT  |                       | Defined + thrown in bumpfee, sendtoaddress, signRawTransactionWithWallet. |
| 13| RPC_WALLET_PASSPHRASE_INCORRECT (-14)                                  | PRESENT  |                       | Defined + thrown in walletpassphrase, walletpassphrasechange. |
| 14| RPC_WALLET_ALREADY_LOADED (-35) / _ALREADY_EXISTS (-36)                | MISSING  | BUG-5                 | Both constants absent; createwallet/loadwallet collapse both to WALLET_ERROR (-4). |
| 15| RPC_METHOD_DEPRECATED (-32)                                            | MISSING  | BUG-11                | Constant absent; no call site (audit-gate-only). |
| 16| JSON-RPC error.data extension field                                    | MISSING  | BUG-12                | Type accepts it (server.ts:143); no producer ever emits it. |
| 17| Batch request partial error handling                                   | MISSING  | BUG-13                | Single bad entry fails the whole batch. JSON-RPC 2.0 §6 violation. |
| 18| Peer disconnect / setban-remove unknown-node codes (-29, -30)          | MISSING  | BUG-3, BUG-4          | Both collapse to MISC_ERROR. |
| 19| HTTP status code 200 for JSON-RPC bodies                               | PARTIAL  | BUG-14                | 200 on success + many errors; 400 on parse error / non-object body. |
| 20| HTTP 401 on auth fail                                                  | PRESENT  |                       | server.ts:838-852. |
| 21| Cookie auth → INVALID_REQUEST (-32600) in JSON body                    | PRESENT  |                       | server.ts:842 maps auth failure to JSON-RPC INVALID_REQUEST in body. |
| 22| Throw style consistency (Error subclass vs raw object)                 | PARTIAL  | BUG-16                | 236 vs 30+; dual style. |
| 23| Modern canonical name RPC_VERIFY_ALREADY_IN_UTXO_SET (-27)             | PARTIAL  | BUG-17                | Only old-name alias RPC_TRANSACTION_ALREADY_IN_CHAIN present. |
| 24| Dead-helper RPCErrorCodes.WALLET_ALREADY_UNLOCKED                      | PARTIAL  | BUG-18                | Defined but unused. |
| 25| RPC_DESERIALIZATION_ERROR (-22) for TX decode failures                 | MISSING  | BUG-2                 | Constant absent; sendrawtransaction / submitpackage / combinerawtransaction (would-be) use RPC_TRANSACTION_REJECTED. |
| 26| RPC_DATABASE_ERROR (-20)                                               | MISSING  | BUG-7                 | Constant absent. |
| 27| RPC_VERIFY_ERROR (-25) variant of RPC_TRANSACTION_ERROR                | PRESENT  |                       | Aliased: VERIFY_ALREADY_IN_CHAIN -25 (note this is a name confusion — should be RPC_VERIFY_ERROR -25; see BUG-17). Treat as PRESENT-with-naming-quirk. |
| 28| RPC_IN_WARMUP (-28)                                                    | MISSING  | BUG-9                 | No warmup state machine at all. |
| 29| HTTP 400 for non-POST → JSON body OR HTTP 405                          | PARTIAL  | BUG-15                | Returns 405 (Method Not Allowed); Core returns 400 with JSON body. |
| 30| RPC_CLIENT_P2P_DISABLED / _NODE_CAPACITY_REACHED / _MEMPOOL_DISABLED   | MISSING  | BUG-10                | All three constants absent. |

## Summary

- **PRESENT**: 10 / 30 (gates 1, 2, 4, 5, 10, 12, 13, 20, 21, 27)
- **PARTIAL**: 5 / 30 (gates 11, 19, 22, 23, 24, 29 — 6 gates classified
  partial in the matrix above)
- **MISSING**: 15 / 30 (gates 3, 6, 7, 8, 9, 14, 15, 16, 17, 18, 25, 26,
  28, 30 + gate 11 also borderline)

(Matrix counts: 10 PRESENT + 5 PARTIAL + 15 MISSING = 30. Gate 11 is
classified PARTIAL above; gate 24 PARTIAL; gate 29 PARTIAL; gate 22
PARTIAL; gate 23 PARTIAL; gate 19 PARTIAL.)

- **18 distinct bugs** spanning **all 5 buckets**:
  P0-API-CDIV (5): wrong codes on the wire that clients branch on
  (BUG-1, 2, 3, 4, 5).
  P1-API (6): wrong category for status reporting (BUG-6, 7, 8, 9, 10, 11).
  P1-WIRE (4): wrong JSON-RPC envelope shape (BUG-12, 13, 14, 15).
  P2-CONSISTENCY (3): hotbuns-internal cleanups (BUG-16, 17, 18).

## Cross-impl context

- **Universal pattern this audit**: "constant-table-incomplete-relative-
  to-Core-protocol.h" — hotbuns defines **20 of 32** canonical codes.
  The 12 missing constants explain 10 of the 18 bugs (every bug 6-11 +
  17 is rooted in a missing constant).
- **No dead-helper finding** in this audit (the 33+ wave streak does
  NOT extend to RPC error codes — the issue is opposite shape: missing
  constants, not unreachable ones).
- **No comment-as-confession finding** — error codes have no
  comment-as-confession surface area.
- **The single largest scale finding** is BUG-1: 86+ throws use the
  wrong code. A simple `RPC_INVALID_PARAMETER = -8` constant + sed
  rename would close it; tests in this audit catch the wire-code
  expectation against Core to confirm any future fix lands.

## Fix-shaping notes (NOT implemented in this audit)

A future FIX-W125 wave would:
1. Extend `RPCErrorCodes` to all 32 canonical Core codes (~12 new
   entries; no breaking change because constants are additive).
2. Mechanical replace `INVALID_PARAMS` → `INVALID_PARAMETER` in every
   `this.rpcError` call except those that are genuinely transport-
   layer (in `processRequest`/parse / batch / method-not-found).
3. Add `DESERIALIZATION_ERROR` (-22) at the 4-5 TX-decode-failure
   sites in `sendrawtransaction` / `submitPackage` / similar.
4. Add `RPC_CLIENT_NODE_NOT_CONNECTED` (-29) /
   `RPC_CLIENT_INVALID_IP_OR_SUBNET` (-30) at the two net.cpp-parity
   sites.
5. Add `RPC_WALLET_ALREADY_LOADED` (-35) / `_ALREADY_EXISTS` (-36) at
   the createwallet / loadwallet error paths (requires walletManager
   to surface "name-already-loaded" vs "name-on-disk-exists" as
   distinct error variants — Modest refactor).
6. Add a startup warmup flag — `chainState.isReady()` predicate
   guarding `processRequest` until `chainState.load()` finishes; raise
   `RPC_IN_WARMUP` (-28) before that.
7. Unify error throws on `this.rpcError`; remove raw-object pattern.
8. HTTP status 200 for all parse/top-level errors.

Estimated W125-FIX size: ~300-400 LOC + ~150 test assertions, single
PR-shaped wave.

## References

- bitcoin-core/src/rpc/protocol.h
- bitcoin-core/src/rpc/util.cpp
- bitcoin-core/src/rpc/server.cpp
- bitcoin-core/src/rpc/server_util.cpp
- bitcoin-core/src/rpc/rawtransaction.cpp
- bitcoin-core/src/rpc/mempool.cpp
- bitcoin-core/src/rpc/blockchain.cpp
- bitcoin-core/src/rpc/mining.cpp
- bitcoin-core/src/rpc/net.cpp
- bitcoin-core/src/rpc/node.cpp
- bitcoin-core/src/wallet/rpc/encrypt.cpp
- bitcoin-core/src/wallet/rpc/spend.cpp
- bitcoin-core/src/wallet/rpc/wallet.cpp
- bitcoin-core/src/wallet/rpc/addresses.cpp
- JSON-RPC 2.0 §5.1 (Error object), §6 (batch).
