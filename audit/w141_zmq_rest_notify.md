# W141 — ZMQ + REST + Notification scripts audit (hotbuns)

**Impl:** hotbuns (TypeScript / Bun)
**Date:** 2026-05-18
**Status:** DISCOVERY — 22 BUGS / 30 gates
**Tests:** `src/__tests__/w141_zmq_rest_notify.test.ts` (assertion-only, no
production code changes).
**No production code changes in this wave.**

## References

### Bitcoin Core
- `bitcoin-core/src/zmq/zmqabstractnotifier.h` —
  `DEFAULT_ZMQ_SNDHWM = 1000`, the abstract publisher contract
  (`NotifyBlock`, `NotifyBlockConnect`, `NotifyBlockDisconnect`,
  `NotifyTransaction`, `NotifyTransactionAcceptance`,
  `NotifyTransactionRemoval`).
- `bitcoin-core/src/zmq/zmqpublishnotifier.cpp` — wire-format
  ground truth:
  - `MSG_HASHBLOCK / MSG_HASHTX / MSG_RAWBLOCK / MSG_RAWTX /
    MSG_SEQUENCE` (lines 33–37).
  - `zmq_send_multipart` (line 40) — three-part `[topic, body,
    seq_LE_u32]`.
  - `CZMQPublishHashBlockNotifier::NotifyBlock` (lines 210–219) —
    hash REVERSED before sending (LE→BE display order via
    `data[31 - i] = hash.begin()[i]`).
  - `SendSequenceMsg` (lines 256–265) — same hash reversal, then
    1-byte label, then optional 8-byte LE mempool sequence.
  - `CZMQPublishRawBlockNotifier::NotifyBlock` (lines 232–243) —
    reads block from disk on demand via `m_get_block_by_index`.
  - `CZMQPublishRawTransactionNotifier::NotifyTransaction` (lines
    245–252) — serialized `TX_WITH_WITNESS`.
- `bitcoin-core/src/zmq/zmqnotificationinterface.cpp`:
  - `Create(get_block_by_index)` (lines 44–85) — reads `-zmqpub*`
    args + per-topic `-zmqpub*hwm` args; supports `unix://` →
    `ipc://` rewrite.
  - `UpdatedBlockTip` (line 151) — **EARLY-RETURN during IBD**
    (`fInitialDownload`) and on no-new-block trips.
  - `TransactionAddedToMempool` (line 161) — fires
    `NotifyTransaction` AND `NotifyTransactionAcceptance`.
  - `BlockConnected` (line 180) — **per-tx `NotifyTransaction`
    loop** so `pubhashtx` / `pubrawtx` fire for every tx in every
    connected block (not only mempool-accepted ones); then
    `NotifyBlockConnect` for `pubsequence` 'C'.
  - `BlockDisconnected` (line 198) — symmetric: per-tx
    `NotifyTransaction` loop on disconnect, then `pubsequence` 'D'.
  - `TryForEachAndRemoveFailed` (line 136) — failed notifier is
    EVICTED, not retried.
- `bitcoin-core/src/zmq/zmqpublishnotifier.h` (mapPublishNotifiers
  multi-topic-per-address sharing).
- `bitcoin-core/src/rest.cpp`:
  - `MAX_GETUTXOS_OUTPOINTS = 15` (line 44), `MAX_REST_HEADERS_RESULTS
    = 2000` (line 45).
  - `ParseDataFormat` (line 129) — `param.rfind('?')` strips the
    query string FIRST, then `param.rfind('.')` extracts the
    extension. Unknown extension → `RESTResponseFormat::UNDEF`,
    NOT a silent JSON fallback.
  - `CheckWarmup` (line 171) — every route returns
    `HTTP_SERVICE_UNAVAILABLE` while `RPCIsInWarmup` is true.
  - `rest_block` (lines 389–469) — distinguishes
    `BLOCK_HAVE_DATA` miss into "(pruned data)" vs "(not fully
    downloaded)"; "JSON output is not supported for this request
    type" if no `tx_verbosity`.
  - `rest_tx` (line 838) — calls `g_txindex->BlockUntilSyncedToCurrentChain()`
    BEFORE looking up the txid (line 851).
  - `rest_getutxos` (line 897) — accepts POST body
    (`strRequestMutable = req->ReadBody()`) AND URI-form input;
    rejects "Combination of URI scheme inputs and raw post data is
    not allowed" if both supplied.
  - `rest_filter_header` (line 500) — calls
    `BlockUntilSyncedToCurrentChain()` (line 563) and the error
    string distinguishes "still indexing" vs
    "indicates index corruption".
  - `rest_block_filter` (line 622) — also calls
    `BlockUntilSyncedToCurrentChain` and adds "Block was not
    connected to active chain" branch (line 670).
  - URL routing table (line 1141): `/rest/tx/`, `/rest/block/
    notxdetails/`, `/rest/block/`, `/rest/blockpart/`,
    `/rest/blockfilter/`, `/rest/blockfilterheaders/`,
    `/rest/chaininfo`, `/rest/mempool/`, `/rest/headers/`,
    `/rest/getutxos`, `/rest/deploymentinfo/`,
    `/rest/blockhashbyheight/`, `/rest/spenttxouts/`.
- `bitcoin-core/src/init.cpp`:
  - `DEFAULT_REST_ENABLE = false` (line 153).
  - `-blocknotify` (line 498) — fires on POST_INIT
    `NotifyBlockTip`, `%s` replaced by `block.GetBlockHash().GetHex()`
    (BE display order, line 2014).
  - `-alertnotify`, `-startupnotify`, `-shutdownnotify` (lines 485,
    529, 530).
  - `StartupNotify` (line 738) — `runCommand` in a detached thread.
  - `ShutdownNotify` (line 256) — joins on each thread (waits
    for completion before continuing shutdown).
- `bitcoin-core/src/common/system.cpp`:
  - `ShellEscape` (line 41) — wraps in `'…'` and escapes embedded
    `'` via `'"'"'`; ONLY used by `-walletnotify` substitution in
    `wallet/wallet.cpp` (NOT by `-blocknotify` per
    init.cpp:2013).
  - `runCommand` (line 50) — calls `::system(strCommand.c_str())`
    DIRECTLY; `%s` is replaced with raw block hash hex which is
    guaranteed `[0-9a-f]{64}` so no escape needed.

### BIPs
- None — this audit covers operator interfaces (ZMQ, REST, notify
  hooks) that sit outside the consensus protocol.

## Audit-framework note (W141 specific)

This is a "scripts + observability" wave, not a consensus wave. The
CLAUDE.md observation about hotbuns ZMQ NIF crashing on `bun install`
applies here: even though the source compiles, the production binary
in the fleet has never been observed to publish ZMQ messages. The
audit assesses whether ZMQ would work IF the runtime cooperated, by
inspecting the static source.

## Hotbuns files in scope

- `src/rpc/zmq.ts` (385 lines) — `ZMQNotificationInterface` class,
  `parseZMQArgs`, `wireZMQNotifications`, `createNotificationEmitter`.
- `src/rpc/rest.ts` (1175 lines) — `RESTServer` class, `Bun.serve`
  wiring, all REST routes.
- `src/cli/cli.ts` (2771 lines) — operator entry-point; wires
  `chainEvents` emitter between `ChainStateManager` and `Mempool`
  (lines 1787–1789); REST opt-in at lines 2074–2097; **never
  imports `ZMQNotificationInterface` / `parseZMQArgs` /
  `wireZMQNotifications`**.
- `src/rpc/server.ts` — `RPCServer.zmqInterface` is a typed-optional
  dependency (lines 202, 458, 541) wired into `getzmqnotifications`
  (line 7396). The dependency exists; nothing constructs it.
- `src/chain/state.ts` (lines 188, 222, 229, 470, 471, 766, 767),
  `src/mempool/mempool.ts` (lines 1169, 1215, 1230, 1242, 2226,
  2229, 2313, 2316) — emit `blockConnected` / `blockDisconnected` /
  `txAccepted` / `txRemoved` events on the shared
  `chainEvents` emitter.

## Audit matrix (30 gates)

| ID | Subsystem | Gate (Core behavior expected of hotbuns) | Status |
|----|-----------|------------------------------------------|--------|
| **ZMQ — wire format** | | | |
| G1 | zmq | Multipart message format `[topic, body, LE-u32 sequence]` | PASS |
| G2 | zmq | Hash bytes in `hashblock` / `hashtx` / `sequence` body are REVERSED (BE display) before send | **BUG-1** |
| G3 | zmq | `rawblock` body = full block with witness; `rawtx` body = `TX_WITH_WITNESS` | PASS |
| G4 | zmq | Sequence body: 32-byte hash + 1-byte label + (optional) 8-byte LE mempool_seq | PASS (format) / **BUG-1** (byte order on hash) |
| G5 | zmq | Per-topic sequence number monotonically increments, wraps as u32 | PASS |
| **ZMQ — lifecycle** | | | |
| G6 | zmq | Topic args parse pattern `-zmqpub<topic>=<addr>` AND per-topic `-zmqpub<topic>hwm=<n>` | **BUG-2** |
| G7 | zmq | CLI arg prefix matches Core: single hyphen `-zmqpub*` (Core) or double `--zmqpub*` (other impls) — argv reaches `parseZMQArgs` | **BUG-3** |
| G8 | zmq | `ZMQNotificationInterface` is constructed and started in production from `cli.ts` when any `-zmqpub*` arg is set | **BUG-4** |
| G9 | zmq | `unix://` socket-address prefix rewritten to `ipc://` before bind | **BUG-5** |
| G10 | zmq | Multiple notifiers share a single socket per address (Core's `mapPublishNotifiers`) | PASS |
| G11 | zmq | `Shutdown` sets `ZMQ_LINGER = 0` before `zmq_close` | **BUG-6** |
| **ZMQ — semantics** | | | |
| G12 | zmq | `UpdatedBlockTip` skips during IBD (`fInitialDownload`) | **BUG-7** |
| G13 | zmq | On `BlockConnected`, fire `NotifyTransaction` (hashtx + rawtx) for EVERY tx in the block, not only mempool-accepted ones | **BUG-8** |
| G14 | zmq | On `BlockDisconnected`, fire `NotifyTransaction` (hashtx + rawtx) for EVERY tx returning to mempool, then `pubsequence` 'D' | **BUG-9** |
| G15 | zmq | A failed publish removes the notifier from rotation (Core's `TryForEachAndRemoveFailed`); does NOT retry on every event | **BUG-10** |
| G16 | zmq | `pubsequence` 'A' fires on `TransactionAddedToMempool` with monotonic mempool sequence; `pubsequence` 'R' fires on every removal-except-block-inclusion | PASS (wiring exists, see G8) |
| **REST — routing + framing** | | | |
| G17 | rest | All endpoints gated by warmup (`HTTP_SERVICE_UNAVAILABLE` while node is in warmup / before chain tip is loaded) | **BUG-11** |
| G18 | rest | `ParseDataFormat` strips query-string before extension parse; UNKNOWN extension yields `UNDEF` (per-route 404 "output format not found"), NOT silent JSON fallback | **BUG-12** |
| G19 | rest | Endpoints exposed: tx, block, block/notxdetails, blockpart, blockfilter, blockfilterheaders, chaininfo, mempool/{info,contents}, headers, getutxos, deploymentinfo, blockhashbyheight, spenttxouts | **BUG-13** |
| G20 | rest | `getutxos` accepts POST body (BIN/HEX inputs) AND URI-form; rejects "Combination of URI scheme inputs and raw post data is not allowed" if both | **BUG-14** |
| G21 | rest | `-rest` is OFF by default; opt-in via `-rest=1` | PASS |
| G22 | rest | REST server binds on its own port (Core embeds REST in the same HTTP server as RPC); hotbuns uses a separate port — default = rpcPort + 1 | PASS (with caveat: NOT Core-byte-identical operator surface) |
| **REST — data accuracy** | | | |
| G23 | rest | `confirmations` is `-1` if block/tx not on active chain | **BUG-15** |
| G24 | rest | `chaininfo.mediantime` is the actual MTP of tip, not zero | **BUG-16** |
| G25 | rest | `chaininfo.softforks` populated with deployment state | **BUG-17** |
| G26 | rest | `rest_tx` calls `BlockUntilSyncedToCurrentChain` on the txindex before lookup | **BUG-18** |
| G27 | rest | `block` route distinguishes "not available (pruned data)" vs "not available (not fully downloaded)" vs "not found" | **BUG-19** |
| G28 | rest | `blockfilter` / `blockfilterheaders` routes call `BlockUntilSyncedToCurrentChain` on the filter index and distinguish "indexing" vs "indicates index corruption" | **BUG-20** |
| **Notification scripts** | | | |
| G29 | notify | `-blocknotify`, `-alertnotify`, `-startupnotify`, `-shutdownnotify`, `-walletnotify` are recognized CLI args; `%s` substitution implemented per Core init.cpp:498/2013 | **BUG-21** |
| G30 | notify | If hotbuns ever adds a notify hook, `%s` is replaced by the BE-hex of the block hash AFTER shell-escaping the substituted value (Core uses ShellEscape for `-walletnotify`; `-blocknotify` is safe because hash hex is `[0-9a-f]{64}`) — and the runner is `child_process.exec` / `Bun.spawn` with full quoting, NOT raw `system()` on untrusted operator-supplied template | **BUG-22** (preemptive — see Notes) |

**Summary:** 22 BUGs across the 30 gates.

## Bug catalogue

### ZMQ — wire format

#### BUG-1 (P0-CDIV): Hash byte-order — hotbuns publishes internal-LE; Core publishes display-BE

`src/rpc/zmq.ts:210` `await this.publish("hashblock", blockHash);`
where `blockHash` comes from `getBlockHash(block.header)` (line 207).

`src/validation/block.ts:163-167`:
```ts
/** Returns in little-endian (internal) format. */
export function getBlockHash(header: BlockHeader): Buffer {
  return hash256(serializeBlockHeader(header));
}
```

Core (`zmqpublishnotifier.cpp:214-218`):
```cpp
uint256 hash = pindex->GetBlockHash();
uint8_t data[32];
for (unsigned int i = 0; i < 32; i++) {
    data[31 - i] = hash.begin()[i];   // REVERSE
}
return SendZmqMessage(MSG_HASHBLOCK, data, 32);
```

Core publishes the bytes in display order (BE). Every downstream
ZMQ consumer in the ecosystem (electrs, Fulcrum, mempool.space,
btcd test fixtures, the Python zmq examples shipped in
`contrib/zmq/zmq_sub.py`) expects display-order hashes — i.e.
the first byte of the body must be the high-order byte of the
hash. Hotbuns sends LSB-first.

Same defect applies to `hashtx` (line 221), `rawblock` (line 213,
the serialized block hash is correct by construction, but the
embedded prev-hash inside is unaffected — only the standalone
`hashblock` / `hashtx` / sequence payloads matter here), and the
hash prefix of `sequence` bodies (lines 305–308 and 311–314 in
`publishSequence`).

**Impact:** every downstream tool that subscribes to hotbuns ZMQ
would index transactions / blocks under reversed txids relative to
the rest of the network. Latent because nothing constructs the
`ZMQNotificationInterface` in production (see BUG-4).

#### BUG-2 (P1-NEAR): Per-topic `-zmqpub*hwm` HWM args ignored

Core (`zmqnotificationinterface.cpp:69`):
```cpp
notifier->SetOutboundMessageHighWaterMark(
    static_cast<int>(gArgs.GetIntArg(arg + "hwm", DEFAULT_ZMQ_SNDHWM)));
```

`hotbuns/src/rpc/zmq.ts:56-83` (`parseZMQArgs`) only matches
`/^--zmqpub(\w+)=(.+)$/` and only emits `topic + address`. There
is no path to set HWM. The `getNotifications` accessor hardcodes
`hwm: 1000` (line 197) regardless of operator intent. An operator
that needs `--zmqpubhashblockhwm=10000` (typical for high-throughput
indexers under bursty mempool traffic) has no knob.

#### BUG-3 (P1-NEAR): CLI arg parsing — `--zmqpub*` requires double-dash; Core uses single

Core's `gArgs.GetArgs("-zmqpubhashblock")` reads single-dash args
out of the `-conf` file and command line. Hotbuns matches
`/^--zmqpub(\w+)=(.+)$/`. Operators copy-pasting Core flags will
silently get zero notifiers. This is a fleet-wide pattern across
hotbuns flags (e.g. `--rpcport` works) but is a documented
divergence from Core that should at least be tolerated by
accepting both `-zmqpub*` and `--zmqpub*` (similar to how Core
historically tolerated both for `-rpcuser`).

### ZMQ — lifecycle

#### BUG-4 (P0-CDIV: dead code): `ZMQNotificationInterface` is never instantiated in production

`src/cli/cli.ts` is the operator entry-point. `grep -n zmq` returns
exactly one hit — a comment on line 1785 referring to "ZMQ-style
txAccepted/txRemoved events" (the same event names this audit just
classified). No `import` of `./rpc/zmq.js`. No call to
`parseZMQArgs(args)`. No `new ZMQNotificationInterface()`. No
`wireZMQNotifications(zmq, chainEvents)`.

`src/rpc/server.ts:202` declares `zmqInterface?` as an OPTIONAL
RPCServerDeps field. The `getzmqnotifications` RPC handler
(line 7396) is registered but always returns `[]` because
`this.zmqInterface` is always `undefined` in production.

This is the SAME dead-code pattern called out at
`src/rpc/rest.ts:21-25`:

> "Wired into production by cli.ts when `--rest=1` is passed
>  (default OFF, matching Bitcoin Core's `DEFAULT_REST_ENABLE =
>  false`). This class was previously written but never instantiated
>  outside tests; the cli.ts wiring closes the dead-code gap flagged
>  by CORE-PARITY-AUDIT/_rest-api-cross-impl-audit-2026-05-06-part2.md (R1)."

REST got rescued. ZMQ has not. The compiled production output
(`src/index.js` lines 29306+, 33357+) shows the same pattern —
`zmqInterface` field exists, never populated.

This is also consistent with CLAUDE.md "Known Issues" note:

> "**hotbuns**: Requires Bun runtime (not Node.js) — uses
>  Bun-specific APIs. ZeroMQ NIF crashes during `bun install` but
>  node runs fine with `bun run`."

The NIF crash never surfaces in production because production
never tries to load the `zeromq` module (`await import("zeromq")`
on `zmq.ts:119` is never reached).

#### BUG-5 (P2-MED): `unix://` → `ipc://` rewrite missing

Core (`zmqnotificationinterface.cpp:61-64`):
```cpp
if (address.starts_with(ADDR_PREFIX_UNIX)) {
    address.replace(0, ADDR_PREFIX_UNIX.length(), ADDR_PREFIX_IPC);
}
```

Hotbuns `start()` passes the address directly to
`socket.bind(address)`. Operators who set
`--zmqpubhashblock=unix:///run/hotbuns/zmq` (a documented Core
form per the bitcoin-core CHANGELOG for v0.20) would get a libzmq
error rather than the expected IPC binding.

#### BUG-6 (P1-NEAR): `ZMQ_LINGER = 0` not set before close

Core (`zmqpublishnotifier.cpp:185-187`):
```cpp
int linger = 0;
zmq_setsockopt(psocket, ZMQ_LINGER, &linger, sizeof(linger));
zmq_close(psocket);
```

Without `LINGER = 0`, `zmq_close` blocks shutdown waiting for
unflushed queued messages. The default linger is `-1` (block
forever). Hotbuns `stop()` (line 156) calls
`pub.socket.close()` without setting linger — under load this
can hang shutdown.

### ZMQ — semantics

#### BUG-7 (P1-NEAR): No IBD skip in `notifyBlock`

Core (`zmqnotificationinterface.cpp:151-154`):
```cpp
void CZMQNotificationInterface::UpdatedBlockTip(
    const CBlockIndex *pindexNew, const CBlockIndex *pindexFork,
    bool fInitialDownload)
{
    if (fInitialDownload || pindexNew == pindexFork) return;
    ...
}
```

Hotbuns `ZMQNotificationInterface.notifyBlock` (line 206) takes a
`Block` and unconditionally publishes. The caller in `cli.ts` (the
`chainEvents.on("blockConnected", ...)` block at line 1790, plus
any prospective ZMQ wire-up) has no IBD signal coupled to it.
Result: during IBD on testnet4 (~200k blocks) hotbuns would emit
~200k `hashblock` + `rawblock` messages, swamping any subscriber.
Core silently drops these.

#### BUG-8 (P1-NEAR): `notifyBlock` fires `hashtx` per tx, but not `rawtx`

Hotbuns (`zmq.ts:218-222`):
```ts
// hashtx for each transaction in block
for (const tx of block.transactions) {
  const txid = getTxId(tx);
  await this.publish("hashtx", txid);
}
```

Core (`zmqnotificationinterface.cpp:185-189`, `BlockConnected`):
```cpp
for (const CTransactionRef& ptx : pblock->vtx) {
    const CTransaction& tx = *ptx;
    TryForEachAndRemoveFailed(notifiers, [&tx](CZMQAbstractNotifier* notifier) {
        return notifier->NotifyTransaction(tx);   // fires BOTH hashtx AND rawtx
    });
}
```

`NotifyTransaction` is the abstract method overridden by both
`CZMQPublishHashTransactionNotifier` (publishes hashtx) AND
`CZMQPublishRawTransactionNotifier` (publishes rawtx). Hotbuns
only emits `hashtx` from the block-iteration loop. A subscriber
to `pubrawtx` connected to Core will see every tx in every
connected block; the same subscriber connected to hotbuns will
only see mempool-accepted txs (via `notifyTransactionAcceptance`).
Block-only txs (coinbase, block-only-broadcast txs, IBD
backfill) are invisible.

#### BUG-9 (P1-NEAR): No `BlockDisconnected` per-tx notification loop

Core (`zmqnotificationinterface.cpp:198-211`):
```cpp
void CZMQNotificationInterface::BlockDisconnected(
    const std::shared_ptr<const CBlock>& pblock,
    const CBlockIndex* pindexDisconnected)
{
    for (const CTransactionRef& ptx : pblock->vtx) {
        ...
        return notifier->NotifyTransaction(tx);   // hashtx + rawtx
    }
    return notifier->NotifyBlockDisconnect(pindexDisconnected);
}
```

Hotbuns `notifyBlockDisconnect` (line 228) only publishes the
sequence 'D' message — no per-tx hashtx/rawtx loop. Subscribers
to `pubhashtx` / `pubrawtx` will miss the txs going BACK into
the mempool on reorg.

#### BUG-10 (P2-MED): No failed-notifier eviction (`TryForEachAndRemoveFailed`)

Core (`zmqnotificationinterface.cpp:136-147`) wraps every
notification fan-out in `TryForEachAndRemoveFailed`. If a notifier
returns `false` (publish failed — e.g. HWM exhausted), the
notifier is shut down and erased from the list. Hotbuns
`publish` (line 267) silently swallows errors (no return value,
no removal). Result: a wedged notifier (e.g. a subscriber that
crashed and stuck the HWM full) leaves the rest of the
notification path slow/blocked forever; Core would recover.

### REST — routing + framing

#### BUG-11 (P2-MED): No warmup gate

Core gates every REST route on `CheckWarmup` (`rest.cpp:171`).
Hotbuns `RESTServer.handleRequest` (line 165) routes immediately;
during chainstate load / index rebuild the REST server returns
500-ish errors (e.g. `bestBlock` null) instead of a clean
`HTTP_SERVICE_UNAVAILABLE`.

#### BUG-12 (P2-MED): Unknown format extension silently falls back to JSON

Hotbuns (`rest.ts:241-245`):
```ts
if (ext === "json" || ext === "bin" || ext === "hex") {
  return { path, format: ext };
}
return { path: param, format: "json" };   // silent fallback
```

Core (`rest.cpp:137-152`) returns
`RESTResponseFormat::UNDEF`, and every route's `default:` case
emits `HTTP_NOT_FOUND, "output format not found (available: ...)"`.
Hotbuns turns `/rest/block/<hash>.txt` into a JSON response (with
the `.txt` chopped off the path); Core would 404.

#### BUG-13 (P2-MED): Missing endpoints — `blockpart`, `spenttxouts`, `deploymentinfo`

Core's URI prefix table (`rest.cpp:1141-1159`) lists 14 routes.
Hotbuns implements 10:
- Missing: `/rest/blockpart/` (range read of a block on disk by
  `offset` + `size` query params).
- Missing: `/rest/spenttxouts/<hash>.<ext>` (CBlockUndo dump per
  block — used by indexers like electrs).
- Missing: `/rest/deploymentinfo/` and `/rest/deploymentinfo/<hash>`
  (BIP-9 / BIP-341 / softfork deployment state — added in v25).

`getblockfilterheaders` is implemented; check.

#### BUG-14 (P2-MED): `getutxos` rejects POST; Core accepts BIN/HEX POST body

Hotbuns (`rest.ts:166-168`):
```ts
if (req.method !== "GET") {
  return this.errorResponse(405, "Only GET requests are supported");
}
```

Core (`rest.cpp:912`): `req->ReadBody()` — `getutxos` happily
accepts POST with binary or hex body carrying serialized
`vOutPoints`. Hotbuns rejects with 405. Bitcoin Core test
fixtures (`test/functional/interface_rest.py`) exercise POST.

### REST — data accuracy

#### BUG-15 (P2-MED): `confirmations` not `-1` for orphaned blocks

Hotbuns (`rest.ts:369`, `formatBlockJson`):
```ts
confirmations: height >= 0 ? bestBlock.height - height + 1 : 0,
```

Core's `confirmations = -1` if the block is not on the active
chain (per the help text in `rpc/blockchain.cpp:614` —
`"-1 if the block is not on the main chain"`).
Hotbuns has no active-chain membership check. For a block on a
stale branch, hotbuns reports a positive depth — operationally
indistinguishable from a confirmed block.

#### BUG-16 (P2-MED): `chaininfo.mediantime` hardcoded to 0

Hotbuns (`rest.ts:894`): `mediantime: 0, // Would need MTP calculation`.
Core's `getblockchaininfo` returns the active-tip MTP. Wallets
and indexers that consult `chaininfo.mediantime` (e.g. for
nSequence relative-locktime relay-policy checks per BIP-113) get
zero, which they may interpret as "tip is at the unix epoch."

#### BUG-17 (P2-MED): `chaininfo.softforks` always empty object

Hotbuns (`rest.ts:901`): `softforks: {},`. Core populates this
with BIP-9 / buried-deployment / signalling state per
`rpc/blockchain.cpp::SoftForkDescPushBack`. Operators relying on
this field for activation timing (e.g. wallet feature gating)
see no deployments.

#### BUG-18 (P2-MED): `rest_tx` does not wait for txindex sync

Core (`rest.cpp:850-852`):
```cpp
if (g_txindex) {
    g_txindex->BlockUntilSyncedToCurrentChain();
}
```

Hotbuns goes straight to `this.txIndex.getTransaction(txid)`
(line 582). Operators querying a tx that was just mined but
hasn't been indexed yet (transient race) get a 404 from hotbuns;
Core blocks briefly and returns the tx. The Bitcoin Core
functional tests (`interface_rest.py`) depend on this gate.

#### BUG-19 (P2-MED): `block` 404 does not distinguish "pruned" vs "not downloaded"

Core (`rest.cpp:418-422`):
```cpp
if (!(pblockindex->nStatus & BLOCK_HAVE_DATA)) {
    if (chainman.m_blockman.IsBlockPruned(*pblockindex)) {
        return RESTERR(req, HTTP_NOT_FOUND, hashStr + " not available (pruned data)");
    }
    return RESTERR(req, HTTP_NOT_FOUND, hashStr + " not available (not fully downloaded)");
}
```

Hotbuns (`rest.ts:307`) returns a single `hashStr + " not found"`
for any miss in `db.getBlock`. SPV clients and indexer tooling
need to disambiguate "the chain has this block; you pruned it"
from "this block doesn't exist or hasn't synced yet" — the former
is a config issue, the latter is a sync state.

#### BUG-20 (P2-MED): `blockfilter*` 404 doesn't distinguish indexing vs corruption

Core (`rest.cpp:565-580`):
```cpp
if (!index_ready) {
    errmsg += " Block filters are still in the process of being indexed.";
} else {
    errmsg += " This error is unexpected and indicates index corruption.";
}
```

Hotbuns (`rest.ts:970-973`, `rest.ts:1077-1082`) always says
"Block filters are still in the process of being indexed."
Operators running with `-blockfilterindex` enabled but a corrupt
index file get the same "be patient" message Core would emit
during IBD. No `BlockUntilSyncedToCurrentChain` call either.

### Notification scripts

#### BUG-21 (P0-FEATURE-MISSING): No `-blocknotify` / `-alertnotify` / `-startupnotify` / `-shutdownnotify` / `-walletnotify` support

`grep -rE 'blocknotify|alertnotify|startupnotify|shutdownnotify|walletnotify' src/` returns ZERO production hits.
Core ships five distinct notify hooks:

- `-blocknotify=<cmd>` (init.cpp:498, 2009–2018) — `%s` replaced by
  the block hash (BE hex) on every new tip post-init.
- `-alertnotify=<cmd>` (init.cpp:485) — fires on consensus alerts.
- `-startupnotify=<cmd>` (init.cpp:529, 738) — fires once on
  startup; thread is DETACHED.
- `-shutdownnotify=<cmd>` (init.cpp:530, 256) — fires on shutdown;
  each thread is JOINED so shutdown blocks on the script.
- `-walletnotify=<cmd>` (wallet/wallet.cpp) — fires on tx
  add/update; `%s` replaced by txid, `%h` by block hash, `%b` by
  block height (depending on Core version); the substituted value
  IS `ShellEscape`'d because it can come from untrusted relayed tx
  data.

Hotbuns has none. The shared `chainEvents` emitter (cli.ts:1787)
is the natural seam — `blocknotify` would be a single
`emitter.on("blockConnected", ...)` invoking a shell command —
but no such wiring exists.

#### BUG-22 (P0-PRE-EMPTIVE): If/when hotbuns adds notify hooks, MUST shell-escape substitutions and avoid `system()`

Pre-emptive flag for the next fix wave. Core's `runCommand`
(`common/system.cpp:50`) calls `::system(strCommand.c_str())`
directly. This is safe for `-blocknotify` because Core's `%s`
substitution is `block.GetBlockHash().GetHex()` (guaranteed
`[0-9a-f]{64}`, no shell metacharacters can appear). It is NOT
safe for `-walletnotify` where the substituted value could be a
crafted hex literal in the more general case; Core uses
`ShellEscape` (`common/system.cpp:41`) for those — but only
correctly for non-Windows code paths.

A TypeScript implementation that takes an operator-supplied
template containing `%s` and naively calls `child_process.exec`
or `Bun.spawn(template, { shell: true })` would be SHELL-INJECTABLE
if any operator-attackable value enters the substitution. For
hotbuns, the safe pattern is:

1. Replace `%s` with the substituted value AFTER validating the
   value is `[0-9a-f]{64}` (block hash, txid) or after running it
   through `ShellEscape`.
2. Run via `Bun.spawn(["sh", "-c", command], { stdio: "ignore" })`
   for `-blocknotify` (where `%s` is hash-hex) — sh-with-arg is
   semantically equivalent to Core's `system()`.
3. For `-walletnotify` (with `%h` / `%b` future expansion), assemble
   the argv directly and skip the shell entirely:
   `Bun.spawn([userBinary, hashHex, heightStr], ...)`.

This bug is flagged here to ensure the FIX-wave doesn't ship a
shell-injection vuln. Mark P0 because it's user-data-on-CLI risk;
mark pre-emptive because hotbuns currently has nothing to inject
INTO (BUG-21).

## Universal cross-impl patterns discovered

This wave surfaces two patterns worth cross-correlating with the
ouroboros / nimrod / camlcoin / blockbrew sibling audits:

- **"dead-code module pattern"** — `ZMQNotificationInterface` is
  written, has 463 lines of green test coverage, but never wired
  into the production entry-point. Same shape as the previously-
  closed REST gap (rest.ts header comment). This is the THIRD
  audit in W141 / W14x to find a written-but-unwired
  observability module in hotbuns; the closure pattern is well-
  understood (rest.ts:21-25 documents it). The natural next
  closure is a single-impl fix wave that imports zmq.ts in
  cli.ts and gates it on `--zmq*` argv presence.

- **"hash byte-order in operator-facing payloads"** — Core
  consistently REVERSES uint256 bytes when emitting to operator
  surfaces (ZMQ payload, REST hex, RPC JSON via `GetHex()`).
  Hotbuns DOES reverse in REST JSON (e.g. `rest.ts:368`
  `Buffer.from(hash).reverse().toString("hex")`), but DOES NOT
  reverse in the would-be ZMQ payload (BUG-1). This is consistent
  with the cross-impl meta-pattern that endianness defects cluster
  at impl-internal boundaries where the abstraction wasn't
  end-to-end tested; sibling impls likely have variants.

## Out-of-scope (for this discovery wave)

- BUG-1's correct fix requires touching `notifyBlock`,
  `notifyTransactionAcceptance`, `notifyTransactionRemoval`, AND
  the helper `publishSequence` — non-trivial 4-call-site sweep.
- BUG-4 wiring is straightforward (mirror the REST opt-in path),
  but requires deciding whether to fail fast when `zeromq`
  fails to load (CLAUDE.md NIF crash) vs. silent-skip-with-warning
  (current REST pattern).
- BUG-21 / BUG-22 are paired: adding notify support without the
  shell-escape pattern would introduce a vuln. Future FIX wave
  must land both together.

## Tests

`src/__tests__/w141_zmq_rest_notify.test.ts` — assertion-only,
mirrors the gate matrix above. Tests that currently PASS pin
existing behavior; tests that ALERT on a bug use `expect(...).toBe`
with the BUGGY value AND inline reference to the Core line numbers
so a follow-up FIX wave can flip the assertion.

No production code changes.
