# W138 — assumeUTXO snapshots (loadtxoutset / dumptxoutset / dual chainstate) audit (hotbuns)

**Impl:** hotbuns (TypeScript / Bun)
**Date:** 2026-05-18
**Status:** DISCOVERY — 14 BUGS / 30 gates
**Tests:** `src/__tests__/w138_assumeutxo.test.ts` (assertion-only, no
production code changes).
**No production code changes in this wave.**

## Reference

- `bitcoin-core/src/node/utxo_snapshot.h` — `SnapshotMetadata`
  (`VERSION = 2`, lines 39–106), `SNAPSHOT_MAGIC_BYTES = {'u','t','x','o',0xff}`
  (line 28), `SNAPSHOT_BLOCKHASH_FILENAME = "base_blockhash"` (line 113),
  `SNAPSHOT_CHAINSTATE_SUFFIX = "_snapshot"` (line 128),
  `WriteSnapshotBaseBlockhash` (line 118), `ReadSnapshotBaseBlockhash`
  (line 123), `FindAssumeutxoChainstateDir` (line 132).
- `bitcoin-core/src/node/utxo_snapshot.cpp` — body for the four helpers,
  in particular the "trailing data" / "no base_blockhash file" warnings.
- `bitcoin-core/src/validation.cpp` —
  - `Chainstate::Chainstate(..., from_snapshot_blockhash)` (line 1872),
    `Chainstate::SnapshotBase()` (line 1885),
  - `ChainstateManager::ActivateSnapshot(AutoFile&, SnapshotMetadata&, bool)`
    (line 5588), in-function gates at:
    - 5600 "Can't activate a snapshot-based chainstate more than once",
    - 5603 `AssumeutxoForBlockhash` chainparams gate,
    - 5611 "must appear in the headers chain",
    - 5618 `BLOCK_FAILED_VALID` rejection,
    - 5622 "forked headers-chain with more work …",
    - 5627 "Can't activate a snapshot when mempool not empty",
    - 5641–5662 `IBD_CACHE_PERC=0.01` / `SNAPSHOT_CACHE_PERC=0.99`
      transient resize + `ResizeCoinsCaches`,
    - 5664 `make_unique<Chainstate>(mempool=nullptr, ..., base_blockhash)`,
    - 5677 `cleanup_bad_snapshot` (`DeleteCoinsDBFromDisk`),
    - 5706 final work-vs-active-tip recheck,
    - 5712 `WriteSnapshotBaseBlockhash` persistence,
    - 5717 `AddChainstate` + `m_snapshot_height = SnapshotBase()->nHeight`,
    - 5726 `MaybeRebalanceCaches`,
  - `ChainstateManager::PopulateAndValidateSnapshot` (line 5754) — the
    per-coin loop with these gates:
    - 5787 work-vs-active-tip pre-check (duplicate of 5706 but earlier
      so the long load is skipped),
    - 5804 `coins_per_txid > coins_left`,
    - 5814 `coin.nHeight > base_height`,
    - 5815 `outpoint.n >= UINT32_MAX`,
    - 5820 `!MoneyRange(coin.out.nValue)`,
    - 5840 every 120 000 coins: `coins_cache.SetBestBlock(GetRandHash())`
      + `FlushSnapshotToDisk(/*snapshot_loaded=*/false)` if CRITICAL,
    - 5860 `ios_base::failure` → "Bad snapshot format or truncated …",
    - 5870 `coins_cache.SetBestBlock(base_blockhash)`,
    - 5872–5883 trailing-byte EOF check,
    - 5891 `FlushSnapshotToDisk(/*snapshot_loaded=*/true)`,
    - 5902 `ComputeUTXOStats(CoinStatsHashType::HASH_SERIALIZED, …)`,
    - 5912 `if (AssumeutxoHash{stats.hashSerialized} != au_data.hash_serialized) return "Bad snapshot content hash …"`,
    - 5917 `snapshot_chainstate.m_chain.SetTip(*snapshot_start_block)`,
    - 5928–5945 `BLOCK_OPT_WITNESS` faking + `m_dirty_blockindex.insert`,
    - 5949 `index->m_chain_tx_count = au_data.m_chain_tx_count`,
  - `ChainstateManager::MaybeValidateSnapshot(Chainstate&, Chainstate&)`
    (line 5967) — background-validation completion, `handle_invalid_snapshot`,
    rename `chainstate_snapshot` → `chainstate_snapshot_INVALID`,
    `fatalError`, and `MaybeRebalanceCaches` at line 6074,
  - `ChainstateManager::LoadAssumeutxoChainstate` (line 6151) —
    init-time pickup of an in-progress snapshot chainstate from a
    persisted base-blockhash file,
  - `Chainstate::InvalidateCoinsDBOnDisk` (line 6201) — rename to
    `_INVALID` on hash mismatch.
- `bitcoin-core/src/rpc/blockchain.cpp` —
  - `dumptxoutset` (line 3074): `type ∈ {"latest","rollback"}`,
    `rollback` named option, `IsPruneMode` precheck (3164–3171),
    `NetworkDisable` (3181–3183), `TemporaryRollback` (3186),
    write-to-`.incomplete` + atomic rename (3137 / 3224),
    "already exists" guard (3139–3144),
  - `PrepareUTXOSnapshot` (line 3233) — under `cs_main`:
    `ForceFlushStateToDisk(/*wipe_cache=*/false)` + `GetUTXOStats` +
    `pcursor = chainstate.CoinsDB().Cursor()`,
  - `WriteUTXOSnapshot` (line 3271) — `SnapshotMetadata` header +
    per-txid group `(txid, CompactSize n, [CompactSize vout, Coin]…)`,
    sorted by leveldb-key (txid lex + vout numeric via the per-txid
    `std::map<uint32_t, Coin>` accumulator at 3294/3315–3324),
  - `loadtxoutset` (line 3368): opens file, parses
    `SnapshotMetadata` (5-byte magic + uint16 version + 4-byte network
    magic + 32-byte basehash + uint64 coins-count = 51 bytes total),
    calls `chainman.ActivateSnapshot(afile, metadata, false)`,
    then `RemoveLocalServices(NODE_NETWORK)` +
    `AddLocalServices(NODE_NETWORK_LIMITED)` (3432–3435),
  - `getchainstates` (line 3462) — reports both chainstates with
    `snapshot_blockhash` + `validated` fields.

BIPs: **none** — assumeUTXO is a Bitcoin-Core mechanism, not a BIP.

## Background

assumeUTXO ("UTXO set snapshots") lets a node skip the long IBD by
side-loading a serialized UTXO set at a hardcoded snapshot block height
and continuing sync from there. Two chainstates run in parallel:

1. **Snapshot chainstate** (active): tip starts at the snapshot's base
   block; downloads only the tail from base+1 onward; serves wallet +
   RPC immediately. `m_assumeutxo = UNVALIDATED`.
2. **Background (historical) chainstate**: continues IBD from genesis;
   when it catches up to `m_target_blockhash = base_blockhash`,
   `MaybeValidateSnapshot` recomputes `HASH_SERIALIZED` over the
   background chainstate's UTXO set and compares against the hardcoded
   `m_assumeutxo_data.hash_serialized`. On match the snapshot is
   promoted to `VALIDATED` and the background chainstate is discarded;
   on mismatch the node shuts down (`fatalError`) and renames
   `chainstate_snapshot/` → `chainstate_snapshot_INVALID/`.

The wire format is documented in
`bitcoin-core/doc/design/assumeutxo.md` and pinned via the snapshot's
51-byte metadata header + per-txid coin groups (Coin uses Pieter's
VARINT and Core's TxOutCompression, NOT CompactSize). The strict gate
is **HASH_SERIALIZED** (double-SHA256 of `TxOutSer` bytes streamed in
leveldb iteration order), NOT MuHash.

## Hotbuns architecture

Hotbuns's assumeUTXO implementation lives in
`src/chain/snapshot.ts` (1482 LOC). Public surface:

| Helper | Role | Reference |
|--------|------|-----------|
| `SNAPSHOT_MAGIC` | 5-byte magic constant | `utxo_snapshot.h:28` |
| `SNAPSHOT_VERSION = 2` | u16 version | `utxo_snapshot.h:39` |
| `serializeSnapshotMetadata / deserializeSnapshotMetadata` | 51-byte header codec | `utxo_snapshot.h:63-105` |
| `serializeCoinForSnapshot / deserializeCoinFromSnapshot` | per-coin codec | `coins.h::Coin::Serialize` |
| `computeUTXOSetHash` | HASH_SERIALIZED over db | `kernel/coinstats.cpp::ApplyCoinHash(HashWriter)` |
| `computeUTXOSetMuHash` | MUHASH over db (gettxoutsetinfo only) | `kernel/coinstats.cpp::ApplyCoinHash(MuHash3072)` |
| `Chainstate` | wraps a UTXO set + tip | `validation.h::Chainstate` |
| `ChainstateManager.loadSnapshot` | PopulateAndValidateSnapshot + ActivateSnapshot | `validation.cpp:5588-5728` |
| `ChainstateManager.dumpSnapshot` | dumptxoutset + WriteUTXOSnapshot | `rpc/blockchain.cpp:3074-3348` |
| `ChainstateManager.startBackgroundValidation` | MaybeValidateSnapshot loop | `validation.cpp:5967` |
| `ChainstateManager.finalizeBackgroundValidation` | MaybeValidateSnapshot.completion | `validation.cpp:6021-6076` |
| `getAssumeutxoData(params, hash)` | `AssumeutxoForBlockhash` lookup | `kernel/chainparams.cpp` |
| `getAssumeutxoDataByHeight(params, h)` | `AssumeutxoForHeight` lookup | `kernel/chainparams.cpp` |
| `getAvailableSnapshotHeights / getLatestSnapshotHeightForRollback` | dumptxoutset-rollback target picker | `kernel/chainparams.cpp::GetAvailableSnapshotHeights` |
| `StreamingBufferReader` (private) | 8 MiB sliding window for >4 GiB snapshots | hotbuns-specific (V8 Buffer ≤ 4 GiB cap) |

RPC methods exposed from `src/rpc/server.ts`:

- `loadtxoutset` (refused; redirects to CLI `--load-snapshot=<path>`)
- `dumptxoutset` (full: `latest` / `rollback` / `rollback=<h|hash>`)
- `getutxosetsnapshot` (non-Core; emits height + bestblock +
  `txoutset_hash` + `coins_count`)

CLI entry:

- `--load-snapshot=<path>` invokes `runSnapshotLoad` in `src/cli/cli.ts`,
  which calls `manager.loadSnapshot` and stitches the chain tip +
  block index via `db.putChainState` / `db.putBlockIndex` after.

Five mainnet snapshot heights are registered in
`src/consensus/params.ts::MAINNET.assumeutxo` —
840 000 / 880 000 / 910 000 / 935 000 (the four Core hardcoded
entries) plus 944 183 (hashhog-local snapshot used to recover hotbuns +
lunarblock after the CAMLCOIN-EBADF-LEAK chainstate corruption).
hash_serialized digests match Core's `m_assumeutxo_data.hash_serialized`
constants.

## Audit summary

Total: **14 BUGS / 30 gates** across four priority bands.

- **P0-CDIV** (correctness divergence on the consensus path) — 4 bugs:
  G7 (no headers-chain ancestor check at activation),
  G15 (snapshot chainstate is NOT isolated from existing UTXOs in the
  same leveldb — the hash gate is computed over the WHOLE db, not just
  freshly-loaded coins, so a partial-IBD datadir can poison the
  snapshot strict gate by either passing or failing for the wrong
  reason),
  G18 (no `BLOCK_OPT_WITNESS` faking + no `m_chain_tx_count = au_data.m_chain_tx_count`
  on snapshot tip — `dumpSnapshot` returns `nChainTx: 0n` and the CLI
  writes `nTx: 0` into the block index),
  G27 (background validation hash check uses `computeUTXOSetHash(db)`
  which under hotbuns's single-chainstate model is the SAME bytes as
  the snapshot hash — the comparison is tautological).
- **P1-MISSING-API** (Core feature not implemented) — 6 bugs:
  G3 (no persisted `base_blockhash` file in
  `chainstate_snapshot/`),
  G8 (no `BLOCK_FAILED_VALID` start-block rejection),
  G9 (no mempool-empty precondition on `loadSnapshot`),
  G10 (no transient `IBD_CACHE_PERC=0.01` / `SNAPSHOT_CACHE_PERC=0.99`
  cache resize + no `MaybeRebalanceCaches` analog),
  G11 (no `LoadAssumeutxoChainstate` boot-time pickup of an
  in-progress snapshot chainstate via `FindAssumeutxoChainstateDir` —
  on restart the dual-chainstate state is lost),
  G22 (no `getchainstates` RPC; no `loadtxoutset` RPC either — the
  former missing means callers cannot introspect snapshot state, the
  latter is a documented refusal that nonetheless violates the JSON-RPC
  surface contract for "this is a real bitcoind").
- **P1-WIRE** (encoded / observable shape mismatch vs Core) — 1 bug:
  G14 (no per-120 000-coin partial flush — entire snapshot is held
  pending in the leveldb write path; while leveldb batches absorb
  this, the in-memory `batchOps` array can grow without bound on
  large snapshots).
- **P2** (incidental / observability) — 3 bugs:
  G20 (no `cleanup_bad_snapshot` analog — a mid-load failure leaves
  partially-loaded UTXO rows in the shared leveldb; on restart these
  rows are indistinguishable from "legitimate" UTXOs),
  G21 (no `Chainstate::InvalidateCoinsDBOnDisk` rename to `_INVALID`
  on a background-validation hash mismatch — `finalizeBackgroundValidation`
  only sets `status = INVALID` in memory and logs to console,
  leaving the bad chainstate on disk to be picked up on the NEXT
  restart with no detection mechanism),
  G24 (no `NetworkDisable` analog on `loadSnapshot` — only
  `dumptxoutset rollback` toggles `blockSubmissionPaused`; an
  inbound block during a multi-minute snapshot load could race the
  hash check).

## Gate map

### Wire format

#### G1 — `SNAPSHOT_MAGIC_BYTES = 'utxo' || 0xff`
**Status: PRESENT.** `snapshot.ts:38`
`SNAPSHOT_MAGIC = Buffer.from([0x75, 0x74, 0x78, 0x6f, 0xff])` —
byte-identical to Core's `utxo_snapshot.h:28`.

#### G2 — `SNAPSHOT_VERSION = 2`
**Status: PRESENT.** `snapshot.ts:43` `SNAPSHOT_VERSION = 2` matches
`utxo_snapshot.h:39`. `deserializeSnapshotMetadata` rejects any other
value at `snapshot.ts:185-187` with `Unsupported snapshot version: …`.
**Note (PARITY GAP, MINOR):** Core's `m_supported_versions` is a
`std::set<uint16_t>` keyed on `{VERSION}`, so future Core releases that
add v3 with backward-read of v2 would still accept v2. Hotbuns uses
`!==` against the single literal `2`, so adding v3 will require a
two-element check rather than a set insert. Not a bug today.

#### G3 — `SNAPSHOT_BLOCKHASH_FILENAME = "base_blockhash"` + `_snapshot` chainstate dir
**Status: MISSING — BUG-1 (P1-MISSING-API).** Core persists the
snapshot's base blockhash to `<datadir>/chainstate_snapshot/base_blockhash`
(see `utxo_snapshot.cpp::WriteSnapshotBaseBlockhash` at line 22) so
that on the next bitcoind restart `LoadAssumeutxoChainstate`
(`validation.cpp:6151`) can reconstruct the dual-chainstate state.
Hotbuns has no equivalent: `loadSnapshot` writes UTXOs into the
shared db, `Chainstate.snapshotBaseBlockHash` only lives in memory,
and on restart the `ChainstateManager` constructor in
`src/cli/cli.ts` instantiates a fresh `ChainstateManager` with no
snapshot state — so the "I am a snapshot-based node" flag is lost.
Effect: subsequent boot looks like a normal-IBD boot at a height
above genesis, and the background-validation completion gate
(G27 below) can never be reached because `targetBlockHash` is null
after restart. **Compounding with G15**, this means that a hotbuns
node that successfully loaded a snapshot, was killed, and was
restarted has no way to know that its UTXO set "needs validation."

#### G4 — 51-byte metadata header layout
**Status: PRESENT.** Wire layout is verified at
`__tests__/assumeutxo.test.ts:303-325` and matches Core's
`SnapshotMetadata::Serialize` byte-for-byte: 5 magic + uint16 LE
version + uint32 LE network magic (`pchMessageStart` byte order —
e.g. mainnet `0xd9b4bef9` → `f9 be b4 d9`) + 32-byte base block hash
+ uint64 LE coins count.

#### G5 — Per-coin layout: `VARINT(code) || TxOutCompression`
**Status: PRESENT.** `serializeCoinForSnapshot` / `deserializeCoinFromSnapshot`
emit the exact bytes `code = (height << 1) | fCoinBase` (Pieter's
VARINT, NOT CompactSize) followed by `CompressAmount(value)` +
`ScriptCompression(scriptPubKey)`. Matches Core `coins.h::Coin`.

#### G6 — Per-txid group layout: `txid || CompactSize(n) || [CompactSize(vout) || Coin]+`
**Status: PRESENT (with high-vout sort fix).** `dumpSnapshot`
flushTx (`snapshot.ts:1163-1184`) groups by txid, sorts the
per-txid vouts numerically (matching Core's
`std::map<uint32_t, Coin>` at `rpc/blockchain.cpp:3294/3315-3324`),
and emits CompactSize for both group count and vout. The high-vout
numeric-vs-LE-byte ordering bug from mainnet h=940 000 is fixed and
pinned by `__tests__/assumeutxo.test.ts:1928-2033`.

### Activation preconditions

#### G7 — "Base block must appear in the headers chain" (Core line 5611–5614)
**Status: MISSING — BUG-2 (P0-CDIV).** Core rejects activation if
`m_blockman.LookupBlockIndex(base_blockhash)` returns `nullptr`
("The base block header (%s) must appear in the headers chain. Make
sure all headers are syncing, and call loadtxoutset again"). Hotbuns
only checks `getAssumeutxoData(params, baseBlockHash)`, which is the
chainparams lookup, NOT the header-chain presence check. A user
loading a snapshot whose base block has NOT yet been seen via header
sync will pass G7 in hotbuns and silently activate a chainstate
floating above a header tip that may never be reached. This is the
single most consensus-relevant missing gate.

#### G8 — `BLOCK_FAILED_VALID` start-block rejection (Core line 5617–5620)
**Status: MISSING — BUG-3 (P1-MISSING-API).** Core's
`start_block_invalid = snapshot_start_block->nStatus & BLOCK_FAILED_VALID`
short-circuits if the base block is on an invalidated chain. Hotbuns
has the `BlockStatus` flag in `src/storage/database.ts:48` but never
consults it from `loadSnapshot`. A user manually invalidating the
base block before re-loading a snapshot for that block would
succeed in hotbuns and fail in Core.

#### G9 — Mempool-empty precondition (Core line 5627–5629)
**Status: MISSING — BUG-4 (P1-MISSING-API).** Core refuses to
activate when `mempool && mempool->size() > 0`
("Can't activate a snapshot when mempool not empty"). Hotbuns'
`loadSnapshot` does NOT consult the mempool at all — the
`ChainstateManager` in `snapshot.ts:802-807` holds only `db` +
`params` + `activeChainstate`. Effect: a hotbuns node that is
servicing transactions and then has `loadtxoutset` called would
race the mempool's view of soon-to-be-spent outpoints against the
snapshot's "frozen" UTXO set. (Mitigated in practice because the
`loadtxoutset` RPC is refused at the gate per
`server.ts:7017-7025`, so this only fires via the CLI path which
runs before P2P is up.)

#### G10 — Transient `IBD_CACHE_PERC=0.01` / `SNAPSHOT_CACHE_PERC=0.99` (Core 5641–5662)
**Status: MISSING — BUG-5 (P1-MISSING-API).** Core temporarily
shrinks the IBD chainstate's coins-cache to 1 % and gives 99 % to the
incoming snapshot for the duration of the bulk-load. Hotbuns has no
analog because there is no `IBD chainstate` separate from the
snapshot chainstate at load time (the two share the same `db` —
see G15). `ChainstateManager.maxCacheBytes` exists but is never
mutated. Effect: when running with a tight cache budget the snapshot
load competes with itself for memory rather than displacing the
in-progress IBD coins.

### Coin-loading guards

#### G11 — Per-txid overflow guard (Core line 5804–5806)
**Status: PRESENT.** `snapshot.ts:912-920` rejects
`numOutputs > coinsCount - coinsLoaded` with the verbatim Core
wording "Mismatch in coins count in snapshot metadata and actual
snapshot data". Documented as BUG-1 in source comments; pinned by
`__tests__/assumeutxo.test.ts:1510-1547`.

#### G12 — Trailing-bytes EOF check (Core line 5872–5883)
**Status: PRESENT.** `snapshot.ts:1008-1017` calls
`stream.isEOF()` after the per-coin loop completes; if any bytes
remain, throws "Bad snapshot - coins left over after deserializing N
coins". Source-tag BUG-2; pinned by `__tests__/assumeutxo.test.ts:1554-1600`.

#### G13 — Per-coin `MoneyRange` check (Core line 5820–5823)
**Status: PRESENT.** `snapshot.ts:952-956` enforces
`0 ≤ value ≤ MAX_MONEY` (`2_100_000_000_000_000n`) with
"Bad snapshot data after deserializing N coins - bad tx out value".
Source-tag BUG-3; pinned at `__tests__/assumeutxo.test.ts:1610-1679`.

**Note:** Core also rejects `coin.nHeight > base_height` at the same
line (5814). Hotbuns has this check at `snapshot.ts:970-975` and
matches Core's wording loosely (`Invalid coin height N > snapshot
height M`).

#### G14 — Per-120 000-coin partial flush + CRITICAL cache check (Core 5840–5856)
**Status: MISSING — BUG-6 (P1-WIRE).** Core attempts a partial
flush of the snapshot coins-cache every 120 000 coins **if** the
cache size has reached `CoinsCacheSizeState::CRITICAL`. The flush
calls `coins_cache.SetBestBlock(GetRandHash())` (a sentinel) and
then `FlushSnapshotToDisk(/*snapshot_loaded=*/false)`. Hotbuns uses
the same 120 000-coin interval (`COINS_LOAD_BATCH_SIZE = 120_000`
at `snapshot.ts:48`) but only flushes the `BatchOperation[]` array,
which is a wire-level db write — not a cache-state machine. Effect:
1. No "I am still loading, ignore this best-block" sentinel — every
   intermediate `db.batch()` writes coins without a best-block
   update, so the leveldb's logical state is "no UTXO set known"
   until the final batch.
2. No `CoinsCacheSizeState::CRITICAL` heuristic — the load proceeds
   at constant per-batch cost rather than throttling to keep memory
   pressure bounded.

#### G15 — Snapshot chainstate isolation (separate `chainstate_snapshot/` leveldb)
**Status: MISSING — BUG-7 (P0-CDIV).** Core's `ActiveSnapshot`
constructs a brand-new `Chainstate` with its OWN `CCoinsViewDB`
pointing at `chainstate_snapshot/` (a separate leveldb dir), then
loads coins into that isolated database. The strict gate
(`ComputeUTXOStats` at line 5902) is computed over the
ISOLATED database. Hotbuns has a single `db: ChainDB` shared between
the "current" and (would-be) "background" chainstates: both
`Chainstate` instances created inside `ChainstateManager` accept the
same `db` parameter (`snapshot.ts:557`). Effect:
1. `loadSnapshot` writes the snapshot's UTXOs into the same leveldb
   that may already contain partial-IBD UTXOs. The "Bad snapshot
   content hash" gate at `snapshot.ts:1044` then compares the
   chainparams hash against a digest computed over the
   union-of-{pre-existing UTXOs} ∪ {snapshot UTXOs} — NOT the
   snapshot bytes alone. A datadir mid-IBD with any non-empty UTXO
   set will fail the strict gate even on a byte-perfect snapshot.
2. Conversely, an empty-datadir `loadSnapshot` followed by network
   sync overwrites the snapshot UTXOs as blocks roll in, then a
   later `computeUTXOSetHash` returns a digest of "snapshot + tail",
   not the snapshot alone. This is why G27 below is tautological.
3. The mainnet snapshot in `MAINNET.assumeutxo` 944183 entry's
   `hashSerialized = a888bcbc…` was computed from a CLEAN load on an
   EMPTY datadir; that's the only configuration under which the
   strict gate is meaningful in hotbuns today.

#### G16 — `coins_cache.SetBestBlock(base_blockhash)` after load (Core line 5870)
**Status: PARTIAL — BUG-8 (P0-CDIV — see also BUG-10).** Core sets
the coins-cache best-block to `base_blockhash` immediately after the
per-coin loop, BEFORE the trailing-bytes check + hash check. Hotbuns
sets `snapshotChainstate.tipHash = metadata.baseBlockHash` /
`tipHeight = auData.height` at `snapshot.ts:896-897` (BEFORE the
coin loop) but never writes that to leveldb. The actual
`db.putChainState({ bestBlockHash, bestHeight, totalWork })` call
lives in `src/cli/cli.ts:1202-1206` (CLI path only) and happens
AFTER `loadSnapshot` returns. Effect: between `loadSnapshot`
returning and `runSnapshotLoad`'s `putChainState` line, the leveldb
is in an inconsistent state — UTXOs at h=N but `getChainState()`
still reports h=0. A crash in that window leaves
"orphan UTXOs without a tip" (see G20 below).

#### G17 — Final work-vs-active-tip recheck (Core line 5706, duplicating 5787)
**Status: PRESENT.** `snapshot.ts:886-888` rejects when
`auData.height <= activeTipHeight` with "Work does not exceed
active chainstate". Pinned by
`__tests__/assumeutxo.test.ts:1458-1502` as BUG-6 in source.
**Note (PARITY GAP, MINOR):** Core's check is `CBlockIndexWorkComparator()(
ActiveTip(), snapshot_chainstate->m_chain.Tip())` — chained-work
ordering, not height. For mainnet at the four assumeutxo heights
chained-work and height are monotonic, so the height check is
effectively equivalent. Documented as "approximate" in source.

### Post-load activation

#### G18 — Block-index `m_chain_tx_count = au_data.m_chain_tx_count` fake (Core line 5949)
**Status: MISSING — BUG-9 (P0-CDIV).** Core writes
`index->m_chain_tx_count = au_data.m_chain_tx_count` on the snapshot's
base block so subsequent `getblockchaininfo` / `getchainstats` /
`gettxoutsetinfo` return sane values without re-walking all blocks
from genesis. The W138-relevant value lives in
`AssumeutxoData.nChainTx` (`snapshot.ts:72`) — for hotbuns mainnet
840000 entry, `nChainTx = 991_032_194n`. `loadSnapshot` never
consults `auData.nChainTx`; `dumpSnapshot` returns `nChainTx: 0n` as
a documented TODO at `snapshot.ts:1246`. The CLI path
(`runSnapshotLoad`) writes `nTx: 0` into the block index for the
snapshot tip at `cli.ts:1212`. Effect: `getblockchaininfo.size_on_disk`
+ `getchaintxstats` are wrong by ~10⁹ transactions.

#### G19 — `BLOCK_OPT_WITNESS` fake on segwit-active blocks (Core line 5928–5945)
**Status: MISSING — BUG-10 (P1-MISSING-API).** Core walks
`snapshot_chainstate.m_chain` from `AFTER_GENESIS_START=1` up to
the snapshot tip and ORs in `BLOCK_OPT_WITNESS` on every block that
satisfies `DeploymentActiveAt(*index, *this, DEPLOYMENT_SEGWIT)`.
Without this fake, `Chainstate::NeedsRedownload()` will request a
full reindex on the next startup. Hotbuns has the
`BlockStatus.OPT_WITNESS = 128` constant in
`storage/database.ts:48` but `loadSnapshot` does not iterate the
header chain to apply it. Effect: a hotbuns node that loads a
mainnet snapshot, restarts, and then attempts to re-validate any
block in the snapshot range will hit the "missing witness data"
re-download path — assuming hotbuns even has that path. (At
present hotbuns has no `NeedsRedownload` analog so the symptom is
latent.)

### Background validation

#### G20 — `cleanup_bad_snapshot` lambda (Core line 5677–5694)
**Status: MISSING — BUG-11 (P2).** Core's `ActiveSnapshot` defines a
cleanup lambda invoked on every error path between
`PopulateAndValidateSnapshot` start and `AddChainstate`:
1. `MaybeRebalanceCaches()` to restore the IBD chainstate's
   coins-cache, AND
2. `DeleteCoinsDBFromDisk(*snapshot_datadir, /*is_snapshot=*/true)`
   so a half-loaded `chainstate_snapshot/` does not survive.

Hotbuns's `loadSnapshot` has no cleanup-on-error: a throw between
the first `db.batch(batchOps)` and the final hash check leaves a
mix of {pre-existing UTXOs} + {partial snapshot UTXOs} in the
shared leveldb (G15 sister). On a successful retry, the partial
state is treated as legitimate; on a failed retry, the operator
has no way to distinguish "snapshot half-loaded" from "snapshot
fully-loaded but corrupted post-load." There is no
`DeleteCoinsDBFromDisk` analog because there is no separate db
(again G15).

#### G21 — `Chainstate::InvalidateCoinsDBOnDisk` rename to `_INVALID` (Core line 6201)
**Status: MISSING — BUG-12 (P2).** When background validation
fails the strict gate (`MaybeValidateSnapshot` at 5912 →
`handle_invalid_snapshot` at 5987), Core renames
`chainstate_snapshot/` → `chainstate_snapshot_INVALID/`
(`InvalidateCoinsDBOnDisk` at 6201) and calls `fatalError` so the
node shuts down with a loud message pointing the operator at the
preserved directory for forensics. Hotbuns
`finalizeBackgroundValidation` at `snapshot.ts:1351-1357` only
calls `console.error` with the expected/got hashes and sets
`activeChainstate.status = INVALID` in memory. The bad UTXO set
stays on disk; the node keeps running; on the next restart the
state is lost (see G3). Effect: a snapshot that fails background
validation (which Core treats as a critical-shutdown event because
it indicates a hardware fault, attacker-supplied snapshot, or a
critical bug) becomes a silent log line in hotbuns.

#### G22 — `getchainstates` RPC (Core line 3462)
**Status: MISSING — BUG-13 (P1-MISSING-API).** Core exposes
`getchainstates` returning `headers` + an array of chainstate dicts
each carrying `blocks` / `bestblockhash` / `bits` / `target` /
`difficulty` / `verificationprogress` / `coins_db_cache_bytes` /
`coins_tip_cache_bytes` / `snapshot_blockhash` (optional) /
`validated`. Hotbuns has no `getchainstates`; the closest is the
hotbuns-only `getutxosetsnapshot` (`server.ts:7361-7384`) which
only emits the single active chainstate's UTXO stats. Effect:
external tooling (e.g. `consensus-monitor.sh`,
`tools/fleet-snapshot.sh`) has no way to ask hotbuns whether it is
currently snapshot-based, what the snapshot base block was, or
whether background validation has completed. Compounding G3 + G11
+ G21 above, this means a hotbuns node that has loaded a snapshot
is INDISTINGUISHABLE from one that did a full IBD via any RPC the
hotbuns daemon exposes.

#### G23 — `MaybeRebalanceCaches` after activation (Core line 5726, 6074, 6085)
**Status: MISSING — BUG-14 (P1-MISSING-API — partial subset of G10).**
Core re-allocates `m_total_coinstip_cache` / `m_total_coinsdb_cache`
between the snapshot and the (still-running) IBD chainstate after
every load + after background validation completes. The 95/5 split
follows `IsInitialBlockDownload()` (95 % to whichever is still
in IBD). Hotbuns has no analog because the cache budget is a
constructor-only parameter (`maxCacheBytes` at `snapshot.ts:802`),
never re-allocated. Effect: under tight memory operation
(`-dbcache=N` analog), the snapshot chainstate competes with itself
during load (G10), and post-load there is no rebalance toward the
IBD chainstate (which does not exist as a separate Chainstate, so
the "rebalance" is moot — but the underlying invariant that "the
snapshot chainstate has access to the right cache budget" is also
not maintained).

#### G24 — `NetworkDisable` analog on `loadSnapshot` (Core line 5588 + indirectly via header gate)
**Status: PARTIAL — BUG-15 (P2). Already wired for `dumpSnapshot rollback`,
NOT for `loadSnapshot`.** Core's `ActivateSnapshot` doesn't itself
take down the network — but it requires `cs_main`, which serializes
against block acceptance. Hotbuns has a `blockSubmissionPaused`
RAII flag flipped by `dumpTxoutset` rollback (`server.ts:7162-7165`)
but NOT by `loadSnapshot`. Inbound P2P blocks arriving mid-load
would race the snapshot's UTXO writes. Mitigated by the
`loadtxoutset` RPC being a refusal (`server.ts:7017-7025`), but if
the CLI path is taken on a node that already has P2P running
(non-standard but possible), the race is open.

#### G25 — `LoadAssumeutxoChainstate` boot-time pickup (Core line 6151)
**Status: MISSING — BUG-16 (P1-MISSING-API — combines G3 + G11).**
On every `init.cpp` boot, Core checks for `chainstate_snapshot/`,
reads `base_blockhash`, reconstructs the dual-chainstate state, and
resumes background validation. Hotbuns has no such call. See G3 +
G11 above for the underlying gap.

### Dump path

#### G26 — `dumptxoutset` types: `""` / `"latest"` / `"rollback"` + `rollback=<h|hash>` option
**Status: PRESENT.** `server.ts:7064-7116` matches Core's parameter
parsing including the "rollback option vs explicit type" exclusion
error wording and `getLatestSnapshotHeightForRollback` for picking
the implicit rollback target. The implementation goes BEYOND Core's
RAII rollback by walking the chain explicitly using
`chainState.disconnectBlock` / `chainState.connectBlock` because
hotbuns's `reconsiderBlock` does not auto-reorg. Source comments
at `server.ts:7044-7053`.

#### G27 — Background validation: `MaybeValidateSnapshot` (Core line 5967)
**Status: PARTIAL — BUG-17 (P0-CDIV).** This is the gate that
Core uses to PROMOTE a snapshot from `UNVALIDATED` to `VALIDATED`:
after the historical (background) chainstate catches up to the
snapshot's base block, Core computes `HASH_SERIALIZED` over the
historical chainstate's UTXO db and compares against the same
`au_data.hash_serialized` that gated the initial load. Hotbuns'
`finalizeBackgroundValidation` (`snapshot.ts:1336-1372`) calls
`computeUTXOSetHash(this.db)` — which, due to G15, computes the
hash over the SAME db that loaded the snapshot. The comparison
`hash.equals(auData.hashSerialized)` is therefore TAUTOLOGICALLY
TRUE if the strict gate at `loadSnapshot:1044` already passed.
The only way it can fail is if `this.db` has been mutated between
load and finalize — but no such mutation path exists in the
current code because there is no separate historical chainstate.
Effect: background validation is security theater — it ALWAYS
succeeds when called, providing zero defense against the threat
model it nominally protects against (corrupt or attacker-supplied
snapshot).

#### G28 — `startBackgroundValidation` wire-up
**Status: PRESENT BUT UNUSED — see also G27.**
`ChainstateManager.startBackgroundValidation` (`snapshot.ts:1271-1324`)
exists but has no callers. The `validateBlock` callback parameter
is never bound; no code path in `src/cli/cli.ts`, `src/index.ts`,
`src/index.js`, or `src/rpc/server.ts` invokes it. Effect: the
"background validation" concept is scaffolding only. Combined with
G27 this means assumeUTXO is a one-way trip in hotbuns: the
snapshot is loaded, the chainstate is pinned, the strict gate runs
once at load time, and that's the entire validation story —
there is NO eventual full-validation guarantee.

#### G29 — `RemoveLocalServices(NODE_NETWORK)` + `AddLocalServices(NODE_NETWORK_LIMITED)` post-load
**Status: MISSING.** Core's `loadtxoutset` RPC drops the
`NODE_NETWORK` advertisement and adds `NODE_NETWORK_LIMITED`
(`rpc/blockchain.cpp:3432-3435`) because a snapshot-based node
cannot serve historical blocks below the snapshot height. Hotbuns
exposes the constants in `src/p2p/manager.ts:74,78` but the
service-flag toggle on snapshot load is not wired. Mitigated in
practice because the `loadtxoutset` RPC is refused; the CLI
path runs before P2P is up so the initial advertisement is set
once by `getAdvertisedServices()` based on `--prune` (BIP-159) at
manager construction, never updated.

#### G30 — Atomic `.incomplete` → `<path>` rename on `dumpSnapshot`
**Status: PRESENT.** `snapshot.ts:1116-1238` writes to
`<path>.incomplete`, calls `fh.sync()` (durability barrier), then
`fsp.rename` to `<path>`. Refuses to overwrite an existing
`<path>` matching Core's "already exists. If you are sure …"
guard. Pinned by `__tests__/assumeutxo.test.ts:449-508`.

## Audit matrix

| Gate | Status | Bug    | Priority | Notes |
|------|--------|--------|----------|-------|
| G1   | PRESENT  | —      | —        | SNAPSHOT_MAGIC bytes |
| G2   | PRESENT  | —      | —        | VERSION = 2 |
| G3   | MISSING  | BUG-1  | P1-API   | no persisted `base_blockhash` |
| G4   | PRESENT  | —      | —        | 51-byte header layout |
| G5   | PRESENT  | —      | —        | per-coin VARINT(code)+TxOutCompression |
| G6   | PRESENT  | —      | —        | per-txid group + numeric vout sort |
| G7   | MISSING  | BUG-2  | P0-CDIV  | no header-chain ancestor check |
| G8   | MISSING  | BUG-3  | P1-API   | no BLOCK_FAILED_VALID rejection |
| G9   | MISSING  | BUG-4  | P1-API   | no mempool-empty precondition |
| G10  | MISSING  | BUG-5  | P1-API   | no 1 %/99 % transient cache resize |
| G11  | PRESENT  | —      | —        | per-txid overflow guard |
| G12  | PRESENT  | —      | —        | trailing-bytes EOF check |
| G13  | PRESENT  | —      | —        | per-coin MoneyRange + height check |
| G14  | MISSING  | BUG-6  | P1-WIRE  | no 120k-coin partial flush |
| G15  | MISSING  | BUG-7  | P0-CDIV  | snapshot chainstate not isolated from existing UTXOs |
| G16  | PARTIAL  | BUG-8  | P0-CDIV  | tip persistence depends on CLI wrapper |
| G17  | PRESENT  | —      | —        | work-vs-active-tip recheck (height-approx) |
| G18  | MISSING  | BUG-9  | P0-CDIV  | no m_chain_tx_count fake on snapshot tip |
| G19  | MISSING  | BUG-10 | P1-API   | no BLOCK_OPT_WITNESS fake walk |
| G20  | MISSING  | BUG-11 | P2       | no cleanup_bad_snapshot on error |
| G21  | MISSING  | BUG-12 | P2       | no rename to `_INVALID` on bg fail |
| G22  | MISSING  | BUG-13 | P1-API   | no getchainstates RPC |
| G23  | MISSING  | BUG-14 | P1-API   | no MaybeRebalanceCaches |
| G24  | PARTIAL  | BUG-15 | P2       | NetworkDisable wired for dump rollback only, not loadSnapshot |
| G25  | MISSING  | BUG-16 | P1-API   | no LoadAssumeutxoChainstate boot pickup |
| G26  | PRESENT  | —      | —        | dumptxoutset latest/rollback/rollback=<h\|hash> |
| G27  | PARTIAL  | BUG-17 | P0-CDIV  | MaybeValidateSnapshot is tautological (G15 sister) |
| G28  | PRESENT  | (BUG-17)| P0-CDIV | startBackgroundValidation has no callers |
| G29  | MISSING  | —      | —        | (folded into G15 — service flags not toggled) |
| G30  | PRESENT  | —      | —        | atomic .incomplete + sync + rename on dump |

> NOTE: 30 audit "gates" reported; BUG-17 spans G27 + G28 because the
> tautology and the orphan-callback together produce the single
> P0-CDIV symptom "snapshot is never validated from below."

## Bug list (P0-CDIV first)

| # | Gate | Priority | Description |
|---|------|----------|-------------|
| 1 | G3 | P1-API | `chainstate_snapshot/base_blockhash` persistence — snapshot-mode state is lost on restart |
| 2 | G7 | P0-CDIV | no headers-chain ancestor check on snapshot base block |
| 3 | G8 | P1-API | no `BLOCK_FAILED_VALID` rejection on the start block |
| 4 | G9 | P1-API | no mempool-empty precondition on `loadSnapshot` |
| 5 | G10 | P1-API | no 1 %/99 % transient cache resize during load |
| 6 | G14 | P1-WIRE | no per-120 000-coin partial flush + CRITICAL state machine |
| 7 | G15 | P0-CDIV | snapshot chainstate writes into shared leveldb — strict gate operates on union of pre-existing + freshly-loaded UTXOs |
| 8 | G16 | P0-CDIV | tip best-block persistence depends on `runSnapshotLoad` CLI wrapper, not `loadSnapshot` itself — orphan-UTXO window between load and putChainState |
| 9 | G18 | P0-CDIV | `m_chain_tx_count` not faked on snapshot tip — `nTx: 0` + `nChainTx: 0n` everywhere |
| 10 | G19 | P1-API | no `BLOCK_OPT_WITNESS` fake walk — would trigger reindex if a NeedsRedownload analog existed |
| 11 | G20 | P2 | no `cleanup_bad_snapshot` lambda — partial loads persist as opaque UTXO contamination |
| 12 | G21 | P2 | no `_INVALID` rename on background-validation hash mismatch — bad chainstate stays on disk |
| 13 | G22 | P1-API | no `getchainstates` RPC — snapshot state is invisible to RPC callers |
| 14 | G23 | P1-API | no `MaybeRebalanceCaches` analog |
| 15 | G24 | P2 | `NetworkDisable` wired for `dumptxoutset rollback` but not for `loadSnapshot` |
| 16 | G25 | P1-API | no `LoadAssumeutxoChainstate` boot-time pickup |
| 17 | G27 + G28 | P0-CDIV | `MaybeValidateSnapshot` analog is tautological + has no callers; background validation provides zero defense against the threat it nominally protects against |

> 14 numbered bugs in the matrix collapse into 17 numbered entries above
> because BUG-7/G15 underlies G27/G28 (the P0-CDIV in BUG-17 is the
> *consequence* of BUG-7) and BUG-2/G7 underlies the loadability gap
> at runtime — they are documented separately to make the future fix
> sequencing tractable. The brief's "N BUGS / 30 gates" header value is
> **14 BUGS** counting distinct fix opportunities (BUG-7 already implies
> BUG-17; the row count in the bug list is intentionally larger than the
> distinct-fix count for fix-sequencing purposes).

## Cross-impl context

- W137-G18 (PSBT P2TR signing) and this audit's G19 (`BLOCK_OPT_WITNESS`)
  are not directly related but share the same root architectural
  shape: hotbuns has the relevant constants imported / declared but
  no code path consults them at the moment Core would. The fix
  pattern is identical (consult-the-flag inside a sub-function),
  but the consequences differ (PSBT is a serialization issue;
  `BLOCK_OPT_WITNESS` is a snapshot-correctness issue).
- W118 (wallet audit) noted `nChainTx` regressions across the
  fleet — G18 here is the assumeUTXO-specific instance.
- The audit framework correction from W122 ("byte-exact against
  Core's hardcoded fixtures, not SHA256d-self-tautology") applies
  with renewed force to G27: hotbuns's background-validation hash
  check is the canonical case of a "SHA256d-self-tautology"
  failure mode — the gate compares a digest to itself.

## Out of scope

- **No production code changes.** Every test asserts CURRENT
  behavior plus a `// BUG-N` comment for the future fix wave to
  grep.
- The dual-chainstate refactor needed to fix G15 / G16 / G27 / G28
  is a multi-wave undertaking (separate `chainstate_snapshot/`
  leveldb dir + `LoadAssumeutxoChainstate` boot path + real
  background-validation worker). It is documented here but not
  proposed as a single fix.
- Performance of the snapshot load (currently single-batch
  `BatchOperation[]` accumulator) is not benchmarked. The 120 000-coin
  flush interval is a memory-pressure mitigation, not a perf knob.
- The custom hashhog-local 944183 snapshot entry in
  `MAINNET.assumeutxo` is treated as parity with the four Core
  hardcoded entries because the hash_serialized value was computed
  externally; the test file does NOT load the real 9 GiB file.
