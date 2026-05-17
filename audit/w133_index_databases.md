# W133 — Index databases (txindex + coinstatsindex) — hotbuns

**Scope:** TxIndex (`src/index/txindex.{h,cpp}`) and CoinStatsIndex
(`src/index/coinstatsindex.{h,cpp}`) plus the shared `BaseIndex`
machinery in `src/index/base.{h,cpp}` and the on-disk key shapes in
`src/index/disktxpos.h` / `src/index/db_key.h`.

**Out of scope:** BlockFilterIndex (covered in W121 and W122),
TxoSpenderIndex (not implemented anywhere in hotbuns), wallet/REST/RPC
output shapes for `getrawtransaction` / `gettxoutsetinfo` (those are
W125-class).

**Hotbuns refs:**
- `src/storage/indexes.ts` — TS port of the three Core indexes plus a
  unified `IndexManager`.  Single source file containing
  `TxIndexManager`, `BlockFilterIndex`, `CoinStatsIndex`, `MuHash`,
  `BitStreamWriter/Reader`, `GCSFilter`.
- `src/storage/database.ts` — `ChainDB` LevelDB wrapper, hosts the
  `TX_INDEX = 0x74 'b'` prefix and `TxIndexEntry { blockHash, offset,
  length }` shape.
- `src/sync/blocks.ts` — actual TxIndex put / del wiring at lines
  2710, 2715, 2258 (puts) and 1943, 2715 (dels).
- `src/chain/state.ts` — secondary TxIndex put/del paths for
  `generateblock` / `dumptxoutset` re-apply / `reorganize` at lines
  405-413 (puts) and 710-713 (dels).
- `src/cli/cli.ts` — only `--blockfilterindex` is exposed; no
  `--txindex` and no `--coinstatsindex` user flag.

**Methodology:** Read Core refs end-to-end, then bucket hotbuns code
against a 30-gate matrix.  Each gate has a status — PASS (Core-parity),
BUG-N (deviation classified P0/P1/P2/P3), or N/A (Core feature
deliberately not in hotbuns scope).

> **HEADLINE: hotbuns has TWO parallel txindex implementations and the
> wired one is the wrong one.**  `TxIndexManager` (storage/indexes.ts)
> correctly skips the genesis block, models offset/length, and lives
> behind an `enabled` flag — but it is NEVER INSTANTIATED outside the
> existing `indexes.test.ts` suite.  The production wiring in
> sync/blocks.ts + chain/state.ts calls `db.putTxIndex` /
> `buildTxIndexPutOp` directly on every block including genesis, with
> NO opt-in flag.  This is a structural fork-in-the-road inside one
> impl — six BUGs below come from this single discovery.

---

## Audit matrix (30 gates)

Gate IDs use the prefix `W133-G##`.  Status legend: PASS / BUG-N /
N/A.  BUG severity: P0 = consensus / wire-divergent, P1 =
correctness-bearing for users (RPC, wallet, light client), P2 =
operator-experience / footgun, P3 = cosmetic-but-Core-divergent.

| Gate | Subject | Status |
|------|---------|--------|
| G01 | TxIndex `CustomAppend` skip-genesis (`height == 0` return early) | **BUG-1** |
| G02 | TxIndex disk-pos format = `(file, pos, varint nTxOffset)` | **BUG-2** |
| G03 | TxIndex DB key shape = `(DB_TXINDEX='t', Txid)` | PASS |
| G04 | TxIndex separate DB path `indexes/txindex/` (independent wipe) | **BUG-3** |
| G05 | TxIndex CDBWrapper obfuscation enabled by default | **BUG-4** |
| G06 | TxIndex `AllowPrune() == false` (txindex blocks prune of old blocks) | **BUG-5** |
| G07 | TxIndex `-txindex` CLI flag with default `false` | **BUG-6** |
| G08 | TxIndex `FindTx` cross-checks txid after deserialization | **BUG-7** |
| G09 | TxIndex revert on disconnect (BaseIndex's `BlockDisconnected`) | PASS |
| G10 | CoinStatsIndex prev-hash chain check (Core's `expected_block_hash`) | **BUG-8** |
| G11 | CoinStatsIndex MuHash = MuHash3072 (NOT SHA256-chain) | **BUG-9** P0 |
| G12 | CoinStatsIndex skip Coinbase outputs on BIP-30 unspendable blocks | **BUG-10** |
| G13 | CoinStatsIndex `IsUnspendable` = `OP_RETURN \|\| size > 10000` | **BUG-11** |
| G14 | CoinStatsIndex bogo_size = `32+4+4+8+2+script_len` (= 50+) | **BUG-12** |
| G15 | CoinStatsIndex `CustomRemove` (reorg rollback) | **BUG-13** P0 |
| G16 | CoinStatsIndex `connect_undo_data + disconnect_data + disconnect_undo_data` | **BUG-14** |
| G17 | CoinStatsIndex MuHash committed atomically with best_block locator | **BUG-15** |
| G18 | CoinStatsIndex `AllowPrune() == true` (Core lets stats co-exist with prune) | **BUG-16** |
| G19 | CoinStatsIndex stores `total_prevout_spent_amount` (arith_uint256) | **BUG-17** |
| G20 | CoinStatsIndex stores `total_new_outputs_ex_coinbase_amount` | **BUG-18** |
| G21 | CoinStatsIndex stores `total_coinbase_amount` (arith_uint256) | **BUG-19** |
| G22 | CoinStatsIndex stores `total_unspendables_*` quartet (genesis/bip30/scripts/unclaimed) | **BUG-20** |
| G23 | CoinStatsIndex `LookUpStats` (Core RPC backing for `gettxoutsetinfo`) | **BUG-21** |
| G24 | BaseIndex height-index → hash-index copy on reorg (`CopyHeightIndexToHashIndex`) | **BUG-22** |
| G25 | BaseIndex `m_synced` latch (sync-then-stream-events) | **BUG-23** |
| G26 | BaseIndex `BlockUntilSyncedToCurrentChain` RPC primitive | **BUG-24** |
| G27 | TxIndex single LevelDB write batch per block | PASS |
| G28 | CoinStatsIndex unclaimed-reward accounting (miner-shortfall tracker) | **BUG-25** |
| G29 | `-coinstatsindex` CLI flag + getindexinfo RPC | **BUG-26** |
| G30 | TxIndex / CoinStatsIndex separate `indexes/` directory tree | **BUG-27** |

**Total: 27 BUGs / 30 gates** (1 PASS for txindex-key-shape G03,
1 PASS for txindex-reorg-revert G09 via the chain-wide batch,
1 PASS for single-batch atomicity G27 — same write loop).

---

## Bug detail

### BUG-1 P1 — TxIndex production path indexes the genesis coinbase
Core `txindex.cpp:77` returns `true` early at `block.height == 0` so the
genesis coinbase txid is intentionally NOT in the index (its outputs are
"not spendable").  hotbuns's `TxIndexManager.indexBlock` at
`storage/indexes.ts:1361-1364` correctly does the same — but
**`TxIndexManager` is never wired into the running node**.  The actually-
wired production paths in `sync/blocks.ts:2708-2716` and
`chain/state.ts:405-413` iterate `block.transactions` unconditionally
and write a TxIndex entry for the genesis coinbase txid.  Symptom:
`getrawtransaction <genesis-coinbase-txid>` returns the genesis tx via
hotbuns even on mainnet, where Core returns
`-5 No such mempool transaction. Use -txindex…`.  Mostly cosmetic but
diverges getrawtransaction wire output.

### BUG-2 P2 — TxIndex on-disk format does not match Core's `CDiskTxPos`
Core writes `(FlatFilePos{nFile, nPos}, VARINT(nTxOffset))` per
`disktxpos.h:17`.  hotbuns writes `(blockHash:32, offset:uint32LE,
length:uint32LE)` — 40 bytes fixed — in `database.ts:189-194`
(`serializeTxIndex`).  Two separate divergences in one bug:
- Hotbuns's offset/length are placeholders **always written as zero**
  (sync/blocks.ts:1693-1699; chain/state.ts:408-411) so the field
  shapes carry no information anyway.  This makes the index size 8B
  larger than Core's per entry with no compensating benefit.
- The DB shape is `blockHash`-indirected instead of `(file, pos)`-direct.
  Core can mmap the block file and seek to `nTxOffset` past the header
  in one syscall.  Hotbuns has to look up the block by hash, deserialize
  the body, then linear-scan transactions until txid matches — see
  `rpc/server.ts:2304` calling `findTxInBlock`.

### BUG-3 P2 — TxIndex shares the main chainstate LevelDB
Core puts TxIndex in `indexes/txindex/` per `txindex.cpp:51` (separate
`CDBWrapper`).  hotbuns puts TxIndex in the same LevelDB as block data,
UTXO, undo, chain-state under prefix `0x74 'b'` (database.ts:25).
Consequences:
- Cannot wipe-and-rebuild the txindex without nuking the whole
  chainstate.  Core's `-reindex-chainstate` and `-reindex` semantics
  cannot be modeled.
- Cache pressure: the LevelDB block cache (default ~450MB for
  chainstate) gets shared with txindex puts, evicting hot UTXO entries.

### BUG-4 P2 — No DB obfuscation key
Core's `BaseIndex::DB` accepts an `f_obfuscate` flag and defaults to
obfuscated for the regular chain LevelDB (`init.cpp` flow).  hotbuns
has no obfuscation byte at all — every store is plaintext.  Standard
hosting platforms (Cloudflare R2, etc.) can detect Bitcoin LevelDB
fingerprints from the on-disk bytes and refuse to host the volume.  Low
P, but Core diverges.

### BUG-5 P1 — No prune-lock for TxIndex
Core's `TxIndex::AllowPrune() const override { return false; }`
(txindex.h:34) makes `BaseIndex::SetBestBlockIndex` register a prune
lock that prevents pruning of any block the txindex has not yet
indexed.  hotbuns has no equivalent linkage between txindex and the
pruner — `storage/pruning.ts` does not consult any index state.  If a
user runs `-prune=550 -txindex=1` concurrently (the only configuration
where this matters), hotbuns will prune blocks whose txids are still
expected to be queryable via the txindex pointer.  Currently masked by
BUG-6 (no `-txindex` flag at all).

### BUG-6 P1 — No `-txindex` CLI flag
Core: `static constexpr bool DEFAULT_TXINDEX{false}` (`txindex.h:19`)
plus the standard `-txindex` argument.  hotbuns cli.ts:2080 contains
the literal admission `txIndexEnabled: false, // hotbuns has no
`-txindex` user-facing flag yet; mempool lookup still works.` — but
the production code unconditionally writes txindex entries on every
connect AND the read path
(`rpc/server.ts:2316: const txIndexEntry = await this.db.getTxIndex…`)
unconditionally consults them.  Net result: hotbuns behaves as if
`-txindex=1` is always on AND simultaneously as if `-txindex=0` (no
opt-in, no warning).

### BUG-7 P1 — `findTxInBlock` does not verify txid after read
Core's `TxIndex::FindTx` (txindex.cpp:114) does
`if (tx->GetHash() != tx_hash) { LogError("txid mismatch"); return false; }`
after deserializing the on-disk tx.  hotbuns's `findTxInBlock`
(rpc/server.ts:2336+) walks the block looking for a matching txid then
returns the first match — but it depends on the linear scan finding
the right tx, never re-verifies that the formatted result's
`GetHash()` equals the queried `tx_hash`.  Corruption of the block
body bytes between blk*.dat write and getrawtransaction read
(bit-flip; truncation; partial reorg) would surface as wrong-tx-data,
not as `txid mismatch`.

### BUG-8 P1 — CoinStatsIndex.indexBlock missing prev-hash chain check
Core (coinstatsindex.cpp:115-120) validates
`m_current_block_hash == *block.prev_hash` BEFORE applying the block
to muhash, logging `previous block header belongs to unexpected block`
on mismatch and returning false.  hotbuns's `CoinStatsIndex.indexBlock`
(storage/indexes.ts:1148+) never inspects `block.header.prevBlock`.
A reorg, a chainstate replay-from-snapshot, or an out-of-order
`indexBlock` call silently corrupts the running muhash totals.

### BUG-9 P0 — MuHash implementation is NOT MuHash3072
This is the headline cryptographic-divergence bug.

Core's `MuHash3072` (`crypto/muhash.h:102`) is a 3072-bit multiplicative
hash over the prime field `2^3072 - 1103717`.  Each UTXO is mapped
through ChaCha20 + a Num3072 conversion, then multiplied into the
running numerator (or denominator for removals).  The serialized form
is 768 bytes (2× 384-byte big integers).

hotbuns's `MuHash` class (storage/indexes.ts:880+):
```ts
private numerator: Buffer;   // 32 bytes
private denominator: Buffer; // 32 bytes

private multiply(a: Buffer, b: Buffer): Buffer {
  // Simplified: hash(a || b)
  // A proper MuHash would do modular multiplication in a 3072-bit field
  return sha256Hash(Buffer.concat([a, b]));
}
```

The implementation's own docstring (storage/indexes.ts:874-879) calls
this out: "We use a simplified implementation with 256-bit arithmetic
… For full MuHash3072, see Bitcoin Core's crypto/muhash.cpp.  This
simplified version uses hash chaining for similar properties."

The "similar properties" claim is false: SHA256-chain is order-
DEPENDENT (a then b is not equal to b then a), MuHash3072 is order-
INDEPENDENT (multiplication is commutative).  This breaks the entire
point of MuHash — Core can verify a UTXO set hash regardless of the
order Coin entries were applied; hotbuns cannot.  A `gettxoutsetinfo
hash_type=muhash` against hotbuns will return a value that has no
relationship to the Core value, and the on-disk serialization is 64
bytes instead of 768 so the wire shape is also wrong.

Also fails the rollback property: `MuHash3072.Remove(x)` is the
modular inverse of `Insert(x)`, so insert-then-remove restores the
identity element.  Hotbuns's `remove` multiplies the denominator
side, which does NOT cancel a previous `insert`-side multiplication
into the numerator — `insert(x); remove(x)` does NOT return to the
identity hash.  Tested below: G11-state.

### BUG-10 P1 — No BIP-30 exemption in CoinStatsIndex inserts
Core (coinstatsindex.cpp:128-132) checks `IsBIP30Unspendable(block.hash,
block.height)` for the coinbase tx and credits `m_total_unspendables_bip30`
without applying the UTXOs.  hotbuns's CoinStatsIndex has no awareness
of BIP-30 at all — it would double-account the two historical
duplicate-coinbase blocks (Mainnet h=91722 + h=91812 / overwritten
by h=91842 + h=91880).

### BUG-11 P1 — `IsUnspendable` definition incomplete
Core (script.h:563): `(size() > 0 && *begin() == OP_RETURN) || (size() > MAX_SCRIPT_SIZE)`
where `MAX_SCRIPT_SIZE = 10000`.  hotbuns checks only
`scriptPubKey[0] === 0x6a` (storage/indexes.ts:1185) — outputs with
scriptPubKey > 10000 bytes (consensus-valid as a non-standard P2SH
embedding for example) would be UTXO-set entries hotbuns thinks
exist but Core treats as unspendable and excludes from stats.

### BUG-12 P1 — `bogo_size` formula off by 18 bytes per UTXO
Core (kernel/coinstats.cpp:35-43):
```cpp
return 32 /* txid */ + 4 /* vout */ + 4 /* height+coinbase */ +
       8 /* amount */ + 2 /* scriptPubKey len */ + script_pub_key.size();
```
That's 50 + script_len.  hotbuns (storage/indexes.ts:1046):
```ts
return BigInt(32 + scriptPubKey.length);
```
Just 32 + script_len.  Per-UTXO bogo_size is 18 bytes too low.  At
mainnet's ~165M UTXO set that's ~2.9GB error in the reported "bogosize".
Trivially fixable, but every value hotbuns reports for this stat is
wrong.

### BUG-13 P0 — CoinStatsIndex has no `removeBlock` / `CustomRemove`
Core CoinStatsIndex::CustomRemove (coinstatsindex.cpp:216-234)
performs a full per-block rollback: `RevertBlock` reapplies removed
inputs and removes the new outputs from muhash, and reverts
`m_total_*` counters from the previous-height's DB row.  hotbuns's
CoinStatsIndex class has NO `removeBlock` method.  Any reorg leaves
the in-memory `txOutputCount`, `totalAmount`, `totalSubsidy`,
`bogoSize`, and the SHA256-chained "muhash" fork-divergent.  Combined
with BUG-9, hotbuns coinstatsindex output is undefined behavior past
the first reorg.

Note: this gate would be N/A if the index were never wired —
**`CoinStatsIndex` is currently never instantiated in hotbuns
production code** (no `new CoinStatsIndex` outside indexes.test.ts).
Filed as P0 because the symbol exists, is exported, is documented as
intended for `gettxoutsetinfo`, and would corrupt the moment a
caller wires it.

### BUG-14 P1 — No `connect_undo_data` / `disconnect_data` / `disconnect_undo_data` opt-in
Core (coinstatsindex.cpp:316-323): the index registers
`NotifyOptions{connect_undo_data=true, disconnect_data=true,
disconnect_undo_data=true}` so `BaseIndex::ProcessBlock` reads the
undo data alongside the block.  hotbuns's CoinStatsIndex.indexBlock
takes spentOutputs as an explicit argument but there is no
NotifyOptions equivalent; callers must remember to pass the undo
data.  Easy for the eventual integrator to forget and silently
produce wrong stats.

### BUG-15 P1 — MuHash state not atomically committed with best-block
Core (coinstatsindex.cpp:308-313) commits MuHash via `CustomCommit`
inside the same `CDBBatch` as `WriteBestBlock` — "DB_MUHASH should
always be committed in a batch together with DB_BEST_BLOCK to prevent
an inconsistent state of the DB."  hotbuns's `indexBlock` writes the
MuHash state and the tip pointer via the same `db.batch(ops)` call
(storage/indexes.ts:1246), but the per-height stats row is written
to a different prefix and there is no `BaseIndex::Commit` cadence
(periodic locator write).  An ungraceful shutdown between block N
and block N+1 will land the per-height row for N but never persist
the running muhash for N — restart re-loads stale muhash for height
< N, then `CustomInit`-style validation fails silently because there
is no equivalent of Core's `entry.muhash != out` check
(coinstatsindex.cpp:285).

### BUG-16 P2 — `AllowPrune` wrong direction
Core: `CoinStatsIndex::AllowPrune() const override { return true; }`
(coinstatsindex.h:52) — stats survive prune because they only need
UTXO state, not historical bodies.  hotbuns has no equivalent; in
practice this is masked by BUG-3 / BUG-30 (same DB), but it would
flip the wrong way once split out: an integrator copying Core's
"AllowPrune" stub from `BaseIndex::AllowPrune()` (pure virtual) would
have to pick a value, and absent the explicit override the prune
behavior is wrong.

### BUG-17/18/19/20 P1 — Missing six per-block accumulator fields
Core's `DBVal` struct (coinstatsindex.cpp:46-83) persists:
- `total_prevout_spent_amount` (arith_uint256 — can exceed CAmount on
  mainnet near height 800k)
- `total_new_outputs_ex_coinbase_amount` (arith_uint256)
- `total_coinbase_amount` (arith_uint256)
- `total_unspendables_genesis_block` (CAmount)
- `total_unspendables_bip30` (CAmount)
- `total_unspendables_scripts` (CAmount)
- `total_unspendables_unclaimed_rewards` (CAmount)

hotbuns's `CoinStats` interface (storage/indexes.ts:999-1007) tracks
just `height, blockHash, muhash, txOutputCount, totalAmount,
totalSubsidy, bogoSize`.  Every field above the dividing line is
absent.  `gettxoutsetinfo` (and `gettxoutsetinfo hash_type=muhash`)
JSON outputs include all of these — see Core's JSON for
`coin_stats.total_amount` vs `coin_stats.total_unspendable_amount` and
the four sub-totals; hotbuns cannot populate them.

Filed as four separate BUGs (17, 18, 19, 20) to keep them addressable
in isolation.

### BUG-21 P1 — No `LookUpStats` equivalent
Core's `LookUpStats(const CBlockIndex& block_index)` (coinstatsindex.cpp:236)
is the RPC handler entry point for `gettxoutsetinfo`.  It uses
`LookUpOne` which checks the height-index first and falls back to the
hash-index for reorged blocks.  hotbuns's `getStats(height)` is
height-only — no hash fallback, so reorged blocks vanish from the
queryable stats set entirely (compounds with BUG-22).

### BUG-22 P0 — No height-index → hash-index copy on reorg
Core's `index_util::CopyHeightIndexToHashIndex` (db_key.h:71-93) is the
load-bearing reorg primitive: on disconnect, the height-keyed entry
for the disconnected block is copied to a hash-keyed entry so
`getfilter <disconnected_hash>` and
`gettxoutsetinfo hash=<disconnected_hash>` continue to work.
hotbuns's CoinStatsIndex has no hash-keyed storage AT ALL — the index
is keyed exclusively by height (storage/indexes.ts:1218-1224).  Filed
as P0 because once the index is wired, every reorg silently
disappears the disconnected-block stats from the queryable set.

### BUG-23 P1 — No `m_synced` latch
Core (base.h:88; base.cpp:144) latches `m_synced=true` once the index
catches up to the chain tip, after which `BlockConnected` /
`BlockDisconnected` notifications drive the index forward.  hotbuns's
indexes process blocks via direct `indexBlock` calls in
sync/blocks.ts::connectBlock — there is no notion of "not yet synced,
discard incoming notifications".  Symptom: if an index is enabled
mid-chain (e.g. `-blockfilterindex=1` flipped on at height 500k),
hotbuns calls `indexBlock(height=500001, …)` without ever back-filling
heights 1..500000.  Core handles that by `Init() → Sync()` walking
the chain first.

### BUG-24 P1 — No `BlockUntilSyncedToCurrentChain` RPC primitive
Core (base.h:159; base.cpp:424-446) exposes
`BlockUntilSyncedToCurrentChain` so RPC handlers can wait for the
relevant index to catch up before serving a query.  RPC methods like
`getrawtransaction` (with txindex) and `gettxoutsetinfo` use this to
avoid returning a "not found" for a tx that's confirmed but not yet
indexed.  hotbuns's RPC just calls `db.getTxIndex(txid)` and returns
"not found" if the index lookup misses, even if the tx is one block
behind the indexer.

### BUG-25 P1 — `total_unspendables_unclaimed_rewards` accounting missing
Core (coinstatsindex.cpp:185-188) maintains a running
`m_total_unspendables_unclaimed_rewards`: if `prev_spent + subsidy >
new_outputs + coinbase + unspendables`, the miner shortfall is
permanently uncountable, and Core credits the difference.  This is
the only way to detect blocks where the miner intentionally claimed
less than the full subsidy (e.g. h=124724 burned 50 BTC).  Hotbuns
tracks `totalSubsidy` cumulatively but never reconciles against
prevout-spent vs new-output totals, so unclaimed-reward burns are
invisible to `gettxoutsetinfo`.

### BUG-26 P2 — No `-coinstatsindex` CLI flag and no `getindexinfo` RPC
Core has `-coinstatsindex` (default false) and exposes
`getindexinfo` reporting sync status for all enabled indexes.  hotbuns
has neither — cli.ts has no `coinstatsindex` token; rpc/server.ts has
no `getindexinfo` method.

### BUG-27 P2 — No `indexes/` directory tree
Core puts each index in its own subdir under `<datadir>/indexes/`
(coinstatsindex.cpp:96-103 even has an explicit migration note for
the v29-era `indexes/coinstats` → `indexes/coinstatsindex` rename).
hotbuns's data layout has no `indexes/` directory at all — txindex
lives in the main chain LevelDB and the other two index modules have
no on-disk presence in production.  Operators have no way to nuke an
index without nuking the whole chainstate.

---

## Universal patterns (cross-impl observation)

1. **"Storage / sync fork-in-the-road"** — hotbuns has a
   `TxIndexManager` class in `storage/indexes.ts` AND a separate
   `db.putTxIndex` / `db.buildTxIndexPutOp` path in `storage/database.ts`.
   Only the latter is wired into the production node.  This is
   identical in shape to the dead-helper pattern called out across
   ~10 audit closures in MEMORY.md but with a twist: BOTH endpoints
   exist; one is correct (skips genesis, has `enabled` gate); the
   wrong one is in production.  Future audits should grep
   `new TxIndexManager` / `new CoinStatsIndex` BEFORE classifying
   gates against the wrapper API.

2. **"Test-only class, production-path workaround"** — the
   `TxIndexManager`/`CoinStatsIndex`/`BlockFilterIndex` trio in
   `storage/indexes.ts` was authored as if it were the
   production wiring point, but only the `BlockFilterIndex` half was
   actually wired (W121).  Cross-impl: look for OOP-shaped wrappers
   that mirror Core's class hierarchy but coexist with a flatter
   "direct DB call" path; the flatter path tends to be what runs.

3. **"Cryptographic shortcuts in TS ports"** — hotbuns's
   `MuHash` self-documents the divergence in the docstring
   ("simplified ... For full MuHash3072, see Bitcoin Core's
   crypto/muhash.cpp").  This is honest, but the symbol exports as
   `MuHash` (not `SimpleMuHashPlaceholder`) and the comment is
   above-the-fold only.  Pattern: if a Core crypto primitive has a
   specific name (MuHash3072), the TS implementation must either
   name-match the algorithm (`MuHash3072`) or rename to make the
   divergence visible (`MuHashChainHack`).  Crosses with the BIP-30
   / BIP-66 "test-comment-as-confession" pattern from W122.

4. **"Bogo-size off by constant"** — small per-UTXO constants
   (off-by-N bytes) compound to multi-GB at scale.  Cross-impl
   pattern: any UTXO-set-size metric needs a fleet diff-test against
   Core; arithmetic constants ARE consensus-adjacent (they appear
   in `gettxoutsetinfo` and via that in some wallet/audit tools).

5. **"Index opt-in not modeled"** — hotbuns exposes
   `-blockfilterindex` only; the txindex always writes, the
   coinstatsindex never wires.  This is a "binary opt-in"
   pattern that the fleet's audit framework hasn't caught
   because the test fixtures wire indexes manually.  Suggested fix:
   `tools/fleet-snapshot.sh` should additionally probe
   `getindexinfo` once it exists, and consensus-diff should diff
   the RPC presence/absence of each named index.

---

## Status report (test expectations)

The companion test file `src/__tests__/w133_index_databases.test.ts`
documents the gates as 30 behavioral tests.  Discovery-only —
expected behavior:

- **Tests that PASS today** (3 gates): G03, G09, G27.
- **Tests that DOCUMENT the bug** (27 gates, all xfailed via
  `.todo` or explicit `expect(bug-shape).toBe(bug-shape)` of the
  current behavior with a `// BUG-N` comment).

No production-code changes.  Total LOC in test file: ~XYZ (see
file).
