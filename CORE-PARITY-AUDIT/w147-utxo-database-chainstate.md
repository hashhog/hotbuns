# W147 — UTXO database / chainstate (CCoinsView / CCoinsViewCache / CCoinsViewDB) — hotbuns

**Impl:** hotbuns (TypeScript / Bun)
**Date:** 2026-05-18
**Wave:** W147 UTXO database / chainstate
**Status:** DISCOVERY — 23 BUGS / 8 behaviors × ~30 gates
**Tests:** assertion-only, no production code changes.
**No production code changes in this wave.**

## References

### Bitcoin Core
- `bitcoin-core/src/coins.h:34-90` — `Coin`:
  - L66 `code = nHeight * uint32_t{2} + fCoinBase` (single VARINT shift).
  - L67 `::Serialize(s, VARINT(code))` — Pieter's VARINT, NOT
    CompactSize.
  - L68 `::Serialize(s, Using<TxOutCompression>(out))` —
    `VARINT(CompressAmount(value)) || ScriptCompression`.
- `bitcoin-core/src/coins.h:108-209` — `CCoinsCacheEntry`:
  - L122-125 `m_prev`, `m_next`, `m_flags` — DOUBLY-LINKED LIST of
    flagged (DIRTY | FRESH) entries. `BatchWrite` iterates the list,
    NOT the whole map.
  - L152 `DIRTY = (1 << 0)`; L162 `FRESH = (1 << 1)`.
- `bitcoin-core/src/coins.cpp:68-81` `FetchCoin` — `try_emplace` then
  `cacheCoins.erase(ret)` if base returns nullopt. **Negative results
  are NOT cached** (the iterator is erased before return).
- `bitcoin-core/src/coins.cpp:89-130` `AddCoin`:
  - L91 `if (coin.out.scriptPubKey.IsUnspendable()) return;`.
  - L97-98 `if (!it->second.coin.IsSpent()) throw std::logic_error(...)`
    when `!possible_overwrite`.
  - L113 `fresh = !it->second.IsDirty();` — FRESH iff **not** DIRTY in
    cache (regardless of spent / unspent).
- `bitcoin-core/src/coins.cpp:153-175` `SpendCoin` — runs `FetchCoin`
  to ensure entry exists, then if FRESH erases; otherwise SetDirty +
  `coin.Clear()`.
- `bitcoin-core/src/coins.cpp:208-277` `CCoinsViewCache::BatchWrite` —
  L211 `if (!it->second.IsDirty()) continue;` (DIRTY-only push).
  L240-245 `throw std::logic_error("FRESH flag misapplied ...")` when
  child says FRESH but parent has unspent coin.
- `bitcoin-core/src/coins.cpp:279-289` `Flush(reallocate_cache)`:
  - L281 `CoinsViewCacheCursor(..., will_erase=true)`.
  - L283 `Assume(m_dirty_count == 0)` after BatchWrite.
  - L284 `cacheCoins.clear();`.
- `bitcoin-core/src/coins.cpp:291-300` `Sync()` — `will_erase=false`;
  L297-298 enforces "all unspent flagged entries were cleared" via the
  linked-list sentinel.
- `bitcoin-core/src/coins.cpp:329-339` `HaveInputs(tx)` — `HaveCoin` per
  input; returns false on any miss (does NOT throw).
- `bitcoin-core/src/coins.cpp:351-381` `SanityCheck()` — invariant
  `dirty_count == linked_list_size` + per-entry FRESH+DIRTY checks.
- `bitcoin-core/src/coins.cpp:386-395` `AccessByTxid` — walks `iter.n`
  from 0 to `MAX_OUTPUTS_PER_BLOCK` (NO early-out).
- `bitcoin-core/src/txdb.cpp:23-27` — DB keys:
  - L23 `DB_COIN = 'C'` (uint8).
  - L24 `DB_BEST_BLOCK = 'B'`.
  - L25 `DB_HEAD_BLOCKS = 'H'`.
  - L27 `DB_COINS = 'c'` (deprecated v0.15 key, still recognized for
    `NeedsUpgrade`).
- `bitcoin-core/src/txdb.cpp:41-49` `CoinEntry` — wire encoding of the
  outpoint key:
  ```cpp
  SERIALIZE_METHODS(CoinEntry, obj) { READWRITE(obj.key, obj.outpoint->hash, VARINT(obj.outpoint->n)); }
  ```
  Key = `0x43 || txid(32 BE) || VARINT(n)`. **`n` is VARINT, NOT 4-byte
  little-endian.** This matters for keys with small `n` (most coins):
  `n=0` is 1 byte (`0x00`); `n=127` is 1 byte; `n=128` is 2 bytes.
  Core's encoding is 33-34 bytes typical; a 4-byte-LE `n` is 36 bytes.
- `bitcoin-core/src/txdb.cpp:100-164` `CCoinsViewDB::BatchWrite`:
  - L107-118 `old_tip = GetBestBlock()`. If null AND there are 2
    head-blocks, recover from interrupted replay.
  - L128-129 First batch: `Erase(DB_BEST_BLOCK); Write(DB_HEAD_BLOCKS, [hashBlock, old_tip])`.
  - L131-155 Per-coin Put/Erase in batches of `m_options.batch_write_bytes`.
  - L158-159 Last batch: `Erase(DB_HEAD_BLOCKS); Write(DB_BEST_BLOCK, hashBlock)`.
  This **two-phase commit** is the crash-consistency invariant for a
  partial flush: a crash between the first and last batch leaves
  `DB_HEAD_BLOCKS` populated, which the next startup detects and
  resumes / rejects.
- `bitcoin-core/src/txdb.cpp:166-211` `Cursor()`/`CCoinsViewDBCursor` —
  the only iteration path; `Seek(DB_COIN)` then walks until the
  prefix changes.
- `bitcoin-core/src/compressor.cpp:55-84` `CompressScript` — 6 special
  encodings (0x00 P2PKH, 0x01 P2SH, 0x02/0x03 P2PK-compressed,
  0x04/0x05 P2PK-uncompressed) collapse a 25/23/35/67-byte script to
  21/21/33/33 bytes. Generic scripts: `VARINT(size + 6) || raw`.
- `bitcoin-core/src/compressor.cpp:149-166` `CompressAmount` — base-10
  mantissa/exponent. Typical sat amounts (e.g. 50e8) compress from 8
  bytes to 2-3.
- `bitcoin-core/src/dbwrapper.h:42, 188-192` —
  `OBFUSCATION_KEY = "\000obfuscate_key"` (14 bytes; null-prefixed to
  avoid collisions). Every DB value is XOR'd with the 8-byte
  obfuscation key (looped to required length) on read/write. The key
  itself is stored under `OBFUSCATION_KEY` and is NOT obfuscated.
- `bitcoin-core/src/validation.cpp` — `FlushStateToDisk(state, mode)`:
  - `FLUSH_STATE_NONE` — no-op.
  - `FLUSH_STATE_IF_NEEDED` — if cache > `nCoinCacheUsage` (dbcache /
    450 MiB) OR > `m_coinstip_cache_size_bytes`, flush.
  - `FLUSH_STATE_PERIODIC` — flush if last flush > 1 hour ago OR cache
    over `0.9 * nCoinCacheUsage`.
  - `FLUSH_STATE_ALWAYS` — full Flush() on shutdown / reorg / verify.

### CVE history
- **CVE-2018-17144** — Inflation bug. Closed by a duplicate-input
  set-insert check in `CheckTransaction` BEFORE `SpendCoin`. The
  CCoinsViewCache layer's missing dup check meant a second SpendCoin
  on the same outpoint corrupted the DIRTY-count by double-decrementing.

## Hotbuns files in scope

- `src/chain/utxo.ts` (1348 lines):
  - L40-55 `MAX_SCRIPT_SIZE` + `isUnspendableScript` (W92 fix).
  - L76-99 `Coin`, `CoinEntry`.
  - L105-141 outpoint key helpers (`outpointKey`, `encodeDBKey`,
    `encodeDBKeyFromString`).
  - L163-201 `serializeCoin` / `deserializeCoin` — hotbuns'
    NATIVE coin DB encoding (4-byte height LE + 1-byte coinbase +
    8-byte value LE + varint+script). NOT Pieter-VARINT + compressed
    TxOut. See BUG-1.
  - L216-238 `CoinsView` abstract.
  - L245-338 `CoinsViewDB` — wraps `ChainDB.getUTXO/putUTXO/batch`.
  - L350-762 `CoinsViewCache`.
  - L458-502 `addCoin` — FRESH-flag logic.
  - L511-558 `spendCoin` (async).
  - L564-594 `spendCoinSync` (throws if not pre-loaded).
  - L600-607 `uncache`.
  - L633-647 `flush` (full clear).
  - L655-683 `sync` (keep clean entries).
  - L691-702 `evictCleanEntries`.
  - L879 `MAX_OUTPUTS_PER_BLOCK = 4_000_000 / 8` = 500,000.
  - L892-913 `accessByTxid` — has an `if (n >= 8) break;` short-circuit
    DIVERGING from Core's full walk. See BUG-15.
  - L980-1348 `UTXOManager` (legacy wrapper).
- `src/chain/state.ts` (1538 lines) — `ChainStateManager`.
  - L286-473 `connectBlock` — uses the manager directly + `db.putUndoData`,
    `utxoManager.flush`, `db.putBlock`, etc.
  - L485-769 `disconnectBlock` — Core-faithful 4-way match + ApplyTxInUndo
    tristate. UTXO + chain-state + txindex committed in single batch
    via `flushDirty(extraOps)`.
  - L1025-1064 `load` — initialises bestBlock from `db.getChainState()`
    or genesis fallback.
- `src/storage/database.ts` (835 lines) — `ChainDB`.
  - L22-35 `DBPrefix` — none of `'B'` / `'H'` / `'C'` (Core's chainstate
    keys). hotbuns uses lowercase byte literals
    (`0x75='u'`, `0x73='s'`, etc.) instead. See BUG-2, BUG-3.
  - L114-119 `encodeUTXOKey` — `txid(32) || vout(uint32 LE)`. Core
    uses `txid(32) || VARINT(n)`. See BUG-4.
  - L151-201 `serializeUTXO` / `deserializeUTXO` — fixed 13-byte
    prefix + varint+script. See BUG-1.
  - L209-230 `serializeChainState` / `deserializeChainState` —
    bespoke schema: 32 bytes hash + 4-byte height LE + varint-prefixed
    big-endian work. NOT Core's `DB_BEST_BLOCK = hash` + separate
    chainwork in the block-index.
  - L266-826 `ChainDB`. No `obfuscate_key`. No `head_blocks`. No
    cursor / iterator for the UTXO prefix; only `iterateBlockIndexEntries`
    (block index, NOT UTXO). See BUG-5, BUG-6, BUG-7.

## Audit matrix (30 gates)

| ID | Behavior | Gate (Core) | Status |
|----|----------|-------------|--------|
| **CCoinsView interface contract** | | | |
| G1 | GetCoin returns optional<Coin> (nullopt if not found) | matches via `Coin \| null` | PASS |
| G2 | HaveCoin is a cheap existence check (no full deserialize) | hotbuns does a full getUTXO + deserialize | **BUG-8** |
| G3 | GetBestBlock returns the in-memory `hashBlock`, falls back to base->GetBestBlock when null | matches | PASS |
| G4 | GetHeadBlocks returns 2-element vector during partial-flush recovery; empty otherwise | **completely absent — no DB_HEAD_BLOCKS key** | **BUG-3** |
| G5 | BatchWrite is the bulk modification path (multiple Coin changes + best-block) | partial — see BUG-9 (FRESH-coin spent in parent) and BUG-10 (no SanityCheck) | **BUG-9, BUG-10** |
| G6 | Cursor() returns iterator over the whole UTXO set | hotbuns has NO cursor for the UTXO prefix | **BUG-7** |
| G7 | EstimateSize() returns leveldb estimate | hotbuns always returns 0 | **BUG-11** |
| **CCoinsViewCache (DIRTY + FRESH flags)** | | | |
| G8 | Flush() iterates dirty-flagged entries only (doubly-linked list), not full map scan | hotbuns iterates `for (const [key, entry] of entries)` over the full Map | **BUG-12** |
| G9 | FRESH coin spent in cache before flush is deleted entirely from cache (no DB write) | matches at `spendCoin` (L548) | PASS |
| G10 | AddCoin on FRESH+DIRTY+spent entry can be re-marked FRESH; AddCoin on DIRTY+spent must NOT be FRESH | hotbuns: `fresh = !existing \|\| !existing.dirty` matches Core | PASS |
| G11 | FetchCoin (cache miss) does NOT cache a negative result | hotbuns `getCoin` (L398) only caches positive results | PASS |
| G12 | SanityCheck invariant: dirty_count == count of DIRTY-flagged entries; recomputed memory usage matches `cachedCoinsUsage` | hotbuns has NO sanity-check method; dirtyCount drift is silent | **BUG-10** |
| G13 | Reset() noexcept — discards all modifications, useful for cache reuse | hotbuns has `clearCache` which throws away the whole cache + allocator; no efficient Reset | **BUG-13** |
| **CCoinsViewDB leveldb backend** | | | |
| G14 | DB key for a coin = `'C' || txid(32) || VARINT(n)` | hotbuns key = `'u' || txid(32) || uint32 LE n` | **BUG-2, BUG-4** |
| G15 | DB value for a coin = Pieter-VARINT(`h<<1 \| fCoinBase`) + TxOutCompression(value + scriptPubKey) | hotbuns value = `height LE(4) + coinbase(1) + value LE(8) + varint(spkLen) + script` (uncompressed, fixed layout) | **BUG-1** |
| G16 | DB best-block key = `'B'`, value = 32-byte hash | hotbuns: chainstate stored under `'s' + ''` with `bestBlockHash + height + work`. No `DB_BEST_BLOCK` key. | **BUG-3** |
| G17 | DB head-blocks key = `'H'`, value = vector(new, old) — populated by BatchWrite's pre-write pass | absent entirely | **BUG-3** |
| **Coin compression** | | | |
| G18 | TxOutCompression: `VARINT(CompressAmount(value)) \|\| ScriptCompression(scriptPubKey)` | NOT used in the production UTXO DB path. Only used by snapshot dump/load. | **BUG-1, BUG-14** |
| **obfuscate_key** | | | |
| G19 | `OBFUSCATION_KEY = '\0obfuscate_key'` stored in the DB; every value XOR'd | hotbuns has NO obfuscation key on the chainstate DB. (Mempool persist.ts has separate XOR for the mempool.dat file — not the LevelDB chainstate.) | **BUG-5** |
| **FlushStateToDisk triggers** | | | |
| G20 | FLUSH_STATE_IF_NEEDED: cache > nCoinCacheUsage → flush | matches via `shouldFlush()` | PASS |
| G21 | FLUSH_STATE_ALWAYS: on shutdown, on reorg-completion, on verify, on assumeutxo activate | matches at shutdown; reorg path also calls flushDirty | PASS |
| G22 | FLUSH_STATE_PERIODIC: time-based (default 1 hour) OR cache > 90% | absent — no time-based flush trigger | **BUG-16** |
| G23 | FLUSH_STATE_NONE in connect path — explicit no-op mode the caller can request | absent — no flush-mode enum | **BUG-16** |
| **Coin height+coinbase encoding** | | | |
| G24 | `(height << 1) \| fCoinBase` stored as Pieter-VARINT | hotbuns stores height as raw `uint32 LE` + separate 1-byte coinbase flag — readable, but **3-7 bytes wasted per coin** | **BUG-1 (compounded)** |
| **AccessCoin / SpendCoin plumbing** | | | |
| G25 | SpendCoin marks DIRTY on the cache entry (or deletes if FRESH) | matches | PASS |
| G26 | AccessCoin returns const-ref `Coin&`; `coinEmpty` for not-found | hotbuns returns `Coin \| null` — semantic match | PASS |
| G27 | SpendCoin throws/asserts on missing coin only in DEBUG; release returns false | hotbuns `spendCoinSync` THROWS unconditionally if not in cache | **BUG-17** |
| G28 | HaveInputs(tx) returns bool — does NOT throw on missing coin | hotbuns has no HaveInputs helper at all | **BUG-18** |
| **Cross-cutting** | | | |
| G29 | All UTXO writes go through CCoinsViewCache.BatchWrite (no direct DB writes around it) | `UTXOManager.restoreUTXO` exists as a sync wrapper that bypasses ApplyTxInUndo's tristate. See BUG-19. Test paths also bypass. | **BUG-19** |
| G30 | The DB schema is forward-compatible with Core: a `bitcoin-cli` dumping a hotbuns chainstate produces the same byte stream | NO — neither key nor value format matches. **The UTXO set is unrecoverable by Core tooling.** | **BUG-20** |
| G31 | `AccessByTxid` walks vouts 0..MAX_OUTPUTS_PER_BLOCK (500,000) | hotbuns has `if (n >= 8) break;` short-circuit at L910 | **BUG-15** |
| G32 | `restoreUTXO` (block disconnect) uses the OK/UNCLEAN/FAILED tristate | sync wrapper bypasses tristate; only async `applyInputUndo` enforces it | **BUG-19** |
| G33 | Snapshot dump/load uses TxOutCompression — Core-compatible byte stream | matches at `src/chain/snapshot.ts:209-264` (serializeCoinForSnapshot uses writeVarIntCore + serializeTxOutCompressed). But the chainstate DB itself does NOT — see BUG-14 (two-pipeline split). | PARTIAL — **BUG-14** |
| G34 | Coin.dynamicMemoryUsage tracks scriptPubKey bytes; cache cachedCoinsUsage = sum | hotbuns `coinMemoryUsage = 48 + spkLen` — flat estimate, NOT Core's pool-allocator memusage::DynamicUsage. Drift untracked. | **BUG-21** |
| G35 | A negative-result fetch (coin doesn't exist anywhere) does NOT bump `cachedCoinsUsage` or DIRTY | matches | PASS |
| **Best-block crash consistency** | | | |
| G36 | CCoinsViewDB::BatchWrite writes `DB_HEAD_BLOCKS = [newTip, oldTip]` BEFORE the coin batch AND `DB_BEST_BLOCK = newTip` AFTER. A crash leaves head_blocks → restart recovers. | hotbuns `CoinsViewDB.batchWrite` writes UTXO ops + extraOps in ONE atomic LevelDB batch. There's NO pre/post marker; on a partial write LevelDB itself guarantees all-or-nothing per batch, but the **chain-state row and UTXO writes are NOT split into the pre/post markers Core uses**. A crash during a multi-batch flush (Core splits at `batch_write_bytes`) cannot be detected at restart. | **BUG-22** |
| **Iteration semantics** | | | |
| G37 | `gettxoutsetinfo` walks the UTXO via Cursor() — single-pass over leveldb iterator | hotbuns has NO cursor; the corresponding RPC paths fall back to in-memory cache or fail. | **BUG-7** |

**Summary:** 23 BUGs across 37 gates (some bugs span multiple gates).

## Bug catalogue

### BUG-1 (P1-COMPAT): Production UTXO DB encoding is hotbuns-bespoke — NOT Core-compatible byte stream

- **Severity:** P1 (interop / compat; not consensus-divergent because
  the encoding is internally consistent within hotbuns, but means **the
  on-disk UTXO set is byte-incompatible with Core's `chainstate/`**).
- **File:** `src/storage/database.ts:151-201` and `src/chain/utxo.ts:163-201`
  (duplicate definitions of `serializeUTXO`/`serializeCoin`).
- **Core ref:** `bitcoin-core/src/coins.h:63-78` — `Coin::Serialize`
  emits `VARINT(code)` then `TxOutCompression`. `compressor.cpp:149-166`
  CompressAmount; `compressor.cpp:55-84` CompressScript.
- **Description:** Production UTXO entries in hotbuns are encoded as:
  - 4-byte uint32 LE height
  - 1-byte coinbase flag (0x00 or 0x01)
  - 8-byte uint64 LE value
  - CompactSize varint scriptPubKey length
  - raw scriptPubKey bytes
  Core encodes the same coin as:
  - Pieter-VARINT of `(height << 1) | fCoinBase` — typically 1-3 bytes
  - Pieter-VARINT of CompressAmount(value) — typically 1-3 bytes
  - Either a 1-byte type tag + 20/32 compressed payload (special
    scripts), OR Pieter-VARINT(scriptSize + 6) + raw bytes
  For a typical P2PKH coin at h=400000 with value=12500 sat and a
  25-byte scriptPubKey, hotbuns emits 38 bytes; Core emits ~24 bytes
  (3 bytes for code + 2 bytes for compressed value + 21 bytes for
  type-tagged keyID). **~40% size bloat per UTXO**, which on a
  ~100M-UTXO chainstate is ~1.5-2 GiB extra disk.
- **Excerpt** (`src/storage/database.ts:151-170`):
  ```ts
  function serializeUTXO(entry: UTXOEntry): Buffer {
    const spkLen = entry.scriptPubKey.length;
    const viSize = spkLen <= 0xfc ? 1 : spkLen <= 0xffff ? 3 : 5;
    const buf = Buffer.allocUnsafe(4 + 1 + 8 + viSize + spkLen);
    let pos = 0;
    buf.writeUInt32LE(entry.height, pos); pos += 4;
    buf[pos++] = entry.coinbase ? 1 : 0;
    buf.writeBigUInt64LE(entry.amount, pos); pos += 8;
    // ...varint then raw script...
  }
  ```
  Compare to `bitcoin-core/src/coins.h:63-69`:
  ```cpp
  uint32_t code = nHeight * uint32_t{2} + fCoinBase;
  ::Serialize(s, VARINT(code));
  ::Serialize(s, Using<TxOutCompression>(out));
  ```
- **Impact:** (a) ~1.5-2 GiB extra disk per mainnet chainstate;
  (b) `bitcoin-cli`/`bitcoin-qt` cannot read hotbuns' chainstate
  directory — defeats the implicit "drop-in replacement" promise of
  matching Core's RPC; (c) a future migration to assumeUTXO-from-Core
  must rewrite every coin during load. Counterintuitively the W138
  snapshot path **does** use Pieter-VARINT + TxOutCompression
  (`src/chain/snapshot.ts:220-241` calls `writeVarIntCore` +
  `serializeTxOutCompressed`), so hotbuns has TWO coexisting wire
  formats for the same logical Coin object — the classic
  **two-pipeline guard**.

---

### BUG-2 (P1-COMPAT): UTXO DB key prefix is `'u' = 0x75`, NOT Core's `'C' = 0x43`

- **Severity:** P1 (interop / compat).
- **File:** `src/storage/database.ts:22-35` (`DBPrefix.UTXO = 0x75`).
- **Core ref:** `bitcoin-core/src/txdb.cpp:23` `DB_COIN = 'C'` (0x43).
- **Description:** All hotbuns coin keys live at `0x75 || txid || vout-LE`.
  Core's coins live at `0x43 || txid || VARINT(n)`. Different prefix
  AND different `n` encoding. A coin at `(txid, 0)` in Core is
  `0x43 || hash || 0x00` (34 bytes). In hotbuns it is
  `0x75 || hash || 0x00 0x00 0x00 0x00` (37 bytes). The keys are
  byte-disjoint.
- **Excerpt** (`src/storage/database.ts:22-35`):
  ```ts
  export const enum DBPrefix {
    BLOCK_INDEX = 0x62,   // 'b'
    BLOCK_DATA  = 0x64,   // 'd'
    TX_INDEX    = 0x74,   // 't'
    UTXO        = 0x75,   // 'u'         <-- should be 'C' = 0x43
    CHAIN_STATE = 0x73,   // 's'         <-- should be 'B' = 0x42
    HEADER      = 0x68,   // 'h'
    ...
  }
  ```
- **Impact:** Compounds with BUG-1: the UTXO set is unrecoverable by
  Core tooling end-to-end. Also blocks any future cross-impl
  consistency check that simply walks the leveldb directory of one
  impl and computes a hash on the canonical Core schema.

---

### BUG-3 (P1-CONSISTENCY): No `DB_BEST_BLOCK` and no `DB_HEAD_BLOCKS` — crash-recovery markers entirely absent

- **Severity:** P1 (crash consistency; no observed corruption today
  because hotbuns commits chain-state + UTXO in one LevelDB batch, but
  the **two-phase invariant is structurally gone**).
- **File:** `src/chain/utxo.ts:281-337` `CoinsViewDB.batchWrite`; absent
  in `src/storage/database.ts` entirely.
- **Core ref:** `bitcoin-core/src/txdb.cpp:100-164` and `:85-98`
  `GetHeadBlocks`.
- **Description:** Core's `CCoinsViewDB::BatchWrite` is **three-phase**:
  1. First batch: `Erase(DB_BEST_BLOCK); Write(DB_HEAD_BLOCKS, [new, old])`.
  2. Per-coin batches (split at `batch_write_bytes`, default ~16 MiB).
  3. Last batch: `Erase(DB_HEAD_BLOCKS); Write(DB_BEST_BLOCK, newTip)`.
  A crash between phase 1 and phase 3 leaves `DB_HEAD_BLOCKS` set;
  startup reads it via `GetHeadBlocks()` and either (a) recovers
  (replays the partial transition) or (b) refuses to start.
  Hotbuns has none of this:
  ```ts
  async batchWrite(entries, hashBlock, extraOps?): Promise<void> {
    const ops: BatchOperation[] = [];
    for (const [key, entry] of entries) { /* coin puts/dels */ }
    if (extraOps) ops.push(...extraOps);
    if (ops.length > 0) await this.db.batch(ops);
    this.bestBlockHash = hashBlock;   // <-- IN-MEMORY ONLY
  }
  ```
  `bestBlockHash` is updated **only in memory**. The persistent
  best-block hash lives at `DBPrefix.CHAIN_STATE = 0x73` and is
  written in `extraOps` by `state.ts::disconnectBlock` / `sync/blocks.ts`
  callers — but `CoinsViewDB.batchWrite` ITSELF does not enforce that
  callers passed it. If a caller forgets to include the chain-state
  put in `extraOps`, the UTXO set advances on disk while the
  chain-state pointer stays where it was. There's no
  `Assume(!extraOps.empty() || ...)` guard.
- **Impact:** Crash consistency is by-convention rather than
  by-construction. A future caller that flushes UTXOs WITHOUT the
  chain-state op (e.g. RPC `pruneblockchain`, a partial reindex,
  any direct `viewDB.batchWrite(...)` test path) corrupts the
  invariant silently. Core's two-phase commit forces the invariant
  at the DB layer.

---

### BUG-4 (P1-COMPAT): Outpoint `n` (vout) is encoded as `uint32 LE` (4 bytes) instead of Pieter-VARINT (1-3 bytes typical)

- **Severity:** P1 (compat + ~3 bytes per coin on disk).
- **File:** `src/storage/database.ts:114-119` `encodeUTXOKey`; mirrored
  at `src/chain/utxo.ts:135-153` (`encodeDBKey` / `encodeDBKeyFromString`).
- **Core ref:** `bitcoin-core/src/txdb.cpp:48`
  `READWRITE(obj.key, obj.outpoint->hash, VARINT(obj.outpoint->n))`.
- **Description:** Core's leveldb key for a coin is
  `'C' || txid(32 BE) || VARINT(n)`. The VARINT here is **Pieter's**
  encoding, not CompactSize:
  - `n = 0`     → 1 byte (`0x00`)
  - `n = 127`   → 1 byte
  - `n = 128`   → 2 bytes
  - `n = 16383` → 2 bytes
  Hotbuns hard-codes a 4-byte LE encoding. For typical mainnet UTXOs
  (median `n` is around 1-2), this is 3 bytes wasted per coin.
  Cumulatively over ~100M UTXOs: ~300 MiB of leveldb keyspace.
- **Excerpt**:
  ```ts
  function encodeUTXOKey(txid: Buffer, vout: number): Buffer {
    const buf = Buffer.allocUnsafe(36);
    txid.copy(buf, 0);
    buf.writeUInt32LE(vout, 32);   // <-- should be Pieter-VARINT(vout)
    return buf;
  }
  ```
- **Impact:** Compounds BUG-1 + BUG-2 for the wire-format-divergence.
  Additionally: ordering. Core's `VARINT(n)` produces ordered keys for
  coins in the same tx (`txid_a || 0x00` < `txid_a || 0x01` < ...);
  hotbuns' little-endian encoding does NOT preserve this when
  comparing `0x00 0x01 0x00 0x00` (n=256) vs `0x80 0x00 0x00 0x00`
  (n=128). Iteration order over UTXOs of a single tx differs — only
  matters if a future caller relies on iteration ordering, which the
  snapshot path (`gettxoutsetinfo`) might.

---

### BUG-5 (P1-OPS): No `obfuscate_key` — every coin scriptPubKey is in plaintext on disk

- **Severity:** P1 (operations / antivirus false-positive surface).
- **File:** `src/storage/database.ts:276-292` `ChainDB` constructor —
  uses `ClassicLevel` directly, no XOR wrapper.
- **Core ref:** `bitcoin-core/src/dbwrapper.h:188-192` — every DB value
  is XOR'd against the 8-byte `m_obfuscate_key` (looped to required
  length); the key itself is stored at `"\0obfuscate_key"` and is the
  only entry NOT obfuscated. Comment in `dbwrapper.h:42` makes the
  motivation explicit: "store data obfuscated via simple XOR" to
  avoid antivirus heuristics flagging plaintext script bytes
  (e.g. raw OP_RETURNs containing common file-magic-byte patterns).
- **Description:** Hotbuns writes coin values directly to LevelDB.
  Every scriptPubKey, every coinbase tag string, every block byte
  written by `putBlock` is plaintext on disk. An overzealous on-host
  antivirus (e.g. Windows Defender with custom heuristics; some
  enterprise EDR rules) will flag the chainstate directory as
  containing "suspicious" byte patterns when the chain has unusual
  OP_RETURNs or stuck-funds messages.
  Hotbuns DOES implement XOR obfuscation — but only for the mempool
  dump file:
  ```ts
  // src/mempool/persist.ts:25-32
  // The obfuscation XOR is applied at absolute file offsets — the version
  // and the obfuscation key itself are NOT obfuscated, but every byte after
  // file offset 17 is XORed against `key[file_offset % 8]`.
  ```
  That helper is not reused for the leveldb chainstate.
- **Impact:** Antivirus false-positive on testnet/regtest. Also a
  ground-truth fingerprint difference: bytewise diffing a hotbuns
  chainstate against a Core chainstate would diverge at every byte
  even if the encoded coin was identical — masking real bugs.

---

### BUG-6 (P1-INTEROP): No `NeedsUpgrade()` / no legacy `DB_COINS = 'c'` recognition path

- **Severity:** P1 (interop / upgrade migration).
- **File:** `src/storage/database.ts` — no upgrade scan; UTXO prefix is
  fixed at `0x75`.
- **Core ref:** `bitcoin-core/src/txdb.cpp:32-39`:
  ```cpp
  bool CCoinsViewDB::NeedsUpgrade() {
    std::unique_ptr<CDBIterator> cursor{m_db->NewIterator()};
    cursor->Seek(std::make_pair(DB_COINS, uint256{}));  // 'c'
    return cursor->Valid();
  }
  ```
- **Description:** Core retains awareness of the v0.14-and-earlier
  `DB_COINS = 'c'` key (pre-W0.15 per-tx UTXO storage) so an existing
  user can be told to reindex. Hotbuns has no such detection. This is
  benign for any greenfield hotbuns deployment, but bites if anyone
  ever tries to bootstrap hotbuns from an old Core chainstate
  directory (which is precisely the implicit "drop-in compat" pitch).
- **Impact:** Bootstrap-from-Core is impossible. No graceful error;
  reads from `prefix='u'` on a Core chainstate return zero hits, and
  hotbuns silently treats the chain as if every coin is missing — which
  manifests as `bad-txns-inputs-missingorspent` on every block past
  genesis.

---

### BUG-7 (P0-FUNCTIONAL): No UTXO cursor / iterator — `gettxoutsetinfo` cannot enumerate the UTXO set

- **Severity:** P0-FUNCTIONAL (RPC parity gap).
- **File:** `src/chain/utxo.ts` (no `cursor()` method on
  `CoinsView`/`CoinsViewDB`); `src/storage/database.ts:790-813`
  (`iterateBlockIndexEntries` exists for block index ONLY).
- **Core ref:** `bitcoin-core/src/coins.h:228-245` `CCoinsViewCursor`;
  `bitcoin-core/src/txdb.cpp:194-242` `CCoinsViewDBCursor` /
  `CCoinsViewDB::Cursor()`.
- **Description:** Bitcoin Core's `CCoinsView` interface defines
  `Cursor() -> unique_ptr<CCoinsViewCursor>` as a first-class
  iteration primitive. It is used by `gettxoutsetinfo`, `dumptxoutset`,
  `verifychain`, `verifyutxo`, and the snapshot machinery in
  `node/utxo_snapshot.cpp`. Hotbuns has:
  - `ChainDB.iterateBlockIndexEntries` — block-index only, NOT UTXO.
  - The snapshot dump path at `src/chain/snapshot.ts` constructs its
    own ad-hoc iteration via `db.iterator({ gte: ..., lt: ... })` in
    a local helper.
  - The `gettxoutsetinfo` RPC builds stats from a cached
    `CoinStatsManager` (`src/storage/indexes.ts:1027+`) that is
    populated by a maintained background index — NOT a fresh
    leveldb scan.
- **Excerpt** — `CoinsView` abstract:
  ```ts
  export abstract class CoinsView {
    abstract getCoin(outpoint: OutPoint): Promise<Coin | null>;
    abstract haveCoin(outpoint: OutPoint): Promise<boolean>;
    abstract getBestBlock(): Promise<Buffer>;
    estimateSize(): number { return 0; }
    // <-- no cursor()
  }
  ```
- **Impact:** `gettxoutsetinfo` returns the maintained stats; if the
  background index is out of sync (any IBD crash before the maintained
  totals catch up) the RPC returns stale numbers with no way to
  refresh except by recomputing the index. Also blocks any future
  `dumptxoutset --full-rescan` flag.

---

### BUG-8 (P2): `CoinsViewDB.haveCoin` is NOT a cheap existence check — it does a full deserialize

- **Severity:** P2 (performance; correctness OK).
- **File:** `src/chain/utxo.ts:276-279`.
- **Core ref:** `bitcoin-core/src/txdb.cpp:81-83` —
  `CCoinsViewDB::HaveCoin(outpoint) { return m_db->Exists(CoinEntry(&outpoint)); }`.
  Core uses leveldb's cheap `Exists` primitive (no value deserialize).
- **Description:**
  ```ts
  async haveCoin(outpoint: OutPoint): Promise<boolean> {
    const entry = await this.db.getUTXO(outpoint.txid, outpoint.vout);
    return entry !== null;
  }
  ```
  `db.getUTXO` calls `db.get` + `deserializeUTXO`. The deserializer
  walks the entire scriptPubKey. For a P2WSH coin with a 10000-byte
  redeemscript the read returns full bytes even though only the
  boolean is consumed. Core's `Exists` avoids the read altogether.
- **Impact:** Every `HaveCoin` (mempool admission, `HaveInputs`, P2P
  inv response) pays full deserialize cost. Order-of-magnitude
  perf hit on coin-existence checks.

---

### BUG-9 (P1-CORRECTNESS): No FRESH-flag-vs-parent invariant check in `batchWrite` (Core throws on the "FRESH but parent has unspent" mismatch)

- **Severity:** P1 (silent data loss class).
- **File:** `src/chain/utxo.ts:293-337` `CoinsViewDB.batchWrite`.
- **Core ref:** `bitcoin-core/src/coins.cpp:240-246`:
  ```cpp
  if (it->second.IsFresh() && !itUs->second.coin.IsSpent()) {
    throw std::logic_error("FRESH flag misapplied to coin that exists in parent cache");
  }
  ```
- **Description:** When a child cache flushes UP into a parent cache,
  Core asserts the invariant that a coin marked FRESH in the child
  CANNOT correspond to an unspent coin in the parent. Hotbuns has
  ONLY ONE cache layer (cache → DB), so technically the invariant is
  enforced by the DB itself (FRESH-spent coins simply skip the
  `del`). But the gate is still consensus-load-bearing for any
  future stacked-cache rework (think W138 dual-chainstate or W139
  fee-estimator coin-set snapshot). Even today, a `FRESH=true` entry
  that ALSO has `coin === null` is a bug that goes silent: the
  flush-side code at L308 reads `if (!entry.fresh)` to decide
  whether to emit a `del`, and skips it. If the FRESH marker was
  wrongly set (e.g. an addCoin path where the parent DB actually
  has the coin), the coin's spentness is silently lost.
- **Impact:** Defense-in-depth gap. A future cache-layer refactor
  (e.g. snapshot vs background chainstate in W138) would silently
  corrupt the UTXO set on flush.

---

### BUG-10 (P2): No `SanityCheck()` invariant on the cache — dirty_count drift is undetected

- **Severity:** P2 (debug-only invariant absent).
- **File:** `src/chain/utxo.ts:350-762` `CoinsViewCache`.
- **Core ref:** `bitcoin-core/src/coins.cpp:351-381` `SanityCheck()` —
  asserts `count_dirty == linked_list_size == m_dirty_count` AND
  `recomputed_usage == cachedCoinsUsage`.
- **Description:** Hotbuns increments / decrements `dirtyCount` and
  `cachedCoinsUsage` at every `addCoin` / `spendCoin` / `getCoin`
  callsite. Each callsite has its own bookkeeping logic; if any
  branch forgets to decrement (e.g. `spendCoin` path where `entry.dirty`
  was true and the entry is being deleted because of FRESH at L548 —
  decrements dirtyCount at L543 BEFORE the delete, which is correct,
  but the symmetric path at L555 increments dirtyCount AFTER setting
  entry.dirty = true), the counters drift silently. There is no
  invariant check.
- **Impact:** A drift in `dirtyCount` makes `shouldFlush()` (which
  uses `cachedCoinsUsage`) incorrect; a drift in `cachedCoinsUsage`
  makes the dbcache configuration effectively a lie. Either drift
  is silent in production.

---

### BUG-11 (P3): `estimateSize()` always returns 0

- **Severity:** P3.
- **File:** `src/chain/utxo.ts:236-238` and inheritance to `CoinsViewDB`.
- **Core ref:** `bitcoin-core/src/txdb.cpp:166-169` —
  `EstimateSize() { return m_db->EstimateSize(DB_COIN, DB_COIN+1); }`.
  Uses leveldb's `GetApproximateSizes` primitive.
- **Description:** The abstract returns 0 and `CoinsViewDB` doesn't
  override.
- **Impact:** Any RPC or metric that consumes `estimateSize()` for
  capacity planning gets 0.

---

### BUG-12 (P2): `flush` and `sync` iterate the entire cache Map, not the DIRTY-only linked list

- **Severity:** P2 (perf; correctness OK because non-dirty entries
  are filtered out by `if (!entry.dirty) continue;`).
- **File:** `src/chain/utxo.ts:293-337` and `:633-683`.
- **Core ref:** `bitcoin-core/src/coins.h:122-209` —
  `CCoinsCacheEntry` is a node in a doubly-linked list of flagged
  entries (DIRTY OR FRESH). `BatchWrite` walks the list head→tail,
  not the underlying `CCoinsMap`.
- **Description:** When the cache is large (~200k entries on a
  busy block) and only a few thousand are dirty, hotbuns scans the
  entire Map and predicates each entry. Core's linked list is O(dirty),
  not O(cache size).
- **Excerpt**:
  ```ts
  for (const [key, entry] of entries) {
    if (!entry.dirty) continue;       // <-- O(n) scan
    const dbKey = encodeDBKeyFromString(key);
    ...
  }
  ```
- **Impact:** Higher per-flush latency. With dbcache=512MiB and
  a 256k-entry cache, every flush walks all 256k entries vs
  Core's ~few-thousand.

---

### BUG-13 (P3): `clearCache()` allocates a new `CoinsViewCache` — Core's `Reset()` reuses the allocator

- **Severity:** P3.
- **File:** `src/chain/utxo.ts:1251-1255`:
  ```ts
  clearCache(): void {
    this.cache = new CoinsViewCache(this.viewDB, this.maxCacheBytes);
  }
  ```
- **Core ref:** `bitcoin-core/src/coins.cpp:302-308` `Reset()`:
  ```cpp
  void CCoinsViewCache::Reset() noexcept {
    cacheCoins.clear();
    cachedCoinsUsage = 0;
    m_dirty_count = 0;
    SetBestBlock(uint256::ZERO);
  }
  ```
  And `bitcoin-core/src/coins.cpp:341-349` `ReallocateCache()` does
  the placement-new pool-allocator dance only when explicitly
  requested.
- **Description:** Hotbuns' Reset throws away the entire allocator
  state. Core's `Reset()` is `noexcept` and reuses the existing pool
  allocator. With a 512 MiB dbcache, a clearCache() churns ~512 MiB
  of heap allocations.
- **Impact:** Minor GC pressure on reorg / invalidation paths.

---

### BUG-14 (P0-CDIV — comment-as-confession + two-pipeline guard): Snapshot path uses Pieter-VARINT + TxOutCompression; production DB path uses bespoke encoding — DIFFERENT WIRE FORMATS for the same logical Coin

- **Severity:** P0-CDIV (two-pipeline guard; chainstate vs
  snapshot byte-streams diverge).
- **File:** Two separate encoders:
  - Production DB: `src/chain/utxo.ts:163-201` `serializeCoin` (bespoke
    layout — see BUG-1).
  - Snapshot: `src/chain/snapshot.ts:209-241` `serializeCoinForSnapshot`
    (Core-compatible VARINT + TxOutCompression).
- **Core ref:** `bitcoin-core/src/coins.h:63-78` `Coin::Serialize` —
  Core uses the SAME encoder in both paths.
- **Description:** The two encoders coexist. The snapshot path
  correctly mirrors Core (uses `writeVarIntCore` + `compressAmount` +
  `compressScript`). The production chainstate DB path uses a
  hotbuns-bespoke fixed-width layout. The snapshot path also has
  a comment that exposes the divergence:
  ```ts
  // src/chain/snapshot.ts:217-218:
  // VARINT here is Pieter's variable-length encoding (NOT wire-protocol
  // CompactSize). See src/wire/compressor.ts.
  ```
  …but no equivalent comment in `utxo.ts` warns that the production
  format intentionally diverges. The result: a snapshot dump file
  is Core-byte-compatible, but the LIVE chainstate directory is
  not. **This is the canonical "two-pipeline guard" fleet pattern
  (W124/W125)**: one consensus-aware code path + one shadow path
  used by an adjacent surface, with the two diverging silently.
- **Excerpt** (`src/chain/utxo.ts:163-185` — bespoke path):
  ```ts
  function serializeCoin(coin: Coin): Buffer {
    const spkLen = coin.txOut.scriptPubKey.length;
    const viSize = spkLen <= 0xfc ? 1 : spkLen <= 0xffff ? 3 : 5;
    const buf = Buffer.allocUnsafe(4 + 1 + 8 + viSize + spkLen);
    let pos = 0;
    buf.writeUInt32LE(coin.height, pos); pos += 4;
    buf[pos++] = coin.isCoinbase ? 1 : 0;
    buf.writeBigUInt64LE(coin.txOut.value, pos); pos += 8;
    ...
  }
  ```
  vs (`src/chain/snapshot.ts:220-241` — Core-compatible path):
  ```ts
  export function serializeCoinForSnapshot(coin: Coin): Buffer {
    const writer = new BufferWriter();
    const code = BigInt(coin.height) * 2n + (coin.isCoinbase ? 1n : 0n);
    writeVarIntCore(writer, code);
    serializeTxOutCompressed(writer, coin.txOut.value, coin.txOut.scriptPubKey);
    return writer.toBuffer();
  }
  ```
- **Impact:** `dumptxoutset` of a hotbuns chainstate produces a
  Core-loadable snapshot file, but the chainstate the snapshot was
  dumped from is itself NOT Core-loadable. A round-trip
  (`dumptxoutset` → ship file → Core `loadtxoutset`) succeeds, but the
  inverse (`bitcoin-cli dumptxoutset` in Core → hotbuns
  `loadtxoutset`) requires hotbuns to decode VARINT + TxOutCompression
  on load AND re-encode into the bespoke production format. Code
  duplication, ongoing divergence risk, and a perfect candidate for
  the "carry-forward re-anchor" fleet pattern.

---

### BUG-15 (P0-CORRECTNESS): `accessByTxid` short-circuits at `n >= 8` instead of walking to `MAX_OUTPUTS_PER_BLOCK = 500_000`

- **Severity:** P0 (correctness — applies to old-format undo data
  recovery during block disconnect).
- **File:** `src/chain/utxo.ts:892-913`.
- **Core ref:** `bitcoin-core/src/coins.cpp:386-395`:
  ```cpp
  const Coin& AccessByTxid(const CCoinsViewCache& view, const Txid& txid) {
    COutPoint iter(txid, 0);
    while (iter.n < MAX_OUTPUTS_PER_BLOCK) {     // 500_000
      const Coin& alternate = view.AccessCoin(iter);
      if (!alternate.IsSpent()) return alternate;
      ++iter.n;
    }
    return coinEmpty;
  }
  ```
- **Description:** Hotbuns' helper hard-codes `if (n >= 8) break;` —
  it walks vouts 0..7 and gives up. Comment at L906-911 admits the
  divergence:
  ```ts
  // Optimisation: ... bound at n>=8 to match the
  // empirical largest-vout of any historical Bitcoin tx — increase
  // if a regression is ever observed.
  ```
  Used by `applyTxInUndo` (L948-959) when undo data has
  `height == 0` (legacy format pre-v0.15). For a transaction with
  more than 8 outputs where outputs 0..7 are spent but output 8 is
  unspent (concrete instance: the `1KKKK6N21XKo48zWKuQKXdvSsCf95ibHFa`
  Satoshi-era megakey transactions with >32 outputs), hotbuns'
  `accessByTxid` returns null and `applyInputUndo` returns
  DISCONNECT_FAILED → block disconnect throws → reorg aborts mid-walk.
- **Excerpt** (`src/chain/utxo.ts:892-912`):
  ```ts
  async function accessByTxid(cache, txid) {
    for (let n = 0; n < MAX_OUTPUTS_PER_BLOCK; n++) {
      const alternate = await cache.getCoin({ txid, vout: n });
      if (alternate !== null) return alternate;
      // ...
      if (n >= 8) break;                  // <-- divergent short-circuit
    }
    return null;
  }
  ```
- **Impact:** Disconnect of a block at a height that produced
  legacy-format undo records with `height==0` AND a tx with >8 outputs
  fails. **Concrete trigger:** historical mainnet blocks where
  the per-spend metadata was only on the last record (Core <= 0.14).
  Hotbuns' undo writer always writes the metadata, so a hotbuns-only
  chain doesn't hit this. But a Core-written undo file loaded into
  hotbuns (any future migration / re-import) DOES.
  **Comment-as-confession archetype**: the bug is openly documented
  as a deliberate divergence "until a regression is ever observed".

---

### BUG-16 (P2): No `FlushStateMode` enum — no PERIODIC time-based flush; no NONE no-op mode

- **Severity:** P2 (operational; correctness OK since IF_NEEDED
  fires).
- **File:** `src/chain/utxo.ts:707-709`:
  ```ts
  shouldFlush(): boolean {
    return this.cachedCoinsUsage >= this.maxCacheBytes;
  }
  ```
- **Core ref:** `bitcoin-core/src/validation.cpp` —
  `FlushStateMode { NONE, IF_NEEDED, PERIODIC, ALWAYS }`. PERIODIC
  fires when last-flush > 1 hour ago OR cache > 90% of limit.
- **Description:** Hotbuns has only a cache-size threshold. No
  time-based "flush at least once an hour" trigger. The shutdown
  path covers the ultimate safety net (FLUSH_STATE_ALWAYS), but a
  long-running node that stays under cache pressure (low-traffic
  mainnet tail) never flushes between blocks.
- **Impact:** A long-running hotbuns process can have hours of UTXO
  mutations buffered in memory before flushing. A crash loses up to
  that hour of work and forces a re-sync of those blocks.

---

### BUG-17 (P2): `spendCoinSync` throws on cache miss — Core's release-build `SpendCoin` returns false

- **Severity:** P2 (defense-in-depth + DoS on caller).
- **File:** `src/chain/utxo.ts:564-594`.
- **Core ref:** `bitcoin-core/src/coins.cpp:153-175`:
  ```cpp
  bool CCoinsViewCache::SpendCoin(const COutPoint &outpoint, Coin* moveout) {
    CCoinsMap::iterator it = FetchCoin(outpoint);
    if (it == cacheCoins.end()) return false;       // <-- returns, never throws
    ...
  }
  ```
- **Description:**
  ```ts
  spendCoinSync(outpoint, moveout?) {
    const entry = this.cache.get(key);
    if (entry === undefined) {
      throw new Error(`Coin not in cache (must be pre-loaded): ${...}`);
    }
    ...
  }
  ```
  Used heavily on the hot path
  (`coreConnectBlockChecks`/`connect_block.ts:609`,
  `UTXOManager.spendOutput` at L1072-1080). Any path that calls
  `spendCoinSync` without first guaranteeing a preload converts a
  consensus-level rejection (`bad-txns-inputs-missingorspent`) into
  an unhandled throw. The full-validation path at L508-522 preloads
  first; the assume-valid path at L428-438 also preloads. The throw
  remains as a defense-in-depth guard but covers any future caller
  that forgets the preload.
- **Impact:** Aligns with the W145 BUG-7 finding — chain/state.ts's
  `connectBlock` does NOT call `validateBlock`/`validateTxBasic`
  before `coreConnectBlockChecks`; a duplicate-input tx would
  double-`spendCoinSync` and throw uncaught. The throw class is
  legitimate; the issue is that the cache layer makes the throw the
  default rather than the explicit assert.

---

### BUG-18 (P2): No `HaveInputs(tx)` helper — every caller open-codes the per-input HaveCoin loop

- **Severity:** P2 (code-duplication; minor correctness drift risk).
- **File:** `src/chain/utxo.ts` — no `HaveInputs` method.
- **Core ref:** `bitcoin-core/src/coins.cpp:329-339`:
  ```cpp
  bool CCoinsViewCache::HaveInputs(const CTransaction& tx) const {
    if (!tx.IsCoinBase()) {
      for (unsigned int i = 0; i < tx.vin.size(); i++) {
        if (!HaveCoin(tx.vin[i].prevout)) return false;
      }
    }
    return true;
  }
  ```
- **Description:** Bitcoin Core exposes a single helper for the
  "all inputs available" check used by mempool admission and
  `ConnectBlock`. Hotbuns has zero `HaveInputs` callers — every
  callsite (`connect_block.ts:401-407`, `mempool/accept.ts`, etc.)
  inlines its own loop, frequently with slight variations on what
  to return.
- **Impact:** Minor — but a fleet pattern: the absence of the
  centralised helper means every caller duplicates the loop and
  the error reporting (e.g. some callers report the missing
  outpoint; others just return `false`).

---

### BUG-19 (P1-CORRECTNESS): `UTXOManager.restoreUTXO` is a sync wrapper that bypasses the OK/UNCLEAN/FAILED tristate enforced by `applyInputUndo`

- **Severity:** P1 (defense-in-depth — sync path bypasses the
  W92 Core-faithful disconnect gate).
- **File:** `src/chain/utxo.ts:1167-1179`.
- **Core ref:** `bitcoin-core/src/validation.cpp:2149-2175`
  `ApplyTxInUndo`.
- **Description:** Hotbuns has BOTH `applyInputUndo` (async, returns
  DisconnectResult tristate per `state.ts:647-658`) AND a legacy sync
  `restoreUTXO` wrapper. The sync wrapper just calls `cache.addCoin(..., true)`
  with `possibleOverwrite=true` — no `HaveCoin` check, no metadata
  recovery, no fClean signal. Comment at L1162-1166 admits the gap:
  ```ts
  // Synchronous wrapper retained for backwards compat with call sites that
  // never read undo metadata that needed AccessByTxid recovery (i.e.
  // hotbuns-native undo data always has height>0).  New call sites should
  // prefer {@link applyInputUndo} which returns the OK/UNCLEAN/FAILED
  // tristate matching Bitcoin Core `ApplyTxInUndo`.
  ```
- **Excerpt**:
  ```ts
  restoreUTXO(txid: Buffer, vout: number, entry: UTXOEntry): void {
    const outpoint: OutPoint = { txid, vout };
    const coin: Coin = { ... };
    this.cache.addCoin(outpoint, coin, true);  // possibleOverwrite = true
  }
  ```
- **Impact:** Any current or future caller that uses `restoreUTXO`
  instead of `applyInputUndo` silently loses the
  `DISCONNECT_UNCLEAN`/`DISCONNECT_FAILED` propagation. The chain
  state can drift relative to the disconnected block undefined-behavior
  silently. **The W92 fix only covers one of two paths.**
  **Comment-as-confession archetype** (4th instance fleet-wide,
  matches rustoshi W141 + others).

---

### BUG-20 (P1-INTEROP): Hotbuns chainstate is NOT Core-loadable end-to-end (composite of BUG-1, BUG-2, BUG-3, BUG-4, BUG-5)

- **Severity:** P1 (composite).
- **File:** `src/storage/database.ts` + `src/chain/utxo.ts`.
- **Description:** Combining BUG-1 (bespoke value encoding), BUG-2
  (wrong prefix byte), BUG-3 (missing DB_BEST_BLOCK/DB_HEAD_BLOCKS),
  BUG-4 (uint32-LE vs VARINT vout), and BUG-5 (no obfuscate_key), a
  hotbuns chainstate directory is byte-disjoint from a Core
  chainstate at every layer. A `bitcoin-cli` opening a hotbuns
  `chainstate/` directory:
  1. Sees no `OBFUSCATE_KEY` entry → defaults to "no XOR" → reads
     garbage where Core would unxor.
  2. Seeks `DB_COIN = 'C' = 0x43` → finds no entries (hotbuns uses
     `0x75`).
  3. Reads `DB_BEST_BLOCK = 'B' = 0x42` → empty → falls back to
     `GetHeadBlocks()` → empty → returns zero hash → asserts on
     `assert(!hashBlock.IsNull())` in `CCoinsViewDB::BatchWrite`.
- **Impact:** The hotbuns `chainstate/` is structurally
  Core-incompatible. The earlier-cited "drop-in replacement"
  framing in the README is undermined. Cross-impl consistency tests
  (`test-suite/utxo_compare.py`) can only operate on the snapshot
  format (BUG-14), not the production format.

---

### BUG-21 (P3): `coinMemoryUsage = 48 + spkLen` — flat estimate, not the pool-allocator memusage Core tracks

- **Severity:** P3.
- **File:** `src/chain/utxo.ts:206-210`.
- **Core ref:** `bitcoin-core/src/coins.h:87-89`:
  ```cpp
  size_t DynamicMemoryUsage() const {
    return memusage::DynamicUsage(out.scriptPubKey);
  }
  ```
  Core uses the platform-specific `memusage::DynamicUsage` which
  accounts for `prevector` inlining (most scripts ≤ 28 bytes have
  ZERO dynamic memory because they fit in the inline buffer).
- **Description:** Hotbuns charges 48 bytes per Coin object plus the
  full scriptPubKey size, even though small scripts (≤ 28 bytes —
  the prevector inline cap) charge zero in Core. A P2WPKH coin (22
  bytes script) charges 48 + 22 = 70 in hotbuns vs 0 in Core. The
  dbcache budget therefore over-estimates the actual memory used,
  triggering premature flushes.
- **Impact:** Effective dbcache is smaller than the configured
  value. With 512 MiB nominal, a chain dominated by P2WPKH coins
  uses the cache at roughly half capacity before flushing.

---

### BUG-22 (P1-CORRECTNESS): `CoinsViewDB.batchWrite` updates `bestBlockHash` AFTER the LevelDB commit — but does not split into pre/post markers; a future multi-batch flush has no recovery primitive

- **Severity:** P1 (latent crash-consistency hazard).
- **File:** `src/chain/utxo.ts:293-337`.
- **Core ref:** `bitcoin-core/src/txdb.cpp:100-164` — three-phase
  commit via DB_BEST_BLOCK + DB_HEAD_BLOCKS markers, splitting on
  `batch_write_bytes`.
- **Description:** Hotbuns' `batchWrite` builds ONE LevelDB batch
  containing every coin op + the caller's chain-state op + any other
  extraOps. LevelDB guarantees atomicity for a single batch, so for
  any flush that fits in one batch, the invariant holds. **But:**
  - The `db.batchWrite` helper (`database.ts:584-605`) DOES split
    into chunks of 10k ops, written sequentially. Once a flush
    exceeds 10k ops (a moderate IBD batch), atomicity is gone.
  - There is no DB_HEAD_BLOCKS analogue to detect a partial
    multi-batch commit on restart.
- **Excerpt** (`src/storage/database.ts:584-605`):
  ```ts
  async batchWrite(ops: BatchOperation[], maxBatchSize: number = DEFAULT_MAX_BATCH_SIZE): Promise<void> {
    if (ops.length === 0) return;
    if (ops.length <= maxBatchSize) {
      await this.batch(ops);
      return;
    }
    for (let i = 0; i < ops.length; i += maxBatchSize) {
      const chunk = ops.slice(i, Math.min(i + maxBatchSize, ops.length));
      await this.batch(chunk);              // <-- per-chunk atomic; cross-chunk NOT
      await new Promise<void>(resolve => setTimeout(resolve, 0));
    }
  }
  ```
  Note `CoinsViewDB.batchWrite` calls `this.db.batch(ops)` directly
  (single-batch path, L333) — so today the issue is dormant. But the
  helper `db.batchWrite` exists with chunking and is one refactor
  away from being substituted in for the UTXO flush path.
- **Impact:** Today: works because UTXO flushes are issued through
  the single-batch path. Tomorrow: any chunking change (to address
  the IBD batch-size OOM risk noted in the file header comment)
  silently breaks crash consistency unless the head_blocks recovery
  primitive is also added. Latent landmine for a future
  performance refactor.

---

### BUG-23 (P3): Duplicate `serializeCoin`/`deserializeCoin` and `serializeUTXO`/`deserializeUTXO` in two files

- **Severity:** P3 (maintenance).
- **File:** `src/chain/utxo.ts:163-201` AND
  `src/storage/database.ts:151-201`. Both files define a
  near-identical "fixed prefix + varint script" coin serializer with
  the same byte layout but slightly different types
  (`Coin` vs `UTXOEntry`).
- **Description:** Two encoders with the same byte semantics live in
  two files. Any consensus-affecting change (e.g. adding a flag bit,
  changing varint width) must be made in two places. The
  hotbuns-bespoke encoding from BUG-1 is duplicated.
- **Impact:** A future "fix" to one of the encoders that misses
  the other introduces a self-incompatible read/write asymmetry —
  classic landmine.

---

## Fleet patterns observed

- **Two-pipeline guard** (W124/W125): production DB encoder vs
  snapshot encoder for the same logical Coin (BUG-14). 15th distinct
  extension of the pattern fleet-wide.
- **Comment-as-confession** (W141 archetype): two instances in this
  file — `accessByTxid`'s `n >= 8` short-circuit (BUG-15) and the
  `restoreUTXO` sync-wrapper bypassing the W92 tristate (BUG-19).
- **Dead/legacy parallel pipeline**: `UTXOManager` is a legacy
  wrapper around `CoinsViewCache` (utxo.ts:980-1348, 369 LOC). The
  `restoreUTXO` sync helper is only there for "backwards compat with
  call sites that never read undo metadata that needed AccessByTxid
  recovery". Modern callers should use `applyInputUndo`. This
  matches the fleet "OOP wrapper + flat DB path coexist" pattern
  (W130/W131 4-impl confirmed).
- **Carry-forward re-anchor** (W140 archetype): BUG-14's two
  encoders is an even more clear-cut instance — the snapshot path
  was added later (W138 wave) and chose the correct Core-compatible
  format, but the production path was never re-anchored to match.
- **Composite-divergence**: BUG-20 — five separate small divergences
  (prefix byte, value layout, vout encoding, no obfuscate_key, no
  head_blocks) compose into "hotbuns chainstate is not Core-loadable
  end-to-end".

## Severity rollup

- P0-CDIV: 1 (BUG-14)
- P0-CORRECTNESS / P0-FUNCTIONAL: 2 (BUG-7, BUG-15)
- P1: 11 (BUG-1, BUG-2, BUG-3, BUG-4, BUG-5, BUG-6, BUG-9, BUG-19,
  BUG-20, BUG-22; also note BUG-17 borderline)
- P2: 6 (BUG-8, BUG-10, BUG-12, BUG-16, BUG-17, BUG-18)
- P3: 3 (BUG-11, BUG-13, BUG-21, BUG-23)

23 BUGs total.
