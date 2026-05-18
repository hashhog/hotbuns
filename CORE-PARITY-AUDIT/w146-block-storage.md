# W146 — Block storage (blkXXXXX.dat + revXXXXX.dat + block-index leveldb) — hotbuns

**Impl:** hotbuns (TypeScript / Bun)
**Date:** 2026-05-18
**Wave:** W146 (4-of-4 quad-wave — IBD & storage theme)
**Status:** DISCOVERY — 23 BUGS / 8 behaviors
**Tests:** assertion-only, no production code changes.
**No production code changes in this wave.**

## References

### Bitcoin Core
- `bitcoin-core/src/node/blockstorage.h:118-129` — pre-allocation chunk sizes
  and storage header bytes:
  ```
  static const unsigned int BLOCKFILE_CHUNK_SIZE = 0x1000000; // 16 MiB
  static const unsigned int UNDOFILE_CHUNK_SIZE  = 0x100000;  //  1 MiB
  static const unsigned int MAX_BLOCKFILE_SIZE   = 0x8000000; // 128 MiB
  static constexpr uint32_t STORAGE_HEADER_BYTES{ /*MessageStart=4*/ + sizeof(unsigned int) /*=4*/ }; // 8
  static constexpr uint32_t UNDO_DATA_DISK_OVERHEAD{ STORAGE_HEADER_BYTES + uint256::size() }; // 8+32 = 40
  ```
- `bitcoin-core/src/node/blockstorage.cpp:58-65` — block-index leveldb prefixes:
  ```
  static constexpr uint8_t DB_BLOCK_FILES{'f'};       // 0x66
  static constexpr uint8_t DB_BLOCK_INDEX{'b'};       // 0x62
  static constexpr uint8_t DB_FLAG{'F'};              // 0x46
  static constexpr uint8_t DB_REINDEX_FLAG{'R'};      // 0x52
  static constexpr uint8_t DB_LAST_BLOCK{'l'};        // 0x6c
  ```
  And in `index/txindex.cpp:31`: `constexpr uint8_t DB_TXINDEX{'t'};` (0x74).
  And in `txdb.cpp:23-27`: `DB_COIN{'C'}=0x43`, `DB_BEST_BLOCK{'B'}=0x42`,
  `DB_HEAD_BLOCKS{'H'}=0x48`, `DB_COINS{'c'}=0x63` (deprecated).
- `bitcoin-core/src/node/blockstorage.h:56-95` — `CBlockFileInfo` serialized via
  `READWRITE(VARINT(obj.nBlocks))…` (Core's VARINT, NOT CompactSize).
- `bitcoin-core/src/chain.h:317-360` — `CDiskBlockIndex` serialized via VARINT,
  with conditional `nFile/nDataPos/nUndoPos` only when `BLOCK_HAVE_DATA |
  BLOCK_HAVE_UNDO` bits are set. **Variable-length** record.
- `bitcoin-core/src/node/blockstorage.cpp:1134-1165` — `BlockManager::WriteBlock`:
  `FindNextBlockPos` allocates space, then `BufferedWriter` writes
  `MessageStart() << block_size` (8 bytes = STORAGE_HEADER_BYTES), then the
  serialized block. `pos.nPos` is set to point *after* the 8-byte header
  (block data start). Closes file with `file.fclose()` — flushes
  `BufferedWriter` to disk; the rotation path calls `FlushBlockFile` which
  triggers fsync via `m_block_file_seq.Flush(...)`.
- `bitcoin-core/src/node/blockstorage.cpp:833-921` — `FindNextBlockPos`:
  - `LOCK(cs_LastBlockFile)` (critical-section serialisation).
  - When `m_blockfile_info[nFile].nSize + nAddSize >= max_blockfile_size`,
    rotate to `MaxBlockfileNum() + 1` and call `FlushBlockFile(last_blockfile,
    fFinalize=true, finalize_undo)`.
  - `m_block_file_seq.Allocate(pos, nAddSize, out_of_space)` — chunked
    pre-allocation via `posix_fallocate` (linux).
- `bitcoin-core/src/node/blockstorage.cpp:945-1034` — `FindUndoPos` /
  `WriteBlockUndo`:
  - Undo file: `BufferedWriter << MessageStart() << blockundo_size << blockundo
    << hasher.GetHash();` — **identical 8-byte STORAGE_HEADER_BYTES**, then
    serialized undo, then 32-byte checksum (40 bytes overhead).
  - Checksum is `HashWriter{} << prev_block_hash << blockundo` (double-SHA256).
- `bitcoin-core/src/node/blockstorage.cpp:1077-1132` — `ReadBlock` /
  `ReadRawBlock`:
  - Opens at `{pos.nFile, pos.nPos - STORAGE_HEADER_BYTES}`, reads
    `blk_start (4) >> blk_size (4)`, validates magic against
    `GetParams().MessageStart()`, then `blk_size > MAX_SIZE` rejects.
  - Magic mismatch → return `Unexpected{ReadRawError::IO}` (file corruption).
- `bitcoin-core/src/kernel/chainparams.cpp` — magic numbers per network:
  - mainnet: `0xF9, 0xBE, 0xB4, 0xD9`  (uint32_LE = 0xD9B4BEF9)
  - testnet3: `0x0B, 0x11, 0x09, 0x07` (= 0x0709110B)
  - testnet4: `0x1c, 0x16, 0x3f, 0x28` (= 0x283F161C)
  - signet: `0x0a, 0x03, 0xcf, 0x40`    (= 0x40CF030A)
  - regtest: `0xFA, 0xBF, 0xB5, 0xDA`   (= 0xDAB5BFFA)

## hotbuns files in scope

- `src/storage/blockfile.ts` — `BlockFileManager`, `BlockStore`, helpers for
  `blkXXXXX.dat`. **649 LOC.** Constants match Core (`MAX_BLOCKFILE_SIZE =
  0x8000000`, `BLOCKFILE_CHUNK_SIZE = 0x1000000`, `STORAGE_HEADER_BYTES = 8`).
- `src/storage/undo.ts` — `UndoFileManager`, `UndoManager`, serializers for
  `revXXXXX.dat`. **466 LOC.**
- `src/storage/database.ts` — `ChainDB` over `ClassicLevel` (LevelDB). Defines
  prefix bytes including `BLOCK_FILES`/`LAST_BLOCK_FILE`/`BLOCK_POS` (0x66/0x6c/
  0x70) but **block bytes are written to LevelDB under the `BLOCK_DATA` prefix
  (0x64, `'d'`)**, NOT to flat files. **835 LOC.**
- `src/storage/pruning.ts` — `PruneManager`. Wired via
  `BlockSync.setPruneManager(...)` (cli.ts:1712, sync/blocks.ts:457) but the
  underlying `BlockFileInfo` it scans is never populated (see BUG-1).
- `src/storage/indexes.ts` — `TxIndex`, `BlockFilterIndex`, `CoinStatsIndex`.
- `src/chain/state.ts:362-419` — `connectBlock` production path: calls
  `db.putUndoData(blockHash, undoData)` → `db.putBlock(blockHash, rawBlock)` →
  `db.putBlockIndex(blockHash, record)`. **NEVER calls `BlockStore`/
  `BlockFileManager`/`UndoFileManager`.**
- `src/sync/blocks.ts:347-457` — block sync path. Same pattern as above.

## Bug list

### BUG-1 — entire `blkXXXXX.dat` + `revXXXXX.dat` machinery is dead code; production stores raw blocks in LevelDB

**Severity:** P0
**File:** hotbuns:src/storage/blockfile.ts:186-573 (BlockFileManager, 387 LOC)
         hotbuns:src/storage/blockfile.ts:579-649 (BlockStore, 70 LOC)
         hotbuns:src/storage/undo.ts:242-398 (UndoFileManager, 156 LOC)
         hotbuns:src/storage/undo.ts:405-463 (UndoManager, 58 LOC)
**Core ref:** bitcoin-core/src/node/blockstorage.cpp:1134-1165 (WriteBlock),
          1077-1081 (ReadBlock), 967-1034 (WriteBlockUndo)
**Description:** The 671 LOC of `BlockFileManager`, `BlockStore`,
`UndoFileManager`, `UndoManager` were architected to mirror Core's
`blkXXXXX.dat`/`revXXXXX.dat` layout with `[magic(4)][size(4)][block]` framing,
128 MiB rotation, 16 MiB pre-allocation, and SHA256d checksum-verified undo.
**Grep confirms ZERO imports from any non-test, non-self file.** The
production connect path (`chain/state.ts:374-393`) and sync path
(`sync/blocks.ts`) both reach for `db.putBlock(blockHash, rawBlock)` and
`db.putUndoData(blockHash, undoData)` — bare LevelDB `put` under prefix `'d'`
(0x64) and `'r'` (0x72). The block bytes are NOT stored under prefix `'b'`
(0x62, which the code reserves for the index record). All the flat-file
infrastructure is unreachable.
**Excerpt (chain/state.ts:374-393):**
```
const undoData = serializeUndoData(spentOutputs);
await this.db.putUndoData(blockHash, undoData);
await this.utxo.flush();
const rawBlock = serializeBlock(block);
await this.db.putBlock(blockHash, rawBlock);    // ← 'd' prefix in LevelDB
…
await this.db.putBlockIndex(blockHash, { … status, dataPos: 1, … });
```
**Impact:** Fleet-pattern *dead-module*: ~700 LOC of carefully-written Core-
mirroring storage code that ships in the binary but never runs. Real
production storage is an opaque LevelDB blob (no flat files, no pruning of
old blocks possible — see BUG-12, no fork-aware file layout, no compatibility
with Core's blocks dir).

### BUG-2 — no fsync / fdatasync anywhere in storage path; data durability rests on LevelDB WAL flushes only

**Severity:** P1
**File:** hotbuns:src/storage/blockfile.ts:389-435 (writeBlock)
         hotbuns:src/storage/undo.ts:316-355 (writeBlockUndo)
         hotbuns:src/storage/database.ts (entire file)
**Core ref:** bitcoin-core/src/node/blockstorage.cpp:732-769 (FlushBlockFile /
          FlushUndoFile both call `m_*_file_seq.Flush(pos, finalize)` →
          `FileCommit` → `fdatasync`/`FlushFileBuffers`)
          bitcoin-core/src/node/blockstorage.cpp:1158-1160 (WriteBlock calls
          `file.fclose()` and treats non-zero return as fatal)
**Description:** `grep -n "fsync\|fdatasync\|posix_fallocate\|sync()"
src/storage/*.ts` returns *zero* hits. The dead `BlockFileManager.writeBlock`
calls `Bun.write(filePath, newData)` (which on Bun returns when the data is
queued to the kernel, NOT after an fsync). `Bun.write` does not invoke
`fdatasync`. There is no `FlushBlockFile` / `FlushUndoFile` equivalent. Even
the production LevelDB path inherits LevelDB's default `sync: false` write
option (database.ts:557-574 builds the batch with no sync flag — LevelDB
only fsyncs the WAL when `sync: true` is passed).
**Excerpt (blockfile.ts:432):**
```
await Bun.write(filePath, newData);
return pos;                          // ← no fsync, no FlushBlockFile
```
**Impact:** Power loss / kernel panic between `db.put` returning and the
LevelDB MANIFEST sync is unrecoverable: hotbuns has no recovery code path
(no reindex flag — BUG-13) and no replay mechanism. The production path
masks this somewhat (LevelDB's own WAL is on disk) but every block-index
update is one async `await` away from being un-fsync'd.

### BUG-3 — `BlockFileManager.writeBlock` reads the entire blkXXXXX.dat (up to 128 MiB) and rewrites it on every block

**Severity:** P1
**File:** hotbuns:src/storage/blockfile.ts:406-432
**Core ref:** bitcoin-core/src/node/blockstorage.cpp:1142-1156 (BufferedWriter
          appends at pre-allocated position)
**Description:** `writeBlock` opens the existing blk file with
`Bun.file(filePath)`, reads the entire file into a Buffer
(`Buffer.from(await file.arrayBuffer())`), copies it into a new Buffer,
appends the new block at the computed offset, then writes the entire Buffer
back with `Bun.write(filePath, newData)`. On a near-full 128 MiB file this
copies and rewrites ~128 MiB to write a 4 KB header + 1 MB block — an
~30x write amplification.
**Excerpt (blockfile.ts:406-432):**
```
const file = Bun.file(filePath);
let existingData = Buffer.alloc(0);
if (await file.exists()) {
  const arrayBuffer = await file.arrayBuffer();
  existingData = Buffer.from(arrayBuffer);    // ← reads 0..128 MiB!
}
…
if (existingData.length >= requiredSize) {
  newData = existingData;
} else {
  newData = Buffer.alloc(requiredSize);
  existingData.copy(newData, 0);
}
header.copy(newData, headerPos);
rawBlock.copy(newData, headerPos + STORAGE_HEADER_BYTES);
await Bun.write(filePath, newData);            // ← rewrites 0..128 MiB!
```
**Impact:** Were this code path live (it is not — BUG-1), IBD would be
O(N²) in block-file size — at h=300k, writing 16 KiB×288 → 1.2 GiB
amplification per block. Bitcoin Core uses `BufferedWriter` over an
`AutoFile` opened in append mode + chunked pre-allocation via
`posix_fallocate`. This is also the same pre-allocation pattern in
`maybePreAllocate` (blockfile.ts:362-374) — which *also* reads-modifies-
writes the entire file.

### BUG-4 — `BlockFileManager.maybePreAllocate` reads & rewrites whole file to extend by zeros (not posix_fallocate)

**Severity:** P1
**File:** hotbuns:src/storage/blockfile.ts:331-383
**Core ref:** bitcoin-core/src/util/fs_helpers.cpp (AllocateFileRange →
          posix_fallocate)
**Description:** `maybePreAllocate` computes the new pre-allocation target,
reads the existing file in full, concatenates a zero-filled Buffer onto the
existing bytes, and re-writes the whole file. Comment at line 362-363
acknowledges "Bun doesn't have truncate, so we append zeros" — but Bun does
have `Bun.file(path).writer()` for streaming append, and Node's
`fs.ftruncate`/`fs.fallocate` (via `node:fs`) are reachable from Bun. The
code path uses the most expensive option.
**Excerpt (blockfile.ts:360-374):**
```
if (newPreAllocSize > existingSize) {
  const allocSize = newPreAllocSize - existingSize;
  if (allocSize > 0) {
    let existing = Buffer.alloc(0);
    if (await file.exists()) {
      existing = Buffer.from(await file.arrayBuffer());
    }
    const newData = Buffer.concat([
      existing,
      Buffer.alloc(allocSize, 0),
    ]);
    await Bun.write(filePath, newData);
  }
}
```
**Impact:** Same O(N²) characteristics as BUG-3. Also dead code (BUG-1).

### BUG-5 — `BlockFileInfo` serialized with **CompactSize**, not Core's **VARINT** — wire-incompatible block-index leveldb format

**Severity:** P0-CDIV (within hotbuns-internal protocol, but format
        explicitly claims Core parity)
**File:** hotbuns:src/storage/blockfile.ts:98-124 (serializeBlockFileInfo /
         deserializeBlockFileInfo) — uses BufferWriter.writeVarInt
         hotbuns:src/wire/serialization.ts:184-217 (writeVarInt is CompactSize)
**Core ref:** bitcoin-core/src/node/blockstorage.h:67-76 (SERIALIZE_METHODS
          uses VARINT macro, not CompactSize)
          bitcoin-core/src/serialize.h:424-460 (WriteVarInt is the
          7-bit-per-byte stop-bit format, totally different on the wire)
**Description:** Core's `CBlockFileInfo` uses `READWRITE(VARINT(obj.nBlocks))`
— this is the *VARINT* extended encoding (7-bit groups with a stop bit), not
*CompactSize* (1/3/5/9-byte length prefix). Hotbuns's `writeVarInt` is
*CompactSize*. Same byte sequence decodes to different values. Example:
`nBlocks=300`. Core VARINT writes `[0x81, 0x2C]` (2 bytes). Hotbuns
`writeVarInt(300)` writes `[0xfd, 0x2c, 0x01]` (3 bytes, CompactSize). The
header file comment at `blockfile.ts:9` claims compatibility with Core's
`blockstorage.cpp`.
**Excerpt (blockfile.ts:98-107):**
```
export function serializeBlockFileInfo(info: BlockFileInfo): Buffer {
  const writer = new BufferWriter();
  writer.writeVarInt(info.nBlocks);         // ← CompactSize, Core uses VARINT
  writer.writeVarInt(info.nSize);
  …
}
```
**Impact:** A `blocks/index/` LevelDB written by hotbuns and read by Core
(or vice versa) cannot exchange CBlockFileInfo records. This is a
silent-failure interop break — Core would deserialize the multi-byte
CompactSize prefix as several VARINT bytes and emerge with wildly different
field values, potentially asserting in `LoadBlockIndexDB`.

### BUG-6 — `BlockIndexRecord` serialized as **fixed 96-byte struct**, not Core's variable-length VARINT `CDiskBlockIndex`

**Severity:** P0-CDIV (format-incompatible block-index leveldb)
**File:** hotbuns:src/storage/database.ts:122-146
         (serializeBlockIndex / deserializeBlockIndex)
**Core ref:** bitcoin-core/src/chain.h:317-360 (CDiskBlockIndex::SERIALIZE_METHODS)
**Description:** Hotbuns uses `Buffer.allocUnsafe(96)` with fixed layout:
`height(uint32 LE) + header(80) + nTx(uint32 LE) + status(uint32 LE) +
dataPos(uint32 LE) = 96 bytes`. Core's `CDiskBlockIndex`:
```
VARINT(DUMMY_VERSION) || VARINT(nHeight) || VARINT(nStatus) || VARINT(nTx) ||
[VARINT(nFile) if (status & (HAVE_DATA|HAVE_UNDO))] ||
[VARINT(nDataPos) if (status & HAVE_DATA)] ||
[VARINT(nUndoPos) if (status & HAVE_UNDO)] ||
i32(nVersion) || hashPrev(32) || hashMerkleRoot(32) || u32(nTime) ||
u32(nBits) || u32(nNonce)
```
Hotbuns has no `nFile`, no `nUndoPos`, and the header is stored as 80
serialized bytes rather than the individual `nVersion/hashPrev/…` fields.
The `dataPos: 1` (database.ts:131, 392) is used as a 1-bit boolean flag —
Core stores a real byte offset.
**Excerpt (database.ts:124-133):**
```
function serializeBlockIndex(record: BlockIndexRecord): Buffer {
  // Fixed layout: height(4) + header(80) + nTx(4) + status(4) + dataPos(4) = 96
  const buf = Buffer.allocUnsafe(96);
  buf.writeUInt32LE(record.height, 0);
  record.header.copy(buf, 4);
  buf.writeUInt32LE(record.nTx, 84);
  buf.writeUInt32LE(record.status, 88);
  buf.writeUInt32LE(record.dataPos, 92);
  return buf;
}
```
**Impact:** Same wire-format incompatibility as BUG-5. Compounds: a Core
blocks/index dir cannot be loaded by hotbuns and vice versa.

### BUG-7 — LevelDB prefix scheme diverges from Core's `chainstate/` scheme

**Severity:** P1
**File:** hotbuns:src/storage/database.ts:22-35 (DBPrefix enum)
**Core ref:** bitcoin-core/src/txdb.cpp:23-27 (DB_COIN='C', DB_BEST_BLOCK='B',
          DB_HEAD_BLOCKS='H', DB_COINS='c' legacy)
          bitcoin-core/src/node/blockstorage.cpp:58-65 (DB_BLOCK_FILES='f',
          DB_BLOCK_INDEX='b', DB_FLAG='F', DB_REINDEX_FLAG='R',
          DB_LAST_BLOCK='l')
**Description:**
| hotbuns prefix       | byte | hotbuns purpose             | Core prefix    | Core purpose            |
|----------------------|------|-----------------------------|----------------|-------------------------|
| `BLOCK_INDEX = 'b'`  | 0x62 | block hash → BlockIndexRec  | `'b'` DB_BLOCK_INDEX | block hash → CDiskBlockIndex |
| `BLOCK_DATA = 'd'`   | 0x64 | block hash → raw block bytes| (none)         | block bytes live in blk*.dat |
| `TX_INDEX = 't'`     | 0x74 | txid → TxIndexEntry         | `'t'` DB_TXINDEX | txid → CDiskTxPos      |
| `UTXO = 'u'`         | 0x75 | outpoint → UTXOEntry        | `'C'` DB_COIN  | COutPoint → Coin       |
| `CHAIN_STATE = 's'`  | 0x73 | (singleton key)             | `'B'` DB_BEST_BLOCK + `'H'` DB_HEAD_BLOCKS | hashBestBlock + 2-phase head pointers |
| `HEADER = 'h'`       | 0x68 | height(BE u32) → block hash | (none, in-memory CChain) | — |
| `UNDO = 'r'`         | 0x72 | block hash → undo bytes     | (none)         | undo lives in rev*.dat |
| `BLOCK_FILES = 'f'`  | 0x66 | file num → CBlockFileInfo   | `'f'` DB_BLOCK_FILES | same |
| `LAST_BLOCK_FILE='l'`| 0x6c | (singleton)                 | `'l'` DB_LAST_BLOCK | same |
| `BLOCK_POS = 'p'`    | 0x70 | block hash → file position  | (none, redundant with block-index nFile/nDataPos) | — |
| `PRUNE_STATE = 'P'`  | 0x50 | (singleton)                 | (none)         | — |
| `CHAIN_WORK = 'w'`   | 0x77 | block hash → chainwork u256 | (none, stored on CBlockIndex) | — |

`UTXO='u'` (0x75) collides with what Core calls `'C'` (0x43) for coin records.
`BLOCK_DATA='d'` (0x64) is an entirely new prefix because hotbuns stuffs block
bytes into the same LevelDB. **Critically**, hotbuns has no `DB_BEST_BLOCK`
('B') or `DB_HEAD_BLOCKS` ('H') — the **two-phase flush** that Core uses to
recover from crashes mid-UTXO-flush (txdb.cpp:125-159) is **not present**.
The chain state is a single `CHAIN_STATE` blob that goes from old-bestblock
straight to new-bestblock with no intermediate "head_blocks" array.
**Impact:** (i) format incompatibility with Core's `chainstate/` layout —
hotbuns CANNOT migrate to/from a Core node's data dir; (ii) **no crash-safe
UTXO commit protocol** (compare W104 / W128-ish patterns elsewhere) — a
crash during `flush()` can leave the UTXO set inconsistent with no recovery
landmark.

### BUG-8 — no DB_REINDEX_FLAG (`'R'`) — `-reindex` CLI option does not exist

**Severity:** P1
**File:** hotbuns:src/storage/database.ts (entire enum DBPrefix has no
         R/reindex entry); confirmed by
         `grep -rn "reindex\|REINDEX" src/storage src/chain src/cli` → 0 hits
**Core ref:** bitcoin-core/src/node/blockstorage.cpp:74-84
          (WriteReindexing / ReadReindexing on `DB_REINDEX_FLAG = 'R'`)
**Description:** Core's `'R'` flag is the canonical "we crashed mid-rebuild,
finish the reindex pass on next start" landmark. It is also the recovery
mechanism Core uses when the operator passes `-reindex` after a torn write
(bad-magic block file). Hotbuns has neither the flag nor a reindex command.
A torn write to LevelDB (split MANIFEST) leaves hotbuns with no automatic
recovery; the only option is `rm -rf` the data dir.
**Impact:** No recovery story from a torn write. Compounds BUG-2 (no fsync)
— power loss + no reindex = data dir unrecoverable.

### BUG-9 — no `DB_FLAG` (`'F'`) namespace — soft-fork activation flags + index-enabled flags un-recordable

**Severity:** P2
**File:** hotbuns:src/storage/database.ts:22-35 (no FLAG prefix)
**Core ref:** bitcoin-core/src/node/blockstorage.cpp:60 (DB_FLAG='F'),
          105-117 (WriteFlag/ReadFlag); src/init.cpp uses it for
          `txindex`/`coinstatsindex`/`blockfilterindex` enable-state.
**Description:** Core persists per-startup configuration ("did the user
enable txindex on this datadir?") under the `'F'` prefix so a startup that
omits `-txindex` from the CLI does not silently switch the index off (which
would corrupt by orphaning index entries). Hotbuns has no analogue —
`indexes.ts` constructs its objects unconditionally from CLI flags with
no persistence check.
**Impact:** If a user runs hotbuns once with `-blockfilterindex=1` and once
without, the index becomes silently stale (the BlockFilterIndex skips
writing for blocks during the second run but its `FILTER_TIP` still points
mid-chain). Recovery requires `rm -rf` of the data dir.

### BUG-10 — `BlockFileManager.scanExistingFiles` silently swallows ANY stat error → boots with wrong currentFileNum/Size

**Severity:** P1
**File:** hotbuns:src/storage/blockfile.ts:243-270
**Core ref:** bitcoin-core/src/node/blockstorage.cpp:1041-1059 (block load
          fails loudly; sets BLOCK_FAILED_VALID on read errors)
**Description:** The scan loop reads `stat(filePath)` inside a
`try { … } catch {}` with empty handler (line 261-263), and the *outer*
try around the glob is identical (line 266-270). On a filesystem permission
error mid-scan, `currentFileNum` stays at 0 and `currentFileSize` stays at 0
— so the next `writeBlock` clobbers blk00000.dat at offset 0 with the
8-byte header, **silently truncating** any previously-written data on a
non-empty file. The two `catch` blocks have no logging.
**Excerpt (blockfile.ts:261-270):**
```
        } catch {
          // File doesn't exist or can't be read     ← swallows ALL errors
        }
      }
    }
  } catch {
    // Directory doesn't exist yet, use defaults    ← swallows ALL errors
    this.currentFileNum = 0;
    this.currentFileSize = 0;
  }
}
```
**Impact:** silent data loss on transient I/O errors (NFS, container mounts,
EACCES on rotated logs). Pattern: "swallow-error-with-zero-default" — a
known fleet-wide anti-pattern that has shown up at least 3 times in prior
audits (W100, W128, W141).

### BUG-11 — `readBlock` loads the entire blkXXXXX.dat (≤ 128 MiB) into memory just to read one block

**Severity:** P1
**File:** hotbuns:src/storage/blockfile.ts:441-487
**Core ref:** bitcoin-core/src/node/blockstorage.cpp:1083-1132 (ReadRawBlock
          opens AutoFile, reads header, seeks, reads only `blk_size` bytes)
**Description:** `readBlock` does `Buffer.from(await file.arrayBuffer())`
→ pulls the ENTIRE file into RAM, then `subarray(pos.pos, blockEnd)` to
extract one block. On a 128 MiB blk file this is a 128 MiB allocation +
copy for every block read (RPC `getblock`, P2P serve-block, reorg
disconnect). Bun supports `Bun.file(path).slice(offset, end)` for ranged
reads — not used.
**Excerpt (blockfile.ts:451):**
```
const fileData = Buffer.from(await file.arrayBuffer());   // ← 128 MiB load
…
return fileData.subarray(pos.pos, blockEnd);              // ← one block out
```
**Impact:** RPC `getblock` over a fat (~16 MiB) Core-format block balloons
peak RSS by 128 MiB per concurrent caller, 30x amplification on the
1-MiB-block case. Latent because dead (BUG-1), but the same anti-pattern
is reachable via `UndoFileManager.readBlockUndo` (undo.ts:372) which IS
intended for production use.

### BUG-12 — `PruneManager` is wired but the underlying `BlockFileInfo` map is permanently empty → pruning is a no-op

**Severity:** P0
**File:** hotbuns:src/storage/pruning.ts:95-113 (loadBlockFileInfo)
         hotbuns:src/storage/pruning.ts:240-295 (findFilesToPrune)
         hotbuns:src/cli/cli.ts:1499-1519 (PruneManager construction)
         hotbuns:src/sync/blocks.ts:457 (setPruneManager hookup)
**Core ref:** bitcoin-core/src/node/blockstorage.cpp:793-815
          (CalculateCurrentUsage iterates `m_blockfile_info` populated by
          WriteBlock); bitcoin-core/src/validation.cpp::FindFilesToPruneManual.
**Description:** `PruneManager.loadBlockFileInfo` reads from
`db.getLastBlockFile()` + `db.getBlockFileInfo(i)` — both LevelDB prefixes
`'l'` and `'f'`. **NOTHING in the codebase ever WRITES those keys** (grep
for `putBlockFileInfo` / `putLastBlockFile` finds only `PruneManager.update
BlockFileInfo` itself + the dead `BlockFileManager`). The map is always
empty. `findFilesToPrune` (line 270) iterates `this.blockFileInfo.keys()`
— always empty — and returns an empty set. `maybePrune` (line 349) and the
`pruneblockchain` RPC (rpc/server.ts:5754) return `filesPruned: 0` every
time. Block data accumulates in LevelDB and is **never deleted**.
**Excerpt (pruning.ts:240-295, abridged):**
```
async findFilesToPrune(chainHeight: number): Promise<Set<number>> {
  const setFilesToPrune = new Set<number>();
  if (!this.isAutomaticPruning() || chainHeight < 0) return setFilesToPrune;
  const target = Math.max(MIN_PRUNE_TARGET, this.pruneTarget);
  const lastBlockCanPrune = chainHeight - MIN_BLOCKS_TO_KEEP;
  …
  let currentUsage = this.calculateCurrentUsage();   // ← always 0
  if (currentUsage + buffer < target) {              // ← always true
    return setFilesToPrune;                          // ← always empty
  }
  …
}
```
**Impact:** `-prune=N` CLI option accepted but does NOTHING. Disk fills with
block data + undo data, eventually causing ENOSPC at LevelDB compaction.
`pruneblockchain` RPC returns 0 every time but does not error — operator
has no signal that pruning is broken. This is the strongest production-
visible consequence of BUG-1.

### BUG-13 — `revXXXXX.dat` undo file header is `[size(4)]` only, not Core's `[magic(4)][size(4)]` (STORAGE_HEADER_BYTES)

**Severity:** P2 (dead code; would be P0-CDIV if live)
**File:** hotbuns:src/storage/undo.ts:337-340 (writeBlockUndo)
         hotbuns:src/storage/undo.ts:379 (readBlockUndo)
**Core ref:** bitcoin-core/src/node/blockstorage.cpp:991-999 (WriteBlockUndo
          writes `fileout << GetParams().MessageStart() << blockundo_size`
          = STORAGE_HEADER_BYTES = 8 bytes)
**Description:** Core's `revXXXXX.dat` framing is identical to `blkXXXXX.dat`
framing: 4-byte network magic + 4-byte size. Hotbuns writes only the size
(4 bytes), no magic. A corrupted/truncated file cannot be detected by magic
mismatch on read.
**Excerpt (undo.ts:337-340):**
```
// Write header: [data length (4 bytes)] [data]
const header = Buffer.alloc(4);
header.writeUInt32LE(dataWithChecksum.length, 0);  // ← no magic
```
**Impact:** Were the file path live, a torn write to a rev file would be
detected only by the inner SHA256d checksum (which is correct — see
undo.ts:174-194). The outer magic-mismatch corruption signal is missing.
Cannot interop with Core's `revXXXXX.dat`.

### BUG-14 — undo `STORAGE_HEADER_BYTES` constant duplicated and divergent: blockfile.ts says 8, undo.ts uses 4

**Severity:** P2
**File:** hotbuns:src/storage/blockfile.ts:23 (STORAGE_HEADER_BYTES = 8)
         hotbuns:src/storage/undo.ts:338 (hard-coded `4`)
**Core ref:** bitcoin-core/src/node/blockstorage.h:128-129
          (UNDO_DATA_DISK_OVERHEAD = STORAGE_HEADER_BYTES + uint256::size())
**Description:** Both files frame data with a length prefix, but the
constant is only exported from `blockfile.ts`. `undo.ts` open-codes
`Buffer.alloc(4)` for the header (line 338) with no reference to the shared
constant. Even setting BUG-13 aside, the **two implementations diverge**:
blockfile uses 8 (magic + size), undo uses 4 (size only). Symptom of the
two paths being authored separately and never reconciled.
**Impact:** Cosmetic, but compounds the broader picture: the storage layer
is a copy-paste from a Core summary that nobody finished wiring up.

### BUG-15 — `BlockPosRecord.undoFileNum / undoPos` are typed `int32` (signed) — sentinel value -1 cannot be persisted as uint32

**Severity:** P2
**File:** hotbuns:src/storage/blockfile.ts:130-164 (BlockPosRecord)
**Core ref:** bitcoin-core/src/chain.h:188-201 (FlatFilePos uses int nFile,
          unsigned int nPos)
**Description:** The comment at line 138 says "File number containing undo
data (-1 if none)" and "Byte offset of undo data (-1 if none)" — sentinel
values. Both fields are serialized with `writeInt32LE` which CAN encode -1
as `0xFFFFFFFF`, **but** the dataPos / fileNum / pos fields above are
`writeUInt32LE` — mixing signedness in adjacent fields is a latent footgun
when this record is copied to disk and re-read on a different machine /
language: a 1-bit error in any other field shifts the layout under the
mixed-sign reader.
**Excerpt (blockfile.ts:144-164):**
```
export function serializeBlockPosRecord(record: BlockPosRecord): Buffer {
  const writer = new BufferWriter();
  writer.writeUInt32LE(record.fileNum);
  writer.writeUInt32LE(record.dataPos);
  writer.writeInt32LE(record.undoFileNum);    // ← int32, sentinel -1
  writer.writeInt32LE(record.undoPos);        // ← int32, sentinel -1
  return writer.toBuffer();
}
```
**Impact:** Latent. Core uses an absent-marker (FlatFilePos::IsNull → both
fields zero) rather than -1; the hotbuns convention is non-standard.

### BUG-16 — `BlockFileInfo.nTimeFirst` initial value is the all-zero `createEmptyBlockFileInfo()`, then `updateBlockFileInfo` correctly sets it — but only because `nBlocks === 0` is checked; if `BlockFileInfo` is loaded from DB with `nBlocks > 0` and updated, the `nTimeFirst < timestamp` check is wrong-direction

**Severity:** P2
**File:** hotbuns:src/storage/blockfile.ts:75-93 (updateBlockFileInfo)
**Core ref:** bitcoin-core/src/node/blockstorage.h:82-94 (AddBlock — uses
          `nHeightFirst > nHeightIn` for monotone decrease)
**Description:** Core's `AddBlock` says `if (nBlocks == 0 || nHeightFirst >
nHeightIn) nHeightFirst = nHeightIn;` — the `>` test makes nHeightFirst the
*minimum* over the file. Hotbuns line 80 says
`if (info.nBlocks === 0 || height < info.nHeightFirst)` — semantically
correct (height < first ⇒ update first), but line 83-85 is again `timestamp
< info.nTimeFirst` — Core says `nTimeFirst > nTimeIn`. Functionally
equivalent (a < b ⇔ b > a), but the source-code review trail diverges from
Core, making sync-from-Core diffs noisy.
**Impact:** Cosmetic. Listed because parity audits care about source-trail
fidelity; the actual numbers come out the same.

### BUG-17 — `deserializeBlockFileInfo` will overflow `readVarInt` → exception on `nTimeFirst`/`nTimeLast` > 0xFFFFFFFF

**Severity:** P3
**File:** hotbuns:src/storage/blockfile.ts:113-124 (deserializeBlockFileInfo
         uses readVarInt for both nTime fields)
**Core ref:** bitcoin-core/src/node/blockstorage.h:64-65 (nTimeFirst,
          nTimeLast are uint64_t, 0..2^64-1)
**Description:** `nTimeFirst` and `nTimeLast` are uint64 in Core. Hotbuns
serializes via `writer.writeVarInt(info.nTimeFirst)` — `BufferWriter.writeVarInt`
handles bigint inputs but the JS `BlockFileInfo` interface (line 51-52)
types these fields as `number`, which truncates at 2^53. A timestamp past
2^53 (year ~285470) cannot be represented; serialization of
`info.nTimeFirst = 1715000000` works fine today but the round-trip type is
narrower than Core's.
**Impact:** Cosmetic until ~year 285470. Listed for type-fidelity.

### BUG-18 — `BlockFileManager` has NO concurrency protection (no `cs_LastBlockFile`-equivalent); two parallel `findNextBlockPos` calls can write to the same file offset

**Severity:** P1
**File:** hotbuns:src/storage/blockfile.ts:288-326 (findNextBlockPos updates
         shared `currentFileNum`/`currentFileSize` mutably under async)
**Core ref:** bitcoin-core/src/node/blockstorage.cpp:835 (LOCK(cs_LastBlockFile))
**Description:** Core wraps `FindNextBlockPos`, `FindUndoPos`,
`FlushBlockFile`, `FlushUndoFile` in a single `cs_LastBlockFile`
mutex-protected section. Hotbuns's `findNextBlockPos` is an `async`
function with two await points (`init()`, `maybePreAllocate()`) — between
the await and `this.currentFileSize += totalSize` (line 323), another
caller can compute the same `pos` and clobber the offset.
**Excerpt (blockfile.ts:298-323):**
```
if (this.currentFileSize + totalSize > MAX_BLOCKFILE_SIZE) {
  this.currentFileNum++;
  this.currentFileSize = 0;
}
…
await this.maybePreAllocate(this.currentFileNum, totalSize);   // ← await
…
const pos: FlatFilePos = { fileNum: this.currentFileNum,
                            pos: this.currentFileSize + STORAGE_HEADER_BYTES };
…
this.currentFileSize += totalSize;       // ← non-atomic in JS event loop
```
**Impact:** Were this live (BUG-1), parallel `connectBlock` calls (which
hotbuns explicitly supports for parallel script verification — see
`sync/blocks.ts`) would race and produce two blocks at the same `pos.pos`,
corrupting the file.

### BUG-19 — `MAX_REV_FILE_SIZE` redefined to `128 MiB` in undo.ts; Core uses no explicit max for rev files (they grow alongside their blk pair)

**Severity:** P3
**File:** hotbuns:src/storage/undo.ts:23 (`const MAX_REV_FILE_SIZE = 128 *
         1024 * 1024;`)
**Core ref:** bitcoin-core/src/node/blockstorage.cpp:945-965 (FindUndoPos
          allocates without a size cap; rotation happens via the **block**
          file's cursor at MAX_BLOCKFILE_SIZE)
**Description:** Core rev files rotate when their **paired** blk file
rotates (FindNextBlockPos calls FlushBlockFile which calls FlushUndoFile
on the same file_num). Hotbuns gives the rev file its own independent
128 MiB cap with its own currentFileNum / currentFilePos counter that
does **not** match the block file's counter — they drift apart. Once they
drift, the on-disk file pair `blkNNNNN.dat`/`revNNNNN.dat` no longer
correspond.
**Impact:** Dead code. If wired, prune-by-file (which assumes blk00037.dat
matches rev00037.dat exactly) would unlink mismatched files and either
delete live data or leave dead undo data on disk.

### BUG-20 — `UndoFileManager.scanExistingFiles` `await Bun.file(blocksDir).exists()` then **immediately discards the result** with a ternary `[] : []`

**Severity:** P2
**File:** hotbuns:src/storage/undo.ts:277-281
**Description:** The line is literally:
```
const files = await Bun.file(blocksDir).exists()
  ? []
  : []; // Will be populated if dir exists
```
The ternary returns `[]` in both branches. The comment "Will be populated"
is wrong — `files` is unused below; the glob runs unconditionally
regardless. Dead-and-wrong code committed together. Same file:
`const stat = Bun.file(filePath); const size = stat.size;` (lines 292-293)
gets the size from a `Bun.file` handle without an `await`, which on Bun
returns 0 when the handle is fresh — `currentFilePos` ends up 0 after a
clean restart, **overwriting** existing undo data on the next write.
**Impact:** Silent overwrite of existing rev files after restart (if live).
Two bugs in one ~5-line block (returns-same-thing ternary + un-await'd
size). Dead code (BUG-1).

### BUG-21 — `BlockFileManager.readBlock` does not validate `blockSize > 0` — a magic-matched zero-size block returns an empty Buffer rather than rejecting

**Severity:** P3
**File:** hotbuns:src/storage/blockfile.ts:465-486
**Core ref:** bitcoin-core/src/node/blockstorage.cpp:1110-1114 (rejects
          `blk_size > MAX_SIZE` — but in Core a 0-size block is still a
          valid encoding for a block-with-only-header which then fails
          deserialization)
**Description:** Lines 465-474 read magic and size and reject only
`blockSize > MAX_BLOCKFILE_SIZE`. A `blockSize = 0` passes the gate (line
478 sets blockEnd = pos.pos, line 486 returns an empty subarray). The
caller (which doesn't exist for production reasons — BUG-1) would have to
re-check on its own.
**Impact:** Defensive; combines with no-size-floor on the wire format.

### BUG-22 — `pruning.ts` re-declares `BLOCKFILE_CHUNK_SIZE` and `UNDOFILE_CHUNK_SIZE` instead of importing from `blockfile.ts`

**Severity:** P3
**File:** hotbuns:src/storage/pruning.ts:50-53
         (`export const BLOCKFILE_CHUNK_SIZE = 16 * 1024 * 1024;`)
         (`export const UNDOFILE_CHUNK_SIZE = 1 * 1024 * 1024;`)
         hotbuns:src/storage/blockfile.ts:20
         (`export const BLOCKFILE_CHUNK_SIZE = 0x1000000;`)
**Description:** Two copies of `BLOCKFILE_CHUNK_SIZE` exist. They happen to
match (`0x1000000 == 16 MiB`). `UNDOFILE_CHUNK_SIZE = 1 MiB` matches Core,
but lives in `pruning.ts` where no undo-file writer can see it. Diverge
risk if anyone changes one and not the other.
**Impact:** Code-hygiene; latent diverge risk.

### BUG-23 — comment-as-confession in `pruning.ts:194-199`: "expensive, but necessary for correctness" / "For now, we mark the file info as empty / The block index records will be updated when we need to access them"

**Severity:** P1
**File:** hotbuns:src/storage/pruning.ts:194-209
**Core ref:** bitcoin-core/src/node/blockstorage.cpp:651-700
          (PruneOneBlockFile iterates the block index and explicitly clears
          `nFile/nDataPos/nUndoPos` on every CBlockIndex in the file)
**Description:** The function `pruneOneBlockFile` is documented as
"Marks all blocks in the file as pruned and resets the file info." But the
body only **resets the file info** — there is no iteration of block index
records to clear their `BLOCK_HAVE_DATA | BLOCK_HAVE_UNDO` status bits.
Comments at 196-198: *"We need to iterate through the database and find
blocks in this file / This is expensive, but necessary for correctness /
For now, we mark the file info as empty"* — and at 199-200: *"The block
index records will be updated when we need to access them"* (which never
happens; there is no on-access updater). Classic fleet-pattern
**comment-as-confession** — the author KNEW this was wrong and pushed it
anyway.
**Excerpt (pruning.ts:189-209):**
```
async pruneOneBlockFile(fileNum: number): Promise<void> {
  const info = this.blockFileInfo.get(fileNum);
  if (!info || info.nSize === 0) {
    return; // Already pruned or doesn't exist
  }
  // Update all block index records that reference this file
  // We need to iterate through the database and find blocks in this file
  // This is expensive, but necessary for correctness   ← comment-as-confession

  // For now, we mark the file info as empty           ← comment-as-confession
  // The block index records will be updated when we need to access them
  const emptyInfo = createEmptyBlockFileInfo();
  await this.updateBlockFileInfo(fileNum, emptyInfo);
  …
}
```
**Impact:** Even if BUG-12's empty-map were fixed and pruning actually
ran, the block index records would still claim `HAVE_DATA | HAVE_UNDO` for
already-unlinked files. A subsequent `getblock` RPC would attempt to read
from a deleted file and crash with "Block file not found" rather than
returning a clean "block pruned" error.

## Fleet-pattern smells

- **Dead-module pattern (entire storage subsystem).** ~700 LOC of carefully
  Core-mirroring code (`BlockFileManager`, `BlockStore`, `UndoFileManager`,
  `UndoManager`) is committed, has 100% test coverage on the unit-test side
  (blockfile.test.ts, undo.test.ts, database.test.ts — all green), and yet
  is invoked from **zero** production call sites (BUG-1, BUG-3, BUG-4,
  BUG-10, BUG-11, BUG-13, BUG-15, BUG-18, BUG-19, BUG-20, BUG-21). Every
  Bitcoin-style flat-file persistence behavior listed in the 8 audit
  behaviors at the top is implemented in the dead code and not present in
  the live path. Matches the fleet patterns called out in W138
  (assumeUTXO `ChainstateManager`/`DualChainstateManager`/`BackgroundValidator`
  dead-class — 9 of 10 impls) and W141 (rustoshi 1079-LOC zmq.rs DEAD).
- **Comment-as-confession (4th class instance in hotbuns this campaign).**
  BUG-23's `pruning.ts:194-198` — "expensive, but necessary for correctness
  / For now, we mark the file info as empty / will be updated when we need
  to access them" — is the same shape as W138 haskoin `Consensus.hs:4917`
  ("In a full implementation, we would compute MuHash3072 here. For now,
  mark as validated") and W141 rustoshi zmq.rs:* . Strong fleet pattern.
- **Two-pipeline guard (15th distinct extension).** Pre-existing hotbuns
  pattern: a Core-shaped pipeline lives alongside a flat `db.put()` pipeline.
  The connect path (`chain/state.ts:374-393`) uses only the flat
  `db.putBlock`/`db.putUndoData`/`db.putBlockIndex` calls. The
  `BlockFileManager`/`UndoFileManager` flat-file pipeline coexists but is
  unreachable. Same shape as W141 ouroboros, W140 ouroboros, W137 ouroboros.
- **30-of-30-gates-buggy (4th instance in the campaign).** All 8 audit
  behaviors are either dead or wrong; every gate in the 8-behavior
  framework lands a bug. Matches clearbit W138 (30/30), lunarblock W139
  (30/30), clearbit W141 (30/30).
- **Swallow-error-with-zero-default (3rd instance).** BUG-10's two empty
  `catch {}` blocks with zero-default initialization is the same shape as
  W100 hotbuns, W128 ouroboros. Latent silent-truncation.
- **Carry-forward re-anchor.** The dead-code state has persisted across
  every previous audit wave that has touched hotbuns/storage (W100, W104,
  W127, W137). No fix wave has wired up the flat-file path; the comment-
  as-confession in pruning.ts dates from before W100. Treat the entire
  storage subsystem as a rewrite candidate rather than incremental fix.

## Summary

23 bugs across 8 behaviors. Breakdown:

| Severity   | Count | Bugs |
|------------|-------|------|
| P0-CDIV    | 2     | BUG-5, BUG-6 |
| P0         | 2     | BUG-1, BUG-12 |
| P1         | 7     | BUG-2, BUG-3, BUG-4, BUG-8, BUG-10, BUG-11, BUG-18, BUG-23 |
| P2         | 6     | BUG-9, BUG-13, BUG-14, BUG-15, BUG-16, BUG-20, BUG-22 |
| P3         | 4     | BUG-17, BUG-19, BUG-21, BUG-22 (overlap) |

Top consensus-/operations-affecting findings:

1. **BUG-1** (P0) — `blkXXXXX.dat`/`revXXXXX.dat` machinery is entirely dead;
   raw blocks live in LevelDB under prefix `'d'`. ~700 LOC of dead code.
2. **BUG-12** (P0) — `-prune=N` is a no-op because `BlockFileInfo` is never
   populated. Disk fills without bound on a long-running mainnet hotbuns.
3. **BUG-5/BUG-6** (P0-CDIV) — block-index leveldb serialization uses
   CompactSize + fixed-96-byte records vs Core's VARINT + variable-length
   `CDiskBlockIndex`. Format-incompatible with any Core `blocks/index/` dir.
