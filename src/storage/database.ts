/**
 * Persistent storage for blocks, headers, and chain state using LevelDB.
 *
 * Uses prefix-based key namespacing and batch write support for atomic operations.
 *
 * Performance optimizations:
 * - Configurable batch sizes to prevent OOM during IBD
 * - Batch accumulation for reduced write amplification
 * - Memory monitoring and GC hints
 */

import { ClassicLevel } from 'classic-level';
import { BufferReader, BufferWriter } from '../wire/serialization.js';

/** Default maximum operations per batch write (prevents OOM). */
const DEFAULT_MAX_BATCH_SIZE = 10000;

/** IBD-optimized batch size (larger batches, less fsync overhead). */
const IBD_BATCH_SIZE = 50000;

/**
 * On-disk coins/chain block-cache budget passed to the backing LevelDB store
 * (the analogue of Bitcoin Core's `m_coinsdb_cache_size_bytes`). 256 MB
 * LevelDB block cache, sized for the 2 GB UTXO cache budget. Exported so the
 * RPC layer (getchainstates) can report the genuine configured value rather
 * than re-deriving it, keeping the constructor and the reported value in sync.
 */
export const COINS_DB_BLOCK_CACHE_BYTES = 256 * 1024 * 1024;

/**
 * LevelDB write-buffer size, mirroring Bitcoin Core dbwrapper.cpp GetOptions:
 * `options.write_buffer_size = nCacheSize / 4`. Two buffers may be live, so
 * this is the per-buffer cap. 64 MiB (with a 256 MiB block cache) is the
 * value that makes bulk snapshot import a memtable-fill rather than a
 * 16 MiB stutter of flushes.
 */
export const COINS_DB_WRITE_BUFFER_BYTES = COINS_DB_BLOCK_CACHE_BYTES / 4;

/**
 * Bitcoin Core sets `options.compression = leveldb::kNoCompression`
 * (dbwrapper.cpp GetOptions). Snappy on already-compact UTXO values burns
 * CPU on every 120k-coin flush and is the opposite of Core's chainstate.
 */
export const COINS_DB_COMPRESSION = false;

/**
 * Maximum size of a single on-disk SST table, mirroring Bitcoin Core's
 * `DBWRAPPER_MAX_FILE_SIZE` (dbwrapper.h:24) — which exists precisely to
 * override LevelDB's 2 MB default:
 *
 *     options.max_file_size = std::max(options.max_file_size,
 *                                      DBWRAPPER_MAX_FILE_SIZE);   // :152
 *
 * At LevelDB's 2 MB default a chain-sized store is split into tens of
 * thousands of tables (measured: 17,336 `.ldb` files for a 31 GB store), which
 * no reasonable table cache can cover. At 32 MiB the same store is ~1,000
 * tables — which is exactly the file count {@link COINS_DB_MAX_OPEN_FILES}
 * is sized to hold. The two constants are a MATCHED PAIR; changing one
 * without the other is what produces table-cache thrash.
 */
export const COINS_DB_MAX_FILE_SIZE_BYTES = 32 * 1024 * 1024;

/**
 * Table-cache size (open table handles).
 *
 * Do NOT lower this to save RSS. A previous clamp to 256 did exactly that and
 * took the node offline: with a table cache far smaller than the table count,
 * nearly every read misses and must open a table, read its index block and
 * evict another. Measured on the live mainnet node while it was pegged, that
 * cost ~2,650 pread64/s with the main JS thread at 98% and the RPC server
 * starved off the event loop. The RSS the clamp was buying back was a phantom:
 * of 3,951,808 kB RSS, 3,887,180 kB was Anonymous, so every file-backed
 * mapping in the process together came to ~63 MB, not the "1-2 GB" claimed.
 *
 * WHY THIS IS NOT BITCOIN CORE'S 1000. Core keeps LevelDB's 1000 default on
 * 64-bit and warns against exceeding it, because past that LevelDB "will fall
 * back to a non-mmap implementation" (dbwrapper.cpp:114-137, PR #12495). That
 * warning is calibrated to Core's store SHAPE: with max_file_size at 32 MiB a
 * chain-sized store is ~1,000 tables, so 1000 handles covers all of them AND
 * stays inside LevelDB's mmap limit (kDefaultMmapLimit, 1000 on 64-bit).
 *
 * hotbuns is not in that regime. Its store was written at LevelDB's 2 MB
 * default before {@link COINS_DB_MAX_FILE_SIZE_BYTES} was set, so it still
 * holds >10,000 tables and is converging only as compaction rewrites them
 * (measured: 17,336 -> 11,387 tables in the first hour after the 32 MiB
 * setting took effect). At that count the mmap path is exhausted no matter
 * what this value is — so capping at 1000 buys none of the benefit Core's
 * warning protects, and costs ~94% table-cache miss rate. Setting 1000 was
 * measured to restore RPC for roughly an hour before the node wedged again.
 *
 * So this is sized to COVER THE ACTUAL TABLE COUNT. Handles are real fds here;
 * the process limit is 524,288 and steady-state usage is <50, so the headroom
 * is ample. Once compaction converges the store to ~1,000 tables, LevelDB will
 * simply hold fewer than this ceiling and the value becomes inert.
 */
export const COINS_DB_MAX_OPEN_FILES = 16384;

/** Key prefixes for database namespaces. */
export const enum DBPrefix {
  BLOCK_INDEX = 0x62, // 'b' - block hash -> block index record
  BLOCK_DATA = 0x64, // 'd' - block hash -> raw block bytes
  TX_INDEX = 0x74, // 't' - txid -> { blockHash, offset, length }
  UTXO = 0x75, // 'u' - outpoint (txid+vout) -> UTXO entry
  CHAIN_STATE = 0x73, // 's' - chain state metadata
  HEADER = 0x68, // 'h' - height (4 bytes BE) -> block hash
  UNDO = 0x72, // 'r' - block hash -> undo data for disconnect
  BLOCK_FILES = 0x66, // 'f' - file number -> block file info
  LAST_BLOCK_FILE = 0x6c, // 'l' - last block file number
  BLOCK_POS = 0x70, // 'p' - block hash -> file position
  PRUNE_STATE = 0x50, // 'P' - pruning state metadata
  CHAIN_WORK = 0x77, // 'w' - block hash -> cumulative chain work (32-byte big-endian uint256)
  MARKER = 0x4d, // 'M' - one-time migration done-markers (name -> completion record)
  /**
   * 'z' - snapshot coins staged by loadSnapshot until the content-hash gate
   * passes (same key layout as UTXO). Must stay the highest prefix so the
   * sorted bulk load into it displaces nothing.
   */
  SNAPSHOT_STAGING = 0x7a,
}

/**
 * MARKER-prefix record of a snapshot load in flight (see
 * {@link ChainDB.recoverSnapshotLoad}). Byte 0 is the phase; the PROMOTE_*
 * phases carry the commit payload (base hash, height, chain work, header).
 */
export const SNAPSHOT_LOAD_MARKER = "snapshot-load-in-progress";
/** MARKER-prefix copy of the rows displaced by {@link ChainDB.prepareSortedBulkLoad}. */
export const SNAPSHOT_DISPLACED_MARKER = "snapshot-bulk-load-displaced";

export const enum SnapshotLoadPhase {
  /** Coins going straight into an EMPTY live UTXO keyspace. */
  LOADING_DIRECT = 1,
  /** Coins going into SNAPSHOT_STAGING; the live set is untouched. */
  LOADING_STAGED = 2,
  /** Hash verified; clearing the live UTXO keyspace before the move. */
  PROMOTE_CLEAR = 3,
  /** Hash verified; moving staged coins into the (cleared) live keyspace. */
  PROMOTE_MOVE = 4,
}

/** What committing a verified snapshot writes besides the coins. */
export interface SnapshotCommit {
  baseHash: Buffer;
  baseHeight: number;
  chainWork: bigint;
  header: Buffer; // 80 bytes
}

/** Block status flags (matches Bitcoin Core). */
export const enum BlockStatus {
  HEADER_VALID = 1,
  TXS_KNOWN = 2,
  TXS_VALID = 4,
  HAVE_DATA = 8,
  HAVE_UNDO = 16,
  /** Block failed validation (set by invalidateblock). */
  FAILED_VALID = 32,
  /** Block descends from a failed block. */
  FAILED_CHILD = 64,
  /** Block has witness data in blk*.dat (enforces SegWit rules). */
  OPT_WITNESS = 128,
}

/** Block index record stored in the database. */
export interface BlockIndexRecord {
  height: number;
  header: Buffer; // 80-byte block header
  nTx: number;
  status: number; // bitmask: 1=header-valid, 2=txs-known, 4=txs-valid
  dataPos: number; // position/flag for block data existence
}

/** UTXO entry stored in the database. */
export interface UTXOEntry {
  height: number;
  coinbase: boolean;
  amount: bigint;
  scriptPubKey: Buffer;
}

/** Transaction index entry (txid -> block location). */
export interface TxIndexEntry {
  blockHash: Buffer; // 32 bytes
  offset: number; // byte offset within block
  length: number; // serialized tx length
}

/** Chain state metadata. */
export interface ChainState {
  bestBlockHash: Buffer;
  bestHeight: number;
  totalWork: bigint;
}

/** Batch operation for atomic writes. */
export interface BatchOperation {
  type: 'put' | 'del';
  prefix: DBPrefix;
  key: Buffer;
  value?: Buffer;
}

/** Chained native WriteBatch used by snapshot import. */
export interface SnapshotWriteBatch {
  putUTXO(txid: Buffer, vout: number, value: Buffer): void;
  readonly length: number;
  write(): Promise<void>;
}

/**
 * Construct a prefixed key for database storage.
 * Writes prefix byte directly into a new buffer instead of concat.
 */
function serializeDisplacedRows(rows: [Buffer, Buffer][]): Buffer {
  const w = new BufferWriter();
  w.writeVarInt(rows.length);
  for (const [k, v] of rows) {
    w.writeVarBytes(k);
    w.writeVarBytes(v);
  }
  return w.toBuffer();
}

function deserializeDisplacedRows(data: Buffer): [Buffer, Buffer][] {
  const r = new BufferReader(data);
  const n = r.readVarInt();
  const rows: [Buffer, Buffer][] = [];
  for (let i = 0; i < n; i++) {
    const k = Buffer.from(r.readVarBytes());
    rows.push([k, Buffer.from(r.readVarBytes())]);
  }
  return rows;
}

function serializeSnapshotLoadMarker(phase: SnapshotLoadPhase, commit?: SnapshotCommit): Buffer {
  if (!commit) return Buffer.from([phase]);
  const out = Buffer.alloc(1 + 32 + 4 + 32 + 80);
  out[0] = phase;
  commit.baseHash.copy(out, 1, 0, 32);
  out.writeUInt32LE(commit.baseHeight >>> 0, 33);
  let w = commit.chainWork;
  for (let i = 31; i >= 0; i--) {
    out[37 + i] = Number(w & 0xffn);
    w >>= 8n;
  }
  commit.header.copy(out, 69, 0, 80);
  return out;
}

function deserializeSnapshotLoadMarker(data: Buffer): { phase: SnapshotLoadPhase; commit: SnapshotCommit | null } {
  const phase = data[0] as SnapshotLoadPhase;
  if (data.length < 149) return { phase, commit: null };
  let chainWork = 0n;
  for (let i = 0; i < 32; i++) chainWork = (chainWork << 8n) | BigInt(data[37 + i]!);
  return {
    phase,
    commit: {
      baseHash: Buffer.from(data.subarray(1, 33)),
      baseHeight: data.readUInt32LE(33),
      chainWork,
      header: Buffer.from(data.subarray(69, 149)),
    },
  };
}

function makeKey(prefix: DBPrefix, key: Buffer): Buffer {
  const buf = Buffer.allocUnsafe(1 + key.length);
  buf[0] = prefix;
  key.copy(buf, 1);
  return buf;
}

/**
 * Encode a height as 4-byte big-endian for lexicographic ordering.
 */
function encodeHeight(height: number): Buffer {
  const buf = Buffer.allocUnsafe(4);
  buf.writeUInt32BE(height, 0);
  return buf;
}

/**
 * Encode a UTXO key: txid (32 bytes) || vout (4 bytes LE).
 */
function encodeUTXOKey(txid: Buffer, vout: number): Buffer {
  const buf = Buffer.allocUnsafe(36);
  txid.copy(buf, 0);
  buf.writeUInt32LE(vout, 32);
  return buf;
}

/**
 * Serialize a BlockIndexRecord to bytes.
 */
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

/**
 * Deserialize a BlockIndexRecord from bytes.
 */
function deserializeBlockIndex(data: Buffer): BlockIndexRecord {
  const reader = new BufferReader(data);
  const height = reader.readUInt32LE();
  const header = reader.readBytes(80);
  const nTx = reader.readUInt32LE();
  const status = reader.readUInt32LE();
  const dataPos = reader.readUInt32LE();
  return { height, header, nTx, status, dataPos };
}

/**
 * Serialize a UTXOEntry to bytes.
 */
function serializeUTXO(entry: UTXOEntry): Buffer {
  const spkLen = entry.scriptPubKey.length;
  const viSize = spkLen <= 0xfc ? 1 : spkLen <= 0xffff ? 3 : 5;
  const buf = Buffer.allocUnsafe(4 + 1 + 8 + viSize + spkLen);
  let pos = 0;
  buf.writeUInt32LE(entry.height, pos); pos += 4;
  buf[pos++] = entry.coinbase ? 1 : 0;
  buf.writeBigUInt64LE(entry.amount, pos); pos += 8;
  if (spkLen <= 0xfc) {
    buf[pos++] = spkLen;
  } else if (spkLen <= 0xffff) {
    buf[pos++] = 0xfd;
    buf.writeUInt16LE(spkLen, pos); pos += 2;
  } else {
    buf[pos++] = 0xfe;
    buf.writeUInt32LE(spkLen, pos); pos += 4;
  }
  entry.scriptPubKey.copy(buf, pos);
  return buf;
}

/**
 * Deserialize a UTXOEntry from bytes.
 */
function deserializeUTXO(data: Buffer): UTXOEntry {
  const reader = new BufferReader(data);
  const height = reader.readUInt32LE();
  const coinbase = reader.readUInt8() === 1;
  const amount = reader.readUInt64LE();
  const scriptPubKey = reader.readVarBytes();
  return { height, coinbase, amount, scriptPubKey };
}

/**
 * Serialize TxIndexEntry to bytes.
 */
function serializeTxIndex(entry: TxIndexEntry): Buffer {
  const writer = new BufferWriter();
  writer.writeHash(entry.blockHash);
  writer.writeUInt32LE(entry.offset);
  writer.writeUInt32LE(entry.length);
  return writer.toBuffer();
}

/**
 * Deserialize TxIndexEntry from bytes.
 */
function deserializeTxIndex(data: Buffer): TxIndexEntry {
  const reader = new BufferReader(data);
  const blockHash = reader.readHash();
  const offset = reader.readUInt32LE();
  const length = reader.readUInt32LE();
  return { blockHash, offset, length };
}

/**
 * Serialize ChainState to bytes.
 */
function serializeChainState(state: ChainState): Buffer {
  const writer = new BufferWriter();
  writer.writeHash(state.bestBlockHash);
  writer.writeUInt32LE(state.bestHeight);
  // Serialize totalWork as a variable-length big integer
  // We store it as a byte array with length prefix
  const workBytes = bigIntToBuffer(state.totalWork);
  writer.writeVarBytes(workBytes);
  return writer.toBuffer();
}

/**
 * Deserialize ChainState from bytes.
 */
function deserializeChainState(data: Buffer): ChainState {
  const reader = new BufferReader(data);
  const bestBlockHash = reader.readHash();
  const bestHeight = reader.readUInt32LE();
  const workBytes = reader.readVarBytes();
  const totalWork = bufferToBigInt(workBytes);
  return { bestBlockHash, bestHeight, totalWork };
}

/**
 * Convert a bigint to a Buffer (big-endian, variable length).
 */
function bigIntToBuffer(n: bigint): Buffer {
  if (n === 0n) {
    return Buffer.alloc(0);
  }
  let hex = n.toString(16);
  if (hex.length % 2 !== 0) {
    hex = '0' + hex;
  }
  return Buffer.from(hex, 'hex');
}

/**
 * Convert a Buffer to a bigint (big-endian).
 */
function bufferToBigInt(buf: Buffer): bigint {
  if (buf.length === 0) {
    return 0n;
  }
  return BigInt('0x' + buf.toString('hex'));
}

/**
 * LevelDB-backed storage for Bitcoin blockchain data.
 *
 * Provides storage for:
 * - Block index records (block metadata)
 * - Raw block data
 * - UTXO set
 * - Chain state
 * - Undo data for reorgs
 */
/** A connect staged by {@link ChainDB.stageConnectedBlock}. */
interface StagedConnect {
  owner: object;
  height: number;
  hash: Buffer;
  nTx: number;
  seq: number;
}

export class ChainDB {
  private db: ClassicLevel<Buffer, Buffer>;
  /**
   * Set true at the start of {@link close}. Allows callers (e.g. P2P-driven
   * async header writes) to short-circuit before invoking the underlying
   * LevelDB so we don't surface `LEVEL_DATABASE_NOT_OPEN` errors as noise
   * during graceful shutdown.
   */
  private closing: boolean;

  /** The on-disk directory this store was opened at (for the AssumeUTXO
   *  background chainstate, which derives a SEPARATE store path from it). */
  private readonly dbPath: string;

  /**
   * Active-chain metadata of blocks connected since the last coins flush:
   * the height -> hash entry (Core `CChain::SetTip`) and the block's nTx.
   * Deep-IBD blocks used to write both with two awaited LevelDB round-trips
   * per block (ARCH-2.5: 25% of block time at 900k), ahead of their coins.
   * They are now kept here and written by {@link CoinsViewDB.batchWrite} in
   * the same batch as the coins and CHAIN_STATE (Core FlushStateToDisk), so
   * the height index never leads the durable UTXO tip. Readers see them
   * through {@link getBlockHashByHeight} / {@link getBlockIndex}.
   *
   * Each entry belongs to the UTXO view (`owner`, a CoinsViewDB) whose coins
   * reflect that block; only that view's flush writes it. ChainStateManager
   * and BlockSync each own a view on this ChainDB, and a flush of the other
   * view does not carry BlockSync's coins. `seq` orders a staged entry
   * against a later direct write. `stagedNTx` indexes the same entries by
   * block hash; an entry superseded at its height by a DIFFERENT block (or
   * by a delete) takes its nTx with it. A direct write that names the same
   * block at that height supersedes only the height entry: the entry moves
   * to `stagedNTxOnly` and its nTx still rides the owner's coins flush,
   * with that block's coins.
   *
   * The staged nTx is an overlay for readers only. No write other than the
   * owner's coins flush stores it (putBlockIndex, buildBlockIndexOrStatusOp
   * store the durable nTx), so a crash before that flush leaves nTx 0.
   */
  private stagedHeights = new Map<number, StagedConnect>();
  private stagedNTx = new Map<string, StagedConnect>();
  private stagedNTxOnly = new Map<number, StagedConnect>();
  private stagedSeq = 0;
  /**
   * Serializes every height-index write (direct puts/deletes, batch() ops on
   * HEADER heights, the coins flush that carries staged connects). Without
   * it a direct write issued while a flush is between its snapshot and its
   * LevelDB write could land first and be overwritten by the stale staged
   * value; with it the write issued later always lands later.
   */
  private heightWriteTail: Promise<void> = Promise.resolve();
  /** Block hashes whose staged nTx a running coins flush is writing. */
  private flushingNTx = new Set<string>();
  /**
   * The op list a running coins flush is handing to {@link batch} while it
   * holds the height-index lock: batch() writes that exact list without
   * queueing on the lock again (it would wait for itself). Every other
   * batch() call queues as usual.
   */
  private coinsFlushOps: BatchOperation[] | null = null;

  constructor(dbPath: string) {
    this.dbPath = dbPath;
    this.db = new ClassicLevel<Buffer, Buffer>(dbPath, {
      keyEncoding: 'buffer',
      valueEncoding: 'buffer',
      // 256 MB LevelDB block cache (increased for 2GB UTXO cache budget)
      cacheSize: COINS_DB_BLOCK_CACHE_BYTES,
      writeBufferSize: COINS_DB_WRITE_BUFFER_BYTES,
      compression: COINS_DB_COMPRESSION,
      // 32 MiB tables, matching Core's DBWRAPPER_MAX_FILE_SIZE, so the store
      // stays at a table count the cache below can actually hold.
      maxFileSize: COINS_DB_MAX_FILE_SIZE_BYTES,
      // LevelDB/Core default for 64-bit hosts. See the constant's doc comment:
      // a previous clamp to 256 here traded a phantom RSS saving for constant
      // table-cache eviction (~2,650 pread64/s measured, main thread pegged
      // at 98% with the RPC server starved off the event loop).
      maxOpenFiles: COINS_DB_MAX_OPEN_FILES,
    });
    this.closing = false;
  }

  /** The on-disk directory this store was opened at. */
  path(): string {
    return this.dbPath;
  }

  async open(): Promise<void> {
    await this.db.open();
  }

  async close(): Promise<void> {
    // Flip the flag *before* awaiting close() so any in-flight async caller
    // that races with us can observe the shutdown and bail early via
    // {@link isClosing}.
    this.closing = true;
    await this.db.close();
  }

  /**
   * True once {@link close} has been entered.  Hot-path writers driven by
   * P2P async tasks (e.g. {@link putBlockIndex} from headers.ts) consult
   * this to skip writes that would otherwise throw `LEVEL_DATABASE_NOT_OPEN`
   * during graceful shutdown.
   */
  isClosing(): boolean {
    return this.closing;
  }

  /**
   * The configured on-disk (LevelDB) block-cache budget in bytes — the value
   * passed to the underlying store's `cacheSize`. This is hotbuns's analogue of
   * Bitcoin Core's `Chainstate::m_coinsdb_cache_size_bytes`, surfaced for the
   * getchainstates RPC so it can report the genuine configured cache size.
   */
  getBlockCacheBytes(): number {
    return COINS_DB_BLOCK_CACHE_BYTES;
  }

  // Block index operations

  async putBlockIndex(
    hash: Buffer,
    record: BlockIndexRecord,
    opts?: { writeHeightIndex?: boolean }
  ): Promise<void> {
    // Belt-and-suspenders: if shutdown is in progress, skip the write rather
    // than racing db.close() and surfacing LEVEL_DATABASE_NOT_OPEN as noise.
    // Caller (saveHeaderEntry) is best-effort during IBD; any header dropped
    // here will be re-fetched and re-saved on the next startup.
    if (this.closing) {
      return;
    }
    const key = makeKey(DBPrefix.BLOCK_INDEX, hash);
    // The height -> hash (active-chain) mapping — hotbuns's analogue
    // of Bitcoin Core's `CChain m_chain` (the height-indexed active chain),
    // which is kept STRICTLY SEPARATE from `mapBlockIndex` (all headers by
    // hash).  Core only mutates `m_chain` via `CChain::SetTip` inside
    // ActivateBestChain's connect/disconnect — never during header reception
    // (`AcceptBlockHeader` touches only `mapBlockIndex`).  Callers that are NOT
    // on the active-connect path (notably `saveHeaderEntry`, which fires for
    // EVERY header including competing forks) MUST pass
    // `writeHeightIndex: false`; otherwise a fork header at the same height as
    // the active tip overwrites the height->hash entry and getblockhash(h)
    // returns an abandoned-branch block while getbestblockhash returns the
    // active tip (the stale-index bug this parameter closes).
    const writeHeight = opts?.writeHeightIndex !== false;
    const hex = hash.toString('hex');
    if (!writeHeight && !this.stagedNTx.has(hex) && !this.flushingNTx.has(hex)) {
      // Header reception: no height-index write and no staged nTx this
      // record could race with, so no need to queue behind a coins flush.
      await this.db.put(key, serializeBlockIndex(record));
      return;
    }
    // Queued behind a running coins flush, which may read-modify-write this
    // record (staged nTx) or write this height (staged connect).
    const seq = this.stagedSeq;
    await this.withHeightIndexLock(async () => {
      await this.db.put(key, serializeBlockIndex(await this.withDurableNTx(hash, record)));
      if (writeHeight) {
        const heightKey = makeKey(DBPrefix.HEADER, encodeHeight(record.height));
        await this.db.put(heightKey, hash);
        // Supersedes a connect staged for this height before this call
        // (stageConnectedBlock), as putBlockHashByHeight and batch() do.
        this.dropStagedHeight(record.height, seq, hash);
      }
    });
  }

  /**
   * Build a {@link BatchOperation} that sets the active-chain height -> hash
   * mapping (Core `CChain::SetTip`).  Used by the multi-block reorg dispatch
   * (sync/blocks.ts) so each reconnected intermediate block's active-chain
   * index entry rides the same atomic batch as the UTXO/undo/txindex writes.
   * Header reception no longer writes these entries, so the reorg-reconnect
   * path is the authority for the [fork+1 .. newTip-1] heights.
   */
  buildHeightHashPutOp(height: number, hash: Buffer): BatchOperation {
    return {
      type: 'put',
      prefix: DBPrefix.HEADER,
      key: encodeHeight(height),
      value: hash,
    };
  }

  /**
   * Build a {@link BatchOperation} that writes a block-index record (hash ->
   * metadata) WITHOUT the active-chain height -> hash entry. Used by the
   * snapshot pre-base header backfill (sync/headers.ts), which stores a whole
   * 2,000-header message in one batch instead of two awaited round-trips per
   * header.
   */
  buildBlockIndexPutOp(hash: Buffer, record: BlockIndexRecord): BatchOperation {
    return {
      type: 'put',
      prefix: DBPrefix.BLOCK_INDEX,
      key: hash,
      value: serializeBlockIndex(record),
    };
  }

  /**
   * Build a {@link BatchOperation} that deletes the active-chain height -> hash
   * mapping at `height`.  Used to clear stale entries ABOVE the new tip after a
   * reorg to a shorter (heavier) chain, and on pure disconnect
   * (invalidateblock), mirroring `CChain::SetTip`'s `vChain.resize(tip+1)`
   * which drops every entry above the new active tip.
   */
  buildHeightHashDeleteOp(height: number): BatchOperation {
    return {
      type: 'del',
      prefix: DBPrefix.HEADER,
      key: encodeHeight(height),
    };
  }

  /** Delete the active-chain height -> hash mapping at `height` (standalone,
   *  non-batch path). Counterpart to {@link buildHeightHashDeleteOp}. */
  async deleteBlockHashByHeight(height: number): Promise<void> {
    if (this.closing) {
      return;
    }
    const seq = this.stagedSeq;
    await this.withHeightIndexLock(async () => {
      const key = makeKey(DBPrefix.HEADER, encodeHeight(height));
      await this.db.del(key);
      this.dropStagedHeight(height, seq, null);
    });
  }

  /**
   * Delete every active-chain height -> hash entry ABOVE `height` in one
   * atomic batch; returns the heights removed (ascending). Used on boot to
   * rewind the height index to the durable UTXO tip after an unclean stop.
   */
  async deleteBlockHashesAbove(height: number): Promise<number[]> {
    return this.withHeightIndexLock(() => this.deleteBlockHashesAboveLocked(height));
  }

  private async deleteBlockHashesAboveLocked(height: number): Promise<number[]> {
    for (const h of new Set([...this.stagedHeights.keys(), ...this.stagedNTxOnly.keys()])) {
      if (h > height) this.dropStagedHeight(h, Number.POSITIVE_INFINITY, null);
    }
    const it = this.db.iterator({
      gt: makeKey(DBPrefix.HEADER, encodeHeight(height)),
      lt: Buffer.from([DBPrefix.HEADER + 1]),
      values: false,
    });
    const keys: Buffer[] = [];
    const heights: number[] = [];
    try {
      for await (const [key] of it) {
        if (key.length !== 5) continue;
        keys.push(Buffer.from(key));
        heights.push(key.readUInt32BE(1));
      }
    } finally {
      await it.close();
    }
    if (keys.length > 0) {
      const batch = this.db.batch();
      for (const k of keys) batch.del(k);
      await batch.write();
    }
    return heights;
  }

  /** Set the active-chain height -> hash mapping at `height` (standalone,
   *  non-batch path). Counterpart to {@link buildHeightHashPutOp}. */
  async putBlockHashByHeight(height: number, hash: Buffer): Promise<void> {
    if (this.closing) {
      return;
    }
    const seq = this.stagedSeq;
    await this.withHeightIndexLock(async () => {
      const key = makeKey(DBPrefix.HEADER, encodeHeight(height));
      await this.db.put(key, hash);
      this.dropStagedHeight(height, seq, hash);
    });
  }

  async getBlockIndex(hash: Buffer): Promise<BlockIndexRecord | null> {
    const key = makeKey(DBPrefix.BLOCK_INDEX, hash);
    const value = await this.db.get(key);
    if (value === undefined) {
      return null;
    }
    const record = deserializeBlockIndex(value);
    if (record.nTx === 0) {
      const staged = this.stagedNTx.get(hash.toString('hex'));
      if (staged) record.nTx = staged.nTx;
    }
    return record;
  }

  /**
   * Record an active-chain connect without writing it: the height -> hash
   * entry and the block's nTx (what {@link putBlockHashByHeight} and
   * {@link updateBlockIndexNTx} wrote per block before). They reach disk with
   * the next flush of `owner` (the CoinsViewDB whose coins reflect this
   * block), atomically with those coins and CHAIN_STATE. See
   * {@link stagedHeights}. A connect staged earlier at this height (a block
   * since disconnected) is replaced, nTx included.
   */
  stageConnectedBlock(owner: object, height: number, hash: Buffer, nTx: number): void {
    this.dropStagedHeight(height, Number.POSITIVE_INFINITY, null);
    const entry: StagedConnect = { owner, height, hash, nTx, seq: ++this.stagedSeq };
    this.stagedHeights.set(height, entry);
    if (nTx > 0) this.stagedNTx.set(hash.toString('hex'), entry);
  }

  /** Number of connects staged and not yet flushed (tests, diagnostics). */
  stagedConnectCount(): number {
    return this.stagedHeights.size + this.stagedNTxOnly.size;
  }

  /**
   * Drop every connect staged by `owner`. Called when that UTXO view is
   * thrown away (BlockSync.discardView): the blocks it described are no
   * longer reflected by any coins that could be flushed, and are connected
   * again.
   */
  discardStagedConnects(owner: object): void {
    for (const s of [...this.stagedHeights.values(), ...this.stagedNTxOnly.values()]) {
      if (s.owner === owner) this.forgetStaged(s);
    }
  }

  /**
   * A direct write issued after `seq` set the height index at `height` to
   * `now` (null: deleted). A connect staged there at or before `seq` loses
   * its height entry. Its nTx goes too, unless `now` names that same block:
   * then the nTx stays staged and rides the owner's coins flush with that
   * block's coins. An nTx left staged earlier at this height (stagedNTxOnly)
   * goes once the height names another block.
   */
  private dropStagedHeight(height: number, seq: number, now: Buffer | null): void {
    const s = this.stagedHeights.get(height);
    if (s && s.seq <= seq) {
      this.stagedHeights.delete(height);
      if (now !== null && now.equals(s.hash) && s.nTx > 0) {
        this.stagedNTxOnly.set(height, s);
        return;
      }
      this.forgetStaged(s);
    }
    const o = this.stagedNTxOnly.get(height);
    if (o && o.seq <= seq && !(now !== null && now.equals(o.hash))) this.forgetStaged(o);
  }

  /** Remove `s` from every staging map that still holds it. */
  private forgetStaged(s: StagedConnect): void {
    if (this.stagedHeights.get(s.height) === s) this.stagedHeights.delete(s.height);
    if (this.stagedNTxOnly.get(s.height) === s) this.stagedNTxOnly.delete(s.height);
    const k = s.hash.toString('hex');
    if (this.stagedNTx.get(k) === s) this.stagedNTx.delete(k);
  }

  /**
   * `record` with the durable nTx in place of a staged one that a reader
   * copied into it (getBlockIndex overlays it): a write that is not the
   * owner's coins flush must not put that nTx on disk ahead of the coins.
   * Called under the height-index lock, so no coins flush is mid-write.
   */
  private async withDurableNTx(hash: Buffer, record: BlockIndexRecord): Promise<BlockIndexRecord> {
    const staged = this.stagedNTx.get(hash.toString('hex'));
    if (!staged || record.nTx !== staged.nTx) return record;
    const durable = await this.db.get(makeKey(DBPrefix.BLOCK_INDEX, hash));
    const durableNTx = durable === undefined ? 0 : deserializeBlockIndex(durable).nTx;
    return durableNTx === record.nTx ? record : { ...record, nTx: durableNTx };
  }

  private withHeightIndexLock<T>(fn: () => Promise<T>): Promise<T> {
    const run = this.heightWriteTail.then(fn);
    this.heightWriteTail = run.then(
      () => {},
      () => {}
    );
    return run;
  }

  /**
   * The coins flush of UTXO view `owner` (CoinsViewDB.batchWrite): one
   * LevelDB batch of `coinOps`, the height index + nTx of every connect
   * `owner` staged, then `extraOps` (CHAIN_STATE, reorg ops).
   *
   * The staged entries are snapshotted under the height-index lock, so the
   * batch carries exactly the blocks staged before the flush started, and a
   * direct height-index write issued meanwhile waits and lands after it. A
   * staged height that `extraOps` writes (a reorg's put/delete) is left out
   * with its nTx: that block is no longer on the active chain this batch
   * describes. The nTx ops read-modify-write the stored record
   * (updateBlockIndexNTx semantics: only a record that exists and has nTx
   * 0). On a failed write nothing is forgotten, so the retry carries the
   * same entries; on success the snapshotted entries are dropped. Returns
   * false when there was nothing to write.
   */
  async writeCoinsBatch(
    owner: object,
    coinOps: BatchOperation[],
    extraOps: BatchOperation[] = []
  ): Promise<boolean> {
    return this.withHeightIndexLock(async () => {
      const seq = this.stagedSeq;
      // Height -> what the last extraOps write there names (null: deleted).
      const overwritten = new Map<number, Buffer | null>();
      for (const op of extraOps) {
        if (op.prefix === DBPrefix.HEADER && op.key.length === 4) {
          overwritten.set(op.key.readUInt32BE(0), op.type === 'put' ? op.value! : null);
        }
      }
      const mine: StagedConnect[] = [];
      for (const s of this.stagedHeights.values()) {
        if (s.owner === owner) mine.push(s);
      }
      for (const s of this.stagedNTxOnly.values()) {
        if (s.owner === owner) mine.push(s);
      }
      const names = (s: StagedConnect) => {
        if (!overwritten.has(s.height)) return true;
        const now = overwritten.get(s.height)!;
        return now !== null && now.equals(s.hash);
      };
      // Height entries still staged and not rewritten by extraOps.
      const written = mine.filter(
        (s) => !overwritten.has(s.height) && this.stagedHeights.get(s.height) === s
      );
      // nTx of every block this view staged that the batch leaves at its height.
      const ntx = mine.filter(
        (s) => names(s) && s.nTx > 0 && this.stagedNTx.get(s.hash.toString('hex')) === s
      );
      for (const s of ntx) this.flushingNTx.add(s.hash.toString('hex'));
      try {
        const stagedOps: BatchOperation[] = [];
        for (const s of written) {
          stagedOps.push(this.buildHeightHashPutOp(s.height, s.hash));
        }
        // A block-index put in extraOps (a status op riding this flush) is
        // the later op for that key and would drop the staged nTx: patch the
        // nTx into it instead of writing a separate record.
        const extra = extraOps.slice();
        const extraIndex = new Map<string, number>();
        extra.forEach((op, i) => {
          if (op.prefix === DBPrefix.BLOCK_INDEX && op.type === 'put' && op.key.length === 32) {
            extraIndex.set(op.key.toString('hex'), i);
          }
        });
        const fromDisk: StagedConnect[] = [];
        for (const s of ntx) {
          const i = extraIndex.get(s.hash.toString('hex'));
          if (i === undefined) {
            fromDisk.push(s);
            continue;
          }
          const record = deserializeBlockIndex(extra[i]!.value!);
          if (record.nTx !== 0) continue;
          record.nTx = s.nTx;
          extra[i] = this.buildBlockIndexPutOp(s.hash, record);
        }
        const values = await Promise.all(
          fromDisk.map((s) => this.db.get(makeKey(DBPrefix.BLOCK_INDEX, s.hash)))
        );
        for (let i = 0; i < fromDisk.length; i++) {
          const value = values[i];
          if (value === undefined) continue;
          const record = deserializeBlockIndex(value);
          if (record.nTx !== 0) continue;
          record.nTx = fromDisk[i]!.nTx;
          stagedOps.push(this.buildBlockIndexPutOp(fromDisk[i]!.hash, record));
        }
        // Coins, then the staged metadata, then the caller's ops: for the
        // same key the later op wins in a LevelDB batch.
        const ops = coinOps.concat(stagedOps, extra);
        if (ops.length === 0) return false;
        // Through batch(), the one entry point for atomic writes.
        this.coinsFlushOps = ops;
        try {
          await this.batch(ops);
        } finally {
          this.coinsFlushOps = null;
        }
        for (const s of mine) {
          if (s.seq <= seq) this.forgetStaged(s);
        }
        // A height this batch wrote directly supersedes a connect any view
        // staged before the flush started (as batch() does).
        for (const [h, now] of overwritten) this.dropStagedHeight(h, seq, now);
        return true;
      } finally {
        for (const s of ntx) this.flushingNTx.delete(s.hash.toString('hex'));
      }
    });
  }

  async getBlockHashByHeight(height: number): Promise<Buffer | null> {
    const staged = this.stagedHeights.get(height);
    if (staged) return staged.hash;
    const key = makeKey(DBPrefix.HEADER, encodeHeight(height));
    const value = await this.db.get(key);
    if (value === undefined) {
      return null;
    }
    return value;
  }

  // Raw block data operations

  async putBlock(hash: Buffer, rawBlock: Buffer): Promise<void> {
    const key = makeKey(DBPrefix.BLOCK_DATA, hash);
    await this.db.put(key, rawBlock);
  }

  /** Build a {@link BatchOperation} that stores a raw block body. */
  buildBlockDataPutOp(hash: Buffer, rawBlock: Buffer): BatchOperation {
    return { type: 'put', prefix: DBPrefix.BLOCK_DATA, key: hash, value: rawBlock };
  }

  /**
   * True when this node holds the raw body of `hash` (LevelDB has(): an
   * iterator seek, no value copy into JS).
   */
  async hasBlock(hash: Buffer): Promise<boolean> {
    return this.db.has(makeKey(DBPrefix.BLOCK_DATA, hash));
  }

  async getBlock(hash: Buffer): Promise<Buffer | null> {
    const key = makeKey(DBPrefix.BLOCK_DATA, hash);
    const value = await this.db.get(key);
    if (value === undefined) {
      return null;
    }
    return value;
  }

  // UTXO set operations

  async putUTXO(txid: Buffer, vout: number, entry: UTXOEntry): Promise<void> {
    const key = makeKey(DBPrefix.UTXO, encodeUTXOKey(txid, vout));
    const value = serializeUTXO(entry);
    await this.db.put(key, value);
  }

  async getUTXO(txid: Buffer, vout: number): Promise<UTXOEntry | null> {
    const key = makeKey(DBPrefix.UTXO, encodeUTXOKey(txid, vout));
    const value = await this.db.get(key);
    if (value === undefined) {
      return null;
    }
    return deserializeUTXO(value);
  }

  async deleteUTXO(txid: Buffer, vout: number): Promise<void> {
    const key = makeKey(DBPrefix.UTXO, encodeUTXOKey(txid, vout));
    await this.db.del(key);
  }

  // Transaction index operations

  async putTxIndex(txid: Buffer, entry: TxIndexEntry): Promise<void> {
    const key = makeKey(DBPrefix.TX_INDEX, txid);
    const value = serializeTxIndex(entry);
    await this.db.put(key, value);
  }

  async getTxIndex(txid: Buffer): Promise<TxIndexEntry | null> {
    const key = makeKey(DBPrefix.TX_INDEX, txid);
    try {
      const value = await this.db.get(key);
      if (value === undefined) {
        return null;
      }
      return deserializeTxIndex(value);
    } catch {
      return null;
    }
  }

  async deleteTxIndex(txid: Buffer): Promise<void> {
    const key = makeKey(DBPrefix.TX_INDEX, txid);
    await this.db.del(key);
  }

  // Chain state operations

  async putChainState(state: ChainState): Promise<void> {
    const key = makeKey(DBPrefix.CHAIN_STATE, Buffer.alloc(0));
    const value = serializeChainState(state);
    await this.db.put(key, value);
  }

  /**
   * Build a {@link BatchOperation} that puts the canonical chain-state record.
   *
   * Use this when callers (e.g. `chain/state.ts::disconnectBlock`,
   * `sync/blocks.ts::connectBlock`) need to commit a chain-state update
   * atomically alongside UTXO and txindex writes via {@link batch} or
   * {@link UTXOManager.flush}'s `extraOps`.  Encapsulates the prefix +
   * serialization details so call sites don't have to duplicate them.
   *
   * Mirrors Bitcoin Core's pattern of building all DisconnectTip writes
   * onto a single `CDBBatch` (validation.cpp:DisconnectTip), so a crash
   * mid-disconnect cannot leave the chainstate inconsistent.
   */
  buildChainStateOp(state: ChainState): BatchOperation {
    return {
      type: 'put',
      prefix: DBPrefix.CHAIN_STATE,
      key: Buffer.alloc(0),
      value: serializeChainState(state),
    };
  }

  /**
   * Build a {@link BatchOperation} that deletes a txindex entry.
   *
   * Pairs with {@link buildChainStateOp} so the Pattern C0 disconnect-side
   * txindex revert (see `chain/state.ts::disconnectBlock`) can ride along
   * inside the same atomic batch as the UTXO + chain-state writes.  Without
   * this, the txindex deletes were three separate awaits; a crash between
   * them was the worst single-block atomicity exposure in the fleet (see
   * `CORE-PARITY-AUDIT/_post-reorg-consistency-fleet-result-2026-05-05.md`,
   * Pattern D).
   */
  buildTxIndexDeleteOp(txid: Buffer): BatchOperation {
    return {
      type: 'del',
      prefix: DBPrefix.TX_INDEX,
      key: txid,
    };
  }

  /**
   * Build a {@link BatchOperation} that writes a txindex entry pointing at
   * the block that contains `txid`.
   *
   * Pairs with {@link buildTxIndexDeleteOp} so the connect-side write of a
   * reorg-reconnected intermediate block can ride the same atomic batch as
   * the disconnect-side deletes and the UTXO + chain-state writes.  The
   * on-disk format is `blockHash(32) || offset(uint32 LE) || length(uint32 LE)`
   * and matches {@link putTxIndex}.  Pattern D (multi-block) — pairs with
   * the single-block Pattern D `9b10550`.
   */
  buildTxIndexPutOp(
    txid: Buffer,
    blockHash: Buffer,
    offset: number = 0,
    length: number = 0,
  ): BatchOperation {
    const value = Buffer.alloc(40);
    blockHash.copy(value, 0);
    value.writeUInt32LE(offset >>> 0, 32);
    value.writeUInt32LE(length >>> 0, 36);
    return {
      type: 'put',
      prefix: DBPrefix.TX_INDEX,
      key: txid,
      value,
    };
  }

  /**
   * Build a {@link BatchOperation} that puts undo data for a connected block.
   *
   * Used by the multi-block reorg dispatch (sync/blocks.ts) so the undo
   * persistence for every reconnected intermediate block rides inside the
   * same atomic batch as the txindex + UTXO + chain-state writes.  Without
   * this, undo persistence for intermediates was a standalone `db.put`,
   * leaving a multi-block reorg with N+1 separate commits.  Pattern D
   * (multi-block).
   */
  buildUndoDataPutOp(blockHash: Buffer, data: Buffer): BatchOperation {
    return {
      type: 'put',
      prefix: DBPrefix.UNDO,
      key: blockHash,
      value: data,
    };
  }

  /**
   * Build a {@link BatchOperation} that ORs new status bits into the existing
   * block index record for `blockHash`.  Returns `null` if the block index
   * entry does not exist (caller should skip the op in that case).
   *
   * Used by the reorg-reconnect path in sync/blocks.ts so that
   * BLOCK_HAVE_DATA (8) and BLOCK_HAVE_UNDO (16) are recorded in the block
   * index atomically with the undo-data write — both riding the same
   * flushDirty batch.  Mirrors Core's behaviour in
   * blockstorage.cpp::WriteBlock / WriteUndoDataForBlock which set nStatus
   * bits before flushing the dirty block index.
   */
  async buildBlockIndexOrStatusOp(
    blockHash: Buffer,
    statusBitsToSet: number,
  ): Promise<BatchOperation | null> {
    // The durable record, not getBlockIndex's staged-nTx overlay: this op
    // may be written outside the coins flush that owns that nTx. When it
    // rides that flush, writeCoinsBatch patches the staged nTx into it.
    const value = await this.db.get(makeKey(DBPrefix.BLOCK_INDEX, blockHash));
    if (value === undefined) {
      return null;
    }
    const existing = deserializeBlockIndex(value);
    const updated: BlockIndexRecord = {
      ...existing,
      status: existing.status | statusBitsToSet,
    };
    const key = makeKey(DBPrefix.BLOCK_INDEX, blockHash);
    return {
      type: 'put',
      prefix: DBPrefix.BLOCK_INDEX,
      key: blockHash,
      value: serializeBlockIndex(updated),
    };
  }

  async getChainState(): Promise<ChainState | null> {
    const key = makeKey(DBPrefix.CHAIN_STATE, Buffer.alloc(0));
    const value = await this.db.get(key);
    if (value === undefined) {
      return null;
    }
    return deserializeChainState(value);
  }

  // Batch operations for atomic writes

  /**
   * Execute batch operations atomically.
   */
  async batch(ops: BatchOperation[]): Promise<void> {
    if (ops === this.coinsFlushOps) {
      // writeCoinsBatch, already under the height-index lock; it settles the
      // staged connects itself.
      await this.writeBatchLocked(ops);
      return;
    }
    // Height -> what the last op there names (null: deleted).
    const heights = new Map<number, Buffer | null>();
    for (const op of ops) {
      if (op.prefix === DBPrefix.HEADER && op.key.length === 4) {
        heights.set(op.key.readUInt32BE(0), op.type === 'put' ? op.value! : null);
      }
    }
    if (heights.size === 0) {
      await this.writeBatchLocked(ops);
      return;
    }
    // A height -> hash write in this batch (reorg ops, invalidateblock)
    // supersedes a connect staged before this call; a later stage still wins.
    const seq = this.stagedSeq;
    await this.withHeightIndexLock(async () => {
      await this.writeBatchLocked(ops);
      for (const [h, now] of heights) this.dropStagedHeight(h, seq, now);
    });
  }

  /** The LevelDB write behind {@link batch}. */
  private async writeBatchLocked(ops: BatchOperation[]): Promise<void> {
    const batch = this.db.batch();
    for (const op of ops) {
      const key = makeKey(op.prefix, op.key);
      if (op.type === 'put') {
        if (!op.value) {
          throw new Error('batch put operation requires a value');
        }
        batch.put(key, op.value);
      } else {
        batch.del(key);
      }
    }
    await batch.write();
  }

  /**
   * Prepare an EMPTY key prefix for a bulk load whose keys arrive in sorted
   * order (the UTXO snapshot import: Core writes the dump in chainstate key
   * order, txid ascending, and our UTXO key is prefix + txid + vout).
   *
   * WHY: LevelDB can place a sorted stream of tables with trivial moves (no
   * rewrite) only while no existing table's key range overlaps the new
   * keys. A fresh datadir already holds genesis rows on BOTH sides of the
   * UTXO prefix ('b'/'h'/'s' below 'u', CHAIN_WORK 'w' above), so the first
   * table spans 'b'..'w' and overlaps every table the import writes after
   * it. Every imported table then went through a real L1->L2 merge with
   * that wide table (and the wide tail re-formed each time): the import ran
   * at compaction speed ("Current memtable full; waiting..."), and it ended
   * with ~60 tables (~2 GB) in L1 against LevelDB's fixed 10 MB L1 target.
   * LevelDB compacts the highest-scoring level first (L1 ~200 vs L0 = files
   * / 4 <= 3), so once block sync filled L0 to 12 tables every write stopped
   * ("Too many L0 files; waiting...") until L1 drained: 20-40 min with no
   * block connected and no header stored (R4 675000->710000, 2026-09-27).
   *
   * The rows above the prefix are displaced (deleted, and the tombstones
   * compacted away, see {@link purgeTombstonesBelow}) for the duration of the
   * load and put back by `restore()`. Then nothing overlaps the import and
   * every table it writes is placed without a rewrite.
   *
   * Only for a store nobody else is writing (startup `--load-snapshot`): a
   * running node reads CHAIN_WORK concurrently. Returns null (do nothing)
   * when the prefix already has keys or more than `maxDisplaced` rows sit
   * above it (not a fresh datadir — then displacing them is not worth the
   * risk). If the process dies mid-load the store is a partial import and
   * must be re-created either way.
   */
  async prepareSortedBulkLoad(
    prefix: DBPrefix,
    maxDisplaced: number = 1024
  ): Promise<{ displaced: number; restore: () => Promise<void> } | null> {
    const lo = Buffer.from([prefix]);
    const hi = Buffer.from([prefix + 1]);
    for await (const _k of this.db.keys({ gte: lo, lt: hi, limit: 1 })) {
      return null;
    }
    const displaced: [Buffer, Buffer][] = [];
    for await (const [k, v] of this.db.iterator({ gte: hi, limit: maxDisplaced + 1 })) {
      displaced.push([Buffer.from(k), Buffer.from(v)]);
    }
    if (displaced.length > maxDisplaced) return null;
    const markerKey = makeKey(DBPrefix.MARKER, Buffer.from(SNAPSHOT_DISPLACED_MARKER, "utf8"));
    if (displaced.length > 0) {
      // The rows leave the store in the same batch that records them under
      // the MARKER prefix, so a crash before restore() cannot lose them:
      // recoverSnapshotLoad() puts them back at startup (audit H9).
      const del = this.db.batch();
      for (const [k] of displaced) del.del(k);
      del.put(markerKey, serializeDisplacedRows(displaced));
      await del.write();
      await this.purgeTombstonesBelow(lo, maxDisplaced * 64);
    }
    let restored = false;
    return {
      displaced: displaced.length,
      restore: async (): Promise<void> => {
        if (restored || displaced.length === 0) return;
        restored = true;
        const put = this.db.batch();
        for (const [k, v] of displaced) put.put(k, v);
        put.del(markerKey);
        await put.write();
      },
    };
  }

  // ── Snapshot load crash safety (audit H9) ──

  /** True when no row exists under `prefix`. */
  async isPrefixEmpty(prefix: DBPrefix): Promise<boolean> {
    for await (const _k of this.db.keys({ gte: Buffer.from([prefix]), lt: Buffer.from([prefix + 1]), limit: 1 })) {
      return false;
    }
    return true;
  }

  /** Delete every row under `prefix`. */
  async clearPrefix(prefix: DBPrefix): Promise<void> {
    await this.db.clear({ gte: Buffer.from([prefix]), lt: Buffer.from([prefix + 1]) });
  }

  /** Record (or advance) the in-flight snapshot load phase. */
  async putSnapshotLoadMarker(phase: SnapshotLoadPhase, commit?: SnapshotCommit): Promise<void> {
    await this.putMarker(SNAPSHOT_LOAD_MARKER, serializeSnapshotLoadMarker(phase, commit));
  }

  /**
   * Move every staged snapshot coin into the live UTXO keyspace, one chunk
   * per batch. Each batch deletes the staged rows it moved, so re-running
   * after a crash continues where it stopped.
   */
  async moveStagedSnapshotCoins(chunk: number = 100_000): Promise<number> {
    const it = this.db.iterator({
      gte: Buffer.from([DBPrefix.SNAPSHOT_STAGING]),
      lt: Buffer.from([DBPrefix.SNAPSHOT_STAGING + 1]),
    });
    let moved = 0;
    let batch = this.db.batch();
    let n = 0;
    try {
      for await (const [k, v] of it) {
        const live = Buffer.from(k);
        live[0] = DBPrefix.UTXO;
        batch.put(live, Buffer.from(v));
        batch.del(Buffer.from(k));
        n++;
        if (n >= chunk) {
          await batch.write();
          moved += n;
          n = 0;
          batch = this.db.batch();
        }
      }
    } finally {
      await it.close();
    }
    if (n > 0) {
      await batch.write();
      moved += n;
    }
    return moved;
  }

  /**
   * The commit point of a snapshot load: the snapshot tip (CHAIN_STATE, base
   * block index, height entry, chain work) lands in one batch with the
   * removal of the in-progress marker, after every coin is in place.
   */
  async commitSnapshotLoad(commit: SnapshotCommit): Promise<void> {
    const ops: BatchOperation[] = [
      this.buildChainStateOp({
        bestBlockHash: commit.baseHash,
        bestHeight: commit.baseHeight,
        totalWork: commit.chainWork,
      }),
      this.buildHeightHashPutOp(commit.baseHeight, commit.baseHash),
      this.buildChainWorkPutOp(commit.baseHash, commit.chainWork),
      { type: 'del', prefix: DBPrefix.MARKER, key: Buffer.from(SNAPSHOT_LOAD_MARKER, "utf8") },
    ];
    // Keep a base record that already exists (its header arrived first).
    if ((await this.db.get(makeKey(DBPrefix.BLOCK_INDEX, commit.baseHash))) === undefined) {
      ops.push(
        this.buildBlockIndexPutOp(commit.baseHash, {
          height: commit.baseHeight,
          header: commit.header,
          nTx: 0,
          status: BlockStatus.HEADER_VALID | BlockStatus.TXS_VALID | BlockStatus.HAVE_DATA,
          dataPos: 0,
        })
      );
    }
    await this.batch(ops);
  }

  /**
   * Undo a snapshot load that has NOT passed its hash gate: drop whatever
   * coins it wrote and its marker. The live set is as it was before the load.
   */
  async abortSnapshotLoad(phase: SnapshotLoadPhase): Promise<void> {
    await this.clearPrefix(
      phase === SnapshotLoadPhase.LOADING_DIRECT ? DBPrefix.UTXO : DBPrefix.SNAPSHOT_STAGING
    );
    await this.db.del(makeKey(DBPrefix.MARKER, Buffer.from(SNAPSHOT_LOAD_MARKER, "utf8")));
  }

  /** Finish replacing the live coins with verified staged coins. */
  async promoteSnapshotLoad(commit: SnapshotCommit, phase: SnapshotLoadPhase): Promise<void> {
    if (phase === SnapshotLoadPhase.PROMOTE_CLEAR) {
      // Core: the snapshot chainstate is a fresh coins DB. Coins the old
      // chainstate held must not survive into it.
      await this.clearPrefix(DBPrefix.UTXO);
      await this.putSnapshotLoadMarker(SnapshotLoadPhase.PROMOTE_MOVE, commit);
    }
    await this.moveStagedSnapshotCoins();
    await this.commitSnapshotLoad(commit);
  }

  /**
   * Startup recovery for a snapshot load the process did not finish (crash,
   * kill, power loss). Before the hash gate: roll back (the coins written are
   * unverified). After it: finish the promotion and commit. Also puts back
   * rows prepareSortedBulkLoad displaced. Returns what it did, or null.
   * Core analogue: a leftover chainstate_snapshot dir is deleted or adopted
   * at startup (validation.cpp ChainstateManager::DetectSnapshotChainstate).
   */
  async recoverSnapshotLoad(): Promise<string | null> {
    const done: string[] = [];
    const displaced = await this.getMarker(SNAPSHOT_DISPLACED_MARKER);
    if (displaced !== null) {
      const rows = deserializeDisplacedRows(displaced);
      const put = this.db.batch();
      for (const [k, v] of rows) put.put(k, v);
      put.del(makeKey(DBPrefix.MARKER, Buffer.from(SNAPSHOT_DISPLACED_MARKER, "utf8")));
      await put.write();
      done.push(`restored ${rows.length} row(s) displaced by an interrupted sorted bulk load`);
    }
    const rec = await this.getMarker(SNAPSHOT_LOAD_MARKER);
    if (rec !== null) {
      const { phase, commit } = deserializeSnapshotLoadMarker(rec);
      if (commit) {
        await this.promoteSnapshotLoad(commit, phase);
        done.push(`finished promoting a verified snapshot at height ${commit.baseHeight}`);
      } else {
        await this.abortSnapshotLoad(phase);
        done.push("rolled back an unverified, interrupted snapshot load");
      }
    }
    return done.length > 0 ? done.join("; ") : null;
  }

  /**
   * Make the deletes of {@link prepareSortedBulkLoad} physical before the
   * import starts. A tombstone is itself a key: flushed together with the
   * genesis rows below the prefix it forms a table spanning 'b'..'w' — the
   * very overlap being removed. `compactRange` first flushes the memtable,
   * but the table lands directly in L2 (nothing overlaps it) and a manual
   * compaction never rewrites the deepest level that holds the range, so
   * the tombstone would survive. Re-putting one row below the prefix makes
   * the next flush overlap that table; it lands one level up and the second
   * `compactRange` merges the two, dropping the tombstone and the value it
   * shadows (no deeper level holds the key). Skipped when the store has more
   * than `maxBelow` rows below the prefix (not a fresh datadir).
   */
  private async purgeTombstonesBelow(prefixKey: Buffer, maxBelow: number): Promise<void> {
    let first: [Buffer, Buffer] | null = null;
    let below = 0;
    for await (const [k, v] of this.db.iterator({ lt: prefixKey, limit: maxBelow + 1 })) {
      if (first === null) first = [Buffer.from(k), Buffer.from(v)];
      below++;
    }
    if (below > maxBelow) return;
    const all = [Buffer.from([0x00]), Buffer.alloc(8, 0xff)] as const;
    await this.db.compactRange(all[0], all[1]);
    if (first !== null) {
      await this.db.put(first[0], first[1]);
      await this.db.compactRange(all[0], all[1]);
    }
  }

  /**
   * Chained LevelDB batch for bulk UTXO import.
   *
   * `putUTXO` encodes the prefixed key and hands the pair to the native
   * WriteBatch, which copies immediately, so the caller's value buffer may
   * be reused after putUTXO returns. The caller flushes at its own cadence.
   */
  newChainedBatch(prefix: DBPrefix = DBPrefix.UTXO): SnapshotWriteBatch {
    const batch = this.db.batch();
    const keyBuf = Buffer.allocUnsafe(37);
    keyBuf[0] = prefix;
    let n = 0;
    return {
      putUTXO: (txid: Buffer, vout: number, value: Buffer): void => {
        txid.copy(keyBuf, 1, 0, 32);
        keyBuf.writeUInt32LE(vout >>> 0, 33);
        // Copy the 37-byte key: abstract-level's buffer encoder is identity,
        // and we reuse keyBuf on the next put.
        batch.put(Buffer.from(keyBuf), value);
        n++;
      },
      get length() {
        return n;
      },
      write: async (): Promise<void> => {
        if (n === 0) return;
        await batch.write();
      },
    };
  }

  /**
   * Execute batch operations with configurable max batch size.
   * Splits large batches into smaller chunks to prevent OOM.
   *
   * @param ops - Batch operations to execute
   * @param maxBatchSize - Maximum operations per batch (default: 10000)
   */
  async batchWrite(ops: BatchOperation[], maxBatchSize: number = DEFAULT_MAX_BATCH_SIZE): Promise<void> {
    if (ops.length === 0) {
      return;
    }

    // If small enough, write in single batch
    if (ops.length <= maxBatchSize) {
      await this.batch(ops);
      return;
    }

    // Split into chunks and write sequentially
    for (let i = 0; i < ops.length; i += maxBatchSize) {
      const chunk = ops.slice(i, Math.min(i + maxBatchSize, ops.length));
      await this.batch(chunk);

      // Yield between chunks so the event loop can process I/O and timers.
      // Avoid full GC (Bun.gc(true)) here — it was causing stop-the-world
      // pauses during every UTXO flush, compounding the sync stall.
      await new Promise<void>(resolve => setTimeout(resolve, 0));
    }
  }

  /**
   * Get IBD-optimized batch size.
   */
  static getIBDBatchSize(): number {
    return IBD_BATCH_SIZE;
  }

  /**
   * Get default batch size.
   */
  static getDefaultBatchSize(): number {
    return DEFAULT_MAX_BATCH_SIZE;
  }

  // Chain work per-block (used by getblockheader/getblock RPC)

  async putChainWork(hash: Buffer, chainWork: bigint): Promise<void> {
    const op = this.buildChainWorkPutOp(hash, chainWork);
    await this.db.put(makeKey(op.prefix, op.key), op.value!);
  }

  /**
   * Build a {@link BatchOperation} that stores a block's cumulative chain
   * work, so it can ride a coins flush with the tip it belongs to.
   */
  buildChainWorkPutOp(hash: Buffer, chainWork: bigint): BatchOperation {
    // Store as 32-byte big-endian uint256
    const buf = Buffer.allocUnsafe(32);
    // Write bigint as big-endian 32 bytes
    let w = chainWork;
    for (let i = 31; i >= 0; i--) {
      buf[i] = Number(w & 0xffn);
      w >>= 8n;
    }
    return { type: 'put', prefix: DBPrefix.CHAIN_WORK, key: hash, value: buf };
  }

  async getChainWork(hash: Buffer): Promise<bigint | null> {
    const key = makeKey(DBPrefix.CHAIN_WORK, hash);
    const value = await this.db.get(key);
    if (value === undefined) {
      return null;
    }
    // Read as 32-byte big-endian uint256
    let result = 0n;
    for (let i = 0; i < 32; i++) {
      result = (result << 8n) | BigInt(value[i]);
    }
    return result;
  }

  // Undo data operations (for block disconnect / reorgs)

  async putUndoData(hash: Buffer, data: Buffer): Promise<void> {
    const key = makeKey(DBPrefix.UNDO, hash);
    await this.db.put(key, data);
  }

  async getUndoData(hash: Buffer): Promise<Buffer | null> {
    const key = makeKey(DBPrefix.UNDO, hash);
    const value = await this.db.get(key);
    if (value === undefined) {
      return null;
    }
    return value;
  }

  // Block file info operations (for flat file storage)

  /**
   * Store block file info for a file number.
   */
  async putBlockFileInfo(fileNum: number, info: Buffer): Promise<void> {
    const key = makeKey(DBPrefix.BLOCK_FILES, encodeFileNum(fileNum));
    await this.db.put(key, info);
  }

  /**
   * Get block file info for a file number.
   */
  async getBlockFileInfo(fileNum: number): Promise<Buffer | null> {
    const key = makeKey(DBPrefix.BLOCK_FILES, encodeFileNum(fileNum));
    try {
      const value = await this.db.get(key);
      if (value === undefined) {
        return null;
      }
      return value;
    } catch {
      return null;
    }
  }

  /**
   * Store the last block file number.
   */
  async putLastBlockFile(fileNum: number): Promise<void> {
    const key = makeKey(DBPrefix.LAST_BLOCK_FILE, Buffer.alloc(0));
    const buf = Buffer.alloc(4);
    buf.writeUInt32LE(fileNum, 0);
    await this.db.put(key, buf);
  }

  /**
   * Get the last block file number.
   */
  async getLastBlockFile(): Promise<number | null> {
    const key = makeKey(DBPrefix.LAST_BLOCK_FILE, Buffer.alloc(0));
    try {
      const value = await this.db.get(key);
      if (value === undefined) {
        return null;
      }
      return value.readUInt32LE(0);
    } catch {
      return null;
    }
  }

  /**
   * Store block position in flat file.
   */
  async putBlockPos(hash: Buffer, posData: Buffer): Promise<void> {
    const key = makeKey(DBPrefix.BLOCK_POS, hash);
    await this.db.put(key, posData);
  }

  /**
   * Get block position from flat file.
   */
  async getBlockPos(hash: Buffer): Promise<Buffer | null> {
    const key = makeKey(DBPrefix.BLOCK_POS, hash);
    try {
      const value = await this.db.get(key);
      if (value === undefined) {
        return null;
      }
      return value;
    } catch {
      return null;
    }
  }

  // Pruning state operations

  /**
   * One-time migration done-marker. Returns the stored record (opaque bytes)
   * or null when the named migration has not completed on this datadir.
   */
  async getMarker(name: string): Promise<Buffer | null> {
    const key = makeKey(DBPrefix.MARKER, Buffer.from(name, "utf8"));
    const value = await this.db.get(key);
    return value === undefined ? null : value;
  }

  /** Record that the named one-time migration completed. */
  async putMarker(name: string, record: Buffer): Promise<void> {
    const key = makeKey(DBPrefix.MARKER, Buffer.from(name, "utf8"));
    await this.db.put(key, record);
  }

  /**
   * Store pruning state metadata.
   */
  async putPruneState(havePruned: boolean, pruneTarget: number): Promise<void> {
    const key = makeKey(DBPrefix.PRUNE_STATE, Buffer.alloc(0));
    const buf = Buffer.alloc(9);
    buf.writeUInt8(havePruned ? 1 : 0, 0);
    buf.writeBigUInt64LE(BigInt(pruneTarget), 1);
    await this.db.put(key, buf);
  }

  /**
   * Get pruning state metadata.
   */
  async getPruneState(): Promise<{ havePruned: boolean; pruneTarget: number } | null> {
    const key = makeKey(DBPrefix.PRUNE_STATE, Buffer.alloc(0));
    try {
      const value = await this.db.get(key);
      if (value === undefined || value.length < 9) {
        return null;
      }
      return {
        havePruned: value.readUInt8(0) === 1,
        pruneTarget: Number(value.readBigUInt64LE(1)),
      };
    } catch {
      return null;
    }
  }

  /**
   * Update a block index record's status flags.
   */
  async updateBlockStatus(hash: Buffer, status: number): Promise<void> {
    const record = await this.getBlockIndex(hash);
    if (record) {
      record.status = status;
      // Metadata-only update on the per-hash block index (Core raises/lowers
      // nStatus on a CBlockIndex without ever calling CChain::SetTip).  Must
      // NOT rewrite the active height->hash index, or a side-branch/fork block
      // whose status is bumped (e.g. storeSideBranchBlock setting HAVE_DATA)
      // would clobber the active tip's height entry.
      await this.putBlockIndex(hash, record, { writeHeightIndex: false });
    }
  }

  /**
   * Iterate all block index entries in the DB.
   * Yields [hash (32B internal-byte-order), BlockIndexRecord] pairs.
   * Used by the startup nTx migration.
   */
  async *iterateBlockIndexEntries(): AsyncGenerator<[Buffer, BlockIndexRecord]> {
    const prefix = Buffer.from([DBPrefix.BLOCK_INDEX]);
    const prefixEnd = Buffer.from([DBPrefix.BLOCK_INDEX + 1]);
    const iterator = this.db.iterator({
      gte: prefix,
      lt: prefixEnd,
    });
    try {
      for await (const [key, value] of iterator) {
        // key = prefix(1) + hash(32)
        if (key.length < 33) continue;
        const hash = Buffer.from(key.subarray(1, 33));
        let record: BlockIndexRecord;
        try {
          record = deserializeBlockIndex(value);
        } catch {
          continue;
        }
        yield [hash, record];
      }
    } finally {
      await iterator.close();
    }
  }

  /**
   * Update only the nTx field of a block index record.
   * No-op if the record does not exist.
   */
  async updateBlockIndexNTx(hash: Buffer, nTx: number): Promise<void> {
    const record = await this.getBlockIndex(hash);
    if (record && record.nTx === 0 && nTx > 0) {
      record.nTx = nTx;
      // Metadata-only nTx backfill — never a CChain::SetTip event, so it must
      // not touch the active height->hash index.  Active-connect callers that
      // rely on the height index being advanced write it explicitly (see
      // BlockSync.connectBlock's non-flush path).
      await this.putBlockIndex(hash, record, { writeHeightIndex: false });
    }
  }

  /**
   * Overwrite the nTx field of a block index record (any value, including 0 =
   * Core's "block data never received"). Used only by the startup nTx
   * provenance reconcile; metadata-only, never touches the height index.
   */
  async setBlockIndexNTx(hash: Buffer, nTx: number): Promise<void> {
    const record = await this.getBlockIndex(hash);
    if (record && record.nTx !== nTx) {
      record.nTx = nTx;
      await this.putBlockIndex(hash, record, { writeHeightIndex: false });
    }
  }
}

/**
 * Encode a file number as 4-byte little-endian.
 */
function encodeFileNum(fileNum: number): Buffer {
  const buf = Buffer.alloc(4);
  buf.writeUInt32LE(fileNum, 0);
  return buf;
}
