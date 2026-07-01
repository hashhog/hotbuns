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

/**
 * Construct a prefixed key for database storage.
 * Writes prefix byte directly into a new buffer instead of concat.
 */
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

  constructor(dbPath: string) {
    this.dbPath = dbPath;
    this.db = new ClassicLevel<Buffer, Buffer>(dbPath, {
      keyEncoding: 'buffer',
      valueEncoding: 'buffer',
      // 256 MB LevelDB block cache (increased for 2GB UTXO cache budget)
      cacheSize: COINS_DB_BLOCK_CACHE_BYTES,
      // 16 MB write buffer
      writeBufferSize: 16 * 1024 * 1024,
      // Limit open file handles to cap mmap RSS overhead.
      // LevelDB opens table files with mmap; at 380K+ blocks the UTXO
      // SST files number in the thousands, each consuming kernel page
      // cache counted in RSS. 256 files * ~2MB = ~512MB mmap ceiling.
      // Default (1000) was contributing ~1-2GB of RSS.
      maxOpenFiles: 256,
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
    const value = serializeBlockIndex(record);
    await this.db.put(key, value);

    // Also store the height -> hash (active-chain) mapping — hotbuns's analogue
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
    if (opts?.writeHeightIndex !== false) {
      const heightKey = makeKey(DBPrefix.HEADER, encodeHeight(record.height));
      await this.db.put(heightKey, hash);
    }
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
    const key = makeKey(DBPrefix.HEADER, encodeHeight(height));
    await this.db.del(key);
  }

  /** Set the active-chain height -> hash mapping at `height` (standalone,
   *  non-batch path). Counterpart to {@link buildHeightHashPutOp}. */
  async putBlockHashByHeight(height: number, hash: Buffer): Promise<void> {
    if (this.closing) {
      return;
    }
    const key = makeKey(DBPrefix.HEADER, encodeHeight(height));
    await this.db.put(key, hash);
  }

  async getBlockIndex(hash: Buffer): Promise<BlockIndexRecord | null> {
    const key = makeKey(DBPrefix.BLOCK_INDEX, hash);
    const value = await this.db.get(key);
    if (value === undefined) {
      return null;
    }
    return deserializeBlockIndex(value);
  }

  async getBlockHashByHeight(height: number): Promise<Buffer | null> {
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
    const existing = await this.getBlockIndex(blockHash);
    if (!existing) {
      return null;
    }
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
    const key = makeKey(DBPrefix.CHAIN_WORK, hash);
    // Store as 32-byte big-endian uint256
    const buf = Buffer.allocUnsafe(32);
    // Write bigint as big-endian 32 bytes
    let w = chainWork;
    for (let i = 31; i >= 0; i--) {
      buf[i] = Number(w & 0xffn);
      w >>= 8n;
    }
    await this.db.put(key, buf);
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
}

/**
 * Encode a file number as 4-byte little-endian.
 */
function encodeFileNum(fileNum: number): Buffer {
  const buf = Buffer.alloc(4);
  buf.writeUInt32LE(fileNum, 0);
  return buf;
}
