/**
 * UTXO cache layer: multi-layer cache with database backing.
 *
 * Implements a layered CoinsView design following Bitcoin Core:
 * - CoinsView: abstract interface for UTXO lookups
 * - CoinsViewDB: reads/writes directly to database
 * - CoinsViewCache: in-memory cache with dirty/fresh flags
 *
 * Key optimizations:
 * - FRESH flag: coin doesn't exist in backing store; if spent before flush, skip DB write
 * - DIRTY flag: coin differs from backing store; needs flush
 * - Batch flushing: accumulates changes and writes atomically
 * - Memory management: flushes when cache exceeds dbcache limit
 *
 * Reference: /home/max/hashhog/bitcoin/src/coins.cpp and coins.h
 */

import type { ChainDB, UTXOEntry, BatchOperation } from "../storage/database.js";
import { DBPrefix } from "../storage/database.js";
import type { Transaction, OutPoint } from "../validation/tx.js";
import { BufferWriter, BufferReader } from "../wire/serialization.js";

/** Default max cache size in bytes (~200MB). */
const DEFAULT_DBCACHE_BYTES = 200 * 1024 * 1024;

/**
 * Estimated overhead per cache entry in the JS heap.
 * Empirical measurement on testnet4: ~3KB per Map entry including
 * the key string (67-char hex), CoinEntry/Coin/txOut nested objects,
 * Buffer with ArrayBuffer backing, bigint, and Map internal bookkeeping.
 */
const CACHE_ENTRY_OVERHEAD = 3000;

/**
 * A single coin in the UTXO set.
 * Corresponds to Bitcoin Core's Coin class.
 */
export interface Coin {
  /** The transaction output: value and scriptPubKey. */
  txOut: {
    value: bigint;
    scriptPubKey: Buffer;
  };
  /** Height at which the containing transaction was included. */
  height: number;
  /** Whether the containing transaction was a coinbase. */
  isCoinbase: boolean;
}

/**
 * A cache entry with flags for cache management.
 * Corresponds to Bitcoin Core's CCoinsCacheEntry.
 */
export interface CoinEntry {
  /** The coin data (null if spent). */
  coin: Coin | null;
  /** True if this entry differs from the backing store. */
  dirty: boolean;
  /** True if this coin doesn't exist in the backing store. */
  fresh: boolean;
}

/**
 * Create an outpoint key string for Map lookup.
 * Format: txid_hex:vout
 */
function outpointKey(txid: Buffer, vout: number): string {
  return `${txid.toString("hex")}:${vout}`;
}

/**
 * Create an outpoint key from OutPoint.
 */
function outpointKeyFromOutpoint(outpoint: OutPoint): string {
  return outpointKey(outpoint.txid, outpoint.vout);
}

/**
 * Parse an outpoint key back to txid and vout.
 */
function parseOutpointKey(key: string): { txid: Buffer; vout: number } {
  const colonIndex = key.lastIndexOf(":");
  if (colonIndex === -1) {
    throw new Error(`Invalid outpoint key: ${key}`);
  }
  const txid = Buffer.from(key.slice(0, colonIndex), "hex");
  const vout = parseInt(key.slice(colonIndex + 1), 10);
  return { txid, vout };
}

/**
 * Encode a UTXO key for database storage.
 * Format: txid (32 bytes) + vout (4 bytes LE)
 *
 * Matches the format used by ChainDB.getUTXO / putUTXO.
 */
function encodeDBKey(txid: Buffer, vout: number): Buffer {
  const buf = Buffer.alloc(36);
  txid.copy(buf, 0);
  buf.writeUInt32LE(vout, 32);
  return buf;
}

/**
 * Serialize a Coin for database storage.
 * Format matches the existing ChainDB UTXOEntry format:
 * - height (4 bytes LE)
 * - coinbase (1 byte)
 * - amount (8 bytes LE)
 * - scriptPubKey (varint length + bytes)
 */
function serializeCoin(coin: Coin): Buffer {
  const writer = new BufferWriter();
  writer.writeUInt32LE(coin.height);
  writer.writeUInt8(coin.isCoinbase ? 1 : 0);
  writer.writeUInt64LE(coin.txOut.value);
  writer.writeVarBytes(coin.txOut.scriptPubKey);
  return writer.toBuffer();
}

/**
 * Deserialize a Coin from database storage.
 */
function deserializeCoin(data: Buffer): Coin {
  const reader = new BufferReader(data);
  const height = reader.readUInt32LE();
  const isCoinbase = reader.readUInt8() === 1;
  const value = reader.readUInt64LE();
  const scriptPubKey = reader.readVarBytes();
  return {
    txOut: { value, scriptPubKey },
    height,
    isCoinbase,
  };
}

/**
 * Estimate memory usage of a Coin.
 */
function coinMemoryUsage(coin: Coin | null): number {
  if (!coin) return 0;
  // Base size: object overhead + bigint + number + boolean + scriptPubKey
  return 48 + coin.txOut.scriptPubKey.length;
}

/**
 * Abstract interface for UTXO set access.
 * Corresponds to Bitcoin Core's CCoinsView.
 */
export abstract class CoinsView {
  /**
   * Retrieve a coin for the given outpoint.
   * Returns null if the coin doesn't exist or is spent.
   */
  abstract getCoin(outpoint: OutPoint): Promise<Coin | null>;

  /**
   * Check if a coin exists (and is unspent).
   */
  abstract haveCoin(outpoint: OutPoint): Promise<boolean>;

  /**
   * Get the block hash representing the current view state.
   */
  abstract getBestBlock(): Promise<Buffer>;

  /**
   * Estimate the database size (0 if not applicable).
   */
  estimateSize(): number {
    return 0;
  }
}

/**
 * CoinsView backed by the database.
 * Corresponds to Bitcoin Core's CCoinsViewDB.
 */
export class CoinsViewDB extends CoinsView {
  private db: ChainDB;
  private bestBlockHash: Buffer;

  constructor(db: ChainDB) {
    super();
    this.db = db;
    this.bestBlockHash = Buffer.alloc(32); // Set from chain state
  }

  /**
   * Set the best block hash (called when chain state is loaded).
   */
  setBestBlock(hash: Buffer): void {
    this.bestBlockHash = hash;
  }

  async getCoin(outpoint: OutPoint): Promise<Coin | null> {
    const entry = await this.db.getUTXO(outpoint.txid, outpoint.vout);
    if (!entry) return null;
    // Convert UTXOEntry to Coin
    return {
      txOut: {
        value: entry.amount,
        scriptPubKey: entry.scriptPubKey,
      },
      height: entry.height,
      isCoinbase: entry.coinbase,
    };
  }

  async haveCoin(outpoint: OutPoint): Promise<boolean> {
    const entry = await this.db.getUTXO(outpoint.txid, outpoint.vout);
    return entry !== null;
  }

  async getBestBlock(): Promise<Buffer> {
    return this.bestBlockHash;
  }

  /**
   * Write a batch of coin changes to the database.
   * Called by CoinsViewCache during flush.
   *
   * @param entries - Cache entries to flush
   * @param hashBlock - Best block hash for this view state
   * @param extraOps - Additional operations to include atomically (e.g., chain state)
   */
  async batchWrite(
    entries: Map<string, CoinEntry>,
    hashBlock: Buffer,
    extraOps?: BatchOperation[]
  ): Promise<void> {
    const ops: BatchOperation[] = [];

    for (const [key, entry] of entries) {
      if (!entry.dirty) continue;

      const { txid, vout } = parseOutpointKey(key);
      const dbKey = encodeDBKey(txid, vout);

      if (entry.coin === null) {
        // Coin was spent - delete from DB unless it was FRESH
        // (FRESH means it never existed in DB, so no need to delete)
        if (!entry.fresh) {
          ops.push({
            type: "del",
            prefix: DBPrefix.UTXO,
            key: dbKey,
          });
        }
      } else {
        // Coin exists - write to DB
        ops.push({
          type: "put",
          prefix: DBPrefix.UTXO,
          key: dbKey,
          value: serializeCoin(entry.coin),
        });
      }
    }

    // Append any extra operations so they are committed atomically
    // with the UTXO changes (e.g., chain state update).
    if (extraOps) {
      ops.push(...extraOps);
    }

    if (ops.length > 0) {
      await this.db.batch(ops);
    }

    this.bestBlockHash = hashBlock;
  }
}

/**
 * In-memory cache layer on top of another CoinsView.
 * Corresponds to Bitcoin Core's CCoinsViewCache.
 *
 * Key behaviors:
 * - Lookups check cache first, then fall through to backing view
 * - Changes are marked DIRTY and accumulated until flush
 * - FRESH flag tracks coins that don't exist in backing store
 * - If a FRESH coin is spent before flush, it can be deleted without DB write
 */
export class CoinsViewCache extends CoinsView {
  private base: CoinsView | CoinsViewDB;
  private cache: Map<string, CoinEntry>;
  private hashBlock: Buffer;

  // Memory management
  private cachedCoinsUsage: number;
  private dirtyCount: number;
  private maxCacheBytes: number;

  // Statistics
  private hits: number;
  private misses: number;
  private flushCount: number;

  constructor(
    base: CoinsView | CoinsViewDB,
    maxCacheBytes: number = DEFAULT_DBCACHE_BYTES
  ) {
    super();
    this.base = base;
    this.cache = new Map();
    this.hashBlock = Buffer.alloc(32);
    this.cachedCoinsUsage = 0;
    this.dirtyCount = 0;
    this.maxCacheBytes = maxCacheBytes;
    this.hits = 0;
    this.misses = 0;
    this.flushCount = 0;
  }

  /**
   * Fetch a coin, checking cache first then backing store.
   */
  async getCoin(outpoint: OutPoint): Promise<Coin | null> {
    const key = outpointKeyFromOutpoint(outpoint);

    // Check cache first
    const cached = this.cache.get(key);
    if (cached !== undefined) {
      this.hits++;
      return cached.coin;
    }

    this.misses++;

    // Fetch from backing store
    const coin = await this.base.getCoin(outpoint);
    if (coin) {
      // Cache for future lookups (not dirty, not fresh)
      const entry: CoinEntry = {
        coin,
        dirty: false,
        fresh: false,
      };
      this.cache.set(key, entry);
      this.cachedCoinsUsage += coinMemoryUsage(coin) + CACHE_ENTRY_OVERHEAD;
    }

    return coin;
  }

  /**
   * Check if a coin exists without fetching full data.
   */
  async haveCoin(outpoint: OutPoint): Promise<boolean> {
    const key = outpointKeyFromOutpoint(outpoint);

    // Check cache first
    const cached = this.cache.get(key);
    if (cached !== undefined) {
      return cached.coin !== null;
    }

    // Check backing store
    return this.base.haveCoin(outpoint);
  }

  /**
   * Check if a coin is in the cache (without DB lookup).
   */
  haveCoinInCache(outpoint: OutPoint): boolean {
    const key = outpointKeyFromOutpoint(outpoint);
    const cached = this.cache.get(key);
    return cached !== undefined && cached.coin !== null;
  }

  /**
   * Get a coin from cache only (no DB lookup).
   * Returns null if not in cache or if spent.
   */
  getCoinFromCache(outpoint: OutPoint): Coin | null {
    const key = outpointKeyFromOutpoint(outpoint);
    const cached = this.cache.get(key);
    if (cached === undefined || cached.coin === null) {
      return null;
    }
    this.hits++;
    return cached.coin;
  }

  /**
   * Add a new coin to the cache.
   *
   * @param outpoint - The outpoint identifying this coin
   * @param coin - The coin data
   * @param possibleOverwrite - True if an unspent coin may already exist
   */
  addCoin(outpoint: OutPoint, coin: Coin, possibleOverwrite: boolean): void {
    const key = outpointKeyFromOutpoint(outpoint);

    // Skip unspendable outputs (OP_RETURN)
    if (
      coin.txOut.scriptPubKey.length > 0 &&
      coin.txOut.scriptPubKey[0] === 0x6a
    ) {
      return;
    }

    const existing = this.cache.get(key);
    let fresh = false;

    if (!possibleOverwrite) {
      // This should be a new coin
      if (existing && existing.coin !== null) {
        throw new Error(
          "Attempted to overwrite an unspent coin (when possibleOverwrite is false)"
        );
      }
      // Mark as FRESH if the existing entry is not DIRTY
      // (If DIRTY and spent, spentness hasn't been flushed yet,
      // so we can't mark it FRESH or we'd lose the delete)
      fresh = !existing || !existing.dirty;
    }

    // Update memory usage
    if (existing) {
      if (existing.dirty) this.dirtyCount--;
      this.cachedCoinsUsage -= coinMemoryUsage(existing.coin);
      // Don't add CACHE_ENTRY_OVERHEAD again - it was counted when the entry was first created
    }

    const entry: CoinEntry = {
      coin,
      dirty: true,
      fresh,
    };

    this.cache.set(key, entry);
    this.dirtyCount++;
    this.cachedCoinsUsage += coinMemoryUsage(coin) + (existing ? 0 : CACHE_ENTRY_OVERHEAD);
  }

  /**
   * Spend a coin (mark as spent in cache).
   *
   * @param outpoint - The outpoint to spend
   * @param moveout - If provided, the coin data is moved here
   * @returns True if the coin existed and was spent
   */
  async spendCoin(outpoint: OutPoint, moveout?: { coin: Coin | null }): Promise<boolean> {
    const key = outpointKeyFromOutpoint(outpoint);

    // First, ensure the coin is in the cache
    let entry = this.cache.get(key);

    if (entry === undefined) {
      // Try to fetch from backing store
      const coin = await this.base.getCoin(outpoint);
      if (!coin) return false;

      // Add to cache as clean
      entry = {
        coin,
        dirty: false,
        fresh: false,
      };
      this.cache.set(key, entry);
      this.cachedCoinsUsage += coinMemoryUsage(coin) + CACHE_ENTRY_OVERHEAD;
    }

    if (entry.coin === null) {
      // Already spent
      return false;
    }

    // Move out the coin if requested
    if (moveout) {
      moveout.coin = entry.coin;
    }

    // Update memory usage
    if (entry.dirty) this.dirtyCount--;
    this.cachedCoinsUsage -= coinMemoryUsage(entry.coin);

    // If FRESH, we can just delete the entry entirely
    // (it was created and spent within this cache session)
    if (entry.fresh) {
      this.cache.delete(key);
    } else {
      // Mark as spent and dirty
      entry.coin = null;
      entry.dirty = true;
      this.dirtyCount++;
    }

    return true;
  }

  /**
   * Synchronous spend for coins already in cache.
   * Throws if the coin is not in cache.
   */
  spendCoinSync(outpoint: OutPoint, moveout?: { coin: Coin | null }): boolean {
    const key = outpointKeyFromOutpoint(outpoint);
    const entry = this.cache.get(key);

    if (entry === undefined) {
      throw new Error(
        `Coin not in cache (must be pre-loaded): ${outpoint.txid.toString("hex")}:${outpoint.vout}`
      );
    }

    if (entry.coin === null) {
      return false;
    }

    if (moveout) {
      moveout.coin = entry.coin;
    }

    if (entry.dirty) this.dirtyCount--;
    this.cachedCoinsUsage -= coinMemoryUsage(entry.coin);

    if (entry.fresh) {
      this.cache.delete(key);
    } else {
      entry.coin = null;
      entry.dirty = true;
      this.dirtyCount++;
    }

    return true;
  }

  /**
   * Remove a non-dirty entry from the cache.
   * Used to free memory without losing data (can be re-fetched from DB).
   */
  uncache(outpoint: OutPoint): void {
    const key = outpointKeyFromOutpoint(outpoint);
    const entry = this.cache.get(key);
    if (entry && !entry.dirty) {
      this.cachedCoinsUsage -= coinMemoryUsage(entry.coin) + CACHE_ENTRY_OVERHEAD;
      this.cache.delete(key);
    }
  }

  /**
   * Get the best block hash for this view.
   */
  async getBestBlock(): Promise<Buffer> {
    if (this.hashBlock.every((b) => b === 0)) {
      this.hashBlock = await this.base.getBestBlock();
    }
    return this.hashBlock;
  }

  /**
   * Set the best block hash.
   */
  setBestBlock(hash: Buffer): void {
    this.hashBlock = hash;
  }

  /**
   * Flush all dirty entries to the backing store and clear the cache.
   *
   * After flush, the cache is empty and all changes are persisted.
   *
   * @param extraOps - Additional DB operations committed atomically with the flush
   */
  async flush(extraOps?: BatchOperation[]): Promise<void> {
    if (!(this.base instanceof CoinsViewDB)) {
      // For layered caches, we'd need to handle this differently
      // For now, assume base is always CoinsViewDB
      throw new Error("flush() requires CoinsViewDB as base");
    }

    await this.base.batchWrite(this.cache, this.hashBlock, extraOps);

    // Clear the cache
    this.cache.clear();
    this.cachedCoinsUsage = 0;
    this.dirtyCount = 0;
    this.flushCount++;
  }

  /**
   * Sync dirty entries to backing store but keep cache contents.
   * Spent entries are erased, unspent entries become clean.
   *
   * @param extraOps - Additional DB operations committed atomically with the sync
   */
  async sync(extraOps?: BatchOperation[]): Promise<void> {
    if (!(this.base instanceof CoinsViewDB)) {
      throw new Error("sync() requires CoinsViewDB as base");
    }

    await this.base.batchWrite(this.cache, this.hashBlock, extraOps);

    // Update cache: remove spent entries, clear dirty flags
    for (const [key, entry] of this.cache) {
      if (entry.coin === null) {
        // Remove spent entries
        this.cachedCoinsUsage -= CACHE_ENTRY_OVERHEAD;
        this.cache.delete(key);
      } else {
        // Clear dirty flag
        entry.dirty = false;
        entry.fresh = false;
      }
    }

    this.dirtyCount = 0;
    this.flushCount++;

    // Evict clean entries if the cache exceeds the memory limit.
    // Clean entries can always be re-fetched from the database.
    if (this.cachedCoinsUsage > this.maxCacheBytes) {
      this.evictCleanEntries();
    }
  }

  /**
   * Evict non-dirty entries from the cache to free memory.
   * Removes clean entries until usage drops below the target (90% of max).
   */
  private evictCleanEntries(): void {
    const target = Math.floor(this.maxCacheBytes * 0.50);
    for (const [key, entry] of this.cache) {
      if (this.cachedCoinsUsage <= target) {
        break;
      }
      if (!entry.dirty) {
        this.cachedCoinsUsage -= coinMemoryUsage(entry.coin) + CACHE_ENTRY_OVERHEAD;
        this.cache.delete(key);
      }
    }
  }

  /**
   * Check if the cache should be flushed based on memory usage.
   */
  shouldFlush(): boolean {
    return this.cachedCoinsUsage >= this.maxCacheBytes;
  }

  /**
   * Get current cache memory usage in bytes.
   */
  getMemoryUsage(): number {
    return this.cachedCoinsUsage;
  }

  /**
   * Get the number of entries in the cache.
   */
  getCacheSize(): number {
    return this.cache.size;
  }

  /**
   * Get the number of dirty entries.
   */
  getDirtyCount(): number {
    return this.dirtyCount;
  }

  /**
   * Get cache statistics.
   */
  getStats(): {
    size: number;
    dirtyCount: number;
    memoryUsage: number;
    maxMemory: number;
    hits: number;
    misses: number;
    flushCount: number;
  } {
    return {
      size: this.cache.size,
      dirtyCount: this.dirtyCount,
      memoryUsage: this.cachedCoinsUsage,
      maxMemory: this.maxCacheBytes,
      hits: this.hits,
      misses: this.misses,
      flushCount: this.flushCount,
    };
  }

  /**
   * Reset statistics.
   */
  resetStats(): void {
    this.hits = 0;
    this.misses = 0;
  }
}

// ============================================================================
// Legacy compatibility exports
// ============================================================================

/** UTXO entry for legacy code compatibility. */
export type { UTXOEntry };

/** Cache statistics for monitoring. */
export interface UTXOCacheStats {
  hits: number;
  misses: number;
  evictions: number;
  flushes: number;
  currentSize: number;
  maxSize: number;
}

/**
 * Interface for UTXO set operations (legacy).
 */
export interface UTXOSet {
  addTransaction(
    txid: Buffer,
    tx: Transaction,
    height: number,
    isCoinbase: boolean
  ): void;
  spendOutput(outpoint: OutPoint): UTXOEntry;
  getUTXO(outpoint: OutPoint): UTXOEntry | null;
  hasUTXO(outpoint: OutPoint): boolean;
}

/**
 * Data stored for undo operations during block disconnect.
 */
export interface SpentUTXO {
  txid: Buffer;
  vout: number;
  entry: UTXOEntry;
}

/**
 * Serialize undo data (list of spent UTXOs) for storage.
 */
export function serializeUndoData(spentOutputs: SpentUTXO[]): Buffer {
  const writer = new BufferWriter();
  writer.writeVarInt(spentOutputs.length);

  for (const spent of spentOutputs) {
    writer.writeHash(spent.txid);
    writer.writeUInt32LE(spent.vout);
    writer.writeUInt32LE(spent.entry.height);
    writer.writeUInt8(spent.entry.coinbase ? 1 : 0);
    writer.writeUInt64LE(spent.entry.amount);
    writer.writeVarBytes(spent.entry.scriptPubKey);
  }

  return writer.toBuffer();
}

/**
 * Deserialize undo data from storage.
 */
export function deserializeUndoData(data: Buffer): SpentUTXO[] {
  const reader = new BufferReader(data);
  const count = reader.readVarInt();
  const spentOutputs: SpentUTXO[] = [];

  for (let i = 0; i < count; i++) {
    const txid = reader.readHash();
    const vout = reader.readUInt32LE();
    const height = reader.readUInt32LE();
    const coinbase = reader.readUInt8() === 1;
    const amount = reader.readUInt64LE();
    const scriptPubKey = reader.readVarBytes();

    spentOutputs.push({
      txid,
      vout,
      entry: { height, coinbase, amount, scriptPubKey },
    });
  }

  return spentOutputs;
}

/**
 * UTXOManager: wrapper around CoinsViewCache for legacy compatibility.
 *
 * This class maintains the same interface as the old UTXOManager but
 * uses the new layered cache system internally.
 */
export class UTXOManager implements UTXOSet {
  private viewDB: CoinsViewDB;
  private cache: CoinsViewCache;
  private maxCacheBytes: number;
  private maxCacheSize: number;

  // Legacy tracking
  private stats: UTXOCacheStats;

  constructor(db: ChainDB, maxCacheBytes: number = DEFAULT_DBCACHE_BYTES) {
    this.viewDB = new CoinsViewDB(db);
    this.cache = new CoinsViewCache(this.viewDB, maxCacheBytes);
    this.maxCacheBytes = maxCacheBytes;
    this.maxCacheSize = Math.floor(maxCacheBytes / CACHE_ENTRY_OVERHEAD);

    this.stats = {
      hits: 0,
      misses: 0,
      evictions: 0,
      flushes: 0,
      currentSize: 0,
      maxSize: this.maxCacheSize,
    };
  }

  /**
   * Get the underlying CoinsViewCache.
   */
  getCoinsViewCache(): CoinsViewCache {
    return this.cache;
  }

  /**
   * Get the underlying CoinsViewDB.
   */
  getCoinsViewDB(): CoinsViewDB {
    return this.viewDB;
  }

  /**
   * Get cache statistics.
   */
  getStats(): UTXOCacheStats {
    const cacheStats = this.cache.getStats();
    return {
      hits: cacheStats.hits,
      misses: cacheStats.misses,
      evictions: 0, // New system doesn't evict, it flushes
      flushes: cacheStats.flushCount,
      currentSize: cacheStats.size,
      maxSize: this.maxCacheSize,
    };
  }

  /**
   * Reset cache statistics.
   */
  resetStats(): void {
    this.cache.resetStats();
  }

  /**
   * Add all outputs from a transaction as new UTXOs.
   */
  addTransaction(
    txid: Buffer,
    tx: Transaction,
    height: number,
    isCoinbase: boolean
  ): void {
    for (let vout = 0; vout < tx.outputs.length; vout++) {
      const output = tx.outputs[vout];
      const outpoint: OutPoint = { txid, vout };

      const coin: Coin = {
        txOut: {
          value: output.value,
          scriptPubKey: output.scriptPubKey,
        },
        height,
        isCoinbase,
      };

      // Coinbases can always be overwritten (pre-BIP30 duplicates)
      this.cache.addCoin(outpoint, coin, isCoinbase);
    }
  }

  /**
   * Spend an input (remove the referenced UTXO).
   * Returns the spent UTXO entry or throws if not found.
   */
  spendOutput(outpoint: OutPoint): UTXOEntry {
    const moveout: { coin: Coin | null } = { coin: null };
    const success = this.cache.spendCoinSync(outpoint, moveout);

    if (!success || !moveout.coin) {
      throw new Error(
        `UTXO not in cache (must be pre-loaded): ${outpoint.txid.toString("hex")}:${outpoint.vout}`
      );
    }

    // Convert Coin to UTXOEntry
    return {
      height: moveout.coin.height,
      coinbase: moveout.coin.isCoinbase,
      amount: moveout.coin.txOut.value,
      scriptPubKey: moveout.coin.txOut.scriptPubKey,
    };
  }

  /**
   * Spend an output asynchronously, loading from DB if needed.
   */
  async spendOutputAsync(outpoint: OutPoint): Promise<UTXOEntry> {
    const moveout: { coin: Coin | null } = { coin: null };
    const success = await this.cache.spendCoin(outpoint, moveout);

    if (!success || !moveout.coin) {
      throw new Error(
        `UTXO not found: ${outpoint.txid.toString("hex")}:${outpoint.vout}`
      );
    }

    return {
      height: moveout.coin.height,
      coinbase: moveout.coin.isCoinbase,
      amount: moveout.coin.txOut.value,
      scriptPubKey: moveout.coin.txOut.scriptPubKey,
    };
  }

  /**
   * Look up a UTXO without spending it.
   * Returns null if not found in cache.
   * Use getUTXOAsync for database lookup.
   */
  getUTXO(outpoint: OutPoint): UTXOEntry | null {
    const coin = this.cache.getCoinFromCache(outpoint);
    if (!coin) return null;

    return {
      height: coin.height,
      coinbase: coin.isCoinbase,
      amount: coin.txOut.value,
      scriptPubKey: coin.txOut.scriptPubKey,
    };
  }

  /**
   * Look up a UTXO asynchronously, checking database if not in cache.
   */
  async getUTXOAsync(outpoint: OutPoint): Promise<UTXOEntry | null> {
    const coin = await this.cache.getCoin(outpoint);
    if (!coin) return null;

    return {
      height: coin.height,
      coinbase: coin.isCoinbase,
      amount: coin.txOut.value,
      scriptPubKey: coin.txOut.scriptPubKey,
    };
  }

  /**
   * Check if a UTXO exists in cache.
   */
  hasUTXO(outpoint: OutPoint): boolean {
    return this.cache.haveCoinInCache(outpoint);
  }

  /**
   * Check if a UTXO exists, checking database if not in cache.
   */
  async hasUTXOAsync(outpoint: OutPoint): Promise<boolean> {
    return this.cache.haveCoin(outpoint);
  }

  /**
   * Add a UTXO entry directly (used during block disconnect to restore spent UTXOs).
   */
  restoreUTXO(txid: Buffer, vout: number, entry: UTXOEntry): void {
    const outpoint: OutPoint = { txid, vout };
    const coin: Coin = {
      txOut: {
        value: entry.amount,
        scriptPubKey: entry.scriptPubKey,
      },
      height: entry.height,
      isCoinbase: entry.coinbase,
    };
    // Restoring a spent UTXO is an overwrite of a spent entry
    this.cache.addCoin(outpoint, coin, true);
  }

  /**
   * Remove a UTXO directly (used during block disconnect to remove outputs).
   */
  async removeUTXO(txid: Buffer, vout: number): Promise<void> {
    const outpoint: OutPoint = { txid, vout };
    await this.cache.spendCoin(outpoint);
  }

  /**
   * Flush cached changes to database as an atomic batch.
   *
   * @param extraOps - Additional DB operations committed atomically with the flush
   */
  async flush(extraOps?: BatchOperation[]): Promise<void> {
    if (this.cache.shouldFlush() || this.cache.getDirtyCount() > 0) {
      await this.cache.flush(extraOps);
    } else if (extraOps && extraOps.length > 0) {
      // Even if nothing to flush, still write the extra ops
      const bestBlock = await this.cache.getBestBlock();
      await this.viewDB.batchWrite(new Map(), bestBlock, extraOps);
    }
  }

  /**
   * Flush only dirty entries to DB.
   *
   * @param extraOps - Additional DB operations committed atomically with the sync
   */
  async flushDirty(extraOps?: BatchOperation[]): Promise<void> {
    await this.cache.sync(extraOps);

    // If the cache is still over the limit after sync+eviction,
    // do a full flush which clears everything.
    if (this.cache.shouldFlush()) {
      await this.cache.flush();
    }
  }

  /**
   * Clear the in-memory cache.
   */
  clearCache(): void {
    // Create a new cache
    this.cache = new CoinsViewCache(this.viewDB, this.maxCacheBytes);
  }

  /**
   * Pre-load a UTXO into the cache from the database.
   */
  async preloadUTXO(outpoint: OutPoint): Promise<boolean> {
    const coin = await this.cache.getCoin(outpoint);
    return coin !== null;
  }

  /**
   * Pre-load multiple UTXOs in batch (parallel LevelDB reads).
   */
  async preloadUTXOs(outpoints: OutPoint[]): Promise<number> {
    // Filter out outpoints already in cache to avoid unnecessary DB reads
    const toLoad: OutPoint[] = [];
    let loaded = 0;
    for (const outpoint of outpoints) {
      if (this.cache.haveCoinInCache(outpoint)) {
        loaded++;
      } else {
        toLoad.push(outpoint);
      }
    }
    if (toLoad.length === 0) return loaded;

    // Fire all DB reads in parallel
    const results = await Promise.all(
      toLoad.map((op) => this.cache.getCoin(op))
    );
    for (const coin of results) {
      if (coin) loaded++;
    }
    return loaded;
  }

  /**
   * Get estimated memory usage of the cache in bytes.
   */
  getEstimatedMemoryUsage(): number {
    return this.cache.getMemoryUsage();
  }

  /**
   * Get the maximum cache size in entries.
   */
  getMaxCacheSize(): number {
    return this.maxCacheSize;
  }

  /**
   * Set a new maximum cache size in bytes.
   */
  setMaxCacheBytes(maxBytes: number): void {
    this.maxCacheBytes = maxBytes;
    this.maxCacheSize = Math.floor(maxBytes / CACHE_ENTRY_OVERHEAD);
  }

  /**
   * Get the number of UTXOs currently in the cache.
   */
  getCacheSize(): number {
    return this.cache.getCacheSize();
  }

  /**
   * Get the number of pending operations.
   */
  getPendingCount(): number {
    return this.cache.getDirtyCount();
  }

  /**
   * Get the number of dirty entries pending flush.
   */
  getDirtyCount(): number {
    return this.cache.getDirtyCount();
  }

  /**
   * Set the best block hash.
   */
  setBestBlock(hash: Buffer): void {
    this.cache.setBestBlock(hash);
    this.viewDB.setBestBlock(hash);
  }
}
