/**
 * UTXO set management: tracking unspent transaction outputs.
 *
 * Implements a write-through cache with LRU eviction for efficient UTXO lookups
 * and batch persistence to the database. UTXOs are added when blocks are connected
 * and removed when spent.
 *
 * Performance optimizations:
 * - LRU eviction: tracks access order and evicts least-recently-used clean entries
 * - Dirty tracking: only flushes modified entries to reduce write amplification
 * - Configurable cache size: defaults to ~450 MB (~5M entries at ~90 bytes each)
 * - Cache statistics: tracks hit/miss rates for monitoring
 */

import type { ChainDB, UTXOEntry, BatchOperation } from "../storage/database.js";
import { DBPrefix } from "../storage/database.js";
import type { Transaction, OutPoint } from "../validation/tx.js";
import { BufferWriter, BufferReader } from "../wire/serialization.js";

/** Estimated bytes per UTXO entry in cache (for size calculations). */
const BYTES_PER_UTXO_ENTRY = 90;

/** Default max cache size in bytes (~450 MB = ~5M entries). */
const DEFAULT_MAX_CACHE_BYTES = 450 * 1024 * 1024;

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
 * Interface for UTXO set operations.
 */
export interface UTXOSet {
  /** Add all outputs from a transaction as new UTXOs. */
  addTransaction(
    txid: Buffer,
    tx: Transaction,
    height: number,
    isCoinbase: boolean
  ): void;

  /** Spend an input (remove the referenced UTXO). Returns the spent UTXO entry or throws. */
  spendOutput(outpoint: OutPoint): UTXOEntry;

  /** Look up a UTXO without spending it. */
  getUTXO(outpoint: OutPoint): UTXOEntry | null;

  /** Check if a UTXO exists. */
  hasUTXO(outpoint: OutPoint): boolean;
}

/**
 * Create a cache key from a txid and vout.
 * Format: txid_hex:vout
 */
function makeOutpointKey(txid: Buffer, vout: number): string {
  return `${txid.toString("hex")}:${vout}`;
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
 * Encode a UTXO key for database storage: txid (32 bytes) || vout (4 bytes LE).
 */
function encodeUTXOKey(txid: Buffer, vout: number): Buffer {
  const buf = Buffer.alloc(36);
  txid.copy(buf, 0);
  buf.writeUInt32LE(vout, 32);
  return buf;
}

/**
 * Serialize a UTXOEntry to bytes for storage.
 */
function serializeUTXO(entry: UTXOEntry): Buffer {
  const writer = new BufferWriter();
  writer.writeUInt32LE(entry.height);
  writer.writeUInt8(entry.coinbase ? 1 : 0);
  writer.writeUInt64LE(entry.amount);
  writer.writeVarBytes(entry.scriptPubKey);
  return writer.toBuffer();
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
 * Data stored for undo operations during block disconnect.
 * For each spent output, we store the full UTXO data plus the outpoint.
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
 * UTXO set manager with write-through caching and LRU eviction.
 *
 * Maintains an in-memory cache of UTXOs being modified. Changes are
 * accumulated in the cache and flushed to the database atomically.
 *
 * Features:
 * - LRU eviction policy for memory-bounded operation
 * - Dirty tracking for efficient flushing
 * - Access order tracking for eviction decisions
 * - Cache statistics for monitoring
 */
export class UTXOManager implements UTXOSet {
  private db: ChainDB;
  private cache: Map<string, UTXOEntry>; // write-through cache
  private spent: Set<string>; // outpoints spent in current batch
  private added: Set<string>; // outpoints added in current batch (for flush)

  // LRU eviction support
  private dirty: Set<string>; // keys modified since last flush
  private accessOrder: Map<string, number>; // key -> access timestamp
  private accessCounter: number; // monotonic counter for access ordering

  // Cache size management
  private maxCacheSize: number; // max entries (derived from max bytes)
  private maxCacheBytes: number; // max bytes

  // Statistics
  private stats: UTXOCacheStats;

  constructor(db: ChainDB, maxCacheBytes: number = DEFAULT_MAX_CACHE_BYTES) {
    this.db = db;
    this.cache = new Map();
    this.spent = new Set();
    this.added = new Set();

    // LRU support
    this.dirty = new Set();
    this.accessOrder = new Map();
    this.accessCounter = 0;

    // Cache size
    this.maxCacheBytes = maxCacheBytes;
    this.maxCacheSize = Math.floor(maxCacheBytes / BYTES_PER_UTXO_ENTRY);

    // Statistics
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
   * Get cache statistics.
   */
  getStats(): UTXOCacheStats {
    return {
      ...this.stats,
      currentSize: this.cache.size,
    };
  }

  /**
   * Reset cache statistics.
   */
  resetStats(): void {
    this.stats = {
      hits: 0,
      misses: 0,
      evictions: 0,
      flushes: 0,
      currentSize: this.cache.size,
      maxSize: this.maxCacheSize,
    };
  }

  /**
   * Touch a key to update its access order (for LRU).
   */
  private touch(key: string): void {
    this.accessOrder.set(key, ++this.accessCounter);
  }

  /**
   * Evict clean (non-dirty) entries to free memory.
   * Evicts the least recently used clean entries until we're under the limit.
   */
  private evictClean(targetFreeCount: number = 1): number {
    if (this.cache.size + targetFreeCount <= this.maxCacheSize) {
      return 0; // No eviction needed
    }

    const toEvict = this.cache.size + targetFreeCount - this.maxCacheSize;

    // Build list of clean entries with their access order
    const cleanEntries: { key: string; accessTime: number }[] = [];
    for (const [key] of this.cache) {
      if (!this.dirty.has(key) && !this.added.has(key)) {
        cleanEntries.push({
          key,
          accessTime: this.accessOrder.get(key) ?? 0,
        });
      }
    }

    // Sort by access time (oldest first)
    cleanEntries.sort((a, b) => a.accessTime - b.accessTime);

    // Evict oldest clean entries
    let evicted = 0;
    for (let i = 0; i < Math.min(toEvict, cleanEntries.length); i++) {
      const key = cleanEntries[i].key;
      this.cache.delete(key);
      this.accessOrder.delete(key);
      evicted++;
      this.stats.evictions++;
    }

    return evicted;
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
      const key = makeOutpointKey(txid, vout);

      const entry: UTXOEntry = {
        height,
        coinbase: isCoinbase,
        amount: output.value,
        scriptPubKey: output.scriptPubKey,
      };

      // Evict if needed before adding
      this.evictClean(1);

      this.cache.set(key, entry);
      this.added.add(key);
      this.dirty.add(key);
      this.touch(key);

      // If this outpoint was previously spent in this batch, remove from spent
      // (can happen during reorganization logic)
      this.spent.delete(key);
    }
  }

  /**
   * Spend an input (remove the referenced UTXO).
   * Returns the spent UTXO entry or throws if not found.
   */
  spendOutput(outpoint: OutPoint): UTXOEntry {
    const key = makeOutpointKey(outpoint.txid, outpoint.vout);

    // Check if already spent in this batch
    if (this.spent.has(key)) {
      throw new Error(
        `UTXO already spent: ${outpoint.txid.toString("hex")}:${outpoint.vout}`
      );
    }

    // Try to get from cache first
    const cached = this.cache.get(key);
    if (cached) {
      this.stats.hits++;
      // Mark as spent
      this.spent.add(key);
      this.dirty.add(key);
      this.cache.delete(key);
      this.added.delete(key);
      this.accessOrder.delete(key);
      return cached;
    }

    this.stats.misses++;
    // UTXO not in cache - need to load from DB synchronously
    // This is a limitation: we need the UTXO entry to return it
    // The caller should pre-load UTXOs before spending
    throw new Error(
      `UTXO not in cache (must be pre-loaded): ${outpoint.txid.toString("hex")}:${outpoint.vout}`
    );
  }

  /**
   * Spend an output asynchronously, loading from DB if needed.
   */
  async spendOutputAsync(outpoint: OutPoint): Promise<UTXOEntry> {
    const key = makeOutpointKey(outpoint.txid, outpoint.vout);

    // Check if already spent in this batch
    if (this.spent.has(key)) {
      throw new Error(
        `UTXO already spent: ${outpoint.txid.toString("hex")}:${outpoint.vout}`
      );
    }

    // Try to get from cache first
    let entry: UTXOEntry | null | undefined = this.cache.get(key);

    if (entry) {
      this.stats.hits++;
    } else {
      this.stats.misses++;
      // Load from database
      entry = await this.db.getUTXO(outpoint.txid, outpoint.vout);
      if (!entry) {
        throw new Error(
          `UTXO not found: ${outpoint.txid.toString("hex")}:${outpoint.vout}`
        );
      }
    }

    // Mark as spent
    this.spent.add(key);
    this.dirty.add(key);
    this.cache.delete(key);
    this.added.delete(key);
    this.accessOrder.delete(key);

    return entry;
  }

  /**
   * Look up a UTXO without spending it.
   * Returns null if not found in cache.
   * Use getUTXOAsync for database lookup.
   */
  getUTXO(outpoint: OutPoint): UTXOEntry | null {
    const key = makeOutpointKey(outpoint.txid, outpoint.vout);

    // If spent in this batch, it doesn't exist
    if (this.spent.has(key)) {
      return null;
    }

    const entry = this.cache.get(key);
    if (entry) {
      this.stats.hits++;
      this.touch(key);
      return entry;
    }

    this.stats.misses++;
    return null;
  }

  /**
   * Look up a UTXO asynchronously, checking database if not in cache.
   */
  async getUTXOAsync(outpoint: OutPoint): Promise<UTXOEntry | null> {
    const key = makeOutpointKey(outpoint.txid, outpoint.vout);

    // If spent in this batch, it doesn't exist
    if (this.spent.has(key)) {
      return null;
    }

    // Check cache first
    const cached = this.cache.get(key);
    if (cached) {
      this.stats.hits++;
      this.touch(key);
      return cached;
    }

    this.stats.misses++;

    // Load from database
    const entry = await this.db.getUTXO(outpoint.txid, outpoint.vout);
    if (entry) {
      // Cache for future lookups
      this.evictClean(1);
      this.cache.set(key, entry);
      this.touch(key);
    }
    return entry;
  }

  /**
   * Check if a UTXO exists in cache.
   * Use hasUTXOAsync for database lookup.
   */
  hasUTXO(outpoint: OutPoint): boolean {
    const key = makeOutpointKey(outpoint.txid, outpoint.vout);

    if (this.spent.has(key)) {
      return false;
    }

    const exists = this.cache.has(key);
    if (exists) {
      this.stats.hits++;
      this.touch(key);
    } else {
      this.stats.misses++;
    }
    return exists;
  }

  /**
   * Check if a UTXO exists, checking database if not in cache.
   */
  async hasUTXOAsync(outpoint: OutPoint): Promise<boolean> {
    const key = makeOutpointKey(outpoint.txid, outpoint.vout);

    if (this.spent.has(key)) {
      return false;
    }

    if (this.cache.has(key)) {
      this.stats.hits++;
      this.touch(key);
      return true;
    }

    this.stats.misses++;
    const entry = await this.db.getUTXO(outpoint.txid, outpoint.vout);
    if (entry) {
      // Cache for future lookups
      this.evictClean(1);
      this.cache.set(key, entry);
      this.touch(key);
    }
    return entry !== null;
  }

  /**
   * Add a UTXO entry directly (used during block disconnect to restore spent UTXOs).
   */
  restoreUTXO(txid: Buffer, vout: number, entry: UTXOEntry): void {
    const key = makeOutpointKey(txid, vout);
    this.evictClean(1);
    this.cache.set(key, entry);
    this.added.add(key);
    this.dirty.add(key);
    this.touch(key);
    this.spent.delete(key);
  }

  /**
   * Remove a UTXO directly (used during block disconnect to remove outputs).
   */
  removeUTXO(txid: Buffer, vout: number): void {
    const key = makeOutpointKey(txid, vout);
    this.cache.delete(key);
    this.added.delete(key);
    this.dirty.add(key);
    this.accessOrder.delete(key);
    this.spent.add(key);
  }

  /**
   * Flush cached changes to database as an atomic batch.
   * This flushes all dirty entries and clears tracking sets.
   */
  async flush(): Promise<void> {
    const ops: BatchOperation[] = [];

    // Add all new/modified UTXOs
    for (const key of this.added) {
      const entry = this.cache.get(key);
      if (entry) {
        const { txid, vout } = parseOutpointKey(key);
        ops.push({
          type: "put",
          prefix: DBPrefix.UTXO,
          key: encodeUTXOKey(txid, vout),
          value: serializeUTXO(entry),
        });
      }
    }

    // Delete all spent UTXOs
    for (const key of this.spent) {
      const { txid, vout } = parseOutpointKey(key);
      ops.push({
        type: "del",
        prefix: DBPrefix.UTXO,
        key: encodeUTXOKey(txid, vout),
      });
    }

    if (ops.length > 0) {
      await this.db.batch(ops);
    }

    this.stats.flushes++;

    // Clear the tracking sets (but keep cache for reads)
    this.added.clear();
    this.spent.clear();
    this.dirty.clear();
  }

  /**
   * Flush only dirty entries to DB and clear dirty set.
   * More efficient than full flush when only some entries changed.
   */
  async flushDirty(): Promise<void> {
    const ops: BatchOperation[] = [];

    // Only process dirty entries
    for (const key of this.dirty) {
      // Check if this was an add or delete
      if (this.spent.has(key)) {
        // This was spent (deleted)
        const { txid, vout } = parseOutpointKey(key);
        ops.push({
          type: "del",
          prefix: DBPrefix.UTXO,
          key: encodeUTXOKey(txid, vout),
        });
      } else if (this.added.has(key)) {
        // This was added/modified
        const entry = this.cache.get(key);
        if (entry) {
          const { txid, vout } = parseOutpointKey(key);
          ops.push({
            type: "put",
            prefix: DBPrefix.UTXO,
            key: encodeUTXOKey(txid, vout),
            value: serializeUTXO(entry),
          });
        }
      }
    }

    if (ops.length > 0) {
      await this.db.batch(ops);
    }

    this.stats.flushes++;

    // Clear dirty tracking (keep added/spent for reference until full flush)
    this.dirty.clear();
  }

  /**
   * Clear the in-memory cache.
   * Call after flush() to release memory.
   */
  clearCache(): void {
    this.cache.clear();
    this.added.clear();
    this.spent.clear();
    this.dirty.clear();
    this.accessOrder.clear();
    this.accessCounter = 0;
  }

  /**
   * Pre-load a UTXO into the cache from the database.
   * Useful for batch operations where we need to spend multiple UTXOs.
   */
  async preloadUTXO(outpoint: OutPoint): Promise<boolean> {
    const key = makeOutpointKey(outpoint.txid, outpoint.vout);

    // Already in cache
    if (this.cache.has(key)) {
      this.touch(key);
      return true;
    }

    // Already spent
    if (this.spent.has(key)) {
      return false;
    }

    // Load from database
    const entry = await this.db.getUTXO(outpoint.txid, outpoint.vout);
    if (entry) {
      this.evictClean(1);
      this.cache.set(key, entry);
      this.touch(key);
      return true;
    }

    return false;
  }

  /**
   * Pre-load multiple UTXOs in batch.
   * More efficient than multiple preloadUTXO calls.
   */
  async preloadUTXOs(outpoints: OutPoint[]): Promise<number> {
    let loaded = 0;
    const toLoad: OutPoint[] = [];

    // Filter out already cached or spent
    for (const outpoint of outpoints) {
      const key = makeOutpointKey(outpoint.txid, outpoint.vout);
      if (this.cache.has(key)) {
        this.touch(key);
        loaded++;
      } else if (!this.spent.has(key)) {
        toLoad.push(outpoint);
      }
    }

    // Load remaining from database
    for (const outpoint of toLoad) {
      const entry = await this.db.getUTXO(outpoint.txid, outpoint.vout);
      if (entry) {
        const key = makeOutpointKey(outpoint.txid, outpoint.vout);
        this.evictClean(1);
        this.cache.set(key, entry);
        this.touch(key);
        loaded++;
      }
    }

    return loaded;
  }

  /**
   * Get estimated memory usage of the cache in bytes.
   */
  getEstimatedMemoryUsage(): number {
    return this.cache.size * BYTES_PER_UTXO_ENTRY;
  }

  /**
   * Get the maximum cache size in entries.
   */
  getMaxCacheSize(): number {
    return this.maxCacheSize;
  }

  /**
   * Set a new maximum cache size in bytes.
   * May trigger eviction if current size exceeds new limit.
   */
  setMaxCacheBytes(maxBytes: number): void {
    this.maxCacheBytes = maxBytes;
    this.maxCacheSize = Math.floor(maxBytes / BYTES_PER_UTXO_ENTRY);
    this.stats.maxSize = this.maxCacheSize;

    // Evict if we're over the new limit
    if (this.cache.size > this.maxCacheSize) {
      this.evictClean(0);
    }
  }

  /**
   * Get the number of UTXOs currently in the cache.
   */
  getCacheSize(): number {
    return this.cache.size;
  }

  /**
   * Get the number of pending operations (adds + spends).
   */
  getPendingCount(): number {
    return this.added.size + this.spent.size;
  }

  /**
   * Get the number of dirty entries pending flush.
   */
  getDirtyCount(): number {
    return this.dirty.size;
  }
}
