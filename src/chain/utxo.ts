/**
 * UTXO set management: tracking unspent transaction outputs.
 *
 * Implements a write-through cache for efficient UTXO lookups and batch
 * persistence to the database. UTXOs are added when blocks are connected
 * and removed when spent.
 */

import type { ChainDB, UTXOEntry, BatchOperation } from "../storage/database.js";
import { DBPrefix } from "../storage/database.js";
import type { Transaction, OutPoint } from "../validation/tx.js";
import { BufferWriter, BufferReader } from "../wire/serialization.js";

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
 * UTXO set manager with write-through caching.
 *
 * Maintains an in-memory cache of UTXOs being modified. Changes are
 * accumulated in the cache and flushed to the database atomically.
 */
export class UTXOManager implements UTXOSet {
  private db: ChainDB;
  private cache: Map<string, UTXOEntry>; // write-through cache
  private spent: Set<string>; // outpoints spent in current batch
  private added: Set<string>; // outpoints added in current batch (for flush)

  constructor(db: ChainDB) {
    this.db = db;
    this.cache = new Map();
    this.spent = new Set();
    this.added = new Set();
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

      this.cache.set(key, entry);
      this.added.add(key);

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
      // Mark as spent
      this.spent.add(key);
      this.cache.delete(key);
      this.added.delete(key);
      return cached;
    }

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

    if (!entry) {
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
    this.cache.delete(key);
    this.added.delete(key);

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

    return this.cache.get(key) ?? null;
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
      return cached;
    }

    // Load from database
    return await this.db.getUTXO(outpoint.txid, outpoint.vout);
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

    return this.cache.has(key);
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
      return true;
    }

    const entry = await this.db.getUTXO(outpoint.txid, outpoint.vout);
    return entry !== null;
  }

  /**
   * Add a UTXO entry directly (used during block disconnect to restore spent UTXOs).
   */
  restoreUTXO(txid: Buffer, vout: number, entry: UTXOEntry): void {
    const key = makeOutpointKey(txid, vout);
    this.cache.set(key, entry);
    this.added.add(key);
    this.spent.delete(key);
  }

  /**
   * Remove a UTXO directly (used during block disconnect to remove outputs).
   */
  removeUTXO(txid: Buffer, vout: number): void {
    const key = makeOutpointKey(txid, vout);
    this.cache.delete(key);
    this.added.delete(key);
    this.spent.add(key);
  }

  /**
   * Flush cached changes to database as an atomic batch.
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

    // Clear the tracking sets (but keep cache for reads)
    this.added.clear();
    this.spent.clear();
  }

  /**
   * Clear the in-memory cache.
   * Call after flush() to release memory.
   */
  clearCache(): void {
    this.cache.clear();
    this.added.clear();
    this.spent.clear();
  }

  /**
   * Pre-load a UTXO into the cache from the database.
   * Useful for batch operations where we need to spend multiple UTXOs.
   */
  async preloadUTXO(outpoint: OutPoint): Promise<boolean> {
    const key = makeOutpointKey(outpoint.txid, outpoint.vout);

    // Already in cache
    if (this.cache.has(key)) {
      return true;
    }

    // Already spent
    if (this.spent.has(key)) {
      return false;
    }

    // Load from database
    const entry = await this.db.getUTXO(outpoint.txid, outpoint.vout);
    if (entry) {
      this.cache.set(key, entry);
      return true;
    }

    return false;
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
}
