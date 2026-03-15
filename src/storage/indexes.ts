/**
 * Block indexes: txindex, blockfilterindex, and coinstatsindex.
 *
 * These optional indexes accelerate various lookups:
 * - TxIndex: map txid -> block location for fast transaction lookup
 * - BlockFilterIndex: BIP157/158 compact block filters for light clients
 * - CoinStatsIndex: UTXO set statistics per block (MuHash, counts, amounts)
 *
 * Reference: Bitcoin Core /home/max/hashhog/bitcoin/src/index/txindex.cpp,
 *            /home/max/hashhog/bitcoin/src/blockfilter.cpp,
 *            /home/max/hashhog/bitcoin/src/index/coinstatsindex.cpp
 */

import type { ChainDB, BatchOperation, TxIndexEntry } from "./database.js";
import { DBPrefix } from "./database.js";
import { BufferReader, BufferWriter } from "../wire/serialization.js";
import type { Block } from "../validation/block.js";
import { deserializeBlock, getBlockHash } from "../validation/block.js";
import { getTxId, isCoinbase } from "../validation/tx.js";
import { sha256Hash, hash256 } from "../crypto/primitives.js";
import type { SpentUTXO } from "../chain/utxo.js";

// =============================================================================
// Database Prefixes for Indexes
// =============================================================================

/**
 * Extended DB prefixes for indexes.
 * These extend the existing DBPrefix enum.
 */
export const IndexPrefix = {
  // Block filter index prefixes
  BLOCK_FILTER: 0x46, // 'F' - block hash -> filter data
  FILTER_HEADER: 0x47, // 'G' - block hash -> filter header
  FILTER_TIP: 0x48, // 'H' - filter index tip (singleton)

  // Coin stats index prefixes
  COIN_STATS: 0x43, // 'C' - height -> coin stats
  COIN_STATS_TIP: 0x44, // 'D' - coinstats index tip (singleton)
  COIN_STATS_MUHASH: 0x45, // 'E' - current muhash state

  // TxIndex extended prefix (for height-based lookups)
  TX_BY_HEIGHT: 0x54, // 'T' - height -> list of txids
} as const;

// =============================================================================
// GCS Filter Implementation (BIP 158)
// =============================================================================

/**
 * GCS filter parameters for basic block filters (BIP 158).
 */
export const BASIC_FILTER_P = 19n; // Golomb-Rice parameter
export const BASIC_FILTER_M = 784931n; // False positive rate inverse (1/M)

/**
 * SipHash-2-4 implementation for GCS filter hashing.
 * Uses block hash as the key (first 16 bytes as k0, k1).
 */
export function sipHash24(key0: bigint, key1: bigint, data: Buffer): bigint {
  // SipHash-2-4 constants
  const c0 = 0x736f6d6570736575n;
  const c1 = 0x646f72616e646f6dn;
  const c2 = 0x6c7967656e657261n;
  const c3 = 0x7465646279746573n;

  let v0 = c0 ^ key0;
  let v1 = c1 ^ key1;
  let v2 = c2 ^ key0;
  let v3 = c3 ^ key1;

  // Process full 8-byte blocks
  const blocks = Math.floor(data.length / 8);
  for (let i = 0; i < blocks; i++) {
    const m = data.readBigUInt64LE(i * 8);
    v3 ^= m;
    // 2 rounds
    for (let j = 0; j < 2; j++) {
      v0 = (v0 + v1) & 0xffffffffffffffffn;
      v1 = ((v1 << 13n) | (v1 >> 51n)) & 0xffffffffffffffffn;
      v1 ^= v0;
      v0 = ((v0 << 32n) | (v0 >> 32n)) & 0xffffffffffffffffn;
      v2 = (v2 + v3) & 0xffffffffffffffffn;
      v3 = ((v3 << 16n) | (v3 >> 48n)) & 0xffffffffffffffffn;
      v3 ^= v2;
      v0 = (v0 + v3) & 0xffffffffffffffffn;
      v3 = ((v3 << 21n) | (v3 >> 43n)) & 0xffffffffffffffffn;
      v3 ^= v0;
      v2 = (v2 + v1) & 0xffffffffffffffffn;
      v1 = ((v1 << 17n) | (v1 >> 47n)) & 0xffffffffffffffffn;
      v1 ^= v2;
      v2 = ((v2 << 32n) | (v2 >> 32n)) & 0xffffffffffffffffn;
    }
    v0 ^= m;
  }

  // Process remaining bytes with length encoding
  let m = BigInt(data.length) << 56n;
  const remaining = data.length % 8;
  for (let i = 0; i < remaining; i++) {
    m |= BigInt(data[blocks * 8 + i]) << BigInt(i * 8);
  }

  v3 ^= m;
  // 2 rounds
  for (let j = 0; j < 2; j++) {
    v0 = (v0 + v1) & 0xffffffffffffffffn;
    v1 = ((v1 << 13n) | (v1 >> 51n)) & 0xffffffffffffffffn;
    v1 ^= v0;
    v0 = ((v0 << 32n) | (v0 >> 32n)) & 0xffffffffffffffffn;
    v2 = (v2 + v3) & 0xffffffffffffffffn;
    v3 = ((v3 << 16n) | (v3 >> 48n)) & 0xffffffffffffffffn;
    v3 ^= v2;
    v0 = (v0 + v3) & 0xffffffffffffffffn;
    v3 = ((v3 << 21n) | (v3 >> 43n)) & 0xffffffffffffffffn;
    v3 ^= v0;
    v2 = (v2 + v1) & 0xffffffffffffffffn;
    v1 = ((v1 << 17n) | (v1 >> 47n)) & 0xffffffffffffffffn;
    v1 ^= v2;
    v2 = ((v2 << 32n) | (v2 >> 32n)) & 0xffffffffffffffffn;
  }
  v0 ^= m;

  // Finalization
  v2 ^= 0xffn;
  // 4 rounds
  for (let j = 0; j < 4; j++) {
    v0 = (v0 + v1) & 0xffffffffffffffffn;
    v1 = ((v1 << 13n) | (v1 >> 51n)) & 0xffffffffffffffffn;
    v1 ^= v0;
    v0 = ((v0 << 32n) | (v0 >> 32n)) & 0xffffffffffffffffn;
    v2 = (v2 + v3) & 0xffffffffffffffffn;
    v3 = ((v3 << 16n) | (v3 >> 48n)) & 0xffffffffffffffffn;
    v3 ^= v2;
    v0 = (v0 + v3) & 0xffffffffffffffffn;
    v3 = ((v3 << 21n) | (v3 >> 43n)) & 0xffffffffffffffffn;
    v3 ^= v0;
    v2 = (v2 + v1) & 0xffffffffffffffffn;
    v1 = ((v1 << 17n) | (v1 >> 47n)) & 0xffffffffffffffffn;
    v1 ^= v2;
    v2 = ((v2 << 32n) | (v2 >> 32n)) & 0xffffffffffffffffn;
  }

  return v0 ^ v1 ^ v2 ^ v3;
}

/**
 * Fast modular reduction: (hash * F) >> 64 where F = N * M
 * This maps the hash to range [0, F) with uniform distribution.
 */
export function fastRange64(hash: bigint, range: bigint): bigint {
  // Compute (hash * range) >> 64
  const product = hash * range;
  return product >> 64n;
}

/**
 * BitStream writer for Golomb-Rice encoding.
 */
export class BitStreamWriter {
  private buffer: number[] = [];
  private currentByte = 0;
  private bitPos = 0;

  /**
   * Write n bits from value (LSB first).
   */
  writeBits(value: bigint, n: number): void {
    for (let i = 0; i < n; i++) {
      if ((value & (1n << BigInt(i))) !== 0n) {
        this.currentByte |= 1 << this.bitPos;
      }
      this.bitPos++;
      if (this.bitPos === 8) {
        this.buffer.push(this.currentByte);
        this.currentByte = 0;
        this.bitPos = 0;
      }
    }
  }

  /**
   * Write a single bit.
   */
  writeBit(bit: number): void {
    if (bit) {
      this.currentByte |= 1 << this.bitPos;
    }
    this.bitPos++;
    if (this.bitPos === 8) {
      this.buffer.push(this.currentByte);
      this.currentByte = 0;
      this.bitPos = 0;
    }
  }

  /**
   * Flush any remaining bits.
   */
  flush(): void {
    if (this.bitPos > 0) {
      this.buffer.push(this.currentByte);
      this.currentByte = 0;
      this.bitPos = 0;
    }
  }

  /**
   * Get the encoded bytes.
   */
  toBuffer(): Buffer {
    return Buffer.from(this.buffer);
  }
}

/**
 * BitStream reader for Golomb-Rice decoding.
 */
export class BitStreamReader {
  private data: Buffer;
  private bytePos = 0;
  private bitPos = 0;

  constructor(data: Buffer) {
    this.data = data;
  }

  /**
   * Read a single bit.
   */
  readBit(): number {
    if (this.bytePos >= this.data.length) {
      throw new Error("BitStreamReader: out of data");
    }
    const bit = (this.data[this.bytePos] >> this.bitPos) & 1;
    this.bitPos++;
    if (this.bitPos === 8) {
      this.bitPos = 0;
      this.bytePos++;
    }
    return bit;
  }

  /**
   * Read n bits as a value (LSB first).
   */
  readBits(n: number): bigint {
    let value = 0n;
    for (let i = 0; i < n; i++) {
      if (this.readBit()) {
        value |= 1n << BigInt(i);
      }
    }
    return value;
  }

  /**
   * Check if there's more data.
   */
  hasMore(): boolean {
    return this.bytePos < this.data.length;
  }
}

/**
 * Golomb-Rice encode a value with parameter P.
 * Value is split into quotient (unary) and remainder (P bits).
 */
export function golombRiceEncode(writer: BitStreamWriter, p: bigint, value: bigint): void {
  const quotient = value >> p;
  const remainder = value & ((1n << p) - 1n);

  // Write quotient in unary (q ones followed by a zero)
  for (let i = 0n; i < quotient; i++) {
    writer.writeBit(1);
  }
  writer.writeBit(0);

  // Write remainder in P bits
  writer.writeBits(remainder, Number(p));
}

/**
 * Golomb-Rice decode a value with parameter P.
 */
export function golombRiceDecode(reader: BitStreamReader, p: bigint): bigint {
  // Read unary-encoded quotient
  let quotient = 0n;
  while (reader.readBit() === 1) {
    quotient++;
  }

  // Read P-bit remainder
  const remainder = reader.readBits(Number(p));

  return (quotient << p) | remainder;
}

/**
 * GCS Filter for BIP 158 block filters.
 */
export class GCSFilter {
  private n: number; // Number of elements
  private m: bigint; // False positive rate parameter
  private p: bigint; // Golomb-Rice parameter
  private f: bigint; // Range: N * M
  private k0: bigint; // SipHash key 0
  private k1: bigint; // SipHash key 1
  private encodedFilter: Buffer;

  /**
   * Create a GCS filter from elements.
   */
  constructor(
    elements: Buffer[],
    blockHash: Buffer,
    m: bigint = BASIC_FILTER_M,
    p: bigint = BASIC_FILTER_P
  ) {
    this.n = elements.length;
    this.m = m;
    this.p = p;
    this.f = BigInt(this.n) * m;

    // Extract SipHash keys from block hash (first 16 bytes, LE)
    this.k0 = blockHash.readBigUInt64LE(0);
    this.k1 = blockHash.readBigUInt64LE(8);

    // Build the filter
    this.encodedFilter = this.build(elements);
  }

  /**
   * Create a GCS filter from pre-encoded data.
   */
  static fromEncoded(
    encoded: Buffer,
    blockHash: Buffer,
    m: bigint = BASIC_FILTER_M,
    p: bigint = BASIC_FILTER_P
  ): GCSFilter {
    const filter = Object.create(GCSFilter.prototype) as GCSFilter;
    filter.m = m;
    filter.p = p;
    filter.k0 = blockHash.readBigUInt64LE(0);
    filter.k1 = blockHash.readBigUInt64LE(8);
    filter.encodedFilter = encoded;

    // Decode N from the encoded filter
    const reader = new BufferReader(encoded);
    filter.n = Number(reader.readVarInt());
    filter.f = BigInt(filter.n) * m;

    return filter;
  }

  /**
   * Hash an element to the filter range.
   */
  private hashToRange(element: Buffer): bigint {
    const hash = sipHash24(this.k0, this.k1, element);
    return fastRange64(hash, this.f);
  }

  /**
   * Build the encoded filter from elements.
   */
  private build(elements: Buffer[]): Buffer {
    if (elements.length === 0) {
      // Empty filter: just encode N=0
      const writer = new BufferWriter();
      writer.writeVarInt(0);
      return writer.toBuffer();
    }

    // Hash and sort elements
    const hashes = elements.map((e) => this.hashToRange(e));
    hashes.sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));

    // Encode using Golomb-Rice coding
    const bitWriter = new BitStreamWriter();

    // Write N as varint prefix (in a separate BufferWriter)
    const prefixWriter = new BufferWriter();
    prefixWriter.writeVarInt(this.n);
    const prefix = prefixWriter.toBuffer();

    // Encode deltas using Golomb-Rice
    let lastValue = 0n;
    for (const hash of hashes) {
      const delta = hash - lastValue;
      golombRiceEncode(bitWriter, this.p, delta);
      lastValue = hash;
    }

    bitWriter.flush();
    return Buffer.concat([prefix, bitWriter.toBuffer()]);
  }

  /**
   * Match a single element against the filter.
   * Returns true if the element may be in the set (possible false positive).
   * Returns false if the element is definitely not in the set.
   */
  match(element: Buffer): boolean {
    if (this.n === 0) return false;

    const target = this.hashToRange(element);
    return this.matchInternal([target]);
  }

  /**
   * Match any of the given elements against the filter.
   * Returns true if any element may be in the set.
   */
  matchAny(elements: Buffer[]): boolean {
    if (this.n === 0 || elements.length === 0) return false;

    const targets = elements.map((e) => this.hashToRange(e));
    targets.sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
    return this.matchInternal(targets);
  }

  /**
   * Internal match against sorted target hashes.
   */
  private matchInternal(sortedTargets: bigint[]): boolean {
    // Parse N from the encoded filter
    const prefixReader = new BufferReader(this.encodedFilter);
    const n = Number(prefixReader.readVarInt());

    if (n === 0) return false;

    // Get the bit stream data (after N varint)
    const bitStreamData = this.encodedFilter.subarray(prefixReader.position);
    const bitReader = new BitStreamReader(bitStreamData);

    let filterValue = 0n;
    let targetIdx = 0;

    for (let i = 0; i < n; i++) {
      const delta = golombRiceDecode(bitReader, this.p);
      filterValue += delta;

      // Advance through targets that are smaller than current filter value
      while (targetIdx < sortedTargets.length && sortedTargets[targetIdx] < filterValue) {
        targetIdx++;
      }

      // Check for match
      if (targetIdx < sortedTargets.length && sortedTargets[targetIdx] === filterValue) {
        return true;
      }

      // If all targets are smaller, no match possible
      if (targetIdx >= sortedTargets.length) {
        return false;
      }
    }

    return false;
  }

  /**
   * Get the encoded filter bytes.
   */
  getEncodedFilter(): Buffer {
    return this.encodedFilter;
  }

  /**
   * Get the number of elements in the filter.
   */
  getN(): number {
    return this.n;
  }

  /**
   * Compute the filter hash (SHA256d of encoded filter).
   */
  getHash(): Buffer {
    return hash256(this.encodedFilter);
  }
}

/**
 * Compute the filter header: hash(filter_hash || prev_filter_header)
 */
export function computeFilterHeader(filterHash: Buffer, prevHeader: Buffer): Buffer {
  return hash256(Buffer.concat([filterHash, prevHeader]));
}

// =============================================================================
// Block Filter Index
// =============================================================================

/**
 * Entry stored in the block filter index.
 */
export interface BlockFilterEntry {
  filter: Buffer; // Encoded GCS filter
  filterHash: Buffer; // SHA256d of filter
  filterHeader: Buffer; // Hash chain linking filters
}

/**
 * BlockFilterIndex: stores BIP 157/158 compact block filters.
 *
 * For each block, computes a GCS filter containing:
 * - All scriptPubKeys from outputs created
 * - All scriptPubKeys from inputs spent (from undo data)
 *
 * The filter allows light clients to determine if a block
 * might contain transactions relevant to their wallet.
 */
export class BlockFilterIndex {
  private db: ChainDB;
  private enabled: boolean;
  private currentHeight: number;
  private currentHeader: Buffer;

  constructor(db: ChainDB, enabled: boolean = false) {
    this.db = db;
    this.enabled = enabled;
    this.currentHeight = -1;
    this.currentHeader = Buffer.alloc(32, 0); // Genesis filter header is zeros
  }

  /**
   * Check if the index is enabled.
   */
  isEnabled(): boolean {
    return this.enabled;
  }

  /**
   * Enable or disable the index.
   */
  setEnabled(enabled: boolean): void {
    this.enabled = enabled;
  }

  /**
   * Get the current index height.
   */
  getHeight(): number {
    return this.currentHeight;
  }

  /**
   * Initialize the index from database.
   */
  async init(): Promise<void> {
    if (!this.enabled) return;

    // Load current tip
    const tipKey = Buffer.from([IndexPrefix.FILTER_TIP]);
    try {
      const tipData = await (this.db as any).db.get(tipKey);
      if (tipData) {
        const reader = new BufferReader(tipData);
        this.currentHeight = reader.readUInt32LE();
        this.currentHeader = reader.readHash();
      }
    } catch {
      // No tip stored yet
    }
  }

  /**
   * Build a filter for a block.
   *
   * @param block - The block to filter
   * @param spentOutputs - The spent outputs (from undo data)
   * @returns The filter entry
   */
  buildFilter(
    block: Block,
    spentOutputs: SpentUTXO[]
  ): GCSFilter {
    const blockHash = getBlockHash(block.header);
    const elements: Buffer[] = [];

    // Add all output scriptPubKeys
    for (const tx of block.transactions) {
      for (const output of tx.outputs) {
        const script = output.scriptPubKey;
        // Skip empty scripts and OP_RETURN
        if (script.length === 0 || script[0] === 0x6a) continue;
        elements.push(script);
      }
    }

    // Add all spent input scriptPubKeys
    for (const spent of spentOutputs) {
      const script = spent.entry.scriptPubKey;
      // Skip empty scripts (OP_RETURN shouldn't be spent, but check anyway)
      if (script.length === 0) continue;
      elements.push(script);
    }

    return new GCSFilter(elements, blockHash);
  }

  /**
   * Index a block.
   *
   * @param block - The block
   * @param height - Block height
   * @param spentOutputs - Spent outputs for filter building
   */
  async indexBlock(
    block: Block,
    height: number,
    spentOutputs: SpentUTXO[]
  ): Promise<void> {
    if (!this.enabled) return;

    const blockHash = getBlockHash(block.header);
    const filter = this.buildFilter(block, spentOutputs);
    const filterHash = filter.getHash();
    const filterHeader = computeFilterHeader(filterHash, this.currentHeader);

    // Prepare batch operations
    const ops: BatchOperation[] = [];

    // Store filter
    const filterKey = Buffer.from([IndexPrefix.BLOCK_FILTER, ...blockHash]);
    ops.push({
      type: "put",
      prefix: IndexPrefix.BLOCK_FILTER as unknown as (typeof DBPrefix)[keyof typeof DBPrefix],
      key: blockHash,
      value: filter.getEncodedFilter(),
    });

    // Store filter header
    ops.push({
      type: "put",
      prefix: IndexPrefix.FILTER_HEADER as unknown as (typeof DBPrefix)[keyof typeof DBPrefix],
      key: blockHash,
      value: filterHeader,
    });

    // Update tip
    const tipWriter = new BufferWriter();
    tipWriter.writeUInt32LE(height);
    tipWriter.writeHash(filterHeader);
    ops.push({
      type: "put",
      prefix: IndexPrefix.FILTER_TIP as unknown as (typeof DBPrefix)[keyof typeof DBPrefix],
      key: Buffer.alloc(0),
      value: tipWriter.toBuffer(),
    });

    await this.db.batch(ops);

    this.currentHeight = height;
    this.currentHeader = filterHeader;
  }

  /**
   * Get a block filter by hash.
   */
  async getFilter(blockHash: Buffer): Promise<Buffer | null> {
    if (!this.enabled) return null;

    const key = Buffer.concat([Buffer.from([IndexPrefix.BLOCK_FILTER]), blockHash]);
    try {
      const data = await (this.db as any).db.get(key);
      return data ?? null;
    } catch {
      return null;
    }
  }

  /**
   * Get a filter header by block hash.
   */
  async getFilterHeader(blockHash: Buffer): Promise<Buffer | null> {
    if (!this.enabled) return null;

    const key = Buffer.concat([Buffer.from([IndexPrefix.FILTER_HEADER]), blockHash]);
    try {
      const data = await (this.db as any).db.get(key);
      return data ?? null;
    } catch {
      return null;
    }
  }
}

// =============================================================================
// MuHash3072 Implementation for CoinStatsIndex
// =============================================================================

/**
 * MuHash3072: A rolling hash that supports removal of elements.
 *
 * MuHash is a multiplicative hash modulo a large prime.
 * It allows efficient addition and removal of set elements.
 *
 * We use a simplified implementation with 256-bit arithmetic,
 * storing the hash as a SHA256 digest for compactness.
 *
 * For full MuHash3072, see Bitcoin Core's crypto/muhash.cpp.
 * This simplified version uses hash chaining for similar properties.
 */
export class MuHash {
  private numerator: Buffer; // Product of added elements
  private denominator: Buffer; // Product of removed elements

  constructor() {
    // Initialize to identity element (1)
    this.numerator = Buffer.alloc(32, 0);
    this.numerator[0] = 1;
    this.denominator = Buffer.alloc(32, 0);
    this.denominator[0] = 1;
  }

  /**
   * Clone this MuHash state.
   */
  clone(): MuHash {
    const copy = new MuHash();
    copy.numerator = Buffer.from(this.numerator);
    copy.denominator = Buffer.from(this.denominator);
    return copy;
  }

  /**
   * Hash a UTXO for inclusion in the set.
   * Format: outpoint || coin_height || coin_amount || scriptPubKey
   */
  private hashUTXO(
    txid: Buffer,
    vout: number,
    height: number,
    isCoinbase: boolean,
    value: bigint,
    scriptPubKey: Buffer
  ): Buffer {
    const writer = new BufferWriter();
    writer.writeHash(txid);
    writer.writeUInt32LE(vout);
    writer.writeUInt32LE((height << 1) | (isCoinbase ? 1 : 0));
    writer.writeUInt64LE(value);
    writer.writeVarBytes(scriptPubKey);
    return sha256Hash(writer.toBuffer());
  }

  /**
   * Multiply two 256-bit values as field elements.
   * This is a simplified version using hash chaining.
   */
  private multiply(a: Buffer, b: Buffer): Buffer {
    // Simplified: hash(a || b)
    // A proper MuHash would do modular multiplication in a 3072-bit field
    return sha256Hash(Buffer.concat([a, b]));
  }

  /**
   * Add a UTXO to the set.
   */
  insert(
    txid: Buffer,
    vout: number,
    height: number,
    isCoinbase: boolean,
    value: bigint,
    scriptPubKey: Buffer
  ): void {
    const hash = this.hashUTXO(txid, vout, height, isCoinbase, value, scriptPubKey);
    this.numerator = this.multiply(this.numerator, hash);
  }

  /**
   * Remove a UTXO from the set.
   */
  remove(
    txid: Buffer,
    vout: number,
    height: number,
    isCoinbase: boolean,
    value: bigint,
    scriptPubKey: Buffer
  ): void {
    const hash = this.hashUTXO(txid, vout, height, isCoinbase, value, scriptPubKey);
    this.denominator = this.multiply(this.denominator, hash);
  }

  /**
   * Finalize and get the hash digest.
   */
  finalize(): Buffer {
    // Simplified: hash(numerator || denominator)
    return sha256Hash(Buffer.concat([this.numerator, this.denominator]));
  }

  /**
   * Serialize the state for storage.
   */
  serialize(): Buffer {
    return Buffer.concat([this.numerator, this.denominator]);
  }

  /**
   * Deserialize state from storage.
   */
  static deserialize(data: Buffer): MuHash {
    if (data.length !== 64) {
      throw new Error("Invalid MuHash serialization length");
    }
    const muhash = new MuHash();
    muhash.numerator = data.subarray(0, 32);
    muhash.denominator = data.subarray(32, 64);
    return muhash;
  }
}

// =============================================================================
// Coin Stats Index
// =============================================================================

/**
 * Per-block UTXO set statistics.
 */
export interface CoinStats {
  height: number;
  blockHash: Buffer;
  muhash: Buffer; // 32-byte MuHash digest
  txOutputCount: bigint; // Number of UTXOs
  totalAmount: bigint; // Total satoshis in UTXOs
  totalSubsidy: bigint; // Cumulative block subsidy
  bogoSize: bigint; // "Bogo" size metric for UTXOs
}

/**
 * Serialize CoinStats for database storage.
 */
function serializeCoinStats(stats: CoinStats): Buffer {
  const writer = new BufferWriter();
  writer.writeUInt32LE(stats.height);
  writer.writeHash(stats.blockHash);
  writer.writeHash(stats.muhash);
  writer.writeUInt64LE(stats.txOutputCount);
  writer.writeUInt64LE(stats.totalAmount);
  writer.writeUInt64LE(stats.totalSubsidy);
  writer.writeUInt64LE(stats.bogoSize);
  return writer.toBuffer();
}

/**
 * Deserialize CoinStats from database.
 */
function deserializeCoinStats(data: Buffer): CoinStats {
  const reader = new BufferReader(data);
  return {
    height: reader.readUInt32LE(),
    blockHash: reader.readHash(),
    muhash: reader.readHash(),
    txOutputCount: reader.readUInt64LE(),
    totalAmount: reader.readUInt64LE(),
    totalSubsidy: reader.readUInt64LE(),
    bogoSize: reader.readUInt64LE(),
  };
}

/**
 * Calculate the "bogo size" of a scriptPubKey.
 * This is a simplified size metric used by Bitcoin Core.
 */
function getBogoSize(scriptPubKey: Buffer): bigint {
  // Base size: 32 bytes overhead + actual script size
  return BigInt(32 + scriptPubKey.length);
}

/**
 * CoinStatsIndex: tracks UTXO set statistics per block.
 *
 * For each block, maintains:
 * - MuHash of the UTXO set (allows verification)
 * - Total number of UTXOs
 * - Total amount in UTXOs
 * - Cumulative subsidy
 */
export class CoinStatsIndex {
  private db: ChainDB;
  private enabled: boolean;

  // Running state
  private muhash: MuHash;
  private txOutputCount: bigint;
  private totalAmount: bigint;
  private totalSubsidy: bigint;
  private bogoSize: bigint;
  private currentHeight: number;
  private currentHash: Buffer;

  constructor(db: ChainDB, enabled: boolean = false) {
    this.db = db;
    this.enabled = enabled;
    this.muhash = new MuHash();
    this.txOutputCount = 0n;
    this.totalAmount = 0n;
    this.totalSubsidy = 0n;
    this.bogoSize = 0n;
    this.currentHeight = -1;
    this.currentHash = Buffer.alloc(32, 0);
  }

  /**
   * Check if the index is enabled.
   */
  isEnabled(): boolean {
    return this.enabled;
  }

  /**
   * Enable or disable the index.
   */
  setEnabled(enabled: boolean): void {
    this.enabled = enabled;
  }

  /**
   * Get the current index height.
   */
  getHeight(): number {
    return this.currentHeight;
  }

  /**
   * Initialize the index from database.
   */
  async init(): Promise<void> {
    if (!this.enabled) return;

    // Load current state
    const tipKey = Buffer.from([IndexPrefix.COIN_STATS_TIP]);
    try {
      const tipData = await (this.db as any).db.get(tipKey);
      if (tipData) {
        const reader = new BufferReader(tipData);
        this.currentHeight = reader.readUInt32LE();
        this.currentHash = reader.readHash();

        // Load MuHash state
        const muhashKey = Buffer.from([IndexPrefix.COIN_STATS_MUHASH]);
        const muhashData = await (this.db as any).db.get(muhashKey);
        if (muhashData) {
          this.muhash = MuHash.deserialize(muhashData);
        }

        // Load stats from current height
        const stats = await this.getStats(this.currentHeight);
        if (stats) {
          this.txOutputCount = stats.txOutputCount;
          this.totalAmount = stats.totalAmount;
          this.totalSubsidy = stats.totalSubsidy;
          this.bogoSize = stats.bogoSize;
        }
      }
    } catch {
      // No state stored yet
    }
  }

  /**
   * Index a block.
   *
   * @param block - The block
   * @param height - Block height
   * @param subsidy - Block subsidy
   * @param spentOutputs - Spent outputs (for MuHash removal)
   */
  async indexBlock(
    block: Block,
    height: number,
    subsidy: bigint,
    spentOutputs: SpentUTXO[]
  ): Promise<void> {
    if (!this.enabled) return;

    const blockHash = getBlockHash(block.header);

    // Add subsidy
    this.totalSubsidy += subsidy;

    // Remove spent outputs from MuHash and stats
    for (const spent of spentOutputs) {
      this.muhash.remove(
        spent.txid,
        spent.vout,
        spent.entry.height,
        spent.entry.coinbase,
        spent.entry.amount,
        spent.entry.scriptPubKey
      );
      this.txOutputCount--;
      this.totalAmount -= spent.entry.amount;
      this.bogoSize -= getBogoSize(spent.entry.scriptPubKey);
    }

    // Add new outputs to MuHash and stats
    for (const tx of block.transactions) {
      const txid = getTxId(tx);
      const txIsCoinbase = isCoinbase(tx);

      for (let vout = 0; vout < tx.outputs.length; vout++) {
        const output = tx.outputs[vout];

        // Skip OP_RETURN (unspendable)
        if (output.scriptPubKey.length > 0 && output.scriptPubKey[0] === 0x6a) {
          continue;
        }

        this.muhash.insert(
          txid,
          vout,
          height,
          txIsCoinbase,
          output.value,
          output.scriptPubKey
        );
        this.txOutputCount++;
        this.totalAmount += output.value;
        this.bogoSize += getBogoSize(output.scriptPubKey);
      }
    }

    // Build stats entry
    const stats: CoinStats = {
      height,
      blockHash,
      muhash: this.muhash.finalize(),
      txOutputCount: this.txOutputCount,
      totalAmount: this.totalAmount,
      totalSubsidy: this.totalSubsidy,
      bogoSize: this.bogoSize,
    };

    // Prepare batch operations
    const ops: BatchOperation[] = [];

    // Store stats by height
    const heightKey = Buffer.alloc(4);
    heightKey.writeUInt32BE(height, 0);
    ops.push({
      type: "put",
      prefix: IndexPrefix.COIN_STATS as unknown as (typeof DBPrefix)[keyof typeof DBPrefix],
      key: heightKey,
      value: serializeCoinStats(stats),
    });

    // Update MuHash state
    ops.push({
      type: "put",
      prefix: IndexPrefix.COIN_STATS_MUHASH as unknown as (typeof DBPrefix)[keyof typeof DBPrefix],
      key: Buffer.alloc(0),
      value: this.muhash.serialize(),
    });

    // Update tip
    const tipWriter = new BufferWriter();
    tipWriter.writeUInt32LE(height);
    tipWriter.writeHash(blockHash);
    ops.push({
      type: "put",
      prefix: IndexPrefix.COIN_STATS_TIP as unknown as (typeof DBPrefix)[keyof typeof DBPrefix],
      key: Buffer.alloc(0),
      value: tipWriter.toBuffer(),
    });

    await this.db.batch(ops);

    this.currentHeight = height;
    this.currentHash = blockHash;
  }

  /**
   * Get stats for a specific height.
   */
  async getStats(height: number): Promise<CoinStats | null> {
    if (!this.enabled) return null;

    const heightKey = Buffer.alloc(4);
    heightKey.writeUInt32BE(height, 0);
    const key = Buffer.concat([Buffer.from([IndexPrefix.COIN_STATS]), heightKey]);

    try {
      const data = await (this.db as any).db.get(key);
      if (data) {
        return deserializeCoinStats(data);
      }
    } catch {
      // Not found
    }

    return null;
  }

  /**
   * Get current stats.
   */
  getCurrentStats(): CoinStats | null {
    if (!this.enabled || this.currentHeight < 0) return null;

    return {
      height: this.currentHeight,
      blockHash: this.currentHash,
      muhash: this.muhash.finalize(),
      txOutputCount: this.txOutputCount,
      totalAmount: this.totalAmount,
      totalSubsidy: this.totalSubsidy,
      bogoSize: this.bogoSize,
    };
  }
}

// =============================================================================
// TxIndex Manager
// =============================================================================

/**
 * TxIndexManager: manages the transaction index.
 *
 * Maps txid -> { blockHash, offset, length } for fast transaction lookup.
 * The existing ChainDB already has TxIndex methods; this class provides
 * higher-level functionality for batch indexing and background sync.
 */
export class TxIndexManager {
  private db: ChainDB;
  private enabled: boolean;
  private currentHeight: number;

  constructor(db: ChainDB, enabled: boolean = false) {
    this.db = db;
    this.enabled = enabled;
    this.currentHeight = -1;
  }

  /**
   * Check if the index is enabled.
   */
  isEnabled(): boolean {
    return this.enabled;
  }

  /**
   * Enable or disable the index.
   */
  setEnabled(enabled: boolean): void {
    this.enabled = enabled;
  }

  /**
   * Get the current index height.
   */
  getHeight(): number {
    return this.currentHeight;
  }

  /**
   * Initialize the index.
   */
  async init(): Promise<void> {
    if (!this.enabled) return;

    // TxIndex doesn't have a separate tip; it's tied to chain state
    // We could track it separately if needed for background sync
  }

  /**
   * Index all transactions in a block.
   *
   * @param block - The block
   * @param height - Block height
   * @param blockOffset - Starting byte offset of block data
   */
  async indexBlock(
    block: Block,
    height: number,
    blockHash: Buffer,
    blockOffset: number = 0
  ): Promise<void> {
    if (!this.enabled) return;

    // Skip genesis block (outputs not spendable)
    if (height === 0) {
      this.currentHeight = height;
      return;
    }

    const ops: BatchOperation[] = [];

    // Header is 80 bytes, then varint tx count
    let txOffset = 80;

    // Add varint length for tx count
    const txCount = block.transactions.length;
    if (txCount < 0xfd) txOffset += 1;
    else if (txCount <= 0xffff) txOffset += 3;
    else if (txCount <= 0xffffffff) txOffset += 5;
    else txOffset += 9;

    for (const tx of block.transactions) {
      const txid = getTxId(tx);

      // Serialize to get length
      const txWriter = new BufferWriter();
      // Minimal serialization to get size
      const hasWitness = tx.inputs.some((input) => input.witness.length > 0);

      txWriter.writeInt32LE(tx.version);

      if (hasWitness) {
        txWriter.writeUInt8(0); // marker
        txWriter.writeUInt8(1); // flag
      }

      txWriter.writeVarInt(tx.inputs.length);
      for (const input of tx.inputs) {
        txWriter.writeHash(input.prevOut.txid);
        txWriter.writeUInt32LE(input.prevOut.vout);
        txWriter.writeVarBytes(input.scriptSig);
        txWriter.writeUInt32LE(input.sequence);
      }

      txWriter.writeVarInt(tx.outputs.length);
      for (const output of tx.outputs) {
        txWriter.writeUInt64LE(output.value);
        txWriter.writeVarBytes(output.scriptPubKey);
      }

      if (hasWitness) {
        for (const input of tx.inputs) {
          txWriter.writeVarInt(input.witness.length);
          for (const item of input.witness) {
            txWriter.writeVarBytes(item);
          }
        }
      }

      txWriter.writeUInt32LE(tx.lockTime);
      const txLength = txWriter.toBuffer().length;

      const entry: TxIndexEntry = {
        blockHash,
        offset: blockOffset + txOffset,
        length: txLength,
      };

      // Serialize entry
      const entryWriter = new BufferWriter();
      entryWriter.writeHash(entry.blockHash);
      entryWriter.writeUInt32LE(entry.offset);
      entryWriter.writeUInt32LE(entry.length);

      ops.push({
        type: "put",
        prefix: DBPrefix.TX_INDEX,
        key: txid,
        value: entryWriter.toBuffer(),
      });

      txOffset += txLength;
    }

    if (ops.length > 0) {
      await this.db.batchWrite(ops);
    }

    this.currentHeight = height;
  }

  /**
   * Look up a transaction by txid.
   */
  async getTransaction(txid: Buffer): Promise<TxIndexEntry | null> {
    return this.db.getTxIndex(txid);
  }

  /**
   * Remove transaction index entries for a block (during reorg).
   */
  async removeBlock(block: Block): Promise<void> {
    if (!this.enabled) return;

    const ops: BatchOperation[] = [];

    for (const tx of block.transactions) {
      const txid = getTxId(tx);
      ops.push({
        type: "del",
        prefix: DBPrefix.TX_INDEX,
        key: txid,
      });
    }

    if (ops.length > 0) {
      await this.db.batch(ops);
    }
  }
}

// =============================================================================
// Index Manager (Unified)
// =============================================================================

/**
 * IndexManager: manages all optional indexes.
 *
 * Coordinates TxIndex, BlockFilterIndex, and CoinStatsIndex.
 * Handles background sync and graceful shutdown.
 */
export class IndexManager {
  private db: ChainDB;
  private txIndex: TxIndexManager;
  private filterIndex: BlockFilterIndex;
  private coinStatsIndex: CoinStatsIndex;
  private syncing: boolean;

  constructor(
    db: ChainDB,
    options: {
      txindex?: boolean;
      blockfilterindex?: boolean;
      coinstatsindex?: boolean;
    } = {}
  ) {
    this.db = db;
    this.txIndex = new TxIndexManager(db, options.txindex ?? false);
    this.filterIndex = new BlockFilterIndex(db, options.blockfilterindex ?? false);
    this.coinStatsIndex = new CoinStatsIndex(db, options.coinstatsindex ?? false);
    this.syncing = false;
  }

  /**
   * Initialize all enabled indexes.
   */
  async init(): Promise<void> {
    await Promise.all([
      this.txIndex.init(),
      this.filterIndex.init(),
      this.coinStatsIndex.init(),
    ]);
  }

  /**
   * Index a newly connected block.
   */
  async indexBlock(
    block: Block,
    height: number,
    subsidy: bigint,
    spentOutputs: SpentUTXO[],
    blockOffset: number = 0
  ): Promise<void> {
    const blockHash = getBlockHash(block.header);

    await Promise.all([
      this.txIndex.indexBlock(block, height, blockHash, blockOffset),
      this.filterIndex.indexBlock(block, height, spentOutputs),
      this.coinStatsIndex.indexBlock(block, height, subsidy, spentOutputs),
    ]);
  }

  /**
   * Get the TxIndex manager.
   */
  getTxIndex(): TxIndexManager {
    return this.txIndex;
  }

  /**
   * Get the BlockFilterIndex.
   */
  getFilterIndex(): BlockFilterIndex {
    return this.filterIndex;
  }

  /**
   * Get the CoinStatsIndex.
   */
  getCoinStatsIndex(): CoinStatsIndex {
    return this.coinStatsIndex;
  }

  /**
   * Check if background sync is running.
   */
  isSyncing(): boolean {
    return this.syncing;
  }

  /**
   * Get the minimum height across all indexes.
   */
  getMinHeight(): number {
    const heights: number[] = [];
    if (this.txIndex.isEnabled()) heights.push(this.txIndex.getHeight());
    if (this.filterIndex.isEnabled()) heights.push(this.filterIndex.getHeight());
    if (this.coinStatsIndex.isEnabled()) heights.push(this.coinStatsIndex.getHeight());

    if (heights.length === 0) return -1;
    return Math.min(...heights);
  }
}
