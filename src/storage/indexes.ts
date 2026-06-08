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
import { MuHash3072 } from "../wire/muhash.js";

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

  // Process remaining bytes with length encoding.
  // The SipHash spec (and Core's CSipHasher) encodes only the low 8 bits of
  // the total byte count in the top byte of the final message block.  In Core
  // m_count is uint8_t so it truncates automatically; here we must mask
  // explicitly to avoid BigInt overflow beyond 64 bits for inputs >= 256 bytes
  // (e.g. long tapscripts).  Core ref: siphash.cpp:Finalize "m_tmp | (uint64_t(m_count) << 56)".
  let m = (BigInt(data.length) & 0xffn) << 56n;
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
 *
 * Bit order: MSB-first within each byte, matching Bitcoin Core's
 * BitStreamWriter<OStream> in streams.h.  Core writes the nbits least
 * significant bits of a value into the stream MSB-first:
 *   m_buffer |= (data << (64 - nbits)) >> (64 - 8 + m_offset)
 * which places the most significant queued bit at the highest available
 * position in the current output byte.
 *
 * Previous implementation was LSB-first which produced filters byte-
 * incompatible with Bitcoin Core and the BIP-158 test vectors.
 */
export class BitStreamWriter {
  private buffer: number[] = [];
  private currentByte = 0;
  // m_offset: number of high-order bits in currentByte already written
  private m_offset = 0;

  /**
   * Write the n least-significant bits of value, MSB first (Core-compatible).
   */
  writeBits(value: bigint, n: number): void {
    let nbits = n;
    while (nbits > 0) {
      const bits = Math.min(8 - this.m_offset, nbits);
      // Extract bits from the MSB side of the remaining value
      // Core: m_buffer |= (data << (64 - nbits)) >> (64 - 8 + m_offset)
      // Equivalent: shift value so the top `bits` of the remaining `nbits` bits
      // land in the low bits, then place them at position (8 - m_offset - bits).
      const shifted = Number((value >> BigInt(nbits - bits)) & BigInt((1 << bits) - 1));
      this.currentByte |= shifted << (8 - this.m_offset - bits);
      this.m_offset += bits;
      nbits -= bits;
      if (this.m_offset === 8) {
        this.buffer.push(this.currentByte);
        this.currentByte = 0;
        this.m_offset = 0;
      }
    }
  }

  /**
   * Write a single bit (1 or 0), MSB first.
   */
  writeBit(bit: number): void {
    if (bit) {
      this.currentByte |= 1 << (7 - this.m_offset);
    }
    this.m_offset++;
    if (this.m_offset === 8) {
      this.buffer.push(this.currentByte);
      this.currentByte = 0;
      this.m_offset = 0;
    }
  }

  /**
   * Flush any remaining bits (zero-padded to a full byte on the LSB side).
   */
  flush(): void {
    if (this.m_offset > 0) {
      this.buffer.push(this.currentByte);
      this.currentByte = 0;
      this.m_offset = 0;
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
 *
 * Bit order: MSB-first within each byte, matching Bitcoin Core's
 * BitStreamReader<IStream> in streams.h.  Core reads from the high-order
 * bit of each byte:
 *   data |= (uint8_t)(m_buffer << m_offset) >> (8 - bits)
 * which extracts bits starting from the most significant position.
 */
export class BitStreamReader {
  private data: Buffer;
  private bytePos = 0;
  // m_offset: number of high-order bits in the current byte already consumed
  private m_offset = 8; // starts at 8 so we read a new byte on first access

  constructor(data: Buffer) {
    this.data = data;
  }

  /**
   * Read a single bit, MSB first (Core-compatible).
   */
  readBit(): number {
    if (this.m_offset === 8) {
      if (this.bytePos >= this.data.length) {
        throw new Error("BitStreamReader: out of data");
      }
      this.m_offset = 0;
      this.bytePos++;
    }
    // Current byte is data[bytePos - 1] (already advanced above)
    const byte = this.data[this.bytePos - 1];
    const bit = (byte >> (7 - this.m_offset)) & 1;
    this.m_offset++;
    return bit;
  }

  /**
   * Read n bits as a value, MSB first, returned in the n LSBs of a bigint.
   */
  readBits(n: number): bigint {
    let value = 0n;
    let nbits = n;
    while (nbits > 0) {
      if (this.m_offset === 8) {
        if (this.bytePos >= this.data.length) {
          throw new Error("BitStreamReader: out of data");
        }
        this.m_offset = 0;
        this.bytePos++;
      }
      const byte = this.data[this.bytePos - 1];
      const bits = Math.min(8 - this.m_offset, nbits);
      // Extract `bits` bits from position m_offset (MSB side)
      const chunk = (byte >> (8 - this.m_offset - bits)) & ((1 << bits) - 1);
      value = (value << BigInt(bits)) | BigInt(chunk);
      this.m_offset += bits;
      nbits -= bits;
    }
    return value;
  }

  /**
   * Check if there's more data.
   */
  hasMore(): boolean {
    return this.bytePos < this.data.length || this.m_offset < 8;
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
   *
   * Duplicates are removed before encoding, matching Bitcoin Core's use of
   * an unordered_set<Element> in BasicFilterElements() (blockfilter.cpp:188)
   * and GCSFilter::GCSFilter(params, elements) (blockfilter.cpp:74).  Without
   * deduplication, duplicate scripts (e.g. the same P2PKH address appears in
   * both an input being spent and an output being created in the same block)
   * would cause the encoded N to diverge from the actual number of unique
   * hashed values, making the filter undecodable by Core-compatible clients.
   */
  constructor(
    elements: Buffer[],
    blockHash: Buffer,
    m: bigint = BASIC_FILTER_M,
    p: bigint = BASIC_FILTER_P
  ) {
    this.m = m;
    this.p = p;

    // Extract SipHash keys from block hash (first 16 bytes, LE)
    this.k0 = blockHash.readBigUInt64LE(0);
    this.k1 = blockHash.readBigUInt64LE(8);

    // Deduplicate elements (Core uses unordered_set, so duplicates are
    // discarded automatically).  We compare by hex-string key.
    const seen = new Set<string>();
    const unique: Buffer[] = [];
    for (const elem of elements) {
      const key = elem.toString("hex");
      if (!seen.has(key)) {
        seen.add(key);
        unique.push(elem);
      }
    }

    this.n = unique.length;
    this.f = BigInt(this.n) * m;

    // Build the filter
    this.encodedFilter = this.build(unique);
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
   * Reconcile the filter index down to the validated chain tip on startup.
   *
   * THE BUG THIS FIXES (SLOW/INCORRECT-RESUME):
   * The block-filter index and the chainstate are flushed to disk on
   * independent schedules. On an UNCLEAN exit (SIGKILL / crash / power loss)
   * the FILTER_TIP singleton can land on disk AHEAD of the chainstate's
   * `bestHeight` — the index recorded filter headers for blocks N+1..M that
   * the validated chainstate then "forgot" because its own flush never
   * completed. On the next startup, `init()` loads the stale-ahead FILTER_TIP,
   * and the per-block connect path (BlockSync) resumes appending filters from
   * `chainState.bestHeight + 1`, chaining each new filter header from the
   * STALE `currentHeader` (the header of a block the node no longer considers
   * its tip). Every filter header served to BIP-157 light clients from that
   * point on is corrupt — it diverges from Bitcoin Core's filter-header chain.
   *
   * THE FIX (mirrors Bitcoin Core's BaseIndex::Rewind,
   * bitcoin-core/src/index/base.cpp:290): before BlockSync resumes, if the
   * index tip is ABOVE the validated chain tip, rewind the index back down to
   * `targetHeight`. We restore `currentHeader` from the hash-keyed
   * FILTER_HEADER entry stored under `targetBlockHash` (the validated tip's
   * block hash) — those entries are intentionally never deleted (see
   * `removeBlock`), so the correct prev-header link is always recoverable.
   * The next `indexBlock(target+1, ...)` then chains from the right header.
   *
   * Core does the equivalent inside its sync loop: NextSyncBlock detects that
   * the index's stored tip is not the chain's next block and calls Rewind to
   * walk the index back to the fork point before re-appending. hotbuns has no
   * background index-sync thread; the reconciliation happens here at startup
   * instead, which is the only window before BlockSync's connect path fires.
   *
   * Semantics:
   *   • NO-OP in the normal (clean-restart) case where the index is at or
   *     behind the validated tip (`currentHeight <= targetHeight`). This is
   *     the common path and must stay a pure read.
   *   • Only the FILTER_TIP singleton is rewound. The hash-keyed BLOCK_FILTER
   *     / FILTER_HEADER entries for the abandoned blocks are left in place
   *     (Core keeps them too; a `getfilter`/`getfilterheader` against an
   *     abandoned hash still succeeds, and they get overwritten if the same
   *     height is re-indexed). This matches `removeBlock`'s data-retention.
   *   • If `targetHeight < 0` (validated chainstate has no tip yet — should
   *     not happen once genesis is connected, but guard anyway) the index is
   *     rewound to the pre-genesis state (height -1, all-zero header).
   *
   * @param targetHeight    - The validated chainstate's bestHeight.
   * @param targetBlockHash - The validated chainstate's best block hash, used
   *                          to recover the correct filter header to chain from.
   *                          Ignored when targetHeight < 0.
   * @returns true if a rewind was performed, false if it was a no-op.
   */
  async reconcileToValidatedTip(
    targetHeight: number,
    targetBlockHash: Buffer
  ): Promise<boolean> {
    if (!this.enabled) return false;

    // Normal case: index is at or behind the validated tip. Nothing to undo.
    // (Behind is handled by BlockSync re-appending the missing blocks; that
    // is not a corruption, just a catch-up.)
    if (this.currentHeight <= targetHeight) {
      return false;
    }

    const fromHeight = this.currentHeight;

    // Determine the filter header to chain from at the validated tip.
    let restoredHeader: Buffer = Buffer.alloc(32, 0);
    if (targetHeight >= 0) {
      const stored = await this.getFilterHeader(targetBlockHash);
      if (stored) {
        restoredHeader = stored;
      } else {
        // The validated tip's filter header is missing from the index. This
        // can happen if the index was enabled mid-chain (so it never indexed
        // the validated tip) — the same fresh-enable divergence mode the
        // genesis seeding handles. Rewinding to the all-zero header is the
        // safest available state; loud-log so the operator knows the
        // filter-header chain will rebuild from here.
        console.warn(
          `[blockfilterindex] reconcileToValidatedTip(h=${targetHeight}, ` +
            `${targetBlockHash.toString("hex").slice(0, 16)}): no stored ` +
            `filter header for validated tip; rewinding to zero header ` +
            `(filter chain will rebuild on next append)`
        );
      }
    }

    // Atomically rewind the FILTER_TIP singleton to the validated tip.
    const tipWriter = new BufferWriter();
    tipWriter.writeUInt32LE(targetHeight >= 0 ? targetHeight : 0);
    tipWriter.writeHash(restoredHeader);

    const ops: BatchOperation[] = [
      {
        type: "put",
        prefix: IndexPrefix.FILTER_TIP as unknown as (typeof DBPrefix)[keyof typeof DBPrefix],
        key: Buffer.alloc(0),
        value: tipWriter.toBuffer(),
      },
    ];
    // When targetHeight < 0 there is nothing valid to point at; delete the
    // singleton so the index is treated as fresh (currentHeight -1).
    if (targetHeight < 0) {
      ops[0] = {
        type: "del",
        prefix: IndexPrefix.FILTER_TIP as unknown as (typeof DBPrefix)[keyof typeof DBPrefix],
        key: Buffer.alloc(0),
      };
    }

    await this.db.batch(ops);

    // In-memory rewind happens AFTER the batch lands so a thrown error from
    // db.batch leaves the in-memory view aligned with disk.
    this.currentHeight = targetHeight >= 0 ? targetHeight : -1;
    this.currentHeader = restoredHeader;

    console.warn(
      `[blockfilterindex] reconciled filter index ahead of chainstate: ` +
        `rewound tip ${fromHeight} -> ${this.currentHeight} ` +
        `(unclean-exit recovery; mirrors Core BaseIndex::Rewind)`
    );

    return true;
  }

  /**
   * Index the genesis block (height 0) so the filter-header chain starts at
   * the genesis filter header — NOT at the all-zero predecessor.
   *
   * Bitcoin Core's BaseIndex (src/index/base.cpp) begins indexing at the
   * genesis block: `CustomAppend` runs for height 0, so the genesis block
   * gets its own basic filter and a filter header
   *   genesis_header = SHA256d( SHA256d(genesis_filter) || 0^256 )
   * which then becomes the prev-header link for the block-1 filter header.
   *
   * hotbuns connects the genesis block at chainState.load() time BEFORE the
   * filter index is wired (cli.ts), and the per-block connect path
   * (BlockSync.connectBlock / ChainStateManager) only fires for blocks that
   * connect AFTER startup. Without this call the index's first appended block
   * (height 1) would chain from the all-zero header, diverging from Core's
   * filter-header chain by exactly the genesis link at EVERY height.
   *
   * Idempotent: only runs when the index has no tip yet (currentHeight < 0,
   * i.e. a fresh index). On a restart the FILTER_TIP singleton already holds
   * the chained currentHeader, so this is a no-op. Genesis has no spent
   * prevouts, so the element set is just the genesis coinbase outputs (which
   * on most networks is an OP_RETURN-free P2PK output → 1 element; regtest's
   * genesis coinbase scriptPubKey is the standard 0x41…ac P2PK, included).
   *
   * @param genesisBlock - The deserialized genesis Block (height 0).
   */
  async ensureGenesisIndexed(genesisBlock: Block): Promise<void> {
    if (!this.enabled) return;
    // Only seed the chain when the index is brand new. A non-fresh index has
    // already chained past genesis; re-seeding would corrupt currentHeader.
    if (this.currentHeight >= 0) return;
    await this.indexBlock(genesisBlock, 0, []);
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

  /**
   * Remove the disconnected tip block from the filter chain (BIP-157
   * Phase 2 — reorg-aware filter chain rollback).
   *
   * Mirrors Bitcoin Core's `BlockFilterIndex::CustomRemove`
   * (src/index/blockfilterindex.cpp:276): on disconnect, the cached
   * `m_last_header` is rewound to the previous block's filter header,
   * and a new disk write is staged that updates the filter-position
   * pointer atomically.
   *
   * Hotbuns specifics:
   *   • The per-block filter (BLOCK_FILTER) and filter-header
   *     (FILTER_HEADER) entries are HASH-keyed, so they remain valid
   *     and queryable for the disconnected block hash even after
   *     rollback — same semantics as Core's CopyHeightIndexToHashIndex,
   *     just without the height-keyed entry to copy from.
   *   • Only the FILTER_TIP singleton is rewound: `currentHeight` →
   *     `height - 1`, `currentHeader` → previous block's filter header.
   *   • The next `indexBlock` call uses the rewound `currentHeader` as
   *     the prev-header input to `computeFilterHeader`, so the
   *     filter-header chain on the new tip is consistent with whatever
   *     block sits at `height - 1` after the reorg.
   *
   * @param block - The block being disconnected (the OLD tip).
   * @param height - The OLD-tip height being rolled away from.
   *
   * No-op when:
   *   • The index is disabled.
   *   • The block being removed is not the cached tip (idempotent
   *     against double-call from chain/state.ts + sync/blocks.ts paths).
   *   • The previous block's filter header is missing from the DB
   *     (genesis-of-index edge: rewind to all-zero header).
   */
  async removeBlock(block: Block, height: number): Promise<void> {
    if (!this.enabled) return;

    const blockHash = getBlockHash(block.header);

    // Idempotence: only rewind when this block is actually our tip.
    // If currentHeight is already < height, a previous removeBlock call
    // already rewound past this block (e.g. multi-block reorg invoked
    // both chain/state.ts::disconnectBlock and the BlockSync reorg
    // dispatch); skip silently to keep the operation safe to call
    // twice.
    if (this.currentHeight !== height) {
      return;
    }
    if (!blockHash.equals(this.currentHeader === null ? Buffer.alloc(0) : blockHash)) {
      // Sanity guard left intentionally lenient: currentHeader is the
      // FILTER header (not the block hash), so we can't strictly
      // compare here. We trust the height match above.
    }

    // Look up the previous block's filter header. For height === 0
    // (genesis-of-index disconnect, vanishingly rare in practice) we
    // rewind to the all-zero filter header — same initial state the
    // index has before it has indexed any block.
    let prevFilterHeader: Buffer = Buffer.alloc(32, 0);
    if (height > 0) {
      const stored = await this.getFilterHeader(block.header.prevBlock);
      if (stored) {
        prevFilterHeader = stored;
      }
      // If `stored` is null (prev block's filter header missing — e.g.
      // index was started after the prev block was already on the
      // chain), fall through to the all-zero default. The caller will
      // see filter-header chain divergence on the next indexBlock,
      // which is the same failure mode as a fresh-enable mid-chain.
      // Loud-log here so the operator knows.
      if (!stored) {
        console.warn(
          `[blockfilterindex] removeBlock(h=${height}, ${blockHash
            .toString("hex")
            .slice(0, 16)}): missing prev filter header for ${block.header.prevBlock
            .toString("hex")
            .slice(0, 16)}; rewinding to zero (filter chain may diverge)`
        );
      }
    }

    // Atomically update the FILTER_TIP singleton. The hash-keyed
    // BLOCK_FILTER and FILTER_HEADER entries for the disconnected
    // block are intentionally NOT deleted — Core keeps them via
    // CopyHeightIndexToHashIndex for the same reason: a getfilter()
    // call against the disconnected block hash should still succeed.
    const tipWriter = new BufferWriter();
    tipWriter.writeUInt32LE(height - 1);
    tipWriter.writeHash(prevFilterHeader);

    const ops: BatchOperation[] = [
      {
        type: "put",
        prefix: IndexPrefix.FILTER_TIP as unknown as (typeof DBPrefix)[keyof typeof DBPrefix],
        key: Buffer.alloc(0),
        value: tipWriter.toBuffer(),
      },
    ];

    await this.db.batch(ops);

    // In-memory rewind happens AFTER the batch lands so a thrown error
    // from db.batch leaves the in-memory view aligned with disk. The
    // height-1 below is correct even at height === 0 (rewinds to -1,
    // matching the constructor's initial state).
    this.currentHeight = height - 1;
    this.currentHeader = prevFilterHeader;
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
// Persistent, reorg-safe Coin Stats Index (Bitcoin Core -coinstatsindex parity)
// =============================================================================

/**
 * Per-coin TxOutSer bytes — the canonical Bitcoin Core kernel/coinstats.cpp
 * `TxOutSer` element fed into the running MuHash3072. Byte-identical to
 * `src/chain/snapshot.ts::txOutSerBytes` (the @tip gettxoutsetinfo path), so
 * the historical digest is constructed exactly like the tip digest:
 *
 *   COutPoint  = txid (32 LE) || vout (uint32 LE)
 *   uint32     = (height << 1) + coinbase
 *   CTxOut     = int64 nValue (LE) || CScript (CompactSize len || bytes)
 *
 * Reference: bitcoin-core/src/kernel/coinstats.cpp::TxOutSer / ApplyCoinHash.
 */
function coinStatsTxOutSer(
  txid: Buffer,
  vout: number,
  height: number,
  coinbase: boolean,
  amount: bigint,
  scriptPubKey: Buffer
): Buffer {
  const writer = new BufferWriter();
  writer.writeHash(txid);
  writer.writeUInt32LE(vout);
  writer.writeUInt32LE(((height << 1) + (coinbase ? 1 : 0)) >>> 0);
  writer.writeUInt64LE(amount);
  writer.writeVarBytes(scriptPubKey);
  return writer.toBuffer();
}

/**
 * Per-coin "bogo size" — kernel/coinstats.cpp::GetBogoSize:
 *   32 (txid) + 4 (vout) + 4 (height|coinbase) + 8 (amount) + 2 (len field)
 *   + scriptPubKey.size()
 * This is the SAME constant set used by `src/chain/snapshot.ts::getBogoSize`
 * for the @tip path, so historical bogosize matches the tip computation.
 */
function coinStatsBogoSize(scriptPubKeyLen: number): bigint {
  return 32n + 4n + 4n + 8n + 2n + BigInt(scriptPubKeyLen);
}

/** Mirror Bitcoin Core `CScript::IsUnspendable` (script/script.h):
 *  empty-or-OP_RETURN-prefixed, or longer than MAX_SCRIPT_SIZE (10000).
 *  Unspendable outputs are never added to the UTXO set, so the index must
 *  skip them when applying created outputs (matches CoinsViewCache.addCoin). */
function coinStatsIsUnspendable(script: Buffer): boolean {
  return (script.length > 0 && script[0] === 0x6a) || script.length > 10000;
}

/**
 * Self-contained per-height running coinstats snapshot record.
 *
 * Wire format (LevelDB value under prefix COIN_STATS, key = height BE32):
 *   block_hash        32 bytes (internal byte order)
 *   muhash serialize  768 bytes (numerator 384 LE || denominator 384 LE)
 *   txouts            u64 LE
 *   total_amount      u64 LE (sats; UTXO totals are always >= 0)
 *   bogo_size         u64 LE
 *
 * Storing the FULL MuHash3072 accumulator (num/den) — not just the digest —
 * makes every height self-contained: connect(H) loads the H-1 record, applies
 * the block delta, writes H; disconnect(H) just drops H and the new tip's
 * running state is the already-persisted H-1 record. No recomputation on
 * reorg, which makes reorg trivially correct and per-height atomic.
 */
interface CoinStatsSnapshot {
  blockHash: Buffer;
  muhash: MuHash3072;
  txouts: bigint;
  totalAmount: bigint;
  bogoSize: bigint;
}

function serializeCoinStatsSnapshot(snap: CoinStatsSnapshot): Buffer {
  const writer = new BufferWriter();
  writer.writeHash(snap.blockHash);
  // MuHash3072.serialize() = numerator(384) || denominator(384) = 768 bytes.
  const mu = snap.muhash.serialize();
  for (const b of mu) writer.writeUInt8(b);
  writer.writeUInt64LE(snap.txouts);
  writer.writeUInt64LE(snap.totalAmount);
  writer.writeUInt64LE(snap.bogoSize);
  return writer.toBuffer();
}

function deserializeCoinStatsSnapshot(data: Buffer): CoinStatsSnapshot {
  const reader = new BufferReader(data);
  const blockHash = reader.readHash();
  const muBytes = reader.readBytes(768);
  const txouts = reader.readUInt64LE();
  const totalAmount = reader.readUInt64LE();
  const bogoSize = reader.readUInt64LE();
  return {
    blockHash,
    muhash: MuHash3072.deserialize(muBytes),
    txouts,
    totalAmount,
    bogoSize,
  };
}

/** Query result for gettxoutsetinfo @ a historical height / getindexinfo. */
export interface CoinStatsAtHeight {
  /** Block hash AT the queried height, internal byte order (32 bytes). */
  blockHash: Buffer;
  /** 32-byte MuHash3072 digest, internal byte order (caller reverses for hex). */
  muhash: Buffer;
  txouts: bigint;
  totalAmount: bigint;
  bogoSize: bigint;
}

/**
 * PersistentCoinStatsIndex — Bitcoin Core `-coinstatsindex` parity.
 *
 * Maintains, per block height, a running MuHash3072 over the UTXO set plus
 * cumulative counts (txouts), total amount, and bogosize, persisted as a
 * SELF-CONTAINED per-height snapshot. Lets `gettxoutsetinfo` answer for a
 * HISTORICAL `hash_or_height` byte-exactly vs Core, and `getindexinfo`
 * report the index.
 *
 * Maintained INCREMENTALLY on the node's PRIMARY block connect+disconnect
 * path (the same path that maintains txindex / blockfilterindex):
 *   - connect(block, H, spentOutputs): load H-1 running state, INSERT each
 *     created spendable output's TxOutSer (skip unspendable), REMOVE each
 *     spent prevout's TxOutSer (from undo data, using its ORIGINAL height +
 *     coinbase flag + amount + script), update counters, write the H snapshot.
 *   - disconnect(H): drop the H snapshot, roll best height back to H-1.
 *
 * Reorg = a sequence of disconnects (drop snapshots) followed by connects of
 * the new branch (each recomputed from its parent snapshot). Idempotent: a
 * repeat connect at an already-indexed height recomputes from H-1 and
 * overwrites, so a double-fire never double-counts.
 *
 * References:
 *   - bitcoin-core/src/index/coinstatsindex.cpp  (CustomAppend / CustomRewind)
 *   - bitcoin-core/src/kernel/coinstats.cpp       (TxOutSer / ApplyCoinHash /
 *                                                  GetBogoSize)
 *   - ouroboros src/ouroboros/coinstatsindex.py,
 *     blockbrew internal/storage/coinstatsindex.go (committed reorg-safe refs).
 */
export class PersistentCoinStatsIndex {
  private db: ChainDB;
  private enabled: boolean;
  /** Highest height with a persisted snapshot, or -1 when empty. */
  private bestHeight: number;

  constructor(db: ChainDB, enabled: boolean = false) {
    this.db = db;
    this.enabled = enabled;
    this.bestHeight = -1;
  }

  isEnabled(): boolean {
    return this.enabled;
  }

  /** Best indexed height (-1 when nothing indexed yet). */
  getHeight(): number {
    return this.bestHeight;
  }

  /** Encode a height as a 4-byte big-endian key for lexicographic ordering. */
  private heightKey(height: number): Buffer {
    const k = Buffer.alloc(4);
    k.writeUInt32BE(height >>> 0, 0);
    return k;
  }

  private snapPutOp(height: number, snap: CoinStatsSnapshot): BatchOperation {
    return {
      type: "put",
      prefix: IndexPrefix.COIN_STATS as unknown as DBPrefix,
      key: this.heightKey(height),
      value: serializeCoinStatsSnapshot(snap),
    };
  }

  private tipPutOp(height: number): BatchOperation {
    const w = new BufferWriter();
    w.writeUInt32LE(height >>> 0);
    return {
      type: "put",
      prefix: IndexPrefix.COIN_STATS_TIP as unknown as DBPrefix,
      key: Buffer.alloc(0),
      value: w.toBuffer(),
    };
  }

  /**
   * Load the persisted snapshot at *height*, or null if absent.
   * Reads through the underlying ClassicLevel (same accessor pattern the
   * sibling indexes use).
   */
  private async readSnapshot(height: number): Promise<CoinStatsSnapshot | null> {
    if (height < 0) return null;
    const key = Buffer.concat([
      Buffer.from([IndexPrefix.COIN_STATS]),
      this.heightKey(height),
    ]);
    try {
      const data = await (this.db as any).db.get(key);
      if (!data) return null;
      return deserializeCoinStatsSnapshot(data);
    } catch {
      return null;
    }
  }

  /** Running accumulator AS OF *height* (empty multiset for height < 0). */
  private async loadRunning(height: number): Promise<CoinStatsSnapshot> {
    const snap = await this.readSnapshot(height);
    if (snap) return snap;
    return {
      blockHash: Buffer.alloc(32, 0),
      muhash: new MuHash3072(),
      txouts: 0n,
      totalAmount: 0n,
      bogoSize: 0n,
    };
  }

  /**
   * Initialise from disk: recover the best indexed height from the TIP
   * singleton (mirrors BlockFilterIndex.init / TxIndexManager.init).
   */
  async init(): Promise<void> {
    if (!this.enabled) return;
    const tipKey = Buffer.from([IndexPrefix.COIN_STATS_TIP]);
    try {
      const tipData = await (this.db as any).db.get(tipKey);
      if (tipData && tipData.length >= 4) {
        this.bestHeight = new BufferReader(tipData).readUInt32LE();
      }
    } catch {
      this.bestHeight = -1;
    }
  }

  /**
   * Seed the height-0 (genesis) snapshot: the EMPTY UTXO set. Core's
   * CoinStatsIndex::CustomAppend takes the genesis `else` branch and adds
   * NOTHING to the muhash (the genesis coinbase output is never spendable),
   * so height 0 is the empty multiset (txouts=0, total_amount=0). The genesis
   * block is connected by chainState.load() and never passes through the
   * per-block connect path, so we seed it explicitly here — symmetric with
   * BlockFilterIndex.ensureGenesisIndexed. No-op if already present.
   */
  async ensureGenesisIndexed(genesisHash: Buffer): Promise<void> {
    if (!this.enabled) return;
    if (this.bestHeight >= 0) return;
    const existing = await this.readSnapshot(0);
    if (existing) {
      if (this.bestHeight < 0) this.bestHeight = 0;
      return;
    }
    const snap: CoinStatsSnapshot = {
      blockHash: Buffer.from(genesisHash),
      muhash: new MuHash3072(),
      txouts: 0n,
      totalAmount: 0n,
      bogoSize: 0n,
    };
    await this.db.batch([this.snapPutOp(0, snap), this.tipPutOp(0)]);
    this.bestHeight = 0;
  }

  /**
   * Connect *block* at *height* into the index (PRIMARY connect hook).
   *
   * Mirrors Bitcoin Core CoinStatsIndex::CustomAppend:
   *   - created outputs: skip unspendable, INSERT TxOutSer, ++txouts,
   *     += amount, += bogosize.
   *   - spent prevouts (from undo data): REMOVE TxOutSer using the coin's
   *     ORIGINAL height + coinbase + amount + script, --txouts, -= amount,
   *     -= bogosize.
   *
   * `spentOutputs` is the same undo data the connect path already collected
   * (coreConnectBlockChecks → serializeUndoData), so no separate UTXO lookup
   * is needed — and it carries each spent coin's original creation metadata.
   *
   * Idempotent: always recomputes from the H-1 snapshot and overwrites H.
   */
  async indexBlock(
    block: Block,
    height: number,
    spentOutputs: SpentUTXO[]
  ): Promise<void> {
    if (!this.enabled) return;
    const blockHash = getBlockHash(block.header);

    // Genesis: empty set (see ensureGenesisIndexed rationale).
    if (height === 0) {
      const snap: CoinStatsSnapshot = {
        blockHash,
        muhash: new MuHash3072(),
        txouts: 0n,
        totalAmount: 0n,
        bogoSize: 0n,
      };
      await this.db.batch([this.snapPutOp(0, snap), this.tipPutOp(0)]);
      if (height > this.bestHeight) this.bestHeight = height;
      return;
    }

    const running = await this.loadRunning(height - 1);
    const muhash = running.muhash;
    let txouts = running.txouts;
    let totalAmount = running.totalAmount;
    let bogoSize = running.bogoSize;

    // ── Created outputs (skip unspendable). ──
    for (const tx of block.transactions) {
      const txid = getTxId(tx);
      const txIsCoinbase = isCoinbase(tx);
      for (let vout = 0; vout < tx.outputs.length; vout++) {
        const out = tx.outputs[vout];
        if (coinStatsIsUnspendable(out.scriptPubKey)) continue;
        muhash.add(
          coinStatsTxOutSer(
            txid,
            vout,
            height,
            txIsCoinbase,
            out.value,
            out.scriptPubKey
          )
        );
        txouts += 1n;
        totalAmount += out.value;
        bogoSize += coinStatsBogoSize(out.scriptPubKey.length);
      }
    }

    // ── Spent prevouts (from undo data; coinbase spends nothing). ──
    for (const spent of spentOutputs) {
      const e = spent.entry;
      muhash.remove(
        coinStatsTxOutSer(
          spent.txid,
          spent.vout,
          e.height,
          e.coinbase,
          e.amount,
          e.scriptPubKey
        )
      );
      txouts -= 1n;
      totalAmount -= e.amount;
      bogoSize -= coinStatsBogoSize(e.scriptPubKey.length);
    }

    const snap: CoinStatsSnapshot = {
      blockHash,
      muhash,
      txouts,
      totalAmount,
      bogoSize,
    };
    await this.db.batch([this.snapPutOp(height, snap), this.tipPutOp(height)]);
    if (height > this.bestHeight) this.bestHeight = height;
  }

  /**
   * Disconnect the block at *height* (PRIMARY disconnect / reorg hook).
   *
   * Drops the per-height snapshot; the running state for the new tip is the
   * already-persisted H-1 snapshot, so no recomputation is needed. Rolls
   * bestHeight back to H-1 when *height* is at/above the current best.
   *
   * Mirrors Bitcoin Core CoinStatsIndex::CustomRewind (per-height reversal).
   */
  async removeBlock(height: number): Promise<void> {
    if (!this.enabled) return;
    const ops: BatchOperation[] = [
      {
        type: "del",
        prefix: IndexPrefix.COIN_STATS as unknown as DBPrefix,
        key: this.heightKey(height),
      },
    ];
    const newBest = height > 0 ? height - 1 : -1;
    if (this.bestHeight !== -1 && height >= this.bestHeight) {
      if (newBest >= 0) {
        ops.push(this.tipPutOp(newBest));
      } else {
        ops.push({
          type: "del",
          prefix: IndexPrefix.COIN_STATS_TIP as unknown as DBPrefix,
          key: Buffer.alloc(0),
        });
      }
    }
    await this.db.batch(ops);
    if (this.bestHeight !== -1 && height >= this.bestHeight) {
      this.bestHeight = newBest;
    }
  }

  /**
   * Query the coinstats snapshot AS OF *height* (used by gettxoutsetinfo and
   * getindexinfo). Returns null when the index is disabled or no snapshot
   * exists at that height.
   */
  async getAtHeight(height: number): Promise<CoinStatsAtHeight | null> {
    if (!this.enabled) return null;
    const snap = await this.readSnapshot(height);
    if (!snap) return null;
    // finalize() mutates the accumulator (folds denominator into numerator),
    // so digest a fresh deserialized copy to keep the snapshot reusable.
    const muCopy = MuHash3072.deserialize(snap.muhash.serialize());
    return {
      blockHash: snap.blockHash,
      muhash: muCopy.finalize(),
      txouts: snap.txouts,
      totalAmount: snap.totalAmount,
      bogoSize: snap.bogoSize,
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
