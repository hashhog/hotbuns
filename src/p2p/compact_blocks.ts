/**
 * BIP152 Compact Block Relay implementation.
 *
 * Compact blocks allow efficient block propagation by using short transaction IDs
 * computed via SipHash. Receiving nodes can reconstruct the full block using
 * transactions from their mempool, only requesting missing transactions.
 *
 * Key features:
 * - Short ID: 6-byte SipHash of wtxid, truncated
 * - High-bandwidth mode: send cmpctblock immediately without inv->getdata
 * - Low-bandwidth mode: send inv first, wait for getdata before cmpctblock
 * - Version 1: pre-segwit serialization
 * - Version 2: witness serialization (post-segwit)
 *
 * Reference: BIP 152
 */

import type { Block, BlockHeader } from "../validation/block.js";
import type { Transaction } from "../validation/tx.js";
import type { Mempool, MempoolEntry } from "../mempool/mempool.js";
import { getTxId, getWTxId } from "../validation/tx.js";
import {
  serializeBlockHeader,
  MAX_BLOCK_WEIGHT,
  MIN_SERIALIZABLE_TRANSACTION_WEIGHT,
  checkWitnessMalleation,
} from "../validation/block.js";
import { sha256Hash } from "../crypto/primitives.js";
import { sipHash24 } from "../storage/indexes.js";
import type {
  CmpctBlockPayload,
  GetBlockTxnPayload,
  BlockTxnPayload,
  PrefilledTx,
} from "./messages.js";

// ============================================================================
// BIP152 Constants
// ============================================================================

/** Short transaction ID length in bytes */
export const SHORT_TXID_LENGTH = 6;

/** BIP152 version 1: pre-segwit (non-witness serialization) */
export const COMPACT_BLOCK_VERSION_1 = 1n;

/** BIP152 version 2: segwit (witness serialization) */
export const COMPACT_BLOCK_VERSION_2 = 2n;

/** Maximum high-bandwidth peers (send cmpctblock directly) */
export const MAX_HIGH_BANDWIDTH_PEERS = 3;

/** Maximum extra transactions to search for collision resolution */
export const MAX_EXTRA_TXN = 100;

/** Mask for extracting 6-byte short ID from SipHash result */
const SHORT_ID_MASK = 0xffffffffffffn;

// ============================================================================
// Compact Block State
// ============================================================================

/**
 * Tracks compact block relay negotiation state for a peer.
 */
export interface CompactBlockState {
  /** Whether we've received sendcmpct from this peer */
  peerSupportsCompact: boolean;

  /** Whether we've sent sendcmpct to this peer */
  weSentCompact: boolean;

  /** Peer's preferred compact block version (1 or 2) */
  peerVersion: bigint;

  /** Whether peer wants high-bandwidth mode (receive cmpctblock immediately) */
  peerWantsHighBandwidth: boolean;

  /** Whether we want high-bandwidth mode from this peer */
  weWantHighBandwidth: boolean;

  /** Blocks we've requested getblocktxn for (hash -> missing indices) */
  pendingBlockTxn: Map<string, PartiallyDownloadedBlock>;
}

/**
 * Statistics for compact block performance tracking.
 */
export interface CompactBlockStats {
  /** Total compact blocks received */
  compactBlocksReceived: number;

  /** Blocks successfully reconstructed from mempool alone */
  successfulReconstructions: number;

  /** Blocks requiring getblocktxn requests */
  reconstructionsWithRequests: number;

  /** Blocks that failed reconstruction entirely */
  failedReconstructions: number;

  /** Total transactions found in mempool during reconstruction */
  mempoolHits: number;

  /** Total transactions that needed to be requested */
  mempoolMisses: number;
}

/**
 * Create initial compact block state for a new peer.
 */
export function createCompactBlockState(): CompactBlockState {
  return {
    peerSupportsCompact: false,
    weSentCompact: false,
    peerVersion: 0n,
    peerWantsHighBandwidth: false,
    weWantHighBandwidth: false,
    pendingBlockTxn: new Map(),
  };
}

/**
 * Create initial statistics.
 */
export function createCompactBlockStats(): CompactBlockStats {
  return {
    compactBlocksReceived: 0,
    successfulReconstructions: 0,
    reconstructionsWithRequests: 0,
    failedReconstructions: 0,
    mempoolHits: 0,
    mempoolMisses: 0,
  };
}

// ============================================================================
// SipHash Short ID Calculation
// ============================================================================

/**
 * Derive SipHash keys from block header and nonce.
 *
 * Per BIP152: k0, k1 = SHA256(header || nonce)[0:8], SHA256(header || nonce)[8:16]
 *
 * @param header - Serialized block header (80 bytes)
 * @param nonce - 64-bit nonce
 * @returns [k0, k1] as bigints
 */
export function deriveSipHashKeys(
  header: Buffer,
  nonce: bigint
): [bigint, bigint] {
  // Serialize header || nonce
  const nonceBuffer = Buffer.alloc(8);
  nonceBuffer.writeBigUInt64LE(nonce, 0);
  const keyData = Buffer.concat([header, nonceBuffer]);

  // SHA256(header || nonce)
  const hash = sha256Hash(keyData);

  // Extract k0 (bytes 0-7) and k1 (bytes 8-15) as little-endian 64-bit integers
  const k0 = hash.readBigUInt64LE(0);
  const k1 = hash.readBigUInt64LE(8);

  return [k0, k1];
}

/**
 * Compute short transaction ID for compact blocks (BIP152).
 *
 * shortid = SipHash-2-4(k0, k1, wtxid) & 0xffffffffffff (6 bytes)
 *
 * IMPORTANT: Uses witness hash (wtxid), not regular txid.
 *
 * @param k0 - First SipHash key
 * @param k1 - Second SipHash key
 * @param wtxid - Witness transaction ID (32 bytes)
 * @returns 6-byte short ID as Buffer
 */
export function computeShortTxId(
  k0: bigint,
  k1: bigint,
  wtxid: Buffer
): Buffer {
  // SipHash-2-4 the wtxid
  const hash = sipHash24(k0, k1, wtxid);

  // Truncate to 6 bytes (48 bits)
  const shortId = hash & SHORT_ID_MASK;

  // Convert to 6-byte buffer (little-endian)
  const result = Buffer.alloc(SHORT_TXID_LENGTH);
  // Write as 8 bytes then truncate (since we can't write 6-byte int directly)
  const temp = Buffer.alloc(8);
  temp.writeBigUInt64LE(shortId, 0);
  temp.copy(result, 0, 0, 6);

  return result;
}

/**
 * Compute short ID and return as bigint (useful for map lookups).
 */
export function computeShortTxIdValue(
  k0: bigint,
  k1: bigint,
  wtxid: Buffer
): bigint {
  return sipHash24(k0, k1, wtxid) & SHORT_ID_MASK;
}

/**
 * Convert 6-byte short ID buffer to bigint.
 */
export function shortIdToValue(shortId: Buffer): bigint {
  if (shortId.length !== 6) {
    throw new Error(`Invalid short ID length: ${shortId.length}`);
  }
  // Read as 8 bytes padded with zeros
  const padded = Buffer.alloc(8);
  shortId.copy(padded, 0);
  return padded.readBigUInt64LE(0);
}

/**
 * Convert bigint short ID to 6-byte buffer.
 */
export function valueToShortId(value: bigint): Buffer {
  const temp = Buffer.alloc(8);
  temp.writeBigUInt64LE(value & SHORT_ID_MASK, 0);
  return temp.subarray(0, 6);
}

// ============================================================================
// Compact Block Creation
// ============================================================================

/**
 * Create a compact block from a full block.
 *
 * Per BIP152:
 * - Coinbase is always prefilled (index 0)
 * - Other transactions are represented by short IDs
 * - Transactions not expected to be in peer's mempool should be prefilled
 *
 * @param block - Full block to compact
 * @param nonce - Random nonce for short ID calculation
 * @param peerMempoolTxids - Optional set of wtxid hex strings expected in peer's mempool
 * @param version - BIP152 version (1 or 2)
 * @returns Compact block payload
 */
export function createCompactBlockFromBlock(
  block: Block,
  nonce: bigint,
  peerMempoolTxids: Set<string> = new Set(),
  version: bigint = COMPACT_BLOCK_VERSION_2
): CmpctBlockPayload {
  const headerSerialized = serializeBlockHeader(block.header);
  const [k0, k1] = deriveSipHashKeys(headerSerialized, nonce);

  const shortIds: Buffer[] = [];
  const prefilledTxns: PrefilledTx[] = [];

  for (let i = 0; i < block.transactions.length; i++) {
    const tx = block.transactions[i];

    // Always prefill coinbase
    if (i === 0) {
      prefilledTxns.push({ index: i, tx });
      continue;
    }

    // Use wtxid for short ID (BIP152 uses witness hash)
    const wtxid = getWTxId(tx);
    const wtxidHex = wtxid.toString("hex");

    // If transaction not expected in peer's mempool, prefill it
    if (peerMempoolTxids.size > 0 && !peerMempoolTxids.has(wtxidHex)) {
      prefilledTxns.push({ index: i, tx });
    } else {
      // Add short ID
      shortIds.push(computeShortTxId(k0, k1, wtxid));
    }
  }

  return {
    header: block.header,
    nonce,
    shortIds,
    prefilledTxns,
  };
}

// ============================================================================
// Partially Downloaded Block
// ============================================================================

/**
 * Status of compact block processing.
 */
export enum ReadStatus {
  /** Successfully processed */
  OK = 0,
  /** Invalid data from peer (misbehavior) */
  INVALID = 1,
  /** Failed to process (not necessarily misbehavior) */
  FAILED = 2,
}

/**
 * Represents a partially downloaded block from compact block relay.
 *
 * Holds the header and available transactions, tracking which slots
 * still need to be filled from getblocktxn responses.
 */
export class PartiallyDownloadedBlock {
  /** Block header */
  header: BlockHeader;

  /** Block hash (hex) */
  readonly blockHash: string;

  /** Total transaction count */
  readonly txCount: number;

  /** Available transactions (undefined = missing) */
  private txnAvailable: (Transaction | undefined)[];

  /** SipHash keys for short ID computation */
  private k0: bigint;
  private k1: bigint;

  /** Map from short ID (as bigint) to transaction index */
  private shortIdToIndex: Map<bigint, number>;

  /** Indices of missing transactions */
  private missingIndices: number[];

  /** Statistics */
  prefilledCount: number = 0;
  mempoolCount: number = 0;

  constructor(compact: CmpctBlockPayload, blockHash: string) {
    this.header = compact.header;
    this.blockHash = blockHash;
    this.txCount = compact.shortIds.length + compact.prefilledTxns.length;
    this.txnAvailable = new Array(this.txCount);
    this.shortIdToIndex = new Map();
    this.missingIndices = [];

    // Derive SipHash keys
    const headerSerialized = serializeBlockHeader(compact.header);
    [this.k0, this.k1] = deriveSipHashKeys(headerSerialized, compact.nonce);
  }

  /**
   * Initialize the partially downloaded block from a compact block.
   *
   * Mirrors Bitcoin Core PartiallyDownloadedBlock::InitData()
   * (blockencodings.cpp:59-181).
   *
   * Gates checked (Core line refs):
   *  G1  header.IsNull() || both lists empty  → INVALID  (L62-63)
   *  G2  BlockTxCount > MAX_BLOCK_WEIGHT / MIN_SERIALIZABLE_TRANSACTION_WEIGHT → INVALID (L64-65)
   *  G3  BlockTxCount > uint16_t::max → INVALID  (serializer gate, L125-128)
   *  G4  prefilled tx IsNull() → INVALID  (L74-76)
   *  G5  prefilled absolute index overflow uint16_t → INVALID  (L77-79)
   *  G6  prefilled index > available slots → INVALID  (L80-85)
   *  G7  short-ID bucket size > 12 → FAILED  (L110-111, DoS gate)
   *  G8  short-ID set collision (map.size != count) → FAILED  (L115-116)
   *
   * @param compact - Compact block payload (with absolute-decoded prefilled indices)
   * @returns Status code
   */
  initData(compact: CmpctBlockPayload): ReadStatus {
    // G1: header null or both lists empty
    if (this.txCount === 0) {
      return ReadStatus.INVALID;
    }

    // G2: max tx count = MAX_BLOCK_WEIGHT / MIN_SERIALIZABLE_TRANSACTION_WEIGHT
    // Core: blockencodings.cpp:64-65
    const MAX_CMPCT_TX_COUNT = Math.floor(MAX_BLOCK_WEIGHT / MIN_SERIALIZABLE_TRANSACTION_WEIGHT);
    if (this.txCount > MAX_CMPCT_TX_COUNT) {
      return ReadStatus.INVALID;
    }

    // G3: BlockTxCount must fit in uint16_t (65535)
    // Core: blockencodings.h:125-128 serializer gate
    if (this.txCount > 0xffff) {
      return ReadStatus.INVALID;
    }

    // Place prefilled transactions
    let lastPrefilledIndex = -1;
    for (let i = 0; i < compact.prefilledTxns.length; i++) {
      const prefilled = compact.prefilledTxns[i];

      // G4: prefilled tx must not be null/empty
      // Core: blockencodings.cpp:74-76
      if (!prefilled.tx) {
        return ReadStatus.INVALID;
      }

      const absoluteIndex = prefilled.index;

      // G5: absolute index must fit in uint16_t
      // Core: blockencodings.cpp:77-79 (lastprefilledindex > uint16_t max)
      if (absoluteIndex > 0xffff) {
        return ReadStatus.INVALID;
      }

      // G6: index must not exceed available slots
      // Core: blockencodings.cpp:80-85
      // "If inserting at an index greater than shorttxids.size() + prefilled inserted so far"
      if (absoluteIndex > compact.shortIds.length + i) {
        return ReadStatus.INVALID;
      }

      if (absoluteIndex >= this.txCount) {
        return ReadStatus.INVALID;
      }

      // Indices must be strictly increasing
      if (absoluteIndex <= lastPrefilledIndex) {
        return ReadStatus.INVALID;
      }

      this.txnAvailable[absoluteIndex] = prefilled.tx;
      lastPrefilledIndex = absoluteIndex;
    }
    this.prefilledCount = compact.prefilledTxns.length;

    // Build short ID -> index mapping with bucket-size DoS guard.
    // Core uses std::unordered_map with default load-factor=1.0, bucket_size().
    // We simulate the bucket-size-12 gate with a collision-count map.
    // Core: blockencodings.cpp:94-116
    //
    // G7: bucket-size > 12 → READ_STATUS_FAILED
    //   With S short IDs and load factor 1.0, bucket count ≈ S.
    //   P(any bucket > 12) ≈ 0 for honest traffic; adversarial input can
    //   force collisions deterministically — bail early at depth 12.
    //
    // G8: size mismatch after insert (exact duplicate short ID) → FAILED
    const bucketCollisionCount = new Map<bigint, number>();
    let shortIdIdx = 0;

    for (let i = 0; i < this.txCount; i++) {
      if (this.txnAvailable[i] === undefined) {
        if (shortIdIdx >= compact.shortIds.length) {
          return ReadStatus.INVALID;
        }

        const shortIdValue = shortIdToValue(compact.shortIds[shortIdIdx]);

        // G7: bucket-size check — each unique short ID maps to one bucket;
        // collisions increment that bucket's count.
        const prev = bucketCollisionCount.get(shortIdValue) ?? 0;
        if (prev >= 12) {
          return ReadStatus.FAILED;
        }
        bucketCollisionCount.set(shortIdValue, prev + 1);

        this.shortIdToIndex.set(shortIdValue, i);
        shortIdIdx++;
      }
    }

    // G8: exact duplicate detection — if any short ID appeared more than once,
    // shortIdToIndex.size < compact.shortIds.length.
    // Core: blockencodings.cpp:115-116
    if (this.shortIdToIndex.size !== compact.shortIds.length) {
      return ReadStatus.FAILED;
    }

    return ReadStatus.OK;
  }

  /**
   * Try to fill missing transactions from mempool and extra pool.
   *
   * Mirrors Bitcoin Core PartiallyDownloadedBlock::InitData() mempool scan
   * and extra_txn scan (blockencodings.cpp:118-176).
   *
   * Key correctness invariants (Core line refs):
   *  - have_txn[] tracks which slots are claimed, preventing a third mempool
   *    tx from re-filling a slot that was already cleared by a collision
   *    (L125-136).  Without this a 3-way collision can silently fill a slot
   *    with the wrong tx.
   *  - extra_txn collision gate: only clear when the new tx's witness hash
   *    differs from the previously-installed one (L163-165).  Avoids thrashing
   *    on duplicate extra entries that carry the same tx.
   *  - Early exit when all short-ID slots are filled (L142-144, L174-176).
   *
   * @param mempool - Mempool to search for transactions
   * @param extraTxn - Extra transactions to search (e.g., recently evicted, orphan pool)
   * @returns List of missing indices after mempool search
   */
  fillFromMempool(
    mempool: { getTransaction(txid: Buffer): MempoolEntry | null; getAllEntries?(): MempoolEntry[] },
    extraTxn: Transaction[] = []
  ): number[] {
    // have_txn[i] tracks whether slot i has been claimed (filled OR collided-and-cleared).
    // Core: blockencodings.cpp:118 `std::vector<bool> have_txn(txn_available.size())`
    const haveTxn: boolean[] = new Array(this.txCount).fill(false);

    // Pre-mark prefilled slots as "have" so they are not re-filled.
    for (let i = 0; i < this.txCount; i++) {
      if (this.txnAvailable[i] !== undefined) {
        haveTxn[i] = true;
      }
    }

    // Search mempool — iterate all entries and compute short IDs.
    // Core: blockencodings.cpp:120-145
    if (mempool.getAllEntries) {
      for (const entry of mempool.getAllEntries()) {
        const wtxid = getWTxId(entry.tx);
        const shortId = computeShortTxIdValue(this.k0, this.k1, wtxid);
        const idx = this.shortIdToIndex.get(shortId);

        if (idx !== undefined) {
          if (!haveTxn[idx]) {
            // First match for this slot — fill it.
            this.txnAvailable[idx] = entry.tx;
            haveTxn[idx] = true;
            this.mempoolCount++;
          } else {
            // Collision: a second mempool tx hashes to the same short ID.
            // Clear the slot; request via getblocktxn.
            // haveTxn[idx] stays true to prevent a third tx refilling the slot.
            // Core: blockencodings.cpp:132-136
            if (this.txnAvailable[idx] !== undefined) {
              this.txnAvailable[idx] = undefined;
              this.mempoolCount--;
            }
            // (if already undefined, this is a 3rd+ collision — no-op)
          }
        }

        // Early exit: all short-ID slots are filled (Core L142-144).
        if (this.mempoolCount === this.shortIdToIndex.size) {
          break;
        }
      }
    }

    // Search extra transactions (recently received, recently evicted, etc.)
    // Core: blockencodings.cpp:147-176
    for (const tx of extraTxn) {
      const wtxid = getWTxId(tx);
      const shortId = computeShortTxIdValue(this.k0, this.k1, wtxid);
      const idx = this.shortIdToIndex.get(shortId);

      if (idx !== undefined) {
        if (!haveTxn[idx]) {
          // First match — fill from extra pool.
          this.txnAvailable[idx] = tx;
          haveTxn[idx] = true;
          this.mempoolCount++;
        } else {
          // Collision between extra_txn and an already-filled slot.
          // Only clear if the witness hashes differ — avoids thrashing on
          // duplicate entries that carry the same transaction.
          // Core: blockencodings.cpp:163-168
          if (
            this.txnAvailable[idx] !== undefined &&
            !getWTxId(this.txnAvailable[idx]!).equals(wtxid)
          ) {
            this.txnAvailable[idx] = undefined;
            this.mempoolCount--;
          }
          // (if already undefined, or same wtxid, no-op)
        }
      }

      // Early exit (Core L174-176).
      if (this.mempoolCount === this.shortIdToIndex.size) {
        break;
      }
    }

    // Compute missing indices
    this.missingIndices = [];
    for (let i = 0; i < this.txCount; i++) {
      if (this.txnAvailable[i] === undefined) {
        this.missingIndices.push(i);
      }
    }

    return this.missingIndices;
  }

  /**
   * Check if a transaction slot is available.
   */
  isTxAvailable(index: number): boolean {
    return index < this.txCount && this.txnAvailable[index] !== undefined;
  }

  /**
   * Get missing transaction indices.
   */
  getMissingIndices(): number[] {
    return this.missingIndices;
  }

  /**
   * Fill missing transactions from a blocktxn response.
   *
   * @param txns - Transactions from blocktxn message
   * @returns true if block is now complete
   */
  fillFromBlockTxn(txns: Transaction[]): boolean {
    if (txns.length !== this.missingIndices.length) {
      return false;
    }

    for (let i = 0; i < txns.length; i++) {
      const idx = this.missingIndices[i];
      this.txnAvailable[idx] = txns[i];
    }

    this.missingIndices = [];
    return true;
  }

  /**
   * Check if the block is fully reconstructed.
   */
  isComplete(): boolean {
    return this.missingIndices.length === 0;
  }

  /**
   * Get the fully reconstructed block, with optional mutation check.
   *
   * Mirrors Bitcoin Core PartiallyDownloadedBlock::FillBlock()
   * (blockencodings.cpp:191-237).
   *
   * After filling all slots, Core calls IsBlockMutated(block, segwit_active)
   * to detect short-ID collisions that produced a formally-complete but
   * internally-inconsistent block (e.g. wrong merkle root or bad witness
   * commitment).  On failure it returns READ_STATUS_FAILED ("Possible Short
   * ID collision", L221).
   *
   * segwitActive defaults to true — callers that know segwit is not active
   * for this block height may pass false to skip the witness commitment check.
   *
   * @param segwitActive - Whether segwit is active at this block's height
   * @returns Block if complete and not mutated, null otherwise
   */
  getBlock(segwitActive: boolean = true): Block | null {
    if (!this.isComplete()) {
      return null;
    }

    // Verify all slots are filled
    const transactions: Transaction[] = [];
    for (let i = 0; i < this.txCount; i++) {
      const tx = this.txnAvailable[i];
      if (tx === undefined) {
        return null;
      }
      transactions.push(tx);
    }

    const block: Block = {
      header: this.header,
      transactions,
    };

    // IsBlockMutated check: verify merkle root and (if segwit active) witness
    // commitment.  A short-ID collision can produce a syntactically valid
    // compact block that reconstructs into a mutated full block.
    // Core: blockencodings.cpp:219-221
    const malleation = checkWitnessMalleation(block, segwitActive);
    if (!malleation.valid) {
      // READ_STATUS_FAILED — possible short-ID collision
      return null;
    }

    return block;
  }
}

// ============================================================================
// Compact Block Manager
// ============================================================================

/**
 * Manages BIP152 compact block relay for a node.
 *
 * Handles:
 * - Negotiating compact block support with peers
 * - Tracking high-bandwidth and low-bandwidth peers
 * - Creating compact blocks for relay
 * - Reconstructing received compact blocks
 * - Requesting missing transactions
 */
export class CompactBlockManager {
  /** Per-peer compact block state */
  private peerStates: Map<string, CompactBlockState> = new Map();

  /** Global statistics */
  private stats: CompactBlockStats = createCompactBlockStats();

  /** High-bandwidth peers (max 3) that receive cmpctblock immediately */
  private highBandwidthPeers: Set<string> = new Set();

  /** Our supported version */
  private ourVersion: bigint = COMPACT_BLOCK_VERSION_2;

  /**
   * Get or create state for a peer.
   */
  getState(peerId: string): CompactBlockState {
    let state = this.peerStates.get(peerId);
    if (!state) {
      state = createCompactBlockState();
      this.peerStates.set(peerId, state);
    }
    return state;
  }

  /**
   * Handle received sendcmpct message.
   *
   * @param peerId - Peer identifier
   * @param enabled - Whether peer enables compact blocks
   * @param version - BIP152 version peer supports
   */
  handleSendCmpct(peerId: string, enabled: boolean, version: bigint): void {
    const state = this.getState(peerId);
    state.peerSupportsCompact = enabled;
    state.peerVersion = version;
    state.peerWantsHighBandwidth = enabled;
  }

  /**
   * Process our sendcmpct to a peer.
   *
   * @param peerId - Peer identifier
   * @param highBandwidth - Whether we want high-bandwidth mode
   */
  sentSendCmpct(peerId: string, highBandwidth: boolean): void {
    const state = this.getState(peerId);
    state.weSentCompact = true;
    state.weWantHighBandwidth = highBandwidth;

    if (highBandwidth && this.highBandwidthPeers.size < MAX_HIGH_BANDWIDTH_PEERS) {
      this.highBandwidthPeers.add(peerId);
    }
  }

  /**
   * Check if peer supports compact blocks.
   */
  peerSupportsCompact(peerId: string): boolean {
    const state = this.peerStates.get(peerId);
    return state?.peerSupportsCompact ?? false;
  }

  /**
   * Get the negotiated version with a peer.
   * Returns the minimum of our version and peer's version.
   */
  getNegotiatedVersion(peerId: string): bigint {
    const state = this.peerStates.get(peerId);
    if (!state?.peerSupportsCompact) {
      return 0n;
    }
    return state.peerVersion < this.ourVersion ? state.peerVersion : this.ourVersion;
  }

  /**
   * Check if peer is a high-bandwidth peer.
   */
  isHighBandwidthPeer(peerId: string): boolean {
    return this.highBandwidthPeers.has(peerId);
  }

  /**
   * Add peer to high-bandwidth set (if space available).
   */
  addHighBandwidthPeer(peerId: string): boolean {
    if (this.highBandwidthPeers.size >= MAX_HIGH_BANDWIDTH_PEERS) {
      return false;
    }
    this.highBandwidthPeers.add(peerId);
    return true;
  }

  /**
   * Remove peer from high-bandwidth set.
   */
  removeHighBandwidthPeer(peerId: string): void {
    this.highBandwidthPeers.delete(peerId);
  }

  /**
   * Create a compact block for sending to a peer.
   *
   * @param block - Full block
   * @param peerId - Target peer
   * @param peerMempoolTxids - Set of wtxid hex strings expected in peer's mempool
   * @returns Compact block payload and nonce
   */
  createCompactBlock(
    block: Block,
    peerId: string,
    peerMempoolTxids: Set<string> = new Set()
  ): CmpctBlockPayload {
    // Generate random nonce
    const nonceBuffer = crypto.getRandomValues(new Uint8Array(8));
    const nonce = Buffer.from(nonceBuffer).readBigUInt64LE(0);

    const version = this.getNegotiatedVersion(peerId) || COMPACT_BLOCK_VERSION_2;

    return createCompactBlockFromBlock(block, nonce, peerMempoolTxids, version);
  }

  /**
   * Start processing a received compact block.
   *
   * @param compact - Received compact block
   * @param blockHash - Block hash (hex)
   * @param peerId - Sending peer
   * @returns PartiallyDownloadedBlock or null if invalid
   */
  startBlockReconstruction(
    compact: CmpctBlockPayload,
    blockHash: string,
    peerId: string
  ): PartiallyDownloadedBlock | null {
    this.stats.compactBlocksReceived++;

    const partial = new PartiallyDownloadedBlock(compact, blockHash);
    const status = partial.initData(compact);

    if (status === ReadStatus.INVALID) {
      this.stats.failedReconstructions++;
      return null;
    }

    if (status === ReadStatus.FAILED) {
      // Short ID collision - fall back to full block request
      this.stats.failedReconstructions++;
      return null;
    }

    // Store in pending state for this peer
    const state = this.getState(peerId);
    state.pendingBlockTxn.set(blockHash, partial);

    return partial;
  }

  /**
   * Try to complete block reconstruction using mempool.
   *
   * @param partial - Partially downloaded block
   * @param mempool - Mempool to search
   * @param extraTxn - Additional transactions to search
   * @returns Missing indices (empty if complete)
   */
  tryFillFromMempool(
    partial: PartiallyDownloadedBlock,
    mempool: { getTransaction(txid: Buffer): MempoolEntry | null; getAllEntries?(): MempoolEntry[] },
    extraTxn: Transaction[] = []
  ): number[] {
    const missing = partial.fillFromMempool(mempool, extraTxn);

    this.stats.mempoolHits += partial.mempoolCount;
    this.stats.mempoolMisses += missing.length;

    if (missing.length === 0) {
      this.stats.successfulReconstructions++;
    } else {
      this.stats.reconstructionsWithRequests++;
    }

    return missing;
  }

  /**
   * Create getblocktxn request for missing transactions.
   *
   * @param blockHash - Block hash
   * @param missingIndices - Indices of missing transactions
   * @returns GetBlockTxnPayload
   */
  createGetBlockTxn(
    blockHash: Buffer,
    missingIndices: number[]
  ): GetBlockTxnPayload {
    return {
      blockHash,
      indexes: missingIndices,
    };
  }

  /**
   * Handle received blocktxn message.
   *
   * @param peerId - Sending peer
   * @param payload - BlockTxn payload
   * @returns Reconstructed block or null
   */
  handleBlockTxn(peerId: string, payload: BlockTxnPayload): Block | null {
    const state = this.peerStates.get(peerId);
    if (!state) {
      return null;
    }

    const blockHashHex = payload.blockHash.toString("hex");
    const partial = state.pendingBlockTxn.get(blockHashHex);
    if (!partial) {
      return null;
    }

    if (!partial.fillFromBlockTxn(payload.transactions)) {
      return null;
    }

    // Remove from pending
    state.pendingBlockTxn.delete(blockHashHex);

    return partial.getBlock();
  }

  /**
   * Clean up peer state on disconnect.
   */
  removePeer(peerId: string): void {
    this.peerStates.delete(peerId);
    this.highBandwidthPeers.delete(peerId);
  }

  /**
   * Get current statistics.
   */
  getStats(): CompactBlockStats {
    return { ...this.stats };
  }

  /**
   * Get reconstruction success rate.
   */
  getSuccessRate(): number {
    const total = this.stats.successfulReconstructions +
                  this.stats.reconstructionsWithRequests +
                  this.stats.failedReconstructions;
    if (total === 0) return 1.0;
    return this.stats.successfulReconstructions / total;
  }

  /**
   * Get mempool hit rate.
   */
  getMempoolHitRate(): number {
    const total = this.stats.mempoolHits + this.stats.mempoolMisses;
    if (total === 0) return 1.0;
    return this.stats.mempoolHits / total;
  }
}

// ============================================================================
// Helper for creating blocktxn response
// ============================================================================

/**
 * Create a blocktxn response for a getblocktxn request.
 *
 * @param block - Full block
 * @param request - GetBlockTxn request
 * @returns BlockTxn response or null if block doesn't match
 */
export function createBlockTxnResponse(
  block: Block,
  request: GetBlockTxnPayload
): BlockTxnPayload | null {
  const transactions: Transaction[] = [];

  for (const idx of request.indexes) {
    if (idx >= block.transactions.length) {
      return null; // Invalid index
    }
    transactions.push(block.transactions[idx]);
  }

  return {
    blockHash: request.blockHash,
    transactions,
  };
}

// Re-export types from messages for convenience
export type {
  CmpctBlockPayload,
  GetBlockTxnPayload,
  BlockTxnPayload,
  PrefilledTx,
} from "./messages.js";
