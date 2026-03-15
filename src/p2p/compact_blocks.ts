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
import { serializeBlockHeader } from "../validation/block.js";
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
   * @param compact - Compact block payload
   * @returns Status code
   */
  initData(compact: CmpctBlockPayload): ReadStatus {
    // Validate bounds
    if (this.txCount === 0) {
      return ReadStatus.INVALID;
    }

    // Per Bitcoin Core: max tx count = MAX_BLOCK_WEIGHT / MIN_SERIALIZABLE_TRANSACTION_WEIGHT
    // We'll use a conservative limit
    if (this.txCount > 100000) {
      return ReadStatus.INVALID;
    }

    // Place prefilled transactions
    let lastIndex = -1;
    for (const prefilled of compact.prefilledTxns) {
      // Decode differential index
      const absoluteIndex = prefilled.index;

      if (absoluteIndex >= this.txCount) {
        return ReadStatus.INVALID;
      }

      // Check for index ordering issues
      if (absoluteIndex <= lastIndex) {
        return ReadStatus.INVALID;
      }

      this.txnAvailable[absoluteIndex] = prefilled.tx;
      lastIndex = absoluteIndex;
    }
    this.prefilledCount = compact.prefilledTxns.length;

    // Build short ID -> index mapping
    let shortIdIdx = 0;
    const shortIdCollisionCheck = new Set<bigint>();

    for (let i = 0; i < this.txCount; i++) {
      if (this.txnAvailable[i] === undefined) {
        if (shortIdIdx >= compact.shortIds.length) {
          return ReadStatus.INVALID;
        }

        const shortIdValue = shortIdToValue(compact.shortIds[shortIdIdx]);

        // Check for collision in the compact block itself
        if (shortIdCollisionCheck.has(shortIdValue)) {
          // Short ID collision detected
          return ReadStatus.FAILED;
        }
        shortIdCollisionCheck.add(shortIdValue);

        this.shortIdToIndex.set(shortIdValue, i);
        shortIdIdx++;
      }
    }

    return ReadStatus.OK;
  }

  /**
   * Try to fill missing transactions from mempool.
   *
   * @param mempool - Mempool to search for transactions
   * @param extraTxn - Extra transactions to search (e.g., recently received)
   * @returns List of missing indices after mempool search
   */
  fillFromMempool(
    mempool: { getTransaction(txid: Buffer): MempoolEntry | null; getAllEntries?(): MempoolEntry[] },
    extraTxn: Transaction[] = []
  ): number[] {
    // Build set of indices we've filled
    const filled = new Set<number>();

    // Search mempool
    // We need to iterate all mempool transactions and compute their short IDs
    // This matches Bitcoin Core's approach for optimal cache behavior
    if (mempool.getAllEntries) {
      for (const entry of mempool.getAllEntries()) {
        const wtxid = getWTxId(entry.tx);
        const shortId = computeShortTxIdValue(this.k0, this.k1, wtxid);
        const idx = this.shortIdToIndex.get(shortId);

        if (idx !== undefined && !filled.has(idx)) {
          if (this.txnAvailable[idx] === undefined) {
            this.txnAvailable[idx] = entry.tx;
            filled.add(idx);
            this.mempoolCount++;
          } else {
            // Collision: two mempool txs match the same short ID
            // Clear and request via getblocktxn
            this.txnAvailable[idx] = undefined;
            this.mempoolCount--;
          }
        }

        // Early exit if we've filled all slots
        if (filled.size === this.shortIdToIndex.size) {
          break;
        }
      }
    }

    // Search extra transactions (recently received, orphan pool, etc.)
    for (const tx of extraTxn) {
      const wtxid = getWTxId(tx);
      const shortId = computeShortTxIdValue(this.k0, this.k1, wtxid);
      const idx = this.shortIdToIndex.get(shortId);

      if (idx !== undefined && this.txnAvailable[idx] === undefined) {
        this.txnAvailable[idx] = tx;
        filled.add(idx);
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
   * Get the fully reconstructed block.
   *
   * @returns Block if complete, null otherwise
   */
  getBlock(): Block | null {
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

    return {
      header: this.header,
      transactions,
    };
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
