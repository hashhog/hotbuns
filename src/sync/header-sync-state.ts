/**
 * Header-sync anti-DoS state machine (PRESYNC/REDOWNLOAD).
 *
 * Implements Bitcoin Core's strategy to prevent memory exhaustion attacks where
 * a peer sends millions of low-work headers. The mechanism works in two phases:
 *
 * 1. PRESYNC: Accept headers without storing them permanently. Only track:
 *    - Cumulative chain work (BigInt)
 *    - Last header hash (for continuity check)
 *    - Bit commitments at regular intervals (for verification in REDOWNLOAD)
 *
 * 2. REDOWNLOAD: Once the chain demonstrates sufficient work (> nMinimumChainWork),
 *    re-request all headers from the beginning and store them permanently, verifying
 *    against the commitments stored during PRESYNC.
 *
 * Reference: Bitcoin Core headerssync.cpp, headerssync.h
 */

import { hash256 } from "../crypto/primitives.js";
import {
  type ConsensusParams,
  compactToBigInt,
} from "../consensus/params.js";
import {
  permittedDifficultyTransition,
  getBlockWork,
} from "../consensus/pow.js";
import type { BlockHeader } from "../validation/block.js";
import { getBlockHash } from "../validation/block.js";

/** Maximum headers per getheaders message. */
export const MAX_HEADERS_RESULTS = 2000;

/**
 * Parameters controlling the anti-DoS header sync behavior.
 */
export interface HeadersSyncParams {
  /**
   * How often to store a commitment (every N headers).
   * Lower values use more memory but provide stronger verification.
   */
  readonly commitmentPeriod: number;

  /**
   * Number of headers to buffer during REDOWNLOAD before releasing.
   * Headers are released once enough commitments have been verified.
   */
  readonly redownloadBufferSize: number;
}

/** Default parameters (similar to Bitcoin Core mainnet). */
export const DEFAULT_HEADERS_SYNC_PARAMS: HeadersSyncParams = {
  commitmentPeriod: 600,
  redownloadBufferSize: 12_000,
};

/**
 * State of the header sync process.
 */
export enum HeadersSyncStateEnum {
  /**
   * PRESYNC: Building commitments to the peer's chain.
   * Not storing headers permanently yet.
   */
  PRESYNC = "presync",

  /**
   * REDOWNLOAD: The peer's chain has sufficient work.
   * Re-downloading and verifying headers against commitments.
   */
  REDOWNLOAD = "redownload",

  /**
   * FINAL: Sync is complete or aborted. No more processing.
   */
  FINAL = "final",
}

/**
 * Result of processing a batch of headers.
 */
export interface ProcessingResult {
  /**
   * Headers that have been PoW-validated and are ready for acceptance
   * into the permanent block index.
   */
  powValidatedHeaders: BlockHeader[];

  /**
   * Whether the processing was successful (no errors detected).
   */
  success: boolean;

  /**
   * Whether the caller should request more headers from this peer.
   */
  requestMore: boolean;
}

/**
 * Compressed header for storage during REDOWNLOAD.
 * Saves memory by not storing prevBlock (can be reconstructed).
 */
interface CompressedHeader {
  version: number;
  merkleRoot: Buffer;
  timestamp: number;
  bits: number;
  nonce: number;
}

/**
 * Per-peer header sync state machine.
 *
 * Manages the PRESYNC/REDOWNLOAD anti-DoS mechanism for a single peer.
 * Each peer connection should have its own HeadersSyncState instance.
 */
export class HeadersSyncState {
  /** Current state of the sync process. */
  private state: HeadersSyncStateEnum;

  /** Consensus parameters for the network. */
  private readonly params: ConsensusParams;

  /** Anti-DoS sync parameters. */
  private readonly syncParams: HeadersSyncParams;

  /** Hash of the starting block (where sync begins from). */
  private readonly chainStartHash: Buffer;

  /** Height of the starting block. */
  private readonly chainStartHeight: number;

  /** Target bits of the starting block. */
  private readonly chainStartBits: number;

  /** Chain work at the starting block. */
  private readonly chainStartWork: bigint;

  /** Minimum work required to transition to REDOWNLOAD. */
  private readonly minimumRequiredWork: bigint;

  /** Cumulative work seen during PRESYNC. */
  private currentChainWork: bigint;

  /** Height of last header received during PRESYNC. */
  private currentHeight: number;

  /** Last header received during PRESYNC (for continuity check). */
  private lastHeaderReceived: BlockHeader | null;

  /** Last header hash received during PRESYNC. */
  private lastHeaderHash: Buffer | null;

  /**
   * Bit commitments stored during PRESYNC.
   * Each bit is a hash of the header at that commitment point.
   */
  private headerCommitments: boolean[];

  /**
   * Random offset for commitment positions.
   * Commitments are stored at heights where (height % period) == offset.
   */
  private readonly commitOffset: number;

  /** Salt for hashing commitments (random per-instance). */
  private readonly commitSalt: Buffer;

  /**
   * Maximum number of commitments allowed.
   * Prevents memory exhaustion even during PRESYNC.
   */
  private readonly maxCommitments: number;

  // REDOWNLOAD phase state
  /** Buffer of headers being redownloaded. */
  private redownloadedHeaders: CompressedHeader[];

  /** Height of last header in redownload buffer. */
  private redownloadBufferLastHeight: number;

  /** Hash of last header in redownload buffer. */
  private redownloadBufferLastHash: Buffer;

  /** Hash of prev block for first header in buffer. */
  private redownloadBufferFirstPrevHash: Buffer;

  /** Cumulative work during REDOWNLOAD. */
  private redownloadChainWork: bigint;

  /** Whether we've reached our target work and can release all remaining headers. */
  private processAllRemainingHeaders: boolean;

  /**
   * Create a new header sync state machine.
   *
   * @param params - Network consensus parameters
   * @param syncParams - Anti-DoS sync parameters
   * @param chainStartHash - Hash of the block to sync from
   * @param chainStartHeight - Height of the starting block
   * @param chainStartBits - Difficulty bits of the starting block
   * @param chainStartWork - Cumulative work at the starting block
   * @param minimumRequiredWork - Minimum work to accept the chain (0 = use nMinimumChainWork)
   */
  constructor(
    params: ConsensusParams,
    syncParams: HeadersSyncParams,
    chainStartHash: Buffer,
    chainStartHeight: number,
    chainStartBits: number,
    chainStartWork: bigint,
    minimumRequiredWork?: bigint
  ) {
    this.state = HeadersSyncStateEnum.PRESYNC;
    this.params = params;
    this.syncParams = syncParams;
    this.chainStartHash = chainStartHash;
    this.chainStartHeight = chainStartHeight;
    this.chainStartBits = chainStartBits;
    this.chainStartWork = chainStartWork;
    this.minimumRequiredWork = minimumRequiredWork ?? params.nMinimumChainWork;

    // Initialize PRESYNC state
    this.currentChainWork = chainStartWork;
    this.currentHeight = chainStartHeight;
    this.lastHeaderReceived = null;
    this.lastHeaderHash = chainStartHash;
    this.headerCommitments = [];

    // Random commitment offset to prevent attacker from knowing exactly where commitments are
    this.commitOffset = Math.floor(Math.random() * syncParams.commitmentPeriod);

    // Random salt for commitment hashing
    this.commitSalt = Buffer.alloc(32);
    for (let i = 0; i < 32; i++) {
      this.commitSalt[i] = Math.floor(Math.random() * 256);
    }

    // Calculate max commitments based on max possible chain length
    // Assuming 6 blocks per second (MTP rule limit) from chain start to now
    const maxSecondsSinceStart = Math.floor(Date.now() / 1000) + 2 * 60 * 60; // + 2 hours future
    const maxBlocks = 6 * maxSecondsSinceStart;
    this.maxCommitments = Math.ceil(maxBlocks / syncParams.commitmentPeriod);

    // Initialize REDOWNLOAD state (will be properly set on transition)
    this.redownloadedHeaders = [];
    this.redownloadBufferLastHeight = 0;
    this.redownloadBufferLastHash = Buffer.alloc(32);
    this.redownloadBufferFirstPrevHash = Buffer.alloc(32);
    this.redownloadChainWork = 0n;
    this.processAllRemainingHeaders = false;
  }

  /**
   * Get the current state of the sync process.
   */
  getState(): HeadersSyncStateEnum {
    return this.state;
  }

  /**
   * Get the height reached during PRESYNC.
   */
  getPresyncHeight(): number {
    return this.currentHeight;
  }

  /**
   * Get the cumulative work seen during PRESYNC.
   */
  getPresyncWork(): bigint {
    return this.currentChainWork;
  }

  /**
   * Get the last header timestamp received during PRESYNC.
   */
  getPresyncTime(): number | null {
    return this.lastHeaderReceived?.timestamp ?? null;
  }

  /**
   * Process a batch of headers received from a peer.
   *
   * @param headers - Headers received from the peer
   * @param fullHeadersMessage - Whether this was a max-size message (2000 headers)
   * @returns Processing result with validated headers and status
   */
  processNextHeaders(
    headers: BlockHeader[],
    fullHeadersMessage: boolean
  ): ProcessingResult {
    const result: ProcessingResult = {
      powValidatedHeaders: [],
      success: false,
      requestMore: false,
    };

    if (headers.length === 0) {
      return result;
    }

    if (this.state === HeadersSyncStateEnum.FINAL) {
      return result;
    }

    if (this.state === HeadersSyncStateEnum.PRESYNC) {
      result.success = this.validateAndStoreHeadersCommitments(headers);

      if (result.success) {
        if (fullHeadersMessage || this.state === HeadersSyncStateEnum.REDOWNLOAD) {
          // Full message means peer may have more, or we just transitioned to REDOWNLOAD
          result.requestMore = true;
        }
        // If not full and still in PRESYNC, the chain ended without enough work
      }
    } else if (this.state === HeadersSyncStateEnum.REDOWNLOAD) {
      result.success = true;

      for (const header of headers) {
        if (!this.validateAndStoreRedownloadedHeader(header)) {
          result.success = false;
          break;
        }
      }

      if (result.success) {
        // Release headers that have sufficient commitments verified
        result.powValidatedHeaders = this.popHeadersReadyForAcceptance();

        if (this.redownloadedHeaders.length === 0 && this.processAllRemainingHeaders) {
          // All done
        } else if (fullHeadersMessage) {
          result.requestMore = true;
        }
        // If not full and not done, the peer stopped sending
      }
    }

    // Finalize if we're not continuing
    if (!(result.success && result.requestMore)) {
      this.finalize();
    }

    return result;
  }

  /**
   * Build a block locator for the next getheaders request.
   *
   * @returns Array of block hashes for the locator
   */
  getNextHeadersRequestLocator(): Buffer[] {
    if (this.state === HeadersSyncStateEnum.FINAL) {
      return [];
    }

    const locator: Buffer[] = [];

    if (this.state === HeadersSyncStateEnum.PRESYNC) {
      // Continue from last received header
      if (this.lastHeaderHash) {
        locator.push(Buffer.from(this.lastHeaderHash));
      }
    } else if (this.state === HeadersSyncStateEnum.REDOWNLOAD) {
      // Continue from last redownloaded header
      locator.push(Buffer.from(this.redownloadBufferLastHash));
    }

    // Always include chain start
    locator.push(Buffer.from(this.chainStartHash));

    return locator;
  }

  /**
   * Finalize the sync state, freeing memory.
   */
  private finalize(): void {
    if (this.state === HeadersSyncStateEnum.FINAL) {
      return;
    }

    this.headerCommitments = [];
    this.lastHeaderReceived = null;
    this.lastHeaderHash = null;
    this.redownloadedHeaders = [];
    this.processAllRemainingHeaders = false;
    this.currentHeight = 0;

    this.state = HeadersSyncStateEnum.FINAL;
  }

  /**
   * PRESYNC: Validate headers and store commitments.
   *
   * @param headers - Headers to process
   * @returns Whether processing was successful
   */
  private validateAndStoreHeadersCommitments(headers: BlockHeader[]): boolean {
    if (headers.length === 0) {
      return true;
    }

    if (this.state !== HeadersSyncStateEnum.PRESYNC) {
      return false;
    }

    // Check continuity: first header must connect to our last
    const firstPrevBlock = headers[0].prevBlock;
    if (this.lastHeaderHash && !firstPrevBlock.equals(this.lastHeaderHash)) {
      // Headers don't connect - possible reorg or attack
      return false;
    }

    // Validate and store commitments for each header
    for (const header of headers) {
      if (!this.validateAndProcessSingleHeader(header)) {
        return false;
      }
    }

    // Check if we've reached sufficient work
    if (this.currentChainWork >= this.minimumRequiredWork) {
      this.transitionToRedownload();
    }

    return true;
  }

  /**
   * PRESYNC: Process a single header.
   *
   * @param header - Header to process
   * @returns Whether the header is valid
   */
  private validateAndProcessSingleHeader(header: BlockHeader): boolean {
    if (this.state !== HeadersSyncStateEnum.PRESYNC) {
      return false;
    }

    const nextHeight = this.currentHeight + 1;

    // Get previous bits for difficulty transition check
    const prevBits = this.lastHeaderReceived?.bits ?? this.chainStartBits;

    // Verify difficulty transition is within allowed bounds
    if (!permittedDifficultyTransition(this.params, nextHeight, prevBits, header.bits)) {
      return false;
    }

    // Store commitment at commitment points
    if (nextHeight % this.syncParams.commitmentPeriod === this.commitOffset) {
      const headerHash = getBlockHash(header);
      const commitment = this.computeCommitment(headerHash);
      this.headerCommitments.push(commitment);

      if (this.headerCommitments.length > this.maxCommitments) {
        // Chain is too long - possible attack
        return false;
      }
    }

    // Update state
    this.currentChainWork += getBlockWork(header.bits);
    this.lastHeaderReceived = header;
    this.lastHeaderHash = getBlockHash(header);
    this.currentHeight = nextHeight;

    return true;
  }

  /**
   * Transition from PRESYNC to REDOWNLOAD phase.
   */
  private transitionToRedownload(): void {
    this.redownloadedHeaders = [];
    this.redownloadBufferLastHeight = this.chainStartHeight;
    this.redownloadBufferLastHash = Buffer.from(this.chainStartHash);
    this.redownloadBufferFirstPrevHash = Buffer.from(this.chainStartHash);
    this.redownloadChainWork = this.chainStartWork;
    this.processAllRemainingHeaders = false;

    this.state = HeadersSyncStateEnum.REDOWNLOAD;
  }

  /**
   * REDOWNLOAD: Validate a header against commitments and store for release.
   *
   * @param header - Header to process
   * @returns Whether the header is valid
   */
  private validateAndStoreRedownloadedHeader(header: BlockHeader): boolean {
    if (this.state !== HeadersSyncStateEnum.REDOWNLOAD) {
      return false;
    }

    const nextHeight = this.redownloadBufferLastHeight + 1;

    // Check continuity
    if (!header.prevBlock.equals(this.redownloadBufferLastHash)) {
      return false;
    }

    // Check difficulty transition
    let prevBits: number;
    if (this.redownloadedHeaders.length > 0) {
      prevBits = this.redownloadedHeaders[this.redownloadedHeaders.length - 1].bits;
    } else {
      prevBits = this.chainStartBits;
    }

    if (!permittedDifficultyTransition(this.params, nextHeight, prevBits, header.bits)) {
      return false;
    }

    // Track work
    this.redownloadChainWork += getBlockWork(header.bits);

    if (this.redownloadChainWork >= this.minimumRequiredWork) {
      this.processAllRemainingHeaders = true;
    }

    // Verify commitment if at a commitment point and not past our target
    if (!this.processAllRemainingHeaders &&
        nextHeight % this.syncParams.commitmentPeriod === this.commitOffset) {
      if (this.headerCommitments.length === 0) {
        // Ran out of commitments - peer gave us different chain
        return false;
      }

      const headerHash = getBlockHash(header);
      const commitment = this.computeCommitment(headerHash);
      const expectedCommitment = this.headerCommitments.shift()!;

      if (commitment !== expectedCommitment) {
        // Commitment mismatch - peer is serving different chain
        return false;
      }
    }

    // Store compressed header
    const compressed: CompressedHeader = {
      version: header.version,
      merkleRoot: header.merkleRoot,
      timestamp: header.timestamp,
      bits: header.bits,
      nonce: header.nonce,
    };

    // Track first prev hash for reconstruction
    if (this.redownloadedHeaders.length === 0) {
      this.redownloadBufferFirstPrevHash = Buffer.from(header.prevBlock);
    }

    this.redownloadedHeaders.push(compressed);
    this.redownloadBufferLastHeight = nextHeight;
    this.redownloadBufferLastHash = getBlockHash(header);

    return true;
  }

  /**
   * Release headers that have been sufficiently verified.
   *
   * @returns Headers ready for permanent storage
   */
  private popHeadersReadyForAcceptance(): BlockHeader[] {
    const result: BlockHeader[] = [];

    if (this.state !== HeadersSyncStateEnum.REDOWNLOAD) {
      return result;
    }

    // Release headers once we have enough verified, or if we're past our target
    while (
      this.redownloadedHeaders.length > this.syncParams.redownloadBufferSize ||
      (this.redownloadedHeaders.length > 0 && this.processAllRemainingHeaders)
    ) {
      const compressed = this.redownloadedHeaders.shift()!;

      // Reconstruct full header
      const fullHeader: BlockHeader = {
        version: compressed.version,
        prevBlock: this.redownloadBufferFirstPrevHash,
        merkleRoot: compressed.merkleRoot,
        timestamp: compressed.timestamp,
        bits: compressed.bits,
        nonce: compressed.nonce,
      };

      result.push(fullHeader);

      // Update first prev hash for next header
      this.redownloadBufferFirstPrevHash = getBlockHash(fullHeader);
    }

    return result;
  }

  /**
   * Compute a 1-bit commitment for a header hash.
   *
   * Uses salted hashing to prevent attacker from predicting commitment values.
   *
   * @param headerHash - Hash of the header
   * @returns Single bit commitment (true/false)
   */
  private computeCommitment(headerHash: Buffer): boolean {
    // Salted hash: SHA256d(salt || headerHash)
    const data = Buffer.concat([this.commitSalt, headerHash]);
    const hashed = hash256(data);
    // Take least significant bit
    return (hashed[0] & 1) === 1;
  }
}
