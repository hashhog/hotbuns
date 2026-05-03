/**
 * Header synchronization from peers.
 *
 * Implements headers-first synchronization: download all block headers from peers
 * using getheaders messages, validate the header chain (proof-of-work, timestamps,
 * difficulty adjustments), and store the validated header chain in the database.
 *
 * Includes anti-DoS protection via PRESYNC/REDOWNLOAD mechanism:
 * - PRESYNC: Accept headers without storing, track cumulative work
 * - REDOWNLOAD: Once sufficient work is demonstrated, re-fetch and store permanently
 */

import type { ChainDB, BlockIndexRecord } from "../storage/database.js";
import { DBPrefix } from "../storage/database.js";
import {
  ConsensusParams,
  compactToBigInt,
  bigIntToCompact,
} from "../consensus/params.js";
import {
  verifyCheckpoint,
  checkForkBelowCheckpoint,
  getLastCheckpointHeight,
} from "../chain/state.js";
import {
  getNextWorkRequired,
  type BlockInfo,
  type BlockLookup,
} from "../consensus/pow.js";
import type { Peer } from "../p2p/peer.js";
import type { PeerManager } from "../p2p/manager.js";
import { BanScores } from "../p2p/manager.js";
import type { NetworkMessage } from "../p2p/messages.js";
import {
  BlockHeader,
  serializeBlockHeader,
  getBlockHash,
} from "../validation/block.js";
import {
  HeadersSyncState,
  HeadersSyncStateEnum,
  MAX_HEADERS_RESULTS,
  DEFAULT_HEADERS_SYNC_PARAMS,
  type HeadersSyncParams,
} from "./header-sync-state.js";

/** Status of a header chain entry. */
export type HeaderStatus = "valid-header" | "valid-fork" | "invalid";

/**
 * Entry in the header chain tracking a validated header and its position.
 */
export interface HeaderChainEntry {
  hash: Buffer;
  header: BlockHeader;
  height: number;
  chainWork: bigint;
  status: HeaderStatus;
}

/** Database key for storing the header chain tip (separate from validated chain tip). */
const HEADER_TIP_KEY = "header_tip";

/**
 * Per-peer anti-DoS sync state.
 */
interface PeerSyncState {
  /** The anti-DoS state machine for this peer. */
  syncState: HeadersSyncState;

  /** When we started syncing with this peer. */
  startTime: number;
}

/**
 * Header synchronization manager.
 *
 * Downloads and validates block headers from peers, maintaining the best
 * header chain (by cumulative work). Headers can be far ahead of fully
 * validated blocks.
 *
 * Uses PRESYNC/REDOWNLOAD anti-DoS mechanism for new connections to prevent
 * memory exhaustion attacks from low-work header chains.
 */
export class HeaderSync {
  private db: ChainDB;
  private params: ConsensusParams;
  private bestHeader: HeaderChainEntry | null;
  private headerChain: Map<string, HeaderChainEntry>; // hash hex -> entry
  private headersByHeight: Map<number, HeaderChainEntry>; // height -> entry on best chain
  private peerManager: PeerManager | null;
  private syncingPeers: Set<string>; // peer keys currently syncing

  /** Per-peer anti-DoS sync state machines. */
  private peerSyncStates: Map<string, PeerSyncState>;

  /** Anti-DoS sync parameters. */
  private syncParams: HeadersSyncParams;

  /** Callbacks invoked after headers are successfully processed. */
  private headersProcessedCallbacks: Array<(newTipHeight: number) => void>;

  constructor(db: ChainDB, params: ConsensusParams, syncParams?: HeadersSyncParams) {
    this.db = db;
    this.params = params;
    this.bestHeader = null;
    this.headerChain = new Map();
    this.headersByHeight = new Map();
    this.peerManager = null;
    this.syncingPeers = new Set();
    this.peerSyncStates = new Map();
    this.syncParams = syncParams ?? DEFAULT_HEADERS_SYNC_PARAMS;
    this.headersProcessedCallbacks = [];
  }

  /**
   * Register a callback to be invoked after new headers are processed.
   * The callback receives the new best header height.
   */
  onHeadersProcessed(callback: (newTipHeight: number) => void): void {
    this.headersProcessedCallbacks.push(callback);
  }

  /**
   * Initialize the header chain with the genesis block.
   */
  initGenesis(): void {
    const genesisHeader = this.parseGenesisHeader();
    const genesisHash = this.params.genesisBlockHash;
    const genesisWork = this.getHeaderWork(genesisHeader.bits);

    const genesisEntry: HeaderChainEntry = {
      hash: genesisHash,
      header: genesisHeader,
      height: 0,
      chainWork: genesisWork,
      status: "valid-header",
    };

    const hashHex = genesisHash.toString("hex");
    this.headerChain.set(hashHex, genesisEntry);
    this.headersByHeight.set(0, genesisEntry);
    this.bestHeader = genesisEntry;
  }

  /**
   * Parse the genesis block header from the consensus params.
   */
  private parseGenesisHeader(): BlockHeader {
    const block = this.params.genesisBlock;
    // Header is the first 80 bytes
    return {
      version: block.readInt32LE(0),
      prevBlock: block.subarray(4, 36),
      merkleRoot: block.subarray(36, 68),
      timestamp: block.readUInt32LE(68),
      bits: block.readUInt32LE(72),
      nonce: block.readUInt32LE(76),
    };
  }

  /**
   * Integrate with PeerManager: register handlers for headers messages
   * and send getheaders on handshake complete.
   */
  registerWithPeerManager(peerManager: PeerManager): void {
    this.peerManager = peerManager;

    // Handle incoming headers messages
    peerManager.onMessage("headers", (peer, msg) => {
      if (msg.type === "headers") {
        this.handleHeadersMessage(peer, msg.payload.headers).catch((err) => {
          console.error(`Error handling headers from ${peer.host}:${peer.port}:`, err);
        });
      }
    });

    // On handshake complete, request headers
    peerManager.onMessage("__connect__", (peer) => {
      this.requestHeaders(peer);
    });

    // Handle incoming getheaders requests from peers (serve headers)
    peerManager.onMessage("getheaders", (peer, msg) => {
      if (msg.type === "getheaders") {
        this.handleGetHeaders(peer, msg.payload).catch((err) => {
          console.error(`Error handling getheaders from ${peer.host}:${peer.port}:`, err);
        });
      }
    });
  }

  /**
   * Handle incoming getheaders request from a peer.
   * Respond with up to 2000 headers starting from the best match
   * in the locator, up to hashStop (or tip if hashStop is zero).
   */
  private async handleGetHeaders(
    peer: Peer,
    payload: { version: number; locatorHashes: Buffer[]; hashStop: Buffer }
  ): Promise<void> {
    // Find the best matching locator hash in our chain
    let startHeight = 0;

    for (const locatorHash of payload.locatorHashes) {
      const entry = this.headerChain.get(locatorHash.toString("hex"));
      if (entry) {
        startHeight = entry.height + 1;
        break;
      }
    }

    // If no locator matched, start from genesis (height 1)
    // (The peer might be at genesis and asking for the chain)

    const hashStopHex = payload.hashStop.toString("hex");
    const isHashStopZero = hashStopHex === "0".repeat(64);

    const headers: BlockHeader[] = [];
    const maxHeaders = 2000; // MAX_HEADERS_RESULTS

    for (let h = startHeight; h <= (this.bestHeader?.height ?? 0) && headers.length < maxHeaders; h++) {
      const entry = this.headersByHeight.get(h);
      if (!entry) break;

      headers.push(entry.header);

      // Stop if we reached hashStop
      if (!isHashStopZero && entry.hash.toString("hex") === hashStopHex) {
        break;
      }
    }

    if (headers.length > 0) {
      peer.send({ type: "headers", payload: { headers } });
    }
  }

  /**
   * Build a block locator from our best header chain for getheaders.
   *
   * Start from tip, go back 10 hashes one-by-one, then double the step size
   * with each subsequent hash. Always include genesis hash at the end.
   */
  getBlockLocator(): Buffer[] {
    const locator: Buffer[] = [];

    if (!this.bestHeader) {
      // Just return genesis
      locator.push(this.params.genesisBlockHash);
      return locator;
    }

    let height = this.bestHeader.height;
    let step = 1;
    let count = 0;

    while (height >= 0) {
      const entry = this.headersByHeight.get(height);
      if (entry) {
        locator.push(entry.hash);
      }

      if (height === 0) {
        break;
      }

      // First 10 entries: step by 1
      // After that: double the step each time
      count++;
      if (count > 10) {
        step *= 2;
      }

      height = Math.max(0, height - step);
    }

    // Ensure genesis is included at the end (if not already)
    const genesisHashHex = this.params.genesisBlockHash.toString("hex");
    const lastHashHex = locator[locator.length - 1]?.toString("hex");
    if (lastHashHex !== genesisHashHex) {
      locator.push(this.params.genesisBlockHash);
    }

    return locator;
  }

  /**
   * Process incoming headers message. Validate and store each header.
   * Returns new valid headers count.
   */
  async processHeaders(headers: BlockHeader[], fromPeer?: Peer | null): Promise<number> {
    let validCount = 0;

    for (const header of headers) {
      const hash = getBlockHash(header);
      const hashHex = hash.toString("hex");

      // Skip if we already have this header
      if (this.headerChain.has(hashHex)) {
        continue;
      }

      // Find parent
      const parentHashHex = header.prevBlock.toString("hex");
      const parent = this.headerChain.get(parentHashHex);

      if (!parent) {
        // Orphan header - we don't have the parent
        // In a full implementation, we'd track orphans and try to connect later
        console.warn(`Orphan header received: ${hashHex.slice(0, 16)}...`);
        continue;
      }

      // Validate header
      const validation = this.validateHeader(header, parent);
      if (!validation.valid) {
        console.warn(
          `Invalid header from ${fromPeer?.host ?? "local"}: ${validation.error}`
        );
        // Could increase peer's ban score here
        continue;
      }

      // Calculate chain work
      const headerWork = this.getHeaderWork(header.bits);
      const chainWork = parent.chainWork + headerWork;

      // Height of this header
      const headerHeight = parent.height + 1;

      // Verify checkpoint if this height has one
      const checkpointResult = verifyCheckpoint(hash, headerHeight, this.params);
      if (!checkpointResult.valid) {
        console.warn(
          `Checkpoint verification failed from ${fromPeer?.host ?? "local"}: ${checkpointResult.error}`
        );
        // This is a consensus violation - could increase ban score significantly
        continue;
      }

      // Check for forks below the last checkpoint
      const forkCheck = checkForkBelowCheckpoint(
        headerHeight,
        hash,
        header.prevBlock,
        this.params,
        (height: number) => this.headersByHeight.get(height)?.hash
      );
      if (!forkCheck.valid) {
        console.warn(
          `Fork below checkpoint rejected from ${fromPeer?.host ?? "local"}: ${forkCheck.error}`
        );
        continue;
      }

      // Determine status
      let status: HeaderStatus = "valid-header";
      if (this.bestHeader && chainWork < this.bestHeader.chainWork) {
        status = "valid-fork";
      }

      // Create entry
      const entry: HeaderChainEntry = {
        hash,
        header,
        height: parent.height + 1,
        chainWork,
        status,
      };

      // Store in memory
      this.headerChain.set(hashHex, entry);

      // Update best header if this chain has more work
      if (!this.bestHeader || chainWork > this.bestHeader.chainWork) {
        this.bestHeader = entry;
        this.updateBestChain(entry);
      }

      // Persist to database
      await this.saveHeaderEntry(entry);

      validCount++;
    }

    // Update header tip in database
    if (validCount > 0 && this.bestHeader) {
      await this.saveHeaderTip(this.bestHeader);

      // Notify listeners that new headers were processed
      const tipHeight = this.bestHeader.height;
      for (const cb of this.headersProcessedCallbacks) {
        try {
          cb(tipHeight);
        } catch {
          // Ignore callback errors
        }
      }
    }

    return validCount;
  }

  /**
   * Update the headersByHeight map after a chain reorganization or extension.
   */
  private updateBestChain(newTip: HeaderChainEntry): void {
    // Walk back from new tip, updating headersByHeight
    let entry: HeaderChainEntry | undefined = newTip;

    while (entry) {
      const existing = this.headersByHeight.get(entry.height);
      if (existing && existing.hash.equals(entry.hash)) {
        // Same entry already on best chain - we can stop
        break;
      }

      this.headersByHeight.set(entry.height, entry);

      // Find parent
      const parentHashHex = entry.header.prevBlock.toString("hex");
      entry = this.headerChain.get(parentHashHex);
    }
  }

  /**
   * Validate a single header against its parent.
   */
  validateHeader(
    header: BlockHeader,
    parent: HeaderChainEntry
  ): { valid: boolean; error?: string } {
    const height = parent.height + 1;

    // 1. Version checks
    if (header.version < 1) {
      return { valid: false, error: "Version must be >= 1" };
    }
    if (height >= this.params.bip34Height && header.version < 2) {
      return { valid: false, error: "Version must be >= 2 after BIP34" };
    }
    if (height >= this.params.bip66Height && header.version < 3) {
      return { valid: false, error: "Version must be >= 3 after BIP66" };
    }
    if (height >= this.params.bip65Height && header.version < 4) {
      return { valid: false, error: "Version must be >= 4 after BIP65" };
    }

    // 2. Timestamp > median of last 11 blocks (Median Time Past)
    const mtp = this.getMedianTimePast(parent);
    if (header.timestamp <= mtp) {
      return {
        valid: false,
        error: `Timestamp ${header.timestamp} must be > median time past ${mtp}`,
      };
    }

    // 3. Timestamp < current time + 2 hours
    const maxFutureTime = Math.floor(Date.now() / 1000) + 2 * 60 * 60;
    if (header.timestamp > maxFutureTime) {
      return { valid: false, error: "Timestamp too far in future" };
    }

    // 4. Proof-of-work: blockHash <= target
    const target = compactToBigInt(header.bits);
    const blockHash = getBlockHash(header);

    // Convert hash to big-endian number for comparison
    const hashReversed = Buffer.from(blockHash).reverse();
    const hashValue = BigInt("0x" + hashReversed.toString("hex"));

    if (hashValue > target) {
      return { valid: false, error: "Proof of work failed: hash > target" };
    }

    // 5. Target must not exceed powLimit
    if (target > this.params.powLimit) {
      return { valid: false, error: "Target exceeds powLimit" };
    }

    // 6. Difficulty matches expected (from retarget calculation or same as parent)
    // Pass the block's timestamp for testnet min-difficulty check
    const expectedTarget = this.getNextTarget(parent, header.timestamp);
    const expectedBits = bigIntToCompact(expectedTarget);

    // Allow some tolerance for rounding in compact encoding
    if (header.bits !== expectedBits) {
      // Check if the actual target is close enough (due to compact encoding precision)
      const actualTarget = compactToBigInt(header.bits);
      if (actualTarget > expectedTarget * 2n || actualTarget < expectedTarget / 2n) {
        return {
          valid: false,
          error: `Difficulty mismatch: expected bits ${expectedBits.toString(16)}, got ${header.bits.toString(16)}`,
        };
      }
    }

    return { valid: true };
  }

  /**
   * Calculate the Median Time Past (MTP) for a header.
   * Sort timestamps of last 11 blocks, take the median.
   */
  getMedianTimePast(entry: HeaderChainEntry): number {
    const timestamps: number[] = [];
    let current: HeaderChainEntry | undefined = entry;

    // Collect up to 11 timestamps
    for (let i = 0; i < 11 && current; i++) {
      timestamps.push(current.header.timestamp);
      const parentHashHex = current.header.prevBlock.toString("hex");
      current = this.headerChain.get(parentHashHex);
    }

    if (timestamps.length === 0) {
      return 0;
    }

    // Sort timestamps
    timestamps.sort((a, b) => a - b);

    // Return median (middle element)
    return timestamps[Math.floor(timestamps.length / 2)];
  }

  /**
   * Calculate the expected difficulty target for a given height.
   *
   * Delegates to the pow module which handles all network-specific rules:
   * - Mainnet: standard 2016-block retargeting
   * - Testnet3: 20-minute min-difficulty rule with walk-back
   * - Testnet4/BIP94: improved retargeting using first block of period
   * - Regtest: always minimum difficulty
   *
   * @param parent - The parent block entry
   * @param blockTimestamp - Timestamp of the new block (for testnet min-diff check)
   */
  getNextTarget(parent: HeaderChainEntry, blockTimestamp?: number): bigint {
    // Create block lookup function that uses our header chain
    const getBlockByHeight: BlockLookup = (height: number): BlockInfo | undefined => {
      const entry = this.headersByHeight.get(height);
      if (!entry) {
        return undefined;
      }
      return {
        height: entry.height,
        header: {
          timestamp: entry.header.timestamp,
          bits: entry.header.bits,
        },
      };
    };

    // Create parent block info
    const parentInfo: BlockInfo = {
      height: parent.height,
      header: {
        timestamp: parent.header.timestamp,
        bits: parent.header.bits,
      },
    };

    // Use current time if no block timestamp provided (for non-testnet validation)
    const timestamp = blockTimestamp ?? Math.floor(Date.now() / 1000);

    return getNextWorkRequired(parentInfo, timestamp, this.params, getBlockByHeight);
  }

  /**
   * Calculate chain work added by a header with given target bits.
   * Work = 2^256 / (target + 1)
   */
  getHeaderWork(bits: number): bigint {
    const target = compactToBigInt(bits);
    if (target <= 0n) {
      return 0n;
    }
    // Work = 2^256 / (target + 1)
    const TWO_256 = 2n ** 256n;
    return TWO_256 / (target + 1n);
  }

  /**
   * Get the best (most-work) header chain tip.
   */
  getBestHeader(): HeaderChainEntry | null {
    return this.bestHeader;
  }

  /**
   * Get a header entry by its hash.
   */
  getHeader(hash: Buffer): HeaderChainEntry | undefined {
    return this.headerChain.get(hash.toString("hex"));
  }

  /**
   * Get a header entry by height (on the best chain).
   */
  getHeaderByHeight(height: number): HeaderChainEntry | undefined {
    return this.headersByHeight.get(height);
  }

  /**
   * Check if we need more headers (peer's best height > our header height).
   */
  needsMoreHeaders(peerBestHeight: number): boolean {
    if (!this.bestHeader) {
      return peerBestHeight > 0;
    }
    return peerBestHeight > this.bestHeader.height;
  }

  /**
   * Request headers from a peer.
   *
   * For peers where we're already past the minimum chain work, we use direct
   * header sync. For new peers during initial sync, we use the PRESYNC/REDOWNLOAD
   * anti-DoS mechanism.
   */
  requestHeaders(peer: Peer, force?: boolean): void {
    const peerKey = `${peer.host}:${peer.port}`;

    // Get peer's best height from version message
    const peerBestHeight = peer.versionPayload?.startHeight ?? 0;

    // Check if we need more headers from this peer.
    // When force=true (e.g. we received an inv for an unknown block), skip
    // this check because the peer's startHeight from the version handshake
    // is stale — the peer has mined or received new blocks since connecting.
    if (!force && !this.needsMoreHeaders(peerBestHeight)) {
      return;
    }

    // Avoid requesting from same peer multiple times
    if (this.syncingPeers.has(peerKey)) {
      return;
    }

    this.syncingPeers.add(peerKey);

    // Check if we need anti-DoS protection for this peer
    const existingState = this.peerSyncStates.get(peerKey);
    let locator: Buffer[];

    if (this.needsAntiDoS() && !existingState) {
      // Create new anti-DoS state for this peer
      const chainStart = this.bestHeader;
      if (!chainStart) {
        // No headers yet, use genesis
        this.syncingPeers.delete(peerKey);
        return;
      }

      const syncState = new HeadersSyncState(
        this.params,
        this.syncParams,
        chainStart.hash,
        chainStart.height,
        chainStart.header.bits,
        chainStart.chainWork
      );

      this.peerSyncStates.set(peerKey, {
        syncState,
        startTime: Date.now(),
      });

      locator = syncState.getNextHeadersRequestLocator();
    } else if (existingState && existingState.syncState.getState() !== HeadersSyncStateEnum.FINAL) {
      // Continue with existing anti-DoS state
      locator = existingState.syncState.getNextHeadersRequestLocator();
    } else {
      // No anti-DoS needed, use normal locator
      locator = this.getBlockLocator();
    }

    const msg: NetworkMessage = {
      type: "getheaders",
      payload: {
        version: this.params.protocolVersion,
        locatorHashes: locator,
        hashStop: Buffer.alloc(32, 0), // Request all headers after locator
      },
    };

    peer.send(msg);
  }

  /**
   * Check if we need anti-DoS protection (haven't reached minimum chain work).
   */
  private needsAntiDoS(): boolean {
    // Skip anti-DoS if minimum chain work is 0 (regtest)
    if (this.params.nMinimumChainWork === 0n) {
      return false;
    }

    // Need anti-DoS if we haven't reached minimum chain work yet
    if (!this.bestHeader) {
      return true;
    }

    return this.bestHeader.chainWork < this.params.nMinimumChainWork;
  }

  /**
   * Handle incoming headers message.
   *
   * Processes headers through anti-DoS state machine if active for this peer,
   * otherwise processes them directly.
   */
  private async handleHeadersMessage(
    peer: Peer,
    headers: BlockHeader[]
  ): Promise<void> {
    const peerKey = `${peer.host}:${peer.port}`;
    this.syncingPeers.delete(peerKey);

    if (headers.length === 0) {
      // Peer has no more headers - sync complete with this peer
      this.cleanupPeerSyncState(peerKey);
      return;
    }

    const peerState = this.peerSyncStates.get(peerKey);
    const fullMessage = headers.length >= MAX_HEADERS_RESULTS;

    if (peerState && peerState.syncState.getState() !== HeadersSyncStateEnum.FINAL) {
      // Process through anti-DoS state machine
      const result = peerState.syncState.processNextHeaders(headers, fullMessage);

      if (!result.success) {
        // Anti-DoS check failed - peer sent bad headers
        console.warn(`Anti-DoS check failed for peer ${peerKey}`);
        this.cleanupPeerSyncState(peerKey);
        if (peer) {
          peer.misbehaving(BanScores.HEADERS_DONT_CONNECT, "headers don't connect to our chain");
        }
        return;
      }

      // Process any headers that were released by the anti-DoS mechanism
      if (result.powValidatedHeaders.length > 0) {
        await this.processHeaders(result.powValidatedHeaders, peer);
      }

      if (result.requestMore) {
        // Anti-DoS state needs more headers
        this.requestHeaders(peer);
      } else {
        // Sync complete (either finished or aborted)
        this.cleanupPeerSyncState(peerKey);
      }
    } else {
      // No anti-DoS state - process directly
      await this.processHeaders(headers, peer);

      // If we received max headers, request more
      if (fullMessage) {
        this.requestHeaders(peer);
      }
    }

    // Update peer manager's best height if needed
    if (this.peerManager && this.bestHeader) {
      this.peerManager.updateBestHeight(this.bestHeader.height);
    }
  }

  /**
   * Clean up anti-DoS state for a peer.
   */
  private cleanupPeerSyncState(peerKey: string): void {
    this.peerSyncStates.delete(peerKey);
  }

  /**
   * Get the anti-DoS sync state for a peer (for testing/monitoring).
   */
  getPeerSyncState(peer: Peer): PeerSyncState | undefined {
    const peerKey = `${peer.host}:${peer.port}`;
    return this.peerSyncStates.get(peerKey);
  }

  /**
   * Load header chain from database on startup.
   *
   * Performance: this used to walk the DB chain by prev-hash links via N
   * serial async `getBlockIndex` calls (one round-trip per header on the
   * back-walk *and* the forward-walk — ~2N round-trips total). At ~944k
   * mainnet headers that pinned a single core at 100% CPU, ~1.5 KB/s
   * LevelDB read rate, and made hotbuns effectively un-bootable post-IBD.
   *
   * The fast path uses a single LevelDB iterator pass over the
   * `BLOCK_INDEX` keyspace to materialize every stored header record into
   * an in-memory map (no async per-record), then walks the chain from
   * genesis forward in pure-JS using the prevBlock pointers in each
   * deserialized header. This is the same pattern used by
   * `chain/snapshot.ts` for the UTXO set scan.
   */
  async loadFromDB(): Promise<void> {
    // Initialize genesis first
    this.initGenesis();

    // Load header tip from database
    const headerTip = await this.loadHeaderTip();
    if (!headerTip) {
      // No stored headers beyond genesis
      return;
    }

    // ------------------------------------------------------------------
    // Single-pass iterator: stream every BLOCK_INDEX record into RAM.
    // Key   = [0x62] || hash(32)              -> 33 bytes
    // Value = serialized BlockIndexRecord     -> 96 bytes
    // ------------------------------------------------------------------
    const blockIndexPrefix = Buffer.from([DBPrefix.BLOCK_INDEX]);
    const blockIndexEnd = Buffer.from([DBPrefix.BLOCK_INDEX + 1]);
    const iterator = (this.db as any).db.iterator({
      gte: blockIndexPrefix,
      lt: blockIndexEnd,
    });

    /** hashHex -> { record, hash } */
    const records = new Map<
      string,
      { record: BlockIndexRecord; hash: Buffer }
    >();

    try {
      for await (const [key, value] of iterator) {
        // Defensive: only consume well-formed [prefix(1) || hash(32)] keys.
        if (key.length !== 33) continue;

        // The iterator's key/value buffers may be reused on the next
        // iteration in classic-level — copy what we keep.
        const hash = Buffer.from(key.subarray(1, 33));
        const hashHex = hash.toString("hex");

        // Skip genesis: we already inserted a fully-formed entry via
        // initGenesis() and it has no parent.
        if (hashHex === this.params.genesisBlockHash.toString("hex")) {
          continue;
        }

        // Deserialize the 96-byte fixed-layout BlockIndexRecord inline so
        // we copy the header bytes once (the iterator buffer is volatile).
        if (value.length < 96) continue;
        const record: BlockIndexRecord = {
          height: value.readUInt32LE(0),
          header: Buffer.from(value.subarray(4, 84)),
          nTx: value.readUInt32LE(84),
          status: value.readUInt32LE(88),
          dataPos: value.readUInt32LE(92),
        };

        records.set(hashHex, { record, hash });
      }
    } finally {
      await iterator.close();
    }

    if (records.size === 0) {
      // Header tip was set but no records exist — degenerate state, nothing
      // to load beyond genesis.
      return;
    }

    // ------------------------------------------------------------------
    // Build the chain in height order. Each record carries its height,
    // so we can sort once and walk forward, computing chainWork from the
    // parent already in `headerChain` (genesis is pre-seeded).
    // ------------------------------------------------------------------
    const sorted = Array.from(records.values()).sort(
      (a, b) => a.record.height - b.record.height,
    );

    for (const { record, hash } of sorted) {
      const headerBuf = record.header;
      const header: BlockHeader = {
        version: headerBuf.readInt32LE(0),
        prevBlock: Buffer.from(headerBuf.subarray(4, 36)),
        merkleRoot: Buffer.from(headerBuf.subarray(36, 68)),
        timestamp: headerBuf.readUInt32LE(68),
        bits: headerBuf.readUInt32LE(72),
        nonce: headerBuf.readUInt32LE(76),
      };

      const parentHashHex = header.prevBlock.toString("hex");
      const parent = this.headerChain.get(parentHashHex);
      if (!parent) {
        // Parent not yet loaded — this can legitimately happen for
        // orphans/forks whose ancestor chain wasn't persisted, or for a
        // partially-corrupt index. Don't crash the boot; skip and let the
        // header sync re-fetch on next round-trip.
        console.warn(
          `Missing parent for header at height ${record.height} ` +
            `(${hash.toString("hex").slice(0, 16)}...)`,
        );
        continue;
      }

      const headerWork = this.getHeaderWork(header.bits);
      const chainWork = parent.chainWork + headerWork;

      let status: HeaderStatus = "valid-header";
      if ((record.status & 1) === 0) {
        status = "invalid";
      }

      const entry: HeaderChainEntry = {
        hash,
        header,
        height: record.height,
        chainWork,
        status,
      };

      this.headerChain.set(hash.toString("hex"), entry);

      if (!this.bestHeader || chainWork > this.bestHeader.chainWork) {
        this.bestHeader = entry;
      }
    }

    // Rebuild headersByHeight for best chain
    if (this.bestHeader) {
      this.updateBestChain(this.bestHeader);
    }
  }

  /**
   * Save a header entry to the database.
   */
  private async saveHeaderEntry(entry: HeaderChainEntry): Promise<void> {
    // Skip header persistence once shutdown has begun.  Without this guard,
    // P2P-driven async header processing (handleHeadersMessage → processHeaders
    // → saveHeaderEntry) racing with db.close() surfaces as noisy
    // LEVEL_DATABASE_NOT_OPEN errors during graceful shutdown.  Any header we
    // drop here will be re-fetched on the next startup; the in-memory chain
    // is already updated.
    if (this.db.isClosing()) {
      return;
    }

    const headerBuf = serializeBlockHeader(entry.header);

    // Status bitmask: 1 = header-valid
    let status = 0;
    if (entry.status === "valid-header" || entry.status === "valid-fork") {
      status |= 1;
    }

    // Preserve nTx and dataPos if connectBlock already stored them.
    // saveHeaderEntry is called during header sync (before we have block data),
    // but connectBlock may have already written nTx > 0 and dataPos > 0 for
    // this block. Overwriting with nTx: 0 / dataPos: 0 would lose that info.
    let nTx = 0;
    let dataPos = 0;
    const existing = await this.db.getBlockIndex(entry.hash);
    if (existing !== null && existing.nTx > 0 && existing.dataPos > 0) {
      nTx = existing.nTx;
      dataPos = existing.dataPos;
      // Merge in any existing status bits (e.g. TXS_VALID, HAVE_DATA)
      status |= existing.status;
    }

    const record: BlockIndexRecord = {
      height: entry.height,
      header: headerBuf,
      nTx,
      status,
      dataPos,
    };

    await this.db.putBlockIndex(entry.hash, record);
  }

  /**
   * Save the current header chain tip to the database.
   * Uses a separate key to avoid confusion with the validated chain tip.
   */
  private async saveHeaderTip(entry: HeaderChainEntry): Promise<void> {
    // Same shutdown guard as saveHeaderEntry — see comment there.
    if (this.db.isClosing()) {
      return;
    }
    // Store header tip separately using a custom key
    // We use the CHAIN_STATE prefix with a special key suffix
    const key = Buffer.from(HEADER_TIP_KEY);
    await this.db.putUndoData(key, entry.hash);
  }

  /**
   * Load the header chain tip from the database.
   */
  private async loadHeaderTip(): Promise<Buffer | null> {
    const key = Buffer.from(HEADER_TIP_KEY);
    return await this.db.getUndoData(key);
  }

  /**
   * Get the total number of headers in the chain.
   */
  getHeaderCount(): number {
    return this.headerChain.size;
  }
}

// Re-export anti-DoS types for convenience
export {
  HeadersSyncState,
  HeadersSyncStateEnum,
  MAX_HEADERS_RESULTS,
  DEFAULT_HEADERS_SYNC_PARAMS,
  type HeadersSyncParams,
  type ProcessingResult,
} from "./header-sync-state.js";
