/**
 * Header synchronization from peers.
 *
 * Implements headers-first synchronization: download all block headers from peers
 * using getheaders messages, validate the header chain (proof-of-work, timestamps,
 * difficulty adjustments), and store the validated header chain in the database.
 */

import type { ChainDB, BlockIndexRecord } from "../storage/database.js";
import {
  ConsensusParams,
  compactToBigInt,
  bigIntToCompact,
} from "../consensus/params.js";
import {
  getNextWorkRequired,
  type BlockInfo,
  type BlockLookup,
} from "../consensus/pow.js";
import type { Peer } from "../p2p/peer.js";
import type { PeerManager } from "../p2p/manager.js";
import type { NetworkMessage } from "../p2p/messages.js";
import {
  BlockHeader,
  serializeBlockHeader,
  getBlockHash,
} from "../validation/block.js";

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
 * Header synchronization manager.
 *
 * Downloads and validates block headers from peers, maintaining the best
 * header chain (by cumulative work). Headers can be far ahead of fully
 * validated blocks.
 */
export class HeaderSync {
  private db: ChainDB;
  private params: ConsensusParams;
  private bestHeader: HeaderChainEntry | null;
  private headerChain: Map<string, HeaderChainEntry>; // hash hex -> entry
  private headersByHeight: Map<number, HeaderChainEntry>; // height -> entry on best chain
  private peerManager: PeerManager | null;
  private syncingPeers: Set<string>; // peer keys currently syncing

  constructor(db: ChainDB, params: ConsensusParams) {
    this.db = db;
    this.params = params;
    this.bestHeader = null;
    this.headerChain = new Map();
    this.headersByHeight = new Map();
    this.peerManager = null;
    this.syncingPeers = new Set();
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
  async processHeaders(headers: BlockHeader[], fromPeer: Peer): Promise<number> {
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
          `Invalid header from ${fromPeer.host}: ${validation.error}`
        );
        // Could increase peer's ban score here
        continue;
      }

      // Calculate chain work
      const headerWork = this.getHeaderWork(header.bits);
      const chainWork = parent.chainWork + headerWork;

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
   */
  requestHeaders(peer: Peer): void {
    const peerKey = `${peer.host}:${peer.port}`;

    // Get peer's best height from version message
    const peerBestHeight = peer.versionPayload?.startHeight ?? 0;

    // Check if we need more headers from this peer
    if (!this.needsMoreHeaders(peerBestHeight)) {
      return;
    }

    // Avoid requesting from same peer multiple times
    if (this.syncingPeers.has(peerKey)) {
      return;
    }

    this.syncingPeers.add(peerKey);

    const locator = this.getBlockLocator();
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
   * Handle incoming headers message.
   */
  private async handleHeadersMessage(
    peer: Peer,
    headers: BlockHeader[]
  ): Promise<void> {
    const peerKey = `${peer.host}:${peer.port}`;
    this.syncingPeers.delete(peerKey);

    if (headers.length === 0) {
      // Peer has no more headers - sync complete with this peer
      return;
    }

    const validCount = await this.processHeaders(headers, peer);

    // If we received 2000 headers (max per message), request more
    if (headers.length >= 2000) {
      this.requestHeaders(peer);
    }

    // Update peer manager's best height if needed
    if (this.peerManager && this.bestHeader) {
      this.peerManager.updateBestHeight(this.bestHeader.height);
    }
  }

  /**
   * Load header chain from database on startup.
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

    // Load all headers from genesis to tip
    // We'll rebuild the in-memory chain by loading each header
    let currentHash = headerTip;
    const headersToLoad: Buffer[] = [];

    // Walk back from tip to genesis, collecting hashes
    while (currentHash) {
      const hashHex = currentHash.toString("hex");
      if (this.headerChain.has(hashHex)) {
        // We've reached a header we already have (genesis)
        break;
      }

      headersToLoad.unshift(currentHash);

      // Get this header's record
      const record = await this.db.getBlockIndex(currentHash);
      if (!record) {
        console.warn(`Missing block index for ${hashHex.slice(0, 16)}...`);
        break;
      }

      // Extract prevBlock from header
      const prevBlock = record.header.subarray(4, 36);
      currentHash = prevBlock;
    }

    // Now load headers from genesis forward
    for (const hash of headersToLoad) {
      const record = await this.db.getBlockIndex(hash);
      if (!record) {
        continue;
      }

      // Parse header from record
      const headerBuf = record.header;
      const header: BlockHeader = {
        version: headerBuf.readInt32LE(0),
        prevBlock: Buffer.from(headerBuf.subarray(4, 36)),
        merkleRoot: Buffer.from(headerBuf.subarray(36, 68)),
        timestamp: headerBuf.readUInt32LE(68),
        bits: headerBuf.readUInt32LE(72),
        nonce: headerBuf.readUInt32LE(76),
      };

      // Find parent
      const parentHashHex = header.prevBlock.toString("hex");
      const parent = this.headerChain.get(parentHashHex);

      if (!parent) {
        console.warn(`Missing parent for header at height ${record.height}`);
        continue;
      }

      // Calculate chain work
      const headerWork = this.getHeaderWork(header.bits);
      const chainWork = parent.chainWork + headerWork;

      // Determine status from record
      let status: HeaderStatus = "valid-header";
      if ((record.status & 1) === 0) {
        status = "invalid";
      }

      const entry: HeaderChainEntry = {
        hash: Buffer.from(hash),
        header,
        height: record.height,
        chainWork,
        status,
      };

      const hashHex = hash.toString("hex");
      this.headerChain.set(hashHex, entry);

      // Track best header
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
    const headerBuf = serializeBlockHeader(entry.header);

    // Status bitmask: 1 = header-valid
    let status = 0;
    if (entry.status === "valid-header" || entry.status === "valid-fork") {
      status |= 1;
    }

    const record: BlockIndexRecord = {
      height: entry.height,
      header: headerBuf,
      nTx: 0, // Unknown until we have the block
      status,
      dataPos: 0, // No block data yet
    };

    await this.db.putBlockIndex(entry.hash, record);
  }

  /**
   * Save the current header chain tip to the database.
   * Uses a separate key to avoid confusion with the validated chain tip.
   */
  private async saveHeaderTip(entry: HeaderChainEntry): Promise<void> {
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
