/**
 * Block download and validation during Initial Block Download (IBD).
 *
 * Implements parallel block fetching from multiple peers using a sliding window,
 * in-order block processing for UTXO validation, and stall detection with
 * adaptive timeouts.
 */

import type { ChainDB, BlockIndexRecord, UTXOEntry, BatchOperation } from "../storage/database.js";
import { DBPrefix } from "../storage/database.js";
import type { ConsensusParams } from "../consensus/params.js";
import { getBlockSubsidy } from "../consensus/params.js";
import type { Peer } from "../p2p/peer.js";
import type { PeerManager } from "../p2p/manager.js";
import type { NetworkMessage, InvVector } from "../p2p/messages.js";
import { InvType } from "../p2p/messages.js";
import { BanScores } from "../p2p/manager.js";
import { HeaderSync, type HeaderChainEntry } from "./headers.js";
import {
  Block,
  getBlockHash,
  serializeBlock,
  serializeBlockHeader,
  validateBlock,
  getTransactionSigOpCost,
  MAX_BLOCK_SIGOPS_COST,
} from "../validation/block.js";
import {
  getTxId,
  isCoinbase,
  checkSequenceLocks,
  SEQUENCE_LOCKTIME_DISABLE_FLAG,
  type UTXOConfirmation,
} from "../validation/tx.js";
import { BufferWriter } from "../wire/serialization.js";
import { UTXOManager, serializeUndoData, type SpentUTXO } from "../chain/utxo.js";

/** Maximum blocks in-flight at once (across all peers). */
const DEFAULT_WINDOW_SIZE = 1024;

/** Maximum blocks in-flight per peer. */
const MAX_IN_FLIGHT_PER_PEER = 16;

/** Base timeout for stall detection (milliseconds). */
const BASE_STALL_TIMEOUT = 5000;

/** Maximum timeout after repeated stalls (milliseconds). */
const MAX_STALL_TIMEOUT = 64000;

/** Interval for progress logging (milliseconds). */
const LOG_INTERVAL = 10000;

/** Maximum items per getdata message. */
const MAX_GETDATA_ITEMS = 50000;

/**
 * Tracks a pending block request.
 */
export interface PendingBlockRequest {
  height: number;
  peer: string;
  requestedAt: number;
  timeout: number; // Current timeout for this request
}

/**
 * State for block download progress.
 */
export interface BlockDownloadState {
  /** Blocks that have been requested but not yet received. */
  pendingBlocks: Map<string, PendingBlockRequest>;
  /** Blocks that have been downloaded but not yet processed. */
  downloadedBlocks: Map<string, Block>;
  /** Next height to process (connect to chain). */
  nextHeightToProcess: number;
  /** Next height to request from peers. */
  nextHeightToRequest: number;
}

/**
 * Per-peer tracking for in-flight requests.
 */
interface PeerInFlight {
  count: number;
  lastResponse: number;
  stallTimeout: number; // Adaptive timeout
}

/**
 * Block synchronization manager for IBD.
 *
 * Downloads full blocks after headers are synced, validates them,
 * updates the UTXO set, and persists to the database.
 */
export class BlockSync {
  private db: ChainDB;
  private params: ConsensusParams;
  private headerSync: HeaderSync;
  private peerManager: PeerManager | null;
  private state: BlockDownloadState;
  private windowSize: number;

  /** Per-peer in-flight tracking. */
  private peerInFlight: Map<string, PeerInFlight>;

  /** UTXO manager with proper layered cache. */
  private utxoManager: UTXOManager;

  /** Timer for stall detection. */
  private stallCheckInterval: ReturnType<typeof setInterval> | null;

  /** Timer for progress logging. */
  private logInterval: ReturnType<typeof setInterval> | null;

  /** Timestamp when sync started. */
  private startTime: number;

  /** Blocks processed since start. */
  private blocksProcessed: number;

  /** Whether IBD is complete. */
  private ibdComplete: boolean;

  /** Running flag. */
  private running: boolean;

  /** Lock to prevent concurrent block processing. */
  private processing: boolean;

  constructor(
    db: ChainDB,
    params: ConsensusParams,
    headerSync: HeaderSync,
    peerManager?: PeerManager
  ) {
    this.db = db;
    this.params = params;
    this.headerSync = headerSync;
    this.peerManager = peerManager ?? null;
    this.windowSize = DEFAULT_WINDOW_SIZE;
    this.peerInFlight = new Map();
    this.utxoManager = new UTXOManager(db);
    this.stallCheckInterval = null;
    this.logInterval = null;
    this.startTime = 0;
    this.blocksProcessed = 0;
    this.ibdComplete = false;
    this.running = false;
    this.processing = false;

    this.state = {
      pendingBlocks: new Map(),
      downloadedBlocks: new Map(),
      nextHeightToProcess: 1, // Genesis is already validated
      nextHeightToRequest: 1,
    };
  }

  /**
   * Start the block download process.
   * Should be called after headers are synced.
   */
  async start(): Promise<void> {
    if (this.running) {
      return;
    }

    this.running = true;
    this.startTime = Date.now();
    this.blocksProcessed = 0;

    // Load chain state to determine starting point
    const chainState = await this.db.getChainState();
    if (chainState) {
      this.state.nextHeightToProcess = chainState.bestHeight + 1;
      this.state.nextHeightToRequest = chainState.bestHeight + 1;
    }

    // Register message handlers
    if (this.peerManager) {
      this.registerWithPeerManager(this.peerManager);
    }

    // Start stall detection timer
    this.stallCheckInterval = setInterval(() => {
      this.handleStalled();
    }, 1000);

    // Start progress logging
    this.logInterval = setInterval(() => {
      this.logProgress();
    }, LOG_INTERVAL);

    // Begin requesting blocks
    this.requestBlocks();
  }

  /**
   * Stop the block sync process.
   */
  async stop(): Promise<void> {
    this.running = false;

    if (this.stallCheckInterval) {
      clearInterval(this.stallCheckInterval);
      this.stallCheckInterval = null;
    }

    if (this.logInterval) {
      clearInterval(this.logInterval);
      this.logInterval = null;
    }

    // Flush any pending UTXO updates
    await this.utxoManager.flush();
  }

  /**
   * Register message handlers with the peer manager.
   */
  registerWithPeerManager(peerManager: PeerManager): void {
    this.peerManager = peerManager;

    // Handle incoming block messages
    peerManager.onMessage("block", (peer, msg) => {
      if (msg.type === "block") {
        this.handleBlock(peer, msg.payload.block).catch((err) => {
          console.error(`Error handling block from ${peer.host}:${peer.port}:`, err);
        });
      }
    });

    // Handle inv messages (for post-IBD)
    peerManager.onMessage("inv", (peer, msg) => {
      if (msg.type === "inv") {
        this.handleInv(peer, msg.payload.inventory).catch((err) => {
          console.error(`Error handling inv from ${peer.host}:${peer.port}:`, err);
        });
      }
    });

    // On new peer connection, request blocks if needed
    peerManager.onMessage("__connect__", (peer) => {
      if (this.running && !this.ibdComplete) {
        this.requestBlocks();
      }
    });

    // When new headers arrive, re-enter IBD if we have blocks to download
    peerManager.onMessage("headers", (_peer, _msg) => {
      if (!this.running) return;
      const bestHeader = this.headerSync.getBestHeader();
      if (bestHeader && bestHeader.height >= this.state.nextHeightToProcess) {
        if (this.ibdComplete) {
          this.ibdComplete = false;
        }
        this.requestBlocks();
      }
    });
  }

  /**
   * Process a received block message from a peer.
   */
  async handleBlock(peer: Peer, block: Block): Promise<void> {
    const blockHash = getBlockHash(block.header);
    const hashHex = blockHash.toString("hex");
    const peerKey = `${peer.host}:${peer.port}`;

    // Check if we requested this block
    const pending = this.state.pendingBlocks.get(hashHex);
    if (!pending) {
      // Unrequested block - could be from inv response post-IBD
      // Check if it's the next block we need
      const headerEntry = this.headerSync.getHeader(blockHash);
      if (!headerEntry) {
        // Unknown block
        return;
      }

      // Store it if it's useful
      if (headerEntry.height >= this.state.nextHeightToProcess) {
        this.state.downloadedBlocks.set(hashHex, block);
        // Try to process blocks in order
        await this.processOrderedBlocks();
      }
      return;
    }

    // Remove from pending
    this.state.pendingBlocks.delete(hashHex);

    // Update peer tracking
    const peerInfo = this.peerInFlight.get(peerKey);
    if (peerInfo) {
      peerInfo.count = Math.max(0, peerInfo.count - 1);
      peerInfo.lastResponse = Date.now();
      // Decay timeout on successful response
      peerInfo.stallTimeout = Math.max(
        BASE_STALL_TIMEOUT,
        Math.floor(peerInfo.stallTimeout * 0.9)
      );
    }

    // Store in downloaded blocks
    this.state.downloadedBlocks.set(hashHex, block);

    // Try to process blocks in order
    await this.processOrderedBlocks();

    // Request more blocks if needed
    this.requestBlocks();
  }

  /**
   * Handle inv messages (announcements of new blocks).
   * Used post-IBD to learn about new blocks.
   */
  private async handleInv(peer: Peer, inventory: InvVector[]): Promise<void> {
    if (!this.ibdComplete) {
      // During IBD, ignore inv messages
      return;
    }

    const blocksToRequest: Buffer[] = [];

    for (const inv of inventory) {
      if (inv.type === InvType.MSG_BLOCK || inv.type === InvType.MSG_WITNESS_BLOCK) {
        const hashHex = inv.hash.toString("hex");

        // Check if we already have this block
        const existing = await this.db.getBlockIndex(inv.hash);
        if (existing && (existing.status & 4) !== 0) {
          // Already have and validated
          continue;
        }

        // Check if we have the header
        const headerEntry = this.headerSync.getHeader(inv.hash);
        if (!headerEntry) {
          // Unknown header - let header sync handle it
          continue;
        }

        // Check if already pending or downloaded
        if (
          !this.state.pendingBlocks.has(hashHex) &&
          !this.state.downloadedBlocks.has(hashHex)
        ) {
          blocksToRequest.push(inv.hash);
        }
      }
    }

    if (blocksToRequest.length > 0) {
      this.sendGetData(peer, blocksToRequest);
    }
  }

  /**
   * Request the next batch of blocks from available peers.
   */
  requestBlocks(): void {
    if (!this.running || !this.peerManager) {
      return;
    }

    const bestHeader = this.headerSync.getBestHeader();
    if (!bestHeader) {
      return;
    }

    // Check if we've caught up
    if (this.state.nextHeightToRequest > bestHeader.height) {
      // All headers have been requested
      if (
        this.state.pendingBlocks.size === 0 &&
        this.state.downloadedBlocks.size === 0 &&
        this.state.nextHeightToProcess > bestHeader.height
      ) {
        this.completeIBD();
      }
      return;
    }

    // Get connected peers
    const peers = this.peerManager.getConnectedPeers();
    if (peers.length === 0) {
      return;
    }

    // Calculate how many more blocks we can request
    const currentInFlight = this.state.pendingBlocks.size;
    const available = this.windowSize - currentInFlight;
    if (available <= 0) {
      return;
    }

    // Build a list of blocks to request, distributed across peers
    const peerQueues: Map<string, Buffer[]> = new Map();

    // Initialize peer queues
    for (const peer of peers) {
      const peerKey = `${peer.host}:${peer.port}`;
      let peerInfo = this.peerInFlight.get(peerKey);
      if (!peerInfo) {
        peerInfo = {
          count: 0,
          lastResponse: Date.now(),
          stallTimeout: BASE_STALL_TIMEOUT,
        };
        this.peerInFlight.set(peerKey, peerInfo);
      }
      peerQueues.set(peerKey, []);
    }

    // Assign blocks to peers round-robin
    let peerIndex = 0;
    const peerList = Array.from(peers);

    while (
      this.state.nextHeightToRequest <= bestHeader.height &&
      this.state.pendingBlocks.size < this.windowSize
    ) {
      const height = this.state.nextHeightToRequest;
      const headerEntry = this.headerSync.getHeaderByHeight(height);

      if (!headerEntry) {
        // Missing header, skip
        this.state.nextHeightToRequest++;
        continue;
      }

      const hashHex = headerEntry.hash.toString("hex");

      // Skip if already pending or downloaded
      if (
        this.state.pendingBlocks.has(hashHex) ||
        this.state.downloadedBlocks.has(hashHex)
      ) {
        this.state.nextHeightToRequest++;
        continue;
      }

      // Find a peer with capacity
      let assigned = false;
      for (let attempts = 0; attempts < peerList.length; attempts++) {
        const peer = peerList[peerIndex % peerList.length];
        const peerKey = `${peer.host}:${peer.port}`;
        const peerInfo = this.peerInFlight.get(peerKey)!;

        if (peerInfo.count < MAX_IN_FLIGHT_PER_PEER) {
          // Assign to this peer
          const queue = peerQueues.get(peerKey)!;
          queue.push(headerEntry.hash);

          // Track pending
          this.state.pendingBlocks.set(hashHex, {
            height,
            peer: peerKey,
            requestedAt: Date.now(),
            timeout: peerInfo.stallTimeout,
          });

          peerInfo.count++;
          assigned = true;
          peerIndex++;
          break;
        }

        peerIndex++;
      }

      if (!assigned) {
        // All peers at capacity
        break;
      }

      this.state.nextHeightToRequest++;
    }

    // Send getdata messages to peers
    for (const [peerKey, hashes] of peerQueues) {
      if (hashes.length === 0) {
        continue;
      }

      const peer = peers.find(
        (p) => `${p.host}:${p.port}` === peerKey
      );
      if (peer) {
        this.sendGetData(peer, hashes);
      }
    }
  }

  /**
   * Send a getdata message requesting blocks.
   */
  private sendGetData(peer: Peer, hashes: Buffer[]): void {
    // Batch into multiple messages if needed
    for (let i = 0; i < hashes.length; i += MAX_GETDATA_ITEMS) {
      const batch = hashes.slice(i, i + MAX_GETDATA_ITEMS);
      const inventory: InvVector[] = batch.map((hash) => ({
        type: InvType.MSG_WITNESS_BLOCK,
        hash,
      }));

      const msg: NetworkMessage = {
        type: "getdata",
        payload: { inventory },
      };

      peer.send(msg);
    }
  }

  /**
   * Process downloaded blocks in height order.
   */
  private async processOrderedBlocks(): Promise<void> {
    // Prevent concurrent block processing - multiple handleBlock calls can
    // interleave at await points, causing UTXO cache corruption.
    if (this.processing) {
      return;
    }
    this.processing = true;

    try {
      await this.processOrderedBlocksInner();
    } finally {
      this.processing = false;
    }

    // Blocks may have arrived while we held the processing lock.  Check if
    // the next block we need is already downloaded and, if so, process it
    // immediately rather than waiting for the next handleBlock call.
    const bestHeader = this.headerSync.getBestHeader();
    if (bestHeader && this.state.nextHeightToProcess <= bestHeader.height) {
      const nextEntry = this.headerSync.getHeaderByHeight(this.state.nextHeightToProcess);
      if (nextEntry && this.state.downloadedBlocks.has(nextEntry.hash.toString("hex"))) {
        // Re-enter (the processing flag is now false so this will proceed)
        await this.processOrderedBlocks();
      }
    }
  }

  private async processOrderedBlocksInner(): Promise<void> {
    const bestHeader = this.headerSync.getBestHeader();
    if (!bestHeader) {
      return;
    }

    while (this.state.nextHeightToProcess <= bestHeader.height) {
      const height = this.state.nextHeightToProcess;
      const headerEntry = this.headerSync.getHeaderByHeight(height);

      if (!headerEntry) {
        // Missing header - shouldn't happen
        break;
      }

      const hashHex = headerEntry.hash.toString("hex");
      const block = this.state.downloadedBlocks.get(hashHex);

      if (!block) {
        // Block not yet downloaded
        break;
      }

      // Validate and connect the block
      const success = await this.connectBlock(block, height);

      if (!success) {
        // Block validation failed - remove from downloaded to avoid infinite
        // retry loop.  The failed block may have partially modified the UTXO
        // cache (spending inputs / adding outputs for earlier txs in the
        // block), so we must clear the in-memory cache and let it be
        // re-populated from the database on the next attempt.
        console.error(`Block validation failed at height ${height}, discarding and re-requesting`);
        this.state.downloadedBlocks.delete(hashHex);

        // Reset the UTXO cache to avoid corrupt state from partial processing
        this.utxoManager.clearCache();

        // Reset nextHeightToRequest so the block will be re-requested
        // from a (potentially different) peer
        if (height < this.state.nextHeightToRequest) {
          this.state.nextHeightToRequest = height;
        }

        break;
      }

      // Remove from downloaded
      this.state.downloadedBlocks.delete(hashHex);

      // Advance to next height
      this.state.nextHeightToProcess++;
      this.blocksProcessed++;
    }

    // Check if IBD is complete
    if (
      this.state.nextHeightToProcess > bestHeader.height &&
      this.state.pendingBlocks.size === 0
    ) {
      this.completeIBD();
    }
  }

  /**
   * Validate and connect a block.
   * Uses UTXOManager with proper layered cache for UTXO tracking.
   */
  async connectBlock(block: Block, height: number): Promise<boolean> {
    const blockHash = getBlockHash(block.header);
    const hashHex = blockHash.toString("hex");

    // Validate the block structure
    const validation = validateBlock(block, height, this.params);
    if (!validation.valid) {
      console.warn(
        `Block ${hashHex.slice(0, 16)}... at height ${height} failed validation: ${validation.error}`
      );
      return false;
    }

    // Verify the block connects to the header chain
    const headerEntry = this.headerSync.getHeaderByHeight(height);
    if (!headerEntry || !headerEntry.hash.equals(blockHash)) {
      console.warn(
        `Block ${hashHex.slice(0, 16)}... does not match expected header at height ${height}`
      );
      return false;
    }

    // BIP68 (CSV) activation check
    const enforceBIP68 = height >= this.params.csvHeight;

    // Get the previous block's MTP for BIP68 time-based locks
    let blockPrevMTP = 0;
    if (enforceBIP68) {
      const prevHeaderEntry = this.headerSync.getHeaderByHeight(height - 1);
      if (prevHeaderEntry) {
        blockPrevMTP = this.headerSync.getMedianTimePast(prevHeaderEntry);
      }
    }

    // Determine which consensus rules are active
    const verifyP2SH = height >= this.params.bip34Height;
    const verifyWitness = height >= this.params.segwitHeight;

    let totalSigOpsCost = 0;

    // Collect spent outputs for undo data
    const spentOutputs: SpentUTXO[] = [];
    let totalInputValue = 0n;
    let totalOutputValue = 0n;

    // Process transactions for UTXO updates using the UTXOManager
    for (let txIndex = 0; txIndex < block.transactions.length; txIndex++) {
      const tx = block.transactions[txIndex];
      const txid = getTxId(tx);
      const txidHex = txid.toString("hex");
      const isCoinbaseTx = isCoinbase(tx);

      const prevOutputs: Buffer[] = [];

      // Spend inputs (except for coinbase)
      if (!isCoinbaseTx) {
        // Collect UTXOs and confirmations for BIP68 sequence lock validation
        const utxoConfirmations: UTXOConfirmation[] = [];

        // First pass: pre-load all UTXOs into cache and gather confirmation info
        for (const input of tx.inputs) {
          const loaded = await this.utxoManager.preloadUTXO(input.prevOut);
          if (!loaded) {
            console.error(
              `Missing UTXO: ${input.prevOut.txid.toString("hex").slice(0, 16)}:${input.prevOut.vout} in tx ${txidHex.slice(0, 16)} at height ${height}`
            );
            return false;
          }

          const utxo = this.utxoManager.getUTXO(input.prevOut);
          if (utxo) {
            prevOutputs.push(utxo.scriptPubKey);

            // Check coinbase maturity
            if (utxo.coinbase) {
              const maturity = height - utxo.height;
              if (maturity < this.params.coinbaseMaturity) {
                console.warn(
                  `Immature coinbase spend in tx ${txidHex.slice(0, 16)}: maturity ${maturity} < ${this.params.coinbaseMaturity}`
                );
                return false;
              }
            }

            // Build UTXO confirmation info for BIP68
            if (enforceBIP68) {
              let coinMTP = 0;
              if (utxo.height > 0) {
                const coinPrevHeader = this.headerSync.getHeaderByHeight(utxo.height - 1);
                if (coinPrevHeader) {
                  coinMTP = this.headerSync.getMedianTimePast(coinPrevHeader);
                }
              }
              utxoConfirmations.push({ height: utxo.height, medianTimePast: coinMTP });
            } else {
              utxoConfirmations.push({ height: utxo.height, medianTimePast: 0 });
            }
          }
        }

        // BIP68 sequence lock validation (only for version >= 2 transactions)
        if (enforceBIP68 && tx.version >= 2) {
          const seqLockValid = checkSequenceLocks(
            tx,
            enforceBIP68,
            height,
            blockPrevMTP,
            utxoConfirmations
          );
          if (!seqLockValid) {
            console.warn(
              `Sequence locks not satisfied for tx ${txidHex.slice(0, 16)} at height ${height}`
            );
            return false;
          }
        }

        // Second pass: spend UTXOs via the UTXOManager
        for (const input of tx.inputs) {
          const spentEntry = this.utxoManager.spendOutput(input.prevOut);
          totalInputValue += spentEntry.amount;

          spentOutputs.push({
            txid: input.prevOut.txid,
            vout: input.prevOut.vout,
            entry: spentEntry,
          });
        }
      }

      // Count sigops for this transaction
      const txSigOpsCost = getTransactionSigOpCost(
        tx,
        prevOutputs,
        verifyP2SH,
        verifyWitness
      );
      totalSigOpsCost += txSigOpsCost;

      // Add outputs as new UTXOs via UTXOManager
      this.utxoManager.addTransaction(txid, tx, height, isCoinbaseTx);

      // Sum output values
      for (const output of tx.outputs) {
        totalOutputValue += output.value;
        if (isCoinbaseTx) {
          // Coinbase outputs are tracked separately
        }
      }
    }

    // Verify sigops cost
    if (totalSigOpsCost > MAX_BLOCK_SIGOPS_COST) {
      console.warn(
        `Block sigops cost ${totalSigOpsCost} exceeds maximum ${MAX_BLOCK_SIGOPS_COST}`
      );
      return false;
    }

    // Calculate coinbase output value
    const coinbaseTx = block.transactions[0];
    let coinbaseOutputValue = 0n;
    for (const output of coinbaseTx.outputs) {
      coinbaseOutputValue += output.value;
    }

    // Verify coinbase output <= subsidy + fees
    const subsidy = getBlockSubsidy(height, this.params);
    const fees = totalInputValue - (totalOutputValue - coinbaseOutputValue);
    const maxCoinbaseValue = subsidy + fees;

    if (coinbaseOutputValue > maxCoinbaseValue) {
      console.warn(
        `Coinbase value ${coinbaseOutputValue} exceeds maximum ${maxCoinbaseValue} at height ${height}`
      );
      return false;
    }

    // Store undo data
    const undoData = serializeUndoData(spentOutputs);
    await this.db.putUndoData(blockHash, undoData);

    // Store block data first (independent of UTXO state)
    const rawBlock = serializeBlock(block);
    await this.db.putBlock(blockHash, rawBlock);

    // Build extra operations to commit atomically with the UTXO flush:
    // block index, height->hash mapping, and chain state.  This prevents
    // a crash from leaving the UTXO set ahead of the recorded chain tip
    // (which would cause "Missing UTXO" errors on the next restart).
    const blockRecord: BlockIndexRecord = {
      height,
      header: serializeBlockHeader(block.header),
      nTx: block.transactions.length,
      status: 1 | 2 | 4, // header-valid, txs-known, txs-valid
      dataPos: 1, // Block data exists
    };
    const indexValue = this.serializeBlockIndex(blockRecord);
    const extraOps: BatchOperation[] = [
      {
        type: "put",
        prefix: DBPrefix.BLOCK_INDEX,
        key: blockHash,
        value: indexValue,
      },
      {
        type: "put",
        prefix: DBPrefix.HEADER,
        key: this.encodeHeight(height),
        value: blockHash,
      },
    ];

    // Include chain state in the same atomic batch
    const headerEntry2 = this.headerSync.getHeaderByHeight(height);
    if (headerEntry2) {
      const chainStateValue = this.serializeChainState(
        blockHash,
        height,
        headerEntry2.chainWork
      );
      extraOps.push({
        type: "put",
        prefix: DBPrefix.CHAIN_STATE,
        key: Buffer.alloc(0),
        value: chainStateValue,
      });
    }

    // Sync UTXO cache + block index + chain state atomically
    this.utxoManager.setBestBlock(blockHash);
    await this.utxoManager.flushDirty(extraOps);

    // Update peer manager's best height
    if (this.peerManager) {
      this.peerManager.updateBestHeight(height);
    }

    return true;
  }

  /**
   * Handle stalled downloads (re-request after timeout).
   */
  handleStalled(): void {
    if (!this.running || !this.peerManager) {
      return;
    }

    const now = Date.now();
    const stalledBlocks: string[] = [];
    const peerStalls: Map<string, number> = new Map();

    // Check for stalled requests
    for (const [hashHex, pending] of this.state.pendingBlocks) {
      const elapsed = now - pending.requestedAt;

      if (elapsed > pending.timeout) {
        stalledBlocks.push(hashHex);

        // Track stalls per peer
        const count = peerStalls.get(pending.peer) ?? 0;
        peerStalls.set(pending.peer, count + 1);
      }
    }

    // Handle stalled peers
    for (const [peerKey, stallCount] of peerStalls) {
      const peerInfo = this.peerInFlight.get(peerKey);
      if (peerInfo) {
        // Double timeout for stalling peer (adaptive)
        peerInfo.stallTimeout = Math.min(
          MAX_STALL_TIMEOUT,
          peerInfo.stallTimeout * 2
        );

        // If many stalls, consider disconnecting
        if (stallCount >= 5 && this.peerManager) {
          const peers = this.peerManager.getConnectedPeers();
          const peer = peers.find((p) => `${p.host}:${p.port}` === peerKey);
          if (peer) {
            this.peerManager.increaseBanScore(
              peer,
              BanScores.SLOW_RESPONSE * stallCount,
              `Stalled ${stallCount} blocks`
            );
          }
        }
      }
    }

    // Re-request stalled blocks
    for (const hashHex of stalledBlocks) {
      const pending = this.state.pendingBlocks.get(hashHex);
      if (!pending) continue;

      // Remove from pending
      this.state.pendingBlocks.delete(hashHex);

      // Decrease peer in-flight count
      const peerInfo = this.peerInFlight.get(pending.peer);
      if (peerInfo) {
        peerInfo.count = Math.max(0, peerInfo.count - 1);
      }

      // Reset nextHeightToRequest if this was lower
      if (pending.height < this.state.nextHeightToRequest) {
        this.state.nextHeightToRequest = pending.height;
      }
    }

    // Request more blocks if any were cleared
    if (stalledBlocks.length > 0) {
      this.requestBlocks();
    }
  }

  /**
   * Mark IBD as complete.
   */
  private completeIBD(): void {
    if (this.ibdComplete) {
      return;
    }

    this.ibdComplete = true;
    this.logProgress();
    console.log("IBD complete! Switching to normal operation.");

    // Flush any remaining UTXO updates
    this.utxoManager.flush().catch((err) => {
      console.error("Error flushing UTXO cache:", err);
    });
  }

  /**
   * Check if IBD is complete.
   */
  isIBDComplete(): boolean {
    return this.ibdComplete;
  }

  /**
   * Get sync progress as a percentage.
   */
  getProgress(): number {
    const bestHeader = this.headerSync.getBestHeader();
    if (!bestHeader || bestHeader.height === 0) {
      return 0;
    }

    const processed = this.state.nextHeightToProcess - 1;
    return (processed / bestHeader.height) * 100;
  }

  /**
   * Log sync progress.
   */
  private logProgress(): void {
    const bestHeader = this.headerSync.getBestHeader();
    if (!bestHeader) {
      return;
    }

    const processed = this.state.nextHeightToProcess - 1;
    const total = bestHeader.height;
    const percent = total > 0 ? (processed / total) * 100 : 0;

    // Calculate blocks per second
    const elapsed = (Date.now() - this.startTime) / 1000;
    const blocksPerSec = elapsed > 0 ? this.blocksProcessed / elapsed : 0;

    const peerCount = this.peerManager?.getConnectedPeers().length ?? 0;

    console.log(
      `IBD: height=${processed}/${total} (${percent.toFixed(1)}%) | ${blocksPerSec.toFixed(0)} blk/s | ${peerCount} peers`
    );
  }

  /**
   * Get current download state (for testing/debugging).
   */
  getState(): BlockDownloadState {
    return this.state;
  }

  // Helper methods

  private encodeHeight(height: number): Buffer {
    const buf = Buffer.alloc(4);
    buf.writeUInt32BE(height, 0);
    return buf;
  }

  private serializeBlockIndex(record: BlockIndexRecord): Buffer {
    const writer = new BufferWriter();
    writer.writeUInt32LE(record.height);
    writer.writeBytes(record.header);
    writer.writeUInt32LE(record.nTx);
    writer.writeUInt32LE(record.status);
    writer.writeUInt32LE(record.dataPos);
    return writer.toBuffer();
  }

  /**
   * Serialize chain state for atomic batch writes.
   * Must match the format used by ChainDB.putChainState / serializeChainState.
   */
  private serializeChainState(
    bestBlockHash: Buffer,
    bestHeight: number,
    totalWork: bigint
  ): Buffer {
    const writer = new BufferWriter();
    writer.writeHash(bestBlockHash);
    writer.writeUInt32LE(bestHeight);
    // totalWork as variable-length big-endian integer with varint length prefix
    let hex = totalWork === 0n ? "" : totalWork.toString(16);
    if (hex.length % 2 !== 0) {
      hex = "0" + hex;
    }
    const workBytes = hex.length > 0 ? Buffer.from(hex, "hex") : Buffer.alloc(0);
    writer.writeVarBytes(workBytes);
    return writer.toBuffer();
  }
}
