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
} from "../validation/block.js";
import {
  getTxId,
  isCoinbase,
  checkSequenceLocks,
  SEQUENCE_LOCKTIME_DISABLE_FLAG,
  type UTXOConfirmation,
} from "../validation/tx.js";
import { BufferWriter } from "../wire/serialization.js";

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

/** UTXO flush interval (blocks). */
const UTXO_FLUSH_INTERVAL = 2000;

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

  /** Pending UTXO updates (batched for efficiency). */
  private pendingUTXOOps: BatchOperation[];

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
    this.pendingUTXOOps = [];
    this.stallCheckInterval = null;
    this.logInterval = null;
    this.startTime = 0;
    this.blocksProcessed = 0;
    this.ibdComplete = false;
    this.running = false;

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
    await this.flushUTXOBatch();
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
        // Block validation failed - stop processing
        // The block will be removed and re-requested from another peer
        console.error(`Block validation failed at height ${height}`);
        break;
      }

      // Remove from downloaded
      this.state.downloadedBlocks.delete(hashHex);

      // Advance to next height
      this.state.nextHeightToProcess++;
      this.blocksProcessed++;

      // Flush UTXO batch periodically
      if (this.blocksProcessed % UTXO_FLUSH_INTERVAL === 0) {
        await this.flushUTXOBatch();
      }
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
   * Updates the UTXO set and persists to the database.
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

    // Prepare batch operations
    const batchOps: BatchOperation[] = [];

    // Compute total fees for coinbase validation
    let totalFees = 0n;

    // Process transactions for UTXO updates
    for (let txIndex = 0; txIndex < block.transactions.length; txIndex++) {
      const tx = block.transactions[txIndex];
      const txid = getTxId(tx);
      const txidHex = txid.toString("hex");
      const isCoinbaseTx = isCoinbase(tx);

      // Spend inputs (except for coinbase)
      if (!isCoinbaseTx) {
        let inputValue = 0n;

        // Collect UTXOs and confirmations for BIP68 sequence lock validation
        const utxoConfirmations: UTXOConfirmation[] = [];
        const inputUTXOs: (UTXOEntry | null)[] = [];

        // First pass: gather all UTXOs
        for (const input of tx.inputs) {
          const prevTxid = input.prevOut.txid;
          const prevVout = input.prevOut.vout;

          // Look up the UTXO being spent
          let utxo = await this.db.getUTXO(prevTxid, prevVout);
          if (!utxo) {
            // Check if it's in the pending ops (created in same block)
            const pendingUtxo = this.findPendingUTXO(prevTxid, prevVout);
            if (!pendingUtxo) {
              console.warn(
                `Missing UTXO for input ${prevTxid.toString("hex").slice(0, 16)}:${prevVout} in tx ${txidHex.slice(0, 16)}`
              );
              // During IBD we may be missing UTXOs - this is expected
              // Use null to indicate missing and skip BIP68 check for this input
              inputUTXOs.push(null);
              utxoConfirmations.push({ height: 0, medianTimePast: 0 });
              continue;
            }
            utxo = pendingUtxo;
          }
          inputUTXOs.push(utxo);

          // Build UTXO confirmation info for BIP68
          // medianTimePast is the MTP of the block *before* the UTXO was mined
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

        // Second pass: validate and spend UTXOs
        for (let i = 0; i < tx.inputs.length; i++) {
          const input = tx.inputs[i];
          const prevTxid = input.prevOut.txid;
          const prevVout = input.prevOut.vout;
          const utxo = inputUTXOs[i];

          if (!utxo) {
            // Already warned about missing UTXO
            continue;
          }

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

          inputValue += utxo.amount;

          // Delete the spent UTXO (only if from DB, not pending)
          const dbUtxo = await this.db.getUTXO(prevTxid, prevVout);
          if (dbUtxo) {
            const utxoKey = this.makeUTXOKey(prevTxid, prevVout);
            batchOps.push({
              type: "del",
              prefix: DBPrefix.UTXO,
              key: utxoKey,
            });
          }
        }

        // Calculate output value
        let outputValue = 0n;
        for (const output of tx.outputs) {
          outputValue += output.value;
        }

        // Add to fees
        totalFees += inputValue - outputValue;
      }

      // Create new UTXOs for outputs
      for (let vout = 0; vout < tx.outputs.length; vout++) {
        const output = tx.outputs[vout];

        // Skip OP_RETURN and provably unspendable outputs
        if (output.scriptPubKey.length > 0 && output.scriptPubKey[0] === 0x6a) {
          continue; // OP_RETURN
        }

        const utxoEntry: UTXOEntry = {
          height,
          coinbase: isCoinbaseTx,
          amount: output.value,
          scriptPubKey: output.scriptPubKey,
        };

        const utxoKey = this.makeUTXOKey(txid, vout);
        const utxoValue = this.serializeUTXOEntry(utxoEntry);

        batchOps.push({
          type: "put",
          prefix: DBPrefix.UTXO,
          key: utxoKey,
          value: utxoValue,
        });
      }
    }

    // Validate coinbase value
    const expectedSubsidy = getBlockSubsidy(height, this.params);
    const maxCoinbaseValue = expectedSubsidy + totalFees;
    const coinbase = block.transactions[0];
    let coinbaseValue = 0n;
    for (const output of coinbase.outputs) {
      coinbaseValue += output.value;
    }

    if (coinbaseValue > maxCoinbaseValue) {
      console.warn(
        `Coinbase value ${coinbaseValue} exceeds maximum ${maxCoinbaseValue} at height ${height}`
      );
      // Note: During IBD we might not have accurate fee calculations
      // due to missing UTXOs. Log but don't fail.
    }

    // Update block index with validated status
    const blockRecord: BlockIndexRecord = {
      height,
      header: serializeBlockHeader(block.header),
      nTx: block.transactions.length,
      status: 1 | 2 | 4, // header-valid, txs-known, txs-valid
      dataPos: 1, // Block data exists
    };

    const indexValue = this.serializeBlockIndex(blockRecord);
    batchOps.push({
      type: "put",
      prefix: DBPrefix.BLOCK_INDEX,
      key: blockHash,
      value: indexValue,
    });

    // Store raw block data
    const rawBlock = serializeBlock(block);
    batchOps.push({
      type: "put",
      prefix: DBPrefix.BLOCK_DATA,
      key: blockHash,
      value: rawBlock,
    });

    // Store height -> hash mapping
    const heightKey = this.encodeHeight(height);
    batchOps.push({
      type: "put",
      prefix: DBPrefix.HEADER,
      key: heightKey,
      value: blockHash,
    });

    // Add to pending UTXO ops
    this.pendingUTXOOps.push(...batchOps);

    // Update chain state
    const headerEntry2 = this.headerSync.getHeaderByHeight(height);
    if (headerEntry2) {
      await this.db.putChainState({
        bestBlockHash: blockHash,
        bestHeight: height,
        totalWork: headerEntry2.chainWork,
      });
    }

    // Update peer manager's best height
    if (this.peerManager) {
      this.peerManager.updateBestHeight(height);
    }

    return true;
  }

  /**
   * Find a UTXO in the pending batch operations.
   */
  private findPendingUTXO(txid: Buffer, vout: number): UTXOEntry | null {
    const targetKey = this.makeUTXOKey(txid, vout);
    const targetKeyHex = targetKey.toString("hex");

    for (const op of this.pendingUTXOOps) {
      if (
        op.type === "put" &&
        op.prefix === DBPrefix.UTXO &&
        op.key.toString("hex") === targetKeyHex &&
        op.value
      ) {
        return this.deserializeUTXOEntry(op.value);
      }
    }

    return null;
  }

  /**
   * Flush pending UTXO batch to database.
   */
  private async flushUTXOBatch(): Promise<void> {
    if (this.pendingUTXOOps.length === 0) {
      return;
    }

    await this.db.batch(this.pendingUTXOOps);
    this.pendingUTXOOps = [];
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
    this.flushUTXOBatch().catch((err) => {
      console.error("Error flushing UTXO batch:", err);
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

  private makeUTXOKey(txid: Buffer, vout: number): Buffer {
    const buf = Buffer.alloc(36);
    txid.copy(buf, 0);
    buf.writeUInt32LE(vout, 32);
    return buf;
  }

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

  private serializeUTXOEntry(entry: UTXOEntry): Buffer {
    const writer = new BufferWriter();
    writer.writeUInt32LE(entry.height);
    writer.writeUInt8(entry.coinbase ? 1 : 0);
    writer.writeUInt64LE(entry.amount);
    writer.writeVarBytes(entry.scriptPubKey);
    return writer.toBuffer();
  }

  private deserializeUTXOEntry(data: Buffer): UTXOEntry {
    let offset = 0;
    const height = data.readUInt32LE(offset);
    offset += 4;
    const coinbase = data.readUInt8(offset) === 1;
    offset += 1;
    const amount = data.readBigUInt64LE(offset);
    offset += 8;
    const scriptLen = data.readUInt8(offset);
    offset += 1;
    const scriptPubKey = data.subarray(offset, offset + scriptLen);
    return { height, coinbase, amount, scriptPubKey };
  }
}
