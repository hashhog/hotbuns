/**
 * Block download and validation during Initial Block Download (IBD).
 *
 * Implements parallel block fetching from multiple peers using a sliding window,
 * in-order block processing for UTXO validation, and stall detection with
 * adaptive timeouts.
 */

import type { ChainDB, BlockIndexRecord, BatchOperation } from "../storage/database.js";
import { DBPrefix } from "../storage/database.js";
import type { ConsensusParams } from "../consensus/params.js";
import { getBlockSubsidy } from "../consensus/params.js";
import type { Peer } from "../p2p/peer.js";
import type { PeerManager } from "../p2p/manager.js";
import type { NetworkMessage, InvVector } from "../p2p/messages.js";
import { InvType } from "../p2p/messages.js";
import { BanScores } from "../p2p/manager.js";
import { HeaderSync } from "./headers.js";
import type { ChainStateManager } from "../chain/state.js";
import {
  Block,
  deserializeBlock,
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
  verifyAllInputsParallel,
  verifyAllInputsSequential,
  ScriptFlags,
  type UTXOConfirmation,
} from "../validation/tx.js";
import type { UTXOEntry } from "../storage/database.js";
import { BufferReader, BufferWriter } from "../wire/serialization.js";
import { UTXOManager, type SpentUTXO } from "../chain/utxo.js";
import {
  shouldSkipScripts,
  type AssumeValidContext,
} from "../consensus/assumevalid.js";

/** Maximum blocks in-flight at once (across all peers). */
const DEFAULT_WINDOW_SIZE = 512;

/** Flush UTXO cache to disk every N blocks during IBD. */
const FLUSH_INTERVAL = 2000;

/** Maximum blocks in-flight per peer. */
const MAX_IN_FLIGHT_PER_PEER = 16;

/** Base timeout for stall detection (milliseconds).
 *  Must be long enough for large blocks (~1 MB pre-SegWit, 1-4 MB post-SegWit)
 *  being downloaded from slow peers during IBD.  30s was too aggressive and
 *  caused rapid steal/re-request cycles that prevented 1 MB blocks from ever
 *  completing transfer. */
const BASE_STALL_TIMEOUT = 120000;

/** Maximum timeout after repeated stalls (milliseconds). */
const MAX_STALL_TIMEOUT = 300000;

/** Interval for progress logging (milliseconds). */
const LOG_INTERVAL = 10000;

/** Maximum items per getdata message. */
const MAX_GETDATA_ITEMS = 50000;

/** Maximum downloaded blocks buffered in memory before throttling requests.
 *  At mainnet heights (500K+), blocks average 2-4MB serialized but expand to
 *  10-20MB as JS objects (transactions, witnesses, Buffers).  32 blocks keeps
 *  ~320-640MB in the heap — manageable under a 4GB RSS cap.  Early small blocks
 *  are processed fast enough that a larger buffer isn't needed. */
const MAX_DOWNLOADED_BUFFER = 32;

/**
 * Tracks a pending block request.
 */
export interface PendingBlockRequest {
  height: number;
  peer: string;
  requestedAt: number;
  timeout: number; // Current timeout for this request
  /** Timestamp of last duplicate request sent for this block. */
  lastDupAt?: number;
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
  blocksDelivered: number; // Tracks actual block deliveries for peer quality
  cooldownUntil: number; // Don't assign blocks until this timestamp
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

  /** Last height at which UTXO cache was flushed to disk. */
  private lastFlushedHeight: number;

  /** Consecutive failures at the same height — used to detect permanent UTXO
   *  corruption that cannot be fixed by cache-clearing alone. */
  private consecutiveFailures: number;
  private lastFailedHeight: number;

  /** Chain state manager — updated after each connected block so RPC
   *  methods like getblockcount reflect the latest chain tip. */
  private chainStateManager: ChainStateManager | null;

  /**
   * Number of parallel script-verification workers.
   * 1  = sequential (verifyAllInputsSequential) — benchmark baseline.
   * >1 = parallel   (verifyAllInputsParallel)   — production default.
   *
   * Controlled via --script-threads=N CLI flag (P2-OPT-ROUND-2).
   * Default: os.cpus().length (Bun: navigator.hardwareConcurrency).
   */
  private scriptThreads: number;

  constructor(
    db: ChainDB,
    params: ConsensusParams,
    headerSync: HeaderSync,
    peerManager?: PeerManager,
    chainStateManager?: ChainStateManager,
    scriptThreads?: number,
    maxCacheBytes?: number
  ) {
    this.db = db;
    this.params = params;
    this.headerSync = headerSync;
    this.peerManager = peerManager ?? null;
    this.chainStateManager = chainStateManager ?? null;
    // Default script thread count: hardware concurrency (>= 1).
    this.scriptThreads =
      scriptThreads ??
      (typeof navigator !== "undefined" && navigator.hardwareConcurrency > 0
        ? navigator.hardwareConcurrency
        : 4);
    this.windowSize = DEFAULT_WINDOW_SIZE;
    this.peerInFlight = new Map();
    this.utxoManager = new UTXOManager(db, maxCacheBytes);
    this.stallCheckInterval = null;
    this.logInterval = null;
    this.startTime = 0;
    this.blocksProcessed = 0;
    this.ibdComplete = false;
    this.running = false;
    this.processing = false;
    this.lastFlushedHeight = 0;
    this.consecutiveFailures = 0;
    this.lastFailedHeight = -1;

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
      this.lastFlushedHeight = chainState.bestHeight;
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

    // If we are in the middle of connectBlock, the UTXO cache may contain
    // partially-processed state (some inputs spent, some outputs added for
    // the in-progress block).  Flushing that to disk would corrupt the UTXO
    // set: a spent coin gets DELETEd from LevelDB even though the block was
    // never fully connected.  On the next restart the chain-state height
    // points *before* that block, so we'd try to spend the coin again — but
    // it's already gone from the DB → permanent "Missing UTXO" stall.
    //
    // Fix: discard the dirty cache when a block is in flight.  We'll
    // re-derive those entries on the next startup from lastFlushedHeight.
    if (this.processing) {
      this.utxoManager.clearCache();
    } else {
      // Flush any pending UTXO updates WITH chain state so shutdown is
      // crash-safe (no "Missing UTXO" on restart).
      const shutdownHeight = this.state.nextHeightToProcess - 1;
      const shutdownEntry = this.headerSync.getHeaderByHeight(shutdownHeight);
      const extraOps: BatchOperation[] = [];
      if (shutdownEntry && shutdownHeight > 0) {
        const chainStateValue = this.serializeChainState(
          shutdownEntry.hash,
          shutdownHeight,
          shutdownEntry.chainWork
        );
        extraOps.push({
          type: "put",
          prefix: DBPrefix.CHAIN_STATE,
          key: Buffer.alloc(0),
          value: chainStateValue,
        });
      }
      await this.utxoManager.flush(extraOps);
    }
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

    // Handle getdata requests (serve blocks to peers)
    peerManager.onMessage("getdata", (peer, msg) => {
      if (msg.type === "getdata") {
        this.handleGetData(peer, msg.payload.inventory).catch((err) => {
          console.error(`Error handling getdata from ${peer.host}:${peer.port}:`, err);
        });
      }
    });

    // Handle notfound messages — peer doesn't have a block we requested.
    // Without this, the pending request lingers until stall timeout,
    // blocking the processing pipeline for the full timeout duration.
    peerManager.onMessage("notfound", (peer, msg) => {
      if (msg.type === "notfound" && msg.payload?.inventory) {
        const peerKey = `${peer.host}:${peer.port}`;
        for (const inv of msg.payload.inventory) {
          if (inv.type === 2 || inv.type === 0x40000002) { // MSG_BLOCK or MSG_WITNESS_BLOCK
            const hashHex = inv.hash.toString("hex");
            const pending = this.state.pendingBlocks.get(hashHex);
            if (pending && pending.peer === peerKey) {
              console.log(`NOTFOUND: block hash=${hashHex.slice(0, 16)} from=${peerKey}, clearing pending`);
              this.state.pendingBlocks.delete(hashHex);
              const peerInfo = this.peerInFlight.get(peerKey);
              if (peerInfo) {
                peerInfo.count = Math.max(0, peerInfo.count - 1);
                // Penalize peer — it claimed to have blocks but doesn't
                peerInfo.stallTimeout = Math.min(
                  300000,
                  peerInfo.stallTimeout * 2
                );
              }
              if (pending.height < this.state.nextHeightToRequest) {
                this.state.nextHeightToRequest = pending.height;
              }
            }
          }
        }
        // Re-request from different peers
        this.requestBlocks();
      }
    });

    // BIP 152: Handle compact block messages
    // Since we don't have a mempool, fall back to requesting the full block
    peerManager.onMessage("cmpctblock", (peer, msg) => {
      if (msg.type === "cmpctblock") {
        const header = msg.payload.header;
        const blockHash = getBlockHash(header);
        const hashHex = blockHash.toString("hex");
        console.log(
          `Received cmpctblock from ${peer.host}:${peer.port}, ` +
          `falling back to full block request (hash=${hashHex})`
        );
        // Request the full block via getdata since we can't reconstruct
        // from compact block without a mempool
        const inv: InvVector = {
          type: InvType.MSG_WITNESS_BLOCK,
          hash: blockHash,
        };
        peer.send({
          type: "getdata",
          payload: { inventory: [inv] },
        });
      }
    });

    // BIP 152: Handle sendcmpct — record peer's compact block preferences
    peerManager.onMessage("sendcmpct", (peer, msg) => {
      if (msg.type === "sendcmpct") {
        console.log(
          `Peer ${peer.host}:${peer.port} supports compact blocks: ` +
          `version=${msg.payload.version}, announce=${msg.payload.enabled}`
        );
      }
    });

    // BIP 152: Handle getblocktxn — peer requesting missing txs for reconstruction
    peerManager.onMessage("getblocktxn", (_peer, _msg) => {
      // We don't serve compact blocks yet, so ignore these
    });

    // BIP 152: Handle blocktxn — response to our getblocktxn request
    peerManager.onMessage("blocktxn", (_peer, _msg) => {
      // We fall back to full block download, so we shouldn't receive these
    });

    // On new peer connection, request blocks if needed
    peerManager.onMessage("__connect__", (peer) => {
      if (this.running && !this.ibdComplete) {
        this.requestBlocks();
      }
    });

    // When new headers are fully processed (callback fires AFTER headerSync
    // has updated bestHeader), re-enter IBD if we have blocks to download.
    // This replaces the old "headers" message handler which suffered from a
    // race condition: the message handler ran before headerSync finished
    // processing headers asynchronously, so bestHeader was stale.
    this.headerSync.onHeadersProcessed((newTipHeight: number) => {
      if (!this.running) return;
      if (newTipHeight >= this.state.nextHeightToProcess) {
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

      // Store it if it's useful and we have room in the buffer
      if (headerEntry.height >= this.state.nextHeightToProcess &&
          this.state.downloadedBlocks.size < MAX_DOWNLOADED_BUFFER) {
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
      peerInfo.blocksDelivered++;
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
   * Inject a block directly (e.g. from submitblock RPC) without a peer.
   * Clears any pending request for this block and stores it in the download
   * buffer for in-order processing.
   */
  async injectBlock(block: Block): Promise<string | null> {
    const blockHash = getBlockHash(block.header);
    const hashHex = blockHash.toString("hex");

    let headerEntry = this.headerSync.getHeader(blockHash);
    if (!headerEntry) {
      // Header not known yet — try to accept it directly from the block.
      // This allows submitblock to work even when header sync is stalled
      // (e.g. after IBD completes but chain work hasn't reached nMinimumChainWork,
      // causing the anti-DoS PRESYNC to block new headers from peers).
      const accepted = await this.headerSync.processHeaders([block.header]);
      if (accepted > 0) {
        headerEntry = this.headerSync.getHeader(blockHash);
      }
      if (!headerEntry) {
        return "inconclusive"; // Still unknown (orphan or invalid header)
      }
      // Re-enter IBD if we were past it, since we now have new headers
      if (this.ibdComplete && headerEntry.height >= this.state.nextHeightToProcess) {
        this.ibdComplete = false;
      }
    }

    // Already processed?
    if (headerEntry.height < this.state.nextHeightToProcess) {
      return "duplicate";
    }

    // Reject blocks that are too far ahead of the processing frontier.
    // Without this check, a fast feeder (submitblock at 20+ blk/s) fills the
    // downloadedBlocks Map with thousands of out-of-order blocks, causing
    // unbounded RSS growth (~1.7MB/block * 5000 blocks = 8.5GB).
    // Allow the next block to process and a small buffer ahead of it.
    if (headerEntry.height > this.state.nextHeightToProcess + MAX_DOWNLOADED_BUFFER &&
        this.state.downloadedBlocks.size >= MAX_DOWNLOADED_BUFFER) {
      return "inconclusive"; // Signal caller to retry later
    }

    // Clear any pending request for this block
    const pending = this.state.pendingBlocks.get(hashHex);
    if (pending) {
      this.state.pendingBlocks.delete(hashHex);
      const peerInfo = this.peerInFlight.get(pending.peer);
      if (peerInfo) {
        peerInfo.count = Math.max(0, peerInfo.count - 1);
      }
    }

    console.log(`INJECT: block height=${headerEntry.height} hash=${hashHex.slice(0, 16)} (submitblock)`);

    // Store in downloaded blocks
    this.state.downloadedBlocks.set(hashHex, block);

    // Try to process blocks in order
    await this.processOrderedBlocks();

    // Request more blocks if needed
    this.requestBlocks();

    return null; // success
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
    let needHeaders = false;

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
          // Unknown header — request headers from this peer so we learn
          // about the new chain, then the onHeadersProcessed callback will
          // trigger block downloads.
          needHeaders = true;
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

    // If we saw block inv(s) with unknown headers, ask the peer for headers.
    // Use force=true because the peer's startHeight from the version handshake
    // is stale — the peer has new blocks we don't know about yet.
    // After headers arrive and are processed, the onHeadersProcessed callback
    // will trigger requestBlocks() to download the actual block data.
    if (needHeaders) {
      this.headerSync.requestHeaders(peer, true);
    }
  }

  /**
   * Handle getdata requests from peers — serve blocks we have stored.
   */
  private async handleGetData(peer: Peer, inventory: InvVector[]): Promise<void> {
    for (const inv of inventory) {
      if (inv.type === InvType.MSG_BLOCK || inv.type === InvType.MSG_WITNESS_BLOCK) {
        const rawBlock = await this.db.getBlock(inv.hash);
        if (rawBlock) {
          const block = deserializeBlock(new BufferReader(rawBlock));
          const blockMsg: NetworkMessage = {
            type: "block",
            payload: { block },
          };
          peer.send(blockMsg);
        }
      }
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

    // Hard stop: if downloaded blocks buffer is full, do NOT request more.
    // This prevents unbounded memory growth when processing can't keep up
    // with downloads. Previously, the window calculation allowed accumulating
    // thousands of blocks in the downloadedBlocks Map (each holding a full
    // deserialized Block), eating 500MB-1.5GB of heap and triggering
    // constant GC, which slowed processing further in a vicious cycle.
    if (this.state.downloadedBlocks.size >= MAX_DOWNLOADED_BUFFER) {
      return;
    }

    // PARALLEL CRITICAL BLOCK REQUEST: if the block at nextHeightToProcess
    // is NOT in downloadedBlocks and IS pending, request it from ALL peers.
    // This ensures the most critical block arrives as fast as possible by
    // racing multiple peers against each other.
    const critEntry = this.headerSync.getHeaderByHeight(this.state.nextHeightToProcess);
    if (critEntry) {
      const critHashHex = critEntry.hash.toString("hex");
      if (!this.state.downloadedBlocks.has(critHashHex)) {
        const critPending = this.state.pendingBlocks.get(critHashHex);
        const critAge = critPending ? Date.now() - critPending.requestedAt : 0;
        // After 30s of waiting, blast the request to all peers
        if (critPending && critAge > 30000) {
          const allPeers = this.peerManager.getConnectedPeers();
          for (const p of allPeers) {
            const pk = `${p.host}:${p.port}`;
            if (pk !== critPending.peer) {
              this.sendGetData(p, [critEntry.hash]);
            }
          }
        }
      }
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

    // Calculate how many more blocks we can request.
    // Cap total outstanding (pending + downloaded) to MAX_DOWNLOADED_BUFFER
    // to bound memory usage from buffered Block objects.
    const currentInFlight = this.state.pendingBlocks.size;
    const totalOutstanding = currentInFlight + this.state.downloadedBlocks.size;
    const effectiveWindow = Math.max(
      4,
      Math.min(this.windowSize, MAX_DOWNLOADED_BUFFER * 2) - totalOutstanding
    );
    const available = effectiveWindow;
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
          lastResponse: 0, // Unknown responsiveness — don't assume responsive
          stallTimeout: BASE_STALL_TIMEOUT,
          blocksDelivered: 0,
          cooldownUntil: 0,
        };
        this.peerInFlight.set(peerKey, peerInfo);
      }
      peerQueues.set(peerKey, []);
    }

    // Sort peers by responsiveness: prefer peers that have actually delivered
    // blocks recently (low stallTimeout AND recent lastResponse).
    // This prevents the round-robin from spreading critical blocks across
    // non-responsive peers that accept getdata but never respond.
    let peerIndex = 0;
    const now = Date.now();
    const peerList = Array.from(peers).sort((a, b) => {
      const aKey = `${a.host}:${a.port}`;
      const bKey = `${b.host}:${b.port}`;
      const aInfo = this.peerInFlight.get(aKey);
      const bInfo = this.peerInFlight.get(bKey);
      const aTimeout = aInfo?.stallTimeout ?? BASE_STALL_TIMEOUT;
      const bTimeout = bInfo?.stallTimeout ?? BASE_STALL_TIMEOUT;
      // Primary: sort by recency of last response (more recent = better)
      const aRecent = aInfo?.lastResponse ?? 0;
      const bRecent = bInfo?.lastResponse ?? 0;
      // Primary: peers that have delivered blocks are strongly preferred
      const aDelivered = aInfo?.blocksDelivered ?? 0;
      const bDelivered = bInfo?.blocksDelivered ?? 0;
      const aHasDelivered = aDelivered > 0 ? 0 : 1;
      const bHasDelivered = bDelivered > 0 ? 0 : 1;
      if (aHasDelivered !== bHasDelivered) return aHasDelivered - bHasDelivered;
      // Secondary: peers that responded recently are preferred
      const aActive = (now - aRecent) < 60000 ? 0 : 1;
      const bActive = (now - bRecent) < 60000 ? 0 : 1;
      if (aActive !== bActive) return aActive - bActive;
      // Tertiary: lower stallTimeout is better
      return aTimeout - bTimeout;
    });
    let requested = 0;

    // Cap how far ahead requests can get relative to processing.  Without
    // this, the request pointer races ahead filling the buffer with blocks
    // at heights far beyond what can be processed, while the one block we
    // actually need at nextHeightToProcess might be missing.
    const maxRequestHeight = this.state.nextHeightToProcess + MAX_DOWNLOADED_BUFFER * 2;

    // For the first few blocks closest to the processing frontier,
    // assign them to the MOST responsive peer (index 0 in sorted list)
    // instead of round-robin. This ensures the blocks we need most
    // urgently go to the peer most likely to deliver them.
    const criticalWindow = 4; // First 4 blocks get priority assignment

    while (
      this.state.nextHeightToRequest <= bestHeader.height &&
      this.state.nextHeightToRequest <= maxRequestHeight &&
      requested < available
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

      // For blocks near the processing frontier, strongly prefer the best peer
      const isCritical = (height - this.state.nextHeightToProcess) < criticalWindow;
      const startIdx = isCritical ? 0 : peerIndex;

      // Find a peer with capacity
      let assigned = false;
      for (let attempts = 0; attempts < peerList.length; attempts++) {
        const idx = isCritical ? attempts : ((startIdx + attempts) % peerList.length);
        const peer = peerList[idx % peerList.length];
        const peerKey = `${peer.host}:${peer.port}`;
        const peerInfo = this.peerInFlight.get(peerKey)!;

        // Skip peers that have been persistently stalling — they likely can't
        // serve blocks at these heights (e.g. pruned nodes).
        if (peerInfo.stallTimeout >= MAX_STALL_TIMEOUT) {
          if (!isCritical) peerIndex++;
          continue;
        }
        // Skip peers in cooldown after stalling
        if (peerInfo.cooldownUntil > Date.now()) {
          if (!isCritical) peerIndex++;
          continue;
        }
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
          requested++;
          if (!isCritical) peerIndex++;
          break;
        }

        if (!isCritical) peerIndex++;
      }

      if (!assigned) {
        // All responsive peers at capacity (or all peers are stalling).
        // Fall back to using ANY peer with capacity, even if stalling.
        // This prevents permanent stalls when all peers have high timeouts.
        for (let attempts = 0; attempts < peerList.length; attempts++) {
          const peer = peerList[peerIndex % peerList.length];
          const fbKey = `${peer.host}:${peer.port}`;
          const fbInfo = this.peerInFlight.get(fbKey)!;
          if (fbInfo.count < MAX_IN_FLIGHT_PER_PEER) {
            const queue = peerQueues.get(fbKey)!;
            queue.push(headerEntry.hash);
            this.state.pendingBlocks.set(hashHex, {
              height,
              peer: fbKey,
              requestedAt: Date.now(),
              timeout: fbInfo.stallTimeout,
            });
            fbInfo.count++;
            assigned = true;
            requested++;
            peerIndex++;
            break;
          }
          peerIndex++;
        }
        if (!assigned) {
          // Truly at capacity
          break;
        }
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

    // Always try to request more blocks after processing — this handles the
    // case where a pending request was stolen from a slow peer and needs to
    // be re-assigned.
    this.requestBlocks();

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
      let block = this.state.downloadedBlocks.get(hashHex);

      if (!block) {
        // Block not yet downloaded.  If it's sitting in the pending map and
        // enough other blocks have arrived in the meantime, the assigned peer
        // is likely slow or dead.  Cancel the pending request and let the
        // next requestBlocks() cycle assign it to a different peer.  This
        // avoids waiting the full stall timeout (30s) while the buffer fills
        // with blocks at higher heights that we can't use yet.
        const pending = this.state.pendingBlocks.get(hashHex);
        // Only steal if the block has been pending for a meaningful amount of
        // time.  The old threshold (downloadedBlocks.size > 4) was too aggressive
        // and caused rapid steal/re-request cycles where the block was constantly
        // yanked from the assigned peer before it had time to deliver a 1 MB
        // block, leading to permanent stalls at the halving boundary.
        const stealAge = pending ? Date.now() - pending.requestedAt : 0;
        // Throttle duplicate requests: don't re-duplicate if we already
        // sent duplicates recently (within BASE_STALL_TIMEOUT/4 = 30s).
        const lastDupAt = pending?.lastDupAt ?? 0;
        const sinceLastDup = Date.now() - lastDupAt;
        // Send duplicates after BASE_STALL_TIMEOUT/2 (60s) from original
        // request, or BASE_STALL_TIMEOUT/4 (30s) from last duplicate send.
        // This gives the assigned peer time to serve its queue (Bitcoin Core
        // serves 1 block per ProcessGetData call, so 16 blocks takes ~16-32s)
        // but ensures we don't wait forever.
        const dupReady = lastDupAt === 0
          ? stealAge > BASE_STALL_TIMEOUT / 2
          : sinceLastDup > BASE_STALL_TIMEOUT / 4;
        if (pending && dupReady && this.state.downloadedBlocks.size > 4) {
          // The assigned peer hasn't delivered while others have.  Instead
          // of stealing (which bounces the request between peers), send a
          // DUPLICATE request to additional peers.  The first response wins.
          // Keep the original pending entry so we don't disrupt the original
          // peer's delivery if it's just slow (queued behind other blocks).
          if (this.peerManager) {
            const connPeers = this.peerManager.getConnectedPeers();
            // Send duplicate getdata to up to 3 other peers
            let duplicatesSent = 0;
            for (const p of connPeers) {
              if (duplicatesSent >= 3) break;
              const pk = `${p.host}:${p.port}`;
              if (pk === pending.peer) continue;
              const pi = this.peerInFlight.get(pk);
              // Prefer peers that have responded recently
              if (pi && pi.lastResponse > 0 && (Date.now() - pi.lastResponse) < 120000) {
                this.sendGetData(p, [headerEntry.hash]);
                duplicatesSent++;
              }
            }
            if (duplicatesSent > 0) {
              // DO NOT reset requestedAt — that prevents the stall handler
              // from ever timing out the original pending entry.  Instead,
              // mark when we last sent duplicates so we don't spam them.
              pending.lastDupAt = Date.now();
              console.log(`DUP-REQ: block ${height} sent to ${duplicatesSent} extra peers (orig=${pending.peer}, age=${stealAge}ms)`);
            }
          }
        }
        break;
      }

      // Validate and connect the block
      const success = await this.connectBlock(block, height);

      if (!success) {
        // Track consecutive failures at the same height to detect permanent
        // UTXO corruption (e.g. a coin was DELETEd from LevelDB during a
        // partial flush but the chain state height was never advanced).
        if (height === this.lastFailedHeight) {
          this.consecutiveFailures++;
        } else {
          this.consecutiveFailures = 1;
          this.lastFailedHeight = height;
        }

        console.error(`Block validation failed at height ${height} (attempt ${this.consecutiveFailures}), discarding and re-requesting`);
        this.state.downloadedBlocks.delete(hashHex);

        // Reset the UTXO cache to avoid corrupt state from partial processing
        this.utxoManager.clearCache();

        if (this.consecutiveFailures >= 3) {
          // The on-disk UTXO set is permanently corrupted at this height.
          // During IBD assume-valid mode, undo data is not stored, so we
          // cannot programmatically roll back the UTXO set.  The only
          // recovery is to wipe the database and re-sync from genesis.
          console.error(
            `\n*** FATAL: Permanent UTXO corruption detected at height ${height}. ***\n` +
            `The same block has failed validation ${this.consecutiveFailures} consecutive times.\n` +
            `This means the on-disk UTXO set has entries that were partially flushed\n` +
            `during a previous unclean shutdown.\n\n` +
            `To recover, delete the data directory and restart:\n` +
            `  rm -rf <datadir>/blocks.db && restart hotbuns\n`
          );
          // Exit with a distinctive code so monitoring scripts can detect this
          process.exit(78); // EX_CONFIG from sysexits.h
        } else {
          // Normal retry: rewind to last flushed height so we re-process
          // from a known-good DB state.
          const rewindTo = this.lastFlushedHeight + 1;
          this.state.nextHeightToProcess = rewindTo;
          this.state.nextHeightToRequest = rewindTo;
        }

        // Discard any buffered blocks that are now stale
        this.state.downloadedBlocks.clear();

        break;
      }

      // Remove from downloaded
      this.state.downloadedBlocks.delete(hashHex);
      // Help V8 GC by nulling block reference
      block = null as any;

      // Advance to next height
      this.state.nextHeightToProcess++;
      this.blocksProcessed++;

      // Flush dirty UTXO entries to disk on memory pressure.
      // The periodic FLUSH_INTERVAL flush is handled inside connectBlock()
      // which already includes chain state atomically. This flush handles
      // only memory-triggered cases between those periodic points.
      //
      // CRITICAL: chain state (bestHeight) MUST be written atomically with
      // UTXO changes. Otherwise a crash between flush and chain-state write
      // leaves the DB in an unrecoverable state: spent coins deleted but
      // bestHeight pointing before the spend, causing "Missing UTXO" on
      // restart. This was the root cause of the height 380001 corruption.
      const memoryFlush = this.utxoManager.shouldFlush();
      if (memoryFlush && this.utxoManager.getDirtyCount() > 0) {
        console.log(`UTXO memory flush at height ${height}: ${this.utxoManager.getCacheSize()} entries`);

        // Build extraOps with chain state so the flush is crash-safe.
        // Use headerEntry which is already resolved for this height.
        const extraOps: BatchOperation[] = [];
        if (headerEntry) {
          const chainStateValue = this.serializeChainState(
            headerEntry.hash,
            height,
            headerEntry.chainWork
          );
          extraOps.push({
            type: "put",
            prefix: DBPrefix.CHAIN_STATE,
            key: Buffer.alloc(0),
            value: chainStateValue,
          });
        }

        await this.utxoManager.flushDirty(extraOps);
        this.lastFlushedHeight = height;

        // Use FULL GC (true) on memory-triggered flushes to release the
        // large batch of evicted Map entries and Buffers back to the OS.
        // With the reduced 256MB cache, memory flushes happen less often
        // (~every 1-3 blocks at 380K+), so the stop-the-world cost is
        // amortized. Incremental GC was insufficient — it left dead objects
        // in the old generation, keeping RSS at 4GB+.
        if (typeof Bun !== "undefined" && Bun.gc) {
          Bun.gc(true);
        }
      }

      // Yield the event loop periodically to prevent starvation of timers,
      // I/O callbacks, and RPC handlers.  Without this, a long chain of
      // cached UTXO hits can resolve all awaits as microtasks, starving
      // the macrotask queue indefinitely.
      if (this.blocksProcessed % 64 === 0) {
        await new Promise<void>(resolve => setTimeout(resolve, 0));
      }

      // Periodic GC every 50 blocks — use incremental (false) to avoid
      // stop-the-world pauses.  At mainnet heights, each block creates ~10-20MB
      // of JS objects (txns, witnesses, Buffers) that become garbage after
      // connectBlock.  Without frequent nudges, V8/JSC defers collection and
      // RSS grows ~1.7MB/block until OOM.  Every-50 keeps RSS stable with
      // negligible throughput impact (~0.5ms per incremental GC).
      if (this.blocksProcessed % 50 === 0 && typeof Bun !== "undefined" && Bun.gc) {
        Bun.gc(false);
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
   * Uses UTXOManager with proper layered cache for UTXO tracking.
   */
  async connectBlock(block: Block, height: number): Promise<boolean> {
    const blockHash = getBlockHash(block.header);
    const hashHex = blockHash.toString("hex");

    // Under assume-valid, skip expensive structural checks (merkle root,
    // witness commitment, per-tx validation) for blocks we trust.
    const assumeValid = this.params.assumeValidHeight > 0 && height <= this.params.assumeValidHeight;

    if (!assumeValid) {
      // Validate the block structure
      const validation = validateBlock(block, height, this.params);
      if (!validation.valid) {
        console.warn(
          `Block ${hashHex.slice(0, 16)}... at height ${height} failed validation: ${validation.error}`
        );
        return false;
      }
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
    const enforceBIP68 = !assumeValid && height >= this.params.csvHeight;

    // Get the previous block's MTP for BIP68 time-based locks
    let blockPrevMTP = 0;
    if (enforceBIP68) {
      const prevHeaderEntry = this.headerSync.getHeaderByHeight(height - 1);
      if (prevHeaderEntry) {
        blockPrevMTP = this.headerSync.getMedianTimePast(prevHeaderEntry);
      }
    }

    // Pre-load ALL UTXOs needed by this block in one parallel batch.
    // This turns N sequential LevelDB reads into N parallel reads.
    {
      const allOutpoints: import("../validation/tx.js").OutPoint[] = [];
      for (const tx of block.transactions) {
        if (!isCoinbase(tx)) {
          for (const input of tx.inputs) {
            allOutpoints.push(input.prevOut);
          }
        }
      }
      if (allOutpoints.length > 0) {
        await this.utxoManager.preloadUTXOs(allOutpoints);
      }
    }

    if (assumeValid) {
      // ============================================================
      // ASSUME-VALID FAST PATH: minimal work, no validation overhead.
      // Skip: maturity checks, BIP68, sigops, coinbase value, undo data.
      // Only: spend inputs, add outputs, compute txids.
      // ============================================================
      for (const tx of block.transactions) {
        const txid = getTxId(tx);
        const isCoinbaseTx = isCoinbase(tx);

        if (!isCoinbaseTx) {
          for (const input of tx.inputs) {
            // All inputs should be in cache from block-level preload or
            // earlier txs in this block. Fallback to async load if missing.
            if (!this.utxoManager.hasUTXO(input.prevOut)) {
              const loaded = await this.utxoManager.preloadUTXO(input.prevOut);
              if (!loaded) {
                console.error(
                  `Missing UTXO at height ${height}: ${input.prevOut.txid.toString("hex").slice(0, 16)}:${input.prevOut.vout}`
                );
                return false;
              }
            }
            this.utxoManager.spendOutput(input.prevOut);
          }
        }

        this.utxoManager.addTransaction(txid, tx, height, isCoinbaseTx);
      }
    } else {
      // ============================================================
      // FULL VALIDATION PATH
      // ============================================================
      const verifyP2SH = height >= this.params.bip34Height;
      const verifyWitness = height >= this.params.segwitHeight;

      let totalSigOpsCost = 0;
      const spentOutputs: SpentUTXO[] = [];
      let totalInputValue = 0n;
      let totalOutputValue = 0n;

      // ── P2-OPT-ROUND-2: assumevalid gate for script verification ──
      // Build the context once per block and check whether scripts should
      // be skipped.  On regtest assumedValid is undefined, so every script
      // fires (good for tests).  On mainnet the 6-condition check applies.
      const bestHeader = this.headerSync.getBestHeader();
      const currentHeaderEntry = this.headerSync.getHeaderByHeight(height);
      const pindexTimestamp = currentHeaderEntry?.header.timestamp ?? 0;
      const bestHeaderTimestamp = bestHeader?.header.timestamp ?? 0;

      const avCtx: AssumeValidContext = {
        pindex: {
          hash: hashHex,
          height,
          chainWork: currentHeaderEntry?.chainWork ?? 0n,
        },
        assumedValidHash: this.params.assumedValid,
        getBlockByHash: (h) => {
          const entry = this.headerSync.getHeader(Buffer.from(h, "hex"));
          if (!entry) return null;
          return { hash: entry.hash.toString("hex"), height: entry.height, chainWork: entry.chainWork };
        },
        getBlockAtHeight: (h) => {
          const entry = this.headerSync.getHeaderByHeight(h);
          if (!entry) return null;
          return { hash: entry.hash.toString("hex"), height: entry.height, chainWork: entry.chainWork };
        },
        bestHeader: bestHeader
          ? { hash: bestHeader.hash.toString("hex"), height: bestHeader.height, chainWork: bestHeader.chainWork }
          : null,
        minimumChainWork: this.params.nMinimumChainWork,
        pindexTimestamp,
        bestHeaderTimestamp,
      };

      const skipScriptsResult = shouldSkipScripts(avCtx);
      const skipScripts = skipScriptsResult.skip;

      for (let txIndex = 0; txIndex < block.transactions.length; txIndex++) {
        const tx = block.transactions[txIndex];
        const txid = getTxId(tx);
        const txidHex = txid.toString("hex");
        const isCoinbaseTx = isCoinbase(tx);

        const prevOutputs: Buffer[] = [];

        if (!isCoinbaseTx) {
          // Check all inputs are in cache
          for (const input of tx.inputs) {
            if (!this.utxoManager.hasUTXO(input.prevOut)) {
              const loaded = await this.utxoManager.preloadUTXO(input.prevOut);
              if (!loaded) {
                console.error(
                  `Missing UTXO: ${input.prevOut.txid.toString("hex").slice(0, 16)}:${input.prevOut.vout} in tx ${txidHex.slice(0, 16)} at height ${height}`
                );
                return false;
              }
            }
          }

          const utxoConfirmations: UTXOConfirmation[] = [];
          // Collect UTXOEntries for script verification (parallel or sequential).
          const inputUTXOs: UTXOEntry[] = [];

          for (const input of tx.inputs) {
            const utxo = this.utxoManager.getUTXO(input.prevOut);
            if (utxo) {
              prevOutputs.push(utxo.scriptPubKey);
              inputUTXOs.push(utxo);

              if (utxo.coinbase) {
                const maturity = height - utxo.height;
                if (maturity < this.params.coinbaseMaturity) {
                  console.warn(
                    `Immature coinbase spend in tx ${txidHex.slice(0, 16)}: maturity ${maturity} < ${this.params.coinbaseMaturity}`
                  );
                  return false;
                }
              }

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

          // ── P2-OPT-ROUND-2: parallel script verification ──
          // Fires for every non-coinbase tx in the full-validation path unless
          // the assumevalid 6-condition gate says to skip.
          if (!skipScripts) {
            const scriptFlags =
              (verifyP2SH ? ScriptFlags.VERIFY_P2SH : ScriptFlags.VERIFY_NONE) |
              (verifyWitness ? ScriptFlags.VERIFY_WITNESS : ScriptFlags.VERIFY_NONE);

            let scriptResult;
            if (this.scriptThreads === 1) {
              // Benchmark baseline: serial path so callers can compare timings.
              scriptResult = verifyAllInputsSequential(tx, inputUTXOs, scriptFlags);
            } else {
              // Production path: parallel (Promise.all across all inputs).
              scriptResult = await verifyAllInputsParallel(tx, inputUTXOs, scriptFlags);
            }

            if (!scriptResult.valid) {
              console.warn(
                `Script verification failed in tx ${txidHex.slice(0, 16)} at height ${height}` +
                  (scriptResult.failedInput !== undefined
                    ? ` (input ${scriptResult.failedInput})`
                    : "") +
                  (scriptResult.error ? `: ${scriptResult.error}` : "")
              );
              return false;
            }
          }

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

        const txSigOpsCost = getTransactionSigOpCost(
          tx,
          prevOutputs,
          verifyP2SH,
          verifyWitness
        );
        totalSigOpsCost += txSigOpsCost;

        this.utxoManager.addTransaction(txid, tx, height, isCoinbaseTx);

        for (const output of tx.outputs) {
          totalOutputValue += output.value;
        }
      }

      if (totalSigOpsCost > MAX_BLOCK_SIGOPS_COST) {
        console.warn(
          `Block sigops cost ${totalSigOpsCost} exceeds maximum ${MAX_BLOCK_SIGOPS_COST}`
        );
        return false;
      }

      const coinbaseTx = block.transactions[0];
      let coinbaseOutputValue = 0n;
      for (const output of coinbaseTx.outputs) {
        coinbaseOutputValue += output.value;
      }

      const subsidy = getBlockSubsidy(height, this.params);
      const fees = totalInputValue - (totalOutputValue - coinbaseOutputValue);
      const maxCoinbaseValue = subsidy + fees;

      if (coinbaseOutputValue > maxCoinbaseValue) {
        console.warn(
          `Coinbase value ${coinbaseOutputValue} exceeds maximum ${maxCoinbaseValue} at height ${height}`
        );
        return false;
      }
    }

    // During IBD, skip per-block DB writes (block data, undo, index) except
    // near the tip. Only update UTXO set in memory and flush periodically.
    // This eliminates the biggest I/O bottleneck: a LevelDB batch write per block.
    this.utxoManager.setBestBlock(blockHash);
    const bestHeader = this.headerSync.getBestHeader();
    const atTip = !bestHeader || height >= bestHeader.height;
    const shouldFlush = atTip || height % FLUSH_INTERVAL === 0;

    // Store raw block data when near the tip so we can serve blocks to
    // peers via getdata.  During deep IBD this is skipped for performance.
    if (atTip) {
      const rawBlock = serializeBlock(block);
      await this.db.putBlock(blockHash, rawBlock);
    }

    if (shouldFlush) {
      // On flush, write chain state atomically with UTXO changes.
      // Also write block index + height mapping so we can resume from here.
      const extraOps: BatchOperation[] = [];

      const blockRecord: BlockIndexRecord = {
        height,
        header: serializeBlockHeader(block.header),
        nTx: block.transactions.length,
        status: 1 | 2 | 4 | (atTip ? 8 : 0), // header-valid, txs-known, txs-valid, have-data when at tip
        dataPos: atTip ? 1 : 0,
      };
      const indexValue = this.serializeBlockIndex(blockRecord);
      extraOps.push(
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
        }
      );

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

      await this.utxoManager.flushDirty(extraOps);
      this.lastFlushedHeight = height;
    }

    // Update peer manager's best height
    if (this.peerManager) {
      this.peerManager.updateBestHeight(height);
    }

    // Update the in-memory chain state so RPC (getblockcount, getbestblockhash)
    // reflects the latest connected block without waiting for a restart.
    if (this.chainStateManager) {
      const headerEntry3 = this.headerSync.getHeaderByHeight(height);
      if (headerEntry3) {
        this.chainStateManager.updateTip(blockHash, height, headerEntry3.chainWork);
      }
    }

    // Relay new tip blocks to peers so they learn about the chain extension.
    if (atTip && this.peerManager) {
      const invMsg: NetworkMessage = {
        type: "inv",
        payload: {
          inventory: [{ type: InvType.MSG_BLOCK, hash: blockHash }],
        },
      };
      this.peerManager.broadcast(invMsg);
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

    // Determine the hash of the most critical block (the one at
    // nextHeightToProcess).  This is the bottleneck — no other block can
    // be processed until it arrives.  Previously we gave it 5x the normal
    // timeout, but that caused a death spiral: the long timeout prevented
    // stall detection, the peer never delivered, the buffer filled with
    // higher blocks, the deadlock handler evicted them, and the cycle
    // repeated forever (observed stuck at block 420,017).
    //
    // Now the critical block gets the SAME timeout as other blocks.
    // The DUP-REQ mechanism in processOrderedBlocksInner handles slow-
    // but-progressing peers by sending parallel requests without cancelling
    // the original.
    const criticalEntry = this.headerSync.getHeaderByHeight(
      this.state.nextHeightToProcess
    );
    const criticalHashHex = criticalEntry?.hash.toString("hex") ?? "";

    // Check for stalled requests
    for (const [hashHex, pending] of this.state.pendingBlocks) {
      const elapsed = now - pending.requestedAt;

      // All blocks use the same timeout.  The critical block no longer
      // gets special treatment — the 5x multiplier caused permanent
      // stalls when the assigned peer was unresponsive.
      const effectiveTimeout = pending.timeout;

      if (elapsed > effectiveTimeout) {
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
        // Put peer in cooldown: don't assign new blocks for a while.
        // Peers that have never delivered blocks get a longer cooldown.
        const cooldownMs = peerInfo.blocksDelivered > 0 ? 60000 : 300000;
        peerInfo.cooldownUntil = Math.max(
          peerInfo.cooldownUntil,
          Date.now() + cooldownMs
        );

        // During IBD, never ban peers for slow delivery — just disconnect.
        // Banning during IBD causes the node to run out of peers and die.
        // After IBD, apply ban scores normally.
        const isIBD = this.headerSync.getBestHeader() &&
          this.state.nextHeightToProcess < this.headerSync.getBestHeader()!.height - 1000;

        if (stallCount >= 20 && this.peerManager) {
          const peers = this.peerManager.getConnectedPeers();
          const peer = peers.find((p) => `${p.host}:${p.port}` === peerKey);
          if (peer && !isIBD) {
            // Only ban outside IBD
            this.peerManager.increaseBanScore(
              peer,
              BanScores.BLOCK_DOWNLOAD_STALL,
              `Stalled ${stallCount} blocks`
            );
          }
          // Log but don't ban during IBD
          if (isIBD) {
            console.log(`IBD: peer ${peerKey} stalled ${stallCount} blocks (not banning)`);
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

    // Clean up pending requests for peers that have disconnected.
    // Without this, requests to dead peers linger for the full stall
    // timeout, blocking progress when the buffer fills.
    if (this.peerManager && this.state.pendingBlocks.size > 0) {
      const connectedPeers = new Set(
        this.peerManager
          .getConnectedPeers()
          .map((p) => `${p.host}:${p.port}`)
      );
      let cleaned = 0;
      for (const [hashHex, pending] of this.state.pendingBlocks) {
        if (!connectedPeers.has(pending.peer)) {
          this.state.pendingBlocks.delete(hashHex);
          if (pending.height < this.state.nextHeightToRequest) {
            this.state.nextHeightToRequest = pending.height;
          }
          cleaned++;
        }
      }
      if (cleaned > 0) {
        this.requestBlocks();
      }
    }

    // Detect processing deadlock: downloaded buffer is full (or near-full)
    // but the next block we need isn't in it.  This happens when the buffer
    // fills with blocks at heights we can't process yet (e.g. blocks arrived
    // out of order with gaps, or a peer failed to deliver a specific block).
    // Without this check, processing stalls permanently because
    // requestBlocks() refuses to fetch more while the buffer is full.
    if (this.state.downloadedBlocks.size >= MAX_DOWNLOADED_BUFFER) {
      const bestHeader = this.headerSync.getBestHeader();
      if (bestHeader && this.state.nextHeightToProcess <= bestHeader.height) {
        const nextEntry = this.headerSync.getHeaderByHeight(
          this.state.nextHeightToProcess
        );
        if (
          nextEntry &&
          !this.state.downloadedBlocks.has(nextEntry.hash.toString("hex"))
        ) {
          // The block we need is NOT in the buffer. Evict blocks that are
          // far ahead of the processing frontier to make room for the blocks
          // we actually need. Keep blocks that are within a small window of
          // the processing height since we'll need them soon.
          const keepWindow = MAX_DOWNLOADED_BUFFER / 2;
          const maxKeepHeight = this.state.nextHeightToProcess + keepWindow;
          let evicted = 0;
          for (const [hashHex] of this.state.downloadedBlocks) {
            const entry = this.headerSync.getHeader(
              Buffer.from(hashHex, "hex")
            );
            if (!entry || entry.height > maxKeepHeight || entry.height < this.state.nextHeightToProcess) {
              this.state.downloadedBlocks.delete(hashHex);
              evicted++;
            }
          }

          // Also clear pending requests beyond the keep window,
          // AND clear the critical block's pending entry if it's been
          // pending too long.  This is the key fix for the 420,017 stall:
          // the buffer filling is proof that the critical block's peer is
          // not delivering, so we must forcibly cancel and re-request.
          let pendingCleared = 0;
          const criticalHashHex = nextEntry.hash.toString("hex");
          for (const [hashHex, pending] of this.state.pendingBlocks) {
            const shouldClear = pending.height > maxKeepHeight ||
              (hashHex === criticalHashHex &&
               (Date.now() - pending.requestedAt) > BASE_STALL_TIMEOUT / 2);
            if (shouldClear) {
              this.state.pendingBlocks.delete(hashHex);
              const peerInfo = this.peerInFlight.get(pending.peer);
              if (peerInfo) {
                peerInfo.count = Math.max(0, peerInfo.count - 1);
              }
              if (hashHex === criticalHashHex) {
                console.log(`DEADLOCK-FIX: cleared pending critical block ${pending.height} from ${pending.peer} (age=${Date.now() - pending.requestedAt}ms)`);
              }
              pendingCleared++;
            }
          }

          if (evicted > 0 || pendingCleared > 0) {
            // Reset request pointer to fill the gap
            this.state.nextHeightToRequest = this.state.nextHeightToProcess;
            this.requestBlocks();
          }
        }
      }
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

    const mem = process.memoryUsage();
    const rssMB = (mem.rss / 1024 / 1024).toFixed(0);
    const heapMB = (mem.heapUsed / 1024 / 1024).toFixed(0);
    const utxoCacheSize = this.utxoManager.getCacheSize();
    const pendingCount = this.state.pendingBlocks.size;
    const downloadedCount = this.state.downloadedBlocks.size;
    const headerCount = this.headerSync.getHeaderCount();

    // Note: removed Bun.gc(true) - full GC every 10s is too expensive during IBD.
    // Let the runtime manage GC naturally.

    console.log(
      `IBD: height=${processed}/${total} (${percent.toFixed(1)}%) | ${blocksPerSec.toFixed(0)} blk/s | ${peerCount} peers | RSS=${rssMB}MB heap=${heapMB}MB | utxo=${utxoCacheSize} pend=${pendingCount} dl=${downloadedCount} hdrs=${headerCount}`
    );
  }

  /**
   * Get current download state (for testing/debugging).
   */
  getState(): BlockDownloadState {
    return this.state;
  }

  /**
   * Prune downloaded blocks that are too far ahead of nextHeightToProcess.
   * Keeps only blocks within MAX_DOWNLOADED_BUFFER heights ahead of
   * processing to avoid memory bloat from out-of-order arrivals.
   */
  private pruneDownloadedBlocks(): void {
    const maxAhead = MAX_DOWNLOADED_BUFFER * 2;
    const pruneThreshold = this.state.nextHeightToProcess + maxAhead;

    for (const [hashHex] of this.state.downloadedBlocks) {
      // Look up the header by the map key directly — avoids re-hashing the
      // block (expensive) and keeps no reference to the Block object so it
      // can be collected immediately after deletion.
      const headerEntry = this.headerSync.getHeader(Buffer.from(hashHex, "hex"));
      if (headerEntry && headerEntry.height > pruneThreshold) {
        this.state.downloadedBlocks.delete(hashHex);
        // Allow this height to be re-requested later
        if (headerEntry.height < this.state.nextHeightToRequest) {
          this.state.nextHeightToRequest = headerEntry.height;
        }
      }
      // Stop pruning once we're under the limit
      if (this.state.downloadedBlocks.size < MAX_DOWNLOADED_BUFFER) {
        break;
      }
    }
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
