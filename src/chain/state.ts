/**
 * Chain state: current tip, chainwork, block connection/disconnection, reorg handling.
 *
 * Manages the validated chain state, connecting and disconnecting blocks,
 * maintaining UTXO consistency, and handling chain reorganizations.
 */

import type {
  BatchOperation,
  ChainDB,
  ChainState,
  UTXOEntry,
  BlockIndexRecord,
} from "../storage/database.js";
import { BlockStatus } from "../storage/database.js";
import type { ConsensusParams } from "../consensus/params.js";
import type { Block, BlockHeader } from "../validation/block.js";
import {
  getBlockHash,
  serializeBlock,
  serializeBlockHeader,
  deserializeBlock,
} from "../validation/block.js";
import type { Transaction } from "../validation/tx.js";
import {
  getTxId,
  isCoinbase,
} from "../validation/tx.js";
import type { HeaderChainEntry } from "../sync/headers.js";
import {
  UTXOManager,
  SpentUTXO,
  serializeUndoData,
  deserializeUndoData,
  DisconnectResult,
} from "./utxo.js";
import { ConsensusError, ConsensusErrorCode } from "../validation/errors.js";
import { BufferReader } from "../wire/serialization.js";
import { globalSigCache } from "../validation/sig_cache.js";
import {
  coreConnectBlockChecks,
} from "../consensus/connect_block.js";

/**
 * Result of transaction input validation.
 */
export interface TxInputValidation {
  valid: boolean;
  fee: bigint;
  error?: string;
}

/**
 * Result of checkpoint verification.
 */
export interface CheckpointResult {
  valid: boolean;
  error?: string;
}

/**
 * Result of chain management operations (invalidateblock, reconsiderblock, preciousblock).
 */
export interface ChainManagementResult {
  success: boolean;
  error?: string;
  /** Number of blocks disconnected (invalidateblock) or reconnected (reconsiderblock). */
  blocksAffected?: number;
}

/**
 * Get the highest checkpoint height from consensus params.
 *
 * @param params - Network consensus parameters
 * @returns The highest checkpoint height, or -1 if no checkpoints
 */
export function getLastCheckpointHeight(params: ConsensusParams): number {
  let maxHeight = -1;
  for (const height of params.checkpoints.keys()) {
    if (height > maxHeight) {
      maxHeight = height;
    }
  }
  return maxHeight;
}

/**
 * Verify that a block at a checkpoint height matches the expected hash.
 *
 * @param hash - Block hash to verify
 * @param height - Block height
 * @param params - Network consensus parameters
 * @returns Checkpoint verification result
 */
export function verifyCheckpoint(
  hash: Buffer,
  height: number,
  params: ConsensusParams
): CheckpointResult {
  const checkpoint = params.checkpoints.get(height);

  // If there's no checkpoint at this height, it passes
  if (!checkpoint) {
    return { valid: true };
  }

  // Verify hash matches exactly
  if (hash.equals(checkpoint)) {
    return { valid: true };
  }

  return {
    valid: false,
    error: `Checkpoint mismatch at height ${height}: expected ${checkpoint.toString("hex")}, got ${hash.toString("hex")}`,
  };
}

/**
 * Check if a header would create a fork below the last checkpoint.
 *
 * During IBD, we reject any chain that forks from our chain at or before
 * the last checkpoint. This prevents long-range attacks where an attacker
 * creates an alternative history.
 *
 * @param headerHeight - Height of the header being validated
 * @param headerHash - Hash of the header being validated
 * @param parentHash - Hash of the parent block
 * @param params - Network consensus parameters
 * @param getAncestorHash - Function to get an ancestor hash at a given height
 * @returns CheckpointResult indicating if the header is valid
 */
export function checkForkBelowCheckpoint(
  headerHeight: number,
  headerHash: Buffer,
  parentHash: Buffer,
  params: ConsensusParams,
  getAncestorHash: (height: number) => Buffer | undefined
): CheckpointResult {
  const lastCheckpointHeight = getLastCheckpointHeight(params);

  // No checkpoints = no fork restrictions
  if (lastCheckpointHeight < 0) {
    return { valid: true };
  }

  // If this header is at or above the last checkpoint, we need to verify
  // that our chain ancestry matches all checkpoints
  if (headerHeight > lastCheckpointHeight) {
    // Verify all checkpoints are in our ancestry
    for (const [cpHeight, cpHash] of params.checkpoints) {
      const ancestorHash = getAncestorHash(cpHeight);
      if (ancestorHash && !ancestorHash.equals(cpHash)) {
        return {
          valid: false,
          error: `Fork detected below checkpoint at height ${cpHeight}: expected ${cpHash.toString("hex")}, got ${ancestorHash.toString("hex")}`,
        };
      }
    }
  }

  // If the header is at a checkpoint height, verify it matches
  const checkpointAtHeight = params.checkpoints.get(headerHeight);
  if (checkpointAtHeight && !headerHash.equals(checkpointAtHeight)) {
    return {
      valid: false,
      error: `Block at checkpoint height ${headerHeight} does not match: expected ${checkpointAtHeight.toString("hex")}, got ${headerHash.toString("hex")}`,
    };
  }

  return { valid: true };
}

/**
 * Chain state manager.
 *
 * Responsible for:
 * - Tracking the current best block (tip)
 * - Connecting validated blocks (updating UTXOs, storing block data)
 * - Disconnecting blocks (restoring UTXOs from undo data)
 * - Handling chain reorganizations
 * - Validating transaction inputs against the UTXO set
 */
export class ChainStateManager {
  private db: ChainDB;
  private utxo: UTXOManager;
  private params: ConsensusParams;
  private bestBlock: { hash: Buffer; height: number; chainWork: bigint };
  private notificationEmitter: import("events").EventEmitter | null;
  /** Tip-change notifier backing the wait-family RPCs (waitfornewblock /
   *  waitforblock / waitforblockheight). Fired on EVERY active-chain tip
   *  advance — every `this.bestBlock = …` mutation point below: connectBlock
   *  (tip extension + reorg reconnect), disconnectBlock (reorg / invalidateblock
   *  rewind), and updateTip (the BlockSync IBD / post-IBD / submitblock /
   *  generate connect path). Core: KernelNotifications::blockTip /
   *  Mining::waitTipChanged (rpc/blockchain.cpp). Wired via setTipNotifier()
   *  from cli.ts and shared with the RPC server through getTipNotifier(). */
  private tipNotifier: import("./tip_notifier.js").TipNotifier | null = null;
  /** Mempool for conflict removal during invalidation. */
  private mempool: import("../mempool/mempool.js").Mempool | null = null;
  /** Header sync for coordinating header chain state. */
  private headerSync: import("../sync/headers.js").HeaderSync | null = null;
  /** Optional BIP-157/158 compact-block-filter index. Wired via
   *  `setBlockFilterIndex()` from cli.ts when `--blockfilterindex=1`.
   *  When set, `disconnectBlock` calls `filterIndex.removeBlock(...)`
   *  so the filter-header chain rewinds in lockstep with the chain
   *  tip — symmetric with `BlockSync.connectBlock` which calls
   *  `filterIndex.indexBlock(...)`. Mirrors Bitcoin Core's
   *  `BlockFilterIndex::CustomRemove` (src/index/blockfilterindex.cpp).
   *
   *  Used by the dumptxoutset rollback dance (rpc/server.ts) and the
   *  generateblock RPC reorg path. The IBD reorg path (BlockSync)
   *  has its own copy of this reference. */
  private filterIndex: import("../storage/indexes.js").BlockFilterIndex | null = null;
  /** Persistent, reorg-safe coinstatsindex. Wired via setCoinStatsIndex()
   *  from cli.ts when `--coinstatsindex=1`. Used by the chain-state-manager
   *  reorg paths (invalidateblock, reorganize, generateblock): connectBlock
   *  calls indexBlock(...), disconnectBlock calls removeBlock(...). The IBD
   *  reorg path (BlockSync) holds its own reference to the same instance.
   *  Reference: bitcoin-core/src/index/coinstatsindex.cpp. */
  private coinStatsIndex: import("../storage/indexes.js").PersistentCoinStatsIndex | null = null;
  /** Optional txospenderindex (Bitcoin Core -txospenderindex parity). Wired via
   *  setTxoSpenderIndex() from cli.ts when `--txospenderindex=1`. Used by the
   *  chain-state-manager reorg paths (invalidateblock, reorganize): connectBlock
   *  calls indexBlock(...), disconnectBlock calls removeBlock(...). The live
   *  reorg path (BlockSync) holds its own reference to the same instance.
   *  Reference: bitcoin-core/src/index/txospenderindex.cpp. */
  private txoSpenderIndex: import("../storage/indexes.js").TxoSpenderIndex | null = null;
  /** Precious block for tie-breaking. null if no precious block set. */
  private preciousBlockHash: Buffer | null = null;
  /** Sequence ID for precious block tie-breaking. Lower = more precious. */
  private blockSequenceId: number = 0;
  /** Last chain work when preciousblock was set. Used to reset sequence IDs. */
  private lastPreciousChainwork: bigint = 0n;
  /** Whether block pruning is enabled (`--prune=N`). Gates the reorg-depth
   *  bound in `reorganize()`: an archive node follows the most-work chain to
   *  the fork point at ANY depth (Core parity, no cap); a pruned node retains
   *  only the MIN_BLOCKS_TO_KEEP (288) undo window. Wired from cli.ts via
   *  `setPruningEnabled()`. Defaults to archive (unbounded). */
  private pruningEnabled: boolean = false;

  constructor(db: ChainDB, params: ConsensusParams, maxCacheBytes?: number) {
    this.db = db;
    this.utxo = new UTXOManager(db, maxCacheBytes);
    this.params = params;
    // Initialize with genesis state - will be overwritten by load()
    this.bestBlock = {
      hash: params.genesisBlockHash,
      height: 0,
      chainWork: 0n,
    };
    this.notificationEmitter = null;
  }

  /**
   * Set the notification event emitter for ZMQ.
   */
  setNotificationEmitter(emitter: import("events").EventEmitter): void {
    this.notificationEmitter = emitter;
  }

  /**
   * Wire the tip-change notifier shared by the wait-family RPCs.  Called once
   * at startup (cli.ts).  The same instance is read back by the RPC server via
   * {@link getTipNotifier} so a waitfornewblock / waitforblock /
   * waitforblockheight handler parks on the same generation counter that this
   * manager (and the BlockSync connect path, via `updateTip`) bumps.
   */
  setTipNotifier(notifier: import("./tip_notifier.js").TipNotifier): void {
    this.tipNotifier = notifier;
  }

  /** The wired tip-change notifier, or null if none (degraded boot / tooling). */
  getTipNotifier(): import("./tip_notifier.js").TipNotifier | null {
    return this.tipNotifier;
  }

  /**
   * Pulse the tip-change notifier (Core KernelNotifications::blockTip).  Called
   * from every active-chain tip-advance site so a blocked wait-family RPC wakes
   * promptly.  Best-effort: a notifier fault must NEVER abort a connect /
   * disconnect / reorg.  The waiter re-reads the authoritative tip on wake, so a
   * dropped pulse degrades only latency, never correctness.
   */
  private notifyTipChanged(): void {
    if (this.tipNotifier === null) return;
    try {
      this.tipNotifier.notify();
    } catch {
      /* best-effort; never let a notifier fault stall block processing */
    }
  }

  /**
   * Fire the `blockConnected` notification on the shared bus for a block that
   * was connected through a path OTHER than `connectBlock` (state.ts:595) —
   * namely the BlockSync connect path used by injectBlock (generatetoaddress /
   * submitblock) and P2P tip-extension. Lets those paths feed the SAME
   * cli.ts listeners (wallet block-connect credit, fee estimator, mempool tip)
   * that `connectBlock` feeds, so wallet getbalance reflects mined coinbases.
   * Core parity: validation.cpp ConnectTip fires GetMainSignals().BlockConnected
   * for every connected block, not only reorg reconnections. No-op when no
   * emitter is wired (e.g. headless tooling). Idempotent per block: a block
   * connects through exactly one of connectBlock / BlockSync, never both.
   */
  emitBlockConnected(block: Block): void {
    if (this.notificationEmitter) {
      this.notificationEmitter.emit("blockConnected", block);
    }
  }

  /**
   * Symmetric counterpart of {@link emitBlockConnected} for the BlockSync reorg
   * disconnect path (disconnectBlockUtxo). Fires `blockDisconnected` so the
   * wallet rolls back the credits this block created (cli.ts: chainEvents.on
   * blockDisconnected -> walletManager.disconnectBlock), keeping wallet state
   * reorg-safe when a fork is replaced via P2P rather than invalidateblock.
   * Core parity: validation.cpp DisconnectTip fires BlockDisconnected. No-op
   * when no emitter is wired; disconnectBlock removes only outpoints the block
   * created, so a notify for a never-credited block is a harmless no-op.
   */
  emitBlockDisconnected(block: Block): void {
    if (this.notificationEmitter) {
      this.notificationEmitter.emit("blockDisconnected", block);
    }
  }

  /**
   * Set the mempool for conflict removal during invalidation.
   */
  setMempool(mempool: import("../mempool/mempool.js").Mempool): void {
    this.mempool = mempool;
  }

  /**
   * Declare whether block pruning is enabled (`--prune=N`). Gates the
   * reorg-depth bound in `reorganize()`: archive (default) follows the
   * most-work chain to the fork point at any depth (Core parity); a pruned
   * node retains only the MIN_BLOCKS_TO_KEEP (288) undo window. Wired from
   * cli.ts alongside `BlockSync.setPruneManager()`.
   */
  setPruningEnabled(enabled: boolean): void {
    this.pruningEnabled = enabled;
  }

  /**
   * Wire the BIP-157/158 compact-block-filter index so disconnect
   * paths invoked through the chain-state manager (dumptxoutset
   * rollback, generateblock reorg) keep the filter-header chain in
   * sync with the chain tip.
   *
   * No-op when not wired (default off, matches Bitcoin Core's
   * `DEFAULT_BLOCKFILTERINDEX = false`).
   *
   * Reference: bitcoin-core/src/index/blockfilterindex.cpp::CustomRemove.
   */
  setBlockFilterIndex(
    filterIndex: import("../storage/indexes.js").BlockFilterIndex
  ): void {
    this.filterIndex = filterIndex;
  }

  /**
   * Wire the persistent coinstatsindex so reorg paths invoked through the
   * chain-state manager (invalidateblock, reorganize, generateblock) keep the
   * per-height UTXO MuHash3072 + counts snapshot in lockstep with the chain
   * tip — connectBlock appends, disconnectBlock rewinds.
   *
   * No-op when not wired (default off; Bitcoin Core DEFAULT_COINSTATSINDEX).
   * Reference: bitcoin-core/src/index/coinstatsindex.cpp.
   */
  setCoinStatsIndex(
    coinStatsIndex: import("../storage/indexes.js").PersistentCoinStatsIndex
  ): void {
    this.coinStatsIndex = coinStatsIndex;
  }

  /**
   * Wire the txospenderindex so reorg paths invoked through the chain-state
   * manager (invalidateblock, reorganize) keep the spent-outpoint -> spending-tx
   * mapping in lockstep with the chain tip — connectBlock writes spend records,
   * disconnectBlock erases them.
   *
   * No-op when not wired (default off; Bitcoin Core DEFAULT_TXOSPENDERINDEX).
   * Reference: bitcoin-core/src/index/txospenderindex.cpp.
   */
  setTxoSpenderIndex(
    txoSpenderIndex: import("../storage/indexes.js").TxoSpenderIndex
  ): void {
    this.txoSpenderIndex = txoSpenderIndex;
  }

  /**
   * Set the header sync for coordinating header chain state.
   */
  setHeaderSync(headerSync: import("../sync/headers.js").HeaderSync): void {
    this.headerSync = headerSync;
  }

  /**
   * Get the UTXO manager for direct access if needed.
   */
  getUTXOManager(): UTXOManager {
    return this.utxo;
  }

  /**
   * Connect a validated block: update UTXOs, store block, update chain tip.
   *
   * Delegates consensus checks + UTXO mutations to coreConnectBlockChecks
   * (src/consensus/connect_block.ts), then handles the DB persistence that is
   * specific to this path (undo data, block store, block index, chain state).
   *
   * Error handling: throws on any consensus or DB failure.
   *
   * Callers:
   *   - rpc/server.ts: generateblock (regtest mining)
   *   - rpc/server.ts: dumptxoutset rollback re-apply
   *   - chain/state.ts::reorganize (reconnect blocks on new chain branch)
   *
   * Reference: Bitcoin Core validation.cpp::ConnectBlock
   */
  async connectBlock(block: Block, height: number): Promise<void> {
    const blockHash = getBlockHash(block.header);

    // Verify checkpoint if this height has one
    const checkpointResult = verifyCheckpoint(blockHash, height, this.params);
    if (!checkpointResult.valid) {
      throw new Error(checkpointResult.error);
    }

    // Delegate all consensus checks (BIP-30, IsFinalTx, maturity, BIP-68, scripts,
    // sigops, coinbase value) and UTXO mutations (spendOutput + addTransaction)
    // to the shared helper.  This eliminates the previous duplication with
    // sync/blocks.ts::connectBlock and ensures both paths run the same checks.
    //
    // This path runs full validation (no assumevalid) because:
    //   - generateblock (regtest) is mining new blocks that haven't been validated
    //   - dumptxoutset re-apply reconnects already-validated blocks, but we still
    //     re-run checks for correctness (cheap relative to DB I/O)
    //   - reorganize reconnects blocks from a previously validated alternative chain
    const csvActive = height >= this.params.csvHeight;

    // W93: thread the canonical genesis hash so coreConnectBlockChecks can
    // short-circuit the per-tx loop on genesis (Core validation.cpp:2339-2343).
    const genesisHashHexLE = Buffer.from(this.params.genesisBlockHash)
      .reverse()
      .toString("hex");

    // W93: pass the UTXO view's current best-block hash for the
    // hashPrevBlock == view.GetBestBlock() invariant (Core validation.cpp:2333).
    // Wrapped in a try because cold start / dumptxoutset reload may leave the
    // view's bestBlock unset — coreConnectBlockChecks treats an all-zero or
    // empty hash as "fresh start" and skips the check.
    let utxoBestBlockHashHexLE: string | undefined;
    try {
      const viewBest = await this.utxo.getCoinsViewCache().getBestBlock();
      if (viewBest && viewBest.length === 32) {
        utxoBestBlockHashHexLE = Buffer.from(viewBest).reverse().toString("hex");
      }
    } catch {
      // best-block unavailable (fresh datadir or migration) — skip the gate
      utxoBestBlockHashHexLE = undefined;
    }

    // W93: prefer prev block's Median Time Past from HeaderSync when wired.
    // Falls back to the block's own timestamp only when HeaderSync is absent
    // (e.g. regtest generateblock pre-tip-sync).
    let computedPrevMTP = block.header.timestamp;
    if (this.headerSync && height > 0) {
      try {
        const prevHeader = this.headerSync.getHeaderByHeight(height - 1);
        if (prevHeader) {
          computedPrevMTP = this.headerSync.getMedianTimePast(prevHeader);
        }
      } catch {
        // header-sync lookup failed — keep the fallback
      }
    }

    const result = await coreConnectBlockChecks(block, height, this.utxo, this.params, {
      assumeValid: false,
      skipScripts: false,
      prevMTP: computedPrevMTP,
      enforceBIP68: csvActive,
      scriptThreads: 1, // this path is not IBD-hot; serial is fine
      // MANDATORY height-gated consensus flags (Core GetBlockScriptFlags).
      verifyDERSig: height >= this.params.bip66Height,
      verifyCLTV: height >= this.params.bip65Height,
      verifyCSV: height >= this.params.csvHeight,
      verifyNullDummy: height >= this.params.segwitHeight,
      genesisHashHex: genesisHashHexLE,
      utxoBestBlockHashHex: utxoBestBlockHashHexLE,
      // BUG-2a fix: wire per-coin MTP for time-based BIP-68 sequence lock
      // enforcement on the reorg-reconnect / regtest / generateblock path.
      // Without this, coinMTP defaults to 0 for every input, making minTime
      // trivially satisfiable by any real prevMTP (false-ACCEPT of time-locked txs).
      //
      // Mirrors exactly sync/blocks.ts:3329-3332 (the IBD/P2P primary path).
      // Reads from headersByHeight, which HeaderSync.loadFromDB() populates from
      // the persistent block-index DB on every startup — correct during IBD AND
      // post-restart (never an in-memory-only source).
      //
      // Partial walk: getMedianTimePast collects up to 11 ancestor timestamps
      // walking back via prevBlock and returns the median of what it finds; it
      // never returns 0 on a short walk.  The only 0 path is when coinHeight <= 0
      // (genesis-ancestor, blocked by coinbase maturity anyway) or when no
      // header entry at (coinHeight-1) exists (data-integrity issue; conservatively
      // allows the lock rather than crash-rejecting).
      getUTXOMTP: this.headerSync
        ? (coinHeight: number): number => {
            if (coinHeight <= 0) return 0;
            const coinPrevHeader =
              this.headerSync!.getHeaderByHeight(coinHeight - 1);
            return coinPrevHeader
              ? this.headerSync!.getMedianTimePast(coinPrevHeader)
              : 0;
          }
        : undefined,
    });

    if (!result.ok) {
      throw new ConsensusError(
        ConsensusErrorCode.CONNECT_BLOCK_FAILED,
        result.error
      );
    }

    const { spentOutputs } = result;

    // W93: update the UTXO view's best-block pointer BEFORE flush, mirroring
    // Bitcoin Core validation.cpp:2654 (`view.SetBestBlock(pindex->GetBlockHash())`).
    // The disconnect path (state.ts:630) already does this symmetrically with
    // `this.utxo.setBestBlock(prevHash)` — the missing connect-side call was an
    // asymmetry that left the in-memory view best-block stale until the next
    // flush completed.  Setting it here makes the W93 view-consistency gate
    // (utxoBestBlockHashHex) work correctly on the very next connect call.
    this.utxo.setBestBlock(blockHash);

    // Serialize and store undo data
    const undoData = serializeUndoData(spentOutputs);
    await this.db.putUndoData(blockHash, undoData);

    // Flush UTXO changes
    await this.utxo.flush();

    // Store block data
    const rawBlock = serializeBlock(block);
    await this.db.putBlock(blockHash, rawBlock);

    // Store block index record (hash -> metadata) and height -> hash mapping
    const headerBytes = serializeBlockHeader(block.header);
    await this.db.putBlockIndex(blockHash, {
      height,
      header: headerBytes,
      nTx: block.transactions.length,
      status: BlockStatus.HEADER_VALID | BlockStatus.TXS_VALID | BlockStatus.HAVE_DATA | BlockStatus.HAVE_UNDO,
      dataPos: 1, // block data exists
    });

    // ── Pattern C0: write txindex on connect ──
    //
    // Mirrors the sync/blocks.ts::connectBlock connect-side wiring
    // added by this fix.  This path runs for generateblock /
    // dumptxoutset re-apply / chain/state.ts::reorganize — they all
    // need the same index entries so getrawtransaction works after
    // a regtest mine or a snapshot rollback.  See
    // CORE-PARITY-AUDIT/_txindex-revert-on-reorg-fleet-result-2026-05-05.md
    // (Pattern C0, hotbuns row).  Best-effort: a put failure is logged
    // and ignored — txindex is an optional secondary index in Core.
    try {
      for (const tx of block.transactions) {
        const txid = getTxId(tx);
        await this.db.putTxIndex(txid, {
          blockHash,
          offset: 0,
          length: 0,
        });
      }
    } catch (err) {
      console.warn(
        `[txindex] failed to write entries for block ${blockHash
          .toString("hex")
          .slice(0, 16)}: ${err instanceof Error ? err.message : String(err)}`
      );
    }

    // ── BIP-157/158: advance the block filter index on connect ──
    //
    // Connect-side counterpart to the `filterIndex.removeBlock(...)` call in
    // disconnectBlock (state.ts:754). Previously this path (generateblock /
    // regtest mining / dumptxoutset re-apply / reorganize) only ever
    // *removed* filter entries on disconnect and never *appended* on
    // connect, so the filter index's height never advanced when blocks were
    // mined through chain/state instead of network IBD (BlockSync.connectBlock
    // already calls indexBlock at blocks.ts:2958). That left the filter index
    // permanently at "no best block" (height -1) on a regtest-mined chain, so
    // getindexinfo reported it un-synced even after the chain reached the tip.
    //
    // Mirrors Bitcoin Core's CValidationInterface BlockConnected fan-out:
    // BaseIndex::BlockConnected → CustomAppend for every connected block,
    // regardless of whether it arrived via net sync or RPC mining
    // (src/index/base.cpp, src/index/blockfilterindex.cpp::CustomAppend).
    // Best-effort: a failure is logged and ignored — the filter index is an
    // optional secondary index and must never abort the chain advance.
    if (this.filterIndex && this.filterIndex.isEnabled()) {
      try {
        await this.filterIndex.indexBlock(block, height, spentOutputs);
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        console.warn(
          `[blockfilterindex] failed to index block ${blockHash
            .toString("hex")
            .slice(0, 16)} at h=${height}: ${msg} (continuing)`
        );
      }
    }

    // ── coinstatsindex: advance the per-height UTXO MuHash on connect ──
    //
    // Connect-side counterpart to the `coinStatsIndex.removeBlock(...)` call in
    // disconnectBlock. Covers the chain-state-manager connect paths
    // (generateblock / dumptxoutset re-apply / reorganize reconnect). Mirrors
    // BaseIndex::BlockConnected → CustomAppend. The spentOutputs list is the
    // same undo data the block-filter index above consumes, carrying each spent
    // coin's original height+coinbase+amount+script for the TxOutSer REMOVE.
    // Best-effort: a failure is logged and ignored — never aborts the connect.
    // Reference: bitcoin-core/src/index/coinstatsindex.cpp::CustomAppend.
    if (this.coinStatsIndex && this.coinStatsIndex.isEnabled()) {
      try {
        await this.coinStatsIndex.indexBlock(block, height, spentOutputs);
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        console.warn(
          `[coinstatsindex] failed to index block ${blockHash
            .toString("hex")
            .slice(0, 16)} at h=${height}: ${msg} (continuing)`
        );
      }
    }

    // ── txospenderindex: write spent-outpoint -> spending-tx on connect ──
    //
    // Connect-side counterpart to the `txoSpenderIndex.removeBlock(...)` call in
    // disconnectBlock. Covers the chain-state-manager connect paths
    // (generateblock / reorganize reconnect). Mirrors Core
    // BaseIndex::BlockConnected -> CustomAppend. Best-effort: a failure is
    // logged and ignored — never aborts the connect.
    // Reference: bitcoin-core/src/index/txospenderindex.cpp::CustomAppend.
    if (this.txoSpenderIndex && this.txoSpenderIndex.isEnabled()) {
      try {
        await this.txoSpenderIndex.indexBlock(block, height);
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        console.warn(
          `[txospenderindex] failed to index block ${blockHash
            .toString("hex")
            .slice(0, 16)} at h=${height}: ${msg} (continuing)`
        );
      }
    }

    // Calculate chain work (approximate - should come from header chain)
    // Work = 2^256 / (target + 1), but we use a simplified version here
    const work = this.calculateWork(block.header.bits);
    const chainWork = this.bestBlock.chainWork + work;

    // Persist per-block chain work so getblockheader can return correct chainwork
    await this.db.putChainWork(blockHash, chainWork);

    // Update chain state
    this.bestBlock = {
      hash: blockHash,
      height,
      chainWork,
    };

    // Tip advanced (extension or reorg reconnect) — wake any wait-family RPC.
    // Core: ConnectTip fires KernelNotifications::blockTip for every connect.
    this.notifyTipChanged();

    await this.db.putChainState({
      bestBlockHash: blockHash,
      bestHeight: height,
      totalWork: chainWork,
    });

    // ── W93 Gate: ConnectTip — mempool.removeForBlock ──
    //
    // Bitcoin Core ConnectTip (validation.cpp:3073-3076) does:
    //   m_mempool->removeForBlock(block_to_connect->vtx, pindexNew->nHeight);
    //   disconnectpool.removeForBlock(block_to_connect->vtx);
    // immediately after the ConnectBlock + flush completes.  This evicts
    // confirmed txs from the mempool so they're not re-served via getmempool /
    // sendrawtransaction.  Pre-W93 the chain/state.ts connect path (regtest
    // generateblock + dumptxoutset reload + reorganize re-apply) NEVER called
    // mempool.removeForBlock — confirmed txs stayed in the mempool until they
    // were explicitly evicted by mempoolTrim or replaced.  Sync/blocks.ts has
    // the same bug; the fix there lives in the sister change.
    //
    // Best-effort: a removeForBlock failure must NOT roll back the connect.
    if (this.mempool) {
      try {
        this.mempool.removeForBlock(block);
      } catch (err) {
        console.warn(
          `[mempool.removeForBlock] non-fatal failure for block ${blockHash
            .toString("hex")
            .slice(0, 16)}: ${err instanceof Error ? err.message : String(err)}`
        );
      }
    }

    // Emit notification for ZMQ
    if (this.notificationEmitter) {
      this.notificationEmitter.emit("blockConnected", block);
    }
  }

  /**
   * Disconnect the tip block (for reorgs): restore spent UTXOs from undo data.
   *
   * Flow:
   * 1. Read undo data for the block
   * 2. For each transaction in reverse order:
   *    a. Remove outputs (they become unspent again in the previous state)
   *    b. Restore spent inputs from undo data
   * 3. Update chain state to previous block
   */
  async disconnectBlock(block: Block, height: number): Promise<void> {
    const blockHash = getBlockHash(block.header);

    // Verify this is the tip block
    if (!blockHash.equals(this.bestBlock.hash)) {
      throw new Error("Can only disconnect the tip block");
    }

    // Load undo data
    const undoData = await this.db.getUndoData(blockHash);
    if (!undoData) {
      throw new Error(`Missing undo data for block ${blockHash.toString("hex")}`);
    }

    const spentOutputs = deserializeUndoData(undoData);

    // ── W92 Core gate: blockUndo / block size consistency ──
    //
    // Mirrors bitcoin-core/src/validation.cpp:2190-2193 — Core checks
    // `blockUndo.vtxundo.size() + 1 != block.vtx.size()` and aborts the
    // disconnect on mismatch.  The +1 accounts for the coinbase (which
    // has no input-undo records).
    //
    // Without this gate a truncated/corrupted undo file would only
    // manifest as a "Missing undo entry for X" error mid-way through
    // the reverse walk, leaving the UTXO set half-restored on disk.
    // With the gate the disconnect aborts cleanly *before* any UTXO
    // mutation.
    //
    // Note: hotbuns stores undo data as a flat list of per-input
    // SpentUTXO records rather than Core's nested per-tx vtxundo, so
    // the equivalent invariant is:
    //   spentOutputs.length === sum(tx.inputs.length for non-coinbase tx)
    let expectedUndoEntries = 0;
    for (let i = 1; i < block.transactions.length; i++) {
      expectedUndoEntries += block.transactions[i].inputs.length;
    }
    if (spentOutputs.length !== expectedUndoEntries) {
      throw new Error(
        `DisconnectBlock(): block and undo data inconsistent ` +
          `(undo has ${spentOutputs.length} entries, expected ${expectedUndoEntries})`
      );
    }

    // Create a map for quick lookup of spent outputs by outpoint.  We keep
    // a separate per-tx queue too so we can validate the per-tx undo size
    // gate below (Core validation.cpp:2229).
    const spentByOutpoint = new Map<string, SpentUTXO>();
    for (const spent of spentOutputs) {
      const key = `${spent.txid.toString("hex")}:${spent.vout}`;
      spentByOutpoint.set(key, spent);
    }

    // ── W92 Core gate: disconnect-side BIP-30 exception ──
    //
    // Mirrors bitcoin-core/src/validation.cpp:2201-2202.  When
    // disconnecting one of the two mainnet blocks immediately preceding
    // a duplicate-coinbase (h=91722 or h=91812), the post-disconnect
    // UTXO set is intentionally inconsistent with the block's outputs
    // (because the LATER duplicate-coinbase block at h=91842 / h=91880
    // re-added the same outpoint).  Core suppresses the output-mismatch
    // fClean flag at these exact (height, hash) tuples.
    const blockHashHex = Buffer.from(blockHash).reverse().toString("hex");
    const fEnforceBIP30 = !this.params.bip30DisconnectExceptionBlocks.some(
      (ex) => ex.height === height && ex.blockHashHex === blockHashHex
    );

    // Tracks whether the disconnect ran clean.  Core also returns
    // DISCONNECT_UNCLEAN here; we surface it as a structured log line
    // because we don't propagate the tristate further up (DisconnectTip
    // does not abort on UNCLEAN in Core either — it just notes the
    // inconsistency and keeps going).
    let fClean = true;

    // Process transactions in reverse order — Core validation.cpp:2205.
    for (let txIndex = block.transactions.length - 1; txIndex >= 0; txIndex--) {
      const tx = block.transactions[txIndex];
      const txid = getTxId(tx);
      const txIsCoinbase = isCoinbase(tx);
      const isBIP30ExceptionTx = txIsCoinbase && !fEnforceBIP30;

      // ── W92 Core gate: per-output match check ──
      //
      // Core validation.cpp:2213-2224 walks every output of the tx and
      // verifies:
      //   - the output exists in the view (`is_spent` after SpendCoin)
      //   - `tx.vout[o] == coin.out`              (value + scriptPubKey)
      //   - `pindex->nHeight == coin.nHeight`     (creation height)
      //   - `is_coinbase == coin.fCoinBase`       (coinbase flag)
      // Unspendable outputs are skipped (they were never in the UTXO set).
      // Any mismatch flips fClean to false UNLESS this is a BIP-30
      // exception coinbase tx.
      for (let o = 0; o < tx.outputs.length; o++) {
        const outScript = tx.outputs[o].scriptPubKey;
        // Mirrors `if (!tx.vout[o].scriptPubKey.IsUnspendable())` — Core
        // skips unspendable outputs from the match check because they
        // were never AddCoin'd.  Hotbuns's CoinsViewCache.addCoin gate
        // (W92) matches: OP_RETURN-prefixed or > MAX_SCRIPT_SIZE.
        const unspendable =
          (outScript.length > 0 && outScript[0] === 0x6a) ||
          outScript.length > 10000;
        if (unspendable) continue;

        const spentCoin = await this.utxo.removeUTXO(txid, o);
        const isSpent = spentCoin !== null;
        const valueMatches = spentCoin && spentCoin.txOut.value === tx.outputs[o].value;
        const scriptMatches =
          spentCoin && spentCoin.txOut.scriptPubKey.equals(tx.outputs[o].scriptPubKey);
        const heightMatches = spentCoin && spentCoin.height === height;
        const coinbaseMatches = spentCoin && spentCoin.isCoinbase === txIsCoinbase;
        if (
          !isSpent ||
          !valueMatches ||
          !scriptMatches ||
          !heightMatches ||
          !coinbaseMatches
        ) {
          if (!isBIP30ExceptionTx) {
            fClean = false; // transaction output mismatch
          }
        }
      }

      // Restore spent inputs (for non-coinbase).  Core
      // validation.cpp:2227-2241.
      if (!txIsCoinbase) {
        // ── W92 Core gate: per-tx undo size check ──
        // Core line 2229: txundo.vprevout.size() != tx.vin.size().
        const expectedInputs = tx.inputs.length;
        let foundInputs = 0;
        for (const input of tx.inputs) {
          const key = `${input.prevOut.txid.toString("hex")}:${input.prevOut.vout}`;
          if (spentByOutpoint.has(key)) foundInputs++;
        }
        if (foundInputs !== expectedInputs) {
          throw new Error(
            `DisconnectBlock(): transaction and undo data inconsistent ` +
              `(tx ${txid.toString("hex").slice(0, 16)} has ${expectedInputs} inputs, ` +
              `found ${foundInputs} undo entries)`
          );
        }

        // ── W92 Core gate: reverse-iterate inputs ──
        // Core validation.cpp:2233 walks `for (j = tx.vin.size(); j > 0;)
        // { --j; ... }` — reverse order on inputs as well as txs.
        // Defensive: matters when undo entries are positional and
        // intra-block input dependencies exist.
        for (let j = tx.inputs.length - 1; j >= 0; j--) {
          const input = tx.inputs[j];
          const key = `${input.prevOut.txid.toString("hex")}:${input.prevOut.vout}`;
          const spent = spentByOutpoint.get(key);
          if (!spent) {
            // Already caught by the size check above, but be explicit.
            throw new Error(
              `Missing undo entry for ${input.prevOut.txid.toString("hex")}:${input.prevOut.vout}`
            );
          }
          // ── W92 Core gate: ApplyTxInUndo tristate ──
          // Replaces direct `restoreUTXO` with the Core-faithful helper
          // that runs HaveCoin → fClean=false, AccessByTxid metadata
          // recovery, and sets the AddCoin overwrite flag correctly.
          // Reference: validation.cpp:2149-2175.
          const res = await this.utxo.applyInputUndo(spent, input.prevOut);
          if (res === DisconnectResult.DISCONNECT_FAILED) {
            throw new Error(
              `DisconnectBlock(): ApplyTxInUndo failed for ${input.prevOut.txid
                .toString("hex")
                .slice(0, 16)}:${input.prevOut.vout} ` +
                `(missing metadata, no sibling output)`
            );
          }
          if (res === DisconnectResult.DISCONNECT_UNCLEAN) {
            fClean = false;
          }
        }
      }
    }

    // Surface UNCLEAN as a single log line per disconnected block, in
    // line with Core's `LogError` for UNCLEAN cases (Core flows it up to
    // DisconnectTip which logs via `BENCH`/`PRUNE` macros).
    if (!fClean) {
      console.warn(
        `[disconnect] block ${blockHash.toString("hex").slice(0, 16)} at h=${height} ` +
          `disconnected with UTXO inconsistencies (DISCONNECT_UNCLEAN)`
      );
    }

    // ── Pattern D: single-batch atomicity for disconnectBlock ──
    //
    // Compute the post-disconnect chain state, then commit it together
    // with the UTXO flush in ONE ClassicLevel batch.  Mirrors
    // bitcoin-core/src/validation.cpp::DisconnectTip, which routes every
    // disconnect-side write through a single CDBBatch.  Prior to the
    // Pattern D fix, disconnectBlock issued separate awaits (utxo.flush +
    // putChainState); a crash between any two left the chainstate
    // inconsistent.  See CORE-PARITY-AUDIT/_post-reorg-consistency-…
    //
    // NOTE: txindex entries are intentionally NOT deleted on disconnect.
    // Bitcoin Core's TxIndex has no CustomRemove override — its default
    // (base.h:136) is a no-op that returns true.  Core keeps txid->block
    // entries even for disconnected blocks so that getrawtransaction can
    // still resolve a tx from an orphaned block via the txindex path.
    // Reference: bitcoin-core/src/index/txindex.{h,cpp} (only CustomAppend,
    // no CustomRemove / BlockDisconnected erase).
    const prevHeight = height - 1;
    const prevHash = block.header.prevBlock;
    const work = this.calculateWork(block.header.bits);
    const prevChainWork = this.bestBlock.chainWork - work;

    // ── W92 Core gate: move UTXO view's best-block pointer to pprev ──
    //
    // Mirrors bitcoin-core/src/validation.cpp:2245 —
    //   view.SetBestBlock(pindex->pprev->GetBlockHash());
    // Done BEFORE the flush so the persisted chainstate's hashBlock
    // field matches the new tip atomically with the UTXO mutations
    // and chain-state row.  Without this the CoinsViewCache's
    // hashBlock can lag the on-disk chainstate by one block, and a
    // subsequent connect would assert against the wrong best-block.
    this.utxo.setBestBlock(prevHash);

    const extraOps: BatchOperation[] = [];

    // Pattern D: chain-state write rides the same batch.
    extraOps.push(
      this.db.buildChainStateOp({
        bestBlockHash: prevHash,
        bestHeight: prevHeight,
        totalWork: prevChainWork,
      })
    );

    // CChain::SetTip parity — the disconnected block is no longer on the active
    // chain, so drop its height->hash active-chain index entry.  Core's
    // `CChain::SetTip` resizes `vChain` down past the disconnected height.  The
    // reorg-reconnect path re-writes the [fork+1 .. newTip] entries for the new
    // branch, but a pure disconnect (invalidateblock, which shrinks the chain
    // with no replacement) must clear the entry here so getblockhash(height)
    // stops returning the now-orphaned block.  Rides the same atomic batch.
    extraOps.push(this.db.buildHeightHashDeleteOp(height));

    // Single atomic flush: UTXO changes + chain state + height->hash delete.
    // (No txindex deletes — see the Core-parity note above.)
    await this.utxo.flush(extraOps);

    // In-memory tip update happens AFTER the batch lands so a thrown
    // error from flush() leaves the in-memory view aligned with disk.
    this.bestBlock = {
      hash: prevHash,
      height: prevHeight,
      chainWork: prevChainWork,
    };

    // Tip moved (reorg rewind / invalidateblock) — this is the DISCONNECT half
    // of a reorg, a tip change too.  Core's KernelNotifications::blockTip fires
    // on disconnect as well, so wake any blocked wait-family RPC.
    this.notifyTipChanged();

    // ── BIP-157 Phase 2: filter-chain rewind on disconnect ──
    //
    // Symmetric with `BlockSync.connectBlock`, which advances the
    // filter chain via `filterIndex.indexBlock(...)`. On disconnect,
    // rewind the filter-header chain so the next reconnected block at
    // height computes its filter header against the *previous* block's
    // filter header (matching the new active chain), not against the
    // disconnected block's filter header.
    //
    // Mirrors bitcoin-core/src/index/blockfilterindex.cpp::CustomRemove,
    // which the BaseIndex worker invokes per `BlockDisconnected` notif.
    // Best-effort: a filter-index hiccup must NOT roll back the chain
    // disconnect — surface as a warning, mirroring Core's IndexFailure
    // handling in BaseIndex.
    if (this.filterIndex && this.filterIndex.isEnabled()) {
      try {
        await this.filterIndex.removeBlock(block, height);
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        console.warn(
          `[blockfilterindex] failed to remove block ${blockHash
            .toString("hex")
            .slice(0, 16)} at h=${height}: ${msg} (continuing)`
        );
      }
    }

    // ── coinstatsindex rewind on disconnect (invalidateblock / reorg) ──
    //
    // Drop the per-height snapshot at `height`; the running state for the new
    // tip is the already-persisted height-1 snapshot. This is the path that
    // invalidateblock walks (invalidateBlock → disconnectBlock), so the
    // harness's invalidateblock-triggered reorg rewinds the index here.
    // Mirrors bitcoin-core/src/index/coinstatsindex.cpp::CustomRewind.
    // Best-effort: never roll back the chain disconnect on a rewind hiccup.
    if (this.coinStatsIndex && this.coinStatsIndex.isEnabled()) {
      try {
        await this.coinStatsIndex.removeBlock(height);
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        console.warn(
          `[coinstatsindex] failed to remove block ${blockHash
            .toString("hex")
            .slice(0, 16)} at h=${height}: ${msg} (continuing)`
        );
      }
    }

    // ── txospenderindex rewind on disconnect (invalidateblock / reorg) ──
    //
    // RE-DERIVE the disconnected block's spend keys from its OWN inputs and
    // erase them (Core CustomRemove). This is the path invalidateblock walks
    // (invalidateBlock -> disconnectBlock), so an invalidateblock-triggered
    // rewind erases the orphaned branch's spend records here. The live reorg
    // path (BlockSync.disconnectBlockUtxo) does the same on the same instance.
    // Best-effort: never roll back the chain disconnect on a rewind hiccup.
    // Mirrors bitcoin-core/src/index/txospenderindex.cpp::CustomRemove.
    if (this.txoSpenderIndex && this.txoSpenderIndex.isEnabled()) {
      try {
        await this.txoSpenderIndex.removeBlock(block, height);
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        console.warn(
          `[txospenderindex] failed to remove block ${blockHash
            .toString("hex")
            .slice(0, 16)} at h=${height}: ${msg} (continuing)`
        );
      }
    }

    // Clear signature cache on disconnect (verifications may no longer be valid)
    globalSigCache.clear();

    // Emit notification for ZMQ
    if (this.notificationEmitter) {
      this.notificationEmitter.emit("blockDisconnected", block);
    }
  }

  /**
   * Handle a chain reorganization to a new tip.
   *
   * Flow:
   * 1. Find the fork point by walking both chains back
   * 2. Disconnect blocks from old chain back to fork
   * 3. Connect blocks on new chain from fork to new tip
   */
  async reorganize(
    newTip: HeaderChainEntry,
    getBlock: (hash: Buffer) => Promise<Block | null>
  ): Promise<void> {
    // ── Core-parity reorg-depth bound ──
    //
    // Bitcoin Core has NO fixed reorg-depth cap: ActivateBestChainStep
    // (validation.cpp) follows the most-work valid chain back to the fork point
    // at ANY depth; there is no nMaxReorgDepth.  MIN_BLOCKS_TO_KEEP=288 is a
    // PRUNING-only undo-retention floor, not a consensus reorg cap — refusing a
    // >288 reorg on an archive node is a Class-A consensus divergence (the node
    // stays on the losing minority chain = split).  So the bound is gated on
    // pruning:
    //   • archive node (default, undo always present) → UNBOUNDED (Core parity).
    //   • pruned node (`--prune=N`) → MIN_BLOCKS_TO_KEEP (288) retained undo
    //     window; a deeper reorg cannot be serviced (undo bodies deleted).
    // Kept in sync with the BlockSync live path (`reorgDepthCap()` in
    // sync/blocks.ts).
    const MIN_BLOCKS_TO_KEEP = 288;
    const MAX_REORG_DEPTH = this.pruningEnabled
      ? MIN_BLOCKS_TO_KEEP
      : Number.MAX_SAFE_INTEGER;

    // Find the fork point
    const { oldBlocks, newBlocks } = await this.findForkPoint(newTip, getBlock);

    if (oldBlocks.length > MAX_REORG_DEPTH || newBlocks.length > MAX_REORG_DEPTH) {
      throw new Error(
        `reorganize(): reorg depth exceeds MAX_REORG_DEPTH=${MAX_REORG_DEPTH} ` +
          `(old=${oldBlocks.length}, new=${newBlocks.length})`
      );
    }

    // Disconnect old blocks (in reverse order, from tip to fork)
    for (const { block, height } of oldBlocks.reverse()) {
      await this.disconnectBlock(block, height);
    }

    // Connect new blocks (in order, from fork to new tip)
    for (const { block, height } of newBlocks) {
      await this.connectBlock(block, height);
    }
  }

  /**
   * Find the fork point between the current chain and a new tip.
   * Returns the blocks to disconnect and connect.
   */
  private async findForkPoint(
    newTip: HeaderChainEntry,
    getBlock: (hash: Buffer) => Promise<Block | null>
  ): Promise<{
    oldBlocks: Array<{ block: Block; height: number }>;
    newBlocks: Array<{ block: Block; height: number }>;
  }> {
    const oldBlocks: Array<{ block: Block; height: number }> = [];
    const newBlocks: Array<{ block: Block; height: number }> = [];

    // Walk back from new tip to find blocks that aren't on our current chain
    let newHeight = newTip.height;
    let newHash = newTip.hash;
    const newBlockHashes: Buffer[] = [];

    while (newHeight > this.bestBlock.height) {
      newBlockHashes.unshift(Buffer.from(newHash));
      const block = await getBlock(newHash);
      if (!block) {
        throw new Error(`Missing block ${newHash.toString("hex")}`);
      }
      newHash = block.header.prevBlock;
      newHeight--;
    }

    // Now walk back both chains until they meet
    let oldHeight = this.bestBlock.height;
    let oldHash = this.bestBlock.hash;

    while (!oldHash.equals(newHash)) {
      // Add old block to disconnect list
      const oldBlock = await getBlock(oldHash);
      if (!oldBlock) {
        throw new Error(`Missing block ${oldHash.toString("hex")}`);
      }
      oldBlocks.push({ block: oldBlock, height: oldHeight });
      oldHash = oldBlock.header.prevBlock;
      oldHeight--;

      // Add new block to connect list
      newBlockHashes.unshift(Buffer.from(newHash));
      const newBlock = await getBlock(newHash);
      if (!newBlock) {
        throw new Error(`Missing block ${newHash.toString("hex")}`);
      }
      newHash = newBlock.header.prevBlock;
      newHeight--;
    }

    // Now build the new blocks list with actual Block objects
    let connectHeight = newHeight + 1;
    for (const hash of newBlockHashes) {
      const block = await getBlock(hash);
      if (!block) {
        throw new Error(`Missing block ${hash.toString("hex")}`);
      }
      newBlocks.push({ block, height: connectHeight });
      connectHeight++;
    }

    return { oldBlocks, newBlocks };
  }

  /**
   * Get the current best block.
   */
  getBestBlock(): { hash: Buffer; height: number; chainWork: bigint } {
    return { ...this.bestBlock };
  }

  /**
   * Update the in-memory chain tip without going through full connectBlock.
   * Used by BlockSync to keep RPC state in sync during IBD.
   */
  updateTip(hash: Buffer, height: number, chainWork: bigint): void {
    this.bestBlock = { hash, height, chainWork };
    // This is the tip-advance funnel for the BlockSync connect path: IBD and
    // post-IBD P2P block-connect, submitblock, and generatetoaddress/
    // generateblock (which all route injectBlock → BlockSync.connectBlock →
    // updateTip). Pulse the wait-family notifier here so those advances wake a
    // blocked waitfornewblock / waitforblock / waitforblockheight.
    this.notifyTipChanged();
  }

  /**
   * Validate transaction inputs against the UTXO set (contextual validation).
   *
   * Checks:
   * - Each input references a valid, unspent output
   * - Coinbase maturity (100 confirmations before spending)
   * - Total input value >= total output value
   * - Returns the transaction fee
   */
  validateTxInputs(tx: Transaction, height: number): TxInputValidation {
    // Coinbase transactions have no inputs to validate
    if (isCoinbase(tx)) {
      return { valid: true, fee: 0n };
    }

    let totalInputValue = 0n;
    let totalOutputValue = 0n;

    // Validate each input
    for (const input of tx.inputs) {
      const utxo = this.utxo.getUTXO(input.prevOut);
      if (!utxo) {
        return {
          valid: false,
          fee: 0n,
          error: `Missing UTXO: ${input.prevOut.txid.toString("hex")}:${input.prevOut.vout}`,
        };
      }

      // Check coinbase maturity
      if (utxo.coinbase) {
        const confirmations = height - utxo.height;
        if (confirmations < this.params.coinbaseMaturity) {
          return {
            valid: false,
            fee: 0n,
            error: ConsensusErrorCode.PREMATURE_COINBASE_SPEND,
          };
        }
      }

      totalInputValue += utxo.amount;
    }

    // Sum output values
    for (const output of tx.outputs) {
      totalOutputValue += output.value;
    }

    // Check that inputs cover outputs
    if (totalInputValue < totalOutputValue) {
      return {
        valid: false,
        fee: 0n,
        error: ConsensusErrorCode.INPUTS_NOT_EQUAL_OUTPUTS,
      };
    }

    const fee = totalInputValue - totalOutputValue;
    return { valid: true, fee };
  }

  /**
   * Validate transaction inputs asynchronously (checks database).
   */
  async validateTxInputsAsync(
    tx: Transaction,
    height: number
  ): Promise<TxInputValidation> {
    // Coinbase transactions have no inputs to validate
    if (isCoinbase(tx)) {
      return { valid: true, fee: 0n };
    }

    let totalInputValue = 0n;
    let totalOutputValue = 0n;

    // Validate each input
    for (const input of tx.inputs) {
      const utxo = await this.utxo.getUTXOAsync(input.prevOut);
      if (!utxo) {
        return {
          valid: false,
          fee: 0n,
          error: ConsensusErrorCode.MISSING_INPUTS,
        };
      }

      // Check coinbase maturity
      if (utxo.coinbase) {
        const confirmations = height - utxo.height;
        if (confirmations < this.params.coinbaseMaturity) {
          return {
            valid: false,
            fee: 0n,
            error: ConsensusErrorCode.PREMATURE_COINBASE_SPEND,
          };
        }
      }

      totalInputValue += utxo.amount;
    }

    // Sum output values
    for (const output of tx.outputs) {
      totalOutputValue += output.value;
    }

    // Check that inputs cover outputs
    if (totalInputValue < totalOutputValue) {
      return {
        valid: false,
        fee: 0n,
        error: ConsensusErrorCode.INPUTS_NOT_EQUAL_OUTPUTS,
      };
    }

    const fee = totalInputValue - totalOutputValue;
    return { valid: true, fee };
  }

  /**
   * Load chain state from database.
   *
   * Startup chainstate reconciliation
   * ---------------------------------
   * After reading the persisted `CHAIN_STATE` record (the single
   * authoritative tip pointer — hotbuns commits the UTXO set and this
   * record in ONE atomic LevelDB batch, so on disk they cannot diverge),
   * we seed the UTXO view's in-memory best-block pointer to match via
   * {@link UTXOManager.reconcileBestBlock}.
   *
   * This is hotbuns' analogue of Bitcoin Core's `Chainstate::LoadChainTip`
   * (validation.cpp:4546): Core makes the in-memory chain tip agree with
   * the coins-view best block on startup.  Pre-fix, hotbuns' `load()`
   * populated `this.bestBlock` but left the `CoinsViewDB.bestBlockHash`
   * at its constructor default (all-zero).  That was *masked* at startup
   * — `coreConnectBlockChecks` treats an all-zero view pointer as the
   * "fresh start" sentinel and skips the `view-out-of-sync` gate — but
   * it meant the gate gave no protection on the first post-restart
   * block, and any later in-memory drift had no startup baseline to be
   * reconciled against.  Seeding it here closes that gap and gives the
   * gate a correct baseline from block 1.
   */
  async load(): Promise<void> {
    const state = await this.db.getChainState();

    if (state) {
      this.bestBlock = {
        hash: state.bestBlockHash,
        height: state.bestHeight,
        chainWork: state.totalWork,
      };
      // Reconcile the UTXO view's in-memory best-block pointer with the
      // persisted chain tip (Core: LoadChainTip).  drifted=true here would
      // indicate the view pointer had a non-genesis stale value at startup
      // (only possible via an in-process code path, since the constructor
      // default is all-zero); we log it for forensic visibility.
      const drifted = await this.utxo.reconcileBestBlock(this.bestBlock.hash);
      if (drifted) {
        console.log(
          `[chainstate] reconciled UTXO view best-block to persisted tip ` +
            `${this.bestBlock.hash.toString("hex")} at height ${this.bestBlock.height}`
        );
      }

      // ── Incomplete-chainstate detection on resume (crash-recovery /
      //    state-integrity class) ──
      //
      // The CHAIN_STATE record is the durable UTXO tip: it is written ONLY in
      // the atomic flush batch alongside the UTXO coins (sync/blocks.ts
      // connectBlock's `shouldFlush` path), so the on-disk UTXO set is complete
      // exactly up to `bestHeight`.  But during deep IBD the ACTIVE-CHAIN
      // height->hash index (DBPrefix.HEADER) is advanced PER-BLOCK
      // (`putBlockHashByHeight`, blocks.ts non-flush path) — ahead of the next
      // periodic flush.  On a CLEAN shutdown `stop()` flushes CHAIN_STATE up to
      // the last connected height, so the height index and CHAIN_STATE agree.
      // On an UNCLEAN shutdown (SIGKILL / OOM / power loss) between the periodic
      // flushes, the height index leads: it describes an active chain up to some
      // height N while the durable UTXO set + CHAIN_STATE only reach
      // `bestHeight` < N.  The dirty in-memory UTXO coins for bestHeight+1..N
      // were never flushed and are gone.
      //
      // Continuing from here runs the node with an active-chain view whose UTXO
      // set is INCOMPLETE: a later block legitimately spending an output that
      // (pre-crash) lived only in the lost cache gets a null `gettxout` and is
      // spuriously rejected with bad-txns-inputs-missingorspent — silent
      // corruption surfacing thousands of blocks later (observed: resume at
      // 250000, spurious reject of valid block 255587).  Note: because the
      // HEADER prefix is written with `writeHeightIndex:false` for non-active
      // headers/forks (see database.ts + headers.ts), an entry ABOVE the durable
      // tip can only be an active-connect leftover from a prior unclean run —
      // never a fork header — so this has no false positive on a clean datadir
      // (where height-index max == bestHeight).
      //
      // Bitcoin Core reconciles the coins-DB best block against the block index
      // on startup (LoadChainTip + ReplayBlocks, validation.cpp:4546/:4773).
      // hotbuns cannot cheaply replay (deep-IBD block bodies are not retained on
      // disk), so we fail CLOSED with a clear, actionable error rather than run
      // with a hole and reject valid blocks later.
      const aheadHash = await this.db.getBlockHashByHeight(this.bestBlock.height + 1);
      if (aheadHash !== null) {
        throw new Error(
          `chainstate incomplete: durable UTXO tip is height ${this.bestBlock.height} ` +
            `(${this.bestBlock.hash.toString("hex")}) but the active-chain height ` +
            `index already contains height ${this.bestBlock.height + 1} ` +
            `(${aheadHash.toString("hex")}). This datadir was shut down UNCLEANLY ` +
            `mid-IBD: the UTXO set for blocks above ${this.bestBlock.height} was ` +
            `never flushed and is lost, so the view has holes. Refusing to run ` +
            `with a corrupt UTXO set (it would spuriously reject valid blocks ` +
            `later). Reindex / re-sync from the last durable tip: stop the node, ` +
            `wipe the datadir, and restart. (chainstate-incomplete, reindex needed)`
        );
      }
    } else {
      // Initialize with genesis block
      const genesisWork = this.calculateWork(this.params.powLimitBits);
      this.bestBlock = {
        hash: this.params.genesisBlockHash,
        height: 0,
        chainWork: genesisWork,
      };

      // Store initial state
      await this.db.putChainState({
        bestBlockHash: this.bestBlock.hash,
        bestHeight: this.bestBlock.height,
        totalWork: this.bestBlock.chainWork,
      });

      // Store genesis block data and index so getblock/getblockheader work at height 0
      const genesisRaw = this.params.genesisBlock;
      await this.db.putBlock(this.params.genesisBlockHash, genesisRaw);
      const genesisBlockParsed = deserializeBlock(new BufferReader(genesisRaw));
      await this.db.putBlockIndex(this.params.genesisBlockHash, {
        height: 0,
        header: serializeBlockHeader(genesisBlockParsed.header),
        nTx: genesisBlockParsed.transactions.length,
        status: BlockStatus.HEADER_VALID | BlockStatus.TXS_VALID | BlockStatus.HAVE_DATA,
        dataPos: 1,
      });
      // Store genesis chain work
      await this.db.putChainWork(this.params.genesisBlockHash, genesisWork);
    }
  }

  /**
   * Calculate the proof-of-work contribution for a block.
   * Work = 2^256 / (target + 1)
   */
  private calculateWork(bits: number): bigint {
    const target = this.compactToBigInt(bits);
    if (target <= 0n) {
      return 0n;
    }
    const TWO_256 = 2n ** 256n;
    return TWO_256 / (target + 1n);
  }

  /**
   * Convert compact difficulty format (nBits) to target value.
   */
  private compactToBigInt(bits: number): bigint {
    const exponent = bits >>> 24;
    const mantissa = bits & 0x7fffff;

    // Handle negative flag (bit 23)
    const isNegative = (bits & 0x800000) !== 0;

    let target: bigint;

    if (exponent <= 3) {
      target = BigInt(mantissa) >> BigInt(8 * (3 - exponent));
    } else {
      target = BigInt(mantissa) << BigInt(8 * (exponent - 3));
    }

    // Return 0 for negative targets (invalid in Bitcoin)
    if (isNegative && target !== 0n) {
      return 0n;
    }

    return target;
  }

  /**
   * Check if a block's prevBlock matches our current tip.
   * Used to detect when a reorganization is needed.
   */
  isNextBlock(header: BlockHeader): boolean {
    return header.prevBlock.equals(this.bestBlock.hash);
  }

  /**
   * Check if we need to reorganize to reach a given block.
   */
  needsReorg(header: BlockHeader): boolean {
    return (
      !header.prevBlock.equals(this.bestBlock.hash) &&
      !getBlockHash(header).equals(this.bestBlock.hash)
    );
  }

  /**
   * Clear the UTXO cache after a batch of operations.
   */
  clearCache(): void {
    this.utxo.clearCache();
  }

  /**
   * Get statistics about the current state.
   */
  getStats(): {
    height: number;
    hash: string;
    chainWork: bigint;
    utxoCacheSize: number;
    pendingOps: number;
    sigCacheSize: number;
  } {
    return {
      height: this.bestBlock.height,
      hash: this.bestBlock.hash.toString("hex"),
      chainWork: this.bestBlock.chainWork,
      utxoCacheSize: this.utxo.getCacheSize(),
      pendingOps: this.utxo.getPendingCount(),
      sigCacheSize: globalSigCache.size,
    };
  }

  /**
   * Get the last (highest) checkpoint height for this network.
   */
  getLastCheckpointHeight(): number {
    return getLastCheckpointHeight(this.params);
  }

  /**
   * Check if we are past all checkpoints.
   * When true, we have validated all checkpoint blocks.
   */
  isPastLastCheckpoint(): boolean {
    const lastCp = this.getLastCheckpointHeight();
    return lastCp < 0 || this.bestBlock.height >= lastCp;
  }

  /**
   * Check if a given height is at or below the last checkpoint.
   * Used to reject forks that attempt to rewrite protected history.
   */
  isProtectedByCheckpoint(height: number): boolean {
    const lastCp = this.getLastCheckpointHeight();
    return lastCp >= 0 && height <= lastCp;
  }

  /**
   * Verify checkpoint for a block at a given height.
   */
  verifyBlockCheckpoint(hash: Buffer, height: number): CheckpointResult {
    return verifyCheckpoint(hash, height, this.params);
  }

  /**
   * Get the consensus parameters.
   */
  getParams(): ConsensusParams {
    return this.params;
  }

  /**
   * Get the database for direct access.
   */
  getDB(): ChainDB {
    return this.db;
  }

  // ========== Chain Management RPCs ==========

  /**
   * Mark a block and all its descendants as invalid.
   *
   * If the block is on the active chain, disconnects blocks back to the fork point.
   * Removes conflicting transactions from the mempool.
   *
   * Reference: Bitcoin Core's Chainstate::InvalidateBlock (validation.cpp)
   *
   * @param blockHash - Hash of the block to invalidate
   * @returns Result indicating success and number of blocks affected
   */
  async invalidateBlock(blockHash: Buffer): Promise<ChainManagementResult> {
    // Check if block exists
    const blockIndex = await this.db.getBlockIndex(blockHash);
    if (!blockIndex) {
      return { success: false, error: "Block not found" };
    }

    // Genesis block cannot be invalidated
    if (blockIndex.height === 0) {
      return { success: false, error: "Cannot invalidate genesis block" };
    }

    // Check if block is protected by checkpoint
    if (this.isProtectedByCheckpoint(blockIndex.height)) {
      return {
        success: false,
        error: `Block at height ${blockIndex.height} is protected by checkpoint`,
      };
    }

    // Check if already marked invalid (FAILED_VALID or FAILED_CHILD)
    if (blockIndex.status & (BlockStatus.FAILED_VALID | BlockStatus.FAILED_CHILD)) {
      return { success: true, blocksAffected: 0 };
    }

    let blocksDisconnected = 0;

    // If this block is on the active chain, disconnect blocks back to it
    const hashHex = blockHash.toString("hex");
    let currentHash = this.bestBlock.hash;
    const blocksToDisconnect: Buffer[] = [];

    // Walk back from tip to find if blockHash is an ancestor
    while (!currentHash.equals(blockHash)) {
      const currentIndex = await this.db.getBlockIndex(currentHash);
      if (!currentIndex || currentIndex.height <= blockIndex.height) {
        // Block is not on our active chain
        break;
      }

      blocksToDisconnect.push(currentHash);

      // Get parent hash from header
      const parentHash = currentIndex.header.subarray(4, 36);
      currentHash = parentHash;
    }

    // If we found it on our chain, disconnect blocks
    if (currentHash.equals(blockHash)) {
      // Also disconnect the invalidated block itself
      blocksToDisconnect.push(blockHash);

      // Disconnect in reverse order (from tip to target)
      for (const hash of blocksToDisconnect) {
        const rawBlock = await this.db.getBlock(hash);
        if (!rawBlock) {
          return {
            success: false,
            error: `Missing block data for ${hash.toString("hex")}`,
          };
        }

        const block = deserializeBlock(new BufferReader(rawBlock));
        const idx = await this.db.getBlockIndex(hash);
        if (!idx) continue;

        await this.disconnectBlock(block, idx.height);
        blocksDisconnected++;

        // Mark the disconnected block as invalid
        await this.db.updateBlockStatus(
          hash,
          idx.status | BlockStatus.FAILED_VALID
        );
      }
    } else {
      // Block is not on our chain, just mark it invalid
      await this.db.updateBlockStatus(
        blockHash,
        blockIndex.status | BlockStatus.FAILED_VALID
      );
    }

    // Mark all descendants as FAILED_CHILD
    await this.markDescendantsInvalid(blockHash, blockIndex.height);

    // Remove conflicting transactions from mempool
    if (this.mempool) {
      // Get all txids in the invalidated block and its descendants
      // This is a simplified version - full implementation would track all descendants
      const rawBlock = await this.db.getBlock(blockHash);
      if (rawBlock) {
        const block = deserializeBlock(new BufferReader(rawBlock));
        for (const tx of block.transactions) {
          const txid = getTxId(tx);
          this.mempool.removeTransaction(txid, true);
        }
      }
    }

    return { success: true, blocksAffected: blocksDisconnected };
  }

  /**
   * Mark descendants of an invalid block as FAILED_CHILD.
   *
   * G17a fix: iterate ALL block index entries (not just the active-chain
   * height→hash mapping) and mark any entry whose ancestor chain contains
   * the invalidated block.  Mirrors Bitcoin Core validation.cpp:3699
   * SetBlockFailureFlags which walks the full block_index by ancestry.
   */
  private async markDescendantsInvalid(
    parentHash: Buffer,
    parentHeight: number
  ): Promise<void> {
    // Collect all entries in a single pass, then propagate FAILED_CHILD in
    // topological order (lower heights before higher).  Using a two-pass
    // approach mirrors Core's SetBlockFailureFlags which also walks the full
    // m_block_index map and checks IsAncestorOf.
    const allEntries: Array<[Buffer, import("../storage/database.js").BlockIndexRecord]> = [];
    for await (const entry of this.db.iterateBlockIndexEntries()) {
      allEntries.push(entry);
    }

    // Sort ascending by height so parents are always processed before children.
    allEntries.sort((a, b) => a[1].height - b[1].height);

    for (const [hash, idx] of allEntries) {
      // Only consider blocks strictly above the invalidated block.
      if (idx.height <= parentHeight) continue;

      // Already marked — nothing to do.
      if (idx.status & BlockStatus.FAILED_CHILD) continue;

      // Check if the direct parent is invalid (FAILED_VALID or FAILED_CHILD).
      // Because we sorted by height, if any ancestor is invalid it will have
      // already been marked by the time we reach this entry.
      const prevBlockHash = idx.header.subarray(4, 36);
      const prevIdx = await this.db.getBlockIndex(prevBlockHash);

      if (prevIdx && (prevIdx.status & (BlockStatus.FAILED_VALID | BlockStatus.FAILED_CHILD))) {
        await this.db.updateBlockStatus(
          hash,
          idx.status | BlockStatus.FAILED_CHILD
        );
        // Update the in-memory copy so subsequent children of this block
        // see the updated status in the same pass.
        idx.status = idx.status | BlockStatus.FAILED_CHILD;
      }
    }
  }

  /**
   * Remove the invalid flag from a block and its ancestors.
   *
   * If the reconsidered chain has more work than the current tip,
   * triggers a reorganization.
   *
   * Reference: Bitcoin Core's Chainstate::ResetBlockFailureFlags (validation.cpp)
   *
   * @param blockHash - Hash of the block to reconsider
   * @returns Result indicating success and number of blocks affected
   */
  async reconsiderBlock(blockHash: Buffer): Promise<ChainManagementResult> {
    // Check if block exists
    const blockIndex = await this.db.getBlockIndex(blockHash);
    if (!blockIndex) {
      return { success: false, error: "Block not found" };
    }

    // Check if actually invalid
    const isInvalid = blockIndex.status & (BlockStatus.FAILED_VALID | BlockStatus.FAILED_CHILD);
    if (!isInvalid) {
      return { success: true, blocksAffected: 0 };
    }

    // Clear invalid flags from this block and all ancestors
    let blocksCleared = 0;
    let currentHash = blockHash;

    while (true) {
      const idx = await this.db.getBlockIndex(currentHash);
      if (!idx) break;

      const wasInvalid = idx.status & (BlockStatus.FAILED_VALID | BlockStatus.FAILED_CHILD);
      if (!wasInvalid) break;

      // Clear both flags
      const newStatus =
        idx.status & ~(BlockStatus.FAILED_VALID | BlockStatus.FAILED_CHILD);
      await this.db.updateBlockStatus(currentHash, newStatus);
      blocksCleared++;

      // Move to parent
      const parentHash = idx.header.subarray(4, 36);
      if (idx.height === 0) break;
      currentHash = parentHash;
    }

    // Also clear flags from descendants of the reconsidered block
    await this.clearDescendantInvalidFlags(blockHash, blockIndex.height);

    // Check if we need to reorganize
    // The reconsidered chain might now have more work than our current tip
    // A full implementation would recalculate chainwork and potentially reorg.
    // For now, return success and let the header sync handle reorg if needed.

    return { success: true, blocksAffected: blocksCleared };
  }

  /**
   * Clear FAILED_CHILD flags from descendants of a reconsidered block.
   *
   * G20 fix: iterate ALL block index entries (not just the active-chain
   * height→hash mapping) and clear FAILED_CHILD on any entry whose parent
   * is now valid.  Mirrors Bitcoin Core validation.cpp::ResetBlockFailureFlags
   * which walks the full block_index and clears flags on all descendants.
   */
  private async clearDescendantInvalidFlags(
    parentHash: Buffer,
    parentHeight: number
  ): Promise<void> {
    // Collect all entries and sort ascending by height so parents are
    // always processed before children.  This ensures that when we clear
    // a FAILED_CHILD flag, the subsequent children of that block see the
    // cleared status in the same pass.
    const allEntries: Array<[Buffer, import("../storage/database.js").BlockIndexRecord]> = [];
    for await (const entry of this.db.iterateBlockIndexEntries()) {
      allEntries.push(entry);
    }

    allEntries.sort((a, b) => a[1].height - b[1].height);

    for (const [hash, idx] of allEntries) {
      // Only consider blocks strictly above the reconsidered block.
      if (idx.height <= parentHeight) continue;

      // Only need to process entries that have FAILED_CHILD set.
      if (!(idx.status & BlockStatus.FAILED_CHILD)) continue;

      // Check if the direct parent is now valid.
      const prevBlockHash = idx.header.subarray(4, 36);
      const prevIdx = await this.db.getBlockIndex(prevBlockHash);

      const parentStillInvalid =
        prevIdx &&
        (prevIdx.status & (BlockStatus.FAILED_VALID | BlockStatus.FAILED_CHILD));

      if (!parentStillInvalid) {
        const newStatus = idx.status & ~BlockStatus.FAILED_CHILD;
        await this.db.updateBlockStatus(hash, newStatus);
        // Update in-memory copy so subsequent children of this block see
        // the cleared status in the same pass.
        idx.status = newStatus;
      }
    }
  }

  /**
   * Mark a block as "precious" for tie-breaking in chain selection.
   *
   * When multiple chains have equal work, the precious block's chain
   * is preferred. This is a tie-breaker, not a fork override.
   *
   * Reference: Bitcoin Core's Chainstate::PreciousBlock (validation.cpp)
   *
   * @param blockHash - Hash of the block to mark as precious
   * @returns Result indicating success
   */
  async preciousBlock(blockHash: Buffer): Promise<ChainManagementResult> {
    // Check if block exists
    const blockIndex = await this.db.getBlockIndex(blockHash);
    if (!blockIndex) {
      return { success: false, error: "Block not found" };
    }

    // Cannot make an invalid block precious
    if (blockIndex.status & (BlockStatus.FAILED_VALID | BlockStatus.FAILED_CHILD)) {
      return { success: false, error: "Cannot mark invalid block as precious" };
    }

    // Calculate chain work for this block
    // Note: Full implementation would need to track chainwork per block
    const headerWork = this.calculateWork(
      blockIndex.header.readUInt32LE(72) // bits field offset in header
    );

    // If the chain has been extended since last precious call, reset
    if (this.bestBlock.chainWork > this.lastPreciousChainwork) {
      this.blockSequenceId = -1;
    }
    this.lastPreciousChainwork = this.bestBlock.chainWork;

    // Set this block as precious with negative sequence ID
    // Lower sequence ID = higher priority in tie-breaking
    this.preciousBlockHash = blockHash;
    this.blockSequenceId--;

    // If this block has equal or more work than our tip, we might want to switch
    // For simplicity, we don't force a reorg here - that would require
    // full chainwork calculation. Return success and let normal chain
    // selection pick up the preference.

    return { success: true, blocksAffected: 0 };
  }

  /**
   * Check if a block is marked as invalid.
   */
  async isBlockInvalid(blockHash: Buffer): Promise<boolean> {
    const idx = await this.db.getBlockIndex(blockHash);
    if (!idx) return false;
    return !!(idx.status & (BlockStatus.FAILED_VALID | BlockStatus.FAILED_CHILD));
  }

  /**
   * Check if a block is marked as precious.
   */
  isPreciousBlock(blockHash: Buffer): boolean {
    return this.preciousBlockHash !== null && this.preciousBlockHash.equals(blockHash);
  }

  /**
   * Get the precious block hash, if any.
   */
  getPreciousBlock(): Buffer | null {
    return this.preciousBlockHash;
  }
}
