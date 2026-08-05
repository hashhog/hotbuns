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
import type { Peer } from "../p2p/peer.js";
import type { PeerManager } from "../p2p/manager.js";
import type { NetworkMessage, InvVector } from "../p2p/messages.js";
import { InvType } from "../p2p/messages.js";
import { BanScores } from "../p2p/manager.js";
import { HeaderSync, type HeaderChainEntry } from "./headers.js";
import type { ChainStateManager } from "../chain/state.js";
import type { Mempool } from "../mempool/mempool.js";
import {
  Block,
  deserializeBlock,
  getBlockHash,
  serializeBlock,
  serializeBlockHeader,
  validateBlock,
} from "../validation/block.js";
import { isCoinbase } from "../validation/tx.js";
import type { Transaction } from "../validation/tx.js";
import { BufferReader, BufferWriter } from "../wire/serialization.js";
import { UTXOManager } from "../chain/utxo.js";
import {
  shouldSkipScripts,
  type AssumeValidContext,
} from "../consensus/assumevalid.js";
import { coreConnectBlockChecks } from "../consensus/connect_block.js";
import {
  MAX_CMPCTBLOCK_DEPTH,
  MAX_BLOCKTXN_DEPTH,
} from "../p2p/compact_blocks.js";

/**
 * Classify a connect-block error string into one of three buckets so the
 * bounded-retry banner can name the right failure class.
 *
 * Pre-2026-05 the FATAL banner unconditionally claimed "Permanent UTXO
 * corruption" regardless of why connectBlock failed. That was correct for
 * genuine half-flushed-UTXO wedges (e.g. the Apr 28 lunarblock EMFILE event)
 * but actively misleading for consensus-rule mismatches: the May tapscript
 * MAX_OPS_PER_SCRIPT failure at height 944,279 fired the same chainstate-
 * corruption banner and burned operator time chasing a chainstate ghost when
 * the real fix was a script.ts rule.
 *
 *   "consensus"  — script / tx-validation rule mismatch with Bitcoin Core.
 *                  Operator action: file a bug, do NOT wipe the datadir.
 *   "chainstate" — block body / undo data missing on disk; the chain tip
 *                  advanced past data that never persisted. Operator action:
 *                  wipe and re-sync (or restore from a snapshot).
 *   "unknown"    — couldn't classify; emit a neutral banner with the raw
 *                  error string and let the operator triage.
 *
 * "Missing UTXO" classification: per the lunarblock 944,186 evidence and
 * d9d9af4 commit, this is classified as a *consensus-failure* secondary
 * effect. A script-rule failure mid-block can leave the in-memory cache
 * half-applied; the next attempt then reports "Missing UTXO" as a downstream
 * symptom of the original consensus failure. If we ever observe a Missing-
 * UTXO without a preceding script-rule failure in the same block, the
 * classification needs revisiting.
 */
export function classifyCallbackError(
  err: unknown
): "consensus" | "chainstate" | "unknown" {
  if (err === null || err === undefined) return "unknown";
  const raw = err instanceof Error ? err.message : String(err);
  if (raw.length === 0) return "unknown";
  const s = raw.toLowerCase();

  // Consensus / script / tx-validation rule failures. Deterministic
  // mismatches with Core's rules → bug in script.ts / tx.ts / block.ts,
  // NOT a corrupt chainstate.
  const consensusPatterns = [
    "tapscript execution failed",
    "tapscript",
    "script number too long",
    "script_size",
    "max_ops",
    "invalid signature",
    "script verification failed",
    "p2wpkh script verification failed",
    "p2wsh script verification failed",
    "taproot key-path signature verification failed",
    "taproot verify returned false",
    "parallel signature verification failed",
    "merkle root mismatch",
    "witness commitment mismatch",
    "duplicate input",
    "coinbase scriptsig",
    "exceeds max_money",
    "negative value",
    "transaction has no inputs",
    "transaction has no outputs",
    "missing utxo", // secondary effect of script failure (see comment above)
    "bip34 requires height",
    "bad-txns",
    "bad-blk",
    "bad-cb-amount",
    "pays too much",
    "non-final",
    "bad sigops",
    "sigops cost",
    "coinbase value",
    "immature coinbase",
    "sequence locks not satisfied",
    "does not match expected header",
  ];
  for (const pat of consensusPatterns) {
    if (s.includes(pat)) return "consensus";
  }

  // Genuine chainstate / on-disk corruption. The persisted chain tip has
  // advanced past blocks whose body or undo data is missing. Operator
  // should wipe + re-sync.
  const chainstatePatterns = [
    "block_in_storage=no",
    "header_in_mem=true",
    "undo data missing",
    "missing undo",
    "failed to find block in chainstate",
    "chain_tip pointing at",
    "block body is missing",
    "lost in hard crash",
    "level_database_not_open",
    "leveldb: not found",
  ];
  for (const pat of chainstatePatterns) {
    if (s.includes(pat)) return "chainstate";
  }

  return "unknown";
}

/**
 * Map a connectBlock error string to a canonical BIP-22 result token.
 * Returns the most specific BIP-22 string possible, or "rejected" as fallback.
 * Reference: Bitcoin Core BIP22ValidationResult() in src/rpc/mining.cpp.
 */
function bip22FromConnectError(err: string): string {
  const s = err.toLowerCase();
  // IsFinalTx (nLockTime) and BIP-68 SequenceLocks failures both map to
  // "bad-txns-nonfinal" per Core validation.cpp:2558 + :4147.
  if (s.includes("non-final") || s.includes("nonfinal") || s.includes("bad-txns-nonfinal") ||
      s.includes("sequence locks not satisfied") || s.includes("sequence lock"))
    return "bad-txns-nonfinal";
  if (s.includes("missing") && s.includes("utxo")) return "bad-txns-inputs-missingorspent";
  if (s.includes("missing utxo") || s.includes("inputs-missingorspent"))
    return "bad-txns-inputs-missingorspent";
  if (s.includes("coinbase") && s.includes("immature")) return "bad-txns-premature-spend-of-coinbase";
  // Non-coinbase tx where sum(inputs) < sum(outputs).
  // Core consensus/tx_verify.cpp::CheckTxInputs "bad-txns-in-belowout".
  // connect_block.ts emits "...outputs exceed inputs...(bad-txns-in-belowout)".
  if (s.includes("bad-txns-in-belowout") || s.includes("outputs exceed inputs")) return "bad-txns-in-belowout";
  // W93: emit canonical token directly when the error string is already
  // prefixed "bad-cb-amount:" (coreConnectBlockChecks now emits this).
  if (s.includes("bad-cb-amount") ||
      ((s.includes("coinbase value") || s.includes("coinbase output")) && s.includes("exceeds")) ||
      (s.includes("coinbase") && s.includes("pays too much"))) return "bad-cb-amount";
  // W93: accumulated fee out-of-range is its own canonical token.
  if (s.includes("accumulated-fee-outofrange")) return "bad-txns-accumulated-fee-outofrange";
  if (s.includes("bad-blk-sigops") || s.includes("sigops")) return "bad-blk-sigops";
  // BIP-30 duplicate-txid overwrite: connect_block emits
  // "bad-txns-BIP30: tried to overwrite transaction ...". Core
  // (validation.cpp:2471) rejects with "bad-txns-BIP30"; surface the exact
  // token instead of collapsing to the generic "rejected" fallback. Placed
  // before the merkle/script catch-alls so the specific token wins.
  if (s.includes("bad-txns-bip30") || s.includes("overwrite transaction")) return "bad-txns-BIP30";
  if (s.includes("merkle")) return "bad-txnmrklroot";
  if (s.includes("witness commitment")) return "bad-witness-merkle-match";
  if (s.includes("coinbase scriptsig") || s.includes("bad-cb-length")) return "bad-cb-length";
  if (s.includes("bip34") || s.includes("bad-cb-height")) return "bad-cb-height";
  if (s.includes("high-hash") || s.includes("proof of work")) return "high-hash";
  // Connect-block script verification failures.
  // Bitcoin Core validation.cpp:2122 uses "block-script-verify-flag-failed (%s)".
  if (s.includes("script") || s.includes("checksig") || s.includes("tapscript") ||
      s.includes("witness program") || s.includes("script verify") || s.includes("block-script-verify")) {
    return "block-script-verify-flag-failed";
  }
  return "rejected";
}

/** Maximum blocks in-flight at once (across all peers). */
const DEFAULT_WINDOW_SIZE = 512;

/** Flush UTXO cache to disk every N blocks during IBD. */
const FLUSH_INTERVAL = 2000;

/** Maximum blocks in-flight per peer.
 *
 *  Lowered from 16 → 4 on 2026-05-27 to fix the IBD pace cap observed at
 *  ~0.4 blk/min (mainnet h=76133 stuck 5 min, h=76134 stuck 1 min, etc.).
 *
 *  Root cause: Bitcoin Core serves blocks SERIALLY (one block per
 *  ProcessGetData call).  With 16 blocks queued at a peer, each block waits
 *  ~5-30 s behind the head of the queue.  For the *critical* block (the one
 *  at nextHeightToProcess), this serial delay STALLS the entire pipeline —
 *  no other block can be processed until the critical one arrives, and the
 *  DUP-REQ fallback only fires every ~30 s.
 *
 *  Worse, while a peer is busy serving its 16-block queue, its
 *  `lastResponse` stays old (> 120 s often), so the DUP-REQ peer-eligibility
 *  filter (`lastResponse > 0 && (now - lastResponse) < 120000`) excludes it
 *  as a duplicate target.  Most peers being saturated → DUP-REQ logs
 *  "sent to 0 extra peers" silently → only one peer is actually racing.
 *
 *  Setting the cap to 4 keeps peers cycling responses every ~1-5 s, which:
 *    1. Keeps `lastResponse` recent across the fleet so DUP-REQ has more
 *       eligible duplicate targets.
 *    2. Bounds the head-of-line blocking on the critical block to at most
 *       ~4 sequential serves (≈ 4-20 s) instead of 16 (≈ 16-80 s).
 *    3. Bitcoin Core itself uses MAX_BLOCKS_IN_TRANSIT_PER_PEER = 16, but
 *       Core also uses parallel script verification + a much shorter
 *       per-block serve loop.  Hotbuns' Bun-JS script verify is slower
 *       than Core's libsecp256k1 batch, so the queue clears slower per peer.
 */
const MAX_IN_FLIGHT_PER_PEER = 4;

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

/** Minimum interval (milliseconds) between forced getheaders re-polls once the
 *  block frontier has drained every known header. See the "header-sync idle
 *  catch-all" in handleStalled(). Keeps a truly-at-tip node from spamming
 *  getheaders while still recovering a wedged header sync within a few
 *  seconds. */
const HEADER_DRAIN_POLL_MS = 5000;

/** Maximum items per getdata message.
 *  Mirrors Bitcoin Core net_processing.cpp:128 MAX_GETDATA_SZ = 1000.
 *  Using the INV cap (50000) here caused 50× bandwidth amplification on
 *  inv→getdata fan-out. */
const MAX_GETDATA_ITEMS = 1000;

/** How long a tx-request in-flight marker is honored before we allow a
 *  re-request from another announcing peer. Roughly Core's GETDATA_TX_INTERVAL
 *  (60s) — long enough that a serving peer has time to deliver, short enough
 *  that a dropped/never-served tx can be re-fetched from someone else. */
const TX_REQUEST_EXPIRY_MS = 60_000;

/** FIFO bound on {@link BlockSync.recentlyRejectedTxs}.
 *  Core sizes m_lazy_recent_rejects at 120_000 entries
 *  (txdownloadman_impl.h:68); ours is an exact Set rather than a rolling
 *  bloom filter, so we keep a tighter bound to cap memory. */
const MAX_RECENT_REJECTED_TXS = 10_000;

/** FIFO bound on {@link BlockSync.recentlyConfirmedTxs}. Core's
 *  RecentConfirmedTransactionsFilter is a 48_000-entry rolling bloom
 *  (txdownloadman_impl.h:125); we hold both txid and wtxid hex per tx, so
 *  48_000 keys is roughly 24_000 transactions — about two mainnet blocks. */
const MAX_RECENT_CONFIRMED_TXS = 48_000;

/** Minimum interval between unconditional expiry sweeps of
 *  {@link BlockSync.requestedTxInFlight}. The sweep is driven from the
 *  existing 1s stall tick, not a new timer. */
const TX_INFLIGHT_SWEEP_INTERVAL_MS = 5_000;

/** Hard ceiling on {@link BlockSync.requestedTxInFlight}. The time-based
 *  sweep is the primary bound; this is the backstop for the case where the
 *  event loop is starved and the 1s tick does not run — an inv storm must
 *  never be able to grow the map without limit. Sized well above the
 *  steady-state working set (Core caps announcements per peer at
 *  MAX_PEER_TX_ANNOUNCEMENTS = 5000). */
const MAX_TX_INFLIGHT = 50_000;

/** Maximum downloaded blocks buffered in memory before throttling requests.
 *  At mainnet heights (500K+), blocks average 2-4MB serialized but expand to
 *  10-20MB as JS objects (transactions, witnesses, Buffers).  32 blocks keeps
 *  ~320-640MB in the heap — manageable under a 4GB RSS cap.  Early small blocks
 *  are processed fast enough that a larger buffer isn't needed. */
const MAX_DOWNLOADED_BUFFER = 32;

/**
 * Mirror of Bitcoin Core's MIN_BLOCKS_TO_KEEP (validation.cpp).
 * Unrequested blocks further than this many heights ahead of the active
 * tip are silently ignored — they cannot contribute to chain selection
 * in the near future and could be used for memory exhaustion by a peer.
 * Core: `if (fTooFarAhead) return true;` (validation.cpp:4325).
 */
const MIN_BLOCKS_TO_KEEP = 288;

/**
 * Maximum depth (number of blocks below the active validated tip) the
 * fork-aware block-download descent will walk to find the fork point and
 * lower the download floor.  The descent bound is now supplied per-call by
 * `reorgDepthCap()` (UNBOUNDED on an archive node — Core-parity, follows the
 * most-work chain to the fork point at any depth — and MIN_BLOCKS_TO_KEEP on a
 * pruned node, matching `handleReorgUtxoAndCollect`).  This module constant is
 * retained only as the pruned-node value surfaced in the diagnostic log below.
 * (Bitcoin Core has no fixed reorg-depth cap; 288 = MIN_BLOCKS_TO_KEEP, the
 * pruned-node undo-retention floor.)
 */
const MAX_FORK_DOWNLOAD_DEPTH = 288;

/** How often (in connected blocks) to ask the prune manager whether files
 *  should be pruned.  Bitcoin Core checks during chainstate flushes; hotbuns
 *  flushes every FLUSH_INTERVAL (2000) blocks during IBD, but we run the
 *  prune scan a bit more often near the tip so disk usage doesn't drift far
 *  past target.  100 is small enough to bound overshoot and large enough that
 *  the O(file_count) iteration is rare. */
const PRUNE_CHECK_INTERVAL = 100;

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

  /** Last time we force-polled peers for more headers after draining the
   *  known-header frontier. See the "header-sync idle catch-all" in
   *  handleStalled(). Rate-limits the forced getheaders. */
  private lastHeaderDrainPoll: number = 0;

  /** Timestamp when sync started. */
  private startTime: number;

  /** Blocks processed since start. */
  private blocksProcessed: number;

  /** Whether IBD is complete. */
  private ibdComplete: boolean;
  // One-way latch: set true the FIRST time initial IBD completes, NEVER flipped
  // back. ibdComplete is transiently set false again when a heavier competing
  // fork is discovered (so requestBlocks re-enters the download path), which
  // would wrongly gate the reorg-drop fork-body storage; this latch records
  // "the node has synced at least once" so maybeStoreForkBody fires for a
  // competing fork at an established tip but NOT during genuine initial IBD.
  private hasCompletedInitialSync: boolean = false;

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

  /** Most recent connectBlock failure message — captured by every warn/error
   *  site that returns false. Read by the bounded-retry banner so it can
   *  classify the failure as consensus vs chainstate vs unknown. */
  private lastConnectError: string;

  /** Reorg-atomicity signal (Core ActivateBestChainStep parity). When a
   *  reorg-tip connect FAILS after the competing chain was partially connected
   *  in-memory (old chain disconnected, B1/B2 reconnected), `connectBlock`
   *  atomically restores the ORIGINAL active-chain tip via
   *  `utxoManager.clearCache(oldTip)` and records that original tip hash here.
   *  The caller's generic failure-cleanup (`processOrderedBlocks`) reads this to
   *  SKIP its own `clearCache(getHeaderByHeight(lastFlushed))` — which, mid-reorg,
   *  would re-point the UTXO view at the COMPETING branch (the best-header chain's
   *  height entry is the losing fork B2, not the active-chain tip A2) and settle
   *  the node on the wrong branch. Set on a reorg-abort restore, consumed + reset
   *  by the caller. Null when the last connect performed no reorg-abort. */
  private reorgAbortRestoredTip: Buffer | null;

  /** Reorg-deferral signal (Core AcceptBlock/ActivateBestChain parity). A
   *  heavier competing fork tip (e.g. B105) can reach `connectBlock` BEFORE its
   *  bridging bodies (fork+1 .. old active tip = B102..B104) have been persisted
   *  to disk as side branches — they are still in flight / being stored on the
   *  P2P path. The reorg dispatch cannot rebuild the UTXO view from the fork
   *  point without those bodies. This is a TRANSIENT ordering condition, NOT a
   *  validation failure: Core's AcceptBlock stores the block and ActivateBestChain
   *  simply waits until every block on the most-work path has BLOCK_HAVE_DATA
   *  before connecting it — it never rejects the block or punishes the peer.
   *  When `handleReorgUtxoAndCollect` detects a missing bridging body it sets this
   *  flag and returns WITHOUT mutating the view; `connectBlock` then aborts the
   *  connect cleanly (no view mutation, no consensus error) and the caller
   *  (`processOrderedBlocksInner`) keeps the fork-tip block buffered, re-requests
   *  the missing bodies, and NEVER bans the peer. Consumed + reset by the caller. */
  private reorgDeferredMissingBodies: boolean = false;

  /** Reorg-to-ancestor HALT signal (crash-recovery / reorg-integrity class).
   *  Set by {@link haltSync} when the sync loop detects an IMPOSSIBLE reorg —
   *  the block it keeps being asked to (re)connect at `nextHeightToProcess` is
   *  already an ANCESTOR of the active validated tip (no reorg is possible / the
   *  target is already connected), so every retry re-trips the `view-out-of-sync`
   *  gate forever. Without this, the loop rewinds to `lastFlushedHeight+1` and
   *  spins at 100% CPU re-requesting + re-serving the same block indefinitely
   *  (observed 174k+ retries after a spurious header invalidation on the modern
   *  replay). When set, `requestBlocks`/`processOrderedBlocks` early-return so the
   *  node stops spinning and hard-fails loudly (RPC stays up for triage). Non-null
   *  value is the human-readable halt reason. */
  private syncHalted: string | null = null;

  /** GAP3 fix (reorg-drop part 2/2): hashHex of competing-fork ("side-branch")
   *  bodies BELOW the active frontier that we have already persisted to disk via
   *  `maybeStoreForkBody`. The request loop consults this set so an evicted-but-
   *  on-disk bridging body is not endlessly re-requested while we wait for the
   *  fork tip to arrive and drive the reorg. Cleared whenever the frontier rolls
   *  back (the bodies may need re-evaluation) and pruned as entries are connected
   *  on the active chain. Bounded by MAX_FORK_DOWNLOAD_DEPTH-worth of bridging
   *  bodies per fork. */
  private forkBodiesOnDisk: Set<string> = new Set();

  /**
   * Tracks which peer (peerKey = "host:port") delivered each downloaded block.
   * Keyed by the same hashHex used in state.downloadedBlocks.  Absent for
   * blocks injected via submitblock (no peer source).  Used by
   * processOrderedBlocksInner to call peer.misbehaving(100) on BLOCK_MUTATED
   * (connectBlock() returns false) — G16 fix.
   */
  private downloadedBlockPeers: Map<string, string>;

  /** Chain state manager — updated after each connected block so RPC
   *  methods like getblockcount reflect the latest chain tip. */
  private chainStateManager: ChainStateManager | null;

  /** Mempool — used to refill transactions disconnected by a chain reorg
   *  (Pattern B, mempool-refill-on-reorg / Bitcoin Core's
   *  MaybeUpdateMempoolForReorg).  Wired via setMempool() from cli.ts.
   *  Reference: camlcoin lib/sync.ml:2354-2363 (canonical shape:
   *  add_transaction per disconnected non-coinbase tx after disconnect
   *  loop completes).  Cross-impl audit:
   *  CORE-PARITY-AUDIT/_mempool-refill-on-reorg-fleet-result-2026-05-05.md. */
  private mempool: Mempool | null = null;

  /**
   * Transaction-request dedup map (classic inv→getdata relay, W-txrelay).
   * Keyed by the inv hash hex we requested (txid for MSG_TX, wtxid for
   * MSG_WTX) → wall-clock ms of the request. When multiple peers announce
   * the same tx we only `getdata` it once until the entry expires
   * (TX_REQUEST_EXPIRY_MS) — mirrors the effect of Bitcoin Core's
   * TxRequestTracker in-flight bookkeeping (net_processing.cpp
   * m_txdownloadman.AddTxAnnouncement), collapsed to a single-attempt
   * time-boxed dedup since hotbuns has no per-peer request scheduler.
   * Entries are opportunistically pruned in {@link isTxRequestInFlight}.
   */
  private requestedTxInFlight: Map<string, number> = new Map();

  /**
   * Small bounded set of inv-hash hex (txid/wtxid) we recently declined to
   * request because we already saw them rejected. hotbuns has no global
   * recent-rejects filter (Core's m_recent_rejects); this is a best-effort
   * local guard so a rejected-tx re-announce storm doesn't cause repeated
   * getdata churn. Populated via {@link markTxRejected}; bounded FIFO.
   */
  private recentlyRejectedTxs: Set<string> = new Set();

  /**
   * Bounded set of inv-hash hex (BOTH txid and wtxid) for transactions we saw
   * confirmed in a recently connected block. Mirrors Bitcoin Core's
   * RecentConfirmedTransactionsFilter (txdownloadman_impl.h:122-127): once a
   * tx is mined it leaves the mempool, so without this filter every peer that
   * re-announces it makes us issue a fresh getdata and re-run
   * acceptToMemoryPool only to reject it. Populated by
   * {@link markTxsConfirmed}, reset by {@link onBlockDisconnected} (Core
   * resets on reorg for exactly the same reason — see
   * TxDownloadManagerImpl::BlockDisconnected).
   */
  private recentlyConfirmedTxs: Set<string> = new Set();

  /** Wall-clock ms of the last unconditional {@link sweepTxRequestsInFlight}. */
  private lastTxInFlightSweep: number = 0;

  /** Orphan pool — wired via {@link setOrphanPool} from cli.ts. Consulted by
   *  {@link alreadyHaveTx} so a tx already parked in the orphanage is neither
   *  re-requested nor re-validated. Core does the same inside AlreadyHaveTx
   *  (txdownloadman_impl.cpp:139, `m_orphanage->HaveTx`). */
  private orphanPool: import("../mempool/orphan_pool.js").OrphanPool | null = null;

  /** Prune manager — wired via setPruneManager() from cli.ts when the
   *  operator passes `--prune=N`.  After every successful connectBlock,
   *  we call `pruneManager.maybePrune(height)` which is a no-op outside
   *  automatic-prune mode (manual mode `--prune=1` only triggers via the
   *  `pruneblockchain` RPC).  Mirrors Bitcoin Core's
   *  `validation.cpp::ConnectTip` → `m_blockman.FindFilesToPrune` call. */
  private pruneManager: import("../storage/pruning.js").PruneManager | null = null;

  /** Throttle counter for auto-prune scans.  Auto-prune iterates over all
   *  block-file-info records to compute current usage, which is O(file_count)
   *  — cheap, but pointless to run on every single connected block during
   *  IBD.  We scan once per `PRUNE_CHECK_INTERVAL` blocks, matching Core's
   *  per-flush cadence (it checks during chainstate flushes, ~every 100
   *  blocks during IBD). */
  private blocksSincePruneCheck: number = 0;

  /** Optional BIP-157/158 compact-block-filter index. Wired via
   *  `setBlockFilterIndex()` from cli.ts when `--blockfilterindex=1`.
   *  When set, every successful new-tip block connect calls
   *  `filterIndex.indexBlock(...)` so the filter + filter-header chain
   *  stays in lockstep with the chain.  Mirrors Bitcoin Core's
   *  `BlockFilterIndex::CustomAppend` (src/index/blockfilterindex.cpp),
   *  which the BaseIndex worker invokes per `BlockConnected` notification.
   *
   *  Surface: REST `/rest/blockfilter/<filtertype>/<hash>` and
   *  `/rest/blockfilterheaders/<filtertype>/<count>/<hash>` (rest.ts).
   *  Reference: BIP-157, BIP-158. */
  private filterIndex: import("../storage/indexes.js").BlockFilterIndex | null = null;

  /**
   * Persistent, reorg-safe coinstatsindex (Bitcoin Core -coinstatsindex
   * parity). Present (non-null) only when the operator passed
   * `--coinstatsindex=1`; cli.ts constructs it and wires it via
   * `setCoinStatsIndex()`. Every successful `connectBlock` calls
   * `coinStatsIndex.indexBlock(block, height, spentOutputs)` so the per-height
   * UTXO MuHash3072 + counts snapshot is maintained on the PRIMARY block
   * connect path — the same path that maintains txindex / blockfilterindex,
   * NOT only the submitblock RPC path. The reorg disconnect side rewinds it in
   * `disconnectBlockUtxo`. Reference:
   * bitcoin-core/src/index/coinstatsindex.cpp::CustomAppend / CustomRewind.
   */
  private coinStatsIndex: import("../storage/indexes.js").PersistentCoinStatsIndex | null = null;

  /**
   * Optional txospenderindex (Bitcoin Core -txospenderindex parity). Present
   * (non-null) only when the operator passed `--txospenderindex=1`; cli.ts
   * constructs it and wires it via `setTxoSpenderIndex()`. Every successful
   * `connectBlock` calls `txoSpenderIndex.indexBlock(block, height)` so the
   * spent-outpoint -> spending-tx mapping is maintained on the PRIMARY connect
   * path (P2P/IBD + submitblock) — the same path that maintains txindex /
   * blockfilterindex / coinstatsindex. The LIVE reorg disconnect side rewinds it
   * in `disconnectBlockUtxo`. Reference:
   * bitcoin-core/src/index/txospenderindex.cpp::CustomAppend / CustomRemove.
   */
  private txoSpenderIndex: import("../storage/indexes.js").TxoSpenderIndex | null = null;

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
    this.lastConnectError = "";
    this.reorgAbortRestoredTip = null;
    this.downloadedBlockPeers = new Map();

    this.state = {
      pendingBlocks: new Map(),
      downloadedBlocks: new Map(),
      nextHeightToProcess: 1, // Genesis is already validated
      nextHeightToRequest: 1,
    };
  }

  /**
   * Wire the mempool reference used for refill-on-reorg.  Optional:
   * when not set, the connect path runs the same as before (no refill).
   * Mirrors Mempool.readdTransactions behavior — coinbases are skipped
   * and re-add failures are tolerated (txs that conflict against the
   * new-chain UTXO are dropped silently, matching Core's
   * MaybeUpdateMempoolForReorg semantics).  See Pattern B audit.
   */
  setMempool(mempool: Mempool): void {
    this.mempool = mempool;
  }

  /**
   * Wire the orphan pool so {@link alreadyHaveTx} can consult it.
   *
   * Core checks the orphanage first inside AlreadyHaveTx
   * (txdownloadman_impl.cpp:139). Without it, a tx parked in our orphanage
   * awaiting its parent is re-requested from every peer that announces it and
   * re-run through acceptToMemoryPool on every delivery, only to be
   * missing-inputs-rejected and dropped as a duplicate orphan add.
   */
  setOrphanPool(orphanPool: import("../mempool/orphan_pool.js").OrphanPool): void {
    this.orphanPool = orphanPool;
  }

  /**
   * Wire the prune manager.
   *
   * When the operator passes `--prune=N` (N≥550 MiB or N=1 manual mode),
   * cli.ts constructs a PruneManager and registers it here so we can call
   * `maybePrune(height)` after every successful connectBlock.
   *
   * Mirrors Bitcoin Core's `m_blockman.FindFilesToPrune` invocation in
   * `validation.cpp::FlushStateToDisk` (called from `ConnectTip`).
   *
   * No-op outside automatic-prune mode: in manual mode (`-prune=1`) the
   * scan is gated on `pruneManager.isAutomaticPruning()` inside
   * `findFilesToPrune`, and the manual `pruneblockchain` RPC handles its
   * own dispatch via `pruneManager.pruneBlockchain(targetHeight, ...)`.
   */
  setPruneManager(pruneManager: import("../storage/pruning.js").PruneManager): void {
    this.pruneManager = pruneManager;
  }

  /**
   * Core-parity reorg / fork-download depth bound.
   *
   * Bitcoin Core has NO reorg-depth cap: `ActivateBestChainStep`
   * (validation.cpp) follows the most-work valid chain back to the fork point
   * at ANY depth. `MIN_BLOCKS_TO_KEEP = 288` is a PRUNING-only undo-retention
   * floor, NOT a consensus reorg cap — capping reorgs at 288 on an archive node
   * is a Class-A consensus divergence (the node would refuse a >288 reorg to a
   * higher-work valid chain and stay on the losing minority branch = chain
   * split). So the bound is gated on pruning:
   *
   *   • archive node (no `--prune`, undo data always on disk) → UNBOUNDED,
   *     matching Core. Peak memory is still bounded by `MAX_REORG_BATCH_OPS`
   *     in `handleReorgUtxoAndCollect`, which aborts the dispatch cleanly on
   *     overflow (caller falls back to the legacy in-place connect) — the same
   *     fail-safe as missing undo data, never a silent wrong-chain settle.
   *
   *   • pruned node (`--prune=N`) → retain the `MIN_BLOCKS_TO_KEEP` (288)
   *     window: a reorg deeper than the retained undo cannot be serviced (the
   *     block/undo bodies have been deleted), so the walk is bounded and the
   *     reorg naturally aborts when the first missing body is hit
   *     (`db.getBlock` → null / `disconnectBlockUtxo` → false), which surfaces
   *     as the loud UTXO-divergence log + legacy-connect fallback. This mirrors
   *     Core's model where a pruned too-deep reorg is a physical failure, not a
   *     policy cap.
   */
  private reorgDepthCap(): number {
    return this.pruneManager?.isPruneMode()
      ? MIN_BLOCKS_TO_KEEP
      : Number.MAX_SAFE_INTEGER;
  }

  /**
   * Wire the BIP-157/158 compact-block-filter index.
   *
   * When the operator passes `--blockfilterindex=1`, cli.ts constructs a
   * `BlockFilterIndex` and registers it here. Every successful
   * `connectBlock` calls `filterIndex.indexBlock(block, height,
   * spentOutputs)` after the block is persisted so the filter +
   * filter-header chain advances in lockstep with the chain tip.
   *
   * No-op when not wired (default off, matches Bitcoin Core's
   * `DEFAULT_BLOCKFILTERINDEX = false`).
   *
   * Reference: bitcoin-core/src/index/blockfilterindex.cpp::CustomAppend.
   */
  setBlockFilterIndex(
    filterIndex: import("../storage/indexes.js").BlockFilterIndex
  ): void {
    this.filterIndex = filterIndex;
  }

  /**
   * Wire the persistent, reorg-safe coinstatsindex.
   *
   * When the operator passes `--coinstatsindex=1`, cli.ts constructs a
   * `PersistentCoinStatsIndex` and registers it here. Every successful
   * `connectBlock` calls `coinStatsIndex.indexBlock(block, height,
   * spentOutputs)` so the per-height UTXO MuHash3072 + counts snapshot is
   * maintained on the PRIMARY connect path; the reorg disconnect side
   * (`disconnectBlockUtxo`) calls `removeBlock(height)`.
   *
   * No-op when not wired (default off, matches Bitcoin Core's
   * `DEFAULT_COINSTATSINDEX = false`).
   *
   * Reference: bitcoin-core/src/index/coinstatsindex.cpp::CustomAppend.
   */
  setCoinStatsIndex(
    coinStatsIndex: import("../storage/indexes.js").PersistentCoinStatsIndex
  ): void {
    this.coinStatsIndex = coinStatsIndex;
  }

  /**
   * Wire the txospenderindex.
   *
   * When the operator passes `--txospenderindex=1`, cli.ts constructs a
   * `TxoSpenderIndex` and registers it here. Every successful `connectBlock`
   * calls `txoSpenderIndex.indexBlock(block, height)` so the spent-outpoint ->
   * spending-tx mapping is maintained on the PRIMARY connect path; the LIVE
   * reorg disconnect side (`disconnectBlockUtxo`) calls `removeBlock(block,
   * height)`.
   *
   * No-op when not wired (default off, matches Bitcoin Core's
   * `DEFAULT_TXOSPENDERINDEX = false`).
   *
   * Reference: bitcoin-core/src/index/txospenderindex.cpp::CustomAppend.
   */
  setTxoSpenderIndex(
    txoSpenderIndex: import("../storage/indexes.js").TxoSpenderIndex
  ): void {
    this.txoSpenderIndex = txoSpenderIndex;
  }

  /**
   * Re-derive the block-sync frontier from the ChainStateManager's current
   * (rolled-back) tip.
   *
   * `invalidateblock` (and any other path that rolls the active chain back via
   * `ChainStateManager.invalidateBlock` / `disconnectBlock`) rewinds the
   * VALIDATED chain state, but the BlockSync IBD frontier
   * (`state.nextHeightToProcess`) is a SEPARATE high-water mark that is only
   * advanced on connect — it is never lowered. After an invalidateblock that
   * rolls the tip from N back to F, the frontier is left at N+1, so a
   * subsequently-submitted competing-chain block at a height in (F, N] takes
   * the `headerEntry.height < nextHeightToProcess` early-return in
   * `injectBlock` ("duplicate", stored only as a side-branch) and NEVER reaches
   * the connect/reorg dispatch in `connectBlock`. The node then cannot adopt
   * the more-work competing chain even though every block is valid — it sits
   * stuck at F. This was caught by the coinstatsindex reorg-safety harness
   * (test-suite/coinstats/*_coinstatsindex.sh): invalidateblock(F+1) then
   * submitblock B's F+1..N+3 left hotbuns pinned at F while Core reorged to B.
   *
   * Fix: after a rollback, snap the frontier back down to `tip.height + 1` and
   * evict any buffered/pending blocks at heights >= the new frontier (stale
   * chain-A bodies that would otherwise be re-fed). Resubmitted competing
   * blocks at heights in (F, N] then route through the normal connect path,
   * where the pre-connect reorg dispatch (`handleReorgUtxoAndCollect`) and the
   * coinstatsindex connect hook fire as on any active-tip extension.
   *
   * Mirrors Bitcoin Core's InvalidateBlock, which rolls back the active chain
   * AND re-derives the set of candidate tips so a competing branch can be
   * activated by a later block (validation.cpp::InvalidateBlock →
   * ActivateBestChain). No-op when no ChainStateManager is wired.
   */
  /**
   * True iff `hash` (at `height`) is already ON the active validated chain —
   * i.e. it is the active-chain block at that height, an ANCESTOR of (or equal
   * to) the current active tip.  Walks the header chain back from the active tip
   * via `prevBlock` down to `height` and compares hashes (Bitcoin Core
   * CChain::Contains / GetAncestor).  Bounded by `MAX_FORK_DOWNLOAD_DEPTH`.
   *
   * Used to detect the "reorg-to-ancestor" impossible-reorg livelock: after a
   * (spurious or real) header invalidation the loop can end up being asked to
   * (re)connect a block that is already an ancestor of the active tip — there is
   * nothing to reorg to, the `view-out-of-sync` gate rejects it on every attempt,
   * and a naive rewind+retry spins forever.  Returns false when no
   * ChainStateManager is wired (the guard simply doesn't fire).
   */
  private isAncestorOfActiveTip(hash: Buffer, height: number): boolean {
    if (!this.chainStateManager) return false;
    const tip = this.chainStateManager.getBestBlock();
    // A block strictly above the active tip cannot be an ancestor of it.
    if (height > tip.height) return false;
    if (tip.hash.equals(hash)) return true;
    let cursor: HeaderChainEntry | undefined = this.headerSync.getHeader(tip.hash);
    let steps = 0;
    while (cursor && steps <= this.reorgDepthCap()) {
      if (cursor.height === height) {
        return cursor.hash.equals(hash);
      }
      if (cursor.height < height) return false; // walked past it
      if (cursor.height === 0) return false;
      cursor = this.headerSync.getHeader(cursor.header.prevBlock);
      steps++;
    }
    return false;
  }

  /**
   * Hard-halt the block-sync loop with a loud, actionable error and STOP
   * spinning.  Crash-recovery / reorg-integrity safety valve: a stuck node that
   * fails loudly is far better than a silent 100%-CPU livelock that re-requests
   * and re-serves the same block 18k times/minute (the reorg-to-ancestor wedge).
   *
   * Clears the running flag + the stall/log timers so no further
   * `requestBlocks` / `processOrderedBlocks` work is scheduled, and latches
   * `syncHalted` so the two hot entrypoints early-return.  Deliberately does NOT
   * `process.exit` — the RPC server keeps serving so an operator can inspect the
   * chain state, `reconsiderblock`, or trigger a reindex.
   */
  private haltSync(reason: string): void {
    if (this.syncHalted !== null) return;
    this.syncHalted = reason;
    this.running = false;
    if (this.stallCheckInterval) {
      clearInterval(this.stallCheckInterval);
      this.stallCheckInterval = null;
    }
    if (this.logInterval) {
      clearInterval(this.logInterval);
      this.logInterval = null;
    }
    console.error(
      `\n*** [SYNC-HALTED] Block sync stopped — ${reason} ***\n` +
        `The node has stopped advancing the chain to avoid a 100%-CPU retry\n` +
        `livelock. RPC remains available for triage. Investigate the invalidated\n` +
        `/ competing header state (getchaintips, reconsiderblock) or reindex.\n`
    );
  }

  resyncFrontierAfterRollback(): void {
    if (!this.chainStateManager) return;
    const tip = this.chainStateManager.getBestBlock();
    const tipHeight = tip.height;
    const newFrontier = tipHeight + 1;
    if (newFrontier >= this.state.nextHeightToProcess) {
      // Frontier already at/below the new tip — nothing to roll back.
      return;
    }
    // CRITICAL: BlockSync owns a SEPARATE UTXOManager instance from the
    // ChainStateManager (both back the same LevelDB, but each has its own
    // in-memory cache + view-best-block pointer; see the constructor's
    // `new UTXOManager(db, ...)`). invalidateBlock rolled the chain back via
    // ChainStateManager.disconnectBlock, which flushed the rolled-back UTXO
    // state to disk and re-pointed *its* view at the fork tip — but BlockSync's
    // utxoManager still caches the pre-rollback set and points its view at the
    // OLD tip. The next connectBlock then trips coreConnectBlockChecks'
    // `view-out-of-sync` gate (the cached view-best != the new block's prev).
    // Drop BlockSync's stale cache and re-point its view at the now-persisted
    // fork tip so subsequent connects lazy-load the correct rolled-back coins.
    this.utxoManager.clearCache(tip.hash);
    this.state.nextHeightToProcess = newFrontier;
    if (this.state.nextHeightToRequest > newFrontier) {
      this.state.nextHeightToRequest = newFrontier;
    }
    if (this.lastFlushedHeight > tipHeight) {
      this.lastFlushedHeight = tipHeight;
    }
    // Evict buffered + pending blocks at heights at/above the new frontier:
    // those are stale chain-A bodies (or speculative downloads) that must not
    // be auto-reconnected ahead of the operator re-feeding the chosen branch.
    for (const [hex, blk] of this.state.downloadedBlocks) {
      const entry = this.headerSync.getHeader(getBlockHash(blk.header));
      if (entry && entry.height >= newFrontier) {
        this.state.downloadedBlocks.delete(hex);
        this.downloadedBlockPeers.delete(hex);
      }
    }
    for (const [hex, pending] of this.state.pendingBlocks) {
      if (pending.height >= newFrontier) {
        this.state.pendingBlocks.delete(hex);
      }
    }
    // GAP3 fix (reorg-drop part 2/2): the frontier moved, so the set of
    // suppressed competing-fork bodies must be re-evaluated from scratch — clear
    // the on-disk markers (the bodies themselves stay on disk; only the
    // re-request-suppression hint is dropped). Purely an optimization marker:
    // this does NOT alter invalidateblock's rollback/reorg semantics.
    this.forkBodiesOnDisk.clear();
    console.log(
      `[invalidateblock] block-sync frontier rolled back to height ${tipHeight} ` +
        `(nextHeightToProcess=${newFrontier})`
    );
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

    // Start stall detection timer. Also drives the unconditional tx-request
    // expiry sweep — reusing this tick rather than adding a second timer.
    this.stallCheckInterval = setInterval(() => {
      this.sweepTxRequestsInFlight();
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
    // Bug #132 (2026-05-26): the prior fix discarded the dirty cache with
    // a bare clearCache() and let the caller's final flush() write
    // chain-state separately. That left the disk with a chain-state
    // pointer advanced past the actual UTXO content for blocks the cache
    // had absorbed but not yet flushed (observed at h=950371 — 65 blocks
    // of dirty UTXOs silently dropped, then `bad-txns-inputs-missingorspent`
    // on the first connect after restart).
    //
    // Fix: wait up to 5s for the in-flight processOrderedBlocksInner loop
    // to reach an iteration boundary (which respects `running=false` and
    // exits naturally), then ALWAYS take the flush-with-chain-state path
    // so the disk is consistent. If the loop hasn't drained in 5s, fall
    // back to the old clearCache() — at that point the worst case is the
    // historical bug, not worse than the prior behavior.
    const drainDeadline = Date.now() + 5000;
    while (this.processing && Date.now() < drainDeadline) {
      await new Promise<void>((resolve) => setTimeout(resolve, 10));
    }
    if (this.processing) {
      // Drain timed out — fall back to the old destructive behavior.
      // This is no worse than what the original code did unconditionally.
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
          if (
            inv.type === InvType.MSG_TX ||
            inv.type === InvType.MSG_WTX ||
            inv.type === InvType.MSG_WITNESS_TX
          ) {
            // The peer can't serve a tx we asked for. Free the in-flight
            // marker immediately so the next announcer can be asked, instead
            // of stalling relay for the full TX_REQUEST_EXPIRY_MS.
            // Core: TxDownloadManagerImpl::ReceivedNotFound →
            // m_txrequest.ReceivedResponse (txdownloadman_impl.cpp:288-296).
            this.requestedTxInFlight.delete(inv.hash.toString("hex"));
            continue;
          }
          if (inv.type === 2 || inv.type === 0x40000002) { // MSG_BLOCK or MSG_WITNESS_BLOCK
            const hashHex = inv.hash.toString("hex");
            const pending = this.state.pendingBlocks.get(hashHex);
            if (pending && pending.peer === peerKey) {
              console.log(`NOTFOUND: block hash=${hashHex.slice(0, 16)} from=${peerKey}, clearing pending`);
              this.state.pendingBlocks.delete(hashHex);
              peer.removeBlockInFlight(hashHex);
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
    // Since we don't have a mempool, fall back to requesting the full block.
    // Depth guard: ignore cmpctblocks for blocks deeper than MAX_CMPCTBLOCK_DEPTH=5
    // from the tip — they are stale or orphan blocks not worth reconstructing.
    // Core: net_processing.cpp MAX_CMPCTBLOCK_DEPTH = 5 (L2466).
    peerManager.onMessage("cmpctblock", (peer, msg) => {
      if (msg.type === "cmpctblock") {
        const header = msg.payload.header;
        const blockHash = getBlockHash(header);
        const hashHex = blockHash.toString("hex");

        // Compute depth below current tip.
        const tipHeight = this.state.nextHeightToProcess - 1;
        const headerEntry = this.headerSync.getHeader(blockHash);
        const blockHeight = headerEntry?.height;
        const depth = blockHeight !== undefined ? tipHeight - blockHeight : 0;

        if (depth > MAX_CMPCTBLOCK_DEPTH) {
          console.log(
            `Ignoring cmpctblock from ${peer.host}:${peer.port} — ` +
            `depth=${depth} exceeds MAX_CMPCTBLOCK_DEPTH=${MAX_CMPCTBLOCK_DEPTH} ` +
            `(hash=${hashHex.slice(0, 16)})`
          );
          return;
        }

        console.log(
          `Received cmpctblock from ${peer.host}:${peer.port}, ` +
          `falling back to full block request (hash=${hashHex})`
        );
        // Request the full block via getdata since we can't reconstruct
        // from compact block without a mempool (BUG-2/BUG-3 — CompactBlockManager
        // dead helper; wiring it is out of scope for FIX-42).
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

    // BIP 152: Handle getblocktxn — peer requesting missing txs for compact block
    // reconstruction they are performing. Depth guard: ignore requests for blocks
    // deeper than MAX_BLOCKTXN_DEPTH=10 from the tip — stale requests waste I/O.
    // Core: net_processing.cpp MAX_BLOCKTXN_DEPTH = 10.
    peerManager.onMessage("getblocktxn", (peer, msg) => {
      if (msg.type !== "getblocktxn") return;

      const blockHash = msg.payload.blockHash;
      const hashHex = blockHash.toString("hex");

      // Depth guard: refuse to serve getblocktxn for old blocks.
      const tipHeight = this.state.nextHeightToProcess - 1;
      const headerEntry = this.headerSync.getHeader(blockHash);
      const blockHeight = headerEntry?.height;
      const depth = blockHeight !== undefined ? tipHeight - blockHeight : 0;

      if (depth > MAX_BLOCKTXN_DEPTH) {
        console.log(
          `Ignoring getblocktxn from ${peer.host}:${peer.port} — ` +
          `depth=${depth} exceeds MAX_BLOCKTXN_DEPTH=${MAX_BLOCKTXN_DEPTH} ` +
          `(hash=${hashHex.slice(0, 16)})`
        );
        return;
      }

      // We don't serve compact blocks yet (BUG-5 — getblocktxn serve path is a stub).
      // The depth guard above is in place; full serving is out of scope for FIX-42.
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

    // On peer disconnect, eagerly clean per-peer block-sync state.  Mirrors
    // Bitcoin Core PeerManagerImpl::FinalizeNode (net_processing.cpp:1675-1730)
    // which erases vBlocksInFlight + m_node_states[nodeid] when a peer is
    // dropped.  Without this, three classes of bug ride on the 1 s
    // `handleStalled` poll:
    //
    //   1. `peerInFlight[peerKey].count` leaks — the only paths that
    //      decrement are handleBlock-on-delivery, the in-band stall handler
    //      (lines 3180-3183), and the deadlock-fix path (lines 3267-3270).
    //      The disconnect-cleanup loop (lines 3206-3214) used to delete the
    //      pending entries but not touch the per-peer count.  If the same
    //      host:port reconnected (common on mainnet, outbound dest port is
    //      always 8333), the new peer inherited a stuck count > 0.  Over an
    //      hour of churn this saturates every entry above
    //      MAX_IN_FLIGHT_PER_PEER (=16) and `requestBlocks()` silently
    //      refuses to assign anything.
    //
    //   2. Bug #139 fixed the headers side (header-sync state cleared on
    //      disconnect — see headers.ts:258); but blocks had no equivalent.
    //      Symptom: `pend=0 dl=1` (one out-of-order future block in the
    //      buffer, zero outstanding requests) for hours, even with 10
    //      connected peers, because the only catch-all path
    //      (handleStalled lines 3199-3217) bails when pendingBlocks.size==0.
    //      Observed live on mainnet 2026-05-27 at h=76051 — 14 hours stuck
    //      after a peer-churn burst left zero pendings and no recovery
    //      trigger fired.
    //
    //   3. peerInFlight + downloadedBlockPeers Maps grew without bound,
    //      one stale entry per ever-seen host:port.  Not user-visible but
    //      a slow memory leak over multi-day uptime.
    //
    // The fix here removes pending entries for this peer, decrements the
    // count (so a reconnect doesn't inherit the stale value), purges the
    // peerInFlight entry, prunes downloadedBlockPeers references, and
    // forces a fresh requestBlocks() — the new peer (or any survivor) can
    // now pick up the gap immediately rather than waiting for the next
    // poll tick.
    peerManager.onMessage("__disconnect__", (peer) => {
      if (!this.running) return;
      const peerKey = `${peer.host}:${peer.port}`;
      let cleared = 0;
      for (const [hashHex, pending] of this.state.pendingBlocks) {
        if (pending.peer === peerKey) {
          this.state.pendingBlocks.delete(hashHex);
          if (pending.height < this.state.nextHeightToRequest) {
            this.state.nextHeightToRequest = pending.height;
          }
          cleared++;
        }
      }
      // Drop the per-peer in-flight tracker so a reconnect starts fresh.
      // This is the core leak fix — without it, a reconnect at the same
      // host:port carries forward a stuck count.
      this.peerInFlight.delete(peerKey);
      // Erase downloadedBlockPeers references — these are advisory (used to
      // misbehavior-score the deliverer if validation later fails), and a
      // stale ref to a disconnected peer is useless.
      for (const [hashHex, key] of this.downloadedBlockPeers) {
        if (key === peerKey) {
          this.downloadedBlockPeers.delete(hashHex);
        }
      }
      // Whether or not we cleared pendings, the topology changed — re-run
      // requestBlocks so a surviving / freshly-connected peer can fill the
      // gap immediately rather than waiting for the next 1 s stall tick.
      // This is what closes the `pend=0 dl=1` deadlock above.
      if (!this.ibdComplete) {
        this.requestBlocks();
      }
      if (cleared > 0) {
        console.log(
          `[disconnect-cleanup] cleared ${cleared} pending blocks from ${peerKey}`
        );
      }
    });

    // When new headers are fully processed (callback fires AFTER headerSync
    // has updated bestHeader), re-enter IBD if we have blocks to download.
    // This replaces the old "headers" message handler which suffered from a
    // race condition: the message handler ran before headerSync finished
    // processing headers asynchronously, so bestHeader was stale.
    this.headerSync.onHeadersProcessed((newTipHeight: number) => {
      if (!this.running) return;
      // GAP2 fix (reorg-drop part 1/2): a heavier competing branch that forks
      // BELOW the active validated tip can have a header tip whose HEIGHT is at
      // or below the processing frontier (more work per block, fewer blocks),
      // so the height-only `newTipHeight >= nextHeightToProcess` test would miss
      // it and never re-enter the download path — leaving the fork's bridging
      // bodies unrequested. Also re-enter when the best header now carries MORE
      // WORK than the active validated tip (Bitcoin Core moves chain selection
      // on greater nChainWork, not greater height). `lowerDownloadFloorForFork`
      // inside `requestBlocks` then lowers the floor to the fork point. For a
      // normal extension this collapses to the original height condition.
      const bestHeader = this.headerSync.getBestHeader();
      const moreWorkThanActiveTip =
        bestHeader !== null &&
        this.chainStateManager !== null &&
        bestHeader.chainWork > this.chainStateManager.getBestBlock().chainWork;
      if (newTipHeight >= this.state.nextHeightToProcess || moreWorkThanActiveTip) {
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
        // Unknown block — peer sent a block whose header we have never seen.
        // Core: ProcessNewBlockHeaders returns nBlocksWithValidHeaders==0 and
        // ProcessBlock calls Misbehaving(pfrom, 100, "invalid header received").
        // G17 fix: score the peer so it cannot flood us with garbage blocks.
        peer.misbehaving(100, "block-invalid-header");
        return;
      }

      // G19c: fTooFarAhead — Core's MIN_BLOCKS_TO_KEEP=288 cap.
      // Unrequested blocks that are more than 288 heights ahead of the
      // active tip cannot advance chain selection soon and could be used
      // for memory exhaustion.  Silently ignore them.
      // Core: if (!fRequested && fTooFarAhead) return true;  (validation.cpp:4325)
      const activeHeight = this.state.nextHeightToProcess - 1;
      const fTooFarAhead = headerEntry.height > activeHeight + MIN_BLOCKS_TO_KEEP;
      if (fTooFarAhead) {
        return;
      }

      // GAP3 fix (reorg-drop part 2/2): a below-frontier competing-fork body
      // delivered unsolicited (inv-driven, post-IBD) must NOT be dropped by the
      // `height >= nextHeightToProcess` gate below — it is a bridging body the
      // reorg dispatch needs on disk. Persist it as a side branch; the fork tip
      // (which is at/above the frontier) then drives the reorg.
      if (await this.maybeStoreForkBody(block, blockHash, hashHex)) {
        await this.processOrderedBlocks();
        return;
      }

      // Store it if it's useful and we have room in the buffer
      if (headerEntry.height >= this.state.nextHeightToProcess &&
          this.state.downloadedBlocks.size < MAX_DOWNLOADED_BUFFER) {
        this.state.downloadedBlocks.set(hashHex, block);
        this.downloadedBlockPeers.set(hashHex, peerKey); // G16: track peer source
        // Try to process blocks in order
        await this.processOrderedBlocks();
      }
      return;
    }

    // Remove from pending
    this.state.pendingBlocks.delete(hashHex);
    peer.removeBlockInFlight(hashHex);

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
    this.downloadedBlockPeers.set(hashHex, peerKey); // G16: track peer source

    // GAP3 fix (reorg-drop part 2/2): if this is a competing-fork body BELOW
    // the active processing frontier (a bridging body the fork-aware download
    // floor of part 1 pulled in), persist it to disk as a side branch and stop
    // here — the reorg dispatch reads it back from disk when the fork TIP
    // connects. Post-IBD only; a normal active-chain / fork-tip block returns
    // false and follows the usual ordered-connect path below unchanged.
    if (await this.maybeStoreForkBody(block, blockHash, hashHex)) {
      // The fork tip may already be buffered; let processOrderedBlocks fire the
      // reorg if so, and request any still-missing bridging/tip bodies.
      await this.processOrderedBlocks();
      this.requestBlocks();
      return;
    }

    // Try to process blocks in order
    await this.processOrderedBlocks();

    // Request more blocks if needed
    this.requestBlocks();
  }

  /**
   * Persist a competing-fork ("side-branch") block body so a later reorg can
   * read it back.
   *
   * A block whose height is BELOW the active processing frontier is not on the
   * active chain right now, but a future heavier sibling may trigger a reorg.
   * The reorg dispatch (`handleReorgUtxoAndCollect`, step 3) reconnects the
   * intermediate fork blocks by reading their bodies via `db.getBlock` — so the
   * bridging fork bodies MUST be on disk before the fork tip connects.
   *
   * Pre-fix (reorg-drop part 2 gap, GAP3) the submitblock path stored these via
   * `injectBlock`'s inline side-branch code, but the live P2P receive path
   * (`handleBlock`) only ever buffered downloaded blocks in the in-memory
   * `downloadedBlocks` map. A below-tip heavier fork arriving over P2P therefore
   * had its bridging bodies (forkPoint+1 .. activeTip) live ONLY in RAM; when the
   * fork tip reached `connectBlock`, the reorg dispatch's `db.getBlock` lookups
   * returned null → "intermediate block body missing" → fall back to the legacy
   * in-place connect → permanent `view-out-of-sync` wedge. This helper is the
   * shared store used by BOTH paths so the bodies reach disk identically.
   *
   * Idempotent: `db.putBlock` is hash-keyed, so re-storing the same body is a
   * no-op except for write amplification. Best-effort: a put failure surfaces
   * later as a "missing block" reorg-dispatch log line, never chain-state
   * corruption. Mirrors Bitcoin Core's AcceptBlock, which writes a valid block
   * body to disk regardless of whether it is on the active chain
   * (validation.cpp::AcceptBlock → SaveBlockToDisk).
   */
  private async storeSideBranchBlock(
    block: Block,
    blockHash: Buffer,
    hashHex: string
  ): Promise<void> {
    try {
      await this.db.putBlock(blockHash, serializeBlock(block));
      // W109 FIX-33: set BLOCK_HAVE_DATA (8) in the block index after writing
      // the body so FindMostWorkChain / prune / AssumeUTXO see HAVE_DATA on
      // these blocks. Mirrors Core blockstorage.cpp::WriteBlock which sets
      // BLOCK_HAVE_DATA before the dirty-index flush.
      const sideBranchIdx = await this.db.getBlockIndex(blockHash);
      if (sideBranchIdx && !(sideBranchIdx.status & 8 /* HAVE_DATA */)) {
        await this.db.updateBlockStatus(
          blockHash,
          sideBranchIdx.status | 8 /* HAVE_DATA */,
        );
      }
    } catch (err) {
      console.warn(
        `[side-branch] failed to store side-branch block ${hashHex.slice(0, 16)}: ${
          err instanceof Error ? err.message : String(err)
        }`
      );
    }
  }

  /**
   * GAP3 fix (reorg-drop part 2/2): route a passively-received P2P block that is
   * a competing-fork body BELOW the active processing frontier through the same
   * side-branch storage the submitblock path uses, instead of dropping it or
   * leaving it stranded in the in-memory download buffer.
   *
   * Returns true when the block was handled as a side-branch body (the caller
   * must NOT additionally buffer/connect it on the active frontier); false when
   * the block is a normal active-frontier block and should follow the usual
   * download-buffer + `processOrderedBlocks` path unchanged.
   *
   * Gated to POST-IBD only (mirrors blockbrew part 2, which keeps raw
   * ConnectBlock during IBD and only routes through the side-branch-aware
   * ProcessSubmittedBlock at/after the tip): during initial sync blocks arrive
   * in order and extend the tip; competing forks below the tip are a
   * steady-state / at-tip phenomenon, and `requestBlocks`'s fork-aware floor
   * (part 1) only lowers below the active tip once a heavier header chain is
   * known. The active-tip EXTENSION path is untouched — a block at/above the
   * frontier returns false immediately, so normal IBD + steady-state extension
   * connect exactly as before (invariant 1).
   *
   * Once the bridging bodies are on disk, the fork TIP block (which IS at/above
   * the frontier and so connects through `connectBlock`) drives the existing
   * pre-connect reorg dispatch (`handleReorgUtxoAndCollect`) which reads those
   * bodies back and switches the active tip to the heavier branch — the same
   * reorg machinery `invalidateblock` → `resyncFrontierAfterRollback` exercises.
   */
  private async maybeStoreForkBody(
    block: Block,
    blockHash: Buffer,
    hashHex: string
  ): Promise<boolean> {
    // Only side-branch a competing fork once the node has synced at least once
    // (NOT during genuine initial IBD). Use the one-way hasCompletedInitialSync
    // latch, NOT ibdComplete — the latter is transiently flipped false when a
    // heavier fork is discovered (onHeadersProcessed), which previously left
    // every bridging fork body un-persisted -> connectBlock found null on disk
    // -> view-out-of-sync wedge (the original blocker re-manifesting).
    if (!this.hasCompletedInitialSync) return false;
    if (!this.chainStateManager) return false;

    const headerEntry = this.headerSync.getHeader(blockHash);
    if (!headerEntry) return false;

    // Only below-frontier blocks are side-branch bodies; at/above the frontier
    // is the normal active-chain (or fork-tip) path → leave it to the caller.
    if (headerEntry.height >= this.state.nextHeightToProcess) return false;

    // Confirm this is a genuine competing-fork body, NOT a block on the active
    // validated chain (a re-delivered active-chain body must not be treated as a
    // side branch). We walk the active validated chain's ancestry down to this
    // block's height and compare the hash at that height: if it differs, this is
    // a fork body. (Bitcoin Core CChain::Contains / FindFork.)
    const activeTip = this.chainStateManager.getBestBlock();
    let onActiveChain = false;
    {
      let cursor: HeaderChainEntry | undefined = this.headerSync.getHeader(
        activeTip.hash
      );
      let steps = 0;
      while (cursor && steps <= this.reorgDepthCap()) {
        if (cursor.height === headerEntry.height) {
          onActiveChain = cursor.hash.equals(blockHash);
          break;
        }
        if (cursor.height < headerEntry.height) break; // walked past it
        if (cursor.height === 0) break;
        cursor = this.headerSync.getHeader(cursor.header.prevBlock);
        steps++;
      }
    }
    if (onActiveChain) return false; // active-chain body — normal handling

    // Genuine below-frontier competing-fork body: persist it to disk so the
    // reorg dispatch can read it when the fork tip connects, then drop the
    // in-memory copy (it will be re-read from disk during the reorg).
    await this.storeSideBranchBlock(block, blockHash, hashHex);
    this.forkBodiesOnDisk.add(hashHex);
    this.state.downloadedBlocks.delete(hashHex);
    this.downloadedBlockPeers.delete(hashHex);
    console.log(
      `[fork-body] stored competing-fork body height=${headerEntry.height} ` +
        `hash=${hashHex.slice(0, 16)} below active frontier ` +
        `${this.state.nextHeightToProcess} as a side branch (reorg pending fork tip)`
    );
    return true;
  }

  /**
   * Inject a block directly (e.g. from submitblock RPC) without a peer.
   * Clears any pending request for this block and stores it in the download
   * buffer for in-order processing.
   */
  async injectBlock(block: Block): Promise<string | null> {
    const blockHash = getBlockHash(block.header);
    const hashHex = blockHash.toString("hex");

    // Per-submission reset of the shared connect-error scratchpad.
    //
    // `lastConnectError` is a BlockSync-instance field that `connectBlock`
    // populates on a failed connect (validation.cpp-style reject reason) and
    // the BIP-22 classifier at the tail of this method reads back to map into
    // a submitblock result string ("bad-txns-nonfinal", etc).  `connectBlock`
    // clears it at its own start (line ~3127), so the *connect decision* is
    // always per-block.  But when a submitted block never reaches
    // `connectBlock` — e.g. its header is a competing sibling that is not the
    // active header at its height, so `processOrderedBlocksInner` can't find
    // its body and breaks without connecting — the classifier below would read
    // the STALE reason left by a PREVIOUS rejected block and wrongly report it
    // for THIS block.  A single non-final-locktime rejection would then poison
    // every subsequent submitblock with "bad-txns-nonfinal".  Finality is a
    // pure per-tx property in Core (IsFinalTx, consensus/tx_verify.cpp — no
    // persisted state), so this scratchpad must be scoped per submission.
    // Reset it here, mirroring the per-block reset connectBlock already does
    // for the P2P/connect path.
    this.lastConnectError = "";

    let headerEntry = this.headerSync.getHeader(blockHash);
    if (!headerEntry) {
      // Header not known yet — try to accept it directly from the block.
      // This allows submitblock to work even when header sync is stalled
      // (e.g. after IBD completes but chain work hasn't reached nMinimumChainWork,
      // causing the anti-DoS PRESYNC to block new headers from peers).
      // minPowChecked=false: the submitblock direct path bypasses the
      // PRESYNC/REDOWNLOAD anti-DoS gate, so we must enforce the
      // too-little-chainwork guard here.  (Core validation.cpp:4229.)
      const accepted = await this.headerSync.processHeaders([block.header], null, false);
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
      // Side-branch storage: persist the block body even though it's
      // not on the active chain right now (see storeSideBranchBlock for
      // the full rationale — a future heavier sibling reorg reads the
      // bridging bodies back via db.getBlock).
      await this.storeSideBranchBlock(block, blockHash, hashHex);
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

    // Snapshot height before processing so we can detect if the block
    // was rejected (processOrderedBlocks is void — failure is implicit).
    const heightBefore = this.state.nextHeightToProcess;
    const injectedHeight = headerEntry.height;

    // Try to process blocks in order
    await this.processOrderedBlocks();

    // Request more blocks if needed
    this.requestBlocks();

    // BIP-22 rejection propagation: if the injected block was next in line
    // but nextHeightToProcess did not advance, connectBlock rejected it.
    // Propagate the rejection reason as a BIP-22 string so the caller
    // (submitblock RPC) can return the right error rather than null (= success).
    // Without this, the harness sees chain-height unchanged → classifies as
    // "accept (chain didn't advance)" which is incorrect.
    if (injectedHeight === heightBefore && this.state.nextHeightToProcess <= heightBefore) {
      const err = this.lastConnectError;
      const errL = err.toLowerCase();
      if (errL.includes("non-final") || errL.includes("nonfinal") || errL.includes("bad-txns-nonfinal") ||
          errL.includes("sequence locks not satisfied") || errL.includes("sequence lock")) {
        return "bad-txns-nonfinal";
      }
      if (err) {
        // Map other connectBlock failures to BIP-22 strings.
        return bip22FromConnectError(err);
      }
      // The block was next in line and the tip did NOT advance, but
      // connectBlock recorded no reason. Falling through to `return null`
      // here reported SUCCESS for a block that was never connected — the
      // exact outcome the comment above says must not happen.
      //
      // Measured 2026-08-05: hotbuns at 960958, fleet tip 961165,
      // `submitblock <961059>` returned {"result":null} and the tip stayed at
      // 960958. Nothing in the response distinguished it from a real accept,
      // so the node looked healthy while silently refusing to advance. See
      // receipts/rustoshi-block-gap-wedge-2026-08-04.md ("class C").
      //
      // Core's contract: submitblock returns the reject reason verbatim, and
      // "rejected" specifically when the reason string is EMPTY
      // (rpc/mining.cpp BIP22ValidationResult). An empty reason is exactly
      // the state we are in, so "rejected" is the Core-parity answer — not
      // "inconclusive", which BIP-22 reserves for a block that was not fully
      // validated (e.g. an orphan).
      //
      // Note this reports the failure without explaining it. Why connectBlock
      // can fail while leaving lastConnectError empty is a separate defect
      // and is what made this node opaque for two days.
      return "rejected";
    }

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
    // Transaction inv items to fetch, preserving the announced inv type so the
    // getdata echoes MSG_WTX/MSG_TX per the peer's wtxidrelay negotiation.
    const txsToRequest: InvVector[] = [];
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
      } else if (inv.type === InvType.MSG_TX || inv.type === InvType.MSG_WTX) {
        // Classic transaction announcement → getdata (BIP-339 aware).
        // Reference: bitcoin-core net_processing.cpp ProcessMessage(INV),
        // the `inv.IsGenTxMsg()` branch (~L4079): outside IBD, feed the
        // announcement into the tx-download manager which decides whether to
        // request. hotbuns collapses that to: request unless we already have
        // the tx, recently rejected it, or already have a request in flight.
        //
        // NOTE: the Erlay set-reconciliation path (src/p2p/erlay.ts) is a
        // SEPARATE mechanism and is intentionally not consulted here — this is
        // the classic fluff/inv→getdata loop.

        // Block-relay-only peers must never relay transactions to us
        // (Core RejectIncomingTxs → reject_tx_invs, net_processing.cpp:5601).
        if (peer.connType === "block_relay") {
          continue;
        }

        // Honor the wtxidrelay negotiation: ignore inv items that don't match
        // (Core net_processing.cpp:4059-4063 — MSG_TX ignored for wtxid peers
        // and vice-versa).
        if (peer.wtxidRelay && inv.type === InvType.MSG_TX) continue;
        if (!peer.wtxidRelay && inv.type === InvType.MSG_WTX) continue;

        const hashHex = inv.hash.toString("hex");

        // AlreadyHaveTx: orphanage / recent-rejects / recent-confirmed /
        // mempool — all O(1). Core: txdownloadman_impl.cpp:199, the
        // `if (AlreadyHaveTx(gtxid, ...)) return true;` early-out inside
        // AddTxAnnouncement.
        if (this.alreadyHaveInv(inv, hashHex)) continue;

        // In-flight request from another peer? (single-attempt dedup)
        if (this.isTxRequestInFlight(hashHex)) continue;

        this.requestedTxInFlight.set(hashHex, Date.now());
        txsToRequest.push({ type: inv.type, hash: inv.hash });
      }
    }

    if (blocksToRequest.length > 0) {
      this.sendGetData(peer, blocksToRequest);
    }

    if (txsToRequest.length > 0) {
      this.sendTxGetData(peer, txsToRequest);
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
    // notfound accumulator for tx items we can't serve — lets the peer stop
    // waiting and re-request the tx elsewhere (Core ProcessGetData →
    // NetMsgType::NOTFOUND, net_processing.cpp:2570-2585).
    const notFound: InvVector[] = [];

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
      } else if (
        inv.type === InvType.MSG_TX ||
        inv.type === InvType.MSG_WTX ||
        inv.type === InvType.MSG_WITNESS_TX
      ) {
        // Serve an unconfirmed transaction from the mempool by txid/wtxid.
        // Reference: bitcoin-core net_processing.cpp ProcessGetData →
        // FindTxForGetData (L2494) → MakeAndPushMessage(TX). On a miss we
        // append to notfound rather than silently dropping.
        const tx = this.findMempoolTxForInv(inv);
        if (tx) {
          const txMsg: NetworkMessage = {
            type: "tx",
            payload: { tx },
          };
          peer.send(txMsg);
        } else {
          notFound.push({ type: inv.type, hash: inv.hash });
        }
      }
    }

    if (notFound.length > 0) {
      peer.send({ type: "notfound", payload: { inventory: notFound } });
    }
  }

  /**
   * True if the tx named by this inv item (txid for MSG_TX/MSG_WITNESS_TX,
   * wtxid for MSG_WTX) is already in the mempool.
   */
  private mempoolHasInv(inv: InvVector): boolean {
    return this.findMempoolTxForInv(inv) !== null;
  }

  /**
   * Look up the mempool transaction referenced by an inv item. MSG_TX and
   * MSG_WITNESS_TX carry a txid; MSG_WTX carries a wtxid. Both are now O(1)
   * map probes.
   *
   * PREVIOUSLY the MSG_WTX branch was a full linear scan of the mempool that
   * re-serialized and double-SHA256'd every entry to recompute its wtxid —
   * O(mempool) hashes for EVERY announced or requested wtxid inv item, and
   * `getAllTxids()` additionally allocated one 32-byte Buffer per pool entry
   * per call. Since essentially every modern peer negotiates `wtxidrelay`,
   * that scan ran on the majority of inv items. Bitcoin Core answers the same
   * question from `index_by_wtxid` on its indexed_transaction_set
   * (txmempool.h), i.e. O(1); the mempool now carries the same index.
   */
  private findMempoolTxForInv(inv: InvVector): Transaction | null {
    if (!this.mempool) return null;

    if (inv.type === InvType.MSG_TX || inv.type === InvType.MSG_WITNESS_TX) {
      const entry = this.mempool.getTransaction(inv.hash);
      return entry ? entry.tx : null;
    }

    if (inv.type === InvType.MSG_WTX) {
      const entry = this.mempool.getTransactionByWtxidHex(inv.hash.toString("hex"));
      return entry ? entry.tx : null;
    }

    return null;
  }

  /**
   * O(1) "already have this inv item's tx?" probe for the announcement path.
   *
   * Same set of sources as {@link alreadyHaveTx}, but an inv carries only ONE
   * hash — whichever form the announcing peer chose — so we can only probe the
   * source that understands that form. Mirrors Core's AlreadyHaveTx being
   * called with a GenTxid on the announcement path
   * (txdownloadman_impl.cpp:199).
   */
  private alreadyHaveInv(inv: InvVector, hashHex: string): boolean {
    if (this.orphanPool !== null && this.orphanPool.hasHex(hashHex, hashHex)) {
      return true;
    }
    if (this.recentlyRejectedTxs.has(hashHex)) return true;
    if (this.recentlyConfirmedTxs.has(hashHex)) return true;
    return this.mempoolHasInv(inv);
  }

  /**
   * True if we already have a getdata in flight for this tx (by inv-hash hex)
   * within the expiry window. Opportunistically prunes expired markers.
   */
  private isTxRequestInFlight(hashHex: string): boolean {
    const at = this.requestedTxInFlight.get(hashHex);
    if (at === undefined) return false;
    if (Date.now() - at > TX_REQUEST_EXPIRY_MS) {
      this.requestedTxInFlight.delete(hashHex);
      return false;
    }
    return true;
  }

  /**
   * Unconditional expiry sweep of the tx-request in-flight map.
   *
   * `isTxRequestInFlight` only ever prunes the ONE key it is asked about, so a
   * marker for a tx that is announced once and never announced again is never
   * revisited and stays in the map forever. Core has no such hazard: its
   * TxRequestTracker expires announcements on every `GetRequestable` pass
   * (txrequest.cpp, the `expired` out-param plumbed through
   * TxDownloadManagerImpl::GetRequestsToSend) regardless of whether a
   * particular hash is looked up again.
   *
   * Driven from the existing 1s stall tick — deliberately NOT a new timer —
   * and rate-limited to TX_INFLIGHT_SWEEP_INTERVAL_MS. Also enforces
   * MAX_TX_INFLIGHT as a backstop for a starved event loop, evicting the
   * oldest insertions first (Map preserves insertion order, and entries are
   * only ever inserted with `Date.now()`, so insertion order IS age order).
   *
   * @returns number of markers dropped.
   */
  sweepTxRequestsInFlight(now: number = Date.now()): number {
    if (now - this.lastTxInFlightSweep < TX_INFLIGHT_SWEEP_INTERVAL_MS) return 0;
    this.lastTxInFlightSweep = now;

    let dropped = 0;
    for (const [hashHex, at] of this.requestedTxInFlight) {
      if (now - at > TX_REQUEST_EXPIRY_MS) {
        this.requestedTxInFlight.delete(hashHex);
        dropped++;
      }
    }

    // Backstop: if the tick has been starved, time-based expiry alone may not
    // have run recently enough. Never let the map exceed the hard cap.
    if (this.requestedTxInFlight.size > MAX_TX_INFLIGHT) {
      const excess = this.requestedTxInFlight.size - MAX_TX_INFLIGHT;
      let n = 0;
      for (const hashHex of this.requestedTxInFlight.keys()) {
        if (n++ >= excess) break;
        this.requestedTxInFlight.delete(hashHex);
        dropped++;
      }
    }

    return dropped;
  }

  /**
   * AlreadyHaveTx — O(1) "do we already know about this transaction?" probe.
   *
   * Mirrors the SHAPE of Bitcoin Core's
   * `TxDownloadManagerImpl::AlreadyHaveTx` (txdownloadman_impl.cpp:125-147):
   * orphanage, then recent-rejects, then recent-confirmed, then mempool.
   * Core's filters are rolling bloom filters (approximate, self-expiring);
   * ours are exact bounded FIFO Sets, which trades a little memory for zero
   * false positives — a false positive here would silently drop a real tx.
   *
   * Used on BOTH sides of the relay loop, exactly as Core does:
   *  - announcement side (`handleInv`) so we never getdata something we have;
   *  - receipt side (the cli.ts `tx` handler) so a duplicate that slipped
   *    through announcement dedup costs a map probe instead of a full
   *    acceptToMemoryPool with its UTXO reads and script verification.
   *
   * Callers pass both hashes; either matching is a hit. (Core prefers the
   * wtxid on the receipt path to dodge witness malleation, but it can only do
   * that because its mempool is indexed by both. hotbuns' mempool is keyed by
   * txid only, so we check the wtxid against the hash-set filters and the
   * txid against the mempool.)
   */
  alreadyHaveTx(txidHex: string, wtxidHex: string): boolean {
    if (this.orphanPool !== null && this.orphanPool.hasHex(wtxidHex, txidHex)) {
      return true;
    }
    if (
      this.recentlyRejectedTxs.has(wtxidHex) ||
      this.recentlyRejectedTxs.has(txidHex)
    ) {
      return true;
    }
    if (
      this.recentlyConfirmedTxs.has(wtxidHex) ||
      this.recentlyConfirmedTxs.has(txidHex)
    ) {
      return true;
    }
    return this.mempool !== null && this.mempool.hasTxidHex(txidHex);
  }

  /**
   * Record that a transaction was accepted into the mempool.
   *
   * Core: `TxDownloadManagerImpl::MempoolAcceptedTx`
   * (txdownloadman_impl.cpp:323-333) — `ForgetTxHash` for both the txid and
   * the wtxid, so the request tracker stops holding a slot for a tx we now
   * have. The orphanage side of Core's function is handled in cli.ts
   * (`processOrphanCascade`), which owns the orphan pool.
   */
  onMempoolAcceptedTx(txidHex: string, wtxidHex: string): void {
    this.requestedTxInFlight.delete(txidHex);
    this.requestedTxInFlight.delete(wtxidHex);
  }

  /**
   * Record every transaction in a newly connected block as recently confirmed.
   *
   * Core: `TxDownloadManagerImpl::BlockConnected` (txdownloadman_impl.cpp:
   * 95-108) inserts the txid — and the wtxid when it differs — into
   * RecentConfirmedTransactionsFilter, and forgets any outstanding request.
   * Without this, a mined tx leaves the mempool and every subsequent
   * announcement of it triggers a fresh getdata plus a full
   * acceptToMemoryPool that can only end in rejection.
   *
   * @param hashes one `{txidHex, wtxidHex}` per transaction in the block
   *               (callers should skip the coinbase; it is never relayed).
   */
  markTxsConfirmed(hashes: Iterable<{ txidHex: string; wtxidHex: string }>): void {
    for (const { txidHex, wtxidHex } of hashes) {
      this.requestedTxInFlight.delete(txidHex);
      this.requestedTxInFlight.delete(wtxidHex);
      this.addRecentlyConfirmed(txidHex);
      if (wtxidHex !== txidHex) this.addRecentlyConfirmed(wtxidHex);
    }
  }

  /** Bounded-FIFO insert into {@link recentlyConfirmedTxs}. */
  private addRecentlyConfirmed(hashHex: string): void {
    if (this.recentlyConfirmedTxs.has(hashHex)) return;
    this.recentlyConfirmedTxs.add(hashHex);
    while (this.recentlyConfirmedTxs.size > MAX_RECENT_CONFIRMED_TXS) {
      const oldest = this.recentlyConfirmedTxs.values().next().value;
      if (oldest === undefined) break;
      this.recentlyConfirmedTxs.delete(oldest);
    }
  }

  /**
   * Reset the recently-confirmed filter on a chain reorg.
   *
   * Core: `TxDownloadManagerImpl::BlockDisconnected`
   * (txdownloadman_impl.cpp:112-123) — transactions from a disconnected block
   * go back to being relayable, and keeping them in the filter would make us
   * refuse to re-download them.
   */
  onBlockDisconnected(): void {
    this.recentlyConfirmedTxs.clear();
    this.onActiveTipChange();
  }

  /**
   * Drop the recent-rejects filter whenever the active tip moves.
   *
   * Core: `TxDownloadManagerImpl::ActiveTipChange`
   * (txdownloadman_impl.cpp:88-92) — `RecentRejectsFilter().reset()` on EVERY
   * tip change, connect or disconnect.
   *
   * This matters more than it looks. Most mempool rejections are transient
   * policy calls, not verdicts: below the rolling minimum fee, non-final
   * locktime, ancestor/descendant limits, mempool full. A tx rejected for any
   * of those at height N is very often perfectly acceptable at height N+1, and
   * a filter that never forgets would blacklist it from ever being downloaded
   * again. Core solves that by wiping the filter on each new tip; our filter
   * only had FIFO eviction, which is not the same thing at all.
   *
   * (This was latent rather than harmful before this wave only because
   * `markTxRejected` had no callers anywhere in the tree, so the filter was
   * never populated. Wiring the drainers makes the reset mandatory.)
   */
  onActiveTipChange(): void {
    this.recentlyRejectedTxs.clear();
  }

  /**
   * Record that an announced/received tx was rejected so we stop re-requesting
   * it on subsequent announcements. Bounded FIFO. Also clears any in-flight
   * request marker. Best-effort local stand-in for Core's m_recent_rejects.
   *
   * Callers pass every hash form they hold (txid and wtxid); an inv may have
   * named either. Must NOT be called for a missing-inputs rejection — Core
   * routes TX_MISSING_INPUTS into the orphanage instead of the rejects filter
   * (net_processing.cpp / txdownloadman_impl.cpp MempoolRejectedTx) precisely
   * so the tx can still be reconsidered once its parent arrives.
   */
  markTxRejected(...hashHexes: string[]): void {
    for (const hashHex of hashHexes) {
      this.requestedTxInFlight.delete(hashHex);
      if (this.recentlyRejectedTxs.has(hashHex)) continue;
      this.recentlyRejectedTxs.add(hashHex);
      while (this.recentlyRejectedTxs.size > MAX_RECENT_REJECTED_TXS) {
        // Drop oldest insertion (Set preserves insertion order).
        const oldest = this.recentlyRejectedTxs.values().next().value;
        if (oldest === undefined) break;
        this.recentlyRejectedTxs.delete(oldest);
      }
    }
  }

  /**
   * Clear the in-flight request marker for a tx once it arrives (called from
   * the tx message handler). Keyed by both txid and wtxid hex so either the
   * MSG_TX or MSG_WTX request marker is cleared.
   *
   * Core equivalent: `m_txrequest.ReceivedResponse` from
   * `TxDownloadManagerImpl::ReceivedTx` (txdownloadman_impl.cpp:510-512) —
   * note Core drains the tracker BEFORE the AlreadyHaveTx drop check, so a
   * duplicate delivery still frees the slot. Callers must do the same.
   */
  clearTxRequestInFlight(...hashHexes: string[]): void {
    for (const h of hashHexes) this.requestedTxInFlight.delete(h);
  }

  /**
   * Test/observability hook: current in-flight tx-request marker count.
   */
  getTxRequestInFlightCount(): number {
    return this.requestedTxInFlight.size;
  }

  /**
   * Send a getdata for transaction inv items, echoing the announced inv type
   * (MSG_WTX vs MSG_TX) so the request matches the peer's wtxidrelay setting.
   * Reference: bitcoin-core net_processing.cpp SendMessages tx-request loop
   * (~L6206): `gtxid.IsWtxid() ? MSG_WTX : (MSG_TX | fetch flags)`.
   */
  private sendTxGetData(peer: Peer, items: InvVector[]): void {
    for (let i = 0; i < items.length; i += MAX_GETDATA_ITEMS) {
      const batch = items.slice(i, i + MAX_GETDATA_ITEMS);
      peer.send({ type: "getdata", payload: { inventory: batch } });
    }
  }

  /**
   * GAP2 fix — fork-aware download floor (reorg-drop fix part 1/2).
   *
   * Ports the shipped rustoshi Unit-E E3 download floor / blockbrew
   * StartBlockDownload ancestry descent, which mirror Bitcoin Core's
   * `FindNextBlocksToDownload` (net_processing.cpp ~1394-1543): the block we
   * still need on the path from the best header tip back to the fork point is
   * *every* block whose body we lack and which is NOT already on the active
   * validated chain — NOT just the blocks strictly above the active tip.
   *
   * THE BUG. hotbuns' `requestBlocks` walks the download frontier by HEIGHT
   * (`getHeaderByHeight`) starting from `nextHeightToRequest`, which is floored
   * at `chainState.bestHeight + 1` (the active validated tip). When a heavier
   * competing branch forks BELOW the active tip (active tip A at height H, fork
   * point F < H, fork tip B at height T with MORE work), HeaderSync makes B the
   * best header and `updateBestChain` re-points `headersByHeight` along the
   * fork for heights F+1..T. But the height floor stays at H+1, so only the
   * fork bodies ABOVE the active tip (H+1..T) are ever requested. The BRIDGING
   * fork bodies F+1..H — the blocks the reorg needs to rebuild the UTXO view
   * from the fork point up — are never getdata-d, so the connect fails forever
   * with "UTXO view best block <F> does not match block prev ... (view-out-of-
   * sync)" and the node stays stuck on the minority chain. This was the SOLE
   * disqualifier proven by tools/reorg-hotbuns-proof.sh.
   *
   * THE FIX. When the best header tip is a competing fork that diverges at/below
   * the active validated tip and carries MORE work, descend the fork tip's
   * ancestry to its fork point (the deepest ancestor already on the active
   * chain) and lower `nextHeightToRequest` to fork-point+1, with NO active-tip
   * height floor. The existing height-keyed walk in `requestBlocks` then reads
   * the FORK branch entries (already re-pointed into `headersByHeight`) at those
   * heights and requests the bridging bodies. Bounded by
   * `MAX_FORK_DOWNLOAD_DEPTH` (a deeper reorg would be refused by the reorg
   * dispatch anyway).
   *
   * INVARIANT (no-fork / steady-state unchanged): when the best header tip is a
   * simple EXTENSION of the active tip (best header is a descendant of the
   * active tip, the normal IBD / steady-state case), this is a no-op — the fork
   * point IS the active tip, fork-point+1 == the existing floor, so the floor
   * is never lowered and the download set is byte-for-byte identical. Only a
   * genuine below/beside-tip heavier fork moves the floor.
   *
   * No-op when no ChainStateManager is wired (the active validated tip can't be
   * resolved), preserving the legacy floor for stub/test connectors.
   */
  private lowerDownloadFloorForFork(bestHeader: HeaderChainEntry): void {
    if (!this.chainStateManager) return;

    const activeTip = this.chainStateManager.getBestBlock();

    // Fast path / steady-state guard: if the best header tip IS the active tip,
    // or carries no more work than it, there is no heavier competing branch to
    // bridge. A simple extension (best header descends from the active tip) has
    // strictly more work but its fork point is the active tip itself, so the
    // descent below would stop immediately at H and never lower the floor —
    // but short-circuiting here keeps the common path allocation-free.
    if (bestHeader.hash.equals(activeTip.hash)) return;
    if (bestHeader.chainWork <= activeTip.chainWork) return;

    // Build the active validated chain's ancestor hash-set, walking up from the
    // active tip, bounded by MAX_FORK_DOWNLOAD_DEPTH. Membership in this set is
    // our "on the active chain" test (Bitcoin Core CChain::Contains), used to
    // locate the fork point as the deepest fork ancestor already on-chain.
    const activeChainHashes = new Set<string>();
    {
      let cursor: HeaderChainEntry | undefined = this.headerSync.getHeader(
        activeTip.hash
      );
      let steps = 0;
      while (cursor && steps <= this.reorgDepthCap()) {
        activeChainHashes.add(cursor.hash.toString("hex"));
        if (cursor.height === 0) break; // reached genesis
        cursor = this.headerSync.getHeader(cursor.header.prevBlock);
        steps++;
      }
    }
    // If the active tip header itself isn't resolvable (pre-init / stub), bail
    // and leave the legacy floor untouched.
    if (activeChainHashes.size === 0) return;

    // Descend the fork tip's ancestry until we reach the fork point — the first
    // ancestor that is on the active chain. The fork point's child (the first
    // fork-branch block ABOVE it) is the lowest height whose body we must
    // request. Bounded by MAX_FORK_DOWNLOAD_DEPTH so a malformed/deep fork can't
    // drive the floor arbitrarily low (a reorg that deep would be refused).
    let forkChildHeight: number | null = null;
    let cursor: HeaderChainEntry | undefined = bestHeader;
    let steps = 0;
    while (cursor && steps <= this.reorgDepthCap()) {
      if (activeChainHashes.has(cursor.hash.toString("hex"))) {
        // `cursor` is the fork point (on the active chain). Its child on the
        // fork branch is height cursor.height + 1.
        forkChildHeight = cursor.height + 1;
        break;
      }
      if (cursor.height === 0) {
        // Reached genesis without meeting the active chain — the fork diverges
        // at genesis (fork point height 0), so the first body we need is
        // height 1. This is the tools/reorg-hotbuns-proof.sh topology.
        forkChildHeight = 1;
        break;
      }
      cursor = this.headerSync.getHeader(cursor.header.prevBlock);
      steps++;
    }

    if (forkChildHeight === null) {
      // Did not reach the fork point within MAX_FORK_DOWNLOAD_DEPTH — the
      // divergence is deeper than the reorg dispatch would accept. Leave the
      // floor where it is; the reorg would be refused regardless.
      console.log(
        `[fork-download] competing fork tip height ${bestHeader.height} forks ` +
          `deeper than MAX_FORK_DOWNLOAD_DEPTH=${MAX_FORK_DOWNLOAD_DEPTH} below the ` +
          `active tip (height ${activeTip.height}); not lowering the download floor ` +
          `(a reorg this deep would be refused)`
      );
      return;
    }

    // Extension guard (Core parity + CPU-spin fix). A best header that simply
    // EXTENDS the active tip has its fork point AT the active tip, so
    // forkChildHeight == activeTip.height + 1. That is NOT a below-tip reorg:
    // there are no bridging bodies at/below the frontier to pull in, and the
    // ordinary height-ascending download already handles it. Only a fork whose
    // fork point is STRICTLY BELOW the active tip (forkChildHeight <=
    // activeTip.height, i.e. fork point height < activeTip.height) needs the
    // floor lowered below the frontier.
    //
    // The pre-fix code only gated on `forkChildHeight < nextHeightToRequest`,
    // so whenever the request pointer had already advanced past an extension
    // tip (nextHeightToRequest > activeTip.height + 1 — the normal "headers
    // ahead of blocks" / near-tip state), it re-lowered the floor and re-logged
    // "[fork-download] ... forks below the active tip" on EVERY requestBlocks /
    // onHeadersProcessed call. With headers streaming in near the tip this
    // became an unbounded log flood that pegged the event loop, starved the P2P
    // keep-alive (peers timed out to zero), and wedged RPC — observed live at
    // the chain tip where the fork point equalled the active tip in every
    // occurrence (a mislabelled extension, never a real below-tip fork). Making
    // the extension case a true no-op — as this function's own contract already
    // promised — eliminates the spin while leaving genuine below-tip reorgs
    // (forkChildHeight <= activeTip.height) fully handled.
    if (forkChildHeight > activeTip.height) {
      return;
    }

    // Only LOWER the floor — never raise it. A genuine below-tip fork lowers the
    // floor to the fork point + 1 so the bridging bodies (fork point + 1 ..
    // active tip) are requested.
    if (forkChildHeight < this.state.nextHeightToRequest) {
      console.log(
        `[fork-download] heavier competing fork (tip height ${bestHeader.height}, ` +
          `work ${bestHeader.chainWork}) forks below the active tip ` +
          `(height ${activeTip.height}); lowering block-download floor ` +
          `from ${this.state.nextHeightToRequest} to ${forkChildHeight} so the ` +
          `bridging fork bodies are requested`
      );
      this.state.nextHeightToRequest = forkChildHeight;
    }
  }

  /**
   * Request the next batch of blocks from available peers.
   */
  requestBlocks(): void {
    if (this.syncHalted !== null || !this.running || !this.peerManager) {
      return;
    }

    const bestHeader = this.headerSync.getBestHeader();
    if (!bestHeader) {
      return;
    }

    // GAP2 fix (reorg-drop part 1/2): before walking the by-height download
    // frontier, lower the floor to the fork point if the best header tip is a
    // heavier competing branch forking at/below the active validated tip. This
    // is the ONLY change to the request path — for a simple extension (normal
    // IBD / steady state) it is a no-op and the floor is untouched.
    this.lowerDownloadFloorForFork(bestHeader);

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

      // GAP3 fix (reorg-drop part 2/2): skip a competing-fork bridging body we
      // already persisted to disk as a side branch (it was evicted from the
      // in-memory buffer to bound memory). Re-requesting it would loop until the
      // fork tip drives the reorg; the body is already on disk for the reorg
      // dispatch to read, so there is nothing to fetch.
      if (this.forkBodiesOnDisk.has(hashHex)) {
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
    // Register each requested block with the peer's in-flight tracker so
    // PeerManager.evictStaleOutboundPeers() can see this peer is actively
    // serving a download and won't drop it before delivery. Without this,
    // hasBlocksInFlight() always returns false in production (only the
    // BlockSync-local pendingBlocks map was tracking requests), peers got
    // evicted after STALE_TIP_THRESHOLD_MS (30 min) of "no blocks", and
    // pend grew to capacity while dl stayed at 0 — see bug #132.
    for (const hash of hashes) {
      peer.addBlockInFlight(hash.toString("hex"));
    }

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
    // Reorg-to-ancestor HALT (crash-recovery / reorg-integrity class): once the
    // sync loop has hard-failed on an impossible reorg it must NOT keep spinning.
    if (this.syncHalted !== null) {
      return;
    }
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
            // Send duplicate getdata to up to 3 other peers.
            //
            // Two-pass selection: prefer recently-active peers (< 120 s since
            // last response), but if fewer than 3 qualify (the common case
            // during IBD when every peer is busy serving its own queue),
            // fall back to ANY non-original connected peer.
            //
            // Pre-fix the "active peer" filter silently rejected every
            // candidate during a fleet-wide stall — `lastResponse` for ALL
            // peers was > 120 s old because they were all queue-blocked —
            // so `duplicatesSent` stayed 0 and the only racer was the
            // original (already-slow) peer.  Observed on mainnet 2026-05-27
            // as ~5-min stalls at h=76133 with `pend=42 dl=23` and 10
            // connected peers, but the DUP-REQ "sent to N extra peers" log
            // line was missing for the duration (N=0 → not logged).
            let duplicatesSent = 0;
            // Pass 1: recently-active peers (preferred).
            for (const p of connPeers) {
              if (duplicatesSent >= 3) break;
              const pk = `${p.host}:${p.port}`;
              if (pk === pending.peer) continue;
              const pi = this.peerInFlight.get(pk);
              if (pi && pi.lastResponse > 0 && (Date.now() - pi.lastResponse) < 120000) {
                this.sendGetData(p, [headerEntry.hash]);
                duplicatesSent++;
              }
            }
            // Pass 2: fall back to any non-original peer if Pass 1 came up
            // empty (all peers saturated / no recent responses).  Better to
            // ask a "stale" peer than to wait another 30 s for the next
            // DUP-REQ cycle.
            if (duplicatesSent === 0) {
              for (const p of connPeers) {
                if (duplicatesSent >= 3) break;
                const pk = `${p.host}:${p.port}`;
                if (pk === pending.peer) continue;
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
        // Core AcceptBlock / ActivateBestChain parity — DEFERRAL, not failure.
        //
        // `connectBlock` reported that a heavier competing fork tip could not be
        // connected yet because a bridging body (fork+1 .. old active tip) is
        // not on disk — the fork tip arrived over P2P ahead of its bridge. This
        // is a transient ordering condition, NOT a validation failure: the block
        // is perfectly valid, the peer is honest, and no view was mutated.
        //
        // Core keeps the block on disk and waits for ActivateBestChainStep to
        // find every block on the most-work path with BLOCK_HAVE_DATA before
        // connecting. We mirror that here: KEEP the fork tip buffered (do NOT
        // discard it), leave the peer alone (NO block-mutated punishment, NO
        // header invalidation, NO consecutive-failure escalation), re-request
        // the still-missing bridging bodies, and stop processing at this height.
        // When the bridge lands (side-branch stored by `maybeStoreForkBody`, which
        // re-enters `processOrderedBlocks`) the fork-tip connect is retried and
        // the reorg completes. Without this, a valid competing block was rejected
        // and the honest peer was banned as "block-mutated" — the reorg wedge.
        if (this.reorgDeferredMissingBodies) {
          this.reorgDeferredMissingBodies = false;
          console.log(
            `[reorg] fork tip at height ${height} deferred pending bridging bodies; ` +
              `keeping it buffered and re-requesting the bridge (peer NOT punished)`
          );
          this.requestBlocks();
          break;
        }

        // Capture the failure reason BEFORE any retry-recovery work mutates
        // state — the classifier needs the raw error string to pick the
        // right banner.
        const failureMsg = this.lastConnectError;

        // ── Reorg-to-ancestor HALT (crash-recovery / reorg-integrity class) ──
        //
        // The block we keep being asked to connect at this height is ALREADY an
        // ancestor of the active validated tip — it is on the active chain, so
        // there is nothing to reorg to and the connect is an IMPOSSIBLE target.
        // Its prevBlock necessarily differs from the (higher) active tip the UTXO
        // view points at, so the `view-out-of-sync` gate rejects it on every
        // attempt; the normal rewind-to-`lastFlushedHeight+1` recovery just
        // re-selects the SAME ancestor and retries forever (174k+ spins observed
        // after a spurious header invalidation: invalidate 255587 → the loop
        // fixated on reconnecting 255556, an already-connected ancestor).
        //
        // Core never reaches this state — ActivateBestChainStep only connects
        // blocks NOT already in m_chain. Here we detect the impossible target and
        // HARD-HALT loudly instead of livelocking. Gated to the view-out-of-sync
        // signal so a genuine reorg (whose target is NOT an active ancestor) is
        // unaffected.
        if (
          /view-out-of-sync/i.test(failureMsg) &&
          this.isAncestorOfActiveTip(headerEntry.hash, height)
        ) {
          const activeTip = this.chainStateManager!.getBestBlock();
          this.haltSync(
            `impossible reorg: block ${hashHex.slice(0, 16)} at height ${height} ` +
              `is already an ancestor of the active tip ` +
              `${activeTip.hash.toString("hex").slice(0, 16)} (height ${activeTip.height}); ` +
              `the reconnect target can never satisfy the view-out-of-sync gate`
          );
          this.state.downloadedBlocks.delete(hashHex);
          this.downloadedBlockPeers.delete(hashHex);
          break;
        }

        // Try to extract failing input/tx coordinates from the error string
        // for faster forensic triage. Mirrors lunarblock d9d9af4.
        const inputMatch = failureMsg.match(/input (\d+)/);
        const txMatch = failureMsg.match(/tx ([0-9a-fA-F]+)/);
        const coords =
          inputMatch || txMatch
            ? ` [tx=${txMatch?.[1] ?? "?"} input=${inputMatch?.[1] ?? "?"}]`
            : "";

        // Bitcoin Core InvalidBlockFound parity (validation.cpp): when a block
        // on the best-header chain fails a genuine CONSENSUS rule, flag its
        // header invalid and re-seat the best-header / by-height index on the
        // active tip we're actually on.  Without this, the invalid block's
        // header stays selected as getHeaderByHeight(height), so a competing
        // VALID sibling at the same height that only TIES it on work can never
        // be adopted (processOrderedBlocks keeps looking up the invalid block's
        // absent body and breaks) — the tip lags Core by one block after an
        // invalid-mid-reorg or an invalid direct child of the active tip.
        //
        // Gated on the CONSENSUS class only: a transient chainstate/undo error
        // must NOT brand a valid header invalid (Core only calls
        // InvalidBlockFound for state.IsInvalid(), never for system errors).
        // In both the reorg-abort and the direct-extension cases the active
        // chain tip is `chainStateManager.getBestBlock()` (the reorg dispatch
        // never advanced it, since the connect failed).
        if (
          this.chainStateManager &&
          headerEntry &&
          classifyCallbackError(failureMsg) === "consensus"
        ) {
          const activeTip = this.chainStateManager.getBestBlock();
          this.headerSync.invalidateHeader(headerEntry.hash, activeTip.hash);
        }

        // Track consecutive failures at the same height to detect permanent
        // UTXO corruption (e.g. a coin was DELETEd from LevelDB during a
        // partial flush but the chain state height was never advanced).
        if (height === this.lastFailedHeight) {
          this.consecutiveFailures++;
        } else {
          this.consecutiveFailures = 1;
          this.lastFailedHeight = height;
        }

        // G16 fix: score the peer that delivered this invalid block — but ONLY
        // for a genuine CONSENSUS violation, mirroring Core's
        // MaybePunishNodeForBlock (net_processing.cpp:1906), which punishes only
        // BLOCK_CONSENSUS / BLOCK_MUTATED (and header/prev-invalid), and NEVER a
        // transient internal condition such as a missing bridging body or the
        // `view-out-of-sync` coordination gate (in Core the latter is an
        // assert that never surfaces from a peer).
        //
        // Pre-fix this ban fired unconditionally on ANY connect-false, so a
        // VALID competing block that merely lost a download race with its own
        // bridge (classified "unknown", not "consensus") got the honest peer
        // disconnected as "block-mutated" — the P2P-robustness bug. The deferral
        // path above already returns early for the specific missing-bridge case;
        // this gate is the defence-in-depth generalisation: a non-consensus
        // connect failure must never punish the delivering peer.
        const blockPeerKey = this.downloadedBlockPeers.get(hashHex);
        if (
          blockPeerKey &&
          this.peerManager &&
          classifyCallbackError(failureMsg) === "consensus"
        ) {
          const deliverer = this.peerManager.getConnectedPeers()
            .find((p) => `${p.host}:${p.port}` === blockPeerKey);
          if (deliverer) {
            // Map the reject reason to Core's block-level punishment token so
            // the log names the real rule, not a blanket "block-mutated".
            const rejectToken = bip22FromConnectError(failureMsg);
            deliverer.misbehaving(100, rejectToken);
          }
        }

        console.error(
          `Block validation failed at height ${height} (attempt ${this.consecutiveFailures})${coords}, discarding and re-requesting: ${failureMsg}`
        );
        this.state.downloadedBlocks.delete(hashHex);
        this.downloadedBlockPeers.delete(hashHex);

        // Reset the UTXO cache to avoid corrupt state from partial processing.
        //
        // CRITICAL — view-best-block reconciliation on failure:
        // `coreConnectBlockChecks` advances the UTXO view's best-block
        // pointer (`utxoManager.setBestBlock`) for a block that passes its
        // in-memory checks *before* the chain-state flush.  IBD only flushes
        // at the tip or every FLUSH_INTERVAL blocks, so a block can connect
        // in-memory (view pointer advanced) without the persisted
        // `CHAIN_STATE` record advancing.  If the very next block then fails
        // validation, a bare `clearCache()` discards the cache but leaves
        // `CoinsViewDB.bestBlockHash` pointing AHEAD of the on-disk tip.
        // The retry re-reads that stale pointer through the fresh cache's
        // lazy-load and trips the `view-out-of-sync` gate
        // (validation.cpp:2333) — a permanent wedge, since every retry
        // repeats the same clear.  This was the May 2026 mainnet h=950148
        // stall: block 950149 failed a consensus check, the view pointer
        // was stuck at 950148, and 950148 could never reconnect.
        //
        // Fix: re-point the view at the block the UTXO set on disk actually
        // reflects — the last *flushed* block (`lastFlushedHeight`).  The
        // retry then sees a consistent view and re-processes from
        // `lastFlushedHeight + 1` correctly.  Falls back to a bare clear
        // (old behaviour) only if that header can't be resolved.
        //
        // REORG-ABORT EXCEPTION (Core ActivateBestChainStep parity): if the
        // failed connect was a REORG whose new tip was invalid, connectBlock
        // has ALREADY atomically restored the UTXO view to the original
        // active-chain tip (`reorgAbortRestoredTip`).  We MUST NOT re-run the
        // `getHeaderByHeight(lastFlushed)` clearCache here: mid-reorg, the
        // best-header chain's height entry is the LOSING competing fork (B2),
        // so this clear would re-point the view at the wrong branch and settle
        // the node there — the exact Reorg-wave-3 bug.  Skip + reset the signal.
        if (this.reorgAbortRestoredTip !== null) {
          console.log(
            `[reorg] connect-fail cleanup skipped — active chain already restored ` +
              `to ${this.reorgAbortRestoredTip.toString("hex").slice(0, 16)} by connectBlock`
          );
          this.reorgAbortRestoredTip = null;
        } else {
        const flushedTipEntry = this.headerSync.getHeaderByHeight(
          this.lastFlushedHeight
        );
        if (flushedTipEntry && this.lastFlushedHeight > 0) {
          this.utxoManager.clearCache(flushedTipEntry.hash);
        } else if (this.lastFlushedHeight === 0) {
          // Pre-first-flush: the on-disk UTXO set is the genesis state.
          // The all-zero "fresh view" sentinel is correct here, so a bare
          // clear (which leaves the pointer untouched / re-seeds all-zero
          // on next lazy-load) is exactly right.
          this.utxoManager.clearCache();
        } else {
          // lastFlushedHeight > 0 but its header is missing — should not
          // happen (headers are synced before blocks).  Bare clear keeps
          // the old behaviour; the consecutive-failure banner below will
          // still surface the stall to the operator.
          console.warn(
            `[connect-fail] could not resolve header for lastFlushedHeight=` +
              `${this.lastFlushedHeight}; UTXO view best-block left unreconciled`
          );
          this.utxoManager.clearCache();
        }
        }

        if (this.consecutiveFailures >= 3) {
          // 2026-05-02 diagnostic split (mirrors lunarblock d9d9af4): classify
          // the captured error so the bounded-retry banner names the right
          // failure class. The original banner pinned blame on chainstate
          // regardless of cause and burned hours of operator time on
          // tapscript / script-rule mismatches (944,279 MAX_OPS_PER_SCRIPT).
          const cls = classifyCallbackError(failureMsg);

          if (cls === "consensus") {
            // Consensus rule mismatch: the chainstate is recoverable; do NOT
            // exit with EX_CONFIG (which signals the operator to wipe). The
            // bounded retry will keep failing until the rule is fixed in
            // code, but the on-disk UTXO set is fine.
            console.error(
              `\n*** [CONSENSUS-FAILURE] Block ${height} (${hashHex.slice(0, 16)}...) ` +
                `failed validation ${this.consecutiveFailures} consecutive times${coords}. ***\n` +
                `Error: ${failureMsg}\n\n` +
                `This is a consensus rule mismatch with Bitcoin Core, NOT chainstate\n` +
                `corruption — file a bug report against hotbuns. The chainstate is\n` +
                `recoverable; do NOT wipe the data directory. Once the rule is fixed\n` +
                `in code, restart and the bounded retry will resume from this height.\n`
            );
            // Rewind to last flushed height so the next attempt re-processes
            // from a known-good DB state. Do NOT process.exit — keep the node
            // alive so RPC remains queryable for triage.
            const rewindTo = this.lastFlushedHeight + 1;
            this.state.nextHeightToProcess = rewindTo;
            this.state.nextHeightToRequest = rewindTo;
          } else if (cls === "chainstate") {
            // Genuine on-disk chainstate corruption: bodies/undo missing.
            // Operator must wipe + re-sync (or restore from a snapshot).
            console.error(
              `\n*** [CHAINSTATE-CORRUPTION] Permanent UTXO corruption detected at height ${height}. ***\n` +
                `Error: ${failureMsg}\n` +
                `The same block has failed validation ${this.consecutiveFailures} consecutive times.\n` +
                `This means the on-disk UTXO set has entries that were partially flushed\n` +
                `during a previous unclean shutdown, or the chainstate is missing\n` +
                `block-body / undo data.\n\n` +
                `To recover, delete the data directory and restart:\n` +
                `  rm -rf <datadir>/blocks.db && restart hotbuns\n`
            );
            // Exit with a distinctive code so monitoring scripts can detect this
            process.exit(78); // EX_CONFIG from sysexits.h
          } else {
            // Unclassified: emit a neutral banner with the raw error so the
            // operator can triage manually. Avoid the misleading
            // "Permanent UTXO corruption" label here.
            console.error(
              `\n*** [CONNECT-FAILURE] Block ${height} (${hashHex.slice(0, 16)}...) ` +
                `failed validation ${this.consecutiveFailures} consecutive times${coords}. ***\n` +
                `Error: ${failureMsg}\n\n` +
                `Triage:\n` +
                `  - If the error looks like a script/tx-validation rule (tapscript,\n` +
                `    SCRIPT_SIZE, MAX_OPS, signature, witness commitment, sigops, etc.),\n` +
                `    treat as a consensus-rule bug and file against hotbuns. Do NOT wipe.\n` +
                `  - If it looks like missing on-disk data (undo data missing, block\n` +
                `    body missing, LEVEL_DATABASE_NOT_OPEN), treat as chainstate\n` +
                `    corruption and wipe + re-sync.\n` +
                `  - Add the new pattern to classifyCallbackError() in sync/blocks.ts\n` +
                `    so future occurrences classify cleanly.\n`
            );
            // Conservative fallback: rewind and let the bounded retry keep
            // running. Don't exit on unknown errors — that's been the most
            // expensive misdiagnosis class.
            const rewindTo = this.lastFlushedHeight + 1;
            this.state.nextHeightToProcess = rewindTo;
            this.state.nextHeightToRequest = rewindTo;
          }
        } else {
          // Normal retry: rewind to last flushed height so we re-process
          // from a known-good DB state.
          const rewindTo = this.lastFlushedHeight + 1;
          this.state.nextHeightToProcess = rewindTo;
          this.state.nextHeightToRequest = rewindTo;
        }

        // Discard any buffered blocks that are now stale
        this.state.downloadedBlocks.clear();
        this.downloadedBlockPeers.clear();

        break;
      }

      // Remove from downloaded
      this.state.downloadedBlocks.delete(hashHex);
      this.downloadedBlockPeers.delete(hashHex);
      // Help V8 GC by nulling block reference
      block = null as any;

      // Advance to next height
      this.state.nextHeightToProcess++;
      this.blocksProcessed++;

      // GAP3 fix (reorg-drop part 2/2): a successful connect at this height may
      // have been the fork tip whose pre-connect reorg dispatch incorporated the
      // bridging side-branch bodies into the active chain. Those bodies are now
      // on the active chain (or, after a frontier advance, no longer competing),
      // so drop their stale on-disk markers — they must not keep suppressing
      // re-requests if a DIFFERENT future fork needs a body at the same height.
      // Bounded, no-op in the common (no recorded fork bodies) case.
      if (this.forkBodiesOnDisk.size > 0) {
        for (const fhex of this.forkBodiesOnDisk) {
          const fEntry = this.headerSync.getHeader(Buffer.from(fhex, "hex"));
          if (!fEntry || fEntry.height < this.state.nextHeightToProcess) {
            this.forkBodiesOnDisk.delete(fhex);
          }
        }
      }

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
   * Record a connectBlock failure reason so the bounded-retry banner can
   * classify it (consensus vs chainstate vs unknown). Called by every
   * warn/error site inside connectBlock that returns false.
   */
  private recordConnectError(msg: string): void {
    this.lastConnectError = msg;
  }

  /**
   * Write txindex entries for every transaction in a connected block
   * (Pattern C0 connect side).
   *
   * Mirrors the put loop in
   * `bitcoin-core/src/index/txindex.cpp::CustomAppend` — one
   * (txid -> { blockHash, offset=0, length=0 }) entry per tx.  Offset
   * and length are placeholders: the hotbuns read path
   * (rpc/server.ts::findTxInBlock) iterates the block body to locate
   * the matching tx, so the precise byte offset isn't load-bearing.
   * If a future change wants to seek directly into the block body, the
   * fields are already serialized into the on-disk entry by
   * `db.putTxIndex`.
   *
   * Best-effort: a put failure is logged and ignored.  txindex is an
   * optional secondary index in Bitcoin Core (see init.cpp's
   * `-txindex` flag); a missing entry surfaces as
   * `getrawtransaction → "no such tx"`, never as chain-state
   * corruption.
   *
   * Reference:
   *   - CORE-PARITY-AUDIT/_txindex-revert-on-reorg-fleet-result-2026-05-05.md
   *     (Pattern C0, hotbuns row)
   *   - sibling Pattern X commit `29879e5` (BIP-34 ancestor-relative)
   *     and Pattern B commit `4fdbc4f` (mempool refill on reorg) which
   *     established the side-branch storage + mempool-refill scaffolding
   *     this entry stacks on.
   *   - parent commit `153c60c` (BIP-141 witness-commitment audit).
   */
  private async writeTxIndexForBlock(
    block: Block,
    blockHash: Buffer
  ): Promise<void> {
    const ops: BatchOperation[] = [];
    const { getTxId } = await import("../validation/tx.js");
    for (const tx of block.transactions) {
      const txid = getTxId(tx);
      // Serialize entry inline so we don't take a dependency on the
      // private serializeTxIndex helper in database.ts.  Format must
      // match: hash(32) || offset(uint32 LE) || length(uint32 LE).
      const value = Buffer.alloc(40);
      blockHash.copy(value, 0);
      // offset and length default to 0 (placeholder; see helper docstring).
      ops.push({
        type: "put",
        prefix: DBPrefix.TX_INDEX,
        key: txid,
        value,
      });
    }
    if (ops.length === 0) return;
    try {
      await this.db.batchWrite(ops);
    } catch (err) {
      console.warn(
        `[txindex] failed to write entries for block ${blockHash
          .toString("hex")
          .slice(0, 16)}: ${err instanceof Error ? err.message : String(err)}`
      );
    }
  }

  /**
   * Disconnect a single block at `height`, restoring spent UTXOs from
   * undo data and removing UTXOs the block created.  Best-effort:
   * returns false (and logs) if undo data is missing on disk, in
   * which case the caller should fall back to the connect-only path
   * (the block remains connected; chain state advances but UTXO
   * divergence vs. Core results — same behaviour as pre-fix).
   *
   * Mirrors the disconnect loop in chain/state.ts::reorganize but
   * runs inside BlockSync's own UTXOManager.  We can't reuse
   * chain/state.ts because that path has its own UTXOManager
   * instance — see the dual-UTXOManager note in the Pattern B fix
   * commit for details.
   *
   * Multi-block atomicity (Pattern D, post-`9b10550`): if `pendingOps`
   * is provided, the txindex deletes are APPENDED to it instead of
   * being written via a standalone `db.batchWrite`.  The caller
   * (`handleReorgUtxoAndCollect` → `connectBlock`) then funnels the
   * accumulated ops through `UTXOManager.flushDirty(extraOps)` so the
   * full reorg (N disconnects + M reconnects + new-tip connect) lands
   * in a single ClassicLevel batch.  When `pendingOps` is undefined
   * (e.g. unit tests that exercise this path in isolation), falls
   * back to the legacy direct-write behaviour for backwards compat.
   */
  private async disconnectBlockUtxo(
    block: Block,
    height: number,
    blockHash: Buffer,
    pendingOps?: BatchOperation[]
  ): Promise<boolean> {
    const undoData = await this.db.getUndoData(blockHash);
    if (!undoData) {
      console.warn(
        `[reorg-disconnect] undo data missing for block ${blockHash.toString("hex").slice(0, 16)} at height ${height}; cannot disconnect`
      );
      return false;
    }
    let spentOutputs;
    try {
      const { deserializeUndoData } = await import("../chain/utxo.js");
      spentOutputs = deserializeUndoData(undoData);
    } catch (err) {
      console.warn(
        `[reorg-disconnect] undo data deserialize failed: ${
          err instanceof Error ? err.message : String(err)
        }`
      );
      return false;
    }

    // ── W92 Core gate: blockUndo / block size consistency ──
    //
    // Mirrors bitcoin-core/src/validation.cpp:2190-2193.  Aborts the
    // disconnect BEFORE any UTXO mutation when the undo file is
    // truncated/corrupted, so we don't leave the UTXO set half-restored.
    let expectedUndoEntries = 0;
    for (let i = 1; i < block.transactions.length; i++) {
      expectedUndoEntries += block.transactions[i].inputs.length;
    }
    if (spentOutputs.length !== expectedUndoEntries) {
      console.warn(
        `[reorg-disconnect] block and undo data inconsistent for ${blockHash
          .toString("hex")
          .slice(0, 16)} at h=${height}: undo has ${spentOutputs.length} entries, expected ${expectedUndoEntries}`
      );
      return false;
    }

    // Build per-outpoint lookup so the per-input restore can find
    // the matching SpentUTXO without an O(n²) loop.
    const spentByOutpoint = new Map<string, (typeof spentOutputs)[0]>();
    for (const spent of spentOutputs) {
      const key = `${spent.txid.toString("hex")}:${spent.vout}`;
      spentByOutpoint.set(key, spent);
    }

    // ── W92 Core gate: disconnect-side BIP-30 exception ──
    //
    // Mirrors bitcoin-core/src/validation.cpp:2201-2202.  See the
    // disconnect-side BIP30 doc on bip30DisconnectExceptionBlocks in
    // consensus/params.ts.
    const blockHashHex = Buffer.from(blockHash).reverse().toString("hex");
    const fEnforceBIP30 = !this.params.bip30DisconnectExceptionBlocks.some(
      (ex) => ex.height === height && ex.blockHashHex === blockHashHex
    );

    let fClean = true;
    const { DisconnectResult } = await import("../chain/utxo.js");

    // Process transactions in reverse order so intra-block dependencies
    // unwind correctly (mirrors chain/state.ts::disconnectBlock).
    for (let txIndex = block.transactions.length - 1; txIndex >= 0; txIndex--) {
      const tx = block.transactions[txIndex];
      const txid = (await import("../validation/tx.js")).getTxId(tx);
      const txIsCoinbase = isCoinbase(tx);
      const isBIP30ExceptionTx = txIsCoinbase && !fEnforceBIP30;

      // Remove outputs created by this block.  W92 Core gate (4-way
      // match: existence + value/scriptPubKey + height + coinbase).
      // Unspendable outputs are skipped because they were never added
      // in the first place — see CoinsViewCache.addCoin.
      for (let vout = 0; vout < tx.outputs.length; vout++) {
        const outScript = tx.outputs[vout].scriptPubKey;
        const unspendable =
          (outScript.length > 0 && outScript[0] === 0x6a) ||
          outScript.length > 10000;
        if (unspendable) continue;

        const spentCoin = await this.utxoManager.removeUTXO(txid, vout);
        const isSpent = spentCoin !== null;
        const valueMatches = spentCoin && spentCoin.txOut.value === tx.outputs[vout].value;
        const scriptMatches =
          spentCoin && spentCoin.txOut.scriptPubKey.equals(tx.outputs[vout].scriptPubKey);
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
            fClean = false;
          }
        }
      }

      // Restore spent inputs (coinbase has none).  W92 gates: per-tx undo
      // size check + reverse-iterate inputs + ApplyTxInUndo tristate.
      if (!txIsCoinbase) {
        for (let j = tx.inputs.length - 1; j >= 0; j--) {
          const input = tx.inputs[j];
          const key = `${input.prevOut.txid.toString("hex")}:${input.prevOut.vout}`;
          const spent = spentByOutpoint.get(key);
          if (!spent) {
            // Missing undo entry: surface as a warning but keep going
            // so we don't half-disconnect.  Other entries may still
            // produce a useful partial-restore.
            console.warn(
              `[reorg-disconnect] missing undo entry for ${key} in block ${blockHash.toString("hex").slice(0, 16)}`
            );
            fClean = false;
            continue;
          }
          const res = await this.utxoManager.applyInputUndo(spent, input.prevOut);
          if (res === DisconnectResult.DISCONNECT_FAILED) {
            console.warn(
              `[reorg-disconnect] applyInputUndo FAILED for ${key} in block ${blockHash
                .toString("hex")
                .slice(0, 16)} (missing metadata + no sibling)`
            );
            return false;
          }
          if (res === DisconnectResult.DISCONNECT_UNCLEAN) {
            fClean = false;
          }
        }
      }
    }

    if (!fClean) {
      console.warn(
        `[reorg-disconnect] block ${blockHash.toString("hex").slice(0, 16)} at h=${height} ` +
          `disconnected with UTXO inconsistencies (DISCONNECT_UNCLEAN)`
      );
    }

    // W92 Core gate: SetBestBlock(pprev) — keep the UTXO view's
    // in-memory hashBlock aligned with the just-rolled-back state.
    this.utxoManager.setBestBlock(block.header.prevBlock);

    // NOTE: txindex entries are intentionally NOT deleted on disconnect.
    // Bitcoin Core's TxIndex has no CustomRemove override — the default
    // BaseIndex::CustomRemove (base.h:136) is a no-op returning true.
    // Core keeps txid->block entries for disconnected blocks so that
    // getrawtransaction can still resolve a tx from an orphaned block.
    // Reference: bitcoin-core/src/index/txindex.{h,cpp} — only CustomAppend
    // is defined; there is no CustomRemove / BlockDisconnected erase.

    // ── BIP-157 Phase 2: filter-chain rewind on disconnect ──
    //
    // Symmetric with the `filterIndex.indexBlock(...)` call in
    // `connectBlock` (line ~2418): the filter-header chain must rewind
    // to the previous block's filter header so that the subsequent
    // intermediate reconnect (in `handleReorgUtxoAndCollect`) and final
    // new-tip connect compute their filter headers against the active
    // chain's prev-header, not the disconnected fork's.
    //
    // Mirrors bitcoin-core/src/index/blockfilterindex.cpp::CustomRemove
    // — the BaseIndex worker's `BlockDisconnected` notification handler.
    //
    // Best-effort: a filter-build/storage failure must NOT roll back
    // the disconnect.  Mirrors Core's IndexFailure handling in
    // BaseIndex which logs + sets m_synced = false rather than killing
    // the chain rewind.  Issued OUTSIDE `pendingOps` because the
    // FILTER_TIP write is small (~36 bytes), idempotent on
    // double-call (guarded by `currentHeight === height`), and the
    // filter index uses its own DB prefix range so cannot conflict
    // with the reorg batch.
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

    // ── coinstatsindex rewind on disconnect (reorg) ──
    //
    // Symmetric with the `coinStatsIndex.indexBlock(...)` call in
    // `connectBlock`: drop the per-height snapshot at `height` so the running
    // state for the new tip is the already-persisted height-1 snapshot. No
    // recomputation needed — the per-height snapshots are self-contained.
    // Mirrors bitcoin-core/src/index/coinstatsindex.cpp::CustomRewind.
    //
    // Best-effort: a rewind failure must NOT roll back the disconnect.
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

    // ── txospenderindex rewind on disconnect (LIVE reorg) ──
    //
    // Symmetric with the `txoSpenderIndex.indexBlock(...)` call in
    // `connectBlock`: RE-DERIVE the disconnected block's spend keys from its OWN
    // inputs and erase them (Core CustomRemove). This is the LIVE reorg path
    // (P2P / submitblock heavier-branch reorg) — the heavier branch orphans this
    // block and its spend records are erased here, BEFORE the new branch's
    // blocks are connected (disconnect-before-connect, inherited from this
    // reorg loop). Mirrors bitcoin-core/src/index/txospenderindex.cpp::CustomRemove.
    //
    // Best-effort: a rewind failure must NOT roll back the disconnect.
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

    // Roll back wallet credits this block created — symmetric with the
    // emitBlockConnected on the connect side. The BlockSync reorg path bypasses
    // chainState.disconnectBlock (state.ts:934, the only other blockDisconnected
    // emitter), so without this a P2P-driven reorg would leave phantom wallet
    // coins from the disconnected fork (reconstructible only by rescan). Core's
    // DisconnectTip fires BlockDisconnected for every disconnected block. The
    // wallet's disconnectBlock removes only outpoints this block created, so a
    // notify for a block whose connect was not credited (deep-IBD, atTip=false)
    // is a harmless no-op. Best-effort: never roll back the UTXO disconnect.
    if (this.chainStateManager) {
      try {
        this.chainStateManager.emitBlockDisconnected(block);
      } catch (err) {
        console.warn(
          `[blockDisconnected notify] non-fatal failure for block ${blockHash
            .toString("hex")
            .slice(0, 16)} at h=${height}: ${err instanceof Error ? err.message : String(err)}`
        );
      }
    }

    return true;
  }

  /**
   * Reorg dispatch: disconnect the old chain back to the fork point,
   * reconnect intermediate new-chain blocks, and collect old-chain
   * non-coinbase txs for mempool refill.  Caller passes a mutable
   * `disconnectedTxsOut` array which is populated in OLD-chain
   * disconnect order (newest first), and an optional `pendingOps`
   * buffer which accumulates every disk write the reorg would
   * otherwise issue piecemeal (txindex deletes, intermediate undo
   * data, intermediate txindex puts).
   *
   * Returns true when the UTXO set has been successfully
   * repositioned at the fork point AND intermediate blocks have
   * been connected — i.e. the next `coreConnectBlockChecks` call
   * will see the correct context.  Returns false on any step that
   * couldn't complete (missing undo, missing intermediate body,
   * intermediate connect failure, MAX_REORG_DEPTH exceeded,
   * MAX_REORG_BATCH_OPS exceeded); caller should fall back to the
   * legacy in-place connect (Pattern Y closure path) and accept the
   * UTXO divergence vs Core.
   *
   * Multi-block atomicity (Pattern D, post-`9b10550`): the
   * `pendingOps` buffer is appended to but not written.  The caller
   * funnels it through `UTXOManager.flushDirty(extraOps)` after the
   * new-tip connect succeeds, so the full reorg (N disconnects + M
   * reconnects + new-tip connect + chain-state) lands in a single
   * ClassicLevel batch.  Mirrors Bitcoin Core's `CDBBatch` pattern
   * in `validation.cpp::ActivateBestChainStep`, where every
   * disconnect/connect inside one chain-activation step rides one
   * batch.
   *
   * Bounded by `MAX_REORG_DEPTH` (depth of the old/new walks) and
   * `MAX_REORG_BATCH_OPS` (size of the accumulated batch buffer)
   * to cap memory growth on a malicious or pathological reorg.
   */
  private async handleReorgUtxoAndCollect(
    newTipBlock: Block,
    newTipHeight: number,
    oldTipHash: Buffer,
    disconnectedTxsOut: Transaction[],
    pendingOps?: BatchOperation[]
  ): Promise<boolean> {
    // Core-parity reorg-depth bound (see `reorgDepthCap`): UNBOUNDED on an
    // archive node (follows the most-work chain to the fork point at any depth,
    // like Core's ActivateBestChainStep), MIN_BLOCKS_TO_KEEP (288) on a pruned
    // node (the retained undo window). Peak memory on a deep archive reorg is
    // still bounded by MAX_REORG_BATCH_OPS below, which aborts cleanly on
    // overflow (legacy-connect fallback) — never a silent wrong-chain settle.
    const MAX_REORG_DEPTH = this.reorgDepthCap();
    // Memory cap on the accumulated batch buffer.  100 reorged blocks
    // × ~hundreds of txindex ops + a handful of undo/chain-state ops
    // tops out near ~250k entries on regtest fixtures; production
    // mainnet blocks (~3-4k txs) would hit the cap on a depth-60
    // reorg.  Aborting the reorg on overflow is the same fail-safe
    // behaviour as missing undo data — caller falls back to the
    // legacy in-place connect.
    const MAX_REORG_BATCH_OPS = 250_000;

    // Snapshot the OLD active-tip height BEFORE any disconnect mutates it, so
    // the post-reorg CChain::SetTip stale-entry sweep (below) knows the top of
    // the range of height->hash entries the old chain may have occupied above
    // the new tip.
    const oldTipHeightAtEntry = this.chainStateManager
      ? this.chainStateManager.getBestBlock().height
      : newTipHeight;

    // Step 1: walk back NEW chain from newTipBlock's prevBlock to
    // find the fork point.  We keep both the hash list (in
    // connect order: fork+1, fork+2, … newTip-1) and the set
    // (for the disconnect-walk stop condition).
    const newAncestorHashes = new Set<string>();
    const newConnectQueue: Array<{ hash: Buffer; height: number }> = [];
    {
      let cursor: Buffer | null = newTipBlock.header.prevBlock;
      let cursorHeight = newTipHeight - 1;
      let depth = 0;
      while (cursor !== null && depth < MAX_REORG_DEPTH) {
        const cursorHex = cursor.toString("hex");
        newAncestorHashes.add(cursorHex);
        // Stop when we reach a block on the OLD chain — that's the
        // fork.  We detect this by checking whether `cursor` is on
        // the path from oldTipHash backwards.  The cheaper proxy:
        // see whether the chainStateManager already has this block
        // in its ancestry by walking it up.  But simpler: just walk
        // both old + new chains in lock-step until they match.
        // For now we record everything and let the disconnect walk
        // do the matching.
        const cursorEntry = this.headerSync.getHeader(cursor);
        if (!cursorEntry) {
          // Header not in memory — can't proceed.
          return false;
        }
        newConnectQueue.unshift({ hash: cursor, height: cursorHeight });
        cursor = cursorEntry.header.prevBlock;
        cursorHeight--;
        depth++;
        // Genesis termination guard.
        if (cursor && cursor.every((b) => b === 0)) break;
      }
    }

    // ── Step 1.5: bridging-body presence pre-flight (Core AcceptBlock /
    //    ActivateBestChain parity) ──
    //
    // The fork-tip block (e.g. B105) can reach `connectBlock` BEFORE its
    // bridging bodies (fork+1 .. old active tip, e.g. B102..B104) have been
    // persisted to disk as side branches — on the live P2P path those bodies
    // are still in flight / being stored by `maybeStoreForkBody`. Step 2 below
    // would disconnect the old chain (mutating the in-memory UTXO view back to
    // the fork point) and step 3 would then find the intermediate bodies
    // missing on disk, leaving the view stranded at the fork point. The
    // fork-tip connect that follows would then fail the `view-out-of-sync` gate
    // — a valid block wrongly rejected, and (pre-fix) the honest peer banned as
    // "block-mutated".
    //
    // Core never does this: AcceptBlock persists every valid block to disk
    // unconditionally, and ActivateBestChainStep only connects a block on the
    // most-work path once EVERY block on that path carries BLOCK_HAVE_DATA —
    // otherwise it simply waits (the missing bodies are (re)requested) and
    // retries later. It never rejects the tip or punishes the peer for a
    // transient "we don't have the bridge yet" condition.
    //
    // So: find the fork point via a read-only HEADER walk of the old chain,
    // filter `newConnectQueue` to the intermediates strictly above it, and
    // verify each intermediate body is already on disk. If ANY is missing, set
    // the deferral signal and return WITHOUT mutating the view. `connectBlock`
    // aborts the connect cleanly and the caller keeps the fork tip buffered,
    // re-requests the bridging bodies, and retries once they land — no
    // consensus error, no peer ban. (The old chain's own bodies are validated
    // in step 2; this pre-flight only guards the NEW branch's bridge.)
    {
      let forkHeight: number | null = null;
      let hcursor: Buffer | null = oldTipHash;
      let hsteps = 0;
      while (hcursor !== null && hsteps < MAX_REORG_DEPTH) {
        if (newAncestorHashes.has(hcursor.toString("hex"))) {
          const forkEntry = this.headerSync.getHeader(hcursor);
          forkHeight = forkEntry ? forkEntry.height : null;
          break;
        }
        const hEntry = this.headerSync.getHeader(hcursor);
        if (!hEntry) break;
        if (hEntry.height === 0) break;
        hcursor = hEntry.header.prevBlock;
        hsteps++;
      }
      if (forkHeight !== null) {
        for (const interm of newConnectQueue) {
          if (interm.height <= forkHeight) continue; // fork + shared prefix
          const body = await this.db.getBlock(interm.hash);
          if (!body) {
            console.log(
              `[reorg] deferring reorg to ${newTipBlock.header.prevBlock
                .toString("hex")
                .slice(0, 16)}… (fork tip height ${newTipHeight}): bridging body ` +
                `for height ${interm.height} (${interm.hash
                  .toString("hex")
                  .slice(0, 16)}) not yet on disk — keeping fork tip buffered, ` +
                `re-requesting the bridge (no view mutation, no peer punishment)`
            );
            this.reorgDeferredMissingBodies = true;
            return false;
          }
        }
      }
    }

    // Step 2: walk back OLD chain from oldTipHash, disconnecting
    // each block (UTXO restore) until we hit a hash already in
    // newAncestorHashes (the fork).  Collect non-coinbase txs along
    // the way for the mempool refill.
    {
      let cursor: Buffer | null = oldTipHash;
      let cursorHeight = this.chainStateManager!.getBestBlock().height;
      let steps = 0;
      while (cursor !== null && steps < MAX_REORG_DEPTH) {
        if (newAncestorHashes.has(cursor.toString("hex"))) {
          // Reached fork point.  Trim newConnectQueue so the
          // intermediates we connect are only those AFTER the fork
          // (and BEFORE newTip).  newConnectQueue currently
          // includes everything walked back, including the fork
          // and possibly older.
          const forkHex = cursor.toString("hex");
          const forkIdx = newConnectQueue.findIndex(
            (n) => n.hash.toString("hex") === forkHex
          );
          if (forkIdx >= 0) {
            // Drop the fork itself + everything older.
            newConnectQueue.splice(0, forkIdx + 1);
          }
          break;
        }
        const rawBlock = await this.db.getBlock(cursor);
        if (!rawBlock) {
          // Old block body missing — can't disconnect properly.
          return false;
        }
        let oldBlock: Block;
        try {
          oldBlock = deserializeBlock(new BufferReader(rawBlock));
        } catch {
          return false;
        }
        // Collect non-coinbase txs (camlcoin lib/sync.ml:2304-2308).
        for (let i = 1; i < oldBlock.transactions.length; i++) {
          const tx = oldBlock.transactions[i];
          if (!isCoinbase(tx)) {
            disconnectedTxsOut.push(tx);
          }
        }
        // Disconnect UTXO (restore from undo data).  Pattern D:
        // `pendingOps` collects the txindex deletes so they land in
        // the same atomic batch as everything else in this reorg.
        const ok = await this.disconnectBlockUtxo(
          oldBlock,
          cursorHeight,
          cursor,
          pendingOps
        );
        if (!ok) {
          // Undo data missing — partial disconnect already happened
          // (best effort).  Caller will see UTXO divergence but
          // chain advances.  Surface as a loud log line.
          console.warn(
            `[reorg] aborting reorg-disconnect at height ${cursorHeight}; UTXO state will diverge from Core`
          );
          return false;
        }
        if (pendingOps && pendingOps.length > MAX_REORG_BATCH_OPS) {
          console.warn(
            `[reorg] batch buffer exceeded ${MAX_REORG_BATCH_OPS} ops at disconnect-height ${cursorHeight}; aborting reorg dispatch`
          );
          return false;
        }
        cursor = oldBlock.header.prevBlock;
        cursorHeight--;
        steps++;
      }
    }

    // DISCONNECT HALF of the reorg complete (old-chain blocks rolled back to
    // the fork).  Pulse the wait-family notifier here in addition to the final
    // connect-half pulse (BlockSync.connectBlock → chainState.updateTip), so a
    // waiter observes the reorg as a tip change even mid-reorg.  Core's
    // KernelNotifications::blockTip fires on disconnect as well as connect.
    // Best-effort: a notifier fault must never abort the reorg.  The waiter
    // re-reads the authoritative tip on wake, so an extra/early pulse is
    // harmless (lost-wakeup-safe generation counter).
    if (this.chainStateManager) {
      try {
        this.chainStateManager.getTipNotifier()?.notify();
      } catch {
        /* best-effort */
      }
    }

    // Step 3: connect intermediate new-chain blocks (those between
    // the fork and the newTip).  Each must be present in the DB as
    // a side-branch body (stored by the side-branch path in
    // injectBlock).  We run coreConnectBlockChecks on each so the
    // UTXO set picks up their outputs.
    for (const intermediate of newConnectQueue) {
      const rawBlock = await this.db.getBlock(intermediate.hash);
      if (!rawBlock) {
        console.warn(
          `[reorg] intermediate block body missing for ${intermediate.hash.toString("hex").slice(0, 16)} at height ${intermediate.height}; cannot connect`
        );
        return false;
      }
      let intermBlock: Block;
      try {
        intermBlock = deserializeBlock(new BufferReader(rawBlock));
      } catch {
        return false;
      }
      // Get prevMTP for the intermediate block.
      let intermPrevMTP = 0;
      const intermPrevHeaderEntry = this.headerSync.getHeaderByHeight(
        intermediate.height - 1
      );
      if (intermPrevHeaderEntry) {
        intermPrevMTP = this.headerSync.getMedianTimePast(intermPrevHeaderEntry);
      }
      const intermResult = await coreConnectBlockChecks(
        intermBlock,
        intermediate.height,
        this.utxoManager,
        this.params,
        {
          // Reorg/intermediate side branches always fully verify scripts
          // (skipScripts: false) — safe over-verify default.  Core does
          // apply assumevalid on reorg-reconnect paths but the ancestor
          // check requires the active chain which is mid-transition here;
          // verifying everything is always correct and simpler.
          skipScripts: false,
          prevMTP: intermPrevMTP,
          enforceBIP68: intermediate.height >= this.params.csvHeight,
          scriptThreads: this.scriptThreads,
          // MANDATORY height-gated consensus flags (Core GetBlockScriptFlags).
          // Side-branch blocks are connected through the SAME full-validation
          // connect path the main chain uses, so reorg revalidates scripts
          // under the correct per-height flag set (no under-flag on reorg).
          verifyDERSig: intermediate.height >= this.params.bip66Height,
          verifyCLTV: intermediate.height >= this.params.bip65Height,
          verifyCSV: intermediate.height >= this.params.csvHeight,
          verifyNullDummy: intermediate.height >= this.params.segwitHeight,
        }
      );
      if (!intermResult.ok) {
        console.warn(
          `[reorg] intermediate block ${intermediate.hash.toString("hex").slice(0, 16)} at height ${intermediate.height} failed connect: ${intermResult.error}`
        );
        return false;
      }
      // Persist undo data for the intermediate so a subsequent
      // reorg in the OTHER direction can also disconnect.  Pattern D
      // (multi-block atomicity): when `pendingOps` is provided, the
      // undo write rides the same atomic batch as every other reorg
      // op.  Falls back to a standalone `db.putUndoData` when called
      // outside the atomic-batch path (defensive, kept for symmetry
      // with `disconnectBlockUtxo`).
      //
      // W109 FIX-33: also OR BLOCK_HAVE_DATA (8) | BLOCK_HAVE_UNDO (16)
      // into the block index for the intermediate.  The body was already
      // on disk (stored as a side-branch) and we just persisted undo, so
      // both bits must be set.  Mirrors Core blockstorage.cpp::WriteBlock
      // + WriteUndoDataForBlock which set nStatus before the dirty-index
      // flush.  Rides the same atomic pendingOps batch so crash-recovery
      // sees a consistent (data+undo present ↔ bits set) invariant.
      try {
        const { serializeUndoData } = await import("../chain/utxo.js");
        const undoData = serializeUndoData(intermResult.spentOutputs);
        if (pendingOps) {
          pendingOps.push(this.db.buildUndoDataPutOp(intermediate.hash, undoData));
          // Set HAVE_DATA (8) | HAVE_UNDO (16) in the block index.
          const statusOp = await this.db.buildBlockIndexOrStatusOp(
            intermediate.hash,
            8 /* HAVE_DATA */ | 16 /* HAVE_UNDO */,
          );
          if (statusOp) {
            pendingOps.push(statusOp);
          }
        } else {
          await this.db.putUndoData(intermediate.hash, undoData);
          // Standalone path: OR the bits directly.
          const intermIdx = await this.db.getBlockIndex(intermediate.hash);
          if (intermIdx) {
            await this.db.updateBlockStatus(
              intermediate.hash,
              intermIdx.status | 8 /* HAVE_DATA */ | 16 /* HAVE_UNDO */,
            );
          }
        }
      } catch {
        // Best-effort; ignore.
      }
      // Pattern C0: write txindex for the now-active intermediate block.
      // The block body must already be in the DB (it was stored as a
      // side-branch via the duplicate path of injectBlock, lines
      // 696-707); we mirror that gate by only writing the index when
      // the body retrieve succeeded above (we already used `rawBlock`).
      //
      // Pattern D: when `pendingOps` is provided, the txindex puts
      // accumulate in the buffer instead of issuing a standalone
      // batch write.  The legacy `writeTxIndexForBlock` path is kept
      // for the standalone call sites (atTip connect outside reorg).
      if (pendingOps) {
        const { getTxId } = await import("../validation/tx.js");
        for (const tx of intermBlock.transactions) {
          const txid = getTxId(tx);
          pendingOps.push(this.db.buildTxIndexPutOp(txid, intermediate.hash));
        }
      } else {
        await this.writeTxIndexForBlock(intermBlock, intermediate.hash);
      }
      // ── BIP-157 Phase 2: extend filter chain on intermediate reconnect ──
      //
      // The new-tip block's filter is appended in `connectBlock` itself
      // (line ~2418, after the reorg dispatch returns). Intermediates
      // (B1, B2, … between fork and new tip) need their own appends here
      // so the filter-header chain stays in lockstep with the chain.
      // Without this, `currentHeader` after the reorg dispatch reflects
      // the disconnected old-tip's prev rather than the latest connected
      // intermediate, and the new-tip filter header would be computed
      // against the wrong prev — chain divergence on every multi-block
      // reorg.
      //
      // Best-effort: failures here log and continue, matching the
      // connect-side gate in `BlockSync.connectBlock`.
      if (this.filterIndex && this.filterIndex.isEnabled()) {
        try {
          await this.filterIndex.indexBlock(
            intermBlock,
            intermediate.height,
            intermResult.spentOutputs
          );
        } catch (err) {
          const msg = err instanceof Error ? err.message : String(err);
          console.warn(
            `[blockfilterindex] failed to index intermediate block ${intermediate.hash
              .toString("hex")
              .slice(0, 16)} at h=${intermediate.height}: ${msg} (continuing)`
          );
        }
      }
      if (pendingOps && pendingOps.length > MAX_REORG_BATCH_OPS) {
        console.warn(
          `[reorg] batch buffer exceeded ${MAX_REORG_BATCH_OPS} ops at intermediate-height ${intermediate.height}; aborting reorg dispatch`
        );
        return false;
      }
      this.utxoManager.setBestBlock(intermediate.hash);
      // CChain::SetTip parity — the reconnected intermediate is now on the
      // ACTIVE chain, so update the height->hash active-chain index.  Header
      // reception no longer writes this entry (headers.ts saveHeaderEntry
      // passes writeHeightIndex:false), so the reorg-reconnect path is the
      // sole authority for the [fork+1 .. newTip-1] heights.  Without this,
      // getblockhash(h) for every reconnected intermediate would return the
      // just-disconnected old-chain block (stale) or null.  Rides the same
      // atomic pendingOps batch as the rest of the reorg.
      if (pendingOps) {
        pendingOps.push(
          this.db.buildHeightHashPutOp(intermediate.height, intermediate.hash)
        );
      } else {
        await this.db.putBlockHashByHeight(intermediate.height, intermediate.hash);
      }
      console.log(
        `[reorg] reconnected intermediate block ${intermediate.hash.toString("hex").slice(0, 16)} at height ${intermediate.height}`
      );
    }

    // CChain::SetTip parity — clear stale height->hash entries ABOVE the new
    // tip.  When the new (heavier) chain is SHORTER than the old chain, the
    // disconnected old-chain blocks left active-chain index entries at heights
    // > newTipHeight.  Core's `CChain::SetTip` resizes `vChain` to
    // `newTip.height + 1`, dropping every entry above the new tip; we mirror
    // that by deleting HEADER[newTipHeight+1 .. oldTipHeight].  (The new tip's
    // own HEADER[newTipHeight] entry is written by the outer connectBlock.)
    if (oldTipHeightAtEntry > newTipHeight) {
      for (let h = newTipHeight + 1; h <= oldTipHeightAtEntry; h++) {
        if (pendingOps) {
          pendingOps.push(this.db.buildHeightHashDeleteOp(h));
        } else {
          await this.db.deleteBlockHashByHeight(h);
        }
      }
    }
    return true;
  }

  /**
   * Walk back the OLD chain from `oldTipHash` collecting non-coinbase
   * transactions of every block disconnected by a reorg, stopping when
   * we reach an ancestor of the NEW chain identified by
   * `newChainAncestorHashes` (a hex set walked back from the new tip's
   * parent).  Bounded by `MAX_REORG_DEPTH` to avoid runaway walks on a
   * malicious header tree.
   *
   * Reference: camlcoin lib/sync.ml:2304-2308 (per-block tx collection)
   * + lib/sync.ml:2354-2363 (refill loop).  Bitcoin Core:
   * validation.cpp::DisconnectTip → MaybeUpdateMempoolForReorg.
   *
   * Disconnected blocks may not all be on disk if pruning ever runs;
   * any missing block aborts the collection (we still let the connect
   * succeed — the UTXO state is independent of the refill).
   */
  private async collectDisconnectedTxs(
    oldTipHash: Buffer,
    newChainAncestorHashes: Set<string>
  ): Promise<Transaction[]> {
    // Core-parity bound (see `reorgDepthCap`): matches the dispatch-side cap in
    // handleReorgUtxoAndCollect — unbounded on archive, MIN_BLOCKS_TO_KEEP on a
    // pruned node. This is the best-effort mempool-refill walk; the connect
    // itself defines chain progress, so over-walking here is harmless.
    const MAX_REORG_DEPTH = this.reorgDepthCap();
    const collected: Transaction[] = [];
    let cursor: Buffer | null = oldTipHash;
    let steps = 0;
    while (cursor !== null && steps < MAX_REORG_DEPTH) {
      const cursorHex = cursor.toString("hex");
      // Stop when the old-chain cursor reaches the fork point (a hash
      // shared with the new chain's ancestry).
      if (newChainAncestorHashes.has(cursorHex)) {
        break;
      }
      const rawBlock = await this.db.getBlock(cursor);
      if (!rawBlock) {
        // Old block body missing — pruned or never persisted (deep
        // IBD path skips putBlock).  Stop collecting; return what we
        // have so far.
        break;
      }
      let oldBlock: Block;
      try {
        oldBlock = deserializeBlock(new BufferReader(rawBlock));
      } catch {
        break;
      }
      for (let i = 1; i < oldBlock.transactions.length; i++) {
        // Skip coinbase (i === 0); coinbases are never re-addable to
        // mempool.  Mirrors Mempool.readdTransactions internal guard.
        const tx = oldBlock.transactions[i];
        if (!isCoinbase(tx)) {
          collected.push(tx);
        }
      }
      cursor = oldBlock.header.prevBlock;
      steps++;
    }
    return collected;
  }

  /**
   * Validate and connect a block.
   *
   * Delegates consensus checks + UTXO mutations to coreConnectBlockChecks
   * (src/consensus/consensus/connect_block.ts), which is also used by the
   * chain/state.ts path (rollback re-apply, reorg, generateblock).
   *
   * This method handles the sync-specific pre-checks (block structure
   * validation, header-chain linkage, assumevalid gate via shouldSkipScripts)
   * and post-processing (IBD flush optimisation, tip/peer updates) that do
   * not belong in the shared helper.
   *
   * Error contract: returns false on any failure; stores the error string in
   * this.lastConnectError for classifyCallbackError / bip22FromConnectError.
   */
  async connectBlock(block: Block, height: number): Promise<boolean> {
    const blockHash = getBlockHash(block.header);
    const hashHex = blockHash.toString("hex");

    // Reset captured error for this attempt; populated by recordConnectError()
    // at every warn/error → return-false site below.
    this.lastConnectError = "";
    // Reset the reorg-atomicity restore signal for this attempt (Core
    // ActivateBestChainStep parity — see the field doc + the reorg-abort
    // restore below).
    this.reorgAbortRestoredTip = null;
    // Reset the reorg-deferral signal for this attempt (Core AcceptBlock /
    // ActivateBestChain parity — set by the reorg dispatch when a bridging body
    // is not yet on disk; see the field doc + the deferral handling below).
    this.reorgDeferredMissingBodies = false;

    // Snapshot the OLD tip BEFORE the connect mutates chain state.  Used
    // by the post-connect mempool-refill check (Pattern B): if the
    // newly-connected block's prevBlock is NOT this snapshot, then a
    // reorg has occurred and the old chain's non-coinbase txs need to
    // be re-fed into the mempool (matching Bitcoin Core's
    // MaybeUpdateMempoolForReorg, validation.cpp).  Pre-fix, hotbuns
    // had no refill — see
    // CORE-PARITY-AUDIT/_mempool-refill-on-reorg-fleet-result-2026-05-05.md
    // (Pattern B1 "no refill at all", 9 of 10 impls failing).  Camlcoin
    // lib/sync.ml:2354-2363 is the canonical shape.
    const oldTipBeforeConnect = this.chainStateManager
      ? this.chainStateManager.getBestBlock().hash
      : null;

    // ── Pre-connect reorg dispatch ──
    //
    // If this block's prevBlock differs from the current chain tip,
    // a reorg is needed: disconnect old-chain blocks (back to fork),
    // then reconnect any new-chain blocks BETWEEN the fork and this
    // block (siblings that previously took the "duplicate" return in
    // injectBlock and were stored as side-branch via the side-branch
    // storage path above).
    //
    // The reorg dispatch is a separate code path from the regular
    // tip-extension connect, primarily to:
    //   1. Walk the old chain restoring UTXOs from undo data (so
    //      input lookups for the new chain see the pre-fork state).
    //   2. Connect intermediate new-chain blocks (B1, B2, …) before
    //      this one (B3) so each block's coreConnectBlockChecks has
    //      the right UTXO context.
    //   3. Collect the disconnected old-chain non-coinbase txs for
    //      the post-connect mempool refill.
    //
    // Best-effort: any step that fails (missing undo data, missing
    // intermediate body, intermediate connect failure) falls back to
    // the legacy in-place connect — chain advances, but UTXO
    // diverges from Core (the pre-fix behaviour).  A loud log line
    // surfaces the divergence.
    let reorgDisconnectedTxs: Transaction[] = [];
    let reorgUtxoFixed = false;
    // Pattern D (multi-block atomicity, post-`9b10550`): collect every
    // disk write the reorg dispatch would otherwise issue piecemeal
    // (per-block txindex deletes, per-intermediate undo data, per-
    // intermediate txindex puts) into one buffer.  After the new-tip
    // connect succeeds, this buffer rides the same `flushDirty`
    // ClassicLevel batch as the new-tip block-index + chain-state +
    // UTXO writes — so the entire reorg lands atomically and a crash
    // mid-reorg leaves either the pre or post state, never a partial
    // mix.  Mirrors Bitcoin Core's `CDBBatch` pattern in
    // `validation.cpp::ActivateBestChainStep`.
    const reorgPendingOps: BatchOperation[] = [];
    // `reorgAttempted` records whether the pre-connect reorg dispatch ran and
    // therefore may have MUTATED the in-memory UTXO view (old chain
    // disconnected, competing intermediates B1/B2 reconnected, view best-block
    // advanced to the last intermediate).  Any failure AFTER this point must
    // atomically restore the ORIGINAL active-chain tip, or the node settles on
    // the losing competing branch (Core ActivateBestChainStep: the competing
    // chain is connected against a throwaway view that is DROPPED on any
    // ConnectTip failure, leaving the active chain unchanged).
    let reorgAttempted = false;
    if (
      oldTipBeforeConnect !== null &&
      this.chainStateManager !== null &&
      this.chainStateManager.getBestBlock().height > 0 &&
      !block.header.prevBlock.equals(oldTipBeforeConnect)
    ) {
      reorgAttempted = true;
      reorgUtxoFixed = await this.handleReorgUtxoAndCollect(
        block,
        height,
        oldTipBeforeConnect,
        reorgDisconnectedTxs,
        reorgPendingOps
      );

      // Core AcceptBlock / ActivateBestChain parity — DEFER, don't reject.
      //
      // The reorg dispatch detected that a bridging body (fork+1 .. old active
      // tip) is not yet on disk, so the competing branch cannot be rebuilt from
      // the fork point RIGHT NOW.  It returned WITHOUT mutating the UTXO view.
      // This is a transient ordering condition on the live P2P path (the fork
      // tip arrived before its bridge), exactly the case Core handles by leaving
      // the block on disk and waiting for the missing path bodies — never by
      // rejecting the tip or punishing the peer.
      //
      // Abort this connect cleanly: no view was touched (return before step 2),
      // so there is nothing to roll back; record no consensus error; return
      // false with `reorgDeferredMissingBodies` still set so the caller keeps the
      // fork tip buffered, re-requests the bridge, and does NOT ban the peer.
      if (this.reorgDeferredMissingBodies) {
        return false;
      }
    }

    // Core ActivateBestChainStep parity — atomic rollback of a failed reorg.
    //
    // The reorg dispatch above mutated the in-memory UTXO view IN PLACE
    // (disconnected the old active chain back to the fork, reconnected the
    // competing intermediates B1/B2, advanced the view best-block).  NOTHING
    // has been flushed to disk yet (`reorgPendingOps` only rides the final
    // success flush), so the on-disk UTXO set still reflects the ORIGINAL
    // active tip (`oldTipBeforeConnect`).  If the new tip (or an intermediate)
    // is invalid — e.g. B3 with bad-cb-amount — every failure return below must
    // FIRST drop the throwaway in-memory mutations and re-point the view at the
    // original active tip, exactly as Core discards the throwaway
    // CCoinsViewCache and leaves `m_chain` on the original branch.
    //
    // Without this, `connectBlock` returned false with the view stranded on the
    // competing branch (B2), and the caller's generic clearCache — keyed on
    // `getHeaderByHeight(lastFlushed)`, which is the BEST-HEADER chain entry =
    // the losing fork B2, not the active-chain tip A2 — cemented the wrong
    // branch (Reorg wave 3: settled at h103 on B2 instead of restoring A2).
    const abortFailedReorg = (): void => {
      if (!reorgAttempted || oldTipBeforeConnect === null) return;
      // Discard the dirty reorg mutations and re-point the view (cache +
      // CoinsViewDB) at the on-disk active tip.  `reorgPendingOps` is dropped
      // on the floor by returning before the flush — no disk write occurred.
      this.utxoManager.clearCache(oldTipBeforeConnect);
      // Signal the caller (processOrderedBlocks) to SKIP its own clearCache,
      // which would otherwise re-point to the competing branch.
      this.reorgAbortRestoredTip = oldTipBeforeConnect;
      console.warn(
        `[reorg] failed reorg to ${hashHex.slice(0, 16)} at height ${height}; ` +
          `atomically restored active chain to ${oldTipBeforeConnect
            .toString("hex")
            .slice(0, 16)} (no partial switch)`
      );
    };

    // Structural block validation (CheckBlock equivalent) always runs regardless
    // of assumevalid.  Bitcoin Core's assumevalid optimization ONLY skips
    // per-input script/signature verification (fScriptChecks gate in
    // ConnectBlock).  All structural gates — merkle root, witness commitment,
    // BIP-34 height-in-coinbase, block weight, tx-structure — remain active.
    // Reference: Bitcoin Core validation.cpp::CheckBlock (line 3918+) which is
    // always called, and ConnectBlock where only
    //   bool fScriptChecks = !fJustCheck && !fAssumeValid;
    // is gated on assumevalid.
    const validation = validateBlock(block, height, this.params);
    if (!validation.valid) {
      const m = `Block ${hashHex.slice(0, 16)}... at height ${height} failed validation: ${validation.error}`;
      console.warn(m);
      this.recordConnectError(m);
      abortFailedReorg();
      return false;
    }

    // Verify the block connects to the header chain
    const headerEntry = this.headerSync.getHeaderByHeight(height);
    if (!headerEntry || !headerEntry.hash.equals(blockHash)) {
      const m = `Block ${hashHex.slice(0, 16)}... does not match expected header at height ${height}`;
      console.warn(m);
      this.recordConnectError(m);
      abortFailedReorg();
      return false;
    }

    // BIP68 (CSV) activation check
    // BIP-68 SequenceLocks are enforced regardless of assumevalid (Core
    // validation.cpp:2552-2561 — only signature/script checks are skipped).
    const enforceBIP68 = height >= this.params.csvHeight;

    // Get the previous block's MTP for BIP-68 time-based locks and IsFinalTx.
    // IsFinalTx always needs MTP when CSV is active (BIP-113), even under assumevalid.
    let blockPrevMTP = 0;
    {
      const prevHeaderEntry = this.headerSync.getHeaderByHeight(height - 1);
      if (prevHeaderEntry) {
        blockPrevMTP = this.headerSync.getMedianTimePast(prevHeaderEntry);
      }
    }

    // ── assumevalid gate for script verification ──
    // Build the context once per block and run the full 5-condition
    // shouldSkipScripts() check (Core validation.cpp:2346-2382).
    // On regtest assumedValid is undefined → every script fires.
    // On mainnet all 5 conditions must hold: AV hash configured, AV in
    // header index, pindex on active chain AND ancestor of AV, best-header
    // chainwork >= minimum, and > 2 weeks of equivalent PoW past pindex.
    const bestHeader = this.headerSync.getBestHeader();
    const currentHeaderEntry = this.headerSync.getHeaderByHeight(height);

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
      // Condition 5 (DoS defense): GetBlockProofEquivalentTime requires
      // GetBlockProof(best_header.bits).  Sourced from the live best header's
      // nBits field; 0 is a safe default (getBitsProof(0)=0 → equivTime=0 →
      // "too recent" → scripts verified, fail-safe).
      bestHeaderBits: bestHeader?.header.bits ?? 0,
      // nPowTargetSpacing for the equivalent-time formula (600 s on mainnet).
      powTargetSpacing: this.params.targetSpacing,
    };

    const skipScriptsResult = shouldSkipScripts(avCtx);
    const skipScripts = skipScriptsResult.skip;

    // ── Delegate consensus checks + UTXO mutations to the shared helper. ──
    //
    // coreConnectBlockChecks handles:
    //   BIP-30, IsFinalTx, bulk-UTXO preload, coinbase maturity, BIP-68/CSV,
    //   script verification, sigops ceiling, coinbase-value check,
    //   spendOutput, addTransaction (in block-order for intra-block chaining).
    //
    // On return ok=true the utxoManager reflects the post-block state.
    // On return ok=false nothing has been flushed; the error is recorded.
    // W93: thread the canonical genesis hash so coreConnectBlockChecks can
    // short-circuit the per-tx loop on genesis (Core validation.cpp:2339-2343).
    const genesisHashHexLE = Buffer.from(this.params.genesisBlockHash)
      .reverse()
      .toString("hex");

    // W93: pass the UTXO view's current best-block hash for the
    // hashPrevBlock == view.GetBestBlock() invariant (Core validation.cpp:2333).
    let utxoBestBlockHashHexLE: string | undefined;
    try {
      const viewBest = await this.utxoManager.getCoinsViewCache().getBestBlock();
      if (viewBest && viewBest.length === 32) {
        utxoBestBlockHashHexLE = Buffer.from(viewBest).reverse().toString("hex");
      }
    } catch {
      utxoBestBlockHashHexLE = undefined;
    }

    const coreResult = await coreConnectBlockChecks(
      block,
      height,
      this.utxoManager,
      this.params,
      {
        skipScripts,
        prevMTP: blockPrevMTP,
        enforceBIP68,
        scriptThreads: this.scriptThreads,
        // MANDATORY height-gated consensus flags (Core GetBlockScriptFlags).
        verifyDERSig: height >= this.params.bip66Height,
        verifyCLTV: height >= this.params.bip65Height,
        verifyCSV: height >= this.params.csvHeight,
        verifyNullDummy: height >= this.params.segwitHeight,
        genesisHashHex: genesisHashHexLE,
        utxoBestBlockHashHex: utxoBestBlockHashHexLE,
        // Per-coin MTP for accurate BIP-68 time-based sequence lock enforcement.
        // Uses HeaderSync to look up the MTP at (coinHeight - 1).
        getUTXOMTP: (coinHeight: number) => {
          if (coinHeight <= 0) return 0;
          const coinPrevHeader = this.headerSync.getHeaderByHeight(coinHeight - 1);
          return coinPrevHeader ? this.headerSync.getMedianTimePast(coinPrevHeader) : 0;
        },
      }
    );

    if (!coreResult.ok) {
      const m = coreResult.error;
      console.warn(m);
      this.recordConnectError(m);
      // Core ActivateBestChainStep parity: the competing chain's new tip failed
      // ConnectBlock (e.g. bad-cb-amount).  Drop the throwaway in-memory reorg
      // mutations and restore the original active chain — never settle on the
      // partially-connected competing branch.
      abortFailedReorg();
      return false;
    }

    // ── Persist undo data near the tip ──
    //
    // coreConnectBlockChecks returned `spentOutputs` which captures the
    // pre-spend UTXO entries for every input the block consumed.
    // Persisting this enables disconnectBlock (chain/state.ts:347) to
    // restore the UTXO set when a reorg disconnects this block.
    //
    // Without persisted undo data, hotbuns has no way to roll back a
    // confirmed block: the UTXO set entries it deleted (or marked
    // spent) are lost.  Pre-fix, this manifested as Pattern B in the
    // mempool-refill-on-reorg corpus (mempool refill failed because
    // input UTXOs were gone).
    //
    // Optimization: only persist undo data near the tip, mirroring
    // the existing `atTip` gate for `db.putBlock`.  Deep IBD reorgs
    // are vanishingly rare (would require an attacker to build
    // millions of blocks of competing chainwork) and Bitcoin Core's
    // pruning eventually drops old undo data anyway.  Reorg-prone
    // ranges are at the tip, which is where we persist.
    //
    // Reference: Bitcoin Core validation.cpp::ConnectBlock writes
    // `CBlockUndo` to `blocks/rev*.dat` for every connected block.
    // (See bitcoin-core/src/validation.cpp::WriteUndoDataForBlock.)
    //
    // Pattern D (multi-block atomicity, post-`9b10550`): the new-tip
    // undo write rides the same `flushDirty(extraOps)` batch as the
    // chain-state, block-index, header, txindex, and reorg-pending
    // ops.  This was previously a standalone `db.putUndoData`; under
    // a reorg it landed BEFORE the reorg's disconnect-side deletes,
    // so a crash window between the undo write and the final flush
    // could leave the chainstate inconsistent.  Now they ride one
    // ClassicLevel batch.
    // ── Reorg-retention window (Core AcceptBlock + MIN_BLOCKS_TO_KEEP parity) ──
    //
    // Bitcoin Core writes EVERY block's body (AcceptBlock → SaveBlockToDisk) and
    // undo data (ConnectBlock → WriteUndoDataForBlock) to disk unconditionally,
    // and only prunes them once they fall MIN_BLOCKS_TO_KEEP (288) below the tip.
    // hotbuns skips those writes for blocks connected below the best-header tip
    // as an IBD I/O optimization (`atTip`). But headers-first sync means ALL
    // headers arrive before the bodies, so during the final catch-up EVERY block
    // is "below the header tip" and its body+undo were never persisted. A
    // competing chain that then triggers a reorg must disconnect those recent
    // blocks — but `handleReorgUtxoAndCollect`'s `db.getBlock` / the
    // disconnect-side `db.getUndoData` return null, so the reorg aborts partway
    // and strands the UTXO view mid-old-chain → the `view-out-of-sync` wedge that
    // fails EVERY live-P2P reorg (harness height 105).
    //
    // Fix: persist body + undo for any block within MIN_BLOCKS_TO_KEEP of the
    // best header — the exact window a peer could present a reorg for (and the
    // same bound the reorg dispatch itself enforces, MAX_REORG_DEPTH=288). Deep
    // IBD blocks (>288 below the target) are still skipped, so IBD throughput is
    // unchanged; only the ~288-block tail persists per-block, which is where
    // reorgs actually happen. This mirrors Core's retention floor exactly.
    const withinReorgWindow =
      !bestHeader || height > bestHeader.height - MIN_BLOCKS_TO_KEEP;

    let newTipUndoOp: BatchOperation | null = null;
    {
      if (withinReorgWindow) {
        try {
          const { serializeUndoData } = await import("../chain/utxo.js");
          const undoData = serializeUndoData(coreResult.spentOutputs);
          newTipUndoOp = this.db.buildUndoDataPutOp(blockHash, undoData);
        } catch (err) {
          // Undo persistence is best-effort — never fail a block
          // connect because of a serialization hiccup.  A missing
          // undo entry surfaces later as a "disconnect impossible"
          // log line, not a chain-state corruption.
          console.warn(
            `[undo] failed to persist undo data for block ${blockHash.toString("hex").slice(0, 16)}: ${
              err instanceof Error ? err.message : String(err)
            }`
          );
        }
      }
    }

    // During IBD, skip per-block DB writes (block data, undo, index) except
    // near the tip. Only update UTXO set in memory and flush periodically.
    // This eliminates the biggest I/O bottleneck: a LevelDB batch write per block.
    this.utxoManager.setBestBlock(blockHash);
    // bestHeader was already fetched in the preamble for the assumevalid gate.
    const atTip = !bestHeader || height >= bestHeader.height;
    // Flush whenever we persist reorg-window body/undo so those ops actually
    // reach disk this call (the batch below / the force-flush else-branch commit
    // newTipUndoOp + newTipTxIndexOps). Deep-IBD blocks fall outside the window,
    // so their flush cadence (FLUSH_INTERVAL) is unchanged.
    const shouldFlush =
      atTip || withinReorgWindow || height % FLUSH_INTERVAL === 0;

    // Store raw block data when near the tip so we can serve blocks to
    // peers via getdata.  During deep IBD this is skipped for performance.
    //
    // Note: `db.putBlock` is a flat-file/LevelDB write that lives
    // outside the chain-state batch.  Pattern D's atomicity guarantee
    // covers the chainstate (UTXO + chain-state + block-index +
    // header + txindex + undo), not the block body file.  A
    // crash between `putBlock` and the final `flushDirty` leaves the
    // body on disk but no chain-state pointer to it — which the
    // restart path treats as "block missing", same as if it were
    // never written.  Mirrors Bitcoin Core's split between
    // `blocks/blk*.dat` (body, written first) and the LevelDB
    // chainstate batch (validation.cpp:WriteBlockToDisk).
    let newTipTxIndexOps: BatchOperation[] = [];
    if (withinReorgWindow) {
      const rawBlock = serializeBlock(block);
      await this.db.putBlock(blockHash, rawBlock);

      // ── Pattern C0: write txindex on connect ──
      //
      // The audit's reorg-correctness fleet result (2026-05-05) caught
      // hotbuns' txindex helper (`db.putTxIndex` / `TxIndexManager`)
      // existing but never wired into the connect callback, so
      // `getrawtransaction(<txid>, true)` errored out for every
      // confirmed tx — pre AND post reorg.  See
      // CORE-PARITY-AUDIT/_txindex-revert-on-reorg-fleet-result-2026-05-05.md
      // (Pattern C0, hotbuns row).
      //
      // Gated on `atTip` so writes mirror `db.putBlock`: the txindex
      // is pointless without the block body persisted (the read path
      // in rpc/server.ts::findTxInBlock walks the block to locate the
      // tx).  Deep IBD blocks are skipped for the same throughput
      // reasons that skip the body write.
      //
      // The TxIndexEntry's `offset`/`length` fields are unused by the
      // current read path (rpc/server.ts:1515-1521 calls
      // findTxInBlock which walks the block); we still emit canonical
      // zeros so the on-disk format matches `db.putTxIndex`.
      //
      // Reference: bitcoin-core/src/index/txindex.cpp::CustomAppend
      // writes one (txid -> CDiskTxPos) entry per tx in the block.
      //
      // Pattern D: when a flush is going to happen this same call
      // (shouldFlush is true), accumulate the txindex puts so they
      // ride the same batch as chain-state + reorg ops.  Otherwise
      // (deep-IBD non-flush), fall back to a standalone batch write
      // — which already happens to be atomic vs. the on-disk state
      // because no chain-state advance occurs without a flush.
      if (shouldFlush) {
        const { getTxId } = await import("../validation/tx.js");
        for (const tx of block.transactions) {
          const txid = getTxId(tx);
          newTipTxIndexOps.push(this.db.buildTxIndexPutOp(txid, blockHash));
        }
      } else {
        await this.writeTxIndexForBlock(block, blockHash);
      }
    }

    // ── BIP-157/158 compact-block-filter index ──
    //
    // When the operator passed `--blockfilterindex=1`, cli.ts wires a
    // BlockFilterIndex into this BlockSync via setBlockFilterIndex().
    // Each connected block produces a GCS filter (over output
    // scriptPubKeys + spent input scriptPubKeys from undo data) which
    // is stored in the chain DB.  The filter-header chain is
    // monotonically advanced by `currentHeader` inside the index, so
    // we run this on every connect (not gated by atTip) — matching
    // Bitcoin Core's `BlockFilterIndex::CustomAppend` cadence.
    //
    // Best-effort: a filter-build failure must NOT roll back the
    // block connect.  An exception here would otherwise abort IBD on
    // an unrelated subsystem.  Mirrors Core's `IndexFailure` handling
    // in BaseIndex which logs + sets m_synced = false rather than
    // killing the chain advance.
    //
    // Surfaced via REST: `/rest/blockfilter/<filtertype>/<hash>` and
    // `/rest/blockfilterheaders/<filtertype>/<count>/<hash>`
    // (src/rpc/rest.ts handleBlockFilter / handleBlockFilterHeaders).
    if (this.filterIndex && this.filterIndex.isEnabled()) {
      try {
        await this.filterIndex.indexBlock(block, height, coreResult.spentOutputs);
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        console.warn(
          `[blockfilterindex] failed to index block ${blockHash.toString("hex").slice(0, 16)} at h=${height}: ${msg} (continuing)`
        );
      }
    }

    // ── coinstatsindex: per-height UTXO MuHash3072 + counts ──
    //
    // When the operator passed `--coinstatsindex=1`, cli.ts wires a
    // PersistentCoinStatsIndex into this BlockSync via setCoinStatsIndex().
    // Each connected block applies its created-output / spent-prevout delta to
    // the running MuHash3072 + txouts/total_amount/bogosize and persists a
    // self-contained per-height snapshot, so `gettxoutsetinfo <type> <height>`
    // can answer for a HISTORICAL height byte-exactly vs Core's coinstatsindex.
    //
    // Run on the PRIMARY connect path (this method) — the same path that
    // maintains txindex/blockfilterindex above — NOT only the submitblock RPC
    // path, so P2P/IBD sync is indexed too. The undo data (coreResult.
    // spentOutputs) carries each spent coin's original height+coinbase+amount+
    // script, exactly what the TxOutSer REMOVE needs.
    //
    // Best-effort: a coinstats failure must NOT roll back the block connect
    // (mirrors Core's BaseIndex IndexFailure handling).
    // Reference: bitcoin-core/src/index/coinstatsindex.cpp::CustomAppend.
    if (this.coinStatsIndex && this.coinStatsIndex.isEnabled()) {
      try {
        await this.coinStatsIndex.indexBlock(block, height, coreResult.spentOutputs);
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        console.warn(
          `[coinstatsindex] failed to index block ${blockHash.toString("hex").slice(0, 16)} at h=${height}: ${msg} (continuing)`
        );
      }
    }

    // ── txospenderindex: spent-outpoint -> spending-tx ──
    //
    // When the operator passed `--txospenderindex=1`, cli.ts wires a
    // TxoSpenderIndex into this BlockSync via setTxoSpenderIndex(). Each
    // connected block writes, for every non-coinbase input, a record mapping the
    // spent outpoint to the spending tx (txid + confirming block hash + full tx
    // hex), so `gettxspendingprevout` can answer the CONFIRMED-spend path.
    //
    // Run on the PRIMARY connect path (this method) — the same path that
    // maintains txindex/blockfilterindex/coinstatsindex above — NOT only the
    // submitblock RPC path, so P2P/IBD sync is indexed too.
    //
    // Best-effort: a failure must NOT roll back the block connect (mirrors
    // Core's BaseIndex IndexFailure handling).
    // Reference: bitcoin-core/src/index/txospenderindex.cpp::CustomAppend.
    if (this.txoSpenderIndex && this.txoSpenderIndex.isEnabled()) {
      try {
        await this.txoSpenderIndex.indexBlock(block, height);
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        console.warn(
          `[txospenderindex] failed to index block ${blockHash.toString("hex").slice(0, 16)} at h=${height}: ${msg} (continuing)`
        );
      }
    }

    // Always persist nTx for this block so getblockheader can return it
    // without re-reading the block body.  This is a tiny write (4 bytes)
    // and is idempotent — updateBlockIndexNTx no-ops if nTx is already set.
    // The full block index (including status + dataPos) is written in the
    // shouldFlush batch below; this covers the non-flush IBD path.
    if (!shouldFlush) {
      await this.db.updateBlockIndexNTx(blockHash, block.transactions.length);
      // CChain::SetTip parity for the non-flush IBD path.  This block is being
      // connected on the ACTIVE chain, so its height->hash active-chain index
      // entry must advance now.  Previously updateBlockIndexNTx wrote this as a
      // side effect (putBlockIndex), but that write is now gated off (it also
      // fired for fork/metadata updates and clobbered the active tip); write it
      // explicitly here so getblockhash(h) resolves every connected IBD height.
      await this.db.putBlockHashByHeight(height, blockHash);
    }

    if (shouldFlush) {
      // On flush, write chain state atomically with UTXO changes.
      // Also write block index + height mapping so we can resume from here.
      // Pattern D: the reorg dispatch's accumulated buffer
      // (`reorgPendingOps`) is folded in here so the entire reorg
      // (N disconnects + M intermediate reconnects + new-tip connect
      //  + chain-state) lands in ONE ClassicLevel batch.
      const extraOps: BatchOperation[] = [];

      // Reorg-side ops first (txindex deletes for disconnected blocks,
      // intermediate undo + txindex puts).  Order doesn't matter for
      // correctness — LevelDB batches are atomic — but writing
      // disconnect-side ops first matches Bitcoin Core's ordering in
      // ActivateBestChainStep (DisconnectTip then ConnectTip).
      if (reorgPendingOps.length > 0) {
        extraOps.push(...reorgPendingOps);
      }

      // New-tip undo + txindex (riding the same batch).
      if (newTipUndoOp) {
        extraOps.push(newTipUndoOp);
      }
      if (newTipTxIndexOps.length > 0) {
        extraOps.push(...newTipTxIndexOps);
      }

      // W93: status bits must include HAVE_UNDO (16) when undo data was
      // persisted on this connect.  Pre-fix, only HEADER_VALID | TXS_KNOWN |
      // TXS_VALID | (atTip ? HAVE_DATA : 0) was set, lying to the block-index
      // about undo availability — pruning + reorg-disconnect both read this
      // bit and would skip rev-data lookup that actually exists on disk.
      // Mirrors Core validation.cpp:2648-2651 RaiseValidity(BLOCK_VALID_SCRIPTS)
      // + WriteBlockUndo's implied HAVE_UNDO marker (Core stores nUndoPos +
      // BLOCK_HAVE_UNDO in CBlockIndex).
      const haveUndo = newTipUndoOp !== null ? 16 : 0;
      const blockRecord: BlockIndexRecord = {
        height,
        header: serializeBlockHeader(block.header),
        nTx: block.transactions.length,
        // 1=HEADER_VALID, 2=TXS_KNOWN, 4=TXS_VALID, 8=HAVE_DATA, 16=HAVE_UNDO.
        // HAVE_DATA / dataPos track the body write above, which now covers the
        // whole reorg-retention window (not just the strict tip), so a
        // reorg-disconnect that reads this bit finds the body actually on disk.
        status: 1 | 2 | 4 | (withinReorgWindow ? 8 : 0) | haveUndo,
        dataPos: withinReorgWindow ? 1 : 0,
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

      // Single atomic flush: UTXO + (reorg ops) + new-tip undo + new-tip
      // txindex + block-index + header + chain-state.
      await this.utxoManager.flushDirty(extraOps);
      this.lastFlushedHeight = height;
    } else {
      // No flush this iteration — but if a reorg accumulated ops we
      // MUST commit them somewhere atomic.  Force a flush in that
      // case (rare: reorg-during-deep-IBD); the alternative is
      // dropping reorg ops on the floor, which would leave the
      // txindex out of sync with the chain.
      if (reorgPendingOps.length > 0 || newTipUndoOp || newTipTxIndexOps.length > 0) {
        const extraOps: BatchOperation[] = [];
        if (reorgPendingOps.length > 0) extraOps.push(...reorgPendingOps);
        if (newTipUndoOp) extraOps.push(newTipUndoOp);
        if (newTipTxIndexOps.length > 0) extraOps.push(...newTipTxIndexOps);
        await this.utxoManager.flushDirty(extraOps);
        this.lastFlushedHeight = height;
      }
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

    // Keep the mempool's notion of the current tip height in sync with
    // the just-connected block.  The mempool uses tipHeight for
    // coinbase-maturity checks (UTXO confirmations = tipHeight - utxo.height)
    // and BIP-113 IsFinalTx (next block height = tipHeight + 1).  Pre-fix,
    // mempool.tipHeight was set once at startup (cli.ts:1142) from the
    // persisted chain state and never updated, so any post-IBD reorg-refill
    // calculated `confirmations = 0 - <utxo_height>` < 0 and rejected every
    // refilled tx with "Coinbase maturity not met" — surfaced by the
    // mempool-refill-on-reorg corpus entry as Pattern B1 (mempool=EMPTY).
    if (this.mempool) {
      this.mempool.setTipHeight(height);
    }

    // ── W93 Gate: ConnectTip — mempool.removeForBlock ──
    //
    // Bitcoin Core ConnectTip (validation.cpp:3073-3076) calls
    // mempool->removeForBlock(block.vtx, height) immediately after the
    // ConnectBlock + flush completes.  This evicts confirmed txs from the
    // mempool so they don't linger and get re-served via getrawmempool /
    // sendrawtransaction (which would otherwise stall or return spurious
    // "already in chain" errors).
    //
    // Gated on `atTip` because deep-IBD blocks (during the IBD fast path)
    // are unlikely to overlap with mempool contents — there's no peer feed
    // until we're synced — so skipping the iteration saves a tiny per-block
    // overhead.  Tip-extension and reorg-reconnect both run the removal.
    //
    // Best-effort: a removeForBlock failure must NOT roll back the connect.
    if (this.mempool && atTip) {
      try {
        this.mempool.removeForBlock(block);
      } catch (err) {
        console.warn(
          `[mempool.removeForBlock] non-fatal failure for block ${blockHash
            .toString("hex")
            .slice(0, 16)} at h=${height}: ${err instanceof Error ? err.message : String(err)}`
        );
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

    // ── Feed the wallet / fee-estimator on block-connect ──
    //
    // generatetoaddress + submitblock route through injectBlock (server.ts
    // generateSingleBlock B3 fix) and P2P tip-extension lands here too — all
    // BYPASS chainState.connectBlock, which is the only other place that fires
    // the shared `blockConnected` notification (state.ts:595). Without this, the
    // wallet's block-connect credit hook (cli.ts: chainEvents.on blockConnected
    // -> walletManager.processBlock) never runs for mined/synced tip blocks, so
    // getbalance stays 0 after generatetoaddress even though the coinbase pays a
    // wallet address (the spend/history/import regression FAIL). Emit here so
    // BOTH connect paths converge on the same listeners — Core's ConnectTip
    // fires BlockConnected for every connected block.
    //
    // Gated on `atTip` (matching removeForBlock + the tip inv above): deep-IBD
    // historical blocks are intentionally not fed per-block — the wallet adopts
    // its funds via the post-IBD rescan, unchanged by this fix. A block connects
    // through exactly one of connectBlock / BlockSync, so there is no double
    // credit. Best-effort: a notify failure must never roll back the connect.
    if (atTip && this.chainStateManager) {
      try {
        this.chainStateManager.emitBlockConnected(block);
      } catch (err) {
        console.warn(
          `[blockConnected notify] non-fatal failure for block ${blockHash
            .toString("hex")
            .slice(0, 16)} at h=${height}: ${err instanceof Error ? err.message : String(err)}`
        );
      }
    }

    // ── Pattern B: mempool refill on reorg ──
    //
    // If the pre-connect reorg dispatch (handleReorgUtxoAndCollect)
    // ran successfully, `reorgDisconnectedTxs` holds the non-coinbase
    // txs from blocks that were disconnected.  Feed them back to the
    // mempool now that the connect of the new tip is complete.
    //
    // Two refill paths are wired:
    //   • reorgUtxoFixed=true → use the FULL-CHECK readdTransactions
    //     path: input UTXOs were properly restored by the
    //     disconnect, so the mempool's policy validation succeeds
    //     normally and we get accurate fee/feeRate/sigOpCost data
    //     in each entry.  Mirrors camlcoin lib/sync.ml:2354-2363.
    //   • reorgUtxoFixed=false → fall back to reorgRefillUnchecked
    //     (no UTXO disconnect happened, so the FULL-CHECK path would
    //     drop every refill candidate with "Missing input").  This
    //     keeps the mempool dimension of the corpus passing even
    //     when undo data is missing on disk, accepting the
    //     UTXO-divergence vs. Core that occurs as a result.
    //
    // Cross-impl audit:
    // CORE-PARITY-AUDIT/_mempool-refill-on-reorg-fleet-result-2026-05-05.md
    // Reference shape: camlcoin lib/sync.ml:2304-2363.
    if (this.mempool && reorgDisconnectedTxs.length > 0) {
      try {
        if (reorgUtxoFixed) {
          await this.mempool.readdTransactions(reorgDisconnectedTxs);
        } else {
          this.mempool.reorgRefillUnchecked(reorgDisconnectedTxs);
        }
        console.log(
          `[mempool-refill] reorg refilled ${reorgDisconnectedTxs.length} txs (path=${reorgUtxoFixed ? "checked" : "unchecked"}, oldTip=${oldTipBeforeConnect!.toString("hex").slice(0, 16)}..., newTip=${blockHash.toString("hex").slice(0, 16)}...)`
        );
      } catch (err) {
        // Refill is best-effort; never fail a successful connect because
        // a tx couldn't be re-added.  The connect itself is what defines
        // chain progress.
        console.warn(
          `[mempool-refill] non-fatal failure during reorg refill: ${
            err instanceof Error ? err.message : String(err)
          }`
        );
      }
    }

    // ── Auto-prune hook ──
    //
    // Mirrors Bitcoin Core's `m_blockman.FindFilesToPrune` call in
    // `validation.cpp::FlushStateToDisk` (invoked from `ConnectTip`):
    // after every accepted block, ask the prune manager whether the
    // current usage has crossed the target.  No-op when:
    //   • pruneManager is unwired (operator did NOT pass `--prune=N`)
    //   • manual mode (`--prune=1`) — `findFilesToPrune` short-circuits
    //     on `isAutomaticPruning()`, leaving the only entry point as the
    //     `pruneblockchain` RPC.
    //
    // Throttled to once per PRUNE_CHECK_INTERVAL blocks so the
    // O(file_count) usage scan doesn't run on every IBD block.  Errors
    // are swallowed: pruning is opportunistic, never block-validation
    // critical, and a bad unlink (e.g. EBUSY on Windows) must not
    // strand the chain.
    if (this.pruneManager && this.pruneManager.isAutomaticPruning()) {
      this.blocksSincePruneCheck++;
      if (this.blocksSincePruneCheck >= PRUNE_CHECK_INTERVAL) {
        this.blocksSincePruneCheck = 0;
        try {
          await this.pruneManager.maybePrune(height);
        } catch (err) {
          console.warn(
            `[prune] non-fatal failure during auto-prune at height ${height}: ${
              err instanceof Error ? err.message : String(err)
            }`
          );
        }
      }
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
    const stalledPeerLookup = new Map<string, Peer>();
    if (this.peerManager) {
      for (const p of this.peerManager.getConnectedPeers()) {
        stalledPeerLookup.set(`${p.host}:${p.port}`, p);
      }
    }
    for (const hashHex of stalledBlocks) {
      const pending = this.state.pendingBlocks.get(hashHex);
      if (!pending) continue;

      // Remove from pending (both local map and peer's in-flight tracker)
      this.state.pendingBlocks.delete(hashHex);
      const stalledPeer = stalledPeerLookup.get(pending.peer);
      if (stalledPeer) {
        stalledPeer.removeBlockInFlight(hashHex);
      }

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
    //
    // The `__disconnect__` handler in registerWithPeerManager normally
    // does this synchronously; this loop is the safety net for the rare
    // case where a peer is dropped before the message handler can run
    // (e.g. a hard socket error path that bypasses the disconnect event).
    // Also decrements peerInfo.count and purges the stale peerInFlight
    // entry — same leak-fix rationale as the disconnect handler.
    if (this.peerManager && this.state.pendingBlocks.size > 0) {
      const connectedPeers = new Set(
        this.peerManager
          .getConnectedPeers()
          .map((p) => `${p.host}:${p.port}`)
      );
      let cleaned = 0;
      const deadPeers = new Set<string>();
      for (const [hashHex, pending] of this.state.pendingBlocks) {
        if (!connectedPeers.has(pending.peer)) {
          this.state.pendingBlocks.delete(hashHex);
          // Decrement the per-peer in-flight count so a reconnect doesn't
          // inherit a stuck value above MAX_IN_FLIGHT_PER_PEER.
          const peerInfo = this.peerInFlight.get(pending.peer);
          if (peerInfo) {
            peerInfo.count = Math.max(0, peerInfo.count - 1);
          }
          if (pending.height < this.state.nextHeightToRequest) {
            this.state.nextHeightToRequest = pending.height;
          }
          deadPeers.add(pending.peer);
          cleaned++;
        }
      }
      // Purge stale peerInFlight entries for the peers we just cleaned.
      // Same rationale as the __disconnect__ handler: a reconnect at the
      // same host:port should start fresh.
      for (const dead of deadPeers) {
        this.peerInFlight.delete(dead);
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
              this.downloadedBlockPeers.delete(hashHex);
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

    // ── Catch-all: idle-with-headroom recovery ──
    //
    // The block-download pipeline must never go idle while there are headers
    // ahead of the processing frontier.  Every other path in this function
    // calls `requestBlocks()` only conditionally (cleared stalls, cleared
    // disconnects, evicted deadlock).  An adversarial timing window slips
    // through all of them:
    //
    //   1. We previously assigned N requests, advancing
    //      `nextHeightToRequest` to N + previously-processed.
    //   2. All N pendings either delivered (advancing nextHeightToProcess by
    //      M < N) or got cleared by the disconnect cleanup above (which
    //      rolls nextHeightToRequest back only to the lowest cleared
    //      pending.height — which can still leave it above
    //      `nextHeightToProcess + MAX_DOWNLOADED_BUFFER * 2`).
    //   3. One out-of-order future block ends up in `downloadedBlocks`
    //      (e.g. a cmpctblock-fallback fetch, or a delivery from an old
    //      assignment that races a cleanup), so `dl > 0` but `pend == 0`.
    //   4. `requestBlocks()` is called but the inner while-loop bails
    //      immediately because `nextHeightToRequest > maxRequestHeight`
    //      (the cap is nextHeightToProcess + 64, which the request pointer
    //      already overshot in step 1).  No assignment happens.
    //   5. No further trigger fires: handleBlock isn't called (nothing
    //      arrives), the in-band stall path skips (pend == 0), the
    //      disconnect path skips (no new disconnect), and the deadlock-fix
    //      skips (dl < MAX_DOWNLOADED_BUFFER).  Stuck.
    //
    // Observed live on mainnet 2026-05-27 at h=76051 — `pend=0 dl=1 hdrs=
    // 250783` for 14 hours, 10 healthy peers, 0 blocks in flight per
    // `getpeerinfo`.  The dl=1 was a future block from a cmpctblock fetch.
    //
    // Fix: if we have headroom (process pointer < best-header AND
    // outstanding work < window) AND no pendings, roll the request pointer
    // back to nextHeightToProcess and retry.  This is the safety net for
    // the entire request pipeline.  Cheap (one comparison + one Map.size
    // read + at most one requestBlocks call per second), and guaranteed to
    // be a no-op in the steady-state happy path because requestBlocks
    // returns immediately when there's nothing to do.
    const bestHeader = this.headerSync.getBestHeader();
    if (
      bestHeader &&
      this.state.nextHeightToProcess <= bestHeader.height &&
      this.state.pendingBlocks.size === 0 &&
      this.state.downloadedBlocks.size < MAX_DOWNLOADED_BUFFER
    ) {
      if (this.state.nextHeightToRequest > this.state.nextHeightToProcess) {
        this.state.nextHeightToRequest = this.state.nextHeightToProcess;
      }
      this.requestBlocks();
    }

    // ── Header-sync idle catch-all ──
    //
    // `headers.ts:requestHeaders` gates the normal getheaders on
    // `needsMoreHeaders(peerBestHeight)`, where `peerBestHeight` is the peer's
    // version-handshake `startHeight` — a value captured ONCE at connect and
    // never refreshed.  A peer can legitimately have more headers than it
    // advertised: it appended blocks after the handshake, or (as in the
    // Track-B forward-replay feeder) it under-reports its height on purpose.
    // Bitcoin Core keeps discovering such headers because peers proactively
    // announce new blocks (inv / unsolicited headers), which drives a forced
    // getheaders (block-sync's inv-for-unknown-header path).  A feeder that
    // only answers requests and never announces gives no such trigger — so
    // once our header tip passes the stale advertised height, header sync
    // stops, and because block forward-sync can only chase known headers, the
    // whole pipeline wedges (symptom: `height=N/N (100%) 0 blk/s pend=0 dl=0`
    // with the feeder able to serve far past N).
    //
    // Fix: when the block frontier has DRAINED every known header
    // (`nextHeightToProcess > bestHeader.height`, nothing left to download)
    // and no block requests are outstanding, force a fresh getheaders from
    // every peer (bypassing the stale-height gate).  On a node genuinely at
    // the chain tip the peer returns an empty batch — a no-op.  If the peer
    // has more, header sync resumes and block download follows.  Rate-limited
    // so a truly-at-tip node only re-polls every HEADER_DRAIN_POLL_MS.
    if (
      bestHeader &&
      this.state.nextHeightToProcess > bestHeader.height &&
      this.state.pendingBlocks.size === 0 &&
      now - this.lastHeaderDrainPoll > HEADER_DRAIN_POLL_MS
    ) {
      this.lastHeaderDrainPoll = now;
      for (const peer of this.peerManager.getConnectedPeers()) {
        this.headerSync.requestHeaders(peer, true);
      }
    }

    // ── Critical-block parallel-blast trigger ──
    //
    // `requestBlocks()` contains a "blast the critical block to ALL peers
    // after 30 s" path (lines ~1158-1174).  Pre-fix that path only ran when
    // requestBlocks() itself was invoked — which during a slow-peer cascade
    // (pend > 0 but no new arrivals) NEVER happened: handleBlock didn't
    // fire (nothing arriving), the other handleStalled triggers all
    // require either a stall-timeout firing or a disconnect, and the
    // idle-with-headroom catch-all above requires `pendingBlocks.size == 0`.
    //
    // Result: a peer stalled for the full 120 s BASE_STALL_TIMEOUT before
    // the critical block was re-requested, even when there were 9 other
    // peers idle and ready to serve.  Symptom on mainnet 2026-05-27:
    // bursty 2-5 blocks zip through, then 5 min stuck, then repeat —
    // ~0.35 blk/min effective IBD rate.
    //
    // Fix: call requestBlocks() unconditionally on every poll tick (1 Hz).
    // It's cheap (early-return if the downloaded buffer is full or there
    // are no peers), and it gives the critical-block blast a chance to run
    // every second instead of only when something else triggers a request
    // cycle.  Combined with the lower MAX_IN_FLIGHT_PER_PEER (4) and the
    // DUP-REQ fall-back-to-any-peer fix above, this should restore IBD
    // throughput to the ~10+ blk/min range observed at smaller heights.
    if (
      bestHeader &&
      this.state.nextHeightToProcess <= bestHeader.height &&
      this.state.pendingBlocks.size > 0
    ) {
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
    this.hasCompletedInitialSync = true;
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
   * The AUTHORITATIVE UTXO view — the one this BlockSync mutates on every
   * connectBlock (spendOutput / addTransaction) and flushes to the coins DB.
   *
   * NOTE: ChainStateManager constructs a SEPARATE UTXOManager over the same
   * LevelDB (chain/state.ts), but its in-memory CoinsViewCache is NOT updated
   * by block connect — so a coin spent by a freshly-connected block can linger
   * (stale-cached) in ChainStateManager's view while it is correctly gone from
   * THIS view + the DB. RPC reads of the live UTXO set (gettxout) must therefore
   * consult THIS manager to see the post-connect state. Exposed read-only.
   */
  getUTXOManager(): UTXOManager {
    return this.utxoManager;
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
        this.downloadedBlockPeers.delete(hashHex);
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
