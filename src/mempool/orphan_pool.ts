/**
 * Orphan transaction pool.
 *
 * An orphan transaction is one whose parent(s) (the txs producing the inputs
 * it spends) are not yet in the mempool or chain. Bitcoin Core stores these
 * in a bounded data structure and re-evaluates them when a parent arrives.
 * Without an orphan pool a node silently drops out-of-order tx broadcasts —
 * not a DoS hole, but breaks fast tx propagation latency on real networks.
 *
 * Reference: bitcoin-core/src/node/txorphanage.{cpp,h}.
 *
 * This is a simplified Core-parity port — it covers the four properties the
 * audit (`CORE-PARITY-AUDIT/_dos-misbehavior-cross-impl-audit-2026-05-06.md`)
 * called out:
 *
 *   1. Global cap of 100 orphan txs.
 *   2. Per-tx size cap of 100_000 bytes (Core MAX_STANDARD_TX_WEIGHT / 4).
 *   3. Per-peer announcement cap so one misbehaving peer can't fill the map.
 *   4. Eviction: random when at the global cap (Core's strategy when the
 *      orphan map overflows; matches `EvictRandom` in the txorphanage
 *      implementation).
 *
 * Plus Core's parent-arrival flow: `findByPrevout` lets the caller retry
 * resolution when a parent tx is admitted; `eraseTx` / `eraseForPeer` /
 * `eraseForBlock` are the standard cleanup hooks.
 *
 * Not thread-safe — caller must externalise synchronisation (matches Core's
 * `class TxOrphanage` contract).
 */

import type { Transaction } from "../validation/tx.js";
import { getTxId, getWTxId, serializeTx } from "../validation/tx.js";

/**
 * Maximum number of orphan transactions stored globally (Core parity).
 *
 * Core's modern txorphanage uses a weight/latency-score scheme but the
 * historical bound is 100 announcements. We keep the simpler announcement
 * count here.
 */
export const MAX_ORPHAN_TRANSACTIONS = 100;

/**
 * Maximum serialized size in bytes of any orphan tx (Core parity).
 *
 * Core uses MAX_STANDARD_TX_WEIGHT (400_000) / WITNESS_SCALE_FACTOR (4) =
 * 100_000 bytes as the orphan-size guard. Larger txs are not standard so
 * they will never resolve through normal relay anyway.
 */
export const MAX_ORPHAN_TX_SIZE = 100_000;

/**
 * Per-peer announcement cap.
 *
 * Without this, a single misbehaving peer can fill the full 100-slot map and
 * prevent honest peers' orphans from being held. Core's modern code uses a
 * weight reservation per peer; we use a count-based bound that scales with
 * the global cap.
 */
export const MAX_PEER_ORPHAN_TX = 50;

/**
 * One orphan entry. The entry tracks its arrival time so eviction can fall
 * back to oldest-first when random eviction would dislodge a fresh arrival.
 */
export interface OrphanEntry {
  tx: Transaction;
  /** Cached txid (= sha256d of legacy serialization). */
  readonly txid: Buffer;
  /** Cached wtxid (= sha256d of segwit serialization). */
  readonly wtxid: Buffer;
  /** Peer that announced this orphan (any string id; usually peer.id). */
  readonly fromPeer: string;
  /** Wall-clock time of admission (ms since epoch). */
  readonly addedAt: number;
  /** Cached serialized size in bytes. */
  readonly size: number;
}

/**
 * Result of attempting to admit an orphan.
 */
export type AdmitResult =
  | { ok: true; entry: OrphanEntry }
  | { ok: false; reason: AdmitRejectReason };

export type AdmitRejectReason =
  | "duplicate" // already in pool
  | "tx-too-large" // exceeds MAX_ORPHAN_TX_SIZE
  | "peer-cap" // peer at MAX_PEER_ORPHAN_TX
  | "no-inputs"; // refuse to track txs with zero inputs (coinbase-shaped)

/**
 * In-memory orphan transaction pool. Bounded, per-peer-capped, with
 * parent-arrival lookup support.
 */
export class OrphanPool {
  /** Primary storage keyed by lowercase hex of wtxid. */
  private readonly byWtxid = new Map<string, OrphanEntry>();

  /** Secondary index: txid hex -> wtxid hex (lets callers look up by either). */
  private readonly txidIndex = new Map<string, string>();

  /**
   * Reverse index: prevOut key (`txid:vout`) -> set of wtxid hex of orphans
   * whose inputs reference that outpoint. This is the "find children of a
   * newly-arrived parent" lookup.
   */
  private readonly byPrevout = new Map<string, Set<string>>();

  /** Per-peer announcement count. */
  private readonly peerCount = new Map<string, number>();

  /**
   * Optional RNG for eviction. Tests inject a deterministic sequence.
   * Defaults to Math.random.
   */
  private readonly random: () => number;

  /** Orphan-specific tunable bounds (override defaults for tests). */
  readonly maxGlobal: number;
  readonly maxPerPeer: number;
  readonly maxTxSize: number;

  constructor(
    options: {
      maxGlobal?: number;
      maxPerPeer?: number;
      maxTxSize?: number;
      random?: () => number;
    } = {}
  ) {
    this.maxGlobal = options.maxGlobal ?? MAX_ORPHAN_TRANSACTIONS;
    this.maxPerPeer = options.maxPerPeer ?? MAX_PEER_ORPHAN_TX;
    this.maxTxSize = options.maxTxSize ?? MAX_ORPHAN_TX_SIZE;
    this.random = options.random ?? Math.random;
  }

  /** Number of orphans currently held. */
  size(): number {
    return this.byWtxid.size;
  }

  /** Has an orphan with this wtxid? */
  has(wtxid: Buffer): boolean {
    return this.byWtxid.has(wtxid.toString("hex"));
  }

  /** Has an orphan with this txid (legacy hash)? */
  hasByTxid(txid: Buffer): boolean {
    return this.txidIndex.has(txid.toString("hex"));
  }

  /** Get an entry by wtxid, or undefined. */
  get(wtxid: Buffer): OrphanEntry | undefined {
    return this.byWtxid.get(wtxid.toString("hex"));
  }

  /** Number of orphans announced by a given peer. */
  countForPeer(peer: string): number {
    return this.peerCount.get(peer) ?? 0;
  }

  /**
   * Admit an orphan. Returns ok=false with a reason if rejected.
   *
   * Caller is responsible for having determined the tx is missing inputs
   * (`TX_MISSING_INPUTS` in Core terms) before calling. We do not re-verify.
   */
  add(tx: Transaction, fromPeer: string): AdmitResult {
    if (tx.inputs.length === 0) {
      return { ok: false, reason: "no-inputs" };
    }

    const size = serializeTx(tx, true).length;
    if (size > this.maxTxSize) {
      return { ok: false, reason: "tx-too-large" };
    }

    const wtxid = getWTxId(tx);
    const wtxidHex = wtxid.toString("hex");
    if (this.byWtxid.has(wtxidHex)) {
      return { ok: false, reason: "duplicate" };
    }

    const peerCount = this.peerCount.get(fromPeer) ?? 0;
    if (peerCount >= this.maxPerPeer) {
      return { ok: false, reason: "peer-cap" };
    }

    // If we're at the global cap, evict a random other orphan.
    while (this.byWtxid.size >= this.maxGlobal) {
      this.evictRandom();
    }

    const txid = getTxId(tx);
    const entry: OrphanEntry = {
      tx,
      txid,
      wtxid,
      fromPeer,
      addedAt: Date.now(),
      size,
    };

    this.byWtxid.set(wtxidHex, entry);
    this.txidIndex.set(txid.toString("hex"), wtxidHex);
    this.peerCount.set(fromPeer, peerCount + 1);

    // Index by each input's prevout so we can look up children when a
    // parent arrives.
    for (const input of tx.inputs) {
      const key = prevoutKey(input.prevOut.txid, input.prevOut.vout);
      let set = this.byPrevout.get(key);
      if (!set) {
        set = new Set();
        this.byPrevout.set(key, set);
      }
      set.add(wtxidHex);
    }

    return { ok: true, entry };
  }

  /**
   * Erase an orphan by wtxid. Returns true if something was removed.
   */
  eraseTx(wtxid: Buffer): boolean {
    const wtxidHex = wtxid.toString("hex");
    const entry = this.byWtxid.get(wtxidHex);
    if (!entry) return false;
    this.removeEntry(entry);
    return true;
  }

  /**
   * Erase all orphans announced by `peer` (e.g. on disconnect).
   * Returns the number of orphans erased.
   */
  eraseForPeer(peer: string): number {
    let removed = 0;
    // Collect first to avoid mutating during iteration.
    const toRemove: OrphanEntry[] = [];
    for (const entry of this.byWtxid.values()) {
      if (entry.fromPeer === peer) toRemove.push(entry);
    }
    for (const entry of toRemove) {
      this.removeEntry(entry);
      removed++;
    }
    return removed;
  }

  /**
   * Erase orphans whose txid appears in this list of confirmed txids.
   *
   * Caller passes confirmed txids when a new block is connected. This is the
   * Core `EraseForBlock` hook; Core also evicts orphans whose inputs are now
   * spent by another tx in the block, but for this simplified port we just
   * remove orphans that themselves got mined.
   */
  eraseForBlock(confirmedTxids: Iterable<Buffer>): number {
    let removed = 0;
    for (const txid of confirmedTxids) {
      const wtxidHex = this.txidIndex.get(txid.toString("hex"));
      if (!wtxidHex) continue;
      const entry = this.byWtxid.get(wtxidHex);
      if (!entry) continue;
      this.removeEntry(entry);
      removed++;
    }
    return removed;
  }

  /**
   * Find every orphan that lists `(parentTxid, vout)` as one of its inputs.
   *
   * On parent-tx arrival the caller iterates the parent's outputs and for
   * each output asks the pool for orphans referring to it. Any returned
   * orphan is a candidate to retry-admit into the mempool now that one of
   * its parents is resolved.
   */
  findByPrevout(parentTxid: Buffer, vout: number): OrphanEntry[] {
    const set = this.byPrevout.get(prevoutKey(parentTxid, vout));
    if (!set) return [];
    const out: OrphanEntry[] = [];
    for (const wtxidHex of set) {
      const entry = this.byWtxid.get(wtxidHex);
      if (entry) out.push(entry);
    }
    return out;
  }

  /**
   * Find every orphan that depends on any output of `parentTxid` (any vout).
   *
   * Used on full parent admission: caller will then re-attempt the orphans
   * via mempool.acceptTx.
   */
  findChildrenOf(parentTxid: Buffer): OrphanEntry[] {
    const parentHex = parentTxid.toString("hex");
    const out: OrphanEntry[] = [];
    const seen = new Set<string>();
    for (const [key, set] of this.byPrevout) {
      const colon = key.indexOf(":");
      if (colon === -1) continue;
      if (key.slice(0, colon) !== parentHex) continue;
      for (const wtxidHex of set) {
        if (seen.has(wtxidHex)) continue;
        seen.add(wtxidHex);
        const entry = this.byWtxid.get(wtxidHex);
        if (entry) out.push(entry);
      }
    }
    return out;
  }

  /**
   * Notify the pool that `parent` has been admitted to the mempool / chain.
   * Returns the orphans that were waiting on it. Caller is responsible for
   * re-running validation on each returned orphan and calling `eraseTx` on
   * the ones that resolve.
   */
  onParentAdmitted(parent: Transaction): OrphanEntry[] {
    return this.findChildrenOf(getTxId(parent));
  }

  /** Remove all orphans (test helper / shutdown). */
  clear(): void {
    this.byWtxid.clear();
    this.txidIndex.clear();
    this.byPrevout.clear();
    this.peerCount.clear();
  }

  /**
   * Evict a random orphan to make space.
   *
   * Core's `LimitOrphans` evicts oldest-first when over the latency budget
   * but historically used random eviction at the global cap. We pick
   * uniformly at random among current entries; if `random` produces a
   * deterministic 0 the result is the first iteration value — caller
   * should not rely on a specific entry being chosen.
   */
  private evictRandom(): void {
    const size = this.byWtxid.size;
    if (size === 0) return;
    const target = Math.floor(this.random() * size);
    let i = 0;
    for (const entry of this.byWtxid.values()) {
      if (i === target) {
        this.removeEntry(entry);
        return;
      }
      i++;
    }
  }

  private removeEntry(entry: OrphanEntry): void {
    const wtxidHex = entry.wtxid.toString("hex");
    this.byWtxid.delete(wtxidHex);
    this.txidIndex.delete(entry.txid.toString("hex"));

    const newPeerCount = (this.peerCount.get(entry.fromPeer) ?? 1) - 1;
    if (newPeerCount <= 0) {
      this.peerCount.delete(entry.fromPeer);
    } else {
      this.peerCount.set(entry.fromPeer, newPeerCount);
    }

    for (const input of entry.tx.inputs) {
      const key = prevoutKey(input.prevOut.txid, input.prevOut.vout);
      const set = this.byPrevout.get(key);
      if (!set) continue;
      set.delete(wtxidHex);
      if (set.size === 0) this.byPrevout.delete(key);
    }
  }
}

function prevoutKey(txid: Buffer, vout: number): string {
  return `${txid.toString("hex")}:${vout}`;
}
