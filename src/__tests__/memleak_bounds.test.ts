/**
 * Regression tests for BUG-hotbuns-memleak-2026-07-20 — RSS climbed to the
 * 16G cgroup cap in 18-36h (3 OOM kills since Jul 17).
 *
 * Structures covered (see receipts/BUG-hotbuns-memleak-2026-07-20.md):
 *   S1 — TxReconciliationTracker.states: per-peer Erlay state + live
 *        setInterval timers, only freed by forgetPeer()/sweep().
 *   S2 — CompactBlockManager.peerStates: per-peer compact-block state incl.
 *        pendingBlockTxn partial blocks (MBs each), only freed by
 *        removePeer()/sweep(); pendingBlockTxn now hard-capped per peer.
 *   S3 — Mempool "300 MB" cap previously counted raw vsize while the JS
 *        object graph retained 10-20x that in heap. Eviction now trims
 *        against estimateEntryUsage() (analogue of Core's
 *        DynamicMemoryUsage(), txmempool.cpp:778/868).
 *
 * Fix-plan item 5: simulated connect/disconnect churn of 1k peers asserts
 * state maps return to size 0 (no leaked entries, no live recon timers).
 */

import { describe, test, expect, beforeEach, afterEach } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  TxReconciliationTracker,
  ReconciliationRegisterResult,
  type TxReconciliationCallbacks,
} from "../p2p/erlay.js";
import {
  CompactBlockManager,
  createCompactBlockFromBlock,
  MAX_PENDING_BLOCKS_PER_PEER,
} from "../p2p/compact_blocks.js";
import type { Peer } from "../p2p/peer.js";
import type { Block, BlockHeader } from "../validation/block.js";
import type { Transaction } from "../validation/tx.js";
import { ChainDB, type UTXOEntry } from "../storage/database.js";
import { UTXOManager } from "../chain/utxo.js";
import { REGTEST } from "../consensus/params.js";
import { Mempool, estimateEntryUsage } from "../mempool/mempool.js";
import { getTxVSize } from "../validation/tx.js";

// ============================================================================
// Helpers
// ============================================================================

function fakePeer(i: number): Peer {
  // Erlay/compact-block state is keyed by `${host}:${port}` only.
  return { host: `10.${(i >> 8) & 0xff}.${i & 0xff}.1`, port: 40000 + (i % 20000) } as unknown as Peer;
}

const noopCallbacks: TxReconciliationCallbacks = {
  sendMessage: () => {},
  requestTransactions: () => {},
  announceTransactions: () => {},
};

function mockHeader(nonce: number = 0): BlockHeader {
  return {
    version: 1,
    prevBlock: Buffer.alloc(32, 0x01),
    merkleRoot: Buffer.alloc(32, 0x02),
    timestamp: 1600000000,
    bits: 0x1d00ffff,
    nonce,
  };
}

function mockCoinbase(height: number = 1): Transaction {
  return {
    version: 1,
    inputs: [
      {
        prevOut: { txid: Buffer.alloc(32, 0x00), vout: 0xffffffff },
        scriptSig: Buffer.from([0x01, height & 0xff]),
        sequence: 0xffffffff,
        witness: [],
      },
    ],
    outputs: [
      {
        value: 5000000000n,
        scriptPubKey: Buffer.from([0x76, 0xa9, 0x14, ...Buffer.alloc(20, 0xaa), 0x88, 0xac]),
      },
    ],
    lockTime: 0,
  };
}

function mockBlock(nonce: number): Block {
  return { header: mockHeader(nonce), transactions: [mockCoinbase()] };
}

// ============================================================================
// S1 — Erlay per-peer state churn
// ============================================================================

describe("S1 — Erlay state is freed on disconnect (1k-peer churn)", () => {
  test("forgetPeer() after 1000 register/disconnect cycles leaves 0 states", () => {
    const tracker = new TxReconciliationTracker(noopCallbacks);
    const peers: Peer[] = [];
    for (let i = 0; i < 1000; i++) {
      const peer = fakePeer(i);
      peers.push(peer);
      const salt = tracker.preRegisterPeer(peer);
      // Half outbound (weInitiate=true → live recon setInterval), half inbound.
      const inbound = i % 2 === 0;
      const result = tracker.registerPeer(peer, inbound, 1, salt ^ 0xdeadbeefn);
      expect(result).toBe(ReconciliationRegisterResult.SUCCESS);
    }
    expect(tracker.getStateCount()).toBe(1000);

    // Disconnect churn: every peer leaves. Before the fix nothing ever
    // called forgetPeer (zero call sites) — states and timers leaked.
    for (const peer of peers) tracker.forgetPeer(peer);
    expect(tracker.getStateCount()).toBe(0);
  });

  test("sweep() reaps states (and timers) for peers no longer connected", () => {
    const tracker = new TxReconciliationTracker(noopCallbacks);
    const peers: Peer[] = [];
    for (let i = 0; i < 1000; i++) {
      const peer = fakePeer(i);
      peers.push(peer);
      const salt = tracker.preRegisterPeer(peer);
      tracker.registerPeer(peer, false, 1, salt ^ 0x1234n); // all with timers
    }
    expect(tracker.getStateCount()).toBe(1000);

    // Only 10 peers are still connected.
    const active = peers.slice(0, 10).map((p) => `${p.host}:${p.port}`);
    const reaped = tracker.sweep(active);
    expect(reaped).toBe(990);
    expect(tracker.getStateCount()).toBe(10);

    // Idempotent: nothing left to reap.
    expect(tracker.sweep(active)).toBe(0);

    // Cleanup remaining timers.
    for (const p of peers.slice(0, 10)) tracker.forgetPeer(p);
    expect(tracker.getStateCount()).toBe(0);
  });
});

// ============================================================================
// S2 — CompactBlockManager per-peer state churn + pendingBlockTxn cap
// ============================================================================

describe("S2 — compact-block peer state is freed and pending map is capped", () => {
  test("removePeer()/sweep() after 1000-peer churn leaves 0 states", () => {
    const mgr = new CompactBlockManager();
    const ids: string[] = [];
    for (let i = 0; i < 1000; i++) {
      const peer = fakePeer(i);
      const id = `${peer.host}:${peer.port}`;
      ids.push(id);
      mgr.getState(id); // what handleSendCmpct/startBlockReconstruction do
    }
    expect(mgr.getPeerStateCount()).toBe(1000);

    for (const id of ids.slice(0, 500)) mgr.removePeer(id);
    expect(mgr.getPeerStateCount()).toBe(500);

    const reaped = mgr.sweep([]);
    expect(reaped).toBe(500);
    expect(mgr.getPeerStateCount()).toBe(0);
  });

  test("pendingBlockTxn is capped at MAX_PENDING_BLOCKS_PER_PEER", () => {
    const mgr = new CompactBlockManager();
    const peerId = "10.0.0.1:8333";
    // A peer that starts many reconstructions and never answers getblocktxn
    // previously stranded one PartiallyDownloadedBlock per cmpctblock forever.
    for (let i = 0; i < 3 * MAX_PENDING_BLOCKS_PER_PEER; i++) {
      const compact = createCompactBlockFromBlock(mockBlock(i), BigInt(i));
      const partial = mgr.startBlockReconstruction(compact, `hash-${i}`, peerId);
      expect(partial).not.toBeNull();
      expect(mgr.getState(peerId).pendingBlockTxn.size).toBeLessThanOrEqual(
        MAX_PENDING_BLOCKS_PER_PEER
      );
    }
    expect(mgr.getState(peerId).pendingBlockTxn.size).toBe(MAX_PENDING_BLOCKS_PER_PEER);
    // Oldest entries were evicted, newest retained.
    expect(mgr.getState(peerId).pendingBlockTxn.has("hash-0")).toBe(false);
    expect(
      mgr.getState(peerId).pendingBlockTxn.has(`hash-${3 * MAX_PENDING_BLOCKS_PER_PEER - 1}`)
    ).toBe(true);
  });
});

// ============================================================================
// S3 — Mempool bounded by estimated heap usage, not raw vsize
// ============================================================================

describe("S3 — mempool eviction bounds estimated heap usage", () => {
  let tempDir: string;
  let db: ChainDB;
  let utxo: UTXOManager;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "memleak-bounds-"));
    db = new ChainDB(tempDir);
    await db.open();
    utxo = new UTXOManager(db);
  });

  afterEach(async () => {
    await db.close();
    await rm(tempDir, { recursive: true, force: true });
  });

  function makeTx(txid: Buffer, value: bigint): Transaction {
    return {
      version: 2,
      inputs: [
        {
          prevOut: { txid, vout: 0 },
          scriptSig: Buffer.alloc(0),
          sequence: 0xffffffff,
          witness: [],
        },
      ],
      outputs: [
        { value, scriptPubKey: Buffer.from([0x51, 0x02, 0x4e, 0x73]) }, // P2A anchor
        { value: 0n, scriptPubKey: Buffer.from([0x6a]) }, // OP_RETURN padding
      ],
      lockTime: 0,
    };
  }

  test("estimateEntryUsage() reflects JS object-graph overhead (>> vsize)", () => {
    const tx = makeTx(Buffer.alloc(32, 0x42), 999_000n);
    const vsize = getTxVSize(tx);
    const usage = estimateEntryUsage(tx, vsize);
    expect(usage).toBeGreaterThanOrEqual(vsize); // hard floor
    // A small parsed tx retains many times its vsize in heap (BUG S3: 10-20x).
    expect(usage).toBeGreaterThan(4 * vsize);
  });

  test("usage stays <= maxSize while adding 100 txs into a tiny pool", async () => {
    // maxSize bounds estimated USAGE (like Core's -maxmempool vs
    // DynamicMemoryUsage), so with ~1.5-2 KB usage per tiny tx this pool
    // saturates after ~10-15 txs — far before 100.
    const MAX = 25_000;
    const mempool = new Mempool(utxo, REGTEST, MAX);
    mempool.setTipHeight(200);

    let accepted = 0;
    for (let i = 0; i < 100; i++) {
      const utxoId = Buffer.alloc(32);
      utxoId.writeUInt32LE(i + 1, 0);
      utxoId[31] = 0x7f;
      const entry: UTXOEntry = {
        height: 1,
        coinbase: false,
        amount: 1_000_000n,
        scriptPubKey: Buffer.from([0x51, 0x02, 0x4e, 0x73]),
      };
      await db.putUTXO(utxoId, 0, entry);

      // Steadily rising feerate so later txs out-bid the rolling minimum
      // that eviction establishes.
      const fee = 2_000n + BigInt(i) * 1_000n;
      const tx = makeTx(utxoId, 1_000_000n - fee);
      const result = await mempool.addTransaction(tx);
      if (result.accepted) accepted++;

      // The invariant under test: after every admission the estimated
      // heap usage is back under the cap (evict() trims on usage).
      const info = mempool.getInfo();
      expect(info.usage).toBeLessThanOrEqual(MAX);
      expect(info.usage).toBeGreaterThanOrEqual(info.bytes); // usage >= vsize total
    }

    const info = mempool.getInfo();
    // Pool must have admitted txs and then evicted to stay bounded —
    // unbounded behavior would end with all accepted txs resident.
    expect(accepted).toBeGreaterThan(info.size);
    expect(info.size).toBeGreaterThan(0);
    expect(info.usage).toBeLessThanOrEqual(MAX);
    expect(info.maxmempool).toBe(MAX);
  });
});
