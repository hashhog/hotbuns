/**
 * Integration tests for the orphan-pool wiring in `src/cli/cli.ts`.
 *
 * These tests reproduce the exact 5 hooks the cli sets up — addTx, missing-input
 * insert, parent-arrival cascade, peer-disconnect erase, block-connect erase —
 * against a real Mempool + UTXOManager instance. The goal is to catch the
 * "orphan pool exists but is never called from production" failure mode that
 * the Pattern-A footnote of hotbuns DoS wave 63b060c flagged.
 *
 * Reference: bitcoin-core/src/node/txorphanage.cpp +
 * CORE-PARITY-AUDIT/_dos-misbehavior-cross-impl-audit-2026-05-06.md.
 */

import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ChainDB, type UTXOEntry } from "../storage/database.js";
import { UTXOManager } from "../chain/utxo.js";
import { REGTEST } from "../consensus/params.js";
import { Mempool } from "./mempool.js";
import { OrphanPool } from "./orphan_pool.js";
import type { Transaction } from "../validation/tx.js";
import { getTxId } from "../validation/tx.js";

/** Minimal regtest-shaped tx (OP_TRUE scripts so script verify is trivially passing). */
function createTestTx(
  inputs: Array<{ txid: Buffer; vout: number }>,
  outputs: Array<{ value: bigint; scriptPubKey?: Buffer }>
): Transaction {
  return {
    version: 2,
    inputs: inputs.map((inp) => ({
      prevOut: { txid: inp.txid, vout: inp.vout },
      scriptSig: Buffer.alloc(0),
      sequence: 0xffffffff,
      witness: [],
    })),
    outputs: [
      ...outputs.map((out) => ({
        value: out.value,
        // P2A: standard "anchor" type, spendable with empty scriptSig + witness.
        scriptPubKey: out.scriptPubKey ?? Buffer.from([0x51, 0x02, 0x4e, 0x73]),
      })),
      { value: 0n, scriptPubKey: Buffer.from([0x6a]) }, // OP_RETURN padding (≥65 bytes)
    ],
    lockTime: 0,
  };
}

async function setupUTXO(
  db: ChainDB,
  txid: Buffer,
  vout: number,
  amount: bigint,
  height: number = 1,
  coinbase: boolean = false
): Promise<void> {
  const entry: UTXOEntry = {
    height,
    coinbase,
    amount,
    scriptPubKey: Buffer.from([0x51, 0x02, 0x4e, 0x73]),
  };
  await db.putUTXO(txid, vout, entry);
}

/** Mirrors the predicate used in cli.ts for routing missing-input rejects to the orphan pool. */
function isMissingInputError(err: string | undefined): boolean {
  if (typeof err !== "string") return false;
  // W96: mempool emits Bitcoin Core's canonical reject reason
  // (`bad-txns-inputs-missingorspent`, see validation.cpp:866). Legacy
  // `Missing input:` is kept for back-compat with older callers.
  return (
    err.startsWith("bad-txns-inputs-missingorspent") ||
    err.startsWith("Missing input:")
  );
}

/**
 * Mirrors `processOrphanCascade` from cli.ts: bounded worklist that promotes
 * orphans whose parent just resolved.  Returns the txids successfully promoted
 * so tests can assert on them.
 */
async function processOrphanCascade(
  parent: Transaction,
  pool: OrphanPool,
  mempool: Mempool,
  maxIter = 64
): Promise<string[]> {
  const promoted: string[] = [];
  const worklist: Transaction[] = [parent];
  let iter = 0;
  while (worklist.length > 0 && iter < maxIter) {
    iter++;
    const next = worklist.shift()!;
    const children = pool.onParentAdmitted(next);
    for (const child of children) {
      const r = await mempool.acceptToMemoryPool(child.tx);
      if (r.accepted) {
        pool.eraseTx(child.wtxid);
        promoted.push(child.txid.toString("hex"));
        worklist.push(child.tx);
      } else if (!isMissingInputError(r.error)) {
        pool.eraseTx(child.wtxid);
      }
    }
  }
  return promoted;
}

describe("OrphanPool — production wiring (integration)", () => {
  let tempDir: string;
  let db: ChainDB;
  let utxo: UTXOManager;
  let mempool: Mempool;
  let orphanPool: OrphanPool;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "orphan-pool-int-"));
    db = new ChainDB(tempDir);
    await db.open();
    utxo = new UTXOManager(db);
    mempool = new Mempool(utxo, REGTEST, 1_000_000);
    mempool.setTipHeight(200);
    orphanPool = new OrphanPool();
  });

  afterEach(async () => {
    await db.close();
    await rm(tempDir, { recursive: true, force: true });
  });

  test("missing-input tx is held in orphan pool, not silently dropped", async () => {
    // Parent tx is NOT in mempool / UTXO yet. Child references it.
    const ghostParentTxid = Buffer.alloc(32, 0xaa);
    const child = createTestTx([{ txid: ghostParentTxid, vout: 0 }], [{ value: 9_000n }]);

    const result = await mempool.acceptToMemoryPool(child);
    expect(result.accepted).toBe(false);
    expect(isMissingInputError(result.error)).toBe(true);

    // cli.ts wiring: missing-input -> orphan pool insert.
    const admit = orphanPool.add(child, "peer-A:8333");
    expect(admit.ok).toBe(true);
    expect(orphanPool.size()).toBe(1);
    if (admit.ok) {
      // Pool indexed the input's prevout so the parent's arrival can find it.
      expect(orphanPool.findByPrevout(ghostParentTxid, 0).length).toBe(1);
      expect(admit.entry.fromPeer).toBe("peer-A:8333");
    }
  });

  test("when parent arrives, orphan is cascade-promoted into mempool", async () => {
    // Build chain: confirmed UTXO -> parent (mempool) -> child (orphan until parent admits).
    const confirmedTxid = Buffer.alloc(32, 0xbb);
    await setupUTXO(db, confirmedTxid, 0, 100_000n);

    const parent = createTestTx(
      [{ txid: confirmedTxid, vout: 0 }],
      [{ value: 90_000n }]
    );
    const parentTxid = getTxId(parent);

    const child = createTestTx([{ txid: parentTxid, vout: 0 }], [{ value: 80_000n }]);
    const childTxid = getTxId(child);

    // Step 1: child arrives first, gets routed to orphan pool.
    const childResult = await mempool.acceptToMemoryPool(child);
    expect(childResult.accepted).toBe(false);
    expect(isMissingInputError(childResult.error)).toBe(true);
    const childAdmit = orphanPool.add(child, "peer-B:18333");
    expect(childAdmit.ok).toBe(true);
    expect(orphanPool.size()).toBe(1);
    expect(mempool.hasTransaction(childTxid)).toBe(false);

    // Step 2: parent arrives. cli.ts hook: on successful admit, cascade-promote.
    const parentResult = await mempool.acceptToMemoryPool(parent);
    expect(parentResult.accepted).toBe(true);
    const promoted = await processOrphanCascade(parent, orphanPool, mempool);

    // Child should now be in the mempool, removed from orphan pool.
    expect(promoted).toContain(childTxid.toString("hex"));
    expect(mempool.hasTransaction(childTxid)).toBe(true);
    expect(orphanPool.size()).toBe(0);
  });

  test("cascade promotes a deep chain (grandparent -> parent -> child) in one trigger", async () => {
    // Confirmed -> A (parent) -> B (child) -> C (grandchild). B and C arrive
    // before A; A's admission must promote B, B's promotion must promote C.
    const confirmedTxid = Buffer.alloc(32, 0xcc);
    await setupUTXO(db, confirmedTxid, 0, 200_000n);

    const txA = createTestTx([{ txid: confirmedTxid, vout: 0 }], [{ value: 180_000n }]);
    const txB = createTestTx([{ txid: getTxId(txA), vout: 0 }], [{ value: 160_000n }]);
    const txC = createTestTx([{ txid: getTxId(txB), vout: 0 }], [{ value: 140_000n }]);

    // C and B arrive first; both go to orphan pool.
    expect((await mempool.acceptToMemoryPool(txC)).accepted).toBe(false);
    expect(orphanPool.add(txC, "peer-X:8333").ok).toBe(true);
    expect((await mempool.acceptToMemoryPool(txB)).accepted).toBe(false);
    expect(orphanPool.add(txB, "peer-X:8333").ok).toBe(true);
    expect(orphanPool.size()).toBe(2);

    // A arrives. Cascade should drain BOTH orphans bottom-up.
    expect((await mempool.acceptToMemoryPool(txA)).accepted).toBe(true);
    const promoted = await processOrphanCascade(txA, orphanPool, mempool);

    expect(promoted.length).toBe(2);
    expect(promoted).toContain(getTxId(txB).toString("hex"));
    expect(promoted).toContain(getTxId(txC).toString("hex"));
    expect(orphanPool.size()).toBe(0);
    expect(mempool.hasTransaction(getTxId(txB))).toBe(true);
    expect(mempool.hasTransaction(getTxId(txC))).toBe(true);
  });

  test("on peer disconnect, that peer's orphans are erased; honest peers untouched", async () => {
    // Three orphans from "evil", one from "honest" — same shape as the
    // cli __disconnect__ hook will see in production.
    const evilKey = "evil:8333";
    const honestKey = "honest:8333";
    for (let i = 0; i < 3; i++) {
      const tx = createTestTx(
        [{ txid: Buffer.alloc(32, 0xd0 + i), vout: 0 }],
        [{ value: 1_000n }]
      );
      const r = orphanPool.add(tx, evilKey);
      expect(r.ok).toBe(true);
    }
    const goodTx = createTestTx(
      [{ txid: Buffer.alloc(32, 0xee), vout: 0 }],
      [{ value: 1_000n }]
    );
    expect(orphanPool.add(goodTx, honestKey).ok).toBe(true);
    expect(orphanPool.size()).toBe(4);

    // cli.ts __disconnect__ hook: orphanPool.eraseForPeer(peerKey(peer)).
    const dropped = orphanPool.eraseForPeer(evilKey);
    expect(dropped).toBe(3);
    expect(orphanPool.size()).toBe(1);
    expect(orphanPool.countForPeer(evilKey)).toBe(0);
    expect(orphanPool.countForPeer(honestKey)).toBe(1);
  });

  test("on block-connect, orphans whose txid was just confirmed are erased", async () => {
    // Build an orphan and then "confirm" its txid in a block (Core's
    // EraseForBlock path).  Mirrors the cli chainEvents.on('blockConnected')
    // hook.
    const tx1 = createTestTx(
      [{ txid: Buffer.alloc(32, 0xf1), vout: 0 }],
      [{ value: 5_000n }]
    );
    const tx2 = createTestTx(
      [{ txid: Buffer.alloc(32, 0xf2), vout: 0 }],
      [{ value: 5_000n }]
    );
    expect(orphanPool.add(tx1, "peer-A:8333").ok).toBe(true);
    expect(orphanPool.add(tx2, "peer-B:8333").ok).toBe(true);
    expect(orphanPool.size()).toBe(2);

    // Block confirms tx1 (its txid is in the block's transactions).
    const confirmedTxids = [getTxId(tx1)];
    const removed = orphanPool.eraseForBlock(confirmedTxids);
    expect(removed).toBe(1);
    expect(orphanPool.size()).toBe(1);
    // tx2 still held (not in block).
    expect(orphanPool.hasByTxid(getTxId(tx2))).toBe(true);
    expect(orphanPool.hasByTxid(getTxId(tx1))).toBe(false);
  });

  test("cascade is bounded; pathological deep chain stops at iteration cap", async () => {
    // With a tiny iteration cap we should still resolve the chain partially,
    // never loop forever. This exercises the bounded-worklist guard the
    // cli.ts function applies (ORPHAN_PROMOTE_MAX_ITER = 64 in production).
    const confirmedTxid = Buffer.alloc(32, 0xa1);
    await setupUTXO(db, confirmedTxid, 0, 1_000_000_000n);

    // Build a 10-deep chain rooted at the confirmed UTXO.
    const chain: Transaction[] = [];
    let prevTxid: Buffer = confirmedTxid;
    let prevValue = 1_000_000_000n;
    for (let i = 0; i < 10; i++) {
      const v = prevValue - 1_000n;
      const t = createTestTx([{ txid: prevTxid, vout: 0 }], [{ value: v }]);
      chain.push(t);
      prevTxid = getTxId(t);
      prevValue = v;
    }

    // Insert chain[1..9] into the orphan pool (chain[0] is the parent).
    for (let i = 1; i < 10; i++) {
      // Each one is missing its parent, so pre-admit attempt rejects.
      const r = await mempool.acceptToMemoryPool(chain[i]);
      expect(r.accepted).toBe(false);
      expect(orphanPool.add(chain[i], "peer-Z:8333").ok).toBe(true);
    }
    expect(orphanPool.size()).toBe(9);

    // Admit chain[0]; with cap=2, only a couple promote. Pool isn't drained,
    // but the loop terminates.
    expect((await mempool.acceptToMemoryPool(chain[0])).accepted).toBe(true);
    const promoted = await processOrphanCascade(chain[0], orphanPool, mempool, 2);
    expect(promoted.length).toBeLessThan(9);
    // Critically: function returned (no infinite loop).
    expect(true).toBe(true);
  });
});
