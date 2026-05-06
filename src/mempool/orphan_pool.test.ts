/**
 * Tests for the orphan transaction pool.
 *
 * Reference: bitcoin-core/src/node/txorphanage.cpp + the cross-impl audit
 * doc at CORE-PARITY-AUDIT/_dos-misbehavior-cross-impl-audit-2026-05-06.md.
 */

import { describe, expect, test } from "bun:test";
import {
  MAX_ORPHAN_TRANSACTIONS,
  MAX_ORPHAN_TX_SIZE,
  MAX_PEER_ORPHAN_TX,
  OrphanPool,
} from "./orphan_pool.js";
import type { Transaction } from "../validation/tx.js";
import { getTxId } from "../validation/tx.js";

/** Build a minimal-shape tx that the orphan pool will hash + serialize. */
function makeTx(
  parents: Array<{ txid: Buffer; vout: number }>,
  outputs: number = 1,
  scriptSigSize: number = 0
): Transaction {
  return {
    version: 2,
    inputs: parents.map((p) => ({
      prevOut: { txid: p.txid, vout: p.vout },
      scriptSig: Buffer.alloc(scriptSigSize),
      sequence: 0xffffffff,
      witness: [],
    })),
    outputs: Array.from({ length: outputs }).map(() => ({
      value: 1_000n,
      scriptPubKey: Buffer.from([0x51]), // OP_TRUE
    })),
    lockTime: 0,
  };
}

function freshTxid(seed: number): Buffer {
  const buf = Buffer.alloc(32);
  buf.writeUInt32LE(seed, 0);
  return buf;
}

describe("OrphanPool — constants", () => {
  test("Core-parity defaults", () => {
    expect(MAX_ORPHAN_TRANSACTIONS).toBe(100);
    expect(MAX_ORPHAN_TX_SIZE).toBe(100_000);
    expect(MAX_PEER_ORPHAN_TX).toBeLessThanOrEqual(MAX_ORPHAN_TRANSACTIONS);
  });
});

describe("OrphanPool — basic admit", () => {
  test("admits an orphan and exposes lookup by wtxid + txid", () => {
    const pool = new OrphanPool();
    const tx = makeTx([{ txid: freshTxid(1), vout: 0 }]);

    const result = pool.add(tx, "peer-A");
    expect(result.ok).toBe(true);
    expect(pool.size()).toBe(1);
    if (result.ok) {
      expect(pool.has(result.entry.wtxid)).toBe(true);
      expect(pool.hasByTxid(result.entry.txid)).toBe(true);
      expect(pool.get(result.entry.wtxid)?.fromPeer).toBe("peer-A");
    }
  });

  test("rejects duplicate (same wtxid) on second admit", () => {
    const pool = new OrphanPool();
    const tx = makeTx([{ txid: freshTxid(2), vout: 0 }]);

    expect(pool.add(tx, "peer-A").ok).toBe(true);
    const second = pool.add(tx, "peer-A");
    expect(second.ok).toBe(false);
    if (!second.ok) expect(second.reason).toBe("duplicate");
    expect(pool.size()).toBe(1);
  });

  test("rejects tx with no inputs (coinbase-shaped)", () => {
    const pool = new OrphanPool();
    const tx = makeTx([], 1);
    const result = pool.add(tx, "peer-A");
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("no-inputs");
  });
});

describe("OrphanPool — bounds (DoS protection)", () => {
  test("rejects tx larger than MAX_ORPHAN_TX_SIZE", () => {
    const pool = new OrphanPool({ maxTxSize: 200 });
    // scriptSig of 300 bytes pushes serialized size well past 200.
    const tx = makeTx([{ txid: freshTxid(3), vout: 0 }], 1, 300);
    const result = pool.add(tx, "peer-A");
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("tx-too-large");
    expect(pool.size()).toBe(0);
  });

  test("respects per-peer cap; honest peers unaffected", () => {
    const pool = new OrphanPool({ maxGlobal: 100, maxPerPeer: 3 });

    // Misbehaving peer P uses up its quota.
    for (let i = 0; i < 3; i++) {
      const tx = makeTx([{ txid: freshTxid(100 + i), vout: 0 }]);
      expect(pool.add(tx, "evil").ok).toBe(true);
    }
    expect(pool.countForPeer("evil")).toBe(3);

    // Fourth from same peer is rejected by per-peer cap.
    const overflowTx = makeTx([{ txid: freshTxid(200), vout: 0 }]);
    const overflow = pool.add(overflowTx, "evil");
    expect(overflow.ok).toBe(false);
    if (!overflow.ok) expect(overflow.reason).toBe("peer-cap");

    // Honest peer can still contribute.
    const goodTx = makeTx([{ txid: freshTxid(300), vout: 0 }]);
    expect(pool.add(goodTx, "honest").ok).toBe(true);
    expect(pool.countForPeer("honest")).toBe(1);
  });

  test("enforces global cap with random eviction; size never exceeds maxGlobal", () => {
    // Deterministic "random" -> always pick index 0 (oldest in iteration order).
    const pool = new OrphanPool({
      maxGlobal: 5,
      maxPerPeer: 100,
      random: () => 0,
    });

    for (let i = 0; i < 50; i++) {
      const tx = makeTx([{ txid: freshTxid(1000 + i), vout: 0 }]);
      const r = pool.add(tx, `peer-${i % 7}`);
      expect(r.ok).toBe(true);
      expect(pool.size()).toBeLessThanOrEqual(5);
    }
    expect(pool.size()).toBe(5);
  });
});

describe("OrphanPool — eraseTx / eraseForPeer / eraseForBlock", () => {
  test("eraseTx removes one entry and decrements peer count", () => {
    const pool = new OrphanPool();
    const tx = makeTx([{ txid: freshTxid(4), vout: 0 }]);
    const res = pool.add(tx, "peer-A");
    if (!res.ok) throw new Error("add failed");

    expect(pool.eraseTx(res.entry.wtxid)).toBe(true);
    expect(pool.size()).toBe(0);
    expect(pool.countForPeer("peer-A")).toBe(0);

    // Second erase is a no-op.
    expect(pool.eraseTx(res.entry.wtxid)).toBe(false);
  });

  test("eraseForPeer drops every orphan from that peer only", () => {
    const pool = new OrphanPool();
    for (let i = 0; i < 3; i++) {
      pool.add(makeTx([{ txid: freshTxid(10 + i), vout: 0 }]), "evil");
    }
    pool.add(makeTx([{ txid: freshTxid(20), vout: 0 }]), "honest");

    const removed = pool.eraseForPeer("evil");
    expect(removed).toBe(3);
    expect(pool.size()).toBe(1);
    expect(pool.countForPeer("evil")).toBe(0);
    expect(pool.countForPeer("honest")).toBe(1);
  });

  test("eraseForBlock removes orphans whose txid was just confirmed", () => {
    const pool = new OrphanPool();
    const tx = makeTx([{ txid: freshTxid(30), vout: 0 }]);
    const res = pool.add(tx, "peer-A");
    if (!res.ok) throw new Error("add failed");

    pool.eraseForBlock([res.entry.txid]);
    expect(pool.size()).toBe(0);
  });
});

describe("OrphanPool — parent-arrival lookup", () => {
  test("findByPrevout returns orphans waiting on a specific outpoint", () => {
    const pool = new OrphanPool();
    const parentTxid = freshTxid(50);

    const child1 = makeTx([{ txid: parentTxid, vout: 0 }]);
    const child2 = makeTx([{ txid: parentTxid, vout: 1 }]);
    const unrelated = makeTx([{ txid: freshTxid(51), vout: 0 }]);
    pool.add(child1, "peer-A");
    pool.add(child2, "peer-B");
    pool.add(unrelated, "peer-C");

    const matches = pool.findByPrevout(parentTxid, 0);
    expect(matches.length).toBe(1);
    expect(matches[0].fromPeer).toBe("peer-A");

    const matchesV1 = pool.findByPrevout(parentTxid, 1);
    expect(matchesV1.length).toBe(1);
    expect(matchesV1[0].fromPeer).toBe("peer-B");

    expect(pool.findByPrevout(freshTxid(999), 0).length).toBe(0);
  });

  test("onParentAdmitted returns all orphans referencing any vout of the parent", () => {
    const pool = new OrphanPool();
    const parent = makeTx([{ txid: freshTxid(60), vout: 0 }], 3); // 3 outputs
    const parentTxid = getTxId(parent);

    // Three orphans, one per output.
    pool.add(makeTx([{ txid: parentTxid, vout: 0 }]), "peer-A");
    pool.add(makeTx([{ txid: parentTxid, vout: 1 }]), "peer-A");
    pool.add(makeTx([{ txid: parentTxid, vout: 2 }]), "peer-B");
    // Unrelated orphan.
    pool.add(makeTx([{ txid: freshTxid(61), vout: 0 }]), "peer-C");

    const children = pool.onParentAdmitted(parent);
    expect(children.length).toBe(3);
    expect(new Set(children.map((c) => c.fromPeer))).toEqual(
      new Set(["peer-A", "peer-B"])
    );
  });

  test("eraseTx clears prevout reverse-index entries", () => {
    const pool = new OrphanPool();
    const parentTxid = freshTxid(70);
    const child = makeTx([{ txid: parentTxid, vout: 0 }]);
    const res = pool.add(child, "peer-A");
    if (!res.ok) throw new Error("add failed");

    expect(pool.findByPrevout(parentTxid, 0).length).toBe(1);
    pool.eraseTx(res.entry.wtxid);
    expect(pool.findByPrevout(parentTxid, 0).length).toBe(0);
  });
});

describe("OrphanPool — clear", () => {
  test("clear empties every internal structure", () => {
    const pool = new OrphanPool();
    pool.add(makeTx([{ txid: freshTxid(80), vout: 0 }]), "peer-A");
    pool.add(makeTx([{ txid: freshTxid(81), vout: 0 }]), "peer-B");
    expect(pool.size()).toBe(2);
    pool.clear();
    expect(pool.size()).toBe(0);
    expect(pool.countForPeer("peer-A")).toBe(0);
    expect(pool.countForPeer("peer-B")).toBe(0);
  });
});
