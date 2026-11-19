/**
 * cffix-hotbuns-orphan-children-lookup
 *
 * `OrphanPool.findChildrenOf` used to scan every key of the `byPrevout`
 * reverse index (one key per orphan input) on each call. It runs for every
 * tx admitted or connected, so a full orphanage of large orphans cost
 * ~200,000 string compares per parent.
 *
 * Core (`src/node/txorphanage.cpp`, `TxOrphanage::AddChildrenToWorkSet`)
 * instead does one keyed lookup per output of the parent:
 * `m_outpoint_to_orphan_it.find(COutPoint(tx.GetHash(), i))`.
 *
 * This test instruments the private `byPrevout` map and counts every key it
 * hands out (`get`/`has` calls plus each entry yielded by iteration).
 */

import { describe, expect, test } from "bun:test";
import { OrphanPool } from "../mempool/orphan_pool.js";
import type { Transaction } from "../validation/tx.js";
import { getTxId } from "../validation/tx.js";

function txid(seed: number): Buffer {
  const b = Buffer.alloc(32);
  b.writeUInt32LE(seed, 0);
  b.writeUInt32LE(0xdeadbeef, 28);
  return b;
}

function makeTx(
  prevouts: Array<{ txid: Buffer; vout: number }>,
  outputs = 1
): Transaction {
  return {
    version: 2,
    inputs: prevouts.map((p) => ({
      prevOut: { txid: p.txid, vout: p.vout },
      scriptSig: Buffer.alloc(0),
      sequence: 0xffffffff,
      witness: [],
    })),
    outputs: Array.from({ length: outputs }).map(() => ({
      value: 1_000n,
      scriptPubKey: Buffer.from([0x51]),
    })),
    lockTime: 0,
  };
}

/** Map that counts every key it is asked about or yields. */
class CountingMap<K, V> extends Map<K, V> {
  visits = 0;
  override get(k: K): V | undefined {
    this.visits++;
    return super.get(k);
  }
  override has(k: K): boolean {
    this.visits++;
    return super.has(k);
  }
  override *entries(): MapIterator<[K, V]> {
    for (const e of super.entries()) {
      this.visits++;
      yield e;
    }
  }
  override [Symbol.iterator](): MapIterator<[K, V]> {
    return this.entries();
  }
  override *keys(): MapIterator<K> {
    for (const [k] of this.entries()) yield k;
  }
  override *values(): MapIterator<V> {
    for (const [, v] of this.entries()) yield v;
  }
  override forEach(
    cb: (v: V, k: K, m: Map<K, V>) => void,
    thisArg?: unknown
  ): void {
    for (const [k, v] of this.entries()) cb.call(thisArg, v, k, this);
  }
}

function instrument(pool: OrphanPool): CountingMap<string, Set<string>> {
  const orig = (pool as any).byPrevout as Map<string, Set<string>>;
  const counting = new CountingMap<string, Set<string>>();
  for (const [k, v] of Map.prototype.entries.call(orig)) {
    Map.prototype.set.call(counting, k, v);
  }
  (pool as any).byPrevout = counting;
  return counting;
}

describe("cffix: OrphanPool.findChildrenOf is a per-output keyed lookup", () => {
  test("findChildrenOf visits at most one byPrevout key per parent output", () => {
    const ORPHANS = 100;
    const INPUTS = 2_000;
    const pool = new OrphanPool({ maxGlobal: ORPHANS, maxPerPeer: ORPHANS });

    const parent = makeTx([{ txid: txid(1), vout: 0 }], 2);
    const parentTxid = getTxId(parent);

    // Orphan 0 spends parent:0, orphan 1 spends parent:1, orphan 2 spends
    // both (must be returned once). Every other input is unrelated.
    const expected = new Set<string>();
    let seed = 1_000;
    for (let i = 0; i < ORPHANS; i++) {
      const prevouts: Array<{ txid: Buffer; vout: number }> = [];
      if (i === 0 || i === 2) prevouts.push({ txid: parentTxid, vout: 0 });
      if (i === 1 || i === 2) prevouts.push({ txid: parentTxid, vout: 1 });
      while (prevouts.length < INPUTS) {
        prevouts.push({ txid: txid(seed++), vout: 0 });
      }
      const res = pool.add(makeTx(prevouts), `peer-${i % 4}`);
      if (!res.ok) throw new Error(`add ${i} failed: ${res.reason}`);
      if (i <= 2) expected.add(res.entry.wtxid.toString("hex"));
    }
    expect(pool.size()).toBe(ORPHANS);

    const counting = instrument(pool);
    // parent:0 is shared by orphans 0 and 2, parent:1 by orphans 1 and 2.
    expect(counting.size).toBe(ORPHANS * INPUTS - 2);

    const children = pool.findChildrenOf(parentTxid, parent.outputs.length);

    expect(counting.visits).toBeLessThanOrEqual(parent.outputs.length);
    expect(children.length).toBe(expected.size);
    expect(new Set(children.map((c) => c.wtxid.toString("hex")))).toEqual(
      expected
    );
  });

  test("onParentAdmitted uses the same keyed lookup", () => {
    const pool = new OrphanPool({ maxGlobal: 10, maxPerPeer: 10 });
    const parent = makeTx([{ txid: txid(2), vout: 0 }], 2);
    const parentTxid = getTxId(parent);
    for (let i = 0; i < 10; i++) {
      const prevouts = Array.from({ length: 500 }, (_, j) => ({
        txid: txid(10_000 + i * 1_000 + j),
        vout: 0,
      }));
      if (i === 5) prevouts[7] = { txid: parentTxid, vout: 1 };
      pool.add(makeTx(prevouts), "p");
    }
    const counting = instrument(pool);
    const children = pool.onParentAdmitted(parent);
    expect(counting.visits).toBeLessThanOrEqual(2);
    expect(children.length).toBe(1);
  });
});
