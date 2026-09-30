/**
 * The cluster-limit / RBF-diagram gates enumerate a cluster with
 * UnionFind.membersOfRoot instead of scanning the whole mempool. These tests
 * pin that the enumeration is exactly the set the scan produced, and that the
 * cluster-count gate still fires at the same boundary.
 */
import { describe, test, expect, beforeEach, afterEach } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ChainDB } from "../storage/database.js";
import { UTXOManager } from "../chain/utxo.js";
import { REGTEST } from "../consensus/params.js";
import { Mempool, UnionFind } from "./mempool.js";
import type { Transaction } from "../validation/tx.js";
import { getTxId } from "../validation/tx.js";

describe("UnionFind.membersOfRoot", () => {
  test("equals { id : find(id) === root } under random unions", () => {
    let seed = 12345;
    const rnd = (n: number) => {
      seed = (seed * 1103515245 + 12345) & 0x7fffffff;
      return seed % n;
    };
    for (let round = 0; round < 20; round++) {
      const uf = new UnionFind();
      const ids = Array.from({ length: 300 }, (_, i) => `t${round}-${i}`);
      for (const id of ids.slice(0, 250)) uf.makeSet(id);
      for (let k = 0; k < 200; k++) {
        const a = ids[rnd(ids.length)];
        const b = ids[rnd(ids.length)];
        // Also exercises find()'s lazy makeSet of ids 250..299.
        if (rnd(3) === 0) uf.find(a);
        else uf.union(a, b);
      }
      const byRoot = new Map<string, Set<string>>();
      for (const id of ids) {
        const r = uf.find(id);
        if (!byRoot.has(r)) byRoot.set(r, new Set());
        byRoot.get(r)!.add(id);
      }
      for (const [root, expected] of byRoot) {
        const got = uf.membersOfRoot(root);
        expect(new Set(got)).toEqual(expected);
        expect(got.length).toBe(expected.size); // no duplicates
      }
      uf.clear();
      expect(uf.membersOfRoot(ids[0])).toEqual([ids[0]]);
    }
  });
});

describe("cluster-count gate after the member-walk change", () => {
  const P2A = Buffer.from([0x51, 0x02, 0x4e, 0x73]);
  let dir: string;
  let db: ChainDB;
  let mempool: Mempool;

  const mk = (prev: Buffer, vout: number, outs: bigint[]): Transaction => ({
    version: 2,
    inputs: [{ prevOut: { txid: prev, vout }, scriptSig: Buffer.alloc(0), sequence: 0xffffffff, witness: [] }],
    outputs: [...outs.map((value) => ({ value, scriptPubKey: P2A })), { value: 0n, scriptPubKey: Buffer.from([0x6a]) }],
    lockTime: 0,
  });

  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "cluster-walk-"));
    db = new ChainDB(dir);
    await db.open();
    mempool = new Mempool(new UTXOManager(db), REGTEST, 50_000_000);
    mempool.setTipHeight(200);
  });
  afterEach(async () => {
    await db.close();
    await rm(dir, { recursive: true, force: true });
  });

  test("64 accepted, 65th too-large-cluster; unrelated txs unaffected", async () => {
    const fund = Buffer.alloc(32, 0x11);
    await db.putUTXO(fund, 0, { height: 1, coinbase: false, amount: 10_000_000n, scriptPubKey: P2A });
    // Unrelated background population (the scan used to walk all of these).
    for (let i = 0; i < 50; i++) {
      const f = Buffer.alloc(32, 0);
      f.writeUInt32LE(i + 1, 0);
      f[31] = 0x77;
      await db.putUTXO(f, 0, { height: 1, coinbase: false, amount: 100_000n, scriptPubKey: P2A });
      expect((await mempool.addTransaction(mk(f, 0, [99_000n]))).accepted).toBe(true);
    }
    // Parent with 70 outputs, then children: parent + 63 children = 64.
    const parent = mk(fund, 0, new Array(70).fill(100_000n));
    expect((await mempool.addTransaction(parent)).accepted).toBe(true);
    const pid = getTxId(parent);
    for (let v = 0; v < 63; v++) {
      const r = await mempool.addTransaction(mk(pid, v, [99_000n]));
      expect(r.accepted).toBe(true);
    }
    const r65 = await mempool.addTransaction(mk(pid, 63, [99_000n]));
    expect(r65.accepted).toBe(false);
    expect(r65.error).toContain("too-large-cluster");
    expect(mempool.getSize()).toBe(50 + 64);
  });
});
