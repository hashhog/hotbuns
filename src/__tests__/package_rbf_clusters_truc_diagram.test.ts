/**
 * Replacement and package-TRUC rules that hotbuns#28's review found off
 * Core v31.1 (the core-regtest harness has no rows for them):
 *
 *   1. Rule 5 counts the distinct CLUSTERS of the direct conflicts
 *      (policy/rbf.cpp GetEntriesForConflicts / GetUniqueClusterCount), not
 *      conflicts + descendants; descendants are evicted with no second cap.
 *   2. A feerate-diagram failure is TX_RECONSIDERABLE "replacement-failed"
 *      (validation.cpp ReplacementChecks), so AcceptPackage retries the tx
 *      with its child.
 *   3. PackageTRUCChecks (validation.cpp:1480) runs on the whole package,
 *      counting an in-package parent once, before anything is evicted or
 *      inserted.
 *   4. The feerate diagram is sized by sigop-adjusted weight
 *      (txmempool.cpp ChangeSet::StageAddition), not ceilinged vsize.
 */

import { describe, it, expect, beforeEach, afterEach } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ChainDB } from "../storage/database.js";
import { UTXOManager } from "../chain/utxo.js";
import { REGTEST } from "../consensus/params.js";
import { Mempool } from "../mempool/mempool.js";
import { RPCServer, type RPCServerConfig, type RPCServerDeps } from "../rpc/server.js";
import {
  getTxId,
  getTxWeight,
  getWTxId,
  serializeTx,
  sigHashWitnessV0,
  type Transaction,
} from "../validation/tx.js";
import { ecdsaSign, hash160, privateKeyToPublicKey, sha256Hash } from "../crypto/primitives.js";

const PRIV = (() => {
  const k = Buffer.alloc(32);
  k[31] = 1;
  return k;
})();
const PUB = privateKeyToPublicKey(PRIV);
const PKH = hash160(PUB);
const P2WPKH = Buffer.concat([Buffer.from([0x00, 0x14]), PKH]);
const SCRIPT_CODE = Buffer.concat([Buffer.from([0x76, 0xa9, 0x14]), PKH, Buffer.from([0x88, 0xac])]);
// OP_DROP OP_1: spent with witness [<pad>, script], so the pad length sets
// the weight one unit at a time. No sigops: adjusted weight == weight.
const DROP_TRUE = Buffer.from([0x75, 0x51]);
const P2WSH_DROP_TRUE = Buffer.concat([Buffer.from([0x00, 0x20]), sha256Hash(DROP_TRUE)]);

const COIN_VALUE = 50_0000_0000n;
const display = (b: Buffer) => Buffer.from(b).reverse().toString("hex");
const txidOf = (tx: Transaction) => display(getTxId(tx));
const wtxidOf = (tx: Transaction) => display(getWTxId(tx));
const hexOf = (tx: Transaction) => serializeTx(tx, true).toString("hex");

type Coin = { txid: Buffer; vout: number; value: bigint };

/** P2WPKH spend of `coins` (key 1) to one change output plus `extra` P2WPKH outputs of 1,000 sat. */
function spend(coins: Coin[], fee: bigint, opts: { version?: number; extra?: number } = {}): Transaction {
  const extra = opts.extra ?? 0;
  const total = coins.reduce((s, c) => s + c.value, 0n);
  const outputs: Transaction["outputs"] = [{ value: total - fee - 1_000n * BigInt(extra), scriptPubKey: P2WPKH }];
  for (let i = 0; i < extra; i++) outputs.push({ value: 1_000n, scriptPubKey: P2WPKH });
  const tx: Transaction = {
    version: opts.version ?? 2,
    inputs: coins.map((c) => ({
      prevOut: { txid: c.txid, vout: c.vout },
      scriptSig: Buffer.alloc(0),
      sequence: 0xfffffffd,
      witness: [],
    })),
    outputs,
    lockTime: 0,
  };
  coins.forEach((c, i) => {
    const sighash = sigHashWitnessV0(tx, i, SCRIPT_CODE, c.value, 1);
    tx.inputs[i].witness = [Buffer.concat([ecdsaSign(sighash, PRIV), Buffer.from([0x01])]), PUB];
  });
  return tx;
}

/** Output 0 of `tx` as a coin. */
const out0 = (tx: Transaction): Coin => ({ txid: getTxId(tx), vout: 0, value: tx.outputs[0].value });

/** Spend of a P2WSH(OP_DROP OP_1) coin with a `pad`-byte witness item. */
function wshSpend(coin: Coin, fee: bigint, pad: number): Transaction {
  return {
    version: 2,
    inputs: [
      {
        prevOut: { txid: coin.txid, vout: coin.vout },
        scriptSig: Buffer.alloc(0),
        sequence: 0xfffffffd,
        witness: [Buffer.alloc(pad, 0x01), DROP_TRUE],
      },
    ],
    outputs: [{ value: coin.value - fee, scriptPubKey: P2WPKH }],
    lockTime: 0,
  };
}

async function rpc(port: number, method: string, params: unknown[]): Promise<any> {
  const res = await fetch(`http://127.0.0.1:${port}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });
  return res.json();
}

let portCounter = 19990;

describe("package RBF / TRUC / diagram follow Core (hotbuns#28 review)", () => {
  let dir: string;
  let db: ChainDB;
  let mempool: Mempool;
  let server: RPCServer;
  let port: number;
  let coinIndex: number;

  /** A fresh confirmed 50 BTC coin at height 1. */
  async function fund(scriptPubKey: Buffer = P2WPKH): Promise<Coin> {
    const txid = Buffer.alloc(32, 0);
    txid.writeUInt32BE(++coinIndex, 0);
    await db.putUTXO(txid, 0, { height: 1, coinbase: false, amount: COIN_VALUE, scriptPubKey });
    return { txid, vout: 0, value: COIN_VALUE };
  }

  async function admit(tx: Transaction): Promise<void> {
    const r = await mempool.addTransaction(tx);
    if (!r.accepted) throw new Error(`setup tx refused: ${r.error}`);
  }

  /**
   * `n` coins, each spent in the mempool by a chain of `length` txs paying
   * 1,000 sat each: `n` separate clusters, `n * length` transactions.
   */
  async function clusters(n: number, length: number): Promise<{ coins: Coin[]; txs: Transaction[] }> {
    const coins: Coin[] = [];
    const txs: Transaction[] = [];
    for (let i = 0; i < n; i++) {
      const coin = await fund();
      coins.push(coin);
      let prev = coin;
      for (let j = 0; j < length; j++) {
        const tx = spend([prev], 1_000n);
        await admit(tx);
        txs.push(tx);
        prev = out0(tx);
      }
    }
    return { coins, txs };
  }

  const inPool = (tx: Transaction) => mempool.hasTransaction(getTxId(tx));

  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "hotbuns-package-rbf-rework-"));
    db = new ChainDB(dir);
    await db.open();
    mempool = new Mempool(new UTXOManager(db), REGTEST, 300_000_000);
    mempool.setTipHeight(200);
    coinIndex = 0;
    port = portCounter++;
    const config: RPCServerConfig = { port, host: "127.0.0.1", noAuth: true };
    const deps: RPCServerDeps = {
      chainState: { getBestBlock: () => ({ hash: Buffer.alloc(32, 0), height: 200, chainWork: 1n }) } as any,
      mempool,
      peerManager: { getConnectedPeers: () => [], broadcast() {}, listBanned: () => [] } as any,
      feeEstimator: { estimateSmartFee: (t: number) => ({ feeRate: 10, blocks: t }) } as any,
      headerSync: { getBestHeader: () => null, getHeader: () => null } as any,
      db: db as any,
      params: REGTEST,
    };
    server = new RPCServer(config, deps);
    server.start();
  });

  afterEach(async () => {
    server.stop();
    await db.close();
    await rm(dir, { recursive: true, force: true });
  });

  describe("1. rule 5 counts conflicting clusters", () => {
    it("a replacement of 100 clusters (200 txs with descendants) is accepted", async () => {
      const { coins, txs } = await clusters(100, 2);
      const r = spend(coins, 1_000_000n);
      const res = await mempool.addTransaction(r);
      expect(res.error).toBeUndefined();
      expect(res.accepted).toBe(true);
      expect(txs.some(inPool)).toBe(false);
      expect(mempool.getSize()).toBe(1);
    });

    it("101 conflicting clusters: too many potential replacements, mempool unchanged", async () => {
      const { coins, txs } = await clusters(101, 1);
      const r = spend(coins, 1_000_000n);
      const res = await mempool.addTransaction(r);
      expect(res.accepted).toBe(false);
      // Core TxValidationState: reason and debug message, joined by ", ".
      expect(res.rejectReason).toBe("too many potential replacements");
      expect(res.rejectDetails).toBe(
        `rejecting replacement ${txidOf(r)}; too many conflicting clusters (101 > 100)`,
      );
      expect(res.error).toBe(
        `too many potential replacements, rejecting replacement ${txidOf(r)}; too many conflicting clusters (101 > 100)`,
      );
      expect(txs.every(inPool)).toBe(true);
      expect(inPool(r)).toBe(false);
    });

    it("package: a parent evicting 105 txs from 5 clusters is retried and accepted", async () => {
      const { coins, txs } = await clusters(5, 21);
      // P alone pays less than the 105,000 sat it evicts: insufficient fee.
      const p = spend(coins, 6_000n);
      const c = spend([out0(p)], 500_000n);
      const res = await mempool.submitPackage([p, c]);
      expect(res.message).toBe("success");
      expect(inPool(p) && inPool(c)).toBe(true);
      expect(txs.some(inPool)).toBe(false);
      expect(res.replacedTxids).toHaveLength(105);
    });

    it("package: 101 clusters across parent and child is too many, mempool unchanged", async () => {
      const { coins, txs } = await clusters(101, 1);
      const p = spend(coins.slice(0, 60), 1_000n);
      const c = spend([out0(p), ...coins.slice(60)], 2_000_000n);
      const res = await mempool.submitPackage([p, c]);
      expect(res.message).toBe(
        `package RBF failed: too many potential replacements, rejecting replacement ${txidOf(c)}; too many conflicting clusters (101 > 100)`,
      );
      expect(txs.every(inPool)).toBe(true);
      expect(inPool(p) || inPool(c)).toBe(false);
    });

    it("a parent alone over 101 clusters ends the package early, mempool unchanged", async () => {
      const { coins, txs } = await clusters(101, 1);
      const p = spend(coins, 1_000n);
      const c = spend([out0(p)], 2_000_000n);
      const res = await mempool.submitPackage([p, c]);
      expect(res.message).toBe("transaction failed");
      expect(res.txResults.get(getWTxId(p).toString("hex"))!.error).toStartWith("too many potential replacements");
      expect(txs.every(inPool)).toBe(true);
      expect(inPool(p) || inPool(c)).toBe(false);
    });
  });

  describe("2. a feerate-diagram failure is retried with the child", () => {
    // X is small and pays 10,000 sat (~91 sat/vB). P double-spends X's coin,
    // pays X's fee plus the incremental fee, but is ~7x larger: alone it
    // loses the diagram. The child lifts the package chunk above X.
    async function setup(childFee: bigint) {
      const coin = await fund();
      const x = spend([coin], 10_000n);
      await admit(x);
      const p = spend([coin], 10_200n, { extra: 20 });
      const c = spend([out0(p)], childFee);
      return { x, p, c };
    }

    it("P alone fails on the diagram (the precondition)", async () => {
      const { p } = await setup(100_000n);
      const res = await mempool.addTransaction(p, { testAccept: true });
      expect(res.accepted).toBe(false);
      // Core ReplacementChecks: TX_RECONSIDERABLE "replacement-failed".
      expect(res.rejectReason).toBe("replacement-failed");
      expect(res.error).toBe("replacement-failed, insufficient feerate: does not improve feerate diagram");
    });

    it("the package whose chunk improves the diagram is accepted", async () => {
      const { x, p, c } = await setup(100_000n);
      const res = await mempool.submitPackage([p, c]);
      expect(res.message).toBe("success");
      expect(inPool(p) && inPool(c)).toBe(true);
      expect(inPool(x)).toBe(false);
    });

    it("a package that still loses the diagram is refused and X stays", async () => {
      const { x, p, c } = await setup(5_000n);
      const res = await mempool.submitPackage([p, c]);
      expect(res.message).toBe("package RBF failed: insufficient feerate: does not improve feerate diagram");
      expect(inPool(x)).toBe(true);
      expect(inPool(p) || inPool(c)).toBe(false);
    });
  });

  describe("3. PackageTRUCChecks before any eviction", () => {
    // X is in the mempool; the v3 parent P double-spends it and pays less,
    // so P alone fails RBF and is retried with its child.
    async function setup(child: { version: number; extra: number }) {
      const coin = await fund();
      const x = spend([coin], 1_000n);
      await admit(x);
      const p = spend([coin], 500n, { version: 3 });
      const c = spend([out0(p)], 300_000n, child);
      return { x, p, c };
    }

    it("a v3 child over 1000 vB is a TRUC-violation and X stays", async () => {
      const { x, p, c } = await setup({ version: 3, extra: 30 });
      const vsize = Math.ceil(getTxWeight(c) / 4);
      expect(vsize).toBeGreaterThan(1000);
      const res = await mempool.submitPackage([p, c]);
      expect(res.message).toBe(
        `TRUC-violation, version=3 child tx ${txidOf(c)} (wtxid=${wtxidOf(c)}) is too big: ${vsize} > 1000 virtual bytes`,
      );
      expect(inPool(x)).toBe(true);
      expect(inPool(p) || inPool(c)).toBe(false);
    });

    it("a non-v3 child of a v3 parent is a TRUC-violation and X stays", async () => {
      const { x, p, c } = await setup({ version: 2, extra: 0 });
      const res = await mempool.submitPackage([p, c]);
      expect(res.message).toBe(
        `TRUC-violation, non-version=3 tx ${txidOf(c)} (wtxid=${wtxidOf(c)}) cannot spend from version=3 tx ${txidOf(p)} (wtxid=${wtxidOf(p)})`,
      );
      expect(inPool(x)).toBe(true);
      expect(inPool(p) || inPool(c)).toBe(false);
    });

    it("a valid v3 1-parent-1-child (child within 1000 vB) replaces X", async () => {
      const { x, p, c } = await setup({ version: 3, extra: 0 });
      const res = await mempool.submitPackage([p, c]);
      expect(res.message).toBe("success");
      expect(inPool(p) && inPool(c)).toBe(true);
      expect(inPool(x)).toBe(false);
    });

    it("testmempoolaccept reports Core's package-error for an oversize v3 child", async () => {
      const p = spend([await fund()], 1_000n, { version: 3 });
      const c = spend([out0(p)], 10_000n, { version: 3, extra: 30 });
      const vsize = Math.ceil(getTxWeight(c) / 4);
      const res = (await rpc(port, "testmempoolaccept", [[hexOf(p), hexOf(c)]])).result;
      const error = `TRUC-violation, version=3 child tx ${txidOf(c)} (wtxid=${wtxidOf(c)}) is too big: ${vsize} > 1000 virtual bytes`;
      expect(res).toEqual([
        { txid: txidOf(p), wtxid: wtxidOf(p), "package-error": error },
        { txid: txidOf(c), wtxid: wtxidOf(c), "package-error": error },
      ]);
    });
  });

  describe("4. the feerate diagram is sized by adjusted weight", () => {
    // O weighs 4k (vsize k); R weighs 4k+1 (vsize k+1) and pays a fee that
    // beats O per weight unit but not per ceilinged vbyte.
    async function setup() {
      const coin = await fund(P2WSH_DROP_TRUE);
      let pad = 1;
      while (getTxWeight(wshSpend(coin, 0n, pad)) % 4 !== 0) pad++;
      const feeO = 10_000n;
      const o = wshSpend(coin, feeO, pad);
      const w = getTxWeight(o);
      const k = w / 4;
      // Largest fee that still does not beat O per ceilinged vbyte.
      const feeR = (feeO * BigInt(k + 1)) / BigInt(k);
      const r = wshSpend(coin, feeR, pad + 1);
      // The instrument: R is one weight unit heavier, a strict improvement
      // per weight unit and none per vbyte.
      expect(getTxWeight(r)).toBe(w + 1);
      expect(feeR * BigInt(w) > feeO * BigInt(w + 1)).toBe(true);
      expect(feeR * BigInt(k) <= feeO * BigInt(k + 1)).toBe(true);
      await admit(o);
      return { coin, o, r, feeR, pad };
    }

    it("a replacement that improves the diagram by weight is accepted", async () => {
      const { o, r } = await setup();
      const res = await mempool.addTransaction(r);
      expect(res.error).toBeUndefined();
      expect(res.accepted).toBe(true);
      expect(inPool(o)).toBe(false);
    });

    it("a heavier replacement at the same fee still loses the diagram", async () => {
      const { coin, o, feeR, pad } = await setup();
      const heavy = wshSpend(coin, feeR, pad + 40);
      const res = await mempool.addTransaction(heavy);
      expect(res.accepted).toBe(false);
      // Core ReplacementChecks: TX_RECONSIDERABLE "replacement-failed".
      expect(res.rejectReason).toBe("replacement-failed");
      expect(res.error).toBe("replacement-failed, insufficient feerate: does not improve feerate diagram");
      expect(inPool(o)).toBe(true);
    });
  });
});
