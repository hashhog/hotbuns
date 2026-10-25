/**
 * submitpackage / testmempoolaccept package semantics, against what Bitcoin
 * Core v31.1 answers for the same packages (tools/core-regtest groups
 * `package`, `seed_submitpackage` and `package_rbf`).
 *
 * Core references:
 *   validation.cpp MemPoolAccept::AcceptPackage — each tx is first tried on
 *     its own; only fee failures (TX_RECONSIDERABLE) and missing inputs are
 *     retried as a package, any other failure ends the package early.
 *   validation.cpp AcceptMultipleTransactionsInternal — PreChecks of every
 *     tx against a view that holds the earlier package txs' outputs, then
 *     the package feerate, package RBF, cluster limits, then scripts.
 *   validation.cpp PolicyScriptChecks — STANDARD_SCRIPT_VERIFY_FLAGS, a
 *     constant: the policy flags do not depend on the tip height.
 *   rpc/mempool.cpp testmempoolaccept / submitpackage — result shape, hashes
 *     in display byte order, effective-feerate = CFeeRate::GetFeePerK().
 *
 * The mempool runs on REGTEST at height 200. The script flags used to come
 * from MAINNET activation heights, so at a regtest height no witness,
 * P2SH or NULLFAIL rule applied and a P2WPKH spend with a bad signature was
 * accepted, alone or in a package.
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
  getWTxId,
  serializeTx,
  sigHashWitnessV0,
  type Transaction,
} from "../validation/tx.js";
import { ecdsaSign, hash160, privateKeyToPublicKey } from "../crypto/primitives.js";

const PRIV = (() => {
  const k = Buffer.alloc(32);
  k[31] = 1;
  return k;
})();
const PUB = privateKeyToPublicKey(PRIV);
const PKH = hash160(PUB);
const P2WPKH = Buffer.concat([Buffer.from([0x00, 0x14]), PKH]);
const SCRIPT_CODE = Buffer.concat([Buffer.from([0x76, 0xa9, 0x14]), PKH, Buffer.from([0x88, 0xac])]);
// OP_1 <pubkey> OP_1 OP_CHECKMULTISIG: 20 legacy sigops, cost 80 (harness bare_multisig_1of1).
const BARE_MULTISIG = Buffer.concat([Buffer.from([0x51, 0x21]), PUB, Buffer.from([0x51, 0xae])]);

const COIN_VALUE = 50_0000_0000n;
const NULLFAIL =
  "mempool-script-verify-flag-failed (Signature must be zero for failed CHECK(MULTI)SIG operation)";

const display = (b: Buffer) => Buffer.from(b).reverse().toString("hex");
const txidOf = (tx: Transaction) => display(getTxId(tx));
const wtxidOf = (tx: Transaction) => display(getWTxId(tx));
const hexOf = (tx: Transaction) => serializeTx(tx, true).toString("hex");
const btc = (sats: bigint | number) => Number(sats) / 1e8;
// CFeeRate(fee, vsize).GetFeePerK() rounds down; ValueFromAmount prints BTC.
const perKvB = (fee: bigint | number, vsize: number) => Math.floor((Number(fee) * 1000) / vsize) / 1e8;

/** A P2WPKH spend of prev:0 (key 1), paying `fee`, signed SIGHASH_ALL. */
function spend(
  prev: Buffer,
  prevValue: bigint,
  fee: bigint,
  extra: { script: Buffer; value: bigint; count: number } | null = null,
  sequence = 0xfffffffd,
): Transaction {
  const outputs = [] as Transaction["outputs"];
  let change = prevValue - fee;
  if (extra) change -= extra.value * BigInt(extra.count);
  outputs.push({ value: change, scriptPubKey: P2WPKH });
  for (let i = 0; i < (extra?.count ?? 0); i++) {
    outputs.push({ value: extra!.value, scriptPubKey: extra!.script });
  }
  const tx: Transaction = {
    version: 2,
    inputs: [{ prevOut: { txid: prev, vout: 0 }, scriptSig: Buffer.alloc(0), sequence, witness: [] }],
    outputs,
    lockTime: 0,
  };
  const sighash = sigHashWitnessV0(tx, 0, SCRIPT_CODE, prevValue, 1);
  tx.inputs[0].witness = [Buffer.concat([ecdsaSign(sighash, PRIV), Buffer.from([0x01])]), PUB];
  return tx;
}

/** Flip the low bit of DER r: still strict DER, so CHECKSIG fails and NULLFAIL fires. */
function corrupt(tx: Transaction): Transaction {
  const sig = Buffer.from(tx.inputs[0].witness[0]);
  sig[4 + sig[3] - 1] ^= 0x01;
  return { ...tx, inputs: [{ ...tx.inputs[0], witness: [sig, tx.inputs[0].witness[1]] }] };
}

async function rpc(port: number, method: string, params: unknown[]): Promise<any> {
  const res = await fetch(`http://127.0.0.1:${port}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });
  return res.json();
}

let portCounter = 19950;

describe("package semantics match Core (regtest)", () => {
  let dir: string;
  let db: ChainDB;
  let mempool: Mempool;
  let server: RPCServer;
  let port: number;
  let coinIndex: number;

  /** A fresh confirmed 50 BTC P2WPKH coin at height 1. */
  async function fund(): Promise<Buffer> {
    const txid = Buffer.alloc(32, 0);
    txid.writeUInt32BE(++coinIndex, 0);
    await db.putUTXO(txid, 0, { height: 1, coinbase: false, amount: COIN_VALUE, scriptPubKey: P2WPKH });
    return txid;
  }

  const inPool = (tx: Transaction) => mempool.hasTransaction(getTxId(tx));

  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "hotbuns-package-cpfp-"));
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

  describe("script checks at a regtest height", () => {
    it("rejects a P2WPKH spend whose signature is invalid (NULLFAIL)", async () => {
      const bad = corrupt(spend(await fund(), COIN_VALUE, 10_000n));
      const res = await mempool.addTransaction(bad, { testAccept: true });
      expect(res.accepted).toBe(false);
      expect(res.error).toStartWith(NULLFAIL);
    });

    it("still accepts the correctly signed spend", async () => {
      const good = spend(await fund(), COIN_VALUE, 10_000n);
      const res = await mempool.addTransaction(good, { testAccept: true });
      expect(res.accepted).toBe(true);
    });

    it("testmempoolaccept of the single bad spend reports Core's reason and details", async () => {
      const prev = await fund();
      const bad = corrupt(spend(prev, COIN_VALUE, 10_000n));
      const res = await rpc(port, "testmempoolaccept", [[hexOf(bad)]]);
      expect(res.result[0]).toEqual({
        txid: txidOf(bad),
        wtxid: wtxidOf(bad),
        allowed: false,
        "reject-reason": NULLFAIL,
        "reject-details": `${NULLFAIL}, input 0 of ${txidOf(bad)} (wtxid ${wtxidOf(bad)}), spending ${display(prev)}:0`,
      });
    });
  });

  describe("testmempoolaccept of a package", () => {
    it("parent-child: the child may spend the package parent", async () => {
      const parent = spend(await fund(), COIN_VALUE, 1_000n);
      const child = spend(getTxId(parent), COIN_VALUE - 1_000n, 1_000n);
      const res = await rpc(port, "testmempoolaccept", [[hexOf(parent), hexOf(child)]]);
      expect(res.result).toHaveLength(2);
      for (const [i, tx] of [parent, child].entries()) {
        const r = res.result[i];
        expect(r.txid).toBe(txidOf(tx));
        expect(r.wtxid).toBe(wtxidOf(tx));
        expect(r.allowed).toBe(true);
        expect(r.fees.base).toBe(btc(1_000));
        expect(r.fees["effective-feerate"]).toBe(perKvB(1_000, r.vsize));
        expect(r.fees["effective-includes"]).toEqual([wtxidOf(tx)]);
      }
      expect(inPool(parent) || inPool(child)).toBe(false);
    });

    it("low-fee parent: individual feerates apply, the rest are left unvalidated", async () => {
      const low = spend(await fund(), COIN_VALUE, 1n);
      const high = spend(getTxId(low), COIN_VALUE - 1n, 20_000n);
      const res = await rpc(port, "testmempoolaccept", [[hexOf(low), hexOf(high)]]);
      expect(res.result[0].allowed).toBe(false);
      expect(res.result[0]["reject-reason"]).toBe("min relay fee not met");
      expect(res.result[1]).toEqual({ txid: txidOf(high), wtxid: wtxidOf(high) });
    });

    it("invalid-sig child: parent allowed, child refused with Core's script error", async () => {
      const parent = spend(await fund(), COIN_VALUE, 10_000n);
      const child = corrupt(spend(getTxId(parent), COIN_VALUE - 10_000n, 10_000n));
      const res = await rpc(port, "testmempoolaccept", [[hexOf(parent), hexOf(child)]]);
      expect(res.result[0].allowed).toBe(true);
      expect(res.result[1]).toEqual({
        txid: txidOf(child),
        wtxid: wtxidOf(child),
        allowed: false,
        "reject-reason": NULLFAIL,
        "reject-details": `${NULLFAIL}, input 0 of ${txidOf(child)} (wtxid ${wtxidOf(child)}), spending ${txidOf(parent)}:0`,
      });
    });

    it("invalid-sig parent: parent refused, child left unvalidated", async () => {
      const goodParent = spend(await fund(), COIN_VALUE, 10_000n);
      const parent = corrupt(goodParent);
      const child = spend(getTxId(parent), COIN_VALUE - 10_000n, 10_000n);
      const res = await rpc(port, "testmempoolaccept", [[hexOf(parent), hexOf(child)]]);
      expect(res.result[0].allowed).toBe(false);
      expect(res.result[0]["reject-reason"]).toBe(NULLFAIL);
      expect(res.result[1]).toEqual({ txid: txidOf(child), wtxid: wtxidOf(child) });
    });
  });

  describe("submitpackage", () => {
    it("CPFP: a parent below min relay fee is carried by its child", async () => {
      const low = spend(await fund(), COIN_VALUE, 1n);
      const high = spend(getTxId(low), COIN_VALUE - 1n, 20_000n);
      const res = (await rpc(port, "submitpackage", [[hexOf(low), hexOf(high)]])).result;
      expect(res.package_msg).toBe("success");
      expect(Object.keys(res["tx-results"]).sort()).toEqual([wtxidOf(low), wtxidOf(high)].sort());
      const lowR = res["tx-results"][wtxidOf(low)];
      const highR = res["tx-results"][wtxidOf(high)];
      expect(lowR.txid).toBe(txidOf(low));
      expect(highR.txid).toBe(txidOf(high));
      const rate = perKvB(20_001, lowR.vsize + highR.vsize);
      expect(lowR.fees).toEqual({ base: btc(1), "effective-feerate": rate, "effective-includes": [wtxidOf(low), wtxidOf(high)] });
      expect(highR.fees).toEqual({ base: btc(20_000), "effective-feerate": rate, "effective-includes": [wtxidOf(low), wtxidOf(high)] });
      expect(res["replaced-transactions"]).toEqual([]);
      expect(inPool(low) && inPool(high)).toBe(true);
    });

    it("missing input: the valid parent enters alone, the child reports Core's token", async () => {
      const base = spend(await fund(), COIN_VALUE, 1_000n);
      const missing: Transaction = {
        version: 2,
        inputs: [
          { prevOut: { txid: getTxId(base), vout: 0 }, scriptSig: Buffer.alloc(0), sequence: 0xffffffff, witness: [] },
          { prevOut: { txid: Buffer.alloc(32, 0x22), vout: 1 }, scriptSig: Buffer.alloc(0), sequence: 0xffffffff, witness: [] },
        ],
        outputs: [{ value: COIN_VALUE - 2_000n, scriptPubKey: P2WPKH }],
        lockTime: 0,
      };
      const res = (await rpc(port, "submitpackage", [[hexOf(base), hexOf(missing)]])).result;
      expect(res.package_msg).toBe("transaction failed");
      const baseR = res["tx-results"][wtxidOf(base)];
      expect(baseR.fees).toEqual({
        base: btc(1_000),
        "effective-feerate": perKvB(1_000, baseR.vsize),
        "effective-includes": [wtxidOf(base)],
      });
      expect(res["tx-results"][wtxidOf(missing)]).toEqual({
        txid: txidOf(missing),
        error: "bad-txns-inputs-missingorspent",
      });
      expect(inPool(base)).toBe(true);
      expect(inPool(missing)).toBe(false);
    });

    it("invalid-sig child: refused, the parent is accepted on its own", async () => {
      const parent = spend(await fund(), COIN_VALUE, 10_000n);
      const child = corrupt(spend(getTxId(parent), COIN_VALUE - 10_000n, 10_000n));
      const res = (await rpc(port, "submitpackage", [[hexOf(parent), hexOf(child)]])).result;
      expect(res.package_msg).toBe("transaction failed");
      const parentR = res["tx-results"][wtxidOf(parent)];
      expect(parentR.fees["effective-includes"]).toEqual([wtxidOf(parent)]);
      expect(res["tx-results"][wtxidOf(child)]).toEqual({
        txid: txidOf(child),
        error: `${NULLFAIL}, input 0 of ${txidOf(child)} (wtxid ${wtxidOf(child)}), spending ${txidOf(parent)}:0`,
      });
      expect(inPool(parent)).toBe(true);
      expect(inPool(child)).toBe(false);
    });

    it("invalid-sig parent: nothing enters the mempool", async () => {
      const prev = await fund();
      const parent = corrupt(spend(prev, COIN_VALUE, 10_000n));
      const child = spend(getTxId(parent), COIN_VALUE - 10_000n, 10_000n);
      const res = (await rpc(port, "submitpackage", [[hexOf(parent), hexOf(child)]])).result;
      expect(res.package_msg).toBe("transaction failed");
      expect(res["tx-results"][wtxidOf(parent)]).toEqual({
        txid: txidOf(parent),
        error: `${NULLFAIL}, input 0 of ${txidOf(parent)} (wtxid ${wtxidOf(parent)}), spending ${display(prev)}:0`,
      });
      expect(res["tx-results"][wtxidOf(child)]).toEqual({
        txid: txidOf(child),
        error: "bad-txns-inputs-missingorspent",
      });
      expect(inPool(parent) || inPool(child)).toBe(false);
    });

    it("a package member already in the mempool reports vsize and base fee only", async () => {
      const parent = spend(await fund(), COIN_VALUE, 10_000n);
      expect((await mempool.addTransaction(parent)).accepted).toBe(true);
      const child = spend(getTxId(parent), COIN_VALUE - 10_000n, 10_000n);
      const res = (await rpc(port, "submitpackage", [[hexOf(parent), hexOf(child)]])).result;
      expect(res.package_msg).toBe("success");
      const parentR = res["tx-results"][wtxidOf(parent)];
      expect(parentR).toEqual({ txid: txidOf(parent), vsize: parentR.vsize, fees: { base: btc(10_000) } });
      expect(res["tx-results"][wtxidOf(child)].fees["effective-includes"]).toEqual([wtxidOf(child)]);
    });
  });

  describe("package RBF (1 parent, 1 child)", () => {
    // O and its child D are in the mempool; P double-spends O's input and
    // pays less than O + D, so P fails RBF alone and is retried with C.
    // O is wide and cheap (600 outputs, like the harness), so the package
    // improves the feerate diagram and the cluster limit decides.
    async function conflicts(): Promise<{ coin: Buffer; o: Transaction; d: Transaction }> {
      const coin = await fund();
      const o = spend(coin, COIN_VALUE, 20_000n, { script: P2WPKH, value: 1_000n, count: 600 });
      const d = spend(getTxId(o), o.outputs[0].value, 1_000n);
      expect((await mempool.addTransaction(o)).accepted).toBe(true);
      expect((await mempool.addTransaction(d)).accepted).toBe(true);
      return { coin, o, d };
    }

    function replacement(coin: Buffer, parentOutputs: number, childOutputs: number) {
      const extraP = parentOutputs ? { script: BARE_MULTISIG, value: 1_000n, count: parentOutputs } : null;
      const p = spend(coin, COIN_VALUE, 6_000n, extraP);
      const pChange = p.outputs[0].value;
      const extraC = childOutputs ? { script: BARE_MULTISIG, value: 1_000n, count: childOutputs } : null;
      const c = spend(getTxId(p), pChange, 200_000n, extraC);
      return { p, c };
    }

    it("testmempoolaccept of a replacement leaves the original in the mempool", async () => {
      // The dry-run return used to come after the RBF eviction.
      const coin = await fund();
      const original = spend(coin, COIN_VALUE, 1_000n);
      expect((await mempool.addTransaction(original)).accepted).toBe(true);
      const replacementTx = spend(coin, COIN_VALUE, 50_000n);
      const res = await rpc(port, "testmempoolaccept", [[hexOf(replacementTx)]]);
      expect(res.result[0].allowed).toBe(true);
      expect(inPool(original)).toBe(true);
      expect(inPool(replacementTx)).toBe(false);
    });

    it("replaces the conflicts when the package pays for them", async () => {
      const { coin, o, d } = await conflicts();
      const { p, c } = replacement(coin, 0, 0);
      const res = (await rpc(port, "submitpackage", [[hexOf(p), hexOf(c)]])).result;
      expect(res.package_msg).toBe("success");
      expect([...res["replaced-transactions"]].sort()).toEqual([txidOf(o), txidOf(d)].sort());
      expect(inPool(p) && inPool(c)).toBe(true);
      expect(inPool(o) || inPool(d)).toBe(false);
    });

    it("at the cluster limit (403,200 adjusted weight) it is accepted", async () => {
      const { coin, o } = await conflicts();
      const { p, c } = replacement(coin, 126, 126);
      const res = (await rpc(port, "submitpackage", [[hexOf(p), hexOf(c)]])).result;
      expect(res.package_msg).toBe("success");
      expect(inPool(p) && inPool(c)).toBe(true);
      expect(inPool(o)).toBe(false);
    });

    it("over the cluster limit (404,800) it is too-large-cluster and the conflicts stay", async () => {
      const { coin, o, d } = await conflicts();
      const { p, c } = replacement(coin, 127, 126);
      const res = (await rpc(port, "submitpackage", [[hexOf(p), hexOf(c)]])).result;
      expect(res.package_msg).toBe("too-large-cluster");
      expect(res["tx-results"][wtxidOf(p)]).toEqual({
        txid: txidOf(p),
        error: `insufficient fee, rejecting replacement ${txidOf(p)}, less fees than conflicting txs; 0.00006 < 0.00021`,
      });
      expect(res["tx-results"][wtxidOf(c)]).toEqual({
        txid: txidOf(c),
        error: "bad-txns-inputs-missingorspent",
      });
      expect(inPool(o) && inPool(d)).toBe(true);
      expect(inPool(p) || inPool(c)).toBe(false);
    });
  });
});
