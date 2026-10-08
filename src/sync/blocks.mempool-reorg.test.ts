/**
 * The mempool stays consistent with the chain on invalidateblock, reconsider
 * and a reorg, and tx admission cannot straddle a block connect.
 * (Audit 2026-10-07 T4 / HB-3; fleet brief "mempool consistent with the chain";
 * tools/mempool-reorg-sweep.py scenarios a/c.)
 *
 * Core (validation.cpp / txmempool.cpp):
 *   - DisconnectTip puts the block's txs in the disconnect pool; ConnectTip runs
 *     mempool.removeForBlock (confirmed + conflicts, recursively) for EVERY
 *     connected block and drops them from the disconnect pool;
 *   - MaybeUpdateMempoolForReorg (InvalidateBlock, ActivateBestChainStep)
 *     re-accepts the pool earliest-first with bypass_limits, removeRecursive's
 *     each refused tx (its in-mempool children go too), re-links in-mempool
 *     children (UpdateTransactionsFromBlock), then removeForReorg drops entries
 *     non-final / sequence-locked / spending an immature coinbase at tip+1;
 *   - ATMP runs under cs_main: no block connects between its coin reads and
 *     the insert.
 */
import { describe, test, expect, beforeEach, afterEach } from "bun:test";
import { mkdtemp, rm } from "fs/promises";
import { tmpdir } from "os";
import { join } from "path";
import { createHash } from "crypto";
import { ChainDB, BlockStatus } from "../storage/database.js";
import { REGTEST, compactToBigInt } from "../consensus/params.js";
import {
  Block,
  BlockHeader,
  getBlockHash,
  computeMerkleRoot,
  encodeBip34Height,
} from "../validation/block.js";
import { Transaction, getTxId } from "../validation/tx.js";
import { computeWitnessCommitmentHash } from "../mining/template.js";
import { HeaderSync } from "./headers.js";
import { BlockSync } from "./blocks.js";
import { ChainStateManager } from "../chain/state.js";
import { Mempool } from "../mempool/mempool.js";
import { FeeEstimator } from "../fees/estimator.js";
import { RPCServer, type RPCServerConfig, type RPCServerDeps } from "../rpc/server.js";

const SUBSIDY = 5_000_000_000n;
const WITNESS_SCRIPT = Buffer.from([0x51]); // OP_TRUE
const P2WSH_TRUE = Buffer.concat([
  Buffer.from([0x00, 0x20]),
  createHash("sha256").update(WITNESS_SCRIPT).digest(),
]);

function coinbaseTx(height: number, spends: Transaction[]): Transaction {
  const outputs = [{ value: SUBSIDY, scriptPubKey: P2WSH_TRUE }];
  const witness: Buffer[] = [];
  if (spends.length > 0) {
    const commitment = computeWitnessCommitmentHash(spends);
    outputs.push({
      value: 0n,
      scriptPubKey: Buffer.concat([Buffer.from([0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed]), commitment]),
    });
    witness.push(Buffer.alloc(32, 0));
  }
  return {
    version: 1,
    inputs: [
      {
        prevOut: { txid: Buffer.alloc(32, 0), vout: 0xffffffff },
        scriptSig: Buffer.concat([encodeBip34Height(height), Buffer.from([0xff, 0x07])]),
        sequence: 0xffffffff,
        witness,
      },
    ],
    outputs,
    lockTime: 0,
  };
}

function mine(prev: Buffer, timestamp: number, height: number, spends: Transaction[] = []): Block {
  const cb = coinbaseTx(height, spends);
  const txs = [cb, ...spends];
  const base: BlockHeader = {
    version: 0x20000000,
    prevBlock: prev,
    merkleRoot: computeMerkleRoot(txs.map(getTxId)),
    timestamp,
    bits: REGTEST.powLimitBits,
    nonce: 0,
  };
  const target = compactToBigInt(REGTEST.powLimitBits);
  for (let nonce = 0; nonce < 10_000_000; nonce++) {
    const header = { ...base, nonce };
    if (BigInt("0x" + Buffer.from(getBlockHash(header)).reverse().toString("hex")) <= target) {
      return { header, transactions: txs };
    }
  }
  throw new Error("failed to mine regtest block");
}

function spendTx(prev: { txid: Buffer; vout: number }, value: bigint, tag: number): Transaction {
  return {
    version: 2,
    inputs: [{ prevOut: prev, scriptSig: Buffer.alloc(0), sequence: 0xfffffffd - tag, witness: [WITNESS_SCRIPT] }],
    outputs: [{ value, scriptPubKey: P2WSH_TRUE }],
    lockTime: 0,
  };
}

const display = (h: Buffer) => Buffer.from(h).reverse().toString("hex");

class MockPeerManager {
  getConnectedPeers() {
    return [];
  }
  getPeerCount() {
    return 0;
  }
  broadcast() {}
  updateBestHeight() {}
}


describe("mempool consistent with the chain on invalidate / reorg (T4, HB-3)", () => {
  let dbPath: string;
  let db: ChainDB;
  let headerSync: HeaderSync;
  let chainState: ChainStateManager;
  let blockSync: BlockSync;
  let mempool: Mempool;
  let server: RPCServer;
  let blocks: Block[]; // active chain, blocks[h] = block at height h
  let t: number;

  const SMALL_DBCACHE = 16_000; // every flush evicts -> coins are cold

  function rpc(method: string, params: unknown[]) {
    const methods = (server as any).methods as Map<string, (p: unknown[]) => Promise<unknown>>;
    return methods.get(method)!(params);
  }

  async function extend(n: number, spendsAt: Map<number, Transaction[]> = new Map()) {
    for (let i = 0; i < n; i++) {
      const h = blocks.length;
      t += 600;
      const b = mine(getBlockHash(blocks[h - 1].header), t, h, spendsAt.get(h) ?? []);
      expect(await blockSync.injectBlock(b)).toBeNull();
      blocks.push(b);
    }
  }

  const cb = (h: number) => ({ txid: getTxId(blocks[h].transactions[0]), vout: 0 });
  const out0 = (tx: Transaction) => ({ txid: getTxId(tx), vout: 0 });
  const hex = (tx: Transaction) => getTxId(tx).toString("hex");
  const pool = () => new Set(mempool.getAllTxids().map((x) => Buffer.from(x).toString("hex")));

  async function accept(tx: Transaction) {
    const r = await mempool.addTransaction(tx);
    expect(r).toEqual(expect.objectContaining({ accepted: true }));
  }

  beforeEach(async () => {
    dbPath = await mkdtemp(join(tmpdir(), "hotbuns-mempool-reorg-"));
    db = new ChainDB(dbPath);
    await db.open();
    headerSync = new HeaderSync(db, REGTEST);
    headerSync.initGenesis();
    chainState = new ChainStateManager(db, REGTEST);
    chainState.setHeaderSync(headerSync);
    blockSync = new BlockSync(db, REGTEST, headerSync, undefined, chainState, undefined, SMALL_DBCACHE);
    mempool = new Mempool(blockSync.getUTXOManager(), REGTEST);
    blockSync.setMempool(mempool);
    const config: RPCServerConfig = { port: 0, host: "127.0.0.1", noAuth: true };
    const deps: RPCServerDeps = {
      chainState,
      mempool,
      peerManager: new MockPeerManager() as any,
      feeEstimator: new FeeEstimator(mempool),
      headerSync,
      db,
      params: REGTEST,
      blockSync,
    };
    server = new RPCServer(config, deps);
    const genesis = headerSync.getBestHeader()!;
    t = genesis.header.timestamp;
    blocks = [{ header: genesis.header, transactions: [] }];
  });

  afterEach(async () => {
    await blockSync.stop();
    await db.close();
    await rm(dbPath, { recursive: true, force: true });
  });

  test("invalidateblock: disconnected txs return (child re-linked); immature / dependent entries go", async () => {
    await extend(101);
    const A1 = spendTx(cb(1), SUBSIDY - 10_000n, 1); // block 102
    const IMM = spendTx(cb(4), SUBSIDY - 10_000n, 2); // block 104: cb4 depth exactly 100 there
    await extend(1, new Map([[102, [A1]]]));
    await extend(1);
    await extend(1, new Map([[104, [IMM]]]));
    expect(chainState.getBestBlock().height).toBe(104);

    const M = spendTx(out0(A1), SUBSIDY - 20_000n, 3); // child of block tx A1
    const D = spendTx(out0(IMM), SUBSIDY - 20_000n, 4); // child of block tx IMM
    const N = spendTx(cb(3), SUBSIDY - 10_000n, 5); // cb3: mature at tip 104, not at 101
    for (const tx of [M, D, N]) await accept(tx);

    await rpc("invalidateblock", [display(getBlockHash(blocks[102].header))]);
    expect(chainState.getBestBlock().height).toBe(101);

    // Core: A1 back (spend height 102: cb1 depth 101); M kept and now A1's
    // child; IMM refused (cb4 depth 98 at 102) -> D removed with it; N
    // removed by removeForReorg (cb3 depth 99 at 102). Nothing left that a
    // block at 102 could not include.
    expect(pool()).toEqual(new Set([hex(A1), hex(M)]));
    const m = mempool.getTransaction(getTxId(M))!;
    expect(m.dependsOn.has(hex(A1))).toBe(true);
    expect(mempool.getTransaction(getTxId(A1))!.spentBy.has(hex(M))).toBe(true);
    expect(m.ancestorCount).toBe(2);

    // reconsiderblock: 102..104 reconnect; removeForBlock on EACH of them
    // (102 is below the best header while it connects) empties the pool of
    // A1, and M (child of a confirmed tx) stays.
    await rpc("reconsiderblock", [display(getBlockHash(blocks[102].header))]);
    for (let i = 0; i < 500 && chainState.getBestBlock().height !== 104; i++) {
      await new Promise((r) => setTimeout(r, 10));
    }
    expect(chainState.getBestBlock().height).toBe(104);
    expect(pool()).toEqual(new Set([hex(M)]));
    expect(mempool.getTransaction(getTxId(M))!.dependsOn.size).toBe(0);
  }, 180_000);

  test("reorg: a refused disconnected tx takes its mempool child; txs confirmed on the new branch are not re-added; conflicts go", async () => {
    await extend(102);
    const A1 = spendTx(cb(1), SUBSIDY - 10_000n, 1);
    const P = spendTx(cb(2), SUBSIDY - 10_000n, 2);
    const Q = spendTx(cb(3), SUBSIDY - 10_000n, 3);
    await extend(1, new Map([[103, [A1, P]]]));
    await extend(1, new Map([[104, [Q]]]));
    const M2 = spendTx(out0(A1), SUBSIDY - 20_000n, 4); // child of A1
    const C = spendTx(out0(P), SUBSIDY - 20_000n, 5); // child of P
    const R = spendTx(out0(Q), SUBSIDY - 20_000n, 6); // child of Q
    const M3 = spendTx(cb(4), SUBSIDY - 10_000n, 7);
    for (const tx of [M2, C, R, M3]) await accept(tx);

    // Branch off 102: 103b conflicts A1, 104b re-confirms P, 105b conflicts M3.
    const X = spendTx(cb(1), SUBSIDY - 11_000n, 8);
    const Z = spendTx(cb(4), SUBSIDY - 11_000n, 9);
    t += 7;
    const b103 = mine(getBlockHash(blocks[102].header), t + 600, 103, [X]);
    const b104 = mine(getBlockHash(b103.header), t + 1200, 104, [P]);
    const b105 = mine(getBlockHash(b104.header), t + 1800, 105, [Z]);
    expect(await blockSync.injectBlock(b103)).toBe("duplicate");
    expect(await blockSync.injectBlock(b104)).toBe("duplicate");
    expect(await blockSync.injectBlock(b105)).toBeNull();
    expect(chainState.getBestBlock().hash.equals(getBlockHash(b105.header))).toBe(true);

    // Core: A1 refused (cb1 spent by X) -> removeRecursive takes M2; P was
    // confirmed again in 104b, so it is dropped from the disconnect pool and
    // C keeps its (confirmed) parent; Q re-accepted and R re-linked as its
    // child; M3 conflicts Z (removeForBlock).
    expect(pool()).toEqual(new Set([hex(Q), hex(C), hex(R)]));
    expect(mempool.getTransaction(getTxId(R))!.dependsOn.has(hex(Q))).toBe(true);
    expect(mempool.getTransaction(getTxId(C))!.dependsOn.size).toBe(0);
  }, 180_000);

  test("HB-3: an admission whose coin read straddles a block connect re-runs against the new tip", async () => {
    await extend(102);
    const a = cb(1);
    const b = cb(2);
    const twoInput: Transaction = {
      version: 2,
      inputs: [
        { prevOut: a, scriptSig: Buffer.alloc(0), sequence: 0xfffffffd, witness: [WITNESS_SCRIPT] },
        { prevOut: b, scriptSig: Buffer.alloc(0), sequence: 0xfffffffd, witness: [WITNESS_SCRIPT] },
      ],
      outputs: [{ value: 2n * SUBSIDY - 20_000n, scriptPubKey: P2WSH_TRUE }],
      lockTime: 0,
    };
    const run = async (blockSpendsA: boolean) => {
      // Park the admission on its SECOND input's (cold) coin read.
      let open!: () => void;
      const gate = new Promise<void>((r) => (open = r));
      const realGet = db.getUTXO.bind(db);
      let armed = true;
      let parked = false;
      (db as any).getUTXO = async (txid: Buffer, vout: number) => {
        const v = await realGet(txid, vout);
        if (armed && txid.equals(b.txid) && vout === b.vout) {
          armed = false;
          parked = true;
          await gate;
        }
        return v;
      };
      const admission = mempool.addTransaction(twoInput);
      for (let i = 0; i < 500 && !parked; i++) await new Promise((r) => setTimeout(r, 2));
      expect(parked).toBe(true);
      // A whole block connects while the admission is parked.
      const spend = blockSpendsA
        ? spendTx(a, SUBSIDY - 30_000n, 9)
        : spendTx(cb(3), SUBSIDY - 30_000n, 9);
      await extend(1, new Map([[blocks.length, [spend]]]));
      open();
      const r = await admission;
      (db as any).getUTXO = realGet;
      return r;
    };
    // Block spends input `a` under the parked admission: Core never admits a
    // tx spending a confirmed-spent coin.
    const r1 = await run(true);
    expect(r1.accepted).toBe(false);
    expect(r1.error).toContain("missingorspent");
    expect(pool().has(hex(twoInput))).toBe(false);
  }, 180_000);

  test("HB-3 control: a block that does not touch the inputs lets the straddling admission through", async () => {
    await extend(102);
    const a = cb(1);
    const b = cb(2);
    const twoInput: Transaction = {
      version: 2,
      inputs: [
        { prevOut: a, scriptSig: Buffer.alloc(0), sequence: 0xfffffffd, witness: [WITNESS_SCRIPT] },
        { prevOut: b, scriptSig: Buffer.alloc(0), sequence: 0xfffffffd, witness: [WITNESS_SCRIPT] },
      ],
      outputs: [{ value: 2n * SUBSIDY - 20_000n, scriptPubKey: P2WSH_TRUE }],
      lockTime: 0,
    };
    let open!: () => void;
    const gate = new Promise<void>((r) => (open = r));
    const realGet = db.getUTXO.bind(db);
    let armed = true;
    let parked = false;
    (db as any).getUTXO = async (txid: Buffer, vout: number) => {
      const v = await realGet(txid, vout);
      if (armed && txid.equals(b.txid) && vout === b.vout) {
        armed = false;
        parked = true;
        await gate;
      }
      return v;
    };
    const admission = mempool.addTransaction(twoInput);
    for (let i = 0; i < 500 && !parked; i++) await new Promise((r) => setTimeout(r, 2));
    expect(parked).toBe(true);
    await extend(1, new Map([[blocks.length, [spendTx(cb(3), SUBSIDY - 30_000n, 9)]]]));
    open();
    const r = await admission;
    (db as any).getUTXO = realGet;
    expect(r.accepted).toBe(true);
    expect(pool().has(hex(twoInput))).toBe(true);
  }, 180_000);

  test("coinbase maturity is counted at the spend height tip+1 (Core CheckTxInputs nSpendHeight)", async () => {
    await extend(101);
    // Tip 101: a block at 102 may spend coinbase 2 (102 - 2 = 100), so ATMP
    // accepts it; coinbase 3 (depth 99) is premature.
    const ok = spendTx(cb(2), SUBSIDY - 10_000n, 1);
    const early = spendTx(cb(3), SUBSIDY - 10_000n, 2);
    expect((await mempool.addTransaction(ok)).accepted).toBe(true);
    const r = await mempool.addTransaction(early);
    expect(r.accepted).toBe(false);
    expect(r.error).toContain("bad-txns-premature-spend-of-coinbase");
  }, 120_000);
});
