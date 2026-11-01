/**
 * invalidateblock puts the disconnected transactions back in the mempool and
 * leaves the mempool consistent with the new tip
 * (core-regtest warden_e / seed_warden_e: 324 open consensus rows).
 *
 * Core (validation.cpp Chainstate::InvalidateBlock ->
 * MaybeUpdateMempoolForReorg; txmempool.cpp UpdateTransactionsFromBlock;
 * txgraph.cpp TxGraphImpl::Trim):
 *   - the disconnected txs are re-accepted earliest-first with bypass_limits;
 *     a refused one is removeRecursive'd, so its in-mempool spenders go too;
 *   - in-mempool children of a re-accepted tx are linked to it, and a cluster
 *     the link makes larger than 64 txs / 101 kvB is trimmed: highest chunk
 *     feerate first, the tx that would break the limit (and its descendants)
 *     is removed;
 *   - removeForReorg drops entries that spend an immature coinbase at tip+1.
 *
 * hotbuns used to removeTransaction the invalidated block's own txs (a no-op:
 * they were confirmed, so not in the pool). The disconnected parent stayed
 * out, its 64 in-pool children stayed in, spending outputs that exist
 * nowhere, and getblocktemplate offered them: a template no node can mine.
 */
import { describe, test, expect, beforeEach, afterEach } from "bun:test";
import { mkdtemp, rm } from "fs/promises";
import { tmpdir } from "os";
import { join } from "path";
import { createHash } from "crypto";
import { ChainDB } from "../storage/database.js";
import { REGTEST, compactToBigInt } from "../consensus/params.js";
import {
  Block,
  BlockHeader,
  getBlockHash,
  computeMerkleRoot,
  encodeBip34Height,
} from "../validation/block.js";
import { Transaction, getTxId, getWTxId } from "../validation/tx.js";
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

/** One input spending `prev` (P2WSH OP_TRUE), outputs `values` to P2WSH OP_TRUE. */
function spendTx(prev: { txid: Buffer; vout: number }, values: bigint[], tag: number, version = 2): Transaction {
  return {
    version,
    inputs: [{ prevOut: prev, scriptSig: Buffer.alloc(0), sequence: 0xfffffffd - tag, witness: [WITNESS_SCRIPT] }],
    outputs: values.map((value) => ({ value, scriptPubKey: P2WSH_TRUE })),
    lockTime: 0,
  };
}

describe("invalidateblock re-adds the disconnected txs (MaybeUpdateMempoolForReorg)", () => {
  let dbPath: string;
  let db: ChainDB;
  let headerSync: HeaderSync;
  let chainState: ChainStateManager;
  let blockSync: BlockSync;
  let mempool: Mempool;
  let server: RPCServer;
  let blocks: Block[]; // active chain, blocks[h] = block at height h
  let t: number;

  function rpc(method: string, params: unknown[]) {
    const methods = (server as any).methods as Map<string, (p: unknown[]) => Promise<unknown>>;
    return methods.get(method)!(params);
  }
  const display = (h: Buffer) => Buffer.from(h).reverse().toString("hex");

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
  const out = (tx: Transaction, vout = 0) => ({ txid: getTxId(tx), vout });
  const hex = (tx: Transaction) => getTxId(tx).toString("hex");
  const pool = () => new Set(mempool.getAllTxids().map((x) => Buffer.from(x).toString("hex")));

  async function accept(tx: Transaction) {
    const r = await mempool.addTransaction(tx);
    expect(r).toEqual(expect.objectContaining({ accepted: true }));
  }

  /** Every input of every pool entry is a coin at the tip or another pool entry. */
  async function expectPoolConsistent() {
    const ids = pool();
    const utxo = blockSync.getUTXOManager();
    for (const id of ids) {
      const entry = mempool.getTransaction(Buffer.from(id, "hex"))!;
      for (const input of entry.tx.inputs) {
        const parent = input.prevOut.txid.toString("hex");
        if (ids.has(parent)) continue;
        const coin = await utxo.getUTXOAsync(input.prevOut);
        expect({ tx: id, input: `${parent}:${input.prevOut.vout}`, coin: coin !== null }).toEqual({
          tx: id,
          input: `${parent}:${input.prevOut.vout}`,
          coin: true,
        });
      }
    }
  }

  beforeEach(async () => {
    dbPath = await mkdtemp(join(tmpdir(), "hotbuns-invalidate-readd-"));
    db = new ChainDB(dbPath);
    await db.open();
    headerSync = new HeaderSync(db, REGTEST);
    headerSync.initGenesis();
    chainState = new ChainStateManager(db, REGTEST);
    chainState.setHeaderSync(headerSync);
    blockSync = new BlockSync(db, REGTEST, headerSync, undefined, chainState, undefined, 16_000);
    mempool = new Mempool(blockSync.getUTXOManager(), REGTEST);
    blockSync.setMempool(mempool);
    const config: RPCServerConfig = { port: 0, host: "127.0.0.1", noAuth: true };
    const deps: RPCServerDeps = {
      chainState,
      mempool,
      peerManager: {
        getConnectedPeers: () => [],
        getPeerCount: () => 0,
        broadcast() {},
        updateBestHeight() {},
      } as any,
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

  test("invalidateblock: the disconnected tx returns and its in-pool child is linked to it", async () => {
    await extend(101);
    const A = spendTx(cb(1), [SUBSIDY - 10_000n], 1);
    await extend(1, new Map([[102, [A]]]));
    const M = spendTx(out(A), [SUBSIDY - 20_000n], 2);
    await accept(M);

    expect((await blockSync.invalidateBlock(getBlockHash(blocks[102].header))).success).toBe(true);
    expect(chainState.getBestBlock().height).toBe(101);
    expect(pool()).toEqual(new Set([hex(A), hex(M)]));
    expect(mempool.getTransaction(getTxId(M))!.dependsOn.has(hex(A))).toBe(true);
    expect(mempool.getTransaction(getTxId(A))!.spentBy.has(hex(M))).toBe(true);
    expect(mempool.getClusterSize(hex(M))).toBe(2);
    await expectPoolConsistent();
  });

  test("warden_e: parent with 64 in-pool children -> parent re-added, cheapest child trimmed at the 64-tx cluster limit", async () => {
    await extend(101);
    const CHILDREN = 64;
    const PARENT_FEE = 10_000n;
    const each = (SUBSIDY - PARENT_FEE) / BigInt(CHILDREN);
    const remainder = SUBSIDY - PARENT_FEE - each * BigInt(CHILDREN);
    const values = Array.from({ length: CHILDREN }, (_, i) => each + (i === 0 ? remainder : 0n));
    const parent = spendTx(cb(1), values, 0);
    await extend(1, new Map([[102, [parent]]]));
    const children = values.map((v, i) => spendTx(out(parent, i), [v - BigInt((i + 1) * 1000)], 1));
    for (const c of children) await accept(c);
    expect(pool().size).toBe(CHILDREN);

    expect((await blockSync.invalidateBlock(getBlockHash(blocks[102].header))).success).toBe(true);
    const ids = pool();
    // Core v31.1 (tools/core-regtest warden_e control): parent in, child 0 out.
    expect({ parent: ids.has(hex(parent)), child0: ids.has(hex(children[0])) }).toEqual({
      parent: true,
      child0: false,
    });
    expect(ids).toEqual(new Set([hex(parent), ...children.slice(1).map(hex)]));
    expect(mempool.getClusterSize(hex(parent))).toBe(CHILDREN);
    await expectPoolConsistent();
    // The template leads with the parent and never carries a tx without its parent.
    const ordered = mempool.getTransactionsByMiningScore().map((e) => e.txid.toString("hex"));
    expect(ordered[0]).toBe(hex(parent));
    expect(ordered).not.toContain(hex(children[0]));
  });

  test("a disconnected tx refused on re-accept takes its in-pool spender with it", async () => {
    await extend(101);
    // Version 4: consensus-valid in a block, non-standard for the mempool.
    const N = spendTx(cb(1), [SUBSIDY - 10_000n], 1, 4);
    await extend(1, new Map([[102, [N]]]));
    const C = spendTx(out(N), [SUBSIDY - 20_000n], 2);
    await accept(C);

    expect((await blockSync.invalidateBlock(getBlockHash(blocks[102].header))).success).toBe(true);
    expect(pool().has(hex(N))).toBe(false);
    expect(pool().has(hex(C))).toBe(false);
    await expectPoolConsistent();
  });

  test("a disconnected coinbase spend immature at the new tip+1 stays out, with its in-pool child", async () => {
    await extend(103);
    // cb(4) has depth 100 at height 104: mature there, immature at 103.
    const IMM = spendTx(cb(4), [SUBSIDY - 10_000n], 1);
    await extend(1, new Map([[104, [IMM]]]));
    const K = spendTx(out(IMM), [SUBSIDY - 20_000n], 2);
    await accept(K);

    // Disconnect 104 and 103: new tip 102, next block 103.
    expect((await blockSync.invalidateBlock(getBlockHash(blocks[103].header))).success).toBe(true);
    expect(chainState.getBestBlock().height).toBe(102);
    expect(pool().has(hex(IMM))).toBe(false);
    expect(pool().has(hex(K))).toBe(false);
    await expectPoolConsistent();
  });

  test("re-added entries carry Core's entry height: the disconnected block's height - 1", async () => {
    await extend(101);
    const A = spendTx(cb(1), [SUBSIDY - 10_000n], 1);
    const B = spendTx(out(A), [SUBSIDY - 20_000n], 2);
    await extend(1, new Map([[102, [A]]]));
    await extend(1, new Map([[103, [B]]]));

    // Disconnect 103 then 102 (Core: ATMP after each DisconnectTip).
    expect((await blockSync.invalidateBlock(getBlockHash(blocks[102].header))).success).toBe(true);
    expect(chainState.getBestBlock().height).toBe(101);
    expect(mempool.getTransaction(getTxId(A))!.height).toBe(101);
    expect(mempool.getTransaction(getTxId(B))!.height).toBe(102);
  });

  test("getmempoolentry / getrawmempool verbose: wtxid is the witness hash and there is no miningScore field", async () => {
    await extend(101);
    const A = spendTx(cb(1), [SUBSIDY - 10_000n], 1);
    await accept(A);
    const wtxid = display(getWTxId(A));
    expect(wtxid).not.toBe(display(getTxId(A)));
    const entry = (await rpc("getmempoolentry", [display(getTxId(A))])) as Record<string, unknown>;
    expect(entry.wtxid).toBe(wtxid);
    // Core entryToJSON (rpc/mempool.cpp) has no miningScore key.
    expect(Object.keys(entry)).not.toContain("miningScore");
    const verbose = (await rpc("getrawmempool", [true])) as Record<string, Record<string, unknown>>;
    expect(verbose[display(getTxId(A))].wtxid).toBe(wtxid);
  });

  test("fan-out cluster chunks like Core: the parent takes its best children, the cheaper ones are their own chunks", async () => {
    await extend(101);
    // Parent ~4.6 sat/vB; children arrive cheapest first.
    const values = [1_000_000n, 1_000_000n, 1_000_000n, 1_000_000n];
    const parent = spendTx(cb(1), [...values, SUBSIDY - 4_000_000n - 1_000n], 0);
    await accept(parent);
    const fees = [200n, 300n, 20_000n, 30_000n];
    const children = values.map((v, i) => spendTx(out(parent, i), [v - fees[i]], 1));
    for (const c of children) await accept(c);
    const chunkOf = (tx: Transaction) => mempool.getMainChunkFeerate(getTxId(tx));
    // Best order: parent, child 3, child 2 (one chunk), then child 1, child 0.
    expect(chunkOf(children[3]).fee).toBe(chunkOf(parent).fee);
    expect(chunkOf(children[2]).fee).toBe(chunkOf(parent).fee);
    expect(chunkOf(parent).fee).toBe(1_000n + 20_000n + 30_000n);
    expect(chunkOf(children[1]).fee).toBe(300n);
    expect(chunkOf(children[0]).fee).toBe(200n);
  });
});
