/**
 * invalidateblock must STICK, and must be serialized with block connect.
 * (Audit 2026-10-07, fleet fix brief #6: HB-10 and HB-2.)
 *
 * Core (validation.cpp):
 *   - InvalidateBlock holds m_chainstate_mutex + cs_main, disconnects the
 *     active branch, marks the block BLOCK_FAILED_VALID and its descendants
 *     failed, and re-derives m_best_header off the failed branch
 *     (InvalidChainFound / RecalculateBestHeader).
 *   - AcceptBlockHeader answers "duplicate-invalid" for a failed block and
 *     "bad-prevblk" for a child of one; FindMostWorkChain never selects them;
 *     net_processing never requests them.
 *   - ResetBlockFailureFlags clears the block, its descendants AND ancestors,
 *     then ActivateBestChain reconnects the best chain.
 *
 * Driven through the real node objects the way cli.ts wires them
 * (BlockSync.injectBlock = submitblock/P2P connect, RPCServer method table =
 * the RPC entrypoint).
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

describe("invalidateblock sticks and is serialized with connect (HB-10, HB-2)", () => {
  let dbPath: string;
  let db: ChainDB;
  let headerSync: HeaderSync;
  let chainState: ChainStateManager;
  let blockSync: BlockSync;
  let server: RPCServer;
  let blocks: Block[]; // blocks[h] = block at height h
  let t: number;

  const SMALL_DBCACHE = 16_000; // every flush evicts → coins are cold

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

  async function waitTip(h: number, ms = 5000) {
    const t0 = Date.now();
    while (Date.now() - t0 < ms && chainState.getBestBlock().height !== h) {
      await new Promise((r) => setTimeout(r, 10));
    }
    return chainState.getBestBlock().height;
  }

  beforeEach(async () => {
    dbPath = await mkdtemp(join(tmpdir(), "hotbuns-invsticky-"));
    db = new ChainDB(dbPath);
    await db.open();
    headerSync = new HeaderSync(db, REGTEST);
    headerSync.initGenesis();
    chainState = new ChainStateManager(db, REGTEST);
    chainState.setHeaderSync(headerSync);
    blockSync = new BlockSync(db, REGTEST, headerSync, undefined, chainState, undefined, SMALL_DBCACHE);
    const mempool = new Mempool(blockSync.getUTXOManager(), REGTEST);
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

  test("HB-10: the failed block and its descendants are refused on header and block accept; reconsider re-activates", async () => {
    await extend(12);
    expect(chainState.getBestBlock().height).toBe(12);
    const b10 = getBlockHash(blocks[10].header);
    const b11 = getBlockHash(blocks[11].header);
    const b12 = getBlockHash(blocks[12].header);

    await rpc("invalidateblock", [display(b10)]);
    expect(chainState.getBestBlock().height).toBe(9);

    // Header layer: failed, best header re-derived off the failed branch.
    expect(headerSync.getHeader(b10)?.status).toBe("invalid");
    expect(headerSync.getHeader(b11)?.status).toBe("invalid");
    expect(headerSync.getHeader(b12)?.status).toBe("invalid");
    expect(headerSync.getBestHeader()?.height).toBe(9);
    expect(headerSync.getHeaderByHeight(10)).toBeFalsy();

    // Block index (persisted): the block and every descendant carry a FAILED
    // flag (Core marks disconnected blocks and children BLOCK_FAILED_VALID).
    const FAILED = BlockStatus.FAILED_VALID | BlockStatus.FAILED_CHILD;
    expect((await db.getBlockIndex(b10))!.status & BlockStatus.FAILED_VALID).toBeTruthy();
    expect((await db.getBlockIndex(b11))!.status & FAILED).toBeTruthy();
    expect((await db.getBlockIndex(b12))!.status & FAILED).toBeTruthy();

    // submitblock of the failed block: Core "duplicate-invalid", tip unchanged.
    expect(await blockSync.injectBlock(blocks[10])).toBe("duplicate-invalid");
    expect(chainState.getBestBlock().height).toBe(9);
    // A child of the failed branch (the network extending it): refused.
    t += 600;
    const b13 = mine(b12, t, 13);
    expect(await blockSync.injectBlock(b13)).toBe("bad-prevblk");
    expect(await blockSync.injectBlock(blocks[11])).toBe("duplicate-invalid");
    expect(chainState.getBestBlock().height).toBe(9);

    // Negative control: reconsiderblock clears the flags and re-activates the
    // best chain from the bodies already on disk, then the chain extends.
    await rpc("reconsiderblock", [display(b10)]);
    expect(headerSync.getHeader(b12)?.status).not.toBe("invalid");
    expect(await waitTip(12)).toBe(12);
    expect(await blockSync.injectBlock(b13)).toBeNull();
    expect(chainState.getBestBlock().height).toBe(13);
  }, 120_000);

  test("HB-2: invalidateblock issued while a connect is parked mid-block waits for it, and the coins on disk match a serial run", async () => {
    // Mature chain: coinbase of block 1 (X) and block 2 (Z) spendable at 102.
    await extend(101);
    const X = { txid: getTxId(blocks[1].transactions[0]), vout: 0 };
    const Z = { txid: getTxId(blocks[2].transactions[0]), vout: 0 };
    const tx102 = spendTx(X, SUBSIDY - 10_000n, 1);
    await extend(1, new Map([[102, [tx102]]]));
    const b102 = getBlockHash(blocks[102].header);
    expect(blockSync.getUTXOManager().getCoinsViewCache().haveCoinInCache(Z)).toBe(false);

    // Block 103 spends Z (cold): park its input read.
    t += 600;
    const tx103 = spendTx(Z, SUBSIDY - 10_000n, 2);
    const blk103 = mine(b102, t, 103, [tx103]);
    let open!: () => void;
    const gate = new Promise<void>((r) => (open = r));
    const realGet = db.getUTXO.bind(db);
    let armed = true;
    let parked = false;
    (db as any).getUTXO = async (txid: Buffer, vout: number) => {
      const v = await realGet(txid, vout);
      if (armed && txid.equals(Z.txid) && vout === Z.vout) {
        armed = false;
        parked = true;
        await gate;
      }
      return v;
    };
    const connect103 = blockSync.injectBlock(blk103);
    for (let i = 0; i < 200 && !parked; i++) await new Promise((r) => setTimeout(r, 2));
    expect(parked).toBe(true);

    // Operator invalidates 102 while 103 is mid-connect.
    const inv = rpc("invalidateblock", [display(b102)]);
    await new Promise((r) => setTimeout(r, 50));
    open();
    const v103 = await connect103;
    await inv;
    console.log(`[HB-2] 103 verdict=${v103 === null ? "connected" : v103}; tip=${chainState.getBestBlock().height}`);

    // Serial result (Core: InvalidateBlock waits for the connect, then
    // disconnects 103 and 102): tip 101, X and Z unspent, nothing of 102/103.
    expect(chainState.getBestBlock().height).toBe(101);
    const cs = await db.getChainState();
    expect(cs!.bestHeight).toBe(101);
    expect(cs!.bestBlockHash.equals(getBlockHash(blocks[101].header))).toBe(true);
    expect(await realGet(X.txid, X.vout)).not.toBeNull();
    expect(await realGet(Z.txid, Z.vout)).not.toBeNull();
    expect(await realGet(getTxId(tx102), 0)).toBeNull();
    expect(await realGet(getTxId(tx103), 0)).toBeNull();
    expect(await realGet(getTxId(blocks[102].transactions[0]), 0)).toBeNull();
    // The live view agrees with disk.
    const live = blockSync.getUTXOManager();
    expect(await live.getUTXOAsync(X)).not.toBeNull();
    expect(await live.getUTXOAsync({ txid: getTxId(tx102), vout: 0 })).toBeNull();

    // Negative control: a block on the surviving tip (101) still connects.
    t += 600;
    const alt102 = mine(getBlockHash(blocks[101].header), t, 102, [spendTx(X, SUBSIDY - 30_000n, 3)]);
    expect(await blockSync.injectBlock(alt102)).toBeNull();
    expect(chainState.getBestBlock().height).toBe(102);
  }, 180_000);
});
