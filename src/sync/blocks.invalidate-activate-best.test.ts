/**
 * invalidateblock / reconsiderblock run ActivateBestChain over the side
 * branches already on disk (Core v31.1 failed_reorg scenarios B and C,
 * tools/core-regtest/harness/scenarios/failed_reorg.py in hashhog).
 *
 * Core (validation.cpp): the invalidateblock and reconsiderblock RPCs both
 * call ActivateBestChain after InvalidateBlock / ResetBlockFailureFlags.
 * FindMostWorkChain picks the most-work candidate with data, ties broken by
 * nSequenceId (the block received first wins); ConnectTip failing a block on
 * that branch marks it BLOCK_FAILED_VALID and the tip settles on the valid
 * prefix.
 *
 * hotbuns used to stop at the invalidated block's parent: a stored side
 * branch with more work was never connected, so the regtest diff stayed on
 * the old branch for every later scenario (186 failed_reorg rows).
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

function coinbaseTx(height: number, spends: Transaction[], tag = 0x07, value = SUBSIDY): Transaction {
  const outputs = [{ value, scriptPubKey: P2WSH_TRUE }];
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
        scriptSig: Buffer.concat([encodeBip34Height(height), Buffer.from([0xff, tag])]),
        sequence: 0xffffffff,
        witness,
      },
    ],
    outputs,
    lockTime: 0,
  };
}

function mine(prev: Buffer, timestamp: number, height: number, spends: Transaction[] = [], tag = 0x07, value = SUBSIDY): Block {
  const cb = coinbaseTx(height, spends, tag, value);
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


const BAD_VALUE = 51n * 100_000_000n; // > subsidy: ConnectBlock fails bad-cb-amount

describe("invalidateblock/reconsiderblock activate the best stored chain (failed_reorg B, C)", () => {
  let dbPath: string;
  let db: ChainDB;
  let headerSync: HeaderSync;
  let chainState: ChainStateManager;
  let blockSync: BlockSync;
  let server: RPCServer;
  let genesisHash: Buffer;
  let t0: number;

  function rpc(method: string, params: unknown[]) {
    const methods = (server as any).methods as Map<string, (p: unknown[]) => Promise<unknown>>;
    return methods.get(method)!(params);
  }

  /** `n` blocks on `prev` starting at `height`; `offset` separates siblings. */
  function branch(prev: Buffer, height: number, n: number, tag: number, offset = 0, badLast = false): Block[] {
    const out: Block[] = [];
    for (let i = 0; i < n; i++) {
      const h = height + i;
      const bad = badLast && i === n - 1;
      const b = mine(prev, t0 + h * 600 + offset, h, [], tag + i, bad ? BAD_VALUE : SUBSIDY);
      out.push(b);
      prev = getBlockHash(b.header);
    }
    return out;
  }

  const hashOf = (b: Block) => getBlockHash(b.header);
  const tipHash = () => chainState.getBestBlock().hash;

  beforeEach(async () => {
    dbPath = await mkdtemp(join(tmpdir(), "hotbuns-invactivate-"));
    db = new ChainDB(dbPath);
    await db.open();
    headerSync = new HeaderSync(db, REGTEST);
    headerSync.initGenesis();
    chainState = new ChainStateManager(db, REGTEST);
    chainState.setHeaderSync(headerSync);
    blockSync = new BlockSync(db, REGTEST, headerSync, undefined, chainState, undefined, 16_000);
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
    genesisHash = genesis.hash;
    t0 = genesis.header.timestamp;
  });

  afterEach(async () => {
    await blockSync.stop();
    await db.close();
    await rm(dbPath, { recursive: true, force: true });
  });

  test("B: invalidateblock connects the heavier stored side branch and stops before its invalid tip", async () => {
    // G-1-2-3a-4a-5a, and 3s-4s-5s_bad off 2 submitted while 5a is the tip.
    const main = branch(genesisHash, 1, 5, 0x30);
    for (const b of main) expect(await blockSync.injectBlock(b)).toBeNull();
    const side = branch(hashOf(main[1]), 3, 3, 0x43, 1, true);
    for (const b of side) await blockSync.injectBlock(b);
    expect(tipHash().equals(hashOf(main[4]))).toBe(true);

    await rpc("invalidateblock", [display(hashOf(main[3]))]);

    // Core: connects 3s and 4s, fails 5s_bad (bad-cb-amount), stays on 4s.
    expect(display(tipHash())).toBe(display(hashOf(side[1])));
    expect(chainState.getBestBlock().height).toBe(4);
    expect(headerSync.getHeader(hashOf(side[2]))?.status).toBe("invalid");
    expect(headerSync.getHeader(hashOf(main[3]))?.status).toBe("invalid");
    // The UTXO view follows: 4s's coinbase exists, 3a's and 5s_bad's do not.
    const view = blockSync.getUTXOManager().getCoinsViewCache();
    const cb = (b: Block) => ({ txid: getTxId(b.transactions[0]), vout: 0 });
    expect(await view.haveCoin(cb(side[1]))).toBe(true);
    expect(await view.haveCoin(cb(main[2]))).toBe(false);
    expect(await view.haveCoin(cb(side[2]))).toBe(false);
    // The failed block is refused, and a valid child of 4s extends the chain.
    expect(await blockSync.injectBlock(side[2])).toBe("duplicate-invalid");
    const next = branch(hashOf(side[1]), 5, 1, 0x60, 2);
    expect(await blockSync.injectBlock(next[0])).toBeNull();
    expect(chainState.getBestBlock().height).toBe(5);
  }, 120_000);

  test("B negative: invalidateblock does not move to a stored side branch with less work", async () => {
    // G-1-2-3a-4a-5a and a lone 3s off 2: after invalidating 5a the tip 4a
    // still out-works 3s, so it stays (Core: no candidate beats 4a).
    const main = branch(genesisHash, 1, 5, 0x30);
    for (const b of main) expect(await blockSync.injectBlock(b)).toBeNull();
    const side = branch(hashOf(main[1]), 3, 1, 0x43, 1);
    await blockSync.injectBlock(side[0]);
    await rpc("invalidateblock", [display(hashOf(main[4]))]);
    expect(display(tipHash())).toBe(display(hashOf(main[3])));
  }, 120_000);

  test("C: reconsiderblock returns an equal-work tie to the branch received first", async () => {
    // G-1-2-3a-4a, and 3s-4s off 2 submitted while 4a is the tip.
    const main = branch(genesisHash, 1, 4, 0x50);
    for (const b of main) expect(await blockSync.injectBlock(b)).toBeNull();
    const side = branch(hashOf(main[1]), 3, 2, 0x63, 1);
    for (const b of side) await blockSync.injectBlock(b);
    expect(display(tipHash())).toBe(display(hashOf(main[3])));

    await rpc("invalidateblock", [display(hashOf(main[3]))]);
    // 4s out-works 3a.
    expect(display(tipHash())).toBe(display(hashOf(side[1])));

    await rpc("reconsiderblock", [display(hashOf(main[3]))]);
    // 4a and 4s tie on work; 4a was received first, so Core goes back to it.
    expect(display(tipHash())).toBe(display(hashOf(main[3])));
    expect(headerSync.getBestHeader()?.hash.equals(hashOf(main[3]))).toBe(true);
    const view = blockSync.getUTXOManager().getCoinsViewCache();
    const cb = (b: Block) => ({ txid: getTxId(b.transactions[0]), vout: 0 });
    expect(await view.haveCoin(cb(main[3]))).toBe(true);
    expect(await view.haveCoin(cb(side[1]))).toBe(false);
  }, 120_000);

  test("C negative: reconsidering an equal-work branch received LATER leaves the tip", async () => {
    // 4a is the tip, 3s-4s arrived later. invalidate 4s (not active: no
    // move), then reconsider it: 4s ties 4a on work but was received after
    // it, so Core keeps 4a.
    const main = branch(genesisHash, 1, 4, 0x50);
    for (const b of main) expect(await blockSync.injectBlock(b)).toBeNull();
    const side = branch(hashOf(main[1]), 3, 2, 0x63, 1);
    for (const b of side) await blockSync.injectBlock(b);
    await rpc("invalidateblock", [display(hashOf(side[1]))]);
    expect(display(tipHash())).toBe(display(hashOf(main[3])));
    await rpc("reconsiderblock", [display(hashOf(side[1]))]);
    expect(display(tipHash())).toBe(display(hashOf(main[3])));
    expect(headerSync.getBestHeader()?.hash.equals(hashOf(main[3]))).toBe(true);
  }, 120_000);
});
