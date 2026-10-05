/**
 * F0 end to end — a coin spent by a CONNECTED block is spent AGAIN.
 *
 * Two roads, both driven through the real node objects the way cli.ts wires
 * them (BlockSync.injectBlock is the submitblock / P2P connect entrypoint):
 *
 * A. Read-through resurrection in BlockSync's (authoritative) coin view.
 *    An RPC reader (gettxout → liveUTXOManager().getUTXOAsync, server.ts:13171)
 *    misses the cache and issues a LevelDB read of coin X.  Before its
 *    continuation runs, block 102 spends X and the per-block flush commits the
 *    delete and drops the spent entry.  The reader then installs its pre-delete
 *    copy as a CLEAN unspent coin, and block 103 spending X again is ACCEPTED.
 *
 * B. The mempool reads a SECOND, stale coin view.  cli.ts builds the mempool
 *    over ChainStateManager's UTXOManager, but blocks connect through
 *    BlockSync's own UTXOManager, which nothing propagates into the first
 *    view's cache.  A coin the mempool once looked up stays "unspent" there
 *    after a block spends it, so a transaction re-spending a confirmed-spent
 *    coin is ACCEPTED into the mempool (and offered to getblocktemplate).
 *
 * Core: one CCoinsViewCache (pcoinsTip) under cs_main serves connect, mempool
 * (CCoinsViewMemPool over it) and gettxout; coins.cpp:69-82 FetchCoin.
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
import { Transaction, getTxId } from "../validation/tx.js";
import { computeWitnessCommitmentHash } from "../mining/template.js";
import { HeaderSync } from "./headers.js";
import { BlockSync } from "./blocks.js";
import { ChainStateManager } from "../chain/state.js";
import { Mempool } from "../mempool/mempool.js";

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

/** Spend `prev` (a P2WSH(OP_TRUE) coin) to a fresh P2WSH(OP_TRUE) output. */
function spendTx(prev: { txid: Buffer; vout: number }, value: bigint, tag: number): Transaction {
  return {
    version: 2,
    inputs: [{ prevOut: prev, scriptSig: Buffer.alloc(0), sequence: 0xfffffffd - tag, witness: [WITNESS_SCRIPT] }],
    outputs: [{ value, scriptPubKey: P2WSH_TRUE }],
    lockTime: 0,
  };
}

describe("F0 end to end: a confirmed-spent coin is spent again", () => {
  let dbPath: string;
  let db: ChainDB;
  let headerSync: HeaderSync;
  let chainState: ChainStateManager;
  let blockSync: BlockSync;
  let tipHash: Buffer;
  let t: number;
  let X: { txid: Buffer; vout: number };

  // A cache far smaller than the UTXO set (as on mainnet: ~300k of ~166M
  // coins) — every per-block flush evicts, so X is cold when it is read.
  const SMALL_DBCACHE = 16_000;

  async function buildMatureChain() {
    const genesis = headerSync.getBestHeader()!;
    t = genesis.header.timestamp;
    tipHash = genesis.hash;
    let first: Block | null = null;
    for (let h = 1; h <= 101; h++) {
      t += 600;
      const b = mine(tipHash, t, h);
      expect(await blockSync.injectBlock(b)).toBeNull();
      tipHash = getBlockHash(b.header);
      if (h === 1) first = b;
    }
    X = { txid: getTxId(first!.transactions[0]), vout: 0 };
    expect(chainState.getBestBlock().height).toBe(101);
  }

  beforeEach(async () => {
    dbPath = await mkdtemp(join(tmpdir(), "hotbuns-f0-resurrection-"));
    db = new ChainDB(dbPath);
    await db.open();
    headerSync = new HeaderSync(db, REGTEST);
    headerSync.initGenesis();
    chainState = new ChainStateManager(db, REGTEST);
    blockSync = new BlockSync(db, REGTEST, headerSync, undefined, chainState, undefined, SMALL_DBCACHE);
  });

  afterEach(async () => {
    await blockSync.stop();
    await db.close();
    await rm(dbPath, { recursive: true, force: true });
  });

  test("A: an RPC read straddling block 102's spend+flush resurrects X; block 103 re-spending X must be REJECTED", async () => {
    await buildMatureChain();
    const live = blockSync.getUTXOManager(); // what gettxout reads (liveUTXOManager)
    expect(live.getCoinsViewCache().haveCoinInCache(X)).toBe(false); // cold
    expect(await db.getUTXO(X.txid, X.vout)).not.toBeNull(); // on disk

    // Gate the next LevelDB read of X: it hits the disk now, its continuation
    // runs only when we open the gate.
    let open!: () => void;
    const gate = new Promise<void>((r) => (open = r));
    const realGet = db.getUTXO.bind(db);
    let armed = true;
    let issued = false;
    (db as any).getUTXO = async (txid: Buffer, vout: number) => {
      const v = await realGet(txid, vout);
      if (armed && txid.equals(X.txid) && vout === X.vout) {
        armed = false;
        issued = true;
        await gate;
      }
      return v;
    };

    const reader = live.getUTXOAsync(X); // gettxout X
    for (let i = 0; i < 50 && !issued; i++) await new Promise((r) => setTimeout(r, 1));
    expect(issued).toBe(true);

    // Block 102 spends X; at tip it is flushed in the same call.
    t += 600;
    const b102 = mine(tipHash, t, 102, [spendTx(X, SUBSIDY - 10_000n, 1)]);
    expect(await blockSync.injectBlock(b102)).toBeNull();
    tipHash = getBlockHash(b102.header);
    expect(await realGet(X.txid, X.vout)).toBeNull(); // the delete is on disk

    open();
    await reader;

    // Block 103 spends X AGAIN with a different transaction.
    t += 600;
    const b103 = mine(tipHash, t, 103, [spendTx(X, SUBSIDY - 20_000n, 2)]);
    const verdict = await blockSync.injectBlock(b103);
    console.log(`[F0-A] block 103 (re-spends X, spent in 102) verdict: ${verdict === null ? "ACCEPTED" : verdict}; tip=${chainState.getBestBlock().height}`);
    expect(verdict).not.toBeNull();
    expect(verdict ?? "").toContain("missingorspent");
    expect(chainState.getBestBlock().height).toBe(102);
  }, 120_000);

  test("A-control: the same blocks with no straddling reader → block 103 is rejected missingorspent", async () => {
    await buildMatureChain();
    t += 600;
    const b102 = mine(tipHash, t, 102, [spendTx(X, SUBSIDY - 10_000n, 1)]);
    expect(await blockSync.injectBlock(b102)).toBeNull();
    tipHash = getBlockHash(b102.header);
    t += 600;
    const b103 = mine(tipHash, t, 103, [spendTx(X, SUBSIDY - 20_000n, 2)]);
    const verdict = await blockSync.injectBlock(b103);
    expect(verdict ?? "").toContain("missingorspent");
    expect(chainState.getBestBlock().height).toBe(102);
  }, 120_000);

  test("B: the mempool must not accept a transaction spending a coin a connected block already spent", async () => {
    await buildMatureChain();
    // Wiring exactly as cli.ts: mempool over ChainStateManager's view, then
    // handed to BlockSync for removeForBlock / reorg refill.
    const mempool = new Mempool(chainState.getUTXOManager(), REGTEST);
    blockSync.setMempool(mempool);
    mempool.setTipHeight(101);

    const t1 = spendTx(X, SUBSIDY - 10_000n, 1);
    const r1 = await mempool.addTransaction(t1);
    expect(r1.accepted).toBe(true);

    t += 600;
    const b102 = mine(tipHash, t, 102, [t1]);
    expect(await blockSync.injectBlock(b102)).toBeNull();
    expect(mempool.hasTransaction(getTxId(t1))).toBe(false); // confirmed, removed
    expect(await db.getUTXO(X.txid, X.vout)).toBeNull(); // X spent on disk
    mempool.setTipHeight(102);

    const t2 = spendTx(X, SUBSIDY - 20_000n, 2);
    const r2 = await mempool.addTransaction(t2);
    console.log(`[F0-B] mempool verdict for a re-spend of X (spent in block 102): ${r2.accepted ? "ACCEPTED" : r2.error}`);
    expect(r2.accepted).toBe(false);
    expect(r2.error ?? "").toContain("missingorspent");
  }, 120_000);
});
