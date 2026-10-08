/**
 * ORIGINAL HEADER (helpers copied from blocks.invalidate-sticky.test.ts):
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
import { serializeBlock } from "../validation/block.js";
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

const serializeHex = (b: Block) => serializeBlock(b).toString("hex");

/**
 * submitblock racing the SAME block over P2P (fleet-conformance SUBP2P,
 * finding 6, 2026-10-08).
 *
 * Core: submitblock -> ProcessNewBlock; AcceptBlock decides "already have it"
 * under cs_main and ActivateBestChain connects under cs_main, so the RPC answers
 * null (this call stored + connected it) or "duplicate" (!new_block) -- never a
 * rejection of a valid block (rpc/mining.cpp submitblock / BIP22ValidationResult).
 *
 * Deployed 3b44fdd: injectBlock ran unlocked; with the P2P loop mid-connect of
 * the block (`processing` held), its processOrderedBlocks() returned at once,
 * the frontier had not moved and no connect error existed -> "rejected".
 */
const peer = (): any => ({
  host: "127.0.0.9",
  port: 18444,
  updateSyncedBlocks() {},
  updateSyncedHeaders() {},
  misbehaving() {},
  removeBlockInFlight() {},
});

describe("submitblock racing the same block over P2P (SUBP2P finding 6)", () => {
  let dbPath: string;
  let db: ChainDB;
  let headerSync: HeaderSync;
  let chainState: ChainStateManager;
  let blockSync: BlockSync;
  let server: RPCServer;
  let blocks: Block[];
  let t: number;

  function rpc(method: string, params: unknown[]) {
    const methods = (server as any).methods as Map<string, (p: unknown[]) => Promise<unknown>>;
    return methods.get(method)!(params);
  }

  async function extend(n: number) {
    for (let i = 0; i < n; i++) {
      const h = blocks.length;
      t += 600;
      const b = mine(getBlockHash(blocks[h - 1].header), t, h);
      expect(await blockSync.injectBlock(b)).toBeNull();
      blocks.push(b);
    }
  }

  beforeEach(async () => {
    dbPath = await mkdtemp(join(tmpdir(), "hotbuns-subrace-"));
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
      chainState, mempool, peerManager: new MockPeerManager() as any,
      feeEstimator: new FeeEstimator(mempool), headerSync, db, params: REGTEST, blockSync,
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

  test("P2P connect of block B in flight, submitblock(B) -> null or 'duplicate', never 'rejected'; tip B", async () => {
    await extend(101);
    // Block 102 spends block 1's coinbase (cold after the small-dbcache flushes):
    // park that input read so the P2P loop holds the chain mid-connect.
    const X = { txid: getTxId(blocks[1].transactions[0]), vout: 0 };
    t += 600;
    const b102 = mine(getBlockHash(blocks[101].header), t, 102, [spendTx(X, SUBSIDY - 10_000n, 1)]);
    let open!: () => void;
    const gate = new Promise<void>((r) => (open = r));
    const realGet = db.getUTXO.bind(db);
    let armed = true;
    let parked = false;
    (db as any).getUTXO = async (txid: Buffer, vout: number) => {
      const v = await realGet(txid, vout);
      if (armed && txid.equals(X.txid) && vout === X.vout) {
        armed = false;
        parked = true;
        await gate;
      }
      return v;
    };
    expect(await headerSync.processHeaders([b102.header], null, false)).toBe(1);
    const p2p = blockSync.handleBlock(peer(), b102);
    for (let i = 0; i < 500 && !parked; i++) await new Promise((r) => setTimeout(r, 2));
    // Instrument check: the race window is really open (else this test proves nothing).
    expect(parked).toBe(true);

    const submit = rpc("submitblock", [serializeHex(b102)]);
    await new Promise((r) => setTimeout(r, 50));
    open();
    const answer = await submit;
    await p2p;
    expect(answer === null || answer === "duplicate").toBe(true);
    expect(chainState.getBestBlock().height).toBe(102);
    expect(chainState.getBestBlock().hash.equals(getBlockHash(b102.header))).toBe(true);

    // And the next block still connects through submitblock (no wedge).
    t += 600;
    const b103 = mine(getBlockHash(b102.header), t, 103);
    expect(await rpc("submitblock", [serializeHex(b103)])).toBeNull();
    expect(chainState.getBestBlock().height).toBe(103);
  }, 120_000);

  test("control: a plain submitblock of an already-connected block answers 'duplicate'", async () => {
    await extend(3);
    expect(await rpc("submitblock", [serializeHex(blocks[3])])).toBe("duplicate");
    expect(chainState.getBestBlock().height).toBe(3);
  }, 60_000);
});
