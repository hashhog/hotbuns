/**
 * A header whose parent is marked invalid is refused, never stored
 * (Core AcceptBlockHeader, validation.cpp:4219-4223: pindexPrev has
 * BLOCK_FAILED_VALID -> state.Invalid(BLOCK_INVALID_PREV, "bad-prevblk"),
 * before AddToBlockIndex). submitheader answers RPC_VERIFY_ERROR (-25)
 * "bad-prevblk" (rpc/mining.cpp submitheader).
 *
 * hotbuns stored such a header with status "invalid". reconsiderblock of
 * the parent then cleared it like any other descendant, so a header Core
 * never indexed became a valid, body-less candidate. When it was seen first
 * at equal work it held the best-header slot at its height, the connect
 * loop waited for its body, and a valid block extending the same tip was
 * answered "rejected" and never connected (Core regtest harness
 * warden_invalidated_submit: accept-child at 103, so the harness's blocks
 * 104-106 were built on a parent hotbuns did not have).
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
  serializeBlockHeader,
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


describe("bad-prevblk: a child of an invalid header is refused, not stored", () => {
  let dbPath: string;
  let db: ChainDB;
  let headerSync: HeaderSync;
  let chainState: ChainStateManager;
  let blockSync: BlockSync;
  let server: RPCServer;
  let blocks: Block[]; // blocks[h] = block at height h
  let t: number;

  function rpc(method: string, params: unknown[]) {
    const methods = (server as any).methods as Map<string, (p: unknown[]) => Promise<unknown>>;
    return methods.get(method)!(params);
  }

  async function rpcError(method: string, params: unknown[]): Promise<{ code: number; message: string } | null> {
    try {
      await rpc(method, params);
      return null;
    } catch (err: any) {
      return { code: err.code, message: err.message };
    }
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

  const headerHex = (b: Block) => serializeBlockHeader(b.header).toString("hex");

  beforeEach(async () => {
    dbPath = await mkdtemp(join(tmpdir(), "hotbuns-badprevblk-"));
    db = new ChainDB(dbPath);
    await db.open();
    headerSync = new HeaderSync(db, REGTEST);
    headerSync.initGenesis();
    chainState = new ChainStateManager(db, REGTEST);
    chainState.setHeaderSync(headerSync);
    blockSync = new BlockSync(db, REGTEST, headerSync, undefined, chainState, undefined);
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
    await extend(5);
  });

  afterEach(async () => {
    await blockSync.stop();
    await db.close();
    await rm(dbPath, { recursive: true, force: true });
  });

  test("submitheader on an invalidated parent answers -25 bad-prevblk and stores nothing", async () => {
    const b5 = getBlockHash(blocks[5].header);
    await rpc("invalidateblock", [display(b5)]);
    expect(chainState.getBestBlock().height).toBe(4);

    const child = mine(b5, t + 1, 6);
    expect(await rpcError("submitheader", [headerHex(child)])).toEqual({ code: -25, message: "bad-prevblk" });
    expect(headerSync.getHeader(getBlockHash(child.header))).toBeUndefined();

    // Control: the same header on a valid parent is accepted (null).
    await rpc("reconsiderblock", [display(b5)]);
    expect(await rpc("submitheader", [headerHex(child)])).toBeNull();
    expect(headerSync.getHeader(getBlockHash(child.header))).toBeDefined();
  }, 120_000);

  test("a P2P headers message extending an invalid header stores nothing", async () => {
    const b5 = getBlockHash(blocks[5].header);
    await rpc("invalidateblock", [display(b5)]);
    const child = mine(b5, t + 1, 6);
    const grandchild = mine(getBlockHash(child.header), t + 2, 7);
    const peer = { host: "127.0.0.1", port: 18444, state: "connected", versionPayload: { startHeight: 7 }, send: () => true };
    expect(await headerSync.processHeaders([child.header, grandchild.header], peer as any)).toBe(0);
    expect(headerSync.getHeader(getBlockHash(child.header))).toBeUndefined();
    expect(headerSync.getHeader(getBlockHash(grandchild.header))).toBeUndefined();
  }, 120_000);

  test("after reconsiderblock, a valid child connects even though a sibling header was offered while the parent was invalid", async () => {
    // The harness sequence (warden_invalidated_submit failed-parent paths).
    const b5 = getBlockHash(blocks[5].header);
    await rpc("invalidateblock", [display(b5)]);
    const headerOnly = mine(b5, t + 1, 6); // offered as a header only, never as a block
    const validChild = mine(b5, t + 2, 6);
    await rpcError("submitheader", [headerHex(headerOnly)]);
    expect(await blockSync.injectBlock(validChild)).toBe("bad-prevblk");

    await rpc("reconsiderblock", [display(b5)]);
    expect(chainState.getBestBlock().height).toBe(5);

    // Core: the header-only sibling was never indexed, so the valid child is
    // the only candidate at 6 and connects.
    expect(await blockSync.injectBlock(validChild)).toBeNull();
    expect(chainState.getBestBlock().height).toBe(6);
    expect(chainState.getBestBlock().hash.equals(getBlockHash(validChild.header))).toBe(true);

    // And the chain keeps extending on it.
    const next = mine(getBlockHash(validChild.header), t + 3, 7);
    expect(await blockSync.injectBlock(next)).toBeNull();
    expect(chainState.getBestBlock().height).toBe(7);
  }, 120_000);

  test("control: a block refused as bad-prevblk connects once its parent is reconsidered", async () => {
    const b5 = getBlockHash(blocks[5].header);
    await rpc("invalidateblock", [display(b5)]);
    const child = mine(b5, t + 1, 6);
    expect(await blockSync.injectBlock(child)).toBe("bad-prevblk");
    await rpc("reconsiderblock", [display(b5)]);
    expect(await blockSync.injectBlock(child)).toBeNull();
    expect(chainState.getBestBlock().height).toBe(6);
  }, 120_000);
});
