/**
 * getchaintips lists every block-index leaf, like Core (fleet item
 * done-fleet-regtest-getchaintips).
 *
 * Core rpc/blockchain.cpp getchaintips: a tip is every m_block_index entry
 * off the active chain that is no other such entry's pprev, plus the active
 * tip; branchlen = height - FindFork(active).height; status is active /
 * invalid (BLOCK_FAILED_MASK) / headers-only (!HaveNumChainTxs) / valid-fork
 * (IsValid(BLOCK_VALID_SCRIPTS): connected once) / valid-headers.
 *
 * hotbuns answered with the active tip alone, so an invalidated block, a
 * stored sibling, a reorged-away block, a fork header and a block that failed
 * ConnectBlock were all missing (tools/core-regtest chain, reorg,
 * seed_invalidated_submit and warden_invalidated_submit tips rows).
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
  serializeBlock,
  serializeBlockHeader,
} from "../validation/block.js";
import { Transaction, getTxId } from "../validation/tx.js";
import { HeaderSync } from "../sync/headers.js";
import { BlockSync } from "../sync/blocks.js";
import { ChainStateManager } from "../chain/state.js";
import { Mempool } from "../mempool/mempool.js";
import { FeeEstimator } from "../fees/estimator.js";
import { RPCServer, type RPCServerConfig, type RPCServerDeps } from "./server.js";

const SUBSIDY = 5_000_000_000n;
const P2WSH_TRUE = Buffer.concat([
  Buffer.from([0x00, 0x20]),
  createHash("sha256").update(Buffer.from([0x51])).digest(),
]);

function mine(prev: Buffer, timestamp: number, height: number, tag: number, value = SUBSIDY): Block {
  const cb: Transaction = {
    version: 1,
    inputs: [
      {
        prevOut: { txid: Buffer.alloc(32, 0), vout: 0xffffffff },
        scriptSig: Buffer.concat([encodeBip34Height(height), Buffer.from([0x01, tag])]),
        sequence: 0xffffffff,
        witness: [],
      },
    ],
    outputs: [{ value, scriptPubKey: P2WSH_TRUE }],
    lockTime: 0,
  };
  const base: BlockHeader = {
    version: 0x20000000,
    prevBlock: prev,
    merkleRoot: computeMerkleRoot([getTxId(cb)]),
    timestamp,
    bits: REGTEST.powLimitBits,
    nonce: 0,
  };
  const target = compactToBigInt(REGTEST.powLimitBits);
  for (let nonce = 0; nonce < 10_000_000; nonce++) {
    const header = { ...base, nonce };
    if (BigInt("0x" + Buffer.from(getBlockHash(header)).reverse().toString("hex")) <= target) {
      return { header, transactions: [cb] };
    }
  }
  throw new Error("failed to mine regtest block");
}

const display = (h: Buffer) => Buffer.from(h).reverse().toString("hex");
const hashOf = (b: Block) => getBlockHash(b.header);

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

type Tip = { height: number; hash: string; branchlen: number; status: string };

describe("getchaintips: every block-index leaf, Core statuses and branchlen", () => {
  let dbPath: string;
  let db: ChainDB;
  let headerSync: HeaderSync;
  let chainState: ChainStateManager;
  let blockSync: BlockSync;
  let server: RPCServer;
  let blocks: Block[]; // blocks[h] = active block at height h
  let t: number;

  function rpc(method: string, params: unknown[]) {
    const methods = (server as any).methods as Map<string, (p: unknown[]) => Promise<unknown>>;
    return methods.get(method)!(params);
  }

  async function tips(): Promise<Map<string, Tip>> {
    const list = (await rpc("getchaintips", [])) as Tip[];
    return new Map(list.map((x) => [x.hash, x]));
  }

  function wire() {
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
  }

  /** Stop everything and boot again from the same datadir. */
  async function restart() {
    await blockSync.stop();
    await db.close();
    db = new ChainDB(dbPath);
    await db.open();
    headerSync = new HeaderSync(db, REGTEST);
    await headerSync.loadFromDB();
    chainState = new ChainStateManager(db, REGTEST);
    await chainState.load();
    wire();
  }

  async function submit(b: Block): Promise<unknown> {
    return rpc("submitblock", [serializeBlock(b).toString("hex")]);
  }

  async function extend(n: number) {
    for (let i = 0; i < n; i++) {
      const h = blocks.length;
      t += 600;
      const b = mine(hashOf(blocks[h - 1]), t, h, 0x10);
      expect(await submit(b)).toBeNull();
      blocks.push(b);
    }
  }

  beforeEach(async () => {
    dbPath = await mkdtemp(join(tmpdir(), "hotbuns-getchaintips-"));
    db = new ChainDB(dbPath);
    await db.open();
    headerSync = new HeaderSync(db, REGTEST);
    headerSync.initGenesis();
    chainState = new ChainStateManager(db, REGTEST);
    wire();
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

  test("control: a linear chain has only the active tip", async () => {
    const all = await tips();
    expect([...all.values()]).toEqual([
      { height: 5, hash: display(hashOf(blocks[5])), branchlen: 0, status: "active" },
    ]);
  }, 120_000);

  test("an invalidated tip is listed invalid, branchlen 1", async () => {
    await rpc("invalidateblock", [display(hashOf(blocks[5]))]);
    const all = await tips();
    expect(all.get(display(hashOf(blocks[4])))).toEqual({
      height: 4, hash: display(hashOf(blocks[4])), branchlen: 0, status: "active",
    });
    expect(all.get(display(hashOf(blocks[5])))).toEqual({
      height: 5, hash: display(hashOf(blocks[5])), branchlen: 1, status: "invalid",
    });
    expect(all.size).toBe(2);
  }, 120_000);

  test("an invalidated branch reports its leaf, not the invalidated block", async () => {
    await rpc("invalidateblock", [display(hashOf(blocks[4]))]);
    const all = await tips();
    expect(all.has(display(hashOf(blocks[4])))).toBe(false);
    expect(all.get(display(hashOf(blocks[5])))).toEqual({
      height: 5, hash: display(hashOf(blocks[5])), branchlen: 2, status: "invalid",
    });
    // reconsiderblock: back to one active tip.
    await rpc("reconsiderblock", [display(hashOf(blocks[4]))]);
    expect([...(await tips()).keys()]).toEqual([display(hashOf(blocks[5]))]);
  }, 120_000);

  test("a stored equal-work sibling block is valid-headers", async () => {
    const sib = mine(hashOf(blocks[4]), t + 1, 5, 0x21);
    await submit(sib);
    expect(chainState.getBestBlock().hash.equals(hashOf(blocks[5]))).toBe(true);
    expect((await tips()).get(display(hashOf(sib)))).toEqual({
      height: 5, hash: display(hashOf(sib)), branchlen: 1, status: "valid-headers",
    });
  }, 120_000);

  test("a header-only fork is headers-only", async () => {
    const sib = mine(hashOf(blocks[3]), t + 1, 4, 0x22);
    expect(await rpc("submitheader", [serializeBlockHeader(sib.header).toString("hex")])).toBeNull();
    expect((await tips()).get(display(hashOf(sib)))).toEqual({
      height: 4, hash: display(hashOf(sib)), branchlen: 1, status: "headers-only",
    });
  }, 120_000);

  test("a reorged-away block is valid-fork", async () => {
    const s5 = mine(hashOf(blocks[4]), t + 1, 5, 0x23);
    const s6 = mine(hashOf(s5), t + 2, 6, 0x23);
    await submit(s5);
    expect(await submit(s6)).toBeNull();
    expect(chainState.getBestBlock().hash.equals(hashOf(s6))).toBe(true);
    const all = await tips();
    expect(all.get(display(hashOf(s6)))!.status).toBe("active");
    expect(all.get(display(hashOf(blocks[5])))).toEqual({
      height: 5, hash: display(hashOf(blocks[5])), branchlen: 1, status: "valid-fork",
    });
  }, 120_000);

  test("a block that failed ConnectBlock on the tip is listed invalid", async () => {
    const bad = mine(hashOf(blocks[5]), t + 1, 6, 0x24, SUBSIDY + 1n);
    expect(await submit(bad)).toBe("bad-cb-amount");
    expect(chainState.getBestBlock().hash.equals(hashOf(blocks[5]))).toBe(true);
    expect((await tips()).get(display(hashOf(bad)))).toEqual({
      height: 6, hash: display(hashOf(bad)), branchlen: 1, status: "invalid",
    });
  }, 120_000);

  test("statuses and branchlen survive a restart", async () => {
    const s5 = mine(hashOf(blocks[4]), t + 1, 5, 0x25);
    const s6 = mine(hashOf(s5), t + 2, 6, 0x25);
    await submit(s5);
    await submit(s6); // reorg: blocks[5] becomes a valid-fork tip
    const hdr = mine(hashOf(blocks[2]), t + 3, 3, 0x26);
    await rpc("submitheader", [serializeBlockHeader(hdr.header).toString("hex")]);
    await rpc("invalidateblock", [display(hashOf(s6))]);
    const before = await tips();
    expect(before.get(display(hashOf(s6)))!.status).toBe("invalid");
    expect(before.get(display(hashOf(blocks[5])))!.status).toBe("valid-fork");
    expect(before.get(display(hashOf(hdr)))!.status).toBe("headers-only");

    await restart();
    const after = await tips();
    expect(after).toEqual(before);
  }, 120_000);
});
