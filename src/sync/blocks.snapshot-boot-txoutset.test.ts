/**
 * Snapshot-boot gettxoutsetinfo at the loaded base (receipt 2026-09-16).
 *
 * After `--load-snapshot` / `loadtxoutset` the campaign runner calls
 * gettxoutsetinfo before any window block connects. At rung 290000 that
 * walk timed out (900s) and the harness recorded NO-ORACLE-SURFACE with
 * utxo_hash="-1" (empty RPC → python default height -1).
 *
 * The load already folded HASH_SERIALIZED + totals. gettxoutsetinfo at
 * that same tip must report height == base and bestblock == base hash
 * without a second coins-DB walk.
 *
 * Control: this file. Negative: after load, the coins iterator throws;
 * the RPC still returns the snapshot-base surface (cache hit). Reverting
 * the cache seed in loadtxoutset / CLI fails that assertion.
 */

import { describe, test, expect, beforeEach, afterEach } from "bun:test";
import { mkdtemp, rm, readdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, dirname, basename } from "node:path";
import { ChainDB } from "../storage/database.js";
import { REGTEST } from "../consensus/params.js";
import { ChainStateManager } from "../chain/state.js";
import { Mempool } from "../mempool/mempool.js";
import { FeeEstimator } from "../fees/estimator.js";
import {
  RPCServer,
  type RPCServerConfig,
  type RPCServerDeps,
} from "../rpc/server.js";
import {
  ChainstateManager,
  registerRegtestAssumeutxo,
  clearRegtestAssumeutxo,
} from "../chain/snapshot.js";
import { createTestBlock, mineRegtestBlock } from "../test/helpers.js";
import { getBlockHash } from "../validation/block.js";

const REGTEST_BUILTIN_ASSUMEUTXO = new Map(REGTEST.assumeutxo ?? []);

class MockPeerManager {
  getConnectedPeers() {
    return [];
  }
  getPeerCount() {
    return 0;
  }
  broadcast() {}
}

class MockHeaderSync {
  getBestHeader() {
    return null;
  }
  getHeader() {
    return undefined;
  }
  getHeaderByHeight() {
    return null;
  }
  async processHeaders() {
    return { success: true, requestMore: false, powValidatedHeaders: [] };
  }
  getMedianTimePast() {
    return 0;
  }
  async adoptChainTipAsBestHeader() {}
}

function callRPC(server: RPCServer, method: string, params: unknown[] = []) {
  const methods = (server as any).methods as Map<
    string,
    (params: unknown[]) => Promise<unknown>
  >;
  const handler = methods.get(method);
  if (!handler) throw new Error(`Method '${method}' not found`);
  return handler(params);
}

async function buildChain(
  chainState: ChainStateManager,
  count: number,
): Promise<{ hashes: Buffer[]; tipHash: Buffer; tipHeight: number }> {
  const hashes: Buffer[] = [];
  let prev = chainState.getBestBlock().hash;
  let height = chainState.getBestBlock().height;
  for (let i = 0; i < count; i++) {
    height++;
    const blk = mineRegtestBlock(createTestBlock(prev, height, [], REGTEST));
    await chainState.connectBlock(blk, height);
    prev = getBlockHash(blk.header);
    hashes.push(prev);
  }
  return { hashes, tipHash: prev, tipHeight: height };
}

describe("snapshot-boot gettxoutsetinfo at the loaded base", () => {
  let tempDir: string;
  let dumpDir: string;
  let db: ChainDB;
  let chainState: ChainStateManager;
  let mempool: Mempool;
  let server: RPCServer;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "hotbuns-snap-txoutset-"));
    dumpDir = await mkdtemp(join(tmpdir(), "hotbuns-snap-txoutset-out-"));
    db = new ChainDB(tempDir);
    await db.open();

    chainState = new ChainStateManager(db, REGTEST);
    await chainState.load();
    mempool = new Mempool(chainState.getUTXOManager(), REGTEST);

    const config: RPCServerConfig = { port: 0, host: "127.0.0.1", noAuth: true };
    const deps: RPCServerDeps = {
      chainState,
      mempool,
      peerManager: new MockPeerManager() as any,
      feeEstimator: new FeeEstimator(mempool),
      headerSync: new MockHeaderSync() as any,
      db,
      params: REGTEST,
      chainstateManager: new ChainstateManager(db, REGTEST),
    };
    server = new RPCServer(config, deps);
  });

  afterEach(async () => {
    clearRegtestAssumeutxo(REGTEST);
    for (const [key, au] of REGTEST_BUILTIN_ASSUMEUTXO) {
      registerRegtestAssumeutxo(REGTEST, au);
      void key;
    }
    await db.close().catch(() => {});
    await rm(tempDir, { recursive: true, force: true }).catch(() => {});
    await rm(dumpDir, { recursive: true, force: true }).catch(() => {});
    const parent = dirname(tempDir);
    const prefix = `${basename(tempDir)}-bgvalidate`;
    const siblings = await readdir(parent).catch(() => [] as string[]);
    await Promise.all(
      siblings
        .filter((name) => name.startsWith(prefix))
        .map((name) => rm(join(parent, name), { recursive: true, force: true }).catch(() => {})),
    );
  });

  test("loadtxoutset then gettxoutsetinfo reports height==base and bestblock==base hash", async () => {
    const n = 4;
    const { hashes } = await buildChain(chainState, n);
    const base = chainState.getBestBlock();
    expect(base.hash.equals(hashes[n - 1])).toBe(true);

    const snapPath = join(dumpDir, "base.dat");
    const dump = (await callRPC(server, "dumptxoutset", [snapPath, "latest"])) as Record<
      string,
      unknown
    >;
    const committedHashHex = dump.txoutset_hash as string;
    const committedHash = Buffer.from(committedHashHex, "hex").reverse();
    const baseHex = Buffer.from(base.hash).reverse().toString("hex");

    registerRegtestAssumeutxo(REGTEST, {
      height: base.height,
      hashSerialized: committedHash,
      nChainTx: BigInt(n + 1),
      blockHash: base.hash,
    });

    const loaded = (await callRPC(server, "loadtxoutset", [snapPath])) as Record<
      string,
      unknown
    >;
    expect(loaded.base_height).toBe(base.height);

    const info = (await callRPC(server, "gettxoutsetinfo", [
      "hash_serialized_3",
    ])) as Record<string, unknown>;

    expect(info.height).toBe(base.height);
    expect(typeof info.height).toBe("number");
    expect(Number.isInteger(info.height)).toBe(true);
    expect(info.bestblock).toBe(baseHex);
    expect(typeof info.hash_serialized_3).toBe("string");
    expect(info.hash_serialized_3).toBe(committedHashHex);
    expect((info.hash_serialized_3 as string).length).toBe(64);
  });

  test("snapshot-base gettxoutsetinfo does not walk the coins DB (iterator throw is a miss)", async () => {
    const n = 4;
    await buildChain(chainState, n);
    const base = chainState.getBestBlock();

    const snapPath = join(dumpDir, "nowalk.dat");
    const dump = (await callRPC(server, "dumptxoutset", [snapPath, "latest"])) as Record<
      string,
      unknown
    >;
    const committedHash = Buffer.from(dump.txoutset_hash as string, "hex").reverse();
    const baseHex = Buffer.from(base.hash).reverse().toString("hex");

    registerRegtestAssumeutxo(REGTEST, {
      height: base.height,
      hashSerialized: committedHash,
      nChainTx: BigInt(n + 1),
      blockHash: base.hash,
    });

    await callRPC(server, "loadtxoutset", [snapPath]);

    const inner = (db as any).db;
    const originalIterator = inner.iterator.bind(inner);
    inner.iterator = () => {
      throw new Error("coins walk must not run at snapshot base");
    };
    try {
      const info = (await callRPC(server, "gettxoutsetinfo", [
        "hash_serialized_3",
      ])) as Record<string, unknown>;
      expect(info.height).toBe(base.height);
      expect(info.bestblock).toBe(baseHex);
      expect(info.hash_serialized_3).toBe(dump.txoutset_hash);
    } finally {
      inner.iterator = originalIterator;
    }
  });
});
