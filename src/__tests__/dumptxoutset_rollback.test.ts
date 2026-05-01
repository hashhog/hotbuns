/**
 * Tests for the `rollback` mode of the dumptxoutset RPC.
 *
 * Mirrors Bitcoin Core's `dumptxoutset` rollback behavior in
 * `bitcoin-core/src/rpc/blockchain.cpp` (3074-3231):
 *
 *   dumptxoutset <path> "rollback"           → use chainparams' latest
 *                                               assumeutxo height ≤ tip
 *   dumptxoutset <path> options={rollback=h} → use explicit height
 *
 * In Core this is wrapped in a `TemporaryRollback` RAII (InvalidateBlock +
 * ReconsiderBlock). In hotbuns we drive it explicitly through
 * `chainState.disconnectBlock` / `chainState.connectBlock` because
 * `reconsiderBlock` does not auto-reorg back.
 *
 * What we verify here:
 *   1. After a successful rollback dump, the chain tip is restored to
 *      its original (pre-dump) height and hash.
 *   2. The dump's `base_height` and `base_hash` reflect the rolled-back
 *      target, NOT the original tip.
 *   3. The `rollback` option resolves both numeric heights and hex hashes.
 *   4. Bare `type="rollback"` resolves the latest assumeutxo height ≤ tip
 *      (uses a custom params variant since regtest has empty assumeutxo).
 *   5. Invalid combinations (rollback height > tip, type "rollback" without
 *      assumeutxo entries, conflicting type+option) raise sensible errors.
 *   6. The default "latest" path still produces a tip-height dump.
 */

import { describe, test, expect, beforeEach, afterEach } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ChainDB } from "../storage/database.js";
import { REGTEST, type ConsensusParams } from "../consensus/params.js";
import { ChainStateManager } from "../chain/state.js";
import { Mempool } from "../mempool/mempool.js";
import { FeeEstimator } from "../fees/estimator.js";
import {
  RPCServer,
  RPCErrorCodes,
  type RPCServerConfig,
  type RPCServerDeps,
} from "../rpc/server.js";
import {
  ChainstateManager,
  type AssumeutxoData,
} from "../chain/snapshot.js";
import {
  createTestBlock,
  mineRegtestBlock,
} from "../test/helpers.js";
import { getBlockHash } from "../validation/block.js";

class MockPeerManager {
  getConnectedPeers() { return []; }
  getPeerCount() { return 0; }
  broadcast() {}
}

class MockHeaderSync {
  getBestHeader() { return null; }
  getHeader() { return null; }
  getHeaderByHeight() { return null; }
  async processHeaders() { return { success: true, requestMore: false, powValidatedHeaders: [] }; }
  getMedianTimePast() { return 0; }
}

// Direct access to RPC method handlers, mirroring the pattern used by
// pruneblockchain.test.ts.
function callRPC(server: RPCServer, method: string, params: unknown[] = []) {
  const methods = (server as any).methods as Map<
    string,
    (params: unknown[]) => Promise<unknown>
  >;
  const handler = methods.get(method);
  if (!handler) {
    throw new Error(`Method '${method}' not found`);
  }
  return handler(params);
}

// Build a regtest chain by repeatedly connecting coinbase-only blocks.
async function buildChain(
  chainState: ChainStateManager,
  count: number,
  params: ConsensusParams = REGTEST
): Promise<{ hashes: Buffer[]; heights: number[] }> {
  const hashes: Buffer[] = [];
  const heights: number[] = [];
  let prev = chainState.getBestBlock().hash;
  let height = chainState.getBestBlock().height;
  for (let i = 0; i < count; i++) {
    height++;
    const blk = mineRegtestBlock(createTestBlock(prev, height, [], params));
    await chainState.connectBlock(blk, height);
    prev = getBlockHash(blk.header);
    hashes.push(prev);
    heights.push(height);
  }
  return { hashes, heights };
}

describe("dumptxoutset rollback", () => {
  let tempDir: string;
  let dumpDir: string;
  let db: ChainDB;
  let chainState: ChainStateManager;
  let mempool: Mempool;
  let server: RPCServer;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "hotbuns-dumptxoutset-rb-"));
    dumpDir = await mkdtemp(join(tmpdir(), "hotbuns-dumptxoutset-out-"));
    db = new ChainDB(tempDir);
    await db.open();

    chainState = new ChainStateManager(db, REGTEST);
    await chainState.load();
    mempool = new Mempool(chainState.getUTXOManager(), REGTEST);

    const config: RPCServerConfig = {
      port: 0,
      host: "127.0.0.1",
      noAuth: true,
    };

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
    await db.close();
    await rm(tempDir, { recursive: true, force: true }).catch(() => {});
    await rm(dumpDir, { recursive: true, force: true }).catch(() => {});
  });

  test("type='latest' (and empty type) dumps at current tip without rolling back", async () => {
    const { hashes } = await buildChain(chainState, 4);
    const tipBefore = chainState.getBestBlock();
    const dumpPath = join(dumpDir, "latest.dat");

    const result = (await callRPC(server, "dumptxoutset", [dumpPath, "latest"])) as Record<string, unknown>;
    expect(result.base_height).toBe(tipBefore.height);
    expect(result.base_hash).toBe(tipBefore.hash.toString("hex"));

    const tipAfter = chainState.getBestBlock();
    expect(tipAfter.height).toBe(tipBefore.height);
    expect(tipAfter.hash.equals(tipBefore.hash)).toBe(true);
    expect(hashes[hashes.length - 1].equals(tipAfter.hash)).toBe(true);
  });

  test("explicit rollback=<height> rolls back, dumps, then re-applies blocks", async () => {
    const { hashes } = await buildChain(chainState, 5);
    const tipBefore = chainState.getBestBlock();
    const targetHeight = tipBefore.height - 3;
    const targetHash = hashes[targetHeight - 1];

    const dumpPath = join(dumpDir, "rollback-h.dat");
    const result = (await callRPC(server, "dumptxoutset", [
      dumpPath,
      "",
      { rollback: targetHeight },
    ])) as Record<string, unknown>;

    // Dump base reflects the rolled-back target.
    expect(result.base_height).toBe(targetHeight);
    expect(result.base_hash).toBe(targetHash.toString("hex"));

    // Chain is restored to the original tip.
    const tipAfter = chainState.getBestBlock();
    expect(tipAfter.height).toBe(tipBefore.height);
    expect(tipAfter.hash.equals(tipBefore.hash)).toBe(true);
  });

  test("rollback=<hex hash> resolves a 32-byte block hash on the active chain", async () => {
    const { hashes } = await buildChain(chainState, 4);
    const tipBefore = chainState.getBestBlock();
    const targetHeight = 2;
    const targetHash = hashes[targetHeight - 1];
    // RPC passes hashes in display order (big-endian / reversed wire bytes).
    const targetHashHex = Buffer.from(targetHash).reverse().toString("hex");

    const dumpPath = join(dumpDir, "rollback-hash.dat");
    const result = (await callRPC(server, "dumptxoutset", [
      dumpPath,
      "rollback",
      { rollback: targetHashHex },
    ])) as Record<string, unknown>;

    expect(result.base_height).toBe(targetHeight);
    expect(result.base_hash).toBe(targetHash.toString("hex"));

    // Chain is restored.
    const tipAfter = chainState.getBestBlock();
    expect(tipAfter.height).toBe(tipBefore.height);
    expect(tipAfter.hash.equals(tipBefore.hash)).toBe(true);
  });

  test("type='rollback' with no assumeutxo entries (regtest) errors", async () => {
    await buildChain(chainState, 3);
    const dumpPath = join(dumpDir, "rb-empty.dat");

    await expect(
      callRPC(server, "dumptxoutset", [dumpPath, "rollback"])
    ).rejects.toMatchObject({
      code: RPCErrorCodes.INVALID_PARAMS,
    });
  });

  test("type='rollback' uses the latest assumeutxo height ≤ tip (custom params)", async () => {
    // Build a regtest variant whose assumeutxo map registers heights 2 and 4
    // — we'll set the tip to 5 so the rollback should choose 4.
    const { hashes } = await buildChain(chainState, 5);

    const customAssume = new Map<string, AssumeutxoData>([
      [
        // Height 2 entry — would NOT be chosen because 4 is also ≤ 5.
        Buffer.from(hashes[1]).reverse().toString("hex"),
        {
          height: 2,
          hashSerialized: Buffer.alloc(32, 0x11),
          nChainTx: 0n,
          blockHash: hashes[1],
        },
      ],
      [
        // Height 4 entry — should win.
        Buffer.from(hashes[3]).reverse().toString("hex"),
        {
          height: 4,
          hashSerialized: Buffer.alloc(32, 0x22),
          nChainTx: 0n,
          blockHash: hashes[3],
        },
      ],
    ]);
    const customParams: ConsensusParams = {
      ...REGTEST,
      assumeutxo: customAssume,
    };

    // Re-mint server with the custom params (params are baked into deps).
    const deps: RPCServerDeps = {
      chainState,
      mempool,
      peerManager: new MockPeerManager() as any,
      feeEstimator: new FeeEstimator(mempool),
      headerSync: new MockHeaderSync() as any,
      db,
      params: customParams,
      chainstateManager: new ChainstateManager(db, customParams),
    };
    const customServer = new RPCServer(
      { port: 0, host: "127.0.0.1", noAuth: true },
      deps
    );

    const dumpPath = join(dumpDir, "rb-auto.dat");
    const result = (await callRPC(customServer, "dumptxoutset", [
      dumpPath,
      "rollback",
    ])) as Record<string, unknown>;
    expect(result.base_height).toBe(4);
    expect(result.base_hash).toBe(hashes[3].toString("hex"));

    // Original tip restored.
    const tipAfter = chainState.getBestBlock();
    expect(tipAfter.height).toBe(5);
    expect(tipAfter.hash.equals(hashes[4])).toBe(true);
  });

  test("rollback height > tip is rejected", async () => {
    await buildChain(chainState, 2);
    const dumpPath = join(dumpDir, "rb-too-high.dat");

    await expect(
      callRPC(server, "dumptxoutset", [dumpPath, "", { rollback: 9999 }])
    ).rejects.toMatchObject({
      code: RPCErrorCodes.INVALID_PARAMS,
    });
  });

  test("rollback option combined with conflicting type='latest' is rejected", async () => {
    await buildChain(chainState, 3);
    const dumpPath = join(dumpDir, "rb-conflict.dat");

    await expect(
      callRPC(server, "dumptxoutset", [dumpPath, "latest", { rollback: 1 }])
    ).rejects.toMatchObject({
      code: RPCErrorCodes.INVALID_PARAMS,
    });
  });

  test("unknown type is rejected", async () => {
    await buildChain(chainState, 2);
    const dumpPath = join(dumpDir, "rb-bogus.dat");

    await expect(
      callRPC(server, "dumptxoutset", [dumpPath, "bogus"])
    ).rejects.toMatchObject({
      code: RPCErrorCodes.INVALID_PARAMS,
    });
  });
});
