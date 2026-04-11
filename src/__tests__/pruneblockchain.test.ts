/**
 * Tests for the pruneblockchain RPC method.
 *
 * Tests cover:
 * - Error when pruning is not enabled
 * - Error for invalid height parameters
 * - Successful pruning returns first unpruned height
 * - Integration with getblockchaininfo
 */

import { describe, it, expect, beforeEach, afterEach, mock } from "bun:test";
import { mkdir, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { RPCServer, RPCServerConfig, RPCServerDeps, RPCErrorCodes } from "../rpc/server.js";
import { ChainDB } from "../storage/database.js";
import { PruneManager, MIN_PRUNE_TARGET } from "../storage/pruning.js";
import { MAINNET } from "../consensus/params.js";

// Mock the dependencies
const createMockChainState = (height: number) => ({
  getBestBlock: () => ({
    height,
    hash: Buffer.alloc(32, 0),
    chainWork: 1000n,
  }),
  getUTXOManager: () => ({}),
});

const createMockMempool = () => ({
  getInfo: () => ({ size: 0, bytes: 0, minFeeRate: 0 }),
  getAllTxids: () => [],
  hasTransaction: () => false,
  getTransaction: () => null,
  addTransaction: async () => ({ accepted: false }),
});

const createMockPeerManager = () => ({
  getConnectedPeers: () => [],
  broadcast: () => {},
  listBanned: () => [],
  banAddress: () => {},
  unbanAddress: () => false,
  clearBanned: () => {},
});

const createMockFeeEstimator = () => ({
  estimateSmartFee: () => ({ feeRate: 1, blocks: 1 }),
});

const createMockHeaderSync = () => ({
  getBestHeader: () => null,
  getHeader: () => null,
  getMedianTimePast: () => 0,
});

describe("pruneblockchain RPC", () => {
  let dataDir: string;
  let db: ChainDB;
  let rpcServer: RPCServer;
  let pruneManager: PruneManager | undefined;

  beforeEach(async () => {
    dataDir = join(tmpdir(), `hotbuns-prune-rpc-test-${Date.now()}-${Math.random().toString(36).slice(2)}`);
    await mkdir(join(dataDir, "blocks"), { recursive: true });

    db = new ChainDB(join(dataDir, "blocks.db"));
    await db.open();
  });

  afterEach(async () => {
    rpcServer?.stop();
    await db.close();
    try {
      await rm(dataDir, { recursive: true, force: true });
    } catch {
      // Ignore cleanup errors
    }
  });

  const createRPCServer = async (pruneTarget: number, chainHeight: number) => {
    if (pruneTarget > 0) {
      pruneManager = new PruneManager(db, dataDir, pruneTarget);
      await pruneManager.init();
    } else {
      pruneManager = undefined;
    }

    const config: RPCServerConfig = {
      port: 0, // Don't actually start server
      host: "127.0.0.1",
      noAuth: true,
    };

    const deps: RPCServerDeps = {
      chainState: createMockChainState(chainHeight) as any,
      mempool: createMockMempool() as any,
      peerManager: createMockPeerManager() as any,
      feeEstimator: createMockFeeEstimator() as any,
      headerSync: createMockHeaderSync() as any,
      db,
      params: MAINNET,
      pruneManager,
    };

    rpcServer = new RPCServer(config, deps);
    return rpcServer;
  };

  // Helper to call RPC method directly (instead of going through HTTP)
  const callRPC = async (
    server: RPCServer,
    method: string,
    params: unknown[] = []
  ): Promise<unknown> => {
    // Access the methods map through the server
    const methods = (server as any).methods as Map<
      string,
      (params: unknown[]) => Promise<unknown>
    >;
    const handler = methods.get(method);
    if (!handler) {
      throw { code: RPCErrorCodes.METHOD_NOT_FOUND, message: `Method '${method}' not found` };
    }
    return handler(params);
  };

  describe("error cases", () => {
    it("should error when pruning is not enabled", async () => {
      const server = await createRPCServer(0, 1000);

      try {
        await callRPC(server, "pruneblockchain", [500]);
        expect(true).toBe(false); // Should not reach here
      } catch (err: any) {
        expect(err.code).toBe(RPCErrorCodes.MISC_ERROR);
        expect(err.message).toContain("not in prune mode");
      }
    });

    it("should error for non-integer height", async () => {
      const server = await createRPCServer(MIN_PRUNE_TARGET, 1000);

      try {
        await callRPC(server, "pruneblockchain", ["not-a-number"]);
        expect(true).toBe(false);
      } catch (err: any) {
        expect(err.code).toBe(RPCErrorCodes.INVALID_PARAMS);
        expect(err.message).toContain("integer");
      }
    });

    it("should error for negative height", async () => {
      const server = await createRPCServer(MIN_PRUNE_TARGET, 1000);

      try {
        await callRPC(server, "pruneblockchain", [-1]);
        expect(true).toBe(false);
      } catch (err: any) {
        expect(err.code).toBe(RPCErrorCodes.INVALID_PARAMS);
        expect(err.message).toContain("Negative");
      }
    });

    it("should error for height beyond chain tip", async () => {
      const server = await createRPCServer(MIN_PRUNE_TARGET, 1000);

      try {
        await callRPC(server, "pruneblockchain", [2000]);
        expect(true).toBe(false);
      } catch (err: any) {
        expect(err.code).toBe(RPCErrorCodes.INVALID_PARAMS);
        expect(err.message).toContain("shorter than the attempted prune height");
      }
    });
  });

  describe("success cases", () => {
    it("should return first unpruned height", async () => {
      const server = await createRPCServer(MIN_PRUNE_TARGET, 1000);

      // With no files to prune, should return 0 (or whatever getFirstUnprunedHeight returns)
      const result = await callRPC(server, "pruneblockchain", [500]);
      expect(typeof result).toBe("number");
    });
  });

  describe("getblockchaininfo integration", () => {
    it("should show pruned=false when pruning is disabled", async () => {
      const server = await createRPCServer(0, 1000);

      const info = (await callRPC(server, "getblockchaininfo")) as Record<string, unknown>;
      expect(info.pruned).toBe(false);
      expect(info.automatic_pruning).toBeUndefined();
      expect(info.prune_target_size).toBeUndefined();
    });

    it("should show automatic_pruning=true when pruning is enabled", async () => {
      const server = await createRPCServer(MIN_PRUNE_TARGET, 1000);

      const info = (await callRPC(server, "getblockchaininfo")) as Record<string, unknown>;
      expect(info.automatic_pruning).toBe(true);
      expect(info.prune_target_size).toBe(MIN_PRUNE_TARGET);
    });

    it("should show pruneheight after pruning has occurred", async () => {
      // Set up pruned state in database
      await db.putPruneState(true, MIN_PRUNE_TARGET);

      const server = await createRPCServer(MIN_PRUNE_TARGET, 1000);

      const info = (await callRPC(server, "getblockchaininfo")) as Record<string, unknown>;
      expect(info.pruned).toBe(true);
      expect(info.pruneheight).toBeDefined();
    });
  });
});
