/**
 * Regtest test: getblockchaininfo.softforks and getdeploymentinfo.deployments
 * must agree on every shared field (type, active, height).
 *
 * Both RPCs now project from the same buildDeploymentState() helper, so any
 * divergence here means the helper is broken or a new deployment was added to
 * only one RPC.
 */

import { describe, test, expect, beforeEach, afterEach } from "bun:test";
import { RPCServer, RPCServerConfig, RPCServerDeps } from "../rpc/server";
import { REGTEST } from "../consensus/params";
import { ChainStateManager } from "../chain/state";
import { Mempool } from "../mempool/mempool";
import { FeeEstimator } from "../fees/estimator";
import { createTestDB } from "../test/helpers";
import type { ChainDB } from "../storage/database";

class MockPeerManager {
  getConnectedPeers() { return []; }
  getPeerCount() { return 0; }
  broadcast() {}
}

class MockHeaderSync {
  getBestHeader() { return null; }
  getHeader() { return null; }
  async processHeaders() { return { success: true, requestMore: false, powValidatedHeaders: [] }; }
  getMedianTimePast() { return 0; }
}

describe("softfork bridge: getblockchaininfo.softforks === getdeploymentinfo.deployments", () => {
  let db: ChainDB;
  let cleanup: () => Promise<void>;
  let chainState: ChainStateManager;
  let rpcServer: RPCServer;

  beforeEach(async () => {
    const testDB = await createTestDB();
    db = testDB.db;
    cleanup = testDB.cleanup;

    chainState = new ChainStateManager(db, REGTEST);
    await chainState.load();
    const mempool = new Mempool(chainState.getUTXOManager(), REGTEST);

    const config: RPCServerConfig = {
      port: 18443,
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
    };

    rpcServer = new RPCServer(config, deps);
  });

  afterEach(async () => {
    if (cleanup) await cleanup();
  });

  test("shared fields (type, active, height) match across both RPCs at genesis", async () => {
    const chainInfo = await (rpcServer as any).getBlockchainInfo() as Record<string, unknown>;
    const deployInfo = await (rpcServer as any).getDeploymentInfo([]) as {
      hash: string;
      height: number;
      deployments: Record<string, { type: string; active: boolean; height: number; min_activation_height: number }>;
    };

    const softforks = chainInfo.softforks as Record<string, { type: string; active: boolean; height: number }>;
    const deployments = deployInfo.deployments;

    // The two RPCs must cover the same set of softfork names.
    const sfNames = new Set(Object.keys(softforks));
    const depNames = new Set(Object.keys(deployments));
    expect(sfNames).toEqual(depNames);

    // For every named deployment the shared fields must agree exactly.
    for (const name of sfNames) {
      const sf = softforks[name];
      const dep = deployments[name];

      expect(sf.type).toBe(dep.type);
      expect(sf.active).toBe(dep.active);
      expect(sf.height).toBe(dep.height);
    }
  });

  test("shared fields match after generating blocks (height > 0)", async () => {
    // Mine several regtest blocks so we cross some activation thresholds.
    const address = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";
    await (rpcServer as any).generateToAddress([10, address]);

    const chainInfo = await (rpcServer as any).getBlockchainInfo() as Record<string, unknown>;
    const deployInfo = await (rpcServer as any).getDeploymentInfo([]) as {
      hash: string;
      height: number;
      deployments: Record<string, { type: string; active: boolean; height: number; min_activation_height: number }>;
    };

    const softforks = chainInfo.softforks as Record<string, { type: string; active: boolean; height: number }>;
    const deployments = deployInfo.deployments;

    const sfNames = new Set(Object.keys(softforks));
    const depNames = new Set(Object.keys(deployments));
    expect(sfNames).toEqual(depNames);

    for (const name of sfNames) {
      const sf = softforks[name];
      const dep = deployments[name];

      expect(sf.type).toBe(dep.type);
      expect(sf.active).toBe(dep.active);
      expect(sf.height).toBe(dep.height);
    }
  });

  test("getdeploymentinfo emits min_activation_height for every deployment", async () => {
    const deployInfo = await (rpcServer as any).getDeploymentInfo([]) as {
      deployments: Record<string, Record<string, unknown>>;
    };

    for (const [name, entry] of Object.entries(deployInfo.deployments)) {
      expect(
        typeof entry.min_activation_height,
        `${name}.min_activation_height should be a number`
      ).toBe("number");
    }
  });

  test("getblockchaininfo.softforks does NOT emit min_activation_height", async () => {
    const chainInfo = await (rpcServer as any).getBlockchainInfo() as Record<string, unknown>;
    const softforks = chainInfo.softforks as Record<string, Record<string, unknown>>;

    for (const [name, entry] of Object.entries(softforks)) {
      expect(
        "min_activation_height" in entry,
        `${name} should not have min_activation_height in getblockchaininfo`
      ).toBe(false);
    }
  });

  test("getdeploymentinfo hash matches getblockchaininfo bestblockhash", async () => {
    const chainInfo = await (rpcServer as any).getBlockchainInfo() as Record<string, unknown>;
    const deployInfo = await (rpcServer as any).getDeploymentInfo([]) as Record<string, unknown>;

    expect(deployInfo.hash).toBe(chainInfo.bestblockhash);
  });
});
