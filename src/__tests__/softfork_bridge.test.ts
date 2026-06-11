/**
 * Regtest test: getdeploymentinfo.deployments is the canonical softfork-state
 * surface, and getblockchaininfo NO LONGER carries `softforks`.
 *
 * Core v31.99 dropped `softforks` from getblockchaininfo (it moved entirely to
 * getdeploymentinfo). hotbuns matches: getblockchaininfo must not emit
 * `softforks`, and getdeploymentinfo remains the source of truth for per-fork
 * type/active/height (+ min_activation_height).
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

describe("softfork surface: getdeploymentinfo.deployments (getblockchaininfo.softforks dropped in v31.99)", () => {
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

  test("getblockchaininfo does NOT carry softforks (v31.99 dropped it)", async () => {
    const chainInfo = await (rpcServer as any).getBlockchainInfo() as Record<string, unknown>;
    expect("softforks" in chainInfo).toBe(false);
  });

  test("getdeploymentinfo.deployments exposes type/active/height at genesis", async () => {
    const deployInfo = await (rpcServer as any).getDeploymentInfo([]) as {
      hash: string;
      height: number;
      deployments: Record<string, { type: string; active: boolean; height: number; min_activation_height: number }>;
    };

    const deployments = deployInfo.deployments;
    expect(Object.keys(deployments).length).toBeGreaterThan(0);
    for (const [name, dep] of Object.entries(deployments)) {
      expect(typeof dep.type, `${name}.type`).toBe("string");
      expect(typeof dep.active, `${name}.active`).toBe("boolean");
      expect(typeof dep.height, `${name}.height`).toBe("number");
    }
  });

  test("getdeploymentinfo.deployments stays consistent after generating blocks (height > 0)", async () => {
    // Mine several regtest blocks so we cross some activation thresholds.
    const address = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";
    await (rpcServer as any).generateToAddress([10, address]);

    const deployInfo = await (rpcServer as any).getDeploymentInfo([]) as {
      deployments: Record<string, { type: string; active: boolean; height: number; min_activation_height: number }>;
    };

    for (const [name, dep] of Object.entries(deployInfo.deployments)) {
      expect(typeof dep.type, `${name}.type`).toBe("string");
      expect(typeof dep.active, `${name}.active`).toBe("boolean");
      expect(typeof dep.height, `${name}.height`).toBe("number");
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

  test("getdeploymentinfo hash matches getblockchaininfo bestblockhash", async () => {
    const chainInfo = await (rpcServer as any).getBlockchainInfo() as Record<string, unknown>;
    const deployInfo = await (rpcServer as any).getDeploymentInfo([]) as Record<string, unknown>;

    expect(deployInfo.hash).toBe(chainInfo.bestblockhash);
  });
});
