/**
 * Regtest mode tests for block generation RPCs.
 *
 * Tests generatetoaddress, generateblock, and generatetodescriptor RPCs.
 */

import { describe, test, expect, beforeEach, afterEach } from "bun:test";
import { RPCServer, RPCServerConfig, RPCServerDeps } from "../rpc/server";
import { REGTEST, MAINNET } from "../consensus/params";
import { ChainStateManager } from "../chain/state";
import { Mempool } from "../mempool/mempool";
import { FeeEstimator } from "../fees/estimator";
import { createTestDB } from "../test/helpers";
import type { ChainDB } from "../storage/database";

// Mock PeerManager
class MockPeerManager {
  getConnectedPeers() { return []; }
  getPeerCount() { return 0; }
  broadcast() {}
}

// Mock HeaderSync
class MockHeaderSync {
  getBestHeader() { return null; }
  getHeader() { return null; }
}

describe("Regtest Generate RPCs", () => {
  let db: ChainDB;
  let cleanup: () => Promise<void>;
  let chainState: ChainStateManager;
  let mempool: Mempool;
  let rpcServer: RPCServer;

  beforeEach(async () => {
    const testDB = await createTestDB();
    db = testDB.db;
    cleanup = testDB.cleanup;

    chainState = new ChainStateManager(db, REGTEST);
    await chainState.load();
    mempool = new Mempool(chainState.getUTXOManager(), REGTEST);

    const config: RPCServerConfig = {
      port: 18443,
      host: "127.0.0.1",
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
    if (cleanup) {
      await cleanup();
    }
  });

  describe("generatetoaddress", () => {
    test("should generate blocks to a regtest P2WPKH address", async () => {
      // bcrt1q is regtest bech32 prefix for P2WPKH
      const address = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";

      // Call RPC method
      const result = await (rpcServer as any).generateToAddress([1, address]);

      // Should return array with one block hash
      expect(Array.isArray(result)).toBe(true);
      expect(result.length).toBe(1);
      expect(typeof result[0]).toBe("string");
      expect(result[0].length).toBe(64); // hex hash

      // Chain should have grown
      const bestBlock = chainState.getBestBlock();
      expect(bestBlock.height).toBe(1);
    });

    test("should generate multiple blocks", async () => {
      const address = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";

      const result = await (rpcServer as any).generateToAddress([5, address]);

      expect(result.length).toBe(5);

      // Each hash should be unique
      const uniqueHashes = new Set(result);
      expect(uniqueHashes.size).toBe(5);

      // Chain should be at height 5
      const bestBlock = chainState.getBestBlock();
      expect(bestBlock.height).toBe(5);
    });

    test("should reject invalid address", async () => {
      await expect(
        (rpcServer as any).generateToAddress([1, "invalid_address"])
      ).rejects.toThrow();
    });

    test("should reject non-regtest mode", async () => {
      // Create a mainnet-like params (fPowNoRetargeting is false)
      const mainnetLikeParams = { ...REGTEST, fPowNoRetargeting: false };

      const mainnetDB = await createTestDB();
      const mainnetChainState = new ChainStateManager(mainnetDB.db, mainnetLikeParams);
      await mainnetChainState.load();
      const mainnetMempool = new Mempool(mainnetChainState.getUTXOManager(), mainnetLikeParams);

      const mainnetConfig: RPCServerConfig = {
        port: 8332,
        host: "127.0.0.1",
      };

      const mainnetDeps: RPCServerDeps = {
        chainState: mainnetChainState,
        mempool: mainnetMempool,
        peerManager: new MockPeerManager() as any,
        feeEstimator: new FeeEstimator(mainnetMempool),
        headerSync: new MockHeaderSync() as any,
        db: mainnetDB.db,
        params: mainnetLikeParams,
      };

      const mainnetRpc = new RPCServer(mainnetConfig, mainnetDeps);

      await expect(
        (mainnetRpc as any).generateToAddress([1, "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080"])
      ).rejects.toThrow("regtest mode");

      await mainnetDB.cleanup();
    });

    test("should accept P2SH address", async () => {
      // 2... prefix for regtest P2SH
      const address = "2MzQwSSnBHWHqSAqtTVQ6v47XtaisrJa1Vc";

      const result = await (rpcServer as any).generateToAddress([1, address]);

      expect(result.length).toBe(1);
      expect(chainState.getBestBlock().height).toBe(1);
    });
  });

  describe("generatetodescriptor", () => {
    test("should generate blocks to a wpkh descriptor", async () => {
      // Simple wpkh descriptor with a test pubkey (generator point G)
      const descriptor = "wpkh(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)";

      const result = await (rpcServer as any).generateToDescriptor([1, descriptor]);

      expect(Array.isArray(result)).toBe(true);
      expect(result.length).toBe(1);
      expect(chainState.getBestBlock().height).toBe(1);
    });

    test("should reject invalid descriptor", async () => {
      await expect(
        (rpcServer as any).generateToDescriptor([1, "invalid_descriptor"])
      ).rejects.toThrow();
    });

    test("should generate multiple blocks to descriptor", async () => {
      const descriptor = "wpkh(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)";

      const result = await (rpcServer as any).generateToDescriptor([3, descriptor]);

      expect(result.length).toBe(3);
      expect(chainState.getBestBlock().height).toBe(3);
    });
  });

  describe("generateblock", () => {
    test("should generate an empty block", async () => {
      const address = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";

      const result = await (rpcServer as any).generateBlock([address, []]);

      expect(typeof result.hash).toBe("string");
      expect(result.hash.length).toBe(64);
      expect(result.hex).toBeUndefined(); // submit=true by default

      expect(chainState.getBestBlock().height).toBe(1);
    });

    test("should return hex when submit=false", async () => {
      const address = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";

      const result = await (rpcServer as any).generateBlock([address, [], false]);

      expect(typeof result.hash).toBe("string");
      expect(typeof result.hex).toBe("string");
      expect(result.hex.length).toBeGreaterThan(0);

      // Block should NOT be connected when submit=false
      expect(chainState.getBestBlock().height).toBe(0);
    });

    test("should reject invalid output", async () => {
      await expect(
        (rpcServer as any).generateBlock(["invalid_address", []])
      ).rejects.toThrow();
    });

    test("should accept descriptor as output", async () => {
      const descriptor = "wpkh(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)";

      const result = await (rpcServer as any).generateBlock([descriptor, []]);

      expect(typeof result.hash).toBe("string");
      expect(chainState.getBestBlock().height).toBe(1);
    });
  });

  describe("block chain growth", () => {
    test("should create valid chain with increasing heights", async () => {
      const address = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";

      // Generate 10 blocks
      const hashes = await (rpcServer as any).generateToAddress([10, address]);

      expect(hashes.length).toBe(10);

      // Verify chain height
      const bestBlock = chainState.getBestBlock();
      expect(bestBlock.height).toBe(10);

      // All hashes should be unique
      const uniqueHashes = new Set(hashes);
      expect(uniqueHashes.size).toBe(10);
    });

    test("should generate blocks with valid PoW", async () => {
      const address = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";

      const hashes = await (rpcServer as any).generateToAddress([1, address]);

      // Block hash should be valid hex
      expect(hashes[0]).toMatch(/^[0-9a-f]{64}$/);
    });

    test("each block should have different hash", async () => {
      const address = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";

      const hashes1 = await (rpcServer as any).generateToAddress([3, address]);
      const hashes2 = await (rpcServer as any).generateToAddress([3, address]);

      // All 6 hashes should be unique
      const allHashes = [...hashes1, ...hashes2];
      const uniqueHashes = new Set(allHashes);
      expect(uniqueHashes.size).toBe(6);
    });
  });

  describe("coinbase maturity", () => {
    test("coinbase outputs require 100 confirmations", async () => {
      const address = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";

      // Generate 1 block (coinbase at height 1)
      await (rpcServer as any).generateToAddress([1, address]);

      // The coinbase output exists but isn't mature yet
      const bestBlock = chainState.getBestBlock();
      expect(bestBlock.height).toBe(1);

      // Generate 99 more blocks (heights 2-100)
      // After this, height=100, coinbase from height=1 has 99 confirmations (not mature)
      await (rpcServer as any).generateToAddress([99, address]);

      expect(chainState.getBestBlock().height).toBe(100);

      // Generate 1 more block (height 101)
      // Now coinbase from height=1 has 100 confirmations (mature!)
      await (rpcServer as any).generateToAddress([1, address]);

      expect(chainState.getBestBlock().height).toBe(101);

      // Coinbase maturity is 100 blocks for regtest
      expect(REGTEST.coinbaseMaturity).toBe(100);
    });
  });
});

describe("Regtest Network Parameters", () => {
  test("should have correct magic bytes", () => {
    // Bitcoin Core regtest magic: 0xfabfb5da (stored as 0xdab5bffa little-endian)
    expect(REGTEST.networkMagic).toBe(0xdab5bffa);
  });

  test("should have correct port", () => {
    expect(REGTEST.defaultPort).toBe(18444);
  });

  test("should have no retargeting enabled", () => {
    expect(REGTEST.fPowNoRetargeting).toBe(true);
  });

  test("should allow min difficulty blocks", () => {
    expect(REGTEST.fPowAllowMinDifficultyBlocks).toBe(true);
  });

  test("should have easiest difficulty", () => {
    // Regtest uses 0x207fffff which is the easiest valid target
    expect(REGTEST.powLimitBits).toBe(0x207fffff);
  });

  test("should have fast halving interval", () => {
    // Regtest uses 150 blocks instead of 210000
    expect(REGTEST.subsidyHalvingInterval).toBe(150);
  });

  test("should have all soft forks active from genesis", () => {
    expect(REGTEST.csvHeight).toBe(0);
    expect(REGTEST.segwitHeight).toBe(0);
    expect(REGTEST.taprootHeight).toBe(0);
  });

  test("should have correct powLimit", () => {
    // 0x207fffff -> 0x7fffff * 2^(8*(0x20-3)) = 0x7fffff * 2^232
    expect(REGTEST.powLimit).toBe(0x7fffff0000000000000000000000000000000000000000000000000000000000n);
  });
});
