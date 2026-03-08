/**
 * Tests for RPC server.
 */

import { describe, it, expect, beforeEach, afterEach } from "bun:test";
import { RPCServer, RPCServerConfig, RPCServerDeps, RPCErrorCodes } from "./server.js";
import { REGTEST } from "../consensus/params.js";

// Mock implementations for dependencies

class MockChainStateManager {
  private bestBlock = {
    hash: Buffer.alloc(32, 0),
    height: 100,
    chainWork: 1000n,
  };

  getBestBlock() {
    return { ...this.bestBlock };
  }

  setBestBlock(hash: Buffer<ArrayBuffer>, height: number, chainWork: bigint) {
    this.bestBlock = { hash, height, chainWork };
  }
}

class MockMempool {
  private entries = new Map<string, { tx: any; txid: Buffer; fee: bigint; feeRate: number; vsize: number; weight: number; addedTime: number; height: number; spentBy: Set<string>; dependsOn: Set<string> }>();

  getInfo() {
    return {
      size: this.entries.size,
      bytes: 1000,
      minFeeRate: 1,
    };
  }

  getAllTxids(): Buffer[] {
    return Array.from(this.entries.values()).map(e => e.txid);
  }

  getTransaction(txid: Buffer) {
    return this.entries.get(txid.toString("hex")) ?? null;
  }

  hasTransaction(txid: Buffer) {
    return this.entries.has(txid.toString("hex"));
  }

  async addTransaction(tx: any) {
    // For testing, we always accept
    return { accepted: true };
  }

  // Helper for tests
  addTestTransaction(txid: Buffer, entry: any) {
    this.entries.set(txid.toString("hex"), {
      tx: entry.tx ?? {},
      txid,
      fee: entry.fee ?? 1000n,
      feeRate: entry.feeRate ?? 10,
      vsize: entry.vsize ?? 200,
      weight: entry.weight ?? 800,
      addedTime: entry.addedTime ?? Math.floor(Date.now() / 1000),
      height: entry.height ?? 100,
      spentBy: entry.spentBy ?? new Set(),
      dependsOn: entry.dependsOn ?? new Set(),
    });
  }
}

class MockPeerManager {
  private peers: any[] = [];

  getConnectedPeers() {
    return this.peers;
  }

  broadcast(_msg: any) {
    // No-op for tests
  }

  addMockPeer(peer: any) {
    this.peers.push(peer);
  }
}

class MockFeeEstimator {
  estimateSmartFee(targetBlocks: number) {
    return {
      feeRate: 10,
      blocks: targetBlocks,
    };
  }
}

class MockHeaderSync {
  private bestHeader = {
    hash: Buffer.alloc(32, 0),
    height: 100,
    chainWork: 1000n,
  };

  getBestHeader() {
    return this.bestHeader;
  }

  getHeader(_hash: Buffer) {
    return {
      hash: Buffer.alloc(32, 0),
      header: {
        version: 1,
        prevBlock: Buffer.alloc(32, 0),
        merkleRoot: Buffer.alloc(32, 0),
        timestamp: 1234567890,
        bits: 0x1d00ffff,
        nonce: 0,
      },
      height: 100,
      chainWork: 1000n,
      status: "valid-header" as const,
    };
  }

  getMedianTimePast(_entry: any) {
    return 1234567890;
  }
}

class MockChainDB {
  private blocks = new Map<string, Buffer>();
  private blockIndexes = new Map<string, any>();
  private hashByHeight = new Map<number, Buffer>();

  async getBlock(hash: Buffer) {
    return this.blocks.get(hash.toString("hex")) ?? null;
  }

  async getBlockIndex(hash: Buffer) {
    return this.blockIndexes.get(hash.toString("hex")) ?? null;
  }

  async getBlockHashByHeight(height: number) {
    return this.hashByHeight.get(height) ?? null;
  }

  // Helpers for tests
  setBlock(hash: Buffer, data: Buffer) {
    this.blocks.set(hash.toString("hex"), data);
  }

  setBlockIndex(hash: Buffer, record: any) {
    this.blockIndexes.set(hash.toString("hex"), record);
  }

  setHashByHeight(height: number, hash: Buffer) {
    this.hashByHeight.set(height, hash);
  }
}

// Helper to make RPC requests
async function rpcRequest(
  port: number,
  method: string,
  params: any[] = [],
  auth?: { user: string; password: string }
): Promise<any> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
  };

  if (auth) {
    const credentials = Buffer.from(`${auth.user}:${auth.password}`).toString("base64");
    headers["Authorization"] = `Basic ${credentials}`;
  }

  const response = await fetch(`http://127.0.0.1:${port}`, {
    method: "POST",
    headers,
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method,
      params,
    }),
  });

  return response.json();
}

// Get a unique port for each test to avoid port conflicts
let portCounter = 18443;
function getTestPort(): number {
  return portCounter++;
}

describe("RPCServer", () => {
  let server: RPCServer;
  let mockChainState: MockChainStateManager;
  let mockMempool: MockMempool;
  let mockPeerManager: MockPeerManager;
  let mockFeeEstimator: MockFeeEstimator;
  let mockHeaderSync: MockHeaderSync;
  let mockDB: MockChainDB;
  let testPort: number;

  beforeEach(() => {
    testPort = getTestPort();
    mockChainState = new MockChainStateManager();
    mockMempool = new MockMempool();
    mockPeerManager = new MockPeerManager();
    mockFeeEstimator = new MockFeeEstimator();
    mockHeaderSync = new MockHeaderSync();
    mockDB = new MockChainDB();

    const config: RPCServerConfig = {
      port: testPort,
      host: "127.0.0.1",
    };

    const deps: RPCServerDeps = {
      chainState: mockChainState as any,
      mempool: mockMempool as any,
      peerManager: mockPeerManager as any,
      feeEstimator: mockFeeEstimator as any,
      headerSync: mockHeaderSync as any,
      db: mockDB as any,
      params: REGTEST,
    };

    server = new RPCServer(config, deps);
    server.start();
  });

  afterEach(() => {
    server.stop();
  });

  describe("Basic HTTP handling", () => {
    it("should reject non-POST requests", async () => {
      const response = await fetch(`http://127.0.0.1:${testPort}`, {
        method: "GET",
      });

      expect(response.status).toBe(405);
      const json = await response.json();
      expect(json.error.code).toBe(RPCErrorCodes.INVALID_REQUEST);
    });

    it("should reject invalid JSON", async () => {
      const response = await fetch(`http://127.0.0.1:${testPort}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: "not valid json",
      });

      expect(response.status).toBe(400);
      const json = await response.json();
      expect(json.error.code).toBe(RPCErrorCodes.PARSE_ERROR);
    });

    it("should return method not found for unknown methods", async () => {
      const result = await rpcRequest(testPort, "unknownmethod");
      expect(result.error.code).toBe(RPCErrorCodes.METHOD_NOT_FOUND);
    });

    it("should handle batched requests", async () => {
      const response = await fetch(`http://127.0.0.1:${testPort}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify([
          { jsonrpc: "2.0", id: 1, method: "getmempoolinfo" },
          { jsonrpc: "2.0", id: 2, method: "getnetworkinfo" },
        ]),
      });

      expect(response.status).toBe(200);
      const json = await response.json();
      expect(Array.isArray(json)).toBe(true);
      expect(json.length).toBe(2);
    });
  });

  describe("Authentication", () => {
    it("should allow requests without auth when no credentials configured", async () => {
      const result = await rpcRequest(testPort, "getmempoolinfo");
      expect(result.result).toBeDefined();
      expect(result.error).toBeUndefined();
    });

    it("should require auth when credentials are configured", async () => {
      // Stop the default server and start one with auth on a new port
      server.stop();
      const authPort = getTestPort();

      const config: RPCServerConfig = {
        port: authPort,
        host: "127.0.0.1",
        rpcUser: "testuser",
        rpcPassword: "testpass",
      };

      const deps: RPCServerDeps = {
        chainState: mockChainState as any,
        mempool: mockMempool as any,
        peerManager: mockPeerManager as any,
        feeEstimator: mockFeeEstimator as any,
        headerSync: mockHeaderSync as any,
        db: mockDB as any,
        params: REGTEST,
      };

      const authServer = new RPCServer(config, deps);
      authServer.start();

      try {
        // Request without auth should fail
        const response = await fetch(`http://127.0.0.1:${authPort}`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "getmempoolinfo" }),
        });

        expect(response.status).toBe(401);
      } finally {
        authServer.stop();
      }
    });

    it("should accept valid auth credentials", async () => {
      // Stop the default server and start one with auth on a new port
      server.stop();
      const authPort = getTestPort();

      const config: RPCServerConfig = {
        port: authPort,
        host: "127.0.0.1",
        rpcUser: "testuser",
        rpcPassword: "testpass",
      };

      const deps: RPCServerDeps = {
        chainState: mockChainState as any,
        mempool: mockMempool as any,
        peerManager: mockPeerManager as any,
        feeEstimator: mockFeeEstimator as any,
        headerSync: mockHeaderSync as any,
        db: mockDB as any,
        params: REGTEST,
      };

      const authServer = new RPCServer(config, deps);
      authServer.start();

      try {
        // Request with valid auth should succeed
        const result = await rpcRequest(authPort, "getmempoolinfo", [], {
          user: "testuser",
          password: "testpass",
        });

        expect(result.result).toBeDefined();
        expect(result.error).toBeUndefined();
      } finally {
        authServer.stop();
      }
    });

    it("should reject invalid auth credentials", async () => {
      // Stop the default server and start one with auth on a new port
      server.stop();
      const authPort = getTestPort();

      const config: RPCServerConfig = {
        port: authPort,
        host: "127.0.0.1",
        rpcUser: "testuser",
        rpcPassword: "testpass",
      };

      const deps: RPCServerDeps = {
        chainState: mockChainState as any,
        mempool: mockMempool as any,
        peerManager: mockPeerManager as any,
        feeEstimator: mockFeeEstimator as any,
        headerSync: mockHeaderSync as any,
        db: mockDB as any,
        params: REGTEST,
      };

      const authServer = new RPCServer(config, deps);
      authServer.start();

      try {
        // Request with wrong password should fail
        const response = await fetch(`http://127.0.0.1:${authPort}`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "Authorization": `Basic ${Buffer.from("testuser:wrongpass").toString("base64")}`,
          },
          body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "getmempoolinfo" }),
        });

        expect(response.status).toBe(401);
      } finally {
        authServer.stop();
      }
    });
  });

  describe("getblockchaininfo", () => {
    it("should return blockchain info", async () => {
      const result = await rpcRequest(testPort, "getblockchaininfo");

      expect(result.result).toBeDefined();
      expect(result.result.chain).toBe("regtest");
      expect(result.result.blocks).toBe(100);
      expect(result.result.headers).toBe(100);
      expect(typeof result.result.difficulty).toBe("number");
      expect(typeof result.result.chainwork).toBe("string");
    });
  });

  describe("getmempoolinfo", () => {
    it("should return mempool info", async () => {
      const result = await rpcRequest(testPort, "getmempoolinfo");

      expect(result.result).toBeDefined();
      expect(result.result.loaded).toBe(true);
      expect(typeof result.result.size).toBe("number");
      expect(typeof result.result.bytes).toBe("number");
    });
  });

  describe("getrawmempool", () => {
    it("should return empty array when mempool is empty", async () => {
      const result = await rpcRequest(testPort, "getrawmempool");

      expect(result.result).toBeDefined();
      expect(Array.isArray(result.result)).toBe(true);
      expect(result.result.length).toBe(0);
    });

    it("should return txids when mempool has transactions", async () => {
      const txid = Buffer.alloc(32, 1);
      mockMempool.addTestTransaction(txid, {});

      const result = await rpcRequest(testPort, "getrawmempool");

      expect(result.result).toBeDefined();
      expect(Array.isArray(result.result)).toBe(true);
      expect(result.result.length).toBe(1);
      expect(result.result[0]).toBe(txid.toString("hex"));
    });

    it("should return verbose entries when verbose=true", async () => {
      const txid = Buffer.alloc(32, 1);
      mockMempool.addTestTransaction(txid, {
        fee: 1000n,
        feeRate: 10,
        vsize: 200,
        weight: 800,
        height: 100,
      });

      const result = await rpcRequest(testPort, "getrawmempool", [true]);

      expect(result.result).toBeDefined();
      expect(typeof result.result).toBe("object");
      const txidHex = txid.toString("hex");
      expect(result.result[txidHex]).toBeDefined();
      expect(result.result[txidHex].vsize).toBe(200);
      expect(result.result[txidHex].weight).toBe(800);
    });
  });

  describe("estimatesmartfee", () => {
    it("should return fee estimate", async () => {
      const result = await rpcRequest(testPort, "estimatesmartfee", [6]);

      expect(result.result).toBeDefined();
      expect(typeof result.result.feerate).toBe("number");
      expect(typeof result.result.blocks).toBe("number");
    });

    it("should reject non-integer conf_target", async () => {
      const result = await rpcRequest(testPort, "estimatesmartfee", ["not a number"]);

      expect(result.error).toBeDefined();
      expect(result.error.code).toBe(RPCErrorCodes.INVALID_PARAMS);
    });
  });

  describe("getpeerinfo", () => {
    it("should return empty array when no peers", async () => {
      const result = await rpcRequest(testPort, "getpeerinfo");

      expect(result.result).toBeDefined();
      expect(Array.isArray(result.result)).toBe(true);
      expect(result.result.length).toBe(0);
    });

    it("should return peer info when peers are connected", async () => {
      mockPeerManager.addMockPeer({
        host: "192.168.1.1",
        port: 8333,
        versionPayload: {
          version: 70016,
          services: 1n,
          userAgent: "/Satoshi:23.0.0/",
          startHeight: 700000,
          relay: true,
        },
      });

      const result = await rpcRequest(testPort, "getpeerinfo");

      expect(result.result).toBeDefined();
      expect(Array.isArray(result.result)).toBe(true);
      expect(result.result.length).toBe(1);
      expect(result.result[0].addr).toBe("192.168.1.1:8333");
    });
  });

  describe("getnetworkinfo", () => {
    it("should return network info", async () => {
      const result = await rpcRequest(testPort, "getnetworkinfo");

      expect(result.result).toBeDefined();
      expect(result.result.version).toBe(REGTEST.protocolVersion);
      expect(result.result.subversion).toBe(REGTEST.userAgent);
      expect(typeof result.result.connections).toBe("number");
    });
  });

  describe("getblockhash", () => {
    it("should return block hash for valid height", async () => {
      const hash = Buffer.alloc(32, 0xab);
      mockDB.setHashByHeight(50, hash);
      mockChainState.setBestBlock(Buffer.alloc(32, 0), 100, 1000n);

      const result = await rpcRequest(testPort, "getblockhash", [50]);

      expect(result.result).toBeDefined();
      expect(result.result).toBe(hash.toString("hex"));
    });

    it("should reject height out of range", async () => {
      const result = await rpcRequest(testPort, "getblockhash", [200]);

      expect(result.error).toBeDefined();
      expect(result.error.code).toBe(RPCErrorCodes.INVALID_PARAMS);
    });

    it("should reject non-integer height", async () => {
      const result = await rpcRequest(testPort, "getblockhash", ["not a number"]);

      expect(result.error).toBeDefined();
      expect(result.error.code).toBe(RPCErrorCodes.INVALID_PARAMS);
    });
  });

  describe("sendrawtransaction", () => {
    it("should accept valid transaction hex", async () => {
      // Create a minimal valid transaction hex
      // version (4) + input count (1) + output count (1) + locktime (4)
      // This is a simplified tx that will parse
      const txHex = "01000000" + // version
        "01" + // input count
        "0000000000000000000000000000000000000000000000000000000000000000" + // prev txid
        "ffffffff" + // prev vout
        "00" + // scriptsig length (0)
        "ffffffff" + // sequence
        "01" + // output count
        "0000000000000000" + // value
        "00" + // scriptpubkey length
        "00000000"; // locktime

      const result = await rpcRequest(testPort, "sendrawtransaction", [txHex]);

      // Should succeed (mock mempool accepts all)
      expect(result.result).toBeDefined();
      expect(typeof result.result).toBe("string");
    });

    it("should reject invalid hex", async () => {
      const result = await rpcRequest(testPort, "sendrawtransaction", ["not hex"]);

      expect(result.error).toBeDefined();
    });

    it("should reject non-string parameter", async () => {
      const result = await rpcRequest(testPort, "sendrawtransaction", [123]);

      expect(result.error).toBeDefined();
      expect(result.error.code).toBe(RPCErrorCodes.INVALID_PARAMS);
    });
  });

  describe("stop", () => {
    it("should return stopping message", async () => {
      let shutdownCalled = false;
      server.setShutdownCallback(() => {
        shutdownCalled = true;
      });

      const result = await rpcRequest(testPort, "stop");

      expect(result.result).toBe("hotbuns stopping");

      // Wait a bit for the shutdown callback to be invoked
      await new Promise(resolve => setTimeout(resolve, 300));
      expect(shutdownCalled).toBe(true);
    });
  });

  describe("Custom method registration", () => {
    it("should allow registering custom methods", async () => {
      server.registerMethod("custommethod", async (params) => {
        return { custom: true, params };
      });

      const result = await rpcRequest(testPort, "custommethod", ["arg1", "arg2"]);

      expect(result.result).toBeDefined();
      expect(result.result.custom).toBe(true);
      expect(result.result.params).toEqual(["arg1", "arg2"]);
    });
  });
});
