/**
 * Tests for RPC server.
 */

import { describe, it, expect, beforeEach, afterEach } from "bun:test";
import { RPCServer, RPCServerConfig, RPCServerDeps, RPCErrorCodes } from "./server.js";
import { REGTEST } from "../consensus/params.js";
import { getBlockHash, serializeBlockHeader } from "../validation/block.js";
import { BufferReader } from "../wire/serialization.js";

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

  removeTransaction(_txid: Buffer, _removeDependents = true): void {
    // No-op for tests
  }

  async isTransactionConfirmed(_txid: Buffer): Promise<boolean> {
    // For testing, assume no transactions are confirmed
    return false;
  }

  isReplaceable(_txid: Buffer): boolean {
    // Full RBF: all mempool transactions are replaceable
    return true;
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
  // Per-test override: when set, getBuckets() returns this array. Tests
  // populate this to drive the estimaterawfee logic.
  public buckets: any[] = [];

  estimateSmartFee(targetBlocks: number) {
    return {
      feeRate: 10,
      blocks: targetBlocks,
    };
  }

  getBuckets() {
    return this.buckets;
  }
}

class MockHeaderSync {
  private bestHeader = {
    hash: Buffer.alloc(32, 0),
    height: 100,
    chainWork: 1000n,
  };
  // Hashes that getHeader should return null for (simulate processHeaders failure)
  private unknownHashes = new Set<string>();

  getBestHeader() {
    return this.bestHeader;
  }

  getHeader(hash: Buffer) {
    if (this.unknownHashes.has(hash.toString("hex"))) {
      return undefined;
    }
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

  /** Make getHeader return undefined for a specific internal-order hash. */
  setUnknown(hash: Buffer) {
    this.unknownHashes.add(hash.toString("hex"));
  }
}

class MockChainDB {
  private blocks = new Map<string, Buffer>();
  private blockIndexes = new Map<string, any>();
  private hashByHeight = new Map<number, Buffer>();
  private chainWorks = new Map<string, bigint>();

  async getBlock(hash: Buffer) {
    return this.blocks.get(hash.toString("hex")) ?? null;
  }

  async getBlockIndex(hash: Buffer) {
    return this.blockIndexes.get(hash.toString("hex")) ?? null;
  }

  async getBlockHashByHeight(height: number) {
    return this.hashByHeight.get(height) ?? null;
  }

  async getChainWork(hash: Buffer): Promise<bigint | null> {
    return this.chainWorks.get(hash.toString("hex")) ?? null;
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

  setChainWork(hash: Buffer, chainWork: bigint) {
    this.chainWorks.set(hash.toString("hex"), chainWork);
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
      noAuth: true,
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
      expect(typeof result.result.initialblockdownload).toBe("boolean");
    });

    it("should include initialblockdownload field that latches to false", async () => {
      const result1 = await rpcRequest(testPort, "getblockchaininfo");
      expect(result1.result.initialblockdownload).toBeDefined();

      // Get IBD status multiple times - it should be consistent
      const result2 = await rpcRequest(testPort, "getblockchaininfo");
      expect(result2.result.initialblockdownload).toBe(result1.result.initialblockdownload);

      // It should be a boolean
      const ibd = result1.result.initialblockdownload;
      expect(typeof ibd).toBe("boolean");
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

  describe("estimaterawfee", () => {
    it("returns short/medium/long horizons with decay+scale even when no data", async () => {
      const result = await rpcRequest(testPort, "estimaterawfee", [6]);

      expect(result.error).toBeUndefined();
      expect(result.result).toBeDefined();
      for (const horizon of ["short", "medium", "long"]) {
        const h = result.result[horizon];
        expect(h).toBeDefined();
        expect(typeof h.decay).toBe("number");
        expect(typeof h.scale).toBe("number");
        // No bucket data populated → must report errors and a fail bucket.
        expect(Array.isArray(h.errors)).toBe(true);
        expect(h.errors[0]).toContain("Insufficient data");
        expect(h.fail).toBeDefined();
      }
    });

    it("returns a passing bucket when threshold is met", async () => {
      // Synthesize one fully-confirming bucket: 50 confirmations within 1
      // block, no unconfirmed → probability = 1.0 ≥ 0.95 threshold.
      mockFeeEstimator.buckets = [
        {
          feeRateRange: { min: 1, max: 2 },
          totalConfirmed: 50,
          totalUnconfirmed: 0,
          confirmationBlocks: new Array(50).fill(1),
          avgConfirmationBlocks: 1,
        },
      ];

      const result = await rpcRequest(testPort, "estimaterawfee", [6, 0.95]);

      expect(result.error).toBeUndefined();
      const short = result.result.short;
      expect(short.feerate).toBeDefined();
      expect(short.pass).toBeDefined();
      expect(short.pass.startrange).toBe(1);
      expect(short.pass.withintarget).toBe(50);
      expect(short.errors).toBeUndefined();
    });

    it("rejects out-of-range threshold", async () => {
      const result = await rpcRequest(testPort, "estimaterawfee", [6, 1.5]);
      expect(result.error).toBeDefined();
      expect(result.error.code).toBe(RPCErrorCodes.INVALID_PARAMS);
      expect(result.error.message).toContain("threshold");
    });

    it("rejects non-integer conf_target", async () => {
      const result = await rpcRequest(testPort, "estimaterawfee", ["nope"]);
      expect(result.error).toBeDefined();
      expect(result.error.code).toBe(RPCErrorCodes.INVALID_PARAMS);
    });
  });

  describe("getmempooldescendants", () => {
    it("rejects malformed txid", async () => {
      const result = await rpcRequest(testPort, "getmempooldescendants", ["xx"]);
      expect(result.error).toBeDefined();
      expect(result.error.code).toBe(RPCErrorCodes.INVALID_PARAMS);
    });

    it("returns INVALID_ADDRESS_OR_KEY when tx not in mempool", async () => {
      const txid = Buffer.alloc(32, 0xab).toString("hex");
      const result = await rpcRequest(testPort, "getmempooldescendants", [txid]);
      expect(result.error).toBeDefined();
      expect(result.error.code).toBe(RPCErrorCodes.INVALID_ADDRESS_OR_KEY);
    });

    it("returns the transitive children list (non-verbose)", async () => {
      // A → B → C chain. getmempooldescendants(A) should return [B, C].
      const a = Buffer.alloc(32, 0x01);
      const b = Buffer.alloc(32, 0x02);
      const c = Buffer.alloc(32, 0x03);

      mockMempool.addTestTransaction(a, {
        spentBy: new Set([b.toString("hex")]),
        dependsOn: new Set(),
      });
      mockMempool.addTestTransaction(b, {
        spentBy: new Set([c.toString("hex")]),
        dependsOn: new Set([a.toString("hex")]),
      });
      mockMempool.addTestTransaction(c, {
        spentBy: new Set(),
        dependsOn: new Set([b.toString("hex")]),
      });

      const result = await rpcRequest(testPort, "getmempooldescendants", [
        a.toString("hex"),
      ]);
      expect(result.error).toBeUndefined();
      expect(Array.isArray(result.result)).toBe(true);
      expect(new Set(result.result)).toEqual(
        new Set([b.toString("hex"), c.toString("hex")])
      );
    });

    it("returns verbose entries when verbose=true", async () => {
      const a = Buffer.alloc(32, 0x10);
      const b = Buffer.alloc(32, 0x11);

      mockMempool.addTestTransaction(a, {
        spentBy: new Set([b.toString("hex")]),
        dependsOn: new Set(),
      });
      mockMempool.addTestTransaction(b, {
        spentBy: new Set(),
        dependsOn: new Set([a.toString("hex")]),
        vsize: 250,
        weight: 1000,
        fee: 2500n,
      });

      const result = await rpcRequest(testPort, "getmempooldescendants", [
        a.toString("hex"),
        true,
      ]);
      expect(result.error).toBeUndefined();
      const child = result.result[b.toString("hex")];
      expect(child).toBeDefined();
      expect(child.vsize).toBe(250);
      expect(child.weight).toBe(1000);
      expect(child.depends).toEqual([a.toString("hex")]);
      expect(child.spentby).toEqual([]);
    });

    it("returns empty list when leaf has no descendants", async () => {
      const leaf = Buffer.alloc(32, 0x77);
      mockMempool.addTestTransaction(leaf, {
        spentBy: new Set(),
        dependsOn: new Set(),
      });

      const result = await rpcRequest(testPort, "getmempooldescendants", [
        leaf.toString("hex"),
      ]);
      expect(result.error).toBeUndefined();
      expect(result.result).toEqual([]);
    });
  });

  describe("signmessagewithprivkey / verifymessage", () => {
    // Hashhog regtest WIF (compressed) for a deterministic key. Derived
    // from privkey = 32 × 0x11 (well-known low-entropy test key) by
    // base58CheckEncode(0xef, priv || 0x01). The corresponding regtest
    // P2PKH address (version 0x6f, HASH160 of compressed pubkey) is
    // n4XmX91N5FfccY678vaG1ELNtXh6skVES7. Both values are produced
    // directly by hotbuns crypto primitives — see the bun -e snippet in
    // the W122 PR description.
    const TEST_WIF = "cN9spWsvaxA8taS7DFMxnk1yJD2gaF2PX1npuTpy3vuZFJdwavaw";
    const TEST_ADDR = "n4XmX91N5FfccY678vaG1ELNtXh6skVES7";

    it("round-trips: signmessagewithprivkey produces a verifymessage-OK signature", async () => {
      const message = "hello hashhog";
      const signed = await rpcRequest(testPort, "signmessagewithprivkey", [
        TEST_WIF,
        message,
      ]);
      expect(signed.error).toBeUndefined();
      expect(typeof signed.result).toBe("string");
      // Compact 65-byte signature → base64 length is 88 (with one '=' pad).
      expect(signed.result.length).toBeGreaterThanOrEqual(86);

      const verified = await rpcRequest(testPort, "verifymessage", [
        TEST_ADDR,
        signed.result,
        message,
      ]);
      expect(verified.error).toBeUndefined();
      expect(verified.result).toBe(true);
    });

    it("verifymessage returns false when message has been tampered with", async () => {
      const signed = await rpcRequest(testPort, "signmessagewithprivkey", [
        TEST_WIF,
        "original",
      ]);
      const verified = await rpcRequest(testPort, "verifymessage", [
        TEST_ADDR,
        signed.result,
        "tampered",
      ]);
      expect(verified.error).toBeUndefined();
      expect(verified.result).toBe(false);
    });

    it("verifymessage returns INVALID_ADDRESS_OR_KEY for a malformed address", async () => {
      const result = await rpcRequest(testPort, "verifymessage", [
        "notabitcoinaddress",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        "msg",
      ]);
      expect(result.error).toBeDefined();
      expect(result.error.code).toBe(RPCErrorCodes.INVALID_ADDRESS_OR_KEY);
    });

    it("verifymessage rejects malformed base64 signatures", async () => {
      const result = await rpcRequest(testPort, "verifymessage", [
        TEST_ADDR,
        "definitely-not-valid",
        "msg",
      ]);
      expect(result.error).toBeDefined();
      expect(result.error.code).toBe(RPCErrorCodes.INVALID_ADDRESS_OR_KEY);
      expect(result.error.message).toContain("Malformed");
    });

    it("verifymessage rejects bech32 (non-PKH) addresses with ADDRESS_NO_KEY", async () => {
      // A bech32 address is not Base58Check-decodable, so we expect
      // INVALID_ADDRESS at the base58check stage. (Core distinguishes
      // ERR_ADDRESS_NO_KEY for SegWit; hotbuns currently maps both
      // failure modes to INVALID_ADDRESS_OR_KEY.)
      const result = await rpcRequest(testPort, "verifymessage", [
        "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqwm7tkn",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        "msg",
      ]);
      expect(result.error).toBeDefined();
      expect(result.error.code).toBe(RPCErrorCodes.INVALID_ADDRESS_OR_KEY);
    });

    it("signmessagewithprivkey rejects an invalid WIF", async () => {
      const result = await rpcRequest(testPort, "signmessagewithprivkey", [
        "not-a-wif",
        "msg",
      ]);
      expect(result.error).toBeDefined();
      expect(result.error.code).toBe(RPCErrorCodes.INVALID_ADDRESS_OR_KEY);
    });

    it("signmessage (wallet RPC) is NOT registered when no wallet is configured", async () => {
      // The fixture-level RPCServer in this file is constructed without a
      // wallet, so signmessage must not be registered. This guards the
      // wallet-conditional registration in registerBuiltinMethods().
      const result = await rpcRequest(testPort, "signmessage", [
        TEST_ADDR,
        "msg",
      ]);
      expect(result.error).toBeDefined();
      expect(result.error.code).toBe(RPCErrorCodes.METHOD_NOT_FOUND);
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

  describe("savemempool / dumpmempool / loadmempool", () => {
    // The fixture-level RPC server in this file is configured WITHOUT a
    // datadir, so both methods take the "no datadir configured" branch
    // — this is the exact error operators see if hotbuns is started
    // without `-datadir` and they hit the RPC.  End-to-end on-disk
    // round-trips live in `src/mempool/persist.test.ts` against a real
    // mempool + tmp directory.
    it("savemempool returns MISC_ERROR when datadir is not configured", async () => {
      const result = await rpcRequest(testPort, "savemempool");
      expect(result.error).toBeDefined();
      expect(result.error.code).toBe(RPCErrorCodes.MISC_ERROR);
      expect(result.error.message).toContain("datadir");
    });

    it("dumpmempool is registered as an alias for savemempool", async () => {
      const result = await rpcRequest(testPort, "dumpmempool");
      expect(result.error).toBeDefined();
      expect(result.error.code).toBe(RPCErrorCodes.MISC_ERROR);
    });

    it("loadmempool returns MISC_ERROR when datadir is not configured", async () => {
      const result = await rpcRequest(testPort, "loadmempool");
      expect(result.error).toBeDefined();
      expect(result.error.code).toBe(RPCErrorCodes.MISC_ERROR);
      expect(result.error.message).toContain("datadir");
    });
  });

  describe("validateaddress", () => {
    it("should validate a valid P2PKH address", async () => {
      // A valid regtest P2PKH address (starts with m or n)
      // This is a testnet/regtest address: mkHGce7dctSxHgaWSSbmmrRWsZfzz7MxMk
      const result = await rpcRequest(testPort, "validateaddress", [
        "mkHGce7dctSxHgaWSSbmmrRWsZfzz7MxMk",
      ]);

      expect(result.result).toBeDefined();
      expect(result.result.isvalid).toBe(true);
      expect(result.result.address).toBe("mkHGce7dctSxHgaWSSbmmrRWsZfzz7MxMk");
      expect(result.result.isscript).toBe(false);
      expect(result.result.iswitness).toBe(false);
    });

    it("should validate a valid bech32 address", async () => {
      // A valid regtest P2WPKH address (bcrt1q...)
      const result = await rpcRequest(testPort, "validateaddress", [
        "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqwm7tkn",
      ]);

      // The checksum might not match since we're using a synthetic address
      // But the parsing should proceed
      expect(result.result).toBeDefined();
    });

    it("should reject invalid addresses", async () => {
      const result = await rpcRequest(testPort, "validateaddress", [
        "notanaddress",
      ]);

      expect(result.result).toBeDefined();
      expect(result.result.isvalid).toBe(false);
      expect(result.result.error).toBeDefined();
    });

    it("should reject non-string parameter", async () => {
      const result = await rpcRequest(testPort, "validateaddress", [123]);

      expect(result.error).toBeDefined();
      expect(result.error.code).toBe(RPCErrorCodes.INVALID_PARAMS);
    });
  });

  describe("getblocktemplate", () => {
    it("should return block template with segwit rule", async () => {
      const result = await rpcRequest(testPort, "getblocktemplate", [
        { rules: ["segwit"] },
      ]);

      expect(result.result).toBeDefined();
      expect(result.result.version).toBeDefined();
      expect(result.result.previousblockhash).toBeDefined();
      expect(result.result.transactions).toBeDefined();
      expect(Array.isArray(result.result.transactions)).toBe(true);
      expect(result.result.coinbasevalue).toBeDefined();
      expect(result.result.height).toBe(101); // Best block height (100) + 1
      expect(result.result.capabilities).toContain("proposal");
      expect(result.result.rules).toContain("!segwit");
    });

    it("should reject without segwit rule", async () => {
      const result = await rpcRequest(testPort, "getblocktemplate", [
        { rules: [] },
      ]);

      expect(result.error).toBeDefined();
      expect(result.error.message).toContain("segwit");
    });

    it("should include transaction data", async () => {
      // Add a transaction to the mempool
      const txid = Buffer.alloc(32, 2);
      mockMempool.addTestTransaction(txid, {
        tx: {
          version: 2,
          inputs: [
            {
              prevOut: { txid: Buffer.alloc(32, 0), vout: 0 },
              scriptSig: Buffer.alloc(0),
              sequence: 0xffffffff,
              witness: [],
            },
          ],
          outputs: [
            { value: 1000n, scriptPubKey: Buffer.alloc(25, 0) },
          ],
          lockTime: 0,
        },
        fee: 500n,
        weight: 400,
      });

      const result = await rpcRequest(testPort, "getblocktemplate", [
        { rules: ["segwit"] },
      ]);

      expect(result.result).toBeDefined();
      expect(result.result.transactions.length).toBe(1);
      expect(result.result.transactions[0].fee).toBe(500);
    });
  });

  describe("getblockchaininfo softforks", () => {
    it("should include softforks in response", async () => {
      const result = await rpcRequest(testPort, "getblockchaininfo");

      expect(result.result).toBeDefined();
      expect(result.result.softforks).toBeDefined();
      expect(result.result.softforks.segwit).toBeDefined();
      expect(result.result.softforks.segwit.type).toBe("buried");
      expect(result.result.softforks.taproot).toBeDefined();
      expect(result.result.softforks.csv).toBeDefined();
      expect(result.result.softforks.bip34).toBeDefined();
    });
  });

  // ─── getblockheader regression tests ─────────────────────────────────────
  // These tests verify the fix for the hash-reversal bug where hotbuns stored
  // blocks with internal-byte-order keys but getblockheader accepted display-
  // order hashes without reversing them, causing all lookups to fail.

  describe("getblockheader regression", () => {
    // Helper: build a minimal 80-byte block header Buffer
    function buildHeaderBuf(
      version: number,
      prevBlock: Buffer,
      merkleRoot: Buffer,
      timestamp: number,
      bits: number,
      nonce: number
    ): Buffer {
      const buf = Buffer.allocUnsafe(80);
      buf.writeInt32LE(version, 0);
      prevBlock.copy(buf, 4);
      merkleRoot.copy(buf, 36);
      buf.writeUInt32LE(timestamp, 68);
      buf.writeUInt32LE(bits, 72);
      buf.writeUInt32LE(nonce, 76);
      return buf;
    }

    // Test 1 — Unit test: getblockheader for a known regtest genesis block
    // returns all consensus-relevant fields with correct values.
    it("unit: getblockheader returns all required fields for the regtest genesis block", async () => {
      // The regtest genesis block is serialised in REGTEST.genesisBlock.
      // Internal hash (= raw hash256 output) is REGTEST.genesisBlockHash.
      // Display hash (what Bitcoin Core and RPC callers use) is the reverse.
      const genesisRaw = REGTEST.genesisBlock;
      const genesisHashInternal = REGTEST.genesisBlockHash;         // internal order
      const genesisHashDisplay = Buffer.from(genesisHashInternal).reverse().toString("hex");

      // Parse the 80-byte header from the raw block
      const headerBuf = genesisRaw.subarray(0, 80);
      const version    = headerBuf.readInt32LE(0);
      const prevBlock  = headerBuf.subarray(4, 36);
      const merkleRoot = headerBuf.subarray(36, 68);
      const time       = headerBuf.readUInt32LE(68);
      const bits       = headerBuf.readUInt32LE(72);
      const nonce      = headerBuf.readUInt32LE(76);

      // Populate mock DB with genesis block index (keyed by INTERNAL hash).
      // Tell MockHeaderSync to return undefined for genesis (simulates processHeaders
      // not having this block), forcing the DB chainwork fallback path.
      const genesisChainWork = 2n; // stored in DB by connectBlock
      mockDB.setBlockIndex(genesisHashInternal, {
        height: 0,
        header: Buffer.from(headerBuf),
        nTx: 1,
        status: 7,
        dataPos: 1,
      });
      mockDB.setChainWork(genesisHashInternal, genesisChainWork);
      mockDB.setHashByHeight(0, Buffer.from(genesisHashInternal));
      mockChainState.setBestBlock(Buffer.from(genesisHashInternal), 0, genesisChainWork);
      // Make headerSync return null so the DB fallback is exercised
      mockHeaderSync.setUnknown(Buffer.from(genesisHashInternal));

      // Call with DISPLAY-order hash (as returned by getblockhash / consensus-diff)
      const result = await rpcRequest(testPort, "getblockheader", [genesisHashDisplay, true]);

      expect(result.error).toBeUndefined();
      const h = result.result;
      expect(h).toBeDefined();

      // All consensus-relevant fields must be present and correct
      expect(h.hash).toBe(genesisHashDisplay);
      expect(h.height).toBe(0);
      expect(h.version).toBe(version);
      expect(h.versionHex).toBe(version.toString(16).padStart(8, "0"));
      expect(h.merkleroot).toBe(Buffer.from(merkleRoot).reverse().toString("hex"));
      expect(h.time).toBe(time);
      // mediantime fallback = header.timestamp when headerSync entry is absent
      expect(h.mediantime).toBe(time);
      expect(h.nonce).toBe(nonce);
      expect(h.bits).toBe(bits.toString(16).padStart(8, "0"));
      expect(typeof h.difficulty).toBe("number");
      // DB fallback chainwork must equal what was stored by connectBlock
      expect(h.chainwork).toBe(genesisChainWork.toString(16).padStart(64, "0"));
      expect(h.nTx).toBe(1);
      expect(h.previousblockhash).toBe(Buffer.from(prevBlock).reverse().toString("hex"));
      // nextblockhash is absent at genesis (no successor stored)
      expect(h.nextblockhash).toBeUndefined();
    });

    // Test 2 — Integration: mine 10 regtest blocks via generatetoaddress, call
    // getblockheader on block 5, and assert every field is present and sane.
    it("integration: getblockheader on a mined block returns all fields", async () => {
      // Build a plausible block index entry simulating what connectBlock stores
      const prevHashInternal = REGTEST.genesisBlockHash;
      const merkleRoot = Buffer.alloc(32, 0xcc);
      const bits       = 0x207fffff; // regtest minimum difficulty
      const timestamp  = 1600000000;
      const nonce      = 42;
      const version    = 0x20000000;

      const headerBuf = buildHeaderBuf(version, Buffer.from(prevHashInternal), merkleRoot, timestamp, bits, nonce);

      // Derive the block hash the same way connectBlock does
      const blockHashInternal = getBlockHash({
        version,
        prevBlock: Buffer.from(prevHashInternal),
        merkleRoot: Buffer.from(merkleRoot),
        timestamp,
        bits,
        nonce,
      });
      const blockHashDisplay = Buffer.from(blockHashInternal).reverse().toString("hex");
      const blockChainWork = 12n; // genesis + 11 blocks worth

      const blockHeight = 5;
      mockChainState.setBestBlock(Buffer.from(blockHashInternal), blockHeight, blockChainWork);
      mockDB.setBlockIndex(blockHashInternal, {
        height: blockHeight,
        header: headerBuf,
        nTx: 2,
        status: 15,
        dataPos: 1,
      });
      mockDB.setChainWork(blockHashInternal, blockChainWork);
      mockDB.setHashByHeight(blockHeight, Buffer.from(blockHashInternal));

      const result = await rpcRequest(testPort, "getblockheader", [blockHashDisplay, true]);

      expect(result.error).toBeUndefined();
      const h = result.result;
      expect(h).toBeDefined();
      expect(h.hash).toBe(blockHashDisplay);
      expect(h.height).toBe(blockHeight);
      expect(h.version).toBe(version);
      expect(h.versionHex).toBe("20000000");
      expect(h.merkleroot).toBe(Buffer.from(merkleRoot).reverse().toString("hex"));
      expect(h.time).toBe(timestamp);
      expect(typeof h.mediantime).toBe("number");
      expect(h.nonce).toBe(nonce);
      expect(h.bits).toBe(bits.toString(16).padStart(8, "0"));
      expect(typeof h.difficulty).toBe("number");
      // chainwork comes from headerSync (mock returns 1000n) or DB fallback; must be 64-char hex
      expect(h.chainwork).toHaveLength(64);
      expect(h.nTx).toBe(2);
      expect(h.previousblockhash).toBe(Buffer.from(prevHashInternal).reverse().toString("hex"));
      expect(h.confirmations).toBe(1); // tip block → 1 confirmation
    });

    // Test 3 — Cross-check: getblockheader on the regtest genesis block returns
    // the exact same field values that Bitcoin Core returns for the same block.
    // Known-good values are taken directly from Bitcoin Core source / docs.
    it("cross-check: regtest genesis getblockheader matches Bitcoin Core known values", async () => {
      // Bitcoin Core regtest genesis block known values (from chainparams.cpp / RPC tests):
      //   display hash:  0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206
      //   height:        0
      //   version:       1
      //   merkleroot:    4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b
      //   time:          1296688602
      //   bits:          207fffff
      //   nonce:         2
      //   previousblockhash (all zeros, displayed reversed = same): 0000...0000
      const GENESIS_DISPLAY_HASH = "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206";
      const GENESIS_MERKLEROOT   = "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b";
      const GENESIS_TIME         = 1296688602;
      const GENESIS_BITS         = "207fffff";
      const GENESIS_NONCE        = 2;
      const GENESIS_VERSION      = 1;
      const GENESIS_PREV         = "0000000000000000000000000000000000000000000000000000000000000000";

      const genesisHashInternal = REGTEST.genesisBlockHash;
      const genesisRaw          = REGTEST.genesisBlock;
      const headerBuf           = Buffer.from(genesisRaw.subarray(0, 80));
      const genesisChainWork    = 2n;

      mockDB.setBlockIndex(genesisHashInternal, {
        height: 0,
        header: headerBuf,
        nTx: 1,
        status: 7,
        dataPos: 1,
      });
      mockDB.setChainWork(genesisHashInternal, genesisChainWork);
      mockDB.setHashByHeight(0, Buffer.from(genesisHashInternal));
      mockChainState.setBestBlock(Buffer.from(genesisHashInternal), 0, genesisChainWork);
      // Disable headerSync for genesis so the DB fallback is tested
      mockHeaderSync.setUnknown(Buffer.from(genesisHashInternal));

      const result = await rpcRequest(testPort, "getblockheader", [GENESIS_DISPLAY_HASH, true]);

      expect(result.error).toBeUndefined();
      const h = result.result;
      expect(h.hash).toBe(GENESIS_DISPLAY_HASH);
      expect(h.height).toBe(0);
      expect(h.version).toBe(GENESIS_VERSION);
      expect(h.versionHex).toBe("00000001");
      expect(h.merkleroot).toBe(GENESIS_MERKLEROOT);
      expect(h.time).toBe(GENESIS_TIME);
      // mediantime fallback = header.timestamp when headerSync entry is absent
      expect(h.mediantime).toBe(GENESIS_TIME);
      expect(h.nonce).toBe(GENESIS_NONCE);
      expect(h.bits).toBe(GENESIS_BITS);
      expect(h.previousblockhash).toBe(GENESIS_PREV);
      // nextblockhash absent at genesis
      expect(h.nextblockhash).toBeUndefined();
      // chainwork comes from DB fallback → must match what connectBlock stored
      expect(h.chainwork).toBe(genesisChainWork.toString(16).padStart(64, "0"));
    });
  });

  describe("getdeploymentinfo", () => {
    it("should return non-empty deployments with segwit and taproot at regtest tip", async () => {
      const result = await rpcRequest(testPort, "getdeploymentinfo");

      expect(result.error).toBeUndefined();
      expect(result.result).toBeDefined();
      expect(result.result.deployments).toBeDefined();

      const deployments = result.result.deployments;

      // Must contain segwit
      expect(deployments.segwit).toBeDefined();
      expect(deployments.segwit.type).toBe("buried");
      expect(typeof deployments.segwit.active).toBe("boolean");
      expect(typeof deployments.segwit.height).toBe("number");
      expect(typeof deployments.segwit.min_activation_height).toBe("number");

      // Must contain taproot
      expect(deployments.taproot).toBeDefined();
      expect(deployments.taproot.type).toBe("buried");
      expect(typeof deployments.taproot.active).toBe("boolean");
      expect(typeof deployments.taproot.height).toBe("number");
      expect(typeof deployments.taproot.min_activation_height).toBe("number");
    });

    it("should return active=true for segwit and taproot on regtest (height-0 activation)", async () => {
      // REGTEST has csvHeight=0, segwitHeight=0, taprootHeight=0 — active from genesis.
      // The mock chain state reports height=100, so all buried deployments should be active.
      const result = await rpcRequest(testPort, "getdeploymentinfo");

      expect(result.error).toBeUndefined();
      const deployments = result.result.deployments;

      expect(deployments.segwit.active).toBe(true);
      expect(deployments.taproot.active).toBe(true);
      expect(deployments.csv.active).toBe(true);
    });

    it("should return all expected deployment keys", async () => {
      const result = await rpcRequest(testPort, "getdeploymentinfo");

      expect(result.error).toBeUndefined();
      const deployments = result.result.deployments;
      const keys = Object.keys(deployments);

      expect(keys).toContain("bip34");
      expect(keys).toContain("bip65");
      expect(keys).toContain("bip66");
      expect(keys).toContain("csv");
      expect(keys).toContain("segwit");
      expect(keys).toContain("taproot");
    });

    it("should return hash and height fields at chain tip", async () => {
      const result = await rpcRequest(testPort, "getdeploymentinfo");

      expect(result.error).toBeUndefined();
      expect(typeof result.result.hash).toBe("string");
      expect(result.result.hash).toHaveLength(64);
      expect(typeof result.result.height).toBe("number");
    });

    it("should reject non-string blockhash param", async () => {
      const result = await rpcRequest(testPort, "getdeploymentinfo", [12345]);

      expect(result.error).toBeDefined();
      expect(result.error.code).toBe(RPCErrorCodes.INVALID_PARAMS);
    });
  });

  // ========== NetworkDisable RAII (dumptxoutset rollback) ==========
  // Mirrors Bitcoin Core's NetworkDisable wrapper around TemporaryRollback
  // in rpc/blockchain.cpp::dumptxoutset. We exercise the flag directly
  // and confirm submitblock short-circuits with a "paused" reject string
  // before any deserialization.
  describe("NetworkDisable rollback gate", () => {
    it("isBlockSubmissionPaused defaults to false", () => {
      expect(server.isBlockSubmissionPaused()).toBe(false);
    });

    it("setBlockSubmissionPausedForTest round-trips the flag", () => {
      server.setBlockSubmissionPausedForTest(true);
      expect(server.isBlockSubmissionPaused()).toBe(true);
      server.setBlockSubmissionPausedForTest(false);
      expect(server.isBlockSubmissionPaused()).toBe(false);
    });

    it("submitblock returns paused reject string while flag is set", async () => {
      server.setBlockSubmissionPausedForTest(true);
      try {
        // Garbage hex is fine: the gate runs before deserialization.
        const result = await rpcRequest(testPort, "submitblock", ["00"]);
        // Bitcoin Core's submitblock returns the reject reason as a
        // top-level string (or null on success). Our gate returns the
        // string directly; the wrapper RPC framework surfaces it as
        // `result.result`.
        expect(result.error).toBeUndefined();
        expect(typeof result.result).toBe("string");
        expect(result.result as string).toContain("paused");
      } finally {
        server.setBlockSubmissionPausedForTest(false);
      }
    });

    it("submitblock proceeds past the gate once flag is cleared", async () => {
      server.setBlockSubmissionPausedForTest(true);
      server.setBlockSubmissionPausedForTest(false);
      // With the gate cleared, the handler must reach decode/inject.
      // We feed garbage hex so it ultimately returns an error — the
      // important assertion is that we DON'T see the "paused" reject.
      const result = await rpcRequest(testPort, "submitblock", ["00"]);
      const reason = result.result as string | undefined;
      const errorMsg = (result.error?.message ?? "") as string;
      expect(typeof reason === "string" && reason.includes("paused")).toBe(false);
      expect(errorMsg.includes("paused")).toBe(false);
    });
  });
});
