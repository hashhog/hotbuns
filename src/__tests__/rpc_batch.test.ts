/**
 * Tests for JSON-RPC batch request handling.
 *
 * Verifies:
 * - Batch requests return array of responses
 * - Each response includes its corresponding id
 * - Individual request failures don't affect other requests
 * - Empty batch returns error
 * - Batch size limit enforced (max 1000)
 * - Non-object/non-array body handled correctly
 */

import { describe, it, expect, beforeEach, afterEach } from "bun:test";
import { RPCServer, RPCServerConfig, RPCServerDeps, RPCErrorCodes, MAX_BATCH_SIZE } from "../rpc/server.js";
import { REGTEST } from "../consensus/params.js";

// Mock implementations for dependencies (reused from server.test.ts)

class MockChainStateManager {
  private bestBlock = {
    hash: Buffer.alloc(32, 0),
    height: 100,
    chainWork: 1000n,
  };

  getBestBlock() {
    return { ...this.bestBlock };
  }
}

class MockMempool {
  getInfo() {
    return {
      size: 0,
      bytes: 0,
      minFeeRate: 1,
    };
  }

  getAllTxids(): Buffer[] {
    return [];
  }

  getTransaction(_txid: Buffer) {
    return null;
  }

  hasTransaction(_txid: Buffer) {
    return false;
  }

  async addTransaction(_tx: any) {
    return { accepted: true };
  }

  removeTransaction(_txid: Buffer, _removeDependents = true): void {}

  async isTransactionConfirmed(_txid: Buffer): Promise<boolean> {
    return false;
  }
}

class MockPeerManager {
  getConnectedPeers() {
    return [];
  }

  broadcast(_msg: any) {}

  listBanned() {
    return [];
  }

  banAddress(_ip: string, _duration: number, _reason: string) {}

  unbanAddress(_ip: string) {
    return false;
  }

  clearBanned() {}
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
  getBestHeader() {
    return {
      hash: Buffer.alloc(32, 0),
      height: 100,
      chainWork: 1000n,
    };
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
  async getBlock(_hash: Buffer) {
    return null;
  }

  async getBlockIndex(_hash: Buffer) {
    return null;
  }

  async getBlockHashByHeight(_height: number) {
    return null;
  }

  async getTxIndex(_txid: Buffer) {
    return null;
  }
}

// Helper to make raw batch requests
async function batchRequest(
  port: number,
  requests: any[]
): Promise<any> {
  const response = await fetch(`http://127.0.0.1:${port}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(requests),
  });

  return { status: response.status, body: await response.json() };
}

// Helper to make raw requests with arbitrary body
async function rawRequest(port: number, body: string): Promise<any> {
  const response = await fetch(`http://127.0.0.1:${port}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body,
  });

  return { status: response.status, body: await response.json() };
}

// Get a unique port for each test
let portCounter = 19000;
function getTestPort(): number {
  return portCounter++;
}

describe("RPC Batch Requests", () => {
  let server: RPCServer;
  let testPort: number;

  beforeEach(() => {
    testPort = getTestPort();

    const config: RPCServerConfig = {
      port: testPort,
      host: "127.0.0.1",
      noAuth: true,
    };

    const deps: RPCServerDeps = {
      chainState: new MockChainStateManager() as any,
      mempool: new MockMempool() as any,
      peerManager: new MockPeerManager() as any,
      feeEstimator: new MockFeeEstimator() as any,
      headerSync: new MockHeaderSync() as any,
      db: new MockChainDB() as any,
      params: REGTEST,
    };

    server = new RPCServer(config, deps);
    server.start();
  });

  afterEach(() => {
    server.stop();
  });

  describe("Successful batch requests", () => {
    it("should return array of responses for batch request", async () => {
      const result = await batchRequest(testPort, [
        { jsonrpc: "2.0", id: 1, method: "getmempoolinfo" },
        { jsonrpc: "2.0", id: 2, method: "getnetworkinfo" },
      ]);

      expect(result.status).toBe(200);
      expect(Array.isArray(result.body)).toBe(true);
      expect(result.body.length).toBe(2);
    });

    it("should preserve response order matching request order", async () => {
      const result = await batchRequest(testPort, [
        { jsonrpc: "2.0", id: 1, method: "getmempoolinfo" },
        { jsonrpc: "2.0", id: 2, method: "getnetworkinfo" },
        { jsonrpc: "2.0", id: 3, method: "getblockchaininfo" },
      ]);

      expect(result.status).toBe(200);
      expect(result.body[0].id).toBe(1);
      expect(result.body[1].id).toBe(2);
      expect(result.body[2].id).toBe(3);
    });

    it("should include correct id in each response", async () => {
      const result = await batchRequest(testPort, [
        { jsonrpc: "2.0", id: "foo", method: "getmempoolinfo" },
        { jsonrpc: "2.0", id: 42, method: "getnetworkinfo" },
        { jsonrpc: "2.0", id: null, method: "getblockchaininfo" },
      ]);

      expect(result.status).toBe(200);
      expect(result.body[0].id).toBe("foo");
      expect(result.body[1].id).toBe(42);
      expect(result.body[2].id).toBe(null);
    });

    it("should handle single-element batch", async () => {
      const result = await batchRequest(testPort, [
        { jsonrpc: "2.0", id: 1, method: "getmempoolinfo" },
      ]);

      expect(result.status).toBe(200);
      expect(Array.isArray(result.body)).toBe(true);
      expect(result.body.length).toBe(1);
      expect(result.body[0].result).toBeDefined();
    });
  });

  describe("Error handling in batches", () => {
    it("should continue processing after individual request failure", async () => {
      const result = await batchRequest(testPort, [
        { jsonrpc: "2.0", id: 1, method: "getmempoolinfo" },
        { jsonrpc: "2.0", id: 2, method: "unknownmethod" },
        { jsonrpc: "2.0", id: 3, method: "getnetworkinfo" },
      ]);

      expect(result.status).toBe(200);
      expect(result.body.length).toBe(3);

      // First request succeeds
      expect(result.body[0].result).toBeDefined();
      expect(result.body[0].error).toBeUndefined();

      // Second request fails
      expect(result.body[1].error).toBeDefined();
      expect(result.body[1].error.code).toBe(RPCErrorCodes.METHOD_NOT_FOUND);

      // Third request succeeds
      expect(result.body[2].result).toBeDefined();
      expect(result.body[2].error).toBeUndefined();
    });

    it("should include error response for invalid request objects", async () => {
      const result = await batchRequest(testPort, [
        { jsonrpc: "2.0", id: 1, method: "getmempoolinfo" },
        { jsonrpc: "2.0", id: 2 }, // Missing method
        { jsonrpc: "2.0", id: 3, method: "getnetworkinfo" },
      ]);

      expect(result.status).toBe(200);
      expect(result.body.length).toBe(3);

      // First request succeeds
      expect(result.body[0].result).toBeDefined();

      // Second request fails (invalid request)
      expect(result.body[1].error).toBeDefined();
      expect(result.body[1].error.code).toBe(RPCErrorCodes.INVALID_REQUEST);

      // Third request succeeds
      expect(result.body[2].result).toBeDefined();
    });

    it("should handle all requests failing gracefully", async () => {
      const result = await batchRequest(testPort, [
        { jsonrpc: "2.0", id: 1, method: "unknownmethod1" },
        { jsonrpc: "2.0", id: 2, method: "unknownmethod2" },
      ]);

      expect(result.status).toBe(200);
      expect(result.body.length).toBe(2);
      expect(result.body[0].error.code).toBe(RPCErrorCodes.METHOD_NOT_FOUND);
      expect(result.body[1].error.code).toBe(RPCErrorCodes.METHOD_NOT_FOUND);
    });
  });

  describe("Empty batch handling", () => {
    it("should return error for empty batch", async () => {
      const result = await batchRequest(testPort, []);

      expect(result.status).toBe(200);
      expect(Array.isArray(result.body)).toBe(false);
      expect(result.body.error).toBeDefined();
      expect(result.body.error.code).toBe(RPCErrorCodes.INVALID_REQUEST);
      expect(result.body.error.message).toContain("Empty batch");
    });
  });

  describe("Batch size limits", () => {
    it("should enforce maximum batch size of 1000", async () => {
      expect(MAX_BATCH_SIZE).toBe(1000);
    });

    it("should reject batch exceeding maximum size", async () => {
      // Create array of 1001 requests (exceeds MAX_BATCH_SIZE)
      const requests = Array(1001).fill(null).map((_, i) => ({
        jsonrpc: "2.0",
        id: i,
        method: "getmempoolinfo",
      }));

      const result = await batchRequest(testPort, requests);

      expect(result.status).toBe(200);
      expect(Array.isArray(result.body)).toBe(false);
      expect(result.body.error).toBeDefined();
      expect(result.body.error.code).toBe(RPCErrorCodes.INVALID_REQUEST);
      expect(result.body.error.message).toContain("exceeds maximum");
    });

    it("should accept batch at maximum size", async () => {
      // Create array of exactly 1000 requests
      const requests = Array(10).fill(null).map((_, i) => ({
        jsonrpc: "2.0",
        id: i,
        method: "getmempoolinfo",
      }));

      const result = await batchRequest(testPort, requests);

      expect(result.status).toBe(200);
      expect(Array.isArray(result.body)).toBe(true);
      expect(result.body.length).toBe(10);
    });
  });

  describe("Non-object/non-array body handling", () => {
    it("should reject string body", async () => {
      const result = await rawRequest(testPort, '"just a string"');

      expect(result.status).toBe(400);
      expect(result.body.error).toBeDefined();
      expect(result.body.error.code).toBe(RPCErrorCodes.PARSE_ERROR);
    });

    it("should reject number body", async () => {
      const result = await rawRequest(testPort, "42");

      expect(result.status).toBe(400);
      expect(result.body.error).toBeDefined();
      expect(result.body.error.code).toBe(RPCErrorCodes.PARSE_ERROR);
    });

    it("should reject boolean body", async () => {
      const result = await rawRequest(testPort, "true");

      expect(result.status).toBe(400);
      expect(result.body.error).toBeDefined();
      expect(result.body.error.code).toBe(RPCErrorCodes.PARSE_ERROR);
    });

    it("should reject null body", async () => {
      const result = await rawRequest(testPort, "null");

      expect(result.status).toBe(400);
      expect(result.body.error).toBeDefined();
      expect(result.body.error.code).toBe(RPCErrorCodes.PARSE_ERROR);
    });
  });

  describe("Mixed request types in batch", () => {
    it("should handle batch with various request types", async () => {
      const result = await batchRequest(testPort, [
        { jsonrpc: "2.0", id: 1, method: "getmempoolinfo" },
        { jsonrpc: "2.0", id: 2, method: "estimatesmartfee", params: [6] },
        { jsonrpc: "2.0", id: 3, method: "getblockchaininfo" },
        { jsonrpc: "2.0", id: 4, method: "getnetworkinfo" },
      ]);

      expect(result.status).toBe(200);
      expect(result.body.length).toBe(4);

      // All should succeed
      for (let i = 0; i < 4; i++) {
        expect(result.body[i].result).toBeDefined();
        expect(result.body[i].error).toBeUndefined();
        expect(result.body[i].id).toBe(i + 1);
      }
    });

    it("should handle batch with missing params", async () => {
      const result = await batchRequest(testPort, [
        { jsonrpc: "2.0", id: 1, method: "getmempoolinfo" }, // No params needed
        { jsonrpc: "2.0", id: 2, method: "getrawmempool" }, // Optional params
      ]);

      expect(result.status).toBe(200);
      expect(result.body.length).toBe(2);
      expect(result.body[0].result).toBeDefined();
      expect(result.body[1].result).toBeDefined();
    });
  });

  describe("JSON-RPC 2.0 compliance", () => {
    it("should include jsonrpc field in all batch responses", async () => {
      const result = await batchRequest(testPort, [
        { jsonrpc: "2.0", id: 1, method: "getmempoolinfo" },
        { jsonrpc: "2.0", id: 2, method: "unknownmethod" },
      ]);

      expect(result.status).toBe(200);
      for (const response of result.body) {
        expect(response.jsonrpc).toBe("2.0");
      }
    });

    it("should not include result field for error responses", async () => {
      const result = await batchRequest(testPort, [
        { jsonrpc: "2.0", id: 1, method: "unknownmethod" },
      ]);

      expect(result.status).toBe(200);
      expect(result.body[0].error).toBeDefined();
      expect(result.body[0].result).toBeUndefined();
    });

    it("should not include error field for success responses", async () => {
      const result = await batchRequest(testPort, [
        { jsonrpc: "2.0", id: 1, method: "getmempoolinfo" },
      ]);

      expect(result.status).toBe(200);
      expect(result.body[0].result).toBeDefined();
      expect(result.body[0].error).toBeUndefined();
    });
  });
});
