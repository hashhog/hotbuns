/**
 * Tests for the JSON-RPC BigInt serializer.
 *
 * Today's RPC churn (PSBT/wallet stubs, Core 31.99 shape fields, etc.) shipped
 * with at least one handler that returns a `bigint`-typed field which trips
 * `JSON.stringify cannot serialize BigInt` in `src/rpc/server.ts:573:30`.
 * The fix: a `bigIntJsonReplacer` wired into both response-serialization sites
 * (single + batch) plus REST's `formatResponse`.
 *
 * Scope:
 * - Unit-test the replacer's two branches (number when ≤ MAX_SAFE_INTEGER,
 *   string otherwise) and its recursion through nested objects/arrays.
 * - End-to-end: register a method that returns a `bigint`-shaped result and
 *   confirm the response serializes cleanly through both the single-request
 *   path (line 587) and the batch path (line 565), exactly the lines that
 *   were throwing in the live fleet.
 */

import { describe, it, expect, beforeEach, afterEach } from "bun:test";
import {
  RPCServer,
  RPCServerConfig,
  RPCServerDeps,
  bigIntJsonReplacer,
} from "../rpc/server.js";
import { REGTEST } from "../consensus/params.js";

// ---------------------------------------------------------------------------
// Pure replacer tests
// ---------------------------------------------------------------------------

describe("bigIntJsonReplacer", () => {
  it("converts a small bigint to a number (≤ Number.MAX_SAFE_INTEGER)", () => {
    const obj = { fee: 1234567n };
    const json = JSON.stringify(obj, bigIntJsonReplacer);
    expect(json).toBe('{"fee":1234567}');
    expect(JSON.parse(json).fee).toBe(1234567);
  });

  it("converts MAX_SAFE_INTEGER bigint exactly at the boundary to number", () => {
    const obj = { val: BigInt(Number.MAX_SAFE_INTEGER) };
    const json = JSON.stringify(obj, bigIntJsonReplacer);
    // Boundary value: stays a number (no precision loss yet).
    expect(json).toBe(`{"val":${Number.MAX_SAFE_INTEGER}}`);
  });

  it("converts a > MAX_SAFE_INTEGER bigint to a decimal string (no precision loss)", () => {
    // 2^60 — clearly outside safe-integer range, where Bitcoin Core renders
    // chainwork / hashrate-like fields as strings to avoid float rounding.
    const big = 1n << 60n;
    const obj = { chainwork: big };
    const json = JSON.stringify(obj, bigIntJsonReplacer);
    expect(json).toBe(`{"chainwork":"${big.toString()}"}`);
    // Round-trip exact: we can rebuild the same bigint from the JSON string.
    expect(BigInt(JSON.parse(json).chainwork)).toBe(big);
  });

  it("converts a negative bigint below MIN_SAFE_INTEGER to a string", () => {
    const big = -(1n << 60n);
    const json = JSON.stringify({ x: big }, bigIntJsonReplacer);
    expect(json).toBe(`{"x":"${big.toString()}"}`);
  });

  it("recurses through nested objects + arrays", () => {
    const payload = {
      vsize: 250,
      // Mix: a `bigint` satoshi amount + a huge work counter.
      fees: { base: 5000n, total: 1n << 70n },
      utxos: [{ value: 100_000n }, { value: 200_000n }],
    };
    const json = JSON.stringify(payload, bigIntJsonReplacer);
    const parsed = JSON.parse(json);
    expect(parsed.vsize).toBe(250);
    expect(parsed.fees.base).toBe(5000);
    expect(parsed.fees.total).toBe((1n << 70n).toString());
    expect(parsed.utxos[0].value).toBe(100_000);
    expect(parsed.utxos[1].value).toBe(200_000);
  });

  it("does not throw on the un-fixed shape (regression for server.ts:573)", () => {
    // Reproduce the live throw: previously this would throw
    //   TypeError: JSON.stringify cannot serialize BigInt
    // The replacer eats it.
    const payload = { jsonrpc: "2.0", id: 1, result: { fee: 1234n } };
    expect(() => JSON.stringify(payload, bigIntJsonReplacer)).not.toThrow();
  });

  it("leaves non-bigint values untouched", () => {
    const payload = {
      str: "hello",
      n: 42,
      b: true,
      nul: null,
      arr: [1, "x", false],
    };
    const json = JSON.stringify(payload, bigIntJsonReplacer);
    expect(JSON.parse(json)).toEqual(payload);
  });
});

// ---------------------------------------------------------------------------
// Mock fleet (mirrors src/__tests__/rpc_batch.test.ts shape).
// ---------------------------------------------------------------------------

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
    return { size: 0, bytes: 0, minFeeRate: 1 };
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
    return { feeRate: 10, blocks: targetBlocks };
  }
}

class MockHeaderSync {
  getBestHeader() {
    return { hash: Buffer.alloc(32, 0), height: 100, chainWork: 1000n };
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

let portCounter = 19500;
function getTestPort(): number {
  return portCounter++;
}

// ---------------------------------------------------------------------------
// End-to-end: simulate the live throw and confirm the replacer is wired in.
// ---------------------------------------------------------------------------

describe("RPC server response BigInt safety", () => {
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
    // Register a method that mirrors the live failure mode: a wallet/UTXO
    // RPC handler that forgot to convert its `bigint` amounts to numbers.
    // Without `bigIntJsonReplacer` the response path crashes with
    // "JSON.stringify cannot serialize BigInt" at server.ts:573:30.
    (server as any).registerMethod(
      "test_returns_bigint",
      async () => ({
        smallSats: 1234n,
        bigWork: 1n << 80n,
        nested: { fee: 5000n },
        list: [{ value: 1n }, { value: 2n }],
      })
    );
    server.start();
  });

  afterEach(() => {
    server.stop();
  });

  it("serializes a bigint-returning RPC method without throwing (single request)", async () => {
    // This is the live-throw repro: handler returns `bigint`, single-request
    // dispatch hits `JSON.stringify(response, bigIntJsonReplacer)` at
    // src/rpc/server.ts:587.
    const response = await fetch(`http://127.0.0.1:${testPort}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "test_returns_bigint",
        params: [],
      }),
    });
    expect(response.status).toBe(200);
    const body = await response.json();
    expect(body.id).toBe(1);
    expect(body.error).toBeUndefined();
    // Small bigint → number (preserves Core's numeric shape for safe ints).
    expect(body.result.smallSats).toBe(1234);
    expect(body.result.nested.fee).toBe(5000);
    expect(body.result.list[0].value).toBe(1);
    // Huge bigint → decimal string (no precision loss).
    expect(body.result.bigWork).toBe((1n << 80n).toString());
  });

  it("serializes a bigint-returning RPC method without throwing (batch request)", async () => {
    // Batch path serializes via `JSON.stringify(responses, bigIntJsonReplacer)`
    // at src/rpc/server.ts:565 — same failure mode, different line.
    const response = await fetch(`http://127.0.0.1:${testPort}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify([
        { jsonrpc: "2.0", id: 1, method: "test_returns_bigint", params: [] },
        { jsonrpc: "2.0", id: 2, method: "test_returns_bigint", params: [] },
      ]),
    });
    expect(response.status).toBe(200);
    const body = await response.json();
    expect(Array.isArray(body)).toBe(true);
    expect(body.length).toBe(2);
    expect(body[0].result.smallSats).toBe(1234);
    expect(body[1].result.bigWork).toBe((1n << 80n).toString());
  });
});
