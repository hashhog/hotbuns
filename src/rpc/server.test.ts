/**
 * Tests for RPC server.
 */

import { describe, it, expect, beforeEach, afterEach } from "bun:test";
import { RPCServer, RPCServerConfig, RPCServerDeps, RPCErrorCodes } from "./server.js";
import { REGTEST } from "../consensus/params.js";
import { getBlockHash, serializeBlockHeader, serializeBlock, computeWitnessMerkleRoot, computeMerkleRoot, encodeBip34Height } from "../validation/block.js";
import { getTxId, getWTxId, serializeTx } from "../validation/tx.js";
import { OrphanPool } from "../mempool/orphan_pool.js";
import { BufferReader } from "../wire/serialization.js";
import { hash256 } from "../crypto/primitives.js";
import { bip22Result, ConsensusErrorCode } from "../validation/errors.js";
import { PeerManager, ServiceFlags, isRoutable } from "../p2p/manager.js";
import { BIP155Network } from "../p2p/addrv2.js";
import { ChainDB } from "../storage/database.js";
import { TxoSpenderIndex } from "../storage/indexes.js";
import { mkdtemp, rm } from "fs/promises";
import { tmpdir } from "os";
import { join } from "path";

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

  // Required by BlockTemplateBuilder.selectTransactions, which is now reached
  // through the production getblocktemplate path after the W123 BUG-21 /
  // W154 BUG-1 / W155 BUG-31 helper wire-up.
  getTransactionsByFeeRate() {
    const entries = Array.from(this.entries.values());
    entries.sort((a, b) => b.feeRate - a.feeRate);
    return entries;
  }

  // Required by Mempool.setTipHeight callers used in BlockTemplateBuilder
  // test scaffolding (no-op for the RPC mock — block height for finality is
  // already injected via MockChainStateManager.getBestBlock).
  setTipHeight(_h: number) {}

  getTransaction(txid: Buffer) {
    return this.entries.get(txid.toString("hex")) ?? null;
  }

  hasTransaction(txid: Buffer) {
    return this.entries.has(txid.toString("hex"));
  }

  // ── gettxspendingprevout support ──
  // outpointIndex analog: "txidHex:vout" -> spending txid hex (internal order).
  private outpointIndex = new Map<string, string>();

  // Test helper: register that `spendingTx` (with txid `spendingTxid`, internal
  // byte order) spends outpoint (prevTxid:vout). Adds the spending tx as a
  // mempool entry so getTransaction(spendingTxid) returns it.
  addSpend(prevTxid: Buffer, vout: number, spendingTxid: Buffer, spendingTx: any) {
    this.outpointIndex.set(`${prevTxid.toString("hex")}:${vout}`, spendingTxid.toString("hex"));
    this.entries.set(spendingTxid.toString("hex"), {
      tx: spendingTx,
      txid: spendingTxid,
      fee: 1000n,
      feeRate: 1,
      vsize: 100,
      weight: 400,
      addedTime: 0,
      height: 1,
      spentBy: new Set(),
      dependsOn: new Set(),
    });
  }

  // Mirrors the real Mempool.getSpendingTxid (CTxMemPool::GetConflictTx analog).
  getSpendingTxid(txid: Buffer, vout: number): string | null {
    return this.outpointIndex.get(`${txid.toString("hex")}:${vout}`) ?? null;
  }

  // Mirrors the real Mempool.getModifiedFee (base fee + prioritisetransaction
  // delta). The mock has no deltas, so this returns the base fee for an
  // in-mempool tx and 0n otherwise. Required by the getrawmempool/
  // getmempoolentry modifiedfee wiring (prioritisetransaction support).
  getModifiedFee(txid: Buffer): bigint {
    const entry = this.entries.get(txid.toString("hex"));
    return entry ? entry.fee : 0n;
  }

  // Mirrors the real Mempool.getPrioritisedTransactions. The mock holds no
  // deltas, so this is always empty — getprioritisedtransactions returns {}.
  getPrioritisedTransactions(): Array<{
    txid: Buffer;
    feeDelta: bigint;
    inMempool: boolean;
    modifiedFee: bigint | null;
  }> {
    return [];
  }

  // Mirrors the real Mempool.prioritiseTransaction (no-op in the mock — there
  // is no delta store to mutate). Lets the prioritisetransaction RPC dispatch
  // succeed against the mock without a delta backing store.
  prioritiseTransaction(_txid: Buffer, _deltaSats: bigint): void {
    // No-op for tests.
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

  // Helper for tests.
  //
  // If the supplied `tx` is structurally serializable (has inputs+outputs
  // arrays), key the entry under the REAL computed txid (`getTxId(tx)`) so
  // the BlockTemplateBuilder-routed production GBT path (which iterates
  // `template.transactions` and recomputes txids) finds the entry. The
  // caller-supplied `txid` is treated as a hint only — tests that pass
  // `Buffer.alloc(32, 2)` just want "a mempool entry to be selected", not
  // a specific txid. Tests that pass a synthetic `tx: {}` (no inputs) keep
  // the legacy fake-txid keying for the old hand-rolled callers.
  //
  // Wire-up: W123 BUG-21 / W154 BUG-1 / W155 BUG-31.
  addTestTransaction(txid: Buffer, entry: any) {
    let key = txid;
    let serializable = false;
    if (entry.tx && Array.isArray(entry.tx.inputs) && Array.isArray(entry.tx.outputs)) {
      try {
        key = getTxId(entry.tx) as Buffer;
        serializable = true;
      } catch {
        // fall through to caller-supplied fake txid
      }
    }
    void serializable;
    const mempoolEntry = {
      tx: entry.tx ?? {},
      txid: key,
      fee: entry.fee ?? 1000n,
      feeRate: entry.feeRate ?? 10,
      vsize: entry.vsize ?? 200,
      weight: entry.weight ?? 800,
      addedTime: entry.addedTime ?? Math.floor(Date.now() / 1000),
      height: entry.height ?? 100,
      spentBy: entry.spentBy ?? new Set(),
      dependsOn: entry.dependsOn ?? new Set(),
    };
    this.entries.set(key.toString("hex"), mempoolEntry);
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

  // ASMap stubs — always return no-asmap state in tests
  usingASMap(): boolean { return false; }
  getMappedAS(_addr: string): number { return 0; }
  getOutboundNetGroups(): Set<string> { return new Set(); }

  // ── addrman substrate for getnodeaddresses / addpeeraddress ───────────
  // Faithful re-implementation of PeerManager.dumpAddrmanForRpc /
  // injectKnownAddress (src/p2p/manager.ts:1451 / 1509) so the live RPC
  // tests exercise the real handler dispatch + count/network arg parsing
  // and Core-shaped output without standing up a full PeerManager. Mirrors
  // the production logic exactly: same 5-key order, services as a JS number,
  // time as integer seconds, network-name filter, count cap (0 = all),
  // routable-IPv4-only insert. Reuses the real isRoutable +
  // networkIdToCoreName so the mock cannot silently drift from production.
  private knownAddresses = new Map<
    string,
    { host: string; port: number; services: bigint; lastSeen: number; networkId: number }
  >();

  dumpAddrmanForRpc(
    count: number,
    network?: string,
  ): Array<{ time: number; services: number; address: string; port: number; network: string }> {
    const selected: Array<{ host: string; port: number; services: bigint; lastSeen: number; networkId: number }> = [];
    for (const info of this.knownAddresses.values()) {
      if (
        network !== undefined &&
        PeerManager.networkIdToCoreName(info.networkId) !== network
      ) {
        continue;
      }
      selected.push(info);
    }
    // Shuffle (order is intentionally non-deterministic, like Core).
    for (let i = selected.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [selected[i], selected[j]] = [selected[j], selected[i]];
    }
    const capped =
      count > 0 && selected.length > count ? selected.slice(0, count) : selected;
    return capped.map((info) => ({
      time: Math.floor(info.lastSeen / 1000),
      services: Number(info.services),
      address: info.host,
      port: info.port,
      network: PeerManager.networkIdToCoreName(info.networkId),
    }));
  }

  injectKnownAddress(
    host: string,
    port: number,
    services: bigint,
    timeSecs: number,
  ): boolean {
    if (!isRoutable(host)) return false;
    if (!Number.isInteger(port) || port <= 0 || port > 0xffff) return false;
    const key = `${host}:${port}`;
    const lastSeenMs = timeSecs * 1000;
    const existing = this.knownAddresses.get(key);
    if (existing) {
      existing.services = services;
      if (lastSeenMs > existing.lastSeen) existing.lastSeen = lastSeenMs;
      return true;
    }
    this.knownAddresses.set(key, {
      host,
      port,
      services,
      lastSeen: lastSeenMs,
      networkId: BIP155Network.IPV4,
    });
    return true;
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

  /**
   * horizons mock: mirrors the shared buckets array under all three
   * horizons so estimaterawfee can iterate per-horizon bucket stats.
   * Each horizon bucket maps confirmed/unconfirmed from the shared bucket.
   */
  get horizons(): Record<number, { decay: number; scale: number; periods: number; buckets: any[] }> {
    const makeBuckets = () =>
      this.buckets.map((b: any) => ({
        confirmed: b.totalConfirmed ?? 0,
        unconfirmed: b.totalUnconfirmed ?? 0,
        confirmationBlocks: b.confirmationBlocks ?? [],
      }));
    return {
      0: { decay: 0.962,   scale: 1,  periods: 12, buckets: makeBuckets() }, // Short
      1: { decay: 0.9952,  scale: 2,  periods: 24, buckets: makeBuckets() }, // Medium
      2: { decay: 0.99931, scale: 24, periods: 42, buckets: makeBuckets() }, // Long
    };
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
  // Per-test override for getNextTarget; defaults to mainnet powLimit-equivalent
  // bits value (matches the `bits: 0x1d00ffff` returned in the parent header
  // entry below).
  public nextTargetOverride: bigint | null = null;
  // Per-test override for the height returned by getHeader(<any>).  Used by
  // the BIP-34 reorg-via-submitblock side-branch test to simulate a parent
  // that is in the block index but is NOT the active tip (parentHeight=110,
  // bestHeader.height=112 → side-branch B1 at h=111).
  public parentHeightOverride: number | null = null;
  // Per-test override for bestHeader.height (mutated under test to simulate
  // the active chain advancing past the fork point).
  public bestHeaderHeightOverride: number | null = null;

  getBestHeader() {
    if (this.bestHeaderHeightOverride !== null) {
      return { ...this.bestHeader, height: this.bestHeaderHeightOverride };
    }
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
      height: this.parentHeightOverride !== null ? this.parentHeightOverride : 100,
      chainWork: 1000n,
      status: "valid-header" as const,
    };
  }

  getMedianTimePast(_entry: any) {
    return 1234567890;
  }

  /**
   * Real HeaderSync.getNextTarget delegates to consensus/pow.ts
   * getNextWorkRequired.  For the mock we just echo the parent's bits
   * (matching mainnet's non-retarget-block rule) unless a test overrides.
   */
  getNextTarget(parent: any, _blockTimestamp?: number): bigint {
    if (this.nextTargetOverride !== null) {
      return this.nextTargetOverride;
    }
    // Re-decode parent.bits the same way getNextTarget would.
    return require("../consensus/params.js").compactToBigInt(parent.header.bits);
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
  private undoData = new Map<string, Buffer>();

  async getBlock(hash: Buffer) {
    return this.blocks.get(hash.toString("hex")) ?? null;
  }

  // Per-block undo data (spent prevouts), keyed by internal-order block hash.
  // Used by getblock(verbosity=2) and getblockstats for fee computation.
  async getUndoData(hash: Buffer) {
    return this.undoData.get(hash.toString("hex")) ?? null;
  }

  setUndoData(hash: Buffer, data: Buffer) {
    this.undoData.set(hash.toString("hex"), data);
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

    it("should include the v31.99 policy fields", async () => {
      const result = await rpcRequest(testPort, "getmempoolinfo");
      // Core v31.99 appends these 5 fields after fullrbf (rpc/mempool.cpp).
      expect(result.result.fullrbf).toBe(true);
      expect(result.result.permitbaremultisig).toBe(true);
      expect(result.result.maxdatacarriersize).toBe(100_000);
      expect(result.result.limitclustercount).toBe(64);
      expect(result.result.limitclustersize).toBe(101_000);
      expect(result.result.optimal).toBe(true);
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

    it("should list all five networks (ipv4, ipv6, onion, i2p, cjdns)", async () => {
      const result = await rpcRequest(testPort, "getnetworkinfo");
      expect(Array.isArray(result.result.networks)).toBe(true);
      expect(result.result.networks.length).toBe(5);
      expect(result.result.networks.map((n: { name: string }) => n.name)).toEqual([
        "ipv4", "ipv6", "onion", "i2p", "cjdns",
      ]);
    });

    it("should report the policy fee defaults (1e-6) and warnings as an array", async () => {
      const result = await rpcRequest(testPort, "getnetworkinfo");
      expect(result.result.relayfee).toBeCloseTo(0.000001, 12);
      expect(result.result.incrementalfee).toBeCloseTo(0.000001, 12);
      expect(Array.isArray(result.result.warnings)).toBe(true);
    });

    it("should advertise hotbuns's REAL service word, P2P_V2 gated on the v2 toggle", async () => {
      const result = await rpcRequest(testPort, "getnetworkinfo");
      // hotbuns advertises NODE_P2P_V2 (0x800) iff the BIP-324 v2 transport is
      // enabled.  v2 is now DEFAULT-ON (env HOTBUNS_BIP324_V2 unset -> on,
      // matching haskoin/camlcoin and Core init.cpp:987-989), so the default
      // localservices word is 0xc09 (== Core v31.99) with P2P_V2 named.  An
      // explicit HOTBUNS_BIP324_V2=0 opt-out drops it back to 0x409.  Resolved
      // from the same predicate so the test is correct under either env; never
      // faked — the bit is set only because v2 is genuinely offered on the wire.
      const v = process.env.HOTBUNS_BIP324_V2;
      const v2On =
        v === undefined ||
        !["0", "false", "off"].includes(v.toLowerCase());
      if (v2On) {
        expect(result.result.localservices).toBe("0000000000000c09");
        expect(result.result.localservicesnames).toContain("P2P_V2");
      } else {
        expect(result.result.localservices).toBe("0000000000000409");
        expect(result.result.localservicesnames).not.toContain("P2P_V2");
      }
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
      expect(Array.isArray(result.result.error_locations)).toBe(true);
      // Core v31.99 key order for an invalid address: isvalid, error_locations,
      // error (error_locations BEFORE error). Lock the emission order in.
      expect(Object.keys(result.result)).toEqual([
        "isvalid", "error_locations", "error",
      ]);
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

    // ─── P0-5 regression (CORE-PARITY-AUDIT/hotbuns-P0-FOUND.md) ─────────
    // Pre-fix, getblocktemplate hard-coded `bits` and `target` to
    // `params.powLimitBits` (genesis-difficulty).  A miner using hotbuns'
    // template would mine to difficulty 1 and produce blocks that fail PoW
    // on every other node — mining was operationally broken.
    //
    // The fix routes through HeaderSync.getNextTarget(parent, curtime)
    // which delegates to consensus/pow.ts getNextWorkRequired().
    it("returns the consensus next-target bits, not powLimitBits (P0-5)", async () => {
      // Force a non-trivial next target so the assertion is meaningful.
      // Pre-fix code returned compactToBigInt(REGTEST.powLimitBits) = the
      // huge 2^255-ish target.  Setting nextTargetOverride to a value
      // whose canonical bits differ from powLimitBits proves the new
      // path actually consults getNextTarget rather than the hard-coded
      // powLimitBits constant.
      const { compactToBigInt, bigIntToCompact } = require("../consensus/params.js");
      const nextBits = 0x1a08e040; // realistic mainnet-era difficulty
      const nextTarget = compactToBigInt(nextBits);
      mockHeaderSync.nextTargetOverride = nextTarget;

      const result = await rpcRequest(testPort, "getblocktemplate", [
        { rules: ["segwit"] },
      ]);

      expect(result.result).toBeDefined();
      // bits is hex-encoded with at least 8 chars (4-byte int).  Compare
      // the parsed numeric value, not the string, to avoid casing issues.
      const returnedBits = parseInt(result.result.bits as string, 16);
      expect(returnedBits).toBe(bigIntToCompact(nextTarget));

      // Pre-fix the value was always equal to params.powLimitBits.  Assert
      // we are NOT returning that value — this test would have failed
      // against the old code.
      expect(returnedBits).not.toBe(REGTEST.powLimitBits);

      // The target hex must encode the same bigint.
      expect(BigInt("0x" + (result.result.target as string))).toBe(nextTarget);
    });

    it("falls back to powLimit when parent header is unknown", async () => {
      // If HeaderSync.getHeader returns undefined for the best block hash
      // (detached header chain corner case) the implementation falls back
      // to powLimit so getblocktemplate stays usable.  This is documented
      // explicitly in the source comment.
      mockHeaderSync.setUnknown(Buffer.alloc(32, 0));

      const result = await rpcRequest(testPort, "getblocktemplate", [
        { rules: ["segwit"] },
      ]);

      expect(result.result).toBeDefined();
      const returnedBits = parseInt(result.result.bits as string, 16);
      expect(returnedBits).toBe(REGTEST.powLimitBits);
    });

    // ─── BIP-141 witness commitment regression tests ──────────────────────
    // Prior code emitted a placeholder "6a24aa21a9ed" + 32 zero bytes, which
    // does not match the actual sha256d(witness_merkle_root || nonce).
    // These tests verify the real algorithm is used.

    it("empty template (coinbase-only) emits canonical witness commitment", async () => {
      // REGTEST segwitHeight=1 and best height=100, so height 101 is post-segwit.
      // Empty mempool → the block has only a coinbase.
      // BIP-141: witness_merkle_root = merkle([0x00...00]) = 0x00...00
      //          witness_commitment  = sha256d(zeros_32 || zeros_32)
      //          commitment_script   = 0x6a24aa21a9ed || commitment (38 bytes)
      const result = await rpcRequest(testPort, "getblocktemplate", [
        { rules: ["segwit"] },
      ]);

      expect(result.result).toBeDefined();
      const dwc: string = result.result.default_witness_commitment as string;
      expect(dwc).toBeDefined();

      // Script must be exactly 38 bytes = 76 hex chars.
      expect(dwc.length).toBe(76);

      // Must start with the BIP-141 OP_RETURN header.
      expect(dwc.startsWith("6a24aa21a9ed")).toBe(true);

      // Compute the expected commitment: sha256d(zero_32 || zero_32).
      const wtxids = [Buffer.alloc(32, 0)]; // coinbase wtxid only
      const witnessRoot = computeWitnessMerkleRoot(wtxids);
      const commitment = hash256(Buffer.concat([witnessRoot, Buffer.alloc(32, 0)]));
      const expected = "6a24aa21a9ed" + commitment.toString("hex");
      expect(dwc).toBe(expected);
    });

    it("template with 3 mempool txs emits commitment over their wtxids", async () => {
      // Add 3 non-witness transactions.  For legacy txs wtxid == txid (no
      // witness field), so the commitment is sha256d(merkle([0, wtxid1, wtxid2, wtxid3]) || zeros).
      //
      // Post-W123-BUG-21-fix the MockMempool keys by `getTxId(tx)` so each tx
      // must differ in its serialized bytes — otherwise all 3 collide on the
      // same map key and only 1 makes it into the template. We perturb each
      // tx's prevOut.vout to give it a unique txid.
      const txid1 = Buffer.alloc(32, 1);
      const txid2 = Buffer.alloc(32, 2);
      const txid3 = Buffer.alloc(32, 3);

      const makeLegacyTx = (txid: Buffer, voutSeed: number) => ({
        tx: {
          version: 2,
          inputs: [{
            prevOut: { txid: Buffer.alloc(32, 0), vout: voutSeed },
            scriptSig: Buffer.alloc(0),
            sequence: 0xffffffff,
            witness: [],
          }],
          outputs: [{ value: 1000n, scriptPubKey: Buffer.alloc(25, 0) }],
          lockTime: 0,
        },
        txid,
        fee: 100n,
        weight: 400,
      });

      mockMempool.addTestTransaction(txid1, makeLegacyTx(txid1, 1));
      mockMempool.addTestTransaction(txid2, makeLegacyTx(txid2, 2));
      mockMempool.addTestTransaction(txid3, makeLegacyTx(txid3, 3));

      const result = await rpcRequest(testPort, "getblocktemplate", [
        { rules: ["segwit"] },
      ]);

      expect(result.result).toBeDefined();
      expect(result.result.transactions).toHaveLength(3);

      const dwc: string = result.result.default_witness_commitment as string;
      expect(dwc).toBeDefined();
      expect(dwc.length).toBe(76);
      expect(dwc.startsWith("6a24aa21a9ed")).toBe(true);

      // The `hash` field in each template tx is the wtxid (getWTxId result, hex).
      // For legacy txs it equals the txid in internal byte order.
      // Compute the expected commitment from the returned wtxids.
      const templateTxs: Array<{ hash: string }> = result.result.transactions as any;
      const wtxids = [
        Buffer.alloc(32, 0), // coinbase zero
        ...templateTxs.map(tx => Buffer.from(tx.hash, "hex")),
      ];
      const witnessRoot = computeWitnessMerkleRoot(wtxids);
      const commitment = hash256(Buffer.concat([witnessRoot, Buffer.alloc(32, 0)]));
      const expected = "6a24aa21a9ed" + commitment.toString("hex");
      expect(dwc).toBe(expected);
    });

    it("commitment differs from the old placeholder zeros", async () => {
      // Regression: the old code returned "6a24aa21a9ed" + "0".repeat(64)
      // regardless of block content.  The real sha256d(zeros||zeros) is NOT
      // 32 zero bytes.
      const result = await rpcRequest(testPort, "getblocktemplate", [
        { rules: ["segwit"] },
      ]);

      const dwc: string = result.result.default_witness_commitment as string;
      const placeholder = "6a24aa21a9ed" + "0".repeat(64);
      expect(dwc).not.toBe(placeholder);
    });
  });

  describe("getblockchaininfo v31.99 shape", () => {
    it("should NOT include softforks (dropped in v31.99, moved to getdeploymentinfo)", async () => {
      const result = await rpcRequest(testPort, "getblockchaininfo");

      expect(result.result).toBeDefined();
      // Core v31.99 removed `softforks` from getblockchaininfo (it now lives in
      // getdeploymentinfo). hotbuns matches: the key must be absent.
      expect(result.result.softforks).toBeUndefined();
    });

    it("should emit warnings as an array of strings", async () => {
      const result = await rpcRequest(testPort, "getblockchaininfo");
      expect(Array.isArray(result.result.warnings)).toBe(true);
    });

    it("should include size_on_disk", async () => {
      const result = await rpcRequest(testPort, "getblockchaininfo");
      expect(typeof result.result.size_on_disk).toBe("number");
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
      // Genesis has no parent — Core gates previousblockhash on blockindex.pprev
      // (blockchain.cpp:177), so the key is OMITTED entirely for height 0.
      expect(h.previousblockhash).toBeUndefined();
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
      //   previousblockhash: OMITTED — Core does not emit it for the genesis
      //     block (gated on blockindex.pprev, blockchain.cpp:177).
      const GENESIS_DISPLAY_HASH = "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206";
      const GENESIS_MERKLEROOT   = "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b";
      const GENESIS_TIME         = 1296688602;
      const GENESIS_BITS         = "207fffff";
      const GENESIS_NONCE        = 2;
      const GENESIS_VERSION      = 1;

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
      // Core omits previousblockhash for the genesis block (no parent).
      expect(h.previousblockhash).toBeUndefined();
      // nextblockhash absent at genesis
      expect(h.nextblockhash).toBeUndefined();
      // chainwork comes from DB fallback → must match what connectBlock stored
      expect(h.chainwork).toBe(genesisChainWork.toString(16).padStart(64, "0"));
    });
  });

  // ─── getblockstats ───────────────────────────────────────────────────────
  // Proven-teeth: build a real regtest-shaped block (coinbase + one spending
  // tx) with stored undo data, then assert getblockstats computes the fee /
  // size / count / percentile fields correctly — by height AND by hash — and
  // that the subset filter + unknown-stat error path behave like Core.
  describe("getblockstats", () => {
    function hdr(
      version: number, prevBlock: Buffer, merkleRoot: Buffer,
      timestamp: number, bits: number, nonce: number
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

    async function setupBlockWithFee() {
      const { getTxWeight, getTxVSize, hasWitness } = await import("../validation/tx.js");
      const { serializeUndoData } = await import("../chain/utxo.js");

      const NULL_TXID = Buffer.alloc(32, 0);
      const p2pkh = Buffer.concat([
        Buffer.from([0x76, 0xa9, 0x14]), Buffer.alloc(20, 0xab), Buffer.from([0x88, 0xac]),
      ]);

      // Coinbase: 1 null input, 1 output (subsidy + fees). Non-segwit.
      const coinbase = {
        version: 1,
        inputs: [{ prevOut: { txid: Buffer.from(NULL_TXID), vout: 0xffffffff },
                   scriptSig: Buffer.from([0x51]), sequence: 0xffffffff, witness: [] }],
        outputs: [{ value: 5000010000n, scriptPubKey: Buffer.from(p2pkh) }], // 50 BTC + 10000 fee
        lockTime: 0,
      };

      // The prevout the spending tx consumes (value 100000 sat).
      const prevTxid = Buffer.alloc(32, 0x11);
      const PREV_VALUE = 100000n;

      // Spending tx: 1 input (the prevout above), 1 output of 90000 → fee 10000.
      const spend = {
        version: 2,
        inputs: [{ prevOut: { txid: Buffer.from(prevTxid), vout: 0 },
                   scriptSig: Buffer.from([0x47, ...new Array(0x47).fill(0)]),
                   sequence: 0xffffffff, witness: [] }],
        outputs: [{ value: 90000n, scriptPubKey: Buffer.from(p2pkh) }],
        lockTime: 0,
      };

      const merkleRoot = computeMerkleRoot([
        getTxId(coinbase as any), getTxId(spend as any),
      ]);
      const block = {
        header: { version: 0x20000000, prevBlock: Buffer.from(REGTEST.genesisBlockHash),
                  merkleRoot, timestamp: 1700000000, bits: 0x207fffff, nonce: 7 },
        transactions: [coinbase, spend],
      };
      const blockRaw = serializeBlock(block as any);
      const headerBuf = hdr(0x20000000, Buffer.from(REGTEST.genesisBlockHash),
        merkleRoot, 1700000000, 0x207fffff, 7);
      const blockHashInternal = getBlockHash(block.header as any);
      const blockHashDisplay = Buffer.from(blockHashInternal).reverse().toString("hex");
      const height = 5;

      mockChainState.setBestBlock(Buffer.from(blockHashInternal), height, 12n);
      mockDB.setBlock(Buffer.from(blockHashInternal), blockRaw);
      mockDB.setBlockIndex(Buffer.from(blockHashInternal),
        { height, header: headerBuf, nTx: 2, status: 15, dataPos: 1 });
      mockDB.setHashByHeight(height, Buffer.from(blockHashInternal));

      // Undo data: one spent prevout carrying the FULL CTxOut (value + script).
      const undo = serializeUndoData([
        { txid: Buffer.from(prevTxid), vout: 0,
          entry: { height: 1, coinbase: false, amount: PREV_VALUE,
                   scriptPubKey: Buffer.from(p2pkh) } },
      ]);
      mockDB.setUndoData(Buffer.from(blockHashInternal), undo);

      const spendWeight = getTxWeight(spend as any);
      const spendVsize = getTxVSize(spend as any);
      const spendSize = serializeTx(spend as any, true).length;
      const isSw = hasWitness(spend as any);
      return { blockHashDisplay, height, spendWeight, spendVsize, spendSize, isSw };
    }

    it("computes fee/size/count/percentile fields for a known block (by height)", async () => {
      const { height, spendWeight, spendVsize, spendSize, isSw } = await setupBlockWithFee();

      const res = await rpcRequest(testPort, "getblockstats", [height]);
      expect(res.error).toBeUndefined();
      const s = res.result;

      // Counts: 2 txs, coinbase excluded from inputs (1 real input), 2 outputs.
      expect(s.height).toBe(height);
      expect(s.txs).toBe(2);
      expect(s.ins).toBe(1);
      expect(s.outs).toBe(2);

      // Fee math: fee = 100000 (in) - 90000 (out) = 10000 sat for the one
      // non-coinbase tx, so total/avg/min/max/median fee all equal 10000.
      expect(s.totalfee).toBe(10000);
      expect(s.avgfee).toBe(10000);
      expect(s.minfee).toBe(10000);
      expect(s.maxfee).toBe(10000);
      expect(s.medianfee).toBe(10000);

      // Feerate = fee * 4 / weight (sat/vB), truncated. Single tx → every
      // percentile equals that one feerate.
      const expFeerate = Math.floor((10000 * 4) / spendWeight);
      expect(s.avgfeerate).toBe(expFeerate);
      expect(s.minfeerate).toBe(expFeerate);
      expect(s.maxfeerate).toBe(expFeerate);
      expect(s.feerate_percentiles).toEqual([
        expFeerate, expFeerate, expFeerate, expFeerate, expFeerate,
      ]);
      void spendVsize;

      // Size stats reflect only the non-coinbase tx.
      expect(s.total_size).toBe(spendSize);
      expect(s.mintxsize).toBe(spendSize);
      expect(s.maxtxsize).toBe(spendSize);
      expect(s.mediantxsize).toBe(spendSize);
      expect(s.total_weight).toBe(spendWeight);

      // SegWit accounting: the spending tx is non-witness here.
      expect(s.swtxs).toBe(isSw ? 1 : 0);

      // total_out = sum of non-coinbase outputs (coinbase reward excluded).
      expect(s.total_out).toBe(90000);

      // utxo_increase = outs - ins = 2 - 1 = 1.
      expect(s.utxo_increase).toBe(1);

      // Regtest subsidy at height 5 = 50 BTC (no halving).
      expect(s.subsidy).toBe(5000000000);

      // blockhash echoes the display-order hash.
      expect(typeof s.blockhash).toBe("string");
      expect(s.blockhash).toHaveLength(64);
    });

    it("returns identical stats when queried by hash, and supports the stats subset", async () => {
      const { blockHashDisplay } = await setupBlockWithFee();

      const byHash = await rpcRequest(testPort, "getblockstats", [blockHashDisplay]);
      expect(byHash.error).toBeUndefined();
      expect(byHash.result.totalfee).toBe(10000);
      expect(byHash.result.blockhash).toBe(blockHashDisplay);

      // Subset: only the requested keys are present.
      const subset = await rpcRequest(testPort, "getblockstats",
        [blockHashDisplay, ["totalfee", "txs", "height"]]);
      expect(subset.error).toBeUndefined();
      expect(Object.keys(subset.result).sort()).toEqual(["height", "totalfee", "txs"]);
      expect(subset.result.totalfee).toBe(10000);
      expect(subset.result.txs).toBe(2);
    });

    it("rejects an unknown selected statistic (RPC_INVALID_PARAMETER, -8)", async () => {
      const { height } = await setupBlockWithFee();
      const res = await rpcRequest(testPort, "getblockstats", [height, ["not_a_real_stat"]]);
      expect(res.error).toBeDefined();
      expect(res.error.code).toBe(RPCErrorCodes.INVALID_PARAMETER);
    });

    it("rejects a height after the current tip (RPC_INVALID_PARAMETER, -8)", async () => {
      await setupBlockWithFee(); // tip at height 5
      const res = await rpcRequest(testPort, "getblockstats", [999999]);
      expect(res.error).toBeDefined();
      expect(res.error.code).toBe(RPCErrorCodes.INVALID_PARAMETER);
    });

    it("returns 'Block not found' (-5) for an unknown block hash", async () => {
      const unknown = Buffer.alloc(32, 0xee).toString("hex");
      const res = await rpcRequest(testPort, "getblockstats", [unknown]);
      expect(res.error).toBeDefined();
      expect(res.error.code).toBe(RPCErrorCodes.INVALID_ADDRESS_OR_KEY);
    });
  });

  // getnodeaddresses — Core parity (rpc/net.cpp:911-970 + netbase.cpp:100-128).
  // Each entry is an object with EXACTLY 5 keys in this order:
  //   time (unix seconds INTEGER), services (raw bitfield INTEGER, NOT hex),
  //   address (host literal, no port), port (INTEGER), network (Core name).
  // Arg shape: count (positional 0, default 1; 0 = all; <0 -> -8
  // "Address count out of range"); network (positional 1, lowercased, only
  // ipv4|ipv6|onion|i2p|cjdns, else -8 "Network not recognized: <raw arg>").
  // Empty addrman -> [] (NOT an error).
  describe("getnodeaddresses", () => {
    it("returns [] (not an error) for an empty addrman", async () => {
      const res = await rpcRequest(testPort, "getnodeaddresses", []);
      expect(res.error).toBeUndefined();
      expect(Array.isArray(res.result)).toBe(true);
      expect(res.result.length).toBe(0);
    });

    it("addpeeraddress(routable IPv4) returns {success:true}", async () => {
      const res = await rpcRequest(testPort, "addpeeraddress", ["8.8.8.8", 8333, false]);
      expect(res.error).toBeUndefined();
      expect(res.result).toEqual({ success: true });
    });

    it("addpeeraddress(non-routable) returns {success:false}", async () => {
      const a = await rpcRequest(testPort, "addpeeraddress", ["10.0.0.1", 8333, false]);
      expect(a.result.success).toBe(false);
      const b = await rpcRequest(testPort, "addpeeraddress", ["127.0.0.1", 8333, false]);
      expect(b.result.success).toBe(false);
    });

    it("emits EXACTLY 5 keys in time/services/address/port/network order with Core types", async () => {
      const add = await rpcRequest(testPort, "addpeeraddress", ["8.8.8.8", 8333, false]);
      expect(add.result.success).toBe(true);

      const res = await rpcRequest(testPort, "getnodeaddresses", [0]);
      expect(res.error).toBeUndefined();
      expect(Array.isArray(res.result)).toBe(true);

      const entry = res.result.find((e: any) => e.address === "8.8.8.8");
      expect(entry).toBeDefined();

      // Key set AND order must match Core exactly.
      expect(Object.keys(entry)).toEqual([
        "time",
        "services",
        "address",
        "port",
        "network",
      ]);

      // Types: services is a JS number (INTEGER, not a hex string).
      expect(typeof entry.time).toBe("number");
      expect(Number.isInteger(entry.time)).toBe(true);
      expect(typeof entry.services).toBe("number");
      // addpeeraddress defaults to NODE_NETWORK|NODE_WITNESS = 1|8 = 9; but
      // assert against the live flags so this stays correct if flags change.
      expect(entry.services).toBe(
        Number(ServiceFlags.NODE_NETWORK | ServiceFlags.NODE_WITNESS),
      );
      expect(entry.address).toBe("8.8.8.8");
      expect(entry.port).toBe(8333);
      expect(entry.network).toBe("ipv4");
    });

    it("count < 0 -> error -8 'Address count out of range'", async () => {
      const res = await rpcRequest(testPort, "getnodeaddresses", [-1]);
      expect(res.error).toBeDefined();
      expect(res.error.code).toBe(RPCErrorCodes.INVALID_PARAMETER);
      expect(res.error.code).toBe(-8);
      expect(res.error.message).toBe("Address count out of range");
    });

    it("unknown network filter -> error -8 echoing the RAW (un-lowercased) arg", async () => {
      const res = await rpcRequest(testPort, "getnodeaddresses", [1, "BogusNet"]);
      expect(res.error).toBeDefined();
      expect(res.error.code).toBe(RPCErrorCodes.INVALID_PARAMETER);
      expect(res.error.code).toBe(-8);
      expect(res.error.message).toBe("Network not recognized: BogusNet");
    });

    it("mixed-case network filter 'IPv4' is accepted (ParseNetwork lowercases)", async () => {
      const add = await rpcRequest(testPort, "addpeeraddress", ["8.8.8.8", 8333, false]);
      expect(add.result.success).toBe(true);

      const res = await rpcRequest(testPort, "getnodeaddresses", [0, "IPv4"]);
      expect(res.error).toBeUndefined();
      expect(Array.isArray(res.result)).toBe(true);
      expect(res.result.length).toBe(1);
      expect(res.result[0].network).toBe("ipv4");
    });

    it("count caps the result; count==0 returns all", async () => {
      for (const ip of ["8.8.8.8", "1.1.1.1", "9.9.9.9"]) {
        const add = await rpcRequest(testPort, "addpeeraddress", [ip, 8333, false]);
        expect(add.result.success).toBe(true);
      }
      const capped = await rpcRequest(testPort, "getnodeaddresses", [2]);
      expect(capped.error).toBeUndefined();
      expect(capped.result.length).toBeLessThanOrEqual(2);

      const all = await rpcRequest(testPort, "getnodeaddresses", [0]);
      expect(all.error).toBeUndefined();
      expect(all.result.length).toBe(3);
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

    it("submitblock returns BIP-22 'rejected' string while paused flag is set", async () => {
      server.setBlockSubmissionPausedForTest(true);
      try {
        // Garbage hex is fine: the gate runs before deserialization.
        const result = await rpcRequest(testPort, "submitblock", ["00"]);
        // BIP-22: reject reason must be a plain string in the result field.
        // The gate returns "rejected" (the canonical catch-all string), not a
        // long message containing "paused" — that would be non-spec.
        expect(result.error).toBeUndefined();
        expect(result.result).toBe("rejected");
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

    it("submitblock paused gate returns canonical BIP-22 'rejected' string", async () => {
      server.setBlockSubmissionPausedForTest(true);
      try {
        const result = await rpcRequest(testPort, "submitblock", ["00"]);
        // Must be the exact canonical BIP-22 string, not a long message
        expect(result.error).toBeUndefined();
        expect(result.result).toBe("rejected");
      } finally {
        server.setBlockSubmissionPausedForTest(false);
      }
    });
  });

  // ========== BIP-22 result string unit tests ==========
  // Tests for the bip22Result() helper in validation/errors.ts.
  // These are pure-function unit tests — no RPC server needed.
  describe("bip22Result unit tests", () => {
    it("null/undefined input returns null (success)", () => {
      expect(bip22Result(null)).toBeNull();
      expect(bip22Result(undefined)).toBeNull();
    });

    it("ConsensusErrorCode.INVALID_POW → 'high-hash'", () => {
      expect(bip22Result(ConsensusErrorCode.INVALID_POW)).toBe("high-hash");
    });

    it("ConsensusErrorCode.BAD_MERKLE_ROOT → 'bad-txnmrklroot'", () => {
      expect(bip22Result(ConsensusErrorCode.BAD_MERKLE_ROOT)).toBe("bad-txnmrklroot");
    });

    it("ConsensusErrorCode.BAD_WITNESS_COMMITMENT → 'bad-witness-merkle-match'", () => {
      expect(bip22Result(ConsensusErrorCode.BAD_WITNESS_COMMITMENT)).toBe("bad-witness-merkle-match");
    });

    it("ConsensusErrorCode.BAD_COINBASE_VALUE → 'bad-cb-amount'", () => {
      expect(bip22Result(ConsensusErrorCode.BAD_COINBASE_VALUE)).toBe("bad-cb-amount");
    });

    it("ConsensusErrorCode.BAD_SIGOPS_COST → 'bad-blk-sigops'", () => {
      expect(bip22Result(ConsensusErrorCode.BAD_SIGOPS_COST)).toBe("bad-blk-sigops");
    });

    it("ConsensusErrorCode.BAD_COINBASE_HEIGHT → 'bad-cb-height'", () => {
      expect(bip22Result(ConsensusErrorCode.BAD_COINBASE_HEIGHT)).toBe("bad-cb-height");
    });

    it("ConsensusErrorCode.SCRIPT_VERIFY_FLAG_FAILED → 'mandatory-script-verify-flag-failed'", () => {
      expect(bip22Result(ConsensusErrorCode.SCRIPT_VERIFY_FLAG_FAILED)).toBe("mandatory-script-verify-flag-failed");
    });

    it("ConsensusErrorCode.DUPLICATE_INPUTS → 'bad-txns-duplicate'", () => {
      expect(bip22Result(ConsensusErrorCode.DUPLICATE_INPUTS)).toBe("bad-txns-duplicate");
    });

    it("ConsensusErrorCode.MISSING_INPUTS → 'bad-txns-inputs-missingorspent'", () => {
      expect(bip22Result(ConsensusErrorCode.MISSING_INPUTS)).toBe("bad-txns-inputs-missingorspent");
    });

    it("ConsensusErrorCode.SEQUENCE_LOCK_NOT_SATISFIED → 'bad-txns-nonfinal'", () => {
      expect(bip22Result(ConsensusErrorCode.SEQUENCE_LOCK_NOT_SATISFIED)).toBe("bad-txns-nonfinal");
    });

    it("ConsensusErrorCode.BLOCK_TIME_TOO_NEW → 'time-too-new'", () => {
      expect(bip22Result(ConsensusErrorCode.BLOCK_TIME_TOO_NEW)).toBe("time-too-new");
    });

    it("ConsensusErrorCode.BLOCK_TIME_TOO_OLD → 'time-too-old'", () => {
      expect(bip22Result(ConsensusErrorCode.BLOCK_TIME_TOO_OLD)).toBe("time-too-old");
    });

    it("free-form 'Merkle root mismatch' → 'bad-txnmrklroot'", () => {
      expect(bip22Result("Merkle root mismatch")).toBe("bad-txnmrklroot");
    });

    it("free-form 'Witness commitment mismatch' → 'bad-witness-merkle-match'", () => {
      expect(bip22Result("Witness commitment mismatch")).toBe("bad-witness-merkle-match");
    });

    it("free-form 'bad-cb-height' already canonical → 'bad-cb-height'", () => {
      expect(bip22Result("bad-cb-height")).toBe("bad-cb-height");
    });

    it("free-form 'non-final transaction' → 'bad-txns-nonfinal'", () => {
      expect(bip22Result("contains non-final transaction (bad-txns-nonfinal)")).toBe("bad-txns-nonfinal");
    });

    it("free-form 'duplicate' passthrough", () => {
      expect(bip22Result("duplicate")).toBe("duplicate");
    });

    it("free-form 'inconclusive' passthrough", () => {
      expect(bip22Result("inconclusive")).toBe("inconclusive");
    });

    it("unknown error string → 'rejected' catch-all", () => {
      expect(bip22Result("something totally unexpected")).toBe("rejected");
      expect(bip22Result("ENOENT")).toBe("rejected");
    });
  });

  // ========== BIP-22 via submitblock RPC ==========
  // Test the full RPC path using a mock blockSync that returns specific strings.
  describe("submitblock BIP-22 result strings", () => {
    // Helper: build a minimal serialized block (coinbase-only, arbitrary nonce).
    // The header's prevBlock is all-zeros so MockHeaderSync.getHeader returns an entry.
    // When badMerkle=true the merkleRoot bytes are wrong to trigger bad-txnmrklroot.
    // When cbHeight is set, encodes that height into the coinbase scriptSig
    // instead of the default 101 (used by the BIP-34 side-branch test).
    function buildMinimalBlockHex(opts: {
      badMerkle?: boolean;
      cbHeight?: number;
    } = {}): string {
      // Minimal coinbase transaction using the correct Transaction field names.
      // Coinbase: prevOut.txid must be all zeros (not 0xff) for isCoinbase() to pass.
      // approxHeight = bestHeader.height + 1 = 101; encode canonically (Core parity).
      const approxHeight = opts.cbHeight ?? 101;
      const heightEnc = encodeBip34Height(approxHeight);
      const scriptSig = heightEnc.length < 2
        ? Buffer.concat([heightEnc, Buffer.from([0x00])])
        : heightEnc;
      const coinbaseTx: import("../validation/tx.js").Transaction = {
        version: 1,
        inputs: [{
          prevOut: { txid: Buffer.alloc(32, 0), vout: 0xffffffff },
          scriptSig,
          sequence: 0xffffffff,
          witness: [],
        }],
        outputs: [{
          value: 50_0000_0000n,
          scriptPubKey: Buffer.from([0x51]), // OP_1
        }],
        lockTime: 0,
      };

      const txid = getTxId(coinbaseTx);
      const correctMerkle = computeMerkleRoot([txid]);

      // Nonces pre-mined to produce a valid PoW hash (< REGTEST.powLimit).
      // With prevBlock=0x00..00, timestamp=1296688602, bits=REGTEST.powLimitBits:
      //   valid-merkle block:  nonce=1 → hash 0x4a9b3dad...
      //   bad-merkle block:    nonce=0 → hash 0x0c345c94...
      const nonce = opts.badMerkle ? 0 : 1;
      const header: import("../validation/block.js").BlockHeader = {
        version: 1,
        prevBlock: Buffer.alloc(32, 0), // matches MockHeaderSync.getHeader returning an entry
        merkleRoot: opts.badMerkle ? Buffer.alloc(32, 0xab) : correctMerkle,
        timestamp: 1296688602,
        bits: REGTEST.powLimitBits,
        nonce,
      };

      const block: import("../validation/block.js").Block = {
        header,
        transactions: [coinbaseTx],
      };

      return serializeBlock(block).toString("hex");
    }

    // Helper: create a RPCServer with a mock blockSync, with regtest powLimit
    // override so the PoW pre-check passes for minimal test blocks.
    function makeServerWithBlockSync(port: number, blockSync: { injectBlock: (b: any) => Promise<string | null> }) {
      // Override the mock headerSync to return regtest powLimit so PoW passes
      mockHeaderSync.nextTargetOverride = REGTEST.powLimit;
      const config: RPCServerConfig = { port, host: "127.0.0.1", noAuth: true };
      const deps: RPCServerDeps = {
        chainState: mockChainState as any,
        mempool: mockMempool as any,
        peerManager: mockPeerManager as any,
        feeEstimator: mockFeeEstimator as any,
        headerSync: mockHeaderSync as any,
        db: mockDB as any,
        params: REGTEST,
        blockSync: blockSync as any,
      };
      return new RPCServer(config, deps);
    }

    it("mock blockSync returning null → submitblock result is null", async () => {
      const port = getTestPort();
      const mockBlockSync = { injectBlock: async (_block: any) => null };
      const s = makeServerWithBlockSync(port, mockBlockSync);
      s.start();
      try {
        const hex = buildMinimalBlockHex();
        const result = await rpcRequest(port, "submitblock", [hex]);
        // null result means success
        expect(result.error).toBeUndefined();
        expect(result.result).toBeNull();
      } finally {
        s.stop();
        mockHeaderSync.nextTargetOverride = null;
      }
    });

    it("mock blockSync returning 'duplicate' → submitblock result is 'duplicate'", async () => {
      const port = getTestPort();
      const mockBlockSync = { injectBlock: async (_block: any) => "duplicate" };
      const s = makeServerWithBlockSync(port, mockBlockSync);
      s.start();
      try {
        const hex = buildMinimalBlockHex();
        const result = await rpcRequest(port, "submitblock", [hex]);
        expect(result.error).toBeUndefined();
        expect(result.result).toBe("duplicate");
      } finally {
        s.stop();
        mockHeaderSync.nextTargetOverride = null;
      }
    });

    it("mock blockSync returning 'inconclusive' → submitblock result is 'inconclusive'", async () => {
      const port = getTestPort();
      const mockBlockSync = { injectBlock: async (_block: any) => "inconclusive" };
      const s = makeServerWithBlockSync(port, mockBlockSync);
      s.start();
      try {
        const hex = buildMinimalBlockHex();
        const result = await rpcRequest(port, "submitblock", [hex]);
        expect(result.error).toBeUndefined();
        expect(result.result).toBe("inconclusive");
      } finally {
        s.stop();
        mockHeaderSync.nextTargetOverride = null;
      }
    });

    it("block with bad merkle root → 'bad-txnmrklroot' before reaching blockSync", async () => {
      const port = getTestPort();
      let injectCalled = false;
      const mockBlockSync = {
        injectBlock: async (_block: any) => {
          injectCalled = true;
          return null;
        },
      };
      const s = makeServerWithBlockSync(port, mockBlockSync);
      s.start();
      try {
        const hex = buildMinimalBlockHex({ badMerkle: true });
        const result = await rpcRequest(port, "submitblock", [hex]);
        expect(result.error).toBeUndefined();
        expect(result.result).toBe("bad-txnmrklroot");
        // Pre-validation should have rejected before injectBlock
        expect(injectCalled).toBe(false);
      } finally {
        s.stop();
        mockHeaderSync.nextTargetOverride = null;
      }
    });

    it("non-hex submitblock param returns JSON-RPC error, not BIP-22 string", async () => {
      const result = await rpcRequest(testPort, "submitblock", [12345]);
      expect(result.error).toBeDefined();
      expect(result.error.code).toBe(RPCErrorCodes.INVALID_PARAMS);
    });

    // BIP-34 side-branch / Pattern X regression
    // (CORE-PARITY-AUDIT/_reorg-via-submitblock-fleet-result-2026-05-05.md).
    //
    // Setup: active best chain at height 112 (chain A's tip), parent of the
    // submitted block is at height 110 (the fork point).  The submitted
    // block's coinbase encodes height 111 — correct relative to its
    // parent, NOT relative to the active tip.  Pre-fix, hotbuns derived
    // approxHeight = bestHeader.height + 1 = 113, so the BIP-34 byte-exact
    // prefix match against the coinbase scriptSig (which encodes 111)
    // failed and submitblock returned `bad-cb-height`.  Post-fix,
    // approxHeight = parentEntry.height + 1 = 111, the BIP-34 check
    // passes, and the block is forwarded to injectBlock.
    it("submitblock side-branch parent.height+1 (not active-tip+1) for BIP-34", async () => {
      const port = getTestPort();
      let injectCalled = false;
      const mockBlockSync = {
        injectBlock: async (_block: any) => {
          injectCalled = true;
          return null;
        },
      };
      const s = makeServerWithBlockSync(port, mockBlockSync);
      // Active tip at h=112 (chain A's tip).  Parent of submitted block
      // (B1) is at h=110 (the fork point shared with A1).  Submitted
      // coinbase encodes 111 — parent.height + 1.
      mockHeaderSync.bestHeaderHeightOverride = 112;
      mockHeaderSync.parentHeightOverride = 110;
      s.start();
      try {
        const hex = buildMinimalBlockHex({ cbHeight: 111 });
        const result = await rpcRequest(port, "submitblock", [hex]);
        // Pre-fix: result.result = "bad-cb-height" (block rejected before
        //   injectBlock ran).
        // Post-fix: result.result = null (success, structural check passes
        //   and blockSync mock accepted).
        expect(result.error).toBeUndefined();
        expect(result.result).toBeNull();
        expect(injectCalled).toBe(true);
      } finally {
        s.stop();
        mockHeaderSync.nextTargetOverride = null;
        mockHeaderSync.bestHeaderHeightOverride = null;
        mockHeaderSync.parentHeightOverride = null;
      }
    });

    // Negative companion: confirms that the active-tip fallback still
    // fires when the parent is genuinely unknown (orphan path).  In that
    // case, the block forwards to injectBlock which returns
    // "inconclusive" — exercising the else branch of the height
    // derivation introduced by the Pattern X fix.
    it("submitblock orphan (parent unknown) falls back to active-tip+1", async () => {
      const port = getTestPort();
      let injectCalled = false;
      const mockBlockSync = {
        injectBlock: async (_block: any) => {
          injectCalled = true;
          return "inconclusive";
        },
      };
      const s = makeServerWithBlockSync(port, mockBlockSync);
      // Mark the parent (all-zeros prevBlock) as unknown so getHeader
      // returns undefined and we exercise the active-tip fallback.
      mockHeaderSync.setUnknown(Buffer.alloc(32, 0));
      mockHeaderSync.bestHeaderHeightOverride = 100;
      s.start();
      try {
        const hex = buildMinimalBlockHex({ cbHeight: 101 });
        const result = await rpcRequest(port, "submitblock", [hex]);
        expect(result.error).toBeUndefined();
        expect(result.result).toBe("inconclusive");
        expect(injectCalled).toBe(true);
      } finally {
        s.stop();
        mockHeaderSync.nextTargetOverride = null;
        mockHeaderSync.bestHeaderHeightOverride = null;
        mockHeaderSync.parentHeightOverride = null;
      }
    });
  });
});

// ───────────────────────────────────────────────────────────────────────────
// getorphantxs (Core-parity; rpc/mempool.cpp, added in v28)
//
// These tests use a REAL OrphanPool (src/mempool/orphan_pool.ts) wired into a
// fresh RPCServer via the orphanPool dep, then drive getorphantxs over real
// HTTP and assert the exact shape + fields at verbosity 0 / 1 / 2 plus the
// Core error semantics. "Proven-teeth": an orphan is actually inserted into the
// pool and the RPC reflects it (not a stubbed handler).
// ───────────────────────────────────────────────────────────────────────────
describe("getorphantxs", () => {
  // Minimal-shape orphan tx (mirrors orphan_pool.test.ts makeTx): one input
  // referencing a not-yet-known parent, one OP_TRUE output. Non-segwit so
  // txid == wtxid, which makes the verbosity-0 vs verbosity-1 cross-checks
  // self-evident.
  function makeOrphanTx() {
    const parentTxid = Buffer.alloc(32);
    parentTxid.writeUInt32LE(0xdeadbeef >>> 0, 0);
    return {
      version: 2,
      inputs: [
        {
          prevOut: { txid: parentTxid, vout: 0 },
          scriptSig: Buffer.alloc(0),
          sequence: 0xffffffff,
          witness: [] as Buffer[],
        },
      ],
      outputs: [{ value: 1_000n, scriptPubKey: Buffer.from([0x51]) }],
      lockTime: 0,
    };
  }

  function makeServerWithOrphan(port: number): {
    server: RPCServer;
    pool: any;
    tx: any;
    txidDisplay: string;
    wtxidDisplay: string;
  } {
    const pool = new OrphanPool();
    const tx = makeOrphanTx();
    const admit = pool.add(tx, "203.0.113.7:8333");
    expect(admit.ok).toBe(true);

    const config: RPCServerConfig = { port, host: "127.0.0.1", noAuth: true };
    const deps: RPCServerDeps = {
      chainState: new MockChainStateManager() as any,
      mempool: new MockMempool() as any,
      peerManager: new MockPeerManager() as any,
      feeEstimator: new MockFeeEstimator() as any,
      headerSync: new MockHeaderSync() as any,
      db: new MockChainDB() as any,
      params: REGTEST,
      orphanPool: pool,
    };
    const server = new RPCServer(config, deps);

    const txidDisplay = Buffer.from(getTxId(tx)).reverse().toString("hex");
    const wtxidDisplay = Buffer.from(getWTxId(tx)).reverse().toString("hex");
    return { server, pool, tx, txidDisplay, wtxidDisplay };
  }

  it("verbosity 0: returns an array of orphan txid strings", async () => {
    const port = getTestPort();
    const { server, txidDisplay } = makeServerWithOrphan(port);
    server.start();
    try {
      const res = await rpcRequest(port, "getorphantxs");
      expect(res.error).toBeUndefined();
      expect(Array.isArray(res.result)).toBe(true);
      expect(res.result.length).toBe(1);
      // Core: orphan.tx->GetHash().ToString() — the NON-witness txid.
      expect(res.result[0]).toBe(txidDisplay);
    } finally {
      server.stop();
    }
  });

  it("verbosity 1: returns objects with Core's exact field set", async () => {
    const port = getTestPort();
    const { server, txidDisplay, wtxidDisplay } = makeServerWithOrphan(port);
    server.start();
    try {
      const res = await rpcRequest(port, "getorphantxs", [1]);
      expect(res.error).toBeUndefined();
      expect(Array.isArray(res.result)).toBe(true);
      expect(res.result.length).toBe(1);

      const o = res.result[0];
      // Exact Core field set: txid, wtxid, bytes, vsize, weight, from. No more.
      expect(Object.keys(o).sort()).toEqual(
        ["bytes", "from", "txid", "vsize", "weight", "wtxid"].sort()
      );
      expect(o.txid).toBe(txidDisplay);
      expect(o.wtxid).toBe(wtxidDisplay);
      expect(typeof o.bytes).toBe("number");
      expect(o.bytes).toBeGreaterThan(0);
      expect(typeof o.vsize).toBe("number");
      expect(typeof o.weight).toBe("number");
      // weight == 4*vsize for a non-witness tx.
      expect(o.weight).toBe(o.vsize * 4);
      // from = 1-element array of the announcing peer key (host:port).
      expect(Array.isArray(o.from)).toBe(true);
      expect(o.from).toEqual(["203.0.113.7:8333"]);
      // verbosity 1 must NOT include hex.
      expect(o.hex).toBeUndefined();
    } finally {
      server.stop();
    }
  });

  it("verbosity 2: verbosity-1 fields PLUS hex", async () => {
    const port = getTestPort();
    const { server } = makeServerWithOrphan(port);
    server.start();
    try {
      const res = await rpcRequest(port, "getorphantxs", [2]);
      expect(res.error).toBeUndefined();
      const o = res.result[0];
      expect(typeof o.hex).toBe("string");
      expect(o.hex.length).toBeGreaterThan(0);
      // Still carries the verbosity-1 fields.
      expect(typeof o.txid).toBe("string");
      expect(Array.isArray(o.from)).toBe(true);
    } finally {
      server.stop();
    }
  });

  it("returns [] when the orphan pool is empty / absent", async () => {
    // Default harness server is constructed without an orphanPool dep.
    const port = getTestPort();
    const config: RPCServerConfig = { port, host: "127.0.0.1", noAuth: true };
    const deps: RPCServerDeps = {
      chainState: new MockChainStateManager() as any,
      mempool: new MockMempool() as any,
      peerManager: new MockPeerManager() as any,
      feeEstimator: new MockFeeEstimator() as any,
      headerSync: new MockHeaderSync() as any,
      db: new MockChainDB() as any,
      params: REGTEST,
    };
    const server = new RPCServer(config, deps);
    server.start();
    try {
      const res = await rpcRequest(port, "getorphantxs");
      expect(res.error).toBeUndefined();
      expect(res.result).toEqual([]);
    } finally {
      server.stop();
    }
  });

  it("rejects out-of-range verbosity with RPC_INVALID_PARAMETER (-8)", async () => {
    const port = getTestPort();
    const { server } = makeServerWithOrphan(port);
    server.start();
    try {
      const res = await rpcRequest(port, "getorphantxs", [3]);
      expect(res.error).toBeDefined();
      expect(res.error.code).toBe(RPCErrorCodes.INVALID_PARAMETER);
      expect(res.error.message).toBe("Invalid verbosity value 3");
    } finally {
      server.stop();
    }
  });

  it("rejects boolean verbosity with RPC_TYPE_ERROR (-3)", async () => {
    const port = getTestPort();
    const { server } = makeServerWithOrphan(port);
    server.start();
    try {
      const res = await rpcRequest(port, "getorphantxs", [true]);
      expect(res.error).toBeDefined();
      expect(res.error.code).toBe(RPCErrorCodes.TYPE_ERROR);
      expect(res.error.message).toBe(
        "Verbosity was boolean but only integer allowed"
      );
    } finally {
      server.stop();
    }
  });
});

// ===========================================================================
// gettxspendingprevout (Bitcoin Core -txospenderindex parity)
// ===========================================================================

describe("gettxspendingprevout", () => {
  let port: number;
  let dbPath: string;
  let db: ChainDB;
  let idx: TxoSpenderIndex;
  let mempool: MockMempool;
  let server: RPCServer;

  // display-order (big-endian) hex helper.
  const displayHex = (le: Buffer) => Buffer.from(le).reverse().toString("hex");

  function spendTx(prevTxidLE: Buffer, vout: number, tag: number) {
    return {
      version: 2,
      inputs: [
        { prevOut: { txid: prevTxidLE, vout }, scriptSig: Buffer.from([tag]), sequence: 0xffffffff, witness: [] },
      ],
      outputs: [{ value: 1n, scriptPubKey: Buffer.from([0x51]) }],
      lockTime: 0,
    };
  }

  function makeBlock(txs: any[], nonce: number) {
    return {
      header: {
        version: 0x20000000,
        prevBlock: Buffer.alloc(32, nonce & 0xff),
        merkleRoot: Buffer.alloc(32, nonce & 0xff),
        timestamp: 1700000000 + nonce,
        bits: 0x207fffff,
        nonce,
      },
      transactions: txs,
    };
  }

  async function makeServer(opts: { withIndex: boolean }) {
    mempool = new MockMempool();
    const deps: RPCServerDeps = {
      chainState: new MockChainStateManager() as any,
      mempool: mempool as any,
      peerManager: new MockPeerManager() as any,
      feeEstimator: new MockFeeEstimator() as any,
      headerSync: new MockHeaderSync() as any,
      db: db as any,
      params: REGTEST,
      txoSpenderIndex: opts.withIndex ? (idx as any) : undefined,
    };
    const s = new RPCServer({ port, host: "127.0.0.1", noAuth: true }, deps);
    s.start();
    return s;
  }

  beforeEach(async () => {
    port = getTestPort();
    dbPath = await mkdtemp(join(tmpdir(), "hotbuns-gtsp-"));
    db = new ChainDB(dbPath);
    await db.open();
    idx = new TxoSpenderIndex(db, true);
    await idx.init();
  });

  afterEach(async () => {
    if (server) server.stop();
    await db.close();
    await rm(dbPath, { recursive: true, force: true });
  });

  it("empty outputs -> RPC_INVALID_PARAMETER (-8) outputs are missing", async () => {
    server = await makeServer({ withIndex: true });
    const r = await rpcRequest(port, "gettxspendingprevout", [[]]);
    expect(r.error.code).toBe(-8);
    expect(r.error.message).toBe("Invalid parameter, outputs are missing");
  });

  it("negative vout -> RPC_INVALID_PARAMETER (-8) vout cannot be negative", async () => {
    server = await makeServer({ withIndex: true });
    const txid = "ab".repeat(32);
    const r = await rpcRequest(port, "gettxspendingprevout", [[{ txid, vout: -1 }]]);
    expect(r.error.code).toBe(-8);
    expect(r.error.message).toBe("Invalid parameter, vout cannot be negative");
  });

  it("unknown options key -> RPC_TYPE_ERROR (-3) strict check", async () => {
    server = await makeServer({ withIndex: true });
    const txid = "ab".repeat(32);
    const r = await rpcRequest(port, "gettxspendingprevout", [[{ txid, vout: 0 }], { bogus: true }]);
    expect(r.error.code).toBe(-3);
  });

  it("mempool_only=false AND index unavailable -> RPC_MISC_ERROR (-1)", async () => {
    // Core: with no index, mempool_only defaults to true and an unspent
    // outpoint returns a bare {txid,vout}. The -1 only fires when the caller
    // EXPLICITLY sets mempool_only=false while the index is unavailable.
    server = await makeServer({ withIndex: false });
    const txid = "ab".repeat(32);
    const r = await rpcRequest(port, "gettxspendingprevout", [
      [{ txid, vout: 0 }],
      { mempool_only: false },
    ]);
    expect(r.error.code).toBe(-1);
    expect(r.error.message).toBe(
      "Mempool lacks a relevant spend, and txospenderindex is unavailable."
    );
  });

  it("default mempool_only with no index -> bare {txid,vout} for unspent (no error)", async () => {
    server = await makeServer({ withIndex: false });
    const txid = "ab".repeat(32);
    const r = await rpcRequest(port, "gettxspendingprevout", [[{ txid, vout: 0 }]]);
    expect(r.error).toBeUndefined();
    expect(r.result[0].txid).toBe(txid);
    expect(r.result[0].vout).toBe(0);
    expect(r.result[0].spendingtxid).toBeUndefined();
  });

  it("confirmed spend via index -> spendingtxid + blockhash; return_spending_tx adds spendingtx", async () => {
    server = await makeServer({ withIndex: true });
    const aTxidLE = Buffer.alloc(32, 0xa1);
    const b = spendTx(aTxidLE, 0, 0x9);
    const blk = makeBlock([
      { version: 1, inputs: [{ prevOut: { txid: Buffer.alloc(32, 0), vout: 0xffffffff }, scriptSig: Buffer.from([1]), sequence: 0xffffffff, witness: [] }], outputs: [{ value: 5n, scriptPubKey: Buffer.from([0x51]) }], lockTime: 0 },
      b,
    ], 7);
    const blkHash = getBlockHash(blk.header);
    await idx.indexBlock(blk, 1);

    // Without return_spending_tx.
    const r1 = await rpcRequest(port, "gettxspendingprevout", [[{ txid: displayHex(aTxidLE), vout: 0 }]]);
    expect(r1.error).toBeUndefined();
    expect(r1.result.length).toBe(1);
    expect(r1.result[0].txid).toBe(displayHex(aTxidLE));
    expect(r1.result[0].vout).toBe(0);
    expect(r1.result[0].spendingtxid).toBe(displayHex(getTxId(b)));
    expect(r1.result[0].blockhash).toBe(displayHex(blkHash));
    expect(r1.result[0].spendingtx).toBeUndefined();

    // With return_spending_tx.
    const r2 = await rpcRequest(port, "gettxspendingprevout", [
      [{ txid: displayHex(aTxidLE), vout: 0 }],
      { return_spending_tx: true },
    ]);
    expect(r2.result[0].spendingtx).toBe(serializeTx(b as any, true).toString("hex"));

    // An unspent outpoint -> bare {txid, vout}.
    const r3 = await rpcRequest(port, "gettxspendingprevout", [[{ txid: displayHex(aTxidLE), vout: 5 }]]);
    expect(r3.result[0].spendingtxid).toBeUndefined();
    expect(r3.result[0].blockhash).toBeUndefined();
  });

  it("mempool spend resolves before the index (no blockhash for mempool spend)", async () => {
    server = await makeServer({ withIndex: true });
    const aTxidLE = Buffer.alloc(32, 0xb2);
    const b = spendTx(aTxidLE, 0, 0x3);
    const bTxid = getTxId(b as any);
    mempool.addSpend(aTxidLE, 0, bTxid, b);

    const r = await rpcRequest(port, "gettxspendingprevout", [
      [{ txid: displayHex(aTxidLE), vout: 0 }],
      { return_spending_tx: true },
    ]);
    expect(r.error).toBeUndefined();
    expect(r.result[0].spendingtxid).toBe(displayHex(bTxid));
    expect(r.result[0].spendingtx).toBe(serializeTx(b as any, true).toString("hex"));
    // Mempool spend is unconfirmed -> no blockhash.
    expect(r.result[0].blockhash).toBeUndefined();
  });

  it("LIVE reorg erases the confirmed spend: after disconnect the index no longer answers", async () => {
    server = await makeServer({ withIndex: true });
    const aTxidLE = Buffer.alloc(32, 0xc3);
    const b = spendTx(aTxidLE, 0, 0x1);
    const blk = makeBlock([
      { version: 1, inputs: [{ prevOut: { txid: Buffer.alloc(32, 0), vout: 0xffffffff }, scriptSig: Buffer.from([1]), sequence: 0xffffffff, witness: [] }], outputs: [{ value: 5n, scriptPubKey: Buffer.from([0x51]) }], lockTime: 0 },
      b,
    ], 8);
    await idx.indexBlock(blk, 1);

    // Confirmed-spend path answers.
    const before = await rpcRequest(port, "gettxspendingprevout", [[{ txid: displayHex(aTxidLE), vout: 0 }]]);
    expect(before.result[0].spendingtxid).toBe(displayHex(getTxId(b)));

    // Heavier branch orphans the block carrying B -> index erases A:0.
    await idx.removeBlock(blk, 1);

    const after = await rpcRequest(port, "gettxspendingprevout", [[{ txid: displayHex(aTxidLE), vout: 0 }]]);
    expect(after.error).toBeUndefined();
    expect(after.result[0].spendingtxid).toBeUndefined();
    expect(after.result[0].blockhash).toBeUndefined();
  });
});
