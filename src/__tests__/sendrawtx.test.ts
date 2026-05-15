/**
 * Tests for sendrawtransaction RPC method.
 *
 * Tests the complete flow: decode, validate, accept to mempool, broadcast.
 */

import { describe, it, expect, beforeEach, afterEach } from "bun:test";
import {
  RPCServer,
  RPCServerConfig,
  RPCServerDeps,
  RPCErrorCodes,
  DEFAULT_MAX_FEE_RATE,
} from "../rpc/server.js";
import { REGTEST } from "../consensus/params.js";
import type { Transaction } from "../validation/tx.js";
import { serializeTx, getTxId, getTxVSize } from "../validation/tx.js";
import type { NetworkMessage } from "../p2p/messages.js";
import { InvType } from "../p2p/messages.js";

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

  setBestBlock(hash: Buffer, height: number, chainWork: bigint) {
    this.bestBlock = { hash: hash as Buffer<ArrayBuffer>, height, chainWork };
  }
}

class MockMempool {
  private entries = new Map<
    string,
    {
      tx: Transaction;
      txid: Buffer;
      fee: bigint;
      feeRate: number;
      vsize: number;
      weight: number;
      addedTime: number;
      height: number;
      spentBy: Set<string>;
      dependsOn: Set<string>;
    }
  >();

  // Track which txids are "confirmed" in the chain
  private confirmedTxids = new Set<string>();

  // Track add/remove calls for test verification
  public addTransactionCalls: Transaction[] = [];
  public removeTransactionCalls: Buffer[] = [];

  // Control add behavior
  public acceptTransaction = true;
  public rejectReason = "";

  getInfo() {
    return {
      size: this.entries.size,
      bytes: 1000,
      minFeeRate: 1,
    };
  }

  getAllTxids(): Buffer[] {
    return Array.from(this.entries.values()).map((e) => e.txid);
  }

  getTransaction(txid: Buffer) {
    return this.entries.get(txid.toString("hex")) ?? null;
  }

  hasTransaction(txid: Buffer) {
    return this.entries.has(txid.toString("hex"));
  }

  async addTransaction(
    tx: Transaction,
    options?: { maxFeeRateSatPerVB?: number },
  ) {
    this.addTransactionCalls.push(tx);

    if (!this.acceptTransaction) {
      return { accepted: false, error: this.rejectReason || "Rejected" };
    }

    // Compute txid and add to entries
    const txid = getTxId(tx);
    const txidHex = txid.toString("hex");
    const vsize = getTxVSize(tx);

    // Default fee rate based on test settings
    const fee = BigInt(vsize * 10); // 10 sat/vB
    const feeRate = 10;

    // W96: honor the caller-provided max fee rate inline (matches real
    // Mempool.addTransaction behavior). If the computed fee rate exceeds the
    // cap, reject before adding to entries so the notification side-effects
    // don't fire for txs that will end up rejected.
    if (
      options?.maxFeeRateSatPerVB !== undefined &&
      options.maxFeeRateSatPerVB > 0 &&
      feeRate > options.maxFeeRateSatPerVB
    ) {
      // Mirror the RPC's expected error text so the test stays meaningful.
      const feeRateBTCkvB = (feeRate * 1000) / 100_000_000;
      return {
        accepted: false,
        error: `Fee rate ${feeRateBTCkvB.toFixed(8)} BTC/kvB exceeds max rate ${(
          options.maxFeeRateSatPerVB / 100_000
        ).toFixed(8)} BTC/kvB`,
      };
    }

    this.entries.set(txidHex, {
      tx,
      txid,
      fee,
      feeRate,
      vsize,
      weight: vsize * 4,
      addedTime: Math.floor(Date.now() / 1000),
      height: 100,
      spentBy: new Set(),
      dependsOn: new Set(),
    });

    return { accepted: true };
  }

  removeTransaction(txid: Buffer, _removeDependents = true): void {
    this.removeTransactionCalls.push(txid);
    this.entries.delete(txid.toString("hex"));
  }

  async isTransactionConfirmed(txid: Buffer): Promise<boolean> {
    return this.confirmedTxids.has(txid.toString("hex"));
  }

  // Test helpers
  addTestTransaction(txid: Buffer, entry: Partial<typeof this.entries extends Map<string, infer V> ? V : never>) {
    const vsize = entry.vsize ?? 200;
    this.entries.set(txid.toString("hex"), {
      tx: entry.tx ?? createTestTransaction(),
      txid,
      fee: entry.fee ?? 2000n,
      feeRate: entry.feeRate ?? 10,
      vsize,
      weight: entry.weight ?? vsize * 4,
      addedTime: entry.addedTime ?? Math.floor(Date.now() / 1000),
      height: entry.height ?? 100,
      spentBy: entry.spentBy ?? new Set(),
      dependsOn: entry.dependsOn ?? new Set(),
    });
  }

  setTransactionConfirmed(txid: Buffer): void {
    this.confirmedTxids.add(txid.toString("hex"));
  }

  setFeeRate(txid: Buffer, feeRate: number): void {
    const entry = this.entries.get(txid.toString("hex"));
    if (entry) {
      entry.feeRate = feeRate;
    }
  }

  reset(): void {
    this.entries.clear();
    this.confirmedTxids.clear();
    this.addTransactionCalls = [];
    this.removeTransactionCalls = [];
    this.acceptTransaction = true;
    this.rejectReason = "";
  }
}

class MockPeer {
  id: string;
  address: string;
  wtxidRelay: boolean;
  sentMessages: NetworkMessage[] = [];

  constructor(opts: { id: string; address: string; wtxidRelay?: boolean }) {
    this.id = opts.id;
    this.address = opts.address;
    this.wtxidRelay = opts.wtxidRelay ?? false;
  }

  send(msg: NetworkMessage) {
    this.sentMessages.push(msg);
  }

  reset() {
    this.sentMessages = [];
  }
}

class MockPeerManager {
  private peers: MockPeer[] = [];
  /** Aggregated sent messages across all peers (for backward-compat). */
  public broadcastCalls: NetworkMessage[] = [];

  getConnectedPeers() {
    return this.peers;
  }

  broadcast(msg: NetworkMessage) {
    this.broadcastCalls.push(msg);
  }

  addMockPeer(opts: { id: string; address: string; wtxidRelay?: boolean }) {
    const peer = new MockPeer(opts);
    this.peers.push(peer);
    // Proxy peer.send → broadcastCalls so existing length-checks still work.
    const origSend = peer.send.bind(peer);
    peer.send = (msg: NetworkMessage) => {
      origSend(msg);
      this.broadcastCalls.push(msg);
    };
  }

  reset(): void {
    this.broadcastCalls = [];
    this.peers = [];
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

  getMedianTimePast(_entry: unknown) {
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
}

// Create a minimal valid transaction for testing
function createTestTransaction(): Transaction {
  return {
    version: 2,
    inputs: [
      {
        prevOut: {
          txid: Buffer.alloc(32, 0xab),
          vout: 0,
        },
        scriptSig: Buffer.alloc(0),
        sequence: 0xffffffff,
        witness: [
          Buffer.from("304402203f0e...".padEnd(144, "0"), "hex"), // fake sig
          Buffer.alloc(33, 0x02), // fake pubkey
        ],
      },
    ],
    outputs: [
      {
        value: 10000n,
        scriptPubKey: Buffer.from("0014" + "00".repeat(20), "hex"), // P2WPKH
      },
    ],
    lockTime: 0,
  };
}

// Helper to make RPC requests
async function rpcRequest(
  port: number,
  method: string,
  params: unknown[] = []
): Promise<{ result?: unknown; error?: { code: number; message: string } }> {
  const response = await fetch(`http://127.0.0.1:${port}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method,
      params,
    }),
  });

  return response.json();
}

// Get a unique port for each test
let portCounter = 19443;
function getTestPort(): number {
  return portCounter++;
}

describe("sendrawtransaction", () => {
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
    mockMempool.reset();
    mockPeerManager.reset();
  });

  describe("parameter validation", () => {
    it("should reject missing hexstring parameter", async () => {
      const result = await rpcRequest(testPort, "sendrawtransaction", []);

      expect(result.error).toBeDefined();
      expect(result.error!.code).toBe(RPCErrorCodes.INVALID_PARAMS);
      expect(result.error!.message).toContain("hexstring");
    });

    it("should reject non-string hexstring", async () => {
      const result = await rpcRequest(testPort, "sendrawtransaction", [12345]);

      expect(result.error).toBeDefined();
      expect(result.error!.code).toBe(RPCErrorCodes.INVALID_PARAMS);
      expect(result.error!.message).toContain("hexstring must be a string");
    });

    it("should reject invalid hex encoding", async () => {
      const result = await rpcRequest(testPort, "sendrawtransaction", ["not-valid-hex"]);

      expect(result.error).toBeDefined();
      expect(result.error!.code).toBe(RPCErrorCodes.INVALID_PARAMS);
    });

    it("should reject odd-length hex string", async () => {
      const result = await rpcRequest(testPort, "sendrawtransaction", ["abc"]);

      expect(result.error).toBeDefined();
      expect(result.error!.code).toBe(RPCErrorCodes.INVALID_PARAMS);
      expect(result.error!.message).toContain("odd length");
    });

    it("should reject malformed transaction data", async () => {
      const result = await rpcRequest(testPort, "sendrawtransaction", ["0011223344"]);

      expect(result.error).toBeDefined();
      expect(result.error!.code).toBe(RPCErrorCodes.RPC_TRANSACTION_REJECTED);
      expect(result.error!.message).toContain("decode failed");
    });
  });

  describe("maxfeerate parameter", () => {
    it("should use default maxfeerate of 0.10 BTC/kvB", () => {
      expect(DEFAULT_MAX_FEE_RATE).toBe(0.1);
    });

    it("should reject non-numeric maxfeerate", async () => {
      const tx = createTestTransaction();
      const txHex = serializeTx(tx, true).toString("hex");

      const result = await rpcRequest(testPort, "sendrawtransaction", [txHex, "invalid"]);

      expect(result.error).toBeDefined();
      expect(result.error!.code).toBe(RPCErrorCodes.INVALID_PARAMS);
      expect(result.error!.message).toContain("maxfeerate must be a number");
    });

    it("should reject negative maxfeerate", async () => {
      const tx = createTestTransaction();
      const txHex = serializeTx(tx, true).toString("hex");

      const result = await rpcRequest(testPort, "sendrawtransaction", [txHex, -1]);

      expect(result.error).toBeDefined();
      expect(result.error!.code).toBe(RPCErrorCodes.INVALID_PARAMS);
      expect(result.error!.message).toContain("cannot be negative");
    });

    it("should reject maxfeerate > 1 BTC/kvB", async () => {
      const tx = createTestTransaction();
      const txHex = serializeTx(tx, true).toString("hex");

      const result = await rpcRequest(testPort, "sendrawtransaction", [txHex, 1.5]);

      expect(result.error).toBeDefined();
      expect(result.error!.code).toBe(RPCErrorCodes.INVALID_PARAMS);
      expect(result.error!.message).toContain("larger than 1 BTC/kvB");
    });

    it("should accept maxfeerate = 0 (allow any fee rate)", async () => {
      const tx = createTestTransaction();
      const txHex = serializeTx(tx, true).toString("hex");

      const result = await rpcRequest(testPort, "sendrawtransaction", [txHex, 0]);

      // Should succeed (0 means accept any rate)
      expect(result.result).toBeDefined();
      expect(result.error).toBeUndefined();
    });

    it("should reject transaction with fee rate exceeding maxfeerate", async () => {
      const tx = createTestTransaction();
      const txHex = serializeTx(tx, true).toString("hex");

      // Set a high fee rate on the mempool entry (1000 sat/vB = 0.01 BTC/kvB)
      // We need to intercept after addTransaction to set the fee rate
      mockMempool.acceptTransaction = true;

      const result = await rpcRequest(testPort, "sendrawtransaction", [txHex, 0.00001]);

      // The transaction has fee rate 10 sat/vB = 0.0001 BTC/kvB
      // maxfeerate is 0.00001 BTC/kvB = 1 sat/vB
      // So it should be rejected
      expect(result.error).toBeDefined();
      expect(result.error!.code).toBe(RPCErrorCodes.RPC_TRANSACTION_REJECTED);
      expect(result.error!.message).toContain("exceeds max rate");

      // W96: maxfeerate is now enforced INSIDE Mempool.addTransaction (via the
      // `maxFeeRateSatPerVB` option) so the tx is never added to the pool and
      // therefore never needs to be removed. Previously the RPC handler added
      // the tx, then removed it on max-fee violation — firing txAccepted /
      // mempoolSequence side-effects on a tx that would ultimately be rejected.
      expect(mockMempool.removeTransactionCalls.length).toBe(0);
    });
  });

  describe("duplicate transaction handling", () => {
    it("should return txid without error if transaction already in mempool", async () => {
      const tx = createTestTransaction();
      const txHex = serializeTx(tx, true).toString("hex");
      const txid = getTxId(tx);

      // Add a peer so broadcastTxInv has someone to send to
      mockPeerManager.addMockPeer({ id: "peer1", address: "192.0.2.1:8333", wtxidRelay: false });

      // Add tx to mempool first
      mockMempool.addTestTransaction(txid, { tx });

      // Try to submit the same tx
      const result = await rpcRequest(testPort, "sendrawtransaction", [txHex]);

      // Should return success with the txid (not an error)
      expect(result.error).toBeUndefined();
      expect(result.result).toBe(Buffer.from(txid).reverse().toString("hex"));

      // Should broadcast inv even for duplicate
      expect(mockPeerManager.broadcastCalls.length).toBe(1);
    });

    it("should return error if transaction already confirmed in blockchain", async () => {
      const tx = createTestTransaction();
      const txHex = serializeTx(tx, true).toString("hex");
      const txid = getTxId(tx);

      // Mark tx as confirmed
      mockMempool.setTransactionConfirmed(txid);

      const result = await rpcRequest(testPort, "sendrawtransaction", [txHex]);

      expect(result.error).toBeDefined();
      expect(result.error!.code).toBe(RPCErrorCodes.RPC_TRANSACTION_ALREADY_IN_CHAIN);
      expect(result.error!.message).toContain("already in block chain");
    });
  });

  describe("mempool acceptance", () => {
    it("should accept valid transaction and return txid", async () => {
      const tx = createTestTransaction();
      const txHex = serializeTx(tx, true).toString("hex");
      const txid = getTxId(tx);

      const result = await rpcRequest(testPort, "sendrawtransaction", [txHex]);

      expect(result.error).toBeUndefined();
      expect(result.result).toBe(Buffer.from(txid).reverse().toString("hex"));

      // Transaction should be added to mempool
      expect(mockMempool.addTransactionCalls.length).toBe(1);
    });

    it("should return error if mempool rejects transaction", async () => {
      const tx = createTestTransaction();
      const txHex = serializeTx(tx, true).toString("hex");

      mockMempool.acceptTransaction = false;
      mockMempool.rejectReason = "Missing inputs";

      const result = await rpcRequest(testPort, "sendrawtransaction", [txHex]);

      expect(result.error).toBeDefined();
      expect(result.error!.code).toBe(RPCErrorCodes.RPC_TRANSACTION_REJECTED);
      expect(result.error!.message).toContain("Missing inputs");
    });

    it("should return error if mempool rejects due to low fee", async () => {
      const tx = createTestTransaction();
      const txHex = serializeTx(tx, true).toString("hex");

      mockMempool.acceptTransaction = false;
      mockMempool.rejectReason = "Fee rate 0.50 sat/vB below minimum 1";

      const result = await rpcRequest(testPort, "sendrawtransaction", [txHex]);

      expect(result.error).toBeDefined();
      expect(result.error!.code).toBe(RPCErrorCodes.RPC_TRANSACTION_REJECTED);
      expect(result.error!.message).toContain("Fee rate");
    });

    it("should return error if mempool rejects due to double-spend", async () => {
      const tx = createTestTransaction();
      const txHex = serializeTx(tx, true).toString("hex");

      mockMempool.acceptTransaction = false;
      mockMempool.rejectReason = "Double-spend conflict with mempool transaction";

      const result = await rpcRequest(testPort, "sendrawtransaction", [txHex]);

      expect(result.error).toBeDefined();
      expect(result.error!.code).toBe(RPCErrorCodes.RPC_TRANSACTION_REJECTED);
      expect(result.error!.message).toContain("Double-spend");
    });
  });

  describe("broadcast to peers", () => {
    it("should broadcast inv message to each peer after accepting transaction", async () => {
      const tx = createTestTransaction();
      const txHex = serializeTx(tx, true).toString("hex");
      const txid = getTxId(tx);

      // Add two legacy peers (no BIP-339 wtxidrelay)
      mockPeerManager.addMockPeer({ id: "peer1", address: "192.0.2.1:8333", wtxidRelay: false });
      mockPeerManager.addMockPeer({ id: "peer2", address: "192.0.2.2:8333", wtxidRelay: false });

      const result = await rpcRequest(testPort, "sendrawtransaction", [txHex]);

      expect(result.error).toBeUndefined();
      expect(result.result).toBe(Buffer.from(txid).reverse().toString("hex"));

      // broadcastTxInv sends one inv per peer (2 peers → 2 calls)
      expect(mockPeerManager.broadcastCalls.length).toBe(2);
      const invMsg = mockPeerManager.broadcastCalls[0];
      expect(invMsg.type).toBe("inv");
      expect((invMsg.payload as any).inventory.length).toBe(1);
      // Legacy peer: MSG_TX (=1), not MSG_WITNESS_TX (0x40000001)
      expect((invMsg.payload as any).inventory[0].type).toBe(InvType.MSG_TX);
      expect(Buffer.compare((invMsg.payload as any).inventory[0].hash, txid)).toBe(0);
    });

    it("should use MSG_WTX for BIP-339-negotiated peers and MSG_TX for legacy peers", async () => {
      const tx = createTestTransaction();
      const txHex = serializeTx(tx, true).toString("hex");

      // One BIP-339 peer, one legacy peer
      mockPeerManager.addMockPeer({ id: "bip339-peer", address: "192.0.2.3:8333", wtxidRelay: true });
      mockPeerManager.addMockPeer({ id: "legacy-peer", address: "192.0.2.4:8333", wtxidRelay: false });

      await rpcRequest(testPort, "sendrawtransaction", [txHex]);

      expect(mockPeerManager.broadcastCalls.length).toBe(2);
      // BIP-339 peer gets MSG_WTX (=5)
      expect((mockPeerManager.broadcastCalls[0].payload as any).inventory[0].type).toBe(InvType.MSG_WTX);
      // Legacy peer gets MSG_TX (=1)
      expect((mockPeerManager.broadcastCalls[1].payload as any).inventory[0].type).toBe(InvType.MSG_TX);
      // Neither should be MSG_WITNESS_TX (0x40000001)
      expect((mockPeerManager.broadcastCalls[0].payload as any).inventory[0].type).not.toBe(InvType.MSG_WITNESS_TX);
      expect((mockPeerManager.broadcastCalls[1].payload as any).inventory[0].type).not.toBe(InvType.MSG_WITNESS_TX);
    });
  });

  describe("error codes", () => {
    it("should use RPC_TRANSACTION_REJECTED (-26) for mempool rejection", async () => {
      const tx = createTestTransaction();
      const txHex = serializeTx(tx, true).toString("hex");

      mockMempool.acceptTransaction = false;
      mockMempool.rejectReason = "Some rejection reason";

      const result = await rpcRequest(testPort, "sendrawtransaction", [txHex]);

      expect(result.error).toBeDefined();
      expect(result.error!.code).toBe(-26);
    });

    it("should use RPC_TRANSACTION_ALREADY_IN_CHAIN (-27) for confirmed tx", async () => {
      const tx = createTestTransaction();
      const txHex = serializeTx(tx, true).toString("hex");
      const txid = getTxId(tx);

      mockMempool.setTransactionConfirmed(txid);

      const result = await rpcRequest(testPort, "sendrawtransaction", [txHex]);

      expect(result.error).toBeDefined();
      expect(result.error!.code).toBe(-27);
    });
  });
});

describe("broadcast integration", () => {
  let server: RPCServer;
  let mockMempool: MockMempool;
  let mockPeerManager: MockPeerManager;
  let testPort: number;

  beforeEach(() => {
    testPort = getTestPort();
    mockMempool = new MockMempool();
    mockPeerManager = new MockPeerManager();

    const config: RPCServerConfig = {
      port: testPort,
      host: "127.0.0.1",
      noAuth: true,
    };

    const deps: RPCServerDeps = {
      chainState: new MockChainStateManager() as any,
      mempool: mockMempool as any,
      peerManager: mockPeerManager as any,
      feeEstimator: new MockFeeEstimator() as any,
      headerSync: new MockHeaderSync() as any,
      db: new MockChainDB() as any,
      params: REGTEST,
    };

    server = new RPCServer(config, deps);
    server.start();

    // Add one legacy peer by default so broadcastTxInv has someone to send to.
    mockPeerManager.addMockPeer({ id: "peer-default", address: "192.0.2.1:8333", wtxidRelay: false });
  });

  afterEach(() => {
    server.stop();
    mockMempool.reset();
    mockPeerManager.reset();
  });

  it("should broadcast inv for new transaction", async () => {
    const tx = createTestTransaction();
    const txHex = serializeTx(tx, true).toString("hex");

    await rpcRequest(testPort, "sendrawtransaction", [txHex]);

    expect(mockPeerManager.broadcastCalls.length).toBe(1);
    expect(mockPeerManager.broadcastCalls[0].type).toBe("inv");
  });

  it("should broadcast inv for duplicate transaction in mempool", async () => {
    const tx = createTestTransaction();
    const txid = getTxId(tx);
    const txHex = serializeTx(tx, true).toString("hex");

    // Add to mempool first
    mockMempool.addTestTransaction(txid, { tx });

    // Submit again
    await rpcRequest(testPort, "sendrawtransaction", [txHex]);

    // Should still broadcast (re-announce to peers)
    expect(mockPeerManager.broadcastCalls.length).toBe(1);
  });

  it("should not broadcast for confirmed transaction", async () => {
    const tx = createTestTransaction();
    const txid = getTxId(tx);
    const txHex = serializeTx(tx, true).toString("hex");

    mockMempool.setTransactionConfirmed(txid);

    await rpcRequest(testPort, "sendrawtransaction", [txHex]);

    // Should not broadcast for confirmed tx (error is returned)
    expect(mockPeerManager.broadcastCalls.length).toBe(0);
  });

  it("should not broadcast for rejected transaction", async () => {
    const tx = createTestTransaction();
    const txHex = serializeTx(tx, true).toString("hex");

    mockMempool.acceptTransaction = false;

    await rpcRequest(testPort, "sendrawtransaction", [txHex]);

    // Should not broadcast for rejected tx
    expect(mockPeerManager.broadcastCalls.length).toBe(0);
  });
});
