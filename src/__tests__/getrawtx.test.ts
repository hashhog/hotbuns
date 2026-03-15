/**
 * Tests for getrawtransaction RPC method.
 *
 * Tests cover:
 * - Mempool transaction lookup
 * - Confirmed transaction lookup via blockhash
 * - Transaction index lookup
 * - Verbose vs non-verbose output
 * - Error cases
 */

import { describe, it, expect, beforeEach, afterEach } from "bun:test";
import { RPCServer, RPCServerConfig, RPCServerDeps, RPCErrorCodes } from "../rpc/server.js";
import { REGTEST } from "../consensus/params.js";
import { serializeTx, getTxId, type Transaction } from "../validation/tx.js";
import { serializeBlock, type Block, type BlockHeader } from "../validation/block.js";
import { hash256 } from "../crypto/primitives.js";

// Create a simple coinbase transaction
function createCoinbaseTx(height: number): Transaction {
  return {
    version: 1,
    inputs: [
      {
        prevOut: {
          txid: Buffer.alloc(32, 0),
          vout: 0xffffffff,
        },
        scriptSig: Buffer.from([height & 0xff, (height >> 8) & 0xff]),
        sequence: 0xffffffff,
        witness: [],
      },
    ],
    outputs: [
      {
        value: 5000000000n,
        scriptPubKey: Buffer.from([
          0x76, 0xa9, 0x14,
          ...Buffer.alloc(20, 0x11),
          0x88, 0xac,
        ]),
      },
    ],
    lockTime: 0,
  };
}

// Create a simple P2PKH transaction
function createP2PKHTx(prevTxid: Buffer, prevVout: number, value: bigint): Transaction {
  return {
    version: 2,
    inputs: [
      {
        prevOut: {
          txid: prevTxid,
          vout: prevVout,
        },
        scriptSig: Buffer.from([0x48, ...Buffer.alloc(72, 0xab)]), // Fake signature
        sequence: 0xfffffffe,
        witness: [],
      },
    ],
    outputs: [
      {
        value,
        scriptPubKey: Buffer.from([
          0x76, 0xa9, 0x14,
          ...Buffer.alloc(20, 0x22),
          0x88, 0xac,
        ]),
      },
    ],
    lockTime: 100,
  };
}

// Create a simple P2WPKH transaction with witness
function createP2WPKHTx(prevTxid: Buffer, prevVout: number, value: bigint): Transaction {
  return {
    version: 2,
    inputs: [
      {
        prevOut: {
          txid: prevTxid,
          vout: prevVout,
        },
        scriptSig: Buffer.alloc(0),
        sequence: 0xfffffffe,
        witness: [
          Buffer.alloc(72, 0xab), // signature
          Buffer.alloc(33, 0xcd), // pubkey
        ],
      },
    ],
    outputs: [
      {
        value,
        scriptPubKey: Buffer.from([
          0x00, 0x14,
          ...Buffer.alloc(20, 0x33),
        ]),
      },
    ],
    lockTime: 0,
  };
}

// Create a block with given transactions
function createBlock(txs: Transaction[], prevHash: Buffer, height: number): Block {
  const header: BlockHeader = {
    version: 0x20000000,
    prevBlock: prevHash,
    merkleRoot: Buffer.alloc(32, height), // Simplified
    timestamp: 1600000000 + height * 600,
    bits: 0x207fffff,
    nonce: 0,
  };
  return { header, transactions: txs };
}

// Mock classes
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
    this.bestBlock = { hash, height, chainWork };
  }
}

class MockMempool {
  private entries = new Map<string, {
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
  }>();

  getInfo() {
    return { size: this.entries.size, bytes: 1000, minFeeRate: 1 };
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

  addTestTransaction(tx: Transaction) {
    const txid = getTxId(tx);
    this.entries.set(txid.toString("hex"), {
      tx,
      txid,
      fee: 1000n,
      feeRate: 10,
      vsize: 200,
      weight: 800,
      addedTime: Math.floor(Date.now() / 1000),
      height: 100,
      spentBy: new Set(),
      dependsOn: new Set(),
    });
    return txid;
  }
}

class MockPeerManager {
  getConnectedPeers() { return []; }
  broadcast(_msg: unknown) {}
  listBanned() { return []; }
}

class MockFeeEstimator {
  estimateSmartFee(target: number) { return { feeRate: 10, blocks: target }; }
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
        timestamp: 1600000000,
        bits: 0x207fffff,
        nonce: 0,
      },
      height: 100,
      chainWork: 1000n,
      status: "valid-header" as const,
    };
  }
  getMedianTimePast(_entry: unknown) { return 1600000000; }
}

class MockChainDB {
  private blocks = new Map<string, Buffer>();
  private blockIndexes = new Map<string, {
    height: number;
    header: Buffer;
    nTx: number;
    status: number;
    dataPos: number;
  }>();
  private hashByHeight = new Map<number, Buffer>();
  private txIndex = new Map<string, { blockHash: Buffer; offset: number; length: number }>();

  async getBlock(hash: Buffer) {
    return this.blocks.get(hash.toString("hex")) ?? null;
  }

  async getBlockIndex(hash: Buffer) {
    return this.blockIndexes.get(hash.toString("hex")) ?? null;
  }

  async getBlockHashByHeight(height: number) {
    return this.hashByHeight.get(height) ?? null;
  }

  async getTxIndex(txid: Buffer) {
    return this.txIndex.get(txid.toString("hex")) ?? null;
  }

  setBlock(hash: Buffer, data: Buffer) {
    this.blocks.set(hash.toString("hex"), data);
  }

  setBlockIndex(hash: Buffer, record: {
    height: number;
    header: Buffer;
    nTx: number;
    status: number;
    dataPos: number;
  }) {
    this.blockIndexes.set(hash.toString("hex"), record);
  }

  setHashByHeight(height: number, hash: Buffer) {
    this.hashByHeight.set(height, hash);
  }

  setTxIndex(txid: Buffer, entry: { blockHash: Buffer; offset: number; length: number }) {
    this.txIndex.set(txid.toString("hex"), entry);
  }
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
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });
  return response.json();
}

let portCounter = 19550;
function getTestPort(): number {
  return portCounter++;
}

describe("getrawtransaction", () => {
  let server: RPCServer;
  let mockChainState: MockChainStateManager;
  let mockMempool: MockMempool;
  let mockDB: MockChainDB;
  let testPort: number;

  beforeEach(() => {
    testPort = getTestPort();
    mockChainState = new MockChainStateManager();
    mockMempool = new MockMempool();
    mockDB = new MockChainDB();

    const config: RPCServerConfig = {
      port: testPort,
      host: "127.0.0.1",
    };

    const deps: RPCServerDeps = {
      chainState: mockChainState as any,
      mempool: mockMempool as any,
      peerManager: new MockPeerManager() as any,
      feeEstimator: new MockFeeEstimator() as any,
      headerSync: new MockHeaderSync() as any,
      db: mockDB as any,
      params: REGTEST,
    };

    server = new RPCServer(config, deps);
    server.start();
  });

  afterEach(() => {
    server.stop();
  });

  describe("mempool transactions", () => {
    it("should return raw hex for mempool tx with verbose=false", async () => {
      const tx = createP2PKHTx(Buffer.alloc(32, 0x01), 0, 49000000n);
      const txid = mockMempool.addTestTransaction(tx);

      const res = await rpcRequest(testPort, "getrawtransaction", [
        txid.toString("hex"),
        false,
      ]);

      expect(res.error).toBeUndefined();
      expect(typeof res.result).toBe("string");
      expect(res.result).toBe(serializeTx(tx, true).toString("hex"));
    });

    it("should return JSON object for mempool tx with verbose=true", async () => {
      const tx = createP2PKHTx(Buffer.alloc(32, 0x02), 1, 48000000n);
      const txid = mockMempool.addTestTransaction(tx);

      const res = await rpcRequest(testPort, "getrawtransaction", [
        txid.toString("hex"),
        true,
      ]);

      expect(res.error).toBeUndefined();
      const result = res.result as Record<string, unknown>;

      expect(result.txid).toBe(txid.toString("hex"));
      expect(result.version).toBe(2);
      expect(result.locktime).toBe(100);
      expect(result.size).toBeGreaterThan(0);
      expect(result.vsize).toBeGreaterThan(0);
      expect(result.weight).toBeGreaterThan(0);
      expect(result.hex).toBeDefined();
      expect(Array.isArray(result.vin)).toBe(true);
      expect(Array.isArray(result.vout)).toBe(true);

      // Should not have block fields for mempool tx
      expect(result.blockhash).toBeUndefined();
      expect(result.confirmations).toBeUndefined();
    });

    it("should return verbose=1 same as verbose=true", async () => {
      const tx = createP2PKHTx(Buffer.alloc(32, 0x03), 0, 47000000n);
      const txid = mockMempool.addTestTransaction(tx);

      const res = await rpcRequest(testPort, "getrawtransaction", [
        txid.toString("hex"),
        1,
      ]);

      expect(res.error).toBeUndefined();
      const result = res.result as Record<string, unknown>;
      expect(result.txid).toBe(txid.toString("hex"));
    });

    it("should handle witness transactions", async () => {
      const tx = createP2WPKHTx(Buffer.alloc(32, 0x04), 0, 46000000n);
      const txid = mockMempool.addTestTransaction(tx);

      const res = await rpcRequest(testPort, "getrawtransaction", [
        txid.toString("hex"),
        true,
      ]);

      expect(res.error).toBeUndefined();
      const result = res.result as Record<string, unknown>;

      // txid and hash (wtxid) should be different for witness tx
      expect(result.txid).toBe(txid.toString("hex"));
      expect(result.hash).not.toBe(result.txid);

      // Should have witness data in vin
      const vin = result.vin as unknown[];
      expect(vin.length).toBe(1);
      const input = vin[0] as Record<string, unknown>;
      expect(input.txinwitness).toBeDefined();
      expect(Array.isArray(input.txinwitness)).toBe(true);
    });
  });

  describe("confirmed transactions via blockhash", () => {
    it("should find tx in specified block", async () => {
      const coinbase = createCoinbaseTx(50);
      const block = createBlock([coinbase], Buffer.alloc(32, 0), 50);
      const blockData = serializeBlock(block);
      const blockHash = hash256(blockData.subarray(0, 80));
      const coinbaseTxid = getTxId(coinbase);

      mockDB.setBlock(blockHash, blockData);
      mockDB.setBlockIndex(blockHash, {
        height: 50,
        header: blockData.subarray(0, 80),
        nTx: 1,
        status: 7,
        dataPos: 0,
      });
      mockChainState.setBestBlock(blockHash, 100, 1000n);

      const res = await rpcRequest(testPort, "getrawtransaction", [
        coinbaseTxid.toString("hex"),
        true,
        blockHash.toString("hex"),
      ]);

      expect(res.error).toBeUndefined();
      const result = res.result as Record<string, unknown>;

      expect(result.txid).toBe(coinbaseTxid.toString("hex"));
      expect(result.blockhash).toBe(blockHash.toString("hex"));
      expect(result.confirmations).toBe(51); // 100 - 50 + 1
      expect(result.blocktime).toBe(block.header.timestamp);
    });

    it("should return raw hex when verbose=false with blockhash", async () => {
      const coinbase = createCoinbaseTx(60);
      const block = createBlock([coinbase], Buffer.alloc(32, 0), 60);
      const blockData = serializeBlock(block);
      const blockHash = hash256(blockData.subarray(0, 80));
      const coinbaseTxid = getTxId(coinbase);

      mockDB.setBlock(blockHash, blockData);
      mockDB.setBlockIndex(blockHash, {
        height: 60,
        header: blockData.subarray(0, 80),
        nTx: 1,
        status: 7,
        dataPos: 0,
      });

      const res = await rpcRequest(testPort, "getrawtransaction", [
        coinbaseTxid.toString("hex"),
        false,
        blockHash.toString("hex"),
      ]);

      expect(res.error).toBeUndefined();
      expect(typeof res.result).toBe("string");
    });

    it("should error if tx not found in specified block", async () => {
      const coinbase = createCoinbaseTx(70);
      const block = createBlock([coinbase], Buffer.alloc(32, 0), 70);
      const blockData = serializeBlock(block);
      const blockHash = hash256(blockData.subarray(0, 80));

      mockDB.setBlock(blockHash, blockData);
      mockDB.setBlockIndex(blockHash, {
        height: 70,
        header: blockData.subarray(0, 80),
        nTx: 1,
        status: 7,
        dataPos: 0,
      });

      // Try to find a different txid
      const fakeTxid = Buffer.alloc(32, 0xff);

      const res = await rpcRequest(testPort, "getrawtransaction", [
        fakeTxid.toString("hex"),
        true,
        blockHash.toString("hex"),
      ]);

      expect(res.error).toBeDefined();
      expect(res.error?.code).toBe(RPCErrorCodes.INVALID_ADDRESS_OR_KEY);
      expect(res.error?.message).toContain("No such transaction found in the provided block");
    });

    it("should format coinbase input correctly", async () => {
      const coinbase = createCoinbaseTx(80);
      const block = createBlock([coinbase], Buffer.alloc(32, 0), 80);
      const blockData = serializeBlock(block);
      const blockHash = hash256(blockData.subarray(0, 80));
      const coinbaseTxid = getTxId(coinbase);

      mockDB.setBlock(blockHash, blockData);
      mockDB.setBlockIndex(blockHash, {
        height: 80,
        header: blockData.subarray(0, 80),
        nTx: 1,
        status: 7,
        dataPos: 0,
      });

      const res = await rpcRequest(testPort, "getrawtransaction", [
        coinbaseTxid.toString("hex"),
        true,
        blockHash.toString("hex"),
      ]);

      expect(res.error).toBeUndefined();
      const result = res.result as Record<string, unknown>;
      const vin = result.vin as unknown[];
      const input = vin[0] as Record<string, unknown>;

      // Coinbase should have 'coinbase' field, not 'txid'
      expect(input.coinbase).toBeDefined();
      expect(input.txid).toBeUndefined();
      expect(input.sequence).toBe(0xffffffff);
    });
  });

  describe("txindex lookup", () => {
    it("should find tx via txindex when no blockhash provided", async () => {
      const coinbase = createCoinbaseTx(90);
      const block = createBlock([coinbase], Buffer.alloc(32, 0), 90);
      const blockData = serializeBlock(block);
      const blockHash = hash256(blockData.subarray(0, 80));
      const coinbaseTxid = getTxId(coinbase);

      mockDB.setBlock(blockHash, blockData);
      mockDB.setBlockIndex(blockHash, {
        height: 90,
        header: blockData.subarray(0, 80),
        nTx: 1,
        status: 7,
        dataPos: 0,
      });
      mockDB.setTxIndex(coinbaseTxid, {
        blockHash,
        offset: 80,
        length: serializeTx(coinbase, true).length,
      });
      mockChainState.setBestBlock(blockHash, 100, 1000n);

      const res = await rpcRequest(testPort, "getrawtransaction", [
        coinbaseTxid.toString("hex"),
        true,
      ]);

      expect(res.error).toBeUndefined();
      const result = res.result as Record<string, unknown>;

      expect(result.txid).toBe(coinbaseTxid.toString("hex"));
      expect(result.blockhash).toBe(blockHash.toString("hex"));
      expect(result.confirmations).toBe(11); // 100 - 90 + 1
    });
  });

  describe("error cases", () => {
    it("should error with invalid txid format", async () => {
      const res = await rpcRequest(testPort, "getrawtransaction", [
        "not-a-hex-txid",
      ]);

      expect(res.error).toBeDefined();
      expect(res.error?.code).toBe(RPCErrorCodes.INVALID_PARAMS);
    });

    it("should error with wrong txid length", async () => {
      const res = await rpcRequest(testPort, "getrawtransaction", [
        "abcd1234", // Too short
      ]);

      expect(res.error).toBeDefined();
      expect(res.error?.code).toBe(RPCErrorCodes.INVALID_PARAMS);
      expect(res.error?.message).toContain("Invalid txid length");
    });

    it("should error with invalid blockhash format", async () => {
      const res = await rpcRequest(testPort, "getrawtransaction", [
        Buffer.alloc(32, 0x01).toString("hex"),
        true,
        123, // Not a string
      ]);

      expect(res.error).toBeDefined();
      expect(res.error?.code).toBe(RPCErrorCodes.INVALID_PARAMS);
    });

    it("should error when tx not found anywhere", async () => {
      const unknownTxid = Buffer.alloc(32, 0xee);

      const res = await rpcRequest(testPort, "getrawtransaction", [
        unknownTxid.toString("hex"),
        true,
      ]);

      expect(res.error).toBeDefined();
      expect(res.error?.code).toBe(RPCErrorCodes.INVALID_ADDRESS_OR_KEY);
      expect(res.error?.message).toContain("No such mempool or blockchain transaction");
    });
  });

  describe("scriptPubKey formatting", () => {
    it("should include address for P2PKH output", async () => {
      const tx = createP2PKHTx(Buffer.alloc(32, 0x05), 0, 45000000n);
      mockMempool.addTestTransaction(tx);
      const txid = getTxId(tx);

      const res = await rpcRequest(testPort, "getrawtransaction", [
        txid.toString("hex"),
        true,
      ]);

      expect(res.error).toBeUndefined();
      const result = res.result as Record<string, unknown>;
      const vout = result.vout as unknown[];
      const output = vout[0] as Record<string, unknown>;
      const scriptPubKey = output.scriptPubKey as Record<string, unknown>;

      expect(scriptPubKey.type).toBe("pubkeyhash");
      expect(scriptPubKey.address).toBeDefined();
      expect(typeof scriptPubKey.address).toBe("string");
      // Regtest P2PKH address starts with 'm' or 'n'
      expect(["m", "n"].includes((scriptPubKey.address as string)[0])).toBe(true);
    });

    it("should include address for P2WPKH output", async () => {
      const tx = createP2WPKHTx(Buffer.alloc(32, 0x06), 0, 44000000n);
      mockMempool.addTestTransaction(tx);
      const txid = getTxId(tx);

      const res = await rpcRequest(testPort, "getrawtransaction", [
        txid.toString("hex"),
        true,
      ]);

      expect(res.error).toBeUndefined();
      const result = res.result as Record<string, unknown>;
      const vout = result.vout as unknown[];
      const output = vout[0] as Record<string, unknown>;
      const scriptPubKey = output.scriptPubKey as Record<string, unknown>;

      expect(scriptPubKey.type).toBe("witness_v0_keyhash");
      expect(scriptPubKey.address).toBeDefined();
      // Regtest bech32 address starts with 'bcrt1'
      expect((scriptPubKey.address as string).startsWith("bcrt1")).toBe(true);
    });
  });
});
