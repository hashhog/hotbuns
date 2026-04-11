/**
 * Tests for REST API server.
 */

import { describe, test, expect, beforeAll, afterAll, beforeEach } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { RESTServer, type RESTServerConfig, type RESTServerDeps } from "../rpc/rest.js";
import type { ChainStateManager } from "../chain/state.js";
import type { Mempool, MempoolEntry } from "../mempool/mempool.js";
import type { HeaderSync, HeaderChainEntry } from "../sync/headers.js";
import type { ChainDB, UTXOEntry, BlockIndexRecord, TxIndexEntry } from "../storage/database.js";
import type { ConsensusParams } from "../consensus/params.js";
import { REGTEST } from "../consensus/params.js";
import type { Transaction } from "../validation/tx.js";
import {
  serializeBlock,
  serializeBlockHeader,
  getBlockHash,
  type Block,
  type BlockHeader,
} from "../validation/block.js";
import { serializeTx, getTxId, getWTxId, getTxWeight, getTxVSize } from "../validation/tx.js";

// =============================================================================
// Mock Classes
// =============================================================================

class MockChainState implements Partial<ChainStateManager> {
  bestBlock = {
    hash: Buffer.alloc(32, 0xaa),
    height: 100,
    chainWork: 0n,
  };

  getBestBlock() {
    return this.bestBlock;
  }
}

class MockMempool implements Partial<Mempool> {
  private entries = new Map<string, MempoolEntry>();
  private outpoints = new Set<string>();

  addEntry(txid: Buffer, entry: MempoolEntry) {
    this.entries.set(txid.toString("hex"), entry);
    // Add spent outpoints
    for (const input of entry.tx.inputs) {
      const key = `${input.prevOut.txid.toString("hex")}:${input.prevOut.vout}`;
      this.outpoints.add(key);
    }
  }

  getTransaction(txid: Buffer): MempoolEntry | null {
    return this.entries.get(txid.toString("hex")) ?? null;
  }

  getAllTxids(): Buffer[] {
    return Array.from(this.entries.keys()).map((hex) => Buffer.from(hex, "hex"));
  }

  getInfo() {
    let bytes = 0;
    for (const entry of this.entries.values()) {
      bytes += entry.vsize;
    }
    return {
      size: this.entries.size,
      bytes,
      minFeeRate: 1,
    };
  }

  isOutpointSpent(txid: Buffer, vout: number): boolean {
    const key = `${txid.toString("hex")}:${vout}`;
    return this.outpoints.has(key);
  }
}

class MockHeaderSync implements Partial<HeaderSync> {
  private headers = new Map<string, HeaderChainEntry>();

  addHeader(hash: Buffer, entry: HeaderChainEntry) {
    this.headers.set(hash.toString("hex"), entry);
  }

  getHeader(hash: Buffer): HeaderChainEntry | undefined {
    return this.headers.get(hash.toString("hex"));
  }

  getBestHeader(): HeaderChainEntry | null {
    return null;
  }

  getMedianTimePast(_entry: HeaderChainEntry): number {
    return Math.floor(Date.now() / 1000);
  }
}

class MockDB implements Partial<ChainDB> {
  private blocks = new Map<string, Buffer>();
  private blockIndex = new Map<string, BlockIndexRecord>();
  private hashByHeight = new Map<number, Buffer>();
  private utxos = new Map<string, UTXOEntry>();
  private txIndex = new Map<string, TxIndexEntry>();

  addBlock(hash: Buffer, data: Buffer, height: number, header: Buffer) {
    this.blocks.set(hash.toString("hex"), data);
    this.blockIndex.set(hash.toString("hex"), {
      height,
      header,
      nTx: 1,
      status: 0,
      dataPos: 0,
    });
    this.hashByHeight.set(height, hash);
  }

  addUTXO(txid: Buffer, vout: number, entry: UTXOEntry) {
    const key = `${txid.toString("hex")}:${vout}`;
    this.utxos.set(key, entry);
  }

  addTxIndex(txid: Buffer, entry: TxIndexEntry) {
    this.txIndex.set(txid.toString("hex"), entry);
  }

  async getBlock(hash: Buffer): Promise<Buffer | null> {
    return this.blocks.get(hash.toString("hex")) ?? null;
  }

  async getBlockIndex(hash: Buffer): Promise<BlockIndexRecord | null> {
    return this.blockIndex.get(hash.toString("hex")) ?? null;
  }

  async getBlockHashByHeight(height: number): Promise<Buffer | null> {
    return this.hashByHeight.get(height) ?? null;
  }

  async getUTXO(txid: Buffer, vout: number): Promise<UTXOEntry | null> {
    const key = `${txid.toString("hex")}:${vout}`;
    return this.utxos.get(key) ?? null;
  }

  async getTxIndex(txid: Buffer): Promise<TxIndexEntry | null> {
    return this.txIndex.get(txid.toString("hex")) ?? null;
  }
}

// =============================================================================
// Test Helpers
// =============================================================================

function createTestBlock(height: number): Block {
  const coinbaseTx: Transaction = {
    version: 2,
    inputs: [
      {
        prevOut: { txid: Buffer.alloc(32, 0), vout: 0xffffffff },
        scriptSig: Buffer.from([0x01, height]),
        sequence: 0xffffffff,
        witness: [],
      },
    ],
    outputs: [
      {
        value: 5000000000n,
        scriptPubKey: Buffer.from([0x51]), // OP_TRUE
      },
    ],
    lockTime: 0,
  };

  const header: BlockHeader = {
    version: 0x20000000,
    prevBlock: Buffer.alloc(32, height - 1),
    merkleRoot: Buffer.alloc(32, 0),
    timestamp: Math.floor(Date.now() / 1000),
    bits: 0x207fffff,
    nonce: 0,
  };

  return {
    header,
    transactions: [coinbaseTx],
  };
}

function createTestTx(): Transaction {
  return {
    version: 2,
    inputs: [
      {
        prevOut: { txid: Buffer.alloc(32, 0xcc), vout: 0 },
        scriptSig: Buffer.alloc(0),
        sequence: 0xffffffff,
        witness: [],
      },
    ],
    outputs: [
      {
        value: 1000000n,
        scriptPubKey: Buffer.from([0x51]),
      },
    ],
    lockTime: 0,
  };
}

function createMempoolEntry(tx: Transaction): MempoolEntry {
  return {
    tx,
    txid: getTxId(tx),
    fee: 1000n,
    feeRate: 10,
    vsize: getTxVSize(tx),
    weight: getTxWeight(tx),
    addedTime: Math.floor(Date.now() / 1000),
    height: 100,
    spentBy: new Set(),
    dependsOn: new Set(),
    ancestorCount: 1,
    ancestorSize: getTxVSize(tx),
    descendantCount: 1,
    descendantSize: getTxVSize(tx),
    clusterId: getTxId(tx).toString("hex"),
    miningScore: 10,
    ephemeralDustParents: new Set(),
    hasEphemeralDust: false,
  };
}

// =============================================================================
// Tests
// =============================================================================

describe("REST API", () => {
  let server: RESTServer;
  let mockChainState: MockChainState;
  let mockMempool: MockMempool;
  let mockHeaderSync: MockHeaderSync;
  let mockDB: MockDB;
  let baseUrl: string;
  let port: number;

  beforeAll(async () => {
    port = 18332 + Math.floor(Math.random() * 1000);
    mockChainState = new MockChainState();
    mockMempool = new MockMempool();
    mockHeaderSync = new MockHeaderSync();
    mockDB = new MockDB();

    const config: RESTServerConfig = {
      port,
      host: "127.0.0.1",
      txIndexEnabled: false,
    };

    const deps: RESTServerDeps = {
      chainState: mockChainState as any,
      mempool: mockMempool as any,
      headerSync: mockHeaderSync as any,
      db: mockDB as any,
      params: REGTEST,
    };

    server = new RESTServer(config, deps);
    server.start();
    baseUrl = `http://127.0.0.1:${port}`;

    // Give server time to start
    await new Promise((r) => setTimeout(r, 50));
  });

  afterAll(() => {
    server.stop();
  });

  beforeEach(() => {
    // Reset mocks between tests if needed
  });

  describe("rest_block", () => {
    test("GET /rest/block/<hash>.json returns block JSON", async () => {
      const block = createTestBlock(50);
      const blockData = serializeBlock(block);
      const blockHash = getBlockHash(block.header);
      const headerBuf = serializeBlockHeader(block.header);

      mockDB.addBlock(blockHash, blockData, 50, headerBuf);
      mockHeaderSync.addHeader(blockHash, {
        hash: blockHash,
        height: 50,
        header: block.header,
        chainWork: 1n,
        status: "valid-header" as const,
      });

      const res = await fetch(`${baseUrl}/rest/block/${blockHash.toString("hex")}.json`);
      expect(res.status).toBe(200);
      expect(res.headers.get("Content-Type")).toBe("application/json");

      const json = await res.json();
      expect(json.hash).toBe(Buffer.from(blockHash).reverse().toString("hex"));
      expect(json.height).toBe(50);
      expect(json.nTx).toBe(1);
      expect(Array.isArray(json.tx)).toBe(true);
    });

    test("GET /rest/block/<hash>.bin returns binary data", async () => {
      const block = createTestBlock(51);
      const blockData = serializeBlock(block);
      const blockHash = getBlockHash(block.header);
      const headerBuf = serializeBlockHeader(block.header);

      mockDB.addBlock(blockHash, blockData, 51, headerBuf);

      const res = await fetch(`${baseUrl}/rest/block/${blockHash.toString("hex")}.bin`);
      expect(res.status).toBe(200);
      expect(res.headers.get("Content-Type")).toBe("application/octet-stream");

      const buf = Buffer.from(await res.arrayBuffer());
      expect(buf.equals(blockData)).toBe(true);
    });

    test("GET /rest/block/<hash>.hex returns hex string", async () => {
      const block = createTestBlock(52);
      const blockData = serializeBlock(block);
      const blockHash = getBlockHash(block.header);
      const headerBuf = serializeBlockHeader(block.header);

      mockDB.addBlock(blockHash, blockData, 52, headerBuf);

      const res = await fetch(`${baseUrl}/rest/block/${blockHash.toString("hex")}.hex`);
      expect(res.status).toBe(200);
      expect(res.headers.get("Content-Type")).toBe("text/plain");

      const text = await res.text();
      expect(text.trim()).toBe(blockData.toString("hex"));
    });

    test("returns 404 for unknown block hash", async () => {
      const unknownHash = Buffer.alloc(32, 0xff).toString("hex");
      const res = await fetch(`${baseUrl}/rest/block/${unknownHash}.json`);
      expect(res.status).toBe(404);
    });

    test("returns 400 for invalid hash", async () => {
      const res = await fetch(`${baseUrl}/rest/block/invalidhash.json`);
      expect(res.status).toBe(400);
    });
  });

  describe("rest_block_notxdetails", () => {
    test("GET /rest/block/notxdetails/<hash>.json returns block with txids only", async () => {
      const block = createTestBlock(53);
      const blockData = serializeBlock(block);
      const blockHash = getBlockHash(block.header);
      const headerBuf = serializeBlockHeader(block.header);

      mockDB.addBlock(blockHash, blockData, 53, headerBuf);
      mockHeaderSync.addHeader(blockHash, {
        hash: blockHash,
        height: 53,
        header: block.header,
        chainWork: 1n,
        status: "valid-header" as const,
      });

      const res = await fetch(`${baseUrl}/rest/block/notxdetails/${blockHash.toString("hex")}.json`);
      expect(res.status).toBe(200);

      const json = await res.json();
      expect(json.hash).toBe(Buffer.from(blockHash).reverse().toString("hex"));
      expect(Array.isArray(json.tx)).toBe(true);
      // Should have txids (strings), not full tx objects
      expect(typeof json.tx[0]).toBe("string");
    });
  });

  describe("rest_blockhashbyheight", () => {
    test("GET /rest/blockhashbyheight/<height>.json returns block hash", async () => {
      const block = createTestBlock(60);
      const blockHash = getBlockHash(block.header);
      const headerBuf = serializeBlockHeader(block.header);

      mockDB.addBlock(blockHash, serializeBlock(block), 60, headerBuf);

      const res = await fetch(`${baseUrl}/rest/blockhashbyheight/60.json`);
      expect(res.status).toBe(200);

      const json = await res.json();
      expect(json.blockhash).toBe(Buffer.from(blockHash).reverse().toString("hex"));
    });

    test("GET /rest/blockhashbyheight/<height>.hex returns hash as hex", async () => {
      const block = createTestBlock(61);
      const blockHash = getBlockHash(block.header);
      const headerBuf = serializeBlockHeader(block.header);

      mockDB.addBlock(blockHash, serializeBlock(block), 61, headerBuf);

      const res = await fetch(`${baseUrl}/rest/blockhashbyheight/61.hex`);
      expect(res.status).toBe(200);
      expect(res.headers.get("Content-Type")).toBe("text/plain");

      const text = await res.text();
      expect(text.trim()).toBe(Buffer.from(blockHash).reverse().toString("hex"));
    });

    test("returns 404 for height out of range", async () => {
      // Best block is at height 100
      const res = await fetch(`${baseUrl}/rest/blockhashbyheight/200.json`);
      expect(res.status).toBe(404);
    });

    test("returns 400 for invalid height", async () => {
      const res = await fetch(`${baseUrl}/rest/blockhashbyheight/-1.json`);
      expect(res.status).toBe(400);
    });
  });

  describe("rest_headers", () => {
    test("GET /rest/headers/<count>/<hash>.json returns headers", async () => {
      const block = createTestBlock(70);
      const blockHash = getBlockHash(block.header);
      const headerBuf = serializeBlockHeader(block.header);

      mockDB.addBlock(blockHash, serializeBlock(block), 70, headerBuf);
      mockHeaderSync.addHeader(blockHash, {
        hash: blockHash,
        height: 70,
        header: block.header,
        chainWork: 1n,
        status: "valid-header" as const,
      });

      const res = await fetch(`${baseUrl}/rest/headers/1/${blockHash.toString("hex")}.json`);
      expect(res.status).toBe(200);

      const json = await res.json();
      expect(Array.isArray(json)).toBe(true);
      expect(json.length).toBeGreaterThanOrEqual(1);
    });

    test("GET /rest/headers/<count>/<hash>.bin returns binary headers", async () => {
      const block = createTestBlock(71);
      const blockHash = getBlockHash(block.header);
      const headerBuf = serializeBlockHeader(block.header);

      mockDB.addBlock(blockHash, serializeBlock(block), 71, headerBuf);

      const res = await fetch(`${baseUrl}/rest/headers/1/${blockHash.toString("hex")}.bin`);
      expect(res.status).toBe(200);
      expect(res.headers.get("Content-Type")).toBe("application/octet-stream");

      const buf = Buffer.from(await res.arrayBuffer());
      // Each header is 80 bytes
      expect(buf.length).toBeGreaterThanOrEqual(80);
    });
  });

  describe("rest_tx", () => {
    test("GET /rest/tx/<txid>.json returns mempool tx", async () => {
      const tx = createTestTx();
      const txid = getTxId(tx);
      const entry = createMempoolEntry(tx);

      mockMempool.addEntry(txid, entry);

      const res = await fetch(`${baseUrl}/rest/tx/${txid.toString("hex")}.json`);
      expect(res.status).toBe(200);

      const json = await res.json();
      expect(json.txid).toBe(Buffer.from(txid).reverse().toString("hex"));
      expect(json.version).toBe(2);
      expect(Array.isArray(json.vin)).toBe(true);
      expect(Array.isArray(json.vout)).toBe(true);
    });

    test("GET /rest/tx/<txid>.hex returns tx hex", async () => {
      const tx = createTestTx();
      const txid = getTxId(tx);
      const entry = createMempoolEntry(tx);

      mockMempool.addEntry(txid, entry);

      const res = await fetch(`${baseUrl}/rest/tx/${txid.toString("hex")}.hex`);
      expect(res.status).toBe(200);
      expect(res.headers.get("Content-Type")).toBe("text/plain");

      const text = await res.text();
      expect(text.trim()).toBe(serializeTx(tx, true).toString("hex"));
    });

    test("returns 404 for unknown tx without txindex", async () => {
      const unknownTxid = Buffer.alloc(32, 0xee).toString("hex");
      const res = await fetch(`${baseUrl}/rest/tx/${unknownTxid}.json`);
      expect(res.status).toBe(404);
      const text = await res.text();
      expect(text).toContain("txindex");
    });
  });

  describe("rest_getutxos", () => {
    test("GET /rest/getutxos/<txid-vout>.json returns UTXO status", async () => {
      const txid = Buffer.alloc(32, 0xdd);
      const entry: UTXOEntry = {
        height: 50,
        coinbase: false,
        amount: 1000000n,
        scriptPubKey: Buffer.from([0x51]),
      };

      mockDB.addUTXO(txid, 0, entry);

      const res = await fetch(`${baseUrl}/rest/getutxos/${txid.toString("hex")}-0.json`);
      expect(res.status).toBe(200);

      const json = await res.json();
      expect(json.chainHeight).toBe(100);
      expect(json.bitmap).toBe("1");
      expect(Array.isArray(json.utxos)).toBe(true);
      expect(json.utxos.length).toBe(1);
      expect(json.utxos[0].height).toBe(50);
    });

    test("returns 0 bitmap for non-existent UTXO", async () => {
      const txid = Buffer.alloc(32, 0xab);
      const res = await fetch(`${baseUrl}/rest/getutxos/${txid.toString("hex")}-0.json`);
      expect(res.status).toBe(200);

      const json = await res.json();
      expect(json.bitmap).toBe("0");
      expect(json.utxos.length).toBe(0);
    });

    test("handles multiple outpoints", async () => {
      const txid1 = Buffer.alloc(32, 0x11);
      const txid2 = Buffer.alloc(32, 0x22);

      mockDB.addUTXO(txid1, 0, {
        height: 50,
        coinbase: false,
        amount: 1000000n,
        scriptPubKey: Buffer.from([0x51]),
      });

      // txid2 doesn't have a UTXO

      const res = await fetch(
        `${baseUrl}/rest/getutxos/${txid1.toString("hex")}-0/${txid2.toString("hex")}-0.json`
      );
      expect(res.status).toBe(200);

      const json = await res.json();
      expect(json.bitmap).toBe("10"); // First exists, second doesn't
      expect(json.utxos.length).toBe(1);
    });

    test("checkmempool flag filters spent outputs", async () => {
      const txid = Buffer.alloc(32, 0x33);
      mockDB.addUTXO(txid, 0, {
        height: 50,
        coinbase: false,
        amount: 1000000n,
        scriptPubKey: Buffer.from([0x51]),
      });

      // Create a mempool tx that spends this UTXO
      const spendingTx: Transaction = {
        version: 2,
        inputs: [
          {
            prevOut: { txid, vout: 0 },
            scriptSig: Buffer.alloc(0),
            sequence: 0xffffffff,
            witness: [],
          },
        ],
        outputs: [
          {
            value: 900000n,
            scriptPubKey: Buffer.from([0x51]),
          },
        ],
        lockTime: 0,
      };
      mockMempool.addEntry(getTxId(spendingTx), createMempoolEntry(spendingTx));

      // Without checkmempool - should find the UTXO
      const res1 = await fetch(`${baseUrl}/rest/getutxos/${txid.toString("hex")}-0.json`);
      const json1 = await res1.json();
      expect(json1.bitmap).toBe("1");

      // With checkmempool - should NOT find the UTXO (spent in mempool)
      const res2 = await fetch(`${baseUrl}/rest/getutxos/checkmempool/${txid.toString("hex")}-0.json`);
      const json2 = await res2.json();
      expect(json2.bitmap).toBe("0");
    });

    test("returns 400 for too many outpoints", async () => {
      // Create 16 outpoints (exceeds MAX_GETUTXOS_OUTPOINTS = 15)
      const outpoints = [];
      for (let i = 0; i < 16; i++) {
        const txid = Buffer.alloc(32, i);
        outpoints.push(`${txid.toString("hex")}-0`);
      }

      const res = await fetch(`${baseUrl}/rest/getutxos/${outpoints.join("/")}.json`);
      expect(res.status).toBe(400);
      const text = await res.text();
      expect(text).toContain("max outpoints exceeded");
    });
  });

  describe("rest_mempool", () => {
    test("GET /rest/mempool/info.json returns mempool info", async () => {
      const res = await fetch(`${baseUrl}/rest/mempool/info.json`);
      expect(res.status).toBe(200);

      const json = await res.json();
      expect(typeof json.size).toBe("number");
      expect(typeof json.bytes).toBe("number");
      expect(json.loaded).toBe(true);
    });

    test("GET /rest/mempool/contents.json returns mempool contents", async () => {
      const tx = createTestTx();
      const txid = getTxId(tx);
      const entry = createMempoolEntry(tx);

      // Use a fresh mempool for this test
      const newMockMempool = new MockMempool();
      newMockMempool.addEntry(txid, entry);

      // Update the server deps
      const config: RESTServerConfig = {
        port: port + 1,
        host: "127.0.0.1",
        txIndexEnabled: false,
      };
      const deps: RESTServerDeps = {
        chainState: mockChainState as any,
        mempool: newMockMempool as any,
        headerSync: mockHeaderSync as any,
        db: mockDB as any,
        params: REGTEST,
      };

      const tempServer = new RESTServer(config, deps);
      tempServer.start();
      await new Promise((r) => setTimeout(r, 50));

      try {
        const res = await fetch(`http://127.0.0.1:${port + 1}/rest/mempool/contents.json`);
        expect(res.status).toBe(200);

        const json = await res.json();
        expect(typeof json).toBe("object");
        const txidHex = Buffer.from(txid).reverse().toString("hex");
        expect(json[txidHex]).toBeDefined();
        expect(json[txidHex].vsize).toBe(entry.vsize);
      } finally {
        tempServer.stop();
      }
    });

    test("returns 400 for invalid mempool endpoint", async () => {
      const res = await fetch(`${baseUrl}/rest/mempool/invalid.json`);
      expect(res.status).toBe(400);
    });

    test("returns 404 for non-json format", async () => {
      const res = await fetch(`${baseUrl}/rest/mempool/info.bin`);
      expect(res.status).toBe(404);
    });
  });

  describe("rest_chaininfo", () => {
    test("GET /rest/chaininfo.json returns chain info", async () => {
      const res = await fetch(`${baseUrl}/rest/chaininfo.json`);
      expect(res.status).toBe(200);

      const json = await res.json();
      expect(json.chain).toBe("regtest");
      expect(json.blocks).toBe(100);
      expect(typeof json.bestblockhash).toBe("string");
      expect(typeof json.chainwork).toBe("string");
    });
  });

  describe("error handling", () => {
    test("returns 404 for unknown endpoint", async () => {
      const res = await fetch(`${baseUrl}/rest/unknown/endpoint.json`);
      expect(res.status).toBe(404);
    });

    test("returns 404 for non-/rest/ paths", async () => {
      const res = await fetch(`${baseUrl}/other/path`);
      expect(res.status).toBe(404);
    });

    test("returns 405 for non-GET requests", async () => {
      const res = await fetch(`${baseUrl}/rest/chaininfo.json`, {
        method: "POST",
      });
      expect(res.status).toBe(405);
    });
  });
});
