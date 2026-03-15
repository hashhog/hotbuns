/**
 * Tests for block indexes: TxIndex, BlockFilterIndex, CoinStatsIndex.
 *
 * Tests cover:
 * - GCS filter encoding/decoding
 * - SipHash implementation
 * - Golomb-Rice coding
 * - TxIndex block indexing and lookup
 * - BlockFilterIndex construction and matching
 * - CoinStatsIndex statistics tracking
 */

import { describe, it, expect, beforeEach, afterEach } from "bun:test";
import {
  GCSFilter,
  sipHash24,
  fastRange64,
  golombRiceEncode,
  golombRiceDecode,
  BitStreamWriter,
  BitStreamReader,
  computeFilterHeader,
  BASIC_FILTER_P,
  BASIC_FILTER_M,
  MuHash,
  TxIndexManager,
  BlockFilterIndex,
  CoinStatsIndex,
  IndexManager,
} from "../storage/indexes.js";
import type { Block, BlockHeader } from "../validation/block.js";
import type { Transaction } from "../validation/tx.js";
import { getTxId } from "../validation/tx.js";
import type { SpentUTXO } from "../chain/utxo.js";
import { hash256 } from "../crypto/primitives.js";

// =============================================================================
// Helper Functions
// =============================================================================

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
          0x76,
          0xa9,
          0x14,
          ...Buffer.alloc(20, height & 0xff),
          0x88,
          0xac,
        ]),
      },
    ],
    lockTime: 0,
  };
}

function createP2PKHTx(
  prevTxid: Buffer,
  prevVout: number,
  value: bigint
): Transaction {
  return {
    version: 2,
    inputs: [
      {
        prevOut: {
          txid: prevTxid,
          vout: prevVout,
        },
        scriptSig: Buffer.from([0x48, ...Buffer.alloc(72, 0xab)]),
        sequence: 0xfffffffe,
        witness: [],
      },
    ],
    outputs: [
      {
        value,
        scriptPubKey: Buffer.from([
          0x76,
          0xa9,
          0x14,
          ...Buffer.alloc(20, 0x22),
          0x88,
          0xac,
        ]),
      },
    ],
    lockTime: 0,
  };
}

function createBlock(
  txs: Transaction[],
  prevHash: Buffer,
  height: number
): Block {
  const header: BlockHeader = {
    version: 0x20000000,
    prevBlock: prevHash,
    merkleRoot: Buffer.alloc(32, height),
    timestamp: 1600000000 + height * 600,
    bits: 0x207fffff,
    nonce: height,
  };
  return { header, transactions: txs };
}

function getBlockHash(header: BlockHeader): Buffer {
  const { BufferWriter } = require("../wire/serialization.js");
  const writer = new BufferWriter();
  writer.writeInt32LE(header.version);
  writer.writeHash(header.prevBlock);
  writer.writeHash(header.merkleRoot);
  writer.writeUInt32LE(header.timestamp);
  writer.writeUInt32LE(header.bits);
  writer.writeUInt32LE(header.nonce);
  return hash256(writer.toBuffer());
}

// =============================================================================
// SipHash Tests
// =============================================================================

describe("sipHash24", () => {
  it("should compute consistent hashes", () => {
    const k0 = 0x0706050403020100n;
    const k1 = 0x0f0e0d0c0b0a0908n;
    const data = Buffer.from([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]);

    const hash1 = sipHash24(k0, k1, data);
    const hash2 = sipHash24(k0, k1, data);

    expect(hash1).toBe(hash2);
  });

  it("should produce different hashes for different inputs", () => {
    const k0 = 0x0706050403020100n;
    const k1 = 0x0f0e0d0c0b0a0908n;

    const hash1 = sipHash24(k0, k1, Buffer.from("hello"));
    const hash2 = sipHash24(k0, k1, Buffer.from("world"));

    expect(hash1).not.toBe(hash2);
  });

  it("should produce different hashes for different keys", () => {
    const data = Buffer.from("test");

    const hash1 = sipHash24(1n, 2n, data);
    const hash2 = sipHash24(3n, 4n, data);

    expect(hash1).not.toBe(hash2);
  });

  it("should handle empty input", () => {
    const k0 = 0x0706050403020100n;
    const k1 = 0x0f0e0d0c0b0a0908n;
    const hash = sipHash24(k0, k1, Buffer.alloc(0));

    expect(typeof hash).toBe("bigint");
  });

  it("should handle single byte input", () => {
    const k0 = 0x0706050403020100n;
    const k1 = 0x0f0e0d0c0b0a0908n;
    const hash = sipHash24(k0, k1, Buffer.from([0x42]));

    expect(typeof hash).toBe("bigint");
  });
});

// =============================================================================
// Fast Range Tests
// =============================================================================

describe("fastRange64", () => {
  it("should map to correct range", () => {
    const result = fastRange64(0xffffffffffffffffn, 1000n);
    expect(result).toBeLessThan(1000n);
  });

  it("should return 0 for hash 0", () => {
    const result = fastRange64(0n, 1000n);
    expect(result).toBe(0n);
  });

  it("should handle large ranges", () => {
    const hash = 0x8000000000000000n;
    const range = 1000000n;
    const result = fastRange64(hash, range);

    expect(result).toBeLessThan(range);
    expect(result).toBeGreaterThanOrEqual(0n);
  });
});

// =============================================================================
// BitStream Tests
// =============================================================================

describe("BitStream", () => {
  it("should write and read single bits", () => {
    const writer = new BitStreamWriter();
    writer.writeBit(1);
    writer.writeBit(0);
    writer.writeBit(1);
    writer.writeBit(1);
    writer.flush();

    const reader = new BitStreamReader(writer.toBuffer());
    expect(reader.readBit()).toBe(1);
    expect(reader.readBit()).toBe(0);
    expect(reader.readBit()).toBe(1);
    expect(reader.readBit()).toBe(1);
  });

  it("should write and read multi-bit values", () => {
    const writer = new BitStreamWriter();
    writer.writeBits(0b10101n, 5);
    writer.writeBits(0b111n, 3);
    writer.flush();

    const reader = new BitStreamReader(writer.toBuffer());
    expect(reader.readBits(5)).toBe(0b10101n);
    expect(reader.readBits(3)).toBe(0b111n);
  });

  it("should handle byte boundaries correctly", () => {
    const writer = new BitStreamWriter();
    // Write 12 bits across byte boundary
    writer.writeBits(0xabcn, 12);
    writer.flush();

    const reader = new BitStreamReader(writer.toBuffer());
    expect(reader.readBits(12)).toBe(0xabcn);
  });

  it("should write and read across multiple bytes", () => {
    const writer = new BitStreamWriter();
    // Write 20 bits
    writer.writeBits(0xfffffn, 20);
    writer.flush();

    const reader = new BitStreamReader(writer.toBuffer());
    expect(reader.readBits(20)).toBe(0xfffffn);
  });
});

// =============================================================================
// Golomb-Rice Coding Tests
// =============================================================================

describe("Golomb-Rice coding", () => {
  it("should encode and decode small values", () => {
    const writer = new BitStreamWriter();
    golombRiceEncode(writer, BASIC_FILTER_P, 100n);
    writer.flush();

    const reader = new BitStreamReader(writer.toBuffer());
    const decoded = golombRiceDecode(reader, BASIC_FILTER_P);

    expect(decoded).toBe(100n);
  });

  it("should encode and decode zero", () => {
    const writer = new BitStreamWriter();
    golombRiceEncode(writer, BASIC_FILTER_P, 0n);
    writer.flush();

    const reader = new BitStreamReader(writer.toBuffer());
    const decoded = golombRiceDecode(reader, BASIC_FILTER_P);

    expect(decoded).toBe(0n);
  });

  it("should encode and decode large values", () => {
    const writer = new BitStreamWriter();
    const largeValue = (1n << BASIC_FILTER_P) * 5n + 12345n;
    golombRiceEncode(writer, BASIC_FILTER_P, largeValue);
    writer.flush();

    const reader = new BitStreamReader(writer.toBuffer());
    const decoded = golombRiceDecode(reader, BASIC_FILTER_P);

    expect(decoded).toBe(largeValue);
  });

  it("should encode and decode multiple values", () => {
    const values = [0n, 100n, 50000n, 1000000n, 42n];
    const writer = new BitStreamWriter();

    for (const v of values) {
      golombRiceEncode(writer, BASIC_FILTER_P, v);
    }
    writer.flush();

    const reader = new BitStreamReader(writer.toBuffer());
    const decoded: bigint[] = [];
    for (let i = 0; i < values.length; i++) {
      decoded.push(golombRiceDecode(reader, BASIC_FILTER_P));
    }

    expect(decoded).toEqual(values);
  });
});

// =============================================================================
// GCS Filter Tests
// =============================================================================

describe("GCSFilter", () => {
  it("should create empty filter", () => {
    const blockHash = Buffer.alloc(32, 0x01);
    const filter = new GCSFilter([], blockHash);

    expect(filter.getN()).toBe(0);
    expect(filter.getEncodedFilter().length).toBeGreaterThan(0);
  });

  it("should create filter with single element", () => {
    const blockHash = Buffer.alloc(32, 0x02);
    const element = Buffer.from("test element");
    const filter = new GCSFilter([element], blockHash);

    expect(filter.getN()).toBe(1);
    expect(filter.match(element)).toBe(true);
  });

  it("should create filter with multiple elements", () => {
    const blockHash = Buffer.alloc(32, 0x03);
    const elements = [
      Buffer.from("element1"),
      Buffer.from("element2"),
      Buffer.from("element3"),
    ];
    const filter = new GCSFilter(elements, blockHash);

    expect(filter.getN()).toBe(3);
    for (const elem of elements) {
      expect(filter.match(elem)).toBe(true);
    }
  });

  it("should not match non-existent elements (low false positive)", () => {
    const blockHash = Buffer.alloc(32, 0x04);
    const elements = [Buffer.from("a"), Buffer.from("b"), Buffer.from("c")];
    const filter = new GCSFilter(elements, blockHash);

    // Test many non-existent elements
    let falsePositives = 0;
    for (let i = 0; i < 1000; i++) {
      const test = Buffer.from(`nonexistent_${i}`);
      if (filter.match(test)) {
        falsePositives++;
      }
    }

    // With M=784931 and 3 elements, expected FP rate is ~3/784931 per test
    // For 1000 tests, we'd expect ~0.004 false positives on average
    // Allow up to 10 for statistical variance
    expect(falsePositives).toBeLessThan(10);
  });

  it("should support matchAny", () => {
    const blockHash = Buffer.alloc(32, 0x05);
    const filterElements = [Buffer.from("x"), Buffer.from("y"), Buffer.from("z")];
    const filter = new GCSFilter(filterElements, blockHash);

    // Test with overlapping set
    expect(filter.matchAny([Buffer.from("a"), Buffer.from("x")])).toBe(true);

    // Test with non-overlapping set (likely false)
    const nonExistent = [Buffer.from("foo"), Buffer.from("bar")];
    // Can't guarantee no false positives, but likely false
    // Don't assert this as it's probabilistic
  });

  it("should serialize and deserialize correctly", () => {
    const blockHash = Buffer.alloc(32, 0x06);
    const elements = [
      Buffer.from("script1"),
      Buffer.from("script2"),
      Buffer.from("script3"),
    ];
    const filter = new GCSFilter(elements, blockHash);
    const encoded = filter.getEncodedFilter();

    const restored = GCSFilter.fromEncoded(encoded, blockHash);

    expect(restored.getN()).toBe(filter.getN());
    for (const elem of elements) {
      expect(restored.match(elem)).toBe(true);
    }
  });

  it("should compute filter hash", () => {
    const blockHash = Buffer.alloc(32, 0x07);
    const filter = new GCSFilter([Buffer.from("test")], blockHash);
    const hash = filter.getHash();

    expect(hash.length).toBe(32);
    expect(hash).toBeInstanceOf(Buffer);
  });
});

// =============================================================================
// Filter Header Tests
// =============================================================================

describe("computeFilterHeader", () => {
  it("should compute filter header as hash chain", () => {
    const filterHash = Buffer.alloc(32, 0x11);
    const prevHeader = Buffer.alloc(32, 0x22);

    const header = computeFilterHeader(filterHash, prevHeader);

    expect(header.length).toBe(32);
    expect(header).not.toEqual(filterHash);
    expect(header).not.toEqual(prevHeader);
  });

  it("should produce different headers for different inputs", () => {
    const filterHash1 = Buffer.alloc(32, 0x01);
    const filterHash2 = Buffer.alloc(32, 0x02);
    const prevHeader = Buffer.alloc(32, 0x00);

    const header1 = computeFilterHeader(filterHash1, prevHeader);
    const header2 = computeFilterHeader(filterHash2, prevHeader);

    expect(header1).not.toEqual(header2);
  });
});

// =============================================================================
// MuHash Tests
// =============================================================================

describe("MuHash", () => {
  it("should initialize to identity", () => {
    const muhash = new MuHash();
    const hash = muhash.finalize();

    expect(hash.length).toBe(32);
  });

  it("should produce different hashes for different inputs", () => {
    const muhash1 = new MuHash();
    muhash1.insert(Buffer.alloc(32, 1), 0, 100, false, 50000000n, Buffer.from([0x76, 0xa9]));

    const muhash2 = new MuHash();
    muhash2.insert(Buffer.alloc(32, 2), 0, 100, false, 50000000n, Buffer.from([0x76, 0xa9]));

    const hash1 = muhash1.finalize();
    const hash2 = muhash2.finalize();

    expect(hash1).not.toEqual(hash2);
  });

  it("should support insert and remove operations", () => {
    const txid = Buffer.alloc(32, 0x42);
    const vout = 0;
    const height = 100;
    const isCoinbase = false;
    const value = 50000000n;
    const script = Buffer.from([0x76, 0xa9, 0x14, ...Buffer.alloc(20, 0x11), 0x88, 0xac]);

    const muhash1 = new MuHash();
    muhash1.insert(txid, vout, height, isCoinbase, value, script);

    const muhash2 = new MuHash();
    muhash2.insert(txid, vout, height, isCoinbase, value, script);
    muhash2.remove(txid, vout, height, isCoinbase, value, script);

    const hash1 = muhash1.finalize();
    const hash2 = muhash2.finalize();

    // After removing what was inserted, should be back to initial state
    expect(hash1).not.toEqual(hash2);
  });

  it("should serialize and deserialize", () => {
    const muhash = new MuHash();
    muhash.insert(Buffer.alloc(32, 1), 0, 100, false, 50000000n, Buffer.alloc(25));

    const serialized = muhash.serialize();
    expect(serialized.length).toBe(64);

    const restored = MuHash.deserialize(serialized);
    const hash1 = muhash.finalize();
    const hash2 = restored.finalize();

    expect(hash1).toEqual(hash2);
  });

  it("should clone correctly", () => {
    const muhash = new MuHash();
    muhash.insert(Buffer.alloc(32, 1), 0, 100, false, 50000000n, Buffer.alloc(25));

    const cloned = muhash.clone();
    muhash.insert(Buffer.alloc(32, 2), 0, 101, false, 60000000n, Buffer.alloc(25));

    const hash1 = muhash.finalize();
    const hash2 = cloned.finalize();

    expect(hash1).not.toEqual(hash2);
  });
});

// =============================================================================
// Mock ChainDB for Integration Tests
// =============================================================================

class MockChainDB {
  private data = new Map<string, Buffer>();
  private txIndex = new Map<string, { blockHash: Buffer; offset: number; length: number }>();

  db = {
    get: async (key: Buffer) => {
      const result = this.data.get(key.toString("hex"));
      if (!result) throw new Error("Not found");
      return result;
    },
    put: async (key: Buffer, value: Buffer) => {
      this.data.set(key.toString("hex"), value);
    },
    del: async (key: Buffer) => {
      this.data.delete(key.toString("hex"));
    },
  };

  async batch(ops: any[]): Promise<void> {
    for (const op of ops) {
      const key = Buffer.concat([Buffer.from([op.prefix]), op.key]);
      if (op.type === "put") {
        this.data.set(key.toString("hex"), op.value);
      } else {
        this.data.delete(key.toString("hex"));
      }
    }
  }

  async batchWrite(ops: any[]): Promise<void> {
    await this.batch(ops);
  }

  async getTxIndex(txid: Buffer) {
    return this.txIndex.get(txid.toString("hex")) ?? null;
  }

  setTxIndex(txid: Buffer, entry: { blockHash: Buffer; offset: number; length: number }) {
    this.txIndex.set(txid.toString("hex"), entry);
  }
}

// =============================================================================
// TxIndex Tests
// =============================================================================

describe("TxIndexManager", () => {
  let mockDB: MockChainDB;
  let txIndex: TxIndexManager;

  beforeEach(() => {
    mockDB = new MockChainDB();
    txIndex = new TxIndexManager(mockDB as any, true);
  });

  it("should be disabled by default", () => {
    const disabled = new TxIndexManager(mockDB as any);
    expect(disabled.isEnabled()).toBe(false);
  });

  it("should be enabled when configured", () => {
    expect(txIndex.isEnabled()).toBe(true);
  });

  it("should skip genesis block", async () => {
    const coinbase = createCoinbaseTx(0);
    const block = createBlock([coinbase], Buffer.alloc(32, 0), 0);
    const blockHash = getBlockHash(block.header);

    await txIndex.indexBlock(block, 0, blockHash, 0);

    expect(txIndex.getHeight()).toBe(0);
    // Genesis txs should not be indexed
    const entry = await txIndex.getTransaction(getTxId(coinbase));
    expect(entry).toBeNull();
  });

  it("should index block transactions", async () => {
    const coinbase = createCoinbaseTx(1);
    const block = createBlock([coinbase], Buffer.alloc(32, 0), 1);
    const blockHash = getBlockHash(block.header);

    await txIndex.indexBlock(block, 1, blockHash, 0);

    expect(txIndex.getHeight()).toBe(1);
  });

  it("should update height after indexing", async () => {
    expect(txIndex.getHeight()).toBe(-1);

    const block1 = createBlock([createCoinbaseTx(1)], Buffer.alloc(32, 0), 1);
    await txIndex.indexBlock(block1, 1, getBlockHash(block1.header), 0);
    expect(txIndex.getHeight()).toBe(1);

    const block2 = createBlock([createCoinbaseTx(2)], getBlockHash(block1.header), 2);
    await txIndex.indexBlock(block2, 2, getBlockHash(block2.header), 0);
    expect(txIndex.getHeight()).toBe(2);
  });
});

// =============================================================================
// BlockFilterIndex Tests
// =============================================================================

describe("BlockFilterIndex", () => {
  let mockDB: MockChainDB;
  let filterIndex: BlockFilterIndex;

  beforeEach(() => {
    mockDB = new MockChainDB();
    filterIndex = new BlockFilterIndex(mockDB as any, true);
  });

  it("should be disabled by default", () => {
    const disabled = new BlockFilterIndex(mockDB as any);
    expect(disabled.isEnabled()).toBe(false);
  });

  it("should be enabled when configured", () => {
    expect(filterIndex.isEnabled()).toBe(true);
  });

  it("should build filter for block", () => {
    const coinbase = createCoinbaseTx(1);
    const block = createBlock([coinbase], Buffer.alloc(32, 0), 1);

    const filter = filterIndex.buildFilter(block, []);

    expect(filter.getN()).toBeGreaterThan(0);
  });

  it("should include output scripts in filter", () => {
    const coinbase = createCoinbaseTx(1);
    const block = createBlock([coinbase], Buffer.alloc(32, 0), 1);
    const outputScript = coinbase.outputs[0].scriptPubKey;

    const filter = filterIndex.buildFilter(block, []);

    expect(filter.match(outputScript)).toBe(true);
  });

  it("should include spent input scripts in filter", () => {
    const coinbase = createCoinbaseTx(1);
    const block = createBlock([coinbase], Buffer.alloc(32, 0), 1);

    const spentScript = Buffer.from([
      0x76, 0xa9, 0x14, ...Buffer.alloc(20, 0xaa), 0x88, 0xac,
    ]);

    const spentOutputs: SpentUTXO[] = [
      {
        txid: Buffer.alloc(32, 0xff),
        vout: 0,
        entry: {
          height: 0,
          coinbase: true,
          amount: 5000000000n,
          scriptPubKey: spentScript,
        },
      },
    ];

    const filter = filterIndex.buildFilter(block, spentOutputs);

    expect(filter.match(spentScript)).toBe(true);
  });

  it("should exclude OP_RETURN outputs", () => {
    const tx: Transaction = {
      version: 1,
      inputs: [
        {
          prevOut: { txid: Buffer.alloc(32, 0), vout: 0xffffffff },
          scriptSig: Buffer.from([1]),
          sequence: 0xffffffff,
          witness: [],
        },
      ],
      outputs: [
        {
          value: 0n,
          scriptPubKey: Buffer.from([0x6a, 0x04, 0x74, 0x65, 0x73, 0x74]), // OP_RETURN "test"
        },
      ],
      lockTime: 0,
    };

    const block = createBlock([tx], Buffer.alloc(32, 0), 1);
    const filter = filterIndex.buildFilter(block, []);

    // OP_RETURN should not be in filter
    expect(filter.getN()).toBe(0);
  });

  it("should index block and store filter", async () => {
    const coinbase = createCoinbaseTx(1);
    const block = createBlock([coinbase], Buffer.alloc(32, 0), 1);

    await filterIndex.indexBlock(block, 1, []);

    expect(filterIndex.getHeight()).toBe(1);
  });
});

// =============================================================================
// CoinStatsIndex Tests
// =============================================================================

describe("CoinStatsIndex", () => {
  let mockDB: MockChainDB;
  let coinStats: CoinStatsIndex;

  beforeEach(() => {
    mockDB = new MockChainDB();
    coinStats = new CoinStatsIndex(mockDB as any, true);
  });

  it("should be disabled by default", () => {
    const disabled = new CoinStatsIndex(mockDB as any);
    expect(disabled.isEnabled()).toBe(false);
  });

  it("should be enabled when configured", () => {
    expect(coinStats.isEnabled()).toBe(true);
  });

  it("should track coinbase outputs", async () => {
    const coinbase = createCoinbaseTx(1);
    const block = createBlock([coinbase], Buffer.alloc(32, 0), 1);
    const subsidy = 5000000000n;

    await coinStats.indexBlock(block, 1, subsidy, []);

    const stats = coinStats.getCurrentStats();
    expect(stats).not.toBeNull();
    expect(stats!.txOutputCount).toBe(1n);
    expect(stats!.totalAmount).toBe(5000000000n);
    expect(stats!.totalSubsidy).toBe(subsidy);
  });

  it("should handle spent outputs", async () => {
    // First block: create output
    const coinbase1 = createCoinbaseTx(1);
    const block1 = createBlock([coinbase1], Buffer.alloc(32, 0), 1);
    await coinStats.indexBlock(block1, 1, 5000000000n, []);

    // Second block: spend that output
    const coinbase2 = createCoinbaseTx(2);
    const spendTx = createP2PKHTx(getTxId(coinbase1), 0, 4999000000n);
    const block2 = createBlock([coinbase2, spendTx], getBlockHash(block1.header), 2);

    const spentOutputs: SpentUTXO[] = [
      {
        txid: getTxId(coinbase1),
        vout: 0,
        entry: {
          height: 1,
          coinbase: true,
          amount: 5000000000n,
          scriptPubKey: coinbase1.outputs[0].scriptPubKey,
        },
      },
    ];

    await coinStats.indexBlock(block2, 2, 5000000000n, spentOutputs);

    const stats = coinStats.getCurrentStats();
    expect(stats).not.toBeNull();
    // 1 coinbase output created, 1 spent, 1 new coinbase, 1 new P2PKH = 2 outputs
    expect(stats!.txOutputCount).toBe(2n);
    expect(stats!.totalSubsidy).toBe(10000000000n); // 2 blocks
  });

  it("should exclude OP_RETURN from statistics", async () => {
    const tx: Transaction = {
      version: 1,
      inputs: [
        {
          prevOut: { txid: Buffer.alloc(32, 0), vout: 0xffffffff },
          scriptSig: Buffer.from([1]),
          sequence: 0xffffffff,
          witness: [],
        },
      ],
      outputs: [
        {
          value: 5000000000n,
          scriptPubKey: Buffer.from([
            0x76, 0xa9, 0x14, ...Buffer.alloc(20, 0x11), 0x88, 0xac,
          ]),
        },
        {
          value: 0n,
          scriptPubKey: Buffer.from([0x6a, 0x04, 0x74, 0x65, 0x73, 0x74]),
        },
      ],
      lockTime: 0,
    };

    const block = createBlock([tx], Buffer.alloc(32, 0), 1);
    await coinStats.indexBlock(block, 1, 5000000000n, []);

    const stats = coinStats.getCurrentStats();
    expect(stats).not.toBeNull();
    // Only non-OP_RETURN output should be counted
    expect(stats!.txOutputCount).toBe(1n);
  });

  it("should update height after indexing", async () => {
    expect(coinStats.getHeight()).toBe(-1);

    const block1 = createBlock([createCoinbaseTx(1)], Buffer.alloc(32, 0), 1);
    await coinStats.indexBlock(block1, 1, 5000000000n, []);
    expect(coinStats.getHeight()).toBe(1);

    const block2 = createBlock(
      [createCoinbaseTx(2)],
      getBlockHash(block1.header),
      2
    );
    await coinStats.indexBlock(block2, 2, 5000000000n, []);
    expect(coinStats.getHeight()).toBe(2);
  });
});

// =============================================================================
// IndexManager Tests
// =============================================================================

describe("IndexManager", () => {
  let mockDB: MockChainDB;

  beforeEach(() => {
    mockDB = new MockChainDB();
  });

  it("should create with no indexes enabled by default", () => {
    const manager = new IndexManager(mockDB as any);

    expect(manager.getTxIndex().isEnabled()).toBe(false);
    expect(manager.getFilterIndex().isEnabled()).toBe(false);
    expect(manager.getCoinStatsIndex().isEnabled()).toBe(false);
  });

  it("should enable indexes via options", () => {
    const manager = new IndexManager(mockDB as any, {
      txindex: true,
      blockfilterindex: true,
      coinstatsindex: true,
    });

    expect(manager.getTxIndex().isEnabled()).toBe(true);
    expect(manager.getFilterIndex().isEnabled()).toBe(true);
    expect(manager.getCoinStatsIndex().isEnabled()).toBe(true);
  });

  it("should index block across all enabled indexes", async () => {
    const manager = new IndexManager(mockDB as any, {
      txindex: true,
      blockfilterindex: true,
      coinstatsindex: true,
    });

    const coinbase = createCoinbaseTx(1);
    const block = createBlock([coinbase], Buffer.alloc(32, 0), 1);

    await manager.indexBlock(block, 1, 5000000000n, [], 0);

    expect(manager.getTxIndex().getHeight()).toBe(1);
    expect(manager.getFilterIndex().getHeight()).toBe(1);
    expect(manager.getCoinStatsIndex().getHeight()).toBe(1);
  });

  it("should report minimum height", async () => {
    const manager = new IndexManager(mockDB as any, {
      txindex: true,
      coinstatsindex: true,
    });

    expect(manager.getMinHeight()).toBe(-1);

    const block = createBlock([createCoinbaseTx(1)], Buffer.alloc(32, 0), 1);
    await manager.indexBlock(block, 1, 5000000000n, [], 0);

    expect(manager.getMinHeight()).toBe(1);
  });

  it("should not be syncing initially", () => {
    const manager = new IndexManager(mockDB as any);
    expect(manager.isSyncing()).toBe(false);
  });
});
