/**
 * Tests for assumeUTXO snapshot functionality.
 */

import { describe, it, expect, beforeEach, afterEach } from "bun:test";
import { rmSync, mkdirSync } from "fs";
import { join } from "path";
import {
  serializeSnapshotMetadata,
  deserializeSnapshotMetadata,
  serializeCoinForSnapshot,
  deserializeCoinFromSnapshot,
  computeUTXOSetHash,
  ChainstateManager,
  Chainstate,
  ChainstateStatus,
  SnapshotValidationResult,
  SNAPSHOT_MAGIC,
  SNAPSHOT_VERSION,
  getAssumeutxoData,
  getAssumeutxoDataByHeight,
  type SnapshotMetadata,
  type AssumeutxoData,
} from "../chain/snapshot.js";
import type { Coin } from "../chain/utxo.js";
import { BufferReader, BufferWriter } from "../wire/serialization.js";
import { ChainDB, DBPrefix } from "../storage/database.js";
import { REGTEST, type ConsensusParams, type AssumeutxoData as ParamsAssumeutxoData } from "../consensus/params.js";

describe("assumeUTXO", () => {
  const testDbPath = "/tmp/hotbuns-assumeutxo-test-" + Date.now();

  beforeEach(() => {
    // Clean up any previous test data
    try {
      rmSync(testDbPath, { recursive: true, force: true });
    } catch {
      // Ignore
    }
    mkdirSync(testDbPath, { recursive: true });
  });

  afterEach(async () => {
    // Clean up test data
    try {
      rmSync(testDbPath, { recursive: true, force: true });
    } catch {
      // Ignore
    }
  });

  describe("Snapshot Metadata Serialization", () => {
    it("should serialize and deserialize metadata correctly", () => {
      const metadata: SnapshotMetadata = {
        networkMagic: 0xdab5bffa, // regtest
        baseBlockHash: Buffer.alloc(32, 0xab),
        coinsCount: 12345678n,
      };

      const serialized = serializeSnapshotMetadata(metadata);
      const reader = new BufferReader(serialized);
      const deserialized = deserializeSnapshotMetadata(reader, 0xdab5bffa);

      expect(deserialized.networkMagic).toBe(metadata.networkMagic);
      expect(deserialized.baseBlockHash.equals(metadata.baseBlockHash)).toBe(true);
      expect(deserialized.coinsCount).toBe(metadata.coinsCount);
    });

    it("should include magic bytes and version", () => {
      const metadata: SnapshotMetadata = {
        networkMagic: 0xd9b4bef9, // mainnet
        baseBlockHash: Buffer.alloc(32, 0),
        coinsCount: 0n,
      };

      const serialized = serializeSnapshotMetadata(metadata);

      // Check magic bytes
      expect(serialized.subarray(0, 5).equals(SNAPSHOT_MAGIC)).toBe(true);

      // Check version (uint16 LE at offset 5)
      expect(serialized.readUInt16LE(5)).toBe(SNAPSHOT_VERSION);
    });

    it("should reject wrong network magic", () => {
      const metadata: SnapshotMetadata = {
        networkMagic: 0xd9b4bef9, // mainnet
        baseBlockHash: Buffer.alloc(32, 0),
        coinsCount: 0n,
      };

      const serialized = serializeSnapshotMetadata(metadata);
      const reader = new BufferReader(serialized);

      // Try to deserialize expecting regtest magic
      expect(() => {
        deserializeSnapshotMetadata(reader, 0xdab5bffa);
      }).toThrow(/Network magic mismatch/);
    });

    it("should reject invalid magic bytes", () => {
      const badMagic = Buffer.concat([
        Buffer.from([0x00, 0x00, 0x00, 0x00, 0x00]), // Invalid magic
        Buffer.alloc(47), // Rest of header
      ]);

      const reader = new BufferReader(badMagic);

      expect(() => {
        deserializeSnapshotMetadata(reader, 0xdab5bffa);
      }).toThrow(/Invalid snapshot magic/);
    });
  });

  describe("Coin Serialization", () => {
    it("should serialize and deserialize a regular coin", () => {
      const coin: Coin = {
        txOut: {
          value: 100000000n, // 1 BTC
          scriptPubKey: Buffer.from("76a914000102030405060708091011121314151617181920888ac", "hex"),
        },
        height: 100000,
        isCoinbase: false,
      };

      const serialized = serializeCoinForSnapshot(coin);
      const reader = new BufferReader(serialized);
      const deserialized = deserializeCoinFromSnapshot(reader);

      expect(deserialized.txOut.value).toBe(coin.txOut.value);
      expect(deserialized.txOut.scriptPubKey.equals(coin.txOut.scriptPubKey)).toBe(true);
      expect(deserialized.height).toBe(coin.height);
      expect(deserialized.isCoinbase).toBe(coin.isCoinbase);
    });

    it("should serialize and deserialize a coinbase coin", () => {
      const coin: Coin = {
        txOut: {
          value: 5000000000n, // 50 BTC
          scriptPubKey: Buffer.from("4104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac", "hex"),
        },
        height: 0,
        isCoinbase: true,
      };

      const serialized = serializeCoinForSnapshot(coin);
      const reader = new BufferReader(serialized);
      const deserialized = deserializeCoinFromSnapshot(reader);

      expect(deserialized.isCoinbase).toBe(true);
      expect(deserialized.height).toBe(0);
    });

    it("should encode height and coinbase flag together", () => {
      // Test that (height << 1) | coinbase encoding works
      const coinbase: Coin = {
        txOut: { value: 1n, scriptPubKey: Buffer.from([0x6a]) },
        height: 50,
        isCoinbase: true,
      };

      const regular: Coin = {
        txOut: { value: 1n, scriptPubKey: Buffer.from([0x6a]) },
        height: 50,
        isCoinbase: false,
      };

      const coinbaseSer = serializeCoinForSnapshot(coinbase);
      const regularSer = serializeCoinForSnapshot(regular);

      // Coinbase should have LSB set, so code = (50 << 1) | 1 = 101
      // Regular should have code = (50 << 1) | 0 = 100
      const coinbaseReader = new BufferReader(coinbaseSer);
      const code1 = coinbaseReader.readVarInt();
      expect(code1 & 1).toBe(1);
      expect(code1 >> 1).toBe(50);
      expect(code1).toBe(101);

      const regularReader = new BufferReader(regularSer);
      const code2 = regularReader.readVarInt();
      expect(code2 & 1).toBe(0);
      expect(code2 >> 1).toBe(50);
      expect(code2).toBe(100);

      // The varints should be different
      expect(code1).not.toBe(code2);
    });
  });

  describe("Chainstate", () => {
    let db: ChainDB;

    beforeEach(async () => {
      db = new ChainDB(join(testDbPath, "chainstate"));
      await db.open();
    });

    afterEach(async () => {
      await db.close();
    });

    it("should create a default chainstate", () => {
      const chainstate = new Chainstate(db, REGTEST);

      expect(chainstate.status).toBe(ChainstateStatus.VALIDATED);
      expect(chainstate.isSnapshot()).toBe(false);
      expect(chainstate.isBackground()).toBe(false);
      expect(chainstate.tipHeight).toBe(0);
    });

    it("should create a snapshot chainstate", () => {
      const baseBlockHash = Buffer.alloc(32, 0xab);
      const chainstate = new Chainstate(db, REGTEST, {
        snapshotBaseBlockHash: baseBlockHash,
        status: ChainstateStatus.UNVALIDATED,
      });

      expect(chainstate.status).toBe(ChainstateStatus.UNVALIDATED);
      expect(chainstate.isSnapshot()).toBe(true);
      expect(chainstate.snapshotBaseBlockHash?.equals(baseBlockHash)).toBe(true);
    });

    it("should detect when background chainstate reaches target", () => {
      const targetHash = Buffer.alloc(32, 0xcd);
      const chainstate = new Chainstate(db, REGTEST);
      chainstate.targetBlockHash = targetHash;

      expect(chainstate.isBackground()).toBe(true);
      expect(chainstate.hasReachedTarget()).toBe(false);

      chainstate.tipHash = targetHash;
      expect(chainstate.hasReachedTarget()).toBe(true);
    });
  });

  describe("ChainstateManager", () => {
    let db: ChainDB;

    beforeEach(async () => {
      db = new ChainDB(join(testDbPath, "chainstate"));
      await db.open();
    });

    afterEach(async () => {
      await db.close();
    });

    it("should create manager with active chainstate", () => {
      const manager = new ChainstateManager(db, REGTEST);

      expect(manager.current()).toBeDefined();
      expect(manager.background()).toBeNull();
    });

    it("should report status correctly", () => {
      const manager = new ChainstateManager(db, REGTEST);
      const status = manager.getStatus();

      expect(status.hasSnapshot).toBe(false);
      expect(status.snapshotValidated).toBe(true); // Default validated
      expect(status.backgroundProgress).toBeNull();
      expect(status.backgroundTarget).toBeNull();
    });
  });

  describe("assumeUtxo Data Lookup", () => {
    it("should return null for params without assumeutxo", () => {
      const paramsNoAssume: ConsensusParams = {
        ...REGTEST,
        assumeutxo: undefined,
      };

      const result = getAssumeutxoData(paramsNoAssume, Buffer.alloc(32, 0xab));
      expect(result).toBeNull();
    });

    it("should return null for unknown block hash", () => {
      const paramsWithAssume: ConsensusParams = {
        ...REGTEST,
        assumeutxo: new Map([
          [
            Buffer.alloc(32, 0x11).toString("hex"),
            {
              height: 100,
              hashSerialized: Buffer.alloc(32, 0x22),
              nChainTx: 1000n,
              blockHash: Buffer.alloc(32, 0x11),
            },
          ],
        ]),
      };

      const result = getAssumeutxoData(paramsWithAssume, Buffer.alloc(32, 0xab));
      expect(result).toBeNull();
    });

    it("should return data for known block hash", () => {
      const blockHash = Buffer.alloc(32, 0x11);
      const expectedData: AssumeutxoData = {
        height: 100,
        hashSerialized: Buffer.alloc(32, 0x22),
        nChainTx: 1000n,
        blockHash,
      };

      const paramsWithAssume: ConsensusParams = {
        ...REGTEST,
        assumeutxo: new Map([[blockHash.toString("hex"), expectedData]]),
      };

      const result = getAssumeutxoData(paramsWithAssume, blockHash);
      expect(result).toBeDefined();
      expect(result?.height).toBe(100);
      expect(result?.nChainTx).toBe(1000n);
    });

    it("should find data by height", () => {
      const blockHash = Buffer.alloc(32, 0x11);
      const expectedData: AssumeutxoData = {
        height: 250,
        hashSerialized: Buffer.alloc(32, 0x33),
        nChainTx: 5000n,
        blockHash,
      };

      const paramsWithAssume: ConsensusParams = {
        ...REGTEST,
        assumeutxo: new Map([[blockHash.toString("hex"), expectedData]]),
      };

      const result = getAssumeutxoDataByHeight(paramsWithAssume, 250);
      expect(result).toBeDefined();
      expect(result?.blockHash.equals(blockHash)).toBe(true);

      const notFound = getAssumeutxoDataByHeight(paramsWithAssume, 999);
      expect(notFound).toBeNull();
    });
  });

  describe("UTXO Set Hash Computation", () => {
    let db: ChainDB;

    beforeEach(async () => {
      db = new ChainDB(join(testDbPath, "utxo-hash"));
      await db.open();
    });

    afterEach(async () => {
      await db.close();
    });

    it("should compute hash for empty UTXO set", async () => {
      const { hash, coinsCount } = await computeUTXOSetHash(db);

      expect(hash).toBeInstanceOf(Buffer);
      expect(hash.length).toBe(32);
      expect(coinsCount).toBe(0n);
    });

    it("should compute different hashes for different UTXO sets", async () => {
      // Add a UTXO
      const txid = Buffer.alloc(32, 0x12);
      await db.putUTXO(txid, 0, {
        height: 100,
        coinbase: false,
        amount: 50000000n,
        scriptPubKey: Buffer.from("76a914000102030405060708091011121314151617181988ac", "hex"),
      });

      const { hash: hash1, coinsCount: count1 } = await computeUTXOSetHash(db);

      expect(count1).toBe(1n);

      // Add another UTXO
      await db.putUTXO(txid, 1, {
        height: 100,
        coinbase: false,
        amount: 25000000n,
        scriptPubKey: Buffer.from("76a914111213141516171819202122232425262728293088ac", "hex"),
      });

      const { hash: hash2, coinsCount: count2 } = await computeUTXOSetHash(db);

      expect(count2).toBe(2n);
      expect(hash1.equals(hash2)).toBe(false);
    });

    it("should support interruption", async () => {
      // Add some UTXOs
      for (let i = 0; i < 10; i++) {
        await db.putUTXO(Buffer.alloc(32, i), 0, {
          height: i,
          coinbase: false,
          amount: BigInt(i * 1000),
          scriptPubKey: Buffer.from([0x76, 0xa9, 0x14]),
        });
      }

      // Interrupt immediately
      let interrupted = false;
      try {
        await computeUTXOSetHash(db, () => true);
      } catch (e) {
        if (e instanceof Error && e.message === "Interrupted") {
          interrupted = true;
        }
      }

      expect(interrupted).toBe(true);
    });
  });

  describe("Snapshot File Operations", () => {
    let db: ChainDB;
    const snapshotPath = "/tmp/hotbuns-test-snapshot.dat";

    beforeEach(async () => {
      db = new ChainDB(join(testDbPath, "snapshot-ops"));
      await db.open();

      const bestBlockHash = Buffer.alloc(32, 0xaa);

      // Set up chain state
      await db.putChainState({
        bestBlockHash,
        bestHeight: 100,
        totalWork: 1000n,
      });

      // Set up block index for the tip
      await db.putBlockIndex(bestBlockHash, {
        height: 100,
        header: Buffer.alloc(80, 0),
        nTx: 1,
        status: 0x1f, // All valid flags
        dataPos: 0,
      });

      // Add some UTXOs
      for (let i = 0; i < 5; i++) {
        const txid = Buffer.alloc(32, i);
        await db.putUTXO(txid, 0, {
          height: i * 10,
          coinbase: i === 0,
          amount: BigInt((i + 1) * 100000000),
          scriptPubKey: Buffer.from([0x76, 0xa9, 0x14, ...Buffer.alloc(20, i), 0x88, 0xac]),
        });
      }
    });

    afterEach(async () => {
      await db.close();
      try {
        rmSync(snapshotPath, { force: true });
        rmSync(snapshotPath + ".tmp", { force: true });
      } catch {
        // Ignore
      }
    });

    it("should dump UTXO set to snapshot file", async () => {
      const manager = new ChainstateManager(db, REGTEST);
      const result = await manager.dumpSnapshot(snapshotPath);

      expect(result.coinsWritten).toBe(5n);
      expect(result.baseHeight).toBe(100);
      expect(result.path).toBe(snapshotPath);
      expect(result.txoutsetHash.length).toBe(64); // hex string

      // Verify file exists
      const file = Bun.file(snapshotPath);
      expect(await file.exists()).toBe(true);
    });
  });

  describe("Background Validation", () => {
    let db: ChainDB;

    beforeEach(async () => {
      db = new ChainDB(join(testDbPath, "bg-validation"));
      await db.open();
    });

    afterEach(async () => {
      await db.close();
    });

    it("should track validation progress", async () => {
      const manager = new ChainstateManager(db, REGTEST);

      // Simulate snapshot activation
      const snapshotChainstate = manager.current();
      snapshotChainstate.snapshotBaseBlockHash = Buffer.alloc(32, 0xab);
      snapshotChainstate.status = ChainstateStatus.UNVALIDATED;

      const status = manager.getStatus();
      expect(status.hasSnapshot).toBe(true);
      expect(status.snapshotValidated).toBe(false);
    });

    it("should stop background validation on request", () => {
      const manager = new ChainstateManager(db, REGTEST);

      // Start would require full setup, just test stop
      manager.stopBackgroundValidation();

      // Should not throw
      expect(true).toBe(true);
    });
  });

  describe("Edge Cases", () => {
    it("should handle large coin heights", () => {
      // Use a height that when shifted left by 1 still fits in a safe integer
      // Max height that works: Math.floor(Number.MAX_SAFE_INTEGER / 2) ~ 4.5 trillion
      // But realistically Bitcoin won't have heights above ~10 million for centuries
      const coin: Coin = {
        txOut: {
          value: 1n,
          scriptPubKey: Buffer.from([0x6a]), // OP_RETURN
        },
        height: 10_000_000, // 10 million blocks (~190 years from genesis)
        isCoinbase: false,
      };

      const serialized = serializeCoinForSnapshot(coin);
      const reader = new BufferReader(serialized);
      const deserialized = deserializeCoinFromSnapshot(reader);

      expect(deserialized.height).toBe(coin.height);
    });

    it("should handle empty scriptPubKey", () => {
      const coin: Coin = {
        txOut: {
          value: 0n,
          scriptPubKey: Buffer.alloc(0),
        },
        height: 0,
        isCoinbase: false,
      };

      const serialized = serializeCoinForSnapshot(coin);
      const reader = new BufferReader(serialized);
      const deserialized = deserializeCoinFromSnapshot(reader);

      expect(deserialized.txOut.scriptPubKey.length).toBe(0);
    });

    it("should handle maximum value coins", () => {
      const coin: Coin = {
        txOut: {
          value: 2100000000000000n, // MAX_MONEY
          scriptPubKey: Buffer.from([0x00, 0x14, ...Buffer.alloc(20, 0xff)]), // P2WPKH
        },
        height: 840000,
        isCoinbase: false,
      };

      const serialized = serializeCoinForSnapshot(coin);
      const reader = new BufferReader(serialized);
      const deserialized = deserializeCoinFromSnapshot(reader);

      expect(deserialized.txOut.value).toBe(coin.txOut.value);
    });
  });
});
