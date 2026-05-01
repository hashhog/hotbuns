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
import {
  readVarIntCore,
  writeVarIntCore,
  compressAmount,
  decompressAmount,
  compressScript,
  decompressScript,
  serializeTxOutCompressed,
  deserializeTxOutCompressed,
} from "../wire/compressor.js";
import { ChainDB, DBPrefix } from "../storage/database.js";
import { REGTEST, type ConsensusParams, type AssumeutxoData as ParamsAssumeutxoData } from "../consensus/params.js";
import { MuHash3072 } from "../wire/muhash.js";

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

    it("should encode height and coinbase flag together (Pieter's VARINT)", () => {
      // Coin::Serialize emits VARINT(nHeight * 2 + fCoinBase).
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

      // code = 50*2 + 1 = 101 (coinbase) and 100 (regular). Both fit in
      // a single VARINT byte (< 0x80) so the on-wire encoding is one byte.
      const coinbaseReader = new BufferReader(coinbaseSer);
      const code1 = readVarIntCore(coinbaseReader);
      expect(code1 & 1n).toBe(1n);
      expect(code1 >> 1n).toBe(50n);
      expect(code1).toBe(101n);

      const regularReader = new BufferReader(regularSer);
      const code2 = readVarIntCore(regularReader);
      expect(code2 & 1n).toBe(0n);
      expect(code2 >> 1n).toBe(50n);
      expect(code2).toBe(100n);

      expect(code1).not.toBe(code2);
    });
  });

  // -----------------------------------------------------------------------
  // Bitcoin Core wire-format compressor tests.
  //
  // These guard the byte-level invariants that snapshots rely on. Reference:
  // bitcoin-core/src/compressor.{h,cpp}.
  // -----------------------------------------------------------------------
  describe("Core compressor (compressAmount / compressScript)", () => {
    it("compressAmount round-trips MAX_MONEY and zero", () => {
      expect(decompressAmount(compressAmount(0n))).toBe(0n);
      expect(decompressAmount(compressAmount(2_100_000_000_000_000n))).toBe(
        2_100_000_000_000_000n
      );
    });

    it("compressAmount has the exact published values for known inputs", () => {
      // n=0 -> 0. n=1: e=0, d=1, n/=10=0; encoded = 1 + (0+0)*10 + 0 = 1.
      expect(compressAmount(0n)).toBe(0n);
      expect(compressAmount(1n)).toBe(1n);
      // 100_000_000 sat (1 BTC): e=8, n=1; e<9, d=1, n/=10=0;
      //   encoded = 1 + (0*9 + 1 - 1)*10 + 8 = 9.
      expect(compressAmount(100_000_000n)).toBe(9n);
    });

    it("VARINT round-trips small, mid, and 64-bit values", () => {
      const cases = [0n, 1n, 0x7fn, 0x80n, 0xffffn, 1n << 40n, (1n << 64n) - 1n];
      for (const v of cases) {
        const w = new BufferWriter();
        writeVarIntCore(w, v);
        const r = new BufferReader(w.toBuffer());
        expect(readVarIntCore(r)).toBe(v);
      }
    });

    it("compressScript identifies P2PKH (special type 0x00, 21-byte payload)", () => {
      const hash20 = Buffer.alloc(20, 0xab);
      const p2pkh = Buffer.concat([
        Buffer.from([0x76, 0xa9, 0x14]),
        hash20,
        Buffer.from([0x88, 0xac]),
      ]);
      const out = compressScript(p2pkh);
      expect(out).not.toBeNull();
      expect(out!.length).toBe(21);
      expect(out![0]).toBe(0x00);
      expect(out!.subarray(1, 21).equals(hash20)).toBe(true);

      const round = decompressScript(0x00, out!.subarray(1));
      expect(round.equals(p2pkh)).toBe(true);
    });

    it("compressScript identifies P2SH (special type 0x01, 21-byte payload)", () => {
      const hash20 = Buffer.alloc(20, 0xcd);
      const p2sh = Buffer.concat([
        Buffer.from([0xa9, 0x14]),
        hash20,
        Buffer.from([0x87]),
      ]);
      const out = compressScript(p2sh);
      expect(out).not.toBeNull();
      expect(out!.length).toBe(21);
      expect(out![0]).toBe(0x01);

      const round = decompressScript(0x01, out!.subarray(1));
      expect(round.equals(p2sh)).toBe(true);
    });

    it("compressScript returns null for unrecognized scripts (e.g. P2WPKH)", () => {
      // OP_0 + 20-byte push (P2WPKH) is NOT one of the 6 special types.
      const p2wpkh = Buffer.concat([Buffer.from([0x00, 0x14]), Buffer.alloc(20, 0)]);
      expect(compressScript(p2wpkh)).toBeNull();
    });

    it("TxOutCompression round-trips a P2PKH coin", () => {
      const hash20 = Buffer.alloc(20, 0x77);
      const spk = Buffer.concat([
        Buffer.from([0x76, 0xa9, 0x14]),
        hash20,
        Buffer.from([0x88, 0xac]),
      ]);
      const w = new BufferWriter();
      serializeTxOutCompressed(w, 50_00000000n, spk);
      const r = new BufferReader(w.toBuffer());
      const got = deserializeTxOutCompressed(r);
      expect(got.value).toBe(50_00000000n);
      expect(got.scriptPubKey.equals(spk)).toBe(true);
    });

    it("TxOutCompression round-trips a non-special script via VARINT(size+6)", () => {
      const oddScript = Buffer.from([0x6a, 0x09, 0x01, 0x02, 0x03]); // OP_RETURN + push5
      const w = new BufferWriter();
      serializeTxOutCompressed(w, 1234n, oddScript);
      const r = new BufferReader(w.toBuffer());
      const got = deserializeTxOutCompressed(r);
      expect(got.value).toBe(1234n);
      expect(got.scriptPubKey.equals(oddScript)).toBe(true);
    });
  });

  // -----------------------------------------------------------------------
  // Snapshot-level byte format checks: header (51 bytes) + per-coin layout.
  // -----------------------------------------------------------------------
  describe("Core snapshot byte format", () => {
    it("metadata header is exactly 51 bytes (5+2+4+32+8)", () => {
      const meta: SnapshotMetadata = {
        networkMagic: 0xd9b4bef9, // mainnet
        baseBlockHash: Buffer.alloc(32, 0xab),
        coinsCount: 12_345_678n,
      };
      const bytes = serializeSnapshotMetadata(meta);
      expect(bytes.length).toBe(51);
      // First 5 bytes: 'utxo' + 0xff
      expect(bytes.subarray(0, 5).equals(SNAPSHOT_MAGIC)).toBe(true);
      // Next 2 bytes: version 2 (uint16 LE)
      expect(bytes.readUInt16LE(5)).toBe(2);
      // Next 4 bytes: network magic in pchMessageStart byte order.
      // For mainnet (0xd9b4bef9 in our internal uint32) this is f9 be b4 d9.
      expect(bytes.subarray(7, 11)).toEqual(
        Buffer.from([0xf9, 0xbe, 0xb4, 0xd9])
      );
      // Next 32 bytes: base block hash (raw).
      expect(bytes.subarray(11, 43).equals(meta.baseBlockHash)).toBe(true);
      // Last 8 bytes: coins count uint64 LE.
      expect(bytes.readBigUInt64LE(43)).toBe(meta.coinsCount);
    });

    it("dump+load round-trips a small UTXO set with mixed coin types", async () => {
      const dbPath = join(testDbPath, "core-rt");
      const db = new ChainDB(dbPath);
      await db.open();

      const tip = Buffer.alloc(32, 0xee);
      // Use a hash and height we register in chain params so loadSnapshot
      // can verify the recomputed HASH_SERIALIZED. We compute the hash
      // first by populating the DB, hashing it, then registering the
      // params and dumping/loading.
      await db.putChainState({
        bestBlockHash: tip,
        bestHeight: 7,
        totalWork: 1n,
      });
      await db.putBlockIndex(tip, {
        height: 7,
        header: Buffer.alloc(80, 0),
        nTx: 1,
        status: 0x1f,
        dataPos: 0,
      });

      // P2PKH coin
      const txid1 = Buffer.alloc(32, 0x01);
      const p2pkh = Buffer.concat([
        Buffer.from([0x76, 0xa9, 0x14]),
        Buffer.alloc(20, 0x33),
        Buffer.from([0x88, 0xac]),
      ]);
      await db.putUTXO(txid1, 0, {
        height: 5,
        coinbase: false,
        amount: 50_00000000n,
        scriptPubKey: p2pkh,
      });

      // P2SH coin
      const txid2 = Buffer.alloc(32, 0x02);
      const p2sh = Buffer.concat([
        Buffer.from([0xa9, 0x14]),
        Buffer.alloc(20, 0x44),
        Buffer.from([0x87]),
      ]);
      await db.putUTXO(txid2, 0, {
        height: 6,
        coinbase: false,
        amount: 1_00000000n,
        scriptPubKey: p2sh,
      });

      // Non-special script (OP_RETURN + 4-byte push)
      const txid3 = Buffer.alloc(32, 0x03);
      const opret = Buffer.from([0x6a, 0x04, 0xde, 0xad, 0xbe, 0xef]);
      await db.putUTXO(txid3, 0, {
        height: 7,
        coinbase: false,
        amount: 0n,
        scriptPubKey: opret,
      });

      // Compute the expected HASH_SERIALIZED so we can register it
      // in the params before loadSnapshot tries to verify it.
      const { hash: serializedHash } = await computeUTXOSetHash(db);

      const params: ConsensusParams = {
        ...REGTEST,
        assumeutxo: new Map([
          [
            tip.toString("hex"),
            {
              height: 7,
              hashSerialized: serializedHash,
              nChainTx: 3n,
              blockHash: tip,
            },
          ],
        ]),
      };

      const snapshotPath = join(testDbPath, "rt.dat");
      const dumpManager = new ChainstateManager(db, params);
      const dump = await dumpManager.dumpSnapshot(snapshotPath);
      expect(dump.coinsWritten).toBe(3n);

      // Wipe UTXOs, then reload from the snapshot file.
      const utxoIter = (db as any).db.iterator({
        gte: Buffer.from([DBPrefix.UTXO]),
        lt: Buffer.from([DBPrefix.UTXO + 1]),
      });
      const delKeys: Buffer[] = [];
      for await (const [key] of utxoIter) {
        delKeys.push(key);
      }
      await utxoIter.close();
      await db.batch(
        delKeys.map((k) => ({ type: "del" as const, prefix: k[0]!, key: k.subarray(1) }))
      );

      const loadManager = new ChainstateManager(db, params);
      const load = await loadManager.loadSnapshot(snapshotPath);
      expect(load.coinsLoaded).toBe(3n);
      expect(load.baseHeight).toBe(7);
      expect(load.baseBlockHash.equals(tip)).toBe(true);

      // Each loaded coin should be readable and identical.
      const c1 = await db.getUTXO(txid1, 0);
      expect(c1).not.toBeNull();
      expect(c1!.scriptPubKey.equals(p2pkh)).toBe(true);
      expect(c1!.amount).toBe(50_00000000n);

      const c2 = await db.getUTXO(txid2, 0);
      expect(c2).not.toBeNull();
      expect(c2!.scriptPubKey.equals(p2sh)).toBe(true);

      const c3 = await db.getUTXO(txid3, 0);
      expect(c3).not.toBeNull();
      expect(c3!.scriptPubKey.equals(opret)).toBe(true);

      await db.close();
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

  // -----------------------------------------------------------------------
  // MuHash3072 wiring: computeUTXOSetHash MUST be MuHash, AND the
  // loadSnapshot strict-validation gate MUST refuse with Core's verbatim
  // "Bad snapshot content hash: expected ..., got ..." string.
  // Reference: bitcoin-core/src/validation.cpp:5912-5914 +
  // bitcoin-core/src/kernel/coinstats.cpp::ApplyCoinHash(MuHash3072&, ...).
  // -----------------------------------------------------------------------
  describe("MuHash3072 wiring (assumeutxo HASH_SERIALIZED)", () => {
    let db: ChainDB;

    beforeEach(async () => {
      db = new ChainDB(join(testDbPath, "muhash-wiring"));
      await db.open();
    });

    afterEach(async () => {
      await db.close();
    });

    /** Serialize a coin into TxOutSer bytes — manually duplicates the
     *  layout `computeUTXOSetHash` feeds into MuHash, so the test pins
     *  the exact byte format independent of internal helpers. */
    function txOutSer(
      txid: Buffer,
      vout: number,
      height: number,
      coinbase: boolean,
      amount: bigint,
      scriptPubKey: Buffer
    ): Buffer {
      const w = new BufferWriter();
      w.writeHash(txid);
      w.writeUInt32LE(vout);
      w.writeUInt32LE(((height << 1) + (coinbase ? 1 : 0)) >>> 0);
      w.writeUInt64LE(amount);
      w.writeVarBytes(scriptPubKey);
      return w.toBuffer();
    }

    it("computeUTXOSetHash matches an independent MuHash3072 over TxOutSer", async () => {
      // Two UTXOs with very different field values to exercise all paths.
      const txidA = Buffer.alloc(32, 0x11);
      const txidB = Buffer.alloc(32, 0x22);
      const spkA = Buffer.from([0x76, 0xa9, 0x14, ...Buffer.alloc(20, 0xaa), 0x88, 0xac]);
      const spkB = Buffer.from([0xa9, 0x14, ...Buffer.alloc(20, 0xbb), 0x87]);

      await db.putUTXO(txidA, 0, {
        height: 12345,
        coinbase: true,
        amount: 50_00000000n,
        scriptPubKey: spkA,
      });
      await db.putUTXO(txidB, 7, {
        height: 23456,
        coinbase: false,
        amount: 1_23456789n,
        scriptPubKey: spkB,
      });

      const { hash, coinsCount } = await computeUTXOSetHash(db);
      expect(coinsCount).toBe(2n);

      // Reproduce the same hash by feeding the canonical TxOutSer bytes
      // into a fresh MuHash3072 — order-independent so we don't care
      // which order the DB iterator returned them in.
      const acc = new MuHash3072();
      acc.add(txOutSer(txidA, 0, 12345, true, 50_00000000n, spkA));
      acc.add(txOutSer(txidB, 7, 23456, false, 1_23456789n, spkB));
      const expected = acc.finalize();

      expect(hash.equals(expected)).toBe(true);
      expect(hash.length).toBe(32);
    });

    it("computeUTXOSetHash is order-independent (MuHash multiset property)", async () => {
      // Insert in one order, snapshot the hash, wipe + reinsert in a
      // different order — MuHash should agree because the underlying
      // primitive is a commutative+associative multiset hash.
      const coins = [
        { txid: Buffer.alloc(32, 0x01), vout: 0, height: 100, cb: true, amt: 5000n, spk: Buffer.from([0x6a, 0x01]) },
        { txid: Buffer.alloc(32, 0x02), vout: 0, height: 200, cb: false, amt: 6000n, spk: Buffer.from([0x6a, 0x02]) },
        { txid: Buffer.alloc(32, 0x03), vout: 0, height: 300, cb: false, amt: 7000n, spk: Buffer.from([0x6a, 0x03]) },
      ];

      for (const c of coins) {
        await db.putUTXO(c.txid, c.vout, { height: c.height, coinbase: c.cb, amount: c.amt, scriptPubKey: c.spk });
      }
      const { hash: h1 } = await computeUTXOSetHash(db);

      // The DB iterates in key order regardless, but the MuHash itself
      // does not depend on iteration order — verify by hashing the same
      // coin set in a deliberately reversed order via two MuHashes.
      const accA = new MuHash3072();
      const accB = new MuHash3072();
      for (const c of coins) {
        accA.add(txOutSer(c.txid, c.vout, c.height, c.cb, c.amt, c.spk));
      }
      for (const c of [...coins].reverse()) {
        accB.add(txOutSer(c.txid, c.vout, c.height, c.cb, c.amt, c.spk));
      }
      const hA = accA.finalize();
      const hB = accB.finalize();
      expect(hA.equals(hB)).toBe(true);
      expect(h1.equals(hA)).toBe(true);
    });

    it("empty UTXO set hashes to SHA256 of the all-zero 384-byte LE Num3072 (MuHash identity / 1)", async () => {
      const { hash, coinsCount } = await computeUTXOSetHash(db);
      expect(coinsCount).toBe(0n);

      // Empty MuHash: numerator=denominator=1, finalize -> num/den=1,
      // serialize LE_384(1) = 0x01 followed by 383 zero bytes, then SHA256.
      const emptyAcc = new MuHash3072();
      const expected = emptyAcc.finalize();
      expect(hash.equals(expected)).toBe(true);
    });

    it("loadSnapshot refuses with Core's verbatim 'Bad snapshot content hash' wording on mismatch", async () => {
      // Build a coherent dump+load pair, then register a *wrong*
      // expected hash in chain params so the strict gate fails.
      const tip = Buffer.alloc(32, 0xfe);
      await db.putChainState({ bestBlockHash: tip, bestHeight: 9, totalWork: 1n });
      await db.putBlockIndex(tip, {
        height: 9,
        header: Buffer.alloc(80, 0),
        nTx: 1,
        status: 0x1f,
        dataPos: 0,
      });

      const txid = Buffer.alloc(32, 0xa0);
      const spk = Buffer.from([0x76, 0xa9, 0x14, ...Buffer.alloc(20, 0x55), 0x88, 0xac]);
      await db.putUTXO(txid, 0, { height: 9, coinbase: false, amount: 1n, scriptPubKey: spk });

      // Wrong expected hash (all 0xcc).
      const badExpected = Buffer.alloc(32, 0xcc);
      const params: ConsensusParams = {
        ...REGTEST,
        assumeutxo: new Map([
          [tip.toString("hex"), { height: 9, hashSerialized: badExpected, nChainTx: 1n, blockHash: tip }],
        ]),
      };

      const dumpPath = join(testDbPath, "muhash-bad.dat");
      const dumpMgr = new ChainstateManager(db, params);
      await dumpMgr.dumpSnapshot(dumpPath);

      // Wipe UTXOs so loadSnapshot has to reload from the file.
      const it = (db as any).db.iterator({
        gte: Buffer.from([DBPrefix.UTXO]),
        lt: Buffer.from([DBPrefix.UTXO + 1]),
      });
      const delKeys: Buffer[] = [];
      for await (const [k] of it) delKeys.push(k);
      await it.close();
      await db.batch(
        delKeys.map((k) => ({ type: "del" as const, prefix: k[0]!, key: k.subarray(1) }))
      );

      const loadMgr = new ChainstateManager(db, params);
      let caught: Error | null = null;
      try {
        await loadMgr.loadSnapshot(dumpPath);
      } catch (e) {
        caught = e as Error;
      }

      expect(caught).not.toBeNull();
      // Verbatim core wording — see bitcoin-core/src/validation.cpp:5913.
      expect(caught!.message.startsWith("Bad snapshot content hash: expected ")).toBe(true);
      expect(caught!.message).toContain(", got ");
      // Both hex blobs must appear in the message.
      expect(caught!.message).toContain(badExpected.toString("hex"));
    });

    it("loadSnapshot accepts a roundtripped snapshot whose hash matches the registered MuHash value", async () => {
      // The complementary success path — register the *correct* MuHash
      // we actually computed and confirm loadSnapshot does not throw.
      const tip = Buffer.alloc(32, 0xfd);
      await db.putChainState({ bestBlockHash: tip, bestHeight: 11, totalWork: 1n });
      await db.putBlockIndex(tip, {
        height: 11,
        header: Buffer.alloc(80, 0),
        nTx: 1,
        status: 0x1f,
        dataPos: 0,
      });

      const txid = Buffer.alloc(32, 0xa1);
      const spk = Buffer.from([0x6a, 0x04, 0xde, 0xad, 0xbe, 0xef]);
      await db.putUTXO(txid, 0, { height: 11, coinbase: false, amount: 42n, scriptPubKey: spk });

      const { hash: real } = await computeUTXOSetHash(db);

      const params: ConsensusParams = {
        ...REGTEST,
        assumeutxo: new Map([
          [tip.toString("hex"), { height: 11, hashSerialized: real, nChainTx: 1n, blockHash: tip }],
        ]),
      };

      const dumpPath = join(testDbPath, "muhash-good.dat");
      const dumpMgr = new ChainstateManager(db, params);
      await dumpMgr.dumpSnapshot(dumpPath);

      // Wipe + reload.
      const it = (db as any).db.iterator({
        gte: Buffer.from([DBPrefix.UTXO]),
        lt: Buffer.from([DBPrefix.UTXO + 1]),
      });
      const delKeys: Buffer[] = [];
      for await (const [k] of it) delKeys.push(k);
      await it.close();
      await db.batch(
        delKeys.map((k) => ({ type: "del" as const, prefix: k[0]!, key: k.subarray(1) }))
      );

      const loadMgr = new ChainstateManager(db, params);
      const result = await loadMgr.loadSnapshot(dumpPath);
      expect(result.coinsLoaded).toBe(1n);
      expect(result.baseHeight).toBe(11);
    });
  });
});
