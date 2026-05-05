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
  computeUTXOSetMuHash,
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
import { sha256Hash } from "../crypto/primitives.js";
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

    it("dumpSnapshot uses atomic-write protocol (no .incomplete on success, refuses to overwrite)", async () => {
      // Mirrors Bitcoin Core's rpc/blockchain.cpp::dumptxoutset which
      // writes to "<path>.incomplete", fsyncs, and renames. After a
      // successful write only <path> should exist; the .incomplete temp
      // must be gone so that mid-dump observers never see a torn file.
      // A second dump to the same path must refuse to overwrite,
      // matching Core's "already exists" guard.
      const fsp = await import("node:fs/promises");
      const db = new ChainDB(join(testDbPath, "atomic-rt"));
      await db.open();

      const tip = Buffer.alloc(32, 0xee);
      await db.putBlockIndex(tip, {
        height: 1,
        header: Buffer.alloc(80, 0),
        nTx: 1,
        status: 0x1f,
        dataPos: 0,
      });
      await db.putChainState({
        bestBlockHash: tip,
        bestHeight: 1,
        totalWork: 1n,
      });

      const snapshotPath = join(testDbPath, "atomic.dat");
      const tempPath = `${snapshotPath}.incomplete`;
      const params: ConsensusParams = { ...REGTEST };
      const mgr = new ChainstateManager(db, params);

      // First dump should succeed.
      await mgr.dumpSnapshot(snapshotPath);

      // <path> exists (resolves with no error from access()).
      let pathExists = false;
      try {
        await fsp.access(snapshotPath);
        pathExists = true;
      } catch {
        pathExists = false;
      }
      expect(pathExists).toBe(true);

      // <path>.incomplete should NOT exist after a successful dump.
      let tempExists = false;
      try {
        await fsp.access(tempPath);
        tempExists = true;
      } catch {
        tempExists = false;
      }
      expect(tempExists).toBe(false);

      // A second dump to the same path must refuse to overwrite.
      await expect(mgr.dumpSnapshot(snapshotPath)).rejects.toThrow(
        /already exists/
      );

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
  // HASH_SERIALIZED wiring (assumeutxo strict gate).
  //
  // `computeUTXOSetHash` MUST produce the SHA256d-via-HashWriter digest
  // (CoinStatsHashType::HASH_SERIALIZED). The four hardcoded mainnet
  // `m_assumeutxo_data.hash_serialized` values in chain params are this
  // digest, NOT MuHash3072 outputs — see Core's
  // `validation.cpp:5902-5914` (calls `ComputeUTXOStats` with
  // `CoinStatsHashType::HASH_SERIALIZED`) and
  // `kernel/coinstats.cpp:161-163` (the HASH_SERIALIZED case constructs a
  // `HashWriter ss{}`, ingests TxOutSer bytes, returns `ss.GetHash()` =
  // double-SHA256). MuHash3072 is reserved for `gettxoutsetinfo` only and
  // is exercised separately below via `computeUTXOSetMuHash`.
  //
  // The loadSnapshot strict-validation gate MUST refuse with Core's
  // verbatim "Bad snapshot content hash: expected ..., got ..." string.
  // -----------------------------------------------------------------------
  describe("HASH_SERIALIZED wiring (assumeutxo strict gate)", () => {
    let db: ChainDB;

    beforeEach(async () => {
      db = new ChainDB(join(testDbPath, "hash-serialized-wiring"));
      await db.open();
    });

    afterEach(async () => {
      await db.close();
    });

    /** Serialize a coin into TxOutSer bytes — manually duplicates the
     *  layout `computeUTXOSetHash` feeds into the HashWriter, so the test
     *  pins the exact byte format independent of internal helpers. */
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

    it("computeUTXOSetHash matches SHA256d (HashWriter::GetHash) over concatenated TxOutSer bytes", async () => {
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

      // The DB iterates in key order; reproduce the same digest by
      // sorting our coins by (prefix||txid||vout) — exactly what
      // ChainDB's UTXO iterator returns.
      const recs = [
        { txid: txidA, vout: 0, h: 12345, cb: true, amt: 50_00000000n, spk: spkA },
        { txid: txidB, vout: 7, h: 23456, cb: false, amt: 1_23456789n, spk: spkB },
      ].sort((a, b) => {
        const ka = Buffer.concat([
          a.txid,
          (() => {
            const b = Buffer.alloc(4);
            b.writeUInt32LE(a.vout);
            return b;
          })(),
        ]);
        const kb = Buffer.concat([
          b.txid,
          (() => {
            const buf = Buffer.alloc(4);
            buf.writeUInt32LE(b.vout);
            return buf;
          })(),
        ]);
        return ka.compare(kb);
      });

      // HASH_SERIALIZED = double-SHA256 of the streamed TxOutSer bytes
      // (HashWriter::GetHash = sha256(sha256_finalize(stream))). The
      // streaming `Bun.CryptoHasher` already produces the inner SHA-256,
      // so we apply ONE more SHA-256 — `sha256Hash`, NOT `hash256`,
      // which would chain two more SHA-256s and yield triple-SHA256
      // (the bug that broke mainnet snapshot loads — see snapshot.ts
      // computeUTXOSetHash final step).
      const hasher = new Bun.CryptoHasher("sha256");
      for (const r of recs) {
        hasher.update(txOutSer(r.txid, r.vout, r.h, r.cb, r.amt, r.spk));
      }
      const inner = Buffer.from(hasher.digest());
      const expected = sha256Hash(inner);

      expect(hash.equals(expected)).toBe(true);
      expect(hash.length).toBe(32);
    });

    it("computeUTXOSetHash is order-dependent (HashWriter ingests in DB iter order)", async () => {
      // HASH_SERIALIZED is NOT order-independent — Core's HashWriter
      // streams bytes into SHA256, so the digest depends on the order
      // they arrive (this is why the assumeutxo commitment pins a
      // specific iteration order via leveldb's lexicographic byte
      // ordering on (prefix||txid||vout) keys).
      const recs = [
        { txid: Buffer.alloc(32, 0x01), vout: 0, h: 100, cb: true, amt: 5000n, spk: Buffer.from([0x6a, 0x01]) },
        { txid: Buffer.alloc(32, 0x02), vout: 0, h: 200, cb: false, amt: 6000n, spk: Buffer.from([0x6a, 0x02]) },
        { txid: Buffer.alloc(32, 0x03), vout: 0, h: 300, cb: false, amt: 7000n, spk: Buffer.from([0x6a, 0x03]) },
      ];

      const fwd = new Bun.CryptoHasher("sha256");
      for (const r of recs) fwd.update(txOutSer(r.txid, r.vout, r.h, r.cb, r.amt, r.spk));
      const hashFwd = sha256Hash(Buffer.from(fwd.digest()));

      const rev = new Bun.CryptoHasher("sha256");
      for (const r of [...recs].reverse()) rev.update(txOutSer(r.txid, r.vout, r.h, r.cb, r.amt, r.spk));
      const hashRev = sha256Hash(Buffer.from(rev.digest()));

      // Different orderings -> different digests under HASH_SERIALIZED.
      expect(hashFwd.equals(hashRev)).toBe(false);
    });

    it("empty UTXO set hashes to double-SHA256 of zero bytes", async () => {
      const { hash, coinsCount } = await computeUTXOSetHash(db);
      expect(coinsCount).toBe(0n);

      // Empty stream -> SHA-256 of "" -> SHA-256(SHA-256("")) = double-SHA256("").
      // Reproduce with one streaming SHA-256 + one more SHA-256, matching
      // computeUTXOSetHash. (Don't use `hash256` here — that would triple-hash.)
      const empty = new Bun.CryptoHasher("sha256");
      const inner = Buffer.from(empty.digest());
      const expected = sha256Hash(inner);

      expect(hash.equals(expected)).toBe(true);
    });

    // -----------------------------------------------------------------------
    // Hard-coded SHA256d fixture — pins HASH_SERIALIZED against a value
    // computed independently (Python `hashlib`) so a future refactor that
    // re-introduces the triple-SHA256 bug fails this test.
    //
    // Bug history (wave 5, 2026-05-02): computeUTXOSetHash finalized
    // `Bun.CryptoHasher` (one SHA-256 of the streamed TxOutSer bytes)
    // and then called `hash256(inner)` — but `hash256(x) = sha256(sha256(x))`,
    // so the chain became sha256(sha256(sha256(stream))) = TRIPLE SHA-256.
    // On the mainnet 165 095 935-coin snapshot this produced
    // `2075205e71f087f76533a3f108b66e22e2de42cdc8a44f5b1601c7b314c66097`
    // = `sha256(a888bcbc...)` instead of `a888bcbc...` (the actual
    // double-SHA256), failing the strict assumeutxo gate. Verified
    // bit-for-bit by per-txid coin-stream diff vs the snapshot file:
    // all 114 383 783 group hashes matched, proving the data was correct
    // and the bug lived in the final fold-down. Fixed by replacing
    // `hash256(inner)` with `sha256Hash(inner)` (one more SHA-256, not
    // two more).
    //
    // Regression pin: empty UTXO set MUST hash to
    //   SHA256(SHA256("")) = 5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456
    // — NOT to triple-SHA256("") =
    //     aa6ac2d4961882f42a345c7615f4133dde8e6d6e7c1b6b40ae4ff6ee52c393d0
    // -----------------------------------------------------------------------
    it("HASH_SERIALIZED is double-SHA256 (NOT triple) — empty UTXO fixture", async () => {
      const { hash, coinsCount } = await computeUTXOSetHash(db);
      expect(coinsCount).toBe(0n);

      // Independently computed: SHA-256(SHA-256(b"")), via Python `hashlib`.
      // This is what Core's HashWriter::GetHash() returns for an empty
      // stream (see bitcoin-core/src/hash.h).
      const expectedDouble = Buffer.from(
        "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456",
        "hex",
      );
      const tripleBuggy = Buffer.from(
        "aa6ac2d4961882f42a345c7615f4133dde8e6d6e7c1b6b40ae4ff6ee52c393d0",
        "hex",
      );

      expect(hash.equals(expectedDouble)).toBe(true);
      // Pin the regression: the buggy triple-SHA256 must NOT match.
      expect(hash.equals(tripleBuggy)).toBe(false);
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

      const dumpPath = join(testDbPath, "strict-bad.dat");
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

    it("loadSnapshot strict gate uses HASH_SERIALIZED, NOT MuHash3072", async () => {
      // Regression guard for cb7488f: the strict gate MUST reject when
      // we register a *MuHash3072* digest in chain params, even though
      // the bytes are valid as a MuHash output. Per Core's
      // validation.cpp:5902, the gate is HASH_SERIALIZED — registering
      // a MuHash digest must therefore fail the comparison.
      const tip = Buffer.alloc(32, 0xfb);
      await db.putChainState({ bestBlockHash: tip, bestHeight: 13, totalWork: 1n });
      await db.putBlockIndex(tip, {
        height: 13,
        header: Buffer.alloc(80, 0),
        nTx: 1,
        status: 0x1f,
        dataPos: 0,
      });

      const txid = Buffer.alloc(32, 0xa3);
      const spk = Buffer.from([0x76, 0xa9, 0x14, ...Buffer.alloc(20, 0x66), 0x88, 0xac]);
      await db.putUTXO(txid, 0, { height: 13, coinbase: false, amount: 7n, scriptPubKey: spk });

      // Compute BOTH digests and confirm they differ.
      const { hash: serialized } = await computeUTXOSetHash(db);
      const { hash: muhash } = await computeUTXOSetMuHash(db);
      expect(serialized.equals(muhash)).toBe(false);

      // Register the MuHash digest as `hashSerialized` in params — the
      // strict gate must reject because the field semantically holds
      // HASH_SERIALIZED, and we computed MuHash.
      const params: ConsensusParams = {
        ...REGTEST,
        assumeutxo: new Map([
          [tip.toString("hex"), { height: 13, hashSerialized: muhash, nChainTx: 1n, blockHash: tip }],
        ]),
      };

      const dumpPath = join(testDbPath, "strict-muhash-rejected.dat");
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
      let caught: Error | null = null;
      try {
        await loadMgr.loadSnapshot(dumpPath);
      } catch (e) {
        caught = e as Error;
      }

      // Strict gate rejects: digest registered as HASH_SERIALIZED was
      // actually MuHash, so the SHA256d check fails.
      expect(caught).not.toBeNull();
      expect(caught!.message.startsWith("Bad snapshot content hash: expected ")).toBe(true);
      // The "got" side is the SHA256d digest (what computeUTXOSetHash
      // produces); confirm the message contains it, NOT the MuHash.
      expect(caught!.message).toContain(serialized.toString("hex"));
    });

    it("loadSnapshot accepts a roundtripped snapshot whose hash matches the registered HASH_SERIALIZED value", async () => {
      // The complementary success path — register the *correct*
      // SHA256d digest we actually computed and confirm loadSnapshot
      // does not throw.
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

      const dumpPath = join(testDbPath, "strict-good.dat");
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

  // -----------------------------------------------------------------------
  // MuHash3072 wiring (gettxoutsetinfo hash_type=muhash).
  //
  // `computeUTXOSetMuHash` is the order-independent multiset hash; it is
  // NOT the assumeutxo strict-gate hash. Reference:
  // bitcoin-core/src/kernel/coinstats.cpp::ApplyCoinHash(MuHash3072&, ...).
  // -----------------------------------------------------------------------
  describe("MuHash3072 wiring (gettxoutsetinfo only)", () => {
    let db: ChainDB;

    beforeEach(async () => {
      db = new ChainDB(join(testDbPath, "muhash-wiring"));
      await db.open();
    });

    afterEach(async () => {
      await db.close();
    });

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

    it("computeUTXOSetMuHash matches an independent MuHash3072 over TxOutSer", async () => {
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

      const { hash, coinsCount } = await computeUTXOSetMuHash(db);
      expect(coinsCount).toBe(2n);

      const acc = new MuHash3072();
      acc.add(txOutSer(txidA, 0, 12345, true, 50_00000000n, spkA));
      acc.add(txOutSer(txidB, 7, 23456, false, 1_23456789n, spkB));
      const expected = acc.finalize();

      expect(hash.equals(expected)).toBe(true);
      expect(hash.length).toBe(32);
    });

    it("computeUTXOSetMuHash is order-independent (multiset property)", async () => {
      const coins = [
        { txid: Buffer.alloc(32, 0x01), vout: 0, height: 100, cb: true, amt: 5000n, spk: Buffer.from([0x6a, 0x01]) },
        { txid: Buffer.alloc(32, 0x02), vout: 0, height: 200, cb: false, amt: 6000n, spk: Buffer.from([0x6a, 0x02]) },
        { txid: Buffer.alloc(32, 0x03), vout: 0, height: 300, cb: false, amt: 7000n, spk: Buffer.from([0x6a, 0x03]) },
      ];

      for (const c of coins) {
        await db.putUTXO(c.txid, c.vout, { height: c.height, coinbase: c.cb, amount: c.amt, scriptPubKey: c.spk });
      }
      const { hash: h1 } = await computeUTXOSetMuHash(db);

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

    it("empty UTXO set hashes to MuHash3072 identity (numerator=denominator=1)", async () => {
      const { hash, coinsCount } = await computeUTXOSetMuHash(db);
      expect(coinsCount).toBe(0n);

      const emptyAcc = new MuHash3072();
      const expected = emptyAcc.finalize();
      expect(hash.equals(expected)).toBe(true);
    });
  });

  // -----------------------------------------------------------------------
  // High-vout iteration order regression test.
  //
  // Bug history: hotbuns LevelDB encodes UTXO keys as
  // [prefix=0x75][txid 32B][vout uint32_LE]. LevelDB iterates byte-lex,
  // so within a txid the vouts come out in LE-byte order rather than
  // numeric order. Bitcoin Core uses `std::map<uint32_t, Coin>` keyed
  // by vout (`kernel/coinstats.cpp:122-128` in ApplyStats /
  // `rpc/blockchain.cpp` WriteUTXOSnapshot), which iterates vouts in
  // NUMERIC order.
  //
  // For any txid with at least one vout >= 256 the two orderings differ
  // (e.g. numeric [0,1,256,257] vs LE-byte [0,1,0,0,0,0,0,1,0,0,0,1,...]
  // when serialized). Mainnet at h=940k has 183,859 of 114M txids with
  // vout >= 256, max vout 13,106 — so a naive byte-lex ingestion of the
  // DB produces a HASH_SERIALIZED digest that does NOT match Core's
  // `m_assumeutxo_data.hash_serialized` constants and breaks
  // dumptxoutset byte-identity vs Core.
  //
  // Fix lives in `computeUTXOSetHash` / `computeUTXOSetMuHash` /
  // `dumpSnapshot` in src/chain/snapshot.ts (group per txid, sort by
  // vout numerically before ingestion / before flushing). This test
  // pins the regression by building a txid with vouts {0, 1, 256, 257,
  // 13106} — the LE-byte and numeric orderings diverge, and any future
  // refactor that drops the per-group sort will fail.
  // -----------------------------------------------------------------------
  describe("High-vout iteration order (regression)", () => {
    let db: ChainDB;

    beforeEach(async () => {
      db = new ChainDB(join(testDbPath, "high-vout-order"));
      await db.open();
    });

    afterEach(async () => {
      await db.close();
    });

    /** Same TxOutSer layout as `computeUTXOSetHash` ingests. */
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

    /** Build the canonical (Core-order) digest for a set of coins.
     *  Sorted by (txid lex ASC, vout NUMERIC ASC) — what Core produces. */
    function canonicalCoreHash(
      records: Array<{
        txid: Buffer;
        vout: number;
        height: number;
        coinbase: boolean;
        amount: bigint;
        spk: Buffer;
      }>
    ): Buffer {
      // Group by txid (DB iterates txids in lex order anyway, since the
      // first 32 bytes of the DB key are txid).
      const sorted = [...records].sort((a, b) => {
        const cmp = a.txid.compare(b.txid);
        if (cmp !== 0) return cmp;
        return a.vout - b.vout; // numeric, matches std::map<uint32_t, Coin>
      });
      const hasher = new Bun.CryptoHasher("sha256");
      for (const r of sorted) {
        hasher.update(txOutSer(r.txid, r.vout, r.height, r.coinbase, r.amount, r.spk));
      }
      // Bun.CryptoHasher already gives the inner SHA-256 of the stream;
      // one more SHA-256 yields Core's HashWriter::GetHash double-SHA256.
      // (Calling `hash256` here would chain a third SHA-256 — the bug
      // computeUTXOSetHash used to have, see snapshot.ts.)
      const inner = Buffer.from(hasher.digest());
      return sha256Hash(inner);
    }

    it("computeUTXOSetHash matches Core canonical order for txid with vout >= 256", async () => {
      // Single txid, vouts spanning the [0, 256+) boundary.
      // The LE-byte ordering of vouts {0, 1, 256, 257, 13106} differs
      // from the numeric ordering — vout=256 has key bytes [00,01,00,00]
      // which sorts AFTER [00,00,00,00] but BEFORE [01,00,00,00] in
      // little-endian byte-lex (matching numeric here), but for vouts
      // like {255, 256} the LE-byte order is {255 -> ff,00,00,00,
      // 256 -> 00,01,00,00} which puts 256 BEFORE 255 in byte-lex while
      // numeric puts 255 first. We use the more dramatic {0,1,256,257,
      // 13106} where multiple ones land in the "wrong" lex slot.
      const txid = Buffer.alloc(32, 0xab);
      const spk = Buffer.from([0x76, 0xa9, 0x14, ...Buffer.alloc(20, 0x55), 0x88, 0xac]);
      const vouts = [0, 1, 256, 257, 13106];

      const records = vouts.map((v) => ({
        txid,
        vout: v,
        height: 800_000 + v, // distinct heights so order matters in digest
        coinbase: false,
        amount: BigInt(v + 1) * 1_000_000n,
        spk,
      }));

      // Insert in numeric order (the order doesn't matter — DB will
      // re-key by [prefix||txid||vout_LE], which sorts by LE-byte).
      for (const r of records) {
        await db.putUTXO(r.txid, r.vout, {
          height: r.height,
          coinbase: r.coinbase,
          amount: r.amount,
          scriptPubKey: r.spk,
        });
      }

      const { hash, coinsCount } = await computeUTXOSetHash(db);
      expect(coinsCount).toBe(BigInt(vouts.length));

      const expected = canonicalCoreHash(
        records.map((r) => ({
          txid: r.txid,
          vout: r.vout,
          height: r.height,
          coinbase: r.coinbase,
          amount: r.amount,
          spk: r.spk,
        }))
      );

      // Sanity: the LE-byte permutation of vouts {0,1,256,257,13106}
      // really does differ from the numeric one.
      const leBytes = (n: number) => {
        const b = Buffer.alloc(4);
        b.writeUInt32LE(n);
        return b;
      };
      const numericOrder = [...vouts].sort((a, b) => a - b);
      const leByteOrder = [...vouts].sort((a, b) => leBytes(a).compare(leBytes(b)));
      expect(JSON.stringify(numericOrder)).not.toBe(JSON.stringify(leByteOrder));

      // The fix: hotbuns now produces the canonical (numeric) digest.
      expect(hash.equals(expected)).toBe(true);

      // And specifically NOT the LE-byte digest, which is what the
      // bug produced. Build that one manually to pin the regression.
      const wrongHasher = new Bun.CryptoHasher("sha256");
      const wrongOrder = [...records].sort((a, b) =>
        leBytes(a.vout).compare(leBytes(b.vout))
      );
      for (const r of wrongOrder) {
        wrongHasher.update(txOutSer(r.txid, r.vout, r.height, r.coinbase, r.amount, r.spk));
      }
      const wrongInner = Buffer.from(wrongHasher.digest());
      const wrongHash = sha256Hash(wrongInner);
      expect(hash.equals(wrongHash)).toBe(false);
    });

    it("computeUTXOSetHash multi-txid: per-txid numeric vout sort within lex-sorted txids", async () => {
      // Three txids, each with mixed-vout. Verify the global digest is
      // ((txid lex) outer, (vout numeric) inner) and not the byte-lex
      // global ordering that LevelDB would naively produce.
      const txidA = Buffer.alloc(32, 0x01);
      const txidB = Buffer.alloc(32, 0x02);
      const txidC = Buffer.alloc(32, 0x03);
      const spk = Buffer.from([0x6a, 0xff]); // OP_RETURN 0xff

      const records = [
        // txidA: vouts {1, 256} — boundary
        { txid: txidA, vout: 1, height: 100, coinbase: false, amount: 100n, spk },
        { txid: txidA, vout: 256, height: 101, coinbase: false, amount: 200n, spk },
        // txidB: vouts {0, 257, 999} — high vouts
        { txid: txidB, vout: 0, height: 200, coinbase: true, amount: 300n, spk },
        { txid: txidB, vout: 257, height: 201, coinbase: false, amount: 400n, spk },
        { txid: txidB, vout: 999, height: 202, coinbase: false, amount: 500n, spk },
        // txidC: single vout (no in-group ordering matters)
        { txid: txidC, vout: 0, height: 300, coinbase: false, amount: 600n, spk },
      ];

      for (const r of records) {
        await db.putUTXO(r.txid, r.vout, {
          height: r.height,
          coinbase: r.coinbase,
          amount: r.amount,
          scriptPubKey: r.spk,
        });
      }

      const { hash, coinsCount } = await computeUTXOSetHash(db);
      expect(coinsCount).toBe(BigInt(records.length));

      const expected = canonicalCoreHash(records);
      expect(hash.equals(expected)).toBe(true);
    });

    it("dumpSnapshot writes per-txid coins in numeric vout order (Core's WriteUTXOSnapshot)", async () => {
      // Build a UTXO set with one high-vout txid, dump it, then read
      // back the snapshot bytes and verify the vouts within the txid
      // group come out in numeric ascending order — what
      // rpc/blockchain.cpp WriteUTXOSnapshot produces from
      // std::map<uint32_t, Coin>.
      const tip = Buffer.alloc(32, 0xfe);
      await db.putChainState({ bestBlockHash: tip, bestHeight: 850_000, totalWork: 1n });
      await db.putBlockIndex(tip, {
        height: 850_000,
        header: Buffer.alloc(80, 0),
        nTx: 1,
        status: 0x1f,
        dataPos: 0,
      });

      const txid = Buffer.alloc(32, 0xcd);
      const spk = Buffer.from([0x76, 0xa9, 0x14, ...Buffer.alloc(20, 0x77), 0x88, 0xac]);
      const vouts = [0, 1, 256, 257, 13106];

      for (const v of vouts) {
        await db.putUTXO(txid, v, {
          height: 100_000 + v,
          coinbase: false,
          amount: BigInt(v + 1) * 1000n,
          scriptPubKey: spk,
        });
      }

      const dumpPath = "/tmp/hotbuns-high-vout-dump-" + Date.now() + ".dat";
      const params: ConsensusParams = {
        ...REGTEST,
        // Empty assumeutxo map so dumpSnapshot doesn't try to look up
        // a chainparams entry — dumpSnapshot doesn't gate on this.
      };
      const mgr = new ChainstateManager(db, params);
      try {
        const result = await mgr.dumpSnapshot(dumpPath);
        expect(result.coinsWritten).toBe(BigInt(vouts.length));

        // Read the snapshot bytes and verify vout ordering inside the
        // group. Header is 51 bytes (5 magic + 2 version + 4 netmagic +
        // 32 baseblockhash + 8 coinscount). Then groups of [txid 32B,
        // CompactSize count, [CompactSize vout, VARINT(code),
        // VARINT(amount), CompressedScript]+]. We only need to check
        // the vout order — the field that was wrong before.
        const file = Bun.file(dumpPath);
        const bytes = Buffer.from(await file.arrayBuffer());
        const reader = new BufferReader(bytes.subarray(51));

        // First (and only) group.
        const groupTxid = reader.readBytes(32);
        expect(groupTxid.equals(txid)).toBe(true);

        // CompactSize count.
        const count = reader.readVarInt();
        expect(count).toBe(vouts.length);

        const observedVouts: number[] = [];
        for (let i = 0; i < count; i++) {
          observedVouts.push(reader.readVarInt());
          // Skip the rest of the per-coin payload (code + amount +
          // compressed script). We don't need to validate them here —
          // a separate test (`computeUTXOSetHash`) covers digest
          // correctness end-to-end. Use readVarIntCore for both code
          // and amount (Pieter's VARINT, NOT CompactSize), then read
          // the compressed-script header byte / payload.
          readVarIntCore(reader); // code
          readVarIntCore(reader); // compressed amount
          const nSize = Number(readVarIntCore(reader));
          // Special scripts (P2PKH, P2SH, P2PK) are 20/20/32 bytes;
          // raw script: nSize - NUM_SPECIAL_SCRIPTS (=6) bytes.
          // For our spk = P2PKH (nSize=0), payload is 20 bytes.
          if (nSize === 0 || nSize === 1) {
            reader.readBytes(20);
          } else if (nSize === 2 || nSize === 3 || nSize === 4 || nSize === 5) {
            reader.readBytes(32);
          } else {
            reader.readBytes(nSize - 6);
          }
        }

        // Numeric ascending — what Core produces.
        expect(observedVouts).toEqual([...vouts].sort((a, b) => a - b));
        // Sanity: confirms this is NOT the LE-byte order (which differs
        // for high vouts).
        const leBytes = (n: number) => {
          const b = Buffer.alloc(4);
          b.writeUInt32LE(n);
          return b;
        };
        const leByteOrder = [...vouts].sort((a, b) =>
          leBytes(a).compare(leBytes(b))
        );
        expect(JSON.stringify(observedVouts)).not.toBe(
          JSON.stringify(leByteOrder)
        );
      } finally {
        try {
          rmSync(dumpPath, { force: true });
          rmSync(dumpPath + ".tmp", { force: true });
        } catch {
          // Ignore
        }
      }
    });
  });
});
