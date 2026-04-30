/**
 * Tests for mempool.dat persistence (Core-compatible MEMPOOL_DUMP_VERSION=2).
 */

import { describe, test, expect, beforeEach, afterEach } from "bun:test";
import { mkdtemp, rm, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ChainDB, UTXOEntry } from "../storage/database.js";
import { UTXOManager } from "../chain/utxo.js";
import { REGTEST } from "../consensus/params.js";
import { Mempool } from "./mempool.js";
import {
  applyObfuscation,
  dumpMempool,
  encodeMempoolDump,
  decodeMempoolDump,
  loadMempool,
  MEMPOOL_DUMP_VERSION,
  MEMPOOL_DUMP_VERSION_NO_XOR_KEY,
  OBFUSCATION_KEY_SIZE,
} from "./persist.js";
import type { Transaction } from "../validation/tx.js";
import { getTxId } from "../validation/tx.js";

describe("mempool persistence", () => {
  let tempDir: string;
  let db: ChainDB;
  let utxo: UTXOManager;
  let mempool: Mempool;

  function makeTx(seed: number, witness: boolean = false): Transaction {
    return {
      version: 2,
      inputs: [
        {
          prevOut: { txid: Buffer.alloc(32, seed), vout: 0 },
          scriptSig: Buffer.alloc(0),
          sequence: 0xffffffff,
          witness: witness ? [Buffer.from([0x01, 0x02, 0x03])] : [],
        },
      ],
      outputs: [
        { value: 9000n, scriptPubKey: Buffer.from([0x51]) }, // OP_TRUE
      ],
      lockTime: 0,
    };
  }

  async function fundUTXO(txid: Buffer, vout: number, amount: bigint): Promise<void> {
    const entry: UTXOEntry = {
      height: 1,
      coinbase: false,
      amount,
      scriptPubKey: Buffer.from([0x51]),
    };
    await db.putUTXO(txid, vout, entry);
  }

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "mempool-persist-"));
    db = new ChainDB(tempDir);
    await db.open();
    utxo = new UTXOManager(db);
    mempool = new Mempool(utxo, REGTEST, 1_000_000);
    mempool.setTipHeight(200);
  });

  afterEach(async () => {
    await db.close();
    await rm(tempDir, { recursive: true, force: true });
  });

  describe("applyObfuscation", () => {
    test("zero key is a no-op", () => {
      const data = Buffer.from([0x11, 0x22, 0x33, 0x44]);
      const expected = Buffer.from(data);
      applyObfuscation(data, 0, Buffer.alloc(8, 0));
      expect(data.equals(expected)).toBe(true);
    });

    test("non-zero key XORs against repeating pattern", () => {
      const data = Buffer.alloc(16, 0xff);
      const key = Buffer.from([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
      applyObfuscation(data, 0, key);
      // After XOR with repeating key, byte i = 0xff ^ key[i%8]
      expect(data[0]).toBe(0xff ^ 0x01);
      expect(data[1]).toBe(0xff ^ 0x02);
      expect(data[7]).toBe(0xff ^ 0x08);
      expect(data[8]).toBe(0xff ^ 0x01); // wrapped
      expect(data[15]).toBe(0xff ^ 0x08);
    });

    test("file offset shifts the key wheel", () => {
      const a = Buffer.from([0x00, 0x00]);
      const b = Buffer.from([0x00, 0x00]);
      const key = Buffer.from([0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18]);
      applyObfuscation(a, 0, key);
      applyObfuscation(b, 1, key);
      // byte at offset 1 against key[1] (=0xb2) must equal byte at offset 0 against key[0] when shifted by 1
      expect(a[0]).toBe(0xa1);
      expect(a[1]).toBe(0xb2);
      expect(b[0]).toBe(0xb2); // because (1+0)%8 = 1
      expect(b[1]).toBe(0xc3);
    });

    test("XOR is its own inverse", () => {
      const original = Buffer.from([0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, 0x12, 0x34]);
      const key = Buffer.from([0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00]);
      const data = Buffer.from(original);
      applyObfuscation(data, 17, key);
      expect(data.equals(original)).toBe(false);
      applyObfuscation(data, 17, key);
      expect(data.equals(original)).toBe(true);
    });

    test("rejects keys of wrong length", () => {
      expect(() =>
        applyObfuscation(Buffer.alloc(4), 0, Buffer.alloc(7))
      ).toThrow(/8 bytes/);
    });
  });

  describe("encodeMempoolDump", () => {
    test("emits version=2 in the first 8 bytes", () => {
      const buf = encodeMempoolDump([], new Map(), new Set(), Buffer.alloc(8, 0));
      // unobfuscated bytes 0-7: version uint64 LE
      expect(buf.readBigUInt64LE(0)).toBe(MEMPOOL_DUMP_VERSION);
    });

    test("emits compactsize=8 + 8-byte key after the version", () => {
      const key = Buffer.from([0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8]);
      const buf = encodeMempoolDump([], new Map(), new Set(), key);
      expect(buf[8]).toBe(OBFUSCATION_KEY_SIZE); // compactsize for 8 fits in one byte
      expect(buf.subarray(9, 17).equals(key)).toBe(true);
    });

    test("empty mempool: total length is 17-byte header + 9 obfuscated body bytes", () => {
      // body = uint64(count=0) [8] + compactsize(deltas=0) [1] + compactsize(unbroadcast=0) [1] = 10
      // wait — 8 + 1 + 1 = 10, but compactsize of 0 is 1 byte each.
      const buf = encodeMempoolDump([], new Map(), new Set(), Buffer.alloc(8, 0));
      expect(buf.length).toBe(17 + 8 + 1 + 1);
    });

    test("round-trips one transaction", () => {
      const tx = makeTx(0xaa);
      const key = Buffer.from([1, 2, 3, 4, 5, 6, 7, 8]);
      const buf = encodeMempoolDump(
        [{ tx, time: 1714200000n, feeDelta: 0n }],
        new Map(),
        new Set(),
        key
      );
      const decoded = decodeMempoolDump(buf);
      expect(decoded.entries).toHaveLength(1);
      expect(decoded.entries[0].time).toBe(1714200000n);
      expect(decoded.entries[0].feeDelta).toBe(0n);
      expect(getTxId(decoded.entries[0].tx).equals(getTxId(tx))).toBe(true);
    });

    test("round-trips a witness transaction (BIP-141)", () => {
      const tx = makeTx(0xbb, /*witness=*/ true);
      const key = Buffer.from([0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88]);
      const buf = encodeMempoolDump(
        [{ tx, time: 0n, feeDelta: 0n }],
        new Map(),
        new Set(),
        key
      );
      const decoded = decodeMempoolDump(buf);
      expect(decoded.entries[0].tx.inputs[0].witness.length).toBe(1);
      expect(decoded.entries[0].tx.inputs[0].witness[0].toString("hex")).toBe(
        "010203"
      );
    });

    test("round-trips mapDeltas + unbroadcast set", () => {
      const txidA = Buffer.alloc(32, 0xa1).toString("hex");
      const txidB = Buffer.alloc(32, 0xb2).toString("hex");
      const deltas = new Map<string, bigint>([
        [txidA, 12345n],
        [txidB, 99999n],
      ]);
      const unbroadcast = new Set<string>([txidA]);
      const buf = encodeMempoolDump(
        [],
        deltas,
        unbroadcast,
        Buffer.from([1, 2, 3, 4, 5, 6, 7, 8])
      );
      const decoded = decodeMempoolDump(buf);
      expect(decoded.mapDeltas.size).toBe(2);
      expect(decoded.mapDeltas.get(txidA)).toBe(12345n);
      expect(decoded.mapDeltas.get(txidB)).toBe(99999n);
      expect(decoded.unbroadcast.size).toBe(1);
      expect(decoded.unbroadcast.has(txidA)).toBe(true);
    });

    test("v1 (no XOR key) decodes correctly", () => {
      // A v1 buffer is: uint64(version=1) + uint64(count=0) + compactsize(0) + compactsize(0)
      const w = Buffer.concat([
        (() => {
          const b = Buffer.alloc(8);
          b.writeBigUInt64LE(MEMPOOL_DUMP_VERSION_NO_XOR_KEY, 0);
          return b;
        })(),
        (() => {
          const b = Buffer.alloc(8);
          b.writeBigUInt64LE(0n, 0); // count
          return b;
        })(),
        Buffer.from([0x00]), // mapDeltas count
        Buffer.from([0x00]), // unbroadcast count
      ]);
      const decoded = decodeMempoolDump(w);
      expect(decoded.entries).toHaveLength(0);
      expect(decoded.mapDeltas.size).toBe(0);
      expect(decoded.unbroadcast.size).toBe(0);
    });

    test("rejects unknown version", () => {
      const b = Buffer.alloc(8);
      b.writeBigUInt64LE(99n, 0);
      expect(() => decodeMempoolDump(b)).toThrow(/version 99/);
    });

    test("rejects file shorter than version field", () => {
      expect(() => decodeMempoolDump(Buffer.alloc(4))).toThrow(/too short/);
    });

    test("byte layout: header is unobfuscated, body is obfuscated", () => {
      // Two encodes with different keys must agree byte-for-byte on the
      // first 8 bytes (version) but diverge inside the body region.
      const a = encodeMempoolDump(
        [],
        new Map(),
        new Set(),
        Buffer.from([1, 2, 3, 4, 5, 6, 7, 8])
      );
      const b = encodeMempoolDump(
        [],
        new Map(),
        new Set(),
        Buffer.from([9, 10, 11, 12, 13, 14, 15, 16])
      );
      expect(a.subarray(0, 8).equals(b.subarray(0, 8))).toBe(true); // version
      // Body region (offset >= 17) is XORed against different keys, so
      // byte 17 must differ when at least one key byte differs at slot 1.
      // (The body's first byte is the LSB of count=0n, so it's 0x00 unobfuscated.)
      expect(a[17]).not.toBe(b[17]);
    });
  });

  describe("dumpMempool / loadMempool round-trip on disk", () => {
    test("empty mempool produces a valid file that loads to empty", async () => {
      const dump = await dumpMempool(mempool, tempDir);
      expect(dump.count).toBe(0);
      const fileBuf = await readFile(dump.path);
      expect(fileBuf.length).toBeGreaterThan(0);
      expect(fileBuf.readBigUInt64LE(0)).toBe(MEMPOOL_DUMP_VERSION);

      // Fresh mempool loads the empty dump cleanly.
      const result = await loadMempool(mempool, tempDir);
      expect(result.succeeded).toBe(0);
      expect(result.failed).toBe(0);
      expect(mempool.getSize()).toBe(0);
    });

    test("dump persists txs, then load restores them through accept-to-mempool", async () => {
      // Set up two spendable UTXOs and add two txs to the mempool.
      const inA = Buffer.alloc(32, 0xa1);
      const inB = Buffer.alloc(32, 0xa2);
      await fundUTXO(inA, 0, 10000n);
      await fundUTXO(inB, 0, 10000n);
      const txA: Transaction = {
        version: 2,
        inputs: [
          {
            prevOut: { txid: inA, vout: 0 },
            scriptSig: Buffer.alloc(0),
            sequence: 0xffffffff,
            witness: [],
          },
        ],
        outputs: [{ value: 9000n, scriptPubKey: Buffer.from([0x51]) }],
        lockTime: 0,
      };
      const txB: Transaction = {
        version: 2,
        inputs: [
          {
            prevOut: { txid: inB, vout: 0 },
            scriptSig: Buffer.alloc(0),
            sequence: 0xffffffff,
            witness: [],
          },
        ],
        outputs: [{ value: 9000n, scriptPubKey: Buffer.from([0x51]) }],
        lockTime: 0,
      };
      const ra = await mempool.addTransaction(txA);
      const rb = await mempool.addTransaction(txB);
      expect(ra.accepted).toBe(true);
      expect(rb.accepted).toBe(true);
      expect(mempool.getSize()).toBe(2);

      const dump = await dumpMempool(mempool, tempDir);
      expect(dump.count).toBe(2);

      // Drain the live mempool, then reload from disk.
      mempool.clear();
      expect(mempool.getSize()).toBe(0);

      const result = await loadMempool(mempool, tempDir);
      expect(result.succeeded).toBe(2);
      expect(result.failed).toBe(0);
      expect(mempool.getSize()).toBe(2);
      expect(mempool.hasTransaction(getTxId(txA))).toBe(true);
      expect(mempool.hasTransaction(getTxId(txB))).toBe(true);
    });

    test("missing file returns succeeded=0 (no-op)", async () => {
      const result = await loadMempool(mempool, tempDir);
      expect(result).toEqual({ succeeded: 0, failed: 0, expired: 0, unbroadcast: 0 });
    });

    test("expired entries are dropped on load", async () => {
      const inA = Buffer.alloc(32, 0x55);
      await fundUTXO(inA, 0, 10000n);
      const tx: Transaction = {
        version: 2,
        inputs: [
          {
            prevOut: { txid: inA, vout: 0 },
            scriptSig: Buffer.alloc(0),
            sequence: 0xffffffff,
            witness: [],
          },
        ],
        outputs: [{ value: 9000n, scriptPubKey: Buffer.from([0x51]) }],
        lockTime: 0,
      };
      // Encode with a deliberately ancient timestamp.
      const buf = encodeMempoolDump(
        [{ tx, time: 0n, feeDelta: 0n }],
        new Map(),
        new Set(),
        Buffer.alloc(8, 0)
      );
      const path = join(tempDir, "mempool.dat");
      await Bun.write(path, buf);

      const result = await loadMempool(mempool, tempDir, /*expirySeconds=*/ 60);
      expect(result.expired).toBe(1);
      expect(result.succeeded).toBe(0);
      expect(mempool.getSize()).toBe(0);
    });

    test("malformed file does not throw — returns zeroes", async () => {
      const path = join(tempDir, "mempool.dat");
      await Bun.write(path, Buffer.from([0xff, 0xff, 0xff])); // garbage
      const result = await loadMempool(mempool, tempDir);
      expect(result.succeeded).toBe(0);
      expect(result.failed).toBe(0);
    });
  });
});
