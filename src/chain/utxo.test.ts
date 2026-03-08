/**
 * Tests for UTXO set management.
 */

import { describe, test, expect, beforeEach, afterEach } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ChainDB, UTXOEntry } from "../storage/database.js";
import {
  UTXOManager,
  serializeUndoData,
  deserializeUndoData,
  SpentUTXO,
} from "./utxo.js";
import type { Transaction, OutPoint } from "../validation/tx.js";

describe("UTXOManager", () => {
  let tempDir: string;
  let db: ChainDB;
  let utxo: UTXOManager;

  // Helper to create a test transaction
  function createTestTx(
    numInputs: number,
    numOutputs: number,
    inputTxid?: Buffer
  ): Transaction {
    const inputs = [];
    for (let i = 0; i < numInputs; i++) {
      inputs.push({
        prevOut: {
          txid: inputTxid || Buffer.alloc(32, i + 1),
          vout: i,
        },
        scriptSig: Buffer.alloc(0),
        sequence: 0xffffffff,
        witness: [],
      });
    }

    const outputs = [];
    for (let i = 0; i < numOutputs; i++) {
      outputs.push({
        value: BigInt((i + 1) * 1000),
        scriptPubKey: Buffer.from([0x76, 0xa9, 0x14, ...Array(20).fill(i), 0x88, 0xac]),
      });
    }

    return {
      version: 1,
      inputs,
      outputs,
      lockTime: 0,
    };
  }

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "utxo-test-"));
    db = new ChainDB(tempDir);
    await db.open();
    utxo = new UTXOManager(db);
  });

  afterEach(async () => {
    await db.close();
    await rm(tempDir, { recursive: true, force: true });
  });

  describe("addTransaction", () => {
    test("adds all outputs as UTXOs", () => {
      const txid = Buffer.alloc(32, 0xaa);
      const tx = createTestTx(0, 3);

      utxo.addTransaction(txid, tx, 100, false);

      // Verify all outputs are in cache
      for (let i = 0; i < 3; i++) {
        const entry = utxo.getUTXO({ txid, vout: i });
        expect(entry).not.toBeNull();
        expect(entry!.height).toBe(100);
        expect(entry!.coinbase).toBe(false);
        expect(entry!.amount).toBe(BigInt((i + 1) * 1000));
      }
    });

    test("marks coinbase outputs correctly", () => {
      const txid = Buffer.alloc(32, 0xbb);
      const tx = createTestTx(0, 1);

      utxo.addTransaction(txid, tx, 50, true);

      const entry = utxo.getUTXO({ txid, vout: 0 });
      expect(entry).not.toBeNull();
      expect(entry!.coinbase).toBe(true);
    });

    test("tracks added UTXOs for flush", () => {
      const txid = Buffer.alloc(32, 0xcc);
      const tx = createTestTx(0, 2);

      expect(utxo.getPendingCount()).toBe(0);
      utxo.addTransaction(txid, tx, 100, false);
      expect(utxo.getPendingCount()).toBe(2);
    });
  });

  describe("spendOutput", () => {
    test("spends UTXO from cache", () => {
      const txid = Buffer.alloc(32, 0xdd);
      const tx = createTestTx(0, 1);
      utxo.addTransaction(txid, tx, 100, false);

      const outpoint: OutPoint = { txid, vout: 0 };
      const entry = utxo.spendOutput(outpoint);

      expect(entry.amount).toBe(1000n);
      expect(utxo.hasUTXO(outpoint)).toBe(false);
    });

    test("throws on double spend", () => {
      const txid = Buffer.alloc(32, 0xee);
      const tx = createTestTx(0, 1);
      utxo.addTransaction(txid, tx, 100, false);

      const outpoint: OutPoint = { txid, vout: 0 };
      utxo.spendOutput(outpoint);

      expect(() => utxo.spendOutput(outpoint)).toThrow("already spent");
    });

    test("throws when UTXO not in cache", () => {
      const txid = Buffer.alloc(32, 0xff);
      const outpoint: OutPoint = { txid, vout: 0 };

      expect(() => utxo.spendOutput(outpoint)).toThrow("not in cache");
    });
  });

  describe("spendOutputAsync", () => {
    test("loads UTXO from database if not in cache", async () => {
      const txid = Buffer.alloc(32, 0x11);
      const entry: UTXOEntry = {
        height: 50,
        coinbase: false,
        amount: 5000n,
        scriptPubKey: Buffer.from([0x00, 0x14, ...Array(20).fill(0x55)]),
      };

      // Store directly in database
      await db.putUTXO(txid, 0, entry);

      const outpoint: OutPoint = { txid, vout: 0 };
      const spent = await utxo.spendOutputAsync(outpoint);

      expect(spent.amount).toBe(5000n);
      expect(spent.height).toBe(50);
    });

    test("throws when UTXO not found in database", async () => {
      const txid = Buffer.alloc(32, 0x22);
      const outpoint: OutPoint = { txid, vout: 0 };

      await expect(utxo.spendOutputAsync(outpoint)).rejects.toThrow("not found");
    });
  });

  describe("getUTXO and hasUTXO", () => {
    test("returns null for spent UTXOs", () => {
      const txid = Buffer.alloc(32, 0x33);
      const tx = createTestTx(0, 1);
      utxo.addTransaction(txid, tx, 100, false);

      const outpoint: OutPoint = { txid, vout: 0 };
      utxo.spendOutput(outpoint);

      expect(utxo.getUTXO(outpoint)).toBeNull();
      expect(utxo.hasUTXO(outpoint)).toBe(false);
    });

    test("returns entry for unspent UTXOs", () => {
      const txid = Buffer.alloc(32, 0x44);
      const tx = createTestTx(0, 1);
      utxo.addTransaction(txid, tx, 100, false);

      const outpoint: OutPoint = { txid, vout: 0 };
      expect(utxo.getUTXO(outpoint)).not.toBeNull();
      expect(utxo.hasUTXO(outpoint)).toBe(true);
    });
  });

  describe("getUTXOAsync and hasUTXOAsync", () => {
    test("checks database when not in cache", async () => {
      const txid = Buffer.alloc(32, 0x55);
      const entry: UTXOEntry = {
        height: 75,
        coinbase: true,
        amount: 50_00000000n,
        scriptPubKey: Buffer.alloc(25),
      };

      await db.putUTXO(txid, 0, entry);

      const outpoint: OutPoint = { txid, vout: 0 };
      const result = await utxo.getUTXOAsync(outpoint);

      expect(result).not.toBeNull();
      expect(result!.coinbase).toBe(true);
      expect(result!.amount).toBe(50_00000000n);

      expect(await utxo.hasUTXOAsync(outpoint)).toBe(true);
    });

    test("returns null for spent even if in database", async () => {
      const txid = Buffer.alloc(32, 0x66);
      const tx = createTestTx(0, 1);
      utxo.addTransaction(txid, tx, 100, false);

      const outpoint: OutPoint = { txid, vout: 0 };
      utxo.spendOutput(outpoint);

      // The cache tracks this as spent
      expect(await utxo.getUTXOAsync(outpoint)).toBeNull();
      expect(await utxo.hasUTXOAsync(outpoint)).toBe(false);
    });
  });

  describe("flush", () => {
    test("persists added UTXOs to database", async () => {
      const txid = Buffer.alloc(32, 0x77);
      const tx = createTestTx(0, 2);
      utxo.addTransaction(txid, tx, 100, false);

      await utxo.flush();

      // Verify in database
      const entry0 = await db.getUTXO(txid, 0);
      const entry1 = await db.getUTXO(txid, 1);

      expect(entry0).not.toBeNull();
      expect(entry0!.amount).toBe(1000n);
      expect(entry1).not.toBeNull();
      expect(entry1!.amount).toBe(2000n);
    });

    test("deletes spent UTXOs from database", async () => {
      const txid = Buffer.alloc(32, 0x88);
      const entry: UTXOEntry = {
        height: 50,
        coinbase: false,
        amount: 3000n,
        scriptPubKey: Buffer.alloc(25),
      };

      // Put directly in database
      await db.putUTXO(txid, 0, entry);

      // Preload and spend
      await utxo.preloadUTXO({ txid, vout: 0 });
      utxo.spendOutput({ txid, vout: 0 });

      await utxo.flush();

      // Verify deleted
      const result = await db.getUTXO(txid, 0);
      expect(result).toBeNull();
    });

    test("clears pending operations after flush", async () => {
      const txid = Buffer.alloc(32, 0x99);
      const tx = createTestTx(0, 1);
      utxo.addTransaction(txid, tx, 100, false);

      expect(utxo.getPendingCount()).toBe(1);
      await utxo.flush();
      expect(utxo.getPendingCount()).toBe(0);
    });
  });

  describe("restoreUTXO and removeUTXO", () => {
    test("restoreUTXO adds UTXO to cache", () => {
      const txid = Buffer.alloc(32, 0xaa);
      const entry: UTXOEntry = {
        height: 25,
        coinbase: false,
        amount: 7500n,
        scriptPubKey: Buffer.alloc(22),
      };

      utxo.restoreUTXO(txid, 0, entry);

      const outpoint: OutPoint = { txid, vout: 0 };
      expect(utxo.hasUTXO(outpoint)).toBe(true);
      expect(utxo.getUTXO(outpoint)!.amount).toBe(7500n);
    });

    test("removeUTXO marks UTXO as spent", () => {
      const txid = Buffer.alloc(32, 0xbb);
      const tx = createTestTx(0, 1);
      utxo.addTransaction(txid, tx, 100, false);

      utxo.removeUTXO(txid, 0);

      expect(utxo.hasUTXO({ txid, vout: 0 })).toBe(false);
    });
  });

  describe("preloadUTXO", () => {
    test("loads UTXO from database into cache", async () => {
      const txid = Buffer.alloc(32, 0xcc);
      const entry: UTXOEntry = {
        height: 150,
        coinbase: false,
        amount: 9999n,
        scriptPubKey: Buffer.alloc(34),
      };

      await db.putUTXO(txid, 0, entry);

      const loaded = await utxo.preloadUTXO({ txid, vout: 0 });
      expect(loaded).toBe(true);

      // Now should be in cache (synchronous access works)
      expect(utxo.hasUTXO({ txid, vout: 0 })).toBe(true);
    });

    test("returns false for non-existent UTXO", async () => {
      const txid = Buffer.alloc(32, 0xdd);
      const loaded = await utxo.preloadUTXO({ txid, vout: 0 });
      expect(loaded).toBe(false);
    });

    test("returns true if already in cache", async () => {
      const txid = Buffer.alloc(32, 0xee);
      const tx = createTestTx(0, 1);
      utxo.addTransaction(txid, tx, 100, false);

      const loaded = await utxo.preloadUTXO({ txid, vout: 0 });
      expect(loaded).toBe(true);
    });

    test("returns false if already spent", async () => {
      const txid = Buffer.alloc(32, 0xff);
      const tx = createTestTx(0, 1);
      utxo.addTransaction(txid, tx, 100, false);
      utxo.spendOutput({ txid, vout: 0 });

      const loaded = await utxo.preloadUTXO({ txid, vout: 0 });
      expect(loaded).toBe(false);
    });
  });

  describe("clearCache", () => {
    test("clears all cached data", () => {
      const txid = Buffer.alloc(32, 0x11);
      const tx = createTestTx(0, 3);
      utxo.addTransaction(txid, tx, 100, false);

      expect(utxo.getCacheSize()).toBe(3);

      utxo.clearCache();

      expect(utxo.getCacheSize()).toBe(0);
      expect(utxo.getPendingCount()).toBe(0);
    });
  });
});

describe("Undo data serialization", () => {
  test("roundtrip serialization of spent UTXOs", () => {
    const spentOutputs: SpentUTXO[] = [
      {
        txid: Buffer.alloc(32, 0xaa),
        vout: 0,
        entry: {
          height: 100,
          coinbase: false,
          amount: 5000n,
          scriptPubKey: Buffer.from([0x76, 0xa9, 0x14, ...Array(20).fill(0x11), 0x88, 0xac]),
        },
      },
      {
        txid: Buffer.alloc(32, 0xbb),
        vout: 2,
        entry: {
          height: 50,
          coinbase: true,
          amount: 50_00000000n,
          scriptPubKey: Buffer.from([0x00, 0x14, ...Array(20).fill(0x22)]),
        },
      },
    ];

    const serialized = serializeUndoData(spentOutputs);
    const deserialized = deserializeUndoData(serialized);

    expect(deserialized.length).toBe(2);

    expect(deserialized[0].txid.equals(spentOutputs[0].txid)).toBe(true);
    expect(deserialized[0].vout).toBe(0);
    expect(deserialized[0].entry.height).toBe(100);
    expect(deserialized[0].entry.coinbase).toBe(false);
    expect(deserialized[0].entry.amount).toBe(5000n);

    expect(deserialized[1].txid.equals(spentOutputs[1].txid)).toBe(true);
    expect(deserialized[1].vout).toBe(2);
    expect(deserialized[1].entry.height).toBe(50);
    expect(deserialized[1].entry.coinbase).toBe(true);
    expect(deserialized[1].entry.amount).toBe(50_00000000n);
  });

  test("handles empty undo data", () => {
    const spentOutputs: SpentUTXO[] = [];

    const serialized = serializeUndoData(spentOutputs);
    const deserialized = deserializeUndoData(serialized);

    expect(deserialized.length).toBe(0);
  });
});
