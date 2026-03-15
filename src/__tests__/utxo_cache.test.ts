/**
 * Tests for UTXO cache layer: CoinsView, CoinsViewDB, CoinsViewCache.
 *
 * Tests the multi-layer cache system with dirty/fresh flag optimization
 * following Bitcoin Core's CCoinsViewCache design.
 */

import { describe, test, expect, beforeEach, afterEach } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ChainDB, UTXOEntry } from "../storage/database.js";
import {
  Coin,
  CoinEntry,
  CoinsView,
  CoinsViewDB,
  CoinsViewCache,
  UTXOManager,
} from "../chain/utxo.js";
import type { OutPoint, Transaction } from "../validation/tx.js";

describe("CoinsViewDB", () => {
  let tempDir: string;
  let db: ChainDB;
  let viewDB: CoinsViewDB;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "coins-view-db-test-"));
    db = new ChainDB(tempDir);
    await db.open();
    viewDB = new CoinsViewDB(db);
  });

  afterEach(async () => {
    await db.close();
    await rm(tempDir, { recursive: true, force: true });
  });

  test("getCoin returns null for non-existent coin", async () => {
    const outpoint: OutPoint = {
      txid: Buffer.alloc(32, 0xaa),
      vout: 0,
    };
    const coin = await viewDB.getCoin(outpoint);
    expect(coin).toBeNull();
  });

  test("haveCoin returns false for non-existent coin", async () => {
    const outpoint: OutPoint = {
      txid: Buffer.alloc(32, 0xbb),
      vout: 0,
    };
    const exists = await viewDB.haveCoin(outpoint);
    expect(exists).toBe(false);
  });

  test("getCoin returns coin after database write", async () => {
    const txid = Buffer.alloc(32, 0xcc);
    const entry: UTXOEntry = {
      height: 100,
      coinbase: false,
      amount: 5000n,
      scriptPubKey: Buffer.from([0x76, 0xa9, 0x14, ...Array(20).fill(0x11), 0x88, 0xac]),
    };

    await db.putUTXO(txid, 0, entry);

    const outpoint: OutPoint = { txid, vout: 0 };
    const coin = await viewDB.getCoin(outpoint);

    expect(coin).not.toBeNull();
    expect(coin!.height).toBe(100);
    expect(coin!.isCoinbase).toBe(false);
    expect(coin!.txOut.value).toBe(5000n);
  });

  test("setBestBlock updates best block hash", async () => {
    const hash = Buffer.alloc(32, 0xdd);
    viewDB.setBestBlock(hash);
    const result = await viewDB.getBestBlock();
    expect(result.equals(hash)).toBe(true);
  });

  test("batchWrite persists coins to database", async () => {
    const entries = new Map<string, CoinEntry>();
    const txid = Buffer.alloc(32, 0xee);
    const key = `${txid.toString("hex")}:0`;

    entries.set(key, {
      coin: {
        txOut: { value: 1000n, scriptPubKey: Buffer.from([0x51]) },
        height: 50,
        isCoinbase: true,
      },
      dirty: true,
      fresh: true,
    });

    const hashBlock = Buffer.alloc(32, 0xff);
    await viewDB.batchWrite(entries, hashBlock);

    const outpoint: OutPoint = { txid, vout: 0 };
    const coin = await viewDB.getCoin(outpoint);

    expect(coin).not.toBeNull();
    expect(coin!.height).toBe(50);
    expect(coin!.isCoinbase).toBe(true);
    expect(coin!.txOut.value).toBe(1000n);
  });

  test("batchWrite deletes spent coins (non-fresh)", async () => {
    // First add a coin to DB
    const txid = Buffer.alloc(32, 0x11);
    const entry: UTXOEntry = {
      height: 25,
      coinbase: false,
      amount: 2500n,
      scriptPubKey: Buffer.from([0x00, 0x14, ...Array(20).fill(0x22)]),
    };
    await db.putUTXO(txid, 0, entry);

    // Now mark it as spent in batchWrite
    const entries = new Map<string, CoinEntry>();
    const key = `${txid.toString("hex")}:0`;
    entries.set(key, {
      coin: null, // Spent
      dirty: true,
      fresh: false, // Not fresh = exists in DB = needs delete
    });

    const hashBlock = Buffer.alloc(32, 0x33);
    await viewDB.batchWrite(entries, hashBlock);

    // Verify it's deleted
    const outpoint: OutPoint = { txid, vout: 0 };
    const coin = await viewDB.getCoin(outpoint);
    expect(coin).toBeNull();
  });

  test("batchWrite skips fresh+spent coins (never hit DB)", async () => {
    // A fresh+spent coin never existed in DB, so nothing to delete
    const entries = new Map<string, CoinEntry>();
    const txid = Buffer.alloc(32, 0x44);
    const key = `${txid.toString("hex")}:0`;

    entries.set(key, {
      coin: null, // Spent
      dirty: true,
      fresh: true, // Fresh = never existed in DB
    });

    const hashBlock = Buffer.alloc(32, 0x55);
    // This should not throw and should not delete anything
    await viewDB.batchWrite(entries, hashBlock);

    // The coin was never in DB, so this should still return null
    const outpoint: OutPoint = { txid, vout: 0 };
    const coin = await viewDB.getCoin(outpoint);
    expect(coin).toBeNull();
  });
});

describe("CoinsViewCache", () => {
  let tempDir: string;
  let db: ChainDB;
  let viewDB: CoinsViewDB;
  let cache: CoinsViewCache;

  function createCoin(value: bigint, height: number, isCoinbase: boolean): Coin {
    return {
      txOut: {
        value,
        scriptPubKey: Buffer.from([0x76, 0xa9, 0x14, ...Array(20).fill(0xab), 0x88, 0xac]),
      },
      height,
      isCoinbase,
    };
  }

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "coins-view-cache-test-"));
    db = new ChainDB(tempDir);
    await db.open();
    viewDB = new CoinsViewDB(db);
    cache = new CoinsViewCache(viewDB);
  });

  afterEach(async () => {
    await db.close();
    await rm(tempDir, { recursive: true, force: true });
  });

  describe("addCoin", () => {
    test("adds coin to cache as dirty and fresh", () => {
      const outpoint: OutPoint = { txid: Buffer.alloc(32, 0xaa), vout: 0 };
      const coin = createCoin(5000n, 100, false);

      cache.addCoin(outpoint, coin, false);

      expect(cache.haveCoinInCache(outpoint)).toBe(true);
      expect(cache.getCacheSize()).toBe(1);
      expect(cache.getDirtyCount()).toBe(1);
    });

    test("skips OP_RETURN outputs", () => {
      const outpoint: OutPoint = { txid: Buffer.alloc(32, 0xbb), vout: 0 };
      const coin: Coin = {
        txOut: {
          value: 0n,
          scriptPubKey: Buffer.from([0x6a, 0x04, 0x74, 0x65, 0x73, 0x74]), // OP_RETURN "test"
        },
        height: 50,
        isCoinbase: false,
      };

      cache.addCoin(outpoint, coin, false);

      expect(cache.haveCoinInCache(outpoint)).toBe(false);
      expect(cache.getCacheSize()).toBe(0);
    });

    test("throws on overwrite when possibleOverwrite is false", () => {
      const outpoint: OutPoint = { txid: Buffer.alloc(32, 0xcc), vout: 0 };
      const coin1 = createCoin(1000n, 10, false);
      const coin2 = createCoin(2000n, 20, false);

      cache.addCoin(outpoint, coin1, false);

      expect(() => cache.addCoin(outpoint, coin2, false)).toThrow(
        "overwrite an unspent coin"
      );
    });

    test("allows overwrite when possibleOverwrite is true", () => {
      const outpoint: OutPoint = { txid: Buffer.alloc(32, 0xdd), vout: 0 };
      const coin1 = createCoin(1000n, 10, false);
      const coin2 = createCoin(2000n, 20, true);

      cache.addCoin(outpoint, coin1, false);
      cache.addCoin(outpoint, coin2, true); // Coinbase can overwrite (pre-BIP30)

      const stats = cache.getStats();
      expect(stats.size).toBe(1);
    });
  });

  describe("getCoin", () => {
    test("returns coin from cache (hit)", async () => {
      const outpoint: OutPoint = { txid: Buffer.alloc(32, 0xee), vout: 0 };
      const coin = createCoin(3000n, 75, false);
      cache.addCoin(outpoint, coin, false);

      const result = await cache.getCoin(outpoint);

      expect(result).not.toBeNull();
      expect(result!.txOut.value).toBe(3000n);
      expect(cache.getStats().hits).toBe(1);
      expect(cache.getStats().misses).toBe(0);
    });

    test("fetches from backing store on cache miss", async () => {
      const txid = Buffer.alloc(32, 0xff);
      const entry: UTXOEntry = {
        height: 200,
        coinbase: false,
        amount: 8000n,
        scriptPubKey: Buffer.from([0x51]),
      };
      await db.putUTXO(txid, 0, entry);

      const outpoint: OutPoint = { txid, vout: 0 };
      const result = await cache.getCoin(outpoint);

      expect(result).not.toBeNull();
      expect(result!.txOut.value).toBe(8000n);
      expect(cache.getStats().misses).toBe(1);

      // Should now be cached
      expect(cache.haveCoinInCache(outpoint)).toBe(true);
    });

    test("returns null for non-existent coin", async () => {
      const outpoint: OutPoint = { txid: Buffer.alloc(32, 0x11), vout: 999 };
      const result = await cache.getCoin(outpoint);
      expect(result).toBeNull();
    });
  });

  describe("spendCoin", () => {
    test("spends coin and marks as dirty", async () => {
      const outpoint: OutPoint = { txid: Buffer.alloc(32, 0x22), vout: 0 };
      const coin = createCoin(4000n, 150, false);
      cache.addCoin(outpoint, coin, false);

      // Reset dirty count after add
      const initialDirty = cache.getDirtyCount();

      const moveout: { coin: Coin | null } = { coin: null };
      const success = await cache.spendCoin(outpoint, moveout);

      expect(success).toBe(true);
      expect(moveout.coin).not.toBeNull();
      expect(moveout.coin!.txOut.value).toBe(4000n);
    });

    test("fresh+spent coin is deleted from cache entirely", async () => {
      const outpoint: OutPoint = { txid: Buffer.alloc(32, 0x33), vout: 0 };
      const coin = createCoin(2000n, 80, false);
      cache.addCoin(outpoint, coin, false);

      // The coin is fresh (new in this cache session)
      // After spending, it should be removed entirely (not kept as spent)
      await cache.spendCoin(outpoint);

      expect(cache.getCacheSize()).toBe(0);
    });

    test("non-fresh spent coin remains in cache as spent", async () => {
      // First put a coin in DB
      const txid = Buffer.alloc(32, 0x44);
      const entry: UTXOEntry = {
        height: 90,
        coinbase: false,
        amount: 6000n,
        scriptPubKey: Buffer.from([0x00, 0x14, ...Array(20).fill(0x55)]),
      };
      await db.putUTXO(txid, 0, entry);

      // Fetch it (this caches it as not-fresh)
      const outpoint: OutPoint = { txid, vout: 0 };
      await cache.getCoin(outpoint);

      // Now spend it
      const success = await cache.spendCoin(outpoint);
      expect(success).toBe(true);

      // The entry should still be in cache (as spent, dirty)
      // because it needs to be flushed as a deletion
      expect(cache.getCacheSize()).toBe(1);
      expect(cache.getDirtyCount()).toBe(1);
    });

    test("returns false for already-spent coin", async () => {
      const txid = Buffer.alloc(32, 0x66);
      const entry: UTXOEntry = {
        height: 100,
        coinbase: false,
        amount: 7000n,
        scriptPubKey: Buffer.from([0x51]),
      };
      await db.putUTXO(txid, 0, entry);

      const outpoint: OutPoint = { txid, vout: 0 };
      await cache.spendCoin(outpoint);

      // Try to spend again
      const success = await cache.spendCoin(outpoint);
      expect(success).toBe(false);
    });

    test("returns false for non-existent coin", async () => {
      const outpoint: OutPoint = { txid: Buffer.alloc(32, 0x77), vout: 0 };
      const success = await cache.spendCoin(outpoint);
      expect(success).toBe(false);
    });
  });

  describe("spendCoinSync", () => {
    test("throws if coin not in cache", () => {
      const outpoint: OutPoint = { txid: Buffer.alloc(32, 0x88), vout: 0 };

      expect(() => cache.spendCoinSync(outpoint)).toThrow("not in cache");
    });

    test("spends coin synchronously from cache", () => {
      const outpoint: OutPoint = { txid: Buffer.alloc(32, 0x99), vout: 0 };
      const coin = createCoin(9000n, 250, true);
      cache.addCoin(outpoint, coin, false);

      const moveout: { coin: Coin | null } = { coin: null };
      const success = cache.spendCoinSync(outpoint, moveout);

      expect(success).toBe(true);
      expect(moveout.coin!.txOut.value).toBe(9000n);
      expect(moveout.coin!.isCoinbase).toBe(true);
    });
  });

  describe("flush", () => {
    test("persists dirty coins to database", async () => {
      const outpoint1: OutPoint = { txid: Buffer.alloc(32, 0xaa), vout: 0 };
      const outpoint2: OutPoint = { txid: Buffer.alloc(32, 0xbb), vout: 1 };

      cache.addCoin(outpoint1, createCoin(1000n, 10, false), false);
      cache.addCoin(outpoint2, createCoin(2000n, 20, true), false);

      cache.setBestBlock(Buffer.alloc(32, 0xcc));
      await cache.flush();

      // Cache should be cleared
      expect(cache.getCacheSize()).toBe(0);
      expect(cache.getDirtyCount()).toBe(0);

      // Coins should be in DB
      const coin1 = await viewDB.getCoin(outpoint1);
      const coin2 = await viewDB.getCoin(outpoint2);

      expect(coin1).not.toBeNull();
      expect(coin1!.txOut.value).toBe(1000n);
      expect(coin2).not.toBeNull();
      expect(coin2!.txOut.value).toBe(2000n);
    });

    test("deletes spent coins from database", async () => {
      // Add coin to DB
      const txid = Buffer.alloc(32, 0xdd);
      const entry: UTXOEntry = {
        height: 30,
        coinbase: false,
        amount: 3000n,
        scriptPubKey: Buffer.from([0x52]),
      };
      await db.putUTXO(txid, 0, entry);

      // Fetch and spend
      const outpoint: OutPoint = { txid, vout: 0 };
      await cache.getCoin(outpoint);
      await cache.spendCoin(outpoint);

      // Flush
      cache.setBestBlock(Buffer.alloc(32, 0xee));
      await cache.flush();

      // Verify deleted
      const coin = await viewDB.getCoin(outpoint);
      expect(coin).toBeNull();
    });

    test("fresh+spent coins never touch database", async () => {
      const outpoint: OutPoint = { txid: Buffer.alloc(32, 0xff), vout: 0 };

      // Add and spend before flush
      cache.addCoin(outpoint, createCoin(5000n, 50, false), false);
      await cache.spendCoin(outpoint);

      // The coin entry should be gone from cache (fresh optimization)
      expect(cache.getCacheSize()).toBe(0);

      // Flush shouldn't need to delete anything
      cache.setBestBlock(Buffer.alloc(32, 0x11));
      await cache.flush();

      // DB should have nothing
      const coin = await viewDB.getCoin(outpoint);
      expect(coin).toBeNull();
    });

    test("increments flush count", async () => {
      const initialFlushCount = cache.getStats().flushCount;

      cache.addCoin(
        { txid: Buffer.alloc(32, 0x22), vout: 0 },
        createCoin(100n, 1, false),
        false
      );
      await cache.flush();

      expect(cache.getStats().flushCount).toBe(initialFlushCount + 1);
    });
  });

  describe("sync", () => {
    test("persists dirty coins but keeps cache contents", async () => {
      const outpoint: OutPoint = { txid: Buffer.alloc(32, 0x33), vout: 0 };
      cache.addCoin(outpoint, createCoin(7000n, 70, false), false);

      cache.setBestBlock(Buffer.alloc(32, 0x44));
      await cache.sync();

      // Cache should still have the coin
      expect(cache.haveCoinInCache(outpoint)).toBe(true);
      // But dirty count should be 0
      expect(cache.getDirtyCount()).toBe(0);

      // DB should have it too
      const coin = await viewDB.getCoin(outpoint);
      expect(coin).not.toBeNull();
    });

    test("removes spent entries from cache after sync", async () => {
      // Add to DB
      const txid = Buffer.alloc(32, 0x55);
      await db.putUTXO(txid, 0, {
        height: 80,
        coinbase: false,
        amount: 8000n,
        scriptPubKey: Buffer.from([0x53]),
      });

      // Fetch and spend
      const outpoint: OutPoint = { txid, vout: 0 };
      await cache.getCoin(outpoint);
      await cache.spendCoin(outpoint);

      // Sync
      await cache.sync();

      // The spent entry should be removed from cache
      expect(cache.haveCoinInCache(outpoint)).toBe(false);
      expect(cache.getCacheSize()).toBe(0);
    });
  });

  describe("uncache", () => {
    test("removes non-dirty entries from cache", async () => {
      // Add to DB
      const txid = Buffer.alloc(32, 0x66);
      await db.putUTXO(txid, 0, {
        height: 90,
        coinbase: false,
        amount: 9000n,
        scriptPubKey: Buffer.from([0x54]),
      });

      // Fetch (creates clean cache entry)
      const outpoint: OutPoint = { txid, vout: 0 };
      await cache.getCoin(outpoint);
      expect(cache.haveCoinInCache(outpoint)).toBe(true);

      // Uncache
      cache.uncache(outpoint);
      expect(cache.haveCoinInCache(outpoint)).toBe(false);
    });

    test("keeps dirty entries in cache", () => {
      const outpoint: OutPoint = { txid: Buffer.alloc(32, 0x77), vout: 0 };
      cache.addCoin(outpoint, createCoin(1000n, 10, false), false);

      // Try to uncache dirty entry
      cache.uncache(outpoint);

      // Should still be there
      expect(cache.haveCoinInCache(outpoint)).toBe(true);
    });
  });

  describe("memory management", () => {
    test("tracks memory usage", () => {
      const outpoint: OutPoint = { txid: Buffer.alloc(32, 0x88), vout: 0 };
      const coin = createCoin(10000n, 100, false);

      const initialUsage = cache.getMemoryUsage();
      cache.addCoin(outpoint, coin, false);

      expect(cache.getMemoryUsage()).toBeGreaterThan(initialUsage);
    });

    test("shouldFlush returns true when over limit", () => {
      // Create a cache with tiny limit
      const smallCache = new CoinsViewCache(viewDB, 100); // 100 bytes limit

      // Add coins until we exceed limit
      for (let i = 0; i < 10; i++) {
        const outpoint: OutPoint = { txid: Buffer.alloc(32, i), vout: 0 };
        smallCache.addCoin(outpoint, createCoin(BigInt(i * 1000), i, false), false);
      }

      expect(smallCache.shouldFlush()).toBe(true);
    });
  });

  describe("statistics", () => {
    test("tracks hits and misses", async () => {
      const outpoint1: OutPoint = { txid: Buffer.alloc(32, 0x99), vout: 0 };
      cache.addCoin(outpoint1, createCoin(1000n, 10, false), false);

      // Hit
      await cache.getCoin(outpoint1);
      expect(cache.getStats().hits).toBe(1);
      expect(cache.getStats().misses).toBe(0);

      // Miss
      const outpoint2: OutPoint = { txid: Buffer.alloc(32, 0xaa), vout: 0 };
      await cache.getCoin(outpoint2);
      expect(cache.getStats().hits).toBe(1);
      expect(cache.getStats().misses).toBe(1);
    });

    test("resetStats clears hit/miss counters", async () => {
      const outpoint: OutPoint = { txid: Buffer.alloc(32, 0xbb), vout: 0 };
      cache.addCoin(outpoint, createCoin(1000n, 10, false), false);
      await cache.getCoin(outpoint);

      cache.resetStats();

      expect(cache.getStats().hits).toBe(0);
      expect(cache.getStats().misses).toBe(0);
    });
  });
});

describe("FRESH flag optimization", () => {
  let tempDir: string;
  let db: ChainDB;
  let viewDB: CoinsViewDB;
  let cache: CoinsViewCache;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "fresh-flag-test-"));
    db = new ChainDB(tempDir);
    await db.open();
    viewDB = new CoinsViewDB(db);
    cache = new CoinsViewCache(viewDB);
  });

  afterEach(async () => {
    await db.close();
    await rm(tempDir, { recursive: true, force: true });
  });

  test("coin created and spent before flush never touches DB", async () => {
    const outpoint: OutPoint = { txid: Buffer.alloc(32, 0xcc), vout: 0 };

    // Create coin (FRESH)
    cache.addCoin(
      outpoint,
      {
        txOut: { value: 5000n, scriptPubKey: Buffer.from([0x51]) },
        height: 100,
        isCoinbase: false,
      },
      false
    );

    // Spend it (FRESH coin is removed from cache entirely)
    await cache.spendCoin(outpoint);

    // Verify cache is empty
    expect(cache.getCacheSize()).toBe(0);

    // Flush (should be a no-op)
    cache.setBestBlock(Buffer.alloc(32, 0xdd));
    await cache.flush();

    // Verify DB is empty (coin never hit DB)
    const coin = await viewDB.getCoin(outpoint);
    expect(coin).toBeNull();
  });

  test("coin loaded from DB is not FRESH", async () => {
    // Put coin in DB
    const txid = Buffer.alloc(32, 0xee);
    await db.putUTXO(txid, 0, {
      height: 50,
      coinbase: true,
      amount: 50_00000000n,
      scriptPubKey: Buffer.from([0x52]),
    });

    // Fetch it (creates non-FRESH cache entry)
    const outpoint: OutPoint = { txid, vout: 0 };
    await cache.getCoin(outpoint);

    // Spend it
    await cache.spendCoin(outpoint);

    // Entry should still be in cache (needs to flush deletion)
    expect(cache.getCacheSize()).toBe(1);
    expect(cache.getDirtyCount()).toBe(1);

    // Flush
    cache.setBestBlock(Buffer.alloc(32, 0xff));
    await cache.flush();

    // Verify coin is deleted from DB
    const coin = await viewDB.getCoin(outpoint);
    expect(coin).toBeNull();
  });

  test("re-adding a spent coin with pending flush loses FRESH flag", async () => {
    // Put coin in DB
    const txid = Buffer.alloc(32, 0x11);
    await db.putUTXO(txid, 0, {
      height: 60,
      coinbase: false,
      amount: 6000n,
      scriptPubKey: Buffer.from([0x53]),
    });

    // Fetch and spend
    const outpoint: OutPoint = { txid, vout: 0 };
    await cache.getCoin(outpoint);
    await cache.spendCoin(outpoint);

    // Re-add (simulating reorg scenario)
    cache.addCoin(
      outpoint,
      {
        txOut: { value: 6000n, scriptPubKey: Buffer.from([0x53]) },
        height: 60,
        isCoinbase: false,
      },
      true // possibleOverwrite = true for reorg
    );

    // This coin should NOT be FRESH because the deletion hasn't been flushed
    // If we mark it FRESH and spend it again, we'd lose the original deletion

    // Spend again
    await cache.spendCoin(outpoint);

    // Entry should be in cache (needs to flush deletion to DB)
    // even though it was re-added and re-spent
    expect(cache.getDirtyCount()).toBe(1);
  });
});

describe("UTXOManager (legacy compatibility)", () => {
  let tempDir: string;
  let db: ChainDB;
  let utxo: UTXOManager;

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
    tempDir = await mkdtemp(join(tmpdir(), "utxo-manager-test-"));
    db = new ChainDB(tempDir);
    await db.open();
    utxo = new UTXOManager(db);
  });

  afterEach(async () => {
    await db.close();
    await rm(tempDir, { recursive: true, force: true });
  });

  test("addTransaction adds all outputs", () => {
    const txid = Buffer.alloc(32, 0xaa);
    const tx = createTestTx(0, 3);

    utxo.addTransaction(txid, tx, 100, false);

    expect(utxo.getCacheSize()).toBe(3);
    expect(utxo.hasUTXO({ txid, vout: 0 })).toBe(true);
    expect(utxo.hasUTXO({ txid, vout: 1 })).toBe(true);
    expect(utxo.hasUTXO({ txid, vout: 2 })).toBe(true);
  });

  test("spendOutput returns spent UTXO", () => {
    const txid = Buffer.alloc(32, 0xbb);
    const tx = createTestTx(0, 1);
    utxo.addTransaction(txid, tx, 100, false);

    const outpoint: OutPoint = { txid, vout: 0 };
    const entry = utxo.spendOutput(outpoint);

    expect(entry.amount).toBe(1000n);
    expect(entry.height).toBe(100);
    expect(utxo.hasUTXO(outpoint)).toBe(false);
  });

  test("flush persists to database", async () => {
    const txid = Buffer.alloc(32, 0xcc);
    const tx = createTestTx(0, 2);
    utxo.addTransaction(txid, tx, 100, false);

    await utxo.flush();

    // Clear cache and reload from DB
    utxo.clearCache();

    const entry0 = await utxo.getUTXOAsync({ txid, vout: 0 });
    const entry1 = await utxo.getUTXOAsync({ txid, vout: 1 });

    expect(entry0).not.toBeNull();
    expect(entry0!.amount).toBe(1000n);
    expect(entry1).not.toBeNull();
    expect(entry1!.amount).toBe(2000n);
  });

  test("restoreUTXO adds UTXO back", () => {
    const txid = Buffer.alloc(32, 0xdd);
    utxo.restoreUTXO(txid, 0, {
      height: 50,
      coinbase: true,
      amount: 50_00000000n,
      scriptPubKey: Buffer.from([0x51]),
    });

    expect(utxo.hasUTXO({ txid, vout: 0 })).toBe(true);
  });

  test("spendOutputAsync loads from DB", async () => {
    const txid = Buffer.alloc(32, 0xee);
    await db.putUTXO(txid, 0, {
      height: 75,
      coinbase: false,
      amount: 7500n,
      scriptPubKey: Buffer.from([0x52]),
    });

    const entry = await utxo.spendOutputAsync({ txid, vout: 0 });

    expect(entry.amount).toBe(7500n);
    expect(entry.height).toBe(75);
  });

  test("getStats returns cache statistics", () => {
    const txid = Buffer.alloc(32, 0xff);
    const tx = createTestTx(0, 2);
    utxo.addTransaction(txid, tx, 100, false);

    const stats = utxo.getStats();

    expect(stats.currentSize).toBe(2);
    expect(stats.flushes).toBe(0);
  });

  test("preloadUTXO loads from database", async () => {
    const txid = Buffer.alloc(32, 0x11);
    await db.putUTXO(txid, 0, {
      height: 80,
      coinbase: false,
      amount: 8000n,
      scriptPubKey: Buffer.from([0x53]),
    });

    const loaded = await utxo.preloadUTXO({ txid, vout: 0 });
    expect(loaded).toBe(true);

    // Should now be in cache
    expect(utxo.hasUTXO({ txid, vout: 0 })).toBe(true);
  });

  test("getDirtyCount returns number of dirty entries", () => {
    const txid = Buffer.alloc(32, 0x22);
    const tx = createTestTx(0, 3);

    expect(utxo.getDirtyCount()).toBe(0);

    utxo.addTransaction(txid, tx, 100, false);

    expect(utxo.getDirtyCount()).toBe(3);
  });
});
