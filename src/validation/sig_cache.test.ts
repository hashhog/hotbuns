import { describe, expect, test, beforeEach } from "bun:test";
import { SigCache, CacheKey, globalSigCache } from "./sig_cache";

describe("sig_cache", () => {
  let cache: SigCache;

  beforeEach(() => {
    cache = new SigCache(100);
  });

  describe("insert and lookup", () => {
    test("lookup returns false for non-existent key", () => {
      const key: CacheKey = {
        txid: "abc123",
        inputIndex: 0,
        flags: 0,
      };
      expect(cache.lookup(key)).toBe(false);
    });

    test("lookup returns true after insert", () => {
      const key: CacheKey = {
        txid: "abc123",
        inputIndex: 0,
        flags: 0,
      };
      cache.insert(key);
      expect(cache.lookup(key)).toBe(true);
    });

    test("different txids are stored separately", () => {
      const key1: CacheKey = { txid: "abc123", inputIndex: 0, flags: 0 };
      const key2: CacheKey = { txid: "def456", inputIndex: 0, flags: 0 };

      cache.insert(key1);
      expect(cache.lookup(key1)).toBe(true);
      expect(cache.lookup(key2)).toBe(false);
    });

    test("different input indices are stored separately", () => {
      const key1: CacheKey = { txid: "abc123", inputIndex: 0, flags: 0 };
      const key2: CacheKey = { txid: "abc123", inputIndex: 1, flags: 0 };

      cache.insert(key1);
      expect(cache.lookup(key1)).toBe(true);
      expect(cache.lookup(key2)).toBe(false);
    });

    test("different flags are stored separately", () => {
      const key1: CacheKey = { txid: "abc123", inputIndex: 0, flags: 0 };
      const key2: CacheKey = { txid: "abc123", inputIndex: 0, flags: 1 };

      cache.insert(key1);
      expect(cache.lookup(key1)).toBe(true);
      expect(cache.lookup(key2)).toBe(false);
    });

    test("inserting same key twice does not increase size", () => {
      const key: CacheKey = { txid: "abc123", inputIndex: 0, flags: 0 };

      cache.insert(key);
      expect(cache.size).toBe(1);

      cache.insert(key);
      expect(cache.size).toBe(1);
    });
  });

  describe("eviction at max capacity", () => {
    test("evicts oldest entry when at max capacity", () => {
      // Create cache with max 3 entries
      const smallCache = new SigCache(3);

      const key1: CacheKey = { txid: "tx1", inputIndex: 0, flags: 0 };
      const key2: CacheKey = { txid: "tx2", inputIndex: 0, flags: 0 };
      const key3: CacheKey = { txid: "tx3", inputIndex: 0, flags: 0 };
      const key4: CacheKey = { txid: "tx4", inputIndex: 0, flags: 0 };

      smallCache.insert(key1);
      smallCache.insert(key2);
      smallCache.insert(key3);

      expect(smallCache.size).toBe(3);
      expect(smallCache.lookup(key1)).toBe(true);
      expect(smallCache.lookup(key2)).toBe(true);
      expect(smallCache.lookup(key3)).toBe(true);

      // Insert fourth key, should evict first
      smallCache.insert(key4);

      expect(smallCache.size).toBe(3);
      expect(smallCache.lookup(key1)).toBe(false); // evicted
      expect(smallCache.lookup(key2)).toBe(true);
      expect(smallCache.lookup(key3)).toBe(true);
      expect(smallCache.lookup(key4)).toBe(true);
    });

    test("FIFO eviction order is maintained", () => {
      const smallCache = new SigCache(2);

      const key1: CacheKey = { txid: "tx1", inputIndex: 0, flags: 0 };
      const key2: CacheKey = { txid: "tx2", inputIndex: 0, flags: 0 };
      const key3: CacheKey = { txid: "tx3", inputIndex: 0, flags: 0 };
      const key4: CacheKey = { txid: "tx4", inputIndex: 0, flags: 0 };

      smallCache.insert(key1);
      smallCache.insert(key2);
      // [key1, key2]

      smallCache.insert(key3);
      // [key2, key3] - key1 evicted

      expect(smallCache.lookup(key1)).toBe(false);
      expect(smallCache.lookup(key2)).toBe(true);
      expect(smallCache.lookup(key3)).toBe(true);

      smallCache.insert(key4);
      // [key3, key4] - key2 evicted

      expect(smallCache.lookup(key2)).toBe(false);
      expect(smallCache.lookup(key3)).toBe(true);
      expect(smallCache.lookup(key4)).toBe(true);
    });

    test("re-inserting existing key does not cause eviction", () => {
      const smallCache = new SigCache(2);

      const key1: CacheKey = { txid: "tx1", inputIndex: 0, flags: 0 };
      const key2: CacheKey = { txid: "tx2", inputIndex: 0, flags: 0 };

      smallCache.insert(key1);
      smallCache.insert(key2);
      expect(smallCache.size).toBe(2);

      // Re-insert key1 (already exists)
      smallCache.insert(key1);

      // Both should still be present
      expect(smallCache.size).toBe(2);
      expect(smallCache.lookup(key1)).toBe(true);
      expect(smallCache.lookup(key2)).toBe(true);
    });
  });

  describe("clear", () => {
    test("clear empties the cache", () => {
      const key1: CacheKey = { txid: "tx1", inputIndex: 0, flags: 0 };
      const key2: CacheKey = { txid: "tx2", inputIndex: 0, flags: 0 };

      cache.insert(key1);
      cache.insert(key2);
      expect(cache.size).toBe(2);

      cache.clear();

      expect(cache.size).toBe(0);
      expect(cache.lookup(key1)).toBe(false);
      expect(cache.lookup(key2)).toBe(false);
    });

    test("cache works normally after clear", () => {
      const key: CacheKey = { txid: "tx1", inputIndex: 0, flags: 0 };

      cache.insert(key);
      cache.clear();
      expect(cache.lookup(key)).toBe(false);

      cache.insert(key);
      expect(cache.lookup(key)).toBe(true);
    });
  });

  describe("size", () => {
    test("size starts at 0", () => {
      expect(cache.size).toBe(0);
    });

    test("size increases with inserts", () => {
      for (let i = 0; i < 10; i++) {
        cache.insert({ txid: `tx${i}`, inputIndex: 0, flags: 0 });
        expect(cache.size).toBe(i + 1);
      }
    });

    test("size respects max capacity", () => {
      const smallCache = new SigCache(5);

      for (let i = 0; i < 10; i++) {
        smallCache.insert({ txid: `tx${i}`, inputIndex: 0, flags: 0 });
      }

      expect(smallCache.size).toBe(5);
    });
  });

  describe("realistic usage", () => {
    test("caching multiple inputs of same transaction", () => {
      const txid = "deadbeef1234567890abcdef";

      // Insert verifications for 3 inputs with same flags
      for (let i = 0; i < 3; i++) {
        cache.insert({ txid, inputIndex: i, flags: 0x1f });
      }

      // All should be cached
      for (let i = 0; i < 3; i++) {
        expect(cache.lookup({ txid, inputIndex: i, flags: 0x1f })).toBe(true);
      }

      // Different flags should not be cached
      for (let i = 0; i < 3; i++) {
        expect(cache.lookup({ txid, inputIndex: i, flags: 0x00 })).toBe(false);
      }
    });

    test("64-character hex txid works correctly", () => {
      const txid = "a".repeat(64);
      const key: CacheKey = { txid, inputIndex: 5, flags: 255 };

      cache.insert(key);
      expect(cache.lookup(key)).toBe(true);
    });
  });

  describe("globalSigCache", () => {
    test("global cache is a SigCache instance", () => {
      expect(globalSigCache).toBeInstanceOf(SigCache);
    });

    test("global cache can store and retrieve entries", () => {
      const key: CacheKey = {
        txid: "global_test_tx_" + Date.now(),
        inputIndex: 0,
        flags: 0,
      };

      // Clear any existing entry
      globalSigCache.clear();

      expect(globalSigCache.lookup(key)).toBe(false);
      globalSigCache.insert(key);
      expect(globalSigCache.lookup(key)).toBe(true);

      // Clean up
      globalSigCache.clear();
    });
  });
});
