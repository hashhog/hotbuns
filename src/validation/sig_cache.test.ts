import { describe, expect, test, beforeEach } from "bun:test";
import { SigCache, globalSigCache } from "./sig_cache";

// ---------------------------------------------------------------------------
// Helpers — build CacheKeys using the canonical computeKey() method so that
// tests are not coupled to the internal key format.
// ---------------------------------------------------------------------------

/** Deterministic 32-byte commit so existing tests stay focused on the
 *  scriptSig/witness/flags axes.  Cross-tx replay tests below override
 *  this to vary the commit per call. */
const DEFAULT_COMMIT = Buffer.alloc(32, 0xee);

function makeKey(
  cache: SigCache,
  scriptSigHex: string,
  witnessHex: string[],
  flags: number,
  commit: Buffer = DEFAULT_COMMIT,
) {
  const scriptSig = Buffer.from(scriptSigHex, "hex");
  const witness = witnessHex.map((h) => Buffer.from(h, "hex"));
  return cache.computeKey(commit, scriptSig, witness, flags);
}

describe("sig_cache", () => {
  let cache: SigCache;

  beforeEach(() => {
    cache = new SigCache(100);
  });

  describe("insert and lookup", () => {
    test("lookup returns false for non-existent key", () => {
      const key = makeKey(cache, "aabbcc", [], 0);
      expect(cache.lookup(key)).toBe(false);
    });

    test("lookup returns true after insert", () => {
      const key = makeKey(cache, "aabbcc", [], 0);
      cache.insert(key);
      expect(cache.lookup(key)).toBe(true);
    });

    test("different scriptSigs are stored separately", () => {
      const key1 = makeKey(cache, "aabbcc", [], 0);
      const key2 = makeKey(cache, "ddeeff", [], 0);

      cache.insert(key1);
      expect(cache.lookup(key1)).toBe(true);
      expect(cache.lookup(key2)).toBe(false);
    });

    test("different witness stacks are stored separately", () => {
      const key1 = makeKey(cache, "", ["aabbcc"], 0);
      const key2 = makeKey(cache, "", ["ddeeff"], 0);

      cache.insert(key1);
      expect(cache.lookup(key1)).toBe(true);
      expect(cache.lookup(key2)).toBe(false);
    });

    test("different flags are stored separately", () => {
      const key1 = makeKey(cache, "aabbcc", [], 0);
      const key2 = makeKey(cache, "aabbcc", [], 1);

      cache.insert(key1);
      expect(cache.lookup(key1)).toBe(true);
      expect(cache.lookup(key2)).toBe(false);
    });

    test("inserting same key twice does not increase size", () => {
      const key = makeKey(cache, "aabbcc", [], 0);

      cache.insert(key);
      expect(cache.size).toBe(1);

      cache.insert(key);
      expect(cache.size).toBe(1);
    });
  });

  describe("eviction at max capacity", () => {
    test("evicts oldest entry when at max capacity", () => {
      const smallCache = new SigCache(3);

      const key1 = makeKey(smallCache, "01", [], 0);
      const key2 = makeKey(smallCache, "02", [], 0);
      const key3 = makeKey(smallCache, "03", [], 0);
      const key4 = makeKey(smallCache, "04", [], 0);

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

      const key1 = makeKey(smallCache, "01", [], 0);
      const key2 = makeKey(smallCache, "02", [], 0);
      const key3 = makeKey(smallCache, "03", [], 0);
      const key4 = makeKey(smallCache, "04", [], 0);

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

      const key1 = makeKey(smallCache, "01", [], 0);
      const key2 = makeKey(smallCache, "02", [], 0);

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
      const key1 = makeKey(cache, "01", [], 0);
      const key2 = makeKey(cache, "02", [], 0);

      cache.insert(key1);
      cache.insert(key2);
      expect(cache.size).toBe(2);

      cache.clear();

      expect(cache.size).toBe(0);
      expect(cache.lookup(key1)).toBe(false);
      expect(cache.lookup(key2)).toBe(false);
    });

    test("cache works normally after clear", () => {
      const key = makeKey(cache, "aabb", [], 0);

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
        const k = makeKey(cache, Buffer.from([i]).toString("hex"), [], 0);
        cache.insert(k);
        expect(cache.size).toBe(i + 1);
      }
    });

    test("size respects max capacity", () => {
      const smallCache = new SigCache(5);

      for (let i = 0; i < 10; i++) {
        const k = makeKey(smallCache, Buffer.from([i]).toString("hex"), [], 0);
        smallCache.insert(k);
      }

      expect(smallCache.size).toBe(5);
    });
  });

  describe("realistic usage", () => {
    test("caching multiple inputs of same transaction (different scriptSigs)", () => {
      // In a real tx each input has a distinct scriptSig/witness,
      // so per-input keys are distinct even if flags are the same.
      const flags = 0x1f;
      for (let i = 0; i < 3; i++) {
        const sig = Buffer.alloc(72, i + 1); // distinct per-input signature bytes
        const k = makeKey(cache, sig.toString("hex"), [], flags);
        cache.insert(k);
      }

      // All three should be present
      for (let i = 0; i < 3; i++) {
        const sig = Buffer.alloc(72, i + 1);
        const k = makeKey(cache, sig.toString("hex"), [], flags);
        expect(cache.lookup(k)).toBe(true);
      }

      // Different flags → different keys
      for (let i = 0; i < 3; i++) {
        const sig = Buffer.alloc(72, i + 1);
        const k = makeKey(cache, sig.toString("hex"), [], 0x00);
        expect(cache.lookup(k)).toBe(false);
      }
    });

    test("witness stack entries produce distinct keys from identical scriptSig inputs", () => {
      const legacyKey = makeKey(cache, "deadbeef", [], 7);
      const segwitKey = makeKey(cache, "", ["deadbeef"], 7);
      expect(legacyKey.entryHex).not.toBe(segwitKey.entryHex);
    });
  });

  // ---------------------------------------------------------------------------
  // Nonce hardening tests (W105 BUG-9 root-cause fix)
  // ---------------------------------------------------------------------------

  describe("nonce hardening (W105)", () => {
    test("nonce field is a 32-byte Buffer set at construction", () => {
      const c = new SigCache(100);
      expect(Buffer.isBuffer(c.nonce)).toBe(true);
      expect(c.nonce.length).toBe(32);
    });

    test("two independent SigCache instances have different nonces", () => {
      const c1 = new SigCache(100);
      const c2 = new SigCache(100);
      // Probability of collision is 1/2^256 — effectively impossible
      expect(c1.nonce.toString("hex")).not.toBe(c2.nonce.toString("hex"));
    });

    test("same spending material with different nonces produces different cache keys — cross-restart unpredictability", () => {
      // Simulate two separate process starts (different nonces) for the same tx input.
      const nonce1 = Buffer.alloc(32, 0xaa);
      const nonce2 = Buffer.alloc(32, 0xbb);
      const c1 = new SigCache(100, nonce1);
      const c2 = new SigCache(100, nonce2);

      const scriptSig = Buffer.from("304402dead01", "hex");
      const witness: Buffer[] = [];
      const flags = 7;

      const key1 = c1.computeKey(DEFAULT_COMMIT, scriptSig, witness, flags);
      const key2 = c2.computeKey(DEFAULT_COMMIT, scriptSig, witness, flags);

      // Different nonces → different entry hashes
      expect(key1.entryHex).not.toBe(key2.entryHex);
    });

    test("different sig bytes for same (txid, inputIndex, flags) produce different keys — adversarial poisoning prevented", () => {
      // Adversary scenario: two different signatures at the same input position
      // (e.g. witness malleation, or a replacement transaction with a different sig).
      // Both must have distinct cache entries so a forged sig cannot get a free hit.
      const sig1 = Buffer.alloc(71, 0x01); // valid sig from honest tx
      const sig2 = Buffer.alloc(71, 0x02); // forged/different sig (adversarial)

      const key1 = cache.computeKey(DEFAULT_COMMIT, sig1, [], 7);
      const key2 = cache.computeKey(DEFAULT_COMMIT, sig2, [], 7);

      expect(key1.entryHex).not.toBe(key2.entryHex);

      // Insert the honest sig — adversarial sig must NOT get a hit
      cache.insert(key1);
      expect(cache.lookup(key1)).toBe(true);
      expect(cache.lookup(key2)).toBe(false);
    });

    test("witness stack element order is part of the key — different orderings are distinct", () => {
      const elem1 = Buffer.from("aabb", "hex");
      const elem2 = Buffer.from("ccdd", "hex");

      const keyAB = cache.computeKey(DEFAULT_COMMIT, Buffer.alloc(0), [elem1, elem2], 7);
      const keyBA = cache.computeKey(DEFAULT_COMMIT, Buffer.alloc(0), [elem2, elem1], 7);

      expect(keyAB.entryHex).not.toBe(keyBA.entryHex);
    });

    test("nonce override (constructor second arg) allows deterministic tests", () => {
      const fixedNonce = Buffer.alloc(32, 0x42);
      const c1 = new SigCache(100, fixedNonce);
      const c2 = new SigCache(100, fixedNonce);

      const sig = Buffer.from("abcd", "hex");
      const k1 = c1.computeKey(DEFAULT_COMMIT, sig, [], 3);
      const k2 = c2.computeKey(DEFAULT_COMMIT, sig, [], 3);

      // Same nonce + same material → same key (deterministic)
      expect(k1.entryHex).toBe(k2.entryHex);
    });
  });

  // ---------------------------------------------------------------------------
  // Cross-tx witness-replay attack (W160 BUG-7 root-cause fix)
  // ---------------------------------------------------------------------------

  describe("sighash commitment binding (W160 BUG-7)", () => {
    test("different sighashCommit values produce different keys for identical (scriptSig, witness, flags)", () => {
      // Attack scenario: attacker observes a P2WPKH witness `[sig, pubkey]`
      // on the wire (tx1).  Attacker constructs tx2 spending a DIFFERENT
      // UTXO previously sent to the same pubkey and copies the witness
      // verbatim.  The scriptSig/witness/flags tuple is IDENTICAL across
      // tx1 and tx2 — only the per-tx sighash commitment differs.
      // Without the sighash in the cache key, tx2 would get a false-positive
      // hit and skip interpreter verification entirely.
      const sig = Buffer.from("3044deadbeef01", "hex");
      const pubkey = Buffer.alloc(33, 0x02);
      const scriptSig = Buffer.alloc(0);
      const witness = [sig, pubkey];
      const flags = 7;

      const commitTx1 = Buffer.alloc(32, 0xaa); // tx1 sighash commitment
      const commitTx2 = Buffer.alloc(32, 0xbb); // tx2 sighash commitment (different tx)

      const keyTx1 = cache.computeKey(commitTx1, scriptSig, witness, flags);
      const keyTx2 = cache.computeKey(commitTx2, scriptSig, witness, flags);

      // Keys MUST differ — otherwise the cross-tx replay attack succeeds.
      expect(keyTx1.entryHex).not.toBe(keyTx2.entryHex);

      // Insert tx1 success → tx2 must still miss the cache (interpreter
      // must run and reject the replay).
      cache.insert(keyTx1);
      expect(cache.lookup(keyTx1)).toBe(true);
      expect(cache.lookup(keyTx2)).toBe(false);
    });

    test("different pubkey commitments produce different keys for identical witness", () => {
      // Belt-and-braces: two different (sighash, pubkey) combos with the
      // same surface witness must produce different keys.
      const witness = [Buffer.from("304401aa", "hex"), Buffer.alloc(33, 0x02)];
      const commit1 = Buffer.alloc(32, 0x11);
      const commit2 = Buffer.alloc(32, 0x22);

      const k1 = cache.computeKey(commit1, Buffer.alloc(0), witness, 7);
      const k2 = cache.computeKey(commit2, Buffer.alloc(0), witness, 7);

      expect(k1.entryHex).not.toBe(k2.entryHex);
    });

    test("computeKey rejects non-32-byte sighashCommit", () => {
      // Defense-in-depth: refuse to compute a key with an under/over-sized
      // commit since that would silently weaken the cache binding.
      const short = Buffer.alloc(31, 0x00);
      const long = Buffer.alloc(33, 0x00);
      expect(() => cache.computeKey(short, Buffer.alloc(0), [], 0)).toThrow(
        /must be 32 bytes/,
      );
      expect(() => cache.computeKey(long, Buffer.alloc(0), [], 0)).toThrow(
        /must be 32 bytes/,
      );
    });

    test("identical sighashCommit + identical witness → same key (cache HIT path still works)", () => {
      // Sanity: the cache must STILL hit when the same (tx, input) is
      // verified twice (mempool ATMP, then block-connect re-verify).
      const commit = Buffer.alloc(32, 0x55);
      const witness = [Buffer.from("304402aabb", "hex"), Buffer.alloc(33, 0x03)];

      const k1 = cache.computeKey(commit, Buffer.alloc(0), witness, 7);
      const k2 = cache.computeKey(commit, Buffer.alloc(0), witness, 7);

      expect(k1.entryHex).toBe(k2.entryHex);
      cache.insert(k1);
      expect(cache.lookup(k2)).toBe(true);
    });
  });

  describe("globalSigCache", () => {
    test("global cache is a SigCache instance", () => {
      expect(globalSigCache).toBeInstanceOf(SigCache);
    });

    test("global cache has a 32-byte nonce set at module load time", () => {
      expect(Buffer.isBuffer(globalSigCache.nonce)).toBe(true);
      expect(globalSigCache.nonce.length).toBe(32);
    });

    test("global cache can store and retrieve entries", () => {
      globalSigCache.clear();

      const sig = Buffer.from("deadbeef" + Date.now().toString(16).padStart(16, "0"), "hex");
      const key = globalSigCache.computeKey(DEFAULT_COMMIT, sig, [], 0);

      expect(globalSigCache.lookup(key)).toBe(false);
      globalSigCache.insert(key);
      expect(globalSigCache.lookup(key)).toBe(true);

      // Clean up
      globalSigCache.clear();
    });
  });
});
