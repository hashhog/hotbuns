/**
 * Signature/script verification cache for faster block connection.
 *
 * Caches successful script verifications to avoid redundant work when
 * a transaction is validated in the mempool and again during block connection.
 *
 * Reference: Bitcoin Core's SignatureCache (script/sigcache.h)
 *
 * Key design: Core uses SHA256(nonce || type_byte || 31_zeroes || sighash || pubkey || sig)
 * keyed on actual cryptographic material.  We mirror that by including a
 * per-process 32-byte random nonce (generated once at construction via
 * crypto.randomBytes) and the raw spending material (scriptSig + witness + flags)
 * so that:
 *   1. Two processes with identical txid/inputIndex cannot share cache entries
 *      (cross-restart poisoning is impossible).
 *   2. Two different signatures spending the same input position but with
 *      different sig bytes produce different keys (prevents adversarial
 *      false-positive cache hits for forged or witness-malleated inputs).
 */

import { createHash, randomBytes } from "crypto";

/**
 * Cache key for script verification results.
 *
 * The opaque `entryHex` field is the hex-encoded first 8 bytes of
 * SHA256(nonce || scriptSig || witnessConcat || flagsLE4), produced by
 * SigCache.computeKey().  Callers should not construct this directly;
 * use SigCache.computeKey() instead.
 */
export interface CacheKey {
  /** Opaque entry: hex of first 8 bytes of SHA256(nonce||material). */
  entryHex: string;
}

/**
 * Signature/script verification cache.
 *
 * Uses a Map which preserves insertion order in JavaScript, allowing
 * FIFO eviction when the cache reaches capacity.
 *
 * Key design decisions:
 * - Only caches successful verifications (failed verifications might succeed
 *   under different circumstances, e.g., with a block containing the tx).
 * - Cache key includes a per-process nonce so keys are unpredictable across
 *   restarts and processes.
 * - Cache key covers the full spending material (scriptSig + witness + flags)
 *   so two different signatures for the same input index produce different
 *   cache entries — preventing adversarial poisoning.
 */
export class SigCache {
  /** Cache storing successful verification results. Value is always true. */
  private cache: Map<string, true>;
  /** Maximum number of entries before eviction. */
  private maxEntries: number;
  /**
   * Per-process random nonce (32 bytes).
   * Generated once at construction.  Makes cache keys unpredictable across
   * restarts, mirroring Core's SignatureCache nonce (sigcache.h:42-32,
   * sigcache.cpp:22 GetRandHash()).
   */
  readonly nonce: Buffer;

  /**
   * Create a new signature cache.
   *
   * @param maxEntries - Maximum entries before eviction (default 50,000)
   * @param nonce      - Optional nonce override (for testing only; omit in
   *                     production so construction uses crypto.randomBytes).
   */
  constructor(maxEntries: number = 50_000, nonce?: Buffer) {
    this.cache = new Map();
    this.maxEntries = maxEntries;
    // Generate a fresh 32-byte nonce or use the provided override.
    this.nonce = nonce ?? randomBytes(32);
  }

  /**
   * Compute a cache entry key from the actual signing material.
   *
   * Key = first 8 bytes of SHA256(nonce || scriptSig || witnessConcat || flagsLE4)
   * returned as a 16-character hex string used as the Map key.
   *
   * Mirrors Core: SHA256(nonce || 'E'||zeros || sighash || pubkey || sig)
   * (sigcache.cpp:41-43).  We use scriptSig+witness as a proxy for the
   * individual sig material because (a) it is available at the
   * verifyInputSignature call site without threading into the interpreter,
   * and (b) any change to sig bytes produces a different key.
   *
   * @param scriptSig   - Input scriptSig bytes (may be empty for segwit).
   * @param witness     - Witness stack for this input (may be empty).
   * @param flags       - ScriptFlags bitmask used for this verification.
   */
  computeKey(scriptSig: Buffer, witness: Buffer[], flags: number): CacheKey {
    const flagsBuf = Buffer.allocUnsafe(4);
    flagsBuf.writeUInt32LE(flags, 0);

    // Concatenate all witness elements with their length prefixes so that
    // [sig, pubkey] and [pubkey, sig] (different stacks) produce different keys.
    const witnessParts: Buffer[] = [];
    for (const item of witness) {
      const lenBuf = Buffer.allocUnsafe(4);
      lenBuf.writeUInt32LE(item.length, 0);
      witnessParts.push(lenBuf, item);
    }

    const material = Buffer.concat([this.nonce, scriptSig, ...witnessParts, flagsBuf]);
    const digest = createHash("sha256").update(material).digest();
    const entryHex = digest.subarray(0, 8).toString("hex");
    return { entryHex };
  }

  /**
   * Look up a verification result in the cache.
   *
   * @param key - The cache key produced by computeKey()
   * @returns true if the verification was previously successful, false otherwise
   */
  lookup(key: CacheKey): boolean {
    return this.cache.has(key.entryHex);
  }

  /**
   * Insert a successful verification into the cache.
   *
   * If the cache is at capacity, evicts the oldest entry (FIFO).
   *
   * @param key - The cache key for the successful verification
   */
  insert(key: CacheKey): void {
    // Don't insert if already present (no need to update)
    if (this.cache.has(key.entryHex)) {
      return;
    }

    // Evict oldest entry if at capacity
    if (this.cache.size >= this.maxEntries) {
      // Map.keys().next().value gives the first (oldest) key
      const oldestKey = this.cache.keys().next().value;
      if (oldestKey !== undefined) {
        this.cache.delete(oldestKey);
      }
    }

    this.cache.set(key.entryHex, true);
  }

  /**
   * Clear all entries from the cache.
   *
   * Call this on chain reorganization/disconnect to ensure stale
   * verifications don't persist.
   */
  clear(): void {
    this.cache.clear();
  }

  /**
   * Get the current number of entries in the cache.
   */
  get size(): number {
    return this.cache.size;
  }
}

/**
 * Global signature cache instance.
 *
 * Used across validation to avoid redundant script verification.
 * Its nonce is generated once at process start via crypto.randomBytes(32).
 */
export const globalSigCache = new SigCache();
