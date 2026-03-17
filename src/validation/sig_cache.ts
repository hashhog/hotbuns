/**
 * Signature/script verification cache for faster block connection.
 *
 * Caches successful script verifications to avoid redundant work when
 * a transaction is validated in the mempool and again during block connection.
 *
 * Reference: Bitcoin Core's SignatureCache (script/sigcache.h)
 */

/**
 * Cache key for script verification results.
 */
export interface CacheKey {
  /** Transaction ID (hex string). */
  txid: string;
  /** Input index being verified. */
  inputIndex: number;
  /** Script verification flags used. */
  flags: number;
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
 * - Cache key includes flags to prevent weaker verification from satisfying
 *   a stronger check.
 */
export class SigCache {
  /** Cache storing successful verification results. Value is always true. */
  private cache: Map<string, true>;
  /** Maximum number of entries before eviction. */
  private maxEntries: number;

  /**
   * Create a new signature cache.
   *
   * @param maxEntries - Maximum entries before eviction (default 50,000)
   */
  constructor(maxEntries: number = 50_000) {
    this.cache = new Map();
    this.maxEntries = maxEntries;
  }

  /**
   * Convert a cache key to a string for Map storage.
   */
  private keyToString(key: CacheKey): string {
    return `${key.txid}:${key.inputIndex}:${key.flags}`;
  }

  /**
   * Look up a verification result in the cache.
   *
   * @param key - The cache key to look up
   * @returns true if the verification was previously successful, false otherwise
   */
  lookup(key: CacheKey): boolean {
    const keyStr = this.keyToString(key);
    return this.cache.has(keyStr);
  }

  /**
   * Insert a successful verification into the cache.
   *
   * If the cache is at capacity, evicts the oldest entry (FIFO).
   *
   * @param key - The cache key for the successful verification
   */
  insert(key: CacheKey): void {
    const keyStr = this.keyToString(key);

    // Don't insert if already present (no need to update)
    if (this.cache.has(keyStr)) {
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

    this.cache.set(keyStr, true);
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
 */
export const globalSigCache = new SigCache();
