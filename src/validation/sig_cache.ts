/**
 * Signature/script verification cache for faster block connection.
 *
 * Caches successful script verifications to avoid redundant work when
 * a transaction is validated in the mempool and again during block connection.
 *
 * Reference: Bitcoin Core's SignatureCache (script/sigcache.h, sigcache.cpp:39-50)
 *
 * Key design: Core keys each cached signature on the triple
 *   SHA256(nonce || type_byte || 31_zeroes || sighash || pubkey || sig)
 * where `sighash` is the actual 32-byte digest the secp256k1 verifier checked
 * the signature against.  Including the sighash is REQUIRED for security:
 * two different transactions can carry the SAME (sig, pubkey) witness — an
 * attacker who observes a P2WPKH `<sig, pubkey>` on the wire can copy that
 * exact witness into a different tx spending another UTXO previously sent to
 * the same pubkey.  The sig is RFC-6979-bound to tx1's sighash and would fail
 * the interpreter against tx2's sighash, but if the cache key omits the
 * sighash the second tx gets a cache hit and bypasses verification entirely
 * (W160 BUG-7 / fleet-wide pattern).
 *
 * Hotbuns caches at per-input granularity (not per-signature), so we bind the
 * cache key to a "sighash commitment" that fully determines every per-input
 * sighash for this tx: the spending txid, input index, prevout, prev amount,
 * and prev scriptPubKey.  Any two different (tx, input) combinations produce
 * a different commitment → cache miss → interpreter actually runs.  This is
 * semantically equivalent to Core's per-signature (sighash, pubkey, sig)
 * triple: pubkey + sig are embedded in the scriptSig/witness bytes already
 * present in the key, and the commitment fully determines the sighash.
 *
 * The 32-byte per-process random nonce (generated once at construction via
 * crypto.randomBytes) prevents cross-restart poisoning.
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
   * Compute a cache entry key from the actual signing material PLUS a
   * sighash commitment that binds the entry to the specific spending
   * transaction + input + prevout context.
   *
   * Key = first 8 bytes of SHA256(
   *         nonce ||
   *         sighashCommit ||   // 32-byte binding to (tx, inputIndex, prevout, amount, scriptPubKey)
   *         scriptSig ||
   *         witnessConcat ||
   *         flagsLE4)
   * returned as a 16-character hex string used as the Map key.
   *
   * Mirrors Core's per-signature key SHA256(nonce || 'E'||zeros || sighash ||
   * pubkey || sig) at sigcache.cpp:39-50.  Hotbuns caches at per-input
   * granularity so the sighashCommit is a binding to the full set of inputs
   * to the sighash algorithm; pubkey + sig are inside scriptSig/witness.
   *
   * @param sighashCommit - 32-byte commitment to (txid, inputIndex, prevout,
   *                        amount, scriptPubKey). REQUIRED — without it
   *                        a copied witness from another tx would get a
   *                        false-positive cache hit (W160 BUG-7).
   * @param scriptSig     - Input scriptSig bytes (may be empty for segwit).
   * @param witness       - Witness stack for this input (may be empty).
   * @param flags         - ScriptFlags bitmask used for this verification.
   */
  computeKey(
    sighashCommit: Buffer,
    scriptSig: Buffer,
    witness: Buffer[],
    flags: number,
  ): CacheKey {
    if (sighashCommit.length !== 32) {
      throw new Error(
        `SigCache.computeKey: sighashCommit must be 32 bytes, got ${sighashCommit.length}`,
      );
    }

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

    const material = Buffer.concat([
      this.nonce,
      sighashCommit,
      scriptSig,
      ...witnessParts,
      flagsBuf,
    ]);
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
