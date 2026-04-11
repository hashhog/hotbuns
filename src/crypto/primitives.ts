/**
 * Cryptographic primitives: SHA256, RIPEMD160, secp256k1 operations.
 *
 * Uses hardware-accelerated implementations where available:
 * - SHA-256: node:crypto (OpenSSL with SHA-NI/SHA2 acceleration) vs @noble/hashes
 * - secp256k1: @noble/curves with optimized field arithmetic
 *
 * All functions accept and return Buffer for consistency with the rest of the codebase.
 */

import { createHash } from "node:crypto";
import { sha256 as nobleSha256 } from "@noble/hashes/sha2.js";
import { ripemd160 } from "@noble/hashes/legacy.js";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { schnorr } from "@noble/curves/secp256k1.js";

// ============================================================================
// SHA-256 Implementation Selection
// ============================================================================

/** SHA-256 implementation function type */
type Sha256Fn = (data: Buffer | Uint8Array) => Buffer;

/** Currently selected SHA-256 implementation */
let sha256Impl: Sha256Fn;

/** Name of the selected implementation */
let sha256ImplName: string;

/**
 * SHA-256 using node:crypto (BoringSSL, hardware-accelerated on supported CPUs).
 */
function sha256NodeCrypto(data: Buffer | Uint8Array): Buffer {
  return createHash("sha256").update(data).digest() as Buffer;
}

/**
 * SHA-256 using @noble/hashes (portable, pure JS).
 */
function sha256Noble(data: Buffer | Uint8Array): Buffer {
  return Buffer.from(nobleSha256(data));
}

/**
 * Benchmark SHA-256 implementations and select the faster one.
 * Runs at module initialization.
 */
function selectSha256Implementation(): { impl: Sha256Fn; name: string } {
  const testData = Buffer.alloc(64, 0xab);
  const iterations = 10000;

  // Warmup
  for (let i = 0; i < 100; i++) {
    sha256NodeCrypto(testData);
    sha256Noble(testData);
  }

  // Benchmark node:crypto
  const nodeStart = performance.now();
  for (let i = 0; i < iterations; i++) {
    sha256NodeCrypto(testData);
  }
  const nodeTime = performance.now() - nodeStart;

  // Benchmark noble
  const nobleStart = performance.now();
  for (let i = 0; i < iterations; i++) {
    sha256Noble(testData);
  }
  const nobleTime = performance.now() - nobleStart;

  // Select faster implementation
  if (nodeTime <= nobleTime) {
    return { impl: sha256NodeCrypto, name: "node:crypto (hardware-accelerated)" };
  } else {
    return { impl: sha256Noble, name: "@noble/hashes (portable)" };
  }
}

// Initialize SHA-256 implementation at module load
const { impl, name } = selectSha256Implementation();
sha256Impl = impl;
sha256ImplName = name;

/**
 * Get the name of the selected SHA-256 implementation.
 */
export function getSha256Implementation(): string {
  return sha256ImplName;
}

// ============================================================================
// Hash Functions
// ============================================================================

// Cache for tagged hash prefixes (SHA256(tag) || SHA256(tag))
const taggedHashPrefixCache = new Map<string, Buffer>();

/**
 * Single SHA-256 hash. Returns 32-byte Buffer.
 * Uses the fastest available implementation (selected at startup).
 */
export function sha256Hash(data: Buffer): Buffer {
  return sha256Impl(data);
}

/**
 * Double SHA-256: SHA-256(SHA-256(data)).
 * Used for block hashes, txids, and other Bitcoin identifiers.
 */
export function hash256(data: Buffer): Buffer {
  return sha256Impl(sha256Impl(data));
}

/**
 * HASH160: RIPEMD-160(SHA-256(data)).
 * Used for Bitcoin addresses (P2PKH, P2SH).
 */
export function hash160(data: Buffer): Buffer {
  return Buffer.from(ripemd160(sha256Impl(data)));
}

/**
 * Tagged hash for Schnorr/Taproot (BIP-340).
 * Computes: SHA-256(SHA-256(tag) || SHA-256(tag) || msg)
 *
 * Tag hashes are cached for performance.
 */
export function taggedHash(tag: string, msg: Buffer): Buffer {
  let prefix = taggedHashPrefixCache.get(tag);
  if (!prefix) {
    const tagHash = sha256Impl(Buffer.from(tag, "utf-8"));
    prefix = Buffer.concat([tagHash, tagHash]);
    taggedHashPrefixCache.set(tag, prefix);
  }
  return sha256Impl(Buffer.concat([prefix, msg]));
}

// ============================================================================
// Optimized SHA-256 for Merkle Trees
// ============================================================================

/**
 * Pre-allocated buffer pool for Merkle tree computation.
 * Reduces GC pressure during intensive hashing.
 */
class HashBufferPool {
  private pool: Buffer[] = [];
  private readonly maxSize = 64;

  acquire(): Buffer {
    return this.pool.pop() ?? Buffer.alloc(32);
  }

  release(buf: Buffer): void {
    if (this.pool.length < this.maxSize && buf.length === 32) {
      buf.fill(0);
      this.pool.push(buf);
    }
  }

  get size(): number {
    return this.pool.length;
  }
}

/** Global buffer pool for Merkle tree operations */
const merkleBufferPool = new HashBufferPool();

/**
 * Double SHA-256 of a 64-byte block (two concatenated 32-byte hashes).
 * Optimized for Merkle tree internal node computation.
 *
 * This is the most performance-critical operation in block validation.
 * Bitcoin Core calls this "TransformD64" and has SIMD-optimized variants.
 */
export function sha256d64(left: Buffer, right: Buffer): Buffer {
  // Concatenate into a 64-byte block
  const combined = Buffer.alloc(64);
  left.copy(combined, 0, 0, 32);
  right.copy(combined, 32, 0, 32);

  // Double SHA-256
  return sha256Impl(sha256Impl(combined));
}

/**
 * Compute Merkle root from transaction hashes using buffer pooling.
 * Uses bottom-up tree construction with pre-allocated buffers.
 *
 * @param hashes Array of 32-byte transaction hashes (TXIDs or WTXIDs)
 * @returns 32-byte Merkle root
 */
export function computeMerkleRootOptimized(hashes: Buffer[]): Buffer {
  if (hashes.length === 0) {
    return Buffer.alloc(32, 0);
  }

  if (hashes.length === 1) {
    return Buffer.from(hashes[0]);
  }

  // Copy input hashes to avoid modifying the original array
  let level: Buffer<ArrayBuffer>[] = hashes.map((h) => Buffer.from(h));
  const combined = Buffer.alloc(64);

  while (level.length > 1) {
    const nextLevel: Buffer<ArrayBuffer>[] = [];

    for (let i = 0; i < level.length; i += 2) {
      const left = level[i];
      // If odd number, duplicate the last element (Bitcoin Merkle tree rule)
      const right = i + 1 < level.length ? level[i + 1] : level[i];

      // Concatenate into 64-byte block
      left.copy(combined, 0, 0, 32);
      right.copy(combined, 32, 0, 32);

      // Double SHA-256 and reuse buffer from pool
      const result = merkleBufferPool.acquire() as Buffer<ArrayBuffer>;
      const hash = sha256Impl(sha256Impl(combined));
      hash.copy(result, 0, 0, 32);
      nextLevel.push(result);
    }

    // Release buffers from previous level (except first iteration which uses input)
    if (level !== hashes) {
      for (const buf of level) {
        merkleBufferPool.release(buf);
      }
    }

    level = nextLevel;
  }

  return level[0];
}

/**
 * Batch compute multiple double SHA-256 hashes.
 * Useful for signature hashing where multiple sighashes are needed.
 *
 * @param inputs Array of data buffers to hash
 * @returns Array of 32-byte double SHA-256 hashes
 */
export function hash256Batch(inputs: Buffer[]): Buffer[] {
  return inputs.map((input) => sha256Impl(sha256Impl(input)));
}

// ============================================================================
// ECDSA Signature Operations
// ============================================================================

/**
 * Sign a 32-byte message hash with a 32-byte private key.
 * Returns DER-encoded signature.
 */
export function ecdsaSign(msgHash: Buffer, privateKey: Buffer): Buffer {
  if (msgHash.length !== 32) {
    throw new Error(`ecdsaSign: msgHash must be 32 bytes, got ${msgHash.length}`);
  }
  if (privateKey.length !== 32) {
    throw new Error(`ecdsaSign: privateKey must be 32 bytes, got ${privateKey.length}`);
  }
  // Sign with prehash: false since we pass a pre-computed hash
  // format: 'der' returns DER-encoded signature
  const signature = secp256k1.sign(msgHash, privateKey, { prehash: false, format: "der" });
  return Buffer.from(signature);
}

/**
 * Verify a DER-encoded ECDSA signature against a public key and message hash.
 * Uses strict DER parsing (rejects non-canonical encodings).
 */
export function ecdsaVerify(
  signature: Buffer,
  msgHash: Buffer,
  publicKey: Buffer
): boolean {
  try {
    return secp256k1.verify(signature, msgHash, publicKey, { prehash: false, format: "der" });
  } catch {
    return false;
  }
}

/**
 * Lax DER signature parser matching Bitcoin Core's ecdsa_signature_parse_der_lax.
 * Handles non-strict DER encoding (excessive padding, non-minimal lengths, etc.)
 * that OpenSSL historically accepted.
 *
 * Returns {r, s} as bigints, or null if completely unparseable.
 */
function laxDerParse(sig: Buffer): { r: bigint; s: bigint } | null {
  let pos = 0;
  const len = sig.length;

  // Sequence tag
  if (pos >= len || sig[pos] !== 0x30) return null;
  pos++;

  // Sequence length (skip, may be non-minimal)
  if (pos >= len) return null;
  let seqLen = sig[pos++];
  if (seqLen & 0x80) {
    const numBytes = seqLen & 0x7f;
    seqLen = 0;
    for (let i = 0; i < numBytes && pos < len; i++) {
      seqLen = (seqLen << 8) | sig[pos++];
    }
  }

  // Parse R
  if (pos >= len || sig[pos] !== 0x02) return null;
  pos++;

  if (pos >= len) return null;
  let rLen = sig[pos++];
  if (rLen & 0x80) {
    const numBytes = rLen & 0x7f;
    rLen = 0;
    for (let i = 0; i < numBytes && pos < len; i++) {
      rLen = (rLen << 8) | sig[pos++];
    }
  }
  if (pos + rLen > len) return null;

  // Extract R value, skip leading zeros
  let rStart = pos;
  let rEnd = pos + rLen;
  while (rStart < rEnd && sig[rStart] === 0x00) rStart++;
  pos += rLen;

  let r = 0n;
  for (let i = rStart; i < rEnd; i++) {
    r = (r << 8n) | BigInt(sig[i]);
  }

  // Parse S
  if (pos >= len || sig[pos] !== 0x02) return null;
  pos++;

  if (pos >= len) return null;
  let sLen = sig[pos++];
  if (sLen & 0x80) {
    const numBytes = sLen & 0x7f;
    sLen = 0;
    for (let i = 0; i < numBytes && pos < len; i++) {
      sLen = (sLen << 8) | sig[pos++];
    }
  }
  if (pos + sLen > len) return null;

  // Extract S value, skip leading zeros
  let sStart = pos;
  let sEnd = pos + sLen;
  while (sStart < sEnd && sig[sStart] === 0x00) sStart++;

  let s = 0n;
  for (let i = sStart; i < sEnd; i++) {
    s = (s << 8n) | BigInt(sig[i]);
  }

  if (r === 0n || s === 0n) return null;
  return { r, s };
}

/**
 * Re-encode (r, s) bigints into a canonical DER signature.
 */
function encodeStrictDER(r: bigint, s: bigint): Buffer {
  // Convert to minimal big-endian byte arrays
  function bigintToMinBytes(n: bigint): Buffer {
    let hex = n.toString(16);
    if (hex.length % 2 !== 0) hex = '0' + hex;
    const buf = Buffer.from(hex, 'hex');
    // Add leading 0x00 if high bit is set (to keep positive in DER signed integer)
    if (buf[0] & 0x80) {
      return Buffer.concat([Buffer.from([0x00]), buf]);
    }
    return buf;
  }

  const rDer = bigintToMinBytes(r);
  const sDer = bigintToMinBytes(s);
  const totalLen = 2 + rDer.length + 2 + sDer.length;

  return Buffer.concat([
    Buffer.from([0x30, totalLen, 0x02, rDer.length]),
    rDer,
    Buffer.from([0x02, sDer.length]),
    sDer,
  ]);
}

/**
 * Verify an ECDSA signature using lax DER parsing.
 * This matches Bitcoin Core's behavior when SCRIPT_VERIFY_DERSIG is not set:
 * non-strict DER encodings are accepted as long as the (r,s) values are valid.
 * Also handles hybrid pubkeys (0x06/0x07 prefix).
 */
export function ecdsaVerifyLax(
  signature: Buffer,
  msgHash: Buffer,
  publicKey: Buffer
): boolean {
  // Handle hybrid pubkeys (0x06/0x07) by converting to uncompressed (0x04)
  let pk = publicKey;
  if (pk.length === 65 && (pk[0] === 0x06 || pk[0] === 0x07)) {
    pk = Buffer.from(pk);
    pk[0] = 0x04;
  }

  try {
    // Always use lax DER parsing: extract (r,s), re-encode as canonical DER.
    // This handles non-strict DER (extra padding, non-minimal lengths, etc.)
    // that OpenSSL historically accepted.
    // Use lowS: false because high-S signatures are valid in Bitcoin when
    // SCRIPT_VERIFY_LOW_S is not set. The interpreter handles LOW_S enforcement separately.
    const parsed = laxDerParse(signature);
    if (!parsed) return false;
    const strictDer = encodeStrictDER(parsed.r, parsed.s);
    return secp256k1.verify(strictDer, msgHash, pk, { prehash: false, format: "der", lowS: false });
  } catch {
    return false;
  }
}

/**
 * Batch verify multiple ECDSA signatures.
 * Returns an array of booleans indicating which signatures are valid.
 *
 * Note: Currently this is sequential verification. True batch verification
 * requires libsecp256k1 binding with secp256k1_ecdsa_verify in batch.
 * The overhead is still reduced by avoiding individual try/catch blocks.
 */
export function ecdsaVerifyBatch(
  signatures: readonly { signature: Buffer; msgHash: Buffer; publicKey: Buffer }[]
): boolean[] {
  const results: boolean[] = new Array(signatures.length);

  for (let i = 0; i < signatures.length; i++) {
    const { signature, msgHash, publicKey } = signatures[i];
    try {
      results[i] = secp256k1.verify(signature, msgHash, publicKey, { prehash: false, format: "der" });
    } catch {
      results[i] = false;
    }
  }

  return results;
}

// ============================================================================
// Schnorr Signature Operations (Taproot BIP-340)
// ============================================================================

/**
 * Create a Schnorr signature (BIP-340) for Taproot key-path spending.
 *
 * @param msgHash 32-byte message hash (typically sighash)
 * @param privateKey 32-byte private key
 * @param auxRand Optional 32-byte auxiliary randomness (defaults to zeros)
 * @returns 64-byte Schnorr signature
 */
export function schnorrSign(
  msgHash: Buffer,
  privateKey: Buffer,
  auxRand?: Buffer
): Buffer {
  if (msgHash.length !== 32) {
    throw new Error(`schnorrSign: msgHash must be 32 bytes, got ${msgHash.length}`);
  }
  if (privateKey.length !== 32) {
    throw new Error(`schnorrSign: privateKey must be 32 bytes, got ${privateKey.length}`);
  }
  if (auxRand && auxRand.length !== 32) {
    throw new Error(`schnorrSign: auxRand must be 32 bytes, got ${auxRand.length}`);
  }

  const sig = schnorr.sign(msgHash, privateKey, auxRand);
  return Buffer.from(sig);
}

/**
 * Verify a Schnorr signature (BIP-340) for Taproot.
 *
 * @param signature 64-byte Schnorr signature
 * @param msgHash 32-byte message hash
 * @param publicKey 32-byte x-only public key
 * @returns true if signature is valid
 */
export function schnorrVerify(
  signature: Buffer,
  msgHash: Buffer,
  publicKey: Buffer
): boolean {
  try {
    if (signature.length !== 64 || msgHash.length !== 32 || publicKey.length !== 32) {
      return false;
    }
    return schnorr.verify(signature, msgHash, publicKey);
  } catch {
    return false;
  }
}

/**
 * Batch verify multiple Schnorr signatures.
 * Returns an array of booleans indicating which signatures are valid.
 *
 * Note: Noble's schnorr.verify is already optimized. True batch verification
 * (aggregate verification) would require libsecp256k1 binding.
 */
export function schnorrVerifyBatch(
  signatures: readonly { signature: Buffer; msgHash: Buffer; publicKey: Buffer }[]
): boolean[] {
  const results: boolean[] = new Array(signatures.length);

  for (let i = 0; i < signatures.length; i++) {
    const { signature, msgHash, publicKey } = signatures[i];
    try {
      if (signature.length !== 64 || msgHash.length !== 32 || publicKey.length !== 32) {
        results[i] = false;
        continue;
      }
      results[i] = schnorr.verify(signature, msgHash, publicKey);
    } catch {
      results[i] = false;
    }
  }

  return results;
}

// ============================================================================
// Key Operations
// ============================================================================

/**
 * Derive the public key from a 32-byte private key.
 * @param privateKey - 32-byte private key
 * @param compressed - If true (default), returns 33-byte compressed public key.
 *                     If false, returns 65-byte uncompressed public key.
 */
export function privateKeyToPublicKey(
  privateKey: Buffer,
  compressed: boolean = true
): Buffer {
  if (privateKey.length !== 32) {
    throw new Error(
      `privateKeyToPublicKey: privateKey must be 32 bytes, got ${privateKey.length}`
    );
  }
  return Buffer.from(secp256k1.getPublicKey(privateKey, compressed));
}

/**
 * Derive the x-only public key (32 bytes) for Taproot.
 * This is the x-coordinate of the public key point.
 *
 * @param privateKey 32-byte private key
 * @returns 32-byte x-only public key
 */
export function privateKeyToXOnlyPubKey(privateKey: Buffer): Buffer {
  if (privateKey.length !== 32) {
    throw new Error(
      `privateKeyToXOnlyPubKey: privateKey must be 32 bytes, got ${privateKey.length}`
    );
  }
  // schnorr.getPublicKey returns x-only pubkey
  return Buffer.from(schnorr.getPublicKey(privateKey));
}

/**
 * Validate that a private key is a valid secp256k1 scalar.
 * Must be: 0 < key < curve order.
 */
export function isValidPrivateKey(key: Buffer): boolean {
  if (key.length !== 32) {
    return false;
  }
  return secp256k1.utils.isValidSecretKey(key);
}

/**
 * Validate that a public key is a valid point on secp256k1.
 * Accepts both compressed (33-byte) and uncompressed (65-byte) formats.
 */
export function isValidPublicKey(key: Buffer): boolean {
  if (key.length !== 33 && key.length !== 65) {
    return false;
  }
  return secp256k1.utils.isValidPublicKey(key);
}

/**
 * Validate that an x-only public key (32 bytes) is valid.
 * Used for Taproot verification.
 */
export function isValidXOnlyPubKey(key: Buffer): boolean {
  if (key.length !== 32) {
    return false;
  }
  try {
    // Try to lift the x-coordinate to a point
    schnorr.utils.lift_x(BigInt("0x" + key.toString("hex")));
    return true;
  } catch {
    return false;
  }
}

// ============================================================================
// Tweak Operations (Taproot)
// ============================================================================

/**
 * Tweak a private key by adding a scalar.
 * Used for Taproot key tweaking: d' = d + t
 *
 * @param privateKey 32-byte private key
 * @param tweak 32-byte tweak scalar
 * @returns 32-byte tweaked private key
 */
export function tweakPrivateKey(privateKey: Buffer, tweak: Buffer): Buffer {
  if (privateKey.length !== 32) {
    throw new Error(`tweakPrivateKey: privateKey must be 32 bytes`);
  }
  if (tweak.length !== 32) {
    throw new Error(`tweakPrivateKey: tweak must be 32 bytes`);
  }

  // Convert to bigints
  const d = BigInt("0x" + privateKey.toString("hex"));
  const t = BigInt("0x" + tweak.toString("hex"));

  // secp256k1 curve order
  const n = BigInt("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");

  // Add modulo curve order
  const result = (d + t) % n;

  // Convert back to buffer
  const hex = result.toString(16).padStart(64, "0");
  return Buffer.from(hex, "hex");
}

/**
 * Tweak a public key by adding a point.
 * Used for Taproot key tweaking: P' = P + t*G
 *
 * @param publicKey 32-byte x-only public key
 * @param tweak 32-byte tweak scalar
 * @returns 32-byte tweaked x-only public key
 */
export function tweakPublicKey(publicKey: Buffer, tweak: Buffer): Buffer {
  if (publicKey.length !== 32) {
    throw new Error(`tweakPublicKey: publicKey must be 32 bytes`);
  }
  if (tweak.length !== 32) {
    throw new Error(`tweakPublicKey: tweak must be 32 bytes`);
  }

  // Lift x to a point
  const x = BigInt("0x" + publicKey.toString("hex"));
  const P = schnorr.utils.lift_x(x);

  // Convert tweak to bigint
  const t = BigInt("0x" + tweak.toString("hex"));

  // Access Point via schnorr.Point (the Pointk1 class)
  const Point = schnorr.Point;

  // Compute tweak*G (generator point)
  const tG = Point.BASE.multiply(t);

  // Add P + tG
  const tweaked = P.add(tG);

  // Return x-only (32 bytes)
  const xHex = tweaked.x.toString(16).padStart(64, "0");
  return Buffer.from(xHex, "hex");
}

// ============================================================================
// Benchmark Utilities
// ============================================================================

export interface CryptoBenchmarkResult {
  implementation: string;
  sha256ThroughputMBps: number;
  hash256OpsPerSec: number;
  merkleRootTxsPerSec: number;
  ecdsaVerifyOpsPerSec: number;
  schnorrVerifyOpsPerSec: number;
}

/**
 * Run cryptographic benchmarks and return results.
 * Useful for verifying hardware acceleration is working.
 */
export async function runCryptoBenchmarks(
  iterations: number = 10000
): Promise<CryptoBenchmarkResult> {
  // Test data
  const testData64 = Buffer.alloc(64, 0xab);
  const testData1MB = Buffer.alloc(1024 * 1024, 0xcd);

  // SHA-256 throughput (MB/s)
  const sha256Start = performance.now();
  for (let i = 0; i < 100; i++) {
    sha256Impl(testData1MB);
  }
  const sha256Time = performance.now() - sha256Start;
  const sha256ThroughputMBps = (100 * 1) / (sha256Time / 1000);

  // Double SHA-256 ops/sec
  const hash256Start = performance.now();
  for (let i = 0; i < iterations; i++) {
    hash256(testData64);
  }
  const hash256Time = performance.now() - hash256Start;
  const hash256OpsPerSec = (iterations / hash256Time) * 1000;

  // Merkle root throughput (txs/sec)
  const txids: Buffer[] = [];
  for (let i = 0; i < 1000; i++) {
    const txid = Buffer.alloc(32);
    txid.writeUInt32LE(i, 0);
    txids.push(txid);
  }
  const merkleStart = performance.now();
  const merkleIterations = iterations / 10;
  for (let i = 0; i < merkleIterations; i++) {
    computeMerkleRootOptimized(txids);
  }
  const merkleTime = performance.now() - merkleStart;
  const merkleRootTxsPerSec = ((merkleIterations * 1000) / merkleTime) * 1000;

  // ECDSA verify ops/sec
  const privateKey = Buffer.from(
    "0000000000000000000000000000000000000000000000000000000000000001",
    "hex"
  );
  const publicKey = privateKeyToPublicKey(privateKey);
  const msgHash = hash256(Buffer.from("test"));
  const signature = ecdsaSign(msgHash, privateKey);

  const ecdsaIterations = Math.min(1000, iterations / 10);
  const ecdsaStart = performance.now();
  for (let i = 0; i < ecdsaIterations; i++) {
    ecdsaVerify(signature, msgHash, publicKey);
  }
  const ecdsaTime = performance.now() - ecdsaStart;
  const ecdsaVerifyOpsPerSec = (ecdsaIterations / ecdsaTime) * 1000;

  // Schnorr verify ops/sec
  const xOnlyPubKey = privateKeyToXOnlyPubKey(privateKey);
  const schnorrSig = schnorrSign(msgHash, privateKey);

  const schnorrIterations = Math.min(1000, iterations / 10);
  const schnorrStart = performance.now();
  for (let i = 0; i < schnorrIterations; i++) {
    schnorrVerify(schnorrSig, msgHash, xOnlyPubKey);
  }
  const schnorrTime = performance.now() - schnorrStart;
  const schnorrVerifyOpsPerSec = (schnorrIterations / schnorrTime) * 1000;

  return {
    implementation: sha256ImplName,
    sha256ThroughputMBps,
    hash256OpsPerSec,
    merkleRootTxsPerSec,
    ecdsaVerifyOpsPerSec,
    schnorrVerifyOpsPerSec,
  };
}

/**
 * Print crypto benchmark results to console.
 */
export function printCryptoBenchmarks(results: CryptoBenchmarkResult): void {
  console.log("\n=== Crypto Benchmarks ===");
  console.log(`Implementation: ${results.implementation}`);
  console.log(`SHA-256 throughput: ${results.sha256ThroughputMBps.toFixed(1)} MB/s`);
  console.log(`Hash256 (double SHA256): ${Math.round(results.hash256OpsPerSec).toLocaleString()} ops/sec`);
  console.log(`Merkle root: ${Math.round(results.merkleRootTxsPerSec).toLocaleString()} txs/sec`);
  console.log(`ECDSA verify: ${Math.round(results.ecdsaVerifyOpsPerSec).toLocaleString()} ops/sec`);
  console.log(`Schnorr verify: ${Math.round(results.schnorrVerifyOpsPerSec).toLocaleString()} ops/sec`);
}
