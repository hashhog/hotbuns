/**
 * Cryptographic primitives: SHA256, RIPEMD160, secp256k1 operations.
 *
 * Uses @noble/hashes for hash functions and @noble/curves for ECC.
 * All functions accept and return Buffer for consistency with the rest of the codebase.
 */

import { sha256 } from "@noble/hashes/sha2.js";
import { ripemd160 } from "@noble/hashes/legacy.js";
import { secp256k1 } from "@noble/curves/secp256k1.js";

// Cache for tagged hash prefixes (SHA256(tag) || SHA256(tag))
const taggedHashPrefixCache = new Map<string, Buffer>();

/**
 * Single SHA-256 hash. Returns 32-byte Buffer.
 */
export function sha256Hash(data: Buffer): Buffer {
  return Buffer.from(sha256(data));
}

/**
 * Double SHA-256: SHA-256(SHA-256(data)).
 * Used for block hashes, txids, and other Bitcoin identifiers.
 */
export function hash256(data: Buffer): Buffer {
  return Buffer.from(sha256(sha256(data)));
}

/**
 * HASH160: RIPEMD-160(SHA-256(data)).
 * Used for Bitcoin addresses (P2PKH, P2SH).
 */
export function hash160(data: Buffer): Buffer {
  return Buffer.from(ripemd160(sha256(data)));
}

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
 * Tagged hash for Schnorr/Taproot (BIP-340).
 * Computes: SHA-256(SHA-256(tag) || SHA-256(tag) || msg)
 *
 * Tag hashes are cached for performance.
 */
export function taggedHash(tag: string, msg: Buffer): Buffer {
  let prefix = taggedHashPrefixCache.get(tag);
  if (!prefix) {
    const tagHash = sha256(Buffer.from(tag, "utf-8"));
    prefix = Buffer.concat([tagHash, tagHash]);
    taggedHashPrefixCache.set(tag, prefix);
  }
  return Buffer.from(sha256(Buffer.concat([prefix, msg])));
}
