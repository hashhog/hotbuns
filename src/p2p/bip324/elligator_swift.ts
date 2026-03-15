/**
 * ElligatorSwift encoding for secp256k1 public keys (BIP324).
 *
 * ElligatorSwift is an encoding that maps secp256k1 public keys to
 * uniformly random 64-byte arrays, making encrypted connections
 * indistinguishable from random data.
 *
 * Reference: Bitcoin Core src/secp256k1/include/secp256k1_ellswift.h
 */

import { secp256k1 } from "@noble/curves/secp256k1.js";
import { createHash } from "crypto";

/** ElligatorSwift public key size in bytes */
export const ELLSWIFT_PUBLIC_KEY_SIZE = 64;

/** secp256k1 field prime p = 2^256 - 2^32 - 977 */
const FIELD_PRIME = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;

/**
 * Modular arithmetic helpers
 */
function mod(a: bigint, p: bigint): bigint {
  const result = a % p;
  return result >= 0n ? result : result + p;
}

function modPow(base: bigint, exp: bigint, p: bigint): bigint {
  let result = 1n;
  base = mod(base, p);
  while (exp > 0n) {
    if (exp & 1n) {
      result = mod(result * base, p);
    }
    exp >>= 1n;
    base = mod(base * base, p);
  }
  return result;
}

function modInverse(a: bigint, p: bigint): bigint {
  return modPow(a, p - 2n, p);
}

/** Square root of -3 mod p (used in ElligatorSwift formulas) */
function getSqrtMinus3(): bigint {
  return modPow(FIELD_PRIME - 3n, (FIELD_PRIME + 1n) / 4n, FIELD_PRIME);
}

// Lazily initialized constant
let _sqrtMinus3: bigint | null = null;
function sqrtMinus3(): bigint {
  if (_sqrtMinus3 === null) {
    _sqrtMinus3 = getSqrtMinus3();
  }
  return _sqrtMinus3;
}

/**
 * Check if a value is a quadratic residue mod p.
 */
function isSquare(a: bigint): boolean {
  if (a === 0n) return true;
  // Euler's criterion: a^((p-1)/2) == 1 mod p
  return modPow(a, (FIELD_PRIME - 1n) / 2n, FIELD_PRIME) === 1n;
}

/**
 * Compute square root mod p (p ≡ 3 mod 4).
 * Returns the smaller of the two roots.
 */
function modSqrt(a: bigint): bigint {
  const root = modPow(a, (FIELD_PRIME + 1n) / 4n, FIELD_PRIME);
  // Return the "smaller" root (canonical)
  const negRoot = mod(-root, FIELD_PRIME);
  return root < negRoot ? root : negRoot;
}

/**
 * Compute f(x) = x^3 + 7 (the secp256k1 curve equation RHS).
 */
function fCurve(x: bigint): bigint {
  return mod(modPow(x, 3n, FIELD_PRIME) + 7n, FIELD_PRIME);
}

/**
 * Convert a 32-byte buffer to a field element (mod p).
 */
function bufferToFieldElement(buf: Buffer): bigint {
  // Big-endian interpretation
  let value = 0n;
  for (let i = 0; i < 32; i++) {
    value = (value << 8n) | BigInt(buf[i]);
  }
  return mod(value, FIELD_PRIME);
}

/**
 * Convert a field element to a 32-byte buffer (big-endian).
 */
function fieldElementToBuffer(fe: bigint): Buffer {
  const buf = Buffer.alloc(32);
  let value = mod(fe, FIELD_PRIME);
  for (let i = 31; i >= 0; i--) {
    buf[i] = Number(value & 0xffn);
    value >>= 8n;
  }
  return buf;
}

/**
 * Decode an ElligatorSwift-encoded public key to x-coordinate.
 *
 * Given 64 bytes representing (u, t), compute the x-coordinate of the point.
 * Reference: BIP324 / secp256k1_ellswift_xswiftec_inv
 */
export function ellswiftDecode(encoded: Buffer): { x: bigint; parity: number } {
  if (encoded.length !== ELLSWIFT_PUBLIC_KEY_SIZE) {
    throw new Error(`Invalid ElligatorSwift encoding length: ${encoded.length}`);
  }

  const u = bufferToFieldElement(encoded.subarray(0, 32));
  const t = bufferToFieldElement(encoded.subarray(32, 64));

  // u' = u if u != 0, else 1
  const uPrime = u !== 0n ? u : 1n;
  // t' = t if t != 0, else 1
  const tPrime = t !== 0n ? t : 1n;

  const u3 = modPow(uPrime, 3n, FIELD_PRIME);
  const t2 = modPow(tPrime, 2n, FIELD_PRIME);

  // t'' = t' if u'^3 + 7 != -t'^2, else 2*t'
  let tPrimePrime = tPrime;
  if (mod(u3 + 7n + t2, FIELD_PRIME) === 0n) {
    tPrimePrime = mod(2n * tPrime, FIELD_PRIME);
  }

  const t2Prime = modPow(tPrimePrime, 2n, FIELD_PRIME);

  // X = (u'^3 + 7 - t''^2) / (2 * t'')
  const twoTPrime = mod(2n * tPrimePrime, FIELD_PRIME);
  const X = mod((u3 + 7n - t2Prime) * modInverse(twoTPrime, FIELD_PRIME), FIELD_PRIME);

  // Y = (X + t'') / (u' * sqrt(-3))
  const uSqrtM3 = mod(uPrime * sqrtMinus3(), FIELD_PRIME);
  const Y = mod((X + tPrimePrime) * modInverse(uSqrtM3, FIELD_PRIME), FIELD_PRIME);

  // y2 = Y^2
  const Y2 = modPow(Y, 2n, FIELD_PRIME);
  const fourY2 = mod(4n * Y2, FIELD_PRIME);

  // Three potential x values:
  // x1 = u' + 4*Y^2
  // x2 = -X / (2*Y) - u'/2
  // x3 = X / (2*Y) - u'/2
  const x1 = mod(uPrime + fourY2, FIELD_PRIME);

  const twoY = mod(2n * Y, FIELD_PRIME);
  const halfU = mod(uPrime * modInverse(2n, FIELD_PRIME), FIELD_PRIME);
  const xOverTwoY = mod(X * modInverse(twoY, FIELD_PRIME), FIELD_PRIME);
  const negXOverTwoY = mod(-xOverTwoY, FIELD_PRIME);

  const x2 = mod(negXOverTwoY - halfU, FIELD_PRIME);
  const x3 = mod(xOverTwoY - halfU, FIELD_PRIME);

  // Find the first x such that f(x) is a square
  let x: bigint;
  if (isSquare(fCurve(x1))) {
    x = x1;
  } else if (isSquare(fCurve(x2))) {
    x = x2;
  } else {
    x = x3;
  }

  // Compute y and determine parity
  const y = modSqrt(fCurve(x));
  const parity = Number(y & 1n);

  return { x, parity };
}

/**
 * Encode a public key using ElligatorSwift.
 *
 * Given a private key and entropy, produce a 64-byte encoding that
 * is indistinguishable from random data.
 *
 * @param privateKey - 32-byte private key
 * @param entropy - 32-byte entropy for randomization
 * @returns 64-byte ElligatorSwift encoding
 */
export function ellswiftCreate(privateKey: Buffer, entropy: Buffer): Buffer {
  if (privateKey.length !== 32) {
    throw new Error(`Invalid private key length: ${privateKey.length}`);
  }
  if (entropy.length !== 32) {
    throw new Error(`Invalid entropy length: ${entropy.length}`);
  }

  // Get the public key x-coordinate
  const pubkey = secp256k1.getPublicKey(privateKey, true);
  // Extract x-coordinate (skip prefix byte)
  const xCoord = bufferToFieldElement(Buffer.from(pubkey.slice(1)));

  // Use entropy to generate u value
  const u = bufferToFieldElement(entropy);

  // Find a valid t using the inverse ElligatorSwift map
  const { t } = ellswiftInverse(xCoord, u);

  // Return (u, t) as 64 bytes
  return Buffer.concat([fieldElementToBuffer(u), fieldElementToBuffer(t)]);
}

/**
 * Compute the inverse ElligatorSwift map to find t given x and u.
 *
 * This implements the inverse encoding algorithm from BIP324.
 * Reference: secp256k1_ellswift_xswiftec_inv
 */
function ellswiftInverse(x: bigint, u: bigint): { t: bigint } {
  // We need to find t such that decoding (u, t) gives x

  // Try different formula variants (c values 0-7)
  for (let c = 0; c < 8; c++) {
    const result = tryEllswiftInverse(x, u, c);
    if (result !== null) {
      return { t: result };
    }
  }

  // If no t found with this u, use a fallback
  // This shouldn't happen with proper entropy, but handle gracefully
  // Generate a new u by hashing the original
  const newEntropy = createHash("sha256").update(fieldElementToBuffer(u)).digest();
  const newU = bufferToFieldElement(newEntropy);
  return ellswiftInverse(x, newU);
}

/**
 * Try to compute t for a specific formula variant.
 *
 * Reference: secp256k1_ellswift_xswiftec_inv_var
 */
function tryEllswiftInverse(x: bigint, u: bigint, c: number): bigint | null {
  const g = fCurve(x); // g = x^3 + 7
  if (!isSquare(g)) return null;

  // Compute v based on c
  let s: bigint;

  if (c < 4) {
    // Formulas using s = x - u
    s = mod(x - u, FIELD_PRIME);
  } else {
    // Formulas using s = -(x + u)
    s = mod(-(x + u), FIELD_PRIME);
  }

  // c mod 2 determines which branch
  const branch = c & 1;
  // c & 2 determines negation
  const negate = (c & 2) !== 0;

  // Compute d = s^3 - 3*s^2 - s*(4*g + u^2) - g
  const u2 = modPow(u, 2n, FIELD_PRIME);
  const s2 = modPow(s, 2n, FIELD_PRIME);
  const s3 = mod(s2 * s, FIELD_PRIME);

  const fourG = mod(4n * g, FIELD_PRIME);
  const d = mod(s3 - 3n * s2 - s * (fourG + u2) - g, FIELD_PRIME);

  if (d === 0n) {
    // Special case
    if (branch === 0) {
      // t = sqrt(-3) * u
      let t = mod(sqrtMinus3() * u, FIELD_PRIME);
      if (negate) t = mod(-t, FIELD_PRIME);
      return t;
    }
    return null;
  }

  // Check if d/g is a square
  const dOverG = mod(d * modInverse(g, FIELD_PRIME), FIELD_PRIME);
  if (!isSquare(dOverG)) return null;

  // Compute t = (sqrt(d/g) ± sqrt(-d/g)) / 2 + s + u
  const sqrtDG = modSqrt(dOverG);

  let t: bigint;
  if (branch === 0) {
    t = mod(sqrtDG * modInverse(2n, FIELD_PRIME) + s + u, FIELD_PRIME);
  } else {
    t = mod(-sqrtDG * modInverse(2n, FIELD_PRIME) + s + u, FIELD_PRIME);
  }

  if (negate) {
    t = mod(-t, FIELD_PRIME);
  }

  // Verify the result
  const decoded = ellswiftDecode(
    Buffer.concat([fieldElementToBuffer(u), fieldElementToBuffer(t)])
  );

  if (decoded.x === x) {
    return t;
  }

  return null;
}

/**
 * Compute BIP340 tagged hash: SHA256(SHA256(tag) || SHA256(tag) || message)
 */
function taggedHash(tag: string, ...messages: Buffer[]): Buffer {
  const tagHash = createHash("sha256").update(tag).digest();
  const hash = createHash("sha256");
  hash.update(tagHash);
  hash.update(tagHash);
  for (const msg of messages) {
    hash.update(msg);
  }
  return hash.digest();
}

/**
 * Perform ECDH using ElligatorSwift-encoded public keys.
 *
 * Uses the BIP324-specific hash function:
 * H_tag(ell_a64 || ell_b64 || x32) with tag "bip324_ellswift_xonly_ecdh"
 *
 * @param ourPrivateKey - Our 32-byte private key
 * @param theirEllswift - Their 64-byte ElligatorSwift-encoded public key
 * @param ourEllswift - Our 64-byte ElligatorSwift-encoded public key
 * @param initiator - Whether we are the connection initiator
 * @returns 32-byte shared secret
 */
export function ellswiftECDH(
  ourPrivateKey: Buffer,
  theirEllswift: Buffer,
  ourEllswift: Buffer,
  initiator: boolean
): Buffer {
  // Decode their public key to get x-coordinate
  const { x: theirX, parity: theirParity } = ellswiftDecode(theirEllswift);

  // Compute the y-coordinate from x
  const y2 = fCurve(theirX);
  let y = modSqrt(y2);

  // Adjust y based on decoded parity
  if (Number(y & 1n) !== theirParity) {
    y = mod(-y, FIELD_PRIME);
  }

  // Create the full public key point
  const theirPubKey = Buffer.concat([
    Buffer.from([0x04]), // Uncompressed prefix
    fieldElementToBuffer(theirX),
    fieldElementToBuffer(y),
  ]);

  // Perform ECDH using noble/curves
  const sharedPoint = secp256k1.getSharedSecret(ourPrivateKey, theirPubKey, true);

  // Extract x-coordinate of shared point (skip prefix)
  const sharedX = Buffer.from(sharedPoint.slice(1, 33));

  // BIP324 orders keys as: initiator (A) || responder (B) || shared_x
  // party=0 means we are initiator (A), party=1 means we are responder (B)
  const ellA64 = initiator ? ourEllswift : theirEllswift;
  const ellB64 = initiator ? theirEllswift : ourEllswift;

  // Use BIP340 tagged hash with tag "bip324_ellswift_xonly_ecdh"
  return taggedHash("bip324_ellswift_xonly_ecdh", ellA64, ellB64, sharedX);
}

/**
 * EllSwiftPubKey wrapper class for BIP324.
 */
export class EllSwiftPubKey {
  readonly data: Buffer;

  constructor(data: Buffer | Uint8Array) {
    if (data.length !== ELLSWIFT_PUBLIC_KEY_SIZE) {
      throw new Error(`Invalid EllSwiftPubKey size: ${data.length}`);
    }
    this.data = Buffer.from(data);
  }

  static create(privateKey: Buffer, entropy: Buffer): EllSwiftPubKey {
    return new EllSwiftPubKey(ellswiftCreate(privateKey, entropy));
  }

  equals(other: EllSwiftPubKey): boolean {
    return this.data.equals(other.data);
  }
}
