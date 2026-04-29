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
 * Given a private key and entropy, produce a 64-byte encoding that is
 * indistinguishable from random data.  Implements
 * `secp256k1_ellswift_create`: pulls (u, branch) values from a tagged-hash
 * PRNG seeded with (compressed pubkey || entropy) and tries
 * `xswiftec_inv_var` until one succeeds (expected ~4 iterations).
 *
 * Reference: bitcoin-core/src/secp256k1/src/modules/ellswift/main_impl.h
 *            secp256k1_ellswift_xelligatorswift_var.
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

  // Compressed pubkey (33 bytes: 0x02/0x03 prefix + x).  The full y-parity
  // determines whether `t` should be flipped at the end so the encoding
  // round-trips back to the original (x, y) point — not just (x, ±y).
  const pubkey = secp256k1.getPublicKey(privateKey, true);
  const xCoord = bufferToFieldElement(Buffer.from(pubkey.slice(1)));
  const yIsOdd = (pubkey[0] & 1) === 1;

  // Tagged-hash PRNG: H_tag("secp256k1_ellswift_encode", pubkey33 || rnd32 || cnt32).
  // Bitcoin Core seeds the hash midstate to the BIP-340 tagged-hash state
  // for "secp256k1_ellswift_encode", writes pubkey33 + rnd32, then for each
  // PRNG call writes a 4-byte counter and finalizes.  We replicate this
  // bit-for-bit so we match Core's encoding output.
  function makePrngSeed(): Buffer {
    // Tag prefix: SHA256("secp256k1_ellswift_encode") || same.
    const tagHash = createHash("sha256")
      .update("secp256k1_ellswift_encode")
      .digest();
    // The state after writing tag||tag (64 bytes) is the BIP-340 tagged
    // hash midstate.  We then write pubkey33 + rnd32 (65 bytes) — the
    // total accumulated input length is 64+65=129 bytes.
    return Buffer.concat([tagHash, tagHash, Buffer.from(pubkey), entropy]);
  }
  const prngBase = makePrngSeed();

  function prng(cnt: number): Buffer {
    const cntBuf = Buffer.alloc(4);
    cntBuf.writeUInt32LE(cnt, 0);
    return createHash("sha256")
      .update(prngBase)
      .update(cntBuf)
      .digest();
  }

  // Pool of 3-bit branch values (cnt=0 generates 64 of them; consumed
  // top-down before the next refill at cnt=65).
  let branchHash: Buffer = prng(0);
  let branchesLeft = 64;
  let cnt = 1;

  // Bound iterations to avoid surprising hangs.  Expected ~4; a 1024-cap
  // gives an astronomically tiny probability of false-failure.
  for (let iter = 0; iter < 1024; iter++) {
    if (branchesLeft === 0) {
      branchHash = prng(cnt);
      cnt++;
      branchesLeft = 64;
    }
    branchesLeft--;
    const idx = branchesLeft >> 1;
    const shift = (branchesLeft & 1) << 2;
    const branch = (branchHash[idx] >> shift) & 7;

    // Pull u32 from the same PRNG (overflow mod p is fine; uniform u32
    // is what matters for indistinguishability).
    const u32 = prng(cnt);
    cnt++;
    const u = mod(bufferToFieldElement(u32), FIELD_PRIME);
    if (u === 0n) continue; // Vanishingly unlikely; skip to keep math clean.

    const t = xswiftecInvVar(xCoord, u, branch);
    if (t === null) continue;

    // Match the y-parity: if t parity differs from y parity, negate t.
    const tIsOdd = (t & 1n) === 1n;
    const tFinal = tIsOdd === yIsOdd ? t : mod(-t, FIELD_PRIME);

    return Buffer.concat([u32, fieldElementToBuffer(tFinal)]);
  }

  // Statistically unreachable for valid inputs.
  throw new Error("ellswiftCreate: PRNG exhausted without finding inverse");
}

/**
 * c1 = (sqrt(-3) - 1) / 2 = 0x851695d4...8e6afa40.
 * Lazily computed once.
 */
let _ellswiftC1: bigint | null = null;
function ellswiftC1(): bigint {
  if (_ellswiftC1 === null) {
    const halfInv = modInverse(2n, FIELD_PRIME);
    _ellswiftC1 = mod((sqrtMinus3() - 1n) * halfInv, FIELD_PRIME);
  }
  return _ellswiftC1;
}

/** c2 = (-sqrt(-3) - 1) / 2. */
let _ellswiftC2: bigint | null = null;
function ellswiftC2(): bigint {
  if (_ellswiftC2 === null) {
    const halfInv = modInverse(2n, FIELD_PRIME);
    _ellswiftC2 = mod((-sqrtMinus3() - 1n) * halfInv, FIELD_PRIME);
  }
  return _ellswiftC2;
}

/** c3 = (-sqrt(-3) + 1) / 2 = -c1. */
function ellswiftC3(): bigint {
  return mod(-ellswiftC1(), FIELD_PRIME);
}

/** c4 = (sqrt(-3) + 1) / 2 = -c2. */
function ellswiftC4(): bigint {
  return mod(-ellswiftC2(), FIELD_PRIME);
}

/**
 * Check whether x is a valid X coordinate on secp256k1 (i.e. x^3 + 7 is a square).
 */
function xOnCurve(x: bigint): boolean {
  return isSquare(fCurve(x));
}

/**
 * Compute the inverse ElligatorSwift partial map: given (x, u, c), return a
 * field element t such that decode(u, t) == x, or null if this branch
 * cannot produce one.  At most one of c in 0..7 will succeed for a given
 * (x, u).  Reference: secp256k1_ellswift_xswiftec_inv_var.
 */
function xswiftecInvVar(x: bigint, u: bigint, c: number): bigint | null {
  let s: bigint;
  let v: bigint;

  if ((c & 2) === 0) {
    // c in {0, 1, 4, 5}.  x1 / x2 branches.

    // If (-u-x) is a valid X coordinate, fail (round-trips to x3 instead).
    const negUX = mod(-(u + x), FIELD_PRIME);
    if (xOnCurve(negUX)) return null;

    // s = -(u^3+7)/(u^2+u*x+x^2).
    const u2 = modPow(u, 2n, FIELD_PRIME);
    const denom = mod(u2 + u * x + modPow(x, 2n, FIELD_PRIME), FIELD_PRIME);
    if (denom === 0n) return null; // Spec proves impossible if -u-x off-curve, but guard.
    const g = mod(modPow(u, 3n, FIELD_PRIME) + 7n, FIELD_PRIME);
    s = mod(-g * modInverse(denom, FIELD_PRIME), FIELD_PRIME);
    if (!isSquare(s)) return null;
    v = x;
  } else {
    // c in {2, 3, 6, 7}.  x3 branch.
    s = mod(x - u, FIELD_PRIME);
    if (!isSquare(s)) return null;

    // r = sqrt(-s*(4*(u^3+7)+3*u^2*s)).  Fail if not a square.
    const u2 = modPow(u, 2n, FIELD_PRIME);
    const u3 = modPow(u, 3n, FIELD_PRIME);
    const inner = mod(4n * (u3 + 7n) + 3n * u2 * s, FIELD_PRIME);
    const q = mod(-s * inner, FIELD_PRIME);
    if (!isSquare(q)) return null;
    const r = modSqrt(q);

    // r=0 with (c & 1)=1 → fail (avoids generating a duplicate output).
    if ((c & 1) === 1 && r === 0n) return null;

    if (s === 0n) return null;

    // v = (r/s - u) / 2.
    const rOverS = mod(r * modInverse(s, FIELD_PRIME), FIELD_PRIME);
    const halfInv = modInverse(2n, FIELD_PRIME);
    v = mod((rOverS - u) * halfInv, FIELD_PRIME);
  }

  // w = sqrt(s).  By construction s is a square at this point.
  const w = modSqrt(s);

  // Sign of w depends on (c & 5):
  //   (c & 5) == 0 || (c & 5) == 5 → m = -w
  //   else                          → m =  w
  const fivebits = c & 5;
  const m = fivebits === 0 || fivebits === 5 ? mod(-w, FIELD_PRIME) : w;

  // u' = (c & 1) ? c4 * u : c3 * u
  const cu = (c & 1) === 1 ? mod(ellswiftC4() * u, FIELD_PRIME) : mod(ellswiftC3() * u, FIELD_PRIME);

  // t = m * (u' + v)
  return mod(m * mod(cu + v, FIELD_PRIME), FIELD_PRIME);
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
