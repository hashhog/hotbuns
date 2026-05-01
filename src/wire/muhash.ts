/**
 * MuHash3072 — incremental multiset hash over a 3072-bit prime field.
 *
 * Used to commit to the UTXO set (HASH_SERIALIZED) and to validate
 * `loadtxoutset` snapshots against the assumeutxo content hash.
 *
 * MuHash maintains the running value as a fraction (numerator/denominator)
 * so add/remove are both single multiplications; only `finalize()` performs
 * the modular inverse. As multiset operations are commutative *and*
 * associative, the order of inserts/removes does not matter.
 *
 * References:
 * - bitcoin-core/src/crypto/muhash.{h,cpp}
 * - bitcoin-core/test/functional/test_framework/crypto/muhash.py
 * - https://cseweb.ucsd.edu/~mihir/papers/inchash.pdf
 *
 * Implementation note: Bitcoin Core hand-rolls 48×64-bit limb arithmetic
 * for performance. TypeScript has native BigInt so we use it directly —
 * fewer LOC and the produced digests are bit-identical to Core's, as the
 * algorithm is a plain `pow(d, -1, p)` on a 3072-bit safe prime.
 */
import { sha256 as nobleSha256 } from "@noble/hashes/sha2.js";
import { chacha20 } from "@noble/ciphers/chacha.js";

/** Number of bytes in a Num3072 little-endian serialization. */
export const NUM3072_BYTE_SIZE = 384;

/** 2**3072 - 1103717: largest 3072-bit safe prime. Same as Core's MuHash modulus. */
export const MUHASH_MODULUS: bigint = (1n << 3072n) - 1103717n;

/** Pre-allocated zero buffer used as ChaCha20 plaintext when extracting keystream. */
const KEYSTREAM_ZEROS_384 = new Uint8Array(NUM3072_BYTE_SIZE);

/** 12-byte zero nonce — matches Core's `ChaCha20Aligned{key}` (no Seek call). */
const KEYSTREAM_NONCE_12 = new Uint8Array(12);

/**
 * Hash a 32-byte input to a 3072-bit number using 6 ChaCha20 blocks.
 *
 * Mirrors `MuHash3072::ToNum3072` in Core: SHA256 the input, use the digest
 * as the ChaCha20 key with a zero 96-bit nonce, generate 384 keystream bytes
 * (counters 0..5), and interpret them little-endian as a Num3072.
 */
export function dataToNum3072(data: Uint8Array): bigint {
  const hashedKey = nobleSha256(data);
  // chacha20(key, nonce, plaintext) returns plaintext XOR keystream.
  // Plaintext = zero buffer => result = pure keystream.
  const keystream = chacha20(hashedKey, KEYSTREAM_NONCE_12, KEYSTREAM_ZEROS_384);
  return bytesToBigIntLE(keystream);
}

/** Convert a little-endian byte array to a BigInt. */
export function bytesToBigIntLE(bytes: Uint8Array): bigint {
  let result = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) {
    result = (result << 8n) | BigInt(bytes[i]!);
  }
  return result;
}

/** Convert a BigInt to a little-endian byte array of the given length (zero-padded). */
export function bigIntToBytesLE(value: bigint, length: number): Buffer {
  if (value < 0n) {
    throw new Error("bigIntToBytesLE: value must be non-negative");
  }
  const out = Buffer.alloc(length);
  let v = value;
  for (let i = 0; i < length; i++) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  if (v !== 0n) {
    throw new Error(`bigIntToBytesLE: value does not fit in ${length} bytes`);
  }
  return out;
}

/**
 * Modular inverse of `a` modulo `m` using the extended Euclidean algorithm.
 *
 * `m` must be prime (or at least coprime to `a`). For MuHash, `m` is the
 * 3072-bit safe prime, which guarantees an inverse exists for any `a` in
 * `[1, m-1]`.
 */
export function modInverse(a: bigint, m: bigint): bigint {
  if (m <= 0n) throw new Error("modInverse: modulus must be positive");
  let g = m;
  let x = 0n;
  let y = 1n;
  let u = 1n;
  let v = 0n;
  let aa = ((a % m) + m) % m;
  if (aa === 0n) throw new Error("modInverse: zero has no inverse");

  while (aa !== 0n) {
    const q = g / aa;
    const r = g - q * aa;
    const m1 = x - u * q;
    const n1 = y - v * q;
    g = aa;
    aa = r;
    x = u;
    y = v;
    u = m1;
    v = n1;
  }
  if (g !== 1n) throw new Error("modInverse: not coprime");
  return ((x % m) + m) % m;
}

/**
 * Num3072: a 3072-bit unsigned integer modulo `MUHASH_MODULUS`.
 *
 * Stored as a single BigInt for simplicity. All operations keep the value
 * fully reduced in `[0, MUHASH_MODULUS)`.
 */
export class Num3072 {
  /** Reduced value in `[0, MUHASH_MODULUS)`. */
  private value: bigint;

  /** Construct a Num3072 with value 1 (multiplicative identity). */
  constructor(initial: bigint = 1n) {
    this.value = ((initial % MUHASH_MODULUS) + MUHASH_MODULUS) % MUHASH_MODULUS;
  }

  /**
   * Construct a Num3072 from a 384-byte little-endian buffer.
   *
   * Note: Core's `Num3072(bytes)` constructor *does not* reduce mod `MUHASH_MODULUS`;
   * it stores raw limbs and only reduces lazily on overflow during multiplication.
   * For interop we accept any value in `[0, 2^3072)` and reduce eagerly.
   */
  static fromBytes(bytes: Uint8Array): Num3072 {
    if (bytes.length !== NUM3072_BYTE_SIZE) {
      throw new Error(`Num3072.fromBytes: expected ${NUM3072_BYTE_SIZE} bytes, got ${bytes.length}`);
    }
    return new Num3072(bytesToBigIntLE(bytes));
  }

  /** Serialize to a 384-byte little-endian buffer (always reduced). */
  toBytes(): Buffer {
    return bigIntToBytesLE(this.value, NUM3072_BYTE_SIZE);
  }

  /** Multiply this by `other` modulo MUHASH_MODULUS, in place. */
  multiply(other: Num3072): void {
    this.value = (this.value * other.value) % MUHASH_MODULUS;
  }

  /** Divide this by `other` modulo MUHASH_MODULUS, in place. */
  divide(other: Num3072): void {
    const inv = modInverse(other.value, MUHASH_MODULUS);
    this.value = (this.value * inv) % MUHASH_MODULUS;
  }

  /** Replace this value by its modular inverse. */
  invert(): void {
    this.value = modInverse(this.value, MUHASH_MODULUS);
  }

  /** Reset to multiplicative identity (1). */
  setToOne(): void {
    this.value = 1n;
  }

  /** Read-only access to the underlying value. */
  getValue(): bigint {
    return this.value;
  }

  /** Structural equality. */
  equals(other: Num3072): boolean {
    return this.value === other.value;
  }
}

/**
 * MuHash3072 incremental multiset hash.
 *
 *   running_value = product(H(x_i))            [for x_i inserted]
 *                 / product(H(y_j))            [for y_j removed]
 *                 (mod MUHASH_MODULUS)
 *
 *   digest = SHA256(LE_384(running_value))
 *
 * Where `H(z) = LE_384(ChaCha20_keystream(SHA256(z)))` interpreted mod MUHASH_MODULUS.
 *
 * `insert` and `remove` are O(1) BigInt multiplies; `finalize` does one
 * modular inverse + one multiply + one SHA256.
 */
export class MuHash3072 {
  private numerator: Num3072;
  private denominator: Num3072;

  /** The empty multiset. */
  constructor();
  /** Singleton multiset containing `data`. */
  constructor(data: Uint8Array);
  constructor(data?: Uint8Array) {
    this.numerator = new Num3072(1n);
    this.denominator = new Num3072(1n);
    if (data !== undefined) {
      this.numerator = new Num3072(dataToNum3072(data));
    }
  }

  /** Insert one element into the multiset. */
  insert(data: Uint8Array): this {
    this.numerator.multiply(new Num3072(dataToNum3072(data)));
    return this;
  }

  /** Alias for `insert`, mirroring Core's `Add` / Bitcoin Python's naming. */
  add(coinBytes: Uint8Array): this {
    return this.insert(coinBytes);
  }

  /** Remove one element from the multiset. */
  remove(data: Uint8Array): this {
    this.denominator.multiply(new Num3072(dataToNum3072(data)));
    return this;
  }

  /**
   * Multiply `this` by another MuHash3072 (set union).
   *
   * The combined multiset's hash equals the product of the two operands'
   * running values, so we can compute MuHashes in parallel and combine
   * them at the end.
   */
  multiply(other: MuHash3072): this {
    this.numerator.multiply(other.numerator);
    this.denominator.multiply(other.denominator);
    return this;
  }

  /** Divide `this` by another MuHash3072 (set difference). */
  divide(other: MuHash3072): this {
    this.numerator.multiply(other.denominator);
    this.denominator.multiply(other.numerator);
    return this;
  }

  /**
   * Finalize into a 32-byte SHA256 digest.
   *
   * Mirrors Core's `MuHash3072::Finalize`: divides numerator by denominator
   * (combining the running fraction), serializes the result LE in 384 bytes,
   * SHA256s it, and resets the denominator to 1 to keep the object valid for
   * further mutation.
   */
  finalize(): Buffer {
    this.numerator.divide(this.denominator);
    this.denominator.setToOne();
    const bytes = this.numerator.toBytes();
    return Buffer.from(nobleSha256(bytes));
  }

  /**
   * Serialize to 768 bytes: numerator (384) || denominator (384).
   *
   * Matches Core's `SERIALIZE_METHODS(MuHash3072, ...)`. Useful for
   * persisting the in-progress accumulator across runs.
   */
  serialize(): Buffer {
    return Buffer.concat([this.numerator.toBytes(), this.denominator.toBytes()]);
  }

  /** Inverse of `serialize`. */
  static deserialize(bytes: Uint8Array): MuHash3072 {
    if (bytes.length !== 2 * NUM3072_BYTE_SIZE) {
      throw new Error(
        `MuHash3072.deserialize: expected ${2 * NUM3072_BYTE_SIZE} bytes, got ${bytes.length}`
      );
    }
    const m = new MuHash3072();
    m.numerator = Num3072.fromBytes(bytes.subarray(0, NUM3072_BYTE_SIZE));
    m.denominator = Num3072.fromBytes(bytes.subarray(NUM3072_BYTE_SIZE));
    return m;
  }
}
