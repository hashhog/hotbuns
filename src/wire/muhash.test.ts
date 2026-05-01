/**
 * MuHash3072 tests.
 *
 * Test vectors are pulled from:
 * - bitcoin-core/src/test/crypto_tests.cpp `muhash_tests`
 * - bitcoin-core/test/functional/test_framework/crypto/muhash.py
 *   (the `TestFrameworkMuhash.test_muhash` end-to-end vector)
 *
 * The Python end-to-end vector (Insert(0), Insert(1), Remove(2)) reverses
 * the digest before hex-comparing because Core renders uint256 big-endian
 * in tests; we keep our digest in *byte* (little-endian) order to match
 * `MuHash3072::Finalize` as called from snapshot/coinstats code, which
 * compares raw 32-byte buffers.
 */
import { describe, test, expect } from "bun:test";
import {
  MuHash3072,
  Num3072,
  dataToNum3072,
  modInverse,
  bytesToBigIntLE,
  bigIntToBytesLE,
  MUHASH_MODULUS,
  NUM3072_BYTE_SIZE,
} from "./muhash.js";

/** Helper: little-endian BigInt encoding sanity. */
function leHex(value: bigint, length: number): string {
  return bigIntToBytesLE(value, length).toString("hex");
}

describe("Num3072 / BigInt round-trip", () => {
  test("bytesToBigIntLE / bigIntToBytesLE round-trips", () => {
    const samples = [0n, 1n, 0xffn, 0xffffn, 1n << 100n, MUHASH_MODULUS - 1n];
    for (const v of samples) {
      const bytes = bigIntToBytesLE(v, 384);
      expect(bytesToBigIntLE(bytes)).toBe(v);
    }
  });

  test("Num3072 default value is 1", () => {
    const n = new Num3072();
    expect(n.getValue()).toBe(1n);
    const out = n.toBytes();
    expect(out.length).toBe(NUM3072_BYTE_SIZE);
    // First byte = 0x01, all other bytes = 0x00.
    expect(out[0]).toBe(1);
    for (let i = 1; i < NUM3072_BYTE_SIZE; i++) expect(out[i]).toBe(0);
  });

  test("Num3072 multiply/divide are inverses", () => {
    const a = new Num3072(0x1234567890abcdefn);
    const b = new Num3072(0xdeadbeefcafebaben);
    const original = new Num3072(a.getValue());
    a.multiply(b);
    a.divide(b);
    expect(a.equals(original)).toBe(true);
  });

  test("modInverse * value === 1 mod p", () => {
    const x = (1n << 200n) | 0xabcdefn;
    const inv = modInverse(x, MUHASH_MODULUS);
    expect((x * inv) % MUHASH_MODULUS).toBe(1n);
  });
});

describe("MuHash3072 — Bitcoin Core vector parity", () => {
  /**
   * Vector from `crypto_tests.cpp::muhash_tests` and
   * `test_framework/crypto/muhash.py`:
   *   acc = MuHash3072({0,0,...,0})           // 32 zero bytes
   *   acc *= MuHash3072({1,0,...,0})
   *   acc /= MuHash3072({2,0,...,0})
   *   finalize -> 32-byte digest
   *
   * Core's BOOST_CHECK uses uint256 hex (big-endian); the Python test
   * also compares the *reversed* digest. So our digest in byte order is
   * the byte-reverse of the published hex string.
   */
  const CORE_HEX_BE = "10d312b100cbd32ada024a6646e40d3482fcff103668d2625f10002a607d5863";

  function expectCoreDigest(digest: Buffer): void {
    // Reverse to compare against Core's big-endian uint256 hex string.
    const reversed = Buffer.from(digest).reverse().toString("hex");
    expect(reversed).toBe(CORE_HEX_BE);
  }

  function pad32(first: number): Uint8Array {
    const b = new Uint8Array(32);
    b[0] = first;
    return b;
  }

  test("constructor + multiply + divide path", () => {
    const acc = new MuHash3072(pad32(0));
    acc.multiply(new MuHash3072(pad32(1)));
    acc.divide(new MuHash3072(pad32(2)));
    expectCoreDigest(acc.finalize());
  });

  test("insert + remove path (equivalent to multiply/divide)", () => {
    const acc = new MuHash3072(pad32(0));
    acc.insert(pad32(1));
    acc.remove(pad32(2));
    expectCoreDigest(acc.finalize());
  });

  test("add() alias matches insert()", () => {
    const a = new MuHash3072(pad32(0));
    a.add(pad32(1));
    a.remove(pad32(2));
    expectCoreDigest(a.finalize());
  });

  test("order independence (commutativity)", () => {
    const orderA = new MuHash3072();
    orderA.insert(pad32(0));
    orderA.insert(pad32(1));
    orderA.remove(pad32(2));

    const orderB = new MuHash3072();
    orderB.remove(pad32(2));
    orderB.insert(pad32(1));
    orderB.insert(pad32(0));

    const orderC = new MuHash3072();
    orderC.insert(pad32(1));
    orderC.remove(pad32(2));
    orderC.insert(pad32(0));

    expect(orderA.finalize().equals(orderB.finalize())).toBe(true);
    expect(orderA.finalize().equals(orderC.finalize())).toBe(true);
  });

  test("insert(x).remove(x) is identity (cancels)", () => {
    // Empty multiset finalizes to SHA256(LE_384(1)).
    const empty = new MuHash3072();
    const emptyDigest = empty.finalize();

    const acc = new MuHash3072();
    acc.insert(pad32(7));
    acc.insert(pad32(42));
    acc.remove(pad32(7));
    acc.remove(pad32(42));
    expect(acc.finalize().equals(emptyDigest)).toBe(true);
  });

  test("union via multiply matches sequential inserts", () => {
    const sequential = new MuHash3072();
    sequential.insert(pad32(3));
    sequential.insert(pad32(5));
    sequential.insert(pad32(9));

    const left = new MuHash3072(pad32(3));
    const right = new MuHash3072(pad32(5));
    right.insert(pad32(9));
    left.multiply(right);

    expect(sequential.finalize().equals(left.finalize())).toBe(true);
  });

  test("finalize is idempotent and does not corrupt state", () => {
    const acc = new MuHash3072(pad32(0));
    acc.insert(pad32(1));
    acc.remove(pad32(2));
    const first = acc.finalize();
    const second = acc.finalize();
    expect(first.equals(second)).toBe(true);
    expectCoreDigest(second);
  });

  test("serialize / deserialize round-trip", () => {
    const acc = new MuHash3072(pad32(1));
    acc.insert(pad32(2));
    const ser = acc.serialize();
    expect(ser.length).toBe(2 * NUM3072_BYTE_SIZE);
    const restored = MuHash3072.deserialize(ser);
    expect(restored.finalize().equals(acc.finalize())).toBe(true);
  });
});

describe("MuHash3072 — dataToNum3072", () => {
  test("zero input yields a deterministic 3072-bit value", () => {
    const v = dataToNum3072(new Uint8Array(32));
    // Sanity: must fit in 3072 bits.
    expect(v).toBeLessThan(1n << 3072n);
    expect(v).toBeGreaterThan(0n);
  });

  test("different inputs yield different values", () => {
    const a = dataToNum3072(new Uint8Array([0]));
    const b = dataToNum3072(new Uint8Array([1]));
    expect(a).not.toBe(b);
  });
});

describe("MuHash3072 — empty / overflow edge cases", () => {
  test("empty multiset finalize is stable", () => {
    const a = new MuHash3072();
    const b = new MuHash3072();
    expect(a.finalize().equals(b.finalize())).toBe(true);
  });

  test("Num3072.fromBytes accepts MUHASH_MODULUS - 1", () => {
    const bytes = bigIntToBytesLE(MUHASH_MODULUS - 1n, NUM3072_BYTE_SIZE);
    const n = Num3072.fromBytes(bytes);
    expect(n.getValue()).toBe(MUHASH_MODULUS - 1n);
  });

  test("Num3072.fromBytes reduces values >= MUHASH_MODULUS", () => {
    // 2^3072 - 1 is the max raw value; reduced it becomes 1103716.
    const allFf = new Uint8Array(NUM3072_BYTE_SIZE).fill(0xff);
    const n = Num3072.fromBytes(allFf);
    const expected = ((1n << 3072n) - 1n) % MUHASH_MODULUS;
    expect(n.getValue()).toBe(expected);
    expect(expected).toBe(1103716n);
  });

  test("le hex sanity for value 1", () => {
    expect(leHex(1n, 4)).toBe("01000000");
  });
});
