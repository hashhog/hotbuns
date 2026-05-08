/**
 * BIP-32 spec-edge-case retry tests.
 *
 * Covers W23 fix: hotbuns CKD_priv must skip the rare cases
 *   parse256(IL) >= n   OR   k_i == 0
 * and retry with index+1, per the BIP-32 spec:
 *   "In case parse256(IL) >= n or k_i = 0, the resulting key is invalid,
 *    and one should proceed with the next value for i."
 *
 * Probability of each case is ~2^-127 with real HMAC-SHA512, so we cannot
 * trigger them deterministically against the real KDF. Instead we unit-test
 * the pure BIP-32 math helper `bip32CkdPrivFromI` with hand-crafted `I`
 * values that hit each invalid case, and we exercise the happy path +
 * BIP-32 vector 1 regression via the public Wallet API.
 */

import { describe, expect, test, beforeEach, afterEach } from "bun:test";
import { rmSync, mkdirSync } from "fs";
import { hmac } from "@noble/hashes/hmac.js";
import { sha512 } from "@noble/hashes/sha2.js";

import {
  Wallet,
  type WalletConfig,
  Bip32InvalidChildError,
  bip32CkdPrivFromI,
} from "./wallet";

const TEST_DATADIR = "/tmp/hotbuns-bip32-test";

// secp256k1 curve order, n
const N = BigInt(
  "0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"
);

function hexToBuf(hex: string): Buffer {
  return Buffer.from(hex.replace(/\s+/g, ""), "hex");
}

function bufN(value: bigint): Buffer {
  let h = value.toString(16);
  if (h.length > 64) throw new Error("value > 256 bits");
  h = h.padStart(64, "0");
  return Buffer.from(h, "hex");
}

/** Build a 64-byte I = IL || IR with chosen IL bigint and arbitrary IR. */
function makeI(IL: bigint, IRHex: string): Buffer {
  const ir = hexToBuf(IRHex.padStart(64, "0"));
  return Buffer.concat([bufN(IL), ir]);
}

describe("Bip32InvalidChildError detection (pure helper)", () => {
  // A non-zero parent key, value chosen arbitrarily.
  const parentKey = hexToBuf(
    "1111111111111111111111111111111111111111111111111111111111111111"
  );
  const fakeIR =
    "abababababababababababababababababababababababababababababababab";

  test("happy path: IL < n and child non-zero produces 32-byte key + 32-byte chaincode", () => {
    const I = makeI(2n, fakeIR);
    const { key, chainCode } = bip32CkdPrivFromI(parentKey, I, 0);
    expect(key.length).toBe(32);
    expect(chainCode.length).toBe(32);
    // child = parent + 2 (mod n) — sanity
    const expected = bufN(
      (BigInt("0x" + parentKey.toString("hex")) + 2n) % N
    );
    expect(key.equals(expected)).toBe(true);
    // chainCode preserved from IR
    expect(chainCode.toString("hex")).toBe(fakeIR);
  });

  test("IL == n triggers Bip32InvalidChildError(il-overflow)", () => {
    const I = makeI(N, fakeIR);
    expect(() => bip32CkdPrivFromI(parentKey, I, 5)).toThrow(
      Bip32InvalidChildError
    );
    try {
      bip32CkdPrivFromI(parentKey, I, 5);
    } catch (e) {
      expect(e).toBeInstanceOf(Bip32InvalidChildError);
      expect((e as Bip32InvalidChildError).index).toBe(5);
      expect((e as Error).message).toContain("il-overflow");
    }
  });

  test("IL == n+1 also overflow", () => {
    const I = makeI(N + 1n, fakeIR);
    expect(() => bip32CkdPrivFromI(parentKey, I, 7)).toThrow(
      Bip32InvalidChildError
    );
  });

  test("IL == 2^256 - 1 is overflow (largest 256-bit value)", () => {
    const I = makeI((1n << 256n) - 1n, fakeIR);
    expect(() => bip32CkdPrivFromI(parentKey, I, 9)).toThrow(
      Bip32InvalidChildError
    );
  });

  test("IL == n - 1 is valid (boundary, just below n)", () => {
    const I = makeI(N - 1n, fakeIR);
    const { key } = bip32CkdPrivFromI(parentKey, I, 0);
    expect(key.length).toBe(32);
    // child = (parent + n - 1) mod n = parent - 1 mod n
    const expected = bufN(
      (BigInt("0x" + parentKey.toString("hex")) + N - 1n) % N
    );
    expect(key.equals(expected)).toBe(true);
  });

  test("k_i == 0 triggers Bip32InvalidChildError(child-zero)", () => {
    // child = (parent + IL) mod n == 0  ⇔  IL == (n - parent) mod n
    const parentBig = BigInt("0x" + parentKey.toString("hex"));
    const IL = (N - parentBig) % N;
    const I = makeI(IL, fakeIR);
    expect(() => bip32CkdPrivFromI(parentKey, I, 42)).toThrow(
      Bip32InvalidChildError
    );
    try {
      bip32CkdPrivFromI(parentKey, I, 42);
    } catch (e) {
      expect(e).toBeInstanceOf(Bip32InvalidChildError);
      expect((e as Bip32InvalidChildError).index).toBe(42);
      expect((e as Error).message).toContain("child-zero");
    }
  });

  test("rejects malformed I (wrong length)", () => {
    expect(() => bip32CkdPrivFromI(parentKey, Buffer.alloc(63), 0)).toThrow(
      /I must be 64 bytes/
    );
    expect(() => bip32CkdPrivFromI(parentKey, Buffer.alloc(65), 0)).toThrow(
      /I must be 64 bytes/
    );
  });
});

describe("BIP-32 vector 1 regression (real KDF)", () => {
  // BIP-32 test vector 1:
  //   Seed (hex): 000102030405060708090a0b0c0d0e0f
  //   Master m fingerprint, m/0' chain code, etc.
  // Compute master from seed via HMAC-SHA512(key="Bitcoin seed").
  // Then derive m/0' (hardened) using bip32CkdPrivFromI directly, and
  // compare the resulting child key + chain code against the spec values.
  //
  // From https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki:
  //   Chain m/0H:
  //     chain code = 47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141
  //     private    = edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea

  const SEED = "000102030405060708090a0b0c0d0e0f";
  const EXPECTED_M_0H_PRIV =
    "edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea";
  const EXPECTED_M_0H_CC =
    "47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141";

  test("master + m/0' matches BIP-32 test vector 1", () => {
    // Master
    const Imaster = Buffer.from(
      hmac(sha512, Buffer.from("Bitcoin seed"), hexToBuf(SEED))
    );
    const masterKey = Imaster.subarray(0, 32);
    const masterCC = Imaster.subarray(32, 64);

    // Hardened child m/0': data = 0x00 || masterKey || index_be(0x80000000)
    const HARD = 0x80000000;
    const data = Buffer.alloc(37);
    data[0] = 0x00;
    masterKey.copy(data, 1);
    data.writeUInt32BE(HARD, 33);
    const I = Buffer.from(hmac(sha512, masterCC, data));

    const { key, chainCode } = bip32CkdPrivFromI(masterKey, I, HARD);
    expect(key.toString("hex")).toBe(EXPECTED_M_0H_PRIV);
    expect(chainCode.toString("hex")).toBe(EXPECTED_M_0H_CC);
  });
});

describe("Wallet retry loop (caller-side)", () => {
  /**
   * The retry loop in `Wallet.deriveKey` is exercised end-to-end by the
   * BIP-84 vectors in wallet.test.ts (real HMAC, no edge-case index hits).
   * We additionally test that the BIP-39/BIP-84 path produces the canonical
   * vector-1 address — proves the refactored deriveChild (which now defers
   * to bip32CkdPrivFromI) did not regress the happy path.
   */
  beforeEach(() => mkdirSync(TEST_DATADIR, { recursive: true }));
  afterEach(() => rmSync(TEST_DATADIR, { recursive: true, force: true }));

  test("BIP-84 vector still derives bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu", () => {
    const config: WalletConfig = {
      datadir: TEST_DATADIR,
      network: "mainnet",
    };
    const w = Wallet.create(
      config,
      "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    );
    const addr = w.getNewAddress("bech32");
    expect(addr).toBe("bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu");
  });
});
