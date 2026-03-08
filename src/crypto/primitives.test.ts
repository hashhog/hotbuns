import { describe, expect, test } from "bun:test";
import {
  sha256Hash,
  hash256,
  hash160,
  ecdsaSign,
  ecdsaVerify,
  privateKeyToPublicKey,
  isValidPrivateKey,
  isValidPublicKey,
  taggedHash,
} from "./primitives";

describe("sha256Hash", () => {
  test("hashes empty buffer", () => {
    const result = sha256Hash(Buffer.alloc(0));
    expect(result.toString("hex")).toBe(
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
  });

  test("hashes 'hello'", () => {
    const result = sha256Hash(Buffer.from("hello"));
    expect(result.toString("hex")).toBe(
      "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    );
  });
});

describe("hash256", () => {
  test("double SHA-256 of empty buffer", () => {
    // SHA-256(SHA-256("")) is a well-known value
    const result = hash256(Buffer.alloc(0));
    expect(result.toString("hex")).toBe(
      "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456"
    );
  });

  test("double SHA-256 of 'hello'", () => {
    const result = hash256(Buffer.from("hello"));
    // Double SHA-256 of "hello"
    expect(result.toString("hex")).toBe(
      "9595c9df90075148eb06860365df33584b75bff782a510c6cd4883a419833d50"
    );
  });
});

describe("hash160", () => {
  test("HASH160 of known public key", () => {
    // Test vector from Bitcoin: compressed public key -> HASH160
    // Using the public key for private key = 1
    const pubKey = Buffer.from(
      "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
      "hex"
    );
    const result = hash160(pubKey);
    expect(result.toString("hex")).toBe(
      "751e76e8199196d454941c45d1b3a323f1433bd6"
    );
  });
});

describe("ECDSA operations", () => {
  // Well-known test private key (NOT for production use!)
  const privateKey = Buffer.from(
    "0000000000000000000000000000000000000000000000000000000000000001",
    "hex"
  );

  test("derives compressed public key from private key", () => {
    const pubKey = privateKeyToPublicKey(privateKey, true);
    expect(pubKey.length).toBe(33);
    expect(pubKey.toString("hex")).toBe(
      "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    );
  });

  test("derives uncompressed public key from private key", () => {
    const pubKey = privateKeyToPublicKey(privateKey, false);
    expect(pubKey.length).toBe(65);
    expect(pubKey[0]).toBe(0x04);
  });

  test("signs and verifies a message hash", () => {
    const msgHash = sha256Hash(Buffer.from("test message"));
    const pubKey = privateKeyToPublicKey(privateKey);
    const signature = ecdsaSign(msgHash, privateKey);

    expect(Buffer.isBuffer(signature)).toBe(true);
    expect(signature.length).toBeGreaterThan(0);

    const valid = ecdsaVerify(signature, msgHash, pubKey);
    expect(valid).toBe(true);
  });

  test("verification fails with wrong public key", () => {
    const msgHash = sha256Hash(Buffer.from("test message"));
    const signature = ecdsaSign(msgHash, privateKey);

    // Different private key -> different public key
    const wrongPrivKey = Buffer.from(
      "0000000000000000000000000000000000000000000000000000000000000002",
      "hex"
    );
    const wrongPubKey = privateKeyToPublicKey(wrongPrivKey);

    const valid = ecdsaVerify(signature, msgHash, wrongPubKey);
    expect(valid).toBe(false);
  });

  test("verification fails with wrong message hash", () => {
    const msgHash = sha256Hash(Buffer.from("test message"));
    const pubKey = privateKeyToPublicKey(privateKey);
    const signature = ecdsaSign(msgHash, privateKey);

    const wrongMsgHash = sha256Hash(Buffer.from("wrong message"));
    const valid = ecdsaVerify(signature, wrongMsgHash, pubKey);
    expect(valid).toBe(false);
  });
});

describe("isValidPrivateKey", () => {
  test("accepts valid private key", () => {
    const validKey = Buffer.from(
      "0000000000000000000000000000000000000000000000000000000000000001",
      "hex"
    );
    expect(isValidPrivateKey(validKey)).toBe(true);
  });

  test("rejects zero", () => {
    const zero = Buffer.alloc(32, 0);
    expect(isValidPrivateKey(zero)).toBe(false);
  });

  test("rejects curve order", () => {
    // secp256k1 curve order n
    const curveOrder = Buffer.from(
      "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
      "hex"
    );
    expect(isValidPrivateKey(curveOrder)).toBe(false);
  });

  test("rejects value greater than curve order", () => {
    const tooLarge = Buffer.from(
      "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364142",
      "hex"
    );
    expect(isValidPrivateKey(tooLarge)).toBe(false);
  });

  test("rejects wrong length", () => {
    const short = Buffer.alloc(16, 1);
    expect(isValidPrivateKey(short)).toBe(false);
  });
});

describe("isValidPublicKey", () => {
  test("accepts valid compressed public key", () => {
    const pubKey = Buffer.from(
      "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
      "hex"
    );
    expect(isValidPublicKey(pubKey)).toBe(true);
  });

  test("accepts valid uncompressed public key", () => {
    const privKey = Buffer.from(
      "0000000000000000000000000000000000000000000000000000000000000001",
      "hex"
    );
    const pubKey = privateKeyToPublicKey(privKey, false);
    expect(isValidPublicKey(pubKey)).toBe(true);
  });

  test("rejects invalid point", () => {
    // Invalid: correct format but not a valid point
    const invalid = Buffer.from(
      "02" + "00".repeat(32),
      "hex"
    );
    expect(isValidPublicKey(invalid)).toBe(false);
  });

  test("rejects wrong length", () => {
    const wrongLength = Buffer.alloc(20, 1);
    expect(isValidPublicKey(wrongLength)).toBe(false);
  });
});

describe("taggedHash", () => {
  test("computes BIP0340/challenge tagged hash", () => {
    // BIP-340 test vector
    // Tag: "BIP0340/challenge"
    // Message: 32 zero bytes
    const msg = Buffer.alloc(32, 0);
    const result = taggedHash("BIP0340/challenge", msg);

    // Pre-computed expected value:
    // SHA256("BIP0340/challenge") = 7bb52d7a9fef58323eb1bf7a407db382d2f3f2d81bb1224f49fe518f6d48d37c
    // tagHash = 7bb52d7a... || 7bb52d7a...
    // SHA256(tagHash || msg)
    expect(result.length).toBe(32);

    // Verify it's consistent (same input produces same output)
    const result2 = taggedHash("BIP0340/challenge", msg);
    expect(result.equals(result2)).toBe(true);

    // Verify the computed value matches expected
    // This is the SHA256(SHA256("BIP0340/challenge") || SHA256("BIP0340/challenge") || 32_zero_bytes)
    expect(result.toString("hex")).toBe(
      "a50885aadef94ee57e5537e27ef82d4db7c756193539d3d8d0bb6ee5f3a7ad46"
    );
  });

  test("different tags produce different hashes", () => {
    const msg = Buffer.from("test");
    const hash1 = taggedHash("TapLeaf", msg);
    const hash2 = taggedHash("TapBranch", msg);
    expect(hash1.equals(hash2)).toBe(false);
  });

  test("different messages produce different hashes", () => {
    const hash1 = taggedHash("BIP0340/aux", Buffer.from("msg1"));
    const hash2 = taggedHash("BIP0340/aux", Buffer.from("msg2"));
    expect(hash1.equals(hash2)).toBe(false);
  });

  test("caches tag hashes for performance", () => {
    // Call twice with same tag to exercise cache
    const msg = Buffer.from("test");
    const hash1 = taggedHash("TapSighash", msg);
    const hash2 = taggedHash("TapSighash", msg);
    expect(hash1.equals(hash2)).toBe(true);
  });
});
