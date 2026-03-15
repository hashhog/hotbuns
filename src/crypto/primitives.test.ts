import { describe, expect, test, beforeAll } from "bun:test";
import {
  sha256Hash,
  hash256,
  hash160,
  ecdsaSign,
  ecdsaVerify,
  ecdsaVerifyBatch,
  privateKeyToPublicKey,
  privateKeyToXOnlyPubKey,
  isValidPrivateKey,
  isValidPublicKey,
  isValidXOnlyPubKey,
  taggedHash,
  schnorrSign,
  schnorrVerify,
  schnorrVerifyBatch,
  tweakPrivateKey,
  tweakPublicKey,
  sha256d64,
  computeMerkleRootOptimized,
  hash256Batch,
  getSha256Implementation,
  runCryptoBenchmarks,
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

describe("ecdsaVerifyBatch", () => {
  test("verifies multiple signatures in batch", () => {
    const privateKey1 = Buffer.from(
      "0000000000000000000000000000000000000000000000000000000000000001",
      "hex"
    );
    const privateKey2 = Buffer.from(
      "0000000000000000000000000000000000000000000000000000000000000002",
      "hex"
    );

    const msgHash1 = sha256Hash(Buffer.from("msg1"));
    const msgHash2 = sha256Hash(Buffer.from("msg2"));

    const sig1 = ecdsaSign(msgHash1, privateKey1);
    const sig2 = ecdsaSign(msgHash2, privateKey2);

    const pubKey1 = privateKeyToPublicKey(privateKey1);
    const pubKey2 = privateKeyToPublicKey(privateKey2);

    const results = ecdsaVerifyBatch([
      { signature: sig1, msgHash: msgHash1, publicKey: pubKey1 },
      { signature: sig2, msgHash: msgHash2, publicKey: pubKey2 },
      { signature: sig1, msgHash: msgHash2, publicKey: pubKey1 }, // Invalid: wrong message
    ]);

    expect(results).toEqual([true, true, false]);
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

describe("Schnorr operations", () => {
  const privateKey = Buffer.from(
    "0000000000000000000000000000000000000000000000000000000000000001",
    "hex"
  );

  test("derives x-only public key", () => {
    const xOnlyPubKey = privateKeyToXOnlyPubKey(privateKey);
    expect(xOnlyPubKey.length).toBe(32);
    // The x-coordinate of the generator point G
    expect(xOnlyPubKey.toString("hex")).toBe(
      "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    );
  });

  test("signs and verifies Schnorr signature", () => {
    const msgHash = sha256Hash(Buffer.from("test message"));
    const xOnlyPubKey = privateKeyToXOnlyPubKey(privateKey);
    const signature = schnorrSign(msgHash, privateKey);

    expect(signature.length).toBe(64);

    const valid = schnorrVerify(signature, msgHash, xOnlyPubKey);
    expect(valid).toBe(true);
  });

  test("Schnorr verification fails with wrong pubkey", () => {
    const msgHash = sha256Hash(Buffer.from("test message"));
    const signature = schnorrSign(msgHash, privateKey);

    const wrongPrivKey = Buffer.from(
      "0000000000000000000000000000000000000000000000000000000000000002",
      "hex"
    );
    const wrongPubKey = privateKeyToXOnlyPubKey(wrongPrivKey);

    const valid = schnorrVerify(signature, msgHash, wrongPubKey);
    expect(valid).toBe(false);
  });

  test("Schnorr verification fails with wrong message", () => {
    const msgHash = sha256Hash(Buffer.from("test message"));
    const xOnlyPubKey = privateKeyToXOnlyPubKey(privateKey);
    const signature = schnorrSign(msgHash, privateKey);

    const wrongMsgHash = sha256Hash(Buffer.from("wrong"));
    const valid = schnorrVerify(signature, wrongMsgHash, xOnlyPubKey);
    expect(valid).toBe(false);
  });

  test("validates x-only public keys", () => {
    const validXOnlyPubKey = privateKeyToXOnlyPubKey(privateKey);
    expect(isValidXOnlyPubKey(validXOnlyPubKey)).toBe(true);

    // Invalid: all zeros (not on curve)
    expect(isValidXOnlyPubKey(Buffer.alloc(32, 0))).toBe(false);

    // Invalid: wrong length
    expect(isValidXOnlyPubKey(Buffer.alloc(33, 1))).toBe(false);
  });
});

describe("schnorrVerifyBatch", () => {
  test("verifies multiple Schnorr signatures in batch", () => {
    const privateKey1 = Buffer.from(
      "0000000000000000000000000000000000000000000000000000000000000001",
      "hex"
    );
    const privateKey2 = Buffer.from(
      "0000000000000000000000000000000000000000000000000000000000000002",
      "hex"
    );

    const msgHash1 = sha256Hash(Buffer.from("msg1"));
    const msgHash2 = sha256Hash(Buffer.from("msg2"));

    const sig1 = schnorrSign(msgHash1, privateKey1);
    const sig2 = schnorrSign(msgHash2, privateKey2);

    const pubKey1 = privateKeyToXOnlyPubKey(privateKey1);
    const pubKey2 = privateKeyToXOnlyPubKey(privateKey2);

    const results = schnorrVerifyBatch([
      { signature: sig1, msgHash: msgHash1, publicKey: pubKey1 },
      { signature: sig2, msgHash: msgHash2, publicKey: pubKey2 },
      { signature: sig1, msgHash: msgHash2, publicKey: pubKey1 }, // Invalid: wrong message
    ]);

    expect(results).toEqual([true, true, false]);
  });
});

describe("Taproot tweak operations", () => {
  const privateKey = Buffer.from(
    "0000000000000000000000000000000000000000000000000000000000000001",
    "hex"
  );
  const tweak = Buffer.from(
    "0000000000000000000000000000000000000000000000000000000000000005",
    "hex"
  );

  test("tweaks private key", () => {
    const tweakedPrivKey = tweakPrivateKey(privateKey, tweak);
    expect(tweakedPrivKey.length).toBe(32);

    // 1 + 5 = 6
    const expected = Buffer.from(
      "0000000000000000000000000000000000000000000000000000000000000006",
      "hex"
    );
    expect(tweakedPrivKey.toString("hex")).toBe(expected.toString("hex"));
  });

  test("tweaks public key", () => {
    const xOnlyPubKey = privateKeyToXOnlyPubKey(privateKey);
    const tweakedPubKey = tweakPublicKey(xOnlyPubKey, tweak);
    expect(tweakedPubKey.length).toBe(32);

    // The tweaked public key should correspond to the tweaked private key
    const expectedPubKey = privateKeyToXOnlyPubKey(tweakPrivateKey(privateKey, tweak));
    expect(tweakedPubKey.toString("hex")).toBe(expectedPubKey.toString("hex"));
  });
});

describe("sha256d64 (Merkle tree optimization)", () => {
  test("computes double SHA-256 of 64-byte block", () => {
    const left = Buffer.alloc(32, 0x01);
    const right = Buffer.alloc(32, 0x02);

    const result = sha256d64(left, right);
    expect(result.length).toBe(32);

    // Verify it matches hash256 of concatenated data
    const expected = hash256(Buffer.concat([left, right]));
    expect(result.toString("hex")).toBe(expected.toString("hex"));
  });
});

describe("computeMerkleRootOptimized", () => {
  test("returns zeros for empty input", () => {
    const result = computeMerkleRootOptimized([]);
    expect(result.toString("hex")).toBe("00".repeat(32));
  });

  test("returns single hash unchanged", () => {
    const hash = Buffer.alloc(32, 0xab);
    const result = computeMerkleRootOptimized([hash]);
    expect(result.toString("hex")).toBe(hash.toString("hex"));
  });

  test("computes Merkle root for two hashes", () => {
    const hash1 = Buffer.alloc(32, 0x01);
    const hash2 = Buffer.alloc(32, 0x02);

    const result = computeMerkleRootOptimized([hash1, hash2]);

    // Should be hash256(hash1 || hash2)
    const expected = hash256(Buffer.concat([hash1, hash2]));
    expect(result.toString("hex")).toBe(expected.toString("hex"));
  });

  test("computes Merkle root for three hashes (odd number)", () => {
    const hash1 = Buffer.alloc(32, 0x01);
    const hash2 = Buffer.alloc(32, 0x02);
    const hash3 = Buffer.alloc(32, 0x03);

    const result = computeMerkleRootOptimized([hash1, hash2, hash3]);

    // Level 1: [hash256(hash1||hash2), hash256(hash3||hash3)]
    // Level 0: hash256(level1[0] || level1[1])
    const level1_0 = hash256(Buffer.concat([hash1, hash2]));
    const level1_1 = hash256(Buffer.concat([hash3, hash3])); // Duplicate last
    const expected = hash256(Buffer.concat([level1_0, level1_1]));

    expect(result.toString("hex")).toBe(expected.toString("hex"));
  });

  test("computes Merkle root for four hashes", () => {
    const hashes = [
      Buffer.alloc(32, 0x01),
      Buffer.alloc(32, 0x02),
      Buffer.alloc(32, 0x03),
      Buffer.alloc(32, 0x04),
    ];

    const result = computeMerkleRootOptimized(hashes);

    // Level 1: [hash256(h1||h2), hash256(h3||h4)]
    // Level 0: hash256(level1[0] || level1[1])
    const level1_0 = hash256(Buffer.concat([hashes[0], hashes[1]]));
    const level1_1 = hash256(Buffer.concat([hashes[2], hashes[3]]));
    const expected = hash256(Buffer.concat([level1_0, level1_1]));

    expect(result.toString("hex")).toBe(expected.toString("hex"));
  });

  test("handles large number of transactions", () => {
    const hashes: Buffer[] = [];
    for (let i = 0; i < 1000; i++) {
      const hash = Buffer.alloc(32);
      hash.writeUInt32LE(i, 0);
      hashes.push(hash);
    }

    const result = computeMerkleRootOptimized(hashes);
    expect(result.length).toBe(32);

    // Verify consistency
    const result2 = computeMerkleRootOptimized(hashes);
    expect(result.toString("hex")).toBe(result2.toString("hex"));
  });
});

describe("hash256Batch", () => {
  test("computes batch of double SHA-256 hashes", () => {
    const inputs = [
      Buffer.from("test1"),
      Buffer.from("test2"),
      Buffer.from("test3"),
    ];

    const results = hash256Batch(inputs);

    expect(results.length).toBe(3);
    for (let i = 0; i < inputs.length; i++) {
      expect(results[i].toString("hex")).toBe(hash256(inputs[i]).toString("hex"));
    }
  });
});

describe("getSha256Implementation", () => {
  test("returns implementation name", () => {
    const impl = getSha256Implementation();
    expect(typeof impl).toBe("string");
    expect(impl.length).toBeGreaterThan(0);
    // Should be one of the known implementations
    expect(
      impl.includes("node:crypto") || impl.includes("@noble/hashes")
    ).toBe(true);
  });
});

describe("crypto benchmarks", () => {
  test("runCryptoBenchmarks returns valid results", async () => {
    const results = await runCryptoBenchmarks(100); // Small iteration count for test

    expect(results.implementation).toBeTruthy();
    expect(results.sha256ThroughputMBps).toBeGreaterThan(0);
    expect(results.hash256OpsPerSec).toBeGreaterThan(0);
    expect(results.merkleRootTxsPerSec).toBeGreaterThan(0);
    expect(results.ecdsaVerifyOpsPerSec).toBeGreaterThan(0);
    expect(results.schnorrVerifyOpsPerSec).toBeGreaterThan(0);
  });
});
