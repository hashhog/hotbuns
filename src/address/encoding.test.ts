/**
 * Tests for Bitcoin address encoding/decoding.
 */

import { describe, test, expect } from "bun:test";
import {
  AddressType,
  base58CheckEncode,
  base58CheckDecode,
  bech32Encode,
  bech32Decode,
  encodeAddress,
  decodeAddress,
  pubkeyToP2PKH,
  pubkeyToP2WPKH,
} from "./encoding.js";
import { hash160 } from "../crypto/primitives.js";

describe("Base58Check", () => {
  test("encode/decode known P2PKH mainnet address (genesis coinbase)", () => {
    // Satoshi's genesis block coinbase address
    // Public key hash for 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
    const hash = Buffer.from("62e907b15cbf27d5425399ebf6f0fb50ebb88f18", "hex");
    const address = base58CheckEncode(0x00, hash);
    expect(address).toBe("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa");

    const decoded = base58CheckDecode(address);
    expect(decoded.version).toBe(0x00);
    expect(decoded.hash.equals(hash)).toBe(true);
  });

  test("encode/decode P2PKH testnet address", () => {
    const hash = Buffer.from("751e76e8199196d454941c45d1b3a323f1433bd6", "hex");
    const address = base58CheckEncode(0x6f, hash);
    expect(address.startsWith("m") || address.startsWith("n")).toBe(true);

    const decoded = base58CheckDecode(address);
    expect(decoded.version).toBe(0x6f);
    expect(decoded.hash.equals(hash)).toBe(true);
  });

  test("encode/decode P2SH mainnet address", () => {
    // Example P2SH hash
    const hash = Buffer.from("89abcdefabbaabbaabbaabbaabbaabbaabbaabba", "hex");
    const address = base58CheckEncode(0x05, hash);
    expect(address.startsWith("3")).toBe(true);

    const decoded = base58CheckDecode(address);
    expect(decoded.version).toBe(0x05);
    expect(decoded.hash.equals(hash)).toBe(true);
  });

  test("detects corrupted checksum", () => {
    // Valid address: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
    // Corrupt one character
    const corrupted = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb";
    expect(() => base58CheckDecode(corrupted)).toThrow("Invalid Base58Check checksum");
  });

  test("detects invalid Base58 characters", () => {
    // '0', 'O', 'I', 'l' are not in the Base58 alphabet
    expect(() => base58CheckDecode("1A1zP1eP5QGefi2DMPTfTL5SLmv7Divf0a")).toThrow(
      "Invalid Base58 character"
    );
  });

  test("handles leading zeros correctly", () => {
    // Hash with leading zero bytes should produce leading '1's
    const hashWithLeadingZeros = Buffer.from(
      "0000000000000000000000000000000000000001",
      "hex"
    );
    const address = base58CheckEncode(0x00, hashWithLeadingZeros);
    // Should start with multiple '1's due to version byte 0x00 and leading zeros
    expect(address.startsWith("1")).toBe(true);

    const decoded = base58CheckDecode(address);
    expect(decoded.hash.equals(hashWithLeadingZeros)).toBe(true);
  });
});

describe("Bech32/Bech32m", () => {
  test("encode/decode P2WPKH mainnet address", () => {
    // Known P2WPKH test vector
    const hash = Buffer.from("751e76e8199196d454941c45d1b3a323f1433bd6", "hex");
    const address = bech32Encode("bc", 0, hash);
    expect(address).toBe("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");

    const decoded = bech32Decode(address);
    expect(decoded.hrp).toBe("bc");
    expect(decoded.witnessVersion).toBe(0);
    expect(decoded.hash.equals(hash)).toBe(true);
  });

  test("encode/decode P2WSH mainnet address", () => {
    // 32-byte hash for P2WSH
    const hash = Buffer.from(
      "1863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262",
      "hex"
    );
    const address = bech32Encode("bc", 0, hash);
    expect(address.startsWith("bc1q")).toBe(true);

    const decoded = bech32Decode(address);
    expect(decoded.hrp).toBe("bc");
    expect(decoded.witnessVersion).toBe(0);
    expect(decoded.hash.equals(hash)).toBe(true);
  });

  test("encode/decode P2TR mainnet address (bech32m)", () => {
    // Known P2TR test vector (BIP-350)
    const hash = Buffer.from(
      "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
      "hex"
    );
    const address = bech32Encode("bc", 1, hash);
    expect(address.startsWith("bc1p")).toBe(true);

    const decoded = bech32Decode(address);
    expect(decoded.hrp).toBe("bc");
    expect(decoded.witnessVersion).toBe(1);
    expect(decoded.hash.equals(hash)).toBe(true);
  });

  test("encode/decode testnet bech32 address", () => {
    const hash = Buffer.from("751e76e8199196d454941c45d1b3a323f1433bd6", "hex");
    const address = bech32Encode("tb", 0, hash);
    expect(address.startsWith("tb1q")).toBe(true);

    const decoded = bech32Decode(address);
    expect(decoded.hrp).toBe("tb");
    expect(decoded.witnessVersion).toBe(0);
    expect(decoded.hash.equals(hash)).toBe(true);
  });

  test("encode/decode regtest bech32 address", () => {
    const hash = Buffer.from("751e76e8199196d454941c45d1b3a323f1433bd6", "hex");
    const address = bech32Encode("bcrt", 0, hash);
    expect(address.startsWith("bcrt1q")).toBe(true);

    const decoded = bech32Decode(address);
    expect(decoded.hrp).toBe("bcrt");
    expect(decoded.witnessVersion).toBe(0);
    expect(decoded.hash.equals(hash)).toBe(true);
  });
});

describe("High-level address encoding", () => {
  test("round-trip P2PKH mainnet", () => {
    const original = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa";
    const decoded = decodeAddress(original);

    expect(decoded.type).toBe(AddressType.P2PKH);
    expect(decoded.network).toBe("mainnet");
    expect(decoded.hash.length).toBe(20);

    const reencoded = encodeAddress(decoded);
    expect(reencoded).toBe(original);
  });

  test("round-trip P2SH mainnet", () => {
    // 3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy (known P2SH address)
    const hash = Buffer.from("b472a266d0bd89c13706a4132ccfb16f7c3b9fcb", "hex");
    const address = encodeAddress({
      type: AddressType.P2SH,
      hash,
      network: "mainnet",
    });
    expect(address).toBe("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy");

    const decoded = decodeAddress(address);
    expect(decoded.type).toBe(AddressType.P2SH);
    expect(decoded.network).toBe("mainnet");
    expect(decoded.hash.equals(hash)).toBe(true);
  });

  test("round-trip P2WPKH mainnet", () => {
    const original = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
    const decoded = decodeAddress(original);

    expect(decoded.type).toBe(AddressType.P2WPKH);
    expect(decoded.network).toBe("mainnet");
    expect(decoded.hash.length).toBe(20);

    const reencoded = encodeAddress(decoded);
    expect(reencoded).toBe(original);
  });

  test("round-trip P2WSH mainnet", () => {
    const hash = Buffer.from(
      "1863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262",
      "hex"
    );
    const address = encodeAddress({
      type: AddressType.P2WSH,
      hash,
      network: "mainnet",
    });

    const decoded = decodeAddress(address);
    expect(decoded.type).toBe(AddressType.P2WSH);
    expect(decoded.network).toBe("mainnet");
    expect(decoded.hash.equals(hash)).toBe(true);

    const reencoded = encodeAddress(decoded);
    expect(reencoded).toBe(address);
  });

  test("round-trip P2TR mainnet", () => {
    const hash = Buffer.from(
      "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
      "hex"
    );
    const address = encodeAddress({
      type: AddressType.P2TR,
      hash,
      network: "mainnet",
    });

    expect(address.startsWith("bc1p")).toBe(true);

    const decoded = decodeAddress(address);
    expect(decoded.type).toBe(AddressType.P2TR);
    expect(decoded.network).toBe("mainnet");
    expect(decoded.hash.equals(hash)).toBe(true);

    const reencoded = encodeAddress(decoded);
    expect(reencoded).toBe(address);
  });

  test("round-trip P2PKH testnet", () => {
    const hash = Buffer.from("751e76e8199196d454941c45d1b3a323f1433bd6", "hex");
    const address = encodeAddress({
      type: AddressType.P2PKH,
      hash,
      network: "testnet",
    });

    // Testnet P2PKH starts with 'm' or 'n'
    expect(address.startsWith("m") || address.startsWith("n")).toBe(true);

    const decoded = decodeAddress(address);
    expect(decoded.type).toBe(AddressType.P2PKH);
    expect(decoded.network).toBe("testnet");

    const reencoded = encodeAddress(decoded);
    expect(reencoded).toBe(address);
  });

  test("round-trip P2SH testnet", () => {
    const hash = Buffer.from("751e76e8199196d454941c45d1b3a323f1433bd6", "hex");
    const address = encodeAddress({
      type: AddressType.P2SH,
      hash,
      network: "testnet",
    });

    // Testnet P2SH starts with '2'
    expect(address.startsWith("2")).toBe(true);

    const decoded = decodeAddress(address);
    expect(decoded.type).toBe(AddressType.P2SH);
    expect(decoded.network).toBe("testnet");

    const reencoded = encodeAddress(decoded);
    expect(reencoded).toBe(address);
  });

  test("decodes invalid address with helpful error", () => {
    expect(() => decodeAddress("notavalidaddress")).toThrow("Invalid Bitcoin address");
  });
});

describe("Public key to address conversion", () => {
  test("pubkeyToP2PKH with known values", () => {
    // Compressed public key (33 bytes)
    const pubkey = Buffer.from(
      "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
      "hex"
    );

    const address = pubkeyToP2PKH(pubkey, "mainnet");
    expect(address.startsWith("1")).toBe(true);

    // Verify round-trip
    const decoded = decodeAddress(address);
    expect(decoded.type).toBe(AddressType.P2PKH);
    expect(decoded.network).toBe("mainnet");

    // Verify hash matches hash160 of pubkey
    const expectedHash = hash160(pubkey);
    expect(decoded.hash.equals(expectedHash)).toBe(true);
  });

  test("pubkeyToP2WPKH with known values", () => {
    // Known test vector for P2WPKH
    // Public key that produces bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4
    const pubkey = Buffer.from(
      "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
      "hex"
    );

    const address = pubkeyToP2WPKH(pubkey, "mainnet");
    expect(address.startsWith("bc1q")).toBe(true);

    const decoded = decodeAddress(address);
    expect(decoded.type).toBe(AddressType.P2WPKH);
    expect(decoded.network).toBe("mainnet");

    // Verify hash matches hash160 of pubkey
    const expectedHash = hash160(pubkey);
    expect(decoded.hash.equals(expectedHash)).toBe(true);
  });

  test("pubkeyToP2WPKH rejects uncompressed keys", () => {
    // Uncompressed public key (65 bytes)
    const uncompressedPubkey = Buffer.alloc(65);
    uncompressedPubkey[0] = 0x04;

    expect(() => pubkeyToP2WPKH(uncompressedPubkey, "mainnet")).toThrow(
      "P2WPKH requires compressed public key"
    );
  });

  test("pubkeyToP2PKH accepts both compressed and uncompressed keys", () => {
    const compressedPubkey = Buffer.from(
      "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
      "hex"
    );
    const uncompressedPubkey = Buffer.alloc(65);
    uncompressedPubkey[0] = 0x04;
    // Fill with some data
    for (let i = 1; i < 65; i++) {
      uncompressedPubkey[i] = i;
    }

    // Both should work without throwing
    const addr1 = pubkeyToP2PKH(compressedPubkey, "mainnet");
    const addr2 = pubkeyToP2PKH(uncompressedPubkey, "mainnet");

    expect(addr1.startsWith("1")).toBe(true);
    expect(addr2.startsWith("1")).toBe(true);
    // Different keys = different addresses
    expect(addr1).not.toBe(addr2);
  });

  test("pubkeyToP2PKH testnet address", () => {
    const pubkey = Buffer.from(
      "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
      "hex"
    );

    const address = pubkeyToP2PKH(pubkey, "testnet");
    expect(address.startsWith("m") || address.startsWith("n")).toBe(true);

    const decoded = decodeAddress(address);
    expect(decoded.type).toBe(AddressType.P2PKH);
    expect(decoded.network).toBe("testnet");
  });

  test("pubkeyToP2WPKH testnet address", () => {
    const pubkey = Buffer.from(
      "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
      "hex"
    );

    const address = pubkeyToP2WPKH(pubkey, "testnet");
    expect(address.startsWith("tb1q")).toBe(true);

    const decoded = decodeAddress(address);
    expect(decoded.type).toBe(AddressType.P2WPKH);
    expect(decoded.network).toBe("testnet");
  });

  test("pubkeyToP2WPKH regtest address", () => {
    const pubkey = Buffer.from(
      "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
      "hex"
    );

    const address = pubkeyToP2WPKH(pubkey, "regtest");
    expect(address.startsWith("bcrt1q")).toBe(true);

    const decoded = decodeAddress(address);
    expect(decoded.type).toBe(AddressType.P2WPKH);
    expect(decoded.network).toBe("regtest");
  });
});

describe("BIP-350 test vectors", () => {
  // Test vectors from BIP-350
  const validBech32mAddresses = [
    "bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kt5nd6y",
    "BC1SW50QGDZ25J",
    "bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs",
  ];

  test("decodes valid bech32m addresses", () => {
    for (const addr of validBech32mAddresses) {
      // These should decode without throwing
      // (they may not be standard address types though)
      expect(() => bech32Decode(addr)).not.toThrow();
    }
  });
});
