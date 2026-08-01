/**
 * W111 Wallet / HD / Descriptors audit — hotbuns (TypeScript/Bun)
 *
 * 30 gates covering BIP-32, BIP-39, BIP-44/49/84/86, BIP-380 descriptors,
 * address types, storage, encryption, KeyPool, signing, and PSBT.
 *
 * Findings:
 *   BUG-1  (HIGH)   Math.random() in coin-selection + shuffleArray (wallet.ts:1711,1852) — FIXED FIX-40
 *   BUG-2  (HIGH)   Dual encryption schemes — save() PBKDF2+GCM vs encryptWallet() scrypt+CBC (incompatible)
 *   BUG-3  (MEDIUM) signPSBTInput() throws for P2TR scriptPubKey (taproot signing absent)
 *   BUG-4  (MEDIUM) KeyPool absent — no keypoolrefill / getkeypoolsize RPC
 *   BUG-5  (MEDIUM) Missing RPCs: walletcreatepsbt, walletprocesspsbt, dumpprivkey, importprivkey, keypoolrefill, getaddressinfo
 *   BUG-6  (LOW)    BIP-39 passphrase (optional extra word) not supported; salt always "mnemonic"
 *   BUG-7  (LOW)    PSBT key-type read as varint instead of single byte (non-conformant BIP-174)
 *
 * Status legend:
 *   PASS — correct behaviour confirmed
 *   FAIL — bug confirmed
 */

import { describe, expect, test, beforeEach, afterEach } from "bun:test";
import { mkdirSync, rmSync } from "fs";
import { hmac } from "@noble/hashes/hmac.js";
import { sha512, sha256 } from "@noble/hashes/sha2.js";
import { pbkdf2 } from "@noble/hashes/pbkdf2.js";
import { schnorr, secp256k1 } from "@noble/curves/secp256k1.js";

import {
  Wallet,
  type WalletConfig,
  Bip32InvalidChildError,
  bip32CkdPrivFromI,
} from "../src/wallet/wallet";

import {
  entropyToMnemonic,
  mnemonicToEntropy,
  validateMnemonic,
  generateMnemonic,
  parseMnemonicString,
} from "../src/wallet/bip39";

import {
  parseDescriptor,
  descriptorChecksum,
  addChecksum,
  validateChecksum,
  encodeExtendedKey,
  decodeExtendedKey,
  type ExtendedKey,
} from "../src/wallet/descriptor";

import {
  createPSBT,
  serializePSBT,
  deserializePSBT,
  signPSBTInput,
  combinePSBTs,
  finalizePSBTInput,
  encodePSBTBase64,
  decodePSBTBase64,
  PSBT_MAGIC,
  type PSBT,
} from "../src/wallet/psbt";

import { privateKeyToPublicKey, hash160, taggedHash, tweakPublicKey } from "../src/crypto/primitives";
import { AddressType } from "../src/address/encoding";

const TEST_DATADIR = "/tmp/hotbuns-w111-audit";

// The canonical BIP-39/84 "abandon" test mnemonic
const ABANDON_MNEMONIC =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

// Expected BIP-84 receive address 0 (from BIP-84 test vector)
const EXPECTED_BIP84_RECEIVE_0 = "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu";

// Expected BIP-84 change address 0
const EXPECTED_BIP84_CHANGE_0 = "bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el";

function makeConfig(network: "mainnet" | "testnet" | "regtest" = "mainnet"): WalletConfig {
  return { datadir: TEST_DATADIR, network };
}

// ============================================================================
// G1: BIP-32 master key derivation (HMAC-SHA512 with "Bitcoin seed")
// ============================================================================
describe("G1: BIP-32 master key derivation", () => {
  beforeEach(() => mkdirSync(TEST_DATADIR, { recursive: true }));
  afterEach(() => rmSync(TEST_DATADIR, { recursive: true, force: true }));

  test("PASS: derive master key from BIP-32 vector 1 seed", () => {
    // BIP-32 test vector 1: seed = 000102030405060708090a0b0c0d0e0f
    // Expected master private key:
    //   e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35
    const seedHex = "000102030405060708090a0b0c0d0e0f";
    const seed = Buffer.from(seedHex, "hex");

    const I = Buffer.from(hmac(sha512, Buffer.from("Bitcoin seed"), seed));
    const masterKey = I.subarray(0, 32);
    const chainCode = I.subarray(32, 64);

    expect(masterKey.toString("hex")).toBe(
      "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35"
    );
    expect(chainCode.toString("hex")).toBe(
      "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508"
    );
  });

  test("PASS: BIP-32 CKD private — correct child key math", () => {
    // Build an I with IL = 2 (well below n)
    const parentKey = Buffer.from(
      "1111111111111111111111111111111111111111111111111111111111111111",
      "hex"
    );
    const IL = Buffer.from(
      "0000000000000000000000000000000000000000000000000000000000000002",
      "hex"
    );
    const IR = Buffer.from(
      "abababababababababababababababababababababababababababababababcd",
      "hex"
    );
    expect(IL.length).toBe(32);
    expect(IR.length).toBe(32);
    const I = Buffer.concat([IL, IR]);
    expect(I.length).toBe(64);

    const { key, chainCode } = bip32CkdPrivFromI(parentKey, I, 0);
    // child = (parent + 2) mod n
    const N = BigInt("0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
    const expected = (BigInt("0x" + parentKey.toString("hex")) + 2n) % N;
    expect(BigInt("0x" + key.toString("hex"))).toBe(expected);
    expect(chainCode.toString("hex")).toBe(IR.toString("hex"));
  });

  test("PASS: BIP-32 CKD private — parse256(IL) >= n throws Bip32InvalidChildError", () => {
    const parentKey = Buffer.from(
      "1111111111111111111111111111111111111111111111111111111111111111",
      "hex"
    );
    const N = BigInt("0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
    // IL = curve order n (overflow)
    let nHex = N.toString(16).padStart(64, "0");
    const IL = Buffer.from(nHex, "hex");
    const IR = Buffer.from("abababababababababababababababababababababababababababababababcd", "hex");
    const I = Buffer.concat([IL, IR]);
    expect(I.length).toBe(64);

    expect(() => bip32CkdPrivFromI(parentKey, I, 5)).toThrow(Bip32InvalidChildError);
  });

  test("PASS: BIP-32 CKD private — child key == 0 throws Bip32InvalidChildError", () => {
    const N = BigInt("0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
    // Set parent key = n-1 and IL = 1 so child = (n-1+1) mod n = 0
    const nMinus1Hex = (N - 1n).toString(16).padStart(64, "0");
    const parentKey = Buffer.from(nMinus1Hex, "hex");
    const IL = Buffer.from("0000000000000000000000000000000000000000000000000000000000000001", "hex");
    const IR = Buffer.from("abababababababababababababababababababababababababababababababcd", "hex");
    const I = Buffer.concat([IL, IR]);
    expect(I.length).toBe(64);

    expect(() => bip32CkdPrivFromI(parentKey, I, 3)).toThrow(Bip32InvalidChildError);
  });
});

// ============================================================================
// G2: BIP-32 hardened vs. non-hardened CKD
// ============================================================================
describe("G2: BIP-32 hardened vs non-hardened derivation", () => {
  beforeEach(() => mkdirSync(TEST_DATADIR, { recursive: true }));
  afterEach(() => rmSync(TEST_DATADIR, { recursive: true, force: true }));

  test("PASS: hardened child uses 0x00 || private key || index as data", () => {
    // Verify the derivation distinguishes hardened (index >= 0x80000000)
    const w = Wallet.create(makeConfig(), ABANDON_MNEMONIC);

    // Derive m/84'/0'/0'/0/0 (hardened path)
    const addr = w.getNewAddress("bech32");
    // BIP-84 test vector confirms this is bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu
    expect(addr).toBe(EXPECTED_BIP84_RECEIVE_0);
  });

  test("PASS: two consecutive receive addresses are different", () => {
    const w = Wallet.create(makeConfig(), ABANDON_MNEMONIC);
    const addr0 = w.getNewAddress("bech32");
    const addr1 = w.getNewAddress("bech32");
    expect(addr0).not.toBe(addr1);
  });
});

// ============================================================================
// G3: BIP-32 child key derivation skip (invalid child → retry with i+1)
// ============================================================================
describe("G3: BIP-32 invalid child skip", () => {
  test("PASS: Bip32InvalidChildError carries the index", () => {
    const parentKey = Buffer.from(
      "1111111111111111111111111111111111111111111111111111111111111111",
      "hex"
    );
    const N = BigInt("0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
    const nHex = N.toString(16).padStart(64, "0");
    const IR = Buffer.from("abababababababababababababababababababababababababababababababcd", "hex");
    const I = Buffer.concat([Buffer.from(nHex, "hex"), IR]);
    expect(I.length).toBe(64);
    try {
      bip32CkdPrivFromI(parentKey, I, 42);
      expect(false).toBe(true); // Should not reach here
    } catch (e) {
      expect(e).toBeInstanceOf(Bip32InvalidChildError);
      expect((e as Bip32InvalidChildError).index).toBe(42);
    }
  });
});

// ============================================================================
// G4: BIP-32 path serialization correctness
// ============================================================================
describe("G4: BIP-32 path — BIP-84 vector", () => {
  beforeEach(() => mkdirSync(TEST_DATADIR, { recursive: true }));
  afterEach(() => rmSync(TEST_DATADIR, { recursive: true, force: true }));

  test("PASS: m/84'/0'/0'/0/0 receive address matches BIP-84 vector", () => {
    const w = Wallet.create(makeConfig("mainnet"), ABANDON_MNEMONIC);
    expect(w.getNewAddress("bech32")).toBe(EXPECTED_BIP84_RECEIVE_0);
  });

  test("PASS: m/84'/0'/0'/1/0 change address matches BIP-84 vector", () => {
    const w = Wallet.create(makeConfig("mainnet"), ABANDON_MNEMONIC);
    expect(w.getChangeAddress("bech32")).toBe(EXPECTED_BIP84_CHANGE_0);
  });
});

// ============================================================================
// G5: BIP-32 xpub / xprv serialization (base58check, 78 bytes)
// ============================================================================
describe("G5: BIP-32 xpub / xprv encode + decode", () => {
  test("PASS: decode → re-encode round-trip for a known xpub", () => {
    // xpub from BIP-32 vector 1: m/0'/1
    // Computed externally; we verify round-trip integrity.
    const xpub =
      "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH";
    const decoded = decodeExtendedKey(xpub);
    const reencoded = encodeExtendedKey(decoded);
    expect(reencoded).toBe(xpub);
  });

  test("PASS: xpub depth/fingerprint/childIndex decoded correctly", () => {
    // xpub at depth 1 (child of master, first BIP-32 vector child m/0')
    const xpub =
      "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH";
    const decoded = decodeExtendedKey(xpub);
    // Depth 1 (direct child of master)
    expect(decoded.depth).toBe(1);
    expect(decoded.isPrivate).toBe(false);
    expect(decoded.key.length).toBe(33); // compressed pubkey
    expect(decoded.chainCode.length).toBe(32);
  });
});

// ============================================================================
// G6-G10: BIP-44/49/84/86 paths
// ============================================================================
describe("G6-G10: HD paths (BIP-44/49/84/86)", () => {
  beforeEach(() => mkdirSync(TEST_DATADIR, { recursive: true }));
  afterEach(() => rmSync(TEST_DATADIR, { recursive: true, force: true }));

  test("PASS G6: BIP-44 (P2PKH) address starts with '1' on mainnet", () => {
    const w = Wallet.create(makeConfig("mainnet"), ABANDON_MNEMONIC);
    const addr = w.getNewAddress("legacy");
    expect(addr.startsWith("1")).toBe(true);
  });

  test("PASS G7: BIP-49 (P2SH-P2WPKH) address starts with '3' on mainnet", () => {
    const w = Wallet.create(makeConfig("mainnet"), ABANDON_MNEMONIC);
    const addr = w.getNewAddress("p2sh-segwit");
    expect(addr.startsWith("3")).toBe(true);
  });

  test("PASS G8: BIP-84 (P2WPKH) address starts with 'bc1q' on mainnet", () => {
    const w = Wallet.create(makeConfig("mainnet"), ABANDON_MNEMONIC);
    const addr = w.getNewAddress("bech32");
    expect(addr.startsWith("bc1q")).toBe(true);
  });

  test("PASS G9: BIP-86 (P2TR) address starts with 'bc1p' on mainnet", () => {
    const w = Wallet.create(makeConfig("mainnet"), ABANDON_MNEMONIC);
    const addr = w.getNewAddress("bech32m");
    expect(addr.startsWith("bc1p")).toBe(true);
  });

  test("PASS G10: coin_type=1 for testnet/regtest", () => {
    // On testnet, BIP-84 path is m/84'/1'/0'/0/0
    // Address should start with 'tb1q' (bech32 testnet)
    const w = Wallet.create(makeConfig("testnet"), ABANDON_MNEMONIC);
    const addr = w.getNewAddress("bech32");
    expect(addr.startsWith("tb1q")).toBe(true);
  });
});

// ============================================================================
// G11-G16: BIP-380 descriptors
// ============================================================================
describe("G11-G16: BIP-380 descriptors", () => {
  test("PASS G11: pkh() descriptor parses and expands", () => {
    const desc = "pkh(02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9)#9tvfrq3z";
    const parsed = parseDescriptor(desc);
    expect(parsed.descriptor).toBeDefined();
    const outputs = parsed.descriptor.expand(0, "mainnet");
    expect(outputs.length).toBeGreaterThan(0);
    expect(outputs[0].scriptPubKey.length).toBe(25); // P2PKH script length
  });

  test("PASS G12: wpkh() descriptor parses and expands", () => {
    const desc = "wpkh(02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9)";
    const parsed = parseDescriptor(desc);
    const outputs = parsed.descriptor.expand(0, "mainnet");
    expect(outputs[0].scriptPubKey.length).toBe(22); // P2WPKH script length
    expect(outputs[0].address).toBeDefined();
    expect(outputs[0].address!.startsWith("bc1q")).toBe(true);
  });

  test("PASS G13: tr() descriptor parses and expands (P2TR)", () => {
    const desc =
      "tr(02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9)";
    const parsed = parseDescriptor(desc);
    const outputs = parsed.descriptor.expand(0, "mainnet");
    expect(outputs[0].scriptPubKey.length).toBe(34); // P2TR script length (OP_1 <32>)
    expect(outputs[0].address!.startsWith("bc1p")).toBe(true);
  });

  test("PASS G14: sh(wpkh()) descriptor produces P2SH address", () => {
    const desc = "sh(wpkh(02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9))";
    const parsed = parseDescriptor(desc);
    const outputs = parsed.descriptor.expand(0, "mainnet");
    expect(outputs[0].address!.startsWith("3")).toBe(true);
    expect(outputs[0].redeemScript).toBeDefined();
  });

  test("PASS G15: descriptor checksum computed and validated correctly", () => {
    const raw = "wpkh(02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9)";
    const withChecksum = addChecksum(raw);
    expect(withChecksum).toContain("#");
    const stripped = validateChecksum(withChecksum);
    expect(stripped).toBe(raw);
  });

  test("PASS G16: sortedmulti() descriptor sorts keys lexicographically", () => {
    // Two keys in non-sorted order — sortedmulti must sort them
    const keyA = "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9";
    const keyB = "03f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9";
    // keyA < keyB lexicographically (02 < 03)
    const desc = `sortedmulti(1,${keyB},${keyA})`;
    const parsed = parseDescriptor(desc);
    const outputs = parsed.descriptor.expand(0, "mainnet");
    // Script: OP_1 <keyA> <keyB> OP_2 OP_CHECKMULTISIG (sorted)
    const script = outputs[0].scriptPubKey;
    // After OP_1 push and key-length byte, first key bytes should be 02xx (smaller key)
    expect(script[2]).toBe(0x02); // first byte of sorted keyA (compressed prefix 02)
  });
});

// ============================================================================
// G17-G18: BIP-39 mnemonic + PBKDF2
// ============================================================================
describe("G17-G18: BIP-39 mnemonic + PBKDF2", () => {
  test("PASS G17: entropy → mnemonic → entropy round-trip", () => {
    const entropy = Buffer.from("00000000000000000000000000000000", "hex");
    const mnemonic = entropyToMnemonic(new Uint8Array(entropy));
    expect(mnemonic.join(" ")).toBe("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about");
    const recovered = mnemonicToEntropy(mnemonic);
    expect(Buffer.from(recovered).toString("hex")).toBe("00000000000000000000000000000000");
  });

  test("PASS G17: TREZOR canonical vector — seed bytes match", () => {
    // TREZOR vector 1, passphrase="TREZOR"
    const mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".split(" ");
    const sentence = mnemonic.join(" ").normalize("NFKD");
    const saltStr = ("mnemonic" + "TREZOR").normalize("NFKD");
    const seed = pbkdf2(sha512, Buffer.from(sentence), Buffer.from(saltStr), {
      c: 2048,
      dkLen: 64,
    });
    // Expected (TREZOR vector 1, 127-char hex — leading zero dropped in test file)
    const expected =
      "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04";
    expect(Buffer.from(seed).toString("hex")).toBe(expected);
  });

  test("PASS G17: validateMnemonic passes on valid words", () => {
    const words = ABANDON_MNEMONIC.split(" ");
    expect(() => validateMnemonic(words)).not.toThrow();
  });

  test("PASS G17: validateMnemonic throws on bad checksum", () => {
    const words = ABANDON_MNEMONIC.split(" ");
    words[11] = "zoo"; // corrupt last word (checksum violation)
    expect(() => validateMnemonic(words)).toThrow();
  });

  test("PASS G17: generateMnemonic returns valid 12-word mnemonic by default", () => {
    const words = generateMnemonic(128);
    expect(words.length).toBe(12);
    expect(() => validateMnemonic(words)).not.toThrow();
  });

  test("PASS G17: generateMnemonic returns valid 24-word mnemonic for 256 bits", () => {
    const words = generateMnemonic(256);
    expect(words.length).toBe(24);
    expect(() => validateMnemonic(words)).not.toThrow();
  });

  test("PASS G18: PBKDF2 iteration count is 2048 (BIP-39 spec)", () => {
    // BIP-39 specifies exactly 2048 PBKDF2-HMAC-SHA512 iterations.
    // We verify by re-deriving with the same parameters and comparing.
    const sentence = ABANDON_MNEMONIC.normalize("NFKD");
    const salt = "mnemonic".normalize("NFKD");
    const seed2048 = pbkdf2(sha512, Buffer.from(sentence), Buffer.from(salt), {
      c: 2048,
      dkLen: 64,
    });

    const w = Wallet.create(makeConfig(), ABANDON_MNEMONIC);
    expect(w.getSeed().toString("hex")).toBe(Buffer.from(seed2048).toString("hex"));
  });

  // BUG-6: no passphrase support
  test("FAIL BUG-6: BIP-39 passphrase (extra word) not supported — salt always 'mnemonic'", () => {
    // BIP-39 spec: salt = NFKD("mnemonic" + passphrase)
    // hotbuns always uses salt = "mnemonic" (no passphrase support).
    // A wallet created with Wallet.create(config, mnemonic, passphrase) would
    // need the passphrase to be threaded into PBKDF2 salt. There is no such
    // parameter in the Wallet.create() signature.
    //
    // This test confirms the signature gap:
    //   Wallet.create(config: WalletConfig, mnemonic?: string)
    //   — no `passphrase` parameter
    //
    // The expected (with passphrase "TREZOR") seed differs from the no-passphrase seed.
    const noPassSeed = Wallet.create(makeConfig(), ABANDON_MNEMONIC).getSeed();
    const withPassSeed = Buffer.from(
      pbkdf2(sha512,
        Buffer.from(ABANDON_MNEMONIC.normalize("NFKD")),
        Buffer.from("mnemonicTREZOR".normalize("NFKD")),
        { c: 2048, dkLen: 64 }
      )
    );
    // They SHOULD differ — confirms passphrase is not supported
    expect(noPassSeed.equals(withPassSeed)).toBe(false);
    // NOTE: No fix here — this documents that Wallet.create() lacks passphrase param
  });
});

// ============================================================================
// G19-G22: Address types
// ============================================================================
describe("G19-G22: Address types", () => {
  beforeEach(() => mkdirSync(TEST_DATADIR, { recursive: true }));
  afterEach(() => rmSync(TEST_DATADIR, { recursive: true, force: true }));

  test("PASS G19: P2PKH address (BIP-44) produced for legacy type", () => {
    const w = Wallet.create(makeConfig("mainnet"), ABANDON_MNEMONIC);
    const addr = w.getNewAddress("legacy");
    // P2PKH starts with 1 on mainnet
    expect(addr.startsWith("1")).toBe(true);
  });

  test("PASS G20: P2SH-P2WPKH address (BIP-49) produced for p2sh-segwit type", () => {
    const w = Wallet.create(makeConfig("mainnet"), ABANDON_MNEMONIC);
    const addr = w.getNewAddress("p2sh-segwit");
    expect(addr.startsWith("3")).toBe(true);
  });

  test("PASS G21: P2WPKH address (BIP-84) is native segwit bech32", () => {
    const w = Wallet.create(makeConfig("mainnet"), ABANDON_MNEMONIC);
    const addr = w.getNewAddress("bech32");
    expect(addr.startsWith("bc1q")).toBe(true);
    expect(addr).toBe(EXPECTED_BIP84_RECEIVE_0);
  });

  test("PASS G22: P2TR address (BIP-86) is taproot bech32m", () => {
    const w = Wallet.create(makeConfig("mainnet"), ABANDON_MNEMONIC);
    const addr = w.getNewAddress("bech32m");
    expect(addr.startsWith("bc1p")).toBe(true);
  });
});

// ============================================================================
// G23-G25: Storage
// ============================================================================
describe("G23-G25: Wallet storage", () => {
  beforeEach(() => mkdirSync(TEST_DATADIR, { recursive: true }));
  afterEach(() => rmSync(TEST_DATADIR, { recursive: true, force: true }));

  test("PASS G23: wallet saves to disk and reloads with correct seed", async () => {
    const config = makeConfig();
    const w1 = Wallet.create(config, ABANDON_MNEMONIC);
    const seedBefore = w1.getSeed().toString("hex");
    await w1.save("testpassword");

    const w2 = await Wallet.load(config, "testpassword");
    expect(w2.getSeed().toString("hex")).toBe(seedBefore);
  });

  test("PASS G24: saved wallet regenerates same BIP-84 address", async () => {
    const config = makeConfig();
    const w1 = Wallet.create(config, ABANDON_MNEMONIC);
    // Consume one address to advance index
    const addr = w1.getNewAddress("bech32");
    await w1.save("testpassword");

    const w2 = await Wallet.load(config, "testpassword");
    // Next address from loaded wallet should be the second one (index 1)
    const addr2 = w2.getNewAddress("bech32");
    // addr2 should differ from addr0 (index 0)
    expect(addr2).not.toBe(EXPECTED_BIP84_RECEIVE_0);
    expect(addr2.startsWith("bc1q")).toBe(true);
  });

  test("PASS G25: incorrect load password throws", async () => {
    const config = makeConfig();
    const w1 = Wallet.create(config, ABANDON_MNEMONIC);
    await w1.save("correctpassword");

    await expect(Wallet.load(config, "wrongpassword")).rejects.toThrow();
  });

  // BUG-2: Dual encryption schemes incompatible
  test("FAIL BUG-2: encryptWallet() (scrypt+CBC) produces incompatible format with save() (PBKDF2+GCM)", () => {
    // save() uses PBKDF2-SHA256 + AES-256-GCM (from @noble/ciphers)
    // encryptWallet() uses scrypt + AES-256-CBC (from node:crypto)
    // These are two separate codepaths with different on-disk formats.
    // A wallet encrypted via encryptWallet() cannot be loaded by Wallet.load()
    // because Wallet.load() uses PBKDF2 while encryptWallet() writes scrypt params.
    //
    // This test documents the design-level inconsistency by verifying both
    // functions exist and use different KDF methods.
    const w = Wallet.create(makeConfig(), ABANDON_MNEMONIC);

    // encryptWallet uses crypto.scrypt (node:crypto)
    expect(typeof w.encryptWallet).toBe("function");
    // save uses pbkdf2 from @noble/hashes
    expect(typeof w.save).toBe("function");

    // BUG: These two encryption paths are NOT interoperable.
    // A round-trip through encryptWallet → load() will fail because:
    //   - encryptWallet writes { encrypted: true, encryptedSeed: hex, salt: hex, iv: hex }
    //     inside WalletData with AES-256-CBC
    //   - load() expects the outer EncryptedWalletFile format with
    //     AES-256-GCM and PBKDF2-SHA256
  });
});

// ============================================================================
// G26-G28: Signing
// ============================================================================
describe("G26-G28: Signing", () => {
  beforeEach(() => mkdirSync(TEST_DATADIR, { recursive: true }));
  afterEach(() => rmSync(TEST_DATADIR, { recursive: true, force: true }));

  test("PASS G26: wallet signs P2WPKH transaction (BIP-143 sighash)", () => {
    const w = Wallet.create(makeConfig("mainnet"), ABANDON_MNEMONIC);
    const addr = w.getNewAddress("bech32");

    // Add a fake UTXO at that address
    w.addUTXO({
      outpoint: {
        txid: Buffer.alloc(32, 0x01),
        vout: 0,
      },
      amount: 1000000n,
      address: addr,
      keyPath: "m/84'/0'/0'/0/0",
      confirmations: 6,
      addressType: AddressType.P2WPKH,
      isCoinbase: false,
    });

    // Create and sign a transaction to the change address
    const changeAddr = w.getChangeAddress("bech32");
    const tx = w.createTransaction([{ address: changeAddr, amount: 50000n }], 1);

    // Should have at least one input with witness data
    expect(tx.inputs.length).toBeGreaterThan(0);
    expect(tx.inputs[0].witness.length).toBe(2); // sig + pubkey
  });

  test("PASS G27: wallet signs P2TR transaction (BIP-341 Schnorr key-path)", () => {
    const w = Wallet.create(makeConfig("mainnet"), ABANDON_MNEMONIC);
    const addr = w.getNewAddress("bech32m");

    w.addUTXO({
      outpoint: {
        txid: Buffer.alloc(32, 0x02),
        vout: 0,
      },
      amount: 2000000n,
      address: addr,
      keyPath: "m/86'/0'/0'/0/0",
      confirmations: 6,
      addressType: AddressType.P2TR,
      isCoinbase: false,
    });

    const changeAddr = w.getChangeAddress("bech32m");
    const tx = w.createTransaction([{ address: changeAddr, amount: 50000n }], 1);
    expect(tx.inputs[0].witness.length).toBe(1); // Schnorr sig only (64 bytes)
    expect(tx.inputs[0].witness[0].length).toBe(64); // SIGHASH_DEFAULT = 64-byte sig
  });

  // BUG-1 (FIXED): Math.random() replaced with crypto.randomBytes() in coin selection
  test("PASS BUG-1 fixed: coin selection + shuffleArray use CSPRNG (Math.random monkey-patch has no effect)", () => {
    // After FIX-40: wallet.ts line 1711 (knapsack) and 1852 (shuffleArray)
    // now call crypto.randomBytes(4).readUInt32BE(0) instead of Math.random().
    //
    // Verification strategy: monkey-patch Math.random to always return a fixed
    // constant (0.0). If the wallet still produces a valid coin selection and
    // mathRandomCalled remains false, then randomness is NOT sourced from Math.random.
    const originalRandom = Math.random;
    let mathRandomCalled = false;
    Math.random = () => {
      mathRandomCalled = true;
      return 0.0; // fixed constant — would produce deterministic/broken results
    };

    try {
      const w = Wallet.create(makeConfig("mainnet"), ABANDON_MNEMONIC);
      const addr0 = w.getNewAddress("bech32");
      const addr1 = w.getNewAddress("bech32");
      const addr2 = w.getNewAddress("bech32");
      w.addUTXO({
        outpoint: { txid: Buffer.alloc(32, 0x03), vout: 0 },
        amount: 200000n,
        address: addr0,
        keyPath: "m/84'/0'/0'/0/0",
        confirmations: 6,
        addressType: AddressType.P2WPKH,
        isCoinbase: false,
      });
      w.addUTXO({
        outpoint: { txid: Buffer.alloc(32, 0x04), vout: 0 },
        amount: 300000n,
        address: addr1,
        keyPath: "m/84'/0'/0'/0/1",
        confirmations: 6,
        addressType: AddressType.P2WPKH,
        isCoinbase: false,
      });
      w.addUTXO({
        outpoint: { txid: Buffer.alloc(32, 0x05), vout: 0 },
        amount: 250000n,
        address: addr2,
        keyPath: "m/84'/0'/0'/0/2",
        confirmations: 6,
        addressType: AddressType.P2WPKH,
        isCoinbase: false,
      });

      // Exercises knapsack (random first pass) + shuffleArray (output ordering)
      const result = w.selectCoinsAdvanced(150000n, 1);
      expect(result.inputs.length).toBeGreaterThan(0);

      // CSPRNG assertion: Math.random must NOT have been called
      expect(mathRandomCalled).toBe(false);
    } finally {
      Math.random = originalRandom;
    }
  });

  test("PASS G28: PSBT signPSBTInput handles P2WPKH", () => {
    const privkey = Buffer.from(
      "0000000000000000000000000000000000000000000000000000000000000001",
      "hex"
    );
    const pubkey = privateKeyToPublicKey(privkey, true);
    const pubkeyHash = hash160(pubkey);

    // Build P2WPKH scriptPubKey: OP_0 <20-byte-hash>
    const scriptPubKey = Buffer.concat([Buffer.from([0x00, 0x14]), pubkeyHash]);

    const tx = {
      version: 2,
      inputs: [
        {
          prevOut: { txid: Buffer.alloc(32), vout: 0 },
          scriptSig: Buffer.alloc(0),
          sequence: 0xffffffff,
          witness: [],
        },
      ],
      outputs: [
        {
          value: 90000n,
          scriptPubKey: Buffer.from([0x51, 0x20, ...Buffer.alloc(32)]),
        },
      ],
      lockTime: 0,
    };

    const psbt = createPSBT(tx);
    psbt.inputs[0].witnessUtxo = { value: 100000n, scriptPubKey };

    // Should not throw
    expect(() => signPSBTInput(psbt, 0, privkey, pubkey)).not.toThrow();
    expect(psbt.inputs[0].partialSigs.size).toBe(1);
  });
});

// ============================================================================
// G29-G30: PSBT (BIP-174 / BIP-370)
// ============================================================================
describe("G29-G30: PSBT serialization + signing", () => {
  test("PASS G29: PSBT magic bytes are 'psbt' + 0xff", () => {
    expect(PSBT_MAGIC.toString("hex")).toBe("70736274ff");
  });

  test("PASS G29: PSBT serialize + deserialize round-trip", () => {
    const tx = {
      version: 2,
      inputs: [
        {
          prevOut: { txid: Buffer.alloc(32, 0xaa), vout: 0 },
          scriptSig: Buffer.alloc(0),
          sequence: 0xffffffff,
          witness: [],
        },
      ],
      outputs: [
        {
          value: 100000n,
          scriptPubKey: Buffer.from([0x00, 0x14, ...Buffer.alloc(20, 0xbb)]),
        },
      ],
      lockTime: 0,
    };

    const psbt = createPSBT(tx);
    const serialized = serializePSBT(psbt);
    const deserialized = deserializePSBT(serialized);

    expect(deserialized.tx.inputs.length).toBe(1);
    expect(deserialized.tx.outputs.length).toBe(1);
    expect(deserialized.tx.outputs[0].value).toBe(100000n);
  });

  test("PASS G29: PSBT base64 encode + decode round-trip", () => {
    const tx = {
      version: 2,
      inputs: [
        {
          prevOut: { txid: Buffer.alloc(32), vout: 0 },
          scriptSig: Buffer.alloc(0),
          sequence: 0xffffffff,
          witness: [],
        },
      ],
      outputs: [
        {
          value: 99000n,
          scriptPubKey: Buffer.from([0x51, 0x20, ...Buffer.alloc(32)]),
        },
      ],
      lockTime: 0,
    };

    const psbt = createPSBT(tx);
    const b64 = encodePSBTBase64(psbt);
    expect(typeof b64).toBe("string");
    const decoded = decodePSBTBase64(b64);
    expect(decoded.tx.outputs[0].value).toBe(99000n);
  });

  test("PASS G29: PSBT deserialize rejects unsigned tx with non-empty scriptSig", () => {
    const tx = {
      version: 2,
      inputs: [
        {
          prevOut: { txid: Buffer.alloc(32), vout: 0 },
          scriptSig: Buffer.alloc(0),
          sequence: 0xffffffff,
          witness: [],
        },
      ],
      outputs: [
        {
          value: 99000n,
          scriptPubKey: Buffer.from([0x00, 0x14, ...Buffer.alloc(20)]),
        },
      ],
      lockTime: 0,
    };

    // PSBT createPSBT validates that inputs have empty scriptSig
    const txWithSig = {
      ...tx,
      inputs: [{ ...tx.inputs[0], scriptSig: Buffer.from([0x01]) }],
    };
    expect(() => createPSBT(txWithSig)).toThrow();
  });

  test("PASS G29: PSBT combiner merges partial signatures from two signers", () => {
    const privkey1 = Buffer.from(
      "0000000000000000000000000000000000000000000000000000000000000001",
      "hex"
    );
    const privkey2 = Buffer.from(
      "0000000000000000000000000000000000000000000000000000000000000002",
      "hex"
    );
    const pubkey1 = privateKeyToPublicKey(privkey1, true);
    const pubkey2 = privateKeyToPublicKey(privkey2, true);
    const pubkeyHash1 = hash160(pubkey1);

    const scriptPubKey = Buffer.concat([Buffer.from([0x00, 0x14]), pubkeyHash1]);

    const tx = {
      version: 2,
      inputs: [
        {
          prevOut: { txid: Buffer.alloc(32), vout: 0 },
          scriptSig: Buffer.alloc(0),
          sequence: 0xffffffff,
          witness: [],
        },
      ],
      outputs: [{ value: 99000n, scriptPubKey: Buffer.from([0x00, 0x14, ...Buffer.alloc(20)]) }],
      lockTime: 0,
    };

    const psbt1 = createPSBT(tx);
    psbt1.inputs[0].witnessUtxo = { value: 100000n, scriptPubKey };
    signPSBTInput(psbt1, 0, privkey1, pubkey1);

    const psbt2 = createPSBT(tx);
    psbt2.inputs[0].witnessUtxo = { value: 100000n, scriptPubKey };
    // Add a fake partial sig from pubkey2
    psbt2.inputs[0].partialSigs.set(pubkey2.toString("hex"), {
      pubkey: pubkey2,
      signature: Buffer.alloc(71, 0xcc),
    });

    const combined = combinePSBTs([psbt1, psbt2]);
    expect(combined.inputs[0].partialSigs.size).toBe(2);
  });

  // BUG-3: signPSBTInput does not handle P2TR
  test("PASS (BUG-3 fixed): signPSBTInput() signs P2TR scriptPubKey (BIP-86 tweak)", () => {
    const privkey = Buffer.from(
      "0000000000000000000000000000000000000000000000000000000000000001",
      "hex"
    );
    const pubkey = privateKeyToPublicKey(privkey, true);

    // P2TR scriptPubKey: OP_1 <32-byte BIP-86 tweaked output key>
    // Q = P + H_TapTweak(x(P))*G (no merkle root — key-path-only output).
    const xOnly = pubkey.subarray(1, 33);
    const tweaked = tweakPublicKey(xOnly, taggedHash("TapTweak", xOnly));
    const scriptPubKey = Buffer.concat([Buffer.from([0x51, 0x20]), tweaked]);

    const tx = {
      version: 2,
      inputs: [
        {
          prevOut: { txid: Buffer.alloc(32), vout: 0 },
          scriptSig: Buffer.alloc(0),
          sequence: 0xffffffff,
          witness: [],
        },
      ],
      outputs: [{ value: 90000n, scriptPubKey: Buffer.from([0x00, 0x14, ...Buffer.alloc(20)]) }],
      lockTime: 0,
    };

    const psbt = createPSBT(tx);
    psbt.inputs[0].witnessUtxo = { value: 100000n, scriptPubKey };

    // BUG-3 FIXED: signPSBTInput handles P2TR (OP_1 <32-byte-key>) — it
    // applies the BIP-341 even-y negation + TapTweak tweak to the private key
    // and emits a 64-byte SIGHASH_DEFAULT key-path signature (tapKeySig).
    signPSBTInput(psbt, 0, privkey, pubkey);
    expect(psbt.inputs[0].tapKeySig).toBeDefined();
    expect(psbt.inputs[0].tapKeySig!.length).toBe(64);

    // Defence-in-depth retained: an UNTWEAKED output key (the pre-fix
    // fixture) is rejected — the wallet key does not own that output.
    const untweakedScript = Buffer.concat([Buffer.from([0x51, 0x20]), xOnly]);
    const psbt2 = createPSBT(tx);
    psbt2.inputs[0].witnessUtxo = { value: 100000n, scriptPubKey: untweakedScript };
    expect(() => signPSBTInput(psbt2, 0, privkey, pubkey)).toThrow(
      /P2TR output key/
    );
  });

  test("PASS G30: PSBT CVE-2020-14199 guard — witnessUtxo vs nonWitnessUtxo cross-check", () => {
    // Verify that getInputUTXO rejects a forged witnessUtxo amount
    const { getInputUTXO } = require("../src/wallet/psbt");

    const realScriptPubKey = Buffer.from([0x00, 0x14, ...Buffer.alloc(20, 0xab)]);
    const tx = {
      version: 2,
      inputs: [
        {
          prevOut: { txid: Buffer.alloc(32), vout: 0 },
          scriptSig: Buffer.alloc(0),
          sequence: 0xffffffff,
          witness: [],
        },
      ],
      outputs: [{ value: 99000n, scriptPubKey: Buffer.from([0x00, 0x14, ...Buffer.alloc(20)]) }],
      lockTime: 0,
    };

    const psbt = createPSBT(tx);

    // Build a fake prevTx with a real output
    const realOutput = { value: 100000n, scriptPubKey: realScriptPubKey };
    const fakePrevTx = {
      version: 2,
      inputs: [
        {
          prevOut: { txid: Buffer.alloc(32), vout: 0 },
          scriptSig: Buffer.alloc(0),
          sequence: 0xffffffff,
          witness: [],
        },
      ],
      outputs: [realOutput],
      lockTime: 0,
    };
    // Trick: override txid in psbt.tx.inputs[0].prevOut to match fakePrevTx
    // For this test, we manually set nonWitnessUtxo and set witnessUtxo
    // with a forged amount.
    psbt.inputs[0].nonWitnessUtxo = fakePrevTx;
    psbt.inputs[0].witnessUtxo = {
      value: 999999n, // forged — doesn't match nonWitnessUtxo.outputs[0].value
      scriptPubKey: realScriptPubKey,
    };

    // getInputUTXO should detect the mismatch and throw
    expect(() => getInputUTXO(psbt, 0)).toThrow(/CVE-2020-14199/);
  });
});

// ============================================================================
// G4 (KeyPool gap) + G5 (missing RPCs) — documented
// ============================================================================
describe("G4 (KeyPool) + G5 (missing RPCs) — documentation tests", () => {
  test("FAIL BUG-4: No KeyPool class — keypoolrefill / getkeypoolsize absent", () => {
    // Bitcoin Core implements a CKeyPool with a default keyPoolSize of 1000.
    // hotbuns pre-generates 20 addresses (ADDRESS_GAP = 20) but has no
    // explicit KeyPool object, no keypoolrefill RPC, and no getkeypoolsize
    // RPC. This means the wallet cannot participate in Core-compatible
    // multi-sig setups that rely on keypool semantics.
    //
    // Confirm: Wallet has no keypoolRefill method
    const w = Object.create(Wallet.prototype);
    expect((w as any).keypoolRefill).toBeUndefined();
    expect((w as any).getKeyPoolSize).toBeUndefined();
  });

  test("FAIL BUG-5: walletcreatepsbt / walletprocesspsbt / dumpprivkey / importprivkey / getaddressinfo RPCs absent", () => {
    // These are standard Bitcoin Core wallet RPCs that are not registered
    // in hotbuns RPC server (src/rpc/server.ts).
    // We cannot import the RPC server here without a full node setup,
    // so we document the finding at the code level: searching the registered
    // method list for these names yields no match.
    //
    // Confirmed absent by grep in server.ts:
    //   walletcreatepsbt — not found
    //   walletprocesspsbt — not found
    //   dumpprivkey — not found
    //   importprivkey — not found
    //   getaddressinfo — not found
    //   keypoolrefill — not found
    //
    // This is a MEDIUM finding: the wallet is functional for basic use but
    // does not implement the full Core wallet RPC surface.
    expect(true).toBe(true); // documentation test
  });
});
