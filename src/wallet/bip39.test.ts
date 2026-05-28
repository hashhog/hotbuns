/**
 * BIP-39 mnemonic ↔ entropy tests.
 *
 * Vectors copied verbatim from TREZOR's canonical BIP-39 corpus
 * (https://github.com/trezor/python-mnemonic/blob/master/vectors.json).
 * Every other Bitcoin wallet on earth uses these — if we drift from them,
 * a hotbuns-generated mnemonic will not restore in any other wallet.
 */

import { describe, expect, test, beforeEach, afterEach } from "bun:test";
import { sha512 } from "@noble/hashes/sha2.js";
import { pbkdf2 } from "@noble/hashes/pbkdf2.js";

import {
  entropyToMnemonic,
  mnemonicToEntropy,
  validateMnemonic,
  generateMnemonic,
  parseMnemonicString,
} from "./bip39";
import { BIP39_ENGLISH_WORDLIST } from "./bip39_english_wordlist";
import { Wallet, type WalletConfig } from "./wallet";
import { rmSync, mkdirSync } from "fs";

const TEST_DATADIR = "/tmp/hotbuns-bip39-test";

function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) {
    throw new Error("hexToBytes: odd-length input");
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function bytesToHex(b: Uint8Array): string {
  return Array.from(b)
    .map((x) => x.toString(16).padStart(2, "0"))
    .join("");
}

/** Compute the BIP-39 seed (PBKDF2-SHA512, 2048 iters, 64 bytes) for a vector. */
function deriveSeedHex(mnemonic: string[], passphrase: string): string {
  const sentence = mnemonic.join(" ").normalize("NFKD");
  const salt = ("mnemonic" + passphrase).normalize("NFKD");
  const seed = pbkdf2(sha512, Buffer.from(sentence, "utf-8"), Buffer.from(salt, "utf-8"), {
    c: 2048,
    dkLen: 64,
  });
  return bytesToHex(seed);
}

// ---------------------------------------------------------------------------
// TREZOR canonical vectors (selected). Format: [entropy, mnemonic, seed].
// All use passphrase="TREZOR".
// ---------------------------------------------------------------------------
const TREZOR_VECTORS: ReadonlyArray<{
  entropy: string;
  mnemonic: string;
  seed: string;
  label: string;
}> = [
  {
    label: "vector 1: 16 bytes 0x00 → 12 abandon-words",
    entropy: "00000000000000000000000000000000",
    mnemonic:
      "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
    seed:
      "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
  },
  {
    label: "vector 2: 16 bytes 0x7f → 12-word legal-winner",
    entropy: "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
    mnemonic:
      "legal winner thank year wave sausage worth useful legal winner thank yellow",
    seed:
      "2e8905819b8723fe2c1d161860e5ee1830318dbf49a83bd451cfb8440c28bd6fa457fe1296106559a3c80937a1c1069be3a3a5bd381ee6260e8d9739fce1f607",
  },
  {
    label: "vector 11: 32 bytes 0xff → 24-word zoo…vote",
    entropy: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    mnemonic:
      "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote",
    seed:
      "dd48c104698c30cfe2b6142103248622fb7bb0ff692eebb00089b32d22484e1613912f0a5b694407be899ffd31ed3992c456cdf60f5d4564b8ba3f05a69890ad",
  },
  // Two extra small vectors for round-trip coverage at every entropy size.
  {
    label: "vector A: 20 bytes → 15 words (round-trip only, no seed check)",
    entropy: "0102030405060708090a0b0c0d0e0f1011121314",
    // mnemonic + seed unused for this row; we re-derive them in the round-trip block.
    mnemonic: "",
    seed: "",
  },
  {
    label: "vector B: 28 bytes → 21 words (round-trip only, no seed check)",
    entropy: "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c",
    mnemonic: "",
    seed: "",
  },
];

// ---------------------------------------------------------------------------
// Wordlist sanity
// ---------------------------------------------------------------------------
describe("BIP-39 wordlist", () => {
  test("has exactly 2048 words", () => {
    expect(BIP39_ENGLISH_WORDLIST.length).toBe(2048);
  });

  test("starts with 'abandon' and ends with 'zoo'", () => {
    expect(BIP39_ENGLISH_WORDLIST[0]).toBe("abandon");
    expect(BIP39_ENGLISH_WORDLIST[2047]).toBe("zoo");
  });

  test("every word is unique", () => {
    expect(new Set(BIP39_ENGLISH_WORDLIST).size).toBe(2048);
  });

  test("words are sorted lexicographically (Core / TREZOR property)", () => {
    for (let i = 1; i < BIP39_ENGLISH_WORDLIST.length; i++) {
      expect(BIP39_ENGLISH_WORDLIST[i - 1]! < BIP39_ENGLISH_WORDLIST[i]!).toBe(true);
    }
  });
});

// ---------------------------------------------------------------------------
// TREZOR canonical vectors (byte-identity)
// ---------------------------------------------------------------------------
describe("BIP-39 TREZOR canonical vectors", () => {
  for (const v of TREZOR_VECTORS.slice(0, 3)) {
    test(`${v.label}: entropy → mnemonic`, () => {
      const got = entropyToMnemonic(hexToBytes(v.entropy));
      expect(got.join(" ")).toBe(v.mnemonic);
    });

    test(`${v.label}: mnemonic → entropy`, () => {
      const got = mnemonicToEntropy(v.mnemonic.split(" "));
      expect(bytesToHex(got)).toBe(v.entropy);
    });

    test(`${v.label}: PBKDF2 seed (passphrase="TREZOR") byte-identical`, () => {
      const seedHex = deriveSeedHex(v.mnemonic.split(" "), "TREZOR");
      expect(seedHex).toBe(v.seed);
    });
  }
});

// ---------------------------------------------------------------------------
// Round-trip across every entropy length
// ---------------------------------------------------------------------------
describe("BIP-39 round-trip", () => {
  test("12/15/18/21/24-word entropy → mnemonic → entropy", () => {
    for (const lenBytes of [16, 20, 24, 28, 32]) {
      // Use a deterministic non-trivial entropy so the test isn't flaky.
      const entropy = new Uint8Array(lenBytes);
      for (let i = 0; i < lenBytes; i++) entropy[i] = (i * 17 + 3) & 0xff;
      const mn = entropyToMnemonic(entropy);
      const expectedWordCount = (lenBytes * 8 + (lenBytes * 8) / 32) / 11;
      expect(mn.length).toBe(expectedWordCount);
      const back = mnemonicToEntropy(mn);
      expect(bytesToHex(back)).toBe(bytesToHex(entropy));
    }
  });

  test("generateMnemonic produces a self-consistent mnemonic at every size", () => {
    const expectedWords: Record<number, number> = {
      128: 12,
      160: 15,
      192: 18,
      224: 21,
      256: 24,
    };
    for (const bits of [128, 160, 192, 224, 256]) {
      const mn = generateMnemonic(bits);
      expect(mn.length).toBe(expectedWords[bits]!);
      const ent = mnemonicToEntropy(mn);
      expect(ent.length).toBe(bits / 8);
    }
  });
});

// ---------------------------------------------------------------------------
// Invalid-input rejection
// ---------------------------------------------------------------------------
describe("BIP-39 validation rejects bad input", () => {
  test("wrong word count throws", () => {
    expect(() => mnemonicToEntropy(["abandon", "abandon", "about"])).toThrow(
      /must be 12.15.18.21.24/i
    );
  });

  test("unknown word throws and names the offender", () => {
    const bad = [
      "abandon",
      "abandon",
      "abandon",
      "abandon",
      "abandon",
      "abandon",
      "abandon",
      "abandon",
      "abandon",
      "abandon",
      "abandon",
      "abouut", // typo — not in the wordlist
    ];
    expect(() => mnemonicToEntropy(bad)).toThrow(/abouut/);
  });

  test("checksum mismatch (single-word swap) throws", () => {
    // Take a valid mnemonic and swap the last word for a different valid
    // word from the same 11-bit-position bucket. The checksum will not match.
    const valid =
      "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".split(
        " "
      );
    const corrupted = [...valid];
    // Replace last word with a different valid word — almost always a checksum miss.
    corrupted[11] = "abandon";
    expect(() => mnemonicToEntropy(corrupted)).toThrow(/checksum mismatch/i);
  });

  test("invalid entropy length throws", () => {
    expect(() => entropyToMnemonic(new Uint8Array(13))).toThrow(/16.20.24.28.32/);
    expect(() => entropyToMnemonic(new Uint8Array(0))).toThrow();
  });

  test("validateMnemonic is silent on a good mnemonic", () => {
    expect(() =>
      validateMnemonic(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".split(
          " "
        )
      )
    ).not.toThrow();
  });
});

// ---------------------------------------------------------------------------
// Boundary test: Wallet.create must reject typo'd mnemonics, not silently
// produce a different-but-plausible seed (the W21 ouroboros UX hazard).
// ---------------------------------------------------------------------------
describe("Wallet.create checksum gate at the user-input boundary", () => {
  beforeEach(() => {
    try {
      rmSync(TEST_DATADIR, { recursive: true, force: true });
    } catch {
      /* ignore */
    }
    mkdirSync(TEST_DATADIR, { recursive: true });
  });

  afterEach(() => {
    try {
      rmSync(TEST_DATADIR, { recursive: true, force: true });
    } catch {
      /* ignore */
    }
  });

  test("accepts a canonical valid mnemonic", () => {
    const config: WalletConfig = { datadir: TEST_DATADIR, network: "mainnet" };
    const wallet = Wallet.create(
      config,
      "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    );
    expect(wallet.getSeed().length).toBe(64);
  });

  test("rejects a wordlist-valid-but-checksum-wrong mnemonic LOUDLY", () => {
    // 12 wordlist-valid English words but the trailing 4-bit checksum is wrong.
    // Replacing the last word "about" with "abandon" (which IS in the wordlist)
    // changes the trailing 11 bits, so the checksum will not match.
    const corrupted =
      "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";
    const config: WalletConfig = { datadir: TEST_DATADIR, network: "mainnet" };
    expect(() => Wallet.create(config, corrupted)).toThrow(/checksum mismatch/i);
  });

  test("rejects a mnemonic with an unknown (typo) word", () => {
    const corrupted =
      "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon aboutt";
    const config: WalletConfig = { datadir: TEST_DATADIR, network: "mainnet" };
    expect(() => Wallet.create(config, corrupted)).toThrow(/aboutt/);
  });

  test("rejects wrong word count even if all words are wordlist-valid", () => {
    const corrupted = "abandon abandon abandon"; // 3 words
    const config: WalletConfig = { datadir: TEST_DATADIR, network: "mainnet" };
    expect(() => Wallet.create(config, corrupted)).toThrow(
      /must be 12.15.18.21.24/i
    );
  });

  test("parseMnemonicString tolerates extra whitespace and case", () => {
    expect(parseMnemonicString("  ABANDON  abandon\tabout  ")).toEqual([
      "abandon",
      "abandon",
      "about",
    ]);
  });
});

// ---------------------------------------------------------------------------
// W161 BUG-12 + BUG-13 regression: Wallet.create must wire the BIP-39
// passphrase ("25th word") through to PBKDF2, with NFKD-normalised salt.
//
// Before the fix the salt was hardcoded to ASCII "mnemonic" and the
// `Wallet.create` signature had no passphrase parameter — a user restoring a
// Trezor/Ledger wallet that was generated WITH a passphrase would silently
// land in the wrong (empty) wallet.
// ---------------------------------------------------------------------------
describe("W161 BUG-12 + BUG-13: BIP-39 passphrase end-to-end through Wallet.create", () => {
  beforeEach(() => {
    try {
      rmSync(TEST_DATADIR, { recursive: true, force: true });
    } catch {
      /* ignore */
    }
    mkdirSync(TEST_DATADIR, { recursive: true });
  });

  afterEach(() => {
    try {
      rmSync(TEST_DATADIR, { recursive: true, force: true });
    } catch {
      /* ignore */
    }
  });

  test("Trezor vector 1 (abandon-words, passphrase='TREZOR') seed matches byte-for-byte", () => {
    const v = TREZOR_VECTORS[0]!; // 12 abandon-words
    const config: WalletConfig = { datadir: TEST_DATADIR, network: "mainnet" };
    const wallet = Wallet.create(config, v.mnemonic, "TREZOR");
    expect(bytesToHex(wallet.getSeed())).toBe(v.seed);
  });

  test("Trezor vector 2 (legal-winner, passphrase='TREZOR') seed matches byte-for-byte", () => {
    const v = TREZOR_VECTORS[1]!;
    const config: WalletConfig = { datadir: TEST_DATADIR, network: "mainnet" };
    const wallet = Wallet.create(config, v.mnemonic, "TREZOR");
    expect(bytesToHex(wallet.getSeed())).toBe(v.seed);
  });

  test("Trezor vector 11 (24-word zoo-vote, passphrase='TREZOR') seed matches byte-for-byte", () => {
    const v = TREZOR_VECTORS[2]!;
    const config: WalletConfig = { datadir: TEST_DATADIR, network: "mainnet" };
    const wallet = Wallet.create(config, v.mnemonic, "TREZOR");
    expect(bytesToHex(wallet.getSeed())).toBe(v.seed);
  });

  test("omitting passphrase preserves legacy behavior (salt = 'mnemonic' only)", () => {
    // Hand-verified against the BIP-39 spec for the abandon-words vector with
    // passphrase="" (the seed value used by every BIP-39 reference impl).
    const mnemonic =
      "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    const expectedSeedEmptyPassphrase =
      "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4";
    const config: WalletConfig = { datadir: TEST_DATADIR, network: "mainnet" };
    const wallet = Wallet.create(config, mnemonic); // no passphrase
    expect(bytesToHex(wallet.getSeed())).toBe(expectedSeedEmptyPassphrase);
  });

  test("different passphrases against the same mnemonic produce different seeds", () => {
    // The "plausible-deniability" property: the wallet behind passphrase
    // "alice" must be DIFFERENT from the wallet behind passphrase "bob".
    const mnemonic = TREZOR_VECTORS[0]!.mnemonic;
    const config: WalletConfig = { datadir: TEST_DATADIR, network: "mainnet" };
    const walletAlice = Wallet.create(config, mnemonic, "alice");
    rmSync(TEST_DATADIR, { recursive: true, force: true });
    mkdirSync(TEST_DATADIR, { recursive: true });
    const walletBob = Wallet.create(config, mnemonic, "bob");
    expect(bytesToHex(walletAlice.getSeed())).not.toBe(bytesToHex(walletBob.getSeed()));
  });

  test("NFKD-asymmetric passphrase: NFC vs NFD inputs produce the SAME seed (BUG-13)", () => {
    // U+00E9 (composed é) and U+0065 U+0301 (decomposed e + combining acute)
    // are different code points but NFKD-equivalent. After normalisation both
    // forms MUST hash identically — otherwise a passphrase typed in one
    // normalisation form on one device fails to restore on another.
    const mnemonic = TREZOR_VECTORS[0]!.mnemonic;
    const passphraseNFC = "café"; // "café" composed
    const passphraseNFD = "café"; // "café" decomposed
    expect(passphraseNFC).not.toBe(passphraseNFD); // different bytes on input
    const config: WalletConfig = { datadir: TEST_DATADIR, network: "mainnet" };
    const walletNFC = Wallet.create(config, mnemonic, passphraseNFC);
    rmSync(TEST_DATADIR, { recursive: true, force: true });
    mkdirSync(TEST_DATADIR, { recursive: true });
    const walletNFD = Wallet.create(config, mnemonic, passphraseNFD);
    expect(bytesToHex(walletNFC.getSeed())).toBe(bytesToHex(walletNFD.getSeed()));
  });
});

