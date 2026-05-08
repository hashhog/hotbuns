/**
 * BIP-39: Mnemonic ↔ entropy encoding + checksum validation.
 *
 * Spec: https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
 *
 * Algorithm:
 *   ENT = entropy (128, 160, 192, 224, or 256 bits = 16/20/24/28/32 bytes)
 *   CS  = ENT / 32         (checksum bits = 4, 5, 6, 7, 8)
 *   MS  = (ENT + CS) / 11  (mnemonic words = 12, 15, 18, 21, 24)
 *
 *   1. Compute SHA-256 of the entropy; take the first CS bits as the checksum.
 *   2. Concatenate (entropy || checksum); split into 11-bit groups.
 *   3. Each 11-bit group → wordlist index (0..2047).
 *
 * NOTE: Per BIP-39 spec, `mnemonicToSeed` (PBKDF2-SHA512 in wallet.ts) does
 * NOT validate the checksum — by design, *any* UTF-8 string is a "valid"
 * input to PBKDF2. The checksum gate must be applied at the user-input
 * boundary (RPC handler / restoreFromMnemonic) so that a typo'd mnemonic
 * fails loudly instead of silently producing a different-but-plausible seed.
 *
 * This module only handles the English wordlist. Adding other wordlists is
 * straightforward but unnecessary today (Bitcoin Core, all 9 sister impls,
 * and every major wallet vendor default to English).
 */

import { sha256 } from "@noble/hashes/sha2.js";
import { randomBytes } from "@noble/ciphers/utils.js";

import { BIP39_ENGLISH_WORDLIST } from "./bip39_english_wordlist.js";

// Build a word→index map once at module load. Lookup must reject unknown
// words (the wordlist is closed; any other word is a typo or wrong language).
const WORD_TO_INDEX: ReadonlyMap<string, number> = new Map(
  BIP39_ENGLISH_WORDLIST.map((w, i) => [w, i] as const)
);

/** Valid entropy lengths per BIP-39 (in bytes). */
const VALID_ENTROPY_BYTE_LENGTHS = new Set([16, 20, 24, 28, 32]);

/** Valid mnemonic word counts per BIP-39. */
const VALID_WORD_COUNTS = new Set([12, 15, 18, 21, 24]);

/**
 * Convert raw entropy → mnemonic (array of words).
 *
 * @param entropy 16/20/24/28/32 bytes of cryptographically-random data
 * @returns 12/15/18/21/24-word mnemonic
 * @throws if entropy length is invalid
 */
export function entropyToMnemonic(entropy: Uint8Array): string[] {
  if (!VALID_ENTROPY_BYTE_LENGTHS.has(entropy.length)) {
    throw new Error(
      `BIP-39: entropy must be 16/20/24/28/32 bytes, got ${entropy.length}`
    );
  }

  const entBits = entropy.length * 8;
  const csBits = entBits / 32; // 4, 5, 6, 7, or 8

  // Checksum = first csBits of SHA-256(entropy)
  const hash = sha256(entropy);

  // Build a bit-string (entropy || checksum) of length entBits + csBits.
  // We accumulate into a single bigint so the chunking math is unambiguous.
  let bits = 0n;
  let bitLen = 0;
  for (const byte of entropy) {
    bits = (bits << 8n) | BigInt(byte);
    bitLen += 8;
  }
  // Append the top csBits from the hash's first byte (csBits ≤ 8).
  // The hash byte already holds the bits MSB-first.
  const csByte = hash[0]!;
  const csValue = csByte >> (8 - csBits); // top csBits, right-justified
  bits = (bits << BigInt(csBits)) | BigInt(csValue);
  bitLen += csBits;

  // Now slice into 11-bit chunks, MSB-first.
  const wordCount = bitLen / 11;
  const words: string[] = new Array(wordCount);
  const mask11 = 0x7ffn; // 11 bits = 0..2047
  for (let i = wordCount - 1; i >= 0; i--) {
    const idx = Number(bits & mask11);
    bits >>= 11n;
    const word = BIP39_ENGLISH_WORDLIST[idx];
    if (word === undefined) {
      // Defense-in-depth: cannot happen for a well-formed 11-bit slice.
      throw new Error(`BIP-39: internal error — wordlist index ${idx} out of range`);
    }
    words[i] = word;
  }

  return words;
}

/**
 * Convert mnemonic (array of words) → raw entropy.
 *
 * Validates:
 *   - word count is 12/15/18/21/24
 *   - every word is in the English wordlist
 *   - the trailing checksum bits match SHA-256(entropy)
 *
 * @throws on any of the above failures (loud, with a clear message).
 */
export function mnemonicToEntropy(mnemonic: string[]): Uint8Array {
  if (!VALID_WORD_COUNTS.has(mnemonic.length)) {
    throw new Error(
      `BIP-39: mnemonic must be 12/15/18/21/24 words, got ${mnemonic.length}`
    );
  }

  // Look up each word; track the first unknown so the error message names it.
  let bits = 0n;
  for (const word of mnemonic) {
    const idx = WORD_TO_INDEX.get(word);
    if (idx === undefined) {
      throw new Error(`BIP-39: unknown word "${word}" (not in English wordlist)`);
    }
    bits = (bits << 11n) | BigInt(idx);
  }

  const totalBits = mnemonic.length * 11;
  const csBits = totalBits / 33; // = entBits/32; integer because wordCount % 3 === 0
  const entBits = totalBits - csBits;
  const entBytes = entBits / 8;

  // Split off the checksum (low csBits) and the entropy (next entBits).
  const csMask = (1n << BigInt(csBits)) - 1n;
  const claimedChecksum = Number(bits & csMask);
  const entropyBig = bits >> BigInt(csBits);

  // Serialize entropy as big-endian bytes.
  const entropy = new Uint8Array(entBytes);
  let tmp = entropyBig;
  for (let i = entBytes - 1; i >= 0; i--) {
    entropy[i] = Number(tmp & 0xffn);
    tmp >>= 8n;
  }

  // Recompute the expected checksum and compare.
  const expectedChecksumByte = sha256(entropy)[0]!;
  const expectedChecksum = expectedChecksumByte >> (8 - csBits);
  if (claimedChecksum !== expectedChecksum) {
    throw new Error(
      "BIP-39: mnemonic checksum mismatch (likely a typo or corrupt backup)"
    );
  }

  return entropy;
}

/**
 * Validate a mnemonic. Throws with a clear error on failure.
 *
 * Use this at the user-input boundary (RPC handler, CLI flag parser, etc.)
 * BEFORE calling `mnemonicToSeed`. PBKDF2 is happy with any UTF-8 input,
 * so without this gate a typo silently produces a different-but-valid seed.
 */
export function validateMnemonic(mnemonic: string[]): void {
  // mnemonicToEntropy does all the checks (length, wordlist, checksum).
  mnemonicToEntropy(mnemonic);
}

/**
 * Generate a fresh random mnemonic.
 *
 * @param entropyBits 128 (default) | 160 | 192 | 224 | 256
 */
export function generateMnemonic(entropyBits: number = 128): string[] {
  if (entropyBits % 32 !== 0 || entropyBits < 128 || entropyBits > 256) {
    throw new Error(
      `BIP-39: entropyBits must be one of 128/160/192/224/256, got ${entropyBits}`
    );
  }
  const entropy = randomBytes(entropyBits / 8);
  return entropyToMnemonic(entropy);
}

/**
 * Parse a mnemonic that was supplied as a single string (the format users
 * typically copy-paste from a backup card). Splits on any run of ASCII
 * whitespace and lowercases each word.
 *
 * Note: BIP-39 §"Wordlist" calls for NFKD normalization of the mnemonic
 * sentence when producing the seed (which `mnemonicToSeed` already does).
 * For wordlist *lookup* the English list contains only ASCII lowercase, so
 * lowercasing + whitespace-split is sufficient and matches every other impl
 * in this fleet.
 */
export function parseMnemonicString(mnemonicSentence: string): string[] {
  return mnemonicSentence
    .normalize("NFKD")
    .trim()
    .split(/\s+/u)
    .map((w) => w.toLowerCase());
}
