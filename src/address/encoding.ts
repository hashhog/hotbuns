/**
 * Bitcoin address encoding: Base58Check, Bech32, Bech32m.
 *
 * Supports all major address types:
 * - P2PKH (Pay to Public Key Hash) - Legacy, Base58Check
 * - P2SH (Pay to Script Hash) - Legacy, Base58Check
 * - P2WPKH (Pay to Witness Public Key Hash) - SegWit v0, Bech32
 * - P2WSH (Pay to Witness Script Hash) - SegWit v0, Bech32
 * - P2TR (Pay to Taproot) - SegWit v1, Bech32m
 */

import { bech32, bech32m } from "bech32";
import { hash256, hash160 } from "../crypto/primitives.js";

// Base58 alphabet (Bitcoin standard)
const BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

// Reverse lookup table for Base58 decoding
const BASE58_MAP = new Map<string, number>();
for (let i = 0; i < BASE58_ALPHABET.length; i++) {
  BASE58_MAP.set(BASE58_ALPHABET[i], i);
}

// Version bytes for Base58Check addresses
const VERSION_BYTES = {
  P2PKH_MAINNET: 0x00,
  P2PKH_TESTNET: 0x6f,
  P2SH_MAINNET: 0x05,
  P2SH_TESTNET: 0xc4,
} as const;

// Human-readable parts for Bech32 addresses
const HRP = {
  MAINNET: "bc",
  TESTNET: "tb",
  REGTEST: "bcrt",
} as const;

export enum AddressType {
  P2PKH = "p2pkh",
  P2SH = "p2sh",
  P2WPKH = "p2wpkh",
  P2WSH = "p2wsh",
  P2TR = "p2tr",
}

export interface DecodedAddress {
  type: AddressType;
  hash: Buffer; // 20 bytes for P2PKH/P2SH/P2WPKH, 32 bytes for P2WSH/P2TR
  network: "mainnet" | "testnet" | "regtest";
}

/**
 * Encode raw bytes to Base58 string.
 * Leading zero bytes become leading '1' characters.
 */
function base58Encode(data: Buffer): string {
  // Count leading zeros
  let leadingZeros = 0;
  for (const byte of data) {
    if (byte === 0) {
      leadingZeros++;
    } else {
      break;
    }
  }

  // Convert bytes to a big integer using repeated base conversion
  // Work with the entire byte array as a big number in base 256
  const digits: number[] = [];

  for (const byte of data) {
    let carry = byte;
    for (let i = 0; i < digits.length; i++) {
      carry += digits[i] * 256;
      digits[i] = carry % 58;
      carry = Math.floor(carry / 58);
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = Math.floor(carry / 58);
    }
  }

  // Build the result string (digits are in reverse order)
  let result = "1".repeat(leadingZeros);
  for (let i = digits.length - 1; i >= 0; i--) {
    result += BASE58_ALPHABET[digits[i]];
  }

  return result;
}

/**
 * Decode a Base58 string to raw bytes.
 */
function base58Decode(str: string): Buffer {
  // Count leading '1's (they represent leading zero bytes)
  let leadingOnes = 0;
  for (const char of str) {
    if (char === "1") {
      leadingOnes++;
    } else {
      break;
    }
  }

  // Convert Base58 string to bytes
  const bytes: number[] = [];

  for (const char of str) {
    const value = BASE58_MAP.get(char);
    if (value === undefined) {
      throw new Error(`Invalid Base58 character: ${char}`);
    }

    let carry = value;
    for (let i = 0; i < bytes.length; i++) {
      carry += bytes[i] * 58;
      bytes[i] = carry % 256;
      carry = Math.floor(carry / 256);
    }
    while (carry > 0) {
      bytes.push(carry % 256);
      carry = Math.floor(carry / 256);
    }
  }

  // Add leading zeros and reverse
  const result = Buffer.alloc(leadingOnes + bytes.length);
  // Leading zeros are already 0 in the buffer
  for (let i = 0; i < bytes.length; i++) {
    result[leadingOnes + bytes.length - 1 - i] = bytes[i];
  }

  return result;
}

/**
 * Base58Check encode: payload = [version_byte || hash], append first 4 bytes of hash256 as checksum.
 */
export function base58CheckEncode(version: number, hash: Buffer): string {
  if (version < 0 || version > 255) {
    throw new Error(`Invalid version byte: ${version}`);
  }

  // Build payload: version byte + hash
  const payload = Buffer.alloc(1 + hash.length);
  payload[0] = version;
  hash.copy(payload, 1);

  // Compute checksum (first 4 bytes of double SHA-256)
  const checksum = hash256(payload).subarray(0, 4);

  // Concatenate payload and checksum
  const data = Buffer.concat([payload, checksum]);

  return base58Encode(data);
}

/**
 * Base58Check decode: validate checksum, return version byte and hash.
 */
export function base58CheckDecode(address: string): { version: number; hash: Buffer } {
  const data = base58Decode(address);

  if (data.length < 5) {
    throw new Error("Base58Check data too short");
  }

  // Split into payload and checksum
  const payload = data.subarray(0, data.length - 4);
  const checksum = data.subarray(data.length - 4);

  // Verify checksum
  const expectedChecksum = hash256(payload).subarray(0, 4);
  if (!checksum.equals(expectedChecksum)) {
    throw new Error("Invalid Base58Check checksum");
  }

  // Extract version and hash
  const version = payload[0];
  const hash = payload.subarray(1);

  return { version, hash: Buffer.from(hash) };
}

/**
 * Encode a hash to a bech32/bech32m address.
 * Witness version 0 uses bech32, version 1+ uses bech32m.
 */
export function bech32Encode(hrp: string, witnessVersion: number, hash: Buffer): string {
  if (witnessVersion < 0 || witnessVersion > 16) {
    throw new Error(`Invalid witness version: ${witnessVersion}`);
  }

  // Convert hash to 5-bit words and prepend witness version
  const words = [witnessVersion, ...bech32.toWords(hash)];

  // Use bech32 for version 0, bech32m for version 1+
  if (witnessVersion === 0) {
    return bech32.encode(hrp, words);
  } else {
    return bech32m.encode(hrp, words);
  }
}

/**
 * Decode a bech32/bech32m address. Returns witness version and hash.
 */
export function bech32Decode(address: string): { hrp: string; witnessVersion: number; hash: Buffer } {
  // Try bech32m first (for version 1+), then bech32 (for version 0)
  let decoded: { prefix: string; words: number[] };
  let usedBech32m = false;

  try {
    decoded = bech32m.decode(address);
    usedBech32m = true;
  } catch {
    try {
      decoded = bech32.decode(address);
    } catch {
      throw new Error("Invalid bech32/bech32m address");
    }
  }

  if (decoded.words.length < 1) {
    throw new Error("Invalid bech32 address: no witness version");
  }

  const witnessVersion = decoded.words[0];

  // Validate encoding type matches witness version
  if (witnessVersion === 0 && usedBech32m) {
    // Version 0 must use bech32, not bech32m
    // Try again with bech32
    try {
      decoded = bech32.decode(address);
    } catch {
      throw new Error("Witness version 0 requires bech32 encoding, not bech32m");
    }
  } else if (witnessVersion !== 0 && !usedBech32m) {
    // Version 1+ must use bech32m
    // Try again with bech32m
    try {
      decoded = bech32m.decode(address);
    } catch {
      throw new Error("Witness version 1+ requires bech32m encoding");
    }
  }

  // Convert 5-bit words back to bytes (skip witness version)
  const hash = Buffer.from(bech32.fromWords(decoded.words.slice(1)));

  return {
    hrp: decoded.prefix,
    witnessVersion,
    hash,
  };
}

/**
 * Get the HRP (human-readable part) for a given network.
 */
function getHrp(network: "mainnet" | "testnet" | "regtest"): string {
  switch (network) {
    case "mainnet":
      return HRP.MAINNET;
    case "testnet":
      return HRP.TESTNET;
    case "regtest":
      return HRP.REGTEST;
  }
}

/**
 * Get network from HRP.
 */
function networkFromHrp(hrp: string): "mainnet" | "testnet" | "regtest" {
  const hrpLower = hrp.toLowerCase();
  if (hrpLower === HRP.MAINNET) return "mainnet";
  if (hrpLower === HRP.TESTNET) return "testnet";
  if (hrpLower === HRP.REGTEST) return "regtest";
  throw new Error(`Unknown HRP: ${hrp}`);
}

/**
 * High-level: encode a DecodedAddress back to a string.
 */
export function encodeAddress(decoded: DecodedAddress): string {
  const { type, hash, network } = decoded;

  switch (type) {
    case AddressType.P2PKH: {
      const version = network === "mainnet" ? VERSION_BYTES.P2PKH_MAINNET : VERSION_BYTES.P2PKH_TESTNET;
      return base58CheckEncode(version, hash);
    }
    case AddressType.P2SH: {
      const version = network === "mainnet" ? VERSION_BYTES.P2SH_MAINNET : VERSION_BYTES.P2SH_TESTNET;
      return base58CheckEncode(version, hash);
    }
    case AddressType.P2WPKH:
      return bech32Encode(getHrp(network), 0, hash);
    case AddressType.P2WSH:
      return bech32Encode(getHrp(network), 0, hash);
    case AddressType.P2TR:
      return bech32Encode(getHrp(network), 1, hash);
    default:
      throw new Error(`Unknown address type: ${type}`);
  }
}

/**
 * High-level: decode any Bitcoin address string to a DecodedAddress.
 */
export function decodeAddress(address: string): DecodedAddress {
  // Try Base58Check first
  try {
    const { version, hash } = base58CheckDecode(address);

    // Determine type and network from version byte
    switch (version) {
      case VERSION_BYTES.P2PKH_MAINNET:
        if (hash.length !== 20) throw new Error("Invalid P2PKH hash length");
        return { type: AddressType.P2PKH, hash, network: "mainnet" };
      case VERSION_BYTES.P2PKH_TESTNET:
        if (hash.length !== 20) throw new Error("Invalid P2PKH hash length");
        return { type: AddressType.P2PKH, hash, network: "testnet" };
      case VERSION_BYTES.P2SH_MAINNET:
        if (hash.length !== 20) throw new Error("Invalid P2SH hash length");
        return { type: AddressType.P2SH, hash, network: "mainnet" };
      case VERSION_BYTES.P2SH_TESTNET:
        if (hash.length !== 20) throw new Error("Invalid P2SH hash length");
        return { type: AddressType.P2SH, hash, network: "testnet" };
      default:
        throw new Error(`Unknown version byte: 0x${version.toString(16)}`);
    }
  } catch (e) {
    // Not a valid Base58Check address, try bech32
  }

  // Try bech32/bech32m
  try {
    const { hrp, witnessVersion, hash } = bech32Decode(address);
    const network = networkFromHrp(hrp);

    // Determine type from witness version and hash length
    if (witnessVersion === 0) {
      if (hash.length === 20) {
        return { type: AddressType.P2WPKH, hash, network };
      } else if (hash.length === 32) {
        return { type: AddressType.P2WSH, hash, network };
      } else {
        throw new Error(`Invalid witness v0 program length: ${hash.length}`);
      }
    } else if (witnessVersion === 1) {
      if (hash.length === 32) {
        return { type: AddressType.P2TR, hash, network };
      } else {
        throw new Error(`Invalid witness v1 program length: ${hash.length}`);
      }
    } else {
      throw new Error(`Unsupported witness version: ${witnessVersion}`);
    }
  } catch (e) {
    if (e instanceof Error && e.message.includes("witness")) {
      throw e;
    }
    throw new Error(`Invalid Bitcoin address: ${address}`);
  }
}

/**
 * Convert a public key (compressed 33 bytes) to a P2WPKH address.
 */
export function pubkeyToP2WPKH(
  pubkey: Buffer,
  network: "mainnet" | "testnet" | "regtest"
): string {
  if (pubkey.length !== 33) {
    throw new Error(`P2WPKH requires compressed public key (33 bytes), got ${pubkey.length}`);
  }

  const hash = hash160(pubkey);
  return bech32Encode(getHrp(network), 0, hash);
}

/**
 * Convert a public key to a P2PKH address.
 */
export function pubkeyToP2PKH(
  pubkey: Buffer,
  network: "mainnet" | "testnet" | "regtest"
): string {
  if (pubkey.length !== 33 && pubkey.length !== 65) {
    throw new Error(`Invalid public key length: ${pubkey.length}`);
  }

  const hash = hash160(pubkey);
  const version = network === "mainnet" ? VERSION_BYTES.P2PKH_MAINNET : VERSION_BYTES.P2PKH_TESTNET;
  return base58CheckEncode(version, hash);
}
