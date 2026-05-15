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

// =====================================================================
// BIP-21 URI parser  (W119 BUG-2 / G28+G29 closure — FIX-62)
// =====================================================================
//
// Format (BIP-21 + BIP-78 extension):
//   bitcoin:<address>[?<query>]
//   query    = key=value("&"key=value)*
//   key      = ALPHA *(ALPHA / DIGIT / "+" / "-" / ".")
//   value    = pct-encoded UTF-8
//
// Recognized params:
//   amount   — decimal BTC, converted to bigint satoshis (lossless 8 dp)
//   label    — UTF-8, percent-decoded
//   message  — UTF-8, percent-decoded
//   lightning — BOLT-11 invoice / BIP-353 fallback (string, no parsing)
//   pj       — BIP-78 PayJoin endpoint URL (string)
//   pjos     — BIP-78 disableoutputsubstitution; "0" => false, "1" => true
//   req-X    — REQUIRED param the wallet does not understand → REJECT
//   other    — stored verbatim in `extras`
//
// Key matching is case-insensitive (per BIP-21 "querykey ... is case
// insensitive"). The scheme prefix "bitcoin:" is case-insensitive too.
// The address itself is passed through to `decodeAddress` for syntactic +
// checksum validation; mismatched network → error.

export type Network = "mainnet" | "testnet" | "regtest";

export interface Bip21Uri {
  address: string;
  amount?: bigint; // satoshis
  label?: string;
  message?: string;
  lightning?: string;
  pj?: string;
  pjos?: boolean; // false = output substitution disabled
  extras?: Record<string, string>;
}

export type Bip21Error =
  | { ok: false; kind: "scheme"; message: string }
  | { ok: false; kind: "empty"; message: string }
  | { ok: false; kind: "address"; message: string }
  | { ok: false; kind: "network"; message: string }
  | { ok: false; kind: "query"; message: string }
  | { ok: false; kind: "pct"; message: string }
  | { ok: false; kind: "amount"; message: string }
  | { ok: false; kind: "pjos"; message: string }
  | { ok: false; kind: "duplicate"; message: string }
  | { ok: false; kind: "req-unknown"; message: string; param: string };

export type Bip21Result = ({ ok: true } & Bip21Uri) | Bip21Error;

/**
 * Percent-decode a query string component to a UTF-8 string.
 * Returns null if the input contains a malformed escape.
 *
 * Spec: BIP-21 inherits RFC-3986 §2.1 percent-encoding. "+" is NOT
 * decoded to space — that's `application/x-www-form-urlencoded`, not
 * RFC-3986. We use TextDecoder({ fatal: true }) to surface invalid UTF-8.
 */
function pctDecode(s: string): string | null {
  // Fast path: nothing to decode.
  if (s.indexOf("%") === -1) return s;

  const bytes: number[] = [];
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c === 0x25 /* '%' */) {
      if (i + 2 >= s.length) return null;
      const hi = s.charCodeAt(i + 1);
      const lo = s.charCodeAt(i + 2);
      const hv = hexDigit(hi);
      const lv = hexDigit(lo);
      if (hv < 0 || lv < 0) return null;
      bytes.push((hv << 4) | lv);
      i += 2;
    } else if (c > 0x7f) {
      // Non-ASCII char in raw input — encode as UTF-8 bytes.
      // BIP-21 examples show literal UTF-8 in label/message even though
      // strictly RFC-3986 wants %-encoding; accept both for robustness.
      const enc = new TextEncoder().encode(s[i]);
      for (let j = 0; j < enc.length; j++) bytes.push(enc[j]);
    } else {
      bytes.push(c);
    }
  }
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(new Uint8Array(bytes));
  } catch {
    return null;
  }
}

function hexDigit(c: number): number {
  if (c >= 0x30 && c <= 0x39) return c - 0x30;
  if (c >= 0x41 && c <= 0x46) return c - 0x41 + 10;
  if (c >= 0x61 && c <= 0x66) return c - 0x61 + 10;
  return -1;
}

/**
 * Parse a decimal BTC amount to bigint satoshis.
 *
 * BIP-21 grammar:   amount  =  *digit [ "." *digit ]
 *
 * - At least one digit must appear on either side of the dot.
 * - No leading sign (negative amounts invalid).
 * - No scientific notation (BIP-21 says "MUST NOT use exponential").
 * - Up to 8 fractional digits. More → reject (silently truncating would
 *   silently lose value).
 */
function parseAmountToSat(raw: string): bigint | null {
  if (raw.length === 0) return null;
  // Must be ASCII decimal digits + optional single dot.
  let dot = -1;
  for (let i = 0; i < raw.length; i++) {
    const c = raw.charCodeAt(i);
    if (c === 0x2e /* '.' */) {
      if (dot !== -1) return null; // multiple dots
      dot = i;
    } else if (!(c >= 0x30 && c <= 0x39)) {
      return null;
    }
  }
  let intPart: string;
  let fracPart: string;
  if (dot === -1) {
    intPart = raw;
    fracPart = "";
  } else {
    intPart = raw.slice(0, dot);
    fracPart = raw.slice(dot + 1);
  }
  // BIP-21 requires at least one digit overall. A bare "." is invalid.
  if (intPart.length === 0 && fracPart.length === 0) return null;
  if (fracPart.length > 8) return null; // overflow precision (10^-8 BTC = 1 sat)
  // Normalize: pad fractional to 8 digits, then read as bigint.
  const padded = fracPart.padEnd(8, "0");
  const whole = intPart === "" ? 0n : BigInt(intPart);
  const frac = padded === "" ? 0n : BigInt(padded);
  return whole * 100_000_000n + frac;
}

/**
 * Parse a BIP-21 URI string into a structured object.
 *
 * Validation gates (each returns a distinct discriminator):
 *   scheme       — input is not "bitcoin:" (case-insensitive)
 *   empty        — no address after "bitcoin:"
 *   address      — address fails decodeAddress() syntactic/checksum
 *   network      — address belongs to wrong network
 *   query        — query string structurally malformed
 *   pct          — percent-decoding produced invalid UTF-8
 *   amount       — amount param failed parseAmountToSat
 *   pjos         — pjos value is neither "0" nor "1"
 *   duplicate    — same key appears twice (excluding extras)
 *   req-unknown  — required param the parser does not handle
 *
 * `decodeAddress` is the address-side guard. Network mismatch
 * (e.g. testnet address with `network="mainnet"`) → "network" error.
 */
export function parseBip21Uri(input: string, network: Network): Bip21Result {
  if (typeof input !== "string") {
    return { ok: false, kind: "scheme", message: "input must be a string" };
  }
  // Scheme is case-insensitive. URI separators ("?", "&", "=") never
  // occur inside the scheme name so we can match on the prefix directly.
  const SCHEME = "bitcoin:";
  if (input.length < SCHEME.length || input.slice(0, SCHEME.length).toLowerCase() !== SCHEME) {
    return { ok: false, kind: "scheme", message: `URI must start with "bitcoin:"` };
  }
  const rest = input.slice(SCHEME.length);
  if (rest.length === 0) {
    return { ok: false, kind: "empty", message: "URI is missing an address" };
  }

  // Split off the query (first "?" only — "?" never appears inside an
  // address). A trailing "#fragment" is permitted by RFC-3986 and
  // ignored here (BIP-21 does not assign a fragment meaning).
  let addrPart = rest;
  let queryPart = "";
  const q = rest.indexOf("?");
  if (q !== -1) {
    addrPart = rest.slice(0, q);
    queryPart = rest.slice(q + 1);
  }
  const hash = addrPart.indexOf("#");
  if (hash !== -1) {
    addrPart = addrPart.slice(0, hash);
  }
  const qHash = queryPart.indexOf("#");
  if (qHash !== -1) {
    queryPart = queryPart.slice(0, qHash);
  }

  if (addrPart.length === 0) {
    return { ok: false, kind: "empty", message: "URI is missing an address" };
  }

  // Validate the address via decodeAddress. This catches both
  // structural (bad checksum, unknown HRP) and network errors.
  let decoded: DecodedAddress;
  try {
    decoded = decodeAddress(addrPart);
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    return { ok: false, kind: "address", message: msg };
  }
  if (decoded.network !== network) {
    return {
      ok: false,
      kind: "network",
      message: `address network ${decoded.network} does not match requested ${network}`,
    };
  }

  // Output struct.
  const out: Bip21Uri = { address: addrPart };
  const extras: Record<string, string> = {};
  let extrasUsed = false;
  // Track keys we've already seen so we can reject duplicates of
  // recognized params. Duplicates of "extras" keys are also rejected
  // because BIP-21 has no merge semantics.
  const seen = new Set<string>();

  if (queryPart.length > 0) {
    const pairs = queryPart.split("&");
    for (const pair of pairs) {
      if (pair.length === 0) continue; // tolerate "&&" or trailing "&"
      const eq = pair.indexOf("=");
      let rawKey: string;
      let rawVal: string;
      if (eq === -1) {
        // BIP-21 grammar requires "key=value". Accept "key" alone as
        // key="" so we can still flag req-foo correctly.
        rawKey = pair;
        rawVal = "";
      } else {
        rawKey = pair.slice(0, eq);
        rawVal = pair.slice(eq + 1);
      }
      if (rawKey.length === 0) {
        return { ok: false, kind: "query", message: "query has empty key" };
      }
      // Keys are NOT percent-decoded per BIP-21 (querykey grammar is
      // ALPHA / DIGIT / "+" / "-" / "."). We do case-fold them.
      const keyLower = rawKey.toLowerCase();
      const value = pctDecode(rawVal);
      if (value === null) {
        return {
          ok: false,
          kind: "pct",
          message: `malformed percent-encoding in value for "${rawKey}"`,
        };
      }

      // req-X handling: spec says wallet MUST reject the URI unless it
      // understands X. We don't understand any req-* params.
      if (keyLower.startsWith("req-")) {
        return {
          ok: false,
          kind: "req-unknown",
          message: `required parameter "${rawKey}" is not understood`,
          param: rawKey,
        };
      }

      if (seen.has(keyLower)) {
        return {
          ok: false,
          kind: "duplicate",
          message: `duplicate query parameter "${rawKey}"`,
        };
      }
      seen.add(keyLower);

      switch (keyLower) {
        case "amount": {
          const sat = parseAmountToSat(value);
          if (sat === null) {
            return { ok: false, kind: "amount", message: `invalid amount "${value}"` };
          }
          out.amount = sat;
          break;
        }
        case "label":
          out.label = value;
          break;
        case "message":
          out.message = value;
          break;
        case "lightning":
          out.lightning = value;
          break;
        case "pj":
          out.pj = value;
          break;
        case "pjos": {
          // BIP-78: "0" disables output substitution; "1" enables (default).
          if (value === "0") {
            out.pjos = false;
          } else if (value === "1") {
            out.pjos = true;
          } else {
            return {
              ok: false,
              kind: "pjos",
              message: `pjos must be "0" or "1", got "${value}"`,
            };
          }
          break;
        }
        default:
          extras[keyLower] = value;
          extrasUsed = true;
          break;
      }
    }
  }

  if (extrasUsed) {
    out.extras = extras;
  }
  return { ok: true, ...out };
}
