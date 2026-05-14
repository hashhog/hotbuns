/**
 * ASMap (Autonomous System Map) — bytecode interpreter and file loader.
 *
 * Provides a compressed mapping from IP address prefixes to Autonomous
 * System Numbers (ASNs) using a binary trie encoded as bytecode instructions.
 *
 * Reference: bitcoin-core/src/util/asmap.h/.cpp
 *
 * Wire format:
 *   - Bytecode stored LSB-first (little-endian bit ordering).
 *   - IP addresses consumed MSB-first (big-endian bit ordering).
 *   - Four instruction types: RETURN, JUMP, MATCH, DEFAULT.
 *   - Variable-length integers with a bespoke prefix-length encoding.
 */

import { createHash } from "node:crypto";
import { readFileSync, statSync } from "node:fs";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Maximum allowed asmap file size (8 MiB). Bitcoin Core enforces this limit. */
export const MAX_ASMAP_FILE_SIZE = 8_388_608; // 8 * 1024 * 1024

/** Sentinel returned by internal decoders on error / EOF. */
const INVALID = 0xffffffff;

// ---------------------------------------------------------------------------
// Instruction opcodes
// Encoding: RETURN=[0], JUMP=[1,0], MATCH=[1,1,0], DEFAULT=[1,1,1]
// ---------------------------------------------------------------------------

const enum Instruction {
  RETURN = 0,
  JUMP = 1,
  MATCH = 2,
  DEFAULT = 3,
}

// ---------------------------------------------------------------------------
// Bit readers
// ---------------------------------------------------------------------------

/**
 * Read one bit from `bytes` at `bitpos` using little-endian bit ordering
 * (LSB first within each byte).  Used for the asmap bytecode.
 * Mutates `state.pos`.
 */
function consumeBitLE(bytes: Uint8Array, state: { pos: number }): boolean {
  const pos = state.pos;
  const bit = (bytes[pos >>> 3]! >>> (pos & 7)) & 1;
  state.pos = pos + 1;
  return bit === 1;
}

/**
 * Read one bit from `bytes` at `bitpos` using big-endian bit ordering
 * (MSB first within each byte).  Used for IP address consumption so that
 * the most-significant bit of the address is inspected first, matching
 * network byte order.
 * Mutates `state.pos`.
 */
function consumeBitBE(bytes: Uint8Array, state: { pos: number }): boolean {
  const pos = state.pos;
  const bit = (bytes[pos >>> 3]! >>> (7 - (pos & 7))) & 1;
  state.pos = pos + 1;
  return bit === 1;
}

// ---------------------------------------------------------------------------
// Variable-length integer decoder
// ---------------------------------------------------------------------------

/**
 * Decode a variable-length integer from the asmap bytecode.
 *
 * Encoding scheme (example with minval=100, bit_sizes=[4,2,2,3]):
 *   x ∈ [100..115] → [0] + [4-bit BE of (x-100)]
 *   x ∈ [116..119] → [1,0] + [2-bit BE of (x-116)]
 *   x ∈ [120..123] → [1,1,0] + [2-bit BE of (x-120)]
 *   x ∈ [124..131] → [1,1,1] + [3-bit BE of (x-124)]
 *
 * In general: k leading "1" continuation bits (k = class index), then a
 * "0" separator (except for the last class), then `bit_sizes[k]` bits in
 * big-endian encoding the position within that class.
 *
 * Returns INVALID on EOF.
 */
function decodeBits(
  data: Uint8Array,
  state: { pos: number },
  minval: number,
  bitSizes: readonly number[],
): number {
  const endBit = data.length * 8;
  let val = minval;

  for (let k = 0; k < bitSizes.length; k++) {
    const sz = bitSizes[k]!;
    const isLast = k === bitSizes.length - 1;
    let contBit = false;
    if (!isLast) {
      if (state.pos >= endBit) return INVALID;
      contBit = consumeBitLE(data, state);
    }
    if (contBit) {
      // This number is in a higher class; add the size of this class and continue.
      val += 1 << sz;
    } else {
      // Decode `sz` mantissa bits in big-endian order within the class.
      for (let b = 0; b < sz; b++) {
        if (state.pos >= endBit) return INVALID;
        const bit = consumeBitLE(data, state) ? 1 : 0;
        val += bit << (sz - 1 - b);
      }
      return val;
    }
  }
  return INVALID; // Reached EOF in exponent part
}

// Encoding tables (mirrors asmap.cpp)
const TYPE_BIT_SIZES  = [0, 0, 1] as const;  // Opcode: 2-bit class with 0/0/1 payload bits
const ASN_BIT_SIZES   = [15, 16, 17, 18, 19, 20, 21, 22, 23, 24] as const;
const MATCH_BIT_SIZES = [1, 2, 3, 4, 5, 6, 7, 8] as const;
const JUMP_BIT_SIZES  = [
  5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
  21, 22, 23, 24, 25, 26, 27, 28, 29, 30,
] as const;

function decodeType(data: Uint8Array, state: { pos: number }): Instruction {
  return decodeBits(data, state, 0, TYPE_BIT_SIZES) as Instruction;
}

function decodeASN(data: Uint8Array, state: { pos: number }): number {
  return decodeBits(data, state, 1, ASN_BIT_SIZES);
}

function decodeMatch(data: Uint8Array, state: { pos: number }): number {
  return decodeBits(data, state, 2, MATCH_BIT_SIZES);
}

function decodeJump(data: Uint8Array, state: { pos: number }): number {
  return decodeBits(data, state, 17, JUMP_BIT_SIZES);
}

// ---------------------------------------------------------------------------
// Core interpreter
// ---------------------------------------------------------------------------

/**
 * Execute the ASMap bytecode to find the ASN for an IP address.
 *
 * @param asmap  Raw asmap bytecode (LSB-first bit ordering).
 * @param ip     IP address bytes (MSB-first, 16 bytes for IPv6, 4 for IPv4).
 * @returns      ASN (≥1), or 0 if no mapping found.
 */
export function interpret(asmap: Uint8Array, ip: Uint8Array): number {
  const asmState = { pos: 0 };
  const ipState  = { pos: 0 };
  const endBit   = asmap.length * 8;
  const ipEndBit = ip.length * 8;
  let defaultAsn = 0;

  while (asmState.pos < endBit) {
    const opcode = decodeType(asmap, asmState);

    if (opcode === Instruction.RETURN) {
      const asn = decodeASN(asmap, asmState);
      if (asn === INVALID) break;
      return asn;

    } else if (opcode === Instruction.JUMP) {
      const jump = decodeJump(asmap, asmState);
      if (jump === INVALID) break;
      if (ipState.pos >= ipEndBit) break;
      if (jump >= endBit - asmState.pos) break;
      if (consumeBitBE(ip, ipState)) {
        asmState.pos += jump; // IP bit = 1 → jump to right subtree
      }
      // IP bit = 0 → fall through to left subtree

    } else if (opcode === Instruction.MATCH) {
      const match = decodeMatch(asmap, asmState);
      if (match === INVALID) break;
      // Bit-width of match value encodes length: n = bit_width(match) - 1
      let matchlen = 0;
      let tmp = match;
      while (tmp > 1) { tmp >>>= 1; matchlen++; }
      if (ipEndBit - ipState.pos < matchlen) break;
      let matched = true;
      for (let b = 0; b < matchlen; b++) {
        const ipBit = consumeBitBE(ip, ipState) ? 1 : 0;
        const patBit = (match >>> (matchlen - 1 - b)) & 1;
        if (ipBit !== patBit) { matched = false; break; }
      }
      if (!matched) return defaultAsn;

    } else if (opcode === Instruction.DEFAULT) {
      const asn = decodeASN(asmap, asmState);
      if (asn === INVALID) break;
      defaultAsn = asn;

    } else {
      break;
    }
  }

  // Reached EOF without RETURN or hit an error.
  // A well-formed (sanity-checked) asmap should never reach here.
  return 0;
}

// ---------------------------------------------------------------------------
// Sanity checker
// ---------------------------------------------------------------------------

/**
 * Structural validation of asmap bytecode.
 *
 * Simulates all possible execution paths.  Returns true iff the bytecode
 * is well-formed: valid jumps, proper termination, no unreachable code,
 * and zero-padded EOF.
 *
 * @param asmap  Raw asmap bytecode.
 * @param bits   Number of IP bits the asmap is designed for (128 for IPv6).
 */
export function sanityCheckAsmap(asmap: Uint8Array, bits: number): boolean {
  const asmState = { pos: 0 };
  const endBit   = asmap.length * 8;

  // Stack of [jumpTargetBitOffset, bitsRemaining] entries for pending jumps.
  const jumps: Array<[number, number]> = [];
  let prevOpcode: Instruction = Instruction.JUMP; // dummy start
  let hadIncompleteMatch = false;

  while (asmState.pos !== endBit) {
    // Detect a jump that lands inside a previous instruction.
    if (jumps.length > 0 && asmState.pos >= jumps[jumps.length - 1]![0]) {
      return false;
    }

    const opcode = decodeType(asmap, asmState);

    if (opcode === Instruction.RETURN) {
      if (prevOpcode === Instruction.DEFAULT) return false; // RETURN after DEFAULT is redundant
      const asn = decodeASN(asmap, asmState);
      if (asn === INVALID) return false;

      if (jumps.length === 0) {
        // No more branches — we're at the final RETURN.
        if (endBit - asmState.pos > 7) return false; // Too much padding
        while (asmState.pos !== endBit) {
          if (consumeBitLE(asmap, asmState)) return false; // Non-zero padding
        }
        return true;
      } else {
        // Pretend we jumped to the queued target.
        const [target, savedBits] = jumps[jumps.length - 1]!;
        if (asmState.pos !== target) return false; // Unreachable code between RETURN and jump target
        bits = savedBits;
        jumps.pop();
        prevOpcode = Instruction.JUMP;
      }

    } else if (opcode === Instruction.JUMP) {
      const jump = decodeJump(asmap, asmState);
      if (jump === INVALID) return false;
      if (jump > endBit - asmState.pos) return false;
      if (bits === 0) return false; // Would consume past IP end
      bits--;
      const target = asmState.pos + jump;
      if (jumps.length > 0 && target >= jumps[jumps.length - 1]![0]) return false; // Intersecting jumps
      jumps.push([target, bits]);
      prevOpcode = Instruction.JUMP;

    } else if (opcode === Instruction.MATCH) {
      const match = decodeMatch(asmap, asmState);
      if (match === INVALID) return false;
      let matchlen = 0;
      let tmp = match;
      while (tmp > 1) { tmp >>>= 1; matchlen++; }
      if (prevOpcode !== Instruction.MATCH) hadIncompleteMatch = false;
      if (matchlen < 8 && hadIncompleteMatch) return false; // Only one short match per sequence
      hadIncompleteMatch = matchlen < 8;
      if (bits < matchlen) return false;
      bits -= matchlen;
      prevOpcode = Instruction.MATCH;

    } else if (opcode === Instruction.DEFAULT) {
      if (prevOpcode === Instruction.DEFAULT) return false; // Two successive DEFAULTs redundant
      const asn = decodeASN(asmap, asmState);
      if (asn === INVALID) return false;
      prevOpcode = Instruction.DEFAULT;

    } else {
      return false;
    }
  }
  return false; // Reached EOF without RETURN
}

/**
 * Validate asmap data for standard 128-bit (IPv6) inputs.
 * Mirrors Bitcoin Core's CheckStandardAsmap().
 */
export function checkStandardAsmap(data: Uint8Array): boolean {
  return sanityCheckAsmap(data, 128);
}

// ---------------------------------------------------------------------------
// File loader
// ---------------------------------------------------------------------------

/**
 * Read an asmap file from disk, enforce the 8 MiB size limit, and validate
 * the bytecode with checkStandardAsmap().
 *
 * Returns the raw bytes on success, or null on any error (missing file,
 * too large, or sanity-check failure).  Mirrors Bitcoin Core's DecodeAsmap().
 *
 * @param filePath  Absolute path to the asmap binary file.
 */
export function loadAsmap(filePath: string): Uint8Array | null {
  let stat: ReturnType<typeof statSync>;
  try {
    stat = statSync(filePath);
  } catch {
    return null;
  }
  if (stat.size > MAX_ASMAP_FILE_SIZE) {
    return null;
  }
  let buf: Buffer;
  try {
    buf = readFileSync(filePath);
  } catch {
    return null;
  }
  const data = new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
  if (!checkStandardAsmap(data)) {
    return null;
  }
  return data;
}

// ---------------------------------------------------------------------------
// Version checksum
// ---------------------------------------------------------------------------

/**
 * Compute a SHA-256 checksum of the raw asmap bytes.
 * Returned as a 32-byte hex string.
 * Mirrors Bitcoin Core's AsmapVersion() (single SHA-256 over the raw data).
 */
export function asmapVersion(data: Uint8Array): string {
  return createHash("sha256").update(data).digest("hex");
}

// ---------------------------------------------------------------------------
// IPv4-in-IPv6 mapping helper
// ---------------------------------------------------------------------------

/**
 * IPv4-in-IPv6 prefix: ::ffff:0:0/96 (RFC 4291 section 2.5.5.2).
 * 80 zero bits, 16 ones bits, then 32 bits of IPv4.
 */
const IPV4_IN_IPV6_PREFIX = new Uint8Array([
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff,
]);

/**
 * Convert a 4-byte IPv4 address to the 16-byte IPv4-in-IPv6 representation
 * required by the asmap trie (which is always 128-bit).
 *
 * Mirrors Bitcoin Core's netgroup.cpp GetMappedAS() IPv4 promotion.
 */
export function ipv4ToMappedIPv6(ipv4: Uint8Array): Uint8Array {
  const result = new Uint8Array(16);
  result.set(IPV4_IN_IPV6_PREFIX, 0);
  result.set(ipv4, 12);
  return result;
}

/**
 * Parse an IPv4 dotted-decimal string ("a.b.c.d") into 4 bytes.
 * Returns null on parse failure.
 */
export function parseIPv4(addr: string): Uint8Array | null {
  const parts = addr.split(".");
  if (parts.length !== 4) return null;
  const bytes = new Uint8Array(4);
  for (let i = 0; i < 4; i++) {
    const n = parseInt(parts[i]!, 10);
    if (isNaN(n) || n < 0 || n > 255 || String(n) !== parts[i]) return null;
    bytes[i] = n;
  }
  return bytes;
}

/**
 * Parse an IPv6 address string (with optional :: compression) into 16 bytes.
 * Returns null on parse failure.
 */
export function parseIPv6(addr: string): Uint8Array | null {
  // Strip brackets if present ([::1])
  const stripped = addr.replace(/^\[|\]$/g, "");
  const bytes = new Uint8Array(16);

  if (stripped.includes("::")) {
    const sides = stripped.split("::");
    if (sides.length !== 2) return null;
    const leftGroups  = sides[0] ? sides[0].split(":") : [];
    const rightGroups = sides[1] ? sides[1].split(":") : [];
    const totalKnown  = leftGroups.length + rightGroups.length;
    if (totalKnown > 8) return null;
    const zeros = 8 - totalKnown;
    const groups: string[] = [
      ...leftGroups,
      ...Array(zeros).fill("0"),
      ...rightGroups,
    ];
    for (let i = 0; i < 8; i++) {
      const val = parseInt(groups[i]!, 16);
      if (isNaN(val) || val < 0 || val > 0xffff) return null;
      bytes[i * 2]     = (val >>> 8) & 0xff;
      bytes[i * 2 + 1] = val & 0xff;
    }
  } else {
    const groups = stripped.split(":");
    if (groups.length !== 8) return null;
    for (let i = 0; i < 8; i++) {
      const val = parseInt(groups[i]!, 16);
      if (isNaN(val) || val < 0 || val > 0xffff) return null;
      bytes[i * 2]     = (val >>> 8) & 0xff;
      bytes[i * 2 + 1] = val & 0xff;
    }
  }
  return bytes;
}

/**
 * Look up the ASN for an IP address string (IPv4 or IPv6).
 *
 * - IPv4: promoted to 128-bit ::ffff:0:0/96 before lookup.
 * - IPv6: used as-is.
 * - Anything else (hostname, Tor, I2P, etc.): returns 0.
 *
 * Returns 0 if asmap is null/empty or the address is not IPv4/IPv6.
 * AS0 is reserved (RFC 7607) and means "no ASN / unmapped".
 *
 * Mirrors Bitcoin Core's NetGroupManager::GetMappedAS().
 */
export function getMappedAS(
  asmapData: Uint8Array | null,
  addr: string,
): number {
  if (!asmapData || asmapData.length === 0) return 0;

  let ip128: Uint8Array | null = null;

  if (addr.includes(":")) {
    // IPv6
    ip128 = parseIPv6(addr);
  } else {
    // Try IPv4
    const ipv4 = parseIPv4(addr);
    if (ipv4) {
      ip128 = ipv4ToMappedIPv6(ipv4);
    }
  }

  if (!ip128) return 0; // Tor, I2P, hostname, etc.

  const asn = interpret(asmapData, ip128);
  return asn === INVALID ? 0 : asn;
}

/**
 * Compute the ASN-based net group for an IP address when asmap is loaded.
 *
 * Mirrors Bitcoin Core's NetGroupManager::GetGroup():
 *   - If GetMappedAS returns non-zero, encode as [2, asn_byte0..3] (5-byte group).
 *   - Otherwise fall back to IP-prefix grouping.
 *
 * The returned Uint8Array is used as a bucket key, matching Core's byte-vector.
 *
 * @param asmapData  Loaded asmap bytes, or null for prefix-only mode.
 * @param addr       Peer address string.
 */
export function getAsnGroup(
  asmapData: Uint8Array | null,
  addr: string,
): Uint8Array {
  if (asmapData && asmapData.length > 0) {
    const asn = getMappedAS(asmapData, addr);
    if (asn !== 0) {
      // Core encodes as NET_IPV6 (2) + 4-byte big-endian ASN
      return new Uint8Array([
        2,
        (asn >>> 24) & 0xff,
        (asn >>> 16) & 0xff,
        (asn >>> 8)  & 0xff,
        asn & 0xff,
      ]);
    }
  }
  // Fallback: IPv4 /16 or IPv6 /32 prefix encoding
  return _prefixGroup(addr);
}

/** Internal: compute a byte-vector group from IP prefix (no ASN). */
function _prefixGroup(addr: string): Uint8Array {
  if (addr.includes(":")) {
    const ipv6 = parseIPv6(addr);
    if (ipv6) {
      // /32 = first 4 bytes  → [NET_IPV6=2, b0, b1, b2, b3]
      return new Uint8Array([2, ipv6[0]!, ipv6[1]!, ipv6[2]!, ipv6[3]!]);
    }
    return new Uint8Array([2]); // degenerate
  }
  const ipv4 = parseIPv4(addr);
  if (ipv4) {
    // /16 = first 2 bytes → [NET_IPV4=1, b0, b1]
    return new Uint8Array([1, ipv4[0]!, ipv4[1]!]);
  }
  // Other (Tor, hostname) → [NET_UNROUTABLE=0]
  return new Uint8Array([0]);
}
