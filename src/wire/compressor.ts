/**
 * Bitcoin Core-compatible amount and script compression for UTXO snapshots.
 *
 * Implements:
 *   - Pieter Wuille's VarInt (the "varint mode default" used by Coin::Serialize),
 *     distinct from the wire-level CompactSize used in p2p messages.
 *   - CompressAmount / DecompressAmount (compressor.cpp).
 *   - CompressScript / DecompressScript (compressor.cpp).
 *   - TxOutCompression: VarInt(CompressAmount(value)) + ScriptCompression(scriptPubKey).
 *
 * References:
 *   - bitcoin-core/src/compressor.{h,cpp}
 *   - bitcoin-core/src/coins.h         (Coin::Serialize)
 *   - bitcoin-core/src/serialize.h     (WriteVarInt / ReadVarInt)
 */
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { BufferWriter, BufferReader } from "./serialization.js";

/**
 * Number of recognized "special" script encodings (0x00..0x05).
 *
 * Mirrors compressor.h's `ScriptCompression::nSpecialScripts = 6`.
 */
export const NUM_SPECIAL_SCRIPTS = 6;

// Bitcoin script opcodes referenced by the script compressor.
const OP_DUP = 0x76;
const OP_HASH160 = 0xa9;
const OP_EQUALVERIFY = 0x88;
const OP_CHECKSIG = 0xac;
const OP_EQUAL = 0x87;

// ---------------------------------------------------------------------------
// VarInt (Pieter's variable-length, NOT wire-protocol CompactSize)
// ---------------------------------------------------------------------------

/**
 * Write Bitcoin Core's VARINT(default-mode) for unsigned 64-bit values.
 *
 *   while (true) {
 *     byte = (n & 0x7F) | (continuation ? 0x80 : 0)
 *     emit byte; if (n <= 0x7F) break;
 *     n = (n >> 7) - 1;
 *   }
 *   emit bytes in reverse.
 *
 * This is the encoding used by Coin::Serialize (the `code` field) and by
 * ScriptCompression (the `nSize` field). It is NOT the same as the
 * CompactSize varint used by `BufferWriter.writeVarInt` / wire-protocol.
 */
export function writeVarIntCore(writer: BufferWriter, value: bigint): void {
  if (value < 0n) {
    throw new Error("writeVarIntCore: value must be non-negative");
  }

  // Buffer at most ceil(64/7) = 10 bytes for a uint64.
  const tmp = new Uint8Array(10);
  let len = 0;
  let n = value;
  // eslint-disable-next-line no-constant-condition
  while (true) {
    const lo = Number(n & 0x7fn);
    tmp[len] = lo | (len ? 0x80 : 0x00);
    if (n <= 0x7fn) break;
    n = (n >> 7n) - 1n;
    len++;
  }
  // Emit in reverse order.
  for (let i = len; i >= 0; i--) {
    writer.writeUInt8(tmp[i]!);
  }
}

/**
 * Read Bitcoin Core's VARINT(default-mode) and return as bigint.
 */
export function readVarIntCore(reader: BufferReader): bigint {
  let n = 0n;
  // eslint-disable-next-line no-constant-condition
  while (true) {
    const ch = reader.readUInt8();
    // Match Core's overflow check on uint64_t (max >> 7).
    if (n > 0xffffffffffffffffn >> 7n) {
      throw new Error("readVarIntCore: size too large");
    }
    n = (n << 7n) | BigInt(ch & 0x7f);
    if (ch & 0x80) {
      if (n === 0xffffffffffffffffn) {
        throw new Error("readVarIntCore: size too large");
      }
      n += 1n;
    } else {
      return n;
    }
  }
}

// ---------------------------------------------------------------------------
// Amount compression
// ---------------------------------------------------------------------------

/**
 * Compress a satoshi amount as in Bitcoin Core.
 *
 *   if n == 0: return 0
 *   strip trailing zeros (e := count, max 9), n /= 10**e
 *   if e < 9: d := n%10 (in [1..9]); n /= 10; return 1 + (n*9 + d - 1)*10 + e
 *   else:                                       return 1 + (n - 1)*10 + 9
 */
export function compressAmount(n: bigint): bigint {
  if (n < 0n) {
    throw new Error("compressAmount: amount must be non-negative");
  }
  if (n === 0n) return 0n;

  let e = 0n;
  let v = n;
  while (v % 10n === 0n && e < 9n) {
    v /= 10n;
    e += 1n;
  }
  if (e < 9n) {
    const d = v % 10n;
    if (d < 1n || d > 9n) {
      throw new Error("compressAmount: invariant violated (d out of range)");
    }
    v /= 10n;
    return 1n + (v * 9n + d - 1n) * 10n + e;
  } else {
    return 1n + (v - 1n) * 10n + 9n;
  }
}

/**
 * Decompress a previously compressed amount.
 */
export function decompressAmount(x: bigint): bigint {
  if (x < 0n) {
    throw new Error("decompressAmount: input must be non-negative");
  }
  if (x === 0n) return 0n;
  let v = x - 1n;
  const e = v % 10n;
  v /= 10n;
  let n: bigint;
  if (e < 9n) {
    const d = (v % 9n) + 1n;
    v /= 9n;
    n = v * 10n + d;
  } else {
    n = v + 1n;
  }
  let exp = e;
  while (exp > 0n) {
    n *= 10n;
    exp -= 1n;
  }
  return n;
}

// ---------------------------------------------------------------------------
// Script compression
// ---------------------------------------------------------------------------

/**
 * Match P2PKH: OP_DUP OP_HASH160 <20-byte push> OP_EQUALVERIFY OP_CHECKSIG.
 */
function isToKeyID(script: Buffer): Buffer | null {
  if (
    script.length === 25 &&
    script[0] === OP_DUP &&
    script[1] === OP_HASH160 &&
    script[2] === 0x14 &&
    script[23] === OP_EQUALVERIFY &&
    script[24] === OP_CHECKSIG
  ) {
    return script.subarray(3, 23);
  }
  return null;
}

/**
 * Match P2SH: OP_HASH160 <20-byte push> OP_EQUAL.
 */
function isToScriptID(script: Buffer): Buffer | null {
  if (
    script.length === 23 &&
    script[0] === OP_HASH160 &&
    script[1] === 0x14 &&
    script[22] === OP_EQUAL
  ) {
    return script.subarray(2, 22);
  }
  return null;
}

/**
 * Match bare P2PK with compressed (33-byte) or uncompressed (65-byte) pubkey.
 *
 * Returns the raw pubkey bytes (33 or 65) or null. For uncompressed pubkeys
 * we additionally validate the point lies on secp256k1 — Core requires
 * `pubkey.IsFullyValid()` because invalid points cannot be represented in
 * compressed form (the y-parity bit would be ambiguous).
 */
function isToPubKey(script: Buffer): Buffer | null {
  if (
    script.length === 35 &&
    script[0] === 33 &&
    script[34] === OP_CHECKSIG &&
    (script[1] === 0x02 || script[1] === 0x03)
  ) {
    return script.subarray(1, 34);
  }
  if (
    script.length === 67 &&
    script[0] === 65 &&
    script[66] === OP_CHECKSIG &&
    script[1] === 0x04
  ) {
    const pubkey = script.subarray(1, 66);
    // Validate: noble's ProjectivePoint.fromBytes throws on invalid points.
    try {
      secp256k1.Point.fromBytes(pubkey);
      return pubkey;
    } catch {
      return null;
    }
  }
  return null;
}

/**
 * Compress a scriptPubKey if it matches one of the 6 special encodings.
 *
 *   0x00 = P2PKH        -> 21 bytes (0x00 || keyID20)
 *   0x01 = P2SH         -> 21 bytes (0x01 || scriptID20)
 *   0x02/0x03 = P2PK compressed pubkey (use the actual parity byte)
 *   0x04/0x05 = P2PK uncompressed pubkey, encoded as 33 bytes:
 *               leading byte = 0x04 | (y & 1), remaining 32 = pubkey x
 *
 * Returns the compressed form, or null if no special encoding applies.
 */
export function compressScript(script: Buffer): Buffer | null {
  const keyID = isToKeyID(script);
  if (keyID) {
    const out = Buffer.alloc(21);
    out[0] = 0x00;
    keyID.copy(out, 1);
    return out;
  }
  const scriptID = isToScriptID(script);
  if (scriptID) {
    const out = Buffer.alloc(21);
    out[0] = 0x01;
    scriptID.copy(out, 1);
    return out;
  }
  const pubkey = isToPubKey(script);
  if (pubkey) {
    const out = Buffer.alloc(33);
    if (pubkey.length === 33) {
      // Compressed: leading 0x02 / 0x03.
      out[0] = pubkey[0]!;
      pubkey.copy(out, 1, 1, 33);
      return out;
    }
    if (pubkey.length === 65) {
      // Uncompressed: encode parity into the leading byte.
      out[0] = 0x04 | (pubkey[64]! & 0x01);
      pubkey.copy(out, 1, 1, 33);
      return out;
    }
  }
  return null;
}

/**
 * For a given special-script type, return the on-disk payload size.
 *
 *   nSize == 0 or 1                      -> 20 bytes (P2PKH / P2SH hash)
 *   nSize == 2, 3, 4, or 5               -> 32 bytes (compressed/parity-encoded x)
 */
export function getSpecialScriptSize(nSize: number): number {
  if (nSize === 0 || nSize === 1) return 20;
  if (nSize >= 2 && nSize <= 5) return 32;
  return 0;
}

/**
 * Decompress a special-script payload back to the original scriptPubKey.
 *
 * For nSize 4/5 (uncompressed P2PK), reconstruct the (uncompressed) pubkey
 * from x and parity using libsecp256k1's point decompression. We use noble's
 * Point.fromBytes which accepts 33-byte compressed input.
 */
export function decompressScript(nSize: number, payload: Buffer): Buffer {
  switch (nSize) {
    case 0x00: {
      const out = Buffer.alloc(25);
      out[0] = OP_DUP;
      out[1] = OP_HASH160;
      out[2] = 0x14;
      payload.copy(out, 3, 0, 20);
      out[23] = OP_EQUALVERIFY;
      out[24] = OP_CHECKSIG;
      return out;
    }
    case 0x01: {
      const out = Buffer.alloc(23);
      out[0] = OP_HASH160;
      out[1] = 0x14;
      payload.copy(out, 2, 0, 20);
      out[22] = OP_EQUAL;
      return out;
    }
    case 0x02:
    case 0x03: {
      const out = Buffer.alloc(35);
      out[0] = 33;
      out[1] = nSize;
      payload.copy(out, 2, 0, 32);
      out[34] = OP_CHECKSIG;
      return out;
    }
    case 0x04:
    case 0x05: {
      // Reconstruct the compressed pubkey: parity = nSize - 2 in {0x02, 0x03}.
      const compressed = Buffer.alloc(33);
      compressed[0] = nSize - 2;
      payload.copy(compressed, 1, 0, 32);
      const point = secp256k1.Point.fromBytes(compressed);
      const uncompressed = Buffer.from(point.toBytes(false));
      if (uncompressed.length !== 65) {
        throw new Error(
          `decompressScript: pubkey decompression returned ${uncompressed.length} bytes, expected 65`
        );
      }
      const out = Buffer.alloc(67);
      out[0] = 65;
      uncompressed.copy(out, 1, 0, 65);
      out[66] = OP_CHECKSIG;
      return out;
    }
    default:
      throw new Error(`decompressScript: unknown nSize ${nSize}`);
  }
}

// ---------------------------------------------------------------------------
// TxOut compression (uses VarInt(CompressAmount(value)) || ScriptCompression)
// ---------------------------------------------------------------------------

/**
 * Serialize a TxOut using Bitcoin Core's TxOutCompression formatter:
 *   VARINT(CompressAmount(nValue)) || ScriptCompression(scriptPubKey)
 *
 * ScriptCompression = if compressible, write the special-script payload
 * (the leading byte already encodes the type, length is fixed). Otherwise
 * write VARINT(scriptSize + nSpecialScripts) followed by the raw script.
 */
export function serializeTxOutCompressed(
  writer: BufferWriter,
  value: bigint,
  scriptPubKey: Buffer
): void {
  // Amount: VARINT(CompressAmount(value)).
  writeVarIntCore(writer, compressAmount(value));

  // Script: try compressed encoding first.
  const compressed = compressScript(scriptPubKey);
  if (compressed) {
    // The leading byte already encodes the type; emit raw bytes (no length prefix).
    writer.writeBytes(compressed);
    return;
  }

  // Generic path: VARINT(size + nSpecialScripts) || raw script.
  const size = BigInt(scriptPubKey.length + NUM_SPECIAL_SCRIPTS);
  writeVarIntCore(writer, size);
  writer.writeBytes(scriptPubKey);
}

/**
 * Deserialize a TxOut written by serializeTxOutCompressed.
 *
 * Returns { value, scriptPubKey } in hotbuns' bigint+Buffer form.
 */
export function deserializeTxOutCompressed(reader: BufferReader): {
  value: bigint;
  scriptPubKey: Buffer;
} {
  const compressed = readVarIntCore(reader);
  const value = decompressAmount(compressed);

  const nSizeBig = readVarIntCore(reader);
  const nSize = Number(nSizeBig);

  if (nSize < NUM_SPECIAL_SCRIPTS) {
    const payloadLen = getSpecialScriptSize(nSize);
    const payload = reader.readBytes(payloadLen);
    const scriptPubKey = decompressScript(nSize, payload);
    return { value, scriptPubKey };
  }

  const rawSize = nSize - NUM_SPECIAL_SCRIPTS;
  const scriptPubKey = reader.readBytes(rawSize);
  return { value, scriptPubKey };
}
