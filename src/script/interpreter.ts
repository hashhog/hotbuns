/**
 * Bitcoin Script interpreter for transaction validation.
 *
 * Implements the Bitcoin Script virtual machine with support for:
 * - P2PKH (Pay to Public Key Hash)
 * - P2SH (Pay to Script Hash)
 * - P2WPKH (Pay to Witness Public Key Hash)
 * - P2WSH (Pay to Witness Script Hash)
 * - P2TR (Pay to Taproot) - basic support
 */

import { sha256Hash, hash256, hash160, ecdsaVerifyLax, schnorrVerify, taggedHash, tweakPublicKey } from "../crypto/primitives.js";
import { ripemd160, sha1 } from "@noble/hashes/legacy.js";
import { AddressType } from "../address/encoding.js";
import { schnorr } from "@noble/curves/secp256k1.js";

/**
 * Script execution error with a specific error code.
 */
export class ScriptError extends Error {
  constructor(public readonly code: string) {
    super(`SCRIPT_ERR_${code}`);
    this.name = "ScriptError";
  }
}

// Script limits
const MAX_SCRIPT_SIZE = 10000;
const MAX_STACK_SIZE = 1000;
const MAX_OPS_PER_SCRIPT = 201;
const MAX_ELEMENT_SIZE = 520;
const MAX_PUBKEYS_PER_MULTISIG = 20;

// Taproot constants (BIP-341/342)
const TAPROOT_LEAF_MASK = 0xfe; // Mask to strip parity bit from leaf version
const TAPROOT_LEAF_TAPSCRIPT = 0xc0; // Leaf version for BIP-342 tapscript
const TAPROOT_CONTROL_BASE_SIZE = 33; // 1 byte version + 32 byte internal key
const TAPROOT_CONTROL_NODE_SIZE = 32; // Size of each Merkle path node
const TAPROOT_CONTROL_MAX_NODE_COUNT = 128; // Maximum depth of Merkle tree
const TAPROOT_ANNEX_TAG = 0x50; // Annex starts with this byte

// BIP-342 tapscript validation-weight constants (script.h):
//   VALIDATION_WEIGHT_OFFSET            = 50  (initial budget bump)
//   VALIDATION_WEIGHT_PER_SIGOP_PASSED  = 50  (per-sigop deduction)
const TAPSCRIPT_SIGOPS_BUDGET_BASE = 50;
const TAPSCRIPT_SIGOPS_PER_SIGCHECK = 50;

/**
 * Compute the byte length of a Bitcoin compact-size encoding for n.
 * Mirrors Core's GetSizeOfCompactSize (serialize.h):
 *   <  0xfd            -> 1 byte
 *   <= 0xffff          -> 3 bytes
 *   <= 0xffffffff      -> 5 bytes
 *   else               -> 9 bytes
 */
export function compactSizeLen(n: number): number {
  if (n < 0xfd) return 1;
  if (n <= 0xffff) return 3;
  if (n <= 0xffffffff) return 5;
  return 9;
}

/**
 * Compute the on-the-wire serialized size of a witness stack the way
 * Core's `::GetSerializeSize(witness.stack)` does it: a compact-size
 * item count followed by, for each item, its compact-size length
 * prefix and the item bytes themselves. Used to seed the BIP-342
 * tapscript validation-weight budget at the leaf entry point.
 */
export function serializedWitnessStackSize(items: Buffer[]): number {
  let total = compactSizeLen(items.length);
  for (const it of items) {
    total += compactSizeLen(it.length) + it.length;
  }
  return total;
}

/**
 * Bitcoin Script opcodes.
 */
export const enum Opcode {
  // Push value
  OP_0 = 0x00,
  OP_FALSE = 0x00,
  OP_PUSHDATA1 = 0x4c,
  OP_PUSHDATA2 = 0x4d,
  OP_PUSHDATA4 = 0x4e,
  OP_1NEGATE = 0x4f,
  OP_RESERVED = 0x50,
  OP_1 = 0x51,
  OP_TRUE = 0x51,
  OP_2 = 0x52,
  OP_3 = 0x53,
  OP_4 = 0x54,
  OP_5 = 0x55,
  OP_6 = 0x56,
  OP_7 = 0x57,
  OP_8 = 0x58,
  OP_9 = 0x59,
  OP_10 = 0x5a,
  OP_11 = 0x5b,
  OP_12 = 0x5c,
  OP_13 = 0x5d,
  OP_14 = 0x5e,
  OP_15 = 0x5f,
  OP_16 = 0x60,

  // Control flow
  OP_NOP = 0x61,
  OP_VER = 0x62,
  OP_IF = 0x63,
  OP_NOTIF = 0x64,
  OP_VERIF = 0x65,
  OP_VERNOTIF = 0x66,
  OP_ELSE = 0x67,
  OP_ENDIF = 0x68,
  OP_VERIFY = 0x69,
  OP_RETURN = 0x6a,

  // Stack
  OP_TOALTSTACK = 0x6b,
  OP_FROMALTSTACK = 0x6c,
  OP_2DROP = 0x6d,
  OP_2DUP = 0x6e,
  OP_3DUP = 0x6f,
  OP_2OVER = 0x70,
  OP_2ROT = 0x71,
  OP_2SWAP = 0x72,
  OP_IFDUP = 0x73,
  OP_DEPTH = 0x74,
  OP_DROP = 0x75,
  OP_DUP = 0x76,
  OP_NIP = 0x77,
  OP_OVER = 0x78,
  OP_PICK = 0x79,
  OP_ROLL = 0x7a,
  OP_ROT = 0x7b,
  OP_SWAP = 0x7c,
  OP_TUCK = 0x7d,

  // Splice (most disabled)
  OP_CAT = 0x7e, // disabled
  OP_SUBSTR = 0x7f, // disabled
  OP_LEFT = 0x80, // disabled
  OP_RIGHT = 0x81, // disabled
  OP_SIZE = 0x82,

  // Bitwise logic (most disabled)
  OP_INVERT = 0x83, // disabled
  OP_AND = 0x84, // disabled
  OP_OR = 0x85, // disabled
  OP_XOR = 0x86, // disabled
  OP_EQUAL = 0x87,
  OP_EQUALVERIFY = 0x88,
  OP_RESERVED1 = 0x89,
  OP_RESERVED2 = 0x8a,

  // Arithmetic
  OP_1ADD = 0x8b,
  OP_1SUB = 0x8c,
  OP_2MUL = 0x8d, // disabled
  OP_2DIV = 0x8e, // disabled
  OP_NEGATE = 0x8f,
  OP_ABS = 0x90,
  OP_NOT = 0x91,
  OP_0NOTEQUAL = 0x92,
  OP_ADD = 0x93,
  OP_SUB = 0x94,
  OP_MUL = 0x95, // disabled
  OP_DIV = 0x96, // disabled
  OP_MOD = 0x97, // disabled
  OP_LSHIFT = 0x98, // disabled
  OP_RSHIFT = 0x99, // disabled
  OP_BOOLAND = 0x9a,
  OP_BOOLOR = 0x9b,
  OP_NUMEQUAL = 0x9c,
  OP_NUMEQUALVERIFY = 0x9d,
  OP_NUMNOTEQUAL = 0x9e,
  OP_LESSTHAN = 0x9f,
  OP_GREATERTHAN = 0xa0,
  OP_LESSTHANOREQUAL = 0xa1,
  OP_GREATERTHANOREQUAL = 0xa2,
  OP_MIN = 0xa3,
  OP_MAX = 0xa4,
  OP_WITHIN = 0xa5,

  // Crypto
  OP_RIPEMD160 = 0xa6,
  OP_SHA1 = 0xa7,
  OP_SHA256 = 0xa8,
  OP_HASH160 = 0xa9,
  OP_HASH256 = 0xaa,
  OP_CODESEPARATOR = 0xab,
  OP_CHECKSIG = 0xac,
  OP_CHECKSIGVERIFY = 0xad,
  OP_CHECKMULTISIG = 0xae,
  OP_CHECKMULTISIGVERIFY = 0xaf,

  // Expansion
  OP_NOP1 = 0xb0,
  OP_CHECKLOCKTIMEVERIFY = 0xb1,
  OP_CHECKSEQUENCEVERIFY = 0xb2,
  OP_NOP4 = 0xb3,
  OP_NOP5 = 0xb4,
  OP_NOP6 = 0xb5,
  OP_NOP7 = 0xb6,
  OP_NOP8 = 0xb7,
  OP_NOP9 = 0xb8,
  OP_NOP10 = 0xb9,

  // Taproot
  OP_CHECKSIGADD = 0xba,

  // Invalid
  OP_INVALIDOPCODE = 0xff,
}

/**
 * A parsed script chunk - either an opcode or push data.
 */
export interface ScriptChunk {
  opcode: number;
  data?: Buffer; // present for push-data ops
}

export type Script = ScriptChunk[];

/**
 * Script verification flags.
 * IMPORTANT: Only consensus flags should be used for block validation.
 * Policy flags are for mempool only.
 */
export interface ScriptFlags {
  verifyP2SH: boolean; // BIP 16 - consensus
  verifyWitness: boolean; // BIP 141 - consensus
  verifyTaproot: boolean; // BIP 341 - consensus
  verifyStrictEncoding: boolean; // policy
  verifyDERSignatures: boolean; // BIP 66 - consensus
  verifyLowS: boolean; // policy
  verifyNullDummy: boolean; // BIP 147 - consensus
  verifyNullFail: boolean; // BIP 146 - consensus (activated with SegWit)
  verifyCheckLockTimeVerify: boolean; // BIP 65 - consensus
  verifyCheckSequenceVerify: boolean; // BIP 112 - consensus
  verifyWitnessPubkeyType: boolean; // BIP 141 - consensus (activated with SegWit)
  verifyMinimalIf?: boolean; // BIP 141 - policy for witness v0, consensus for tapscript
  verifyMinimalData?: boolean; // BIP 62 - require minimal encoding for script numbers
  verifySigPushOnly?: boolean; // policy - scriptSig must be push-only
  verifyDiscourageUpgradableNops?: boolean; // policy - unused NOPs must error
  verifyCleanStack?: boolean; // BIP 62 - stack must have exactly one element after execution
  verifyDiscourageUpgradableWitnessProgram?: boolean; // policy - unknown witness versions must error
}

/**
 * Signature version for sighash calculation.
 */
export const enum SigVersion {
  BASE = 0,
  WITNESS_V0 = 1,
  TAPROOT = 2,
  TAPSCRIPT = 3,
}

/**
 * Execution context for script evaluation.
 */
export interface ExecutionContext {
  stack: Buffer[];
  altStack: Buffer[];
  flags: ScriptFlags;
  sigHasher: (subscript: Buffer, hashType: number) => Buffer;
  sigVersion?: SigVersion;
  // Transaction context for CLTV/CSV
  txVersion?: number; // Spending tx version
  txLockTime?: number; // Spending tx locktime
  txSequence?: number; // Spending input sequence
  // Tapscript-specific fields
  taprootSigHasher?: (hashType: number, codeSepPos: number) => Buffer;
  sigopsBudget?: number; // Remaining sigops for tapscript
}

// Disabled opcodes that cause immediate script failure
const DISABLED_OPCODES = new Set([
  Opcode.OP_CAT,
  Opcode.OP_SUBSTR,
  Opcode.OP_LEFT,
  Opcode.OP_RIGHT,
  Opcode.OP_INVERT,
  Opcode.OP_AND,
  Opcode.OP_OR,
  Opcode.OP_XOR,
  Opcode.OP_2MUL,
  Opcode.OP_2DIV,
  Opcode.OP_MUL,
  Opcode.OP_DIV,
  Opcode.OP_MOD,
  Opcode.OP_LSHIFT,
  Opcode.OP_RSHIFT,
]);

/**
 * Check if an opcode is OP_SUCCESSx (tapscript only).
 * These opcodes cause immediate success in tapscript execution.
 *
 * OP_SUCCESSx opcodes: 0x50, 0x62, 0x89, 0x8a, 0x8d, 0x8e, 0x95-0xaf, 0xba-0xfe
 * Reference: BIP-342
 */
function isOpSuccess(opcode: number): boolean {
  // BIP-342 OP_SUCCESSx: opcodes that cause immediate script success in tapscript.
  // These are specifically the undefined/disabled opcodes, NOT active ones.
  // Reference: Bitcoin Core IsOpSuccess() in script/interpreter.cpp
  if (opcode === 0x50) return true; // OP_RESERVED (80)
  if (opcode === 0x62) return true; // OP_VER (98)
  if (opcode >= 0x7e && opcode <= 0x81) return true; // OP_CAT..OP_RIGHT (126-129)
  if (opcode >= 0x83 && opcode <= 0x86) return true; // OP_SUBSTR..OP_XOR (131-134)
  if (opcode >= 0x89 && opcode <= 0x8a) return true; // OP_RESERVED1, OP_RESERVED2 (137-138)
  if (opcode >= 0x8d && opcode <= 0x8e) return true; // OP_2MUL, OP_2DIV (141-142)
  if (opcode >= 0x95 && opcode <= 0x99) return true; // OP_MUL..OP_RSHIFT (149-153)
  if (opcode >= 0xbb && opcode <= 0xfe) return true; // OP_NOP11..OP_INVALIDOPCODE-1 (187-254)
  return false;
}

/**
 * Check if a raw script contains any OP_SUCCESSx opcodes.
 * If it does, the script succeeds immediately (BIP-342 rule).
 */
function containsOpSuccess(script: Buffer): boolean {
  let i = 0;
  while (i < script.length) {
    const opcode = script[i];
    i++;

    // Check for OP_SUCCESS before parsing push data
    if (isOpSuccess(opcode)) {
      return true;
    }

    // Skip push data
    if (opcode >= 1 && opcode <= 75) {
      i += opcode;
    } else if (opcode === Opcode.OP_PUSHDATA1 && i < script.length) {
      const len = script[i];
      i += 1 + len;
    } else if (opcode === Opcode.OP_PUSHDATA2 && i + 1 < script.length) {
      const len = script[i] | (script[i + 1] << 8);
      i += 2 + len;
    } else if (opcode === Opcode.OP_PUSHDATA4 && i + 3 < script.length) {
      const len = script[i] | (script[i + 1] << 8) | (script[i + 2] << 16) | (script[i + 3] << 24);
      i += 4 + len;
    }
  }
  return false;
}

/**
 * Encode a number as a Bitcoin script number.
 * Numbers are encoded as little-endian with a sign bit in the MSB of the last byte.
 */
export function scriptNumEncode(n: number): Buffer {
  if (n === 0) {
    return Buffer.alloc(0);
  }

  const negative = n < 0;
  let absValue = Math.abs(n);

  const bytes: number[] = [];
  while (absValue > 0) {
    bytes.push(absValue & 0xff);
    absValue = Math.floor(absValue / 256);
  }

  // If the most significant byte has its high bit set, we need an extra byte
  // to store the sign bit
  if (bytes[bytes.length - 1] & 0x80) {
    bytes.push(negative ? 0x80 : 0x00);
  } else if (negative) {
    bytes[bytes.length - 1] |= 0x80;
  }

  return Buffer.from(bytes);
}

/**
 * Decode a Bitcoin script number.
 * Numbers are little-endian with a sign bit in the MSB of the last byte.
 */
export function scriptNumDecode(buf: Buffer, maxLen: number = 4, requireMinimal: boolean = false): number {
  if (buf.length === 0) {
    return 0;
  }

  if (buf.length > maxLen) {
    throw new Error(`Script number too long: ${buf.length} > ${maxLen}`);
  }

  // Check for non-minimal encoding
  if (requireMinimal) {
    if (buf.length === 1) {
      // Single byte 0x00 is non-minimal (should be empty for zero)
      // Single byte 0x80 is non-minimal (negative zero should be empty)
      if (buf[0] === 0x00 || buf[0] === 0x80) {
        throw new ScriptError("UNKNOWN");
      }
    } else if (buf.length > 1) {
      // If the last byte is 0x00 or 0x80, and the second-to-last byte
      // doesn't have its high bit set, then we have a non-minimal encoding
      if ((buf[buf.length - 1] & 0x7f) === 0) {
        if ((buf[buf.length - 2] & 0x80) === 0) {
          throw new ScriptError("UNKNOWN");
        }
      }
    }
  }

  let result = 0;
  for (let i = 0; i < buf.length; i++) {
    result += buf[i] * (2 ** (8 * i));
  }

  // Check sign bit
  if (buf[buf.length - 1] & 0x80) {
    // Negative number - clear the sign bit and negate
    return -(result - 0x80 * (2 ** (8 * (buf.length - 1))));
  }

  return result;
}

/**
 * Check if a public key is compressed (33 bytes, starting with 0x02 or 0x03).
 * Used for SCRIPT_VERIFY_WITNESS_PUBKEYTYPE enforcement in witness v0 scripts.
 */
function isCompressedPubKey(pubkey: Buffer): boolean {
  if (pubkey.length !== 33) {
    return false;
  }
  if (pubkey[0] !== 0x02 && pubkey[0] !== 0x03) {
    return false;
  }
  return true;
}

/**
 * Check if a public key is valid for STRICTENC purposes.
 * Valid formats: compressed (02/03 + 32 bytes), uncompressed (04 + 64 bytes).
 * Hybrid keys (06/07) are NOT valid under STRICTENC.
 */
function isValidPubKeyEncoding(pubkey: Buffer): boolean {
  if (pubkey.length < 1) return false;
  if (pubkey[0] === 0x04) {
    return pubkey.length === 65; // Uncompressed
  }
  if (pubkey[0] === 0x02 || pubkey[0] === 0x03) {
    return pubkey.length === 33; // Compressed
  }
  return false;
}

/**
 * Check if a signature is valid strict DER encoding (BIP66).
 * This is a pure format check; it does NOT verify the signature cryptographically.
 */
function isValidSignatureEncoding(sig: Buffer): boolean {
  // Format: 0x30 [total-length] 0x02 [R-length] [R] 0x02 [S-length] [S]
  if (sig.length < 8) return false;
  if (sig.length > 72) return false;
  if (sig[0] !== 0x30) return false;
  if (sig[1] !== sig.length - 2) return false;
  if (sig[2] !== 0x02) return false;

  const rLen = sig[3];
  if (rLen === 0) return false;
  if (5 + rLen >= sig.length) return false;
  if (sig[4 + rLen] !== 0x02) return false;

  const sLen = sig[5 + rLen];
  if (sLen === 0) return false;
  if (6 + rLen + sLen !== sig.length) return false;

  // R must not be negative
  if (sig[4] & 0x80) return false;
  // R must not have unnecessary leading zeros
  if (rLen > 1 && sig[4] === 0x00 && !(sig[5] & 0x80)) return false;

  // S must not be negative
  const sStart = 6 + rLen;
  if (sig[sStart] & 0x80) return false;
  // S must not have unnecessary leading zeros
  if (sLen > 1 && sig[sStart] === 0x00 && !(sig[sStart + 1] & 0x80)) return false;

  return true;
}

/**
 * Check if a signature has a valid defined hashtype (STRICTENC).
 */
function isDefinedHashtypeSignature(sig: Buffer): boolean {
  if (sig.length === 0) return true;
  const hashType = sig[sig.length - 1] & ~0x80; // Strip ANYONECANPAY
  if (hashType < 1 || hashType > 3) return false; // Must be ALL, NONE, or SINGLE
  return true;
}

/** secp256k1 curve order */
const SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n;
const SECP256K1_N_HALF = SECP256K1_N / 2n;

/**
 * Check if a signature has low S value (BIP62 rule 5).
 * The S value must be at most half the curve order.
 */
function isLowDERSignature(sig: Buffer): boolean {
  if (!isValidSignatureEncoding(sig)) return false;
  const rLen = sig[3];
  const sLen = sig[5 + rLen];
  const sStart = 6 + rLen;
  const sBytes = sig.subarray(sStart, sStart + sLen);
  let s = 0n;
  for (let i = 0; i < sBytes.length; i++) {
    s = (s << 8n) | BigInt(sBytes[i]);
  }
  return s <= SECP256K1_N_HALF;
}

/**
 * Validate a signature against the active flags. Returns true if valid (or check not required).
 * Throws ScriptError with the appropriate code if invalid.
 */
function checkSignatureEncoding(sig: Buffer, flags: ScriptFlags): boolean {
  if (sig.length === 0) return true;

  // DERSIG: signature must be strict DER
  if ((flags.verifyDERSignatures || flags.verifyStrictEncoding) && !isValidSignatureEncoding(sig.subarray(0, sig.length - 1))) {
    throw new ScriptError("SIG_DER");
  }

  // STRICTENC: hash type must be defined
  if (flags.verifyStrictEncoding && !isDefinedHashtypeSignature(sig)) {
    throw new ScriptError("SIG_HASHTYPE");
  }

  // LOW_S: S value must be low
  if (flags.verifyLowS && !isLowDERSignature(sig.subarray(0, sig.length - 1))) {
    throw new ScriptError("SIG_HIGH_S");
  }

  return true;
}

/**
 * Validate a public key against the active flags.
 * Throws ScriptError with the appropriate code if invalid.
 */
function checkPubKeyEncoding(pubkey: Buffer, flags: ScriptFlags, sigVersion: SigVersion): boolean {
  // STRICTENC: pubkey must be valid compressed or uncompressed
  if (flags.verifyStrictEncoding && !isValidPubKeyEncoding(pubkey)) {
    throw new ScriptError("PUBKEYTYPE");
  }

  // WITNESS_PUBKEYTYPE: In witness v0, pubkeys must be compressed
  if (flags.verifyWitnessPubkeyType && sigVersion === SigVersion.WITNESS_V0 && !isCompressedPubKey(pubkey)) {
    throw new ScriptError("WITNESS_PUBKEYTYPE");
  }

  return true;
}

/**
 * Check if a stack element is "true" (non-zero).
 */
function castToBool(buf: Buffer): boolean {
  for (let i = 0; i < buf.length; i++) {
    if (buf[i] !== 0) {
      // Can be negative zero (0x80 in last byte only)
      if (i === buf.length - 1 && buf[i] === 0x80) {
        return false;
      }
      return true;
    }
  }
  return false;
}

/**
 * Check if a stack element passes MINIMALIF requirements.
 * For witness v0: value must be empty (false) or exactly [0x01] (true).
 * For tapscript: same rule but enforced as consensus.
 *
 * Any other value like [0x02], [0x00], [0x01, 0x00] etc. is rejected.
 * Reference: Bitcoin Core interpreter.cpp OP_IF handler.
 */
function checkMinimalIf(element: Buffer): boolean {
  if (element.length === 0) {
    return true; // Empty buffer is valid (false)
  }
  if (element.length === 1 && element[0] === 1) {
    return true; // Exactly [0x01] is valid (true)
  }
  return false; // All other values are invalid
}

/**
 * Check if a push operation uses minimal encoding (MINIMALDATA rule, BIP 62).
 * - Empty data should use OP_0 (not OP_PUSHDATA1 with length 0)
 * - Single byte 0x01-0x10 should use OP_1-OP_16
 * - Single byte 0x81 should use OP_1NEGATE
 * - Data up to 75 bytes should use direct push (opcode = length)
 * - Data 76-255 bytes should use OP_PUSHDATA1
 * - Data 256-65535 bytes should use OP_PUSHDATA2
 */
function checkMinimalPush(chunk: ScriptChunk): boolean {
  const data = chunk.data!;
  const opcode = chunk.opcode;

  if (data.length === 0) {
    // Empty data should use OP_0
    return opcode === Opcode.OP_0;
  }
  if (data.length === 1) {
    if (data[0] >= 1 && data[0] <= 16) {
      // Single byte 1-16 should use OP_1 through OP_16
      return opcode === Opcode.OP_1 + (data[0] - 1);
    }
    if (data[0] === 0x81) {
      // Single byte 0x81 should use OP_1NEGATE
      return opcode === Opcode.OP_1NEGATE;
    }
  }
  if (data.length <= 75) {
    // Direct push: opcode should equal data length
    return opcode === data.length;
  }
  if (data.length <= 255) {
    // Should use OP_PUSHDATA1
    return opcode === Opcode.OP_PUSHDATA1;
  }
  if (data.length <= 65535) {
    // Should use OP_PUSHDATA2
    return opcode === Opcode.OP_PUSHDATA2;
  }
  return true;
}

/**
 * Verify a Schnorr signature for tapscript (BIP-342).
 *
 * @param sig - Signature (64 bytes, or 65 bytes with sighash type)
 * @param pubkey - 32-byte x-only public key
 * @param ctx - Execution context with taproot sighash function
 * @param codeSepPos - Position of last OP_CODESEPARATOR
 * @returns true if signature is valid
 */
function verifySchnorrSig(
  sig: Buffer,
  pubkey: Buffer,
  ctx: ExecutionContext,
  codeSepPos: number
): boolean {
  // Empty signature means "not signing this key"
  if (sig.length === 0) {
    return false;
  }

  // BIP-342: Empty pubkey (0 bytes) always fails
  if (pubkey.length === 0) {
    throw new ScriptError("TAPSCRIPT_EMPTY_PUBKEY");
  }

  // BIP-342: Unknown pubkey type (not 32 bytes) succeeds for forward compatibility
  if (pubkey.length !== 32) {
    return true;
  }

  // Signature must be 64 or 65 bytes
  if (sig.length !== 64 && sig.length !== 65) {
    throw new ScriptError("SCHNORR_SIG_SIZE");
  }

  // Extract hash type
  let hashType: number;
  let sigBytes: Buffer;

  if (sig.length === 65) {
    hashType = sig[64];
    sigBytes = sig.subarray(0, 64);
    // SIGHASH_DEFAULT (0x00) is not allowed with explicit byte in 65-byte sig
    if (hashType === 0x00) {
      throw new ScriptError("SCHNORR_SIG_HASHTYPE");
    }
  } else {
    // 64-byte signature implies SIGHASH_DEFAULT (0x00)
    hashType = 0x00;
    sigBytes = sig;
  }

  // Validate hash type
  if (!isValidTaprootHashType(hashType)) {
    throw new ScriptError("SCHNORR_SIG_HASHTYPE");
  }

  // Need taproot sighash function
  if (!ctx.taprootSigHasher) {
    throw new ScriptError("TAPROOT_CONTEXT_MISSING");
  }

  // Compute sighash
  const sighash = ctx.taprootSigHasher(hashType, codeSepPos);

  // Verify Schnorr signature
  if (!schnorrVerify(sigBytes, sighash, pubkey)) {
    throw new ScriptError("SCHNORR_SIG");
  }

  return true;
}

/**
 * Parse a raw script into chunks.
 */
export function parseScript(raw: Buffer): Script {
  const chunks: Script = [];
  let i = 0;

  while (i < raw.length) {
    const opcode = raw[i];
    i++;

    if (opcode === 0) {
      // OP_0 - push empty
      chunks.push({ opcode: Opcode.OP_0, data: Buffer.alloc(0) });
    } else if (opcode >= 1 && opcode <= 75) {
      // Direct push of N bytes
      const data = raw.subarray(i, i + opcode);
      if (data.length !== opcode) {
        throw new Error("Script parse error: not enough data for push");
      }
      chunks.push({ opcode, data: Buffer.from(data) });
      i += opcode;
    } else if (opcode === Opcode.OP_PUSHDATA1) {
      if (i >= raw.length) {
        throw new Error("Script parse error: OP_PUSHDATA1 missing length");
      }
      const len = raw[i];
      i++;
      const data = raw.subarray(i, i + len);
      if (data.length !== len) {
        throw new Error("Script parse error: not enough data for OP_PUSHDATA1");
      }
      chunks.push({ opcode, data: Buffer.from(data) });
      i += len;
    } else if (opcode === Opcode.OP_PUSHDATA2) {
      if (i + 1 >= raw.length) {
        throw new Error("Script parse error: OP_PUSHDATA2 missing length");
      }
      const len = raw[i] | (raw[i + 1] << 8);
      i += 2;
      const data = raw.subarray(i, i + len);
      if (data.length !== len) {
        throw new Error("Script parse error: not enough data for OP_PUSHDATA2");
      }
      chunks.push({ opcode, data: Buffer.from(data) });
      i += len;
    } else if (opcode === Opcode.OP_PUSHDATA4) {
      if (i + 3 >= raw.length) {
        throw new Error("Script parse error: OP_PUSHDATA4 missing length");
      }
      const len = raw[i] | (raw[i + 1] << 8) | (raw[i + 2] << 16) | (raw[i + 3] << 24);
      i += 4;
      const data = raw.subarray(i, i + len);
      if (data.length !== len) {
        throw new Error("Script parse error: not enough data for OP_PUSHDATA4");
      }
      chunks.push({ opcode, data: Buffer.from(data) });
      i += len;
    } else {
      // Regular opcode
      chunks.push({ opcode });
    }
  }

  return chunks;
}

/**
 * Check if a raw script contains only push operations.
 *
 * Push operations are:
 * - OP_0 (0x00)
 * - Direct data pushes (0x01-0x4b, where opcode = number of bytes)
 * - OP_PUSHDATA1, OP_PUSHDATA2, OP_PUSHDATA4 (0x4c-0x4e)
 * - OP_1NEGATE (0x4f)
 * - OP_RESERVED (0x50) - considered push-only (but fails on execution)
 * - OP_1 through OP_16 (0x51-0x60)
 *
 * This is consensus-critical for P2SH (BIP16).
 * Reference: Bitcoin Core script.cpp IsPushOnly()
 */
export function isPushOnly(script: Buffer): boolean {
  let i = 0;

  while (i < script.length) {
    const opcode = script[i];
    i++;

    // Any opcode > OP_16 is not a push
    if (opcode > Opcode.OP_16) {
      return false;
    }

    // For data push opcodes, skip over the pushed data
    if (opcode >= 1 && opcode <= 75) {
      // Direct push: opcode is the number of bytes
      if (i + opcode > script.length) return false; // Truncated
      i += opcode;
    } else if (opcode === Opcode.OP_PUSHDATA1) {
      if (i >= script.length) return false;
      const len = script[i];
      if (i + 1 + len > script.length) return false; // Truncated
      i += 1 + len;
    } else if (opcode === Opcode.OP_PUSHDATA2) {
      if (i + 2 > script.length) return false;
      const len = script[i] | (script[i + 1] << 8);
      if (i + 2 + len > script.length) return false; // Truncated
      i += 2 + len;
    } else if (opcode === Opcode.OP_PUSHDATA4) {
      if (i + 4 > script.length) return false;
      const len = script[i] | (script[i + 1] << 8) | (script[i + 2] << 16) | (script[i + 3] << 24);
      if (i + 4 + len > script.length) return false; // Truncated
      i += 4 + len;
    }
    // OP_0, OP_1NEGATE, OP_RESERVED, OP_1-OP_16 are all <= OP_16 and don't push extra data
  }

  return true;
}

/**
 * Serialize a parsed script back to raw bytes.
 */
export function serializeScript(script: Script): Buffer {
  const parts: Buffer[] = [];

  for (const chunk of script) {
    if (chunk.data !== undefined) {
      const len = chunk.data.length;
      if (chunk.opcode === Opcode.OP_0) {
        parts.push(Buffer.from([0x00]));
      } else if (chunk.opcode >= 1 && chunk.opcode <= 75) {
        parts.push(Buffer.from([len]));
        parts.push(chunk.data);
      } else if (chunk.opcode === Opcode.OP_PUSHDATA1) {
        parts.push(Buffer.from([Opcode.OP_PUSHDATA1, len]));
        parts.push(chunk.data);
      } else if (chunk.opcode === Opcode.OP_PUSHDATA2) {
        parts.push(Buffer.from([Opcode.OP_PUSHDATA2, len & 0xff, (len >> 8) & 0xff]));
        parts.push(chunk.data);
      } else if (chunk.opcode === Opcode.OP_PUSHDATA4) {
        parts.push(
          Buffer.from([
            Opcode.OP_PUSHDATA4,
            len & 0xff,
            (len >> 8) & 0xff,
            (len >> 16) & 0xff,
            (len >> 24) & 0xff,
          ])
        );
        parts.push(chunk.data);
      }
    } else {
      parts.push(Buffer.from([chunk.opcode]));
    }
  }

  return Buffer.concat(parts);
}

/**
 * Remove all occurrences of a signature from scriptCode (FindAndDelete).
 * ONLY for legacy (BASE) signature version.
 */
function findAndDelete(script: Buffer, sig: Buffer): Buffer {
  if (sig.length === 0) {
    return script;
  }

  // Build the push-encoded signature to search for
  let pushSig: Buffer;
  if (sig.length < 76) {
    pushSig = Buffer.concat([Buffer.from([sig.length]), sig]);
  } else if (sig.length < 256) {
    pushSig = Buffer.concat([Buffer.from([Opcode.OP_PUSHDATA1, sig.length]), sig]);
  } else {
    pushSig = Buffer.concat([
      Buffer.from([Opcode.OP_PUSHDATA2, sig.length & 0xff, (sig.length >> 8) & 0xff]),
      sig,
    ]);
  }

  // Find and remove all occurrences
  const parts: Buffer[] = [];
  let i = 0;
  while (i < script.length) {
    // Check if pushSig appears at position i
    if (i + pushSig.length <= script.length && script.subarray(i, i + pushSig.length).equals(pushSig)) {
      // Skip this occurrence
      i += pushSig.length;
    } else {
      parts.push(script.subarray(i, i + 1));
      i++;
    }
  }

  return Buffer.concat(parts);
}

/**
 * Execute a parsed script.
 */
export function executeScript(script: Script, ctx: ExecutionContext): boolean {
  const { stack, altStack, flags, sigHasher } = ctx;
  const sigVersion = ctx.sigVersion ?? SigVersion.BASE;

  // Condition stack for IF/ELSE/ENDIF
  const condStack: boolean[] = [];

  // Track code separator position for sighash
  let codeSepPos = 0xffffffff;

  // Count non-push opcodes
  let opCount = 0;

  for (let pc = 0; pc < script.length; pc++) {
    const chunk = script[pc];
    const opcode = chunk.opcode;

    // Check if we're in an executing branch
    const executing = condStack.every((v) => v);

    // Check for disabled opcodes (fail even if not executing)
    if (DISABLED_OPCODES.has(opcode)) {
      return false;
    }

    // OP_VERIF and OP_VERNOTIF are always invalid
    if (opcode === Opcode.OP_VERIF || opcode === Opcode.OP_VERNOTIF) {
      return false;
    }

    // Count non-push opcodes.
    // BIP-342 (tapscript) exempts execution from MAX_OPS_PER_SCRIPT — Core's
    // interpreter.cpp:450-455 only enforces this cap for SigVersion::BASE
    // and SigVersion::WITNESS_V0. Inscriptions/ordinals routinely exceed
    // 201 opcodes; e.g. mainnet block 944,279 tx 8775be68... vin[1] has
    // ~701 non-push opcodes in a 282 KB tapscript.
    if (opcode > Opcode.OP_16 && sigVersion !== SigVersion.TAPSCRIPT) {
      opCount++;
      if (opCount > MAX_OPS_PER_SCRIPT) {
        return false;
      }
    }

    // Push data operations
    if (chunk.data !== undefined) {
      // PUSH_SIZE check applies even in unexecuted branches
      if (chunk.data.length > MAX_ELEMENT_SIZE) {
        return false;
      }
      if (executing) {
        // MINIMALDATA: Check that push uses minimal encoding
        if (flags.verifyMinimalData && !checkMinimalPush(chunk)) {
          throw new ScriptError("MINIMALDATA");
        }
        stack.push(chunk.data);
      }
      continue;
    }

    // OP_1NEGATE through OP_16 push numbers
    if (opcode === Opcode.OP_1NEGATE) {
      if (executing) {
        stack.push(scriptNumEncode(-1));
      }
      continue;
    }

    if (opcode >= Opcode.OP_1 && opcode <= Opcode.OP_16) {
      if (executing) {
        const n = opcode - Opcode.OP_1 + 1;
        stack.push(scriptNumEncode(n));
      }
      continue;
    }

    // Control flow (always processed, even in non-executing branches)
    if (opcode === Opcode.OP_IF || opcode === Opcode.OP_NOTIF) {
      let value = false;
      if (executing) {
        if (stack.length < 1) {
          return false;
        }
        const top = stack.pop()!;

        // MINIMALIF: In witness v0 (with flag) and tapscript, the argument must be
        // either empty (false) or exactly [0x01] (true). Any other value is rejected.
        // For tapscript, this is unconditional consensus.
        // For witness v0, it's enabled via SCRIPT_VERIFY_MINIMALIF flag.
        if (sigVersion === SigVersion.TAPSCRIPT) {
          // Tapscript: MINIMALIF is unconditional consensus
          if (!checkMinimalIf(top)) {
            throw new ScriptError("MINIMALIF");
          }
        } else if (sigVersion === SigVersion.WITNESS_V0 && flags.verifyMinimalIf) {
          // Witness v0: MINIMALIF is policy (but we enforce when flag is set)
          if (!checkMinimalIf(top)) {
            throw new ScriptError("MINIMALIF");
          }
        }

        value = castToBool(top);
        if (opcode === Opcode.OP_NOTIF) {
          value = !value;
        }
      }
      condStack.push(executing && value);
      continue;
    }

    if (opcode === Opcode.OP_ELSE) {
      if (condStack.length === 0) {
        return false;
      }
      // Only flip if all outer conditions are true
      const outerExecuting = condStack.length === 1 || condStack.slice(0, -1).every((v) => v);
      if (outerExecuting) {
        condStack[condStack.length - 1] = !condStack[condStack.length - 1];
      }
      continue;
    }

    if (opcode === Opcode.OP_ENDIF) {
      if (condStack.length === 0) {
        return false;
      }
      condStack.pop();
      continue;
    }

    // Skip remaining opcodes if not executing
    if (!executing) {
      continue;
    }

    switch (opcode) {
      // Control
      case Opcode.OP_NOP:
        break;

      case Opcode.OP_NOP1:
      case Opcode.OP_NOP4:
      case Opcode.OP_NOP5:
      case Opcode.OP_NOP6:
      case Opcode.OP_NOP7:
      case Opcode.OP_NOP8:
      case Opcode.OP_NOP9:
      case Opcode.OP_NOP10:
        if (flags.verifyDiscourageUpgradableNops) {
          throw new ScriptError("DISCOURAGE_UPGRADABLE_NOPS");
        }
        break;

      case Opcode.OP_VERIFY: {
        if (stack.length < 1) return false;
        const top = stack.pop()!;
        if (!castToBool(top)) return false;
        break;
      }

      case Opcode.OP_RETURN:
        return false;

      case Opcode.OP_CHECKLOCKTIMEVERIFY: {
        if (!flags.verifyCheckLockTimeVerify) {
          if (flags.verifyDiscourageUpgradableNops) {
            throw new ScriptError("DISCOURAGE_UPGRADABLE_NOPS");
          }
          break; // Treated as NOP
        }
        if (stack.length < 1) return false;
        // Value is checked but not popped
        const locktime = scriptNumDecode(stack[stack.length - 1], 5);
        if (locktime < 0) throw new ScriptError("NEGATIVE_LOCKTIME");

        // Compare against tx locktime (if context available)
        if (ctx.txLockTime !== undefined) {
          const txLockTime = ctx.txLockTime;
          // Both must be in the same domain (block height vs time)
          const LOCKTIME_THRESHOLD = 500000000;
          if (
            (locktime < LOCKTIME_THRESHOLD && txLockTime >= LOCKTIME_THRESHOLD) ||
            (locktime >= LOCKTIME_THRESHOLD && txLockTime < LOCKTIME_THRESHOLD)
          ) {
            throw new ScriptError("UNSATISFIED_LOCKTIME");
          }
          if (locktime > txLockTime) {
            throw new ScriptError("UNSATISFIED_LOCKTIME");
          }
          // Sequence must not be final (0xFFFFFFFF disables locktime check)
          if (ctx.txSequence !== undefined && ctx.txSequence === 0xFFFFFFFF) {
            throw new ScriptError("UNSATISFIED_LOCKTIME");
          }
        }
        break;
      }

      case Opcode.OP_CHECKSEQUENCEVERIFY: {
        if (!flags.verifyCheckSequenceVerify) {
          if (flags.verifyDiscourageUpgradableNops) {
            throw new ScriptError("DISCOURAGE_UPGRADABLE_NOPS");
          }
          break; // Treated as NOP
        }
        if (stack.length < 1) return false;
        const sequence = scriptNumDecode(stack[stack.length - 1], 5);
        if (sequence < 0) throw new ScriptError("NEGATIVE_LOCKTIME");

        // If the disable flag (bit 31) is set, CSV is a no-op
        if (sequence & (1 << 31)) break;

        // CSV requires tx version >= 2
        if (ctx.txVersion !== undefined && ctx.txVersion < 2) {
          throw new ScriptError("UNSATISFIED_LOCKTIME");
        }

        // Compare against input sequence (if context available)
        if (ctx.txSequence !== undefined) {
          const txSeq = ctx.txSequence;
          // If input sequence has disable flag set, fail
          if (txSeq & (1 << 31)) {
            throw new ScriptError("UNSATISFIED_LOCKTIME");
          }
          // Both must be in the same type (time vs height)
          const TYPE_FLAG = 1 << 22;
          if ((sequence & TYPE_FLAG) !== (txSeq & TYPE_FLAG)) {
            throw new ScriptError("UNSATISFIED_LOCKTIME");
          }
          // Compare masked values
          const MASK = 0x0000ffff;
          if ((sequence & MASK) > (txSeq & MASK)) {
            throw new ScriptError("UNSATISFIED_LOCKTIME");
          }
        }
        break;
      }

      // Stack operations
      case Opcode.OP_TOALTSTACK: {
        if (stack.length < 1) return false;
        altStack.push(stack.pop()!);
        break;
      }

      case Opcode.OP_FROMALTSTACK: {
        if (altStack.length < 1) return false;
        stack.push(altStack.pop()!);
        break;
      }

      case Opcode.OP_2DROP: {
        if (stack.length < 2) return false;
        stack.pop();
        stack.pop();
        break;
      }

      case Opcode.OP_2DUP: {
        if (stack.length < 2) return false;
        const a = stack[stack.length - 2];
        const b = stack[stack.length - 1];
        stack.push(Buffer.from(a));
        stack.push(Buffer.from(b));
        break;
      }

      case Opcode.OP_3DUP: {
        if (stack.length < 3) return false;
        const a = stack[stack.length - 3];
        const b = stack[stack.length - 2];
        const c = stack[stack.length - 1];
        stack.push(Buffer.from(a));
        stack.push(Buffer.from(b));
        stack.push(Buffer.from(c));
        break;
      }

      case Opcode.OP_2OVER: {
        if (stack.length < 4) return false;
        const a = stack[stack.length - 4];
        const b = stack[stack.length - 3];
        stack.push(Buffer.from(a));
        stack.push(Buffer.from(b));
        break;
      }

      case Opcode.OP_2ROT: {
        if (stack.length < 6) return false;
        const a = stack.splice(stack.length - 6, 1)[0];
        const b = stack.splice(stack.length - 5, 1)[0];
        stack.push(a);
        stack.push(b);
        break;
      }

      case Opcode.OP_2SWAP: {
        if (stack.length < 4) return false;
        const a = stack[stack.length - 4];
        const b = stack[stack.length - 3];
        stack[stack.length - 4] = stack[stack.length - 2];
        stack[stack.length - 3] = stack[stack.length - 1];
        stack[stack.length - 2] = a;
        stack[stack.length - 1] = b;
        break;
      }

      case Opcode.OP_IFDUP: {
        if (stack.length < 1) return false;
        if (castToBool(stack[stack.length - 1])) {
          stack.push(Buffer.from(stack[stack.length - 1]));
        }
        break;
      }

      case Opcode.OP_DEPTH: {
        stack.push(scriptNumEncode(stack.length));
        break;
      }

      case Opcode.OP_DROP: {
        if (stack.length < 1) return false;
        stack.pop();
        break;
      }

      case Opcode.OP_DUP: {
        if (stack.length < 1) return false;
        stack.push(Buffer.from(stack[stack.length - 1]));
        break;
      }

      case Opcode.OP_NIP: {
        if (stack.length < 2) return false;
        stack.splice(stack.length - 2, 1);
        break;
      }

      case Opcode.OP_OVER: {
        if (stack.length < 2) return false;
        stack.push(Buffer.from(stack[stack.length - 2]));
        break;
      }

      case Opcode.OP_PICK: {
        if (stack.length < 1) return false;
        const n = scriptNumDecode(stack.pop()!, 4, !!flags.verifyMinimalData);
        if (n < 0 || n >= stack.length) return false;
        stack.push(Buffer.from(stack[stack.length - 1 - n]));
        break;
      }

      case Opcode.OP_ROLL: {
        if (stack.length < 1) return false;
        const n = scriptNumDecode(stack.pop()!, 4, !!flags.verifyMinimalData);
        if (n < 0 || n >= stack.length) return false;
        const item = stack.splice(stack.length - 1 - n, 1)[0];
        stack.push(item);
        break;
      }

      case Opcode.OP_ROT: {
        if (stack.length < 3) return false;
        const item = stack.splice(stack.length - 3, 1)[0];
        stack.push(item);
        break;
      }

      case Opcode.OP_SWAP: {
        if (stack.length < 2) return false;
        const tmp = stack[stack.length - 1];
        stack[stack.length - 1] = stack[stack.length - 2];
        stack[stack.length - 2] = tmp;
        break;
      }

      case Opcode.OP_TUCK: {
        if (stack.length < 2) return false;
        const top = stack[stack.length - 1];
        stack.splice(stack.length - 2, 0, Buffer.from(top));
        break;
      }

      // Splice
      case Opcode.OP_SIZE: {
        if (stack.length < 1) return false;
        stack.push(scriptNumEncode(stack[stack.length - 1].length));
        break;
      }

      // Bitwise
      case Opcode.OP_EQUAL: {
        if (stack.length < 2) return false;
        const a = stack.pop()!;
        const b = stack.pop()!;
        stack.push(a.equals(b) ? scriptNumEncode(1) : Buffer.alloc(0));
        break;
      }

      case Opcode.OP_EQUALVERIFY: {
        if (stack.length < 2) return false;
        const a = stack.pop()!;
        const b = stack.pop()!;
        if (!a.equals(b)) return false;
        break;
      }

      // Arithmetic
      case Opcode.OP_1ADD: {
        if (stack.length < 1) return false;
        const n = scriptNumDecode(stack.pop()!, 4, !!flags.verifyMinimalData);
        stack.push(scriptNumEncode(n + 1));
        break;
      }

      case Opcode.OP_1SUB: {
        if (stack.length < 1) return false;
        const n = scriptNumDecode(stack.pop()!, 4, !!flags.verifyMinimalData);
        stack.push(scriptNumEncode(n - 1));
        break;
      }

      case Opcode.OP_NEGATE: {
        if (stack.length < 1) return false;
        const n = scriptNumDecode(stack.pop()!, 4, !!flags.verifyMinimalData);
        stack.push(scriptNumEncode(-n));
        break;
      }

      case Opcode.OP_ABS: {
        if (stack.length < 1) return false;
        const n = scriptNumDecode(stack.pop()!, 4, !!flags.verifyMinimalData);
        stack.push(scriptNumEncode(Math.abs(n)));
        break;
      }

      case Opcode.OP_NOT: {
        if (stack.length < 1) return false;
        const n = scriptNumDecode(stack.pop()!, 4, !!flags.verifyMinimalData);
        stack.push(scriptNumEncode(n === 0 ? 1 : 0));
        break;
      }

      case Opcode.OP_0NOTEQUAL: {
        if (stack.length < 1) return false;
        const n = scriptNumDecode(stack.pop()!, 4, !!flags.verifyMinimalData);
        stack.push(scriptNumEncode(n !== 0 ? 1 : 0));
        break;
      }

      case Opcode.OP_ADD: {
        if (stack.length < 2) return false;
        const b = scriptNumDecode(stack.pop()!, 4, !!flags.verifyMinimalData);
        const a = scriptNumDecode(stack.pop()!, 4, !!flags.verifyMinimalData);
        stack.push(scriptNumEncode(a + b));
        break;
      }

      case Opcode.OP_SUB: {
        if (stack.length < 2) return false;
        const b = scriptNumDecode(stack.pop()!, 4, !!flags.verifyMinimalData);
        const a = scriptNumDecode(stack.pop()!, 4, !!flags.verifyMinimalData);
        stack.push(scriptNumEncode(a - b));
        break;
      }

      case Opcode.OP_BOOLAND: {
        if (stack.length < 2) return false;
        const b = scriptNumDecode(stack.pop()!, 4, !!flags.verifyMinimalData);
        const a = scriptNumDecode(stack.pop()!, 4, !!flags.verifyMinimalData);
        stack.push(scriptNumEncode(a !== 0 && b !== 0 ? 1 : 0));
        break;
      }

      case Opcode.OP_BOOLOR: {
        if (stack.length < 2) return false;
        const b = scriptNumDecode(stack.pop()!, 4, !!flags.verifyMinimalData);
        const a = scriptNumDecode(stack.pop()!, 4, !!flags.verifyMinimalData);
        stack.push(scriptNumEncode(a !== 0 || b !== 0 ? 1 : 0));
        break;
      }

      case Opcode.OP_NUMEQUAL: {
        if (stack.length < 2) return false;
        const b = scriptNumDecode(stack.pop()!, 4, !!flags.verifyMinimalData);
        const a = scriptNumDecode(stack.pop()!, 4, !!flags.verifyMinimalData);
        stack.push(scriptNumEncode(a === b ? 1 : 0));
        break;
      }

      case Opcode.OP_NUMEQUALVERIFY: {
        if (stack.length < 2) return false;
        const b = scriptNumDecode(stack.pop()!, 4, !!flags.verifyMinimalData);
        const a = scriptNumDecode(stack.pop()!, 4, !!flags.verifyMinimalData);
        if (a !== b) return false;
        break;
      }

      case Opcode.OP_NUMNOTEQUAL: {
        if (stack.length < 2) return false;
        const b = scriptNumDecode(stack.pop()!, 4, !!flags.verifyMinimalData);
        const a = scriptNumDecode(stack.pop()!, 4, !!flags.verifyMinimalData);
        stack.push(scriptNumEncode(a !== b ? 1 : 0));
        break;
      }

      case Opcode.OP_LESSTHAN: {
        if (stack.length < 2) return false;
        const b = scriptNumDecode(stack.pop()!, 4, !!flags.verifyMinimalData);
        const a = scriptNumDecode(stack.pop()!, 4, !!flags.verifyMinimalData);
        stack.push(scriptNumEncode(a < b ? 1 : 0));
        break;
      }

      case Opcode.OP_GREATERTHAN: {
        if (stack.length < 2) return false;
        const b = scriptNumDecode(stack.pop()!, 4, !!flags.verifyMinimalData);
        const a = scriptNumDecode(stack.pop()!, 4, !!flags.verifyMinimalData);
        stack.push(scriptNumEncode(a > b ? 1 : 0));
        break;
      }

      case Opcode.OP_LESSTHANOREQUAL: {
        if (stack.length < 2) return false;
        const b = scriptNumDecode(stack.pop()!, 4, !!flags.verifyMinimalData);
        const a = scriptNumDecode(stack.pop()!, 4, !!flags.verifyMinimalData);
        stack.push(scriptNumEncode(a <= b ? 1 : 0));
        break;
      }

      case Opcode.OP_GREATERTHANOREQUAL: {
        if (stack.length < 2) return false;
        const b = scriptNumDecode(stack.pop()!, 4, !!flags.verifyMinimalData);
        const a = scriptNumDecode(stack.pop()!, 4, !!flags.verifyMinimalData);
        stack.push(scriptNumEncode(a >= b ? 1 : 0));
        break;
      }

      case Opcode.OP_MIN: {
        if (stack.length < 2) return false;
        const b = scriptNumDecode(stack.pop()!, 4, !!flags.verifyMinimalData);
        const a = scriptNumDecode(stack.pop()!, 4, !!flags.verifyMinimalData);
        stack.push(scriptNumEncode(Math.min(a, b)));
        break;
      }

      case Opcode.OP_MAX: {
        if (stack.length < 2) return false;
        const b = scriptNumDecode(stack.pop()!, 4, !!flags.verifyMinimalData);
        const a = scriptNumDecode(stack.pop()!, 4, !!flags.verifyMinimalData);
        stack.push(scriptNumEncode(Math.max(a, b)));
        break;
      }

      case Opcode.OP_WITHIN: {
        if (stack.length < 3) return false;
        const max = scriptNumDecode(stack.pop()!, 4, !!flags.verifyMinimalData);
        const min = scriptNumDecode(stack.pop()!, 4, !!flags.verifyMinimalData);
        const x = scriptNumDecode(stack.pop()!, 4, !!flags.verifyMinimalData);
        stack.push(scriptNumEncode(x >= min && x < max ? 1 : 0));
        break;
      }

      // Crypto
      case Opcode.OP_RIPEMD160: {
        if (stack.length < 1) return false;
        const data = stack.pop()!;
        stack.push(Buffer.from(ripemd160(data)));
        break;
      }

      case Opcode.OP_SHA1: {
        if (stack.length < 1) return false;
        const data = stack.pop()!;
        stack.push(Buffer.from(sha1(data)));
        break;
      }

      case Opcode.OP_SHA256: {
        if (stack.length < 1) return false;
        const data = stack.pop()!;
        stack.push(sha256Hash(data));
        break;
      }

      case Opcode.OP_HASH160: {
        if (stack.length < 1) return false;
        const data = stack.pop()!;
        stack.push(hash160(data));
        break;
      }

      case Opcode.OP_HASH256: {
        if (stack.length < 1) return false;
        const data = stack.pop()!;
        stack.push(hash256(data));
        break;
      }

      case Opcode.OP_CODESEPARATOR: {
        codeSepPos = pc;
        break;
      }

      case Opcode.OP_CHECKSIG:
      case Opcode.OP_CHECKSIGVERIFY: {
        if (stack.length < 2) return false;

        // IMPORTANT: Pop pubkey first (top of stack), then signature
        const pubkey = stack.pop()!;
        const sig = stack.pop()!;

        let success = false;

        if (sigVersion === SigVersion.TAPSCRIPT) {
          // BIP-342 validation-weight budget: decrement by 50 BEFORE
          // pubkey inspection, gated on sig.length > 0. Mirrors Core's
          // `success = !sig.empty()` check at interpreter.cpp:357-366.
          // Empty sigs do NOT consume budget. Per Core's comment,
          // "Passing with an upgradable public key version is also
          // counted", so the deduction fires for any non-empty sig.
          if (sig.length > 0 && ctx.sigopsBudget !== undefined) {
            ctx.sigopsBudget -= TAPSCRIPT_SIGOPS_PER_SIGCHECK;
            if (ctx.sigopsBudget < 0) {
              throw new ScriptError("TAPSCRIPT_VALIDATION_WEIGHT");
            }
          }
          // Tapscript: use Schnorr signatures (BIP-342)
          success = verifySchnorrSig(sig, pubkey, ctx, codeSepPos);
        } else {
          // Legacy or witness v0: use ECDSA

          // Validate signature and pubkey encoding per active flags
          checkSignatureEncoding(sig, flags);
          checkPubKeyEncoding(pubkey, flags, sigVersion);

          if (sig.length > 0) {
            const hashType = sig[sig.length - 1];
            const sigBytes = sig.subarray(0, sig.length - 1);

            // Build subscript for sighash
            let subscript: Buffer;
            if (sigVersion === SigVersion.BASE) {
              // For legacy, we need to remove the signature from the scriptCode
              const scriptCode = serializeScript(script.slice(codeSepPos === 0xffffffff ? 0 : codeSepPos + 1));
              subscript = findAndDelete(scriptCode, sig);
            } else {
              // For segwit, just use the scriptCode without FindAndDelete
              subscript = serializeScript(script.slice(codeSepPos === 0xffffffff ? 0 : codeSepPos + 1));
            }

            const sighash = sigHasher(subscript, hashType);
            success = ecdsaVerifyLax(sigBytes, sighash, pubkey);
          }

          // NULLFAIL: If signature check fails and signature is non-empty, fail
          if (!success && flags.verifyNullFail && sig.length > 0) {
            return false;
          }
        }

        if (opcode === Opcode.OP_CHECKSIGVERIFY) {
          if (!success) return false;
        } else {
          stack.push(success ? scriptNumEncode(1) : Buffer.alloc(0));
        }
        break;
      }

      case Opcode.OP_CHECKSIGADD: {
        // BIP-342: OP_CHECKSIGADD for tapscript
        // Stack: ... sig n pubkey -> ... n+sig_result (where sig_result is 0 or 1)
        if (sigVersion !== SigVersion.TAPSCRIPT) {
          // OP_CHECKSIGADD is only valid in tapscript
          return false;
        }

        if (stack.length < 3) return false;

        const pubkey = stack.pop()!;
        const nElement = stack.pop()!;
        const sig = stack.pop()!;

        // Decode n as a script number
        const n = scriptNumDecode(nElement, 4, !!flags.verifyMinimalData);

        // Verify signature
        let sigResult = 0;
        if (sig.length === 0) {
          // Empty signature means no signature provided (result is 0)
          sigResult = 0;
        } else {
          // Verify the Schnorr signature
          const success = verifySchnorrSig(sig, pubkey, ctx, codeSepPos);
          sigResult = success ? 1 : 0;

          // Consume sigops budget
          if (ctx.sigopsBudget !== undefined) {
            ctx.sigopsBudget -= TAPSCRIPT_SIGOPS_PER_SIGCHECK;
            if (ctx.sigopsBudget < 0) {
              throw new ScriptError("TAPSCRIPT_VALIDATION_WEIGHT");
            }
          }
        }

        // Push n + sig_result
        stack.push(scriptNumEncode(n + sigResult));
        break;
      }

      case Opcode.OP_CHECKMULTISIG:
      case Opcode.OP_CHECKMULTISIGVERIFY: {
        // OP_CHECKMULTISIG is disabled in tapscript (BIP-342)
        if (sigVersion === SigVersion.TAPSCRIPT) {
          throw new ScriptError("TAPSCRIPT_CHECKMULTISIG");
        }

        // Get n (number of pubkeys)
        if (stack.length < 1) return false;
        const n = scriptNumDecode(stack.pop()!, 4, !!flags.verifyMinimalData);
        if (n < 0 || n > MAX_PUBKEYS_PER_MULTISIG) return false;

        opCount += n;
        if (opCount > MAX_OPS_PER_SCRIPT) return false;

        // Get pubkeys
        if (stack.length < n) return false;
        const pubkeys: Buffer[] = [];
        for (let i = 0; i < n; i++) {
          pubkeys.push(stack.pop()!);
        }

        // Get m (number of required signatures)
        if (stack.length < 1) return false;
        const m = scriptNumDecode(stack.pop()!, 4, !!flags.verifyMinimalData);
        if (m < 0 || m > n) return false;

        // Get signatures
        if (stack.length < m) return false;
        const sigs: Buffer[] = [];
        for (let i = 0; i < m; i++) {
          sigs.push(stack.pop()!);
        }

        // Pop the dummy element (bug in original Bitcoin)
        if (stack.length < 1) return false;
        const dummy = stack.pop()!;

        // NULLDUMMY: dummy must be empty when flag is set
        if (flags.verifyNullDummy && dummy.length !== 0) {
          return false;
        }

        // Build subscript
        let subscript: Buffer;
        if (sigVersion === SigVersion.BASE) {
          subscript = serializeScript(script.slice(codeSepPos === 0xffffffff ? 0 : codeSepPos + 1));
          // Remove all signatures from scriptCode
          for (const sig of sigs) {
            subscript = findAndDelete(subscript, sig);
          }
        } else {
          subscript = serializeScript(script.slice(codeSepPos === 0xffffffff ? 0 : codeSepPos + 1));
        }

        // Verify signatures
        // Algorithm: try to match each signature to a key, moving forward through both.
        // Empty signatures always fail the check (don't match any key).
        let success = true;
        let iKey = 0;
        let iSig = 0;

        while (iSig < sigs.length && success) {
          const sig = sigs[iSig];
          const pubkey = pubkeys[iKey];

          // Check encoding of signature and pubkey when actually testing them
          checkSignatureEncoding(sig, flags);
          checkPubKeyEncoding(pubkey, flags, sigVersion);

          let sigValid = false;
          if (sig.length > 0) {
            const hashType = sig[sig.length - 1];
            const sigBytes = sig.subarray(0, sig.length - 1);
            const sighash = sigHasher(subscript, hashType);
            sigValid = ecdsaVerifyLax(sigBytes, sighash, pubkey);
          }
          // Empty signatures always fail (sigValid remains false)

          if (sigValid) {
            iSig++;
          }

          iKey++;

          // Check if we have enough keys left
          if (sigs.length - iSig > pubkeys.length - iKey) {
            success = false;
          }
        }

        // NULLFAIL: If the operation failed, all signatures must be empty
        if (!success && flags.verifyNullFail) {
          for (const sig of sigs) {
            if (sig.length > 0) {
              return false;
            }
          }
        }

        if (opcode === Opcode.OP_CHECKMULTISIGVERIFY) {
          if (!success) return false;
        } else {
          stack.push(success ? scriptNumEncode(1) : Buffer.alloc(0));
        }
        break;
      }

      case Opcode.OP_RESERVED:
      case Opcode.OP_VER:
      case Opcode.OP_RESERVED1:
      case Opcode.OP_RESERVED2:
        return false;

      default:
        // Unknown opcode
        return false;
    }

    // Stack size check (after each operation)
    if (stack.length + altStack.length > MAX_STACK_SIZE) {
      return false;
    }
  }

  // Check for unbalanced conditionals
  if (condStack.length !== 0) {
    return false;
  }

  return true;
}

/**
 * Check if script is P2PKH: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
 */
export function isP2PKH(script: Buffer): boolean {
  return (
    script.length === 25 &&
    script[0] === Opcode.OP_DUP &&
    script[1] === Opcode.OP_HASH160 &&
    script[2] === 20 &&
    script[23] === Opcode.OP_EQUALVERIFY &&
    script[24] === Opcode.OP_CHECKSIG
  );
}

/**
 * Check if script is P2SH: OP_HASH160 <20 bytes> OP_EQUAL
 */
export function isP2SH(script: Buffer): boolean {
  return (
    script.length === 23 &&
    script[0] === Opcode.OP_HASH160 &&
    script[1] === 20 &&
    script[22] === Opcode.OP_EQUAL
  );
}

/**
 * Check if script is P2WPKH: OP_0 <20 bytes>
 */
export function isP2WPKH(script: Buffer): boolean {
  return script.length === 22 && script[0] === Opcode.OP_0 && script[1] === 20;
}

/**
 * Check if script is P2WSH: OP_0 <32 bytes>
 */
export function isP2WSH(script: Buffer): boolean {
  return script.length === 34 && script[0] === Opcode.OP_0 && script[1] === 32;
}

/**
 * Check if script is P2TR: OP_1 <32 bytes>
 */
export function isP2TR(script: Buffer): boolean {
  return script.length === 34 && script[0] === Opcode.OP_1 && script[1] === 32;
}

/**
 * Pay-to-Anchor (P2A) script constant.
 * This is a witness v1 program with a 2-byte program (0x4e73, "Ns" in ASCII).
 * P2A outputs are anyone-can-spend and used for fee bumping via CPFP.
 *
 * Script: OP_1 OP_PUSHBYTES_2 0x4e 0x73 (4 bytes total)
 * Reference: Bitcoin Core script.cpp IsPayToAnchor()
 */
export const P2A_SCRIPT = Buffer.from([0x51, 0x02, 0x4e, 0x73]);

/**
 * Check if script is P2A (Pay-to-Anchor): OP_1 <2 bytes: 0x4e73>
 *
 * P2A is a specific witness v1 program used for anchor outputs.
 * It's anyone-can-spend (requires empty witness) and must have 0 value.
 *
 * Reference: Bitcoin Core script.cpp IsPayToAnchor()
 */
export function isP2A(script: Buffer): boolean {
  return (
    script.length === 4 &&
    script[0] === Opcode.OP_1 &&
    script[1] === 0x02 &&
    script[2] === 0x4e &&
    script[3] === 0x73
  );
}

/**
 * Check if a witness program is P2A (given version and program bytes).
 * This is used after parsing a witness program to identify anchors.
 *
 * Reference: Bitcoin Core script.cpp IsPayToAnchor(int version, vector<unsigned char>& program)
 */
export function isP2AProgram(version: number, program: Buffer): boolean {
  return (
    version === 1 &&
    program.length === 2 &&
    program[0] === 0x4e &&
    program[1] === 0x73
  );
}

/**
 * Transaction output types for the script solver.
 * Matches Bitcoin Core's TxoutType enum.
 */
export type TxoutType =
  | "p2pkh"
  | "p2sh"
  | "p2wpkh"
  | "p2wsh"
  | "p2tr"
  | "anchor"
  | "nulldata"
  | "witness_unknown"
  | "nonstandard";

/**
 * Detect script type.
 * Returns both AddressType-compatible values and extended TxoutType values.
 */
export function getScriptType(script: Buffer): TxoutType {
  if (isP2PKH(script)) return "p2pkh";
  if (isP2SH(script)) return "p2sh";
  if (isP2WPKH(script)) return "p2wpkh";
  if (isP2WSH(script)) return "p2wsh";
  // Check P2A before P2TR since P2A is a specific witness v1 program
  if (isP2A(script)) return "anchor";
  if (isP2TR(script)) return "p2tr";
  // Check for OP_RETURN (nulldata)
  if (script.length >= 1 && script[0] === Opcode.OP_RETURN) return "nulldata";
  // Check for unknown witness versions (witness v2-v16)
  if (isWitnessProgram(script)) return "witness_unknown";
  return "nonstandard";
}

/**
 * Check if a script is a valid witness program (any version).
 * Witness programs are: OP_n (where n is 0-16) followed by a push of 2-40 bytes.
 */
export function isWitnessProgram(script: Buffer): boolean {
  if (script.length < 4 || script.length > 42) return false;
  // First byte must be OP_0 (0x00) or OP_1-OP_16 (0x51-0x60)
  const version = script[0];
  if (version !== 0x00 && (version < 0x51 || version > 0x60)) return false;
  // Second byte must be the push length (2-40 bytes)
  const pushLen = script[1];
  if (pushLen < 2 || pushLen > 40) return false;
  // Total length must match: version (1) + push opcode (1) + data (pushLen)
  return script.length === 2 + pushLen;
}

/**
 * Build an implicit P2PKH script from a pubkey hash.
 */
function buildP2PKHScript(pubkeyHash: Buffer): Buffer {
  return Buffer.concat([
    Buffer.from([Opcode.OP_DUP, Opcode.OP_HASH160, 20]),
    pubkeyHash,
    Buffer.from([Opcode.OP_EQUALVERIFY, Opcode.OP_CHECKSIG]),
  ]);
}

/**
 * Context for taproot signature verification.
 * Includes the sighash function for key-path and script-path spending.
 */
export interface TaprootContext {
  /**
   * Compute taproot sighash for key-path spending.
   * @param hashType - 0x00 for SIGHASH_DEFAULT, or standard sighash type
   */
  keyPathSigHasher: (hashType: number) => Buffer;
  /**
   * Compute taproot sighash for script-path spending.
   * @param hashType - Sighash type
   * @param leafHash - 32-byte tap leaf hash
   * @param codeSepPos - Position of last executed OP_CODESEPARATOR (0xFFFFFFFF if none)
   */
  scriptPathSigHasher: (hashType: number, leafHash: Buffer, codeSepPos: number) => Buffer;
}

/**
 * Verify a complete script (scriptSig + scriptPubKey + witness).
 * Handles P2PKH, P2SH, P2WPKH, P2WSH, P2TR evaluation.
 */
export function verifyScript(
  scriptSig: Buffer,
  scriptPubKey: Buffer,
  witness: Buffer[],
  flags: ScriptFlags,
  sigHasher: (subscript: Buffer, hashType: number) => Buffer,
  taprootCtx?: TaprootContext,
  txContext?: { txVersion: number; txLockTime: number; txSequence: number },
  witnessSigHasher?: (subscript: Buffer, hashType: number) => Buffer
): boolean {
  // Check script size limits
  if (scriptSig.length > MAX_SCRIPT_SIZE || scriptPubKey.length > MAX_SCRIPT_SIZE) {
    return false;
  }

  // Parse scripts
  let parsedSig: Script;
  let parsedPubKey: Script;
  try {
    parsedSig = parseScript(scriptSig);
    parsedPubKey = parseScript(scriptPubKey);
  } catch {
    return false;
  }

  // SIG_PUSHONLY: When flag is set, scriptSig must be push-only
  if (flags.verifySigPushOnly && !isPushOnly(scriptSig)) {
    throw new ScriptError("SIG_PUSHONLY");
  }

  // Step 1: Execute scriptSig
  const stack: Buffer[] = [];
  const ctx: ExecutionContext = {
    stack,
    altStack: [],
    flags,
    sigHasher,
    txVersion: txContext?.txVersion,
    txLockTime: txContext?.txLockTime,
    txSequence: txContext?.txSequence,
    sigVersion: SigVersion.BASE,
  };

  if (!executeScript(parsedSig, ctx)) {
    return false;
  }

  // Copy stack for potential P2SH evaluation
  const stackCopy = stack.map((b) => Buffer.from(b));

  // Clear altstack between scriptSig and scriptPubKey (they don't share altstack)
  ctx.altStack.length = 0;

  // Step 2: Execute scriptPubKey
  if (!executeScript(parsedPubKey, ctx)) {
    return false;
  }

  // Check final stack
  if (stack.length === 0 || !castToBool(stack[stack.length - 1])) {
    return false;
  }

  // Step 3: P2SH evaluation
  if (flags.verifyP2SH && isP2SH(scriptPubKey)) {
    // scriptSig must be push-only for P2SH (BIP16)
    // This is enforced unconditionally for P2SH, separate from SCRIPT_VERIFY_SIGPUSHONLY
    if (!isPushOnly(scriptSig)) {
      throw new ScriptError("SIG_PUSHONLY");
    }

    if (stackCopy.length === 0) {
      return false;
    }

    // The top stack item is the serialized redeem script
    const redeemScript = stackCopy[stackCopy.length - 1];
    if (redeemScript.length > MAX_SCRIPT_SIZE) {
      return false;
    }

    let parsedRedeem: Script;
    try {
      parsedRedeem = parseScript(redeemScript);
    } catch {
      return false;
    }

    // Execute redeem script with remaining stack items
    const p2shStack = stackCopy.slice(0, -1);
    const p2shCtx: ExecutionContext = {
      stack: p2shStack,
      altStack: [],
      flags,
      sigHasher,
      sigVersion: SigVersion.BASE,
      txVersion: txContext?.txVersion,
      txLockTime: txContext?.txLockTime,
      txSequence: txContext?.txSequence,
    };

    if (!executeScript(parsedRedeem, p2shCtx)) {
      return false;
    }

    if (p2shStack.length === 0 || !castToBool(p2shStack[p2shStack.length - 1])) {
      return false;
    }

    // CLEANSTACK: after P2SH evaluation, stack must have exactly one element
    if (flags.verifyCleanStack && p2shStack.length !== 1) {
      throw new ScriptError("CLEANSTACK");
    }

    // Check for P2SH-wrapped witness
    if (flags.verifyWitness) {
      if (isP2WPKH(redeemScript)) {
        return verifyWitnessV0(redeemScript, witness, flags, witnessSigHasher ?? sigHasher);
      }
      if (isP2WSH(redeemScript)) {
        return verifyWitnessV0(redeemScript, witness, flags, witnessSigHasher ?? sigHasher);
      }
      if (isWitnessProgram(redeemScript)) {
        // P2SH-wrapped witness: check v0 program length
        const witnessVersion = redeemScript[0];
        const programLen = redeemScript[1];
        if (witnessVersion === 0x00 && programLen !== 20 && programLen !== 32) {
          throw new ScriptError("WITNESS_PROGRAM_WRONG_LENGTH");
        }
        if (flags.verifyDiscourageUpgradableWitnessProgram) {
          throw new ScriptError("DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM");
        }
        return true;
      }
      // P2SH non-witness: if witness is non-empty, fail
      if (witness.length > 0) {
        throw new ScriptError("WITNESS_UNEXPECTED");
      }
    }

    return true;
  }

  // CLEANSTACK: after non-P2SH evaluation, stack must have exactly one element
  if (flags.verifyCleanStack && stack.length !== 1) {
    throw new ScriptError("CLEANSTACK");
  }

  // Step 4: Native SegWit evaluation
  if (flags.verifyWitness) {
    if (isP2WPKH(scriptPubKey) || isP2WSH(scriptPubKey)) {
      // For native segwit, scriptSig must be empty
      if (scriptSig.length !== 0) {
        return false;
      }
      return verifyWitnessV0(scriptPubKey, witness, flags, witnessSigHasher ?? sigHasher);
    }

    if (flags.verifyTaproot && isP2TR(scriptPubKey)) {
      if (scriptSig.length !== 0) {
        return false;
      }
      // Full taproot verification
      return verifyTaproot(scriptPubKey, witness, flags, taprootCtx);
    }

    // P2A (Pay-to-Anchor): anyone-can-spend with empty witness
    // This is a witness v1 program with a 2-byte program (0x4e73)
    // Reference: Bitcoin Core interpreter.cpp VerifyWitnessProgram
    if (flags.verifyTaproot && isP2A(scriptPubKey)) {
      if (scriptSig.length !== 0) {
        return false;
      }
      // P2A requires empty witness (anyone can spend)
      if (witness.length !== 0) {
        return false;
      }
      return true;
    }

    // Unknown witness program: forward-compatible (BIP141)
    // If scriptPubKey is a witness program but not a known type, it succeeds
    // unless DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM is set
    if (isWitnessProgram(scriptPubKey)) {
      if (scriptSig.length !== 0) {
        return false;
      }

      // For witness v0, program must be exactly 20 (P2WPKH) or 32 (P2WSH) bytes.
      // Any other v0 program length is invalid (BIP141 consensus rule).
      const witnessVersion = scriptPubKey[0];
      const programLen = scriptPubKey[1];
      if (witnessVersion === 0x00 && programLen !== 20 && programLen !== 32) {
        throw new ScriptError("WITNESS_PROGRAM_WRONG_LENGTH");
      }

      if (flags.verifyDiscourageUpgradableWitnessProgram) {
        throw new ScriptError("DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM");
      }
      // Unknown witness versions succeed (anyone-can-spend for forward compatibility)
      return true;
    }

    // WITNESS flag is set but scriptPubKey is not a witness program:
    // If witness is non-empty, it must fail (BIP141 consensus rule)
    if (witness.length > 0) {
      throw new ScriptError("WITNESS_UNEXPECTED");
    }
  }

  return true;
}

// =============================================================================
// Taproot Verification (BIP-341/342)
// =============================================================================

/**
 * Verify a taproot (P2TR) witness program.
 * Handles both key-path and script-path spending.
 *
 * Key-path: witness = [signature] (64 or 65 bytes)
 * Script-path: witness = [...stack, script, control_block] with optional annex
 */
export function verifyTaproot(
  scriptPubKey: Buffer,
  witness: Buffer[],
  flags: ScriptFlags,
  taprootCtx?: TaprootContext
): boolean {
  // P2TR: OP_1 <32 bytes>
  // Output key Q is the 32-byte x-only pubkey in scriptPubKey
  const outputKeyBytes = scriptPubKey.subarray(2, 34);

  if (witness.length === 0) {
    return false;
  }

  // Check for annex: if >= 2 witness elements and last element starts with 0x50
  let annexHash: Buffer | undefined;
  let witnessStack = witness;

  if (witness.length >= 2 && witness[witness.length - 1][0] === TAPROOT_ANNEX_TAG) {
    // Extract annex and compute its hash
    const annex = witness[witness.length - 1];
    annexHash = sha256Hash(annex);
    // Remove annex from witness stack for further processing
    witnessStack = witness.slice(0, -1);
  }

  if (witnessStack.length === 1) {
    // Key-path spending: single witness element is the signature
    return verifyTaprootKeyPath(outputKeyBytes, witnessStack[0], annexHash, taprootCtx);
  } else {
    // Script-path spending: witness = [...stack, script, control_block]
    // Pass the FULL pre-strip `witness` (annex INCLUDED) for the
    // BIP-342 validation-weight budget seed — Core's
    // ::GetSerializeSize(witness.stack) at interpreter.cpp:1981
    // counts annex + control + script + args.
    return verifyTaprootScriptPath(outputKeyBytes, witnessStack, witness, annexHash, flags, taprootCtx);
  }
}

/**
 * Verify taproot key-path spending.
 *
 * The output key Q is directly used for verification (no tweak recomputation needed,
 * as we're verifying that the signature was made by whoever knows the tweak).
 *
 * @param outputKey - 32-byte x-only output key from scriptPubKey
 * @param signature - 64-byte Schnorr signature, or 65 bytes with sighash type
 * @param annexHash - SHA256 of annex if present
 * @param taprootCtx - Taproot context with sighash function
 */
function verifyTaprootKeyPath(
  outputKey: Buffer,
  signature: Buffer,
  annexHash: Buffer | undefined,
  taprootCtx?: TaprootContext
): boolean {
  if (!taprootCtx) {
    // No taproot context provided - cannot verify
    throw new ScriptError("TAPROOT_CONTEXT_MISSING");
  }

  // Signature must be 64 or 65 bytes
  if (signature.length !== 64 && signature.length !== 65) {
    throw new ScriptError("SCHNORR_SIG_SIZE");
  }

  // Extract hash type
  let hashType: number;
  let sigBytes: Buffer;

  if (signature.length === 65) {
    hashType = signature[64];
    sigBytes = signature.subarray(0, 64);
    // SIGHASH_DEFAULT (0x00) is not allowed with explicit byte
    if (hashType === 0x00) {
      throw new ScriptError("SCHNORR_SIG_HASHTYPE");
    }
  } else {
    // 64-byte signature implies SIGHASH_DEFAULT (0x00)
    hashType = 0x00;
    sigBytes = signature;
  }

  // Validate hash type
  if (!isValidTaprootHashType(hashType)) {
    throw new ScriptError("SCHNORR_SIG_HASHTYPE");
  }

  // Compute sighash
  const sighash = taprootCtx.keyPathSigHasher(hashType);

  // Verify Schnorr signature against the output key
  if (!schnorrVerify(sigBytes, sighash, outputKey)) {
    throw new ScriptError("SCHNORR_SIG");
  }

  return true;
}

/**
 * Verify taproot script-path spending.
 *
 * @param outputKey - 32-byte x-only output key from scriptPubKey
 * @param witnessStack - Witness elements (excluding annex): [...stack, script, control_block]
 * @param fullWitness - The ORIGINAL pre-strip witness (annex INCLUDED).
 *                     Used to seed the BIP-342 validation-weight budget
 *                     via ::GetSerializeSize(witness.stack) at Core's
 *                     interpreter.cpp:1981.
 * @param annexHash - SHA256 of annex if present
 * @param flags - Script verification flags
 * @param taprootCtx - Taproot context with sighash function
 */
function verifyTaprootScriptPath(
  outputKey: Buffer,
  witnessStack: Buffer[],
  fullWitness: Buffer[],
  annexHash: Buffer | undefined,
  flags: ScriptFlags,
  taprootCtx?: TaprootContext
): boolean {
  if (witnessStack.length < 2) {
    return false;
  }

  // Control block is the last element
  const controlBlock = witnessStack[witnessStack.length - 1];
  // Script is the second-to-last element
  const tapscript = witnessStack[witnessStack.length - 2];
  // Stack items are everything before the script
  const stack = witnessStack.slice(0, -2);

  // Validate control block size
  // Minimum: 33 bytes (1 byte version + 32 byte internal key)
  // Maximum: 33 + 128 * 32 = 4129 bytes
  if (controlBlock.length < TAPROOT_CONTROL_BASE_SIZE) {
    throw new ScriptError("TAPROOT_WRONG_CONTROL_SIZE");
  }

  // Control block size must be 33 + n*32 for some n
  if ((controlBlock.length - TAPROOT_CONTROL_BASE_SIZE) % TAPROOT_CONTROL_NODE_SIZE !== 0) {
    throw new ScriptError("TAPROOT_WRONG_CONTROL_SIZE");
  }

  const pathLen = (controlBlock.length - TAPROOT_CONTROL_BASE_SIZE) / TAPROOT_CONTROL_NODE_SIZE;
  if (pathLen > TAPROOT_CONTROL_MAX_NODE_COUNT) {
    throw new ScriptError("TAPROOT_WRONG_CONTROL_SIZE");
  }

  // Extract leaf version and parity from first byte
  const leafVersionWithParity = controlBlock[0];
  const leafVersion = leafVersionWithParity & TAPROOT_LEAF_MASK;
  const outputKeyParity = leafVersionWithParity & 0x01;

  // Extract internal pubkey (32 bytes)
  const internalPubKey = controlBlock.subarray(1, 33);

  // Compute leaf hash: tagged_hash("TapLeaf", leaf_version || compact_size(script_len) || script)
  const leafHash = computeTapLeafHash(leafVersion, tapscript);

  // Walk the Merkle path to compute the root
  let currentHash = leafHash;
  for (let i = 0; i < pathLen; i++) {
    const siblingOffset = TAPROOT_CONTROL_BASE_SIZE + i * TAPROOT_CONTROL_NODE_SIZE;
    const sibling = controlBlock.subarray(siblingOffset, siblingOffset + TAPROOT_CONTROL_NODE_SIZE);
    currentHash = computeTapBranchHash(currentHash, sibling);
  }

  // Compute tweaked key: Q = P + tagged_hash("TapTweak", P || merkle_root) * G
  const tweak = taggedHash("TapTweak", Buffer.concat([internalPubKey, currentHash]));

  // Tweak the internal pubkey
  let tweakedKey: Buffer;
  let tweakedKeyParity: number;
  try {
    const result = tweakPublicKeyWithParity(internalPubKey, tweak);
    tweakedKey = result.key;
    tweakedKeyParity = result.parity;
  } catch {
    throw new ScriptError("WITNESS_PROGRAM_MISMATCH");
  }

  // Verify the tweaked key matches the output key
  if (!tweakedKey.equals(outputKey)) {
    throw new ScriptError("WITNESS_PROGRAM_MISMATCH");
  }

  // Verify parity matches
  if (tweakedKeyParity !== outputKeyParity) {
    throw new ScriptError("WITNESS_PROGRAM_MISMATCH");
  }

  // If leaf version is 0xC0 (tapscript), execute the script with BIP-342 rules
  if (leafVersion === TAPROOT_LEAF_TAPSCRIPT) {
    return executeTapscript(tapscript, stack, leafHash, annexHash, flags, taprootCtx, fullWitness);
  }

  // Unknown leaf version: succeed (future extensibility)
  return true;
}

/**
 * Compute TapLeaf hash: tagged_hash("TapLeaf", leaf_version || compact_size(script_len) || script)
 */
function computeTapLeafHash(leafVersion: number, script: Buffer): Buffer {
  // Build the data: leaf_version (1 byte) + compact_size(script.length) + script
  const lenBytes = encodeCompactSize(script.length);
  const data = Buffer.concat([Buffer.from([leafVersion]), lenBytes, script]);
  return taggedHash("TapLeaf", data);
}

/**
 * Compute TapBranch hash: tagged_hash("TapBranch", sorted(a, b))
 * The two hashes are sorted lexicographically before hashing.
 */
function computeTapBranchHash(a: Buffer, b: Buffer): Buffer {
  // Sort lexicographically
  if (a.compare(b) < 0) {
    return taggedHash("TapBranch", Buffer.concat([a, b]));
  } else {
    return taggedHash("TapBranch", Buffer.concat([b, a]));
  }
}

/**
 * Encode a number as Bitcoin's compact size format.
 */
function encodeCompactSize(n: number): Buffer {
  if (n < 0xfd) {
    return Buffer.from([n]);
  } else if (n <= 0xffff) {
    return Buffer.from([0xfd, n & 0xff, (n >> 8) & 0xff]);
  } else if (n <= 0xffffffff) {
    return Buffer.from([0xfe, n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff, (n >> 24) & 0xff]);
  } else {
    throw new Error("Value too large for compact size");
  }
}

/**
 * Tweak a public key and return both the tweaked key and its parity.
 */
function tweakPublicKeyWithParity(pubkey: Buffer, tweak: Buffer): { key: Buffer; parity: number } {
  if (pubkey.length !== 32) {
    throw new Error("Public key must be 32 bytes (x-only)");
  }
  if (tweak.length !== 32) {
    throw new Error("Tweak must be 32 bytes");
  }

  // Lift x to a point (assume even y)
  const x = BigInt("0x" + pubkey.toString("hex"));
  const P = schnorr.utils.lift_x(x);

  // Convert tweak to bigint
  const t = BigInt("0x" + tweak.toString("hex"));

  // Compute tweak*G
  const Point = schnorr.Point;
  const tG = Point.BASE.multiply(t);

  // Add P + tG
  const tweaked = P.add(tG);

  // Check if y is even or odd
  const parity = tweaked.y % 2n === 0n ? 0 : 1;

  // Return x-only key (32 bytes)
  const xHex = tweaked.x.toString(16).padStart(64, "0");
  return {
    key: Buffer.from(xHex, "hex"),
    parity,
  };
}

/**
 * Check if a sighash type is valid for taproot.
 * Valid types: 0x00 (DEFAULT), 0x01 (ALL), 0x02 (NONE), 0x03 (SINGLE),
 * and any of these | 0x80 (ANYONECANPAY)
 */
function isValidTaprootHashType(hashType: number): boolean {
  if (hashType === 0x00) return true; // SIGHASH_DEFAULT
  const base = hashType & 0x1f;
  const anyoneCanPay = hashType & 0x80;
  // Base must be 0x01, 0x02, or 0x03
  if (base < 0x01 || base > 0x03) return false;
  // Only ANYONECANPAY flag is allowed
  if ((hashType & 0x7c) !== 0) return false;
  return true;
}

/**
 * Execute a tapscript (BIP-342).
 *
 * Tapscript rules:
 * - OP_CHECKSIG uses Schnorr instead of ECDSA
 * - OP_CHECKSIGADD replaces OP_CHECKMULTISIG
 * - OP_CHECKMULTISIG and OP_CHECKMULTISIGVERIFY are disabled
 * - OP_SUCCESSx opcodes cause immediate success
 * - MINIMALIF is enforced
 * - Sigops budget based on witness size
 */
function executeTapscript(
  script: Buffer,
  stack: Buffer[],
  leafHash: Buffer,
  annexHash: Buffer | undefined,
  flags: ScriptFlags,
  taprootCtx?: TaprootContext,
  fullWitness?: Buffer[],
): boolean {
  if (!taprootCtx) {
    throw new ScriptError("TAPROOT_CONTEXT_MISSING");
  }

  // Check for OP_SUCCESSx opcodes - if present, script succeeds immediately
  if (containsOpSuccess(script)) {
    return true;
  }

  // Parse the script
  let parsedScript: Script;
  try {
    parsedScript = parseScript(script);
  } catch {
    return false;
  }

  // BIP-342 validation-weight budget (interpreter.cpp:1981):
  //   m_validation_weight_left = ::GetSerializeSize(witness.stack)
  //                              + VALIDATION_WEIGHT_OFFSET (50)
  // `fullWitness` is the ORIGINAL pre-pop stack (annex INCLUDED,
  // control block + script INCLUDED, args INCLUDED), matching what
  // Core passes to ::GetSerializeSize. If a caller doesn't supply
  // fullWitness (test entry points), fall back to a conservative
  // approximation built from the post-pop stack + script bytes;
  // this is NOT consensus-safe but preserves the previous test API.
  const witnessForBudget = fullWitness
    ? serializedWitnessStackSize(fullWitness)
    : (() => {
        let n = script.length;
        for (const it of stack) n += it.length;
        return n;
      })();
  const sigopsBudget = TAPSCRIPT_SIGOPS_BUDGET_BASE + witnessForBudget;

  // Create sighash function for tapscript
  const taprootSigHasher = (hashType: number, codeSepPos: number): Buffer => {
    return taprootCtx.scriptPathSigHasher(hashType, leafHash, codeSepPos);
  };

  // Execute with tapscript rules
  const ctx: ExecutionContext = {
    stack: [...stack],
    altStack: [],
    flags: { ...flags, verifyMinimalIf: true }, // MINIMALIF always enforced
    sigHasher: () => Buffer.alloc(32), // Not used for tapscript
    sigVersion: SigVersion.TAPSCRIPT,
    taprootSigHasher,
    sigopsBudget,
  };

  if (!executeScript(parsedScript, ctx)) {
    return false;
  }

  // Clean stack check: exactly 1 true element
  if (ctx.stack.length !== 1) {
    throw new ScriptError("CLEANSTACK");
  }
  if (!castToBool(ctx.stack[0])) {
    return false;
  }

  return true;
}

/**
 * Verify witness v0 (P2WPKH or P2WSH).
 */
function verifyWitnessV0(
  witnessProgram: Buffer,
  witness: Buffer[],
  flags: ScriptFlags,
  sigHasher: (subscript: Buffer, hashType: number) => Buffer
): boolean {
  const programHash = witnessProgram.subarray(2);

  if (isP2WPKH(witnessProgram)) {
    // P2WPKH: witness = [signature, pubkey]
    if (witness.length !== 2) {
      return false;
    }

    // Check pubkey hash matches
    const pubkeyHash = hash160(witness[1]);
    if (!pubkeyHash.equals(programHash)) {
      return false;
    }

    // Build implicit P2PKH script and execute
    const p2pkhScript = buildP2PKHScript(programHash);
    const parsedScript = parseScript(p2pkhScript);

    // Witness stack: wire format is [sig, pubkey] where index 0 is stack bottom
    // and last index is stack top. No reversal needed.
    const witnessStack = [...witness];

    // Per BIP 141, MINIMALIF is enforced unconditionally in witness v0 (P2WSH)
    const witnessFlags: ScriptFlags = { ...flags, verifyMinimalIf: true };

    const ctx: ExecutionContext = {
      stack: witnessStack,
      altStack: [],
      flags: witnessFlags,
      sigHasher,
      sigVersion: SigVersion.WITNESS_V0,
    };

    if (!executeScript(parsedScript, ctx)) {
      return false;
    }

    // Witness cleanstack: stack must have exactly 1 element AND it must be true
    // This is NOT gated by SCRIPT_VERIFY_CLEANSTACK flag — it's always enforced for witness
    if (witnessStack.length !== 1) {
      throw new ScriptError("CLEANSTACK");
    }
    if (!castToBool(witnessStack[0])) {
      return false;
    }

    return true;
  }

  if (isP2WSH(witnessProgram)) {
    // P2WSH: witness = [...stack items, witnessScript]
    if (witness.length === 0) {
      return false;
    }

    // The last witness item is the witness script
    const witnessScript = witness[witness.length - 1];

    // Check script hash matches
    const scriptHash = sha256Hash(witnessScript);
    if (!scriptHash.equals(programHash)) {
      return false;
    }

    if (witnessScript.length > MAX_SCRIPT_SIZE) {
      return false;
    }

    let parsedScript: Script;
    try {
      parsedScript = parseScript(witnessScript);
    } catch {
      return false;
    }

    // Witness stack (excluding the script itself). Wire format is already
    // bottom-to-top (index 0 = bottom, last = top). No reversal needed.
    const witnessStack = [...witness.slice(0, -1)];

    // Per BIP 141, MINIMALIF is enforced unconditionally in witness v0 (P2WSH)
    const witnessFlags: ScriptFlags = { ...flags, verifyMinimalIf: true };

    const ctx: ExecutionContext = {
      stack: witnessStack,
      altStack: [],
      flags: witnessFlags,
      sigHasher,
      sigVersion: SigVersion.WITNESS_V0,
    };

    if (!executeScript(parsedScript, ctx)) {
      return false;
    }

    // Witness cleanstack: stack must have exactly 1 element AND it must be true
    // This is NOT gated by SCRIPT_VERIFY_CLEANSTACK flag — it's always enforced for witness
    if (witnessStack.length !== 1) {
      throw new ScriptError("CLEANSTACK");
    }
    if (!castToBool(witnessStack[0])) {
      return false;
    }

    return true;
  }

  return false;
}

/**
 * Create default consensus flags for a given block height.
 */
export function getConsensusFlags(height: number): ScriptFlags {
  return {
    verifyP2SH: height >= 173805, // BIP 16
    verifyDERSignatures: height >= 363725, // BIP 66
    verifyCheckLockTimeVerify: height >= 388381, // BIP 65
    verifyCheckSequenceVerify: height >= 419328, // BIP 112
    verifyWitness: height >= 481824, // BIP 141
    verifyNullDummy: height >= 481824, // BIP 147
    verifyNullFail: height >= 481824, // BIP 146 (activated with SegWit)
    verifyWitnessPubkeyType: height >= 481824, // BIP 141 (activated with SegWit)
    verifyTaproot: height >= 709632, // BIP 341
    // Policy flags - NOT consensus
    verifyStrictEncoding: false,
    verifyLowS: false,
  };
}
