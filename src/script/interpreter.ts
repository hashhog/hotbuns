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
  verifyDiscourageUpgradablePubkeyType?: boolean; // BIP 342 - policy - unknown tapscript pubkey types must error
  verifyDiscourageOpSuccess?: boolean; // BIP 342 - policy - OP_SUCCESSx must error
  verifyDiscourageUpgradableTaprootVersion?: boolean; // BIP 341 - policy - unknown leaf versions must error
  verifyConstScriptCode?: boolean; // SCRIPT_VERIFY_CONST_SCRIPTCODE - policy - OP_CODESEPARATOR / FindAndDelete in pre-segwit script must error
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
 * Reference: Bitcoin Core interpreter.cpp:190-199 IsDefinedHashtypeSignature.
 * Core returns false for empty sig (not true). checkSignatureEncoding guards
 * the empty case before calling this function, but the function must also
 * be correct per Core spec when called directly.
 */
function isDefinedHashtypeSignature(sig: Buffer): boolean {
  if (sig.length === 0) return false; // Core: returns false for empty sig
  const hashType = sig[sig.length - 1] & ~0x80; // Strip ANYONECANPAY (0x80)
  if (hashType < 1 || hashType > 3) return false; // Must be ALL(1), NONE(2), or SINGLE(3)
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
 *
 * Reference: Bitcoin Core interpreter.cpp:201-216 CheckSignatureEncoding.
 *
 * Gate ordering mirrors Core exactly:
 *   1. DER format check — fires when DERSIG | LOW_S | STRICTENC (any one) is set.
 *      Core line 207: `(flags & (DERSIG|LOW_S|STRICTENC)) != 0 && !IsValidSignatureEncoding`
 *      Bug fix: hotbuns previously omitted LOW_S from this gate, causing a wrong
 *      SIG_HIGH_S error code (instead of SIG_DER) when only verifyLowS was active
 *      and the DER format was malformed.
 *   2. LOW_S check — fires only when DERSIG check above already passed.
 *   3. STRICTENC hashtype check — fires after DER check.
 *
 * Note: the DER check is performed on the stripped sig (sig without hashtype byte),
 * so the bounds are 8 (min) / 72 (max) rather than Core's 9/73 (full sig). The
 * arithmetic is equivalent: stripped_len = full_len - 1.
 */
function checkSignatureEncoding(sig: Buffer, flags: ScriptFlags): boolean {
  if (sig.length === 0) return true;

  // Gate 1: DER format check.
  // Fires when ANY of DERSIG, LOW_S, or STRICTENC is active (Core line 207).
  // Critical: LOW_S must be included here — if only LOW_S is set and the DER is
  // malformed, Core returns SIG_DER (not SIG_HIGH_S).
  if ((flags.verifyDERSignatures || flags.verifyLowS || flags.verifyStrictEncoding) && !isValidSignatureEncoding(sig.subarray(0, sig.length - 1))) {
    throw new ScriptError("SIG_DER");
  }

  // Gate 2: LOW_S check — only reached when DER format above was valid.
  // isLowDERSignature internally re-validates DER (harmless), then checks S ≤ N/2.
  if (flags.verifyLowS && !isLowDERSignature(sig.subarray(0, sig.length - 1))) {
    throw new ScriptError("SIG_HIGH_S");
  }

  // Gate 3: STRICTENC hashtype check.
  if (flags.verifyStrictEncoding && !isDefinedHashtypeSignature(sig)) {
    throw new ScriptError("SIG_HASHTYPE");
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
 * Verify a Schnorr signature for tapscript (BIP-342). Mirrors Core's
 * `EvalChecksigTapscript` in `script/interpreter.cpp` (lines 347-385) plus
 * `CheckSchnorrSignature` (lines 1717-1742).
 *
 * Consensus-critical ordering, identical to Core:
 *   success = !sig.empty();
 *   if (success) deduct validation-weight budget;     // sigops/witnesssize ratio
 *   if (pubkey.size() == 0) -> TAPSCRIPT_EMPTY_PUBKEY  // ALWAYS, even with empty sig
 *   else if (pubkey.size() == 32) { if (success) verify; }
 *   else -> upgradable pubkey, success unchanged (DISCOURAGE flag may error)
 *
 * Returns the verification result (true/false) — this is what gets pushed onto
 * the stack by OP_CHECKSIG / accumulated by OP_CHECKSIGADD. Throws on hard
 * errors (empty pubkey, malformed Schnorr sig, exhausted budget).
 *
 * NOTE on budget: the caller is responsible for decrementing the validation-
 * weight budget BEFORE invoking this function (when sig is non-empty), so that
 * the budget-exhaustion error is reported with the correct error code
 * (TAPSCRIPT_VALIDATION_WEIGHT) and order relative to TAPSCRIPT_EMPTY_PUBKEY.
 * This function does NOT touch ctx.sigopsBudget.
 *
 * Earlier versions short-circuited on `sig.length === 0` before checking
 * pubkey.length === 0 — a consensus split vs Core, which rejects empty-pubkey
 * even with empty sig. Fixed in W94 BIP-341/342 audit.
 *
 * @param sig - Signature (64 bytes, or 65 bytes with sighash type)
 * @param pubkey - x-only public key (32 bytes, or upgradable)
 * @param ctx - Execution context with taproot sighash function
 * @param codeSepPos - Position of last OP_CODESEPARATOR
 * @param flags - Script verification flags (for DISCOURAGE_UPGRADABLE_PUBKEYTYPE)
 * @returns true if signature is valid (or upgradable pubkey + non-empty sig)
 */
function verifySchnorrSig(
  sig: Buffer,
  pubkey: Buffer,
  ctx: ExecutionContext,
  codeSepPos: number,
  flags?: ScriptFlags
): boolean {
  // BIP-342: Empty pubkey (0 bytes) always fails — checked BEFORE the empty-sig
  // short-circuit, because Core's EvalChecksigTapscript performs this check
  // unconditionally (interpreter.cpp:367-368). An empty sig + empty pubkey must
  // still trigger TAPSCRIPT_EMPTY_PUBKEY, not silently push 0.
  if (pubkey.length === 0) {
    throw new ScriptError("TAPSCRIPT_EMPTY_PUBKEY");
  }

  // Empty signature → no Schnorr check (sigops budget was already deducted
  // by the caller if sig was non-empty). For empty sig, success=false.
  if (sig.length === 0) {
    return false;
  }

  // BIP-342: Unknown pubkey type (not 32 bytes) — successful for forward
  // compatibility. Policy flag DISCOURAGE_UPGRADABLE_PUBKEYTYPE may make this
  // a hard error (e.g. on mempool acceptance), but consensus accepts.
  if (pubkey.length !== 32) {
    if (flags?.verifyDiscourageUpgradablePubkeyType) {
      throw new ScriptError("DISCOURAGE_UPGRADABLE_PUBKEYTYPE");
    }
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
 * Build the minimal-encoding push script for `data`, mirroring the
 * `CScript() << std::vector<unsigned char>` operator in Bitcoin Core
 * (interpreter.cpp:2082).
 *
 * Encoding rules (identical to blockbrew canonicalPushScript / Core CScript<<):
 *   - empty (0 bytes) → OP_0  (0x00)
 *   - 1–75 bytes      → <len> <data>                          (direct push)
 *   - 76–255 bytes    → OP_PUSHDATA1 <len8> <data>
 *   - 256–65535 bytes → OP_PUSHDATA2 <len16le> <data>
 *   - >65535 bytes    → OP_PUSHDATA4 <len32le> <data>
 *
 * Used by the P2SH-wrapped-witness malleation check (BIP141 §Native P2WPKH):
 * the scriptSig must be BYTE-FOR-BYTE equal to this value.
 */
function canonicalPushScript(data: Buffer): Buffer {
  const n = data.length;
  if (n === 0) {
    return Buffer.from([Opcode.OP_0]);
  }
  if (n <= 75) {
    const out = Buffer.allocUnsafe(1 + n);
    out[0] = n;
    data.copy(out, 1);
    return out;
  }
  if (n <= 0xff) {
    const out = Buffer.allocUnsafe(2 + n);
    out[0] = Opcode.OP_PUSHDATA1;
    out[1] = n;
    data.copy(out, 2);
    return out;
  }
  if (n <= 0xffff) {
    const out = Buffer.allocUnsafe(3 + n);
    out[0] = Opcode.OP_PUSHDATA2;
    out[1] = n & 0xff;
    out[2] = (n >> 8) & 0xff;
    data.copy(out, 3);
    return out;
  }
  const out = Buffer.allocUnsafe(5 + n);
  out[0] = Opcode.OP_PUSHDATA4;
  out[1] = n & 0xff;
  out[2] = (n >> 8) & 0xff;
  out[3] = (n >> 16) & 0xff;
  out[4] = (n >> 24) & 0xff;
  data.copy(out, 5);
  return out;
}

/**
 * Return the byte position immediately after the opcode (and its push data) at `pos`.
 *
 * Mirrors Bitcoin Core's CScript::GetOp() stepping used in FindAndDelete
 * (interpreter.cpp:229-255). CScript::GetOp advances pc past the entire push
 * payload; bytes inside a push payload are therefore NEVER at an opcode boundary
 * and are invisible to FindAndDelete's match check.
 *
 * Returns -1 when the script is truncated at pos (GetOp would return false).
 */
function opcodeEndPos(script: Buffer, pos: number): number {
  if (pos >= script.length) return pos;
  const opcode = script[pos];
  if (opcode >= 0x01 && opcode <= 0x4b) {
    // OP_PUSHBYTES_1..75: 1-byte opcode + opcode bytes of data
    const end = pos + 1 + opcode;
    return end <= script.length ? end : -1;
  } else if (opcode === 0x4c) { // OP_PUSHDATA1: 1 + 1 (len) + len
    if (pos + 1 >= script.length) return -1;
    const end = pos + 2 + script[pos + 1];
    return end <= script.length ? end : -1;
  } else if (opcode === 0x4d) { // OP_PUSHDATA2: 1 + 2 (len LE) + len
    if (pos + 2 >= script.length) return -1;
    const end = pos + 3 + (script[pos + 1] | (script[pos + 2] << 8));
    return end <= script.length ? end : -1;
  } else if (opcode === 0x4e) { // OP_PUSHDATA4: 1 + 4 (len LE) + len
    if (pos + 4 >= script.length) return -1;
    const end =
      pos + 5 +
      (script[pos + 1] |
        (script[pos + 2] << 8) |
        (script[pos + 3] << 16) |
        (script[pos + 4] << 24));
    return end <= script.length ? end : -1;
  } else {
    // OP_0 (0x00) and all non-push opcodes: 1 byte
    return pos + 1;
  }
}

/**
 * Remove all occurrences of a signature from scriptCode (FindAndDelete).
 * ONLY for legacy (BASE) signature version.
 *
 * Matches Core's FindAndDelete (interpreter.cpp:229-255) exactly: the scan
 * advances pc via CScript::GetOp(), so a match attempt is made ONLY at opcode
 * boundaries. A pushSig occurrence that begins inside a push data payload is
 * NEVER deleted. The old byte-by-byte fallback (advance by 1 on no-match) was
 * wrong — it could match pushSig bytes that happen to appear inside a larger
 * OP_PUSHDATA payload, giving a spurious found>0 and triggering
 * SCRIPT_VERIFY_CONST_SCRIPTCODE rejection for valid scripts.
 *
 * Returns both the rewritten script AND the number of occurrences removed.
 * Core's FindAndDelete returns the match count so the caller can enforce
 * SCRIPT_VERIFY_CONST_SCRIPTCODE — if a signature push was actually deleted
 * from the scriptCode while that flag is set, the script is rejected with
 * SCRIPT_ERR_SIG_FINDANDDELETE (interpreter.cpp:330-332 for CHECKSIG,
 * :1146-1148 for CHECKMULTISIG).
 */
function findAndDelete(script: Buffer, sig: Buffer): { result: Buffer; found: number } {
  if (sig.length === 0) {
    return { result: script, found: 0 };
  }

  // Build the canonical push-encoded signature to search for.
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

  // Opcode-aligned scan, mirroring Core interpreter.cpp:229-255.
  //
  // Core's do-while calls CScript::GetOp(pc, opcode) to advance pc past each
  // opcode boundary; the match check `std::equal(b.begin(), b.end(), pc)` fires
  // only BEFORE that GetOp call — i.e., always at an opcode boundary. Bytes
  // inside a push payload are never at an opcode boundary, so they are invisible.
  //
  // We replicate this by using opcodeEndPos() to advance pc, matching Core's
  // per-boundary semantics. `segStart` tracks the start of the current "keep"
  // segment so we build the output incrementally without copying unchanged bytes.
  let found = 0;
  const parts: Buffer[] = [];
  let segStart = 0; // start of the current kept segment
  let pc = 0;       // current opcode boundary (mirrors Core's `pc` iterator)

  while (pc < script.length) {
    // Delete all consecutive occurrences of pushSig starting at pc
    // (mirrors Core's inner while at interpreter.cpp:240-244).
    while (
      pc + pushSig.length <= script.length &&
      script.subarray(pc, pc + pushSig.length).equals(pushSig)
    ) {
      parts.push(script.subarray(segStart, pc)); // flush kept segment
      pc += pushSig.length;
      segStart = pc;
      found++;
    }
    // Advance pc past the current opcode (mirrors CScript::GetOp(pc, opcode)).
    const next = opcodeEndPos(script, pc);
    if (next < 0) break; // truncated script — stop (GetOp returned false)
    pc = next;
  }

  if (found === 0) {
    return { result: script, found: 0 };
  }

  // Flush the final kept segment (mirrors Core's post-loop insert at line 250).
  parts.push(script.subarray(segStart));
  return { result: Buffer.concat(parts), found };
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

    // SCRIPT_VERIFY_CONST_SCRIPTCODE: OP_CODESEPARATOR in a pre-segwit (BASE)
    // script is rejected even in an unexecuted branch (Core interpreter.cpp:
    // 474-476, SCRIPT_ERR_OP_CODESEPARATOR). Checked here — above the executing
    // guard — to match Core's placement above the opcode-case dispatch.
    if (
      opcode === Opcode.OP_CODESEPARATOR &&
      sigVersion === SigVersion.BASE &&
      flags.verifyConstScriptCode
    ) {
      throw new ScriptError("OP_CODESEPARATOR");
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
        // BIP-65: OP_CHECKLOCKTIMEVERIFY
        // Reference: bitcoin-core/src/script/interpreter.cpp:522-558 (OP_CLTV case)
        //            bitcoin-core/src/script/interpreter.cpp:1745-1779 (CheckLockTime)
        if (!flags.verifyCheckLockTimeVerify) {
          if (flags.verifyDiscourageUpgradableNops) {
            throw new ScriptError("DISCOURAGE_UPGRADABLE_NOPS");
          }
          break; // Treated as NOP2
        }
        // Gate 1: empty stack → invalid stack operation
        if (stack.length < 1) throw new ScriptError("INVALID_STACK_OPERATION");
        // Gate 2: 5-byte script num (year-2038-safe, per BIP-65 §Motivation)
        // Value is checked but NOT popped.
        // bug-hunt 8B: Core passes fRequireMinimal — CScriptNum(stacktop(-1),
        // fRequireMinimal, 5) (interpreter.cpp OP_CHECKLOCKTIMEVERIFY). A
        // non-minimally-encoded operand must be rejected under MINIMALDATA, same
        // as every arithmetic opcode below; previously this dropped the flag.
        const locktime = scriptNumDecode(stack[stack.length - 1], 5, !!flags.verifyMinimalData);
        // Gate 3: negative operand → reject
        if (locktime < 0) throw new ScriptError("NEGATIVE_LOCKTIME");

        // Gates 4-6: require txLockTime / txSequence from spending context.
        // Missing context is treated as UNSATISFIED (fail-safe, not fail-open).
        // Pre-fix bug: `if (ctx.txLockTime !== undefined)` wrapped all checks,
        // letting scripts with CLTV pass silently when no txContext was supplied
        // (e.g. in verifyWitnessV0 / executeTapscript, which didn't thread it).
        // Core ref: CheckLockTime() is always called unconditionally — there is
        // no "no context" code path in the C++ checker.
        if (ctx.txLockTime === undefined) {
          throw new ScriptError("UNSATISFIED_LOCKTIME");
        }
        const txLockTime = ctx.txLockTime;

        // Gate 4: both must be in the same domain (block-height vs. block-time).
        // LOCKTIME_THRESHOLD = 500_000_000 (script/script.h:47)
        const LOCKTIME_THRESHOLD = 500_000_000;
        if (
          (locktime < LOCKTIME_THRESHOLD && txLockTime >= LOCKTIME_THRESHOLD) ||
          (locktime >= LOCKTIME_THRESHOLD && txLockTime < LOCKTIME_THRESHOLD)
        ) {
          throw new ScriptError("UNSATISFIED_LOCKTIME");
        }

        // Gate 5: operand must be <= tx nLockTime (Core: if nLockTime > txTo->nLockTime return false)
        if (locktime > txLockTime) {
          throw new ScriptError("UNSATISFIED_LOCKTIME");
        }

        // Gate 6: spending input's nSequence must not be SEQUENCE_FINAL (0xffffffff).
        // When all inputs are final, nLockTime is ignored by IsFinalTx, which
        // would make CLTV bypassable.  Core: if SEQUENCE_FINAL == txTo->vin[nIn].nSequence return false.
        // Pre-fix bug: `if (ctx.txSequence !== undefined && ...)` — double-optional
        // guard skipped the check when txSequence was absent.
        if (ctx.txSequence === undefined) {
          throw new ScriptError("UNSATISFIED_LOCKTIME");
        }
        if (ctx.txSequence === 0xFFFFFFFF) {
          throw new ScriptError("UNSATISFIED_LOCKTIME");
        }
        break;
      }

      case Opcode.OP_CHECKSEQUENCEVERIFY: {
        // BIP-112: OP_CHECKSEQUENCEVERIFY
        // Reference: bitcoin-core/src/script/interpreter.cpp:561-593,
        //            GenericTransactionSignatureChecker::CheckSequence():1782-1826
        if (!flags.verifyCheckSequenceVerify) {
          if (flags.verifyDiscourageUpgradableNops) {
            throw new ScriptError("DISCOURAGE_UPGRADABLE_NOPS");
          }
          break; // Treated as NOP3
        }
        if (stack.length < 1) throw new ScriptError("INVALID_STACK_OPERATION");
        // nSequence is a 32-bit unsigned field; allow 5-byte encoding.
        // bug-hunt 8B: Core: CScriptNum(stacktop(-1), fRequireMinimal, 5)
        // (interpreter.cpp OP_CHECKSEQUENCEVERIFY) — honor MINIMALDATA here too.
        const sequence = scriptNumDecode(stack[stack.length - 1], 5, !!flags.verifyMinimalData);
        if (sequence < 0) throw new ScriptError("NEGATIVE_LOCKTIME");

        // If the disable flag (bit 31) is set, CSV behaves as NOP (BIP-112 §3)
        // Use >>> 0 to treat sequence as unsigned 32-bit before masking
        if ((sequence >>> 0) & 0x80000000) break;

        // CSV requires spending tx version >= 2 (BIP-68 activation)
        // Core: if (txTo->version < 2) return false;  — unconditional.
        // Core's `txTo->version` is uint32_t (primitives/transaction.h), so the
        // `< 2` comparison is UNSIGNED. hotbuns deserializeTx reads the version
        // with readInt32LE (signed), so a wire version of 0xffffffff arrives as
        // -1 and would spuriously fail the gate (false-reject; tx_valid.json
        // vector 165). Coerce to unsigned (>>> 0) to match Core's uint32_t
        // semantics. Core ref: interpreter.cpp:1790 CheckSequence().
        if (ctx.txVersion === undefined || (ctx.txVersion >>> 0) < 2) {
          throw new ScriptError("UNSATISFIED_LOCKTIME");
        }

        // Core: unconditional — if txToSequence disable flag set, fail
        if (ctx.txSequence === undefined) {
          throw new ScriptError("UNSATISFIED_LOCKTIME");
        }
        const txSeq = ctx.txSequence;
        // If input's sequence has the disable flag set (bit 31), CSV fails
        // (BIP-112: the spending input's sequence must not have the disable bit)
        if ((txSeq >>> 0) & 0x80000000) {
          throw new ScriptError("UNSATISFIED_LOCKTIME");
        }

        // Mask both operands to TYPE_FLAG | MASK before comparing (Core: nLockTimeMask)
        // This ensures we compare apples-to-apples: both height-based or both time-based.
        const nLockTimeMask = 0x00400000 | 0x0000ffff; // SEQUENCE_LOCKTIME_TYPE_FLAG | MASK
        const txSeqMasked = (txSeq >>> 0) & nLockTimeMask;
        const seqMasked = (sequence >>> 0) & nLockTimeMask;

        // Both must be in the same type (height-based or time-based)
        // height-based: masked value < TYPE_FLAG (bit 22 clear)
        // time-based:   masked value >= TYPE_FLAG (bit 22 set)
        const TYPE_FLAG = 0x00400000; // 1 << 22
        if (!(
          (txSeqMasked < TYPE_FLAG && seqMasked < TYPE_FLAG) ||
          (txSeqMasked >= TYPE_FLAG && seqMasked >= TYPE_FLAG)
        )) {
          throw new ScriptError("UNSATISFIED_LOCKTIME");
        }

        // The script operand must be <= the input's sequence (both masked)
        if (seqMasked > txSeqMasked) {
          throw new ScriptError("UNSATISFIED_LOCKTIME");
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
          // Tapscript: use Schnorr signatures (BIP-342). Note that the
          // budget was just deducted above; verifySchnorrSig still performs
          // the unconditional EMPTY_PUBKEY check before short-circuiting on
          // empty sig, so an empty sig + empty pubkey case correctly errors.
          success = verifySchnorrSig(sig, pubkey, ctx, codeSepPos, flags);
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
              const fad = findAndDelete(scriptCode, sig);
              // SCRIPT_VERIFY_CONST_SCRIPTCODE: if a signature push was actually
              // deleted from the scriptCode, reject (Core interpreter.cpp:330-332).
              if (fad.found > 0 && flags.verifyConstScriptCode) {
                throw new ScriptError("SIG_FINDANDDELETE");
              }
              subscript = fad.result;
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
        // BIP-342: OP_CHECKSIGADD for tapscript.
        // Stack: ... sig n pubkey -> ... n+sig_result (where sig_result is 0 or 1)
        //
        // Mirrors Core's interpreter.cpp:1058-1102 (OP_CHECKSIGADD case) which
        // delegates to EvalChecksig -> EvalChecksigTapscript. Consensus-critical
        // ordering identical to OP_CHECKSIG:
        //   1) budget deduct iff sig non-empty (BEFORE pubkey check, so a
        //      budget-exhausted upgradable-pubkey-only failure still surfaces
        //      as TAPSCRIPT_VALIDATION_WEIGHT not TAPSCRIPT_EMPTY_PUBKEY)
        //   2) empty pubkey -> TAPSCRIPT_EMPTY_PUBKEY (ALWAYS, even empty sig)
        //   3) 32-byte pubkey -> Schnorr verify if non-empty sig
        //   4) other size -> upgradable, success preserved
        //
        // Pre-W94 behavior: if `sig.length === 0`, the function silently set
        // sigResult=0 and SKIPPED the empty-pubkey check entirely, allowing
        // CHECKSIGADD with an empty pubkey + empty sig to push n+0 instead
        // of erroring. That was a consensus split vs Core, which always
        // rejects empty pubkey.
        if (sigVersion !== SigVersion.TAPSCRIPT) {
          // OP_CHECKSIGADD is only valid in tapscript
          return false;
        }

        if (stack.length < 3) return false;

        const pubkey = stack.pop()!;
        const nElement = stack.pop()!;
        const sig = stack.pop()!;

        // Decode n as a script number. BIP-342 explicitly bounds the
        // accumulator to 4-byte CScriptNum (same as the rest of script).
        const n = scriptNumDecode(nElement, 4, !!flags.verifyMinimalData);

        // 1) Budget deduction BEFORE pubkey check (Core: EvalChecksigTapscript
        //    interpreter.cpp:357-366). Only fires when sig is non-empty —
        //    empty sig => `success=false` => budget untouched.
        if (sig.length > 0 && ctx.sigopsBudget !== undefined) {
          ctx.sigopsBudget -= TAPSCRIPT_SIGOPS_PER_SIGCHECK;
          if (ctx.sigopsBudget < 0) {
            throw new ScriptError("TAPSCRIPT_VALIDATION_WEIGHT");
          }
        }

        // 2-4) verifySchnorrSig encapsulates the unconditional empty-pubkey
        //      check, the 32-byte Schnorr verify path, and the upgradable
        //      pubkey type policy gate. Returns false for empty sig + valid
        //      32-byte pubkey (no error), true for non-empty sig that
        //      verifies, true for non-empty sig with upgradable pubkey
        //      type (DISCOURAGE may flip that to a hard error).
        const success = verifySchnorrSig(sig, pubkey, ctx, codeSepPos, flags);
        const sigResult = success ? 1 : 0;

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
            const fad = findAndDelete(subscript, sig);
            // SCRIPT_VERIFY_CONST_SCRIPTCODE: reject if a signature push was
            // actually deleted (Core interpreter.cpp:1146-1148).
            if (fad.found > 0 && flags.verifyConstScriptCode) {
              throw new ScriptError("SIG_FINDANDDELETE");
            }
            subscript = fad.result;
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
 * Check if script is P2PK (Pay-to-Public-Key): <pubkey> OP_CHECKSIG
 *
 * Valid pubkey sizes: 33 bytes (compressed) or 65 bytes (uncompressed).
 * Script layout: <1-byte push opcode = pubkey_len> <pubkey> OP_CHECKSIG
 * Mirrors Bitcoin Core Solver() TxoutType::PUBKEY path (src/script/solver.cpp).
 */
export function isP2PK(script: Buffer): boolean {
  // Compressed: 35 bytes (1 + 33 + 1), uncompressed: 67 bytes (1 + 65 + 1)
  if (script.length === 35 || script.length === 67) {
    const keyLen = script.length - 2;
    return script[0] === keyLen && script[script.length - 1] === Opcode.OP_CHECKSIG;
  }
  return false;
}

/**
 * Parse a bare multisig script and return { m, n } if valid, null otherwise.
 *
 * Bare multisig layout: OP_m <pub1> ... <pubN> OP_n OP_CHECKMULTISIG
 * where m ∈ [1,n] and n ∈ [1,20] (Core MAX_PUBKEYS_PER_MULTISIG).
 * Pubkeys must be 33-byte (compressed) or 65-byte (uncompressed).
 *
 * Mirrors Bitcoin Core Solver() TxoutType::MULTISIG path.
 * Policy IsStandard() imposes an additional cap: n ≤ 3.
 */
export function getBareMultisigParams(script: Buffer): { m: number; n: number } | null {
  if (script.length < 3) return null;
  // Last byte must be OP_CHECKMULTISIG (0xae)
  if (script[script.length - 1] !== Opcode.OP_CHECKMULTISIG) return null;

  // OP_n for n-of-N: second-to-last byte encodes n (OP_1=0x51..OP_16=0x60)
  const nOpcode = script[script.length - 2];
  if (nOpcode < 0x51 || nOpcode > 0x60) return null;
  const n = nOpcode - 0x50;

  // First byte encodes m (OP_1=0x51..OP_16=0x60)
  const mOpcode = script[0];
  if (mOpcode < 0x51 || mOpcode > 0x60) return null;
  const m = mOpcode - 0x50;
  if (m < 1 || m > n) return null;

  // Walk through n pubkeys between the m/n opcodes.
  //
  // Core's MatchMultisig (script/solver.cpp:85-105) reads each key with
  // `script.GetOp(it, opcode, data)` and accepts it iff `CPubKey::ValidSize(data)`
  // — i.e. the *decoded* push payload is 33 or 65 bytes (pubkey.h:77). GetOp
  // (script/script.cpp GetScriptOp) decodes direct 1-byte pushes AND the
  // PUSHDATA1/2/4 forms, so a pubkey pushed as `OP_PUSHDATA1 0x21 <33B>` is just
  // as standard as the direct `0x21 <33B>` form. Matching only the direct-push
  // opcodes over-rejected PUSHDATA-prefixed bare multisig that Core relays as
  // standard MULTISIG. The push opcode is NOT required to be minimal here — Core's
  // MatchMultisig does not call CheckMinimalPush on the keys.
  const end = script.length - 2; // exclusive: OP_n is the second-to-last byte
  let pos = 1;
  for (let i = 0; i < n; i++) {
    if (pos >= end) return null; // ran out of script
    // Decode one push (GetScriptOp parity) and capture its payload length.
    const opcode = script[pos];
    let payloadLen: number;
    let headerLen: number;
    if (opcode >= 0x01 && opcode <= 0x4b) {
      // Direct push of 1..75 bytes.
      payloadLen = opcode;
      headerLen = 1;
    } else if (opcode === 0x4c) {
      // OP_PUSHDATA1: 1-byte length follows.
      if (pos + 2 > end) return null;
      payloadLen = script[pos + 1];
      headerLen = 2;
    } else if (opcode === 0x4d) {
      // OP_PUSHDATA2: 2-byte LE length follows.
      if (pos + 3 > end) return null;
      payloadLen = script.readUInt16LE(pos + 1);
      headerLen = 3;
    } else if (opcode === 0x4e) {
      // OP_PUSHDATA4: 4-byte LE length follows.
      if (pos + 5 > end) return null;
      payloadLen = script.readUInt32LE(pos + 1);
      headerLen = 5;
    } else {
      // Not a data push → not a pubkey → not a (bare) multisig.
      return null;
    }
    // CPubKey::ValidSize: only 33-byte (compressed) or 65-byte (uncompressed)
    // payloads are valid public keys.
    if (payloadLen !== 33 && payloadLen !== 65) return null;
    pos += headerLen + payloadLen;
  }

  // After all pubkeys, we should be at the OP_n byte (second-to-last)
  if (pos !== script.length - 2) return null;

  return { m, n };
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
  | "p2pk"
  | "multisig"
  | "nonstandard";

/**
 * Check whether all bytes in `script` starting at `offset` are push-only
 * opcodes (OP_0, OP_PUSHBYTES_1..75, OP_PUSHDATA1/2/4, OP_1NEGATE, OP_1..OP_16).
 *
 * Mirrors Bitcoin Core's CScript::IsPushOnly(const_iterator pc) in
 * script/script.h. Used by getScriptType to classify NULL_DATA scripts: Core's
 * Solver() only returns NULL_DATA when OP_RETURN is followed by push-only data.
 * A script like `6a 09 deadbeef` (OP_RETURN + push-9 with only 4 bytes of data)
 * fails this check because the push is truncated, so it is classified nonstandard.
 */
function isPushOnlyFrom(script: Buffer, offset: number): boolean {
  let i = offset;
  while (i < script.length) {
    const op = script[i];
    if (op === 0x00) { i++; continue; } // OP_0
    if (op >= 0x01 && op <= 0x4b) {
      // OP_PUSHBYTES_N: expects N more bytes
      if (i + 1 + op > script.length) return false;
      i += 1 + op;
    } else if (op === 0x4c) {
      // OP_PUSHDATA1
      if (i + 1 >= script.length) return false;
      const len = script[i + 1];
      if (i + 2 + len > script.length) return false;
      i += 2 + len;
    } else if (op === 0x4d) {
      // OP_PUSHDATA2
      if (i + 2 >= script.length) return false;
      const len = script.readUInt16LE(i + 1);
      if (i + 3 + len > script.length) return false;
      i += 3 + len;
    } else if (op === 0x4e) {
      // OP_PUSHDATA4
      if (i + 4 >= script.length) return false;
      const len = script.readUInt32LE(i + 1);
      if (i + 5 + len > script.length) return false;
      i += 5 + len;
    } else if (op === 0x4f || (op >= 0x51 && op <= 0x60)) {
      // OP_1NEGATE (0x4f) and OP_1..OP_16 (0x51..0x60)
      i++;
    } else {
      // Any other opcode (including non-push ops and > OP_16) is not push-only
      return false;
    }
  }
  return true;
}

/**
 * Detect script type.
 * Returns both AddressType-compatible values and extended TxoutType values.
 *
 * NULL_DATA classification mirrors Bitcoin Core's Solver() (src/script/solver.cpp):
 * the script must start with OP_RETURN and all remaining bytes must be push-only.
 * A script like `6a 09 deadbeef` (OP_RETURN + push-9 opcode with only 4 payload
 * bytes) has a truncated push and is classified "nonstandard", not "nulldata".
 */
export function getScriptType(script: Buffer): TxoutType {
  if (isP2PKH(script)) return "p2pkh";
  if (isP2SH(script)) return "p2sh";
  if (isP2WPKH(script)) return "p2wpkh";
  if (isP2WSH(script)) return "p2wsh";
  // Check P2A before P2TR since P2A is a specific witness v1 program
  if (isP2A(script)) return "anchor";
  if (isP2TR(script)) return "p2tr";
  // P2PK: <pubkey> OP_CHECKSIG (mirrors Core Solver TxoutType::PUBKEY)
  if (isP2PK(script)) return "p2pk";
  // Bare multisig: m <keys> n OP_CHECKMULTISIG (mirrors Core TxoutType::MULTISIG)
  if (getBareMultisigParams(script) !== null) return "multisig";
  // Check for OP_RETURN (nulldata): post-OP_RETURN data must be push-only.
  // Core's Solver() requires IsPushOnly after OP_RETURN; a truncated push
  // (e.g. 6a09deadbeef) must be classified "nonstandard".
  if (script.length >= 1 && script[0] === Opcode.OP_RETURN && isPushOnlyFrom(script, 1)) {
    return "nulldata";
  }
  // Witness program of an unrecognised shape. The canonical witness types
  // (P2WPKH/P2WSH for v0, P2TR for v1+32, P2A for the v1 anchor) are handled
  // above; any *remaining* witness program falls here. Mirrors Bitcoin Core's
  // Solver() (src/script/solver.cpp:154-178): a witness program with
  // `version != 0` is WITNESS_UNKNOWN (this includes v1 programs whose size is
  // not 32 and not the anchor — Core does NOT exclude OP_1 here, so e.g. a v1
  // 16-byte program is WITNESS_UNKNOWN, not nonstandard). A v0 witness program
  // with a non-{20,32} program size is NONSTANDARD (Core's trailing
  // `return TxoutType::NONSTANDARD` at solver.cpp:177), NOT witness_unknown.
  if (isWitnessProgram(script)) {
    // First byte is OP_0 (v0) or OP_1..OP_16 (0x51..0x60 → v1..v16).
    const version = script[0] === 0x00 ? 0 : script[0] - 0x50;
    if (version !== 0) return "witness_unknown";
    return "nonstandard";
  }
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

    // CLEANSTACK: after P2SH evaluation, stack must have exactly one element.
    //
    // Same Core resize-to-1 bypass as the native path (interpreter.cpp
    // ~2087-2107): when the redeemScript is itself a witness program, a
    // SUCCESSFUL VerifyWitnessProgram is followed by `stack.resize(1)` BEFORE
    // the SCRIPT_VERIFY_CLEANSTACK `stack.size() != 1` check. The P2SH-wrapped
    // witness program (OP_0/OP_1..OP_16 + push) leaves TWO elements on
    // p2shStack after EvalScript, so checking the pre-resize p2shStack here
    // would FALSE-REJECT every P2SH-wrapped witness spend (SCRIPT_ERR_CLEANSTACK).
    // The witness program is verified just below and enforces its own internal
    // cleanstack rule, so skip the main-stack check for a witness redeemScript.
    if (
      flags.verifyCleanStack &&
      p2shStack.length !== 1 &&
      !(flags.verifyWitness && isWitnessProgram(redeemScript))
    ) {
      throw new ScriptError("CLEANSTACK");
    }

    // Check for P2SH-wrapped witness
    if (flags.verifyWitness) {
      if (isWitnessProgram(redeemScript)) {
        // Core interpreter.cpp:2082-2086: for a P2SH-wrapped witness program the
        // scriptSig must be EXACTLY the minimal canonical push of the redeemScript
        // bytes — nothing more, nothing less.  An OP_PUSHDATA1-encoded push of the
        // same bytes is push-only, evaluates identically, but is NOT the canonical
        // encoding, so Core rejects it as SCRIPT_ERR_WITNESS_MALLEATED_P2SH.
        // MINIMALDATA is a policy/standard flag (not in GetBlockScriptFlags), so
        // under block/ConnectBlock validation this byte-exact comparison is the
        // ONLY guard against scriptSig malleability for this spend type.
        if (!scriptSig.equals(canonicalPushScript(redeemScript))) {
          throw new ScriptError("WITNESS_MALLEATED_P2SH");
        }
        if (isP2WPKH(redeemScript)) {
          return verifyWitnessV0(redeemScript, witness, flags, witnessSigHasher ?? sigHasher, txContext);
        }
        if (isP2WSH(redeemScript)) {
          return verifyWitnessV0(redeemScript, witness, flags, witnessSigHasher ?? sigHasher, txContext);
        }
        // Remaining witness versions (v1+)
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

  // CLEANSTACK: after non-P2SH evaluation, stack must have exactly one element.
  //
  // Mirror Core VerifyScript (interpreter.cpp ~2042-2107): after a SUCCESSFUL
  // bare witness-program evaluation Core does `stack.resize(1)` ("Bypass the
  // cleanstack check at the end. The actual stack is obviously not clean for
  // witness programs.") BEFORE enforcing SCRIPT_VERIFY_CLEANSTACK as
  // `stack.size() != 1`. A native-segwit scriptPubKey (OP_0/OP_1..OP_16 +
  // push) leaves TWO elements on the main stack after EvalScript
  // (`[<empty>, <program>]`), so running the cleanstack predicate against
  // that pre-resize main stack here would FALSE-REJECT every native witness
  // spend (SCRIPT_ERR_CLEANSTACK). The witness program is verified below in
  // Step 4 (verifyWitnessV0 / verifyTaproot), which implicitly enforces the
  // witness-internal cleanstack rule (interpreter.cpp:1866-1867). So skip the
  // main-stack cleanstack check when the scriptPubKey is a witness program
  // under WITNESS — equivalent to Core's resize-to-1 bypass.
  if (
    flags.verifyCleanStack &&
    stack.length !== 1 &&
    !(flags.verifyWitness && isWitnessProgram(scriptPubKey))
  ) {
    throw new ScriptError("CLEANSTACK");
  }

  // Step 4: Native SegWit evaluation
  if (flags.verifyWitness) {
    if (isP2WPKH(scriptPubKey) || isP2WSH(scriptPubKey)) {
      // For native segwit, scriptSig must be empty
      if (scriptSig.length !== 0) {
        return false;
      }
      return verifyWitnessV0(scriptPubKey, witness, flags, witnessSigHasher ?? sigHasher, txContext);
    }

    if (flags.verifyTaproot && isP2TR(scriptPubKey)) {
      if (scriptSig.length !== 0) {
        return false;
      }
      // Full taproot verification
      return verifyTaproot(scriptPubKey, witness, flags, taprootCtx, txContext);
    }

    // P2A (Pay-to-Anchor): anyone-can-spend, witness ignored at consensus.
    // Core VerifyWitnessProgram (interpreter.cpp:1990-1991):
    //   `} else if (!is_p2sh && CScript::IsPayToAnchor(witversion, program)) { return true; }`
    // Core returns true UNCONDITIONALLY — the witness stack is never inspected.
    // Requiring an empty witness was wrong: it is a POLICY/standardness rule
    // only, not a consensus rule. A P2A input with a non-empty witness is
    // valid at the block level (direction: false-reject fixed).
    if (flags.verifyTaproot && isP2A(scriptPubKey)) {
      if (scriptSig.length !== 0) {
        return false;
      }
      // Witness is not checked — empty or non-empty both succeed (anyone-can-spend).
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
  taprootCtx?: TaprootContext,
  txContext?: { txVersion: number; txLockTime: number; txSequence: number }
): boolean {
  // P2TR: OP_1 <32 bytes>
  // Output key Q is the 32-byte x-only pubkey in scriptPubKey
  const outputKeyBytes = scriptPubKey.subarray(2, 34);

  if (witness.length === 0) {
    return false;
  }

  // Check for annex: if >= 2 witness elements and last element starts with 0x50.
  // BIP-341: annex is consumed (not executed) and contributes only its hash to
  // the sighash via the spend_type byte. Annex hash is computed as
  // SHA256(compact_size(len(annex)) || annex) — i.e. SHA256 of the wire-format
  // varbytes serialization, matching Core's
  // `(HashWriter{} << annex).GetSHA256()` at interpreter.cpp:1954 (the `<< annex`
  // operator on a vector serializes a CompactSize length prefix then the bytes).
  //
  // Pre-W94 this was `sha256Hash(annex)` — missing the compact-size prefix. The
  // hash is only consumed by the BIP-341 sigmsg; in production the
  // canonical annex hash is computed in `validation/tx.ts` and baked into the
  // taprootCtx sighash closures before `verifyTaproot` runs, so the bug was
  // latent (the locally-recomputed annexHash here was never threaded into
  // sighash computation). The fix below keeps `verifyTaproot` self-consistent
  // for test callers that DON'T pre-bake the annexHash into their sigHasher.
  let annexHash: Buffer | undefined;
  let witnessStack = witness;

  if (witness.length >= 2 && witness[witness.length - 1][0] === TAPROOT_ANNEX_TAG) {
    const annex = witness[witness.length - 1];
    // SHA256(compact_size(annex.length) || annex.bytes)
    annexHash = sha256Hash(Buffer.concat([encodeCompactSize(annex.length), annex]));
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
    return verifyTaprootScriptPath(outputKeyBytes, witnessStack, witness, annexHash, flags, taprootCtx, txContext);
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
  taprootCtx?: TaprootContext,
  txContext?: { txVersion: number; txLockTime: number; txSequence: number }
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
    return executeTapscript(tapscript, stack, leafHash, annexHash, flags, taprootCtx, fullWitness, txContext);
  }

  // Unknown leaf version: consensus accepts for forward extensibility
  // (Core: interpreter.cpp:1985-1988). Policy flag
  // `DISCOURAGE_UPGRADABLE_TAPROOT_VERSION` may turn this into a hard error,
  // used in IsStandard / mempool acceptance to prevent accidental dust on
  // unrecognized leaf versions.
  if (flags.verifyDiscourageUpgradableTaprootVersion) {
    throw new ScriptError("DISCOURAGE_UPGRADABLE_TAPROOT_VERSION");
  }
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
// secp256k1 curve order (n).  Used for BIP-341 step-2 tweak validation:
// the tagged-hash tweak must be a valid scalar (t < n) or the result of
// the tweak is undefined per spec.
const SECP256K1_ORDER = BigInt(
  "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"
);

function tweakPublicKeyWithParity(pubkey: Buffer, tweak: Buffer): { key: Buffer; parity: number } {
  if (pubkey.length !== 32) {
    throw new Error("Public key must be 32 bytes (x-only)");
  }
  if (tweak.length !== 32) {
    throw new Error("Tweak must be 32 bytes");
  }

  // Convert tweak to bigint.
  //
  // BIP-341 ("Tweaking a public key"):
  //   t = int_from_bytes(taggedHash("TapTweak", pubkey + h))
  //   if t >= SECP256K1_ORDER: raise ValueError
  //
  // Pre-W95: this check was missing — Point.BASE.multiply(t) would silently
  // reduce mod n and emit a tweaked key that disagreed with libsecp256k1's
  // `secp256k1_xonly_pubkey_tweak_add_check` (Core uses the latter via
  // `XOnlyPubKey::CheckTapTweak` in src/pubkey.cpp). The catch in the
  // caller maps this throw to WITNESS_PROGRAM_MISMATCH.
  const t = BigInt("0x" + tweak.toString("hex"));
  if (t >= SECP256K1_ORDER) {
    throw new Error("tweakPublicKeyWithParity: tweak overflows curve order");
  }

  // Lift x to a point (assume even y); throws if x >= p or not on curve.
  const x = BigInt("0x" + pubkey.toString("hex"));
  const P = schnorr.utils.lift_x(x);

  // Compute tweak*G
  const Point = schnorr.Point;
  const tG = Point.BASE.multiply(t);

  // Add P + tG
  const tweaked = P.add(tG);

  // BIP-341 step 4: "if Q is point at infinity: raise ValueError".
  // noble's toAffine() returns {x:0n, y:0n} for the infinity point and
  // does NOT throw; without this guard we'd silently emit an all-zero
  // x-only key with parity=0 and the parity branch below would assert
  // tweakedKey != outputKey via the byte compare (in practice always),
  // but spec says reject up-front.
  if (tweaked.is0()) {
    throw new Error("tweakPublicKeyWithParity: tweaked point is at infinity");
  }

  // Check if y is even or odd. `.y` returns the affine y-coordinate.
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
  txContext?: { txVersion: number; txLockTime: number; txSequence: number }
): boolean {
  if (!taprootCtx) {
    throw new ScriptError("TAPROOT_CONTEXT_MISSING");
  }

  // BIP-342 (Core interpreter.cpp:1836-1853): OP_SUCCESSx scanning happens
  // BEFORE any stack/element size enforcement, because "OP_SUCCESSx processing
  // overrides everything, including stack element size limits". If found,
  // the script unconditionally succeeds (subject to DISCOURAGE_OP_SUCCESS).
  if (containsOpSuccess(script)) {
    if (flags.verifyDiscourageOpSuccess) {
      throw new ScriptError("DISCOURAGE_OP_SUCCESS");
    }
    return true;
  }

  // BIP-342 (Core interpreter.cpp:1854-1861): post-OP_SUCCESS-scan, enforce
  // tapscript initial-stack invariants.
  //   1) MAX_STACK_SIZE (1000) on initial stack — fires only for TAPSCRIPT.
  //   2) MAX_SCRIPT_ELEMENT_SIZE (520) on every initial stack item — fires
  //      for both WITNESS_V0 and TAPSCRIPT.
  // Pre-W94 hotbuns enforced neither on the initial witness stack — both
  // checks only ran during script execution, which never sees the unconsumed
  // top-of-stack items if execution succeeded with fewer pops. A 1001-item
  // witness or a 521-byte witness element could ride through validation as
  // long as the script didn't touch those items. Core rejects, hotbuns
  // accepted: consensus split.
  if (stack.length > MAX_STACK_SIZE) {
    throw new ScriptError("STACK_SIZE");
  }
  for (const elem of stack) {
    if (elem.length > MAX_ELEMENT_SIZE) {
      throw new ScriptError("PUSH_SIZE");
    }
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
  // W81 fix: thread txContext so CLTV/CSV in tapscript can access nLockTime
  // and nSequence.  Pre-fix: ctx had no txVersion/txLockTime/txSequence,
  // so every OP_CLTV / OP_CSV in a tapscript silently passed (fail-open).
  const ctx: ExecutionContext = {
    stack: [...stack],
    altStack: [],
    flags: { ...flags, verifyMinimalIf: true }, // MINIMALIF always enforced
    sigHasher: () => Buffer.alloc(32), // Not used for tapscript
    sigVersion: SigVersion.TAPSCRIPT,
    taprootSigHasher,
    sigopsBudget,
    txVersion: txContext?.txVersion,
    txLockTime: txContext?.txLockTime,
    txSequence: txContext?.txSequence,
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
  sigHasher: (subscript: Buffer, hashType: number) => Buffer,
  txContext?: { txVersion: number; txLockTime: number; txSequence: number }
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

    // Per Core interpreter.cpp:621-622, MINIMALIF under witness v0 is a policy
    // rule enabled ONLY through SCRIPT_VERIFY_MINIMALIF — it is NOT enforced
    // unconditionally. Pass the caller's flags straight through (the IF/NOTIF
    // handler already gates on flags.verifyMinimalIf for WITNESS_V0).
    const witnessFlags: ScriptFlags = flags;

    // W81 fix: thread txContext so CLTV/CSV in P2WPKH redeem scripts can
    // access nLockTime and nSequence.  Pre-fix: ctx had no txVersion/txLockTime/
    // txSequence fields, so every CLTV in a witness-v0 script silently passed.
    const ctx: ExecutionContext = {
      stack: witnessStack,
      altStack: [],
      flags: witnessFlags,
      sigHasher,
      sigVersion: SigVersion.WITNESS_V0,
      txVersion: txContext?.txVersion,
      txLockTime: txContext?.txLockTime,
      txSequence: txContext?.txSequence,
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

    // BIP-141 / Core interpreter.cpp:1858-1861: enforce 520-byte element-size
    // limit on the initial witness stack BEFORE handing it to the interpreter.
    // The in-interpreter PUSH_SIZE check at line ~988 only fires on
    // explicit OP_PUSHDATA operations, not on items already on the stack.
    // Without this gate a witness with >520-byte items could ride through
    // validation if the redeem script doesn't touch them.
    for (const elem of witnessStack) {
      if (elem.length > MAX_ELEMENT_SIZE) {
        throw new ScriptError("PUSH_SIZE");
      }
    }

    // Per Core interpreter.cpp:621-622, MINIMALIF under witness v0 is a policy
    // rule enabled ONLY through SCRIPT_VERIFY_MINIMALIF — it is NOT enforced
    // unconditionally. Pass the caller's flags straight through (the IF/NOTIF
    // handler already gates on flags.verifyMinimalIf for WITNESS_V0).
    const witnessFlags: ScriptFlags = flags;

    // W81 fix: thread txContext so CLTV/CSV in P2WSH redeem scripts can
    // access nLockTime and nSequence.  Pre-fix: ctx had no txVersion/txLockTime/
    // txSequence fields, so every CLTV in a P2WSH script silently passed.
    const ctx: ExecutionContext = {
      stack: witnessStack,
      altStack: [],
      flags: witnessFlags,
      sigHasher,
      sigVersion: SigVersion.WITNESS_V0,
      txVersion: txContext?.txVersion,
      txLockTime: txContext?.txLockTime,
      txSequence: txContext?.txSequence,
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
 * Create consensus-only script verification flags for a given block height.
 *
 * Returns ONLY Bitcoin Core MANDATORY_SCRIPT_VERIFY_FLAGS:
 *   P2SH | DERSIG | NULLDUMMY | CLTV | CSV | WITNESS | TAPROOT
 * (each gated on its BIP deployment height).
 *
 * Policy-only flags (NULLFAIL, WITNESS_PUBKEYTYPE, LOW_S, STRICTENC, etc.)
 * are NOT set here.  Use getStandardFlags() for mempool/relay purposes.
 *
 * Ref: Bitcoin Core policy/policy.h:105-111 + validation.cpp:2250-2289.
 */
export function getConsensusFlags(height: number): ScriptFlags {
  return {
    verifyP2SH: height >= 173805,             // BIP 16
    verifyDERSignatures: height >= 363725,     // BIP 66
    verifyCheckLockTimeVerify: height >= 388381, // BIP 65
    verifyCheckSequenceVerify: height >= 419328, // BIP 112
    verifyWitness: height >= 481824,           // BIP 141
    verifyNullDummy: height >= 481824,         // BIP 147 (consensus)
    verifyTaproot: height >= 709632,           // BIP 341
    // Policy flags are always false in the consensus computer
    verifyNullFail: false,                     // policy-only (BIP 146)
    verifyWitnessPubkeyType: false,            // policy-only (BIP 141 standardness)
    verifyStrictEncoding: false,               // policy-only
    verifyLowS: false,                         // policy-only
  };
}

/**
 * Convert a ScriptFlags bitmask (from validation/tx.ts) to an interpreter
 * ScriptFlags object.
 *
 * Called by verifyInputSignature to translate the per-block bitmask that
 * coreConnectBlockChecks computes from height/params into the interpreter's
 * structured form.  This replaces the old getConsensusFlags(709632) hardcode
 * (BUG-11 + BUG-30 fix).
 *
 * Bitmask bit definitions (must mirror validation/tx.ts ScriptFlags enum;
 * kept as literals here to avoid a circular import):
 *   VERIFY_P2SH                = 1 << 0
 *   VERIFY_WITNESS             = 1 << 1
 *   VERIFY_DERSIG              = 1 << 3
 *   VERIFY_NULLDUMMY           = 1 << 4
 *   VERIFY_CHECKLOCKTIMEVERIFY = 1 << 5
 *   VERIFY_CHECKSEQUENCEVERIFY = 1 << 6
 *   VERIFY_TAPROOT             = 1 << 9
 *
 * DERSIG/CLTV/CSV/NULLDUMMY are honoured from their OWN bits (set by
 * coreConnectBlockChecks from each rule's activation height, matching Core
 * GetBlockScriptFlags).  They are additionally OR'd with `verifyWitness`
 * because on every Bitcoin network segwit activates strictly after BIP66/65/112
 * and simultaneously with BIP147 — so SegWit being active implies all four are
 * active.  Keeping the OR preserves the historical behaviour for callers that
 * pass only the P2SH|WITNESS|TAPROOT bitmask (e.g. wallet/standalone defaults),
 * while the explicit bits close the pre-segwit under-flag window
 * (heights [bip66Height, segwitHeight) where DERSIG/CLTV/CSV are active but
 * SegWit is not).
 */
export function scriptFlagsFromBitmask(bitmask: number): ScriptFlags {
  const verifyP2SH    = (bitmask & (1 << 0)) !== 0;
  const verifyWitness = (bitmask & (1 << 1)) !== 0;
  const verifyTaproot = (bitmask & (1 << 9)) !== 0;
  const verifyDERSig    = (bitmask & (1 << 3)) !== 0;
  const verifyNullDummy = (bitmask & (1 << 4)) !== 0;
  const verifyCLTV      = (bitmask & (1 << 5)) !== 0;
  const verifyCSV       = (bitmask & (1 << 6)) !== 0;
  return {
    verifyP2SH,
    verifyWitness,
    verifyTaproot,
    // Honour each rule's own bit; OR with verifyWitness since SegWit-active
    // implies BIP66/65/112/147 active (segwit activates after all of them).
    verifyDERSignatures:       verifyDERSig    || verifyWitness, // BIP-66
    verifyCheckLockTimeVerify: verifyCLTV      || verifyWitness, // BIP-65
    verifyCheckSequenceVerify: verifyCSV       || verifyWitness, // BIP-112
    verifyNullDummy:           verifyNullDummy || verifyWitness, // BIP-147
    // Policy flags are never set during block validation.
    verifyNullFail:            false,
    verifyWitnessPubkeyType:   false,
    verifyStrictEncoding:      false,
    verifyLowS:                false,
  };
}

/**
 * Create standard (mempool/relay) script verification flags for a given height.
 *
 * Composes the consensus flags from getConsensusFlags() and adds the policy-only
 * STANDARD_SCRIPT_VERIFY_FLAGS additions that Bitcoin Core uses in mempool
 * acceptance (policy/policy.h:119-132).
 *
 * Do NOT use this for block validation — use getConsensusFlags() there.
 */
export function getStandardFlags(height: number): ScriptFlags {
  const flags = getConsensusFlags(height);
  return {
    ...flags,
    verifyNullFail: height >= 481824,          // policy: BIP 146
    verifyWitnessPubkeyType: height >= 481824, // policy: BIP 141 standardness
    verifyStrictEncoding: height >= 363725,    // policy: BIP 66 standardness
    verifyLowS: height >= 363725,              // policy: BIP 62 rule 5
  };
}
