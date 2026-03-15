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

import { sha256Hash, hash256, hash160, ecdsaVerify } from "../crypto/primitives.js";
import { ripemd160 } from "@noble/hashes/legacy.js";
import { AddressType } from "../address/encoding.js";

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
    absValue >>= 8;
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
export function scriptNumDecode(buf: Buffer, maxLen: number = 4): number {
  if (buf.length === 0) {
    return 0;
  }

  if (buf.length > maxLen) {
    throw new Error(`Script number too long: ${buf.length} > ${maxLen}`);
  }

  // Check for non-minimal encoding
  if (buf.length > 1) {
    // If the last byte is 0x00 or 0x80, and the second-to-last byte
    // doesn't have its high bit set, then we have a non-minimal encoding
    if ((buf[buf.length - 1] & 0x7f) === 0) {
      if ((buf[buf.length - 2] & 0x80) === 0) {
        throw new Error("Non-minimal script number encoding");
      }
    }
  }

  let result = 0;
  for (let i = 0; i < buf.length; i++) {
    result |= buf[i] << (8 * i);
  }

  // Check sign bit
  if (buf[buf.length - 1] & 0x80) {
    // Negative number - clear the sign bit and negate
    return -(result & ~(0x80 << (8 * (buf.length - 1))));
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

    // Count non-push opcodes
    if (opcode > Opcode.OP_16) {
      opCount++;
      if (opCount > MAX_OPS_PER_SCRIPT) {
        return false;
      }
    }

    // Push data operations
    if (chunk.data !== undefined) {
      if (executing) {
        if (chunk.data.length > MAX_ELEMENT_SIZE) {
          return false;
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

    // Stack size check
    if (stack.length + altStack.length > MAX_STACK_SIZE) {
      return false;
    }

    switch (opcode) {
      // Control
      case Opcode.OP_NOP:
      case Opcode.OP_NOP1:
      case Opcode.OP_NOP4:
      case Opcode.OP_NOP5:
      case Opcode.OP_NOP6:
      case Opcode.OP_NOP7:
      case Opcode.OP_NOP8:
      case Opcode.OP_NOP9:
      case Opcode.OP_NOP10:
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
          break; // Treated as NOP
        }
        if (stack.length < 1) return false;
        // Value is checked but not popped
        const locktime = scriptNumDecode(stack[stack.length - 1], 5);
        if (locktime < 0) return false;
        // Additional locktime validation would happen here with tx context
        break;
      }

      case Opcode.OP_CHECKSEQUENCEVERIFY: {
        if (!flags.verifyCheckSequenceVerify) {
          break; // Treated as NOP
        }
        if (stack.length < 1) return false;
        const sequence = scriptNumDecode(stack[stack.length - 1], 5);
        if (sequence < 0) return false;
        // Additional sequence validation would happen here with tx context
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
        const n = scriptNumDecode(stack.pop()!);
        if (n < 0 || n >= stack.length) return false;
        stack.push(Buffer.from(stack[stack.length - 1 - n]));
        break;
      }

      case Opcode.OP_ROLL: {
        if (stack.length < 1) return false;
        const n = scriptNumDecode(stack.pop()!);
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
        const n = scriptNumDecode(stack.pop()!);
        stack.push(scriptNumEncode(n + 1));
        break;
      }

      case Opcode.OP_1SUB: {
        if (stack.length < 1) return false;
        const n = scriptNumDecode(stack.pop()!);
        stack.push(scriptNumEncode(n - 1));
        break;
      }

      case Opcode.OP_NEGATE: {
        if (stack.length < 1) return false;
        const n = scriptNumDecode(stack.pop()!);
        stack.push(scriptNumEncode(-n));
        break;
      }

      case Opcode.OP_ABS: {
        if (stack.length < 1) return false;
        const n = scriptNumDecode(stack.pop()!);
        stack.push(scriptNumEncode(Math.abs(n)));
        break;
      }

      case Opcode.OP_NOT: {
        if (stack.length < 1) return false;
        const n = scriptNumDecode(stack.pop()!);
        stack.push(scriptNumEncode(n === 0 ? 1 : 0));
        break;
      }

      case Opcode.OP_0NOTEQUAL: {
        if (stack.length < 1) return false;
        const n = scriptNumDecode(stack.pop()!);
        stack.push(scriptNumEncode(n !== 0 ? 1 : 0));
        break;
      }

      case Opcode.OP_ADD: {
        if (stack.length < 2) return false;
        const b = scriptNumDecode(stack.pop()!);
        const a = scriptNumDecode(stack.pop()!);
        stack.push(scriptNumEncode(a + b));
        break;
      }

      case Opcode.OP_SUB: {
        if (stack.length < 2) return false;
        const b = scriptNumDecode(stack.pop()!);
        const a = scriptNumDecode(stack.pop()!);
        stack.push(scriptNumEncode(a - b));
        break;
      }

      case Opcode.OP_BOOLAND: {
        if (stack.length < 2) return false;
        const b = scriptNumDecode(stack.pop()!);
        const a = scriptNumDecode(stack.pop()!);
        stack.push(scriptNumEncode(a !== 0 && b !== 0 ? 1 : 0));
        break;
      }

      case Opcode.OP_BOOLOR: {
        if (stack.length < 2) return false;
        const b = scriptNumDecode(stack.pop()!);
        const a = scriptNumDecode(stack.pop()!);
        stack.push(scriptNumEncode(a !== 0 || b !== 0 ? 1 : 0));
        break;
      }

      case Opcode.OP_NUMEQUAL: {
        if (stack.length < 2) return false;
        const b = scriptNumDecode(stack.pop()!);
        const a = scriptNumDecode(stack.pop()!);
        stack.push(scriptNumEncode(a === b ? 1 : 0));
        break;
      }

      case Opcode.OP_NUMEQUALVERIFY: {
        if (stack.length < 2) return false;
        const b = scriptNumDecode(stack.pop()!);
        const a = scriptNumDecode(stack.pop()!);
        if (a !== b) return false;
        break;
      }

      case Opcode.OP_NUMNOTEQUAL: {
        if (stack.length < 2) return false;
        const b = scriptNumDecode(stack.pop()!);
        const a = scriptNumDecode(stack.pop()!);
        stack.push(scriptNumEncode(a !== b ? 1 : 0));
        break;
      }

      case Opcode.OP_LESSTHAN: {
        if (stack.length < 2) return false;
        const b = scriptNumDecode(stack.pop()!);
        const a = scriptNumDecode(stack.pop()!);
        stack.push(scriptNumEncode(a < b ? 1 : 0));
        break;
      }

      case Opcode.OP_GREATERTHAN: {
        if (stack.length < 2) return false;
        const b = scriptNumDecode(stack.pop()!);
        const a = scriptNumDecode(stack.pop()!);
        stack.push(scriptNumEncode(a > b ? 1 : 0));
        break;
      }

      case Opcode.OP_LESSTHANOREQUAL: {
        if (stack.length < 2) return false;
        const b = scriptNumDecode(stack.pop()!);
        const a = scriptNumDecode(stack.pop()!);
        stack.push(scriptNumEncode(a <= b ? 1 : 0));
        break;
      }

      case Opcode.OP_GREATERTHANOREQUAL: {
        if (stack.length < 2) return false;
        const b = scriptNumDecode(stack.pop()!);
        const a = scriptNumDecode(stack.pop()!);
        stack.push(scriptNumEncode(a >= b ? 1 : 0));
        break;
      }

      case Opcode.OP_MIN: {
        if (stack.length < 2) return false;
        const b = scriptNumDecode(stack.pop()!);
        const a = scriptNumDecode(stack.pop()!);
        stack.push(scriptNumEncode(Math.min(a, b)));
        break;
      }

      case Opcode.OP_MAX: {
        if (stack.length < 2) return false;
        const b = scriptNumDecode(stack.pop()!);
        const a = scriptNumDecode(stack.pop()!);
        stack.push(scriptNumEncode(Math.max(a, b)));
        break;
      }

      case Opcode.OP_WITHIN: {
        if (stack.length < 3) return false;
        const max = scriptNumDecode(stack.pop()!);
        const min = scriptNumDecode(stack.pop()!);
        const x = scriptNumDecode(stack.pop()!);
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

        // WITNESS_PUBKEYTYPE: In witness v0, pubkeys must be compressed
        if (
          flags.verifyWitnessPubkeyType &&
          sigVersion === SigVersion.WITNESS_V0 &&
          !isCompressedPubKey(pubkey)
        ) {
          return false;
        }

        let success = false;
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
          success = ecdsaVerify(sigBytes, sighash, pubkey);
        }

        // NULLFAIL: If signature check fails and signature is non-empty, fail
        if (!success && flags.verifyNullFail && sig.length > 0) {
          return false;
        }

        if (opcode === Opcode.OP_CHECKSIGVERIFY) {
          if (!success) return false;
        } else {
          stack.push(success ? scriptNumEncode(1) : Buffer.alloc(0));
        }
        break;
      }

      case Opcode.OP_CHECKMULTISIG:
      case Opcode.OP_CHECKMULTISIGVERIFY: {
        // Get n (number of pubkeys)
        if (stack.length < 1) return false;
        const n = scriptNumDecode(stack.pop()!);
        if (n < 0 || n > MAX_PUBKEYS_PER_MULTISIG) return false;

        opCount += n;
        if (opCount > MAX_OPS_PER_SCRIPT) return false;

        // Get pubkeys
        if (stack.length < n) return false;
        const pubkeys: Buffer[] = [];
        for (let i = 0; i < n; i++) {
          const pubkey = stack.pop()!;
          // WITNESS_PUBKEYTYPE: In witness v0, pubkeys must be compressed
          if (
            flags.verifyWitnessPubkeyType &&
            sigVersion === SigVersion.WITNESS_V0 &&
            !isCompressedPubKey(pubkey)
          ) {
            return false;
          }
          pubkeys.push(pubkey);
        }

        // Get m (number of required signatures)
        if (stack.length < 1) return false;
        const m = scriptNumDecode(stack.pop()!);
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

          let sigValid = false;
          if (sig.length > 0) {
            const hashType = sig[sig.length - 1];
            const sigBytes = sig.subarray(0, sig.length - 1);
            const sighash = sigHasher(subscript, hashType);
            sigValid = ecdsaVerify(sigBytes, sighash, pubkey);
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
 * Detect script type.
 */
export function getScriptType(script: Buffer): AddressType | "nonstandard" {
  if (isP2PKH(script)) return AddressType.P2PKH;
  if (isP2SH(script)) return AddressType.P2SH;
  if (isP2WPKH(script)) return AddressType.P2WPKH;
  if (isP2WSH(script)) return AddressType.P2WSH;
  if (isP2TR(script)) return AddressType.P2TR;
  return "nonstandard";
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
 * Verify a complete script (scriptSig + scriptPubKey + witness).
 * Handles P2PKH, P2SH, P2WPKH, P2WSH evaluation.
 */
export function verifyScript(
  scriptSig: Buffer,
  scriptPubKey: Buffer,
  witness: Buffer[],
  flags: ScriptFlags,
  sigHasher: (subscript: Buffer, hashType: number) => Buffer
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

  // Step 1: Execute scriptSig
  const stack: Buffer[] = [];
  const ctx: ExecutionContext = {
    stack,
    altStack: [],
    flags,
    sigHasher,
    sigVersion: SigVersion.BASE,
  };

  if (!executeScript(parsedSig, ctx)) {
    return false;
  }

  // Copy stack for potential P2SH evaluation
  const stackCopy = stack.map((b) => Buffer.from(b));

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
    };

    if (!executeScript(parsedRedeem, p2shCtx)) {
      return false;
    }

    if (p2shStack.length === 0 || !castToBool(p2shStack[p2shStack.length - 1])) {
      return false;
    }

    // Check for P2SH-wrapped witness
    if (flags.verifyWitness) {
      if (isP2WPKH(redeemScript)) {
        return verifyWitnessV0(redeemScript, witness, flags, sigHasher);
      }
      if (isP2WSH(redeemScript)) {
        return verifyWitnessV0(redeemScript, witness, flags, sigHasher);
      }
    }
  }

  // Step 4: Native SegWit evaluation
  if (flags.verifyWitness) {
    if (isP2WPKH(scriptPubKey) || isP2WSH(scriptPubKey)) {
      // For native segwit, scriptSig must be empty
      if (scriptSig.length !== 0) {
        return false;
      }
      return verifyWitnessV0(scriptPubKey, witness, flags, sigHasher);
    }

    if (flags.verifyTaproot && isP2TR(scriptPubKey)) {
      if (scriptSig.length !== 0) {
        return false;
      }
      // Basic taproot - just check witness exists
      // Full taproot implementation would handle key path and script path
      return witness.length >= 1;
    }
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

    // For witness v0, MINIMALIF is unconditionally enabled (part of SegWit rules)
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

    // For witness v0, MINIMALIF is unconditionally enabled (part of SegWit rules)
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
