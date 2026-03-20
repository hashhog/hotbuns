/**
 * Script test harness for hotbuns Bitcoin implementation.
 *
 * Loads Bitcoin Core's script_tests.json test vectors and verifies
 * the script interpreter against each expected result.
 *
 * Formats:
 *   [scriptSig_asm, scriptPubKey_asm, flags, expected_result]              (4 fields)
 *   [scriptSig_asm, scriptPubKey_asm, flags, expected_result, comment]     (5 fields)
 *   [[witness...], amount, scriptSig_asm, scriptPubKey_asm, flags, result] (6+ fields, skipped)
 *
 * Single-element arrays are comments and are skipped.
 */

import { readFileSync } from "fs";
import {
  Opcode,
  verifyScript,
  serializeScript,
  scriptNumEncode,
  type ScriptFlags,
  type ScriptChunk,
  type Script,
} from "../src/script/interpreter.js";
import {
  type Transaction,
  type TxIn,
  type TxOut,
  getTxId,
  sigHashLegacy,
  sigHashWitnessV0,
} from "../src/validation/tx.js";

const VECTOR_PATH =
  "/home/max/hashhog/bitcoin/src/test/data/script_tests.json";

// ---------------------------------------------------------------------------
// Opcode name lookup
// ---------------------------------------------------------------------------

const OPCODE_MAP: Record<string, number> = {
  // Push values
  "OP_0": Opcode.OP_0, "OP_FALSE": Opcode.OP_FALSE,
  "OP_PUSHDATA1": Opcode.OP_PUSHDATA1, "OP_PUSHDATA2": Opcode.OP_PUSHDATA2,
  "OP_PUSHDATA4": Opcode.OP_PUSHDATA4,
  "OP_1NEGATE": Opcode.OP_1NEGATE, "OP_RESERVED": Opcode.OP_RESERVED,
  "OP_1": Opcode.OP_1, "OP_TRUE": Opcode.OP_TRUE,
  "OP_2": Opcode.OP_2, "OP_3": Opcode.OP_3, "OP_4": Opcode.OP_4,
  "OP_5": Opcode.OP_5, "OP_6": Opcode.OP_6, "OP_7": Opcode.OP_7,
  "OP_8": Opcode.OP_8, "OP_9": Opcode.OP_9, "OP_10": Opcode.OP_10,
  "OP_11": Opcode.OP_11, "OP_12": Opcode.OP_12, "OP_13": Opcode.OP_13,
  "OP_14": Opcode.OP_14, "OP_15": Opcode.OP_15, "OP_16": Opcode.OP_16,
  // Control
  "OP_NOP": Opcode.OP_NOP, "OP_VER": Opcode.OP_VER,
  "OP_IF": Opcode.OP_IF, "OP_NOTIF": Opcode.OP_NOTIF,
  "OP_VERIF": Opcode.OP_VERIF, "OP_VERNOTIF": Opcode.OP_VERNOTIF,
  "OP_ELSE": Opcode.OP_ELSE, "OP_ENDIF": Opcode.OP_ENDIF,
  "OP_VERIFY": Opcode.OP_VERIFY, "OP_RETURN": Opcode.OP_RETURN,
  // Stack
  "OP_TOALTSTACK": Opcode.OP_TOALTSTACK, "OP_FROMALTSTACK": Opcode.OP_FROMALTSTACK,
  "OP_2DROP": Opcode.OP_2DROP, "OP_2DUP": Opcode.OP_2DUP,
  "OP_3DUP": Opcode.OP_3DUP, "OP_2OVER": Opcode.OP_2OVER,
  "OP_2ROT": Opcode.OP_2ROT, "OP_2SWAP": Opcode.OP_2SWAP,
  "OP_IFDUP": Opcode.OP_IFDUP, "OP_DEPTH": Opcode.OP_DEPTH,
  "OP_DROP": Opcode.OP_DROP, "OP_DUP": Opcode.OP_DUP,
  "OP_NIP": Opcode.OP_NIP, "OP_OVER": Opcode.OP_OVER,
  "OP_PICK": Opcode.OP_PICK, "OP_ROLL": Opcode.OP_ROLL,
  "OP_ROT": Opcode.OP_ROT, "OP_SWAP": Opcode.OP_SWAP,
  "OP_TUCK": Opcode.OP_TUCK,
  // Splice (disabled)
  "OP_CAT": Opcode.OP_CAT, "OP_SUBSTR": Opcode.OP_SUBSTR,
  "OP_LEFT": Opcode.OP_LEFT, "OP_RIGHT": Opcode.OP_RIGHT,
  "OP_SIZE": Opcode.OP_SIZE,
  // Bitwise (disabled)
  "OP_INVERT": Opcode.OP_INVERT, "OP_AND": Opcode.OP_AND,
  "OP_OR": Opcode.OP_OR, "OP_XOR": Opcode.OP_XOR,
  // Comparison
  "OP_EQUAL": Opcode.OP_EQUAL, "OP_EQUALVERIFY": Opcode.OP_EQUALVERIFY,
  "OP_RESERVED1": Opcode.OP_RESERVED1, "OP_RESERVED2": Opcode.OP_RESERVED2,
  // Arithmetic
  "OP_1ADD": Opcode.OP_1ADD, "OP_1SUB": Opcode.OP_1SUB,
  "OP_2MUL": Opcode.OP_2MUL, "OP_2DIV": Opcode.OP_2DIV,
  "OP_NEGATE": Opcode.OP_NEGATE, "OP_ABS": Opcode.OP_ABS,
  "OP_NOT": Opcode.OP_NOT, "OP_0NOTEQUAL": Opcode.OP_0NOTEQUAL,
  "OP_ADD": Opcode.OP_ADD, "OP_SUB": Opcode.OP_SUB,
  "OP_MUL": Opcode.OP_MUL, "OP_DIV": Opcode.OP_DIV,
  "OP_MOD": Opcode.OP_MOD, "OP_LSHIFT": Opcode.OP_LSHIFT,
  "OP_RSHIFT": Opcode.OP_RSHIFT,
  "OP_BOOLAND": Opcode.OP_BOOLAND, "OP_BOOLOR": Opcode.OP_BOOLOR,
  "OP_NUMEQUAL": Opcode.OP_NUMEQUAL, "OP_NUMEQUALVERIFY": Opcode.OP_NUMEQUALVERIFY,
  "OP_NUMNOTEQUAL": Opcode.OP_NUMNOTEQUAL,
  "OP_LESSTHAN": Opcode.OP_LESSTHAN, "OP_GREATERTHAN": Opcode.OP_GREATERTHAN,
  "OP_LESSTHANOREQUAL": Opcode.OP_LESSTHANOREQUAL,
  "OP_GREATERTHANOREQUAL": Opcode.OP_GREATERTHANOREQUAL,
  "OP_MIN": Opcode.OP_MIN, "OP_MAX": Opcode.OP_MAX,
  "OP_WITHIN": Opcode.OP_WITHIN,
  // Crypto
  "OP_RIPEMD160": Opcode.OP_RIPEMD160, "OP_SHA1": Opcode.OP_SHA1,
  "OP_SHA256": Opcode.OP_SHA256, "OP_HASH160": Opcode.OP_HASH160,
  "OP_HASH256": Opcode.OP_HASH256,
  "OP_CODESEPARATOR": Opcode.OP_CODESEPARATOR,
  "OP_CHECKSIG": Opcode.OP_CHECKSIG, "OP_CHECKSIGVERIFY": Opcode.OP_CHECKSIGVERIFY,
  "OP_CHECKMULTISIG": Opcode.OP_CHECKMULTISIG,
  "OP_CHECKMULTISIGVERIFY": Opcode.OP_CHECKMULTISIGVERIFY,
  // Locktime
  "OP_NOP1": Opcode.OP_NOP1,
  "OP_CHECKLOCKTIMEVERIFY": Opcode.OP_CHECKLOCKTIMEVERIFY,
  "OP_CLTV": Opcode.OP_CHECKLOCKTIMEVERIFY,
  "OP_NOP2": Opcode.OP_CHECKLOCKTIMEVERIFY,
  "OP_CHECKSEQUENCEVERIFY": Opcode.OP_CHECKSEQUENCEVERIFY,
  "OP_CSV": Opcode.OP_CHECKSEQUENCEVERIFY,
  "OP_NOP3": Opcode.OP_CHECKSEQUENCEVERIFY,
  "OP_NOP4": Opcode.OP_NOP4, "OP_NOP5": Opcode.OP_NOP5,
  "OP_NOP6": Opcode.OP_NOP6, "OP_NOP7": Opcode.OP_NOP7,
  "OP_NOP8": Opcode.OP_NOP8, "OP_NOP9": Opcode.OP_NOP9,
  "OP_NOP10": Opcode.OP_NOP10,
  "OP_CHECKSIGADD": Opcode.OP_CHECKSIGADD,
  "OP_INVALIDOPCODE": Opcode.OP_INVALIDOPCODE,
};

// Add aliases without OP_ prefix
const bareAliases: Record<string, number> = {};
for (const [key, val] of Object.entries(OPCODE_MAP)) {
  if (key.startsWith("OP_")) {
    bareAliases[key.slice(3)] = val;
  }
}
Object.assign(OPCODE_MAP, bareAliases);

// ---------------------------------------------------------------------------
// Script assembly parser
// ---------------------------------------------------------------------------

function hexToBuffer(hexStr: string): Buffer {
  return Buffer.from(hexStr, "hex");
}

function pushDataBuf(data: Buffer): Buffer {
  const len = data.length;
  if (len === 0) {
    return Buffer.from([0x00]);
  }
  if (len <= 75) {
    return Buffer.concat([Buffer.from([len]), data]);
  }
  if (len <= 255) {
    return Buffer.concat([Buffer.from([0x4c, len]), data]);
  }
  if (len <= 65535) {
    return Buffer.concat([Buffer.from([0x4d, len & 0xff, (len >> 8) & 0xff]), data]);
  }
  return Buffer.concat([
    Buffer.from([0x4e, len & 0xff, (len >> 8) & 0xff, (len >> 16) & 0xff, (len >> 24) & 0xff]),
    data,
  ]);
}

function parseScriptAsm(asm: string): Buffer {
  const parts: Buffer[] = [];
  const tokens = asm.split(/\s+/).filter((t) => t.length > 0);

  for (let i = 0; i < tokens.length; i++) {
    const tok = tokens[i];

    // Quoted string
    if (tok.startsWith("'") && tok.endsWith("'") && tok.length >= 2) {
      const text = tok.slice(1, -1);
      parts.push(pushDataBuf(Buffer.from(text, "ascii")));
      continue;
    }

    // Hex literal
    if (tok.startsWith("0x") || tok.startsWith("0X")) {
      const hexStr = tok.slice(2);
      const data = hexToBuffer(hexStr);

      // Check for push prefix pattern
      if (data.length === 1 && i + 1 < tokens.length && (tokens[i + 1].startsWith("0x") || tokens[i + 1].startsWith("0X"))) {
        const opByte = data[0];
        if ((opByte >= 1 && opByte <= 75) || opByte === 0x4c || opByte === 0x4d || opByte === 0x4e) {
          const nextData = hexToBuffer(tokens[i + 1].slice(2));
          parts.push(Buffer.from([opByte]));
          parts.push(nextData);
          i++;
          continue;
        }
      }

      parts.push(data);
      continue;
    }

    // Opcode name
    const opVal = OPCODE_MAP[tok] ?? OPCODE_MAP["OP_" + tok];
    if (opVal !== undefined) {
      parts.push(Buffer.from([opVal]));
      continue;
    }

    // Special: bare "0"
    if (tok === "0") {
      parts.push(Buffer.from([0x00]));
      continue;
    }

    // Decimal number
    const n = parseInt(tok, 10);
    if (!isNaN(n)) {
      if (n === -1) {
        parts.push(Buffer.from([0x4f]));
      } else if (n >= 1 && n <= 16) {
        parts.push(Buffer.from([0x50 + n]));
      } else {
        const encoded = scriptNumEncode(n);
        parts.push(pushDataBuf(encoded));
      }
      continue;
    }

    throw new Error(`unknown token: ${JSON.stringify(tok)}`);
  }

  return Buffer.concat(parts);
}

// ---------------------------------------------------------------------------
// Flag parser
// ---------------------------------------------------------------------------

function parseFlags(s: string): ScriptFlags {
  const flags: ScriptFlags = {
    verifyP2SH: false,
    verifyWitness: false,
    verifyTaproot: false,
    verifyStrictEncoding: false,
    verifyDERSignatures: false,
    verifyLowS: false,
    verifyNullDummy: false,
    verifyNullFail: false,
    verifyCheckLockTimeVerify: false,
    verifyCheckSequenceVerify: false,
    verifyWitnessPubkeyType: false,
  };

  if (!s || s === "NONE") return flags;

  for (const f of s.split(",")) {
    switch (f.trim()) {
      case "P2SH": flags.verifyP2SH = true; break;
      case "STRICTENC": flags.verifyStrictEncoding = true; break;
      case "DERSIG": flags.verifyDERSignatures = true; break;
      case "LOW_S": flags.verifyLowS = true; break;
      case "NULLDUMMY": flags.verifyNullDummy = true; break;
      case "CLEANSTACK": flags.verifyCleanStack = true; break;
      case "CHECKLOCKTIMEVERIFY": flags.verifyCheckLockTimeVerify = true; break;
      case "CHECKSEQUENCEVERIFY": flags.verifyCheckSequenceVerify = true; break;
      case "WITNESS": flags.verifyWitness = true; break;
      case "WITNESS_PUBKEYTYPE": flags.verifyWitnessPubkeyType = true; break;
      case "NULLFAIL": flags.verifyNullFail = true; break;
      case "TAPROOT": flags.verifyTaproot = true; break;
      case "MINIMALIF": flags.verifyMinimalIf = true; break;
      case "MINIMALDATA": flags.verifyMinimalData = true; break;
      case "SIGPUSHONLY": flags.verifySigPushOnly = true; break;
      case "DISCOURAGE_UPGRADABLE_NOPS": flags.verifyDiscourageUpgradableNops = true; break;
      case "DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM":
      case "DISCOURAGE_OP_SUCCESS":
      case "CONST_SCRIPTCODE":
      case "DISCOURAGE_UPGRADABLE_TAPROOT_VERSION":
        // May not be in interface; skip
        break;
      default:
        // Unknown flag; ignore
        break;
    }
  }
  return flags;
}

// ---------------------------------------------------------------------------
// Crediting & spending transactions (matches Bitcoin Core's test approach)
// ---------------------------------------------------------------------------

/**
 * Build a "crediting transaction" per Bitcoin Core's script_tests.cpp:
 * - version 1, locktime 0
 * - one input: null prevout (all-zero txid, vout=0xFFFFFFFF), scriptSig = OP_0 OP_0, sequence 0xFFFFFFFF
 * - one output: scriptPubKey = test's scriptPubKey, value = 0
 */
function buildCreditingTx(scriptPubKey: Buffer): Transaction {
  return {
    version: 1,
    inputs: [{
      prevOut: { txid: Buffer.alloc(32, 0), vout: 0xFFFFFFFF },
      scriptSig: Buffer.from([0x00, 0x00]), // OP_0 OP_0
      sequence: 0xFFFFFFFF,
      witness: [],
    }],
    outputs: [{
      value: 0n,
      scriptPubKey,
    }],
    lockTime: 0,
  };
}

/**
 * Build a "spending transaction" per Bitcoin Core's script_tests.cpp:
 * - version 1, locktime 0
 * - one input: prevout = txid of crediting tx : 0, scriptSig = test's scriptSig, sequence 0xFFFFFFFF
 * - one output: scriptPubKey = empty, value = 0
 */
function buildSpendingTx(creditingTx: Transaction, scriptSig: Buffer): Transaction {
  const creditTxId = getTxId(creditingTx);
  return {
    version: 1,
    inputs: [{
      prevOut: { txid: creditTxId, vout: 0 },
      scriptSig,
      sequence: 0xFFFFFFFF,
      witness: [],
    }],
    outputs: [{
      value: 0n,
      scriptPubKey: Buffer.alloc(0),
    }],
    lockTime: 0,
  };
}

/**
 * Create a real sigHasher for a spending transaction.
 * The sigHasher callback receives the subscript (already processed by the
 * interpreter: sliced after OP_CODESEPARATOR, FindAndDelete applied for legacy)
 * and the hashType byte from the signature.
 */
function makeSigHasher(spendingTx: Transaction, inputIndex: number): (subscript: Buffer, hashType: number) => Buffer {
  return (subscript: Buffer, hashType: number): Buffer => {
    return sigHashLegacy(spendingTx, inputIndex, subscript, hashType);
  };
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

const raw = readFileSync(VECTOR_PATH, "utf-8");
const vectors: any[] = JSON.parse(raw);

let pass = 0;
let fail = 0;
let skip = 0;
let parseErrors = 0;

for (let i = 0; i < vectors.length; i++) {
  const entry = vectors[i];

  if (!Array.isArray(entry)) {
    skip++;
    continue;
  }

  // Skip comments
  if (entry.length <= 1) {
    skip++;
    continue;
  }

  // Skip witness tests (first element is an array)
  if (Array.isArray(entry[0])) {
    skip++;
    continue;
  }

  if (entry.length < 4) {
    skip++;
    continue;
  }

  const scriptSigAsm: string = entry[0];
  const scriptPubKeyAsm: string = entry[1];
  const flagsStr: string = entry[2];
  const expected: string = entry[3];
  const comment: string = entry.length >= 5 ? entry[4] : "";

  let scriptSig: Buffer;
  let scriptPubKey: Buffer;

  try {
    scriptSig = parseScriptAsm(scriptSigAsm);
  } catch (e: any) {
    parseErrors++;
    if (parseErrors <= 20) {
      console.error(`test ${i}: parse scriptSig error: ${e.message} (asm: ${JSON.stringify(scriptSigAsm)})`);
    }
    continue;
  }

  try {
    scriptPubKey = parseScriptAsm(scriptPubKeyAsm);
  } catch (e: any) {
    parseErrors++;
    if (parseErrors <= 20) {
      console.error(`test ${i}: parse scriptPubKey error: ${e.message} (asm: ${JSON.stringify(scriptPubKeyAsm)})`);
    }
    continue;
  }

  const flags = parseFlags(flagsStr);
  const witness: Buffer[] = [];

  // Build crediting and spending transactions (Bitcoin Core approach)
  const creditingTx = buildCreditingTx(scriptPubKey);
  const spendingTx = buildSpendingTx(creditingTx, scriptSig);
  const sigHasher = makeSigHasher(spendingTx, 0);

  // Provide tx context for CLTV/CSV verification
  const txContext = {
    txVersion: spendingTx.version,
    txLockTime: spendingTx.lockTime,
    txSequence: spendingTx.inputs[0].sequence,
  };

  let gotOK: boolean;
  try {
    gotOK = verifyScript(scriptSig, scriptPubKey, witness, flags, sigHasher, undefined, txContext);
  } catch {
    gotOK = false;
  }

  const expectOK = expected === "OK";

  if (expectOK === gotOK) {
    pass++;
  } else {
    fail++;
    if (fail <= 50) {
      console.error(
        `FAIL test ${i}: expected=${expected} got=${gotOK ? "OK" : "FAIL"} ` +
        `sigAsm=${JSON.stringify(scriptSigAsm)} pubkeyAsm=${JSON.stringify(scriptPubKeyAsm)} ` +
        `flags=${flagsStr} comment=${JSON.stringify(comment)}`
      );
    }
  }
}

console.log(`script_tests.json results: ${pass} passed, ${fail} failed, ${skip} skipped, ${parseErrors} parse errors`);

if (fail > 0) {
  console.error(`NOTE: ${fail} test(s) failed with real signature verification`);
}
