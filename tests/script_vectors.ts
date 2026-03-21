/**
 * Script test harness for hotbuns Bitcoin implementation.
 *
 * Loads Bitcoin Core's script_tests.json test vectors and verifies
 * the script interpreter against each expected result.
 *
 * Formats:
 *   [scriptSig_asm, scriptPubKey_asm, flags, expected_result]              (4 fields)
 *   [scriptSig_asm, scriptPubKey_asm, flags, expected_result, comment]     (5 fields)
 *   [[witness...], amount, scriptSig_asm, scriptPubKey_asm, flags, result] (6+ fields, witness)
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
  type TaprootContext,
} from "../src/script/interpreter.js";
import {
  type Transaction,
  type TxIn,
  type TxOut,
  getTxId,
  sigHashLegacy,
  sigHashWitnessV0,
} from "../src/validation/tx.js";
import { taggedHash } from "../src/crypto/primitives.js";
import { schnorr } from "@noble/curves/secp256k1.js";

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
// Taproot placeholder resolution
// ---------------------------------------------------------------------------

// Internal key for taproot test vectors: secp256k1 generator x-coordinate
const TAPROOT_INTERNAL_KEY = Buffer.from(
  "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
  "hex"
);

/**
 * Encode a length as Bitcoin compact size.
 */
function compactSize(n: number): Buffer {
  if (n < 0xfd) return Buffer.from([n]);
  if (n <= 0xffff) return Buffer.from([0xfd, n & 0xff, (n >> 8) & 0xff]);
  return Buffer.from([
    0xfe, n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff, (n >> 24) & 0xff,
  ]);
}

/**
 * Compute taproot leaf hash, control block, and output key for a single-leaf tree.
 *
 * Returns { scriptBytes, controlBlock, outputKey } where:
 * - scriptBytes: the serialized script
 * - controlBlock: (0xc0 | parity) || internal_key (33 bytes, single leaf = no merkle path)
 * - outputKey: 32-byte x-only tweaked output key
 */
function computeTaprootParams(scriptAsm: string): {
  scriptBytes: Buffer;
  controlBlock: Buffer;
  outputKey: Buffer;
} {
  const scriptBytes = parseScriptAsm(scriptAsm);

  // Tapleaf hash: tagged_hash("TapLeaf", 0xc0 || compact_size(script_len) || script)
  const leafData = Buffer.concat([
    Buffer.from([0xc0]),
    compactSize(scriptBytes.length),
    scriptBytes,
  ]);
  const leafHash = taggedHash("TapLeaf", leafData);

  // Merkle root = leaf hash (single leaf, no sibling)
  const merkleRoot = leafHash;

  // Tweak: tagged_hash("TapTweak", internal_key || merkle_root)
  const tweak = taggedHash(
    "TapTweak",
    Buffer.concat([TAPROOT_INTERNAL_KEY, merkleRoot])
  );

  // Compute tweaked key: P + tweak*G
  const x = BigInt("0x" + TAPROOT_INTERNAL_KEY.toString("hex"));
  const P = schnorr.utils.lift_x(x);
  const t = BigInt("0x" + tweak.toString("hex"));
  const Point = schnorr.Point;
  const tG = Point.BASE.multiply(t);
  const tweaked = P.add(tG);

  // Output key parity
  const parity = tweaked.y % 2n === 0n ? 0 : 1;

  // Output key x-only (32 bytes)
  const outputKey = Buffer.from(
    tweaked.x.toString(16).padStart(64, "0"),
    "hex"
  );

  // Control block: (0xc0 | parity) || internal_key  (no merkle path for single leaf)
  const controlBlock = Buffer.concat([
    Buffer.from([0xc0 | parity]),
    TAPROOT_INTERNAL_KEY,
  ]);

  return { scriptBytes, controlBlock, outputKey };
}

/**
 * Resolve taproot placeholders in a witness-format test vector.
 *
 * Finds the witness item prefixed with "#SCRIPT#", extracts the ASM,
 * computes the script bytes / control block / output key, and replaces
 * the placeholder items in-place.
 *
 * Returns the resolved outputKey hex for use in scriptPubKey, or null if
 * this vector has no taproot placeholders.
 */
function resolveTaprootPlaceholders(
  witnessHexItems: string[],
  scriptPubKeyAsm: string
): { resolvedWitness: string[]; resolvedPubKeyAsm: string } | null {
  // Find the #SCRIPT# witness item
  const scriptIdx = witnessHexItems.findIndex((w) => w.startsWith("#SCRIPT#"));
  if (scriptIdx === -1 && !scriptPubKeyAsm.includes("#TAPROOTOUTPUT#")) {
    return null;
  }

  if (scriptIdx === -1) {
    return null; // shouldn't happen in valid vectors
  }

  // Extract script ASM (everything after "#SCRIPT# ")
  const scriptAsm = witnessHexItems[scriptIdx].slice("#SCRIPT# ".length);

  // Compute taproot parameters
  const { scriptBytes, controlBlock, outputKey } =
    computeTaprootParams(scriptAsm);

  // Build resolved witness: replace #SCRIPT# with hex of script bytes,
  // replace #CONTROLBLOCK# with hex of control block
  const resolvedWitness = witnessHexItems.map((item) => {
    if (item.startsWith("#SCRIPT#")) {
      return scriptBytes.toString("hex");
    }
    if (item === "#CONTROLBLOCK#") {
      return controlBlock.toString("hex");
    }
    return item;
  });

  // Replace #TAPROOTOUTPUT# in scriptPubKey ASM with hex of output key
  const resolvedPubKeyAsm = scriptPubKeyAsm.replace(
    "#TAPROOTOUTPUT#",
    "0x" + outputKey.toString("hex")
  );

  return { resolvedWitness, resolvedPubKeyAsm };
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
        flags.verifyDiscourageUpgradableWitnessProgram = true;
        break;
      case "DISCOURAGE_OP_SUCCESS":
      case "CONST_SCRIPTCODE":
      case "DISCOURAGE_UPGRADABLE_TAPROOT_VERSION":
        // Not yet implemented; skip
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
 * - one output: scriptPubKey = test's scriptPubKey, value = amount
 */
function buildCreditingTx(scriptPubKey: Buffer, amount: bigint = 0n): Transaction {
  return {
    version: 1,
    inputs: [{
      prevOut: { txid: Buffer.alloc(32, 0), vout: 0xFFFFFFFF },
      scriptSig: Buffer.from([0x00, 0x00]), // OP_0 OP_0
      sequence: 0xFFFFFFFF,
      witness: [],
    }],
    outputs: [{
      value: amount,
      scriptPubKey,
    }],
    lockTime: 0,
  };
}

/**
 * Build a "spending transaction" per Bitcoin Core's script_tests.cpp:
 * - version 1, locktime 0
 * - one input: prevout = txid of crediting tx : 0, scriptSig = test's scriptSig, sequence 0xFFFFFFFF
 * - one output: scriptPubKey = empty, value = amount
 */
function buildSpendingTx(
  creditingTx: Transaction,
  scriptSig: Buffer,
  witness: Buffer[] = [],
  amount: bigint = 0n
): Transaction {
  const creditTxId = getTxId(creditingTx);
  return {
    version: 1,
    inputs: [{
      prevOut: { txid: creditTxId, vout: 0 },
      scriptSig,
      sequence: 0xFFFFFFFF,
      witness,
    }],
    outputs: [{
      value: amount,
      scriptPubKey: Buffer.alloc(0),
    }],
    lockTime: 0,
  };
}

/**
 * Create a legacy sigHasher for a spending transaction.
 */
function makeSigHasher(spendingTx: Transaction, inputIndex: number): (subscript: Buffer, hashType: number) => Buffer {
  return (subscript: Buffer, hashType: number): Buffer => {
    return sigHashLegacy(spendingTx, inputIndex, subscript, hashType);
  };
}

/**
 * Create a BIP143 witness v0 sigHasher for a spending transaction.
 */
function makeWitnessSigHasher(
  spendingTx: Transaction,
  inputIndex: number,
  amount: bigint
): (subscript: Buffer, hashType: number) => Buffer {
  return (subscript: Buffer, hashType: number): Buffer => {
    return sigHashWitnessV0(spendingTx, inputIndex, subscript, amount, hashType);
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

  // Determine if this is a witness test vector or a legacy test vector
  let scriptSigAsm: string;
  let scriptPubKeyAsm: string;
  let flagsStr: string;
  let expected: string;
  let comment: string;
  let witnessHexItems: string[] = [];
  let amountSatoshis: bigint = 0n;
  let isWitness = false;

  if (Array.isArray(entry[0])) {
    // Witness format: [[witness_hex1, ..., amount_btc], scriptSig_asm, scriptPubKey_asm, flags, result, ?comment]
    // The amount is the LAST element of the witness array (always a number)
    if (entry.length < 5) {
      skip++;
      continue;
    }
    isWitness = true;
    const witnessArr = entry[0] as any[];
    // Last element of witness array is the amount in BTC
    const rawAmount = witnessArr[witnessArr.length - 1] as number;
    amountSatoshis = BigInt(Math.round(rawAmount * 1e8));
    // Witness items are all elements except the last (the amount)
    witnessHexItems = witnessArr.slice(0, -1) as string[];
    scriptSigAsm = entry[1];
    scriptPubKeyAsm = entry[2];
    flagsStr = entry[3];
    expected = entry[4];
    comment = entry.length >= 6 ? entry[5] : "";
  } else {
    if (entry.length < 4) {
      skip++;
      continue;
    }
    scriptSigAsm = entry[0];
    scriptPubKeyAsm = entry[1];
    flagsStr = entry[2];
    expected = entry[3];
    comment = entry.length >= 5 ? entry[4] : "";
  }

  // Resolve taproot placeholders (#SCRIPT#, #CONTROLBLOCK#, #TAPROOTOUTPUT#)
  if (isWitness) {
    const resolved = resolveTaprootPlaceholders(witnessHexItems, scriptPubKeyAsm);
    if (resolved) {
      witnessHexItems = resolved.resolvedWitness;
      scriptPubKeyAsm = resolved.resolvedPubKeyAsm;
    }
  }

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

  // Parse witness stack from hex strings
  const witness: Buffer[] = witnessHexItems.map((hex) =>
    hex.length === 0 ? Buffer.alloc(0) : Buffer.from(hex, "hex")
  );

  // Build crediting and spending transactions (Bitcoin Core approach)
  const creditingTx = buildCreditingTx(scriptPubKey, amountSatoshis);
  const spendingTx = buildSpendingTx(creditingTx, scriptSig, witness, amountSatoshis);
  const sigHasher = makeSigHasher(spendingTx, 0);

  // Create witness-aware sigHasher for BIP143
  const witnessSigHasher = makeWitnessSigHasher(spendingTx, 0, amountSatoshis);

  // Provide tx context for CLTV/CSV verification
  const txContext = {
    txVersion: spendingTx.version,
    txLockTime: spendingTx.lockTime,
    txSequence: spendingTx.inputs[0].sequence,
  };

  // Build a TaprootContext for taproot script-path test vectors.
  // These tests don't perform real Schnorr signature verification
  // (they test script logic), but executeTapscript requires the context.
  let taprootCtx: TaprootContext | undefined;
  if (flags.verifyTaproot && isWitness && witness.length >= 2) {
    taprootCtx = {
      keyPathSigHasher: (_hashType: number) => Buffer.alloc(32),
      scriptPathSigHasher: (_hashType: number, _leafHash: Buffer, _codeSepPos: number) =>
        Buffer.alloc(32),
    };
  }

  let gotOK: boolean;
  try {
    gotOK = verifyScript(
      scriptSig, scriptPubKey, witness, flags, sigHasher,
      taprootCtx, txContext, witnessSigHasher
    );
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
        `flags=${flagsStr} comment=${JSON.stringify(comment)}` +
        (isWitness ? ` witness=[${witnessHexItems.length} items] amount=${amountSatoshis}` : "")
      );
    }
  }
}

console.log(`script_tests.json results: ${pass} passed, ${fail} failed, ${skip} skipped, ${parseErrors} parse errors`);

if (fail > 0) {
  console.error(`NOTE: ${fail} test(s) failed with real signature verification`);
}
