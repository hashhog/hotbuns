/**
 * Partially Signed Bitcoin Transactions (PSBT) - BIP 174/370
 *
 * Implements the standard format for unsigned/partially-signed transactions
 * that enables multi-party signing workflows.
 *
 * References:
 * - BIP 174: https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki
 * - BIP 370: https://github.com/bitcoin/bips/blob/master/bip-0370.mediawiki
 * - Bitcoin Core: /src/psbt.h, /src/node/psbt.cpp
 */

import { BufferReader, BufferWriter } from "../wire/serialization.js";
import {
  type Transaction,
  type TxIn,
  type TxOut,
  type OutPoint,
  serializeTx,
  deserializeTx,
  getTxId,
  sigHashWitnessV0,
  sigHashLegacy,
  SIGHASH_ALL,
  hasWitness,
} from "../validation/tx.js";
import {
  hash160,
  ecdsaSign,
  ecdsaVerify,
  taggedHash,
} from "../crypto/primitives.js";

// =============================================================================
// PSBT Constants
// =============================================================================

/** PSBT magic bytes: "psbt" + 0xff separator */
export const PSBT_MAGIC = Buffer.from("70736274ff", "hex");

/** PSBT separator byte (0x00) marks end of a map */
export const PSBT_SEPARATOR = 0x00;

/** Maximum PSBT file size (100 MB) */
export const PSBT_MAX_FILE_SIZE = 100_000_000;

/** Highest supported PSBT version */
export const PSBT_HIGHEST_VERSION = 0;

// Global key types
export const PSBT_GLOBAL_UNSIGNED_TX = 0x00;
export const PSBT_GLOBAL_XPUB = 0x01;
export const PSBT_GLOBAL_VERSION = 0xfb;
export const PSBT_GLOBAL_PROPRIETARY = 0xfc;

// Input key types
export const PSBT_IN_NON_WITNESS_UTXO = 0x00;
export const PSBT_IN_WITNESS_UTXO = 0x01;
export const PSBT_IN_PARTIAL_SIG = 0x02;
export const PSBT_IN_SIGHASH = 0x03;
export const PSBT_IN_REDEEMSCRIPT = 0x04;
export const PSBT_IN_WITNESSSCRIPT = 0x05;
export const PSBT_IN_BIP32_DERIVATION = 0x06;
export const PSBT_IN_SCRIPTSIG = 0x07;
export const PSBT_IN_SCRIPTWITNESS = 0x08;
export const PSBT_IN_RIPEMD160 = 0x0a;
export const PSBT_IN_SHA256 = 0x0b;
export const PSBT_IN_HASH160 = 0x0c;
export const PSBT_IN_HASH256 = 0x0d;
export const PSBT_IN_TAP_KEY_SIG = 0x13;
export const PSBT_IN_TAP_SCRIPT_SIG = 0x14;
export const PSBT_IN_TAP_LEAF_SCRIPT = 0x15;
export const PSBT_IN_TAP_BIP32_DERIVATION = 0x16;
export const PSBT_IN_TAP_INTERNAL_KEY = 0x17;
export const PSBT_IN_TAP_MERKLE_ROOT = 0x18;
export const PSBT_IN_PROPRIETARY = 0xfc;

// Output key types
export const PSBT_OUT_REDEEMSCRIPT = 0x00;
export const PSBT_OUT_WITNESSSCRIPT = 0x01;
export const PSBT_OUT_BIP32_DERIVATION = 0x02;
export const PSBT_OUT_TAP_INTERNAL_KEY = 0x05;
export const PSBT_OUT_TAP_TREE = 0x06;
export const PSBT_OUT_TAP_BIP32_DERIVATION = 0x07;
export const PSBT_OUT_PROPRIETARY = 0xfc;

// =============================================================================
// PSBT Types
// =============================================================================

/**
 * BIP32 key origin info: fingerprint + derivation path.
 */
export interface KeyOriginInfo {
  /** 4-byte fingerprint of the master key */
  fingerprint: Buffer;
  /** Array of derivation path indices (uint32) */
  path: number[];
}

/**
 * Per-input PSBT data.
 */
export interface PSBTInput {
  /** Full previous transaction (for non-segwit validation) */
  nonWitnessUtxo?: Transaction;
  /** Previous output being spent (for segwit) */
  witnessUtxo?: TxOut;
  /** Partial signatures: pubkey -> signature (DER + sighash type) */
  partialSigs: Map<string, { pubkey: Buffer; signature: Buffer }>;
  /** Sighash type to use for this input */
  sighashType?: number;
  /** Redeem script for P2SH */
  redeemScript?: Buffer;
  /** Witness script for P2WSH */
  witnessScript?: Buffer;
  /** BIP32 derivation paths: pubkey hex -> KeyOriginInfo */
  bip32Derivation: Map<string, { pubkey: Buffer; origin: KeyOriginInfo }>;
  /** Final scriptSig (after finalization) */
  finalScriptSig?: Buffer;
  /** Final witness stack (after finalization) */
  finalScriptWitness?: Buffer[];
  /** Hash preimages for RIPEMD160 */
  ripemd160Preimages: Map<string, Buffer>;
  /** Hash preimages for SHA256 */
  sha256Preimages: Map<string, Buffer>;
  /** Hash preimages for HASH160 */
  hash160Preimages: Map<string, Buffer>;
  /** Hash preimages for HASH256 */
  hash256Preimages: Map<string, Buffer>;
  /** Taproot key-path signature */
  tapKeySig?: Buffer;
  /** Taproot internal key (x-only, 32 bytes) */
  tapInternalKey?: Buffer;
  /** Taproot merkle root */
  tapMerkleRoot?: Buffer;
  /** Unknown key-value pairs */
  unknown: Map<string, Buffer>;
}

/**
 * Per-output PSBT data.
 */
export interface PSBTOutput {
  /** Redeem script for P2SH output */
  redeemScript?: Buffer;
  /** Witness script for P2WSH output */
  witnessScript?: Buffer;
  /** BIP32 derivation paths: pubkey hex -> KeyOriginInfo */
  bip32Derivation: Map<string, { pubkey: Buffer; origin: KeyOriginInfo }>;
  /** Taproot internal key (x-only, 32 bytes) */
  tapInternalKey?: Buffer;
  /** Taproot script tree */
  tapTree?: Array<{ depth: number; leafVersion: number; script: Buffer }>;
  /** Unknown key-value pairs */
  unknown: Map<string, Buffer>;
}

/**
 * A Partially Signed Bitcoin Transaction.
 */
export interface PSBT {
  /** The unsigned transaction */
  tx: Transaction;
  /** Global extended public keys */
  xpubs: Map<string, { xpub: Buffer; origin: KeyOriginInfo }>;
  /** Per-input data */
  inputs: PSBTInput[];
  /** Per-output data */
  outputs: PSBTOutput[];
  /** PSBT version (0 for BIP174) */
  version?: number;
  /** Unknown global key-value pairs */
  unknown: Map<string, Buffer>;
}

/**
 * PSBT role types.
 */
export enum PSBTRole {
  CREATOR = "creator",
  UPDATER = "updater",
  SIGNER = "signer",
  COMBINER = "combiner",
  FINALIZER = "finalizer",
  EXTRACTOR = "extractor",
}

/**
 * Result of analyzing a PSBT.
 */
export interface PSBTAnalysis {
  /** Number of inputs */
  inputCount: number;
  /** Number of outputs */
  outputCount: number;
  /** Number of fully signed inputs */
  signedInputs: number;
  /** Number of finalized inputs */
  finalizedInputs: number;
  /** Whether the PSBT is complete (all inputs finalized) */
  isComplete: boolean;
  /** Estimated fee (if all UTXO info is present) */
  estimatedFee?: bigint;
  /** Per-input analysis */
  inputAnalysis: Array<{
    index: number;
    hasSig: boolean;
    isFinalized: boolean;
    signaturesNeeded: number;
    signatureCount: number;
    utxoAmount?: bigint;
  }>;
  /** Next roles that can be performed */
  nextRoles: PSBTRole[];
}

// =============================================================================
// PSBT Creation
// =============================================================================

/**
 * Create a new empty PSBTInput.
 */
export function createPSBTInput(): PSBTInput {
  return {
    partialSigs: new Map(),
    bip32Derivation: new Map(),
    ripemd160Preimages: new Map(),
    sha256Preimages: new Map(),
    hash160Preimages: new Map(),
    hash256Preimages: new Map(),
    unknown: new Map(),
  };
}

/**
 * Create a new empty PSBTOutput.
 */
export function createPSBTOutput(): PSBTOutput {
  return {
    bip32Derivation: new Map(),
    unknown: new Map(),
  };
}

/**
 * Create a new PSBT from an unsigned transaction.
 *
 * This is the CREATOR role: constructs a blank PSBT with an unsigned tx.
 *
 * @param tx - The unsigned transaction (all scriptSigs and witnesses must be empty)
 */
export function createPSBT(tx: Transaction): PSBT {
  // Validate that transaction is unsigned
  for (const input of tx.inputs) {
    if (input.scriptSig.length > 0) {
      throw new Error("Transaction inputs must have empty scriptSig");
    }
    if (input.witness.length > 0) {
      throw new Error("Transaction inputs must have empty witness");
    }
  }

  return {
    tx,
    xpubs: new Map(),
    inputs: tx.inputs.map(() => createPSBTInput()),
    outputs: tx.outputs.map(() => createPSBTOutput()),
    unknown: new Map(),
  };
}

// =============================================================================
// PSBT Serialization
// =============================================================================

/**
 * Write a PSBT key-value pair.
 *
 * Format: [keyLen][keyType][keyData][valueLen][valueData]
 */
function writeKeyValue(
  writer: BufferWriter,
  keyType: number,
  keyData: Buffer,
  value: Buffer
): void {
  // Key: compact size length + type byte + key data
  const keyTypeBuffer = Buffer.alloc(1);
  keyTypeBuffer[0] = keyType;
  const fullKey = Buffer.concat([keyTypeBuffer, keyData]);
  writer.writeVarBytes(fullKey);

  // Value: compact size length + value data
  writer.writeVarBytes(value);
}

/**
 * Write a PSBT key-value pair with just the type (no key data).
 */
function writeKeyValueSimple(
  writer: BufferWriter,
  keyType: number,
  value: Buffer
): void {
  writeKeyValue(writer, keyType, Buffer.alloc(0), value);
}

/**
 * Serialize a transaction without witness data for PSBT.
 */
function serializeTxForPSBT(tx: Transaction): Buffer {
  // PSBT stores transactions without witness data
  return serializeTx(tx, false);
}

/**
 * Serialize a KeyOriginInfo (fingerprint + derivation path).
 */
function serializeKeyOrigin(origin: KeyOriginInfo): Buffer {
  const writer = new BufferWriter();
  writer.writeBytes(origin.fingerprint);
  for (const index of origin.path) {
    writer.writeUInt32LE(index);
  }
  return writer.toBuffer();
}

/**
 * Deserialize a KeyOriginInfo from bytes.
 */
function deserializeKeyOrigin(data: Buffer): KeyOriginInfo {
  if (data.length < 4 || (data.length - 4) % 4 !== 0) {
    throw new Error("Invalid key origin length");
  }

  const fingerprint = data.subarray(0, 4);
  const path: number[] = [];

  for (let i = 4; i < data.length; i += 4) {
    path.push(data.readUInt32LE(i));
  }

  return { fingerprint: Buffer.from(fingerprint), path };
}

/**
 * Serialize a PSBTInput.
 */
function serializePSBTInput(input: PSBTInput): Buffer {
  const writer = new BufferWriter();

  // Non-witness UTXO
  if (input.nonWitnessUtxo) {
    const txData = serializeTx(input.nonWitnessUtxo, true);
    writeKeyValueSimple(writer, PSBT_IN_NON_WITNESS_UTXO, txData);
  }

  // Witness UTXO
  if (input.witnessUtxo) {
    const utxoWriter = new BufferWriter();
    utxoWriter.writeUInt64LE(input.witnessUtxo.value);
    utxoWriter.writeVarBytes(input.witnessUtxo.scriptPubKey);
    writeKeyValueSimple(writer, PSBT_IN_WITNESS_UTXO, utxoWriter.toBuffer());
  }

  // Only write signing data if not finalized
  if (!input.finalScriptSig && !input.finalScriptWitness) {
    // Partial signatures
    for (const { pubkey, signature } of input.partialSigs.values()) {
      writeKeyValue(writer, PSBT_IN_PARTIAL_SIG, pubkey, signature);
    }

    // Sighash type
    if (input.sighashType !== undefined) {
      const sighashWriter = new BufferWriter();
      sighashWriter.writeUInt32LE(input.sighashType);
      writeKeyValueSimple(writer, PSBT_IN_SIGHASH, sighashWriter.toBuffer());
    }

    // Redeem script
    if (input.redeemScript) {
      writeKeyValueSimple(writer, PSBT_IN_REDEEMSCRIPT, input.redeemScript);
    }

    // Witness script
    if (input.witnessScript) {
      writeKeyValueSimple(writer, PSBT_IN_WITNESSSCRIPT, input.witnessScript);
    }

    // BIP32 derivation
    for (const { pubkey, origin } of input.bip32Derivation.values()) {
      writeKeyValue(
        writer,
        PSBT_IN_BIP32_DERIVATION,
        pubkey,
        serializeKeyOrigin(origin)
      );
    }

    // Hash preimages
    for (const [hashHex, preimage] of input.ripemd160Preimages) {
      writeKeyValue(
        writer,
        PSBT_IN_RIPEMD160,
        Buffer.from(hashHex, "hex"),
        preimage
      );
    }

    for (const [hashHex, preimage] of input.sha256Preimages) {
      writeKeyValue(
        writer,
        PSBT_IN_SHA256,
        Buffer.from(hashHex, "hex"),
        preimage
      );
    }

    for (const [hashHex, preimage] of input.hash160Preimages) {
      writeKeyValue(
        writer,
        PSBT_IN_HASH160,
        Buffer.from(hashHex, "hex"),
        preimage
      );
    }

    for (const [hashHex, preimage] of input.hash256Preimages) {
      writeKeyValue(
        writer,
        PSBT_IN_HASH256,
        Buffer.from(hashHex, "hex"),
        preimage
      );
    }

    // Taproot key signature
    if (input.tapKeySig) {
      writeKeyValueSimple(writer, PSBT_IN_TAP_KEY_SIG, input.tapKeySig);
    }

    // Taproot internal key
    if (input.tapInternalKey) {
      writeKeyValueSimple(writer, PSBT_IN_TAP_INTERNAL_KEY, input.tapInternalKey);
    }

    // Taproot merkle root
    if (input.tapMerkleRoot) {
      writeKeyValueSimple(writer, PSBT_IN_TAP_MERKLE_ROOT, input.tapMerkleRoot);
    }
  }

  // Final scriptSig
  if (input.finalScriptSig) {
    writeKeyValueSimple(writer, PSBT_IN_SCRIPTSIG, input.finalScriptSig);
  }

  // Final witness
  if (input.finalScriptWitness) {
    const witnessWriter = new BufferWriter();
    witnessWriter.writeVarInt(input.finalScriptWitness.length);
    for (const item of input.finalScriptWitness) {
      witnessWriter.writeVarBytes(item);
    }
    writeKeyValueSimple(writer, PSBT_IN_SCRIPTWITNESS, witnessWriter.toBuffer());
  }

  // Unknown fields
  for (const [keyHex, value] of input.unknown) {
    const key = Buffer.from(keyHex, "hex");
    writer.writeVarBytes(key);
    writer.writeVarBytes(value);
  }

  // Separator
  writer.writeUInt8(PSBT_SEPARATOR);

  return writer.toBuffer();
}

/**
 * Serialize a PSBTOutput.
 */
function serializePSBTOutput(output: PSBTOutput): Buffer {
  const writer = new BufferWriter();

  // Redeem script
  if (output.redeemScript) {
    writeKeyValueSimple(writer, PSBT_OUT_REDEEMSCRIPT, output.redeemScript);
  }

  // Witness script
  if (output.witnessScript) {
    writeKeyValueSimple(writer, PSBT_OUT_WITNESSSCRIPT, output.witnessScript);
  }

  // BIP32 derivation
  for (const { pubkey, origin } of output.bip32Derivation.values()) {
    writeKeyValue(
      writer,
      PSBT_OUT_BIP32_DERIVATION,
      pubkey,
      serializeKeyOrigin(origin)
    );
  }

  // Taproot internal key
  if (output.tapInternalKey) {
    writeKeyValueSimple(writer, PSBT_OUT_TAP_INTERNAL_KEY, output.tapInternalKey);
  }

  // Taproot tree
  if (output.tapTree && output.tapTree.length > 0) {
    const treeWriter = new BufferWriter();
    for (const leaf of output.tapTree) {
      treeWriter.writeUInt8(leaf.depth);
      treeWriter.writeUInt8(leaf.leafVersion);
      treeWriter.writeVarBytes(leaf.script);
    }
    writeKeyValueSimple(writer, PSBT_OUT_TAP_TREE, treeWriter.toBuffer());
  }

  // Unknown fields
  for (const [keyHex, value] of output.unknown) {
    const key = Buffer.from(keyHex, "hex");
    writer.writeVarBytes(key);
    writer.writeVarBytes(value);
  }

  // Separator
  writer.writeUInt8(PSBT_SEPARATOR);

  return writer.toBuffer();
}

/**
 * Serialize a PSBT to binary format.
 */
export function serializePSBT(psbt: PSBT): Buffer {
  const writer = new BufferWriter();

  // Magic bytes
  writer.writeBytes(PSBT_MAGIC);

  // Global unsigned tx (required)
  const txData = serializeTxForPSBT(psbt.tx);
  writeKeyValueSimple(writer, PSBT_GLOBAL_UNSIGNED_TX, txData);

  // Global xpubs
  for (const { xpub, origin } of psbt.xpubs.values()) {
    // Key: type(1) + xpub(78)
    // Value: key origin (4 + 4*depth)
    writeKeyValue(writer, PSBT_GLOBAL_XPUB, xpub, serializeKeyOrigin(origin));
  }

  // PSBT version (only if > 0)
  if (psbt.version !== undefined && psbt.version > 0) {
    const versionWriter = new BufferWriter();
    versionWriter.writeUInt32LE(psbt.version);
    writeKeyValueSimple(writer, PSBT_GLOBAL_VERSION, versionWriter.toBuffer());
  }

  // Unknown global fields
  for (const [keyHex, value] of psbt.unknown) {
    const key = Buffer.from(keyHex, "hex");
    writer.writeVarBytes(key);
    writer.writeVarBytes(value);
  }

  // Global separator
  writer.writeUInt8(PSBT_SEPARATOR);

  // Inputs
  for (const input of psbt.inputs) {
    writer.writeBytes(serializePSBTInput(input));
  }

  // Outputs
  for (const output of psbt.outputs) {
    writer.writeBytes(serializePSBTOutput(output));
  }

  return writer.toBuffer();
}

/**
 * Encode a PSBT to base64.
 */
export function encodePSBTBase64(psbt: PSBT): string {
  return serializePSBT(psbt).toString("base64");
}

// =============================================================================
// PSBT Deserialization
// =============================================================================

/**
 * Read key-value pairs from a PSBT map until separator.
 *
 * @returns Array of [key, value] pairs
 */
function readKeyValuePairs(reader: BufferReader): Array<[Buffer, Buffer]> {
  const pairs: Array<[Buffer, Buffer]> = [];

  while (reader.remaining > 0) {
    // Read key length
    const keyLen = reader.readVarInt();

    // Empty key = separator
    if (keyLen === 0) {
      break;
    }

    // Read key
    const key = reader.readBytes(keyLen);

    // Read value
    const value = reader.readVarBytes();

    pairs.push([key, value]);
  }

  return pairs;
}

/**
 * Get the type from a PSBT key.
 */
function getKeyType(key: Buffer): number {
  if (key.length === 0) {
    throw new Error("Empty PSBT key");
  }
  // The key type is a varint at the start of the key
  const keyReader = new BufferReader(key);
  return keyReader.readVarInt();
}

/**
 * Get the key data (everything after the type) from a PSBT key.
 */
function getKeyData(key: Buffer): Buffer {
  if (key.length === 0) {
    throw new Error("Empty PSBT key");
  }
  const keyReader = new BufferReader(key);
  keyReader.readVarInt(); // Skip type
  return key.subarray(keyReader.position);
}

/**
 * Deserialize a PSBTInput from key-value pairs.
 */
function deserializePSBTInput(pairs: Array<[Buffer, Buffer]>): PSBTInput {
  const input = createPSBTInput();
  const seenKeys = new Set<string>();

  for (const [key, value] of pairs) {
    const keyHex = key.toString("hex");
    const keyType = getKeyType(key);
    const keyData = getKeyData(key);

    switch (keyType) {
      case PSBT_IN_NON_WITNESS_UTXO: {
        if (seenKeys.has(keyHex)) {
          throw new Error("Duplicate key: non-witness UTXO");
        }
        if (keyData.length !== 0) {
          throw new Error("Non-witness UTXO key must have no data");
        }
        const txReader = new BufferReader(value);
        input.nonWitnessUtxo = deserializeTx(txReader);
        seenKeys.add(keyHex);
        break;
      }

      case PSBT_IN_WITNESS_UTXO: {
        if (seenKeys.has(keyHex)) {
          throw new Error("Duplicate key: witness UTXO");
        }
        if (keyData.length !== 0) {
          throw new Error("Witness UTXO key must have no data");
        }
        const utxoReader = new BufferReader(value);
        const utxoValue = utxoReader.readUInt64LE();
        const scriptPubKey = utxoReader.readVarBytes();
        input.witnessUtxo = { value: utxoValue, scriptPubKey };
        seenKeys.add(keyHex);
        break;
      }

      case PSBT_IN_PARTIAL_SIG: {
        if (keyData.length !== 33 && keyData.length !== 65) {
          throw new Error("Invalid partial sig pubkey length");
        }
        const pubkeyHex = keyData.toString("hex");
        if (input.partialSigs.has(pubkeyHex)) {
          throw new Error("Duplicate partial signature");
        }
        input.partialSigs.set(pubkeyHex, {
          pubkey: Buffer.from(keyData),
          signature: Buffer.from(value),
        });
        break;
      }

      case PSBT_IN_SIGHASH: {
        if (seenKeys.has(keyHex)) {
          throw new Error("Duplicate key: sighash type");
        }
        if (keyData.length !== 0) {
          throw new Error("Sighash type key must have no data");
        }
        const sighashReader = new BufferReader(value);
        input.sighashType = sighashReader.readUInt32LE();
        seenKeys.add(keyHex);
        break;
      }

      case PSBT_IN_REDEEMSCRIPT: {
        if (seenKeys.has(keyHex)) {
          throw new Error("Duplicate key: redeem script");
        }
        if (keyData.length !== 0) {
          throw new Error("Redeem script key must have no data");
        }
        input.redeemScript = Buffer.from(value);
        seenKeys.add(keyHex);
        break;
      }

      case PSBT_IN_WITNESSSCRIPT: {
        if (seenKeys.has(keyHex)) {
          throw new Error("Duplicate key: witness script");
        }
        if (keyData.length !== 0) {
          throw new Error("Witness script key must have no data");
        }
        input.witnessScript = Buffer.from(value);
        seenKeys.add(keyHex);
        break;
      }

      case PSBT_IN_BIP32_DERIVATION: {
        if (keyData.length !== 33 && keyData.length !== 65) {
          throw new Error("Invalid BIP32 derivation pubkey length");
        }
        const pubkeyHex = keyData.toString("hex");
        if (input.bip32Derivation.has(pubkeyHex)) {
          throw new Error("Duplicate BIP32 derivation");
        }
        input.bip32Derivation.set(pubkeyHex, {
          pubkey: Buffer.from(keyData),
          origin: deserializeKeyOrigin(value),
        });
        break;
      }

      case PSBT_IN_SCRIPTSIG: {
        if (seenKeys.has(keyHex)) {
          throw new Error("Duplicate key: final scriptSig");
        }
        if (keyData.length !== 0) {
          throw new Error("Final scriptSig key must have no data");
        }
        input.finalScriptSig = Buffer.from(value);
        seenKeys.add(keyHex);
        break;
      }

      case PSBT_IN_SCRIPTWITNESS: {
        if (seenKeys.has(keyHex)) {
          throw new Error("Duplicate key: final witness");
        }
        if (keyData.length !== 0) {
          throw new Error("Final witness key must have no data");
        }
        const witnessReader = new BufferReader(value);
        const witnessCount = witnessReader.readVarInt();
        input.finalScriptWitness = [];
        for (let i = 0; i < witnessCount; i++) {
          input.finalScriptWitness.push(witnessReader.readVarBytes());
        }
        seenKeys.add(keyHex);
        break;
      }

      case PSBT_IN_RIPEMD160: {
        if (keyData.length !== 20) {
          throw new Error("Invalid RIPEMD160 hash length");
        }
        const hashHex = keyData.toString("hex");
        if (input.ripemd160Preimages.has(hashHex)) {
          throw new Error("Duplicate RIPEMD160 preimage");
        }
        input.ripemd160Preimages.set(hashHex, Buffer.from(value));
        break;
      }

      case PSBT_IN_SHA256: {
        if (keyData.length !== 32) {
          throw new Error("Invalid SHA256 hash length");
        }
        const hashHex = keyData.toString("hex");
        if (input.sha256Preimages.has(hashHex)) {
          throw new Error("Duplicate SHA256 preimage");
        }
        input.sha256Preimages.set(hashHex, Buffer.from(value));
        break;
      }

      case PSBT_IN_HASH160: {
        if (keyData.length !== 20) {
          throw new Error("Invalid HASH160 hash length");
        }
        const hashHex = keyData.toString("hex");
        if (input.hash160Preimages.has(hashHex)) {
          throw new Error("Duplicate HASH160 preimage");
        }
        input.hash160Preimages.set(hashHex, Buffer.from(value));
        break;
      }

      case PSBT_IN_HASH256: {
        if (keyData.length !== 32) {
          throw new Error("Invalid HASH256 hash length");
        }
        const hashHex = keyData.toString("hex");
        if (input.hash256Preimages.has(hashHex)) {
          throw new Error("Duplicate HASH256 preimage");
        }
        input.hash256Preimages.set(hashHex, Buffer.from(value));
        break;
      }

      case PSBT_IN_TAP_KEY_SIG: {
        if (seenKeys.has(keyHex)) {
          throw new Error("Duplicate key: taproot key sig");
        }
        if (keyData.length !== 0) {
          throw new Error("Taproot key sig key must have no data");
        }
        if (value.length < 64 || value.length > 65) {
          throw new Error("Invalid taproot signature length");
        }
        input.tapKeySig = Buffer.from(value);
        seenKeys.add(keyHex);
        break;
      }

      case PSBT_IN_TAP_INTERNAL_KEY: {
        if (seenKeys.has(keyHex)) {
          throw new Error("Duplicate key: taproot internal key");
        }
        if (keyData.length !== 0) {
          throw new Error("Taproot internal key key must have no data");
        }
        if (value.length !== 32) {
          throw new Error("Invalid taproot internal key length");
        }
        input.tapInternalKey = Buffer.from(value);
        seenKeys.add(keyHex);
        break;
      }

      case PSBT_IN_TAP_MERKLE_ROOT: {
        if (seenKeys.has(keyHex)) {
          throw new Error("Duplicate key: taproot merkle root");
        }
        if (keyData.length !== 0) {
          throw new Error("Taproot merkle root key must have no data");
        }
        if (value.length !== 32) {
          throw new Error("Invalid taproot merkle root length");
        }
        input.tapMerkleRoot = Buffer.from(value);
        seenKeys.add(keyHex);
        break;
      }

      default:
        // Unknown key type - store as unknown
        if (input.unknown.has(keyHex)) {
          throw new Error("Duplicate unknown key");
        }
        input.unknown.set(keyHex, Buffer.from(value));
        break;
    }
  }

  return input;
}

/**
 * Deserialize a PSBTOutput from key-value pairs.
 */
function deserializePSBTOutput(pairs: Array<[Buffer, Buffer]>): PSBTOutput {
  const output = createPSBTOutput();
  const seenKeys = new Set<string>();

  for (const [key, value] of pairs) {
    const keyHex = key.toString("hex");
    const keyType = getKeyType(key);
    const keyData = getKeyData(key);

    switch (keyType) {
      case PSBT_OUT_REDEEMSCRIPT: {
        if (seenKeys.has(keyHex)) {
          throw new Error("Duplicate key: output redeem script");
        }
        if (keyData.length !== 0) {
          throw new Error("Output redeem script key must have no data");
        }
        output.redeemScript = Buffer.from(value);
        seenKeys.add(keyHex);
        break;
      }

      case PSBT_OUT_WITNESSSCRIPT: {
        if (seenKeys.has(keyHex)) {
          throw new Error("Duplicate key: output witness script");
        }
        if (keyData.length !== 0) {
          throw new Error("Output witness script key must have no data");
        }
        output.witnessScript = Buffer.from(value);
        seenKeys.add(keyHex);
        break;
      }

      case PSBT_OUT_BIP32_DERIVATION: {
        if (keyData.length !== 33 && keyData.length !== 65) {
          throw new Error("Invalid BIP32 derivation pubkey length");
        }
        const pubkeyHex = keyData.toString("hex");
        if (output.bip32Derivation.has(pubkeyHex)) {
          throw new Error("Duplicate BIP32 derivation");
        }
        output.bip32Derivation.set(pubkeyHex, {
          pubkey: Buffer.from(keyData),
          origin: deserializeKeyOrigin(value),
        });
        break;
      }

      case PSBT_OUT_TAP_INTERNAL_KEY: {
        if (seenKeys.has(keyHex)) {
          throw new Error("Duplicate key: output taproot internal key");
        }
        if (keyData.length !== 0) {
          throw new Error("Output taproot internal key key must have no data");
        }
        if (value.length !== 32) {
          throw new Error("Invalid taproot internal key length");
        }
        output.tapInternalKey = Buffer.from(value);
        seenKeys.add(keyHex);
        break;
      }

      case PSBT_OUT_TAP_TREE: {
        if (seenKeys.has(keyHex)) {
          throw new Error("Duplicate key: output taproot tree");
        }
        if (keyData.length !== 0) {
          throw new Error("Output taproot tree key must have no data");
        }
        const treeReader = new BufferReader(value);
        output.tapTree = [];
        while (treeReader.remaining > 0) {
          const depth = treeReader.readUInt8();
          const leafVersion = treeReader.readUInt8();
          const script = treeReader.readVarBytes();
          output.tapTree.push({ depth, leafVersion, script });
        }
        seenKeys.add(keyHex);
        break;
      }

      default:
        // Unknown key type - store as unknown
        if (output.unknown.has(keyHex)) {
          throw new Error("Duplicate unknown key");
        }
        output.unknown.set(keyHex, Buffer.from(value));
        break;
    }
  }

  return output;
}

/**
 * Deserialize a PSBT from binary format.
 */
export function deserializePSBT(data: Buffer): PSBT {
  if (data.length > PSBT_MAX_FILE_SIZE) {
    throw new Error(`PSBT too large: ${data.length} bytes (max ${PSBT_MAX_FILE_SIZE})`);
  }

  const reader = new BufferReader(data);

  // Check magic bytes
  const magic = reader.readBytes(5);
  if (!magic.equals(PSBT_MAGIC)) {
    throw new Error("Invalid PSBT magic bytes");
  }

  // Read global key-value pairs
  const globalPairs = readKeyValuePairs(reader);

  // Parse global data
  let tx: Transaction | undefined;
  const xpubs = new Map<string, { xpub: Buffer; origin: KeyOriginInfo }>();
  let version: number | undefined;
  const unknown = new Map<string, Buffer>();
  const seenGlobalKeys = new Set<string>();

  for (const [key, value] of globalPairs) {
    const keyHex = key.toString("hex");
    const keyType = getKeyType(key);
    const keyData = getKeyData(key);

    switch (keyType) {
      case PSBT_GLOBAL_UNSIGNED_TX: {
        if (seenGlobalKeys.has(keyHex)) {
          throw new Error("Duplicate key: unsigned tx");
        }
        if (keyData.length !== 0) {
          throw new Error("Unsigned tx key must have no data");
        }
        const txReader = new BufferReader(value);
        tx = deserializeTx(txReader);

        // Verify all inputs have empty scriptSig and witness
        for (const input of tx.inputs) {
          if (input.scriptSig.length > 0 || input.witness.length > 0) {
            throw new Error("Unsigned tx must have empty scriptSigs and witnesses");
          }
        }
        seenGlobalKeys.add(keyHex);
        break;
      }

      case PSBT_GLOBAL_XPUB: {
        // Key data should be 78 bytes (BIP32 extended key)
        if (keyData.length !== 78) {
          throw new Error("Invalid xpub length");
        }
        const xpubHex = keyData.toString("hex");
        if (xpubs.has(xpubHex)) {
          throw new Error("Duplicate xpub");
        }
        xpubs.set(xpubHex, {
          xpub: Buffer.from(keyData),
          origin: deserializeKeyOrigin(value),
        });
        break;
      }

      case PSBT_GLOBAL_VERSION: {
        if (seenGlobalKeys.has(keyHex)) {
          throw new Error("Duplicate key: PSBT version");
        }
        if (keyData.length !== 0) {
          throw new Error("PSBT version key must have no data");
        }
        const versionReader = new BufferReader(value);
        version = versionReader.readUInt32LE();
        if (version > PSBT_HIGHEST_VERSION) {
          throw new Error(`Unsupported PSBT version: ${version}`);
        }
        seenGlobalKeys.add(keyHex);
        break;
      }

      default:
        // Unknown key type - store as unknown
        if (unknown.has(keyHex)) {
          throw new Error("Duplicate unknown global key");
        }
        unknown.set(keyHex, Buffer.from(value));
        break;
    }
  }

  if (!tx) {
    throw new Error("No unsigned transaction in PSBT");
  }

  // Read inputs
  const inputs: PSBTInput[] = [];
  for (let i = 0; i < tx.inputs.length; i++) {
    const inputPairs = readKeyValuePairs(reader);
    const input = deserializePSBTInput(inputPairs);

    // Validate non-witness UTXO matches outpoint
    if (input.nonWitnessUtxo) {
      const prevTxId = getTxId(input.nonWitnessUtxo);
      if (!prevTxId.equals(tx.inputs[i].prevOut.txid)) {
        throw new Error(`Non-witness UTXO does not match outpoint for input ${i}`);
      }
      if (tx.inputs[i].prevOut.vout >= input.nonWitnessUtxo.outputs.length) {
        throw new Error(`Output index out of range for input ${i}`);
      }
    }

    inputs.push(input);
  }

  if (inputs.length !== tx.inputs.length) {
    throw new Error("Input count mismatch");
  }

  // Read outputs
  const outputs: PSBTOutput[] = [];
  for (let i = 0; i < tx.outputs.length; i++) {
    const outputPairs = readKeyValuePairs(reader);
    outputs.push(deserializePSBTOutput(outputPairs));
  }

  if (outputs.length !== tx.outputs.length) {
    throw new Error("Output count mismatch");
  }

  return {
    tx,
    xpubs,
    inputs,
    outputs,
    version,
    unknown,
  };
}

/**
 * Decode a PSBT from base64 string.
 */
export function decodePSBTBase64(base64: string): PSBT {
  const data = Buffer.from(base64, "base64");
  return deserializePSBT(data);
}

// =============================================================================
// PSBT Operations
// =============================================================================

/**
 * Get the UTXO for a PSBT input.
 */
export function getInputUTXO(psbt: PSBT, inputIndex: number): TxOut | undefined {
  if (inputIndex < 0 || inputIndex >= psbt.inputs.length) {
    return undefined;
  }

  const input = psbt.inputs[inputIndex];
  const txInput = psbt.tx.inputs[inputIndex];

  // Prefer witness UTXO
  if (input.witnessUtxo) {
    return input.witnessUtxo;
  }

  // Fall back to non-witness UTXO
  if (input.nonWitnessUtxo) {
    const vout = txInput.prevOut.vout;
    if (vout < input.nonWitnessUtxo.outputs.length) {
      return input.nonWitnessUtxo.outputs[vout];
    }
  }

  return undefined;
}

/**
 * Check if a PSBT input has been signed.
 */
export function isInputSigned(input: PSBTInput): boolean {
  return (
    input.partialSigs.size > 0 ||
    input.tapKeySig !== undefined ||
    input.finalScriptSig !== undefined ||
    input.finalScriptWitness !== undefined
  );
}

/**
 * Check if a PSBT input is finalized.
 */
export function isInputFinalized(input: PSBTInput): boolean {
  return (
    input.finalScriptSig !== undefined || input.finalScriptWitness !== undefined
  );
}

/**
 * Update a PSBT input with UTXO information.
 *
 * This is part of the UPDATER role.
 */
export function updateInputUTXO(
  psbt: PSBT,
  inputIndex: number,
  utxo: TxOut | Transaction,
  isWitness: boolean = true
): void {
  if (inputIndex < 0 || inputIndex >= psbt.inputs.length) {
    throw new Error(`Invalid input index: ${inputIndex}`);
  }

  const input = psbt.inputs[inputIndex];

  if ("value" in utxo && "scriptPubKey" in utxo) {
    // TxOut for witness UTXO
    if (isWitness) {
      input.witnessUtxo = utxo;
    }
  } else {
    // Full transaction for non-witness UTXO
    input.nonWitnessUtxo = utxo as Transaction;

    // Also extract witness UTXO if script is segwit
    const txInput = psbt.tx.inputs[inputIndex];
    const prevOutput = (utxo as Transaction).outputs[txInput.prevOut.vout];
    if (prevOutput) {
      const scriptPubKey = prevOutput.scriptPubKey;
      // Check if it's a segwit script (OP_0 <20/32 bytes> or OP_1-16 <32 bytes>)
      if (
        scriptPubKey.length === 22 ||
        scriptPubKey.length === 34 ||
        (scriptPubKey.length === 23 && scriptPubKey[0] >= 0x51 && scriptPubKey[0] <= 0x60)
      ) {
        input.witnessUtxo = prevOutput;
      }
    }
  }
}

/**
 * Add a partial signature to a PSBT input.
 *
 * This is part of the SIGNER role.
 */
export function addPartialSignature(
  psbt: PSBT,
  inputIndex: number,
  pubkey: Buffer,
  signature: Buffer
): void {
  if (inputIndex < 0 || inputIndex >= psbt.inputs.length) {
    throw new Error(`Invalid input index: ${inputIndex}`);
  }

  const input = psbt.inputs[inputIndex];

  if (isInputFinalized(input)) {
    throw new Error("Cannot add signature to finalized input");
  }

  const pubkeyHex = pubkey.toString("hex");
  input.partialSigs.set(pubkeyHex, { pubkey, signature });
}

/**
 * Sign a PSBT input with a private key.
 *
 * This is the SIGNER role.
 *
 * @param psbt - The PSBT to sign
 * @param inputIndex - The input index to sign
 * @param privateKey - The private key to sign with
 * @param publicKey - The public key corresponding to the private key
 * @param sighashType - The sighash type (default: SIGHASH_ALL)
 */
export function signPSBTInput(
  psbt: PSBT,
  inputIndex: number,
  privateKey: Buffer,
  publicKey: Buffer,
  sighashType: number = SIGHASH_ALL
): void {
  if (inputIndex < 0 || inputIndex >= psbt.inputs.length) {
    throw new Error(`Invalid input index: ${inputIndex}`);
  }

  const input = psbt.inputs[inputIndex];

  if (isInputFinalized(input)) {
    throw new Error("Cannot sign finalized input");
  }

  const utxo = getInputUTXO(psbt, inputIndex);
  if (!utxo) {
    throw new Error("No UTXO information for input");
  }

  // Determine script type and compute sighash
  const scriptPubKey = utxo.scriptPubKey;
  let sighash: Buffer;

  // Check for P2WPKH: OP_0 <20 bytes>
  if (
    scriptPubKey.length === 22 &&
    scriptPubKey[0] === 0x00 &&
    scriptPubKey[1] === 0x14
  ) {
    // Native P2WPKH
    const pubKeyHash = hash160(publicKey);

    // Verify pubkey matches the scriptPubKey
    if (!scriptPubKey.subarray(2).equals(pubKeyHash)) {
      throw new Error("Public key does not match P2WPKH scriptPubKey");
    }

    // Build script code: OP_DUP OP_HASH160 <pubkeyhash> OP_EQUALVERIFY OP_CHECKSIG
    const scriptCode = Buffer.concat([
      Buffer.from([0x76, 0xa9, 0x14]),
      pubKeyHash,
      Buffer.from([0x88, 0xac]),
    ]);

    sighash = sigHashWitnessV0(psbt.tx, inputIndex, scriptCode, utxo.value, sighashType);
  }
  // Check for P2PKH: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
  else if (
    scriptPubKey.length === 25 &&
    scriptPubKey[0] === 0x76 &&
    scriptPubKey[1] === 0xa9 &&
    scriptPubKey[2] === 0x14 &&
    scriptPubKey[23] === 0x88 &&
    scriptPubKey[24] === 0xac
  ) {
    // Legacy P2PKH
    sighash = sigHashLegacy(psbt.tx, inputIndex, scriptPubKey, sighashType);
  }
  // Check for P2SH-P2WPKH
  else if (
    scriptPubKey.length === 23 &&
    scriptPubKey[0] === 0xa9 &&
    scriptPubKey[1] === 0x14 &&
    scriptPubKey[22] === 0x87 &&
    input.redeemScript
  ) {
    // P2SH-P2WPKH: check if redeem script is P2WPKH
    const redeemScript = input.redeemScript;
    if (
      redeemScript.length === 22 &&
      redeemScript[0] === 0x00 &&
      redeemScript[1] === 0x14
    ) {
      const pubKeyHash = hash160(publicKey);

      // Verify pubkey matches
      if (!redeemScript.subarray(2).equals(pubKeyHash)) {
        throw new Error("Public key does not match P2SH-P2WPKH redeem script");
      }

      // Build script code
      const scriptCode = Buffer.concat([
        Buffer.from([0x76, 0xa9, 0x14]),
        pubKeyHash,
        Buffer.from([0x88, 0xac]),
      ]);

      sighash = sigHashWitnessV0(psbt.tx, inputIndex, scriptCode, utxo.value, sighashType);
    } else {
      throw new Error("Unsupported P2SH script type");
    }
  } else {
    throw new Error("Unsupported script type for signing");
  }

  // Sign
  const signature = ecdsaSign(sighash, privateKey);
  const sigWithType = Buffer.concat([signature, Buffer.from([sighashType])]);

  // Add partial signature
  addPartialSignature(psbt, inputIndex, publicKey, sigWithType);

  // Store sighash type if not already set
  if (input.sighashType === undefined) {
    input.sighashType = sighashType;
  }
}

/**
 * Combine multiple PSBTs with the same underlying transaction.
 *
 * This is the COMBINER role.
 */
export function combinePSBTs(psbts: PSBT[]): PSBT {
  if (psbts.length === 0) {
    throw new Error("No PSBTs to combine");
  }

  if (psbts.length === 1) {
    return psbts[0];
  }

  // Verify all PSBTs have the same transaction
  const baseTxId = getTxId(psbts[0].tx);
  for (let i = 1; i < psbts.length; i++) {
    const txId = getTxId(psbts[i].tx);
    if (!txId.equals(baseTxId)) {
      throw new Error("Cannot combine PSBTs with different transactions");
    }
  }

  // Create combined PSBT starting from the first one
  const result: PSBT = {
    tx: psbts[0].tx,
    xpubs: new Map(psbts[0].xpubs),
    inputs: psbts[0].inputs.map((input) => ({
      ...input,
      partialSigs: new Map(input.partialSigs),
      bip32Derivation: new Map(input.bip32Derivation),
      ripemd160Preimages: new Map(input.ripemd160Preimages),
      sha256Preimages: new Map(input.sha256Preimages),
      hash160Preimages: new Map(input.hash160Preimages),
      hash256Preimages: new Map(input.hash256Preimages),
      unknown: new Map(input.unknown),
    })),
    outputs: psbts[0].outputs.map((output) => ({
      ...output,
      bip32Derivation: new Map(output.bip32Derivation),
      unknown: new Map(output.unknown),
    })),
    version: psbts[0].version,
    unknown: new Map(psbts[0].unknown),
  };

  // Merge data from other PSBTs
  for (let i = 1; i < psbts.length; i++) {
    const psbt = psbts[i];

    // Merge xpubs
    for (const [key, value] of psbt.xpubs) {
      if (!result.xpubs.has(key)) {
        result.xpubs.set(key, value);
      }
    }

    // Merge inputs
    for (let j = 0; j < psbt.inputs.length; j++) {
      const srcInput = psbt.inputs[j];
      const dstInput = result.inputs[j];

      // Merge UTXO info
      if (srcInput.nonWitnessUtxo && !dstInput.nonWitnessUtxo) {
        dstInput.nonWitnessUtxo = srcInput.nonWitnessUtxo;
      }
      if (srcInput.witnessUtxo && !dstInput.witnessUtxo) {
        dstInput.witnessUtxo = srcInput.witnessUtxo;
      }

      // Merge partial signatures
      for (const [key, value] of srcInput.partialSigs) {
        if (!dstInput.partialSigs.has(key)) {
          dstInput.partialSigs.set(key, value);
        }
      }

      // Merge BIP32 derivation
      for (const [key, value] of srcInput.bip32Derivation) {
        if (!dstInput.bip32Derivation.has(key)) {
          dstInput.bip32Derivation.set(key, value);
        }
      }

      // Merge scripts
      if (srcInput.redeemScript && !dstInput.redeemScript) {
        dstInput.redeemScript = srcInput.redeemScript;
      }
      if (srcInput.witnessScript && !dstInput.witnessScript) {
        dstInput.witnessScript = srcInput.witnessScript;
      }

      // Merge finalized data
      if (srcInput.finalScriptSig && !dstInput.finalScriptSig) {
        dstInput.finalScriptSig = srcInput.finalScriptSig;
      }
      if (srcInput.finalScriptWitness && !dstInput.finalScriptWitness) {
        dstInput.finalScriptWitness = srcInput.finalScriptWitness;
      }

      // Merge taproot
      if (srcInput.tapKeySig && !dstInput.tapKeySig) {
        dstInput.tapKeySig = srcInput.tapKeySig;
      }
      if (srcInput.tapInternalKey && !dstInput.tapInternalKey) {
        dstInput.tapInternalKey = srcInput.tapInternalKey;
      }
      if (srcInput.tapMerkleRoot && !dstInput.tapMerkleRoot) {
        dstInput.tapMerkleRoot = srcInput.tapMerkleRoot;
      }

      // Merge preimages
      for (const [key, value] of srcInput.ripemd160Preimages) {
        if (!dstInput.ripemd160Preimages.has(key)) {
          dstInput.ripemd160Preimages.set(key, value);
        }
      }
      for (const [key, value] of srcInput.sha256Preimages) {
        if (!dstInput.sha256Preimages.has(key)) {
          dstInput.sha256Preimages.set(key, value);
        }
      }
      for (const [key, value] of srcInput.hash160Preimages) {
        if (!dstInput.hash160Preimages.has(key)) {
          dstInput.hash160Preimages.set(key, value);
        }
      }
      for (const [key, value] of srcInput.hash256Preimages) {
        if (!dstInput.hash256Preimages.has(key)) {
          dstInput.hash256Preimages.set(key, value);
        }
      }

      // Merge unknown
      for (const [key, value] of srcInput.unknown) {
        if (!dstInput.unknown.has(key)) {
          dstInput.unknown.set(key, value);
        }
      }
    }

    // Merge outputs
    for (let j = 0; j < psbt.outputs.length; j++) {
      const srcOutput = psbt.outputs[j];
      const dstOutput = result.outputs[j];

      if (srcOutput.redeemScript && !dstOutput.redeemScript) {
        dstOutput.redeemScript = srcOutput.redeemScript;
      }
      if (srcOutput.witnessScript && !dstOutput.witnessScript) {
        dstOutput.witnessScript = srcOutput.witnessScript;
      }
      if (srcOutput.tapInternalKey && !dstOutput.tapInternalKey) {
        dstOutput.tapInternalKey = srcOutput.tapInternalKey;
      }
      if (srcOutput.tapTree && !dstOutput.tapTree) {
        dstOutput.tapTree = srcOutput.tapTree;
      }

      for (const [key, value] of srcOutput.bip32Derivation) {
        if (!dstOutput.bip32Derivation.has(key)) {
          dstOutput.bip32Derivation.set(key, value);
        }
      }

      for (const [key, value] of srcOutput.unknown) {
        if (!dstOutput.unknown.has(key)) {
          dstOutput.unknown.set(key, value);
        }
      }
    }

    // Merge global unknown
    for (const [key, value] of psbt.unknown) {
      if (!result.unknown.has(key)) {
        result.unknown.set(key, value);
      }
    }
  }

  return result;
}

/**
 * Finalize a PSBT input by constructing the final scriptSig/witness.
 *
 * This is the FINALIZER role.
 */
export function finalizePSBTInput(psbt: PSBT, inputIndex: number): boolean {
  if (inputIndex < 0 || inputIndex >= psbt.inputs.length) {
    return false;
  }

  const input = psbt.inputs[inputIndex];

  // Already finalized
  if (isInputFinalized(input)) {
    return true;
  }

  const utxo = getInputUTXO(psbt, inputIndex);
  if (!utxo) {
    return false;
  }

  const scriptPubKey = utxo.scriptPubKey;

  // P2WPKH: OP_0 <20 bytes>
  if (
    scriptPubKey.length === 22 &&
    scriptPubKey[0] === 0x00 &&
    scriptPubKey[1] === 0x14
  ) {
    // Need exactly one signature
    if (input.partialSigs.size !== 1) {
      return false;
    }

    const [sig] = input.partialSigs.values();
    input.finalScriptSig = Buffer.alloc(0);
    input.finalScriptWitness = [sig.signature, sig.pubkey];

    // Clear signing data
    clearSigningData(input);
    return true;
  }

  // P2PKH: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
  if (
    scriptPubKey.length === 25 &&
    scriptPubKey[0] === 0x76 &&
    scriptPubKey[1] === 0xa9 &&
    scriptPubKey[2] === 0x14 &&
    scriptPubKey[23] === 0x88 &&
    scriptPubKey[24] === 0xac
  ) {
    // Need exactly one signature
    if (input.partialSigs.size !== 1) {
      return false;
    }

    const [sig] = input.partialSigs.values();

    // Build scriptSig: <sig> <pubkey>
    const sigPush = pushData(sig.signature);
    const pubkeyPush = pushData(sig.pubkey);
    input.finalScriptSig = Buffer.concat([sigPush, pubkeyPush]);
    input.finalScriptWitness = undefined;

    // Clear signing data
    clearSigningData(input);
    return true;
  }

  // P2SH-P2WPKH
  if (
    scriptPubKey.length === 23 &&
    scriptPubKey[0] === 0xa9 &&
    scriptPubKey[1] === 0x14 &&
    scriptPubKey[22] === 0x87 &&
    input.redeemScript
  ) {
    const redeemScript = input.redeemScript;

    // Check if P2WPKH wrapped in P2SH
    if (
      redeemScript.length === 22 &&
      redeemScript[0] === 0x00 &&
      redeemScript[1] === 0x14
    ) {
      if (input.partialSigs.size !== 1) {
        return false;
      }

      const [sig] = input.partialSigs.values();

      // scriptSig: <redeemScript>
      input.finalScriptSig = pushData(redeemScript);
      // witness: <sig> <pubkey>
      input.finalScriptWitness = [sig.signature, sig.pubkey];

      // Clear signing data
      clearSigningData(input);
      return true;
    }
  }

  // Unsupported script type
  return false;
}

/**
 * Clear signing data from a finalized input.
 */
function clearSigningData(input: PSBTInput): void {
  input.partialSigs.clear();
  input.sighashType = undefined;
  input.redeemScript = undefined;
  input.witnessScript = undefined;
  input.bip32Derivation.clear();
  input.ripemd160Preimages.clear();
  input.sha256Preimages.clear();
  input.hash160Preimages.clear();
  input.hash256Preimages.clear();
  input.tapKeySig = undefined;
  input.tapInternalKey = undefined;
  input.tapMerkleRoot = undefined;
}

/**
 * Push data with appropriate opcode.
 */
function pushData(data: Buffer): Buffer {
  if (data.length < 0x4c) {
    return Buffer.concat([Buffer.from([data.length]), data]);
  } else if (data.length <= 0xff) {
    return Buffer.concat([Buffer.from([0x4c, data.length]), data]);
  } else if (data.length <= 0xffff) {
    const lenBuf = Buffer.alloc(2);
    lenBuf.writeUInt16LE(data.length);
    return Buffer.concat([Buffer.from([0x4d]), lenBuf, data]);
  } else {
    const lenBuf = Buffer.alloc(4);
    lenBuf.writeUInt32LE(data.length);
    return Buffer.concat([Buffer.from([0x4e]), lenBuf, data]);
  }
}

/**
 * Finalize all inputs in a PSBT.
 *
 * @returns true if all inputs were finalized
 */
export function finalizePSBT(psbt: PSBT): boolean {
  let allFinalized = true;

  for (let i = 0; i < psbt.inputs.length; i++) {
    if (!finalizePSBTInput(psbt, i)) {
      allFinalized = false;
    }
  }

  return allFinalized;
}

/**
 * Extract a fully signed transaction from a finalized PSBT.
 *
 * This is the EXTRACTOR role.
 */
export function extractTransaction(psbt: PSBT): Transaction {
  // Verify all inputs are finalized
  for (let i = 0; i < psbt.inputs.length; i++) {
    if (!isInputFinalized(psbt.inputs[i])) {
      throw new Error(`Input ${i} is not finalized`);
    }
  }

  // Build the signed transaction
  const inputs: TxIn[] = psbt.tx.inputs.map((input, i) => {
    const psbtInput = psbt.inputs[i];
    return {
      prevOut: input.prevOut,
      scriptSig: psbtInput.finalScriptSig || Buffer.alloc(0),
      sequence: input.sequence,
      witness: psbtInput.finalScriptWitness || [],
    };
  });

  return {
    version: psbt.tx.version,
    inputs,
    outputs: psbt.tx.outputs,
    lockTime: psbt.tx.lockTime,
  };
}

/**
 * Analyze a PSBT to determine its state and next steps.
 */
export function analyzePSBT(psbt: PSBT): PSBTAnalysis {
  const inputAnalysis: PSBTAnalysis["inputAnalysis"] = [];
  let signedInputs = 0;
  let finalizedInputs = 0;
  let totalInputValue = 0n;
  let hasAllUtxos = true;

  for (let i = 0; i < psbt.inputs.length; i++) {
    const input = psbt.inputs[i];
    const utxo = getInputUTXO(psbt, i);

    const isFinal = isInputFinalized(input);
    const hasSig = isInputSigned(input);
    const sigCount = input.partialSigs.size + (input.tapKeySig ? 1 : 0);

    // For simple P2PKH/P2WPKH, only 1 signature needed
    // For multisig, would need to analyze the script
    const sigsNeeded = 1;

    inputAnalysis.push({
      index: i,
      hasSig,
      isFinalized: isFinal,
      signaturesNeeded: sigsNeeded,
      signatureCount: sigCount,
      utxoAmount: utxo?.value,
    });

    if (hasSig) signedInputs++;
    if (isFinal) finalizedInputs++;

    if (utxo) {
      totalInputValue += utxo.value;
    } else {
      hasAllUtxos = false;
    }
  }

  const isComplete = finalizedInputs === psbt.inputs.length;

  // Calculate estimated fee
  let estimatedFee: bigint | undefined;
  if (hasAllUtxos) {
    let totalOutputValue = 0n;
    for (const output of psbt.tx.outputs) {
      totalOutputValue += output.value;
    }
    estimatedFee = totalInputValue - totalOutputValue;
  }

  // Determine next roles
  const nextRoles: PSBTRole[] = [];

  if (!isComplete) {
    // Can still update if missing UTXO info
    if (!hasAllUtxos) {
      nextRoles.push(PSBTRole.UPDATER);
    }

    // Can sign if has UTXO info but not all signed
    if (hasAllUtxos && signedInputs < psbt.inputs.length) {
      nextRoles.push(PSBTRole.SIGNER);
    }

    // Can combine if partially signed
    if (signedInputs > 0) {
      nextRoles.push(PSBTRole.COMBINER);
    }

    // Can finalize if all inputs signed
    if (signedInputs === psbt.inputs.length && finalizedInputs < psbt.inputs.length) {
      nextRoles.push(PSBTRole.FINALIZER);
    }
  }

  // Can extract if complete
  if (isComplete) {
    nextRoles.push(PSBTRole.EXTRACTOR);
  }

  return {
    inputCount: psbt.inputs.length,
    outputCount: psbt.outputs.length,
    signedInputs,
    finalizedInputs,
    isComplete,
    estimatedFee,
    inputAnalysis,
    nextRoles,
  };
}

/**
 * Convert a legacy signed transaction to a PSBT.
 *
 * This extracts scriptSig/witness as finalized data.
 */
export function convertToPSBT(tx: Transaction): PSBT {
  // Create unsigned version of the transaction
  const unsignedTx: Transaction = {
    version: tx.version,
    inputs: tx.inputs.map((input) => ({
      prevOut: input.prevOut,
      scriptSig: Buffer.alloc(0),
      sequence: input.sequence,
      witness: [],
    })),
    outputs: tx.outputs,
    lockTime: tx.lockTime,
  };

  // Create PSBT
  const psbt = createPSBT(unsignedTx);

  // Add finalized data from original transaction
  for (let i = 0; i < tx.inputs.length; i++) {
    const input = tx.inputs[i];
    const psbtInput = psbt.inputs[i];

    if (input.scriptSig.length > 0) {
      psbtInput.finalScriptSig = input.scriptSig;
    }

    if (input.witness.length > 0) {
      psbtInput.finalScriptWitness = input.witness;
    }
  }

  return psbt;
}

// =============================================================================
// Decode PSBT (for RPC)
// =============================================================================

/**
 * Decoded PSBT representation for RPC output.
 */
export interface DecodedPSBT {
  tx: {
    txid: string;
    version: number;
    locktime: number;
    vin: Array<{
      txid: string;
      vout: number;
      scriptSig: { asm: string; hex: string };
      sequence: number;
    }>;
    vout: Array<{
      value: number;
      n: number;
      scriptPubKey: { asm: string; hex: string; type: string };
    }>;
  };
  unknown: Record<string, string>;
  inputs: Array<{
    witness_utxo?: { amount: number; scriptPubKey: { asm: string; hex: string; type: string } };
    non_witness_utxo?: { txid: string };
    partial_signatures?: Record<string, string>;
    sighash?: string;
    redeem_script?: { asm: string; hex: string };
    witness_script?: { asm: string; hex: string };
    bip32_derivs?: Array<{ pubkey: string; master_fingerprint: string; path: string }>;
    final_scriptSig?: { asm: string; hex: string };
    final_scriptwitness?: string[];
    unknown?: Record<string, string>;
  }>;
  outputs: Array<{
    redeem_script?: { asm: string; hex: string };
    witness_script?: { asm: string; hex: string };
    bip32_derivs?: Array<{ pubkey: string; master_fingerprint: string; path: string }>;
    unknown?: Record<string, string>;
  }>;
  fee?: number;
}

/**
 * Simple script disassembly (hex to asm).
 */
function disassembleScript(script: Buffer): string {
  // Very basic disassembly - just return hex for now
  // A full implementation would decode opcodes
  return script.toString("hex");
}

/**
 * Get script type from scriptPubKey.
 */
function getScriptType(script: Buffer): string {
  if (script.length === 22 && script[0] === 0x00 && script[1] === 0x14) {
    return "witness_v0_keyhash";
  }
  if (script.length === 34 && script[0] === 0x00 && script[1] === 0x20) {
    return "witness_v0_scripthash";
  }
  if (script.length === 34 && script[0] === 0x51 && script[1] === 0x20) {
    return "witness_v1_taproot";
  }
  if (
    script.length === 25 &&
    script[0] === 0x76 &&
    script[1] === 0xa9 &&
    script[2] === 0x14 &&
    script[23] === 0x88 &&
    script[24] === 0xac
  ) {
    return "pubkeyhash";
  }
  if (
    script.length === 23 &&
    script[0] === 0xa9 &&
    script[1] === 0x14 &&
    script[22] === 0x87
  ) {
    return "scripthash";
  }
  return "nonstandard";
}

/**
 * Format derivation path from indices.
 */
function formatDerivationPath(origin: KeyOriginInfo): string {
  const parts = origin.path.map((index) => {
    if (index >= 0x80000000) {
      return `${index - 0x80000000}'`;
    }
    return index.toString();
  });
  return "m/" + parts.join("/");
}

/**
 * Decode a PSBT for RPC output.
 */
export function decodePSBT(psbt: PSBT): DecodedPSBT {
  const txid = getTxId(psbt.tx).reverse().toString("hex");

  const vin = psbt.tx.inputs.map((input) => ({
    txid: Buffer.from(input.prevOut.txid).reverse().toString("hex"),
    vout: input.prevOut.vout,
    scriptSig: {
      asm: disassembleScript(input.scriptSig),
      hex: input.scriptSig.toString("hex"),
    },
    sequence: input.sequence,
  }));

  const vout = psbt.tx.outputs.map((output, n) => ({
    value: Number(output.value) / 100_000_000,
    n,
    scriptPubKey: {
      asm: disassembleScript(output.scriptPubKey),
      hex: output.scriptPubKey.toString("hex"),
      type: getScriptType(output.scriptPubKey),
    },
  }));

  const unknown: Record<string, string> = {};
  for (const [key, value] of psbt.unknown) {
    unknown[key] = value.toString("hex");
  }

  const inputs = psbt.inputs.map((input) => {
    const result: DecodedPSBT["inputs"][0] = {};

    if (input.witnessUtxo) {
      result.witness_utxo = {
        amount: Number(input.witnessUtxo.value) / 100_000_000,
        scriptPubKey: {
          asm: disassembleScript(input.witnessUtxo.scriptPubKey),
          hex: input.witnessUtxo.scriptPubKey.toString("hex"),
          type: getScriptType(input.witnessUtxo.scriptPubKey),
        },
      };
    }

    if (input.nonWitnessUtxo) {
      result.non_witness_utxo = {
        txid: getTxId(input.nonWitnessUtxo).reverse().toString("hex"),
      };
    }

    if (input.partialSigs.size > 0) {
      result.partial_signatures = {};
      for (const [pubkeyHex, { signature }] of input.partialSigs) {
        result.partial_signatures[pubkeyHex] = signature.toString("hex");
      }
    }

    if (input.sighashType !== undefined) {
      const sighashNames: Record<number, string> = {
        1: "ALL",
        2: "NONE",
        3: "SINGLE",
        0x81: "ALL|ANYONECANPAY",
        0x82: "NONE|ANYONECANPAY",
        0x83: "SINGLE|ANYONECANPAY",
      };
      result.sighash = sighashNames[input.sighashType] ?? `UNKNOWN(${input.sighashType})`;
    }

    if (input.redeemScript) {
      result.redeem_script = {
        asm: disassembleScript(input.redeemScript),
        hex: input.redeemScript.toString("hex"),
      };
    }

    if (input.witnessScript) {
      result.witness_script = {
        asm: disassembleScript(input.witnessScript),
        hex: input.witnessScript.toString("hex"),
      };
    }

    if (input.bip32Derivation.size > 0) {
      result.bip32_derivs = [];
      for (const { pubkey, origin } of input.bip32Derivation.values()) {
        result.bip32_derivs.push({
          pubkey: pubkey.toString("hex"),
          master_fingerprint: origin.fingerprint.toString("hex"),
          path: formatDerivationPath(origin),
        });
      }
    }

    if (input.finalScriptSig) {
      result.final_scriptSig = {
        asm: disassembleScript(input.finalScriptSig),
        hex: input.finalScriptSig.toString("hex"),
      };
    }

    if (input.finalScriptWitness) {
      result.final_scriptwitness = input.finalScriptWitness.map((item) =>
        item.toString("hex")
      );
    }

    if (input.unknown.size > 0) {
      result.unknown = {};
      for (const [key, value] of input.unknown) {
        result.unknown[key] = value.toString("hex");
      }
    }

    return result;
  });

  const outputs = psbt.outputs.map((output) => {
    const result: DecodedPSBT["outputs"][0] = {};

    if (output.redeemScript) {
      result.redeem_script = {
        asm: disassembleScript(output.redeemScript),
        hex: output.redeemScript.toString("hex"),
      };
    }

    if (output.witnessScript) {
      result.witness_script = {
        asm: disassembleScript(output.witnessScript),
        hex: output.witnessScript.toString("hex"),
      };
    }

    if (output.bip32Derivation.size > 0) {
      result.bip32_derivs = [];
      for (const { pubkey, origin } of output.bip32Derivation.values()) {
        result.bip32_derivs.push({
          pubkey: pubkey.toString("hex"),
          master_fingerprint: origin.fingerprint.toString("hex"),
          path: formatDerivationPath(origin),
        });
      }
    }

    if (output.unknown.size > 0) {
      result.unknown = {};
      for (const [key, value] of output.unknown) {
        result.unknown[key] = value.toString("hex");
      }
    }

    return result;
  });

  // Calculate fee
  let fee: number | undefined;
  const analysis = analyzePSBT(psbt);
  if (analysis.estimatedFee !== undefined) {
    fee = Number(analysis.estimatedFee) / 100_000_000;
  }

  return {
    tx: {
      txid,
      version: psbt.tx.version,
      locktime: psbt.tx.lockTime,
      vin,
      vout,
    },
    unknown,
    inputs,
    outputs,
    fee,
  };
}
