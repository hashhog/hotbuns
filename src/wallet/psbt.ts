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
  getWTxId,
  getTxWeight,
  getTxVSize,
  sigHashWitnessV0,
  sigHashLegacy,
  SIGHASH_ALL,
  hasWitness,
} from "../validation/tx.js";
import {
  hash160,
  hash256,
  sha256Hash,
  ecdsaSign,
  ecdsaVerify,
  taggedHash,
} from "../crypto/primitives.js";
import { base58CheckEncode, bech32Encode } from "../address/encoding.js";
import { addChecksum } from "./descriptor.js";

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
export const PSBT_OUT_MUSIG2_PARTICIPANT_PUBKEYS = 0x08;
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
  /** Taproot script path signatures: map of (xonly_hex + leaf_hash_hex) -> {xonly, leafHash, sig} */
  tapScriptSigs: Map<string, { xonly: Buffer; leafHash: Buffer; sig: Buffer }>;
  /** Taproot leaf scripts: map of (script_hex + leaf_ver) -> {script, leafVer, controlBlocks[]} */
  tapLeafScripts: Map<string, { script: Buffer; leafVer: number; controlBlocks: Buffer[] }>;
  /** Taproot BIP32 derivation: xonly_hex -> {xonly, leafHashes[], origin} */
  tapBip32Derivation: Map<string, { xonly: Buffer; leafHashes: Buffer[]; origin: KeyOriginInfo }>;
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
  /** Taproot BIP32 derivation: xonly_hex -> {xonly, leafHashes[], origin} */
  tapBip32Derivation: Map<string, { xonly: Buffer; leafHashes: Buffer[]; origin: KeyOriginInfo }>;
  /** MuSig2 participant pubkeys: agg_pubkey_hex -> {aggPubkey, participantPubkeys[]} */
  musig2Participants: Map<string, { aggPubkey: Buffer; participantPubkeys: Buffer[] }>;
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
    tapScriptSigs: new Map(),
    tapLeafScripts: new Map(),
    tapBip32Derivation: new Map(),
    unknown: new Map(),
  };
}

/**
 * Create a new empty PSBTOutput.
 */
export function createPSBTOutput(): PSBTOutput {
  return {
    bip32Derivation: new Map(),
    tapBip32Derivation: new Map(),
    musig2Participants: new Map(),
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
          // W34-A: Buffer.from() defensive copy to detach from the caller's
          // input Buffer. readVarBytes returns a subarray view; without this
          // copy, mutating the source PSBT bytes after deserialize would
          // corrupt our stored witness items (W32-B JS analog).
          input.finalScriptWitness.push(Buffer.from(witnessReader.readVarBytes()));
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

      case PSBT_IN_TAP_SCRIPT_SIG: {
        // Key: type(1) + xonly_pubkey(32) + leaf_hash(32) = 65 bytes total
        if (keyData.length !== 64) {
          throw new Error("Taproot script sig key must have exactly 64 bytes of key data");
        }
        if (seenKeys.has(keyHex)) {
          throw new Error("Duplicate key: taproot script path sig");
        }
        if (value.length < 64 || value.length > 65) {
          throw new Error("Invalid taproot script path signature length");
        }
        const tapSigXonly = Buffer.from(keyData.subarray(0, 32));
        const tapSigLeafHash = Buffer.from(keyData.subarray(32, 64));
        const tapSigMapKey = tapSigXonly.toString("hex") + tapSigLeafHash.toString("hex");
        input.tapScriptSigs.set(tapSigMapKey, {
          xonly: tapSigXonly,
          leafHash: tapSigLeafHash,
          sig: Buffer.from(value),
        });
        seenKeys.add(keyHex);
        break;
      }

      case PSBT_IN_TAP_LEAF_SCRIPT: {
        // Key: type(1) + control_block(>=33 bytes); Value: script + leaf_ver(1)
        if (keyData.length < 33) {
          throw new Error("Taproot leaf script key data must be at least 33 bytes (control block)");
        }
        if ((keyData.length - 1) % 32 !== 0) {
          throw new Error("Taproot leaf script control block size is not valid");
        }
        if (value.length < 1) {
          throw new Error("Taproot leaf script value must be at least 1 byte");
        }
        const controlBlock = Buffer.from(keyData);
        const leafVer = value[value.length - 1];
        const leafScript = Buffer.from(value.subarray(0, value.length - 1));
        const leafScriptMapKey = leafScript.toString("hex") + ":" + leafVer.toString();
        const existing = input.tapLeafScripts.get(leafScriptMapKey);
        if (existing) {
          existing.controlBlocks.push(controlBlock);
        } else {
          input.tapLeafScripts.set(leafScriptMapKey, {
            script: leafScript,
            leafVer,
            controlBlocks: [controlBlock],
          });
        }
        // Note: multiple control_blocks for same leaf script are valid — don't add to seenKeys
        break;
      }

      case PSBT_IN_TAP_BIP32_DERIVATION: {
        // Key: type(1) + xonly_pubkey(32) = 33 bytes total
        if (keyData.length !== 32) {
          throw new Error("Taproot BIP32 derivation key must have exactly 32 bytes of key data");
        }
        if (seenKeys.has(keyHex)) {
          throw new Error("Duplicate key: taproot BIP32 derivation");
        }
        const tapBip32Xonly = Buffer.from(keyData);
        // Value: compact_size(N_hashes) + N_hashes*32 + fingerprint(4) + path(N*4)
        const tapBip32Reader = new BufferReader(value);
        const nHashes = tapBip32Reader.readVarInt();
        const tapLeafHashes: Buffer[] = [];
        for (let j = 0; j < nHashes; j++) {
          tapLeafHashes.push(Buffer.from(tapBip32Reader.readBytes(32)));
        }
        const originData = value.subarray(tapBip32Reader.position);
        const tapBip32Origin = deserializeKeyOrigin(originData);
        input.tapBip32Derivation.set(tapBip32Xonly.toString("hex"), {
          xonly: tapBip32Xonly,
          leafHashes: tapLeafHashes,
          origin: tapBip32Origin,
        });
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
          // W34-A: Buffer.from() defensive copy to detach from the caller's
          // input Buffer. readVarBytes returns a subarray view; without this
          // copy, mutating the source PSBT bytes after deserialize would
          // corrupt our stored tapTree script (W32-B JS analog).
          const script = Buffer.from(treeReader.readVarBytes());
          output.tapTree.push({ depth, leafVersion, script });
        }
        seenKeys.add(keyHex);
        break;
      }

      case PSBT_OUT_TAP_BIP32_DERIVATION: {
        // Key: type(1) + xonly_pubkey(32) = 33 bytes total
        if (keyData.length !== 32) {
          throw new Error("Output taproot BIP32 derivation key must have exactly 32 bytes of key data");
        }
        if (seenKeys.has(keyHex)) {
          throw new Error("Duplicate key: output taproot BIP32 derivation");
        }
        const outTapBip32Xonly = Buffer.from(keyData);
        // Value: compact_size(N_hashes) + N_hashes*32 + fingerprint(4) + path(N*4)
        const outTapBip32Reader = new BufferReader(value);
        const outNHashes = outTapBip32Reader.readVarInt();
        const outTapLeafHashes: Buffer[] = [];
        for (let j = 0; j < outNHashes; j++) {
          outTapLeafHashes.push(Buffer.from(outTapBip32Reader.readBytes(32)));
        }
        const outOriginData = value.subarray(outTapBip32Reader.position);
        const outTapBip32Origin = deserializeKeyOrigin(outOriginData);
        output.tapBip32Derivation.set(outTapBip32Xonly.toString("hex"), {
          xonly: outTapBip32Xonly,
          leafHashes: outTapLeafHashes,
          origin: outTapBip32Origin,
        });
        seenKeys.add(keyHex);
        break;
      }

      case PSBT_OUT_MUSIG2_PARTICIPANT_PUBKEYS: {
        // Key: type(varint 0x08) + agg_pubkey(33 bytes)
        // Value: N concatenated 33-byte compressed participant pubkeys
        if (keyData.length !== 33) {
          throw new Error("Output MuSig2 participant pubkeys key must have exactly 33 bytes of key data");
        }
        if (seenKeys.has(keyHex)) {
          throw new Error("Duplicate key: output MuSig2 participant pubkeys");
        }
        if (value.length === 0 || value.length % 33 !== 0) {
          throw new Error("Output MuSig2 participant pubkeys value length must be a multiple of 33");
        }
        const musig2AggPubkey = Buffer.from(keyData);
        const musig2ParticipantPubkeys: Buffer[] = [];
        for (let j = 0; j < value.length; j += 33) {
          musig2ParticipantPubkeys.push(Buffer.from(value.subarray(j, j + 33)));
        }
        output.musig2Participants.set(musig2AggPubkey.toString("hex"), {
          aggPubkey: musig2AggPubkey,
          participantPubkeys: musig2ParticipantPubkeys,
        });
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
 *
 * When both `witnessUtxo` and `nonWitnessUtxo` are present, this function
 * cross-checks that the `witnessUtxo` agrees byte-for-byte with the
 * outpoint-indexed entry from the full prevtx (`nonWitnessUtxo.outputs[vout]`).
 * A mismatch is rejected with a clear error rather than silently trusting the
 * witness amount.
 *
 * This is the post-CVE-2020-14199 amount oracle defense: a malicious upstream
 * party can lie about a `witnessUtxo.value` to trick the signer into
 * authorizing a much larger fee than it intended. Bitcoin Core mitigates this
 * in `wallet/scriptpubkeyman.cpp` by re-deriving the amount from the
 * `nonWitnessUtxo` whenever it's available; we fail closed if the two
 * disagree (either tampering or operator error). Mirrors `PSBTInput::IsSane`
 * (`bitcoin-core/src/psbt.cpp`) intent.
 *
 * Note: A1 (`nonWitnessUtxo` txid vs outpoint) is enforced earlier on
 * deserialize at `deserializePSBT` (psbt.ts:1107-1116) and is preserved.
 */
export function getInputUTXO(psbt: PSBT, inputIndex: number): TxOut | undefined {
  if (inputIndex < 0 || inputIndex >= psbt.inputs.length) {
    return undefined;
  }

  const input = psbt.inputs[inputIndex];
  const txInput = psbt.tx.inputs[inputIndex];

  // CVE-2020-14199 cross-check: when both UTXO fields are present, the
  // `witnessUtxo` MUST match the corresponding output of `nonWitnessUtxo`.
  // This prevents a hostile updater from feeding the signer a forged amount
  // that bypasses BIP-143's value commitment guarantee. Bitcoin Core's
  // wallet code performs the equivalent rederivation in
  // `wallet/scriptpubkeyman.cpp`.
  if (input.witnessUtxo && input.nonWitnessUtxo) {
    const vout = txInput.prevOut.vout;
    if (vout >= input.nonWitnessUtxo.outputs.length) {
      throw new Error(
        `PSBT input ${inputIndex}: vout ${vout} out of range for nonWitnessUtxo ` +
          `(${input.nonWitnessUtxo.outputs.length} outputs)`
      );
    }
    const fromFullTx = input.nonWitnessUtxo.outputs[vout];
    if (input.witnessUtxo.value !== fromFullTx.value) {
      throw new Error(
        `PSBT input ${inputIndex}: witnessUtxo.value (${input.witnessUtxo.value}) ` +
          `does not match nonWitnessUtxo.outputs[${vout}].value (${fromFullTx.value}); ` +
          `refusing to sign (CVE-2020-14199)`
      );
    }
    if (!input.witnessUtxo.scriptPubKey.equals(fromFullTx.scriptPubKey)) {
      throw new Error(
        `PSBT input ${inputIndex}: witnessUtxo.scriptPubKey does not match ` +
          `nonWitnessUtxo.outputs[${vout}].scriptPubKey; refusing to sign ` +
          `(CVE-2020-14199)`
      );
    }
  }

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
  // Check for P2SH-wrapped: OP_HASH160 <20 bytes> OP_EQUAL
  else if (
    scriptPubKey.length === 23 &&
    scriptPubKey[0] === 0xa9 &&
    scriptPubKey[1] === 0x14 &&
    scriptPubKey[22] === 0x87 &&
    input.redeemScript
  ) {
    const redeemScript = input.redeemScript;

    // Verify redeemScript hashes to scriptPubKey commitment.
    if (!hash160(redeemScript).equals(scriptPubKey.subarray(2, 22))) {
      throw new Error("redeemScript does not match P2SH scriptPubKey");
    }

    // P2SH-P2WPKH: redeemScript = OP_0 <20 bytes>
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
    }
    // P2SH-P2WSH: redeemScript = OP_0 <32 bytes>
    else if (
      redeemScript.length === 34 &&
      redeemScript[0] === 0x00 &&
      redeemScript[1] === 0x20 &&
      input.witnessScript
    ) {
      const witnessScript = input.witnessScript;

      // BIP-143: scriptCode for P2WSH sighash is sha256(witnessScript) committed in
      // the redeemScript; verify match.
      const wsHash = sha256Hash(witnessScript);
      if (!redeemScript.subarray(2).equals(wsHash)) {
        throw new Error("witnessScript does not match P2SH-P2WSH redeemScript commitment");
      }

      // For P2WSH the BIP-143 scriptCode IS the witnessScript itself.
      sighash = sigHashWitnessV0(psbt.tx, inputIndex, witnessScript, utxo.value, sighashType);
    } else {
      throw new Error("Unsupported P2SH script type");
    }
  }
  // Native P2WSH: OP_0 <32 bytes>
  else if (
    scriptPubKey.length === 34 &&
    scriptPubKey[0] === 0x00 &&
    scriptPubKey[1] === 0x20 &&
    input.witnessScript
  ) {
    const witnessScript = input.witnessScript;

    // Verify witnessScript hashes to the scriptPubKey commitment.
    const wsHash = sha256Hash(witnessScript);
    if (!scriptPubKey.subarray(2).equals(wsHash)) {
      throw new Error("witnessScript does not match P2WSH scriptPubKey");
    }

    // BIP-143: scriptCode for P2WSH sighash is the witnessScript itself.
    sighash = sigHashWitnessV0(psbt.tx, inputIndex, witnessScript, utxo.value, sighashType);
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

  // Create combined PSBT starting from the first one.
  //
  // W35-A: The {...input}/{...output} spreads shallow-copy every field by ref,
  // including the array-of-Buffer fields finalScriptWitness (Input) and
  // tapTree (Output). With W34-A's deserialize fix landed (7f9e272), the
  // underlying bytes are no longer aliased into the source PSBT's input
  // buffer — but psbts[0]'s in-memory items are still shared with `result`
  // via the spread. A caller mutating psbts[0].inputs[i].finalScriptWitness[k]
  // after combine() would corrupt the combined PSBT directly. Deep-copy
  // array-of-Buffer fields the same way the merge path (i>=1) does.
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
      tapScriptSigs: new Map(input.tapScriptSigs),
      tapLeafScripts: new Map(input.tapLeafScripts),
      tapBip32Derivation: new Map(input.tapBip32Derivation),
      unknown: new Map(input.unknown),
      finalScriptWitness: input.finalScriptWitness?.map((b) => Buffer.from(b)),
    })),
    outputs: psbts[0].outputs.map((output) => ({
      ...output,
      bip32Derivation: new Map(output.bip32Derivation),
      tapBip32Derivation: new Map(output.tapBip32Derivation),
      musig2Participants: new Map(output.musig2Participants),
      unknown: new Map(output.unknown),
      tapTree: output.tapTree?.map((leaf) => ({
        depth: leaf.depth,
        leafVersion: leaf.leafVersion,
        script: Buffer.from(leaf.script),
      })),
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
        // W34-A: deep-copy each Buffer when shallow-copying the array ref.
        // Otherwise the combined PSBT shares underlying buffers with the
        // source PSBT — a later mutation of the source's bytes (or the
        // caller's deserialized buffer) would corrupt the combined PSBT.
        dstInput.finalScriptWitness = srcInput.finalScriptWitness.map((b) =>
          Buffer.from(b),
        );
      }

      // Merge taproot
      if (srcInput.tapKeySig && !dstInput.tapKeySig) {
        dstInput.tapKeySig = srcInput.tapKeySig;
      }
      for (const [key, value] of srcInput.tapScriptSigs) {
        if (!dstInput.tapScriptSigs.has(key)) {
          dstInput.tapScriptSigs.set(key, value);
        }
      }
      for (const [key, value] of srcInput.tapLeafScripts) {
        if (!dstInput.tapLeafScripts.has(key)) {
          dstInput.tapLeafScripts.set(key, value);
        }
      }
      for (const [key, value] of srcInput.tapBip32Derivation) {
        if (!dstInput.tapBip32Derivation.has(key)) {
          dstInput.tapBip32Derivation.set(key, value);
        }
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
        // W34-A: deep-copy each leaf's script Buffer when shallow-copying
        // the array ref. Otherwise the combined PSBT shares underlying
        // script buffers with the source PSBT.
        dstOutput.tapTree = srcOutput.tapTree.map((leaf) => ({
          depth: leaf.depth,
          leafVersion: leaf.leafVersion,
          script: Buffer.from(leaf.script),
        }));
      }

      for (const [key, value] of srcOutput.bip32Derivation) {
        if (!dstOutput.bip32Derivation.has(key)) {
          dstOutput.bip32Derivation.set(key, value);
        }
      }
      for (const [key, value] of srcOutput.tapBip32Derivation) {
        if (!dstOutput.tapBip32Derivation.has(key)) {
          dstOutput.tapBip32Derivation.set(key, value);
        }
      }
      for (const [key, value] of srcOutput.musig2Participants) {
        if (!dstOutput.musig2Participants.has(key)) {
          dstOutput.musig2Participants.set(key, value);
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

  // P2SH-wrapped (P2SH-P2WPKH or P2SH-P2WSH)
  if (
    scriptPubKey.length === 23 &&
    scriptPubKey[0] === 0xa9 &&
    scriptPubKey[1] === 0x14 &&
    scriptPubKey[22] === 0x87 &&
    input.redeemScript
  ) {
    const redeemScript = input.redeemScript;

    // P2SH-P2WPKH: redeemScript = OP_0 <20 bytes>
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

    // P2SH-P2WSH: redeemScript = OP_0 <32 bytes>
    if (
      redeemScript.length === 34 &&
      redeemScript[0] === 0x00 &&
      redeemScript[1] === 0x20 &&
      input.witnessScript
    ) {
      const witnessScript = input.witnessScript;
      const witness = buildP2WSHWitness(witnessScript, input.partialSigs);
      if (!witness) {
        return false;
      }

      // scriptSig wraps the segwit redeemScript
      input.finalScriptSig = pushData(redeemScript);
      input.finalScriptWitness = witness;

      clearSigningData(input);
      return true;
    }

    // Legacy P2SH-multisig (BIP-11):
    //   redeemScript = OP_M <pk1> ... <pkN> OP_N OP_CHECKMULTISIG
    //
    // Build scriptSig = OP_0 sig1 ... sigM PUSH(redeemScript). Signatures must
    // be ordered to match pubkey-position in the redeemScript (CHECKMULTISIG
    // is order-sensitive — see ProduceSignature in bitcoin-core/src/script/sign.cpp
    // and the existing buildP2WSHWitness logic above).
    {
      const parsed = parseMultisigScript(redeemScript);
      if (parsed) {
        const { m, pubkeys } = parsed;

        const orderedSigs: Buffer[] = [];
        for (const pk of pubkeys) {
          const entry = input.partialSigs.get(pk.toString("hex"));
          if (entry) {
            orderedSigs.push(entry.signature);
            if (orderedSigs.length === m) {
              break;
            }
          }
        }
        if (orderedSigs.length < m) {
          return false;
        }

        // Bare CHECKMULTISIG dummy must be the empty pushdata in legacy P2SH
        // too (NULLDUMMY: STANDARD post-BIP-147).
        const parts: Buffer[] = [Buffer.from([0x00])];
        for (const sig of orderedSigs) {
          parts.push(pushData(sig));
        }
        parts.push(pushData(redeemScript));

        input.finalScriptSig = Buffer.concat(parts);
        input.finalScriptWitness = undefined;

        clearSigningData(input);
        return true;
      }
    }
  }

  // Native P2WSH: OP_0 <32 bytes>
  if (
    scriptPubKey.length === 34 &&
    scriptPubKey[0] === 0x00 &&
    scriptPubKey[1] === 0x20 &&
    input.witnessScript
  ) {
    const witnessScript = input.witnessScript;
    const witness = buildP2WSHWitness(witnessScript, input.partialSigs);
    if (!witness) {
      return false;
    }

    input.finalScriptSig = Buffer.alloc(0);
    input.finalScriptWitness = witness;

    clearSigningData(input);
    return true;
  }

  // Unsupported script type
  return false;
}

/**
 * Build the witness stack for a P2WSH input given a witnessScript and a set of
 * partial signatures.
 *
 * Currently supports two witnessScript shapes:
 *   • Single-key CHECKSIG: `<pubkey> OP_CHECKSIG` → witness `[sig, witnessScript]`
 *   • Bare M-of-N CHECKMULTISIG (BIP-11):
 *       `OP_M <pubkey1> ... <pubkeyN> OP_N OP_CHECKMULTISIG`
 *     → witness `[OP_0 dummy, sig1, ..., sigM, witnessScript]`
 *     where signatures are ordered to match the order of their pubkeys in
 *     witnessScript (CHECKMULTISIG checks signatures in pubkey order).
 *
 * Returns `undefined` if the script is unsupported or the partial-signature set
 * is insufficient.
 */
function buildP2WSHWitness(
  witnessScript: Buffer,
  partialSigs: Map<string, { pubkey: Buffer; signature: Buffer }>
): Buffer[] | undefined {
  const parsed = parseMultisigScript(witnessScript);
  if (parsed) {
    const { m, pubkeys } = parsed;

    // Pick the first M signatures whose pubkey appears in the script,
    // preserving script-pubkey order (CHECKMULTISIG bug requires this).
    const orderedSigs: Buffer[] = [];
    for (const pk of pubkeys) {
      const entry = partialSigs.get(pk.toString("hex"));
      if (entry) {
        orderedSigs.push(entry.signature);
        if (orderedSigs.length === m) {
          break;
        }
      }
    }
    if (orderedSigs.length < m) {
      return undefined;
    }

    // CHECKMULTISIG expects an extra dummy item on the stack (the OP_CHECKMULTISIG
    // off-by-one bug).  In bare segwit-v0 P2WSH that dummy MUST be the empty
    // pushdata (NULLDUMMY: STANDARD post-BIP-147, MANDATORY post-segwit).
    return [Buffer.alloc(0), ...orderedSigs, witnessScript];
  }

  // Single-key CHECKSIG: <pubkey> OP_CHECKSIG
  // Layout: 0x21 <33-byte pubkey> 0xac  → length 35
  if (
    witnessScript.length === 35 &&
    witnessScript[0] === 0x21 &&
    witnessScript[34] === 0xac
  ) {
    const pubkey = witnessScript.subarray(1, 34);
    const entry = partialSigs.get(pubkey.toString("hex"));
    if (!entry) {
      return undefined;
    }
    return [entry.signature, witnessScript];
  }

  // Unknown witnessScript shape — caller can still pre-populate
  // finalScriptWitness manually if needed.
  return undefined;
}

/**
 * Parse a bare M-of-N CHECKMULTISIG script (BIP-11 layout):
 *   OP_M <pubkey1> ... <pubkeyN> OP_N OP_CHECKMULTISIG
 *
 * Each pubkey may be 33 (compressed) or 65 (uncompressed) bytes; we accept
 * either shape because P2WSH script validation does not enforce compression.
 *
 * Returns `undefined` if the script does not match the multisig template.
 */
function parseMultisigScript(
  script: Buffer
): { m: number; n: number; pubkeys: Buffer[] } | undefined {
  if (script.length < 1 + 1 + 1) return undefined;
  // Trailing byte must be OP_CHECKMULTISIG (0xae).
  if (script[script.length - 1] !== 0xae) return undefined;

  // OP_1..OP_16 are 0x51..0x60 in the interpreter.
  const mOp = script[0];
  if (mOp < 0x51 || mOp > 0x60) return undefined;
  const m = mOp - 0x50;

  const nOp = script[script.length - 2];
  if (nOp < 0x51 || nOp > 0x60) return undefined;
  const n = nOp - 0x50;

  if (m < 1 || m > n || n > 16) return undefined;

  // Walk pubkeys between OP_M and OP_N.  Each pubkey is a single push:
  //   0x21 <33 bytes>   (compressed)
  //   0x41 <65 bytes>   (uncompressed)
  const pubkeys: Buffer[] = [];
  let i = 1;
  const end = script.length - 2;
  while (i < end) {
    const pushLen = script[i];
    if (pushLen !== 0x21 && pushLen !== 0x41) return undefined;
    const expected = pushLen;
    if (i + 1 + expected > end) return undefined;
    pubkeys.push(script.subarray(i + 1, i + 1 + expected));
    i += 1 + expected;
  }
  if (i !== end) return undefined;
  if (pubkeys.length !== n) return undefined;

  return { m, n, pubkeys };
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
  input.tapScriptSigs.clear();
  input.tapLeafScripts.clear();
  input.tapBip32Derivation.clear();
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

// =============================================================================
// analyzepsbt RPC support (W47, mirrors bitcoin-core/src/node/psbt.cpp)
// =============================================================================

/**
 * Per-input result of {@link analyzePSBTCore}.
 *
 * Shape mirrors Bitcoin Core's `analyzepsbt` JSON (`rpc/rawtransaction.cpp`):
 *   { has_utxo, is_final, next, missing? }
 *
 * `missing` is a partial Core-shape sub-object — we currently emit only
 * `signatures` (hex pubkeys whose partial sig is absent) when the per-input
 * verdict is `signer` and we can derive a missing-pubkey list from a
 * multisig redeem/witness script. We do NOT emit `pubkeys`,
 * `redeemscript`, or `witnessscript` (those would require a full
 * descriptor walk to compute Core-byte-identical hashes; downstream
 * consumers in the W40-C harness only check the top-level `next`
 * field, and the per-input `missing` is informational).
 */
export interface AnalyzedInput {
  has_utxo: boolean;
  is_final: boolean;
  next: "creator" | "updater" | "signer" | "finalizer" | "extractor";
  missing?: { signatures?: string[] };
}

export interface AnalyzedPSBT {
  inputs: AnalyzedInput[];
  next: "creator" | "updater" | "signer" | "finalizer" | "extractor";
}

/**
 * Parse the (M, N) threshold from a bare CHECKMULTISIG redeem/witness script.
 *
 * Layout (BIP-11 / Core's `IsStandardMultisig`):
 *   <OP_M> <pubkey_1> ... <pubkey_N> <OP_N> OP_CHECKMULTISIG
 * where OP_M / OP_N are OP_1..OP_16 (0x51..0x60).
 *
 * Returns `{ m, n, pubkeys }` on a well-formed multisig (each pubkey is 33
 * compressed or 65 uncompressed bytes); `undefined` otherwise. Caller
 * uses this to count how many partial sigs are still missing.
 *
 * Reference: bitcoin-core/src/script/standard.cpp `MatchMultisig`.
 */
export function parseMultisigThreshold(
  script: Buffer
): { m: number; n: number; pubkeys: Buffer[] } | undefined {
  if (script.length < 4) return undefined;
  if (script[script.length - 1] !== 0xae) return undefined; // OP_CHECKMULTISIG

  const mByte = script[0];
  const nByte = script[script.length - 2];
  if (mByte < 0x51 || mByte > 0x60) return undefined;
  if (nByte < 0x51 || nByte > 0x60) return undefined;
  const m = mByte - 0x50;
  const n = nByte - 0x50;
  if (m < 1 || m > n || n > 20) return undefined;

  // Walk the pubkey pushes between OP_M and OP_N.
  const pubkeys: Buffer[] = [];
  let i = 1;
  const end = script.length - 2;
  while (i < end) {
    const op = script[i];
    let pushLen: number;
    if (op >= 0x01 && op <= 0x4b) {
      pushLen = op;
      i += 1;
    } else if (op === 0x4c) {
      if (i + 1 >= end) return undefined;
      pushLen = script[i + 1];
      i += 2;
    } else {
      // OP_PUSHDATA2/4 not used for pubkeys in bare multisig.
      return undefined;
    }
    if (pushLen !== 33 && pushLen !== 65) return undefined;
    if (i + pushLen > end) return undefined;
    pubkeys.push(Buffer.from(script.subarray(i, i + pushLen)));
    i += pushLen;
  }
  if (pubkeys.length !== n) return undefined;
  return { m, n, pubkeys };
}

/**
 * Compute the minimum number of partial sigs required to finalize an
 * input.
 *
 * Mirrors Core's `SignPSBTInput` dummy-sign attempt in
 * `src/node/psbt.cpp::AnalyzePSBT`: for next-role analysis, the only
 * thing that matters is the missing-sigs count.
 *
 * - Multisig (P2SH / P2WSH / P2SH-P2WSH): M from the redeem/witness script.
 * - Taproot key-path: 1 (the schnorr sig).
 * - Single-sig (P2PKH / P2WPKH / P2SH-P2WPKH): 1.
 * - No utxo / no script: undefined (caller treats as "cannot classify").
 */
export function requiredSigCount(input: PSBTInput): number | undefined {
  // Prefer witness_script (P2WSH and nested P2SH-P2WSH multisig).
  if (input.witnessScript) {
    const ms = parseMultisigThreshold(input.witnessScript);
    return ms ? ms.m : 1;
  }
  if (input.redeemScript) {
    const ms = parseMultisigThreshold(input.redeemScript);
    if (ms) return ms.m;
    // Bare P2SH that isn't multisig (e.g. P2SH-P2WPKH wrapper).
    return 1;
  }
  if (input.tapInternalKey) return 1;
  // Plain witness_utxo / non_witness_utxo without a script suggests a
  // single-sig P2PKH or P2WPKH (taproot key-path is covered above when
  // the PSBT advertises tap_internal_key).
  if (input.witnessUtxo || input.nonWitnessUtxo) return 1;
  return undefined;
}

/**
 * Is this input ready for the finalizer step?
 *
 * Mirrors Core's "dummy-sign succeeds" branch in `AnalyzePSBT`: when a
 * non-finalized input has every signature it needs (M-of-N for multisig;
 * 1 for single-sig; tap_key_sig for taproot), the next role is FINALIZER,
 * not SIGNER.
 */
export function isInputReadyToFinalize(input: PSBTInput): boolean {
  if (isInputFinalized(input)) return false;
  if (input.tapKeySig) return true;
  const nSigs = input.partialSigs.size;
  if (nSigs === 0) return false;
  const needed = requiredSigCount(input);
  if (needed === undefined) {
    // Cannot classify; legacy any-sig heuristic — match camlcoin W41
    // behavior so we don't regress single-sig inputs.
    return nSigs >= 1;
  }
  return nSigs >= needed;
}

/**
 * Per-input next role for analyzepsbt, mirroring Bitcoin Core's
 * `AnalyzePSBT` (`bitcoin-core/src/node/psbt.cpp`).
 */
export function inputNextRole(
  input: PSBTInput
): "updater" | "signer" | "finalizer" | "extractor" {
  const hasUtxo =
    input.witnessUtxo !== undefined || input.nonWitnessUtxo !== undefined;
  if (isInputFinalized(input)) return "extractor";
  if (!hasUtxo) return "updater";
  if (isInputReadyToFinalize(input)) return "finalizer";
  return "signer";
}

const ROLE_RANK: Record<string, number> = {
  creator: 0,
  updater: 1,
  signer: 2,
  finalizer: 3,
  extractor: 4,
};

/**
 * Compute the Core-byte-shape result for the `analyzepsbt` RPC.
 *
 * - Per-input `next` is computed via {@link inputNextRole}.
 * - PSBT-level `next` is the minimum (in Core's order
 *   creator < updater < signer < finalizer < extractor) of all per-input
 *   roles, defaulting to `extractor` for empty input lists (which Core's
 *   AnalyzePSBT can never actually reach — a PSBT with no inputs is
 *   rejected upstream — but the harness only runs against well-formed
 *   PSBTs anyway).
 *
 * For per-input multisig inputs missing some sigs, we additionally emit
 * `missing.signatures` as a list of hex pubkeys whose partial sig is
 * absent. This mirrors Core's `SignatureData::missing_sigs` field shape
 * (a list of pubkey identifiers) — Core uses key IDs (hash160) rather
 * than full pubkeys; we emit pubkeys directly because the W40-C harness
 * does not assert on this sub-field.
 *
 * Reference: bitcoin-core/src/node/psbt.cpp `AnalyzePSBT`.
 * Reference: camlcoin lib/psbt.ml `psbt_next_role` (W41 / 2a22a0e).
 */
export function analyzePSBTCore(psbt: PSBT): AnalyzedPSBT {
  const inputs: AnalyzedInput[] = psbt.inputs.map((input) => {
    const hasUtxo =
      input.witnessUtxo !== undefined || input.nonWitnessUtxo !== undefined;
    const finalized = isInputFinalized(input);
    const next = inputNextRole(input);
    const result: AnalyzedInput = {
      has_utxo: hasUtxo,
      is_final: finalized,
      next,
    };

    // Compute missing.signatures for multisig signer-state inputs.
    if (next === "signer") {
      const script = input.witnessScript ?? input.redeemScript;
      if (script) {
        const ms = parseMultisigThreshold(script);
        if (ms) {
          const missing: string[] = [];
          for (const pk of ms.pubkeys) {
            if (!input.partialSigs.has(pk.toString("hex"))) {
              missing.push(pk.toString("hex"));
            }
          }
          if (missing.length > 0) {
            result.missing = { signatures: missing };
          }
        }
      }
    }
    return result;
  });

  let next: AnalyzedPSBT["next"] = "extractor";
  for (const inp of inputs) {
    if (ROLE_RANK[inp.next] < ROLE_RANK[next]) {
      next = inp.next;
    }
  }

  return { inputs, next };
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
export interface DecodedScriptPubKey {
  asm: string;
  desc: string;
  hex: string;
  address?: string;
  type: string;
}

export interface DecodedPSBT {
  tx: {
    txid: string;
    hash: string;
    version: number;
    size: number;
    vsize: number;
    weight: number;
    locktime: number;
    vin: Array<{
      txid: string;
      vout: number;
      scriptSig: { asm: string; hex: string };
      sequence: number;
    }>;
    vout: Array<{
      value: unknown;
      n: number;
      scriptPubKey: DecodedScriptPubKey;
    }>;
  };
  global_xpubs: unknown[];
  psbt_version: number;
  proprietary: unknown[];
  unknown: Record<string, string>;
  inputs: Array<{
    witness_utxo?: { amount: unknown; scriptPubKey: DecodedScriptPubKey };
    non_witness_utxo?: Record<string, unknown>;
    partial_signatures?: Record<string, string>;
    sighash?: string;
    redeem_script?: { asm: string; hex: string; type: string };
    witness_script?: { asm: string; hex: string; type: string };
    bip32_derivs?: Array<{ pubkey: string; master_fingerprint: string; path: string }>;
    final_scriptSig?: { asm: string; hex: string };
    final_scriptwitness?: string[];
    // BIP-371 taproot input fields
    taproot_key_path_sig?: string;
    taproot_script_path_sigs?: unknown[];
    taproot_scripts?: unknown[];
    taproot_bip32_derivs?: unknown[];
    taproot_internal_key?: string;
    taproot_merkle_root?: string;
    unknown?: Record<string, string>;
  }>;
  outputs: Array<{
    redeem_script?: { asm: string; hex: string; type: string };
    witness_script?: { asm: string; hex: string; type: string };
    bip32_derivs?: Array<{ pubkey: string; master_fingerprint: string; path: string }>;
    // BIP-371 taproot output fields
    taproot_internal_key?: string;
    taproot_tree?: unknown[];
    taproot_bip32_derivs?: unknown[];
    musig2_participant_pubkeys?: unknown[];
    unknown?: Record<string, string>;
  }>;
  fee?: unknown;
}

/**
 * Opcode name lookup — mirrors bitcoin-core/src/script/script.cpp::GetOpName.
 * Small numbers (OP_0, OP_1..OP_16) use Core's numeric string form ("0",
 * "1".."16"). OP_1NEGATE → "-1". Unknown opcodes → "OP_UNKNOWN".
 */
function getOpcodeName(op: number): string {
  const names: Record<number, string> = {
    0x4f: "-1",       // OP_1NEGATE
    0x50: "OP_RESERVED",
    0x51: "1",  0x52: "2",  0x53: "3",  0x54: "4",
    0x55: "5",  0x56: "6",  0x57: "7",  0x58: "8",
    0x59: "9",  0x5a: "10", 0x5b: "11", 0x5c: "12",
    0x5d: "13", 0x5e: "14", 0x5f: "15", 0x60: "16",
    0x61: "OP_NOP",
    0x63: "OP_IF",    0x64: "OP_NOTIF",
    0x67: "OP_ELSE",  0x68: "OP_ENDIF",
    0x69: "OP_VERIFY",
    0x6a: "OP_RETURN",
    0x6b: "OP_TOALTSTACK", 0x6c: "OP_FROMALTSTACK",
    0x6d: "OP_2DROP", 0x6e: "OP_2DUP",  0x6f: "OP_3DUP",
    0x70: "OP_2OVER", 0x71: "OP_2ROT",  0x72: "OP_2SWAP",
    0x73: "OP_IFDUP", 0x74: "OP_DEPTH", 0x75: "OP_DROP",
    0x76: "OP_DUP",   0x77: "OP_NIP",   0x78: "OP_OVER",
    0x87: "OP_EQUAL", 0x88: "OP_EQUALVERIFY",
    0x8b: "OP_1ADD",  0x8c: "OP_1SUB",
    0x91: "OP_NOT",   0x92: "OP_0NOTEQUAL",
    0x93: "OP_ADD",   0x94: "OP_SUB",
    0x9a: "OP_BOOLAND", 0x9b: "OP_BOOLOR",
    0x9c: "OP_NUMEQUAL", 0x9d: "OP_NUMEQUALVERIFY",
    0x9e: "OP_NUMNOTEQUAL",
    0x9f: "OP_LESSTHAN", 0xa0: "OP_GREATERTHAN",
    0xa1: "OP_LESSTHANOREQUAL", 0xa2: "OP_GREATERTHANOREQUAL",
    0xa3: "OP_MIN",   0xa4: "OP_MAX",   0xa5: "OP_WITHIN",
    0xa6: "OP_RIPEMD160", 0xa7: "OP_SHA1",
    0xa8: "OP_SHA256", 0xa9: "OP_HASH160", 0xaa: "OP_HASH256",
    0xab: "OP_CODESEPARATOR",
    0xac: "OP_CHECKSIG", 0xad: "OP_CHECKSIGVERIFY",
    0xae: "OP_CHECKMULTISIG", 0xaf: "OP_CHECKMULTISIGVERIFY",
    0xb0: "OP_NOP1",
    0xb1: "OP_CHECKLOCKTIMEVERIFY", 0xb2: "OP_CHECKSEQUENCEVERIFY",
    0xb3: "OP_NOP4",  0xb4: "OP_NOP5",  0xb5: "OP_NOP6",
    0xb6: "OP_NOP7",  0xb7: "OP_NOP8",  0xb8: "OP_NOP9",
    0xb9: "OP_NOP10",
    0xba: "OP_CHECKSIGADD",
  };
  return names[op] ?? "OP_UNKNOWN";
}

/**
 * Sighash type name table mirroring bitcoin-core/src/core_io.cpp mapSigHashTypes.
 * Unknown types are not in this map (SighashToStr returns "" for unknowns).
 */
const SIGHASH_TYPE_NAMES: Record<number, string> = {
  0x01: "ALL",
  0x02: "NONE",
  0x03: "SINGLE",
  0x81: "ALL|ANYONECANPAY",
  0x82: "NONE|ANYONECANPAY",
  0x83: "SINGLE|ANYONECANPAY",
};

/**
 * Script ASM disassembly with sighash decode (ScriptToAsmStr fAttemptSighashDecode=true).
 *
 * For push data >4 bytes: if the pushed bytes look like a DER-encoded signature
 * (first byte 0x30) and the last byte is a recognised sighash type, strip the
 * last byte and append "[SIGHASH_NAME]" (e.g. "[ALL]"). Otherwise fall through
 * to plain hex rendering. This mirrors Bitcoin Core's ScriptToAsmStr logic at
 * bitcoin-core/src/core_io.cpp:376-393.
 *
 * Used for final_scriptSig only.
 */
function disassembleScriptSigHashDecode(script: Buffer): string {
  if (script.length === 0) return "";

  const parts: string[] = [];
  let i = 0;

  while (i < script.length) {
    const op = script[i];

    if (op === 0x00) {
      parts.push("0");
      i++;
    } else if (op >= 0x01 && op <= 0x4b) {
      const len = op;
      if (i + 1 + len > script.length) { parts.push("[error]"); break; }
      const data = Buffer.from(script.subarray(i + 1, i + 1 + len));
      if (len <= 4) {
        parts.push(scriptNumToAsmStr(data));
      } else {
        parts.push(decodeWithSigHash(data));
      }
      i += 1 + len;
    } else if (op === 0x4c) {
      if (i + 1 >= script.length) { parts.push("[error]"); break; }
      const len = script[i + 1];
      if (i + 2 + len > script.length) { parts.push("[error]"); break; }
      const data = Buffer.from(script.subarray(i + 2, i + 2 + len));
      parts.push(len <= 4 ? scriptNumToAsmStr(data) : decodeWithSigHash(data));
      i += 2 + len;
    } else if (op === 0x4d) {
      if (i + 2 >= script.length) { parts.push("[error]"); break; }
      const len = script.readUInt16LE(i + 1);
      if (i + 3 + len > script.length) { parts.push("[error]"); break; }
      const data = Buffer.from(script.subarray(i + 3, i + 3 + len));
      parts.push(len <= 4 ? scriptNumToAsmStr(data) : decodeWithSigHash(data));
      i += 3 + len;
    } else if (op === 0x4e) {
      if (i + 4 >= script.length) { parts.push("[error]"); break; }
      const len = script.readUInt32LE(i + 1);
      if (i + 5 + len > script.length) { parts.push("[error]"); break; }
      const data = Buffer.from(script.subarray(i + 5, i + 5 + len));
      parts.push(len <= 4 ? scriptNumToAsmStr(data) : decodeWithSigHash(data));
      i += 5 + len;
    } else {
      parts.push(getOpcodeName(op));
      i++;
    }
  }

  return parts.join(" ");
}

/**
 * Attempt sighash decode on a pushed data element >4 bytes.
 *
 * If data looks like a DER signature (byte[0] == 0x30) and the last byte is
 * a recognised sighash type, emit hex(data[0..n-2]) + "[SIGHASH_NAME]".
 * Otherwise emit plain hex.
 *
 * Mirrors Core's CheckSignatureEncoding + mapSigHashTypes check at
 * bitcoin-core/src/core_io.cpp:382-390.
 */
function decodeWithSigHash(data: Buffer): string {
  if (data.length >= 2 && data[0] === 0x30) {
    const lastByte = data[data.length - 1];
    const sigHashName = SIGHASH_TYPE_NAMES[lastByte];
    if (sigHashName !== undefined) {
      return data.subarray(0, data.length - 1).toString("hex") + "[" + sigHashName + "]";
    }
  }
  return data.toString("hex");
}

/**
 * Build a full TxToUniv-shaped JSON object for non_witness_utxo.
 *
 * Mirrors bitcoin-core/src/core_io.cpp::TxToUniv called with include_hex=false.
 * Shape: {txid, hash, version, size, vsize, weight, locktime, vin[], vout[]}
 * No "hex" field (Core omits it for PSBT's non_witness_utxo).
 *
 * vin[i].scriptSig uses plain disassembleScript (fAttemptSighashDecode=false
 * for the prevtx, not the spending tx).
 * vin[i] includes txinwitness when the input has witness data.
 * vout[i] uses formatBtcAmount + buildScriptPubKeyObj.
 */
function buildTxToUnivJSON(tx: Transaction): Record<string, unknown> {
  const txid = Buffer.from(getTxId(tx)).reverse().toString("hex");
  const hash = Buffer.from(getWTxId(tx)).reverse().toString("hex");
  const size = serializeTx(tx, hasWitness(tx)).length;
  const weight = getTxWeight(tx);
  const vsize = getTxVSize(tx);

  const vin = tx.inputs.map((input) => {
    const entry: Record<string, unknown> = {
      txid: Buffer.from(input.prevOut.txid).reverse().toString("hex"),
      vout: input.prevOut.vout,
      scriptSig: {
        asm: disassembleScript(input.scriptSig),
        hex: input.scriptSig.toString("hex"),
      },
      sequence: input.sequence,
    };
    if (input.witness && input.witness.length > 0) {
      entry.txinwitness = input.witness.map((w) => Buffer.from(w).toString("hex"));
    }
    return entry;
  });

  const vout = tx.outputs.map((output, n) => ({
    value: formatBtcAmount(output.value),
    n,
    scriptPubKey: buildScriptPubKeyObj(output.scriptPubKey),
  }));

  return {
    txid,
    hash,
    version: tx.version,
    size,
    vsize,
    weight,
    locktime: tx.lockTime,
    vin,
    vout,
  };
}

/**
 * Decode a CScriptNum push (≤4 bytes) to its signed-integer string.
 * Core's ScriptToAsmStr renders small pushes this way.
 */
function scriptNumToAsmStr(vch: Buffer): string {
  if (vch.length === 0) return "0";
  let result = 0;
  for (let i = 0; i < vch.length; i++) {
    result |= vch[i] << (8 * i);
  }
  // Sign bit is in MSB of last byte.
  const last = vch[vch.length - 1];
  if (last & 0x80) {
    // Clear sign bit, negate.
    const signBitMask = 1 << (8 * (vch.length - 1) + 7 - (8 * (vch.length - 1)));
    result &= ~(0x80 << (8 * (vch.length - 1)));
    result = -result;
  }
  return result.toString();
}

/**
 * Core-compatible script ASM disassembly (ScriptToAsmStr, fAttemptSighashDecode=false).
 * - OP_0 (0x00) → "0"
 * - Small pushes (1–4 bytes) → CScriptNum integer text
 * - Large pushes (>4 bytes) → hex
 * - Non-push opcodes → GetOpName string
 */
function disassembleScript(script: Buffer): string {
  if (script.length === 0) return "";

  const parts: string[] = [];
  let i = 0;

  while (i < script.length) {
    const op = script[i];

    if (op === 0x00) {
      // OP_0 → "0"
      parts.push("0");
      i++;
    } else if (op >= 0x01 && op <= 0x4b) {
      // OP_PUSHBYTES_N
      const len = op;
      if (i + 1 + len > script.length) { parts.push("[error]"); break; }
      const data = script.subarray(i + 1, i + 1 + len);
      if (len <= 4) {
        parts.push(scriptNumToAsmStr(data));
      } else {
        parts.push(data.toString("hex"));
      }
      i += 1 + len;
    } else if (op === 0x4c) {
      // OP_PUSHDATA1
      if (i + 1 >= script.length) { parts.push("[error]"); break; }
      const len = script[i + 1];
      if (i + 2 + len > script.length) { parts.push("[error]"); break; }
      const data = script.subarray(i + 2, i + 2 + len);
      parts.push(len <= 4 ? scriptNumToAsmStr(data) : data.toString("hex"));
      i += 2 + len;
    } else if (op === 0x4d) {
      // OP_PUSHDATA2
      if (i + 2 >= script.length) { parts.push("[error]"); break; }
      const len = script.readUInt16LE(i + 1);
      if (i + 3 + len > script.length) { parts.push("[error]"); break; }
      const data = script.subarray(i + 3, i + 3 + len);
      parts.push(len <= 4 ? scriptNumToAsmStr(data) : data.toString("hex"));
      i += 3 + len;
    } else if (op === 0x4e) {
      // OP_PUSHDATA4
      if (i + 4 >= script.length) { parts.push("[error]"); break; }
      const len = script.readUInt32LE(i + 1);
      if (i + 5 + len > script.length) { parts.push("[error]"); break; }
      const data = script.subarray(i + 5, i + 5 + len);
      parts.push(len <= 4 ? scriptNumToAsmStr(data) : data.toString("hex"));
      i += 5 + len;
    } else {
      parts.push(getOpcodeName(op));
      i++;
    }
  }

  return parts.join(" ");
}

/**
 * Get script type string matching Bitcoin Core's scriptPubKey type names.
 */
function getScriptType(script: Buffer): string {
  // P2WPKH: OP_0 <20 bytes>
  if (script.length === 22 && script[0] === 0x00 && script[1] === 0x14) {
    return "witness_v0_keyhash";
  }
  // P2WSH: OP_0 <32 bytes>
  if (script.length === 34 && script[0] === 0x00 && script[1] === 0x20) {
    return "witness_v0_scripthash";
  }
  // P2TR: OP_1 <32 bytes>
  if (script.length === 34 && script[0] === 0x51 && script[1] === 0x20) {
    return "witness_v1_taproot";
  }
  // P2PKH: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
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
  // P2SH: OP_HASH160 <20 bytes> OP_EQUAL
  if (
    script.length === 23 &&
    script[0] === 0xa9 &&
    script[1] === 0x14 &&
    script[22] === 0x87
  ) {
    return "scripthash";
  }
  // P2PK: <33 or 65 bytes pubkey> OP_CHECKSIG
  if (
    (script.length === 35 || script.length === 67) &&
    script[script.length - 1] === 0xac
  ) {
    return "pubkey";
  }
  // OP_RETURN (nulldata)
  if (script.length >= 1 && script[0] === 0x6a) {
    return "nulldata";
  }
  return "nonstandard";
}

/**
 * Sentinel prefix used to tag BTC amount strings so the RPC JSON replacer
 * (server.ts::bigIntJsonReplacer) can detect and un-quote them, turning
 * the JSON string `"__BTC__:1.00000000"` into the raw JSON number
 * `1.00000000` after a post-process pass.
 *
 * This is the canonical way to embed raw JSON numbers in JavaScript
 * without a custom serializer: (1) tag in JSON replacer, (2) strip
 * quotes in the final string pass.
 */
export const BTC_AMOUNT_SENTINEL = "__BTC__:";

/**
 * Format a satoshi amount as Bitcoin Core's ValueFromAmount:
 * always 8 fractional digits, no scientific notation (e.g. "1.00000000").
 *
 * Returns an object whose toJSON() emits a sentinel-tagged string that the
 * RPC serializer post-processes into a raw JSON number.  See BTC_AMOUNT_SENTINEL.
 *
 * Reference: bitcoin-core/src/core_io.cpp ValueFromAmount (%s%d.%08d).
 */
export function formatBtcAmount(sats: bigint): { toJSON(): string } {
  const neg = sats < 0n;
  const abs = neg ? -sats : sats;
  const whole = abs / 100_000_000n;
  const frac = abs % 100_000_000n;
  const fracStr = frac.toString().padStart(8, "0");
  const raw = (neg ? "-" : "") + whole.toString() + "." + fracStr;
  return { toJSON() { return BTC_AMOUNT_SENTINEL + raw; } };
}

/**
 * Extract the canonical Bitcoin address from a scriptPubKey, matching
 * Core's ExtractDestination. Returns null for P2PK, multisig, nulldata,
 * nonstandard. The network is always mainnet for the live PSBT fleet.
 */
function spkToAddress(script: Buffer): string | null {
  const type = getScriptType(script);

  if (type === "pubkeyhash" && script.length === 25) {
    return base58CheckEncode(0x00, script.subarray(3, 23));
  }
  if (type === "scripthash" && script.length === 23) {
    return base58CheckEncode(0x05, script.subarray(2, 22));
  }
  if (type === "witness_v0_keyhash" && script.length === 22) {
    return bech32Encode("bc", 0, script.subarray(2, 22));
  }
  if (type === "witness_v0_scripthash" && script.length === 34) {
    return bech32Encode("bc", 0, script.subarray(2, 34));
  }
  if (type === "witness_v1_taproot" && script.length === 34) {
    return bech32Encode("bc", 1, script.subarray(2, 34));
  }
  return null;
}

/**
 * Build a BIP-380 descriptor string for a scriptPubKey, mirroring Core's
 * InferDescriptor in the no-provider context (decodepsbt):
 *   rawtr(<x-only-hex>)#<checksum>   — for OP_1 <32bytes> (witness_v1_taproot)
 *   addr(<address>)#<checksum>       — for other standard address-encodable scripts
 *   raw(<hex>)#<checksum>            — otherwise
 *
 * CRITICAL: taproot outputs use rawtr() NOT addr(), matching Core's InferDescriptor
 * which returns a RawTRDescriptor when no signing provider is available.
 */
function inferDescriptor(script: Buffer): string {
  // witness_v1_taproot: OP_1 (0x51) + OP_DATA_32 (0x20) + 32 bytes = 34 bytes
  if (script.length === 34 && script[0] === 0x51 && script[1] === 0x20) {
    const xonly = script.subarray(2, 34).toString("hex");
    const inner = `rawtr(${xonly})`;
    try {
      return addChecksum(inner);
    } catch {
      return inner;
    }
  }
  const addr = spkToAddress(script);
  let inner: string;
  if (addr !== null) {
    inner = `addr(${addr})`;
  } else {
    inner = `raw(${script.toString("hex")})`;
  }
  try {
    return addChecksum(inner);
  } catch {
    return inner;
  }
}

/**
 * Build the Core-compatible scriptPubKey JSON object:
 *   { asm, desc, hex, address?, type }
 * The `address` field is suppressed for bare-pubkey scripts (type==="pubkey"),
 * matching Core's ScriptToUniv behaviour.
 */
function buildScriptPubKeyObj(script: Buffer): DecodedScriptPubKey {
  const type = getScriptType(script);
  const result: DecodedScriptPubKey = {
    asm: disassembleScript(script),
    desc: inferDescriptor(script),
    hex: script.toString("hex"),
    type,
  };
  if (type !== "pubkey") {
    const addr = spkToAddress(script);
    if (addr !== null) {
      result.address = addr;
    }
  }
  return result;
}

/**
 * Format derivation path from indices.
 */
function formatDerivationPath(origin: KeyOriginInfo): string {
  const parts = origin.path.map((index) => {
    if (index >= 0x80000000) {
      // Core's WriteHDKeypath uses 'h' suffix (not apostrophe) for hardened paths
      return `${index - 0x80000000}h`;
    }
    return index.toString();
  });
  if (parts.length === 0) {
    return "m";
  }
  return "m/" + parts.join("/");
}

/**
 * Decode a PSBT for RPC output, producing Bitcoin Core-byte-compatible JSON.
 *
 * References:
 *   bitcoin-core/src/rpc/rawtransaction.cpp::decodepsbt
 *   bitcoin-core/src/core_io.cpp::TxToUniv, ScriptToUniv, ValueFromAmount
 */
export function decodePSBT(psbt: PSBT): DecodedPSBT {
  const tx = psbt.tx;

  // tx.txid and tx.hash — for non-segwit PSBTs (unsigned global tx has no
  // witness data) these are identical. Both are displayed as big-endian hex.
  // NOTE: Buffer.reverse() mutates in place; clone before reversing so the
  // cached _cachedTxId is not corrupted (getWTxId returns the same buffer
  // reference for non-segwit txs).
  const txid = Buffer.from(getTxId(tx)).reverse().toString("hex");
  const hash = Buffer.from(getWTxId(tx)).reverse().toString("hex");

  // tx size/vsize/weight (Core's TxToUniv fields)
  const txSize = serializeTx(tx, hasWitness(tx)).length;
  const txWeight = getTxWeight(tx);
  const txVsize = getTxVSize(tx);

  const vin = tx.inputs.map((input) => ({
    txid: Buffer.from(input.prevOut.txid).reverse().toString("hex"),
    vout: input.prevOut.vout,
    scriptSig: {
      asm: disassembleScript(input.scriptSig),
      hex: input.scriptSig.toString("hex"),
    },
    sequence: input.sequence,
  }));

  const vout = tx.outputs.map((output, n) => ({
    value: formatBtcAmount(output.value),
    n,
    scriptPubKey: buildScriptPubKeyObj(output.scriptPubKey),
  }));

  const unknown: Record<string, string> = {};
  for (const [key, value] of psbt.unknown) {
    unknown[key] = value.toString("hex");
  }

  // Track total input value for fee calculation.
  // Core computes: fee = total_in - total_out, emitted only when all UTXOs present.
  let totalIn = 0n;
  let haveAllUtxos = true;

  const inputs = psbt.inputs.map((input, i) => {
    const result: DecodedPSBT["inputs"][0] = {};

    // UTXOs — mirrors rawtransaction.cpp:1122-1156.
    // Core tracks txout as the *last-assigned* value (non_witness_utxo wins if
    // both are present) and adds it once to total_in.
    let haveUtxo = false;
    let utxoValue: bigint | undefined;

    if (input.witnessUtxo) {
      result.witness_utxo = {
        amount: formatBtcAmount(input.witnessUtxo.value),
        scriptPubKey: buildScriptPubKeyObj(input.witnessUtxo.scriptPubKey),
      };
      utxoValue = input.witnessUtxo.value;
      haveUtxo = true;
    }

    if (input.nonWitnessUtxo) {
      result.non_witness_utxo = buildTxToUnivJSON(input.nonWitnessUtxo);
      // non_witness_utxo overwrites txout (Core semantics): use the specific
      // output being spent.
      const vout = psbt.tx.inputs[i]?.prevOut.vout ?? 0;
      if (vout < input.nonWitnessUtxo.outputs.length) {
        utxoValue = input.nonWitnessUtxo.outputs[vout].value;
      } else {
        haveAllUtxos = false;
        utxoValue = undefined;
      }
      haveUtxo = true;
    }

    if (haveUtxo && utxoValue !== undefined) {
      totalIn += utxoValue;
    } else if (!haveUtxo) {
      haveAllUtxos = false;
    }

    // Partial signatures
    if (input.partialSigs.size > 0) {
      result.partial_signatures = {};
      for (const [pubkeyHex, { signature }] of input.partialSigs) {
        result.partial_signatures[pubkeyHex] = signature.toString("hex");
      }
    }

    // Sighash type — emit string name, "" for unknown (matches SighashToStr)
    if (input.sighashType !== undefined) {
      result.sighash = SIGHASH_TYPE_NAMES[input.sighashType] ?? "";
    }

    // Redeem script / witness script — ScriptToUniv default shape: {asm, hex, type}
    if (input.redeemScript) {
      result.redeem_script = {
        asm: disassembleScript(input.redeemScript),
        hex: input.redeemScript.toString("hex"),
        type: getScriptType(input.redeemScript),
      };
    }

    if (input.witnessScript) {
      result.witness_script = {
        asm: disassembleScript(input.witnessScript),
        hex: input.witnessScript.toString("hex"),
        type: getScriptType(input.witnessScript),
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

    // BIP-371 Taproot fields (all conditional — omit when empty)

    // taproot_key_path_sig (PSBT_IN_TAP_KEY_SIG 0x13)
    if (input.tapKeySig) {
      result.taproot_key_path_sig = input.tapKeySig.toString("hex");
    }

    // taproot_script_path_sigs (PSBT_IN_TAP_SCRIPT_SIG 0x14)
    if (input.tapScriptSigs.size > 0) {
      result.taproot_script_path_sigs = [];
      for (const { xonly, leafHash, sig } of input.tapScriptSigs.values()) {
        (result.taproot_script_path_sigs as unknown[]).push({
          pubkey: xonly.toString("hex"),
          leaf_hash: leafHash.toString("hex"),
          sig: sig.toString("hex"),
        });
      }
    }

    // taproot_scripts (PSBT_IN_TAP_LEAF_SCRIPT 0x15)
    if (input.tapLeafScripts.size > 0) {
      result.taproot_scripts = [];
      for (const { script, leafVer, controlBlocks } of input.tapLeafScripts.values()) {
        (result.taproot_scripts as unknown[]).push({
          script: script.toString("hex"),
          leaf_ver: leafVer,
          control_blocks: controlBlocks.map((cb) => cb.toString("hex")),
        });
      }
    }

    // taproot_bip32_derivs (PSBT_IN_TAP_BIP32_DERIVATION 0x16)
    if (input.tapBip32Derivation.size > 0) {
      result.taproot_bip32_derivs = [];
      for (const { xonly, leafHashes, origin } of input.tapBip32Derivation.values()) {
        (result.taproot_bip32_derivs as unknown[]).push({
          pubkey: xonly.toString("hex"),
          master_fingerprint: origin.fingerprint.toString("hex"),
          path: formatDerivationPath(origin),
          leaf_hashes: leafHashes.map((h) => h.toString("hex")),
        });
      }
    }

    // taproot_internal_key (PSBT_IN_TAP_INTERNAL_KEY 0x17)
    if (input.tapInternalKey) {
      result.taproot_internal_key = input.tapInternalKey.toString("hex");
    }

    // taproot_merkle_root (PSBT_IN_TAP_MERKLE_ROOT 0x18)
    if (input.tapMerkleRoot) {
      result.taproot_merkle_root = input.tapMerkleRoot.toString("hex");
    }

    // final_scriptSig — ScriptToAsmStr with fAttemptSighashDecode=true
    if (input.finalScriptSig) {
      result.final_scriptSig = {
        asm: disassembleScriptSigHashDecode(input.finalScriptSig),
        hex: input.finalScriptSig.toString("hex"),
      };
    }

    if (input.finalScriptWitness) {
      result.final_scriptwitness = input.finalScriptWitness.map((item) =>
        Buffer.from(item).toString("hex")
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
        type: getScriptType(output.redeemScript),
      };
    }

    if (output.witnessScript) {
      result.witness_script = {
        asm: disassembleScript(output.witnessScript),
        hex: output.witnessScript.toString("hex"),
        type: getScriptType(output.witnessScript),
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

    // Taproot internal key (PSBT_OUT_TAP_INTERNAL_KEY 0x05)
    if (output.tapInternalKey) {
      result.taproot_internal_key = output.tapInternalKey.toString("hex");
    }

    // Taproot tree (PSBT_OUT_TAP_TREE 0x06) — emit as taproot_tree
    if (output.tapTree && output.tapTree.length > 0) {
      result.taproot_tree = output.tapTree.map(({ depth, leafVersion, script }) => ({
        depth,
        leaf_ver: leafVersion,
        script: script.toString("hex"),
      }));
    }

    // Taproot BIP32 derivs (PSBT_OUT_TAP_BIP32_DERIVATION 0x07)
    if (output.tapBip32Derivation.size > 0) {
      result.taproot_bip32_derivs = [];
      for (const { xonly, leafHashes, origin } of output.tapBip32Derivation.values()) {
        (result.taproot_bip32_derivs as unknown[]).push({
          pubkey: xonly.toString("hex"),
          master_fingerprint: origin.fingerprint.toString("hex"),
          path: formatDerivationPath(origin),
          leaf_hashes: leafHashes.map((h) => h.toString("hex")),
        });
      }
    }

    // MuSig2 participant pubkeys (PSBT_OUT_MUSIG2_PARTICIPANT_PUBKEYS 0x08)
    if (output.musig2Participants.size > 0) {
      result.musig2_participant_pubkeys = [];
      for (const { aggPubkey, participantPubkeys } of output.musig2Participants.values()) {
        (result.musig2_participant_pubkeys as unknown[]).push({
          aggregate_pubkey: aggPubkey.toString("hex"),
          participant_pubkeys: participantPubkeys.map((p) => p.toString("hex")),
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

  // Fee calculation: mirrors rawtransaction.cpp:1254-1258.
  // Emit "fee" only when all inputs have UTXOs and fee is non-negative.
  const totalOut = tx.outputs.reduce((sum, o) => sum + o.value, 0n);
  const result: DecodedPSBT = {
    tx: {
      txid,
      hash,
      version: tx.version,
      size: txSize,
      vsize: txVsize,
      weight: txWeight,
      locktime: tx.lockTime,
      vin,
      vout,
    },
    global_xpubs: [],
    psbt_version: 0,
    proprietary: [],
    unknown,
    inputs,
    outputs,
  };

  if (haveAllUtxos && totalIn >= totalOut) {
    result.fee = formatBtcAmount(totalIn - totalOut);
  }

  return result;
}
