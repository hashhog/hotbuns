/**
 * Transaction validation: structure, serialization, sighash computation.
 *
 * Implements BIP-143 segwit sighash and legacy sighash algorithms,
 * transaction serialization with/without witness data, and basic validation.
 *
 * Performance optimizations:
 * - Parallel signature verification using Promise.all
 * - Sighash caching for BIP-143 (hashPrevouts, hashSequence, hashOutputs)
 */

import { BufferReader, BufferWriter, varIntSize } from "../wire/serialization.js";
import { hash256, ecdsaVerify } from "../crypto/primitives.js";
import type { UTXOEntry } from "../storage/database.js";

/**
 * Script verification flags.
 */
export const enum ScriptFlags {
  VERIFY_NONE = 0,
  VERIFY_P2SH = 1 << 0,
  VERIFY_WITNESS = 1 << 1,
  VERIFY_STRICTENC = 1 << 2,
  VERIFY_DERSIG = 1 << 3,
  VERIFY_NULLDUMMY = 1 << 4,
  VERIFY_CHECKLOCKTIMEVERIFY = 1 << 5,
  VERIFY_CHECKSEQUENCEVERIFY = 1 << 6,
  VERIFY_MINIMALDATA = 1 << 7,
}

/** Result of input verification. */
export interface InputVerifyResult {
  valid: boolean;
  inputIndex: number;
  error?: string;
}

/** Result of transaction verification. */
export interface TxVerifyResult {
  valid: boolean;
  error?: string;
  failedInput?: number;
}

// Sighash type constants
export const SIGHASH_ALL = 0x01;
export const SIGHASH_NONE = 0x02;
export const SIGHASH_SINGLE = 0x03;
export const SIGHASH_ANYONECANPAY = 0x80;

/**
 * A reference to a transaction output (txid + output index).
 */
export interface OutPoint {
  txid: Buffer; // 32 bytes
  vout: number; // uint32
}

/**
 * Transaction input.
 */
export interface TxIn {
  prevOut: OutPoint;
  scriptSig: Buffer;
  sequence: number; // uint32
  witness: Buffer[]; // segwit witness stack
}

/**
 * Transaction output.
 */
export interface TxOut {
  value: bigint; // satoshis (int64)
  scriptPubKey: Buffer;
}

/**
 * A Bitcoin transaction.
 */
export interface Transaction {
  version: number; // int32
  inputs: TxIn[];
  outputs: TxOut[];
  lockTime: number; // uint32
}

/**
 * Check if a transaction has any witness data.
 */
export function hasWitness(tx: Transaction): boolean {
  return tx.inputs.some((input) => input.witness.length > 0);
}

/**
 * Serialize a transaction to bytes.
 *
 * @param tx - Transaction to serialize
 * @param withWitness - If true, include witness data (BIP-141 format)
 */
export function serializeTx(tx: Transaction, withWitness: boolean): Buffer {
  const writer = new BufferWriter();

  // Version (4 bytes, little-endian)
  writer.writeInt32LE(tx.version);

  // Segwit marker and flag (only if withWitness and tx has witness data)
  const includeWitness = withWitness && hasWitness(tx);
  if (includeWitness) {
    writer.writeUInt8(0x00); // marker
    writer.writeUInt8(0x01); // flag
  }

  // Input count
  writer.writeVarInt(tx.inputs.length);

  // Inputs
  for (const input of tx.inputs) {
    writer.writeHash(input.prevOut.txid);
    writer.writeUInt32LE(input.prevOut.vout);
    writer.writeVarBytes(input.scriptSig);
    writer.writeUInt32LE(input.sequence);
  }

  // Output count
  writer.writeVarInt(tx.outputs.length);

  // Outputs
  for (const output of tx.outputs) {
    // Value as signed 64-bit (but always positive in valid txs)
    writer.writeUInt64LE(output.value);
    writer.writeVarBytes(output.scriptPubKey);
  }

  // Witness data (only if including witness)
  if (includeWitness) {
    for (const input of tx.inputs) {
      writer.writeVarInt(input.witness.length);
      for (const item of input.witness) {
        writer.writeVarBytes(item);
      }
    }
  }

  // Lock time (4 bytes, little-endian)
  writer.writeUInt32LE(tx.lockTime);

  return writer.toBuffer();
}

/**
 * Deserialize a transaction from a BufferReader.
 */
export function deserializeTx(reader: BufferReader): Transaction {
  const version = reader.readInt32LE();

  // Check for segwit marker
  const marker = reader.readUInt8();
  let flag = 0;
  let inputCount: number;

  if (marker === 0x00) {
    // Segwit format: marker=0x00, flag=0x01
    flag = reader.readUInt8();
    if (flag !== 0x01) {
      throw new Error(`Invalid segwit flag: ${flag}`);
    }
    inputCount = reader.readVarInt();
  } else {
    // Legacy format: marker is actually first byte of varint input count
    // We need to "unread" the marker and read it as part of the varint
    // Since BufferReader doesn't support unread, handle inline
    if (marker <= 0xfc) {
      inputCount = marker;
    } else if (marker === 0xfd) {
      inputCount = reader.readUInt16LE();
    } else if (marker === 0xfe) {
      inputCount = reader.readUInt32LE();
    } else {
      // 0xff - 8 byte varint, but for input counts this shouldn't happen
      const bigVal = reader.readUInt64LE();
      if (bigVal > BigInt(Number.MAX_SAFE_INTEGER)) {
        throw new Error("Input count exceeds safe integer range");
      }
      inputCount = Number(bigVal);
    }
  }

  // Parse inputs
  const inputs: TxIn[] = [];
  for (let i = 0; i < inputCount; i++) {
    const txid = reader.readHash();
    const vout = reader.readUInt32LE();
    const scriptSig = reader.readVarBytes();
    const sequence = reader.readUInt32LE();

    inputs.push({
      prevOut: { txid, vout },
      scriptSig,
      sequence,
      witness: [], // Will be populated later if segwit
    });
  }

  // Parse outputs
  const outputCount = reader.readVarInt();
  const outputs: TxOut[] = [];
  for (let i = 0; i < outputCount; i++) {
    const value = reader.readUInt64LE();
    const scriptPubKey = reader.readVarBytes();
    outputs.push({ value, scriptPubKey });
  }

  // Parse witness data if present
  if (flag === 0x01) {
    for (let i = 0; i < inputCount; i++) {
      const witnessCount = reader.readVarInt();
      const witness: Buffer[] = [];
      for (let j = 0; j < witnessCount; j++) {
        witness.push(reader.readVarBytes());
      }
      inputs[i].witness = witness;
    }
  }

  const lockTime = reader.readUInt32LE();

  return { version, inputs, outputs, lockTime };
}

/**
 * Compute the transaction ID (hash of non-witness serialization, reversed).
 * The txid is stored in little-endian (internal) format.
 */
export function getTxId(tx: Transaction): Buffer {
  const serialized = serializeTx(tx, false);
  return hash256(serialized);
}

/**
 * Compute the witness transaction ID (hash of witness serialization).
 * For non-witness transactions, this equals the regular txid.
 */
export function getWTxId(tx: Transaction): Buffer {
  if (!hasWitness(tx)) {
    return getTxId(tx);
  }
  const serialized = serializeTx(tx, true);
  return hash256(serialized);
}

/**
 * Calculate the base size of a transaction (without witness data).
 */
function getTxBaseSize(tx: Transaction): number {
  // version(4) + inputCount(varint) + inputs + outputCount(varint) + outputs + lockTime(4)
  let size = 4; // version

  size += varIntSize(tx.inputs.length);
  for (const input of tx.inputs) {
    // prevOut: txid(32) + vout(4) = 36
    // scriptSig: varint + data
    // sequence: 4
    size += 32 + 4;
    size += varIntSize(input.scriptSig.length) + input.scriptSig.length;
    size += 4;
  }

  size += varIntSize(tx.outputs.length);
  for (const output of tx.outputs) {
    // value: 8
    // scriptPubKey: varint + data
    size += 8;
    size += varIntSize(output.scriptPubKey.length) + output.scriptPubKey.length;
  }

  size += 4; // lockTime

  return size;
}

/**
 * Calculate the total size of a transaction (with witness data if present).
 */
function getTxTotalSize(tx: Transaction): number {
  if (!hasWitness(tx)) {
    return getTxBaseSize(tx);
  }

  let size = getTxBaseSize(tx);

  // Add marker(1) + flag(1)
  size += 2;

  // Add witness data
  for (const input of tx.inputs) {
    size += varIntSize(input.witness.length);
    for (const item of input.witness) {
      size += varIntSize(item.length) + item.length;
    }
  }

  return size;
}

/**
 * Calculate transaction weight (BIP-141).
 * weight = base_size * 3 + total_size
 */
export function getTxWeight(tx: Transaction): number {
  const baseSize = getTxBaseSize(tx);
  const totalSize = getTxTotalSize(tx);
  return baseSize * 3 + totalSize;
}

/**
 * Calculate transaction virtual size (vsize).
 * vsize = ceil(weight / 4)
 */
export function getTxVSize(tx: Transaction): number {
  return Math.ceil(getTxWeight(tx) / 4);
}

/**
 * BIP-143 sighash computation for segwit v0.
 *
 * Preimage format:
 * [version(4)][hashPrevouts(32)][hashSequence(32)][outpoint(36)]
 * [scriptCode(var)][value(8)][sequence(4)][hashOutputs(32)][locktime(4)][hashType(4)]
 */
export function sigHashWitnessV0(
  tx: Transaction,
  inputIndex: number,
  subscript: Buffer,
  value: bigint,
  hashType: number
): Buffer {
  if (inputIndex < 0 || inputIndex >= tx.inputs.length) {
    throw new Error(`Invalid input index: ${inputIndex}`);
  }

  const anyoneCanPay = (hashType & SIGHASH_ANYONECANPAY) !== 0;
  const sigHashBase = hashType & 0x1f;

  // hashPrevouts: double SHA-256 of all input outpoints (unless ANYONECANPAY)
  let hashPrevouts: Buffer;
  if (anyoneCanPay) {
    hashPrevouts = Buffer.alloc(32, 0);
  } else {
    const prevoutsWriter = new BufferWriter();
    for (const input of tx.inputs) {
      prevoutsWriter.writeHash(input.prevOut.txid);
      prevoutsWriter.writeUInt32LE(input.prevOut.vout);
    }
    hashPrevouts = hash256(prevoutsWriter.toBuffer());
  }

  // hashSequence: double SHA-256 of all input sequences
  // (unless ANYONECANPAY, SINGLE, or NONE)
  let hashSequence: Buffer;
  if (anyoneCanPay || sigHashBase === SIGHASH_SINGLE || sigHashBase === SIGHASH_NONE) {
    hashSequence = Buffer.alloc(32, 0);
  } else {
    const sequenceWriter = new BufferWriter();
    for (const input of tx.inputs) {
      sequenceWriter.writeUInt32LE(input.sequence);
    }
    hashSequence = hash256(sequenceWriter.toBuffer());
  }

  // hashOutputs: depends on sighash type
  let hashOutputs: Buffer;
  if (sigHashBase === SIGHASH_NONE) {
    hashOutputs = Buffer.alloc(32, 0);
  } else if (sigHashBase === SIGHASH_SINGLE) {
    if (inputIndex < tx.outputs.length) {
      const outputWriter = new BufferWriter();
      const output = tx.outputs[inputIndex];
      outputWriter.writeUInt64LE(output.value);
      outputWriter.writeVarBytes(output.scriptPubKey);
      hashOutputs = hash256(outputWriter.toBuffer());
    } else {
      hashOutputs = Buffer.alloc(32, 0);
    }
  } else {
    // SIGHASH_ALL
    const outputsWriter = new BufferWriter();
    for (const output of tx.outputs) {
      outputsWriter.writeUInt64LE(output.value);
      outputsWriter.writeVarBytes(output.scriptPubKey);
    }
    hashOutputs = hash256(outputsWriter.toBuffer());
  }

  // Build preimage
  const preimageWriter = new BufferWriter();
  preimageWriter.writeInt32LE(tx.version);
  preimageWriter.writeBytes(hashPrevouts);
  preimageWriter.writeBytes(hashSequence);

  // Current input's outpoint
  const currentInput = tx.inputs[inputIndex];
  preimageWriter.writeHash(currentInput.prevOut.txid);
  preimageWriter.writeUInt32LE(currentInput.prevOut.vout);

  // Script code (for P2WPKH: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG)
  preimageWriter.writeVarBytes(subscript);

  // Value being spent
  preimageWriter.writeUInt64LE(value);

  // Sequence
  preimageWriter.writeUInt32LE(currentInput.sequence);

  preimageWriter.writeBytes(hashOutputs);
  preimageWriter.writeUInt32LE(tx.lockTime);
  preimageWriter.writeUInt32LE(hashType);

  return hash256(preimageWriter.toBuffer());
}

/**
 * Legacy sighash computation (pre-segwit).
 *
 * Creates a modified copy of the transaction with:
 * - All input scripts cleared except the one being signed
 * - The subscript placed in the signing input
 * - Modifications based on sighash type
 */
export function sigHashLegacy(
  tx: Transaction,
  inputIndex: number,
  subscript: Buffer,
  hashType: number
): Buffer {
  if (inputIndex < 0 || inputIndex >= tx.inputs.length) {
    throw new Error(`Invalid input index: ${inputIndex}`);
  }

  const anyoneCanPay = (hashType & SIGHASH_ANYONECANPAY) !== 0;
  const sigHashBase = hashType & 0x1f;

  // Handle SIGHASH_SINGLE with inputIndex >= outputs.length
  // This is a Bitcoin quirk: returns hash of 0x01 (32 bytes zero-padded)
  if (sigHashBase === SIGHASH_SINGLE && inputIndex >= tx.outputs.length) {
    const oneHash = Buffer.alloc(32, 0);
    oneHash[0] = 1;
    return oneHash;
  }

  // Create modified transaction
  const writer = new BufferWriter();
  writer.writeInt32LE(tx.version);

  // Determine which inputs to include
  let inputsToSign: TxIn[];
  if (anyoneCanPay) {
    // Only the signing input
    inputsToSign = [tx.inputs[inputIndex]];
  } else {
    inputsToSign = tx.inputs;
  }

  writer.writeVarInt(inputsToSign.length);

  for (let i = 0; i < inputsToSign.length; i++) {
    const input = inputsToSign[i];
    const actualIndex = anyoneCanPay ? inputIndex : i;
    const isSigningInput = actualIndex === inputIndex;

    writer.writeHash(input.prevOut.txid);
    writer.writeUInt32LE(input.prevOut.vout);

    // Script: subscript for signing input, empty for others
    if (isSigningInput) {
      writer.writeVarBytes(subscript);
    } else {
      writer.writeVarBytes(Buffer.alloc(0));
    }

    // Sequence: modified for SIGHASH_NONE and SIGHASH_SINGLE (except signing input)
    if (
      !isSigningInput &&
      (sigHashBase === SIGHASH_NONE || sigHashBase === SIGHASH_SINGLE)
    ) {
      writer.writeUInt32LE(0);
    } else {
      writer.writeUInt32LE(input.sequence);
    }
  }

  // Determine outputs
  let outputsToInclude: TxOut[];
  if (sigHashBase === SIGHASH_NONE) {
    outputsToInclude = [];
  } else if (sigHashBase === SIGHASH_SINGLE) {
    // Include outputs up to and including the signing input's index
    outputsToInclude = tx.outputs.slice(0, inputIndex + 1);
  } else {
    outputsToInclude = tx.outputs;
  }

  writer.writeVarInt(outputsToInclude.length);

  for (let i = 0; i < outputsToInclude.length; i++) {
    const output = outputsToInclude[i];

    if (sigHashBase === SIGHASH_SINGLE && i < inputIndex) {
      // Outputs before the signing input are "nullified"
      writer.writeUInt64LE(0xffffffffffffffffn); // -1 as uint64
      writer.writeVarBytes(Buffer.alloc(0));
    } else {
      writer.writeUInt64LE(output.value);
      writer.writeVarBytes(output.scriptPubKey);
    }
  }

  writer.writeUInt32LE(tx.lockTime);

  // Append hash type as 4-byte little-endian
  writer.writeUInt32LE(hashType);

  return hash256(writer.toBuffer());
}

/**
 * Basic transaction validation (structure only, not script execution).
 */
export function validateTxBasic(tx: Transaction): { valid: boolean; error?: string } {
  // Must have at least one input
  if (tx.inputs.length === 0) {
    return { valid: false, error: "Transaction has no inputs" };
  }

  // Must have at least one output
  if (tx.outputs.length === 0) {
    return { valid: false, error: "Transaction has no outputs" };
  }

  // Check for duplicate inputs
  const seenOutpoints = new Set<string>();
  for (const input of tx.inputs) {
    const key = `${input.prevOut.txid.toString("hex")}:${input.prevOut.vout}`;
    if (seenOutpoints.has(key)) {
      return { valid: false, error: "Duplicate input" };
    }
    seenOutpoints.add(key);
  }

  // Check output values
  let totalOutput = 0n;
  for (const output of tx.outputs) {
    // Value must be non-negative
    if (output.value < 0n) {
      return { valid: false, error: "Negative output value" };
    }

    // Value must not exceed max coins (21M BTC = 2.1e15 satoshis)
    if (output.value > 2_100_000_000_000_000n) {
      return { valid: false, error: "Output value exceeds maximum" };
    }

    totalOutput += output.value;

    // Total must not overflow
    if (totalOutput > 2_100_000_000_000_000n) {
      return { valid: false, error: "Total output value exceeds maximum" };
    }
  }

  // Check transaction size (rough sanity check)
  const serialized = serializeTx(tx, true);
  if (serialized.length < 10) {
    return { valid: false, error: "Transaction too small" };
  }

  // Max transaction size is 100KB for standard transactions
  // (consensus allows up to 4MB weight)
  if (serialized.length > 4_000_000) {
    return { valid: false, error: "Transaction too large" };
  }

  return { valid: true };
}

/**
 * Check if a transaction is a coinbase transaction.
 */
export function isCoinbase(tx: Transaction): boolean {
  if (tx.inputs.length !== 1) {
    return false;
  }

  const input = tx.inputs[0];
  const nullTxid = Buffer.alloc(32, 0);

  return (
    input.prevOut.txid.equals(nullTxid) && input.prevOut.vout === 0xffffffff
  );
}

/**
 * BIP-143 sighash cache for efficient batch verification.
 * Caches hashPrevouts, hashSequence, and hashOutputs.
 */
export interface SigHashCache {
  hashPrevouts?: Buffer;
  hashSequence?: Buffer;
  hashOutputsAll?: Buffer;
}

/**
 * Compute BIP-143 sighash with cache support.
 * Reuses cached intermediate hashes when possible.
 */
export function sigHashWitnessV0Cached(
  tx: Transaction,
  inputIndex: number,
  subscript: Buffer,
  value: bigint,
  hashType: number,
  cache: SigHashCache
): Buffer {
  if (inputIndex < 0 || inputIndex >= tx.inputs.length) {
    throw new Error(`Invalid input index: ${inputIndex}`);
  }

  const anyoneCanPay = (hashType & SIGHASH_ANYONECANPAY) !== 0;
  const sigHashBase = hashType & 0x1f;

  // hashPrevouts: double SHA-256 of all input outpoints (unless ANYONECANPAY)
  let hashPrevouts: Buffer;
  if (anyoneCanPay) {
    hashPrevouts = Buffer.alloc(32, 0);
  } else {
    if (!cache.hashPrevouts) {
      const prevoutsWriter = new BufferWriter();
      for (const input of tx.inputs) {
        prevoutsWriter.writeHash(input.prevOut.txid);
        prevoutsWriter.writeUInt32LE(input.prevOut.vout);
      }
      cache.hashPrevouts = hash256(prevoutsWriter.toBuffer());
    }
    hashPrevouts = cache.hashPrevouts;
  }

  // hashSequence: double SHA-256 of all input sequences
  // (unless ANYONECANPAY, SINGLE, or NONE)
  let hashSequence: Buffer;
  if (anyoneCanPay || sigHashBase === SIGHASH_SINGLE || sigHashBase === SIGHASH_NONE) {
    hashSequence = Buffer.alloc(32, 0);
  } else {
    if (!cache.hashSequence) {
      const sequenceWriter = new BufferWriter();
      for (const input of tx.inputs) {
        sequenceWriter.writeUInt32LE(input.sequence);
      }
      cache.hashSequence = hash256(sequenceWriter.toBuffer());
    }
    hashSequence = cache.hashSequence;
  }

  // hashOutputs: depends on sighash type
  let hashOutputs: Buffer;
  if (sigHashBase === SIGHASH_NONE) {
    hashOutputs = Buffer.alloc(32, 0);
  } else if (sigHashBase === SIGHASH_SINGLE) {
    if (inputIndex < tx.outputs.length) {
      const outputWriter = new BufferWriter();
      const output = tx.outputs[inputIndex];
      outputWriter.writeUInt64LE(output.value);
      outputWriter.writeVarBytes(output.scriptPubKey);
      hashOutputs = hash256(outputWriter.toBuffer());
    } else {
      hashOutputs = Buffer.alloc(32, 0);
    }
  } else {
    // SIGHASH_ALL - can be cached
    if (!cache.hashOutputsAll) {
      const outputsWriter = new BufferWriter();
      for (const output of tx.outputs) {
        outputsWriter.writeUInt64LE(output.value);
        outputsWriter.writeVarBytes(output.scriptPubKey);
      }
      cache.hashOutputsAll = hash256(outputsWriter.toBuffer());
    }
    hashOutputs = cache.hashOutputsAll;
  }

  // Build preimage
  const preimageWriter = new BufferWriter();
  preimageWriter.writeInt32LE(tx.version);
  preimageWriter.writeBytes(hashPrevouts);
  preimageWriter.writeBytes(hashSequence);

  // Current input's outpoint
  const currentInput = tx.inputs[inputIndex];
  preimageWriter.writeHash(currentInput.prevOut.txid);
  preimageWriter.writeUInt32LE(currentInput.prevOut.vout);

  // Script code (for P2WPKH: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG)
  preimageWriter.writeVarBytes(subscript);

  // Value being spent
  preimageWriter.writeUInt64LE(value);

  // Sequence
  preimageWriter.writeUInt32LE(currentInput.sequence);

  preimageWriter.writeBytes(hashOutputs);
  preimageWriter.writeUInt32LE(tx.lockTime);
  preimageWriter.writeUInt32LE(hashType);

  return hash256(preimageWriter.toBuffer());
}

/**
 * Verify a single input script (simplified P2PKH/P2WPKH verification).
 *
 * For P2WPKH: witness[0] = signature (DER + sighash), witness[1] = pubkey
 */
export function verifyInputSignature(
  tx: Transaction,
  inputIndex: number,
  utxo: UTXOEntry,
  cache: SigHashCache
): InputVerifyResult {
  const input = tx.inputs[inputIndex];
  const scriptPubKey = utxo.scriptPubKey;

  // Check for P2WPKH: OP_0 <20 bytes>
  if (scriptPubKey.length === 22 &&
      scriptPubKey[0] === 0x00 &&
      scriptPubKey[1] === 0x14) {
    // Native P2WPKH
    if (input.witness.length !== 2) {
      return { valid: false, inputIndex, error: "P2WPKH requires 2 witness items" };
    }

    const signature = input.witness[0];
    const pubkey = input.witness[1];

    if (signature.length < 1) {
      return { valid: false, inputIndex, error: "Empty signature" };
    }

    if (pubkey.length !== 33 && pubkey.length !== 65) {
      return { valid: false, inputIndex, error: "Invalid public key length" };
    }

    // Extract sighash type from last byte of signature
    const hashType = signature[signature.length - 1];
    const derSig = signature.subarray(0, signature.length - 1);

    // Build P2WPKH script code: OP_DUP OP_HASH160 <pubkeyhash> OP_EQUALVERIFY OP_CHECKSIG
    const pubKeyHash = scriptPubKey.subarray(2, 22);
    const scriptCode = Buffer.concat([
      Buffer.from([0x76, 0xa9, 0x14]),
      pubKeyHash,
      Buffer.from([0x88, 0xac]),
    ]);

    // Compute sighash
    const sighash = sigHashWitnessV0Cached(tx, inputIndex, scriptCode, utxo.amount, hashType, cache);

    // Verify signature
    const valid = ecdsaVerify(derSig, sighash, pubkey);
    if (!valid) {
      return { valid: false, inputIndex, error: "Signature verification failed" };
    }

    return { valid: true, inputIndex };
  }

  // Check for P2PKH: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
  if (scriptPubKey.length === 25 &&
      scriptPubKey[0] === 0x76 &&
      scriptPubKey[1] === 0xa9 &&
      scriptPubKey[2] === 0x14 &&
      scriptPubKey[23] === 0x88 &&
      scriptPubKey[24] === 0xac) {
    // Legacy P2PKH
    if (input.scriptSig.length < 2) {
      return { valid: false, inputIndex, error: "Empty scriptSig for P2PKH" };
    }

    // Parse scriptSig: <sig> <pubkey>
    const reader = new BufferReader(input.scriptSig);

    // Read signature (pushed with length prefix)
    const sigLen = reader.readUInt8();
    if (sigLen > reader.remaining + 1) {
      return { valid: false, inputIndex, error: "Invalid signature length in scriptSig" };
    }
    const sigWithType = reader.readBytes(sigLen);

    // Read public key
    const pubkeyLen = reader.readUInt8();
    if (pubkeyLen > reader.remaining + 1) {
      return { valid: false, inputIndex, error: "Invalid pubkey length in scriptSig" };
    }
    const pubkey = reader.readBytes(pubkeyLen);

    if (sigWithType.length < 1) {
      return { valid: false, inputIndex, error: "Empty signature" };
    }

    // Extract sighash type and DER signature
    const hashType = sigWithType[sigWithType.length - 1];
    const derSig = sigWithType.subarray(0, sigWithType.length - 1);

    // Compute legacy sighash with scriptPubKey as subscript
    const sighash = sigHashLegacy(tx, inputIndex, scriptPubKey, hashType);

    // Verify signature
    const valid = ecdsaVerify(derSig, sighash, pubkey);
    if (!valid) {
      return { valid: false, inputIndex, error: "Signature verification failed" };
    }

    return { valid: true, inputIndex };
  }

  // For other script types, skip verification (would need full script interpreter)
  return { valid: true, inputIndex };
}

/**
 * Verify all input scripts in parallel using Promise.all.
 *
 * Uses a shared sighash cache for BIP-143 to avoid redundant computation.
 */
export async function verifyAllInputsParallel(
  tx: Transaction,
  utxos: UTXOEntry[],
  _flags: ScriptFlags = ScriptFlags.VERIFY_NONE
): Promise<TxVerifyResult> {
  // Skip verification for coinbase
  if (isCoinbase(tx)) {
    return { valid: true };
  }

  // Validate input count matches UTXO count
  if (tx.inputs.length !== utxos.length) {
    return { valid: false, error: "UTXO count mismatch" };
  }

  // Create shared sighash cache for BIP-143
  const cache: SigHashCache = {};

  // Create verification promises for each input
  const verifyPromises = tx.inputs.map((_, index) =>
    Promise.resolve(verifyInputSignature(tx, index, utxos[index], cache))
  );

  // Run all verifications in parallel
  const results = await Promise.all(verifyPromises);

  // Check for any failures
  for (const result of results) {
    if (!result.valid) {
      return {
        valid: false,
        error: result.error ?? "Input verification failed",
        failedInput: result.inputIndex,
      };
    }
  }

  return { valid: true };
}

/**
 * Verify all inputs sequentially (for comparison/fallback).
 */
export function verifyAllInputsSequential(
  tx: Transaction,
  utxos: UTXOEntry[],
  _flags: ScriptFlags = ScriptFlags.VERIFY_NONE
): TxVerifyResult {
  // Skip verification for coinbase
  if (isCoinbase(tx)) {
    return { valid: true };
  }

  // Validate input count matches UTXO count
  if (tx.inputs.length !== utxos.length) {
    return { valid: false, error: "UTXO count mismatch" };
  }

  // Create shared sighash cache for BIP-143
  const cache: SigHashCache = {};

  // Verify each input
  for (let i = 0; i < tx.inputs.length; i++) {
    const result = verifyInputSignature(tx, i, utxos[i], cache);
    if (!result.valid) {
      return {
        valid: false,
        error: result.error ?? "Input verification failed",
        failedInput: i,
      };
    }
  }

  return { valid: true };
}
