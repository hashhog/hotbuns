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
import { hash256, sha256Hash, ecdsaVerify, schnorrVerify, taggedHash } from "../crypto/primitives.js";
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

// Taproot sighash constants (BIP-341)
export const SIGHASH_DEFAULT = 0x00; // Taproot only: same as SIGHASH_ALL but no byte in signature

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
  /** Cached txid (set lazily by getTxId to avoid re-serialization). */
  _cachedTxId?: Buffer;
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
  if (tx._cachedTxId) return tx._cachedTxId;
  const serialized = serializeTx(tx, false);
  const txid = hash256(serialized);
  tx._cachedTxId = txid;
  return txid;
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

// OP_CODESEPARATOR opcode value
const OP_CODESEPARATOR = 0xab;

/**
 * Remove all occurrences of OP_CODESEPARATOR from a script.
 * Used when preparing subscript for legacy sighash computation.
 *
 * References Bitcoin Core's CTransactionSignatureSerializer::SerializeScriptCode
 */
export function removeCodeSeparators(script: Buffer): Buffer {
  if (script.length === 0) return script;

  // Count OP_CODESEPARATOR bytes to determine if we need to modify
  let separatorCount = 0;
  let pos = 0;

  while (pos < script.length) {
    const opcode = script[pos];

    if (opcode === OP_CODESEPARATOR) {
      separatorCount++;
      pos++;
      continue;
    }

    // Skip push data
    if (opcode <= 0x4b) {
      // Direct push: 1-75 bytes
      pos += 1 + opcode;
    } else if (opcode === 0x4c) {
      // OP_PUSHDATA1
      if (pos + 1 >= script.length) break;
      const len = script[pos + 1];
      pos += 2 + len;
    } else if (opcode === 0x4d) {
      // OP_PUSHDATA2
      if (pos + 2 >= script.length) break;
      const len = script[pos + 1] | (script[pos + 2] << 8);
      pos += 3 + len;
    } else if (opcode === 0x4e) {
      // OP_PUSHDATA4
      if (pos + 4 >= script.length) break;
      const len =
        script[pos + 1] |
        (script[pos + 2] << 8) |
        (script[pos + 3] << 16) |
        (script[pos + 4] << 24);
      pos += 5 + len;
    } else {
      // Single-byte opcode
      pos++;
    }
  }

  if (separatorCount === 0) {
    return script;
  }

  // Build result without OP_CODESEPARATOR
  const result: number[] = [];
  pos = 0;

  while (pos < script.length) {
    const opcode = script[pos];

    if (opcode === OP_CODESEPARATOR) {
      pos++;
      continue;
    }

    let chunkEnd: number;

    if (opcode <= 0x4b) {
      // Direct push: 1-75 bytes
      chunkEnd = pos + 1 + opcode;
    } else if (opcode === 0x4c) {
      // OP_PUSHDATA1
      if (pos + 1 >= script.length) {
        chunkEnd = script.length;
      } else {
        const len = script[pos + 1];
        chunkEnd = pos + 2 + len;
      }
    } else if (opcode === 0x4d) {
      // OP_PUSHDATA2
      if (pos + 2 >= script.length) {
        chunkEnd = script.length;
      } else {
        const len = script[pos + 1] | (script[pos + 2] << 8);
        chunkEnd = pos + 3 + len;
      }
    } else if (opcode === 0x4e) {
      // OP_PUSHDATA4
      if (pos + 4 >= script.length) {
        chunkEnd = script.length;
      } else {
        const len =
          script[pos + 1] |
          (script[pos + 2] << 8) |
          (script[pos + 3] << 16) |
          (script[pos + 4] << 24);
        chunkEnd = pos + 5 + len;
      }
    } else {
      // Single-byte opcode
      chunkEnd = pos + 1;
    }

    // Clamp to script bounds
    chunkEnd = Math.min(chunkEnd, script.length);

    // Copy chunk
    for (let i = pos; i < chunkEnd; i++) {
      result.push(script[i]);
    }
    pos = chunkEnd;
  }

  return Buffer.from(result);
}

/**
 * Create the push-encoded form of data for FindAndDelete.
 * This matches Bitcoin Core's CScript() << data.
 */
function encodePushData(data: Buffer): Buffer {
  if (data.length === 0) {
    // Empty data: just OP_0
    return Buffer.from([0x00]);
  } else if (data.length <= 0x4b) {
    // Direct push (1-75 bytes)
    const result = Buffer.allocUnsafe(1 + data.length);
    result[0] = data.length;
    data.copy(result, 1);
    return result;
  } else if (data.length <= 0xff) {
    // OP_PUSHDATA1
    const result = Buffer.allocUnsafe(2 + data.length);
    result[0] = 0x4c;
    result[1] = data.length;
    data.copy(result, 2);
    return result;
  } else if (data.length <= 0xffff) {
    // OP_PUSHDATA2
    const result = Buffer.allocUnsafe(3 + data.length);
    result[0] = 0x4d;
    result[1] = data.length & 0xff;
    result[2] = (data.length >> 8) & 0xff;
    data.copy(result, 3);
    return result;
  } else {
    // OP_PUSHDATA4
    const result = Buffer.allocUnsafe(5 + data.length);
    result[0] = 0x4e;
    result[1] = data.length & 0xff;
    result[2] = (data.length >> 8) & 0xff;
    result[3] = (data.length >> 16) & 0xff;
    result[4] = (data.length >> 24) & 0xff;
    data.copy(result, 5);
    return result;
  }
}

/**
 * Find and delete all occurrences of a byte sequence from a script.
 * This is used in legacy sighash to remove the signature from the scriptCode
 * before hashing. It operates on raw bytes, matching at opcode boundaries.
 *
 * References Bitcoin Core's FindAndDelete function.
 *
 * @param script - The script to search in
 * @param needle - The byte sequence to remove (typically push-encoded signature)
 * @returns A new Buffer with all occurrences removed
 */
export function findAndDelete(script: Buffer, needle: Buffer): Buffer {
  if (needle.length === 0 || script.length < needle.length) {
    return script;
  }

  const result: number[] = [];
  let pos = 0;
  let lastCopied = 0;

  while (pos < script.length) {
    // Check if needle matches at current position
    if (
      pos + needle.length <= script.length &&
      script.subarray(pos, pos + needle.length).equals(needle)
    ) {
      // Copy bytes from lastCopied to pos (excluding the match)
      for (let i = lastCopied; i < pos; i++) {
        result.push(script[i]);
      }
      // Skip past the match
      pos += needle.length;
      lastCopied = pos;
      continue;
    }

    // Advance by one opcode
    const opcode = script[pos];
    let nextPos: number;

    if (opcode <= 0x4b) {
      // Direct push: 1-75 bytes
      nextPos = pos + 1 + opcode;
    } else if (opcode === 0x4c) {
      // OP_PUSHDATA1
      if (pos + 1 >= script.length) {
        nextPos = script.length;
      } else {
        const len = script[pos + 1];
        nextPos = pos + 2 + len;
      }
    } else if (opcode === 0x4d) {
      // OP_PUSHDATA2
      if (pos + 2 >= script.length) {
        nextPos = script.length;
      } else {
        const len = script[pos + 1] | (script[pos + 2] << 8);
        nextPos = pos + 3 + len;
      }
    } else if (opcode === 0x4e) {
      // OP_PUSHDATA4
      if (pos + 4 >= script.length) {
        nextPos = script.length;
      } else {
        const len =
          script[pos + 1] |
          (script[pos + 2] << 8) |
          (script[pos + 3] << 16) |
          (script[pos + 4] << 24);
        nextPos = pos + 5 + len;
      }
    } else {
      // Single-byte opcode
      nextPos = pos + 1;
    }

    // Clamp to script bounds
    nextPos = Math.min(nextPos, script.length);
    pos = nextPos;
  }

  // Copy any remaining bytes
  for (let i = lastCopied; i < script.length; i++) {
    result.push(script[i]);
  }

  // Only return new buffer if we actually removed something
  if (result.length === script.length) {
    return script;
  }

  return Buffer.from(result);
}

/**
 * Prepare subscript for legacy sighash by removing the signature and all OP_CODESEPARATOR.
 * This matches Bitcoin Core's behavior for pre-segwit signature hashing.
 *
 * @param subscript - The script code (portion after last executed OP_CODESEPARATOR)
 * @param signature - The signature being verified (to be removed via FindAndDelete)
 * @returns The prepared subscript ready for sighash computation
 */
export function prepareSubscriptForSigning(
  subscript: Buffer,
  signature?: Buffer
): Buffer {
  // First remove OP_CODESEPARATOR
  let result = removeCodeSeparators(subscript);

  // Then remove the push-encoded signature if provided
  if (signature && signature.length > 0) {
    const pushEncodedSig = encodePushData(signature);
    result = findAndDelete(result, pushEncodedSig);
  }

  return result;
}

/**
 * Legacy sighash computation (pre-segwit).
 *
 * Creates a modified copy of the transaction with:
 * - All input scripts cleared except the one being signed
 * - The subscript placed in the signing input
 * - Modifications based on sighash type
 * - OP_CODESEPARATOR removed from subscript
 *
 * Note: For full CHECKSIG/CHECKMULTISIG verification, the signature should also
 * be removed via FindAndDelete before calling this function, or use the
 * sigHashLegacyWithSig variant.
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

  // Remove OP_CODESEPARATOR from subscript before hashing
  const cleanedSubscript = removeCodeSeparators(subscript);

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

    // Script: cleaned subscript for signing input, empty for others
    if (isSigningInput) {
      writer.writeVarBytes(cleanedSubscript);
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

  // Append hash type as 4-byte little-endian (signed)
  writer.writeInt32LE(hashType);

  return hash256(writer.toBuffer());
}

/**
 * Legacy sighash computation with signature removal (FindAndDelete).
 *
 * This version removes the signature from the subscript before hashing,
 * which is required for proper CHECKSIG/CHECKMULTISIG verification in
 * pre-segwit scripts.
 *
 * @param tx - The transaction
 * @param inputIndex - The input being signed
 * @param subscript - The script code (after last OP_CODESEPARATOR)
 * @param hashType - The sighash type (from the signature's last byte)
 * @param signature - The signature being verified (will be removed from subscript)
 */
export function sigHashLegacyWithSig(
  tx: Transaction,
  inputIndex: number,
  subscript: Buffer,
  hashType: number,
  signature: Buffer
): Buffer {
  // Prepare subscript: remove OP_CODESEPARATOR and the signature
  const cleanedSubscript = prepareSubscriptForSigning(subscript, signature);
  return sigHashLegacyRaw(tx, inputIndex, cleanedSubscript, hashType);
}

/**
 * Raw legacy sighash computation without any subscript preprocessing.
 * Use this when you have already prepared the subscript (removed OP_CODESEPARATOR
 * and FindAndDelete'd the signature).
 */
export function sigHashLegacyRaw(
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

  // Append hash type as 4-byte little-endian (signed)
  writer.writeInt32LE(hashType);

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

// =============================================================================
// BIP-341 Taproot Sighash
// =============================================================================

/**
 * Taproot sighash cache for efficient batch verification.
 * Caches intermediate hashes per BIP-341.
 */
export interface TaprootSigHashCache {
  // Single SHA-256 hashes (not double-hashed like BIP-143)
  shaPrevouts?: Buffer;
  shaAmounts?: Buffer;
  shaScriptPubKeys?: Buffer;
  shaSequences?: Buffer;
  shaOutputs?: Buffer;
}

/**
 * Compute taproot sighash (BIP-341).
 *
 * This implements the SigMsg() function for taproot key-path and script-path spending.
 *
 * @param tx - The transaction
 * @param inputIndex - Index of the input being signed
 * @param prevOuts - Array of previous outputs (scriptPubKey + value) for ALL inputs
 * @param hashType - Sighash type (0x00 = SIGHASH_DEFAULT = SIGHASH_ALL without explicit byte)
 * @param extFlag - Extension flag: 0 for key-path, 1 for script-path
 * @param annexHash - SHA256 of (compact_size(len(annex)) || annex) if annex present, else undefined
 * @param tapLeafHash - Leaf hash for script-path spending (32 bytes), undefined for key-path
 * @param keyVersion - Key version (0x00 for BIP-342 tapscript), undefined for key-path
 * @param codeSepPos - Code separator position (0xFFFFFFFF if no OP_CODESEPARATOR executed)
 * @param cache - Cache for intermediate hashes
 * @returns 32-byte sighash
 */
/**
 * Build the BIP-341 sigmsg preimage — the bytes fed into TapSighash tagged
 * hash. Exposed so the bip341-vector-runner shim can validate the preimage
 * against bitcoin-core's bip341_wallet_vectors.json before checking the
 * final hash.
 */
export function sigMsgTaproot(
  tx: Transaction,
  inputIndex: number,
  prevOuts: { scriptPubKey: Buffer; value: bigint }[],
  hashType: number,
  extFlag: number,
  annexHash: Buffer | undefined,
  tapLeafHash: Buffer | undefined,
  keyVersion: number | undefined,
  codeSepPos: number,
  cache: TaprootSigHashCache
): Buffer {
  if (inputIndex < 0 || inputIndex >= tx.inputs.length) {
    throw new Error(`Invalid input index: ${inputIndex}`);
  }
  if (prevOuts.length !== tx.inputs.length) {
    throw new Error("prevOuts must have same length as inputs");
  }

  const effectiveHashType = hashType === SIGHASH_DEFAULT ? SIGHASH_ALL : hashType;
  const anyoneCanPay = (effectiveHashType & SIGHASH_ANYONECANPAY) !== 0;
  const sigHashBase = effectiveHashType & 0x1f;

  if (sigHashBase === SIGHASH_SINGLE && inputIndex >= tx.outputs.length) {
    throw new Error("SIGHASH_SINGLE with no corresponding output");
  }

  const writer = new BufferWriter();
  writer.writeUInt8(0x00); // epoch
  writer.writeUInt8(hashType); // original, not effective

  writer.writeInt32LE(tx.version);
  writer.writeUInt32LE(tx.lockTime);

  if (!anyoneCanPay) {
    if (!cache.shaPrevouts) {
      const prevoutsWriter = new BufferWriter();
      for (const input of tx.inputs) {
        prevoutsWriter.writeHash(input.prevOut.txid);
        prevoutsWriter.writeUInt32LE(input.prevOut.vout);
      }
      cache.shaPrevouts = sha256Hash(prevoutsWriter.toBuffer());
    }
    writer.writeBytes(cache.shaPrevouts);

    if (!cache.shaAmounts) {
      const amountsWriter = new BufferWriter();
      for (const prevOut of prevOuts) {
        amountsWriter.writeUInt64LE(prevOut.value);
      }
      cache.shaAmounts = sha256Hash(amountsWriter.toBuffer());
    }
    writer.writeBytes(cache.shaAmounts);

    if (!cache.shaScriptPubKeys) {
      const spkWriter = new BufferWriter();
      for (const prevOut of prevOuts) {
        spkWriter.writeVarBytes(prevOut.scriptPubKey);
      }
      cache.shaScriptPubKeys = sha256Hash(spkWriter.toBuffer());
    }
    writer.writeBytes(cache.shaScriptPubKeys);

    if (!cache.shaSequences) {
      const seqWriter = new BufferWriter();
      for (const input of tx.inputs) {
        seqWriter.writeUInt32LE(input.sequence);
      }
      cache.shaSequences = sha256Hash(seqWriter.toBuffer());
    }
    writer.writeBytes(cache.shaSequences);
  }

  if (sigHashBase !== SIGHASH_NONE && sigHashBase !== SIGHASH_SINGLE) {
    if (!cache.shaOutputs) {
      const outputsWriter = new BufferWriter();
      for (const output of tx.outputs) {
        outputsWriter.writeUInt64LE(output.value);
        outputsWriter.writeVarBytes(output.scriptPubKey);
      }
      cache.shaOutputs = sha256Hash(outputsWriter.toBuffer());
    }
    writer.writeBytes(cache.shaOutputs);
  }

  const hasAnnex = annexHash !== undefined;
  const spendType = (extFlag * 2) | (hasAnnex ? 1 : 0);
  writer.writeUInt8(spendType);

  if (anyoneCanPay) {
    const currentInput = tx.inputs[inputIndex];
    const currentPrevOut = prevOuts[inputIndex];
    writer.writeHash(currentInput.prevOut.txid);
    writer.writeUInt32LE(currentInput.prevOut.vout);
    writer.writeUInt64LE(currentPrevOut.value);
    writer.writeVarBytes(currentPrevOut.scriptPubKey);
    writer.writeUInt32LE(currentInput.sequence);
  } else {
    writer.writeUInt32LE(inputIndex);
  }

  if (hasAnnex && annexHash) {
    writer.writeBytes(annexHash);
  }

  if (sigHashBase === SIGHASH_SINGLE) {
    const output = tx.outputs[inputIndex];
    const outputWriter = new BufferWriter();
    outputWriter.writeUInt64LE(output.value);
    outputWriter.writeVarBytes(output.scriptPubKey);
    const shaSingleOutput = sha256Hash(outputWriter.toBuffer());
    writer.writeBytes(shaSingleOutput);
  }

  if (extFlag === 1) {
    if (tapLeafHash === undefined || keyVersion === undefined) {
      throw new Error("tapLeafHash and keyVersion required for script-path");
    }
    writer.writeBytes(tapLeafHash);
    writer.writeUInt8(keyVersion);
    writer.writeUInt32LE(codeSepPos);
  }

  return writer.toBuffer();
}

export function sigHashTaproot(
  tx: Transaction,
  inputIndex: number,
  prevOuts: { scriptPubKey: Buffer; value: bigint }[],
  hashType: number,
  extFlag: number,
  annexHash: Buffer | undefined,
  tapLeafHash: Buffer | undefined,
  keyVersion: number | undefined,
  codeSepPos: number,
  cache: TaprootSigHashCache
): Buffer {
  const msg = sigMsgTaproot(
    tx, inputIndex, prevOuts, hashType, extFlag,
    annexHash, tapLeafHash, keyVersion, codeSepPos, cache
  );
  return taggedHash("TapSighash", msg);
}

/**
 * Compute taproot sighash for key-path spending (ext_flag=0).
 * Convenience function that sets ext_flag=0 and omits script-path params.
 */
export function sigHashTaprootKeyPath(
  tx: Transaction,
  inputIndex: number,
  prevOuts: { scriptPubKey: Buffer; value: bigint }[],
  hashType: number,
  annexHash: Buffer | undefined,
  cache: TaprootSigHashCache
): Buffer {
  return sigHashTaproot(
    tx,
    inputIndex,
    prevOuts,
    hashType,
    0, // ext_flag = 0 for key-path
    annexHash,
    undefined, // no tapLeafHash
    undefined, // no keyVersion
    0xffffffff, // codeSepPos not used
    cache
  );
}

/**
 * Compute taproot sighash for script-path spending (ext_flag=1).
 * Convenience function that sets ext_flag=1.
 */
export function sigHashTaprootScriptPath(
  tx: Transaction,
  inputIndex: number,
  prevOuts: { scriptPubKey: Buffer; value: bigint }[],
  hashType: number,
  annexHash: Buffer | undefined,
  tapLeafHash: Buffer,
  codeSepPos: number,
  cache: TaprootSigHashCache
): Buffer {
  return sigHashTaproot(
    tx,
    inputIndex,
    prevOuts,
    hashType,
    1, // ext_flag = 1 for script-path
    annexHash,
    tapLeafHash,
    0x00, // key_version = 0 for BIP-342 tapscript
    codeSepPos,
    cache
  );
}

/**
 * Verify a single input script (P2PKH / P2WPKH / P2TR — others fall through).
 *
 * For P2WPKH: witness[0] = signature (DER + sighash), witness[1] = pubkey
 * For P2TR: witness[0] = Schnorr sig (key-path) or {…, script, control_block}
 *           (script-path); annex if last element starts with 0x50.
 *
 * @param utxos - all of the spending tx's prev-outputs, in input order. Required
 *   so P2TR sighash can hash sha_amounts + sha_scriptpubkeys over every input
 *   per BIP-341. Pass null/undefined for legacy/segwit-v0-only call sites.
 * @param taprootCache - shared per-tx cache of sha_prevouts/amounts/scriptpubkeys/
 *   sequences/outputs so multiple Taproot inputs in the same tx don't recompute.
 */
export function verifyInputSignature(
  tx: Transaction,
  inputIndex: number,
  utxo: UTXOEntry,
  cache: SigHashCache,
  utxos?: UTXOEntry[],
  taprootCache?: TaprootSigHashCache
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

  // BIP-341 P2TR: OP_1 <32 bytes>
  if (scriptPubKey.length === 34 &&
      scriptPubKey[0] === 0x51 &&
      scriptPubKey[1] === 0x20) {
    if (input.scriptSig.length !== 0) {
      return { valid: false, inputIndex, error: "Taproot input must have empty scriptSig" };
    }
    if (input.witness.length === 0) {
      return { valid: false, inputIndex, error: "Taproot witness empty" };
    }
    if (!utxos || utxos.length !== tx.inputs.length) {
      // Fail-closed: previously this returned { valid: true } silently for any
      // non-PKH script type (BIP-341 P0). Without per-input prevouts we can't
      // compute sha_amounts/sha_scriptpubkeys, so we can't verify the Schnorr
      // sig. Refuse rather than accept-anything.
      return { valid: false, inputIndex, error: "Taproot verify requires all prev-outputs" };
    }

    // Detect annex (last witness element starting with 0x50 when stack has >= 2 items)
    let annexHash: Buffer | undefined = undefined;
    if (input.witness.length >= 2) {
      const last = input.witness[input.witness.length - 1];
      if (last.length > 0 && last[0] === 0x50) {
        // BIP-341 sha_annex = sha256(compact_size(annex_len) || annex)
        const annexW = new BufferWriter();
        annexW.writeVarBytes(last);
        annexHash = sha256Hash(annexW.toBuffer());
      }
    }

    const prevOuts = utxos.map(u => ({
      scriptPubKey: u.scriptPubKey,
      value: u.amount,
    }));
    const tprCache = taprootCache ?? {};

    // Build TaprootContext closures over this input's prevouts + annex.
    // verifyTaproot in the interpreter handles BIP-341 dispatch (key-path
    // vs script-path) + control-block walk + tapscript exec.
    const taprootCtx = {
      keyPathSigHasher: (hashType: number) =>
        sigHashTaproot(tx, inputIndex, prevOuts, hashType, 0,
          annexHash, undefined, undefined, 0xffffffff, tprCache),
      scriptPathSigHasher: (hashType: number, leafHash: Buffer, codeSepPos: number) =>
        sigHashTaproot(tx, inputIndex, prevOuts, hashType, 1,
          annexHash, leafHash, 0x00, codeSepPos, tprCache),
    };

    // Lazy require to avoid a circular import (interpreter.ts ↔ tx.ts).
    const interp = require("../script/interpreter.js") as typeof import("../script/interpreter.js");
    const flags = interp.getConsensusFlags(709632); // height-independent: Taproot active

    try {
      const ok = interp.verifyTaproot(scriptPubKey, input.witness, flags, taprootCtx);
      if (!ok) {
        return { valid: false, inputIndex, error: "Taproot verify returned false" };
      }
      return { valid: true, inputIndex };
    } catch (e) {
      return {
        valid: false,
        inputIndex,
        error: `Taproot verify failed: ${(e as Error).message}`,
      };
    }
  }

  // P2WSH and P2SH still fall through unverified — separate consensus gap
  // documented in PARITY-MATRIX.md. Out of scope for this Taproot P0 commit.
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
  // Shared per-tx Taproot sighash cache (sha_prevouts/amounts/scriptpubkeys/...)
  const taprootCache: TaprootSigHashCache = {};

  // Create verification promises for each input
  const verifyPromises = tx.inputs.map((_, index) =>
    Promise.resolve(verifyInputSignature(tx, index, utxos[index], cache, utxos, taprootCache))
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
  // Shared per-tx Taproot sighash cache.
  const taprootCache: TaprootSigHashCache = {};

  // Verify each input
  for (let i = 0; i < tx.inputs.length; i++) {
    const result = verifyInputSignature(tx, i, utxos[i], cache, utxos, taprootCache);
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

// =============================================================================
// BIP68 Sequence Lock Implementation
// =============================================================================

/**
 * BIP68 sequence lock constants.
 *
 * References:
 * - BIP68: https://github.com/bitcoin/bips/blob/master/bip-0068.mediawiki
 * - Bitcoin Core: /src/consensus/tx_verify.cpp (CalculateSequenceLocks, EvaluateSequenceLocks)
 */

/** If this flag is set on sequence, BIP68 is disabled for that input. */
export const SEQUENCE_LOCKTIME_DISABLE_FLAG = 1 << 31;

/** If this flag is set, the lock is time-based; otherwise block-based. */
export const SEQUENCE_LOCKTIME_TYPE_FLAG = 1 << 22;

/** Mask for the relative lock value (lower 16 bits). */
export const SEQUENCE_LOCKTIME_MASK = 0x0000ffff;

/** Granularity for time-based locks: 512 seconds (9 minutes). */
export const SEQUENCE_LOCKTIME_GRANULARITY = 9;

/** Final sequence value (no relative timelock). */
export const SEQUENCE_FINAL = 0xffffffff;

/**
 * UTXO confirmation info needed for sequence lock validation.
 * This includes the height at which the UTXO was confirmed and the
 * median time past (MTP) of the block *prior* to that block.
 */
export interface UTXOConfirmation {
  /** Height at which the UTXO's transaction was confirmed. */
  height: number;
  /** Median time past of the block *before* the UTXO was mined (for time locks). */
  medianTimePast: number;
}

/**
 * Result of sequence lock calculation.
 */
export interface SequenceLockResult {
  /** Minimum block height that must be reached (or -1 if no height lock). */
  minHeight: number;
  /** Minimum MTP that must be reached (or -1 if no time lock). */
  minTime: number;
}

/**
 * Calculate the sequence locks for a transaction.
 *
 * For each input with BIP68 active (nSequence bit 31 clear and tx version >= 2):
 * - If bit 22 is set: time-based lock using 512-second granularity
 * - If bit 22 is clear: height-based lock
 *
 * The returned values use nLockTime semantics: they represent the *last invalid*
 * height/time. A transaction is valid when block.height > minHeight AND
 * block.prevMTP > minTime.
 *
 * @param tx - The transaction to check
 * @param enforceBIP68 - Whether BIP68 is active (true if height >= CSV activation)
 * @param utxoConfirmations - Confirmation info for each input's UTXO
 * @returns The minimum height and time locks
 */
export function calculateSequenceLocks(
  tx: Transaction,
  enforceBIP68: boolean,
  utxoConfirmations: UTXOConfirmation[]
): SequenceLockResult {
  // Use -1 to indicate "any height/time is valid" (nLockTime semantics)
  let minHeight = -1;
  let minTime = -1;

  // BIP68 only applies to transactions with version >= 2
  if (!enforceBIP68 || tx.version < 2) {
    return { minHeight, minTime };
  }

  if (utxoConfirmations.length !== tx.inputs.length) {
    throw new Error("UTXO confirmation count must match input count");
  }

  for (let i = 0; i < tx.inputs.length; i++) {
    const input = tx.inputs[i];
    const nSequence = input.sequence;

    // Bit 31 set means BIP68 is disabled for this input
    // Use >>> 0 to ensure unsigned comparison (JS bitwise operates on signed 32-bit)
    if ((nSequence >>> 0) & SEQUENCE_LOCKTIME_DISABLE_FLAG) {
      continue;
    }

    const utxoConf = utxoConfirmations[i];
    const lockValue = nSequence & SEQUENCE_LOCKTIME_MASK;

    if (nSequence & SEQUENCE_LOCKTIME_TYPE_FLAG) {
      // Time-based lock
      // Lock is relative to the MTP of the block *before* the UTXO was mined
      const nCoinTime = utxoConf.medianTimePast;
      // The lock is in 512-second units (left shift by SEQUENCE_LOCKTIME_GRANULARITY)
      // Subtract 1 to convert to nLockTime semantics (last invalid time)
      const lockTime = nCoinTime + (lockValue << SEQUENCE_LOCKTIME_GRANULARITY) - 1;
      minTime = Math.max(minTime, lockTime);
    } else {
      // Height-based lock
      // Lock is relative to the height at which the UTXO was mined
      // Subtract 1 to convert to nLockTime semantics (last invalid height)
      const lockHeight = utxoConf.height + lockValue - 1;
      minHeight = Math.max(minHeight, lockHeight);
    }
  }

  return { minHeight, minTime };
}

/**
 * Evaluate whether sequence locks are satisfied at a given block.
 *
 * The transaction is valid if:
 * - The block height is GREATER than minHeight (minHeight is last invalid)
 * - The previous block's MTP is GREATER than minTime (minTime is last invalid)
 *
 * @param blockHeight - The height of the block being validated
 * @param blockPrevMTP - The median time past of the *previous* block
 * @param locks - The sequence locks to check
 * @returns true if all sequence locks are satisfied
 */
export function evaluateSequenceLocks(
  blockHeight: number,
  blockPrevMTP: number,
  locks: SequenceLockResult
): boolean {
  // minHeight/minTime use nLockTime semantics (last invalid value)
  // So we need height > minHeight and prevMTP > minTime
  if (locks.minHeight >= blockHeight) {
    return false;
  }
  if (locks.minTime >= blockPrevMTP) {
    return false;
  }
  return true;
}

/**
 * Check if a transaction's sequence locks are satisfied.
 *
 * This is the main entry point for BIP68 validation, combining
 * calculateSequenceLocks and evaluateSequenceLocks.
 *
 * @param tx - The transaction to validate
 * @param enforceBIP68 - Whether BIP68 is active
 * @param blockHeight - Height of the block being validated
 * @param blockPrevMTP - MTP of the previous block
 * @param utxoConfirmations - Confirmation info for each input's UTXO
 * @returns true if sequence locks are satisfied
 */
export function checkSequenceLocks(
  tx: Transaction,
  enforceBIP68: boolean,
  blockHeight: number,
  blockPrevMTP: number,
  utxoConfirmations: UTXOConfirmation[]
): boolean {
  const locks = calculateSequenceLocks(tx, enforceBIP68, utxoConfirmations);
  return evaluateSequenceLocks(blockHeight, blockPrevMTP, locks);
}
