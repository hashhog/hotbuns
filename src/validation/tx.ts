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
import { globalSigCache } from "./sig_cache.js";
// Type-only import — erased at compile time, so it does NOT create the
// runtime interpreter.ts ↔ tx.ts cycle that the lazy require()s below avoid.
import type { TaprootContext } from "../script/interpreter.js";

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
  /** BIP-341 Taproot (consensus). Active on mainnet from height 709632. */
  VERIFY_TAPROOT = 1 << 9,
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
    // Since BufferReader doesn't support unread, handle inline.
    // Non-canonical encoding is rejected (Core: "non-canonical ReadCompactSize()").
    if (marker <= 0xfc) {
      inputCount = marker;
    } else if (marker === 0xfd) {
      const raw16 = reader.readUInt16LE();
      if (raw16 < 253) {
        throw new Error("non-canonical CompactSize");
      }
      inputCount = raw16;
    } else if (marker === 0xfe) {
      const raw32 = reader.readUInt32LE();
      if (raw32 < 0x10000) {
        throw new Error("non-canonical CompactSize");
      }
      inputCount = raw32;
    } else {
      // 0xff - 8 byte varint, but for input counts this shouldn't happen
      const bigVal = reader.readUInt64LE();
      if (bigVal < 0x100000000n) {
        throw new Error("non-canonical CompactSize");
      }
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
    // Core primitives/transaction.h:228-231: it is illegal to encode witnesses
    // when all witness stacks are empty (BIP144 segwit marker+flag present but
    // tx.HasWitness() is false).  Throw exactly as Core does.
    const hasWitness = inputs.some((inp) => inp.witness.length > 0);
    if (!hasWitness) {
      throw new Error("Superfluous witness record");
    }
  }

  const lockTime = reader.readUInt32LE();

  return { version, inputs, outputs, lockTime };
}

/**
 * Deserialize a transaction in LEGACY (non-witness) form only.
 *
 * Mirrors Core's `TX_NO_WITNESS` deserialization (allow_witness=false): the
 * byte after `version` is always interpreted as the input-count varint, never
 * as a segwit `0x00` marker. A genuinely witness-serialized hex (which starts
 * with the `0x00 0x01` marker/flag, i.e. a zero-input vin under legacy rules)
 * therefore parses differently here — exactly as Core's two decoders diverge.
 */
function deserializeTxLegacy(reader: BufferReader): Transaction {
  const version = reader.readInt32LE();

  // Input count varint (no segwit-marker special-casing).
  const inputCount = reader.readVarInt();

  const inputs: TxIn[] = [];
  for (let i = 0; i < inputCount; i++) {
    const txidBytes = reader.readHash();
    const vout = reader.readUInt32LE();
    const scriptSig = reader.readVarBytes();
    const sequence = reader.readUInt32LE();
    inputs.push({
      prevOut: { txid: txidBytes, vout },
      scriptSig,
      sequence,
      witness: [],
    });
  }

  const outputCount = reader.readVarInt();
  const outputs: TxOut[] = [];
  for (let i = 0; i < outputCount; i++) {
    const value = reader.readUInt64LE();
    const scriptPubKey = reader.readVarBytes();
    outputs.push({ value, scriptPubKey });
  }

  const lockTime = reader.readUInt32LE();
  return { version, inputs, outputs, lockTime };
}

/**
 * Lightweight equivalent of Core's `CheckTxScriptsSanity` tie-breaker used by
 * `DecodeTx`. Core checks every input scriptSig (non-coinbase) and every output
 * scriptPubKey decodes as a valid op sequence and is within MAX_SCRIPT_SIZE.
 * We only need it to break the rare tie where BOTH the witness and legacy
 * decodes fully consume the input; a too-large script is the practical signal.
 */
const MAX_SCRIPT_SIZE = 10000;

function checkTxScriptsSanity(tx: Transaction): boolean {
  const isCoinbase =
    tx.inputs.length === 1 &&
    tx.inputs[0].prevOut.vout === 0xffffffff &&
    tx.inputs[0].prevOut.txid.every((b) => b === 0);
  if (!isCoinbase) {
    for (const input of tx.inputs) {
      if (input.scriptSig.length > MAX_SCRIPT_SIZE) return false;
    }
  }
  for (const output of tx.outputs) {
    if (output.scriptPubKey.length > MAX_SCRIPT_SIZE) return false;
  }
  return true;
}

/** A decode attempt that succeeded only if it fully consumed the input. */
function tryDecode(
  bytes: Buffer,
  decode: (r: BufferReader) => Transaction,
): Transaction | null {
  const reader = new BufferReader(bytes);
  let tx: Transaction;
  try {
    tx = decode(reader);
  } catch {
    return null;
  }
  // Core ignores serializations that do not fully consume the hex string.
  if (!reader.eof) return null;
  return tx;
}

/**
 * Decode a network-serialized transaction honoring an explicit witness hint,
 * faithfully mirroring Bitcoin Core's `DecodeTx(try_no_witness, try_witness)`
 * (core_io.cpp). Used by the `converttopsbt` RPC.
 *
 *   - try_witness    enables the extended (BIP-144 witness) deserialization.
 *   - try_no_witness enables the legacy (no-witness) deserialization.
 *
 * A serialization is only accepted if it FULLY consumes the input. If both
 * decode attempts succeed, the one passing `checkTxScriptsSanity` wins; if
 * neither or both pass, the extended one wins (Core's documented tie-break).
 *
 * Throws an Error (caller maps to RPC -22) when neither permitted form decodes.
 */
export function decodeTxWitnessAware(
  bytes: Buffer,
  tryNoWitness: boolean,
  tryWitness: boolean,
): Transaction {
  // Extended (witness) decode — deserializeTx interprets the 0x00/0x01 marker.
  const txExtended = tryWitness ? tryDecode(bytes, deserializeTx) : null;
  // Fast path: extended decodes and is sane (Core's early-return optimization).
  if (txExtended && checkTxScriptsSanity(txExtended)) {
    return txExtended;
  }

  // Legacy (no-witness) decode.
  const txLegacy = tryNoWitness ? tryDecode(bytes, deserializeTxLegacy) : null;
  if (txLegacy && checkTxScriptsSanity(txLegacy)) {
    return txLegacy;
  }

  // Neither (or both) passed sanity: prefer extended, then legacy.
  if (txExtended) return txExtended;
  if (txLegacy) return txLegacy;

  throw new Error("TX decode failed");
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
 * Calculate transaction virtual size (vsize, naive — no sigop adjustment).
 * vsize = ceil(weight / 4)
 *
 * This is the plain vsize used for RPC output fields like
 * decoderawtransaction.vsize. For mempool fee-rate math, use
 * getSigOpsAdjustedVSize() which accounts for sigop cost inflation.
 */
export function getTxVSize(tx: Transaction): number {
  return Math.ceil(getTxWeight(tx) / 4);
}

/**
 * Compute the sigop-adjusted weight of a transaction.
 *
 * Mirrors Bitcoin Core GetSigOpsAdjustedWeight() (policy/policy.cpp:390-393):
 *   return std::max(weight, sigop_cost * bytes_per_sigop);
 *
 * Reference: bitcoin-core/src/policy/policy.h:196
 */
export function getSigOpsAdjustedWeight(
  weight: number,
  sigOpCost: number,
  bytesPerSigop: number
): number {
  return Math.max(weight, sigOpCost * bytesPerSigop);
}

/**
 * Compute the virtual size of a transaction, optionally adjusted for sigop cost.
 *
 * Mirrors Bitcoin Core GetVirtualTransactionSize() (policy/policy.cpp:395-398):
 *   return (GetSigOpsAdjustedWeight(nWeight, nSigOpCost, bytes_per_sigop)
 *           + WITNESS_SCALE_FACTOR - 1) / WITNESS_SCALE_FACTOR;
 *
 * When sigOpCost and bytesPerSigop are 0, this reduces to the naive vsize.
 *
 * Reference: bitcoin-core/src/policy/policy.h:182-188
 */
export function getVirtualTransactionSize(
  weight: number,
  sigOpCost: number,
  bytesPerSigop: number
): number {
  const adjWeight = getSigOpsAdjustedWeight(weight, sigOpCost, bytesPerSigop);
  return Math.ceil(adjWeight / 4); // WITNESS_SCALE_FACTOR = 4
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
 *
 * Mirrors Bitcoin Core consensus/tx_check.cpp::CheckTransaction gate-for-gate:
 *   1. bad-txns-vin-empty
 *   2. bad-txns-vout-empty
 *   3. bad-txns-oversize  (stripped_size * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT)
 *   4. bad-txns-vout-negative   (CVE-2010-5139)
 *   5. bad-txns-vout-toolarge   (CVE-2010-5139)
 *   6. bad-txns-txouttotal-toolarge (CVE-2010-5139)
 *   7. bad-txns-inputs-duplicate    (CVE-2018-17144)
 *   8. bad-cb-length    (coinbase scriptSig 2..100 bytes)
 *   9. bad-txns-prevout-null  (non-coinbase inputs must not have null prevout)
 *
 * Error strings match Core's reject reason tokens exactly so they flow through
 * bip22Result() / P2P reject messages unchanged.
 *
 * Reference: bitcoin-core/src/consensus/tx_check.cpp:11-59
 */
export function validateTxBasic(tx: Transaction): { valid: boolean; error?: string } {
  // Gate 1: bad-txns-vin-empty
  // Core tx_check.cpp:14-15
  if (tx.inputs.length === 0) {
    return { valid: false, error: "bad-txns-vin-empty" };
  }

  // Gate 2: bad-txns-vout-empty
  // Core tx_check.cpp:16-17
  if (tx.outputs.length === 0) {
    return { valid: false, error: "bad-txns-vout-empty" };
  }

  // Gate 3: bad-txns-oversize
  // Core tx_check.cpp:18-21:
  //   GetSerializeSize(TX_NO_WITNESS(tx)) * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT
  // i.e. stripped_size * 4 > 4_000_000  →  stripped_size > 1_000_000.
  // We check stripped (non-witness) size * 4, NOT total wire size.
  const strippedSize = serializeTx(tx, false).length;
  if (strippedSize * 4 > 4_000_000) {
    return { valid: false, error: "bad-txns-oversize" };
  }

  // Gates 4-6: output value range checks (CVE-2010-5139).
  // Core tx_check.cpp:23-34.
  // NOTE: value is deserialized from wire as uint64 (readUInt64LE), but Bitcoin's
  // wire format is signed int64.  A negative wire value (e.g. -1 = 0xffffffffffffffff)
  // will have the high bit set, producing a large unsigned bigint.  We must
  // reinterpret as signed before the negative check — mirrors Core (negative before toolarge).
  const MAX_MONEY = 2_100_000_000_000_000n; // 21_000_000 * COIN
  const INT64_MAX = 0x7fffffffffffffffn;
  const UINT64_WRAP = 0x10000000000000000n; // 2^64
  let totalOutput = 0n;
  for (const output of tx.outputs) {
    // Reinterpret uint64 as int64: if high bit is set, value is negative.
    const signedValue = output.value > INT64_MAX ? output.value - UINT64_WRAP : output.value;

    // Gate 4: bad-txns-vout-negative
    if (signedValue < 0n) {
      return { valid: false, error: "bad-txns-vout-negative" };
    }

    // Gate 5: bad-txns-vout-toolarge
    if (output.value > MAX_MONEY) {
      return { valid: false, error: "bad-txns-vout-toolarge" };
    }

    totalOutput += output.value;

    // Gate 6: bad-txns-txouttotal-toolarge
    if (totalOutput > MAX_MONEY) {
      return { valid: false, error: "bad-txns-txouttotal-toolarge" };
    }
  }

  // Gate 7: bad-txns-inputs-duplicate (CVE-2018-17144).
  // Core tx_check.cpp:36-45.
  // Failure to check this causes either a crash or an inflation bug depending
  // on the underlying UTXO DB implementation — this is the CVE-2018-17144 class.
  const seenOutpoints = new Set<string>();
  for (const input of tx.inputs) {
    const key = `${input.prevOut.txid.toString("hex")}:${input.prevOut.vout}`;
    if (seenOutpoints.has(key)) {
      return { valid: false, error: "bad-txns-inputs-duplicate" };
    }
    seenOutpoints.add(key);
  }

  // Gates 8-9: coinbase vs non-coinbase specific checks.
  // Core tx_check.cpp:47-57.
  const coinbaseTx = isCoinbase(tx);
  if (coinbaseTx) {
    // Gate 8: bad-cb-length — coinbase scriptSig must be 2..100 bytes.
    // Core: COINBASE_SCRIPT_SIZE_MIN=2, COINBASE_SCRIPT_SIZE_MAX=100.
    const cbLen = tx.inputs[0].scriptSig.length;
    if (cbLen < 2 || cbLen > 100) {
      return { valid: false, error: "bad-cb-length" };
    }
  } else {
    // Gate 9: bad-txns-prevout-null — non-coinbase inputs must not reference null outpoints.
    // Core tx_check.cpp:54-56: if (txin.prevout.IsNull()) → "bad-txns-prevout-null".
    // A null prevout (all-zero txid + 0xffffffff vout) is reserved for coinbase
    // transactions only; encountering it in a non-coinbase tx is a consensus error.
    const NULL_TXID = Buffer.alloc(32, 0);
    for (const input of tx.inputs) {
      if (input.prevOut.txid.equals(NULL_TXID) && input.prevOut.vout === 0xffffffff) {
        return { valid: false, error: "bad-txns-prevout-null" };
      }
    }
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
 * Build the BIP-341 TaprootContext — key-path AND script-path sighash
 * closures over ALL prevouts — for one input of `tx`.
 *
 * Shared by block validation (`verifyInputSignature`: both the dedicated
 * P2TR branch and the catch-all `verifyScript` branch) and by mempool ATMP
 * (`mempool.ts` verifyAllInputs), so both paths compute identical BIP-341
 * sighashes from the same all-prevouts data. This mirrors Bitcoin Core,
 * where the mempool and block paths share one PrecomputedTransactionData:
 * MemPoolAccept keeps `ws.m_precomputed_txdata` ("Reused across
 * PolicyScriptChecks and ConsensusScriptChecks", validation.cpp:660-661),
 * CheckInputScripts gathers EVERY spent coin into
 * `txdata.Init(tx, std::move(spent_outputs))` (validation.cpp:2086-2097),
 * and SignatureHashSchnorr consumes the resulting
 * m_spent_amounts_single_hash / m_spent_scripts_single_hash precomputations
 * (interpreter.cpp:1447-1449, 1483-1503).
 *
 * Detects the BIP-341 annex on this input's witness (last element tagged
 * 0x50 when the stack has >= 2 items) and bakes
 * sha_annex = sha256(compact_size(len(annex)) || annex) into both closures.
 *
 * @param prevOuts - (scriptPubKey, value) of EVERY input's prevout, in
 *   input order — length MUST equal tx.inputs.length (sigMsgTaproot throws
 *   otherwise).
 * @param cache - shared per-tx TaprootSigHashCache so multiple taproot
 *   inputs in one tx don't recompute sha_prevouts/amounts/scriptpubkeys.
 */
export function buildTaprootContext(
  tx: Transaction,
  inputIndex: number,
  prevOuts: { scriptPubKey: Buffer; value: bigint }[],
  cache: TaprootSigHashCache
): TaprootContext {
  const witness = tx.inputs[inputIndex].witness;

  // Detect annex (last witness element starting with 0x50 when stack has >= 2 items).
  // BIP-341 sha_annex = sha256(compact_size(annex_len) || annex).
  let annexHash: Buffer | undefined = undefined;
  if (witness.length >= 2) {
    const last = witness[witness.length - 1];
    if (last.length > 0 && last[0] === 0x50) {
      const annexW = new BufferWriter();
      annexW.writeVarBytes(last);
      annexHash = sha256Hash(annexW.toBuffer());
    }
  }

  return {
    keyPathSigHasher: (hashType: number) =>
      sigHashTaproot(tx, inputIndex, prevOuts, hashType, 0,
        annexHash, undefined, undefined, 0xffffffff, cache),
    scriptPathSigHasher: (hashType: number, leafHash: Buffer, codeSepPos: number) =>
      sigHashTaproot(tx, inputIndex, prevOuts, hashType, 1,
        annexHash, leafHash, 0x00, codeSepPos, cache),
  };
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
  taprootCache?: TaprootSigHashCache,
  /** Per-block script verification flags (from coreConnectBlockChecks). When
   *  omitted the function defaults to all consensus rules active, matching the
   *  pre-fix behaviour for standalone / wallet call sites. */
  scriptVerifyFlags: ScriptFlags = ScriptFlags.VERIFY_P2SH |
    ScriptFlags.VERIFY_WITNESS |
    ScriptFlags.VERIFY_TAPROOT
): InputVerifyResult {
  const input = tx.inputs[inputIndex];
  const scriptPubKey = utxo.scriptPubKey;

  // Sig-cache lookup: if this input's signing material was already verified
  // successfully (e.g. during mempool ATMP), skip the secp256k1 work.
  // Key includes a 32-byte "sighash commitment" binding the entry to
  // (spending_txid, inputIndex, prevout, prev_amount, prev_scriptPubKey).
  // This is REQUIRED to prevent cross-tx witness-replay attacks (W160 BUG-7):
  // an attacker who observes a P2WPKH `<sig, pubkey>` witness on the wire
  // could otherwise copy that identical witness into a tx spending a different
  // UTXO sent to the same pubkey and get a false-positive cache hit, since
  // the RFC-6979-deterministic sig is bound to tx1's sighash but the cache
  // lookup would skip the interpreter entirely.  Mirrors Core's
  // CachingTransactionSignatureChecker (sigcache.cpp:39-50) which keys on
  // the (sighash, pubkey, sig) triple.
  const sighashCommitWriter = new BufferWriter();
  sighashCommitWriter.writeHash(getTxId(tx));
  sighashCommitWriter.writeUInt32LE(inputIndex);
  sighashCommitWriter.writeHash(input.prevOut.txid);
  sighashCommitWriter.writeUInt32LE(input.prevOut.vout);
  sighashCommitWriter.writeUInt64LE(utxo.amount);
  sighashCommitWriter.writeVarBytes(utxo.scriptPubKey);
  const sighashCommit = sha256Hash(sighashCommitWriter.toBuffer());

  const cacheKey = globalSigCache.computeKey(
    sighashCommit,
    input.scriptSig,
    input.witness,
    scriptVerifyFlags,
  );
  if (globalSigCache.lookup(cacheKey)) {
    return { valid: true, inputIndex };
  }

  // P2PKH/P2WPKH fast paths previously short-circuited here with a hand-rolled
  // <sig><pubkey> parser that called ecdsaVerify directly.  That bypassed the
  // script interpreter entirely and skipped DERSIG (BIP-66), NULLDUMMY, push-only
  // scriptSig enforcement, OP_PUSHDATA1/2/4 handling, OP_DUP/OP_HASH160/
  // OP_EQUALVERIFY/OP_CHECKSIG opcode dispatch, and (for P2WPKH) the witness
  // pubkey-type check.  An attacker-mined block carrying a non-strict-DER sig
  // or a scriptSig with extra opcodes would have been silently accepted by
  // hotbuns and rejected by Bitcoin Core — a latent consensus split.
  //
  // Both script types are now routed to the catch-all `verifyScript` branch
  // below which calls the full interpreter with consensus flags.

  // BIP-341 P2TR: OP_1 <32 bytes>
  if (scriptPubKey.length === 34 &&
      scriptPubKey[0] === 0x51 &&
      scriptPubKey[1] === 0x20) {
    if (input.scriptSig.length !== 0) {
      return { valid: false, inputIndex, error: "Taproot input must have empty scriptSig" };
    }
    // TAPROOT NOT ACTIVE => the v1 witness program is an UPGRADABLE witness
    // program, i.e. anyone-can-spend, and NONE of the BIP-341 rules below may
    // run. Bitcoin Core, VerifyWitnessProgram (script/interpreter.cpp:1947-1950):
    //
    //   } else if (witversion == 1 && program.size() == WITNESS_V1_TAPROOT_SIZE && !is_p2sh) {
    //       if (!(flags & SCRIPT_VERIFY_TAPROOT)) return set_success(serror);
    //       if (stack.size() == 0) return set_error(serror, SCRIPT_ERR_WITNESS_PROGRAM_WITNESS_EMPTY);
    //
    // The flag test comes FIRST — before the empty-witness test — and returns
    // SUCCESS, not failure.
    //
    // This branch previously had no flag gate at all: it enforced BIP-341 purely
    // on the scriptPubKey SHAPE. That made hotbuns reject mainnet block 692261,
    // whose whole reason for being in consensusparams.script_flag_exceptions is
    // that Core validates it with P2SH|WITNESS and TAPROOT CLEARED. Fixing
    // getScriptFlagsForBlock (Wave B) was necessary but not sufficient, because
    // the computed flag was then ignored here. FALSE-REJECT of a real chain
    // block — the node stalls on a block the network considers valid.
    // Found by the tools/phaseb-vectors checkblock vector at 692261.
    if ((scriptVerifyFlags & ScriptFlags.VERIFY_TAPROOT) === 0) {
      return { valid: true, inputIndex };
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

    const prevOuts = utxos.map(u => ({
      scriptPubKey: u.scriptPubKey,
      value: u.amount,
    }));
    const tprCache = taprootCache ?? {};

    // Build TaprootContext closures over this input's prevouts + annex via
    // the shared builder (also used by the mempool ATMP path).
    // verifyTaproot in the interpreter handles BIP-341 dispatch (key-path
    // vs script-path) + control-block walk + tapscript exec.
    const taprootCtx = buildTaprootContext(tx, inputIndex, prevOuts, tprCache);

    // Lazy require to avoid a circular import (interpreter.ts ↔ tx.ts).
    const interp = require("../script/interpreter.js") as typeof import("../script/interpreter.js");
    // Build interpreter flags from the per-block bitmask so that pre-activation
    // blocks are not validated with rules that were not yet active.
    const flags = interp.scriptFlagsFromBitmask(scriptVerifyFlags);

    // Spending-tx context for tapscript OP_CHECKLOCKTIMEVERIFY /
    // OP_CHECKSEQUENCEVERIFY (BIP-342). Without it, executeTapscript's CLTV/CSV
    // handlers see txLockTime/txSequence === undefined and fail-safe with
    // SCRIPT_ERR_UNSATISFIED_LOCKTIME — wrongly rejecting every valid tapscript
    // timelock spend (e.g. mainnet block 950149 tx 1b0d64e4…f54d input 0).
    // The catch-all `verifyScript` branch below already threads this; the P2TR
    // branch was the one omission.
    const txContext = {
      txVersion: tx.version,
      txLockTime: tx.lockTime,
      txSequence: input.sequence,
    };

    try {
      const ok = interp.verifyTaproot(scriptPubKey, input.witness, flags, taprootCtx, txContext);
      if (!ok) {
        return { valid: false, inputIndex, error: "Taproot verify returned false" };
      }
      globalSigCache.insert(cacheKey);
      return { valid: true, inputIndex };
    } catch (e) {
      return {
        valid: false,
        inputIndex,
        error: `Taproot verify failed: ${(e as Error).message}`,
      };
    }
  }

  // Everything else (P2WSH, P2SH, P2SH-wrapped SegWit, P2A, unknown
  // witness versions, bare scripts, …) — route to the full script
  // interpreter. Pre-fix this branch returned `{ valid: true }` for
  // any non-PKH/P2TR script type, silently accepting all P2WSH/P2SH
  // inputs at consensus level.
  if (!utxos || utxos.length !== tx.inputs.length) {
    return { valid: false, inputIndex, error: "Script verify requires all prev-outputs" };
  }

  const interp = require("../script/interpreter.js") as typeof import("../script/interpreter.js");
  // Build interpreter flags from the per-block bitmask so that pre-activation
  // blocks are not validated with rules that were not yet active (BUG-11/BUG-30
  // fix: was hardcoded getConsensusFlags(709632) which applied Taproot/SegWit/P2SH
  // rules on regtest blocks at height 0).
  const flags = interp.scriptFlagsFromBitmask(scriptVerifyFlags);

  const tprCache = taprootCache ?? {};
  const prevOuts = utxos.map(u => ({
    scriptPubKey: u.scriptPubKey,
    value: u.amount,
  }));

  const legacySigHasher = (subscript: Buffer, hashType: number) =>
    sigHashLegacy(tx, inputIndex, subscript, hashType);

  const witnessSigHasher = (scriptCode: Buffer, hashType: number) =>
    sigHashWitnessV0Cached(tx, inputIndex, scriptCode, utxo.amount, hashType, cache);

  // Shared TaprootContext builder (annex detection + key/script-path sighash
  // closures). Harmless for non-Taproot scripts since the interpreter ignores
  // taprootCtx unless scriptPubKey is P2TR.
  const taprootCtx = buildTaprootContext(tx, inputIndex, prevOuts, tprCache);

  const txContext = {
    txVersion: tx.version,
    txLockTime: tx.lockTime,
    txSequence: input.sequence,
  };

  try {
    const ok = interp.verifyScript(
      input.scriptSig,
      scriptPubKey,
      input.witness,
      flags,
      legacySigHasher,
      taprootCtx,
      txContext,
      witnessSigHasher,
    );
    if (!ok) {
      return { valid: false, inputIndex, error: "Script verify returned false" };
    }
    globalSigCache.insert(cacheKey);
    return { valid: true, inputIndex };
  } catch (e) {
    return {
      valid: false,
      inputIndex,
      error: `Script verify failed: ${(e as Error).message}`,
    };
  }
}

/**
 * Verify all input scripts in parallel using Promise.all.
 *
 * Uses a shared sighash cache for BIP-143 to avoid redundant computation.
 */
export async function verifyAllInputsParallel(
  tx: Transaction,
  utxos: UTXOEntry[],
  flags: ScriptFlags = ScriptFlags.VERIFY_P2SH |
    ScriptFlags.VERIFY_WITNESS |
    ScriptFlags.VERIFY_TAPROOT
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
    Promise.resolve(verifyInputSignature(tx, index, utxos[index], cache, utxos, taprootCache, flags))
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
  flags: ScriptFlags = ScriptFlags.VERIFY_P2SH |
    ScriptFlags.VERIFY_WITNESS |
    ScriptFlags.VERIFY_TAPROOT
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
    const result = verifyInputSignature(tx, i, utxos[i], cache, utxos, taprootCache, flags);
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

/**
 * BIP-68 applies only when version >= 2. Core stores version as uint32_t and
 * compares it UNSIGNED (fEnforceBIP68 = tx.version >= 2, tx_verify.cpp:51), so a
 * high-bit version (e.g. 0x80000002) STILL enforces BIP-68. hotbuns reads the
 * version via readInt32LE (signed), so a signed `>= 2` would treat 0x80000002 as
 * negative and SKIP enforcement, false-accepting a tx with an unmet relative
 * timelock (a chain split). `>>> 0` reinterprets as unsigned 32-bit -- same as the
 * OP_CSV path (interpreter.ts:1249).
 */
export function bip68VersionActive(version: number): boolean {
  return (version >>> 0) >= 2;
}

export function calculateSequenceLocks(
  tx: Transaction,
  enforceBIP68: boolean,
  utxoConfirmations: UTXOConfirmation[]
): SequenceLockResult {
  // Use -1 to indicate "any height/time is valid" (nLockTime semantics)
  let minHeight = -1;
  let minTime = -1;

  // BIP68 only applies to transactions with version >= 2 (compared unsigned).
  if (!enforceBIP68 || !bip68VersionActive(tx.version)) {
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
