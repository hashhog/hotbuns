/**
 * Block validation: header checks, merkle root, consensus rules.
 *
 * Implements block serialization, merkle tree computation, proof-of-work
 * validation, and full block validation against consensus rules.
 */

import { BufferReader, BufferWriter } from "../wire/serialization.js";
import { hash256 } from "../crypto/primitives.js";
import { ConsensusParams, compactToBigInt } from "../consensus/params.js";
import {
  Transaction,
  deserializeTx,
  serializeTx,
  getTxId,
  getWTxId,
  getTxWeight,
  hasWitness,
  isCoinbase,
  validateTxBasic,
} from "./tx.js";

/**
 * Block header structure (80 bytes serialized).
 */
export interface BlockHeader {
  version: number; // int32
  prevBlock: Buffer; // 32 bytes
  merkleRoot: Buffer; // 32 bytes
  timestamp: number; // uint32
  bits: number; // uint32 (compact target)
  nonce: number; // uint32
}

/**
 * A complete Bitcoin block.
 */
export interface Block {
  header: BlockHeader;
  transactions: Transaction[];
}

/**
 * Serialize a block header to 80 bytes.
 */
export function serializeBlockHeader(header: BlockHeader): Buffer {
  const writer = new BufferWriter();
  writer.writeInt32LE(header.version);
  writer.writeHash(header.prevBlock);
  writer.writeHash(header.merkleRoot);
  writer.writeUInt32LE(header.timestamp);
  writer.writeUInt32LE(header.bits);
  writer.writeUInt32LE(header.nonce);
  return writer.toBuffer();
}

/**
 * Deserialize a block header from a BufferReader.
 */
export function deserializeBlockHeader(reader: BufferReader): BlockHeader {
  const version = reader.readInt32LE();
  const prevBlock = reader.readHash();
  const merkleRoot = reader.readHash();
  const timestamp = reader.readUInt32LE();
  const bits = reader.readUInt32LE();
  const nonce = reader.readUInt32LE();

  return { version, prevBlock, merkleRoot, timestamp, bits, nonce };
}

/**
 * Serialize a complete block.
 */
export function serializeBlock(block: Block): Buffer {
  const writer = new BufferWriter();

  // Header (80 bytes)
  writer.writeBytes(serializeBlockHeader(block.header));

  // Transaction count
  writer.writeVarInt(block.transactions.length);

  // Transactions (with witness data)
  for (const tx of block.transactions) {
    writer.writeBytes(serializeTx(tx, true));
  }

  return writer.toBuffer();
}

/**
 * Deserialize a complete block from a BufferReader.
 */
export function deserializeBlock(reader: BufferReader): Block {
  const header = deserializeBlockHeader(reader);

  const txCount = reader.readVarInt();
  const transactions: Transaction[] = [];

  for (let i = 0; i < txCount; i++) {
    transactions.push(deserializeTx(reader));
  }

  return { header, transactions };
}

/**
 * Compute the block hash (double SHA-256 of the 80-byte header).
 * Returns in little-endian (internal) format.
 */
export function getBlockHash(header: BlockHeader): Buffer {
  return hash256(serializeBlockHeader(header));
}

/**
 * Compute the merkle root from a list of transaction IDs.
 * If the list is empty, returns 32 zero bytes.
 *
 * Merkle tree construction:
 * - Hash pairs: hash256(left || right)
 * - If odd number of nodes, duplicate the last one
 */
export function computeMerkleRoot(txids: Buffer[]): Buffer {
  if (txids.length === 0) {
    return Buffer.alloc(32, 0);
  }

  // Clone the array to avoid modifying the input
  let level: Buffer[] = txids.map((txid) => Buffer.from(txid));

  while (level.length > 1) {
    const nextLevel: Buffer[] = [];

    for (let i = 0; i < level.length; i += 2) {
      const left = level[i];
      // If odd, duplicate the last element
      const right = i + 1 < level.length ? level[i + 1] : level[i];
      nextLevel.push(hash256(Buffer.concat([left, right])));
    }

    level = nextLevel;
  }

  return level[0];
}

/**
 * Compute the witness merkle root from witness transaction IDs.
 * The coinbase wtxid is replaced with 32 zero bytes.
 */
export function computeWitnessMerkleRoot(wtxids: Buffer[]): Buffer {
  if (wtxids.length === 0) {
    return Buffer.alloc(32, 0);
  }

  // Clone and replace coinbase wtxid with zeros
  const modifiedWtxids = wtxids.map((wtxid, index) => {
    if (index === 0) {
      return Buffer.alloc(32, 0);
    }
    return Buffer.from(wtxid);
  });

  return computeMerkleRoot(modifiedWtxids);
}

/**
 * Extract the witness commitment from a block's coinbase transaction.
 * Returns null if no witness commitment is found.
 *
 * The witness commitment is in an output with scriptPubKey:
 * OP_RETURN (0x6a) 0x24 0xaa21a9ed <32-byte commitment>
 *
 * If multiple commitments exist, the last one is used.
 */
export function getWitnessCommitment(block: Block): Buffer | null {
  if (block.transactions.length === 0) {
    return null;
  }

  const coinbase = block.transactions[0];

  // Search outputs in reverse order (last commitment wins)
  for (let i = coinbase.outputs.length - 1; i >= 0; i--) {
    const script = coinbase.outputs[i].scriptPubKey;

    // Minimum length: OP_RETURN(1) + 0x24(1) + 0xaa21a9ed(4) + commitment(32) = 38
    if (script.length < 38) {
      continue;
    }

    // Check for OP_RETURN (0x6a)
    if (script[0] !== 0x6a) {
      continue;
    }

    // Check for push of 36 bytes (0x24)
    if (script[1] !== 0x24) {
      continue;
    }

    // Check for commitment header: aa21a9ed
    if (
      script[2] !== 0xaa ||
      script[3] !== 0x21 ||
      script[4] !== 0xa9 ||
      script[5] !== 0xed
    ) {
      continue;
    }

    // Extract the 32-byte commitment
    return script.subarray(6, 38);
  }

  return null;
}

/**
 * Validate a block header against consensus rules.
 *
 * Checks:
 * - Timestamp not too far in future (2 hours)
 * - Target does not exceed powLimit
 * - Proof of work (block hash <= target)
 * - prevBlock matches if provided
 */
export function validateBlockHeader(
  header: BlockHeader,
  prevHeader: BlockHeader | null,
  params: ConsensusParams
): { valid: boolean; error?: string } {
  // Timestamp must not be more than 2 hours in the future
  // Check this first to avoid expensive PoW computation for obviously bad headers
  const maxFutureTime = Math.floor(Date.now() / 1000) + 2 * 60 * 60;
  if (header.timestamp > maxFutureTime) {
    return { valid: false, error: "Block timestamp too far in future" };
  }

  // Target must not exceed powLimit
  const target = compactToBigInt(header.bits);
  if (target > params.powLimit) {
    return { valid: false, error: "Target exceeds powLimit" };
  }

  // Check proof of work
  const blockHash = getBlockHash(header);

  // Convert block hash to big-endian number for comparison
  // The hash is in little-endian, so we need to reverse it for numeric comparison
  const hashReversed = Buffer.from(blockHash).reverse();
  const hashValue = BigInt("0x" + hashReversed.toString("hex"));

  if (hashValue > target) {
    return { valid: false, error: "Proof of work failed: hash > target" };
  }

  // If we have a previous header, check that prevBlock matches
  if (prevHeader !== null) {
    const prevHash = getBlockHash(prevHeader);
    if (!header.prevBlock.equals(prevHash)) {
      return { valid: false, error: "prevBlock does not match previous header hash" };
    }

    // Timestamp must be greater than median of previous 11 blocks
    // (simplified: just check it's not before prev block)
    // Full implementation would track median time past
    if (header.timestamp <= prevHeader.timestamp - 7200) {
      // Allow some leeway
      return { valid: false, error: "Block timestamp too old" };
    }
  }

  return { valid: true };
}

/**
 * Validate a complete block against consensus rules.
 *
 * Checks:
 * - Block is non-empty
 * - First transaction is coinbase
 * - No other transactions are coinbase
 * - Merkle root matches computed value
 * - Witness commitment matches (if segwit active)
 * - Total block weight within limit
 * - Each transaction is valid
 */
export function validateBlock(
  block: Block,
  height: number,
  params: ConsensusParams
): { valid: boolean; error?: string } {
  // Block must have at least one transaction
  if (block.transactions.length === 0) {
    return { valid: false, error: "Block has no transactions" };
  }

  // First transaction must be coinbase
  const coinbaseTx = block.transactions[0];
  if (!isCoinbase(coinbaseTx)) {
    return { valid: false, error: "First transaction is not coinbase" };
  }

  // No other transaction can be coinbase
  for (let i = 1; i < block.transactions.length; i++) {
    if (isCoinbase(block.transactions[i])) {
      return { valid: false, error: `Transaction ${i} is coinbase but should not be` };
    }
  }

  // Verify merkle root
  const txids = block.transactions.map((tx) => getTxId(tx));
  const computedMerkleRoot = computeMerkleRoot(txids);

  if (!computedMerkleRoot.equals(block.header.merkleRoot)) {
    return { valid: false, error: "Merkle root mismatch" };
  }

  // Check if segwit is active
  const segwitActive = height >= params.segwitHeight;

  // Check for witness data in block
  const hasWitnessData = block.transactions.some((tx) => hasWitness(tx));

  // Verify witness commitment if segwit is active and block has witness data
  if (segwitActive && hasWitnessData) {
    const commitment = getWitnessCommitment(block);
    if (commitment === null) {
      return { valid: false, error: "Missing witness commitment" };
    }

    // Compute expected commitment
    const wtxids = block.transactions.map((tx) => getWTxId(tx));
    const witnessMerkleRoot = computeWitnessMerkleRoot(wtxids);

    // Get witness nonce from coinbase (should be in witness stack)
    let witnessNonce: Buffer;
    if (
      coinbaseTx.inputs[0].witness.length > 0 &&
      coinbaseTx.inputs[0].witness[0].length === 32
    ) {
      witnessNonce = coinbaseTx.inputs[0].witness[0];
    } else {
      // Default to 32 zero bytes if no nonce
      witnessNonce = Buffer.alloc(32, 0);
    }

    const expectedCommitment = hash256(
      Buffer.concat([witnessMerkleRoot, witnessNonce])
    );

    if (!commitment.equals(expectedCommitment)) {
      return { valid: false, error: "Witness commitment mismatch" };
    }
  }

  // Calculate block weight
  let totalWeight = 0;
  for (const tx of block.transactions) {
    totalWeight += getTxWeight(tx);
  }

  // Add header weight (80 bytes * 4 = 320 weight units)
  totalWeight += 80 * 4;

  if (totalWeight > params.maxBlockWeight) {
    return { valid: false, error: "Block weight exceeds maximum" };
  }

  // Validate each transaction
  for (let i = 0; i < block.transactions.length; i++) {
    const tx = block.transactions[i];
    const result = validateTxBasic(tx);
    if (!result.valid) {
      return { valid: false, error: `Transaction ${i}: ${result.error}` };
    }
  }

  // Note: Full validation would also check:
  // - BIP34 coinbase height encoding
  // - Total sigops cost within limit
  // - Coinbase output value <= subsidy + fees
  // - All inputs exist and are unspent (UTXO validation)
  // - Script validation for all inputs
  // - No double spends within block

  return { valid: true };
}

/**
 * Calculate the base size of a block (without witness data).
 */
export function getBlockBaseSize(block: Block): number {
  // Header is always 80 bytes
  let size = 80;

  // varint tx count
  const txCount = block.transactions.length;
  if (txCount <= 0xfc) size += 1;
  else if (txCount <= 0xffff) size += 3;
  else if (txCount <= 0xffffffff) size += 5;
  else size += 9;

  // Each transaction without witness
  for (const tx of block.transactions) {
    size += serializeTx(tx, false).length;
  }

  return size;
}

/**
 * Calculate the total size of a block (with witness data).
 */
export function getBlockTotalSize(block: Block): number {
  return serializeBlock(block).length;
}

/**
 * Calculate block weight (BIP-141).
 * weight = base_size * 3 + total_size
 */
export function getBlockWeight(block: Block): number {
  const baseSize = getBlockBaseSize(block);
  const totalSize = getBlockTotalSize(block);
  return baseSize * 3 + totalSize;
}
