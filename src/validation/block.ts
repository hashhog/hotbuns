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
import { isP2SH, isP2WPKH, isP2WSH, isPushOnly, Opcode } from "../script/interpreter.js";

// =============================================================================
// Sigop Counting Constants
// =============================================================================

/**
 * Maximum sigops cost per block (weighted).
 * Legacy/P2SH sigops cost 4x, witness sigops cost 1x.
 */
export const MAX_BLOCK_SIGOPS_COST = 80_000;

/**
 * Witness scale factor for sigop cost calculation.
 * Legacy and P2SH sigops are multiplied by this factor.
 */
export const WITNESS_SCALE_FACTOR = 4;

/**
 * Maximum pubkeys in a CHECKMULTISIG operation.
 */
export const MAX_PUBKEYS_PER_MULTISIG = 20;

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
  // - Coinbase output value <= subsidy + fees
  // - All inputs exist and are unspent (UTXO validation)
  // - Script validation for all inputs
  // - No double spends within block
  // - Total sigops cost (requires prevOutputs, done in connectBlock)

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

// =============================================================================
// Sigop Counting Implementation
// =============================================================================
// Reference: Bitcoin Core consensus/tx_verify.cpp and script/script.cpp
// =============================================================================

/**
 * Count signature operations in a raw script.
 *
 * If `accurate` is true (for P2SH redeem scripts and witness scripts),
 * OP_CHECKMULTISIG(VERIFY) uses the preceding OP_N to determine the
 * key count. Otherwise, it counts as MAX_PUBKEYS_PER_MULTISIG (20).
 *
 * @param script - The raw script bytes
 * @param accurate - Whether to use accurate multisig counting
 * @returns The number of sigops in the script
 */
export function countScriptSigOps(script: Buffer, accurate: boolean): number {
  let sigOps = 0;
  let lastOpcode = 0xff; // Invalid opcode
  let pos = 0;

  while (pos < script.length) {
    const opcode = script[pos];
    pos++;

    // Skip push data
    if (opcode <= Opcode.OP_PUSHDATA4) {
      if (opcode === 0) {
        // OP_0 - no data to skip
      } else if (opcode >= 1 && opcode <= 75) {
        // Direct push
        pos += opcode;
      } else if (opcode === Opcode.OP_PUSHDATA1) {
        if (pos >= script.length) break;
        const len = script[pos];
        pos += 1 + len;
      } else if (opcode === Opcode.OP_PUSHDATA2) {
        if (pos + 1 >= script.length) break;
        const len = script[pos] | (script[pos + 1] << 8);
        pos += 2 + len;
      } else if (opcode === Opcode.OP_PUSHDATA4) {
        if (pos + 3 >= script.length) break;
        const len =
          script[pos] |
          (script[pos + 1] << 8) |
          (script[pos + 2] << 16) |
          (script[pos + 3] << 24);
        pos += 4 + len;
      }
      lastOpcode = opcode;
      continue;
    }

    // Count sigops
    if (opcode === Opcode.OP_CHECKSIG || opcode === Opcode.OP_CHECKSIGVERIFY) {
      sigOps++;
    } else if (
      opcode === Opcode.OP_CHECKMULTISIG ||
      opcode === Opcode.OP_CHECKMULTISIGVERIFY
    ) {
      // If accurate mode and preceding opcode was OP_1-OP_16, use that as key count
      if (accurate && lastOpcode >= Opcode.OP_1 && lastOpcode <= Opcode.OP_16) {
        sigOps += lastOpcode - Opcode.OP_1 + 1;
      } else {
        // Default to max pubkeys
        sigOps += MAX_PUBKEYS_PER_MULTISIG;
      }
    }

    lastOpcode = opcode;
  }

  return sigOps;
}

/**
 * Count legacy sigops in a transaction.
 *
 * This counts sigops from:
 * - scriptSig (input scripts)
 * - scriptPubKey (output scripts)
 *
 * Uses inaccurate counting (OP_CHECKMULTISIG = 20 sigops).
 *
 * Reference: Bitcoin Core GetLegacySigOpCount()
 */
export function getLegacySigOpCount(tx: Transaction): number {
  let sigOps = 0;

  // Count sigops in all input scriptSigs
  for (const input of tx.inputs) {
    sigOps += countScriptSigOps(input.scriptSig, false);
  }

  // Count sigops in all output scriptPubKeys
  for (const output of tx.outputs) {
    sigOps += countScriptSigOps(output.scriptPubKey, false);
  }

  return sigOps;
}

/**
 * Extract the last push data from a scriptSig.
 * Used for P2SH redeem script extraction.
 *
 * @param scriptSig - The input script
 * @returns The last pushed data item, or null if none
 */
function getLastPushData(scriptSig: Buffer): Buffer | null {
  let lastData: Buffer | null = null;
  let pos = 0;

  while (pos < scriptSig.length) {
    const opcode = scriptSig[pos];
    pos++;

    if (opcode === 0) {
      // OP_0 - empty push
      lastData = Buffer.alloc(0);
    } else if (opcode >= 1 && opcode <= 75) {
      // Direct push
      if (pos + opcode > scriptSig.length) return null;
      lastData = scriptSig.subarray(pos, pos + opcode);
      pos += opcode;
    } else if (opcode === Opcode.OP_PUSHDATA1) {
      if (pos >= scriptSig.length) return null;
      const len = scriptSig[pos];
      pos++;
      if (pos + len > scriptSig.length) return null;
      lastData = scriptSig.subarray(pos, pos + len);
      pos += len;
    } else if (opcode === Opcode.OP_PUSHDATA2) {
      if (pos + 1 >= scriptSig.length) return null;
      const len = scriptSig[pos] | (scriptSig[pos + 1] << 8);
      pos += 2;
      if (pos + len > scriptSig.length) return null;
      lastData = scriptSig.subarray(pos, pos + len);
      pos += len;
    } else if (opcode === Opcode.OP_PUSHDATA4) {
      if (pos + 3 >= scriptSig.length) return null;
      const len =
        scriptSig[pos] |
        (scriptSig[pos + 1] << 8) |
        (scriptSig[pos + 2] << 16) |
        (scriptSig[pos + 3] << 24);
      pos += 4;
      if (pos + len > scriptSig.length) return null;
      lastData = scriptSig.subarray(pos, pos + len);
      pos += len;
    } else if (opcode > Opcode.OP_16) {
      // Non-push opcode - P2SH scriptSig must be push-only
      return null;
    } else {
      // OP_1NEGATE, OP_1-OP_16 (push small numbers)
      // Not relevant for P2SH as redeem scripts are typically larger
      lastData = Buffer.from([opcode === Opcode.OP_1NEGATE ? 0x81 : opcode - Opcode.OP_1 + 1]);
    }
  }

  return lastData;
}

/**
 * Count P2SH sigops in a transaction.
 *
 * For each input spending a P2SH output, extract the redeem script
 * from the scriptSig and count sigops with accurate mode.
 *
 * Reference: Bitcoin Core GetP2SHSigOpCount()
 *
 * @param tx - The transaction
 * @param prevOutputs - The scriptPubKeys being spent, indexed by input
 * @returns Additional P2SH sigops (not including legacy count)
 */
export function getP2SHSigOpCount(
  tx: Transaction,
  prevOutputs: Buffer[]
): number {
  // Coinbase has no P2SH inputs
  if (isCoinbase(tx)) {
    return 0;
  }

  let sigOps = 0;

  for (let i = 0; i < tx.inputs.length; i++) {
    const input = tx.inputs[i];
    const prevScript = prevOutputs[i];

    // Check if previous output is P2SH
    if (!isP2SH(prevScript)) {
      continue;
    }

    // Extract the redeem script from scriptSig
    // P2SH scriptSig must be push-only
    if (!isPushOnly(input.scriptSig)) {
      continue;
    }

    const redeemScript = getLastPushData(input.scriptSig);
    if (!redeemScript) {
      continue;
    }

    // Count sigops in redeem script with accurate mode
    sigOps += countScriptSigOps(redeemScript, true);
  }

  return sigOps;
}

/**
 * Count sigops in a witness program (P2WPKH or P2WSH).
 *
 * - P2WPKH (20-byte program): 1 sigop
 * - P2WSH (32-byte program): count from witness script with accurate mode
 *
 * Reference: Bitcoin Core WitnessSigOps()
 *
 * @param witnessVersion - The witness version (0 for v0)
 * @param witnessProgram - The witness program bytes
 * @param witness - The witness stack
 * @returns Sigop count (NOT scaled)
 */
export function countWitnessProgramSigOps(
  witnessVersion: number,
  witnessProgram: Buffer,
  witness: Buffer[]
): number {
  if (witnessVersion === 0) {
    // P2WPKH: 20-byte program = 1 sigop
    if (witnessProgram.length === 20) {
      return 1;
    }

    // P2WSH: 32-byte program = count from witness script
    if (witnessProgram.length === 32 && witness.length > 0) {
      const witnessScript = witness[witness.length - 1];
      return countScriptSigOps(witnessScript, true);
    }
  }

  // Future witness versions: 0 sigops
  return 0;
}

/**
 * Check if a script is a witness program and extract its version and program.
 *
 * Witness programs have the form: OP_N <2-40 bytes>
 * where OP_N is OP_0 (0x00) or OP_1-OP_16 (0x51-0x60)
 *
 * @param script - The scriptPubKey
 * @returns [version, program] or null if not a witness program
 */
export function parseWitnessProgram(
  script: Buffer
): [number, Buffer] | null {
  if (script.length < 4 || script.length > 42) {
    return null;
  }

  const version = script[0];

  // OP_0 or OP_1-OP_16
  if (version !== 0x00 && (version < 0x51 || version > 0x60)) {
    return null;
  }

  // Second byte is the push length
  const programLen = script[1];
  if (programLen + 2 !== script.length) {
    return null;
  }

  // Program must be 2-40 bytes
  if (programLen < 2 || programLen > 40) {
    return null;
  }

  const witnessVersion = version === 0x00 ? 0 : version - 0x50;
  const program = script.subarray(2);

  return [witnessVersion, program];
}

/**
 * Count witness sigops for a transaction input.
 *
 * Handles:
 * - Native witness programs (P2WPKH, P2WSH)
 * - P2SH-wrapped witness programs (P2SH-P2WPKH, P2SH-P2WSH)
 *
 * Reference: Bitcoin Core CountWitnessSigOps()
 *
 * @param input - The transaction input
 * @param prevScript - The scriptPubKey being spent
 * @returns Sigop count (NOT scaled)
 */
export function countInputWitnessSigOps(
  input: { scriptSig: Buffer; witness: Buffer[] },
  prevScript: Buffer
): number {
  // Check for native witness program
  const nativeProgram = parseWitnessProgram(prevScript);
  if (nativeProgram) {
    const [version, program] = nativeProgram;
    return countWitnessProgramSigOps(version, program, input.witness);
  }

  // Check for P2SH-wrapped witness program
  if (isP2SH(prevScript) && isPushOnly(input.scriptSig)) {
    const redeemScript = getLastPushData(input.scriptSig);
    if (redeemScript) {
      const wrappedProgram = parseWitnessProgram(redeemScript);
      if (wrappedProgram) {
        const [version, program] = wrappedProgram;
        return countWitnessProgramSigOps(version, program, input.witness);
      }
    }
  }

  return 0;
}

/**
 * Calculate the total sigop cost for a transaction.
 *
 * This is the weighted sigop count:
 * - Legacy sigops: count * WITNESS_SCALE_FACTOR (4)
 * - P2SH sigops: count * WITNESS_SCALE_FACTOR (4)
 * - Witness sigops: count * 1
 *
 * Reference: Bitcoin Core GetTransactionSigOpCost()
 *
 * @param tx - The transaction
 * @param prevOutputs - The scriptPubKeys being spent, indexed by input
 * @param verifyP2SH - Whether P2SH is active (BIP 16)
 * @param verifyWitness - Whether witness is active (BIP 141)
 * @returns The weighted sigop cost
 */
export function getTransactionSigOpCost(
  tx: Transaction,
  prevOutputs: Buffer[],
  verifyP2SH: boolean,
  verifyWitness: boolean
): number {
  // Legacy sigops (scriptSig + scriptPubKey) scaled by witness factor
  let cost = getLegacySigOpCount(tx) * WITNESS_SCALE_FACTOR;

  // Coinbase has no inputs to examine
  if (isCoinbase(tx)) {
    return cost;
  }

  // P2SH sigops (from redeem scripts) scaled by witness factor
  if (verifyP2SH) {
    cost += getP2SHSigOpCount(tx, prevOutputs) * WITNESS_SCALE_FACTOR;
  }

  // Witness sigops (not scaled - already at weight 1)
  if (verifyWitness) {
    for (let i = 0; i < tx.inputs.length; i++) {
      cost += countInputWitnessSigOps(tx.inputs[i], prevOutputs[i]);
    }
  }

  return cost;
}

/**
 * Calculate the total sigop cost for a block.
 *
 * @param block - The block
 * @param prevOutputsMap - Map from input index to prevOut scriptPubKey for each tx
 * @param verifyP2SH - Whether P2SH is active
 * @param verifyWitness - Whether witness is active
 * @returns The total weighted sigop cost
 */
export function getBlockSigOpsCost(
  block: Block,
  prevOutputsMap: Map<number, Buffer[]>,
  verifyP2SH: boolean,
  verifyWitness: boolean
): number {
  let totalCost = 0;

  for (let i = 0; i < block.transactions.length; i++) {
    const tx = block.transactions[i];
    const prevOutputs = prevOutputsMap.get(i) ?? [];
    totalCost += getTransactionSigOpCost(tx, prevOutputs, verifyP2SH, verifyWitness);
  }

  return totalCost;
}

/**
 * Validate that a block's sigop cost is within the limit.
 *
 * @param block - The block
 * @param prevOutputsMap - Map from tx index to prevOut scriptPubKeys
 * @param verifyP2SH - Whether P2SH is active
 * @param verifyWitness - Whether witness is active
 * @returns Validation result
 */
export function validateBlockSigOps(
  block: Block,
  prevOutputsMap: Map<number, Buffer[]>,
  verifyP2SH: boolean,
  verifyWitness: boolean
): { valid: boolean; error?: string; cost?: number } {
  const cost = getBlockSigOpsCost(block, prevOutputsMap, verifyP2SH, verifyWitness);

  if (cost > MAX_BLOCK_SIGOPS_COST) {
    return {
      valid: false,
      error: `Block sigops cost ${cost} exceeds maximum ${MAX_BLOCK_SIGOPS_COST}`,
      cost,
    };
  }

  return { valid: true, cost };
}
