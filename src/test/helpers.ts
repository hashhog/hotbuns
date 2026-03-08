/**
 * Test infrastructure helpers for hotbuns Bitcoin node testing.
 *
 * Provides utilities for creating test databases, blocks, transactions,
 * and mining regtest blocks.
 */

import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ChainDB } from "../storage/database.js";
import { REGTEST, type ConsensusParams, getBlockSubsidy } from "../consensus/params.js";
import type { Block, BlockHeader } from "../validation/block.js";
import { computeMerkleRoot, getBlockHash, serializeBlockHeader } from "../validation/block.js";
import type { Transaction, OutPoint, TxIn, TxOut } from "../validation/tx.js";
import { getTxId, serializeTx } from "../validation/tx.js";
import { hash256, privateKeyToPublicKey, hash160 } from "../crypto/primitives.js";

/**
 * Create a temporary database for testing.
 * Returns cleanup function to remove the temp directory.
 */
export async function createTestDB(): Promise<{ db: ChainDB; cleanup: () => Promise<void> }> {
  const tempDir = await mkdtemp(join(tmpdir(), "hotbuns-test-"));
  const db = new ChainDB(tempDir);
  await db.open();

  return {
    db,
    cleanup: async () => {
      await db.close();
      await rm(tempDir, { recursive: true, force: true });
    },
  };
}

/**
 * Create a minimal valid block for testing.
 *
 * @param prevHash - Previous block hash (32 bytes)
 * @param height - Block height (used for coinbase)
 * @param txs - Additional transactions (coinbase is auto-generated)
 * @param params - Consensus parameters (default: REGTEST)
 */
export function createTestBlock(
  prevHash: Buffer,
  height: number,
  txs: Transaction[] = [],
  params: ConsensusParams = REGTEST
): Block {
  // Calculate subsidy
  const subsidy = getBlockSubsidy(height, params);

  // Calculate fees from additional txs (simplified - assumes fee is pre-calculated)
  let totalFees = 0n;

  // Create coinbase transaction
  const coinbase = createCoinbaseTx(height, subsidy + totalFees);

  // All transactions: coinbase first, then any additional
  const transactions = [coinbase, ...txs];

  // Compute merkle root from txids
  const txids = transactions.map((tx) => getTxId(tx));
  const merkleRoot = computeMerkleRoot(txids);

  // Create block header
  const header: BlockHeader = {
    version: 0x20000000,
    prevBlock: prevHash,
    merkleRoot,
    timestamp: Math.floor(Date.now() / 1000),
    bits: params.powLimitBits,
    nonce: 0,
  };

  return { header, transactions };
}

/**
 * Create a coinbase transaction for a given height and value.
 *
 * @param height - Block height (encoded in scriptSig per BIP34)
 * @param value - Total coinbase value (subsidy + fees)
 * @param pubKeyHash - Optional public key hash for output (defaults to test hash)
 */
export function createCoinbaseTx(
  height: number,
  value: bigint,
  pubKeyHash: Buffer = Buffer.alloc(20, 0x01)
): Transaction {
  // Encode height in scriptSig (BIP34 minimal encoding)
  const heightScript = encodeHeightForCoinbase(height);

  // P2PKH output script: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
  const scriptPubKey = Buffer.concat([
    Buffer.from([0x76, 0xa9, 0x14]),
    pubKeyHash,
    Buffer.from([0x88, 0xac]),
  ]);

  return {
    version: 1,
    inputs: [
      {
        prevOut: {
          txid: Buffer.alloc(32, 0),
          vout: 0xffffffff,
        },
        scriptSig: heightScript,
        sequence: 0xffffffff,
        witness: [],
      },
    ],
    outputs: [
      {
        value,
        scriptPubKey,
      },
    ],
    lockTime: 0,
  };
}

/**
 * Encode height for coinbase scriptSig (BIP34).
 */
function encodeHeightForCoinbase(height: number): Buffer {
  if (height === 0) {
    return Buffer.from([0x00]);
  }

  if (height >= 1 && height <= 16) {
    return Buffer.from([0x50 + height]);
  }

  // Minimal encoding: push the height as little-endian bytes
  const bytes: number[] = [];
  let h = height;
  while (h > 0) {
    bytes.push(h & 0xff);
    h >>= 8;
  }

  // If high bit is set, add 0x00 to make it positive
  if (bytes[bytes.length - 1] & 0x80) {
    bytes.push(0x00);
  }

  return Buffer.from([bytes.length, ...bytes]);
}

/**
 * Create a test transaction spending given UTXOs.
 *
 * @param inputs - Array of outpoints to spend
 * @param outputs - Array of outputs to create
 */
export function createTestTx(
  inputs: OutPoint[],
  outputs: { value: bigint; script: Buffer }[]
): Transaction {
  const txInputs: TxIn[] = inputs.map((outpoint) => ({
    prevOut: outpoint,
    scriptSig: Buffer.alloc(0), // Empty for P2WPKH
    sequence: 0xffffffff,
    witness: [],
  }));

  const txOutputs: TxOut[] = outputs.map((out) => ({
    value: out.value,
    scriptPubKey: out.script,
  }));

  return {
    version: 2,
    inputs: txInputs,
    outputs: txOutputs,
    lockTime: 0,
  };
}

/**
 * Create a P2PKH output script.
 */
export function p2pkhScript(pubKeyHash: Buffer): Buffer {
  if (pubKeyHash.length !== 20) {
    throw new Error("pubKeyHash must be 20 bytes");
  }
  return Buffer.concat([
    Buffer.from([0x76, 0xa9, 0x14]),
    pubKeyHash,
    Buffer.from([0x88, 0xac]),
  ]);
}

/**
 * Create a P2WPKH output script.
 */
export function p2wpkhScript(pubKeyHash: Buffer): Buffer {
  if (pubKeyHash.length !== 20) {
    throw new Error("pubKeyHash must be 20 bytes");
  }
  return Buffer.concat([Buffer.from([0x00, 0x14]), pubKeyHash]);
}

/**
 * Mine a regtest block (find a valid nonce for the low-difficulty target).
 *
 * Regtest difficulty is extremely low (0x207fffff), so finding a valid
 * nonce is near-instant (typically just a few iterations).
 *
 * @param block - Block with header.nonce = 0
 * @returns Block with valid nonce set
 */
export function mineRegtestBlock(block: Block): Block {
  // Get target from bits
  const target = compactToBigInt(block.header.bits);

  // Try nonces until we find a valid one
  for (let nonce = 0; nonce < 0xffffffff; nonce++) {
    const header: BlockHeader = {
      ...block.header,
      nonce,
    };

    const headerHash = getBlockHash(header);
    const hashValue = hashToBigInt(headerHash);

    if (hashValue <= target) {
      return {
        header,
        transactions: block.transactions,
      };
    }
  }

  throw new Error("Failed to mine block - no valid nonce found");
}

/**
 * Convert a 32-byte hash to a bigint (little-endian).
 */
function hashToBigInt(hash: Buffer): bigint {
  // Convert hash to big-endian hex string for bigint parsing
  const reversed = Buffer.from(hash).reverse();
  return BigInt("0x" + reversed.toString("hex"));
}

/**
 * Convert compact difficulty (nBits) to target bigint.
 */
function compactToBigInt(bits: number): bigint {
  const exponent = bits >>> 24;
  const mantissa = bits & 0x7fffff;
  const isNegative = (bits & 0x800000) !== 0;

  let target: bigint;
  if (exponent <= 3) {
    target = BigInt(mantissa) >> BigInt(8 * (3 - exponent));
  } else {
    target = BigInt(mantissa) << BigInt(8 * (exponent - 3));
  }

  if (isNegative && target !== 0n) {
    return 0n;
  }

  return target;
}

/**
 * Generate a random 32-byte private key.
 */
export function randomPrivateKey(): Buffer {
  // secp256k1 curve order
  const curveOrder = BigInt(
    "0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"
  );

  // Generate random bytes and ensure they're valid
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);

  // Convert to bigint and ensure it's in valid range (1, curveOrder - 1)
  let value = BigInt("0x" + Buffer.from(bytes).toString("hex"));
  value = (value % (curveOrder - 1n)) + 1n;

  // Convert back to buffer
  let hex = value.toString(16).padStart(64, "0");
  return Buffer.from(hex, "hex");
}

/**
 * Generate a key pair for testing.
 */
export function generateTestKeyPair(): {
  privateKey: Buffer;
  publicKey: Buffer;
  pubKeyHash: Buffer;
} {
  const privateKey = randomPrivateKey();
  const publicKey = privateKeyToPublicKey(privateKey, true);
  const pubKeyHash = hash160(publicKey);

  return { privateKey, publicKey, pubKeyHash };
}

/**
 * Create a chain of test blocks.
 *
 * @param startingPrevHash - Previous block hash for first block
 * @param startHeight - Height of first block
 * @param count - Number of blocks to create
 * @param params - Consensus parameters
 */
export function createBlockChain(
  startingPrevHash: Buffer,
  startHeight: number,
  count: number,
  params: ConsensusParams = REGTEST
): Block[] {
  const blocks: Block[] = [];
  let prevHash = startingPrevHash;

  for (let i = 0; i < count; i++) {
    const height = startHeight + i;
    const block = createTestBlock(prevHash, height, [], params);
    const minedBlock = mineRegtestBlock(block);
    blocks.push(minedBlock);
    prevHash = getBlockHash(minedBlock.header);
  }

  return blocks;
}

/**
 * Wait for a condition to be true (for async tests).
 */
export async function waitFor(
  condition: () => boolean | Promise<boolean>,
  timeoutMs: number = 5000,
  intervalMs: number = 50
): Promise<void> {
  const startTime = Date.now();

  while (Date.now() - startTime < timeoutMs) {
    if (await condition()) {
      return;
    }
    await sleep(intervalMs);
  }

  throw new Error(`waitFor timed out after ${timeoutMs}ms`);
}

/**
 * Sleep for the specified number of milliseconds.
 */
export function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Create a mock UTXO entry for testing.
 */
export function createMockUTXO(
  amount: bigint,
  height: number,
  coinbase: boolean = false
): {
  amount: bigint;
  height: number;
  coinbase: boolean;
  scriptPubKey: Buffer;
} {
  return {
    amount,
    height,
    coinbase,
    scriptPubKey: p2pkhScript(Buffer.alloc(20, 0x01)),
  };
}

/**
 * Compute the merkle root for a list of transactions.
 */
export function computeTxMerkleRoot(txs: Transaction[]): Buffer {
  const txids = txs.map((tx) => getTxId(tx));
  return computeMerkleRoot(txids);
}
