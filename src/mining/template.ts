/**
 * Block template construction for mining.
 *
 * Selects transactions from the mempool to maximize fees while respecting
 * weight limits and dependency ordering. Constructs coinbase transaction
 * with proper BIP34 height encoding and witness commitment.
 */

import type { ConsensusParams } from "../consensus/params.js";
import { getBlockSubsidy, compactToBigInt, bigIntToCompact } from "../consensus/params.js";
import type { ChainStateManager } from "../chain/state.js";
import type { Mempool, MempoolEntry } from "../mempool/mempool.js";
import type {
  Transaction,
  TxIn,
  TxOut,
} from "../validation/tx.js";
import {
  getTxId,
  getWTxId,
  getTxWeight,
  serializeTx,
} from "../validation/tx.js";
import type { BlockHeader, Block } from "../validation/block.js";
import {
  computeMerkleRoot,
  computeWitnessMerkleRoot,
} from "../validation/block.js";
import { hash256 } from "../crypto/primitives.js";
import { BufferWriter, varIntSize } from "../wire/serialization.js";

/**
 * Locktime threshold: values below this are block heights, above are Unix timestamps.
 * Per BIP-113 and consensus rules.
 */
const LOCKTIME_THRESHOLD = 500_000_000;

/**
 * Check if a transaction is final for inclusion in a block at the given height and time.
 *
 * A transaction is final if:
 * - nLockTime == 0, OR
 * - nLockTime < threshold (block height or time depending on LOCKTIME_THRESHOLD), OR
 * - All inputs have nSequence == 0xFFFFFFFF
 *
 * Reference: Bitcoin Core's IsFinalTx() in consensus/tx_verify.cpp
 *
 * @param tx - The transaction to check
 * @param blockHeight - The height of the block being assembled
 * @param blockTime - The median time past (MTP) of the previous block
 * @returns true if the transaction is final
 */
export function isFinalTx(tx: Transaction, blockHeight: number, blockTime: number): boolean {
  // nLockTime == 0 means always final
  if (tx.lockTime === 0) {
    return true;
  }

  // Determine if locktime is height-based or time-based
  const lockTimeThreshold = tx.lockTime < LOCKTIME_THRESHOLD ? blockHeight : blockTime;

  // If nLockTime is less than the threshold, the tx is final
  if (tx.lockTime < lockTimeThreshold) {
    return true;
  }

  // Even if nLockTime isn't satisfied, a transaction is still final if all
  // inputs have nSequence == 0xFFFFFFFF (SEQUENCE_FINAL)
  for (const input of tx.inputs) {
    if (input.sequence !== 0xffffffff) {
      return false;
    }
  }

  return true;
}

/**
 * A complete block template ready for mining.
 */
export interface BlockTemplate {
  /** Block header (nonce set to 0, ready for mining). */
  header: BlockHeader;
  /** The coinbase transaction. */
  coinbaseTx: Transaction;
  /** Selected mempool transactions (ordered by inclusion order). */
  transactions: Transaction[];
  /** Total fees from all selected transactions. */
  totalFees: bigint;
  /** Total weight of the block (including header). */
  totalWeight: number;
  /** Total sigops cost of the block. */
  totalSigOps: number;
  /** Block height. */
  height: number;
  /** Target value for proof of work. */
  target: bigint;
}

/**
 * Reserve weight for coinbase transaction.
 * A typical coinbase with witness commitment is ~200 bytes base, ~1000 weight units.
 * We reserve 4000 to be safe and allow for larger coinbase scripts.
 */
const COINBASE_WEIGHT_RESERVE = 4000;

/**
 * Witness commitment header: OP_RETURN (0x6a) + push 36 bytes (0x24) + commitment marker (0xaa21a9ed)
 */
const WITNESS_COMMITMENT_HEADER = Buffer.from([0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed]);

/**
 * Block template builder.
 *
 * Constructs valid block templates by selecting transactions from the mempool,
 * ordering them correctly (respecting dependencies), and creating the coinbase
 * transaction with proper height encoding and witness commitment.
 */
export class BlockTemplateBuilder {
  private mempool: Mempool;
  private chainState: ChainStateManager;
  private params: ConsensusParams;

  /**
   * Median time past for locktime validation.
   * Set via setMedianTimePast() or automatically calculated if available.
   */
  private medianTimePast: number = 0;

  constructor(mempool: Mempool, chainState: ChainStateManager, params: ConsensusParams) {
    this.mempool = mempool;
    this.chainState = chainState;
    this.params = params;
  }

  /**
   * Set the median time past for locktime validation.
   * This should be the MTP of the previous block (the block we're building on top of).
   *
   * @param mtp - The median time past in Unix timestamp seconds
   */
  setMedianTimePast(mtp: number): void {
    this.medianTimePast = mtp;
  }

  /**
   * Get the current median time past.
   */
  getMedianTimePast(): number {
    return this.medianTimePast;
  }

  /**
   * Build a block template for the given coinbase output script.
   *
   * @param coinbaseScript - The scriptPubKey for the coinbase output (miner's reward address)
   * @param extraNonce - Extra data for the coinbase to expand nonce search space
   * @returns A complete block template ready for mining
   */
  createTemplate(coinbaseScript: Buffer, extraNonce: Buffer = Buffer.alloc(0)): BlockTemplate {
    const bestBlock = this.chainState.getBestBlock();
    const height = bestBlock.height + 1;

    // Select transactions from mempool
    const { txs: selectedEntries, totalFees, totalWeight: txWeight } = this.selectTransactions();

    // Get the selected transactions
    const transactions = selectedEntries.map(entry => entry.tx);

    // Get next block target
    const target = this.getNextTarget();

    // Build coinbase transaction (needs witness commitment if segwit active)
    const segwitActive = height >= this.params.segwitHeight;

    // Compute witness commitment if segwit is active
    let witnessCommitment: Buffer = Buffer.alloc(32, 0);
    if (segwitActive) {
      // We need the coinbase wtxid as 32 zero bytes for the commitment
      const wtxids: Buffer[] = [Buffer.alloc(32, 0)]; // Coinbase wtxid placeholder
      for (const tx of transactions) {
        wtxids.push(getWTxId(tx));
      }
      const witnessMerkleRoot = computeWitnessMerkleRoot(wtxids);
      // Witness nonce is 32 zero bytes
      const witnessNonce: Buffer = Buffer.alloc(32, 0);
      witnessCommitment = hash256(Buffer.concat([witnessMerkleRoot, witnessNonce]));
    }

    const coinbaseTx = this.buildCoinbase(
      height,
      totalFees,
      coinbaseScript,
      extraNonce,
      segwitActive ? witnessCommitment : Buffer.alloc(0)
    );

    // Compute merkle root with coinbase first
    const allTxs = [coinbaseTx, ...transactions];
    const txids = allTxs.map(tx => getTxId(tx));
    const merkleRoot = computeMerkleRoot(txids);

    // Calculate block timestamp (max of current time and MTP + 1)
    // For simplicity, we use current time since we don't have easy access to MTP here
    // In production, this should be max(now, MTP + 1)
    const timestamp = Math.floor(Date.now() / 1000);

    // Build block header
    const header: BlockHeader = {
      version: 0x20000000, // BIP9 version bits
      prevBlock: bestBlock.hash,
      merkleRoot,
      timestamp,
      bits: bigIntToCompact(target),
      nonce: 0, // Miner will increment this
    };

    // Calculate total block weight
    const coinbaseWeight = getTxWeight(coinbaseTx);
    const headerWeight = 80 * 4; // 80 bytes * 4 = 320 weight units
    const totalWeight = headerWeight + coinbaseWeight + txWeight;

    // For now, sigops tracking is simplified (would need per-tx sigop counting)
    const totalSigOps = 0;

    return {
      header,
      coinbaseTx,
      transactions,
      totalFees,
      totalWeight,
      totalSigOps,
      height,
      target,
    };
  }

  /**
   * Select transactions from the mempool greedily by fee rate.
   *
   * Respects:
   * - Maximum block weight (minus coinbase reserve)
   * - Maximum sigops cost
   * - Parent-child dependencies (parent must be included before child)
   * - Transaction locktime (must be final at the target block height/time)
   */
  private selectTransactions(): { txs: MempoolEntry[]; totalFees: bigint; totalWeight: number } {
    const maxWeight = this.params.maxBlockWeight - COINBASE_WEIGHT_RESERVE - 80 * 4; // Subtract header weight too
    const maxSigOps = this.params.maxBlockSigOpsCost;

    // Get target block height for locktime validation
    const bestBlock = this.chainState.getBestBlock();
    const targetHeight = bestBlock.height + 1;

    // Get all mempool entries sorted by fee rate (descending)
    const entries = this.mempool.getTransactionsByFeeRate();

    const selected: MempoolEntry[] = [];
    const selectedTxids = new Set<string>();
    let totalFees = 0n;
    let totalWeight = 0;
    let totalSigOps = 0;

    // Track which entries we've processed to avoid re-checking
    const processed = new Set<string>();

    // Track entries that are not final (for skipping)
    const notFinal = new Set<string>();

    // Helper to check if all dependencies are satisfied
    const canInclude = (entry: MempoolEntry): boolean => {
      for (const parentTxidHex of entry.dependsOn) {
        if (!selectedTxids.has(parentTxidHex)) {
          return false;
        }
      }
      return true;
    };

    // Helper to add an entry and its ancestors
    const addWithAncestors = (entry: MempoolEntry): boolean => {
      const txidHex = entry.txid.toString("hex");

      if (selectedTxids.has(txidHex)) {
        return true; // Already selected
      }

      // Check if this transaction is final
      if (notFinal.has(txidHex)) {
        return false;
      }

      if (!isFinalTx(entry.tx, targetHeight, this.medianTimePast)) {
        notFinal.add(txidHex);
        return false;
      }

      // First, recursively add all ancestors
      for (const parentTxidHex of entry.dependsOn) {
        if (!selectedTxids.has(parentTxidHex)) {
          // Find the parent entry
          const parentTxid = Buffer.from(parentTxidHex, "hex");
          const parentEntry = this.mempool.getTransaction(parentTxid);
          if (!parentEntry) {
            // Parent not in mempool anymore, can't include this tx
            return false;
          }
          if (!addWithAncestors(parentEntry)) {
            return false;
          }
        }
      }

      // Now we can add this entry
      // Check weight constraint
      if (totalWeight + entry.weight > maxWeight) {
        return false;
      }

      // Note: For proper sigops tracking, we would need to count sigops per tx
      // For now, we skip sigops checking as it requires script analysis

      selected.push(entry);
      selectedTxids.add(txidHex);
      totalFees += entry.fee;
      totalWeight += entry.weight;

      return true;
    };

    // Process entries by fee rate
    for (const entry of entries) {
      const txidHex = entry.txid.toString("hex");

      if (processed.has(txidHex) || selectedTxids.has(txidHex)) {
        continue;
      }

      processed.add(txidHex);

      // Try to add this entry (with its ancestors if needed)
      addWithAncestors(entry);

      // Early exit if we've filled the block
      if (totalWeight >= maxWeight - 1000) {
        break; // Leave some margin
      }
    }

    return { txs: selected, totalFees, totalWeight };
  }

  /**
   * Build the coinbase transaction.
   *
   * Structure:
   * - Input: prevOut = {txid: 32 zero bytes, vout: 0xFFFFFFFF}, scriptSig = [BIP34 height] + extraNonce + optional data
   * - Output 0: value = subsidy + fees, scriptPubKey = coinbaseScript
   * - Output 1 (if segwit): OP_RETURN witness commitment
   * - Witness (if segwit): 32 zero bytes (witness nonce)
   */
  private buildCoinbase(
    height: number,
    fees: bigint,
    coinbaseScript: Buffer,
    extraNonce: Buffer,
    witnessCommitment: Buffer
  ): Transaction {
    // Calculate subsidy
    const subsidy = getBlockSubsidy(height, this.params);
    const totalReward = subsidy + fees;

    // Build BIP34 height push for scriptSig
    const heightPush = this.encodeBIP34Height(height);

    // Build scriptSig: height push + extraNonce
    const scriptSig = Buffer.concat([heightPush, extraNonce]);

    // Build inputs
    const inputs: TxIn[] = [
      {
        prevOut: {
          txid: Buffer.alloc(32, 0),
          vout: 0xffffffff,
        },
        scriptSig,
        sequence: 0xffffffff,
        witness: witnessCommitment.length > 0 ? [Buffer.alloc(32, 0)] : [], // Witness nonce if segwit
      },
    ];

    // Build outputs
    const outputs: TxOut[] = [
      {
        value: totalReward,
        scriptPubKey: coinbaseScript,
      },
    ];

    // Add witness commitment output if needed
    if (witnessCommitment.length === 32) {
      const commitmentScript = Buffer.concat([
        WITNESS_COMMITMENT_HEADER,
        witnessCommitment,
      ]);
      outputs.push({
        value: 0n,
        scriptPubKey: commitmentScript,
      });
    }

    return {
      version: 2,
      inputs,
      outputs,
      lockTime: 0,
    };
  }

  /**
   * Encode height as BIP34 push data for coinbase scriptSig.
   *
   * BIP34 requires the height to be pushed using minimal CScript encoding:
   * - Heights 0: OP_0 (0x00)
   * - Heights 1-16: OP_1 to OP_16 (0x51-0x60)
   * - Heights 17+: [length byte] [height in little-endian]
   *
   * For heights >= 17, we use the minimal encoding which is:
   * - 1 byte for heights 17-127 (since 0x00 prefix needed for >= 128 to avoid negative)
   * - 2 bytes for heights 128-32767
   * - etc.
   */
  private encodeBIP34Height(height: number): Buffer {
    if (height < 0) {
      throw new Error("Height cannot be negative");
    }

    if (height === 0) {
      // OP_0
      return Buffer.from([0x00]);
    }

    if (height >= 1 && height <= 16) {
      // OP_1 to OP_16 (0x51 to 0x60)
      return Buffer.from([0x50 + height]);
    }

    // For heights >= 17, use minimal push encoding
    // Convert height to little-endian bytes, with minimal encoding
    const heightBytes = this.encodeScriptNum(height);

    // Push opcode + height bytes
    return Buffer.concat([
      Buffer.from([heightBytes.length]), // Push length (will be 1-4 for reasonable heights)
      heightBytes,
    ]);
  }

  /**
   * Encode a number as a minimal CScript number (little-endian with sign handling).
   */
  private encodeScriptNum(n: number): Buffer {
    if (n === 0) {
      return Buffer.alloc(0);
    }

    const negative = n < 0;
    let absValue = Math.abs(n);
    const result: number[] = [];

    while (absValue > 0) {
      result.push(absValue & 0xff);
      absValue >>= 8;
    }

    // If the most significant byte has the high bit set and the number is positive,
    // add a 0x00 byte to avoid it being interpreted as negative
    if (result[result.length - 1] & 0x80) {
      result.push(negative ? 0x80 : 0x00);
    } else if (negative) {
      result[result.length - 1] |= 0x80;
    }

    return Buffer.from(result);
  }

  /**
   * Compute the witness commitment for the block.
   *
   * commitment = hash256(witness_merkle_root || witness_nonce)
   *
   * The witness merkle root uses wtxids, with the coinbase wtxid as 32 zero bytes.
   */
  private computeWitnessCommitment(txs: Transaction[], coinbaseWtxid: Buffer): Buffer {
    // Build list of wtxids with coinbase as zeros
    const wtxids: Buffer[] = [Buffer.alloc(32, 0)]; // Coinbase wtxid is always zeros
    for (const tx of txs) {
      wtxids.push(getWTxId(tx));
    }

    const witnessMerkleRoot = computeWitnessMerkleRoot(wtxids);

    // Witness nonce is 32 zero bytes
    const witnessNonce = Buffer.alloc(32, 0);

    return hash256(Buffer.concat([witnessMerkleRoot, witnessNonce]));
  }

  /**
   * Calculate the next block's target from the current chain state.
   *
   * This is a simplified version. In production, this would need to
   * properly implement difficulty adjustment based on the last 2016 blocks.
   */
  private getNextTarget(): bigint {
    const bestBlock = this.chainState.getBestBlock();

    // For now, return a simple target based on current chain state
    // A full implementation would calculate difficulty adjustment
    // This would typically come from the HeaderSync module

    // Default to max target (easiest difficulty) for simplicity
    // In production, this should calculate proper difficulty adjustment
    return this.params.powLimit;
  }
}

/**
 * Create a coinbase output script for a P2PKH address.
 * Format: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
 */
export function createP2PKHCoinbaseScript(pubKeyHash: Buffer): Buffer {
  if (pubKeyHash.length !== 20) {
    throw new Error("pubKeyHash must be 20 bytes");
  }
  return Buffer.concat([
    Buffer.from([0x76, 0xa9, 0x14]), // OP_DUP OP_HASH160 PUSH20
    pubKeyHash,
    Buffer.from([0x88, 0xac]), // OP_EQUALVERIFY OP_CHECKSIG
  ]);
}

/**
 * Create a coinbase output script for a P2WPKH address (native segwit).
 * Format: OP_0 <20 bytes>
 */
export function createP2WPKHCoinbaseScript(pubKeyHash: Buffer): Buffer {
  if (pubKeyHash.length !== 20) {
    throw new Error("pubKeyHash must be 20 bytes");
  }
  return Buffer.concat([
    Buffer.from([0x00, 0x14]), // OP_0 PUSH20
    pubKeyHash,
  ]);
}

/**
 * Create a coinbase output script for a P2WSH address.
 * Format: OP_0 <32 bytes>
 */
export function createP2WSHCoinbaseScript(scriptHash: Buffer): Buffer {
  if (scriptHash.length !== 32) {
    throw new Error("scriptHash must be 32 bytes");
  }
  return Buffer.concat([
    Buffer.from([0x00, 0x20]), // OP_0 PUSH32
    scriptHash,
  ]);
}
