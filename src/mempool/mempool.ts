/**
 * Transaction mempool: unconfirmed transaction storage and eviction.
 *
 * Manages the pool of unconfirmed transactions waiting to be included in blocks.
 * Validates transactions, tracks dependencies between mempool transactions,
 * enforces fee-rate minimums, and evicts low-fee transactions when full.
 */

import type { UTXOEntry } from "../storage/database.js";
import type { UTXOManager } from "../chain/utxo.js";
import type { ConsensusParams } from "../consensus/params.js";
import type { Block } from "../validation/block.js";
import type { Transaction, OutPoint } from "../validation/tx.js";
import {
  validateTxBasic,
  getTxId,
  getTxWeight,
  getTxVSize,
  isCoinbase,
  serializeTx,
} from "../validation/tx.js";
import {
  verifyScript,
  getConsensusFlags,
  type ScriptFlags,
} from "../script/interpreter.js";
import { sigHashLegacy, sigHashWitnessV0 } from "../validation/tx.js";

/**
 * Ancestor/descendant limits per BIP-125.
 */
const MAX_ANCESTORS = 25;
const MAX_DESCENDANTS = 25;
const MAX_ANCESTOR_SIZE = 101_000; // 101 KB in vbytes

/**
 * Default mempool size (300 MB in vbytes).
 */
const DEFAULT_MAX_SIZE = 300_000_000;

/**
 * Default minimum fee rate (1 sat/vB).
 */
const DEFAULT_MIN_FEE_RATE = 1;

/**
 * An entry in the mempool representing an unconfirmed transaction.
 */
export interface MempoolEntry {
  /** The transaction. */
  tx: Transaction;
  /** The transaction ID (hash of non-witness serialization). */
  txid: Buffer;
  /** Transaction fee in satoshis. */
  fee: bigint;
  /** Fee rate in satoshis per virtual byte. */
  feeRate: number;
  /** Virtual size (vsize = ceil(weight/4)). */
  vsize: number;
  /** Transaction weight (BIP-141). */
  weight: number;
  /** Unix timestamp when added to mempool. */
  addedTime: number;
  /** Chain height when the transaction was added. */
  height: number;
  /** Set of txids (hex) that spend outputs of this transaction (children). */
  spentBy: Set<string>;
  /** Set of txids (hex) that this transaction depends on (parents in mempool). */
  dependsOn: Set<string>;
}

/**
 * UTXO entry from mempool (not yet confirmed).
 */
interface MempoolUTXO {
  amount: bigint;
  scriptPubKey: Buffer;
  txid: Buffer;
  vout: number;
}

/**
 * Transaction memory pool.
 *
 * Validates and stores unconfirmed transactions. When full, evicts transactions
 * with the lowest fee rate. Tracks dependencies between mempool transactions
 * to handle chained unconfirmed transactions.
 */
export class Mempool {
  /** Map of txid hex -> entry. */
  private entries: Map<string, MempoolEntry>;

  /** Map of "txid_hex:vout" -> spending txid hex. */
  private outpointIndex: Map<string, string>;

  /** Maximum mempool size in vbytes. */
  private maxSize: number;

  /** Current total vsize of all entries. */
  private currentSize: number;

  /** UTXO manager for checking confirmed outputs. */
  private utxo: UTXOManager;

  /** Consensus parameters. */
  private params: ConsensusParams;

  /** Minimum fee rate to accept (sat/vB). Dynamic based on eviction. */
  private minFeeRate: number;

  /** Current chain tip height. */
  private tipHeight: number;

  constructor(
    utxo: UTXOManager,
    params: ConsensusParams,
    maxSize: number = DEFAULT_MAX_SIZE
  ) {
    this.entries = new Map();
    this.outpointIndex = new Map();
    this.maxSize = maxSize;
    this.currentSize = 0;
    this.utxo = utxo;
    this.params = params;
    this.minFeeRate = DEFAULT_MIN_FEE_RATE;
    this.tipHeight = 0;
  }

  /**
   * Set the current chain tip height.
   */
  setTipHeight(height: number): void {
    this.tipHeight = height;
  }

  /**
   * Get the current chain tip height.
   */
  getTipHeight(): number {
    return this.tipHeight;
  }

  /**
   * Validate and add a transaction to the mempool.
   *
   * Validation steps:
   * 1. Basic structural validation (validateTxBasic)
   * 2. Not already in mempool or confirmed
   * 3. No double-spend conflicts with existing mempool entries
   * 4. All inputs exist (in UTXO set or mempool)
   * 5. Input values >= output values (positive fee)
   * 6. Fee rate >= minFeeRate
   * 7. Script validation for all inputs
   * 8. Weight <= MAX_BLOCK_WEIGHT
   * 9. Ancestor/descendant limits
   */
  async addTransaction(
    tx: Transaction
  ): Promise<{ accepted: boolean; error?: string }> {
    // 1. Basic structural validation
    const basicResult = validateTxBasic(tx);
    if (!basicResult.valid) {
      return { accepted: false, error: basicResult.error };
    }

    // Coinbase transactions cannot be in mempool
    if (isCoinbase(tx)) {
      return { accepted: false, error: "Coinbase transaction not allowed in mempool" };
    }

    const txid = getTxId(tx);
    const txidHex = txid.toString("hex");

    // 2. Not already in mempool
    if (this.entries.has(txidHex)) {
      return { accepted: false, error: "Transaction already in mempool" };
    }

    // 3. Check for double-spend conflicts
    const conflicts = this.checkConflicts(tx);
    if (conflicts.length > 0) {
      return {
        accepted: false,
        error: `Double-spend conflict with mempool transaction ${conflicts[0].txid.toString("hex")}`,
      };
    }

    // 4. Check all inputs exist and calculate fee
    let totalInput = 0n;
    const parentTxids: Set<string> = new Set();
    const inputUtxos: Array<{
      utxo: UTXOEntry | MempoolUTXO;
      input: (typeof tx.inputs)[0];
      isMempool: boolean;
    }> = [];

    for (const input of tx.inputs) {
      const outpointKey = `${input.prevOut.txid.toString("hex")}:${input.prevOut.vout}`;
      const parentTxidHex = input.prevOut.txid.toString("hex");

      // Check if input is from mempool
      const mempoolParent = this.entries.get(parentTxidHex);
      if (mempoolParent) {
        if (input.prevOut.vout >= mempoolParent.tx.outputs.length) {
          return {
            accepted: false,
            error: `Invalid mempool input: ${outpointKey}`,
          };
        }

        const output = mempoolParent.tx.outputs[input.prevOut.vout];
        totalInput += output.value;
        parentTxids.add(parentTxidHex);
        inputUtxos.push({
          utxo: {
            amount: output.value,
            scriptPubKey: output.scriptPubKey,
            txid: input.prevOut.txid,
            vout: input.prevOut.vout,
          },
          input,
          isMempool: true,
        });
      } else {
        // Check UTXO set
        const utxo = await this.utxo.getUTXOAsync(input.prevOut);
        if (!utxo) {
          return {
            accepted: false,
            error: `Missing input: ${outpointKey}`,
          };
        }

        // Check coinbase maturity
        if (utxo.coinbase) {
          const confirmations = this.tipHeight - utxo.height;
          if (confirmations < this.params.coinbaseMaturity) {
            return {
              accepted: false,
              error: `Coinbase maturity not met: ${confirmations} < ${this.params.coinbaseMaturity}`,
            };
          }
        }

        totalInput += utxo.amount;
        inputUtxos.push({ utxo, input, isMempool: false });
      }
    }

    // 5. Calculate fee
    let totalOutput = 0n;
    for (const output of tx.outputs) {
      totalOutput += output.value;
    }

    if (totalInput < totalOutput) {
      return {
        accepted: false,
        error: `Insufficient input value: ${totalInput} < ${totalOutput}`,
      };
    }

    const fee = totalInput - totalOutput;

    // Calculate weight and vsize
    const weight = getTxWeight(tx);
    const vsize = getTxVSize(tx);

    // 8. Check weight limit
    if (weight > this.params.maxBlockWeight) {
      return {
        accepted: false,
        error: `Transaction weight ${weight} exceeds max ${this.params.maxBlockWeight}`,
      };
    }

    // 6. Check fee rate
    const feeRate = Number(fee) / vsize;
    if (feeRate < this.minFeeRate) {
      return {
        accepted: false,
        error: `Fee rate ${feeRate.toFixed(2)} sat/vB below minimum ${this.minFeeRate}`,
      };
    }

    // 9. Check ancestor/descendant limits
    const ancestorResult = this.checkAncestorLimits(parentTxids, vsize);
    if (!ancestorResult.valid) {
      return { accepted: false, error: ancestorResult.error };
    }

    // 7. Script validation
    const flags = getConsensusFlags(this.tipHeight);

    for (let i = 0; i < tx.inputs.length; i++) {
      const { utxo, input, isMempool } = inputUtxos[i];

      // Create sighash function for this input
      const sigHasher = (subscript: Buffer, hashType: number): Buffer => {
        // Determine if this is a witness input
        const witnessProgram = utxo.scriptPubKey;
        const isSegwit =
          (witnessProgram.length === 22 &&
            witnessProgram[0] === 0x00 &&
            witnessProgram[1] === 20) ||
          (witnessProgram.length === 34 &&
            witnessProgram[0] === 0x00 &&
            witnessProgram[1] === 32);

        if (isSegwit || input.witness.length > 0) {
          return sigHashWitnessV0(tx, i, subscript, utxo.amount, hashType);
        } else {
          return sigHashLegacy(tx, i, subscript, hashType);
        }
      };

      const valid = verifyScript(
        input.scriptSig,
        utxo.scriptPubKey,
        input.witness,
        flags,
        sigHasher
      );

      if (!valid) {
        return {
          accepted: false,
          error: `Script validation failed for input ${i}`,
        };
      }
    }

    // Create the mempool entry
    const entry: MempoolEntry = {
      tx,
      txid,
      fee,
      feeRate,
      vsize,
      weight,
      addedTime: Math.floor(Date.now() / 1000),
      height: this.tipHeight,
      spentBy: new Set(),
      dependsOn: parentTxids,
    };

    // Add to mempool
    this.entries.set(txidHex, entry);
    this.currentSize += vsize;

    // Update parent entries' spentBy
    for (const parentTxidHex of parentTxids) {
      const parent = this.entries.get(parentTxidHex);
      if (parent) {
        parent.spentBy.add(txidHex);
      }
    }

    // Index the spent outpoints
    for (const input of tx.inputs) {
      const outpointKey = `${input.prevOut.txid.toString("hex")}:${input.prevOut.vout}`;
      this.outpointIndex.set(outpointKey, txidHex);
    }

    // Evict if over size limit
    if (this.currentSize > this.maxSize) {
      this.evict();
    }

    return { accepted: true };
  }

  /**
   * Remove a transaction from the mempool.
   *
   * @param txid - The transaction ID to remove
   * @param removeDependents - If true, also remove all dependent transactions (default: true)
   */
  removeTransaction(txid: Buffer, removeDependents: boolean = true): void {
    const txidHex = txid.toString("hex");
    const entry = this.entries.get(txidHex);

    if (!entry) {
      return;
    }

    // If removing dependents, recursively remove children first
    if (removeDependents) {
      for (const childTxidHex of entry.spentBy) {
        const childTxid = Buffer.from(childTxidHex, "hex");
        this.removeTransaction(childTxid, true);
      }
    }

    // Remove from parent's spentBy
    for (const parentTxidHex of entry.dependsOn) {
      const parent = this.entries.get(parentTxidHex);
      if (parent) {
        parent.spentBy.delete(txidHex);
      }
    }

    // Remove outpoint index entries
    for (const input of entry.tx.inputs) {
      const outpointKey = `${input.prevOut.txid.toString("hex")}:${input.prevOut.vout}`;
      this.outpointIndex.delete(outpointKey);
    }

    // Remove from entries
    this.entries.delete(txidHex);
    this.currentSize -= entry.vsize;
  }

  /**
   * Remove all transactions confirmed in a block.
   *
   * Also removes any transactions that conflict with the block
   * (double-spends that weren't included).
   */
  removeForBlock(block: Block): void {
    const confirmedTxids = new Set<string>();

    // First, collect all confirmed txids and remove them
    for (const tx of block.transactions) {
      if (isCoinbase(tx)) continue;

      const txid = getTxId(tx);
      const txidHex = txid.toString("hex");
      confirmedTxids.add(txidHex);

      // Remove the transaction (but not its dependents yet - they may also be confirmed)
      const entry = this.entries.get(txidHex);
      if (entry) {
        // Remove outpoint index entries
        for (const input of entry.tx.inputs) {
          const outpointKey = `${input.prevOut.txid.toString("hex")}:${input.prevOut.vout}`;
          this.outpointIndex.delete(outpointKey);
        }

        // Remove from entries
        this.entries.delete(txidHex);
        this.currentSize -= entry.vsize;
      }
    }

    // Now check for conflicts (mempool txs that spend inputs used by block txs)
    const conflictingTxids: string[] = [];

    for (const tx of block.transactions) {
      if (isCoinbase(tx)) continue;

      for (const input of tx.inputs) {
        const outpointKey = `${input.prevOut.txid.toString("hex")}:${input.prevOut.vout}`;
        const spendingTxid = this.outpointIndex.get(outpointKey);

        if (spendingTxid && !confirmedTxids.has(spendingTxid)) {
          conflictingTxids.push(spendingTxid);
        }
      }
    }

    // Remove conflicting transactions (with their dependents)
    for (const txidHex of conflictingTxids) {
      const txid = Buffer.from(txidHex, "hex");
      this.removeTransaction(txid, true);
    }

    // Update dependency tracking for remaining transactions
    for (const [txidHex, entry] of this.entries) {
      // Remove confirmed parents from dependsOn
      for (const parentTxidHex of entry.dependsOn) {
        if (confirmedTxids.has(parentTxidHex)) {
          entry.dependsOn.delete(parentTxidHex);
        }
      }

      // Remove confirmed children from spentBy
      for (const childTxidHex of entry.spentBy) {
        if (confirmedTxids.has(childTxidHex)) {
          entry.spentBy.delete(childTxidHex);
        }
      }
    }
  }

  /**
   * Re-add transactions after a block disconnect (reorg).
   *
   * Attempts to re-add transactions that were previously confirmed
   * but are now unconfirmed due to a chain reorganization.
   */
  async readdTransactions(txs: Transaction[]): Promise<void> {
    for (const tx of txs) {
      // Skip coinbase
      if (isCoinbase(tx)) continue;

      // Try to add back to mempool - ignore failures
      await this.addTransaction(tx);
    }
  }

  /**
   * Get transactions sorted by fee rate (descending) for block template.
   */
  getTransactionsByFeeRate(): MempoolEntry[] {
    const entries = Array.from(this.entries.values());

    // Sort by fee rate descending
    entries.sort((a, b) => b.feeRate - a.feeRate);

    return entries;
  }

  /**
   * Get a transaction from the mempool by txid.
   */
  getTransaction(txid: Buffer): MempoolEntry | null {
    const txidHex = txid.toString("hex");
    return this.entries.get(txidHex) ?? null;
  }

  /**
   * Check if a transaction exists in the mempool.
   */
  hasTransaction(txid: Buffer): boolean {
    return this.entries.has(txid.toString("hex"));
  }

  /**
   * Get all transaction IDs in the mempool.
   */
  getAllTxids(): Buffer[] {
    return Array.from(this.entries.keys()).map((hex) => Buffer.from(hex, "hex"));
  }

  /**
   * Check if a transaction conflicts with existing mempool entries.
   *
   * A conflict occurs when the transaction spends an output that is
   * already spent by another mempool transaction (double-spend).
   */
  private checkConflicts(tx: Transaction): MempoolEntry[] {
    const conflicts: MempoolEntry[] = [];

    for (const input of tx.inputs) {
      const outpointKey = `${input.prevOut.txid.toString("hex")}:${input.prevOut.vout}`;
      const spendingTxid = this.outpointIndex.get(outpointKey);

      if (spendingTxid) {
        const entry = this.entries.get(spendingTxid);
        if (entry && !conflicts.includes(entry)) {
          conflicts.push(entry);
        }
      }
    }

    return conflicts;
  }

  /**
   * Check ancestor limits for a new transaction.
   */
  private checkAncestorLimits(
    parentTxids: Set<string>,
    newTxVsize: number
  ): { valid: boolean; error?: string } {
    // Count all ancestors (including parents of parents)
    const ancestors = new Set<string>();
    let ancestorSize = newTxVsize;
    const queue = Array.from(parentTxids);

    while (queue.length > 0) {
      const txidHex = queue.shift()!;

      if (ancestors.has(txidHex)) continue;
      ancestors.add(txidHex);

      const entry = this.entries.get(txidHex);
      if (entry) {
        ancestorSize += entry.vsize;

        // Add this entry's parents to the queue
        for (const parentTxidHex of entry.dependsOn) {
          if (!ancestors.has(parentTxidHex)) {
            queue.push(parentTxidHex);
          }
        }
      }
    }

    // The limit includes the new transaction itself
    // So if ancestors.size >= MAX_ANCESTORS, adding this tx would exceed the limit
    if (ancestors.size >= MAX_ANCESTORS) {
      return {
        valid: false,
        error: `Too many ancestors: ${ancestors.size} >= ${MAX_ANCESTORS}`,
      };
    }

    if (ancestorSize > MAX_ANCESTOR_SIZE) {
      return {
        valid: false,
        error: `Ancestor size too large: ${ancestorSize} > ${MAX_ANCESTOR_SIZE}`,
      };
    }

    // Check descendant limits for each parent
    for (const parentTxidHex of parentTxids) {
      const parent = this.entries.get(parentTxidHex);
      if (parent) {
        const descendantCount = this.countDescendants(parentTxidHex);
        if (descendantCount >= MAX_DESCENDANTS) {
          return {
            valid: false,
            error: `Parent ${parentTxidHex.slice(0, 16)}... has too many descendants: ${descendantCount} >= ${MAX_DESCENDANTS}`,
          };
        }
      }
    }

    return { valid: true };
  }

  /**
   * Count the number of descendants for a transaction.
   */
  private countDescendants(txidHex: string): number {
    const descendants = new Set<string>();
    const queue: string[] = [];

    const entry = this.entries.get(txidHex);
    if (!entry) return 0;

    for (const childTxidHex of entry.spentBy) {
      queue.push(childTxidHex);
    }

    while (queue.length > 0) {
      const childTxidHex = queue.shift()!;

      if (descendants.has(childTxidHex)) continue;
      descendants.add(childTxidHex);

      const childEntry = this.entries.get(childTxidHex);
      if (childEntry) {
        for (const grandchildTxidHex of childEntry.spentBy) {
          if (!descendants.has(grandchildTxidHex)) {
            queue.push(grandchildTxidHex);
          }
        }
      }
    }

    return descendants.size;
  }

  /**
   * Evict lowest fee-rate transactions to make room.
   *
   * Removes transactions with the lowest fee rate until the mempool
   * is below the size limit. Updates minFeeRate to the rate of the
   * last evicted transaction.
   */
  private evict(): void {
    // Sort by fee rate ascending
    const entries = Array.from(this.entries.values());
    entries.sort((a, b) => a.feeRate - b.feeRate);

    let evictedFeeRate = this.minFeeRate;

    while (this.currentSize > this.maxSize && entries.length > 0) {
      const lowest = entries.shift()!;
      evictedFeeRate = lowest.feeRate;

      // Remove the transaction and all its descendants
      this.removeTransaction(lowest.txid, true);

      // Re-filter entries list since we may have removed descendants
      const remainingTxids = new Set(this.entries.keys());
      entries.splice(
        0,
        entries.length,
        ...entries.filter((e) => remainingTxids.has(e.txid.toString("hex")))
      );
    }

    // Update minimum fee rate to slightly above the last evicted rate
    this.minFeeRate = Math.max(this.minFeeRate, evictedFeeRate * 1.1);
  }

  /**
   * Get mempool statistics.
   */
  getInfo(): { size: number; bytes: number; minFeeRate: number } {
    return {
      size: this.entries.size,
      bytes: this.currentSize,
      minFeeRate: this.minFeeRate,
    };
  }

  /**
   * Get mempool entry count.
   */
  getSize(): number {
    return this.entries.size;
  }

  /**
   * Clear all mempool entries.
   */
  clear(): void {
    this.entries.clear();
    this.outpointIndex.clear();
    this.currentSize = 0;
    this.minFeeRate = DEFAULT_MIN_FEE_RATE;
  }
}
