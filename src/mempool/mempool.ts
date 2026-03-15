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
  getWTxId,
  getTxWeight,
  getTxVSize,
  isCoinbase,
  serializeTx,
} from "../validation/tx.js";
import { sha256Hash } from "../crypto/primitives.js";
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
 * TRUC (v3) policy constants per BIP 431.
 * v3 transactions have stricter relay rules to enable more reliable fee bumping.
 */
export const TRUC_VERSION = 3;
/** Maximum number of transactions including a TRUC tx and all its mempool ancestors. */
export const TRUC_ANCESTOR_LIMIT = 2;
/** Maximum number of transactions including an unconfirmed tx and its descendants. */
export const TRUC_DESCENDANT_LIMIT = 2;
/** Maximum sigop-adjusted virtual size of all v3 transactions. */
export const TRUC_MAX_VSIZE = 10_000;
/** Maximum sigop-adjusted virtual size of a tx which spends from an unconfirmed TRUC transaction. */
export const TRUC_CHILD_MAX_VSIZE = 1000;

/**
 * Package relay limits.
 * MAX_PACKAGE_COUNT: Maximum number of transactions in a package
 * MAX_PACKAGE_WEIGHT: Maximum total weight of a package (404,000 WU = 101 kvB)
 */
export const MAX_PACKAGE_COUNT = 25;
export const MAX_PACKAGE_WEIGHT = 404_000;

/**
 * Default mempool size (300 MB in vbytes).
 */
const DEFAULT_MAX_SIZE = 300_000_000;

/**
 * Default minimum fee rate (1 sat/vB).
 */
const DEFAULT_MIN_FEE_RATE = 1;

/**
 * Default incremental relay fee rate (1 sat/vB).
 * Replacement must pay at least this much per vbyte more than what it evicts.
 */
const DEFAULT_INCREMENTAL_RELAY_FEE = 1;

/**
 * Maximum number of transactions that can be evicted by a single RBF replacement.
 * This includes the directly conflicting transactions and all their descendants.
 */
const MAX_REPLACEMENT_CANDIDATES = 100;

/**
 * Package validation result types.
 */
export enum PackageValidationResult {
  /** Package validation state was not set (success). */
  PCKG_RESULT_UNSET = 0,
  /** Package policy validation failed. */
  PCKG_POLICY = 1,
  /** One or more transactions in the package failed validation. */
  PCKG_TX = 2,
  /** Internal mempool error. */
  PCKG_MEMPOOL_ERROR = 3,
}

/**
 * Result of validating/accepting a single transaction within a package.
 */
export interface PackageTxResult {
  /** Transaction ID (hex). */
  txid: string;
  /** Witness transaction ID (hex). */
  wtxid: string;
  /** Whether the transaction was accepted. */
  accepted: boolean;
  /** Error message if not accepted. */
  error?: string;
  /** Virtual size if accepted. */
  vsize?: number;
  /** Fee in satoshis if accepted. */
  fee?: bigint;
  /** Effective fee rate (package fee rate) if accepted. */
  effectiveFeeRate?: number;
  /** WTXIDs of transactions included in the effective fee rate calculation. */
  effectiveIncludes?: string[];
}

/**
 * Result of package validation/acceptance.
 */
export interface PackageResult {
  /** Overall package validation result. */
  result: PackageValidationResult;
  /** Human-readable message. */
  message: string;
  /** Per-transaction results keyed by wtxid. */
  txResults: Map<string, PackageTxResult>;
  /** Transactions that were replaced (RBF). */
  replacedTxids: string[];
}

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
  /** Cached ancestor count (including self). */
  ancestorCount: number;
  /** Cached total ancestor size in vbytes (including self). */
  ancestorSize: number;
  /** Cached descendant count (including self). */
  descendantCount: number;
  /** Cached total descendant size in vbytes (including self). */
  descendantSize: number;
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

  /** Incremental relay fee rate (sat/vB). Replacement must pay this per vbyte over replaced fees. */
  private incrementalRelayFee: number;

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
    this.incrementalRelayFee = DEFAULT_INCREMENTAL_RELAY_FEE;
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

    // 3. Check for double-spend conflicts - with RBF support
    const conflicts = this.checkConflicts(tx);
    let isReplacement = false;
    let conflictsToEvict: MempoolEntry[] = [];
    let totalConflictingFee = 0n;
    let totalConflictingVsize = 0;

    if (conflicts.length > 0) {
      // Mark this as a potential RBF replacement - we'll validate the fees later
      isReplacement = true;

      // Gather all conflicts and their descendants
      const allConflictTxids = new Set<string>();
      for (const conflict of conflicts) {
        allConflictTxids.add(conflict.txid.toString("hex"));
        const descendants = this.getDescendantSet(conflict.txid.toString("hex"));
        for (const desc of descendants) {
          allConflictTxids.add(desc);
        }
      }

      // Check eviction limit (Rule #5: max 100 transactions)
      if (allConflictTxids.size > MAX_REPLACEMENT_CANDIDATES) {
        return {
          accepted: false,
          error: `RBF would evict too many transactions: ${allConflictTxids.size} > ${MAX_REPLACEMENT_CANDIDATES}`,
        };
      }

      // Collect all entries to be evicted
      for (const txidHex of allConflictTxids) {
        const entry = this.entries.get(txidHex);
        if (entry) {
          conflictsToEvict.push(entry);
          totalConflictingFee += entry.fee;
          totalConflictingVsize += entry.vsize;
        }
      }
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

    // RBF replacement checks (BIP 125 Rule #3 and #4)
    if (isReplacement) {
      // Rule #3: Replacement must pay a higher absolute fee
      if (fee <= totalConflictingFee) {
        return {
          accepted: false,
          error: `RBF replacement fee ${fee} must be greater than conflicting fee ${totalConflictingFee}`,
        };
      }

      // Rule #4: Additional fee must cover the replacement's own bandwidth
      // newFee - sumOldFees >= incrementalRelayFee * newVsize
      const additionalFee = fee - totalConflictingFee;
      const requiredIncrementalFee = BigInt(this.incrementalRelayFee * vsize);
      if (additionalFee < requiredIncrementalFee) {
        return {
          accepted: false,
          error: `RBF incremental fee ${additionalFee} < required ${requiredIncrementalFee} (${this.incrementalRelayFee} sat/vB * ${vsize} vB)`,
        };
      }

      // Additional check: new tx's fee rate must be higher than all directly conflicting txs
      for (const conflict of conflicts) {
        if (feeRate <= conflict.feeRate) {
          return {
            accepted: false,
            error: `RBF replacement fee rate ${feeRate.toFixed(2)} must be higher than conflicting tx ${conflict.txid.toString("hex").slice(0, 16)}... fee rate ${conflict.feeRate.toFixed(2)}`,
          };
        }
      }
    }

    // 9a. Check TRUC (v3) policy rules
    const trucResult = this.checkTRUCPolicy(
      tx,
      vsize,
      parentTxids,
      conflicts,
      isReplacement
    );
    if (!trucResult.valid) {
      // If sibling eviction is possible, add the sibling to conflicts
      if (trucResult.siblingToEvict) {
        // Sibling eviction: v3 child can replace existing v3 child
        const siblingEntry = this.entries.get(trucResult.siblingToEvict);
        if (siblingEntry) {
          // For sibling eviction, we allow replacement without normal RBF fee-rate rules
          // Just need to pay higher absolute fee
          if (fee <= siblingEntry.fee) {
            return {
              accepted: false,
              error: `TRUC sibling eviction requires higher fee: ${fee} <= ${siblingEntry.fee}`,
            };
          }

          // Add sibling to eviction list
          if (!conflictsToEvict.some((e) => e.txid.toString("hex") === trucResult.siblingToEvict)) {
            conflictsToEvict.push(siblingEntry);
            totalConflictingFee += siblingEntry.fee;
            totalConflictingVsize += siblingEntry.vsize;
            isReplacement = true;
          }
        }
      } else {
        return { accepted: false, error: trucResult.error };
      }
    }

    // 9b. Check ancestor/descendant limits (standard, non-TRUC)
    // For TRUC, we've already checked in checkTRUCPolicy with stricter limits
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

    // If this is an RBF replacement, remove all conflicting transactions first
    if (isReplacement) {
      for (const conflictEntry of conflictsToEvict) {
        // Remove without removing dependents since we're removing all of them
        this.removeTransactionInternal(conflictEntry.txid);
      }
    }

    // Calculate ancestor stats before creating entry
    const { ancestorCount, ancestorSize } = this.calculateAncestorStats(parentTxids, vsize);

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
      ancestorCount,
      ancestorSize,
      descendantCount: 1, // Only self initially
      descendantSize: vsize,
    };

    // Add to mempool
    this.entries.set(txidHex, entry);
    this.currentSize += vsize;

    // Update parent entries' spentBy and descendant stats
    for (const parentTxidHex of parentTxids) {
      const parent = this.entries.get(parentTxidHex);
      if (parent) {
        parent.spentBy.add(txidHex);
      }
    }

    // Update all ancestors' descendant counts
    this.updateAncestorDescendantStats(txidHex, vsize);

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

    // Update ancestors' descendant stats before removing
    const ancestors = this.getAncestorSet(entry.dependsOn);
    for (const ancestorTxidHex of ancestors) {
      const ancestor = this.entries.get(ancestorTxidHex);
      if (ancestor) {
        ancestor.descendantCount -= 1;
        ancestor.descendantSize -= entry.vsize;
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

    // Recalculate cached stats for all remaining entries
    this.recalculateAllStats();
  }

  /**
   * Recalculate all cached ancestor/descendant stats.
   * Called after bulk operations like removeForBlock.
   */
  private recalculateAllStats(): void {
    // Reset all stats
    for (const entry of this.entries.values()) {
      entry.ancestorCount = 1; // Self
      entry.ancestorSize = entry.vsize;
      entry.descendantCount = 1; // Self
      entry.descendantSize = entry.vsize;
    }

    // Recalculate ancestors for each entry
    for (const [txidHex, entry] of this.entries) {
      const ancestors = this.getAncestorSet(entry.dependsOn);
      let ancestorSize = entry.vsize;
      for (const ancestorTxidHex of ancestors) {
        const ancestor = this.entries.get(ancestorTxidHex);
        if (ancestor) {
          ancestorSize += ancestor.vsize;
        }
      }
      entry.ancestorCount = ancestors.size + 1;
      entry.ancestorSize = ancestorSize;
    }

    // Recalculate descendants: for each entry, increment all its ancestors' descendant counts
    for (const [txidHex, entry] of this.entries) {
      const ancestors = this.getAncestorSet(entry.dependsOn);
      for (const ancestorTxidHex of ancestors) {
        const ancestor = this.entries.get(ancestorTxidHex);
        if (ancestor) {
          ancestor.descendantCount += 1;
          ancestor.descendantSize += entry.vsize;
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
   * Check if a transaction is already confirmed in the blockchain.
   *
   * A transaction is considered confirmed if at least one of its outputs
   * exists in the UTXO set (or was spent after being confirmed).
   * We check output 0 as a heuristic - if the tx was confirmed, at least
   * one output must have been created.
   *
   * @param txid The transaction ID to check
   * @returns true if the transaction appears to be confirmed
   */
  async isTransactionConfirmed(txid: Buffer): Promise<boolean> {
    // Check if output 0 exists in the UTXO set
    // If it does, the transaction is confirmed (output exists)
    const utxoExists = await this.utxo.hasUTXOAsync({ txid, vout: 0 });
    return utxoExists;
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
    // Calculate ancestor stats
    const { ancestorCount, ancestorSize } = this.calculateAncestorStats(parentTxids, newTxVsize);

    // The limit includes the new transaction itself
    // So if ancestorCount > MAX_ANCESTORS, it exceeds the limit
    if (ancestorCount > MAX_ANCESTORS) {
      return {
        valid: false,
        error: `Too many ancestors: ${ancestorCount} > ${MAX_ANCESTORS}`,
      };
    }

    if (ancestorSize > MAX_ANCESTOR_SIZE) {
      return {
        valid: false,
        error: `Ancestor size too large: ${ancestorSize} > ${MAX_ANCESTOR_SIZE}`,
      };
    }

    // Check descendant limits for each ancestor
    // Adding this tx would increase each ancestor's descendant count by 1
    const allAncestors = this.getAncestorSet(parentTxids);
    for (const ancestorTxidHex of allAncestors) {
      const ancestor = this.entries.get(ancestorTxidHex);
      if (ancestor) {
        // Use cached descendant count - adding this tx would add 1 more
        const newDescendantCount = ancestor.descendantCount + 1;
        if (newDescendantCount > MAX_DESCENDANTS) {
          return {
            valid: false,
            error: `Ancestor ${ancestorTxidHex.slice(0, 16)}... would have too many descendants: ${newDescendantCount} > ${MAX_DESCENDANTS}`,
          };
        }
      }
    }

    return { valid: true };
  }

  /**
   * Check TRUC (v3) policy rules for a transaction.
   *
   * Rules for nVersion === 3 transactions:
   * 1. A v3 tx can have at most 1 unconfirmed ancestor (parent) in the mempool.
   * 2. A v3 tx can have at most 1 unconfirmed descendant (child).
   * 3. A v3 child tx must be at most 1000 vbytes.
   * 4. A v3 parent can be up to standard size (TRUC_MAX_VSIZE = 10000).
   * 5. v3 transactions are always replaceable (implicit RBF signaling).
   * 6. A v3 child can replace an existing v3 child of the same parent without
   *    the normal RBF fee-rate rule (sibling eviction).
   * 7. Non-v3 transactions cannot spend unconfirmed v3 outputs;
   *    v3 transactions cannot spend unconfirmed non-v3 outputs.
   *
   * @returns Result with optional siblingToEvict txid for sibling eviction
   */
  private checkTRUCPolicy(
    tx: Transaction,
    vsize: number,
    parentTxids: Set<string>,
    conflicts: MempoolEntry[],
    isReplacement: boolean
  ): { valid: boolean; error?: string; siblingToEvict?: string } {
    const isV3 = tx.version === TRUC_VERSION;

    // Get mempool parents (those that are in the mempool)
    const mempoolParents: MempoolEntry[] = [];
    for (const parentTxidHex of parentTxids) {
      const parent = this.entries.get(parentTxidHex);
      if (parent) {
        mempoolParents.push(parent);
      }
    }

    // Rule 7: Check version inheritance between this tx and its mempool parents
    for (const parent of mempoolParents) {
      const parentIsV3 = parent.tx.version === TRUC_VERSION;

      if (isV3 && !parentIsV3) {
        // v3 tx cannot spend unconfirmed non-v3 outputs
        return {
          valid: false,
          error: `version=3 tx cannot spend from non-version=3 unconfirmed tx ${parent.txid.toString("hex").slice(0, 16)}...`,
        };
      }

      if (!isV3 && parentIsV3) {
        // non-v3 tx cannot spend unconfirmed v3 outputs
        return {
          valid: false,
          error: `non-version=3 tx cannot spend from version=3 unconfirmed tx ${parent.txid.toString("hex").slice(0, 16)}...`,
        };
      }
    }

    // The rest of the rules only apply to v3 transactions
    if (!isV3) {
      return { valid: true };
    }

    // Rule 4: v3 tx must be within TRUC_MAX_VSIZE
    if (vsize > TRUC_MAX_VSIZE) {
      return {
        valid: false,
        error: `version=3 tx is too big: ${vsize} > ${TRUC_MAX_VSIZE} vbytes`,
      };
    }

    // Rule 1: v3 tx can have at most 1 unconfirmed ancestor (parent) in mempool
    // With TRUC_ANCESTOR_LIMIT = 2, that means parent + self
    if (mempoolParents.length > 1) {
      return {
        valid: false,
        error: `version=3 tx would have too many ancestors: ${mempoolParents.length + 1} > ${TRUC_ANCESTOR_LIMIT}`,
      };
    }

    // If there's a mempool parent, ensure it doesn't also have an ancestor
    if (mempoolParents.length === 1) {
      const parent = mempoolParents[0];
      // Check if parent has any mempool ancestors
      if (parent.dependsOn.size > 0) {
        return {
          valid: false,
          error: `version=3 tx would have too many ancestors`,
        };
      }

      // Rule 3: If this is a child (has unconfirmed parent), it must be small
      if (vsize > TRUC_CHILD_MAX_VSIZE) {
        return {
          valid: false,
          error: `version=3 child tx is too big: ${vsize} > ${TRUC_CHILD_MAX_VSIZE} vbytes`,
        };
      }

      // Rule 2: Check descendant limit for the parent
      // The parent can have at most 1 descendant (this new tx)
      // But if an existing child will be replaced (conflict or sibling eviction), it's ok
      const parentTxidHex = parent.txid.toString("hex");

      // Count current descendants of the parent (not including pending conflicts)
      const conflictTxids = new Set(conflicts.map((c) => c.txid.toString("hex")));
      let currentDescendants = 0;
      let existingChild: MempoolEntry | undefined;

      for (const childTxidHex of parent.spentBy) {
        if (!conflictTxids.has(childTxidHex)) {
          currentDescendants++;
          const child = this.entries.get(childTxidHex);
          if (child && child.tx.version === TRUC_VERSION) {
            existingChild = child;
          }
        }
      }

      // If parent already has a descendant that isn't being replaced
      if (currentDescendants >= 1) {
        // Sibling eviction: if there's exactly one existing v3 child, we can evict it
        if (
          currentDescendants === 1 &&
          existingChild &&
          existingChild.descendantCount === 1 // Child has no grandchildren
        ) {
          // Allow sibling eviction - return the sibling to be evicted
          return {
            valid: false,
            error: `version=3 tx would exceed descendant limit`,
            siblingToEvict: existingChild.txid.toString("hex"),
          };
        }

        return {
          valid: false,
          error: `version=3 tx would exceed descendant limit: parent ${parentTxidHex.slice(0, 16)}... already has ${currentDescendants} descendant(s)`,
        };
      }
    }

    return { valid: true };
  }

  /**
   * Calculate ancestor count and size for a new transaction.
   */
  private calculateAncestorStats(
    parentTxids: Set<string>,
    newTxVsize: number
  ): { ancestorCount: number; ancestorSize: number } {
    const ancestors = this.getAncestorSet(parentTxids);

    let ancestorSize = newTxVsize; // Include self
    for (const txidHex of ancestors) {
      const entry = this.entries.get(txidHex);
      if (entry) {
        ancestorSize += entry.vsize;
      }
    }

    return {
      ancestorCount: ancestors.size + 1, // +1 for self
      ancestorSize,
    };
  }

  /**
   * Get the set of all ancestor txids (not including self).
   */
  private getAncestorSet(parentTxids: Set<string>): Set<string> {
    const ancestors = new Set<string>();
    const queue = Array.from(parentTxids);

    while (queue.length > 0) {
      const txidHex = queue.shift()!;

      if (ancestors.has(txidHex)) continue;
      ancestors.add(txidHex);

      const entry = this.entries.get(txidHex);
      if (entry) {
        for (const parentTxidHex of entry.dependsOn) {
          if (!ancestors.has(parentTxidHex)) {
            queue.push(parentTxidHex);
          }
        }
      }
    }

    return ancestors;
  }

  /**
   * Update all ancestors' descendant counts when a new tx is added.
   */
  private updateAncestorDescendantStats(newTxidHex: string, newTxVsize: number): void {
    const entry = this.entries.get(newTxidHex);
    if (!entry) return;

    const ancestors = this.getAncestorSet(entry.dependsOn);
    for (const ancestorTxidHex of ancestors) {
      const ancestor = this.entries.get(ancestorTxidHex);
      if (ancestor) {
        ancestor.descendantCount += 1;
        ancestor.descendantSize += newTxVsize;
      }
    }
  }

  /**
   * Count the number of descendants for a transaction (using BFS, not cache).
   * This is used for verification/debugging.
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
   * Get the set of all descendant txids (not including self).
   * Used for RBF to calculate total eviction count.
   */
  private getDescendantSet(txidHex: string): Set<string> {
    const descendants = new Set<string>();
    const queue: string[] = [];

    const entry = this.entries.get(txidHex);
    if (!entry) return descendants;

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

    return descendants;
  }

  /**
   * Remove a transaction from the mempool without removing dependents.
   * Used internally by RBF when we're removing all conflicts at once.
   */
  private removeTransactionInternal(txid: Buffer): void {
    const txidHex = txid.toString("hex");
    const entry = this.entries.get(txidHex);

    if (!entry) {
      return;
    }

    // Update ancestors' descendant stats before removing
    const ancestors = this.getAncestorSet(entry.dependsOn);
    for (const ancestorTxidHex of ancestors) {
      const ancestor = this.entries.get(ancestorTxidHex);
      if (ancestor) {
        ancestor.descendantCount -= 1;
        ancestor.descendantSize -= entry.vsize;
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
   * Check if a transaction is replaceable (always true for full RBF).
   * In full RBF mode, all unconfirmed transactions are replaceable.
   */
  isReplaceable(_txid: Buffer): boolean {
    // Full RBF: all mempool transactions are replaceable
    return true;
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
   * Get the minimum fee rate in sat/kvB (for BIP133 feefilter).
   * Returns the current minimum relay fee rate * 1000.
   */
  getMinFeeRateKvB(): bigint {
    return BigInt(Math.floor(this.minFeeRate * 1000));
  }

  /**
   * Set the incremental relay fee rate (sat/vB).
   * For RBF, replacement must pay at least this * newVsize more than replaced fees.
   */
  setIncrementalRelayFee(rate: number): void {
    this.incrementalRelayFee = rate;
  }

  /**
   * Get the incremental relay fee rate (sat/vB).
   */
  getIncrementalRelayFee(): number {
    return this.incrementalRelayFee;
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

  /**
   * Submit a package of transactions for validation and acceptance.
   *
   * Package validation allows related transactions to be validated together,
   * enabling CPFP (Child-Pays-For-Parent) fee bumping. A parent transaction
   * with a low fee rate can be accepted if its child pays enough fees to
   * bring the combined package fee rate above the mempool minimum.
   *
   * @param transactions - Array of transactions in topological order (parents before children)
   * @returns Package validation result with per-transaction results
   */
  async submitPackage(transactions: Transaction[]): Promise<PackageResult> {
    // Initialize result
    const txResults = new Map<string, PackageTxResult>();
    const replacedTxids: string[] = [];

    // Empty package
    if (transactions.length === 0) {
      return {
        result: PackageValidationResult.PCKG_POLICY,
        message: "package-empty",
        txResults,
        replacedTxids,
      };
    }

    // Single transaction - just use regular acceptance
    if (transactions.length === 1) {
      const tx = transactions[0];
      const txid = getTxId(tx).toString("hex");
      const wtxid = getWTxId(tx).toString("hex");

      const result = await this.addTransaction(tx);

      txResults.set(wtxid, {
        txid,
        wtxid,
        accepted: result.accepted,
        error: result.error,
        vsize: result.accepted ? getTxVSize(tx) : undefined,
      });

      return {
        result: result.accepted
          ? PackageValidationResult.PCKG_RESULT_UNSET
          : PackageValidationResult.PCKG_TX,
        message: result.accepted ? "success" : result.error || "transaction-rejected",
        txResults,
        replacedTxids,
      };
    }

    // Validate package structure
    const packageValidation = validatePackage(transactions);
    if (!packageValidation.valid) {
      // Create error results for all transactions
      for (const tx of transactions) {
        const txid = getTxId(tx).toString("hex");
        const wtxid = getWTxId(tx).toString("hex");
        txResults.set(wtxid, {
          txid,
          wtxid,
          accepted: false,
          error: "package-not-validated",
        });
      }

      return {
        result: PackageValidationResult.PCKG_POLICY,
        message: packageValidation.error!,
        txResults,
        replacedTxids,
      };
    }

    // Build a map of pending transactions for fee calculation
    // This allows us to look up outputs from package members that aren't in mempool yet
    const pendingTxs = new Map<string, Transaction>();
    for (const tx of transactions) {
      pendingTxs.set(getTxId(tx).toString("hex"), tx);
    }

    // First pass: calculate fees for all transactions using the pending map
    const txFees = new Map<string, bigint>();
    const txVsizes = new Map<string, number>();

    for (const tx of transactions) {
      const txid = getTxId(tx).toString("hex");
      const wtxid = getWTxId(tx).toString("hex");

      // Check if already in mempool
      if (this.entries.has(txid)) {
        const entry = this.entries.get(txid)!;
        txFees.set(txid, entry.fee);
        txVsizes.set(txid, entry.vsize);
        txResults.set(wtxid, {
          txid,
          wtxid,
          accepted: true,
          vsize: entry.vsize,
          fee: entry.fee,
        });
        continue;
      }

      // Calculate fee for this transaction
      const feeResult = await this.calculateTxFee(tx, pendingTxs);
      if (!feeResult.valid) {
        // Transaction is invalid
        txResults.set(wtxid, {
          txid,
          wtxid,
          accepted: false,
          error: feeResult.error,
        });

        return {
          result: PackageValidationResult.PCKG_TX,
          message: feeResult.error || "transaction-invalid",
          txResults,
          replacedTxids,
        };
      }

      txFees.set(txid, feeResult.fee!);
      txVsizes.set(txid, getTxVSize(tx));
    }

    // Calculate total package fee and vsize
    let totalPackageFee = 0n;
    let totalPackageVsize = 0;
    const packageWtxids: string[] = [];

    for (const tx of transactions) {
      const txid = getTxId(tx).toString("hex");
      const wtxid = getWTxId(tx).toString("hex");

      // Skip transactions already in mempool (they're already accounted for)
      if (this.entries.has(txid)) {
        continue;
      }

      totalPackageFee += txFees.get(txid)!;
      totalPackageVsize += txVsizes.get(txid)!;
      packageWtxids.push(wtxid);
    }

    // Calculate package fee rate
    const packageFeeRate = totalPackageVsize > 0
      ? Number(totalPackageFee) / totalPackageVsize
      : 0;

    // Check if package fee rate meets minimum
    if (totalPackageVsize > 0 && packageFeeRate < this.minFeeRate) {
      // Package fee rate too low
      for (const tx of transactions) {
        const txid = getTxId(tx).toString("hex");
        const wtxid = getWTxId(tx).toString("hex");

        if (this.entries.has(txid)) {
          continue; // Already in mempool
        }

        txResults.set(wtxid, {
          txid,
          wtxid,
          accepted: false,
          error: `Package fee rate ${packageFeeRate.toFixed(2)} sat/vB below minimum ${this.minFeeRate}`,
        });
      }

      return {
        result: PackageValidationResult.PCKG_POLICY,
        message: "package-fee-too-low",
        txResults,
        replacedTxids,
      };
    }

    // Now add all transactions to mempool in order
    // Bypass individual fee checks since we've validated package fee rate
    const acceptedTxs: Transaction[] = [];

    for (const tx of transactions) {
      const txid = getTxId(tx).toString("hex");
      const wtxid = getWTxId(tx).toString("hex");

      // Skip if already in mempool
      if (this.entries.has(txid)) {
        continue;
      }

      // Add with bypassed fee check
      const result = await this.addTransactionBypassFeeCheck(tx);

      if (result.accepted) {
        acceptedTxs.push(tx);
        const entry = this.entries.get(txid)!;
        txResults.set(wtxid, {
          txid,
          wtxid,
          accepted: true,
          vsize: entry.vsize,
          fee: entry.fee,
          effectiveFeeRate: packageFeeRate,
          effectiveIncludes: packageWtxids,
        });
      } else {
        txResults.set(wtxid, {
          txid,
          wtxid,
          accepted: false,
          error: result.error,
        });

        // Remove already accepted transactions from this package
        for (const acceptedTx of acceptedTxs) {
          this.removeTransaction(getTxId(acceptedTx), true);
        }

        return {
          result: PackageValidationResult.PCKG_TX,
          message: result.error || "transaction-rejected",
          txResults,
          replacedTxids,
        };
      }
    }

    return {
      result: PackageValidationResult.PCKG_RESULT_UNSET,
      message: "success",
      txResults,
      replacedTxids,
    };
  }

  /**
   * Calculate the fee for a transaction without adding it to mempool.
   * Used for CPFP package fee rate calculation.
   *
   * @param tx - Transaction to calculate fee for
   * @param pendingTxs - Optional map of txid -> Transaction for transactions
   *                     in the package that haven't been added to mempool yet.
   */
  private async calculateTxFee(
    tx: Transaction,
    pendingTxs?: Map<string, Transaction>
  ): Promise<{ valid: boolean; fee?: bigint; error?: string }> {
    // Basic validation
    const basicResult = validateTxBasic(tx);
    if (!basicResult.valid) {
      return { valid: false, error: basicResult.error };
    }

    if (isCoinbase(tx)) {
      return { valid: false, error: "Coinbase transaction not allowed" };
    }

    // Calculate input values
    let totalInput = 0n;

    for (const input of tx.inputs) {
      const parentTxidHex = input.prevOut.txid.toString("hex");

      // Check pending transactions first (package members not yet in mempool)
      if (pendingTxs && pendingTxs.has(parentTxidHex)) {
        const pendingTx = pendingTxs.get(parentTxidHex)!;
        if (input.prevOut.vout >= pendingTx.outputs.length) {
          return { valid: false, error: `Invalid pending input` };
        }
        totalInput += pendingTx.outputs[input.prevOut.vout].value;
        continue;
      }

      // Check mempool
      const mempoolParent = this.entries.get(parentTxidHex);
      if (mempoolParent) {
        if (input.prevOut.vout >= mempoolParent.tx.outputs.length) {
          return { valid: false, error: `Invalid mempool input` };
        }
        totalInput += mempoolParent.tx.outputs[input.prevOut.vout].value;
        continue;
      }

      // Check UTXO set
      const utxo = await this.utxo.getUTXOAsync(input.prevOut);
      if (!utxo) {
        return { valid: false, error: `Missing input` };
      }
      totalInput += utxo.amount;
    }

    // Calculate output values
    let totalOutput = 0n;
    for (const output of tx.outputs) {
      totalOutput += output.value;
    }

    if (totalInput < totalOutput) {
      return { valid: false, error: `Insufficient input value` };
    }

    return { valid: true, fee: totalInput - totalOutput };
  }

  /**
   * Add a transaction bypassing the fee rate check.
   * Used for CPFP where the package fee rate has already been validated.
   */
  private async addTransactionBypassFeeCheck(
    tx: Transaction
  ): Promise<{ accepted: boolean; error?: string }> {
    // Save current minFeeRate
    const savedMinFeeRate = this.minFeeRate;

    // Temporarily set minFeeRate to 0 to bypass the check
    this.minFeeRate = 0;

    try {
      const result = await this.addTransaction(tx);
      return result;
    } finally {
      // Restore minFeeRate
      this.minFeeRate = savedMinFeeRate;
    }
  }
}

// ============================================================================
// Package Validation Functions
// ============================================================================

/**
 * Check if transactions are topologically sorted (parents before children).
 *
 * @param transactions - Array of transactions to check
 * @returns true if topologically sorted
 */
export function isTopoSortedPackage(transactions: Transaction[]): boolean {
  // Build a set of txids we've seen so far
  const seenTxids = new Set<string>();

  for (const tx of transactions) {
    const txid = getTxId(tx).toString("hex");

    // Check if any input spends a transaction that comes later
    for (const input of tx.inputs) {
      const parentTxid = input.prevOut.txid.toString("hex");
      // If the parent txid is in our set of txids for this package but not yet seen,
      // it means a parent appears after its child
      if (!seenTxids.has(parentTxid)) {
        // Check if this parent is in the package at all
        const parentInPackage = transactions.some(
          (t) => getTxId(t).toString("hex") === parentTxid
        );
        if (parentInPackage) {
          // Parent is in package but hasn't been processed yet = not topo sorted
          return false;
        }
      }
    }

    seenTxids.add(txid);
  }

  return true;
}

/**
 * Check if package has no conflicting transactions (no double-spends within package).
 *
 * @param transactions - Array of transactions to check
 * @returns true if consistent (no conflicts)
 */
export function isConsistentPackage(transactions: Transaction[]): boolean {
  const inputsSeen = new Set<string>();

  for (const tx of transactions) {
    // Empty inputs are not allowed for non-coinbase transactions
    if (tx.inputs.length === 0) {
      return false;
    }

    // Check for duplicate inputs within package
    for (const input of tx.inputs) {
      const outpointKey = `${input.prevOut.txid.toString("hex")}:${input.prevOut.vout}`;
      if (inputsSeen.has(outpointKey)) {
        // This input is spent by another transaction in the package
        return false;
      }
    }

    // Add all inputs from this transaction
    for (const input of tx.inputs) {
      const outpointKey = `${input.prevOut.txid.toString("hex")}:${input.prevOut.vout}`;
      inputsSeen.add(outpointKey);
    }
  }

  return true;
}

/**
 * Check if package is a child-with-parents structure.
 * The last transaction must be the child, and all other transactions must be parents of that child.
 *
 * @param transactions - Array of transactions to check
 * @returns true if child-with-parents structure
 */
export function isChildWithParents(transactions: Transaction[]): boolean {
  if (transactions.length < 2) {
    return false;
  }

  const child = transactions[transactions.length - 1];

  // Get all input txids of the child
  const childInputTxids = new Set<string>();
  for (const input of child.inputs) {
    childInputTxids.add(input.prevOut.txid.toString("hex"));
  }

  // Every other transaction must be a parent of the child
  for (let i = 0; i < transactions.length - 1; i++) {
    const txid = getTxId(transactions[i]).toString("hex");
    if (!childInputTxids.has(txid)) {
      return false;
    }
  }

  return true;
}

/**
 * Check if package is a child-with-parents tree structure.
 * Child-with-parents, plus parents don't depend on each other.
 *
 * @param transactions - Array of transactions to check
 * @returns true if child-with-parents tree structure
 */
export function isChildWithParentsTree(transactions: Transaction[]): boolean {
  if (!isChildWithParents(transactions)) {
    return false;
  }

  // Get set of parent txids
  const parentTxids = new Set<string>();
  for (let i = 0; i < transactions.length - 1; i++) {
    parentTxids.add(getTxId(transactions[i]).toString("hex"));
  }

  // Each parent must not have an input that is one of the other parents
  for (let i = 0; i < transactions.length - 1; i++) {
    const tx = transactions[i];
    for (const input of tx.inputs) {
      if (parentTxids.has(input.prevOut.txid.toString("hex"))) {
        return false;
      }
    }
  }

  return true;
}

/**
 * Validate a package of transactions.
 *
 * Checks:
 * 1. Package size limits (max 25 transactions, max 404,000 WU)
 * 2. No duplicate transactions
 * 3. Topological ordering (parents before children)
 * 4. No conflicting transactions (double-spends within package)
 *
 * @param transactions - Array of transactions to validate
 * @returns Validation result
 */
export function validatePackage(
  transactions: Transaction[]
): { valid: boolean; error?: string } {
  // Check transaction count
  if (transactions.length > MAX_PACKAGE_COUNT) {
    return {
      valid: false,
      error: "package-too-many-transactions",
    };
  }

  // Calculate total weight
  let totalWeight = 0;
  for (const tx of transactions) {
    totalWeight += getTxWeight(tx);
  }

  // Single transaction packages skip the weight check (reported on individual tx)
  if (transactions.length > 1 && totalWeight > MAX_PACKAGE_WEIGHT) {
    return {
      valid: false,
      error: "package-too-large",
    };
  }

  // Check for duplicate transactions
  const txids = new Set<string>();
  for (const tx of transactions) {
    const txid = getTxId(tx).toString("hex");
    if (txids.has(txid)) {
      return {
        valid: false,
        error: "package-contains-duplicates",
      };
    }
    txids.add(txid);
  }

  // Check topological ordering
  if (!isTopoSortedPackage(transactions)) {
    return {
      valid: false,
      error: "package-not-sorted",
    };
  }

  // Check for conflicts
  if (!isConsistentPackage(transactions)) {
    return {
      valid: false,
      error: "conflict-in-package",
    };
  }

  return { valid: true };
}

/**
 * Compute the package hash (for P2P relay).
 *
 * The package hash is SHA256 of the sorted wtxids concatenated together.
 *
 * @param transactions - Array of transactions
 * @returns 32-byte package hash
 */
export function getPackageHash(transactions: Transaction[]): Buffer {
  // Get all wtxids
  const wtxids = transactions.map((tx) => getWTxId(tx));

  // Sort wtxids lexicographically (comparing as byte arrays)
  wtxids.sort((a, b) => Buffer.compare(a, b));

  // Concatenate and hash
  const concat = Buffer.concat(wtxids);
  return sha256Hash(concat);
}
