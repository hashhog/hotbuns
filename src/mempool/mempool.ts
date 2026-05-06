/**
 * Transaction mempool: unconfirmed transaction storage and eviction.
 *
 * Manages the pool of unconfirmed transactions waiting to be included in blocks.
 * Validates transactions, tracks dependencies between mempool transactions,
 * enforces fee-rate minimums, and evicts low-fee transactions when full.
 *
 * Uses cluster mempool architecture: transactions are organized into clusters
 * (connected components of the dependency graph) and each cluster is linearized
 * for optimal fee-rate ordering.
 */

import { EventEmitter } from "events";
import type { UTXOEntry } from "../storage/database.js";
import type { UTXOManager } from "../chain/utxo.js";
import type { ConsensusParams } from "../consensus/params.js";
import type { Block } from "../validation/block.js";
import { getTransactionSigOpCost, WITNESS_SCALE_FACTOR } from "../validation/block.js";
import type { Transaction, OutPoint, UTXOConfirmation } from "../validation/tx.js";
import {
  validateTxBasic,
  getTxId,
  getWTxId,
  getTxWeight,
  getTxVSize,
  isCoinbase,
  serializeTx,
  checkSequenceLocks,
} from "../validation/tx.js";
import { isFinalTx } from "../mining/template.js";
import { sha256Hash } from "../crypto/primitives.js";
import {
  verifyScript,
  getConsensusFlags,
  getStandardFlags,
  isP2A,
  type ScriptFlags,
} from "../script/interpreter.js";
import { sigHashLegacy, sigHashWitnessV0 } from "../validation/tx.js";
import {
  shouldSkipScripts,
  type AssumeValidBlockEntry,
} from "../consensus/assumevalid.js";

/**
 * Maximum cluster size (replaces ancestor/descendant limits).
 * A cluster is a connected component of transactions in the mempool.
 */
export const MAX_CLUSTER_SIZE = 100;

/**
 * Default dust relay fee rate in sat/kvB.
 * Used to calculate the dust threshold for outputs.
 */
const DUST_RELAY_FEE = 3000;

/**
 * Maximum number of dust outputs allowed per transaction.
 * Per ephemeral anchor policy, only one dust output is allowed.
 */
export const MAX_DUST_OUTPUTS_PER_TX = 1;

/**
 * Legacy ancestor/descendant limits per BIP-125.
 * These are now superseded by MAX_CLUSTER_SIZE but kept for TRUC policy.
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
 * Standard transaction weight ceiling (BIP-141 / policy).
 *
 * `MAX_STANDARD_TX_WEIGHT` is the relay-policy gate Bitcoin Core enforces
 * inside `IsStandardTx` (`bitcoin-core/src/policy/policy.cpp`). It is *not*
 * a consensus rule — the consensus limit is the per-block weight ceiling
 * (`maxBlockWeight = 4_000_000`). Standard txs are 10× tighter so a single
 * relay tx cannot crowd out the rest of the block.
 *
 * Stored as a bigint because the rest of hotbuns's serialization layer
 * uses bigints for 64-bit values.  Compared against `getTxWeight()` which
 * returns a regular `number` — a `BigInt(weight)` cast happens at the
 * comparison site to avoid bigint↔number mixing here.
 */
export const MAX_STANDARD_TX_WEIGHT = 400_000n;

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
  /** Cluster ID this transaction belongs to. */
  clusterId: string;
  /** Mining score (effective fee rate as sat/vB from chunk). */
  miningScore: number;
  /** Set of ephemeral dust parent txids (hex) that this tx spends from. */
  ephemeralDustParents: Set<string>;
  /** True if this transaction has ephemeral dust outputs. */
  hasEphemeralDust: boolean;
  /**
   * Weighted sigop cost for this transaction.
   * legacy sigops × WITNESS_SCALE_FACTOR + P2SH sigops × WITNESS_SCALE_FACTOR
   * + witness sigops × 1.
   * Reference: Bitcoin Core GetTransactionSigOpCost()
   */
  sigOpCost: number;
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

// ============================================================================
// Ephemeral Anchor Policy Functions
// ============================================================================

/**
 * Get the dust threshold for a given scriptPubKey.
 *
 * Dust is defined as an output whose value is less than the cost to spend it.
 * The threshold depends on the output type (witness vs non-witness).
 *
 * Default dust relay fee: 3000 sat/kvB
 * - Segwit output: 98 * 3000 / 1000 = 294 sats
 * - Non-segwit output: 182 * 3000 / 1000 = 546 sats
 */
export function getDustThreshold(scriptPubKey: Buffer): bigint {
  // OP_RETURN is unspendable, dust threshold is 0
  if (scriptPubKey.length > 0 && scriptPubKey[0] === 0x6a) {
    return 0n;
  }

  // Check if witness program (OP_0/OP_1-16 + push)
  const isWitness = scriptPubKey.length >= 4 &&
    (scriptPubKey[0] === 0x00 || (scriptPubKey[0] >= 0x51 && scriptPubKey[0] <= 0x60)) &&
    scriptPubKey[1] >= 2 && scriptPubKey[1] <= 40 &&
    scriptPubKey.length === scriptPubKey[1] + 2;

  if (isWitness) {
    // Segwit: output size + input size with witness discount
    // nSize = output_size + (32 + 4 + 1 + (107/4) + 4) = output_size + 67.75
    // For typical P2WPKH (31 bytes output): 31 + 67 = 98 bytes
    // At 3000 sat/kvB: 98 * 3000 / 1000 = 294 sats
    const outputSize = BigInt(scriptPubKey.length + 8 + 1); // value (8) + scriptLen (1) + script
    const inputSize = 32n + 4n + 1n + 26n + 4n; // prevout + vout + scriptLen + sig/4 + sequence
    return ((outputSize + inputSize) * BigInt(DUST_RELAY_FEE)) / 1000n;
  } else {
    // Non-segwit: output size + input size
    // nSize = output_size + (32 + 4 + 1 + 107 + 4) = output_size + 148
    // For typical P2PKH (34 bytes output): 34 + 148 = 182 bytes
    // At 3000 sat/kvB: 182 * 3000 / 1000 = 546 sats
    const outputSize = BigInt(scriptPubKey.length + 8 + 1);
    const inputSize = 32n + 4n + 1n + 107n + 4n;
    return ((outputSize + inputSize) * BigInt(DUST_RELAY_FEE)) / 1000n;
  }
}

/**
 * Check if an output is dust (value below dust threshold).
 */
export function isDust(value: bigint, scriptPubKey: Buffer): boolean {
  return value < getDustThreshold(scriptPubKey);
}

/**
 * Check if an output is ephemeral dust (0-value dust output).
 * Ephemeral dust is a 0-value output that would normally be considered dust.
 */
export function isEphemeralDust(value: bigint, scriptPubKey: Buffer): boolean {
  return value === 0n && isDust(value, scriptPubKey);
}

/**
 * Get all dust output indices for a transaction.
 */
export function getDustOutputs(tx: Transaction): number[] {
  const dustOutputs: number[] = [];
  for (let i = 0; i < tx.outputs.length; i++) {
    const output = tx.outputs[i];
    if (isDust(output.value, output.scriptPubKey)) {
      dustOutputs.push(i);
    }
  }
  return dustOutputs;
}

/**
 * Get all ephemeral dust output indices for a transaction.
 * Ephemeral dust must be 0-value.
 */
export function getEphemeralDustOutputs(tx: Transaction): number[] {
  const ephemeralOutputs: number[] = [];
  for (let i = 0; i < tx.outputs.length; i++) {
    const output = tx.outputs[i];
    if (output.value === 0n && isDust(output.value, output.scriptPubKey)) {
      ephemeralOutputs.push(i);
    }
  }
  return ephemeralOutputs;
}

/**
 * Check if a transaction has ephemeral dust outputs.
 */
export function hasEphemeralDust(tx: Transaction): boolean {
  return getEphemeralDustOutputs(tx).length > 0;
}

/**
 * Pre-check ephemeral transaction: a tx with dust must have 0 fee.
 * This ensures we never give incentive to mine a dust-creating tx alone.
 */
export function preCheckEphemeralTx(tx: Transaction, fee: bigint): { valid: boolean; error?: string } {
  const dustOutputs = getDustOutputs(tx);

  // If there's no dust, the transaction passes
  if (dustOutputs.length === 0) {
    return { valid: true };
  }

  // A transaction with dust outputs must have 0 fee
  if (fee !== 0n) {
    return {
      valid: false,
      error: "tx with dust output must be 0-fee"
    };
  }

  // Only one dust output allowed per tx
  if (dustOutputs.length > MAX_DUST_OUTPUTS_PER_TX) {
    return {
      valid: false,
      error: `too many dust outputs: ${dustOutputs.length} > ${MAX_DUST_OUTPUTS_PER_TX}`
    };
  }

  return { valid: true };
}

/**
 * Result of ephemeral spend check.
 */
export interface EphemeralSpendResult {
  valid: boolean;
  /** If invalid, the txid of the transaction that failed the check. */
  failedTxid?: string;
  /** If invalid, the wtxid of the transaction that failed the check. */
  failedWtxid?: string;
  /** Error message if invalid. */
  error?: string;
}

/**
 * Check that all ephemeral dust outputs from parents are spent by children.
 *
 * For each transaction in the package:
 * 1. Find all in-package and in-mempool parents
 * 2. Collect all dust outputs from those parents
 * 3. Verify the child spends ALL parent dust outputs
 */
export function checkEphemeralSpends(
  packageTxs: Transaction[],
  mempoolEntries: Map<string, MempoolEntry>
): EphemeralSpendResult {
  // Build txid -> Transaction map for package lookups
  const packageTxMap = new Map<string, Transaction>();
  for (const tx of packageTxs) {
    packageTxMap.set(getTxId(tx).toString("hex"), tx);
  }

  // For each transaction, check that it spends all parent dust
  for (const tx of packageTxs) {
    const processedParents = new Set<string>();
    const unspentParentDust = new Set<string>(); // "txid:vout" format

    // Collect dust from all parents (both in-package and in-mempool)
    for (const input of tx.inputs) {
      const parentTxid = input.prevOut.txid.toString("hex");

      // Skip already processed parents
      if (processedParents.has(parentTxid)) {
        continue;
      }

      // Look for parent in package or mempool
      let parentTx: Transaction | undefined;

      // Check package first
      if (packageTxMap.has(parentTxid)) {
        parentTx = packageTxMap.get(parentTxid);
      } else {
        // Check mempool
        const mempoolEntry = mempoolEntries.get(parentTxid);
        if (mempoolEntry) {
          parentTx = mempoolEntry.tx;
        }
      }

      // If we found the parent, collect its dust outputs
      if (parentTx) {
        for (let i = 0; i < parentTx.outputs.length; i++) {
          const output = parentTx.outputs[i];
          if (isDust(output.value, output.scriptPubKey)) {
            unspentParentDust.add(`${parentTxid}:${i}`);
          }
        }
      }

      processedParents.add(parentTxid);
    }

    // If no parent dust, this tx passes
    if (unspentParentDust.size === 0) {
      continue;
    }

    // Mark dust outputs as spent by this transaction's inputs
    for (const input of tx.inputs) {
      const outpointKey = `${input.prevOut.txid.toString("hex")}:${input.prevOut.vout}`;
      unspentParentDust.delete(outpointKey);
    }

    // If there's still unspent parent dust, the check fails
    if (unspentParentDust.size > 0) {
      const txid = getTxId(tx).toString("hex");
      const wtxid = getWTxId(tx).toString("hex");
      return {
        valid: false,
        failedTxid: txid,
        failedWtxid: wtxid,
        error: `tx ${txid.slice(0, 16)}... did not spend parent's ephemeral dust`,
      };
    }
  }

  return { valid: true };
}

// ============================================================================
// Cluster Mempool Data Structures
// ============================================================================

/**
 * Union-Find (Disjoint Set Union) data structure for efficient cluster identification.
 * Uses weighted union with path compression for near-constant time operations.
 */
export class UnionFind {
  /** Parent pointers. Maps txid hex -> parent txid hex. */
  private parent: Map<string, string>;
  /** Rank (tree depth) for each root. */
  private rank: Map<string, number>;
  /** Size of each set (number of elements). */
  private size: Map<string, number>;

  constructor() {
    this.parent = new Map();
    this.rank = new Map();
    this.size = new Map();
  }

  /**
   * Add a new element to the union-find structure.
   */
  makeSet(id: string): void {
    if (this.parent.has(id)) return;
    this.parent.set(id, id);
    this.rank.set(id, 0);
    this.size.set(id, 1);
  }

  /**
   * Find the root of the set containing the given element.
   * Uses path compression for efficiency.
   */
  find(id: string): string {
    if (!this.parent.has(id)) {
      this.makeSet(id);
    }
    let root = id;
    // Find root
    while (this.parent.get(root) !== root) {
      root = this.parent.get(root)!;
    }
    // Path compression
    let current = id;
    while (current !== root) {
      const next = this.parent.get(current)!;
      this.parent.set(current, root);
      current = next;
    }
    return root;
  }

  /**
   * Union two sets. Returns the root of the merged set.
   * Uses union by rank.
   */
  union(a: string, b: string): string {
    const rootA = this.find(a);
    const rootB = this.find(b);

    if (rootA === rootB) return rootA;

    const rankA = this.rank.get(rootA)!;
    const rankB = this.rank.get(rootB)!;
    const sizeA = this.size.get(rootA)!;
    const sizeB = this.size.get(rootB)!;

    // Union by rank
    if (rankA < rankB) {
      this.parent.set(rootA, rootB);
      this.size.set(rootB, sizeA + sizeB);
      return rootB;
    } else if (rankA > rankB) {
      this.parent.set(rootB, rootA);
      this.size.set(rootA, sizeA + sizeB);
      return rootA;
    } else {
      this.parent.set(rootB, rootA);
      this.rank.set(rootA, rankA + 1);
      this.size.set(rootA, sizeA + sizeB);
      return rootA;
    }
  }

  /**
   * Get the size of the set containing the given element.
   */
  getSize(id: string): number {
    const root = this.find(id);
    return this.size.get(root) ?? 0;
  }

  /**
   * Check if two elements are in the same set.
   */
  connected(a: string, b: string): boolean {
    return this.find(a) === this.find(b);
  }

  /**
   * Remove an element from the structure.
   * Note: This is expensive - requires rebuilding affected sets.
   */
  remove(id: string): void {
    this.parent.delete(id);
    this.rank.delete(id);
    this.size.delete(id);
  }

  /**
   * Clear the entire structure.
   */
  clear(): void {
    this.parent.clear();
    this.rank.clear();
    this.size.clear();
  }

  /**
   * Get all unique root IDs (cluster IDs).
   */
  getAllRoots(): Set<string> {
    const roots = new Set<string>();
    for (const id of this.parent.keys()) {
      roots.add(this.find(id));
    }
    return roots;
  }
}

/**
 * A chunk in the linearization: a set of transactions with aggregate fee rate.
 * Chunks are contiguous prefixes of the linearization that form valid topological orderings.
 */
export interface Chunk {
  /** Transaction IDs (hex) in this chunk. */
  txids: Set<string>;
  /** Total fee (satoshis). */
  totalFee: bigint;
  /** Total vsize (vbytes). */
  totalVsize: number;
  /** Aggregate fee rate (sat/vB). */
  feeRate: number;
}

/**
 * A linearization of a cluster: an ordered list of chunks.
 */
export interface Linearization {
  /** Ordered list of chunks from highest to lowest fee rate. */
  chunks: Chunk[];
  /** Map from txid hex -> chunk index in the linearization. */
  txToChunk: Map<string, number>;
}

/**
 * A cluster: a connected component of transactions in the mempool.
 */
export interface Cluster {
  /** Cluster ID (typically the root txid in union-find). */
  id: string;
  /** All transaction IDs in this cluster. */
  txids: Set<string>;
  /** Total fee. */
  totalFee: bigint;
  /** Total vsize. */
  totalVsize: number;
  /** Current linearization of the cluster. */
  linearization: Linearization;
}

/**
 * Transaction memory pool.
 *
 * Validates and stores unconfirmed transactions. When full, evicts transactions
 * with the lowest fee rate. Tracks dependencies between mempool transactions
 * to handle chained unconfirmed transactions.
 *
 * Uses cluster mempool architecture where transactions are organized into
 * clusters (connected components) and linearized for optimal mining.
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

  /** Median Time Past of the current chain tip (BIP-113 / BIP-68). */
  private tipMTP: number;

  /** Incremental relay fee rate (sat/vB). Replacement must pay this per vbyte over replaced fees. */
  private incrementalRelayFee: number;

  /** Union-Find structure for cluster identification. */
  private clusters: UnionFind;

  /** Map of cluster ID -> Cluster object with linearization. */
  private clusterCache: Map<string, Cluster>;

  /** Whether cluster cache needs to be rebuilt. */
  private clusterCacheDirty: boolean;

  /** Optional event emitter for ZMQ notifications. */
  private notificationEmitter: EventEmitter | null;

  /** Monotonically increasing sequence number for mempool events. */
  private mempoolSequence: bigint;

  /**
   * Optional header sync for assumevalid ancestor checks.
   * When set, the script-verification skip gate is evaluated before each
   * script check. For mempool transactions (always above the assumevalid
   * height), the decision will always be "verify scripts" — the gate is
   * provided here so that it fires automatically once the IBD path gains
   * script verification (P2-OPT-ROUND-2).
   */
  private headerSync: import("../sync/headers.js").HeaderSync | null = null;

  constructor(
    utxo: UTXOManager,
    params: ConsensusParams,
    maxSize: number = DEFAULT_MAX_SIZE,
    notificationEmitter: EventEmitter | null = null
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
    this.tipMTP = 0;
    this.clusters = new UnionFind();
    this.clusterCache = new Map();
    this.clusterCacheDirty = false;
    this.notificationEmitter = notificationEmitter;
    this.mempoolSequence = 0n;
  }

  /**
   * Set the notification event emitter for ZMQ.
   */
  setNotificationEmitter(emitter: EventEmitter): void {
    this.notificationEmitter = emitter;
  }

  /**
   * Set the header sync reference for assumevalid ancestor checks.
   *
   * Once set, the script-verification skip gate (shouldSkipScripts) is
   * evaluated before each per-input verifyScript call in addTransaction.
   * For unconfirmed mempool txns the check will always return "verify
   * scripts" since they are above the assumevalid height. This wiring
   * exists so the canonical gate is in place for the IBD path once
   * script verification is added there (P2-OPT-ROUND-2).
   */
  setHeaderSync(headerSync: import("../sync/headers.js").HeaderSync): void {
    this.headerSync = headerSync;
  }

  /**
   * Get the current mempool sequence number.
   */
  getMempoolSequence(): bigint {
    return this.mempoolSequence;
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
   * Set the Median Time Past of the current chain tip.
   * Used for BIP-113 IsFinalTx and BIP-68 SequenceLocks checks.
   *
   * @param mtp - MTP in Unix timestamp seconds
   */
  setTipMTP(mtp: number): void {
    this.tipMTP = mtp;
  }

  /**
   * Get the current chain tip MTP.
   */
  getTipMTP(): number {
    return this.tipMTP;
  }

  /**
   * AcceptToMemoryPool validates and adds a transaction to the mempool.
   * This is the canonical entry point matching Bitcoin Core's naming convention.
   * Performs all policy checks including BIP125 RBF, fee-rate validation,
   * script verification, and cluster mempool limits.
   */
  async acceptToMemoryPool(
    tx: Transaction
  ): Promise<{ accepted: boolean; error?: string }> {
    return this.addTransaction(tx);
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

    // 8a. Standard-tx relay-policy weight gate (IsStandardTx in
    //     bitcoin-core/src/policy/policy.cpp).  Mempool txs above
    //     MAX_STANDARD_TX_WEIGHT (400_000 WU = 100 kvB) are non-standard
    //     and rejected at the relay layer even though they would be
    //     consensus-valid as block contents.
    if (BigInt(weight) > MAX_STANDARD_TX_WEIGHT) {
      return {
        accepted: false,
        error: `tx-size: weight ${weight} exceeds standard limit ${MAX_STANDARD_TX_WEIGHT}`,
      };
    }

    // 8b. Consensus block-weight ceiling (4 MWU). Defence-in-depth: a
    //     well-formed standard tx will always pass 8a first, so this
    //     branch only fires if the standard limit is ever raised.
    if (weight > this.params.maxBlockWeight) {
      return {
        accepted: false,
        error: `Transaction weight ${weight} exceeds max ${this.params.maxBlockWeight}`,
      };
    }

    // 8c. BIP-113 IsFinalTx: nLockTime must be satisfied at the next block.
    //     Reference: Bitcoin Core CheckFinalTxAtTip() (validation.cpp).
    //     nextHeight = tipHeight + 1; lockTimeCutoff = MTP (BIP-113 MTP rule).
    //     If headerSync is available, compute MTP from the best header; otherwise
    //     fall back to the cached tipMTP value (set via setTipMTP).
    const nextHeight = this.tipHeight + 1;
    let currentMTP = this.tipMTP;
    if (this.headerSync) {
      const bestHdr = this.headerSync.getBestHeader();
      if (bestHdr) {
        currentMTP = this.headerSync.getMedianTimePast(bestHdr);
      }
    }
    if (!isFinalTx(tx, nextHeight, currentMTP)) {
      return {
        accepted: false,
        error: "non-final: bad-txns-nonfinal",
      };
    }

    // 8d. BIP-68 SequenceLocks: per-input relative locktimes (CSV).
    //     Reference: Bitcoin Core CheckSequenceLocksAtTip() (validation.cpp).
    //     For confirmed UTXOs: use tipMTP conservatively as coin MTP (may
    //     false-reject time-locked txs near the boundary but never false-admits).
    //     For mempool parents: synthetic height = tipHeight + 1 (Core convention).
    const enforceBIP68 =
      tx.version >= 2 &&
      this.tipHeight >= (this.params.csvHeight ?? 0);
    if (enforceBIP68) {
      const utxoConfirmations: UTXOConfirmation[] = inputUtxos.map(({ utxo, isMempool: isMp }) => {
        if (isMp) {
          // Unconfirmed parent: treat as mined at tipHeight + 1 with currentMTP.
          return { height: nextHeight, medianTimePast: currentMTP };
        } else {
          // Confirmed UTXO: height from DB; use currentMTP conservatively for MTP.
          const confirmedUtxo = utxo as UTXOEntry;
          return { height: confirmedUtxo.height, medianTimePast: currentMTP };
        }
      });
      if (!checkSequenceLocks(tx, enforceBIP68, nextHeight, currentMTP, utxoConfirmations)) {
        return {
          accepted: false,
          error: "non-BIP68-final: bad-txns-nonfinal",
        };
      }
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

    // 9b. Check cluster size limit (replaces ancestor/descendant limits)
    // For TRUC, we've already checked in checkTRUCPolicy with stricter limits
    const clusterResult = this.checkClusterSizeLimit(parentTxids, vsize);
    if (!clusterResult.valid) {
      return { accepted: false, error: clusterResult.error };
    }

    // Also check legacy ancestor/descendant limits for backward compatibility
    const ancestorResult = this.checkAncestorLimits(parentTxids, vsize);
    if (!ancestorResult.valid) {
      return { accepted: false, error: ancestorResult.error };
    }

    // 7. Script validation
    //
    // Evaluate the assumevalid skip gate before the per-input script loop.
    // For mempool transactions (unconfirmed, at tip height) the ancestor
    // check will always fail (the tx isn't in any confirmed block), so the
    // gate always returns "verify scripts" here. The gate is wired here so
    // that when the IBD path gains script verification (P2-OPT-ROUND-2),
    // the canonical shouldSkipScripts() function fires automatically.
    //
    // NOTE: hotbuns's IBD path (BlockSync.connectBlock) does not currently
    // invoke script verification — this is the separate P2-OPT-ROUND-2 gap
    // "hotbuns has verifyAllInputsParallel defined but never imported; script
    // verification absent from IBD path". Once that is fixed, the assumevalid
    // decision function will fire in the IBD path automatically.
    let skipScripts = false;
    if (this.headerSync && this.params.assumedValid) {
      // Build a pseudo-pindex for the mempool context.
      // Mempool txns are unconfirmed so height is tipHeight+1; hash is
      // unknown — we use an empty hex which will fail the ancestor check,
      // ensuring skipScripts=false for all mempool txns as expected.
      const pindexEntry: AssumeValidBlockEntry = {
        hash: "",
        height: this.tipHeight + 1,
        chainWork: 0n,
      };
      const bestHeader = this.headerSync.getBestHeader();
      const skipResult = shouldSkipScripts({
        pindex: pindexEntry,
        assumedValidHash: this.params.assumedValid,
        getBlockByHash: (hashHex) => {
          const entry = this.headerSync!.getHeader(Buffer.from(hashHex, "hex"));
          if (!entry) return null;
          return { hash: entry.hash.toString("hex"), height: entry.height, chainWork: entry.chainWork };
        },
        getBlockAtHeight: (height) => {
          const entry = this.headerSync!.getHeaderByHeight(height);
          if (!entry) return null;
          return { hash: entry.hash.toString("hex"), height: entry.height, chainWork: entry.chainWork };
        },
        bestHeader: bestHeader
          ? { hash: bestHeader.hash.toString("hex"), height: bestHeader.height, chainWork: bestHeader.chainWork }
          : null,
        minimumChainWork: this.params.nMinimumChainWork,
        pindexTimestamp: Math.floor(Date.now() / 1000),
        bestHeaderTimestamp: bestHeader ? bestHeader.header.timestamp : 0,
      });
      skipScripts = skipResult.skip;
    }

    // Mempool uses standard (policy) flags — stricter than consensus block flags.
    const flags = getStandardFlags(this.tipHeight);

    if (!skipScripts) {
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

    // Track ephemeral dust relationships
    const ephemeralDustParents = new Set<string>();
    for (const parentTxidHex of parentTxids) {
      const parent = this.entries.get(parentTxidHex);
      if (parent && parent.hasEphemeralDust) {
        ephemeralDustParents.add(parentTxidHex);
      }
    }

    // Check if this tx has ephemeral dust outputs
    const txHasEphemeralDust = hasEphemeralDust(tx);

    // Compute weighted sigop cost for this tx.
    // prevOutputs must be in input order; fall back to empty Buffer for
    // any input whose prevout is not in inputUtxos (defence-in-depth).
    // Reference: Bitcoin Core GetTransactionSigOpCost() in consensus/tx_verify.cpp
    const prevOutputsForSigOps: Buffer[] = tx.inputs.map((inp) => {
      const utxoEntry = inputUtxos.find(
        (u) => u.input === inp
      );
      return utxoEntry ? Buffer.from(utxoEntry.utxo.scriptPubKey) : Buffer.alloc(0);
    });
    const sigOpCost = getTransactionSigOpCost(
      tx,
      prevOutputsForSigOps,
      /* verifyP2SH */ true,
      /* verifyWitness */ true
    );

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
      clusterId: txidHex, // Will be updated by addToCluster
      miningScore: feeRate, // Will be updated by linearization
      ephemeralDustParents,
      hasEphemeralDust: txHasEphemeralDust,
      sigOpCost,
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

    // Add to cluster structure
    this.addToCluster(txidHex, parentTxids);

    // Index the spent outpoints
    for (const input of tx.inputs) {
      const outpointKey = `${input.prevOut.txid.toString("hex")}:${input.prevOut.vout}`;
      this.outpointIndex.set(outpointKey, txidHex);
    }

    // Evict if over size limit
    if (this.currentSize > this.maxSize) {
      this.evict();
    }

    // Emit notification for ZMQ
    if (this.notificationEmitter) {
      const seq = this.mempoolSequence;
      this.mempoolSequence += 1n;
      this.notificationEmitter.emit("txAccepted", tx, seq);
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

    // Ephemeral anchor cascade: if this tx spends ephemeral dust from a parent,
    // and this is the only child spending that parent's dust, the parent must
    // also be removed (it can't exist in mempool without its dust being spent).
    const ephemeralParentsToRemove: string[] = [];
    for (const parentTxidHex of entry.ephemeralDustParents) {
      const parent = this.entries.get(parentTxidHex);
      if (parent && parent.hasEphemeralDust) {
        // Check if any other child still spends this parent's dust
        let hasOtherChild = false;
        for (const otherChildHex of parent.spentBy) {
          if (otherChildHex !== txidHex && this.entries.has(otherChildHex)) {
            const otherChild = this.entries.get(otherChildHex)!;
            if (otherChild.ephemeralDustParents.has(parentTxidHex)) {
              hasOtherChild = true;
              break;
            }
          }
        }
        if (!hasOtherChild) {
          ephemeralParentsToRemove.push(parentTxidHex);
        }
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

    // Mark cluster cache as dirty
    this.clusterCacheDirty = true;

    // Emit notification for ZMQ
    if (this.notificationEmitter) {
      const seq = this.mempoolSequence;
      this.mempoolSequence += 1n;
      this.notificationEmitter.emit("txRemoved", txid, seq);
    }

    // Cascade removal of ephemeral dust parents that no longer have their dust spent
    for (const parentTxidHex of ephemeralParentsToRemove) {
      const parentTxid = Buffer.from(parentTxidHex, "hex");
      this.removeTransaction(parentTxid, true);
    }
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

    // Rebuild cluster structure from scratch
    this.rebuildClusters();
  }

  /**
   * Rebuild the cluster union-find structure from scratch.
   * Called after bulk operations like removeForBlock.
   */
  private rebuildClusters(): void {
    this.clusters.clear();
    this.clusterCache.clear();

    // Create singleton sets for all remaining transactions
    for (const txidHex of this.entries.keys()) {
      this.clusters.makeSet(txidHex);
    }

    // Union based on dependencies
    for (const [txidHex, entry] of this.entries) {
      for (const parentTxidHex of entry.dependsOn) {
        if (this.entries.has(parentTxidHex)) {
          this.clusters.union(txidHex, parentTxidHex);
        }
      }
    }

    this.clusterCacheDirty = true;
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
   *
   * Per-tx accept/reject is logged so the reorg dispatcher can
   * surface partial-refill conditions (Pattern B2) in operator logs
   * without trying to re-thread the result back through the caller
   * chain.
   */
  async readdTransactions(txs: Transaction[]): Promise<void> {
    for (const tx of txs) {
      // Skip coinbase
      if (isCoinbase(tx)) continue;

      // Try to add back to mempool — log failure reason.  Reorg refill
      // is best-effort (Bitcoin Core's MaybeUpdateMempoolForReorg
      // semantics: drop txs that are no longer policy-valid against
      // the new tip).  Surfacing the error helps diagnose Pattern B2
      // partial-refill bugs vs. transient policy mismatches.
      const result = await this.addTransaction(tx);
      if (!result.accepted) {
        const txid = getTxId(tx).toString("hex");
        console.warn(
          `[mempool-readd] tx ${txid.slice(0, 16)}... rejected during reorg refill: ${result.error}`
        );
      }
    }
  }

  /**
   * Re-admit transactions disconnected by a chain reorg WITHOUT
   * re-running input UTXO / script / standardness checks.  Used by
   * the reorg-refill code path (BlockSync.connectBlock detects a
   * tip-prev mismatch and feeds disconnected txs here to mirror
   * Bitcoin Core's MaybeUpdateMempoolForReorg, validation.cpp).
   *
   * Why an unchecked path is needed in hotbuns specifically:
   *
   *   1. hotbuns's IBD-time block connect (BlockSync.connectBlock)
   *      does NOT persist undo data — coreConnectBlockChecks returns
   *      `spentOutputs` but BlockSync drops it (only the chain/state.ts
   *      path persists undo data, and that path is unwired during IBD).
   *      Without persisted undo data, a true UTXO disconnect is
   *      impossible: the inputs that the disconnected txs consumed
   *      cannot be restored to the UTXO set.
   *   2. The full validation that addTransaction runs (input lookup,
   *      script, BIP-68/113, fee) would therefore reject every refill
   *      candidate with "Missing input" because the input UTXOs were
   *      consumed by the now-disconnected blocks but never restored.
   *
   * This unchecked admission is policy-correct for the refill case
   * because the txs WERE valid against the chain that included them
   * (the disconnected blocks) — Core's MaybeUpdateMempoolForReorg
   * makes the same trust assumption (it does run a re-validation but
   * only because Core HAS a proper UTXO disconnect; with that prereq
   * met, all checks pass).  The ancestor/descendant + cluster
   * accounting and indexes are still maintained for getrawmempool /
   * RBF / fee-rate ordering correctness.
   *
   * Cross-impl audit:
   * CORE-PARITY-AUDIT/_mempool-refill-on-reorg-fleet-result-2026-05-05.md
   * Reference: camlcoin lib/sync.ml:2354-2363 (uses checked path
   * because OCaml's reorg has full UTXO disconnect first).
   *
   * Side effect: emits a [mempool-reorg-refill] log line per
   * admission so the corpus harness diagnosis (Pattern B1
   * vs B2 vs ordering) can be cross-referenced against per-impl logs.
   */
  reorgRefillUnchecked(txs: Transaction[]): void {
    for (const tx of txs) {
      if (isCoinbase(tx)) continue;
      const txid = getTxId(tx);
      const txidHex = txid.toString("hex");

      // Idempotency: if already in mempool (e.g. user broadcast
      // arrived between disconnect and refill), skip.  Mirrors
      // addTransaction's "already in mempool" guard.
      if (this.entries.has(txidHex)) continue;

      const weight = getTxWeight(tx);
      const vsize = getTxVSize(tx);
      // Fee + feeRate cannot be computed without the input UTXO set.
      // Use 0 (sentinel) — getrawmempool returns the txid which is
      // what the corpus harness checks; ordering uses miningScore
      // which we set to 0 too, so refill txs sort to the end (mining
      // selection prefers paying txs).
      const fee = 0n;
      const feeRate = 0;

      const entry: MempoolEntry = {
        tx,
        txid,
        fee,
        feeRate,
        vsize,
        weight,
        addedTime: Math.floor(Date.now() / 1000),
        height: this.tipHeight,
        spentBy: new Set<string>(),
        dependsOn: new Set<string>(), // unchecked path: no parent tracking
        ancestorCount: 1,
        ancestorSize: vsize,
        descendantCount: 1,
        descendantSize: vsize,
        clusterId: txidHex,
        miningScore: 0,
        ephemeralDustParents: new Set<string>(),
        hasEphemeralDust: false,
        sigOpCost: 0,
      };

      this.entries.set(txidHex, entry);
      this.currentSize += vsize;

      // Index spent outpoints so a later RBF / double-spend would
      // surface this entry as a conflict (defence-in-depth).
      for (const input of tx.inputs) {
        const outpointKey = `${input.prevOut.txid.toString("hex")}:${input.prevOut.vout}`;
        this.outpointIndex.set(outpointKey, txidHex);
      }

      console.log(
        `[mempool-reorg-refill] re-admitted disconnected tx ${txidHex.slice(0, 16)}... (vsize=${vsize})`
      );
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
   * Evict lowest mining-score transactions to make room.
   *
   * Uses cluster-based eviction: finds the transaction with the lowest
   * mining score (chunk fee rate) from the worst cluster and removes it.
   * Updates minFeeRate to the rate of the last evicted transaction.
   */
  private evict(): void {
    this.rebuildClusterCache();

    let evictedFeeRate = this.minFeeRate;

    while (this.currentSize > this.maxSize && this.entries.size > 0) {
      // Find the transaction with the lowest mining score
      let worstTxidHex: string | null = null;
      let worstScore = Infinity;

      for (const [txidHex, entry] of this.entries) {
        // Use mining score (chunk fee rate) for eviction
        const score = entry.miningScore;
        if (score < worstScore) {
          worstScore = score;
          worstTxidHex = txidHex;
        }
      }

      if (!worstTxidHex) break;

      const entry = this.entries.get(worstTxidHex)!;
      evictedFeeRate = entry.miningScore;

      // Remove the transaction and all its descendants
      this.removeTransaction(entry.txid, true);

      // Mark cluster cache as dirty since we removed transactions
      this.clusterCacheDirty = true;
      this.rebuildClusterCache();
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
    this.clusters.clear();
    this.clusterCache.clear();
    this.clusterCacheDirty = false;
  }

  /**
   * Check if an outpoint is spent by a mempool transaction.
   */
  isOutpointSpent(txid: Buffer, vout: number): boolean {
    const outpointKey = `${txid.toString("hex")}:${vout}`;
    return this.outpointIndex.has(outpointKey);
  }

  // ============================================================================
  // Cluster Mempool Methods
  // ============================================================================

  /**
   * Get the cluster ID for a transaction.
   */
  getClusterId(txidHex: string): string {
    return this.clusters.find(txidHex);
  }

  /**
   * Get the size of a cluster (number of transactions).
   */
  getClusterSize(txidHex: string): number {
    return this.clusters.getSize(txidHex);
  }

  /**
   * Check if adding a transaction would exceed the cluster size limit.
   * A new transaction may merge multiple clusters together.
   */
  private checkClusterSizeLimit(parentTxids: Set<string>, newTxVsize: number): { valid: boolean; error?: string } {
    // Calculate the resulting cluster size if this tx is added
    // First, find all unique clusters that would be merged
    const clusterRoots = new Set<string>();
    for (const parentTxidHex of parentTxids) {
      if (this.entries.has(parentTxidHex)) {
        clusterRoots.add(this.clusters.find(parentTxidHex));
      }
    }

    // Sum up the sizes of all clusters that would be merged + 1 for the new tx
    let mergedSize = 1;
    for (const root of clusterRoots) {
      mergedSize += this.clusters.getSize(root);
    }

    if (mergedSize > MAX_CLUSTER_SIZE) {
      return {
        valid: false,
        error: `Cluster would exceed maximum size: ${mergedSize} > ${MAX_CLUSTER_SIZE}`,
      };
    }

    return { valid: true };
  }

  /**
   * Add a transaction to the cluster structure.
   * Updates union-find and marks cluster cache as dirty.
   */
  private addToCluster(txidHex: string, parentTxids: Set<string>): void {
    // Create a new singleton cluster for this tx
    this.clusters.makeSet(txidHex);

    // Union with all parent clusters
    for (const parentTxidHex of parentTxids) {
      if (this.entries.has(parentTxidHex)) {
        this.clusters.union(txidHex, parentTxidHex);
      }
    }

    // Mark cache as dirty since cluster structure changed
    this.clusterCacheDirty = true;
  }

  /**
   * Rebuild the cluster cache from scratch.
   * Called lazily when cluster information is needed.
   */
  private rebuildClusterCache(): void {
    if (!this.clusterCacheDirty) return;

    this.clusterCache.clear();

    // Group transactions by cluster ID
    const clusterTxids = new Map<string, Set<string>>();
    for (const txidHex of this.entries.keys()) {
      const clusterId = this.clusters.find(txidHex);
      if (!clusterTxids.has(clusterId)) {
        clusterTxids.set(clusterId, new Set());
      }
      clusterTxids.get(clusterId)!.add(txidHex);
    }

    // Build cluster objects with linearization
    for (const [clusterId, txids] of clusterTxids) {
      const linearization = this.linearizeCluster(txids);

      let totalFee = 0n;
      let totalVsize = 0;
      for (const txidHex of txids) {
        const entry = this.entries.get(txidHex)!;
        totalFee += entry.fee;
        totalVsize += entry.vsize;
      }

      const cluster: Cluster = {
        id: clusterId,
        txids,
        totalFee,
        totalVsize,
        linearization,
      };

      this.clusterCache.set(clusterId, cluster);

      // Update mining scores for all transactions in this cluster
      for (let chunkIdx = 0; chunkIdx < linearization.chunks.length; chunkIdx++) {
        const chunk = linearization.chunks[chunkIdx];
        for (const txidHex of chunk.txids) {
          const entry = this.entries.get(txidHex);
          if (entry) {
            entry.clusterId = clusterId;
            entry.miningScore = chunk.feeRate;
          }
        }
      }
    }

    this.clusterCacheDirty = false;
  }

  /**
   * Linearize a cluster: order transactions by optimal fee-rate chunks.
   *
   * This implements the greedy algorithm from Bitcoin Core's cluster_linearize.h:
   * 1. Start with the linearization in topological order
   * 2. Compute chunks by absorbing higher-feerate transactions into earlier chunks
   *
   * A chunk is a contiguous prefix of the linearization that forms a valid
   * topological ordering. Transactions in the same chunk get the same mining score
   * (the chunk's aggregate fee rate).
   */
  linearizeCluster(txids: Set<string>): Linearization {
    if (txids.size === 0) {
      return { chunks: [], txToChunk: new Map() };
    }

    // Build a topological ordering of the cluster
    const topoOrder = this.topologicalSort(txids);

    // Compute chunks using the greedy algorithm from Bitcoin Core
    // Each tx starts as its own chunk, then absorb higher-feerate chunks
    const chunks: Chunk[] = [];

    for (const txidHex of topoOrder) {
      const entry = this.entries.get(txidHex)!;

      // Create a new chunk for this transaction
      const newChunk: Chunk = {
        txids: new Set([txidHex]),
        totalFee: entry.fee,
        totalVsize: entry.vsize,
        feeRate: entry.feeRate,
      };

      // While the new chunk has a higher feerate than the last chunk, absorb it
      // This implements: while (!ret.empty() && new_chunk.feerate >> ret.back().feerate)
      while (chunks.length > 0 && this.compareFeeRate(newChunk, chunks[chunks.length - 1]) > 0) {
        const lastChunk = chunks.pop()!;
        // Merge lastChunk into newChunk
        for (const txid of lastChunk.txids) {
          newChunk.txids.add(txid);
        }
        newChunk.totalFee += lastChunk.totalFee;
        newChunk.totalVsize += lastChunk.totalVsize;
        newChunk.feeRate = Number(newChunk.totalFee) / newChunk.totalVsize;
      }

      chunks.push(newChunk);
    }

    // Build txToChunk map
    const txToChunk = new Map<string, number>();
    for (let i = 0; i < chunks.length; i++) {
      for (const txidHex of chunks[i].txids) {
        txToChunk.set(txidHex, i);
      }
    }

    return { chunks, txToChunk };
  }

  /**
   * Compare two chunks by fee rate.
   * Returns > 0 if a has higher feerate, < 0 if b has higher, 0 if equal.
   * Uses cross-multiplication to avoid floating point issues.
   */
  private compareFeeRate(a: Chunk, b: Chunk): number {
    // a.feeRate > b.feeRate iff a.fee * b.size > b.fee * a.size
    const lhs = a.totalFee * BigInt(b.totalVsize);
    const rhs = b.totalFee * BigInt(a.totalVsize);
    if (lhs > rhs) return 1;
    if (lhs < rhs) return -1;
    return 0;
  }

  /**
   * Topologically sort a set of transactions (parents before children).
   * Uses Kahn's algorithm.
   */
  private topologicalSort(txids: Set<string>): string[] {
    // Build in-degree counts and adjacency for the subset
    const inDegree = new Map<string, number>();
    const children = new Map<string, Set<string>>();

    for (const txidHex of txids) {
      inDegree.set(txidHex, 0);
      children.set(txidHex, new Set());
    }

    // Count in-degree (number of parents within the cluster)
    for (const txidHex of txids) {
      const entry = this.entries.get(txidHex)!;
      for (const parentTxidHex of entry.dependsOn) {
        if (txids.has(parentTxidHex)) {
          inDegree.set(txidHex, (inDegree.get(txidHex) || 0) + 1);
          children.get(parentTxidHex)!.add(txidHex);
        }
      }
    }

    // Start with nodes that have no in-cluster parents
    // Sort by ancestor count for deterministic ordering
    const queue: string[] = [];
    for (const [txidHex, degree] of inDegree) {
      if (degree === 0) {
        queue.push(txidHex);
      }
    }
    // Sort queue by ancestor count for consistent ordering
    queue.sort((a, b) => {
      const entryA = this.entries.get(a)!;
      const entryB = this.entries.get(b)!;
      return entryA.ancestorCount - entryB.ancestorCount;
    });

    const result: string[] = [];
    while (queue.length > 0) {
      const txidHex = queue.shift()!;
      result.push(txidHex);

      // Decrease in-degree for all children
      for (const childTxidHex of children.get(txidHex)!) {
        const newDegree = inDegree.get(childTxidHex)! - 1;
        inDegree.set(childTxidHex, newDegree);
        if (newDegree === 0) {
          queue.push(childTxidHex);
          // Re-sort to maintain consistent ordering
          queue.sort((a, b) => {
            const entryA = this.entries.get(a)!;
            const entryB = this.entries.get(b)!;
            return entryA.ancestorCount - entryB.ancestorCount;
          });
        }
      }
    }

    return result;
  }

  /**
   * Get the cluster containing a transaction.
   */
  getCluster(txidHex: string): Cluster | null {
    this.rebuildClusterCache();
    const clusterId = this.clusters.find(txidHex);
    return this.clusterCache.get(clusterId) || null;
  }

  /**
   * Get all clusters in the mempool.
   */
  getAllClusters(): Cluster[] {
    this.rebuildClusterCache();
    return Array.from(this.clusterCache.values());
  }

  /**
   * Get the mining score (chunk fee rate) for a transaction.
   * Returns the fee rate of the chunk this transaction belongs to in its cluster's linearization.
   */
  getMiningScore(txidHex: string): number {
    this.rebuildClusterCache();
    const entry = this.entries.get(txidHex);
    if (!entry) return 0;
    return entry.miningScore;
  }

  /**
   * Get transactions sorted by mining score (descending) for block template.
   * This respects chunk boundaries and topological ordering within clusters.
   */
  getTransactionsByMiningScore(): MempoolEntry[] {
    this.rebuildClusterCache();

    // Collect all chunks from all clusters
    const allChunks: { chunk: Chunk; clusterId: string }[] = [];
    for (const cluster of this.clusterCache.values()) {
      for (const chunk of cluster.linearization.chunks) {
        allChunks.push({ chunk, clusterId: cluster.id });
      }
    }

    // Sort chunks by fee rate descending
    allChunks.sort((a, b) => b.chunk.feeRate - a.chunk.feeRate);

    // Flatten into transaction entries, respecting topological order within chunks
    const result: MempoolEntry[] = [];
    for (const { chunk, clusterId } of allChunks) {
      // Get transactions in this chunk in topological order
      const chunkTxids = this.topologicalSort(chunk.txids);
      for (const txidHex of chunkTxids) {
        const entry = this.entries.get(txidHex);
        if (entry) {
          result.push(entry);
        }
      }
    }

    return result;
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

      // Single transaction with ephemeral dust cannot be accepted alone
      // It requires a child in the same package to spend the dust
      if (hasEphemeralDust(tx)) {
        txResults.set(wtxid, {
          txid,
          wtxid,
          accepted: false,
          error: "tx has ephemeral dust but no child spending it",
        });

        return {
          result: PackageValidationResult.PCKG_POLICY,
          message: "ephemeral-dust-no-child",
          txResults,
          replacedTxids,
        };
      }

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

      // Pre-check ephemeral tx: dust outputs require 0-fee
      const ephemeralPreCheck = preCheckEphemeralTx(tx, feeResult.fee!);
      if (!ephemeralPreCheck.valid) {
        txResults.set(wtxid, {
          txid,
          wtxid,
          accepted: false,
          error: ephemeralPreCheck.error,
        });

        return {
          result: PackageValidationResult.PCKG_POLICY,
          message: ephemeralPreCheck.error || "ephemeral-policy-violation",
          txResults,
          replacedTxids,
        };
      }
    }

    // Check ephemeral spends: all dust from parents must be spent by children
    const ephemeralCheck = checkEphemeralSpends(transactions, this.entries);
    if (!ephemeralCheck.valid) {
      // Find the failing transaction
      for (const tx of transactions) {
        const txid = getTxId(tx).toString("hex");
        const wtxid = getWTxId(tx).toString("hex");

        if (this.entries.has(txid)) {
          continue; // Already in mempool, not the issue
        }

        if (wtxid === ephemeralCheck.failedWtxid) {
          txResults.set(wtxid, {
            txid,
            wtxid,
            accepted: false,
            error: ephemeralCheck.error,
          });
        } else {
          txResults.set(wtxid, {
            txid,
            wtxid,
            accepted: false,
            error: "missing-ephemeral-spends",
          });
        }
      }

      return {
        result: PackageValidationResult.PCKG_POLICY,
        message: ephemeralCheck.error || "missing-ephemeral-spends",
        txResults,
        replacedTxids,
      };
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
