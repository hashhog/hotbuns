/**
 * Chain state: current tip, chainwork, block connection/disconnection, reorg handling.
 *
 * Manages the validated chain state, connecting and disconnecting blocks,
 * maintaining UTXO consistency, and handling chain reorganizations.
 */

import type { ChainDB, ChainState, UTXOEntry, BlockIndexRecord } from "../storage/database.js";
import { BlockStatus } from "../storage/database.js";
import type { ConsensusParams } from "../consensus/params.js";
import { getBlockSubsidy } from "../consensus/params.js";
import type { Block, BlockHeader } from "../validation/block.js";
import {
  getBlockHash,
  serializeBlock,
  serializeBlockHeader,
  deserializeBlock,
  getTransactionSigOpCost,
  MAX_BLOCK_SIGOPS_COST,
} from "../validation/block.js";
import type { Transaction, UTXOConfirmation } from "../validation/tx.js";
import {
  getTxId,
  isCoinbase,
  checkSequenceLocks,
  SEQUENCE_LOCKTIME_DISABLE_FLAG,
} from "../validation/tx.js";
import type { HeaderChainEntry } from "../sync/headers.js";
import {
  UTXOManager,
  SpentUTXO,
  serializeUndoData,
  deserializeUndoData,
} from "./utxo.js";
import { ConsensusError, ConsensusErrorCode } from "../validation/errors.js";
import { BufferReader } from "../wire/serialization.js";
import { globalSigCache } from "../validation/sig_cache.js";

/**
 * Result of transaction input validation.
 */
export interface TxInputValidation {
  valid: boolean;
  fee: bigint;
  error?: string;
}

/**
 * Result of checkpoint verification.
 */
export interface CheckpointResult {
  valid: boolean;
  error?: string;
}

/**
 * Result of chain management operations (invalidateblock, reconsiderblock, preciousblock).
 */
export interface ChainManagementResult {
  success: boolean;
  error?: string;
  /** Number of blocks disconnected (invalidateblock) or reconnected (reconsiderblock). */
  blocksAffected?: number;
}

/**
 * Get the highest checkpoint height from consensus params.
 *
 * @param params - Network consensus parameters
 * @returns The highest checkpoint height, or -1 if no checkpoints
 */
export function getLastCheckpointHeight(params: ConsensusParams): number {
  let maxHeight = -1;
  for (const height of params.checkpoints.keys()) {
    if (height > maxHeight) {
      maxHeight = height;
    }
  }
  return maxHeight;
}

/**
 * Verify that a block at a checkpoint height matches the expected hash.
 *
 * @param hash - Block hash to verify
 * @param height - Block height
 * @param params - Network consensus parameters
 * @returns Checkpoint verification result
 */
export function verifyCheckpoint(
  hash: Buffer,
  height: number,
  params: ConsensusParams
): CheckpointResult {
  const checkpoint = params.checkpoints.get(height);

  // If there's no checkpoint at this height, it passes
  if (!checkpoint) {
    return { valid: true };
  }

  // Verify hash matches exactly
  if (hash.equals(checkpoint)) {
    return { valid: true };
  }

  return {
    valid: false,
    error: `Checkpoint mismatch at height ${height}: expected ${checkpoint.toString("hex")}, got ${hash.toString("hex")}`,
  };
}

/**
 * Check if a header would create a fork below the last checkpoint.
 *
 * During IBD, we reject any chain that forks from our chain at or before
 * the last checkpoint. This prevents long-range attacks where an attacker
 * creates an alternative history.
 *
 * @param headerHeight - Height of the header being validated
 * @param headerHash - Hash of the header being validated
 * @param parentHash - Hash of the parent block
 * @param params - Network consensus parameters
 * @param getAncestorHash - Function to get an ancestor hash at a given height
 * @returns CheckpointResult indicating if the header is valid
 */
export function checkForkBelowCheckpoint(
  headerHeight: number,
  headerHash: Buffer,
  parentHash: Buffer,
  params: ConsensusParams,
  getAncestorHash: (height: number) => Buffer | undefined
): CheckpointResult {
  const lastCheckpointHeight = getLastCheckpointHeight(params);

  // No checkpoints = no fork restrictions
  if (lastCheckpointHeight < 0) {
    return { valid: true };
  }

  // If this header is at or above the last checkpoint, we need to verify
  // that our chain ancestry matches all checkpoints
  if (headerHeight > lastCheckpointHeight) {
    // Verify all checkpoints are in our ancestry
    for (const [cpHeight, cpHash] of params.checkpoints) {
      const ancestorHash = getAncestorHash(cpHeight);
      if (ancestorHash && !ancestorHash.equals(cpHash)) {
        return {
          valid: false,
          error: `Fork detected below checkpoint at height ${cpHeight}: expected ${cpHash.toString("hex")}, got ${ancestorHash.toString("hex")}`,
        };
      }
    }
  }

  // If the header is at a checkpoint height, verify it matches
  const checkpointAtHeight = params.checkpoints.get(headerHeight);
  if (checkpointAtHeight && !headerHash.equals(checkpointAtHeight)) {
    return {
      valid: false,
      error: `Block at checkpoint height ${headerHeight} does not match: expected ${checkpointAtHeight.toString("hex")}, got ${headerHash.toString("hex")}`,
    };
  }

  return { valid: true };
}

/**
 * Chain state manager.
 *
 * Responsible for:
 * - Tracking the current best block (tip)
 * - Connecting validated blocks (updating UTXOs, storing block data)
 * - Disconnecting blocks (restoring UTXOs from undo data)
 * - Handling chain reorganizations
 * - Validating transaction inputs against the UTXO set
 */
export class ChainStateManager {
  private db: ChainDB;
  private utxo: UTXOManager;
  private params: ConsensusParams;
  private bestBlock: { hash: Buffer; height: number; chainWork: bigint };
  private notificationEmitter: import("events").EventEmitter | null;
  /** Mempool for conflict removal during invalidation. */
  private mempool: import("../mempool/mempool.js").Mempool | null = null;
  /** Header sync for coordinating header chain state. */
  private headerSync: import("../sync/headers.js").HeaderSync | null = null;
  /** Precious block for tie-breaking. null if no precious block set. */
  private preciousBlockHash: Buffer | null = null;
  /** Sequence ID for precious block tie-breaking. Lower = more precious. */
  private blockSequenceId: number = 0;
  /** Last chain work when preciousblock was set. Used to reset sequence IDs. */
  private lastPreciousChainwork: bigint = 0n;

  constructor(db: ChainDB, params: ConsensusParams, maxCacheBytes?: number) {
    this.db = db;
    this.utxo = new UTXOManager(db, maxCacheBytes);
    this.params = params;
    // Initialize with genesis state - will be overwritten by load()
    this.bestBlock = {
      hash: params.genesisBlockHash,
      height: 0,
      chainWork: 0n,
    };
    this.notificationEmitter = null;
  }

  /**
   * Set the notification event emitter for ZMQ.
   */
  setNotificationEmitter(emitter: import("events").EventEmitter): void {
    this.notificationEmitter = emitter;
  }

  /**
   * Set the mempool for conflict removal during invalidation.
   */
  setMempool(mempool: import("../mempool/mempool.js").Mempool): void {
    this.mempool = mempool;
  }

  /**
   * Set the header sync for coordinating header chain state.
   */
  setHeaderSync(headerSync: import("../sync/headers.js").HeaderSync): void {
    this.headerSync = headerSync;
  }

  /**
   * Get the UTXO manager for direct access if needed.
   */
  getUTXOManager(): UTXOManager {
    return this.utxo;
  }

  /**
   * Connect a validated block: update UTXOs, store block, update chain tip.
   *
   * Flow:
   * 1. For each transaction in the block (in order):
   *    a. For non-coinbase: validate and spend each input. Accumulate spent UTXOs for undo data.
   *    b. For all: add each output as new UTXOs.
   * 2. Verify sigops cost is within limit.
   * 3. Verify total fees + subsidy match coinbase output value.
   * 4. Serialize undo data and store via db.putUndoData().
   * 5. Flush UTXO changes, store block, update chain state.
   */
  async connectBlock(block: Block, height: number): Promise<void> {
    const blockHash = getBlockHash(block.header);

    // Verify checkpoint if this height has one
    const checkpointResult = verifyCheckpoint(blockHash, height, this.params);
    if (!checkpointResult.valid) {
      throw new Error(checkpointResult.error);
    }

    // BIP-30: reject any block that would overwrite an existing unspent output.
    // Two mainnet blocks (h=91842, h=91880) are permanently exempt; they predate
    // BIP-30 and intentionally duplicate earlier coinbase txids.
    // After BIP-34 activation (h≥bip34Height), coinbase-height uniqueness makes
    // duplicates practically impossible, so skip up to h=1,983,702. After that
    // BIP-34 modular arithmetic begins to repeat pre-BIP34 heights, so re-enable.
    // Reference: Bitcoin Core validation.cpp ConnectBlock / IsBIP30Repeat().
    const BIP34_IMPLIES_BIP30_LIMIT = 1_983_702;
    const isExemptHeight = this.params.bip30ExceptionHeights.includes(height);
    const bip34Active = height >= this.params.bip34Height;
    const belowReenableLimit = height < BIP34_IMPLIES_BIP30_LIMIT;
    const enforceBip30 = !isExemptHeight && !(bip34Active && belowReenableLimit);

    if (enforceBip30) {
      for (const tx of block.transactions) {
        const txid = getTxId(tx);
        for (let vout = 0; vout < tx.outputs.length; vout++) {
          const exists = await this.utxo.hasUTXOAsync({ txid, vout });
          if (exists) {
            throw new ConsensusError(
              ConsensusErrorCode.BIP30_DUPLICATE_OUTPUT,
              `bad-txns-BIP30: tried to overwrite transaction ${txid.toString("hex")}:${vout}`
            );
          }
        }
      }
    }

    const spentOutputs: SpentUTXO[] = [];
    let totalInputValue = 0n;
    let totalOutputValue = 0n;

    // Determine which consensus rules are active at this height
    const verifyP2SH = height >= this.params.bip34Height;
    const verifyWitness = height >= this.params.segwitHeight;

    // Track sigops cost and prevOutputs for each transaction
    let totalSigOpsCost = 0;

    // Process transactions in order
    for (let txIndex = 0; txIndex < block.transactions.length; txIndex++) {
      const tx = block.transactions[txIndex];
      const txid = getTxId(tx);
      const txIsCoinbase = isCoinbase(tx);

      // Collect prevOutputs for sigop counting
      const prevOutputs: Buffer[] = [];

      // For non-coinbase transactions, spend inputs
      if (!txIsCoinbase) {
        for (const input of tx.inputs) {
          // Pre-load the UTXO if not in cache
          const loaded = await this.utxo.preloadUTXO(input.prevOut);
          if (!loaded) {
            throw new Error(
              `Missing UTXO: ${input.prevOut.txid.toString("hex")}:${input.prevOut.vout}`
            );
          }

          // Get the UTXO for sigop counting before spending
          const utxoEntry = this.utxo.getUTXO(input.prevOut);
          if (utxoEntry) {
            prevOutputs.push(utxoEntry.scriptPubKey);

            // Check coinbase maturity: coinbase outputs require COINBASE_MATURITY (100) confirmations
            if (utxoEntry.coinbase) {
              const confirmations = height - utxoEntry.height;
              if (confirmations < this.params.coinbaseMaturity) {
                throw new ConsensusError(
                  ConsensusErrorCode.PREMATURE_COINBASE_SPEND,
                  `coinbase at height ${utxoEntry.height} has only ${confirmations} confirmations, need ${this.params.coinbaseMaturity}`
                );
              }
            }
          }

          // Spend the UTXO
          const spentEntry = this.utxo.spendOutput(input.prevOut);
          totalInputValue += spentEntry.amount;

          // Store for undo data
          spentOutputs.push({
            txid: input.prevOut.txid,
            vout: input.prevOut.vout,
            entry: spentEntry,
          });
        }
      }

      // Count sigops for this transaction
      const txSigOpsCost = getTransactionSigOpCost(
        tx,
        prevOutputs,
        verifyP2SH,
        verifyWitness
      );
      totalSigOpsCost += txSigOpsCost;

      // Add outputs as new UTXOs
      this.utxo.addTransaction(txid, tx, height, txIsCoinbase);

      // Sum output values
      for (const output of tx.outputs) {
        totalOutputValue += output.value;
        if (txIsCoinbase) {
          // Track coinbase output separately for fee verification
        }
      }
    }

    // Verify sigops cost is within limit
    if (totalSigOpsCost > MAX_BLOCK_SIGOPS_COST) {
      throw new Error(
        `Block sigops cost ${totalSigOpsCost} exceeds maximum ${MAX_BLOCK_SIGOPS_COST}`
      );
    }

    // Calculate total coinbase output value
    const coinbaseTx = block.transactions[0];
    let coinbaseOutputValue = 0n;
    for (const output of coinbaseTx.outputs) {
      coinbaseOutputValue += output.value;
    }

    // Verify coinbase output <= subsidy + fees
    const subsidy = getBlockSubsidy(height, this.params);
    const fees = totalInputValue - (totalOutputValue - coinbaseOutputValue);
    const maxCoinbaseValue = subsidy + fees;

    if (coinbaseOutputValue > maxCoinbaseValue) {
      throw new Error(
        `Coinbase output (${coinbaseOutputValue}) exceeds subsidy + fees (${maxCoinbaseValue})`
      );
    }

    // Serialize and store undo data
    const undoData = serializeUndoData(spentOutputs);
    await this.db.putUndoData(blockHash, undoData);

    // Flush UTXO changes
    await this.utxo.flush();

    // Store block data
    const rawBlock = serializeBlock(block);
    await this.db.putBlock(blockHash, rawBlock);

    // Store block index record (hash -> metadata) and height -> hash mapping
    const headerBytes = serializeBlockHeader(block.header);
    await this.db.putBlockIndex(blockHash, {
      height,
      header: headerBytes,
      nTx: block.transactions.length,
      status: BlockStatus.HEADER_VALID | BlockStatus.TXS_VALID | BlockStatus.HAVE_DATA | BlockStatus.HAVE_UNDO,
      dataPos: 1, // block data exists
    });

    // Calculate chain work (approximate - should come from header chain)
    // Work = 2^256 / (target + 1), but we use a simplified version here
    const work = this.calculateWork(block.header.bits);
    const chainWork = this.bestBlock.chainWork + work;

    // Persist per-block chain work so getblockheader can return correct chainwork
    await this.db.putChainWork(blockHash, chainWork);

    // Update chain state
    this.bestBlock = {
      hash: blockHash,
      height,
      chainWork,
    };

    await this.db.putChainState({
      bestBlockHash: blockHash,
      bestHeight: height,
      totalWork: chainWork,
    });

    // Emit notification for ZMQ
    if (this.notificationEmitter) {
      this.notificationEmitter.emit("blockConnected", block);
    }
  }

  /**
   * Disconnect the tip block (for reorgs): restore spent UTXOs from undo data.
   *
   * Flow:
   * 1. Read undo data for the block
   * 2. For each transaction in reverse order:
   *    a. Remove outputs (they become unspent again in the previous state)
   *    b. Restore spent inputs from undo data
   * 3. Update chain state to previous block
   */
  async disconnectBlock(block: Block, height: number): Promise<void> {
    const blockHash = getBlockHash(block.header);

    // Verify this is the tip block
    if (!blockHash.equals(this.bestBlock.hash)) {
      throw new Error("Can only disconnect the tip block");
    }

    // Load undo data
    const undoData = await this.db.getUndoData(blockHash);
    if (!undoData) {
      throw new Error(`Missing undo data for block ${blockHash.toString("hex")}`);
    }

    const spentOutputs = deserializeUndoData(undoData);

    // Create a map for quick lookup of spent outputs by outpoint
    const spentByOutpoint = new Map<string, UTXOEntry>();
    for (const spent of spentOutputs) {
      const key = `${spent.txid.toString("hex")}:${spent.vout}`;
      spentByOutpoint.set(key, spent.entry);
    }

    // Process transactions in reverse order
    for (let txIndex = block.transactions.length - 1; txIndex >= 0; txIndex--) {
      const tx = block.transactions[txIndex];
      const txid = getTxId(tx);
      const txIsCoinbase = isCoinbase(tx);

      // Remove outputs (they were created by this block)
      for (let vout = 0; vout < tx.outputs.length; vout++) {
        await this.utxo.removeUTXO(txid, vout);
      }

      // Restore spent inputs (for non-coinbase)
      if (!txIsCoinbase) {
        for (const input of tx.inputs) {
          const key = `${input.prevOut.txid.toString("hex")}:${input.prevOut.vout}`;
          const entry = spentByOutpoint.get(key);
          if (!entry) {
            throw new Error(
              `Missing undo entry for ${input.prevOut.txid.toString("hex")}:${input.prevOut.vout}`
            );
          }
          this.utxo.restoreUTXO(input.prevOut.txid, input.prevOut.vout, entry);
        }
      }
    }

    // Flush UTXO changes
    await this.utxo.flush();

    // Update chain state to previous block
    const prevHeight = height - 1;
    const prevHash = block.header.prevBlock;

    // Calculate previous chain work
    const work = this.calculateWork(block.header.bits);
    const prevChainWork = this.bestBlock.chainWork - work;

    this.bestBlock = {
      hash: prevHash,
      height: prevHeight,
      chainWork: prevChainWork,
    };

    await this.db.putChainState({
      bestBlockHash: prevHash,
      bestHeight: prevHeight,
      totalWork: prevChainWork,
    });

    // Clear signature cache on disconnect (verifications may no longer be valid)
    globalSigCache.clear();

    // Emit notification for ZMQ
    if (this.notificationEmitter) {
      this.notificationEmitter.emit("blockDisconnected", block);
    }
  }

  /**
   * Handle a chain reorganization to a new tip.
   *
   * Flow:
   * 1. Find the fork point by walking both chains back
   * 2. Disconnect blocks from old chain back to fork
   * 3. Connect blocks on new chain from fork to new tip
   */
  async reorganize(
    newTip: HeaderChainEntry,
    getBlock: (hash: Buffer) => Promise<Block | null>
  ): Promise<void> {
    // Find the fork point
    const { oldBlocks, newBlocks } = await this.findForkPoint(newTip, getBlock);

    // Disconnect old blocks (in reverse order, from tip to fork)
    for (const { block, height } of oldBlocks.reverse()) {
      await this.disconnectBlock(block, height);
    }

    // Connect new blocks (in order, from fork to new tip)
    for (const { block, height } of newBlocks) {
      await this.connectBlock(block, height);
    }
  }

  /**
   * Find the fork point between the current chain and a new tip.
   * Returns the blocks to disconnect and connect.
   */
  private async findForkPoint(
    newTip: HeaderChainEntry,
    getBlock: (hash: Buffer) => Promise<Block | null>
  ): Promise<{
    oldBlocks: Array<{ block: Block; height: number }>;
    newBlocks: Array<{ block: Block; height: number }>;
  }> {
    const oldBlocks: Array<{ block: Block; height: number }> = [];
    const newBlocks: Array<{ block: Block; height: number }> = [];

    // Walk back from new tip to find blocks that aren't on our current chain
    let newHeight = newTip.height;
    let newHash = newTip.hash;
    const newBlockHashes: Buffer[] = [];

    while (newHeight > this.bestBlock.height) {
      newBlockHashes.unshift(Buffer.from(newHash));
      const block = await getBlock(newHash);
      if (!block) {
        throw new Error(`Missing block ${newHash.toString("hex")}`);
      }
      newHash = block.header.prevBlock;
      newHeight--;
    }

    // Now walk back both chains until they meet
    let oldHeight = this.bestBlock.height;
    let oldHash = this.bestBlock.hash;

    while (!oldHash.equals(newHash)) {
      // Add old block to disconnect list
      const oldBlock = await getBlock(oldHash);
      if (!oldBlock) {
        throw new Error(`Missing block ${oldHash.toString("hex")}`);
      }
      oldBlocks.push({ block: oldBlock, height: oldHeight });
      oldHash = oldBlock.header.prevBlock;
      oldHeight--;

      // Add new block to connect list
      newBlockHashes.unshift(Buffer.from(newHash));
      const newBlock = await getBlock(newHash);
      if (!newBlock) {
        throw new Error(`Missing block ${newHash.toString("hex")}`);
      }
      newHash = newBlock.header.prevBlock;
      newHeight--;
    }

    // Now build the new blocks list with actual Block objects
    let connectHeight = newHeight + 1;
    for (const hash of newBlockHashes) {
      const block = await getBlock(hash);
      if (!block) {
        throw new Error(`Missing block ${hash.toString("hex")}`);
      }
      newBlocks.push({ block, height: connectHeight });
      connectHeight++;
    }

    return { oldBlocks, newBlocks };
  }

  /**
   * Get the current best block.
   */
  getBestBlock(): { hash: Buffer; height: number; chainWork: bigint } {
    return { ...this.bestBlock };
  }

  /**
   * Update the in-memory chain tip without going through full connectBlock.
   * Used by BlockSync to keep RPC state in sync during IBD.
   */
  updateTip(hash: Buffer, height: number, chainWork: bigint): void {
    this.bestBlock = { hash, height, chainWork };
  }

  /**
   * Validate transaction inputs against the UTXO set (contextual validation).
   *
   * Checks:
   * - Each input references a valid, unspent output
   * - Coinbase maturity (100 confirmations before spending)
   * - Total input value >= total output value
   * - Returns the transaction fee
   */
  validateTxInputs(tx: Transaction, height: number): TxInputValidation {
    // Coinbase transactions have no inputs to validate
    if (isCoinbase(tx)) {
      return { valid: true, fee: 0n };
    }

    let totalInputValue = 0n;
    let totalOutputValue = 0n;

    // Validate each input
    for (const input of tx.inputs) {
      const utxo = this.utxo.getUTXO(input.prevOut);
      if (!utxo) {
        return {
          valid: false,
          fee: 0n,
          error: `Missing UTXO: ${input.prevOut.txid.toString("hex")}:${input.prevOut.vout}`,
        };
      }

      // Check coinbase maturity
      if (utxo.coinbase) {
        const confirmations = height - utxo.height;
        if (confirmations < this.params.coinbaseMaturity) {
          return {
            valid: false,
            fee: 0n,
            error: ConsensusErrorCode.PREMATURE_COINBASE_SPEND,
          };
        }
      }

      totalInputValue += utxo.amount;
    }

    // Sum output values
    for (const output of tx.outputs) {
      totalOutputValue += output.value;
    }

    // Check that inputs cover outputs
    if (totalInputValue < totalOutputValue) {
      return {
        valid: false,
        fee: 0n,
        error: ConsensusErrorCode.INPUTS_NOT_EQUAL_OUTPUTS,
      };
    }

    const fee = totalInputValue - totalOutputValue;
    return { valid: true, fee };
  }

  /**
   * Validate transaction inputs asynchronously (checks database).
   */
  async validateTxInputsAsync(
    tx: Transaction,
    height: number
  ): Promise<TxInputValidation> {
    // Coinbase transactions have no inputs to validate
    if (isCoinbase(tx)) {
      return { valid: true, fee: 0n };
    }

    let totalInputValue = 0n;
    let totalOutputValue = 0n;

    // Validate each input
    for (const input of tx.inputs) {
      const utxo = await this.utxo.getUTXOAsync(input.prevOut);
      if (!utxo) {
        return {
          valid: false,
          fee: 0n,
          error: ConsensusErrorCode.MISSING_INPUTS,
        };
      }

      // Check coinbase maturity
      if (utxo.coinbase) {
        const confirmations = height - utxo.height;
        if (confirmations < this.params.coinbaseMaturity) {
          return {
            valid: false,
            fee: 0n,
            error: ConsensusErrorCode.PREMATURE_COINBASE_SPEND,
          };
        }
      }

      totalInputValue += utxo.amount;
    }

    // Sum output values
    for (const output of tx.outputs) {
      totalOutputValue += output.value;
    }

    // Check that inputs cover outputs
    if (totalInputValue < totalOutputValue) {
      return {
        valid: false,
        fee: 0n,
        error: ConsensusErrorCode.INPUTS_NOT_EQUAL_OUTPUTS,
      };
    }

    const fee = totalInputValue - totalOutputValue;
    return { valid: true, fee };
  }

  /**
   * Load chain state from database.
   */
  async load(): Promise<void> {
    const state = await this.db.getChainState();

    if (state) {
      this.bestBlock = {
        hash: state.bestBlockHash,
        height: state.bestHeight,
        chainWork: state.totalWork,
      };
    } else {
      // Initialize with genesis block
      const genesisWork = this.calculateWork(this.params.powLimitBits);
      this.bestBlock = {
        hash: this.params.genesisBlockHash,
        height: 0,
        chainWork: genesisWork,
      };

      // Store initial state
      await this.db.putChainState({
        bestBlockHash: this.bestBlock.hash,
        bestHeight: this.bestBlock.height,
        totalWork: this.bestBlock.chainWork,
      });

      // Store genesis block data and index so getblock/getblockheader work at height 0
      const genesisRaw = this.params.genesisBlock;
      await this.db.putBlock(this.params.genesisBlockHash, genesisRaw);
      const genesisBlockParsed = deserializeBlock(new BufferReader(genesisRaw));
      await this.db.putBlockIndex(this.params.genesisBlockHash, {
        height: 0,
        header: serializeBlockHeader(genesisBlockParsed.header),
        nTx: genesisBlockParsed.transactions.length,
        status: BlockStatus.HEADER_VALID | BlockStatus.TXS_VALID | BlockStatus.HAVE_DATA,
        dataPos: 1,
      });
      // Store genesis chain work
      await this.db.putChainWork(this.params.genesisBlockHash, genesisWork);
    }
  }

  /**
   * Calculate the proof-of-work contribution for a block.
   * Work = 2^256 / (target + 1)
   */
  private calculateWork(bits: number): bigint {
    const target = this.compactToBigInt(bits);
    if (target <= 0n) {
      return 0n;
    }
    const TWO_256 = 2n ** 256n;
    return TWO_256 / (target + 1n);
  }

  /**
   * Convert compact difficulty format (nBits) to target value.
   */
  private compactToBigInt(bits: number): bigint {
    const exponent = bits >>> 24;
    const mantissa = bits & 0x7fffff;

    // Handle negative flag (bit 23)
    const isNegative = (bits & 0x800000) !== 0;

    let target: bigint;

    if (exponent <= 3) {
      target = BigInt(mantissa) >> BigInt(8 * (3 - exponent));
    } else {
      target = BigInt(mantissa) << BigInt(8 * (exponent - 3));
    }

    // Return 0 for negative targets (invalid in Bitcoin)
    if (isNegative && target !== 0n) {
      return 0n;
    }

    return target;
  }

  /**
   * Check if a block's prevBlock matches our current tip.
   * Used to detect when a reorganization is needed.
   */
  isNextBlock(header: BlockHeader): boolean {
    return header.prevBlock.equals(this.bestBlock.hash);
  }

  /**
   * Check if we need to reorganize to reach a given block.
   */
  needsReorg(header: BlockHeader): boolean {
    return (
      !header.prevBlock.equals(this.bestBlock.hash) &&
      !getBlockHash(header).equals(this.bestBlock.hash)
    );
  }

  /**
   * Clear the UTXO cache after a batch of operations.
   */
  clearCache(): void {
    this.utxo.clearCache();
  }

  /**
   * Get statistics about the current state.
   */
  getStats(): {
    height: number;
    hash: string;
    chainWork: bigint;
    utxoCacheSize: number;
    pendingOps: number;
    sigCacheSize: number;
  } {
    return {
      height: this.bestBlock.height,
      hash: this.bestBlock.hash.toString("hex"),
      chainWork: this.bestBlock.chainWork,
      utxoCacheSize: this.utxo.getCacheSize(),
      pendingOps: this.utxo.getPendingCount(),
      sigCacheSize: globalSigCache.size,
    };
  }

  /**
   * Get the last (highest) checkpoint height for this network.
   */
  getLastCheckpointHeight(): number {
    return getLastCheckpointHeight(this.params);
  }

  /**
   * Check if we are past all checkpoints.
   * When true, we have validated all checkpoint blocks.
   */
  isPastLastCheckpoint(): boolean {
    const lastCp = this.getLastCheckpointHeight();
    return lastCp < 0 || this.bestBlock.height >= lastCp;
  }

  /**
   * Check if a given height is at or below the last checkpoint.
   * Used to reject forks that attempt to rewrite protected history.
   */
  isProtectedByCheckpoint(height: number): boolean {
    const lastCp = this.getLastCheckpointHeight();
    return lastCp >= 0 && height <= lastCp;
  }

  /**
   * Verify checkpoint for a block at a given height.
   */
  verifyBlockCheckpoint(hash: Buffer, height: number): CheckpointResult {
    return verifyCheckpoint(hash, height, this.params);
  }

  /**
   * Get the consensus parameters.
   */
  getParams(): ConsensusParams {
    return this.params;
  }

  /**
   * Get the database for direct access.
   */
  getDB(): ChainDB {
    return this.db;
  }

  // ========== Chain Management RPCs ==========

  /**
   * Mark a block and all its descendants as invalid.
   *
   * If the block is on the active chain, disconnects blocks back to the fork point.
   * Removes conflicting transactions from the mempool.
   *
   * Reference: Bitcoin Core's Chainstate::InvalidateBlock (validation.cpp)
   *
   * @param blockHash - Hash of the block to invalidate
   * @returns Result indicating success and number of blocks affected
   */
  async invalidateBlock(blockHash: Buffer): Promise<ChainManagementResult> {
    // Check if block exists
    const blockIndex = await this.db.getBlockIndex(blockHash);
    if (!blockIndex) {
      return { success: false, error: "Block not found" };
    }

    // Genesis block cannot be invalidated
    if (blockIndex.height === 0) {
      return { success: false, error: "Cannot invalidate genesis block" };
    }

    // Check if block is protected by checkpoint
    if (this.isProtectedByCheckpoint(blockIndex.height)) {
      return {
        success: false,
        error: `Block at height ${blockIndex.height} is protected by checkpoint`,
      };
    }

    // Check if already marked invalid
    if (blockIndex.status & BlockStatus.FAILED_VALID) {
      return { success: true, blocksAffected: 0 };
    }

    let blocksDisconnected = 0;

    // If this block is on the active chain, disconnect blocks back to it
    const hashHex = blockHash.toString("hex");
    let currentHash = this.bestBlock.hash;
    const blocksToDisconnect: Buffer[] = [];

    // Walk back from tip to find if blockHash is an ancestor
    while (!currentHash.equals(blockHash)) {
      const currentIndex = await this.db.getBlockIndex(currentHash);
      if (!currentIndex || currentIndex.height <= blockIndex.height) {
        // Block is not on our active chain
        break;
      }

      blocksToDisconnect.push(currentHash);

      // Get parent hash from header
      const parentHash = currentIndex.header.subarray(4, 36);
      currentHash = parentHash;
    }

    // If we found it on our chain, disconnect blocks
    if (currentHash.equals(blockHash)) {
      // Also disconnect the invalidated block itself
      blocksToDisconnect.push(blockHash);

      // Disconnect in reverse order (from tip to target)
      for (const hash of blocksToDisconnect) {
        const rawBlock = await this.db.getBlock(hash);
        if (!rawBlock) {
          return {
            success: false,
            error: `Missing block data for ${hash.toString("hex")}`,
          };
        }

        const block = deserializeBlock(new BufferReader(rawBlock));
        const idx = await this.db.getBlockIndex(hash);
        if (!idx) continue;

        await this.disconnectBlock(block, idx.height);
        blocksDisconnected++;

        // Mark the disconnected block as invalid
        await this.db.updateBlockStatus(
          hash,
          idx.status | BlockStatus.FAILED_VALID
        );
      }
    } else {
      // Block is not on our chain, just mark it invalid
      await this.db.updateBlockStatus(
        blockHash,
        blockIndex.status | BlockStatus.FAILED_VALID
      );
    }

    // Mark all descendants as FAILED_CHILD
    await this.markDescendantsInvalid(blockHash, blockIndex.height);

    // Remove conflicting transactions from mempool
    if (this.mempool) {
      // Get all txids in the invalidated block and its descendants
      // This is a simplified version - full implementation would track all descendants
      const rawBlock = await this.db.getBlock(blockHash);
      if (rawBlock) {
        const block = deserializeBlock(new BufferReader(rawBlock));
        for (const tx of block.transactions) {
          const txid = getTxId(tx);
          this.mempool.removeTransaction(txid, true);
        }
      }
    }

    return { success: true, blocksAffected: blocksDisconnected };
  }

  /**
   * Mark descendants of an invalid block as FAILED_CHILD.
   */
  private async markDescendantsInvalid(
    parentHash: Buffer,
    parentHeight: number
  ): Promise<void> {
    // This is a simplified implementation
    // A full implementation would iterate through all block index entries
    // and check ancestry. For now, we rely on the header chain to track
    // which blocks descend from the invalid block.

    // Walk through heights above parent looking for descendants
    let height = parentHeight + 1;
    while (height <= this.bestBlock.height + 1000) {
      // Look up to 1000 blocks ahead
      const hashAtHeight = await this.db.getBlockHashByHeight(height);
      if (!hashAtHeight) break;

      const idx = await this.db.getBlockIndex(hashAtHeight);
      if (!idx) {
        height++;
        continue;
      }

      // Check if this block's parent chain contains the invalid block
      // by comparing prevBlock
      const prevBlockHash = idx.header.subarray(4, 36);
      const prevIdx = await this.db.getBlockIndex(prevBlockHash);

      if (prevIdx && prevIdx.status & (BlockStatus.FAILED_VALID | BlockStatus.FAILED_CHILD)) {
        // Parent is invalid, mark this as FAILED_CHILD
        await this.db.updateBlockStatus(
          hashAtHeight,
          idx.status | BlockStatus.FAILED_CHILD
        );
      }

      height++;
    }
  }

  /**
   * Remove the invalid flag from a block and its ancestors.
   *
   * If the reconsidered chain has more work than the current tip,
   * triggers a reorganization.
   *
   * Reference: Bitcoin Core's Chainstate::ResetBlockFailureFlags (validation.cpp)
   *
   * @param blockHash - Hash of the block to reconsider
   * @returns Result indicating success and number of blocks affected
   */
  async reconsiderBlock(blockHash: Buffer): Promise<ChainManagementResult> {
    // Check if block exists
    const blockIndex = await this.db.getBlockIndex(blockHash);
    if (!blockIndex) {
      return { success: false, error: "Block not found" };
    }

    // Check if actually invalid
    const isInvalid = blockIndex.status & (BlockStatus.FAILED_VALID | BlockStatus.FAILED_CHILD);
    if (!isInvalid) {
      return { success: true, blocksAffected: 0 };
    }

    // Clear invalid flags from this block and all ancestors
    let blocksCleared = 0;
    let currentHash = blockHash;

    while (true) {
      const idx = await this.db.getBlockIndex(currentHash);
      if (!idx) break;

      const wasInvalid = idx.status & (BlockStatus.FAILED_VALID | BlockStatus.FAILED_CHILD);
      if (!wasInvalid) break;

      // Clear both flags
      const newStatus =
        idx.status & ~(BlockStatus.FAILED_VALID | BlockStatus.FAILED_CHILD);
      await this.db.updateBlockStatus(currentHash, newStatus);
      blocksCleared++;

      // Move to parent
      const parentHash = idx.header.subarray(4, 36);
      if (idx.height === 0) break;
      currentHash = parentHash;
    }

    // Also clear flags from descendants of the reconsidered block
    await this.clearDescendantInvalidFlags(blockHash, blockIndex.height);

    // Check if we need to reorganize
    // The reconsidered chain might now have more work than our current tip
    // A full implementation would recalculate chainwork and potentially reorg.
    // For now, return success and let the header sync handle reorg if needed.

    return { success: true, blocksAffected: blocksCleared };
  }

  /**
   * Clear FAILED_CHILD flags from descendants of a reconsidered block.
   */
  private async clearDescendantInvalidFlags(
    parentHash: Buffer,
    parentHeight: number
  ): Promise<void> {
    // Similar to markDescendantsInvalid, but clears flags instead
    let height = parentHeight + 1;
    while (height <= this.bestBlock.height + 1000) {
      const hashAtHeight = await this.db.getBlockHashByHeight(height);
      if (!hashAtHeight) break;

      const idx = await this.db.getBlockIndex(hashAtHeight);
      if (!idx) {
        height++;
        continue;
      }

      // Check if this block has FAILED_CHILD set
      if (idx.status & BlockStatus.FAILED_CHILD) {
        // Check if its parent is now valid
        const prevBlockHash = idx.header.subarray(4, 36);
        const prevIdx = await this.db.getBlockIndex(prevBlockHash);

        const parentStillInvalid =
          prevIdx &&
          prevIdx.status & (BlockStatus.FAILED_VALID | BlockStatus.FAILED_CHILD);

        if (!parentStillInvalid) {
          // Clear FAILED_CHILD flag
          const newStatus = idx.status & ~BlockStatus.FAILED_CHILD;
          await this.db.updateBlockStatus(hashAtHeight, newStatus);
        }
      }

      height++;
    }
  }

  /**
   * Mark a block as "precious" for tie-breaking in chain selection.
   *
   * When multiple chains have equal work, the precious block's chain
   * is preferred. This is a tie-breaker, not a fork override.
   *
   * Reference: Bitcoin Core's Chainstate::PreciousBlock (validation.cpp)
   *
   * @param blockHash - Hash of the block to mark as precious
   * @returns Result indicating success
   */
  async preciousBlock(blockHash: Buffer): Promise<ChainManagementResult> {
    // Check if block exists
    const blockIndex = await this.db.getBlockIndex(blockHash);
    if (!blockIndex) {
      return { success: false, error: "Block not found" };
    }

    // Cannot make an invalid block precious
    if (blockIndex.status & (BlockStatus.FAILED_VALID | BlockStatus.FAILED_CHILD)) {
      return { success: false, error: "Cannot mark invalid block as precious" };
    }

    // Calculate chain work for this block
    // Note: Full implementation would need to track chainwork per block
    const headerWork = this.calculateWork(
      blockIndex.header.readUInt32LE(72) // bits field offset in header
    );

    // If the chain has been extended since last precious call, reset
    if (this.bestBlock.chainWork > this.lastPreciousChainwork) {
      this.blockSequenceId = -1;
    }
    this.lastPreciousChainwork = this.bestBlock.chainWork;

    // Set this block as precious with negative sequence ID
    // Lower sequence ID = higher priority in tie-breaking
    this.preciousBlockHash = blockHash;
    this.blockSequenceId--;

    // If this block has equal or more work than our tip, we might want to switch
    // For simplicity, we don't force a reorg here - that would require
    // full chainwork calculation. Return success and let normal chain
    // selection pick up the preference.

    return { success: true, blocksAffected: 0 };
  }

  /**
   * Check if a block is marked as invalid.
   */
  async isBlockInvalid(blockHash: Buffer): Promise<boolean> {
    const idx = await this.db.getBlockIndex(blockHash);
    if (!idx) return false;
    return !!(idx.status & (BlockStatus.FAILED_VALID | BlockStatus.FAILED_CHILD));
  }

  /**
   * Check if a block is marked as precious.
   */
  isPreciousBlock(blockHash: Buffer): boolean {
    return this.preciousBlockHash !== null && this.preciousBlockHash.equals(blockHash);
  }

  /**
   * Get the precious block hash, if any.
   */
  getPreciousBlock(): Buffer | null {
    return this.preciousBlockHash;
  }
}
