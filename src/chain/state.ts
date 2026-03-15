/**
 * Chain state: current tip, chainwork, block connection/disconnection, reorg handling.
 *
 * Manages the validated chain state, connecting and disconnecting blocks,
 * maintaining UTXO consistency, and handling chain reorganizations.
 */

import type { ChainDB, ChainState, UTXOEntry } from "../storage/database.js";
import type { ConsensusParams } from "../consensus/params.js";
import { getBlockSubsidy } from "../consensus/params.js";
import type { Block, BlockHeader } from "../validation/block.js";
import {
  getBlockHash,
  serializeBlock,
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

  constructor(db: ChainDB, params: ConsensusParams) {
    this.db = db;
    this.utxo = new UTXOManager(db);
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

    // Calculate chain work (approximate - should come from header chain)
    // Work = 2^256 / (target + 1), but we use a simplified version here
    const work = this.calculateWork(block.header.bits);
    const chainWork = this.bestBlock.chainWork + work;

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
        this.utxo.removeUTXO(txid, vout);
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
      this.bestBlock = {
        hash: this.params.genesisBlockHash,
        height: 0,
        chainWork: this.calculateWork(this.params.powLimitBits),
      };

      // Store initial state
      await this.db.putChainState({
        bestBlockHash: this.bestBlock.hash,
        bestHeight: this.bestBlock.height,
        totalWork: this.bestBlock.chainWork,
      });
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
  } {
    return {
      height: this.bestBlock.height,
      hash: this.bestBlock.hash.toString("hex"),
      chainWork: this.bestBlock.chainWork,
      utxoCacheSize: this.utxo.getCacheSize(),
      pendingOps: this.utxo.getPendingCount(),
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
}
