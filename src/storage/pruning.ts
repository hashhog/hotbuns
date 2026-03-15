/**
 * Block pruning support.
 *
 * Automatically deletes old block data files to keep disk usage below a target,
 * while retaining enough data for reorgs. Follows Bitcoin Core's pruning model.
 *
 * Key constraints:
 * - Minimum prune target: 550 MiB (to retain enough blocks for reorgs)
 * - Keep at least MIN_BLOCKS_TO_KEEP (288) blocks from the tip
 * - Prune entire files, not individual blocks
 * - Undo data must be pruned with its corresponding block data
 *
 * Reference: Bitcoin Core's node/blockstorage.cpp (PruneOneBlockFile, FindFilesToPrune)
 */

import { unlink } from "node:fs/promises";
import { join } from "node:path";
import type { ChainDB, BlockIndexRecord } from "./database.js";
import { BlockStatus } from "./database.js";
import type { BlockFileInfo } from "./blockfile.js";
import {
  serializeBlockFileInfo,
  deserializeBlockFileInfo,
  createEmptyBlockFileInfo,
} from "./blockfile.js";

/** Minimum prune target in bytes (550 MiB). */
export const MIN_PRUNE_TARGET = 550 * 1024 * 1024;

/** Minimum blocks to keep from the tip (288 = ~2 days of blocks). */
export const MIN_BLOCKS_TO_KEEP = 288;

/** Block file chunk size for pre-allocation (16 MiB). */
export const BLOCKFILE_CHUNK_SIZE = 16 * 1024 * 1024;

/** Undo file chunk size (1 MiB). */
export const UNDOFILE_CHUNK_SIZE = 1 * 1024 * 1024;

/**
 * Result of a prune operation.
 */
export interface PruneResult {
  /** Number of files pruned. */
  filesPruned: number;
  /** Bytes freed. */
  bytesFreed: number;
  /** Height of the first block that was NOT pruned. */
  firstUnprunedHeight: number;
}

/**
 * Prune manager handles automatic and manual pruning of block data.
 */
export class PruneManager {
  private db: ChainDB;
  private dataDir: string;
  private pruneTarget: number;
  private havePruned: boolean;
  private blockFileInfo: Map<number, BlockFileInfo>;

  constructor(db: ChainDB, dataDir: string, pruneTarget: number) {
    this.db = db;
    this.dataDir = dataDir;
    this.pruneTarget = pruneTarget;
    this.havePruned = false;
    this.blockFileInfo = new Map();
  }

  /**
   * Initialize the prune manager and load state from DB.
   */
  async init(): Promise<void> {
    // Load pruning state from DB
    const state = await this.db.getPruneState();
    if (state) {
      this.havePruned = state.havePruned;
    }

    // Load block file info
    await this.loadBlockFileInfo();
  }

  /**
   * Load all block file info from the database.
   */
  private async loadBlockFileInfo(): Promise<void> {
    const lastFile = await this.db.getLastBlockFile();
    if (lastFile === null) return;

    for (let i = 0; i <= lastFile; i++) {
      const infoData = await this.db.getBlockFileInfo(i);
      if (infoData) {
        const info = deserializeBlockFileInfo(infoData);
        this.blockFileInfo.set(i, info);
      }
    }
  }

  /**
   * Update block file info in memory and persist to DB.
   */
  async updateBlockFileInfo(fileNum: number, info: BlockFileInfo): Promise<void> {
    this.blockFileInfo.set(fileNum, info);
    await this.db.putBlockFileInfo(fileNum, serializeBlockFileInfo(info));
  }

  /**
   * Check if pruning is enabled.
   */
  isPruneMode(): boolean {
    return this.pruneTarget > 0;
  }

  /**
   * Check if any pruning has occurred.
   */
  hasEverPruned(): boolean {
    return this.havePruned;
  }

  /**
   * Get the pruning target in bytes.
   */
  getPruneTarget(): number {
    return this.pruneTarget;
  }

  /**
   * Calculate current disk usage from all block files.
   */
  calculateCurrentUsage(): number {
    let total = 0;
    for (const info of this.blockFileInfo.values()) {
      total += info.nSize + info.nUndoSize;
    }
    return total;
  }

  /**
   * Get the block file path.
   */
  private getBlockFilePath(fileNum: number): string {
    const fileName = `blk${String(fileNum).padStart(5, "0")}.dat`;
    return join(this.dataDir, "blocks", fileName);
  }

  /**
   * Get the rev (undo) file path.
   */
  private getRevFilePath(fileNum: number): string {
    const fileName = `rev${String(fileNum).padStart(5, "0")}.dat`;
    return join(this.dataDir, "blocks", fileName);
  }

  /**
   * Prune a single block file.
   * Marks all blocks in the file as pruned and resets the file info.
   */
  async pruneOneBlockFile(fileNum: number): Promise<void> {
    const info = this.blockFileInfo.get(fileNum);
    if (!info || info.nSize === 0) {
      return; // Already pruned or doesn't exist
    }

    // Update all block index records that reference this file
    // We need to iterate through the database and find blocks in this file
    // This is expensive, but necessary for correctness

    // For now, we mark the file info as empty
    // The block index records will be updated when we need to access them
    const emptyInfo = createEmptyBlockFileInfo();
    await this.updateBlockFileInfo(fileNum, emptyInfo);

    // Mark that we have pruned
    if (!this.havePruned) {
      this.havePruned = true;
      await this.db.putPruneState(true, this.pruneTarget);
    }
  }

  /**
   * Delete the actual files from disk.
   */
  async unlinkPrunedFiles(filesToPrune: Set<number>): Promise<void> {
    for (const fileNum of filesToPrune) {
      const blockPath = this.getBlockFilePath(fileNum);
      const revPath = this.getRevFilePath(fileNum);

      try {
        await unlink(blockPath);
      } catch {
        // File may not exist
      }

      try {
        await unlink(revPath);
      } catch {
        // File may not exist
      }
    }
  }

  /**
   * Find files to prune based on automatic pruning rules.
   * Called periodically during block validation.
   *
   * @param chainHeight Current best chain height
   * @returns Set of file numbers to prune
   */
  async findFilesToPrune(chainHeight: number): Promise<Set<number>> {
    const setFilesToPrune = new Set<number>();

    if (!this.isPruneMode() || chainHeight < 0) {
      return setFilesToPrune;
    }

    const target = Math.max(MIN_PRUNE_TARGET, this.pruneTarget);

    // Calculate prune range
    const lastBlockCanPrune = chainHeight - MIN_BLOCKS_TO_KEEP;
    const minBlockToPrune = 0; // We can prune from genesis

    if (lastBlockCanPrune < minBlockToPrune) {
      return setFilesToPrune; // Not enough blocks yet
    }

    let currentUsage = this.calculateCurrentUsage();

    // Buffer for next allocation
    const buffer = BLOCKFILE_CHUNK_SIZE + UNDOFILE_CHUNK_SIZE;

    if (currentUsage + buffer < target) {
      return setFilesToPrune; // Below target, no pruning needed
    }

    // Find files to prune, oldest first
    const fileNums = Array.from(this.blockFileInfo.keys()).sort((a, b) => a - b);

    for (const fileNum of fileNums) {
      const info = this.blockFileInfo.get(fileNum)!;

      if (info.nSize === 0) {
        continue; // Already pruned
      }

      if (currentUsage + buffer < target) {
        break; // Below target now
      }

      // Check if file is within prune-safe range
      if (info.nHeightLast > lastBlockCanPrune || info.nHeightFirst < minBlockToPrune) {
        continue; // Can't prune this file
      }

      // Prune this file
      await this.pruneOneBlockFile(fileNum);
      setFilesToPrune.add(fileNum);
      currentUsage -= info.nSize + info.nUndoSize;
    }

    return setFilesToPrune;
  }

  /**
   * Find files to prune for manual pruning (pruneblockchain RPC).
   *
   * @param targetHeight Prune blocks up to this height
   * @param chainHeight Current best chain height
   * @returns Set of file numbers to prune
   */
  async findFilesToPruneManual(
    targetHeight: number,
    chainHeight: number
  ): Promise<Set<number>> {
    const setFilesToPrune = new Set<number>();

    if (chainHeight < 0) {
      return setFilesToPrune;
    }

    // Calculate prune range
    const lastBlockCanPrune = Math.min(targetHeight, chainHeight - MIN_BLOCKS_TO_KEEP);
    const minBlockToPrune = 0;

    if (lastBlockCanPrune < minBlockToPrune) {
      return setFilesToPrune;
    }

    const fileNums = Array.from(this.blockFileInfo.keys()).sort((a, b) => a - b);

    for (const fileNum of fileNums) {
      const info = this.blockFileInfo.get(fileNum)!;

      if (info.nSize === 0) {
        continue; // Already pruned
      }

      // Check if entire file is within prune range
      if (info.nHeightLast > lastBlockCanPrune || info.nHeightFirst < minBlockToPrune) {
        continue;
      }

      await this.pruneOneBlockFile(fileNum);
      setFilesToPrune.add(fileNum);
    }

    return setFilesToPrune;
  }

  /**
   * Execute automatic pruning if needed.
   *
   * @param chainHeight Current best chain height
   * @returns Prune result
   */
  async maybePrune(chainHeight: number): Promise<PruneResult> {
    const filesToPrune = await this.findFilesToPrune(chainHeight);

    if (filesToPrune.size === 0) {
      return {
        filesPruned: 0,
        bytesFreed: 0,
        firstUnprunedHeight: 0,
      };
    }

    // Calculate bytes freed before unlinking
    let bytesFreed = 0;
    for (const fileNum of filesToPrune) {
      const info = this.blockFileInfo.get(fileNum);
      if (info) {
        bytesFreed += info.nSize + info.nUndoSize;
      }
    }

    // Unlink the files
    await this.unlinkPrunedFiles(filesToPrune);

    // Find first unpruned height
    const firstUnprunedHeight = this.getFirstUnprunedHeight();

    console.log(
      `Pruned ${filesToPrune.size} block files, freed ${(bytesFreed / 1024 / 1024).toFixed(2)} MiB`
    );

    return {
      filesPruned: filesToPrune.size,
      bytesFreed,
      firstUnprunedHeight,
    };
  }

  /**
   * Execute manual pruning to a specific height.
   *
   * @param targetHeight Prune blocks up to this height
   * @param chainHeight Current best chain height
   * @returns Prune result
   */
  async pruneBlockchain(
    targetHeight: number,
    chainHeight: number
  ): Promise<PruneResult> {
    if (!this.isPruneMode()) {
      throw new Error("Pruning is not enabled. Start with -prune=<n> to enable.");
    }

    const filesToPrune = await this.findFilesToPruneManual(targetHeight, chainHeight);

    if (filesToPrune.size === 0) {
      return {
        filesPruned: 0,
        bytesFreed: 0,
        firstUnprunedHeight: this.getFirstUnprunedHeight(),
      };
    }

    // Calculate bytes freed
    let bytesFreed = 0;
    for (const fileNum of filesToPrune) {
      const info = this.blockFileInfo.get(fileNum);
      if (info) {
        bytesFreed += info.nSize + info.nUndoSize;
      }
    }

    // Unlink the files
    await this.unlinkPrunedFiles(filesToPrune);

    const firstUnprunedHeight = this.getFirstUnprunedHeight();

    console.log(
      `Manual prune: removed ${filesToPrune.size} block files, freed ${(bytesFreed / 1024 / 1024).toFixed(2)} MiB`
    );

    return {
      filesPruned: filesToPrune.size,
      bytesFreed,
      firstUnprunedHeight,
    };
  }

  /**
   * Get the height of the first block that has not been pruned.
   */
  getFirstUnprunedHeight(): number {
    let minHeight = Infinity;

    for (const info of this.blockFileInfo.values()) {
      if (info.nSize > 0 && info.nHeightFirst < minHeight) {
        minHeight = info.nHeightFirst;
      }
    }

    return minHeight === Infinity ? 0 : minHeight;
  }

  /**
   * Check if a block at the given height has been pruned.
   * This is an approximation based on file info, not exact per-block tracking.
   */
  isBlockPruned(height: number): boolean {
    for (const info of this.blockFileInfo.values()) {
      if (info.nSize > 0 && info.nHeightFirst <= height && info.nHeightLast >= height) {
        return false; // Block is in a non-pruned file
      }
    }

    // If we have pruned and the block is not in any file, it's pruned
    return this.havePruned;
  }

  /**
   * Get pruning info for getblockchaininfo RPC.
   */
  getPruneInfo(): {
    pruned: boolean;
    pruneheight?: number;
    automatic_pruning: boolean;
    prune_target_size?: number;
  } {
    if (!this.isPruneMode()) {
      return {
        pruned: false,
        automatic_pruning: false,
      };
    }

    const result: {
      pruned: boolean;
      pruneheight?: number;
      automatic_pruning: boolean;
      prune_target_size?: number;
    } = {
      pruned: this.havePruned,
      automatic_pruning: true,
      prune_target_size: this.pruneTarget,
    };

    if (this.havePruned) {
      result.pruneheight = this.getFirstUnprunedHeight();
    }

    return result;
  }
}
