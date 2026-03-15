/**
 * Tests for block pruning functionality.
 *
 * Tests cover:
 * - PruneManager initialization and configuration
 * - Automatic pruning based on disk usage target
 * - Manual pruning via pruneblockchain RPC
 * - Block file deletion
 * - MIN_BLOCKS_TO_KEEP enforcement
 * - Pruned block detection
 */

import { describe, it, expect, beforeEach, afterEach } from "bun:test";
import { mkdir, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { ChainDB, BlockStatus } from "../storage/database.js";
import {
  PruneManager,
  MIN_PRUNE_TARGET,
  MIN_BLOCKS_TO_KEEP,
} from "../storage/pruning.js";
import {
  type BlockFileInfo,
  serializeBlockFileInfo,
  createEmptyBlockFileInfo,
} from "../storage/blockfile.js";

describe("PruneManager", () => {
  let dataDir: string;
  let db: ChainDB;
  let pruneManager: PruneManager;

  beforeEach(async () => {
    // Create a unique temporary directory for each test
    dataDir = join(tmpdir(), `hotbuns-prune-test-${Date.now()}-${Math.random().toString(36).slice(2)}`);
    await mkdir(join(dataDir, "blocks"), { recursive: true });

    db = new ChainDB(join(dataDir, "blocks.db"));
    await db.open();
  });

  afterEach(async () => {
    await db.close();
    try {
      await rm(dataDir, { recursive: true, force: true });
    } catch {
      // Ignore cleanup errors
    }
  });

  describe("initialization", () => {
    it("should initialize with pruning disabled when target is 0", async () => {
      pruneManager = new PruneManager(db, dataDir, 0);
      await pruneManager.init();

      expect(pruneManager.isPruneMode()).toBe(false);
      expect(pruneManager.hasEverPruned()).toBe(false);
    });

    it("should initialize with pruning enabled when target > 0", async () => {
      const target = 550 * 1024 * 1024; // 550 MiB
      pruneManager = new PruneManager(db, dataDir, target);
      await pruneManager.init();

      expect(pruneManager.isPruneMode()).toBe(true);
      expect(pruneManager.getPruneTarget()).toBe(target);
    });

    it("should load existing prune state from database", async () => {
      // Set prune state in database
      await db.putPruneState(true, 600 * 1024 * 1024);

      pruneManager = new PruneManager(db, dataDir, 600 * 1024 * 1024);
      await pruneManager.init();

      expect(pruneManager.hasEverPruned()).toBe(true);
    });
  });

  describe("disk usage calculation", () => {
    it("should calculate zero usage when no files exist", async () => {
      pruneManager = new PruneManager(db, dataDir, MIN_PRUNE_TARGET);
      await pruneManager.init();

      expect(pruneManager.calculateCurrentUsage()).toBe(0);
    });

    it("should calculate usage from block file info", async () => {
      // Create some mock block file info
      const fileInfo1: BlockFileInfo = {
        nBlocks: 10,
        nSize: 1024 * 1024, // 1 MiB
        nUndoSize: 128 * 1024, // 128 KiB
        nHeightFirst: 0,
        nHeightLast: 9,
        nTimeFirst: 1000000,
        nTimeLast: 1000900,
      };

      const fileInfo2: BlockFileInfo = {
        nBlocks: 5,
        nSize: 512 * 1024,
        nUndoSize: 64 * 1024,
        nHeightFirst: 10,
        nHeightLast: 14,
        nTimeFirst: 1001000,
        nTimeLast: 1001400,
      };

      await db.putBlockFileInfo(0, serializeBlockFileInfo(fileInfo1));
      await db.putBlockFileInfo(1, serializeBlockFileInfo(fileInfo2));
      await db.putLastBlockFile(1);

      pruneManager = new PruneManager(db, dataDir, MIN_PRUNE_TARGET);
      await pruneManager.init();

      const expectedUsage = fileInfo1.nSize + fileInfo1.nUndoSize + fileInfo2.nSize + fileInfo2.nUndoSize;
      expect(pruneManager.calculateCurrentUsage()).toBe(expectedUsage);
    });
  });

  describe("automatic pruning", () => {
    it("should not prune when below target", async () => {
      const target = 10 * 1024 * 1024; // 10 MiB target (below MIN but for testing)
      pruneManager = new PruneManager(db, dataDir, target);
      await pruneManager.init();

      // No files, definitely below target
      const result = await pruneManager.maybePrune(1000);
      expect(result.filesPruned).toBe(0);
    });

    it("should respect MIN_BLOCKS_TO_KEEP", async () => {
      // Create file info for blocks close to tip
      const fileInfo: BlockFileInfo = {
        nBlocks: 100,
        nSize: 100 * 1024 * 1024, // Large file to trigger pruning
        nUndoSize: 10 * 1024 * 1024,
        nHeightFirst: 800, // Within MIN_BLOCKS_TO_KEEP of tip 1000
        nHeightLast: 899,
        nTimeFirst: 1000000,
        nTimeLast: 1009900,
      };

      await db.putBlockFileInfo(0, serializeBlockFileInfo(fileInfo));
      await db.putLastBlockFile(0);

      const target = 50 * 1024 * 1024; // 50 MiB target
      pruneManager = new PruneManager(db, dataDir, target);
      await pruneManager.init();

      // With chainHeight 1000, we should keep blocks after 1000 - 288 = 712
      // File contains blocks 800-899, all within keep range
      const filesToPrune = await pruneManager.findFilesToPrune(1000);
      expect(filesToPrune.size).toBe(0); // Should not prune
    });

    it("should prune files entirely below keep range", async () => {
      // Create file info for old blocks with large size to exceed target
      const fileInfo: BlockFileInfo = {
        nBlocks: 100,
        nSize: 600 * 1024 * 1024, // 600 MiB - larger than MIN_PRUNE_TARGET
        nUndoSize: 10 * 1024 * 1024,
        nHeightFirst: 0,
        nHeightLast: 99, // Old blocks, well below tip
        nTimeFirst: 1000000,
        nTimeLast: 1009900,
      };

      await db.putBlockFileInfo(0, serializeBlockFileInfo(fileInfo));
      await db.putLastBlockFile(0);

      // Create the actual file so we can test deletion
      const blockFilePath = join(dataDir, "blocks", "blk00000.dat");
      const revFilePath = join(dataDir, "blocks", "rev00000.dat");
      await writeFile(blockFilePath, Buffer.alloc(1024));
      await writeFile(revFilePath, Buffer.alloc(256));

      // Use MIN_PRUNE_TARGET (550 MiB), which is less than current usage (610 MiB)
      pruneManager = new PruneManager(db, dataDir, MIN_PRUNE_TARGET);
      await pruneManager.init();

      // Verify usage exceeds target
      const usage = pruneManager.calculateCurrentUsage();
      expect(usage).toBeGreaterThan(MIN_PRUNE_TARGET);

      // With chainHeight 1000, we can prune blocks below 1000 - 288 = 712
      // File contains blocks 0-99, all prunable
      const filesToPrune = await pruneManager.findFilesToPrune(1000);
      expect(filesToPrune.size).toBe(1);
      expect(filesToPrune.has(0)).toBe(true);
    });
  });

  describe("manual pruning (pruneblockchain)", () => {
    it("should prune files up to specified height", async () => {
      // Create multiple file infos
      const fileInfo0: BlockFileInfo = {
        nBlocks: 100,
        nSize: 10 * 1024 * 1024,
        nUndoSize: 1 * 1024 * 1024,
        nHeightFirst: 0,
        nHeightLast: 99,
        nTimeFirst: 1000000,
        nTimeLast: 1009900,
      };

      const fileInfo1: BlockFileInfo = {
        nBlocks: 100,
        nSize: 10 * 1024 * 1024,
        nUndoSize: 1 * 1024 * 1024,
        nHeightFirst: 100,
        nHeightLast: 199,
        nTimeFirst: 1010000,
        nTimeLast: 1019900,
      };

      const fileInfo2: BlockFileInfo = {
        nBlocks: 100,
        nSize: 10 * 1024 * 1024,
        nUndoSize: 1 * 1024 * 1024,
        nHeightFirst: 200,
        nHeightLast: 299,
        nTimeFirst: 1020000,
        nTimeLast: 1029900,
      };

      await db.putBlockFileInfo(0, serializeBlockFileInfo(fileInfo0));
      await db.putBlockFileInfo(1, serializeBlockFileInfo(fileInfo1));
      await db.putBlockFileInfo(2, serializeBlockFileInfo(fileInfo2));
      await db.putLastBlockFile(2);

      // Create the actual files
      for (let i = 0; i <= 2; i++) {
        const blockFilePath = join(dataDir, "blocks", `blk0000${i}.dat`);
        const revFilePath = join(dataDir, "blocks", `rev0000${i}.dat`);
        await writeFile(blockFilePath, Buffer.alloc(1024));
        await writeFile(revFilePath, Buffer.alloc(256));
      }

      const target = MIN_PRUNE_TARGET;
      pruneManager = new PruneManager(db, dataDir, target);
      await pruneManager.init();

      // Prune up to height 150 with chainHeight 500
      // This should prune file 0 (blocks 0-99) only
      // File 1 (blocks 100-199) spans across height 150, so may not be pruned
      const result = await pruneManager.pruneBlockchain(150, 500);

      // File 0 should be pruned, file 1 has blocks above 150
      expect(result.filesPruned).toBeGreaterThanOrEqual(1);
    });

    it("should error when pruning is not enabled", async () => {
      pruneManager = new PruneManager(db, dataDir, 0);
      await pruneManager.init();

      expect(pruneManager.isPruneMode()).toBe(false);
      expect(() => pruneManager.pruneBlockchain(100, 1000)).toThrow(
        "Pruning is not enabled"
      );
    });

    it("should respect MIN_BLOCKS_TO_KEEP for manual pruning", async () => {
      const fileInfo: BlockFileInfo = {
        nBlocks: 100,
        nSize: 10 * 1024 * 1024,
        nUndoSize: 1 * 1024 * 1024,
        nHeightFirst: 900,
        nHeightLast: 999,
        nTimeFirst: 1000000,
        nTimeLast: 1009900,
      };

      await db.putBlockFileInfo(0, serializeBlockFileInfo(fileInfo));
      await db.putLastBlockFile(0);

      pruneManager = new PruneManager(db, dataDir, MIN_PRUNE_TARGET);
      await pruneManager.init();

      // Try to prune up to height 990 with chainHeight 1000
      // But MIN_BLOCKS_TO_KEEP (288) means we can only prune up to 1000 - 288 = 712
      // File has blocks 900-999, which are all above 712, so nothing should be pruned
      const result = await pruneManager.pruneBlockchain(990, 1000);
      expect(result.filesPruned).toBe(0);
    });
  });

  describe("isBlockPruned", () => {
    it("should return false when no pruning has occurred", async () => {
      pruneManager = new PruneManager(db, dataDir, MIN_PRUNE_TARGET);
      await pruneManager.init();

      expect(pruneManager.isBlockPruned(100)).toBe(false);
    });

    it("should return true for blocks in pruned files", async () => {
      // Create file info with nSize = 0 (pruned)
      const prunedFileInfo = createEmptyBlockFileInfo();
      await db.putBlockFileInfo(0, serializeBlockFileInfo(prunedFileInfo));

      // Create another file with actual data
      const activeFileInfo: BlockFileInfo = {
        nBlocks: 100,
        nSize: 10 * 1024 * 1024,
        nUndoSize: 1 * 1024 * 1024,
        nHeightFirst: 100,
        nHeightLast: 199,
        nTimeFirst: 1000000,
        nTimeLast: 1009900,
      };
      await db.putBlockFileInfo(1, serializeBlockFileInfo(activeFileInfo));
      await db.putLastBlockFile(1);
      await db.putPruneState(true, MIN_PRUNE_TARGET);

      pruneManager = new PruneManager(db, dataDir, MIN_PRUNE_TARGET);
      await pruneManager.init();

      // Block 50 would have been in file 0, which is now pruned
      expect(pruneManager.isBlockPruned(50)).toBe(true);

      // Block 150 is in file 1, which is not pruned
      expect(pruneManager.isBlockPruned(150)).toBe(false);
    });
  });

  describe("getPruneInfo", () => {
    it("should return correct info when pruning is disabled", async () => {
      pruneManager = new PruneManager(db, dataDir, 0);
      await pruneManager.init();

      const info = pruneManager.getPruneInfo();
      expect(info.pruned).toBe(false);
      expect(info.automatic_pruning).toBe(false);
      expect(info.prune_target_size).toBeUndefined();
    });

    it("should return correct info when pruning is enabled but not yet occurred", async () => {
      pruneManager = new PruneManager(db, dataDir, MIN_PRUNE_TARGET);
      await pruneManager.init();

      const info = pruneManager.getPruneInfo();
      expect(info.pruned).toBe(false);
      expect(info.automatic_pruning).toBe(true);
      expect(info.prune_target_size).toBe(MIN_PRUNE_TARGET);
    });

    it("should return pruneheight after pruning has occurred", async () => {
      await db.putPruneState(true, MIN_PRUNE_TARGET);

      // Create file info starting at height 100
      const fileInfo: BlockFileInfo = {
        nBlocks: 100,
        nSize: 10 * 1024 * 1024,
        nUndoSize: 1 * 1024 * 1024,
        nHeightFirst: 100,
        nHeightLast: 199,
        nTimeFirst: 1000000,
        nTimeLast: 1009900,
      };
      await db.putBlockFileInfo(0, serializeBlockFileInfo(fileInfo));
      await db.putLastBlockFile(0);

      pruneManager = new PruneManager(db, dataDir, MIN_PRUNE_TARGET);
      await pruneManager.init();

      const info = pruneManager.getPruneInfo();
      expect(info.pruned).toBe(true);
      expect(info.pruneheight).toBe(100); // First unpruned block
      expect(info.automatic_pruning).toBe(true);
    });
  });

  describe("file deletion", () => {
    it("should delete block and rev files", async () => {
      const fileInfo: BlockFileInfo = {
        nBlocks: 100,
        nSize: 1024,
        nUndoSize: 256,
        nHeightFirst: 0,
        nHeightLast: 99,
        nTimeFirst: 1000000,
        nTimeLast: 1009900,
      };

      await db.putBlockFileInfo(0, serializeBlockFileInfo(fileInfo));
      await db.putLastBlockFile(0);

      // Create the actual files
      const blockFilePath = join(dataDir, "blocks", "blk00000.dat");
      const revFilePath = join(dataDir, "blocks", "rev00000.dat");
      await writeFile(blockFilePath, Buffer.alloc(1024));
      await writeFile(revFilePath, Buffer.alloc(256));

      // Verify files exist
      expect(await Bun.file(blockFilePath).exists()).toBe(true);
      expect(await Bun.file(revFilePath).exists()).toBe(true);

      pruneManager = new PruneManager(db, dataDir, MIN_PRUNE_TARGET);
      await pruneManager.init();

      // Prune and unlink
      const filesToPrune = new Set([0]);
      await pruneManager.unlinkPrunedFiles(filesToPrune);

      // Verify files are deleted
      expect(await Bun.file(blockFilePath).exists()).toBe(false);
      expect(await Bun.file(revFilePath).exists()).toBe(false);
    });
  });
});

describe("MIN_PRUNE_TARGET constant", () => {
  it("should be 550 MiB", () => {
    expect(MIN_PRUNE_TARGET).toBe(550 * 1024 * 1024);
  });
});

describe("MIN_BLOCKS_TO_KEEP constant", () => {
  it("should be 288", () => {
    expect(MIN_BLOCKS_TO_KEEP).toBe(288);
  });
});
