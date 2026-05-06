/**
 * Tests for prune subsystem wiring (post-DEAD audit).
 *
 * Pre-fix the PruneManager class existed but `deps.pruneManager` was always
 * `undefined` because cli.ts never constructed one.  These tests pin down
 * the contract that the wiring relies on:
 *
 *   1. PruneManager honors `--prune=1` (PRUNE_TARGET_MANUAL) → isPruneMode
 *      true, isAutomaticPruning false; auto-scan is a no-op; manual
 *      `pruneblockchain` RPC works.
 *   2. PruneManager honors `--prune=N` (N≥550 MiB) → isPruneMode true,
 *      isAutomaticPruning true; auto-scan + manual RPC both work.
 *   3. getblockchaininfo response shape matches Bitcoin Core
 *      rpc/blockchain.cpp:1452 (`prune_target_size` ONLY when
 *      `automatic_pruning === true`).
 *   4. BlockSync.setPruneManager wiring is reachable from outside (the
 *      cli.ts → blockSync.setPruneManager call must compile + dispatch
 *      against the shipped class shape).
 */

import { describe, it, expect, beforeEach, afterEach } from "bun:test";
import { mkdir, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { ChainDB } from "../storage/database.js";
import {
  PruneManager,
  PRUNE_TARGET_MANUAL,
  MIN_PRUNE_TARGET,
} from "../storage/pruning.js";
import {
  type BlockFileInfo,
  serializeBlockFileInfo,
} from "../storage/blockfile.js";
import { BlockSync } from "../sync/blocks.js";
import { HeaderSync } from "../sync/headers.js";
import { MAINNET } from "../consensus/params.js";

describe("prune wiring (post-DEAD audit)", () => {
  let dataDir: string;
  let db: ChainDB;

  beforeEach(async () => {
    dataDir = join(
      tmpdir(),
      `hotbuns-prune-wiring-${Date.now()}-${Math.random().toString(36).slice(2)}`
    );
    await mkdir(join(dataDir, "blocks"), { recursive: true });
    db = new ChainDB(join(dataDir, "blocks.db"));
    await db.open();
  });

  afterEach(async () => {
    await db.close();
    try {
      await rm(dataDir, { recursive: true, force: true });
    } catch {
      // ignore
    }
  });

  describe("manual mode (--prune=1)", () => {
    it("isPruneMode=true, isAutomaticPruning=false", async () => {
      const pm = new PruneManager(db, dataDir, PRUNE_TARGET_MANUAL);
      await pm.init();

      expect(pm.isPruneMode()).toBe(true);
      expect(pm.isAutomaticPruning()).toBe(false);
      expect(pm.getPruneTarget()).toBe(PRUNE_TARGET_MANUAL);
    });

    it("auto-prune scan is a no-op even when usage exceeds floor", async () => {
      // Plant a block file fat enough that auto-prune *would* fire if
      // this were auto mode (size > MIN_PRUNE_TARGET, low height range).
      const fileInfo: BlockFileInfo = {
        nBlocks: 100,
        nSize: 600 * 1024 * 1024,
        nUndoSize: 10 * 1024 * 1024,
        nHeightFirst: 0,
        nHeightLast: 99,
        nTimeFirst: 1000000,
        nTimeLast: 1009900,
      };
      await db.putBlockFileInfo(0, serializeBlockFileInfo(fileInfo));
      await db.putLastBlockFile(0);

      const pm = new PruneManager(db, dataDir, PRUNE_TARGET_MANUAL);
      await pm.init();

      const filesToPrune = await pm.findFilesToPrune(1000);
      expect(filesToPrune.size).toBe(0);

      const result = await pm.maybePrune(1000);
      expect(result.filesPruned).toBe(0);
    });

    it("manual pruneblockchain RPC still works", async () => {
      // Plant two old, deletable files.
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
      await db.putBlockFileInfo(0, serializeBlockFileInfo(fileInfo0));
      await db.putBlockFileInfo(1, serializeBlockFileInfo(fileInfo1));
      await db.putLastBlockFile(1);
      await writeFile(join(dataDir, "blocks", "blk00000.dat"), Buffer.alloc(1024));
      await writeFile(join(dataDir, "blocks", "rev00000.dat"), Buffer.alloc(256));
      await writeFile(join(dataDir, "blocks", "blk00001.dat"), Buffer.alloc(1024));
      await writeFile(join(dataDir, "blocks", "rev00001.dat"), Buffer.alloc(256));

      const pm = new PruneManager(db, dataDir, PRUNE_TARGET_MANUAL);
      await pm.init();

      // tip=600, prune-up-to=150 → file 0 (blocks 0-99) prunable; file 1
      // straddles 150 so still kept.
      const result = await pm.pruneBlockchain(150, 600);
      expect(result.filesPruned).toBeGreaterThanOrEqual(1);
    });

    it("getPruneInfo: pruned=false, automatic_pruning=false, no prune_target_size", async () => {
      const pm = new PruneManager(db, dataDir, PRUNE_TARGET_MANUAL);
      await pm.init();

      const info = pm.getPruneInfo();
      expect(info.pruned).toBe(false);
      expect(info.automatic_pruning).toBe(false);
      // Bitcoin Core (rpc/blockchain.cpp:1454): `prune_target_size` is
      // only emitted when automatic_pruning is true.  Manual mode
      // suppresses it.
      expect(info.prune_target_size).toBeUndefined();
    });

    it("getPruneInfo after manual prune reports pruned=true with pruneheight", async () => {
      // Plant + prune one file manually.
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
      await db.putBlockFileInfo(0, serializeBlockFileInfo(fileInfo0));
      await db.putBlockFileInfo(1, serializeBlockFileInfo(fileInfo1));
      await db.putLastBlockFile(1);

      const pm = new PruneManager(db, dataDir, PRUNE_TARGET_MANUAL);
      await pm.init();

      await pm.pruneBlockchain(99, 600);
      const info = pm.getPruneInfo();
      expect(info.automatic_pruning).toBe(false);
      expect(info.pruned).toBe(true);
      expect(info.pruneheight).toBe(100); // first unpruned
      expect(info.prune_target_size).toBeUndefined();
    });
  });

  describe("auto mode (--prune=N)", () => {
    it("isPruneMode=true, isAutomaticPruning=true", async () => {
      const pm = new PruneManager(db, dataDir, MIN_PRUNE_TARGET);
      await pm.init();

      expect(pm.isPruneMode()).toBe(true);
      expect(pm.isAutomaticPruning()).toBe(true);
    });

    it("getPruneInfo: automatic_pruning=true, prune_target_size set", async () => {
      const pm = new PruneManager(db, dataDir, MIN_PRUNE_TARGET);
      await pm.init();

      const info = pm.getPruneInfo();
      expect(info.automatic_pruning).toBe(true);
      expect(info.prune_target_size).toBe(MIN_PRUNE_TARGET);
    });
  });

  describe("disabled (--prune=0)", () => {
    it("isPruneMode=false and getPruneInfo reflects it", async () => {
      const pm = new PruneManager(db, dataDir, 0);
      await pm.init();

      expect(pm.isPruneMode()).toBe(false);
      expect(pm.isAutomaticPruning()).toBe(false);

      const info = pm.getPruneInfo();
      expect(info.pruned).toBe(false);
      expect(info.automatic_pruning).toBe(false);
      expect(info.prune_target_size).toBeUndefined();
    });
  });

  describe("BlockSync.setPruneManager", () => {
    it("accepts a PruneManager and is callable without throwing", () => {
      const headerSync = new HeaderSync(db, MAINNET);
      const blockSync = new BlockSync(db, MAINNET, headerSync);

      const pm = new PruneManager(db, dataDir, MIN_PRUNE_TARGET);
      // No init() needed for the wiring assertion — we just need to
      // check the setter accepts the type and stores it.
      expect(() => blockSync.setPruneManager(pm)).not.toThrow();
    });
  });

  describe("PRUNE_TARGET_MANUAL sentinel", () => {
    it("is a positive integer, distinct from any valid byte count", () => {
      expect(PRUNE_TARGET_MANUAL).toBeGreaterThan(0);
      // Must be larger than any plausible byte target so the inequality
      // pruneTarget !== PRUNE_TARGET_MANUAL never collides with a real
      // operator-supplied value.  Core uses uint64::max; we use
      // Number.MAX_SAFE_INTEGER (2^53 - 1) which is comfortably above
      // any disk-target a user would set in MiB units (largest plausible
      // is ~2^40 bytes = 1 TiB).
      expect(PRUNE_TARGET_MANUAL).toBeGreaterThan(MIN_PRUNE_TARGET * 1_000_000);
    });
  });
});
