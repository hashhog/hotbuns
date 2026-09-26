/**
 * Resume-time chainstate-integrity regression (crash-recovery / state-integrity).
 *
 * Production blocker (modern-replay triage): after an UNCLEAN shutdown mid-IBD
 * (SIGKILL / OOM / power loss between the periodic FLUSH_INTERVAL flushes), the
 * on-disk ACTIVE-CHAIN height->hash index (DBPrefix.HEADER, advanced per-block by
 * `putBlockHashByHeight`) can lead the durable UTXO tip recorded in CHAIN_STATE
 * (written only in the atomic flush batch alongside the UTXO coins). The dirty
 * in-memory coins for the leading heights were never flushed and are lost, so the
 * UTXO set has holes. Pre-fix, `ChainStateManager.load()` fixed only the
 * best-block POINTER and ran on — later spuriously rejecting a valid block whose
 * prevout `gettxout` returned null (observed: resume at 250000, spurious reject of
 * valid block 255587 with bad-txns-inputs-missingorspent).
 *
 * First fix: `load()` failed closed ("chainstate incomplete, reindex needed").
 * That made every unclean stop mid-IBD a wipe-and-resync. Current behaviour
 * (2026-09-26): the coins on disk are a complete UTXO set AT the CHAIN_STATE
 * tip, and block sync resumes from that tip, so `load()` rolls the height index
 * back to it (Core: the tip comes from the coins-DB best block) and the blocks
 * above are connected again. On a CLEAN datadir the height index == CHAIN_STATE
 * tip, so nothing is removed.
 */

import { describe, test, expect, beforeEach, afterEach } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ChainDB } from "../storage/database.js";
import { REGTEST } from "../consensus/params.js";
import { ChainStateManager } from "./state.js";

describe("ChainStateManager.load resume-integrity guard", () => {
  let tempDir: string;
  let db: ChainDB;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "hotbuns-resume-integrity-"));
    db = new ChainDB(tempDir);
    await db.open();
  });

  afterEach(async () => {
    await db.close();
    await rm(tempDir, { recursive: true, force: true });
  });

  test("ROLLS BACK the height index when it leads the durable UTXO tip (unclean stop), instead of refusing to boot", async () => {
    // Durable UTXO tip = height 5 (what the last atomic flush persisted).
    const tipHash = Buffer.alloc(32, 0xa5);
    await db.putChainState({
      bestBlockHash: tipHash,
      bestHeight: 5,
      totalWork: 100n,
    });
    await db.putBlockHashByHeight(5, tipHash);
    // Active-chain height index advanced to 6..9 (and a stray 12) by per-block
    // writes from a prior run that stopped before the next coins flush — the
    // coins for those heights were never persisted.
    for (const h of [6, 7, 8, 9, 12]) {
      await db.putBlockHashByHeight(h, Buffer.alloc(32, h));
    }

    const csm = new ChainStateManager(db, REGTEST);
    // Pre-fix: rejects with "chainstate incomplete ... wipe the datadir".
    await expect(csm.load()).resolves.toBeUndefined();
    expect(csm.getBestBlock().height).toBe(5);
    expect(csm.getBestBlock().hash.equals(tipHash)).toBe(true);
    // Height index now agrees with the durable coins tip.
    expect((await db.getBlockHashByHeight(5))!.equals(tipHash)).toBe(true);
    for (const h of [6, 7, 8, 9, 10, 12]) {
      expect(await db.getBlockHashByHeight(h)).toBeNull();
    }
    // Second boot is a no-op (idempotent).
    const csm2 = new ChainStateManager(db, REGTEST);
    await expect(csm2.load()).resolves.toBeUndefined();
    expect(csm2.getBestBlock().height).toBe(5);
  });

  test("does NOT halt on a clean datadir (height index == durable tip)", async () => {
    const tipHash = Buffer.alloc(32, 0xc1);
    await db.putChainState({
      bestBlockHash: tipHash,
      bestHeight: 5,
      totalWork: 100n,
    });
    // Clean shutdown: the active height index reaches exactly the durable tip
    // (height 5) and no higher — the counterpart write for height 6 was never
    // made because block 6 never connected.
    await db.putBlockHashByHeight(5, tipHash);

    const csm = new ChainStateManager(db, REGTEST);
    await expect(csm.load()).resolves.toBeUndefined();
    expect(csm.getBestBlock().height).toBe(5);
  });

  test("does NOT halt on a fresh (genesis-only) datadir", async () => {
    // No CHAIN_STATE yet — load() initializes genesis and must not trip the guard.
    const csm = new ChainStateManager(db, REGTEST);
    await expect(csm.load()).resolves.toBeUndefined();
    expect(csm.getBestBlock().height).toBe(0);
  });
});
