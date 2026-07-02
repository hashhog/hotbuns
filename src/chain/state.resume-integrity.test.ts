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
 * Fix: `load()` detects the leading active-chain index (an entry above the
 * durable CHAIN_STATE tip) and FAILS CLOSED with a clear, actionable
 * "chainstate incomplete, reindex needed" error instead of silently running with
 * a corrupt view. On a CLEAN datadir the height index == CHAIN_STATE tip, so there
 * is no false positive.
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

  test("HALTS when the active-chain height index leads the durable UTXO tip (unclean shutdown)", async () => {
    // Durable UTXO tip = height 5 (what the last atomic flush persisted).
    const tipHash = Buffer.alloc(32, 0xa5);
    await db.putChainState({
      bestBlockHash: tipHash,
      bestHeight: 5,
      totalWork: 100n,
    });
    // Active-chain height index advanced to 6 by a per-block write from a prior
    // run that was then killed before the next flush — the height-6 coins were
    // never persisted. This is the incomplete-chainstate signal.
    await db.putBlockHashByHeight(6, Buffer.alloc(32, 0x06));

    const csm = new ChainStateManager(db, REGTEST);
    await expect(csm.load()).rejects.toThrow(/chainstate incomplete/i);
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
