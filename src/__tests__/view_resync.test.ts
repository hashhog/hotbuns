/**
 * UTXO-view / chain-state reconciliation tests (hotbuns).
 *
 * Regression coverage for the May 2026 mainnet h=950148 "view-out-of-sync"
 * stall.  Root cause: `coreConnectBlockChecks` advances the UTXO view's
 * best-block pointer (`UTXOManager.setBestBlock`, which mutates BOTH the
 * `CoinsViewCache` AND the long-lived `CoinsViewDB`) for every block that
 * passes its in-memory checks — but the persisted `CHAIN_STATE` record only
 * advances on a flush.  When a block connected in-memory (view pointer
 * advanced) and the *next* block then failed validation, `sync/blocks.ts`
 * called `UTXOManager.clearCache()`.  Pre-fix that discarded the cache but
 * left `CoinsViewDB.bestBlockHash` pointing one block AHEAD of the on-disk
 * tip.  Every retry then re-read the stale pointer through a fresh cache and
 * tripped the view-best-block gate (validation.cpp:2333) — a permanent wedge.
 *
 * The fix:
 *   - `UTXOManager.clearCache(bestBlockAfterClear?)` — when given the on-disk
 *     tip, re-points BOTH cache + CoinsViewDB so the view is consistent.
 *   - `UTXOManager.reconcileBestBlock(persistedTipHash)` — startup
 *     reconciliation (hotbuns' analogue of Core's `LoadChainTip`).
 *   - `ChainStateManager.load()` calls `reconcileBestBlock` after reading
 *     the persisted `CHAIN_STATE` record.
 *
 * Reference: bitcoin-core/src/validation.cpp:2333 (the assert),
 *            :4546 LoadChainTip, :4773 ReplayBlocks.
 */

import { describe, test, expect, beforeEach, afterEach } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ChainDB } from "../storage/database.js";
import { REGTEST } from "../consensus/params.js";
import { UTXOManager } from "../chain/utxo.js";
import { ChainStateManager } from "../chain/state.js";
import {
  coreConnectBlockChecks,
} from "../consensus/connect_block.js";
import type { Block, BlockHeader } from "../validation/block.js";
import { getBlockHash } from "../validation/block.js";
import { getTxId } from "../validation/tx.js";
import type { Transaction } from "../validation/tx.js";
import { hash256 } from "../crypto/primitives.js";

// ─── Helpers ─────────────────────────────────────────────────────────────────

function makeCoinbase(height: number, value: bigint): Transaction {
  return {
    version: 1,
    inputs: [
      {
        prevOut: { txid: Buffer.alloc(32, 0), vout: 0xffffffff },
        scriptSig: Buffer.concat([Buffer.from([0x03]), Buffer.alloc(3, height)]),
        sequence: 0xffffffff,
        witness: [],
      },
    ],
    outputs: [
      {
        value,
        scriptPubKey: Buffer.from([0x76, 0xa9, 0x14, ...Array(20).fill(0x01), 0x88, 0xac]),
      },
    ],
    lockTime: 0,
  };
}

function makeHeader(prevBlock: Buffer, merkleRoot: Buffer): BlockHeader {
  return {
    version: 0x20000000,
    prevBlock,
    merkleRoot,
    timestamp: Math.floor(Date.now() / 1000),
    bits: REGTEST.powLimitBits,
    nonce: 0,
  };
}

function makeBlock(prevBlock: Buffer, txs: Transaction[]): Block {
  const txids = txs.map(getTxId);
  const merkle = txids.length === 1 ? txids[0] : hash256(Buffer.concat(txids));
  return { header: makeHeader(prevBlock, merkle), transactions: txs };
}

/** Display-order (LE) hex of a block's hash, as the gate expects. */
function viewBestHexLE(blockHashInternal: Buffer): string {
  return Buffer.from(blockHashInternal).reverse().toString("hex");
}

// ─── Tests ───────────────────────────────────────────────────────────────────

describe("UTXO-view / chain-state reconciliation (h=950148 stall regression)", () => {
  let tempDir: string;
  let db: ChainDB;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "hotbuns-view-resync-"));
    db = new ChainDB(tempDir);
    await db.open();
  });

  afterEach(async () => {
    await db.close();
    await rm(tempDir, { recursive: true, force: true });
  });

  // ── The wedge: clearCache() must not strand a stale view pointer ──────────
  describe("clearCache() resets the CoinsViewDB best-block pointer", () => {
    test("WEDGE REPRO: bare clearCache() leaves a stale view pointer ahead of disk", async () => {
      const utxo = new UTXOManager(db);

      // Block N connected in-memory: the view best-block pointer was advanced
      // to N's hash by coreConnectBlockChecks → utxoManager.setBestBlock.
      const blockNHash = Buffer.alloc(32, 0x77); // stand-in for block 950148
      utxo.setBestBlock(blockNHash);

      // Block N+1 fails validation. Pre-fix recovery: a BARE clearCache().
      utxo.clearCache();

      // The fresh cache lazy-loads its pointer from the CoinsViewDB — which
      // STILL holds block N. This is the stale pointer that wedged mainnet.
      const stale = await utxo.getCoinsViewCache().getBestBlock();
      expect(stale.equals(blockNHash)).toBe(true);
    });

    test("FIX: clearCache(onDiskTip) re-points cache AND CoinsViewDB to the on-disk tip", async () => {
      const utxo = new UTXOManager(db);

      const blockNHash = Buffer.alloc(32, 0x77); // block 950148 (connected in-mem)
      const onDiskTipHash = Buffer.alloc(32, 0x55); // block 950147 (last flushed)
      utxo.setBestBlock(blockNHash);

      // Recovery path post-fix: pass the last-flushed tip.
      utxo.clearCache(onDiskTipHash);

      // Both layers now reflect the on-disk tip — no stale pointer.
      const cacheBest = await utxo.getCoinsViewCache().getBestBlock();
      expect(cacheBest.equals(onDiskTipHash)).toBe(true);
      // CoinsViewDB layer too (a second clearCache lazy-loads from it).
      const dbBest = await utxo.getCoinsViewDB().getBestBlock();
      expect(dbBest.equals(onDiskTipHash)).toBe(true);
    });
  });

  // ── reconcileBestBlock — startup reconciliation primitive ─────────────────
  describe("UTXOManager.reconcileBestBlock()", () => {
    test("reports drift and corrects the pointer when the view is ahead of the persisted tip", async () => {
      const utxo = new UTXOManager(db);

      const aheadHash = Buffer.alloc(32, 0x77); // in-memory view ahead
      const persistedTip = Buffer.alloc(32, 0x55); // persisted CHAIN_STATE tip
      utxo.setBestBlock(aheadHash);

      const drifted = await utxo.reconcileBestBlock(persistedTip);
      expect(drifted).toBe(true);

      const best = await utxo.getCoinsViewCache().getBestBlock();
      expect(best.equals(persistedTip)).toBe(true);
    });

    test("reports no drift (false) when the view already matches the persisted tip", async () => {
      const utxo = new UTXOManager(db);
      const tip = Buffer.alloc(32, 0x55);
      utxo.setBestBlock(tip);

      const drifted = await utxo.reconcileBestBlock(tip);
      expect(drifted).toBe(false);
    });
  });

  // ── The end-to-end gate behaviour the wedge tripped ──────────────────────
  describe("coreConnectBlockChecks view-out-of-sync gate after reconciliation", () => {
    test("a stale (ahead) view pointer trips the view-out-of-sync gate", async () => {
      const utxo = new UTXOManager(db);

      // Simulate the wedged state: view best = block 950148, but we are
      // re-processing block 950148 whose prev = block 950147.
      const block950148Hash = Buffer.alloc(32, 0x77);
      const block950147Hash = Buffer.alloc(32, 0x55);
      utxo.setBestBlock(block950148Hash);

      const block950148 = makeBlock(block950147Hash, [
        makeCoinbase(950148, 0n),
      ]);

      const viewBest = await utxo.getCoinsViewCache().getBestBlock();
      const result = await coreConnectBlockChecks(block950148, 950148, utxo, REGTEST, {
        utxoBestBlockHashHex: viewBestHexLE(viewBest),
      });

      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.error).toContain("view-out-of-sync");
      }
    });

    test("after clearCache(onDiskTip) the SAME block re-connects cleanly (wedge cleared)", async () => {
      const utxo = new UTXOManager(db);

      const block950148Hash = Buffer.alloc(32, 0x77);
      const block950147Hash = Buffer.alloc(32, 0x55);

      // Wedged: view ahead at 950148.
      utxo.setBestBlock(block950148Hash);

      // Recovery: clear + reconcile to the on-disk tip (block 950147).
      utxo.clearCache(block950147Hash);

      // Re-process block 950148 (prev = 950147). The gate must now PASS.
      const block950148 = makeBlock(block950147Hash, [
        makeCoinbase(950148, 0n),
      ]);
      const viewBest = await utxo.getCoinsViewCache().getBestBlock();
      const result = await coreConnectBlockChecks(block950148, 950148, utxo, REGTEST, {
        utxoBestBlockHashHex: viewBestHexLE(viewBest),
      });

      expect(result.ok).toBe(true);
    });
  });

  // ── ChainStateManager.load() seeds the view from the persisted record ────
  describe("ChainStateManager.load() startup reconciliation", () => {
    test("seeds the UTXO view best-block pointer from the persisted CHAIN_STATE record", async () => {
      // Persist a chain-state record at a non-genesis tip.
      const persistedTip = Buffer.alloc(32, 0x55);
      await db.putChainState({
        bestBlockHash: persistedTip,
        bestHeight: 950147,
        totalWork: 123456789n,
      });

      // load() must seed the UTXO view's best-block pointer to match.
      const csm = new ChainStateManager(db, REGTEST);
      await csm.load();

      const utxo = csm.getUTXOManager();
      const viewBest = await utxo.getCoinsViewCache().getBestBlock();
      expect(viewBest.equals(persistedTip)).toBe(true);

      // And the chain-state itself loaded correctly.
      expect(csm.getBestBlock().height).toBe(950147);
      expect(csm.getBestBlock().hash.equals(persistedTip)).toBe(true);
    });

    test("after load() the view-out-of-sync gate has a correct baseline (no false fresh-view skip)", async () => {
      // Persist tip at block 950147.
      const block950147Hash = Buffer.alloc(32, 0x55);
      await db.putChainState({
        bestBlockHash: block950147Hash,
        bestHeight: 950147,
        totalWork: 1n,
      });

      const csm = new ChainStateManager(db, REGTEST);
      await csm.load();
      const utxo = csm.getUTXOManager();

      // Connecting block 950148 (prev = 950147) must pass the gate: the
      // seeded pointer equals the block's prev.
      const block950148 = makeBlock(block950147Hash, [
        makeCoinbase(950148, 0n),
      ]);
      const viewBest = await utxo.getCoinsViewCache().getBestBlock();
      const okResult = await coreConnectBlockChecks(block950148, 950148, utxo, REGTEST, {
        utxoBestBlockHashHex: viewBestHexLE(viewBest),
      });
      expect(okResult.ok).toBe(true);

      // Connecting a WRONG-parent block at 950148 must be REJECTED — proving
      // the gate is now armed (pre-fix the all-zero pointer skipped it).
      const wrongParentBlock = makeBlock(Buffer.alloc(32, 0xee), [
        makeCoinbase(950148, 0n),
      ]);
      const viewBest2 = await utxo.getCoinsViewCache().getBestBlock();
      const rejectResult = await coreConnectBlockChecks(
        wrongParentBlock,
        950148,
        utxo,
        REGTEST,
        { utxoBestBlockHashHex: viewBestHexLE(viewBest2) }
      );
      expect(rejectResult.ok).toBe(false);
      if (!rejectResult.ok) {
        expect(rejectResult.error).toContain("view-out-of-sync");
      }
    });
  });
});
