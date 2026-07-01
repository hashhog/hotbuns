/**
 * EFFECTIVE regression test — after an invalid-mid-reorg rejection, a later
 * VALID block that extends the active chain must ACTIVATE (tip advances),
 * matching Bitcoin Core (Core InvalidBlockFound + FindMostWorkChain).
 *
 * Drives the ACTUAL node path exactly as `submitblock` does — every block
 * enters via `BlockSync.injectBlock`, routing through
 * `processOrderedBlocks -> connectBlock -> handleReorgUtxoAndCollect`.
 *
 * Scenario (live-oracle "5-invalid-midreorg" finding):
 *
 *      genesis ── A1 ── A2 ── A3            (active chain + valid follow-up)
 *              \
 *               B1 ── B2 ── B3(invalid: bad-cb-amount)   (heavier competing tip)
 *
 * 1. A1,A2 build the active chain (tip = A2, height 2).
 * 2. B1,B2 are stored as side-branch bodies (below-frontier competing siblings).
 * 3. B3 makes the B-chain the heaviest → the node reorgs, fails on B3
 *    (bad-cb-amount), and — per the 2149a91 atomicity fix — stays on A2 with a
 *    clean UTXO view (NO partial switch to B2). [regression guard]
 * 4. A3 (a valid direct child of A2, SAME height as B3, only TIES B3 on work)
 *    is submitted. Bitcoin Core, having marked B3 BLOCK_FAILED_VALID, selects
 *    A3 as the most-work VALID chain and activates it → tip = A3, height 3.
 *
 * PRE-FIX BUG (MEDIUM): hotbuns left the invalid B3 selected as
 * `getHeaderByHeight(3)` (B3's header was never flagged invalid, and A3 —
 * tying B3 on work — did not displace it as best header). `injectBlock`
 * returned null (accept) and stored A3, but `processOrderedBlocks` kept
 * looking up B3's (absent) body at height 3 and broke without connecting A3.
 * The tip stayed at height 2 — one block behind Core.
 *
 * POST-FIX: on B3's consensus failure, `HeaderSync.invalidateHeader` flags B3
 * invalid and re-seats the best-header / by-height index on the restored
 * active tip A2, so A3 (heavier than A2) is promoted and connects → height 3.
 *
 * FAILS at the parent commit (tip stuck at 2), PASSES with the fix
 * (`verify-fix.sh`-style EFFECTIVE check).
 */

import { describe, test, expect, beforeEach, afterEach } from "bun:test";
import { mkdtemp, rm } from "fs/promises";
import { tmpdir } from "os";
import { join } from "path";
import { ChainDB } from "../storage/database.js";
import { REGTEST, compactToBigInt } from "../consensus/params.js";
import {
  Block,
  BlockHeader,
  getBlockHash,
  computeMerkleRoot,
  encodeBip34Height,
} from "../validation/block.js";
import { Transaction, getTxId } from "../validation/tx.js";
import { HeaderSync } from "./headers.js";
import { BlockSync } from "./blocks.js";
import { ChainStateManager } from "../chain/state.js";

const REGTEST_SUBSIDY = 5_000_000_000n; // 50 BTC (no halving at these heights)

function coinbaseTx(
  height: number,
  extraNonce: number,
  value: bigint = REGTEST_SUBSIDY
): Transaction {
  return {
    version: 1,
    inputs: [
      {
        prevOut: { txid: Buffer.alloc(32, 0), vout: 0xffffffff },
        scriptSig: Buffer.concat([
          encodeBip34Height(height),
          Buffer.from([0xff, extraNonce & 0xff]),
        ]),
        sequence: 0xffffffff,
        witness: [],
      },
    ],
    outputs: [
      {
        value,
        scriptPubKey: Buffer.from([
          0x76, 0xa9, 0x14, ...Buffer.alloc(20, 0x11), 0x88, 0xac,
        ]),
      },
    ],
    lockTime: 0,
  };
}

function mineBlock(
  prevBlock: Buffer,
  timestamp: number,
  height: number,
  extraNonce: number,
  coinbaseValue: bigint = REGTEST_SUBSIDY
): Block {
  const cb = coinbaseTx(height, extraNonce, coinbaseValue);
  const merkleRoot = computeMerkleRoot([getTxId(cb)]);
  const base: BlockHeader = {
    version: 4,
    prevBlock,
    merkleRoot,
    timestamp,
    bits: REGTEST.powLimitBits,
    nonce: 0,
  };
  const target = compactToBigInt(REGTEST.powLimitBits);
  for (let nonce = 0; nonce < 10_000_000; nonce++) {
    const header = { ...base, nonce };
    const h = Buffer.from(getBlockHash(header)).reverse();
    if (BigInt("0x" + h.toString("hex")) <= target) {
      return { header, transactions: [cb] };
    }
  }
  throw new Error("failed to mine regtest block");
}

const cbOutpoint = (block: Block) => ({
  txid: getTxId(block.transactions[0]),
  vout: 0,
});

describe("BlockSync invalid-mid-reorg: valid follow-up activates (Core parity)", () => {
  let dbPath: string;
  let db: ChainDB;
  let headerSync: HeaderSync;
  let chainState: ChainStateManager;
  let blockSync: BlockSync;

  beforeEach(async () => {
    dbPath = await mkdtemp(join(tmpdir(), "hotbuns-midreorg-activate-"));
    db = new ChainDB(dbPath);
    await db.open();
    headerSync = new HeaderSync(db, REGTEST);
    headerSync.initGenesis();
    chainState = new ChainStateManager(db, REGTEST);
    blockSync = new BlockSync(db, REGTEST, headerSync, undefined, chainState);
  });

  afterEach(async () => {
    await blockSync.stop();
    await db.close();
    await rm(dbPath, { recursive: true, force: true });
  });

  test(
    "A3 (valid child of A2) activates after B3 (invalid competing tip) is rejected",
    async () => {
      const genesis = headerSync.getBestHeader()!;
      const t0 = genesis.header.timestamp;

      // ── Active chain: genesis -> A1 -> A2 ──
      const A1 = mineBlock(genesis.hash, t0 + 600, 1, /*A*/ 1);
      const A2 = mineBlock(getBlockHash(A1.header), t0 + 1200, 2, 1);
      expect(await blockSync.injectBlock(A1)).toBeNull();
      expect(await blockSync.injectBlock(A2)).toBeNull();

      const A2Hash = getBlockHash(A2.header);
      expect(chainState.getBestBlock().height).toBe(2);
      expect(chainState.getBestBlock().hash.equals(A2Hash)).toBe(true);

      // ── Competing chain: genesis -> B1 -> B2 -> B3(invalid bad-cb-amount) ──
      const B1 = mineBlock(genesis.hash, t0 + 600, 1, /*B*/ 2);
      const B2 = mineBlock(getBlockHash(B1.header), t0 + 1200, 2, 2);
      const B3 = mineBlock(
        getBlockHash(B2.header),
        t0 + 1800,
        3,
        2,
        REGTEST_SUBSIDY * 2n // bad-cb-amount
      );

      expect(await blockSync.injectBlock(B1)).toBe("duplicate");
      expect(await blockSync.injectBlock(B2)).toBe("duplicate");

      // B3 drives the reorg, which MUST fail and roll back to A2 atomically.
      const b3Result = await blockSync.injectBlock(B3);
      expect(b3Result).not.toBeNull(); // rejected (bad-cb-amount)

      // ── Regression guard (2149a91): still on A2, NOT switched to B. ──
      expect(chainState.getBestBlock().height).toBe(2);
      expect(chainState.getBestBlock().hash.equals(A2Hash)).toBe(true);
      const utxo = (blockSync as any).utxoManager;
      const viewBest: Buffer = await utxo.getCoinsViewCache().getBestBlock();
      expect(viewBest.equals(A2Hash)).toBe(true);
      expect(await utxo.getUTXOAsync(cbOutpoint(A1))).not.toBeNull();
      expect(await utxo.getUTXOAsync(cbOutpoint(A2))).not.toBeNull();
      // cb#1 (A1 coinbase) unspent; competing B1 coin absent.
      expect(await utxo.getUTXOAsync(cbOutpoint(B1))).toBeNull();
      expect(await utxo.getUTXOAsync(cbOutpoint(B2))).toBeNull();

      // ── The fix: submit ONLY A3 (a valid direct child of A2 at the SAME ──
      // height as B3, tying B3 on work).  Core marks B3 BLOCK_FAILED_VALID
      // and activates A3 as the most-work valid chain → height 3.
      const A3 = mineBlock(A2Hash, t0 + 1800, 3, /*A*/ 1);
      const A3Hash = getBlockHash(A3.header);
      const a3Result = await blockSync.injectBlock(A3);
      expect(a3Result).toBeNull(); // accepted

      // ── The assertion that FAILS pre-fix (tip stuck at 2) and PASSES post-fix. ──
      expect(chainState.getBestBlock().height).toBe(3);
      expect(chainState.getBestBlock().hash.equals(A3Hash)).toBe(true);

      // The by-height active index now resolves h3 to A3 (not the invalid B3).
      const h3 = headerSync.getHeaderByHeight(3);
      expect(h3).toBeDefined();
      expect(h3!.hash.equals(A3Hash)).toBe(true);

      // UTXO set is coherent on the A chain through the recovery.
      expect(await utxo.getUTXOAsync(cbOutpoint(A1))).not.toBeNull();
      expect(await utxo.getUTXOAsync(cbOutpoint(A3))).not.toBeNull();
      expect(await utxo.getUTXOAsync(cbOutpoint(B1))).toBeNull();
    },
    30_000
  );

  test(
    "invalid competing tip alone (no follow-up) still stays on A2 (no 2149a91 regression)",
    async () => {
      const genesis = headerSync.getBestHeader()!;
      const t0 = genesis.header.timestamp;

      const A1 = mineBlock(genesis.hash, t0 + 600, 1, 1);
      const A2 = mineBlock(getBlockHash(A1.header), t0 + 1200, 2, 1);
      await blockSync.injectBlock(A1);
      await blockSync.injectBlock(A2);
      const A2Hash = getBlockHash(A2.header);

      const B1 = mineBlock(genesis.hash, t0 + 600, 1, 2);
      const B2 = mineBlock(getBlockHash(B1.header), t0 + 1200, 2, 2);
      const B3 = mineBlock(
        getBlockHash(B2.header),
        t0 + 1800,
        3,
        2,
        REGTEST_SUBSIDY * 2n
      );
      await blockSync.injectBlock(B1);
      await blockSync.injectBlock(B2);
      expect(await blockSync.injectBlock(B3)).not.toBeNull();

      // Node stays on A2 with a clean view — the losing branch is never adopted.
      expect(chainState.getBestBlock().height).toBe(2);
      expect(chainState.getBestBlock().hash.equals(A2Hash)).toBe(true);
      const utxo = (blockSync as any).utxoManager;
      expect((await utxo.getCoinsViewCache().getBestBlock()).equals(A2Hash)).toBe(true);
      expect(await utxo.getUTXOAsync(cbOutpoint(B1))).toBeNull();
    },
    30_000
  );
});
