/**
 * EFFECTIVE regression test — atomic reorg rollback on a failed competing tip
 * (Reorg wave 3; Core ActivateBestChainStep parity).
 *
 * Drives the ACTUAL node reorg path exactly as `submitblock` does — every block
 * enters via `BlockSync.injectBlock` (the submitblock RPC entrypoint), which
 * routes through `processOrderedBlocks -> connectBlock -> handleReorgUtxoAndCollect`.
 *
 * Scenario (mirrors the live-oracle finding):
 *
 *      genesis ── A1 ── A2            (active chain)
 *              \
 *               B1 ── B2 ── B3(invalid: bad-cb-amount)   (heavier competing chain)
 *
 * Submitting B3 makes B the heaviest chain, so the node reorgs: it disconnects
 * A2/A1 back to the fork (genesis), reconnects the competing intermediates
 * B1/B2 against the in-memory UTXO view, then validates B3 — which fails
 * `bad-cb-amount`. Bitcoin Core connects the competing chain against a THROWAWAY
 * CCoinsViewCache and DROPS it on any ConnectTip failure, leaving `m_chain` on
 * the original active branch A2 (validation.cpp ActivateBestChainStep +
 * DisconnectTip/ConnectTip; chain.cpp CChain::FindFork).
 *
 * Pre-fix, hotbuns eagerly mutated the in-memory view in place (A disconnected,
 * B1/B2 reconnected, view best-block advanced to B2), returned false, and the
 * caller's generic clearCache — keyed on `getHeaderByHeight(lastFlushed)`, which
 * mid-reorg is the LOSING fork B2 (the best-HEADER chain's height entry), not
 * the active-chain tip A2 — cemented the UTXO view on the wrong branch. The node
 * settled at A2's height but on B2's UTXO, and could never advance again (the
 * stranded B2 view-best-block pointer trips the view-out-of-sync gate for any
 * A-extension), so it could not reach Core's next tip.
 *
 * Post-fix, `connectBlock` atomically restores the original active tip A2 on the
 * failed reorg, so:
 *   1. the UTXO view stays on A2 (A1 coin present, B1 coin absent), and
 *   2. a later valid A-extension (A3, A4) connects and the node reaches h4.
 *
 * This test FAILS at the parent commit and PASSES with the fix
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

/** Regtest block subsidy for the low heights used here (no halving). */
const REGTEST_SUBSIDY = 5_000_000_000n; // 50 BTC

/** Valid coinbase (P2PKH to a dummy hash) with byte-exact BIP34 height prefix
 *  plus a per-branch extranonce tag so competing branches at the same height
 *  produce distinct txids/hashes. */
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
          encodeBip34Height(height), // canonical BIP34 prefix (OP_1..OP_16 etc.)
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

/** Mine a regtest block; `extraNonce` tags the coinbase so competing branches
 *  at the same height get distinct hashes. */
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

describe("BlockSync reorg atomicity (Reorg wave 3)", () => {
  let dbPath: string;
  let db: ChainDB;
  let headerSync: HeaderSync;
  let chainState: ChainStateManager;
  let blockSync: BlockSync;

  beforeEach(async () => {
    dbPath = await mkdtemp(join(tmpdir(), "hotbuns-reorg-atomicity-"));
    db = new ChainDB(dbPath);
    await db.open();
    headerSync = new HeaderSync(db, REGTEST);
    headerSync.initGenesis();
    chainState = new ChainStateManager(db, REGTEST);
    // Wire the real ChainStateManager so the reorg dispatch (which keys off
    // getBestBlock()/updateTip) engages — same wiring cli.ts uses.
    blockSync = new BlockSync(db, REGTEST, headerSync, undefined, chainState);
  });

  afterEach(async () => {
    await blockSync.stop();
    await db.close();
    await rm(dbPath, { recursive: true, force: true });
  });

  test(
    "invalid competing tip: node restores active chain A2 (no partial switch to B2) and can still advance",
    async () => {
      const genesis = headerSync.getBestHeader()!;
      const t0 = genesis.header.timestamp;

      // ── Active chain A: genesis -> A1 -> A2 ──
      const A1 = mineBlock(genesis.hash, t0 + 600, 1, /*A*/ 1);
      const A2 = mineBlock(getBlockHash(A1.header), t0 + 1200, 2, 1);
      expect(await blockSync.injectBlock(A1)).toBeNull(); // accepted
      expect(await blockSync.injectBlock(A2)).toBeNull(); // accepted

      const A2Hash = getBlockHash(A2.header);
      expect(chainState.getBestBlock().height).toBe(2);
      expect(chainState.getBestBlock().hash.equals(A2Hash)).toBe(true);

      // ── Competing chain B: genesis -> B1 -> B2 -> B3(invalid) ──
      // B1/B2 valid; B3 claims double the block subsidy => bad-cb-amount.
      const B1 = mineBlock(genesis.hash, t0 + 600, 1, /*B*/ 2);
      const B2 = mineBlock(getBlockHash(B1.header), t0 + 1200, 2, 2);
      const B3 = mineBlock(
        getBlockHash(B2.header),
        t0 + 1800,
        3,
        2,
        REGTEST_SUBSIDY * 2n // bad-cb-amount
      );

      // Submit the competing intermediates first (stored as side-branch
      // bodies, exactly as submitblock does for below-frontier siblings).
      expect(await blockSync.injectBlock(B1)).toBe("duplicate");
      expect(await blockSync.injectBlock(B2)).toBe("duplicate");

      // Submitting B3 makes B the heaviest chain and drives the reorg, which
      // must FAIL on B3 and roll back to A2 atomically.
      const b3Result = await blockSync.injectBlock(B3);
      expect(b3Result).not.toBeNull(); // B3 rejected (bad-cb-amount)

      // ── Checkpoint 1: the active chain is fully restored to A2, NOT B2. ──
      // (Pre-fix: view best-block == B2, A1 coin gone, B1 coin present.)
      const utxo = (blockSync as any).utxoManager;
      const viewBest: Buffer = await utxo.getCoinsViewCache().getBestBlock();
      expect(viewBest.equals(A2Hash)).toBe(true);

      // A1's coinbase UTXO is present (A chain intact); B1's is absent
      // (the competing branch was never committed).
      expect(await utxo.getUTXOAsync(cbOutpoint(A1))).not.toBeNull();
      expect(await utxo.getUTXOAsync(cbOutpoint(A2))).not.toBeNull();
      expect(await utxo.getUTXOAsync(cbOutpoint(B1))).toBeNull();
      expect(await utxo.getUTXOAsync(cbOutpoint(B2))).toBeNull();

      // Chain tip unchanged — still A2 at height 2.
      expect(chainState.getBestBlock().height).toBe(2);
      expect(chainState.getBestBlock().hash.equals(A2Hash)).toBe(true);

      // ── Checkpoint 2: a later valid A-extension connects and the node ──
      // advances past the losing branch (Core reaches the next tip; pre-fix
      // the stranded B2 view-best-block pointer trips view-out-of-sync and
      // the node can never advance).
      const A3 = mineBlock(A2Hash, t0 + 1800, 3, 1);
      const A4 = mineBlock(getBlockHash(A3.header), t0 + 2400, 4, 1);
      await blockSync.injectBlock(A3);
      await blockSync.injectBlock(A4);

      const A4Hash = getBlockHash(A4.header);
      expect(chainState.getBestBlock().height).toBe(4);
      expect(chainState.getBestBlock().hash.equals(A4Hash)).toBe(true);
      // A chain remains coherent through the recovery.
      expect(await utxo.getUTXOAsync(cbOutpoint(A1))).not.toBeNull();
      expect(await utxo.getUTXOAsync(cbOutpoint(B1))).toBeNull();
    },
    30_000
  );
});
