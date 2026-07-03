/**
 * W92 — DisconnectBlock + ApplyTxInUndo + chain-reorg audit tests.
 *
 * Targets the Core-faithful gates added in W92 to chain/state.ts +
 * chain/utxo.ts + sync/blocks.ts:
 *
 *   1. IsUnspendable filter accepts both OP_RETURN AND size>10000.
 *   2. Disconnect-side BIP-30 exception heights (mainnet 91722/91812)
 *      are wired into ConsensusParams.
 *   3. DisconnectBlock 4-way per-output match check (existence +
 *      value/scriptPubKey + height + coinbase).
 *   4. ApplyTxInUndo HaveCoin → fClean=false UNCLEAN signal.
 *   5. ApplyTxInUndo missing-metadata recovery via AccessByTxid.
 *   6. ApplyTxInUndo DISCONNECT_FAILED when neither undo metadata nor
 *      sibling output is present.
 *   7. DisconnectResult tristate enum is exported.
 *   8. blockUndo / block.vtx size consistency check aborts cleanly.
 *   9. Per-tx undo size check aborts cleanly.
 *  10. SetBestBlock(pprev) updates the UTXO view atomically.
 *  11. reorganize() rejects depth > MAX_REORG_DEPTH.
 *
 * Reference: bitcoin-core/src/validation.cpp:2149-2175, 2179-2248, 2929-...
 *            bitcoin-core/src/validation.h:451-455
 *            bitcoin-core/src/script/script.h:563-565
 *            bitcoin-core/src/coins.cpp:386-395 (AccessByTxid)
 */

import { describe, test, expect, beforeEach, afterEach } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ChainDB } from "../storage/database.js";
import { REGTEST, MAINNET, TESTNET, TESTNET4, SIGNET } from "../consensus/params.js";
import { ChainStateManager } from "../chain/state.js";
import {
  UTXOManager,
  DisconnectResult,
  applyTxInUndo,
  CoinsViewCache,
  CoinsViewDB,
  type SpentUTXO,
  type Coin,
} from "../chain/utxo.js";
import type { Block, BlockHeader } from "../validation/block.js";
import { getBlockHash } from "../validation/block.js";
import { getTxId } from "../validation/tx.js";
import type { Transaction } from "../validation/tx.js";
import { hash256 } from "../crypto/primitives.js";

// ─── Test helpers (copied from src/chain/state.test.ts) ──────────────────────

function createCoinbaseTx(height: number, value: bigint): Transaction {
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
        scriptPubKey: Buffer.from([
          0x76, 0xa9, 0x14, ...Array(20).fill(0x01), 0x88, 0xac,
        ]),
      },
    ],
    lockTime: 0,
  };
}

function createBlockHeader(prevBlock: Buffer, merkleRoot: Buffer): BlockHeader {
  return {
    version: 0x20000000,
    prevBlock,
    merkleRoot,
    timestamp: Math.floor(Date.now() / 1000),
    bits: REGTEST.powLimitBits,
    nonce: 0,
  };
}

function createBlock(prevBlock: Buffer, txs: Transaction[]): Block {
  const txids = txs.map(getTxId);
  // simplified merkle root: just hash the concatenation
  const merkleRoot =
    txids.length === 1 ? txids[0] : hash256(Buffer.concat(txids));
  return {
    header: createBlockHeader(prevBlock, merkleRoot),
    transactions: txs,
  };
}

// ─── Tests ───────────────────────────────────────────────────────────────────

describe("W92: DisconnectBlock + ApplyTxInUndo + chain reorg", () => {
  let tempDir: string;
  let db: ChainDB;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "hotbuns-w92-"));
    db = new ChainDB(tempDir);
    await db.open();
  });

  afterEach(async () => {
    await db.close();
    await rm(tempDir, { recursive: true, force: true });
  });

  // ── Gate #1: IsUnspendable filter ─────────────────────────────────────────
  describe("IsUnspendable filter (script.h:563-565)", () => {
    test("OP_RETURN-prefixed scripts are NOT added to UTXO set", async () => {
      const utxo = new UTXOManager(db);
      const cache = utxo.getCoinsViewCache();
      const txid = hash256(Buffer.from("opreturn"));
      const opReturnScript = Buffer.from([
        0x6a,
        0x05,
        0xde,
        0xad,
        0xbe,
        0xef,
        0x42,
      ]);
      cache.addCoin(
        { txid, vout: 0 },
        { txOut: { value: 0n, scriptPubKey: opReturnScript }, height: 100, isCoinbase: false },
        false
      );
      // Should not be in the cache after addCoin
      expect(cache.haveCoinInCache({ txid, vout: 0 })).toBe(false);
    });

    test("scriptPubKey > MAX_SCRIPT_SIZE (10000 bytes) is NOT added", async () => {
      const utxo = new UTXOManager(db);
      const cache = utxo.getCoinsViewCache();
      const txid = hash256(Buffer.from("huge"));
      // 10001-byte script that does NOT start with OP_RETURN.  Pre-W92
      // this would have been added (gate was OP_RETURN-only); post-W92
      // it must be filtered.
      const huge = Buffer.alloc(10001, 0x51 /* OP_1 — valid opcode */);
      cache.addCoin(
        { txid, vout: 0 },
        { txOut: { value: 100n, scriptPubKey: huge }, height: 100, isCoinbase: false },
        false
      );
      expect(cache.haveCoinInCache({ txid, vout: 0 })).toBe(false);
    });

    test("normal scripts (< MAX_SCRIPT_SIZE, not OP_RETURN) ARE added", async () => {
      const utxo = new UTXOManager(db);
      const cache = utxo.getCoinsViewCache();
      const txid = hash256(Buffer.from("normal"));
      const p2pkh = Buffer.from([
        0x76,
        0xa9,
        0x14,
        ...Array(20).fill(0x01),
        0x88,
        0xac,
      ]);
      cache.addCoin(
        { txid, vout: 0 },
        { txOut: { value: 1000n, scriptPubKey: p2pkh }, height: 100, isCoinbase: false },
        false
      );
      expect(cache.haveCoinInCache({ txid, vout: 0 })).toBe(true);
    });
  });

  // ── Gate #2: disconnect-side BIP-30 exception heights ─────────────────────
  describe("BIP-30 disconnect-side exception heights (validation.cpp:2201)", () => {
    test("mainnet wires 91722 and 91812 (the heights overwritten BY duplicates)", () => {
      expect(MAINNET.bip30DisconnectExceptionBlocks.length).toBe(2);
      const heights = MAINNET.bip30DisconnectExceptionBlocks.map((b) => b.height);
      expect(heights).toContain(91722);
      expect(heights).toContain(91812);
    });

    test("mainnet hashes match Core's validation.cpp:2201-2202", () => {
      const b91722 = MAINNET.bip30DisconnectExceptionBlocks.find(
        (b) => b.height === 91722
      );
      const b91812 = MAINNET.bip30DisconnectExceptionBlocks.find(
        (b) => b.height === 91812
      );
      expect(b91722?.blockHashHex).toBe(
        "00000000000271a2dc26e7667f8419f2e15416dc6955e5a6c6cdf3f2574dd08e"
      );
      expect(b91812?.blockHashHex).toBe(
        "00000000000af0aed4792b1acee3d966af36cf5def14935db8de83d6f9306f2f"
      );
    });

    test("connect-side and disconnect-side exception heights are distinct", () => {
      const connectHeights = MAINNET.bip30ExceptionBlocks.map((b) => b.height);
      const disconnectHeights = MAINNET.bip30DisconnectExceptionBlocks.map(
        (b) => b.height
      );
      // Connect side: the duplicate-coinbase blocks themselves (91842/91880).
      expect(connectHeights).toContain(91842);
      expect(connectHeights).toContain(91880);
      // Disconnect side: the immediately-preceding (overwritten) blocks.
      expect(disconnectHeights).toContain(91722);
      expect(disconnectHeights).toContain(91812);
      // They MUST NOT overlap — different blocks per validation.cpp comment.
      for (const dh of disconnectHeights) {
        expect(connectHeights).not.toContain(dh);
      }
    });

    test("testnet/testnet4 and signet/regtest have empty disconnect-exception list", () => {
      expect(TESTNET.bip30DisconnectExceptionBlocks.length).toBe(0);
      expect(TESTNET4.bip30DisconnectExceptionBlocks.length).toBe(0);
      expect(SIGNET.bip30DisconnectExceptionBlocks.length).toBe(0);
      expect(REGTEST.bip30DisconnectExceptionBlocks.length).toBe(0);
    });
  });

  // ── Gate #4 + #6: ApplyTxInUndo tristate ──────────────────────────────────
  describe("ApplyTxInUndo tristate (validation.cpp:2149-2175)", () => {
    test("DISCONNECT_OK when outpoint is absent (clean restore)", async () => {
      const utxo = new UTXOManager(db);
      const cache = utxo.getCoinsViewCache();
      const inputTxid = hash256(Buffer.from("input"));
      const spent: SpentUTXO = {
        txid: inputTxid,
        vout: 0,
        entry: {
          height: 42,
          coinbase: false,
          amount: 5_000_000n,
          scriptPubKey: Buffer.from([0x51 /* OP_1 */]),
        },
      };
      const result = await applyTxInUndo(spent, cache, {
        txid: inputTxid,
        vout: 0,
      });
      expect(result).toBe(DisconnectResult.DISCONNECT_OK);
      // The coin is now back in the view.
      expect(cache.haveCoinInCache({ txid: inputTxid, vout: 0 })).toBe(true);
    });

    test("DISCONNECT_UNCLEAN when outpoint already in view (overwrite)", async () => {
      const utxo = new UTXOManager(db);
      const cache = utxo.getCoinsViewCache();
      const inputTxid = hash256(Buffer.from("overwrite"));
      // Seed the cache with an existing coin at this outpoint.
      cache.addCoin(
        { txid: inputTxid, vout: 0 },
        { txOut: { value: 1n, scriptPubKey: Buffer.from([0x51]) }, height: 1, isCoinbase: false },
        false
      );
      const spent: SpentUTXO = {
        txid: inputTxid,
        vout: 0,
        entry: {
          height: 42,
          coinbase: false,
          amount: 5_000_000n,
          scriptPubKey: Buffer.from([0x51]),
        },
      };
      const result = await applyTxInUndo(spent, cache, {
        txid: inputTxid,
        vout: 0,
      });
      // Pre-W92 there was no UNCLEAN signal at all — this assertion ratifies
      // the new tristate.
      expect(result).toBe(DisconnectResult.DISCONNECT_UNCLEAN);
    });

    test("DISCONNECT_FAILED when undo.height==0 AND no sibling exists", async () => {
      const utxo = new UTXOManager(db);
      const cache = utxo.getCoinsViewCache();
      const inputTxid = hash256(Buffer.from("orphan"));
      // height=0 marks missing-metadata (Core's pre-v0.15 undo format).
      const spent: SpentUTXO = {
        txid: inputTxid,
        vout: 5,
        entry: {
          height: 0,
          coinbase: false,
          amount: 5_000_000n,
          scriptPubKey: Buffer.from([0x51]),
        },
      };
      const result = await applyTxInUndo(spent, cache, {
        txid: inputTxid,
        vout: 5,
      });
      expect(result).toBe(DisconnectResult.DISCONNECT_FAILED);
    });

    test("missing-metadata recovery via AccessByTxid sibling lookup", async () => {
      const utxo = new UTXOManager(db);
      const cache = utxo.getCoinsViewCache();
      const txid = hash256(Buffer.from("multi"));
      // Seed vout=1 as an unspent sibling carrying the height+coinbase data.
      const siblingHeight = 314;
      const siblingCoinbase = true;
      cache.addCoin(
        { txid, vout: 1 },
        {
          txOut: { value: 50n, scriptPubKey: Buffer.from([0x51]) },
          height: siblingHeight,
          isCoinbase: siblingCoinbase,
        },
        false
      );
      // Apply undo for vout=0 with height=0 (missing-metadata).
      const spent: SpentUTXO = {
        txid,
        vout: 0,
        entry: {
          height: 0,
          coinbase: false /* WILL be overridden by sibling */,
          amount: 100n,
          scriptPubKey: Buffer.from([0x51]),
        },
      };
      const result = await applyTxInUndo(spent, cache, { txid, vout: 0 });
      expect(result).toBe(DisconnectResult.DISCONNECT_OK);
      // The recovered coin should have the sibling's height + coinbase flag.
      const restored = cache.getCoinFromCache({ txid, vout: 0 });
      expect(restored).not.toBeNull();
      expect(restored!.height).toBe(siblingHeight);
      expect(restored!.isCoinbase).toBe(siblingCoinbase);
      // Value/scriptPubKey come from the undo record itself, not the sibling.
      expect(restored!.txOut.value).toBe(100n);
    });
  });

  // ── Gate #7: DisconnectResult enum exported ───────────────────────────────
  describe("DisconnectResult tristate enum (validation.h:451-456)", () => {
    test("exports OK / UNCLEAN / FAILED matching Core ordering", () => {
      expect(DisconnectResult.DISCONNECT_OK).toBe(0);
      expect(DisconnectResult.DISCONNECT_UNCLEAN).toBe(1);
      expect(DisconnectResult.DISCONNECT_FAILED).toBe(2);
    });
  });

  // ── Gate #8 + #9: undo-size consistency checks ────────────────────────────
  describe("blockUndo / block.vtx size consistency (validation.cpp:2190)", () => {
    test("disconnectBlock rejects undo files with wrong entry count", async () => {
      const chainState = new ChainStateManager(db, REGTEST);
      await chainState.load();

      // Build a block at height=1 with a coinbase + one spending tx.
      const cb = createCoinbaseTx(1, 50_00000000n);
      // Create a fake non-coinbase tx with one input.
      const fakeInputTxid = hash256(Buffer.from("input-1"));
      const spendTx: Transaction = {
        version: 1,
        inputs: [
          {
            prevOut: { txid: fakeInputTxid, vout: 0 },
            scriptSig: Buffer.alloc(71),
            sequence: 0xffffffff,
            witness: [],
          },
        ],
        outputs: [
          {
            value: 1n,
            scriptPubKey: Buffer.from([0x51]),
          },
        ],
        lockTime: 0,
      };
      const block = createBlock(REGTEST.genesisBlockHash, [cb, spendTx]);
      const blockHash = getBlockHash(block.header);

      // Pretend this block is the tip without going through connectBlock.
      // We just want to exercise the undo-size check, so we mock the state.
      (chainState as any).bestBlock = {
        hash: blockHash,
        height: 1,
        chainWork: 1n,
      };

      // Write WRONG undo data — empty buffer = 0 entries; expected = 1
      // (one for the spendTx's single input).
      const { serializeUndoData } = await import("../chain/utxo.js");
      await db.putUndoData(blockHash, serializeUndoData([]));

      await expect(chainState.disconnectBlock(block, 1)).rejects.toThrow(
        /block and undo data inconsistent/
      );
    });
  });

  // ── Gate #10: SetBestBlock(pprev) called atomically ───────────────────────
  describe("SetBestBlock(pprev) on disconnect (validation.cpp:2245)", () => {
    test("UTXO view's hashBlock is moved to pprev after disconnectBlock", async () => {
      const chainState = new ChainStateManager(db, REGTEST);
      await chainState.load();

      // Build a single block at height=1 with only a coinbase (no
      // inputs to restore, simplest case for the SetBestBlock gate).
      const cb = createCoinbaseTx(1, 50_00000000n);
      const block = createBlock(REGTEST.genesisBlockHash, [cb]);
      const blockHash = getBlockHash(block.header);

      // Inject the block into the chain state so we have a tip to disconnect.
      // We don't run full consensus checks here — we just need the UTXO
      // cache to look like it's at height=1 with the coinbase output present.
      const cbTxid = getTxId(cb);
      const utxo = (chainState as any).utxo as UTXOManager;
      utxo.addTransaction(cbTxid, cb, 1, true);
      utxo.setBestBlock(blockHash);
      (chainState as any).bestBlock = {
        hash: blockHash,
        height: 1,
        chainWork: 1n,
      };

      // Empty undo data (coinbase has no inputs to restore — but a
      // single-tx block with no spends means undo entries == 0).
      const { serializeUndoData } = await import("../chain/utxo.js");
      await db.putUndoData(blockHash, serializeUndoData([]));

      await chainState.disconnectBlock(block, 1);

      // After disconnect, the UTXO cache's best-block must be pprev = genesis.
      const newBest = await utxo.getCoinsViewCache().getBestBlock();
      expect(newBest.equals(REGTEST.genesisBlockHash)).toBe(true);
    });
  });

  // ── Gate #11: reorganize() depth cap ──────────────────────────────────────
  describe("reorganize() reorg-depth bound is gated on pruning (Core parity)", () => {
    // Helper: build a ChainStateManager whose findForkPoint is stubbed to
    // report a 400-block old chain to disconnect (deeper than the 288
    // pruned-node window).
    async function deepReorgFixture() {
      const chainState = new ChainStateManager(db, REGTEST);
      await chainState.load();
      (chainState as any).bestBlock = {
        hash: Buffer.alloc(32, 0xff),
        height: 400,
        chainWork: 1n,
      };
      const fakeOldBlocks = Array.from({ length: 400 }, (_, i) => ({
        block: createBlock(Buffer.alloc(32, i), [createCoinbaseTx(400 - i, 50n)]),
        height: 400 - i,
      }));
      (chainState as any).findForkPoint = async () => ({
        oldBlocks: fakeOldBlocks,
        newBlocks: [] as any[],
      });
      const newTip = {
        hash: Buffer.alloc(32, 0xaa),
        height: 700,
        header: createBlockHeader(Buffer.alloc(32, 0), Buffer.alloc(32, 0)),
        chainWork: 2n,
      } as any;
      return { chainState, newTip };
    }

    test("PRUNED node: rejects reorgs deeper than 288 blocks (retained undo window)", async () => {
      // On a pruned node the undo bodies beyond MIN_BLOCKS_TO_KEEP=288 have
      // been deleted, so a deeper reorg cannot be serviced and is bounded.
      const { chainState, newTip } = await deepReorgFixture();
      chainState.setPruningEnabled(true);
      await expect(
        chainState.reorganize(newTip, async () => null)
      ).rejects.toThrow(/MAX_REORG_DEPTH/);
    });

    test("ARCHIVE node (default): does NOT refuse a >288 reorg (Core has no reorg-depth cap)", async () => {
      // Core's ActivateBestChainStep follows the most-work valid chain to the
      // fork point at ANY depth; capping at 288 on an archive node is a
      // Class-A consensus divergence.  The depth check must NOT fire — the
      // reorg proceeds past the bound (and fails later only because this
      // fixture's disconnect bodies are synthetic, never with MAX_REORG_DEPTH).
      const { chainState, newTip } = await deepReorgFixture();
      // pruningEnabled defaults to false (archive).
      let threw: unknown = null;
      try {
        await chainState.reorganize(newTip, async () => null);
      } catch (e) {
        threw = e;
      }
      expect(String(threw)).not.toMatch(/MAX_REORG_DEPTH/);
    });
  });
});
