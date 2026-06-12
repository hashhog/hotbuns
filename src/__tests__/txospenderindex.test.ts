/**
 * Tests for the txospenderindex (Bitcoin Core -txospenderindex parity) and the
 * gettxspendingprevout RPC.
 *
 * Covers, against a REAL ClassicLevel-backed ChainDB:
 *  - connect(block) writes spent-outpoint -> spending-tx records; findSpender
 *    returns the spending tx + confirming block hash.
 *  - disconnect(block) RE-DERIVES the keys from the block's OWN inputs and
 *    erases them (the single unified removeBlock(block, height) the invalidate-
 *    block path AND the live-reorg path both call) — proving the reorg erase.
 *  - default-off: a disabled index never writes and findSpender returns null
 *    (falsification: the pre-index node cannot answer the confirmed-spend path).
 *  - genesis (height 0) is a no-op (coinbase-only, null prevout).
 *
 * The full daemon LIVE-REORG erase (heavier branch orphans B) is proven by the
 * regtest harness (CORE-PARITY-AUDIT/_hotbuns-txospender-regtest-proof). This
 * unit test pins the index + RPC semantics in-process (no slot needed).
 *
 * References: bitcoin-core/src/index/txospenderindex.{h,cpp},
 *             bitcoin-core/src/rpc/mempool.cpp::gettxspendingprevout.
 */

import { describe, it, expect, beforeEach, afterEach } from "bun:test";
import { mkdtemp, rm } from "fs/promises";
import { tmpdir } from "os";
import { join } from "path";
import { ChainDB } from "../storage/database.js";
import { TxoSpenderIndex } from "../storage/indexes.js";
import type { Block } from "../validation/block.js";
import { getBlockHash } from "../validation/block.js";
import type { Transaction } from "../validation/tx.js";
import { getTxId } from "../validation/tx.js";

// ---------------------------------------------------------------------------
// Block / tx builders
// ---------------------------------------------------------------------------

function coinbaseTx(height: number): Transaction {
  return {
    version: 1,
    inputs: [
      {
        prevOut: { txid: Buffer.alloc(32, 0), vout: 0xffffffff },
        scriptSig: Buffer.from([height & 0xff, (height >> 8) & 0xff]),
        sequence: 0xffffffff,
        witness: [],
      },
    ],
    outputs: [{ value: 5000000000n, scriptPubKey: Buffer.from([0x51]) }],
    lockTime: 0,
  };
}

// tx B spends (prevTxid:prevVout).
function spendTx(prevTxid: Buffer, prevVout: number, tag: number): Transaction {
  return {
    version: 2,
    inputs: [
      {
        prevOut: { txid: prevTxid, vout: prevVout },
        scriptSig: Buffer.from([tag & 0xff]),
        sequence: 0xffffffff,
        witness: [],
      },
    ],
    outputs: [
      { value: 4999990000n, scriptPubKey: Buffer.from([0x76, 0xa9, 0x14, ...Buffer.alloc(20, tag), 0x88, 0xac]) },
    ],
    lockTime: 0,
  };
}

function block(prevBlock: Buffer, txs: Transaction[], nonce: number): Block {
  return {
    header: {
      version: 0x20000000,
      prevBlock,
      merkleRoot: Buffer.alloc(32, nonce & 0xff),
      timestamp: 1700000000 + nonce,
      bits: 0x207fffff,
      nonce,
    },
    transactions: txs,
  };
}

describe("TxoSpenderIndex", () => {
  let dbPath: string;
  let db: ChainDB;

  beforeEach(async () => {
    dbPath = await mkdtemp(join(tmpdir(), "hotbuns-txospender-"));
    db = new ChainDB(dbPath);
    await db.open();
  });

  afterEach(async () => {
    await db.close();
    await rm(dbPath, { recursive: true, force: true });
  });

  it("connect writes spend records; findSpender returns spender + block hash", async () => {
    const idx = new TxoSpenderIndex(db, true);
    await idx.init();

    // tx A is funded by some prior outpoint; tx B spends A:0.
    const aTxid = Buffer.alloc(32, 0xaa); // outpoint A being spent below is aTxid:0
    const b = spendTx(aTxid, 0, 0x42);
    const blk = block(Buffer.alloc(32, 0x11), [coinbaseTx(1), b], 1);
    const blkHash = getBlockHash(blk.header);

    await idx.indexBlock(blk, 1);
    expect(idx.getHeight()).toBe(1);

    const found = await idx.findSpender(aTxid, 0);
    expect(found).not.toBeNull();
    expect(found!.spendingTxid.equals(getTxId(b))).toBe(true);
    expect(found!.blockHash.equals(blkHash)).toBe(true);
    expect(found!.spendingTxHex.length).toBeGreaterThan(0);

    // An unspent outpoint -> null.
    expect(await idx.findSpender(aTxid, 9)).toBeNull();
  });

  it("disconnect re-derives keys from the block's own inputs and erases them (reorg undo)", async () => {
    const idx = new TxoSpenderIndex(db, true);
    await idx.init();

    const aTxid = Buffer.alloc(32, 0xbb);
    const b = spendTx(aTxid, 0, 0x7);
    const blk = block(Buffer.alloc(32, 0x22), [coinbaseTx(1), b], 2);

    await idx.indexBlock(blk, 1);
    expect(await idx.findSpender(aTxid, 0)).not.toBeNull();

    // The SAME removeBlock(block, height) call both the invalidateblock path
    // (ChainStateManager.disconnectBlock) and the LIVE reorg path
    // (BlockSync.disconnectBlockUtxo) invoke.
    await idx.removeBlock(blk, 1);
    expect(await idx.findSpender(aTxid, 0)).toBeNull();
    expect(idx.getHeight()).toBe(0);
  });

  it("a LIVE-reorg sequence (disconnect B's branch, connect heavier branch) erases A:0", async () => {
    const idx = new TxoSpenderIndex(db, true);
    await idx.init();
    await idx.ensureGenesisIndexed();

    const aTxid = Buffer.alloc(32, 0xcc);
    const b = spendTx(aTxid, 0, 0x1); // B spends A:0 on the original branch
    const branch1 = block(Buffer.alloc(32, 0x33), [coinbaseTx(1), b], 10);
    await idx.indexBlock(branch1, 1);
    expect(await idx.findSpender(aTxid, 0)).not.toBeNull();

    // Heavier branch orphans B: disconnect branch1, then connect a competing
    // block at the same height that does NOT spend A:0.
    await idx.removeBlock(branch1, 1);
    const branch2 = block(Buffer.alloc(32, 0x33), [coinbaseTx(1)], 11);
    await idx.indexBlock(branch2, 1);

    // A:0 is now unspent on the active chain — the index erased it.
    expect(await idx.findSpender(aTxid, 0)).toBeNull();
    expect(idx.getHeight()).toBe(1);
  });

  it("disabled index never writes and findSpender returns null (default-off falsification)", async () => {
    const idx = new TxoSpenderIndex(db, false);
    await idx.init();

    const aTxid = Buffer.alloc(32, 0xdd);
    const blk = block(Buffer.alloc(32, 0x44), [coinbaseTx(1), spendTx(aTxid, 0, 0x9)], 3);
    await idx.indexBlock(blk, 1);

    expect(idx.isEnabled()).toBe(false);
    expect(await idx.findSpender(aTxid, 0)).toBeNull();
  });

  it("genesis (height 0) is a no-op (coinbase-only, null prevout)", async () => {
    const idx = new TxoSpenderIndex(db, true);
    await idx.init();
    const g = block(Buffer.alloc(32, 0), [coinbaseTx(0)], 0);
    await idx.indexBlock(g, 0);
    expect(idx.getHeight()).toBe(0);
    // Null prevout is never indexed.
    expect(await idx.findSpender(Buffer.alloc(32, 0), 0xffffffff)).toBeNull();
  });
});
