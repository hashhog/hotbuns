/**
 * verify-neon-hotbuns-findings, Neon finding 15 (consensus, chain-state path).
 *
 * Core's ConnectBlock works on a temporary CCoinsViewCache that is thrown away
 * when any check fails. ChainStateManager.connectBlock spent inputs and added
 * outputs in its own UTXO cache and left them there on failure, so the next
 * block saw the failed block's spends (false reject of a valid sibling: its
 * inputs look spent, its coinbase trips BIP-30) and its outputs (false accept
 * of a spend of a coin that never existed). Callers: --import-blocks (tries
 * the next sibling after a failure), generateblock fallback, dumptxoutset
 * re-apply, reorganize().
 */

import { describe, test, expect, beforeEach, afterEach } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ChainDB } from "../storage/database.js";
import { REGTEST } from "../consensus/params.js";
import { ChainStateManager } from "../chain/state.js";
import type { Block, BlockHeader } from "../validation/block.js";
import { getBlockHash } from "../validation/block.js";
import { getTxId } from "../validation/tx.js";
import type { Transaction } from "../validation/tx.js";
import { hash256 } from "../crypto/primitives.js";

const COIN = 100_000_000n;
const OP_TRUE_SPK = Buffer.from([0x51]);

function coinbase(height: number, value: bigint): Transaction {
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
    outputs: [{ value, scriptPubKey: OP_TRUE_SPK }],
    lockTime: 0,
  };
}

function spend(prev: { txid: Buffer; vout: number }[], outValue: bigint, tag = 0): Transaction {
  return {
    version: 1,
    inputs: prev.map((p) => ({
      prevOut: p,
      scriptSig: Buffer.alloc(0),
      sequence: 0xffffffff,
      witness: [],
    })),
    // `tag` makes otherwise identical spends distinct txids.
    outputs: [{ value: outValue, scriptPubKey: OP_TRUE_SPK }],
    lockTime: tag,
  };
}

function merkleRoot(txs: Transaction[]): Buffer {
  let level: Buffer[] = txs.map((t) => Buffer.from(getTxId(t)));
  while (level.length > 1) {
    const next: Buffer[] = [];
    for (let i = 0; i < level.length; i += 2) {
      const r = i + 1 < level.length ? level[i + 1] : level[i];
      next.push(hash256(Buffer.concat([level[i], r])));
    }
    level = next;
  }
  return level[0];
}

function block(prev: Buffer, txs: Transaction[], timestamp: number): Block {
  const header: BlockHeader = {
    version: 0x20000000,
    prevBlock: prev,
    merkleRoot: merkleRoot(txs),
    timestamp,
    bits: REGTEST.powLimitBits,
    nonce: 0,
  };
  return { header, transactions: txs };
}

// ── F15 ─────────────────────────────────────────────────────────────────────
describe("F15: a failed ChainStateManager.connectBlock leaves no UTXO changes behind", () => {
  let dir: string;
  let db: ChainDB;
  let cs: ChainStateManager;
  let u: { txid: Buffer; vout: number };

  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "hotbuns-neon-f15-"));
    db = new ChainDB(dir);
    await db.open();
    cs = new ChainStateManager(db, REGTEST);
    await cs.load();
    // Block 1 (coinbase only) so the tip is not genesis.
    const b1 = block(REGTEST.genesisBlockHash, [coinbase(1, 50n * COIN)], 1_700_000_000);
    await cs.connectBlock(b1, 1);
    // A mature, spendable OP_TRUE coin U, persisted.
    const txid = hash256(Buffer.from("neon-f15-U"));
    u = { txid, vout: 0 };
    const um = cs.getUTXOManager();
    um.getCoinsViewCache().addCoin(
      u,
      { txOut: { value: 10n * COIN, scriptPubKey: OP_TRUE_SPK }, height: 1, isCoinbase: false },
      false,
    );
    await um.flush();
  });
  afterEach(async () => {
    await db.close();
    await rm(dir, { recursive: true, force: true });
  });

  /**
   * Block 2 candidate: tx1 spends U and creates X, then tx2 spends a coin that
   * does not exist, so the block fails after tx1 was applied to the view.
   */
  function badBlock(prev: Buffer): { b: Block; tx1: Transaction } {
    const tx1 = spend([u], 10n * COIN - 1000n);
    const tx2 = spend([{ txid: hash256(Buffer.from("neon-f15-missing")), vout: 0 }], 1000n);
    return { b: block(prev, [coinbase(2, 50n * COIN), tx1, tx2], 1_700_000_100), tx1 };
  }

  test("F15 a valid sibling spending the same coin connects after a failed block", async () => {
    const tip = cs.getBestBlock().hash;
    const { b: bad } = badBlock(tip);
    await expect(cs.connectBlock(bad, 2)).rejects.toThrow("bad-txns-inputs-missingorspent");

    // A different coinbase, so only the spend of U is shared with the failed block.
    const good = block(tip, [coinbase(2, 49n * COIN), spend([u], 10n * COIN - 500n, 7)], 1_700_000_200);
    await cs.connectBlock(good, 2);
    expect(Buffer.from(cs.getBestBlock().hash).equals(getBlockHash(good.header))).toBe(true);
  });

  test("F15 a valid sibling with the same coinbase as the failed block is not a BIP-30 overwrite", async () => {
    const tip = cs.getBestBlock().hash;
    const { b: bad } = badBlock(tip);
    await expect(cs.connectBlock(bad, 2)).rejects.toThrow("bad-txns-inputs-missingorspent");

    // The failed block's coinbase never entered the UTXO set in Core.
    const good = block(tip, [coinbase(2, 50n * COIN)], 1_700_000_200);
    await cs.connectBlock(good, 2);
    expect(Buffer.from(cs.getBestBlock().hash).equals(getBlockHash(good.header))).toBe(true);
  });

  test("F15 an output created only by the failed block cannot be spent afterwards", async () => {
    const tip = cs.getBestBlock().hash;
    const { b: bad, tx1 } = badBlock(tip);
    await expect(cs.connectBlock(bad, 2)).rejects.toThrow("bad-txns-inputs-missingorspent");

    const phantom = block(
      tip,
      [coinbase(2, 49n * COIN), spend([{ txid: getTxId(tx1), vout: 0 }], 1000n, 9)],
      1_700_000_200,
    );
    await expect(cs.connectBlock(phantom, 2)).rejects.toThrow("bad-txns-inputs-missingorspent");
    expect(await cs.getUTXOManager().hasUTXOAsync(u)).toBe(true);
  });
});
