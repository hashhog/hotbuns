/**
 * Regression test for the assumevalid SCOPE fix (#3 cluster).
 *
 * Before the fix, coreConnectBlockChecks had a height-driven "assume-valid fast
 * path" that, when assumeValid=true, skipped coinbase maturity, BIP-68, sigops
 * AND per-tx value checks — far more than Core's fScriptChecks=false, which
 * skips ONLY signature/script verification. This let a block in the assumevalid
 * window spend an IMMATURE coinbase (and worse) without rejection.
 *
 * The fast path was removed: every block now runs the full validation path and
 * only `skipScripts` gates signature verification. This test asserts that an
 * immature-coinbase spend under assumeValid=true is now REJECTED (it would have
 * been accepted by the deleted fast path).
 */
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, test, beforeEach, afterEach } from "bun:test";

import { ChainDB } from "../storage/database.js";
import { UTXOManager } from "../chain/utxo.js";
import { REGTEST } from "../consensus/params.js";
import { coreConnectBlockChecks } from "../consensus/connect_block.js";
import type { Block, BlockHeader } from "../validation/block.js";
import type { Transaction } from "../validation/tx.js";
import { getTxId } from "../validation/tx.js";
import { hash256 } from "../crypto/primitives.js";

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
    outputs: [{ value, scriptPubKey: Buffer.from([0x51]) /* OP_1 (anyone-can-spend) */ }],
    lockTime: 0,
  };
}

function makeSpend(prevTxid: Buffer, vout: number, value: bigint): Transaction {
  return {
    version: 1,
    inputs: [{ prevOut: { txid: prevTxid, vout }, scriptSig: Buffer.from([]), sequence: 0xffffffff, witness: [] }],
    outputs: [{ value, scriptPubKey: Buffer.from([0x51]) }],
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

describe("assumevalid SCOPE — fast-path deletion still enforces non-script checks", () => {
  let tempDir: string;
  let db: ChainDB;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "hotbuns-av-scope-"));
    db = new ChainDB(tempDir);
    await db.open();
  });
  afterEach(async () => {
    await db.close();
    await rm(tempDir, { recursive: true, force: true });
  });

  test("immature-coinbase spend under assumeValid=true is REJECTED (was accepted by the fast path)", async () => {
    const utxo = new UTXOManager(db);

    // A coinbase mined at height 100.
    const cbHeight = 100;
    const coinbase = makeCoinbase(cbHeight, 50_00000000n);
    const cbTxid = getTxId(coinbase);
    utxo.addTransaction(cbTxid, coinbase, cbHeight, /*isCoinbase*/ true);

    // A block at height 150 — only 50 confirmations, BELOW the 100-block
    // coinbase maturity — whose non-coinbase tx spends that coinbase output.
    const spendHeight = 150;
    const blockCoinbase = makeCoinbase(spendHeight, 50_00000000n);
    const spend = makeSpend(cbTxid, 0, 49_00000000n);
    const block = makeBlock(Buffer.alloc(32, 0x11), [blockCoinbase, spend]);

    // assumeValid=true (would have taken the deleted fast path) AND
    // skipScripts=true (Core only skips signatures). Maturity must STILL fire.
    const result = await coreConnectBlockChecks(block, spendHeight, utxo, REGTEST, {
      assumeValid: true,
      skipScripts: true,
    });

    expect(result.ok).toBe(false);
    // Maturity is now enforced even under assumeValid (the deleted fast path
    // skipped it). hotbuns' canonical message for an immature coinbase spend:
    expect((result as { error: string }).error).toContain("Immature coinbase spend");
  });
});
