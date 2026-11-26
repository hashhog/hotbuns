/**
 * verify-neon-hotbuns-findings, Neon finding 11 (consensus).
 *
 * The input-value MoneyRange check is PER TRANSACTION in Core
 * (consensus/tx_verify.cpp CheckTxInputs: nValueIn is a local). hotbuns summed
 * every input of every tx in the block and range-checked that sum, so a valid
 * block whose chained transactions move more than 21M BTC in total was
 * rejected with bad-txns-inputvalues-outofrange: a chain split on any network.
 */

import { describe, test, expect, beforeEach, afterEach } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ChainDB } from "../storage/database.js";
import { REGTEST } from "../consensus/params.js";
import { UTXOManager } from "../chain/utxo.js";
import { coreConnectBlockChecks } from "../consensus/connect_block.js";
import type { Block, BlockHeader } from "../validation/block.js";
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

// ── F11 ─────────────────────────────────────────────────────────────────────
describe("F11: input MoneyRange is per transaction (CheckTxInputs), not per block", () => {
  let dir: string;
  let db: ChainDB;
  let utxo: UTXOManager;

  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "hotbuns-neon-f11-"));
    db = new ChainDB(dir);
    await db.open();
    utxo = new UTXOManager(db);
  });
  afterEach(async () => {
    await db.close();
    await rm(dir, { recursive: true, force: true });
  });

  function seed(tag: string, value: bigint): { txid: Buffer; vout: number } {
    const txid = hash256(Buffer.from(tag));
    utxo.getCoinsViewCache().addCoin(
      { txid, vout: 0 },
      { txOut: { value, scriptPubKey: OP_TRUE_SPK }, height: 1, isCoinbase: false },
      false,
    );
    return { txid, vout: 0 };
  }

  test("F11 chained txs moving > 21M BTC in total are accepted (Core accepts)", async () => {
    const u = seed("neon-f11-chain", 15_000_000n * COIN);
    const tx1 = spend([u], 15_000_000n * COIN - 1000n);
    const tx2 = spend([{ txid: getTxId(tx1), vout: 0 }], 15_000_000n * COIN - 2000n);
    const b = block(Buffer.alloc(32, 0), [coinbase(10, 50n * COIN), tx1, tx2], 1_700_000_000);

    const r = await coreConnectBlockChecks(b, 10, utxo, REGTEST, { skipScripts: true });
    if (!r.ok) throw new Error(`rejected: ${r.error}`);
    expect(r.ok).toBe(true);
  });

  test("F11 control: one tx whose own inputs sum > MAX_MONEY is still rejected", async () => {
    const a = seed("neon-f11-a", 15_000_000n * COIN);
    const c = seed("neon-f11-b", 15_000_000n * COIN);
    const tx = spend([a, c], 1000n);
    const b = block(Buffer.alloc(32, 0), [coinbase(10, 50n * COIN), tx], 1_700_000_000);

    const r = await coreConnectBlockChecks(b, 10, utxo, REGTEST, { skipScripts: true });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toContain("bad-txns-inputvalues-outofrange");
  });
});
