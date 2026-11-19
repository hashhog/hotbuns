/**
 * cffix-hotbuns-atmp-serialize: AcceptToMemoryPool must be atomic.
 *
 * Core runs MemPoolAccept::AcceptSingleTransaction (and the package paths)
 * under LOCK(cs_main) + LOCK(m_pool.cs), so the duplicate / conflict checks
 * and the insert can never interleave with another accept. hotbuns'
 * addTransaction is async: it checks conflicts, then awaits
 * utxo.getUTXOAsync, then inserts without re-checking. Two concurrent calls
 * that spend the same outpoint both passed the conflict check and both got
 * inserted: two double-spending txs in the mempool, and any block template
 * built from it is invalid.
 */

import { describe, test, expect, beforeEach, afterEach } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ChainDB, type UTXOEntry } from "../storage/database.js";
import { UTXOManager } from "../chain/utxo.js";
import { REGTEST } from "../consensus/params.js";
import { Mempool } from "../mempool/mempool.js";
import type { Transaction, OutPoint } from "../validation/tx.js";
import { getTxId } from "../validation/tx.js";

// P2A anchor: standard, spendable with empty scriptSig + witness.
const P2A = Buffer.from([0x51, 0x02, 0x4e, 0x73]);

function spend(txid: Buffer, vout: number, value: bigint): Transaction {
  return {
    version: 2,
    inputs: [
      {
        prevOut: { txid, vout },
        scriptSig: Buffer.alloc(0),
        sequence: 0xffffffff,
        witness: [],
      },
    ],
    outputs: [
      { value, scriptPubKey: P2A },
      // OP_RETURN pad: keeps the non-witness size >= 65 bytes.
      { value: 0n, scriptPubKey: Buffer.from([0x6a]) },
    ],
    lockTime: 0,
  };
}

describe("cffix-hotbuns-atmp-serialize", () => {
  let tempDir: string;
  let db: ChainDB;
  let utxo: UTXOManager;
  let mempool: Mempool;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "cffix-atmp-serialize-"));
    db = new ChainDB(tempDir);
    await db.open();
    utxo = new UTXOManager(db);
    // Make every coin lookup yield to the event loop, so a second accept can
    // run while the first is suspended between its conflict check and insert.
    const orig = utxo.getUTXOAsync.bind(utxo);
    (utxo as any).getUTXOAsync = async (op: OutPoint) => {
      await Promise.resolve();
      await new Promise((r) => setTimeout(r, 0));
      return orig(op);
    };
    mempool = new Mempool(utxo, REGTEST, 1_000_000);
    mempool.setTipHeight(200);
  });

  afterEach(async () => {
    await db.close();
    await rm(tempDir, { recursive: true, force: true });
  });

  async function fund(fill: number, amount: bigint): Promise<Buffer> {
    const txid = Buffer.alloc(32, fill);
    const entry: UTXOEntry = { height: 1, coinbase: false, amount, scriptPubKey: P2A };
    await db.putUTXO(txid, 0, entry);
    return txid;
  }

  function spendersOf(txid: Buffer, vout: number): string[] {
    const out: string[] = [];
    for (const id of mempool.getAllTxids()) {
      const e = mempool.getTransaction(id)!;
      for (const inp of e.tx.inputs) {
        if (inp.prevOut.txid.equals(txid) && inp.prevOut.vout === vout) {
          out.push(getTxId(e.tx).toString("hex"));
        }
      }
    }
    return out;
  }

  test("concurrent acceptToMemoryPool of two spends of one outpoint admits exactly one", async () => {
    const funding = await fund(0xa1, 10_000n);
    const txA = spend(funding, 0, 9_000n); // 1000 sat fee
    const txB = spend(funding, 0, 9_500n); // 500 sat fee: cannot RBF txA

    const [ra, rb] = await Promise.all([
      mempool.acceptToMemoryPool(txA),
      mempool.acceptToMemoryPool(txB),
    ]);

    const accepted = [ra, rb].filter((r) => r.accepted).length;
    expect(accepted).toBe(1);
    expect(ra.accepted).toBe(true);
    expect(rb.accepted).toBe(false);
    expect(spendersOf(funding, 0)).toEqual([getTxId(txA).toString("hex")]);
  });

  test("many concurrent spends of one outpoint leave a single spender", async () => {
    const funding = await fund(0xa2, 100_000n);
    // Strictly decreasing fees: the first one wins, each later one is a
    // lower-fee conflict and must be refused.
    const txs = [0, 1, 2, 3, 4].map((i) => spend(funding, 0, 90_000n + BigInt(i) * 1_000n));

    const results = await Promise.all(txs.map((t) => mempool.acceptToMemoryPool(t)));

    expect(results.filter((r) => r.accepted).length).toBe(1);
    expect(spendersOf(funding, 0).length).toBe(1);
  });

  test("concurrent single accept and submitPackage cannot both spend one outpoint", async () => {
    const funding = await fund(0xa3, 10_000n);
    const txA = spend(funding, 0, 9_000n);
    const txB = spend(funding, 0, 9_500n);

    const [ra, pkg] = await Promise.all([
      mempool.acceptToMemoryPool(txA),
      mempool.submitPackage([txB]),
    ]);

    const pkgAccepted = [...pkg.txResults.values()].filter((r) => r.accepted).length;
    expect((ra.accepted ? 1 : 0) + pkgAccepted).toBe(1);
    expect(spendersOf(funding, 0).length).toBe(1);
  });

  test("an accept that throws does not wedge the next one", async () => {
    const funding = await fund(0xa4, 10_000n);
    const orig = (utxo as any).getUTXOAsync;
    let failNext = true;
    (utxo as any).getUTXOAsync = async (op: OutPoint) => {
      if (failNext) {
        failNext = false;
        throw new Error("injected coin-view failure");
      }
      return orig(op);
    };

    const first = mempool.acceptToMemoryPool(spend(funding, 0, 9_000n));
    const second = mempool.acceptToMemoryPool(spend(funding, 0, 8_000n));
    await expect(first).rejects.toThrow("injected coin-view failure");
    const r2 = await second;
    expect(r2.accepted).toBe(true);
    expect(spendersOf(funding, 0).length).toBe(1);
  });
});
