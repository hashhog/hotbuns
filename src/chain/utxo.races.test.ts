/**
 * Two CoinsViewCache races, each pinned by a test that fails on the pre-fix
 * code (48c9832) and passes with the dirty-set cache.  Only public API is
 * used so the file runs unchanged against either version.
 *
 * 1. Spent-coin resurrection: a FRESH coin that is in an in-flight
 *    batchWrite as a PUT, then spent before the write lands, was dropped
 *    from the cache without a DELETE (FRESH ⇒ "never on disk") — but the
 *    in-flight batch put it on disk.  After the next sync the spent coin is
 *    live on disk again.
 *
 * 2. Stale read overwriting a newer entry: getCoin() misses, awaits the DB,
 *    and meanwhile another path loads + spends the same outpoint.  When the
 *    first read resolves it `cache.set`s its clean copy over the spent+dirty
 *    entry: the spend is forgotten in memory (coin reads as unspent again)
 *    and the pending DELETE is never written.
 */
import { describe, expect, test } from "bun:test";
import { UTXOManager, type Coin } from "./utxo.js";
import { DBPrefix, type BatchOperation, type ChainDB, type UTXOEntry } from "../storage/database.js";
import type { OutPoint } from "../validation/tx.js";

class FakeChainDB {
  store = new Map<string, Buffer>();
  /** When set, batch() awaits it before applying. */
  batchGate: Promise<void> | null = null;
  /** When set, the NEXT getUTXO awaits it (then it is cleared). */
  nextGetGate: Promise<void> | null = null;

  async getUTXO(txid: Buffer, vout: number): Promise<UTXOEntry | null> {
    const gate = this.nextGetGate;
    this.nextGetGate = null;
    const v = this.store.get(k(txid, vout));
    if (gate) await gate;
    if (!v) return null;
    const len = v[13]!;
    return {
      height: v.readUInt32LE(0),
      coinbase: v[4] === 1,
      amount: v.readBigUInt64LE(5),
      scriptPubKey: Buffer.from(v.subarray(14, 14 + len)),
    };
  }

  async batch(ops: BatchOperation[]): Promise<void> {
    if (this.batchGate) await this.batchGate;
    for (const op of ops) {
      if (op.prefix !== DBPrefix.UTXO) continue;
      const key = op.key.toString("hex");
      if (op.type === "put") this.store.set(key, Buffer.from(op.value!));
      else this.store.delete(key);
    }
  }
}

function k(txid: Buffer, vout: number): string {
  const b = Buffer.alloc(36);
  txid.copy(b, 0);
  b.writeUInt32LE(vout, 32);
  return b.toString("hex");
}

function op(n: number): OutPoint {
  const txid = Buffer.alloc(32, 0);
  txid.writeUInt32LE(n, 0);
  return { txid, vout: 0 };
}

function coin(n: number): Coin {
  return {
    txOut: { value: BigInt(1000 + n), scriptPubKey: Buffer.from([0x00, 0x14, ...Array(20).fill(n & 0xff)]) },
    height: 100,
    isCoinbase: false,
  };
}

function gate(): { p: Promise<void>; open: () => void } {
  let open!: () => void;
  const p = new Promise<void>((r) => (open = r));
  return { p, open };
}

describe("CoinsViewCache races", () => {
  test("race 1: a FRESH coin spent while its PUT is in flight is deleted on disk, not resurrected", async () => {
    const db = new FakeChainDB();
    const m = new UTXOManager(db as unknown as ChainDB, 1 << 30);
    const c = m.getCoinsViewCache();
    c.addCoin(op(1), coin(1), false); // FRESH + DIRTY
    c.addCoin(op(2), coin(2), false);

    const g = gate();
    db.batchGate = g.p;
    const syncing = m.flushDirty(); // batch ops (PUT op1, PUT op2) are built, write pending
    await Promise.resolve();
    // ConnectBlock spends op1 while the write is in flight.
    expect(c.spendCoinSync(op(1))).toBe(true);
    g.open();
    await syncing;
    db.batchGate = null;
    await m.flushDirty(); // whatever is still pending must now reach disk

    expect(db.store.has(k(op(1).txid, 0))).toBe(false); // spent: must not be on disk
    expect(db.store.has(k(op(2).txid, 0))).toBe(true);
    // And a restart agrees.
    const restarted = new UTXOManager(db as unknown as ChainDB, 1 << 30);
    expect(await restarted.getUTXOAsync(op(1))).toBeNull();
  });

  test("race 2: a DB read that resolves late does not overwrite a newer (spent) cache entry", async () => {
    const db = new FakeChainDB();
    const seed = new UTXOManager(db as unknown as ChainDB, 1 << 30);
    seed.getCoinsViewCache().addCoin(op(7), coin(7), false);
    await seed.flushDirty();
    expect(db.store.has(k(op(7).txid, 0))).toBe(true);

    const m = new UTXOManager(db as unknown as ChainDB, 1 << 30);
    const c = m.getCoinsViewCache();

    const g = gate();
    db.nextGetGate = g.p;
    const slowRead = c.getCoin(op(7)); // reads the DB value, then stalls
    // Another loader of the same outpoint completes, and the coin is spent.
    expect(await c.getCoin(op(7))).not.toBeNull();
    expect(c.spendCoinSync(op(7))).toBe(true);
    expect(c.haveCoinInCache(op(7))).toBe(false);

    g.open();
    await slowRead; // the stale clean copy arrives

    // The spend must survive in memory...
    expect(c.haveCoinInCache(op(7))).toBe(false);
    expect(await c.haveCoin(op(7))).toBe(false);
    // ...and on disk.
    await m.flushDirty();
    expect(db.store.has(k(op(7).txid, 0))).toBe(false);
  });
});
