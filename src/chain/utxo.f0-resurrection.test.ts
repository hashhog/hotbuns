/**
 * F0 — coin-cache RESURRECTION (invariant I5, receipts/arch-f6-f7-design-2026-10-05.md).
 *
 * A populate-after-miss read (`getCoin` / `spendCoin` / `haveCoin` missing the
 * cache) issues a LevelDB read and awaits it.  While it is in flight the
 * connect path loads the same coin, spends it, and `sync()`/`flush()` commits
 * the DELETE and then drops the spent entry from the cache.  On 625795c the
 * read's continuation re-checks only "is there a cache entry now?" — there is
 * none any more — so it installs its PRE-DELETE copy as a CLEAN unspent coin.
 * The next block spending that coin again then finds it in the cache.
 *
 * Core: CCoinsViewCache::FetchCoin (coins.cpp:69-82) runs under cs_main, so a
 * base read can never straddle a BatchWrite; a spent coin is DIRTY until
 * written and is then gone from both cache and DB.  The equivalent rule for an
 * async cache: a DB result may be installed (or returned) only if no coins-DB
 * write committed since the read was issued; otherwise read again.
 *
 * Only the public API is used, so the file runs against 625795c and the fix.
 */
import { describe, expect, test } from "bun:test";
import { UTXOManager, type Coin } from "./utxo.js";
import { DBPrefix, type BatchOperation, type ChainDB, type UTXOEntry } from "../storage/database.js";
import type { OutPoint } from "../validation/tx.js";

class FakeChainDB {
  store = new Map<string, Buffer>();
  /** When set, the NEXT getUTXO reads its value immediately, then awaits this
   *  gate before returning — i.e. a read that has hit the disk but whose
   *  continuation has not run yet. */
  nextGetGate: Promise<void> | null = null;
  gatedReadIssued = false;

  async getUTXO(txid: Buffer, vout: number): Promise<UTXOEntry | null> {
    const gate = this.nextGetGate;
    this.nextGetGate = null;
    const v = this.store.get(k(txid, vout));
    if (gate) {
      this.gatedReadIssued = true;
      await gate;
    }
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

/** X on disk, a fresh (cold) manager over it. */
async function setup(n: number) {
  const db = new FakeChainDB();
  const seed = new UTXOManager(db as unknown as ChainDB, 1 << 30);
  seed.getCoinsViewCache().addCoin(op(n), coin(n), false);
  await seed.flushDirty();
  expect(db.store.has(k(op(n).txid, 0))).toBe(true);
  const m = new UTXOManager(db as unknown as ChainDB, 1 << 30);
  return { db, m, c: m.getCoinsViewCache() };
}

/** The connect path: load X, spend it, commit (sync or full flush). */
async function connectSpendAndCommit(m: UTXOManager, n: number, full: boolean) {
  const c = m.getCoinsViewCache();
  expect(await c.getCoin(op(n))).not.toBeNull();
  expect(c.spendCoinSync(op(n))).toBe(true);
  if (full) await m.flush();
  else await m.flushDirty();
}

describe("F0: a DB read that straddles a committed spend must not resurrect the coin (I5)", () => {
  for (const full of [false, true]) {
    const how = full ? "flush()" : "sync()";
    test(`getCoin: read issued, spend + ${how} commit the delete, read completes → coin NOT installed`, async () => {
      const { db, m, c } = await setup(11);
      const g = gate();
      db.nextGetGate = g.p;
      const reader = c.getCoin(op(11)); // RPC gettxout / mempool reader misses
      await Promise.resolve();
      expect(db.gatedReadIssued).toBe(true);

      await connectSpendAndCommit(m, 11, full);
      expect(db.store.has(k(op(11).txid, 0))).toBe(false); // delete is on disk

      g.open();
      const seen = await reader;
      // The reader must not report (or install) a coin that is spent and gone.
      expect(seen).toBeNull();
      expect(c.haveCoinInCache(op(11))).toBe(false);
      // The next block's spend of X must fail.
      expect(await c.spendCoin(op(11))).toBe(false);
      await m.flushDirty();
      expect(db.store.has(k(op(11).txid, 0))).toBe(false);
    });
  }

  test("spendCoin: a miss-read straddling a committed spend must not spend the coin a second time", async () => {
    const { db, m, c } = await setup(12);
    const g = gate();
    db.nextGetGate = g.p;
    const second = c.spendCoin(op(12)); // second spender misses the cache
    await Promise.resolve();
    expect(db.gatedReadIssued).toBe(true);

    await connectSpendAndCommit(m, 12, false);

    g.open();
    expect(await second).toBe(false);
    expect(c.haveCoinInCache(op(12))).toBe(false);
  });

  test("haveCoin: a miss-read straddling a committed spend reports the coin gone", async () => {
    const { db, m, c } = await setup(13);
    const g = gate();
    db.nextGetGate = g.p;
    const probe = c.haveCoin(op(13));
    await Promise.resolve();
    expect(db.gatedReadIssued).toBe(true);

    await connectSpendAndCommit(m, 13, false);

    g.open();
    expect(await probe).toBe(false);
  });

  test("control: with no straddling write the read installs the coin clean (read-through still works)", async () => {
    const { db, c } = await setup(14);
    const g = gate();
    db.nextGetGate = g.p;
    const reader = c.getCoin(op(14));
    await Promise.resolve();
    g.open();
    expect(await reader).not.toBeNull();
    expect(c.haveCoinInCache(op(14))).toBe(true);
    expect(c.getDirtyCount()).toBe(0);
    c.debugCheckInvariants();
  });
});
