/**
 * CoinsViewCache dirty-set flush + eviction: the UTXO set must be identical
 * after any sequence of add / spend / restore / sync / flush / evict /
 * restart, and a sync must write exactly the modified coins in ONE batch
 * together with the caller's chain-state ops.
 *
 * A fake ChainDB (in-memory store, records every batch) gives exact write
 * counts; one test repeats the restart check on a real LevelDB ChainDB.
 */
import { describe, expect, test } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  CACHE_ENTRY_OVERHEAD,
  CoinsViewCache,
  CoinsViewDB,
  EVICT_TARGET_FRACTION,
  UTXOManager,
  coinMemoryUsage,
  type Coin,
} from "./utxo.js";
import {
  ChainDB,
  DBPrefix,
  type BatchOperation,
  type UTXOEntry,
} from "../storage/database.js";
import type { OutPoint } from "../validation/tx.js";

// ── fake ChainDB ────────────────────────────────────────────────────────────

function decodeCoinValue(v: Buffer): UTXOEntry {
  const height = v.readUInt32LE(0);
  const coinbase = v[4] === 1;
  const amount = v.readBigUInt64LE(5);
  let pos = 13;
  let len = v[pos++]!;
  if (len === 0xfd) {
    len = v.readUInt16LE(pos);
    pos += 2;
  } else if (len === 0xfe) {
    len = v.readUInt32LE(pos);
    pos += 4;
  }
  return { height, coinbase, amount, scriptPubKey: Buffer.from(v.subarray(pos, pos + len)) };
}

class FakeChainDB {
  /** hex(36-byte utxo key) -> serialized coin */
  store = new Map<string, Buffer>();
  /** Non-UTXO ops (chain state etc), last value per prefix:key. */
  meta = new Map<string, Buffer>();
  batches: BatchOperation[][] = [];
  gets = 0;
  /** When set, batch() awaits this before applying (to open a race window). */
  gate: Promise<void> | null = null;

  async getUTXO(txid: Buffer, vout: number): Promise<UTXOEntry | null> {
    this.gets++;
    const k = Buffer.alloc(36);
    txid.copy(k, 0);
    k.writeUInt32LE(vout, 32);
    const v = this.store.get(k.toString("hex"));
    return v ? decodeCoinValue(v) : null;
  }

  async batch(ops: BatchOperation[]): Promise<void> {
    this.batches.push(ops);
    if (this.gate) await this.gate;
    for (const op of ops) {
      if (op.prefix === DBPrefix.UTXO) {
        const k = op.key.toString("hex");
        if (op.type === "put") this.store.set(k, Buffer.from(op.value!));
        else this.store.delete(k);
      } else {
        const k = `${op.prefix}:${op.key.toString("hex")}`;
        if (op.type === "put") this.meta.set(k, Buffer.from(op.value!));
        else this.meta.delete(k);
      }
    }
  }
}

// ── helpers ─────────────────────────────────────────────────────────────────

function op(n: number, vout = 0): OutPoint {
  const txid = Buffer.alloc(32, 0);
  txid.writeUInt32LE(n, 0);
  txid.writeUInt32LE(0xc0ffee, 28);
  return { txid, vout };
}

function coin(n: number, height = 100 + (n % 50)): Coin {
  // P2WPKH-shaped, value derived from n so a wrong coin is detectable.
  const spk = Buffer.alloc(22, n & 0xff);
  spk[0] = 0x00;
  spk[1] = 0x14;
  return { txOut: { value: BigInt(1000 + n), scriptPubKey: spk }, height, isCoinbase: n % 7 === 0 };
}

function keyOf(o: OutPoint): string {
  const k = Buffer.alloc(36);
  o.txid.copy(k, 0);
  k.writeUInt32LE(o.vout, 32);
  return k.toString("hex");
}

function sameCoin(a: UTXOEntry | Coin | null, b: Coin | null): boolean {
  if (a === null || b === null) return a === b;
  const av = "amount" in a ? a.amount : a.txOut.value;
  const as = "amount" in a ? a.scriptPubKey : a.txOut.scriptPubKey;
  const ah = a.height;
  const ac = "amount" in a ? a.coinbase : a.isCoinbase;
  return av === b.txOut.value && as.equals(b.txOut.scriptPubKey) && ah === b.height && ac === b.isCoinbase;
}

/** Store content must equal the model exactly (same key set, same coins). */
function expectStoreEquals(fake: FakeChainDB, model: Map<string, Coin>): void {
  expect(fake.store.size).toBe(model.size);
  for (const [k, c] of model) {
    const v = fake.store.get(k);
    expect(v).toBeDefined();
    expect(sameCoin(decodeCoinValue(v!), c)).toBe(true);
  }
}

function newManager(fake: FakeChainDB, budget = 1 << 30): UTXOManager {
  return new UTXOManager(fake as unknown as ChainDB, budget);
}

const chainStateOp = (tag: number): BatchOperation => ({
  type: "put",
  prefix: DBPrefix.CHAIN_STATE,
  key: Buffer.alloc(0),
  value: Buffer.from([tag]),
});

// ── tests ───────────────────────────────────────────────────────────────────

describe("dirty-set sync writes exactly the modified coins", () => {
  test("puts = surviving new coins, dels = spent DB coins, nothing for clean loads", async () => {
    const fake = new FakeChainDB();
    // 1000 coins already on disk.
    const seed = newManager(fake);
    for (let n = 1; n <= 1000; n++) seed.getCoinsViewCache().addCoin(op(n), coin(n), false);
    await seed.flushDirty([chainStateOp(1)]);
    expect(fake.store.size).toBe(1000);
    fake.batches = [];

    const m = newManager(fake);
    const c = m.getCoinsViewCache();
    // Load 500 coins clean.
    for (let n = 1; n <= 500; n++) expect(await c.getCoin(op(n))).not.toBeNull();
    // Spend 30 of them (non-FRESH -> must be deleted on disk).
    for (let n = 1; n <= 30; n++) expect(c.spendCoinSync(op(n))).toBe(true);
    // 50 new coins; 10 of them spent again before the sync (FRESH -> no op).
    for (let n = 2001; n <= 2050; n++) c.addCoin(op(n), coin(n), false);
    for (let n = 2001; n <= 2010; n++) expect(c.spendCoinSync(op(n))).toBe(true);
    // Spend-then-restore of a DB coin (disconnect shape): dirty, must be a put.
    expect(c.spendCoinSync(op(499))).toBe(true);
    c.addCoin(op(499), coin(499), true);

    expect(c.getDirtyCount()).toBe(30 + 40 + 1);
    c.debugCheckInvariants();

    await m.flushDirty([chainStateOp(2)]);

    expect(fake.batches.length).toBe(1); // one atomic batch
    const ops = fake.batches[0]!;
    const utxoOps = ops.filter((o) => o.prefix === DBPrefix.UTXO);
    const puts = utxoOps.filter((o) => o.type === "put").map((o) => o.key.toString("hex"));
    const dels = utxoOps.filter((o) => o.type === "del").map((o) => o.key.toString("hex"));
    expect(new Set(puts)).toEqual(
      new Set([...Array.from({ length: 40 }, (_, i) => keyOf(op(2011 + i))), keyOf(op(499))]),
    );
    expect(new Set(dels)).toEqual(new Set(Array.from({ length: 30 }, (_, i) => keyOf(op(1 + i)))));
    expect(puts.length).toBe(41);
    expect(dels.length).toBe(30);
    // The chain-state op rides in the same batch.
    expect(ops.filter((o) => o.prefix === DBPrefix.CHAIN_STATE).length).toBe(1);

    // Sync cleared everything; clean survivors stayed cached.
    expect(c.getDirtyCount()).toBe(0);
    expect(c.getCacheSize()).toBe(500 - 30 + 40);
    c.debugCheckInvariants();

    // A second sync with no mutations writes no coin ops at all.
    fake.batches = [];
    await m.flushDirty([chainStateOp(3)]);
    expect(fake.batches.length).toBe(1);
    expect(fake.batches[0]!.filter((o) => o.prefix === DBPrefix.UTXO).length).toBe(0);
  });

  test("a mutation during the batch await keeps its dirty flag and is written next sync", async () => {
    const fake = new FakeChainDB();
    const m = newManager(fake);
    const c = m.getCoinsViewCache();
    for (let n = 1; n <= 20; n++) c.addCoin(op(n), coin(n), false);

    let release!: () => void;
    fake.gate = new Promise<void>((r) => (release = r));
    const syncing = m.flushDirty();
    // ConnectBlock races the LevelDB write.
    c.addCoin(op(99), coin(99), false);
    // op(5) is in the in-flight batch as a put; spending it now must still
    // produce a delete later (it may not be treated as FRESH any more).
    expect(c.spendCoinSync(op(5))).toBe(true);
    release();
    await syncing;
    fake.gate = null;

    // Nothing may be marked clean: the snapshot no longer matches the cache.
    expect(c.getDirtyCount()).toBeGreaterThan(0);
    c.debugCheckInvariants();
    await m.flushDirty();
    const model = new Map<string, Coin>();
    for (let n = 1; n <= 20; n++) if (n !== 5) model.set(keyOf(op(n)), coin(n));
    model.set(keyOf(op(99)), coin(99));
    expectStoreEquals(fake, model);
  });
});

describe("randomised model check: add/spend/restore/sync/flush/evict/restart", () => {
  for (const seed of [1, 2, 3, 4, 5, 6]) {
    test(`seed ${seed}`, async () => {
      let s = (Math.imul(seed, 2654435761) | 0) || 1;
      const rnd = (n: number) => {
        // xorshift32, exact in int32 arithmetic
        s ^= s << 13;
        s ^= s >>> 17;
        s ^= s << 5;
        return (s >>> 0) % n;
      };
      const fake = new FakeChainDB();
      // Tiny budget so memory-triggered eviction happens constantly.
      const perCoin = CACHE_ENTRY_OVERHEAD + coinMemoryUsage(coin(1));
      const budget = perCoin * (10 + rnd(50));
      let m = newManager(fake, budget);
      const model = new Map<string, Coin>(); // the live UTXO set
      let durable = new Map<string, Coin>(); // what disk must hold
      const spentStack: { o: OutPoint; c: Coin }[] = [];
      let next = 1;
      let tag = 0;
      const seen = { spendsFromDisk: 0, restarts: 0, restores: 0, syncs: 0, evictingSyncs: 0 };

      for (let step = 0; step < 4000; step++) {
        const r = rnd(100);
        const c = m.getCoinsViewCache();
        if (r < 48) {
          const n = next++;
          const o = op(n, rnd(3));
          if (!model.has(keyOf(o))) {
            c.addCoin(o, coin(n), false);
            model.set(keyOf(o), coin(n));
          }
        } else if (r < 70 && model.size > 0) {
          // Spend a random live coin through the async path (loads from DB
          // when evicted) — the ConnectBlock preload+spend shape.
          const keys = [...model.keys()];
          const k = keys[rnd(keys.length)]!;
          const buf = Buffer.from(k, "hex");
          const o = { txid: buf.subarray(0, 32), vout: buf.readUInt32LE(32) };
          if (!c.haveCoinInCache(o)) seen.spendsFromDisk++;
          const moved = { coin: null as Coin | null };
          expect(await c.spendCoin(o, moved)).toBe(true);
          expect(sameCoin(moved.coin, model.get(k)!)).toBe(true);
          model.delete(k);
          spentStack.push({ o, c: moved.coin! });
        } else if (r < 78 && spentStack.length > 0) {
          // Disconnect: restore the most recently spent coin.
          const { o, c: coinBack } = spentStack.pop()!;
          if (!model.has(keyOf(o))) {
            m.restoreUTXO(o.txid, o.vout, {
              height: coinBack.height,
              coinbase: coinBack.isCoinbase,
              amount: coinBack.txOut.value,
              scriptPubKey: coinBack.txOut.scriptPubKey,
            });
            model.set(keyOf(o), coinBack);
            seen.restores++;
          }
        } else if (r < 88) {
          const before = fake.batches.length;
          if (m.shouldFlush()) seen.evictingSyncs++;
          seen.syncs++;
          await m.flushDirty([chainStateOp(++tag & 0xff)]);
          expect(fake.batches.length).toBe(before + 1);
          durable = new Map(model);
          expect(m.getEstimatedMemoryUsage()).toBeLessThanOrEqual(budget);
        } else if (r < 91) {
          // UTXOManager.flush: full flush-and-clear when anything is dirty or
          // the cache is over budget; otherwise only the extra ops are written.
          const hadWork = m.getDirtyCount() > 0 || m.shouldFlush();
          await m.flush([chainStateOp(++tag & 0xff)]);
          durable = new Map(model);
          if (hadWork) expect(m.getCacheSize()).toBe(0);
        } else if (r < 93) {
          // Crash + restart: the cache is lost; disk must equal the last
          // durable point, and the live model rolls back to it.
          expectStoreEquals(fake, durable);
          seen.restarts++;
          m = newManager(fake, budget);
          model.clear();
          for (const [k, v] of durable) model.set(k, v);
          spentStack.length = 0;
        } else if (model.size > 0) {
          // Point reads agree with the model.
          const keys = [...model.keys()];
          const k = keys[rnd(keys.length)]!;
          const buf = Buffer.from(k, "hex");
          const got = await c.getCoin({ txid: buf.subarray(0, 32), vout: buf.readUInt32LE(32) });
          expect(sameCoin(got, model.get(k)!)).toBe(true);
        }
        m.getCoinsViewCache().debugCheckInvariants();
      }

      console.log(`seed ${seed}: ${JSON.stringify(seen)} final live=${model.size}`);
      // The run must actually exercise every path it claims to check.
      expect(seen.spendsFromDisk).toBeGreaterThan(20);
      expect(seen.restarts).toBeGreaterThan(20);
      expect(seen.restores).toBeGreaterThan(20);
      expect(seen.evictingSyncs).toBeGreaterThan(5);

      // Final: sync, then a restart must see exactly the model.
      await m.flushDirty([chainStateOp(0)]);
      expectStoreEquals(fake, model);
      const fresh = newManager(fake, budget);
      for (const [k, v] of model) {
        const buf = Buffer.from(k, "hex");
        const got = await fresh.getUTXOAsync({ txid: buf.subarray(0, 32), vout: buf.readUInt32LE(32) });
        expect(sameCoin(got, v)).toBe(true);
      }
      // No resurrection: a sample of spent outpoints reads back as absent.
      for (let n = 1; n < next; n += 97) {
        for (let v = 0; v < 3; v++) {
          const o = op(n, v);
          if (!model.has(keyOf(o))) expect(await fresh.getUTXOAsync(o)).toBeNull();
        }
      }
    });
  }
});

describe("memory-triggered eviction", () => {
  test("evicts only clean coins, oldest first, down to the target; nothing is lost", async () => {
    const fake = new FakeChainDB();
    const perCoin = CACHE_ENTRY_OVERHEAD + coinMemoryUsage(coin(1));
    const budget = perCoin * 1000;
    const m = newManager(fake, budget);
    const c = m.getCoinsViewCache();
    for (let n = 1; n <= 1200; n++) c.addCoin(op(n), coin(n), false);
    expect(m.shouldFlush()).toBe(true);
    await m.flushDirty();
    expect(m.getEstimatedMemoryUsage()).toBeLessThanOrEqual(Math.floor(budget * EVICT_TARGET_FRACTION));
    expect(m.getEstimatedMemoryUsage()).toBeGreaterThan(Math.floor(budget * EVICT_TARGET_FRACTION) - perCoin);
    c.debugCheckInvariants();
    // Oldest went first: op(1) evicted, op(1200) still cached.
    expect(c.haveCoinInCache(op(1))).toBe(false);
    expect(c.haveCoinInCache(op(1200))).toBe(true);
    // Every coin still readable (evicted ones from disk), values intact.
    for (let n = 1; n <= 1200; n++) expect(sameCoin(await c.getCoin(op(n)), coin(n))).toBe(true);
  });

  test("memory flush evicts to target even when dropping spent entries gets under budget", async () => {
    // Regression: with eviction gated on "still over budget after the sync",
    // a cache just over budget because of spent entries dropped only those,
    // sat just below the budget, and memory-flushed again on the next block.
    const fake = new FakeChainDB();
    const perCoin = CACHE_ENTRY_OVERHEAD + coinMemoryUsage(coin(1));
    const budget = perCoin * 1000;
    const seed = newManager(fake, budget * 10);
    for (let n = 1; n <= 1000; n++) seed.getCoinsViewCache().addCoin(op(n), coin(n), false);
    await seed.flushDirty();
    const m = newManager(fake, budget);
    const c = m.getCoinsViewCache();
    for (let n = 1; n <= 1000; n++) await c.getCoin(op(n)); // exactly at budget, clean
    for (let n = 1; n <= 20; n++) c.spendCoinSync(op(n)); // spent, dirty
    c.addCoin(op(1001), coin(1001), false); // one new output tips it over
    expect(m.shouldFlush()).toBe(true);
    await m.flushDirty();
    expect(m.getEstimatedMemoryUsage()).toBeLessThanOrEqual(Math.floor(budget * EVICT_TARGET_FRACTION));
    // Room for ~25% of the budget before the next memory flush.
    for (let n = 2001; n <= 2200; n++) c.addCoin(op(n), coin(n), false);
    expect(m.shouldFlush()).toBe(false);
    c.debugCheckInvariants();
  });

  test("a sync under budget evicts nothing (periodic/tip flushes keep the cache warm)", async () => {
    const fake = new FakeChainDB();
    const perCoin = CACHE_ENTRY_OVERHEAD + coinMemoryUsage(coin(1));
    const m = newManager(fake, perCoin * 1000);
    const c = m.getCoinsViewCache();
    for (let n = 1; n <= 900; n++) c.addCoin(op(n), coin(n), false);
    await m.flushDirty();
    expect(c.getCacheSize()).toBe(900);
    expect(c.getDirtyCount()).toBe(0);
  });

  test("memory counter survives spend-while-FRESH churn without leaking", async () => {
    const fake = new FakeChainDB();
    const m = newManager(fake, 1 << 20);
    const c = m.getCoinsViewCache();
    for (let n = 1; n <= 5000; n++) {
      c.addCoin(op(n), coin(n), false);
      if (n % 3 !== 0) c.spendCoinSync(op(n));
    }
    c.debugCheckInvariants();
    await m.flushDirty();
    c.debugCheckInvariants();
    // Some survivors were evicted by the over-budget sync: spend via the
    // async path, which reloads them from disk.
    for (let n = 3; n <= 5000; n += 3) expect(await c.spendCoin(op(n))).toBe(true);
    await m.flushDirty();
    expect(c.getCacheSize()).toBe(0);
    expect(m.getEstimatedMemoryUsage()).toBe(0);
    expect(fake.store.size).toBe(0);
  });
});

describe("real LevelDB: flush + close + reopen", () => {
  test("coins survive restart exactly; spent ones stay spent", async () => {
    const dir = await mkdtemp(join(tmpdir(), "hotbuns-dirtyset-"));
    try {
      let db = new ChainDB(dir);
      await db.open();
      const perCoin = CACHE_ENTRY_OVERHEAD + coinMemoryUsage(coin(1));
      let m = new UTXOManager(db, perCoin * 300);
      const model = new Map<string, Coin>();
      for (let n = 1; n <= 1000; n++) {
        m.getCoinsViewCache().addCoin(op(n), coin(n), false);
        model.set(keyOf(op(n)), coin(n));
        if (n % 100 === 0) await m.flushDirty(); // over budget -> evicts
      }
      for (let n = 1; n <= 1000; n += 3) {
        expect((await m.spendOutputAsync(op(n))).amount).toBe(BigInt(1000 + n));
        model.delete(keyOf(op(n)));
      }
      await m.flushDirty();
      // Unsynced tail: must NOT reach disk.
      m.getCoinsViewCache().addCoin(op(5000), coin(5000), false);
      await m.getCoinsViewCache().spendCoin(op(2));
      await db.close();

      db = new ChainDB(dir);
      await db.open();
      m = new UTXOManager(db);
      for (let n = 1; n <= 1000; n++) {
        const got = await m.getUTXOAsync(op(n));
        expect(sameCoin(got, model.get(keyOf(op(n))) ?? null)).toBe(true);
      }
      expect(await m.getUTXOAsync(op(5000))).toBeNull();
      await db.close();
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});

describe("CoinsViewDB.batchWrite accepts the dirty iterator", () => {
  test("a plain Map still works (API compatibility)", async () => {
    const fake = new FakeChainDB();
    const v = new CoinsViewDB(fake as unknown as ChainDB);
    const entries = new Map([[`${op(1).txid.toString("hex")}:0`, { coin: coin(1), dirty: true, fresh: true }]]);
    await v.batchWrite(entries, Buffer.alloc(32, 1));
    expect(fake.store.size).toBe(1);
    const cache = new CoinsViewCache(v);
    expect(sameCoin(await cache.getCoin(op(1)), coin(1))).toBe(true);
  });
});
