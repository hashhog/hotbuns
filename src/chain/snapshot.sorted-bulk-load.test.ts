/**
 * Snapshot import must not leave LevelDB with compaction debt.
 *
 * R4 675000->710000 (2026-09-27) connected 242 blocks and then connected
 * nothing and stored no header for 10+ min: LevelDB had stopped every write
 * ("Too many L0 files; waiting...") because the import left ~60 tables in L1
 * (10 MB target) and LevelDB drains the higher-scoring L1 before L0. The debt
 * came from the import itself: a fresh datadir holds genesis rows on both
 * sides of the UTXO prefix ('b' block index below 'u', 'w' chain work above),
 * so the first table spans the whole UTXO key range and every sorted table
 * the import wrote after it had to be MERGED instead of trivially moved.
 *
 * Setup: the store is reopened with small tables so ~80 MB of coins (the
 * loader's ~10 MB batches each become one memtable) cross LevelDB's 10 MB L1
 * target many times over. The measure is LevelDB's own LOG: bytes rewritten
 * by merge compactions over bytes flushed. A sorted import into an empty
 * prefix should be placed by trivial moves; the control (no isolation, i.e.
 * the pre-fix startup path) re-merges every byte (ratio ~1.0).
 *
 *   HOTBUNS_UNIT_CHILD=1 bun test ./src/chain/snapshot.sorted-bulk-load.test.ts
 */
import { afterEach, describe, expect, it } from "bun:test";
import { mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { ClassicLevel } from "classic-level";
import { REGTEST } from "../consensus/params.js";
import { ChainDB } from "../storage/database.js";
import { writeVarIntCore } from "../wire/compressor.js";
import { BufferWriter } from "../wire/serialization.js";
import { ChainstateManager, serializeSnapshotMetadata } from "./snapshot.js";

const N = 1_000_000;
const SMALL = 256 * 1024;

function writeSortedSnapshot(path: string, coins: number): void {
  const header = serializeSnapshotMetadata({
    networkMagic: REGTEST.networkMagic,
    baseBlockHash: Buffer.alloc(32, 0x11),
    coinsCount: BigInt(coins),
  });
  const w = new BufferWriter(coins * 64 + 64);
  w.writeBytes(header);
  const hash160 = Buffer.alloc(20, 0x22);
  for (let i = 0; i < coins; i++) {
    // Core dumps in chainstate key order: txid ascending (big-endian here).
    const txid = Buffer.alloc(32, 0x5a);
    txid.writeUInt32BE(i, 0);
    w.writeBytes(txid);
    w.writeVarInt(1);
    w.writeVarInt(0);
    writeVarIntCore(w, 2n);
    writeVarIntCore(w, 0n);
    writeVarIntCore(w, 0n);
    w.writeBytes(hash160);
  }
  writeFileSync(path, w.toBuffer());
}

/**
 * From the store's own LOG: bytes LevelDB REWROTE in merge compactions
 * ("Compacted a@x + b@y files => N bytes") over bytes it FLUSHED from the
 * memtable ("Level-0 table #n: N bytes OK"). A trivial move ("Moved #n to
 * level-k") rewrites nothing. ~1.0 means every imported byte was merged
 * again; a sorted import that nothing overlaps stays near 0.
 */
function compactionRewriteRatio(dbPath: string): { rewriteMB: number; flushedMB: number; ratio: number } {
  let rewrite = 0;
  let flushed = 0;
  for (const line of readFileSync(join(dbPath, "LOG"), "utf8").split("\n")) {
    const c = line.match(/Compacted .* => (\d+) bytes/);
    if (c) rewrite += Number(c[1]);
    const f = line.match(/Level-0 table #\d+: (\d+) bytes OK/);
    if (f) flushed += Number(f[1]);
  }
  const mb = 1024 * 1024;
  return { rewriteMB: rewrite / mb, flushedMB: flushed / mb, ratio: flushed > 0 ? rewrite / flushed : 0 };
}

/** A fresh datadir as ChainStateManager leaves it before a --load-snapshot. */
async function seedFreshDatadir(db: ChainDB): Promise<Buffer> {
  const genesis = Buffer.alloc(32, 0x01);
  await db.putChainState({ bestBlockHash: genesis, bestHeight: 0, totalWork: 1n });
  await db.putBlockIndex(genesis, {
    height: 0,
    header: Buffer.alloc(80, 0x02),
    nTx: 1,
    status: 1,
    dataPos: 1,
  });
  await db.putChainWork(genesis, 0x100010001n);
  return genesis;
}

describe("snapshot sorted bulk load", () => {
  const dir = `/tmp/hotbuns-sorted-bulk-load-${process.pid}-${Date.now()}`;
  const prevUnsafe = process.env.HASHHOG_UNSAFE_SNAPSHOT_HEIGHT;

  afterEach(() => {
    if (prevUnsafe === undefined) delete process.env.HASHHOG_UNSAFE_SNAPSHOT_HEIGHT;
    else process.env.HASHHOG_UNSAFE_SNAPSHOT_HEIGHT = prevUnsafe;
    rmSync(dir, { recursive: true, force: true });
  });

  async function importInto(sub: string, isolate: boolean) {
    mkdirSync(join(dir, sub), { recursive: true });
    const snapPath = join(dir, sub, "snap.dat");
    writeSortedSnapshot(snapPath, N);
    process.env.HASHHOG_UNSAFE_SNAPSHOT_HEIGHT = "1000";
    const dbPath = join(dir, sub, "db");
    const db = new ChainDB(dbPath);
    // Same store, small buffers, so the test sees many flushes/compactions.
    // (abstract-level opens on construction: release that handle's lock.)
    const holder = db as unknown as { db: ClassicLevel<Buffer, Buffer> };
    await holder.db.close();
    const raw = new ClassicLevel<Buffer, Buffer>(dbPath, {
      keyEncoding: "buffer",
      valueEncoding: "buffer",
      writeBufferSize: SMALL,
      maxFileSize: SMALL,
      compression: false,
    });
    holder.db = raw;
    await db.open();
    try {
      const genesis = await seedFreshDatadir(db);
      const mgr = new ChainstateManager(db, REGTEST);
      const res = await mgr.loadSnapshot(snapPath, undefined, { isolateBulkLoad: isolate });
      // Let queued background compactions finish before reading the stats.
      await new Promise((r) => setTimeout(r, 500));
      return {
        coins: Number(res.coinsLoaded),
        lsm: compactionRewriteRatio(dbPath),
        genesisWork: await db.getChainWork(genesis),
        coin: await db.getUTXO(
          (() => { const t = Buffer.alloc(32, 0x5a); t.writeUInt32BE(N - 1, 0); return t; })(),
          0,
        ),
      };
    } finally {
      await db.close();
    }
  }

  it(
    "startup load into a fresh datadir is placed without compaction rewrites",
    async () => {
      const r = await importInto("isolated", true);
      console.log(`sorted-bulk-load: coins=${r.coins} rewrite_MB=${r.lsm.rewriteMB.toFixed(1)} flushed_MB=${r.lsm.flushedMB.toFixed(1)} ratio=${r.lsm.ratio.toFixed(2)}`);
      expect(r.coins).toBe(N);
      // Nothing overlaps the imported tables, so none is merged (pre-fix: every
      // byte was merged again, ratio ~1.0).
      expect(r.lsm.ratio).toBeLessThan(0.1);
      // The displaced genesis CHAIN_WORK row is back, and the coins are there.
      expect(r.genesisWork).toBe(0x100010001n);
      expect(r.coin).not.toBeNull();
    },
    { timeout: 120_000 },
  );

  it(
    "control: without isolation the same import re-reads the data (instrument sees the bug)",
    async () => {
      const r = await importInto("control", false);
      console.log(`sorted-bulk-load control: coins=${r.coins} rewrite_MB=${r.lsm.rewriteMB.toFixed(1)} flushed_MB=${r.lsm.flushedMB.toFixed(1)} ratio=${r.lsm.ratio.toFixed(2)}`);
      expect(r.coins).toBe(N);
      expect(r.lsm.ratio).toBeGreaterThan(0.8);
    },
    { timeout: 120_000 },
  );
});
