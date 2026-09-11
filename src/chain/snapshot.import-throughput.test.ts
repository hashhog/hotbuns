/**
 * Snapshot-import throughput gate.
 *
 * Ladder positioning waits CAMPAIGN_RPC_DEADLINE_OVERRIDE=1800s (30 min)
 * for RPC after `--load-snapshot`. A 168M-coin mainnet dump that does not
 * finish in that window is POSITION_FAIL and every range on this node is
 * blocked. Measured 2026-09-09: the import was still running at 30 min
 * (finished ~55 min).
 *
 * Bar: 168_000_000 coins / 1800 s = 93_334 coins/s. A synthetic 200k-coin
 * dump is large enough that per-coin await/alloc overhead dominates, and
 * small enough to run in the unit suite. HASHHOG_UNSAFE_SNAPSHOT_HEIGHT
 * skips the post-load HASH_SERIALIZED walk so the number is the import
 * itself (the RSS-growing phase of the 09-09 run).
 *
 * Control: `bun test src/chain/snapshot.import-throughput.test.ts`
 */
import { afterEach, describe, expect, it } from "bun:test";
import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { REGTEST } from "../consensus/params.js";
import { ChainDB } from "../storage/database.js";
import { writeVarIntCore } from "../wire/compressor.js";
import { BufferWriter } from "../wire/serialization.js";
import { ChainstateManager, serializeSnapshotMetadata } from "./snapshot.js";

/** 168 million coins in the 30-minute campaign readiness window. */
const BAR_COINS_PER_SEC = 168_000_000 / 1800;
const N = 200_000;

function writeSyntheticSnapshot(path: string, coins: number): void {
  const header = serializeSnapshotMetadata({
    networkMagic: REGTEST.networkMagic,
    baseBlockHash: Buffer.alloc(32, 0x11),
    coinsCount: BigInt(coins),
  });
  const w = new BufferWriter(coins * 64 + 64);
  w.writeBytes(header);
  const hash160 = Buffer.alloc(20, 0x22);
  for (let i = 0; i < coins; i++) {
    const txid = Buffer.alloc(32, 0);
    txid.writeUInt32LE(i, 0);
    w.writeBytes(txid);
    w.writeVarInt(1);
    w.writeVarInt(0);
    writeVarIntCore(w, 2n); // height 1, not coinbase
    writeVarIntCore(w, 0n); // amount 0
    writeVarIntCore(w, 0n); // P2PKH special
    w.writeBytes(hash160);
  }
  writeFileSync(path, w.toBuffer());
}

describe("snapshot import throughput", () => {
  const dir = `/tmp/hotbuns-import-throughput-${process.pid}-${Date.now()}`;
  const prevUnsafe = process.env.HASHHOG_UNSAFE_SNAPSHOT_HEIGHT;

  afterEach(async () => {
    if (prevUnsafe === undefined)
      delete process.env.HASHHOG_UNSAFE_SNAPSHOT_HEIGHT;
    else process.env.HASHHOG_UNSAFE_SNAPSHOT_HEIGHT = prevUnsafe;
    try {
      rmSync(dir, { recursive: true, force: true });
    } catch {
      // best-effort
    }
  });

  it(
    `loads ${N} coins faster than 168M-in-30min (${Math.round(BAR_COINS_PER_SEC)} coins/s)`,
    async () => {
      mkdirSync(dir, { recursive: true });
      const snapPath = join(dir, "snap.dat");
      writeSyntheticSnapshot(snapPath, N);

      process.env.HASHHOG_UNSAFE_SNAPSHOT_HEIGHT = "1000";
      const db = new ChainDB(join(dir, "db"));
      await db.open();
      try {
        const mgr = new ChainstateManager(db, REGTEST);
        const t0 = performance.now();
        const result = await mgr.loadSnapshot(snapPath);
        const ms = performance.now() - t0;
        const rate = Number(result.coinsLoaded) / (ms / 1000);
        const wouldFinish168m = Math.round(168_000_000 / rate);
        console.log(
          `import-throughput: coins=${result.coinsLoaded} ms=${Math.round(ms)} ` +
            `coins_per_s=${Math.round(rate)} bar=${Math.round(BAR_COINS_PER_SEC)} ` +
            `168M_eta_s=${wouldFinish168m}`,
        );
        expect(Number(result.coinsLoaded)).toBe(N);
        expect(rate).toBeGreaterThanOrEqual(BAR_COINS_PER_SEC);
      } finally {
        await db.close();
      }
    },
    { timeout: 120_000 },
  );
});
