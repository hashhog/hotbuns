/**
 * The mempool's rolling-fee decay reads the node clock (Core GetTime(), which
 * honours setmocktime). Advancing the mock clock must decay getMinFee().
 * Reference: bitcoin-core/src/txmempool.cpp GetMinFee.
 */
import { describe, test, expect, beforeEach, afterEach } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ChainDB } from "../storage/database.js";
import { UTXOManager } from "../chain/utxo.js";
import { REGTEST } from "../consensus/params.js";
import { Mempool } from "../mempool/mempool.js";
import { setMockTime } from "../clock.js";

describe("mempool rolling fee under mock time", () => {
  let dir: string;
  let db: ChainDB;
  let mempool: Mempool;

  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "mocktime-mempool-"));
    db = new ChainDB(dir);
    await db.open();
    mempool = new Mempool(new UTXOManager(db), REGTEST);
  });

  afterEach(async () => {
    setMockTime(0);
    await db.close();
    await rm(dir, { recursive: true, force: true });
  });

  test("advancing the mock clock decays the rolling minimum fee", () => {
    const T = 1_700_000_000;
    setMockTime(T);
    const m = mempool as any;
    m.rollingMinimumFeeRate = 100_000;
    m.blockSinceLastRollingFeeBump = true;
    m.lastRollingFeeUpdate = T;
    expect(mempool.getMinFee()).toBe(100_000); // within 10s: no decay yet
    setMockTime(T + 12 * 3600);
    const decayed = mempool.getMinFee();
    expect(decayed).toBeLessThan(100_000);
    expect(decayed).toBeGreaterThan(0);
  });
});
