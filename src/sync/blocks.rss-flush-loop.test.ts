/**
 * RSS flush loop after the pre-base header backfill (R4 852000 / 930000).
 *
 * receipts/hotbuns-r4-stall-analysis-2026-10-07.md: after 088f392 the ~940k
 * backfilled HeaderChainEntry objects hold anon RSS at 4.1–4.7 GB, on top of
 * the RSS flush line (4 × --dbcache=1024). A UTXO sync under the coins-cache
 * budget evicts nothing, so the level trigger fired again on the next block
 * with dirty coins: 5,920 flushes in 12,235 blocks, 2,903 in 10,000, against
 * 0–1 on every pre-backfill slice. Throughput fell to ~370–400 blk/h.
 *
 * Here the test process's own anon RSS plays the header index: dbcache is set
 * to anon/8, so anon sits over 4 × dbcache for the whole run while the coins
 * cache (a few hundred coins) stays far under its budget and never trips the
 * cache trigger. Every block is > MIN_BLOCKS_TO_KEEP below the best header,
 * so the only flushes are memory flushes.
 *
 * Core: FlushStateToDisk (validation.cpp) has no RSS trigger; a CRITICAL
 * coins-cache flush empties the cache, so it cannot re-fire on the next block.
 */
import { describe, test, expect, beforeEach, afterEach } from "bun:test";
import { mkdtemp, rm } from "fs/promises";
import { tmpdir } from "os";
import { join } from "path";
import { ChainDB } from "../storage/database.js";
import { REGTEST, compactToBigInt } from "../consensus/params.js";
import {
  Block,
  BlockHeader,
  getBlockHash,
  computeMerkleRoot,
  encodeBip34Height,
} from "../validation/block.js";
import { Transaction, getTxId } from "../validation/tx.js";
import { HeaderSync } from "./headers.js";
import { BlockSync } from "./blocks.js";
import { ChainStateManager } from "../chain/state.js";
import { readProcRss } from "../chain/memory_snapshot.js";
import * as memorySnapshot from "../chain/memory_snapshot.js";

const OP_TRUE = Buffer.from([0x51]);
const MATURE = 101; // coinbase of height h is spendable from h + 100
const CONNECT = 140; // blocks 1..140 are connected
const HEADERS = CONNECT + 300; // every connected block is > 288 below the best header
const BALLAST_AT = 70; // the growth test adds anon ballast before this height

function subsidy(height: number): bigint {
  return 5_000_000_000n >> BigInt(Math.floor(height / REGTEST.subsidyHalvingInterval));
}

function coinbaseTx(height: number): Transaction {
  return {
    version: 1,
    inputs: [
      {
        prevOut: { txid: Buffer.alloc(32, 0), vout: 0xffffffff },
        scriptSig: Buffer.concat([encodeBip34Height(height), Buffer.from([0xff, 0x09])]),
        sequence: 0xffffffff,
        witness: [],
      },
    ],
    outputs: [{ value: subsidy(height), scriptPubKey: OP_TRUE }],
    lockTime: 0,
  };
}

function spendTx(src: Transaction, value: bigint): Transaction {
  return {
    version: 2,
    inputs: [
      {
        prevOut: { txid: getTxId(src), vout: 0 },
        scriptSig: Buffer.alloc(0),
        sequence: 0xffffffff,
        witness: [],
      },
    ],
    outputs: [{ value, scriptPubKey: OP_TRUE }],
    lockTime: 0,
  };
}

/** Heights 1..HEADERS. Each block h in MATURE+1..CONNECT also spends coinbase(h - MATURE). */
function mineChain(prev: Buffer, t0: number): Block[] {
  const target = compactToBigInt(REGTEST.powLimitBits);
  const out: Block[] = [];
  for (let height = 1; height <= HEADERS; height++) {
    const txs = [coinbaseTx(height)];
    if (height > MATURE && height <= CONNECT) {
      const src = out[height - MATURE - 1].transactions[0];
      txs.push(spendTx(src, subsidy(height - MATURE) - 1000n));
    }
    const base: BlockHeader = {
      version: 4,
      prevBlock: prev,
      merkleRoot: computeMerkleRoot(txs.map((t) => getTxId(t))),
      timestamp: t0 + height * 600,
      bits: REGTEST.powLimitBits,
      nonce: 0,
    };
    let mined: Block | null = null;
    for (let nonce = 0; nonce < 10_000_000; nonce++) {
      const header = { ...base, nonce };
      if (BigInt("0x" + Buffer.from(getBlockHash(header)).reverse().toString("hex")) <= target) {
        mined = { header, transactions: txs };
        break;
      }
    }
    if (!mined) throw new Error("failed to mine regtest block");
    out.push(mined);
    prev = getBlockHash(mined.header);
  }
  return out;
}

function mockPeer(): any {
  return {
    host: "127.0.0.1",
    port: 18444,
    state: "connected",
    versionPayload: { startHeight: HEADERS, services: 0x409n },
    send: () => true,
    addBlockInFlight: () => {},
    removeBlockInFlight: () => {},
    misbehaving: () => {},
  };
}

function mockPeerManager(peers: any[]): any {
  return {
    getConnectedPeers: () => peers,
    onMessage: () => {},
    broadcast: () => {},
    increaseBanScore: () => {},
    updateBestHeight: () => {},
  };
}

/** Coinbase of height h is unspent at tip `tip` iff no block <= tip spends it. */
function coinbaseUnspentAt(h: number, tip: number): boolean {
  const spender = h + MATURE; // block (h + 101) spends coinbase(h), for 102..CONNECT
  return h <= tip && !(spender > MATURE && spender <= CONNECT && spender <= tip);
}

let chain: Block[] = [];

describe("RSS flush trigger with a flat anon baseline over 4 x dbcache", () => {
  let dbPath: string;
  let db: ChainDB;
  let headerSync: HeaderSync;
  let rssFlushHeights: number[];
  let cacheFlushes: number;
  let origLog: typeof console.log;
  let ballast: Buffer | null = null;

  async function openNode(maxCacheBytes: number): Promise<BlockSync> {
    headerSync = new HeaderSync(db, REGTEST);
    headerSync.initGenesis();
    if (chain.length === 0) {
      const genesis = headerSync.getBestHeader()!;
      chain = mineChain(genesis.hash, genesis.header.timestamp);
    }
    await headerSync.processHeaders(chain.map((b) => b.header), mockPeer());
    expect(headerSync.getBestHeader()!.height).toBe(HEADERS);
    const csm = new ChainStateManager(db, REGTEST);
    await csm.load();
    const bs = new BlockSync(
      db,
      REGTEST,
      headerSync,
      mockPeerManager([mockPeer()]),
      csm,
      1,
      maxCacheBytes,
    );
    (bs as any).running = true; // as after start(), without timers / P2P
    const cs = await db.getChainState();
    const from = cs ? cs.bestHeight + 1 : 1;
    if (cs) (bs as any).lastFlushedHeight = cs.bestHeight;
    bs.getState().nextHeightToProcess = from;
    bs.getState().nextHeightToRequest = CONNECT + 1;
    return bs;
  }

  function buffer(bs: BlockSync, from: number, to: number): void {
    for (let h = from; h <= to; h++) {
      const b = chain[h - 1];
      bs.getState().downloadedBlocks.set(getBlockHash(b.header).toString("hex"), b);
    }
  }

  /** dbcache such that 4 x dbcache sits well under this process's anon RSS. */
  function dbcacheUnderAnon(): number {
    const proc = readProcRss();
    expect(proc).not.toBeNull();
    return Math.max(1 << 20, Math.floor(proc!.anon / 8));
  }

  beforeEach(async () => {
    dbPath = await mkdtemp(join(tmpdir(), "hotbuns-rss-flush-loop-"));
    db = new ChainDB(dbPath);
    await db.open();
    rssFlushHeights = [];
    cacheFlushes = 0;
    origLog = console.log;
    console.log = (...args: unknown[]) => {
      const line = args.map(String).join(" ");
      const m = /^UTXO memory flush \((rss|cache)\) at height (\d+)/.exec(line);
      if (m) {
        if (m[1] === "rss") rssFlushHeights.push(Number(m[2]));
        else cacheFlushes++;
        return;
      }
      origLog(...args);
    };
  });

  afterEach(async () => {
    console.log = origLog;
    ballast = null;
    try {
      await db.close();
    } catch {}
    await rm(dbPath, { recursive: true, force: true });
  });

  test(
    "a flat anon baseline over 4 x dbcache flushes once, not on every block with dirty coins",
    async () => {
      const bs = await openNode(dbcacheUnderAnon());
      buffer(bs, 1, CONNECT);
      await (bs as any).processOrderedBlocks();
      expect(bs.getState().nextHeightToProcess).toBe(CONNECT + 1);
      expect(cacheFlushes).toBe(0);
      // master: one RSS flush per connected block (140). The trigger fires
      // once on the baseline and stays quiet while anon does not grow.
      expect(rssFlushHeights.length).toBeGreaterThanOrEqual(1);
      expect(rssFlushHeights.length).toBeLessThanOrEqual(2);
    },
    120_000,
  );

  test(
    "control: anon under 4 x dbcache never fires the RSS trigger",
    async () => {
      const proc = readProcRss();
      expect(proc).not.toBeNull();
      const bs = await openNode(proc!.anon);
      buffer(bs, 1, CONNECT);
      await (bs as any).processOrderedBlocks();
      expect(bs.getState().nextHeightToProcess).toBe(CONNECT + 1);
      expect(rssFlushHeights).toEqual([]);
      expect(cacheFlushes).toBe(0);
    },
    120_000,
  );

  test(
    "anon that grows by the re-arm step still forces a flush, and a crash after it loses and resurrects no coin",
    async () => {
      const gate = (memorySnapshot as Record<string, unknown>).RSS_REARM_MIN_BYTES;
      expect(typeof gate).toBe("number");
      const dbcache = dbcacheUnderAnon();
      const bs = await openNode(dbcache);
      buffer(bs, 1, BALLAST_AT - 1);
      await (bs as any).processOrderedBlocks();
      const before = rssFlushHeights.length;
      expect(before).toBeGreaterThanOrEqual(1);
      // Grow anon by more than the re-arm step (memory a flush could free).
      const step = Math.max(dbcache, gate as number);
      ballast = Buffer.alloc(step + (64 << 20), 1);
      buffer(bs, BALLAST_AT, CONNECT);
      await (bs as any).processOrderedBlocks();
      expect(bs.getState().nextHeightToProcess).toBe(CONNECT + 1);
      expect(rssFlushHeights.length).toBeGreaterThan(before);
      expect(rssFlushHeights.some((h) => h >= BALLAST_AT)).toBe(true);
      expect(rssFlushHeights.length).toBeLessThanOrEqual(4);

      // Crash: the dirty coins after the last RSS flush are lost with the
      // process. Disk must hold exactly the UTXO set at the flushed tip.
      const cs = await db.getChainState();
      expect(cs).not.toBeNull();
      const durable = cs!.bestHeight;
      expect(durable).toBe(rssFlushHeights[rssFlushHeights.length - 1]);
      expect(durable).toBeLessThan(CONNECT);
      expect(cs!.bestBlockHash.equals(getBlockHash(chain[durable - 1].header))).toBe(true);
      await db.close();
      ballast = null;

      db = new ChainDB(dbPath);
      await db.open();
      for (let h = 1; h <= CONNECT; h++) {
        const cb = await db.getUTXO(getTxId(chain[h - 1].transactions[0]), 0);
        expect([h, cb !== null]).toEqual([h, coinbaseUnspentAt(h, durable)]);
        if (h > MATURE) {
          const sp = await db.getUTXO(getTxId(chain[h - 1].transactions[1]), 0);
          expect([h, sp !== null]).toEqual([h, h <= durable]);
        }
      }

      // Restart from the durable tip and replay the lost blocks. Every coin
      // spent before the crash stays spent; every coin created after it exists
      // once.
      const bs2 = await openNode(dbcache);
      expect(bs2.getState().nextHeightToProcess).toBe(durable + 1);
      buffer(bs2, durable + 1, CONNECT);
      await (bs2 as any).processOrderedBlocks();
      expect(bs2.getState().nextHeightToProcess).toBe(CONNECT + 1);
      await bs2.stop();
      const cs2 = await db.getChainState();
      expect(cs2!.bestHeight).toBe(CONNECT);
      for (let h = 1; h <= CONNECT; h++) {
        const cb = await db.getUTXO(getTxId(chain[h - 1].transactions[0]), 0);
        expect([h, cb !== null]).toEqual([h, coinbaseUnspentAt(h, CONNECT)]);
        if (h > MATURE) {
          const sp = await db.getUTXO(getTxId(chain[h - 1].transactions[1]), 0);
          expect([h, sp !== null]).toEqual([h, true]);
        }
      }
    },
    180_000,
  );
});
