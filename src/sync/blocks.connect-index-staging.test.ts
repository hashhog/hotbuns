/**
 * Deep-IBD connects stage their height index + nTx into the coins flush
 * batch (ARCH-2.5 ntx_write, 25% of block time at 900k).
 *
 * Before: every block connected > MIN_BLOCKS_TO_KEEP below the best header
 * (no flush this block) awaited two LevelDB writes, updateBlockIndexNTx
 * (get + put) and putBlockHashByHeight, and those wrote the active-chain
 * height index AHEAD of the coins and CHAIN_STATE, which reach disk only at
 * the next flush. An unclean stop then left height -> hash entries above the
 * durable UTXO tip, which ChainStateManager.load() rolls back on boot
 * (cf3b7dd, state.resume-integrity.test.ts).
 *
 * After: the connect writes nothing; ChainDB keeps the two values in memory
 * (readers see them) and CoinsViewDB.batchWrite puts them in the same
 * LevelDB batch as the coins and CHAIN_STATE. Core: FlushStateToDisk writes
 * the dirty block index and the coins in one flush; nothing about a block's
 * chain position reaches disk before its coins.
 */
import { describe, test, expect, beforeEach, afterEach } from "bun:test";
import { mkdtemp, rm } from "fs/promises";
import { tmpdir } from "os";
import { join } from "path";
import { ChainDB, DBPrefix } from "../storage/database.js";
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
import { UTXOManager } from "../chain/utxo.js";
import type { BatchOperation } from "../storage/database.js";

const OP_TRUE = Buffer.from([0x51]);
const MATURE = 101; // coinbase of height h is spendable from h + 100
const CONNECT = 140; // blocks 1..140 are connected, all on the non-flush path
const HEADERS = CONNECT + 300; // every connected block is > 288 below the best header

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

let chain: Block[] = [];

/** 4 GiB: neither the coins-cache nor the RSS flush trigger fires. */
const NO_MEMORY_FLUSH = 4 * 1024 * 1024 * 1024;

type Write = { kind: "put" | "del" | "batch"; prefixes: number[] };

describe("deep-IBD connect stages its height index and nTx into the coins flush", () => {
  let dbPath: string;
  let db: ChainDB;
  let writes: Write[];

  async function openNode(): Promise<BlockSync> {
    const headerSync = new HeaderSync(db, REGTEST);
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
      NO_MEMORY_FLUSH,
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

  /** Record every LevelDB write (key prefix byte) from here on. */
  function recordWrites(): void {
    const level = (db as any).db;
    const put = level.put.bind(level);
    const del = level.del.bind(level);
    const mkBatch = level.batch.bind(level);
    level.put = (k: Buffer, v: Buffer, ...rest: unknown[]) => {
      writes.push({ kind: "put", prefixes: [k[0]!] });
      return put(k, v, ...rest);
    };
    level.del = (k: Buffer, ...rest: unknown[]) => {
      writes.push({ kind: "del", prefixes: [k[0]!] });
      return del(k, ...rest);
    };
    level.batch = (...args: unknown[]) => {
      const b = mkBatch(...args);
      const prefixes: number[] = [];
      const bput = b.put.bind(b);
      const bdel = b.del.bind(b);
      b.put = (k: Buffer, v: Buffer) => {
        prefixes.push(k[0]!);
        return bput(k, v);
      };
      b.del = (k: Buffer) => {
        prefixes.push(k[0]!);
        return bdel(k);
      };
      const write = b.write.bind(b);
      b.write = (...w: unknown[]) => {
        writes.push({ kind: "batch", prefixes });
        return write(...w);
      };
      return b;
    };
  }

  async function connectAll(): Promise<BlockSync> {
    const bs = await openNode();
    recordWrites();
    buffer(bs, 1, CONNECT);
    await (bs as any).processOrderedBlocks();
    expect(bs.getState().nextHeightToProcess).toBe(CONNECT + 1);
    return bs;
  }

  /** Simulate a crash: drop the process state, reopen the store. */
  async function crashAndReopen(): Promise<void> {
    await db.close();
    db = new ChainDB(dbPath);
    await db.open();
  }

  beforeEach(async () => {
    dbPath = await mkdtemp(join(tmpdir(), "hotbuns-connect-index-staging-"));
    db = new ChainDB(dbPath);
    await db.open();
    writes = [];
  });

  afterEach(async () => {
    try {
      await db.close();
    } catch {}
    await rm(dbPath, { recursive: true, force: true });
  });

  test(
    "a non-flush block connect issues no block-index or height-index write",
    async () => {
      await connectAll();
      const indexWrites = writes.filter((w) =>
        w.prefixes.some((p) => p === DBPrefix.HEADER || p === DBPrefix.BLOCK_INDEX),
      );
      // master: 2 x 140 (updateBlockIndexNTx put + putBlockHashByHeight put).
      expect(indexWrites.length).toBe(0);
    },
    120_000,
  );

  test(
    "an unclean stop leaves no height-index entry above the durable CHAIN_STATE tip",
    async () => {
      await connectAll();
      await crashAndReopen();
      const cs = await db.getChainState();
      const durable = cs ? cs.bestHeight : 0;
      expect(durable).toBeLessThan(CONNECT);
      const leading: number[] = [];
      for (let h = durable + 1; h <= CONNECT; h++) {
        if ((await db.getBlockHashByHeight(h)) !== null) leading.push(h);
      }
      // master: every connected height 1..140 is on disk ahead of its coins.
      expect(leading).toEqual([]);
    },
    120_000,
  );

  test(
    "readers see the staged connects before the flush",
    async () => {
      await connectAll();
      for (let h = 1; h <= CONNECT; h++) {
        const hash = getBlockHash(chain[h - 1].header);
        const atH = await db.getBlockHashByHeight(h);
        expect([h, atH?.toString("hex")]).toEqual([h, hash.toString("hex")]);
        const idx = await db.getBlockIndex(hash);
        expect([h, idx?.nTx]).toEqual([h, chain[h - 1].transactions.length]);
      }
    },
    120_000,
  );

  test(
    "the coins flush writes the height index and nTx in the same batch as CHAIN_STATE",
    async () => {
      const bs = await connectAll();
      writes = [];
      await bs.stop(); // flushes every dirty coin + CHAIN_STATE (cf3b7dd)
      const csBatches = writes.filter(
        (w) => w.kind === "batch" && w.prefixes.includes(DBPrefix.CHAIN_STATE),
      );
      expect(csBatches.length).toBe(1);
      const flush = csBatches[0]!;
      expect(flush.prefixes.includes(DBPrefix.UTXO)).toBe(true);
      expect(flush.prefixes.filter((p) => p === DBPrefix.HEADER).length).toBe(CONNECT);
      expect(flush.prefixes.filter((p) => p === DBPrefix.BLOCK_INDEX).length).toBe(CONNECT);
      expect(db.stagedConnectCount()).toBe(0);

      await crashAndReopen();
      const cs = await db.getChainState();
      expect(cs!.bestHeight).toBe(CONNECT);
      for (let h = 1; h <= CONNECT; h++) {
        const hash = getBlockHash(chain[h - 1].header);
        const atH = await db.getBlockHashByHeight(h);
        expect([h, atH?.toString("hex")]).toEqual([h, hash.toString("hex")]);
        const idx = await db.getBlockIndex(hash);
        expect([h, idx?.nTx]).toEqual([h, chain[h - 1].transactions.length]);
      }
      // Nothing above the tip.
      expect(await db.getBlockHashByHeight(CONNECT + 1)).toBeNull();
    },
    120_000,
  );

  test(
    "a discarded UTXO view drops the height index of the blocks it described",
    async () => {
      const bs = await connectAll();
      // The connect-failure path: re-point the view at the on-disk tip, here
      // genesis (no flush yet).
      (bs as any).discardUnflushedView();
      // master: the entries are already on disk and survive the discard.
      expect(await db.getBlockHashByHeight(CONNECT)).toBeNull();
      expect(await db.getBlockHashByHeight(1)).toBeNull();
      expect(db.stagedConnectCount()).toBe(0);
    },
    120_000,
  );

  test(
    "another UTXO view on the same store dropping its cache keeps BlockSync's staged connects",
    async () => {
      const bs = await connectAll();
      // ChainStateManager owns a second UTXOManager over the same ChainDB.
      const csm = (bs as any).chainStateManager as ChainStateManager;
      csm.clearCache();
      csm.resetCoinsViewToTip();
      expect(db.stagedConnectCount()).toBe(CONNECT);
      await bs.stop();
      await crashAndReopen();
      for (let h = 1; h <= CONNECT; h++) {
        const atH = await db.getBlockHashByHeight(h);
        expect([h, atH?.toString("hex")]).toEqual([h, getBlockHash(chain[h - 1].header).toString("hex")]);
      }
    },
    120_000,
  );

  test(
    "a later direct height-index write supersedes a staged connect",
    async () => {
      const bs = await connectAll();
      const other = Buffer.alloc(32, 0x5a);
      await db.putBlockHashByHeight(CONNECT, other);
      expect((await db.getBlockHashByHeight(CONNECT))!.equals(other)).toBe(true);
      await db.batch([db.buildHeightHashDeleteOp(CONNECT - 1)]);
      expect(await db.getBlockHashByHeight(CONNECT - 1)).toBeNull();
      // putBlockIndex writes the height index too (ChainStateManager connect).
      const viaIndex = Buffer.alloc(32, 0x6b);
      await db.putBlockIndex(viaIndex, {
        height: CONNECT - 2,
        header: Buffer.alloc(80),
        nTx: 1,
        status: 0,
        dataPos: 0,
      });
      expect((await db.getBlockHashByHeight(CONNECT - 2))!.equals(viaIndex)).toBe(true);
      // The next coins flush must not write the staged hash back over it.
      await bs.stop();
      await crashAndReopen();
      expect((await db.getBlockHashByHeight(CONNECT - 2))!.equals(viaIndex)).toBe(true);
      // Untouched heights still resolve to the connected chain.
      const h = CONNECT - 3;
      expect((await db.getBlockHashByHeight(h))!.equals(getBlockHash(chain[h - 1].header))).toBe(true);
    },
    120_000,
  );

  /** Make the next `n` LevelDB batch writes reject (recorded first). */
  function failNextBatchWrites(n: number): () => number {
    const level = (db as any).db;
    const mkBatch = level.batch.bind(level);
    let left = n;
    let failed = 0;
    level.batch = (...args: unknown[]) => {
      const b = mkBatch(...args);
      const write = b.write.bind(b);
      b.write = (...w: unknown[]) => {
        if (left > 0) {
          left--;
          failed++;
          return Promise.reject(new Error("injected LevelDB write failure"));
        }
        return write(...w);
      };
      return b;
    };
    return () => failed;
  }

  async function durableHeightsAbove(height: number): Promise<number[]> {
    const out: number[] = [];
    for (let h = height + 1; h <= HEADERS; h++) {
      if ((await db.getBlockHashByHeight(h)) !== null) out.push(h);
    }
    return out;
  }

  test(
    "a failed coins flush writes nothing and keeps every staged connect",
    async () => {
      const bs = await connectAll();
      const failed = failNextBatchWrites(1);
      const ops = await (bs as any).buildViewTipChainStateOps();
      await expect((bs as any).utxoManager.flushDirty(ops)).rejects.toThrow(
        "injected LevelDB write failure",
      );
      expect(failed()).toBe(1);
      expect(db.stagedConnectCount()).toBe(CONNECT);
      await crashAndReopen();
      const cs = await db.getChainState();
      const durable = cs ? cs.bestHeight : 0;
      expect(durable).toBe(0);
      expect(await durableHeightsAbove(durable)).toEqual([]);
      const idx = await db.getBlockIndex(getBlockHash(chain[CONNECT - 1].header));
      expect(idx?.nTx).toBe(0);
    },
    120_000,
  );

  test(
    "durableFlushDirty's retry writes the staged heights and nTx in the same batch as the coins",
    async () => {
      const bs = await connectAll();
      const failed = failNextBatchWrites(1); // outside the recorder: not recorded
      writes = [];
      const ops = await (bs as any).buildViewTipChainStateOps();
      expect(await (bs as any).durableFlushDirty(ops, "test flush")).toBe(true);
      expect(failed()).toBe(1);
      const csBatches = writes.filter(
        (w) => w.kind === "batch" && w.prefixes.includes(DBPrefix.CHAIN_STATE),
      );
      // The retry (the failed attempt never reached the recorder): the whole
      // flush, coins and the staged metadata together.
      expect(csBatches.length).toBe(1);
      for (const b of csBatches) {
        expect(b.prefixes.includes(DBPrefix.UTXO)).toBe(true);
        expect(b.prefixes.filter((p) => p === DBPrefix.HEADER).length).toBe(CONNECT);
        expect(b.prefixes.filter((p) => p === DBPrefix.BLOCK_INDEX).length).toBe(CONNECT);
      }
      expect(db.stagedConnectCount()).toBe(0);
      await crashAndReopen();
      expect((await db.getChainState())!.bestHeight).toBe(CONNECT);
      for (let h = 1; h <= CONNECT; h++) {
        const hash = getBlockHash(chain[h - 1].header);
        expect([h, (await db.getBlockHashByHeight(h))?.toString("hex")]).toEqual([h, hash.toString("hex")]);
        expect([h, (await db.getBlockIndex(hash))?.nTx]).toEqual([h, chain[h - 1].transactions.length]);
      }
      expect(await durableHeightsAbove(CONNECT)).toEqual([]);
    },
    120_000,
  );

  test(
    "a direct height-index write issued while a coins flush is stalled lands after it",
    async () => {
      const bs = await connectAll();
      // Stall the flush inside its nTx read-modify-write, i.e. after it has
      // snapshotted the staged connects and before its batch is written.
      const level = (db as any).db;
      const get = level.get.bind(level);
      let release!: () => void;
      const gate = new Promise<void>((r) => (release = r));
      let stalled = false;
      level.get = async (k: Buffer, ...rest: unknown[]) => {
        if (k[0] === DBPrefix.BLOCK_INDEX && !stalled) {
          stalled = true;
          await gate;
        }
        return get(k, ...rest);
      };
      const ops = await (bs as any).buildViewTipChainStateOps();
      const flush = (bs as any).utxoManager.flushDirty(ops);
      for (let i = 0; i < 200 && !stalled; i++) await new Promise((r) => setTimeout(r, 5));
      expect(stalled).toBe(true);

      const viaIndex = Buffer.alloc(32, 0x6b);
      const direct = Buffer.alloc(32, 0x5a);
      const w1 = db.putBlockIndex(viaIndex, {
        height: CONNECT - 2,
        header: Buffer.alloc(80),
        nTx: 1,
        status: 0,
        dataPos: 0,
      });
      const w2 = db.putBlockHashByHeight(CONNECT - 3, direct);
      const w3 = db.deleteBlockHashByHeight(CONNECT - 4);
      release();
      await Promise.all([flush, w1, w2, w3]);
      level.get = get;

      await crashAndReopen();
      expect((await db.getChainState())!.bestHeight).toBe(CONNECT);
      expect((await db.getBlockHashByHeight(CONNECT - 2))!.equals(viaIndex)).toBe(true);
      expect((await db.getBlockHashByHeight(CONNECT - 3))!.equals(direct)).toBe(true);
      expect(await db.getBlockHashByHeight(CONNECT - 4)).toBeNull();
      // The superseded blocks' coins WERE in that batch (the snapshot was
      // taken with them), so their nTx is a fact about blocks that batch
      // connected and is written; see the next test for the case where it
      // is not.
      const old = getBlockHash(chain[CONNECT - 3].header);
      expect((await db.getBlockIndex(old))?.nTx).toBe(chain[CONNECT - 3].transactions.length);
      const h = CONNECT - 5;
      expect((await db.getBlockHashByHeight(h))!.equals(getBlockHash(chain[h - 1].header))).toBe(true);
    },
    120_000,
  );

  test(
    "a flush of ChainStateManager's own view does not persist BlockSync's staged connects",
    async () => {
      const bs = await connectAll();
      const csm = (bs as any).chainStateManager as ChainStateManager;
      // ChainStateManager's view flushes (it re-puts the durable CHAIN_STATE,
      // as its connect/disconnect flushes do) while BlockSync's 1..140 are
      // staged and BlockSync's coins are not flushed.
      const level = (db as any).db;
      const csKey = Buffer.from([DBPrefix.CHAIN_STATE]);
      const csRaw: Buffer | undefined = await level.get(csKey);
      expect(csRaw).toBeDefined();
      writes = [];
      await csm
        .getUTXOManager()
        .flush([{ type: "put", prefix: DBPrefix.CHAIN_STATE, key: Buffer.alloc(0), value: csRaw! }]);
      const csBatches = writes.filter((w) => w.kind === "batch" && w.prefixes.includes(DBPrefix.CHAIN_STATE));
      expect(csBatches.length).toBe(1);
      expect(csBatches[0]!.prefixes.filter((p) => p === DBPrefix.HEADER).length).toBe(0);
      expect(db.stagedConnectCount()).toBe(CONNECT);

      await crashAndReopen();
      const cs = await db.getChainState();
      const durable = cs ? cs.bestHeight : 0;
      expect(durable).toBe(0);
      // Nothing for load() to roll back: no height leads the durable coins.
      expect(await durableHeightsAbove(durable)).toEqual([]);
      const realDelete = db.deleteBlockHashesAbove.bind(db);
      const removed: number[][] = [];
      db.deleteBlockHashesAbove = async (h: number) => {
        const r = await realDelete(h);
        removed.push(r);
        return r;
      };
      const csm2 = new ChainStateManager(db, REGTEST);
      await csm2.load();
      expect(csm2.getBestBlock().height).toBe(durable);
      expect(removed.flat()).toEqual([]);
      expect(await durableHeightsAbove(durable)).toEqual([]);
    },
    120_000,
  );
});

/**
 * Disconnects and reorgs while connects are still only staged. BlockSync
 * itself cannot get here today: staging happens only for blocks deeper than
 * MIN_BLOCKS_TO_KEEP below the best header, which keep no undo data (so
 * disconnectBlockUtxo refuses them), every reorg-window connect flushes, and
 * invalidateblock flushes the live view first. These tests therefore drive
 * the ChainDB directly with the exact writes the reorg / disconnect paths
 * issue: height puts/deletes riding the coins flush as extraOps
 * (handleReorgUtxoAndCollect with pendingOps, ChainStateManager.disconnect),
 * and the standalone putBlockHashByHeight / deleteBlockHashByHeight.
 */
describe("staged connects under a disconnect or a shorter-chain reorg", () => {
  let dbPath: string;
  let db: ChainDB;

  const H = (h: number) => Buffer.alloc(32, h); // main chain block at h
  const F = (h: number) => Buffer.alloc(32, 0x80 + h); // fork block at h
  const coinOf = (hash: Buffer) => ({ txid: hash, vout: 0 });

  beforeEach(async () => {
    dbPath = await mkdtemp(join(tmpdir(), "hotbuns-staged-reorg-"));
    db = new ChainDB(dbPath);
    await db.open();
  });
  afterEach(async () => {
    try {
      await db.close();
    } catch {}
    await rm(dbPath, { recursive: true, force: true });
  });

  async function reopen(): Promise<void> {
    await db.close();
    db = new ChainDB(dbPath);
    await db.open();
  }

  /** A view whose blocks 1..10 are connected and staged (nTx = h + 1). */
  async function stagedChain(): Promise<UTXOManager> {
    const utxo = new UTXOManager(db);
    for (let h = 1; h <= 10; h++) await connect(utxo, h, H(h));
    return utxo;
  }

  async function connect(utxo: UTXOManager, h: number, hash: Buffer): Promise<void> {
    await db.putBlockIndex(
      hash,
      { height: h, header: Buffer.alloc(80), nTx: 0, status: 0, dataPos: 0 },
      { writeHeightIndex: false },
    );
    utxo.getCoinsViewCache().addCoin(
      coinOf(hash),
      { txOut: { value: 1000n, scriptPubKey: OP_TRUE }, height: h, isCoinbase: true },
      false,
    );
    db.stageConnectedBlock(utxo.getCoinsViewDB(), h, hash, h + 1);
  }

  function disconnect(utxo: UTXOManager, hash: Buffer): void {
    expect(utxo.getCoinsViewCache().spendCoinSync(coinOf(hash))).toBe(true);
  }

  async function expectDurable(
    active: Array<[number, Buffer]>,
    gone: number[],
    stale: Buffer[],
  ): Promise<void> {
    const fresh = new UTXOManager(db);
    for (const [h, hash] of active) {
      expect([h, (await db.getBlockHashByHeight(h))?.toString("hex")]).toEqual([h, hash.toString("hex")]);
      expect([h, (await db.getBlockIndex(hash))?.nTx]).toEqual([h, h + 1]);
      expect([h, await fresh.preloadUTXO(coinOf(hash))]).toEqual([h, true]);
    }
    for (const h of gone) {
      expect([h, await db.getBlockHashByHeight(h)]).toEqual([h, null]);
    }
    for (const hash of stale) {
      // Its coins are not in the durable set, so neither is its nTx.
      expect([hash[0], await fresh.preloadUTXO(coinOf(hash))]).toEqual([hash[0], false]);
      expect([hash[0], (await db.getBlockIndex(hash))?.nTx]).toEqual([hash[0], 0]);
    }
  }

  test(
    "a disconnect riding the coins flush: the disconnected heights and their nTx are not durable",
    async () => {
      const utxo = await stagedChain();
      const extraOps: BatchOperation[] = [];
      for (let h = 10; h >= 8; h--) {
        disconnect(utxo, H(h));
        extraOps.push(db.buildHeightHashDeleteOp(h));
      }
      await utxo.flushDirty(extraOps);
      expect(db.stagedConnectCount()).toBe(0);
      await reopen();
      await expectDurable(
        Array.from({ length: 7 }, (_, i) => [i + 1, H(i + 1)] as [number, Buffer]),
        [8, 9, 10],
        [H(8), H(9), H(10)],
      );
    },
    30_000,
  );

  test(
    "a shorter-chain reorg with the new branch staged: the height index follows the surviving chain",
    async () => {
      const utxo = await stagedChain();
      // Disconnect 6..10, connect fork blocks 6 and 7 (staged, as a deep-IBD
      // connect stages), and drop the old entries above the new tip (the
      // reorg's CChain::SetTip sweep).
      const extraOps: BatchOperation[] = [];
      for (let h = 10; h >= 6; h--) disconnect(utxo, H(h));
      await connect(utxo, 6, F(6));
      await connect(utxo, 7, F(7));
      for (let h = 8; h <= 10; h++) extraOps.push(db.buildHeightHashDeleteOp(h));
      await utxo.flushDirty(extraOps);
      expect(db.stagedConnectCount()).toBe(0);
      await reopen();
      await expectDurable(
        [
          [1, H(1)], [2, H(2)], [3, H(3)], [4, H(4)], [5, H(5)],
          [6, F(6)], [7, F(7)],
        ],
        [8, 9, 10],
        [H(6), H(7), H(8), H(9), H(10)],
      );
    },
    30_000,
  );

  test(
    "standalone height writes during a disconnect supersede staged connects, nTx included",
    async () => {
      const utxo = await stagedChain();
      // The reorg path without pendingOps: direct puts and deletes, then the
      // next coins flush.
      for (let h = 10; h >= 8; h--) disconnect(utxo, H(h));
      await db.deleteBlockHashByHeight(10);
      await db.deleteBlockHashByHeight(9);
      await connect(utxo, 8, F(8));
      await db.putBlockHashByHeight(8, F(8));
      expect((await db.getBlockIndex(H(9)))?.nTx).toBe(0);
      await utxo.flushDirty();
      await reopen();
      // F(8)'s height entry was written directly (not staged), and its nTx
      // with it was superseded too: only the height is asserted for it.
      expect((await db.getBlockHashByHeight(8))!.equals(F(8))).toBe(true);
      await expectDurable(
        Array.from({ length: 7 }, (_, i) => [i + 1, H(i + 1)] as [number, Buffer]),
        [9, 10],
        [H(8), H(9), H(10)],
      );
    },
    30_000,
  );

  test(
    "a block index write that supersedes a staged height before the flush keeps the old block's nTx at 0",
    async () => {
      const utxo = await stagedChain();
      disconnect(utxo, H(10));
      await db.putBlockIndex(F(10), { height: 10, header: Buffer.alloc(80), nTx: 11, status: 0, dataPos: 0 });
      await utxo.flushDirty();
      await reopen();
      expect((await db.getBlockHashByHeight(10))!.equals(F(10))).toBe(true);
      expect((await db.getBlockIndex(F(10)))?.nTx).toBe(11);
      await expectDurable(
        Array.from({ length: 9 }, (_, i) => [i + 1, H(i + 1)] as [number, Buffer]),
        [],
        [H(10)],
      );
    },
    30_000,
  );
});

