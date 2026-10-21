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
      await connectAll();
      const other = Buffer.alloc(32, 0x5a);
      await db.putBlockHashByHeight(CONNECT, other);
      expect((await db.getBlockHashByHeight(CONNECT))!.equals(other)).toBe(true);
      await db.batch([db.buildHeightHashDeleteOp(CONNECT - 1)]);
      expect(await db.getBlockHashByHeight(CONNECT - 1)).toBeNull();
      // Untouched heights still resolve to the connected chain.
      const h = CONNECT - 2;
      expect((await db.getBlockHashByHeight(h))!.equals(getBlockHash(chain[h - 1].header))).toBe(true);
    },
    120_000,
  );
});
