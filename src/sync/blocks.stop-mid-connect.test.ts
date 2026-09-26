/**
 * Stop during sync must leave a datadir that boots (QUEUES hotbuns item 0,
 * 2026-09-26).
 *
 * Observed on master cf1ab7d (mainnet replay 632000 -> 633023, --dbcache=1024,
 * RPC `stop` at ~632300 while blocks were arriving):
 *   - blocks kept connecting after "Stopping services..." (the connect loop only
 *     checked `running` when the next body was NOT buffered);
 *   - BlockSync.stop() waited 5 s for the in-flight connect, then DISCARDED the
 *     dirty UTXO cache (clearCache) while that connect was still running;
 *   - the in-flight block then failed bad-txns-inputs-missingorspent and its
 *     valid header was flagged `[invalidate-header]`;
 *   - no CHAIN_STATE was written for heights whose height->hash entries were
 *     already persisted per block, so the relaunch refused to boot
 *     ("chainstate incomplete ... wipe the datadir").
 *
 * Core (validation.cpp ActivateBestChain / FlushStateToDisk, init.cpp Shutdown):
 * shutdown interrupts connection BETWEEN blocks, the in-flight block finishes,
 * then coins + best block are flushed atomically; an interrupted connect never
 * marks a block invalid.
 *
 * The blocks here sit > MIN_BLOCKS_TO_KEEP below the best header, so they take
 * the deep-IBD non-flush path (coins stay in the cache, height index is written
 * per block) — the path the mainnet repro exercised.
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

const HEADERS = 320; // > MIN_BLOCKS_TO_KEEP (288) above the connected blocks
const BUFFERED = 10; // bodies 1..10 downloaded and waiting
const STOP_DURING = 3; // stop() is requested while block 3 is connecting

function subsidy(height: number): bigint {
  return 5_000_000_000n >> BigInt(Math.floor(height / REGTEST.subsidyHalvingInterval));
}

function coinbaseTx(height: number): Transaction {
  return {
    version: 1,
    inputs: [
      {
        prevOut: { txid: Buffer.alloc(32, 0), vout: 0xffffffff },
        scriptSig: Buffer.concat([encodeBip34Height(height), Buffer.from([0xff, 0x07])]),
        sequence: 0xffffffff,
        witness: [],
      },
    ],
    outputs: [
      {
        value: subsidy(height),
        scriptPubKey: Buffer.from([0x76, 0xa9, 0x14, ...Buffer.alloc(20, 0x11), 0x88, 0xac]),
      },
    ],
    lockTime: 0,
  };
}

function mineChain(prev: Buffer, t0: number, n: number): Block[] {
  const target = compactToBigInt(REGTEST.powLimitBits);
  const out: Block[] = [];
  for (let height = 1; height <= n; height++) {
    const cb = coinbaseTx(height);
    const base: BlockHeader = {
      version: 4,
      prevBlock: prev,
      merkleRoot: computeMerkleRoot([getTxId(cb)]),
      timestamp: t0 + height * 600,
      bits: REGTEST.powLimitBits,
      nonce: 0,
    };
    let mined: Block | null = null;
    for (let nonce = 0; nonce < 10_000_000; nonce++) {
      const header = { ...base, nonce };
      if (BigInt("0x" + Buffer.from(getBlockHash(header)).reverse().toString("hex")) <= target) {
        mined = { header, transactions: [cb] };
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

const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

describe("BlockSync.stop() during sync (stop-during-sync durability)", () => {
  let dbPath: string;
  let db: ChainDB;
  let headerSync: HeaderSync;
  let chain: Block[];
  let bs: BlockSync;

  beforeEach(async () => {
    dbPath = await mkdtemp(join(tmpdir(), "hotbuns-stop-mid-connect-"));
    db = new ChainDB(dbPath);
    await db.open();
    headerSync = new HeaderSync(db, REGTEST);
    headerSync.initGenesis();
    const genesis = headerSync.getBestHeader()!;
    chain = mineChain(genesis.hash, genesis.header.timestamp, HEADERS);
    await headerSync.processHeaders(chain.map((b) => b.header), mockPeer());
    expect(headerSync.getBestHeader()!.height).toBe(HEADERS);

    const csm = new ChainStateManager(db, REGTEST);
    await csm.load();
    bs = new BlockSync(db, REGTEST, headerSync, mockPeerManager([mockPeer()]), csm);
    (bs as any).running = true; // as after start(), without timers / P2P
    bs.getState().nextHeightToProcess = 1;
    bs.getState().nextHeightToRequest = BUFFERED + 1;
    for (let i = 0; i < BUFFERED; i++) {
      bs.getState().downloadedBlocks.set(getBlockHash(chain[i].header).toString("hex"), chain[i]);
    }
  });

  afterEach(async () => {
    try {
      await db.close();
    } catch {}
    await rm(dbPath, { recursive: true, force: true });
  });

  test(
    "stop mid-connect: in-flight block finishes, no new block starts, coins + chain state + height index flushed together, and the datadir reopens",
    async () => {
      const connected: number[] = [];
      const orig = (bs as any).connectBlock.bind(bs);
      let stopP: Promise<void> | null = null;
      (bs as any).connectBlock = async (block: Block, height: number) => {
        connected.push(height);
        if (height === STOP_DURING) {
          // Shutdown arrives while this block is in flight, and the connect
          // outlasts master's 5 s drain deadline (a slow mainnet block).
          stopP = bs.stop();
          await sleep(5600);
        }
        return orig(block, height);
      };

      await (bs as any).processOrderedBlocks();
      expect(stopP).not.toBeNull();
      await stopP;

      // Never start a block after stop (master connected all 10).
      expect(connected).toEqual([1, 2, 3]);

      // Durable state is exactly "block 3 connected".
      const cs = await db.getChainState();
      expect(cs).not.toBeNull();
      expect(cs!.bestHeight).toBe(STOP_DURING);
      expect(cs!.bestBlockHash.equals(getBlockHash(chain[STOP_DURING - 1].header))).toBe(true);
      for (let h = 1; h <= STOP_DURING; h++) {
        const got = await db.getBlockHashByHeight(h);
        expect(got?.equals(getBlockHash(chain[h - 1].header))).toBe(true);
        // Every connected block's coinbase coin reached disk with the tip.
        expect(await db.getUTXO(getTxId(chain[h - 1].transactions[0]), 0)).not.toBeNull();
      }
      expect(await db.getBlockHashByHeight(STOP_DURING + 1)).toBeNull();

      // The in-flight valid block was not judged invalid.
      const e3 = headerSync.getHeader(getBlockHash(chain[STOP_DURING - 1].header))!;
      expect(e3.status).not.toBe("invalid");

      // Relaunch on the same datadir boots and resumes from block 3.
      await db.close();
      db = new ChainDB(dbPath);
      await db.open();
      const csm2 = new ChainStateManager(db, REGTEST);
      await expect(csm2.load()).resolves.toBeUndefined();
      expect(csm2.getBestBlock().height).toBe(STOP_DURING);
      const hs2 = new HeaderSync(db, REGTEST);
      await hs2.loadFromDB();
      for (const b of chain.slice(0, 5)) {
        const e = hs2.getHeader(getBlockHash(b.header));
        expect(e?.status).not.toBe("invalid");
      }
    },
    60_000
  );

  test("a connect that fails after stop() began does not invalidate the header or punish the peer", async () => {
    let misbehaved = 0;
    const peer = mockPeer();
    peer.misbehaving = () => {
      misbehaved++;
    };
    (bs as any).peerManager = mockPeerManager([peer]);
    const hex2 = getBlockHash(chain[1].header).toString("hex");
    (bs as any).downloadedBlockPeers.set(hex2, `${peer.host}:${peer.port}`);

    const orig = (bs as any).connectBlock.bind(bs);
    let stopP: Promise<void> | null = null;
    (bs as any).connectBlock = async (block: Block, height: number) => {
      if (height === 2) {
        stopP = bs.stop();
        // What the torn cache produced on master: a spurious missing-input
        // failure for a valid block.
        (bs as any).recordConnectError(
          "bad-txns-inputs-missingorspent: input 0 of tx deadbeef missing"
        );
        return false;
      }
      return orig(block, height);
    };

    await (bs as any).processOrderedBlocks();
    await stopP;

    const e2 = headerSync.getHeader(getBlockHash(chain[1].header))!;
    expect(e2.status).not.toBe("invalid");
    expect(headerSync.getBestHeader()!.height).toBe(HEADERS);
    expect(misbehaved).toBe(0);

    // A failed connect discards the cache back to the last flush (the failed
    // block's partial writes live there), so the durable tip is genesis and
    // nothing beyond it is claimed — block 1's coins were discarded too, and
    // CHAIN_STATE must not say otherwise.
    const cs = await db.getChainState();
    expect(cs!.bestHeight).toBe(0);
    expect(await db.getUTXO(getTxId(chain[0].transactions[0]), 0)).toBeNull();
    await db.close();
    db = new ChainDB(dbPath);
    await db.open();
    const csm2 = new ChainStateManager(db, REGTEST);
    await expect(csm2.load()).resolves.toBeUndefined();
    expect(csm2.getBestBlock().height).toBe(0);
    // Block 1's per-block height entry (written ahead of its coins) was
    // rolled back to the durable tip on boot.
    expect(await db.getBlockHashByHeight(1)).toBeNull();
  }, 60_000);
});
