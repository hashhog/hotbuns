/**
 * Snapshot-boot header pointer (receipt 2026-09-10).
 *
 * After `--load-snapshot` the chain tip is the assumeUTXO base (e.g.
 * 900,000) but HeaderSync stayed on genesis: loadFromDB returned early
 * without HEADER_TIP, then skipped the dummy BLOCK_INDEX record
 * (prevBlock = zeros, parent missing). getblockchaininfo.headers stayed
 * 0 and the campaign harness reported
 * `header-sync STALLED at 0 < base 900000` against a serving --connect
 * peer. 3b05a669 re-seats once headers have arrived; snapshot-boot never
 * selected a header at all.
 *
 * Bitcoin Core: AddToBlockIndex (blockstorage.cpp:249) sets
 * m_best_header on every TREE-valid insert. Snapshot load must leave
 * that pointer on the loaded base before any peer headers arrive.
 *
 * Reverting the disconnected-index insert in loadFromDB, or seedHeader,
 * fails the post-boot assertions (EFFECTIVE control).
 */

import { describe, test, expect, beforeEach, afterEach, mock } from "bun:test";
import { mkdtemp, rm } from "fs/promises";
import { tmpdir } from "os";
import { join } from "path";
import { ChainDB, BlockStatus } from "../storage/database.js";
import { REGTEST } from "../consensus/params.js";
import { HeaderSync } from "./headers.js";
import { BlockSync } from "./blocks.js";
import type { BlockHeader } from "../validation/block.js";

const SNAPSHOT_HEIGHT = 900_000;
const SNAPSHOT_HASH = Buffer.alloc(32, 0x90);
const SNAPSHOT_WORK = 0x1000n;

function dummyHeader(): BlockHeader {
  return {
    version: 0,
    prevBlock: Buffer.alloc(32, 0),
    merkleRoot: Buffer.alloc(32, 0),
    timestamp: 0,
    bits: 0,
    nonce: 0,
  };
}

function createMockPeerManager(): any {
  return {
    getConnectedPeers: () => [],
    onMessage: mock(() => {}),
    broadcast: mock(() => {}),
    increaseBanScore: mock(() => {}),
    updateBestHeight: mock(() => {}),
  };
}

function createMockChainStateManager(activeTip: {
  hash: Buffer;
  height: number;
  chainWork: bigint;
}): any {
  return {
    getBestBlock: () => ({ ...activeTip }),
  };
}

/** Persist the historical `--load-snapshot` shape: chain tip + dummy
 *  BLOCK_INDEX, no HEADER_TIP. That is the 09-10 wedge datadir. */
async function persistOldSnapshotShape(db: ChainDB): Promise<void> {
  await db.putChainState({
    bestBlockHash: SNAPSHOT_HASH,
    bestHeight: SNAPSHOT_HEIGHT,
    totalWork: SNAPSHOT_WORK,
  });
  await db.putBlockIndex(SNAPSHOT_HASH, {
    height: SNAPSHOT_HEIGHT,
    header: Buffer.alloc(80),
    nTx: 0,
    status: BlockStatus.HEADER_VALID | BlockStatus.TXS_VALID | BlockStatus.HAVE_DATA,
    dataPos: 0,
  });
}

describe("snapshot-boot header pointer (09-10 stall at 0)", () => {
  let dbPath: string;
  let db: ChainDB;
  let headerSync: HeaderSync;

  beforeEach(async () => {
    dbPath = await mkdtemp(join(tmpdir(), "hotbuns-snapshot-boot-"));
    db = new ChainDB(dbPath);
    await db.open();
    headerSync = new HeaderSync(db, REGTEST);
    headerSync.initGenesis();
  });

  afterEach(async () => {
    await db.close();
    await rm(dbPath, { recursive: true, force: true });
  });

  test("seedHeader leaves the pointer on the snapshot base before any peer headers", async () => {
    expect(headerSync.getBestHeader()!.height).toBe(0);

    await headerSync.seedHeader({
      hash: SNAPSHOT_HASH,
      header: dummyHeader(),
      height: SNAPSHOT_HEIGHT,
      chainWork: SNAPSHOT_WORK,
    });

    const best = headerSync.getBestHeader();
    expect(best).not.toBeNull();
    expect(best!.height).toBe(SNAPSHOT_HEIGHT);
    expect(best!.hash.equals(SNAPSHOT_HASH)).toBe(true);
    expect(headerSync.getHeaderByHeight(SNAPSHOT_HEIGHT)?.hash.equals(SNAPSHOT_HASH)).toBe(
      true
    );
    // Genesis stays in the index; we did not walk 1..base from a peer.
    expect(headerSync.getHeaderByHeight(0)?.height).toBe(0);
    expect(headerSync.getHeaderCount()).toBe(2);
  });

  test("loadFromDB reconstructs the pointer from a snapshot-shaped datadir (no HEADER_TIP, no peer headers)", async () => {
    await persistOldSnapshotShape(db);

    const hs = new HeaderSync(db, REGTEST);
    await hs.loadFromDB();

    const best = hs.getBestHeader();
    expect(best).not.toBeNull();
    expect(best!.height).toBe(SNAPSHOT_HEIGHT);
    expect(best!.hash.equals(SNAPSHOT_HASH)).toBe(true);
    expect(hs.getHeaderByHeight(SNAPSHOT_HEIGHT)?.hash.equals(SNAPSHOT_HASH)).toBe(true);
  });

  test("download frontier starts at the snapshot base, not 0", async () => {
    await persistOldSnapshotShape(db);

    const hs = new HeaderSync(db, REGTEST);
    await hs.loadFromDB();
    expect(hs.getBestHeader()!.height).toBe(SNAPSHOT_HEIGHT);

    const bs = new BlockSync(
      db,
      REGTEST,
      hs,
      createMockPeerManager(),
      createMockChainStateManager({
        hash: SNAPSHOT_HASH,
        height: SNAPSHOT_HEIGHT,
        chainWork: SNAPSHOT_WORK,
      })
    );

    await bs.start();
    const state = bs.getState();
    // start() reads CHAIN_STATE: next request is the first height above
    // the loaded base, not genesis+1. The header ceiling is the base
    // itself — requestBlocks has nothing to fetch until a peer extends
    // the header chain.
    expect(state.nextHeightToProcess).toBe(SNAPSHOT_HEIGHT + 1);
    expect(state.nextHeightToRequest).toBe(SNAPSHOT_HEIGHT + 1);
    expect(hs.getBestHeader()!.height).toBe(SNAPSHOT_HEIGHT);
    expect(state.nextHeightToRequest > hs.getBestHeader()!.height).toBe(true);
    expect(state.pendingBlocks.size).toBe(0);

    await bs.stop();
  });

  test("adoptChainTipAsBestHeader pins a loaded chain tip that loadFromDB has not selected yet", async () => {
    // Chain state only — no BLOCK_INDEX row. The in-process adopt path
    // (RPC loadtxoutset / CLI after --load-snapshot) must still seed.
    await db.putChainState({
      bestBlockHash: SNAPSHOT_HASH,
      bestHeight: SNAPSHOT_HEIGHT,
      totalWork: SNAPSHOT_WORK,
    });

    const hs = new HeaderSync(db, REGTEST);
    hs.initGenesis();
    expect(hs.getBestHeader()!.height).toBe(0);

    await hs.adoptChainTipAsBestHeader(SNAPSHOT_HASH, SNAPSHOT_HEIGHT);

    const best = hs.getBestHeader();
    expect(best!.height).toBe(SNAPSHOT_HEIGHT);
    expect(best!.hash.equals(SNAPSHOT_HASH)).toBe(true);

    // Restart reconstructs from the HEADER_TIP seedHeader persisted.
    const hs2 = new HeaderSync(db, REGTEST);
    await hs2.loadFromDB();
    expect(hs2.getBestHeader()!.height).toBe(SNAPSHOT_HEIGHT);
    expect(hs2.getBestHeader()!.hash.equals(SNAPSHOT_HASH)).toBe(true);
  });
});
