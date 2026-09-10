/**
 * Best-header pointer vs download scheduler (receipt 2026-09-07).
 *
 * Live stall: `headerSync.getBestHeader()` froze at 965,848 while
 * `getHeaderCount()` was 967,863; `requestBlocks` uses the pointer as a
 * height ceiling, bailed at `nextHeightToRequest > bestHeader.height`, and
 * sat at 100% with dl=0 / pend=0 for 15 h. `getblockchaininfo.headers` is
 * the same pointer, so RPC also reported headers == blocks.
 *
 * Bitcoin Core: `m_best_header` is updated in `AddToBlockIndex`
 * (blockstorage.cpp:249) whenever a TREE-valid header out-works it, and
 * `FindNextBlocksToDownload` (net_processing.cpp:1394) walks the header
 * INDEX toward that chain — the pointer and the scheduler cannot diverge.
 *
 * This harness drives them apart (pointer reseated onto an ancestor, heavier
 * headers left in the index), then shows `requestBlocks` re-seats the
 * pointer and enqueues the missing bodies. Reverting the
 * `promoteMostWorkHeader` call in `requestBlocks` fails the post-heal
 * assertions (EFFECTIVE control).
 */

import { describe, test, expect, beforeEach, afterEach, mock } from "bun:test";
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
} from "../validation/block.js";
import { Transaction, getTxId } from "../validation/tx.js";
import { HeaderSync, type HeaderChainEntry } from "./headers.js";
import { BlockSync } from "./blocks.js";

function createMockPeer(host = "127.0.0.1", port = 8333): any {
  return {
    host,
    port,
    state: "connected",
    versionPayload: { startHeight: 1000, services: 0x409n },
    send: mock(() => true),
    addBlockInFlight: mock(() => {}),
    removeBlockInFlight: mock(() => {}),
    misbehaving: mock(() => {}),
  };
}

function createMockPeerManager(peers: any[] = []): any {
  const handlers: Map<string, Array<(peer: any, msg: any) => void>> = new Map();
  return {
    getConnectedPeers: () => peers,
    onMessage: (type: string, handler: (peer: any, msg: any) => void) => {
      const existing = handlers.get(type) ?? [];
      existing.push(handler);
      handlers.set(type, existing);
    },
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

function createCoinbaseTx(height: number, branchTag: number): Transaction {
  const heightScript = Buffer.alloc(4);
  heightScript.writeUInt32LE(height);
  return {
    version: 1,
    inputs: [
      {
        prevOut: { txid: Buffer.alloc(32, 0), vout: 0xffffffff },
        scriptSig: Buffer.concat([
          Buffer.from([0x03]),
          heightScript.subarray(0, 3),
          Buffer.from([0x01, branchTag & 0xff]),
        ]),
        sequence: 0xffffffff,
        witness: [],
      },
    ],
    outputs: [
      {
        value: 5000000000n,
        scriptPubKey: Buffer.from([
          0x76, 0xa9, 0x14, ...Buffer.alloc(20, 0x11), 0x88, 0xac,
        ]),
      },
    ],
    lockTime: 0,
  };
}

function createValidBlock(
  prevBlock: Buffer,
  timestamp: number,
  height: number,
  branchTag: number
): Block {
  const coinbaseTx = createCoinbaseTx(height, branchTag);
  const merkleRoot = computeMerkleRoot([getTxId(coinbaseTx)]);
  const baseHeader: BlockHeader = {
    version: 4,
    prevBlock,
    merkleRoot,
    timestamp,
    bits: REGTEST.powLimitBits,
    nonce: 0,
  };
  const target = compactToBigInt(REGTEST.powLimitBits);
  for (let nonce = 0; nonce < 10000000; nonce++) {
    const header = { ...baseHeader, nonce };
    const hashReversed = Buffer.from(getBlockHash(header)).reverse();
    if (BigInt("0x" + hashReversed.toString("hex")) <= target) {
      return { header, transactions: [coinbaseTx] };
    }
  }
  return { header: baseHeader, transactions: [coinbaseTx] };
}

function buildChain(
  prev: Block | { header: BlockHeader },
  prevHeight: number,
  n: number,
  branchTag: number,
  startTs: number
): Block[] {
  const out: Block[] = [];
  let prevHash = getBlockHash(prev.header);
  let ts = startTs;
  for (let i = 0; i < n; i++) {
    const b = createValidBlock(prevHash, ts, prevHeight + 1 + i, branchTag);
    out.push(b);
    prevHash = getBlockHash(b.header);
    ts += 600;
  }
  return out;
}

/**
 * Drive the best-header POINTER and the header INDEX apart: reseat
 * `bestHeader` + `headersByHeight` onto `frozenHeight` while leaving the
 * heavier descendants in `headerChain`. Mirrors the 09-07 shape
 * (pointer at the validated tip, index still holding more-work headers)
 * without going through invalidateHeader, which would also flag the
 * descendants.
 */
function freezeBestHeaderPointer(hs: HeaderSync, frozenHeight: number): HeaderChainEntry {
  const frozen = hs.getHeaderByHeight(frozenHeight);
  if (!frozen) {
    throw new Error(`no header at height ${frozenHeight} to freeze on`);
  }
  const oldBest = hs.getBestHeader();
  const oldHeight = oldBest ? oldBest.height : frozenHeight;
  for (let h = frozenHeight + 1; h <= oldHeight; h++) {
    (hs as any).headersByHeight.delete(h);
  }
  (hs as any).bestHeader = frozen;
  return frozen;
}

describe("best-header pointer vs download scheduler (09-07 stall)", () => {
  let dbPath: string;
  let db: ChainDB;
  let headerSync: HeaderSync;

  beforeEach(async () => {
    dbPath = await mkdtemp(join(tmpdir(), "hotbuns-best-header-stall-"));
    db = new ChainDB(dbPath);
    await db.open();
    headerSync = new HeaderSync(db, REGTEST);
    headerSync.initGenesis();
  });

  afterEach(async () => {
    await db.close();
    await rm(dbPath, { recursive: true, force: true });
  });

  test("pointer can lag the index; requestBlocks re-seats and enqueues the missing bodies", async () => {
    const genesis = headerSync.getBestHeader()!;
    const g = { header: genesis.header };

    // 20-header chain. Validated tip will sit at 10; 11..20 stay header-only
    // — the normal "headers ahead of blocks" state, then we freeze the
    // pointer back to 10 to simulate the stall.
    const chain = buildChain(g, 0, 20, /*branch*/ 1, genesis.header.timestamp + 600);
    await headerSync.processHeaders(
      chain.map((b) => b.header),
      createMockPeer()
    );
    expect(headerSync.getBestHeader()!.height).toBe(20);
    const trueTipHash = getBlockHash(chain[19].header);
    const trueTipWork = headerSync.getHeader(trueTipHash)!.chainWork;

    // Drive pointer and scheduler apart.
    const frozen = freezeBestHeaderPointer(headerSync, 10);
    expect(headerSync.getBestHeader()!.height).toBe(10);
    expect(headerSync.getBestHeader()!.hash.equals(frozen.hash)).toBe(true);
    // Index still holds the heavier tip — this is the 09-07 disagreement
    // (RPC headers=pointer, IBD hdrs=index size).
    expect(headerSync.getHeader(trueTipHash)).toBeDefined();
    expect(headerSync.getHeader(trueTipHash)!.chainWork > frozen.chainWork).toBe(
      true
    );
    expect(headerSync.getHeaderCount()).toBeGreaterThan(frozen.height + 1);
    // headersByHeight no longer has the descendants, so a height walk
    // capped at the pointer would see nothing to request.
    expect(headerSync.getHeaderByHeight(20)).toBeUndefined();

    const activeTip = {
      hash: frozen.hash,
      height: frozen.height,
      chainWork: frozen.chainWork,
    };
    const peers = Array.from({ length: 16 }, (_, i) =>
      createMockPeer("127.0.0.1", 9200 + i)
    );
    const peerManager = createMockPeerManager(peers);
    const bs = new BlockSync(
      db,
      REGTEST,
      headerSync,
      peerManager,
      createMockChainStateManager(activeTip)
    );

    // Caught up to the *stale* pointer — the 09-07 100% IBD shape
    // (`height=965848/965848`, nextHeightToRequest > bestHeader.height).
    bs.getState().nextHeightToProcess = frozen.height + 1;
    bs.getState().nextHeightToRequest = frozen.height + 1;
    (bs as any).running = true;

    // Pre-heal: the scheduler's own caught-up predicate is true. Without
    // promoteMostWorkHeader this is an immediate return, pend=0 dl=0.
    expect(bs.getState().nextHeightToRequest > headerSync.getBestHeader()!.height).toBe(
      true
    );

    bs.requestBlocks();

    // Fix closed it: pointer on the most-work header, scheduler walking
    // that chain, bodies 11..20 enqueued.
    const healed = headerSync.getBestHeader()!;
    expect(healed.height).toBe(20);
    expect(healed.hash.equals(trueTipHash)).toBe(true);
    expect(healed.chainWork).toBe(trueTipWork);
    expect(headerSync.getHeaderByHeight(20)?.hash.equals(trueTipHash)).toBe(true);

    const state = bs.getState();
    expect(state.pendingBlocks.size).toBeGreaterThan(0);
    for (let i = 10; i < 20; i++) {
      const hex = getBlockHash(chain[i].header).toString("hex");
      expect(state.pendingBlocks.has(hex)).toBe(true);
    }

    await bs.stop();
  });

  test("re-delivered already-known headers heal a stale pointer (drain-poll path)", async () => {
    const genesis = headerSync.getBestHeader()!;
    const chain = buildChain(
      { header: genesis.header },
      0,
      8,
      /*branch*/ 1,
      genesis.header.timestamp + 600
    );
    const headers = chain.map((b) => b.header);
    await headerSync.processHeaders(headers, createMockPeer());
    expect(headerSync.getBestHeader()!.height).toBe(8);

    freezeBestHeaderPointer(headerSync, 3);
    expect(headerSync.getBestHeader()!.height).toBe(3);

    // Drain-poll re-asks getheaders; the peer re-sends the same batch.
    // Pre-fix: already-have was `continue` and the pointer stayed frozen.
    const accepted = await headerSync.processHeaders(headers, createMockPeer());
    expect(accepted).toBe(0);
    expect(headerSync.getBestHeader()!.height).toBe(8);
    expect(
      headerSync.getBestHeader()!.hash.equals(getBlockHash(chain[7].header))
    ).toBe(true);
  });
});
