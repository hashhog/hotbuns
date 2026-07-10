/**
 * GAP2 regression tests — fork-aware block download (reorg-drop fix part 1/2).
 *
 * The production blocker (proven by tools/reorg-hotbuns-proof.sh): a heavier
 * competing chain B that forks at/below the active validated tip A makes the
 * node download only the fork bodies ABOVE the active tip and never the
 * BRIDGING bodies at/below the tip, so the reorg connect fails forever with
 * "UTXO view best block ... does not match block prev ... (view-out-of-sync)"
 * and the node stays stuck on the minority chain.
 *
 * Root cause (GAP2): `requestBlocks` walks the download frontier by HEIGHT,
 * floored at `nextHeightToRequest = activeTip.height + 1`. When the heavier
 * fork diverges below the active tip, the bridging heights fork-point+1 ..
 * active-tip are below that floor and are never requested.
 *
 * Fix: `lowerDownloadFloorForFork` descends the best header tip's ancestry to
 * the fork point and lowers `nextHeightToRequest` to fork-point+1 (no active-
 * tip height floor), so the existing height walk — which already reads the
 * fork-branch entries re-pointed into `headersByHeight` — requests the bridging
 * bodies. Bounded by MAX_FORK_DOWNLOAD_DEPTH. A simple extension is a no-op.
 *
 * Mirrors the shipped blockbrew Part-1 tests
 * (internal/p2p/block_download_fork_test.go:
 * TestStartBlockDownload_BelowTipHeavierFork / _NoForkUnchanged) and the
 * rustoshi Unit-E E3 download-floor change.
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
import { HeaderSync } from "./headers.js";
import { BlockSync } from "./blocks.js";

/** Minimal mock peer (only the methods requestBlocks / sendGetData touch). */
function createMockPeer(host = "127.0.0.1", port = 8333): any {
  return {
    host,
    port,
    state: "connected",
    versionPayload: { startHeight: 1000, services: 0x409n },
    send: mock(() => {}),
    addBlockInFlight: mock(() => {}),
    removeBlockInFlight: mock(() => {}),
    misbehaving: mock(() => {}),
  };
}

/** Minimal mock peer manager that just yields the connected peers. */
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

/**
 * Mock ChainStateManager — the only method the fork-aware download floor calls
 * is `getBestBlock()`, which must return the ACTIVE VALIDATED tip (NOT the best
 * header tip). Mirrors blockbrew's mockChainConnector{tipHash,tipHeight}.
 */
function createMockChainStateManager(activeTip: {
  hash: Buffer;
  height: number;
  chainWork: bigint;
}): any {
  return {
    getBestBlock: () => ({ ...activeTip }),
  };
}

/**
 * Build a coinbase whose merkle root differs per `branchTag`, so two branches
 * at the same height off the same parent produce DISTINCT block hashes.
 */
function createCoinbaseTx(height: number, branchTag: number): Transaction {
  const heightScript = Buffer.alloc(4);
  heightScript.writeUInt32LE(height);
  return {
    version: 1,
    inputs: [
      {
        prevOut: { txid: Buffer.alloc(32, 0), vout: 0xffffffff },
        // The extra branchTag push makes the coinbase (hence merkle root,
        // hence block hash) unique per branch.
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

/** Mine a valid regtest block extending `prevBlock`, tagged to a branch. */
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

/** Append `n` blocks on top of `prev`, returning them ascending. */
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

describe("BlockSync fork-aware download (GAP2)", () => {
  let dbPath: string;
  let db: ChainDB;
  let headerSync: HeaderSync;

  beforeEach(async () => {
    dbPath = await mkdtemp(join(tmpdir(), "hotbuns-fork-dl-test-"));
    db = new ChainDB(dbPath);
    await db.open();
    headerSync = new HeaderSync(db, REGTEST);
    headerSync.initGenesis();
  });

  afterEach(async () => {
    await db.close();
    await rm(dbPath, { recursive: true, force: true });
  });

  test("below-tip heavier fork: bridging bodies are enqueued (floor lowered to fork point)", async () => {
    const genesis = headerSync.getBestHeader()!;
    const g = { header: genesis.header };

    // Active chain A: genesis -> 1..10. The active VALIDATED tip is A@10.
    const chainA = buildChain(g, 0, 10, /*branch*/ 1, genesis.header.timestamp + 600);
    await headerSync.processHeaders(chainA.map((b) => b.header), createMockPeer());
    const activeTipEntry = headerSync.getBestHeader()!;
    expect(activeTipEntry.height).toBe(10);

    // Heavier competing chain B: genesis -> 1'..15' (forks at genesis, height 0).
    // 15 > 10 equal-difficulty blocks => B becomes the best HEADER chain.
    const chainB = buildChain(g, 0, 15, /*branch*/ 2, genesis.header.timestamp + 700);
    await headerSync.processHeaders(chainB.map((b) => b.header), createMockPeer());
    const bestHeader = headerSync.getBestHeader()!;
    expect(bestHeader.height).toBe(15);
    expect(bestHeader.hash.equals(getBlockHash(chainB[14].header))).toBe(true);

    // The active validated tip is A@10 (NOT the best header). Wire a mock
    // ChainStateManager that reports it, exactly as the live node would.
    const activeTip = {
      hash: activeTipEntry.hash,
      height: activeTipEntry.height,
      chainWork: activeTipEntry.chainWork,
    };
    // Enough peers that the per-peer in-flight cap (MAX_IN_FLIGHT_PER_PEER=4)
    // does not throttle the whole fork span out of a single requestBlocks pass.
    const peers = Array.from({ length: 16 }, (_, i) =>
      createMockPeer("127.0.0.1", 9000 + i)
    );
    const peerManager = createMockPeerManager(peers);
    const bs = new BlockSync(
      db,
      REGTEST,
      headerSync,
      peerManager,
      createMockChainStateManager(activeTip)
    );

    // Simulate the live start() floor (set from the active validated tip):
    // nextHeightToRequest/Process = activeTip.height + 1 = 11. This is the
    // exact pre-fix floor that starved the bridging bodies.
    bs.getState().nextHeightToProcess = activeTip.height + 1;
    bs.getState().nextHeightToRequest = activeTip.height + 1;
    (bs as any).running = true;

    bs.requestBlocks();

    const state = bs.getState();

    // The floor was LOWERED to the fork point + 1 (= 1, since B forks at
    // genesis). The request loop then WALKS UP from there, requesting every
    // needed fork body and advancing the pointer past the last requested
    // height — so the lowering is observable through the pending set below, not
    // through the post-walk pointer. Pre-fix the floor stayed at 11 and the
    // bridging bodies 1..10 were never requestable at all.
    expect(state.nextHeightToRequest).toBeGreaterThan(11);

    // The bridging fork bodies 1..10 (the set GAP2 starved) MUST now be
    // requested (pending), and they must be the FORK branch's blocks — NOT
    // chain A's already-validated siblings at the same heights.
    for (let i = 0; i < 10; i++) {
      const forkHashHex = getBlockHash(chainB[i].header).toString("hex");
      expect(state.pendingBlocks.has(forkHashHex)).toBe(true);
      // The active-chain sibling at the same height must NOT be requested.
      const aHashHex = getBlockHash(chainA[i].header).toString("hex");
      expect(state.pendingBlocks.has(aHashHex)).toBe(false);
    }
    // The fork's only-above-tip bodies (11..15) are also requested.
    for (let i = 10; i < 15; i++) {
      const forkHashHex = getBlockHash(chainB[i].header).toString("hex");
      expect(state.pendingBlocks.has(forkHashHex)).toBe(true);
    }
    // Every pending request must be a fork-branch (chain B) hash.
    const forkHashes = new Set(
      chainB.map((b) => getBlockHash(b.header).toString("hex"))
    );
    for (const hashHex of state.pendingBlocks.keys()) {
      expect(forkHashes.has(hashHex)).toBe(true);
    }

    await bs.stop();
  });

  test("no-fork extension unchanged: floor stays at active-tip+1, only ahead-of-tip bodies requested", async () => {
    const genesis = headerSync.getBestHeader()!;
    const g = { header: genesis.header };

    // Single chain: genesis -> 1..20. The active validated tip is at height 10;
    // 11..20 are header-only (the normal "headers ahead of blocks" state).
    const chain = buildChain(g, 0, 20, /*branch*/ 1, genesis.header.timestamp + 600);
    await headerSync.processHeaders(chain.map((b) => b.header), createMockPeer());
    expect(headerSync.getBestHeader()!.height).toBe(20);

    const activeTipEntry = headerSync.getHeaderByHeight(10)!;
    const activeTip = {
      hash: activeTipEntry.hash,
      height: activeTipEntry.height,
      chainWork: activeTipEntry.chainWork,
    };
    const peers = Array.from({ length: 16 }, (_, i) =>
      createMockPeer("127.0.0.1", 9100 + i)
    );
    const peerManager = createMockPeerManager(peers);
    const bs = new BlockSync(
      db,
      REGTEST,
      headerSync,
      peerManager,
      createMockChainStateManager(activeTip)
    );

    bs.getState().nextHeightToProcess = activeTip.height + 1; // 11
    bs.getState().nextHeightToRequest = activeTip.height + 1; // 11
    (bs as any).running = true;

    bs.requestBlocks();

    const state = bs.getState();

    // INVARIANT: a simple extension must NOT lower the floor — the fork point IS
    // the active tip (fork-point+1 == 11 == the existing floor), so the walk
    // starts at 11 exactly as pre-fix and advances to 21 after requesting
    // 11..20. The lowering code never fired (no below-tip body is pending).
    expect(state.nextHeightToRequest).toBe(21);

    // No below-tip body may be requested (heights 1..10 are on the active chain
    // and already validated). Only the ahead-of-tip bodies 11..20 are pending.
    for (let i = 0; i < 10; i++) {
      const hashHex = getBlockHash(chain[i].header).toString("hex");
      expect(state.pendingBlocks.has(hashHex)).toBe(false);
    }
    for (let i = 10; i < 20; i++) {
      const hashHex = getBlockHash(chain[i].header).toString("hex");
      expect(state.pendingBlocks.has(hashHex)).toBe(true);
    }

    await bs.stop();
  });

  test("extension with request pointer ahead of frontier: no floor lowering, no fork-download spin", async () => {
    // Live CPU-spin repro (mainnet tip): the best header simply EXTENDS the
    // active tip (fork point == active tip), but the request pointer has already
    // advanced past the frontier (the ordinary "headers ahead of blocks" state
    // near the tip). Pre-fix `lowerDownloadFloorForFork` re-lowered the floor and
    // re-logged "[fork-download] ... forks below the active tip" on EVERY
    // requestBlocks call, flooding the log and pegging CPU. The fix makes an
    // extension a true no-op.
    const genesis = headerSync.getBestHeader()!;
    const g = { header: genesis.header };

    // Single chain: genesis -> 1..12. Active validated tip = 10; 11,12 are
    // header-only extensions of the active tip.
    const chain = buildChain(g, 0, 12, /*branch*/ 1, genesis.header.timestamp + 600);
    await headerSync.processHeaders(chain.map((b) => b.header), createMockPeer());
    expect(headerSync.getBestHeader()!.height).toBe(12);

    const activeTipEntry = headerSync.getHeaderByHeight(10)!;
    const activeTip = {
      hash: activeTipEntry.hash,
      height: activeTipEntry.height,
      chainWork: activeTipEntry.chainWork,
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

    // Frontier stuck at 11 (block 11 not yet connected) but the request pointer
    // already ran ahead to 13 (11 and 12 requested) — the exact live geometry:
    // nextHeightToRequest (13) > forkChildHeight for the extension (11).
    bs.getState().nextHeightToProcess = 11;
    bs.getState().nextHeightToRequest = 13;
    (bs as any).running = true;

    // Capture the fork-download log flood signature.
    const origLog = console.log;
    let forkDownloadLines = 0;
    console.log = (...args: any[]) => {
      if (
        typeof args[0] === "string" &&
        args[0].includes("[fork-download]") &&
        args[0].includes("forks below the active tip")
      ) {
        forkDownloadLines++;
      }
    };
    try {
      // Several cycles, mirroring repeated requestBlocks / onHeadersProcessed.
      for (let i = 0; i < 5; i++) bs.requestBlocks();
    } finally {
      console.log = origLog;
    }

    // The extension must NOT be treated as a below-tip fork: no floor lowering,
    // no "forks below the active tip" log line on any cycle.
    expect(forkDownloadLines).toBe(0);
    // The request pointer must not be dragged back down below the frontier.
    expect(bs.getState().nextHeightToRequest).toBeGreaterThanOrEqual(13);
    // No below-tip body (heights 1..10, already on the active chain) requested.
    for (let i = 0; i < 10; i++) {
      const hashHex = getBlockHash(chain[i].header).toString("hex");
      expect(bs.getState().pendingBlocks.has(hashHex)).toBe(false);
    }

    await bs.stop();
  });
});
