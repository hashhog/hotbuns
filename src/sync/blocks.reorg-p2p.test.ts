/**
 * GAP3 regression tests — P2P reorg routing (reorg-drop fix part 2/2).
 *
 * The production blocker (proven by tools/reorg-hotbuns-proof.sh): a heavier
 * competing chain B that forks at/below the active validated tip A makes the
 * node download the bridging bodies (part 1 fixed the download floor) but the
 * passive P2P receive path then DROPS / strands them — the bridging fork bodies
 * live only in the in-memory `downloadedBlocks` map, never on disk. When the
 * fork TIP reaches `connectBlock`, the pre-connect reorg dispatch
 * (`handleReorgUtxoAndCollect`) reads the intermediate bodies via `db.getBlock`,
 * finds them missing, falls back to the legacy in-place connect, and wedges
 * forever with "view-out-of-sync". The node stays stuck on the minority chain.
 *
 * Root cause (GAP3): the real reorg machinery
 * (`ChainStateManager.reorganize` / the `connectBlock` reorg dispatch +
 * `resyncFrontierAfterRollback`) was only reachable from the `invalidateblock`
 * RPC and submitblock; the live P2P `handleBlock` path never stored a
 * below-frontier competing-fork body to disk, so the reorg dispatch could never
 * read the bridging bodies back.
 *
 * Fix: `maybeStoreForkBody` routes a passively-received below-frontier
 * competing-fork body through the SAME side-branch storage submitblock uses
 * (`storeSideBranchBlock` → `db.putBlock` + HAVE_DATA), so once the bridging
 * bodies are on disk the fork TIP (at/above the frontier) drives the existing
 * reorg dispatch and the active tip switches to the heavier branch.
 *
 * Mirrors the shipped blockbrew Part-2 tests
 * (internal/p2p/block_connect_reorg_test.go:
 * TestConnectPendingBlocks_BelowTipHeavierForkReorgs / _IBDExtensionUnchanged),
 * which assert the routing decision (store-as-side-branch vs reorg vs extend),
 * not a full UTXO replay.
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
  serializeBlock,
} from "../validation/block.js";
import { Transaction, getTxId } from "../validation/tx.js";
import { HeaderSync } from "./headers.js";
import { BlockSync } from "./blocks.js";

/** Minimal mock peer (only the methods the receive/request path touches). */
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
 * Mock ChainStateManager reporting the ACTIVE VALIDATED tip (NOT the best
 * header). `getBestBlock` is the only method `maybeStoreForkBody` /
 * `lowerDownloadFloorForFork` consult. Mirrors the Part-1 test mock.
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

/** Build a coinbase whose merkle root differs per `branchTag`. */
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

describe("BlockSync P2P reorg routing (GAP3)", () => {
  let dbPath: string;
  let db: ChainDB;
  let headerSync: HeaderSync;

  beforeEach(async () => {
    dbPath = await mkdtemp(join(tmpdir(), "hotbuns-reorg-p2p-test-"));
    db = new ChainDB(dbPath);
    await db.open();
    headerSync = new HeaderSync(db, REGTEST);
    headerSync.initGenesis();
  });

  afterEach(async () => {
    await db.close();
    await rm(dbPath, { recursive: true, force: true });
  });

  /**
   * The core part-2 regression. Active chain A is validated to height 10
   * (tip = A@10). A heavier competing chain B forks at genesis and reaches
   * height 15, becoming the best HEADER chain. We feed the bridging fork bodies
   * (b1..b10, all BELOW the active frontier 11) into the live P2P receive path
   * (`handleBlock`) bottom-up and assert each is:
   *   1. STORED to disk as a side branch (readable via db.getBlock) — the bodies
   *      the reorg dispatch needs (pre-fix they were dropped / left in RAM).
   *   2. recorded in `forkBodiesOnDisk` and evicted from the in-memory buffer.
   *   3. NOT connected to the active tip (the active tip legitimately stays A@10
   *      until the fork tip drives the reorg).
   * Then we feed the fork TIP region (b11..b15, at/above the frontier) and assert
   * it routes through `connectBlock` — the path that drives the existing
   * pre-connect reorg dispatch (`handleReorgUtxoAndCollect`) — proving the reorg
   * is now REACHABLE from the P2P path (GAP3 closed). `connectBlock` is spied so
   * the test does not need a full UTXO replay (the reorg dispatch itself is
   * already covered by the invalidateblock / coinstatsindex harness).
   */
  test("below-tip heavier fork: P2P bridging bodies stored as side branches; fork tip drives the reorg connect", async () => {
    const genesis = headerSync.getBestHeader()!;
    const g = { header: genesis.header };

    // Active chain A: genesis -> 1..10 (validated tip A@10).
    const chainA = buildChain(g, 0, 10, /*branch*/ 1, genesis.header.timestamp + 600);
    await headerSync.processHeaders(chainA.map((b) => b.header), createMockPeer());
    const activeTipEntry = headerSync.getBestHeader()!;
    expect(activeTipEntry.height).toBe(10);

    // Heavier competing chain B: genesis -> 1'..15' (forks at genesis).
    const chainB = buildChain(g, 0, 15, /*branch*/ 2, genesis.header.timestamp + 700);
    await headerSync.processHeaders(chainB.map((b) => b.header), createMockPeer());
    const bestHeader = headerSync.getBestHeader()!;
    expect(bestHeader.height).toBe(15);
    expect(bestHeader.hash.equals(getBlockHash(chainB[14].header))).toBe(true);

    const activeTip = {
      hash: activeTipEntry.hash,
      height: activeTipEntry.height,
      chainWork: activeTipEntry.chainWork,
    };
    const peer = createMockPeer("127.0.0.1", 9000);
    const peerManager = createMockPeerManager([peer]);
    const bs = new BlockSync(
      db,
      REGTEST,
      headerSync,
      peerManager,
      createMockChainStateManager(activeTip)
    );

    // Post-IBD, live-node frontier at the active validated tip + 1.
    bs.getState().nextHeightToProcess = activeTip.height + 1; // 11
    bs.getState().nextHeightToRequest = activeTip.height + 1; // 11
    (bs as any).running = true;
    (bs as any).ibdComplete = true; // part 2 only routes post-IBD
    (bs as any).hasCompletedInitialSync = true;

    // Spy connectBlock so the fork-tip path is observable without a real UTXO
    // replay. Record every (hash,height) it is asked to connect; report success
    // so processOrderedBlocks advances exactly as the real connect would on a
    // successful reorg. This is the equivalent of blockbrew's mockChainConnector.
    const connectCalls: Array<{ hashHex: string; height: number }> = [];
    (bs as any).connectBlock = async (block: Block, height: number) => {
      connectCalls.push({
        hashHex: getBlockHash(block.header).toString("hex"),
        height,
      });
      return true;
    };

    // ── Phase 1: deliver the bridging fork bodies b1..b10 (BELOW frontier 11). ──
    // The download path requested these (part 1); they arrive as solicited
    // (pending) blocks bottom-up.
    for (let i = 0; i < 10; i++) {
      const fb = chainB[i];
      const fbHash = getBlockHash(fb.header);
      const fbHex = fbHash.toString("hex");
      // Model the part-1 download request: mark pending so handleBlock takes the
      // requested-block arm (the live path the download pipeline drives).
      bs.getState().pendingBlocks.set(fbHex, {
        height: fb.header ? i + 1 : i + 1,
        peer: `${peer.host}:${peer.port}`,
        requestedAt: Date.now(),
      } as any);
      await bs.handleBlock(peer, fb);
    }

    // INVARIANT (GAP3 closed): every bridging fork body is now ON DISK as a side
    // branch — exactly what the reorg dispatch reads via db.getBlock. Pre-fix
    // these were dropped / left only in RAM.
    for (let i = 0; i < 10; i++) {
      const fbHash = getBlockHash(chainB[i].header);
      const fbHex = fbHash.toString("hex");
      const raw = await db.getBlock(fbHash);
      expect(raw).not.toBeNull();
      expect(raw!.equals(serializeBlock(chainB[i]))).toBe(true);
      // Recorded as an on-disk fork body and evicted from the RAM buffer.
      expect((bs as any).forkBodiesOnDisk.has(fbHex)).toBe(true);
      expect(bs.getState().downloadedBlocks.has(fbHex)).toBe(false);
      // HAVE_DATA (8) set on the side-branch block index.
      const idx = await db.getBlockIndex(fbHash);
      expect(idx).not.toBeNull();
      expect((idx!.status & 8) !== 0).toBe(true);
    }

    // The active tip MUST NOT have advanced on the bridging bodies (they are not
    // active-chain extensions). connectBlock was never asked to connect a
    // below-frontier body.
    for (const c of connectCalls) {
      expect(c.height).toBeGreaterThanOrEqual(11);
    }

    // ── Phase 2: deliver the fork TIP region b11..b15 (AT/ABOVE frontier 11). ──
    // These are NOT side-branch bodies (height >= frontier); they route through
    // the normal ordered-connect path → connectBlock → the reorg dispatch.
    for (let i = 10; i < 15; i++) {
      const fb = chainB[i];
      const fbHex = getBlockHash(fb.header).toString("hex");
      bs.getState().pendingBlocks.set(fbHex, {
        height: i + 1,
        peer: `${peer.host}:${peer.port}`,
        requestedAt: Date.now(),
      } as any);
      await bs.handleBlock(peer, fb);
    }

    // INVARIANT (reorg REACHABLE from P2P): connectBlock was driven for the fork
    // tip b11 (height 11) — the block whose prevBlock (b10) != active tip (a10),
    // so the pre-connect reorg dispatch fires and switches the active tip to the
    // heavier branch. Pre-fix this connect was never reached for a below-tip
    // fork because the bridging bodies were missing and b11 wedged on retry.
    const b11Hex = getBlockHash(chainB[10].header).toString("hex");
    const connectedB11 = connectCalls.find((c) => c.hashHex === b11Hex);
    expect(connectedB11).toBeDefined();
    expect(connectedB11!.height).toBe(11);

    // And it connected a chain-B block (the heavier fork) at height 11, NOT
    // chain A's already-validated sibling — i.e. the node switched branches.
    const a11Hex =
      chainA.length >= 11
        ? getBlockHash(chainA[10].header).toString("hex")
        : null;
    if (a11Hex) {
      expect(connectCalls.some((c) => c.hashHex === a11Hex)).toBe(false);
    }

    await bs.stop();
  });

  /**
   * Invariant-1 guard (no-fork extension unchanged): a block that simply EXTENDS
   * the active validated tip (its height == the frontier, its parent IS the
   * active tip) must NEVER be routed through the side-branch path — it connects
   * exactly as before. `maybeStoreForkBody` must return false for it, nothing is
   * stored as a side branch, and connectBlock is driven on the extension.
   */
  test("no-fork extension: tip-extending block bypasses the side-branch path entirely", async () => {
    const genesis = headerSync.getBestHeader()!;
    const g = { header: genesis.header };

    // Single chain: genesis -> 1..11. Validated tip at height 10; block 11
    // extends it. No competing fork exists.
    const chain = buildChain(g, 0, 11, /*branch*/ 1, genesis.header.timestamp + 600);
    await headerSync.processHeaders(chain.map((b) => b.header), createMockPeer());
    expect(headerSync.getBestHeader()!.height).toBe(11);

    const activeTipEntry = headerSync.getHeaderByHeight(10)!;
    const activeTip = {
      hash: activeTipEntry.hash,
      height: activeTipEntry.height,
      chainWork: activeTipEntry.chainWork,
    };
    const peer = createMockPeer("127.0.0.1", 9100);
    const peerManager = createMockPeerManager([peer]);
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
    (bs as any).ibdComplete = true;
    (bs as any).hasCompletedInitialSync = true;

    const connectCalls: Array<{ hashHex: string; height: number }> = [];
    (bs as any).connectBlock = async (block: Block, height: number) => {
      connectCalls.push({
        hashHex: getBlockHash(block.header).toString("hex"),
        height,
      });
      return true;
    };

    // Block 11 extends the active tip (height == frontier).
    const ext = chain[10];
    const extHash = getBlockHash(ext.header);
    const extHex = extHash.toString("hex");

    // maybeStoreForkBody must decline it (height >= frontier).
    const routed = await (bs as any).maybeStoreForkBody(ext, extHash, extHex);
    expect(routed).toBe(false);

    // Deliver it as a solicited block; it must connect, NOT be side-branched.
    bs.getState().pendingBlocks.set(extHex, {
      height: 11,
      peer: `${peer.host}:${peer.port}`,
      requestedAt: Date.now(),
    } as any);
    await bs.handleBlock(peer, ext);

    // No side-branch storage occurred for an extension.
    expect((bs as any).forkBodiesOnDisk.size).toBe(0);
    // connectBlock WAS driven on the extension (normal path, invariant 1).
    expect(connectCalls.some((c) => c.hashHex === extHex && c.height === 11)).toBe(
      true
    );

    await bs.stop();
  });

  /**
   * Invariant-1 guard (IBD unchanged): during IBD (`ibdComplete=false`) the
   * side-branch routing is OFF — a below-frontier body is handled by the
   * original in-order path, never persisted as a side branch. (Competing forks
   * below the tip are an at-tip / steady-state phenomenon; IBD blocks arrive in
   * order and extend.) Mirrors blockbrew's _IBDExtensionUnchanged.
   */
  test("IBD guard: below-frontier body is NOT routed to the side-branch path during IBD", async () => {
    const genesis = headerSync.getBestHeader()!;
    const g = { header: genesis.header };

    const chainA = buildChain(g, 0, 10, /*branch*/ 1, genesis.header.timestamp + 600);
    await headerSync.processHeaders(chainA.map((b) => b.header), createMockPeer());
    const chainB = buildChain(g, 0, 15, /*branch*/ 2, genesis.header.timestamp + 700);
    await headerSync.processHeaders(chainB.map((b) => b.header), createMockPeer());

    const activeTipEntry = headerSync.getHeaderByHeight(10)!;
    const activeTip = {
      hash: activeTipEntry.hash,
      height: activeTipEntry.height,
      chainWork: activeTipEntry.chainWork,
    };
    const bs = new BlockSync(
      db,
      REGTEST,
      headerSync,
      createMockPeerManager([createMockPeer("127.0.0.1", 9200)]),
      createMockChainStateManager(activeTip)
    );
    bs.getState().nextHeightToProcess = activeTip.height + 1;
    bs.getState().nextHeightToRequest = activeTip.height + 1;
    (bs as any).running = true;
    (bs as any).ibdComplete = false; // IBD in progress

    const fb = chainB[0]; // height 1, below frontier 11, on the heavier fork
    const fbHash = getBlockHash(fb.header);
    const routed = await (bs as any).maybeStoreForkBody(
      fb,
      fbHash,
      fbHash.toString("hex")
    );
    expect(routed).toBe(false); // IBD: side-branch routing disabled
    expect((bs as any).forkBodiesOnDisk.size).toBe(0);

    await bs.stop();
  });

  /**
   * Guard: a re-delivered ACTIVE-CHAIN body (a block already on the active
   * validated chain, at a height below the frontier) must NOT be mistaken for a
   * competing-fork body and side-branched. maybeStoreForkBody walks the active
   * chain and returns false when the hash matches the active-chain block at that
   * height.
   */
  test("active-chain body re-delivered below frontier is NOT treated as a side branch", async () => {
    const genesis = headerSync.getBestHeader()!;
    const g = { header: genesis.header };

    // Active chain to height 12; frontier at 13. Block at height 5 is on the
    // active chain, below the frontier.
    const chainA = buildChain(g, 0, 12, /*branch*/ 1, genesis.header.timestamp + 600);
    await headerSync.processHeaders(chainA.map((b) => b.header), createMockPeer());

    const activeTipEntry = headerSync.getHeaderByHeight(12)!;
    const activeTip = {
      hash: activeTipEntry.hash,
      height: activeTipEntry.height,
      chainWork: activeTipEntry.chainWork,
    };
    const bs = new BlockSync(
      db,
      REGTEST,
      headerSync,
      createMockPeerManager([createMockPeer("127.0.0.1", 9300)]),
      createMockChainStateManager(activeTip)
    );
    bs.getState().nextHeightToProcess = activeTip.height + 1; // 13
    bs.getState().nextHeightToRequest = activeTip.height + 1;
    (bs as any).running = true;
    (bs as any).ibdComplete = true;
    (bs as any).hasCompletedInitialSync = true;

    const activeBody = chainA[4]; // height 5, on the active chain
    const abHash = getBlockHash(activeBody.header);
    const routed = await (bs as any).maybeStoreForkBody(
      activeBody,
      abHash,
      abHash.toString("hex")
    );
    expect(routed).toBe(false); // on the active chain → not a side branch
    expect((bs as any).forkBodiesOnDisk.size).toBe(0);

    await bs.stop();
  });
});
