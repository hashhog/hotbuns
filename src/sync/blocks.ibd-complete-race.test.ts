/**
 * Snapshot-boot IBD-complete race (range-runner stall at 227914 / 265000).
 *
 * The worker-pool commit (`ce1231b`) made ConnectBlock `await` script checks,
 * so the event loop can accept more headers while a block is still connecting.
 * `processOrderedBlocksInner` captured `bestHeader` once at entry and then
 * called `completeIBD()` when `nextHeightToProcess` passed that *stale*
 * snapshot — even if the live header tip had already moved on. `completeIBD`
 * then fire-and-forget `utxoManager.flush()`, which CLEARS the UTXO cache
 * after `batchWrite`. The processing lock dropped, the next block re-entered
 * connect, and cache-only (FRESH) coins vanished → `bad-txns-inputs-missingorspent`
 * on a valid main-chain block, header invalidation, peer disconnect, rewind
 * onto an ancestor, `[SYNC-HALTED] impossible reorg`.
 *
 * Receipt: receipts/hotbuns-worker-pool-stall-227914-2026-09-12.md
 * (logs show "IBD complete" at 98.5% with headers thousands ahead, then
 * missing-inputs, then the halt — not a worker deadlock).
 *
 * Control: this file + `RANGE_FORCE=1 bash tools/range-runner.sh run hotbuns 227914 230909`
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
} from "../validation/block.js";
import { Transaction, getTxId } from "../validation/tx.js";
import { HeaderSync } from "./headers.js";
import { BlockSync } from "./blocks.js";

function createMockPeer(host = "127.0.0.1", port = 8333): any {
  return {
    host,
    port,
    state: "connected",
    versionPayload: { startHeight: 1000, services: 0x409n },
    send: () => true,
    addBlockInFlight: () => {},
    removeBlockInFlight: () => {},
    misbehaving: () => {},
  };
}

function createMockPeerManager(peers: any[] = []): any {
  return {
    getConnectedPeers: () => peers,
    onMessage: () => {},
    broadcast: () => {},
    increaseBanScore: () => {},
    updateBestHeight: () => {},
  };
}

function createMockChainStateManager(activeTip: {
  hash: Buffer;
  height: number;
  chainWork: bigint;
}): any {
  return { getBestBlock: () => ({ ...activeTip }) };
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
): Block {
  const coinbaseTx = createCoinbaseTx(height, 1);
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
  prevHeader: BlockHeader,
  prevHeight: number,
  n: number,
  startTs: number,
): Block[] {
  const out: Block[] = [];
  let prevHash = getBlockHash(prevHeader);
  let ts = startTs;
  for (let i = 0; i < n; i++) {
    const b = createValidBlock(prevHash, ts, prevHeight + 1 + i);
    out.push(b);
    prevHash = getBlockHash(b.header);
    ts += 600;
  }
  return out;
}

describe("IBD-complete race (stale bestHeader + unawaited cache-clearing flush)", () => {
  let dbPath: string;
  let db: ChainDB;
  let headerSync: HeaderSync;

  beforeEach(async () => {
    dbPath = await mkdtemp(join(tmpdir(), "hotbuns-ibd-complete-race-"));
    db = new ChainDB(dbPath);
    await db.open();
    headerSync = new HeaderSync(db, REGTEST);
    headerSync.initGenesis();
  });

  afterEach(async () => {
    await db.close();
    await rm(dbPath, { recursive: true, force: true });
  });

  test("headers arriving during connectBlock do not spuriously complete IBD", async () => {
    const genesis = headerSync.getBestHeader()!;
    const chain = buildChain(genesis.header, 0, 5, genesis.header.timestamp + 600);
    const peer = createMockPeer("127.0.0.1", 9402);
    await headerSync.processHeaders(
      chain.map((b) => b.header),
      peer,
    );
    expect(headerSync.getBestHeader()!.height).toBe(5);

    const tip5 = headerSync.getHeaderByHeight(5)!;
    const bs = new BlockSync(
      db,
      REGTEST,
      headerSync,
      createMockPeerManager([peer]),
      createMockChainStateManager({
        hash: tip5.hash,
        height: 5,
        chainWork: tip5.chainWork,
      }),
    );
    (bs as any).running = true;

    const block5 = chain[4]!;
    const hex5 = getBlockHash(block5.header).toString("hex");
    bs.getState().nextHeightToProcess = 5;
    bs.getState().downloadedBlocks.set(hex5, block5);

    let inConnect = false;
    let resume!: () => void;
    const gate = new Promise<void>((r) => {
      resume = r;
    });
    (bs as any).connectBlock = async () => {
      inConnect = true;
      await gate;
      return true;
    };

    const running = (bs as any).processOrderedBlocks();
    for (let i = 0; i < 50 && !inConnect; i++) {
      await new Promise((r) => setTimeout(r, 0));
    }
    expect(inConnect).toBe(true);
    expect((bs as any).ibdComplete).toBe(false);

    // Headers pull ahead while the worker-pool (here: mocked connect) is
    // awaited — the snapshot-boot shape: Inner captured bestHeader=5.
    const more = buildChain(block5.header, 5, 8, block5.header.timestamp + 600);
    await headerSync.processHeaders(
      more.map((b) => b.header),
      peer,
    );
    expect(headerSync.getBestHeader()!.height).toBe(13);

    resume();
    await running;

    expect((bs as any).ibdComplete).toBe(false);
    expect(bs.getState().nextHeightToProcess).toBe(6);
    expect(headerSync.getBestHeader()!.height).toBe(13);

    await bs.stop();
  });

  test("genuine IBD-complete awaits UTXO flush before dropping the processing lock", async () => {
    const genesis = headerSync.getBestHeader()!;
    const chain = buildChain(genesis.header, 0, 3, genesis.header.timestamp + 600);
    const peer = createMockPeer("127.0.0.1", 9403);
    await headerSync.processHeaders(
      chain.map((b) => b.header),
      peer,
    );

    const tip3 = headerSync.getHeaderByHeight(3)!;
    const bs = new BlockSync(
      db,
      REGTEST,
      headerSync,
      createMockPeerManager([peer]),
      createMockChainStateManager({
        hash: tip3.hash,
        height: 3,
        chainWork: tip3.chainWork,
      }),
    );
    (bs as any).running = true;

    const block3 = chain[2]!;
    const hex3 = getBlockHash(block3.header).toString("hex");
    bs.getState().nextHeightToProcess = 3;
    bs.getState().downloadedBlocks.set(hex3, block3);

    (bs as any).connectBlock = async () => true;

    let flushStarted = false;
    let flushReleased = false;
    let releaseFlush!: () => void;
    const flushGate = new Promise<void>((r) => {
      releaseFlush = r;
    });
    const hang = async () => {
      flushStarted = true;
      await flushGate;
      flushReleased = true;
    };
    (bs as any).utxoManager.flush = hang;
    (bs as any).utxoManager.flushDirty = hang;

    const running = (bs as any).processOrderedBlocks();
    for (let i = 0; i < 50 && !flushStarted; i++) {
      await new Promise((r) => setTimeout(r, 0));
    }
    expect(flushStarted).toBe(true);

    let settled = false;
    void running.then(() => {
      settled = true;
    });
    await new Promise((r) => setTimeout(r, 20));
    // Pre-fix completeIBD did not await flush, so Inner returned (and
    // dropped `processing`) while the cache-clearing flush was still in
    // flight. Post-fix the lock is held until flushDirty finishes.
    expect(settled).toBe(false);
    expect(flushReleased).toBe(false);

    releaseFlush();
    await running;
    expect(settled).toBe(true);
    expect(flushReleased).toBe(true);
    expect((bs as any).ibdComplete).toBe(true);

    await bs.stop();
  });
});
