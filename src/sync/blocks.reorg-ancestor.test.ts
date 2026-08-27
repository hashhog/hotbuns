/**
 * Reorg-to-ancestor livelock regression (crash-recovery / reorg-integrity class).
 *
 * Production blocker (modern-replay triage): after a (spurious or real) header
 * invalidation, hotbuns' invalidate-header -> reorg machinery could end up being
 * asked to (re)connect a block that is ALREADY an ancestor of the active
 * validated tip (observed: invalidate 255587 -> the loop fixated on reconnecting
 * 255556, an already-connected ancestor). The reconnect target's prevBlock
 * necessarily differs from the higher active-tip the UTXO view points at, so the
 * `view-out-of-sync` gate rejects it on EVERY attempt. The pre-fix
 * rewind-to-`lastFlushedHeight+1` recovery re-selected the same ancestor and
 * retried forever — a 100%-CPU livelock (174k+ retries, ~18k re-serves/60s).
 *
 * Fix: `processOrderedBlocksInner` detects a view-out-of-sync failure whose
 * target block is an ancestor of the active tip (an impossible reorg) and
 * HARD-HALTS the sync loop loudly (`haltSync`) instead of spinning. RPC stays up
 * for triage; `requestBlocks` / `processOrderedBlocks` early-return once halted.
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
  height: number
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
  startTs: number
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

describe("BlockSync reorg-to-ancestor halt", () => {
  let dbPath: string;
  let db: ChainDB;
  let headerSync: HeaderSync;

  beforeEach(async () => {
    dbPath = await mkdtemp(join(tmpdir(), "hotbuns-reorg-ancestor-"));
    db = new ChainDB(dbPath);
    await db.open();
    headerSync = new HeaderSync(db, REGTEST);
    headerSync.initGenesis();
  });

  afterEach(async () => {
    await db.close();
    await rm(dbPath, { recursive: true, force: true });
  });

  test("view-out-of-sync on an ANCESTOR target hard-halts (bounded), does not livelock", async () => {
    const genesis = headerSync.getBestHeader()!;

    // Single validated chain to height 10; active tip = block @10.
    const chain = buildChain(genesis.header, 0, 10, genesis.header.timestamp + 600);
    await headerSync.processHeaders(chain.map((b) => b.header), createMockPeer());
    expect(headerSync.getBestHeader()!.height).toBe(10);

    const tipEntry = headerSync.getHeaderByHeight(10)!;
    const activeTip = {
      hash: tipEntry.hash,
      height: tipEntry.height,
      chainWork: tipEntry.chainWork,
    };

    const bs = new BlockSync(
      db,
      REGTEST,
      headerSync,
      createMockPeerManager([createMockPeer("127.0.0.1", 9400)]),
      createMockChainStateManager(activeTip)
    );
    (bs as any).running = true;

    // Model the wedge: the loop has been pointed back at height 5 — a block that
    // is ALREADY an ancestor of the active tip (chain[4]). Feed the ancestor body
    // into the download buffer at that height so processOrderedBlocks tries to
    // connect it.
    const ancestorBlock = chain[4]; // height 5, on the active chain
    const ancestorHash = getBlockHash(ancestorBlock.header);
    const ancestorHex = ancestorHash.toString("hex");
    bs.getState().nextHeightToProcess = 5;
    bs.getState().downloadedBlocks.set(ancestorHex, ancestorBlock);

    // Spy connectBlock: reproduce the view-out-of-sync rejection the real gate
    // returns when the view best-block (active tip @10) != the block's prev.
    let connectCalls = 0;
    (bs as any).connectBlock = async (_block: Block, _height: number) => {
      connectCalls++;
      (bs as any).lastConnectError =
        "UTXO view best block <tip> does not match block prev <x> at height 5 (view-out-of-sync)";
      return false;
    };

    // Drive the loop repeatedly — pre-fix each pass re-attempts the ancestor
    // (unbounded); post-fix the first pass halts and every later pass no-ops.
    for (let i = 0; i < 5; i++) {
      await (bs as any).processOrderedBlocks();
    }

    // HALTED loudly and bounded.
    expect((bs as any).syncHalted).not.toBeNull();
    expect(String((bs as any).syncHalted)).toContain("impossible reorg");
    expect((bs as any).running).toBe(false);
    // connectBlock was attempted at most once — NOT 174k times.
    expect(connectCalls).toBe(1);
    // The impossible target was evicted from the buffer.
    expect(bs.getState().downloadedBlocks.has(ancestorHex)).toBe(false);

    await bs.stop();
  });

  test("view-out-of-sync on a NON-ancestor target does NOT halt (genuine reorg unaffected)", async () => {
    const genesis = headerSync.getBestHeader()!;
    const chain = buildChain(genesis.header, 0, 10, genesis.header.timestamp + 600);
    await headerSync.processHeaders(chain.map((b) => b.header), createMockPeer());

    // Active tip deliberately LOWER (height 3) than the block we try to connect
    // (height 5) — so the height-5 block is NOT an ancestor of the tip; this is a
    // normal transient view-out-of-sync during a real reorg, which must NOT halt.
    const tip3 = headerSync.getHeaderByHeight(3)!;
    const activeTip = { hash: tip3.hash, height: tip3.height, chainWork: tip3.chainWork };

    const bs = new BlockSync(
      db,
      REGTEST,
      headerSync,
      createMockPeerManager([createMockPeer("127.0.0.1", 9401)]),
      createMockChainStateManager(activeTip)
    );
    (bs as any).running = true;

    const block5 = chain[4];
    const hex5 = getBlockHash(block5.header).toString("hex");
    bs.getState().nextHeightToProcess = 5;
    bs.getState().downloadedBlocks.set(hex5, block5);

    (bs as any).connectBlock = async () => {
      (bs as any).lastConnectError = "at height 5 (view-out-of-sync)";
      return false;
    };

    await (bs as any).processOrderedBlocks();

    // NOT halted — the target is above the active tip, so it is not an ancestor.
    expect((bs as any).syncHalted).toBeNull();

    await bs.stop();
  });
});
