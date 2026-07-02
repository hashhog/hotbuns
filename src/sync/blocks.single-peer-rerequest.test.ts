/**
 * VERIFY-FIRST probe: single-peer block re-request gap.
 *
 * Scenario: exactly ONE connected peer. The node requests a block; the peer
 * withholds it (never delivers). After the stall timeout the node must
 * RE-REQUEST the block from that same sole peer (Core parity: on a block
 * download timeout, re-request from an available peer, including the only one).
 *
 * Pre-fix hypothesis (from task): the re-request path excludes pending.peer,
 * so with a single peer the withheld block wedges forever.
 *
 * This test asserts the sole peer receives a SECOND getdata for the withheld
 * block after the stall handler runs.
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

function createMockPeerManager(peers: any[] = []): any {
  return {
    getConnectedPeers: () => peers,
    onMessage: () => {},
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
  prev: { header: BlockHeader },
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

/** Count getdata inventory items across a mock peer's send() calls that
 *  reference the given block hash. */
function getdataCountFor(peer: any, hash: Buffer): number {
  const hex = hash.toString("hex");
  let n = 0;
  for (const call of peer.send.mock.calls) {
    const msg = call[0];
    if (msg && msg.type === "getdata" && msg.payload?.inventory) {
      for (const inv of msg.payload.inventory) {
        if (Buffer.isBuffer(inv.hash) && inv.hash.toString("hex") === hex) n++;
      }
    }
  }
  return n;
}

describe("BlockSync single-peer re-request (Core parity)", () => {
  let dbPath: string;
  let db: ChainDB;
  let headerSync: HeaderSync;

  beforeEach(async () => {
    dbPath = await mkdtemp(join(tmpdir(), "hotbuns-single-peer-test-"));
    db = new ChainDB(dbPath);
    await db.open();
    headerSync = new HeaderSync(db, REGTEST);
    headerSync.initGenesis();
  });

  afterEach(async () => {
    await db.close();
    await rm(dbPath, { recursive: true, force: true });
  });

  test("withheld block is re-requested from the SOLE peer after stall timeout", async () => {
    const genesis = headerSync.getBestHeader()!;
    const chain = buildChain(
      { header: genesis.header },
      0,
      3,
      1,
      genesis.header.timestamp + 600
    );
    await headerSync.processHeaders(chain.map((b) => b.header), createMockPeer());
    expect(headerSync.getBestHeader()!.height).toBe(3);

    const activeTip = {
      hash: genesis.hash,
      height: 0,
      chainWork: genesis.chainWork,
    };

    // Exactly ONE peer.
    const solePeer = createMockPeer("127.0.0.1", 9500);
    const peerManager = createMockPeerManager([solePeer]);
    const bs = new BlockSync(
      db,
      REGTEST,
      headerSync,
      peerManager,
      createMockChainStateManager(activeTip)
    );

    bs.getState().nextHeightToProcess = 1;
    bs.getState().nextHeightToRequest = 1;
    (bs as any).running = true;

    // Initial request: block 1 goes to the sole peer.
    bs.requestBlocks();
    const block1Hash = getBlockHash(chain[0].header);
    const block1Hex = block1Hash.toString("hex");
    expect(bs.getState().pendingBlocks.has(block1Hex)).toBe(true);
    expect(bs.getState().pendingBlocks.get(block1Hex)!.peer).toBe(
      "127.0.0.1:9500"
    );
    const initialSends = getdataCountFor(solePeer, block1Hash);
    expect(initialSends).toBeGreaterThanOrEqual(1);

    // Peer WITHHOLDS: never delivers. Simulate the stall timeout elapsing by
    // backdating every pending request beyond its timeout.
    const now = Date.now();
    for (const [, pending] of bs.getState().pendingBlocks) {
      pending.requestedAt = now - (pending.timeout + 5000);
    }

    // Stall handler fires (this is the 1 Hz timer callback in the live node).
    (bs as any).handleStalled();

    // CORE PARITY: the withheld block MUST be re-requested. With a single peer
    // that means re-requesting from the SAME sole peer. If the re-request path
    // excluded pending.peer there would be no second getdata -> wedge forever.
    //
    // The authoritative re-request path here is handleStalled() -> requestBlocks(),
    // whose fallback assignment loop (blocks.ts "Fall back to using ANY peer with
    // capacity") does NOT exclude the stalled peer, so the sole peer is re-used.
    const afterSends = getdataCountFor(solePeer, block1Hash);
    expect(afterSends).toBeGreaterThan(initialSends);

    // And it must be tracked as pending to the sole peer again (not orphaned).
    expect(bs.getState().pendingBlocks.has(block1Hex)).toBe(true);
    expect(bs.getState().pendingBlocks.get(block1Hex)!.peer).toBe(
      "127.0.0.1:9500"
    );

    // SUSTAINED: a second stall cycle must ALSO re-request from the sole peer
    // (the peer is now in cooldown + has a doubled stall timeout, yet the
    // fallback path still re-uses it — it never gets permanently excluded).
    const now2 = Date.now();
    for (const [, pending] of bs.getState().pendingBlocks) {
      pending.requestedAt = now2 - (pending.timeout + 5000);
    }
    (bs as any).handleStalled();
    const afterSends2 = getdataCountFor(solePeer, block1Hash);
    expect(afterSends2).toBeGreaterThan(afterSends);
    expect(bs.getState().pendingBlocks.get(block1Hex)!.peer).toBe(
      "127.0.0.1:9500"
    );

    await bs.stop();
  });
});
