/**
 * Malleated block bodies (Core IsBlockMutated) and a block that arrives before
 * its header (fleet-conformance MAL / BBH, 2026-10-08).
 *
 * Core net_processing.cpp ProcessMessage "block": when the parent is known,
 * IsBlockMutated runs before anything else; a mutated body punishes the
 * SENDER, removes only that peer's request and returns -- the block is not
 * marked failed and is fetched again from another peer.  A block whose header
 * is unknown but whose parent is known is accepted through AcceptBlockHeader
 * inside ProcessNewBlock.
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
  blockMutation,
} from "../validation/block.js";
import { Transaction, getTxId } from "../validation/tx.js";
import { hash256 } from "../crypto/primitives.js";
import { HeaderSync } from "./headers.js";
import { BlockSync } from "./blocks.js";

function mockPeer(host: string, port: number): any {
  const p: any = {
    host,
    port,
    state: "connected",
    shouldDisconnect: false,
    versionPayload: { startHeight: 1000, services: 0x409n },
    send: mock(() => true),
    addBlockInFlight: mock(() => {}),
    removeBlockInFlight: mock(() => {}),
    updateSyncedBlocks: mock(() => {}),
    updateSyncedHeaders: mock(() => {}),
  };
  // Like Peer.misbehaving for a local peer: disconnect at once.
  p.misbehaving = mock((_n: number, _why: string) => {
    p.shouldDisconnect = true;
    p.state = "disconnected";
  });
  return p;
}

function mockPeerManager(peers: any[]): any {
  return {
    getConnectedPeers: () => peers.filter((p) => p.state === "connected"),
    onMessage: () => {},
    broadcast: mock(() => {}),
    increaseBanScore: mock(() => {}),
    updateBestHeight: mock(() => {}),
  };
}

/** Segwit coinbase: witness nonce [32 x 00] + the BIP-141 commitment for a
 *  coinbase-only block (witness root = 32 x 00). */
function segwitCoinbase(height: number): Transaction {
  const h = Buffer.alloc(4);
  h.writeUInt32LE(height);
  const nonce = Buffer.alloc(32, 0);
  const commitment = hash256(Buffer.concat([Buffer.alloc(32, 0), nonce]));
  return {
    version: 2,
    inputs: [
      {
        prevOut: { txid: Buffer.alloc(32, 0), vout: 0xffffffff },
        scriptSig: Buffer.concat([Buffer.from([0x03]), h.subarray(0, 3), Buffer.from([0x51])]),
        sequence: 0xffffffff,
        witness: [nonce],
      },
    ],
    outputs: [
      { value: 5000000000n, scriptPubKey: Buffer.from([0x51]) },
      {
        value: 0n,
        scriptPubKey: Buffer.concat([Buffer.from([0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed]), commitment]),
      },
    ],
    lockTime: 0,
  };
}

function mine(prevBlock: Buffer, timestamp: number, txs: Transaction[]): Block {
  const merkleRoot = computeMerkleRoot(txs.map((t) => getTxId(t)));
  const target = compactToBigInt(REGTEST.powLimitBits);
  for (let nonce = 0; nonce < 10_000_000; nonce++) {
    const header: BlockHeader = { version: 4, prevBlock, merkleRoot, timestamp, bits: REGTEST.powLimitBits, nonce };
    if (BigInt("0x" + Buffer.from(getBlockHash(header)).reverse().toString("hex")) <= target) {
      return { header, transactions: txs };
    }
  }
  throw new Error("could not mine");
}

function stripped(b: Block): Block {
  return {
    header: b.header,
    transactions: b.transactions.map((tx) => ({
      ...tx,
      inputs: tx.inputs.map((i) => ({ ...i, witness: [] })),
    })),
  };
}

function getdataFor(peer: any, hash: Buffer): number {
  const hex = hash.toString("hex");
  let n = 0;
  for (const [msg] of peer.send.mock.calls) {
    if (msg?.type === "getdata") {
      for (const inv of msg.payload.inventory) if (inv.hash.toString("hex") === hex) n++;
    }
  }
  return n;
}

describe("blockMutation (Core IsBlockMutated)", () => {
  const genesisHash = Buffer.alloc(32, 7);
  const honest = mine(genesisHash, 1_700_000_000, [segwitCoinbase(1)]);

  test("honest segwit block is not mutated", () => {
    expect(blockMutation(honest, true)).toBeNull();
  });
  test("witness-stripped body: bad-witness-nonce-size, same block hash", () => {
    const s = stripped(honest);
    expect(getBlockHash(s.header).equals(getBlockHash(honest.header))).toBe(true);
    expect(blockMutation(s, true)).toBe("bad-witness-nonce-size");
  });
  test("witness before segwit: unexpected-witness", () => {
    expect(blockMutation(honest, false)).toBe("unexpected-witness");
  });
  test("transactions that do not match the header: bad-txnmrklroot", () => {
    const other = { header: honest.header, transactions: [segwitCoinbase(2)] };
    expect(blockMutation(other, true)).toBe("bad-txnmrklroot");
  });
  test("CVE-2012-2459 duplicate: bad-txns-duplicate", () => {
    const cb = segwitCoinbase(3);
    const tx: Transaction = {
      version: 2,
      inputs: [{ prevOut: { txid: Buffer.alloc(32, 9), vout: 0 }, scriptSig: Buffer.from([0x51]), sequence: 0, witness: [] }],
      outputs: [{ value: 1n, scriptPubKey: Buffer.from([0x51]) }],
      lockTime: 0,
    };
    const tx2: Transaction = { ...tx, lockTime: 1 };
    // [cb, tx, tx2, tx2] has the same root as [cb, tx, tx2]: Core flags the
    // adjacent identical pair (merkle.cpp ComputeMerkleRoot `mutated`).
    const b = mine(genesisHash, 1_700_000_001, [cb, tx, tx2, tx2]);
    expect(blockMutation(b, true)).toBe("bad-txns-duplicate");
  });
  test("no coinbase + a 64-byte transaction: mutated; no coinbase otherwise: not mutated", () => {
    const tx64: Transaction = {
      version: 2,
      inputs: [{ prevOut: { txid: Buffer.alloc(32, 1), vout: 0 }, scriptSig: Buffer.alloc(0), sequence: 0, witness: [] }],
      outputs: [{ value: 1n, scriptPubKey: Buffer.from([0x51, 0x51, 0x51, 0x51]) }],
      lockTime: 0,
    };
    const b = mine(genesisHash, 1_700_000_002, [tx64]);
    expect(blockMutation(b, true)).toMatch(/^mutated: 64-byte/);
    const tx65 = { ...tx64, outputs: [{ value: 1n, scriptPubKey: Buffer.from([0x51, 0x51, 0x51, 0x51, 0x51]) }] };
    expect(blockMutation(mine(genesisHash, 1_700_000_003, [tx65]), true)).toBeNull();
  });
});

describe("BlockSync: mutated body on receipt / block before its header", () => {
  let dbPath: string;
  let db: ChainDB;
  let headerSync: HeaderSync;

  beforeEach(async () => {
    dbPath = await mkdtemp(join(tmpdir(), "hotbuns-mutated-block-test-"));
    db = new ChainDB(dbPath);
    await db.open();
    headerSync = new HeaderSync(db, REGTEST);
    headerSync.initGenesis();
  });
  afterEach(async () => {
    await db.close();
    await rm(dbPath, { recursive: true, force: true });
  });

  function chainOf(n: number): Block[] {
    const genesis = headerSync.getBestHeader()!;
    const out: Block[] = [];
    let prev = genesis.hash;
    let ts = genesis.header.timestamp + 600;
    for (let i = 1; i <= n; i++) {
      const b = mine(prev, ts, [segwitCoinbase(i)]);
      out.push(b);
      prev = getBlockHash(b.header);
      ts += 600;
    }
    return out;
  }

  test("MAL: stripped body from E -> E punished, block not buffered/marked, re-requested from H", async () => {
    const chain = chainOf(2);
    const E = mockPeer("127.0.0.2", 1);
    const H = mockPeer("127.0.0.3", 2);
    await headerSync.processHeaders(chain.map((b) => b.header), E);
    const genesis = headerSync.getHeaderByHeight(0)!;
    const bs = new BlockSync(db, REGTEST, headerSync, mockPeerManager([E]), {
      getBestBlock: () => ({ hash: genesis.hash, height: 0, chainWork: genesis.chainWork }),
    } as any);
    (bs as any).running = true;
    (bs as any).processOrderedBlocks = async () => {};
    bs.getState().nextHeightToProcess = 1;
    bs.getState().nextHeightToRequest = 1;
    bs.requestBlocks();
    const h1 = getBlockHash(chain[0].header);
    const h1hex = h1.toString("hex");
    expect(bs.getState().pendingBlocks.get(h1hex)?.peer).toBe("127.0.0.2:1");

    // H connects; E serves block 1 witness-stripped.
    (bs as any).peerManager = mockPeerManager([E, H]);
    await bs.handleBlock(E, stripped(chain[0]));

    expect(E.misbehaving).toHaveBeenCalledTimes(1);
    expect(E.misbehaving.mock.calls[0][1]).toMatch(/mutated block: bad-witness-nonce-size/);
    expect(bs.getState().downloadedBlocks.has(h1hex)).toBe(false);
    expect(headerSync.getHeader(h1)!.status).not.toBe("invalid");
    // Re-requested from the honest peer at once (E's requests freed).
    expect(bs.getState().pendingBlocks.get(h1hex)?.peer).toBe("127.0.0.3:2");
    expect(getdataFor(H, h1)).toBe(1);

    // The honest body is accepted.
    await bs.handleBlock(H, chain[0]);
    expect(H.misbehaving).not.toHaveBeenCalled();
    expect(bs.getState().downloadedBlocks.has(h1hex)).toBe(true);
    await bs.stop();
  });

  test("BBH: a valid block before its header (parent known) is accepted, sender not punished", async () => {
    const chain = chainOf(2);
    const P = mockPeer("127.0.0.3", 3);
    await headerSync.processHeaders([chain[0].header], P);
    const genesis = headerSync.getHeaderByHeight(0)!;
    const bs = new BlockSync(db, REGTEST, headerSync, mockPeerManager([P]), {
      getBestBlock: () => ({ hash: genesis.hash, height: 0, chainWork: genesis.chainWork }),
    } as any);
    let ordered = 0;
    (bs as any).processOrderedBlocks = async () => { ordered++; };
    bs.getState().nextHeightToProcess = 2;
    bs.getState().nextHeightToRequest = 3;

    const h2 = getBlockHash(chain[1].header);
    expect(headerSync.getHeader(h2)).toBeUndefined();
    await bs.handleBlock(P, chain[1]);
    expect(P.misbehaving).not.toHaveBeenCalled();
    expect(headerSync.getHeader(h2)?.height).toBe(2);
    expect(bs.getState().downloadedBlocks.has(h2.toString("hex"))).toBe(true);
    expect(ordered).toBe(1);
    await bs.stop();
  });

  test("a block whose parent is unknown still punishes (Core BLOCK_MISSING_PREV)", async () => {
    const chain = chainOf(2);
    const P = mockPeer("127.0.0.3", 4);
    const genesis = headerSync.getHeaderByHeight(0)!;
    const bs = new BlockSync(db, REGTEST, headerSync, mockPeerManager([P]), {
      getBestBlock: () => ({ hash: genesis.hash, height: 0, chainWork: genesis.chainWork }),
    } as any);
    (bs as any).processOrderedBlocks = async () => {};
    await bs.handleBlock(P, chain[1]); // parent (block 1) never seen
    expect(P.misbehaving).toHaveBeenCalledTimes(1);
    expect(headerSync.getHeader(getBlockHash(chain[1].header))).toBeUndefined();
    await bs.stop();
  });
});
