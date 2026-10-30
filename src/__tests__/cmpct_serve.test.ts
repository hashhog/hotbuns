/**
 * Serving BIP-152 compact blocks (item done-hotbuns-cmpct-serve).
 *
 * Core ProcessGetBlockData (IsMsgCmpctBlk arm): getdata(MSG_CMPCT_BLOCK) for a
 * block within MAX_CMPCTBLOCK_DEPTH (5) of the tip is answered with a
 * cmpctblock, deeper with the full block. ProcessGetBlockTxn: getblocktxn
 * within MAX_BLOCKTXN_DEPTH (10) is answered with blocktxn, deeper with the
 * full block, an out-of-range index with nothing.
 */
import { describe, expect, test, beforeEach, afterEach } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { ChainDB } from "../storage/database.js";
import { BlockSync } from "../sync/blocks.js";
import { HeaderSync } from "../sync/headers.js";
import { REGTEST } from "../consensus/params.js";
import { InvType, serializeMessage, deserializeMessage, parseHeader, MESSAGE_HEADER_SIZE } from "../p2p/messages.js";
import type { NetworkMessage } from "../p2p/messages.js";
import { serializeBlock, getBlockHash, serializeBlockHeader } from "../validation/block.js";
import type { Block } from "../validation/block.js";
import { getWTxId } from "../validation/tx.js";
import type { Transaction } from "../validation/tx.js";
import { deriveSipHashKeys, computeShortTxId } from "../p2p/compact_blocks.js";

function stubPeer() {
  const sent: NetworkMessage[] = [];
  const peer: any = {
    host: "127.0.0.1",
    port: 1,
    send(msg: NetworkMessage) {
      sent.push(msg);
      return true;
    },
  };
  return { peer, sent };
}

function mkTx(id: number): Transaction {
  return {
    version: 2,
    inputs: [{
      prevOut: { txid: Buffer.alloc(32, id), vout: 0 },
      scriptSig: Buffer.from([0x00]),
      sequence: 0xffffffff,
      witness: [Buffer.alloc(33, id)],
    }],
    outputs: [{ value: 1000n, scriptPubKey: Buffer.from([0x51]) }],
    lockTime: 0,
  };
}

/** A 4-tx block: coinbase + 3 spends. Header contents are irrelevant to serving. */
function mkBlock(): Block {
  const txs = [mkTx(0), mkTx(1), mkTx(2), mkTx(3)];
  return {
    header: {
      version: 0x20000000,
      prevBlock: Buffer.alloc(32, 7),
      merkleRoot: Buffer.alloc(32, 9),
      timestamp: 1700000000,
      bits: 0x207fffff,
      nonce: 42,
    },
    transactions: txs,
  } as Block;
}

describe("serve cmpctblock / blocktxn", () => {
  let dataDir: string;
  let db: ChainDB;
  let sync: any;
  let block: Block;
  let hash: Buffer;
  const TIP = 100;

  function placeAtDepth(depth: number) {
    const h = TIP - depth;
    (sync.headerSync as any).getHeader = (x: Buffer) =>
      x.equals(hash) ? { height: h } : undefined;
  }

  beforeEach(async () => {
    dataDir = await mkdtemp(join(tmpdir(), "hotbuns-cmpct-serve-"));
    db = new ChainDB(join(dataDir, "blocks.db"));
    await db.open();
    sync = new BlockSync(db, REGTEST, new HeaderSync(db, REGTEST)) as any;
    sync.state.nextHeightToProcess = TIP + 1;
    block = mkBlock();
    hash = getBlockHash(block.header);
    await db.putBlock(hash, serializeBlock(block));
  });

  afterEach(async () => {
    await db.close();
    await rm(dataDir, { recursive: true, force: true });
  });

  test("getdata(MSG_CMPCT_BLOCK) at the tip -> cmpctblock with Core's short IDs", async () => {
    placeAtDepth(0);
    const { peer, sent } = stubPeer();
    await sync.handleGetData(peer, [{ type: InvType.MSG_CMPCT_BLOCK, hash }]);
    expect(sent.map((m) => m.type)).toEqual(["cmpctblock"]);
    const p: any = sent[0].payload;
    expect(p.header).toEqual(block.header);
    expect(p.prefilledTxns.map((t: any) => t.index)).toEqual([0]);
    expect(p.shortIds.length).toBe(3);
    // BIP-152: key = SHA256(header || nonce), id = SipHash-2-4(wtxid) & 48 bits
    const [k0, k1] = deriveSipHashKeys(serializeBlockHeader(block.header), p.nonce);
    block.transactions.slice(1).forEach((tx, i) => {
      expect(p.shortIds[i].equals(computeShortTxId(k0, k1, getWTxId(tx)))).toBe(true);
    });
    // must survive the wire round trip
    const wire = serializeMessage(REGTEST.networkMagic, sent[0]);
    const back: any = deserializeMessage(parseHeader(wire.subarray(0, MESSAGE_HEADER_SIZE)), wire.subarray(MESSAGE_HEADER_SIZE));
    expect(back.payload.shortIds.length).toBe(3);
  });

  test("getdata(MSG_CMPCT_BLOCK) at MAX_CMPCTBLOCK_DEPTH -> cmpctblock, one deeper -> full block", async () => {
    placeAtDepth(5);
    let r = stubPeer();
    await sync.handleGetData(r.peer, [{ type: InvType.MSG_CMPCT_BLOCK, hash }]);
    expect(r.sent.map((m) => m.type)).toEqual(["cmpctblock"]);
    placeAtDepth(6);
    r = stubPeer();
    await sync.handleGetData(r.peer, [{ type: InvType.MSG_CMPCT_BLOCK, hash }]);
    // A full block is served as its stored bytes under the `block` command
    // (audit H1); see getdata-serve-queue.test.ts for the wire identity.
    expect(r.sent.map((m) => m.type)).toEqual(["rawblock"]);
  });

  test("getdata(MSG_WITNESS_BLOCK) is still a full block", async () => {
    placeAtDepth(0);
    const { peer, sent } = stubPeer();
    await sync.handleGetData(peer, [{ type: InvType.MSG_WITNESS_BLOCK, hash }]);
    expect(sent.map((m) => m.type)).toEqual(["rawblock"]);
  });

  test("getblocktxn within depth -> blocktxn with exactly the requested txs", async () => {
    placeAtDepth(10);
    const { peer, sent } = stubPeer();
    await sync.handleGetBlockTxn(peer, { blockHash: hash, indexes: [1, 3] });
    expect(sent.map((m) => m.type)).toEqual(["blocktxn"]);
    const p: any = sent[0].payload;
    expect(p.blockHash.equals(hash)).toBe(true);
    expect(p.transactions.map((t: Transaction) => getWTxId(t).toString("hex"))).toEqual(
      [1, 3].map((i) => getWTxId(block.transactions[i]).toString("hex")),
    );
  });

  test("getblocktxn deeper than MAX_BLOCKTXN_DEPTH -> full block", async () => {
    placeAtDepth(11);
    const { peer, sent } = stubPeer();
    await sync.handleGetBlockTxn(peer, { blockHash: hash, indexes: [1] });
    expect(sent.map((m) => m.type)).toEqual(["block"]);
  });

  test("getblocktxn with an out-of-range index or unknown block -> no reply", async () => {
    placeAtDepth(0);
    let r = stubPeer();
    await sync.handleGetBlockTxn(r.peer, { blockHash: hash, indexes: [4] });
    expect(r.sent.length).toBe(0);
    r = stubPeer();
    await sync.handleGetBlockTxn(r.peer, { blockHash: Buffer.alloc(32, 0xee), indexes: [0] });
    expect(r.sent.length).toBe(0);
  });
});

describe("sendrawtransaction relay honors the peer's feefilter", () => {
  test("broadcastTxInv skips a peer whose feefilter exceeds the tx feerate", async () => {
    const { RPCServer } = await import("../rpc/server.js");
    const sent: string[] = [];
    const mk = (name: string, ff: bigint) => ({
      wtxidRelay: true, feeFilterReceived: ff,
      send: () => { sent.push(name); return true; },
    });
    const fake: any = {
      mempool: { getTransaction: () => ({ feeRate: 2 }) },
      peerManager: { getConnectedPeers: () => [mk("none", 0n), mk("low", 1000n), mk("high", 1_000_000n)] },
    };
    (RPCServer.prototype as any).broadcastTxInv.call(fake, Buffer.alloc(32, 1));
    expect(sent).toEqual(["none", "low"]);
  });
});
