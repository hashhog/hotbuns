/**
 * Message-level tests for the classic inv->getdata->tx relay loop.
 *
 * hotbuns previously ANNOUNCED txs but never REQUESTED (handleInv ignored
 * tx invs) nor SERVED (handleGetData served only blocks) individual txs.
 * These tests pin down both newly-added P2P paths in src/sync/blocks.ts:
 *
 *   (a) REQUEST: handleInv on a tx-inv for an unknown tx emits a getdata
 *       echoing the announced inv type; a tx already in the mempool emits
 *       nothing.
 *   (b) SERVE: handleGetData for a tx in the mempool sends a `tx` message;
 *       a miss sends a `notfound`.
 *
 * Reference: bitcoin-core net_processing.cpp ProcessMessage(INV) tx branch
 * (~L4079) and ProcessGetData -> FindTxForGetData (~L2494).
 */

import { describe, expect, test, beforeEach, afterEach } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { ChainDB } from "../storage/database.js";
import { BlockSync } from "../sync/blocks.js";
import { HeaderSync } from "../sync/headers.js";
import { MAINNET } from "../consensus/params.js";
import { InvType } from "../p2p/messages.js";
import type { NetworkMessage } from "../p2p/messages.js";
import { getTxId, getWTxId } from "../validation/tx.js";
import type { Transaction } from "../validation/tx.js";

// A minimal (non-witness) transaction — enough for txid/wtxid computation.
function makeTx(seq: number): Transaction {
  return {
    version: 2,
    inputs: [
      {
        prevOut: { txid: Buffer.alloc(32, seq & 0xff), vout: seq },
        scriptSig: Buffer.from([0x51]),
        sequence: 0xffffffff,
        witness: [],
      },
    ],
    outputs: [{ value: 1000n, scriptPubKey: Buffer.from([0x51]) }],
    lockTime: 0,
  };
}

// Fake mempool exposing just the surface findMempoolTxForInv / alreadyHaveTx
// use. Mirrors the real Mempool's txid map AND its wtxid index — the wtxid
// lookup is an O(1) index probe now, not a linear rescan of every entry.
function makeMempool(txs: Transaction[]) {
  const byTxid = new Map<string, Transaction>();
  const byWtxid = new Map<string, string>();
  for (const tx of txs) {
    const txidHex = getTxId(tx).toString("hex");
    byTxid.set(txidHex, tx);
    byWtxid.set(getWTxId(tx).toString("hex"), txidHex);
  }
  return {
    getTransaction(txid: Buffer) {
      const tx = byTxid.get(txid.toString("hex"));
      return tx ? { tx } : null;
    },
    getAllTxids(): Buffer[] {
      return Array.from(byTxid.keys()).map((h) => Buffer.from(h, "hex"));
    },
    hasTxidHex(txidHex: string): boolean {
      return byTxid.has(txidHex);
    },
    hasWtxidHex(wtxidHex: string): boolean {
      return byWtxid.has(wtxidHex);
    },
    getTransactionByWtxidHex(wtxidHex: string) {
      const txidHex = byWtxid.get(wtxidHex);
      if (txidHex === undefined) return null;
      const tx = byTxid.get(txidHex);
      return tx ? { tx } : null;
    },
  };
}

// Fake peer that records every message it is asked to send.
function makePeer(overrides: Record<string, unknown> = {}) {
  const sent: NetworkMessage[] = [];
  const peer = {
    host: "10.0.0.9",
    port: 8333,
    connType: "full_relay",
    wtxidRelay: false,
    send(msg: NetworkMessage) {
      sent.push(msg);
    },
    ...overrides,
  };
  return { peer, sent };
}

describe("tx inv->getdata->tx relay loop", () => {
  let dataDir: string;
  let db: ChainDB;
  let headerSync: HeaderSync;

  beforeEach(async () => {
    dataDir = await mkdtemp(join(tmpdir(), "hotbuns-txrelay-"));
    db = new ChainDB(join(dataDir, "blocks.db"));
    await db.open();
    headerSync = new HeaderSync(db, MAINNET);
  });

  afterEach(async () => {
    await db.close();
    await rm(dataDir, { recursive: true, force: true });
  });

  function makeSync(txsInMempool: Transaction[]): any {
    const sync = new BlockSync(db, MAINNET, headerSync) as any;
    sync.ibdComplete = true; // post-IBD gate — required for tx invs
    sync.setMempool(makeMempool(txsInMempool) as any);
    return sync;
  }

  test("(a) handleInv on unknown tx-inv emits a getdata for it", async () => {
    const sync = makeSync([]);
    const tx = makeTx(1);
    const txid = getTxId(tx);
    const { peer, sent } = makePeer(); // wtxidRelay = false → MSG_TX

    await sync.handleInv(peer, [{ type: InvType.MSG_TX, hash: txid }]);

    const getdatas = sent.filter((m) => m.type === "getdata");
    expect(getdatas.length).toBe(1);
    const inv = (getdatas[0].payload as any).inventory;
    expect(inv.length).toBe(1);
    expect(inv[0].type).toBe(InvType.MSG_TX);
    expect(inv[0].hash.equals(txid)).toBe(true);
  });

  test("(a) handleInv echoes MSG_WTX for a wtxidrelay peer", async () => {
    const sync = makeSync([]);
    const tx = makeTx(2);
    const wtxid = getWTxId(tx);
    const { peer, sent } = makePeer({ wtxidRelay: true });

    await sync.handleInv(peer, [{ type: InvType.MSG_WTX, hash: wtxid }]);

    const getdatas = sent.filter((m) => m.type === "getdata");
    expect(getdatas.length).toBe(1);
    expect((getdatas[0].payload as any).inventory[0].type).toBe(InvType.MSG_WTX);
  });

  test("(a) handleInv emits NO getdata for a tx already in the mempool", async () => {
    const tx = makeTx(3);
    const txid = getTxId(tx);
    const sync = makeSync([tx]); // already present
    const { peer, sent } = makePeer();

    await sync.handleInv(peer, [{ type: InvType.MSG_TX, hash: txid }]);

    expect(sent.filter((m) => m.type === "getdata").length).toBe(0);
  });

  test("(a) handleInv dedups a tx announced by two peers into ONE getdata", async () => {
    const sync = makeSync([]);
    const tx = makeTx(4);
    const txid = getTxId(tx);
    const a = makePeer();
    const b = makePeer({ host: "10.0.0.10" });

    await sync.handleInv(a.peer, [{ type: InvType.MSG_TX, hash: txid }]);
    await sync.handleInv(b.peer, [{ type: InvType.MSG_TX, hash: txid }]);

    expect(a.sent.filter((m) => m.type === "getdata").length).toBe(1);
    expect(b.sent.filter((m) => m.type === "getdata").length).toBe(0);
  });

  test("(a) block-relay-only peers never trigger a tx getdata", async () => {
    const sync = makeSync([]);
    const tx = makeTx(5);
    const txid = getTxId(tx);
    const { peer, sent } = makePeer({ connType: "block_relay" });

    await sync.handleInv(peer, [{ type: InvType.MSG_TX, hash: txid }]);

    expect(sent.filter((m) => m.type === "getdata").length).toBe(0);
  });

  test("(b) handleGetData serves a mempool tx as a `tx` message", async () => {
    const tx = makeTx(6);
    const txid = getTxId(tx);
    const sync = makeSync([tx]);
    const { peer, sent } = makePeer();

    await sync.handleGetData(peer, [{ type: InvType.MSG_TX, hash: txid }]);

    const txMsgs = sent.filter((m) => m.type === "tx");
    expect(txMsgs.length).toBe(1);
    expect(getTxId((txMsgs[0].payload as any).tx).equals(txid)).toBe(true);
    expect(sent.some((m) => m.type === "notfound")).toBe(false);
  });

  test("(b) handleGetData serves a mempool tx by wtxid (MSG_WTX)", async () => {
    const tx = makeTx(7);
    const wtxid = getWTxId(tx);
    const sync = makeSync([tx]);
    const { peer, sent } = makePeer();

    await sync.handleGetData(peer, [{ type: InvType.MSG_WTX, hash: wtxid }]);

    expect(sent.filter((m) => m.type === "tx").length).toBe(1);
  });

  test("(b) handleGetData sends notfound for a tx not in the mempool", async () => {
    const sync = makeSync([]);
    const missing = getTxId(makeTx(8));
    const { peer, sent } = makePeer();

    await sync.handleGetData(peer, [{ type: InvType.MSG_TX, hash: missing }]);

    expect(sent.filter((m) => m.type === "tx").length).toBe(0);
    const nf = sent.filter((m) => m.type === "notfound");
    expect(nf.length).toBe(1);
    expect((nf[0].payload as any).inventory[0].hash.equals(missing)).toBe(true);
  });
});
