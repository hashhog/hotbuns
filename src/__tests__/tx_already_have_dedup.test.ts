/**
 * AlreadyHaveTx dedup + tx-request in-flight tracker.
 *
 * Pins the Core-shaped transaction dedup surface added to BlockSync:
 *
 *   (A) AlreadyHaveTx — orphanage / recent-rejects / recent-confirmed /
 *       mempool, all O(1). Core: TxDownloadManagerImpl::AlreadyHaveTx
 *       (bitcoin-core/src/node/txdownloadman_impl.cpp:125-147).
 *   (B) The in-flight request tracker's DRAINERS. Before this wave
 *       `clearTxRequestInFlight` and `markTxRejected` had zero callers
 *       anywhere in the tree, so the map only ever grew and only ever
 *       shed the single key a later announcement happened to re-probe.
 *       Core drains on every outcome: ReceivedTx / ReceivedNotFound /
 *       MempoolAcceptedTx / MempoolRejectedTx / BlockConnected.
 *   (C) The UNCONDITIONAL expiry sweep. A marker for a tx announced exactly
 *       once and never again was previously immortal, because the only
 *       pruning path was inside `isTxRequestInFlight(hashHex)` — i.e. it
 *       pruned a key only when asked about that same key. Core expires on
 *       every GetRequestable pass regardless of lookups.
 *   (D) The wtxid mempool index — MSG_WTX inv resolution used to be a full
 *       mempool scan that re-serialized and double-SHA256'd every entry.
 *
 * Reference: bitcoin-core/src/node/txdownloadman_impl.cpp,
 * bitcoin-core/src/txmempool.h (index_by_wtxid).
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
import { OrphanPool } from "../mempool/orphan_pool.js";

/** Minimal spendable-shaped tx; only its hashes matter here. */
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

/** Fake mempool mirroring the real one's txid map + wtxid index. */
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

/** Same, but with a witness so wtxid !== txid. */
function makeSegwitTx(seq: number): Transaction {
  const tx = makeTx(seq);
  tx.inputs[0].scriptSig = Buffer.alloc(0);
  tx.inputs[0].witness = [Buffer.from([0x01]), Buffer.from([0x51])];
  return tx;
}

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

describe("AlreadyHaveTx dedup + tx-request in-flight tracker", () => {
  let dataDir: string;
  let db: ChainDB;
  let headerSync: HeaderSync;

  beforeEach(async () => {
    dataDir = await mkdtemp(join(tmpdir(), "hotbuns-alreadyhave-"));
    db = new ChainDB(join(dataDir, "blocks.db"));
    await db.open();
    headerSync = new HeaderSync(db, MAINNET);
  });

  afterEach(async () => {
    await db.close();
    await rm(dataDir, { recursive: true, force: true });
  });

  function makeSync(txsInMempool: Transaction[] = []): any {
    const sync = new BlockSync(db, MAINNET, headerSync) as any;
    sync.ibdComplete = true; // post-IBD gate — required for tx invs
    sync.setMempool(makeMempool(txsInMempool) as any);
    return sync;
  }

  // -------------------------------------------------------------------------
  // (A) AlreadyHaveTx sources
  // -------------------------------------------------------------------------

  test("alreadyHaveTx is false for a wholly unknown tx", () => {
    const sync = makeSync();
    const tx = makeTx(1);
    expect(
      sync.alreadyHaveTx(
        getTxId(tx).toString("hex"),
        getWTxId(tx).toString("hex")
      )
    ).toBe(false);
  });

  test("alreadyHaveTx hits on the mempool (by txid)", () => {
    const tx = makeTx(2);
    const sync = makeSync([tx]);
    expect(
      sync.alreadyHaveTx(
        getTxId(tx).toString("hex"),
        getWTxId(tx).toString("hex")
      )
    ).toBe(true);
  });

  test("alreadyHaveTx hits on the recent-rejects filter", () => {
    const sync = makeSync();
    const tx = makeTx(3);
    const txidHex = getTxId(tx).toString("hex");
    const wtxidHex = getWTxId(tx).toString("hex");
    sync.markTxRejected(txidHex, wtxidHex);
    expect(sync.alreadyHaveTx(txidHex, wtxidHex)).toBe(true);
  });

  test("alreadyHaveTx hits on the recent-confirmed filter after a block connects", () => {
    const sync = makeSync();
    const tx = makeTx(4);
    const txidHex = getTxId(tx).toString("hex");
    const wtxidHex = getWTxId(tx).toString("hex");
    expect(sync.alreadyHaveTx(txidHex, wtxidHex)).toBe(false);
    sync.markTxsConfirmed([{ txidHex, wtxidHex }]);
    expect(sync.alreadyHaveTx(txidHex, wtxidHex)).toBe(true);
  });

  test("a reorg clears recent-confirmed (Core BlockDisconnected resets the filter)", () => {
    const sync = makeSync();
    const tx = makeTx(5);
    const txidHex = getTxId(tx).toString("hex");
    const wtxidHex = getWTxId(tx).toString("hex");
    sync.markTxsConfirmed([{ txidHex, wtxidHex }]);
    expect(sync.alreadyHaveTx(txidHex, wtxidHex)).toBe(true);
    sync.onBlockDisconnected();
    // Must become downloadable again — the tx is unconfirmed once more.
    expect(sync.alreadyHaveTx(txidHex, wtxidHex)).toBe(false);
  });

  test("a new tip clears recent-rejects (Core ActiveTipChange)", () => {
    const sync = makeSync();
    const tx = makeTx(20);
    const txidHex = getTxId(tx).toString("hex");
    const wtxidHex = getWTxId(tx).toString("hex");
    // Most rejections are height-dependent policy (min fee, non-final
    // locktime, ancestor limits) — a new tip must make the tx downloadable
    // again, or a transient reject becomes a permanent blacklist.
    sync.markTxRejected(txidHex, wtxidHex);
    expect(sync.alreadyHaveTx(txidHex, wtxidHex)).toBe(true);
    sync.onActiveTipChange();
    expect(sync.alreadyHaveTx(txidHex, wtxidHex)).toBe(false);
  });

  test("a reorg clears recent-rejects as well as recent-confirmed", () => {
    const sync = makeSync();
    const rejected = makeTx(21);
    const confirmed = makeTx(22);
    sync.markTxRejected(
      getTxId(rejected).toString("hex"),
      getWTxId(rejected).toString("hex")
    );
    sync.markTxsConfirmed([
      {
        txidHex: getTxId(confirmed).toString("hex"),
        wtxidHex: getWTxId(confirmed).toString("hex"),
      },
    ]);
    sync.onBlockDisconnected();
    for (const tx of [rejected, confirmed]) {
      expect(
        sync.alreadyHaveTx(
          getTxId(tx).toString("hex"),
          getWTxId(tx).toString("hex")
        )
      ).toBe(false);
    }
  });

  test("alreadyHaveTx hits on the orphan pool", () => {
    const sync = makeSync();
    const orphans = new OrphanPool();
    sync.setOrphanPool(orphans);
    const tx = makeTx(6);
    const txidHex = getTxId(tx).toString("hex");
    const wtxidHex = getWTxId(tx).toString("hex");
    expect(sync.alreadyHaveTx(txidHex, wtxidHex)).toBe(false);
    expect(orphans.add(tx, "peer-1").ok).toBe(true);
    expect(sync.alreadyHaveTx(txidHex, wtxidHex)).toBe(true);
  });

  // -------------------------------------------------------------------------
  // (A') The announcement path uses the same sources
  // -------------------------------------------------------------------------

  test("handleInv emits NO getdata for a tx we recently confirmed", async () => {
    const sync = makeSync();
    const tx = makeTx(7);
    const txid = getTxId(tx);
    sync.markTxsConfirmed([
      { txidHex: txid.toString("hex"), wtxidHex: getWTxId(tx).toString("hex") },
    ]);
    const { peer, sent } = makePeer();
    await sync.handleInv(peer, [{ type: InvType.MSG_TX, hash: txid }]);
    expect(sent.filter((m) => m.type === "getdata").length).toBe(0);
  });

  test("handleInv emits NO getdata for a tx sitting in the orphan pool", async () => {
    const sync = makeSync();
    const orphans = new OrphanPool();
    sync.setOrphanPool(orphans);
    const tx = makeTx(8);
    expect(orphans.add(tx, "peer-1").ok).toBe(true);
    const { peer, sent } = makePeer({ wtxidRelay: true });
    await sync.handleInv(peer, [{ type: InvType.MSG_WTX, hash: getWTxId(tx) }]);
    expect(sent.filter((m) => m.type === "getdata").length).toBe(0);
  });

  // -------------------------------------------------------------------------
  // (B) Drainers
  // -------------------------------------------------------------------------

  test("an inv marks the request in flight and a second announcement is suppressed", async () => {
    const sync = makeSync();
    const tx = makeTx(9);
    const txid = getTxId(tx);
    const a = makePeer();
    const b = makePeer({ host: "10.0.0.10" });

    await sync.handleInv(a.peer, [{ type: InvType.MSG_TX, hash: txid }]);
    expect(a.sent.filter((m) => m.type === "getdata").length).toBe(1);
    expect(sync.getTxRequestInFlightCount()).toBe(1);

    await sync.handleInv(b.peer, [{ type: InvType.MSG_TX, hash: txid }]);
    expect(b.sent.filter((m) => m.type === "getdata").length).toBe(0);
  });

  test("clearTxRequestInFlight drains on delivery (Core ReceivedTx)", async () => {
    const sync = makeSync();
    const tx = makeTx(10);
    const txidHex = getTxId(tx).toString("hex");
    const wtxidHex = getWTxId(tx).toString("hex");
    const { peer } = makePeer();
    await sync.handleInv(peer, [{ type: InvType.MSG_TX, hash: getTxId(tx) }]);
    expect(sync.getTxRequestInFlightCount()).toBe(1);
    sync.clearTxRequestInFlight(txidHex, wtxidHex);
    expect(sync.getTxRequestInFlightCount()).toBe(0);
  });

  test("onMempoolAcceptedTx drains both hash forms (Core MempoolAcceptedTx)", async () => {
    const sync = makeSync();
    const tx = makeSegwitTx(11);
    const txidHex = getTxId(tx).toString("hex");
    const wtxidHex = getWTxId(tx).toString("hex");
    expect(wtxidHex).not.toBe(txidHex);
    // Simulate one peer announcing by txid and another by wtxid: two markers.
    const a = makePeer();
    const b = makePeer({ host: "10.0.0.11", wtxidRelay: true });
    await sync.handleInv(a.peer, [{ type: InvType.MSG_TX, hash: getTxId(tx) }]);
    await sync.handleInv(b.peer, [{ type: InvType.MSG_WTX, hash: getWTxId(tx) }]);
    expect(sync.getTxRequestInFlightCount()).toBe(2);
    sync.onMempoolAcceptedTx(txidHex, wtxidHex);
    expect(sync.getTxRequestInFlightCount()).toBe(0);
  });

  test("markTxRejected drains AND blocks re-request", async () => {
    const sync = makeSync();
    const tx = makeTx(12);
    const txid = getTxId(tx);
    const a = makePeer();
    await sync.handleInv(a.peer, [{ type: InvType.MSG_TX, hash: txid }]);
    expect(sync.getTxRequestInFlightCount()).toBe(1);

    sync.markTxRejected(txid.toString("hex"), getWTxId(tx).toString("hex"));
    expect(sync.getTxRequestInFlightCount()).toBe(0);

    const b = makePeer({ host: "10.0.0.12" });
    await sync.handleInv(b.peer, [{ type: InvType.MSG_TX, hash: txid }]);
    expect(b.sent.filter((m) => m.type === "getdata").length).toBe(0);
  });

  test("notfound for a tx frees the marker so another peer can be asked", async () => {
    const sync = makeSync();
    const peerManager = {
      handlers: new Map<string, Function>(),
      onMessage(type: string, fn: Function) {
        this.handlers.set(type, fn);
      },
      emit(type: string, peer: unknown, msg: unknown) {
        this.handlers.get(type)?.(peer, msg);
      },
    };
    sync.registerWithPeerManager(peerManager as any);

    const tx = makeTx(13);
    const txid = getTxId(tx);
    const a = makePeer();
    await sync.handleInv(a.peer, [{ type: InvType.MSG_TX, hash: txid }]);
    expect(sync.getTxRequestInFlightCount()).toBe(1);

    peerManager.emit("notfound", a.peer, {
      type: "notfound",
      payload: { inventory: [{ type: InvType.MSG_TX, hash: txid }] },
    });
    expect(sync.getTxRequestInFlightCount()).toBe(0);

    const b = makePeer({ host: "10.0.0.13" });
    await sync.handleInv(b.peer, [{ type: InvType.MSG_TX, hash: txid }]);
    expect(b.sent.filter((m) => m.type === "getdata").length).toBe(1);
  });

  test("markTxsConfirmed drains in-flight markers for the mined txs", async () => {
    const sync = makeSync();
    const tx = makeTx(14);
    const { peer } = makePeer();
    await sync.handleInv(peer, [{ type: InvType.MSG_TX, hash: getTxId(tx) }]);
    expect(sync.getTxRequestInFlightCount()).toBe(1);
    sync.markTxsConfirmed([
      {
        txidHex: getTxId(tx).toString("hex"),
        wtxidHex: getWTxId(tx).toString("hex"),
      },
    ]);
    expect(sync.getTxRequestInFlightCount()).toBe(0);
  });

  // -------------------------------------------------------------------------
  // (C) Unconditional expiry sweep
  // -------------------------------------------------------------------------

  test("the sweep expires a marker that is NEVER looked up again", async () => {
    const sync = makeSync();
    const tx = makeTx(15);
    const { peer } = makePeer();
    await sync.handleInv(peer, [{ type: InvType.MSG_TX, hash: getTxId(tx) }]);
    expect(sync.getTxRequestInFlightCount()).toBe(1);

    // Nothing ever probes this hash again — the old opportunistic prune
    // inside isTxRequestInFlight() could not reach it, so it leaked.
    const wayLater = Date.now() + 10 * 60_000;
    expect(sync.sweepTxRequestsInFlight(wayLater)).toBe(1);
    expect(sync.getTxRequestInFlightCount()).toBe(0);
  });

  test("the sweep keeps markers that are still inside the expiry window", async () => {
    const sync = makeSync();
    const { peer } = makePeer();
    await sync.handleInv(peer, [
      { type: InvType.MSG_TX, hash: getTxId(makeTx(16)) },
    ]);
    // +10s, well under the 60s TX_REQUEST_EXPIRY_MS.
    expect(sync.sweepTxRequestsInFlight(Date.now() + 10_000)).toBe(0);
    expect(sync.getTxRequestInFlightCount()).toBe(1);
  });

  test("the sweep is rate-limited so it cannot run on every 1s tick", async () => {
    const sync = makeSync();
    const { peer } = makePeer();
    await sync.handleInv(peer, [
      { type: InvType.MSG_TX, hash: getTxId(makeTx(17)) },
    ]);
    const t0 = Date.now() + 10 * 60_000;
    expect(sync.sweepTxRequestsInFlight(t0)).toBe(1);
    // Immediately after, a second call is a no-op (returns 0 without scanning).
    await sync.handleInv(peer, [
      { type: InvType.MSG_TX, hash: getTxId(makeTx(18)) },
    ]);
    expect(sync.sweepTxRequestsInFlight(t0 + 1)).toBe(0);
    expect(sync.getTxRequestInFlightCount()).toBe(1);
  });

  test("the hard cap evicts oldest-first when the tick has been starved", () => {
    const sync = makeSync();
    // Fill past MAX_TX_INFLIGHT (50_000) with non-expired markers, so only the
    // size backstop — not time-based expiry — can bring the map back down.
    const now = Date.now();
    const map: Map<string, number> = sync.requestedTxInFlight;
    for (let i = 0; i < 50_010; i++) {
      map.set(i.toString(16).padStart(64, "0"), now);
    }
    expect(sync.getTxRequestInFlightCount()).toBe(50_010);
    // now + 1ms: nothing is time-expired (expiry is 60s), so every drop here
    // comes from the cap.
    expect(sync.sweepTxRequestsInFlight(now + 1)).toBe(10);
    expect(sync.getTxRequestInFlightCount()).toBe(50_000);
    // Oldest (first-inserted) went first.
    expect(map.has((0).toString(16).padStart(64, "0"))).toBe(false);
    expect(map.has((50_009).toString(16).padStart(64, "0"))).toBe(true);
  });

  // -------------------------------------------------------------------------
  // (D) O(1) wtxid resolution
  // -------------------------------------------------------------------------

  test("MSG_WTX inv resolves through the wtxid index, not a mempool rescan", async () => {
    const tx = makeTx(19);
    const sync = makeSync([tx]);
    const { peer, sent } = makePeer({ wtxidRelay: true });
    // Already in the mempool → AlreadyHaveTx via the wtxid index → no getdata.
    await sync.handleInv(peer, [{ type: InvType.MSG_WTX, hash: getWTxId(tx) }]);
    expect(sent.filter((m) => m.type === "getdata").length).toBe(0);
    // And the serve path finds it by wtxid too.
    await sync.handleGetData(peer, [
      { type: InvType.MSG_WTX, hash: getWTxId(tx) },
    ]);
    expect(sent.filter((m) => m.type === "tx").length).toBe(1);
    expect(sent.filter((m) => m.type === "notfound").length).toBe(0);
  });
});
