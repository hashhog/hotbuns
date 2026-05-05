/**
 * Unit tests for the P2P `tx` message handler wired in cli.ts.
 *
 * The handler is the entry point that closes the "tx-relay black hole"
 * finding from the wave-45a mempool audit (commit cc44813).  It was
 * present in cli.ts since 8f2f477 (2026-04-09) but was missing an
 * IBD-skip gate.  The gate was added in the wave-45a fix wave
 * (feat(p2p): add IBD-skip gate to P2P tx-message handler).
 *
 * Reference: bitcoin-core/src/net_processing.cpp ProcessMessage(NetMsgType::TX)
 *   line 4395: if (m_chainman.IsInitialBlockDownload()) return;
 *
 * These tests simulate the handler logic directly — they do NOT start a
 * full node, but exercise the three observable behaviors:
 *   1. IBD skip  — acceptToMemoryPool NOT called during IBD
 *   2. Accept     — acceptToMemoryPool called and relay triggered post-IBD
 *   3. Reject     — acceptToMemoryPool called but relay NOT triggered
 */

import { describe, it, expect, beforeEach } from "bun:test";
import type { Transaction } from "../validation/tx.js";
import { getTxId } from "../validation/tx.js";
import { InventoryRelay } from "../p2p/relay.js";
import type { InvVector } from "../p2p/messages.js";
import type { Peer } from "../p2p/peer.js";

// ---------------------------------------------------------------------------
// Minimal stubs
// ---------------------------------------------------------------------------

function makePeer(host = "127.0.0.1", port = 18444): Peer {
  return {
    host,
    port,
    state: "connected",
    services: 0n,
    version: 70016,
    feeFilterReceived: 0,
    send: () => {},
    disconnect: () => {},
  } as unknown as Peer;
}

function makeTestTx(): Transaction {
  return {
    version: 2,
    inputs: [
      {
        prevOut: { txid: Buffer.alloc(32, 0xcc), vout: 0 },
        scriptSig: Buffer.alloc(0),
        sequence: 0xffffffff,
        witness: [Buffer.alloc(71, 0x30), Buffer.alloc(33, 0x02)],
      },
    ],
    outputs: [
      {
        value: 50000n,
        scriptPubKey: Buffer.from("0014" + "aa".repeat(20), "hex"),
      },
    ],
    lockTime: 0,
  };
}

// ---------------------------------------------------------------------------
// Simulate the handler extracted from cli.ts so we can test it in isolation.
//
// The handler logic (stripped of node bootstrap):
//
//   if (msg.type !== "tx") return;
//   if (!blockSync.isIBDComplete()) return;           // IBD gate (added in this wave)
//   const tx = msg.payload.tx;
//   const result = await mempool.acceptToMemoryPool(tx);
//   if (result.accepted) {
//     const txid = getTxId(tx);
//     const entry = mempool.getTransaction(txid);
//     const feeRate = entry ? entry.feeRate : 0;
//     txRelay.queueTxToAllFiltered(txidHex, feeRate);
//   }
// ---------------------------------------------------------------------------

interface MockMempoolEntry {
  feeRate: number;
}

class StubMempool {
  public acceptCalls: Transaction[] = [];
  private _accept: boolean;
  private _feeRate: number;

  constructor(accept = true, feeRate = 10) {
    this._accept = accept;
    this._feeRate = feeRate;
  }

  async acceptToMemoryPool(tx: Transaction): Promise<{ accepted: boolean; error?: string }> {
    this.acceptCalls.push(tx);
    if (!this._accept) return { accepted: false, error: "insufficient fee" };
    return { accepted: true };
  }

  getTransaction(_txid: Buffer): MockMempoolEntry | null {
    if (!this._accept) return null;
    return { feeRate: this._feeRate };
  }
}

class StubBlockSync {
  private _ibdComplete: boolean;
  constructor(ibdComplete: boolean) {
    this._ibdComplete = ibdComplete;
  }
  isIBDComplete(): boolean {
    return this._ibdComplete;
  }
}

/**
 * Build and invoke the tx message handler with the given stubs.
 * Returns { acceptCalls, queuedTxids }.
 */
async function invokeHandler(opts: {
  ibdComplete: boolean;
  accept: boolean;
  feeRate?: number;
}): Promise<{ acceptCalls: number; queuedTxids: string[] }> {
  const peer = makePeer();
  const tx = makeTestTx();
  const mempool = new StubMempool(opts.accept, opts.feeRate ?? 10);
  const blockSync = new StubBlockSync(opts.ibdComplete);

  const queuedTxids: string[] = [];
  const txRelay = new InventoryRelay((_p: Peer, inventory: InvVector[]) => {
    for (const inv of inventory) {
      queuedTxids.push(inv.hash.toString("hex"));
    }
  });
  txRelay.addPeer(peer, true);

  // Replicate the handler body verbatim (minus the type guard on msg.type
  // which we always satisfy here).
  const msg = { type: "tx" as const, payload: { tx } };
  if (msg.type !== "tx") {
    // unreachable in these tests
  } else if (!blockSync.isIBDComplete()) {
    // IBD gate — drop
  } else {
    const result = await mempool.acceptToMemoryPool(tx);
    if (result.accepted) {
      const txid = getTxId(tx);
      const txidHex = txid.toString("hex");
      const entry = mempool.getTransaction(txid);
      const feeRate = entry ? entry.feeRate : 0;
      txRelay.queueTxToAllFiltered(txidHex, feeRate);
    }
  }

  // Flush the relay queue immediately so we can inspect what would be sent.
  txRelay.flushNow(peer);
  txRelay.stop();

  return { acceptCalls: mempool.acceptCalls.length, queuedTxids };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("P2P tx-message handler — IBD skip gate", () => {
  it("drops tx during IBD without calling acceptToMemoryPool", async () => {
    const { acceptCalls, queuedTxids } = await invokeHandler({
      ibdComplete: false,
      accept: true,
    });
    expect(acceptCalls).toBe(0);
    expect(queuedTxids.length).toBe(0);
  });

  it("processes tx after IBD completes", async () => {
    const { acceptCalls } = await invokeHandler({
      ibdComplete: true,
      accept: true,
    });
    expect(acceptCalls).toBe(1);
  });
});

describe("P2P tx-message handler — accept and relay path", () => {
  it("queues txid for relay on successful accept", async () => {
    const tx = makeTestTx();
    const expectedTxid = getTxId(tx).toString("hex");

    const { queuedTxids } = await invokeHandler({
      ibdComplete: true,
      accept: true,
      feeRate: 15,
    });

    expect(queuedTxids.length).toBe(1);
    expect(queuedTxids[0]).toBe(expectedTxid);
  });

  it("does NOT queue txid for relay on rejected tx", async () => {
    const { acceptCalls, queuedTxids } = await invokeHandler({
      ibdComplete: true,
      accept: false,
    });
    expect(acceptCalls).toBe(1);      // handler did call acceptToMemoryPool
    expect(queuedTxids.length).toBe(0); // but did NOT relay
  });
});

describe("P2P tx-message handler — relay respects feefilter", () => {
  it("does not queue tx if feeRate is below peer feefilter threshold", async () => {
    const peer = makePeer();
    // Peer advertises a feefilter of 20,000 sat/kvB (= 20 sat/vB).
    // meetsFeeFilter converts txFeeRate (sat/vB) to sat/kvB before comparing,
    // so peer threshold must be a bigint in sat/kvB units.
    (peer as any).feeFilterReceived = 20_000n;

    const tx = makeTestTx();
    const mempool = new StubMempool(true, 5); // tx feeRate=5 sat/vB < 20 sat/vB threshold

    const queuedTxids: string[] = [];
    const txRelay = new InventoryRelay((_p: Peer, inventory: InvVector[]) => {
      for (const inv of inventory) queuedTxids.push(inv.hash.toString("hex"));
    });
    txRelay.addPeer(peer, true);

    // Simulate handler (ibdComplete=true, accepted)
    const result = await mempool.acceptToMemoryPool(tx);
    if (result.accepted) {
      const txid = getTxId(tx);
      const txidHex = txid.toString("hex");
      const entry = mempool.getTransaction(txid);
      const feeRate = entry ? entry.feeRate : 0;
      txRelay.queueTxToAllFiltered(txidHex, feeRate);
    }
    txRelay.flushNow(peer);
    txRelay.stop();

    // feeRate=5 < threshold=20 → tx should NOT be relayed to this peer
    expect(queuedTxids.length).toBe(0);
  });

  it("queues tx when feeRate meets peer feefilter threshold", async () => {
    const peer = makePeer();
    // Peer threshold: 10,000 sat/kvB (= 10 sat/vB)
    (peer as any).feeFilterReceived = 10_000n;

    const tx = makeTestTx();
    const mempool = new StubMempool(true, 25); // tx feeRate=25 sat/vB >= 10 sat/vB threshold

    const queuedTxids: string[] = [];
    const txRelay = new InventoryRelay((_p: Peer, inventory: InvVector[]) => {
      for (const inv of inventory) queuedTxids.push(inv.hash.toString("hex"));
    });
    txRelay.addPeer(peer, false);

    const result = await mempool.acceptToMemoryPool(tx);
    if (result.accepted) {
      const txid = getTxId(tx);
      const txidHex = txid.toString("hex");
      const entry = mempool.getTransaction(txid);
      const feeRate = entry ? entry.feeRate : 0;
      txRelay.queueTxToAllFiltered(txidHex, feeRate);
    }
    txRelay.flushNow(peer);
    txRelay.stop();

    expect(queuedTxids.length).toBe(1);
  });
});
