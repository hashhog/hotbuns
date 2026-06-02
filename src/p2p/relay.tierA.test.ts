/**
 * Tier-A leak-bound regression: per-peer pending-tx-announcement cap.
 *
 * Root cause: `RelayManager`/`InventoryRelay` per-peer `pendingTxs` Set had no
 * cap — the flush only drains INVENTORY_BATCH_SIZE (7) txids per Poisson tick,
 * so a flooding/stuck peer could grow the set without bound (at-tip only; the
 * tx handler is IBD-gated). Fix: cap at MAX_PEER_TX_ANNOUNCEMENTS = 5000 on the
 * enqueue path (Core net_processing.cpp parity); drop announcements past the
 * cap. See CORE-PARITY-AUDIT/_hotbuns-rss-leak-rootcause-2026-06-02.md (Tier A.3).
 */

import { describe, expect, test } from "bun:test";
import {
  InventoryRelay,
  MAX_PEER_TX_ANNOUNCEMENTS,
} from "./relay.js";
import { Peer, type PeerConfig, type PeerEvents } from "./peer.js";

function makePeerConfig(overrides: Partial<PeerConfig> = {}): PeerConfig {
  return {
    host: "10.0.0.1",
    port: 8333,
    magic: 0xd9b4bef9,
    protocolVersion: 70016,
    services: 9n,
    userAgent: "/test:0.0.1/",
    bestHeight: 0,
    relay: true,
    ...overrides,
  };
}

function makeNullEvents(): PeerEvents {
  return {
    onMessage: () => {},
    onConnect: () => {},
    onDisconnect: () => {},
    onHandshakeComplete: () => {},
  };
}

function makePeer(opts?: Partial<PeerConfig>): Peer {
  return new Peer(makePeerConfig(opts), makeNullEvents());
}

/** Distinct 32-byte txid hex for index i. */
function txid(i: number): string {
  const buf = Buffer.alloc(32);
  buf.writeUInt32LE(i >>> 0, 0);
  buf.writeUInt32LE((i / 0x100000000) >>> 0, 4);
  return buf.toString("hex");
}

describe("Tier A.3: relay pendingTxs per-peer cap", () => {
  test("MAX_PEER_TX_ANNOUNCEMENTS matches Core (5000)", () => {
    expect(MAX_PEER_TX_ANNOUNCEMENTS).toBe(5000);
  });

  test("pendingTxs stays <= cap under a flood via queueTx", () => {
    const relay = new InventoryRelay(() => {});
    const peer = makePeer();
    relay.addPeer(peer);

    // Flood well past the cap with distinct txids.
    for (let i = 0; i < MAX_PEER_TX_ANNOUNCEMENTS + 2500; i++) {
      relay.queueTx(peer, txid(i));
    }

    expect(relay.getPendingCount(peer)).toBe(MAX_PEER_TX_ANNOUNCEMENTS);
    relay.stop();
  });

  test("pendingTxs stays <= cap under a flood via queueTxToAll", () => {
    const relay = new InventoryRelay(() => {});
    const peer = makePeer();
    relay.addPeer(peer);

    for (let i = 0; i < MAX_PEER_TX_ANNOUNCEMENTS + 1000; i++) {
      relay.queueTxToAll(txid(i));
    }

    expect(relay.getPendingCount(peer)).toBe(MAX_PEER_TX_ANNOUNCEMENTS);
    relay.stop();
  });

  test("re-announcing an already-queued txid does not grow the set past cap", () => {
    const relay = new InventoryRelay(() => {});
    const peer = makePeer();
    relay.addPeer(peer);

    // Fill exactly to the cap.
    for (let i = 0; i < MAX_PEER_TX_ANNOUNCEMENTS; i++) {
      relay.queueTx(peer, txid(i));
    }
    expect(relay.getPendingCount(peer)).toBe(MAX_PEER_TX_ANNOUNCEMENTS);

    // Re-announce existing txids — idempotent, set size unchanged.
    relay.queueTx(peer, txid(0));
    relay.queueTx(peer, txid(123));
    expect(relay.getPendingCount(peer)).toBe(MAX_PEER_TX_ANNOUNCEMENTS);

    // A brand-new txid past the cap is dropped.
    relay.queueTx(peer, txid(MAX_PEER_TX_ANNOUNCEMENTS + 1));
    expect(relay.getPendingCount(peer)).toBe(MAX_PEER_TX_ANNOUNCEMENTS);
    relay.stop();
  });

  test("draining (flush) frees room so new announcements can re-enter under cap", () => {
    const relay = new InventoryRelay(() => {});
    const peer = makePeer();
    relay.addPeer(peer);

    for (let i = 0; i < MAX_PEER_TX_ANNOUNCEMENTS; i++) {
      relay.queueTx(peer, txid(i));
    }
    expect(relay.getPendingCount(peer)).toBe(MAX_PEER_TX_ANNOUNCEMENTS);

    // One flush drains up to INVENTORY_BATCH_SIZE entries.
    relay.flushNow(peer);
    const afterFlush = relay.getPendingCount(peer);
    expect(afterFlush).toBeLessThan(MAX_PEER_TX_ANNOUNCEMENTS);

    // New txids can now be queued again, still bounded by the cap.
    for (let i = 0; i < MAX_PEER_TX_ANNOUNCEMENTS; i++) {
      relay.queueTx(peer, txid(100_000 + i));
    }
    expect(relay.getPendingCount(peer)).toBeLessThanOrEqual(
      MAX_PEER_TX_ANNOUNCEMENTS
    );
    relay.stop();
  });
});
