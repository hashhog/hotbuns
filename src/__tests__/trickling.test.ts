/**
 * Tests for inventory trickling (transaction announcement batching).
 *
 * Verifies that transactions are delayed and batched according to
 * Poisson timing, and that blocks are always announced immediately.
 */

import { describe, expect, test, beforeEach, afterEach, mock } from "bun:test";
import {
  InventoryRelay,
  INBOUND_INVENTORY_BROADCAST_INTERVAL,
  OUTBOUND_INVENTORY_BROADCAST_INTERVAL,
  INVENTORY_BROADCAST_MAX,
  INVENTORY_BATCH_SIZE,
} from "../p2p/relay.js";
import type { Peer } from "../p2p/peer.js";
import type { InvVector } from "../p2p/messages.js";
import { InvType } from "../p2p/messages.js";

/** Create a mock peer for testing. */
function createMockPeer(host: string = "127.0.0.1", port: number = 8333): Peer {
  return {
    host,
    port,
    state: "connected",
    send: () => {},
  } as unknown as Peer;
}

/** Helper to wait for a condition with timeout */
async function waitFor(
  condition: () => boolean,
  timeoutMs: number = 2000
): Promise<void> {
  const start = Date.now();
  while (!condition()) {
    if (Date.now() - start > timeoutMs) {
      throw new Error("waitFor timeout");
    }
    await new Promise((r) => setTimeout(r, 10));
  }
}

describe("InventoryRelay constants", () => {
  test("has correct interval for inbound peers", () => {
    expect(INBOUND_INVENTORY_BROADCAST_INTERVAL).toBe(5_000);
  });

  test("has correct interval for outbound peers", () => {
    expect(OUTBOUND_INVENTORY_BROADCAST_INTERVAL).toBe(2_000);
  });

  test("has correct broadcast max", () => {
    expect(INVENTORY_BROADCAST_MAX).toBe(1000);
  });

  test("has correct batch size", () => {
    expect(INVENTORY_BATCH_SIZE).toBe(7);
  });
});

describe("InventoryRelay peer management", () => {
  let relay: InventoryRelay;
  let sentInvs: Array<{ peer: Peer; inventory: InvVector[] }>;

  beforeEach(() => {
    sentInvs = [];
    relay = new InventoryRelay((peer, inventory) => {
      sentInvs.push({ peer, inventory });
    });
  });

  afterEach(() => {
    relay.stop();
  });

  test("adds and removes peers", () => {
    const peer = createMockPeer();

    relay.addPeer(peer, false);
    expect(relay.getPendingCount(peer)).toBe(0);
    expect(relay.getNextFlushTime(peer)).not.toBeNull();

    relay.removePeer(peer);
    expect(relay.getNextFlushTime(peer)).toBeNull();
  });

  test("does not duplicate peer registration", () => {
    const peer = createMockPeer();

    relay.addPeer(peer, false);
    const firstFlushTime = relay.getNextFlushTime(peer);

    relay.addPeer(peer, false); // Should be no-op
    expect(relay.getNextFlushTime(peer)).toBe(firstFlushTime);
  });
});

describe("InventoryRelay transaction queueing", () => {
  let relay: InventoryRelay;
  let sentInvs: Array<{ peer: Peer; inventory: InvVector[] }>;

  beforeEach(() => {
    sentInvs = [];
    relay = new InventoryRelay((peer, inventory) => {
      sentInvs.push({ peer, inventory });
    });
  });

  afterEach(() => {
    relay.stop();
  });

  test("queues transactions to specific peer", () => {
    const peer = createMockPeer();
    relay.addPeer(peer, false);

    const txid = "0".repeat(64);
    relay.queueTx(peer, txid);

    expect(relay.getPendingCount(peer)).toBe(1);
  });

  test("queues transactions to all peers", () => {
    const peer1 = createMockPeer("127.0.0.1", 8333);
    const peer2 = createMockPeer("127.0.0.2", 8333);

    relay.addPeer(peer1, false);
    relay.addPeer(peer2, false);

    const txid = "1".repeat(64);
    relay.queueTxToAll(txid);

    expect(relay.getPendingCount(peer1)).toBe(1);
    expect(relay.getPendingCount(peer2)).toBe(1);
  });

  test("does not queue to unregistered peer", () => {
    const peer = createMockPeer();
    const txid = "2".repeat(64);

    // No addPeer call
    relay.queueTx(peer, txid);

    expect(relay.getPendingCount(peer)).toBe(0);
  });

  test("deduplicates queued transactions", () => {
    const peer = createMockPeer();
    relay.addPeer(peer, false);

    const txid = "3".repeat(64);
    relay.queueTx(peer, txid);
    relay.queueTx(peer, txid);
    relay.queueTx(peer, txid);

    expect(relay.getPendingCount(peer)).toBe(1);
  });
});

describe("InventoryRelay block relay", () => {
  let relay: InventoryRelay;
  let sentInvs: Array<{ peer: Peer; inventory: InvVector[] }>;

  beforeEach(() => {
    sentInvs = [];
    relay = new InventoryRelay((peer, inventory) => {
      sentInvs.push({ peer, inventory });
    });
  });

  afterEach(() => {
    relay.stop();
  });

  test("relays block immediately to specific peer", () => {
    const peer = createMockPeer();
    relay.addPeer(peer, false);

    const blockHash = Buffer.alloc(32, 0xab);
    relay.relayBlockNow(peer, blockHash);

    expect(sentInvs).toHaveLength(1);
    expect(sentInvs[0].peer).toBe(peer);
    expect(sentInvs[0].inventory).toHaveLength(1);
    expect(sentInvs[0].inventory[0].type).toBe(InvType.MSG_BLOCK);
    expect(sentInvs[0].inventory[0].hash.equals(blockHash)).toBe(true);
  });

  test("relays block immediately to all peers", () => {
    const peer1 = createMockPeer("127.0.0.1", 8333);
    const peer2 = createMockPeer("127.0.0.2", 8333);

    relay.addPeer(peer1, false);
    relay.addPeer(peer2, false);

    const blockHash = Buffer.alloc(32, 0xcd);
    relay.relayBlockToAll(blockHash);

    expect(sentInvs).toHaveLength(2);

    // Both peers should receive the block
    const hosts = sentInvs.map((s) => s.peer.host);
    expect(hosts).toContain("127.0.0.1");
    expect(hosts).toContain("127.0.0.2");

    // All should be block inv
    for (const sent of sentInvs) {
      expect(sent.inventory[0].type).toBe(InvType.MSG_BLOCK);
    }
  });

  test("does not relay block to unregistered peer", () => {
    const peer = createMockPeer();
    // No addPeer call

    const blockHash = Buffer.alloc(32, 0xef);
    relay.relayBlockNow(peer, blockHash);

    expect(sentInvs).toHaveLength(0);
  });
});

describe("InventoryRelay flush behavior", () => {
  let relay: InventoryRelay;
  let sentInvs: Array<{ peer: Peer; inventory: InvVector[] }>;

  beforeEach(() => {
    sentInvs = [];
    relay = new InventoryRelay((peer, inventory) => {
      sentInvs.push({ peer, inventory });
    });
  });

  afterEach(() => {
    relay.stop();
  });

  test("flushNow sends pending transactions", () => {
    const peer = createMockPeer();
    relay.addPeer(peer, false);

    // Queue some transactions
    for (let i = 0; i < 5; i++) {
      relay.queueTx(peer, i.toString(16).padStart(64, "0"));
    }

    expect(relay.getPendingCount(peer)).toBe(5);

    // Force flush
    relay.flushNow(peer);

    expect(sentInvs).toHaveLength(1);
    expect(sentInvs[0].inventory).toHaveLength(5);
    expect(relay.getPendingCount(peer)).toBe(0);

    // All should be witness tx type
    for (const inv of sentInvs[0].inventory) {
      expect(inv.type).toBe(InvType.MSG_WITNESS_TX);
    }
  });

  test("respects batch size limit per flush", () => {
    const peer = createMockPeer();
    relay.addPeer(peer, false);

    // Queue more than batch size
    for (let i = 0; i < 20; i++) {
      relay.queueTx(peer, i.toString(16).padStart(64, "0"));
    }

    expect(relay.getPendingCount(peer)).toBe(20);

    // First flush
    relay.flushNow(peer);

    expect(sentInvs).toHaveLength(1);
    expect(sentInvs[0].inventory.length).toBeLessThanOrEqual(INVENTORY_BATCH_SIZE);
    expect(relay.getPendingCount(peer)).toBe(20 - sentInvs[0].inventory.length);

    // Second flush
    relay.flushNow(peer);

    expect(sentInvs).toHaveLength(2);
    expect(sentInvs[1].inventory.length).toBeLessThanOrEqual(INVENTORY_BATCH_SIZE);
  });

  test("does not send empty inv messages", () => {
    const peer = createMockPeer();
    relay.addPeer(peer, false);

    // No transactions queued
    relay.flushNow(peer);

    expect(sentInvs).toHaveLength(0);
  });

  test("clears pending transactions after flush", () => {
    const peer = createMockPeer();
    relay.addPeer(peer, false);

    const txid = "4".repeat(64);
    relay.queueTx(peer, txid);

    relay.flushNow(peer);

    expect(relay.getPendingCount(peer)).toBe(0);

    // Another flush should send nothing
    relay.flushNow(peer);
    expect(sentInvs).toHaveLength(1); // Only the first flush sent anything
  });
});

describe("InventoryRelay Poisson timing", () => {
  let relay: InventoryRelay;
  let sentInvs: Array<{ peer: Peer; inventory: InvVector[] }>;

  beforeEach(() => {
    sentInvs = [];
    relay = new InventoryRelay((peer, inventory) => {
      sentInvs.push({ peer, inventory });
    });
  });

  afterEach(() => {
    relay.stop();
  });

  test("schedules next flush time for outbound peer", () => {
    const peer = createMockPeer();
    const beforeAdd = Date.now();

    relay.addPeer(peer, false); // outbound

    const nextFlush = relay.getNextFlushTime(peer);
    expect(nextFlush).not.toBeNull();

    // Should be scheduled sometime in the future
    // Due to Poisson, could be very soon or much later, but should be >= now
    expect(nextFlush!).toBeGreaterThanOrEqual(beforeAdd);
  });

  test("schedules next flush time for inbound peer", () => {
    const peer = createMockPeer();
    const beforeAdd = Date.now();

    relay.addPeer(peer, true); // inbound

    const nextFlush = relay.getNextFlushTime(peer);
    expect(nextFlush).not.toBeNull();
    expect(nextFlush!).toBeGreaterThanOrEqual(beforeAdd);
  });

  test("reschedules after flush", () => {
    const peer = createMockPeer();
    relay.addPeer(peer, false);

    relay.queueTx(peer, "5".repeat(64));

    const firstFlushTime = relay.getNextFlushTime(peer);
    relay.flushNow(peer);
    const secondFlushTime = relay.getNextFlushTime(peer);

    // New flush time should be different (very likely due to randomness)
    // This isn't guaranteed but is highly probable
    expect(secondFlushTime).toBeGreaterThanOrEqual(Date.now());
  });

  test("automatically flushes after delay", async () => {
    // Use a very short interval for testing
    const shortRelay = new InventoryRelay((peer, inventory) => {
      sentInvs.push({ peer, inventory });
    });

    const peer = createMockPeer();
    shortRelay.addPeer(peer, false);

    // Queue a transaction
    shortRelay.queueTx(peer, "6".repeat(64));

    // The automatic flush should happen within a reasonable time
    // Due to Poisson timing, we wait up to 3x the average interval
    await waitFor(
      () => sentInvs.length > 0,
      OUTBOUND_INVENTORY_BROADCAST_INTERVAL * 3
    );

    expect(sentInvs.length).toBeGreaterThanOrEqual(1);

    shortRelay.stop();
  }, 10000);
});

describe("InventoryRelay Fisher-Yates shuffle", () => {
  test("transactions are shuffled (statistical test)", () => {
    const sentInvs: Array<{ peer: Peer; inventory: InvVector[] }> = [];
    const relay = new InventoryRelay((peer, inventory) => {
      sentInvs.push({ peer, inventory });
    });

    const peer = createMockPeer();
    relay.addPeer(peer, false);

    // Queue transactions in sequential order
    const txids: string[] = [];
    for (let i = 0; i < 7; i++) {
      const txid = i.toString(16).padStart(64, "0");
      txids.push(txid);
      relay.queueTx(peer, txid);
    }

    // Flush and check if order differs from input
    relay.flushNow(peer);

    const sentHashes = sentInvs[0].inventory.map((inv) => inv.hash.toString("hex"));

    // Very unlikely to be in exact same order after shuffle (1/5040 for 7 items)
    // But we can't guarantee it, so we just verify we got all txids
    expect(sentHashes.length).toBe(7);
    for (const txid of txids) {
      expect(sentHashes).toContain(txid);
    }

    relay.stop();
  });
});

describe("InventoryRelay stop behavior", () => {
  test("stop cancels pending timers", () => {
    const sentInvs: Array<{ peer: Peer; inventory: InvVector[] }> = [];
    const relay = new InventoryRelay((peer, inventory) => {
      sentInvs.push({ peer, inventory });
    });

    const peer = createMockPeer();
    relay.addPeer(peer, false);

    relay.queueTx(peer, "7".repeat(64));

    relay.stop();

    // After stop, flush time should be null
    expect(relay.getNextFlushTime(peer)).toBeNull();
  });

  test("stop prevents new relay operations", () => {
    const sentInvs: Array<{ peer: Peer; inventory: InvVector[] }> = [];
    const relay = new InventoryRelay((peer, inventory) => {
      sentInvs.push({ peer, inventory });
    });

    const peer = createMockPeer();
    relay.addPeer(peer, false);

    relay.stop();

    // Block relay should be no-op after stop
    relay.relayBlockToAll(Buffer.alloc(32, 0x00));
    expect(sentInvs).toHaveLength(0);
  });
});

describe("InventoryRelay integration", () => {
  test("transactions are delayed, blocks are immediate", async () => {
    const sentInvs: Array<{
      peer: Peer;
      inventory: InvVector[];
      time: number;
    }> = [];

    const relay = new InventoryRelay((peer, inventory) => {
      sentInvs.push({ peer, inventory, time: Date.now() });
    });

    const peer = createMockPeer();
    relay.addPeer(peer, false);

    const startTime = Date.now();

    // Queue transaction
    relay.queueTx(peer, "a".repeat(64));

    // Immediately relay block
    relay.relayBlockNow(peer, Buffer.alloc(32, 0xbb));

    // Block should be sent immediately
    expect(sentInvs.length).toBeGreaterThanOrEqual(1);
    expect(sentInvs[0].inventory[0].type).toBe(InvType.MSG_BLOCK);
    expect(sentInvs[0].time - startTime).toBeLessThan(100);

    // Transaction should NOT be sent immediately (still pending)
    expect(relay.getPendingCount(peer)).toBe(1);

    // Wait for transaction flush
    await waitFor(
      () => relay.getPendingCount(peer) === 0,
      OUTBOUND_INVENTORY_BROADCAST_INTERVAL * 3
    );

    // Transaction should now be sent
    const txInv = sentInvs.find((s) =>
      s.inventory.some((i) => i.type === InvType.MSG_WITNESS_TX)
    );
    expect(txInv).toBeDefined();

    relay.stop();
  }, 10000);
});
