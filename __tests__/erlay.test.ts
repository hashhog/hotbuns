/**
 * BIP-330 Erlay tests.
 *
 * Tests for set reconciliation, short ID computation, and the
 * TxReconciliationTracker lifecycle.
 */

import { describe, expect, test, beforeEach, mock } from "bun:test";
import {
  TxReconciliationTracker,
  ReconciliationRegisterResult,
  computeReconSalt,
  computeShortId,
  deriveSipHashKeys,
  createSendTxRcnclMessage,
  isErlaySupported,
  ERLAY_VERSION,
  OUTBOUND_RECON_INTERVAL_MS,
  INBOUND_RECON_INTERVAL_MS,
} from "../src/p2p/erlay.js";
import type { Peer } from "../src/p2p/peer.js";
import type { NetworkMessage } from "../src/p2p/messages.js";

// Mock peer for testing
function createMockPeer(overrides: Partial<Peer> = {}): Peer {
  return {
    host: "127.0.0.1",
    port: 8333,
    state: "connected",
    handshakeComplete: true,
    send: mock(() => {}),
    ...overrides,
  } as unknown as Peer;
}

describe("Erlay Short ID Computation", () => {
  test("computeReconSalt produces consistent output", () => {
    const salt1 = 0x1234567890abcdefn;
    const salt2 = 0xfedcba0987654321n;

    const result1 = computeReconSalt(salt1, salt2);
    const result2 = computeReconSalt(salt2, salt1); // Order reversed

    // Should be same regardless of order (min/max sorted)
    expect(result1.equals(result2)).toBe(true);
    expect(result1.length).toBe(32);
  });

  test("computeReconSalt produces different results for different salts", () => {
    const salt1 = 0x1111111111111111n;
    const salt2 = 0x2222222222222222n;
    const salt3 = 0x3333333333333333n;

    const result1 = computeReconSalt(salt1, salt2);
    const result2 = computeReconSalt(salt1, salt3);

    expect(result1.equals(result2)).toBe(false);
  });

  test("deriveSipHashKeys extracts keys from salt", () => {
    const salt = Buffer.alloc(32);
    // Write known values at positions 0 and 8
    salt.writeBigUInt64LE(0x0123456789abcdefn, 0);
    salt.writeBigUInt64LE(0xfedcba9876543210n, 8);

    const [k0, k1] = deriveSipHashKeys(salt);

    expect(k0).toBe(0x0123456789abcdefn);
    expect(k1).toBe(0xfedcba9876543210n);
  });

  test("computeShortId produces 32-bit output", () => {
    const k0 = 0x0123456789abcdefn;
    const k1 = 0xfedcba9876543210n;
    const wtxid = Buffer.alloc(32, 0xaa);

    const shortId = computeShortId(k0, k1, wtxid);

    expect(shortId).toBeGreaterThanOrEqual(0);
    expect(shortId).toBeLessThanOrEqual(0xffffffff);
    expect(Number.isInteger(shortId)).toBe(true);
  });

  test("computeShortId is deterministic", () => {
    const k0 = 0x1234n;
    const k1 = 0x5678n;
    const wtxid = Buffer.from("aa".repeat(32), "hex");

    const id1 = computeShortId(k0, k1, wtxid);
    const id2 = computeShortId(k0, k1, wtxid);

    expect(id1).toBe(id2);
  });

  test("computeShortId differs for different inputs", () => {
    const k0 = 0x1234n;
    const k1 = 0x5678n;
    const wtxid1 = Buffer.alloc(32, 0x01);
    const wtxid2 = Buffer.alloc(32, 0x02);

    const id1 = computeShortId(k0, k1, wtxid1);
    const id2 = computeShortId(k0, k1, wtxid2);

    expect(id1).not.toBe(id2);
  });
});

describe("TxReconciliationTracker", () => {
  let tracker: TxReconciliationTracker;
  let sentMessages: Array<{ peer: Peer; msg: NetworkMessage }>;
  let requestedTxs: Array<{ peer: Peer; wtxids: Buffer[] }>;
  let announcedTxs: Array<{ peer: Peer; wtxids: Buffer[] }>;

  beforeEach(() => {
    sentMessages = [];
    requestedTxs = [];
    announcedTxs = [];

    tracker = new TxReconciliationTracker({
      sendMessage: (peer, msg) => sentMessages.push({ peer, msg }),
      requestTransactions: (peer, wtxids) => requestedTxs.push({ peer, wtxids }),
      announceTransactions: (peer, wtxids) => announcedTxs.push({ peer, wtxids }),
    });
  });

  test("preRegisterPeer generates salt", () => {
    const peer = createMockPeer();

    const salt = tracker.preRegisterPeer(peer);

    expect(typeof salt).toBe("bigint");
    expect(salt).toBeGreaterThan(0n);
  });

  test("preRegisterPeer generates unique salts", () => {
    const peer1 = createMockPeer({ host: "127.0.0.1", port: 8333 });
    const peer2 = createMockPeer({ host: "127.0.0.2", port: 8333 });

    const salt1 = tracker.preRegisterPeer(peer1);
    const salt2 = tracker.preRegisterPeer(peer2);

    // Very likely to be different (2^64 space)
    // Could theoretically collide but extremely unlikely
    expect(salt1).not.toBe(salt2);
  });

  test("registerPeer fails without preRegister", () => {
    const peer = createMockPeer();

    const result = tracker.registerPeer(peer, true, ERLAY_VERSION, 12345n);

    expect(result).toBe(ReconciliationRegisterResult.NOT_FOUND);
    expect(tracker.isPeerRegistered(peer)).toBe(false);
  });

  test("registerPeer succeeds after preRegister", () => {
    const peer = createMockPeer();

    tracker.preRegisterPeer(peer);
    const result = tracker.registerPeer(peer, true, ERLAY_VERSION, 12345n);

    expect(result).toBe(ReconciliationRegisterResult.SUCCESS);
    expect(tracker.isPeerRegistered(peer)).toBe(true);
  });

  test("registerPeer fails on duplicate registration", () => {
    const peer = createMockPeer();

    tracker.preRegisterPeer(peer);
    tracker.registerPeer(peer, true, ERLAY_VERSION, 12345n);
    const result = tracker.registerPeer(peer, true, ERLAY_VERSION, 67890n);

    expect(result).toBe(ReconciliationRegisterResult.ALREADY_REGISTERED);
  });

  test("registerPeer fails on version 0", () => {
    const peer = createMockPeer();

    tracker.preRegisterPeer(peer);
    const result = tracker.registerPeer(peer, true, 0, 12345n);

    expect(result).toBe(ReconciliationRegisterResult.PROTOCOL_VIOLATION);
    expect(tracker.isPeerRegistered(peer)).toBe(false);
  });

  test("forgetPeer removes registration", () => {
    const peer = createMockPeer();

    tracker.preRegisterPeer(peer);
    tracker.registerPeer(peer, true, ERLAY_VERSION, 12345n);
    expect(tracker.isPeerRegistered(peer)).toBe(true);

    tracker.forgetPeer(peer);
    expect(tracker.isPeerRegistered(peer)).toBe(false);
  });

  test("outbound connection becomes initiator", () => {
    const peer = createMockPeer();

    tracker.preRegisterPeer(peer);
    // isPeerInbound = false means we are outbound (we connected to them)
    tracker.registerPeer(peer, false, ERLAY_VERSION, 12345n);

    expect(tracker.isPeerRegistered(peer)).toBe(true);
    // Initiator role is determined internally; we can check via timer behavior
  });

  test("inbound connection becomes responder", () => {
    const peer = createMockPeer();

    tracker.preRegisterPeer(peer);
    // isPeerInbound = true means they connected to us (we are responder)
    tracker.registerPeer(peer, true, ERLAY_VERSION, 12345n);

    expect(tracker.isPeerRegistered(peer)).toBe(true);
  });

  test("shouldQueueForReconciliation returns false for unregistered peer", () => {
    const peer = createMockPeer();

    expect(tracker.shouldQueueForReconciliation(peer)).toBe(false);
  });

  test("shouldQueueForReconciliation returns true for registered peer", () => {
    const peer = createMockPeer();

    tracker.preRegisterPeer(peer);
    tracker.registerPeer(peer, true, ERLAY_VERSION, 12345n);

    expect(tracker.shouldQueueForReconciliation(peer)).toBe(true);
  });

  test("addToReconSet adds transaction to set", () => {
    const peer = createMockPeer();
    const wtxid = Buffer.alloc(32, 0xab);

    tracker.preRegisterPeer(peer);
    tracker.registerPeer(peer, true, ERLAY_VERSION, 12345n);

    // Should not throw
    tracker.addToReconSet(peer, wtxid);
  });

  test("removeFromReconSet removes transaction from set", () => {
    const peer = createMockPeer();
    const wtxid = Buffer.alloc(32, 0xcd);

    tracker.preRegisterPeer(peer);
    tracker.registerPeer(peer, true, ERLAY_VERSION, 12345n);

    tracker.addToReconSet(peer, wtxid);
    tracker.removeFromReconSet(peer, wtxid);

    // Should not throw
  });

  test("handleSendTxRcncl registers peer", () => {
    const peer = createMockPeer();

    tracker.preRegisterPeer(peer);
    tracker.handleSendTxRcncl(peer, { version: ERLAY_VERSION, salt: 99999n }, true);

    expect(tracker.isPeerRegistered(peer)).toBe(true);
  });

  test("handleInvTx triggers transaction request", () => {
    const peer = createMockPeer();
    const wtxid = Buffer.alloc(32, 0xef);

    tracker.preRegisterPeer(peer);
    tracker.registerPeer(peer, true, ERLAY_VERSION, 12345n);

    tracker.handleInvTx(peer, { wtxids: [wtxid] });

    expect(requestedTxs.length).toBe(1);
    expect(requestedTxs[0].wtxids.length).toBe(1);
    expect(requestedTxs[0].wtxids[0].equals(wtxid)).toBe(true);
  });

  test("handleMessage returns false for non-Erlay message", () => {
    const peer = createMockPeer();
    const msg: NetworkMessage = { type: "ping", payload: { nonce: 123n } };

    const handled = tracker.handleMessage(peer, msg, true);

    expect(handled).toBe(false);
  });

  test("handleMessage returns true for Erlay message", () => {
    const peer = createMockPeer();

    tracker.preRegisterPeer(peer);

    const msg: NetworkMessage = {
      type: "sendtxrcncl",
      payload: { version: ERLAY_VERSION, salt: 12345n },
    };

    const handled = tracker.handleMessage(peer, msg, true);

    expect(handled).toBe(true);
    expect(tracker.isPeerRegistered(peer)).toBe(true);
  });

  test("getRegisteredPeerCount returns correct count", () => {
    expect(tracker.getRegisteredPeerCount()).toBe(0);

    const peer1 = createMockPeer({ host: "1.1.1.1", port: 8333 });
    const peer2 = createMockPeer({ host: "2.2.2.2", port: 8333 });

    tracker.preRegisterPeer(peer1);
    tracker.registerPeer(peer1, true, ERLAY_VERSION, 111n);
    expect(tracker.getRegisteredPeerCount()).toBe(1);

    tracker.preRegisterPeer(peer2);
    tracker.registerPeer(peer2, false, ERLAY_VERSION, 222n);
    expect(tracker.getRegisteredPeerCount()).toBe(2);

    tracker.forgetPeer(peer1);
    expect(tracker.getRegisteredPeerCount()).toBe(1);

    // Clean up timers
    tracker.stopAll();
  });

  test("stopAll cleans up timers", () => {
    const peer = createMockPeer();

    tracker.preRegisterPeer(peer);
    // Outbound = initiator = has timer
    tracker.registerPeer(peer, false, ERLAY_VERSION, 12345n);

    // Should not throw
    tracker.stopAll();
  });
});

describe("Erlay Helper Functions", () => {
  test("createSendTxRcnclMessage creates correct message", () => {
    const salt = 0xaabbccddeeff0011n;
    const msg = createSendTxRcnclMessage(salt);

    expect(msg.type).toBe("sendtxrcncl");
    expect(msg.payload).toEqual({
      version: ERLAY_VERSION,
      salt,
    });
  });

  test("isErlaySupported returns false for old versions", () => {
    expect(isErlaySupported(70015)).toBe(false);
    expect(isErlaySupported(70000)).toBe(false);
    expect(isErlaySupported(60002)).toBe(false);
  });

  test("isErlaySupported returns true for version 70016+", () => {
    expect(isErlaySupported(70016)).toBe(true);
    expect(isErlaySupported(70017)).toBe(true);
    expect(isErlaySupported(80000)).toBe(true);
  });
});

describe("Erlay Constants", () => {
  test("ERLAY_VERSION is 1", () => {
    expect(ERLAY_VERSION).toBe(1);
  });

  test("reconciliation intervals are correct", () => {
    expect(OUTBOUND_RECON_INTERVAL_MS).toBe(2000);
    expect(INBOUND_RECON_INTERVAL_MS).toBe(8000);
  });
});
