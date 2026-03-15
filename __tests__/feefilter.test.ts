/**
 * BIP133 feefilter tests.
 *
 * Tests feefilter message handling, relay filtering based on peer feefilter,
 * Poisson-delayed broadcasting, hysteresis, and incremental relay fee.
 */

import { describe, expect, test, beforeEach, mock } from "bun:test";
import {
  FeeFilterManager,
  meetsFeeFilter,
  poissonDelay,
  checkIncrementalRelayFee,
  DEFAULT_MIN_RELAY_FEE_RATE,
  DEFAULT_INCREMENTAL_RELAY_FEE,
  AVG_FEEFILTER_BROADCAST_INTERVAL_MS,
  MAX_FEEFILTER_CHANGE_DELAY_MS,
  MAX_MONEY,
  FEEFILTER_VERSION,
} from "../src/p2p/feefilter.js";
import type { Peer } from "../src/p2p/peer.js";

// Mock peer for testing
function createMockPeer(overrides: Partial<Peer> = {}): Peer {
  return {
    host: "127.0.0.1",
    port: 8333,
    feeFilterReceived: 0n,
    feeFilterSent: 0n,
    nextFeeFilterSend: 0,
    send: mock(() => {}),
    ...overrides,
  } as unknown as Peer;
}

describe("FeeFilterManager", () => {
  let sendCalls: Array<{ peer: Peer; feeRate: bigint }>;
  let manager: FeeFilterManager;

  beforeEach(() => {
    sendCalls = [];
    manager = new FeeFilterManager((peer, feeRate) => {
      sendCalls.push({ peer, feeRate });
    });
  });

  test("sends default min relay fee rate initially", () => {
    const peer = createMockPeer();
    manager.sendInitialFeeFilter(peer);

    expect(sendCalls.length).toBe(1);
    expect(sendCalls[0].feeRate).toBe(DEFAULT_MIN_RELAY_FEE_RATE);
    expect(peer.feeFilterSent).toBe(DEFAULT_MIN_RELAY_FEE_RATE);
  });

  test("sends MAX_MONEY during IBD", () => {
    manager.setInIBD(true);
    const peer = createMockPeer();
    manager.sendInitialFeeFilter(peer);

    expect(sendCalls.length).toBe(1);
    expect(sendCalls[0].feeRate).toBe(MAX_MONEY);
  });

  test("sends updated fee rate after exiting IBD", () => {
    manager.setInIBD(true);
    manager.setMinFeeRate(5000n);

    let peer = createMockPeer();
    manager.sendInitialFeeFilter(peer);
    expect(sendCalls[0].feeRate).toBe(MAX_MONEY);

    // Exit IBD
    manager.setInIBD(false);

    peer = createMockPeer();
    manager.sendInitialFeeFilter(peer);
    expect(sendCalls[1].feeRate).toBe(5000n);
  });

  test("handleFeeFilter updates peer state", () => {
    const peer = createMockPeer();
    expect(peer.feeFilterReceived).toBe(0n);

    manager.handleFeeFilter(peer, 3000n);
    expect(peer.feeFilterReceived).toBe(3000n);
  });

  test("handleFeeFilter ignores invalid values", () => {
    const peer = createMockPeer({ feeFilterReceived: 1000n });

    // Negative values
    manager.handleFeeFilter(peer, -1n);
    expect(peer.feeFilterReceived).toBe(1000n);

    // Over MAX_MONEY
    manager.handleFeeFilter(peer, MAX_MONEY + 1n);
    expect(peer.feeFilterReceived).toBe(1000n);
  });

  test("maybeSendFeeFilter skips block-relay-only peers", () => {
    const peer = createMockPeer();
    const now = Date.now();

    // Set peer's next send time to now (should trigger send)
    peer.nextFeeFilterSend = now;

    manager.maybeSendFeeFilter(peer, now, true /* isBlockRelayOnly */);
    expect(sendCalls.length).toBe(0);
  });

  test("maybeSendFeeFilter sends when time is up", () => {
    const peer = createMockPeer();
    const now = Date.now();

    // Set peer's next send time to now
    peer.nextFeeFilterSend = now;

    manager.maybeSendFeeFilter(peer, now, false);
    expect(sendCalls.length).toBe(1);
    expect(peer.nextFeeFilterSend).toBeGreaterThan(now);
  });

  test("maybeSendFeeFilter skips if fee rate unchanged", () => {
    const peer = createMockPeer();
    const now = Date.now();

    // First send
    peer.nextFeeFilterSend = now;
    manager.maybeSendFeeFilter(peer, now, false);
    expect(sendCalls.length).toBe(1);

    // Second call - should not send because fee rate unchanged
    const newNow = peer.nextFeeFilterSend + 1;
    manager.maybeSendFeeFilter(peer, newNow, false);
    expect(sendCalls.length).toBe(1);
  });

  test("maybeSendFeeFilter reschedules on substantial change", () => {
    const peer = createMockPeer();
    const now = Date.now();

    // Set peer's next send time far in the future
    peer.nextFeeFilterSend = now + AVG_FEEFILTER_BROADCAST_INTERVAL_MS + MAX_FEEFILTER_CHANGE_DELAY_MS + 1000;
    peer.feeFilterSent = 1000n;

    // Substantial change: 4x increase
    manager.setMinFeeRate(5000n);
    manager.maybeSendFeeFilter(peer, now, false);

    // Should have rescheduled to within MAX_FEEFILTER_CHANGE_DELAY_MS
    expect(peer.nextFeeFilterSend).toBeLessThanOrEqual(now + MAX_FEEFILTER_CHANGE_DELAY_MS);
  });

  test("setMinFeeRate enforces minimum", () => {
    // Setting below default should use default
    manager.setMinFeeRate(500n);
    const peer = createMockPeer();
    manager.sendInitialFeeFilter(peer);

    expect(sendCalls[0].feeRate).toBe(DEFAULT_MIN_RELAY_FEE_RATE);
  });
});

describe("meetsFeeFilter", () => {
  test("returns true when peer has no feefilter", () => {
    expect(meetsFeeFilter(0.5, 0n)).toBe(true);
    expect(meetsFeeFilter(100, 0n)).toBe(true);
  });

  test("returns true when fee rate meets threshold", () => {
    // 1 sat/vB = 1000 sat/kvB
    expect(meetsFeeFilter(1, 1000n)).toBe(true);
    expect(meetsFeeFilter(2, 1000n)).toBe(true);
    expect(meetsFeeFilter(1.5, 1000n)).toBe(true);
  });

  test("returns false when fee rate is below threshold", () => {
    // 0.5 sat/vB = 500 sat/kvB
    expect(meetsFeeFilter(0.5, 1000n)).toBe(false);
    expect(meetsFeeFilter(0.99, 1000n)).toBe(false);
  });

  test("handles edge cases", () => {
    // Exactly at threshold
    expect(meetsFeeFilter(1, 1000n)).toBe(true);

    // Very small values
    expect(meetsFeeFilter(0.001, 1n)).toBe(true);
    expect(meetsFeeFilter(0.001, 2n)).toBe(false);

    // Large values
    expect(meetsFeeFilter(1000, 500000n)).toBe(true);
  });
});

describe("poissonDelay", () => {
  test("generates positive delays", () => {
    for (let i = 0; i < 100; i++) {
      const delay = poissonDelay(10000);
      expect(delay).toBeGreaterThanOrEqual(0);
    }
  });

  test("averages approximately to the input interval", () => {
    const interval = 10000;
    const samples = 10000;
    let sum = 0;

    for (let i = 0; i < samples; i++) {
      sum += poissonDelay(interval);
    }

    const average = sum / samples;
    // Should be within 10% of expected average
    expect(average).toBeGreaterThan(interval * 0.9);
    expect(average).toBeLessThan(interval * 1.1);
  });
});

describe("checkIncrementalRelayFee", () => {
  test("accepts valid incremental fee", () => {
    // newFee = 2000, newVsize = 200, oldFee = 1000
    // Additional fee = 1000
    // Required (1000 sat/kvB * 200 vB / 1000) = 200
    const result = checkIncrementalRelayFee(2000n, 200, 1000n);
    expect(result.isValid).toBe(true);
    expect(result.error).toBeUndefined();
  });

  test("rejects insufficient incremental fee", () => {
    // newFee = 1100, newVsize = 200, oldFee = 1000
    // Additional fee = 100
    // Required (1000 sat/kvB * 200 vB / 1000) = 200
    const result = checkIncrementalRelayFee(1100n, 200, 1000n);
    expect(result.isValid).toBe(false);
    expect(result.error).toBeDefined();
  });

  test("uses custom incremental relay fee", () => {
    // With 500 sat/kvB incremental fee:
    // Required (500 * 200 / 1000) = 100
    const result = checkIncrementalRelayFee(1100n, 200, 1000n, 500n);
    expect(result.isValid).toBe(true);
  });

  test("handles edge case at exact threshold", () => {
    // newFee = 1200, newVsize = 200, oldFee = 1000
    // Additional fee = 200
    // Required (1000 * 200 / 1000) = 200
    const result = checkIncrementalRelayFee(1200n, 200, 1000n);
    expect(result.isValid).toBe(true);
  });

  test("handles large transaction sizes", () => {
    // 100 kvB transaction
    const vsize = 100000;
    // Required: 1000 * 100000 / 1000 = 100000 satoshis
    const result = checkIncrementalRelayFee(200000n, vsize, 100000n);
    expect(result.isValid).toBe(true);

    const result2 = checkIncrementalRelayFee(150000n, vsize, 100000n);
    expect(result2.isValid).toBe(false);
  });
});

describe("feefilter constants", () => {
  test("default min relay fee is 1000 sat/kvB", () => {
    expect(DEFAULT_MIN_RELAY_FEE_RATE).toBe(1000n);
  });

  test("default incremental relay fee is 1000 sat/kvB", () => {
    expect(DEFAULT_INCREMENTAL_RELAY_FEE).toBe(1000n);
  });

  test("feefilter protocol version is 70013", () => {
    expect(FEEFILTER_VERSION).toBe(70013);
  });

  test("average broadcast interval is 10 minutes", () => {
    expect(AVG_FEEFILTER_BROADCAST_INTERVAL_MS).toBe(10 * 60 * 1000);
  });

  test("max change delay is 5 minutes", () => {
    expect(MAX_FEEFILTER_CHANGE_DELAY_MS).toBe(5 * 60 * 1000);
  });
});
