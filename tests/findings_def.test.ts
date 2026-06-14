/**
 * Regression tests for three Core-parity fixes:
 *
 *   Finding D (CONSENSUS) — Superfluous witness record
 *     Bitcoin Core primitives/transaction.h:228-231 throws when the BIP144
 *     segwit marker+flag are present but NO input has a non-empty witness
 *     stack (tx.HasWitness() == false).  hotbuns silently accepted such txs,
 *     causing a consensus split on txid/merkle computation.
 *
 *   Finding E (policy) — ADDR/ADDRV2 3-hour store-drop removed
 *     Bitcoin Core net_processing.cpp:5678-5680 clamps out-of-range
 *     timestamps but always stores the address.  hotbuns was dropping any
 *     address older than 3 hours from the store, starving the address book.
 *
 *   Finding F (policy) — ADDR/ADDRV2 relay gated on message size <=10
 *     Bitcoin Core net_processing.cpp:5688 only relays per-address when the
 *     incoming ADDR/ADDRV2 message carries <=10 entries.  hotbuns was relaying
 *     all messages regardless of size, amplifying getaddr-reply spam.
 */

import { describe, test, expect } from "bun:test";
import { BufferReader } from "../src/wire/serialization.js";
import { deserializeTx } from "../src/validation/tx.js";
import {
  PeerManager,
  type PeerManagerConfig,
  ServiceFlags,
} from "../src/p2p/manager.js";
import { REGTEST } from "../src/consensus/params.js";
import { BIP155Network } from "../src/p2p/addrv2.js";

// ─── helpers ──────────────────────────────────────────────────────────────────

function makeConfig(overrides: Partial<PeerManagerConfig> = {}): PeerManagerConfig {
  return {
    maxOutbound: 10,
    maxInbound: 117,
    params: REGTEST,
    bestHeight: 0,
    datadir: "/tmp/hotbuns-findings-def-test",
    ...overrides,
  };
}

/** Access private PeerManager state for white-box assertions. */
function pm(manager: PeerManager): any {
  return manager as any;
}

// ─── Finding D — Superfluous witness record ───────────────────────────────────

describe("Finding D — Superfluous witness record rejected at deserialize", () => {
  /**
   * 63-byte transaction with BIP144 segwit marker+flag (0x00 0x01) set but
   * all witness stacks empty.  Bitcoin Core throws "Superfluous witness record"
   * (primitives/transaction.h:228-231).  This exact hex was accepted before
   * the fix.
   *
   * Breakdown:
   *   01000000          version=1
   *   00                segwit marker
   *   01                segwit flag
   *   01                1 input
   *   0000...0000       prevout txid (32 bytes zeroes)
   *   00000000          prevout vout=0
   *   00                scriptSig length=0
   *   ffffffff          sequence=0xffffffff
   *   01                1 output
   *   00f2052a01000000  value=5000000000 satoshis
   *   00                scriptPubKey length=0
   *   00                witness stack item count for input[0] = 0  (EMPTY)
   *   00000000          locktime=0
   */
  const SUPERFLUOUS_WITNESS_HEX =
    "0100000000010100000000000000000000000000000000000000000000000000000000000000000000000000ffffffff0100f2052a01000000000000000000";

  test("superfluous-witness tx is REJECTED (throws at deserialize)", () => {
    const buf = Buffer.from(SUPERFLUOUS_WITNESS_HEX, "hex");
    const reader = new BufferReader(buf);
    expect(() => deserializeTx(reader)).toThrow("Superfluous witness record");
  });

  test("normal segwit tx with a non-empty witness stack is still accepted", () => {
    // Construct a minimal segwit tx where input[0] has 1 witness item.
    // Structure: version(4) marker(1) flag(1) inputCount(1) ...input(41)
    //            outputCount(1) ...output(9) witnessStack[0].count(1) item_len(1) item(1)
    //            locktime(4)
    const w = new Uint8Array([
      // version = 1 (LE)
      0x01, 0x00, 0x00, 0x00,
      // segwit marker + flag
      0x00, 0x01,
      // 1 input
      0x01,
      // prevout: 32-byte zero txid + vout=0
      ...new Uint8Array(32), 0x00, 0x00, 0x00, 0x00,
      // scriptSig length=0
      0x00,
      // sequence = 0xffffffff
      0xff, 0xff, 0xff, 0xff,
      // 1 output
      0x01,
      // value = 50_0000_0000 satoshi (LE 8 bytes) = 0x12a05f200
      0x00, 0x52, 0x0f, 0x12, 0x00, 0x00, 0x00, 0x00,
      // scriptPubKey length=0
      0x00,
      // witness for input[0]: 1 stack item of 1 byte (0xab)
      0x01,  // stack item count = 1
      0x01,  // item length = 1
      0xab,  // item data
      // locktime = 0
      0x00, 0x00, 0x00, 0x00,
    ]);
    const reader = new BufferReader(Buffer.from(w));
    const tx = deserializeTx(reader);
    expect(tx.inputs[0].witness.length).toBe(1);
    expect(tx.inputs[0].witness[0]).toEqual(Buffer.from([0xab]));
  });
});

// ─── Finding E — ADDR 3h store-drop replaced by Core-faithful timestamp clamp ─

describe("Finding E — old ADDR entries are STORED (not dropped)", () => {
  /**
   * Build a fake ADDR payload that simulates handleAddrMessage being called
   * with entries older than 3 hours.  Before the fix these were silently
   * dropped (the `if (now - entry.timestamp > 3*60*60) continue` guard).
   * After the fix the address is stored with its timestamp clamped to
   * 5 days ago (Core net_processing.cpp:5679).
   */

  test("addr entry 4h old is stored in knownAddresses (not dropped)", () => {
    const manager = new PeerManager(makeConfig());

    const now = Math.floor(Date.now() / 1000);
    // 4 hours ago — before the fix this was dropped
    const oldTs = now - 4 * 60 * 60;

    // Construct a fake routable IPv4 addr entry (1.2.3.4:8333).
    // NetworkAddress.ip is 16 bytes: IPv4-mapped IPv6 prefix ::ffff: + 4 octets.
    const ip1234 = Buffer.from([0,0,0,0,0,0,0,0,0,0,0xff,0xff,1,2,3,4]);
    const entry = {
      timestamp: oldTs,
      addr: {
        ip: ip1234,
        port: 8333,
        services: BigInt(ServiceFlags.NODE_NETWORK | ServiceFlags.NODE_WITNESS),
      },
    };

    // Invoke the private handler directly with a minimal fake peer.
    // admitAddrTokens uses peer.host + peer.port to key the token bucket.
    const fakePeer = { host: "192.0.2.1", port: 8333, noban: true } as any;
    (pm(manager) as any).handleAddrMessage(fakePeer, { addrs: [entry] });

    const known: Map<string, any> = pm(manager).knownAddresses;
    expect(known.has("1.2.3.4:8333")).toBe(true);
  });

  test("addr entry with future timestamp >10min is stored with clamped ts (5d ago)", () => {
    const manager = new PeerManager(makeConfig());

    const now = Math.floor(Date.now() / 1000);
    const futureTs = now + 20 * 60; // 20 min in the future

    const ip5678 = Buffer.from([0,0,0,0,0,0,0,0,0,0,0xff,0xff,5,6,7,8]);
    const entry = {
      timestamp: futureTs,
      addr: {
        ip: ip5678,
        port: 8333,
        services: BigInt(ServiceFlags.NODE_NETWORK),
      },
    };

    const fakePeer2 = { host: "192.0.2.2", port: 8333, noban: true } as any;
    (pm(manager) as any).handleAddrMessage(fakePeer2, { addrs: [entry] });

    const known: Map<string, any> = pm(manager).knownAddresses;
    const stored = known.get("5.6.7.8:8333");
    expect(stored).toBeDefined();
    // lastSeen should be ~5 days ago (clamped), NOT the future timestamp
    const storedTs = stored!.lastSeen / 1000; // convert back to seconds
    const fiveDaysAgo = now - 5 * 24 * 60 * 60;
    expect(storedTs).toBeLessThan(now - 4 * 24 * 60 * 60);
    expect(storedTs).toBeGreaterThan(fiveDaysAgo - 60); // within 60s tolerance
  });

  test("addr entry 4h old via addrv2 path is also stored (not dropped)", () => {
    const manager = new PeerManager(makeConfig());

    const now = Math.floor(Date.now() / 1000);
    const oldTs = now - 4 * 60 * 60;

    // Minimal addrv2 IPv4 entry
    const entry = {
      timestamp: oldTs,
      addr: {
        networkId: BIP155Network.IPV4,
        addr: Buffer.from([9, 10, 11, 12]),
        port: 8333,
        services: BigInt(ServiceFlags.NODE_NETWORK),
      },
    };

    const fakePeer3 = { host: "192.0.2.3", port: 8333, noban: true } as any;
    (pm(manager) as any).handleAddrV2Message(fakePeer3, { addrs: [entry] });

    const known: Map<string, any> = pm(manager).knownAddresses;
    // The key is produced by getAddrV2Key for an IPv4 addrv2 entry
    const found = [...known.values()].some((v) => v.host === "9.10.11.12");
    expect(found).toBe(true);
  });
});

// ─── Finding F — ADDR relay gated on message size <=10 ───────────────────────

describe("Finding F — ADDR relay only fires when message has <=10 entries", () => {
  /**
   * relayAddrToRandomPeers is private; we test the gating at the
   * handlePeerMessage callsite by counting how many times the relay method
   * is invoked. We patch it temporarily via the `any` cast to observe calls.
   */

  function makeConnectedPeer(id: string): any {
    return {
      host: id,
      port: 8333,
      state: "connected",
      addrTokenBucket: 1000,
      send: () => {},
    };
  }

  function makeAddrMsg(count: number): any {
    const now = Math.floor(Date.now() / 1000);
    const addrs = Array.from({ length: count }, (_, i) => ({
      timestamp: now,
      addr: {
        // Use different IPs so each parses distinctly (not actually needed for relay)
        ip: Buffer.from([1, i & 0xff, (i >> 8) & 0xff, 1]),
        port: 8333,
        services: BigInt(ServiceFlags.NODE_NETWORK),
      },
    }));
    return { type: "addr", payload: { addrs } };
  }

  test("relay fires when addr message carries exactly 10 entries", () => {
    const manager = new PeerManager(makeConfig());
    let relayCount = 0;
    (pm(manager) as any).relayAddrToRandomPeers = () => { relayCount++; };

    const source = makeConnectedPeer("source");
    // register peer in peers map so handlePeerMessage resolves it
    pm(manager).peers = new Map([["source:8333", source]]);
    pm(manager).lastActivity = new Map();

    (pm(manager) as any).handlePeerMessage(source, makeAddrMsg(10));
    expect(relayCount).toBe(1);
  });

  test("relay does NOT fire when addr message carries 11 entries", () => {
    const manager = new PeerManager(makeConfig());
    let relayCount = 0;
    (pm(manager) as any).relayAddrToRandomPeers = () => { relayCount++; };

    const source = makeConnectedPeer("source");
    pm(manager).peers = new Map([["source:8333", source]]);
    pm(manager).lastActivity = new Map();

    (pm(manager) as any).handlePeerMessage(source, makeAddrMsg(11));
    expect(relayCount).toBe(0);
  });

  test("relay does NOT fire when addr message carries 1000 entries (getaddr reply)", () => {
    const manager = new PeerManager(makeConfig());
    let relayCount = 0;
    (pm(manager) as any).relayAddrToRandomPeers = () => { relayCount++; };

    const source = makeConnectedPeer("source");
    pm(manager).peers = new Map([["source:8333", source]]);
    pm(manager).lastActivity = new Map();

    (pm(manager) as any).handlePeerMessage(source, makeAddrMsg(1000));
    expect(relayCount).toBe(0);
  });

  test("relay fires when addr message carries 1 entry", () => {
    const manager = new PeerManager(makeConfig());
    let relayCount = 0;
    (pm(manager) as any).relayAddrToRandomPeers = () => { relayCount++; };

    const source = makeConnectedPeer("source");
    pm(manager).peers = new Map([["source:8333", source]]);
    pm(manager).lastActivity = new Map();

    (pm(manager) as any).handlePeerMessage(source, makeAddrMsg(1));
    expect(relayCount).toBe(1);
  });
});
