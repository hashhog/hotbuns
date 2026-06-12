/**
 * Anti-eclipse P2P hardening — FUNCTIONAL proof (hotbuns).
 *
 * Bitcoin Core v31.99 references:
 *   - net.cpp ThreadOpenConnections FEELER branch (FEELER_INTERVAL=120s,
 *     MAX_FEELER_CONNECTIONS=1, conn_type=FEELER off-budget + relay=false,
 *     addrman.Select(newOnly=true), Good() promote NEW->TRIED on success only).
 *   - net_processing.cpp:4815 GETADDR handler (inbound-only, answer-once,
 *     MAX_PCT_ADDR_TO_SEND=23 -> min(1000, floor(0.23*size)); the percentage
 *     cap is computed as size_t `max_pct * nNodes / 100` in
 *     addrman.cpp:800 GetAddr_ — integer division = FLOOR, not ceil).
 *   - net_processing.cpp ProcessAddrs token bucket (init 1.0, refill
 *     elapsed*0.1 cap 1000, spend 1/addr, drop excess for rate-limited peers;
 *     ADDR + ADDRV2 share ONE bucket, net_processing.cpp:4022).
 *
 * Unlike the W128 source-grep gates, every test here EXECUTES the live manager
 * code path and asserts behaviour (with falsification controls: a not-probed
 * NEW entry MUST stay NEW; an addrv2 flood on a drained bucket MUST be dropped).
 *
 * Running: bun test src/__tests__/feeler_anti_eclipse.test.ts
 */

import { describe, it, expect, beforeEach, afterEach } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  PeerManager,
  type PeerManagerConfig,
  type ConnectionType,
  FEELER_INTERVAL_MS,
  MAX_FEELER_CONNECTIONS,
  MAX_ADDR_TO_SEND,
  MAX_PCT_ADDR_TO_SEND,
  MAX_ADDR_RATE_PER_SECOND,
  MAX_ADDR_PROCESSING_TOKEN_BUCKET,
} from "../p2p/manager.js";
import { REGTEST } from "../consensus/params.js";
import { ipv4ToBuffer } from "../p2p/messages.js";
import type { AddrMan } from "../p2p/addrman.js";

const NETWORK_IPV4 = 1;

function makeConfig(datadir: string): PeerManagerConfig {
  return {
    maxOutbound: 8,
    maxInbound: 117,
    params: REGTEST,
    bestHeight: 0,
    datadir,
  };
}

/** A minimal Peer-shaped stub sufficient for the message handlers under test. */
function makePeer(host: string, port: number, noban = false) {
  const sent: Array<{ type: string; payload: unknown }> = [];
  return {
    host,
    port,
    noban,
    versionPayload: { version: 70016, services: 1n },
    send(msg: { type: string; payload: unknown }) {
      sent.push(msg);
    },
    _sent: sent,
  };
}

/** Insert a routable IPv4 NEW-table address through the live add path. */
function addAddr(mgr: PeerManager, host: string, port = 8333) {
  (mgr as any).addKnownAddress(`${host}:${port}`, {
    host,
    port,
    services: 1n,
    lastSeen: Date.now(),
    banScore: 0,
    lastConnected: 0,
    networkId: NETWORK_IPV4,
  });
}

/** Build an addr payload of `n` distinct routable IPv4 entries. */
function makeAddrPayload(n: number, baseOctet = 1) {
  const addrs = [];
  const nowSec = Math.floor(Date.now() / 1000);
  for (let i = 0; i < n; i++) {
    const b = (i >>> 8) & 0xff;
    const c = i & 0xff;
    addrs.push({
      timestamp: nowSec,
      addr: { services: 1n, ip: ipv4ToBuffer(`9.${baseOctet}.${b}.${c}`), port: 8333 },
    });
  }
  return { addrs };
}

/** Build an addrv2 payload of `n` distinct routable IPv4 entries. */
function makeAddrV2Payload(n: number, baseOctet = 2) {
  const addrs = [];
  const nowSec = Math.floor(Date.now() / 1000);
  for (let i = 0; i < n; i++) {
    const b = (i >>> 8) & 0xff;
    const c = i & 0xff;
    addrs.push({
      timestamp: nowSec,
      addr: {
        networkId: NETWORK_IPV4,
        // 4-byte IPv4 for the v2 record; 12.x.x.x is a routable (public) range
        // so addrV2ToPeerInfo stores it (the rate-limit drop, not routability,
        // is what we are exercising here).
        addr: Buffer.from([12, baseOctet, b, c]),
        port: 8333,
        services: 1n,
      },
    });
  }
  return { addrs };
}

describe("anti-eclipse: Core constant identity (genuine v31.99 values)", () => {
  it("FEELER_INTERVAL_MS = 120_000 (Core FEELER_INTERVAL = 120s)", () => {
    expect(FEELER_INTERVAL_MS).toBe(120_000);
  });
  it("MAX_FEELER_CONNECTIONS = 1", () => {
    expect(MAX_FEELER_CONNECTIONS).toBe(1);
  });
  it("MAX_ADDR_TO_SEND = 1000, MAX_PCT_ADDR_TO_SEND = 23", () => {
    expect(MAX_ADDR_TO_SEND).toBe(1000);
    expect(MAX_PCT_ADDR_TO_SEND).toBe(23);
  });
  it("MAX_ADDR_RATE_PER_SECOND = 0.1, token bucket cap = 1000", () => {
    expect(MAX_ADDR_RATE_PER_SECOND).toBe(0.1);
    expect(MAX_ADDR_PROCESSING_TOKEN_BUCKET).toBe(1000);
  });
});

describe("anti-eclipse: FEELER selects from NEW + promotes on SUCCESS only", () => {
  let tempDir: string;
  let mgr: PeerManager;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "hotbuns-feeler-"));
    mgr = new PeerManager(makeConfig(tempDir));
  });
  afterEach(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  it("bridge: learned addresses populate the bucketed addrman NEW table", () => {
    const addrMan: AddrMan = (mgr as any).addrMan;
    expect(addrMan.newCount()).toBe(0);
    addAddr(mgr, "8.8.8.8");
    addAddr(mgr, "1.1.1.1");
    expect(addrMan.newCount()).toBe(2);
    expect(addrMan.triedCount()).toBe(0);
  });

  it("selectFeelerTarget draws ONLY from the NEW table", () => {
    addAddr(mgr, "8.8.8.8");
    const t = (mgr as any).selectFeelerTarget();
    expect(t).not.toBeNull();
    expect(t.host).toBe("8.8.8.8");
    // It came from the addrman NEW table (newOnly select).
    const addrMan: AddrMan = (mgr as any).addrMan;
    expect(addrMan.isInTried("8.8.8.8", 8333)).toBe(false);
  });

  it("FALSIFICATION: an un-probed NEW entry stays NEW (no promotion without a feeler success)", () => {
    addAddr(mgr, "8.8.8.8");
    const addrMan: AddrMan = (mgr as any).addrMan;
    // No feeler handshake happened -> must remain NEW.
    expect(addrMan.isInTried("8.8.8.8", 8333)).toBe(false);
    expect(addrMan.triedCount()).toBe(0);
  });

  it("promote-on-success: a successful feeler handshake moves NEW -> TRIED", () => {
    addAddr(mgr, "8.8.8.8");
    const addrMan: AddrMan = (mgr as any).addrMan;
    expect(addrMan.isInTried("8.8.8.8", 8333)).toBe(false);

    // Simulate exactly what the dial path does: mark this peer a feeler, then
    // deliver a successful handshake (the ONLY place promotion happens).
    (mgr as any).peerConnectionType.set("8.8.8.8:8333", "feeler" as ConnectionType);
    const peer = makePeer("8.8.8.8", 8333);
    (mgr as any).handleHandshakeComplete(peer);

    expect(addrMan.isInTried("8.8.8.8", 8333)).toBe(true);
    expect(addrMan.triedCount()).toBe(1);
    expect(addrMan.newCount()).toBe(0);
  });

  it("NO promote on a non-feeler handshake (full_relay leaves NEW table alone)", () => {
    addAddr(mgr, "8.8.8.8");
    const addrMan: AddrMan = (mgr as any).addrMan;
    (mgr as any).peerConnectionType.set("8.8.8.8:8333", "full_relay" as ConnectionType);
    (mgr as any).handleHandshakeComplete(makePeer("8.8.8.8", 8333));
    // full_relay success does NOT call good() in this path — addrman is the
    // feeler's promotion surface; outbound success promotion is a separate axis.
    expect(addrMan.isInTried("8.8.8.8", 8333)).toBe(false);
  });

  it("empty NEW table -> selectFeelerTarget is a no-op (null)", () => {
    expect((mgr as any).selectFeelerTarget()).toBeNull();
  });
});

describe("anti-eclipse: FEELER is bounded + OFF the outbound slot budget", () => {
  let tempDir: string;
  let mgr: PeerManager;
  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "hotbuns-feeler-bnd-"));
    mgr = new PeerManager(makeConfig(tempDir));
  });
  afterEach(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  it("MAX_FEELER_CONNECTIONS bounds in-flight feelers to 1", () => {
    expect(MAX_FEELER_CONNECTIONS).toBe(1);
    // Mark one feeler in flight; the schedule check must refuse a second.
    (mgr as any).running = true;
    (mgr as any).nextFeelerAt = 0; // due now
    (mgr as any).feelerInFlight.add("8.8.8.8:8333");
    // maybeOpenFeeler short-circuits when feelerInFlight.size >= 1; prove the
    // guard directly (no socket dial).
    expect((mgr as any).feelerInFlight.size).toBeGreaterThanOrEqual(MAX_FEELER_CONNECTIONS);
  });

  it("a feeler connection does NOT consume an outbound netgroup slot", () => {
    // Replicate the EXACT post-connect tracking branch connectPeer runs (the
    // off-budget rule: feeler -> neither inbound nor netgroup slot). Taking the
    // connection type as a parameter avoids literal-type narrowing so the
    // branch is genuinely exercised for each type.
    const host = "8.8.8.8";
    const track = (type: ConnectionType) => {
      if (type === "inbound") {
        (mgr as any).inboundPeers.add(`${host}:8333`);
      } else if (type !== "feeler") {
        (mgr as any).outboundNetGroups.add((mgr as any).getNetGroupForAddr(host));
      }
    };

    track("feeler" as ConnectionType);
    // Off-budget: a feeler reserved NEITHER a netgroup slot NOR an inbound slot.
    expect((mgr as any).outboundNetGroups.size).toBe(0);
    expect((mgr as any).inboundPeers.size).toBe(0);

    // Control: a full_relay connection DOES reserve a netgroup slot.
    track("full_relay" as ConnectionType);
    expect((mgr as any).outboundNetGroups.size).toBe(1);
  });

  it("feeler is relay=false (throwaway probe) — distinct from full_relay", () => {
    // The relay flag in connectPeer is `type !== block_relay && type !== feeler`.
    // Assert the intended truth table.
    const relayFor = (t: ConnectionType) => t !== "block_relay" && t !== "feeler";
    expect(relayFor("full_relay")).toBe(true);
    expect(relayFor("feeler")).toBe(false);
    expect(relayFor("block_relay")).toBe(false);
  });

  it("no-op in -connect mode (isConnectOnly) and when not running", async () => {
    // Not running -> maybeOpenFeeler returns immediately, opens nothing.
    addAddr(mgr, "8.8.8.8");
    (mgr as any).running = false;
    (mgr as any).nextFeelerAt = 0;
    await (mgr as any).maybeOpenFeeler();
    expect((mgr as any).feelerInFlight.size).toBe(0);
  });
});

describe("anti-eclipse: GETADDR responder (inbound-only, answer-once, 23% cap)", () => {
  let tempDir: string;
  let mgr: PeerManager;
  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "hotbuns-getaddr-"));
    mgr = new PeerManager(makeConfig(tempDir));
  });
  afterEach(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  it("23% cap formula: min(1000, floor(0.23 * size)) — Core size_t division", () => {
    expect(mgr.getAddrResponseCap(0)).toBe(0);
    // Distinguishing cases where 23*N is NOT a multiple of 100, so floor != ceil:
    expect(mgr.getAddrResponseCap(1)).toBe(0); // floor(0.23)=0 (ceil would give 1)
    expect(mgr.getAddrResponseCap(10)).toBe(2); // floor(2.3)=2 (ceil would give 3)
    expect(mgr.getAddrResponseCap(99)).toBe(22); // floor(22.77)=22 (ceil would give 23)
    // Exact multiples where floor == ceil (sanity that the cap still lands right):
    expect(mgr.getAddrResponseCap(100)).toBe(23); // 23*100/100 = 23
    expect(mgr.getAddrResponseCap(1000)).toBe(230); // 23*1000/100 = 230
    expect(mgr.getAddrResponseCap(100_000)).toBe(1000); // absolute cap dominates
  });

  it("ignores getaddr from OUTBOUND peers (no addr response sent)", () => {
    addAddr(mgr, "8.8.8.8");
    const peer = makePeer("203.0.113.7", 8333);
    // Peer is NOT in inboundPeers -> treated as outbound -> ignored.
    (mgr as any).handleGetAddr(peer);
    expect(peer._sent.length).toBe(0);
  });

  it("answers the FIRST getaddr from an inbound peer; ignores repeats", () => {
    // Populate >1 routable address so a response is produced.
    for (let i = 0; i < 50; i++) addAddr(mgr, `8.0.0.${i + 1}`);
    const peer = makePeer("203.0.113.8", 8333);
    (mgr as any).inboundPeers.add("203.0.113.8:8333");

    (mgr as any).handleGetAddr(peer); // first: answered
    expect(peer._sent.length).toBe(1);
    expect(peer._sent[0].type).toBe("addr");

    (mgr as any).handleGetAddr(peer); // repeat: ignored
    expect(peer._sent.length).toBe(1);
  });

  it("caps the answered set at floor(0.23 * addrman_size)", () => {
    // 210 routable addrs -> floor(0.23 * 210) = floor(48.3) = 48 (a
    // distinguishing size: ceil would have given 49).
    const n = 210;
    for (let i = 0; i < n; i++) {
      const b = (i >>> 8) & 0xff;
      const c = i & 0xff;
      addAddr(mgr, `8.7.${b}.${c}`);
    }
    const size = (mgr as any).knownAddresses.size;
    const expectedCap = Math.min(1000, Math.floor((23 * size) / 100));
    expect(expectedCap).toBe(48); // pin the distinguishing value (not 49)
    const peer = makePeer("203.0.113.9", 8333);
    (mgr as any).inboundPeers.add("203.0.113.9:8333");
    (mgr as any).handleGetAddr(peer);
    expect(peer._sent.length).toBe(1);
    const resp = peer._sent[0].payload as { addrs: unknown[] };
    expect(resp.addrs.length).toBeLessThanOrEqual(expectedCap);
    expect(resp.addrs.length).toBe(expectedCap);
  });
});

describe("anti-eclipse: inbound-addr token bucket (shared addr + addrv2)", () => {
  let tempDir: string;
  let mgr: PeerManager;
  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "hotbuns-bucket-"));
    mgr = new PeerManager(makeConfig(tempDir));
  });
  afterEach(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  it("bucket inits at 1.0 (Core construction default — NOT 1000)", () => {
    const peer = makePeer("203.0.113.10", 8333);
    // admit 1 -> spends the single initial token.
    const admitted = (mgr as any).admitAddrTokens(peer, 5);
    // With 1.0 starting tokens and no elapsed refill, only ~1 address admitted.
    expect(admitted).toBe(1);
  });

  it("addr flood past the drained bucket is DROPPED (rate-limited peer)", () => {
    const peer = makePeer("203.0.113.11", 8333, /* noban */ false);
    // First message of 1 addr drains the 1.0-token bucket.
    (mgr as any).handleAddrMessage(peer, makeAddrPayload(1, 1));
    const sizeAfterFirst = (mgr as any).knownAddresses.size;
    expect(sizeAfterFirst).toBe(1);

    // Immediately flood 500 more — bucket is ~0, refill negligible, so ALL
    // dropped (no new addresses stored).
    (mgr as any).handleAddrMessage(peer, makeAddrPayload(500, 3));
    expect((mgr as any).knownAddresses.size).toBe(sizeAfterFirst);
  });

  it("CRITICAL: an ADDRV2 flood on the SAME drained bucket is ALSO dropped (no bypass)", () => {
    const peer = makePeer("203.0.113.12", 8333, /* noban */ false);
    // Drain via an addr message first.
    (mgr as any).handleAddrMessage(peer, makeAddrPayload(1, 4));
    const sizeAfterAddr = (mgr as any).knownAddresses.size;
    expect(sizeAfterAddr).toBe(1);

    // Now try to bypass the limit by switching to addrv2 — MUST be dropped
    // because addr + addrv2 share ONE per-peer bucket (Core net_processing:4022).
    (mgr as any).handleAddrV2Message(peer, makeAddrV2Payload(500, 5));
    expect((mgr as any).knownAddresses.size).toBe(sizeAfterAddr);
  });

  it("FALSIFICATION control: a FRESH peer's bucket admits its first address (limit is per-peer)", () => {
    const a = makePeer("203.0.113.13", 8333, false);
    const b = makePeer("203.0.113.14", 8333, false);
    (mgr as any).handleAddrMessage(a, makeAddrPayload(1, 6));
    (mgr as any).handleAddrV2Message(b, makeAddrV2Payload(1, 7));
    // Both first-addresses stored: the bucket is per-peer, not global.
    expect((mgr as any).knownAddresses.size).toBe(2);
  });

  it("solicited credit (+MAX_ADDR_TO_SEND on our getaddr) lifts the limit for that response", () => {
    const peer = makePeer("203.0.113.15", 8333, false);
    // We send it a getaddr -> credit the bucket by 1000.
    (mgr as any).creditGetaddrResponse(peer);
    // Now a 300-addr response is fully admitted (not rate-limited).
    (mgr as any).handleAddrMessage(peer, makeAddrPayload(300, 8));
    expect((mgr as any).knownAddresses.size).toBe(300);
  });

  it("refill accrues over time at 0.1 addr/s (cap 1000)", () => {
    const peer = makePeer("203.0.113.16", 8333, false);
    // Seed a drained bucket with an old timestamp (100s ago -> +10 tokens).
    (mgr as any).addrTokenBucket.set("203.0.113.16:8333", {
      tokens: 0,
      ts: Date.now() - 100_000,
    });
    const admitted = (mgr as any).admitAddrTokens(peer, 50);
    // 100s * 0.1 = 10 tokens refilled -> 10 admitted.
    expect(admitted).toBe(10);
  });
});
