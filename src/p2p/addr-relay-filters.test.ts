/**
 * Audit H4 (audits/security/hotbuns-2026-10-29.md): every addr/addrv2 message
 * of <=10 entries, even an empty one, was forwarded as-is to 2 random
 * connected peers, block-relay-only ones included. The token bucket only
 * limited what was stored; freshness, routability, services, getaddr replies
 * and already-known addresses were never checked, and addrv2 went to peers
 * that never sent sendaddrv2.
 *
 * Core: ProcessAddrs (net_processing.cpp:5625-5703) relays only addresses
 * that passed the token bucket, advertise NODE_NETWORK(_LIMITED), are not
 * banned, are stamped within 10 minutes, are routable, come from a <=10-entry
 * message and not from a getaddr reply. RelayAddress (:2277) sends each to 2
 * deterministic addr-relay peers (never block-relay-only, SetupAddressRelay
 * :5608) that do not already know it (m_addr_known) and can decode it
 * (IsAddrCompatible).
 *
 * Regtest only: an in-memory PeerManager with local stub peers.
 */

import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { PeerManager, ServiceFlags, type PeerManagerConfig } from "./manager.js";
import { REGTEST } from "../consensus/params.js";
import { BIP155Network } from "./addrv2.js";

let dir: string;

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "hotbuns-addr-relay-"));
});

afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
});

function makeManager(): any {
  const config: PeerManagerConfig = {
    maxOutbound: 8,
    maxInbound: 117,
    params: REGTEST,
    bestHeight: 0,
    datadir: dir,
  };
  return new PeerManager(config) as any;
}

interface StubPeer {
  host: string;
  port: number;
  state: string;
  wantsAddrV2: boolean;
  sent: any[];
  send(msg: any): boolean;
}

function stubPeer(host: string, wantsAddrV2 = false): StubPeer {
  const p: StubPeer = {
    host,
    port: 18444,
    state: "connected",
    wantsAddrV2,
    sent: [],
    send(msg: any) {
      p.sent.push(msg);
      return true;
    },
  };
  return p;
}

/** Register a stub peer the way connect/accept does. */
function add(pm: any, p: StubPeer, kind: "full_relay" | "block_relay" | "inbound"): StubPeer {
  const key = `${p.host}:${p.port}`;
  pm.peers.set(key, p);
  pm.peerConnectionType.set(key, kind);
  if (kind === "inbound") pm.inboundPeers.add(key);
  return p;
}

function mapped(ip: string): Buffer {
  const b = Buffer.alloc(16);
  b[10] = 0xff;
  b[11] = 0xff;
  ip.split(".").forEach((o, i) => (b[12 + i] = Number(o)));
  return b;
}

const NET = ServiceFlags.NODE_NETWORK | ServiceFlags.NODE_WITNESS;

function addrEntry(ip: string, opts: { age?: number; services?: bigint } = {}) {
  return {
    timestamp: Math.floor(Date.now() / 1000) - (opts.age ?? 30),
    addr: { services: opts.services ?? NET, ip: mapped(ip), port: 8333 },
  };
}

function addrMsg(...entries: any[]): any {
  return { type: "addr", payload: { addrs: entries } };
}

/** Every address any target was sent, as "ip" strings. */
function relayed(...targets: StubPeer[]): string[] {
  const out: string[] = [];
  for (const t of targets) {
    for (const m of t.sent) {
      if (m.type === "addr") {
        for (const e of m.payload.addrs) out.push(e.addr.ip.subarray(12).join("."));
      } else if (m.type === "addrv2") {
        for (const e of m.payload.addrs) out.push(`v2:${e.addr.addr.toString("hex")}`);
      }
    }
  }
  return out;
}

describe("H4: addr relay applies Core's admission and filters", () => {
  test("control: a fresh routable address from a full-relay peer is relayed to 2 peers", () => {
    const pm = makeManager();
    const src = add(pm, stubPeer("8.0.0.1"), "inbound");
    const targets = [1, 2, 3].map((i) => add(pm, stubPeer(`8.0.1.${i}`), "full_relay"));
    pm.handlePeerMessage(src, addrMsg(addrEntry("9.9.9.9")));
    expect(relayed(...targets)).toEqual(["9.9.9.9", "9.9.9.9"]);
  });

  test("an empty addr message is not relayed", () => {
    const pm = makeManager();
    const src = add(pm, stubPeer("8.0.0.1"), "inbound");
    const t = [add(pm, stubPeer("8.0.1.1"), "full_relay"), add(pm, stubPeer("8.0.1.2"), "full_relay")];
    pm.handlePeerMessage(src, addrMsg());
    expect(t[0].sent.length + t[1].sent.length).toBe(0);
  });

  test("a block-relay-only peer is never sent relayed addresses", () => {
    const pm = makeManager();
    const src = add(pm, stubPeer("8.0.0.1"), "inbound");
    const blockOnly = add(pm, stubPeer("8.0.1.1"), "block_relay");
    pm.handlePeerMessage(src, addrMsg(addrEntry("9.9.9.9")));
    expect(blockOnly.sent.length).toBe(0);
  });

  test("addr from a block-relay-only peer is ignored: not stored, not relayed", () => {
    const pm = makeManager();
    const src = add(pm, stubPeer("8.0.0.1"), "block_relay");
    const t = add(pm, stubPeer("8.0.1.1"), "full_relay");
    pm.handlePeerMessage(src, addrMsg(addrEntry("9.9.9.9")));
    expect(t.sent.length).toBe(0);
    expect(pm.knownAddresses.has("9.9.9.9:8333")).toBe(false);
  });

  test("addresses past the token bucket are not relayed", () => {
    const pm = makeManager();
    const src = add(pm, stubPeer("8.0.0.1"), "inbound");
    const t = [add(pm, stubPeer("8.0.1.1"), "full_relay"), add(pm, stubPeer("8.0.1.2"), "full_relay")];
    const entries = Array.from({ length: 10 }, (_, i) => addrEntry(`9.9.9.${i + 1}`));
    pm.handlePeerMessage(src, addrMsg(...entries));
    // A new peer's bucket holds 1 token (Core m_addr_token_bucket{1.0}).
    expect(new Set(relayed(...t)).size).toBe(1);
  });

  test("stale, unroutable and non-serving addresses are not relayed", () => {
    const pm = makeManager();
    const t = [add(pm, stubPeer("8.0.1.1"), "full_relay"), add(pm, stubPeer("8.0.1.2"), "full_relay")];
    // One source per entry so each gets its own token.
    const cases = [
      addrEntry("9.9.9.1", { age: 11 * 60 }), // older than 10 minutes
      addrEntry("192.168.1.1"), // RFC1918
      addrEntry("9.9.9.3", { services: ServiceFlags.NODE_WITNESS }), // no NODE_NETWORK(_LIMITED)
    ];
    cases.forEach((e, i) => {
      const src = add(pm, stubPeer(`8.0.0.${i + 1}`), "inbound");
      pm.handlePeerMessage(src, addrMsg(e));
    });
    expect(relayed(...t)).toEqual([]);
  });

  test("a getaddr reply is not relayed", () => {
    const pm = makeManager();
    const src = add(pm, stubPeer("8.0.0.1"), "full_relay");
    const t = [add(pm, stubPeer("8.0.1.1"), "full_relay"), add(pm, stubPeer("8.0.1.2"), "full_relay")];
    pm.creditGetaddrResponse(src); // we asked it for addresses
    pm.handlePeerMessage(src, addrMsg(addrEntry("9.9.9.9")));
    expect(relayed(...t)).toEqual([]);
    // That reply ended the getaddr round: later announcements relay again.
    pm.handlePeerMessage(src, addrMsg(addrEntry("9.9.9.8")));
    expect(relayed(...t)).toEqual(["9.9.9.8", "9.9.9.8"]);
  });

  test("an address reaches a peer at most once (m_addr_known)", () => {
    const pm = makeManager();
    const t = [add(pm, stubPeer("8.0.1.1"), "full_relay"), add(pm, stubPeer("8.0.1.2"), "full_relay")];
    for (let i = 1; i <= 5; i++) {
      const src = add(pm, stubPeer(`8.0.0.${i}`), "inbound");
      pm.handlePeerMessage(src, addrMsg(addrEntry("9.9.9.9")));
    }
    expect(relayed(...t)).toEqual(["9.9.9.9", "9.9.9.9"]);
  });

  test("an address is not echoed back to the peer that sent it", () => {
    const pm = makeManager();
    const a = add(pm, stubPeer("8.0.1.1"), "full_relay");
    const b = add(pm, stubPeer("8.0.1.2"), "full_relay");
    const src = add(pm, stubPeer("8.0.0.1"), "inbound");
    pm.handlePeerMessage(src, addrMsg(addrEntry("9.9.9.9")));
    // b now relays the same address back: a already has it, src sent it.
    pm.handlePeerMessage(b, addrMsg(addrEntry("9.9.9.9")));
    expect(relayed(src)).toEqual([]);
    expect(relayed(a)).toEqual(["9.9.9.9"]);
  });

  test("an inbound peer gets relayed addresses only after it opted in", () => {
    const pm = makeManager();
    const quiet = add(pm, stubPeer("8.0.1.1"), "inbound");
    const src = add(pm, stubPeer("8.0.0.1"), "inbound");
    pm.handlePeerMessage(src, addrMsg(addrEntry("9.9.9.9")));
    expect(quiet.sent.length).toBe(0);
    pm.handlePeerMessage(quiet, { type: "getaddr", payload: null });
    quiet.sent.length = 0;
    const src2 = add(pm, stubPeer("8.0.0.2"), "inbound");
    pm.handlePeerMessage(src2, addrMsg(addrEntry("9.9.9.8")));
    expect(relayed(quiet)).toEqual(["9.9.9.8"]);
  });

  test("a Tor address goes only to sendaddrv2 peers; v1 peers get legacy addr", () => {
    const pm = makeManager();
    const v1 = add(pm, stubPeer("8.0.1.1", false), "full_relay");
    const v2 = add(pm, stubPeer("8.0.1.2", true), "full_relay");
    const src = add(pm, stubPeer("8.0.0.1", true), "inbound");
    const now = Math.floor(Date.now() / 1000);
    // A valid TorV3 address: ed25519 pubkey bytes, onion checksum is not part
    // of the wire form, so any 32 bytes that pass isValidTorV3Address do.
    const tor = Buffer.alloc(32, 0x11);
    pm.handlePeerMessage(src, {
      type: "addrv2",
      payload: {
        addrs: [{ timestamp: now - 30, addr: { networkId: BIP155Network.TORV3, addr: tor, port: 8333, services: NET } }],
      },
    });
    expect(v1.sent.length).toBe(0);
    expect(v2.sent.map((m) => m.type)).toEqual(["addrv2"]);

    // An IPv4 address sent as addrv2 reaches the v1 peer as plain addr. The
    // first source leaves so v1 and v2 are the only 2 candidates.
    src.state = "disconnected";
    const src2 = add(pm, stubPeer("8.0.0.2", true), "inbound");
    pm.handlePeerMessage(src2, {
      type: "addrv2",
      payload: {
        addrs: [{
          timestamp: now - 30,
          addr: { networkId: BIP155Network.IPV4, addr: Buffer.from([9, 9, 9, 9]), port: 8333, services: NET },
        }],
      },
    });
    expect(v1.sent.map((m) => m.type)).toEqual(["addr"]);
    expect(relayed(v1)).toEqual(["9.9.9.9"]);
  });
});
