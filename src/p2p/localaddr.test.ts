/**
 * Self-address advertisement (Core -externalip / -discover / MaybeSendAddr).
 *
 * Covers: the routable filter, discovery from VERSION addr_recv, the addr /
 * addrv2 message contents (incl. the LISTEN port), the IBD gate, the
 * connection-type gates, the Poisson re-send slot, and the getpeerinfo
 * addrlocal source.
 */

import { describe, expect, test, beforeEach, afterEach } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PeerManager, type PeerManagerConfig } from "./manager.js";
import {
  LocalAddrTable,
  LOCAL_MANUAL,
  DISCOVERED_LOCAL_ADDR_TTL_MS,
  MAX_DISCOVERED_LOCAL_ADDRS,
  isRoutableAddr,
  ipBytesToString,
  normalizeHost,
  parseExternalIP,
  peerAddrLocal,
  nextLocalAddrDelayMs,
  AVG_LOCAL_ADDRESS_BROADCAST_INTERVAL_MS,
} from "./localaddr.js";
import {
  hostToBuffer,
  serializeMessage,
  parseHeader,
  deserializeMessage,
  type NetworkMessage,
} from "./messages.js";
import { REGTEST } from "../consensus/params.js";
import { resolveDiscover, parseArgs } from "../cli/cli.js";

const LISTEN_PORT = 39777;

function makeConfig(datadir: string, extra: Partial<PeerManagerConfig> = {}): PeerManagerConfig {
  return {
    maxOutbound: 8,
    maxInbound: 117,
    params: REGTEST,
    bestHeight: 0,
    datadir,
    listen: true,
    port: LISTEN_PORT,
    ...extra,
  };
}

interface FakePeer {
  host: string;
  port: number;
  versionPayload: any;
  wantsAddrV2: boolean;
  nextLocalAddrSend: number;
  handshakeComplete: boolean;
  sent: NetworkMessage[];
  send(msg: NetworkMessage): boolean;
  disconnect(reason?: string): void;
}

/** A handshaken peer whose VERSION said it sees us at `addrRecv`. */
function fakePeer(host: string, port: number, addrRecv?: { host: string; port: number }): FakePeer {
  const p: FakePeer = {
    host,
    port,
    versionPayload: {
      version: 70016,
      services: 0x409n,
      timestamp: 0n,
      addrRecv: addrRecv
        ? { services: 0n, ip: hostToBuffer(addrRecv.host), port: addrRecv.port }
        : { services: 0n, ip: Buffer.alloc(16, 0), port: 0 },
      addrFrom: { services: 0n, ip: Buffer.alloc(16, 0), port: 0 },
      nonce: 1n,
      userAgent: "/Satoshi:28.0.0/",
      startHeight: 0,
      relay: true,
    },
    wantsAddrV2: false,
    nextLocalAddrSend: 0,
    handshakeComplete: true,
    sent: [],
    send(msg: NetworkMessage) {
      this.sent.push(msg);
      return true;
    },
    disconnect() {},
  };
  return p;
}

/** Register a fake peer in the manager's bookkeeping with a connection type. */
function register(mgr: PeerManager, p: FakePeer, connType: "full_relay" | "block_relay" | "inbound" | "feeler") {
  const key = `${p.host}:${p.port}`;
  (mgr as any).peers.set(key, p);
  (mgr as any).peerConnectionType.set(key, connType);
  if (connType === "inbound") (mgr as any).inboundPeers.add(key);
}

/** Wire round-trip a message through the real serializer. */
function roundTrip(msg: NetworkMessage): NetworkMessage {
  const wire = serializeMessage(REGTEST.networkMagic, msg);
  const header = parseHeader(wire)!;
  return deserializeMessage(header, wire.subarray(24, 24 + header.length));
}

describe("routable filter", () => {
  test("IPv4 reuses the node's isRoutable", () => {
    expect(isRoutableAddr("1.2.3.4")).toBe(true);
    expect(isRoutableAddr("76.38.7.169")).toBe(true);
    for (const h of ["127.0.0.1", "0.0.0.0", "10.1.2.3", "172.16.0.1", "192.168.1.128",
      "169.254.1.1", "100.64.0.1", "198.18.0.1", "192.0.2.1", "203.0.113.5"]) {
      expect(isRoutableAddr(h)).toBe(false);
    }
  });

  test("IPv4-mapped IPv6 is judged as IPv4", () => {
    expect(isRoutableAddr("::ffff:1.2.3.4")).toBe(true);
    expect(isRoutableAddr("::ffff:127.0.0.1")).toBe(false);
    expect(normalizeHost("::ffff:1.2.3.4")).toBe("1.2.3.4");
  });

  test("IPv6 Core non-routable ranges", () => {
    expect(isRoutableAddr("2606:4700::1111")).toBe(true);
    expect(isRoutableAddr("[2a01:4f8::1]")).toBe(true);
    for (const h of ["::", "::1", "2001:db8::1", "fc00::1", "fd12::1", "fe80::1",
      "2001:10::1", "2001:20::1"]) {
      expect(isRoutableAddr(h)).toBe(false);
    }
    expect(isRoutableAddr("not-an-ip")).toBe(false);
    expect(isRoutableAddr("12zz::1")).toBe(false);
  });

  test("ipBytesToString: unspecified -> null, v4-mapped -> dotted, v6 compressed", () => {
    expect(ipBytesToString(Buffer.alloc(16, 0))).toBeNull();
    expect(ipBytesToString(hostToBuffer("0.0.0.0"))).toBeNull();
    expect(ipBytesToString(hostToBuffer("1.2.3.4"))).toBe("1.2.3.4");
    expect(ipBytesToString(hostToBuffer("2001:db8:0:0:1:0:0:1"))).toBe("2001:db8::1:0:0:1");
  });
});

describe("--externalip parsing and -discover soft-set", () => {
  test("parseExternalIP forms", () => {
    expect(parseExternalIP("1.2.3.4")).toEqual({ host: "1.2.3.4", port: 0 });
    expect(parseExternalIP("1.2.3.4:8331")).toEqual({ host: "1.2.3.4", port: 8331 });
    expect(parseExternalIP("[2a01:4f8::1]:8331")).toEqual({ host: "2a01:4f8::1", port: 8331 });
    expect(parseExternalIP("2a01:4f8::1")).toEqual({ host: "2a01:4f8::1", port: 0 });
    expect(() => parseExternalIP("example.com")).toThrow();
    expect(() => parseExternalIP("1.2.3.4:0")).toThrow();
    expect(() => parseExternalIP("1.2.3.4:70000")).toThrow();
  });

  test("CLI: repeatable + comma-separated; discover off unless explicit", () => {
    const a = parseArgs(["bun", "x", "--externalip=1.2.3.4,5.6.7.8:9", "--externalip=9.9.9.9"]);
    expect(a.config.externalIP).toEqual(["1.2.3.4", "5.6.7.8:9", "9.9.9.9"]);
    expect(resolveDiscover(a.config)).toBe(false);
    const b = parseArgs(["bun", "x", "--externalip=1.2.3.4", "--discover"]);
    expect(resolveDiscover(b.config)).toBe(true);
    const c = parseArgs(["bun", "x"]);
    expect(resolveDiscover(c.config)).toBe(true);
    const d = parseArgs(["bun", "x", "--discover=0"]);
    expect(resolveDiscover(d.config)).toBe(false);
  });
});

describe("LocalAddrTable", () => {
  test("manual entry is usable at score LOCAL_MANUAL; non-routable refused", () => {
    const t = new LocalAddrTable();
    expect(t.addManual("192.168.1.5", 8331)).toBe(false);
    expect(t.addManual("1.2.3.4", 8331)).toBe(true);
    expect(t.best(null, 0)).toEqual({ address: "1.2.3.4", port: 8331, score: LOCAL_MANUAL });
  });

  test("discovered entry needs 2 distinct netgroups; same group does not count twice", () => {
    const t = new LocalAddrTable();
    const now = 1_000_000;
    expect(t.confirm("5.6.7.8", 8331, "ipv4:9.9", true, now)).toBe(true);
    expect(t.best(null, now)).toBeNull();
    t.confirm("5.6.7.8", 8331, "ipv4:9.9", true, now); // same /16 again
    expect(t.best(null, now)).toBeNull();
    t.confirm("5.6.7.8", 8331, "ipv4:8.8", true, now);
    expect(t.best(null, now)).toEqual({ address: "5.6.7.8", port: 8331, score: 2 });
  });

  test("inbound (create=false) only bumps an existing entry", () => {
    const t = new LocalAddrTable();
    expect(t.confirm("5.6.7.8", 8331, "ipv4:9.9", false, 0)).toBe(false);
    expect(t.size).toBe(0);
    t.confirm("5.6.7.8", 8331, "ipv4:9.9", true, 0);
    expect(t.confirm("5.6.7.8", 8331, "ipv4:7.7", false, 0)).toBe(true);
    expect(t.list(0)[0].score).toBe(2);
  });

  test("discovered entries expire after 3h unconfirmed; manual never", () => {
    const t = new LocalAddrTable();
    t.addManual("1.2.3.4", 8331);
    t.confirm("5.6.7.8", 8331, "g1", true, 0);
    expect(t.size).toBe(2);
    expect(t.list(DISCOVERED_LOCAL_ADDR_TTL_MS + 1).map((e) => e.address)).toEqual(["1.2.3.4"]);
  });

  test("discovered entries are capped", () => {
    const t = new LocalAddrTable();
    for (let i = 1; i <= MAX_DISCOVERED_LOCAL_ADDRS + 5; i++) {
      t.confirm(`5.6.7.${i}`, 8331, "g", true, i);
    }
    expect(t.size).toBe(MAX_DISCOVERED_LOCAL_ADDRS);
  });

  test("best prefers the peer's address family", () => {
    const t = new LocalAddrTable();
    t.addManual("1.2.3.4", 8331);
    t.addManual("2a01:4f8::1", 8331);
    expect(t.best("2606:4700::1111", 0)!.address).toBe("2a01:4f8::1");
    expect(t.best("8.8.8.8", 0)!.address).toBe("1.2.3.4");
  });
});

describe("PeerManager self-advertisement", () => {
  let dir: string;
  let mgr: PeerManager;

  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "hotbuns-selfadv-"));
  });
  afterEach(async () => {
    await mgr?.stop();
    await rm(dir, { recursive: true, force: true });
  });

  test("externalip bare IP gets the LISTEN port; localaddresses shape", () => {
    mgr = new PeerManager(makeConfig(dir));
    expect(mgr.addExternalIP("1.2.3.4")).toBe(true);
    expect(mgr.addExternalIP("10.0.0.1")).toBe(false);
    expect(mgr.getLocalAddresses()).toEqual([{ address: "1.2.3.4", port: LISTEN_PORT, score: 4 }]);
  });

  test("not listening: externalip refused and nothing sent", () => {
    mgr = new PeerManager(makeConfig(dir, { listen: false }));
    expect(mgr.addExternalIP("1.2.3.4")).toBe(false);
    const p = fakePeer("8.8.8.8", 8333);
    register(mgr, p, "full_relay");
    expect(mgr.maybeSendLocalAddr(p as any, Date.now())).toBe(false);
    expect(p.sent.length).toBe(0);
  });

  test("discovery from outbound addr_recv: both routable, listen port, 2 groups", () => {
    mgr = new PeerManager(makeConfig(dir));
    const now = Date.now();
    // Peer reports it sees us at 5.6.7.8:54321 (our ephemeral port) — we
    // must store OUR LISTEN PORT, not 54321.
    mgr.noteVersionAddrRecv(fakePeer("8.8.8.8", 8333, { host: "5.6.7.8", port: 54321 }) as any, false, now);
    expect(mgr.getLocalAddresses()).toEqual([{ address: "5.6.7.8", port: LISTEN_PORT, score: 1 }]);
    mgr.noteVersionAddrRecv(fakePeer("9.9.9.9", 8333, { host: "5.6.7.8", port: 1 }) as any, false, now);
    expect(mgr.getLocalAddresses()).toEqual([{ address: "5.6.7.8", port: LISTEN_PORT, score: 2 }]);
  });

  test("discovery rejects non-routable peer or addr_recv, inbound-create, and discover=false", () => {
    mgr = new PeerManager(makeConfig(dir));
    const now = Date.now();
    mgr.noteVersionAddrRecv(fakePeer("127.0.0.1", 8333, { host: "5.6.7.8", port: 1 }) as any, false, now);
    mgr.noteVersionAddrRecv(fakePeer("8.8.8.8", 8333, { host: "192.168.1.128", port: 1 }) as any, false, now);
    mgr.noteVersionAddrRecv(fakePeer("8.8.4.4", 8333) as any, false, now); // unspecified
    mgr.noteVersionAddrRecv(fakePeer("9.9.9.9", 50000, { host: "5.6.7.8", port: 1 }) as any, true, now);
    expect(mgr.getLocalAddresses()).toEqual([]);
    const m2 = new PeerManager(makeConfig(dir, { discover: false }));
    m2.noteVersionAddrRecv(fakePeer("8.8.8.8", 8333, { host: "5.6.7.8", port: 1 }) as any, false, now);
    expect(m2.getLocalAddresses()).toEqual([]);
    m2.stop();
  });

  test("addr message: one entry, our services, time now, LISTEN port (wire round-trip)", () => {
    mgr = new PeerManager(makeConfig(dir, { discover: false }));
    mgr.addExternalIP("1.2.3.4");
    const p = fakePeer("8.8.8.8", 8333, { host: "5.6.7.8", port: 50000 });
    register(mgr, p, "full_relay");
    const now = 1_790_000_000_000;
    expect(mgr.maybeSendLocalAddr(p as any, now)).toBe(true);
    expect(p.sent.length).toBe(1);
    const msg = roundTrip(p.sent[0]);
    expect(msg.type).toBe("addr");
    if (msg.type !== "addr") throw new Error("unreachable");
    expect(msg.payload.addrs.length).toBe(1);
    const e = msg.payload.addrs[0];
    expect(e.timestamp).toBe(Math.floor(now / 1000));
    expect(e.addr.services).toBe(REGTEST.services);
    expect(ipBytesToString(e.addr.ip)).toBe("1.2.3.4");
    expect(e.addr.port).toBe(LISTEN_PORT);
  });

  test("addrv2 when the peer sent sendaddrv2", () => {
    mgr = new PeerManager(makeConfig(dir, { discover: false }));
    mgr.addExternalIP("1.2.3.4");
    const p = fakePeer("8.8.8.8", 8333);
    p.wantsAddrV2 = true;
    register(mgr, p, "full_relay");
    const now = 1_790_000_000_000;
    expect(mgr.maybeSendLocalAddr(p as any, now)).toBe(true);
    const msg = roundTrip(p.sent[0]);
    expect(msg.type).toBe("addrv2");
    if (msg.type !== "addrv2") throw new Error("unreachable");
    expect(msg.payload.addrs.length).toBe(1);
    const e = msg.payload.addrs[0];
    expect(e.addr.networkId).toBe(1); // IPv4
    expect([...e.addr.addr]).toEqual([1, 2, 3, 4]);
    expect(e.addr.port).toBe(LISTEN_PORT);
    expect(e.addr.services).toBe(REGTEST.services);
    expect(e.timestamp).toBe(Math.floor(now / 1000));
  });

  test("IBD gate: nothing sent in IBD and the slot stays open for the first post-IBD tick", () => {
    let ibd = true;
    mgr = new PeerManager(makeConfig(dir, { discover: false, isIBD: () => ibd }));
    mgr.addExternalIP("1.2.3.4");
    const p = fakePeer("8.8.8.8", 8333);
    register(mgr, p, "full_relay");
    const t0 = 1_790_000_000_000;
    expect(mgr.maybeSendLocalAddr(p as any, t0)).toBe(false);
    expect(p.sent.length).toBe(0);
    expect(p.nextLocalAddrSend).toBe(0); // untouched
    ibd = false;
    expect(mgr.maybeSendLocalAddr(p as any, t0 + 60_000)).toBe(true);
    expect(p.sent.length).toBe(1);
  });

  test("setIBDProvider installs the gate after construction", () => {
    mgr = new PeerManager(makeConfig(dir, { discover: false }));
    mgr.addExternalIP("1.2.3.4");
    mgr.setIBDProvider(() => true);
    const p = fakePeer("8.8.8.8", 8333);
    register(mgr, p, "full_relay");
    expect(mgr.maybeSendLocalAddr(p as any, Date.now())).toBe(false);
  });

  test("never to block-relay-only or feeler; inbound OK", () => {
    mgr = new PeerManager(makeConfig(dir, { discover: false }));
    mgr.addExternalIP("1.2.3.4");
    const br = fakePeer("8.8.8.8", 8333);
    const fe = fakePeer("8.8.4.4", 8333);
    const ib = fakePeer("9.9.9.9", 50123);
    register(mgr, br, "block_relay");
    register(mgr, fe, "feeler");
    register(mgr, ib, "inbound");
    const now = Date.now();
    expect(mgr.maybeSendLocalAddr(br as any, now)).toBe(false);
    expect(mgr.maybeSendLocalAddr(fe as any, now)).toBe(false);
    expect(mgr.maybeSendLocalAddr(ib as any, now)).toBe(true);
    expect(br.sent.length + fe.sent.length).toBe(0);
  });

  test("Poisson re-send slot: not again until due", () => {
    mgr = new PeerManager(makeConfig(dir, { discover: false }));
    mgr.addExternalIP("1.2.3.4");
    const p = fakePeer("8.8.8.8", 8333);
    register(mgr, p, "full_relay");
    const now = 1_790_000_000_000;
    expect(mgr.maybeSendLocalAddr(p as any, now)).toBe(true);
    expect(p.nextLocalAddrSend).toBeGreaterThan(now);
    expect(mgr.maybeSendLocalAddr(p as any, now + 1)).toBe(false);
    expect(mgr.maybeSendLocalAddr(p as any, p.nextLocalAddrSend + 1)).toBe(true);
    expect(p.sent.length).toBe(2);
    // Exponential with a 24h mean.
    expect(nextLocalAddrDelayMs(() => 1 - Math.exp(-1))).toBeCloseTo(AVG_LOCAL_ADDRESS_BROADCAST_INTERVAL_MS, 0);
  });

  test("no usable address: nothing sent (discovered score 1, loopback peer view)", () => {
    mgr = new PeerManager(makeConfig(dir));
    mgr.noteVersionAddrRecv(fakePeer("8.8.8.8", 8333, { host: "5.6.7.8", port: 1 }) as any, false, Date.now());
    const p = fakePeer("127.0.0.1", 8333, { host: "127.0.0.1", port: 1 });
    register(mgr, p, "full_relay");
    expect(mgr.maybeSendLocalAddr(p as any, Date.now())).toBe(false);
  });

  test("GetLocalAddrForPeer: peer's view used when table empty (IP only outbound, IP+port inbound)", () => {
    mgr = new PeerManager(makeConfig(dir));
    const out = fakePeer("8.8.8.8", 8333, { host: "5.6.7.8", port: 50000 });
    const inb = fakePeer("9.9.9.9", 50123, { host: "5.6.7.8", port: 8331 });
    expect(mgr.getLocalAddrForPeer(out as any, false, Date.now())).toEqual({ host: "5.6.7.8", port: LISTEN_PORT });
    expect(mgr.getLocalAddrForPeer(inb as any, true, Date.now())).toEqual({ host: "5.6.7.8", port: 8331 });
    // With a manual entry the peer's view wins only at 1/2 odds.
    mgr.addExternalIP("1.2.3.4");
    expect(mgr.getLocalAddrForPeer(out as any, false, Date.now(), () => 0.9)).toEqual({ host: "1.2.3.4", port: LISTEN_PORT });
    expect(mgr.getLocalAddrForPeer(out as any, false, Date.now(), () => 0.1)).toEqual({ host: "5.6.7.8", port: LISTEN_PORT });
  });

  test("getpeerinfo addrlocal source: peer's addr_recv, null when unspecified", () => {
    mgr = new PeerManager(makeConfig(dir));
    expect(mgr.getPeerAddrLocal(fakePeer("8.8.8.8", 8333, { host: "5.6.7.8", port: 50000 }) as any)).toBe("5.6.7.8:50000");
    expect(mgr.getPeerAddrLocal(fakePeer("8.8.8.8", 8333) as any)).toBeNull();
    expect(mgr.getPeerAddrLocal(fakePeer("::1", 8333, { host: "2a01:4f8::1", port: 8331 }) as any)).toBe("[2a01:4f8::1]:8331");
    expect(peerAddrLocal({ versionPayload: null })).toBeNull();
  });
});
