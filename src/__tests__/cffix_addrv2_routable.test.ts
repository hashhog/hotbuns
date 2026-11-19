/**
 * cffix-hotbuns-addrv2-routable — a peer's addrv2 must not make us dial
 * loopback / LAN / link-local / ULA, or a well-known service port.
 *
 * Bug (fingerprint hotbuns-p2p-addrv2-store-skips-isroutable):
 * `handleAddrV2Message` only ran `isValidNetworkAddressV2`, which is true for
 * any 4-byte IPv4 / 16-byte IPv6. The legacy `addr` path rejects non-routable
 * addresses, the addrv2 path did not, so 127.0.0.1:8332, 10.0.0.1:22, fe80::1
 * and fc00::1 were stored in `knownAddresses`, mirrored into the bucketed
 * addrman, and handed to the outbound dialer. The dialer had no bad-port
 * check either.
 *
 * Core:
 *   addrman.cpp AddrManImpl::AddSingle: `if (!addr.IsRoutable()) return false;`
 *     (the one insertion point for addr AND addrv2).
 *   net.cpp ThreadOpenConnections: `if (nTries < 50 && (addr.IsIPv4() ||
 *     addr.IsIPv6()) && IsBadPort(addr.GetPort())) continue;`
 *   netbase.cpp IsBadPort.
 *
 * The tests drive the real addrv2 ingestion path (handleAddrV2Message), the
 * real candidate selection (getCandidateAddresses / selectFeelerTarget) and
 * the real AddrMan.add.
 */

import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import * as managerMod from "../p2p/manager.js";
import { PeerManager, ServiceFlags, type PeerManagerConfig } from "../p2p/manager.js";
import { BIP155Network } from "../p2p/messages.js";
import { AddrMan } from "../p2p/addrman.js";
import { REGTEST } from "../consensus/params.js";

let dir: string;

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "hotbuns-cffix-addrv2-routable-"));
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

const SERVICES = ServiceFlags.NODE_NETWORK | ServiceFlags.NODE_WITNESS;

function v4(ip: string, port: number): any {
  return {
    networkId: BIP155Network.IPV4,
    addr: Buffer.from(ip.split(".").map(Number)),
    port,
    services: SERVICES,
  };
}

function v6(hex: string, port: number): any {
  return { networkId: BIP155Network.IPV6, addr: Buffer.from(hex, "hex"), port, services: SERVICES };
}

/** Send one addrv2 message from a stub peer, with a full token bucket. */
function feedAddrV2(pm: any, addrs: any[]): void {
  const peer = { host: "93.184.216.34", port: 8333, state: "connected", wantsAddrV2: true, send: () => true };
  pm.addrTokenBucket.set(`${peer.host}:${peer.port}`, { tokens: 1e6, ts: Date.now() });
  const now = Math.floor(Date.now() / 1000);
  pm.handleAddrV2Message(peer, { addrs: addrs.map((addr) => ({ timestamp: now - 60, addr })) });
}

function addrManHosts(pm: any): string[] {
  return [...pm.addrMan.getEntries(false), ...pm.addrMan.getEntries(true)].map(
    (e: any) => `${e.host}:${e.port}`,
  );
}

describe("cffix: addrv2 stores only routable addresses (Core AddSingle IsRoutable)", () => {
  test("IPv4: 127.0.0.1:8332 and 10.0.0.1:22 are dropped, the routable one is kept", () => {
    const pm = makeManager();
    feedAddrV2(pm, [v4("127.0.0.1", 8332), v4("10.0.0.1", 22), v4("8.8.8.8", 8333)]);
    expect([...pm.knownAddresses.keys()]).toEqual(["8.8.8.8:8333"]);
    expect(pm.getCandidateAddresses(10).map((c: any) => `${c.host}:${c.port}`)).toEqual([
      "8.8.8.8:8333",
    ]);
    expect(addrManHosts(pm)).toEqual(["8.8.8.8:8333"]);
  });

  test("IPv4: every non-routable class Core rejects is dropped", () => {
    const pm = makeManager();
    const bad = [
      "0.1.2.3", "127.0.0.1", "10.1.2.3", "172.16.0.1", "172.31.255.255", "192.168.1.1",
      "198.18.0.1", "198.19.0.1", "169.254.1.1", "100.64.0.1", "100.127.0.1",
      "192.0.2.1", "198.51.100.1", "203.0.113.1", "255.255.255.255", "0.0.0.0",
    ];
    feedAddrV2(pm, bad.map((ip) => v4(ip, 8333)));
    expect([...pm.knownAddresses.keys()]).toEqual([]);
    expect(pm.getCandidateAddresses(100)).toEqual([]);
  });

  test("IPv6: loopback, link-local, ULA, documentation, ORCHID are dropped; global is kept", () => {
    const pm = makeManager();
    const routable = "26064700000000000000000000001111"; // 2606:4700::1111
    feedAddrV2(pm, [
      v6("00000000000000000000000000000001", 8333), // ::1
      v6("00000000000000000000000000000000", 8333), // ::
      v6("fe800000000000000000000000000001", 8333), // fe80::1
      v6("fc000000000000000000000000000001", 8333), // fc00::1 (ULA)
      v6("fd123456789a00000000000000000001", 8333), // fd12:: (ULA)
      v6("20010db8000000000000000000000001", 8333), // 2001:db8::1 (RFC3849)
      v6("20010010000000000000000000000001", 8333), // 2001:10::1 (RFC4843)
      v6("20010020000000000000000000000001", 8333), // 2001:20::1 (RFC7343)
      v6("00000000000000000000ffff7f000001", 8333), // ::ffff:127.0.0.1
      v6(routable, 8333),
    ]);
    expect([...pm.knownAddresses.keys()]).toEqual([`[${routable}]:8333`]);
  });

  test("Tor v3 (no IP) is still stored: Core treats valid onion addresses as routable", () => {
    const pm = makeManager();
    feedAddrV2(pm, [{ networkId: BIP155Network.TORV3, addr: Buffer.alloc(32, 7), port: 8333, services: SERVICES }]);
    expect(pm.knownAddresses.size).toBe(1);
  });

  test("the legacy addr path still stores routable and drops non-routable (no regression)", () => {
    const pm = makeManager();
    const peer = { host: "93.184.216.34", port: 8333, state: "connected", wantsAddrV2: false, send: () => true };
    pm.addrTokenBucket.set(`${peer.host}:${peer.port}`, { tokens: 1e6, ts: Date.now() });
    const mapped = (ip: string) => {
      const b = Buffer.alloc(16);
      b[10] = 0xff;
      b[11] = 0xff;
      ip.split(".").forEach((o, i) => (b[12 + i] = Number(o)));
      return b;
    };
    const now = Math.floor(Date.now() / 1000);
    pm.handleAddrMessage(peer, {
      addrs: ["127.0.0.1", "8.8.4.4"].map((ip) => ({
        timestamp: now - 60,
        addr: { services: SERVICES, ip: mapped(ip), port: 8333 },
      })),
    });
    expect([...pm.knownAddresses.keys()]).toEqual(["8.8.4.4:8333"]);
  });
});

describe("cffix: the shared insertion points refuse non-routable addresses", () => {
  test("addKnownAddress drops a non-routable PeerInfo whatever the caller", () => {
    const pm = makeManager();
    const info = (host: string) => ({
      host, port: 8333, services: SERVICES, lastSeen: Date.now(), banScore: 0, lastConnected: 0,
    });
    pm.addKnownAddress("127.0.0.1:8333", info("127.0.0.1"));
    pm.addKnownAddress("192.168.0.5:8333", info("192.168.0.5"));
    pm.addKnownAddress("1.1.1.1:8333", info("1.1.1.1"));
    expect([...pm.knownAddresses.keys()]).toEqual(["1.1.1.1:8333"]);
  });

  test("AddrMan.add returns false for non-routable IPv4/IPv6 and stores nothing", () => {
    const am = new AddrMan();
    for (const host of ["127.0.0.1", "10.0.0.1", "169.254.3.3", "::1", "fe80::1", "fc00::1"]) {
      expect(am.add(host, 8333, "8.8.8.8", SERVICES, 1_700_000_000, 1_700_000_000)).toBe(false);
    }
    expect(am.size()).toBe(0);
    expect(am.add("8.8.8.8", 8333, "1.1.1.1", SERVICES, 1_700_000_000, 1_700_000_000)).toBe(true);
    expect(am.size()).toBe(1);
  });
});

describe("cffix: the dialer skips Core's bad ports (net.cpp IsBadPort)", () => {
  test("isBadPort is exported and matches Core's netbase.cpp list", () => {
    const isBadPort = (managerMod as any).isBadPort as ((p: number) => boolean) | undefined;
    expect(typeof isBadPort).toBe("function");
    if (!isBadPort) return;
    for (const p of [1, 22, 23, 25, 53, 110, 143, 465, 3306, 3389, 5432, 5900, 6667, 10080, 27017]) {
      expect(isBadPort(p)).toBe(true);
    }
    for (const p of [0, 80, 443, 8080, 8332, 8333, 18333, 18444, 48333, 65535]) {
      expect(isBadPort(p)).toBe(false);
    }
  });

  test("a routable address on a bad port is stored (Core stores it) but never a dial candidate", () => {
    const pm = makeManager();
    feedAddrV2(pm, [v4("8.8.4.4", 22), v4("8.8.8.8", 8333), v4("1.1.1.1", 25)]);
    // Core's addrman has no port filter: all three are kept.
    expect(pm.knownAddresses.size).toBe(3);
    expect(pm.getCandidateAddresses(10).map((c: any) => `${c.host}:${c.port}`)).toEqual([
      "8.8.8.8:8333",
    ]);
  });

  test("the feeler pick skips a bad-port NEW entry", () => {
    const pm = makeManager();
    feedAddrV2(pm, [v4("8.8.4.4", 22)]);
    expect(addrManHosts(pm)).toEqual(["8.8.4.4:22"]);
    expect(pm.selectFeelerTarget()).toBeNull();
  });
});
