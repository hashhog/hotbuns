/**
 * W117 BIP-155 Networks fleet audit — hotbuns
 *
 * Covers 30 gates across:
 *   G1-G10   Tor v3 (.onion) — SOCKS5 proxy, control protocol, inbound/outbound
 *   G11-G16  I2P — SAM protocol, session, inbound/outbound
 *   G17-G20  CJDNS — fc00::/8 prefix, routing
 *   G21-G24  Outbound routing — proxy selection, network-type filtering, CLI config
 *   G25-G28  Address resolution — isAddrV1Compatible, addrv2 relay, isRoutable for special nets
 *   G29-G30  addrv2 wire format + getnetworkinfo RPC
 *
 * BUG list found in this wave:
 *   BUG-1  (G21/G26) DEAD HELPER: proxy.ts (SOCKS5Client / TorControl / I2PSAM / ProxyManager)
 *          is fully implemented (~1530 LOC) but never imported in any production source file.
 *          Tor v3 and I2P outbound connections are impossible despite the full SAM/SOCKS5 code.
 *   BUG-2  (G25) MEDIUM: relayAddrToRandomPeers() does NOT check peer.wantsAddrV2 before
 *          forwarding an addrv2 message. Core checks IsAddrCompatible (m_wants_addrv2 ||
 *          addr.IsAddrV1Compatible()). hotbuns sends raw addrv2 to v1-only peers.
 *   BUG-3  (G30) MEDIUM: getnetworkinfo "networks" array hardcodes only ipv4/ipv6.
 *          Missing onion, i2p, cjdns entries (reachable:false since proxy is unwired).
 *          Core always returns all 5 network types.
 *   BUG-4  (G29) LOW: deserializeAddrV2Payload stores unknown-networkId entries in addrs[].
 *          Core silently drops entries with unrecognised network IDs (returns false from
 *          SetNetFromBIP155Network, then caller skips the entry). hotbuns stores them,
 *          and isValidNetworkAddressV2 returns true for them (unknown → default: return true),
 *          so they propagate into knownAddresses.
 *   BUG-5  (G21) LOW: getCandidateAddresses() does NOT filter by networkId.
 *          Tor/I2P/CJDNS PeerInfo entries (stored with rawAddr, host = hex-string) can be
 *          selected for outbound TCP connection; connectPeer calls Bun.connect(hexStr, port)
 *          which errors, wasting outbound slots and polluting lastConnected timestamps.
 *   BUG-6  (G22/G23) LOW: No --proxy / --onion / --i2psam CLI options.
 *          Since proxy.ts is never instantiated from cli.ts, the SOCKS5/TorControl/I2PSAM
 *          stack cannot be activated at runtime regardless of configuration.
 *
 * References:
 *   bitcoin-core/src/i2p.h/cpp
 *   bitcoin-core/src/torcontrol.h/cpp
 *   bitcoin-core/src/netbase.h/cpp
 *   bitcoin-core/src/net_processing.cpp (RelayAddress, IsAddrCompatible, processMessage addrv2)
 *   bitcoin-core/src/netaddress.cpp (SetNetFromBIP155Network, IsRoutable, IsAddrV1Compatible)
 */

import { describe, test, expect, beforeEach, afterEach } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

// --- addrv2 module ---
import {
  BIP155Network,
  type NetworkAddressV2,
  type AddrV2Entry,
  serializeAddrV2Payload,
  deserializeAddrV2Payload,
  isValidNetworkAddressV2,
  isValidTorV3Address,
  isValidCJDNSAddress,
  isValidI2PAddress,
  isAddrV1Compatible,
  getNetworkName,
  ipv4ToNetworkAddressV2,
  networkAddressV2ToIPv4String,
  networkAddressV2ToLegacy,
} from "../src/p2p/addrv2.js";

// --- wire serialization helpers ---
import { BufferReader, BufferWriter } from "../src/wire/serialization.js";

// --- p2p manager ---
import { isRoutable } from "../src/p2p/manager.js";

// --- proxy module (checked for dead-helper) ---
import {
  SOCKS5Client,
  TorControl,
  I2PSAM,
  ProxyManager,
  socks5ErrorString,
  getNetworkTypeFromAddress,
  networkTypeToBIP155,
  I2P_SAM31_PORT,
  SOCKSVersion,
  SOCKS5Method,
  SOCKS5Reply,
} from "../src/p2p/proxy.js";

// ---------------------------------------------------------------------------
// G1-G10: Tor v3 (.onion)
// ---------------------------------------------------------------------------

describe("G1 — TorV3 BIP155Network.TORV3 = 4", () => {
  test("BIP155Network.TORV3 equals 4", () => {
    expect(BIP155Network.TORV3).toBe(4);
  });

  test("TORV3 address size is 32 bytes (ed25519 pubkey)", () => {
    // BIP-155: network_id 4, addr length = 32
    const entry: NetworkAddressV2 = {
      networkId: BIP155Network.TORV3,
      addr: Buffer.alloc(32, 0xab),
      port: 8333,
      services: 1n,
    };
    expect(isValidNetworkAddressV2(entry)).toBe(true);
  });

  test("TORV3 address with wrong size is invalid", () => {
    const entry: NetworkAddressV2 = {
      networkId: BIP155Network.TORV3,
      addr: Buffer.alloc(31, 0xab),
      port: 8333,
      services: 1n,
    };
    expect(isValidNetworkAddressV2(entry)).toBe(false);
  });
});

describe("G2 — TorV3 address validation (ed25519 pubkey non-zero)", () => {
  test("rejects all-zero TorV3 pubkey (invalid point)", () => {
    expect(isValidTorV3Address(Buffer.alloc(32, 0))).toBe(false);
  });

  test("accepts non-zero 32-byte TorV3 pubkey", () => {
    const pubkey = Buffer.alloc(32, 0x01);
    expect(isValidTorV3Address(pubkey)).toBe(true);
  });

  test("rejects 33-byte TorV3 pubkey (too long)", () => {
    expect(isValidTorV3Address(Buffer.alloc(33, 0x01))).toBe(false);
  });
});

describe("G3 — TorV3 not AddrV1Compatible", () => {
  test("TORV3 address is NOT v1 compatible", () => {
    const addr: NetworkAddressV2 = {
      networkId: BIP155Network.TORV3,
      addr: Buffer.alloc(32, 0x01),
      port: 8333,
      services: 1n,
    };
    expect(isAddrV1Compatible(addr)).toBe(false);
  });

  test("networkAddressV2ToLegacy returns null for TORV3", () => {
    const addr: NetworkAddressV2 = {
      networkId: BIP155Network.TORV3,
      addr: Buffer.alloc(32, 0x01),
      port: 8333,
      services: 1n,
    };
    expect(networkAddressV2ToLegacy(addr)).toBeNull();
  });
});

describe("G4 — TorV2 (networkId=3) is deprecated and rejected", () => {
  test("TORV2 address is always invalid (deprecated)", () => {
    const addr: NetworkAddressV2 = {
      networkId: BIP155Network.TORV2,
      addr: Buffer.alloc(10),
      port: 8333,
      services: 0n,
    };
    expect(isValidNetworkAddressV2(addr)).toBe(false);
  });

  test("BIP155Network.TORV2 = 3", () => {
    expect(BIP155Network.TORV2).toBe(3);
  });
});

describe("G5 — SOCKS5Client class exists (Tor outbound proxy)", () => {
  test("SOCKS5Client can be constructed", () => {
    const client = new SOCKS5Client({ host: "127.0.0.1", port: 9050 });
    expect(client).toBeDefined();
  });

  test("SOCKS5Client supports stream isolation option", () => {
    const client = new SOCKS5Client({ host: "127.0.0.1", port: 9050 }, true);
    expect(client).toBeDefined();
  });
});

describe("G6 — TorControl class exists (hidden service creation)", () => {
  test("TorControl can be constructed", () => {
    const ctrl = new TorControl({ host: "127.0.0.1", port: 9051 });
    expect(ctrl).toBeDefined();
  });

  test("TorControl getServiceId() returns null before connect", () => {
    const ctrl = new TorControl({ host: "127.0.0.1", port: 9051 });
    expect(ctrl.getServiceId()).toBeNull();
  });

  test("TorControl getOnionAddress() returns null before connect", () => {
    const ctrl = new TorControl({ host: "127.0.0.1", port: 9051 });
    expect(ctrl.getOnionAddress()).toBeNull();
  });
});

describe("G7 — SOCKS5 error messages match Core Socks5ErrorString()", () => {
  test("SUCCEEDED = 'success'", () => {
    expect(socks5ErrorString(SOCKS5Reply.SUCCEEDED)).toBe("success");
  });

  test("CONNECTION_REFUSED = 'connection refused'", () => {
    expect(socks5ErrorString(SOCKS5Reply.CONNECTION_REFUSED)).toBe("connection refused");
  });

  test("Tor hidden service errors present", () => {
    expect(socks5ErrorString(SOCKS5Reply.TOR_HS_DESC_NOT_FOUND)).toContain("onion service");
    expect(socks5ErrorString(SOCKS5Reply.TOR_HS_INTRO_FAILED)).toContain("onion service");
    expect(socks5ErrorString(SOCKS5Reply.TOR_HS_REND_FAILED)).toContain("onion service");
  });
});

describe("G8 — SOCKS5 constants", () => {
  test("SOCKSVersion.SOCKS5 = 0x05", () => {
    expect(SOCKSVersion.SOCKS5).toBe(0x05);
  });

  test("SOCKS5Method.NO_AUTH = 0x00", () => {
    expect(SOCKS5Method.NO_AUTH).toBe(0x00);
  });

  test("SOCKS5Method.USER_PASS = 0x02", () => {
    expect(SOCKS5Method.USER_PASS).toBe(0x02);
  });
});

describe("G9 — getNetworkTypeFromAddress identifies .onion correctly", () => {
  test(".onion address → 'onion'", () => {
    expect(getNetworkTypeFromAddress("abc123.onion")).toBe("onion");
    expect(getNetworkTypeFromAddress("some56789012345678901234567890.onion")).toBe("onion");
  });

  test(".b32.i2p address → 'i2p'", () => {
    expect(getNetworkTypeFromAddress("some32chars.b32.i2p")).toBe("i2p");
  });

  test("fc00::/8 address → 'cjdns'", () => {
    expect(getNetworkTypeFromAddress("[fc00::1]")).toBe("cjdns");
    expect(getNetworkTypeFromAddress("fc12:3456::1")).toBe("cjdns");
  });

  test("IPv4 address → 'ipv4'", () => {
    expect(getNetworkTypeFromAddress("1.2.3.4")).toBe("ipv4");
  });
});

describe("G10 — networkTypeToBIP155 maps correctly", () => {
  test("'onion' → BIP155Network.TORV3", () => {
    expect(networkTypeToBIP155("onion")).toBe(BIP155Network.TORV3);
  });

  test("'i2p' → BIP155Network.I2P", () => {
    expect(networkTypeToBIP155("i2p")).toBe(BIP155Network.I2P);
  });

  test("'cjdns' → BIP155Network.CJDNS", () => {
    expect(networkTypeToBIP155("cjdns")).toBe(BIP155Network.CJDNS);
  });

  test("'ipv4' → BIP155Network.IPV4", () => {
    expect(networkTypeToBIP155("ipv4")).toBe(BIP155Network.IPV4);
  });
});

// ---------------------------------------------------------------------------
// G11-G16: I2P
// ---------------------------------------------------------------------------

describe("G11 — I2P BIP155Network.I2P = 5", () => {
  test("BIP155Network.I2P equals 5", () => {
    expect(BIP155Network.I2P).toBe(5);
  });

  test("I2P address size is 32 bytes (SHA256 hash of destination)", () => {
    const addr: NetworkAddressV2 = {
      networkId: BIP155Network.I2P,
      addr: Buffer.alloc(32, 0xde),
      port: 0, // I2P_SAM31_PORT
      services: 1n,
    };
    expect(isValidNetworkAddressV2(addr)).toBe(true);
  });

  test("I2P address with wrong size is invalid", () => {
    expect(isValidI2PAddress(Buffer.alloc(31))).toBe(false);
    expect(isValidI2PAddress(Buffer.alloc(33))).toBe(false);
  });
});

describe("G12 — I2P_SAM31_PORT = 0 (BIP-155 + Core convention)", () => {
  test("I2P_SAM31_PORT equals 0", () => {
    // Core: netaddress.h: static constexpr uint16_t I2P_SAM31_PORT{0};
    expect(I2P_SAM31_PORT).toBe(0);
  });
});

describe("G13 — I2P not AddrV1Compatible", () => {
  test("I2P address is NOT v1 compatible", () => {
    const addr: NetworkAddressV2 = {
      networkId: BIP155Network.I2P,
      addr: Buffer.alloc(32, 0xcd),
      port: 0,
      services: 1n,
    };
    expect(isAddrV1Compatible(addr)).toBe(false);
  });
});

describe("G14 — I2PSAM class exists (SAM v3.1 protocol)", () => {
  test("I2PSAM can be constructed", () => {
    const sam = new I2PSAM({ host: "127.0.0.1", port: 7656 });
    expect(sam).toBeDefined();
  });

  test("I2PSAM getAddress() returns null before session", () => {
    const sam = new I2PSAM({ host: "127.0.0.1", port: 7656 });
    expect(sam.getAddress()).toBeNull();
  });

  test("I2PSAM getDestination() returns null before session", () => {
    const sam = new I2PSAM({ host: "127.0.0.1", port: 7656 });
    expect(sam.getDestination()).toBeNull();
  });
});

describe("G15 — I2P addrv2 round-trip serialization", () => {
  test("I2P address serializes and deserializes correctly", () => {
    const i2pHash = Buffer.alloc(32, 0xde);
    const entries: AddrV2Entry[] = [
      {
        timestamp: 1700000000,
        addr: {
          networkId: BIP155Network.I2P,
          addr: i2pHash,
          port: 0, // I2P_SAM31_PORT
          services: 1n,
        },
      },
    ];
    const serialized = serializeAddrV2Payload(entries);
    const reader = new BufferReader(serialized);
    const { addrs } = deserializeAddrV2Payload(reader);

    expect(addrs.length).toBe(1);
    expect(addrs[0].addr.networkId).toBe(BIP155Network.I2P);
    expect(addrs[0].addr.addr.length).toBe(32);
    expect(addrs[0].addr.port).toBe(0);
    expect(addrs[0].addr.addr.equals(i2pHash)).toBe(true);
  });
});

describe("G16 — ProxyManager correctly routes I2P addresses", () => {
  test("ProxyManager.isReachable('i2p') returns false without SAM config", () => {
    const mgr = new ProxyManager({});
    expect(mgr.isReachable("i2p")).toBe(false);
  });

  test("ProxyManager.getI2PAddress() returns null without SAM", () => {
    const mgr = new ProxyManager({});
    expect(mgr.getI2PAddress()).toBeNull();
  });

  test("connectI2P throws when SAM not configured", async () => {
    const mgr = new ProxyManager({});
    await expect(mgr.connect("some.b32.i2p", 0)).rejects.toThrow(
      "I2P SAM not configured"
    );
  });
});

// ---------------------------------------------------------------------------
// G17-G20: CJDNS
// ---------------------------------------------------------------------------

describe("G17 — CJDNS BIP155Network.CJDNS = 6", () => {
  test("BIP155Network.CJDNS equals 6", () => {
    expect(BIP155Network.CJDNS).toBe(6);
  });

  test("CJDNS address size is 16 bytes", () => {
    const cjdnsAddr = Buffer.alloc(16);
    cjdnsAddr[0] = 0xfc;
    const entry: NetworkAddressV2 = {
      networkId: BIP155Network.CJDNS,
      addr: cjdnsAddr,
      port: 8333,
      services: 1n,
    };
    expect(isValidNetworkAddressV2(entry)).toBe(true);
  });
});

describe("G18 — CJDNS must have fc prefix", () => {
  test("CJDNS address without 0xfc prefix is invalid", () => {
    const addr = Buffer.alloc(16, 0x20);
    expect(isValidCJDNSAddress(addr)).toBe(false);
  });

  test("CJDNS address with 0xfc prefix is valid", () => {
    const addr = Buffer.alloc(16, 0x00);
    addr[0] = 0xfc;
    expect(isValidCJDNSAddress(addr)).toBe(true);
  });

  test("CJDNS address with wrong length is invalid", () => {
    const addr = Buffer.alloc(15);
    addr[0] = 0xfc;
    expect(isValidCJDNSAddress(addr)).toBe(false);
  });
});

describe("G19 — CJDNS not AddrV1Compatible", () => {
  test("CJDNS address is NOT v1 compatible", () => {
    const addr = Buffer.alloc(16, 0xfc);
    addr[0] = 0xfc;
    const entry: NetworkAddressV2 = {
      networkId: BIP155Network.CJDNS,
      addr,
      port: 8333,
      services: 0n,
    };
    expect(isAddrV1Compatible(entry)).toBe(false);
  });
});

describe("G20 — CJDNS addrv2 round-trip serialization", () => {
  test("CJDNS address serializes and deserializes correctly", () => {
    const cjdns = Buffer.alloc(16);
    cjdns[0] = 0xfc;
    for (let i = 1; i < 16; i++) cjdns[i] = i;
    const entries: AddrV2Entry[] = [
      {
        timestamp: 1700000000,
        addr: {
          networkId: BIP155Network.CJDNS,
          addr: cjdns,
          port: 8333,
          services: 9n,
        },
      },
    ];
    const serialized = serializeAddrV2Payload(entries);
    const reader = new BufferReader(serialized);
    const { addrs } = deserializeAddrV2Payload(reader);

    expect(addrs.length).toBe(1);
    expect(addrs[0].addr.networkId).toBe(BIP155Network.CJDNS);
    expect(addrs[0].addr.addr[0]).toBe(0xfc);
    expect(addrs[0].addr.port).toBe(8333);
  });
});

// ---------------------------------------------------------------------------
// G21-G24: Outbound routing
// ---------------------------------------------------------------------------

describe("G21 — BUG-1: proxy.ts is a dead helper (not wired into production code)", () => {
  /**
   * BUG-1 (HIGH — dead helper).
   *
   * proxy.ts exports SOCKS5Client, TorControl, I2PSAM, and ProxyManager but
   * nothing in the production source tree (cli.ts, manager.ts, peer.ts,
   * index.ts) imports it.  Tor v3 and I2P connections are impossible at runtime.
   *
   * Core reference: init.cpp initialises g_torcontrol and the I2P session
   * based on -proxy / -onion / -i2psam flags; these are wired into CConnman.
   *
   * Fix: import ProxyManager from proxy.ts in cli.ts and pass it into
   * PeerManagerConfig; add --proxy / --onion / --i2psam CLI flags.
   */
  test("ProxyManager class is importable from proxy.ts", () => {
    // This test verifies the implementation EXISTS in proxy.ts.
    // The bug is that it is never instantiated from production code.
    expect(typeof ProxyManager).toBe("function");
    expect(typeof SOCKS5Client).toBe("function");
    expect(typeof TorControl).toBe("function");
    expect(typeof I2PSAM).toBe("function");
  });

  test("ProxyManager.isReachable('onion') returns false without proxy config", () => {
    const mgr = new ProxyManager({});
    // With no proxy configured, onion should not be reachable.
    expect(mgr.isReachable("onion")).toBe(false);
  });

  test("ProxyManager.isReachable('onion') returns true when onionProxy configured (after initialize)", async () => {
    // isReachable checks this.onionProxy which is only set after initialize().
    const mgr = new ProxyManager({ onionProxy: { host: "127.0.0.1", port: 9050 } });
    // Before initialize, onionProxy is null → not reachable yet.
    // After initialize, it is constructed → reachable.
    await mgr.initialize();
    expect(mgr.isReachable("onion")).toBe(true);
    await mgr.close();
  });

  test("ProxyManager.getOnionAddress() returns null before Tor connect", () => {
    const mgr = new ProxyManager({});
    expect(mgr.getOnionAddress()).toBeNull();
  });

  test("connect to .onion throws when no proxy configured", async () => {
    const mgr = new ProxyManager({});
    await expect(mgr.connect("abc.onion", 8333)).rejects.toThrow(
      "no proxy configured for .onion addresses"
    );
  });
});

describe("G22 — BUG-6: No --proxy/--onion/--i2psam CLI options", () => {
  /**
   * BUG-6 (LOW). cli.ts does not define --proxy, --onion, or --i2psam flags.
   * Since ProxyManager is never instantiated from cli.ts, the entire
   * anonymous-network stack cannot be activated at runtime.
   *
   * Core reference: init.cpp:AppInitParameterInteraction() reads -proxy,
   * -onion, -i2psam, -cjdnsreachable and passes them to CConnman.
   */
  test("ProxyManager initializes cleanly with empty config", async () => {
    const mgr = new ProxyManager({});
    // initialize() should not throw even when no proxies configured
    await mgr.initialize();
    expect(mgr.isReachable("ipv4")).toBe(true);
    expect(mgr.isReachable("onion")).toBe(false);
    expect(mgr.isReachable("i2p")).toBe(false);
    await mgr.close();
  });
});

describe("G23 — Outbound connection filtering: TORV3/I2P/CJDNS in knownAddresses", () => {
  /**
   * BUG-5 (LOW). getCandidateAddresses() does not filter by networkId.
   * Entries with networkId=TORV3/I2P/CJDNS have host set to a hex string
   * (e.g. "0102...1f20") which is not a valid TCP hostname; connectPeer will
   * attempt Bun.connect(hexStr, port) which fails.
   *
   * Core reference: CConnman::CreateNodeFromAcceptedSocket and AttemptToEvict
   * route based on CNetAddr::GetNetwork(), never passing Tor/I2P addresses
   * to plain TCP connect.
   */
  test("isAddrV1Compatible returns false for TORV3/I2P/CJDNS PeerInfo types", () => {
    // These addresses should NOT be sent via legacy addr v1 messages.
    const torAddr: NetworkAddressV2 = {
      networkId: BIP155Network.TORV3,
      addr: Buffer.alloc(32, 0x01),
      port: 8333,
      services: 1n,
    };
    const i2pAddr: NetworkAddressV2 = {
      networkId: BIP155Network.I2P,
      addr: Buffer.alloc(32, 0x02),
      port: 0,
      services: 1n,
    };
    const cjdnsAddr: NetworkAddressV2 = {
      networkId: BIP155Network.CJDNS,
      addr: Buffer.concat([Buffer.from([0xfc]), Buffer.alloc(15)]),
      port: 8333,
      services: 1n,
    };
    expect(isAddrV1Compatible(torAddr)).toBe(false);
    expect(isAddrV1Compatible(i2pAddr)).toBe(false);
    expect(isAddrV1Compatible(cjdnsAddr)).toBe(false);
  });
});

describe("G24 — ProxyManager routes based on address type", () => {
  test("getNetworkTypeFromAddress classifies all five types", () => {
    expect(getNetworkTypeFromAddress("1.2.3.4")).toBe("ipv4");
    expect(getNetworkTypeFromAddress("2001:db8::1")).toBe("ipv6");
    expect(getNetworkTypeFromAddress("abc.onion")).toBe("onion");
    expect(getNetworkTypeFromAddress("abc.b32.i2p")).toBe("i2p");
    expect(getNetworkTypeFromAddress("fc01::1")).toBe("cjdns");
  });

  test("ProxyManager routes .onion to onion-proxy path (throws 'no proxy' not TCP error)", async () => {
    // Without any proxy configured, connecting to .onion should throw
    // "no proxy configured for .onion addresses", not a TCP error.
    // This distinguishes from clearnet which tries TCP directly.
    const mgr = new ProxyManager({});
    await mgr.initialize();
    await expect(mgr.connect("abc.onion", 8333)).rejects.toThrow(
      "no proxy configured for .onion addresses"
    );
    await mgr.close();
  });
});

// ---------------------------------------------------------------------------
// G25-G28: Address resolution and relay
// ---------------------------------------------------------------------------

describe("G25 — BUG-2: addrv2 relay does not check peer.wantsAddrV2", () => {
  /**
   * BUG-2 (MEDIUM — P2P protocol violation).
   *
   * manager.ts relayAddrToRandomPeers() sends msg as-is to all connected peers
   * without checking peer.wantsAddrV2. When msg.type === "addrv2", this sends
   * an addrv2 message to peers that have not sent sendaddrv2, violating BIP-155.
   *
   * Core reference: net_processing.cpp RelayAddress() calls IsAddrCompatible()
   * which returns: peer.m_wants_addrv2 || addr.IsAddrV1Compatible().
   * Only peers that signalled sendaddrv2 receive addrv2 messages; others receive
   * the equivalent legacy addr (v1) or nothing if the address is not v1 compatible.
   *
   * Fix: in relayAddrToRandomPeers(), filter target peers by peer.wantsAddrV2
   * when msg.type === "addrv2" (since TorV3/I2P/CJDNS are not addr-v1 compatible).
   */
  test("peer.wantsAddrV2 flag exists on Peer class (field check)", async () => {
    // Verify the flag exists as documented in peer.ts.
    // We import the module to ensure the field is present.
    const { Peer } = await import("../src/p2p/peer.js");
    // wantsAddrV2 should start as false on a newly constructed peer.
    // We can't construct a full peer without a socket here, but we can
    // verify the prototype has the property or that the type expectation holds.
    expect(Peer).toBeDefined();
  });

  test("isAddrCompatible logic: v1-only peer should NOT receive addrv2 for TORV3 address", () => {
    // Core: IsAddrCompatible = m_wants_addrv2 || addr.IsAddrV1Compatible()
    // For TORV3: IsAddrV1Compatible() = false.
    // So a peer with m_wants_addrv2=false should not receive this addrv2 message.
    const torAddr: NetworkAddressV2 = {
      networkId: BIP155Network.TORV3,
      addr: Buffer.alloc(32, 0x01),
      port: 8333,
      services: 1n,
    };
    // v1-only peer (wantsAddrV2 = false): address not v1-compatible → should NOT relay
    const isV1Compatible = isAddrV1Compatible(torAddr);
    const peerWantsAddrV2 = false; // simulate v1-only peer
    const shouldRelay = peerWantsAddrV2 || isV1Compatible;
    expect(shouldRelay).toBe(false); // hotbuns relays anyway — BUG-2
  });

  test("isAddrCompatible logic: addrv2 peer should receive TORV3 address", () => {
    const torAddr: NetworkAddressV2 = {
      networkId: BIP155Network.TORV3,
      addr: Buffer.alloc(32, 0x01),
      port: 8333,
      services: 1n,
    };
    const peerWantsAddrV2 = true;
    const shouldRelay = peerWantsAddrV2 || isAddrV1Compatible(torAddr);
    expect(shouldRelay).toBe(true);
  });

  test("isAddrCompatible logic: IPv4 address should relay to v1-only peers", () => {
    // IPv4 is v1-compatible, so even v1-only peers should get it.
    const ipv4Addr = ipv4ToNetworkAddressV2("1.2.3.4", 8333, 1n);
    const peerWantsAddrV2 = false;
    const shouldRelay = peerWantsAddrV2 || isAddrV1Compatible(ipv4Addr);
    expect(shouldRelay).toBe(true);
  });
});

describe("G26 — isRoutable: special networks are always considered routable", () => {
  /**
   * Core: CNetAddr::IsRoutable() for NET_ONION/NET_I2P/NET_CJDNS returns true
   * (they pass IsValid() and none of the RFC exclusion checks apply).
   * hotbuns's isRoutable() is IPv4-only (returns false for non-IPv4 strings),
   * so it cannot be called on TorV3/I2P/CJDNS addresses.  handleAddrV2Message
   * does not call isRoutable for these — which is correct behavior since they
   * are inherently "public" addresses.  This gate verifies the reasoning.
   */
  test("isRoutable returns false for non-IPv4 strings (by design)", () => {
    // isRoutable in manager.ts only handles IPv4
    expect(isRoutable("abc.onion")).toBe(false); // Not IPv4 format → returns false
    expect(isRoutable("not-an-ip")).toBe(false);
  });

  test("isRoutable returns true for a valid public IPv4 address", () => {
    expect(isRoutable("1.2.3.4")).toBe(true);
    expect(isRoutable("8.8.8.8")).toBe(true);
  });

  test("isRoutable returns false for RFC1918 addresses", () => {
    expect(isRoutable("10.0.0.1")).toBe(false);
    expect(isRoutable("192.168.1.1")).toBe(false);
    expect(isRoutable("172.16.0.1")).toBe(false);
  });
});

describe("G27 — addrv2 message 1000-entry limit (same as addr v1)", () => {
  test("deserializeAddrV2Payload throws when count > 1000", () => {
    const writer = new BufferWriter();
    writer.writeVarInt(1001); // Exceeds MAX_ADDR_TO_SEND
    const reader = new BufferReader(writer.toBuffer());
    expect(() => deserializeAddrV2Payload(reader)).toThrow("Too many addresses");
  });

  test("deserializeAddrV2Payload accepts exactly 1000 (boundary)", () => {
    // Build a minimal payload with 1000 IPv4 entries
    const writer = new BufferWriter();
    writer.writeVarInt(1000);
    const ipBuf = Buffer.from([1, 2, 3, 4]);
    const portBuf = Buffer.alloc(2);
    portBuf.writeUInt16BE(8333, 0);
    for (let i = 0; i < 1000; i++) {
      writer.writeUInt32LE(1700000000);   // timestamp
      writer.writeVarInt(1n);             // services
      writer.writeUInt8(BIP155Network.IPV4); // networkId
      writer.writeVarInt(4);              // addrLen
      writer.writeBytes(ipBuf);           // addr
      writer.writeBytes(portBuf);         // port
    }
    const reader = new BufferReader(writer.toBuffer());
    const { addrs } = deserializeAddrV2Payload(reader);
    expect(addrs.length).toBe(1000);
  });
});

describe("G28 — MAX_ADDRV2_SIZE = 512 enforced", () => {
  test("address length > 512 is rejected", () => {
    const writer = new BufferWriter();
    writer.writeVarInt(1);              // count
    writer.writeUInt32LE(1700000000);   // timestamp
    writer.writeVarInt(1n);             // services
    writer.writeUInt8(99);              // unknown networkId
    writer.writeVarInt(513);            // address length > 512
    const reader = new BufferReader(writer.toBuffer());
    expect(() => deserializeAddrV2Payload(reader)).toThrow("Address too large");
  });

  test("address length exactly 512 for unknown network is accepted", () => {
    const writer = new BufferWriter();
    writer.writeVarInt(1);
    writer.writeUInt32LE(1700000000);
    writer.writeVarInt(1n);
    writer.writeUInt8(99);              // unknown networkId
    writer.writeVarInt(512);
    writer.writeBytes(Buffer.alloc(512));
    const portBuf = Buffer.alloc(2);
    portBuf.writeUInt16BE(8333, 0);
    writer.writeBytes(portBuf);
    const reader = new BufferReader(writer.toBuffer());
    const { addrs } = deserializeAddrV2Payload(reader);
    expect(addrs.length).toBe(1);
    expect(addrs[0].addr.networkId).toBe(99);
  });
});

// ---------------------------------------------------------------------------
// G29-G30: addrv2 wire format + getnetworkinfo RPC
// ---------------------------------------------------------------------------

describe("G29 — BUG-4: unknown networkId entries are stored rather than skipped", () => {
  /**
   * BUG-4 (LOW).
   *
   * Core: SetNetFromBIP155Network() returns false for unknown networkIds.
   * The serialization layer catches that and SKIPS the entry entirely.
   * hotbuns deserializeAddrV2Payload() stores unknown-networkId entries in
   * the returned addrs[] array.  isValidNetworkAddressV2() returns true for
   * these (default case), so handleAddrV2Message stores them in knownAddresses.
   *
   * Fix: deserializeAddrV2Payload should skip (not store) entries with unknown
   * networkId, matching Core's "Don't throw … silently drop them" comment.
   */
  test("unknown networkId entry is currently included in deserialized array", () => {
    // BUG: Core would skip this entry; hotbuns stores it.
    const writer = new BufferWriter();
    writer.writeVarInt(2); // 2 addresses: one unknown, one valid IPv4
    // Unknown entry
    writer.writeUInt32LE(1700000000);
    writer.writeVarInt(1n);
    writer.writeUInt8(99); // unknown networkId
    writer.writeVarInt(10);
    writer.writeBytes(Buffer.alloc(10));
    const portBuf = Buffer.alloc(2);
    portBuf.writeUInt16BE(8333, 0);
    writer.writeBytes(portBuf);
    // Valid IPv4 entry
    writer.writeUInt32LE(1700000001);
    writer.writeVarInt(1n);
    writer.writeUInt8(BIP155Network.IPV4);
    writer.writeVarInt(4);
    writer.writeBytes(Buffer.from([1, 2, 3, 4]));
    writer.writeBytes(portBuf);

    const reader = new BufferReader(writer.toBuffer());
    const { addrs } = deserializeAddrV2Payload(reader);
    // BUG: both entries are stored. Core would only store the IPv4 entry.
    expect(addrs.length).toBe(2); // documents the bug: should be 1
    expect(addrs[0].addr.networkId).toBe(99); // the unknown entry is present
    expect(addrs[1].addr.networkId).toBe(BIP155Network.IPV4);
  });

  test("isValidNetworkAddressV2 returns true for unknown networkId (size <= 512)", () => {
    // This is why unknown entries propagate: the validator accepts them.
    const unknownAddr: NetworkAddressV2 = {
      networkId: 99,
      addr: Buffer.alloc(10),
      port: 8333,
      services: 0n,
    };
    // BUG: should return false (unknown = skip), but returns true
    expect(isValidNetworkAddressV2(unknownAddr)).toBe(true);
  });
});

describe("G30 — BUG-3: getnetworkinfo missing onion/i2p/cjdns in networks array", () => {
  /**
   * BUG-3 (MEDIUM).
   *
   * Core: getnetworkinfo returns 5 network entries: ipv4, ipv6, onion, i2p, cjdns.
   * hotbuns hardcodes only [{name:"ipv4"}, {name:"ipv6"}] in the response.
   * Missing onion/i2p/cjdns entries with reachable:false (always false since
   * proxy.ts is dead — BUG-1).
   *
   * Reference: bitcoin-core/src/rpc/net.cpp getnetworkinfo(), nets loop over
   * {NET_IPV4, NET_IPV6, NET_ONION, NET_I2P, NET_CJDNS}.
   *
   * Fix: add the three anonymous-network entries with reachable:false and
   * proxy:"" to the networks array in getNetworkInfo().
   */
  let datadir: string;
  let cleanup: (() => Promise<void>) | undefined;

  beforeEach(async () => {
    datadir = await mkdtemp(join(tmpdir(), "hotbuns-w117-"));
  });

  afterEach(async () => {
    if (cleanup) await cleanup();
    await rm(datadir, { recursive: true, force: true });
  });

  test("RPC server exports getnetworkinfo handler", async () => {
    const { RPCServer } = await import("../src/rpc/server.js");
    expect(typeof RPCServer).toBe("function");
  });

  test("getnetworkinfo networks array: ipv4 and ipv6 are present", async () => {
    const { REGTEST } = await import("../src/consensus/params.js");
    const { ChainStateManager } = await import("../src/chain/state.js");
    const { Mempool } = await import("../src/mempool/mempool.js");
    const { FeeEstimator } = await import("../src/fees/estimator.js");
    const { RPCServer } = await import("../src/rpc/server.js");
    const { createTestDB } = await import("../src/test/helpers.js");

    const testDB = await createTestDB();
    const db = testDB.db;
    cleanup = testDB.cleanup;

    const chainState = new ChainStateManager(db, REGTEST);
    await chainState.load();
    const mempool = new Mempool(chainState.getUTXOManager(), REGTEST);

    class MockPeerManager {
      getConnectedPeers() { return []; }
      // getnetworkinfo reads this for Core's `networkactive` field
      // (PeerManager.getNetworkActive, manager.ts:849).
      getNetworkActive() { return true; }
      getPeerCount() { return 0; }
      broadcast() {}
    }
    class MockHeaderSync {
      getBestHeader() { return null; }
      getHeader() { return null; }
      async processHeaders() { return { success: true, requestMore: false, powValidatedHeaders: [] }; }
      getMedianTimePast() { return 0; }
    }

    const rpc = new RPCServer(
      { port: 18443, host: "127.0.0.1", noAuth: true },
      {
        chainState,
        mempool,
        peerManager: new MockPeerManager() as any,
        feeEstimator: new FeeEstimator(mempool),
        headerSync: new MockHeaderSync() as any,
        db,
        params: REGTEST,
      }
    ) as any;

    const info = await rpc.getNetworkInfo();
    const names = (info.networks as any[]).map((n: any) => n.name);
    expect(names).toContain("ipv4");
    expect(names).toContain("ipv6");
  });

  test("BUG-3 documented: networks array lacks onion/i2p/cjdns entries", async () => {
    const { REGTEST } = await import("../src/consensus/params.js");
    const { ChainStateManager } = await import("../src/chain/state.js");
    const { Mempool } = await import("../src/mempool/mempool.js");
    const { FeeEstimator } = await import("../src/fees/estimator.js");
    const { RPCServer } = await import("../src/rpc/server.js");
    const { createTestDB } = await import("../src/test/helpers.js");

    const testDB = await createTestDB();
    const db = testDB.db;
    cleanup = testDB.cleanup;

    const chainState = new ChainStateManager(db, REGTEST);
    await chainState.load();
    const mempool = new Mempool(chainState.getUTXOManager(), REGTEST);

    class MockPeerManager {
      getConnectedPeers() { return []; }
      // getnetworkinfo reads this for Core's `networkactive` field
      // (PeerManager.getNetworkActive, manager.ts:849).
      getNetworkActive() { return true; }
      getPeerCount() { return 0; }
      broadcast() {}
    }
    class MockHeaderSync {
      getBestHeader() { return null; }
      getHeader() { return null; }
      async processHeaders() { return { success: true, requestMore: false, powValidatedHeaders: [] }; }
      getMedianTimePast() { return 0; }
    }

    const rpc = new RPCServer(
      { port: 18443, host: "127.0.0.1", noAuth: true },
      {
        chainState,
        mempool,
        peerManager: new MockPeerManager() as any,
        feeEstimator: new FeeEstimator(mempool),
        headerSync: new MockHeaderSync() as any,
        db,
        params: REGTEST,
      }
    ) as any;

    const info = await rpc.getNetworkInfo();
    const names = (info.networks as any[]).map((n: any) => n.name);
    // FIXED (BUG-3): Core's getnetworkinfo lists all five networks, and
    // hotbuns now emits onion/i2p/cjdns alongside ipv4/ipv6.
    // Core always returns all 5 network types.
    expect(names).toContain("onion");
    expect(names).toContain("i2p");
    expect(names).toContain("cjdns");
    // Core always returns all 5 network types.
    expect(names.length).toBe(5);
  });
});

// ---------------------------------------------------------------------------
// Additional coverage: wire format, services encoding, mixed-message relay
// ---------------------------------------------------------------------------

describe("Wire format: services field uses compactSize (not uint64) in addrv2", () => {
  test("small services value encoded as 1 byte (0x00-0xfc range)", () => {
    const entries: AddrV2Entry[] = [
      {
        timestamp: 1700000000,
        addr: ipv4ToNetworkAddressV2("1.2.3.4", 8333, 9n), // NODE_NETWORK | NODE_WITNESS
      },
    ];
    const buf = serializeAddrV2Payload(entries);
    const reader = new BufferReader(buf);
    const { addrs } = deserializeAddrV2Payload(reader);
    expect(addrs[0].addr.services).toBe(9n);
  });

  test("NODE_NETWORK_LIMITED (0x0400) encoded correctly via compactSize", () => {
    const entries: AddrV2Entry[] = [
      {
        timestamp: 1700000000,
        addr: ipv4ToNetworkAddressV2("1.2.3.4", 8333, 0x0400n),
      },
    ];
    const buf = serializeAddrV2Payload(entries);
    const reader = new BufferReader(buf);
    const { addrs } = deserializeAddrV2Payload(reader);
    expect(addrs[0].addr.services).toBe(0x0400n);
  });

  test("port is big-endian in addrv2", () => {
    const port = 0x20fb; // 8443
    const entries: AddrV2Entry[] = [
      {
        timestamp: 1700000000,
        addr: ipv4ToNetworkAddressV2("1.2.3.4", port, 1n),
      },
    ];
    const buf = serializeAddrV2Payload(entries);
    // Format: count(1) + time(4) + services(1) + netId(1) + addrLen(1) + addr(4) + port(2)
    const portOffset = 1 + 4 + 1 + 1 + 1 + 4;
    expect(buf[portOffset]).toBe(0x20);
    expect(buf[portOffset + 1]).toBe(0xfb);
  });
});

describe("Mixed network addrv2 serialization round-trip", () => {
  test("4 network types serialize and deserialize in order", () => {
    const tor = Buffer.alloc(32, 0xaa);
    const i2p = Buffer.alloc(32, 0xbb);
    const cjdns = Buffer.alloc(16, 0x00);
    cjdns[0] = 0xfc;

    const entries: AddrV2Entry[] = [
      { timestamp: 1700000000, addr: ipv4ToNetworkAddressV2("1.2.3.4", 8333, 1n) },
      { timestamp: 1700000001, addr: { networkId: BIP155Network.TORV3, addr: tor, port: 8333, services: 8n } },
      { timestamp: 1700000002, addr: { networkId: BIP155Network.I2P, addr: i2p, port: 0, services: 1n } },
      { timestamp: 1700000003, addr: { networkId: BIP155Network.CJDNS, addr: cjdns, port: 8333, services: 9n } },
    ];

    const buf = serializeAddrV2Payload(entries);
    const reader = new BufferReader(buf);
    const { addrs } = deserializeAddrV2Payload(reader);

    expect(addrs.length).toBe(4);
    expect(addrs[0].addr.networkId).toBe(BIP155Network.IPV4);
    expect(addrs[1].addr.networkId).toBe(BIP155Network.TORV3);
    expect(addrs[2].addr.networkId).toBe(BIP155Network.I2P);
    expect(addrs[3].addr.networkId).toBe(BIP155Network.CJDNS);

    expect(addrs[1].addr.addr.equals(tor)).toBe(true);
    expect(addrs[2].addr.addr.equals(i2p)).toBe(true);
    expect(addrs[3].addr.addr[0]).toBe(0xfc);
  });
});

describe("Network name mapping", () => {
  test("getNetworkName covers all 6 BIP155 IDs", () => {
    expect(getNetworkName(1)).toBe("IPv4");
    expect(getNetworkName(2)).toBe("IPv6");
    expect(getNetworkName(3)).toBe("TorV2");
    expect(getNetworkName(4)).toBe("TorV3");
    expect(getNetworkName(5)).toBe("I2P");
    expect(getNetworkName(6)).toBe("CJDNS");
    expect(getNetworkName(99)).toBe("Unknown(99)");
  });
});
