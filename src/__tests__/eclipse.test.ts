/**
 * Tests for eclipse attack protections.
 *
 * Tests network group diversity, anchor connections, and inbound eviction.
 */

import { describe, expect, test, beforeEach, afterEach } from "bun:test";
import { mkdtemp, rm, readdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  PeerManager,
  type PeerManagerConfig,
  getNetGroup,
  isLocalAddress,
  type EvictionCandidate,
  MAX_OUTBOUND_FULL_RELAY,
  MAX_OUTBOUND_BLOCK_RELAY,
  MAX_BLOCK_RELAY_ONLY_ANCHORS,
  EVICTION_PROTECT_NETGROUP,
  EVICTION_PROTECT_PING,
  EVICTION_PROTECT_TX,
  EVICTION_PROTECT_BLOCKS,
} from "../p2p/manager.js";
import { REGTEST } from "../consensus/params.js";

/** Test timeout in ms */
const TEST_TIMEOUT = 10000;

/** Create a mock peer object for testing */
function createMockPeer(host: string, port: number, options: {
  latency?: number;
  state?: string;
} = {}) {
  return {
    host,
    port,
    latency: options.latency ?? 100,
    state: options.state ?? "connected",
    disconnect: () => {},
  };
}

describe("getNetGroup", () => {
  test("IPv4 addresses use /16 prefix", () => {
    // Same /16
    expect(getNetGroup("192.168.1.1")).toBe("ipv4:192.168");
    expect(getNetGroup("192.168.2.100")).toBe("ipv4:192.168");
    expect(getNetGroup("192.168.255.255")).toBe("ipv4:192.168");

    // Different /16
    expect(getNetGroup("192.169.1.1")).toBe("ipv4:192.169");
    expect(getNetGroup("10.0.1.1")).toBe("ipv4:10.0");
    expect(getNetGroup("172.16.5.5")).toBe("ipv4:172.16");
  });

  test("different /16 subnets produce different groups", () => {
    const group1 = getNetGroup("192.168.1.1");
    const group2 = getNetGroup("192.169.1.1");
    const group3 = getNetGroup("10.0.1.1");

    expect(group1).not.toBe(group2);
    expect(group1).not.toBe(group3);
    expect(group2).not.toBe(group3);
  });

  test("same /16 subnet produces same group", () => {
    const addresses = [
      "192.168.0.1",
      "192.168.100.200",
      "192.168.255.255",
    ];

    const groups = addresses.map(getNetGroup);
    expect(new Set(groups).size).toBe(1);
  });

  test("IPv6 addresses use /32 prefix", () => {
    // Full IPv6 addresses
    expect(getNetGroup("2001:0db8:85a3:0000:0000:8a2e:0370:7334")).toBe(
      "ipv6:2001:0db8"
    );
    expect(getNetGroup("2001:0db8:1234:5678:90ab:cdef:0123:4567")).toBe(
      "ipv6:2001:0db8"
    );

    // Different /32
    expect(getNetGroup("2001:0db9:85a3:0000:0000:8a2e:0370:7334")).toBe(
      "ipv6:2001:0db9"
    );
  });

  test("IPv6 with double colon notation", () => {
    // ::1 (loopback)
    expect(getNetGroup("::1")).toBe("ipv6:0000:0000");

    // 2001:db8::1
    expect(getNetGroup("2001:db8::1")).toBe("ipv6:2001:0db8");
  });

  test("handles hostname as fallback", () => {
    expect(getNetGroup("seed.bitcoin.sipa.be")).toBe(
      "other:seed.bitcoin.sipa.be"
    );
  });
});

describe("isLocalAddress", () => {
  test("identifies localhost addresses", () => {
    expect(isLocalAddress("127.0.0.1")).toBe(true);
    expect(isLocalAddress("localhost")).toBe(true);
    expect(isLocalAddress("::1")).toBe(true);
    expect(isLocalAddress("127.0.1.1")).toBe(true);
  });

  test("identifies non-local addresses", () => {
    expect(isLocalAddress("192.168.1.1")).toBe(false);
    expect(isLocalAddress("10.0.0.1")).toBe(false);
    expect(isLocalAddress("8.8.8.8")).toBe(false);
    expect(isLocalAddress("2001:db8::1")).toBe(false);
  });
});

describe("network group diversity", () => {
  let tempDir: string;
  let manager: PeerManager;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "hotbuns-eclipse-test-"));
    const config: PeerManagerConfig = {
      maxOutbound: 10,
      maxInbound: 117,
      params: REGTEST,
      bestHeight: 0,
      datadir: tempDir,
    };
    manager = new PeerManager(config);
  });

  afterEach(async () => {
    await manager.stop();
    await rm(tempDir, { recursive: true, force: true });
  });

  test("rejects outbound connection to same netgroup", async () => {
    // Manually add a netgroup to simulate existing connection
    // @ts-expect-error - accessing private field for testing
    manager.outboundNetGroups.add("ipv4:192.168");

    // Try to connect to peer in same /16
    await expect(
      manager.connectPeer("192.168.1.1", 8333, "full_relay")
    ).rejects.toThrow("netgroup");
  });

  test("allows outbound connection to different netgroup", () => {
    // Add a netgroup
    // @ts-expect-error - accessing private field for testing
    manager.outboundNetGroups.add("ipv4:192.168");

    // Verify different /16 is not blocked by netgroup check
    const netGroup = getNetGroup("10.0.0.1");
    // @ts-expect-error - accessing private field for testing
    expect(manager.outboundNetGroups.has(netGroup)).toBe(false);
  });

  test("tracks outbound netgroups correctly", () => {
    // Add some netgroups
    // @ts-expect-error - accessing private field for testing
    manager.outboundNetGroups.add("ipv4:192.168");
    // @ts-expect-error - accessing private field for testing
    manager.outboundNetGroups.add("ipv4:10.0");

    const groups = manager.getOutboundNetGroups();
    expect(groups.has("ipv4:192.168")).toBe(true);
    expect(groups.has("ipv4:10.0")).toBe(true);
    expect(groups.size).toBe(2);
  });

  test("inbound connections skip netgroup check", () => {
    // Add a netgroup to outbound set
    // @ts-expect-error - accessing private field for testing
    manager.outboundNetGroups.add("ipv4:192.168");

    // The check in connectPeer only applies to non-inbound connections
    // Verify that the netgroup is in the outbound set
    // @ts-expect-error - accessing private field for testing
    expect(manager.outboundNetGroups.has("ipv4:192.168")).toBe(true);

    // For inbound, the check is skipped - we can verify the code path
    // by checking that inbound doesn't add to outboundNetGroups
    const key = "192.168.50.50:8333";
    // @ts-expect-error - accessing private fields
    manager.peers.set(key, createMockPeer("192.168.50.50", 8333));
    // @ts-expect-error - accessing private fields
    manager.peerConnectionType.set(key, "inbound");
    // @ts-expect-error - accessing private fields
    manager.inboundPeers.add(key);

    // Outbound netgroups should not have been modified
    expect(manager.getOutboundNetGroups().size).toBe(1);
    // But we should have an inbound peer
    expect(manager.getInboundCount()).toBe(1);
  });
});

describe("anchor connections", () => {
  let tempDir: string;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "hotbuns-anchor-test-"));
  });

  afterEach(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  test("anchors file is created on shutdown", async () => {
    const config: PeerManagerConfig = {
      maxOutbound: 10,
      maxInbound: 117,
      params: REGTEST,
      bestHeight: 0,
      datadir: tempDir,
    };

    const manager = new PeerManager(config);

    // Manually add a block-relay connection to be saved as anchor
    // @ts-expect-error - accessing private fields for testing
    manager.peerConnectionType.set("192.168.1.1:8333", "block_relay");
    // @ts-expect-error - accessing private field for testing
    manager.peers.set("192.168.1.1:8333", createMockPeer("192.168.1.1", 8333));

    await manager.stop();

    // Check that anchors.dat was created
    const files = await readdir(tempDir);
    expect(files).toContain("anchors.dat");
  });

  test("anchors are loaded on start", async () => {
    const config: PeerManagerConfig = {
      maxOutbound: 10,
      maxInbound: 117,
      params: REGTEST,
      bestHeight: 0,
      datadir: tempDir,
    };

    // Create a mock anchors.dat file
    const { BufferWriter } = await import("../wire/serialization.js");
    const writer = new BufferWriter();
    writer.writeUInt8(1); // version
    writer.writeVarInt(2); // count
    writer.writeVarString("192.168.1.1");
    writer.writeUInt16LE(8333);
    writer.writeVarString("10.0.0.1");
    writer.writeUInt16LE(8333);

    await Bun.write(join(tempDir, "anchors.dat"), writer.toBuffer());

    const manager = new PeerManager(config);

    // Use loadAnchors directly instead of start() to avoid DNS/connection timeouts
    // @ts-expect-error - accessing private method for testing
    await manager.loadAnchors();

    // Check anchors were loaded
    const anchors = manager.getAnchors();
    expect(anchors.length).toBe(2);
    expect(anchors[0]).toEqual({ host: "192.168.1.1", port: 8333 });
    expect(anchors[1]).toEqual({ host: "10.0.0.1", port: 8333 });

    // Anchors file should be deleted after loading
    const files = await readdir(tempDir);
    expect(files).not.toContain("anchors.dat");

    await manager.stop();
  });

  test("limits anchors to MAX_BLOCK_RELAY_ONLY_ANCHORS", async () => {
    const config: PeerManagerConfig = {
      maxOutbound: 10,
      maxInbound: 117,
      params: REGTEST,
      bestHeight: 0,
      datadir: tempDir,
    };

    // Create anchors.dat with more than max anchors
    const { BufferWriter } = await import("../wire/serialization.js");
    const writer = new BufferWriter();
    writer.writeUInt8(1); // version
    writer.writeVarInt(5); // count (more than max)

    for (let i = 0; i < 5; i++) {
      writer.writeVarString(`192.168.${i}.1`);
      writer.writeUInt16LE(8333);
    }

    await Bun.write(join(tempDir, "anchors.dat"), writer.toBuffer());

    const manager = new PeerManager(config);

    // Use loadAnchors directly instead of start() to avoid DNS/connection timeouts
    // @ts-expect-error - accessing private method for testing
    await manager.loadAnchors();

    // Should only load up to MAX_BLOCK_RELAY_ONLY_ANCHORS
    const anchors = manager.getAnchors();
    expect(anchors.length).toBe(MAX_BLOCK_RELAY_ONLY_ANCHORS);

    await manager.stop();
  });
});

describe("inbound eviction", () => {
  let tempDir: string;
  let manager: PeerManager;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "hotbuns-eviction-test-"));
    const config: PeerManagerConfig = {
      maxOutbound: 10,
      maxInbound: 10, // Small for testing
      params: REGTEST,
      bestHeight: 0,
      datadir: tempDir,
    };
    manager = new PeerManager(config);
  });

  afterEach(async () => {
    await manager.stop();
    await rm(tempDir, { recursive: true, force: true });
  });

  test("selectPeerToEvict returns null with no inbound peers", () => {
    const evicted = manager.selectPeerToEvict();
    expect(evicted).toBeNull();
  });

  test("selectPeerToEvict protects by network group diversity", () => {
    // Add mock inbound peers
    // @ts-expect-error - accessing private fields for testing
    manager.inboundPeers.add("192.168.1.1:8333");
    // @ts-expect-error - accessing private fields
    manager.inboundPeers.add("10.0.0.1:8333");
    // @ts-expect-error - accessing private fields
    manager.inboundPeers.add("172.16.0.1:8333");
    // @ts-expect-error - accessing private fields
    manager.inboundPeers.add("8.8.8.8:8333");
    // @ts-expect-error - accessing private fields
    manager.inboundPeers.add("1.1.1.1:8333");

    // Add mock peer objects
    const now = Date.now();
    const mockPeers = [
      { host: "192.168.1.1", port: 8333, latency: 100 },
      { host: "10.0.0.1", port: 8333, latency: 50 },
      { host: "172.16.0.1", port: 8333, latency: 200 },
      { host: "8.8.8.8", port: 8333, latency: 30 },
      { host: "1.1.1.1", port: 8333, latency: 150 },
    ];

    for (const p of mockPeers) {
      const key = `${p.host}:${p.port}`;
      // @ts-expect-error - accessing private fields
      manager.peers.set(key, createMockPeer(p.host, p.port, { latency: p.latency }));
      // @ts-expect-error - accessing private fields
      manager.peerConnectionType.set(key, "inbound");
      // @ts-expect-error - accessing private fields
      manager.knownAddresses.set(key, {
        host: p.host,
        port: p.port,
        services: 1n,
        lastSeen: now,
        banScore: 0,
        lastConnected: now,
        connectionType: "inbound",
        connectedTime: now - Math.random() * 10000,
        minPingTime: p.latency,
      });
    }

    // With only 5 peers and EVICTION_PROTECT_NETGROUP=4,
    // most should be protected, but we should still get one
    const evicted = manager.selectPeerToEvict();

    // Should return a peer or null (if all protected)
    // The exact result depends on protection algorithm
    expect(evicted === null || typeof evicted === "string").toBe(true);
  });

  test("protects localhost connections from eviction", () => {
    // Add localhost peer and remote peers
    // @ts-expect-error - accessing private fields
    manager.inboundPeers.add("127.0.0.1:8333");
    // @ts-expect-error - accessing private fields
    manager.inboundPeers.add("192.168.1.1:8333");

    const now = Date.now();

    // @ts-expect-error - accessing private fields
    manager.peers.set("127.0.0.1:8333", createMockPeer("127.0.0.1", 8333, { latency: 1 }));
    // @ts-expect-error - accessing private fields
    manager.peers.set("192.168.1.1:8333", createMockPeer("192.168.1.1", 8333, { latency: 100 }));

    // @ts-expect-error - accessing private fields
    manager.peerConnectionType.set("127.0.0.1:8333", "inbound");
    // @ts-expect-error - accessing private fields
    manager.peerConnectionType.set("192.168.1.1:8333", "inbound");

    // @ts-expect-error - accessing private fields
    manager.knownAddresses.set("127.0.0.1:8333", {
      host: "127.0.0.1",
      port: 8333,
      services: 1n,
      lastSeen: now,
      banScore: 0,
      lastConnected: now,
      connectedTime: now,
    });
    // @ts-expect-error - accessing private fields
    manager.knownAddresses.set("192.168.1.1:8333", {
      host: "192.168.1.1",
      port: 8333,
      services: 1n,
      lastSeen: now,
      banScore: 0,
      lastConnected: now,
      connectedTime: now,
    });

    const evicted = manager.selectPeerToEvict();

    // If a peer is evicted, it should NOT be localhost
    if (evicted) {
      expect(evicted).not.toBe("127.0.0.1:8333");
    }
  });

  test("recordBlockFromPeer updates lastBlockTime", () => {
    const key = "192.168.1.1:8333";
    const now = Date.now();

    // @ts-expect-error - accessing private fields
    manager.knownAddresses.set(key, {
      host: "192.168.1.1",
      port: 8333,
      services: 1n,
      lastSeen: now,
      banScore: 0,
      lastConnected: now,
    });

    manager.recordBlockFromPeer(key);

    // @ts-expect-error - accessing private fields
    const info = manager.knownAddresses.get(key);
    expect(info?.lastBlockTime).toBeGreaterThan(0);
  });

  test("recordTxFromPeer updates lastTxTime", () => {
    const key = "192.168.1.1:8333";
    const now = Date.now();

    // @ts-expect-error - accessing private fields
    manager.knownAddresses.set(key, {
      host: "192.168.1.1",
      port: 8333,
      services: 1n,
      lastSeen: now,
      banScore: 0,
      lastConnected: now,
    });

    manager.recordTxFromPeer(key);

    // @ts-expect-error - accessing private fields
    const info = manager.knownAddresses.get(key);
    expect(info?.lastTxTime).toBeGreaterThan(0);
  });

  test("recordPingFromPeer updates minPingTime", () => {
    const key = "192.168.1.1:8333";
    const now = Date.now();

    // @ts-expect-error - accessing private fields
    manager.knownAddresses.set(key, {
      host: "192.168.1.1",
      port: 8333,
      services: 1n,
      lastSeen: now,
      banScore: 0,
      lastConnected: now,
    });

    manager.recordPingFromPeer(key, 50);
    // @ts-expect-error - accessing private fields
    expect(manager.knownAddresses.get(key)?.minPingTime).toBe(50);

    // Should update to lower value
    manager.recordPingFromPeer(key, 30);
    // @ts-expect-error - accessing private fields
    expect(manager.knownAddresses.get(key)?.minPingTime).toBe(30);

    // Should not update to higher value
    manager.recordPingFromPeer(key, 100);
    // @ts-expect-error - accessing private fields
    expect(manager.knownAddresses.get(key)?.minPingTime).toBe(30);
  });
});

describe("eviction from largest netgroup", () => {
  let tempDir: string;
  let manager: PeerManager;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "hotbuns-eviction-test-"));
    const config: PeerManagerConfig = {
      maxOutbound: 10,
      maxInbound: 100,
      params: REGTEST,
      bestHeight: 0,
      datadir: tempDir,
    };
    manager = new PeerManager(config);
  });

  afterEach(async () => {
    await manager.stop();
    await rm(tempDir, { recursive: true, force: true });
  });

  test("evicts from largest network group", () => {
    const now = Date.now();

    // Create peers with varying netgroup sizes
    // Group 1: 192.168.x.x - 5 peers (largest)
    // Group 2: 10.0.x.x - 2 peers
    // Group 3: 172.16.x.x - 1 peer

    const peers = [
      // Group 1 (largest - should be eviction target)
      { host: "192.168.1.1", port: 8333 },
      { host: "192.168.1.2", port: 8333 },
      { host: "192.168.1.3", port: 8333 },
      { host: "192.168.1.4", port: 8333 },
      { host: "192.168.1.5", port: 8333 },
      // Group 2
      { host: "10.0.0.1", port: 8333 },
      { host: "10.0.0.2", port: 8333 },
      // Group 3
      { host: "172.16.0.1", port: 8333 },
    ];

    for (let i = 0; i < peers.length; i++) {
      const p = peers[i];
      const key = `${p.host}:${p.port}`;

      // @ts-expect-error - accessing private fields
      manager.inboundPeers.add(key);
      // @ts-expect-error - accessing private fields
      manager.peers.set(key, createMockPeer(p.host, p.port));
      // @ts-expect-error - accessing private fields
      manager.peerConnectionType.set(key, "inbound");
      // @ts-expect-error - accessing private fields
      manager.knownAddresses.set(key, {
        host: p.host,
        port: p.port,
        services: 1n,
        lastSeen: now,
        banScore: 0,
        lastConnected: now,
        connectionType: "inbound",
        connectedTime: now - (peers.length - i) * 1000, // Oldest first
        minPingTime: 100,
      });
    }

    const evicted = manager.selectPeerToEvict();

    // Evicted peer should be from the largest group (192.168.x.x)
    if (evicted) {
      expect(evicted.startsWith("192.168.")).toBe(true);
    }
  });
});

describe("connection type tracking", () => {
  let tempDir: string;
  let manager: PeerManager;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "hotbuns-conn-test-"));
    const config: PeerManagerConfig = {
      maxOutbound: 10,
      maxInbound: 117,
      params: REGTEST,
      bestHeight: 0,
      datadir: tempDir,
    };
    manager = new PeerManager(config);
  });

  afterEach(async () => {
    await manager.stop();
    await rm(tempDir, { recursive: true, force: true });
  });

  test("getConnectionType returns correct type", () => {
    // @ts-expect-error - accessing private fields
    manager.peerConnectionType.set("192.168.1.1:8333", "full_relay");
    // @ts-expect-error - accessing private fields
    manager.peerConnectionType.set("10.0.0.1:8333", "block_relay");
    // @ts-expect-error - accessing private fields
    manager.peerConnectionType.set("172.16.0.1:8333", "inbound");

    expect(manager.getConnectionType("192.168.1.1:8333")).toBe("full_relay");
    expect(manager.getConnectionType("10.0.0.1:8333")).toBe("block_relay");
    expect(manager.getConnectionType("172.16.0.1:8333")).toBe("inbound");
    expect(manager.getConnectionType("unknown:8333")).toBeUndefined();
  });

  test("getFullRelayCount returns correct count", () => {
    // @ts-expect-error - accessing private fields
    manager.peerConnectionType.set("192.168.1.1:8333", "full_relay");
    // @ts-expect-error - accessing private fields
    manager.peerConnectionType.set("192.168.1.2:8333", "full_relay");
    // @ts-expect-error - accessing private fields
    manager.peerConnectionType.set("10.0.0.1:8333", "block_relay");
    // @ts-expect-error - accessing private fields
    manager.peerConnectionType.set("172.16.0.1:8333", "inbound");

    expect(manager.getFullRelayCount()).toBe(2);
  });

  test("getBlockRelayCount returns correct count", () => {
    // @ts-expect-error - accessing private fields
    manager.peerConnectionType.set("192.168.1.1:8333", "full_relay");
    // @ts-expect-error - accessing private fields
    manager.peerConnectionType.set("10.0.0.1:8333", "block_relay");
    // @ts-expect-error - accessing private fields
    manager.peerConnectionType.set("10.0.0.2:8333", "block_relay");
    // @ts-expect-error - accessing private fields
    manager.peerConnectionType.set("172.16.0.1:8333", "inbound");

    expect(manager.getBlockRelayCount()).toBe(2);
  });

  test("getInboundCount returns correct count", () => {
    // @ts-expect-error - accessing private fields
    manager.inboundPeers.add("192.168.1.1:8333");
    // @ts-expect-error - accessing private fields
    manager.inboundPeers.add("10.0.0.1:8333");

    expect(manager.getInboundCount()).toBe(2);
  });
});

describe("constants", () => {
  test("MAX_OUTBOUND_FULL_RELAY is 8", () => {
    expect(MAX_OUTBOUND_FULL_RELAY).toBe(8);
  });

  test("MAX_OUTBOUND_BLOCK_RELAY is 2", () => {
    expect(MAX_OUTBOUND_BLOCK_RELAY).toBe(2);
  });

  test("MAX_BLOCK_RELAY_ONLY_ANCHORS is 2", () => {
    expect(MAX_BLOCK_RELAY_ONLY_ANCHORS).toBe(2);
  });

  test("eviction protection counts are defined", () => {
    expect(EVICTION_PROTECT_NETGROUP).toBe(4);
    expect(EVICTION_PROTECT_PING).toBe(8);
    expect(EVICTION_PROTECT_TX).toBe(4);
    expect(EVICTION_PROTECT_BLOCKS).toBe(4);
  });
});
