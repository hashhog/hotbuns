/**
 * Tests for the PeerManager class.
 *
 * Uses mock servers and DNS resolution to test peer discovery,
 * connection lifecycle, ban scoring, and message routing.
 */

import { describe, expect, test, beforeEach, afterEach, mock, spyOn } from "bun:test";
import type { TCPSocketListener, Socket } from "bun";
import {
  PeerManager,
  type PeerManagerConfig,
  type PeerInfo,
  ServiceFlags,
  BanScores,
} from "./manager.js";
import { Peer } from "./peer.js";
import {
  type NetworkMessage,
  MESSAGE_HEADER_SIZE,
  parseHeader,
  deserializeMessage,
  serializeMessage,
  ipv4ToBuffer,
} from "./messages.js";
import { REGTEST } from "../consensus/params.js";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

/** Test timeout in ms */
const TEST_TIMEOUT = 10000;

/**
 * Mock Bitcoin peer server for testing.
 * Performs version handshake and can send/receive messages.
 */
class MockPeerServer {
  private server: TCPSocketListener<undefined> | null = null;
  clientSocket: Socket<undefined> | null = null;
  private recvBuffer: Buffer = Buffer.alloc(0);
  private magic: number;
  port: number = 0;

  onMessage: ((msg: NetworkMessage) => void) | null = null;
  onConnect: (() => void) | null = null;
  receivedMessages: NetworkMessage[] = [];

  constructor(magic: number = REGTEST.networkMagic) {
    this.magic = magic;
  }

  async start(): Promise<void> {
    this.server = Bun.listen<undefined>({
      hostname: "127.0.0.1",
      port: 0,
      socket: {
        data: (socket, data) => {
          this.clientSocket = socket;
          this.recvBuffer = Buffer.concat([this.recvBuffer, Buffer.from(data)]);
          this.processBuffer();
        },
        open: (socket) => {
          this.clientSocket = socket;
          this.onConnect?.();
        },
        close: () => {
          this.clientSocket = null;
        },
        error: () => {
          this.clientSocket = null;
        },
      },
    });
    this.port = this.server.port;
  }

  stop(): void {
    if (this.clientSocket) {
      this.clientSocket.end();
      this.clientSocket = null;
    }
    if (this.server) {
      this.server.stop();
      this.server = null;
    }
    this.recvBuffer = Buffer.alloc(0);
    this.receivedMessages = [];
    this.onMessage = null;
    this.onConnect = null;
  }

  private processBuffer(): void {
    while (this.recvBuffer.length >= MESSAGE_HEADER_SIZE) {
      const header = parseHeader(this.recvBuffer);
      if (!header) break;

      const totalLength = MESSAGE_HEADER_SIZE + header.length;
      if (this.recvBuffer.length < totalLength) break;

      const payload = this.recvBuffer.subarray(MESSAGE_HEADER_SIZE, totalLength);
      const msg = deserializeMessage(header, payload);
      this.recvBuffer = this.recvBuffer.subarray(totalLength);

      this.receivedMessages.push(msg);
      this.onMessage?.(msg);
    }
  }

  send(msg: NetworkMessage): void {
    if (this.clientSocket) {
      const data = serializeMessage(this.magic, msg);
      this.clientSocket.write(data);
    }
  }

  sendVersion(): void {
    const now = BigInt(Math.floor(Date.now() / 1000));
    const nonce = BigInt(Math.floor(Math.random() * Number.MAX_SAFE_INTEGER));

    this.send({
      type: "version",
      payload: {
        version: 70016,
        services: 0x0409n,
        timestamp: now,
        addrRecv: {
          services: 0n,
          ip: ipv4ToBuffer("127.0.0.1"),
          port: 0,
        },
        addrFrom: {
          services: 0x0409n,
          ip: ipv4ToBuffer("127.0.0.1"),
          port: this.port,
        },
        nonce,
        userAgent: "/mock-peer:0.0.1/",
        startHeight: 850000,
        relay: true,
      },
    });
  }

  sendVerack(): void {
    this.send({ type: "verack", payload: null });
  }

  autoHandshake(): void {
    this.onMessage = (msg) => {
      if (msg.type === "version") {
        this.sendVersion();
        this.sendVerack();
      }
    };
  }
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

describe("PeerManager", () => {
  let tempDir: string;
  let mockServer1: MockPeerServer;
  let mockServer2: MockPeerServer;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "hotbuns-test-"));
    mockServer1 = new MockPeerServer();
    mockServer2 = new MockPeerServer();
    await mockServer1.start();
    await mockServer2.start();
  });

  afterEach(async () => {
    mockServer1.stop();
    mockServer2.stop();
    await rm(tempDir, { recursive: true, force: true });
  });

  test("creates PeerManager with config", () => {
    const config: PeerManagerConfig = {
      maxOutbound: 8,
      maxInbound: 117,
      params: REGTEST,
      bestHeight: 0,
      datadir: tempDir,
    };

    const manager = new PeerManager(config);
    expect(manager).toBeDefined();
    expect(manager.getConnectedPeers()).toHaveLength(0);
    expect(manager.getOutboundCount()).toBe(0);
  });

  test("connects to a single peer", async () => {
    const config: PeerManagerConfig = {
      maxOutbound: 8,
      maxInbound: 117,
      params: REGTEST,
      bestHeight: 0,
      datadir: tempDir,
    };

    mockServer1.autoHandshake();

    const manager = new PeerManager(config);

    const peer = await manager.connectPeer("127.0.0.1", mockServer1.port);
    expect(peer).toBeDefined();
    expect(peer.host).toBe("127.0.0.1");
    expect(peer.port).toBe(mockServer1.port);

    // Wait for handshake to complete
    await waitFor(() => peer.state === "connected");

    expect(manager.getConnectedPeers()).toHaveLength(1);
    expect(manager.getOutboundCount()).toBe(1);

    await manager.stop();
  }, TEST_TIMEOUT);

  test("connects to multiple peers", async () => {
    const config: PeerManagerConfig = {
      maxOutbound: 8,
      maxInbound: 117,
      params: REGTEST,
      bestHeight: 0,
      datadir: tempDir,
    };

    mockServer1.autoHandshake();
    mockServer2.autoHandshake();

    const manager = new PeerManager(config);

    const peer1 = await manager.connectPeer("127.0.0.1", mockServer1.port);
    const peer2 = await manager.connectPeer("127.0.0.1", mockServer2.port);

    await waitFor(() => peer1.state === "connected" && peer2.state === "connected");

    expect(manager.getConnectedPeers()).toHaveLength(2);
    expect(manager.getOutboundCount()).toBe(2);

    await manager.stop();
  }, TEST_TIMEOUT);

  test("disconnects peer on request", async () => {
    const config: PeerManagerConfig = {
      maxOutbound: 8,
      maxInbound: 117,
      params: REGTEST,
      bestHeight: 0,
      datadir: tempDir,
    };

    mockServer1.autoHandshake();

    const manager = new PeerManager(config);
    const peer = await manager.connectPeer("127.0.0.1", mockServer1.port);

    await waitFor(() => peer.state === "connected");
    expect(manager.getConnectedPeers()).toHaveLength(1);

    const key = `127.0.0.1:${mockServer1.port}`;
    manager.disconnectPeer(key);

    await waitFor(() => peer.state === "disconnected");
    expect(manager.getConnectedPeers()).toHaveLength(0);

    await manager.stop();
  }, TEST_TIMEOUT);

  test("broadcasts message to all connected peers", async () => {
    const config: PeerManagerConfig = {
      maxOutbound: 8,
      maxInbound: 117,
      params: REGTEST,
      bestHeight: 0,
      datadir: tempDir,
    };

    mockServer1.autoHandshake();
    mockServer2.autoHandshake();

    const manager = new PeerManager(config);

    const peer1 = await manager.connectPeer("127.0.0.1", mockServer1.port);
    const peer2 = await manager.connectPeer("127.0.0.1", mockServer2.port);

    await waitFor(() => peer1.state === "connected" && peer2.state === "connected");

    // Broadcast a ping message
    const nonce = 12345n;
    manager.broadcast({ type: "ping", payload: { nonce } });

    // Wait for both servers to receive the ping
    await waitFor(() =>
      mockServer1.receivedMessages.some((m) => m.type === "ping") &&
      mockServer2.receivedMessages.some((m) => m.type === "ping")
    );

    const ping1 = mockServer1.receivedMessages.find((m) => m.type === "ping");
    const ping2 = mockServer2.receivedMessages.find((m) => m.type === "ping");

    expect(ping1).toBeDefined();
    expect(ping2).toBeDefined();
    if (ping1?.type === "ping") expect(ping1.payload.nonce).toBe(nonce);
    if (ping2?.type === "ping") expect(ping2.payload.nonce).toBe(nonce);

    await manager.stop();
  }, TEST_TIMEOUT);

  test("routes messages to registered handlers", async () => {
    const config: PeerManagerConfig = {
      maxOutbound: 8,
      maxInbound: 117,
      params: REGTEST,
      bestHeight: 0,
      datadir: tempDir,
    };

    mockServer1.autoHandshake();

    const manager = new PeerManager(config);

    const receivedPings: NetworkMessage[] = [];
    manager.onMessage("ping", (_peer, msg) => {
      receivedPings.push(msg);
    });

    const peer = await manager.connectPeer("127.0.0.1", mockServer1.port);

    await waitFor(() => peer.state === "connected");

    // Server sends a ping
    mockServer1.send({ type: "ping", payload: { nonce: 99999n } });

    // Wait for handler to receive it
    await waitFor(() => receivedPings.length > 0);

    expect(receivedPings).toHaveLength(1);
    expect(receivedPings[0].type).toBe("ping");
    if (receivedPings[0].type === "ping") {
      expect(receivedPings[0].payload.nonce).toBe(99999n);
    }

    await manager.stop();
  }, TEST_TIMEOUT);

  test("increases ban score and evicts misbehaving peer", async () => {
    const config: PeerManagerConfig = {
      maxOutbound: 8,
      maxInbound: 117,
      params: REGTEST,
      bestHeight: 0,
      datadir: tempDir,
    };

    mockServer1.autoHandshake();

    const manager = new PeerManager(config);
    const peer = await manager.connectPeer("127.0.0.1", mockServer1.port);

    await waitFor(() => peer.state === "connected");

    // Increase ban score below threshold
    manager.increaseBanScore(peer, 50, "test reason");

    // Peer should still be connected
    expect(manager.getConnectedPeers()).toHaveLength(1);

    // Increase ban score above threshold
    manager.increaseBanScore(peer, 60, "another test reason");

    // Peer should be disconnected and banned
    await waitFor(() => peer.state === "disconnected");
    expect(manager.getConnectedPeers()).toHaveLength(0);

    // Check that peer is banned
    const addresses = manager.getKnownAddresses();
    const key = `127.0.0.1:${mockServer1.port}`;
    const info = addresses.get(key);
    expect(info?.banScore).toBeGreaterThanOrEqual(100);

    await manager.stop();
  }, TEST_TIMEOUT);

  test("returns already connected peer when connecting twice", async () => {
    const config: PeerManagerConfig = {
      maxOutbound: 8,
      maxInbound: 117,
      params: REGTEST,
      bestHeight: 0,
      datadir: tempDir,
    };

    mockServer1.autoHandshake();

    const manager = new PeerManager(config);

    const peer1 = await manager.connectPeer("127.0.0.1", mockServer1.port);
    await waitFor(() => peer1.state === "connected");

    const peer2 = await manager.connectPeer("127.0.0.1", mockServer1.port);

    // Should return the same peer instance
    expect(peer2).toBe(peer1);
    expect(manager.getConnectedPeers()).toHaveLength(1);

    await manager.stop();
  }, TEST_TIMEOUT);

  test("updates best height", async () => {
    const config: PeerManagerConfig = {
      maxOutbound: 8,
      maxInbound: 117,
      params: REGTEST,
      bestHeight: 0,
      datadir: tempDir,
    };

    const manager = new PeerManager(config);

    manager.updateBestHeight(100000);

    // Should be reflected in new connections
    // (internal state - we can't easily verify this without exposing config)
    expect(manager).toBeDefined();

    await manager.stop();
  });

  test("handles multiple message handlers for same type", async () => {
    const config: PeerManagerConfig = {
      maxOutbound: 8,
      maxInbound: 117,
      params: REGTEST,
      bestHeight: 0,
      datadir: tempDir,
    };

    mockServer1.autoHandshake();

    const manager = new PeerManager(config);

    const handler1Calls: number[] = [];
    const handler2Calls: number[] = [];

    manager.onMessage("ping", () => {
      handler1Calls.push(1);
    });
    manager.onMessage("ping", () => {
      handler2Calls.push(2);
    });

    const peer = await manager.connectPeer("127.0.0.1", mockServer1.port);
    await waitFor(() => peer.state === "connected");

    mockServer1.send({ type: "ping", payload: { nonce: 111n } });

    await waitFor(() => handler1Calls.length > 0 && handler2Calls.length > 0);

    expect(handler1Calls).toHaveLength(1);
    expect(handler2Calls).toHaveLength(1);

    await manager.stop();
  }, TEST_TIMEOUT);

  test("bans peer on disconnectPeer with ban flag", async () => {
    const config: PeerManagerConfig = {
      maxOutbound: 8,
      maxInbound: 117,
      params: REGTEST,
      bestHeight: 0,
      datadir: tempDir,
    };

    mockServer1.autoHandshake();

    const manager = new PeerManager(config);
    const peer = await manager.connectPeer("127.0.0.1", mockServer1.port);

    await waitFor(() => peer.state === "connected");

    const key = `127.0.0.1:${mockServer1.port}`;
    manager.disconnectPeer(key, true); // Ban

    await waitFor(() => peer.state === "disconnected");

    const addresses = manager.getKnownAddresses();
    const info = addresses.get(key);
    expect(info?.banScore).toBe(100);

    await manager.stop();
  }, TEST_TIMEOUT);

  test("does not dispatch messages after stop() — no DB writes can race db.close", async () => {
    // Regression for hotbuns LEVEL_DATABASE_NOT_OPEN spam during graceful
    // shutdown.  Pattern in production:
    //   SIGTERM → gracefulShutdown → peerManager.stop() → db.close()
    //   Buffered "headers" messages still flow → handler fires →
    //   saveHeaderEntry → db.put() → throws LEVEL_DATABASE_NOT_OPEN.
    // Fix (Approach A): handlePeerMessage bails when this.running === false.
    const config: PeerManagerConfig = {
      maxOutbound: 8,
      maxInbound: 117,
      params: REGTEST,
      bestHeight: 0,
      datadir: tempDir,
    };

    mockServer1.autoHandshake();

    const manager = new PeerManager(config);

    let dispatchedAfterStop = 0;
    manager.onMessage("ping", () => {
      dispatchedAfterStop++;
    });

    const peer = await manager.connectPeer("127.0.0.1", mockServer1.port);
    await waitFor(() => peer.state === "connected");

    // Sanity: handler fires BEFORE stop().
    mockServer1.send({ type: "ping", payload: { nonce: 1n } });
    await waitFor(() => dispatchedAfterStop > 0);
    expect(dispatchedAfterStop).toBe(1);

    // Begin shutdown.
    await manager.stop();

    // After stop(), any further dispatch attempts must be no-ops.  Simulate
    // the production race by directly invoking the public message-handling
    // path (the buffered-data pathway in real life) — handler must NOT fire.
    // We use the "ping" handler as a proxy for the headers handler in
    // headers.ts; the gate is in handlePeerMessage which is type-agnostic.
    const before = dispatchedAfterStop;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (manager as any).handlePeerMessage(peer, {
      type: "ping",
      payload: { nonce: 2n },
    });
    expect(dispatchedAfterStop).toBe(before); // Still 1, not 2.
  }, TEST_TIMEOUT);
});

describe("PeerManager address persistence", () => {
  let tempDir: string;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "hotbuns-test-"));
  });

  afterEach(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  test("saves and loads addresses on stop/start", async () => {
    const mockServer = new MockPeerServer();
    await mockServer.start();
    mockServer.autoHandshake();

    const config: PeerManagerConfig = {
      maxOutbound: 8,
      maxInbound: 117,
      params: REGTEST,
      bestHeight: 0,
      datadir: tempDir,
    };

    // First manager: connect and stop
    const manager1 = new PeerManager(config);
    const peer = await manager1.connectPeer("127.0.0.1", mockServer.port);
    await waitFor(() => peer.state === "connected");
    await manager1.stop();

    mockServer.stop();

    // Second manager: should load saved addresses
    const manager2 = new PeerManager(config);
    await manager2.start();

    const addresses = manager2.getKnownAddresses();
    const key = `127.0.0.1:${mockServer.port}`;

    expect(addresses.has(key)).toBe(true);
    const info = addresses.get(key);
    expect(info?.host).toBe("127.0.0.1");
    expect(info?.port).toBe(mockServer.port);

    await manager2.stop();
  }, TEST_TIMEOUT);
});

describe("PeerManager addr message handling", () => {
  let tempDir: string;
  let mockServer: MockPeerServer;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "hotbuns-test-"));
    mockServer = new MockPeerServer();
    await mockServer.start();
  });

  afterEach(async () => {
    mockServer.stop();
    await rm(tempDir, { recursive: true, force: true });
  });

  test("adds addresses from addr message", async () => {
    const config: PeerManagerConfig = {
      maxOutbound: 8,
      maxInbound: 117,
      params: REGTEST,
      bestHeight: 0,
      datadir: tempDir,
    };

    mockServer.autoHandshake();

    const manager = new PeerManager(config);
    const peer = await manager.connectPeer("127.0.0.1", mockServer.port);

    await waitFor(() => peer.state === "connected");

    // Send addr message with some addresses
    const now = Math.floor(Date.now() / 1000);
    mockServer.send({
      type: "addr",
      payload: {
        addrs: [
          {
            timestamp: now,
            addr: {
              services: BigInt(ServiceFlags.NODE_NETWORK) | BigInt(ServiceFlags.NODE_WITNESS),
              ip: ipv4ToBuffer("192.168.1.1"),
              port: 8333,
            },
          },
          {
            timestamp: now,
            addr: {
              services: BigInt(ServiceFlags.NODE_NETWORK),
              ip: ipv4ToBuffer("10.0.0.1"),
              port: 8333,
            },
          },
        ],
      },
    });

    // Wait for addresses to be processed
    await waitFor(() => {
      const addresses = manager.getKnownAddresses();
      return addresses.has("192.168.1.1:8333") && addresses.has("10.0.0.1:8333");
    });

    const addresses = manager.getKnownAddresses();
    expect(addresses.has("192.168.1.1:8333")).toBe(true);
    expect(addresses.has("10.0.0.1:8333")).toBe(true);

    await manager.stop();
  }, TEST_TIMEOUT);

  test("ignores old addresses from addr message", async () => {
    const config: PeerManagerConfig = {
      maxOutbound: 8,
      maxInbound: 117,
      params: REGTEST,
      bestHeight: 0,
      datadir: tempDir,
    };

    mockServer.autoHandshake();

    const manager = new PeerManager(config);
    const peer = await manager.connectPeer("127.0.0.1", mockServer.port);

    await waitFor(() => peer.state === "connected");

    // Send addr message with old timestamp (more than 3 hours old)
    const oldTimestamp = Math.floor(Date.now() / 1000) - 4 * 60 * 60;
    mockServer.send({
      type: "addr",
      payload: {
        addrs: [
          {
            timestamp: oldTimestamp,
            addr: {
              services: BigInt(ServiceFlags.NODE_NETWORK),
              ip: ipv4ToBuffer("192.168.2.1"),
              port: 8333,
            },
          },
        ],
      },
    });

    // Give some time for processing
    await new Promise((r) => setTimeout(r, 100));

    const addresses = manager.getKnownAddresses();
    expect(addresses.has("192.168.2.1:8333")).toBe(false);

    await manager.stop();
  }, TEST_TIMEOUT);
});

describe("PeerManager service flags", () => {
  test("ServiceFlags object has correct values", () => {
    expect(BigInt(ServiceFlags.NODE_NETWORK)).toBe(1n);
    expect(BigInt(ServiceFlags.NODE_BLOOM)).toBe(4n);
    expect(BigInt(ServiceFlags.NODE_WITNESS)).toBe(8n);
    expect(BigInt(ServiceFlags.NODE_NETWORK_LIMITED)).toBe(1024n);
  });

  test("BanScores has expected values", () => {
    expect(BanScores.INVALID_MESSAGE).toBe(20);
    expect(BanScores.INVALID_BLOCK).toBe(100);
    expect(BanScores.SLOW_RESPONSE).toBe(2);
    expect(BanScores.PROTOCOL_VIOLATION).toBe(10);
    expect(BanScores.UNREQUESTED_DATA).toBe(5);
  });
});

describe("PeerManager DNS resolution", () => {
  let tempDir: string;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "hotbuns-test-"));
  });

  afterEach(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  test("starts with empty DNS seeds (regtest)", async () => {
    const config: PeerManagerConfig = {
      maxOutbound: 8,
      maxInbound: 117,
      params: REGTEST, // Regtest has no DNS seeds
      bestHeight: 0,
      datadir: tempDir,
    };

    const manager = new PeerManager(config);
    await manager.start();

    // Regtest has no DNS seeds or fallback peers, so no addresses
    const addresses = manager.getKnownAddresses();
    expect(addresses.size).toBe(0);

    await manager.stop();
  }, TEST_TIMEOUT);
});

describe("PeerManager connection lifecycle", () => {
  let tempDir: string;
  let mockServer: MockPeerServer;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "hotbuns-test-"));
    mockServer = new MockPeerServer();
    await mockServer.start();
  });

  afterEach(async () => {
    mockServer.stop();
    await rm(tempDir, { recursive: true, force: true });
  });

  test("handles peer disconnect event", async () => {
    const config: PeerManagerConfig = {
      maxOutbound: 8,
      maxInbound: 117,
      params: REGTEST,
      bestHeight: 0,
      datadir: tempDir,
    };

    mockServer.autoHandshake();

    const manager = new PeerManager(config);
    const peer = await manager.connectPeer("127.0.0.1", mockServer.port);

    let disconnectCalled = false;
    manager.onMessage("__disconnect__", () => {
      disconnectCalled = true;
    });

    await waitFor(() => peer.state === "connected");

    // Server closes connection
    mockServer.stop();

    await waitFor(() => peer.state === "disconnected");
    await waitFor(() => disconnectCalled);

    expect(disconnectCalled).toBe(true);
    expect(manager.getConnectedPeers()).toHaveLength(0);

    await manager.stop();
  }, TEST_TIMEOUT);

  test("handles handshake complete event", async () => {
    const config: PeerManagerConfig = {
      maxOutbound: 8,
      maxInbound: 117,
      params: REGTEST,
      bestHeight: 0,
      datadir: tempDir,
    };

    mockServer.autoHandshake();

    const manager = new PeerManager(config);

    let connectCalled = false;
    manager.onMessage("__connect__", () => {
      connectCalled = true;
    });

    const peer = await manager.connectPeer("127.0.0.1", mockServer.port);

    await waitFor(() => peer.state === "connected");
    await waitFor(() => connectCalled);

    expect(connectCalled).toBe(true);

    await manager.stop();
  }, TEST_TIMEOUT);
});
