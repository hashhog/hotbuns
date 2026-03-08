/**
 * Tests for the Peer class.
 *
 * Uses Bun.listen to create a mock TCP server that simulates
 * a Bitcoin peer, performing handshakes and exchanging messages.
 */

import { describe, expect, test, beforeEach, afterEach } from "bun:test";
import type { TCPSocketListener, Socket } from "bun";
import { Peer, type PeerConfig, type PeerEvents } from "./peer.js";
import {
  type NetworkMessage,
  type VersionPayload,
  MESSAGE_HEADER_SIZE,
  parseHeader,
  deserializeMessage,
  serializeMessage,
  ipv4ToBuffer,
} from "./messages.js";
import { REGTEST } from "../consensus/params.js";

/** Test timeout in ms */
const TEST_TIMEOUT = 5000;

/** Default mock peer config for tests */
function createTestConfig(port: number): PeerConfig {
  return {
    host: "127.0.0.1",
    port,
    magic: REGTEST.networkMagic,
    protocolVersion: 70016,
    services: 0n,
    userAgent: "/test:0.0.1/",
    bestHeight: 0,
    relay: true,
  };
}

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
      port: 0, // Let OS pick a port
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

  /** Send version message (as if we are a peer) */
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

  /** Perform full handshake automatically */
  autoHandshake(): void {
    this.onMessage = (msg) => {
      if (msg.type === "version") {
        this.sendVersion();
        this.sendVerack();
      }
    };
  }

  /** Create ping message */
  sendPing(nonce: bigint): void {
    this.send({ type: "ping", payload: { nonce } });
  }

  /** Create pong message */
  sendPong(nonce: bigint): void {
    this.send({ type: "pong", payload: { nonce } });
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

describe("Peer", () => {
  let mockServer: MockPeerServer;

  beforeEach(async () => {
    mockServer = new MockPeerServer();
    await mockServer.start();
  });

  afterEach(() => {
    mockServer.stop();
  });

  test("connects to peer and sends version message", async () => {
    const config = createTestConfig(mockServer.port);

    let connected = false;
    let handshakeComplete = false;

    const events: PeerEvents = {
      onConnect: () => { connected = true; },
      onDisconnect: () => {},
      onMessage: () => {},
      onHandshakeComplete: () => { handshakeComplete = true; },
    };

    // Set up auto-handshake on server
    mockServer.autoHandshake();

    const peer = new Peer(config, events);
    await peer.connect();

    // Wait for version message to be received
    await waitFor(() => mockServer.receivedMessages.some((m) => m.type === "version"));

    expect(connected).toBe(true);
    expect(peer.state).toBe("connected");
    expect(handshakeComplete).toBe(true);

    // Verify version message was sent
    const versionMsg = mockServer.receivedMessages.find((m) => m.type === "version");
    expect(versionMsg).toBeDefined();
    expect(versionMsg?.type).toBe("version");
    if (versionMsg?.type === "version") {
      expect(versionMsg.payload.userAgent).toBe("/test:0.0.1/");
      expect(versionMsg.payload.version).toBe(70016);
    }

    peer.disconnect();
  }, TEST_TIMEOUT);

  test("stores remote peer version payload after handshake", async () => {
    const config = createTestConfig(mockServer.port);

    let storedVersion: VersionPayload | null = null;

    const events: PeerEvents = {
      onConnect: () => {},
      onDisconnect: () => {},
      onMessage: () => {},
      onHandshakeComplete: (peer) => {
        storedVersion = peer.versionPayload;
      },
    };

    mockServer.autoHandshake();

    const peer = new Peer(config, events);
    await peer.connect();

    // Wait for handshake
    await waitFor(() => peer.state === "connected");

    expect(storedVersion).not.toBeNull();
    expect(storedVersion!.userAgent).toBe("/mock-peer:0.0.1/");
    expect(storedVersion!.startHeight).toBe(850000);

    peer.disconnect();
  }, TEST_TIMEOUT);

  test("sends verack after receiving version", async () => {
    const config = createTestConfig(mockServer.port);

    const events: PeerEvents = {
      onConnect: () => {},
      onDisconnect: () => {},
      onMessage: () => {},
      onHandshakeComplete: () => {},
    };

    mockServer.autoHandshake();

    const peer = new Peer(config, events);
    await peer.connect();

    // Wait for verack to be received by server
    await waitFor(() => mockServer.receivedMessages.some((m) => m.type === "verack"));

    const verackMsg = mockServer.receivedMessages.find((m) => m.type === "verack");
    expect(verackMsg).toBeDefined();
    expect(verackMsg?.type).toBe("verack");

    peer.disconnect();
  }, TEST_TIMEOUT);

  test("ping/pong measures latency", async () => {
    const config = createTestConfig(mockServer.port);

    const messagesReceived: NetworkMessage[] = [];

    const events: PeerEvents = {
      onConnect: () => {},
      onDisconnect: () => {},
      onMessage: (_peer, msg) => {
        messagesReceived.push(msg);
      },
      onHandshakeComplete: () => {},
    };

    // Auto-handshake, then respond to ping with pong
    mockServer.onMessage = (msg) => {
      if (msg.type === "version") {
        mockServer.sendVersion();
        mockServer.sendVerack();
      } else if (msg.type === "ping") {
        // Echo back the nonce as pong
        mockServer.sendPong(msg.payload.nonce);
      }
    };

    const peer = new Peer(config, events);
    await peer.connect();

    // Wait for handshake
    await waitFor(() => peer.state === "connected");

    // Send ping
    const beforePing = Date.now();
    peer.sendPing();

    // Wait for pong response
    await waitFor(() => messagesReceived.some((m) => m.type === "pong"));

    const afterPong = Date.now();

    // Latency should be set and reasonable
    expect(peer.latency).toBeGreaterThanOrEqual(0);
    expect(peer.latency).toBeLessThanOrEqual(afterPong - beforePing + 100);

    peer.disconnect();
  }, TEST_TIMEOUT);

  test("sends feature negotiation messages after handshake", async () => {
    const config = createTestConfig(mockServer.port);

    const events: PeerEvents = {
      onConnect: () => {},
      onDisconnect: () => {},
      onMessage: () => {},
      onHandshakeComplete: () => {},
    };

    mockServer.autoHandshake();

    const peer = new Peer(config, events);
    await peer.connect();

    // Wait for handshake and feature messages
    await waitFor(() =>
      mockServer.receivedMessages.some((m) => m.type === "sendheaders") &&
      mockServer.receivedMessages.some((m) => m.type === "sendaddrv2") &&
      mockServer.receivedMessages.some((m) => m.type === "wtxidrelay")
    );

    expect(mockServer.receivedMessages.some((m) => m.type === "sendheaders")).toBe(true);
    expect(mockServer.receivedMessages.some((m) => m.type === "sendaddrv2")).toBe(true);
    expect(mockServer.receivedMessages.some((m) => m.type === "wtxidrelay")).toBe(true);

    peer.disconnect();
  }, TEST_TIMEOUT);

  test("disconnect sets state to disconnected", async () => {
    const config = createTestConfig(mockServer.port);

    let disconnected = false;

    const events: PeerEvents = {
      onConnect: () => {},
      onDisconnect: () => { disconnected = true; },
      onMessage: () => {},
      onHandshakeComplete: () => {},
    };

    mockServer.autoHandshake();

    const peer = new Peer(config, events);
    await peer.connect();

    // Wait for handshake
    await waitFor(() => peer.state === "connected");

    peer.disconnect("test disconnect");

    expect(peer.state).toBe("disconnected");
    expect(disconnected).toBe(true);
  }, TEST_TIMEOUT);

  test("handles partial message delivery (TCP framing)", async () => {
    // This test simulates partial TCP reads by having the server
    // send messages byte-by-byte
    const config = createTestConfig(mockServer.port);

    let handshakeComplete = false;

    const events: PeerEvents = {
      onConnect: () => {},
      onDisconnect: () => {},
      onMessage: () => {},
      onHandshakeComplete: () => { handshakeComplete = true; },
    };

    // Custom handler that sends version in chunks
    mockServer.onMessage = (msg) => {
      if (msg.type === "version") {
        // Send version message in small chunks
        const versionData = serializeMessage(REGTEST.networkMagic, {
          type: "version",
          payload: {
            version: 70016,
            services: 0n,
            timestamp: BigInt(Math.floor(Date.now() / 1000)),
            addrRecv: { services: 0n, ip: ipv4ToBuffer("127.0.0.1"), port: 0 },
            addrFrom: { services: 0n, ip: ipv4ToBuffer("127.0.0.1"), port: 0 },
            nonce: 12345n,
            userAgent: "/chunked:0.0.1/",
            startHeight: 100,
            relay: true,
          },
        });

        const socket = mockServer.clientSocket;
        if (socket) {
          // Send header only first
          socket.write(versionData.subarray(0, 24));
          // Then payload after a short delay
          setTimeout(() => {
            socket.write(versionData.subarray(24));
            // Then send verack
            mockServer.sendVerack();
          }, 50);
        }
      }
    };

    const peer = new Peer(config, events);
    await peer.connect();

    // Wait for handshake with timeout
    await waitFor(() => handshakeComplete, 2000);

    expect(handshakeComplete).toBe(true);
    expect(peer.state).toBe("connected");
    expect(peer.versionPayload?.userAgent).toBe("/chunked:0.0.1/");

    peer.disconnect();
  }, TEST_TIMEOUT);

  test("dispatches messages to onMessage after handshake", async () => {
    const config = createTestConfig(mockServer.port);

    const messagesReceived: NetworkMessage[] = [];

    const events: PeerEvents = {
      onConnect: () => {},
      onDisconnect: () => {},
      onMessage: (_peer, msg) => {
        messagesReceived.push(msg);
      },
      onHandshakeComplete: () => {},
    };

    mockServer.autoHandshake();

    const peer = new Peer(config, events);
    await peer.connect();

    // Wait for handshake
    await waitFor(() => peer.state === "connected");

    // Server sends a ping
    const testNonce = 999999n;
    mockServer.sendPing(testNonce);

    // Wait for message
    await waitFor(() => messagesReceived.some((m) => m.type === "ping"));

    const pingMsg = messagesReceived.find((m) => m.type === "ping");
    expect(pingMsg).toBeDefined();
    if (pingMsg?.type === "ping") {
      expect(pingMsg.payload.nonce).toBe(testNonce);
    }

    peer.disconnect();
  }, TEST_TIMEOUT);

  test("handles multiple messages in single TCP packet", async () => {
    const config = createTestConfig(mockServer.port);

    const messagesReceived: NetworkMessage[] = [];

    const events: PeerEvents = {
      onConnect: () => {},
      onDisconnect: () => {},
      onMessage: (_peer, msg) => {
        messagesReceived.push(msg);
      },
      onHandshakeComplete: () => {},
    };

    mockServer.autoHandshake();

    const peer = new Peer(config, events);
    await peer.connect();

    // Wait for handshake
    await waitFor(() => peer.state === "connected");

    // Send multiple messages concatenated in one write
    const ping1 = serializeMessage(REGTEST.networkMagic, {
      type: "ping",
      payload: { nonce: 111n },
    });
    const ping2 = serializeMessage(REGTEST.networkMagic, {
      type: "ping",
      payload: { nonce: 222n },
    });
    const ping3 = serializeMessage(REGTEST.networkMagic, {
      type: "ping",
      payload: { nonce: 333n },
    });

    const socket = mockServer.clientSocket;
    if (socket) {
      socket.write(Buffer.concat([ping1, ping2, ping3]));
    }

    // Wait for all messages
    await waitFor(() => {
      const pings = messagesReceived.filter((m) => m.type === "ping");
      return pings.length >= 3;
    });

    const pings = messagesReceived.filter((m) => m.type === "ping");
    expect(pings.length).toBe(3);

    peer.disconnect();
  }, TEST_TIMEOUT);
});

describe("Peer error handling", () => {
  test("disconnects on invalid magic", async () => {
    const mockServer = new MockPeerServer(REGTEST.networkMagic);
    await mockServer.start();

    // Config with different magic than server will send
    const config: PeerConfig = {
      host: "127.0.0.1",
      port: mockServer.port,
      magic: 0x12345678, // Wrong magic
      protocolVersion: 70016,
      services: 0n,
      userAgent: "/test/",
      bestHeight: 0,
      relay: true,
    };

    let disconnected = false;

    const events: PeerEvents = {
      onConnect: () => {},
      onDisconnect: () => {
        disconnected = true;
      },
      onMessage: () => {},
      onHandshakeComplete: () => {},
    };

    // Server sends version with REGTEST magic
    mockServer.onMessage = (msg) => {
      if (msg.type === "version") {
        mockServer.sendVersion();
      }
    };

    const peer = new Peer(config, events);
    await peer.connect();

    // Wait for disconnect
    await waitFor(() => peer.state === "disconnected");

    expect(peer.state).toBe("disconnected");
    expect(disconnected).toBe(true);
    mockServer.stop();
  }, TEST_TIMEOUT);

  test("handles connection refused", async () => {
    const config: PeerConfig = {
      host: "127.0.0.1",
      port: 1, // Port 1 should be refused
      magic: REGTEST.networkMagic,
      protocolVersion: 70016,
      services: 0n,
      userAgent: "/test/",
      bestHeight: 0,
      relay: true,
    };

    let disconnected = false;

    const events: PeerEvents = {
      onConnect: () => {},
      onDisconnect: () => {
        disconnected = true;
      },
      onMessage: () => {},
      onHandshakeComplete: () => {},
    };

    const peer = new Peer(config, events);

    try {
      await peer.connect();
      // If connect doesn't throw, wait for disconnect event
      await waitFor(() => peer.state === "disconnected", 1000);
    } catch {
      // Connection might throw immediately
    }

    expect(peer.state).toBe("disconnected");
  }, TEST_TIMEOUT);
});
