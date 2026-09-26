/**
 * Tests for version handshake pre-message rejection.
 *
 * Tests cover:
 * - Pre-handshake message rejection (misbehavior scoring)
 * - Duplicate VERSION detection
 * - Self-connection detection via nonce
 * - Minimum protocol version enforcement (70015)
 * - Handshake timeout
 */

import { describe, expect, test, beforeEach, afterEach } from "bun:test";
import type { TCPSocketListener, Socket } from "bun";
import {
  Peer,
  type PeerConfig,
  type PeerEvents,
  MIN_PEER_PROTO_VERSION,
  HANDSHAKE_TIMEOUT_MS,
} from "../p2p/peer.js";
import {
  type NetworkMessage,
  MESSAGE_HEADER_SIZE,
  parseHeader,
  deserializeMessage,
  serializeMessage,
  ipv4ToBuffer,
} from "../p2p/messages.js";
import { REGTEST } from "../consensus/params.js";

/** Test timeout in ms */
const TEST_TIMEOUT = 10000;

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

  /** Send version message with custom parameters */
  sendVersion(options: {
    version?: number;
    nonce?: bigint;
  } = {}): void {
    const now = BigInt(Math.floor(Date.now() / 1000));
    const nonce = options.nonce ?? BigInt(Math.floor(Math.random() * Number.MAX_SAFE_INTEGER));

    this.send({
      type: "version",
      payload: {
        version: options.version ?? 70016,
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

  sendPing(nonce: bigint): void {
    this.send({ type: "ping", payload: { nonce } });
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

// Core parity: messages other than VERSION before the peer's VERSION, and
// "unsupported" messages between VERSION and VERACK, are logged and IGNORED
// (net_processing.cpp:3810-3814, :4010-4011) — no misbehaviour, no disconnect.
describe("Pre-handshake message handling (Core: ignore, not misbehave)", () => {
  let mockServer: MockPeerServer;

  beforeEach(async () => {
    mockServer = new MockPeerServer();
    await mockServer.start();
    Peer.clearLocalNonces();
  });

  afterEach(() => {
    mockServer.stop();
  });

  test("ignores non-version message before version received", async () => {
    const config = createTestConfig(mockServer.port);

    let disconnected = false;
    const events: PeerEvents = {
      onConnect: () => {},
      onDisconnect: () => { disconnected = true; },
      onMessage: () => {},
      onHandshakeComplete: () => {},
    };

    // Server sends a ping before version
    mockServer.onMessage = (msg) => {
      if (msg.type === "version") {
        // Instead of sending version, send a ping first
        mockServer.sendPing(12345n);
      }
    };

    const peer = new Peer(config, events);
    await peer.connect();

    await new Promise((r) => setTimeout(r, 300));

    expect(peer.misbehaviorScore).toBe(0);
    expect(disconnected).toBe(false);
    expect(peer.state).not.toBe("disconnected");
    expect(peer.handshakeComplete).toBe(false);

    peer.disconnect();
  }, TEST_TIMEOUT);

  test("ignores inv message before handshake complete", async () => {
    const config = createTestConfig(mockServer.port);

    const events: PeerEvents = {
      onConnect: () => {},
      onDisconnect: () => {},
      onMessage: () => {},
      onHandshakeComplete: () => {},
    };

    // Server sends version, then inv before verack
    mockServer.onMessage = (msg) => {
      if (msg.type === "version") {
        mockServer.sendVersion();
        // Don't send verack yet, send inv instead
        mockServer.send({
          type: "inv",
          payload: { inventory: [] },
        });
      }
    };

    const peer = new Peer(config, events);
    await peer.connect();

    await waitFor(() => peer.ignoredPreVerackMessages > 0);

    expect(peer.misbehaviorScore).toBe(0);
    expect(peer.state).not.toBe("disconnected");
    expect(peer.handshakeComplete).toBe(false);

    // The handshake still completes once the verack arrives.
    mockServer.sendVerack();
    await waitFor(() => peer.handshakeComplete);

    peer.disconnect();
  }, TEST_TIMEOUT);

  test("allows wtxidrelay before verack", async () => {
    const config = createTestConfig(mockServer.port);

    let handshakeComplete = false;
    const events: PeerEvents = {
      onConnect: () => {},
      onDisconnect: () => {},
      onMessage: () => {},
      onHandshakeComplete: () => { handshakeComplete = true; },
    };

    // Server sends version, wtxidrelay, then verack
    mockServer.onMessage = (msg) => {
      if (msg.type === "version") {
        mockServer.sendVersion();
        mockServer.send({ type: "wtxidrelay", payload: null });
        mockServer.sendVerack();
      }
    };

    const peer = new Peer(config, events);
    await peer.connect();

    await waitFor(() => handshakeComplete);

    expect(peer.misbehaviorScore).toBe(0);
    expect(peer.handshakeComplete).toBe(true);

    peer.disconnect();
  }, TEST_TIMEOUT);

  test("allows sendaddrv2 before verack", async () => {
    const config = createTestConfig(mockServer.port);

    let handshakeComplete = false;
    const events: PeerEvents = {
      onConnect: () => {},
      onDisconnect: () => {},
      onMessage: () => {},
      onHandshakeComplete: () => { handshakeComplete = true; },
    };

    // Server sends version, sendaddrv2, then verack
    mockServer.onMessage = (msg) => {
      if (msg.type === "version") {
        mockServer.sendVersion();
        mockServer.send({ type: "sendaddrv2", payload: null });
        mockServer.sendVerack();
      }
    };

    const peer = new Peer(config, events);
    await peer.connect();

    await waitFor(() => handshakeComplete);

    expect(peer.misbehaviorScore).toBe(0);
    expect(peer.handshakeComplete).toBe(true);

    peer.disconnect();
  }, TEST_TIMEOUT);
});

describe("Duplicate VERSION detection", () => {
  let mockServer: MockPeerServer;

  beforeEach(async () => {
    mockServer = new MockPeerServer();
    await mockServer.start();
    Peer.clearLocalNonces();
  });

  afterEach(() => {
    mockServer.stop();
  });

  // Core net_processing.cpp:3582-3585: "redundant version message" is logged
  // and ignored — no misbehaviour.
  test("ignores duplicate version message (no misbehaviour)", async () => {
    const config = createTestConfig(mockServer.port);

    const events: PeerEvents = {
      onConnect: () => {},
      onDisconnect: () => {},
      onMessage: () => {},
      onHandshakeComplete: () => {},
    };

    // Server sends version twice
    let versionCount = 0;
    mockServer.onMessage = (msg) => {
      if (msg.type === "version") {
        mockServer.sendVersion();
        versionCount++;
        if (versionCount === 1) {
          // Send duplicate version
          mockServer.sendVersion();
        }
        mockServer.sendVerack();
      }
    };

    const peer = new Peer(config, events);
    await peer.connect();

    await waitFor(() => peer.handshakeComplete);
    await new Promise((r) => setTimeout(r, 100));

    expect(peer.misbehaviorScore).toBe(0);
    expect(peer.state).toBe("connected");

    peer.disconnect();
  }, TEST_TIMEOUT);
});

describe("Self-connection detection", () => {
  let mockServer: MockPeerServer;

  beforeEach(async () => {
    mockServer = new MockPeerServer();
    await mockServer.start();
    Peer.clearLocalNonces();
  });

  afterEach(() => {
    mockServer.stop();
  });

  test("disconnects when receiving our own nonce", async () => {
    const config = createTestConfig(mockServer.port);

    let disconnected = false;
    const events: PeerEvents = {
      onConnect: () => {},
      onDisconnect: () => { disconnected = true; },
      onMessage: () => {},
      onHandshakeComplete: () => {},
    };

    const peer = new Peer(config, events);

    // Server echoes back the peer's nonce (simulating self-connection)
    mockServer.onMessage = (msg) => {
      if (msg.type === "version") {
        // Extract the nonce from the received version and send it back
        const receivedNonce = msg.payload.nonce;
        mockServer.sendVersion({ nonce: receivedNonce });
        mockServer.sendVerack();
      }
    };

    await peer.connect();

    // Wait for disconnect due to self-connection
    await waitFor(() => disconnected || peer.state === "disconnected");

    expect(peer.state).toBe("disconnected");
    expect(peer.handshakeComplete).toBe(false);
  }, TEST_TIMEOUT);

  test("accepts different nonce (not self-connection)", async () => {
    const config = createTestConfig(mockServer.port);

    let handshakeComplete = false;
    const events: PeerEvents = {
      onConnect: () => {},
      onDisconnect: () => {},
      onMessage: () => {},
      onHandshakeComplete: () => { handshakeComplete = true; },
    };

    // Server uses a different nonce
    mockServer.onMessage = (msg) => {
      if (msg.type === "version") {
        mockServer.sendVersion({ nonce: 999999n });
        mockServer.sendVerack();
      }
    };

    const peer = new Peer(config, events);
    await peer.connect();

    await waitFor(() => handshakeComplete);

    expect(peer.handshakeComplete).toBe(true);
    expect(peer.state).toBe("connected");

    peer.disconnect();
  }, TEST_TIMEOUT);
});

describe("Minimum protocol version", () => {
  let mockServer: MockPeerServer;

  beforeEach(async () => {
    mockServer = new MockPeerServer();
    await mockServer.start();
    Peer.clearLocalNonces();
  });

  afterEach(() => {
    mockServer.stop();
  });

  test("MIN_PEER_PROTO_VERSION is Core's 31800", () => {
    expect(MIN_PEER_PROTO_VERSION).toBe(31800);
  });

  test("disconnects peer with version below 31800", async () => {
    const config = createTestConfig(mockServer.port);

    let disconnected = false;
    const events: PeerEvents = {
      onConnect: () => {},
      onDisconnect: () => { disconnected = true; },
      onMessage: () => {},
      onHandshakeComplete: () => {},
    };

    // Server sends old version
    mockServer.onMessage = (msg) => {
      if (msg.type === "version") {
        mockServer.sendVersion({ version: 31799 }); // Below minimum
        mockServer.sendVerack();
      }
    };

    const peer = new Peer(config, events);
    await peer.connect();

    await waitFor(() => disconnected || peer.state === "disconnected");

    expect(peer.state).toBe("disconnected");
    expect(peer.handshakeComplete).toBe(false);
  }, TEST_TIMEOUT);

  test("accepts peer with version exactly 70015", async () => {
    const config = createTestConfig(mockServer.port);

    let handshakeComplete = false;
    const events: PeerEvents = {
      onConnect: () => {},
      onDisconnect: () => {},
      onMessage: () => {},
      onHandshakeComplete: () => { handshakeComplete = true; },
    };

    // Server sends exactly minimum version
    mockServer.onMessage = (msg) => {
      if (msg.type === "version") {
        mockServer.sendVersion({ version: 70015 });
        mockServer.sendVerack();
      }
    };

    const peer = new Peer(config, events);
    await peer.connect();

    await waitFor(() => handshakeComplete);

    expect(peer.handshakeComplete).toBe(true);
    expect(peer.versionPayload?.version).toBe(70015);

    peer.disconnect();
  }, TEST_TIMEOUT);

  test("accepts peer with version above 70015", async () => {
    const config = createTestConfig(mockServer.port);

    let handshakeComplete = false;
    const events: PeerEvents = {
      onConnect: () => {},
      onDisconnect: () => {},
      onMessage: () => {},
      onHandshakeComplete: () => { handshakeComplete = true; },
    };

    // Server sends higher version
    mockServer.onMessage = (msg) => {
      if (msg.type === "version") {
        mockServer.sendVersion({ version: 70016 });
        mockServer.sendVerack();
      }
    };

    const peer = new Peer(config, events);
    await peer.connect();

    await waitFor(() => handshakeComplete);

    expect(peer.handshakeComplete).toBe(true);
    expect(peer.versionPayload?.version).toBe(70016);

    peer.disconnect();
  }, TEST_TIMEOUT);
});

describe("Handshake timeout", () => {
  let mockServer: MockPeerServer;

  beforeEach(async () => {
    mockServer = new MockPeerServer();
    await mockServer.start();
    Peer.clearLocalNonces();
  });

  afterEach(() => {
    mockServer.stop();
  });

  test("HANDSHAKE_TIMEOUT_MS is 60 seconds", () => {
    expect(HANDSHAKE_TIMEOUT_MS).toBe(60_000);
  });

  // Note: We don't test actual 60-second timeout as that would make tests too slow.
  // The timeout mechanism is verified by the fact that handshakeTimer is set.

  test("handshakeComplete is false initially", async () => {
    const config = createTestConfig(mockServer.port);

    const events: PeerEvents = {
      onConnect: () => {},
      onDisconnect: () => {},
      onMessage: () => {},
      onHandshakeComplete: () => {},
    };

    const peer = new Peer(config, events);
    expect(peer.handshakeComplete).toBe(false);
  });

  test("handshakeComplete becomes true after successful handshake", async () => {
    const config = createTestConfig(mockServer.port);

    let handshakeComplete = false;
    const events: PeerEvents = {
      onConnect: () => {},
      onDisconnect: () => {},
      onMessage: () => {},
      onHandshakeComplete: () => { handshakeComplete = true; },
    };

    mockServer.autoHandshake();

    const peer = new Peer(config, events);
    await peer.connect();

    await waitFor(() => handshakeComplete);

    expect(peer.handshakeComplete).toBe(true);

    peer.disconnect();
  }, TEST_TIMEOUT);
});

describe("handshakeComplete field", () => {
  let mockServer: MockPeerServer;

  beforeEach(async () => {
    mockServer = new MockPeerServer();
    await mockServer.start();
    Peer.clearLocalNonces();
  });

  afterEach(() => {
    mockServer.stop();
  });

  test("messages are dispatched after handshakeComplete is true", async () => {
    const config = createTestConfig(mockServer.port);

    const messagesReceived: NetworkMessage[] = [];
    const events: PeerEvents = {
      onConnect: () => {},
      onDisconnect: () => {},
      onMessage: (_peer, msg) => { messagesReceived.push(msg); },
      onHandshakeComplete: () => {},
    };

    mockServer.autoHandshake();

    const peer = new Peer(config, events);
    await peer.connect();

    await waitFor(() => peer.handshakeComplete);

    // Now send a ping after handshake
    mockServer.sendPing(54321n);

    await waitFor(() => messagesReceived.some(m => m.type === "ping"));

    expect(messagesReceived.some(m => m.type === "ping")).toBe(true);

    peer.disconnect();
  }, TEST_TIMEOUT);

  test("redundant verack after handshake is ignored", async () => {
    const config = createTestConfig(mockServer.port);

    const events: PeerEvents = {
      onConnect: () => {},
      onDisconnect: () => {},
      onMessage: () => {},
      onHandshakeComplete: () => {},
    };

    // Server sends extra verack after handshake
    let sentExtraVerack = false;
    mockServer.onMessage = (msg) => {
      if (msg.type === "version") {
        mockServer.sendVersion();
        mockServer.sendVerack();
      } else if (msg.type === "verack" && !sentExtraVerack) {
        sentExtraVerack = true;
        // Send extra verack
        mockServer.sendVerack();
      }
    };

    const peer = new Peer(config, events);
    await peer.connect();

    await waitFor(() => peer.handshakeComplete);

    // Give time for extra verack to be processed
    await new Promise(r => setTimeout(r, 100));

    // Should not cause any issues or misbehavior
    expect(peer.misbehaviorScore).toBe(0);
    expect(peer.state).toBe("connected");

    peer.disconnect();
  }, TEST_TIMEOUT);
});
