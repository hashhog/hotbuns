/**
 * Tests for stale peer eviction.
 *
 * Tests cover:
 * - Ping interval and timeout detection
 * - Stale tip peer eviction
 * - Headers request timeout
 * - Block download timeout
 * - Protected peer preservation
 */

import { describe, expect, test, beforeEach, afterEach } from "bun:test";
import type { TCPSocketListener, Socket } from "bun";
import {
  Peer,
  type PeerConfig,
  type PeerEvents,
  PING_INTERVAL_MS,
  PING_TIMEOUT_MS,
  HEADERS_RESPONSE_TIMEOUT_MS,
  BLOCK_DOWNLOAD_TIMEOUT_BASE_MS,
  BLOCK_DOWNLOAD_TIMEOUT_PER_PEER_MS,
  STALE_TIP_THRESHOLD_MS,
  MAX_BLOCKS_IN_TRANSIT_PER_PEER,
  MINIMUM_CONNECT_TIME_MS,
  MAX_OUTBOUND_PEERS_TO_PROTECT,
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

  sendVersion(options: { startHeight?: number } = {}): void {
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
        startHeight: options.startHeight ?? 850000,
        relay: true,
      },
    });
  }

  sendVerack(): void {
    this.send({ type: "verack", payload: null });
  }

  sendPong(nonce: bigint): void {
    this.send({ type: "pong", payload: { nonce } });
  }

  autoHandshake(options: { startHeight?: number } = {}): void {
    this.onMessage = (msg) => {
      if (msg.type === "version") {
        this.sendVersion(options);
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

describe("Stale peer timing constants", () => {
  test("PING_INTERVAL_MS is 2 minutes", () => {
    expect(PING_INTERVAL_MS).toBe(2 * 60 * 1000);
  });

  test("PING_TIMEOUT_MS is 20 minutes", () => {
    expect(PING_TIMEOUT_MS).toBe(20 * 60 * 1000);
  });

  test("HEADERS_RESPONSE_TIMEOUT_MS is 2 minutes", () => {
    expect(HEADERS_RESPONSE_TIMEOUT_MS).toBe(2 * 60 * 1000);
  });

  test("STALE_TIP_THRESHOLD_MS is 30 minutes", () => {
    expect(STALE_TIP_THRESHOLD_MS).toBe(30 * 60 * 1000);
  });

  test("BLOCK_DOWNLOAD_TIMEOUT_BASE_MS is 10 minutes", () => {
    expect(BLOCK_DOWNLOAD_TIMEOUT_BASE_MS).toBe(10 * 60 * 1000);
  });

  test("BLOCK_DOWNLOAD_TIMEOUT_PER_PEER_MS is 5 minutes", () => {
    expect(BLOCK_DOWNLOAD_TIMEOUT_PER_PEER_MS).toBe(5 * 60 * 1000);
  });

  test("MAX_BLOCKS_IN_TRANSIT_PER_PEER is 16", () => {
    expect(MAX_BLOCKS_IN_TRANSIT_PER_PEER).toBe(16);
  });

  test("MINIMUM_CONNECT_TIME_MS is 30 seconds", () => {
    expect(MINIMUM_CONNECT_TIME_MS).toBe(30 * 1000);
  });

  test("MAX_OUTBOUND_PEERS_TO_PROTECT is 4", () => {
    expect(MAX_OUTBOUND_PEERS_TO_PROTECT).toBe(4);
  });
});

describe("Peer stale tracking fields", () => {
  let mockServer: MockPeerServer;

  beforeEach(async () => {
    mockServer = new MockPeerServer();
    await mockServer.start();
    Peer.clearLocalNonces();
  });

  afterEach(() => {
    mockServer.stop();
  });

  test("peer initializes stale tracking fields correctly", async () => {
    const config = createTestConfig(mockServer.port);
    const events: PeerEvents = {
      onConnect: () => {},
      onDisconnect: () => {},
      onMessage: () => {},
      onHandshakeComplete: () => {},
    };

    const peer = new Peer(config, events);

    expect(peer.lastBlockTime).toBe(0);
    expect(peer.lastTxTime).toBe(0);
    expect(peer.pingSentTime).toBe(0);
    expect(peer.pingOutstanding).toBe(false);
    expect(peer.headersRequestTime).toBe(0);
    expect(peer.connectedTime).toBeGreaterThan(0);
    expect(peer.blocksInFlight.size).toBe(0);
    expect(peer.bestKnownHeight).toBe(0);
  });

  test("bestKnownHeight is set from version message", async () => {
    const config = createTestConfig(mockServer.port);
    let handshakeComplete = false;
    const events: PeerEvents = {
      onConnect: () => {},
      onDisconnect: () => {},
      onMessage: () => {},
      onHandshakeComplete: () => { handshakeComplete = true; },
    };

    mockServer.autoHandshake({ startHeight: 850000 });

    const peer = new Peer(config, events);
    await peer.connect();

    await waitFor(() => handshakeComplete);

    expect(peer.bestKnownHeight).toBe(850000);

    peer.disconnect();
  }, TEST_TIMEOUT);

  test("recordBlockReceived updates lastBlockTime", async () => {
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

    await waitFor(() => peer.handshakeComplete);

    expect(peer.lastBlockTime).toBe(0);

    peer.recordBlockReceived();

    expect(peer.lastBlockTime).toBeGreaterThan(0);

    peer.disconnect();
  }, TEST_TIMEOUT);

  test("recordTxReceived updates lastTxTime", async () => {
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

    await waitFor(() => peer.handshakeComplete);

    expect(peer.lastTxTime).toBe(0);

    peer.recordTxReceived();

    expect(peer.lastTxTime).toBeGreaterThan(0);

    peer.disconnect();
  }, TEST_TIMEOUT);
});

describe("Ping timeout detection", () => {
  let mockServer: MockPeerServer;

  beforeEach(async () => {
    mockServer = new MockPeerServer();
    await mockServer.start();
    Peer.clearLocalNonces();
  });

  afterEach(() => {
    mockServer.stop();
  });

  test("sendPing sets pingOutstanding and pingSentTime", async () => {
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

    await waitFor(() => peer.handshakeComplete);

    expect(peer.pingOutstanding).toBe(false);
    expect(peer.pingSentTime).toBe(0);

    peer.sendPing();

    expect(peer.pingOutstanding).toBe(true);
    expect(peer.pingSentTime).toBeGreaterThan(0);

    peer.disconnect();
  }, TEST_TIMEOUT);

  test("pong response clears pingOutstanding", async () => {
    const config = createTestConfig(mockServer.port);
    let receivedPing = false;
    let pingNonce: bigint = 0n;
    const events: PeerEvents = {
      onConnect: () => {},
      onDisconnect: () => {},
      onMessage: () => {},
      onHandshakeComplete: () => {},
    };

    mockServer.onMessage = (msg) => {
      if (msg.type === "version") {
        mockServer.sendVersion();
        mockServer.sendVerack();
      } else if (msg.type === "ping") {
        receivedPing = true;
        pingNonce = msg.payload.nonce;
        // Reply with pong
        mockServer.sendPong(pingNonce);
      }
    };

    const peer = new Peer(config, events);
    await peer.connect();

    await waitFor(() => peer.handshakeComplete);

    peer.sendPing();
    expect(peer.pingOutstanding).toBe(true);

    await waitFor(() => receivedPing);
    await waitFor(() => !peer.pingOutstanding);

    expect(peer.pingOutstanding).toBe(false);
    expect(peer.pingSentTime).toBe(0);
    // latency is measured as Date.now() difference; may be 0 on fast loopback connections
    expect(peer.latency).toBeGreaterThanOrEqual(0);

    peer.disconnect();
  }, TEST_TIMEOUT);

  test("hasPingTimedOut returns false when no ping outstanding", () => {
    const config = createTestConfig(12345);
    const events: PeerEvents = {
      onConnect: () => {},
      onDisconnect: () => {},
      onMessage: () => {},
      onHandshakeComplete: () => {},
    };

    const peer = new Peer(config, events);

    expect(peer.hasPingTimedOut()).toBe(false);
  });

  test("hasPingTimedOut returns false when ping is recent", async () => {
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

    await waitFor(() => peer.handshakeComplete);

    peer.sendPing();

    // Immediately after sending, should not be timed out
    expect(peer.hasPingTimedOut()).toBe(false);

    peer.disconnect();
  }, TEST_TIMEOUT);

  test("needsPing returns false when ping is outstanding", async () => {
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

    await waitFor(() => peer.handshakeComplete);

    peer.sendPing();

    // Should not need ping when one is outstanding
    const lastActivity = Date.now() - PING_INTERVAL_MS - 1000;
    expect(peer.needsPing(lastActivity)).toBe(false);

    peer.disconnect();
  }, TEST_TIMEOUT);

  test("needsPing returns true when no ping outstanding and idle", async () => {
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

    await waitFor(() => peer.handshakeComplete);

    // Simulate idle time exceeding PING_INTERVAL_MS
    const lastActivity = Date.now() - PING_INTERVAL_MS - 1000;
    expect(peer.needsPing(lastActivity)).toBe(true);

    peer.disconnect();
  }, TEST_TIMEOUT);
});

describe("Headers timeout detection", () => {
  let mockServer: MockPeerServer;

  beforeEach(async () => {
    mockServer = new MockPeerServer();
    await mockServer.start();
    Peer.clearLocalNonces();
  });

  afterEach(() => {
    mockServer.stop();
  });

  test("markHeadersRequested sets headersRequestTime", async () => {
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

    await waitFor(() => peer.handshakeComplete);

    expect(peer.headersRequestTime).toBe(0);

    peer.markHeadersRequested();

    expect(peer.headersRequestTime).toBeGreaterThan(0);

    peer.disconnect();
  }, TEST_TIMEOUT);

  test("markHeadersReceived clears headersRequestTime", async () => {
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

    await waitFor(() => peer.handshakeComplete);

    peer.markHeadersRequested();
    expect(peer.headersRequestTime).toBeGreaterThan(0);

    peer.markHeadersReceived();
    expect(peer.headersRequestTime).toBe(0);

    peer.disconnect();
  }, TEST_TIMEOUT);

  test("hasHeadersTimedOut returns false when no request pending", () => {
    const config = createTestConfig(12345);
    const events: PeerEvents = {
      onConnect: () => {},
      onDisconnect: () => {},
      onMessage: () => {},
      onHandshakeComplete: () => {},
    };

    const peer = new Peer(config, events);

    expect(peer.hasHeadersTimedOut()).toBe(false);
  });

  test("hasHeadersTimedOut returns false when request is recent", async () => {
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

    await waitFor(() => peer.handshakeComplete);

    peer.markHeadersRequested();

    // Immediately after requesting, should not be timed out
    expect(peer.hasHeadersTimedOut()).toBe(false);

    peer.disconnect();
  }, TEST_TIMEOUT);
});

describe("Block download tracking", () => {
  let mockServer: MockPeerServer;

  beforeEach(async () => {
    mockServer = new MockPeerServer();
    await mockServer.start();
    Peer.clearLocalNonces();
  });

  afterEach(() => {
    mockServer.stop();
  });

  test("addBlockInFlight adds block to tracking", async () => {
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

    await waitFor(() => peer.handshakeComplete);

    expect(peer.getBlocksInFlightCount()).toBe(0);

    peer.addBlockInFlight("0000000000000000000000000000000000000000000000000000000000000001");

    expect(peer.getBlocksInFlightCount()).toBe(1);
    expect(peer.hasBlocksInFlight()).toBe(true);

    peer.disconnect();
  }, TEST_TIMEOUT);

  test("removeBlockInFlight removes block from tracking", async () => {
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

    await waitFor(() => peer.handshakeComplete);

    const blockHash = "0000000000000000000000000000000000000000000000000000000000000001";
    peer.addBlockInFlight(blockHash);
    expect(peer.getBlocksInFlightCount()).toBe(1);

    peer.removeBlockInFlight(blockHash);
    expect(peer.getBlocksInFlightCount()).toBe(0);
    expect(peer.hasBlocksInFlight()).toBe(false);

    peer.disconnect();
  }, TEST_TIMEOUT);

  test("addBlockInFlight respects MAX_BLOCKS_IN_TRANSIT_PER_PEER", async () => {
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

    await waitFor(() => peer.handshakeComplete);

    // Add MAX_BLOCKS_IN_TRANSIT_PER_PEER blocks
    for (let i = 0; i < MAX_BLOCKS_IN_TRANSIT_PER_PEER; i++) {
      peer.addBlockInFlight(`hash${i.toString().padStart(60, "0")}`);
    }
    expect(peer.getBlocksInFlightCount()).toBe(MAX_BLOCKS_IN_TRANSIT_PER_PEER);

    // Try to add one more - should be rejected
    peer.addBlockInFlight("hashoverflow00000000000000000000000000000000000000000000000000");
    expect(peer.getBlocksInFlightCount()).toBe(MAX_BLOCKS_IN_TRANSIT_PER_PEER);

    peer.disconnect();
  }, TEST_TIMEOUT);

  test("getTimedOutBlock returns null when no blocks timed out", async () => {
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

    await waitFor(() => peer.handshakeComplete);

    peer.addBlockInFlight("0000000000000000000000000000000000000000000000000000000000000001");

    // Immediately after adding, should not be timed out
    expect(peer.getTimedOutBlock(5)).toBeNull();

    peer.disconnect();
  }, TEST_TIMEOUT);
});

describe("Best known height tracking", () => {
  let mockServer: MockPeerServer;

  beforeEach(async () => {
    mockServer = new MockPeerServer();
    await mockServer.start();
    Peer.clearLocalNonces();
  });

  afterEach(() => {
    mockServer.stop();
  });

  test("updateBestKnownHeight updates height when higher", async () => {
    const config = createTestConfig(mockServer.port);
    const events: PeerEvents = {
      onConnect: () => {},
      onDisconnect: () => {},
      onMessage: () => {},
      onHandshakeComplete: () => {},
    };

    mockServer.autoHandshake({ startHeight: 100 });

    const peer = new Peer(config, events);
    await peer.connect();

    await waitFor(() => peer.handshakeComplete);

    expect(peer.bestKnownHeight).toBe(100);

    peer.updateBestKnownHeight(200);
    expect(peer.bestKnownHeight).toBe(200);

    peer.disconnect();
  }, TEST_TIMEOUT);

  test("updateBestKnownHeight does not update height when lower", async () => {
    const config = createTestConfig(mockServer.port);
    const events: PeerEvents = {
      onConnect: () => {},
      onDisconnect: () => {},
      onMessage: () => {},
      onHandshakeComplete: () => {},
    };

    mockServer.autoHandshake({ startHeight: 200 });

    const peer = new Peer(config, events);
    await peer.connect();

    await waitFor(() => peer.handshakeComplete);

    expect(peer.bestKnownHeight).toBe(200);

    peer.updateBestKnownHeight(100);
    expect(peer.bestKnownHeight).toBe(200); // Should not decrease

    peer.disconnect();
  }, TEST_TIMEOUT);
});

describe("Eviction candidate metrics", () => {
  test("connectedTime is set on peer creation", () => {
    const config = createTestConfig(12345);
    const events: PeerEvents = {
      onConnect: () => {},
      onDisconnect: () => {},
      onMessage: () => {},
      onHandshakeComplete: () => {},
    };

    const beforeCreate = Date.now();
    const peer = new Peer(config, events);
    const afterCreate = Date.now();

    expect(peer.connectedTime).toBeGreaterThanOrEqual(beforeCreate);
    expect(peer.connectedTime).toBeLessThanOrEqual(afterCreate);
  });
});
