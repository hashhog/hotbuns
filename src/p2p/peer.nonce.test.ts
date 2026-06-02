/**
 * Tier-A leak-bound regression: Peer.localNonces released on EVERY disconnect.
 *
 * Root cause: the self-connection nonce is added to the static `localNonces`
 * Set in every Peer constructor but was deleted ONLY inside `disconnect()`. The
 * socket close/error/connectError handlers and the connect-failure catch blocks
 * set state="disconnected" + emit onDisconnect directly, bypassing disconnect(),
 * so every socket-dropped peer and every failed dial leaked one bigint forever.
 * Fix: a private `releaseNonce()` is called from disconnect() AND from all the
 * socket handlers + connect-failure paths (Core FinalizeNode parity).
 * See CORE-PARITY-AUDIT/_hotbuns-rss-leak-rootcause-2026-06-02.md (Tier A.2).
 */

import { describe, expect, test, beforeEach, afterEach } from "bun:test";
import type { TCPSocketListener, Socket } from "bun";
import { Peer, type PeerConfig, type PeerEvents } from "./peer.js";
import { REGTEST } from "../consensus/params.js";

const TEST_TIMEOUT = 5000;

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

function makeNullEvents(): PeerEvents {
  return {
    onMessage: () => {},
    onConnect: () => {},
    onDisconnect: () => {},
    onHandshakeComplete: () => {},
  };
}

/** Minimal TCP server that just accepts and can abruptly drop the connection. */
class DropServer {
  private server: TCPSocketListener<undefined> | null = null;
  private clientSocket: Socket<undefined> | null = null;
  port = 0;

  async start(): Promise<void> {
    this.server = Bun.listen<undefined>({
      hostname: "127.0.0.1",
      port: 0,
      socket: {
        data: (socket) => {
          this.clientSocket = socket;
        },
        open: (socket) => {
          this.clientSocket = socket;
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

  /** Abruptly drop the client connection — triggers the peer's close handler. */
  dropClient(): void {
    if (this.clientSocket) {
      this.clientSocket.end();
      this.clientSocket = null;
    }
  }

  stop(): void {
    this.dropClient();
    if (this.server) {
      this.server.stop();
      this.server = null;
    }
  }
}

async function waitFor(
  condition: () => boolean,
  timeoutMs = 2000
): Promise<void> {
  const start = Date.now();
  while (!condition()) {
    if (Date.now() - start > timeoutMs) {
      throw new Error("waitFor timeout");
    }
    await new Promise((r) => setTimeout(r, 10));
  }
}

describe("Tier A.2: Peer.localNonces release on all disconnect paths", () => {
  let server: DropServer;

  beforeEach(async () => {
    // The localNonces Set is static (process-wide). Reset so each test starts
    // from a known-empty baseline regardless of test ordering.
    Peer.clearLocalNonces();
    server = new DropServer();
    await server.start();
  });

  afterEach(() => {
    server.stop();
    Peer.clearLocalNonces();
  });

  test("nonce is registered on construction", () => {
    expect(Peer.localNoncesSize()).toBe(0);
    const peer = new Peer(createTestConfig(server.port), makeNullEvents());
    expect(Peer.localNoncesSize()).toBe(1);
    peer.disconnect();
  });

  test("clean disconnect() releases the nonce (baseline)", () => {
    const peer = new Peer(createTestConfig(server.port), makeNullEvents());
    expect(Peer.localNoncesSize()).toBe(1);
    peer.disconnect();
    expect(Peer.localNoncesSize()).toBe(0);
  });

  test(
    "socket-drop (server closes) releases the nonce WITHOUT a clean disconnect()",
    async () => {
      const peer = new Peer(createTestConfig(server.port), makeNullEvents());
      await peer.connect();
      expect(Peer.localNoncesSize()).toBe(1);

      // Server abruptly drops the connection — the peer's `close` handler fires
      // (NOT peer.disconnect()). Pre-fix this left the nonce in the set forever.
      server.dropClient();

      await waitFor(() => peer.state === "disconnected");
      expect(Peer.localNoncesSize()).toBe(0);
    },
    TEST_TIMEOUT
  );

  test(
    "failed outbound dial releases the nonce (connectError / timeout path)",
    async () => {
      // Port 1 is reserved/unbound — the dial fails before any handshake.
      const peer = new Peer(createTestConfig(1), makeNullEvents());
      const before = Peer.localNoncesSize();
      expect(before).toBe(1);

      await expect(peer.connect()).rejects.toBeDefined();
      // Give the connectError handler a tick to fire if the rejection came from
      // the timeout race rather than the handler.
      await waitFor(() => Peer.localNoncesSize() === 0);
      expect(Peer.localNoncesSize()).toBe(0);
    },
    TEST_TIMEOUT
  );

  test("many socket-drops do not accumulate nonces", async () => {
    for (let i = 0; i < 20; i++) {
      const peer = new Peer(createTestConfig(server.port), makeNullEvents());
      await peer.connect();
      server.dropClient();
      await waitFor(() => peer.state === "disconnected");
    }
    expect(Peer.localNoncesSize()).toBe(0);
  }, TEST_TIMEOUT);
});
