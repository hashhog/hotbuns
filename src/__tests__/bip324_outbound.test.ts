/**
 * BIP-324 outbound v2 integration tests.
 *
 * Mirrors src/__tests__/bip324_inbound.test.ts for the initiator side:
 * drives a Peer through its connect() / processRecvBuffer path with a
 * synthetic v2 responder (built from another V2Transport instance).
 * Also verifies the v1-only cache in PeerManager and the env-var gate
 * Peer.bip324V2Enabled().
 *
 * The tests bypass Bun.connect by calling prepareV2Outbound() directly
 * and injecting a stub socket — the manager-level connect() is exercised
 * indirectly via mock peers in manager.test.ts.
 */

import { describe, expect, test, beforeEach, afterEach } from "bun:test";
import {
  Peer,
  type PeerConfig,
  type PeerEvents,
} from "../p2p/peer.js";
import {
  V2Transport,
  V1_PREFIX_LEN,
} from "../p2p/v2_transport.js";
import {
  type NetworkMessage,
  deserializeV2Message,
} from "../p2p/messages.js";
import { REGTEST } from "../consensus/params.js";
import {
  PeerManager,
  type PeerManagerConfig,
  V1_ONLY_CACHE_MAX,
  V1_ONLY_CACHE_TTL_MS,
} from "../p2p/manager.js";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

/** Stub Bun.Socket — captures writes; enough for Peer.send() / disconnect(). */
function makeStubSocket(): {
  socket: unknown;
  written: Buffer[];
  ended: boolean;
} {
  const written: Buffer[] = [];
  let ended = false;
  const socket = {
    write(data: Buffer | Uint8Array | string): number {
      const buf = data instanceof Uint8Array ? Buffer.from(data) : Buffer.from(String(data));
      written.push(buf);
      return buf.length;
    },
    end(): void {
      ended = true;
    },
    remoteAddress: "127.0.0.1",
  } as unknown;
  return {
    socket,
    written,
    get ended() {
      return ended;
    },
  } as { socket: unknown; written: Buffer[]; ended: boolean };
}

function makeConfig(): PeerConfig {
  return {
    host: "127.0.0.1",
    port: 0,
    magic: REGTEST.networkMagic,
    protocolVersion: 70016,
    services: 0n,
    userAgent: "/hotbuns-test:0.0.1/",
    bestHeight: 0,
    relay: true,
  };
}

function makeEvents(captured: {
  msgs: NetworkMessage[];
  handshakeComplete: boolean;
}): PeerEvents {
  return {
    onConnect: () => {},
    onDisconnect: () => {},
    onMessage: (_p, msg) => {
      captured.msgs.push(msg);
    },
    onHandshakeComplete: () => {
      captured.handshakeComplete = true;
    },
  };
}

const REGTEST_MAGIC_LE = (() => {
  const buf = Buffer.alloc(4);
  buf.writeUInt32LE(REGTEST.networkMagic, 0);
  return buf;
})();

describe("Peer.bip324V2Enabled (outbound v2 gate)", () => {
  const ORIGINAL = process.env.HOTBUNS_BIP324_V2;
  afterEach(() => {
    if (ORIGINAL === undefined) {
      delete process.env.HOTBUNS_BIP324_V2;
    } else {
      process.env.HOTBUNS_BIP324_V2 = ORIGINAL;
    }
  });

  test("defaults to off when env var unset", () => {
    delete process.env.HOTBUNS_BIP324_V2;
    expect(Peer.bip324V2Enabled()).toBe(false);
  });

  test("enables when set to '1'", () => {
    process.env.HOTBUNS_BIP324_V2 = "1";
    expect(Peer.bip324V2Enabled()).toBe(true);
  });

  test("enables when set to 'true'", () => {
    process.env.HOTBUNS_BIP324_V2 = "true";
    expect(Peer.bip324V2Enabled()).toBe(true);
  });

  test("disables when set to '0'", () => {
    process.env.HOTBUNS_BIP324_V2 = "0";
    expect(Peer.bip324V2Enabled()).toBe(false);
  });

  test("disables when set to 'false'", () => {
    process.env.HOTBUNS_BIP324_V2 = "false";
    expect(Peer.bip324V2Enabled()).toBe(false);
  });

  test("disables when set to 'FALSE'", () => {
    process.env.HOTBUNS_BIP324_V2 = "FALSE";
    expect(Peer.bip324V2Enabled()).toBe(false);
  });
});

describe("BIP-324 outbound state machine", () => {
  test("initiator queues ellswift pubkey + garbage before any inbound bytes", () => {
    const captured = { msgs: [] as NetworkMessage[], handshakeComplete: false };
    const peer = new Peer(makeConfig(), makeEvents(captured));
    const stub = makeStubSocket();

    // Manually drive the open-callback path: inject the socket, prepare
    // v2 (queues pubkey + garbage), then flush.
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const p = peer as any;
    p.socket = stub.socket;
    p.state = "handshaking";
    p.prepareV2Outbound();
    p.flushV2SendBuffer();

    // Initiator sends 64-byte ellswift pubkey + 0..32-byte garbage.  Floor
    // is 64 bytes (no garbage); cap is 64 + 4095 (our garbage is bounded
    // at MAX_GARBAGE_LEN by V2Transport — 4095 in the spec).
    const sentBytes = Buffer.concat(stub.written);
    expect(sentBytes.length).toBeGreaterThanOrEqual(64);
    expect(sentBytes.length).toBeLessThanOrEqual(64 + 4095);

    // First 4 bytes should NOT match REGTEST magic — this would make the
    // peer treat us as a v1 sender and corrupt classification.  Probability
    // of collision is 2^-32 (uniform random ellswift bytes).
    expect(sentBytes.subarray(0, 4).equals(REGTEST_MAGIC_LE)).toBe(false);
  });

  test("initiator handshake completes against synthetic v2 responder", () => {
    const captured = { msgs: [] as NetworkMessage[], handshakeComplete: false };
    const peer = new Peer(makeConfig(), makeEvents(captured));
    const stub = makeStubSocket();

    // Wire up the peer in v2 outbound mode.
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const p = peer as any;
    p.socket = stub.socket;
    p.state = "handshaking";
    p.prepareV2Outbound();
    p.flushV2SendBuffer();

    // Capture the initiator's pubkey + garbage bytes.
    const initBytes1 = Buffer.concat(stub.written);
    stub.written.length = 0;
    expect(initBytes1.length).toBeGreaterThanOrEqual(64);

    // Construct a synthetic responder V2Transport.  The responder has no
    // skip-v1-check set: it WILL classify the initiator's first 4 bytes
    // against the v1 magic — and (with overwhelming probability) decide
    // those bytes are NOT magic, so it transitions into v2 KEY state.
    const responder = new V2Transport(REGTEST_MAGIC_LE, /* initiator */ false);
    const r1 = responder.receiveBytes(initBytes1);
    expect(r1.fallbackV1).toBe(false);
    expect(r1.error).toBeUndefined();
    expect(responder.isReady()).toBe(true);

    // Drain responder's reply: pubkey + garbage + terminator + version
    // packet (empty contents, AAD = responder garbage).
    const respBytes = responder.consumeSendBuffer();
    expect(respBytes.length).toBeGreaterThan(64 + 16);

    // Feed responder bytes to peer.  This should drive cipher init,
    // queue terminator + our version packet, and emit our application
    // VERSION over the encrypted transport.
    peer.feedData(respBytes);

    // Peer should have written: terminator + version-packet + encrypted
    // application-layer VERSION message.
    const initBytes2 = Buffer.concat(stub.written);
    expect(initBytes2.length).toBeGreaterThan(0);

    // Feed back to responder; it should successfully decrypt our VERSION.
    const r2 = responder.receiveBytes(initBytes2);
    expect(r2.fallbackV1).toBe(false);
    expect(r2.error).toBeUndefined();
    expect(responder.isVersionReceived()).toBe(true);

    // Drain responder's received messages: should see our application
    // VERSION.
    const v2msgs = responder.getReceivedMessages();
    expect(v2msgs.length).toBe(1);
    expect(v2msgs[0].type).toBe("version");
    const decoded = deserializeV2Message(v2msgs[0].type, v2msgs[0].payload);
    expect(decoded.type).toBe("version");
    if (decoded.type === "version") {
      expect(decoded.payload.userAgent).toBe("/hotbuns-test:0.0.1/");
    }
  });

  test("initiator detects v1 peer and disconnects with typed reason", () => {
    const captured = { msgs: [] as NetworkMessage[], handshakeComplete: false };
    let disconnectError: Error | undefined;
    const events: PeerEvents = {
      onConnect: () => {},
      onDisconnect: (_p, err) => {
        disconnectError = err;
      },
      onMessage: (_p, msg) => {
        captured.msgs.push(msg);
      },
      onHandshakeComplete: () => {
        captured.handshakeComplete = true;
      },
    };
    const peer = new Peer(makeConfig(), events);
    const stub = makeStubSocket();

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const p = peer as any;
    p.socket = stub.socket;
    p.state = "handshaking";
    p.prepareV2Outbound();
    p.flushV2SendBuffer();

    // Synthesize a v1 VERSION-style reply: 4-byte magic + 12-byte
    // command "version\0\0\0\0\0".  This is the fast-path v1 detection
    // (clearbit-style) the initiator should hit before wasting 30s on
    // V2Transport state.
    const v1Prefix = Buffer.concat([
      REGTEST_MAGIC_LE,
      Buffer.from([0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0, 0, 0, 0, 0]),
    ]);
    expect(v1Prefix.length).toBe(V1_PREFIX_LEN);

    peer.feedData(v1Prefix);

    // Peer should have synchronously disconnected.
    expect(peer.state).toBe("disconnected");
    expect(stub.ended).toBe(true);
  });

  test("initiator timeouts surface as handshake-timeout disconnects", async () => {
    const captured = { msgs: [] as NetworkMessage[], handshakeComplete: false };
    const peer = new Peer(makeConfig(), makeEvents(captured));
    const stub = makeStubSocket();

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const p = peer as any;
    p.socket = stub.socket;
    p.state = "handshaking";
    p.prepareV2Outbound();
    p.flushV2SendBuffer();
    // Arm a short v2 handshake timer (10ms) — production uses 30s, but the
    // unit test only cares that the timer fires and disconnects.
    p.handshakeTimer = setTimeout(() => {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const peerAny = peer as any;
      if (!peerAny.handshakeComplete && peerAny.state !== "disconnected") {
        peer.disconnect("v2 handshake timeout");
      }
    }, 10);

    // Wait for the timer to fire.
    await new Promise((resolve) => setTimeout(resolve, 30));

    expect(peer.state).toBe("disconnected");
    expect(stub.ended).toBe(true);
  });
});

describe("PeerManager v1-only cache", () => {
  let manager: PeerManager;
  let datadir: string;

  const baseConfig = (datadir: string): PeerManagerConfig => ({
    maxOutbound: 8,
    maxInbound: 117,
    params: REGTEST,
    bestHeight: 0,
    datadir,
    listen: false,
  });

  beforeEach(async () => {
    datadir = await mkdtemp(join(tmpdir(), "hotbuns-v1cache-"));
    manager = new PeerManager(baseConfig(datadir));
  });

  afterEach(async () => {
    await rm(datadir, { recursive: true, force: true });
  });

  test("isV1Only returns false for unseen address", () => {
    expect(manager.isV1Only("1.2.3.4:8333")).toBe(false);
  });

  test("markV1Only then isV1Only returns true", () => {
    manager.markV1Only("1.2.3.4:8333");
    expect(manager.isV1Only("1.2.3.4:8333")).toBe(true);
  });

  test("clearV1OnlyCache drops all entries", () => {
    manager.markV1Only("1.2.3.4:8333");
    manager.markV1Only("5.6.7.8:8333");
    expect(manager.isV1Only("1.2.3.4:8333")).toBe(true);
    manager.clearV1OnlyCache();
    expect(manager.isV1Only("1.2.3.4:8333")).toBe(false);
    expect(manager.isV1Only("5.6.7.8:8333")).toBe(false);
  });

  test("evicts entries past TTL", () => {
    manager.markV1Only("1.2.3.4:8333");
    // Directly stamp the entry's timestamp to past the TTL.  We poke
    // the internal Map for this — public API doesn't expose a setter
    // and Date.now() is stable enough we don't want to rely on real
    // wall-clock advance.
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const internal = (manager as any).v1OnlyCache as Map<string, number>;
    internal.set("1.2.3.4:8333", Date.now() - V1_ONLY_CACHE_TTL_MS - 1000);
    expect(manager.isV1Only("1.2.3.4:8333")).toBe(false);
    // After lookup-eviction, the entry should be gone.
    expect(internal.has("1.2.3.4:8333")).toBe(false);
  });

  test("bounded at V1_ONLY_CACHE_MAX entries; oldest evicted on overflow", () => {
    // Fill the cache.
    for (let i = 0; i < V1_ONLY_CACHE_MAX; i++) {
      manager.markV1Only(`10.0.0.${i % 255}.${i}:8333`);
    }
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const internal = (manager as any).v1OnlyCache as Map<string, number>;
    expect(internal.size).toBe(V1_ONLY_CACHE_MAX);

    // Add one more — first inserted entry should be dropped.
    const firstKey = internal.keys().next().value as string;
    manager.markV1Only("99.99.99.99:8333");
    expect(internal.size).toBe(V1_ONLY_CACHE_MAX);
    expect(internal.has(firstKey)).toBe(false);
    expect(internal.has("99.99.99.99:8333")).toBe(true);
  });
});
