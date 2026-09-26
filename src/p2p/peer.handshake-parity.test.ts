/**
 * Handshake Core-parity tests (inbound + outbound).
 *
 * Bitcoin Core (net_processing.cpp ProcessMessage):
 *  - MIN_PEER_PROTO_VERSION = 31800 for ALL peers (:3619); witness is a
 *    services question, only enforced for outbound connections we chose
 *    (ExpectServicesFromConn, :3608).
 *  - Between VERSION and VERACK: VERSION/VERACK/WTXIDRELAY/SENDADDRV2/
 *    SENDTXRCNCL and SENDHEADERS (:3896) / SENDCMPCT (:3901) are processed;
 *    everything else is logged "Unsupported message prior to verack" and
 *    ignored (:4010-4011) — no misbehaviour, no disconnect.
 *  - Feature messages we send are gated on the common version
 *    (wtxidrelay/sendaddrv2 >= 70016, sendheaders >= 70012,
 *    sendcmpct >= 70014, pong > 60000).
 *
 * The inbound tests drive a REAL Peer through acceptSocket()/feedData() on a
 * real TCP socket — the same path PeerManager's Bun.listen handler uses.
 */

import { describe, expect, test, afterEach } from "bun:test";
import type { TCPSocketListener, Socket } from "bun";
import {
  Peer,
  MIN_PEER_PROTO_VERSION,
  hasAllDesirableServiceFlags,
  canServeWitnessBlocks,
  type PeerConfig,
  type PeerEvents,
} from "./peer.js";
import {
  type NetworkMessage,
  MESSAGE_HEADER_SIZE,
  parseHeader,
  deserializeMessage,
  serializeMessage,
  ipv4ToBuffer,
} from "./messages.js";
import { REGTEST } from "../consensus/params.js";

const TEST_TIMEOUT = 8000;

async function waitFor(cond: () => boolean, timeoutMs = 3000): Promise<void> {
  const start = Date.now();
  while (!cond()) {
    if (Date.now() - start > timeoutMs) throw new Error("waitFor timeout");
    await new Promise((r) => setTimeout(r, 10));
  }
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

function versionMsg(version: number, services = 0x409n): NetworkMessage {
  return {
    type: "version",
    payload: {
      version,
      services,
      timestamp: BigInt(Math.floor(Date.now() / 1000)),
      addrRecv: { services: 0n, ip: ipv4ToBuffer("127.0.0.1"), port: 0 },
      addrFrom: { services, ip: ipv4ToBuffer("127.0.0.1"), port: 0 },
      nonce: BigInt(Math.floor(Math.random() * Number.MAX_SAFE_INTEGER)) + 1n,
      userAgent: "/parity-client:0.1/",
      startHeight: 0,
      relay: true,
    },
  };
}

function serverConfig(): PeerConfig {
  return {
    host: "127.0.0.1",
    port: 0,
    magic: REGTEST.networkMagic,
    protocolVersion: 70016,
    services: 0x409n,
    userAgent: "/hotbuns-test/",
    bestHeight: 0,
    relay: true,
  };
}

/**
 * An inbound harness: a Bun.listen server that wraps each accepted socket
 * in an inbound Peer (acceptSocket + feedData), plus a raw client.
 */
class InboundHarness {
  server: TCPSocketListener<{ peer?: Peer }> | null = null;
  peer: Peer | null = null;
  disconnectedWith: string | null = null;
  handshakeDone = false;
  dispatched: string[] = [];
  client: Socket<undefined> | null = null;
  clientClosed = false;
  received: NetworkMessage[] = [];
  private buf = Buffer.alloc(0);

  async start(): Promise<void> {
    this.server = Bun.listen<{ peer?: Peer }>({
      hostname: "127.0.0.1",
      port: 0,
      socket: {
        open: (sock) => {
          const events: PeerEvents = {
            onConnect: () => {},
            onDisconnect: (_p, err) => {
              this.disconnectedWith ??= err?.message ?? "disconnected";
            },
            onMessage: (_p, m) => {
              this.dispatched.push(m.type);
            },
            onHandshakeComplete: () => {
              this.handshakeDone = true;
            },
          };
          const peer = new Peer(serverConfig(), events, undefined, { connType: "inbound" });
          // Capture the disconnect reason (Peer.disconnect does not forward it).
          const orig = peer.disconnect.bind(peer);
          peer.disconnect = (reason?: string) => {
            if (peer.state !== "disconnected" && this.disconnectedWith === null) {
              this.disconnectedWith = reason ?? "disconnected";
            }
            orig(reason);
          };
          sock.data = { peer };
          this.peer = peer;
          peer.acceptSocket(sock as unknown as Socket<unknown>);
        },
        data: (sock, data) => {
          sock.data?.peer?.feedData(Buffer.from(data));
        },
        close: (sock) => {
          sock.data?.peer?.disconnect("remote closed");
        },
        error: () => {},
      },
    });

    this.client = await Bun.connect<undefined>({
      hostname: "127.0.0.1",
      port: this.server.port,
      socket: {
        data: (_s, data) => {
          this.buf = Buffer.concat([this.buf, Buffer.from(data)]);
          while (this.buf.length >= MESSAGE_HEADER_SIZE) {
            const h = parseHeader(this.buf);
            if (!h) break;
            const total = MESSAGE_HEADER_SIZE + h.length;
            if (this.buf.length < total) break;
            this.received.push(deserializeMessage(h, this.buf.subarray(MESSAGE_HEADER_SIZE, total)));
            this.buf = this.buf.subarray(total);
          }
        },
        close: () => {
          this.clientClosed = true;
        },
        error: () => {
          this.clientClosed = true;
        },
      },
    });
  }

  send(msg: NetworkMessage): void {
    this.client!.write(serializeMessage(REGTEST.networkMagic, msg));
  }

  has(type: string): boolean {
    return this.received.some((m) => m.type === type);
  }

  stop(): void {
    try { this.peer?.disconnect("test done"); } catch { /* ignore */ }
    try { this.client?.end(); } catch { /* ignore */ }
    try { this.server?.stop(true); } catch { /* ignore */ }
  }
}

describe("handshake Core parity — constants", () => {
  test("MIN_PEER_PROTO_VERSION is Core's 31800", () => {
    expect(MIN_PEER_PROTO_VERSION).toBe(31800);
  });

  test("desirable services: NETWORK|WITNESS, or LIMITED|WITNESS near tip", () => {
    expect(hasAllDesirableServiceFlags(0x9n, false)).toBe(true); // NETWORK|WITNESS
    expect(hasAllDesirableServiceFlags(0x1n, false)).toBe(false); // no witness
    expect(hasAllDesirableServiceFlags(0x408n, false)).toBe(false); // limited, in IBD
    expect(hasAllDesirableServiceFlags(0x408n, true)).toBe(true); // limited, near tip
  });

  test("block-download gate needs witness + (network|limited)", () => {
    expect(canServeWitnessBlocks(0x409n)).toBe(true);
    expect(canServeWitnessBlocks(0x408n)).toBe(true);
    expect(canServeWitnessBlocks(0x1n)).toBe(false);
    expect(canServeWitnessBlocks(0x8n)).toBe(false);
  });
});

describe("handshake Core parity — inbound", () => {
  let h: InboundHarness;
  afterEach(() => h?.stop());

  test("inbound VERSION(70002) completes the handshake and is sent only messages it can parse", async () => {
    h = new InboundHarness();
    await h.start();
    h.send(versionMsg(70002, 0x1n)); // old version, no NODE_WITNESS
    await waitFor(() => h.has("version") && h.has("verack"));
    h.send({ type: "verack", payload: null });
    await waitFor(() => h.handshakeDone);
    await sleep(200);

    expect(h.disconnectedWith).toBeNull();
    expect(h.clientClosed).toBe(false);
    expect(h.peer!.state).toBe("connected");
    expect(h.peer!.commonVersion).toBe(70002);
    // None of these may be sent to a 70002 peer (Core gates: wtxidrelay /
    // sendaddrv2 >= 70016, sendcmpct >= 70014, sendheaders >= 70012).
    expect(h.has("wtxidrelay")).toBe(false);
    expect(h.has("sendaddrv2")).toBe(false);
    expect(h.has("sendcmpct")).toBe(false);
    expect(h.has("sendheaders")).toBe(false);
    expect(h.received.map((m) => m.type)).toEqual(["version", "verack"]);
  }, TEST_TIMEOUT);

  test("inbound VERSION(70012) gets sendheaders but not sendcmpct / wtxidrelay", async () => {
    h = new InboundHarness();
    await h.start();
    h.send(versionMsg(70012, 0x1n));
    await waitFor(() => h.has("verack"));
    h.send({ type: "verack", payload: null });
    await waitFor(() => h.has("sendheaders"));
    await sleep(200);
    expect(h.has("sendcmpct")).toBe(false);
    expect(h.has("wtxidrelay")).toBe(false);
    expect(h.peer!.state).toBe("connected");
  }, TEST_TIMEOUT);

  test("inbound VERSION below 31800 is still disconnected", async () => {
    h = new InboundHarness();
    await h.start();
    h.send(versionMsg(31799));
    await waitFor(() => h.disconnectedWith !== null);
    expect(h.disconnectedWith).toContain("obsolete version");
  }, TEST_TIMEOUT);

  test("inbound VERSION(70016) still gets wtxidrelay + sendaddrv2 + sendcmpct", async () => {
    h = new InboundHarness();
    await h.start();
    h.send(versionMsg(70016));
    await waitFor(() => h.has("verack"));
    h.send({ type: "verack", payload: null });
    await waitFor(() => h.has("sendcmpct") && h.has("sendheaders"));
    expect(h.has("wtxidrelay")).toBe(true);
    expect(h.has("sendaddrv2")).toBe(true);
  }, TEST_TIMEOUT);

  test("pre-verack sendheaders + sendcmpct are recorded and do not disconnect", async () => {
    h = new InboundHarness();
    await h.start();
    h.send(versionMsg(70016));
    await waitFor(() => h.has("verack"));
    h.send({ type: "sendheaders", payload: null });
    h.send({ type: "sendcmpct", payload: { enabled: true, version: 2n } });
    await waitFor(() => h.peer!.prefersHeaders && h.peer!.providesCmpctBlocks);
    await sleep(200);
    expect(h.disconnectedWith).toBeNull();
    expect(h.peer!.requestedHbCmpctBlocks).toBe(true);
    expect(h.peer!.handshakeComplete).toBe(false);
    // handshake still completes afterwards
    h.send({ type: "verack", payload: null });
    await waitFor(() => h.handshakeDone);
    expect(h.peer!.state).toBe("connected");
  }, TEST_TIMEOUT);

  test("pre-verack ping / inv / feefilter / getheaders are ignored, no disconnect, no pong", async () => {
    h = new InboundHarness();
    await h.start();
    h.send(versionMsg(70016));
    await waitFor(() => h.has("verack"));
    for (let i = 0; i < 25; i++) {
      h.send({ type: "ping", payload: { nonce: BigInt(i + 1) } });
      h.send({ type: "inv", payload: { inventory: [{ type: 1, hash: Buffer.alloc(32, i) }] } });
    }
    h.send({ type: "feefilter", payload: { feeRate: 1000n } });
    await waitFor(() => h.peer!.ignoredPreVerackMessages >= 51);
    await sleep(200);
    expect(h.disconnectedWith).toBeNull();
    expect(h.clientClosed).toBe(false);
    expect(h.dispatched).toEqual([]); // ignored, not dispatched
    expect(h.has("pong")).toBe(false);
    h.send({ type: "verack", payload: null });
    await waitFor(() => h.handshakeDone);
    expect(h.peer!.state).toBe("connected");
  }, TEST_TIMEOUT);

  test("redundant VERSION before verack is ignored (Core logs only), not a disconnect", async () => {
    h = new InboundHarness();
    await h.start();
    h.send(versionMsg(70016));
    await waitFor(() => h.has("verack"));
    h.send(versionMsg(70016)); // redundant version: Core logs + ignores
    await sleep(200);
    expect(h.disconnectedWith).toBeNull();
    h.send({ type: "verack", payload: null });
    await waitFor(() => h.handshakeDone);
  }, TEST_TIMEOUT);

  test("bare (pre-BIP31) ping from a 60000 peer is parsed, not a disconnect", async () => {
    h = new InboundHarness();
    await h.start();
    h.send(versionMsg(60000, 0x1n));
    await waitFor(() => h.has("verack"));
    h.send({ type: "verack", payload: null });
    await waitFor(() => h.handshakeDone);
    h.send({ type: "ping", payload: { nonce: 0n, noNonce: true } });
    await waitFor(() => h.dispatched.includes("ping"));
    await sleep(100);
    expect(h.disconnectedWith).toBeNull();
    // sendPing to such a peer is bare and arms no timeout
    h.peer!.sendPing();
    expect(h.peer!.pingOutstanding).toBe(false);
  }, TEST_TIMEOUT);
});

describe("handshake Core parity — outbound", () => {
  let server: TCPSocketListener<undefined> | null = null;
  afterEach(() => {
    server?.stop(true);
    server = null;
  });

  /** Mock remote that answers our VERSION with `ver`/`services` + verack. */
  async function startRemote(ver: number, services: bigint): Promise<number> {
    let buf = Buffer.alloc(0);
    server = Bun.listen<undefined>({
      hostname: "127.0.0.1",
      port: 0,
      socket: {
        data: (sock, data) => {
          buf = Buffer.concat([buf, Buffer.from(data)]);
          while (buf.length >= MESSAGE_HEADER_SIZE) {
            const hd = parseHeader(buf);
            if (!hd) break;
            const total = MESSAGE_HEADER_SIZE + hd.length;
            if (buf.length < total) break;
            const m = deserializeMessage(hd, buf.subarray(MESSAGE_HEADER_SIZE, total));
            buf = buf.subarray(total);
            if (m.type === "version") {
              sock.write(serializeMessage(REGTEST.networkMagic, versionMsg(ver, services)));
              sock.write(serializeMessage(REGTEST.networkMagic, { type: "verack", payload: null }));
            }
          }
        },
        open: () => {},
        close: () => {},
        error: () => {},
      },
    });
    return server.port;
  }

  function outboundPeer(port: number, expectServices: boolean) {
    const state = { done: false, disc: null as string | null };
    const events: PeerEvents = {
      onConnect: () => {},
      onDisconnect: (_p, e) => { state.disc ??= e?.message ?? "disconnected"; },
      onMessage: () => {},
      onHandshakeComplete: () => { state.done = true; },
    };
    const cfg: PeerConfig = { ...serverConfig(), port, expectServices, isNearTip: () => false };
    const peer = new Peer(cfg, events);
    const orig = peer.disconnect.bind(peer);
    peer.disconnect = (reason?: string) => {
      if (peer.state !== "disconnected" && state.disc === null) {
        state.disc = reason ?? "disconnected";
      }
      orig(reason);
    };
    return { peer, state };
  }

  test("outbound relay connection to a 70002 NETWORK|WITNESS peer completes", async () => {
    const port = await startRemote(70002, 0x9n);
    const { peer, state } = outboundPeer(port, true);
    await peer.connect();
    await waitFor(() => state.done);
    expect(state.disc).toBeNull();
    peer.disconnect();
  }, TEST_TIMEOUT);

  test("outbound relay connection without NODE_WITNESS is dropped (ExpectServicesFromConn)", async () => {
    const port = await startRemote(70016, 0x1n);
    const { peer, state } = outboundPeer(port, true);
    await peer.connect().catch(() => {});
    await waitFor(() => state.disc !== null);
    expect(state.disc).toContain("expected services");
    expect(state.done).toBe(false);
  }, TEST_TIMEOUT);

  test("manual/feeler-style outbound (expectServices=false) keeps a non-witness peer", async () => {
    const port = await startRemote(70016, 0x1n);
    const { peer, state } = outboundPeer(port, false);
    await peer.connect();
    await waitFor(() => state.done);
    expect(state.disc).toBeNull();
    peer.disconnect();
  }, TEST_TIMEOUT);
});
