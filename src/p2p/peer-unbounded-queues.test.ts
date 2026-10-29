/**
 * Security audit 2026-10-29, finding C1: one peer that stops reading
 * exhausts node memory.
 *
 * Peer.outbox was the only send buffer (Bun's Socket.write does not buffer)
 * and nothing bounded it: the node kept dispatching a non-reading peer's
 * messages and queueing their replies. A ~93-byte getheaders buys a reply of
 * up to 2000 headers (~162 KB), so a few MB of requests pinned GBs.
 *
 * Bitcoin Core bounds both directions per peer:
 *   - send: over -maxsendbuffer (1000 KB, net.h:99) fPauseSend is set
 *     (net.cpp PushMessage) and the peer's messages are not processed
 *     (net_processing.cpp:5157, net.cpp:3150) until the queue drains;
 *   - receive: over -maxreceivebuffer (5000 KB, net.h:98) fPauseRecv stops
 *     reading the socket (net.cpp:4033,4045), so TCP flow control stops the
 *     sender.
 *
 * These tests run a REAL inbound Peer on a loopback socket (the path
 * PeerManager's Bun.listen handler uses) against a local attacker client
 * that completes the handshake, stops reading, and streams getheaders.
 * Queue sizes are read from the Peer's private fields so the same
 * assertions run against the pre-fix code.
 */

import { describe, expect, test, afterEach } from "bun:test";
import type { TCPSocketListener, Socket } from "bun";
import { Peer, type PeerConfig, type PeerEvents } from "./peer.js";
import { type NetworkMessage, serializeMessage, ipv4ToBuffer } from "./messages.js";
import { REGTEST } from "../consensus/params.js";
import { deserializeBlockHeader } from "../validation/block.js";
import { BufferReader } from "../wire/serialization.js";
import { V2Transport } from "./v2_transport.js";
import { readFileSync } from "fs";

/** Core DEFAULT_MAXSENDBUFFER / DEFAULT_MAXRECEIVEBUFFER (net.h). */
const CORE_MAX_SEND_BUFFER = 1000 * 1000;
const CORE_MAX_RECEIVE_BUFFER = 5000 * 1000;

const MAGIC = REGTEST.networkMagic;
const GENESIS_HEADER = deserializeBlockHeader(new BufferReader(REGTEST.genesisBlock.subarray(0, 80)));
/** 200 headers: ~16 KB reply per 93-byte request (~170x amplification). */
const REPLY: NetworkMessage = {
  type: "headers",
  payload: { headers: Array.from({ length: 200 }, () => GENESIS_HEADER) },
};
const REPLY_BYTES = serializeMessage(MAGIC, REPLY).length;

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

async function waitFor(cond: () => boolean, timeoutMs = 10_000): Promise<void> {
  const start = Date.now();
  while (!cond()) {
    if (Date.now() - start > timeoutMs) throw new Error("waitFor timeout");
    await sleep(10);
  }
}

/** Wait until `value()` stops changing for `quietMs`. */
async function settle(value: () => number, quietMs = 300, timeoutMs = 10_000): Promise<void> {
  const start = Date.now();
  let last = value();
  let since = Date.now();
  while (Date.now() - since < quietMs) {
    if (Date.now() - start > timeoutMs) return;
    await sleep(20);
    const v = value();
    if (v !== last) {
      last = v;
      since = Date.now();
    }
  }
}

function versionMsg(): NetworkMessage {
  return {
    type: "version",
    payload: {
      version: 70016,
      services: 0x409n,
      timestamp: BigInt(Math.floor(Date.now() / 1000)),
      addrRecv: { services: 0n, ip: ipv4ToBuffer("127.0.0.1"), port: 0 },
      addrFrom: { services: 0x409n, ip: ipv4ToBuffer("127.0.0.1"), port: 0 },
      nonce: BigInt(Math.floor(Math.random() * Number.MAX_SAFE_INTEGER)) + 1n,
      userAgent: "/attacker:0.1/",
      startHeight: 0,
      relay: true,
    },
  };
}

function getheadersMsg(i: number): NetworkMessage {
  // One unknown locator hash, zero stop: answered from genesis.
  const locator = Buffer.alloc(32);
  locator.writeUInt32LE(i + 1, 0);
  locator[31] = 0xab;
  return {
    type: "getheaders",
    payload: { version: 70016, locatorHashes: [locator], hashStop: Buffer.alloc(32) },
  };
}

function nodeConfig(extra: Partial<PeerConfig> = {}): PeerConfig {
  return {
    host: "127.0.0.1",
    port: 0,
    magic: MAGIC,
    protocolVersion: 70016,
    services: 0x409n,
    userAgent: "/hotbuns-test/",
    bestHeight: 0,
    relay: true,
    ...extra,
  };
}

/** Bytes the node has queued for / from this peer, from private fields. */
function outboxBytes(peer: Peer): number {
  return ((peer as any).outbox as Buffer[]).reduce((n, b) => n + b.length, 0);
}
function recvQueueBytes(peer: Peer): number {
  const p = peer as any;
  return (p.recvBuffer as Buffer).length + (p.deferredV2Total ?? 0);
}

/**
 * Node side: a Bun.listen server wrapping the accepted socket in an inbound
 * Peer. Its message handler answers every getheaders with REPLY (sync, like
 * HeaderSync.handleGetHeaders) and `burst` copies of it when configured.
 * Attacker side: a raw client that can stop and resume reading.
 */
class Harness {
  server: TCPSocketListener<{ peer?: Peer }> | null = null;
  peer: Peer | null = null;
  client: Socket<undefined> | null = null;
  dispatched = new Map<string, number>();
  handshakeDone = false;
  disconnected = false;
  disconnectReason: string | null = null;
  clientBytes = 0;
  peakOutbox = 0;
  peakRecv = 0;
  private clientPaused = false;
  private drainWaiters: (() => void)[] = [];
  private sampler: ReturnType<typeof setInterval> | null = null;

  constructor(
    private cfg: Partial<PeerConfig> = {},
    private burst = 1,
    private burstMsg: NetworkMessage = REPLY,
  ) {}

  count(type: string): number {
    return this.dispatched.get(type) ?? 0;
  }

  async start(): Promise<void> {
    this.server = Bun.listen<{ peer?: Peer }>({
      hostname: "127.0.0.1",
      port: 0,
      socket: {
        open: (sock) => {
          const events: PeerEvents = {
            onConnect: () => {},
            onDisconnect: () => {
              this.disconnected = true;
            },
            onMessage: (p, m) => {
              this.dispatched.set(m.type, this.count(m.type) + 1);
              if (m.type === "getheaders") {
                for (let i = 0; i < this.burst; i++) p.send(this.burstMsg);
              } else if (m.type === "ping") {
                p.send({ type: "pong", payload: { nonce: m.payload.nonce } });
              }
              this.sample();
            },
            onHandshakeComplete: () => {
              this.handshakeDone = true;
            },
          };
          const peer = new Peer(nodeConfig(this.cfg), events, undefined, { connType: "inbound" });
          const orig = peer.disconnect.bind(peer);
          peer.disconnect = (reason?: string) => {
            if (peer.state !== "disconnected") this.disconnectReason ??= reason ?? "disconnected";
            orig(reason);
          };
          sock.data = { peer };
          this.peer = peer;
          peer.acceptSocket(sock as unknown as Socket<unknown>);
        },
        data: (sock, data) => {
          sock.data?.peer?.feedData(Buffer.from(data));
          this.sample();
        },
        drain: (sock) => {
          sock.data?.peer?.onDrain();
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
          this.clientBytes += data.length;
          this.reassertClientPause();
        },
        drain: () => {
          this.reassertClientPause();
          const w = this.drainWaiters;
          this.drainWaiters = [];
          for (const f of w) f();
        },
        close: () => {},
        error: () => {},
      },
    });
    this.sampler = setInterval(() => this.sample(), 5);

    this.send(versionMsg());
    this.send({ type: "verack", payload: null });
    await waitFor(() => this.handshakeDone);
  }

  /**
   * The attacker stops reading. Bun 1.3.11 re-arms reading on a short write
   * or a writable event (the same quirk Peer.reassertRecvPause works around),
   * so the pause is re-applied after each of those; otherwise the "silent"
   * attacker would keep draining its socket while it writes.
   */
  pauseClient(): void {
    this.clientPaused = true;
    this.client!.pause();
  }

  resumeClient(): void {
    this.clientPaused = false;
    this.client!.resume();
  }

  private reassertClientPause(): void {
    if (!this.clientPaused) return;
    this.client!.resume();
    this.client!.pause();
  }

  private sample(): void {
    if (!this.peer) return;
    this.peakOutbox = Math.max(this.peakOutbox, outboxBytes(this.peer));
    this.peakRecv = Math.max(this.peakRecv, recvQueueBytes(this.peer));
  }

  send(msg: NetworkMessage): void {
    this.client!.write(serializeMessage(MAGIC, msg));
  }

  /**
   * Write `data` as fast as the kernel takes it; give up after `timeoutMs`
   * without progress. Returns bytes accepted.
   */
  async pump(data: Buffer, timeoutMs = 1500): Promise<number> {
    let off = 0;
    while (off < data.length) {
      const n = this.client!.write(data.subarray(off));
      off += n;
      this.reassertClientPause();
      if (off >= data.length) break;
      const drained = await Promise.race([
        new Promise<boolean>((r) => this.drainWaiters.push(() => r(true))),
        sleep(timeoutMs).then(() => false),
      ]);
      if (!drained) break;
    }
    return off;
  }

  stop(): void {
    if (this.sampler) clearInterval(this.sampler);
    try { this.peer?.disconnect("test done"); } catch { /* ignore */ }
    try { this.client?.terminate(); } catch { /* ignore */ }
    try { this.server?.stop(true); } catch { /* ignore */ }
  }
}

function tcpRmemMax(): number {
  try {
    const f = readFileSync("/proc/sys/net/ipv4/tcp_rmem", "utf8");
    return Number(f.trim().split(/\s+/)[2]);
  } catch {
    return 6 * 1024 * 1024;
  }
}

function getheadersFlood(n: number): Buffer {
  return Buffer.concat(Array.from({ length: n }, (_, i) => serializeMessage(MAGIC, getheadersMsg(i))));
}

describe("C1: per-peer send/receive queues are bounded (Core maxsendbuffer/maxreceivebuffer)", () => {
  let h: Harness;
  afterEach(() => h?.stop());

  test(
    "a peer that stops reading cannot grow its send queue past maxsendbuffer",
    async () => {
      h = new Harness();
      await h.start();
      h.pauseClient(); // attacker stops reading

      // 3000 x 93 B in => 3000 x ~16 KB (~48 MB) of replies if all were
      // dispatched. The loopback kernel buffers (both ends, autotuned) absorb
      // up to ~15 MB of that before the node's writes start coming up short.
      const N = 3000;
      await h.pump(getheadersFlood(N));
      await settle(() => h.count("getheaders"), 1000);

      // Bound: the limit plus the one reply that crossed it.
      expect(h.peakOutbox).toBeLessThanOrEqual(CORE_MAX_SEND_BUFFER + REPLY_BYTES);
      // And the node stopped answering: requests are held, not served.
      expect(h.count("getheaders")).toBeLessThan(N);
      expect(h.peer!.state).toBe("connected");

      // Liveness: once the attacker reads again every request is answered
      // and the queues empty — the pause is backpressure, not a wedge.
      h.resumeClient();
      await waitFor(() => h.count("getheaders") === N && outboxBytes(h.peer!) === 0, 20_000);
      await waitFor(() => h.clientBytes >= N * REPLY_BYTES);
      expect(h.disconnected).toBe(false);
    },
    40_000,
  );

  test(
    "a send-paused peer's further input pauses its socket at maxreceivebuffer",
    async () => {
      h = new Harness();
      await h.start();
      h.pauseClient();

      // Fill the send side first (as above) so the node stops dispatching...
      await h.pump(getheadersFlood(3000));
      await settle(() => h.count("getheaders"), 1000);
      const answered = h.count("getheaders");
      // ...then stream 25 MB more of pings (small replies, so the receive
      // side is what gets measured). That is more than the loopback
      // kernel buffers on both ends (~10 MB) plus maxreceivebuffer.
      const PINGS = 800_000;
      const ping = (i: number) => serializeMessage(MAGIC, { type: "ping", payload: { nonce: BigInt(i) } });
      const more = Buffer.concat(Array.from({ length: PINGS }, (_, i) => ping(i)));
      const accepted = await h.pump(more, 1500);
      await settle(() => recvQueueBytes(h.peer!));

      expect((h.peer as any).recvPaused).toBe(true);
      // Bun finishes its current read loop after pause(), so the overshoot
      // is what the kernel had buffered: at most tcp_rmem's max.
      expect(h.peakRecv).toBeLessThan(CORE_MAX_RECEIVE_BUFFER + tcpRmemMax() + 1_000_000);
      expect(h.peakOutbox).toBeLessThanOrEqual(CORE_MAX_SEND_BUFFER + REPLY_BYTES);
      // TCP flow control stopped the sender: it could not hand over all 12 MB.
      expect(accepted).toBeLessThan(more.length);
      expect(h.count("getheaders")).toBe(answered);
      // Only the few pings dispatched while the send queue dipped under the
      // limit were answered; the rest wait.
      expect(h.count("ping")).toBeLessThan(PINGS / 10);
      expect(h.peer!.state).toBe("connected");

      // Resume: reading again releases both pauses and everything sent is
      // dispatched.
      h.resumeClient();
      const rest = await h.pump(more.subarray(accepted), 30_000);
      expect(rest).toBe(more.length - accepted);
      await waitFor(() => h.count("getheaders") === 3000 && h.count("ping") === PINGS, 60_000);
      expect((h.peer as any).recvPaused).toBe(false);
      expect(h.disconnected).toBe(false);
    },
    120_000,
  );

  test(
    "a send queue over the hard limit disconnects the peer",
    async () => {
      // One request that makes the node queue 60 x 512 KB in one dispatch
      // (the shape of an async getdata batch, which the dispatch pause cannot
      // stop part-way). Hard limit lowered to 2 MB for the test.
      const blob: NetworkMessage = {
        type: "headers",
        payload: { headers: Array.from({ length: 6500 }, () => GENESIS_HEADER) },
      };
      // 30 MB is past what the loopback kernel buffers can absorb.
      h = new Harness({ sendBufferHardLimit: 2_000_000 }, 60, blob);
      await h.start();
      h.pauseClient();
      h.send(getheadersMsg(0));
      await waitFor(() => h.disconnected, 5000);
      expect(h.disconnectReason).toBe("send buffer over hard limit");
      expect(outboxBytes(h.peer!)).toBe(0);
    },
    20_000,
  );
});

describe("C1/H3: dispatch holds on the v2 transport", () => {
  test("held v2 messages are queued, counted and dispatched in order on release", async () => {
    const magicLE = Buffer.alloc(4);
    magicLE.writeUInt32LE(MAGIC, 0);
    const written: Buffer[] = [];
    const paused: string[] = [];
    const stub = {
      write(data: Buffer | Uint8Array | string): number {
        const buf = Buffer.from(data as Uint8Array);
        written.push(buf);
        return buf.length;
      },
      end() {},
      terminate() {},
      pause() { paused.push("pause"); },
      resume() { paused.push("resume"); },
      remoteAddress: "127.0.0.1",
    };
    const got: string[] = [];
    const events: PeerEvents = {
      onConnect: () => {},
      onDisconnect: () => {},
      onMessage: (_p, m) => {
        got.push(m.type === "ping" ? `ping:${m.payload.nonce}` : m.type);
      },
      onHandshakeComplete: () => {},
    };
    const peer = new Peer(nodeConfig({ maxReceiveBuffer: 100 }), events);
    try {
      const p = peer as any;
      p.socket = stub;
      p.state = "handshaking";
      p.prepareV2Outbound();
      p.flushV2SendBuffer();
      const responder = new V2Transport(magicLE, false);
      responder.receiveBytes(Buffer.concat(written));
      written.length = 0;
      peer.feedData(responder.consumeSendBuffer());
      responder.receiveBytes(Buffer.concat(written));
      responder.getReceivedMessages();

      const enc = (m: NetworkMessage) => {
        const raw = serializeMessage(MAGIC, m);
        return responder.encryptMessage(m.type, raw.subarray(24));
      };
      peer.feedData(Buffer.concat([enc(versionMsg()), enc({ type: "verack", payload: null })]));
      expect(peer.state).toBe("connected");

      peer.holdIngress("test");
      const pings = [1n, 2n, 3n].map((nonce) => enc({ type: "ping", payload: { nonce } }));
      peer.feedData(Buffer.concat(pings));
      expect(got).toEqual([]);
      expect(peer.getRecvQueueBytes()).toBe(24);
      peer.feedData(Buffer.concat(Array.from({ length: 20 }, () => enc({ type: "ping", payload: { nonce: 9n } }))));
      expect(peer.isRecvPaused()).toBe(true);
      expect(paused).toEqual(["pause"]);

      peer.releaseIngress("test");
      await sleep(5);
      expect(got.slice(0, 3)).toEqual(["ping:1", "ping:2", "ping:3"]);
      expect(got.length).toBe(23);
      expect(peer.getRecvQueueBytes()).toBe(0);
      expect(peer.isRecvPaused()).toBe(false);
      expect(paused).toEqual(["pause", "resume"]);
    } finally {
      peer.disconnect();
    }
  });
});
