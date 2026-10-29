/**
 * Security audit 2026-10-29, finding H3: the tx ingress queue was unbounded
 * and survived disconnect.
 *
 * The socket was always drained and every decoded `tx` queued, so a flood of
 * cheap-to-send, slow-to-validate transactions outran the serial ATMP loop
 * and grew the queue with parsed objects; and nothing removed a peer's
 * entries when it disconnected, so its transactions were still validated
 * after it was gone.
 *
 * Core: a peer whose process queue passes -maxreceivebuffer (5000 KB) is not
 * read (fPauseRecv, net.cpp:4033,4045) until the queue drains, and its queued
 * messages are discarded in FinalizeNode.
 */
import { describe, test, expect } from "bun:test";
import { TxIngressQueue } from "./tx_ingress.js";
import { Peer, type PeerConfig, type PeerEvents } from "./peer.js";
import { type NetworkMessage, serializeMessage, ipv4ToBuffer } from "./messages.js";
import { REGTEST } from "../consensus/params.js";
import { getTxTotalSize, type Transaction } from "../validation/tx.js";

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

describe("H3: TxIngressQueue per-peer byte bound", () => {
  test("a peer over maxPeerBytes is paused, and resumed once it drains", async () => {
    const events: string[] = [];
    let release: () => void = () => {};
    let gate = new Promise<void>((r) => (release = r));
    const q = new TxIngressQueue<string, number>({
      process: async () => {
        await gate;
      },
      sizeOf: (n) => n,
      maxPeerBytes: 1000,
      onPeerPause: (p) => events.push(`pause:${p}`),
      onPeerResume: (p) => events.push(`resume:${p}`),
    });
    for (let i = 0; i < 4; i++) q.enqueue("A", 300); // 1200 > 1000
    q.enqueue("B", 300);
    expect(events).toEqual(["pause:A"]);
    expect(q.isPeerPaused("A")).toBe(true);
    expect(q.isPeerPaused("B")).toBe(false);
    expect(q.peerQueuedBytes("A")).toBe(1200);
    // Further input while paused does not re-signal.
    q.enqueue("A", 300);
    expect(events).toEqual(["pause:A"]);

    await sleep(1); // drain started: A's first tx left the queue (1200 left)
    expect(q.peerQueuedBytes("A")).toBe(1200);
    release();
    gate = Promise.resolve();
    await q.idle();
    expect(events).toEqual(["pause:A", "resume:A"]);
    expect(q.isPeerPaused("A")).toBe(false);
    expect(q.peerQueuedBytes("A")).toBe(0);
    expect(q.stats.processed).toBe(6);
  });

  test("a throwing pause/resume callback does not abort the drain", async () => {
    const seen: number[] = [];
    const errors: unknown[] = [];
    const q = new TxIngressQueue<string, number>({
      process: async (_p, n) => {
        seen.push(n);
      },
      sizeOf: () => 10,
      maxPeerBytes: 15,
      onPeerPause: () => {
        throw new Error("pause");
      },
      onPeerResume: () => {
        throw new Error("resume");
      },
      onError: (e) => errors.push(e),
    });
    for (let i = 0; i < 4; i++) q.enqueue("A", i);
    await q.idle();
    expect(seen).toEqual([0, 1, 2, 3]);
    expect(errors.map((e) => (e as Error).message)).toEqual(["pause", "resume"]);
  });

  test("drop(peer) discards a disconnected peer's queue: none of it is validated", async () => {
    const seen: string[] = [];
    const resumed: string[] = [];
    let release: () => void = () => {};
    const gate = new Promise<void>((r) => (release = r));
    const q = new TxIngressQueue<string, string>({
      process: async (peer, msg) => {
        seen.push(`${peer}:${msg}`);
        await gate;
      },
      sizeOf: () => 100,
      maxPeerBytes: 150,
      onPeerPause: () => {},
      onPeerResume: (p) => {
        resumed.push(p);
      },
    });
    for (let i = 0; i < 50; i++) q.enqueue("evil", `t${i}`);
    q.enqueue("good", "g0");
    q.enqueue("good", "g1");
    await sleep(1); // evil:t0 is being validated
    expect(q.drop("evil")).toBe(49);
    expect(q.size()).toBe(2);
    expect(q.peerQueuedBytes("evil")).toBe(0);
    expect(q.isPeerPaused("evil")).toBe(false);
    release();
    await q.idle();
    expect(seen).toEqual(["evil:t0", "good:g0", "good:g1"]);
    expect(q.stats.dropped).toBe(49);
    // "good" was over its share too and is resumed; "evil" is gone, never resumed.
    expect(resumed).toEqual(["good"]);
    // The peer may come back as a new connection and start from zero.
    q.enqueue("evil", "again");
    await q.idle();
    expect(seen.at(-1)).toBe("evil:again");
  });
});

// ---------------------------------------------------------------------------
// The wiring cli.ts uses: the queue holds the Peer's dispatch over the limit,
// which (Peer, C1) pauses the socket once 5 MB more is waiting.

function tx(i: number, scriptBytes: number): Transaction {
  const txid = Buffer.alloc(32);
  txid.writeUInt32LE(i + 1, 0);
  return {
    version: 2,
    inputs: [{ prevOut: { txid, vout: 0 }, scriptSig: Buffer.alloc(scriptBytes, 0x51), sequence: 0xffffffff, witness: [] }],
    outputs: [{ value: 1000n, scriptPubKey: Buffer.from([0x51]) }],
    lockTime: 0,
  };
}

describe("H3: cli wiring — a peer flooding txs stops being read", () => {
  test("queue over the limit holds the peer; release resumes it; disconnect drops", async () => {
    const MAGIC = REGTEST.networkMagic;
    const paused: string[] = [];
    const stub = {
      write: (d: Uint8Array) => d.length,
      end() {},
      terminate() {},
      pause() { paused.push("pause"); },
      resume() { paused.push("resume"); },
      remoteAddress: "127.0.0.1",
    };
    let processing: () => void = () => {};
    let gate = new Promise<void>((r) => (processing = r));
    const validated: number[] = [];
    let q!: TxIngressQueue<Peer, NetworkMessage>;
    const events: PeerEvents = {
      onConnect: () => {},
      onDisconnect: (p) => q.drop(p),
      onMessage: (p, m) => {
        if (m.type === "tx") q.enqueue(p, m);
      },
      onHandshakeComplete: () => {},
    };
    const cfg: PeerConfig = {
      host: "127.0.0.1", port: 0, magic: MAGIC, protocolVersion: 70016,
      services: 0x409n, userAgent: "/t/", bestHeight: 0, relay: true,
      maxReceiveBuffer: 50_000,
    };
    const peer = new Peer(cfg, events, undefined, { connType: "inbound" });
    q = new TxIngressQueue<Peer, NetworkMessage>({
      process: async (_p, m) => {
        if (m.type === "tx") validated.push(m.payload.tx.version);
        await gate;
      },
      sizeOf: (m) => (m.type === "tx" ? getTxTotalSize(m.payload.tx) : 0),
      maxPeerBytes: 20_000,
      onPeerPause: (p) => p.holdIngress("tx-ingress"),
      onPeerResume: (p) => p.releaseIngress("tx-ingress"),
    });
    peer.acceptSocket(stub as any);
    const wire = (m: NetworkMessage) => serializeMessage(MAGIC, m);
    peer.feedData(
      Buffer.concat([
        wire({
          type: "version",
          payload: {
            version: 70016, services: 0x409n, timestamp: BigInt(Math.floor(Date.now() / 1000)),
            addrRecv: { services: 0n, ip: ipv4ToBuffer("127.0.0.1"), port: 0 },
            addrFrom: { services: 0x409n, ip: ipv4ToBuffer("127.0.0.1"), port: 0 },
            nonce: 77n, userAgent: "/flood/", startHeight: 0, relay: true,
          },
        }),
        wire({ type: "verack", payload: null }),
      ])
    );
    expect(peer.state).toBe("connected");

    // 200 txs of ~1 KB each = ~200 KB, 10x the queue's 20 KB share.
    const flood = Buffer.concat(Array.from({ length: 200 }, (_, i) => wire({ type: "tx", payload: { tx: tx(i, 1000) } })));
    peer.feedData(flood);
    // Dispatch stopped just past the limit; the rest waits as raw bytes, and
    // being over maxReceiveBuffer, the socket is paused.
    expect(q.size()).toBeLessThan(25);
    expect(q.peerQueuedBytes(peer)).toBeLessThan(20_000 + 1100);
    expect(peer.getRecvQueueBytes()).toBeGreaterThan(150_000);
    expect(peer.isRecvPaused()).toBe(true);
    expect(paused).toEqual(["pause"]);

    // Validation catches up: the hold is released and all 200 arrive.
    processing();
    gate = Promise.resolve();
    for (let i = 0; i < 200 && q.stats.enqueued < 200; i++) await sleep(5);
    await q.idle();
    expect(q.stats.enqueued).toBe(200);
    expect(validated.length).toBe(200);
    expect(peer.isRecvPaused()).toBe(false);
    expect(paused).toEqual(["pause", "resume"]);

    // Disconnect with a backlog: the backlog is discarded, not validated.
    let hold: () => void = () => {};
    gate = new Promise<void>((r) => (hold = r));
    peer.feedData(Buffer.concat(Array.from({ length: 10 }, (_, i) => wire({ type: "tx", payload: { tx: tx(i, 100) } }))));
    await sleep(1);
    const before = validated.length;
    peer.disconnect("test");
    hold();
    await q.idle();
    expect(validated.length).toBe(before);
    expect(q.size()).toBe(0);
  });
});
