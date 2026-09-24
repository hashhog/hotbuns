/**
 * Independent control for the live `notfound` fix (034b63d).
 *
 * A serializeMessage round-trip, and a log with zero
 * "Unknown message type: notfound" lines, do not prove a peer received a
 * well-formed notfound. These tests drive a getdata miss through
 * BlockSync → Peer.send and parse the bytes the peer actually reads
 * with a checker that does not call hotbuns serialize/deserialize:
 *
 *   - v1: real TCP. Magic, 12-byte NUL-padded "notfound", length, and
 *     SHA256d checksum are checked with node:crypto. Inventory echoes
 *     the tx misses (type + hash) and omits a block miss — Core
 *     ProcessGetData puts only tx items in vNotFound
 *     (net_processing.cpp, the NOTFOUND push after the block branch).
 *   - v2: BIP-324. The responder decrypts command "notfound". The
 *     short id on the wire is 17, Core's V2_MESSAGE_IDS index
 *     (net.cpp). Payload bytes match the same hand-built layout.
 *   - A send() that returns false must not look like delivery. Callers
 *     that ignore the boolean cannot tell a dropped notfound from one
 *     that reached the peer.
 *
 * Negative control: flipping one payload byte and keeping the old
 * checksum must fail the checker. A checker that does not look at the
 * bytes would still pass.
 */

import { describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Socket } from "bun";

import { REGTEST } from "../consensus/params.js";
import { ChainDB } from "../storage/database.js";
import { BlockSync } from "../sync/blocks.js";
import { HeaderSync } from "../sync/headers.js";
import { getTxId, getWTxId, type Transaction } from "../validation/tx.js";
import { Peer, type PeerConfig, type PeerEvents } from "./peer.js";
import { PeerManager, type PeerManagerConfig } from "./manager.js";
import {
  InvType,
  ipv4ToBuffer,
  serializeMessage,
  type NetworkMessage,
} from "./messages.js";
import { encodeMessageType } from "./bip324/message_ids.js";
import { V2Transport } from "./v2_transport.js";

const TEST_TIMEOUT = 10_000;

function sha256d(data: Buffer): Buffer {
  const once = createHash("sha256").update(data).digest();
  return createHash("sha256").update(once).digest();
}

interface Frame {
  command: string;
  payload: Buffer;
}

/** Frame a v1 byte stream. Does not import hotbuns message codecs. */
function frameV1(buf: Buffer, magic: number): { frames: Frame[]; rest: number } {
  const frames: Frame[] = [];
  let off = 0;
  while (off + 24 <= buf.length) {
    const magicGot = buf.readUInt32LE(off);
    if (magicGot !== magic) {
      throw new Error(`bad magic at ${off}: ${magicGot.toString(16)}`);
    }
    const cmdBuf = buf.subarray(off + 4, off + 16);
    let end = 0;
    while (end < 12 && cmdBuf[end] !== 0) {
      const c = cmdBuf[end];
      if (c < 0x20 || c > 0x7e) throw new Error("non-ascii command");
      end++;
    }
    for (let i = end; i < 12; i++) {
      if (cmdBuf[i] !== 0) throw new Error("command padding");
    }
    const command = cmdBuf.toString("ascii", 0, end);
    const len = buf.readUInt32LE(off + 16);
    if (len > 4_000_000) throw new Error(`len ${len}`);
    if (off + 24 + len > buf.length) break;
    const payload = Buffer.from(buf.subarray(off + 24, off + 24 + len));
    const sum = buf.subarray(off + 20, off + 24);
    const expectSum = sha256d(payload).subarray(0, 4);
    if (!sum.equals(expectSum)) {
      throw new Error(
        `checksum ${command}: got ${sum.toString("hex")} expected ${expectSum.toString("hex")}`,
      );
    }
    frames.push({ command, payload });
    off += 24 + len;
  }
  return { frames, rest: buf.length - off };
}

function parseInv(payload: Buffer): { type: number; hash: Buffer }[] {
  if (payload.length < 1) throw new Error("empty inv");
  let off = 0;
  const first = payload[off++];
  let count: number;
  if (first < 0xfd) {
    count = first;
  } else if (first === 0xfd) {
    count = payload.readUInt16LE(off);
    off += 2;
  } else {
    throw new Error(`unexpected compact size ${first}`);
  }
  const items: { type: number; hash: Buffer }[] = [];
  for (let i = 0; i < count; i++) {
    if (off + 36 > payload.length) throw new Error("short inv");
    const type = payload.readUInt32LE(off);
    off += 4;
    items.push({ type, hash: Buffer.from(payload.subarray(off, off + 32)) });
    off += 32;
  }
  if (off !== payload.length) throw new Error(`inv tail ${payload.length - off}`);
  return items;
}

function makeTx(seq: number): Transaction {
  return {
    version: 2,
    inputs: [
      {
        prevOut: { txid: Buffer.alloc(32, seq & 0xff), vout: seq },
        scriptSig: Buffer.from([0x51]),
        sequence: 0xffffffff,
        witness: [],
      },
    ],
    outputs: [{ value: 1000n, scriptPubKey: Buffer.from([0x51]) }],
    lockTime: 0,
  };
}

async function openSync(): Promise<{
  dir: string;
  db: ChainDB;
  sync: BlockSync;
}> {
  const dir = await mkdtemp(join(tmpdir(), "hotbuns-notfound-"));
  const db = new ChainDB(join(dir, "blocks.db"));
  await db.open();
  const headerSync = new HeaderSync(db, REGTEST);
  const sync = new BlockSync(db, REGTEST, headerSync);
  return { dir, db, sync };
}

async function closeSync(dir: string, db: ChainDB): Promise<void> {
  await db.close();
  await rm(dir, { recursive: true, force: true });
}

function waitFor(cond: () => boolean, timeoutMs: number, label: string): Promise<void> {
  const start = Date.now();
  return new Promise((resolve, reject) => {
    const tick = () => {
      try {
        if (cond()) {
          resolve();
          return;
        }
      } catch (err) {
        reject(err);
        return;
      }
      if (Date.now() - start > timeoutMs) {
        reject(new Error(`${label} timeout after ${timeoutMs}ms`));
        return;
      }
      setTimeout(tick, 10);
    };
    tick();
  });
}

describe("notfound reaches a peer", () => {
  test(
    "v1 getdata miss: peer reads a checksum-valid notfound, not a block",
    async () => {
      const { dir, db, sync } = await openSync();
      const tx = makeTx(7);
      const knownTxid = getTxId(tx);
      const missTx = Buffer.alloc(32, 0x22);
      const missBlock = Buffer.alloc(32, 0x33);
      const missWtx = Buffer.alloc(32, 0x44);
      const missWitness = Buffer.alloc(32, 0x55);
      sync.setMempool({
        getTransaction(hash: Buffer) {
          return hash.equals(knownTxid) ? { tx } : null;
        },
        getTransactionByWtxidHex(hex: string) {
          return hex === getWTxId(tx).toString("hex") ? { tx } : null;
        },
      } as any);

      const mgr = new PeerManager({
        maxOutbound: 0,
        maxInbound: 8,
        maxOutboundFullRelay: 0,
        maxOutboundBlockRelay: 0,
        params: REGTEST,
        bestHeight: 0,
        datadir: dir,
        listen: true,
        dnsSeed: false,
        port: 0,
        bind: ["127.0.0.1"],
        handshakeTimeoutMs: 10_000,
      } satisfies PeerManagerConfig);
      sync.registerWithPeerManager(mgr);

      const chunks: Buffer[] = [];
      let sock: Socket<undefined> | null = null;
      try {
        await mgr.start();
        const port = mgr.getListeningBinds()[0].port;
        sock = await Bun.connect({
          hostname: "127.0.0.1",
          port,
          socket: {
            data(_s, data) {
              chunks.push(Buffer.from(data));
            },
            open() {},
            close() {},
            error() {},
          },
        });

        const send = (msg: NetworkMessage) => {
          if (!sock) throw new Error("socket closed");
          const n = sock.write(serializeMessage(REGTEST.networkMagic, msg));
          if (n < 0) throw new Error(`client write failed (${n})`);
        };

        const now = BigInt(Math.floor(Date.now() / 1000));
        send({
          type: "version",
          payload: {
            version: 70016,
            services: 0x409n,
            timestamp: now,
            addrRecv: { services: 0n, ip: ipv4ToBuffer("127.0.0.1"), port: 0 },
            addrFrom: { services: 0x409n, ip: ipv4ToBuffer("127.0.0.1"), port: 1 },
            nonce: BigInt(Math.floor(Math.random() * Number.MAX_SAFE_INTEGER)),
            userAgent: "/notfound-peer:0.0.1/",
            startHeight: 0,
            relay: true,
          },
        });

        await waitFor(() => {
          const { frames } = frameV1(Buffer.concat(chunks), REGTEST.networkMagic);
          return frames.some((f) => f.command === "verack");
        }, 3000, "verack");
        send({ type: "verack", payload: null });
        await waitFor(
          () => mgr.getConnectedPeers().some((p) => p.state === "connected"),
          3000,
          "connected",
        );

        send({
          type: "getdata",
          payload: {
            inventory: [
              { type: InvType.MSG_TX, hash: knownTxid },
              { type: InvType.MSG_TX, hash: missTx },
              { type: InvType.MSG_BLOCK, hash: missBlock },
              { type: InvType.MSG_WTX, hash: missWtx },
              { type: InvType.MSG_WITNESS_TX, hash: missWitness },
            ],
          },
        });

        let frames: Frame[] = [];
        await waitFor(() => {
          const parsed = frameV1(Buffer.concat(chunks), REGTEST.networkMagic);
          frames = parsed.frames;
          return (
            parsed.rest === 0 &&
            frames.some((f) => f.command === "notfound") &&
            frames.some((f) => f.command === "tx")
          );
        }, 3000, "notfound frame");

        const nf = frames.filter((f) => f.command === "notfound");
        expect(nf.length).toBe(1);
        const items = parseInv(nf[0].payload);
        expect(items.map((i) => i.type)).toEqual([
          InvType.MSG_TX,
          InvType.MSG_WTX,
          InvType.MSG_WITNESS_TX,
        ]);
        expect(items[0].hash.equals(missTx)).toBe(true);
        expect(items[1].hash.equals(missWtx)).toBe(true);
        expect(items[2].hash.equals(missWitness)).toBe(true);
        // Core does not notfound a block it does not have.
        expect(items.some((i) => i.hash.equals(missBlock))).toBe(false);
        expect(items.some((i) => i.hash.equals(knownTxid))).toBe(false);
        expect(frames.some((f) => f.command === "block")).toBe(false);

        // Negative control: same checksum, one payload byte flipped.
        const good = nf[0].payload;
        const flipped = Buffer.from(good);
        flipped[flipped.length - 1] ^= 0xff;
        const header = Buffer.alloc(24);
        header.writeUInt32LE(REGTEST.networkMagic, 0);
        header.write("notfound", 4, "ascii");
        header.writeUInt32LE(flipped.length, 16);
        sha256d(good).copy(header, 20, 0, 4);
        expect(() => frameV1(Buffer.concat([header, flipped]), REGTEST.networkMagic)).toThrow(
          /checksum/,
        );
      } finally {
        sock?.end();
        await mgr.stop();
        await closeSync(dir, db);
      }
    },
    TEST_TIMEOUT,
  );

  test(
    "v2 getdata miss: responder decrypts notfound short-id 17",
    async () => {
      const { dir, db, sync } = await openSync();
      const tx = makeTx(9);
      const knownTxid = getTxId(tx);
      const missTx = Buffer.alloc(32, 0x66);
      sync.setMempool({
        getTransaction(hash: Buffer) {
          return hash.equals(knownTxid) ? { tx } : null;
        },
        getTransactionByWtxidHex() {
          return null;
        },
      } as any);

      // BIP-324 assigned id. Core net.cpp V2_MESSAGE_IDS[17] == NOTFOUND.
      expect(encodeMessageType("notfound").equals(Buffer.from([17]))).toBe(true);

      const magicLE = Buffer.alloc(4);
      magicLE.writeUInt32LE(REGTEST.networkMagic, 0);
      const written: Buffer[] = [];
      const stub = {
        write(data: Buffer | Uint8Array | string): number {
          const buf = Buffer.from(data as Uint8Array);
          written.push(buf);
          return buf.length;
        },
        end() {},
        remoteAddress: "127.0.0.1",
      };
      const events: PeerEvents = {
        onConnect: () => {},
        onDisconnect: () => {},
        onMessage: () => {},
        onHandshakeComplete: () => {},
      };
      const config: PeerConfig = {
        host: "127.0.0.1",
        port: 0,
        magic: REGTEST.networkMagic,
        protocolVersion: 70016,
        services: 0n,
        userAgent: "/notfound-v2:0.0.1/",
        bestHeight: 0,
        relay: true,
      };
      const peer = new Peer(config, events);
      try {
        const p = peer as any;
        p.socket = stub;
        p.state = "handshaking";
        p.prepareV2Outbound();
        p.flushV2SendBuffer();

        const responder = new V2Transport(magicLE, false);
        const r1 = responder.receiveBytes(Buffer.concat(written));
        expect(r1.error).toBeUndefined();
        written.length = 0;
        peer.feedData(responder.consumeSendBuffer());
        const r2 = responder.receiveBytes(Buffer.concat(written));
        expect(r2.error).toBeUndefined();
        expect(responder.isVersionReceived()).toBe(true);
        responder.getReceivedMessages();
        written.length = 0;

        await (sync as any).handleGetData(peer, [
          { type: InvType.MSG_TX, hash: knownTxid },
          { type: InvType.MSG_TX, hash: missTx },
          { type: InvType.MSG_BLOCK, hash: Buffer.alloc(32, 0x77) },
        ]);

        const r3 = responder.receiveBytes(Buffer.concat(written));
        expect(r3.error).toBeUndefined();
        const msgs = responder.getReceivedMessages();
        expect(msgs.map((m) => m.type)).toEqual(["tx", "notfound"]);
        const items = parseInv(msgs[1].payload);
        expect(items.length).toBe(1);
        expect(items[0].type).toBe(InvType.MSG_TX);
        expect(items[0].hash.equals(missTx)).toBe(true);
      } finally {
        peer.disconnect();
        await closeSync(dir, db);
      }
    },
    TEST_TIMEOUT,
  );

  test("notfound: a send that returns false did not reach the peer", async () => {
    const { dir, db, sync } = await openSync();
    try {
      const missing = Buffer.alloc(32, 0xab);
      const peer = {
        host: "10.0.0.9",
        port: 8333,
        send() {
          return false;
        },
      };
      await expect(
        (sync as any).handleGetData(peer, [{ type: InvType.MSG_TX, hash: missing }]),
      ).rejects.toThrow(/notfound did not reach 10\.0\.0\.9:8333/);
    } finally {
      await closeSync(dir, db);
    }
  });
});
