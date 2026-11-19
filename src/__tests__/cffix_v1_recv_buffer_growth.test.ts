/**
 * cffix-hotbuns-v1-recv-buffer-growth
 * (fingerprint hotbuns:p2p:recv-partial-message-full-recopy-per-read)
 *
 * Peer.onData rebuilt the v1 receive buffer on every socket read
 * (allocUnsafe(old + new) and a copy of the whole partial message), and
 * V2Transport.receiveBytes did the same with Buffer.concat plus a Buffer.from
 * copy of the remainder per consumed chunk. A peer that drips one 4 MB message
 * in 1,000-byte reads therefore cost ~8 GB of memcpy (~2,000x the message).
 *
 * Core (net.cpp V1Transport::readData) appends in place into a vector it
 * grows geometrically, so copying is amortized O(n). These tests count every
 * byte the Buffer allocators hand out while the message is fed in and require
 * the total to stay a small constant multiple of the message size. They also
 * check the reassembled bytes: the v1 message must pass its checksum and the
 * v2 packet must decrypt (AEAD), and a one-byte corruption must be caught, so
 * a "fix" that loses or reorders bytes cannot pass.
 */

import { afterEach, describe, expect, test } from "bun:test";
import { randomBytes } from "crypto";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { Peer, type PeerConfig, type PeerEvents } from "../p2p/peer.js";
import { serializeHeader } from "../p2p/messages.js";
import { V2Transport, RecvState } from "../p2p/v2_transport.js";
import { REGTEST } from "../consensus/params.js";

const MSG_TOTAL = 4_000_000;
const CHUNK = 1_000;
const MAX_COPY_FACTOR = 3;
// v2 also counts the plaintext decrypt() allocates for the packet (1x) on top
// of the receive buffer's geometric growth (< 2x + one read), so its bound is
// one message size higher. Base is ~2,000x on both.
const MAX_COPY_FACTOR_V2 = 4;

// ---------------------------------------------------------------- allocation
// counting: wrap every Buffer allocator and sum the bytes it returns.

type AnyFn = (...args: any[]) => any;
const B = Buffer as unknown as Record<string, AnyFn>;
const ALLOCATORS = ["allocUnsafe", "allocUnsafeSlow", "alloc", "from", "concat"];
const originals = new Map<string, AnyFn>();
let allocated = 0;
let counting = false;

function startCounting(): void {
  allocated = 0;
  for (const name of ALLOCATORS) {
    const orig = B[name];
    originals.set(name, orig);
    B[name] = function (this: unknown, ...args: any[]) {
      const out = orig.apply(this, args);
      if (counting && out && typeof out.length === "number") allocated += out.length;
      return out;
    };
  }
  counting = true;
}

function stopCounting(): number {
  counting = false;
  for (const [name, orig] of originals) B[name] = orig;
  originals.clear();
  return allocated;
}

afterEach(() => {
  if (originals.size > 0) stopCounting();
});

// ---------------------------------------------------------------- v1 helpers

function makeV1Peer() {
  const config: PeerConfig = {
    host: "127.0.0.1",
    port: 18444,
    magic: REGTEST.networkMagic,
    protocolVersion: 70016,
    services: 0n,
    userAgent: "/test:0.0.1/",
    bestHeight: 0,
    relay: true,
  };
  const events = {
    onMessage: () => {},
    onDisconnect: () => {},
    onHandshakeComplete: () => {},
  } as unknown as PeerEvents;
  const peer = new Peer(config, events);
  const p = peer as any;
  p.transportMode = "v1";
  const dispatched: { type: string }[] = [];
  const disconnects: string[] = [];
  p.handleMessage = (msg: { type: string }) => dispatched.push(msg);
  p.disconnect = (reason?: string) => disconnects.push(String(reason));
  const feed = (data: Buffer) => p.onData(data);
  return { p, feed, dispatched, disconnects };
}

/** A v1 message of exactly `total` bytes with an unknown command. */
function v1Message(command: string, total: number): Buffer {
  const payload = randomBytes(total - 24);
  return Buffer.concat([serializeHeader(REGTEST.networkMagic, command, payload), payload]);
}

function chunks(buf: Buffer, size: number): Buffer[] {
  const out: Buffer[] = [];
  for (let i = 0; i < buf.length; i += size) {
    out.push(Buffer.from(buf.subarray(i, Math.min(i + size, buf.length))));
  }
  return out;
}

describe("v1 receive buffer grows geometrically (Core V1Transport::readData)", () => {
  test("a 4,000,000-byte message in 4,000 reads of 1,000 bytes copies < 3x its size", () => {
    const { feed, dispatched, disconnects } = makeV1Peer();
    const msg = v1Message("zzunknown", MSG_TOTAL);
    const parts = chunks(msg, CHUNK);
    expect(parts.length).toBe(4000);

    startCounting();
    for (const part of parts) feed(part);
    const copied = stopCounting();

    // The message was reassembled intact (checksum over all 3,999,976 payload
    // bytes) and dispatched exactly once.
    expect(disconnects).toEqual([]);
    expect(dispatched.map((m) => m.type)).toEqual(["zzunknown"]);
    console.log(`v1: ${copied} bytes allocated for a ${MSG_TOTAL}-byte message (${(copied / MSG_TOTAL).toFixed(2)}x)`);
    expect(copied).toBeLessThan(MAX_COPY_FACTOR * MSG_TOTAL);
  });

  test("random chunking across several messages reassembles every one in order", () => {
    const { p, feed, dispatched, disconnects } = makeV1Peer();
    const msgs = [
      v1Message("zza", 300_000),
      v1Message("zzb", 24),
      v1Message("zzc", 1_000_000),
      v1Message("zzd", 25),
      v1Message("zze", 70_000),
    ];
    const wire = Buffer.concat(msgs);
    let i = 0;
    let seed = 7;
    while (i < wire.length) {
      seed = (seed * 1103515245 + 12345) & 0x7fffffff;
      const n = 1 + (seed % 9000);
      feed(Buffer.from(wire.subarray(i, Math.min(i + n, wire.length))));
      i += n;
    }
    expect(disconnects).toEqual([]);
    expect(dispatched.map((m) => m.type)).toEqual(["zza", "zzb", "zzc", "zzd", "zze"]);
    expect(p.getRecvQueueBytes()).toBe(0);
  });

  test("negative control: one flipped payload byte fails the checksum", () => {
    const { feed, dispatched, disconnects } = makeV1Peer();
    const msg = v1Message("zzunknown", MSG_TOTAL);
    msg[2_345_678] ^= 0x01;
    for (const part of chunks(msg, CHUNK)) feed(part);
    expect(dispatched).toEqual([]);
    expect(disconnects.length).toBe(1);
    expect(disconnects[0]).toContain("Checksum mismatch");
  });
});

// ---------------------------------------------------------------- v2 helpers

const MAINNET_MAGIC = Buffer.from([0xf9, 0xbe, 0xb4, 0xd9]);

function randPriv(): Buffer {
  let k = randomBytes(32);
  while (!secp256k1.utils.isValidSecretKey(k)) k = randomBytes(32);
  return k;
}

/** Initiator and responder, handshake done, responder in APP. */
function makeReadyPair() {
  const initiator = V2Transport.withParams(MAINNET_MAGIC, true, randPriv(), randomBytes(32), Buffer.alloc(0));
  const responder = V2Transport.withParams(MAINNET_MAGIC, false, randPriv(), randomBytes(32), Buffer.alloc(0));
  responder.receiveBytes(initiator.consumeSendBuffer());
  initiator.receiveBytes(responder.consumeSendBuffer());
  responder.receiveBytes(initiator.consumeSendBuffer());
  expect(responder.getRecvState()).toBe(RecvState.APP);
  expect(responder.getReceivedMessages()).toEqual([]);
  return { initiator, responder };
}

describe("v2 receive buffer grows geometrically", () => {
  test("a ~4 MB packet in 1,000-byte reads copies < 4x its size (decrypt included)", () => {
    const { initiator, responder } = makeReadyPair();
    const payload = randomBytes(3_999_000);
    const packet = initiator.encryptMessage("ping", payload);
    const parts = chunks(packet, CHUNK);

    startCounting();
    for (const part of parts) {
      const r = responder.receiveBytes(part);
      expect(r.error).toBeUndefined();
    }
    const copied = stopCounting();

    const msgs = responder.getReceivedMessages();
    expect(msgs.length).toBe(1);
    expect(msgs[0].type).toBe("ping");
    expect(msgs[0].payload.equals(payload)).toBe(true);
    console.log(`v2: ${copied} bytes allocated for a ${packet.length}-byte packet (${(copied / packet.length).toFixed(2)}x)`);
    expect(copied).toBeLessThan(MAX_COPY_FACTOR_V2 * packet.length);
  });

  test("random chunking across several packets decrypts every one in order", () => {
    const { initiator, responder } = makeReadyPair();
    const payloads = [randomBytes(500_000), randomBytes(0), randomBytes(3), randomBytes(1_200_000)];
    const wire = Buffer.concat(payloads.map((pl) => initiator.encryptMessage("ping", pl)));
    let i = 0;
    let seed = 11;
    while (i < wire.length) {
      seed = (seed * 1103515245 + 12345) & 0x7fffffff;
      const n = 1 + (seed % 7000);
      const r = responder.receiveBytes(Buffer.from(wire.subarray(i, Math.min(i + n, wire.length))));
      expect(r.error).toBeUndefined();
      i += n;
    }
    const msgs = responder.getReceivedMessages();
    expect(msgs.length).toBe(payloads.length);
    msgs.forEach((m, k) => expect(m.payload.equals(payloads[k])).toBe(true));
  });

  test("negative control: one flipped ciphertext byte fails decryption", () => {
    const { initiator, responder } = makeReadyPair();
    const packet = initiator.encryptMessage("ping", randomBytes(3_999_000));
    packet[2_345_678] ^= 0x01;
    let err: string | undefined;
    for (const part of chunks(packet, CHUNK)) {
      const r = responder.receiveBytes(part);
      if (r.error) err = r.error;
    }
    expect(err).toBe("Decryption failed");
    expect(responder.getReceivedMessages()).toEqual([]);
  });
});

// ---------------------------------------------------------------- aliasing
// A v1 payload is handed to a sliced parse as a VIEW and parsed across
// macrotasks while later reads are appended, and parsed messages may keep
// views of it. An in-place buffer must therefore never rewrite a byte it has
// handed out. Loaded dynamically so this file still loads on the base commit
// (where the module does not exist) and fails here by assertion.

describe("RecvBuffer never rewrites bytes it has handed out", () => {
  test("views taken before append / growth / drain keep their bytes", async () => {
    const mod = await import("../p2p/recv_buffer.js").catch(() => null);
    expect(mod).not.toBeNull();
    const rb = new mod!.RecvBuffer();
    const a = randomBytes(1000);
    rb.append(a);
    const v1 = rb.view().subarray(0, 600);
    const v1Copy = Buffer.from(v1);
    rb.consume(600);
    // Appends into spare capacity, then growth past it.
    for (let i = 0; i < 50; i++) rb.append(randomBytes(777));
    expect(v1.equals(v1Copy)).toBe(true);
    // Drain to empty, then refill: must not reuse the old store from offset 0.
    const v2 = rb.view();
    const v2Copy = Buffer.from(v2);
    rb.consume(rb.length);
    expect(rb.length).toBe(0);
    rb.append(randomBytes(rb.length + 40_000));
    expect(v2.equals(v2Copy)).toBe(true);
    expect(v1.equals(v1Copy)).toBe(true);
    // The live bytes are exactly what was appended after the drain.
    const tail = randomBytes(5);
    const before = Buffer.from(rb.view());
    rb.append(tail);
    expect(rb.view().equals(Buffer.concat([before, tail]))).toBe(true);
  });
});
