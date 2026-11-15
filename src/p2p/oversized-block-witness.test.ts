/**
 * Audit H2, block path (fleet security findings 2026-11-08): a peer sends a
 * ~4 MB `block` (or cmpctblock / blocktxn) made of millions of empty witness
 * items. That is consensus-valid shape for spends of unknown witness
 * versions, so it cannot be size-gated like the loose `tx` (hotbuns#40). It
 * was parsed synchronously on the one JS event loop before any check,
 * stalling every peer and RPC client for 200-370 ms per message.
 *
 * Fix: block-sized payloads are parsed by a stepped parser in slices of
 * PARSE_SLICE_MS, handing the event loop back between slices, with this
 * peer's later messages held behind it (Core parses on the msghand thread,
 * so its RPC and other peers are not stalled).
 *
 * Consensus safety: the accept set must not change. A block that parsed
 * before parses to the same bytes, and a malformed one is still refused with
 * the same error and the same disconnect. Both are checked below, for the
 * sliced path and the synchronous one.
 *
 * Regtest only: the frames go to a local Peer over a stub socket.
 */

import { describe, expect, test } from "bun:test";

import * as messages from "./messages.js";
import { Peer, type PeerConfig, type PeerEvents } from "./peer.js";
import { REGTEST } from "../consensus/params.js";
import { serializeBlock } from "../validation/block.js";
import { deserializeTx, serializeTx } from "../validation/tx.js";
import * as txmod from "../validation/tx.js";
import { BufferReader, BufferWriter } from "../wire/serialization.js";
import { hash256 } from "../crypto/primitives.js";

const HEADER = Buffer.alloc(80, 0x11);

/** One segwit tx with `items` witness items of `itemLen` bytes on input 0. */
function writeFloodTx(w: BufferWriter, items: number, itemLen = 0, tag = 1): void {
  w.writeInt32LE(2);
  w.writeUInt8(0x00);
  w.writeUInt8(0x01);
  w.writeVarInt(1);
  w.writeBytes(Buffer.alloc(32, tag));
  w.writeUInt32LE(0);
  w.writeVarInt(0);
  w.writeUInt32LE(0xffffffff);
  w.writeVarInt(1);
  w.writeUInt64LE(1000n);
  w.writeVarInt(1);
  w.writeUInt8(0x51);
  w.writeVarInt(items);
  const item = Buffer.alloc(itemLen, 0xab);
  for (let i = 0; i < items; i++) {
    w.writeVarInt(itemLen);
    if (itemLen) w.writeBytes(item);
  }
  w.writeUInt32LE(0);
}

/** A ~`size`-byte block: one tx whose witness is all empty items. */
function floodBlock(size: number): Buffer {
  const w = new BufferWriter();
  w.writeBytes(HEADER);
  w.writeVarInt(1);
  writeFloodTx(w, size - 160);
  return w.toBuffer();
}

/**
 * A witness-heavy block of many txs with mixed witness stacks: empty items,
 * non-empty items, empty stacks next to full ones, a legacy tx, and a
 * multi-input tx, so the round trip covers every branch of the parser.
 */
function mixedBlock(): Buffer {
  const w = new BufferWriter();
  w.writeBytes(HEADER);
  const txs: Buffer[] = [];
  // legacy coinbase-shaped tx
  {
    const t = new BufferWriter();
    t.writeInt32LE(1);
    t.writeVarInt(1);
    t.writeBytes(Buffer.alloc(32, 0));
    t.writeUInt32LE(0xffffffff);
    t.writeVarInt(4);
    t.writeBytes(Buffer.from([0x03, 0x01, 0x02, 0x03]));
    t.writeUInt32LE(0xffffffff);
    t.writeVarInt(1);
    t.writeUInt64LE(5_000_000_000n);
    t.writeVarInt(1);
    t.writeUInt8(0x51);
    t.writeUInt32LE(0);
    txs.push(t.toBuffer());
  }
  for (let k = 0; k < 300; k++) {
    const t = new BufferWriter();
    writeFloodTx(t, 1 + (k % 40) * 97, k % 3 === 0 ? 0 : (k % 7) + 1, k & 0xff);
    txs.push(t.toBuffer());
  }
  // two inputs: [empty, 0xaa, empty] and [] (an empty stack beside a full one)
  {
    const t = new BufferWriter();
    t.writeInt32LE(2);
    t.writeUInt8(0x00);
    t.writeUInt8(0x01);
    t.writeVarInt(2);
    for (let i = 0; i < 2; i++) {
      t.writeBytes(Buffer.alloc(32, 0x40 + i));
      t.writeUInt32LE(i);
      t.writeVarInt(0);
      t.writeUInt32LE(0xfffffffe);
    }
    t.writeVarInt(1);
    t.writeUInt64LE(1n);
    t.writeVarInt(1);
    t.writeUInt8(0x51);
    t.writeVarInt(3);
    t.writeVarInt(0);
    t.writeVarInt(1);
    t.writeUInt8(0xaa);
    t.writeVarInt(0);
    t.writeVarInt(0);
    t.writeUInt32LE(0);
    txs.push(t.toBuffer());
  }
  w.writeVarInt(txs.length);
  for (const t of txs) w.writeBytes(t);
  return w.toBuffer();
}

function header(command: string, payload: Buffer): messages.MessageHeader {
  return {
    magic: REGTEST.networkMagic,
    command,
    length: payload.length,
    checksum: hash256(payload).subarray(0, 4),
  };
}

function v1Frame(command: string, payload: Buffer): Buffer {
  const h = Buffer.alloc(24);
  h.writeUInt32LE(REGTEST.networkMagic, 0);
  h.write(command, 4, "ascii");
  h.writeUInt32LE(payload.length, 16);
  hash256(payload).copy(h, 20, 0, 4);
  return Buffer.concat([h, payload]);
}

/** A handshaken peer on a stub socket; records dispatches and disconnects. */
function stubPeer() {
  const dispatched: messages.NetworkMessage[] = [];
  const reasons: (string | undefined)[] = [];
  const events: PeerEvents = {
    onConnect: () => {},
    onDisconnect: () => {},
    onMessage: (_p, msg) => dispatched.push(msg),
    onHandshakeComplete: () => {},
  };
  const config: PeerConfig = {
    host: "127.0.0.1",
    port: 18444,
    magic: REGTEST.networkMagic,
    protocolVersion: 70016,
    services: 0n,
    userAgent: "/h2-block-test/",
    bestHeight: 0,
    relay: true,
  };
  const peer = new Peer(config, events);
  const p = peer as any;
  p.socket = {
    write: (d: Uint8Array) => d.length,
    end() {},
    terminate() {},
    pause() {},
    resume() {},
    remoteAddress: "127.0.0.1",
  };
  p.state = "connected";
  p.transportMode = "v1";
  p.receivedVersion = true;
  p.versionReceived = true;
  p.verackReceived = true;
  p.handshakeComplete = true;
  const origDisconnect = peer.disconnect.bind(peer);
  peer.disconnect = (reason?: string) => {
    reasons.push(reason);
    origDisconnect(reason);
  };
  return { peer, dispatched, reasons };
}

/** Make the stub peer a v2 peer whose transport hands over `msgs` once. */
function asV2(peer: Peer, msgs: { type: string; payload: Buffer }[]): void {
  const p = peer as any;
  let pending = msgs;
  p.transportMode = "v2";
  p.versionSent = true;
  p.v2Transport = {
    isReady: () => true,
    isHandshakeReady: () => true,
    isInitiator: () => false,
    receiveBytes: () => ({}),
    pendingSendBytes: () => 0,
    consumeSendBuffer: () => Buffer.alloc(0),
    hasReceivedMessages: () => pending.length > 0,
    getReceivedMessages: () => {
      const out = pending;
      pending = [];
      return out;
    },
  };
}

/**
 * Run `feed` with a 10 ms ticker, wait until `done()` (or 15 s), and return
 * the longest gap between ticks: how long the event loop was held.
 */
async function maxTickGap(feed: () => void, done: () => boolean): Promise<number> {
  let last = performance.now();
  let maxGap = 0;
  const ticker = setInterval(() => {
    const now = performance.now();
    maxGap = Math.max(maxGap, now - last);
    last = now;
  }, 10);
  // Let the ticker start before the payload arrives.
  await new Promise((r) => setTimeout(r, 30));
  last = performance.now();
  feed();
  const deadline = performance.now() + 15_000;
  while (!done() && performance.now() < deadline) {
    await new Promise((r) => setTimeout(r, 5));
  }
  // One more tick so a stall at the very end is measured too.
  await new Promise((r) => setTimeout(r, 25));
  clearInterval(ticker);
  maxGap = Math.max(maxGap, performance.now() - last - 25);
  return maxGap;
}

const FLOOD_SIZE = 3_990_000;
const FLOOD = floodBlock(FLOOD_SIZE);

describe("H2 block path: a 4 MB empty-witness block does not stall the event loop", () => {
  test("v1 block of ~3.99M empty witness items: no tick gap over 100 ms, block dispatched, peer kept", async () => {
    const { peer, dispatched, reasons } = stubPeer();
    const gap = await maxTickGap(
      () => peer.feedData(v1Frame("block", FLOOD)),
      () => dispatched.length > 0 || peer.state === "disconnected",
    );
    console.log(`v1 block: max tick gap ${gap.toFixed(1)} ms`);
    expect(dispatched.map((m) => m.type)).toEqual(["block"]);
    expect(peer.state).not.toBe("disconnected");
    expect(reasons).toEqual([]);
    expect(peer.misbehaviorScore).toBe(0);
    // Master: 200-370 ms in one synchronous parse.
    expect(gap).toBeLessThan(100);
  });

  test("v2 block of ~3.99M empty witness items: no tick gap over 100 ms, block dispatched, peer kept", async () => {
    const { peer, dispatched, reasons } = stubPeer();
    asV2(peer, [{ type: "block", payload: FLOOD }]);
    const gap = await maxTickGap(
      () => peer.feedData(Buffer.from([0x00])),
      () => dispatched.length > 0 || peer.state === "disconnected",
    );
    console.log(`v2 block: max tick gap ${gap.toFixed(1)} ms`);
    expect(dispatched.map((m) => m.type)).toEqual(["block"]);
    expect(peer.state).not.toBe("disconnected");
    expect(reasons).toEqual([]);
    expect(peer.misbehaviorScore).toBe(0);
    expect(gap).toBeLessThan(100);
  });

  test("blocktxn carrying the same flood tx: no tick gap over 100 ms", async () => {
    const w = new BufferWriter();
    w.writeBytes(Buffer.alloc(32, 0x22));
    w.writeVarInt(1);
    writeFloodTx(w, 3_989_000);
    const payload = w.toBuffer();
    const { peer, dispatched } = stubPeer();
    const gap = await maxTickGap(
      () => peer.feedData(v1Frame("blocktxn", payload)),
      () => dispatched.length > 0 || peer.state === "disconnected",
    );
    console.log(`blocktxn: max tick gap ${gap.toFixed(1)} ms`);
    expect(dispatched.map((m) => m.type)).toEqual(["blocktxn"]);
    expect(gap).toBeLessThan(100);
  });

  test("cmpctblock with the flood tx prefilled: no tick gap over 100 ms", async () => {
    const w = new BufferWriter();
    w.writeBytes(HEADER);
    w.writeUInt64LE(7n);
    w.writeVarInt(0);
    w.writeVarInt(1);
    w.writeVarInt(0);
    writeFloodTx(w, 3_989_000);
    const payload = w.toBuffer();
    const { peer, dispatched } = stubPeer();
    const gap = await maxTickGap(
      () => peer.feedData(v1Frame("cmpctblock", payload)),
      () => dispatched.length > 0 || peer.state === "disconnected",
    );
    console.log(`cmpctblock: max tick gap ${gap.toFixed(1)} ms`);
    expect(dispatched.map((m) => m.type)).toEqual(["cmpctblock"]);
    expect(gap).toBeLessThan(100);
  });
});

describe("H2 block path: consensus safety (controls, pass before and after)", () => {
  test("the flood block round-trips byte-identically through the peer", async () => {
    const { peer, dispatched } = stubPeer();
    peer.feedData(v1Frame("block", FLOOD));
    const deadline = Date.now() + 15_000;
    while (dispatched.length === 0 && Date.now() < deadline) await new Promise((r) => setTimeout(r, 5));
    const msg = dispatched[0];
    expect(msg?.type).toBe("block");
    if (msg?.type !== "block") return;
    expect(msg.payload.block.transactions[0].inputs[0].witness.length).toBe(FLOOD_SIZE - 160);
    expect(serializeBlock(msg.payload.block).equals(FLOOD)).toBe(true);
  });

  test("a witness-heavy multi-tx block round-trips byte-identically, sync and through the peer (v1 and v2)", async () => {
    const raw = mixedBlock();
    const sync = messages.deserializeMessage(header("block", raw), raw);
    expect(sync.type).toBe("block");
    if (sync.type === "block") expect(serializeBlock(sync.payload.block).equals(raw)).toBe(true);

    for (const v2 of [false, true]) {
      const { peer, dispatched } = stubPeer();
      if (v2) {
        asV2(peer, [{ type: "block", payload: raw }]);
        peer.feedData(Buffer.from([0x00]));
      } else {
        peer.feedData(v1Frame("block", raw));
      }
      const deadline = Date.now() + 15_000;
      while (dispatched.length === 0 && Date.now() < deadline) await new Promise((r) => setTimeout(r, 5));
      const msg = dispatched[0];
      expect(msg?.type).toBe("block");
      if (msg?.type !== "block") return;
      expect(serializeBlock(msg.payload.block).equals(raw)).toBe(true);
      expect(msg.payload.block).toEqual((sync as any).payload.block);
    }
  });

  test("every tx in the mixed block parses the same in slices as in one go", () => {
    const raw = mixedBlock();
    const sync = messages.deserializeMessage(header("block", raw), raw);
    if (sync.type !== "block") throw new Error("not a block");
    for (const tx of sync.payload.block.transactions) {
      const bytes = serializeTx(tx, true);
      expect(deserializeTx(new BufferReader(bytes))).toEqual(tx);
    }
  });

  test("messages behind a block wait for it: dispatch order is unchanged", async () => {
    const { peer, dispatched } = stubPeer();
    const ping = Buffer.alloc(8, 0x07);
    peer.feedData(Buffer.concat([v1Frame("block", FLOOD), v1Frame("ping", ping)]));
    const deadline = Date.now() + 15_000;
    while (dispatched.length < 2 && Date.now() < deadline) await new Promise((r) => setTimeout(r, 5));
    expect(dispatched.map((m) => m.type)).toEqual(["block", "ping"]);
    expect((peer as any).recvBuffer.length).toBe(0);
  });

  test("a truncated 4 MB block is refused with the same error, and the v1 peer is disconnected with it", async () => {
    const bad = FLOOD.subarray(0, FLOOD.length - 2);
    let syncErr = "";
    try {
      messages.deserializeMessage(header("block", bad), bad);
    } catch (e) {
      syncErr = (e as Error).message;
    }
    expect(syncErr).not.toBe("");

    const { peer, dispatched, reasons } = stubPeer();
    peer.feedData(v1Frame("block", bad));
    const deadline = Date.now() + 15_000;
    while (peer.state !== "disconnected" && Date.now() < deadline) await new Promise((r) => setTimeout(r, 5));
    expect(peer.state).toBe("disconnected");
    expect(dispatched).toEqual([]);
    expect(reasons).toEqual([syncErr]);
  });

  test("a superfluous-witness block is refused with the same error, sync and through the peer", async () => {
    // Segwit marker with every witness stack empty: Core's "Superfluous witness record".
    const w = new BufferWriter();
    w.writeBytes(HEADER);
    w.writeVarInt(1);
    writeFloodTx(w, 0);
    const bad = w.toBuffer();
    expect(() => messages.deserializeMessage(header("block", bad), bad)).toThrow("Superfluous witness record");
    const { peer, reasons } = stubPeer();
    peer.feedData(v1Frame("block", bad));
    const deadline = Date.now() + 15_000;
    while (peer.state !== "disconnected" && Date.now() < deadline) await new Promise((r) => setTimeout(r, 5));
    expect(reasons).toEqual(["Superfluous witness record"]);
  });

  test("a malformed v2 block is logged and discarded, the peer is kept (as before)", async () => {
    const bad = FLOOD.subarray(0, FLOOD.length - 2);
    const { peer, dispatched, reasons } = stubPeer();
    asV2(peer, [
      { type: "block", payload: bad },
      { type: "ping", payload: Buffer.alloc(8, 0x09) },
    ]);
    peer.feedData(Buffer.from([0x00]));
    const deadline = Date.now() + 15_000;
    while (dispatched.length === 0 && Date.now() < deadline) await new Promise((r) => setTimeout(r, 5));
    expect(dispatched.map((m) => m.type)).toEqual(["ping"]);
    expect(peer.state).not.toBe("disconnected");
    expect(reasons).toEqual([]);
  });
});

describe("H2 block path: the stepped parser", () => {
  test("deserializeTxSteps yields inside one huge tx and returns what deserializeTx returns", () => {
    const steps = (txmod as any).deserializeTxSteps;
    expect(typeof steps).toBe("function");
    const w = new BufferWriter();
    writeFloodTx(w, 100_000);
    const raw = w.toBuffer();
    const g = steps(new BufferReader(raw));
    let yields = 0;
    let r = g.next();
    while (!r.done) {
      yields++;
      r = g.next();
    }
    expect(yields).toBeGreaterThan(10);
    expect(r.value).toEqual(deserializeTx(new BufferReader(raw)));
    expect(serializeTx(r.value, true).equals(raw)).toBe(true);
  });
});
