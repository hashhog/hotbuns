/**
 * Audit H2 (audits/security/hotbuns-2026-10-29.md): a 4 MB `tx` of ~4 million
 * empty witness items was fully parsed on the event loop (~0.6-0.7 s, about
 * +430 MB) before any standardness gate, with no penalty, stalling every peer
 * and RPC client.
 *
 * Fix: a loose `tx` payload over MAX_STANDARD_TX_WEIGHT bytes is dropped
 * unparsed (weight >= size, so such a tx is always non-standard `tx-size`,
 * which hotbuns' mempool rejects unconditionally); the peer is kept, as Core
 * does not punish a non-standard tx. Empty witness items share one zero-length
 * Buffer, which halves the cost of the same shape inside a block.
 *
 * Regtest only: the frames go to a local Peer over a stub socket.
 */

import { describe, expect, test } from "bun:test";

import * as messages from "./messages.js";
import { Peer, type PeerConfig, type PeerEvents } from "./peer.js";
import { REGTEST } from "../consensus/params.js";
import { deserializeTx, serializeTx } from "../validation/tx.js";
import { BufferReader, BufferWriter } from "../wire/serialization.js";
import { hash256 } from "../crypto/primitives.js";

/** A segwit tx, 1 input / 1 output, padded to ~`size` bytes of witness items. */
function witnessFloodTx(size: number, itemLen = 0): Buffer {
  const w = new BufferWriter();
  w.writeInt32LE(2);
  w.writeUInt8(0x00);
  w.writeUInt8(0x01);
  w.writeVarInt(1);
  w.writeBytes(Buffer.alloc(32, 0x01));
  w.writeUInt32LE(0);
  w.writeVarInt(0);
  w.writeUInt32LE(0xffffffff);
  w.writeVarInt(1);
  w.writeUInt64LE(1000n);
  w.writeVarInt(1);
  w.writeUInt8(0x51);
  const n = Math.floor((size - 70) / (1 + itemLen));
  w.writeVarInt(n);
  const item = Buffer.alloc(itemLen, 0xab);
  for (let i = 0; i < n; i++) {
    w.writeVarInt(itemLen);
    if (itemLen) w.writeBytes(item);
  }
  w.writeUInt32LE(0);
  return w.toBuffer();
}

function txHeader(payload: Buffer): messages.MessageHeader {
  return {
    magic: REGTEST.networkMagic,
    command: "tx",
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

/** A handshaken v1 peer on a stub socket; records what it dispatches. */
function v1Peer() {
  const dispatched: string[] = [];
  const events: PeerEvents = {
    onConnect: () => {},
    onDisconnect: () => {},
    onMessage: (_p, msg) => dispatched.push(msg.type),
    onHandshakeComplete: () => {},
  };
  const config: PeerConfig = {
    host: "127.0.0.1",
    port: 18444,
    magic: REGTEST.networkMagic,
    protocolVersion: 70016,
    services: 0n,
    userAgent: "/h2-test/",
    bestHeight: 0,
    relay: true,
  };
  const peer = new Peer(config, events);
  const p = peer as any;
  p.socket = { write: (d: Uint8Array) => d.length, end() {}, remoteAddress: "127.0.0.1" };
  p.state = "connected";
  p.transportMode = "v1";
  p.receivedVersion = true;
  p.versionReceived = true;
  p.verackReceived = true;
  p.handshakeComplete = true;
  return { peer, dispatched };
}

describe("H2: oversized loose tx is not parsed", () => {
  test("a tx payload over MAX_STANDARD_TX_WEIGHT bytes is refused before parsing", () => {
    const payload = witnessFloodTx(3_990_000);
    let thrown: unknown = null;
    let parsed: unknown = null;
    try {
      parsed = messages.deserializeMessage(txHeader(payload), payload);
    } catch (e) {
      thrown = e;
    }
    // Master parsed all ~3.99 million witness items and returned the tx.
    expect(parsed).toBeNull();
    expect((thrown as Error)?.name).toBe("OversizedTxMessageError");
  });

  test("the v1 peer drops the oversized tx, stays connected and keeps reading", () => {
    const { peer, dispatched } = v1Peer();
    const big = witnessFloodTx(3_990_000);
    const ping = Buffer.alloc(8, 0x07);
    // Oversized tx then a ping in one read: the frame after it still parses.
    peer.feedData(Buffer.concat([v1Frame("tx", big), v1Frame("ping", ping)]));
    expect(peer.state).not.toBe("disconnected");
    expect(dispatched).not.toContain("tx");
    expect(dispatched).toContain("ping");
    expect((peer as any).recvBuffer.length).toBe(0);
  });

  test("control: a standard-size tx still parses and dispatches", () => {
    const payload = witnessFloodTx(50_000, 1);
    const msg = messages.deserializeMessage(txHeader(payload), payload);
    expect(msg.type).toBe("tx");
    const { peer, dispatched } = v1Peer();
    peer.feedData(v1Frame("tx", payload));
    expect(dispatched).toEqual(["tx"]);
  });

  test("the limit is exactly MAX_STANDARD_TX_WEIGHT (400,000) bytes", () => {
    expect((messages as any).MAX_TX_MESSAGE_PAYLOAD).toBe(400_000);
    const at = witnessFloodTx(400_000);
    const padded = Buffer.concat([at, Buffer.alloc(400_000 - at.length)]);
    // 400,000 bytes is not over the limit: it reaches the parser (and fails
    // there only because of the trailing padding the test added).
    expect(() => messages.deserializeMessage(txHeader(padded), padded)).not.toThrow(
      (messages as any).OversizedTxMessageError,
    );
    const over = Buffer.alloc(400_001);
    expect(() => messages.deserializeMessage(txHeader(over), over)).toThrow(/exceeds 400000/);
  });
});

describe("H2: empty witness items in a block-sized tx", () => {
  test("empty and non-empty witness items round-trip byte-identically", () => {
    // Consensus safety: the shared empty item must serialize as one 0x00.
    const w = new BufferWriter();
    w.writeInt32LE(2);
    w.writeUInt8(0x00);
    w.writeUInt8(0x01);
    w.writeVarInt(2);
    for (let i = 0; i < 2; i++) {
      w.writeBytes(Buffer.alloc(32, i + 1));
      w.writeUInt32LE(i);
      w.writeVarInt(0);
      w.writeUInt32LE(0xfffffffe);
    }
    w.writeVarInt(1);
    w.writeUInt64LE(5000n);
    w.writeVarInt(1);
    w.writeUInt8(0x51);
    // input 0: [empty, 0xaa, empty]; input 1: [empty]
    w.writeVarInt(3);
    w.writeVarInt(0);
    w.writeVarInt(1);
    w.writeUInt8(0xaa);
    w.writeVarInt(0);
    w.writeVarInt(1);
    w.writeVarInt(0);
    w.writeUInt32LE(0);
    const raw = w.toBuffer();

    const tx = deserializeTx(new BufferReader(raw));
    expect(tx.inputs[0].witness.map((b) => b.length)).toEqual([0, 1, 0]);
    expect(tx.inputs[1].witness.map((b) => b.length)).toEqual([0]);
    expect(serializeTx(tx, true).equals(raw)).toBe(true);
    // Writing into an item cannot change another: an empty Buffer has no bytes.
    tx.inputs[0].witness[0].fill(0xff);
    expect(tx.inputs[1].witness[0].length).toBe(0);
    expect(serializeTx(tx, true).equals(raw)).toBe(true);
  });
});
