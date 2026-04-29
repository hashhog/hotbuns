/**
 * BIP-324 inbound v2 integration tests.
 *
 * Drives a Peer through its acceptSocket / processRecvBuffer path with
 * synthetic v1 and v2 wires.  Verifies the peek-classify logic in
 * Peer.processRecvBuffer and the responder-side V2Transport handshake
 * flow.
 *
 * The tests bypass Bun.connect / Bun.listen (which would require real
 * TCP sockets) by hand-feeding bytes via Peer.feedData and capturing
 * Peer.send via a stub socket that records writes into a buffer.
 */

import { describe, expect, test } from "bun:test";
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
  serializeMessage,
  type NetworkMessage,
  parseHeader,
  MESSAGE_HEADER_SIZE,
  deserializeV2Message,
} from "../p2p/messages.js";
import { REGTEST } from "../consensus/params.js";

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

describe("BIP-324 inbound classification", () => {
  test("inbound v1 VERSION prefix routes through plaintext path", () => {
    const captured = { msgs: [] as NetworkMessage[], handshakeComplete: false };
    const peer = new Peer(makeConfig(), makeEvents(captured));
    const stub = makeStubSocket();
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (peer as any).acceptSocket(stub.socket);

    // Build a real v1 VERSION message and feed it.  The Peer should:
    //   - classify the wire as v1 (peeked first 16 bytes match magic + "version")
    //   - process the VERSION through handleHandshake (not onMessage)
    //   - send our own v1 VERSION + wtxidrelay + sendaddrv2 + verack reply.
    const versionMsg: NetworkMessage = {
      type: "version",
      payload: {
        version: 70016,
        services: 0n,
        timestamp: BigInt(Math.floor(Date.now() / 1000)),
        addrRecv: { services: 0n, ip: Buffer.alloc(16), port: 0 },
        addrFrom: { services: 0n, ip: Buffer.alloc(16), port: 0 },
        nonce: 0xdeadbeefn,
        userAgent: "/peer:0.0/",
        startHeight: 0,
        relay: true,
      },
    };
    const wire = serializeMessage(REGTEST.networkMagic, versionMsg);
    peer.feedData(wire);

    // Peer should have written its own v1 VERSION reply.  During the v1
    // handshake the peer's VERSION is consumed by handleHandshake (which
    // does NOT propagate it to onMessage), so we verify behavior via
    // outbound writes instead.
    expect(stub.written.length).toBeGreaterThan(0);
    const concatenated = Buffer.concat(stub.written);
    expect(concatenated.length).toBeGreaterThanOrEqual(MESSAGE_HEADER_SIZE);
    const hdr = parseHeader(concatenated);
    expect(hdr).not.toBeNull();
    expect(hdr!.command).toBe("version");
    expect(hdr!.magic).toBe(REGTEST.networkMagic);

    // After receiving their VERSION we should have also queued wtxidrelay,
    // sendaddrv2, verack.  Walk all messages and verify the sequence.
    let offset = 0;
    const commands: string[] = [];
    while (offset + MESSAGE_HEADER_SIZE <= concatenated.length) {
      const h = parseHeader(concatenated.subarray(offset));
      if (!h) break;
      commands.push(h.command);
      offset += MESSAGE_HEADER_SIZE + h.length;
    }
    expect(commands).toContain("version");
    expect(commands).toContain("verack");
  });

  test("inbound non-v1 prefix routes through V2Transport responder", () => {
    const captured = { msgs: [] as NetworkMessage[], handshakeComplete: false };
    const peer = new Peer(makeConfig(), makeEvents(captured));
    const stub = makeStubSocket();
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (peer as any).acceptSocket(stub.socket);

    // Build an "initiator" V2Transport — it will produce a real 64-byte
    // ElligatorSwift pubkey + garbage that the Peer (responder) must
    // classify as v2 (since it doesn't match the v1 magic+command prefix).
    const initiator = new V2Transport(REGTEST_MAGIC_LE, /* initiator */ true);
    const initBytes1 = initiator.consumeSendBuffer();
    expect(initBytes1.length).toBeGreaterThanOrEqual(64);

    // Sanity: the first 16 bytes of an ellswift pubkey should not match
    // the v1 prefix (probability of collision = 2^-32 over the magic +
    // ~zero of also matching the command bytes).
    expect(initBytes1.length).toBeGreaterThanOrEqual(V1_PREFIX_LEN);
    // We fed enough bytes to classify; they almost certainly do NOT
    // match magic + "version".  If they do (astronomically unlikely),
    // the test would deterministically reproduce — fail loudly.
    const looksLikeV1 = initBytes1.subarray(0, 4).equals(REGTEST_MAGIC_LE) &&
      initBytes1.subarray(4, 16).equals(Buffer.from(
        [0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0, 0, 0, 0, 0]
      ));
    expect(looksLikeV1).toBe(false);

    // Feed initiator's pubkey + garbage to the Peer.  The responder side
    // should:
    //   1. Construct a V2Transport(responder, skipV1Check=true)
    //   2. Compute ECDH from the initiator's pubkey
    //   3. Queue: responder pubkey + garbage + terminator + version
    //      packet (empty contents, AAD = our_garbage)
    //   4. Once cipher is initialized, send our application-layer
    //      v1-formatted VERSION through the encrypted channel
    peer.feedData(initBytes1);

    // Stage 1: responder's outbound bytes — pubkey + garbage + terminator
    // + version packet + encrypted application VERSION.  Way more than
    // 64 bytes.
    const respFirst = Buffer.concat(stub.written);
    stub.written.length = 0;
    expect(respFirst.length).toBeGreaterThan(64 + 16); // pubkey + terminator floor

    // Drive the initiator with the responder's reply.  This consumes the
    // pubkey, the garbage (zero-length on the responder side, by chance),
    // the terminator, the version packet (empty contents), and the
    // encrypted application VERSION.
    const ack = initiator.receiveBytes(respFirst);
    expect(ack.fallbackV1).toBe(false);
    expect(ack.error).toBeUndefined();
    expect(initiator.isReady()).toBe(true);
    expect(initiator.isHandshakeReady()).toBe(true);
    expect(initiator.isVersionReceived()).toBe(true);

    // The responder's VERSION should have been delivered through the v2
    // transport.  Decode and verify userAgent matches our config.
    const v2msgs = initiator.getReceivedMessages();
    expect(v2msgs.length).toBe(1);
    expect(v2msgs[0].type).toBe("version");
    const decoded = deserializeV2Message(v2msgs[0].type, v2msgs[0].payload);
    expect(decoded.type).toBe("version");
    if (decoded.type === "version") {
      expect(decoded.payload.userAgent).toBe("/hotbuns-test:0.0.1/");
    }

    // Initiator queues its own terminator + version packet; feed back to
    // the Peer to complete the handshake on its side.
    const initBytes2 = initiator.consumeSendBuffer();
    expect(initBytes2.length).toBeGreaterThan(0);
    peer.feedData(initBytes2);

    // The responder's V2Transport should have observed the initiator's
    // version packet (decoy or real); it doesn't generate any new
    // outbound bytes since application-VERSION was already sent.
    expect(stub.written.length).toBe(0);
  });

  test("inbound classification waits for 16 bytes before deciding", () => {
    const captured = { msgs: [] as NetworkMessage[], handshakeComplete: false };
    const peer = new Peer(makeConfig(), makeEvents(captured));
    const stub = makeStubSocket();
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (peer as any).acceptSocket(stub.socket);

    // Feed only 4 bytes (just the magic).  This is ambiguous — we need
    // 12 more bytes of command to know if the peer is v1.  Peer should
    // NOT have classified yet, NOT sent anything.
    peer.feedData(REGTEST_MAGIC_LE);
    expect(stub.written.length).toBe(0);
    expect(captured.msgs.length).toBe(0);

    // Now feed the rest of the v1 VERSION command.
    peer.feedData(Buffer.from([0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0, 0, 0, 0, 0]));
    // Peer should have classified as v1 and emitted its own VERSION.
    expect(stub.written.length).toBeGreaterThan(0);
    const concatenated = Buffer.concat(stub.written);
    const hdr = parseHeader(concatenated);
    expect(hdr).not.toBeNull();
    expect(hdr!.command).toBe("version");
  });
});
