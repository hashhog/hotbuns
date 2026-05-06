/**
 * Tests for Bitcoin P2P message serialization and deserialization.
 */

import { describe, expect, test } from "bun:test";
import { MAINNET } from "../consensus/params.js";
import { hash256 } from "../crypto/primitives.js";
import { BufferWriter } from "../wire/serialization.js";
import {
  MessageHeader,
  NetworkMessage,
  NetworkAddress,
  VersionPayload,
  InvType,
  InvVector,
  MESSAGE_HEADER_SIZE,
  MAX_MESSAGE_SIZE,
  MAX_INV_SZ,
  MAX_HEADERS_RESULTS,
  MAX_ADDR_TO_SEND,
  MAX_LOCATOR_SZ,
  serializeMessage,
  deserializeMessage,
  serializeHeader,
  parseHeader,
  ipv4ToBuffer,
} from "./messages.js";

// Use mainnet magic for tests
const MAGIC = MAINNET.networkMagic;

describe("P2P message header", () => {
  test("serializeHeader creates 24-byte header", () => {
    const payload = Buffer.from("test payload");
    const header = serializeHeader(MAGIC, "version", payload);

    expect(header.length).toBe(MESSAGE_HEADER_SIZE);
  });

  test("serializeHeader encodes magic correctly", () => {
    const payload = Buffer.alloc(0);
    const header = serializeHeader(MAGIC, "verack", payload);

    // Mainnet magic: 0xd9b4bef9
    expect(header.readUInt32LE(0)).toBe(0xd9b4bef9);
  });

  test("serializeHeader null-pads command to 12 bytes", () => {
    const payload = Buffer.alloc(0);
    const header = serializeHeader(MAGIC, "ping", payload);

    // Command starts at offset 4, should be "ping" + 8 null bytes
    const cmdBuf = header.subarray(4, 16);
    expect(cmdBuf.toString("ascii", 0, 4)).toBe("ping");
    expect(cmdBuf[4]).toBe(0);
    expect(cmdBuf[11]).toBe(0);
  });

  test("serializeHeader computes correct checksum", () => {
    const payload = Buffer.from("hello world");
    const header = serializeHeader(MAGIC, "test", payload);

    const expectedChecksum = hash256(payload).subarray(0, 4);
    const actualChecksum = header.subarray(20, 24);

    expect(actualChecksum.equals(expectedChecksum)).toBe(true);
  });

  test("serializeHeader encodes payload length", () => {
    const payload = Buffer.alloc(12345);
    const header = serializeHeader(MAGIC, "data", payload);

    expect(header.readUInt32LE(16)).toBe(12345);
  });

  test("serializeHeader rejects command > 12 chars", () => {
    expect(() => {
      serializeHeader(MAGIC, "verylongcommand", Buffer.alloc(0));
    }).toThrow("Command name too long");
  });

  test("serializeHeader rejects oversized payload", () => {
    const oversized = Buffer.alloc(MAX_MESSAGE_SIZE + 1);
    expect(() => {
      serializeHeader(MAGIC, "block", oversized);
    }).toThrow("Payload too large");
  });

  test("parseHeader returns null for insufficient data", () => {
    const partial = Buffer.alloc(20); // Less than 24 bytes
    expect(parseHeader(partial)).toBe(null);
  });

  test("parseHeader correctly parses header", () => {
    const payload = Buffer.from("test data");
    const serialized = serializeHeader(MAGIC, "version", payload);

    const parsed = parseHeader(serialized);
    expect(parsed).not.toBe(null);
    expect(parsed!.magic).toBe(MAGIC);
    expect(parsed!.command).toBe("version");
    expect(parsed!.length).toBe(payload.length);
  });

  test("parseHeader extracts command until null byte", () => {
    const payload = Buffer.alloc(0);
    const header = serializeHeader(MAGIC, "inv", payload);

    const parsed = parseHeader(header);
    expect(parsed!.command).toBe("inv");
  });

  test("parseHeader handles full 12-char command", () => {
    const payload = Buffer.alloc(0);
    const header = serializeHeader(MAGIC, "sendheaders", payload);

    const parsed = parseHeader(header);
    expect(parsed!.command).toBe("sendheaders");
  });

  test("parseHeader rejects oversized payload length", () => {
    // Manually create a header with oversized length
    const header = Buffer.alloc(24);
    header.writeUInt32LE(MAGIC, 0);
    header.write("test", 4, "ascii");
    header.writeUInt32LE(MAX_MESSAGE_SIZE + 1, 16);

    expect(() => parseHeader(header)).toThrow("Payload length exceeds maximum");
  });
});

describe("ipv4ToBuffer", () => {
  test("converts localhost correctly", () => {
    const buf = ipv4ToBuffer("127.0.0.1");

    expect(buf.length).toBe(16);

    // First 10 bytes are zeros
    for (let i = 0; i < 10; i++) {
      expect(buf[i]).toBe(0);
    }

    // Bytes 10-11 are 0xFF
    expect(buf[10]).toBe(0xff);
    expect(buf[11]).toBe(0xff);

    // IPv4 bytes
    expect(buf[12]).toBe(127);
    expect(buf[13]).toBe(0);
    expect(buf[14]).toBe(0);
    expect(buf[15]).toBe(1);
  });

  test("converts 192.168.1.1 correctly", () => {
    const buf = ipv4ToBuffer("192.168.1.1");

    expect(buf[12]).toBe(192);
    expect(buf[13]).toBe(168);
    expect(buf[14]).toBe(1);
    expect(buf[15]).toBe(1);
  });

  test("converts 0.0.0.0 correctly", () => {
    const buf = ipv4ToBuffer("0.0.0.0");

    expect(buf[10]).toBe(0xff);
    expect(buf[11]).toBe(0xff);
    expect(buf[12]).toBe(0);
    expect(buf[13]).toBe(0);
    expect(buf[14]).toBe(0);
    expect(buf[15]).toBe(0);
  });

  test("converts 255.255.255.255 correctly", () => {
    const buf = ipv4ToBuffer("255.255.255.255");

    expect(buf[12]).toBe(255);
    expect(buf[13]).toBe(255);
    expect(buf[14]).toBe(255);
    expect(buf[15]).toBe(255);
  });

  test("produces IPv4-mapped IPv6 format", () => {
    const buf = ipv4ToBuffer("8.8.8.8");

    // Expected format: 00 00 00 00 00 00 00 00 00 00 FF FF 08 08 08 08
    const expected = Buffer.from([
      0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0xff, 0xff,
      0x08, 0x08, 0x08, 0x08,
    ]);

    expect(buf.equals(expected)).toBe(true);
  });

  test("rejects invalid IPv4 addresses", () => {
    expect(() => ipv4ToBuffer("256.0.0.1")).toThrow();
    expect(() => ipv4ToBuffer("1.2.3")).toThrow();
    expect(() => ipv4ToBuffer("1.2.3.4.5")).toThrow();
    expect(() => ipv4ToBuffer("abc.def.ghi.jkl")).toThrow();
    expect(() => ipv4ToBuffer("-1.0.0.0")).toThrow();
  });
});

describe("version message", () => {
  function createVersionPayload(): VersionPayload {
    return {
      version: 70016,
      services: 0x0409n,
      timestamp: BigInt(Math.floor(Date.now() / 1000)),
      addrRecv: {
        services: 0x0409n,
        ip: ipv4ToBuffer("192.168.1.1"),
        port: 8333,
      },
      addrFrom: {
        services: 0x0409n,
        ip: ipv4ToBuffer("127.0.0.1"),
        port: 8333,
      },
      nonce: 0x1234567890abcdefn,
      userAgent: "/hotbuns:0.1.0/",
      startHeight: 850000,
      relay: true,
    };
  }

  test("round-trips correctly", () => {
    const original: NetworkMessage = {
      type: "version",
      payload: createVersionPayload(),
    };

    const serialized = serializeMessage(MAGIC, original);
    const header = parseHeader(serialized)!;
    const payload = serialized.subarray(MESSAGE_HEADER_SIZE);

    const deserialized = deserializeMessage(header, payload);

    expect(deserialized.type).toBe("version");
    if (deserialized.type === "version") {
      expect(deserialized.payload.version).toBe(70016);
      expect(deserialized.payload.services).toBe(0x0409n);
      expect(deserialized.payload.nonce).toBe(0x1234567890abcdefn);
      expect(deserialized.payload.userAgent).toBe("/hotbuns:0.1.0/");
      expect(deserialized.payload.startHeight).toBe(850000);
      expect(deserialized.payload.relay).toBe(true);
      expect(deserialized.payload.addrRecv.port).toBe(8333);
      expect(deserialized.payload.addrFrom.port).toBe(8333);
    }
  });

  test("preserves network address details", () => {
    const original: NetworkMessage = {
      type: "version",
      payload: createVersionPayload(),
    };

    const serialized = serializeMessage(MAGIC, original);
    const header = parseHeader(serialized)!;
    const payload = serialized.subarray(MESSAGE_HEADER_SIZE);

    const deserialized = deserializeMessage(header, payload);

    if (deserialized.type === "version") {
      // Verify addrRecv IP is preserved
      const expectedRecvIp = ipv4ToBuffer("192.168.1.1");
      expect(deserialized.payload.addrRecv.ip.equals(expectedRecvIp)).toBe(true);

      // Verify addrFrom IP is preserved
      const expectedFromIp = ipv4ToBuffer("127.0.0.1");
      expect(deserialized.payload.addrFrom.ip.equals(expectedFromIp)).toBe(true);
    }
  });

  test("port is big-endian in serialization", () => {
    const original: NetworkMessage = {
      type: "version",
      payload: createVersionPayload(),
    };

    const serialized = serializeMessage(MAGIC, original);

    // In the version payload:
    // - First 4 bytes: version (int32)
    // - Next 8 bytes: services (uint64)
    // - Next 8 bytes: timestamp (int64)
    // - addrRecv starts at offset 20:
    //   - 8 bytes services
    //   - 16 bytes IP
    //   - 2 bytes port (big-endian)
    // Port is at offset 20 + 8 + 16 = 44 from start of payload

    const payload = serialized.subarray(MESSAGE_HEADER_SIZE);
    const portOffset = 4 + 8 + 8 + 8 + 16; // 44
    const portBytes = payload.subarray(portOffset, portOffset + 2);

    // Port 8333 = 0x208D, big-endian: 0x20 0x8D
    expect(portBytes[0]).toBe(0x20);
    expect(portBytes[1]).toBe(0x8d);
  });
});

describe("ping/pong messages", () => {
  test("ping round-trips correctly", () => {
    const original: NetworkMessage = {
      type: "ping",
      payload: { nonce: 0xdeadbeefcafebaben },
    };

    const serialized = serializeMessage(MAGIC, original);
    const header = parseHeader(serialized)!;
    const payload = serialized.subarray(MESSAGE_HEADER_SIZE);

    expect(header.command).toBe("ping");
    expect(payload.length).toBe(8); // nonce is 8 bytes

    const deserialized = deserializeMessage(header, payload);

    expect(deserialized.type).toBe("ping");
    if (deserialized.type === "ping") {
      expect(deserialized.payload.nonce).toBe(0xdeadbeefcafebaben);
    }
  });

  test("pong round-trips correctly", () => {
    const original: NetworkMessage = {
      type: "pong",
      payload: { nonce: 0x123456789abcdef0n },
    };

    const serialized = serializeMessage(MAGIC, original);
    const header = parseHeader(serialized)!;
    const payload = serialized.subarray(MESSAGE_HEADER_SIZE);

    expect(header.command).toBe("pong");

    const deserialized = deserializeMessage(header, payload);

    expect(deserialized.type).toBe("pong");
    if (deserialized.type === "pong") {
      expect(deserialized.payload.nonce).toBe(0x123456789abcdef0n);
    }
  });
});

describe("inv message", () => {
  test("serializes single inventory vector", () => {
    const txHash = Buffer.alloc(32);
    txHash.fill(0xab);

    const original: NetworkMessage = {
      type: "inv",
      payload: {
        inventory: [
          { type: InvType.MSG_TX, hash: txHash },
        ],
      },
    };

    const serialized = serializeMessage(MAGIC, original);
    const header = parseHeader(serialized)!;
    const payload = serialized.subarray(MESSAGE_HEADER_SIZE);

    expect(header.command).toBe("inv");
    // 1 byte varint count + (4 bytes type + 32 bytes hash) = 37 bytes
    expect(payload.length).toBe(37);

    const deserialized = deserializeMessage(header, payload);

    expect(deserialized.type).toBe("inv");
    if (deserialized.type === "inv") {
      expect(deserialized.payload.inventory.length).toBe(1);
      expect(deserialized.payload.inventory[0].type).toBe(InvType.MSG_TX);
      expect(deserialized.payload.inventory[0].hash.equals(txHash)).toBe(true);
    }
  });

  test("serializes multiple inventory vectors", () => {
    const txHash = Buffer.alloc(32, 0x11);
    const blockHash = Buffer.alloc(32, 0x22);
    const witnessBlockHash = Buffer.alloc(32, 0x33);

    const original: NetworkMessage = {
      type: "inv",
      payload: {
        inventory: [
          { type: InvType.MSG_TX, hash: txHash },
          { type: InvType.MSG_BLOCK, hash: blockHash },
          { type: InvType.MSG_WITNESS_BLOCK, hash: witnessBlockHash },
        ],
      },
    };

    const serialized = serializeMessage(MAGIC, original);
    const header = parseHeader(serialized)!;
    const payload = serialized.subarray(MESSAGE_HEADER_SIZE);

    const deserialized = deserializeMessage(header, payload);

    expect(deserialized.type).toBe("inv");
    if (deserialized.type === "inv") {
      expect(deserialized.payload.inventory.length).toBe(3);
      expect(deserialized.payload.inventory[0].type).toBe(InvType.MSG_TX);
      expect(deserialized.payload.inventory[1].type).toBe(InvType.MSG_BLOCK);
      expect(deserialized.payload.inventory[2].type).toBe(InvType.MSG_WITNESS_BLOCK);
    }
  });

  test("handles empty inventory", () => {
    const original: NetworkMessage = {
      type: "inv",
      payload: { inventory: [] },
    };

    const serialized = serializeMessage(MAGIC, original);
    const header = parseHeader(serialized)!;
    const payload = serialized.subarray(MESSAGE_HEADER_SIZE);

    // Just the varint count (0)
    expect(payload.length).toBe(1);
    expect(payload[0]).toBe(0);

    const deserialized = deserializeMessage(header, payload);

    expect(deserialized.type).toBe("inv");
    if (deserialized.type === "inv") {
      expect(deserialized.payload.inventory.length).toBe(0);
    }
  });
});

describe("getdata message", () => {
  test("round-trips correctly", () => {
    const hash1 = Buffer.alloc(32, 0xaa);
    const hash2 = Buffer.alloc(32, 0xbb);

    const original: NetworkMessage = {
      type: "getdata",
      payload: {
        inventory: [
          { type: InvType.MSG_WITNESS_TX, hash: hash1 },
          { type: InvType.MSG_BLOCK, hash: hash2 },
        ],
      },
    };

    const serialized = serializeMessage(MAGIC, original);
    const header = parseHeader(serialized)!;
    const payload = serialized.subarray(MESSAGE_HEADER_SIZE);

    expect(header.command).toBe("getdata");

    const deserialized = deserializeMessage(header, payload);

    expect(deserialized.type).toBe("getdata");
    if (deserialized.type === "getdata") {
      expect(deserialized.payload.inventory.length).toBe(2);
      expect(deserialized.payload.inventory[0].type).toBe(InvType.MSG_WITNESS_TX);
      expect(deserialized.payload.inventory[1].type).toBe(InvType.MSG_BLOCK);
    }
  });
});

describe("headers message", () => {
  test("serializes empty headers list", () => {
    const original: NetworkMessage = {
      type: "headers",
      payload: { headers: [] },
    };

    const serialized = serializeMessage(MAGIC, original);
    const header = parseHeader(serialized)!;
    const payload = serialized.subarray(MESSAGE_HEADER_SIZE);

    expect(header.command).toBe("headers");
    expect(payload.length).toBe(1); // Just varint count

    const deserialized = deserializeMessage(header, payload);

    expect(deserialized.type).toBe("headers");
    if (deserialized.type === "headers") {
      expect(deserialized.payload.headers.length).toBe(0);
    }
  });

  test("serializes block headers with txn_count", () => {
    const blockHeader = {
      version: 0x20000000,
      prevBlock: Buffer.alloc(32, 0xaa),
      merkleRoot: Buffer.alloc(32, 0xbb),
      timestamp: 1700000000,
      bits: 0x1d00ffff,
      nonce: 12345678,
    };

    const original: NetworkMessage = {
      type: "headers",
      payload: { headers: [blockHeader] },
    };

    const serialized = serializeMessage(MAGIC, original);
    const header = parseHeader(serialized)!;
    const payload = serialized.subarray(MESSAGE_HEADER_SIZE);

    // 1 byte count + (80 bytes header + 1 byte txn_count) = 82 bytes
    expect(payload.length).toBe(82);

    const deserialized = deserializeMessage(header, payload);

    expect(deserialized.type).toBe("headers");
    if (deserialized.type === "headers") {
      expect(deserialized.payload.headers.length).toBe(1);
      expect(deserialized.payload.headers[0].version).toBe(0x20000000);
      expect(deserialized.payload.headers[0].timestamp).toBe(1700000000);
      expect(deserialized.payload.headers[0].bits).toBe(0x1d00ffff);
      expect(deserialized.payload.headers[0].nonce).toBe(12345678);
    }
  });

  test("serializes multiple headers", () => {
    const headers = [];
    for (let i = 0; i < 5; i++) {
      headers.push({
        version: 0x20000000 + i,
        prevBlock: Buffer.alloc(32, i),
        merkleRoot: Buffer.alloc(32, i + 0x10),
        timestamp: 1700000000 + i * 600,
        bits: 0x1d00ffff,
        nonce: i * 1000,
      });
    }

    const original: NetworkMessage = {
      type: "headers",
      payload: { headers },
    };

    const serialized = serializeMessage(MAGIC, original);
    const header = parseHeader(serialized)!;
    const payload = serialized.subarray(MESSAGE_HEADER_SIZE);

    const deserialized = deserializeMessage(header, payload);

    expect(deserialized.type).toBe("headers");
    if (deserialized.type === "headers") {
      expect(deserialized.payload.headers.length).toBe(5);
      for (let i = 0; i < 5; i++) {
        expect(deserialized.payload.headers[i].version).toBe(0x20000000 + i);
        expect(deserialized.payload.headers[i].nonce).toBe(i * 1000);
      }
    }
  });
});

describe("getheaders message", () => {
  test("round-trips correctly", () => {
    const locatorHashes = [
      Buffer.alloc(32, 0x11),
      Buffer.alloc(32, 0x22),
      Buffer.alloc(32, 0x33),
    ];
    const hashStop = Buffer.alloc(32, 0x00);

    const original: NetworkMessage = {
      type: "getheaders",
      payload: {
        version: 70016,
        locatorHashes,
        hashStop,
      },
    };

    const serialized = serializeMessage(MAGIC, original);
    const header = parseHeader(serialized)!;
    const payload = serialized.subarray(MESSAGE_HEADER_SIZE);

    expect(header.command).toBe("getheaders");

    const deserialized = deserializeMessage(header, payload);

    expect(deserialized.type).toBe("getheaders");
    if (deserialized.type === "getheaders") {
      expect(deserialized.payload.version).toBe(70016);
      expect(deserialized.payload.locatorHashes.length).toBe(3);
      expect(deserialized.payload.locatorHashes[0].equals(locatorHashes[0])).toBe(true);
      expect(deserialized.payload.locatorHashes[1].equals(locatorHashes[1])).toBe(true);
      expect(deserialized.payload.locatorHashes[2].equals(locatorHashes[2])).toBe(true);
      expect(deserialized.payload.hashStop.equals(hashStop)).toBe(true);
    }
  });
});

describe("getblocks message", () => {
  test("round-trips correctly", () => {
    const locatorHashes = [
      Buffer.alloc(32, 0xaa),
    ];
    const hashStop = Buffer.alloc(32, 0xff);

    const original: NetworkMessage = {
      type: "getblocks",
      payload: {
        version: 70015,
        locatorHashes,
        hashStop,
      },
    };

    const serialized = serializeMessage(MAGIC, original);
    const header = parseHeader(serialized)!;
    const payload = serialized.subarray(MESSAGE_HEADER_SIZE);

    expect(header.command).toBe("getblocks");

    const deserialized = deserializeMessage(header, payload);

    expect(deserialized.type).toBe("getblocks");
    if (deserialized.type === "getblocks") {
      expect(deserialized.payload.version).toBe(70015);
      expect(deserialized.payload.locatorHashes.length).toBe(1);
      expect(deserialized.payload.hashStop.equals(hashStop)).toBe(true);
    }
  });
});

describe("empty payload messages", () => {
  test("verack round-trips correctly", () => {
    const original: NetworkMessage = { type: "verack", payload: null };

    const serialized = serializeMessage(MAGIC, original);
    const header = parseHeader(serialized)!;
    const payload = serialized.subarray(MESSAGE_HEADER_SIZE);

    expect(header.command).toBe("verack");
    expect(payload.length).toBe(0);

    const deserialized = deserializeMessage(header, payload);
    expect(deserialized.type).toBe("verack");
    expect(deserialized.payload).toBe(null);
  });

  test("getaddr round-trips correctly", () => {
    const original: NetworkMessage = { type: "getaddr", payload: null };

    const serialized = serializeMessage(MAGIC, original);
    const header = parseHeader(serialized)!;
    const payload = serialized.subarray(MESSAGE_HEADER_SIZE);

    expect(header.command).toBe("getaddr");
    expect(payload.length).toBe(0);

    const deserialized = deserializeMessage(header, payload);
    expect(deserialized.type).toBe("getaddr");
  });

  test("sendheaders round-trips correctly", () => {
    const original: NetworkMessage = { type: "sendheaders", payload: null };

    const serialized = serializeMessage(MAGIC, original);
    const header = parseHeader(serialized)!;
    const payload = serialized.subarray(MESSAGE_HEADER_SIZE);

    expect(header.command).toBe("sendheaders");
    expect(payload.length).toBe(0);

    const deserialized = deserializeMessage(header, payload);
    expect(deserialized.type).toBe("sendheaders");
  });

  test("wtxidrelay round-trips correctly", () => {
    const original: NetworkMessage = { type: "wtxidrelay", payload: null };

    const serialized = serializeMessage(MAGIC, original);
    const header = parseHeader(serialized)!;
    const payload = serialized.subarray(MESSAGE_HEADER_SIZE);

    expect(header.command).toBe("wtxidrelay");
    expect(payload.length).toBe(0);

    const deserialized = deserializeMessage(header, payload);
    expect(deserialized.type).toBe("wtxidrelay");
  });

  test("sendaddrv2 round-trips correctly", () => {
    const original: NetworkMessage = { type: "sendaddrv2", payload: null };

    const serialized = serializeMessage(MAGIC, original);
    const header = parseHeader(serialized)!;
    const payload = serialized.subarray(MESSAGE_HEADER_SIZE);

    expect(header.command).toBe("sendaddrv2");
    expect(payload.length).toBe(0);

    const deserialized = deserializeMessage(header, payload);
    expect(deserialized.type).toBe("sendaddrv2");
  });

  test("mempool round-trips correctly", () => {
    // BIP-35: empty-payload request for peer's mempool contents.
    const original: NetworkMessage = { type: "mempool", payload: null };

    const serialized = serializeMessage(MAGIC, original);
    const header = parseHeader(serialized)!;
    const payload = serialized.subarray(MESSAGE_HEADER_SIZE);

    expect(header.command).toBe("mempool");
    expect(payload.length).toBe(0);

    const deserialized = deserializeMessage(header, payload);
    expect(deserialized.type).toBe("mempool");
    expect(deserialized.payload).toBe(null);
  });
});

describe("addr message", () => {
  test("round-trips correctly", () => {
    const original: NetworkMessage = {
      type: "addr",
      payload: {
        addrs: [
          {
            timestamp: 1700000000,
            addr: {
              services: 0x0409n,
              ip: ipv4ToBuffer("192.168.1.100"),
              port: 8333,
            },
          },
          {
            timestamp: 1700000100,
            addr: {
              services: 0x01n,
              ip: ipv4ToBuffer("10.0.0.1"),
              port: 18333,
            },
          },
        ],
      },
    };

    const serialized = serializeMessage(MAGIC, original);
    const header = parseHeader(serialized)!;
    const payload = serialized.subarray(MESSAGE_HEADER_SIZE);

    expect(header.command).toBe("addr");

    const deserialized = deserializeMessage(header, payload);

    expect(deserialized.type).toBe("addr");
    if (deserialized.type === "addr") {
      expect(deserialized.payload.addrs.length).toBe(2);
      expect(deserialized.payload.addrs[0].timestamp).toBe(1700000000);
      expect(deserialized.payload.addrs[0].addr.port).toBe(8333);
      expect(deserialized.payload.addrs[1].timestamp).toBe(1700000100);
      expect(deserialized.payload.addrs[1].addr.port).toBe(18333);
    }
  });
});

describe("reject message", () => {
  test("round-trips without data", () => {
    const original: NetworkMessage = {
      type: "reject",
      payload: {
        message: "tx",
        ccode: 0x10, // REJECT_INVALID
        reason: "dust output",
      },
    };

    const serialized = serializeMessage(MAGIC, original);
    const header = parseHeader(serialized)!;
    const payload = serialized.subarray(MESSAGE_HEADER_SIZE);

    expect(header.command).toBe("reject");

    const deserialized = deserializeMessage(header, payload);

    expect(deserialized.type).toBe("reject");
    if (deserialized.type === "reject") {
      expect(deserialized.payload.message).toBe("tx");
      expect(deserialized.payload.ccode).toBe(0x10);
      expect(deserialized.payload.reason).toBe("dust output");
      expect(deserialized.payload.data).toBeUndefined();
    }
  });

  test("round-trips with data", () => {
    const txHash = Buffer.alloc(32, 0xab);

    const original: NetworkMessage = {
      type: "reject",
      payload: {
        message: "block",
        ccode: 0x11, // REJECT_DUPLICATE
        reason: "already have block",
        data: txHash,
      },
    };

    const serialized = serializeMessage(MAGIC, original);
    const header = parseHeader(serialized)!;
    const payload = serialized.subarray(MESSAGE_HEADER_SIZE);

    const deserialized = deserializeMessage(header, payload);

    expect(deserialized.type).toBe("reject");
    if (deserialized.type === "reject") {
      expect(deserialized.payload.message).toBe("block");
      expect(deserialized.payload.data).toBeDefined();
      expect(deserialized.payload.data!.equals(txHash)).toBe(true);
    }
  });
});

describe("sendcmpct message", () => {
  test("round-trips correctly", () => {
    const original: NetworkMessage = {
      type: "sendcmpct",
      payload: {
        enabled: true,
        version: 2n,
      },
    };

    const serialized = serializeMessage(MAGIC, original);
    const header = parseHeader(serialized)!;
    const payload = serialized.subarray(MESSAGE_HEADER_SIZE);

    expect(header.command).toBe("sendcmpct");
    // 1 byte enabled + 8 bytes version
    expect(payload.length).toBe(9);

    const deserialized = deserializeMessage(header, payload);

    expect(deserialized.type).toBe("sendcmpct");
    if (deserialized.type === "sendcmpct") {
      expect(deserialized.payload.enabled).toBe(true);
      expect(deserialized.payload.version).toBe(2n);
    }
  });

  test("handles disabled state", () => {
    const original: NetworkMessage = {
      type: "sendcmpct",
      payload: {
        enabled: false,
        version: 1n,
      },
    };

    const serialized = serializeMessage(MAGIC, original);
    const header = parseHeader(serialized)!;
    const payload = serialized.subarray(MESSAGE_HEADER_SIZE);

    const deserialized = deserializeMessage(header, payload);

    expect(deserialized.type).toBe("sendcmpct");
    if (deserialized.type === "sendcmpct") {
      expect(deserialized.payload.enabled).toBe(false);
    }
  });
});

describe("feefilter message", () => {
  test("round-trips correctly", () => {
    const original: NetworkMessage = {
      type: "feefilter",
      payload: {
        feeRate: 1000n, // 1 sat/byte
      },
    };

    const serialized = serializeMessage(MAGIC, original);
    const header = parseHeader(serialized)!;
    const payload = serialized.subarray(MESSAGE_HEADER_SIZE);

    expect(header.command).toBe("feefilter");
    expect(payload.length).toBe(8);

    const deserialized = deserializeMessage(header, payload);

    expect(deserialized.type).toBe("feefilter");
    if (deserialized.type === "feefilter") {
      expect(deserialized.payload.feeRate).toBe(1000n);
    }
  });
});

describe("checksum verification", () => {
  test("correct checksum passes", () => {
    const original: NetworkMessage = { type: "verack", payload: null };
    const serialized = serializeMessage(MAGIC, original);

    const header = parseHeader(serialized)!;
    const payload = serialized.subarray(MESSAGE_HEADER_SIZE);

    // Should not throw
    expect(() => deserializeMessage(header, payload)).not.toThrow();
  });

  test("incorrect checksum throws", () => {
    const original: NetworkMessage = {
      type: "ping",
      payload: { nonce: 12345n },
    };
    const serialized = serializeMessage(MAGIC, original);

    const header = parseHeader(serialized)!;
    const payload = serialized.subarray(MESSAGE_HEADER_SIZE);

    // Corrupt the checksum
    header.checksum[0] ^= 0xff;

    expect(() => deserializeMessage(header, payload)).toThrow("Checksum mismatch");
  });

  test("corrupted payload fails checksum", () => {
    const original: NetworkMessage = {
      type: "ping",
      payload: { nonce: 12345n },
    };
    const serialized = serializeMessage(MAGIC, original);

    const header = parseHeader(serialized)!;
    const payload = Buffer.from(serialized.subarray(MESSAGE_HEADER_SIZE));

    // Corrupt the payload
    payload[0] ^= 0xff;

    expect(() => deserializeMessage(header, payload)).toThrow("Checksum mismatch");
  });
});

describe("unknown command handling", () => {
  // Per Bitcoin Core behavior, unknown messages are silently ignored (not rejected).
  // New message types are added regularly and peers may send messages we don't understand.
  test("deserializeMessage ignores unknown command (does not throw)", () => {
    const payload = Buffer.alloc(0);
    const checksum = hash256(payload).subarray(0, 4);

    const header: MessageHeader = {
      magic: MAGIC,
      command: "unknown",
      length: 0,
      checksum,
    };

    // Should not throw; returns an object with the raw command type
    const result = deserializeMessage(header, payload);
    expect(result).toBeDefined();
  });
});

describe("message constants", () => {
  test("MESSAGE_HEADER_SIZE is 24", () => {
    expect(MESSAGE_HEADER_SIZE).toBe(24);
  });

  test("MAX_MESSAGE_SIZE is 32 MiB", () => {
    expect(MAX_MESSAGE_SIZE).toBe(32 * 1024 * 1024);
  });
});

// ============================================================================
// Wire-decode caps (DoS protection)
//
// An adversarial peer can send a varint count larger than the protocol limit
// to force gigabyte-scale allocation before the loop runs out of payload bytes
// and fails. Each peer-supplied count MUST be checked BEFORE allocating.
//
// Reference: bitcoin-core/src/net_processing.cpp / src/net_processing.h.
// Cross-impl audit: CORE-PARITY-AUDIT/_dos-misbehavior-cross-impl-audit-2026-05-06.md.
// ============================================================================

describe("wire-decode caps (DoS protection)", () => {
  /** Helper: build a fake header for a given command + payload. */
  function makeHeader(command: string, payload: Buffer): MessageHeader {
    return {
      magic: MAGIC,
      command,
      length: payload.length,
      checksum: hash256(payload).subarray(0, 4),
    };
  }

  test("MAX_INV_SZ is 50000", () => {
    expect(MAX_INV_SZ).toBe(50_000);
  });

  test("MAX_HEADERS_RESULTS is 2000", () => {
    expect(MAX_HEADERS_RESULTS).toBe(2_000);
  });

  test("MAX_ADDR_TO_SEND is 1000", () => {
    expect(MAX_ADDR_TO_SEND).toBe(1_000);
  });

  test("MAX_LOCATOR_SZ is 101", () => {
    expect(MAX_LOCATOR_SZ).toBe(101);
  });

  test("inv: count > MAX_INV_SZ throws before allocating", () => {
    const writer = new BufferWriter();
    writer.writeVarInt(MAX_INV_SZ + 1);
    // Don't bother filling actual inv vectors — the cap MUST trigger first.
    const payload = writer.toBuffer();
    const header = makeHeader("inv", payload);
    expect(() => deserializeMessage(header, payload)).toThrow(/MAX_INV_SZ/);
  });

  test("inv: count = 0xFEFFFFFFFF (~1.1e9) attacker payload throws before alloc", () => {
    // Reproducer from the audit doc: varint 0xFEFFFFFFFF -> 4-byte 0xFFFFFFFF
    const writer = new BufferWriter();
    writer.writeVarInt(0xffffffff);
    const payload = writer.toBuffer();
    const header = makeHeader("inv", payload);
    expect(() => deserializeMessage(header, payload)).toThrow(/MAX_INV_SZ/);
  });

  test("getdata: count > MAX_INV_SZ throws (shares deserializer)", () => {
    const writer = new BufferWriter();
    writer.writeVarInt(MAX_INV_SZ + 1);
    const payload = writer.toBuffer();
    const header = makeHeader("getdata", payload);
    expect(() => deserializeMessage(header, payload)).toThrow(/MAX_INV_SZ/);
  });

  test("notfound: count > MAX_INV_SZ throws (shares deserializer)", () => {
    const writer = new BufferWriter();
    writer.writeVarInt(MAX_INV_SZ + 1);
    const payload = writer.toBuffer();
    const header = makeHeader("notfound", payload);
    expect(() => deserializeMessage(header, payload)).toThrow(/MAX_INV_SZ/);
  });

  test("inv: count = MAX_INV_SZ (boundary) does NOT trip cap", () => {
    // The cap rejects strictly greater than MAX_INV_SZ. At exactly the limit
    // we expect a buffer-underrun error (we didn't supply 50000 inv vectors).
    const writer = new BufferWriter();
    writer.writeVarInt(MAX_INV_SZ);
    const payload = writer.toBuffer();
    const header = makeHeader("inv", payload);
    expect(() => deserializeMessage(header, payload)).not.toThrow(/MAX_INV_SZ/);
  });

  test("headers: count > MAX_HEADERS_RESULTS throws before allocating", () => {
    const writer = new BufferWriter();
    writer.writeVarInt(MAX_HEADERS_RESULTS + 1);
    const payload = writer.toBuffer();
    const header = makeHeader("headers", payload);
    expect(() => deserializeMessage(header, payload)).toThrow(/MAX_HEADERS_RESULTS/);
  });

  test("headers: count = MAX_HEADERS_RESULTS (boundary) does NOT trip cap", () => {
    const writer = new BufferWriter();
    writer.writeVarInt(MAX_HEADERS_RESULTS);
    const payload = writer.toBuffer();
    const header = makeHeader("headers", payload);
    expect(() => deserializeMessage(header, payload)).not.toThrow(/MAX_HEADERS_RESULTS/);
  });

  test("addr: count > MAX_ADDR_TO_SEND throws before allocating", () => {
    const writer = new BufferWriter();
    writer.writeVarInt(MAX_ADDR_TO_SEND + 1);
    const payload = writer.toBuffer();
    const header = makeHeader("addr", payload);
    expect(() => deserializeMessage(header, payload)).toThrow(/MAX_ADDR_TO_SEND/);
  });

  test("getheaders locator: count > MAX_LOCATOR_SZ throws before allocating", () => {
    const writer = new BufferWriter();
    writer.writeUInt32LE(70016); // protocol version
    writer.writeVarInt(MAX_LOCATOR_SZ + 1);
    const payload = writer.toBuffer();
    const header = makeHeader("getheaders", payload);
    expect(() => deserializeMessage(header, payload)).toThrow(/MAX_LOCATOR_SZ/);
  });

  test("getblocks locator: count > MAX_LOCATOR_SZ throws before allocating", () => {
    const writer = new BufferWriter();
    writer.writeUInt32LE(70016);
    writer.writeVarInt(MAX_LOCATOR_SZ + 1);
    const payload = writer.toBuffer();
    const header = makeHeader("getblocks", payload);
    expect(() => deserializeMessage(header, payload)).toThrow(/MAX_LOCATOR_SZ/);
  });
});
