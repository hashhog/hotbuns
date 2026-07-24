import { describe, test, expect } from "bun:test";
import { BufferWriter, BufferReader, varIntSize } from "./serialization";

describe("varIntSize", () => {
  test("returns 1 for values 0-252", () => {
    expect(varIntSize(0)).toBe(1);
    expect(varIntSize(252)).toBe(1);
    expect(varIntSize(0xfc)).toBe(1);
  });

  test("returns 3 for values 253-65535", () => {
    expect(varIntSize(253)).toBe(3);
    expect(varIntSize(0xfd)).toBe(3);
    expect(varIntSize(0xffff)).toBe(3);
    expect(varIntSize(65535)).toBe(3);
  });

  test("returns 5 for values 65536-0xFFFFFFFF", () => {
    expect(varIntSize(65536)).toBe(5);
    expect(varIntSize(0x10000)).toBe(5);
    expect(varIntSize(0xffffffff)).toBe(5);
  });

  test("returns 9 for values > 0xFFFFFFFF", () => {
    expect(varIntSize(0x100000000n)).toBe(9);
    expect(varIntSize(0xffffffffffffffffn)).toBe(9);
  });

  test("throws for negative values", () => {
    expect(() => varIntSize(-1)).toThrow("non-negative");
    expect(() => varIntSize(-1n)).toThrow("non-negative");
  });
});

describe("BufferWriter", () => {
  describe("primitive types", () => {
    test("writeUInt8", () => {
      const writer = new BufferWriter();
      writer.writeUInt8(0);
      writer.writeUInt8(0xff);
      expect(writer.toBuffer()).toEqual(Buffer.from([0x00, 0xff]));
    });

    test("writeUInt16LE", () => {
      const writer = new BufferWriter();
      writer.writeUInt16LE(0);
      writer.writeUInt16LE(0xffff);
      expect(writer.toBuffer()).toEqual(Buffer.from([0x00, 0x00, 0xff, 0xff]));
    });

    test("writeUInt32LE", () => {
      const writer = new BufferWriter();
      writer.writeUInt32LE(0);
      writer.writeUInt32LE(0xffffffff);
      expect(writer.toBuffer()).toEqual(
        Buffer.from([0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff])
      );
    });

    test("writeInt32LE with negative value", () => {
      const writer = new BufferWriter();
      writer.writeInt32LE(-1);
      expect(writer.toBuffer()).toEqual(Buffer.from([0xff, 0xff, 0xff, 0xff]));
    });

    test("writeUInt64LE", () => {
      const writer = new BufferWriter();
      writer.writeUInt64LE(0n);
      writer.writeUInt64LE(0xffffffffffffffffn);
      const buf = writer.toBuffer();
      expect(buf.length).toBe(16);
      expect(buf.subarray(0, 8)).toEqual(
        Buffer.from([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
      );
      expect(buf.subarray(8, 16)).toEqual(
        Buffer.from([0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff])
      );
    });
  });

  describe("varint encoding", () => {
    test("value 0 encodes as 1 byte", () => {
      const writer = new BufferWriter();
      writer.writeVarInt(0);
      expect(writer.toBuffer()).toEqual(Buffer.from([0x00]));
    });

    test("value 252 encodes as 1 byte", () => {
      const writer = new BufferWriter();
      writer.writeVarInt(252);
      expect(writer.toBuffer()).toEqual(Buffer.from([0xfc]));
    });

    test("value 253 uses 0xFD prefix with 2 bytes", () => {
      const writer = new BufferWriter();
      writer.writeVarInt(253);
      expect(writer.toBuffer()).toEqual(Buffer.from([0xfd, 0xfd, 0x00]));
    });

    test("value 65535 uses 0xFD prefix with 2 bytes", () => {
      const writer = new BufferWriter();
      writer.writeVarInt(65535);
      expect(writer.toBuffer()).toEqual(Buffer.from([0xfd, 0xff, 0xff]));
    });

    test("value 65536 uses 0xFE prefix with 4 bytes", () => {
      const writer = new BufferWriter();
      writer.writeVarInt(65536);
      expect(writer.toBuffer()).toEqual(
        Buffer.from([0xfe, 0x00, 0x00, 0x01, 0x00])
      );
    });

    test("value 0xFFFFFFFF uses 0xFE prefix with 4 bytes", () => {
      const writer = new BufferWriter();
      writer.writeVarInt(0xffffffff);
      expect(writer.toBuffer()).toEqual(
        Buffer.from([0xfe, 0xff, 0xff, 0xff, 0xff])
      );
    });

    test("value 0x100000000 uses 0xFF prefix with 8 bytes", () => {
      const writer = new BufferWriter();
      writer.writeVarInt(0x100000000n);
      expect(writer.toBuffer()).toEqual(
        Buffer.from([0xff, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00])
      );
    });

    test("throws for negative values", () => {
      const writer = new BufferWriter();
      expect(() => writer.writeVarInt(-1)).toThrow("non-negative");
    });
  });

  describe("bytes and strings", () => {
    test("writeBytes writes raw bytes", () => {
      const writer = new BufferWriter();
      writer.writeBytes(Buffer.from([0x01, 0x02, 0x03]));
      expect(writer.toBuffer()).toEqual(Buffer.from([0x01, 0x02, 0x03]));
    });

    test("writeVarBytes writes length-prefixed bytes", () => {
      const writer = new BufferWriter();
      writer.writeVarBytes(Buffer.from([0x01, 0x02, 0x03]));
      expect(writer.toBuffer()).toEqual(Buffer.from([0x03, 0x01, 0x02, 0x03]));
    });

    test("writeVarString writes length-prefixed UTF-8 string", () => {
      const writer = new BufferWriter();
      writer.writeVarString("abc");
      expect(writer.toBuffer()).toEqual(Buffer.from([0x03, 0x61, 0x62, 0x63]));
    });

    test("writeHash writes exactly 32 bytes", () => {
      const hash = Buffer.alloc(32, 0xab);
      const writer = new BufferWriter();
      writer.writeHash(hash);
      expect(writer.toBuffer()).toEqual(hash);
    });

    test("writeHash throws for non-32-byte input", () => {
      const writer = new BufferWriter();
      expect(() => writer.writeHash(Buffer.alloc(31))).toThrow("32 bytes");
      expect(() => writer.writeHash(Buffer.alloc(33))).toThrow("32 bytes");
    });
  });
});

describe("BufferReader", () => {
  describe("primitive types", () => {
    test("readUInt8", () => {
      const reader = new BufferReader(Buffer.from([0x00, 0xff]));
      expect(reader.readUInt8()).toBe(0);
      expect(reader.readUInt8()).toBe(255);
    });

    test("readUInt16LE", () => {
      const reader = new BufferReader(Buffer.from([0x00, 0x00, 0xff, 0xff]));
      expect(reader.readUInt16LE()).toBe(0);
      expect(reader.readUInt16LE()).toBe(0xffff);
    });

    test("readUInt32LE", () => {
      const reader = new BufferReader(
        Buffer.from([0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff])
      );
      expect(reader.readUInt32LE()).toBe(0);
      expect(reader.readUInt32LE()).toBe(0xffffffff);
    });

    test("readInt32LE with negative value", () => {
      const reader = new BufferReader(Buffer.from([0xff, 0xff, 0xff, 0xff]));
      expect(reader.readInt32LE()).toBe(-1);
    });

    test("readUInt64LE", () => {
      const reader = new BufferReader(
        Buffer.from([
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
          0xff, 0xff, 0xff, 0xff,
        ])
      );
      expect(reader.readUInt64LE()).toBe(0n);
      expect(reader.readUInt64LE()).toBe(0xffffffffffffffffn);
    });
  });

  describe("varint decoding", () => {
    test("reads 1-byte varint (0-252)", () => {
      const reader = new BufferReader(Buffer.from([0x00, 0xfc]));
      expect(reader.readVarInt()).toBe(0);
      expect(reader.readVarInt()).toBe(252);
    });

    test("reads 3-byte varint (0xFD prefix)", () => {
      const reader = new BufferReader(
        Buffer.from([0xfd, 0xfd, 0x00, 0xfd, 0xff, 0xff])
      );
      expect(reader.readVarInt()).toBe(253);
      expect(reader.readVarInt()).toBe(65535);
    });

    test("reads 5-byte varint (0xFE prefix)", () => {
      const reader = new BufferReader(Buffer.from([0xfe, 0x00, 0x00, 0x01, 0x00]));
      expect(reader.readVarInt()).toBe(65536);
    });

    // A CompactSize read as a length/count is range-checked against
    // MAX_SIZE = 0x02000000, exactly as Bitcoin Core's ReadCompactSize does
    // (serialize.h:358, range_check defaulting to true). This guard is the
    // W107 DoS hardening (0ce752b) — an adversarial peer must not be able to
    // claim a 4-billion-element array. Values above MAX_SIZE that are NOT a
    // size (e.g. the BIP-155 addrv2 services bitmask) must be read with
    // readCompactSizeNoCheck() instead — see 37cf27b.
    test("rejects a 0xFE varint above MAX_SIZE (Core range check)", () => {
      const reader = new BufferReader(Buffer.from([0xfe, 0xff, 0xff, 0xff, 0xff]));
      expect(() => reader.readVarInt()).toThrow("size too large");
    });

    test("accepts exactly MAX_SIZE (boundary is inclusive, as in Core)", () => {
      // 0x02000000 little-endian = 00 00 00 02
      const reader = new BufferReader(Buffer.from([0xfe, 0x00, 0x00, 0x00, 0x02]));
      expect(reader.readVarInt()).toBe(0x02000000);
    });

    test("readCompactSizeNoCheck decodes above-MAX_SIZE values (non-size fields)", () => {
      const reader = new BufferReader(Buffer.from([0xfe, 0xff, 0xff, 0xff, 0xff]));
      expect(reader.readCompactSizeNoCheck()).toBe(0xffffffffn);
    });

    test("reads 9-byte varint (0xFF prefix) as a non-size value", () => {
      const bytes = Buffer.from([0xff, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00]);
      // 0x100000000 exceeds MAX_SIZE, so as a size it is rejected on the 0xff
      // path too (Core checks every path, serialize.h:358); as a non-size
      // 64-bit field it decodes normally.
      expect(() => new BufferReader(bytes).readVarIntBig()).toThrow("size too large");
      expect(new BufferReader(bytes).readCompactSizeNoCheck()).toBe(0x100000000n);
    });

    test("rejects non-canonical 0xFF encoding", () => {
      // 0xff-prefixed value below 0x100000000 must use a shorter encoding.
      const bytes = Buffer.from([0xff, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
      expect(() => new BufferReader(bytes).readVarIntBig()).toThrow("non-canonical");
    });
  });

  describe("bytes and strings", () => {
    test("readBytes reads fixed number of bytes", () => {
      const reader = new BufferReader(Buffer.from([0x01, 0x02, 0x03, 0x04]));
      expect(reader.readBytes(2)).toEqual(Buffer.from([0x01, 0x02]));
      expect(reader.readBytes(2)).toEqual(Buffer.from([0x03, 0x04]));
    });

    test("readVarBytes reads length-prefixed bytes", () => {
      const reader = new BufferReader(Buffer.from([0x03, 0x01, 0x02, 0x03]));
      expect(reader.readVarBytes()).toEqual(Buffer.from([0x01, 0x02, 0x03]));
    });

    test("readVarString reads length-prefixed UTF-8 string", () => {
      const reader = new BufferReader(Buffer.from([0x03, 0x61, 0x62, 0x63]));
      expect(reader.readVarString()).toBe("abc");
    });

    test("readHash reads exactly 32 bytes", () => {
      const hash = Buffer.alloc(32, 0xab);
      const reader = new BufferReader(hash);
      const result = reader.readHash();
      expect(result).toEqual(hash);
      expect(result.length).toBe(32);
      expect(reader.eof).toBe(true);
    });
  });

  describe("position tracking", () => {
    test("position tracks read offset", () => {
      const reader = new BufferReader(Buffer.from([0x01, 0x02, 0x03, 0x04]));
      expect(reader.position).toBe(0);
      reader.readUInt8();
      expect(reader.position).toBe(1);
      reader.readUInt16LE();
      expect(reader.position).toBe(3);
    });

    test("remaining tracks bytes left", () => {
      const reader = new BufferReader(Buffer.from([0x01, 0x02, 0x03, 0x04]));
      expect(reader.remaining).toBe(4);
      reader.readUInt8();
      expect(reader.remaining).toBe(3);
    });

    test("eof indicates end of buffer", () => {
      const reader = new BufferReader(Buffer.from([0x01]));
      expect(reader.eof).toBe(false);
      reader.readUInt8();
      expect(reader.eof).toBe(true);
    });
  });

  describe("error handling", () => {
    test("throws when reading past end of buffer", () => {
      const reader = new BufferReader(Buffer.from([0x01]));
      expect(() => reader.readUInt16LE()).toThrow("remaining");
    });

    test("throws when readBytes exceeds buffer", () => {
      const reader = new BufferReader(Buffer.from([0x01, 0x02]));
      expect(() => reader.readBytes(3)).toThrow("remaining");
    });

    test("throws when readHash has insufficient bytes", () => {
      const reader = new BufferReader(Buffer.alloc(31));
      expect(() => reader.readHash()).toThrow("remaining");
    });
  });
});

describe("round-trip tests", () => {
  test("primitive types round-trip correctly", () => {
    const writer = new BufferWriter();
    writer.writeUInt8(123);
    writer.writeUInt16LE(45678);
    writer.writeUInt32LE(0xdeadbeef);
    writer.writeInt32LE(-12345);
    writer.writeUInt64LE(0x123456789abcdef0n);

    const reader = new BufferReader(writer.toBuffer());
    expect(reader.readUInt8()).toBe(123);
    expect(reader.readUInt16LE()).toBe(45678);
    expect(reader.readUInt32LE()).toBe(0xdeadbeef);
    expect(reader.readInt32LE()).toBe(-12345);
    expect(reader.readUInt64LE()).toBe(0x123456789abcdef0n);
    expect(reader.eof).toBe(true);
  });

  test("varint values round-trip correctly", () => {
    // Every value here is a valid SIZE (<= MAX_SIZE 0x02000000), so it
    // round-trips through the range-checked reader. Above-MAX_SIZE values are
    // covered separately below: writeVarInt encodes them (Core's
    // WriteCompactSize has no range check either), but reading them back as a
    // size is rejected by design.
    const testValues = [0, 1, 252, 253, 254, 255, 65535, 65536, 0x02000000];

    const writer = new BufferWriter();
    for (const v of testValues) {
      writer.writeVarInt(v);
    }

    const reader = new BufferReader(writer.toBuffer());
    for (const expected of testValues) {
      const actual = reader.readVarIntBig();
      expect(actual).toBe(BigInt(expected));
    }
    expect(reader.eof).toBe(true);
  });

  test("above-MAX_SIZE varints encode, but decode only as non-size values", () => {
    for (const v of [0xffffffff, 0x100000000n]) {
      const writer = new BufferWriter();
      writer.writeVarInt(v); // writer is unrestricted, like Core's WriteCompactSize
      const buf = writer.toBuffer();

      // As a length/count: rejected (MAX_SIZE guard, Core serialize.h:358).
      expect(() => new BufferReader(buf).readVarIntBig()).toThrow("size too large");

      // As a non-size 64-bit field (e.g. addrv2 services): decodes fine.
      expect(new BufferReader(buf).readCompactSizeNoCheck()).toBe(BigInt(v));
    }
  });

  test("compound message round-trip", () => {
    const hash = Buffer.alloc(32);
    for (let i = 0; i < 32; i++) hash[i] = i;

    const writer = new BufferWriter();
    writer.writeUInt32LE(0x0100); // version
    writer.writeVarInt(2); // count
    writer.writeHash(hash);
    writer.writeVarString("hello");
    writer.writeUInt64LE(50000n);
    writer.writeVarBytes(Buffer.from([0xde, 0xad, 0xbe, 0xef]));

    const reader = new BufferReader(writer.toBuffer());
    expect(reader.readUInt32LE()).toBe(0x0100);
    expect(reader.readVarInt()).toBe(2);
    expect(reader.readHash()).toEqual(hash);
    expect(reader.readVarString()).toBe("hello");
    expect(reader.readUInt64LE()).toBe(50000n);
    expect(reader.readVarBytes()).toEqual(Buffer.from([0xde, 0xad, 0xbe, 0xef]));
    expect(reader.eof).toBe(true);
  });

  test("boundary values at primitive limits", () => {
    const writer = new BufferWriter();
    writer.writeUInt8(0);
    writer.writeUInt8(0xff);
    writer.writeUInt16LE(0);
    writer.writeUInt16LE(0xffff);
    writer.writeUInt32LE(0);
    writer.writeUInt32LE(0xffffffff);

    const reader = new BufferReader(writer.toBuffer());
    expect(reader.readUInt8()).toBe(0);
    expect(reader.readUInt8()).toBe(0xff);
    expect(reader.readUInt16LE()).toBe(0);
    expect(reader.readUInt16LE()).toBe(0xffff);
    expect(reader.readUInt32LE()).toBe(0);
    expect(reader.readUInt32LE()).toBe(0xffffffff);
    expect(reader.eof).toBe(true);
  });
});

describe("BufferReader — no backing-buffer retention (hotbuns OOM leak guard)", () => {
  // 2026-07-24 OOM root cause: readBytes returned a subarray VIEW, so any parsed
  // field kept long-term (a UTXO-cache coin's scriptPubKey, a headerChain hash, a
  // mempool tx field) pinned the ENTIRE multi-MB block/message buffer it was sliced
  // from. Repro: 50 KB of stored 32-byte views retained 800 MB (200 x 4 MB blocks);
  // coinMemoryUsage() counts the view length not the pinned buffer, so the 512 MB
  // dbcache bound never fired -> 10-16 GB / 18-36 h climb-to-OOM. readBytes MUST
  // return an independent copy so a stored field can never pin its source buffer.
  test("readBytes returns an independent copy, not a view into the source", () => {
    const src = Buffer.alloc(4 * 1024 * 1024, 0xab); // a "4 MB block" buffer
    const field = new BufferReader(src).readBytes(32);
    expect(field).toEqual(src.subarray(0, 32)); // content is correct
    expect(field.buffer).not.toBe(src.buffer); // must NOT share the 4 MB backing store
    expect(field.buffer.byteLength).toBeLessThan(src.buffer.byteLength);
  });

  test("readHash and readVarBytes results are copies too", () => {
    const src = Buffer.concat([
      Buffer.alloc(32, 0x11), // 32-byte hash
      Buffer.from([0x03, 0x22, 0x22, 0x22]), // varbytes: varint len 3 + 3 bytes
    ]);
    const reader = new BufferReader(src);
    const hash = reader.readHash();
    const vb = reader.readVarBytes();
    expect(hash.buffer).not.toBe(src.buffer);
    expect(vb.buffer).not.toBe(src.buffer);
    expect(hash).toEqual(Buffer.alloc(32, 0x11));
    expect(vb).toEqual(Buffer.alloc(3, 0x22));
  });

  test("mutating the source after a read does not affect the parsed copy", () => {
    const src = Buffer.alloc(64, 0x01);
    const field = new BufferReader(src).readBytes(32);
    src.fill(0xff); // overwrite the source in place
    expect(field.every((b) => b === 0x01)).toBe(true); // copy is unaffected
  });
});
