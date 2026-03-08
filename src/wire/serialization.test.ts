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
      const reader = new BufferReader(
        Buffer.from([0xfe, 0x00, 0x00, 0x01, 0x00, 0xfe, 0xff, 0xff, 0xff, 0xff])
      );
      expect(reader.readVarInt()).toBe(65536);
      expect(reader.readVarInt()).toBe(0xffffffff);
    });

    test("reads 9-byte varint (0xFF prefix)", () => {
      const reader = new BufferReader(
        Buffer.from([0xff, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00])
      );
      expect(reader.readVarIntBig()).toBe(0x100000000n);
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
    const testValues = [
      0,
      1,
      252,
      253,
      254,
      255,
      65535,
      65536,
      0xffffffff,
      0x100000000n,
    ];

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
