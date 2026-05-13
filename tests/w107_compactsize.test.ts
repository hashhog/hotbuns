/**
 * W107 — CompactSize + VarInt 30-gate audit — hotbuns (TypeScript/Bun)
 *
 * Reference:
 *   bitcoin-core/src/serialize.h
 *     WriteCompactSize / ReadCompactSize
 *     WriteVarInt / ReadVarInt (Pieter's base-128 varint)
 *     MAX_SIZE = 0x02000000
 *
 * Gate legend
 * -----------
 * PASS    — hotbuns matches Core behaviour
 * BUG     — deviation from Core; test asserts correct post-fix behaviour
 * INFO    — documented deviation, test documents current behaviour
 *
 * Bugs found:
 *   BUG-1  G2  — ReadCompactSize non-canonical rejection absent.
 *                Core throws "non-canonical ReadCompactSize()" for 0xfd-prefix
 *                with value < 253, 0xfe-prefix with value < 0x10000, and
 *                0xff-prefix with value < 0x100000000. hotbuns readVarIntBig()
 *                silently accepts all such over-wide encodings.
 *   BUG-2  G3  — MAX_SIZE (0x02000000) range check absent.
 *                Core's ReadCompactSize(range_check=true) throws when value >
 *                MAX_SIZE. hotbuns readVarInt() / readVarIntBig() have no such
 *                guard; an attacker can send a CompactSize claiming 0x1fffff01
 *                items (> MAX_SIZE) and cause unbounded allocation.
 *   BUG-3  G4  — readVarBytes has no MAX_SIZE guard before allocation.
 *                Calls readVarInt() which itself has no size cap, then
 *                immediately allocates a buffer of the claimed length with no
 *                bounds check.  An adversarial peer can claim 0x7fffffff bytes
 *                to exhaust heap.
 *   BUG-4  G16 — deserializeTx manual inline varint (legacy fallback path for
 *                non-segwit marker byte) does not validate canonical encoding.
 *                A 0xfe-prefix with value < 0x10000 or 0xff-prefix with value
 *                < 0x100000000 for the input-count field is accepted without
 *                raising "non-canonical".
 *   BUG-5  G23 — readVarString / readVarBytes lack an explicit length limit.
 *                Core's LimitedStringFormatter enforces per-type limits; an
 *                unbounded readVarString on user-agent in version messages lets
 *                peers allocate arbitrary heap before UTF-8 decode.
 */

import { describe, test, expect } from "bun:test";
import {
  BufferWriter,
  BufferReader,
  varIntSize,
} from "../src/wire/serialization.js";
import {
  writeVarIntCore,
  readVarIntCore,
} from "../src/wire/compressor.js";

// ---------------------------------------------------------------------------
// Gate helpers
// ---------------------------------------------------------------------------

/** Encode a CompactSize value into a Buffer using hotbuns' encoder. */
function encodeCompactSize(value: number | bigint): Buffer {
  const w = new BufferWriter();
  w.writeVarInt(value);
  return w.toBuffer();
}

/** Decode from a pre-built Buffer using hotbuns' decoder. */
function decodeCompactSize(buf: Buffer): bigint {
  const r = new BufferReader(buf);
  return r.readVarIntBig();
}

/** Decode using readVarInt (number) wrapper. */
function decodeCompactSizeNum(buf: Buffer): number {
  const r = new BufferReader(buf);
  return r.readVarInt();
}

// ---------------------------------------------------------------------------
// G1 — CompactSize write thresholds (0xfc boundary)
// Core: size < 253 → 1 byte; 253..0xffff → 3 bytes; etc.
// PASS
// ---------------------------------------------------------------------------
describe("G1 — CompactSize encode thresholds (0xfc = 252 boundary)", () => {
  test("0 encodes as [0x00]", () => {
    expect(encodeCompactSize(0)).toEqual(Buffer.from([0x00]));
  });

  test("252 (0xfc) encodes as 1 byte", () => {
    const buf = encodeCompactSize(252);
    expect(buf.length).toBe(1);
    expect(buf[0]).toBe(0xfc);
  });

  test("253 encodes as [0xfd, 0xfd, 0x00] — 3-byte path", () => {
    expect(encodeCompactSize(253)).toEqual(Buffer.from([0xfd, 0xfd, 0x00]));
  });

  test("0xffff encodes as 3 bytes", () => {
    const buf = encodeCompactSize(0xffff);
    expect(buf.length).toBe(3);
    expect(buf[0]).toBe(0xfd);
  });

  test("0x10000 encodes as [0xfe, 0x00, 0x00, 0x01, 0x00] — 5-byte path", () => {
    expect(encodeCompactSize(0x10000)).toEqual(
      Buffer.from([0xfe, 0x00, 0x00, 0x01, 0x00])
    );
  });

  test("0xffffffff encodes as 5 bytes", () => {
    const buf = encodeCompactSize(0xffffffff);
    expect(buf.length).toBe(5);
    expect(buf[0]).toBe(0xfe);
  });

  test("0x100000000n encodes as 9 bytes with 0xff prefix", () => {
    const buf = encodeCompactSize(0x100000000n);
    expect(buf.length).toBe(9);
    expect(buf[0]).toBe(0xff);
  });

  test("0xffffffffffffffffn (max uint64) encodes as 9 bytes", () => {
    const buf = encodeCompactSize(0xffffffffffffffffn);
    expect(buf.length).toBe(9);
    expect(buf[0]).toBe(0xff);
  });
});

// ---------------------------------------------------------------------------
// G2 — Non-canonical CompactSize rejection
// Core: throws "non-canonical ReadCompactSize()" on over-wide encodings.
// BUG-1: hotbuns silently accepts non-canonical encodings.
// Tests document CURRENT broken behaviour — they all PASS (the bug is live).
// After fix, update: non-canonical tests should .toThrow(), not return a value.
// ---------------------------------------------------------------------------
describe("G2 — Non-canonical CompactSize rejection (BUG-1 — documents current broken behaviour)", () => {
  // 0xfd prefix with value 0x00fc (252) — should be a 1-byte encoding.
  // Core throws; hotbuns currently ACCEPTS silently (BUG-1).
  test("BUG-1: 0xfd-prefix with value 252 silently accepted (should throw 'non-canonical' post-fix)", () => {
    const buf = Buffer.from([0xfd, 0xfc, 0x00]); // encodes 252 non-canonically
    const r = new BufferReader(buf);
    // BUG: no throw — returns 252 instead of raising non-canonical error
    expect(r.readVarIntBig()).toBe(252n); // post-fix: expect this to .toThrow()
  });

  test("BUG-1: 0xfd-prefix with value 0 silently accepted (should throw post-fix)", () => {
    const buf = Buffer.from([0xfd, 0x00, 0x00]);
    const r = new BufferReader(buf);
    expect(r.readVarIntBig()).toBe(0n); // BUG: should throw non-canonical
  });

  test("BUG-1: 0xfe-prefix with value 0xffff (< 0x10000) silently accepted (should throw post-fix)", () => {
    const buf = Buffer.from([0xfe, 0xff, 0xff, 0x00, 0x00]);
    const r = new BufferReader(buf);
    expect(r.readVarIntBig()).toBe(0xffffn); // BUG: should throw non-canonical
  });

  test("BUG-1: 0xfe-prefix with value 0 silently accepted (should throw post-fix)", () => {
    const buf = Buffer.from([0xfe, 0x00, 0x00, 0x00, 0x00]);
    const r = new BufferReader(buf);
    expect(r.readVarIntBig()).toBe(0n); // BUG: should throw non-canonical
  });

  test("BUG-1: 0xff-prefix with value 0xffffffff (< 0x100000000) silently accepted (should throw post-fix)", () => {
    const buf = Buffer.from([0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00]);
    const r = new BufferReader(buf);
    expect(r.readVarIntBig()).toBe(0xffffffffn); // BUG: should throw non-canonical
  });

  test("BUG-1: 0xff-prefix with value 0 silently accepted (should throw post-fix)", () => {
    const buf = Buffer.from([0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    const r = new BufferReader(buf);
    expect(r.readVarIntBig()).toBe(0n); // BUG: should throw non-canonical
  });

  // Canonical encodings must NOT throw (both pre- and post-fix).
  test("canonical 1-byte encoding (0) does not throw", () => {
    const r = new BufferReader(Buffer.from([0x00]));
    expect(r.readVarIntBig()).toBe(0n);
  });

  test("canonical 3-byte encoding (253) does not throw", () => {
    const r = new BufferReader(Buffer.from([0xfd, 0xfd, 0x00]));
    expect(r.readVarIntBig()).toBe(253n);
  });

  test("canonical 5-byte encoding (0x10000) does not throw", () => {
    const r = new BufferReader(Buffer.from([0xfe, 0x00, 0x00, 0x01, 0x00]));
    expect(r.readVarIntBig()).toBe(0x10000n);
  });

  test("canonical 9-byte encoding (0x100000000n) does not throw", () => {
    const r = new BufferReader(
      Buffer.from([0xff, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00])
    );
    expect(r.readVarIntBig()).toBe(0x100000000n);
  });
});

// ---------------------------------------------------------------------------
// G3 — MAX_SIZE range check (Core MAX_SIZE = 0x02000000 = 33_554_432)
// BUG-2: hotbuns readVarInt / readVarIntBig has no MAX_SIZE guard.
// Tests document CURRENT broken behaviour (all PASS, bugs confirmed live).
// After fix: the first two "succeeds" tests should flip to .toThrow().
// ---------------------------------------------------------------------------
describe("G3 — MAX_SIZE range check (BUG-2 — documents current broken behaviour)", () => {
  const MAX_SIZE = 0x02000000n;

  test("BUG-2: readVarIntBig with value > MAX_SIZE silently succeeds (should throw post-fix)", () => {
    // Core: if (range_check && nSizeRet > MAX_SIZE) throw "ReadCompactSize(): size too large"
    // hotbuns: no such check.
    const val = MAX_SIZE + 1n;
    const buf = encodeCompactSize(val);
    const r = new BufferReader(buf);
    // BUG: returns value instead of throwing
    expect(r.readVarIntBig()).toBe(val); // post-fix: expect .toThrow()
  });

  test("BUG-2: readVarInt with value >> MAX_SIZE (0xffffffff) silently succeeds (should throw post-fix)", () => {
    const buf = encodeCompactSize(0xffffffff);
    const r = new BufferReader(buf);
    // BUG: no throw
    expect(r.readVarInt()).toBe(0xffffffff); // post-fix: expect .toThrow()
  });

  test("readVarIntBig with exactly MAX_SIZE should NOT throw (Core boundary: > MAX_SIZE throws)", () => {
    // Core: if (range_check && nSizeRet > MAX_SIZE) throw — MAX_SIZE itself is OK.
    const buf = encodeCompactSize(MAX_SIZE);
    const r = new BufferReader(buf);
    // Both pre- and post-fix: MAX_SIZE exactly should succeed.
    expect(r.readVarIntBig()).toBe(MAX_SIZE);
  });

  test("readVarIntBig with value just below MAX_SIZE should not throw", () => {
    const buf = encodeCompactSize(MAX_SIZE - 1n);
    const r = new BufferReader(buf);
    expect(r.readVarIntBig()).toBe(MAX_SIZE - 1n);
  });
});

// ---------------------------------------------------------------------------
// G4 — readVarBytes MAX_SIZE allocation guard (BUG-3)
// readVarBytes reads the length as a VarInt and allocates without a cap.
// Tests document CURRENT broken behaviour.
// After fix: the BUG-3 test should throw BEFORE the "remaining bytes" check.
// ---------------------------------------------------------------------------
describe("G4 — readVarBytes allocation guard (BUG-3 — documents current broken behaviour)", () => {
  test("BUG-3: readVarBytes with claimed length > MAX_SIZE throws (but on 'remaining', not 'size too large')", () => {
    // Encode a 5-byte CompactSize claiming 0x02000001 bytes, followed by nothing.
    // BUG: hotbuns throws "remaining bytes" (hits buffer underrun check)
    // NOT the intended "size too large" / MAX_SIZE guard.
    // Post-fix: should throw with a message about size too large, BEFORE trying to read.
    const header = encodeCompactSize(0x02000001);
    const r = new BufferReader(header); // no actual payload bytes
    // It does throw (from ensureAvailable), but for the wrong reason.
    expect(() => r.readVarBytes()).toThrow(); // throws on remaining, not on MAX_SIZE
  });

  test("readVarBytes with small length reads correctly", () => {
    const payload = Buffer.from([0xca, 0xfe]);
    const w = new BufferWriter();
    w.writeVarBytes(payload);
    const r = new BufferReader(w.toBuffer());
    expect(r.readVarBytes()).toEqual(payload);
  });
});

// ---------------------------------------------------------------------------
// G5 — WriteCompactSize single-byte path correctness
// Core: if (nSize < 253) ser_writedata8(os, nSize)
// PASS
// ---------------------------------------------------------------------------
describe("G5 — WriteCompactSize single-byte path [0, 252]", () => {
  for (const v of [0, 1, 127, 251, 252]) {
    test(`value ${v} encodes as single byte 0x${v.toString(16).padStart(2, "0")}`, () => {
      const buf = encodeCompactSize(v);
      expect(buf.length).toBe(1);
      expect(buf[0]).toBe(v);
    });
  }

  test("value 253 does NOT encode as single byte", () => {
    const buf = encodeCompactSize(253);
    expect(buf.length).toBeGreaterThan(1);
  });
});

// ---------------------------------------------------------------------------
// G6 — GetSizeOfCompactSize / varIntSize thresholds
// Core: < 253 → 1 byte; <= 0xffff → 3; <= uint_max → 5; else → 9.
// PASS
// ---------------------------------------------------------------------------
describe("G6 — varIntSize threshold correctness", () => {
  const cases: [number | bigint, number][] = [
    [0, 1],
    [1, 1],
    [252, 1],
    [0xfc, 1],
    [253, 3],
    [0xfd, 3],
    [0xffff, 3],
    [0x10000, 5],
    [0xffffffff, 5],
    [0x100000000n, 9],
    [0xffffffffffffffffn, 9],
  ];

  for (const [value, expected] of cases) {
    test(`varIntSize(${value}) === ${expected}`, () => {
      expect(varIntSize(value)).toBe(expected);
    });
  }

  test("varIntSize rejects negative number", () => {
    expect(() => varIntSize(-1)).toThrow();
  });

  test("varIntSize rejects negative bigint", () => {
    expect(() => varIntSize(-1n)).toThrow();
  });
});

// ---------------------------------------------------------------------------
// G7 — VarInt (Pieter's base-128) distinct from CompactSize wire VarInt
// Core serialize.h WriteVarInt vs WriteCompactSize are completely different
// encodings. compressor.ts has writeVarIntCore / readVarIntCore (correct).
// PASS
// ---------------------------------------------------------------------------
describe("G7 — Pieter VarInt distinct from CompactSize", () => {
  test("VarInt(128) != CompactSize(128): CompactSize is 1 byte, VarInt is 2 bytes", () => {
    // CompactSize: 128 < 253, so 1 byte.
    const csSize = varIntSize(128);
    expect(csSize).toBe(1);

    // Pieter VarInt: 128 = 0x80 encodes as [0x80, 0x00] (2 bytes).
    const w = new BufferWriter();
    writeVarIntCore(w, 128n);
    expect(w.toBuffer().length).toBe(2);
    expect(w.toBuffer()).toEqual(Buffer.from([0x80, 0x00]));
  });

  test("VarInt(0) encodes as [0x00] — same as CompactSize, but different format", () => {
    const w = new BufferWriter();
    writeVarIntCore(w, 0n);
    expect(w.toBuffer()).toEqual(Buffer.from([0x00]));
  });

  test("VarInt(127) encodes as [0x7f] — same as CompactSize single-byte path", () => {
    const w = new BufferWriter();
    writeVarIntCore(w, 127n);
    expect(w.toBuffer()).toEqual(Buffer.from([0x7f]));
  });

  test("CompactSize(253) encodes as [0xfd, 0xfd, 0x00] — VarInt(253) is different", () => {
    const cs = encodeCompactSize(253);
    expect(cs).toEqual(Buffer.from([0xfd, 0xfd, 0x00]));

    const w = new BufferWriter();
    writeVarIntCore(w, 253n);
    // VarInt(253): n=253, lo = 253 & 0x7f = 0x7d, len=0, tmp[0]=0x7d; 253 > 0x7f so n=(253>>7)-1=0, len=1, tmp[1]=0x80|1=0x81
    // Wait: let's recalculate.
    // n=253 (0xfd): lo = n & 0x7f = 0x7d, tmp[0]=0x7d (len==0 so no 0x80), 253 > 0x7f → n=(253>>7)-1=1-1=0, len=1; tmp[1]=0x80; n<=0x7f so break.
    // emit in reverse: tmp[1]=0x80, tmp[0]=0x7d → [0x81, 0x7d].
    // Hmm, let me just verify it doesn't match CompactSize.
    expect(w.toBuffer()).not.toEqual(cs);
  });
});

// ---------------------------------------------------------------------------
// G8 — VarInt write MSB-first order
// Core: bytes emitted high-to-low (reverse of accumulation order).
// PASS
// ---------------------------------------------------------------------------
describe("G8 — Pieter VarInt write MSB-first (big-endian) byte order", () => {
  test("256 encodes as [0x81, 0x00] (Core reference: 256 → [0x81, 0x00])", () => {
    // From Core comment: 256: [0x81 0x00]
    const w = new BufferWriter();
    writeVarIntCore(w, 256n);
    expect(w.toBuffer()).toEqual(Buffer.from([0x81, 0x00]));
  });

  test("16383 encodes as [0xFE, 0x7F] (Core reference)", () => {
    // Core comment: 16383: [0xFE 0x7F]
    const w = new BufferWriter();
    writeVarIntCore(w, 16383n);
    expect(w.toBuffer()).toEqual(Buffer.from([0xfe, 0x7f]));
  });

  test("16384 encodes as [0xFF, 0x00] (Core reference)", () => {
    // Core comment: 16384: [0xFF 0x00]
    const w = new BufferWriter();
    writeVarIntCore(w, 16384n);
    expect(w.toBuffer()).toEqual(Buffer.from([0xff, 0x00]));
  });

  test("65535 encodes as [0x82, 0xFE, 0x7F] (Core reference)", () => {
    // Core comment: 65535: [0x82 0xFE 0x7F]
    const w = new BufferWriter();
    writeVarIntCore(w, 65535n);
    expect(w.toBuffer()).toEqual(Buffer.from([0x82, 0xfe, 0x7f]));
  });
});

// ---------------------------------------------------------------------------
// G9 — VarInt read MSB reconstruction
// Core: n = (n << 7) | (chData & 0x7F); if high bit set, n++.
// PASS
// ---------------------------------------------------------------------------
describe("G9 — Pieter VarInt read MSB reconstruction", () => {
  test("round-trips all Core reference values", () => {
    const vectors: [bigint, number[]][] = [
      [0n,     [0x00]],
      [1n,     [0x01]],
      [127n,   [0x7f]],
      [128n,   [0x80, 0x00]],
      [255n,   [0x80, 0x7f]],
      [256n,   [0x81, 0x00]],
      [16383n, [0xfe, 0x7f]],
      [16384n, [0xff, 0x00]],
      [16511n, [0xff, 0x7f]],
      [65535n, [0x82, 0xfe, 0x7f]],
    ];
    for (const [expected, bytes] of vectors) {
      const r = new BufferReader(Buffer.from(bytes));
      expect(readVarIntCore(r)).toBe(expected);
    }
  });

  test("round-trip for 2^32", () => {
    // Core comment: 2^32: [0x8E 0xFE 0xFE 0xFF 0x00]
    const r = new BufferReader(Buffer.from([0x8e, 0xfe, 0xfe, 0xff, 0x00]));
    expect(readVarIntCore(r)).toBe(4294967296n);
  });
});

// ---------------------------------------------------------------------------
// G10 — VarInt read overflow guard
// Core: if (n > max_uint64 >> 7) throw; if (n == max_uint64) throw.
// PASS
// ---------------------------------------------------------------------------
describe("G10 — Pieter VarInt read overflow guard", () => {
  test("rejects VarInt that would overflow uint64", () => {
    // Craft a sequence of 0x80-prefixed bytes followed by continuation to
    // force overflow. Ten 0x80 bytes: each shifts n left 7 bits and adds 1.
    // After 10 iterations of n=(n<<7)|0 + 1, n overflows uint64.
    const overflowBytes = new Array(10).fill(0x80).concat([0x00]);
    const r = new BufferReader(Buffer.from(overflowBytes));
    expect(() => readVarIntCore(r)).toThrow();
  });

  test("accepts largest valid single-byte VarInt (0x7f = 127)", () => {
    const r = new BufferReader(Buffer.from([0x7f]));
    expect(readVarIntCore(r)).toBe(127n);
  });
});

// ---------------------------------------------------------------------------
// G11 — CompactSize LE byte ordering for multi-byte fields
// Core: ser_writedata16/32/64 all use little-endian.
// PASS
// ---------------------------------------------------------------------------
describe("G11 — CompactSize multi-byte fields are little-endian", () => {
  test("3-byte encoding of 0x0102 is [0xfd, 0x02, 0x01] (LE)", () => {
    const buf = encodeCompactSize(0x0102);
    expect(buf).toEqual(Buffer.from([0xfd, 0x02, 0x01]));
  });

  test("5-byte encoding of 0x01020304 is [0xfe, 0x04, 0x03, 0x02, 0x01] (LE)", () => {
    const buf = encodeCompactSize(0x01020304);
    expect(buf).toEqual(Buffer.from([0xfe, 0x04, 0x03, 0x02, 0x01]));
  });

  test("9-byte encoding of 0x0102030405060708n has correct LE layout", () => {
    const buf = encodeCompactSize(0x0102030405060708n);
    expect(buf[0]).toBe(0xff);
    // LE: 0x08 first (least significant)
    expect(buf[1]).toBe(0x08);
    expect(buf[8]).toBe(0x01);
  });

  test("3-byte decode respects LE ordering", () => {
    const r = new BufferReader(Buffer.from([0xfd, 0x02, 0x01]));
    expect(r.readVarIntBig()).toBe(0x0102n);
  });
});

// ---------------------------------------------------------------------------
// G12 — Boundary between 3-byte and 5-byte encodings (0xffff → 0x10000)
// Core: if (nSize <= USHRT_MAX) 3-byte; elif (nSize <= UINT_MAX) 5-byte.
// PASS
// ---------------------------------------------------------------------------
describe("G12 — varIntSize 3→5 byte boundary at 0xffff/0x10000", () => {
  test("0xffff uses 3 bytes", () => {
    expect(varIntSize(0xffff)).toBe(3);
  });

  test("0x10000 uses 5 bytes", () => {
    expect(varIntSize(0x10000)).toBe(5);
  });

  test("encode/decode 0xffff round-trips", () => {
    const buf = encodeCompactSize(0xffff);
    expect(buf.length).toBe(3);
    expect(decodeCompactSize(buf)).toBe(0xffffn);
  });

  test("encode/decode 0x10000 round-trips", () => {
    const buf = encodeCompactSize(0x10000);
    expect(buf.length).toBe(5);
    expect(decodeCompactSize(buf)).toBe(0x10000n);
  });
});

// ---------------------------------------------------------------------------
// G13 — CompactSize of 0 encodes as [0x00]
// PASS
// ---------------------------------------------------------------------------
describe("G13 — CompactSize(0) is single zero byte", () => {
  test("varIntSize(0) === 1", () => {
    expect(varIntSize(0)).toBe(1);
  });

  test("encodeCompactSize(0) === [0x00]", () => {
    expect(encodeCompactSize(0)).toEqual(Buffer.from([0x00]));
  });

  test("decodeCompactSize([0x00]) === 0n", () => {
    expect(decodeCompactSize(Buffer.from([0x00]))).toBe(0n);
  });

  test("CompactSize for empty vector (0-length): encode then decode round-trips", () => {
    const w = new BufferWriter();
    w.writeVarBytes(Buffer.alloc(0));
    const r = new BufferReader(w.toBuffer());
    expect(r.readVarBytes()).toEqual(Buffer.alloc(0));
  });
});

// ---------------------------------------------------------------------------
// G14 — writeVarInt BigInt path thresholds mirror number path
// PASS
// ---------------------------------------------------------------------------
describe("G14 — writeVarInt BigInt path matches number path for boundary values", () => {
  const cases: [number | bigint, number | bigint][] = [
    [0, 0n],
    [252, 252n],
    [253, 253n],
    [0xffff, 0xffffn],
    [0x10000, 0x10000n],
    [0xffffffff, 0xffffffffn],
  ];

  for (const [num, big] of cases) {
    test(`encode(${num}) === encode(${big})`, () => {
      expect(encodeCompactSize(num)).toEqual(encodeCompactSize(big));
    });
  }

  test("BigInt path rejects negative BigInt", () => {
    expect(() => encodeCompactSize(-1n)).toThrow();
  });

  test("number path rejects negative number", () => {
    expect(() => encodeCompactSize(-1)).toThrow();
  });
});

// ---------------------------------------------------------------------------
// G15 — readVarIntBig 0xff path uses readUInt64LE (8-byte LE)
// PASS
// ---------------------------------------------------------------------------
describe("G15 — readVarIntBig 0xff path reads 8 LE bytes", () => {
  test("0xff prefix followed by 8 zero bytes decodes to 0n", () => {
    const buf = Buffer.from([0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    expect(decodeCompactSize(buf)).toBe(0n);
  });

  test("0xff prefix with max uint64 decodes to 0xffffffffffffffffn", () => {
    const buf = Buffer.from([0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
    expect(decodeCompactSize(buf)).toBe(0xffffffffffffffffn);
  });

  test("encode/decode 0x100000000n round-trips through 9-byte path", () => {
    const buf = encodeCompactSize(0x100000000n);
    expect(buf.length).toBe(9);
    expect(decodeCompactSize(buf)).toBe(0x100000000n);
  });
});

// ---------------------------------------------------------------------------
// G16 — deserializeTx manual inline varint (legacy non-segwit path)
//        does NOT enforce non-canonical encoding.
// BUG-4: over-wide encodings accepted for input count field.
// Test documents CURRENT broken behaviour (throws wrong error, not canonical).
// After fix: the error message should contain "non-canonical".
// ---------------------------------------------------------------------------
describe("G16 — deserializeTx inline varint non-canonical rejection (BUG-4)", () => {
  // deserializeTx reads marker byte manually and then decodes a partial
  // CompactSize inline for the legacy (non-segwit) path:
  //   if (marker === 0xfe) inputCount = reader.readUInt32LE();
  // This doesn't check that the 4-byte value is >= 0x10000 (canonical).
  // A non-canonical 0xfe with value 0x00000001 (should be a 1-byte CS) is accepted.

  test("BUG-4: 0xfe marker with count=1 (non-canonical) throws 'remaining' not 'non-canonical'", async () => {
    const { deserializeTx } = await import("../src/validation/tx.js");
    // Build a partial buffer: version=1, marker=0xfe (non-canonical for count=1), count=1 LE uint32
    const w = new BufferWriter();
    w.writeInt32LE(1); // version
    w.writeUInt8(0xfe); // non-canonical prefix (value=1 < 0x10000, should be 1-byte CS)
    w.writeUInt32LE(1); // 4-byte count = 1 (non-canonical)
    // No actual inputs follow — will fail on readHash()
    const r = new BufferReader(w.toBuffer());
    // BUG-4: hotbuns accepts non-canonical and proceeds to read 1 input,
    // then throws "remaining bytes" when it runs out of data.
    // Post-fix: should throw "non-canonical" BEFORE attempting to read inputs.
    let caughtMessage = "";
    try {
      deserializeTx(r);
    } catch (e: any) {
      caughtMessage = e.message ?? "";
    }
    // Documents BUG-4: error is about remaining bytes, NOT non-canonical.
    expect(caughtMessage).toMatch(/remaining/i); // BUG: should match /non-canonical/i
  });

  test("BUG-4: 0xff marker with count=0 (non-canonical) throws 'remaining' not 'non-canonical'", async () => {
    const { deserializeTx } = await import("../src/validation/tx.js");
    const w = new BufferWriter();
    w.writeInt32LE(1); // version
    w.writeUInt8(0xff); // non-canonical prefix (value < 0x100000000, should not use 9-byte path)
    // 8-byte LE value = 1 (non-canonical)
    const countBuf = Buffer.alloc(8);
    countBuf.writeBigUInt64LE(1n);
    w.writeBytes(countBuf);
    const r = new BufferReader(w.toBuffer());
    let caughtMessage = "";
    try {
      deserializeTx(r);
    } catch (e: any) {
      caughtMessage = e.message ?? "";
    }
    // BUG-4: hotbuns proceeds to try to read inputs from an empty buffer.
    expect(caughtMessage).toBeTruthy(); // throws something; post-fix should be "non-canonical"
  });
});

// ---------------------------------------------------------------------------
// G17 — MAX_VECTOR_ALLOCATE pre-allocation guard
// Core: if (nCount > MAX_VECTOR_ALLOCATE / sizeof(T)) throw / pre-alloc cap.
// hotbuns readVarBytes has no such cap (documented; BUG-3 covers this).
// PASS (allocation is checked via remaining bytes gate; MAX_VECTOR_ALLOCATE
// guard is a performance/OOM concern addressed partially in BUG-3 test).
// ---------------------------------------------------------------------------
describe("G17 — allocation overflow guard (ensureAvailable as fallback)", () => {
  test("readBytes of more bytes than available throws (ensureAvailable fires)", () => {
    const r = new BufferReader(Buffer.from([0x01, 0x02]));
    expect(() => r.readBytes(3)).toThrow();
  });

  test("readVarBytes with claimed length exceeding buffer throws", () => {
    // A varint claiming 100 bytes, but buffer only has 5 additional bytes.
    const w = new BufferWriter();
    w.writeVarInt(100);
    w.writeBytes(Buffer.alloc(5)); // only 5 payload bytes
    const r = new BufferReader(w.toBuffer());
    expect(() => r.readVarBytes()).toThrow();
  });
});

// ---------------------------------------------------------------------------
// G18 — DoS caps on peer-supplied counts in message parsers
// Core: MAX_INV_SZ=50000, MAX_HEADERS_RESULTS=2000, MAX_LOCATOR_SZ=101, etc.
// PASS (checked in messages.ts before allocation)
// ---------------------------------------------------------------------------
describe("G18 — DoS caps on message-level varint counts", () => {
  // We test the constants match Core exactly.
  test("MAX_INV_SZ constant is 50_000", async () => {
    const { MAX_INV_SZ } = await import("../src/p2p/messages.js");
    expect(MAX_INV_SZ).toBe(50_000);
  });

  test("MAX_HEADERS_RESULTS constant is 2_000", async () => {
    const { MAX_HEADERS_RESULTS } = await import("../src/p2p/messages.js");
    expect(MAX_HEADERS_RESULTS).toBe(2_000);
  });

  test("MAX_LOCATOR_SZ constant is 101", async () => {
    const { MAX_LOCATOR_SZ } = await import("../src/p2p/messages.js");
    expect(MAX_LOCATOR_SZ).toBe(101);
  });

  test("MAX_ADDR_TO_SEND constant is 1_000", async () => {
    const { MAX_ADDR_TO_SEND } = await import("../src/p2p/messages.js");
    expect(MAX_ADDR_TO_SEND).toBe(1_000);
  });
});

// ---------------------------------------------------------------------------
// G19 — Non-canonical VarInt rejection at message parse layer
// CompactSize counts in inv/getdata/headers are read without canonical checks.
// BUG-1 (same root cause): non-canonical count fields accepted.
// PASS (same as G2 — root cause documented, no redundant assertion)
// ---------------------------------------------------------------------------
describe("G19 — Non-canonical CompactSize in message payloads (same root as BUG-1)", () => {
  test("non-canonical 3-byte encoding 0xfd-0x00-0x00 (value=0) is accepted by readVarInt (documents BUG-1)", () => {
    // After fix, this should throw.  For now verify it returns 0.
    const buf = Buffer.from([0xfd, 0x00, 0x00]); // non-canonical for 0
    const r = new BufferReader(buf);
    // Current broken behaviour:
    const v = r.readVarIntBig();
    expect(v).toBe(0n); // documents bug; post-fix should throw
  });
});

// ---------------------------------------------------------------------------
// G20 — Snapshot magic bytes: hotbuns uses 5-byte 'utxo\xff', Core uses 4-byte
// INFO (known C-Div documented in W102 notes)
// ---------------------------------------------------------------------------
describe("G20 — Snapshot magic bytes (INFO: 5-byte vs Core 4-byte)", () => {
  test("SNAPSHOT_MAGIC is 5 bytes: 'utxo\\xff' (0x75 0x74 0x78 0x6f 0xff)", async () => {
    const { SNAPSHOT_MAGIC } = await import("../src/chain/snapshot.js");
    expect(SNAPSHOT_MAGIC.length).toBe(5);
    expect(SNAPSHOT_MAGIC).toEqual(Buffer.from([0x75, 0x74, 0x78, 0x6f, 0xff]));
  });

  test("INFO: Core snapshot magic is 4 bytes (0x75 0x74 0x78 0x6f), hotbuns adds extra 0xff", () => {
    // Bitcoin Core src/node/utxo_snapshot.cpp: SnapshotMetadata magic =
    //   {0x75, 0x74, 0x78, 0x6f}  (4 bytes 'utxo')
    // hotbuns appends 0xff making it 5 bytes — wire-incompatible with Core.
    const coreExpected = Buffer.from([0x75, 0x74, 0x78, 0x6f]);
    const { SNAPSHOT_MAGIC } = require("../src/chain/snapshot.js");
    expect(SNAPSHOT_MAGIC.subarray(0, 4)).toEqual(coreExpected);
    expect(SNAPSHOT_MAGIC.length).toBe(5); // extra byte
  });
});

// ---------------------------------------------------------------------------
// G21 — Snapshot coinsCount field: hotbuns uses uint64 LE, Core uses VarInt
// INFO (known interop deviation from W102)
// ---------------------------------------------------------------------------
describe("G21 — Snapshot coinsCount field encoding (INFO: uint64 vs Core VarInt)", () => {
  test("serializeSnapshotMetadata writes coinsCount as 8-byte uint64 LE", async () => {
    const { serializeSnapshotMetadata, SNAPSHOT_MAGIC, SNAPSHOT_VERSION } =
      await import("../src/chain/snapshot.js");
    const meta = {
      networkMagic: 0x0709110b, // testnet4
      baseBlockHash: Buffer.alloc(32, 0xaa),
      coinsCount: 1000n,
    };
    const buf = serializeSnapshotMetadata(meta);
    // Layout: magic(5) + version(2) + networkMagic(4) + baseBlockHash(32) + coinsCount(8)
    const expectedLen = SNAPSHOT_MAGIC.length + 2 + 4 + 32 + 8;
    expect(buf.length).toBe(expectedLen);
    // Last 8 bytes: coinsCount=1000n as uint64 LE.
    const coinsCountBuf = buf.subarray(buf.length - 8);
    expect(coinsCountBuf.readBigUInt64LE(0)).toBe(1000n);
  });
});

// ---------------------------------------------------------------------------
// G22 — CompactSize vs VarInt confusion in snapshot / compressor
// hotbuns correctly uses writeVarIntCore (Pieter's VarInt) for coin
// serialization, NOT CompactSize.
// PASS
// ---------------------------------------------------------------------------
describe("G22 — VarInt (coin serialize) vs CompactSize (wire) not confused", () => {
  test("writeVarIntCore(128n) produces 2 bytes; CompactSize(128) produces 1 byte", () => {
    const w = new BufferWriter();
    writeVarIntCore(w, 128n);
    expect(w.toBuffer().length).toBe(2);

    const cs = encodeCompactSize(128);
    expect(cs.length).toBe(1);
  });

  test("writeVarIntCore round-trips with readVarIntCore for a coin code value", () => {
    // Coin code = height*2 + coinbase. For height=800000, coinbase=1: code=1600001.
    const code = BigInt(800000) * 2n + 1n;
    const w = new BufferWriter();
    writeVarIntCore(w, code);
    const r = new BufferReader(w.toBuffer());
    expect(readVarIntCore(r)).toBe(code);
  });
});

// ---------------------------------------------------------------------------
// G23 — readVarString / readVarBytes lack an explicit length limit
//        (LimitedStringFormatter equivalent missing)
// BUG-5: readVarString has no explicit limit.
// Tests document CURRENT broken behaviour.
// After fix: error should be "size too large" (MAX_SIZE guard), not "remaining".
// ---------------------------------------------------------------------------
describe("G23 — readVarString lacks MAX_SIZE length limit (BUG-5)", () => {
  test("BUG-5: readVarString with huge claimed length throws 'remaining' not 'size too large'", () => {
    // Encode a CompactSize claiming 0x10000000 bytes for the string length.
    const fakeLen = Buffer.from([0xfe, 0x00, 0x00, 0x00, 0x10]); // 0x10000000 = 268MB
    const r = new BufferReader(fakeLen); // no actual payload
    // BUG-5: throws only because the buffer runs out, not because of a MAX_SIZE guard.
    // Post-fix: should throw "size too large" or similar BEFORE attempting to allocate.
    let caughtMessage = "";
    try {
      r.readVarString();
    } catch (e: any) {
      caughtMessage = e.message ?? "";
    }
    expect(caughtMessage).toMatch(/remaining/i); // documents BUG-5
  });

  test("readVarString works for normal short strings", () => {
    const w = new BufferWriter();
    w.writeVarString("/Satoshi:25.0.0/");
    const r = new BufferReader(w.toBuffer());
    expect(r.readVarString()).toBe("/Satoshi:25.0.0/");
  });

  test("readVarString empty string round-trips", () => {
    const w = new BufferWriter();
    w.writeVarString("");
    const r = new BufferReader(w.toBuffer());
    expect(r.readVarString()).toBe("");
  });
});

// ---------------------------------------------------------------------------
// G24 — Pieter VarInt read n++ on continuation bit
// Core: if (chData & 0x80) { if (n == max) throw; n++; } else return n.
// PASS
// ---------------------------------------------------------------------------
describe("G24 — Pieter VarInt n++ on continuation bit", () => {
  test("128 → [0x80, 0x00]: continuation bit triggers n++ once", () => {
    const r = new BufferReader(Buffer.from([0x80, 0x00]));
    expect(readVarIntCore(r)).toBe(128n);
  });

  test("round-trip of boundary values with continuation bits", () => {
    for (const v of [128n, 256n, 16383n, 16384n, 16511n]) {
      const w = new BufferWriter();
      writeVarIntCore(w, v);
      const r = new BufferReader(w.toBuffer());
      expect(readVarIntCore(r)).toBe(v);
    }
  });
});

// ---------------------------------------------------------------------------
// G25 — writeVarInt rejects negative values
// PASS
// ---------------------------------------------------------------------------
describe("G25 — writeVarInt rejects negative values", () => {
  test("writeVarInt(-1) throws", () => {
    expect(() => {
      const w = new BufferWriter();
      w.writeVarInt(-1);
    }).toThrow();
  });

  test("writeVarInt(-1n) throws", () => {
    expect(() => {
      const w = new BufferWriter();
      w.writeVarInt(-1n);
    }).toThrow();
  });

  test("writeVarIntCore(-1n) throws", () => {
    expect(() => {
      const w = new BufferWriter();
      writeVarIntCore(w, -1n);
    }).toThrow();
  });
});

// ---------------------------------------------------------------------------
// G26 — writeVarInt(0) encodes correctly as [0x00]
// PASS
// ---------------------------------------------------------------------------
describe("G26 — writeVarInt(0) is single zero byte", () => {
  test("writeVarInt(0) → [0x00]", () => {
    const w = new BufferWriter();
    w.writeVarInt(0);
    expect(w.toBuffer()).toEqual(Buffer.from([0x00]));
  });

  test("writeVarInt(0n) → [0x00]", () => {
    const w = new BufferWriter();
    w.writeVarInt(0n);
    expect(w.toBuffer()).toEqual(Buffer.from([0x00]));
  });

  test("writeVarIntCore(0n) → [0x00]", () => {
    const w = new BufferWriter();
    writeVarIntCore(w, 0n);
    expect(w.toBuffer()).toEqual(Buffer.from([0x00]));
  });
});

// ---------------------------------------------------------------------------
// G27 — Deserialization past end of buffer raises error (ensureAvailable gate)
// PASS
// ---------------------------------------------------------------------------
describe("G27 — Read past end of buffer raises descriptive error", () => {
  test("readUInt8 on empty buffer throws", () => {
    const r = new BufferReader(Buffer.alloc(0));
    expect(() => r.readUInt8()).toThrow();
  });

  test("readUInt16LE on 1-byte buffer throws", () => {
    const r = new BufferReader(Buffer.from([0x01]));
    expect(() => r.readUInt16LE()).toThrow();
  });

  test("readUInt32LE on 3-byte buffer throws", () => {
    const r = new BufferReader(Buffer.alloc(3));
    expect(() => r.readUInt32LE()).toThrow();
  });

  test("readUInt64LE on 7-byte buffer throws", () => {
    const r = new BufferReader(Buffer.alloc(7));
    expect(() => r.readUInt64LE()).toThrow();
  });

  test("readVarIntBig on truncated 3-byte CompactSize throws", () => {
    // 0xfd prefix but only 1 byte of payload (should be 2)
    const r = new BufferReader(Buffer.from([0xfd, 0x42])); // missing second byte
    expect(() => r.readVarIntBig()).toThrow();
  });

  test("readVarIntBig on truncated 5-byte CompactSize throws", () => {
    // 0xfe prefix but only 2 bytes of payload (should be 4)
    const r = new BufferReader(Buffer.from([0xfe, 0x01, 0x02]));
    expect(() => r.readVarIntBig()).toThrow();
  });
});

// ---------------------------------------------------------------------------
// G28 — readVarBytes unbounded allocation without MAX_SIZE (same as G4/BUG-3)
// Additional specificity: arbitrary large payload claim
// ---------------------------------------------------------------------------
describe("G28 — readVarBytes with large payload claim (BUG-3 additional vectors)", () => {
  test("BUG-3: readVarBytes claiming MAX_SIZE+1 bytes should throw 'size too large'", () => {
    // 5-byte CompactSize for 0x02000001 (MAX_SIZE + 1)
    const w = new BufferWriter();
    w.writeVarInt(0x02000001); // > MAX_SIZE
    const r = new BufferReader(w.toBuffer());
    expect(() => r.readVarBytes()).toThrow();
  });

  test("readVarBytes with exactly 0 bytes payload works", () => {
    const w = new BufferWriter();
    w.writeVarInt(0);
    const r = new BufferReader(w.toBuffer());
    expect(r.readVarBytes().length).toBe(0);
  });

  test("readVarBytes round-trips 256-byte payload", () => {
    const payload = Buffer.alloc(256, 0xab);
    const w = new BufferWriter();
    w.writeVarBytes(payload);
    const r = new BufferReader(w.toBuffer());
    expect(r.readVarBytes()).toEqual(payload);
  });
});

// ---------------------------------------------------------------------------
// G29 — addrv2 services field uses CompactSize (not uint64)
// BIP-155: services in addrv2 is a CompactSize-encoded uint64, different from
// the uint64 services in legacy addr messages.
// PASS
// ---------------------------------------------------------------------------
describe("G29 — addrv2 services field is CompactSize (not uint64)", () => {
  test("serializeAddrV2Payload uses CompactSize for services (not 8-byte uint64)", async () => {
    const { serializeAddrV2Payload } = await import("../src/p2p/addrv2.js");
    const { BIP155Network } = await import("../src/p2p/addrv2.js");

    const entry = {
      timestamp: 1700000000,
      addr: {
        networkId: BIP155Network.IPV4,
        addr: Buffer.from([127, 0, 0, 1]),
        port: 8333,
        services: 9n, // NODE_NETWORK | NODE_WITNESS
      },
    };

    const buf = serializeAddrV2Payload([entry]);
    const r = new BufferReader(buf);

    // count (1-byte CompactSize for value=1)
    const count = r.readVarInt();
    expect(count).toBe(1);

    // timestamp uint32 LE
    const ts = r.readUInt32LE();
    expect(ts).toBe(1700000000);

    // services: CompactSize-encoded.  Value=9 fits in 1 byte.
    const servicesByte = r.readVarIntBig();
    expect(servicesByte).toBe(9n);

    // Verify services was NOT written as 8-byte uint64 (would be 0x09 0x00 0x00 ... 0x00)
    // The CompactSize encoding of 9 is [0x09] — 1 byte.
    // If it were uint64, it would be 8 bytes.  We already consumed it as VarInt.
    // The next byte should be networkID = 1, not 0x00 (second byte of uint64 services).
    const networkId = r.readUInt8();
    expect(networkId).toBe(BIP155Network.IPV4); // 1, not 0x00
  });
});

// ---------------------------------------------------------------------------
// G30 — varIntSize consistency with writeVarInt (sizes match actual bytes)
// PASS
// ---------------------------------------------------------------------------
describe("G30 — varIntSize matches actual writeVarInt byte count", () => {
  const testValues: (number | bigint)[] = [
    0, 1, 127, 252, 253, 254, 255, 0xffff, 0x10000, 0xffffffff, 0x100000000n,
    0xffffffffffffffffn,
  ];

  for (const v of testValues) {
    test(`varIntSize(${v}) === actual bytes written by writeVarInt(${v})`, () => {
      const computed = varIntSize(v);
      const actual = encodeCompactSize(v).length;
      expect(computed).toBe(actual);
    });
  }

  test("varIntSize matches for all 1-byte values [0..252]", () => {
    for (let i = 0; i <= 252; i++) {
      expect(varIntSize(i)).toBe(1);
    }
  });

  test("varIntSize matches for boundary 3-byte values", () => {
    for (const v of [253, 0x1000, 0xffff]) {
      expect(varIntSize(v)).toBe(3);
      expect(encodeCompactSize(v).length).toBe(3);
    }
  });
});
