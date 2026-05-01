/**
 * Tests for Bitcoin Core-compatible amount/script compression.
 *
 * Reference vectors and round-trip checks pulled from
 * bitcoin-core/src/test/compress_tests.cpp where possible.
 */
import { describe, test, expect } from "bun:test";
import {
  writeVarIntCore,
  readVarIntCore,
  compressAmount,
  decompressAmount,
  compressScript,
  decompressScript,
  serializeTxOutCompressed,
  deserializeTxOutCompressed,
  getSpecialScriptSize,
  NUM_SPECIAL_SCRIPTS,
} from "./compressor.js";
import { BufferWriter, BufferReader } from "./serialization.js";

describe("VARINT (Pieter's varint, Coin::Serialize)", () => {
  test("encodes 0..127 as a single byte equal to the value", () => {
    for (const n of [0n, 1n, 0x42n, 0x7fn]) {
      const w = new BufferWriter();
      writeVarIntCore(w, n);
      const buf = w.toBuffer();
      expect(buf.length).toBe(1);
      expect(buf[0]).toBe(Number(n));
    }
  });

  test("0x80 encodes as two bytes 0x80 0x00", () => {
    const w = new BufferWriter();
    writeVarIntCore(w, 0x80n);
    expect(w.toBuffer()).toEqual(Buffer.from([0x80, 0x00]));
  });

  test("round-trips boundary values up to uint64 max", () => {
    const cases: bigint[] = [
      0n,
      1n,
      0x7fn,
      0x80n,
      0xffn,
      0x100n,
      0xffffn,
      0x10000n,
      0xffffffffn,
      0x100000000n,
      (1n << 63n) - 1n,
      (1n << 64n) - 1n,
    ];
    for (const v of cases) {
      const w = new BufferWriter();
      writeVarIntCore(w, v);
      const r = new BufferReader(w.toBuffer());
      expect(readVarIntCore(r)).toBe(v);
    }
  });

  test("rejects negative values on write", () => {
    const w = new BufferWriter();
    expect(() => writeVarIntCore(w, -1n)).toThrow();
  });
});

describe("CompressAmount / DecompressAmount", () => {
  test("identity for zero", () => {
    expect(compressAmount(0n)).toBe(0n);
    expect(decompressAmount(0n)).toBe(0n);
  });

  test("known compress values from Core", () => {
    // 1 sat -> 0x09 (e=0, n=0, d=1: 1 + (0*9 + 1 - 1)*10 + 0 = 1; wait let me recompute)
    // n=1: trailing zeros e=0, e<9 so d=n%10=1, n /= 10 = 0;
    //   encoded = 1 + (n*9 + d - 1)*10 + e = 1 + (0+0)*10 + 0 = 1.
    expect(compressAmount(1n)).toBe(1n);
    // 100_000_000 sat (1 BTC): trailing zeros e=8, n=1; e<9, d=n%10=1, n/=10=0;
    //   encoded = 1 + (0*9 + 1 - 1)*10 + 8 = 9.
    expect(compressAmount(100_000_000n)).toBe(9n);
    // 1_000_000_000 sat (10 BTC): trailing zeros e=9 (clamped); n=1;
    //   encoded = 1 + (n - 1)*10 + 9 = 1 + 0 + 9 = 10.
    expect(compressAmount(1_000_000_000n)).toBe(10n);
    // 50 BTC subsidy = 5_000_000_000 sat: e=9, n=5;
    //   encoded = 1 + 4*10 + 9 = 50.
    expect(compressAmount(5_000_000_000n)).toBe(50n);
  });

  test("round-trips a sweep of plausible amounts", () => {
    const cases: bigint[] = [
      0n,
      1n,
      546n, // dust threshold area
      100_000_000n,
      50_00000000n,
      21_000_000n * 100_000_000n, // MAX_MONEY
      999_999_999_999_999n,
    ];
    for (const v of cases) {
      expect(decompressAmount(compressAmount(v))).toBe(v);
    }
  });
});

describe("CompressScript / DecompressScript", () => {
  test("P2PKH (type 0x00)", () => {
    const h = Buffer.alloc(20, 0xa1);
    const spk = Buffer.concat([
      Buffer.from([0x76, 0xa9, 0x14]),
      h,
      Buffer.from([0x88, 0xac]),
    ]);
    const out = compressScript(spk);
    expect(out).not.toBeNull();
    expect(out!.length).toBe(21);
    expect(out![0]).toBe(0x00);
    expect(out!.subarray(1).equals(h)).toBe(true);

    const round = decompressScript(0x00, out!.subarray(1));
    expect(round.equals(spk)).toBe(true);
  });

  test("P2SH (type 0x01)", () => {
    const h = Buffer.alloc(20, 0xb2);
    const spk = Buffer.concat([
      Buffer.from([0xa9, 0x14]),
      h,
      Buffer.from([0x87]),
    ]);
    const out = compressScript(spk);
    expect(out).not.toBeNull();
    expect(out!.length).toBe(21);
    expect(out![0]).toBe(0x01);

    const round = decompressScript(0x01, out!.subarray(1));
    expect(round.equals(spk)).toBe(true);
  });

  test("P2PK compressed pubkey (type 0x02 / 0x03)", () => {
    // Generator point compressed: 0x02 || x. This is a real curve point.
    const xG = Buffer.from(
      "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
      "hex"
    );
    const compressed = Buffer.concat([Buffer.from([0x02]), xG]);
    const spk = Buffer.concat([
      Buffer.from([0x21]),
      compressed,
      Buffer.from([0xac]),
    ]);
    const out = compressScript(spk);
    expect(out).not.toBeNull();
    expect(out!.length).toBe(33);
    expect(out![0]).toBe(0x02);
    const round = decompressScript(0x02, out!.subarray(1));
    expect(round.equals(spk)).toBe(true);
  });

  test("P2PK uncompressed pubkey (type 0x04 / 0x05)", () => {
    // Use the hardcoded Satoshi-genesis pubkey, which is on-curve.
    const fullPubkey = Buffer.from(
      "04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f",
      "hex"
    );
    const spk = Buffer.concat([
      Buffer.from([0x41]),
      fullPubkey,
      Buffer.from([0xac]),
    ]);
    const out = compressScript(spk);
    expect(out).not.toBeNull();
    expect(out!.length).toBe(33);
    // Leading byte: 0x04 | (y & 1).
    const yLastByte = fullPubkey[64]!;
    expect(out![0]).toBe(0x04 | (yLastByte & 0x01));

    const round = decompressScript(out![0], out!.subarray(1));
    expect(round.equals(spk)).toBe(true);
  });

  test("returns null for non-special scripts (P2WPKH, OP_RETURN, etc.)", () => {
    // P2WPKH
    expect(
      compressScript(Buffer.concat([Buffer.from([0x00, 0x14]), Buffer.alloc(20)]))
    ).toBeNull();
    // OP_RETURN (data carrier)
    expect(compressScript(Buffer.from([0x6a, 0x02, 0xab, 0xcd]))).toBeNull();
    // Plain push, no CHECKSIG suffix
    expect(compressScript(Buffer.from([0x21, ...new Uint8Array(33)]))).toBeNull();
  });

  test("getSpecialScriptSize matches Core's table", () => {
    expect(getSpecialScriptSize(0)).toBe(20);
    expect(getSpecialScriptSize(1)).toBe(20);
    expect(getSpecialScriptSize(2)).toBe(32);
    expect(getSpecialScriptSize(3)).toBe(32);
    expect(getSpecialScriptSize(4)).toBe(32);
    expect(getSpecialScriptSize(5)).toBe(32);
    // Outside range: 0 (caller falls through to raw script branch).
    expect(getSpecialScriptSize(6)).toBe(0);
  });

  test("nSpecialScripts constant is 6", () => {
    expect(NUM_SPECIAL_SCRIPTS).toBe(6);
  });
});

describe("TxOutCompression (VarInt(value)+ScriptCompression)", () => {
  test("byte-level layout for a P2PKH 50 BTC coinbase output", () => {
    const h = Buffer.alloc(20, 0x55);
    const spk = Buffer.concat([
      Buffer.from([0x76, 0xa9, 0x14]),
      h,
      Buffer.from([0x88, 0xac]),
    ]);
    const w = new BufferWriter();
    serializeTxOutCompressed(w, 50_00000000n, spk);
    const bytes = w.toBuffer();

    // Expected layout:
    //   VARINT(CompressAmount(5_000_000_000)) = VARINT(50) = 1 byte (0x32).
    //   ScriptCompression: 21-byte payload (leading 0x00 + 20-byte hash).
    expect(bytes.length).toBe(1 + 21);
    expect(bytes[0]).toBe(50); // 0x32
    expect(bytes[1]).toBe(0x00); // P2PKH special-type tag
    expect(bytes.subarray(2).equals(h)).toBe(true);

    // Round-trip
    const r = new BufferReader(bytes);
    const got = deserializeTxOutCompressed(r);
    expect(got.value).toBe(50_00000000n);
    expect(got.scriptPubKey.equals(spk)).toBe(true);
  });

  test("non-special script writes VARINT(size + 6) prefix", () => {
    const odd = Buffer.from([0x6a, 0x04, 0x01, 0x02, 0x03, 0x04]); // 6 bytes
    const w = new BufferWriter();
    serializeTxOutCompressed(w, 1n, odd);
    const bytes = w.toBuffer();
    // Amount: VARINT(CompressAmount(1)) = VARINT(1) = 1 byte (0x01).
    // Script: VARINT(6 + 6) = VARINT(12) = 1 byte (0x0c) + 6 raw bytes.
    expect(bytes[0]).toBe(0x01);
    expect(bytes[1]).toBe(0x0c);
    expect(bytes.subarray(2).equals(odd)).toBe(true);

    const r = new BufferReader(bytes);
    const got = deserializeTxOutCompressed(r);
    expect(got.value).toBe(1n);
    expect(got.scriptPubKey.equals(odd)).toBe(true);
  });
});
