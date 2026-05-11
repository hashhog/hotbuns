/**
 * BIP-158 block filter test vectors.
 *
 * Test vectors are drawn from the official Bitcoin Core test data at
 * src/test/data/blockfilters.json (testnet3 blocks).  They verify
 * byte-identical compatibility with Core's GCSFilter implementation,
 * covering the three hot-spots fixed in W90:
 *
 *   Bug 1  — SipHash length byte not masked to 8 bits (BigInt overflow for
 *             scripts >= 256 bytes).  Ref: siphash.cpp Finalize(), uint8_t cast.
 *   Bug 2  — Element set not deduplicated before encoding.
 *             Ref: blockfilter.cpp BasicFilterElements(), unordered_set.
 *   Bug 3  — BitStream used LSB-first bit order instead of Core's MSB-first.
 *             Ref: streams.h BitStreamWriter::Write / BitStreamReader::Read.
 *
 * Running: bun test src/__tests__/blockfilter_bip158.test.ts
 */

import { describe, it, expect } from "bun:test";
import {
  GCSFilter,
  sipHash24,
  fastRange64,
  golombRiceEncode,
  golombRiceDecode,
  BitStreamWriter,
  BitStreamReader,
  computeFilterHeader,
  BASIC_FILTER_P,
  BASIC_FILTER_M,
} from "../storage/indexes.js";
import { hash256 } from "../crypto/primitives.js";

// =============================================================================
// Helpers
// =============================================================================

/**
 * Convert a display (reversed) Bitcoin hash hex string to internal byte-order Buffer.
 * Bitcoin hashes are displayed in reversed byte order (RPC/explorer convention).
 * Our hash functions return internal byte order.
 */
function displayHashToInternalBytes(displayHex: string): Buffer {
  return Buffer.from(displayHex, "hex").reverse();
}

/**
 * Compare a raw-bytes Buffer to a display-format (reversed) hash hex string.
 * The BIP-158 JSON stores filter headers in display (reversed) byte order.
 */
function expectBytesMatchDisplayHash(raw: Buffer, displayHex: string): void {
  const rawDisplay = Buffer.from(raw).reverse().toString("hex");
  expect(rawDisplay).toBe(displayHex);
}

// =============================================================================
// Bug 3: BitStream MSB-first encoding (Core-compatible)
// =============================================================================

describe("BitStream MSB-first (Core-compatible bit order)", () => {
  it("writeBit MSB-first: first bit lands in bit 7 of first byte", () => {
    const w = new BitStreamWriter();
    w.writeBit(1); // should set bit 7 of byte 0
    w.flush();
    const buf = w.toBuffer();
    // 0x80 = 10000000b — bit 7 is the first bit
    expect(buf[0]).toBe(0x80);
  });

  it("writeBit MSB-first: 0 1 0 1 0 1 0 1 = 0x55", () => {
    const w = new BitStreamWriter();
    for (const b of [0, 1, 0, 1, 0, 1, 0, 1]) w.writeBit(b);
    w.flush();
    // 0 1 0 1 0 1 0 1 MSB-first = 0b01010101 = 0x55
    expect(w.toBuffer()[0]).toBe(0x55);
  });

  it("writeBits MSB-first: 0b10110 in 5 bits", () => {
    const w = new BitStreamWriter();
    w.writeBits(0b10110n, 5);
    w.flush();
    // 5 bits MSB-first into top 5 bits of byte: 10110_000 = 0xb0
    expect(w.toBuffer()[0]).toBe(0xb0);
  });

  it("roundtrip: writeBits/readBits MSB-first", () => {
    const values: Array<[bigint, number]> = [
      [0n, 1],
      [1n, 1],
      [0b10101n, 5],
      [0b111n, 3],
      [0xabcn, 12],
      [0xfffffn, 20],
      [12345678n, 25],
    ];

    const w = new BitStreamWriter();
    for (const [v, n] of values) w.writeBits(v, n);
    w.flush();

    const r = new BitStreamReader(w.toBuffer());
    for (const [v, n] of values) {
      expect(r.readBits(n)).toBe(v);
    }
  });

  it("roundtrip: writeBit + readBit across byte boundaries", () => {
    const bits = [1, 0, 1, 1, 0, 0, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1];
    const w = new BitStreamWriter();
    for (const b of bits) w.writeBit(b);
    w.flush();

    const r = new BitStreamReader(w.toBuffer());
    for (const b of bits) {
      expect(r.readBit()).toBe(b);
    }
  });

  it("known byte: 8 bits 1-0-0-0-0-0-0-1 MSB-first = 0x81", () => {
    const w = new BitStreamWriter();
    for (const b of [1, 0, 0, 0, 0, 0, 0, 1]) w.writeBit(b);
    w.flush();
    expect(w.toBuffer()[0]).toBe(0x81);
  });
});

// =============================================================================
// Golomb-Rice roundtrip (depends on MSB-first BitStream)
// =============================================================================

describe("Golomb-Rice encoding/decoding (MSB-first)", () => {
  const P = BASIC_FILTER_P; // 19n

  it("encodes and decodes 0", () => {
    const w = new BitStreamWriter();
    golombRiceEncode(w, P, 0n);
    w.flush();
    const r = new BitStreamReader(w.toBuffer());
    expect(golombRiceDecode(r, P)).toBe(0n);
  });

  it("encodes and decodes values spanning multiple quotient-1 bits", () => {
    const values = [0n, 1n, 100n, 524288n, 1000000n, 784930n];
    const w = new BitStreamWriter();
    for (const v of values) golombRiceEncode(w, P, v);
    w.flush();
    const r = new BitStreamReader(w.toBuffer());
    for (const v of values) expect(golombRiceDecode(r, P)).toBe(v);
  });

  it("encodes a value with known quotient and remainder", () => {
    // value = 2^19 + 7 = 524295.  quotient=1, remainder=7.
    // MSB-first encoding: 1 (q=1 unary), 0 (terminator), then 19 bits of 7.
    // 7 in 19 bits = 0b000_0000_0000_0000_0111
    // Stream: 1 0 [19 bits of 7] padded to full bytes.
    const value = (1n << P) + 7n;
    const w = new BitStreamWriter();
    golombRiceEncode(w, P, value);
    w.flush();
    const r = new BitStreamReader(w.toBuffer());
    expect(golombRiceDecode(r, P)).toBe(value);
  });
});

// =============================================================================
// Bug 1: SipHash length byte masking
// =============================================================================

describe("SipHash-2-4 length byte masking (Bug 1)", () => {
  it("produces consistent hashes for short data", () => {
    const k0 = 0x0706050403020100n;
    const k1 = 0x0f0e0d0c0b0a0908n;
    const data = Buffer.alloc(15);
    for (let i = 0; i < 15; i++) data[i] = i;
    const h1 = sipHash24(k0, k1, data);
    const h2 = sipHash24(k0, k1, data);
    expect(h1).toBe(h2);
    expect(typeof h1).toBe("bigint");
    // must fit in 64 bits
    expect(h1 & 0xffffffffffffffffn).toBe(h1);
  });

  it("256-byte script: SipHash result fits in 64 bits (no BigInt overflow)", () => {
    // Crafted to trigger the former BigInt overflow: a 256-byte script would
    // produce BigInt(256) << 56n = 0x10000000000000000n (65 bits) before the
    // fix.  With the fix, we mask to (256n & 0xffn) << 56n = 0n (256 % 256 = 0).
    const k0 = 1n;
    const k1 = 2n;
    const data = Buffer.alloc(256, 0xaa);
    const hash = sipHash24(k0, k1, data);
    expect(hash & 0xffffffffffffffffn).toBe(hash);
    expect(typeof hash).toBe("bigint");
  });

  it("257-byte script: SipHash result fits in 64 bits (no BigInt overflow)", () => {
    const k0 = 1n;
    const k1 = 2n;
    const data = Buffer.alloc(257, 0xbb);
    const hash = sipHash24(k0, k1, data);
    expect(hash & 0xffffffffffffffffn).toBe(hash);
  });

  it("length-byte masking: data of length 256 and 0 have different hashes", () => {
    // Without the fix, both would have the same top-byte of the last block
    // (0n << 56n = 0n), making them potentially collide.  After fix they
    // still differ because the remaining-byte payloads differ.
    const k0 = 1n;
    const k1 = 2n;
    // Length 256: 0 remaining bytes after 32 full 8-byte blocks; length byte = 0
    const data256 = Buffer.alloc(256, 0x01);
    // Length 0: 0 bytes, 0 full blocks; length byte = 0
    const data0 = Buffer.alloc(0);
    const h256 = sipHash24(k0, k1, data256);
    const h0 = sipHash24(k0, k1, data0);
    // They should differ because the message content differs
    expect(h256).not.toBe(h0);
  });
});

// =============================================================================
// Bug 2: Element deduplication
// =============================================================================

describe("GCSFilter element deduplication (Bug 2)", () => {
  it("deduplicated filter N equals unique element count", () => {
    const blockHash = Buffer.alloc(32, 0x01);
    const script = Buffer.from([0x76, 0xa9, 0x14, ...Buffer.alloc(20, 0x11), 0x88, 0xac]);
    // Pass the same script 5 times — should count as 1
    const filter = new GCSFilter([script, script, script, script, script], blockHash);
    expect(filter.getN()).toBe(1);
  });

  it("filter with 2 identical elements still matches the element", () => {
    const blockHash = Buffer.alloc(32, 0x02);
    const s = Buffer.from("uniq_script");
    const filter = new GCSFilter([s, s], blockHash);
    expect(filter.getN()).toBe(1);
    expect(filter.match(s)).toBe(true);
  });

  it("filter with 3 unique elements has N=3", () => {
    const blockHash = Buffer.alloc(32, 0x03);
    const elems = [
      Buffer.from("script_a"),
      Buffer.from("script_b"),
      Buffer.from("script_c"),
    ];
    const filter = new GCSFilter(elems, blockHash);
    expect(filter.getN()).toBe(3);
    for (const e of elems) expect(filter.match(e)).toBe(true);
  });

  it("2 unique + 1 dup: N=2", () => {
    const blockHash = Buffer.alloc(32, 0x04);
    const a = Buffer.from("alpha");
    const b = Buffer.from("beta");
    const filter = new GCSFilter([a, b, a], blockHash);
    expect(filter.getN()).toBe(2);
    expect(filter.match(a)).toBe(true);
    expect(filter.match(b)).toBe(true);
  });
});

// =============================================================================
// BIP-158 official test vectors (from bitcoin-core/src/test/data/blockfilters.json)
// =============================================================================

describe("BIP-158 official test vectors", () => {
  /**
   * Block 0 (testnet3 genesis), filter type BASIC.
   *
   * Block hash (display):  000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943
   * Block hash (internal): 43497fd7f8269571...00000000
   * Previous filter header: (zeros — genesis)
   * scriptPubKey: 4104678afdb0...5fac (67 bytes, OP_DATA_65 <pubkey> OP_CHECKSIG)
   * Expected filter hex:   019dfca8
   * Expected header (display): 21584579b7eb08997773e5aeff3a7f932700042d0ed2a6129012b7d7ae81b750
   *
   * NOTE: the BIP-158 JSON stores filter headers in Bitcoin display byte order
   * (reversed relative to internal byte order).  computeFilterHeader() returns
   * raw (internal) bytes; we use expectBytesMatchDisplayHash() to compare.
   */
  it("block 0 genesis: filter bytes match Core", () => {
    const blockHashDisplay = "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943";
    const blockHash = displayHashToInternalBytes(blockHashDisplay);

    // scriptPubKey (not including the CompactSize length prefix from the wire format)
    const script = Buffer.from(
      "4104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac",
      "hex"
    );

    const filter = new GCSFilter([script], blockHash);
    expect(filter.getN()).toBe(1);
    expect(filter.getEncodedFilter().toString("hex")).toBe("019dfca8");

    // Verify match works correctly on the actual script
    expect(filter.match(script)).toBe(true);

    // Verify filter hash
    const filterHash = filter.getHash();
    expect(filterHash.length).toBe(32);

    // Verify filter header (hash256(filterHash || prevHeader), prevHeader = zeros)
    // The BIP-158 JSON stores headers in display (reversed) format.
    const prevHeader = Buffer.alloc(32, 0);
    const header = computeFilterHeader(filterHash, prevHeader);
    expectBytesMatchDisplayHash(header,
      "21584579b7eb08997773e5aeff3a7f932700042d0ed2a6129012b7d7ae81b750"
    );
  });

  /**
   * Block 2 (testnet3), BASIC filter.
   *
   * Block hash (display):  000000006c02c8ea6e4ff69651f7fcde348fb9d557a06e6957b65552002a7820
   * scriptPubKey: 21038a7f6ef1c8ca0c588aa53fa860128077c9e6c11e6830f4d7ee4e763a56b7718fac
   *   (35 bytes = OP_DATA_33 <compressed-pubkey> OP_CHECKSIG)
   *   The JSON shows the wire form with the length byte 0x23 prepended; we strip it.
   * Previous filter header (display): d7bdac13a59d745b1add0d2ce852f1a0442e8945fc1bf3848d3cbffd88c24fe1
   * Expected filter:       0174a170
   * Expected header (display): 186afd11ef2b5e7e3504f2e8cbf8df28a1fd251fe53d60dff8b1467d1b386cf0
   */
  it("block 2: filter bytes match Core", () => {
    const blockHashDisplay = "000000006c02c8ea6e4ff69651f7fcde348fb9d557a06e6957b65552002a7820";
    const blockHash = displayHashToInternalBytes(blockHashDisplay);

    // scriptPubKey only (without the 0x23 CompactSize length prefix in the JSON)
    const script = Buffer.from(
      "21038a7f6ef1c8ca0c588aa53fa860128077c9e6c11e6830f4d7ee4e763a56b7718fac",
      "hex"
    );

    const filter = new GCSFilter([script], blockHash);
    expect(filter.getN()).toBe(1);
    expect(filter.getEncodedFilter().toString("hex")).toBe("0174a170");
    expect(filter.match(script)).toBe(true);

    // prevHeader is stored in display format in JSON — convert to internal bytes
    const prevHeader = displayHashToInternalBytes(
      "d7bdac13a59d745b1add0d2ce852f1a0442e8945fc1bf3848d3cbffd88c24fe1"
    );
    const header = computeFilterHeader(filter.getHash(), prevHeader);
    expectBytesMatchDisplayHash(header,
      "186afd11ef2b5e7e3504f2e8cbf8df28a1fd251fe53d60dff8b1467d1b386cf0"
    );
  });

  /**
   * Block 3 (testnet3), BASIC filter.
   *
   * Block hash (display):  000000008b896e272758da5297bcd98fdc6d97c9b765ecec401e286dc1fdbe10
   * scriptPubKey: 2103f6d9ff4c12959445ca5549c811683bf9c88e637b222dd2e0311154c4c85cf423ac
   *   (35 bytes, same pattern as block 2)
   * Previous filter header (display): 186afd11ef2b5e7e3504f2e8cbf8df28a1fd251fe53d60dff8b1467d1b386cf0
   * Expected filter:       016cf7a0
   * Expected header (display): 8d63aadf5ab7257cb6d2316a57b16f517bff1c6388f124ec4c04af1212729d2a
   */
  it("block 3: filter bytes match Core", () => {
    const blockHashDisplay = "000000008b896e272758da5297bcd98fdc6d97c9b765ecec401e286dc1fdbe10";
    const blockHash = displayHashToInternalBytes(blockHashDisplay);

    const script = Buffer.from(
      "2103f6d9ff4c12959445ca5549c811683bf9c88e637b222dd2e0311154c4c85cf423ac",
      "hex"
    );

    const filter = new GCSFilter([script], blockHash);
    expect(filter.getN()).toBe(1);
    expect(filter.getEncodedFilter().toString("hex")).toBe("016cf7a0");
    expect(filter.match(script)).toBe(true);

    const prevHeader = displayHashToInternalBytes(
      "186afd11ef2b5e7e3504f2e8cbf8df28a1fd251fe53d60dff8b1467d1b386cf0"
    );
    const header = computeFilterHeader(filter.getHash(), prevHeader);
    expectBytesMatchDisplayHash(header,
      "8d63aadf5ab7257cb6d2316a57b16f517bff1c6388f124ec4c04af1212729d2a"
    );
  });

  /**
   * Block 1414221: empty filter (coinbase only, non-parseable OP_RETURN-like
   * output, plus the filter is empty "00").
   *
   * This tests the empty filter case (N=0, encoded = "00").
   *
   * Block hash (display):  0000000000000027b2b3b3381f114f674f481544ff2be37ae3788d7e078383b1
   * Expected filter:       00   (empty — sole output is unspendable)
   * Expected header:       021e8882ef5a0ed932edeebbecfeda1d7ce528ec7b3daa27641acf1189d7b5dc
   * Previous filter header: 5e5e12d90693c8e936f01847859404c67482439681928353ca1296982042864e
   */
  it("block 1414221: empty filter (no spendable scripts)", () => {
    const filter = new GCSFilter([], Buffer.alloc(32, 0));
    expect(filter.getN()).toBe(0);
    expect(filter.getEncodedFilter().toString("hex")).toBe("00");
    expect(filter.match(Buffer.from("anything"))).toBe(false);
  });

  /**
   * GCSFilter.fromEncoded round-trip: decode the genesis filter back and
   * verify it still matches the genesis script.
   */
  it("block 0: fromEncoded round-trip matches original script", () => {
    const blockHashDisplay = "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943";
    const blockHash = displayHashToInternalBytes(blockHashDisplay);
    const script = Buffer.from(
      "4104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac",
      "hex"
    );

    // Use the known-good encoded bytes from Core
    const encoded = Buffer.from("019dfca8", "hex");
    const restored = GCSFilter.fromEncoded(encoded, blockHash);
    expect(restored.getN()).toBe(1);
    expect(restored.match(script)).toBe(true);
  });

  /**
   * Deduplication + BIP-158 vector: feeding the genesis script twice must
   * produce exactly the same filter bytes as the single-element case.
   * This exercises Bug 2 (dedup) in a vector-verified context.
   */
  it("block 0: duplicate script input produces identical filter to single-script input", () => {
    const blockHash = displayHashToInternalBytes(
      "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943"
    );
    const script = Buffer.from(
      "4104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac",
      "hex"
    );

    const filterOnce = new GCSFilter([script], blockHash);
    const filterDup = new GCSFilter([script, script, script], blockHash);

    expect(filterOnce.getN()).toBe(1);
    expect(filterDup.getN()).toBe(1);
    expect(filterDup.getEncodedFilter().toString("hex")).toBe("019dfca8");
    expect(filterOnce.getEncodedFilter().toString("hex")).toBe(
      filterDup.getEncodedFilter().toString("hex")
    );
  });
});

// =============================================================================
// fastRange64: verify 64-bit semantics
// =============================================================================

describe("fastRange64 precision", () => {
  it("(2^64 - 1) * M / 2^64 stays below M", () => {
    const maxU64 = 0xffffffffffffffffn;
    const M = BASIC_FILTER_M;
    const result = fastRange64(maxU64, 10n * M);
    expect(result).toBeLessThan(10n * M);
  });

  it("result always < range for a selection of inputs", () => {
    const range = 784931n * 100n;
    const hashes = [
      0n,
      1n,
      0x8000000000000000n,
      0xffffffffffffffffn,
      0x123456789abcdef0n,
    ];
    for (const h of hashes) {
      const r = fastRange64(h, range);
      expect(r).toBeLessThan(range);
      expect(r).toBeGreaterThanOrEqual(0n);
      // Result must fit in 64 bits
      expect(r & 0xffffffffffffffffn).toBe(r);
    }
  });
});
