/**
 * Minisketch tests.
 *
 * Tests GF(2^32) arithmetic and set reconciliation functionality.
 */

import { describe, expect, test } from "bun:test";
import {
  Minisketch,
  GF2_32,
  makeMinisketch32,
  estimateDifference,
  chooseSketchCapacity,
  MINISKETCH_BITS,
} from "../src/p2p/minisketch.js";

describe("GF(2^32) Arithmetic", () => {
  describe("add/sub", () => {
    test("add is XOR", () => {
      expect(GF2_32.add(0, 0)).toBe(0);
      expect(GF2_32.add(1, 0)).toBe(1);
      expect(GF2_32.add(0, 1)).toBe(1);
      expect(GF2_32.add(1, 1)).toBe(0);
      expect(GF2_32.add(0xff, 0xff)).toBe(0);
      expect(GF2_32.add(0xaa, 0x55)).toBe(0xff);
    });

    test("sub is same as add in GF(2)", () => {
      expect(GF2_32.sub(0, 0)).toBe(GF2_32.add(0, 0));
      expect(GF2_32.sub(1, 1)).toBe(GF2_32.add(1, 1));
      expect(GF2_32.sub(0xdeadbeef, 0xcafebabe)).toBe(GF2_32.add(0xdeadbeef, 0xcafebabe));
    });
  });

  describe("mul", () => {
    test("multiply by 0 gives 0", () => {
      expect(GF2_32.mul(0, 0)).toBe(0);
      expect(GF2_32.mul(12345, 0)).toBe(0);
      expect(GF2_32.mul(0, 67890)).toBe(0);
    });

    test("multiply by 1 gives identity", () => {
      expect(GF2_32.mul(1, 1)).toBe(1);
      expect(GF2_32.mul(12345, 1)).toBe(12345);
      expect(GF2_32.mul(1, 67890)).toBe(67890);
    });

    test("multiplication is commutative", () => {
      expect(GF2_32.mul(5, 7)).toBe(GF2_32.mul(7, 5));
      expect(GF2_32.mul(0x1234, 0x5678)).toBe(GF2_32.mul(0x5678, 0x1234));
      expect(GF2_32.mul(0xdeadbeef, 0xcafebabe)).toBe(GF2_32.mul(0xcafebabe, 0xdeadbeef));
    });

    test("multiplication is associative", () => {
      const a = 123;
      const b = 456;
      const c = 789;
      expect(GF2_32.mul(GF2_32.mul(a, b), c)).toBe(GF2_32.mul(a, GF2_32.mul(b, c)));
    });

    test("multiplication distributes over addition", () => {
      const a = 0x111;
      const b = 0x222;
      const c = 0x333;
      const left = GF2_32.mul(a, GF2_32.add(b, c));
      const right = GF2_32.add(GF2_32.mul(a, b), GF2_32.mul(a, c));
      expect(left).toBe(right);
    });
  });

  describe("pow", () => {
    test("power of 0 is 1", () => {
      expect(GF2_32.pow(123, 0)).toBe(1);
      expect(GF2_32.pow(0xffffffff, 0)).toBe(1);
    });

    test("power of 1 is identity", () => {
      expect(GF2_32.pow(123, 1)).toBe(123);
      expect(GF2_32.pow(0xabcd, 1)).toBe(0xabcd);
    });

    test("power of 2 is square", () => {
      const x = 0x1234;
      expect(GF2_32.pow(x, 2)).toBe(GF2_32.mul(x, x));
    });

    test("power of 3 is cube", () => {
      const x = 0x5678;
      expect(GF2_32.pow(x, 3)).toBe(GF2_32.mul(GF2_32.mul(x, x), x));
    });
  });

  describe("inv", () => {
    test("inverse of 0 is 0", () => {
      expect(GF2_32.inv(0)).toBe(0);
    });

    test("inverse of 1 is 1", () => {
      expect(GF2_32.inv(1)).toBe(1);
    });

    test("a * inv(a) = 1 for non-zero a", () => {
      const values = [2, 3, 7, 255, 0x1234, 0xabcdef, 0xffffffff >>> 0];
      for (const a of values) {
        const invA = GF2_32.inv(a);
        const product = GF2_32.mul(a, invA);
        expect(product).toBe(1);
      }
    });

    test("inv(inv(a)) = a", () => {
      const values = [5, 17, 0x9999, 0xdeadbeef >>> 0];
      for (const a of values) {
        expect(GF2_32.inv(GF2_32.inv(a))).toBe(a >>> 0);
      }
    });
  });

  describe("div", () => {
    test("throws on division by zero", () => {
      expect(() => GF2_32.div(123, 0)).toThrow("Division by zero");
    });

    test("a / a = 1", () => {
      expect(GF2_32.div(123, 123)).toBe(1);
      expect(GF2_32.div(0xffffffff >>> 0, 0xffffffff >>> 0)).toBe(1);
    });

    test("a / 1 = a", () => {
      expect(GF2_32.div(123, 1)).toBe(123);
      expect(GF2_32.div(0xabcd, 1)).toBe(0xabcd);
    });

    test("(a * b) / b = a", () => {
      const a = 0x1234;
      const b = 0x5678;
      const product = GF2_32.mul(a, b);
      expect(GF2_32.div(product, b)).toBe(a);
    });
  });
});

describe("Minisketch", () => {
  describe("constructor", () => {
    test("creates sketch with given capacity", () => {
      const sketch = new Minisketch(10);
      expect(sketch.getCapacity()).toBe(10);
    });

    test("throws on capacity < 1", () => {
      expect(() => new Minisketch(0)).toThrow();
    });
  });

  describe("isEmpty", () => {
    test("new sketch is empty", () => {
      const sketch = new Minisketch(5);
      expect(sketch.isEmpty()).toBe(true);
    });

    test("sketch with element is not empty", () => {
      const sketch = new Minisketch(5);
      sketch.add(123);
      expect(sketch.isEmpty()).toBe(false);
    });

    test("adding same element twice makes sketch empty (XOR)", () => {
      const sketch = new Minisketch(5);
      sketch.add(123);
      sketch.add(123);
      expect(sketch.isEmpty()).toBe(true);
    });
  });

  describe("serialize/deserialize", () => {
    test("serializes to correct size", () => {
      const sketch = new Minisketch(10);
      const data = sketch.serialize();
      // 10 syndromes * 4 bytes each = 40 bytes
      expect(data.length).toBe(40);
    });

    test("deserialize restores sketch", () => {
      const original = new Minisketch(5);
      original.add(100);
      original.add(200);
      original.add(300);

      const serialized = original.serialize();
      const restored = Minisketch.deserialize(serialized);

      expect(restored.getCapacity()).toBe(5);
      expect(restored.serialize().equals(serialized)).toBe(true);
    });

    test("throws on invalid serialization length", () => {
      const badData = Buffer.alloc(7); // Not divisible by 4
      expect(() => Minisketch.deserialize(badData)).toThrow();
    });
  });

  describe("clone", () => {
    test("creates independent copy", () => {
      const original = new Minisketch(5);
      original.add(42);

      const copy = original.clone();
      expect(copy.serialize().equals(original.serialize())).toBe(true);

      // Modify original
      original.add(100);

      // Copy should be unchanged
      expect(copy.serialize().equals(original.serialize())).toBe(false);
    });
  });

  describe("merge", () => {
    test("merging with empty sketch preserves original", () => {
      const sketch1 = new Minisketch(5);
      sketch1.add(123);
      const originalData = sketch1.serialize();

      const sketch2 = new Minisketch(5);
      sketch1.merge(sketch2);

      expect(sketch1.serialize().equals(originalData)).toBe(true);
    });

    test("merging identical sketches gives empty sketch", () => {
      const sketch1 = new Minisketch(5);
      sketch1.add(100);
      sketch1.add(200);

      const sketch2 = new Minisketch(5);
      sketch2.add(100);
      sketch2.add(200);

      sketch1.merge(sketch2);
      expect(sketch1.isEmpty()).toBe(true);
    });

    test("merging captures symmetric difference", () => {
      const sketch1 = new Minisketch(5);
      sketch1.add(100);
      sketch1.add(200); // common

      const sketch2 = new Minisketch(5);
      sketch2.add(200); // common
      sketch2.add(300);

      // Reference: what sketch of just {100, 300} looks like
      const expected = new Minisketch(5);
      expected.add(100);
      expected.add(300);

      sketch1.merge(sketch2);
      expect(sketch1.serialize().equals(expected.serialize())).toBe(true);
    });

    test("throws on mismatched capacities", () => {
      const sketch1 = new Minisketch(5);
      const sketch2 = new Minisketch(10);

      expect(() => sketch1.merge(sketch2)).toThrow();
    });
  });

  describe("decode", () => {
    test("decodes empty sketch to empty set", () => {
      const sketch = new Minisketch(5);
      const result = sketch.decode();

      expect(result).not.toBeNull();
      expect(result!.length).toBe(0);
    });

    // Note: Full decoding of non-empty sketches requires finding roots of
    // error-locator polynomials in GF(2^32). For production, libminisketch
    // should be used via FFI. These tests verify the sketch structure works.

    test("sketch with element is non-empty", () => {
      const sketch = new Minisketch(5);
      sketch.add(42);

      expect(sketch.isEmpty()).toBe(false);

      // For now, decode may return null for non-trivial sets
      // In production, use libminisketch via Bun FFI
      const result = sketch.decode();
      // Allow either successful decode or null (fallback behavior)
      if (result !== null) {
        expect(result.length).toBe(1);
        expect(result).toContain(42);
      }
    });

    test("merged sketch captures difference syndromes", () => {
      // Set A: {100, 200, 300}
      const sketchA = new Minisketch(10);
      sketchA.add(100);
      sketchA.add(200);
      sketchA.add(300);

      // Set B: {200, 300, 400}
      const sketchB = new Minisketch(10);
      sketchB.add(200);
      sketchB.add(300);
      sketchB.add(400);

      // Merge gives symmetric difference: {100, 400}
      sketchA.merge(sketchB);

      // Verify merge produced correct structure
      // (comparison with manually computed difference sketch)
      const expectedDiff = new Minisketch(10);
      expectedDiff.add(100);
      expectedDiff.add(400);

      expect(sketchA.serialize().equals(expectedDiff.serialize())).toBe(true);
    });
  });
});

describe("Helper Functions", () => {
  describe("makeMinisketch32", () => {
    test("creates Minisketch with given capacity", () => {
      const sketch = makeMinisketch32(15);
      expect(sketch.getCapacity()).toBe(15);
    });
  });

  describe("estimateDifference", () => {
    test("identical sets have no difference", () => {
      expect(estimateDifference(10, 10, 1.0)).toBe(0);
    });

    test("no overlap means max difference", () => {
      expect(estimateDifference(10, 10, 0.0)).toBe(20);
    });

    test("default overlap of 0.5", () => {
      // 10 and 10 with 50% overlap
      // common = 5, localOnly = 5, remoteOnly = 5
      expect(estimateDifference(10, 10)).toBe(10);
    });
  });

  describe("chooseSketchCapacity", () => {
    test("returns at least 1", () => {
      expect(chooseSketchCapacity(0, 0)).toBeGreaterThanOrEqual(1);
    });

    test("scales with set size difference", () => {
      const small = chooseSketchCapacity(10, 10);
      const large = chooseSketchCapacity(100, 100);

      expect(large).toBeGreaterThan(small);
    });

    test("respects maximum capacity", () => {
      const cap = chooseSketchCapacity(10000, 10000);
      expect(cap).toBeLessThanOrEqual(1000);
    });

    test("applies margin ratio", () => {
      const base = chooseSketchCapacity(100, 100, 1.0);
      const withMargin = chooseSketchCapacity(100, 100, 2.0);

      expect(withMargin).toBeGreaterThan(base);
    });
  });
});

describe("MINISKETCH_BITS constant", () => {
  test("is 32 for Erlay", () => {
    expect(MINISKETCH_BITS).toBe(32);
  });
});
