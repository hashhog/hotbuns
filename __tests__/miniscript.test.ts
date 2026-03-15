/**
 * Tests for Miniscript: parsing, type checking, compilation, and satisfaction.
 *
 * Tests cover:
 * - Parsing miniscript expressions
 * - Type system validation
 * - Script compilation
 * - Witness satisfaction generation
 * - Analysis functions
 */

import { describe, expect, test } from "bun:test";
import {
  parseMiniscript,
  compileScript,
  computeType,
  computeSatisfaction,
  generateWitness,
  analyzeMiniscript,
  miniscriptToString,
  isValidTopLevel,
  isSane,
  needsSignature,
  isNonMalleable,
  MiniscriptContext,
  BaseType,
  Availability,
  type MiniscriptNode,
  type SatisfactionContext,
} from "../src/wallet/miniscript.js";
import { parseDescriptor } from "../src/wallet/descriptor.js";
import { Opcode } from "../src/script/interpreter.js";

// =============================================================================
// Test Vectors
// =============================================================================

// Test compressed pubkey (33 bytes)
const TEST_PUBKEY_1 =
  "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const TEST_PUBKEY_2 =
  "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
const TEST_PUBKEY_3 =
  "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9";

// Test x-only pubkey (32 bytes, for Tapscript)
const TEST_XONLY_1 =
  "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

// Test hashes
const TEST_SHA256_HASH =
  "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"; // SHA256("")
const TEST_HASH160 = "751e76e8199196d454941c45d1b3a323f1433bd6"; // HASH160 of TEST_PUBKEY_1
const TEST_RIPEMD160 = "9c1185a5c5e9fc54612808977ee8f548b2258d31"; // RIPEMD160("")

// Test preimage
const TEST_PREIMAGE = "0000000000000000000000000000000000000000000000000000000000000000";

// Test signature (DER encoded, placeholder)
const TEST_SIG = "3044022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f8179802205e3e5b7def0fdcf90e3e9c8e4ba4b1d3e7d8e4f0a1b2c3d4e5f6a7b8c9d0e1f201";

// =============================================================================
// Parsing Tests
// =============================================================================

describe("Miniscript Parsing", () => {
  describe("Basic Fragments", () => {
    test("parses 0 (just_0)", () => {
      const node = parseMiniscript("0");
      expect(node.type).toBe("just_0");
    });

    test("parses 1 (just_1)", () => {
      const node = parseMiniscript("1");
      expect(node.type).toBe("just_1");
    });

    test("parses pk(KEY) as c:pk_k", () => {
      const node = parseMiniscript(`pk(${TEST_PUBKEY_1})`);
      // pk(KEY) is syntactic sugar for c:pk_k(KEY)
      expect(node.type).toBe("wrap_c");
      if (node.type === "wrap_c") {
        expect(node.inner.type).toBe("pk_k");
        if (node.inner.type === "pk_k") {
          expect(node.inner.key.toString("hex")).toBe(TEST_PUBKEY_1);
        }
      }
    });

    test("parses pk_k(KEY)", () => {
      const node = parseMiniscript(`pk_k(${TEST_PUBKEY_1})`);
      expect(node.type).toBe("pk_k");
    });

    test("parses pkh(KEY) as c:pk_h", () => {
      const node = parseMiniscript(`pkh(${TEST_PUBKEY_1})`);
      // pkh(KEY) is syntactic sugar for c:pk_h(KEY)
      expect(node.type).toBe("wrap_c");
    });

    test("parses pk_h(KEY)", () => {
      const node = parseMiniscript(`pk_h(${TEST_PUBKEY_1})`);
      expect(node.type).toBe("pk_h");
    });

    test("parses older(N)", () => {
      const node = parseMiniscript("older(144)");
      expect(node.type).toBe("older");
      if (node.type === "older") {
        expect(node.sequence).toBe(144);
      }
    });

    test("parses after(N)", () => {
      const node = parseMiniscript("after(500000)");
      expect(node.type).toBe("after");
      if (node.type === "after") {
        expect(node.locktime).toBe(500000);
      }
    });

    test("parses sha256(H)", () => {
      const node = parseMiniscript(`sha256(${TEST_SHA256_HASH})`);
      expect(node.type).toBe("sha256");
      if (node.type === "sha256") {
        expect(node.hash.toString("hex")).toBe(TEST_SHA256_HASH);
      }
    });

    test("parses hash256(H)", () => {
      const node = parseMiniscript(`hash256(${TEST_SHA256_HASH})`);
      expect(node.type).toBe("hash256");
    });

    test("parses ripemd160(H)", () => {
      const node = parseMiniscript(`ripemd160(${TEST_RIPEMD160})`);
      expect(node.type).toBe("ripemd160");
    });

    test("parses hash160(H)", () => {
      const node = parseMiniscript(`hash160(${TEST_HASH160})`);
      expect(node.type).toBe("hash160");
    });
  });

  describe("Combiners", () => {
    test("parses and_v(V,B)", () => {
      const node = parseMiniscript(
        `and_v(v:pk(${TEST_PUBKEY_1}),pk(${TEST_PUBKEY_2}))`
      );
      expect(node.type).toBe("and_v");
    });

    test("parses and_b(B,W)", () => {
      const node = parseMiniscript(
        `and_b(pk(${TEST_PUBKEY_1}),s:pk(${TEST_PUBKEY_2}))`
      );
      expect(node.type).toBe("and_b");
    });

    test("parses or_b(Bd,Wd)", () => {
      const node = parseMiniscript(
        `or_b(pk(${TEST_PUBKEY_1}),s:pk(${TEST_PUBKEY_2}))`
      );
      expect(node.type).toBe("or_b");
    });

    test("parses or_c(Bdu,V)", () => {
      const node = parseMiniscript(
        `or_c(pk(${TEST_PUBKEY_1}),v:pk(${TEST_PUBKEY_2}))`
      );
      expect(node.type).toBe("or_c");
    });

    test("parses or_d(Bdu,B)", () => {
      const node = parseMiniscript(
        `or_d(pk(${TEST_PUBKEY_1}),pk(${TEST_PUBKEY_2}))`
      );
      expect(node.type).toBe("or_d");
    });

    test("parses or_i(X,Y)", () => {
      const node = parseMiniscript(
        `or_i(pk(${TEST_PUBKEY_1}),pk(${TEST_PUBKEY_2}))`
      );
      expect(node.type).toBe("or_i");
    });

    test("parses andor(X,Y,Z)", () => {
      const node = parseMiniscript(
        `andor(pk(${TEST_PUBKEY_1}),pk(${TEST_PUBKEY_2}),pk(${TEST_PUBKEY_3}))`
      );
      expect(node.type).toBe("andor");
    });

    test("parses thresh(k,X,...)", () => {
      const node = parseMiniscript(
        `thresh(2,pk(${TEST_PUBKEY_1}),s:pk(${TEST_PUBKEY_2}),s:pk(${TEST_PUBKEY_3}))`
      );
      expect(node.type).toBe("thresh");
      if (node.type === "thresh") {
        expect(node.threshold).toBe(2);
        expect(node.subs.length).toBe(3);
      }
    });
  });

  describe("Multi", () => {
    test("parses multi(k,KEY,...)", () => {
      const node = parseMiniscript(
        `multi(2,${TEST_PUBKEY_1},${TEST_PUBKEY_2},${TEST_PUBKEY_3})`
      );
      expect(node.type).toBe("multi");
      if (node.type === "multi") {
        expect(node.threshold).toBe(2);
        expect(node.keys.length).toBe(3);
      }
    });

    test("parses multi_a(k,KEY,...) in tapscript", () => {
      const node = parseMiniscript(
        `multi_a(2,${TEST_XONLY_1},${TEST_XONLY_1})`,
        MiniscriptContext.TAPSCRIPT
      );
      expect(node.type).toBe("multi_a");
      if (node.type === "multi_a") {
        expect(node.threshold).toBe(2);
        expect(node.keys.length).toBe(2);
      }
    });
  });

  describe("Wrappers", () => {
    test("parses a:X (wrap_a)", () => {
      const node = parseMiniscript(`a:pk(${TEST_PUBKEY_1})`);
      expect(node.type).toBe("wrap_a");
    });

    test("parses s:X (wrap_s)", () => {
      const node = parseMiniscript(`s:pk(${TEST_PUBKEY_1})`);
      expect(node.type).toBe("wrap_s");
    });

    test("parses c:X (wrap_c)", () => {
      const node = parseMiniscript(`c:pk_k(${TEST_PUBKEY_1})`);
      expect(node.type).toBe("wrap_c");
    });

    test("parses d:X (wrap_d)", () => {
      const node = parseMiniscript(`d:v:pk(${TEST_PUBKEY_1})`);
      expect(node.type).toBe("wrap_d");
    });

    test("parses v:X (wrap_v)", () => {
      const node = parseMiniscript(`v:pk(${TEST_PUBKEY_1})`);
      expect(node.type).toBe("wrap_v");
    });

    test("parses j:X (wrap_j)", () => {
      const node = parseMiniscript(`j:pk(${TEST_PUBKEY_1})`);
      expect(node.type).toBe("wrap_j");
    });

    test("parses n:X (wrap_n)", () => {
      const node = parseMiniscript(`n:pk(${TEST_PUBKEY_1})`);
      expect(node.type).toBe("wrap_n");
    });

    test("parses t:X (and_v with just_1)", () => {
      const node = parseMiniscript(`t:pk(${TEST_PUBKEY_1})`);
      // t:X = and_v(v:X, 1)
      expect(node.type).toBe("and_v");
    });

    test("parses l:X (or_i with 0)", () => {
      const node = parseMiniscript(`l:pk(${TEST_PUBKEY_1})`);
      // l:X = or_i(0, X)
      expect(node.type).toBe("or_i");
      if (node.type === "or_i") {
        expect(node.left.type).toBe("just_0");
      }
    });

    test("parses u:X (or_i with 0)", () => {
      const node = parseMiniscript(`u:pk(${TEST_PUBKEY_1})`);
      // u:X = or_i(X, 0)
      expect(node.type).toBe("or_i");
      if (node.type === "or_i") {
        expect(node.right.type).toBe("just_0");
      }
    });
  });

  describe("Complex Expressions", () => {
    test("parses nested wrappers", () => {
      const node = parseMiniscript(`a:s:pk(${TEST_PUBKEY_1})`);
      expect(node.type).toBe("wrap_a");
      if (node.type === "wrap_a") {
        expect(node.inner.type).toBe("wrap_s");
      }
    });

    test("parses 2-of-3 multisig policy", () => {
      const policy = `thresh(2,pk(${TEST_PUBKEY_1}),s:pk(${TEST_PUBKEY_2}),s:pk(${TEST_PUBKEY_3}))`;
      const node = parseMiniscript(policy);
      expect(node.type).toBe("thresh");
    });

    test("parses escrow with timelock", () => {
      // Alice and Bob, or Alice after 100 blocks
      const policy = `or_d(and_v(v:pk(${TEST_PUBKEY_1}),pk(${TEST_PUBKEY_2})),and_v(v:pk(${TEST_PUBKEY_1}),older(100)))`;
      const node = parseMiniscript(policy);
      expect(node.type).toBe("or_d");
    });
  });

  describe("Error Cases", () => {
    test("throws on invalid fragment", () => {
      expect(() => parseMiniscript("invalid()")).toThrow();
    });

    test("throws on unclosed parenthesis", () => {
      expect(() => parseMiniscript(`pk(${TEST_PUBKEY_1}`)).toThrow();
    });

    test("throws on invalid key length", () => {
      expect(() => parseMiniscript("pk(abcd)")).toThrow();
    });

    test("throws on invalid hash length for sha256", () => {
      expect(() => parseMiniscript("sha256(abcd)")).toThrow("32 bytes");
    });

    test("throws on invalid threshold", () => {
      expect(() => parseMiniscript(`multi(5,${TEST_PUBKEY_1},${TEST_PUBKEY_2})`)).toThrow();
    });
  });
});

// =============================================================================
// Type System Tests
// =============================================================================

describe("Miniscript Type System", () => {
  describe("Base Types", () => {
    test("pk_k has type K", () => {
      // Use pk_k directly for type K
      const node = parseMiniscript(`pk_k(${TEST_PUBKEY_1})`);
      const type = computeType(node);
      expect(type.base).toBe(BaseType.K);
    });

    test("pk (c:pk_k) has type B", () => {
      // pk(KEY) = c:pk_k(KEY) has type B
      const node = parseMiniscript(`pk(${TEST_PUBKEY_1})`);
      const type = computeType(node);
      expect(type.base).toBe(BaseType.B);
    });

    test("0 has type B", () => {
      const node = parseMiniscript("0");
      const type = computeType(node);
      expect(type.base).toBe(BaseType.B);
    });

    test("1 has type B", () => {
      const node = parseMiniscript("1");
      const type = computeType(node);
      expect(type.base).toBe(BaseType.B);
    });

    test("v:pk has type V", () => {
      // v:pk = v:c:pk_k
      const node = parseMiniscript(`v:pk(${TEST_PUBKEY_1})`);
      const type = computeType(node);
      expect(type.base).toBe(BaseType.V);
    });

    test("a:pk has type W", () => {
      // a:pk = a:c:pk_k
      const node = parseMiniscript(`a:pk(${TEST_PUBKEY_1})`);
      const type = computeType(node);
      expect(type.base).toBe(BaseType.W);
    });
  });

  describe("Type Properties", () => {
    test("pk_k has property s (requires signature)", () => {
      const node = parseMiniscript(`pk(${TEST_PUBKEY_1})`);
      const type = computeType(node);
      expect(type.props.s).toBe(true);
    });

    test("older has property f (forced)", () => {
      const node = parseMiniscript("older(100)");
      const type = computeType(node);
      expect(type.props.f).toBe(true);
    });

    test("older has property z (zero-arg)", () => {
      const node = parseMiniscript("older(100)");
      const type = computeType(node);
      expect(type.props.z).toBe(true);
    });

    test("multi has properties s and m", () => {
      const node = parseMiniscript(
        `multi(2,${TEST_PUBKEY_1},${TEST_PUBKEY_2})`
      );
      const type = computeType(node);
      expect(type.props.s).toBe(true);
      expect(type.props.m).toBe(true);
    });
  });

  describe("Timelock Properties", () => {
    test("older with height has property h", () => {
      const node = parseMiniscript("older(100)");
      const type = computeType(node);
      expect(type.props.h).toBe(true);
      expect(type.props.g).toBe(false);
    });

    test("older with time flag has property g", () => {
      // SEQUENCE_LOCKTIME_TYPE_FLAG = 1 << 22 = 0x400000
      const node = parseMiniscript("older(4194404)"); // 0x400000 | 100
      const type = computeType(node);
      expect(type.props.g).toBe(true);
      expect(type.props.h).toBe(false);
    });

    test("after with height has property j", () => {
      const node = parseMiniscript("after(100)");
      const type = computeType(node);
      expect(type.props.j).toBe(true);
      expect(type.props.i).toBe(false);
    });

    test("after with time has property i", () => {
      const node = parseMiniscript("after(1700000000)"); // Unix timestamp
      const type = computeType(node);
      expect(type.props.i).toBe(true);
      expect(type.props.j).toBe(false);
    });
  });

  describe("Type Validation", () => {
    test("isValidTopLevel for pk", () => {
      const node = parseMiniscript(`pk(${TEST_PUBKEY_1})`);
      expect(isValidTopLevel(node)).toBe(true);
    });

    test("isValidTopLevel for v:pk is false (type V)", () => {
      const node = parseMiniscript(`v:pk(${TEST_PUBKEY_1})`);
      expect(isValidTopLevel(node)).toBe(false);
    });

    test("needsSignature for pk", () => {
      const node = parseMiniscript(`pk(${TEST_PUBKEY_1})`);
      expect(needsSignature(node)).toBe(true);
    });

    test("needsSignature for sha256 is false", () => {
      const node = parseMiniscript(`sha256(${TEST_SHA256_HASH})`);
      expect(needsSignature(node)).toBe(false);
    });

    test("isNonMalleable for pk", () => {
      const node = parseMiniscript(`pk(${TEST_PUBKEY_1})`);
      expect(isNonMalleable(node)).toBe(true);
    });
  });
});

// =============================================================================
// Script Compilation Tests
// =============================================================================

describe("Miniscript Script Compilation", () => {
  test("compiles 0 to OP_0", () => {
    const node = parseMiniscript("0");
    const script = compileScript(node);
    expect(script).toEqual(Buffer.from([Opcode.OP_0]));
  });

  test("compiles 1 to OP_1", () => {
    const node = parseMiniscript("1");
    const script = compileScript(node);
    expect(script).toEqual(Buffer.from([Opcode.OP_1]));
  });

  test("compiles pk_k to <key>", () => {
    const node = parseMiniscript(`pk(${TEST_PUBKEY_1})`);
    const script = compileScript(node);
    // <push 33 bytes> <key>
    expect(script[0]).toBe(33);
    expect(script.subarray(1, 34).toString("hex")).toBe(TEST_PUBKEY_1);
  });

  test("compiles older to <n> OP_CHECKSEQUENCEVERIFY", () => {
    const node = parseMiniscript("older(144)");
    const script = compileScript(node);
    // <push 2 bytes> <144 little-endian> OP_CHECKSEQUENCEVERIFY
    expect(script[script.length - 1]).toBe(Opcode.OP_CHECKSEQUENCEVERIFY);
  });

  test("compiles after to <n> OP_CHECKLOCKTIMEVERIFY", () => {
    const node = parseMiniscript("after(500000)");
    const script = compileScript(node);
    expect(script[script.length - 1]).toBe(Opcode.OP_CHECKLOCKTIMEVERIFY);
  });

  test("compiles multi to CHECKMULTISIG", () => {
    const node = parseMiniscript(
      `multi(2,${TEST_PUBKEY_1},${TEST_PUBKEY_2},${TEST_PUBKEY_3})`
    );
    const script = compileScript(node);
    expect(script[script.length - 1]).toBe(Opcode.OP_CHECKMULTISIG);
  });

  test("compiles multi_a to CHECKSIGADD chain", () => {
    const node = parseMiniscript(
      `multi_a(2,${TEST_XONLY_1},${TEST_XONLY_1})`,
      MiniscriptContext.TAPSCRIPT
    );
    const script = compileScript(node, MiniscriptContext.TAPSCRIPT);
    // Should contain CHECKSIG and CHECKSIGADD
    expect(script.includes(Opcode.OP_CHECKSIG)).toBe(true);
    expect(script.includes(Opcode.OP_CHECKSIGADD)).toBe(true);
    expect(script.includes(Opcode.OP_NUMEQUAL)).toBe(true);
  });

  test("compiles and_v concatenates scripts", () => {
    const node = parseMiniscript(
      `and_v(v:pk(${TEST_PUBKEY_1}),pk(${TEST_PUBKEY_2}))`
    );
    const script = compileScript(node);
    // Should have VERIFY in it (from v:)
    expect(script.includes(Opcode.OP_VERIFY)).toBe(true);
  });

  test("compiles or_i to IF/ELSE/ENDIF", () => {
    const node = parseMiniscript(
      `or_i(pk(${TEST_PUBKEY_1}),pk(${TEST_PUBKEY_2}))`
    );
    const script = compileScript(node);
    expect(script.includes(Opcode.OP_IF)).toBe(true);
    expect(script.includes(Opcode.OP_ELSE)).toBe(true);
    expect(script.includes(Opcode.OP_ENDIF)).toBe(true);
  });

  test("compiles sha256 hash check", () => {
    const node = parseMiniscript(`sha256(${TEST_SHA256_HASH})`);
    const script = compileScript(node);
    expect(script.includes(Opcode.OP_SIZE)).toBe(true);
    expect(script.includes(Opcode.OP_SHA256)).toBe(true);
    expect(script.includes(Opcode.OP_EQUAL)).toBe(true);
  });
});

// =============================================================================
// Satisfaction Tests
// =============================================================================

describe("Miniscript Satisfaction", () => {
  const createContext = (
    sigs: Map<string, Buffer> = new Map(),
    preimages: Map<string, Buffer> = new Map(),
    options: Partial<SatisfactionContext> = {}
  ): SatisfactionContext => ({
    signatures: sigs,
    preimages,
    ...options,
  });

  describe("Basic Satisfaction", () => {
    test("pk_k satisfied with signature", () => {
      const node = parseMiniscript(`pk(${TEST_PUBKEY_1})`);
      const sig = Buffer.from(TEST_SIG, "hex");
      const ctx = createContext(new Map([[TEST_PUBKEY_1, sig]]));

      const result = computeSatisfaction(node, ctx);
      expect(result.sat.available).toBe(Availability.YES);
      expect(result.sat.stack.length).toBe(1);
      expect(result.sat.stack[0].hasSig).toBe(true);
    });

    test("pk_k dissatisfied with empty sig", () => {
      const node = parseMiniscript(`pk(${TEST_PUBKEY_1})`);
      const ctx = createContext();

      const result = computeSatisfaction(node, ctx);
      expect(result.sat.available).toBe(Availability.NO);
      expect(result.nsat.available).toBe(Availability.YES);
      expect(result.nsat.stack[0].data.length).toBe(0);
    });

    test("sha256 satisfied with preimage", () => {
      const node = parseMiniscript(`sha256(${TEST_SHA256_HASH})`);
      const preimage = Buffer.from(TEST_PREIMAGE, "hex");
      const ctx = createContext(new Map(), new Map([[TEST_SHA256_HASH, preimage]]));

      const result = computeSatisfaction(node, ctx);
      expect(result.sat.available).toBe(Availability.YES);
    });

    test("sha256 dissatisfied with zero padding", () => {
      const node = parseMiniscript(`sha256(${TEST_SHA256_HASH})`);
      const ctx = createContext();

      const result = computeSatisfaction(node, ctx);
      expect(result.sat.available).toBe(Availability.NO);
      expect(result.nsat.available).toBe(Availability.YES);
      expect(result.nsat.stack[0].data.length).toBe(32);
    });

    test("older satisfied when sequence matches", () => {
      const node = parseMiniscript("older(100)");
      const ctx = createContext(new Map(), new Map(), { sequence: 150 });

      const result = computeSatisfaction(node, ctx);
      expect(result.sat.available).toBe(Availability.YES);
      expect(result.sat.stack.length).toBe(0);
    });

    test("older not satisfied when sequence too low", () => {
      const node = parseMiniscript("older(100)");
      const ctx = createContext(new Map(), new Map(), { sequence: 50 });

      const result = computeSatisfaction(node, ctx);
      expect(result.sat.available).toBe(Availability.NO);
    });
  });

  describe("Combiner Satisfaction", () => {
    test("and_v satisfied when both satisfied", () => {
      const node = parseMiniscript(
        `and_v(v:pk(${TEST_PUBKEY_1}),pk(${TEST_PUBKEY_2}))`
      );
      const sig1 = Buffer.from(TEST_SIG, "hex");
      const sig2 = Buffer.from(TEST_SIG, "hex");
      const ctx = createContext(
        new Map([
          [TEST_PUBKEY_1, sig1],
          [TEST_PUBKEY_2, sig2],
        ])
      );

      const result = computeSatisfaction(node, ctx);
      expect(result.sat.available).toBe(Availability.YES);
    });

    test("or_d satisfied with first branch", () => {
      const node = parseMiniscript(
        `or_d(pk(${TEST_PUBKEY_1}),pk(${TEST_PUBKEY_2}))`
      );
      const sig1 = Buffer.from(TEST_SIG, "hex");
      const ctx = createContext(new Map([[TEST_PUBKEY_1, sig1]]));

      const result = computeSatisfaction(node, ctx);
      expect(result.sat.available).toBe(Availability.YES);
    });

    test("or_d satisfied with second branch", () => {
      const node = parseMiniscript(
        `or_d(pk(${TEST_PUBKEY_1}),pk(${TEST_PUBKEY_2}))`
      );
      const sig2 = Buffer.from(TEST_SIG, "hex");
      const ctx = createContext(new Map([[TEST_PUBKEY_2, sig2]]));

      const result = computeSatisfaction(node, ctx);
      expect(result.sat.available).toBe(Availability.YES);
    });

    test("or_i chooses smaller satisfaction", () => {
      const node = parseMiniscript(
        `or_i(pk(${TEST_PUBKEY_1}),pk(${TEST_PUBKEY_2}))`
      );
      const sig1 = Buffer.from(TEST_SIG, "hex");
      const sig2 = Buffer.from(TEST_SIG, "hex");
      const ctx = createContext(
        new Map([
          [TEST_PUBKEY_1, sig1],
          [TEST_PUBKEY_2, sig2],
        ])
      );

      const result = computeSatisfaction(node, ctx);
      expect(result.sat.available).toBe(Availability.YES);
    });
  });

  describe("Multi Satisfaction", () => {
    test("multi 2-of-3 satisfied with 2 signatures", () => {
      const node = parseMiniscript(
        `multi(2,${TEST_PUBKEY_1},${TEST_PUBKEY_2},${TEST_PUBKEY_3})`
      );
      const sig1 = Buffer.from(TEST_SIG, "hex");
      const sig2 = Buffer.from(TEST_SIG, "hex");
      const ctx = createContext(
        new Map([
          [TEST_PUBKEY_1, sig1],
          [TEST_PUBKEY_2, sig2],
        ])
      );

      const result = computeSatisfaction(node, ctx);
      expect(result.sat.available).toBe(Availability.YES);
      // Should have dummy + 2 sigs
      expect(result.sat.stack.length).toBe(3);
      expect(result.sat.stack[0].data.length).toBe(0); // CHECKMULTISIG dummy
    });

    test("multi 2-of-3 not satisfied with 1 signature", () => {
      const node = parseMiniscript(
        `multi(2,${TEST_PUBKEY_1},${TEST_PUBKEY_2},${TEST_PUBKEY_3})`
      );
      const sig1 = Buffer.from(TEST_SIG, "hex");
      const ctx = createContext(new Map([[TEST_PUBKEY_1, sig1]]));

      const result = computeSatisfaction(node, ctx);
      expect(result.sat.available).toBe(Availability.NO);
    });
  });

  describe("Witness Generation", () => {
    test("generateWitness returns witness for pk", () => {
      const node = parseMiniscript(`pk(${TEST_PUBKEY_1})`);
      const sig = Buffer.from(TEST_SIG, "hex");
      const ctx = createContext(new Map([[TEST_PUBKEY_1, sig]]));

      const witness = generateWitness(node, ctx);
      expect(witness).not.toBeNull();
      expect(witness!.length).toBe(1);
      expect(witness![0]).toEqual(sig);
    });

    test("generateWitness returns null when unsatisfiable", () => {
      const node = parseMiniscript(`pk(${TEST_PUBKEY_1})`);
      const ctx = createContext();

      const witness = generateWitness(node, ctx);
      expect(witness).toBeNull();
    });
  });
});

// =============================================================================
// Analysis Tests
// =============================================================================

describe("Miniscript Analysis", () => {
  test("analyzes simple pk", () => {
    const node = parseMiniscript(`pk(${TEST_PUBKEY_1})`);
    const analysis = analyzeMiniscript(node);

    expect(analysis.requiredKeys.length).toBe(1);
    expect(analysis.requiredKeys[0].toString("hex")).toBe(TEST_PUBKEY_1);
    expect(analysis.isSane).toBe(true);
    expect(analysis.issues.length).toBe(0);
  });

  test("detects required hashes", () => {
    const node = parseMiniscript(`sha256(${TEST_SHA256_HASH})`);
    const analysis = analyzeMiniscript(node);

    expect(analysis.requiredHashes.length).toBe(1);
    expect(analysis.requiredHashes[0].toString("hex")).toBe(TEST_SHA256_HASH);
  });

  test("detects timelocks", () => {
    const node = parseMiniscript("older(100)");
    const analysis = analyzeMiniscript(node);

    expect(analysis.timelocks.relativeHeight.length).toBe(1);
    expect(analysis.timelocks.relativeHeight[0]).toBe(100);
  });

  test("detects timelock conflicts", () => {
    // Mix height and time timelocks
    const node = parseMiniscript(
      `and_v(v:older(100),after(1700000000))`
    );
    const analysis = analyzeMiniscript(node);

    expect(analysis.timelocks.hasConflict).toBe(true);
    expect(analysis.issues.some((i) => i.includes("conflict"))).toBe(true);
  });

  test("computes script size", () => {
    const node = parseMiniscript(`pk(${TEST_PUBKEY_1})`);
    const analysis = analyzeMiniscript(node);

    expect(analysis.scriptSize).toBeGreaterThan(0);
    // pk(KEY) = c:pk_k(KEY) = <key> OP_CHECKSIG = 34 bytes + 1 opcode = 35 bytes
    expect(analysis.scriptSize).toBe(35);
  });

  test("estimates max witness size", () => {
    const node = parseMiniscript(
      `multi(2,${TEST_PUBKEY_1},${TEST_PUBKEY_2})`
    );
    const analysis = analyzeMiniscript(node);

    // 1 dummy + 2 signatures (max ~73 bytes each)
    expect(analysis.maxWitnessSize).toBeGreaterThan(100);
  });

  test("isSane returns false for scripts without signature", () => {
    const node = parseMiniscript(`sha256(${TEST_SHA256_HASH})`);
    expect(isSane(node)).toBe(false);
  });

  test("isSane returns true for good scripts", () => {
    const node = parseMiniscript(`pk(${TEST_PUBKEY_1})`);
    expect(isSane(node)).toBe(true);
  });
});

// =============================================================================
// String Representation Tests
// =============================================================================

describe("Miniscript String Representation", () => {
  test("round-trips pk_k", () => {
    // pk_k round-trips exactly (pk is sugar for c:pk_k)
    const original = `pk_k(${TEST_PUBKEY_1})`;
    const node = parseMiniscript(original);
    const str = miniscriptToString(node);
    expect(str).toBe(original);
  });

  test("pk round-trips", () => {
    // pk(KEY) is parsed as c:pk_k(KEY) but stringified back to pk(KEY)
    const input = `pk(${TEST_PUBKEY_1})`;
    const node = parseMiniscript(input);
    const str = miniscriptToString(node);
    expect(str).toBe(input);
  });

  test("round-trips multi", () => {
    const original = `multi(2,${TEST_PUBKEY_1},${TEST_PUBKEY_2})`;
    const node = parseMiniscript(original);
    const str = miniscriptToString(node);
    expect(str).toBe(original);
  });

  test("round-trips wrappers", () => {
    const original = `a:pk(${TEST_PUBKEY_1})`;
    const node = parseMiniscript(original);
    const str = miniscriptToString(node);
    expect(str).toBe(original);
  });

  test("round-trips combiners", () => {
    const original = `or_d(pk(${TEST_PUBKEY_1}),pk(${TEST_PUBKEY_2}))`;
    const node = parseMiniscript(original);
    const str = miniscriptToString(node);
    expect(str).toBe(original);
  });
});

// =============================================================================
// Descriptor Integration Tests
// =============================================================================

describe("Miniscript Descriptor Integration", () => {
  test("parses wsh(miniscript)", () => {
    const desc = `wsh(pk(${TEST_PUBKEY_1}))`;
    const parsed = parseDescriptor(desc);
    expect(parsed.descriptor.getType()).toBe("wsh");
  });

  test("parses wsh(multi(...))", () => {
    const desc = `wsh(multi(2,${TEST_PUBKEY_1},${TEST_PUBKEY_2}))`;
    const parsed = parseDescriptor(desc);
    expect(parsed.descriptor.getType()).toBe("wsh");
  });

  test("expands wsh(miniscript) to script", () => {
    const desc = `wsh(pk(${TEST_PUBKEY_1}))`;
    const parsed = parseDescriptor(desc);
    const outputs = parsed.descriptor.expand(0, "mainnet");

    expect(outputs.length).toBe(1);
    expect(outputs[0].scriptPubKey.length).toBe(34); // OP_0 <32 bytes>
    expect(outputs[0].witnessScript).toBeDefined();
  });

  test("parses wsh(or_d(...))", () => {
    const desc = `wsh(or_d(pk(${TEST_PUBKEY_1}),pk(${TEST_PUBKEY_2})))`;
    const parsed = parseDescriptor(desc);
    expect(parsed.descriptor.getType()).toBe("wsh");
  });

  test("parses sh(wsh(miniscript))", () => {
    const desc = `sh(wsh(pk(${TEST_PUBKEY_1})))`;
    const parsed = parseDescriptor(desc);
    expect(parsed.descriptor.getType()).toBe("sh");
  });
});
