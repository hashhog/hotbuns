/**
 * Tests for Bitcoin Script interpreter.
 */

import { describe, expect, test } from "bun:test";
import {
  Opcode,
  parseScript,
  serializeScript,
  executeScript,
  verifyScript,
  isP2PKH,
  isP2SH,
  isP2WPKH,
  isP2WSH,
  isP2TR,
  getScriptType,
  scriptNumEncode,
  scriptNumDecode,
  getConsensusFlags,
  compactSizeLen,
  serializedWitnessStackSize,
  type ScriptFlags,
  type ExecutionContext,
  SigVersion,
} from "./interpreter.js";
import { AddressType } from "../address/encoding.js";
import { hash160, ecdsaSign, privateKeyToPublicKey, hash256 } from "../crypto/primitives.js";

// Helper to create default flags
function defaultFlags(): ScriptFlags {
  return {
    verifyP2SH: true,
    verifyWitness: true,
    verifyTaproot: true,
    verifyStrictEncoding: false,
    verifyDERSignatures: true,
    verifyLowS: false,
    verifyNullDummy: true,
    verifyNullFail: true,
    verifyCheckLockTimeVerify: true,
    verifyCheckSequenceVerify: true,
    verifyWitnessPubkeyType: true,
  };
}

// Dummy sigHasher for tests that don't need real signatures
function dummySigHasher(_subscript: Buffer, _hashType: number): Buffer {
  return Buffer.alloc(32);
}

// Helper to build a simple execution context
function createContext(initialStack: Buffer[] = []): ExecutionContext {
  return {
    stack: [...initialStack],
    altStack: [],
    flags: defaultFlags(),
    sigHasher: dummySigHasher,
  };
}

describe("scriptNumEncode/Decode", () => {
  test("encodes and decodes zero", () => {
    const encoded = scriptNumEncode(0);
    expect(encoded.length).toBe(0);
    expect(scriptNumDecode(encoded)).toBe(0);
  });

  test("encodes and decodes positive numbers", () => {
    expect(scriptNumDecode(scriptNumEncode(1))).toBe(1);
    expect(scriptNumDecode(scriptNumEncode(127))).toBe(127);
    expect(scriptNumDecode(scriptNumEncode(128))).toBe(128);
    expect(scriptNumDecode(scriptNumEncode(255))).toBe(255);
    expect(scriptNumDecode(scriptNumEncode(256))).toBe(256);
    expect(scriptNumDecode(scriptNumEncode(32767))).toBe(32767);
    expect(scriptNumDecode(scriptNumEncode(32768))).toBe(32768);
  });

  test("encodes and decodes negative numbers", () => {
    expect(scriptNumDecode(scriptNumEncode(-1))).toBe(-1);
    expect(scriptNumDecode(scriptNumEncode(-127))).toBe(-127);
    expect(scriptNumDecode(scriptNumEncode(-128))).toBe(-128);
    expect(scriptNumDecode(scriptNumEncode(-255))).toBe(-255);
    expect(scriptNumDecode(scriptNumEncode(-256))).toBe(-256);
  });

  test("handles edge cases", () => {
    // Ensure proper sign bit handling
    const n127 = scriptNumEncode(127);
    expect(n127.length).toBe(1);
    expect(n127[0]).toBe(127);

    const n128 = scriptNumEncode(128);
    expect(n128.length).toBe(2);
    expect(n128[0]).toBe(128);
    expect(n128[1]).toBe(0);

    const nm1 = scriptNumEncode(-1);
    expect(nm1.length).toBe(1);
    expect(nm1[0]).toBe(0x81);
  });
});

describe("parseScript", () => {
  test("parses OP_0", () => {
    const script = parseScript(Buffer.from([0x00]));
    expect(script.length).toBe(1);
    expect(script[0].opcode).toBe(Opcode.OP_0);
    expect(script[0].data?.length).toBe(0);
  });

  test("parses direct push", () => {
    const script = parseScript(Buffer.from([0x03, 0x01, 0x02, 0x03]));
    expect(script.length).toBe(1);
    expect(script[0].opcode).toBe(3);
    expect(script[0].data?.equals(Buffer.from([0x01, 0x02, 0x03]))).toBe(true);
  });

  test("parses OP_PUSHDATA1", () => {
    const data = Buffer.alloc(100, 0xab);
    const raw = Buffer.concat([Buffer.from([Opcode.OP_PUSHDATA1, 100]), data]);
    const script = parseScript(raw);
    expect(script.length).toBe(1);
    expect(script[0].opcode).toBe(Opcode.OP_PUSHDATA1);
    expect(script[0].data?.equals(data)).toBe(true);
  });

  test("parses OP_PUSHDATA2", () => {
    const data = Buffer.alloc(300, 0xcd);
    const raw = Buffer.concat([
      Buffer.from([Opcode.OP_PUSHDATA2, 0x2c, 0x01]), // 300 = 0x012c
      data,
    ]);
    const script = parseScript(raw);
    expect(script.length).toBe(1);
    expect(script[0].opcode).toBe(Opcode.OP_PUSHDATA2);
    expect(script[0].data?.length).toBe(300);
  });

  test("parses regular opcodes", () => {
    const raw = Buffer.from([Opcode.OP_DUP, Opcode.OP_HASH160, Opcode.OP_EQUALVERIFY]);
    const script = parseScript(raw);
    expect(script.length).toBe(3);
    expect(script[0].opcode).toBe(Opcode.OP_DUP);
    expect(script[0].data).toBeUndefined();
    expect(script[1].opcode).toBe(Opcode.OP_HASH160);
    expect(script[2].opcode).toBe(Opcode.OP_EQUALVERIFY);
  });

  test("parses P2PKH scriptPubKey", () => {
    const pubkeyHash = Buffer.alloc(20, 0xaa);
    const raw = Buffer.concat([
      Buffer.from([Opcode.OP_DUP, Opcode.OP_HASH160, 20]),
      pubkeyHash,
      Buffer.from([Opcode.OP_EQUALVERIFY, Opcode.OP_CHECKSIG]),
    ]);
    const script = parseScript(raw);
    expect(script.length).toBe(5);
    expect(script[0].opcode).toBe(Opcode.OP_DUP);
    expect(script[1].opcode).toBe(Opcode.OP_HASH160);
    expect(script[2].data?.equals(pubkeyHash)).toBe(true);
    expect(script[3].opcode).toBe(Opcode.OP_EQUALVERIFY);
    expect(script[4].opcode).toBe(Opcode.OP_CHECKSIG);
  });
});

describe("serializeScript", () => {
  test("serializes empty script", () => {
    const raw = serializeScript([]);
    expect(raw.length).toBe(0);
  });

  test("serializes OP_0", () => {
    const raw = serializeScript([{ opcode: Opcode.OP_0, data: Buffer.alloc(0) }]);
    expect(raw.equals(Buffer.from([0x00]))).toBe(true);
  });

  test("round-trips through parse and serialize", () => {
    const original = Buffer.concat([
      Buffer.from([Opcode.OP_DUP, Opcode.OP_HASH160, 20]),
      Buffer.alloc(20, 0x11),
      Buffer.from([Opcode.OP_EQUALVERIFY, Opcode.OP_CHECKSIG]),
    ]);
    const parsed = parseScript(original);
    const serialized = serializeScript(parsed);
    expect(serialized.equals(original)).toBe(true);
  });
});

describe("executeScript - basic operations", () => {
  test("OP_1 through OP_16 push correct values", () => {
    for (let i = 1; i <= 16; i++) {
      const opcode = Opcode.OP_1 + i - 1;
      const ctx = createContext();
      const script = parseScript(Buffer.from([opcode]));
      expect(executeScript(script, ctx)).toBe(true);
      expect(ctx.stack.length).toBe(1);
      expect(scriptNumDecode(ctx.stack[0])).toBe(i);
    }
  });

  test("OP_1NEGATE pushes -1", () => {
    const ctx = createContext();
    const script = parseScript(Buffer.from([Opcode.OP_1NEGATE]));
    expect(executeScript(script, ctx)).toBe(true);
    expect(ctx.stack.length).toBe(1);
    expect(scriptNumDecode(ctx.stack[0])).toBe(-1);
  });

  test("OP_DUP duplicates top element", () => {
    const ctx = createContext([Buffer.from([0x42])]);
    const script = parseScript(Buffer.from([Opcode.OP_DUP]));
    expect(executeScript(script, ctx)).toBe(true);
    expect(ctx.stack.length).toBe(2);
    expect(ctx.stack[0].equals(ctx.stack[1])).toBe(true);
  });

  test("OP_DROP removes top element", () => {
    const ctx = createContext([Buffer.from([0x01]), Buffer.from([0x02])]);
    const script = parseScript(Buffer.from([Opcode.OP_DROP]));
    expect(executeScript(script, ctx)).toBe(true);
    expect(ctx.stack.length).toBe(1);
    expect(ctx.stack[0].equals(Buffer.from([0x01]))).toBe(true);
  });

  test("OP_SWAP swaps top two elements", () => {
    const ctx = createContext([Buffer.from([0x01]), Buffer.from([0x02])]);
    const script = parseScript(Buffer.from([Opcode.OP_SWAP]));
    expect(executeScript(script, ctx)).toBe(true);
    expect(ctx.stack.length).toBe(2);
    expect(ctx.stack[0].equals(Buffer.from([0x02]))).toBe(true);
    expect(ctx.stack[1].equals(Buffer.from([0x01]))).toBe(true);
  });

  test("OP_ROT rotates top three elements", () => {
    const ctx = createContext([
      Buffer.from([0x01]),
      Buffer.from([0x02]),
      Buffer.from([0x03]),
    ]);
    const script = parseScript(Buffer.from([Opcode.OP_ROT]));
    expect(executeScript(script, ctx)).toBe(true);
    expect(ctx.stack.length).toBe(3);
    // After ROT: bottom becomes top
    expect(ctx.stack[2].equals(Buffer.from([0x01]))).toBe(true);
    expect(ctx.stack[1].equals(Buffer.from([0x03]))).toBe(true);
    expect(ctx.stack[0].equals(Buffer.from([0x02]))).toBe(true);
  });

  test("OP_OVER copies second element to top", () => {
    const ctx = createContext([Buffer.from([0x01]), Buffer.from([0x02])]);
    const script = parseScript(Buffer.from([Opcode.OP_OVER]));
    expect(executeScript(script, ctx)).toBe(true);
    expect(ctx.stack.length).toBe(3);
    expect(ctx.stack[2].equals(Buffer.from([0x01]))).toBe(true);
  });

  test("OP_NIP removes second element", () => {
    const ctx = createContext([Buffer.from([0x01]), Buffer.from([0x02])]);
    const script = parseScript(Buffer.from([Opcode.OP_NIP]));
    expect(executeScript(script, ctx)).toBe(true);
    expect(ctx.stack.length).toBe(1);
    expect(ctx.stack[0].equals(Buffer.from([0x02]))).toBe(true);
  });

  test("OP_TUCK inserts top under second", () => {
    const ctx = createContext([Buffer.from([0x01]), Buffer.from([0x02])]);
    const script = parseScript(Buffer.from([Opcode.OP_TUCK]));
    expect(executeScript(script, ctx)).toBe(true);
    expect(ctx.stack.length).toBe(3);
    expect(ctx.stack[2].equals(Buffer.from([0x02]))).toBe(true);
  });

  test("OP_DEPTH returns stack depth", () => {
    const ctx = createContext([Buffer.from([1]), Buffer.from([2]), Buffer.from([3])]);
    const script = parseScript(Buffer.from([Opcode.OP_DEPTH]));
    expect(executeScript(script, ctx)).toBe(true);
    expect(ctx.stack.length).toBe(4);
    expect(scriptNumDecode(ctx.stack[3])).toBe(3);
  });

  test("OP_SIZE returns element size", () => {
    const ctx = createContext([Buffer.from([1, 2, 3, 4, 5])]);
    const script = parseScript(Buffer.from([Opcode.OP_SIZE]));
    expect(executeScript(script, ctx)).toBe(true);
    expect(ctx.stack.length).toBe(2);
    expect(scriptNumDecode(ctx.stack[1])).toBe(5);
  });
});

describe("executeScript - alt stack", () => {
  test("OP_TOALTSTACK and OP_FROMALTSTACK", () => {
    const ctx = createContext([Buffer.from([0x42])]);
    const script = parseScript(
      Buffer.from([Opcode.OP_TOALTSTACK, Opcode.OP_1, Opcode.OP_FROMALTSTACK])
    );
    expect(executeScript(script, ctx)).toBe(true);
    expect(ctx.stack.length).toBe(2);
    expect(ctx.stack[1].equals(Buffer.from([0x42]))).toBe(true);
    expect(ctx.altStack.length).toBe(0);
  });
});

describe("executeScript - arithmetic", () => {
  test("OP_ADD adds two numbers", () => {
    const ctx = createContext([scriptNumEncode(5), scriptNumEncode(3)]);
    const script = parseScript(Buffer.from([Opcode.OP_ADD]));
    expect(executeScript(script, ctx)).toBe(true);
    expect(scriptNumDecode(ctx.stack[0])).toBe(8);
  });

  test("OP_SUB subtracts two numbers", () => {
    const ctx = createContext([scriptNumEncode(10), scriptNumEncode(3)]);
    const script = parseScript(Buffer.from([Opcode.OP_SUB]));
    expect(executeScript(script, ctx)).toBe(true);
    expect(scriptNumDecode(ctx.stack[0])).toBe(7);
  });

  test("OP_1ADD increments", () => {
    const ctx = createContext([scriptNumEncode(5)]);
    const script = parseScript(Buffer.from([Opcode.OP_1ADD]));
    expect(executeScript(script, ctx)).toBe(true);
    expect(scriptNumDecode(ctx.stack[0])).toBe(6);
  });

  test("OP_1SUB decrements", () => {
    const ctx = createContext([scriptNumEncode(5)]);
    const script = parseScript(Buffer.from([Opcode.OP_1SUB]));
    expect(executeScript(script, ctx)).toBe(true);
    expect(scriptNumDecode(ctx.stack[0])).toBe(4);
  });

  test("OP_NEGATE negates", () => {
    const ctx = createContext([scriptNumEncode(5)]);
    const script = parseScript(Buffer.from([Opcode.OP_NEGATE]));
    expect(executeScript(script, ctx)).toBe(true);
    expect(scriptNumDecode(ctx.stack[0])).toBe(-5);
  });

  test("OP_ABS takes absolute value", () => {
    const ctx = createContext([scriptNumEncode(-5)]);
    const script = parseScript(Buffer.from([Opcode.OP_ABS]));
    expect(executeScript(script, ctx)).toBe(true);
    expect(scriptNumDecode(ctx.stack[0])).toBe(5);
  });

  test("OP_NOT logical not", () => {
    const ctx1 = createContext([scriptNumEncode(0)]);
    expect(executeScript(parseScript(Buffer.from([Opcode.OP_NOT])), ctx1)).toBe(true);
    expect(scriptNumDecode(ctx1.stack[0])).toBe(1);

    const ctx2 = createContext([scriptNumEncode(5)]);
    expect(executeScript(parseScript(Buffer.from([Opcode.OP_NOT])), ctx2)).toBe(true);
    expect(scriptNumDecode(ctx2.stack[0])).toBe(0);
  });

  test("OP_0NOTEQUAL", () => {
    const ctx1 = createContext([scriptNumEncode(0)]);
    expect(executeScript(parseScript(Buffer.from([Opcode.OP_0NOTEQUAL])), ctx1)).toBe(true);
    expect(scriptNumDecode(ctx1.stack[0])).toBe(0);

    const ctx2 = createContext([scriptNumEncode(5)]);
    expect(executeScript(parseScript(Buffer.from([Opcode.OP_0NOTEQUAL])), ctx2)).toBe(true);
    expect(scriptNumDecode(ctx2.stack[0])).toBe(1);
  });

  test("comparison operators", () => {
    // LESSTHAN
    const ctx1 = createContext([scriptNumEncode(3), scriptNumEncode(5)]);
    expect(executeScript(parseScript(Buffer.from([Opcode.OP_LESSTHAN])), ctx1)).toBe(true);
    expect(scriptNumDecode(ctx1.stack[0])).toBe(1);

    // GREATERTHAN
    const ctx2 = createContext([scriptNumEncode(5), scriptNumEncode(3)]);
    expect(executeScript(parseScript(Buffer.from([Opcode.OP_GREATERTHAN])), ctx2)).toBe(true);
    expect(scriptNumDecode(ctx2.stack[0])).toBe(1);

    // NUMEQUAL
    const ctx3 = createContext([scriptNumEncode(5), scriptNumEncode(5)]);
    expect(executeScript(parseScript(Buffer.from([Opcode.OP_NUMEQUAL])), ctx3)).toBe(true);
    expect(scriptNumDecode(ctx3.stack[0])).toBe(1);

    // NUMNOTEQUAL
    const ctx4 = createContext([scriptNumEncode(5), scriptNumEncode(3)]);
    expect(executeScript(parseScript(Buffer.from([Opcode.OP_NUMNOTEQUAL])), ctx4)).toBe(true);
    expect(scriptNumDecode(ctx4.stack[0])).toBe(1);
  });

  test("OP_MIN and OP_MAX", () => {
    const ctx1 = createContext([scriptNumEncode(3), scriptNumEncode(7)]);
    expect(executeScript(parseScript(Buffer.from([Opcode.OP_MIN])), ctx1)).toBe(true);
    expect(scriptNumDecode(ctx1.stack[0])).toBe(3);

    const ctx2 = createContext([scriptNumEncode(3), scriptNumEncode(7)]);
    expect(executeScript(parseScript(Buffer.from([Opcode.OP_MAX])), ctx2)).toBe(true);
    expect(scriptNumDecode(ctx2.stack[0])).toBe(7);
  });

  test("OP_WITHIN", () => {
    // 5 is within [3, 8)
    const ctx1 = createContext([scriptNumEncode(5), scriptNumEncode(3), scriptNumEncode(8)]);
    expect(executeScript(parseScript(Buffer.from([Opcode.OP_WITHIN])), ctx1)).toBe(true);
    expect(scriptNumDecode(ctx1.stack[0])).toBe(1);

    // 8 is NOT within [3, 8)
    const ctx2 = createContext([scriptNumEncode(8), scriptNumEncode(3), scriptNumEncode(8)]);
    expect(executeScript(parseScript(Buffer.from([Opcode.OP_WITHIN])), ctx2)).toBe(true);
    expect(scriptNumDecode(ctx2.stack[0])).toBe(0);
  });

  test("OP_BOOLAND and OP_BOOLOR", () => {
    // BOOLAND true && true
    const ctx1 = createContext([scriptNumEncode(1), scriptNumEncode(1)]);
    expect(executeScript(parseScript(Buffer.from([Opcode.OP_BOOLAND])), ctx1)).toBe(true);
    expect(scriptNumDecode(ctx1.stack[0])).toBe(1);

    // BOOLAND true && false
    const ctx2 = createContext([scriptNumEncode(1), scriptNumEncode(0)]);
    expect(executeScript(parseScript(Buffer.from([Opcode.OP_BOOLAND])), ctx2)).toBe(true);
    expect(scriptNumDecode(ctx2.stack[0])).toBe(0);

    // BOOLOR true || false
    const ctx3 = createContext([scriptNumEncode(1), scriptNumEncode(0)]);
    expect(executeScript(parseScript(Buffer.from([Opcode.OP_BOOLOR])), ctx3)).toBe(true);
    expect(scriptNumDecode(ctx3.stack[0])).toBe(1);

    // BOOLOR false || false
    const ctx4 = createContext([scriptNumEncode(0), scriptNumEncode(0)]);
    expect(executeScript(parseScript(Buffer.from([Opcode.OP_BOOLOR])), ctx4)).toBe(true);
    expect(scriptNumDecode(ctx4.stack[0])).toBe(0);
  });
});

describe("executeScript - equality", () => {
  test("OP_EQUAL with equal values", () => {
    const ctx = createContext([Buffer.from([1, 2, 3]), Buffer.from([1, 2, 3])]);
    const script = parseScript(Buffer.from([Opcode.OP_EQUAL]));
    expect(executeScript(script, ctx)).toBe(true);
    expect(scriptNumDecode(ctx.stack[0])).toBe(1);
  });

  test("OP_EQUAL with unequal values", () => {
    const ctx = createContext([Buffer.from([1, 2, 3]), Buffer.from([1, 2, 4])]);
    const script = parseScript(Buffer.from([Opcode.OP_EQUAL]));
    expect(executeScript(script, ctx)).toBe(true);
    expect(ctx.stack[0].length).toBe(0); // false = empty
  });

  test("OP_EQUALVERIFY succeeds with equal values", () => {
    const ctx = createContext([Buffer.from([1, 2, 3]), Buffer.from([1, 2, 3])]);
    const script = parseScript(Buffer.from([Opcode.OP_EQUALVERIFY]));
    expect(executeScript(script, ctx)).toBe(true);
    expect(ctx.stack.length).toBe(0);
  });

  test("OP_EQUALVERIFY fails with unequal values", () => {
    const ctx = createContext([Buffer.from([1, 2, 3]), Buffer.from([1, 2, 4])]);
    const script = parseScript(Buffer.from([Opcode.OP_EQUALVERIFY]));
    expect(executeScript(script, ctx)).toBe(false);
  });
});

describe("executeScript - crypto", () => {
  test("OP_HASH160", () => {
    const data = Buffer.from("hello");
    const ctx = createContext([data]);
    const script = parseScript(Buffer.from([Opcode.OP_HASH160]));
    expect(executeScript(script, ctx)).toBe(true);
    expect(ctx.stack.length).toBe(1);
    expect(ctx.stack[0].equals(hash160(data))).toBe(true);
  });

  test("OP_HASH256", () => {
    const data = Buffer.from("hello");
    const ctx = createContext([data]);
    const script = parseScript(Buffer.from([Opcode.OP_HASH256]));
    expect(executeScript(script, ctx)).toBe(true);
    expect(ctx.stack.length).toBe(1);
    expect(ctx.stack[0].equals(hash256(data))).toBe(true);
  });

  test("OP_SHA256", () => {
    const data = Buffer.from("hello");
    const ctx = createContext([data]);
    const script = parseScript(Buffer.from([Opcode.OP_SHA256]));
    expect(executeScript(script, ctx)).toBe(true);
    expect(ctx.stack.length).toBe(1);
    expect(ctx.stack[0].length).toBe(32);
  });

  test("OP_RIPEMD160", () => {
    const data = Buffer.from("hello");
    const ctx = createContext([data]);
    const script = parseScript(Buffer.from([Opcode.OP_RIPEMD160]));
    expect(executeScript(script, ctx)).toBe(true);
    expect(ctx.stack.length).toBe(1);
    expect(ctx.stack[0].length).toBe(20);
  });
});

describe("executeScript - control flow", () => {
  test("OP_IF with true condition", () => {
    // OP_1 OP_IF OP_2 OP_ENDIF
    const script = parseScript(
      Buffer.from([Opcode.OP_1, Opcode.OP_IF, Opcode.OP_2, Opcode.OP_ENDIF])
    );
    const ctx = createContext();
    expect(executeScript(script, ctx)).toBe(true);
    expect(ctx.stack.length).toBe(1);
    expect(scriptNumDecode(ctx.stack[0])).toBe(2);
  });

  test("OP_IF with false condition", () => {
    // OP_0 OP_IF OP_2 OP_ENDIF
    const script = parseScript(
      Buffer.from([Opcode.OP_0, Opcode.OP_IF, Opcode.OP_2, Opcode.OP_ENDIF])
    );
    const ctx = createContext();
    expect(executeScript(script, ctx)).toBe(true);
    expect(ctx.stack.length).toBe(0);
  });

  test("OP_IF/OP_ELSE with true condition", () => {
    // OP_1 OP_IF OP_2 OP_ELSE OP_3 OP_ENDIF
    const script = parseScript(
      Buffer.from([
        Opcode.OP_1,
        Opcode.OP_IF,
        Opcode.OP_2,
        Opcode.OP_ELSE,
        Opcode.OP_3,
        Opcode.OP_ENDIF,
      ])
    );
    const ctx = createContext();
    expect(executeScript(script, ctx)).toBe(true);
    expect(ctx.stack.length).toBe(1);
    expect(scriptNumDecode(ctx.stack[0])).toBe(2);
  });

  test("OP_IF/OP_ELSE with false condition", () => {
    // OP_0 OP_IF OP_2 OP_ELSE OP_3 OP_ENDIF
    const script = parseScript(
      Buffer.from([
        Opcode.OP_0,
        Opcode.OP_IF,
        Opcode.OP_2,
        Opcode.OP_ELSE,
        Opcode.OP_3,
        Opcode.OP_ENDIF,
      ])
    );
    const ctx = createContext();
    expect(executeScript(script, ctx)).toBe(true);
    expect(ctx.stack.length).toBe(1);
    expect(scriptNumDecode(ctx.stack[0])).toBe(3);
  });

  test("OP_NOTIF with false condition executes branch", () => {
    // OP_0 OP_NOTIF OP_2 OP_ENDIF
    const script = parseScript(
      Buffer.from([Opcode.OP_0, Opcode.OP_NOTIF, Opcode.OP_2, Opcode.OP_ENDIF])
    );
    const ctx = createContext();
    expect(executeScript(script, ctx)).toBe(true);
    expect(ctx.stack.length).toBe(1);
    expect(scriptNumDecode(ctx.stack[0])).toBe(2);
  });

  test("nested IF/ELSE", () => {
    // OP_1 OP_IF OP_1 OP_IF OP_5 OP_ENDIF OP_ENDIF
    const script = parseScript(
      Buffer.from([
        Opcode.OP_1,
        Opcode.OP_IF,
        Opcode.OP_1,
        Opcode.OP_IF,
        Opcode.OP_5,
        Opcode.OP_ENDIF,
        Opcode.OP_ENDIF,
      ])
    );
    const ctx = createContext();
    expect(executeScript(script, ctx)).toBe(true);
    expect(ctx.stack.length).toBe(1);
    expect(scriptNumDecode(ctx.stack[0])).toBe(5);
  });

  test("OP_RETURN in non-executing branch does not fail", () => {
    // OP_0 OP_IF OP_RETURN OP_ENDIF OP_1
    const script = parseScript(
      Buffer.from([Opcode.OP_0, Opcode.OP_IF, Opcode.OP_RETURN, Opcode.OP_ENDIF, Opcode.OP_1])
    );
    const ctx = createContext();
    expect(executeScript(script, ctx)).toBe(true);
    expect(ctx.stack.length).toBe(1);
    expect(scriptNumDecode(ctx.stack[0])).toBe(1);
  });

  test("OP_RETURN in executing branch fails", () => {
    // OP_1 OP_IF OP_RETURN OP_ENDIF
    const script = parseScript(
      Buffer.from([Opcode.OP_1, Opcode.OP_IF, Opcode.OP_RETURN, Opcode.OP_ENDIF])
    );
    const ctx = createContext();
    expect(executeScript(script, ctx)).toBe(false);
  });

  test("unbalanced IF fails", () => {
    const script = parseScript(Buffer.from([Opcode.OP_1, Opcode.OP_IF]));
    const ctx = createContext();
    expect(executeScript(script, ctx)).toBe(false);
  });

  test("ENDIF without IF fails", () => {
    const script = parseScript(Buffer.from([Opcode.OP_ENDIF]));
    const ctx = createContext();
    expect(executeScript(script, ctx)).toBe(false);
  });

  test("ELSE without IF fails", () => {
    const script = parseScript(Buffer.from([Opcode.OP_ELSE]));
    const ctx = createContext();
    expect(executeScript(script, ctx)).toBe(false);
  });
});

describe("executeScript - VERIFY operations", () => {
  test("OP_VERIFY with true succeeds", () => {
    const ctx = createContext([scriptNumEncode(1)]);
    const script = parseScript(Buffer.from([Opcode.OP_VERIFY]));
    expect(executeScript(script, ctx)).toBe(true);
    expect(ctx.stack.length).toBe(0);
  });

  test("OP_VERIFY with false fails", () => {
    const ctx = createContext([scriptNumEncode(0)]);
    const script = parseScript(Buffer.from([Opcode.OP_VERIFY]));
    expect(executeScript(script, ctx)).toBe(false);
  });

  test("OP_NUMEQUALVERIFY succeeds", () => {
    const ctx = createContext([scriptNumEncode(5), scriptNumEncode(5)]);
    const script = parseScript(Buffer.from([Opcode.OP_NUMEQUALVERIFY]));
    expect(executeScript(script, ctx)).toBe(true);
    expect(ctx.stack.length).toBe(0);
  });

  test("OP_NUMEQUALVERIFY fails", () => {
    const ctx = createContext([scriptNumEncode(5), scriptNumEncode(3)]);
    const script = parseScript(Buffer.from([Opcode.OP_NUMEQUALVERIFY]));
    expect(executeScript(script, ctx)).toBe(false);
  });
});

describe("executeScript - disabled opcodes", () => {
  test("OP_CAT fails", () => {
    const ctx = createContext([Buffer.from([1]), Buffer.from([2])]);
    const script = parseScript(Buffer.from([Opcode.OP_CAT]));
    expect(executeScript(script, ctx)).toBe(false);
  });

  test("OP_MUL fails", () => {
    const ctx = createContext([scriptNumEncode(2), scriptNumEncode(3)]);
    const script = parseScript(Buffer.from([Opcode.OP_MUL]));
    expect(executeScript(script, ctx)).toBe(false);
  });
});

describe("executeScript - CHECKSIG", () => {
  test("OP_CHECKSIG with valid signature succeeds", () => {
    const privateKey = Buffer.from(
      "0000000000000000000000000000000000000000000000000000000000000001",
      "hex"
    );
    const publicKey = privateKeyToPublicKey(privateKey, true);
    const msgHash = Buffer.alloc(32, 0x42);

    const sigBytes = ecdsaSign(msgHash, privateKey);
    const hashType = 0x01; // SIGHASH_ALL
    const sig = Buffer.concat([sigBytes, Buffer.from([hashType])]);

    // Create a sigHasher that returns our predetermined hash
    const sigHasher = (_subscript: Buffer, _ht: number) => msgHash;

    const ctx: ExecutionContext = {
      stack: [sig, publicKey],
      altStack: [],
      flags: defaultFlags(),
      sigHasher,
      sigVersion: SigVersion.BASE,
    };

    // Simple script: just OP_CHECKSIG
    const script = parseScript(Buffer.from([Opcode.OP_CHECKSIG]));
    expect(executeScript(script, ctx)).toBe(true);
    expect(ctx.stack.length).toBe(1);
    expect(scriptNumDecode(ctx.stack[0])).toBe(1);
  });

  test("OP_CHECKSIG with invalid signature pushes false (without NULLFAIL)", () => {
    const privateKey = Buffer.from(
      "0000000000000000000000000000000000000000000000000000000000000001",
      "hex"
    );
    const publicKey = privateKeyToPublicKey(privateKey, true);
    const msgHash = Buffer.alloc(32, 0x42);

    // Sign different message
    const differentHash = Buffer.alloc(32, 0x99);
    const sigBytes = ecdsaSign(differentHash, privateKey);
    const hashType = 0x01;
    const sig = Buffer.concat([sigBytes, Buffer.from([hashType])]);

    const sigHasher = (_subscript: Buffer, _ht: number) => msgHash;

    const ctx: ExecutionContext = {
      stack: [sig, publicKey],
      altStack: [],
      flags: { ...defaultFlags(), verifyNullFail: false }, // Disable NULLFAIL for legacy behavior
      sigHasher,
      sigVersion: SigVersion.BASE,
    };

    const script = parseScript(Buffer.from([Opcode.OP_CHECKSIG]));
    expect(executeScript(script, ctx)).toBe(true);
    expect(ctx.stack.length).toBe(1);
    expect(ctx.stack[0].length).toBe(0); // false
  });

  test("OP_CHECKSIGVERIFY with valid signature succeeds", () => {
    const privateKey = Buffer.from(
      "0000000000000000000000000000000000000000000000000000000000000001",
      "hex"
    );
    const publicKey = privateKeyToPublicKey(privateKey, true);
    const msgHash = Buffer.alloc(32, 0x42);

    const sigBytes = ecdsaSign(msgHash, privateKey);
    const sig = Buffer.concat([sigBytes, Buffer.from([0x01])]);

    const sigHasher = (_subscript: Buffer, _ht: number) => msgHash;

    const ctx: ExecutionContext = {
      stack: [sig, publicKey],
      altStack: [],
      flags: defaultFlags(),
      sigHasher,
      sigVersion: SigVersion.BASE,
    };

    const script = parseScript(Buffer.from([Opcode.OP_CHECKSIGVERIFY]));
    expect(executeScript(script, ctx)).toBe(true);
    expect(ctx.stack.length).toBe(0);
  });
});

describe("executeScript - CHECKMULTISIG", () => {
  test("2-of-3 multisig succeeds", () => {
    // Create 3 keypairs
    const privKeys = [
      Buffer.from("0000000000000000000000000000000000000000000000000000000000000001", "hex"),
      Buffer.from("0000000000000000000000000000000000000000000000000000000000000002", "hex"),
      Buffer.from("0000000000000000000000000000000000000000000000000000000000000003", "hex"),
    ];
    const pubKeys = privKeys.map((k) => privateKeyToPublicKey(k, true));

    const msgHash = Buffer.alloc(32, 0x42);
    const sigHasher = (_subscript: Buffer, _ht: number) => msgHash;

    // Sign with first two keys
    const sig1 = Buffer.concat([ecdsaSign(msgHash, privKeys[0]), Buffer.from([0x01])]);
    const sig2 = Buffer.concat([ecdsaSign(msgHash, privKeys[1]), Buffer.from([0x01])]);

    // Stack: dummy sig1 sig2 m=2 pubkey1 pubkey2 pubkey3 n=3
    const ctx: ExecutionContext = {
      stack: [
        Buffer.alloc(0), // dummy element
        sig1,
        sig2,
        scriptNumEncode(2), // m
        pubKeys[0],
        pubKeys[1],
        pubKeys[2],
        scriptNumEncode(3), // n
      ],
      altStack: [],
      flags: defaultFlags(),
      sigHasher,
      sigVersion: SigVersion.BASE,
    };

    const script = parseScript(Buffer.from([Opcode.OP_CHECKMULTISIG]));
    expect(executeScript(script, ctx)).toBe(true);
    expect(ctx.stack.length).toBe(1);
    expect(scriptNumDecode(ctx.stack[0])).toBe(1);
  });

  test("2-of-3 multisig pushes false with wrong signatures (without NULLFAIL)", () => {
    const privKeys = [
      Buffer.from("0000000000000000000000000000000000000000000000000000000000000001", "hex"),
      Buffer.from("0000000000000000000000000000000000000000000000000000000000000002", "hex"),
      Buffer.from("0000000000000000000000000000000000000000000000000000000000000003", "hex"),
    ];
    const pubKeys = privKeys.map((k) => privateKeyToPublicKey(k, true));

    const msgHash = Buffer.alloc(32, 0x42);
    const wrongHash = Buffer.alloc(32, 0x99);
    const sigHasher = (_subscript: Buffer, _ht: number) => msgHash;

    // Sign wrong message
    const sig1 = Buffer.concat([ecdsaSign(wrongHash, privKeys[0]), Buffer.from([0x01])]);
    const sig2 = Buffer.concat([ecdsaSign(wrongHash, privKeys[1]), Buffer.from([0x01])]);

    const ctx: ExecutionContext = {
      stack: [
        Buffer.alloc(0),
        sig1,
        sig2,
        scriptNumEncode(2),
        pubKeys[0],
        pubKeys[1],
        pubKeys[2],
        scriptNumEncode(3),
      ],
      altStack: [],
      flags: { ...defaultFlags(), verifyNullFail: false }, // Disable NULLFAIL for legacy behavior
      sigHasher,
      sigVersion: SigVersion.BASE,
    };

    const script = parseScript(Buffer.from([Opcode.OP_CHECKMULTISIG]));
    expect(executeScript(script, ctx)).toBe(true);
    expect(ctx.stack.length).toBe(1);
    expect(ctx.stack[0].length).toBe(0); // false
  });

  test("NULLDUMMY: non-empty dummy fails when flag set", () => {
    const privKey = Buffer.from(
      "0000000000000000000000000000000000000000000000000000000000000001",
      "hex"
    );
    const pubKey = privateKeyToPublicKey(privKey, true);
    const msgHash = Buffer.alloc(32, 0x42);
    const sigHasher = (_subscript: Buffer, _ht: number) => msgHash;
    const sig = Buffer.concat([ecdsaSign(msgHash, privKey), Buffer.from([0x01])]);

    const ctx: ExecutionContext = {
      stack: [
        Buffer.from([0x42]), // non-empty dummy!
        sig,
        scriptNumEncode(1),
        pubKey,
        scriptNumEncode(1),
      ],
      altStack: [],
      flags: { ...defaultFlags(), verifyNullDummy: true },
      sigHasher,
      sigVersion: SigVersion.BASE,
    };

    const script = parseScript(Buffer.from([Opcode.OP_CHECKMULTISIG]));
    expect(executeScript(script, ctx)).toBe(false);
  });

  test("OP_CHECKMULTISIGVERIFY succeeds", () => {
    const privKey = Buffer.from(
      "0000000000000000000000000000000000000000000000000000000000000001",
      "hex"
    );
    const pubKey = privateKeyToPublicKey(privKey, true);
    const msgHash = Buffer.alloc(32, 0x42);
    const sigHasher = (_subscript: Buffer, _ht: number) => msgHash;
    const sig = Buffer.concat([ecdsaSign(msgHash, privKey), Buffer.from([0x01])]);

    const ctx: ExecutionContext = {
      stack: [Buffer.alloc(0), sig, scriptNumEncode(1), pubKey, scriptNumEncode(1)],
      altStack: [],
      flags: defaultFlags(),
      sigHasher,
      sigVersion: SigVersion.BASE,
    };

    const script = parseScript(Buffer.from([Opcode.OP_CHECKMULTISIGVERIFY]));
    expect(executeScript(script, ctx)).toBe(true);
    expect(ctx.stack.length).toBe(0);
  });
});

describe("script type detection", () => {
  test("isP2PKH", () => {
    const pubkeyHash = Buffer.alloc(20, 0xaa);
    const p2pkh = Buffer.concat([
      Buffer.from([Opcode.OP_DUP, Opcode.OP_HASH160, 20]),
      pubkeyHash,
      Buffer.from([Opcode.OP_EQUALVERIFY, Opcode.OP_CHECKSIG]),
    ]);
    expect(isP2PKH(p2pkh)).toBe(true);
    expect(isP2SH(p2pkh)).toBe(false);
    expect(isP2WPKH(p2pkh)).toBe(false);
    expect(getScriptType(p2pkh)).toBe(AddressType.P2PKH);
  });

  test("isP2SH", () => {
    const scriptHash = Buffer.alloc(20, 0xbb);
    const p2sh = Buffer.concat([
      Buffer.from([Opcode.OP_HASH160, 20]),
      scriptHash,
      Buffer.from([Opcode.OP_EQUAL]),
    ]);
    expect(isP2SH(p2sh)).toBe(true);
    expect(isP2PKH(p2sh)).toBe(false);
    expect(getScriptType(p2sh)).toBe(AddressType.P2SH);
  });

  test("isP2WPKH", () => {
    const pubkeyHash = Buffer.alloc(20, 0xcc);
    const p2wpkh = Buffer.concat([Buffer.from([Opcode.OP_0, 20]), pubkeyHash]);
    expect(isP2WPKH(p2wpkh)).toBe(true);
    expect(isP2WSH(p2wpkh)).toBe(false);
    expect(getScriptType(p2wpkh)).toBe(AddressType.P2WPKH);
  });

  test("isP2WSH", () => {
    const scriptHash = Buffer.alloc(32, 0xdd);
    const p2wsh = Buffer.concat([Buffer.from([Opcode.OP_0, 32]), scriptHash]);
    expect(isP2WSH(p2wsh)).toBe(true);
    expect(isP2WPKH(p2wsh)).toBe(false);
    expect(getScriptType(p2wsh)).toBe(AddressType.P2WSH);
  });

  test("isP2TR", () => {
    const pubkey = Buffer.alloc(32, 0xee);
    const p2tr = Buffer.concat([Buffer.from([Opcode.OP_1, 32]), pubkey]);
    expect(isP2TR(p2tr)).toBe(true);
    expect(isP2WSH(p2tr)).toBe(false);
    expect(getScriptType(p2tr)).toBe(AddressType.P2TR);
  });

  test("nonstandard script", () => {
    const nonstandard = Buffer.from([Opcode.OP_1, Opcode.OP_2, Opcode.OP_ADD]);
    expect(isP2PKH(nonstandard)).toBe(false);
    expect(isP2SH(nonstandard)).toBe(false);
    expect(isP2WPKH(nonstandard)).toBe(false);
    expect(isP2WSH(nonstandard)).toBe(false);
    expect(isP2TR(nonstandard)).toBe(false);
    expect(getScriptType(nonstandard)).toBe("nonstandard");
  });
});

describe("verifyScript - P2PKH", () => {
  test("P2PKH success", () => {
    const privateKey = Buffer.from(
      "0000000000000000000000000000000000000000000000000000000000000001",
      "hex"
    );
    const publicKey = privateKeyToPublicKey(privateKey, true);
    const pubkeyHash = hash160(publicKey);

    const msgHash = Buffer.alloc(32, 0x42);
    const sigBytes = ecdsaSign(msgHash, privateKey);
    const sig = Buffer.concat([sigBytes, Buffer.from([0x01])]);

    // scriptSig: <sig> <pubkey>
    const scriptSig = Buffer.concat([
      Buffer.from([sig.length]),
      sig,
      Buffer.from([publicKey.length]),
      publicKey,
    ]);

    // scriptPubKey: OP_DUP OP_HASH160 <pubkeyHash> OP_EQUALVERIFY OP_CHECKSIG
    const scriptPubKey = Buffer.concat([
      Buffer.from([Opcode.OP_DUP, Opcode.OP_HASH160, 20]),
      pubkeyHash,
      Buffer.from([Opcode.OP_EQUALVERIFY, Opcode.OP_CHECKSIG]),
    ]);

    const sigHasher = (_subscript: Buffer, _ht: number) => msgHash;

    expect(verifyScript(scriptSig, scriptPubKey, [], defaultFlags(), sigHasher)).toBe(true);
  });

  test("P2PKH failure - wrong pubkey", () => {
    const privateKey = Buffer.from(
      "0000000000000000000000000000000000000000000000000000000000000001",
      "hex"
    );
    const publicKey = privateKeyToPublicKey(privateKey, true);
    const wrongPubkeyHash = Buffer.alloc(20, 0x99); // wrong hash

    const msgHash = Buffer.alloc(32, 0x42);
    const sig = Buffer.concat([ecdsaSign(msgHash, privateKey), Buffer.from([0x01])]);

    const scriptSig = Buffer.concat([
      Buffer.from([sig.length]),
      sig,
      Buffer.from([publicKey.length]),
      publicKey,
    ]);

    const scriptPubKey = Buffer.concat([
      Buffer.from([Opcode.OP_DUP, Opcode.OP_HASH160, 20]),
      wrongPubkeyHash,
      Buffer.from([Opcode.OP_EQUALVERIFY, Opcode.OP_CHECKSIG]),
    ]);

    const sigHasher = (_subscript: Buffer, _ht: number) => msgHash;

    expect(verifyScript(scriptSig, scriptPubKey, [], defaultFlags(), sigHasher)).toBe(false);
  });
});

describe("getConsensusFlags", () => {
  test("returns correct flags for genesis block", () => {
    const flags = getConsensusFlags(0);
    expect(flags.verifyP2SH).toBe(false);
    expect(flags.verifyWitness).toBe(false);
    expect(flags.verifyTaproot).toBe(false);
  });

  test("returns correct flags for post-P2SH height", () => {
    const flags = getConsensusFlags(200000);
    expect(flags.verifyP2SH).toBe(true);
    expect(flags.verifyWitness).toBe(false);
  });

  test("returns correct flags for post-SegWit height", () => {
    const flags = getConsensusFlags(500000);
    expect(flags.verifyP2SH).toBe(true);
    expect(flags.verifyWitness).toBe(true);
    expect(flags.verifyNullDummy).toBe(true);
    expect(flags.verifyTaproot).toBe(false);
  });

  test("returns correct flags for post-Taproot height", () => {
    const flags = getConsensusFlags(800000);
    expect(flags.verifyP2SH).toBe(true);
    expect(flags.verifyWitness).toBe(true);
    expect(flags.verifyTaproot).toBe(true);
  });
});

describe("script limits", () => {
  test("rejects script over size limit", () => {
    // MAX_SCRIPT_SIZE is 10000
    const largeScript = Buffer.alloc(10001, Opcode.OP_NOP);
    expect(verifyScript(largeScript, Buffer.from([Opcode.OP_1]), [], defaultFlags(), dummySigHasher)).toBe(
      false
    );
  });

  test("rejects element over size limit", () => {
    // MAX_ELEMENT_SIZE is 520
    const largeData = Buffer.alloc(521, 0x42);
    const scriptSig = Buffer.concat([
      Buffer.from([Opcode.OP_PUSHDATA2, 0x09, 0x02]), // 521 bytes
      largeData,
    ]);
    expect(verifyScript(scriptSig, Buffer.from([Opcode.OP_DROP, Opcode.OP_1]), [], defaultFlags(), dummySigHasher)).toBe(
      false
    );
  });

  test("legacy script enforces MAX_OPS_PER_SCRIPT (201)", () => {
    // 202 OP_NOP opcodes would exceed MAX_OPS_PER_SCRIPT in BASE sigversion.
    const ops: number[] = [];
    for (let i = 0; i < 202; i++) ops.push(Opcode.OP_NOP);
    ops.push(Opcode.OP_1); // final true
    const parsed = parseScript(Buffer.from(ops));
    const ctx: ExecutionContext = {
      stack: [],
      altStack: [],
      flags: defaultFlags(),
      sigHasher: dummySigHasher,
      sigVersion: SigVersion.BASE,
    };
    expect(executeScript(parsed, ctx)).toBe(false);
  });

  test("tapscript exempt from MAX_OPS_PER_SCRIPT (BIP-342)", () => {
    // Regression: mainnet block 944,279 tx 8775be68... vin[1] has a
    // 282 KB tapscript with ~701 non-push opcodes. Per BIP-342 / Core
    // interpreter.cpp:450-455, MAX_OPS_PER_SCRIPT does NOT apply in
    // tapscript. Hotbuns previously rejected such blocks.
    const ops: number[] = [];
    // Use OP_NOP — counts as a non-push opcode but does nothing.
    for (let i = 0; i < 1000; i++) ops.push(Opcode.OP_NOP);
    ops.push(Opcode.OP_1); // leave true on stack so script succeeds
    const parsed = parseScript(Buffer.from(ops));
    const ctx: ExecutionContext = {
      stack: [],
      altStack: [],
      flags: defaultFlags(),
      sigHasher: dummySigHasher,
      sigVersion: SigVersion.TAPSCRIPT,
      taprootSigHasher: () => Buffer.alloc(32),
      sigopsBudget: 100000,
    };
    // Script should execute past the 201-op cap; final stack should be
    // [OP_1] which is true. We assert that executeScript does NOT return
    // false on opcount overflow.
    expect(executeScript(parsed, ctx)).toBe(true);
    expect(ctx.stack.length).toBe(1);
  });
});

// ===========================================================================
// BIP-342 tapscript validation-weight budget (interpreter.cpp:362)
// ===========================================================================
describe("BIP-342 tapscript validation-weight budget", () => {
  test("compactSizeLen matches Core's GetSizeOfCompactSize", () => {
    expect(compactSizeLen(0)).toBe(1);
    expect(compactSizeLen(0xfc)).toBe(1);
    expect(compactSizeLen(0xfd)).toBe(3);
    expect(compactSizeLen(0xffff)).toBe(3);
    expect(compactSizeLen(0x10000)).toBe(5);
    expect(compactSizeLen(0xffffffff)).toBe(5);
    expect(compactSizeLen(0x100000000)).toBe(9);
  });

  test("serializedWitnessStackSize matches Core's ::GetSerializeSize", () => {
    // Empty stack = just the count compact-size byte.
    expect(serializedWitnessStackSize([])).toBe(1);
    // One 64-byte item: 1 (count) + 1 (item len prefix) + 64 (bytes).
    expect(serializedWitnessStackSize([Buffer.alloc(64)])).toBe(66);
    // Two items, 100 + 33 bytes:
    expect(serializedWitnessStackSize([Buffer.alloc(100), Buffer.alloc(33)]))
      .toBe(1 + (1 + 100) + (1 + 33));
  });

  test("OP_CHECKSIG: exhausted budget aborts (32-byte pubkey)", () => {
    // Budget = 49: a single non-empty sig MUST trip the gate.
    // Stack (top-down): pubkey, sig.
    const pubkey = Buffer.alloc(32, 0x02);
    const sig = Buffer.alloc(64, 0x42);
    const script = Buffer.from([Opcode.OP_CHECKSIG]);
    const parsed = parseScript(script);
    const ctx: ExecutionContext = {
      stack: [sig, pubkey],
      altStack: [],
      flags: defaultFlags(),
      sigHasher: dummySigHasher,
      sigVersion: SigVersion.TAPSCRIPT,
      taprootSigHasher: () => Buffer.alloc(32),
      sigopsBudget: 49,
    };
    expect(() => executeScript(parsed, ctx)).toThrow("TAPSCRIPT_VALIDATION_WEIGHT");
  });

  test("OP_CHECKSIG: budget consumed once per non-empty sig (unknown pubkey path)", () => {
    // Use a non-32-byte pubkey so verifySchnorrSig returns true without
    // running real Schnorr crypto on the fake bytes (the BIP-342
    // "Passing with an upgradable public key version is also counted"
    // path — Core deducts BEFORE this branch). Budget 50 -> 0.
    const pubkey = Buffer.alloc(33, 0x02);
    const sig = Buffer.alloc(64, 0x42);
    const script = Buffer.from([Opcode.OP_CHECKSIG]);
    const parsed = parseScript(script);
    const ctx: ExecutionContext = {
      stack: [sig, pubkey],
      altStack: [],
      flags: defaultFlags(),
      sigHasher: dummySigHasher,
      sigVersion: SigVersion.TAPSCRIPT,
      taprootSigHasher: () => Buffer.alloc(32),
      sigopsBudget: 50,
    };
    // unknown-pubkey-type → success=true; budget 50 -> 0.
    executeScript(parsed, ctx);
    expect(ctx.sigopsBudget).toBe(0);
  });

  test("OP_CHECKSIG: empty sig consumes NO budget (regression)", () => {
    // Pre-fix hotbuns decremented the budget unconditionally on the
    // tapscript CHECKSIG path, which was wrong: Core only decrements
    // when sig is non-empty (interpreter.cpp:357-366). With budget=0
    // and an empty sig, this should succeed (push false), not throw.
    const pubkey = Buffer.alloc(32, 0x02);
    const sig = Buffer.alloc(0);
    const script = Buffer.from([Opcode.OP_CHECKSIG]);
    const parsed = parseScript(script);
    const ctx: ExecutionContext = {
      stack: [sig, pubkey],
      altStack: [],
      flags: defaultFlags(),
      sigHasher: dummySigHasher,
      sigVersion: SigVersion.TAPSCRIPT,
      taprootSigHasher: () => Buffer.alloc(32),
      sigopsBudget: 0,
    };
    // No throw: the gate only fires for non-empty sigs.
    expect(executeScript(parsed, ctx)).toBe(true);
    expect(ctx.sigopsBudget).toBe(0);
  });

  test("OP_CHECKSIGADD: exhausted budget aborts (with non-empty sig)", () => {
    // Use a non-32-byte pubkey so verifySchnorrSig returns true on the
    // forward-compat path. CHECKSIGADD verifies the sig FIRST in
    // hotbuns then deducts budget, so the throw type might be
    // SCHNORR_SIG before this fires for fake 32-byte pubkey bytes.
    // The unknown-pubkey path returns true with no Schnorr crypto, so
    // we cleanly hit the budget gate.
    const pubkey = Buffer.alloc(33, 0x02);
    const sig = Buffer.alloc(64, 0x42);
    const script = Buffer.from([Opcode.OP_CHECKSIGADD]);
    const parsed = parseScript(script);
    const ctx: ExecutionContext = {
      stack: [sig, scriptNumEncode(0), pubkey],
      altStack: [],
      flags: defaultFlags(),
      sigHasher: dummySigHasher,
      sigVersion: SigVersion.TAPSCRIPT,
      taprootSigHasher: () => Buffer.alloc(32),
      sigopsBudget: 0,
    };
    expect(() => executeScript(parsed, ctx)).toThrow("TAPSCRIPT_VALIDATION_WEIGHT");
  });

  test("OP_CHECKSIGADD: empty sig consumes NO budget", () => {
    const pubkey = Buffer.alloc(32, 0x02);
    const script = Buffer.from([Opcode.OP_CHECKSIGADD]);
    const parsed = parseScript(script);
    const ctx: ExecutionContext = {
      stack: [Buffer.alloc(0), scriptNumEncode(5), pubkey],
      altStack: [],
      flags: defaultFlags(),
      sigHasher: dummySigHasher,
      sigVersion: SigVersion.TAPSCRIPT,
      taprootSigHasher: () => Buffer.alloc(32),
      sigopsBudget: 0,
    };
    // No throw; pushes 5 unchanged.
    executeScript(parsed, ctx);
    expect(ctx.sigopsBudget).toBe(0);
    expect(scriptNumDecode(ctx.stack[0], 4, false)).toBe(5);
  });

  test("Legacy / SegWit-v0 CHECKSIG unaffected by budget", () => {
    // Use a non-tapscript sig version. The path doesn't read sigopsBudget.
    // Empty sig + uncompressed pubkey: legacy CHECKSIG pushes false.
    const pubkey = Buffer.alloc(33, 0x02);
    const sig = Buffer.alloc(0);
    const script = Buffer.from([Opcode.OP_CHECKSIG]);
    const parsed = parseScript(script);
    const ctx: ExecutionContext = {
      stack: [sig, pubkey],
      altStack: [],
      flags: { ...defaultFlags(), verifyNullFail: false },
      sigHasher: dummySigHasher,
      sigVersion: SigVersion.WITNESS_V0,
      // No sigopsBudget on the legacy path.
    };
    expect(executeScript(parsed, ctx)).toBe(true);
  });
});
