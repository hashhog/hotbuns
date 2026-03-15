/**
 * Tests for SCRIPT_VERIFY_MINIMALIF enforcement.
 *
 * When MINIMALIF is active (mandatory for segwit v0 and tapscript), the argument
 * to OP_IF/OP_NOTIF must be exactly:
 * - Empty Buffer (false), OR
 * - Buffer.from([0x01]) (true)
 *
 * Any other truthy values like [0x02], [0x01, 0x00], [0x00], etc. are rejected.
 *
 * Reference: Bitcoin Core interpreter.cpp, SCRIPT_VERIFY_MINIMALIF handler.
 */

import { describe, expect, test } from "bun:test";
import {
  verifyScript,
  ScriptError,
  type ScriptFlags,
  Opcode,
  executeScript,
  parseScript,
  type ExecutionContext,
  SigVersion,
} from "../script/interpreter.js";
import { sha256Hash } from "../crypto/primitives.js";

// Helper to create a P2WSH scriptPubKey from a witness script hash
function makeP2WSH(scriptHash: Buffer): Buffer {
  return Buffer.concat([Buffer.from([Opcode.OP_0, 32]), scriptHash]);
}

// Helper to create default witness flags
function witnessFlags(): ScriptFlags {
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
    verifyMinimalIf: true,
  };
}

// Dummy sigHasher
function dummySigHasher(_subscript: Buffer, _hashType: number): Buffer {
  return Buffer.alloc(32);
}

describe("MINIMALIF - OP_IF with various input values", () => {
  test("OP_IF with [0x01] on stack succeeds (valid true)", () => {
    // Witness script: OP_IF OP_TRUE OP_ELSE OP_FALSE OP_ENDIF
    // Stack input: [0x01] (valid true value)
    // Expected: takes IF branch, pushes TRUE
    const witnessScript = Buffer.from([
      Opcode.OP_IF,
      Opcode.OP_TRUE,
      Opcode.OP_ELSE,
      Opcode.OP_FALSE,
      Opcode.OP_ENDIF,
    ]);
    const scriptHash = sha256Hash(witnessScript);
    const scriptPubKey = makeP2WSH(scriptHash);

    // Provide [0x01] as the condition
    const conditionValue = Buffer.from([0x01]);
    const witness = [conditionValue, witnessScript];

    const result = verifyScript(Buffer.alloc(0), scriptPubKey, witness, witnessFlags(), dummySigHasher);
    expect(result).toBe(true);
  });

  test("OP_IF with empty buffer on stack takes else branch (valid false)", () => {
    // Witness script: OP_IF OP_FALSE OP_ELSE OP_TRUE OP_ENDIF
    // Stack input: empty (valid false value)
    // Expected: takes ELSE branch, pushes TRUE
    const witnessScript = Buffer.from([
      Opcode.OP_IF,
      Opcode.OP_FALSE,
      Opcode.OP_ELSE,
      Opcode.OP_TRUE,
      Opcode.OP_ENDIF,
    ]);
    const scriptHash = sha256Hash(witnessScript);
    const scriptPubKey = makeP2WSH(scriptHash);

    // Provide empty buffer as the condition
    const conditionValue = Buffer.alloc(0);
    const witness = [conditionValue, witnessScript];

    const result = verifyScript(Buffer.alloc(0), scriptPubKey, witness, witnessFlags(), dummySigHasher);
    expect(result).toBe(true);
  });

  test("OP_IF with [0x02] on stack fails MINIMALIF", () => {
    // Witness script: OP_IF OP_TRUE OP_ELSE OP_FALSE OP_ENDIF
    // Stack input: [0x02] (invalid - not 0x01)
    // Expected: MINIMALIF error
    const witnessScript = Buffer.from([
      Opcode.OP_IF,
      Opcode.OP_TRUE,
      Opcode.OP_ELSE,
      Opcode.OP_FALSE,
      Opcode.OP_ENDIF,
    ]);
    const scriptHash = sha256Hash(witnessScript);
    const scriptPubKey = makeP2WSH(scriptHash);

    const conditionValue = Buffer.from([0x02]);
    const witness = [conditionValue, witnessScript];

    expect(() => {
      verifyScript(Buffer.alloc(0), scriptPubKey, witness, witnessFlags(), dummySigHasher);
    }).toThrow(ScriptError);

    try {
      verifyScript(Buffer.alloc(0), scriptPubKey, witness, witnessFlags(), dummySigHasher);
    } catch (e) {
      expect(e).toBeInstanceOf(ScriptError);
      expect((e as ScriptError).code).toBe("MINIMALIF");
    }
  });

  test("OP_IF with [0x00] on stack fails MINIMALIF", () => {
    // Witness script: OP_IF OP_TRUE OP_ELSE OP_TRUE OP_ENDIF
    // Stack input: [0x00] (invalid - should be empty for false)
    const witnessScript = Buffer.from([
      Opcode.OP_IF,
      Opcode.OP_TRUE,
      Opcode.OP_ELSE,
      Opcode.OP_TRUE,
      Opcode.OP_ENDIF,
    ]);
    const scriptHash = sha256Hash(witnessScript);
    const scriptPubKey = makeP2WSH(scriptHash);

    const conditionValue = Buffer.from([0x00]);
    const witness = [conditionValue, witnessScript];

    expect(() => {
      verifyScript(Buffer.alloc(0), scriptPubKey, witness, witnessFlags(), dummySigHasher);
    }).toThrow(ScriptError);

    try {
      verifyScript(Buffer.alloc(0), scriptPubKey, witness, witnessFlags(), dummySigHasher);
    } catch (e) {
      expect(e).toBeInstanceOf(ScriptError);
      expect((e as ScriptError).code).toBe("MINIMALIF");
    }
  });

  test("OP_IF with [0x01, 0x00] on stack fails MINIMALIF", () => {
    // Multi-byte value even though it evaluates to true
    const witnessScript = Buffer.from([
      Opcode.OP_IF,
      Opcode.OP_TRUE,
      Opcode.OP_ELSE,
      Opcode.OP_FALSE,
      Opcode.OP_ENDIF,
    ]);
    const scriptHash = sha256Hash(witnessScript);
    const scriptPubKey = makeP2WSH(scriptHash);

    const conditionValue = Buffer.from([0x01, 0x00]);
    const witness = [conditionValue, witnessScript];

    expect(() => {
      verifyScript(Buffer.alloc(0), scriptPubKey, witness, witnessFlags(), dummySigHasher);
    }).toThrow(ScriptError);

    try {
      verifyScript(Buffer.alloc(0), scriptPubKey, witness, witnessFlags(), dummySigHasher);
    } catch (e) {
      expect(e).toBeInstanceOf(ScriptError);
      expect((e as ScriptError).code).toBe("MINIMALIF");
    }
  });

  test("OP_IF with large truthy value fails MINIMALIF", () => {
    // [0x42, 0x42, 0x42] - truthy but not minimal
    const witnessScript = Buffer.from([
      Opcode.OP_IF,
      Opcode.OP_TRUE,
      Opcode.OP_ELSE,
      Opcode.OP_FALSE,
      Opcode.OP_ENDIF,
    ]);
    const scriptHash = sha256Hash(witnessScript);
    const scriptPubKey = makeP2WSH(scriptHash);

    const conditionValue = Buffer.from([0x42, 0x42, 0x42]);
    const witness = [conditionValue, witnessScript];

    expect(() => {
      verifyScript(Buffer.alloc(0), scriptPubKey, witness, witnessFlags(), dummySigHasher);
    }).toThrow(ScriptError);

    try {
      verifyScript(Buffer.alloc(0), scriptPubKey, witness, witnessFlags(), dummySigHasher);
    } catch (e) {
      expect(e).toBeInstanceOf(ScriptError);
      expect((e as ScriptError).code).toBe("MINIMALIF");
    }
  });
});

describe("MINIMALIF - OP_NOTIF", () => {
  test("OP_NOTIF with empty buffer takes the branch (valid false input)", () => {
    // OP_NOTIF with false input -> takes branch
    const witnessScript = Buffer.from([
      Opcode.OP_NOTIF,
      Opcode.OP_TRUE,
      Opcode.OP_ELSE,
      Opcode.OP_FALSE,
      Opcode.OP_ENDIF,
    ]);
    const scriptHash = sha256Hash(witnessScript);
    const scriptPubKey = makeP2WSH(scriptHash);

    const conditionValue = Buffer.alloc(0); // false
    const witness = [conditionValue, witnessScript];

    const result = verifyScript(Buffer.alloc(0), scriptPubKey, witness, witnessFlags(), dummySigHasher);
    expect(result).toBe(true);
  });

  test("OP_NOTIF with [0x01] skips the branch (valid true input)", () => {
    // OP_NOTIF with true input -> skips branch, takes else
    const witnessScript = Buffer.from([
      Opcode.OP_NOTIF,
      Opcode.OP_FALSE,
      Opcode.OP_ELSE,
      Opcode.OP_TRUE,
      Opcode.OP_ENDIF,
    ]);
    const scriptHash = sha256Hash(witnessScript);
    const scriptPubKey = makeP2WSH(scriptHash);

    const conditionValue = Buffer.from([0x01]); // true
    const witness = [conditionValue, witnessScript];

    const result = verifyScript(Buffer.alloc(0), scriptPubKey, witness, witnessFlags(), dummySigHasher);
    expect(result).toBe(true);
  });

  test("OP_NOTIF with [0x02] fails MINIMALIF", () => {
    const witnessScript = Buffer.from([
      Opcode.OP_NOTIF,
      Opcode.OP_TRUE,
      Opcode.OP_ELSE,
      Opcode.OP_TRUE,
      Opcode.OP_ENDIF,
    ]);
    const scriptHash = sha256Hash(witnessScript);
    const scriptPubKey = makeP2WSH(scriptHash);

    const conditionValue = Buffer.from([0x02]);
    const witness = [conditionValue, witnessScript];

    expect(() => {
      verifyScript(Buffer.alloc(0), scriptPubKey, witness, witnessFlags(), dummySigHasher);
    }).toThrow(ScriptError);

    try {
      verifyScript(Buffer.alloc(0), scriptPubKey, witness, witnessFlags(), dummySigHasher);
    } catch (e) {
      expect(e).toBeInstanceOf(ScriptError);
      expect((e as ScriptError).code).toBe("MINIMALIF");
    }
  });
});

describe("MINIMALIF - Legacy scripts (no MINIMALIF enforcement)", () => {
  test("Legacy OP_IF with [0x02] succeeds (no MINIMALIF in legacy)", () => {
    // For legacy scripts, MINIMALIF is not enforced
    const stack: Buffer[] = [Buffer.from([0x02])];
    const script = parseScript(
      Buffer.from([Opcode.OP_IF, Opcode.OP_TRUE, Opcode.OP_ELSE, Opcode.OP_FALSE, Opcode.OP_ENDIF])
    );

    const ctx: ExecutionContext = {
      stack,
      altStack: [],
      flags: { ...witnessFlags(), verifyMinimalIf: false },
      sigHasher: dummySigHasher,
      sigVersion: SigVersion.BASE,
    };

    // Should succeed in legacy mode (MINIMALIF flag is false)
    const result = executeScript(script, ctx);
    expect(result).toBe(true);
    expect(ctx.stack.length).toBe(1);
    // [0x02] is truthy, so takes IF branch -> pushes TRUE (encoded as 1)
    expect(ctx.stack[0][0]).toBe(1);
  });

  test("Legacy OP_IF with [0x00] succeeds (no MINIMALIF in legacy)", () => {
    // [0x00] is falsy in legacy, should take ELSE branch
    const stack: Buffer[] = [Buffer.from([0x00])];
    const script = parseScript(
      Buffer.from([Opcode.OP_IF, Opcode.OP_FALSE, Opcode.OP_ELSE, Opcode.OP_TRUE, Opcode.OP_ENDIF])
    );

    const ctx: ExecutionContext = {
      stack,
      altStack: [],
      flags: { ...witnessFlags(), verifyMinimalIf: false },
      sigHasher: dummySigHasher,
      sigVersion: SigVersion.BASE,
    };

    const result = executeScript(script, ctx);
    expect(result).toBe(true);
    expect(ctx.stack.length).toBe(1);
    // [0x00] is falsy, takes ELSE branch -> pushes TRUE
    expect(ctx.stack[0][0]).toBe(1);
  });
});

describe("MINIMALIF - Witness v0 enforces MINIMALIF unconditionally", () => {
  test("P2WSH automatically enforces MINIMALIF even if flag not set", () => {
    // Even without explicitly setting verifyMinimalIf, P2WSH should enforce it
    const flags: ScriptFlags = {
      verifyP2SH: true,
      verifyWitness: true,
      verifyTaproot: false,
      verifyStrictEncoding: false,
      verifyDERSignatures: true,
      verifyLowS: false,
      verifyNullDummy: true,
      verifyNullFail: true,
      verifyCheckLockTimeVerify: true,
      verifyCheckSequenceVerify: true,
      verifyWitnessPubkeyType: true,
      // verifyMinimalIf NOT set
    };

    const witnessScript = Buffer.from([
      Opcode.OP_IF,
      Opcode.OP_TRUE,
      Opcode.OP_ELSE,
      Opcode.OP_FALSE,
      Opcode.OP_ENDIF,
    ]);
    const scriptHash = sha256Hash(witnessScript);
    const scriptPubKey = makeP2WSH(scriptHash);

    // Invalid MINIMALIF value
    const conditionValue = Buffer.from([0x02]);
    const witness = [conditionValue, witnessScript];

    // Should still throw MINIMALIF error because witness v0 enforces it internally
    expect(() => {
      verifyScript(Buffer.alloc(0), scriptPubKey, witness, flags, dummySigHasher);
    }).toThrow(ScriptError);

    try {
      verifyScript(Buffer.alloc(0), scriptPubKey, witness, flags, dummySigHasher);
    } catch (e) {
      expect(e).toBeInstanceOf(ScriptError);
      expect((e as ScriptError).code).toBe("MINIMALIF");
    }
  });
});

describe("MINIMALIF - Nested IF statements", () => {
  test("Nested IF with valid MINIMALIF values succeeds", () => {
    // IF IF TRUE ENDIF ELSE FALSE ENDIF
    const witnessScript = Buffer.from([
      Opcode.OP_IF,
      Opcode.OP_IF,
      Opcode.OP_TRUE,
      Opcode.OP_ENDIF,
      Opcode.OP_ELSE,
      Opcode.OP_FALSE,
      Opcode.OP_ENDIF,
    ]);
    const scriptHash = sha256Hash(witnessScript);
    const scriptPubKey = makeP2WSH(scriptHash);

    // Both conditions are valid [0x01]
    const witness = [Buffer.from([0x01]), Buffer.from([0x01]), witnessScript];

    const result = verifyScript(Buffer.alloc(0), scriptPubKey, witness, witnessFlags(), dummySigHasher);
    expect(result).toBe(true);
  });

  test("Nested IF with invalid inner value fails", () => {
    // IF IF TRUE ENDIF ELSE FALSE ENDIF
    const witnessScript = Buffer.from([
      Opcode.OP_IF,
      Opcode.OP_IF,
      Opcode.OP_TRUE,
      Opcode.OP_ENDIF,
      Opcode.OP_ELSE,
      Opcode.OP_FALSE,
      Opcode.OP_ENDIF,
    ]);
    const scriptHash = sha256Hash(witnessScript);
    const scriptPubKey = makeP2WSH(scriptHash);

    // First valid, second invalid
    const witness = [Buffer.from([0x02]), Buffer.from([0x01]), witnessScript];

    expect(() => {
      verifyScript(Buffer.alloc(0), scriptPubKey, witness, witnessFlags(), dummySigHasher);
    }).toThrow(ScriptError);

    try {
      verifyScript(Buffer.alloc(0), scriptPubKey, witness, witnessFlags(), dummySigHasher);
    } catch (e) {
      expect(e).toBeInstanceOf(ScriptError);
      expect((e as ScriptError).code).toBe("MINIMALIF");
    }
  });
});
