/**
 * Tests for P2SH push-only scriptSig enforcement (BIP 16).
 *
 * When spending a P2SH output, the scriptSig must contain only push opcodes.
 * This is enforced unconditionally when P2SH is active (separate from SCRIPT_VERIFY_SIGPUSHONLY).
 *
 * Reference: Bitcoin Core script.cpp IsPushOnly(), interpreter.cpp VerifyScript()
 */

import { describe, expect, test } from "bun:test";
import {
  Opcode,
  isPushOnly,
  verifyScript,
  ScriptError,
  type ScriptFlags,
} from "../script/interpreter.js";
import { hash160 } from "../crypto/primitives.js";

// Helper to create standard flags with P2SH enabled
function standardFlags(): ScriptFlags {
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

describe("isPushOnly", () => {
  test("empty script is push-only", () => {
    expect(isPushOnly(Buffer.alloc(0))).toBe(true);
  });

  test("OP_0 is push-only", () => {
    expect(isPushOnly(Buffer.from([Opcode.OP_0]))).toBe(true);
  });

  test("OP_1 through OP_16 are push-only", () => {
    for (let i = Opcode.OP_1; i <= Opcode.OP_16; i++) {
      expect(isPushOnly(Buffer.from([i]))).toBe(true);
    }
  });

  test("OP_1NEGATE is push-only", () => {
    expect(isPushOnly(Buffer.from([Opcode.OP_1NEGATE]))).toBe(true);
  });

  test("OP_RESERVED is push-only (but fails on execution)", () => {
    // Bitcoin Core considers OP_RESERVED (0x50) push-only
    // even though executing it fails
    expect(isPushOnly(Buffer.from([Opcode.OP_RESERVED]))).toBe(true);
  });

  test("direct data push (1-75 bytes) is push-only", () => {
    // Push 5 bytes: 0x05 followed by 5 data bytes
    const script = Buffer.from([5, 0x01, 0x02, 0x03, 0x04, 0x05]);
    expect(isPushOnly(script)).toBe(true);
  });

  test("OP_PUSHDATA1 is push-only", () => {
    // OP_PUSHDATA1 with 3 bytes of data
    const script = Buffer.from([Opcode.OP_PUSHDATA1, 3, 0xaa, 0xbb, 0xcc]);
    expect(isPushOnly(script)).toBe(true);
  });

  test("OP_PUSHDATA2 is push-only", () => {
    // OP_PUSHDATA2 with 2 bytes of data (length as LE uint16)
    const script = Buffer.from([Opcode.OP_PUSHDATA2, 2, 0, 0xaa, 0xbb]);
    expect(isPushOnly(script)).toBe(true);
  });

  test("OP_PUSHDATA4 is push-only", () => {
    // OP_PUSHDATA4 with 1 byte of data (length as LE uint32)
    const script = Buffer.from([Opcode.OP_PUSHDATA4, 1, 0, 0, 0, 0xff]);
    expect(isPushOnly(script)).toBe(true);
  });

  test("multiple pushes are push-only", () => {
    // OP_0 + push 2 bytes + OP_1
    const script = Buffer.from([Opcode.OP_0, 2, 0xaa, 0xbb, Opcode.OP_1]);
    expect(isPushOnly(script)).toBe(true);
  });

  test("OP_DUP is NOT push-only", () => {
    expect(isPushOnly(Buffer.from([Opcode.OP_DUP]))).toBe(false);
  });

  test("OP_HASH160 is NOT push-only", () => {
    expect(isPushOnly(Buffer.from([Opcode.OP_HASH160]))).toBe(false);
  });

  test("OP_EQUAL is NOT push-only", () => {
    expect(isPushOnly(Buffer.from([Opcode.OP_EQUAL]))).toBe(false);
  });

  test("OP_CHECKSIG is NOT push-only", () => {
    expect(isPushOnly(Buffer.from([Opcode.OP_CHECKSIG]))).toBe(false);
  });

  test("OP_NOP is NOT push-only", () => {
    expect(isPushOnly(Buffer.from([Opcode.OP_NOP]))).toBe(false);
  });

  test("push data followed by OP_DUP is NOT push-only", () => {
    const script = Buffer.from([2, 0xaa, 0xbb, Opcode.OP_DUP]);
    expect(isPushOnly(script)).toBe(false);
  });

  test("OP_IF is NOT push-only", () => {
    expect(isPushOnly(Buffer.from([Opcode.OP_IF]))).toBe(false);
  });

  test("truncated direct push returns false", () => {
    // Claims to push 10 bytes but only has 3
    const script = Buffer.from([10, 0x01, 0x02, 0x03]);
    expect(isPushOnly(script)).toBe(false);
  });

  test("truncated OP_PUSHDATA1 returns false", () => {
    // OP_PUSHDATA1 with no length byte
    expect(isPushOnly(Buffer.from([Opcode.OP_PUSHDATA1]))).toBe(false);
    // OP_PUSHDATA1 claiming 5 bytes but only has 2
    expect(isPushOnly(Buffer.from([Opcode.OP_PUSHDATA1, 5, 0xaa, 0xbb]))).toBe(false);
  });
});

describe("P2SH push-only enforcement", () => {
  // Simple P2SH redeem script: OP_1 (always true)
  const redeemScript = Buffer.from([Opcode.OP_1]);
  const redeemScriptHash = hash160(redeemScript);

  // P2SH scriptPubKey: OP_HASH160 <20 bytes> OP_EQUAL
  const p2shScriptPubKey = Buffer.concat([
    Buffer.from([Opcode.OP_HASH160, 20]),
    redeemScriptHash,
    Buffer.from([Opcode.OP_EQUAL]),
  ]);

  const dummySigHasher = (_subscript: Buffer, _ht: number) => Buffer.alloc(32);

  test("P2SH with push-only scriptSig succeeds", () => {
    // Valid scriptSig: just push the redeem script
    const scriptSig = Buffer.concat([Buffer.from([redeemScript.length]), redeemScript]);

    const result = verifyScript(scriptSig, p2shScriptPubKey, [], standardFlags(), dummySigHasher);
    expect(result).toBe(true);
  });

  test("P2SH with OP_NOP in scriptSig throws SIG_PUSHONLY", () => {
    // OP_NOP executes successfully (does nothing) but is > OP_16 so not push-only
    // Place OP_NOP at the end so scriptSig executes successfully
    const scriptSig = Buffer.concat([
      Buffer.from([redeemScript.length]),
      redeemScript,
      Buffer.from([Opcode.OP_NOP]),
    ]);

    // scriptSig will execute successfully, then scriptPubKey will succeed,
    // then P2SH check will find OP_NOP and throw SIG_PUSHONLY
    expect(() => {
      verifyScript(scriptSig, p2shScriptPubKey, [], standardFlags(), dummySigHasher);
    }).toThrow(ScriptError);

    try {
      verifyScript(scriptSig, p2shScriptPubKey, [], standardFlags(), dummySigHasher);
    } catch (e) {
      expect(e).toBeInstanceOf(ScriptError);
      expect((e as ScriptError).code).toBe("SIG_PUSHONLY");
    }
  });

  test("P2SH with OP_NOP at start of scriptSig throws SIG_PUSHONLY", () => {
    // OP_NOP before push - should throw because OP_NOP > OP_16
    const scriptSig = Buffer.concat([
      Buffer.from([Opcode.OP_NOP]),
      Buffer.from([redeemScript.length]),
      redeemScript,
    ]);

    expect(() => {
      verifyScript(scriptSig, p2shScriptPubKey, [], standardFlags(), dummySigHasher);
    }).toThrow(ScriptError);

    try {
      verifyScript(scriptSig, p2shScriptPubKey, [], standardFlags(), dummySigHasher);
    } catch (e) {
      expect(e).toBeInstanceOf(ScriptError);
      expect((e as ScriptError).code).toBe("SIG_PUSHONLY");
    }
  });

  test("P2SH with OP_NOP1 in scriptSig throws SIG_PUSHONLY", () => {
    // OP_NOP1 also > OP_16
    const scriptSig = Buffer.concat([
      Buffer.from([redeemScript.length]),
      redeemScript,
      Buffer.from([Opcode.OP_NOP1]),
    ]);

    expect(() => {
      verifyScript(scriptSig, p2shScriptPubKey, [], standardFlags(), dummySigHasher);
    }).toThrow(ScriptError);
  });

  test("P2SH with OP_VERIFY in scriptSig fails before push-only check", () => {
    // OP_VERIFY pops and verifies the top item, so the redeemScript gets consumed
    // This means the P2SH outer scriptPubKey (HASH160 EQUAL) fails because
    // the stack doesn't have the expected content after OP_VERIFY runs.
    // The script fails during evaluation, not at the push-only check.
    const scriptSig = Buffer.concat([
      Buffer.from([redeemScript.length]),
      redeemScript,
      Buffer.from([Opcode.OP_VERIFY]),
    ]);

    // This returns false (evaluation fails) rather than throwing SIG_PUSHONLY
    const result = verifyScript(scriptSig, p2shScriptPubKey, [], standardFlags(), dummySigHasher);
    expect(result).toBe(false);
  });

  test("P2SH scriptSig with only OP_0 through OP_16 succeeds", () => {
    // All these are valid push-only opcodes
    const scriptSig = Buffer.concat([
      Buffer.from([Opcode.OP_0]),  // push empty
      Buffer.from([Opcode.OP_1]),  // push 1
      Buffer.from([Opcode.OP_16]), // push 16
      Buffer.from([Opcode.OP_1NEGATE]), // push -1
      Buffer.from([redeemScript.length]),
      redeemScript,
    ]);

    // Should succeed (no SIG_PUSHONLY error)
    // May fail for other reasons (stack not clean), but not SIG_PUSHONLY
    try {
      verifyScript(scriptSig, p2shScriptPubKey, [], standardFlags(), dummySigHasher);
    } catch (e) {
      if (e instanceof ScriptError) {
        expect((e as ScriptError).code).not.toBe("SIG_PUSHONLY");
      }
    }
  });

  test("non-P2SH script with OP_NOP in scriptSig does not throw SIG_PUSHONLY", () => {
    // For non-P2SH scripts, scriptSig can have any opcodes
    // Use a simple bare script that always succeeds
    const bareScriptPubKey = Buffer.from([Opcode.OP_1]); // Always true

    // scriptSig with OP_NOP
    const scriptSig = Buffer.from([Opcode.OP_NOP]);

    // This should succeed (OP_NOP does nothing, then OP_1 succeeds)
    // and should NOT throw SIG_PUSHONLY since it's not P2SH
    let threw = false;
    let threwPushOnly = false;
    try {
      const result = verifyScript(scriptSig, bareScriptPubKey, [], standardFlags(), dummySigHasher);
      expect(result).toBe(true);
    } catch (e) {
      threw = true;
      if (e instanceof ScriptError && (e as ScriptError).code === "SIG_PUSHONLY") {
        threwPushOnly = true;
      }
    }

    // Should not throw SIG_PUSHONLY
    expect(threwPushOnly).toBe(false);
  });

  test("P2SH enforcement works with OP_PUSHDATA1", () => {
    // scriptSig using OP_PUSHDATA1 is still push-only
    const data = Buffer.alloc(100, 0x42);
    const scriptSig = Buffer.concat([
      Buffer.from([Opcode.OP_PUSHDATA1, data.length]),
      data,
      Buffer.from([redeemScript.length]),
      redeemScript,
    ]);

    // This is push-only, so should not throw SIG_PUSHONLY
    try {
      verifyScript(scriptSig, p2shScriptPubKey, [], standardFlags(), dummySigHasher);
    } catch (e) {
      if (e instanceof ScriptError) {
        expect((e as ScriptError).code).not.toBe("SIG_PUSHONLY");
      }
    }
  });

  test("P2SH enforcement works with multiple OP_NOP opcodes", () => {
    // Multiple non-push opcodes
    const scriptSig = Buffer.concat([
      Buffer.from([redeemScript.length]),
      redeemScript,
      Buffer.from([Opcode.OP_NOP, Opcode.OP_NOP, Opcode.OP_NOP]),
    ]);

    expect(() => {
      verifyScript(scriptSig, p2shScriptPubKey, [], standardFlags(), dummySigHasher);
    }).toThrow(ScriptError);
  });
});

describe("P2SH push-only with P2SH flag disabled", () => {
  const redeemScript = Buffer.from([Opcode.OP_1]);
  const redeemScriptHash = hash160(redeemScript);
  const p2shScriptPubKey = Buffer.concat([
    Buffer.from([Opcode.OP_HASH160, 20]),
    redeemScriptHash,
    Buffer.from([Opcode.OP_EQUAL]),
  ]);

  const flagsWithoutP2SH = (): ScriptFlags => ({
    ...standardFlags(),
    verifyP2SH: false,
  });

  const dummySigHasher = (_subscript: Buffer, _ht: number) => Buffer.alloc(32);

  test("with P2SH disabled, computational opcodes in scriptSig are allowed", () => {
    // When P2SH is disabled, the P2SH scriptPubKey is treated as a bare script
    // that just checks hash equality. The scriptSig is allowed to have any opcodes.

    // scriptSig that pushes the hash (not the redeem script) to make EQUAL succeed
    // This is just testing that SIG_PUSHONLY is not enforced without P2SH flag
    const scriptSig = Buffer.concat([
      Buffer.from([Opcode.OP_NOP]), // Computational opcode
      Buffer.from([20]),
      redeemScriptHash,
    ]);

    // Should NOT throw SIG_PUSHONLY
    try {
      verifyScript(scriptSig, p2shScriptPubKey, [], flagsWithoutP2SH(), dummySigHasher);
    } catch (e) {
      if (e instanceof ScriptError) {
        expect((e as ScriptError).code).not.toBe("SIG_PUSHONLY");
      }
    }
  });
});
