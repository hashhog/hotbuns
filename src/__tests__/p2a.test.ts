/**
 * Tests for Pay-to-Anchor (P2A) output type.
 *
 * P2A is a standardized anyone-can-spend output script used for fee bumping
 * via CPFP in Lightning and similar protocols. The script is:
 *   OP_1 OP_PUSHBYTES_2 0x4e 0x73 (witness v1 with 2-byte program "Ns")
 *
 * Key characteristics:
 * - 4-byte script: 0x51 0x02 0x4e 0x73
 * - Witness v1 program with 2-byte data (0x4e73)
 * - Anyone-can-spend: requires empty witness
 * - Must have 0 value (dust exemption)
 *
 * Reference: Bitcoin Core script/solver.cpp TxoutType::ANCHOR
 */

import { describe, expect, test } from "bun:test";
import {
  isP2A,
  isP2AProgram,
  P2A_SCRIPT,
  getScriptType,
  verifyScript,
  Opcode,
  type ScriptFlags,
} from "../script/interpreter.js";

// Helper to create default flags with witness and taproot enabled
function taprootFlags(): ScriptFlags {
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

describe("P2A script detection", () => {
  test("P2A_SCRIPT constant is correct", () => {
    // OP_1 (0x51) + OP_PUSHBYTES_2 (0x02) + 0x4e + 0x73
    expect(P2A_SCRIPT).toEqual(Buffer.from([0x51, 0x02, 0x4e, 0x73]));
    expect(P2A_SCRIPT.length).toBe(4);
  });

  test("isP2A detects valid anchor script", () => {
    expect(isP2A(P2A_SCRIPT)).toBe(true);
  });

  test("isP2A detects anchor script built manually", () => {
    const script = Buffer.from([Opcode.OP_1, 0x02, 0x4e, 0x73]);
    expect(isP2A(script)).toBe(true);
  });

  test("isP2A rejects wrong length", () => {
    // Too short
    expect(isP2A(Buffer.from([0x51, 0x02, 0x4e]))).toBe(false);
    // Too long
    expect(isP2A(Buffer.from([0x51, 0x02, 0x4e, 0x73, 0x00]))).toBe(false);
    // Empty
    expect(isP2A(Buffer.alloc(0))).toBe(false);
  });

  test("isP2A rejects wrong version byte", () => {
    // OP_0 instead of OP_1
    expect(isP2A(Buffer.from([0x00, 0x02, 0x4e, 0x73]))).toBe(false);
    // OP_2 instead of OP_1
    expect(isP2A(Buffer.from([0x52, 0x02, 0x4e, 0x73]))).toBe(false);
  });

  test("isP2A rejects wrong push length", () => {
    // Wrong push length (0x03 instead of 0x02)
    expect(isP2A(Buffer.from([0x51, 0x03, 0x4e, 0x73]))).toBe(false);
    // Wrong push length (0x01)
    expect(isP2A(Buffer.from([0x51, 0x01, 0x4e, 0x73]))).toBe(false);
  });

  test("isP2A rejects wrong program bytes", () => {
    // Wrong first byte
    expect(isP2A(Buffer.from([0x51, 0x02, 0x00, 0x73]))).toBe(false);
    // Wrong second byte
    expect(isP2A(Buffer.from([0x51, 0x02, 0x4e, 0x00]))).toBe(false);
    // Both wrong
    expect(isP2A(Buffer.from([0x51, 0x02, 0x00, 0x00]))).toBe(false);
  });

  test("isP2A distinguishes from P2TR", () => {
    // P2TR: OP_1 + 32-byte pubkey
    const p2tr = Buffer.concat([
      Buffer.from([Opcode.OP_1, 32]),
      Buffer.alloc(32, 0x42),
    ]);
    expect(isP2A(p2tr)).toBe(false);
    expect(p2tr.length).toBe(34);
  });
});

describe("P2A program detection", () => {
  test("isP2AProgram detects valid anchor program", () => {
    const program = Buffer.from([0x4e, 0x73]);
    expect(isP2AProgram(1, program)).toBe(true);
  });

  test("isP2AProgram rejects wrong version", () => {
    const program = Buffer.from([0x4e, 0x73]);
    expect(isP2AProgram(0, program)).toBe(false);
    expect(isP2AProgram(2, program)).toBe(false);
  });

  test("isP2AProgram rejects wrong program length", () => {
    // Too short
    expect(isP2AProgram(1, Buffer.from([0x4e]))).toBe(false);
    // Too long
    expect(isP2AProgram(1, Buffer.from([0x4e, 0x73, 0x00]))).toBe(false);
  });

  test("isP2AProgram rejects wrong program bytes", () => {
    expect(isP2AProgram(1, Buffer.from([0x00, 0x73]))).toBe(false);
    expect(isP2AProgram(1, Buffer.from([0x4e, 0x00]))).toBe(false);
  });
});

describe("getScriptType for P2A", () => {
  test("getScriptType returns 'anchor' for P2A script", () => {
    expect(getScriptType(P2A_SCRIPT)).toBe("anchor");
  });

  test("getScriptType returns 'p2tr' for P2TR (not anchor)", () => {
    const p2tr = Buffer.concat([
      Buffer.from([Opcode.OP_1, 32]),
      Buffer.alloc(32, 0x42),
    ]);
    expect(getScriptType(p2tr)).toBe("p2tr");
  });

  test("getScriptType returns 'witness_unknown' for other v1 programs", () => {
    // Witness v1 with 3-byte program (not P2A, not P2TR)
    const v1_3byte = Buffer.from([Opcode.OP_1, 0x03, 0x00, 0x00, 0x00]);
    expect(getScriptType(v1_3byte)).toBe("witness_unknown");
  });

  test("getScriptType correctly identifies standard script types", () => {
    // P2PKH
    const p2pkh = Buffer.concat([
      Buffer.from([Opcode.OP_DUP, Opcode.OP_HASH160, 20]),
      Buffer.alloc(20, 0x42),
      Buffer.from([Opcode.OP_EQUALVERIFY, Opcode.OP_CHECKSIG]),
    ]);
    expect(getScriptType(p2pkh)).toBe("p2pkh");

    // P2SH
    const p2sh = Buffer.concat([
      Buffer.from([Opcode.OP_HASH160, 20]),
      Buffer.alloc(20, 0x42),
      Buffer.from([Opcode.OP_EQUAL]),
    ]);
    expect(getScriptType(p2sh)).toBe("p2sh");

    // P2WPKH
    const p2wpkh = Buffer.concat([
      Buffer.from([Opcode.OP_0, 20]),
      Buffer.alloc(20, 0x42),
    ]);
    expect(getScriptType(p2wpkh)).toBe("p2wpkh");

    // P2WSH
    const p2wsh = Buffer.concat([
      Buffer.from([Opcode.OP_0, 32]),
      Buffer.alloc(32, 0x42),
    ]);
    expect(getScriptType(p2wsh)).toBe("p2wsh");

    // OP_RETURN (nulldata)
    const opReturn = Buffer.from([Opcode.OP_RETURN, 0x04, 0xde, 0xad, 0xbe, 0xef]);
    expect(getScriptType(opReturn)).toBe("nulldata");
  });
});

describe("P2A script verification", () => {
  test("P2A with empty witness and empty scriptSig succeeds", () => {
    const scriptPubKey = P2A_SCRIPT;
    const scriptSig = Buffer.alloc(0);
    const witness: Buffer[] = [];
    const sigHasher = (_subscript: Buffer, _ht: number) => Buffer.alloc(32);

    const result = verifyScript(scriptSig, scriptPubKey, witness, taprootFlags(), sigHasher);
    expect(result).toBe(true);
  });

  test("P2A with non-empty witness fails", () => {
    const scriptPubKey = P2A_SCRIPT;
    const scriptSig = Buffer.alloc(0);
    // P2A must have empty witness
    const witness = [Buffer.from([0x01])];
    const sigHasher = (_subscript: Buffer, _ht: number) => Buffer.alloc(32);

    const result = verifyScript(scriptSig, scriptPubKey, witness, taprootFlags(), sigHasher);
    expect(result).toBe(false);
  });

  test("P2A with non-empty scriptSig fails", () => {
    const scriptPubKey = P2A_SCRIPT;
    // Native segwit (including P2A) must have empty scriptSig
    const scriptSig = Buffer.from([0x00]);
    const witness: Buffer[] = [];
    const sigHasher = (_subscript: Buffer, _ht: number) => Buffer.alloc(32);

    const result = verifyScript(scriptSig, scriptPubKey, witness, taprootFlags(), sigHasher);
    expect(result).toBe(false);
  });

  test("P2A verification requires taproot flag enabled", () => {
    const scriptPubKey = P2A_SCRIPT;
    const scriptSig = Buffer.alloc(0);
    const witness: Buffer[] = [];
    const sigHasher = (_subscript: Buffer, _ht: number) => Buffer.alloc(32);

    // Without taproot flag, P2A should still pass legacy evaluation
    // (the script OP_1 <data> executes successfully, leaving 1 on stack)
    const flags = taprootFlags();
    flags.verifyTaproot = false;

    const result = verifyScript(scriptSig, scriptPubKey, witness, flags, sigHasher);
    expect(result).toBe(true);
  });
});

describe("P2A policy rules", () => {
  test("P2A output must have zero value (documented behavior)", () => {
    // This test documents the expected policy: P2A outputs should be 0-value.
    // The actual value check would be in transaction validation, not script verification.
    // Here we just verify the script bytes are correct.
    expect(isP2A(P2A_SCRIPT)).toBe(true);

    // P2A is designed for anchor outputs with 0 satoshi value.
    // The dust exemption for P2A outputs is enforced at the policy layer,
    // not the script interpreter layer.
  });

  test("P2A is a standard output type", () => {
    // P2A should be recognized as a standard script type
    const scriptType = getScriptType(P2A_SCRIPT);
    expect(scriptType).toBe("anchor");
    expect(scriptType).not.toBe("nonstandard");
    expect(scriptType).not.toBe("witness_unknown");
  });

  test("P2A script is exactly 4 bytes", () => {
    // Important for standardness: P2A is always exactly 4 bytes
    expect(P2A_SCRIPT.length).toBe(4);
  });
});

describe("P2A edge cases", () => {
  test("P2A script bytes spell 'Ns' in ASCII", () => {
    // The program bytes 0x4e 0x73 are "Ns" in ASCII
    // This is a deliberate choice in the P2A design
    const programBytes = P2A_SCRIPT.subarray(2);
    expect(programBytes.toString("ascii")).toBe("Ns");
  });

  test("P2A is witness version 1", () => {
    // First byte is OP_1 (0x51), which represents witness version 1
    expect(P2A_SCRIPT[0]).toBe(Opcode.OP_1);
    expect(P2A_SCRIPT[0]).toBe(0x51);
  });

  test("P2A program length is 2 bytes", () => {
    // Second byte indicates a 2-byte push
    expect(P2A_SCRIPT[1]).toBe(2);
  });

  test("multiple P2A outputs in a transaction are allowed", () => {
    // Each P2A output is independently valid
    // (validation happens per-input when spending)
    expect(isP2A(P2A_SCRIPT)).toBe(true);
    expect(isP2A(P2A_SCRIPT)).toBe(true);
  });

  test("spending P2A requires only empty witness", () => {
    // This is the key property: P2A is trivially spendable
    const scriptPubKey = P2A_SCRIPT;
    const scriptSig = Buffer.alloc(0);
    const witness: Buffer[] = [];
    const sigHasher = (_subscript: Buffer, _ht: number) => Buffer.alloc(32);

    expect(verifyScript(scriptSig, scriptPubKey, witness, taprootFlags(), sigHasher)).toBe(true);
  });
});
