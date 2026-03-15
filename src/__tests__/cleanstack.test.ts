/**
 * Tests for witness cleanstack enforcement.
 *
 * Witness scripts (P2WPKH, P2WSH, tapscript) MUST leave exactly one element
 * on the stack after execution, and that element must be true.
 *
 * This is hardcoded in Bitcoin Core's ExecuteWitnessScript and is NOT gated
 * by the SCRIPT_VERIFY_CLEANSTACK flag (which only applies to P2SH).
 */

import { describe, expect, test } from "bun:test";
import {
  verifyScript,
  ScriptError,
  getConsensusFlags,
  type ScriptFlags,
  Opcode,
} from "../script/interpreter.js";
import { sha256Hash, hash160, ecdsaSign, privateKeyToPublicKey } from "../crypto/primitives.js";

// Helper to create a P2WPKH scriptPubKey from a pubkey hash
function makeP2WPKH(pubkeyHash: Buffer): Buffer {
  return Buffer.concat([Buffer.from([Opcode.OP_0, 20]), pubkeyHash]);
}

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
  };
}

describe("witness cleanstack - P2WSH", () => {
  test("P2WSH with exactly one true element on stack succeeds", () => {
    // Simple script: OP_TRUE (pushes 1, leaving exactly one true element)
    const witnessScript = Buffer.from([Opcode.OP_TRUE]);
    const scriptHash = sha256Hash(witnessScript);
    const scriptPubKey = makeP2WSH(scriptHash);

    const witness = [witnessScript];
    const sigHasher = (_subscript: Buffer, _ht: number) => Buffer.alloc(32);

    const result = verifyScript(Buffer.alloc(0), scriptPubKey, witness, witnessFlags(), sigHasher);
    expect(result).toBe(true);
  });

  test("P2WSH with empty stack fails (not cleanstack)", () => {
    // Script that leaves empty stack: DROP TRUE DROP
    // Stack progression: [x] -> [] -> [TRUE] -> []
    // But we need to provide initial stack item...
    // Actually let's use: OP_1 OP_DROP (leaves empty stack)
    const witnessScript = Buffer.from([Opcode.OP_1, Opcode.OP_DROP]);
    const scriptHash = sha256Hash(witnessScript);
    const scriptPubKey = makeP2WSH(scriptHash);

    const witness = [witnessScript];
    const sigHasher = (_subscript: Buffer, _ht: number) => Buffer.alloc(32);

    expect(() => {
      verifyScript(Buffer.alloc(0), scriptPubKey, witness, witnessFlags(), sigHasher);
    }).toThrow(ScriptError);

    try {
      verifyScript(Buffer.alloc(0), scriptPubKey, witness, witnessFlags(), sigHasher);
    } catch (e) {
      expect(e).toBeInstanceOf(ScriptError);
      expect((e as ScriptError).code).toBe("CLEANSTACK");
    }
  });

  test("P2WSH with two elements on stack fails (cleanstack violation)", () => {
    // Script: OP_TRUE OP_TRUE (leaves 2 elements on stack)
    const witnessScript = Buffer.from([Opcode.OP_TRUE, Opcode.OP_TRUE]);
    const scriptHash = sha256Hash(witnessScript);
    const scriptPubKey = makeP2WSH(scriptHash);

    const witness = [witnessScript];
    const sigHasher = (_subscript: Buffer, _ht: number) => Buffer.alloc(32);

    expect(() => {
      verifyScript(Buffer.alloc(0), scriptPubKey, witness, witnessFlags(), sigHasher);
    }).toThrow(ScriptError);

    try {
      verifyScript(Buffer.alloc(0), scriptPubKey, witness, witnessFlags(), sigHasher);
    } catch (e) {
      expect(e).toBeInstanceOf(ScriptError);
      expect((e as ScriptError).code).toBe("CLEANSTACK");
    }
  });

  test("P2WSH with three elements on stack fails (cleanstack violation)", () => {
    // Script: OP_1 OP_2 OP_3 (leaves 3 elements)
    const witnessScript = Buffer.from([Opcode.OP_1, Opcode.OP_2, Opcode.OP_3]);
    const scriptHash = sha256Hash(witnessScript);
    const scriptPubKey = makeP2WSH(scriptHash);

    const witness = [witnessScript];
    const sigHasher = (_subscript: Buffer, _ht: number) => Buffer.alloc(32);

    expect(() => {
      verifyScript(Buffer.alloc(0), scriptPubKey, witness, witnessFlags(), sigHasher);
    }).toThrow(ScriptError);

    try {
      verifyScript(Buffer.alloc(0), scriptPubKey, witness, witnessFlags(), sigHasher);
    } catch (e) {
      expect(e).toBeInstanceOf(ScriptError);
      expect((e as ScriptError).code).toBe("CLEANSTACK");
    }
  });

  test("P2WSH with one false element fails (EVAL_FALSE, not CLEANSTACK)", () => {
    // Script: OP_FALSE (pushes 0/empty, leaving one element that is false)
    const witnessScript = Buffer.from([Opcode.OP_FALSE]);
    const scriptHash = sha256Hash(witnessScript);
    const scriptPubKey = makeP2WSH(scriptHash);

    const witness = [witnessScript];
    const sigHasher = (_subscript: Buffer, _ht: number) => Buffer.alloc(32);

    // This should return false (not throw CLEANSTACK error)
    // because the stack has 1 element, but it's false
    const result = verifyScript(Buffer.alloc(0), scriptPubKey, witness, witnessFlags(), sigHasher);
    expect(result).toBe(false);
  });

  test("P2WSH with witness stack items leaves extra elements (cleanstack violation)", () => {
    // Witness script: just OP_TRUE
    // But we push extra items via witness stack
    const witnessScript = Buffer.from([Opcode.OP_TRUE]);
    const scriptHash = sha256Hash(witnessScript);
    const scriptPubKey = makeP2WSH(scriptHash);

    // Provide extra witness items that will remain on stack
    // Witness: [extra_item, witnessScript]
    // After script execution: stack will have [extra_item, TRUE]
    const extraItem = Buffer.from([0x42]);
    const witness = [extraItem, witnessScript];
    const sigHasher = (_subscript: Buffer, _ht: number) => Buffer.alloc(32);

    expect(() => {
      verifyScript(Buffer.alloc(0), scriptPubKey, witness, witnessFlags(), sigHasher);
    }).toThrow(ScriptError);

    try {
      verifyScript(Buffer.alloc(0), scriptPubKey, witness, witnessFlags(), sigHasher);
    } catch (e) {
      expect(e).toBeInstanceOf(ScriptError);
      expect((e as ScriptError).code).toBe("CLEANSTACK");
    }
  });
});

describe("witness cleanstack - P2WPKH", () => {
  const privateKey = Buffer.from(
    "0000000000000000000000000000000000000000000000000000000000000001",
    "hex"
  );
  const pubkey = privateKeyToPublicKey(privateKey, true);
  const pubkeyHash = hash160(pubkey);
  const correctHash = Buffer.alloc(32, 0x42);

  test("P2WPKH with valid sig leaves exactly one element (success)", () => {
    const scriptPubKey = makeP2WPKH(pubkeyHash);
    const sig = Buffer.concat([ecdsaSign(correctHash, privateKey), Buffer.from([0x01])]);
    const witness = [sig, pubkey];
    const sigHasher = (_subscript: Buffer, _ht: number) => correctHash;

    const result = verifyScript(Buffer.alloc(0), scriptPubKey, witness, witnessFlags(), sigHasher);
    expect(result).toBe(true);
  });

  test("P2WPKH requires exactly 2 witness elements", () => {
    const scriptPubKey = makeP2WPKH(pubkeyHash);
    const sig = Buffer.concat([ecdsaSign(correctHash, privateKey), Buffer.from([0x01])]);

    // Only 1 witness element - should fail
    const witness = [sig];
    const sigHasher = (_subscript: Buffer, _ht: number) => correctHash;

    const result = verifyScript(Buffer.alloc(0), scriptPubKey, witness, witnessFlags(), sigHasher);
    expect(result).toBe(false);
  });

  test("P2WPKH with 3 witness elements fails", () => {
    const scriptPubKey = makeP2WPKH(pubkeyHash);
    const sig = Buffer.concat([ecdsaSign(correctHash, privateKey), Buffer.from([0x01])]);

    // 3 witness elements - should fail (witness program mismatch)
    const witness = [Buffer.from([0x42]), sig, pubkey];
    const sigHasher = (_subscript: Buffer, _ht: number) => correctHash;

    const result = verifyScript(Buffer.alloc(0), scriptPubKey, witness, witnessFlags(), sigHasher);
    expect(result).toBe(false);
  });
});

describe("cleanstack NOT enforced for legacy scripts", () => {
  test("legacy P2PKH with extra items on stack still succeeds", () => {
    // Build a P2PKH scriptPubKey
    const privateKey = Buffer.from(
      "0000000000000000000000000000000000000000000000000000000000000001",
      "hex"
    );
    const pubkey = privateKeyToPublicKey(privateKey, true);
    const pubkeyHash = hash160(pubkey);
    const correctHash = Buffer.alloc(32, 0x42);

    // P2PKH scriptPubKey: OP_DUP OP_HASH160 <pubkeyHash> OP_EQUALVERIFY OP_CHECKSIG
    const scriptPubKey = Buffer.concat([
      Buffer.from([Opcode.OP_DUP, Opcode.OP_HASH160, 20]),
      pubkeyHash,
      Buffer.from([Opcode.OP_EQUALVERIFY, Opcode.OP_CHECKSIG]),
    ]);

    const sig = Buffer.concat([ecdsaSign(correctHash, privateKey), Buffer.from([0x01])]);

    // scriptSig pushes: extraItem, sig, pubkey
    // After P2PKH execution: stack has [extraItem, TRUE]
    // Legacy scripts don't enforce cleanstack by default
    const extraItem = Buffer.from([0x42]);
    const scriptSig = Buffer.concat([
      Buffer.from([extraItem.length]),
      extraItem,
      Buffer.from([sig.length]),
      sig,
      Buffer.from([pubkey.length]),
      pubkey,
    ]);

    const flags = witnessFlags();
    const sigHasher = (_subscript: Buffer, _ht: number) => correctHash;

    // Legacy scripts with CLEANSTACK flag OFF should succeed even with extra items
    const result = verifyScript(scriptSig, scriptPubKey, [], flags, sigHasher);
    expect(result).toBe(true);
  });
});
