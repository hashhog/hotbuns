/**
 * Tests for SCRIPT_VERIFY_NULLFAIL (BIP 146).
 *
 * When NULLFAIL is active:
 * - OP_CHECKSIG/OP_CHECKSIGVERIFY: if signature check fails, signature must be empty
 * - OP_CHECKMULTISIG/OP_CHECKMULTISIGVERIFY: if operation fails, ALL signatures must be empty
 */

import { describe, expect, test } from "bun:test";
import {
  Opcode,
  parseScript,
  executeScript,
  scriptNumEncode,
  getConsensusFlags,
  type ScriptFlags,
  type ExecutionContext,
  SigVersion,
} from "../script/interpreter.js";
import { ecdsaSign, privateKeyToPublicKey } from "../crypto/primitives.js";

// Helper to create flags with NULLFAIL enabled
function flagsWithNullFail(): ScriptFlags {
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
  };
}

// Helper to create flags with NULLFAIL disabled
function flagsWithoutNullFail(): ScriptFlags {
  return {
    ...flagsWithNullFail(),
    verifyNullFail: false,
  };
}

describe("SCRIPT_VERIFY_NULLFAIL - OP_CHECKSIG", () => {
  const privateKey = Buffer.from(
    "0000000000000000000000000000000000000000000000000000000000000001",
    "hex"
  );
  const publicKey = privateKeyToPublicKey(privateKey, true);
  const correctHash = Buffer.alloc(32, 0x42);
  const wrongHash = Buffer.alloc(32, 0x99);

  test("NULLFAIL: non-empty failing signature is rejected", () => {
    // Sign with wrong hash so verification will fail
    const badSig = Buffer.concat([ecdsaSign(wrongHash, privateKey), Buffer.from([0x01])]);
    const sigHasher = (_subscript: Buffer, _ht: number) => correctHash;

    const ctx: ExecutionContext = {
      stack: [badSig, publicKey],
      altStack: [],
      flags: flagsWithNullFail(),
      sigHasher,
      sigVersion: SigVersion.BASE,
    };

    const script = parseScript(Buffer.from([Opcode.OP_CHECKSIG]));
    expect(executeScript(script, ctx)).toBe(false);
  });

  test("NULLFAIL: empty signature is allowed (returns false on stack)", () => {
    const emptySig = Buffer.alloc(0);
    const sigHasher = (_subscript: Buffer, _ht: number) => correctHash;

    const ctx: ExecutionContext = {
      stack: [emptySig, publicKey],
      altStack: [],
      flags: flagsWithNullFail(),
      sigHasher,
      sigVersion: SigVersion.BASE,
    };

    const script = parseScript(Buffer.from([Opcode.OP_CHECKSIG]));
    expect(executeScript(script, ctx)).toBe(true);
    expect(ctx.stack.length).toBe(1);
    expect(ctx.stack[0].length).toBe(0); // false result
  });

  test("NULLFAIL: valid signature succeeds", () => {
    const validSig = Buffer.concat([ecdsaSign(correctHash, privateKey), Buffer.from([0x01])]);
    const sigHasher = (_subscript: Buffer, _ht: number) => correctHash;

    const ctx: ExecutionContext = {
      stack: [validSig, publicKey],
      altStack: [],
      flags: flagsWithNullFail(),
      sigHasher,
      sigVersion: SigVersion.BASE,
    };

    const script = parseScript(Buffer.from([Opcode.OP_CHECKSIG]));
    expect(executeScript(script, ctx)).toBe(true);
    expect(ctx.stack.length).toBe(1);
    expect(ctx.stack[0][0]).toBe(1); // true result
  });

  test("without NULLFAIL: non-empty failing signature returns false (not rejected)", () => {
    const badSig = Buffer.concat([ecdsaSign(wrongHash, privateKey), Buffer.from([0x01])]);
    const sigHasher = (_subscript: Buffer, _ht: number) => correctHash;

    const ctx: ExecutionContext = {
      stack: [badSig, publicKey],
      altStack: [],
      flags: flagsWithoutNullFail(),
      sigHasher,
      sigVersion: SigVersion.BASE,
    };

    const script = parseScript(Buffer.from([Opcode.OP_CHECKSIG]));
    expect(executeScript(script, ctx)).toBe(true);
    expect(ctx.stack.length).toBe(1);
    expect(ctx.stack[0].length).toBe(0); // false result, but not rejected
  });
});

describe("SCRIPT_VERIFY_NULLFAIL - OP_CHECKSIGVERIFY", () => {
  const privateKey = Buffer.from(
    "0000000000000000000000000000000000000000000000000000000000000001",
    "hex"
  );
  const publicKey = privateKeyToPublicKey(privateKey, true);
  const correctHash = Buffer.alloc(32, 0x42);
  const wrongHash = Buffer.alloc(32, 0x99);

  test("NULLFAIL: non-empty failing signature is rejected", () => {
    const badSig = Buffer.concat([ecdsaSign(wrongHash, privateKey), Buffer.from([0x01])]);
    const sigHasher = (_subscript: Buffer, _ht: number) => correctHash;

    const ctx: ExecutionContext = {
      stack: [badSig, publicKey],
      altStack: [],
      flags: flagsWithNullFail(),
      sigHasher,
      sigVersion: SigVersion.BASE,
    };

    const script = parseScript(Buffer.from([Opcode.OP_CHECKSIGVERIFY]));
    expect(executeScript(script, ctx)).toBe(false);
  });

  test("NULLFAIL: valid signature succeeds", () => {
    const validSig = Buffer.concat([ecdsaSign(correctHash, privateKey), Buffer.from([0x01])]);
    const sigHasher = (_subscript: Buffer, _ht: number) => correctHash;

    const ctx: ExecutionContext = {
      stack: [validSig, publicKey],
      altStack: [],
      flags: flagsWithNullFail(),
      sigHasher,
      sigVersion: SigVersion.BASE,
    };

    const script = parseScript(Buffer.from([Opcode.OP_CHECKSIGVERIFY]));
    expect(executeScript(script, ctx)).toBe(true);
    expect(ctx.stack.length).toBe(0);
  });
});

describe("SCRIPT_VERIFY_NULLFAIL - OP_CHECKMULTISIG", () => {
  const privateKeys = [
    Buffer.from("0000000000000000000000000000000000000000000000000000000000000001", "hex"),
    Buffer.from("0000000000000000000000000000000000000000000000000000000000000002", "hex"),
    Buffer.from("0000000000000000000000000000000000000000000000000000000000000003", "hex"),
  ];
  const publicKeys = privateKeys.map((k) => privateKeyToPublicKey(k, true));
  const correctHash = Buffer.alloc(32, 0x42);
  const wrongHash = Buffer.alloc(32, 0x99);

  test("NULLFAIL: non-empty failing signatures rejected in 2-of-3 multisig", () => {
    // Sign with wrong hash so verification will fail
    const badSig1 = Buffer.concat([ecdsaSign(wrongHash, privateKeys[0]), Buffer.from([0x01])]);
    const badSig2 = Buffer.concat([ecdsaSign(wrongHash, privateKeys[1]), Buffer.from([0x01])]);
    const sigHasher = (_subscript: Buffer, _ht: number) => correctHash;

    const ctx: ExecutionContext = {
      stack: [
        Buffer.alloc(0), // dummy
        badSig1,
        badSig2,
        scriptNumEncode(2), // nSigs
        publicKeys[0],
        publicKeys[1],
        publicKeys[2],
        scriptNumEncode(3), // nKeys
      ],
      altStack: [],
      flags: flagsWithNullFail(),
      sigHasher,
      sigVersion: SigVersion.BASE,
    };

    const script = parseScript(Buffer.from([Opcode.OP_CHECKMULTISIG]));
    expect(executeScript(script, ctx)).toBe(false);
  });

  test("NULLFAIL: all empty signatures allowed when operation fails", () => {
    // Empty signatures - operation will fail but NULLFAIL won't trigger
    const emptySig = Buffer.alloc(0);
    const sigHasher = (_subscript: Buffer, _ht: number) => correctHash;

    const ctx: ExecutionContext = {
      stack: [
        Buffer.alloc(0), // dummy
        emptySig,
        emptySig,
        scriptNumEncode(2), // nSigs
        publicKeys[0],
        publicKeys[1],
        publicKeys[2],
        scriptNumEncode(3), // nKeys
      ],
      altStack: [],
      flags: flagsWithNullFail(),
      sigHasher,
      sigVersion: SigVersion.BASE,
    };

    const script = parseScript(Buffer.from([Opcode.OP_CHECKMULTISIG]));
    // Operation succeeds (returns false on stack) because empty sigs are valid for NULLFAIL
    expect(executeScript(script, ctx)).toBe(true);
    expect(ctx.stack.length).toBe(1);
    expect(ctx.stack[0].length).toBe(0); // false result
  });

  test("NULLFAIL: valid signatures succeed", () => {
    const validSig1 = Buffer.concat([ecdsaSign(correctHash, privateKeys[0]), Buffer.from([0x01])]);
    const validSig2 = Buffer.concat([ecdsaSign(correctHash, privateKeys[1]), Buffer.from([0x01])]);
    const sigHasher = (_subscript: Buffer, _ht: number) => correctHash;

    const ctx: ExecutionContext = {
      stack: [
        Buffer.alloc(0), // dummy
        validSig1,
        validSig2,
        scriptNumEncode(2), // nSigs
        publicKeys[0],
        publicKeys[1],
        publicKeys[2],
        scriptNumEncode(3), // nKeys
      ],
      altStack: [],
      flags: flagsWithNullFail(),
      sigHasher,
      sigVersion: SigVersion.BASE,
    };

    const script = parseScript(Buffer.from([Opcode.OP_CHECKMULTISIG]));
    expect(executeScript(script, ctx)).toBe(true);
    expect(ctx.stack.length).toBe(1);
    expect(ctx.stack[0][0]).toBe(1); // true result
  });

  test("without NULLFAIL: non-empty failing signatures return false (not rejected)", () => {
    const badSig1 = Buffer.concat([ecdsaSign(wrongHash, privateKeys[0]), Buffer.from([0x01])]);
    const badSig2 = Buffer.concat([ecdsaSign(wrongHash, privateKeys[1]), Buffer.from([0x01])]);
    const sigHasher = (_subscript: Buffer, _ht: number) => correctHash;

    const ctx: ExecutionContext = {
      stack: [
        Buffer.alloc(0), // dummy
        badSig1,
        badSig2,
        scriptNumEncode(2), // nSigs
        publicKeys[0],
        publicKeys[1],
        publicKeys[2],
        scriptNumEncode(3), // nKeys
      ],
      altStack: [],
      flags: flagsWithoutNullFail(),
      sigHasher,
      sigVersion: SigVersion.BASE,
    };

    const script = parseScript(Buffer.from([Opcode.OP_CHECKMULTISIG]));
    expect(executeScript(script, ctx)).toBe(true);
    expect(ctx.stack.length).toBe(1);
    expect(ctx.stack[0].length).toBe(0); // false result, but not rejected
  });

  test("NULLFAIL: mixed empty and non-empty failing sigs rejected", () => {
    // One empty sig, one bad sig - should still fail NULLFAIL
    const emptySig = Buffer.alloc(0);
    const badSig = Buffer.concat([ecdsaSign(wrongHash, privateKeys[1]), Buffer.from([0x01])]);
    const sigHasher = (_subscript: Buffer, _ht: number) => correctHash;

    const ctx: ExecutionContext = {
      stack: [
        Buffer.alloc(0), // dummy
        emptySig,
        badSig,
        scriptNumEncode(2), // nSigs
        publicKeys[0],
        publicKeys[1],
        publicKeys[2],
        scriptNumEncode(3), // nKeys
      ],
      altStack: [],
      flags: flagsWithNullFail(),
      sigHasher,
      sigVersion: SigVersion.BASE,
    };

    const script = parseScript(Buffer.from([Opcode.OP_CHECKMULTISIG]));
    expect(executeScript(script, ctx)).toBe(false);
  });
});

describe("SCRIPT_VERIFY_NULLFAIL - getConsensusFlags", () => {
  test("NULLFAIL disabled before segwit activation (height 481823)", () => {
    const flags = getConsensusFlags(481823);
    expect(flags.verifyNullFail).toBe(false);
  });

  test("NULLFAIL enabled at segwit activation (height 481824)", () => {
    const flags = getConsensusFlags(481824);
    expect(flags.verifyNullFail).toBe(true);
  });

  test("NULLFAIL enabled after segwit activation (height 500000)", () => {
    const flags = getConsensusFlags(500000);
    expect(flags.verifyNullFail).toBe(true);
  });

  test("NULLFAIL disabled at genesis (height 0)", () => {
    const flags = getConsensusFlags(0);
    expect(flags.verifyNullFail).toBe(false);
  });
});
