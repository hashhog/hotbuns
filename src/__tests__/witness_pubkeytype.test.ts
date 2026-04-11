/**
 * Tests for SCRIPT_VERIFY_WITNESS_PUBKEYTYPE (BIP 141).
 *
 * When WITNESS_PUBKEYTYPE is active in witness v0 scripts:
 * - Public keys must be compressed (33 bytes, starting with 0x02 or 0x03)
 * - Uncompressed keys (65 bytes, starting with 0x04) are rejected
 */

import { describe, expect, test } from "bun:test";
import {
  Opcode,
  parseScript,
  executeScript,
  scriptNumEncode,
  getConsensusFlags,
  ScriptError,
  type ScriptFlags,
  type ExecutionContext,
  SigVersion,
} from "../script/interpreter.js";
import { ecdsaSign, privateKeyToPublicKey } from "../crypto/primitives.js";

// Helper to create flags with WITNESS_PUBKEYTYPE enabled
function flagsWithWitnessPubkeyType(): ScriptFlags {
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

// Helper to create flags with WITNESS_PUBKEYTYPE disabled
function flagsWithoutWitnessPubkeyType(): ScriptFlags {
  return {
    ...flagsWithWitnessPubkeyType(),
    verifyWitnessPubkeyType: false,
  };
}

describe("SCRIPT_VERIFY_WITNESS_PUBKEYTYPE - OP_CHECKSIG", () => {
  const privateKey = Buffer.from(
    "0000000000000000000000000000000000000000000000000000000000000001",
    "hex"
  );
  const compressedPubkey = privateKeyToPublicKey(privateKey, true);
  const uncompressedPubkey = privateKeyToPublicKey(privateKey, false);
  const correctHash = Buffer.alloc(32, 0x42);

  test("WITNESS_PUBKEYTYPE: compressed pubkey succeeds in witness v0", () => {
    const validSig = Buffer.concat([ecdsaSign(correctHash, privateKey), Buffer.from([0x01])]);
    const sigHasher = (_subscript: Buffer, _ht: number) => correctHash;

    const ctx: ExecutionContext = {
      stack: [validSig, compressedPubkey],
      altStack: [],
      flags: flagsWithWitnessPubkeyType(),
      sigHasher,
      sigVersion: SigVersion.WITNESS_V0,
    };

    const script = parseScript(Buffer.from([Opcode.OP_CHECKSIG]));
    expect(executeScript(script, ctx)).toBe(true);
    expect(ctx.stack.length).toBe(1);
    expect(ctx.stack[0][0]).toBe(1); // true result
  });

  test("WITNESS_PUBKEYTYPE: uncompressed pubkey rejected in witness v0", () => {
    const validSig = Buffer.concat([ecdsaSign(correctHash, privateKey), Buffer.from([0x01])]);
    const sigHasher = (_subscript: Buffer, _ht: number) => correctHash;

    const ctx: ExecutionContext = {
      stack: [validSig, uncompressedPubkey],
      altStack: [],
      flags: flagsWithWitnessPubkeyType(),
      sigHasher,
      sigVersion: SigVersion.WITNESS_V0,
    };

    // executeScript throws ScriptError for WITNESS_PUBKEYTYPE violations (like Bitcoin Core)
    const script = parseScript(Buffer.from([Opcode.OP_CHECKSIG]));
    expect(() => executeScript(script, ctx)).toThrow(ScriptError);
  });

  test("WITNESS_PUBKEYTYPE: uncompressed pubkey allowed in legacy scripts", () => {
    const validSig = Buffer.concat([ecdsaSign(correctHash, privateKey), Buffer.from([0x01])]);
    const sigHasher = (_subscript: Buffer, _ht: number) => correctHash;

    const ctx: ExecutionContext = {
      stack: [validSig, uncompressedPubkey],
      altStack: [],
      flags: flagsWithWitnessPubkeyType(),
      sigHasher,
      sigVersion: SigVersion.BASE,
    };

    const script = parseScript(Buffer.from([Opcode.OP_CHECKSIG]));
    expect(executeScript(script, ctx)).toBe(true);
    expect(ctx.stack.length).toBe(1);
    expect(ctx.stack[0][0]).toBe(1); // true result
  });

  test("without WITNESS_PUBKEYTYPE: uncompressed pubkey allowed in witness v0", () => {
    const validSig = Buffer.concat([ecdsaSign(correctHash, privateKey), Buffer.from([0x01])]);
    const sigHasher = (_subscript: Buffer, _ht: number) => correctHash;

    const ctx: ExecutionContext = {
      stack: [validSig, uncompressedPubkey],
      altStack: [],
      flags: flagsWithoutWitnessPubkeyType(),
      sigHasher,
      sigVersion: SigVersion.WITNESS_V0,
    };

    const script = parseScript(Buffer.from([Opcode.OP_CHECKSIG]));
    expect(executeScript(script, ctx)).toBe(true);
    expect(ctx.stack.length).toBe(1);
    expect(ctx.stack[0][0]).toBe(1); // true result
  });

  test("WITNESS_PUBKEYTYPE: invalid pubkey format (wrong length) rejected", () => {
    const validSig = Buffer.concat([ecdsaSign(correctHash, privateKey), Buffer.from([0x01])]);
    const sigHasher = (_subscript: Buffer, _ht: number) => correctHash;

    // Invalid: 32 bytes with 0x02 prefix
    const invalidPubkey = Buffer.alloc(32, 0x02);

    const ctx: ExecutionContext = {
      stack: [validSig, invalidPubkey],
      altStack: [],
      flags: flagsWithWitnessPubkeyType(),
      sigHasher,
      sigVersion: SigVersion.WITNESS_V0,
    };

    // executeScript throws ScriptError for WITNESS_PUBKEYTYPE violations (like Bitcoin Core)
    const script = parseScript(Buffer.from([Opcode.OP_CHECKSIG]));
    expect(() => executeScript(script, ctx)).toThrow(ScriptError);
  });

  test("WITNESS_PUBKEYTYPE: invalid pubkey format (wrong prefix) rejected", () => {
    const validSig = Buffer.concat([ecdsaSign(correctHash, privateKey), Buffer.from([0x01])]);
    const sigHasher = (_subscript: Buffer, _ht: number) => correctHash;

    // Invalid: 33 bytes but starts with 0x04 (not 0x02 or 0x03)
    const invalidPubkey = Buffer.alloc(33, 0x04);

    const ctx: ExecutionContext = {
      stack: [validSig, invalidPubkey],
      altStack: [],
      flags: flagsWithWitnessPubkeyType(),
      sigHasher,
      sigVersion: SigVersion.WITNESS_V0,
    };

    // executeScript throws ScriptError for WITNESS_PUBKEYTYPE violations (like Bitcoin Core)
    const script = parseScript(Buffer.from([Opcode.OP_CHECKSIG]));
    expect(() => executeScript(script, ctx)).toThrow(ScriptError);
  });
});

describe("SCRIPT_VERIFY_WITNESS_PUBKEYTYPE - OP_CHECKSIGVERIFY", () => {
  const privateKey = Buffer.from(
    "0000000000000000000000000000000000000000000000000000000000000001",
    "hex"
  );
  const compressedPubkey = privateKeyToPublicKey(privateKey, true);
  const uncompressedPubkey = privateKeyToPublicKey(privateKey, false);
  const correctHash = Buffer.alloc(32, 0x42);

  test("WITNESS_PUBKEYTYPE: compressed pubkey succeeds in CHECKSIGVERIFY", () => {
    const validSig = Buffer.concat([ecdsaSign(correctHash, privateKey), Buffer.from([0x01])]);
    const sigHasher = (_subscript: Buffer, _ht: number) => correctHash;

    const ctx: ExecutionContext = {
      stack: [validSig, compressedPubkey],
      altStack: [],
      flags: flagsWithWitnessPubkeyType(),
      sigHasher,
      sigVersion: SigVersion.WITNESS_V0,
    };

    const script = parseScript(Buffer.from([Opcode.OP_CHECKSIGVERIFY]));
    expect(executeScript(script, ctx)).toBe(true);
    expect(ctx.stack.length).toBe(0);
  });

  test("WITNESS_PUBKEYTYPE: uncompressed pubkey rejected in CHECKSIGVERIFY", () => {
    const validSig = Buffer.concat([ecdsaSign(correctHash, privateKey), Buffer.from([0x01])]);
    const sigHasher = (_subscript: Buffer, _ht: number) => correctHash;

    const ctx: ExecutionContext = {
      stack: [validSig, uncompressedPubkey],
      altStack: [],
      flags: flagsWithWitnessPubkeyType(),
      sigHasher,
      sigVersion: SigVersion.WITNESS_V0,
    };

    // executeScript throws ScriptError for WITNESS_PUBKEYTYPE violations (like Bitcoin Core)
    const script = parseScript(Buffer.from([Opcode.OP_CHECKSIGVERIFY]));
    expect(() => executeScript(script, ctx)).toThrow(ScriptError);
  });
});

describe("SCRIPT_VERIFY_WITNESS_PUBKEYTYPE - OP_CHECKMULTISIG", () => {
  const privateKeys = [
    Buffer.from("0000000000000000000000000000000000000000000000000000000000000001", "hex"),
    Buffer.from("0000000000000000000000000000000000000000000000000000000000000002", "hex"),
    Buffer.from("0000000000000000000000000000000000000000000000000000000000000003", "hex"),
  ];
  const compressedPubkeys = privateKeys.map((k) => privateKeyToPublicKey(k, true));
  const uncompressedPubkeys = privateKeys.map((k) => privateKeyToPublicKey(k, false));
  const correctHash = Buffer.alloc(32, 0x42);

  test("WITNESS_PUBKEYTYPE: compressed pubkeys succeed in 2-of-3 multisig", () => {
    const validSig1 = Buffer.concat([ecdsaSign(correctHash, privateKeys[0]), Buffer.from([0x01])]);
    const validSig2 = Buffer.concat([ecdsaSign(correctHash, privateKeys[1]), Buffer.from([0x01])]);
    const sigHasher = (_subscript: Buffer, _ht: number) => correctHash;

    const ctx: ExecutionContext = {
      stack: [
        Buffer.alloc(0), // dummy
        validSig1,
        validSig2,
        scriptNumEncode(2), // nSigs
        compressedPubkeys[0],
        compressedPubkeys[1],
        compressedPubkeys[2],
        scriptNumEncode(3), // nKeys
      ],
      altStack: [],
      flags: flagsWithWitnessPubkeyType(),
      sigHasher,
      sigVersion: SigVersion.WITNESS_V0,
    };

    const script = parseScript(Buffer.from([Opcode.OP_CHECKMULTISIG]));
    expect(executeScript(script, ctx)).toBe(true);
    expect(ctx.stack.length).toBe(1);
    expect(ctx.stack[0][0]).toBe(1); // true result
  });

  test("WITNESS_PUBKEYTYPE: uncompressed pubkeys rejected in 2-of-3 multisig", () => {
    const validSig1 = Buffer.concat([ecdsaSign(correctHash, privateKeys[0]), Buffer.from([0x01])]);
    const validSig2 = Buffer.concat([ecdsaSign(correctHash, privateKeys[1]), Buffer.from([0x01])]);
    const sigHasher = (_subscript: Buffer, _ht: number) => correctHash;

    const ctx: ExecutionContext = {
      stack: [
        Buffer.alloc(0), // dummy
        validSig1,
        validSig2,
        scriptNumEncode(2), // nSigs
        uncompressedPubkeys[0],
        uncompressedPubkeys[1],
        uncompressedPubkeys[2],
        scriptNumEncode(3), // nKeys
      ],
      altStack: [],
      flags: flagsWithWitnessPubkeyType(),
      sigHasher,
      sigVersion: SigVersion.WITNESS_V0,
    };

    // executeScript throws ScriptError for WITNESS_PUBKEYTYPE violations (like Bitcoin Core)
    const script = parseScript(Buffer.from([Opcode.OP_CHECKMULTISIG]));
    expect(() => executeScript(script, ctx)).toThrow(ScriptError);
  });

  test("WITNESS_PUBKEYTYPE: mixed compressed/uncompressed rejected (first key uncompressed)", () => {
    const validSig1 = Buffer.concat([ecdsaSign(correctHash, privateKeys[0]), Buffer.from([0x01])]);
    const validSig2 = Buffer.concat([ecdsaSign(correctHash, privateKeys[1]), Buffer.from([0x01])]);
    const sigHasher = (_subscript: Buffer, _ht: number) => correctHash;

    const ctx: ExecutionContext = {
      stack: [
        Buffer.alloc(0), // dummy
        validSig1,
        validSig2,
        scriptNumEncode(2), // nSigs
        uncompressedPubkeys[0], // First key uncompressed - should fail
        compressedPubkeys[1],
        compressedPubkeys[2],
        scriptNumEncode(3), // nKeys
      ],
      altStack: [],
      flags: flagsWithWitnessPubkeyType(),
      sigHasher,
      sigVersion: SigVersion.WITNESS_V0,
    };

    // executeScript throws ScriptError for WITNESS_PUBKEYTYPE violations (like Bitcoin Core)
    const script = parseScript(Buffer.from([Opcode.OP_CHECKMULTISIG]));
    expect(() => executeScript(script, ctx)).toThrow(ScriptError);
  });

  test("WITNESS_PUBKEYTYPE: mixed compressed/uncompressed rejected (last key uncompressed)", () => {
    const validSig1 = Buffer.concat([ecdsaSign(correctHash, privateKeys[0]), Buffer.from([0x01])]);
    const validSig2 = Buffer.concat([ecdsaSign(correctHash, privateKeys[1]), Buffer.from([0x01])]);
    const sigHasher = (_subscript: Buffer, _ht: number) => correctHash;

    const ctx: ExecutionContext = {
      stack: [
        Buffer.alloc(0), // dummy
        validSig1,
        validSig2,
        scriptNumEncode(2), // nSigs
        compressedPubkeys[0],
        compressedPubkeys[1],
        uncompressedPubkeys[2], // Last key uncompressed - should fail
        scriptNumEncode(3), // nKeys
      ],
      altStack: [],
      flags: flagsWithWitnessPubkeyType(),
      sigHasher,
      sigVersion: SigVersion.WITNESS_V0,
    };

    // executeScript throws ScriptError for WITNESS_PUBKEYTYPE violations (like Bitcoin Core)
    const script = parseScript(Buffer.from([Opcode.OP_CHECKMULTISIG]));
    expect(() => executeScript(script, ctx)).toThrow(ScriptError);
  });

  test("WITNESS_PUBKEYTYPE: uncompressed pubkeys allowed in legacy multisig", () => {
    const validSig1 = Buffer.concat([ecdsaSign(correctHash, privateKeys[0]), Buffer.from([0x01])]);
    const validSig2 = Buffer.concat([ecdsaSign(correctHash, privateKeys[1]), Buffer.from([0x01])]);
    const sigHasher = (_subscript: Buffer, _ht: number) => correctHash;

    const ctx: ExecutionContext = {
      stack: [
        Buffer.alloc(0), // dummy
        validSig1,
        validSig2,
        scriptNumEncode(2), // nSigs
        uncompressedPubkeys[0],
        uncompressedPubkeys[1],
        uncompressedPubkeys[2],
        scriptNumEncode(3), // nKeys
      ],
      altStack: [],
      flags: flagsWithWitnessPubkeyType(),
      sigHasher,
      sigVersion: SigVersion.BASE,
    };

    const script = parseScript(Buffer.from([Opcode.OP_CHECKMULTISIG]));
    expect(executeScript(script, ctx)).toBe(true);
    expect(ctx.stack.length).toBe(1);
    expect(ctx.stack[0][0]).toBe(1); // true result
  });

  test("without WITNESS_PUBKEYTYPE: uncompressed pubkeys allowed in witness v0 multisig", () => {
    const validSig1 = Buffer.concat([ecdsaSign(correctHash, privateKeys[0]), Buffer.from([0x01])]);
    const validSig2 = Buffer.concat([ecdsaSign(correctHash, privateKeys[1]), Buffer.from([0x01])]);
    const sigHasher = (_subscript: Buffer, _ht: number) => correctHash;

    const ctx: ExecutionContext = {
      stack: [
        Buffer.alloc(0), // dummy
        validSig1,
        validSig2,
        scriptNumEncode(2), // nSigs
        uncompressedPubkeys[0],
        uncompressedPubkeys[1],
        uncompressedPubkeys[2],
        scriptNumEncode(3), // nKeys
      ],
      altStack: [],
      flags: flagsWithoutWitnessPubkeyType(),
      sigHasher,
      sigVersion: SigVersion.WITNESS_V0,
    };

    const script = parseScript(Buffer.from([Opcode.OP_CHECKMULTISIG]));
    expect(executeScript(script, ctx)).toBe(true);
    expect(ctx.stack.length).toBe(1);
    expect(ctx.stack[0][0]).toBe(1); // true result
  });
});

describe("SCRIPT_VERIFY_WITNESS_PUBKEYTYPE - getConsensusFlags", () => {
  test("WITNESS_PUBKEYTYPE disabled before segwit activation (height 481823)", () => {
    const flags = getConsensusFlags(481823);
    expect(flags.verifyWitnessPubkeyType).toBe(false);
  });

  test("WITNESS_PUBKEYTYPE enabled at segwit activation (height 481824)", () => {
    const flags = getConsensusFlags(481824);
    expect(flags.verifyWitnessPubkeyType).toBe(true);
  });

  test("WITNESS_PUBKEYTYPE enabled after segwit activation (height 500000)", () => {
    const flags = getConsensusFlags(500000);
    expect(flags.verifyWitnessPubkeyType).toBe(true);
  });

  test("WITNESS_PUBKEYTYPE disabled at genesis (height 0)", () => {
    const flags = getConsensusFlags(0);
    expect(flags.verifyWitnessPubkeyType).toBe(false);
  });
});

// NOTE: Integration tests for verifyScript with P2WPKH/P2WSH are not included here
// because verifyWitnessV0 has a pre-existing bug with witness stack ordering.
// The unit tests above thoroughly test WITNESS_PUBKEYTYPE at the executeScript level.
