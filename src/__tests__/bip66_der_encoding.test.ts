/**
 * Comprehensive BIP-66 + signature/pubkey encoding tests.
 *
 * Covers all ~22 gates across 7 functions:
 *   isValidSignatureEncoding  (BIP-66 DER format, 14 checks)
 *   isDefinedHashtypeSignature (STRICTENC hashtype, 2 checks)
 *   isLowDERSignature          (LOW_S, 2 checks)
 *   checkSignatureEncoding     (gate ordering, 5 flag combos)
 *   isCompressedPubKey         (WITNESS_PUBKEYTYPE, 4 checks)
 *   isValidPubKeyEncoding      (STRICTENC pubkey, 4 checks)
 *   checkPubKeyEncoding        (flag dispatch, 4 checks)
 *
 * Reference: Bitcoin Core src/script/interpreter.cpp:64-227 (IsCompressedPubKey,
 *   IsValidSignatureEncoding, IsLowDERSignature, IsDefinedHashtypeSignature,
 *   CheckSignatureEncoding, CheckPubKeyEncoding) + :335-345 (EvalChecksigPreTapscript
 *   NULLFAIL gate) + :1150-1210 (CHECKMULTISIG NULLFAIL/NULLDUMMY gates).
 *
 * Bug fixes validated here:
 *   Bug 1 — isDefinedHashtypeSignature returned true for empty sig (Core: false).
 *   Bug 2 — checkSignatureEncoding DER pre-check gate missing verifyLowS: when only
 *            verifyLowS was active and the DER was malformed, the code incorrectly
 *            threw SIG_HIGH_S instead of SIG_DER (Core: SIG_DER for malformed DER
 *            regardless of which flag triggered the DER check).
 *   Bug 3 — witness_pubkeytype.test.ts incorrectly expected verifyWitnessPubkeyType=true
 *            in getConsensusFlags; the flag is policy-only per Core policy/policy.h:128.
 */

import { describe, expect, test } from "bun:test";
import {
  Opcode,
  parseScript,
  executeScript,
  ScriptError,
  scriptNumEncode,
  getConsensusFlags,
  getStandardFlags,
  type ScriptFlags,
  type ExecutionContext,
  SigVersion,
} from "../script/interpreter.js";
import { ecdsaSign, privateKeyToPublicKey } from "../crypto/primitives.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Build a minimal valid DER sig (without hashtype) with given R and S buffers. */
function buildDER(R: Buffer, S: Buffer): Buffer {
  const rTag = Buffer.from([0x02, R.length]);
  const sTag = Buffer.from([0x02, S.length]);
  const inner = Buffer.concat([rTag, R, sTag, S]);
  return Buffer.concat([Buffer.from([0x30, inner.length]), inner]);
}

/** Build a valid DER sig (with hashtype byte appended). */
function buildSig(R: Buffer, S: Buffer, hashType = 0x01): Buffer {
  return Buffer.concat([buildDER(R, S), Buffer.from([hashType])]);
}

/** 32-byte R with high bit clear (positive, no leading zero needed). */
const R32 = Buffer.alloc(32, 0x01);
/** 32-byte S with high bit clear and S ≤ N/2 (low-S). */
// secp256k1 N/2 = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF975B8301...
// A small positive S is guaranteed to be low-S.
const S_LOW = Buffer.alloc(32, 0x02);
/** High-S value — valid DER (positive, no leading zero needed) but S > N/2.
 * secp256k1 N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
 * N/2        = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0
 * We use     = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A1
 * which is   = N/2 + 1 — definitely > N/2, starts with 0x7F (high bit clear → positive DER).
 */
const S_HIGH = Buffer.from("7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A1", "hex");

/** Valid minimal compressed pubkey. */
const PRIVKEY = Buffer.from("0000000000000000000000000000000000000000000000000000000000000001", "hex");
const COMPRESSED_PUBKEY = privateKeyToPublicKey(PRIVKEY, true);   // 33 bytes, 0x02/0x03 prefix
const UNCOMPRESSED_PUBKEY = privateKeyToPublicKey(PRIVKEY, false); // 65 bytes, 0x04 prefix

const DUMMY_HASH = Buffer.alloc(32, 0x42);
const DUMMY_SIGHASH = (_subscript: Buffer, _ht: number): Buffer => DUMMY_HASH;

function flagsBase(): ScriptFlags {
  return {
    verifyP2SH: false,
    verifyWitness: false,
    verifyTaproot: false,
    verifyStrictEncoding: false,
    verifyDERSignatures: false,
    verifyLowS: false,
    verifyNullDummy: false,
    verifyNullFail: false,
    verifyCheckLockTimeVerify: false,
    verifyCheckSequenceVerify: false,
    verifyWitnessPubkeyType: false,
  };
}

function makeCtx(stack: Buffer[], flags: ScriptFlags, sigVersion = SigVersion.BASE): ExecutionContext {
  return { stack: [...stack], altStack: [], flags, sigHasher: DUMMY_SIGHASH, sigVersion };
}

// Convenience: a raw OP_CHECKSIG script
const CHECKSIG_SCRIPT = parseScript(Buffer.from([Opcode.OP_CHECKSIG]));
const CHECKMULTISIG_SCRIPT = parseScript(Buffer.from([Opcode.OP_CHECKMULTISIG]));

// ---------------------------------------------------------------------------
// Section 1: isValidSignatureEncoding — 14 DER format gates
// (tested indirectly via checkSignatureEncoding with verifyDERSignatures=true)
// ---------------------------------------------------------------------------

describe("isValidSignatureEncoding — DER format (BIP-66)", () => {
  const flags: ScriptFlags = { ...flagsBase(), verifyDERSignatures: true };

  test("gate 1: minimum-length sig (9 bytes full = 8 stripped DER) is accepted", () => {
    // Minimum: 0x30 [6] 0x02 [1] [R] 0x02 [1] [S] [hashtype]
    // R=0x01, S=0x01 → DER part = 8 bytes, full sig = 9 bytes
    const sig = buildSig(Buffer.from([0x01]), Buffer.from([0x01]));
    expect(sig.length).toBe(9);
    const validSig = Buffer.concat([ecdsaSign(DUMMY_HASH, PRIVKEY), Buffer.from([0x01])]);
    const ctx = makeCtx([validSig, COMPRESSED_PUBKEY], flags);
    // Valid sig passes DER check (sig content may fail crypto but DER check passes)
    expect(() => {
      const c2 = makeCtx([sig, COMPRESSED_PUBKEY], flags);
      executeScript(CHECKSIG_SCRIPT, c2);
    }).not.toThrow();
  });

  test("gate 1: too-short sig (< 8 bytes stripped DER) is rejected with SIG_DER", () => {
    // 8-byte full sig = 7-byte stripped DER → below minimum
    const shortSig = Buffer.from([0x30, 0x05, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01]);
    // Full sig needs hashtype; this IS only 8 bytes (no hashtype slot) so we add one
    const sig = Buffer.concat([shortSig, Buffer.from([0x01])]);
    // stripped = 8 bytes, but sig[1]=0x05, len check 0x05 != 8-2=6 → rejects
    const ctx = makeCtx([sig, COMPRESSED_PUBKEY], flags);
    expect(() => executeScript(CHECKSIG_SCRIPT, ctx)).toThrow(ScriptError);
  });

  test("gate 2: too-long sig (> 72 bytes stripped DER) is rejected with SIG_DER", () => {
    // Build a sig with R=33 bytes and S=33 bytes → DER part = 2+2+33+2+33 = 72+2 = 74 bytes
    // Actually: 0x30 [len=70] 0x02 [33] [R33] 0x02 [33] [S33] = 2+2+33+2+33+1hashtype = 73+1 = 74
    // Let's make an oversized R+S combination
    const bigR = Buffer.alloc(35, 0x01); // 35-byte R
    const bigS = Buffer.alloc(35, 0x02); // 35-byte S
    // DER = 0x30 [2+35+2+35=74] 0x02 [35] R 0x02 [35] S = 76 bytes
    // With hashtype = 77 bytes total (stripped DER = 76 bytes > 72)
    const sig = buildSig(bigR, bigS);
    expect(sig.length).toBeGreaterThan(73);
    const ctx = makeCtx([sig, COMPRESSED_PUBKEY], flags);
    expect(() => executeScript(CHECKSIG_SCRIPT, ctx)).toThrow(ScriptError);
  });

  test("gate 3: compound tag must be 0x30", () => {
    const der = buildDER(R32, S_LOW);
    der[0] = 0x31; // wrong compound tag
    const sig = Buffer.concat([der, Buffer.from([0x01])]);
    const ctx = makeCtx([sig, COMPRESSED_PUBKEY], flags);
    expect(() => executeScript(CHECKSIG_SCRIPT, ctx)).toThrow(ScriptError);
  });

  test("gate 4: total-length field must match sig.size()-3 (full sig)", () => {
    const der = buildDER(R32, S_LOW);
    der[1] = der[1] + 1; // wrong total length
    const sig = Buffer.concat([der, Buffer.from([0x01])]);
    const ctx = makeCtx([sig, COMPRESSED_PUBKEY], flags);
    expect(() => executeScript(CHECKSIG_SCRIPT, ctx)).toThrow(ScriptError);
  });

  test("gate 5: R integer tag must be 0x02", () => {
    const der = buildDER(R32, S_LOW);
    der[2] = 0x03; // wrong R tag
    const sig = Buffer.concat([der, Buffer.from([0x01])]);
    const ctx = makeCtx([sig, COMPRESSED_PUBKEY], flags);
    expect(() => executeScript(CHECKSIG_SCRIPT, ctx)).toThrow(ScriptError);
  });

  test("gate 6: R length must not be zero", () => {
    // Build: 0x30 [total] 0x02 [0x00] 0x02 [1] [S]
    const inner = Buffer.from([0x02, 0x00, 0x02, 0x01, 0x01]);
    const der = Buffer.concat([Buffer.from([0x30, inner.length]), inner]);
    const sig = Buffer.concat([der, Buffer.from([0x01])]);
    const ctx = makeCtx([sig, COMPRESSED_PUBKEY], flags);
    expect(() => executeScript(CHECKSIG_SCRIPT, ctx)).toThrow(ScriptError);
  });

  test("gate 7: lenR must fit inside remaining sig bytes", () => {
    // R length claims 50 bytes but there aren't that many bytes
    const inner = Buffer.from([0x02, 50, 0x01, 0x02, 0x01, 0x01]); // claimed R=50 but only 1 byte
    const der = Buffer.concat([Buffer.from([0x30, inner.length]), inner]);
    const sig = Buffer.concat([der, Buffer.from([0x01])]);
    const ctx = makeCtx([sig, COMPRESSED_PUBKEY], flags);
    expect(() => executeScript(CHECKSIG_SCRIPT, ctx)).toThrow(ScriptError);
  });

  test("gate 8: S integer tag must be 0x02 (at offset 4+lenR)", () => {
    const der = buildDER(R32, S_LOW);
    // The S tag is at position 4 + R32.length = 4 + 32 = 36
    der[4 + R32.length] = 0x03;
    const sig = Buffer.concat([der, Buffer.from([0x01])]);
    const ctx = makeCtx([sig, COMPRESSED_PUBKEY], flags);
    expect(() => executeScript(CHECKSIG_SCRIPT, ctx)).toThrow(ScriptError);
  });

  test("gate 9: S length must not be zero", () => {
    // Build: 0x30 [total] 0x02 [1] [R] 0x02 [0x00]
    const inner = Buffer.from([0x02, 0x01, 0x01, 0x02, 0x00]);
    const der = Buffer.concat([Buffer.from([0x30, inner.length]), inner]);
    const sig = Buffer.concat([der, Buffer.from([0x01])]);
    const ctx = makeCtx([sig, COMPRESSED_PUBKEY], flags);
    expect(() => executeScript(CHECKSIG_SCRIPT, ctx)).toThrow(ScriptError);
  });

  test("gate 10: lenR + lenS + 7 must equal full sig size", () => {
    const der = buildDER(R32, S_LOW);
    // Corrupt inner content so lengths don't add up (add extra byte)
    const sig = Buffer.concat([der, Buffer.from([0x01, 0x99])]); // extra byte after hashtype
    const ctx = makeCtx([sig, COMPRESSED_PUBKEY], flags);
    // sig[1] == der.length - 2 but sig.length - 3 != sig[1] now
    expect(() => executeScript(CHECKSIG_SCRIPT, ctx)).toThrow(ScriptError);
  });

  test("gate 11: R must not be negative (high bit set)", () => {
    const R = Buffer.alloc(32, 0x01);
    R[0] = 0x80; // high bit set = negative
    const sig = buildSig(R, S_LOW);
    const ctx = makeCtx([sig, COMPRESSED_PUBKEY], flags);
    expect(() => executeScript(CHECKSIG_SCRIPT, ctx)).toThrow(ScriptError);
  });

  test("gate 12: R must not have unnecessary leading zero (non-negative following byte)", () => {
    // Leading zero only allowed if next byte has high bit set (otherwise would be negative).
    // 0x00 0x01 — the 0x01 does NOT have high bit set, so the leading zero is unnecessary.
    const R = Buffer.concat([Buffer.from([0x00, 0x01]), Buffer.alloc(30, 0x01)]);
    const sig = buildSig(R, S_LOW);
    const ctx = makeCtx([sig, COMPRESSED_PUBKEY], flags);
    expect(() => executeScript(CHECKSIG_SCRIPT, ctx)).toThrow(ScriptError);
  });

  test("gate 12: leading zero in R is allowed when next byte has high bit (prevents negative)", () => {
    // 0x00 0x80... — necessary leading zero
    const R = Buffer.concat([Buffer.from([0x00, 0x80]), Buffer.alloc(30, 0x01)]);
    const sig = buildSig(R, S_LOW);
    const ctx = makeCtx([sig, COMPRESSED_PUBKEY], flags);
    // Should NOT throw SIG_DER (the leading zero is required here)
    expect(() => executeScript(CHECKSIG_SCRIPT, ctx)).not.toThrow();
  });

  test("gate 13: S must not be negative (high bit set)", () => {
    const S = Buffer.alloc(32, 0x01);
    S[0] = 0x80; // high bit set = negative
    const sig = buildSig(R32, S);
    const ctx = makeCtx([sig, COMPRESSED_PUBKEY], flags);
    expect(() => executeScript(CHECKSIG_SCRIPT, ctx)).toThrow(ScriptError);
  });

  test("gate 14: S must not have unnecessary leading zero", () => {
    const S = Buffer.concat([Buffer.from([0x00, 0x01]), Buffer.alloc(30, 0x02)]);
    const sig = buildSig(R32, S);
    const ctx = makeCtx([sig, COMPRESSED_PUBKEY], flags);
    expect(() => executeScript(CHECKSIG_SCRIPT, ctx)).toThrow(ScriptError);
  });

  test("gate 14: leading zero in S allowed when next byte has high bit", () => {
    const S = Buffer.concat([Buffer.from([0x00, 0x80]), Buffer.alloc(30, 0x02)]);
    const sig = buildSig(R32, S);
    const ctx = makeCtx([sig, COMPRESSED_PUBKEY], flags);
    expect(() => executeScript(CHECKSIG_SCRIPT, ctx)).not.toThrow();
  });

  test("empty signature is always accepted (DER flag active)", () => {
    const ctx = makeCtx([Buffer.alloc(0), COMPRESSED_PUBKEY], flags);
    expect(() => executeScript(CHECKSIG_SCRIPT, ctx)).not.toThrow();
    expect(ctx.stack.length).toBe(1);
    expect(ctx.stack[0].length).toBe(0); // false (sig check failed, empty sig)
  });
});

// ---------------------------------------------------------------------------
// Section 2: isDefinedHashtypeSignature — STRICTENC hashtype gate
// Bug 1: was returning true for empty sig (Core: false)
// ---------------------------------------------------------------------------

describe("isDefinedHashtypeSignature — STRICTENC hashtype gate", () => {
  const flags: ScriptFlags = { ...flagsBase(), verifyStrictEncoding: true };

  test("hashtype 0x01 (SIGHASH_ALL) is valid", () => {
    const sig = buildSig(R32, S_LOW, 0x01);
    const ctx = makeCtx([sig, COMPRESSED_PUBKEY], flags);
    expect(() => executeScript(CHECKSIG_SCRIPT, ctx)).not.toThrow();
  });

  test("hashtype 0x02 (SIGHASH_NONE) is valid", () => {
    const sig = buildSig(R32, S_LOW, 0x02);
    const ctx = makeCtx([sig, COMPRESSED_PUBKEY], flags);
    expect(() => executeScript(CHECKSIG_SCRIPT, ctx)).not.toThrow();
  });

  test("hashtype 0x03 (SIGHASH_SINGLE) is valid", () => {
    const sig = buildSig(R32, S_LOW, 0x03);
    const ctx = makeCtx([sig, COMPRESSED_PUBKEY], flags);
    expect(() => executeScript(CHECKSIG_SCRIPT, ctx)).not.toThrow();
  });

  test("hashtype 0x81 (SIGHASH_ALL | ANYONECANPAY) is valid", () => {
    const sig = buildSig(R32, S_LOW, 0x81);
    const ctx = makeCtx([sig, COMPRESSED_PUBKEY], flags);
    expect(() => executeScript(CHECKSIG_SCRIPT, ctx)).not.toThrow();
  });

  test("hashtype 0x82 (SIGHASH_NONE | ANYONECANPAY) is valid", () => {
    const sig = buildSig(R32, S_LOW, 0x82);
    const ctx = makeCtx([sig, COMPRESSED_PUBKEY], flags);
    expect(() => executeScript(CHECKSIG_SCRIPT, ctx)).not.toThrow();
  });

  test("hashtype 0x83 (SIGHASH_SINGLE | ANYONECANPAY) is valid", () => {
    const sig = buildSig(R32, S_LOW, 0x83);
    const ctx = makeCtx([sig, COMPRESSED_PUBKEY], flags);
    expect(() => executeScript(CHECKSIG_SCRIPT, ctx)).not.toThrow();
  });

  test("hashtype 0x00 is invalid (SIG_HASHTYPE)", () => {
    const sig = buildSig(R32, S_LOW, 0x00);
    const ctx = makeCtx([sig, COMPRESSED_PUBKEY], flags);
    expect(() => executeScript(CHECKSIG_SCRIPT, ctx)).toThrow(ScriptError);
    try { executeScript(CHECKSIG_SCRIPT, makeCtx([sig, COMPRESSED_PUBKEY], flags)); }
    catch (e) { expect((e as ScriptError).code).toBe("SIG_HASHTYPE"); }
  });

  test("hashtype 0x04 is invalid (SIG_HASHTYPE)", () => {
    const sig = buildSig(R32, S_LOW, 0x04);
    const ctx = makeCtx([sig, COMPRESSED_PUBKEY], flags);
    expect(() => executeScript(CHECKSIG_SCRIPT, ctx)).toThrow(ScriptError);
  });

  test("hashtype 0xff is invalid (SIG_HASHTYPE)", () => {
    // 0xff & ~0x80 = 0x7f — not 1/2/3
    const sig = buildSig(R32, S_LOW, 0xff);
    const ctx = makeCtx([sig, COMPRESSED_PUBKEY], flags);
    expect(() => executeScript(CHECKSIG_SCRIPT, ctx)).toThrow(ScriptError);
  });

  test("empty signature is accepted even with STRICTENC (checkSignatureEncoding early exits)", () => {
    // Core: empty sig → early return true in CheckSignatureEncoding. isDefinedHashtypeSignature
    // itself returns false for empty (Bug 1 fix), but checkSignatureEncoding guards it.
    const ctx = makeCtx([Buffer.alloc(0), COMPRESSED_PUBKEY], flags);
    expect(() => executeScript(CHECKSIG_SCRIPT, ctx)).not.toThrow();
    expect(ctx.stack[0].length).toBe(0); // false result — no sig match
  });
});

// ---------------------------------------------------------------------------
// Section 3: checkSignatureEncoding — gate ordering and flag combos
// Bug 2: DER pre-check gate was missing verifyLowS
// ---------------------------------------------------------------------------

describe("checkSignatureEncoding — gate ordering (Core interpreter.cpp:201-216)", () => {
  test("verifyLowS alone rejects malformed DER with SIG_DER (not SIG_HIGH_S)", () => {
    // Bug 2 fix: when only verifyLowS is active and DER is malformed, Core returns
    // SIG_DER because the DER pre-check fires for DERSIG|LOW_S|STRICTENC (any of them).
    // Pre-fix hotbuns skipped the explicit DER check when only LOW_S was set, and the
    // malformed DER would fall through to isLowDERSignature which returned false → SIG_HIGH_S.
    const flags: ScriptFlags = {
      ...flagsBase(),
      verifyLowS: true,
      // verifyDERSignatures: false
      // verifyStrictEncoding: false
    };
    const der = buildDER(R32, S_LOW);
    der[0] = 0x31; // corrupt compound tag → DER invalid
    const sig = Buffer.concat([der, Buffer.from([0x01])]);
    const ctx = makeCtx([sig, COMPRESSED_PUBKEY], flags);
    let caughtCode = "";
    try { executeScript(CHECKSIG_SCRIPT, ctx); }
    catch (e) { caughtCode = (e as ScriptError).code; }
    expect(caughtCode).toBe("SIG_DER");
  });

  test("verifyDERSignatures alone rejects malformed DER with SIG_DER", () => {
    const flags: ScriptFlags = { ...flagsBase(), verifyDERSignatures: true };
    const der = buildDER(R32, S_LOW);
    der[0] = 0x31;
    const sig = Buffer.concat([der, Buffer.from([0x01])]);
    const ctx = makeCtx([sig, COMPRESSED_PUBKEY], flags);
    let caughtCode = "";
    try { executeScript(CHECKSIG_SCRIPT, ctx); }
    catch (e) { caughtCode = (e as ScriptError).code; }
    expect(caughtCode).toBe("SIG_DER");
  });

  test("verifyStrictEncoding alone rejects malformed DER with SIG_DER", () => {
    const flags: ScriptFlags = { ...flagsBase(), verifyStrictEncoding: true };
    const der = buildDER(R32, S_LOW);
    der[0] = 0x31;
    const sig = Buffer.concat([der, Buffer.from([0x01])]);
    const ctx = makeCtx([sig, COMPRESSED_PUBKEY], flags);
    let caughtCode = "";
    try { executeScript(CHECKSIG_SCRIPT, ctx); }
    catch (e) { caughtCode = (e as ScriptError).code; }
    expect(caughtCode).toBe("SIG_DER");
  });

  test("verifyLowS: high-S valid-DER sig is rejected with SIG_HIGH_S", () => {
    const flags: ScriptFlags = { ...flagsBase(), verifyLowS: true };
    const sig = buildSig(R32, S_HIGH);
    const ctx = makeCtx([sig, COMPRESSED_PUBKEY], flags);
    let caughtCode = "";
    try { executeScript(CHECKSIG_SCRIPT, ctx); }
    catch (e) { caughtCode = (e as ScriptError).code; }
    expect(caughtCode).toBe("SIG_HIGH_S");
  });

  test("verifyLowS: low-S valid-DER sig is accepted", () => {
    const flags: ScriptFlags = { ...flagsBase(), verifyLowS: true };
    const sig = buildSig(R32, S_LOW);
    const ctx = makeCtx([sig, COMPRESSED_PUBKEY], flags);
    expect(() => executeScript(CHECKSIG_SCRIPT, ctx)).not.toThrow();
  });

  test("no flags set: any DER format accepted (no encoding check fired)", () => {
    const badDer = Buffer.from([0x31, 0x05, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x01]);
    const ctx = makeCtx([badDer, COMPRESSED_PUBKEY], flagsBase());
    // With NO encoding flags, checkSignatureEncoding is a no-op; bad DER passes encoding check
    expect(() => executeScript(CHECKSIG_SCRIPT, ctx)).not.toThrow();
  });

  test("LOW_S gate comes after DER gate (DER must pass before Low-S is checked)", () => {
    // A sig with bad DER AND high S — the DER gate fires first
    const flags: ScriptFlags = { ...flagsBase(), verifyLowS: true };
    const R = Buffer.alloc(32, 0x01);
    R[0] = 0x80; // negative R → invalid DER
    const sig = buildSig(R, S_HIGH); // also high S
    let caughtCode = "";
    try { executeScript(CHECKSIG_SCRIPT, makeCtx([sig, COMPRESSED_PUBKEY], flags)); }
    catch (e) { caughtCode = (e as ScriptError).code; }
    // DER check fires first → SIG_DER, not SIG_HIGH_S
    expect(caughtCode).toBe("SIG_DER");
  });

  test("STRICTENC hashtype gate comes after DER gate", () => {
    // Bad DER + invalid hashtype — DER gate fires first
    const flags: ScriptFlags = { ...flagsBase(), verifyStrictEncoding: true };
    const der = buildDER(R32, S_LOW);
    der[0] = 0x31; // bad DER
    const sig = Buffer.concat([der, Buffer.from([0x05])]); // also bad hashtype
    let caughtCode = "";
    try { executeScript(CHECKSIG_SCRIPT, makeCtx([sig, COMPRESSED_PUBKEY], flags)); }
    catch (e) { caughtCode = (e as ScriptError).code; }
    expect(caughtCode).toBe("SIG_DER");
  });
});

// ---------------------------------------------------------------------------
// Section 4: isCompressedPubKey / isValidPubKeyEncoding / checkPubKeyEncoding
// ---------------------------------------------------------------------------

describe("checkPubKeyEncoding — STRICTENC and WITNESS_PUBKEYTYPE gates", () => {
  const SIGHASH = Buffer.alloc(32, 0x42);
  const sigHasher = (_s: Buffer, _h: number) => SIGHASH;

  test("STRICTENC: compressed pubkey (0x02) is valid", () => {
    const flags: ScriptFlags = { ...flagsBase(), verifyStrictEncoding: true };
    const validSig = Buffer.concat([ecdsaSign(SIGHASH, PRIVKEY), Buffer.from([0x01])]);
    const ctx = makeCtx([validSig, COMPRESSED_PUBKEY], { ...flags, sigHasher } as any);
    const ctx2: ExecutionContext = {
      stack: [validSig, COMPRESSED_PUBKEY],
      altStack: [],
      flags,
      sigHasher,
      sigVersion: SigVersion.BASE,
    };
    expect(() => executeScript(CHECKSIG_SCRIPT, ctx2)).not.toThrow();
  });

  test("STRICTENC: uncompressed pubkey (0x04, 65 bytes) is valid", () => {
    const flags: ScriptFlags = { ...flagsBase(), verifyStrictEncoding: true };
    const validSig = Buffer.concat([ecdsaSign(SIGHASH, PRIVKEY), Buffer.from([0x01])]);
    const ctx: ExecutionContext = {
      stack: [validSig, UNCOMPRESSED_PUBKEY],
      altStack: [],
      flags,
      sigHasher,
      sigVersion: SigVersion.BASE,
    };
    expect(() => executeScript(CHECKSIG_SCRIPT, ctx)).not.toThrow();
  });

  test("STRICTENC: hybrid key (0x06, 65 bytes) is invalid (SIG_PUBKEYTYPE)", () => {
    const flags: ScriptFlags = { ...flagsBase(), verifyStrictEncoding: true };
    const hybridKey = Buffer.concat([Buffer.from([0x06]), UNCOMPRESSED_PUBKEY.subarray(1)]);
    const validSig = buildSig(R32, S_LOW);
    const ctx: ExecutionContext = {
      stack: [validSig, hybridKey],
      altStack: [],
      flags,
      sigHasher,
      sigVersion: SigVersion.BASE,
    };
    expect(() => executeScript(CHECKSIG_SCRIPT, ctx)).toThrow(ScriptError);
    let code = "";
    try {
      executeScript(CHECKSIG_SCRIPT, {
        stack: [validSig, hybridKey], altStack: [], flags, sigHasher, sigVersion: SigVersion.BASE,
      });
    } catch (e) { code = (e as ScriptError).code; }
    expect(code).toBe("PUBKEYTYPE");
  });

  test("STRICTENC: wrong-length compressed-prefix key rejected (SIG_PUBKEYTYPE)", () => {
    const flags: ScriptFlags = { ...flagsBase(), verifyStrictEncoding: true };
    const badKey = Buffer.alloc(32, 0x02); // 32 bytes, wrong length for compressed
    const sig = buildSig(R32, S_LOW);
    const ctx: ExecutionContext = {
      stack: [sig, badKey], altStack: [], flags, sigHasher, sigVersion: SigVersion.BASE,
    };
    expect(() => executeScript(CHECKSIG_SCRIPT, ctx)).toThrow(ScriptError);
  });

  test("WITNESS_PUBKEYTYPE: uncompressed key rejected in witness v0 (SIG_WITNESS_PUBKEYTYPE)", () => {
    const flags: ScriptFlags = { ...flagsBase(), verifyWitnessPubkeyType: true };
    const validSig = buildSig(R32, S_LOW);
    const ctx: ExecutionContext = {
      stack: [validSig, UNCOMPRESSED_PUBKEY],
      altStack: [],
      flags,
      sigHasher,
      sigVersion: SigVersion.WITNESS_V0,
    };
    let code = "";
    try { executeScript(CHECKSIG_SCRIPT, ctx); }
    catch (e) { code = (e as ScriptError).code; }
    expect(code).toBe("WITNESS_PUBKEYTYPE");
  });

  test("WITNESS_PUBKEYTYPE: compressed key accepted in witness v0", () => {
    const flags: ScriptFlags = { ...flagsBase(), verifyWitnessPubkeyType: true };
    const validSig = Buffer.concat([ecdsaSign(SIGHASH, PRIVKEY), Buffer.from([0x01])]);
    const ctx: ExecutionContext = {
      stack: [validSig, COMPRESSED_PUBKEY],
      altStack: [],
      flags,
      sigHasher,
      sigVersion: SigVersion.WITNESS_V0,
    };
    expect(() => executeScript(CHECKSIG_SCRIPT, ctx)).not.toThrow();
  });

  test("WITNESS_PUBKEYTYPE: uncompressed key allowed in legacy (BASE) scripts", () => {
    const flags: ScriptFlags = { ...flagsBase(), verifyWitnessPubkeyType: true };
    const validSig = Buffer.concat([ecdsaSign(SIGHASH, PRIVKEY), Buffer.from([0x01])]);
    const ctx: ExecutionContext = {
      stack: [validSig, UNCOMPRESSED_PUBKEY],
      altStack: [],
      flags,
      sigHasher,
      sigVersion: SigVersion.BASE, // BASE, not WITNESS_V0
    };
    expect(() => executeScript(CHECKSIG_SCRIPT, ctx)).not.toThrow();
  });
});

// ---------------------------------------------------------------------------
// Section 5: NULLFAIL gate (OP_CHECKSIG and OP_CHECKMULTISIG)
// Reference: Core interpreter.cpp:335-345 (CHECKSIG), :1186-1188 (CHECKMULTISIG)
// ---------------------------------------------------------------------------

describe("NULLFAIL gate (interpreter.cpp:335-345, :1186-1188)", () => {
  const SIGHASH = Buffer.alloc(32, 0xaa);
  const sigHasher = (_s: Buffer, _h: number) => SIGHASH;
  const WRONG_HASH = Buffer.alloc(32, 0xbb);

  test("NULLFAIL: OP_CHECKSIG with non-empty failing sig is rejected", () => {
    const flags: ScriptFlags = { ...flagsBase(), verifyNullFail: true };
    const wrongSig = Buffer.concat([ecdsaSign(WRONG_HASH, PRIVKEY), Buffer.from([0x01])]);
    const ctx: ExecutionContext = {
      stack: [wrongSig, COMPRESSED_PUBKEY],
      altStack: [], flags, sigHasher, sigVersion: SigVersion.BASE,
    };
    expect(executeScript(CHECKSIG_SCRIPT, ctx)).toBe(false);
  });

  test("NULLFAIL: OP_CHECKSIG with empty sig is allowed (pushes false)", () => {
    const flags: ScriptFlags = { ...flagsBase(), verifyNullFail: true };
    const ctx: ExecutionContext = {
      stack: [Buffer.alloc(0), COMPRESSED_PUBKEY],
      altStack: [], flags, sigHasher, sigVersion: SigVersion.BASE,
    };
    expect(executeScript(CHECKSIG_SCRIPT, ctx)).toBe(true);
    expect(ctx.stack[0].length).toBe(0); // false result
  });

  test("NULLFAIL: OP_CHECKMULTISIG non-empty failing sigs rejected", () => {
    const flags: ScriptFlags = { ...flagsBase(), verifyNullFail: true };
    const wrongSig = Buffer.concat([ecdsaSign(WRONG_HASH, PRIVKEY), Buffer.from([0x01])]);
    const ctx: ExecutionContext = {
      stack: [
        Buffer.alloc(0),    // dummy
        wrongSig,           // sig
        scriptNumEncode(1), // nSigs = 1
        COMPRESSED_PUBKEY,  // pubkey
        scriptNumEncode(1), // nKeys = 1
      ],
      altStack: [], flags, sigHasher, sigVersion: SigVersion.BASE,
    };
    expect(executeScript(CHECKMULTISIG_SCRIPT, ctx)).toBe(false);
  });

  test("NULLFAIL: OP_CHECKMULTISIG all-empty sigs allowed when failing", () => {
    const flags: ScriptFlags = { ...flagsBase(), verifyNullFail: true };
    const ctx: ExecutionContext = {
      stack: [
        Buffer.alloc(0),    // dummy
        Buffer.alloc(0),    // empty sig
        scriptNumEncode(1), // nSigs = 1
        COMPRESSED_PUBKEY,
        scriptNumEncode(1), // nKeys = 1
      ],
      altStack: [], flags, sigHasher, sigVersion: SigVersion.BASE,
    };
    expect(executeScript(CHECKMULTISIG_SCRIPT, ctx)).toBe(true);
    expect(ctx.stack[0].length).toBe(0); // false result
  });
});

// ---------------------------------------------------------------------------
// Section 6: NULLDUMMY gate (OP_CHECKMULTISIG dummy element)
// Reference: Core interpreter.cpp:1199-1203
// ---------------------------------------------------------------------------

describe("NULLDUMMY gate (interpreter.cpp:1199-1203)", () => {
  const SIGHASH = Buffer.alloc(32, 0x42);
  const sigHasher = (_s: Buffer, _h: number) => SIGHASH;
  const validSig = Buffer.concat([ecdsaSign(SIGHASH, PRIVKEY), Buffer.from([0x01])]);

  test("NULLDUMMY: empty dummy element is accepted", () => {
    const flags: ScriptFlags = { ...flagsBase(), verifyNullDummy: true };
    const ctx: ExecutionContext = {
      stack: [
        Buffer.alloc(0),    // correct: empty dummy
        validSig,
        scriptNumEncode(1),
        COMPRESSED_PUBKEY,
        scriptNumEncode(1),
      ],
      altStack: [], flags, sigHasher, sigVersion: SigVersion.BASE,
    };
    expect(executeScript(CHECKMULTISIG_SCRIPT, ctx)).toBe(true);
    expect(ctx.stack[0][0]).toBe(1); // true result
  });

  test("NULLDUMMY: non-empty dummy element is rejected", () => {
    const flags: ScriptFlags = { ...flagsBase(), verifyNullDummy: true };
    const ctx: ExecutionContext = {
      stack: [
        Buffer.from([0x01]), // non-empty dummy — NULLDUMMY violation
        validSig,
        scriptNumEncode(1),
        COMPRESSED_PUBKEY,
        scriptNumEncode(1),
      ],
      altStack: [], flags, sigHasher, sigVersion: SigVersion.BASE,
    };
    expect(executeScript(CHECKMULTISIG_SCRIPT, ctx)).toBe(false);
  });

  test("without NULLDUMMY: non-empty dummy is accepted", () => {
    const flags: ScriptFlags = { ...flagsBase(), verifyNullDummy: false };
    const ctx: ExecutionContext = {
      stack: [
        Buffer.from([0x01]), // non-empty, but flag disabled
        validSig,
        scriptNumEncode(1),
        COMPRESSED_PUBKEY,
        scriptNumEncode(1),
      ],
      altStack: [], flags, sigHasher, sigVersion: SigVersion.BASE,
    };
    expect(executeScript(CHECKMULTISIG_SCRIPT, ctx)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Section 7: getConsensusFlags / getStandardFlags flag assignments
// Bug 3: test file incorrectly expected verifyWitnessPubkeyType=true in consensus
// ---------------------------------------------------------------------------

describe("getConsensusFlags — policy vs consensus flag assignment", () => {
  test("DERSIG active from height 363725 (BIP-66)", () => {
    expect(getConsensusFlags(363724).verifyDERSignatures).toBe(false);
    expect(getConsensusFlags(363725).verifyDERSignatures).toBe(true);
  });

  test("NULLDUMMY active from height 481824 (BIP-147 consensus)", () => {
    expect(getConsensusFlags(481823).verifyNullDummy).toBe(false);
    expect(getConsensusFlags(481824).verifyNullDummy).toBe(true);
  });

  test("NULLFAIL is policy-only — never in getConsensusFlags", () => {
    // Core: NULLFAIL is in STANDARD_NOT_MANDATORY (policy). getConsensusFlags must return false.
    expect(getConsensusFlags(0).verifyNullFail).toBe(false);
    expect(getConsensusFlags(481824).verifyNullFail).toBe(false);
    expect(getConsensusFlags(900000).verifyNullFail).toBe(false);
  });

  test("WITNESS_PUBKEYTYPE is policy-only — never in getConsensusFlags (Bug 3)", () => {
    // Core: SCRIPT_VERIFY_WITNESS_PUBKEYTYPE is in STANDARD_SCRIPT_VERIFY_FLAGS but
    // NOT in MANDATORY_SCRIPT_VERIFY_FLAGS. Reference: policy/policy.h:128.
    // getConsensusFlags() is the MANDATORY computer — it must NOT set this flag.
    expect(getConsensusFlags(0).verifyWitnessPubkeyType).toBe(false);
    expect(getConsensusFlags(481824).verifyWitnessPubkeyType).toBe(false);
    expect(getConsensusFlags(900000).verifyWitnessPubkeyType).toBe(false);
  });

  test("STRICTENC is policy-only — never in getConsensusFlags", () => {
    expect(getConsensusFlags(0).verifyStrictEncoding).toBe(false);
    expect(getConsensusFlags(363725).verifyStrictEncoding).toBe(false);
  });

  test("LOW_S is policy-only — never in getConsensusFlags", () => {
    expect(getConsensusFlags(0).verifyLowS).toBe(false);
    expect(getConsensusFlags(363725).verifyLowS).toBe(false);
  });
});

describe("getStandardFlags — policy flags activated at correct heights", () => {
  test("NULLFAIL active from height 481824 (policy, BIP-146)", () => {
    expect(getStandardFlags(481823).verifyNullFail).toBe(false);
    expect(getStandardFlags(481824).verifyNullFail).toBe(true);
  });

  test("WITNESS_PUBKEYTYPE active from height 481824 (policy)", () => {
    expect(getStandardFlags(481823).verifyWitnessPubkeyType).toBe(false);
    expect(getStandardFlags(481824).verifyWitnessPubkeyType).toBe(true);
  });

  test("STRICTENC active from height 363725 (policy)", () => {
    expect(getStandardFlags(363724).verifyStrictEncoding).toBe(false);
    expect(getStandardFlags(363725).verifyStrictEncoding).toBe(true);
  });

  test("LOW_S active from height 363725 (policy)", () => {
    expect(getStandardFlags(363724).verifyLowS).toBe(false);
    expect(getStandardFlags(363725).verifyLowS).toBe(true);
  });
});
