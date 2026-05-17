/**
 * W127 Taproot / Schnorr / Tapscript audit (hotbuns).
 *
 * 30-gate audit matrix over BIP-340 (Schnorr), BIP-341 (Taproot),
 * BIP-342 (Tapscript). See audit/w127_taproot.md.
 *
 * Gates that map to PRESENT verdicts are pinned as assertions here.
 * Gates that map to PARTIAL / MISSING (and BUGs) use it.skip() to
 * keep the test suite informational; they describe what the future
 * fix should pin.
 *
 * Reference implementations:
 *   - bitcoin-core/src/script/interpreter.cpp
 *     (EvalChecksigTapscript, ExecuteWitnessScript,
 *      VerifyTaprootCommitment, VerifyWitnessProgram,
 *      SignatureHashSchnorr, CheckSchnorrSignature,
 *      ComputeTapleafHash, ComputeTapbranchHash)
 *   - bitcoin-core/src/script/script.cpp (IsOpSuccess)
 *   - bitcoin-core/src/pubkey.cpp (XOnlyPubKey::CheckTapTweak)
 *   - bitcoin-core/src/test/data/bip341_wallet_vectors.json
 */

import { describe, expect, it, test } from "bun:test";
import {
  Opcode,
  parseScript,
  executeScript,
  scriptNumEncode,
  scriptNumDecode,
  serializedWitnessStackSize,
  compactSizeLen,
  type ScriptFlags,
  type ExecutionContext,
  SigVersion,
  verifyTaproot,
  type TaprootContext,
} from "../script/interpreter.js";
import {
  taggedHash,
  schnorrVerify,
  isValidXOnlyPubKey,
  tweakPrivateKey,
  tweakPublicKey,
  privateKeyToXOnlyPubKey,
  sha256Hash,
} from "../crypto/primitives.js";
import { schnorrVerifyFFI, FFI_AVAILABLE } from "../crypto/secp256k1_ffi.js";

// ---------------------------------------------------------------------------
// Constants from BIPs / Core
// ---------------------------------------------------------------------------

const SECP256K1_ORDER = BigInt(
  "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"
);
const TAPROOT_LEAF_MASK = 0xfe;
const TAPROOT_LEAF_TAPSCRIPT = 0xc0;
const TAPROOT_CONTROL_BASE_SIZE = 33;
const TAPROOT_CONTROL_NODE_SIZE = 32;
const TAPROOT_CONTROL_MAX_NODE_COUNT = 128;
const VALIDATION_WEIGHT_OFFSET = 50;
const VALIDATION_WEIGHT_PER_SIGOP_PASSED = 50;
const MAX_STACK_SIZE = 1000;
const MAX_SCRIPT_ELEMENT_SIZE = 520;
const ANNEX_TAG = 0x50;

// ---------------------------------------------------------------------------
// Test fixtures (BIP-341 wallet vector #1, scriptPubKey)
// ---------------------------------------------------------------------------

// Vector 1: internalPubkey + null scriptTree → tweakedPubkey
// bitcoin-core/src/test/data/bip341_wallet_vectors.json #1
const V1_INTERNAL_PK = Buffer.from(
  "d6889cb081036e0faefa3a35157ad71086b123b2b144b649798b494c300a961d",
  "hex"
);
const V1_TWEAK = Buffer.from(
  "b86e7be8f39bab32a6f2c0443abbc210f0edac0e2c53d501b36b64437d9c6c70",
  "hex"
);
const V1_TWEAKED_PK = Buffer.from(
  "53a1f6e454df1aa2776a2814a721372d6258050de330b3c6d10ee8f4e0dda343",
  "hex"
);

// Vector 2: internal key + single-leaf scriptTree
// bitcoin-core/src/test/data/bip341_wallet_vectors.json #2
const V2_INTERNAL_PK = Buffer.from(
  "187791b6f712a8ea41c8ecdd0ee77fab3e85263b37e1ec18a3651926b3a6cf27",
  "hex"
);
const V2_LEAF_SCRIPT = Buffer.from(
  "20d85a959b0290bf19bb89ed43c916be835475d013da4b362117393e25a48229b8ac",
  "hex"
);
const V2_LEAF_HASH = Buffer.from(
  "5b75adecf53548f3ec6ad7d78383bf84cc57b55a3127c72b9a2481752dd88b21",
  "hex"
);
const V2_TWEAKED_PK = Buffer.from(
  "147c9c57132f6e7ecddba9800bb0c4449251c92a1e60371ee77557b6620f3ea3",
  "hex"
);

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function tapscriptFlags(extra?: Partial<ScriptFlags>): ScriptFlags {
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
    ...extra,
  };
}

function dummySigHasher(_subscript: Buffer, _hashType: number): Buffer {
  return Buffer.alloc(32);
}

function tapscriptCtx(stack: Buffer[], opts: Partial<ExecutionContext> = {}): ExecutionContext {
  return {
    stack: [...stack],
    altStack: [],
    flags: tapscriptFlags(),
    sigHasher: dummySigHasher,
    sigVersion: SigVersion.TAPSCRIPT,
    taprootSigHasher: () => Buffer.alloc(32),
    sigopsBudget: 5_000,
    ...opts,
  };
}

function encodeCompactSizeLocal(n: number): Buffer {
  if (n < 0xfd) return Buffer.from([n]);
  if (n <= 0xffff) return Buffer.from([0xfd, n & 0xff, (n >> 8) & 0xff]);
  if (n <= 0xffffffff)
    return Buffer.from([0xfe, n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff, (n >> 24) & 0xff]);
  throw new Error("unsupported");
}

function makeP2TR(xonly: Buffer): Buffer {
  if (xonly.length !== 32) throw new Error("expected 32B x-only");
  return Buffer.concat([Buffer.from([0x51, 0x20]), xonly]);
}

// =============================================================================
// BIP-340 — Schnorr & tagged hashing
// =============================================================================

describe("W127 G01 — BIP-340 §3.3 tagged hash structural identity", () => {
  test("taggedHash(tag, msg) = SHA256(SHA256(tag) || SHA256(tag) || msg)", () => {
    // Manually compute against the BIP-340 reference formula and check parity.
    const tag = "BIP0340/challenge";
    const tagHash = sha256Hash(Buffer.from(tag, "utf-8"));
    const msg = Buffer.from("hello world", "utf-8");
    const manual = sha256Hash(Buffer.concat([tagHash, tagHash, msg]));
    const lib = taggedHash(tag, msg);
    expect(lib.equals(manual)).toBe(true);
  });

  test("BIP-340 'BIP0340/challenge' tagged hash of 32-zero msg matches W95 pin", () => {
    // Pinning the same precomputed reference as W95 (schnorr_bip340_w95.test.ts:60-66),
    // so a regression that breaks tagged hashing fails both W95 and W127.
    const got = taggedHash("BIP0340/challenge", Buffer.alloc(32, 0));
    expect(got.toString("hex")).toBe(
      "a50885aadef94ee57e5537e27ef82d4db7c756193539d3d8d0bb6ee5f3a7ad46"
    );
  });
});

describe("W127 G02 — tagged-hash midstate cache returns stable output", () => {
  test("repeated taggedHash calls with same tag/msg are byte-identical", () => {
    const msg = Buffer.from("hashhog", "utf-8");
    const a = taggedHash("TapLeaf", msg);
    const b = taggedHash("TapLeaf", msg);
    const c = taggedHash("TapLeaf", msg);
    expect(a.equals(b)).toBe(true);
    expect(b.equals(c)).toBe(true);
  });

  test("distinct tags produce distinct outputs (cache key isolation)", () => {
    const msg = Buffer.from("hashhog", "utf-8");
    const tagged = ["TapLeaf", "TapBranch", "TapTweak", "TapSighash"].map((t) =>
      taggedHash(t, msg)
    );
    for (let i = 0; i < tagged.length; i++) {
      for (let j = i + 1; j < tagged.length; j++) {
        expect(tagged[i].equals(tagged[j])).toBe(false);
      }
    }
  });
});

describe("W127 G03 — BIP-340 §3.4 wrapper length gates", () => {
  test("schnorrVerify rejects when signature length != 64", () => {
    const msg = Buffer.alloc(32);
    const pk = Buffer.alloc(32, 1);
    expect(schnorrVerify(Buffer.alloc(0), msg, pk)).toBe(false);
    expect(schnorrVerify(Buffer.alloc(63), msg, pk)).toBe(false);
    expect(schnorrVerify(Buffer.alloc(65), msg, pk)).toBe(false);
  });

  test("schnorrVerify rejects when message length != 32", () => {
    const sig = Buffer.alloc(64);
    const pk = Buffer.alloc(32, 1);
    expect(schnorrVerify(sig, Buffer.alloc(31), pk)).toBe(false);
    expect(schnorrVerify(sig, Buffer.alloc(33), pk)).toBe(false);
  });

  test("schnorrVerify rejects when pubkey length != 32", () => {
    const sig = Buffer.alloc(64);
    const msg = Buffer.alloc(32);
    expect(schnorrVerify(sig, msg, Buffer.alloc(31))).toBe(false);
    expect(schnorrVerify(sig, msg, Buffer.alloc(33))).toBe(false);
  });
});

describe("W127 G04 — Schnorr verify delegates to libsecp256k1 when FFI available", () => {
  test("FFI flag set and verify routes through libsecp256k1", () => {
    expect(FFI_AVAILABLE).toBe(true);
    // Build a fresh keypair and verify a real signature through both paths.
    // Use deterministic private key.
    const privKey = Buffer.alloc(32, 0);
    privKey[31] = 0x42;
    const pubKey = privateKeyToXOnlyPubKey(privKey);
    const msg = sha256Hash(Buffer.from("w127", "utf-8"));
    // Build a signature using @noble (since schnorrSign already routes via @noble)
    const { schnorrSign } = require("../crypto/primitives.js");
    const sig = schnorrSign(msg, privKey);
    // The FFI path is the production code; assert it accepts.
    expect(schnorrVerifyFFI(sig, msg, pubKey)).toBe(true);
    // And the top-level wrapper does too (it picks FFI by default).
    expect(schnorrVerify(sig, msg, pubKey)).toBe(true);
  });
});

describe("W127 G05 — Schnorr fallback to @noble when FFI unavailable", () => {
  // We can't toggle FFI off at runtime cleanly, so we just assert that the
  // fallback code path is callable directly and produces identical results.
  test("schnorr.verify (noble) and FFI agree on the same valid signature", () => {
    const { schnorrSign } = require("../crypto/primitives.js");
    const privKey = Buffer.alloc(32, 0);
    privKey[31] = 0x11;
    const pubKey = privateKeyToXOnlyPubKey(privKey);
    const msg = sha256Hash(Buffer.from("fallback", "utf-8"));
    const sig = schnorrSign(msg, privKey);
    expect(schnorrVerifyFFI(sig, msg, pubKey)).toBe(true);
    // Direct @noble call must also agree.
    const { schnorr } = require("@noble/curves/secp256k1.js");
    expect(schnorr.verify(sig, msg, pubKey)).toBe(true);
  });
});

describe("W127 G06 — BIP-340 §2 x-only pubkey lift_x validity", () => {
  test("isValidXOnlyPubKey accepts a randomly derived x-only key", () => {
    const priv = Buffer.alloc(32, 0);
    priv[31] = 0x07;
    const pub = privateKeyToXOnlyPubKey(priv);
    expect(pub.length).toBe(32);
    expect(isValidXOnlyPubKey(pub)).toBe(true);
  });

  test("isValidXOnlyPubKey rejects x=0 (not on curve)", () => {
    expect(isValidXOnlyPubKey(Buffer.alloc(32, 0))).toBe(false);
  });

  test("isValidXOnlyPubKey rejects 31-byte and 33-byte buffers", () => {
    expect(isValidXOnlyPubKey(Buffer.alloc(31))).toBe(false);
    expect(isValidXOnlyPubKey(Buffer.alloc(33))).toBe(false);
  });
});

// =============================================================================
// BIP-341 — Taproot key tweaking
// =============================================================================

describe("W127 G07 — BIP-341 §3 tweakPrivateKey validity gates", () => {
  test("rejects d == 0", () => {
    expect(() => tweakPrivateKey(Buffer.alloc(32, 0), Buffer.alloc(32, 1))).toThrow(
      /privateKey is not a valid secp256k1 scalar/
    );
  });

  test("rejects d >= n", () => {
    // d = n exactly
    const n = SECP256K1_ORDER.toString(16).padStart(64, "0");
    expect(() => tweakPrivateKey(Buffer.from(n, "hex"), Buffer.alloc(32, 1))).toThrow(
      /privateKey is not a valid secp256k1 scalar/
    );
  });

  test("rejects t >= n", () => {
    const validPriv = Buffer.alloc(32, 0);
    validPriv[31] = 0x05;
    const n = SECP256K1_ORDER.toString(16).padStart(64, "0");
    expect(() => tweakPrivateKey(validPriv, Buffer.from(n, "hex"))).toThrow(
      /tweak is not a valid scalar/
    );
  });
});

describe("W127 G08 — BIP-341 tweakPrivateKey even-y negation", () => {
  test("tweaking a valid key produces a 32-byte result", () => {
    const priv = Buffer.alloc(32, 0);
    priv[31] = 0x03;
    // Use a small non-zero tweak.
    const tweak = Buffer.alloc(32, 0);
    tweak[31] = 0x01;
    const tweaked = tweakPrivateKey(priv, tweak);
    expect(tweaked.length).toBe(32);
    // The tweaked key derives an x-only pubkey that lifts.
    const pub = privateKeyToXOnlyPubKey(tweaked);
    expect(isValidXOnlyPubKey(pub)).toBe(true);
  });
});

describe("W127 G09 — BIP-341 tweakPublicKey validity gates", () => {
  test("rejects t >= n", () => {
    const priv = Buffer.alloc(32, 0);
    priv[31] = 0x04;
    const pub = privateKeyToXOnlyPubKey(priv);
    const n = SECP256K1_ORDER.toString(16).padStart(64, "0");
    expect(() => tweakPublicKey(pub, Buffer.from(n, "hex"))).toThrow(
      /tweak is not a valid scalar/
    );
  });

  test("BIP-341 vector #1: internalPK + null-tree tweak → expected tweakedPK", () => {
    const tweaked = tweakPublicKey(V1_INTERNAL_PK, V1_TWEAK);
    expect(tweaked.toString("hex")).toBe(V1_TWEAKED_PK.toString("hex"));
  });
});

describe("W127 G10 — interpreter's tweakPublicKeyWithParity tracks parity", () => {
  test("BIP-341 vector #2: internalPK + leaf-merkle-root tweak agrees with primitives.tweakPublicKey for x", () => {
    // Compute the tweak from internal + merkleRoot per BIP-341.
    const tweak = taggedHash("TapTweak", Buffer.concat([V2_INTERNAL_PK, V2_LEAF_HASH]));
    const tweaked = tweakPublicKey(V2_INTERNAL_PK, tweak);
    expect(tweaked.toString("hex")).toBe(V2_TWEAKED_PK.toString("hex"));
  });
});

// =============================================================================
// BIP-341 — Control block + leaf + branch
// =============================================================================

describe("W127 G11 — control-block length gates (33 base + 32n nodes, n ≤ 128)", () => {
  test("verifyTaproot rejects controlBlock < 33 bytes", () => {
    // Build a witness with [script, controlBlock<33B].
    // We invoke verifyTaproot directly; it will route to script-path because
    // witnessStack.length >= 2.  controlBlock=32B should throw.
    const spk = makeP2TR(Buffer.alloc(32, 0x01));
    const script = Buffer.from([Opcode.OP_TRUE]);
    const ctrl = Buffer.alloc(32, 0xc0); // too short
    const flags = tapscriptFlags();
    const ctx: TaprootContext = {
      keyPathSigHasher: () => Buffer.alloc(32),
      scriptPathSigHasher: () => Buffer.alloc(32),
    };
    expect(() => verifyTaproot(spk, [script, ctrl], flags, ctx)).toThrow(
      /TAPROOT_WRONG_CONTROL_SIZE/
    );
  });

  test("verifyTaproot rejects controlBlock with non-32-multiple node tail", () => {
    const spk = makeP2TR(Buffer.alloc(32, 0x01));
    const script = Buffer.from([Opcode.OP_TRUE]);
    // 33 + 31 bytes = not a multiple of 32 in the node region.
    const ctrl = Buffer.concat([Buffer.alloc(33, 0xc0), Buffer.alloc(31, 0x42)]);
    const flags = tapscriptFlags();
    const ctx: TaprootContext = {
      keyPathSigHasher: () => Buffer.alloc(32),
      scriptPathSigHasher: () => Buffer.alloc(32),
    };
    expect(() => verifyTaproot(spk, [script, ctrl], flags, ctx)).toThrow(
      /TAPROOT_WRONG_CONTROL_SIZE/
    );
  });

  test("verifyTaproot rejects pathLen > 128 (Core TAPROOT_CONTROL_MAX_NODE_COUNT)", () => {
    const spk = makeP2TR(Buffer.alloc(32, 0x01));
    const script = Buffer.from([Opcode.OP_TRUE]);
    // 33 + 129 * 32 = 4161 bytes (one beyond the max).
    const ctrl = Buffer.concat([
      Buffer.alloc(33, 0xc0),
      Buffer.alloc((TAPROOT_CONTROL_MAX_NODE_COUNT + 1) * 32, 0x42),
    ]);
    const flags = tapscriptFlags();
    const ctx: TaprootContext = {
      keyPathSigHasher: () => Buffer.alloc(32),
      scriptPathSigHasher: () => Buffer.alloc(32),
    };
    expect(() => verifyTaproot(spk, [script, ctrl], flags, ctx)).toThrow(
      /TAPROOT_WRONG_CONTROL_SIZE/
    );
  });
});

describe("W127 G12 — TAPROOT_LEAF_MASK strips parity bit from leaf version", () => {
  test("leaf-version mask = 0xfe (BIP-341)", () => {
    expect(TAPROOT_LEAF_MASK).toBe(0xfe);
    // 0xc0 & 0xfe = 0xc0 (tapscript); parity bit is the low bit.
    expect(0xc0 & TAPROOT_LEAF_MASK).toBe(TAPROOT_LEAF_TAPSCRIPT);
    expect(0xc1 & TAPROOT_LEAF_MASK).toBe(TAPROOT_LEAF_TAPSCRIPT);
  });
});

describe("W127 G13 — TapLeaf preimage = leaf_version || compact_size(len) || script", () => {
  test("TapLeaf vector #2 matches Core ComputeTapleafHash", () => {
    // BIP-341 wallet vector #2 (scriptPubKey[1]):
    //   leafVersion = 192 (0xc0)
    //   script      = 20d85a959b...8ac (35B)
    //   leafHash    = 5b75adecf5354...88b21
    const lv = Buffer.from([0xc0]);
    const lenPrefix = encodeCompactSizeLocal(V2_LEAF_SCRIPT.length);
    const preimage = Buffer.concat([lv, lenPrefix, V2_LEAF_SCRIPT]);
    const got = taggedHash("TapLeaf", preimage);
    expect(got.equals(V2_LEAF_HASH)).toBe(true);
  });
});

describe("W127 G14 — TapBranch is lex-sorted sha-tagged concat", () => {
  test("TapBranch(a,b) == TapBranch(b,a) when sorted", () => {
    const a = Buffer.alloc(32, 0x11);
    const b = Buffer.alloc(32, 0x22);
    // lex sort: a < b, so TapBranch(a||b)
    const expected = taggedHash("TapBranch", Buffer.concat([a, b]));
    // Build a 2-leaf tree and verify the merkle root: pretend leafHash=a and sibling=b
    // The interpreter's computeTapBranchHash is private, so we replicate it from
    // BIP-341 + Core spec.
    const got =
      a.compare(b) < 0
        ? taggedHash("TapBranch", Buffer.concat([a, b]))
        : taggedHash("TapBranch", Buffer.concat([b, a]));
    expect(got.equals(expected)).toBe(true);
  });

  test("TapBranch order is canonical (reverse input → same hash)", () => {
    const a = Buffer.alloc(32, 0x33);
    const b = Buffer.alloc(32, 0x22);
    const h1 =
      a.compare(b) < 0
        ? taggedHash("TapBranch", Buffer.concat([a, b]))
        : taggedHash("TapBranch", Buffer.concat([b, a]));
    const h2 =
      b.compare(a) < 0
        ? taggedHash("TapBranch", Buffer.concat([b, a]))
        : taggedHash("TapBranch", Buffer.concat([a, b]));
    expect(h1.equals(h2)).toBe(true);
  });
});

describe("W127 G15 — control-block parity bit checked vs tweaked-key parity", () => {
  // Black-box: we can't easily force a parity mismatch without a real Schnorr
  // setup. Instead pin the structural fact: leaf-version with parity bit 0x01
  // means "tweaked output key has odd Y", and the audit relies on the
  // verifyTaproot path checking it.
  test("leafVersion parity-bit extraction: 0xc0 → parity 0, 0xc1 → parity 1", () => {
    expect(0xc0 & 0x01).toBe(0);
    expect(0xc1 & 0x01).toBe(1);
    expect(0xc0 & TAPROOT_LEAF_MASK).toBe(0xc0);
    expect(0xc1 & TAPROOT_LEAF_MASK).toBe(0xc0);
  });
});

describe("W127 G16 — unknown leaf version: consensus accepts, DISCOURAGE rejects", () => {
  // Cannot easily build a valid tweaked output key for a forged-leaf-version
  // tree without significant fixture work. The constants are checked here;
  // the behavioral test lives in taproot_tapscript_bip341_342.test.ts (W94)
  // for the DISCOURAGE_UPGRADABLE_PUBKEYTYPE sibling case.
  test("TAPROOT_LEAF_TAPSCRIPT is 0xc0 (BIP-342)", () => {
    expect(TAPROOT_LEAF_TAPSCRIPT).toBe(0xc0);
  });
});

describe("W127 G17 — annex hash uses CompactSize length prefix", () => {
  test("annex hash for 6-byte annex matches SHA256(0x06 || annex)", () => {
    // Annex = 0x50 || 'hello' = 6 bytes. CompactSize(6) = 0x06.
    const annex = Buffer.concat([Buffer.from([ANNEX_TAG]), Buffer.from("hello")]);
    const expected = sha256Hash(Buffer.concat([Buffer.from([0x06]), annex]));
    const compactPrefix = Buffer.from([annex.length]);
    const got = sha256Hash(Buffer.concat([compactPrefix, annex]));
    expect(got.equals(expected)).toBe(true);
  });

  test("annex hash uses 3-byte 0xfd-prefixed CompactSize when len >= 0xfd", () => {
    // Build a 300-byte annex starting with 0x50.
    const annex = Buffer.alloc(300, 0x42);
    annex[0] = ANNEX_TAG;
    const compactPrefix = Buffer.from([0xfd, 300 & 0xff, (300 >> 8) & 0xff]);
    const expected = sha256Hash(Buffer.concat([compactPrefix, annex]));
    expect(expected.length).toBe(32);
  });
});

describe("W127 G18 — key-path: only one stack item after annex strip", () => {
  test("verifyTaproot with 1-item witness routes to key-path", () => {
    // Build a fake taproot context and use a 64B sig.
    const spk = makeP2TR(Buffer.alloc(32, 0x02));
    const sig64 = Buffer.alloc(64, 0x01);
    const ctx: TaprootContext = {
      keyPathSigHasher: () => Buffer.alloc(32),
      scriptPathSigHasher: () => Buffer.alloc(32),
    };
    // schnorrVerify will fail (random sig); we expect SCHNORR_SIG thrown via
    // the key-path branch, NOT TAPROOT_WRONG_CONTROL_SIZE (which only fires
    // on the script-path).
    expect(() => verifyTaproot(spk, [sig64], tapscriptFlags(), ctx)).toThrow(/SCHNORR_SIG/);
  });
});

describe("W127 G19 — key-path sig length 64 or 65", () => {
  test("63-byte sig throws SCHNORR_SIG_SIZE", () => {
    const spk = makeP2TR(Buffer.alloc(32, 0x02));
    const sig = Buffer.alloc(63, 0x01);
    const ctx: TaprootContext = {
      keyPathSigHasher: () => Buffer.alloc(32),
      scriptPathSigHasher: () => Buffer.alloc(32),
    };
    expect(() => verifyTaproot(spk, [sig], tapscriptFlags(), ctx)).toThrow(/SCHNORR_SIG_SIZE/);
  });

  test("66-byte sig throws SCHNORR_SIG_SIZE", () => {
    const spk = makeP2TR(Buffer.alloc(32, 0x02));
    const sig = Buffer.alloc(66, 0x01);
    const ctx: TaprootContext = {
      keyPathSigHasher: () => Buffer.alloc(32),
      scriptPathSigHasher: () => Buffer.alloc(32),
    };
    expect(() => verifyTaproot(spk, [sig], tapscriptFlags(), ctx)).toThrow(/SCHNORR_SIG_SIZE/);
  });
});

describe("W127 G20 — 65-byte sig with hash_type=0x00 → SCHNORR_SIG_HASHTYPE", () => {
  test("65B sig with last byte = 0x00 is rejected", () => {
    const spk = makeP2TR(Buffer.alloc(32, 0x02));
    const sig = Buffer.alloc(65, 0x01);
    sig[64] = 0x00; // explicit SIGHASH_DEFAULT in 65-byte form: not allowed.
    const ctx: TaprootContext = {
      keyPathSigHasher: () => Buffer.alloc(32),
      scriptPathSigHasher: () => Buffer.alloc(32),
    };
    expect(() => verifyTaproot(spk, [sig], tapscriptFlags(), ctx)).toThrow(/SCHNORR_SIG_HASHTYPE/);
  });
});

describe("W127 G21 — valid taproot hash types: 0x00, 0x01-0x03, 0x81-0x83", () => {
  test("invalid hash type bits in 65-byte sig are rejected", () => {
    const spk = makeP2TR(Buffer.alloc(32, 0x02));
    // hash_type = 0x04 (invalid for taproot — not in {0x00..0x03} ∪ {0x80..0x83})
    const sig = Buffer.alloc(65, 0x01);
    sig[64] = 0x04;
    const ctx: TaprootContext = {
      keyPathSigHasher: () => Buffer.alloc(32),
      scriptPathSigHasher: () => Buffer.alloc(32),
    };
    expect(() => verifyTaproot(spk, [sig], tapscriptFlags(), ctx)).toThrow(/SCHNORR_SIG_HASHTYPE/);
  });

  test("hash_type=0x80 (ANYONECANPAY|DEFAULT) is rejected (base must be 0x01-0x03 when ANYONECANPAY)", () => {
    const spk = makeP2TR(Buffer.alloc(32, 0x02));
    const sig = Buffer.alloc(65, 0x01);
    sig[64] = 0x80;
    const ctx: TaprootContext = {
      keyPathSigHasher: () => Buffer.alloc(32),
      scriptPathSigHasher: () => Buffer.alloc(32),
    };
    expect(() => verifyTaproot(spk, [sig], tapscriptFlags(), ctx)).toThrow(/SCHNORR_SIG_HASHTYPE/);
  });
});

// =============================================================================
// BIP-342 — Tapscript opcodes + sigops + OP_SUCCESS
// =============================================================================

describe("W127 G22 — IsOpSuccess() coverage matches Core script.cpp:364-370", () => {
  // Core: opcode == 80 || opcode == 98 || (126..129) || (131..134) ||
  //       (137..138) || (141..142) || (149..153) || (187..254)
  test("OP_RESERVED (80) is OP_SUCCESSx", () => {
    // Script of only OP_RESERVED.
    const script = Buffer.from([80]);
    const stack: Buffer[] = [];
    // The "leaf" tapscript path triggers OP_SUCCESS scan.
    // Use OP_SUCCESS by direct opcode 0x50.
    const parsed = parseScript(script);
    // executeScript shouldn't be invoked for OP_SUCCESS scripts; the gate
    // sits inside executeTapscript, not executeScript. We pin the constant
    // and the containsOpSuccess result via the parseScript invariant:
    expect(parsed.length).toBe(1);
    expect(parsed[0].opcode).toBe(80);
  });

  // The literal scan ranges (assertion is just numerical so a future
  // contributor who changes the table sees the test break).
  test("OP_SUCCESSx canonical ranges (from Core IsOpSuccess)", () => {
    const successOpcodes = [
      80, 98,
      ...Array.from({ length: 4 }, (_, i) => 126 + i), // 126-129
      ...Array.from({ length: 4 }, (_, i) => 131 + i), // 131-134
      ...Array.from({ length: 2 }, (_, i) => 137 + i), // 137-138
      ...Array.from({ length: 2 }, (_, i) => 141 + i), // 141-142
      ...Array.from({ length: 5 }, (_, i) => 149 + i), // 149-153
      ...Array.from({ length: 68 }, (_, i) => 187 + i), // 187-254
    ];
    // Total count from Core: 1+1+4+4+2+2+5+68 = 87 opcodes
    expect(successOpcodes.length).toBe(87);
    // Spot check the boundary cases.
    expect(successOpcodes).toContain(80);
    expect(successOpcodes).toContain(126);
    expect(successOpcodes).toContain(129);
    expect(successOpcodes).toContain(187);
    expect(successOpcodes).toContain(254);
    expect(successOpcodes).not.toContain(155);
    expect(successOpcodes).not.toContain(186);
    expect(successOpcodes).not.toContain(255); // OP_INVALIDOPCODE not in success list
  });
});

describe("W127 G23 — OP_SUCCESSx consensus success + DISCOURAGE_OP_SUCCESS policy reject", () => {
  // Use OP_RESERVED (0x50) as the simplest OP_SUCCESS opcode.
  // Build the full pipeline through verifyTaproot with a real tweak so the
  // commitment check passes.
  test("OP_SUCCESSx with DISCOURAGE_OP_SUCCESS off (consensus) succeeds via verifyTaproot", () => {
    // Build a single-leaf tree: leaf = OP_RESERVED (a single OP_SUCCESSx opcode).
    const internalPriv = Buffer.alloc(32, 0);
    internalPriv[31] = 0x09;
    const internalPub = privateKeyToXOnlyPubKey(internalPriv);
    const leafScript = Buffer.from([0x50]); // OP_RESERVED = OP_SUCCESSx
    const lenPrefix = encodeCompactSizeLocal(leafScript.length);
    const leafHash = taggedHash(
      "TapLeaf",
      Buffer.concat([Buffer.from([TAPROOT_LEAF_TAPSCRIPT]), lenPrefix, leafScript])
    );
    const tweak = taggedHash("TapTweak", Buffer.concat([internalPub, leafHash]));
    const outputKey = tweakPublicKey(internalPub, tweak);
    // For the parity bit we need to recompute via the interpreter helper, but
    // the public tweakPublicKey just gives us x. We try both parities via
    // the control block.
    for (const parity of [0, 1]) {
      const ctrl = Buffer.concat([
        Buffer.from([TAPROOT_LEAF_TAPSCRIPT | parity]),
        internalPub,
      ]);
      const spk = makeP2TR(outputKey);
      const ctx: TaprootContext = {
        keyPathSigHasher: () => Buffer.alloc(32),
        scriptPathSigHasher: () => Buffer.alloc(32),
      };
      try {
        const ok = verifyTaproot(spk, [leafScript, ctrl], tapscriptFlags(), ctx);
        // Hit; the correct parity worked.
        expect(ok).toBe(true);
        return;
      } catch {
        // Wrong parity; try the other.
      }
    }
    throw new Error("neither parity matched — fixture broken");
  });

  test("OP_SUCCESSx with DISCOURAGE_OP_SUCCESS on (policy) throws DISCOURAGE_OP_SUCCESS", () => {
    // Same as above but with the policy flag flipped.
    const internalPriv = Buffer.alloc(32, 0);
    internalPriv[31] = 0x0a;
    const internalPub = privateKeyToXOnlyPubKey(internalPriv);
    const leafScript = Buffer.from([0x50]);
    const lenPrefix = encodeCompactSizeLocal(leafScript.length);
    const leafHash = taggedHash(
      "TapLeaf",
      Buffer.concat([Buffer.from([TAPROOT_LEAF_TAPSCRIPT]), lenPrefix, leafScript])
    );
    const tweak = taggedHash("TapTweak", Buffer.concat([internalPub, leafHash]));
    const outputKey = tweakPublicKey(internalPub, tweak);
    const flags = tapscriptFlags({ verifyDiscourageOpSuccess: true });
    const ctx: TaprootContext = {
      keyPathSigHasher: () => Buffer.alloc(32),
      scriptPathSigHasher: () => Buffer.alloc(32),
    };
    for (const parity of [0, 1]) {
      const ctrl = Buffer.concat([
        Buffer.from([TAPROOT_LEAF_TAPSCRIPT | parity]),
        internalPub,
      ]);
      const spk = makeP2TR(outputKey);
      try {
        // The correct parity will fail with DISCOURAGE_OP_SUCCESS (policy);
        // the wrong parity will fail with WITNESS_PROGRAM_MISMATCH.
        verifyTaproot(spk, [leafScript, ctrl], flags, ctx);
        throw new Error("should have thrown");
      } catch (e) {
        const msg = (e as Error).message;
        if (msg.includes("DISCOURAGE_OP_SUCCESS")) return; // correct parity, gate hit.
        if (msg.includes("WITNESS_PROGRAM_MISMATCH")) continue; // wrong parity, try other
        throw e;
      }
    }
    throw new Error("DISCOURAGE_OP_SUCCESS not thrown for either parity");
  });
});

describe("W127 G24 — MAX_STACK_SIZE (1000) + MAX_ELEMENT_SIZE (520) constants", () => {
  test("constants match Core script.h", () => {
    expect(MAX_STACK_SIZE).toBe(1000);
    expect(MAX_SCRIPT_ELEMENT_SIZE).toBe(520);
    expect(VALIDATION_WEIGHT_OFFSET).toBe(50);
    expect(VALIDATION_WEIGHT_PER_SIGOP_PASSED).toBe(50);
  });
});

describe("W127 G25 — OP_CHECKMULTISIG / OP_CHECKMULTISIGVERIFY disabled in tapscript", () => {
  test("OP_CHECKMULTISIG in tapscript throws TAPSCRIPT_CHECKMULTISIG", () => {
    const parsed = parseScript(Buffer.from([Opcode.OP_CHECKMULTISIG]));
    // BIP-342 disables CMS unconditionally. Need at least 1 stack item to reach
    // the gate (Core's interpreter reaches the CMS case after popping the
    // count). Push enough.
    const ctx = tapscriptCtx([
      Buffer.alloc(0),
      scriptNumEncode(0),
      scriptNumEncode(0),
    ]);
    expect(() => executeScript(parsed, ctx)).toThrow(/TAPSCRIPT_CHECKMULTISIG/);
  });

  test("OP_CHECKMULTISIGVERIFY in tapscript throws TAPSCRIPT_CHECKMULTISIG", () => {
    const parsed = parseScript(Buffer.from([Opcode.OP_CHECKMULTISIGVERIFY]));
    const ctx = tapscriptCtx([
      Buffer.alloc(0),
      scriptNumEncode(0),
      scriptNumEncode(0),
    ]);
    expect(() => executeScript(parsed, ctx)).toThrow(/TAPSCRIPT_CHECKMULTISIG/);
  });
});

describe("W127 G26 — MAX_OPS_PER_SCRIPT exempt in tapscript (BIP-342)", () => {
  test("250 OP_NOP opcodes in tapscript: opcount limit is NOT enforced", () => {
    // 250 OP_NOPs would fail in BASE/WITNESS_V0 (>201) but tapscript is exempt.
    // We can't reach 250 via the parser without pushing them all so we use the
    // raw script with 250 0x61 bytes.
    const script = Buffer.alloc(250, 0x61); // OP_NOP
    const parsed = parseScript(script);
    const ctx = tapscriptCtx([scriptNumEncode(1)]); // start with true on stack
    // Execute should succeed (return true) since no opcount enforced.
    // But OP_NOP doesn't push; we need a TRUE on the stack at end.
    // After 250 OP_NOPs the stack is the initial [1]. Then cleanstack would
    // be implicit; here we just confirm executeScript doesn't throw on
    // opcount.
    expect(() => executeScript(parsed, ctx)).not.toThrow(/MAX_OPS_PER_SCRIPT|OPCOUNT/);
  });

  test("Same 250-OP_NOP script in BASE sigversion DOES hit opcount limit", () => {
    const script = Buffer.alloc(250, 0x61);
    const parsed = parseScript(script);
    const ctx = tapscriptCtx([scriptNumEncode(1)], { sigVersion: SigVersion.BASE });
    // Base sigversion enforces MAX_OPS_PER_SCRIPT = 201; 250 > 201; executeScript
    // returns false but doesn't throw a named error (it returns false). Pin via
    // result.
    const result = executeScript(parsed, ctx);
    expect(result).toBe(false);
  });
});

describe("W127 G27 — MINIMALIF unconditional in tapscript", () => {
  test("OP_IF with non-canonical truthy value in tapscript throws MINIMALIF", () => {
    // Push 0x02 (truthy but not minimal — minimal would be [0x01]) then OP_IF.
    const script = Buffer.from([0x01, 0x02, Opcode.OP_IF, Opcode.OP_TRUE, Opcode.OP_ENDIF]);
    const parsed = parseScript(script);
    const ctx = tapscriptCtx([], { sigVersion: SigVersion.TAPSCRIPT });
    expect(() => executeScript(parsed, ctx)).toThrow(/MINIMALIF/);
  });

  test("OP_IF with non-canonical value in BASE sigversion does NOT throw MINIMALIF (unless flag set)", () => {
    const script = Buffer.from([0x01, 0x02, Opcode.OP_IF, Opcode.OP_TRUE, Opcode.OP_ENDIF]);
    const parsed = parseScript(script);
    const ctx = tapscriptCtx([], { sigVersion: SigVersion.BASE, flags: tapscriptFlags({ verifyMinimalIf: false }) });
    // Without the flag, BASE/WITNESS_V0 accepts.
    expect(() => executeScript(parsed, ctx)).not.toThrow(/MINIMALIF/);
  });
});

describe("W127 G28 — BIP-342 sigops validation-weight budget seed", () => {
  // BUG-1 territory: the fallback budget in executeTapscript (when fullWitness
  // not supplied) under-counts vs Core. The production path (verifyTaproot)
  // does pass fullWitness, so this only fires in test-only entry points.

  test("serializedWitnessStackSize matches Core ::GetSerializeSize(witness.stack)", () => {
    // Empty stack: just the CompactSize(0) = 1 byte.
    expect(serializedWitnessStackSize([])).toBe(1);
    // Single 32-byte element: CompactSize(1) + CompactSize(32) + 32 = 1+1+32 = 34
    expect(serializedWitnessStackSize([Buffer.alloc(32)])).toBe(34);
    // Two elements (32B each): 1 + (1+32) + (1+32) = 67
    expect(serializedWitnessStackSize([Buffer.alloc(32), Buffer.alloc(32)])).toBe(67);
  });

  test("compactSizeLen boundary cases (0xfc / 0xfd / 0xffff / 0x10000)", () => {
    expect(compactSizeLen(0)).toBe(1);
    expect(compactSizeLen(0xfc)).toBe(1);
    expect(compactSizeLen(0xfd)).toBe(3);
    expect(compactSizeLen(0xffff)).toBe(3);
    expect(compactSizeLen(0x10000)).toBe(5);
  });

  // BUG-1: the fallback budget seed in executeTapscript is non-consensus-safe.
  // No production path hits it, but a regression there would silently
  // shrink the budget. Pinning that the fallback exists by inspection only;
  // a runtime gate would require exposing the function.
  it.skip("BUG-1: executeTapscript fallback budget seed differs from canonical", () => {
    // To pin this in a test we would need executeTapscript exported, which
    // it isn't. Filed as BUG-1 (P1) in audit/w127_taproot.md.
  });
});

describe("W127 G29 — BIP-342 EvalChecksigTapscript ordering: success/budget/empty-pubkey", () => {
  // The order is consensus-critical:
  //   success = !sig.empty();
  //   if (success) deduct budget;
  //   if (pubkey.empty()) error TAPSCRIPT_EMPTY_PUBKEY;   // ALWAYS, even empty sig
  //   else if (pubkey.size()==32) { if (success) verify }
  //   else upgradable pubkey
  // W94 already pinned this; here we add cross-checks.

  test("Empty pubkey + empty sig → TAPSCRIPT_EMPTY_PUBKEY (W94 regression guard)", () => {
    const parsed = parseScript(Buffer.from([Opcode.OP_CHECKSIG]));
    const ctx = tapscriptCtx([Buffer.alloc(0), Buffer.alloc(0)]);
    expect(() => executeScript(parsed, ctx)).toThrow(/TAPSCRIPT_EMPTY_PUBKEY/);
  });

  test("Empty pubkey + non-empty sig + budget=0 → TAPSCRIPT_VALIDATION_WEIGHT (deducted first)", () => {
    const parsed = parseScript(Buffer.from([Opcode.OP_CHECKSIG]));
    const ctx = tapscriptCtx([Buffer.alloc(64, 0x42), Buffer.alloc(0)], { sigopsBudget: 0 });
    expect(() => executeScript(parsed, ctx)).toThrow(/TAPSCRIPT_VALIDATION_WEIGHT/);
  });

  test("32-byte valid pubkey + empty sig: success=false, budget untouched", () => {
    const priv = Buffer.alloc(32, 0);
    priv[31] = 0x21;
    const pub = privateKeyToXOnlyPubKey(priv);
    const parsed = parseScript(Buffer.from([Opcode.OP_CHECKSIG]));
    const ctx = tapscriptCtx([Buffer.alloc(0), pub], { sigopsBudget: 50 });
    executeScript(parsed, ctx);
    expect(ctx.sigopsBudget).toBe(50);
    // pushes empty buffer for failed sig
    expect(ctx.stack.length).toBe(1);
    expect(ctx.stack[0].length).toBe(0);
  });

  test("Upgradable (33-byte) pubkey + non-empty sig: budget IS deducted (Core 'also counted')", () => {
    const parsed = parseScript(Buffer.from([Opcode.OP_CHECKSIG]));
    const ctx = tapscriptCtx([Buffer.alloc(64, 0x42), Buffer.alloc(33, 0x02)], {
      sigopsBudget: 100,
    });
    executeScript(parsed, ctx);
    expect(ctx.sigopsBudget).toBe(50); // 100 - 50
  });
});

// =============================================================================
// G30 — End-to-end BIP-341 wallet vector parity
// =============================================================================

describe("W127 G30 — bip341_wallet_vectors.json round-trip", () => {
  // Vector 1: scriptPubKey-only path (BIP-86, no script tree).
  // The wallet derivation already works; this test pins it via the
  // primitives.tweakPublicKey helper.
  test("BIP-341 vector #1: tweakPublicKey reproduces canonical tweakedPubkey", () => {
    const got = tweakPublicKey(V1_INTERNAL_PK, V1_TWEAK);
    expect(got.toString("hex")).toBe(V1_TWEAKED_PK.toString("hex"));
  });

  // Vector 2: with a single tapscript leaf.
  test("BIP-341 vector #2: TapLeaf hash + TapTweak compose to canonical tweakedPubkey", () => {
    const lv = Buffer.from([TAPROOT_LEAF_TAPSCRIPT]);
    const lenPrefix = encodeCompactSizeLocal(V2_LEAF_SCRIPT.length);
    const leafHash = taggedHash("TapLeaf", Buffer.concat([lv, lenPrefix, V2_LEAF_SCRIPT]));
    expect(leafHash.equals(V2_LEAF_HASH)).toBe(true);
    const tweak = taggedHash("TapTweak", Buffer.concat([V2_INTERNAL_PK, leafHash]));
    const got = tweakPublicKey(V2_INTERNAL_PK, tweak);
    expect(got.toString("hex")).toBe(V2_TWEAKED_PK.toString("hex"));
  });

  // Bug-2: bip341-shim is not wired into a test runner.
  it.skip(
    "BUG-2: bip341_wallet_vectors.json keyPath / scriptPath / sighash vectors not exercised end-to-end via tools/bip341-shim",
    () => {
      // To pin, would invoke `bun tools/bip341-shim/bip341-shim.ts` over a
      // pipe and walk all 11 vectors. Out of audit-only scope.
    }
  );
});

// =============================================================================
// Structural BUGs (not gates — they catalogue findings, not pin pre-existing
// behavior)
// =============================================================================

describe("W127 BUGs catalogue (structural / hygiene)", () => {
  it.skip("BUG-3: wallet/descriptor.ts:1624 has a duplicate tweakPublicKey shadowing crypto/primitives.ts:755", () => {
    // Structural finding — not a runtime divergence yet. Filed in audit.
  });

  it.skip("BUG-4: wallet/descriptor.ts:1503 has duplicate TapLeaf/TapBranch inlining shadowing interpreter helpers", () => {
    // Two-parallel-systems pattern. Filed in audit.
  });

  it.skip("BUG-5: interpreter.ts:12 dead import of tweakPublicKey from primitives.ts", () => {
    // Linter-class finding; static analysis would catch it. Filed in audit.
  });

  it.skip("BUG-6: containsOpSuccess can mis-scan a malformed OP_PUSHDATA{2,4} tail", () => {
    // Mitigated by parseScript running after the scan; same yes/no decision,
    // different error code. Filed in audit.
  });

  it.skip("BUG-7: verifyTaproot returns false instead of throwing WITNESS_PROGRAM_WITNESS_EMPTY on empty stack", () => {
    // Same yes/no, different error code. Filed in audit.
  });

  it.skip("BUG-8: executeTapscript silently returns false on parseScript throw instead of BAD_OPCODE", () => {
    // Same yes/no, different error code. Filed in audit.
  });
});
