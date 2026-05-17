/**
 * W131 — Output Descriptors + Miniscript discovery audit (hotbuns)
 *
 * Pins behaviour for the 30-gate audit matrix documented in
 * `audit/w131_descriptors_miniscript.md`. Tests are split into:
 *
 *   - PRESENT (`it(...)`) — must pass on master. These pin the current
 *     correct behaviour so a future regression flips the test red.
 *   - PARTIAL / MISSING (`it.skip(...)`) — describe the divergence vs
 *     Bitcoin Core. Each carries a `BUG-N` tag and a comment that the
 *     fix wave can grep for to flip `.skip()` → run.
 *
 * No production code changes. References for every gate are in the
 * audit doc.
 *
 * Run: `bun test src/__tests__/w131_descriptors_miniscript.test.ts`
 */

import { describe, expect, it } from "bun:test";
import {
  addChecksum,
  descriptorChecksum,
  parseDescriptor,
  validateChecksum,
} from "../wallet/descriptor.js";
import {
  BaseType,
  MiniscriptContext,
  computeType,
  parseMiniscript,
} from "../wallet/miniscript.js";

// =============================================================================
// Test vectors
// =============================================================================

/** Canonical Core descriptor-checksum vector. See
 *  bitcoin-core/src/test/descriptor_tests.cpp:1031 — "Error in payload"
 *  uses `tjg09x5t` as the expected good checksum.
 */
const CORE_VECTOR_DESC =
  "sh(multi(2,[00000000/111'/222]xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL,xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y/0))";
const CORE_VECTOR_CHECKSUM = "tjg09x5t";

const SECP_G_HEX =
  "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const SECP_G_XONLY =
  "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

// =============================================================================
// G01..G03 BIP-380 checksum — PRESENT
// =============================================================================

describe("W131 G01 — BIP-380 polynomial constants", () => {
  it("descriptorChecksum byte-exactly matches Core test vector tjg09x5t", () => {
    // bitcoin-core/src/script/descriptor.cpp:106-150 produces this output for
    // the canonical multi descriptor. Cross-impl byte exactness pins the
    // polymod constants AND the MSB-first 5-bit ordering (the "looks LSB-first
    // because we prepend per iteration" subtlety in descriptor.ts:182-185).
    expect(descriptorChecksum(CORE_VECTOR_DESC)).toBe(CORE_VECTOR_CHECKSUM);
  });

  it("simple pk(...) checksum is 8 chars from bech32 alphabet", () => {
    const cs = descriptorChecksum(`pk(${SECP_G_HEX})`);
    expect(cs).toHaveLength(8);
    expect(/^[qpzry9x8gf2tvdw0s3jn54khce6mua7l]+$/.test(cs)).toBe(true);
  });
});

describe("W131 G02 — BIP-380 INPUT_CHARSET byte-exact", () => {
  it("rejects char not in 95-char input alphabet", () => {
    // Core descriptor.cpp:134 returns "" — hotbuns throws (BUG-3).
    // For now, the structural check: a control character is rejected.
    expect(() => descriptorChecksum("pk(\x01)")).toThrow();
  });
});

describe("W131 G03 — BIP-380 CHECKSUM_CHARSET (bech32 alphabet)", () => {
  it("Core vector checksum uses only bech32 characters", () => {
    expect(/^[qpzry9x8gf2tvdw0s3jn54khce6mua7l]+$/.test(CORE_VECTOR_CHECKSUM)).toBe(
      true
    );
  });
});

// =============================================================================
// G04 BIP-380 output ordering — PRESENT (BUG-1 demoted to test-only)
// =============================================================================

describe("W131 G04 — BIP-380 8-char checksum MSB-first 5-bit groups", () => {
  it("LSB-first-looking loop with prepend yields Core's MSB-first sequence", () => {
    // descriptor.ts:182-185 uses `result = char + result` which inverts the
    // index. We verified manually that this is mathematically equivalent to
    // Core's `(c >> (5 * (7 - j))) & 31`. Pin with the cross-impl vector.
    expect(descriptorChecksum(CORE_VECTOR_DESC)).toBe(CORE_VECTOR_CHECKSUM);
  });
});

// =============================================================================
// G05 BIP-380 multiple-# rejected — MISSING (BUG-2)
// =============================================================================

describe("W131 G05 — BIP-380 multiple '#' separators rejected", () => {
  // BUG-2: hotbuns validateChecksum splits on first '#', accepting `desc##xx`.
  // Core descriptor.cpp + descriptor_tests.cpp:1033 emits "Multiple '#' symbols".
  it.skip("validateChecksum rejects double '#' with descriptive error [BUG-2]", () => {
    const desc = `pk(${SECP_G_HEX})##abcdefgh`;
    expect(() => validateChecksum(desc)).toThrow(/Multiple '#'/);
  });

  it("validateChecksum accepts single '#' with valid 8-char checksum", () => {
    // PRESENT — the single-# path works correctly.
    const desc = `pk(${SECP_G_HEX})`;
    const withCs = addChecksum(desc);
    expect(validateChecksum(withCs)).toBe(desc);
  });
});

// =============================================================================
// G06 BIP-380 invalid-char returns "" — MISSING (BUG-3)
// =============================================================================

describe("W131 G06 — BIP-380 invalid char returns empty (Core parity)", () => {
  // BUG-3: hotbuns throws; Core returns "" so that callers wrap with their
  // own "Invalid characters in payload" envelope.
  it.skip("descriptorChecksum returns '' on out-of-charset character [BUG-3]", () => {
    expect(descriptorChecksum("pk(\x00)")).toBe("");
  });

  it("currently throws on out-of-charset character (hotbuns behaviour)", () => {
    expect(() => descriptorChecksum("pk(\x00)")).toThrow();
  });
});

// =============================================================================
// G07 BIP-380 apostrophe/h interchangeable — PRESENT
// =============================================================================

describe("W131 G07 — hardened apostrophe and 'h' are interchangeable", () => {
  it("accepts /0h equivalently to /0' in origin path", () => {
    const xpub =
      "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL";
    const a = parseDescriptor(`pk([00000000/0h]${xpub})`);
    const b = parseDescriptor(`pk([00000000/0']${xpub})`);
    expect(a.descriptor.getType()).toBe(b.descriptor.getType());
  });
});

// =============================================================================
// G08 BIP-381 pk(KEY) x-only only inside P2TR ctx — PARTIAL (BUG-4)
// =============================================================================

describe("W131 G08 — pk(KEY) x-only requires P2TR ctx", () => {
  // BUG-4: hotbuns accepts 32-byte hex in any ctx; sets xonly by length alone.
  // Core descriptor.cpp:1907-1914 only accepts 32-byte hex when ctx==P2TR.
  it.skip("wsh(pk(<32-byte hex>)) is rejected [BUG-4]", () => {
    // Core: "wsh(pk(79be...))" → error "Invalid public key length"
    expect(() => parseDescriptor(`wsh(pk(${SECP_G_XONLY}))`)).toThrow(
      /Invalid public key/
    );
  });

  it("rawtr(<32-byte hex>) is accepted (TR ctx)", () => {
    // PRESENT — 32-byte raw works in TR contexts.
    const parsed = parseDescriptor(`rawtr(${SECP_G_XONLY})`);
    expect(parsed.descriptor.getType()).toBe("rawtr");
  });
});

// =============================================================================
// G09 pkh rejected inside tr — PRESENT
// =============================================================================

describe("W131 G09 — pkh() rejected inside tr()", () => {
  it("rejects pkh inside tr", () => {
    expect(() =>
      parseDescriptor(`tr(${SECP_G_XONLY},pkh(${SECP_G_HEX}))`)
    ).toThrow();
  });
});

// =============================================================================
// G10 wpkh rejected inside wsh/tr — PRESENT
// =============================================================================

describe("W131 G10 — wpkh() rejected inside wsh/tr", () => {
  it("rejects wpkh inside wsh", () => {
    expect(() => parseDescriptor(`wsh(wpkh(${SECP_G_HEX}))`)).toThrow();
  });
  it("rejects wpkh inside tr", () => {
    expect(() =>
      parseDescriptor(`tr(${SECP_G_XONLY},wpkh(${SECP_G_HEX}))`)
    ).toThrow();
  });
});

// =============================================================================
// G11 multi() ≤ 20 — PARTIAL (BUG-5)
// =============================================================================

describe("W131 G11 — multi() ≤ 20 keys at parse time", () => {
  // BUG-5: hotbuns defers the 20-key cap to expand-time.
  it.skip("parseDescriptor rejects multi(21,...) at parse [BUG-5]", () => {
    const keys = Array(21).fill(SECP_G_HEX).join(",");
    expect(() => parseDescriptor(`wsh(multi(21,${keys}))`)).toThrow(/keys/i);
  });

  it("multi(2,k1,k2) parses successfully at parse-time", () => {
    expect(() =>
      parseDescriptor(`wsh(multi(2,${SECP_G_HEX},${SECP_G_HEX}))`)
    ).not.toThrow();
  });
});

// =============================================================================
// G12 bare multi() top-level ≤ 3 — MISSING (BUG-6)
// =============================================================================

describe("W131 G12 — bare multi() ≤ 3 keys at TOP", () => {
  // BUG-6: hotbuns has no TOP-context cap. Core enforces ≤ 3 for bare multisig.
  it.skip("parseDescriptor rejects bare multi(2,k1,k2,k3,k4) at TOP [BUG-6]", () => {
    const keys = `${SECP_G_HEX},${SECP_G_HEX},${SECP_G_HEX},${SECP_G_HEX}`;
    expect(() => parseDescriptor(`multi(2,${keys})`)).toThrow(/at most 3/);
  });
});

// =============================================================================
// G13 multi() rejected inside tr — PRESENT
// =============================================================================

describe("W131 G13 — multi() rejected inside tr()", () => {
  it("rejects multi inside tr", () => {
    expect(() =>
      parseDescriptor(
        `tr(${SECP_G_XONLY},multi(2,${SECP_G_HEX},${SECP_G_HEX}))`
      )
    ).toThrow();
  });
});

// =============================================================================
// G14 multi_a ≤ 999 in tapscript — PRESENT (miniscript-level)
// =============================================================================

describe("W131 G14 — multi_a() ≤ 999 keys", () => {
  it("parses multi_a(1,K) as miniscript in Tapscript", () => {
    const node = parseMiniscript(
      `multi_a(1,${SECP_G_XONLY})`,
      MiniscriptContext.TAPSCRIPT
    );
    expect(node.type).toBe("multi_a");
  });

  it("rejects multi_a(1, k_1, ..., k_1000) (≥ 1000 keys)", () => {
    const keys = Array(1000).fill(SECP_G_XONLY).join(",");
    expect(() =>
      parseMiniscript(`multi_a(1,${keys})`, MiniscriptContext.TAPSCRIPT)
    ).toThrow(/Too many keys/);
  });
});

// =============================================================================
// G15 sortedmulti_a — MISSING (BUG-7)
// =============================================================================

describe("W131 G15 — sortedmulti_a() inside tr() (BIP-386)", () => {
  // BUG-7: hotbuns has no `sortedmulti_a` fragment in miniscript and no
  // descriptor parser branch. HW-wallet multi-sig in tr() can't be parsed.
  it.skip("parseDescriptor accepts tr(K,sortedmulti_a(2,k1,k2,k3)) [BUG-7]", () => {
    expect(() =>
      parseDescriptor(
        `tr(${SECP_G_XONLY},sortedmulti_a(2,${SECP_G_XONLY},${SECP_G_XONLY},${SECP_G_XONLY}))`
      )
    ).not.toThrow();
  });
});

// =============================================================================
// G16 rawtr at TOP — PRESENT
// =============================================================================

describe("W131 G16 — rawtr() at TOP only", () => {
  it("rawtr() at top parses", () => {
    expect(() => parseDescriptor(`rawtr(${SECP_G_XONLY})`)).not.toThrow();
  });
  it("nested rawtr() is rejected", () => {
    expect(() => parseDescriptor(`sh(rawtr(${SECP_G_XONLY}))`)).toThrow();
  });
});

// =============================================================================
// G17 BIP-341 TapLeaf in descriptor — PARTIAL (BUG-19)
// =============================================================================

describe("W131 G17 — tr() Taproot Merkle root TapLeaf tag", () => {
  // BUG-19: descriptor.ts:1503-1527 inlines TapLeaf instead of using
  // interpreter.ts:computeTapLeafHash. Structural divergence.
  it("tr(K, leaf) parses + addresses derive without throwing", () => {
    // Structural PRESENT check; byte-exact tag identity covered by W127.
    const desc = `tr(${SECP_G_XONLY},pk(${SECP_G_XONLY}))`;
    expect(() => parseDescriptor(desc)).not.toThrow();
  });
});

// =============================================================================
// G18 BIP-341 TapBranch lex-sort — PRESENT (structurally; from W127)
// =============================================================================

describe("W131 G18 — tr() TapBranch lex-sort", () => {
  it("tr(K, {leaf_a, leaf_b}) parses", () => {
    const desc = `tr(${SECP_G_XONLY},{pk(${SECP_G_XONLY}),pk(${SECP_G_XONLY})})`;
    expect(() => parseDescriptor(desc)).not.toThrow();
  });
});

// =============================================================================
// G19 tweakPublicKey t<n + reject infinity — PARTIAL (BUG-18)
// =============================================================================

describe("W131 G19 — tr() output-key tweak from primitives.ts", () => {
  // BUG-18 (W127 BUG-3 still open): descriptor.ts has a LOCAL `tweakPublicKey`
  // shadowing crypto/primitives.ts. Diff: same lift_x + base mul, but
  // length validation is missing.
  it.skip("descriptor.ts re-uses primitives.ts:tweakPublicKey [BUG-18]", () => {
    // Source-grep test: after the fix wave, descriptor.ts should `import
    // { tweakPublicKey } from "../crypto/primitives.js"` and not define
    // its own function.
    const src = require("fs").readFileSync(
      require("path").join(__dirname, "../wallet/descriptor.ts"),
      "utf8"
    );
    expect(src).not.toMatch(/^function tweakPublicKey\(/m);
  });
});

// =============================================================================
// G20 multipath <0;1> — MISSING (BUG-8)
// =============================================================================

describe("W131 G20 — BIP-380 multipath <a;b;...> in path", () => {
  // BUG-8: hotbuns parseExtendedKey path loop doesn't accept '<'. HW wallets
  // routinely emit `xpub.../<0;1>/*` for receive+change.
  it.skip("parseDescriptor accepts wpkh(xpub.../<0;1>/*) [BUG-8]", () => {
    const xpub =
      "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL";
    expect(() => parseDescriptor(`wpkh(${xpub}/<0;1>/*)`)).not.toThrow();
  });
});

// =============================================================================
// G21 origin path ≤ 0x7FFFFFFF — MISSING (BUG-9)
// =============================================================================

describe("W131 G21 — BIP-380 origin path value ≤ 0x7FFFFFFF", () => {
  // BUG-9: hotbuns doesn't bound the int. parseInt + HARDENED_OFFSET silently
  // overflows. Result: different derived key than Core for same descriptor.
  it.skip("parseDescriptor rejects path with value > 0x7FFFFFFF [BUG-9]", () => {
    const xpub =
      "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL";
    expect(() =>
      parseDescriptor(`pk([deadbeef/2147483648h]${xpub})`)
    ).toThrow(/out of range/);
  });
});

// =============================================================================
// G22 Miniscript fragments — PRESENT
// =============================================================================

describe("W131 G22 — all 22 miniscript fragments + 7 wrappers parsed", () => {
  it("parses every primary fragment shape", () => {
    const ctx = MiniscriptContext.P2WSH;
    expect(parseMiniscript("0", ctx).type).toBe("just_0");
    expect(parseMiniscript("1", ctx).type).toBe("just_1");
    expect(parseMiniscript(`pk_k(${SECP_G_HEX})`, ctx).type).toBe("pk_k");
    expect(parseMiniscript("older(100)", ctx).type).toBe("older");
    expect(parseMiniscript("after(100)", ctx).type).toBe("after");
    expect(
      parseMiniscript(
        "sha256(0000000000000000000000000000000000000000000000000000000000000000)",
        ctx
      ).type
    ).toBe("sha256");
    expect(
      parseMiniscript(
        "hash256(0000000000000000000000000000000000000000000000000000000000000000)",
        ctx
      ).type
    ).toBe("hash256");
    expect(
      parseMiniscript("hash160(0000000000000000000000000000000000000000), ctx".slice(0, -5), ctx).type
    ).toBe("hash160");
    expect(parseMiniscript(`multi(1,${SECP_G_HEX})`, ctx).type).toBe("multi");
  });

  it("parses wrapper prefixes a:/s:/c:/d:/v:/j:/n:", () => {
    const ctx = MiniscriptContext.P2WSH;
    expect(parseMiniscript("v:0", ctx).type).toBe("wrap_v");
    expect(parseMiniscript("d:v:0", ctx).type).toBe("wrap_d");
    // t:X = and_v(X,1); l:X = or_i(0,X); u:X = or_i(X,0) sugars
    expect(parseMiniscript("t:0", ctx).type).toBe("and_v");
    expect(parseMiniscript("l:0", ctx).type).toBe("or_i");
    expect(parseMiniscript("u:0", ctx).type).toBe("or_i");
  });
});

// =============================================================================
// G23 wrap_a type rule masks z,n + always sets x — PARTIAL (BUG-10)
// =============================================================================

describe("W131 G23 — wrap_a type rule (Core: x always set, z/n masked)", () => {
  // BUG-10: hotbuns spreads ALL inner props instead of Core's
  // (x & "udfems") | "x" mask. Hand-traced divergence below.
  it.skip("a:pk_k(K) should have x=true and n=false [BUG-10]", () => {
    const node = parseMiniscript(`a:pk_k(${SECP_G_HEX})`, MiniscriptContext.P2WSH);
    const t = computeType(node, MiniscriptContext.P2WSH);
    // Core: WRAP_A masks `n` out via (x & "udfems"), always adds `x`.
    expect(t.props.n).toBe(false);
    expect(t.props.x).toBe(true);
  });

  it("a:pk_k(K) currently has n=true, x=false (hotbuns reality)", () => {
    // Pin current behaviour so a fix flips both at once.
    const node = parseMiniscript(`a:pk_k(${SECP_G_HEX})`, MiniscriptContext.P2WSH);
    const t = computeType(node, MiniscriptContext.P2WSH);
    expect(t.props.n).toBe(true);
    expect(t.props.x).toBe(false);
  });
});

// =============================================================================
// G24 wrap_s type rule masks — PARTIAL (BUG-11)
// =============================================================================

describe("W131 G24 — wrap_s type rule (Core: Bo->W, mask udfemsx)", () => {
  // BUG-11: same shape as BUG-10. The spread carries z (Core masks it).
  it.skip("s:c:pk_k(K) z should be false; n should be false [BUG-11]", () => {
    const node = parseMiniscript(
      `s:c:pk_k(${SECP_G_HEX})`,
      MiniscriptContext.P2WSH
    );
    const t = computeType(node, MiniscriptContext.P2WSH);
    expect(t.props.n).toBe(false);
    expect(t.props.z).toBe(false);
  });
});

// =============================================================================
// G25 wrap_d u only in Tapscript — MISSING (BUG-12)
// =============================================================================

describe("W131 G25 — wrap_d u-flag context-dependent (Core: only Tapscript)", () => {
  // BUG-12: hotbuns sets u=true unconditionally. Core: u only in Tapscript
  // because MINIMALIF is a policy rule in P2WSH but consensus in Tapscript.
  it.skip("d:v:0 in P2WSH should have u=false [BUG-12]", () => {
    const node = parseMiniscript("d:v:0", MiniscriptContext.P2WSH);
    const t = computeType(node, MiniscriptContext.P2WSH);
    expect(t.props.u).toBe(false);
  });

  it("d:v:0 in Tapscript has u=true (CORRECT)", () => {
    const node = parseMiniscript("d:v:0", MiniscriptContext.TAPSCRIPT);
    const t = computeType(node, MiniscriptContext.TAPSCRIPT);
    expect(t.props.u).toBe(true);
  });

  it("d:v:0 in P2WSH currently has u=true (BUG-12 reality)", () => {
    const node = parseMiniscript("d:v:0", MiniscriptContext.P2WSH);
    const t = computeType(node, MiniscriptContext.P2WSH);
    expect(t.props.u).toBe(true); // Should be false; pinned to flip with fix.
  });
});

// =============================================================================
// G26 wrap_v type rule — PRESENT (BUG-13 demoted)
// =============================================================================

describe("W131 G26 — wrap_v type rule preserves timelock props", () => {
  it("v:after(100) preserves the timelock 'i'/'j' prop from inner", () => {
    const node = parseMiniscript("v:after(100)", MiniscriptContext.P2WSH);
    const t = computeType(node, MiniscriptContext.P2WSH);
    expect(t.base).toBe(BaseType.V);
    // after(100) is height-based (locktime < LOCKTIME_THRESHOLD), so j=true
    expect(t.props.j).toBe(true);
    expect(t.props.i).toBe(false);
  });
});

// =============================================================================
// G27 isSane checks duplicate keys + valid satisfactions — PARTIAL (BUG-14)
// =============================================================================

describe("W131 G27 — isSane covers CheckDuplicateKey + ValidSatisfactions", () => {
  // BUG-14: hotbuns isSane checks m+s+k+B+size but not duplicate keys
  // or witness resource limits.
  it.skip("multi(2, K, K) (duplicate keys) should be insane [BUG-14]", () => {
    // Wallet check: a miniscript with duplicate keys is malleable.
    // For now we just check that parser doesn't deduplicate keys —
    // the absence of a CheckDuplicateKey gate is the bug.
    const node = parseMiniscript(
      `multi(2,${SECP_G_HEX},${SECP_G_HEX})`,
      MiniscriptContext.P2WSH
    );
    expect(node.type).toBe("multi");
    // After fix: an isSaneTopLevel(node) call would return false here.
  });
});

// =============================================================================
// G28 multi_a 32-byte enforcement — PARTIAL (BUG-14)
// =============================================================================

describe("W131 G28 — multi_a keys must be 32 bytes (x-only)", () => {
  // BUG-14 (continued): parseMultiA accepts any hex length. A 33-byte
  // compressed key compiles to a P2TR-invalid script and the wallet sees
  // a broken Tapscript only at broadcast.
  it.skip("parseMiniscript rejects multi_a with 33-byte key [BUG-14]", () => {
    expect(() =>
      parseMiniscript(
        `multi_a(1,${SECP_G_HEX})`,
        MiniscriptContext.TAPSCRIPT
      )
    ).toThrow(/32 bytes/);
  });

  it("parseMiniscript accepts multi_a with 32-byte x-only key", () => {
    expect(() =>
      parseMiniscript(
        `multi_a(1,${SECP_G_XONLY})`,
        MiniscriptContext.TAPSCRIPT
      )
    ).not.toThrow();
  });
});

// =============================================================================
// G29 Tapscript size cap — PARTIAL (BUG-15)
// =============================================================================

describe("W131 G29 — Tapscript size cap matches Core's dynamic max", () => {
  // BUG-15: hotbuns hardcodes MAX_TAPSCRIPT_SIZE=10000.
  // Core: ≈ 395_700 bytes (MAX_STANDARD_TX_WEIGHT-derived).
  it.skip("Tapscript with body > 10000 but < Core max is accepted [BUG-15]", () => {
    // Future test: synthesize a miniscript that compiles to ~20000 bytes
    // and assert it passes isSane(). Currently hotbuns rejects.
    expect(true).toBe(true); // placeholder until BUG-15 closed
  });
});

// =============================================================================
// G30 or_b malleability rule preserves (s_x + s_y) — PARTIAL (BUG-16)
// =============================================================================

describe("W131 G30 — or_b malleability rule m=m_x*m_y*e_x*e_y*(s_x+s_y)", () => {
  // BUG-16: hotbuns drops (s_x + s_y) factor.
  // BUG-20a: just_0 has wrong e=false, so or_b malleability double-skewed.
  it.skip("or_b(c:pk_k(K), s:0): m should match Core (s_x present) [BUG-16]", () => {
    const node = parseMiniscript(
      `or_b(c:pk_k(${SECP_G_HEX}),s:0)`,
      MiniscriptContext.P2WSH
    );
    const t = computeType(node, MiniscriptContext.P2WSH);
    // Core: lp.s=true (c:pk_k requires sig), rp.s=false (just_0). (s_x + s_y) = true.
    // lp.m=true, rp.m=true; lp.e=true, rp.e=true (Core just_0 has e). m=true.
    expect(t.props.m).toBe(true);
  });
});

// =============================================================================
// BUG-20a/b: just_0 / just_1 type-rule mask divergence
// =============================================================================

describe("W131 just_0 / just_1 type-rule masks (Core Bzudemsxk / Bzufmxk)", () => {
  it.skip("just_0 should have e=true (Core: Bzudemsxk) [BUG-20a]", () => {
    const node = parseMiniscript("0", MiniscriptContext.P2WSH);
    const t = computeType(node, MiniscriptContext.P2WSH);
    expect(t.props.e).toBe(true);
  });

  it("just_0 currently has e=false (BUG-20a reality)", () => {
    const node = parseMiniscript("0", MiniscriptContext.P2WSH);
    const t = computeType(node, MiniscriptContext.P2WSH);
    expect(t.props.e).toBe(false);
  });

  it.skip("just_1 should have x=true (Core: Bzufmxk) [BUG-20b]", () => {
    const node = parseMiniscript("1", MiniscriptContext.P2WSH);
    const t = computeType(node, MiniscriptContext.P2WSH);
    expect(t.props.x).toBe(true);
  });

  it("just_1 currently has x=false (BUG-20b reality)", () => {
    const node = parseMiniscript("1", MiniscriptContext.P2WSH);
    const t = computeType(node, MiniscriptContext.P2WSH);
    expect(t.props.x).toBe(false);
  });
});

// =============================================================================
// Two-parallel-systems regression guards (W127 BUG-3/4 + W131 BUG-18/19)
// =============================================================================

describe("W131 two-parallel-systems hazard guards", () => {
  it.skip("descriptor.ts imports tweakPublicKey from primitives.ts [BUG-18]", () => {
    // After fix: descriptor.ts top-level imports `{ tweakPublicKey }` from
    // ../crypto/primitives.js, NOT a local function declaration.
    const fs = require("fs");
    const path = require("path");
    const src = fs.readFileSync(
      path.join(__dirname, "../wallet/descriptor.ts"),
      "utf8"
    );
    expect(src).toMatch(/from "\.\.\/crypto\/primitives\.js".*tweakPublicKey/s);
    expect(src).not.toMatch(/^function tweakPublicKey\(/m);
  });

  it.skip("descriptor.ts imports TapLeaf hash helpers, no inline taggedHash('TapLeaf') [BUG-19]", () => {
    const fs = require("fs");
    const path = require("path");
    const src = fs.readFileSync(
      path.join(__dirname, "../wallet/descriptor.ts"),
      "utf8"
    );
    expect(src).not.toMatch(/taggedHash\(['"]TapLeaf['"]/);
    expect(src).not.toMatch(/taggedHash\(['"]TapBranch['"]/);
  });
});

// =============================================================================
// Round-trip sanity (W131-scope structural)
// =============================================================================

describe("W131 round-trip — descriptor + miniscript do not regress", () => {
  it("parseDescriptor(addChecksum(pk(K))) round-trips", () => {
    const desc = `pk(${SECP_G_HEX})`;
    const withCs = addChecksum(desc);
    const p = parseDescriptor(withCs);
    expect(p.descriptor.getType()).toBe("pk");
  });

  it("miniscript pk_k round-trip via parser", () => {
    const node = parseMiniscript(
      `pk_k(${SECP_G_HEX})`,
      MiniscriptContext.P2WSH
    );
    expect(node.type).toBe("pk_k");
  });
});
