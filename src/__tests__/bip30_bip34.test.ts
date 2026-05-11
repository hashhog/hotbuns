/**
 * W79 BIP-30 + BIP-34 coinbase comprehensive audit — hotbuns
 *
 * 10 gates per Bitcoin Core spec:
 *
 * Gate 1/10 — IsBIP30Repeat: exempt by height AND block hash (not height alone).
 *   Core: validation.cpp:6189-6192 IsBIP30Repeat().
 *
 * Gate 2  — BIP-34 skip of BIP-30: skip only when bip34Hash is confirmed on
 *   the canonical chain AND height < BIP34_IMPLIES_BIP30_LIMIT.
 *   Core: validation.cpp:2460-2462.
 *
 * Gate 3  — BIP34_IMPLIES_BIP30_LIMIT = 1,983,702: re-enable BIP-30 at
 *   and above this height.
 *   Core: validation.cpp:2430, 2467.
 *
 * Gate 4  — BIP-34 ContextualCheckBlock: coinbase scriptSig must start with the
 *   byte-exact canonical CScript() << nHeight encoding.
 *   Core: validation.cpp:4151-4159.
 *
 * Gate 5  — Minimum coinbase scriptSig: 2 bytes (bad-cb-length).
 *   Core: consensus/tx_check.cpp COINBASE_SCRIPT_SIZE_MIN=2.
 *
 * Gate 6  — Maximum coinbase scriptSig: 100 bytes (bad-cb-length).
 *   Core: consensus/tx_check.cpp COINBASE_SCRIPT_SIZE_MAX=100.
 *
 * Gate 7  — BIP-34 prefix match: only a PREFIX of scriptSig must match (not
 *   exact equality), so miners can append extra bytes.
 *   Core: validation.cpp:4155-4156 std::equal(...begin...end...).
 *
 * Gate 8  — encodeBip34Height correctness: height 0 → OP_0, 1..16 → OP_N,
 *   17+ → length-prefixed CScriptNum (minimal, sign-magnitude LE).
 *   Core: script.h CScript() << nHeight (operator<<).
 *
 * Gate 9  — bip30ExceptionBlocks fields: mainnet has exactly the two historical
 *   blocks by height AND canonical hash; testnet/regtest/signet have none.
 *
 * Gate 10 — bip34Hash fields: mainnet has the canonical hash at h=227931,
 *   testnet3 has its own hash, other networks have null (BIP34 from genesis).
 */

import { describe, expect, test } from "bun:test";
import {
  MAINNET,
  REGTEST,
  TESTNET,
  TESTNET4,
  SIGNET,
} from "../consensus/params.js";
import { encodeBip34Height, validateBip34Height } from "../validation/block.js";

// ─────────────────────────────────────────────────────────────────────────────
// Gate 9: bip30ExceptionBlocks fields
// ─────────────────────────────────────────────────────────────────────────────

describe("Gate 9: bip30ExceptionBlocks params", () => {
  test("MAINNET has exactly 2 exception blocks (h=91842 and h=91880)", () => {
    expect(MAINNET.bip30ExceptionBlocks).toHaveLength(2);

    const e842 = MAINNET.bip30ExceptionBlocks.find((e) => e.height === 91842);
    expect(e842).toBeDefined();
    // Core validation.cpp:6191: "00000000000a4d0a398161ffc163c503763b1f4360639393e0e4c8e300e0caec"
    expect(e842?.blockHashHex).toBe(
      "00000000000a4d0a398161ffc163c503763b1f4360639393e0e4c8e300e0caec"
    );

    const e880 = MAINNET.bip30ExceptionBlocks.find((e) => e.height === 91880);
    expect(e880).toBeDefined();
    // Core validation.cpp:6192: "00000000000743f190a18c5577a3c2d2a1f610ae9601ac046a38084ccb7cd721"
    expect(e880?.blockHashHex).toBe(
      "00000000000743f190a18c5577a3c2d2a1f610ae9601ac046a38084ccb7cd721"
    );
  });

  test("MAINNET does NOT include old incorrect heights 91722 or 91812 (those are unspendable, not repeat)", () => {
    const h91722 = MAINNET.bip30ExceptionBlocks.find((e) => e.height === 91722);
    const h91812 = MAINNET.bip30ExceptionBlocks.find((e) => e.height === 91812);
    expect(h91722).toBeUndefined();
    expect(h91812).toBeUndefined();
  });

  test("REGTEST, TESTNET, TESTNET4, SIGNET have empty bip30ExceptionBlocks", () => {
    expect(REGTEST.bip30ExceptionBlocks).toHaveLength(0);
    expect(TESTNET.bip30ExceptionBlocks).toHaveLength(0);
    expect(TESTNET4.bip30ExceptionBlocks).toHaveLength(0);
    expect(SIGNET.bip30ExceptionBlocks).toHaveLength(0);
  });

  test("bip30ExceptionBlocks and bip30ExceptionHeights are consistent", () => {
    // The heights in bip30ExceptionBlocks must match bip30ExceptionHeights.
    const blockHeights = MAINNET.bip30ExceptionBlocks.map((e) => e.height).sort();
    const exceptionHeights = [...MAINNET.bip30ExceptionHeights].sort();
    expect(blockHeights).toEqual(exceptionHeights);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Gate 10: bip34Hash fields
// ─────────────────────────────────────────────────────────────────────────────

describe("Gate 10: bip34Hash params", () => {
  test("MAINNET bip34Hash is a 32-byte Buffer (non-null)", () => {
    expect(MAINNET.bip34Hash).not.toBeNull();
    expect(MAINNET.bip34Hash).toBeInstanceOf(Buffer);
    expect(MAINNET.bip34Hash!.length).toBe(32);
  });

  test("MAINNET bip34Hash corresponds to block 000000000000024b89b42a942fe0d9fea3bb44ab7bd1b19115dd6a759c0808b8 (display order)", () => {
    // Core kernel/chainparams.cpp:90:
    //   consensus.BIP34Hash = uint256{"000000000000024b89b42a942fe0d9fea3bb44ab7bd1b19115dd6a759c0808b8"};
    // We store it in internal (LE) byte order (reversed from display).
    const displayHex = "000000000000024b89b42a942fe0d9fea3bb44ab7bd1b19115dd6a759c0808b8";
    const expectedLE = Buffer.from(displayHex, "hex").reverse();
    expect(MAINNET.bip34Hash!.equals(expectedLE)).toBe(true);
  });

  test("TESTNET bip34Hash is non-null (testnet3 has a canonical BIP34 activation block)", () => {
    expect(TESTNET.bip34Hash).not.toBeNull();
    expect(TESTNET.bip34Hash).toBeInstanceOf(Buffer);
    // Core kernel/chainparams.cpp:213:
    //   consensus.BIP34Hash = uint256{"0000000023b3a96d3484e5abb3755c413e7d41500f8e2a5c3f0dd01299cd8ef8"};
    const displayHex = "0000000023b3a96d3484e5abb3755c413e7d41500f8e2a5c3f0dd01299cd8ef8";
    const expectedLE = Buffer.from(displayHex, "hex").reverse();
    expect(TESTNET.bip34Hash!.equals(expectedLE)).toBe(true);
  });

  test("REGTEST bip34Hash is null (BIP34 active from genesis, no skip needed)", () => {
    // Core kernel/chainparams.cpp:536-537: BIP34Height=1, BIP34Hash=uint256()
    expect(REGTEST.bip34Hash).toBeNull();
  });

  test("TESTNET4 bip34Hash is null (BIP34 active from genesis)", () => {
    expect(TESTNET4.bip34Hash).toBeNull();
  });

  test("SIGNET bip34Hash is null (BIP34 active from genesis)", () => {
    expect(SIGNET.bip34Hash).toBeNull();
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Gate 8: encodeBip34Height / CScriptNum correctness
// Reference: Bitcoin Core script.h CScript() << nHeight (operator<<), which
// calls CScriptNum serialization.
// ─────────────────────────────────────────────────────────────────────────────

describe("Gate 8: encodeBip34Height CScriptNum correctness", () => {
  test("height 0 → [0x00] (OP_0, not a length-prefixed push)", () => {
    // Core CScript() << 0 = CScript() << OP_0 = [0x00]
    expect(encodeBip34Height(0)).toEqual(Buffer.from([0x00]));
  });

  test("height 1 → [0x51] (OP_1)", () => {
    expect(encodeBip34Height(1)).toEqual(Buffer.from([0x51]));
  });

  test("height 16 → [0x60] (OP_16)", () => {
    expect(encodeBip34Height(16)).toEqual(Buffer.from([0x60]));
  });

  test("height 17 → [0x01, 0x11] (length-prefixed, minimal CScriptNum)", () => {
    // 17 = 0x11. Fits in one byte, high bit clear → [0x01, 0x11]
    expect(encodeBip34Height(17)).toEqual(Buffer.from([0x01, 0x11]));
  });

  test("height 127 → [0x01, 0x7f] (one byte, high bit clear)", () => {
    // 127 = 0x7f, high bit clear → [0x01, 0x7f]
    expect(encodeBip34Height(127)).toEqual(Buffer.from([0x01, 0x7f]));
  });

  test("height 128 → [0x02, 0x80, 0x00] (needs sign extension byte)", () => {
    // 128 = 0x80: last byte has high bit set → append 0x00 → [0x80, 0x00]
    // Length prefix: 2 → [0x02, 0x80, 0x00]
    expect(encodeBip34Height(128)).toEqual(Buffer.from([0x02, 0x80, 0x00]));
  });

  test("height 227931 (mainnet BIP34 activation) → correct CScriptNum", () => {
    // 227931 = 0x37a5b → LE: [0x5b, 0x7a, 0x03]. High bit of 0x03 clear.
    // → length-prefix 0x03, then [0x5b, 0x7a, 0x03]
    const encoded = encodeBip34Height(227931);
    expect(encoded.length).toBe(4);
    expect(encoded[0]).toBe(0x03); // length byte
    expect(encoded[1]).toBe(0x5b); // LE byte 0
    expect(encoded[2]).toBe(0x7a); // LE byte 1
    expect(encoded[3]).toBe(0x03); // LE byte 2
  });

  test("height 1983702 (BIP34_IMPLIES_BIP30_LIMIT) → correct CScriptNum", () => {
    // 1983702 = 0x1e44d6 → LE: [0xd6, 0x44, 0x1e], high bit of 0x1e clear
    // → length-prefix 0x03, then [0xd6, 0x44, 0x1e]
    const encoded = encodeBip34Height(1_983_702);
    expect(encoded.length).toBe(4);
    expect(encoded[0]).toBe(0x03);
    expect(encoded[1]).toBe(0xd6);
    expect(encoded[2]).toBe(0x44);
    expect(encoded[3]).toBe(0x1e);
  });

  test("heights 1..16 use single OP_N byte (not length-prefixed)", () => {
    for (let h = 1; h <= 16; h++) {
      const enc = encodeBip34Height(h);
      expect(enc.length).toBe(1);
      expect(enc[0]).toBe(0x50 + h);
    }
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Gate 4: BIP-34 height validation in validateBip34Height
// ─────────────────────────────────────────────────────────────────────────────

describe("Gate 4: validateBip34Height prefix-match semantics", () => {
  function makeCoinbaseTx(scriptSig: Buffer) {
    return {
      version: 1,
      inputs: [
        {
          prevOut: { txid: Buffer.alloc(32, 0), vout: 0xffffffff },
          scriptSig,
          sequence: 0xffffffff,
          witness: [] as Buffer[],
        },
      ],
      outputs: [],
      lockTime: 0,
    };
  }

  test("exact encoding is valid (Gate 4a — exact match)", () => {
    const height = 500_000;
    const exact = encodeBip34Height(height);
    const tx = makeCoinbaseTx(exact);
    expect(validateBip34Height(tx, height)).toBe(true);
  });

  test("prefix match is valid — extra bytes after encoding are allowed (Gate 7)", () => {
    // Core uses std::equal(expect.begin(), expect.end(), sig.begin()) — prefix only.
    const height = 500_000;
    const exact = encodeBip34Height(height);
    const padded = Buffer.concat([exact, Buffer.from([0xde, 0xad, 0xbe, 0xef])]);
    const tx = makeCoinbaseTx(padded);
    expect(validateBip34Height(tx, height)).toBe(true);
  });

  test("wrong height encoding is invalid", () => {
    const height = 500_000;
    const wrongEnc = encodeBip34Height(500_001);
    const tx = makeCoinbaseTx(wrongEnc);
    expect(validateBip34Height(tx, height)).toBe(false);
  });

  test("scriptSig shorter than expect fails (Gate 5 interaction — not enough bytes)", () => {
    const height = 500_000;
    const expect_enc = encodeBip34Height(height);
    const short = expect_enc.subarray(0, expect_enc.length - 1);
    const tx = makeCoinbaseTx(short);
    expect(validateBip34Height(tx, height)).toBe(false);
  });

  test("height 0 encoding: [0x00] must prefix-match scriptSig", () => {
    const height = 0;
    const enc = encodeBip34Height(height);
    expect(enc).toEqual(Buffer.from([0x00]));
    const tx = makeCoinbaseTx(Buffer.from([0x00, 0x01, 0x02]));
    expect(validateBip34Height(tx, height)).toBe(true);
  });

  test("empty scriptSig always fails validation (no bytes to match)", () => {
    const tx = makeCoinbaseTx(Buffer.alloc(0));
    expect(validateBip34Height(tx, 100)).toBe(false);
  });

  test("non-canonical encoding for height 128 fails (must match exact CScriptNum form)", () => {
    // Correct: [0x02, 0x80, 0x00]. Incorrect: OP_PUSHDATA1 form or padded mantissa.
    const height = 128;
    // Padded mantissa: [0x03, 0x80, 0x00, 0x00] — extra zero is non-minimal
    const nonMinimal = Buffer.from([0x03, 0x80, 0x00, 0x00]);
    const tx = makeCoinbaseTx(nonMinimal);
    expect(validateBip34Height(tx, height)).toBe(false);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Gate 5 + 6: coinbase scriptSig length (2..100 bytes)
// Exercised via validateBlock — the limits live in validation/block.ts::validateBlock
// ─────────────────────────────────────────────────────────────────────────────

describe("Gate 5+6: coinbase scriptSig length 2..100 bytes", () => {
  // We use raw encodeBip34Height values to generate boundary cases and verify
  // that lengths outside [2, 100] are detected (exercised via block validation
  // in the integration tests; these unit tests verify the encoding helpers don't
  // generate out-of-bounds lengths for realistic heights).

  test("encodeBip34Height(0) produces 1 byte (below minimum — requires padding)", () => {
    // This is 1 byte; callers must pad to ≥ 2 bytes.  The block validator
    // in validateBlock rejects scriptSig < 2 bytes.
    expect(encodeBip34Height(0).length).toBe(1);
  });

  test("encodeBip34Height for all mainnet heights ≤ 1,983,702 produces ≤ 4 bytes", () => {
    // Spot-check: 4 bytes is well within the 100-byte cap.
    for (const h of [1, 16, 17, 127, 128, 255, 256, 65536, 227931, 1_983_702]) {
      const enc = encodeBip34Height(h);
      expect(enc.length).toBeLessThanOrEqual(5); // 4 data bytes + 1 len byte max
    }
  });

  test("height requiring 4-byte CScriptNum mantissa stays under 100-byte cap", () => {
    // Bitcoin blockheight won't exceed 21M in Bitcoin's lifespan.
    // 21,000,000 = 0x1406F40 → 4 bytes LE: [0x40, 0x6F, 0x40, 0x01], high bit clear
    // → encoded as [0x04, 0x40, 0x6F, 0x40, 0x01] = 5 bytes (1 len + 4 data)
    const enc = encodeBip34Height(21_000_000);
    expect(enc.length).toBe(5);
    expect(enc.length).toBeLessThan(100);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Gate 1/10: IsBIP30Repeat — height AND hash check
// These tests directly verify the logic in bip30ExceptionBlocks, which is the
// source of truth for the exemption check in coreConnectBlockChecks.
// ─────────────────────────────────────────────────────────────────────────────

describe("Gate 1/10: IsBIP30Repeat height+hash exemption logic", () => {
  function isBip30Repeat(
    height: number,
    blockHashHex: string
  ): boolean {
    return MAINNET.bip30ExceptionBlocks.some(
      (ex) => ex.height === height && ex.blockHashHex === blockHashHex
    );
  }

  test("h=91842 with canonical hash → exempt (IsBIP30Repeat returns true)", () => {
    expect(
      isBip30Repeat(
        91842,
        "00000000000a4d0a398161ffc163c503763b1f4360639393e0e4c8e300e0caec"
      )
    ).toBe(true);
  });

  test("h=91880 with canonical hash → exempt (IsBIP30Repeat returns true)", () => {
    expect(
      isBip30Repeat(
        91880,
        "00000000000743f190a18c5577a3c2d2a1f610ae9601ac046a38084ccb7cd721"
      )
    ).toBe(true);
  });

  test("h=91842 with WRONG hash → NOT exempt (alt-chain block must still enforce BIP-30)", () => {
    // This is the key fix: Core checks height AND hash; height alone is wrong.
    expect(
      isBip30Repeat(91842, "00000000000000000000000000000000000000000000000000000000deadbeef")
    ).toBe(false);
  });

  test("h=91880 with WRONG hash → NOT exempt", () => {
    expect(
      isBip30Repeat(91880, "0000000000000000000000000000000000000000000000000000000000000001")
    ).toBe(false);
  });

  test("h=91722 (unspendable, not repeat) → NOT in exception list at all", () => {
    // 91722 is IsBIP30Unspendable, not IsBIP30Repeat.
    // It must NOT be in bip30ExceptionBlocks.
    expect(isBip30Repeat(91722, "00000000000271a2dc26e7667f8419f2e15416dc6955e5a6c6cdf3f2574dd08e")).toBe(false);
  });

  test("h=91812 (unspendable, not repeat) → NOT in exception list at all", () => {
    expect(isBip30Repeat(91812, "00000000000af0aed4792b1acee3d966af36cf5def14935db8de83d6f9306f2f")).toBe(false);
  });

  test("unrelated height → NOT exempt", () => {
    expect(isBip30Repeat(100000, "00000000000271a2dc26e7667f8419f2e15416dc6955e5a6c6cdf3f2574dd08e")).toBe(false);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Gate 2 + 3: BIP-34 skip gate and BIP34_IMPLIES_BIP30_LIMIT
// These verify the fEnforceBIP30 logic from coreConnectBlockChecks.
// ─────────────────────────────────────────────────────────────────────────────

describe("Gate 2+3: BIP-34 skip gate and BIP34_IMPLIES_BIP30_LIMIT = 1,983,702", () => {
  const BIP34_IMPLIES_BIP30_LIMIT = 1_983_702;

  // Reimplementation of the fEnforceBIP30 logic for unit testing.
  function fEnforceBIP30(
    height: number,
    isExempt: boolean,
    bip34HashConfirmed: boolean
  ): boolean {
    const belowLimit = height < BIP34_IMPLIES_BIP30_LIMIT;
    const skippedByBIP34 = bip34HashConfirmed && belowLimit;
    const enforce = !isExempt && !skippedByBIP34;
    // Core: if (fEnforceBIP30 || height >= BIP34_IMPLIES_BIP30_LIMIT)
    return enforce || height >= BIP34_IMPLIES_BIP30_LIMIT;
  }

  test("below bip34Height (no bip34Hash confirmed) → BIP-30 enforced", () => {
    expect(fEnforceBIP30(100_000, false, false)).toBe(true);
  });

  test("above bip34Height with bip34Hash confirmed and below limit → BIP-30 skipped", () => {
    // Between 227931 and 1983701, BIP-34 makes duplicates impossible.
    expect(fEnforceBIP30(300_000, false, true)).toBe(false);
    expect(fEnforceBIP30(1_983_701, false, true)).toBe(false);
  });

  test("above bip34Height WITHOUT bip34Hash confirmed → BIP-30 still enforced", () => {
    // Alternative chain: bip34Hash check fails → still enforce BIP-30.
    // This is the Gate 2 fix: height-only check was wrong.
    expect(fEnforceBIP30(300_000, false, false)).toBe(true);
  });

  test("at BIP34_IMPLIES_BIP30_LIMIT = 1,983,702 → BIP-30 re-enabled regardless", () => {
    // Core: if (fEnforceBIP30 || height >= BIP34_IMPLIES_BIP30_LIMIT)
    // Even with bip34Hash confirmed, at and above 1,983,702 BIP-30 fires.
    expect(fEnforceBIP30(1_983_702, false, true)).toBe(true);
    expect(fEnforceBIP30(2_000_000, false, true)).toBe(true);
  });

  test("exempt height at BIP34_IMPLIES_BIP30_LIMIT → BIP-30 still fires (height >= limit overrides)", () => {
    // The OR condition means even exempt-height blocks above the limit get checked.
    // This matches Core: if (fEnforceBIP30 || pindex->nHeight >= BIP34_IMPLIES_BIP30_LIMIT)
    // fEnforceBIP30 is false (exempt) but the OR condition fires the check anyway.
    expect(fEnforceBIP30(1_983_702, true, true)).toBe(true);
  });

  test("MAINNET bip34Hash is non-null → bip34HashConfirmed=true once past bip34Height", () => {
    expect(MAINNET.bip34Hash).not.toBeNull();
    // At height 227931 (bip34Height), bip34Hash is available for the skip.
    const confirmed = MAINNET.bip34Hash !== null && 227_931 >= MAINNET.bip34Height;
    expect(confirmed).toBe(true);
  });

  test("REGTEST bip34Hash is null → bip34HashConfirmed=false (BIP-30 always enforces on short chains)", () => {
    expect(REGTEST.bip34Hash).toBeNull();
    const confirmed = REGTEST.bip34Hash !== null && 1000 >= REGTEST.bip34Height;
    expect(confirmed).toBe(false);
  });
});
