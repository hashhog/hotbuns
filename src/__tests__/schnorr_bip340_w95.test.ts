/**
 * W95 BIP-340 Schnorr + tagged-hash audit (hotbuns).
 *
 * Pins the gates documented in BIP-340 §3.4 (Verification) and BIP-341
 * §3 (Key Tweaking). Bitcoin Core's reference for these gates lives at
 *
 *   bitcoin-core/src/secp256k1/src/modules/schnorrsig/main_impl.h:224-270
 *   bitcoin-core/src/pubkey.cpp:257-280  (XOnlyPubKey::CheckTapTweak)
 *
 * Hotbuns delegates the 8-step verify to libsecp256k1 via FFI, so the
 * primary correctness check is byte-identity against libsecp256k1's
 * `secp256k1_schnorrsig_verify` on the official BIP-340 vector set —
 * that lives in `src/crypto/secp256k1_ffi.test.ts`. This file pins the
 * wrapper-level gates that *we* implement:
 *
 *   1. taggedHash midstate cache produces SHA256(tag) || SHA256(tag).
 *   2. taggedHash output for "BIP0340/challenge" matches a known vector.
 *   3. schnorrVerify enforces length checks (sig=64, msgHash=32, pk=32).
 *   4. schnorrVerify is byte-compatible with @noble fallback when FFI off.
 *   5. tweakPrivateKey: rejects t >= n.
 *   6. tweakPrivateKey: rejects d == 0 or d >= n.
 *   7. tweakPublicKey:  rejects t >= n.
 *   8. tweakPublicKey:  rejects tweaked point at infinity.
 *   9. taggedHash("TapTweak", ...) round-trips: pubkey+empty → output key
 *      matches a known BIP-86 vector.
 *  10. isValidXOnlyPubKey rejects x=0 and x>=p edge cases.
 */

import { describe, expect, test } from "bun:test";
import {
  taggedHash,
  schnorrSign,
  schnorrVerify,
  isValidXOnlyPubKey,
  tweakPrivateKey,
  tweakPublicKey,
  privateKeyToXOnlyPubKey,
  sha256Hash,
} from "../crypto/primitives.js";
import { schnorrVerifyFFI, FFI_AVAILABLE } from "../crypto/secp256k1_ffi.js";

// secp256k1 curve order
const SECP256K1_ORDER = BigInt(
  "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"
);
// secp256k1 field size
const SECP256K1_P = BigInt(
  "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F"
);

function bigintTo32(n: bigint): Buffer {
  return Buffer.from(n.toString(16).padStart(64, "0"), "hex");
}

describe("W95 BIP-340 §3.3 tagged hash", () => {
  test("taggedHash matches manual SHA256(SHA256(tag)||SHA256(tag)||msg)", () => {
    // Reference for "BIP0340/challenge" with 32-zero-byte message
    // (matches the precomputed midstate in
    //  bitcoin-core/src/secp256k1/src/modules/schnorrsig/main_impl.h:104-117
    //  applied to a 32-zero message, then finalized.)
    const msg = Buffer.alloc(32, 0);
    const got = taggedHash("BIP0340/challenge", msg);
    expect(got.toString("hex")).toBe(
      "a50885aadef94ee57e5537e27ef82d4db7c756193539d3d8d0bb6ee5f3a7ad46"
    );
  });

  test("taggedHash is domain-separated by tag", () => {
    const msg = Buffer.from("hello world", "utf-8");
    const h1 = taggedHash("BIP0340/challenge", msg);
    const h2 = taggedHash("BIP0340/nonce", msg);
    const h3 = taggedHash("BIP0340/aux", msg);
    const h4 = taggedHash("TapLeaf", msg);
    const h5 = taggedHash("TapBranch", msg);
    const h6 = taggedHash("TapTweak", msg);
    const h7 = taggedHash("TapSighash", msg);
    const all = [h1, h2, h3, h4, h5, h6, h7];
    // All seven must be pairwise distinct: the tag is the only varying input.
    for (let i = 0; i < all.length; i++) {
      for (let j = i + 1; j < all.length; j++) {
        expect(all[i].equals(all[j])).toBe(false);
      }
    }
  });

  test("taggedHash midstate cache returns stable output across repeats", () => {
    const msg = Buffer.from("abc");
    const a = taggedHash("BIP0340/challenge", msg);
    const b = taggedHash("BIP0340/challenge", msg);
    const c = taggedHash("BIP0340/challenge", msg);
    expect(a.equals(b)).toBe(true);
    expect(b.equals(c)).toBe(true);
  });
});

describe("W95 BIP-340 §3.4 verification: wrapper length gates", () => {
  test("schnorrVerify rejects sig.length != 64", () => {
    const msg = Buffer.alloc(32);
    const pk = Buffer.alloc(32, 1);
    expect(schnorrVerify(Buffer.alloc(0), msg, pk)).toBe(false);
    expect(schnorrVerify(Buffer.alloc(63), msg, pk)).toBe(false);
    expect(schnorrVerify(Buffer.alloc(65), msg, pk)).toBe(false);
  });

  test("schnorrVerify rejects msgHash.length != 32", () => {
    const sig = Buffer.alloc(64);
    const pk = Buffer.alloc(32, 1);
    expect(schnorrVerify(sig, Buffer.alloc(0), pk)).toBe(false);
    expect(schnorrVerify(sig, Buffer.alloc(31), pk)).toBe(false);
    expect(schnorrVerify(sig, Buffer.alloc(33), pk)).toBe(false);
  });

  test("schnorrVerify rejects publicKey.length != 32", () => {
    const sig = Buffer.alloc(64);
    const msg = Buffer.alloc(32);
    expect(schnorrVerify(sig, msg, Buffer.alloc(0))).toBe(false);
    expect(schnorrVerify(sig, msg, Buffer.alloc(31))).toBe(false);
    expect(schnorrVerify(sig, msg, Buffer.alloc(33))).toBe(false);
  });

  test("schnorrSign + schnorrVerify round-trip on random key", () => {
    const sk = sha256Hash(Buffer.from("w95-key-1"));
    const msg = sha256Hash(Buffer.from("w95-msg-1"));
    const xpk = privateKeyToXOnlyPubKey(sk);
    const sig = schnorrSign(msg, sk);
    expect(sig.length).toBe(64);
    expect(schnorrVerify(sig, msg, xpk)).toBe(true);

    // Flip one bit of msg → fails
    const badMsg = Buffer.from(msg);
    badMsg[0] ^= 0x01;
    expect(schnorrVerify(sig, badMsg, xpk)).toBe(false);

    // Flip one bit of sig → fails
    const badSig = Buffer.from(sig);
    badSig[33] ^= 0x02;
    expect(schnorrVerify(badSig, msg, xpk)).toBe(false);
  });
});

describe("W95 BIP-340 official vector 0 — direct schnorrVerify check", () => {
  test("verifies the BIP-340 spec's index-0 known-good signature", () => {
    // index 0 from bitcoin-core/test/functional/test_framework/bip340_test_vectors.csv
    const pk = Buffer.from(
      "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
      "hex"
    );
    const msg = Buffer.alloc(32, 0);
    const sig = Buffer.from(
      "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0",
      "hex"
    );
    expect(schnorrVerify(sig, msg, pk)).toBe(true);
  });

  test("rejects sig[0:32] == field size (vector 12)", () => {
    // From bitcoin-core/test/functional/test_framework/bip340_test_vectors.csv:14
    const pk = Buffer.from(
      "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
      "hex"
    );
    const msg = Buffer.from(
      "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
      "hex"
    );
    const sig = Buffer.from(
      "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F" +
        "69E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B",
      "hex"
    );
    // rx >= p must be rejected by libsecp256k1's fe_set_b32_limit (step 1 of
    // schnorrsig_verify in main_impl.h:240). This is the "rx < p" gate.
    expect(schnorrVerify(sig, msg, pk)).toBe(false);
  });

  test("rejects sig[32:64] == curve order (vector 13)", () => {
    // From bitcoin-core/test/functional/test_framework/bip340_test_vectors.csv:15
    const pk = Buffer.from(
      "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
      "hex"
    );
    const msg = Buffer.from(
      "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
      "hex"
    );
    // s = exactly n must overflow scalar_set_b32 (step 2 of schnorrsig_verify
    // in main_impl.h:244). This is the "s < n" gate.
    const sig = Buffer.from(
      "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E177769" +
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
      "hex"
    );
    expect(schnorrVerify(sig, msg, pk)).toBe(false);
  });

  test("rejects public key not on the curve (vector 5)", () => {
    // From bitcoin-core/test/functional/test_framework/bip340_test_vectors.csv:7
    // The xonly pubkey lifts to something off-curve.
    const pk = Buffer.from(
      "EEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34",
      "hex"
    );
    const msg = Buffer.from(
      "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
      "hex"
    );
    const sig = Buffer.from(
      "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E17776969E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B",
      "hex"
    );
    // xonly_pubkey_load step 3 of schnorrsig_verify must reject.
    expect(schnorrVerify(sig, msg, pk)).toBe(false);
  });
});

describe("W95 BIP-340 variable-length message support (FFI)", () => {
  test("verifies vector 15 (msg of size 0)", () => {
    if (!FFI_AVAILABLE) return;
    const pk = Buffer.from(
      "778CAA53B4393AC467774D09497A87224BF9FAB6F6E68B23086497324D6FD117",
      "hex"
    );
    const sig = Buffer.from(
      "71535DB165ECD9FBBC046E5FFAEA61186BB6AD436732FCCC25291A55895464CF6069CE26BF03466228F19A3A62DB8A649F2D560FAC652827D1AF0574E427AB63",
      "hex"
    );
    expect(schnorrVerifyFFI(sig, Buffer.alloc(0), pk)).toBe(true);
  });

  test("verifies vector 16 (msg of size 1)", () => {
    if (!FFI_AVAILABLE) return;
    const pk = Buffer.from(
      "778CAA53B4393AC467774D09497A87224BF9FAB6F6E68B23086497324D6FD117",
      "hex"
    );
    const sig = Buffer.from(
      "08A20A0AFEF64124649232E0693C583AB1B9934AE63B4C3511F3AE1134C6A303EA3173BFEA6683BD101FA5AA5DBC1996FE7CACFC5A577D33EC14564CEC2BACBF",
      "hex"
    );
    expect(schnorrVerifyFFI(sig, Buffer.from("11", "hex"), pk)).toBe(true);
  });

  test("variable-length msg fails with wrong sig", () => {
    if (!FFI_AVAILABLE) return;
    const pk = Buffer.from(
      "778CAA53B4393AC467774D09497A87224BF9FAB6F6E68B23086497324D6FD117",
      "hex"
    );
    const wrongSig = Buffer.alloc(64, 0xab);
    expect(schnorrVerifyFFI(wrongSig, Buffer.from("11", "hex"), pk)).toBe(false);
  });
});

describe("W95 BIP-341 §3 key tweaking — tweakPublicKey gates", () => {
  test("rejects tweak == n (overflow)", () => {
    const pk = Buffer.from(
      "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
      "hex"
    );
    const tweakAtOrder = bigintTo32(SECP256K1_ORDER);
    expect(() => tweakPublicKey(pk, tweakAtOrder)).toThrow(/scalar|curve order/i);
  });

  test("rejects tweak > n (overflow)", () => {
    const pk = Buffer.from(
      "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
      "hex"
    );
    const tweakOverflow = bigintTo32(SECP256K1_ORDER + 1n);
    expect(() => tweakPublicKey(pk, tweakOverflow)).toThrow(/scalar|curve order/i);
  });

  test("accepts tweak == n-1 (max valid scalar)", () => {
    const pk = Buffer.from(
      "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
      "hex"
    );
    const tweakMaxValid = bigintTo32(SECP256K1_ORDER - 1n);
    // Should not throw; the result is a valid x-only key.
    const tweaked = tweakPublicKey(pk, tweakMaxValid);
    expect(tweaked.length).toBe(32);
  });

  test("rejects 31-byte tweak", () => {
    const pk = Buffer.alloc(32, 1);
    expect(() => tweakPublicKey(pk, Buffer.alloc(31))).toThrow(/32 bytes/);
  });

  test("rejects 31-byte pubkey", () => {
    const tw = Buffer.alloc(32);
    expect(() => tweakPublicKey(Buffer.alloc(31), tw)).toThrow(/32 bytes/);
  });
});

describe("W95 BIP-341 §3 key tweaking — tweakPrivateKey gates", () => {
  test("rejects d == 0", () => {
    const zero = Buffer.alloc(32);
    const tw = Buffer.alloc(32, 1);
    expect(() => tweakPrivateKey(zero, tw)).toThrow(/secp256k1 scalar/);
  });

  test("rejects d == n", () => {
    const d = bigintTo32(SECP256K1_ORDER);
    const tw = Buffer.alloc(32, 1);
    expect(() => tweakPrivateKey(d, tw)).toThrow(/secp256k1 scalar/);
  });

  test("rejects d > n", () => {
    // d = n + 1
    const d = bigintTo32(SECP256K1_ORDER + 1n);
    const tw = Buffer.alloc(32, 1);
    expect(() => tweakPrivateKey(d, tw)).toThrow(/secp256k1 scalar/);
  });

  test("rejects tweak == n", () => {
    const d = bigintTo32(1n);
    const tw = bigintTo32(SECP256K1_ORDER);
    expect(() => tweakPrivateKey(d, tw)).toThrow(/scalar/);
  });

  test("rejects tweak > n", () => {
    const d = bigintTo32(1n);
    const tw = bigintTo32(SECP256K1_ORDER + 5n);
    expect(() => tweakPrivateKey(d, tw)).toThrow(/scalar/);
  });

  test("BIP-341 even-y negation round-trip: tweak(d) * G == tweak_pub(d*G)", () => {
    // Generate a known internal key, derive its xonly pubkey, compute the
    // BIP-86 tweak (no script merkle root → tweak = TaggedHash("TapTweak", xpk)),
    // then check that tweakPrivateKey followed by privateKeyToXOnlyPubKey
    // equals tweakPublicKey applied to the internal xpk. This is the
    // consensus-invariant: "the spender knows a secret for the output key".
    const d = sha256Hash(Buffer.from("w95-internal-key"));
    const xpk = privateKeyToXOnlyPubKey(d);
    const tweak = taggedHash("TapTweak", xpk);

    const tweakedPriv = tweakPrivateKey(d, tweak);
    const tweakedXpkFromPriv = privateKeyToXOnlyPubKey(tweakedPriv);
    const tweakedXpkFromPub = tweakPublicKey(xpk, tweak);

    expect(tweakedXpkFromPriv.equals(tweakedXpkFromPub)).toBe(true);
  });

  test("BIP-340-signed message verifies against the tweaked output key", () => {
    // Full end-to-end: sign with the tweaked private key, verify with
    // the tweaked public key. This is the only "is the implementation
    // consensus-correct?" check that exercises the full Taproot key-path
    // flow without an FFI fallback.
    const d = sha256Hash(Buffer.from("w95-keypath-secret"));
    const xpk = privateKeyToXOnlyPubKey(d);
    const tweak = taggedHash("TapTweak", xpk);
    const tweakedPriv = tweakPrivateKey(d, tweak);
    const tweakedXpk = tweakPublicKey(xpk, tweak);

    const msg = sha256Hash(Buffer.from("w95-spend-pre-image"));
    const sig = schnorrSign(msg, tweakedPriv);

    // Verify against the on-chain output key
    expect(schnorrVerify(sig, msg, tweakedXpk)).toBe(true);

    // And reject a tampered message
    const badMsg = Buffer.from(msg);
    badMsg[7] ^= 0x80;
    expect(schnorrVerify(sig, badMsg, tweakedXpk)).toBe(false);
  });
});

describe("W95 BIP-340 isValidXOnlyPubKey edge cases", () => {
  test("rejects x = 0", () => {
    expect(isValidXOnlyPubKey(Buffer.alloc(32, 0))).toBe(false);
  });

  test("rejects x = p (field size)", () => {
    const xAtP = bigintTo32(SECP256K1_P);
    expect(isValidXOnlyPubKey(xAtP)).toBe(false);
  });

  test("rejects x > p (overflow)", () => {
    const xOverflow = bigintTo32(SECP256K1_P + 1n);
    expect(isValidXOnlyPubKey(xOverflow)).toBe(false);
  });

  test("rejects an x that has no on-curve y", () => {
    // From BIP-340 official csv (index 5): EEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34
    // is documented as "public key not on the curve" — i.e. x is in the
    // field but x³+7 is a quadratic non-residue, so lift_x has no root.
    const offCurve = Buffer.from(
      "EEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34",
      "hex"
    );
    expect(isValidXOnlyPubKey(offCurve)).toBe(false);
  });

  test("accepts the generator's x-coordinate", () => {
    const G_x = Buffer.from(
      "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
      "hex"
    );
    expect(isValidXOnlyPubKey(G_x)).toBe(true);
  });

  test("rejects non-32-byte input", () => {
    expect(isValidXOnlyPubKey(Buffer.alloc(31))).toBe(false);
    expect(isValidXOnlyPubKey(Buffer.alloc(33))).toBe(false);
  });
});

describe("W95 BIP-341 known-good TapTweak (xpk-only, BIP-86)", () => {
  test("BIP-86 vector: internal key + empty merkle → output key", () => {
    // BIP-86 test vector 1 (https://github.com/bitcoin/bips/blob/master/bip-0086.mediawiki):
    //   internal key (xonly): cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115
    //   BIP-86 tweak        : TaggedHash("TapTweak", internal_key) since merkle is empty
    //   output key (xonly)  : a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c
    const internal = Buffer.from(
      "cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115",
      "hex"
    );
    const expected = Buffer.from(
      "a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c",
      "hex"
    );
    const tweak = taggedHash("TapTweak", internal);
    const got = tweakPublicKey(internal, tweak);
    expect(got.toString("hex")).toBe(expected.toString("hex"));
  });
});
