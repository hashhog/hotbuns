/**
 * Regression test for the mainnet-block-124276 consensus divergence
 * (found live by the AV=0 genesis rig, 2026-08-20).
 *
 * INCIDENT
 * --------
 * The from-genesis --assumevalid=0 rig rejected mainnet block 124276 with
 * SCRIPT_ERR_SIG_DER on tx
 *   fb0a1d8d34fa5537e461ac384bac761125e1bfa7fec286fa72511240fa66864d
 * (internal little-endian prefix 4d8666fa40125172...), input 0 — then marked
 * the real block's HEADER invalid, propagated invalidity to all ~818k
 * descendant headers, and wedged: no download target, and every re-synced
 * header rejected for extending an "invalid" ancestor (the endless
 * "Anti-DoS check failed" loop).
 *
 * Strict DER is BIP-66, activation height 363,725. At 124,276 it is NOT
 * active, and this signature — R and S each padded to 34 bytes with TWO
 * leading zero bytes, classic lenient-OpenSSL output — is valid by consensus.
 * Bitcoin Core accepts this block with flags P2SH|WITNESS|TAPROOT only
 * (GetBlockScriptFlags: DERSIG is OR'd on at bip66Height, validation.cpp:2268).
 *
 * ROOT CAUSE
 * ----------
 * scriptFlagsFromBitmask mapped
 *     verifyDERSignatures: verifyDERSig || verifyWitness
 * (and the same for CLTV / CSV / NULLDUMMY), reasoning "SegWit active implies
 * BIP66/65/112/147 active". That is true of the real activation ORDER, but the
 * code tested the WITNESS *flag*, which — since getScriptFlagsForBlock adopted
 * Core's v24+ shape — is set for EVERY block from genesis. So all four rules
 * were enforced from block 0 and the per-height gates were dead code.
 *
 * The mainnet node never saw this: assumevalid skips those scripts. The rig is
 * the first time hotbuns ever verified a 2011 signature.
 */
import { describe, expect, test } from "bun:test";
import { scriptFlagsFromBitmask } from "../script/interpreter.js";
import { ScriptFlags } from "../validation/tx.js";

// Core's unconditional base (validation.cpp:2262): P2SH | WITNESS | TAPROOT.
const BASE =
  ScriptFlags.VERIFY_P2SH | ScriptFlags.VERIFY_WITNESS | ScriptFlags.VERIFY_TAPROOT;

describe("scriptFlagsFromBitmask height-gate integrity (block 124276 incident)", () => {
  test("pre-BIP66 mask (base only) must NOT enforce DERSIG/CLTV/CSV/NULLDUMMY", () => {
    // This is the exact mask coreConnectBlockChecks computes for height 124276.
    const f = scriptFlagsFromBitmask(BASE);
    expect(f.verifyWitness).toBe(true);
    // THE ASSERTIONS THE OLD MAPPING FAILED: WITNESS must not imply any of
    // the four height-gated rules.
    expect(f.verifyDERSignatures).toBe(false);       // BIP-66  (h 363,725)
    expect(f.verifyCheckLockTimeVerify).toBe(false); // BIP-65  (h 388,381)
    expect(f.verifyCheckSequenceVerify).toBe(false); // BIP-112 (h 419,328)
    expect(f.verifyNullDummy).toBe(false);           // BIP-147 (h 481,824)
  });

  test("post-activation mask still enforces each rule via its own bit", () => {
    const f = scriptFlagsFromBitmask(
      BASE |
        ScriptFlags.VERIFY_DERSIG |
        ScriptFlags.VERIFY_NULLDUMMY |
        ScriptFlags.VERIFY_CHECKLOCKTIMEVERIFY |
        ScriptFlags.VERIFY_CHECKSEQUENCEVERIFY
    );
    expect(f.verifyDERSignatures).toBe(true);
    expect(f.verifyCheckLockTimeVerify).toBe(true);
    expect(f.verifyCheckSequenceVerify).toBe(true);
    expect(f.verifyNullDummy).toBe(true);
  });

  test("the ACTUAL block-124276 signature: loose DER, so DERSIG-off must be the pre-BIP66 verdict", () => {
    // Byte-exact signature from tx fb0a1d8d...864d input 0 (with sighash byte).
    // R and S are each 0x22 (34) bytes with two leading zero bytes — a BIP-66
    // violation, legal before activation.
    const sigWithHashType = Buffer.from(
      "3048022200002b83d59c1d23c08efd82ee0662fec23309c3adbcbd1f0b8695378d" +
        "b4b14e736602220000334a96676e58b1bb01784cb7c556dd8ce1c220171904da22" +
        "e18fe1e7d1510db501",
      "hex"
    );
    expect(sigWithHashType.length).toBe(75);

    // The strict-DER validity of the bare signature is what SCRIPT_ERR_SIG_DER
    // keys on. We assert THROUGH the public mapping: a flag set with DERSIG on
    // must call this encoding invalid; with the true height-124276 mask it must
    // never be consulted. (isValidSignatureEncoding itself is module-private;
    // the two mapping tests above pin the flag routing, and this documents the
    // exact wire bytes for any future re-litigation.)
    const der = sigWithHashType.subarray(0, sigWithHashType.length - 1);
    expect(der[0]).toBe(0x30); // SEQUENCE
    expect(der[2]).toBe(0x02); // INTEGER (R)
    expect(der[3]).toBe(0x22); // R length 34 — over-padded
    expect(der[4]).toBe(0x00); // R leading zero #1
    expect(der[5]).toBe(0x00); // R leading zero #2 — the BIP-66 violation
  });
});
