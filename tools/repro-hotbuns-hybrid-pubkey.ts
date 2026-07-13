#!/usr/bin/env bun
/**
 * Reproducer for hotbuns#7 — hybrid pubkey (0x06/0x07) parity byte not validated.
 *
 * THE BUG
 * -------
 * A hybrid-encoded secp256k1 public key is a 65-byte key whose leading tag byte
 * carries the parity of the Y coordinate: 0x06 = HYBRID_EVEN, 0x07 = HYBRID_ODD.
 * The tag is only valid if its low bit matches the actual parity of Y.
 * libsecp256k1 enforces this in secp256k1_eckey_pubkey_parse
 * (bitcoin-core/src/secp256k1/src/eckey_impl.h:28-31):
 *
 *     if ((pub[0] == HYBRID_EVEN || pub[0] == HYBRID_ODD) &&
 *         secp256k1_fe_is_odd(&y) != (pub[0] == HYBRID_ODD)) return 0;
 *
 * Bitcoin Core's CHECKSIG hands the RAW pubkey bytes to
 * secp256k1_ec_pubkey_parse (src/pubkey.cpp CPubKey::Verify), so a wrong-parity
 * hybrid key fails to parse -> the key is invalid -> CHECKSIG pushes FALSE (the
 * script continues; it is not a script error).
 *
 * hotbuns' lax verify path UNCONDITIONALLY rewrote the tag byte to 0x04 before
 * parsing (src/crypto/secp256k1_ffi.ts:405-410 FFI path,
 * src/crypto/primitives.ts:433-438 @noble fallback), which discards the parity
 * tag entirely. A wrong-parity hybrid key + an otherwise-valid ECDSA signature
 * therefore verified TRUE in hotbuns while Core yields FALSE -> false-accept in
 * block validation -> adversarial chain-split (hybrid keys are extinct on the
 * real chain but forgeable in a crafted block).
 *
 * THE ORACLE
 * ----------
 * This process is linked against the SAME libsecp256k1 that Bitcoin Core uses
 * for consensus. parsePubkeyFFI() calls secp256k1_ec_pubkey_parse directly, so
 * parsePubkeyFFI(key) === (Core's CHECKSIG would accept this key). We use it as
 * a ground-truth oracle for the correct parse decision.
 *
 * PASS/FAIL
 * ---------
 *   pre-fix : ecdsaVerifyLaxFFI(sig, msg, wrongParityHybrid) === true   (BUG: false-accept)
 *   post-fix: ecdsaVerifyLaxFFI(sig, msg, wrongParityHybrid) === false  (matches Core/libsecp)
 *   always  : a CORRECT-parity hybrid must still verify TRUE (no over-rejection),
 *             and compressed (0x02/0x03) + uncompressed (0x04) keys are unaffected.
 *
 * Exits non-zero if hotbuns diverges from the libsecp/Core oracle on any vector.
 *
 * Run:  bun run tools/repro-hotbuns-hybrid-pubkey.ts
 */

import { sha256 } from "@noble/hashes/sha2.js";
import { secp256k1 as nobleSecp } from "@noble/curves/secp256k1.js";
import { ecdsaVerifyLaxFFI, parsePubkeyFFI, FFI_AVAILABLE } from "../src/crypto/secp256k1_ffi.js";
// ecdsaVerifyLaxNoble is the extracted @noble fallback path (added by the fix).
// It is imported lazily below so this reproducer still runs pre-fix, when the
// export does not yet exist.

const HYBRID_EVEN = 0x06;
const HYBRID_ODD = 0x07;

function deterministicPrivKey(i: number): Buffer {
  // sha256("hotbuns-7-repro" || i) reduced into a valid, non-zero scalar.
  const seed = Buffer.concat([Buffer.from("hotbuns-7-repro"), Buffer.from([i])]);
  let k = Buffer.from(sha256(seed));
  // Vanishingly unlikely to be 0 / >= n; noble validates on use anyway.
  if (k[0] === 0) k[0] = 1;
  return k;
}

interface Vector {
  name: string;
  key: Buffer;
  // Ground truth from libsecp256k1 (== Bitcoin Core CHECKSIG decision).
  oracleValid: boolean;
}

let failures = 0;
const rows: string[] = [];

function record(
  label: string,
  hotbunsResult: boolean,
  expected: boolean
): void {
  const ok = hotbunsResult === expected;
  if (!ok) failures++;
  rows.push(
    `  ${ok ? "PASS" : "FAIL"}  ${label.padEnd(52)} hotbuns=${String(hotbunsResult).padEnd(5)} expected=${expected}`
  );
}

async function main(): Promise<void> {
  console.log("hotbuns#7 reproducer — hybrid pubkey (0x06/0x07) parity validation\n");
  console.log(`FFI_AVAILABLE=${FFI_AVAILABLE} (consensus path uses libsecp256k1 when true)\n`);

  if (!FFI_AVAILABLE) {
    console.error("libsecp256k1 FFI unavailable — cannot exercise the consensus path / oracle. ABORT.");
    process.exit(2);
  }

  // Try to load the extracted @noble fallback (present only post-fix).
  let ecdsaVerifyLaxNoble: ((s: Buffer, m: Buffer, p: Buffer) => boolean) | null = null;
  try {
    const prim = await import("../src/crypto/primitives.js");
    if (typeof (prim as any).ecdsaVerifyLaxNoble === "function") {
      ecdsaVerifyLaxNoble = (prim as any).ecdsaVerifyLaxNoble;
    }
  } catch {
    /* ignore */
  }

  // Exercise several keys so we cover both real-Y parities.
  for (let i = 0; i < 6; i++) {
    const priv = deterministicPrivKey(i);
    const uncompressed = Buffer.from(nobleSecp.getPublicKey(priv, false)); // 0x04 || X(32) || Y(32)
    const compressed = Buffer.from(nobleSecp.getPublicKey(priv, true)); // 0x02/0x03 || X(32)
    const realYodd = (uncompressed[64] & 1) === 1;

    // Correct-parity hybrid: tag low bit matches Y parity.
    const correctHybrid = Buffer.from(uncompressed);
    correctHybrid[0] = realYodd ? HYBRID_ODD : HYBRID_EVEN;

    // Wrong-parity hybrid: tag low bit deliberately mismatches Y parity.
    const wrongHybrid = Buffer.from(uncompressed);
    wrongHybrid[0] = realYodd ? HYBRID_EVEN : HYBRID_ODD;

    const msg = Buffer.from(sha256(Buffer.concat([Buffer.from("msg"), Buffer.from([i])])));
    const sig = Buffer.from(nobleSecp.sign(msg, priv, { prehash: false, format: "der" }));

    // Ground truth from the SAME C library Core links: does the key parse?
    const vectors: Vector[] = [
      { name: `compressed(0x0${compressed[0]})`, key: compressed, oracleValid: parsePubkeyFFI(compressed) },
      { name: "uncompressed(0x04)", key: uncompressed, oracleValid: parsePubkeyFFI(uncompressed) },
      { name: `hybrid-correct(0x0${correctHybrid[0]})`, key: correctHybrid, oracleValid: parsePubkeyFFI(correctHybrid) },
      { name: `hybrid-WRONG(0x0${wrongHybrid[0]})`, key: wrongHybrid, oracleValid: parsePubkeyFFI(wrongHybrid) },
    ];

    for (const v of vectors) {
      // Core: CHECKSIG accepts iff (key parses) AND (sig valid). Sig is valid by
      // construction, so the CHECKSIG decision == the parse decision == oracleValid.
      const expected = v.oracleValid;
      record(`key#${i} ${v.name} [FFI]`, ecdsaVerifyLaxFFI(sig, msg, v.key), expected);
      if (ecdsaVerifyLaxNoble) {
        record(`key#${i} ${v.name} [@noble]`, ecdsaVerifyLaxNoble(sig, msg, v.key), expected);
      }
    }

    // Sanity: the two hybrids differ ONLY in the tag byte, and the oracle must
    // split them (correct -> valid, wrong -> invalid). If not, the vector is
    // degenerate (e.g. X==0 edge) and would not prove the bug.
    if (i === 0) {
      const correctOK = parsePubkeyFFI(correctHybrid);
      const wrongOK = parsePubkeyFFI(wrongHybrid);
      console.log(
        `oracle split check (key#0): correct-parity hybrid parses=${correctOK}, wrong-parity hybrid parses=${wrongOK}\n`
      );
      if (!correctOK || wrongOK) {
        console.error("Oracle did not split the two hybrids — reproducer vector is degenerate. ABORT.");
        process.exit(2);
      }
    }
  }

  console.log(rows.join("\n"));
  console.log("");
  if (!ecdsaVerifyLaxNoble) {
    console.log("(note: ecdsaVerifyLaxNoble export absent — @noble fallback path not exercised; pre-fix run)\n");
  }

  if (failures > 0) {
    console.error(`RESULT: ${failures} divergence(s) from the libsecp256k1/Core oracle — hotbuns#7 REPRODUCED (RED).`);
    process.exit(1);
  }
  console.log("RESULT: hotbuns matches the libsecp256k1/Core oracle on every vector — hotbuns#7 fixed (GREEN).");
}

main();
