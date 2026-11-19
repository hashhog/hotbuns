/**
 * Lax DER long-form length must not wrap (cffix-hotbuns-laxder-length-wrap).
 *
 * Core's ecdsa_signature_parse_der_lax (bitcoin-core/src/pubkey.cpp:45-) reads
 * a long-form R/S length by first skipping leading zero length bytes and then
 * returning 0 (parse failure -> CHECKSIG false) when 4 or more significant
 * length bytes remain, or when the length exceeds the remaining input.
 *
 * hotbuns built the length with `(len << 8) | byte` in a 32-bit int and kept
 * no limit, so the R length `85 01 00 00 00 20` (0x0100000020) wrapped to 0x20
 * and the signature verified. Core rejects it. This only matters where DERSIG
 * is not enforced (pre-BIP66 heights, fresh regtest / custom chains), which is
 * exactly when the lax verifier is reached.
 *
 * Both paths are covered: the libsecp256k1 FFI (`_laxDerToCompact`) when it
 * loads, and the @noble fallback (`laxDerParse`), plus the dispatcher the
 * interpreter calls.
 */

import { describe, expect, test } from "bun:test";
import {
  ecdsaSign,
  ecdsaVerifyLax,
  ecdsaVerifyLaxNoble,
  privateKeyToPublicKey,
} from "../crypto/primitives.js";
import { FFI_AVAILABLE, ecdsaVerifyLaxFFI } from "../crypto/secp256k1_ffi.js";

const PRIVKEY = Buffer.from(
  "0000000000000000000000000000000000000000000000000000000000000007",
  "hex"
);
const MSG = Buffer.alloc(32, 0x5a);
const PUBKEY = privateKeyToPublicKey(PRIVKEY, true);
// @noble signs low-S canonical DER: 30 L 02 rl R 02 sl S
const SIG = ecdsaSign(MSG, PRIVKEY);

function split(sig: Buffer): { r: Buffer; s: Buffer } {
  expect(sig[0]).toBe(0x30);
  expect(sig[2]).toBe(0x02);
  const rl = sig[3];
  const r = sig.subarray(4, 4 + rl);
  expect(sig[4 + rl]).toBe(0x02);
  const sl = sig[5 + rl];
  const s = sig.subarray(6 + rl, 6 + rl + sl);
  return { r, s };
}

/** Re-encode with an arbitrary R length prefix (bytes after the 0x02 tag). */
function withRLength(rLenBytes: number[]): Buffer {
  const { r, s } = split(SIG);
  const body = Buffer.concat([
    Buffer.from([0x02, ...rLenBytes]),
    r,
    Buffer.from([0x02, s.length]),
    s,
  ]);
  return Buffer.concat([Buffer.from([0x30, body.length]), body]);
}

/** Re-encode with an arbitrary S length prefix. */
function withSLength(sLenBytes: number[]): Buffer {
  const { r, s } = split(SIG);
  const body = Buffer.concat([
    Buffer.from([0x02, r.length]),
    r,
    Buffer.from([0x02, ...sLenBytes]),
    s,
  ]);
  return Buffer.concat([Buffer.from([0x30, body.length]), body]);
}

type Verifier = [string, (sig: Buffer) => boolean];
const VERIFIERS: Verifier[] = [
  ["noble", (sig) => ecdsaVerifyLaxNoble(sig, MSG, PUBKEY)],
  ["dispatch", (sig) => ecdsaVerifyLax(sig, MSG, PUBKEY)],
];
if (FFI_AVAILABLE) {
  VERIFIERS.push(["ffi", (sig) => ecdsaVerifyLaxFFI(sig, MSG, PUBKEY)]);
}

describe("lax DER long-form length (Core ecdsa_signature_parse_der_lax)", () => {
  test("FFI loads in this environment (so the FFI path is exercised)", () => {
    expect(FFI_AVAILABLE).toBe(true);
  });

  for (const [name, verify] of VERIFIERS) {
    describe(name, () => {
      // Controls: the encodings Core accepts must still verify.
      test("control: plain encoding verifies", () => {
        expect(verify(SIG)).toBe(true);
      });
      test("control: long-form 81 xx verifies", () => {
        const { r } = split(SIG);
        expect(verify(withRLength([0x81, r.length]))).toBe(true);
      });
      test("control: leading-zero length bytes are skipped (84 00 00 00 xx)", () => {
        const { r } = split(SIG);
        expect(verify(withRLength([0x84, 0x00, 0x00, 0x00, r.length]))).toBe(true);
      });
      test("control: 8 leading-zero length bytes then 1 significant (89 00x8 xx)", () => {
        const { r } = split(SIG);
        expect(verify(withRLength([0x89, 0, 0, 0, 0, 0, 0, 0, 0, r.length]))).toBe(true);
      });

      // The bug: lengths that wrap a 32-bit accumulator.
      test("R length 85 01 00 00 00 xx (wraps to xx) is rejected", () => {
        const { r } = split(SIG);
        expect(verify(withRLength([0x85, 0x01, 0x00, 0x00, 0x00, r.length]))).toBe(false);
      });
      test("S length 85 01 00 00 00 xx (wraps to xx) is rejected", () => {
        const { s } = split(SIG);
        expect(verify(withSLength([0x85, 0x01, 0x00, 0x00, 0x00, s.length]))).toBe(false);
      });
      test("R length 88 01 00 00 00 00 00 00 xx (wraps to xx) is rejected", () => {
        const { r } = split(SIG);
        expect(
          verify(withRLength([0x88, 0x01, 0, 0, 0, 0, 0, 0, r.length]))
        ).toBe(false);
      });
      // Control: 4 significant bytes is rejected (Core lenbyte >= 4).
      test("control: R length with 4 significant bytes (84 01 00 00 xx) is rejected", () => {
        const { r } = split(SIG);
        expect(verify(withRLength([0x84, 0x01, 0x00, 0x00, r.length]))).toBe(false);
      });
      // Long-form count larger than the remaining input is rejected.
      test("sequence length byte count past end of input is rejected", () => {
        expect(verify(Buffer.from([0x30, 0xff, 0x02, 0x01]))).toBe(false);
      });
    });
  }
});
