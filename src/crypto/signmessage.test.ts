/**
 * Unit tests for src/crypto/signmessage.ts.
 *
 * These run independently of the RPC layer and cover the BIP-137 / Core
 * MessageSign / MessageVerify primitives directly.
 */

import { describe, it, expect } from "bun:test";
import {
  messageHash,
  messageSign,
  messageVerify,
  privateKeyToP2PKHAddress,
  MessageVerificationResult,
  MESSAGE_MAGIC,
} from "./signmessage.js";

describe("signmessage helpers", () => {
  // Deterministic test key: 32 bytes of 0x11. Same fixture as the RPC
  // round-trip test in rpc/server.test.ts, kept in sync deliberately.
  const PRIVKEY = Buffer.alloc(32, 0x11);
  const REGTEST_ADDR = "n4XmX91N5FfccY678vaG1ELNtXh6skVES7";

  it("messageHash uses the Bitcoin magic prefix", () => {
    // Known property: the first input to the hash writer is the varstr
    // of the magic, so the same message under the same magic must
    // produce the same 32-byte digest.
    const a = messageHash("hello");
    const b = messageHash("hello");
    expect(a.equals(b)).toBe(true);
    expect(a.length).toBe(32);

    // A different message must produce a different hash.
    expect(a.equals(messageHash("world"))).toBe(false);

    // The magic constant must match Core's `Bitcoin Signed Message:\n`.
    expect(MESSAGE_MAGIC).toBe("Bitcoin Signed Message:\n");
  });

  it("privateKeyToP2PKHAddress derives the expected regtest address", () => {
    expect(privateKeyToP2PKHAddress(PRIVKEY, "regtest")).toBe(REGTEST_ADDR);
  });

  it("messageSign produces a 65-byte compact signature (88-char base64)", () => {
    const sig = messageSign(PRIVKEY, "hashhog");
    // Base64 of 65 bytes = ceil(65/3)*4 = 88 chars (single '=' pad).
    expect(sig.length).toBe(88);
    const raw = Buffer.from(sig, "base64");
    expect(raw.length).toBe(65);
    // Header byte for compressed key: 27 + recovery (0..3) + 4 → 31..34.
    expect(raw[0]).toBeGreaterThanOrEqual(31);
    expect(raw[0]).toBeLessThanOrEqual(34);
  });

  it("round-trips: messageVerify(addr, messageSign(priv, msg), msg) === OK", () => {
    const sig = messageSign(PRIVKEY, "round-trip");
    expect(messageVerify(REGTEST_ADDR, sig, "round-trip")).toBe(
      MessageVerificationResult.OK
    );
  });

  it("returns ERR_NOT_SIGNED when the message has been tampered with", () => {
    const sig = messageSign(PRIVKEY, "original");
    expect(messageVerify(REGTEST_ADDR, sig, "tampered")).toBe(
      MessageVerificationResult.ERR_NOT_SIGNED
    );
  });

  it("returns ERR_INVALID_ADDRESS for non-base58check input", () => {
    expect(messageVerify("not-an-address", "AAAA", "msg")).toBe(
      MessageVerificationResult.ERR_INVALID_ADDRESS
    );
  });

  it("returns ERR_ADDRESS_NO_KEY for non-P2PKH base58 versions (e.g. P2SH)", () => {
    // Build a synthetic P2SH (mainnet version 0x05) address with a 20-byte
    // hash, base58check encoded. messageVerify must reject it as no-key.
    // We piggy-back on the encode helper from address/encoding.
    const { base58CheckEncode } = require("../address/encoding.js");
    const fakeP2SH = base58CheckEncode(0x05, Buffer.alloc(20, 0x42));
    // Provide a syntactically-valid 65-byte base64 signature so the
    // address-version check is reached before the signature check.
    const sig = Buffer.alloc(65).toString("base64");
    expect(messageVerify(fakeP2SH, sig, "msg")).toBe(
      MessageVerificationResult.ERR_ADDRESS_NO_KEY
    );
  });

  it("returns ERR_MALFORMED_SIGNATURE for wrong-length sigs", () => {
    expect(messageVerify(REGTEST_ADDR, "AAAA", "msg")).toBe(
      MessageVerificationResult.ERR_MALFORMED_SIGNATURE
    );
  });
});
