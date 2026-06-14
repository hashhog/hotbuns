import { describe, expect, test } from "bun:test";
import { bip68VersionActive } from "../validation/tx.js";

// Differential bug-hunt (2026-06-14): the BIP-68 connect-block gates compared
// tx.version signed, while Core stores version as uint32_t and computes
// fEnforceBIP68 = version >= 2 UNSIGNED (tx_verify.cpp:51). hotbuns reads version
// via readInt32LE (signed), so a high-bit version (0x80000002 = -2147483646 as
// int32) read as < 2 would SKIP BIP-68 -> false-accept a tx whose relative
// timelock is unmet (a chain split). bip68VersionActive uses `>>> 0` (unsigned),
// matching the OP_CSV path (interpreter.ts:1249). Pure function -> non-vacuity is
// self-evident: a signed `>= 2` is false for the high-bit cases below.
describe("BIP-68 version gate compares unsigned (Core uint32_t)", () => {
  test("high-bit version 0x80000002 enables BIP-68", () => {
    // readInt32LE gives -2147483646 for the on-wire bytes 0x80000002.
    expect(bip68VersionActive(-2147483646)).toBe(true);
    // 0xFFFFFFFF read signed is -1.
    expect(bip68VersionActive(-1)).toBe(true);
    expect(bip68VersionActive(2)).toBe(true);
    expect(bip68VersionActive(3)).toBe(true);
    expect(bip68VersionActive(1)).toBe(false);
    expect(bip68VersionActive(0)).toBe(false);
  });
});
