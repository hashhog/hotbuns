/**
 * Unit tests for getScriptFlagsForBlock — the script-flag exception table.
 *
 * Covers Bitcoin Core's script_flag_exceptions (validation.cpp:2262-2266):
 *   • mainnet BIP16 violator  → VERIFY_NONE (0)
 *   • mainnet Taproot violator → VERIFY_P2SH | VERIFY_WITNESS (3)
 *   • testnet3 BIP16 violator  → VERIFY_NONE (0)
 *   • non-exception hash at same height → normal height-driven flags
 *
 * Reference: Bitcoin Core kernel/chainparams.cpp:85-88, 210-211;
 *            src/validation.cpp:2262-2266.
 */

import { describe, it, expect } from "bun:test";
import { getScriptFlagsForBlock } from "../consensus/connect_block.js";
import { MAINNET, TESTNET } from "../consensus/params.js";
import { ScriptFlags } from "../validation/tx.js";

describe("getScriptFlagsForBlock — script_flag_exceptions", () => {
  // ── Mainnet BIP16 violator ─────────────────────────────────────────────────
  // Hash: 00000000000002dc756eebf4f49723ed8d30cc28a5f108eb94b1ba88ac4f9c22
  // This block is at a height before BIP16 activation (bip16Height = 173805)
  // so the height-driven booleans are all false except for those active from
  // genesis.  The exception should override to SCRIPT_VERIFY_NONE (0)
  // regardless of what the height booleans would produce.
  const MAINNET_BIP16_VIOLATOR =
    "00000000000002dc756eebf4f49723ed8d30cc28a5f108eb94b1ba88ac4f9c22";

  it("mainnet BIP16 violator → VERIFY_NONE regardless of height booleans", () => {
    // All flags false (pre-BIP16 height).
    const flags = getScriptFlagsForBlock(
      MAINNET,
      MAINNET_BIP16_VIOLATOR,
      /* verifyP2SH      */ false,
      /* verifyWitness   */ false,
      /* verifyTaproot   */ false,
      /* verifyDERSig    */ false,
      /* verifyCLTV      */ false,
      /* verifyCSV       */ false,
      /* verifyNullDummy */ false,
    );
    expect(flags).toBe(ScriptFlags.VERIFY_NONE);
  });

  it("mainnet BIP16 violator → VERIFY_NONE even if height booleans would add flags", () => {
    // All flags true (simulate a post-segwit height) — exception must still win.
    const flags = getScriptFlagsForBlock(
      MAINNET,
      MAINNET_BIP16_VIOLATOR,
      /* verifyP2SH      */ true,
      /* verifyWitness   */ true,
      /* verifyTaproot   */ true,
      /* verifyDERSig    */ true,
      /* verifyCLTV      */ true,
      /* verifyCSV       */ true,
      /* verifyNullDummy */ true,
    );
    expect(flags).toBe(ScriptFlags.VERIFY_NONE);
    expect(flags).toBe(0);
  });

  // ── Mainnet Taproot violator ───────────────────────────────────────────────
  // Hash: 0000000000000000000f14c35b2d841e986ab5441de8c585d5ffe55ea1e395ad
  // Core override: SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS = 3.
  const MAINNET_TAPROOT_VIOLATOR =
    "0000000000000000000f14c35b2d841e986ab5441de8c585d5ffe55ea1e395ad";

  it("mainnet Taproot violator → VERIFY_P2SH | VERIFY_WITNESS only", () => {
    const expected = ScriptFlags.VERIFY_P2SH | ScriptFlags.VERIFY_WITNESS;
    // Height booleans as they would be at post-taproot height.
    const flags = getScriptFlagsForBlock(
      MAINNET,
      MAINNET_TAPROOT_VIOLATOR,
      /* verifyP2SH      */ true,
      /* verifyWitness   */ true,
      /* verifyTaproot   */ true,
      /* verifyDERSig    */ true,
      /* verifyCLTV      */ true,
      /* verifyCSV       */ true,
      /* verifyNullDummy */ true,
    );
    expect(flags).toBe(expected);
    // Taproot flag must NOT be set.
    expect(flags & ScriptFlags.VERIFY_TAPROOT).toBe(0);
    // P2SH and Witness must be set.
    expect(flags & ScriptFlags.VERIFY_P2SH).toBeTruthy();
    expect(flags & ScriptFlags.VERIFY_WITNESS).toBeTruthy();
  });

  // ── NON-exception hash at the BIP16-violator's effective height ───────────
  // A different hash at the same height must produce normal by-height flags.
  // This proves the exception does NOT over-trigger.
  it("non-exception hash at same height → normal height-driven flags", () => {
    const NON_EXCEPTION_HASH =
      "0000000000000000000000000000000000000000000000000000000000abcdef";
    // Use the height-boolean inputs that match the BIP16 violator's era
    // (pre-BIP16: all false).
    const flags = getScriptFlagsForBlock(
      MAINNET,
      NON_EXCEPTION_HASH,
      /* verifyP2SH      */ false,
      /* verifyWitness   */ false,
      /* verifyTaproot   */ false,
      /* verifyDERSig    */ false,
      /* verifyCLTV      */ false,
      /* verifyCSV       */ false,
      /* verifyNullDummy */ false,
    );
    // All booleans false → result should be VERIFY_NONE (but for the right
    // reason: all flags disabled by height, NOT by the exception table).
    expect(flags).toBe(ScriptFlags.VERIFY_NONE);
  });

  it("non-exception hash post-taproot → all flags set", () => {
    const NON_EXCEPTION_HASH =
      "0000000000000000000000000000000000000000000000000000000000abcdef";
    // All post-taproot flags active.
    const flags = getScriptFlagsForBlock(
      MAINNET,
      NON_EXCEPTION_HASH,
      /* verifyP2SH      */ true,
      /* verifyWitness   */ true,
      /* verifyTaproot   */ true,
      /* verifyDERSig    */ true,
      /* verifyCLTV      */ true,
      /* verifyCSV       */ true,
      /* verifyNullDummy */ true,
    );
    const expected =
      ScriptFlags.VERIFY_P2SH |
      ScriptFlags.VERIFY_WITNESS |
      ScriptFlags.VERIFY_TAPROOT |
      ScriptFlags.VERIFY_DERSIG |
      ScriptFlags.VERIFY_CHECKLOCKTIMEVERIFY |
      ScriptFlags.VERIFY_CHECKSEQUENCEVERIFY |
      ScriptFlags.VERIFY_NULLDUMMY;
    expect(flags).toBe(expected);
  });

  // ── Testnet3 BIP16 violator ────────────────────────────────────────────────
  // Hash: 00000000dd30457c001f4095d208cc1296b0eed002427aa599874af7a432b105
  // Core override: SCRIPT_VERIFY_NONE (0). Mirrors chainparams.cpp:210-211.
  const TESTNET3_BIP16_VIOLATOR =
    "00000000dd30457c001f4095d208cc1296b0eed002427aa599874af7a432b105";

  it("testnet3 BIP16 violator → VERIFY_NONE", () => {
    const flags = getScriptFlagsForBlock(
      TESTNET,
      TESTNET3_BIP16_VIOLATOR,
      /* verifyP2SH      */ false,
      /* verifyWitness   */ false,
      /* verifyTaproot   */ false,
      /* verifyDERSig    */ false,
      /* verifyCLTV      */ false,
      /* verifyCSV       */ false,
      /* verifyNullDummy */ false,
    );
    expect(flags).toBe(ScriptFlags.VERIFY_NONE);
  });

  it("testnet3 BIP16 violator NOT in mainnet exception table", () => {
    // The testnet3 exception hash should NOT trigger on mainnet params.
    const flags = getScriptFlagsForBlock(
      MAINNET,
      TESTNET3_BIP16_VIOLATOR,
      /* verifyP2SH      */ true,
      /* verifyWitness   */ true,
      /* verifyTaproot   */ false,
      /* verifyDERSig    */ true,
      /* verifyCLTV      */ true,
      /* verifyCSV       */ true,
      /* verifyNullDummy */ true,
    );
    // No exception match on mainnet → normal flag assembly.
    const expected =
      ScriptFlags.VERIFY_P2SH |
      ScriptFlags.VERIFY_WITNESS |
      ScriptFlags.VERIFY_DERSIG |
      ScriptFlags.VERIFY_CHECKLOCKTIMEVERIFY |
      ScriptFlags.VERIFY_CHECKSEQUENCEVERIFY |
      ScriptFlags.VERIFY_NULLDUMMY;
    expect(flags).toBe(expected);
  });

  // ── Mainnet exceptions not in testnet3 table ──────────────────────────────
  it("mainnet Taproot violator hash NOT in testnet3 exception table", () => {
    // testnet3 only has the BIP16 violator; mainnet Taproot hash is NOT an
    // exception on testnet3.
    const flags = getScriptFlagsForBlock(
      TESTNET,
      MAINNET_TAPROOT_VIOLATOR,
      /* verifyP2SH      */ true,
      /* verifyWitness   */ true,
      /* verifyTaproot   */ true,
      /* verifyDERSig    */ true,
      /* verifyCLTV      */ false,
      /* verifyCSV       */ false,
      /* verifyNullDummy */ false,
    );
    // No exception → normal flags.
    const expected =
      ScriptFlags.VERIFY_P2SH |
      ScriptFlags.VERIFY_WITNESS |
      ScriptFlags.VERIFY_TAPROOT |
      ScriptFlags.VERIFY_DERSIG;
    expect(flags).toBe(expected);
  });
});
