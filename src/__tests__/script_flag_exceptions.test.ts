/**
 * Unit tests for getScriptFlagsForBlock — the script-flag exception table.
 *
 * Pins Bitcoin Core's GetBlockScriptFlags (validation.cpp:2249-2289) as a
 * THREE-step sequence, which is the whole point of these tests:
 *
 *   1. BASE      — P2SH | WITNESS | TAPROOT, unconditional, every block (:2262)
 *   2. EXCEPTION — REPLACE the whole set on a block-hash hit (:2264-2267)
 *   3. HEIGHT    — OR DERSIG/CLTV/CSV/NULLDUMMY on top of step 2 (:2268-2286)
 *
 * Step 3 running AFTER step 2 is the property most easily got wrong: an
 * early-return on the exception drops all four height flags, which at block
 * 692261 (exception value P2SH|WITNESS, with all four active at that height)
 * is a FALSE-ACCEPT. Several tests below exist specifically to fail if anyone
 * reintroduces the early return.
 *
 * The six boolean parameters are ONLY the height-gated four; the base trio
 * takes no caller input by design.
 *
 * Reference: Bitcoin Core kernel/chainparams.cpp:85-88, 210-211;
 *            src/validation.cpp:2249-2289.
 */

import { describe, it, expect } from "bun:test";
import { getScriptFlagsForBlock } from "../consensus/connect_block.js";
import { MAINNET, TESTNET } from "../consensus/params.js";
import { ScriptFlags } from "../validation/tx.js";

const BASE_TRIO =
  ScriptFlags.VERIFY_P2SH |
  ScriptFlags.VERIFY_WITNESS |
  ScriptFlags.VERIFY_TAPROOT;

const HEIGHT_FOUR =
  ScriptFlags.VERIFY_DERSIG |
  ScriptFlags.VERIFY_CHECKLOCKTIMEVERIFY |
  ScriptFlags.VERIFY_CHECKSEQUENCEVERIFY |
  ScriptFlags.VERIFY_NULLDUMMY;

describe("getScriptFlagsForBlock — script_flag_exceptions", () => {
  // ── Mainnet BIP16 violator ─────────────────────────────────────────────────
  // Hash: 00000000000002dc756eebf4f49723ed8d30cc28a5f108eb94b1ba88ac4f9c22
  // Block 170060. Core override: SCRIPT_VERIFY_NONE (0).
  const MAINNET_BIP16_VIOLATOR =
    "00000000000002dc756eebf4f49723ed8d30cc28a5f108eb94b1ba88ac4f9c22";

  it("mainnet BIP16 violator at its real height → VERIFY_NONE", () => {
    // Block 170060 predates every height gate on mainnet (bip66=363725,
    // bip65=388381, csv=419328, segwit=481824), so all four are false and the
    // exception's replacement of the base trio is the entire result.
    const flags = getScriptFlagsForBlock(
      MAINNET,
      MAINNET_BIP16_VIOLATOR,
      /* verifyDERSig    */ false,
      /* verifyCLTV      */ false,
      /* verifyCSV       */ false,
      /* verifyNullDummy */ false,
    );
    expect(flags).toBe(ScriptFlags.VERIFY_NONE);
    expect(flags).toBe(0);
  });

  it("mainnet BIP16 violator REPLACES the base trio, but height flags still OR on", () => {
    // Counterfactual: the same hash with all four height gates active. Core's
    // step 2 replaces the trio with 0, then step 3 ORs the four on top — it
    // does NOT return 0. An early-return implementation returns VERIFY_NONE
    // here and fails this test, which is exactly what it is for.
    const flags = getScriptFlagsForBlock(
      MAINNET,
      MAINNET_BIP16_VIOLATOR,
      /* verifyDERSig    */ true,
      /* verifyCLTV      */ true,
      /* verifyCSV       */ true,
      /* verifyNullDummy */ true,
    );
    expect(flags).toBe(HEIGHT_FOUR);
    // The exception stripped every base-trio bit...
    expect(flags & BASE_TRIO).toBe(0);
    // ...but did not swallow the height-gated four.
    expect(flags).not.toBe(ScriptFlags.VERIFY_NONE);
  });

  // ── Mainnet Taproot violator ───────────────────────────────────────────────
  // Hash: 0000000000000000000f14c35b2d841e986ab5441de8c585d5ffe55ea1e395ad
  // Block 692261. Core override: SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS.
  const MAINNET_TAPROOT_VIOLATOR =
    "0000000000000000000f14c35b2d841e986ab5441de8c585d5ffe55ea1e395ad";

  it("mainnet Taproot violator → P2SH|WITNESS from the table PLUS its era's height flags", () => {
    // This is the case the early return got wrong. At height 692261 all four
    // of DERSIG/CLTV/CSV/NULLDUMMY are long active on mainnet, so Core's
    // result is the table value OR those four. Returning P2SH|WITNESS alone
    // would accept scripts Core rejects under BIP-66/65/112/147.
    const flags = getScriptFlagsForBlock(
      MAINNET,
      MAINNET_TAPROOT_VIOLATOR,
      /* verifyDERSig    */ true,
      /* verifyCLTV      */ true,
      /* verifyCSV       */ true,
      /* verifyNullDummy */ true,
    );
    const expected =
      ScriptFlags.VERIFY_P2SH | ScriptFlags.VERIFY_WITNESS | HEIGHT_FOUR;
    expect(flags).toBe(expected);
    // TAPROOT is the bit the exception exists to remove — it must be clear.
    expect(flags & ScriptFlags.VERIFY_TAPROOT).toBe(0);
    // P2SH and WITNESS survive because the table value contains them.
    expect(flags & ScriptFlags.VERIFY_P2SH).toBeTruthy();
    expect(flags & ScriptFlags.VERIFY_WITNESS).toBeTruthy();
    // Regression guard against the early return, stated directly.
    expect(flags).not.toBe(
      ScriptFlags.VERIFY_P2SH | ScriptFlags.VERIFY_WITNESS
    );
  });

  // ── NON-exception hash ─────────────────────────────────────────────────────
  // A different hash must get the unconditional base trio — proving the
  // exception does not over-trigger AND that the trio is not height-gated.
  const NON_EXCEPTION_HASH =
    "0000000000000000000000000000000000000000000000000000000000abcdef";

  it("non-exception hash with no height flags → base trio, NOT zero", () => {
    // Core sets P2SH|WITNESS|TAPROOT on EVERY block regardless of height
    // (:2262). A height-gated implementation returns 0 here at an early
    // height and fails this test.
    const flags = getScriptFlagsForBlock(
      MAINNET,
      NON_EXCEPTION_HASH,
      /* verifyDERSig    */ false,
      /* verifyCLTV      */ false,
      /* verifyCSV       */ false,
      /* verifyNullDummy */ false,
    );
    expect(flags).toBe(BASE_TRIO);
    expect(flags).not.toBe(ScriptFlags.VERIFY_NONE);
  });

  it("non-exception hash with all height flags → trio plus all four", () => {
    const flags = getScriptFlagsForBlock(
      MAINNET,
      NON_EXCEPTION_HASH,
      /* verifyDERSig    */ true,
      /* verifyCLTV      */ true,
      /* verifyCSV       */ true,
      /* verifyNullDummy */ true,
    );
    expect(flags).toBe(BASE_TRIO | HEIGHT_FOUR);
  });

  // ── Testnet3 BIP16 violator ────────────────────────────────────────────────
  // Hash: 00000000dd30457c001f4095d208cc1296b0eed002427aa599874af7a432b105
  // Core override: SCRIPT_VERIFY_NONE (0). Mirrors chainparams.cpp:210-211.
  const TESTNET3_BIP16_VIOLATOR =
    "00000000dd30457c001f4095d208cc1296b0eed002427aa599874af7a432b105";

  it("testnet3 BIP16 violator at its real height → VERIFY_NONE", () => {
    const flags = getScriptFlagsForBlock(
      TESTNET,
      TESTNET3_BIP16_VIOLATOR,
      /* verifyDERSig    */ false,
      /* verifyCLTV      */ false,
      /* verifyCSV       */ false,
      /* verifyNullDummy */ false,
    );
    expect(flags).toBe(ScriptFlags.VERIFY_NONE);
  });

  it("testnet3 BIP16 violator is NOT in the mainnet exception table", () => {
    // Same hash, mainnet params → no match, so the base trio stands.
    const flags = getScriptFlagsForBlock(
      MAINNET,
      TESTNET3_BIP16_VIOLATOR,
      /* verifyDERSig    */ true,
      /* verifyCLTV      */ true,
      /* verifyCSV       */ true,
      /* verifyNullDummy */ true,
    );
    expect(flags).toBe(BASE_TRIO | HEIGHT_FOUR);
    // Specifically: the testnet3 exception must not have stripped the trio.
    expect(flags & BASE_TRIO).toBe(BASE_TRIO);
  });

  it("mainnet Taproot violator hash is NOT in the testnet3 exception table", () => {
    // testnet3 carries only the BIP16 violator.
    const flags = getScriptFlagsForBlock(
      TESTNET,
      MAINNET_TAPROOT_VIOLATOR,
      /* verifyDERSig    */ true,
      /* verifyCLTV      */ false,
      /* verifyCSV       */ false,
      /* verifyNullDummy */ false,
    );
    expect(flags).toBe(BASE_TRIO | ScriptFlags.VERIFY_DERSIG);
    expect(flags & ScriptFlags.VERIFY_TAPROOT).toBeTruthy();
  });
});

// ─── The flag must actually be HONOURED, not just computed ────────────────────
// Wave B fixed getScriptFlagsForBlock so the exception clears TAPROOT at block
// 692261. That was necessary but NOT sufficient: verifyInputSignature had a
// BIP-341 fast path keyed purely on the scriptPubKey SHAPE (OP_1 <32 bytes>)
// that never consulted the flags, so it enforced Taproot anyway and
// FALSE-REJECTED the block. Caught by the tools/phaseb-vectors checkblock
// vector at 692261; guarded here so it cannot regress silently.
//
// Bitcoin Core, VerifyWitnessProgram (script/interpreter.cpp:1947-1950):
//     if (!(flags & SCRIPT_VERIFY_TAPROOT)) return set_success(serror);
//     if (stack.size() == 0) return set_error(serror, ...WITNESS_EMPTY);
// The flag test comes FIRST and returns SUCCESS — a v1 program without the
// TAPROOT flag is an upgradable witness program, i.e. anyone-can-spend.
describe("P2TR spends honour SCRIPT_VERIFY_TAPROOT", () => {
  const { verifyInputSignature } = require("../validation/tx.js") as
    typeof import("../validation/tx.js");

  // OP_1 <32 zero bytes> — a syntactically valid v1 witness program.
  const p2trSpk = Buffer.concat([
    Buffer.from([0x51, 0x20]),
    Buffer.alloc(32, 0),
  ]);
  const mkTx = () => ({
    version: 2,
    inputs: [{
      prevOut: { txid: Buffer.alloc(32, 1), vout: 0 },
      scriptSig: Buffer.alloc(0),
      sequence: 0xffffffff,
      witness: [] as Buffer[],          // EMPTY witness
    }],
    outputs: [{ value: 1000n, scriptPubKey: Buffer.alloc(0) }],
    lockTime: 0,
  }) as unknown as Parameters<typeof verifyInputSignature>[0];
  const utxo = {
    height: 100, coinbase: false, amount: 2000n, scriptPubKey: p2trSpk,
  } as unknown as Parameters<typeof verifyInputSignature>[2];

  it("TAPROOT clear (the 692261 exception case) → anyone-can-spend, VALID", () => {
    const flags = ScriptFlags.VERIFY_P2SH | ScriptFlags.VERIFY_WITNESS; // no TAPROOT
    const r = verifyInputSignature(mkTx(), 0, utxo, {} as never, undefined, undefined, flags);
    expect(r.valid).toBe(true);
  });

  it("TAPROOT set → the empty witness is still rejected", () => {
    const flags = ScriptFlags.VERIFY_P2SH | ScriptFlags.VERIFY_WITNESS |
                  ScriptFlags.VERIFY_TAPROOT;
    const r = verifyInputSignature(mkTx(), 0, utxo, {} as never, undefined, undefined, flags);
    expect(r.valid).toBe(false);
  });
});
