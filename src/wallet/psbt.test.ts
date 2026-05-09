/**
 * PSBT signer-side defenses against UTXO-amount oracle attacks.
 *
 * Covers W41 follow-up to the W40-A audit:
 *   - A1 (`nonWitnessUtxo` txid vs outpoint) is enforced earlier in
 *     `deserializePSBT` (psbt.ts:1107-1116) and is verified here as still in
 *     place.
 *   - A2 (CVE-2020-14199): when a PSBT input carries BOTH `witnessUtxo`
 *     AND `nonWitnessUtxo`, `getInputUTXO` cross-checks that the witness
 *     amount + scriptPubKey agree with the corresponding output of the
 *     full prevtx; otherwise it throws and signing fails closed.
 *
 * Reference: bitcoin-core/src/psbt.cpp `PSBTInput::IsSane`,
 * bitcoin-core/src/wallet/scriptpubkeyman.cpp (post-CVE-2020-14199 amount
 * cross-check).
 */

import { describe, expect, test } from "bun:test";
import { hash160, privateKeyToPublicKey } from "../crypto/primitives";
import {
  type Transaction,
  type TxOut,
  SIGHASH_ALL,
} from "../validation/tx";
import {
  addPartialSignature,
  analyzePSBTCore,
  createPSBT,
  finalizePSBTInput,
  getInputUTXO,
  isInputFinalized,
  parseMultisigThreshold,
  signPSBTInput,
} from "./psbt";

// =============================================================================
// Test helpers (asymmetric Buffer fixtures per W32-B rule — no palindromes)
// =============================================================================

function makeKey(seed: number): { priv: Buffer; pub: Buffer } {
  const priv = Buffer.alloc(32);
  // Asymmetric: distinct head + tail bytes derived from seed.
  priv[0] = 0x02;
  priv[1] = (seed * 31) & 0xff;
  priv[2] = (seed * 17) & 0xff;
  priv.writeUInt32BE(0x01_00_00_00 | (seed & 0xff), 28);
  const pub = privateKeyToPublicKey(priv, true);
  return { priv, pub };
}

/** Asymmetric 32-byte txid (head/tail differ). */
function makeAsymTxid(tag: number): Buffer {
  const b = Buffer.alloc(32);
  for (let i = 0; i < 32; i++) {
    // Simple but asymmetric pattern depending on position + tag.
    b[i] = ((i * 7 + tag * 31 + 0x4d) & 0xff) ^ (i & 0x0f);
  }
  // Force head != tail just in case.
  b[0] = (0xa0 ^ tag) & 0xff;
  b[31] = (0x5e ^ tag) & 0xff;
  return b;
}

/** Build a P2WPKH scriptPubKey for a given pubkey: OP_0 <hash160(pub)>. */
function p2wpkhScript(pub: Buffer): Buffer {
  return Buffer.concat([Buffer.from([0x00, 0x14]), hash160(pub)]);
}

/** Build a synthetic prevtx that pays `value` to `scriptPubKey` at vout 0. */
function makePrevTx(scriptPubKey: Buffer, value: bigint, tag: number): Transaction {
  return {
    version: 2,
    inputs: [
      {
        prevOut: { txid: makeAsymTxid(0xee ^ tag), vout: 7 },
        scriptSig: Buffer.alloc(0),
        sequence: 0xffffffff,
        witness: [],
      },
    ],
    outputs: [{ value, scriptPubKey }],
    lockTime: 0,
  };
}

/** Build an unsigned spend tx referencing prevTxid at vout 0. */
function makeSpendTx(prevTxid: Buffer, value: bigint): Transaction {
  // Asymmetric dummy P2WPKH output (each byte distinct from neighbors).
  const dummyHash = Buffer.alloc(20);
  for (let i = 0; i < 20; i++) dummyHash[i] = (i * 13 + 0x37) & 0xff;
  return {
    version: 2,
    inputs: [
      {
        prevOut: { txid: prevTxid, vout: 0 },
        scriptSig: Buffer.alloc(0),
        sequence: 0xffffffff,
        witness: [],
      },
    ],
    outputs: [
      {
        value: value - 1000n,
        scriptPubKey: Buffer.concat([Buffer.from([0x00, 0x14]), dummyHash]),
      },
    ],
    lockTime: 0,
  };
}

// =============================================================================
// A2 regression: CVE-2020-14199 amount/script cross-check
// =============================================================================

describe("PSBT WITNESS_UTXO cross-check (CVE-2020-14199, W41)", () => {
  test("A1 sanity: deserialize-time txid check is still in place at psbt.ts:1107-1116", () => {
    // We don't re-test the deserializer end-to-end here (covered by other
    // suites); this is a structural sentinel — A1 SHOULD live in the
    // deserialization path (the audit cites psbt.ts:1107-1116). If a future
    // refactor moves the logic, this test fails loudly so the audit doc and
    // commit message can be updated.
    const src = require("fs").readFileSync(
      require("path").resolve(__dirname, "psbt.ts"),
      "utf8"
    ) as string;
    expect(src).toContain("Non-witness UTXO does not match outpoint");
    expect(src).toContain("getTxId(input.nonWitnessUtxo)");
  });

  test("A2 amount mismatch: signing fails when witnessUtxo.value != nonWitnessUtxo.outputs[vout].value", () => {
    const k = makeKey(101);
    const scriptPubKey = p2wpkhScript(k.pub);
    const honestValue = 250_000n;
    const lyingValue = 999_999_999n; // attacker tries to inflate fee oracle

    // Honest prevtx says 250_000; malicious witnessUtxo claims ~10 BTC.
    const prevTx = makePrevTx(scriptPubKey, honestValue, 0x01);
    const spendTx = makeSpendTx(makeAsymTxid(0x01), honestValue);

    const psbt = createPSBT(spendTx);
    psbt.inputs[0].nonWitnessUtxo = prevTx;
    psbt.inputs[0].witnessUtxo = { value: lyingValue, scriptPubKey };

    // getInputUTXO must fail closed (defense-in-depth — covers any future
    // caller, not just signPSBTInput).
    expect(() => getInputUTXO(psbt, 0)).toThrow(/CVE-2020-14199/);
    expect(() => getInputUTXO(psbt, 0)).toThrow(/witnessUtxo\.value/);

    // signPSBTInput must therefore also reject.
    expect(() =>
      signPSBTInput(psbt, 0, k.priv, k.pub, SIGHASH_ALL)
    ).toThrow(/CVE-2020-14199/);

    // No partial sigs were stored before the throw.
    expect(psbt.inputs[0].partialSigs.size).toBe(0);
  });

  test("A2 scriptPubKey mismatch: signing fails when witnessUtxo.scriptPubKey != nonWitnessUtxo.outputs[vout].scriptPubKey", () => {
    const kHonest = makeKey(102);
    const kAttacker = makeKey(103);
    const honestScript = p2wpkhScript(kHonest.pub);
    const attackerScript = p2wpkhScript(kAttacker.pub);
    const value = 175_000n;

    // Both UTXOs claim same value but bind different scripts. A naive signer
    // would honor witnessUtxo and produce a sig under attackerScript while
    // believing it spent honestScript — exactly the oracle attack shape.
    const prevTx = makePrevTx(honestScript, value, 0x02);
    const spendTx = makeSpendTx(makeAsymTxid(0x02), value);

    const psbt = createPSBT(spendTx);
    psbt.inputs[0].nonWitnessUtxo = prevTx;
    psbt.inputs[0].witnessUtxo = { value, scriptPubKey: attackerScript };

    expect(() => getInputUTXO(psbt, 0)).toThrow(/CVE-2020-14199/);
    expect(() => getInputUTXO(psbt, 0)).toThrow(/scriptPubKey/);

    expect(() =>
      signPSBTInput(psbt, 0, kHonest.priv, kHonest.pub, SIGHASH_ALL)
    ).toThrow(/CVE-2020-14199/);

    expect(psbt.inputs[0].partialSigs.size).toBe(0);
  });

  test("A2 happy path: matching witnessUtxo + nonWitnessUtxo allows getInputUTXO to return the witness entry unchanged", () => {
    const k = makeKey(104);
    const scriptPubKey = p2wpkhScript(k.pub);
    const value = 333_333n;

    const prevTx = makePrevTx(scriptPubKey, value, 0x03);
    const spendTx = makeSpendTx(makeAsymTxid(0x03), value);

    const psbt = createPSBT(spendTx);
    psbt.inputs[0].nonWitnessUtxo = prevTx;
    psbt.inputs[0].witnessUtxo = { value, scriptPubKey };

    // Return shape unchanged: should yield the same TxOut as before the W41
    // check landed (the witnessUtxo entry, by reference).
    const got = getInputUTXO(psbt, 0);
    expect(got).toBeDefined();
    expect(got!.value).toBe(value);
    expect(got!.scriptPubKey.equals(scriptPubKey)).toBe(true);
    expect(got).toBe(psbt.inputs[0].witnessUtxo!);
  });

  test("A2 vout out of range: signing fails with a clear error rather than silently trusting witnessUtxo", () => {
    const k = makeKey(105);
    const scriptPubKey = p2wpkhScript(k.pub);
    const value = 12_345n;

    // prevtx only has 1 output (vout=0) but spend points at vout=5.
    const prevTx: Transaction = {
      version: 2,
      inputs: [
        {
          prevOut: { txid: makeAsymTxid(0x55), vout: 0 },
          scriptSig: Buffer.alloc(0),
          sequence: 0xffffffff,
          witness: [],
        },
      ],
      outputs: [{ value, scriptPubKey }],
      lockTime: 0,
    };
    const spendTx: Transaction = {
      version: 2,
      inputs: [
        {
          prevOut: { txid: makeAsymTxid(0x66), vout: 5 },
          scriptSig: Buffer.alloc(0),
          sequence: 0xffffffff,
          witness: [],
        },
      ],
      outputs: [{ value: value - 100n, scriptPubKey }],
      lockTime: 0,
    };

    const psbt = createPSBT(spendTx);
    psbt.inputs[0].nonWitnessUtxo = prevTx;
    psbt.inputs[0].witnessUtxo = { value, scriptPubKey };

    expect(() => getInputUTXO(psbt, 0)).toThrow(/out of range/);
  });
});

// =============================================================================
// W43: legacy P2SH-multisig finalize branch
//
// Regression for W42-A: finalizePSBTInput was missing a branch for legacy
// P2SH-multisig (only P2SH-P2WPKH and P2SH-P2WSH were dispatched on a
// redeemScript). A pure-multisig redeemScript fell through to `return false`,
// which made `tools/psbt-multi-input-test.sh` impossible to pass for hotbuns
// (input 0 of the W40-C fixture is exactly this case).
//
// The new branch must order signatures by pubkey-position in the redeemScript
// (CHECKMULTISIG is order-sensitive), NOT by partialSig insertion order. We
// exercise that explicitly by inserting the partial sigs in REVERSE pubkey
// order and asserting the resulting scriptSig still spells them in script
// order.
//
// Reference: existing buildP2WSHWitness (psbt.ts) and ProduceSignature in
// bitcoin-core/src/script/sign.cpp.
// =============================================================================

describe("PSBT finalize: legacy P2SH-multisig (W43)", () => {
  /** Build a 2-of-2 P2SH-multisig redeemScript for two distinct pubkeys. */
  function build2of2Redeem(pubA: Buffer, pubB: Buffer): Buffer {
    // OP_2 <0x21 pubA> <0x21 pubB> OP_2 OP_CHECKMULTISIG
    return Buffer.concat([
      Buffer.from([0x52]), // OP_2
      Buffer.from([0x21]),
      pubA,
      Buffer.from([0x21]),
      pubB,
      Buffer.from([0x52]), // OP_2
      Buffer.from([0xae]), // OP_CHECKMULTISIG
    ]);
  }

  /** P2SH scriptPubKey: OP_HASH160 <hash160(redeem)> OP_EQUAL. */
  function p2shScript(redeem: Buffer): Buffer {
    return Buffer.concat([
      Buffer.from([0xa9, 0x14]),
      hash160(redeem),
      Buffer.from([0x87]),
    ]);
  }

  test("finalize 2-of-2 P2SH-multisig with sigs inserted in REVERSE pubkey order — scriptSig follows redeemScript order", () => {
    // Use distinct seeds to guarantee asymmetric pubkey bytes (W32-B).
    const kA = makeKey(241);
    const kB = makeKey(242);
    expect(kA.pub.equals(kB.pub)).toBe(false);

    const redeem = build2of2Redeem(kA.pub, kB.pub);
    const spk = p2shScript(redeem);
    const value = 271_828n;

    const prevTx = makePrevTx(spk, value, 0xa3);
    const spendTx = makeSpendTx(makeAsymTxid(0xa3), value);

    const psbt = createPSBT(spendTx);
    psbt.inputs[0].nonWitnessUtxo = prevTx;
    psbt.inputs[0].redeemScript = redeem;

    // Asymmetric, distinguishable fake-DER signatures (NOT real ECDSA — we
    // only exercise the finalize/assembly path, not signature verification).
    // Each sig is unique so we can assert ordering precisely.
    const sigA = Buffer.alloc(72);
    for (let i = 0; i < 72; i++) sigA[i] = (i * 11 + 0xa1) & 0xff;
    sigA[0] = 0x30;
    sigA[71] = 0x01; // SIGHASH_ALL

    const sigB = Buffer.alloc(71);
    for (let i = 0; i < 71; i++) sigB[i] = (i * 13 + 0xb2) & 0xff;
    sigB[0] = 0x30;
    sigB[70] = 0x01; // SIGHASH_ALL

    expect(sigA.equals(sigB)).toBe(false);
    expect(sigA[0]).not.toBe(sigA[sigA.length - 1]);
    expect(sigB[0]).not.toBe(sigB[sigB.length - 1]);

    // Insert in REVERSE pubkey order (B first, then A). The finalizer must
    // STILL emit them in script order (A then B).
    addPartialSignature(psbt, 0, kB.pub, sigB);
    addPartialSignature(psbt, 0, kA.pub, sigA);

    const ok = finalizePSBTInput(psbt, 0);
    expect(ok).toBe(true);
    expect(isInputFinalized(psbt.inputs[0])).toBe(true);

    const ss = psbt.inputs[0].finalScriptSig!;
    expect(ss).toBeDefined();
    expect(psbt.inputs[0].finalScriptWitness).toBeUndefined();

    // Expected layout: OP_0 <push sigA> <push sigB> <push redeem>
    //                   sigA before sigB because kA is first in redeem.
    const pushSigA = Buffer.concat([Buffer.from([sigA.length]), sigA]);
    const pushSigB = Buffer.concat([Buffer.from([sigB.length]), sigB]);
    // redeem is < 0x4c bytes? No — 2-of-2 redeem is 1+1+33+1+33+1+1 = 71
    // bytes which is still < 0x4c (76). Use the same single-byte length push.
    expect(redeem.length).toBeLessThan(0x4c);
    const pushRedeem = Buffer.concat([Buffer.from([redeem.length]), redeem]);

    const expected = Buffer.concat([
      Buffer.from([0x00]), // OP_0 (CHECKMULTISIG dummy / NULLDUMMY)
      pushSigA,
      pushSigB,
      pushRedeem,
    ]);
    expect(ss.equals(expected)).toBe(true);

    // Sentinel: clearSigningData ran (W41 cleanup parity).
    expect(psbt.inputs[0].partialSigs.size).toBe(0);
    expect(psbt.inputs[0].redeemScript).toBeUndefined();
  });

  test("finalize fails (returns false) when only 1 of 2 partial sigs are present", () => {
    const kA = makeKey(243);
    const kB = makeKey(244);
    const redeem = build2of2Redeem(kA.pub, kB.pub);
    const spk = p2shScript(redeem);
    const value = 314_159n;

    const prevTx = makePrevTx(spk, value, 0xa4);
    const spendTx = makeSpendTx(makeAsymTxid(0xa4), value);

    const psbt = createPSBT(spendTx);
    psbt.inputs[0].nonWitnessUtxo = prevTx;
    psbt.inputs[0].redeemScript = redeem;

    const sigA = Buffer.alloc(70);
    for (let i = 0; i < 70; i++) sigA[i] = (i * 17 + 0xc1) & 0xff;
    sigA[0] = 0x30;
    sigA[69] = 0x01;

    addPartialSignature(psbt, 0, kA.pub, sigA);

    const ok = finalizePSBTInput(psbt, 0);
    expect(ok).toBe(false);
    expect(isInputFinalized(psbt.inputs[0])).toBe(false);
    // Partial sigs must NOT be cleared on failure.
    expect(psbt.inputs[0].partialSigs.size).toBe(1);
    expect(psbt.inputs[0].redeemScript).toBeDefined();
  });
});

// =============================================================================
// W47: analyzepsbt per-input role classifier + PSBT-level next rollup.
//
// Mirrors the OCaml regression added in camlcoin commit `2a22a0e` (W41).
// The W40-C harness (tools/psbt-multi-input-test.sh) reported camlcoin's
// analyzepsbt returning next="signer" on a fixture whose two inputs each
// have all required partial sigs; Bitcoin Core 31.99 reports next="finalizer".
// We reproduce the bug-shape here so hotbuns can't regress.
//
// Reference: bitcoin-core/src/node/psbt.cpp `AnalyzePSBT`.
// Reference: camlcoin lib/psbt.ml `psbt_next_role` (W41 / 2a22a0e).
// =============================================================================

describe("analyzepsbt: per-input role classifier + PSBT-level next (W47)", () => {
  /** Build a 2-of-2 P2SH-multisig redeemScript for two distinct pubkeys. */
  function build2of2Redeem(pubA: Buffer, pubB: Buffer): Buffer {
    return Buffer.concat([
      Buffer.from([0x52]), // OP_2
      Buffer.from([0x21]), pubA,
      Buffer.from([0x21]), pubB,
      Buffer.from([0x52]), // OP_2
      Buffer.from([0xae]), // OP_CHECKMULTISIG
    ]);
  }

  /** P2SH scriptPubKey: OP_HASH160 <hash160(redeem)> OP_EQUAL. */
  function p2shScript(redeem: Buffer): Buffer {
    return Buffer.concat([
      Buffer.from([0xa9, 0x14]),
      hash160(redeem),
      Buffer.from([0x87]),
    ]);
  }

  /** Asymmetric fake-DER signature. NOT a valid ECDSA sig — we only
   *  exercise the classifier, not signature verification. */
  function makeFakeSig(seed: number): Buffer {
    const sig = Buffer.alloc(70);
    for (let i = 0; i < 70; i++) sig[i] = (i * 17 + seed) & 0xff;
    sig[0] = 0x30;
    sig[69] = 0x01; // SIGHASH_ALL
    return sig;
  }

  test("parseMultisigThreshold extracts (2, 2) and the two pubkeys from a bare 2-of-2 CHECKMULTISIG", () => {
    const kA = makeKey(401);
    const kB = makeKey(402);
    const redeem = build2of2Redeem(kA.pub, kB.pub);

    const ms = parseMultisigThreshold(redeem);
    expect(ms).toBeDefined();
    expect(ms!.m).toBe(2);
    expect(ms!.n).toBe(2);
    expect(ms!.pubkeys).toHaveLength(2);
    expect(ms!.pubkeys[0].equals(kA.pub)).toBe(true);
    expect(ms!.pubkeys[1].equals(kB.pub)).toBe(true);
  });

  test("W40-C regression: 2-of-2 P2SH-multisig with both partial sigs → next='finalizer' (NOT 'signer')", () => {
    // This mirrors camlcoin's W41 regression test exactly: a PSBT whose
    // single input has every required signature must report
    // next='finalizer', not 'signer', because the next role is the
    // finalizer (not yet another signer).
    const kA = makeKey(411);
    const kB = makeKey(412);
    const redeem = build2of2Redeem(kA.pub, kB.pub);
    const spk = p2shScript(redeem);
    const value = 271_828n;

    const prevTx = makePrevTx(spk, value, 0xb1);
    const spendTx = makeSpendTx(makeAsymTxid(0xb1), value);

    const psbt = createPSBT(spendTx);
    psbt.inputs[0].nonWitnessUtxo = prevTx;
    psbt.inputs[0].redeemScript = redeem;
    addPartialSignature(psbt, 0, kA.pub, makeFakeSig(0xa1));
    addPartialSignature(psbt, 0, kB.pub, makeFakeSig(0xb2));

    const a = analyzePSBTCore(psbt);
    expect(a.inputs).toHaveLength(1);
    expect(a.inputs[0].has_utxo).toBe(true);
    expect(a.inputs[0].is_final).toBe(false);
    expect(a.inputs[0].next).toBe("finalizer");
    expect(a.inputs[0].missing).toBeUndefined();
    expect(a.next).toBe("finalizer");
  });

  test("partially-signed 2-of-2 P2SH-multisig (1 of 2) → next='signer' + missing.signatures lists the absent pubkey", () => {
    const kA = makeKey(421);
    const kB = makeKey(422);
    const redeem = build2of2Redeem(kA.pub, kB.pub);
    const spk = p2shScript(redeem);
    const value = 314_159n;

    const prevTx = makePrevTx(spk, value, 0xb2);
    const spendTx = makeSpendTx(makeAsymTxid(0xb2), value);

    const psbt = createPSBT(spendTx);
    psbt.inputs[0].nonWitnessUtxo = prevTx;
    psbt.inputs[0].redeemScript = redeem;
    // Only kA has signed.
    addPartialSignature(psbt, 0, kA.pub, makeFakeSig(0xc3));

    const a = analyzePSBTCore(psbt);
    expect(a.inputs).toHaveLength(1);
    expect(a.inputs[0].has_utxo).toBe(true);
    expect(a.inputs[0].is_final).toBe(false);
    expect(a.inputs[0].next).toBe("signer");
    expect(a.inputs[0].missing).toBeDefined();
    expect(a.inputs[0].missing!.signatures).toEqual([kB.pub.toString("hex")]);
    expect(a.next).toBe("signer");
  });

  test("finalized PSBT (final_script_sig set) → next='extractor' at both per-input and PSBT level", () => {
    const kA = makeKey(431);
    const kB = makeKey(432);
    const redeem = build2of2Redeem(kA.pub, kB.pub);
    const spk = p2shScript(redeem);
    const value = 161_803n;

    const prevTx = makePrevTx(spk, value, 0xb3);
    const spendTx = makeSpendTx(makeAsymTxid(0xb3), value);

    const psbt = createPSBT(spendTx);
    psbt.inputs[0].nonWitnessUtxo = prevTx;
    // Stash a non-empty final_script_sig — its exact bytes don't matter
    // for analyzepsbt (we only check is_final).
    psbt.inputs[0].finalScriptSig = Buffer.from([0x00, 0x47, 0x30]);

    const a = analyzePSBTCore(psbt);
    expect(a.inputs).toHaveLength(1);
    expect(a.inputs[0].is_final).toBe(true);
    expect(a.inputs[0].next).toBe("extractor");
    expect(a.next).toBe("extractor");
  });

  test("PSBT-level next is the MIN of per-input roles (mixed: one finalizer + one updater → 'updater')", () => {
    // Two inputs: input 0 has utxo+sigs (finalizer); input 1 has no utxo
    // (updater). PSBT-level next must be 'updater' (the rarer role wins
    // because it's earlier in Core's role order).
    const kA = makeKey(441);
    const kB = makeKey(442);
    const redeem = build2of2Redeem(kA.pub, kB.pub);
    const spk = p2shScript(redeem);
    const value = 999_999n;

    const prevTx = makePrevTx(spk, value, 0xb4);
    const spendTx: Transaction = {
      version: 2,
      inputs: [
        {
          prevOut: { txid: makeAsymTxid(0xb4), vout: 0 },
          scriptSig: Buffer.alloc(0),
          sequence: 0xffffffff,
          witness: [],
        },
        {
          prevOut: { txid: makeAsymTxid(0xb5), vout: 0 },
          scriptSig: Buffer.alloc(0),
          sequence: 0xffffffff,
          witness: [],
        },
      ],
      outputs: [
        {
          value: value - 2000n,
          scriptPubKey: Buffer.concat([
            Buffer.from([0x00, 0x14]),
            // Distinct asymmetric dummy hash (W32-B).
            Buffer.from(Array.from({ length: 20 }, (_, i) => (i * 13 + 0x73) & 0xff)),
          ]),
        },
      ],
      lockTime: 0,
    };

    const psbt = createPSBT(spendTx);
    // Input 0 is fully signed (finalizer).
    psbt.inputs[0].nonWitnessUtxo = prevTx;
    psbt.inputs[0].redeemScript = redeem;
    addPartialSignature(psbt, 0, kA.pub, makeFakeSig(0xa9));
    addPartialSignature(psbt, 0, kB.pub, makeFakeSig(0xba));
    // Input 1 has no UTXO at all.

    const a = analyzePSBTCore(psbt);
    expect(a.inputs).toHaveLength(2);
    expect(a.inputs[0].next).toBe("finalizer");
    expect(a.inputs[1].has_utxo).toBe(false);
    expect(a.inputs[1].next).toBe("updater");
    expect(a.next).toBe("updater");
  });
});
