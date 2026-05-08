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
  createPSBT,
  getInputUTXO,
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
