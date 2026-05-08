/**
 * BIP-143 segwit-v0 P2WSH + P2SH-P2WSH signing & verification tests.
 *
 * Covers W29-D Phase-2 signer additions in `psbt.ts`:
 *   - signPSBTInput dispatch on bare P2WSH scriptPubKey + witnessScript
 *   - signPSBTInput dispatch on P2SH-P2WSH (redeemScript = OP_0 <32B>)
 *   - finalizePSBTInput building witness `[OP_0 dummy, sigs..., witnessScript]`
 *
 * Each test signs with the wallet path, finalizes the PSBT, extracts the
 * transaction, and runs the full hotbuns script interpreter (verifyAllInputs)
 * with mainnet-active consensus flags — the same path IBD/mempool use. That
 * means the witness must satisfy DERSIG, NULLDUMMY, MINIMALDATA, etc., or
 * verification fails closed.
 */

import { describe, expect, test } from "bun:test";
import {
  hash160,
  sha256Hash,
  privateKeyToPublicKey,
} from "../crypto/primitives";
import {
  type Transaction,
  type TxOut,
  SIGHASH_ALL,
  verifyAllInputsSequential,
} from "../validation/tx";
import type { UTXOEntry } from "../storage/database";
import {
  createPSBT,
  signPSBTInput,
  finalizePSBT,
  extractTransaction,
} from "./psbt";

// =============================================================================
// Test helpers
// =============================================================================

function makeKey(seed: number): { priv: Buffer; pub: Buffer } {
  // Deterministic 32-byte private key in [1, n) — for tests the exact value
  // doesn't matter as long as it's a valid scalar. Avoid 0 by ORing seed in.
  const priv = Buffer.alloc(32);
  priv.writeUInt32BE(0x01_00_00_00 | (seed & 0xff), 28);
  // Make the high bytes distinct so different seeds give different keys.
  priv[0] = 0x02;
  priv[1] = (seed * 31) & 0xff;
  priv[2] = (seed * 17) & 0xff;
  const pub = privateKeyToPublicKey(priv, true);
  return { priv, pub };
}

/** Build a bare M-of-N CHECKMULTISIG script: OP_M <pk1> ... <pkN> OP_N OP_CHECKMULTISIG */
function buildMultisigScript(m: number, pubkeys: Buffer[]): Buffer {
  const n = pubkeys.length;
  const parts: Buffer[] = [Buffer.from([0x50 + m])]; // OP_M (OP_1=0x51)
  for (const pk of pubkeys) {
    if (pk.length !== 33) throw new Error("test helper: expects compressed pubkeys");
    parts.push(Buffer.from([0x21]));
    parts.push(pk);
  }
  parts.push(Buffer.from([0x50 + n])); // OP_N
  parts.push(Buffer.from([0xae])); // OP_CHECKMULTISIG
  return Buffer.concat(parts);
}

/** Build a P2WSH scriptPubKey: OP_0 <sha256(witnessScript)> */
function p2wshScriptPubKey(witnessScript: Buffer): Buffer {
  const h = sha256Hash(witnessScript);
  return Buffer.concat([Buffer.from([0x00, 0x20]), h]);
}

/** Build a P2SH scriptPubKey: OP_HASH160 <hash160(redeemScript)> OP_EQUAL */
function p2shScriptPubKey(redeemScript: Buffer): Buffer {
  const h = hash160(redeemScript);
  return Buffer.concat([Buffer.from([0xa9, 0x14]), h, Buffer.from([0x87])]);
}

/** Build the redeemScript that nests P2WSH inside P2SH: OP_0 <sha256(ws)>. */
function p2shP2wshRedeemScript(witnessScript: Buffer): Buffer {
  const h = sha256Hash(witnessScript);
  return Buffer.concat([Buffer.from([0x00, 0x20]), h]);
}

/** Build a stub funding tx that pays `amount` to `scriptPubKey` at vout 0. */
function makePrevTx(scriptPubKey: Buffer, amount: bigint): {
  tx: Transaction;
  txid: Buffer;
} {
  const tx: Transaction = {
    version: 2,
    inputs: [
      {
        prevOut: { txid: Buffer.alloc(32, 0xee), vout: 0 },
        scriptSig: Buffer.alloc(0),
        sequence: 0xffffffff,
        witness: [],
      },
    ],
    outputs: [{ value: amount, scriptPubKey }],
    lockTime: 0,
  };
  // Synthetic txid: hash a unique tag so each test gets a different prevout.
  const txid = sha256Hash(
    Buffer.concat([Buffer.from("p2wsh-test-prev"), scriptPubKey, Buffer.from(amount.toString())])
  );
  return { tx, txid };
}

/** Build an unsigned spending tx: 1 input from `prev`, 1 output to dummy P2WPKH. */
function makeSpendTx(prevTxid: Buffer, value: bigint): Transaction {
  // dummy P2WPKH output: OP_0 <20 bytes>
  const dummyOut: TxOut = {
    value: value - 1000n, // 1000 sat fee
    scriptPubKey: Buffer.concat([Buffer.from([0x00, 0x14]), Buffer.alloc(20, 0x42)]),
  };
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
    outputs: [dummyOut],
    lockTime: 0,
  };
}

// =============================================================================
// Tests
// =============================================================================

describe("BIP-143 P2WSH multisig signing", () => {
  test("P2WSH 2-of-3 multisig: PSBT sign + finalize + interpreter verify", () => {
    const k1 = makeKey(1);
    const k2 = makeKey(2);
    const k3 = makeKey(3);
    const witnessScript = buildMultisigScript(2, [k1.pub, k2.pub, k3.pub]);
    const scriptPubKey = p2wshScriptPubKey(witnessScript);
    const value = 100_000n;

    const { txid } = makePrevTx(scriptPubKey, value);
    const spendTx = makeSpendTx(txid, value);

    const psbt = createPSBT(spendTx);
    psbt.inputs[0].witnessUtxo = { value, scriptPubKey };
    psbt.inputs[0].witnessScript = witnessScript;

    // Sign with k1 and k3 (skip k2 to exercise non-contiguous ordering).
    signPSBTInput(psbt, 0, k1.priv, k1.pub, SIGHASH_ALL);
    signPSBTInput(psbt, 0, k3.priv, k3.pub, SIGHASH_ALL);

    expect(psbt.inputs[0].partialSigs.size).toBe(2);

    const allFinal = finalizePSBT(psbt);
    expect(allFinal).toBe(true);

    const witness = psbt.inputs[0].finalScriptWitness;
    expect(witness).toBeDefined();
    expect(witness!.length).toBe(4); // [OP_0 dummy, sig_k1, sig_k3, witnessScript]
    expect(witness![0].length).toBe(0); // CHECKMULTISIG dummy must be empty (NULLDUMMY)
    // Witness script must be the last element on the stack.
    expect(witness![witness!.length - 1].equals(witnessScript)).toBe(true);

    // Run the full script interpreter — same path IBD uses.
    const signedTx = extractTransaction(psbt);
    const utxo: UTXOEntry = {
      height: 100_000,
      coinbase: false,
      amount: value,
      scriptPubKey,
    };
    const result = verifyAllInputsSequential(signedTx, [utxo]);
    expect(result.valid).toBe(true);
  });

  test("P2SH-P2WSH 2-of-2 multisig: PSBT sign + finalize + interpreter verify", () => {
    const k1 = makeKey(11);
    const k2 = makeKey(12);
    const witnessScript = buildMultisigScript(2, [k1.pub, k2.pub]);
    const redeemScript = p2shP2wshRedeemScript(witnessScript);
    const scriptPubKey = p2shScriptPubKey(redeemScript);
    const value = 250_000n;

    const { txid } = makePrevTx(scriptPubKey, value);
    const spendTx = makeSpendTx(txid, value);

    const psbt = createPSBT(spendTx);
    psbt.inputs[0].witnessUtxo = { value, scriptPubKey };
    psbt.inputs[0].redeemScript = redeemScript;
    psbt.inputs[0].witnessScript = witnessScript;

    signPSBTInput(psbt, 0, k1.priv, k1.pub, SIGHASH_ALL);
    signPSBTInput(psbt, 0, k2.priv, k2.pub, SIGHASH_ALL);

    const allFinal = finalizePSBT(psbt);
    expect(allFinal).toBe(true);

    // scriptSig must wrap the segwit redeemScript as a single push.
    const finalScriptSig = psbt.inputs[0].finalScriptSig;
    expect(finalScriptSig).toBeDefined();
    // Push of 34-byte redeemScript: prefix 0x22 then redeemScript.
    expect(finalScriptSig![0]).toBe(0x22);
    expect(finalScriptSig!.subarray(1).equals(redeemScript)).toBe(true);

    const witness = psbt.inputs[0].finalScriptWitness;
    expect(witness).toBeDefined();
    expect(witness!.length).toBe(4); // [dummy, sig_k1, sig_k2, witnessScript]
    expect(witness![0].length).toBe(0);

    const signedTx = extractTransaction(psbt);
    const utxo: UTXOEntry = {
      height: 100_000,
      coinbase: false,
      amount: value,
      scriptPubKey,
    };
    const result = verifyAllInputsSequential(signedTx, [utxo]);
    expect(result.valid).toBe(true);
  });

  test("PSBT-finalized witness === manual canonical witness (parallel-impl-drift sentinel)", () => {
    // Sign the same input twice: once via signPSBTInput+finalizePSBT, once by
    // hand-rolling the canonical BIP-143 witness assembly. The two witness
    // stacks must be byte-identical. This catches drift between hotbuns's
    // PSBT signer and the canonical BIP-143 multisig assembly used by the
    // other 9 impls (pattern: lunarblock W28 a977878, blockbrew W27-D 5d9d942).
    const k1 = makeKey(21);
    const k2 = makeKey(22);
    const k3 = makeKey(23);
    const witnessScript = buildMultisigScript(2, [k1.pub, k2.pub, k3.pub]);
    const scriptPubKey = p2wshScriptPubKey(witnessScript);
    const value = 500_000n;

    const { txid } = makePrevTx(scriptPubKey, value);
    const spendTx = makeSpendTx(txid, value);

    // ---- PSBT path -----------------------------------------------------
    const psbt = createPSBT({
      version: spendTx.version,
      inputs: spendTx.inputs.map((i) => ({ ...i })),
      outputs: spendTx.outputs.map((o) => ({ ...o })),
      lockTime: spendTx.lockTime,
    });
    psbt.inputs[0].witnessUtxo = { value, scriptPubKey };
    psbt.inputs[0].witnessScript = witnessScript;
    signPSBTInput(psbt, 0, k1.priv, k1.pub, SIGHASH_ALL);
    signPSBTInput(psbt, 0, k2.priv, k2.pub, SIGHASH_ALL);
    expect(finalizePSBT(psbt)).toBe(true);
    const psbtWitness = psbt.inputs[0].finalScriptWitness!;

    // ---- Manual canonical assembly --------------------------------------
    // BIP-143 sighash with witnessScript as scriptCode.
    const { sigHashWitnessV0, SIGHASH_ALL: SH_ALL } = require("../validation/tx");
    const { ecdsaSign } = require("../crypto/primitives");
    const sighash = sigHashWitnessV0(spendTx, 0, witnessScript, value, SH_ALL);
    const sig1 = Buffer.concat([ecdsaSign(sighash, k1.priv), Buffer.from([SH_ALL])]);
    const sig2 = Buffer.concat([ecdsaSign(sighash, k2.priv), Buffer.from([SH_ALL])]);
    // Witness order must match script-pubkey order: k1 appears before k2 in the
    // witnessScript, so sig1 comes before sig2.  Dummy is the empty pushdata.
    const manualWitness: Buffer[] = [Buffer.alloc(0), sig1, sig2, witnessScript];

    expect(psbtWitness.length).toBe(manualWitness.length);
    for (let i = 0; i < psbtWitness.length; i++) {
      expect(psbtWitness[i].equals(manualWitness[i])).toBe(true);
    }

    // Sanity: the manual witness also passes the interpreter.
    const signedTx = extractTransaction(psbt);
    const utxo: UTXOEntry = {
      height: 100_000,
      coinbase: false,
      amount: value,
      scriptPubKey,
    };
    expect(verifyAllInputsSequential(signedTx, [utxo]).valid).toBe(true);
  });
});
