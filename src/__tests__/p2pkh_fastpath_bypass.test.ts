/**
 * Regression test for P0-1 (CORE-PARITY-AUDIT/hotbuns-P0-FOUND.md).
 *
 * `verifyInputSignature` previously short-circuited P2PKH and P2WPKH inputs
 * with a hand-rolled `<sig><pubkey>` parser that called `ecdsaVerify` directly
 * and bypassed the script interpreter.  That fast path silently skipped:
 *   - DERSIG strict-DER check (BIP-66, MANDATORY consensus flag post-h=363725)
 *   - NULLDUMMY (consensus, post-segwit)
 *   - OP_DUP/OP_HASH160/OP_EQUALVERIFY/OP_CHECKSIG opcode dispatch
 *   - OP_PUSHDATA1/2/4 for the scriptSig pushes (parser only handled direct
 *     pushes 0x01–0x4b, treating 0x4c=OP_PUSHDATA1 as a 76-byte length).
 *
 * Fix: the fast path was deleted; both P2PKH and P2WPKH now route to the
 * catch-all `verifyScript()` branch which dispatches the full interpreter.
 *
 * These tests exercise inputs the fast path silently mishandled and the
 * interpreter handles correctly:
 *   1. P2PKH with sig pushed via OP_PUSHDATA1 — the fast path read the 0x4c
 *      opcode as a 76-byte length and grabbed garbage; the interpreter parses
 *      it as a single push.  Core accepts.
 *   2. P2PKH with a non-strict-DER signature (extra inner padding) — the fast
 *      path delegated to libsecp's strict parser which rejected; we want the
 *      same rejection but routed through DERSIG (BIP-66) in the interpreter.
 *   3. P2WPKH with sig pushed via direct push (sanity — happy path that worked
 *      before and must still work).
 */

import { describe, expect, test } from "bun:test";
import {
  sigHashLegacy,
  sigHashWitnessV0Cached,
  verifyInputSignature,
  SIGHASH_ALL,
  type SigHashCache,
  type Transaction,
} from "../validation/tx.js";
import {
  ecdsaSign,
  privateKeyToPublicKey,
  hash160,
} from "../crypto/primitives.js";
import type { UTXOEntry } from "../storage/database.js";

// Deterministic test key (secp256k1 scalar in the valid range).
const PRIVATE_KEY = Buffer.from(
  "0101010101010101010101010101010101010101010101010101010101010101",
  "hex"
);
const PUBLIC_KEY = privateKeyToPublicKey(PRIVATE_KEY, true); // 33-byte compressed
const PUBKEY_HASH = hash160(PUBLIC_KEY);

// P2PKH scriptPubKey: OP_DUP OP_HASH160 <20-byte pkh> OP_EQUALVERIFY OP_CHECKSIG
function p2pkhScriptPubKey(pkh: Buffer): Buffer {
  return Buffer.concat([
    Buffer.from([0x76, 0xa9, 0x14]),
    pkh,
    Buffer.from([0x88, 0xac]),
  ]);
}

// P2WPKH scriptPubKey: OP_0 <20-byte pkh>
function p2wpkhScriptPubKey(pkh: Buffer): Buffer {
  return Buffer.concat([Buffer.from([0x00, 0x14]), pkh]);
}

// Bare P2PKH spending tx (legacy, no witness).
function buildLegacyP2PKHSpend(scriptSig: Buffer): Transaction {
  return {
    version: 2,
    inputs: [{
      prevOut: { txid: Buffer.alloc(32, 0xab), vout: 0 },
      scriptSig,
      sequence: 0xffffffff,
      witness: [],
    }],
    outputs: [{ value: 1000n, scriptPubKey: p2pkhScriptPubKey(PUBKEY_HASH) }],
    lockTime: 0,
  };
}

describe("P0-1 P2PKH fast-path bypass", () => {
  test("P2PKH with sig pushed via OP_PUSHDATA1 is accepted (fast path would have rejected)", () => {
    // Pre-build the unsigned tx so the input we're going to sign is shaped
    // identically to the final tx.  scriptSig is a placeholder — sigHashLegacy
    // uses the scriptPubKey of the spent UTXO as the subscript anyway.
    const utxoScript = p2pkhScriptPubKey(PUBKEY_HASH);
    const tx = buildLegacyP2PKHSpend(Buffer.alloc(0));
    const sighash = sigHashLegacy(tx, 0, utxoScript, SIGHASH_ALL);
    const derSig = ecdsaSign(sighash, PRIVATE_KEY);
    const sigWithType = Buffer.concat([derSig, Buffer.from([SIGHASH_ALL])]);

    // scriptSig: OP_PUSHDATA1 <sigLen> <sig>  <directPush_pkLen> <pubkey>
    // Pushing the sig via OP_PUSHDATA1 is a valid, Core-accepted scriptSig but
    // the deleted fast path would have read 0x4c as sigLen=76 and grabbed
    // garbage.  Routing through the interpreter parses it correctly.
    const scriptSig = Buffer.concat([
      Buffer.from([0x4c, sigWithType.length]), // OP_PUSHDATA1 <len>
      sigWithType,
      Buffer.from([PUBLIC_KEY.length]), // direct push
      PUBLIC_KEY,
    ]);
    tx.inputs[0].scriptSig = scriptSig;

    const utxo: UTXOEntry = {
      height: 1,
      coinbase: false,
      amount: 100_000n,
      scriptPubKey: utxoScript,
    };
    const cache: SigHashCache = {};
    const result = verifyInputSignature(tx, 0, utxo, cache, [utxo]);
    expect(result.valid).toBe(true);
  });

  test("P2PKH with non-strict-DER sig is rejected (DERSIG / BIP-66 enforced via interpreter)", () => {
    // Construct a non-strict DER signature: take a valid sig and inject an
    // extra leading 0x00 padding byte into R, then re-encode with the wrong
    // length byte.  The strict DERSIG check requires:
    //   "R must not have unnecessary leading zeros"
    // (interpreter.ts:482).  Bitcoin Core's MANDATORY_SCRIPT_VERIFY_FLAGS
    // include DERSIG post-h=363725.
    const utxoScript = p2pkhScriptPubKey(PUBKEY_HASH);
    const tx = buildLegacyP2PKHSpend(Buffer.alloc(0));
    const sighash = sigHashLegacy(tx, 0, utxoScript, SIGHASH_ALL);
    const goodSig = ecdsaSign(sighash, PRIVATE_KEY);

    // goodSig layout: 0x30 [seqLen] 0x02 [rLen] [R] 0x02 [sLen] [S]
    // Inject an extra 0x00 byte at the start of R to break the no-leading-zeros
    // rule.  Adjust seqLen and rLen accordingly.
    const seqLen = goodSig[1];
    const rLen = goodSig[3];
    const rBytes = goodSig.subarray(4, 4 + rLen);
    const sStart = 4 + rLen;
    const tail = goodSig.subarray(sStart); // 0x02 [sLen] [S]

    // Pad R with a leading 0x00 (only legal if next byte's high bit is set,
    // which we deliberately avoid by ensuring R[0]'s high bit is clear — if
    // it isn't we just bump seqLen+rLen anyway, the rule "rLen > 1 && R[0]==0
    // && !(R[1] & 0x80)" still trips because R[1] (was R[0]) has variable
    // high bit; this remains non-strict-DER if either:
    //   (a) we always add a 0 prefix, OR
    //   (b) R[0] was already non-negative.
    // Either way the strict parser returns false.
    const paddedR = Buffer.concat([Buffer.from([0x00]), rBytes]);
    const newRLen = paddedR.length;
    const newSeqLen = seqLen + 1;
    const malSig = Buffer.concat([
      Buffer.from([0x30, newSeqLen, 0x02, newRLen]),
      paddedR,
      tail,
    ]);

    const sigWithType = Buffer.concat([malSig, Buffer.from([SIGHASH_ALL])]);

    // Standard P2PKH scriptSig: <sig> <pubkey>
    const scriptSig = Buffer.concat([
      Buffer.from([sigWithType.length]),
      sigWithType,
      Buffer.from([PUBLIC_KEY.length]),
      PUBLIC_KEY,
    ]);
    tx.inputs[0].scriptSig = scriptSig;

    const utxo: UTXOEntry = {
      height: 1,
      coinbase: false,
      amount: 100_000n,
      scriptPubKey: utxoScript,
    };
    const cache: SigHashCache = {};
    const result = verifyInputSignature(tx, 0, utxo, cache, [utxo]);
    // verifyInputSignature uses getConsensusFlags(709632) which has
    // verifyDERSignatures=true; DERSIG must reject the non-strict-DER sig.
    expect(result.valid).toBe(false);
  });

  test("P2PKH happy path: strict-DER sig with direct pushes is accepted", () => {
    const utxoScript = p2pkhScriptPubKey(PUBKEY_HASH);
    const tx = buildLegacyP2PKHSpend(Buffer.alloc(0));
    const sighash = sigHashLegacy(tx, 0, utxoScript, SIGHASH_ALL);
    const derSig = ecdsaSign(sighash, PRIVATE_KEY);
    const sigWithType = Buffer.concat([derSig, Buffer.from([SIGHASH_ALL])]);

    const scriptSig = Buffer.concat([
      Buffer.from([sigWithType.length]),
      sigWithType,
      Buffer.from([PUBLIC_KEY.length]),
      PUBLIC_KEY,
    ]);
    tx.inputs[0].scriptSig = scriptSig;

    const utxo: UTXOEntry = {
      height: 1,
      coinbase: false,
      amount: 100_000n,
      scriptPubKey: utxoScript,
    };
    const cache: SigHashCache = {};
    const result = verifyInputSignature(tx, 0, utxo, cache, [utxo]);
    expect(result.valid).toBe(true);
  });

  test("P2WPKH happy path: still verifies through interpreter", () => {
    // Build a P2WPKH spend with witness = [<sig+hashType>, <pubkey>].
    const utxoScript = p2wpkhScriptPubKey(PUBKEY_HASH);
    const tx: Transaction = {
      version: 2,
      inputs: [{
        prevOut: { txid: Buffer.alloc(32, 0xcd), vout: 0 },
        scriptSig: Buffer.alloc(0), // P2WPKH: empty scriptSig
        sequence: 0xffffffff,
        witness: [],
      }],
      outputs: [{ value: 1000n, scriptPubKey: utxoScript }],
      lockTime: 0,
    };

    // P2WPKH scriptCode = OP_DUP OP_HASH160 <pkh> OP_EQUALVERIFY OP_CHECKSIG
    const scriptCode = Buffer.concat([
      Buffer.from([0x76, 0xa9, 0x14]),
      PUBKEY_HASH,
      Buffer.from([0x88, 0xac]),
    ]);
    const cache: SigHashCache = {};
    const utxoAmount = 100_000n;
    const sighash = sigHashWitnessV0Cached(tx, 0, scriptCode, utxoAmount, SIGHASH_ALL, cache);
    const derSig = ecdsaSign(sighash, PRIVATE_KEY);
    const sigWithType = Buffer.concat([derSig, Buffer.from([SIGHASH_ALL])]);
    tx.inputs[0].witness = [sigWithType, PUBLIC_KEY];

    const utxo: UTXOEntry = {
      height: 1,
      coinbase: false,
      amount: utxoAmount,
      scriptPubKey: utxoScript,
    };
    const result = verifyInputSignature(tx, 0, utxo, cache, [utxo]);
    expect(result.valid).toBe(true);
  });
});
