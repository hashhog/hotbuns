/**
 * Offline unit tests for the converttopsbt + joinpsbts PSBT transforms.
 *
 * These exercise the pure transform helpers in src/wallet/psbt.ts directly
 * (rpcConvertToPSBT / joinPSBTs) plus the network round-trip used by the RPC
 * handlers (deserializeTx -> transform -> encode -> decode). NO node, NO
 * regtest, NO RPC server is started — these are deterministic offline checks.
 *
 * Parity reference: bitcoin-core/src/rpc/rawtransaction.cpp::converttopsbt
 * and ::joinpsbts (Bitcoin Core v31.99).
 */

import { describe, it, expect } from "bun:test";
import {
  rpcConvertToPSBT,
  joinPSBTs,
  createPSBT,
  encodePSBTBase64,
  decodePSBTBase64,
  createPSBTInput,
  createPSBTOutput,
  type PSBT,
} from "../wallet/psbt.js";
import {
  serializeTx,
  deserializeTx,
  decodeTxWitnessAware,
  type Transaction,
  type TxIn,
} from "../validation/tx.js";
import { BufferReader } from "../wire/serialization.js";

// ---------------------------------------------------------------------------
// Helpers for building deterministic test transactions / PSBTs.
// ---------------------------------------------------------------------------

/** A 32-byte little-endian txid seeded from a single byte. */
function txid(seed: number): Buffer {
  return Buffer.alloc(32, seed);
}

/** Build an input. scriptSig/witness default to empty (unsigned). */
function makeInput(
  seed: number,
  vout: number,
  opts: { scriptSig?: Buffer; witness?: Buffer[] } = {},
): TxIn {
  return {
    prevOut: { txid: txid(seed), vout },
    scriptSig: opts.scriptSig ?? Buffer.alloc(0),
    sequence: 0xffffffff,
    witness: opts.witness ?? [],
  };
}

/** Build a 1-out tx with the given inputs. */
function makeTx(
  inputs: TxIn[],
  opts: { version?: number; lockTime?: number; outValue?: bigint } = {},
): Transaction {
  return {
    version: opts.version ?? 2,
    inputs,
    outputs: [
      {
        value: opts.outValue ?? 1000n,
        // OP_DUP OP_HASH160 <20-byte> OP_EQUALVERIFY OP_CHECKSIG (P2PKH-ish)
        scriptPubKey: Buffer.concat([
          Buffer.from([0x76, 0xa9, 0x14]),
          Buffer.alloc(20, 0xab),
          Buffer.from([0x88, 0xac]),
        ]),
      },
    ],
    lockTime: opts.lockTime ?? 0,
  };
}

/** Build a blank PSBT from a tx (all maps empty). */
function blankPSBT(tx: Transaction): PSBT {
  return {
    tx,
    xpubs: new Map(),
    inputs: tx.inputs.map(() => createPSBTInput()),
    outputs: tx.outputs.map(() => createPSBTOutput()),
    unknown: new Map(),
  };
}

/** Set of "txid_hex:vout" strings for set-comparison of inputs. */
function inputKeySet(tx: Transaction): Set<string> {
  return new Set(
    tx.inputs.map((i) => `${i.prevOut.txid.toString("hex")}:${i.prevOut.vout}`),
  );
}

/** Set of "value:scriptPubKey_hex" strings for set-comparison of outputs. */
function outputKeySet(tx: Transaction): Set<string> {
  return new Set(
    tx.outputs.map((o) => `${o.value}:${o.scriptPubKey.toString("hex")}`),
  );
}

// ===========================================================================
// converttopsbt
// ===========================================================================

describe("converttopsbt (rpcConvertToPSBT)", () => {
  it("throws (Core -22 message) when an input has a scriptSig and permitsigdata is false", () => {
    const tx = makeTx([
      makeInput(0x01, 0, { scriptSig: Buffer.from("4830450201", "hex") }),
    ]);
    expect(() => rpcConvertToPSBT(tx, false)).toThrow(
      "Inputs must not have scriptSigs and scriptWitnesses",
    );
  });

  it("throws when an input has a witness and permitsigdata is false", () => {
    const tx = makeTx([
      makeInput(0x02, 0, { witness: [Buffer.from("deadbeef", "hex")] }),
    ]);
    expect(() => rpcConvertToPSBT(tx, false)).toThrow(
      "Inputs must not have scriptSigs and scriptWitnesses",
    );
  });

  it("succeeds with sig data when permitsigdata is true and clears the sig data", () => {
    const tx = makeTx([
      makeInput(0x03, 0, {
        scriptSig: Buffer.from("4830450201", "hex"),
        witness: [Buffer.from("cafe", "hex")],
      }),
    ]);
    const psbt = rpcConvertToPSBT(tx, true);
    // scriptSig + witness must be cleared on the embedded tx.
    expect(psbt.tx.inputs[0].scriptSig.length).toBe(0);
    expect(psbt.tx.inputs[0].witness.length).toBe(0);
  });

  it("produces a blank PSBT: empty per-input and per-output maps round-tripping the cleared tx", () => {
    // A clean (unsigned) tx, two inputs + one output.
    const tx = makeTx([makeInput(0x10, 0), makeInput(0x11, 3)]);
    const psbt = rpcConvertToPSBT(tx, false);

    // One empty map per input/output, and no global data.
    expect(psbt.inputs.length).toBe(tx.inputs.length);
    expect(psbt.outputs.length).toBe(tx.outputs.length);
    expect(psbt.xpubs.size).toBe(0);
    expect(psbt.unknown.size).toBe(0);
    for (const inp of psbt.inputs) {
      expect(inp.nonWitnessUtxo).toBeUndefined();
      expect(inp.witnessUtxo).toBeUndefined();
      expect(inp.partialSigs.size).toBe(0);
      expect(inp.redeemScript).toBeUndefined();
      expect(inp.unknown.size).toBe(0);
    }
    for (const out of psbt.outputs) {
      expect(out.redeemScript).toBeUndefined();
      expect(out.bip32Derivation.size).toBe(0);
      expect(out.unknown.size).toBe(0);
    }

    // Round-trips: base64 encode then decode reproduces the same (cleared) tx.
    const decoded = decodePSBTBase64(encodePSBTBase64(psbt));
    expect(decoded.tx.version).toBe(tx.version);
    expect(decoded.tx.lockTime).toBe(tx.lockTime);
    expect(inputKeySet(decoded.tx)).toEqual(inputKeySet(tx));
    expect(outputKeySet(decoded.tx)).toEqual(outputKeySet(tx));
    for (const inp of decoded.tx.inputs) {
      expect(inp.scriptSig.length).toBe(0);
      expect(inp.witness.length).toBe(0);
    }
  });

  it("matches the full RPC path: signed hex -> deserialize -> reject; unsigned hex -> blank PSBT", () => {
    // Build a SIGNED legacy tx, serialize to hex, deserialize like the RPC does.
    const signed = makeTx([
      makeInput(0x20, 1, { scriptSig: Buffer.from("47304402", "hex") }),
    ]);
    const signedHex = serializeTx(signed, false).toString("hex");
    const reTx = deserializeTx(new BufferReader(Buffer.from(signedHex, "hex")));
    expect(() => rpcConvertToPSBT(reTx, false)).toThrow(
      "Inputs must not have scriptSigs and scriptWitnesses",
    );

    // An UNSIGNED tx round-trips through hex into a blank PSBT.
    const unsigned = makeTx([makeInput(0x21, 0)]);
    const unsignedHex = serializeTx(unsigned, false).toString("hex");
    const reTx2 = deserializeTx(new BufferReader(Buffer.from(unsignedHex, "hex")));
    const psbt = rpcConvertToPSBT(reTx2, false);
    const decoded = decodePSBTBase64(encodePSBTBase64(psbt));
    expect(inputKeySet(decoded.tx)).toEqual(inputKeySet(unsigned));
  });

  // BUG 3 (witness-hint parity). Core derives, for converttopsbt:
  //   try_witness    = iswitness  (when specified)
  //   try_no_witness = !iswitness (when specified)
  // so iswitness=true tries ONLY the extended (BIP-144) deserialization and a
  // hex it cannot fully consume fails with RPC_DESERIALIZATION_ERROR (-22).
  // decodeTxWitnessAware mirrors core_io.cpp::DecodeTx; the RPC handler calls
  // it with exactly these flags.
  it("iswitness=true forces witness-only decode: a non-witness hex fails (Core -22)", () => {
    // A LEGACY tx with ZERO inputs: the bytes after `version` are 0x00 (vin
    // count) then 0x01 (vout count) — i.e. the segwit marker+flag pattern. The
    // legacy decode consumes it fine; the extended (witness) decode mis-reads
    // the 0x00 as a segwit marker and cannot fully consume → witness-only fails.
    const zeroInTx: Transaction = {
      version: 2,
      inputs: [],
      outputs: [
        {
          value: 1000n,
          scriptPubKey: Buffer.concat([
            Buffer.from([0x76, 0xa9, 0x14]),
            Buffer.alloc(20, 0xab),
            Buffer.from([0x88, 0xac]),
          ]),
        },
      ],
      lockTime: 0,
    };
    const legacyBytes = serializeTx(zeroInTx, false);
    // Sanity: the discriminating marker pattern is present (00 01 after version).
    expect(legacyBytes.subarray(4, 6).toString("hex")).toBe("0001");

    // iswitness omitted (try both) and iswitness=false (legacy only) decode OK.
    expect(() => decodeTxWitnessAware(legacyBytes, true, true)).not.toThrow();
    expect(() => decodeTxWitnessAware(legacyBytes, true, false)).not.toThrow();

    // iswitness=true (witness only) MUST fail — this is the BUG-3 fix.
    expect(() => decodeTxWitnessAware(legacyBytes, false, true)).toThrow(
      "TX decode failed",
    );

    // Core parity guard: a NORMAL non-witness tx (>=1 input) still SUCCEEDS
    // under iswitness=true, because its extended decode fully consumes.
    const oneInTx: Transaction = makeTx([makeInput(0x70, 0)]);
    const oneInBytes = serializeTx(oneInTx, false);
    expect(() => decodeTxWitnessAware(oneInBytes, false, true)).not.toThrow();
  });
});

// ===========================================================================
// joinpsbts
// ===========================================================================

describe("joinpsbts (joinPSBTs)", () => {
  it("throws Core -8 message when fewer than 2 PSBTs are given", () => {
    const a = blankPSBT(makeTx([makeInput(0x30, 0)]));
    expect(() => joinPSBTs([])).toThrow(
      "At least two PSBTs are required to join PSBTs.",
    );
    expect(() => joinPSBTs([a])).toThrow(
      "At least two PSBTs are required to join PSBTs.",
    );
  });

  it("throws (duplicate-input, Core -8) when two PSBTs share an outpoint", () => {
    const shared = makeInput(0x40, 7);
    const a = blankPSBT(makeTx([shared]));
    const b = blankPSBT(makeTx([{ ...shared }])); // same txid:vout
    expect(() => joinPSBTs([a, b])).toThrow(/exists in multiple PSBTs/);
  });

  it("joins two distinct PSBTs into the UNION of inputs+outputs (set-compared)", () => {
    const a = blankPSBT(
      makeTx([makeInput(0x51, 0), makeInput(0x52, 1)], {
        version: 2,
        lockTime: 500,
        outValue: 111n,
      }),
    );
    const b = blankPSBT(
      makeTx([makeInput(0x53, 0)], {
        version: 3,
        lockTime: 100,
        outValue: 222n,
      }),
    );

    const joined = joinPSBTs([a, b]); // default = no shuffle (deterministic)

    // UNION of inputs/outputs, compared as SETS (order is shuffle-dependent).
    const expectedInputs = new Set([
      ...inputKeySet(a.tx),
      ...inputKeySet(b.tx),
    ]);
    const expectedOutputs = new Set([
      ...outputKeySet(a.tx),
      ...outputKeySet(b.tx),
    ]);
    expect(inputKeySet(joined.tx)).toEqual(expectedInputs);
    expect(outputKeySet(joined.tx)).toEqual(expectedOutputs);
    expect(joined.tx.inputs.length).toBe(3);
    expect(joined.tx.outputs.length).toBe(2);

    // Per-input/output PSBT maps count must track the tx (one map each).
    expect(joined.inputs.length).toBe(joined.tx.inputs.length);
    expect(joined.outputs.length).toBe(joined.tx.outputs.length);

    // max version, min locktime (Core best_version / best_locktime).
    expect(joined.tx.version).toBe(3);
    expect(joined.tx.lockTime).toBe(100);
  });

  it("is invariant under a shuffle: result is the same SET regardless of order", () => {
    const a = blankPSBT(makeTx([makeInput(0x61, 0), makeInput(0x62, 0)]));
    const b = blankPSBT(makeTx([makeInput(0x63, 0), makeInput(0x64, 0)]));

    // Reverse permutation as the "shuffle" — must still yield the same union.
    const reverse = (n: number) =>
      Array.from({ length: n }, (_v, i) => n - 1 - i);
    const joined = joinPSBTs([a, b], reverse);

    const expectedInputs = new Set([
      ...inputKeySet(a.tx),
      ...inputKeySet(b.tx),
    ]);
    expect(inputKeySet(joined.tx)).toEqual(expectedInputs);
    expect(joined.tx.inputs.length).toBe(4);
  });

  // BUG 1 (signature-clearing parity). Core's PartiallySignedTransaction::
  // AddInput (psbt.cpp:58-60) UNCONDITIONALLY clears partial_sigs,
  // final_script_sig and final_script_witness on every input it adds, so
  // joining already-signed PSBTs drops the per-input signature data.
  it("clears partialSigs/finalScriptSig/finalScriptWitness on every joined input (Core AddInput)", () => {
    // Build two distinct single-input PSBTs whose per-input maps carry a
    // partial sig + a finalized scriptSig + a finalized witness.
    const signedInputMap = () => {
      const m = createPSBTInput();
      m.partialSigs.set("aa".repeat(33), {
        pubkey: Buffer.alloc(33, 0xaa),
        signature: Buffer.from("3045deadbeef", "hex"),
      });
      m.finalScriptSig = Buffer.from("47304402aa", "hex");
      m.finalScriptWitness = [Buffer.from("cafe", "hex")];
      return m;
    };

    const a: PSBT = {
      tx: makeTx([makeInput(0x80, 0)]),
      xpubs: new Map(),
      inputs: [signedInputMap()],
      outputs: [createPSBTOutput()],
      unknown: new Map(),
    };
    const b: PSBT = {
      tx: makeTx([makeInput(0x81, 0)]),
      xpubs: new Map(),
      inputs: [signedInputMap()],
      outputs: [createPSBTOutput()],
      unknown: new Map(),
    };

    const joined = joinPSBTs([a, b]); // default = no shuffle (deterministic)

    expect(joined.inputs.length).toBe(2);
    for (const inp of joined.inputs) {
      expect(inp.partialSigs.size).toBe(0);
      expect(inp.finalScriptSig).toBeUndefined();
      expect(inp.finalScriptWitness).toBeUndefined();
    }

    // The source PSBTs must NOT be mutated by the join (joined maps are copies).
    expect(a.inputs[0].partialSigs.size).toBe(1);
    expect(a.inputs[0].finalScriptSig).toBeDefined();
    expect(b.inputs[0].finalScriptWitness).toBeDefined();
  });

  // BUG 2 (full-CTxIn dedup parity). Core dedups via std::find over tx.vin
  // using CTxIn::operator== (prevout AND scriptSig AND nSequence,
  // primitives/transaction.h:126-131). Two inputs sharing an outpoint but
  // differing in nSequence are BOTH accepted — not a duplicate.
  it("accepts two inputs with the same outpoint but different nSequence (full-CTxIn dedup)", () => {
    const inA: TxIn = {
      prevOut: { txid: txid(0x90), vout: 4 },
      scriptSig: Buffer.alloc(0),
      sequence: 0xfffffffe,
      witness: [],
    };
    const inB: TxIn = {
      prevOut: { txid: txid(0x90), vout: 4 }, // SAME outpoint
      scriptSig: Buffer.alloc(0),
      sequence: 0xffffffff, // DIFFERENT nSequence
      witness: [],
    };
    const a = blankPSBT(makeTx([inA]));
    const b = blankPSBT(makeTx([inB]));

    // Must NOT throw the duplicate-input (-8) error.
    const joined = joinPSBTs([a, b]);
    expect(joined.tx.inputs.length).toBe(2);
    expect(joined.inputs.length).toBe(2);
    const seqs = joined.tx.inputs.map((i) => i.sequence).sort();
    expect(seqs).toEqual([0xfffffffe, 0xffffffff]);

    // A genuine duplicate (identical prevout + scriptSig + nSequence) still -8.
    const dupA = blankPSBT(makeTx([{ ...inA }]));
    const dupB = blankPSBT(makeTx([{ ...inA }]));
    expect(() => joinPSBTs([dupA, dupB])).toThrow(/exists in multiple PSBTs/);
  });
});
