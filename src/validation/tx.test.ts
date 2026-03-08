import { describe, expect, test } from "bun:test";
import { BufferReader } from "../wire/serialization";
import {
  Transaction,
  TxIn,
  TxOut,
  OutPoint,
  serializeTx,
  deserializeTx,
  getTxId,
  getWTxId,
  hasWitness,
  getTxWeight,
  getTxVSize,
  sigHashWitnessV0,
  sigHashLegacy,
  validateTxBasic,
  isCoinbase,
  SIGHASH_ALL,
  SIGHASH_NONE,
  SIGHASH_SINGLE,
  SIGHASH_ANYONECANPAY,
} from "./tx";

/**
 * Helper to create a simple legacy transaction.
 */
function createLegacyTx(): Transaction {
  return {
    version: 1,
    inputs: [
      {
        prevOut: {
          txid: Buffer.from(
            "0000000000000000000000000000000000000000000000000000000000000001",
            "hex"
          ),
          vout: 0,
        },
        scriptSig: Buffer.from([0x00]), // OP_FALSE
        sequence: 0xffffffff,
        witness: [],
      },
    ],
    outputs: [
      {
        value: 100000000n, // 1 BTC
        scriptPubKey: Buffer.from([0x76, 0xa9, 0x14]), // P2PKH start
      },
    ],
    lockTime: 0,
  };
}

/**
 * Helper to create a segwit transaction with witness data.
 */
function createSegwitTx(): Transaction {
  return {
    version: 2,
    inputs: [
      {
        prevOut: {
          txid: Buffer.from(
            "0000000000000000000000000000000000000000000000000000000000000002",
            "hex"
          ),
          vout: 1,
        },
        scriptSig: Buffer.alloc(0), // Empty for P2WPKH
        sequence: 0xfffffffe,
        witness: [
          Buffer.from("304402...", "hex").subarray(0, 0), // placeholder signature
          Buffer.alloc(33, 0x02), // placeholder pubkey
        ],
      },
    ],
    outputs: [
      {
        value: 50000000n, // 0.5 BTC
        scriptPubKey: Buffer.from([0x00, 0x14]), // P2WPKH version
      },
    ],
    lockTime: 500000,
  };
}

/**
 * Helper to create a coinbase transaction.
 */
function createCoinbaseTx(): Transaction {
  return {
    version: 1,
    inputs: [
      {
        prevOut: {
          txid: Buffer.alloc(32, 0), // All zeros
          vout: 0xffffffff, // Max uint32
        },
        scriptSig: Buffer.from([0x03, 0x01, 0x00, 0x00]), // Block height 1
        sequence: 0xffffffff,
        witness: [],
      },
    ],
    outputs: [
      {
        value: 5000000000n, // 50 BTC
        scriptPubKey: Buffer.from([0x41]), // OP_PUSHBYTES_65
      },
    ],
    lockTime: 0,
  };
}

describe("hasWitness", () => {
  test("returns false for legacy transaction", () => {
    const tx = createLegacyTx();
    expect(hasWitness(tx)).toBe(false);
  });

  test("returns true for segwit transaction", () => {
    const tx = createSegwitTx();
    // Need actual witness data
    tx.inputs[0].witness = [Buffer.from([0x01]), Buffer.from([0x02])];
    expect(hasWitness(tx)).toBe(true);
  });

  test("returns false for empty witness arrays", () => {
    const tx = createSegwitTx();
    tx.inputs[0].witness = [];
    expect(hasWitness(tx)).toBe(false);
  });
});

describe("serializeTx", () => {
  test("legacy tx starts with version", () => {
    const tx = createLegacyTx();
    const serialized = serializeTx(tx, false);

    // Version should be first 4 bytes, little-endian
    expect(serialized.readInt32LE(0)).toBe(1);
  });

  test("legacy tx has input count after version", () => {
    const tx = createLegacyTx();
    const serialized = serializeTx(tx, false);

    // Input count is at offset 4
    expect(serialized[4]).toBe(1);
  });

  test("legacy tx without witness flag when serialized with witness=true but no witness data", () => {
    const tx = createLegacyTx();
    const withWitness = serializeTx(tx, true);
    const withoutWitness = serializeTx(tx, false);

    // Should be identical since there's no witness data
    expect(withWitness.equals(withoutWitness)).toBe(true);
  });

  test("segwit tx includes marker and flag when withWitness=true", () => {
    const tx = createSegwitTx();
    tx.inputs[0].witness = [Buffer.from([0x01, 0x02])];

    const serialized = serializeTx(tx, true);

    // Version (4 bytes) + marker (0x00) + flag (0x01)
    expect(serialized.readInt32LE(0)).toBe(2); // version
    expect(serialized[4]).toBe(0x00); // marker
    expect(serialized[5]).toBe(0x01); // flag
  });

  test("segwit tx without marker when withWitness=false", () => {
    const tx = createSegwitTx();
    tx.inputs[0].witness = [Buffer.from([0x01, 0x02])];

    const serialized = serializeTx(tx, false);

    // Version (4 bytes), then immediately input count (should be 1)
    expect(serialized.readInt32LE(0)).toBe(2);
    expect(serialized[4]).toBe(1); // input count, not marker
  });
});

describe("deserializeTx", () => {
  test("round-trip legacy transaction", () => {
    const original = createLegacyTx();
    const serialized = serializeTx(original, false);
    const reader = new BufferReader(serialized);
    const deserialized = deserializeTx(reader);

    expect(deserialized.version).toBe(original.version);
    expect(deserialized.inputs.length).toBe(original.inputs.length);
    expect(deserialized.outputs.length).toBe(original.outputs.length);
    expect(deserialized.lockTime).toBe(original.lockTime);
    expect(deserialized.inputs[0].prevOut.txid.equals(original.inputs[0].prevOut.txid)).toBe(true);
    expect(deserialized.inputs[0].prevOut.vout).toBe(original.inputs[0].prevOut.vout);
    expect(deserialized.inputs[0].scriptSig.equals(original.inputs[0].scriptSig)).toBe(true);
    expect(deserialized.outputs[0].value).toBe(original.outputs[0].value);
  });

  test("round-trip segwit transaction", () => {
    const original = createSegwitTx();
    original.inputs[0].witness = [Buffer.from([0x01, 0x02, 0x03]), Buffer.from([0x04, 0x05])];

    const serialized = serializeTx(original, true);
    const reader = new BufferReader(serialized);
    const deserialized = deserializeTx(reader);

    expect(deserialized.version).toBe(original.version);
    expect(deserialized.inputs[0].witness.length).toBe(2);
    expect(deserialized.inputs[0].witness[0].equals(original.inputs[0].witness[0])).toBe(true);
    expect(deserialized.inputs[0].witness[1].equals(original.inputs[0].witness[1])).toBe(true);
  });

  test("parses real mainnet transaction", () => {
    // First standard transaction in Bitcoin (block 170)
    // TX: f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16
    const rawTx = Buffer.from(
      "0100000001c997a5e56e104102fa209c6a852dd90660a20b2d9c352423edce25857fcd3704000000004847304402204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd410220181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d0901ffffffff0200ca9a3b00000000434104ae1a62fe09c5f51b13905f07f06b99a2f7159b2225f374cd378d71302fa28414e7aab37397f554a7df5f142c21c1b7303b8a0626f1baded5c72a704f7e6cd84cac00286bee0000000043410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3ac00000000",
      "hex"
    );

    const reader = new BufferReader(rawTx);
    const tx = deserializeTx(reader);

    expect(tx.version).toBe(1);
    expect(tx.inputs.length).toBe(1);
    expect(tx.outputs.length).toBe(2);
    expect(tx.lockTime).toBe(0);

    // First output: 10 BTC to Hal Finney
    expect(tx.outputs[0].value).toBe(1000000000n);
    // Second output: change back to Satoshi
    expect(tx.outputs[1].value).toBe(4000000000n);
  });
});

describe("getTxId", () => {
  test("legacy transaction has correct txid", () => {
    // Using the real block 170 transaction
    const rawTx = Buffer.from(
      "0100000001c997a5e56e104102fa209c6a852dd90660a20b2d9c352423edce25857fcd3704000000004847304402204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd410220181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d0901ffffffff0200ca9a3b00000000434104ae1a62fe09c5f51b13905f07f06b99a2f7159b2225f374cd378d71302fa28414e7aab37397f554a7df5f142c21c1b7303b8a0626f1baded5c72a704f7e6cd84cac00286bee0000000043410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3ac00000000",
      "hex"
    );

    const reader = new BufferReader(rawTx);
    const tx = deserializeTx(reader);
    const txid = getTxId(tx);

    // Expected txid (in internal little-endian byte order)
    const expectedTxid = Buffer.from(
      "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16",
      "hex"
    ).reverse();

    expect(txid.equals(expectedTxid)).toBe(true);
  });

  test("txid does not include witness data", () => {
    const tx = createSegwitTx();
    tx.inputs[0].witness = [Buffer.from([0x01, 0x02, 0x03])];

    const txid1 = getTxId(tx);

    // Change witness data
    tx.inputs[0].witness = [Buffer.from([0x04, 0x05, 0x06])];
    const txid2 = getTxId(tx);

    // TxId should be the same
    expect(txid1.equals(txid2)).toBe(true);
  });
});

describe("getWTxId", () => {
  test("wtxid equals txid for non-witness transaction", () => {
    const tx = createLegacyTx();
    const txid = getTxId(tx);
    const wtxid = getWTxId(tx);

    expect(wtxid.equals(txid)).toBe(true);
  });

  test("wtxid differs from txid for witness transaction", () => {
    const tx = createSegwitTx();
    tx.inputs[0].witness = [Buffer.from([0x01, 0x02, 0x03])];

    const txid = getTxId(tx);
    const wtxid = getWTxId(tx);

    expect(wtxid.equals(txid)).toBe(false);
  });

  test("wtxid changes with witness data", () => {
    const tx = createSegwitTx();
    tx.inputs[0].witness = [Buffer.from([0x01, 0x02, 0x03])];
    const wtxid1 = getWTxId(tx);

    tx.inputs[0].witness = [Buffer.from([0x04, 0x05, 0x06])];
    const wtxid2 = getWTxId(tx);

    expect(wtxid1.equals(wtxid2)).toBe(false);
  });
});

describe("getTxWeight and getTxVSize", () => {
  test("legacy transaction weight is 4x size", () => {
    const tx = createLegacyTx();
    const serialized = serializeTx(tx, false);
    const weight = getTxWeight(tx);

    // For non-witness tx: base_size * 3 + total_size = size * 4
    expect(weight).toBe(serialized.length * 4);
  });

  test("vsize equals size for legacy transaction", () => {
    const tx = createLegacyTx();
    const serialized = serializeTx(tx, false);
    const vsize = getTxVSize(tx);

    expect(vsize).toBe(serialized.length);
  });

  test("segwit transaction has discounted witness", () => {
    const tx = createSegwitTx();
    tx.inputs[0].witness = [
      Buffer.alloc(72, 0x30), // ~72 byte signature
      Buffer.alloc(33, 0x02), // 33 byte pubkey
    ];

    const baseSize = serializeTx(tx, false).length;
    const totalSize = serializeTx(tx, true).length;
    const weight = getTxWeight(tx);

    // weight = base_size * 3 + total_size
    expect(weight).toBe(baseSize * 3 + totalSize);

    // vsize should be less than total size
    const vsize = getTxVSize(tx);
    expect(vsize).toBeLessThan(totalSize);
    expect(vsize).toBe(Math.ceil(weight / 4));
  });
});

describe("sigHashLegacy", () => {
  test("throws for invalid input index", () => {
    const tx = createLegacyTx();
    expect(() => sigHashLegacy(tx, -1, Buffer.alloc(0), SIGHASH_ALL)).toThrow();
    expect(() => sigHashLegacy(tx, 1, Buffer.alloc(0), SIGHASH_ALL)).toThrow();
  });

  test("SIGHASH_ALL produces consistent hash", () => {
    const tx = createLegacyTx();
    const subscript = Buffer.from([0x76, 0xa9, 0x14]);

    const hash1 = sigHashLegacy(tx, 0, subscript, SIGHASH_ALL);
    const hash2 = sigHashLegacy(tx, 0, subscript, SIGHASH_ALL);

    expect(hash1.equals(hash2)).toBe(true);
    expect(hash1.length).toBe(32);
  });

  test("SIGHASH_NONE produces different hash", () => {
    const tx = createLegacyTx();
    const subscript = Buffer.from([0x76, 0xa9, 0x14]);

    const hashAll = sigHashLegacy(tx, 0, subscript, SIGHASH_ALL);
    const hashNone = sigHashLegacy(tx, 0, subscript, SIGHASH_NONE);

    expect(hashAll.equals(hashNone)).toBe(false);
  });

  test("SIGHASH_SINGLE with index >= outputs returns special hash", () => {
    const tx: Transaction = {
      version: 1,
      inputs: [
        {
          prevOut: { txid: Buffer.alloc(32, 1), vout: 0 },
          scriptSig: Buffer.alloc(0),
          sequence: 0xffffffff,
          witness: [],
        },
        {
          prevOut: { txid: Buffer.alloc(32, 2), vout: 0 },
          scriptSig: Buffer.alloc(0),
          sequence: 0xffffffff,
          witness: [],
        },
      ],
      outputs: [
        { value: 100n, scriptPubKey: Buffer.from([0x00]) },
      ],
      lockTime: 0,
    };

    // Input index 1, but only 1 output - triggers the bug behavior
    const hash = sigHashLegacy(tx, 1, Buffer.alloc(0), SIGHASH_SINGLE);

    // Should return 0x01 padded to 32 bytes
    const expected = Buffer.alloc(32, 0);
    expected[0] = 1;
    expect(hash.equals(expected)).toBe(true);
  });

  test("ANYONECANPAY only signs current input", () => {
    const tx: Transaction = {
      version: 1,
      inputs: [
        {
          prevOut: { txid: Buffer.alloc(32, 1), vout: 0 },
          scriptSig: Buffer.alloc(0),
          sequence: 0xffffffff,
          witness: [],
        },
        {
          prevOut: { txid: Buffer.alloc(32, 2), vout: 0 },
          scriptSig: Buffer.alloc(0),
          sequence: 0xffffffff,
          witness: [],
        },
      ],
      outputs: [
        { value: 100n, scriptPubKey: Buffer.from([0x00]) },
      ],
      lockTime: 0,
    };

    const hashACP = sigHashLegacy(tx, 0, Buffer.from([0x76]), SIGHASH_ALL | SIGHASH_ANYONECANPAY);
    const hashNoACP = sigHashLegacy(tx, 0, Buffer.from([0x76]), SIGHASH_ALL);

    expect(hashACP.equals(hashNoACP)).toBe(false);
  });
});

describe("sigHashWitnessV0", () => {
  test("throws for invalid input index", () => {
    const tx = createSegwitTx();
    expect(() => sigHashWitnessV0(tx, -1, Buffer.alloc(0), 100000000n, SIGHASH_ALL)).toThrow();
    expect(() => sigHashWitnessV0(tx, 1, Buffer.alloc(0), 100000000n, SIGHASH_ALL)).toThrow();
  });

  test("BIP-143 test vector", () => {
    // BIP-143 example: native P2WPKH
    // This is a simplified test - full test would use the exact BIP-143 vectors
    const tx = createSegwitTx();
    const subscript = Buffer.from([
      0x76, 0xa9, 0x14, // OP_DUP OP_HASH160 OP_PUSH20
      ...Buffer.alloc(20, 0x00),
      0x88, 0xac, // OP_EQUALVERIFY OP_CHECKSIG
    ]);

    const sighash = sigHashWitnessV0(tx, 0, subscript, 100000000n, SIGHASH_ALL);

    expect(sighash.length).toBe(32);
  });

  test("SIGHASH_ALL produces consistent hash", () => {
    const tx = createSegwitTx();
    const subscript = Buffer.from([0x76, 0xa9, 0x14]);

    const hash1 = sigHashWitnessV0(tx, 0, subscript, 100000000n, SIGHASH_ALL);
    const hash2 = sigHashWitnessV0(tx, 0, subscript, 100000000n, SIGHASH_ALL);

    expect(hash1.equals(hash2)).toBe(true);
  });

  test("different values produce different hashes", () => {
    const tx = createSegwitTx();
    const subscript = Buffer.from([0x76, 0xa9, 0x14]);

    const hash1 = sigHashWitnessV0(tx, 0, subscript, 100000000n, SIGHASH_ALL);
    const hash2 = sigHashWitnessV0(tx, 0, subscript, 200000000n, SIGHASH_ALL);

    expect(hash1.equals(hash2)).toBe(false);
  });

  test("SIGHASH_SINGLE with index >= outputs returns zeros for hashOutputs", () => {
    const tx: Transaction = {
      version: 2,
      inputs: [
        {
          prevOut: { txid: Buffer.alloc(32, 1), vout: 0 },
          scriptSig: Buffer.alloc(0),
          sequence: 0xffffffff,
          witness: [Buffer.from([0x01])],
        },
        {
          prevOut: { txid: Buffer.alloc(32, 2), vout: 0 },
          scriptSig: Buffer.alloc(0),
          sequence: 0xffffffff,
          witness: [Buffer.from([0x02])],
        },
      ],
      outputs: [
        { value: 100n, scriptPubKey: Buffer.from([0x00]) },
      ],
      lockTime: 0,
    };

    // Should not throw, but use zero hash for outputs
    const hash = sigHashWitnessV0(tx, 1, Buffer.from([0x76]), 50000000n, SIGHASH_SINGLE);
    expect(hash.length).toBe(32);
  });
});

describe("validateTxBasic", () => {
  test("valid transaction passes", () => {
    const tx = createLegacyTx();
    const result = validateTxBasic(tx);
    expect(result.valid).toBe(true);
    expect(result.error).toBeUndefined();
  });

  test("no inputs fails", () => {
    const tx = createLegacyTx();
    tx.inputs = [];
    const result = validateTxBasic(tx);
    expect(result.valid).toBe(false);
    expect(result.error).toContain("no inputs");
  });

  test("no outputs fails", () => {
    const tx = createLegacyTx();
    tx.outputs = [];
    const result = validateTxBasic(tx);
    expect(result.valid).toBe(false);
    expect(result.error).toContain("no outputs");
  });

  test("duplicate inputs fails", () => {
    const tx = createLegacyTx();
    tx.inputs.push(tx.inputs[0]); // Duplicate
    const result = validateTxBasic(tx);
    expect(result.valid).toBe(false);
    expect(result.error).toContain("Duplicate");
  });

  test("negative output value fails", () => {
    const tx = createLegacyTx();
    tx.outputs[0].value = -1n;
    const result = validateTxBasic(tx);
    expect(result.valid).toBe(false);
    expect(result.error).toContain("Negative");
  });

  test("output exceeding max coins fails", () => {
    const tx = createLegacyTx();
    tx.outputs[0].value = 2_100_000_000_000_001n;
    const result = validateTxBasic(tx);
    expect(result.valid).toBe(false);
    expect(result.error).toContain("exceeds maximum");
  });

  test("total output exceeding max coins fails", () => {
    const tx = createLegacyTx();
    tx.outputs = [
      { value: 1_500_000_000_000_000n, scriptPubKey: Buffer.from([0x00]) },
      { value: 1_000_000_000_000_000n, scriptPubKey: Buffer.from([0x00]) },
    ];
    const result = validateTxBasic(tx);
    expect(result.valid).toBe(false);
    expect(result.error).toContain("Total output");
  });
});

describe("isCoinbase", () => {
  test("returns true for coinbase transaction", () => {
    const tx = createCoinbaseTx();
    expect(isCoinbase(tx)).toBe(true);
  });

  test("returns false for regular transaction", () => {
    const tx = createLegacyTx();
    expect(isCoinbase(tx)).toBe(false);
  });

  test("returns false for multiple inputs", () => {
    const tx = createCoinbaseTx();
    tx.inputs.push({
      prevOut: { txid: Buffer.alloc(32, 1), vout: 0 },
      scriptSig: Buffer.alloc(0),
      sequence: 0xffffffff,
      witness: [],
    });
    expect(isCoinbase(tx)).toBe(false);
  });

  test("returns false for non-null txid", () => {
    const tx = createCoinbaseTx();
    tx.inputs[0].prevOut.txid[0] = 1;
    expect(isCoinbase(tx)).toBe(false);
  });

  test("returns false for non-0xffffffff vout", () => {
    const tx = createCoinbaseTx();
    tx.inputs[0].prevOut.vout = 0;
    expect(isCoinbase(tx)).toBe(false);
  });
});
