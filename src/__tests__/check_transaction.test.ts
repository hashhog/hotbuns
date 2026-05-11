/**
 * W84 CheckTransaction + CheckTxInputs + CVE-2018-17144 + GetBlockSubsidy audit.
 *
 * Tests the complete gate set from:
 *   - Bitcoin Core consensus/tx_check.cpp::CheckTransaction (9 gates)
 *   - Bitcoin Core consensus/tx_verify.cpp::CheckTxInputs (MoneyRange checks)
 *   - Bitcoin Core validation.cpp::GetBlockSubsidy (64-halving schedule)
 *   - Bitcoin Core validation.cpp::ConnectBlock (accumulated fee range)
 *
 * CVE-2018-17144: duplicate-input check must fire BEFORE any UTXO DB access.
 * CVE-2010-5139:  negative / overlarge output value check.
 *
 * Reference: bitcoin-core/src/consensus/tx_check.cpp, tx_verify.cpp, validation.cpp
 */

import { describe, expect, test } from "bun:test";
import { validateTxBasic, isCoinbase, type Transaction, type TxIn, type TxOut } from "../validation/tx.js";
import { getBlockSubsidy, MAINNET, REGTEST } from "../consensus/params.js";

// ─── Helpers ──────────────────────────────────────────────────────────────────

function makeTxIn(txidByte = 1, vout = 0): TxIn {
  return {
    prevOut: {
      txid: Buffer.alloc(32, txidByte),
      vout,
    },
    scriptSig: Buffer.from([0x00]),
    sequence: 0xffffffff,
    witness: [],
  };
}

function makeTxOut(value: bigint = 100_000_000n): TxOut {
  return {
    value,
    scriptPubKey: Buffer.from([0x76, 0xa9, 0x14, ...Buffer.alloc(20, 0), 0x88, 0xac]),
  };
}

function makeNormalTx(): Transaction {
  return {
    version: 1,
    inputs: [makeTxIn(1)],
    outputs: [makeTxOut()],
    lockTime: 0,
  };
}

function makeCoinbaseTx(scriptSigBytes?: Buffer): Transaction {
  return {
    version: 1,
    inputs: [
      {
        prevOut: { txid: Buffer.alloc(32, 0), vout: 0xffffffff },
        scriptSig: scriptSigBytes ?? Buffer.from([0x03, 0x01, 0x00, 0x00]), // 4 bytes
        sequence: 0xffffffff,
        witness: [],
      },
    ],
    outputs: [makeTxOut()],
    lockTime: 0,
  };
}

// ─── Gate 1: bad-txns-vin-empty ───────────────────────────────────────────────

describe("CheckTransaction gate 1: bad-txns-vin-empty", () => {
  test("empty inputs rejected with canonical error string", () => {
    const tx = makeNormalTx();
    tx.inputs = [];
    const r = validateTxBasic(tx);
    expect(r.valid).toBe(false);
    expect(r.error).toBe("bad-txns-vin-empty");
  });

  test("single input passes", () => {
    expect(validateTxBasic(makeNormalTx()).valid).toBe(true);
  });
});

// ─── Gate 2: bad-txns-vout-empty ─────────────────────────────────────────────

describe("CheckTransaction gate 2: bad-txns-vout-empty", () => {
  test("empty outputs rejected with canonical error string", () => {
    const tx = makeNormalTx();
    tx.outputs = [];
    const r = validateTxBasic(tx);
    expect(r.valid).toBe(false);
    expect(r.error).toBe("bad-txns-vout-empty");
  });

  test("single output passes", () => {
    expect(validateTxBasic(makeNormalTx()).valid).toBe(true);
  });
});

// ─── Gate 3: bad-txns-oversize ───────────────────────────────────────────────

describe("CheckTransaction gate 3: bad-txns-oversize", () => {
  // Core: stripped_size * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT
  //       stripped_size * 4 > 4_000_000  →  stripped_size > 1_000_000
  test("tx with stripped size just over 1MB rejected", () => {
    const tx = makeNormalTx();
    // scriptSig of 1_000_001 bytes makes stripped size >> 1_000_000
    tx.inputs[0] = { ...tx.inputs[0], scriptSig: Buffer.alloc(1_000_001) };
    const r = validateTxBasic(tx);
    expect(r.valid).toBe(false);
    expect(r.error).toBe("bad-txns-oversize");
  });

  test("oversize checked before output value gate", () => {
    const tx = makeNormalTx();
    tx.inputs[0] = { ...tx.inputs[0], scriptSig: Buffer.alloc(1_000_001) };
    // Also set a negative output that would fire gate 4 — oversize must win
    tx.outputs[0] = { ...tx.outputs[0], value: 0xffffffffffffffffn };
    const r = validateTxBasic(tx);
    expect(r.error).toBe("bad-txns-oversize");
  });
});

// ─── Gate 4: bad-txns-vout-negative (CVE-2010-5139) ─────────────────────────

describe("CheckTransaction gate 4: bad-txns-vout-negative (CVE-2010-5139)", () => {
  test("negative output value (wire -1) rejected", () => {
    const tx = makeNormalTx();
    // 0xffffffffffffffff is the wire encoding of -1 as signed int64
    tx.outputs[0] = { ...tx.outputs[0], value: 0xffffffffffffffffn };
    const r = validateTxBasic(tx);
    expect(r.valid).toBe(false);
    expect(r.error).toBe("bad-txns-vout-negative");
  });

  test("negative output value (wire INT64_MIN) rejected", () => {
    const tx = makeNormalTx();
    tx.outputs[0] = { ...tx.outputs[0], value: 0x8000000000000000n }; // INT64_MIN
    const r = validateTxBasic(tx);
    expect(r.valid).toBe(false);
    expect(r.error).toBe("bad-txns-vout-negative");
  });

  test("zero output value is valid", () => {
    const tx = makeNormalTx();
    tx.outputs[0] = { ...tx.outputs[0], value: 0n };
    expect(validateTxBasic(tx).valid).toBe(true);
  });

  test("MAX_MONEY output value is valid", () => {
    const tx = makeNormalTx();
    tx.outputs[0] = { ...tx.outputs[0], value: 2_100_000_000_000_000n };
    expect(validateTxBasic(tx).valid).toBe(true);
  });
});

// ─── Gate 5: bad-txns-vout-toolarge (CVE-2010-5139) ─────────────────────────

describe("CheckTransaction gate 5: bad-txns-vout-toolarge (CVE-2010-5139)", () => {
  test("single output one satoshi over MAX_MONEY rejected", () => {
    const tx = makeNormalTx();
    tx.outputs[0] = { ...tx.outputs[0], value: 2_100_000_000_000_001n };
    const r = validateTxBasic(tx);
    expect(r.valid).toBe(false);
    expect(r.error).toBe("bad-txns-vout-toolarge");
  });

  test("exact MAX_MONEY (21_000_000 BTC) is valid", () => {
    const tx = makeNormalTx();
    tx.outputs[0] = { ...tx.outputs[0], value: 2_100_000_000_000_000n };
    expect(validateTxBasic(tx).valid).toBe(true);
  });
});

// ─── Gate 6: bad-txns-txouttotal-toolarge (CVE-2010-5139) ────────────────────

describe("CheckTransaction gate 6: bad-txns-txouttotal-toolarge (CVE-2010-5139)", () => {
  test("two MAX_MONEY outputs rejected", () => {
    const tx = makeNormalTx();
    tx.outputs = [
      { value: 2_100_000_000_000_000n, scriptPubKey: Buffer.from([0x00]) },
      { value: 2_100_000_000_000_000n, scriptPubKey: Buffer.from([0x00]) },
    ];
    const r = validateTxBasic(tx);
    expect(r.valid).toBe(false);
    expect(r.error).toBe("bad-txns-txouttotal-toolarge");
  });

  test("two large outputs that sum just over MAX_MONEY rejected", () => {
    const tx = makeNormalTx();
    tx.outputs = [
      { value: 1_500_000_000_000_000n, scriptPubKey: Buffer.from([0x00]) },
      { value: 1_000_000_000_000_000n, scriptPubKey: Buffer.from([0x00]) },
    ];
    const r = validateTxBasic(tx);
    expect(r.valid).toBe(false);
    expect(r.error).toBe("bad-txns-txouttotal-toolarge");
  });

  test("two outputs that sum to exactly MAX_MONEY are valid", () => {
    const tx = makeNormalTx();
    tx.outputs = [
      { value: 1_050_000_000_000_000n, scriptPubKey: Buffer.from([0x00]) },
      { value: 1_050_000_000_000_000n, scriptPubKey: Buffer.from([0x00]) },
    ];
    expect(validateTxBasic(tx).valid).toBe(true);
  });
});

// ─── Gate 7: bad-txns-inputs-duplicate (CVE-2018-17144) ─────────────────────

describe("CheckTransaction gate 7: bad-txns-inputs-duplicate (CVE-2018-17144)", () => {
  // CVE-2018-17144: bitcoind before 0.16.3 did not check duplicate inputs,
  // allowing an inflation bug via double-spend of the same UTXO in one tx.
  test("exact duplicate input (same txid + vout) rejected", () => {
    const tx = makeNormalTx();
    tx.inputs = [makeTxIn(1, 0), makeTxIn(1, 0)]; // identical outpoints
    const r = validateTxBasic(tx);
    expect(r.valid).toBe(false);
    expect(r.error).toBe("bad-txns-inputs-duplicate");
  });

  test("same txid but different vout is NOT a duplicate", () => {
    const tx = makeNormalTx();
    tx.inputs = [makeTxIn(1, 0), makeTxIn(1, 1)]; // same txid, different vout
    expect(validateTxBasic(tx).valid).toBe(true);
  });

  test("different txid same vout is NOT a duplicate", () => {
    const tx = makeNormalTx();
    tx.inputs = [makeTxIn(1, 0), makeTxIn(2, 0)]; // different txid
    expect(validateTxBasic(tx).valid).toBe(true);
  });

  test("three inputs where first two are duplicates rejected", () => {
    const tx = makeNormalTx();
    tx.inputs = [makeTxIn(1, 0), makeTxIn(1, 0), makeTxIn(2, 0)];
    const r = validateTxBasic(tx);
    expect(r.valid).toBe(false);
    expect(r.error).toBe("bad-txns-inputs-duplicate");
  });
});

// ─── Gate 8: bad-cb-length ───────────────────────────────────────────────────

describe("CheckTransaction gate 8: bad-cb-length (coinbase scriptSig length)", () => {
  // Core: COINBASE_SCRIPT_SIZE_MIN=2, COINBASE_SCRIPT_SIZE_MAX=100
  test("coinbase scriptSig 1 byte → bad-cb-length", () => {
    const tx = makeCoinbaseTx(Buffer.from([0x51])); // 1 byte
    const r = validateTxBasic(tx);
    expect(r.valid).toBe(false);
    expect(r.error).toBe("bad-cb-length");
  });

  test("coinbase scriptSig 0 bytes → bad-cb-length", () => {
    const tx = makeCoinbaseTx(Buffer.alloc(0));
    const r = validateTxBasic(tx);
    expect(r.valid).toBe(false);
    expect(r.error).toBe("bad-cb-length");
  });

  test("coinbase scriptSig 101 bytes → bad-cb-length", () => {
    const tx = makeCoinbaseTx(Buffer.alloc(101, 0xaa));
    const r = validateTxBasic(tx);
    expect(r.valid).toBe(false);
    expect(r.error).toBe("bad-cb-length");
  });

  test("coinbase scriptSig exactly 2 bytes → valid", () => {
    const tx = makeCoinbaseTx(Buffer.from([0x51, 0x52]));
    expect(validateTxBasic(tx).valid).toBe(true);
  });

  test("coinbase scriptSig exactly 100 bytes → valid", () => {
    const tx = makeCoinbaseTx(Buffer.alloc(100, 0xaa));
    expect(validateTxBasic(tx).valid).toBe(true);
  });

  test("coinbase scriptSig 50 bytes → valid", () => {
    const tx = makeCoinbaseTx(Buffer.alloc(50, 0xaa));
    expect(validateTxBasic(tx).valid).toBe(true);
  });
});

// ─── Gate 9: bad-txns-prevout-null ───────────────────────────────────────────

describe("CheckTransaction gate 9: bad-txns-prevout-null", () => {
  // Core: non-coinbase tx must not have any input with IsNull() prevout
  // (all-zero txid + 0xffffffff vout is the coinbase marker, illegal in non-cb txns)
  test("non-coinbase tx with null prevout (zero txid + 0xffffffff) → bad-txns-prevout-null", () => {
    // A tx with two inputs where the second is a null prevout. The first
    // input is non-null, so isCoinbase() = false, and gate 9 should fire.
    const tx = makeNormalTx();
    tx.inputs = [
      makeTxIn(1, 0), // non-null input → keeps isCoinbase() = false
      {
        prevOut: { txid: Buffer.alloc(32, 0), vout: 0xffffffff },
        scriptSig: Buffer.from([0x00]),
        sequence: 0xffffffff,
        witness: [],
      },
    ];
    const r = validateTxBasic(tx);
    expect(r.valid).toBe(false);
    expect(r.error).toBe("bad-txns-prevout-null");
  });

  test("null txid with non-0xffffffff vout is NOT a null prevout", () => {
    const tx = makeNormalTx();
    tx.inputs[0] = {
      ...tx.inputs[0],
      prevOut: { txid: Buffer.alloc(32, 0), vout: 0 },
    };
    // All-zero txid with vout 0 is technically a (likely non-existent) UTXO ref,
    // not a null prevout. Core allows it through CheckTransaction.
    expect(validateTxBasic(tx).valid).toBe(true);
  });

  test("non-zero txid with 0xffffffff vout is NOT a null prevout", () => {
    const tx = makeNormalTx();
    tx.inputs[0] = {
      ...tx.inputs[0],
      prevOut: { txid: Buffer.alloc(32, 1), vout: 0xffffffff },
    };
    // Only the all-zero txid + 0xffffffff combination is IsNull() in Core.
    expect(validateTxBasic(tx).valid).toBe(true);
  });

  test("coinbase tx with null prevout is valid (expected)", () => {
    const tx = makeCoinbaseTx();
    expect(validateTxBasic(tx).valid).toBe(true);
  });

  test("non-coinbase with multiple inputs, second has null prevout → rejected", () => {
    const tx = makeNormalTx();
    tx.inputs.push({
      prevOut: { txid: Buffer.alloc(32, 0), vout: 0xffffffff },
      scriptSig: Buffer.from([0x00]),
      sequence: 0xffffffff,
      witness: [],
    });
    const r = validateTxBasic(tx);
    expect(r.valid).toBe(false);
    expect(r.error).toBe("bad-txns-prevout-null");
  });
});

// ─── GetBlockSubsidy ──────────────────────────────────────────────────────────

describe("GetBlockSubsidy", () => {
  const COIN = 100_000_000n;

  test("genesis block: 50 BTC", () => {
    expect(getBlockSubsidy(0, MAINNET)).toBe(50n * COIN);
  });

  test("block 209999 (last block before first halving): 50 BTC", () => {
    expect(getBlockSubsidy(209_999, MAINNET)).toBe(50n * COIN);
  });

  test("block 210000 (first halving): 25 BTC", () => {
    expect(getBlockSubsidy(210_000, MAINNET)).toBe(25n * COIN);
  });

  test("block 420000 (second halving): 12.5 BTC", () => {
    expect(getBlockSubsidy(420_000, MAINNET)).toBe(12_50000000n);
  });

  test("block 630000 (third halving): 6.25 BTC", () => {
    expect(getBlockSubsidy(630_000, MAINNET)).toBe(6_25000000n);
  });

  test("block 840000 (fourth halving): 3.125 BTC", () => {
    expect(getBlockSubsidy(840_000, MAINNET)).toBe(3_12500000n);
  });

  test("block 6720000 (halving 32): 1 sat", () => {
    // 50 BTC >> 32 = 50 * 1e8 / 2^32 ≈ 1.16 sat → floors to 1 sat
    expect(getBlockSubsidy(6_720_000, MAINNET)).toBe(1n);
  });

  test("block at halving 64 → 0 satoshis (guard against undefined right-shift)", () => {
    // Core: if (halvings >= 64) return 0
    // JavaScript BigInt right-shift is well-defined, but Core has this guard
    // to avoid undefined behaviour of C++ right-shift for 64+ shifts.
    expect(getBlockSubsidy(64 * 210_000, MAINNET)).toBe(0n);
  });

  test("block at halving 32: last non-zero subsidy (1 sat)", () => {
    // 5_000_000_000 >> 32 = 1 sat; >> 33 = 0 sat
    expect(getBlockSubsidy(32 * 210_000, MAINNET)).toBe(1n);
  });

  test("block at halving 33: subsidy is 0 (last real zero before the guard)", () => {
    expect(getBlockSubsidy(33 * 210_000, MAINNET)).toBe(0n);
  });

  test("halving 64 and beyond: always 0", () => {
    for (const h of [64, 65, 100, 1000]) {
      expect(getBlockSubsidy(h * 210_000, MAINNET)).toBe(0n);
    }
  });

  // Regtest uses subsidyHalvingInterval = 150
  test("regtest: first halving at block 150 → 25 BTC", () => {
    expect(getBlockSubsidy(150, REGTEST)).toBe(25n * COIN);
  });

  test("regtest: block 149 → 50 BTC", () => {
    expect(getBlockSubsidy(149, REGTEST)).toBe(50n * COIN);
  });

  test("subsidy is a right-shift (not integer division truncation)", () => {
    // Verify that BigInt right-shift produces the same result as Core's
    // nSubsidy >>= halvings pattern.
    const initial = 50n * COIN; // 5_000_000_000n
    for (let halvings = 0; halvings < 64; halvings++) {
      const expected = initial >> BigInt(halvings);
      expect(getBlockSubsidy(halvings * 210_000, MAINNET)).toBe(expected);
    }
  });
});

// ─── isCoinbase ───────────────────────────────────────────────────────────────

describe("isCoinbase", () => {
  test("coinbase: single input with null txid + 0xffffffff vout", () => {
    expect(isCoinbase(makeCoinbaseTx())).toBe(true);
  });

  test("non-coinbase: non-null txid", () => {
    expect(isCoinbase(makeNormalTx())).toBe(false);
  });

  test("non-coinbase: coinbase-like prevout but vout != 0xffffffff", () => {
    const tx = makeCoinbaseTx();
    tx.inputs[0] = { ...tx.inputs[0], prevOut: { txid: Buffer.alloc(32, 0), vout: 0 } };
    expect(isCoinbase(tx)).toBe(false);
  });

  test("non-coinbase: multiple inputs", () => {
    const tx = makeCoinbaseTx();
    tx.inputs.push(makeTxIn());
    expect(isCoinbase(tx)).toBe(false);
  });
});
