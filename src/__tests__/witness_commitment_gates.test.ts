/**
 * W77 — BIP-141 witness commitment comprehensive gate tests.
 *
 * Covers all 12 gates from Bitcoin Core's CheckWitnessMalleation() and
 * GetWitnessCommitmentIndex() (validation.cpp:3864-3916,
 * consensus/validation.h:147-165).
 *
 * Gate map:
 *  A  — segwit active → enter commitment-validation branch
 *  B  — coinbase witness stack must have exactly 1 item (bad-witness-nonce-size)
 *  C  — that item must be exactly 32 bytes (bad-witness-nonce-size)
 *  D  — SHA256d(witness_merkle_root || nonce) must equal committed hash
 *       (bad-witness-merkle-match)
 *  E  — no witness data allowed when no commitment present (unexpected-witness)
 *  F  — commitment scan is forward; LAST matching output wins
 *  G  — size gate: scriptPubKey.length >= 38 (MINIMUM_WITNESS_COMMITMENT)
 *  H  — magic byte check: [0]=0x6a [1]=0x24 [2..5]=0xaa21a9ed
 *  I  — empty block → NO_WITNESS_COMMITMENT
 *  J  — coinbase witness 0 items → bad-witness-nonce-size (NOT a silently-zero fallback)
 *  K  — coinbase witness item wrong length (e.g. 31 bytes) → bad-witness-nonce-size
 *  L  — segwit NOT active + witness data in non-coinbase tx → unexpected-witness
 */

import { describe, expect, test } from "bun:test";
import { hash256 } from "../crypto/primitives";
import { REGTEST } from "../consensus/params";
import {
  Block,
  computeMerkleRoot,
  getWitnessCommitmentIndex,
  getWitnessCommitment,
  checkWitnessMalleation,
  validateBlock,
  NO_WITNESS_COMMITMENT,
  MINIMUM_WITNESS_COMMITMENT,
} from "../validation/block";
import { Transaction, getTxId, getWTxId } from "../validation/tx";
import { encodeBip34Height } from "../validation/block";

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

/** Build a minimal coinbase transaction for the given height. */
function makeCoinbase(height: number = 1, witnessStack: Buffer[] = []): Transaction {
  const heightEnc = encodeBip34Height(height);
  const scriptSig =
    heightEnc.length < 2 ? Buffer.concat([heightEnc, Buffer.from([0x00])]) : heightEnc;

  return {
    version: 1,
    inputs: [
      {
        prevOut: { txid: Buffer.alloc(32, 0), vout: 0xffffffff },
        scriptSig,
        sequence: 0xffffffff,
        witness: witnessStack,
      },
    ],
    outputs: [{ value: 5_000_000_000n, scriptPubKey: Buffer.from([0x51]) }],
    lockTime: 0,
  };
}

/** Build a minimal non-coinbase transaction, optionally with witness data. */
function makeRegularTx(witness: Buffer[] = []): Transaction {
  return {
    version: 1,
    inputs: [
      {
        prevOut: { txid: Buffer.alloc(32, 1), vout: 0 },
        scriptSig: Buffer.from([0x00]),
        sequence: 0xffffffff,
        witness,
      },
    ],
    outputs: [{ value: 100_000_000n, scriptPubKey: Buffer.from([0x51]) }],
    lockTime: 0,
  };
}

/** Build a 6+32 = 38-byte witness commitment script (OP_RETURN + magic + hash). */
function makeCommitmentScript(hash: Buffer): Buffer {
  return Buffer.concat([
    Buffer.from([0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed]),
    hash,
  ]);
}

/**
 * Compute the correct witness commitment for a list of transactions.
 * Mirrors Core: SHA256d(BlockWitnessMerkleRoot || witnessNonce).
 * coinbase wtxid is treated as 0x000...000.
 */
function computeCorrectCommitment(
  txs: Transaction[],
  witnessNonce: Buffer
): Buffer {
  const wtxids = txs.map((tx, i) =>
    i === 0 ? Buffer.alloc(32, 0) : getWTxId(tx)
  );
  const witnessMerkleRoot = computeMerkleRoot(wtxids);
  return hash256(Buffer.concat([witnessMerkleRoot, witnessNonce]));
}

/**
 * Assemble a complete block with correct merkle root.
 * The coinbase is taken from `transactions[0]`.
 */
function makeBlock(transactions: Transaction[]): Block {
  const txids = transactions.map(getTxId);
  const merkleRoot = computeMerkleRoot(txids);
  return {
    header: {
      version: 0x20000000,
      prevBlock: Buffer.alloc(32, 0),
      merkleRoot,
      timestamp: Math.floor(Date.now() / 1000),
      bits: REGTEST.powLimitBits,
      nonce: 0,
    },
    transactions,
  };
}

/**
 * Convenience: build a segwit-valid block with correct commitment.
 * Returns the block, segwit height, and the nonce used.
 */
function makeValidSegwitBlock(): { block: Block; segwitHeight: number; nonce: Buffer } {
  const nonce = Buffer.alloc(32, 0); // canonical zero nonce

  // Build a coinbase with the correct witness nonce but no commitment output yet
  const coinbase = makeCoinbase(1, [nonce]);

  // Add a non-coinbase tx with witness data
  const regularTx = makeRegularTx([Buffer.from("witness data")]);

  const txs = [coinbase, regularTx];

  // Compute the correct commitment hash
  const commitment = computeCorrectCommitment(txs, nonce);
  const commitScript = makeCommitmentScript(commitment);

  // Add the commitment output to the coinbase
  coinbase.outputs.push({ value: 0n, scriptPubKey: commitScript });

  // Build a fresh coinbase with the output update (re-compute txid)
  const block = makeBlock([coinbase, regularTx]);

  return { block, segwitHeight: 1, nonce };
}

// ---------------------------------------------------------------------------
// Gate A: segwit active branch
// ---------------------------------------------------------------------------

describe("Gate A — segwit active enters commitment branch", () => {
  test("valid segwit block passes checkWitnessMalleation(true)", () => {
    const { block } = makeValidSegwitBlock();
    const result = checkWitnessMalleation(block, true);
    expect(result.valid).toBe(true);
  });

  test("valid segwit block passes validateBlock at segwitHeight", () => {
    const { block, segwitHeight } = makeValidSegwitBlock();
    const params = { ...REGTEST, segwitHeight };
    const result = validateBlock(block, segwitHeight, params);
    expect(result.valid).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Gate B: coinbase witness stack must have exactly 1 item
// ---------------------------------------------------------------------------

describe("Gate B — coinbase witness stack size must be exactly 1", () => {
  test("0 items in witness stack → bad-witness-nonce-size", () => {
    // Build coinbase with commitment output but NO witness stack
    const coinbase = makeCoinbase(1, []); // empty witness stack
    const dummyCommitment = Buffer.alloc(32, 0xab);
    coinbase.outputs.push({ value: 0n, scriptPubKey: makeCommitmentScript(dummyCommitment) });

    const block = makeBlock([coinbase]);
    const result = checkWitnessMalleation(block, true);
    expect(result.valid).toBe(false);
    expect(result.error).toBe("bad-witness-nonce-size");
  });

  test("2 items in witness stack → bad-witness-nonce-size", () => {
    const coinbase = makeCoinbase(1, [Buffer.alloc(32, 0), Buffer.alloc(32, 0)]);
    const dummyCommitment = Buffer.alloc(32, 0xab);
    coinbase.outputs.push({ value: 0n, scriptPubKey: makeCommitmentScript(dummyCommitment) });

    const block = makeBlock([coinbase]);
    const result = checkWitnessMalleation(block, true);
    expect(result.valid).toBe(false);
    expect(result.error).toBe("bad-witness-nonce-size");
  });
});

// ---------------------------------------------------------------------------
// Gate C: coinbase witness item must be exactly 32 bytes
// ---------------------------------------------------------------------------

describe("Gate C — witness nonce must be exactly 32 bytes", () => {
  test("31-byte nonce → bad-witness-nonce-size", () => {
    const coinbase = makeCoinbase(1, [Buffer.alloc(31, 0)]); // 31 bytes, not 32
    const dummyCommitment = Buffer.alloc(32, 0xab);
    coinbase.outputs.push({ value: 0n, scriptPubKey: makeCommitmentScript(dummyCommitment) });

    const block = makeBlock([coinbase]);
    const result = checkWitnessMalleation(block, true);
    expect(result.valid).toBe(false);
    expect(result.error).toBe("bad-witness-nonce-size");
  });

  test("33-byte nonce → bad-witness-nonce-size", () => {
    const coinbase = makeCoinbase(1, [Buffer.alloc(33, 0)]); // 33 bytes
    const dummyCommitment = Buffer.alloc(32, 0xab);
    coinbase.outputs.push({ value: 0n, scriptPubKey: makeCommitmentScript(dummyCommitment) });

    const block = makeBlock([coinbase]);
    const result = checkWitnessMalleation(block, true);
    expect(result.valid).toBe(false);
    expect(result.error).toBe("bad-witness-nonce-size");
  });

  test("0-byte nonce → bad-witness-nonce-size (not silent fallback)", () => {
    // This is the regression: old code used a 32-zero fallback for missing/wrong-size nonces.
    const coinbase = makeCoinbase(1, [Buffer.alloc(0)]); // 0 bytes
    const dummyCommitment = Buffer.alloc(32, 0xab);
    coinbase.outputs.push({ value: 0n, scriptPubKey: makeCommitmentScript(dummyCommitment) });

    const block = makeBlock([coinbase]);
    const result = checkWitnessMalleation(block, true);
    expect(result.valid).toBe(false);
    expect(result.error).toBe("bad-witness-nonce-size");
  });

  test("correct 32-byte nonce passes gate C", () => {
    const { block } = makeValidSegwitBlock();
    const result = checkWitnessMalleation(block, true);
    expect(result.valid).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Gate D: SHA256d hash must match committed value
// ---------------------------------------------------------------------------

describe("Gate D — witness merkle hash must match commitment", () => {
  test("wrong commitment hash → bad-witness-merkle-match", () => {
    const nonce = Buffer.alloc(32, 0);
    const coinbase = makeCoinbase(1, [nonce]);
    // Use a wrong (all-0xff) commitment
    const wrongHash = Buffer.alloc(32, 0xff);
    coinbase.outputs.push({ value: 0n, scriptPubKey: makeCommitmentScript(wrongHash) });

    const block = makeBlock([coinbase]);
    const result = checkWitnessMalleation(block, true);
    expect(result.valid).toBe(false);
    expect(result.error).toBe("bad-witness-merkle-match");
  });

  test("flipped bit in commitment → bad-witness-merkle-match", () => {
    const nonce = Buffer.alloc(32, 0);
    const coinbase = makeCoinbase(1, [nonce]);
    const txs = [coinbase];
    const correctHash = computeCorrectCommitment(txs, nonce);

    // Flip one bit
    const badHash = Buffer.from(correctHash);
    badHash[0] ^= 0x01;
    coinbase.outputs.push({ value: 0n, scriptPubKey: makeCommitmentScript(badHash) });

    const block = makeBlock([coinbase]);
    const result = checkWitnessMalleation(block, true);
    expect(result.valid).toBe(false);
    expect(result.error).toBe("bad-witness-merkle-match");
  });

  test("correct commitment → passes gate D", () => {
    const nonce = Buffer.alloc(32, 0);
    const coinbase = makeCoinbase(1, [nonce]);
    const txs = [coinbase];
    const correctHash = computeCorrectCommitment(txs, nonce);
    coinbase.outputs.push({ value: 0n, scriptPubKey: makeCommitmentScript(correctHash) });

    const block = makeBlock(txs);
    const result = checkWitnessMalleation(block, true);
    expect(result.valid).toBe(true);
  });

  test("commitment hash depends on actual wtxids (non-coinbase tx)", () => {
    const nonce = Buffer.alloc(32, 0);
    const coinbase = makeCoinbase(1, [nonce]);
    const regularTx = makeRegularTx([Buffer.from("witness")]);
    const txs = [coinbase, regularTx];

    const correctHash = computeCorrectCommitment(txs, nonce);
    coinbase.outputs.push({ value: 0n, scriptPubKey: makeCommitmentScript(correctHash) });

    const block = makeBlock(txs);
    const result = checkWitnessMalleation(block, true);
    expect(result.valid).toBe(true);
  });

  test("non-coinbase witness data changes wtxid → wrong commitment → bad-witness-merkle-match", () => {
    const nonce = Buffer.alloc(32, 0);
    const coinbase = makeCoinbase(1, [nonce]);

    // Compute commitment for [coinbase] only
    const wrongHash = computeCorrectCommitment([coinbase], nonce);
    coinbase.outputs.push({ value: 0n, scriptPubKey: makeCommitmentScript(wrongHash) });

    // But block also has regularTx with witness — changes witness merkle root
    const regularTx = makeRegularTx([Buffer.from("extra witness")]);
    const block = makeBlock([coinbase, regularTx]);

    const result = checkWitnessMalleation(block, true);
    expect(result.valid).toBe(false);
    expect(result.error).toBe("bad-witness-merkle-match");
  });
});

// ---------------------------------------------------------------------------
// Gate E: unexpected-witness
// ---------------------------------------------------------------------------

describe("Gate E — unexpected-witness rejection", () => {
  test("segwit NOT active + coinbase has witness → unexpected-witness (checkWitnessMalleation)", () => {
    const coinbase = makeCoinbase(1, [Buffer.alloc(32, 0)]); // witness nonce
    const block = makeBlock([coinbase]);
    const result = checkWitnessMalleation(block, false); // segwit not active
    expect(result.valid).toBe(false);
    expect(result.error).toBe("unexpected-witness");
  });

  test("segwit NOT active + non-coinbase has witness → unexpected-witness", () => {
    const coinbase = makeCoinbase(1, []);
    const regularTx = makeRegularTx([Buffer.from("witness")]);
    const block = makeBlock([coinbase, regularTx]);

    const result = checkWitnessMalleation(block, false);
    expect(result.valid).toBe(false);
    expect(result.error).toBe("unexpected-witness");
  });

  test("segwit NOT active + no witness → valid", () => {
    const coinbase = makeCoinbase(1, []);
    const block = makeBlock([coinbase]);
    const result = checkWitnessMalleation(block, false);
    expect(result.valid).toBe(true);
  });

  test("segwit active + NO commitment + witness data → unexpected-witness (not 'Missing commitment')", () => {
    // Regression: old code returned "Missing witness commitment" here;
    // Core returns "unexpected-witness" because the unexpected-witness check fires.
    const coinbase = makeCoinbase(1, [Buffer.alloc(32, 0)]);
    // No commitment output added
    const block = makeBlock([coinbase]);

    const result = checkWitnessMalleation(block, true);
    expect(result.valid).toBe(false);
    expect(result.error).toBe("unexpected-witness");
  });

  test("segwit active + NO commitment + NO witness data → valid (OK to omit commitment)", () => {
    const coinbase = makeCoinbase(1, []);
    const block = makeBlock([coinbase]);
    const result = checkWitnessMalleation(block, true);
    expect(result.valid).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Gate F: last commitment output wins (forward scan, keep updating)
// ---------------------------------------------------------------------------

describe("Gate F — last matching output wins (forward scan)", () => {
  test("getWitnessCommitmentIndex returns index of LAST matching output", () => {
    const coinbase = makeCoinbase(1, []);
    const hash1 = Buffer.alloc(32, 0x01);
    const hash2 = Buffer.alloc(32, 0x02);
    const hash3 = Buffer.alloc(32, 0x03);

    coinbase.outputs.push({ value: 0n, scriptPubKey: makeCommitmentScript(hash1) });
    coinbase.outputs.push({ value: 0n, scriptPubKey: makeCommitmentScript(hash2) });
    coinbase.outputs.push({ value: 0n, scriptPubKey: makeCommitmentScript(hash3) });

    const block = makeBlock([coinbase]);
    const idx = getWitnessCommitmentIndex(block);
    // hash1 at output 1, hash2 at output 2, hash3 at output 3 — last = index 3
    expect(idx).toBe(3);
  });

  test("getWitnessCommitment returns hash from LAST matching output", () => {
    const coinbase = makeCoinbase(1, []);
    const hash1 = Buffer.alloc(32, 0x01);
    const hash2 = Buffer.alloc(32, 0x02);

    coinbase.outputs.push({ value: 0n, scriptPubKey: makeCommitmentScript(hash1) });
    coinbase.outputs.push({ value: 0n, scriptPubKey: makeCommitmentScript(hash2) });

    const block = makeBlock([coinbase]);
    const commitment = getWitnessCommitment(block);
    expect(commitment).not.toBeNull();
    expect(commitment!.equals(hash2)).toBe(true); // last one
  });

  test("only last commitment output is validated in checkWitnessMalleation", () => {
    // First output has garbage hash, second output has correct hash.
    // Should PASS because last (correct) output is used.
    const nonce = Buffer.alloc(32, 0);
    const coinbase = makeCoinbase(1, [nonce]);
    const txs = [coinbase];

    const wrongHash = Buffer.alloc(32, 0xff);
    const correctHash = computeCorrectCommitment(txs, nonce);

    coinbase.outputs.push({ value: 0n, scriptPubKey: makeCommitmentScript(wrongHash) });
    coinbase.outputs.push({ value: 0n, scriptPubKey: makeCommitmentScript(correctHash) });

    const block = makeBlock(txs);
    const result = checkWitnessMalleation(block, true);
    expect(result.valid).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Gate G: MINIMUM_WITNESS_COMMITMENT size check (>= 38)
// ---------------------------------------------------------------------------

describe("Gate G — scriptPubKey must be >= 38 bytes", () => {
  test("script exactly 38 bytes is recognized as commitment", () => {
    const coinbase = makeCoinbase(1, []);
    const hash = Buffer.alloc(32, 0xab);
    const script = makeCommitmentScript(hash); // exactly 38 bytes
    expect(script.length).toBe(MINIMUM_WITNESS_COMMITMENT);
    coinbase.outputs.push({ value: 0n, scriptPubKey: script });

    const block = makeBlock([coinbase]);
    expect(getWitnessCommitmentIndex(block)).toBeGreaterThanOrEqual(0);
  });

  test("script 37 bytes is NOT recognized as commitment", () => {
    const coinbase = makeCoinbase(1, []);
    // 37 bytes: 6-byte header + 31-byte partial hash
    const shortScript = Buffer.concat([
      Buffer.from([0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed]),
      Buffer.alloc(31, 0xab), // only 31 bytes instead of 32
    ]);
    expect(shortScript.length).toBe(37);
    coinbase.outputs.push({ value: 0n, scriptPubKey: shortScript });

    const block = makeBlock([coinbase]);
    expect(getWitnessCommitmentIndex(block)).toBe(NO_WITNESS_COMMITMENT);
  });

  test("script > 38 bytes is still recognized (extra data after commitment)", () => {
    const coinbase = makeCoinbase(1, []);
    const hash = Buffer.alloc(32, 0xab);
    // Append 5 extra bytes after the standard 38
    const longScript = Buffer.concat([makeCommitmentScript(hash), Buffer.alloc(5, 0x00)]);
    expect(longScript.length).toBe(43);
    coinbase.outputs.push({ value: 0n, scriptPubKey: longScript });

    const block = makeBlock([coinbase]);
    expect(getWitnessCommitmentIndex(block)).toBeGreaterThanOrEqual(0);
  });
});

// ---------------------------------------------------------------------------
// Gate H: Magic byte check
// ---------------------------------------------------------------------------

describe("Gate H — magic bytes 0x6a 0x24 0xaa21a9ed", () => {
  function makeScriptWithMagic(b0: number, b1: number, b2: number, b3: number, b4: number, b5: number): Buffer {
    return Buffer.concat([
      Buffer.from([b0, b1, b2, b3, b4, b5]),
      Buffer.alloc(32, 0),
    ]);
  }

  test("OP_RETURN byte wrong (0x6b instead of 0x6a) → not recognized", () => {
    const coinbase = makeCoinbase(1, []);
    coinbase.outputs.push({ value: 0n, scriptPubKey: makeScriptWithMagic(0x6b, 0x24, 0xaa, 0x21, 0xa9, 0xed) });
    const block = makeBlock([coinbase]);
    expect(getWitnessCommitmentIndex(block)).toBe(NO_WITNESS_COMMITMENT);
  });

  test("push byte wrong (0x23 instead of 0x24) → not recognized", () => {
    const coinbase = makeCoinbase(1, []);
    coinbase.outputs.push({ value: 0n, scriptPubKey: makeScriptWithMagic(0x6a, 0x23, 0xaa, 0x21, 0xa9, 0xed) });
    const block = makeBlock([coinbase]);
    expect(getWitnessCommitmentIndex(block)).toBe(NO_WITNESS_COMMITMENT);
  });

  test("magic byte 2 wrong (0xab instead of 0xaa) → not recognized", () => {
    const coinbase = makeCoinbase(1, []);
    coinbase.outputs.push({ value: 0n, scriptPubKey: makeScriptWithMagic(0x6a, 0x24, 0xab, 0x21, 0xa9, 0xed) });
    const block = makeBlock([coinbase]);
    expect(getWitnessCommitmentIndex(block)).toBe(NO_WITNESS_COMMITMENT);
  });

  test("magic byte 3 wrong (0x20 instead of 0x21) → not recognized", () => {
    const coinbase = makeCoinbase(1, []);
    coinbase.outputs.push({ value: 0n, scriptPubKey: makeScriptWithMagic(0x6a, 0x24, 0xaa, 0x20, 0xa9, 0xed) });
    const block = makeBlock([coinbase]);
    expect(getWitnessCommitmentIndex(block)).toBe(NO_WITNESS_COMMITMENT);
  });

  test("correct magic → recognized", () => {
    const coinbase = makeCoinbase(1, []);
    coinbase.outputs.push({ value: 0n, scriptPubKey: makeScriptWithMagic(0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed) });
    const block = makeBlock([coinbase]);
    expect(getWitnessCommitmentIndex(block)).toBeGreaterThanOrEqual(0);
  });
});

// ---------------------------------------------------------------------------
// Gate I: Empty block → NO_WITNESS_COMMITMENT
// ---------------------------------------------------------------------------

describe("Gate I — empty transaction list → NO_WITNESS_COMMITMENT", () => {
  test("getWitnessCommitmentIndex returns -1 for empty block", () => {
    const block: Block = {
      header: {
        version: 1,
        prevBlock: Buffer.alloc(32, 0),
        merkleRoot: Buffer.alloc(32, 0),
        timestamp: 0,
        bits: REGTEST.powLimitBits,
        nonce: 0,
      },
      transactions: [],
    };
    expect(getWitnessCommitmentIndex(block)).toBe(NO_WITNESS_COMMITMENT);
  });

  test("getWitnessCommitment returns null for empty block", () => {
    const block: Block = {
      header: {
        version: 1,
        prevBlock: Buffer.alloc(32, 0),
        merkleRoot: Buffer.alloc(32, 0),
        timestamp: 0,
        bits: REGTEST.powLimitBits,
        nonce: 0,
      },
      transactions: [],
    };
    expect(getWitnessCommitment(block)).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// Gate J: 0 witness items → bad-witness-nonce-size (regression: was silently zero-filled)
// ---------------------------------------------------------------------------

describe("Gate J — 0 witness items is not silently treated as 32-zero nonce", () => {
  test("commitment present + coinbase witness.length == 0 → bad-witness-nonce-size", () => {
    const coinbase = makeCoinbase(1, []); // EMPTY witness stack
    const dummyHash = Buffer.alloc(32, 0xcc);
    coinbase.outputs.push({ value: 0n, scriptPubKey: makeCommitmentScript(dummyHash) });

    const block = makeBlock([coinbase]);
    const result = checkWitnessMalleation(block, true);
    expect(result.valid).toBe(false);
    expect(result.error).toBe("bad-witness-nonce-size");
  });
});

// ---------------------------------------------------------------------------
// Gate K: witness item wrong length → bad-witness-nonce-size
// ---------------------------------------------------------------------------

describe("Gate K — nonce wrong length rejects (not silently ignored)", () => {
  for (const len of [0, 1, 16, 31, 33, 64]) {
    test(`nonce length ${len} → bad-witness-nonce-size`, () => {
      const coinbase = makeCoinbase(1, [Buffer.alloc(len, 0)]);
      const dummyHash = Buffer.alloc(32, 0xcc);
      coinbase.outputs.push({ value: 0n, scriptPubKey: makeCommitmentScript(dummyHash) });

      const block = makeBlock([coinbase]);
      const result = checkWitnessMalleation(block, true);
      expect(result.valid).toBe(false);
      expect(result.error).toBe("bad-witness-nonce-size");
    });
  }
});

// ---------------------------------------------------------------------------
// Gate L: segwit NOT active + witness in any tx → unexpected-witness via validateBlock
// ---------------------------------------------------------------------------

describe("Gate L — validateBlock rejects witness data when segwit not active", () => {
  test("segwit inactive + coinbase witness → unexpected-witness from validateBlock", () => {
    const coinbase = makeCoinbase(1, [Buffer.alloc(32, 0)]);
    const block = makeBlock([coinbase]);

    // Use params with segwitHeight far in the future (height 1 is pre-segwit)
    const params = { ...REGTEST, segwitHeight: 100 };
    const result = validateBlock(block, 1, params);
    expect(result.valid).toBe(false);
    expect(result.error).toBe("unexpected-witness");
  });

  test("segwit inactive + non-coinbase witness → unexpected-witness from validateBlock", () => {
    const coinbase = makeCoinbase(1, []);
    const regularTx = makeRegularTx([Buffer.from("witness")]);
    const txs = [coinbase, regularTx];
    const block = makeBlock(txs);

    const params = { ...REGTEST, segwitHeight: 100 };
    const result = validateBlock(block, 1, params);
    expect(result.valid).toBe(false);
    expect(result.error).toBe("unexpected-witness");
  });

  test("segwit active + valid commitment → passes validateBlock", () => {
    const { block, segwitHeight } = makeValidSegwitBlock();
    const params = { ...REGTEST, segwitHeight };
    const result = validateBlock(block, segwitHeight, params);
    expect(result.valid).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Integration: regression for old "Missing witness commitment" error string
// ---------------------------------------------------------------------------

describe("Regression — old 'Missing witness commitment' error replaced by 'unexpected-witness'", () => {
  test("segwit active + witness data + NO commitment output → unexpected-witness (not 'Missing commitment')", () => {
    // Old code returned "Missing witness commitment"; Core returns "unexpected-witness"
    // because the no-commitment path falls through to the unexpected-witness scan.
    const nonce = Buffer.alloc(32, 0);
    const coinbase = makeCoinbase(1, [nonce]); // has witness but no commitment output
    const regularTx = makeRegularTx([Buffer.from("witness")]);
    const block = makeBlock([coinbase, regularTx]);

    const params = { ...REGTEST, segwitHeight: 1 };
    const result = validateBlock(block, 1, params);
    expect(result.valid).toBe(false);
    expect(result.error).toBe("unexpected-witness");
    expect(result.error).not.toContain("Missing");
  });
});
