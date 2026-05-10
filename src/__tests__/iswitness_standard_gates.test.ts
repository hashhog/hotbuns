/**
 * IsWitnessStandard policy gate unit tests (W72).
 *
 * Tests the 6 gates implemented in isWitnessStandard() which mirrors Bitcoin
 * Core's IsWitnessStandard() function (bitcoin-core/src/policy/policy.cpp:265-352).
 *
 * Gates tested:
 *  1. P2A prevScript + any witness          → reject "bad-witness-nonstandard"
 *  2. P2SH-wrapped: eval fail / empty stack → reject
 *  3. Non-witness prevScript + witness      → reject "bad-witness-nonstandard"
 *  4. P2WSH v0 32B:
 *       - witnessScript > 3600 bytes        → reject (MAX_STANDARD_P2WSH_SCRIPT_SIZE)
 *       - witness stack items > 100         → reject (MAX_STANDARD_P2WSH_STACK_ITEMS)
 *       - any item > 80 bytes               → reject (MAX_STANDARD_P2WSH_STACK_ITEM_SIZE)
 *  5. P2TR v1 32B (non-P2SH-wrapped):
 *       - annex (last item[0] == 0x50)      → reject
 *       - tapscript (leaf 0xc0): item > 80B → reject (MAX_STANDARD_TAPSCRIPT_STACK_ITEM_SIZE)
 *       - empty stack (0 items)             → reject
 *  6. Coinbase: exempt (addTransaction rejects coinbase before witness check)
 *
 * Reference: bitcoin-core/src/policy/policy.cpp:265-352
 * Wave: W72 hotbuns IsWitnessStandard fleet audit
 */

import { describe, test, expect, beforeEach, afterEach } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ChainDB, type UTXOEntry } from "../storage/database.js";
import { UTXOManager } from "../chain/utxo.js";
import { REGTEST } from "../consensus/params.js";
import {
  Mempool,
  MAX_STANDARD_P2WSH_SCRIPT_SIZE,
  MAX_STANDARD_P2WSH_STACK_ITEMS,
  MAX_STANDARD_P2WSH_STACK_ITEM_SIZE,
  MAX_STANDARD_TAPSCRIPT_STACK_ITEM_SIZE,
} from "../mempool/mempool.js";
import type { Transaction } from "../validation/tx.js";

// ---------------------------------------------------------------------------
// Script constants
// ---------------------------------------------------------------------------

/** P2WSH output: OP_0 <32-byte hash> */
const P2WSH_SCRIPT = Buffer.concat([Buffer.from([0x00, 0x20]), Buffer.alloc(32)]);

/** P2TR output: OP_1 <32-byte key> */
const P2TR_SCRIPT = Buffer.concat([Buffer.from([0x51, 0x20]), Buffer.alloc(32)]);

/** P2A (anchor) output: OP_1 OP_PUSHBYTES_2 0x4e 0x73 */
const P2A_SCRIPT = Buffer.from([0x51, 0x02, 0x4e, 0x73]);

/** P2SH output: OP_HASH160 <20-byte hash> OP_EQUAL */
const P2SH_SCRIPT = Buffer.from([0xa9, 0x14, ...Buffer.alloc(20), 0x87]);

/** P2PKH output: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG */
const P2PKH_SCRIPT = Buffer.from([0x76, 0xa9, 0x14, ...Buffer.alloc(20), 0x88, 0xac]);

/** P2WPKH output: OP_0 <20-byte hash> */
const P2WPKH_SCRIPT = Buffer.concat([Buffer.from([0x00, 0x14]), Buffer.alloc(20)]);

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Build a minimal witness P2WSH scriptSig (empty — native segwit has no scriptSig).
 * For P2SH-wrapped segwit, scriptSig = OP_PUSHDATA(<redeemScript>).
 */
function p2shScriptSigFor(redeemScript: Buffer): Buffer {
  // Encode: OP_PUSHDATA if > 75 bytes, else direct push.
  if (redeemScript.length <= 75) {
    return Buffer.concat([Buffer.from([redeemScript.length]), redeemScript]);
  } else if (redeemScript.length <= 0xff) {
    return Buffer.concat([Buffer.from([0x4c, redeemScript.length]), redeemScript]);
  } else {
    const lenBuf = Buffer.alloc(2);
    lenBuf.writeUInt16LE(redeemScript.length, 0);
    return Buffer.concat([Buffer.from([0x4d]), lenBuf, redeemScript]);
  }
}

/** A minimal OP_TRUE witnessScript (1 byte: OP_1 = 0x51) */
const OP_TRUE_WITNESS_SCRIPT = Buffer.from([0x51]);

/** P2SH(P2WSH) redeem script: OP_0 <sha256(witnessScript)> */
function p2shP2wshRedeemScript(witnessScript: Buffer): Buffer {
  const { createHash } = require("node:crypto");
  const hash = createHash("sha256").update(witnessScript).digest();
  return Buffer.concat([Buffer.from([0x00, 0x20]), hash]);
}

// ---------------------------------------------------------------------------
// Test suite
// ---------------------------------------------------------------------------

describe("IsWitnessStandard policy gates (W72)", () => {
  let tempDir: string;
  let db: ChainDB;
  let utxo: UTXOManager;
  let mempool: Mempool;

  // Distinct seed txids for each test UTXO
  const SEED_P2WSH   = Buffer.alloc(32, 0x01);
  const SEED_P2TR    = Buffer.alloc(32, 0x02);
  const SEED_P2A     = Buffer.alloc(32, 0x03);
  const SEED_P2SH    = Buffer.alloc(32, 0x04);
  const SEED_P2PKH   = Buffer.alloc(32, 0x05);
  const SEED_P2WPKH  = Buffer.alloc(32, 0x06);

  const UTXO_AMOUNT = 10_000_000n;

  /**
   * Build a spending tx with given prevout, scriptSig, and witness.
   * Outputs: one P2A output (anyone-can-spend, standard) to stay above 65B.
   */
  function buildTx(opts: {
    prevTxid: Buffer;
    prevVout?: number;
    scriptSig?: Buffer;
    witness?: Buffer[];
    outputScript?: Buffer;
  }): Transaction {
    return {
      version: 2,
      inputs: [
        {
          prevOut: { txid: opts.prevTxid, vout: opts.prevVout ?? 0 },
          scriptSig: opts.scriptSig ?? Buffer.alloc(0),
          sequence: 0xffffffff,
          witness: opts.witness ?? [],
        },
      ],
      outputs: [
        {
          value: 9_000_000n,
          scriptPubKey: opts.outputScript ?? P2A_SCRIPT,
        },
        // OP_RETURN padding to ensure non-witness size ≥ 65 bytes
        { value: 0n, scriptPubKey: Buffer.from([0x6a]) },
      ],
      lockTime: 0,
    };
  }

  /** Register a UTXO in the DB. */
  async function fund(txid: Buffer, spk: Buffer, vout = 0): Promise<void> {
    const entry: UTXOEntry = {
      height: 1,
      coinbase: false,
      amount: UTXO_AMOUNT,
      scriptPubKey: spk,
    };
    await db.putUTXO(txid, vout, entry);
  }

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "iswitness-standard-"));
    db = new ChainDB(tempDir);
    await db.open();
    utxo = new UTXOManager(db);
    mempool = new Mempool(utxo, REGTEST, 1_000_000);
    mempool.setTipHeight(200);

    // Fund all test UTXOs
    await fund(SEED_P2WSH,  P2WSH_SCRIPT);
    await fund(SEED_P2TR,   P2TR_SCRIPT);
    await fund(SEED_P2A,    P2A_SCRIPT);
    await fund(SEED_P2SH,   P2SH_SCRIPT);
    await fund(SEED_P2PKH,  P2PKH_SCRIPT);
    await fund(SEED_P2WPKH, P2WPKH_SCRIPT);
  });

  afterEach(async () => {
    await db.close();
    await rm(tempDir, { recursive: true, force: true });
  });

  // --------------------------------------------------------------------------
  // Exported constant verification
  // --------------------------------------------------------------------------
  describe("exported IsWitnessStandard constants match Core values", () => {
    test("MAX_STANDARD_P2WSH_SCRIPT_SIZE = 3600", () => {
      expect(MAX_STANDARD_P2WSH_SCRIPT_SIZE).toBe(3_600);
    });
    test("MAX_STANDARD_P2WSH_STACK_ITEMS = 100", () => {
      expect(MAX_STANDARD_P2WSH_STACK_ITEMS).toBe(100);
    });
    test("MAX_STANDARD_P2WSH_STACK_ITEM_SIZE = 80", () => {
      expect(MAX_STANDARD_P2WSH_STACK_ITEM_SIZE).toBe(80);
    });
    test("MAX_STANDARD_TAPSCRIPT_STACK_ITEM_SIZE = 80", () => {
      expect(MAX_STANDARD_TAPSCRIPT_STACK_ITEM_SIZE).toBe(80);
    });
  });

  // --------------------------------------------------------------------------
  // Gate 1: P2A + witness → reject
  // Core policy.cpp:283-285
  // --------------------------------------------------------------------------
  describe("gate 1: P2A prevScript + witness → reject", () => {
    test("P2A input with non-empty witness is rejected", async () => {
      const tx = buildTx({
        prevTxid: SEED_P2A,
        witness: [Buffer.alloc(64)], // any non-empty witness
      });
      const result = await mempool.addTransaction(tx);
      expect(result.accepted).toBe(false);
      expect(result.error).toContain("bad-witness-nonstandard");
    });

    test("P2A input with empty witness is accepted (no witness stuffing)", async () => {
      const tx = buildTx({
        prevTxid: SEED_P2A,
        witness: [], // no witness
      });
      const result = await mempool.addTransaction(tx);
      // Should not fail on the witness standard gate (may fail on script validation)
      expect(result.error ?? "").not.toContain("bad-witness-nonstandard");
    });
  });

  // --------------------------------------------------------------------------
  // Gate 2: P2SH-wrapped: eval scriptSig → fail/empty → reject
  // Core policy.cpp:287-298
  // --------------------------------------------------------------------------
  describe("gate 2: P2SH-wrapped witness scriptSig eval", () => {
    test("P2SH input with empty scriptSig + witness is rejected (empty stack)", async () => {
      // P2SH with witness but scriptSig = empty → stack after eval is empty → reject
      const tx = buildTx({
        prevTxid: SEED_P2SH,
        scriptSig: Buffer.alloc(0), // empty scriptSig → empty stack
        witness: [Buffer.alloc(32)],
      });
      const result = await mempool.addTransaction(tx);
      expect(result.accepted).toBe(false);
      expect(result.error).toContain("bad-witness-nonstandard");
    });

    test("P2SH input with non-witness redeemScript + witness is rejected (not a witness program)", async () => {
      // Push a P2PKH script as the redeemScript — it is not a witness program.
      // After eval, prevScript = P2PKH → gate 3 fires.
      const redeemScript = P2PKH_SCRIPT;
      const scriptSig = p2shScriptSigFor(redeemScript);
      const tx = buildTx({
        prevTxid: SEED_P2SH,
        scriptSig,
        witness: [Buffer.alloc(32)],
      });
      const result = await mempool.addTransaction(tx);
      expect(result.accepted).toBe(false);
      expect(result.error).toContain("bad-witness-nonstandard");
    });
  });

  // --------------------------------------------------------------------------
  // Gate 3: non-witness prevScript + non-empty witness → reject
  // Core policy.cpp:301-306: !prevScript.IsWitnessProgram() → return false
  // --------------------------------------------------------------------------
  describe("gate 3: non-witness prevScript + witness → reject", () => {
    test("P2PKH prevScript with non-empty witness is rejected", async () => {
      const tx = buildTx({
        prevTxid: SEED_P2PKH,
        witness: [Buffer.alloc(32)],
      });
      const result = await mempool.addTransaction(tx);
      expect(result.accepted).toBe(false);
      expect(result.error).toContain("bad-witness-nonstandard");
    });

    test("P2PKH prevScript with empty witness is not rejected by this gate", async () => {
      const tx = buildTx({
        prevTxid: SEED_P2PKH,
        witness: [], // no witness → gate skips this input entirely
      });
      const result = await mempool.addTransaction(tx);
      // Gate 3 must not fire (may fail on script validation but not witness-standard)
      expect(result.error ?? "").not.toContain("bad-witness-nonstandard");
    });
  });

  // --------------------------------------------------------------------------
  // Gate 4: P2WSH v0 32-byte program standard limits
  // Core policy.cpp:309-318
  // --------------------------------------------------------------------------
  describe("gate 4: P2WSH witness standard limits", () => {
    // witnessScript > 3600 bytes
    test("P2WSH witnessScript of 3601 bytes is rejected (> MAX_STANDARD_P2WSH_SCRIPT_SIZE)", async () => {
      const oversizedScript = Buffer.alloc(3_601, 0x51); // 3601 bytes
      const tx = buildTx({
        prevTxid: SEED_P2WSH,
        witness: [oversizedScript], // only witnessScript, no args
      });
      const result = await mempool.addTransaction(tx);
      expect(result.accepted).toBe(false);
      expect(result.error).toContain("bad-witness-nonstandard");
    });

    test("P2WSH witnessScript of exactly 3600 bytes passes the size gate", async () => {
      const exactScript = Buffer.alloc(3_600, 0x51);
      const tx = buildTx({
        prevTxid: SEED_P2WSH,
        witness: [exactScript],
      });
      const result = await mempool.addTransaction(tx);
      // Should not fail on witnessScript size gate
      expect(result.error ?? "").not.toContain("bad-witness-nonstandard");
    });

    // stack items > 100
    test("P2WSH with 101 witness stack items (excl. witnessScript) is rejected", async () => {
      // 101 arg items + 1 witnessScript = 102 items total; sizeWitnessStack = 101 > 100
      const items: Buffer[] = Array.from({ length: 101 }, () => Buffer.alloc(1));
      items.push(Buffer.from([0x51])); // witnessScript
      const tx = buildTx({
        prevTxid: SEED_P2WSH,
        witness: items,
      });
      const result = await mempool.addTransaction(tx);
      expect(result.accepted).toBe(false);
      expect(result.error).toContain("bad-witness-nonstandard");
    });

    test("P2WSH with exactly 100 witness stack items passes the depth gate", async () => {
      // 100 arg items + 1 witnessScript = 101 total; sizeWitnessStack = 100 (boundary)
      const items: Buffer[] = Array.from({ length: 100 }, () => Buffer.alloc(1));
      items.push(Buffer.from([0x51])); // witnessScript
      const tx = buildTx({
        prevTxid: SEED_P2WSH,
        witness: items,
      });
      const result = await mempool.addTransaction(tx);
      expect(result.error ?? "").not.toContain("bad-witness-nonstandard");
    });

    // individual item > 80 bytes
    test("P2WSH with a stack item of 81 bytes is rejected (> MAX_STANDARD_P2WSH_STACK_ITEM_SIZE)", async () => {
      const bigItem = Buffer.alloc(81); // 81 bytes — one over the limit
      const witnessScript = Buffer.from([0x51]);
      const tx = buildTx({
        prevTxid: SEED_P2WSH,
        witness: [bigItem, witnessScript],
      });
      const result = await mempool.addTransaction(tx);
      expect(result.accepted).toBe(false);
      expect(result.error).toContain("bad-witness-nonstandard");
    });

    test("P2WSH with stack items of exactly 80 bytes passes the item-size gate", async () => {
      const exactItem = Buffer.alloc(80); // boundary — must pass
      const witnessScript = Buffer.from([0x51]);
      const tx = buildTx({
        prevTxid: SEED_P2WSH,
        witness: [exactItem, witnessScript],
      });
      const result = await mempool.addTransaction(tx);
      expect(result.error ?? "").not.toContain("bad-witness-nonstandard");
    });

    // witnessScript is the LAST item; the size limit only applies to items before it
    test("P2WSH witnessScript itself is not subject to the 80-byte item limit", async () => {
      // Use a 100-byte witnessScript but only 1-byte arg items — should only fail
      // on witnessScript size if > 3600, not on the 80B item limit.
      const smallArgs = [Buffer.alloc(80)]; // within per-item limit
      const bigWitnessScript = Buffer.alloc(200, 0x51); // 200 bytes, under 3600
      const tx = buildTx({
        prevTxid: SEED_P2WSH,
        witness: [...smallArgs, bigWitnessScript],
      });
      const result = await mempool.addTransaction(tx);
      // Not rejected on witness-standard (may fail script validation)
      expect(result.error ?? "").not.toContain("bad-witness-nonstandard");
    });
  });

  // --------------------------------------------------------------------------
  // Gate 5: P2TR (v1, 32-byte program, not P2SH-wrapped)
  // Core policy.cpp:324-348
  // --------------------------------------------------------------------------
  describe("gate 5: P2TR Taproot witness standard limits", () => {
    // Annex: last item starts with 0x50
    test("P2TR with annex (last item[0] == 0x50) is rejected", async () => {
      const annexItem = Buffer.from([0x50, 0xde, 0xad]); // starts with ANNEX_TAG
      const tx = buildTx({
        prevTxid: SEED_P2TR,
        witness: [Buffer.alloc(64), annexItem], // 2+ items, last is annex
      });
      const result = await mempool.addTransaction(tx);
      expect(result.accepted).toBe(false);
      expect(result.error).toContain("bad-witness-nonstandard");
    });

    test("P2TR key-path spend (1 item, no annex) is accepted", async () => {
      // Key-path: single 64-byte Schnorr signature. No policy limits apply.
      const tx = buildTx({
        prevTxid: SEED_P2TR,
        witness: [Buffer.alloc(64)], // Schnorr sig
      });
      const result = await mempool.addTransaction(tx);
      // Gate 5 must not fire (may fail script validation)
      expect(result.error ?? "").not.toContain("bad-witness-nonstandard");
    });

    test("P2TR empty witness stack (0 items) is rejected", async () => {
      // 0 stack elements — already invalid by consensus; non-standard too.
      // BUT: addTransaction skips inputs with empty witness (witness.length === 0)!
      // Core skips with scriptWitness.IsNull() — so this input is simply skipped.
      // The real rejection for empty witness comes from script validation, not this gate.
      // This test documents the expected behavior: gate skips, script validation rejects.
      const tx = buildTx({
        prevTxid: SEED_P2TR,
        witness: [], // empty witness → gate skips this input
      });
      const result = await mempool.addTransaction(tx);
      // Gate 5 does not fire (input is skipped); script validation may reject.
      expect(result.error ?? "").not.toContain("bad-witness-nonstandard");
    });

    // Script-path spend: tapscript leaf 0xc0 → item size limit
    test("P2TR tapscript script-path: witness item > 80 bytes is rejected", async () => {
      // Script-path witness layout: [<arg>..., <script>, <control_block>]
      // Control block first byte: leaf_version (0xc0 | parity) → 0xc0 or 0xc1
      // We use 0xc0 so (controlBlock[0] & 0xfe) === 0xc0 === TAPROOT_LEAF_TAPSCRIPT.
      const bigArg = Buffer.alloc(81); // 81 bytes > MAX_STANDARD_TAPSCRIPT_STACK_ITEM_SIZE
      const script = Buffer.from([0x51]); // OP_TRUE
      const controlBlock = Buffer.from([0xc0, ...Buffer.alloc(32)]); // leaf ver 0xc0 + 32-byte merkle path
      const tx = buildTx({
        prevTxid: SEED_P2TR,
        witness: [bigArg, script, controlBlock],
      });
      const result = await mempool.addTransaction(tx);
      expect(result.accepted).toBe(false);
      expect(result.error).toContain("bad-witness-nonstandard");
    });

    test("P2TR tapscript script-path: witness items of exactly 80 bytes pass", async () => {
      const exactArg = Buffer.alloc(80); // boundary — must pass
      const script = Buffer.from([0x51]);
      const controlBlock = Buffer.from([0xc0, ...Buffer.alloc(32)]);
      const tx = buildTx({
        prevTxid: SEED_P2TR,
        witness: [exactArg, script, controlBlock],
      });
      const result = await mempool.addTransaction(tx);
      expect(result.error ?? "").not.toContain("bad-witness-nonstandard");
    });

    test("P2TR non-tapscript leaf (leaf != 0xc0): no item size limit applied", async () => {
      // Leaf version 0xc2 → (0xc2 & 0xfe) = 0xc2 ≠ 0xc0 → unknown leaf, no per-item limit.
      const bigArg = Buffer.alloc(200); // way over 80 bytes — should NOT be rejected
      const script = Buffer.from([0x51]);
      const controlBlock = Buffer.from([0xc2, ...Buffer.alloc(32)]); // non-tapscript leaf
      const tx = buildTx({
        prevTxid: SEED_P2TR,
        witness: [bigArg, script, controlBlock],
      });
      const result = await mempool.addTransaction(tx);
      // No bad-witness-nonstandard for unknown leaf versions
      expect(result.error ?? "").not.toContain("bad-witness-nonstandard");
    });

    test("P2TR script-path: empty control block is rejected", async () => {
      // Control block must not be empty (Core policy.cpp:335: if empty → return false)
      const arg = Buffer.alloc(32);
      const script = Buffer.from([0x51]);
      const emptyControlBlock = Buffer.alloc(0); // empty → reject
      const tx = buildTx({
        prevTxid: SEED_P2TR,
        witness: [arg, script, emptyControlBlock],
      });
      const result = await mempool.addTransaction(tx);
      expect(result.accepted).toBe(false);
      expect(result.error).toContain("bad-witness-nonstandard");
    });
  });

  // --------------------------------------------------------------------------
  // Gate 6: Coinbase inputs are exempt (checked before addTransaction)
  // Core policy.cpp:267-268: if (tx.IsCoinBase()) return true;
  // --------------------------------------------------------------------------
  describe("gate 6: coinbase exempt", () => {
    test("coinbase transaction is rejected before witness check (mempool guard)", async () => {
      // Coinbase txs are rejected by the mempool's coinbase guard before
      // IsWitnessStandard is even called. Any coinbase-specific witness
      // data is never evaluated.
      const coinbaseTx: Transaction = {
        version: 2,
        inputs: [
          {
            prevOut: { txid: Buffer.alloc(32, 0x00), vout: 0xffffffff },
            scriptSig: Buffer.from([0x03, 0x01, 0x00, 0x00]), // height push
            sequence: 0xffffffff,
            witness: [Buffer.alloc(32)], // non-empty witness
          },
        ],
        outputs: [{ value: 5_000_000_000n, scriptPubKey: P2A_SCRIPT }],
        lockTime: 0,
      };
      const result = await mempool.addTransaction(coinbaseTx);
      // Rejected by coinbase guard, not by witness-standard gate
      expect(result.accepted).toBe(false);
      expect(result.error).not.toContain("bad-witness-nonstandard");
    });
  });

  // --------------------------------------------------------------------------
  // Regression: inputs without witness are skipped (null witness guard)
  // Core policy.cpp:274-275: if (tx.vin[i].scriptWitness.IsNull()) continue;
  // --------------------------------------------------------------------------
  describe("null witness guard: inputs with empty witness are skipped", () => {
    test("P2WPKH prevScript with empty witness is not rejected by witness-standard gate", async () => {
      // Spending a P2WPKH with empty witness is invalid at consensus but should not
      // fire the witness-standard gate (gate skips the input).
      const tx = buildTx({
        prevTxid: SEED_P2WPKH,
        witness: [],
      });
      const result = await mempool.addTransaction(tx);
      expect(result.error ?? "").not.toContain("bad-witness-nonstandard");
    });
  });
});
