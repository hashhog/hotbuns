/**
 * Tests for ephemeral anchor policy.
 *
 * Ephemeral anchors allow zero-value dust outputs that MUST be spent by
 * a child transaction in the same package. This enables efficient fee bumping
 * for protocols like Lightning.
 *
 * Key rules:
 * - A tx with dust outputs must have 0 fee
 * - All dust outputs must be spent by a child in the same package
 * - If the child is evicted, the parent must also be evicted
 *
 * Reference: Bitcoin Core policy/ephemeral_policy.cpp
 */

import { describe, test, expect, beforeEach, afterEach } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ChainDB, UTXOEntry } from "../storage/database.js";
import { UTXOManager } from "../chain/utxo.js";
import { REGTEST } from "../consensus/params.js";
import {
  Mempool,
  PackageValidationResult,
  getDustThreshold,
  isDust,
  isEphemeralDust,
  getDustOutputs,
  getEphemeralDustOutputs,
  hasEphemeralDust,
  preCheckEphemeralTx,
  checkEphemeralSpends,
} from "../mempool/mempool.js";
import type { Transaction } from "../validation/tx.js";
import { getTxId, getWTxId } from "../validation/tx.js";
import { P2A_SCRIPT, isP2A } from "../script/interpreter.js";

describe("Ephemeral Anchor Policy", () => {
  let tempDir: string;
  let db: ChainDB;
  let utxo: UTXOManager;
  let mempool: Mempool;

  // Helper to create a test transaction
  function createTestTx(
    inputs: Array<{ txid: Buffer; vout: number; sequence?: number }>,
    outputs: Array<{ value: bigint; scriptPubKey?: Buffer }>
  ): Transaction {
    return {
      version: 2,
      inputs: inputs.map((inp) => ({
        prevOut: { txid: inp.txid, vout: inp.vout },
        scriptSig: Buffer.alloc(0),
        sequence: inp.sequence ?? 0xffffffff,
        witness: [],
      })),
      outputs: outputs.map((out) => ({
        value: out.value,
        scriptPubKey: out.scriptPubKey ?? Buffer.from([0x51]), // OP_TRUE
      })),
      lockTime: 0,
    };
  }

  // Helper to set up a UTXO
  async function setupUTXO(
    txid: Buffer,
    vout: number,
    amount: bigint,
    height: number = 1,
    coinbase: boolean = false
  ): Promise<void> {
    const entry: UTXOEntry = {
      height,
      coinbase,
      amount,
      scriptPubKey: Buffer.from([0x51]), // OP_TRUE
    };
    await db.putUTXO(txid, vout, entry);
  }

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "ephemeral-test-"));
    db = new ChainDB(tempDir);
    await db.open();
    utxo = new UTXOManager(db);
    mempool = new Mempool(utxo, REGTEST, 1_000_000);
    mempool.setTipHeight(200);
  });

  afterEach(async () => {
    await db.close();
    await rm(tempDir, { recursive: true, force: true });
  });

  describe("Dust threshold helpers", () => {
    test("getDustThreshold returns correct value for P2PKH", () => {
      // P2PKH scriptPubKey: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
      const p2pkh = Buffer.from([
        0x76, 0xa9, 0x14, ...Buffer.alloc(20, 0x42), 0x88, 0xac
      ]);
      const threshold = getDustThreshold(p2pkh);
      // Non-segwit: approximately 546 sats at 3000 sat/kvB
      expect(threshold).toBeGreaterThan(500n);
      expect(threshold).toBeLessThan(600n);
    });

    test("getDustThreshold returns correct value for P2WPKH", () => {
      // P2WPKH scriptPubKey: OP_0 <20 bytes>
      const p2wpkh = Buffer.concat([
        Buffer.from([0x00, 0x14]),
        Buffer.alloc(20, 0x42),
      ]);
      const threshold = getDustThreshold(p2wpkh);
      // Segwit: approximately 294 sats at 3000 sat/kvB
      expect(threshold).toBeGreaterThan(250n);
      expect(threshold).toBeLessThan(350n);
    });

    test("getDustThreshold returns 0 for OP_RETURN", () => {
      // OP_RETURN is unspendable
      const opReturn = Buffer.from([0x6a, 0x04, 0xde, 0xad, 0xbe, 0xef]);
      expect(getDustThreshold(opReturn)).toBe(0n);
    });

    test("isDust correctly identifies dust outputs", () => {
      const p2wpkh = Buffer.concat([
        Buffer.from([0x00, 0x14]),
        Buffer.alloc(20, 0x42),
      ]);

      expect(isDust(100n, p2wpkh)).toBe(true);
      expect(isDust(1000n, p2wpkh)).toBe(false);
      expect(isDust(0n, p2wpkh)).toBe(true);
    });

    test("isEphemeralDust only returns true for 0-value outputs", () => {
      const p2wpkh = Buffer.concat([
        Buffer.from([0x00, 0x14]),
        Buffer.alloc(20, 0x42),
      ]);

      expect(isEphemeralDust(0n, p2wpkh)).toBe(true);
      expect(isEphemeralDust(100n, p2wpkh)).toBe(false); // dust but not ephemeral
      expect(isEphemeralDust(1000n, p2wpkh)).toBe(false);
    });
  });

  describe("Ephemeral dust detection", () => {
    test("getDustOutputs finds dust outputs in transaction", () => {
      const tx = createTestTx(
        [{ txid: Buffer.alloc(32, 0x01), vout: 0 }],
        [
          { value: 100n }, // dust (OP_TRUE is non-witness, ~546 threshold)
          { value: 100000n }, // not dust
        ]
      );

      const dustOutputs = getDustOutputs(tx);
      expect(dustOutputs).toContain(0);
      expect(dustOutputs).not.toContain(1);
    });

    test("getEphemeralDustOutputs finds 0-value dust outputs", () => {
      const tx = createTestTx(
        [{ txid: Buffer.alloc(32, 0x01), vout: 0 }],
        [
          { value: 0n }, // ephemeral dust
          { value: 100n }, // regular dust (not ephemeral)
          { value: 100000n }, // not dust
        ]
      );

      const ephemeralOutputs = getEphemeralDustOutputs(tx);
      expect(ephemeralOutputs).toContain(0);
      expect(ephemeralOutputs).not.toContain(1);
      expect(ephemeralOutputs).not.toContain(2);
    });

    test("hasEphemeralDust returns true only when 0-value dust exists", () => {
      const txWithEphemeral = createTestTx(
        [{ txid: Buffer.alloc(32, 0x01), vout: 0 }],
        [
          { value: 0n }, // ephemeral dust
          { value: 100000n }, // not dust
        ]
      );

      const txWithoutEphemeral = createTestTx(
        [{ txid: Buffer.alloc(32, 0x01), vout: 0 }],
        [
          { value: 100n }, // regular dust, not ephemeral
          { value: 100000n }, // not dust
        ]
      );

      expect(hasEphemeralDust(txWithEphemeral)).toBe(true);
      expect(hasEphemeralDust(txWithoutEphemeral)).toBe(false);
    });

    test("P2A output with 0 value is ephemeral dust", () => {
      const txWithP2A = createTestTx(
        [{ txid: Buffer.alloc(32, 0x01), vout: 0 }],
        [
          { value: 0n, scriptPubKey: P2A_SCRIPT }, // P2A anchor
          { value: 100000n },
        ]
      );

      expect(hasEphemeralDust(txWithP2A)).toBe(true);
      expect(getEphemeralDustOutputs(txWithP2A)).toContain(0);
    });
  });

  describe("preCheckEphemeralTx", () => {
    test("accepts tx without dust", () => {
      const tx = createTestTx(
        [{ txid: Buffer.alloc(32, 0x01), vout: 0 }],
        [{ value: 100000n }] // not dust
      );

      const result = preCheckEphemeralTx(tx, 1000n);
      expect(result.valid).toBe(true);
    });

    test("accepts tx with dust and 0 fee", () => {
      const tx = createTestTx(
        [{ txid: Buffer.alloc(32, 0x01), vout: 0 }],
        [{ value: 0n }] // dust
      );

      const result = preCheckEphemeralTx(tx, 0n);
      expect(result.valid).toBe(true);
    });

    test("rejects tx with dust and non-zero fee", () => {
      const tx = createTestTx(
        [{ txid: Buffer.alloc(32, 0x01), vout: 0 }],
        [
          { value: 0n }, // dust
          { value: 100000n },
        ]
      );

      const result = preCheckEphemeralTx(tx, 1000n);
      expect(result.valid).toBe(false);
      expect(result.error).toContain("0-fee");
    });
  });

  describe("checkEphemeralSpends", () => {
    test("accepts package where child spends all parent dust", () => {
      // Parent with ephemeral dust output
      const parent = createTestTx(
        [{ txid: Buffer.alloc(32, 0xff), vout: 0 }],
        [
          { value: 0n }, // ephemeral dust
          { value: 100000n },
        ]
      );
      const parentTxid = getTxId(parent);

      // Child spends the ephemeral dust
      const child = createTestTx(
        [
          { txid: parentTxid, vout: 0 }, // spends ephemeral dust
          { txid: parentTxid, vout: 1 }, // spends regular output
        ],
        [{ value: 99000n }]
      );

      const result = checkEphemeralSpends([parent, child], new Map());
      expect(result.valid).toBe(true);
    });

    test("rejects package where child does not spend parent dust", () => {
      // Parent with ephemeral dust output
      const parent = createTestTx(
        [{ txid: Buffer.alloc(32, 0xff), vout: 0 }],
        [
          { value: 0n }, // ephemeral dust at index 0
          { value: 100000n }, // regular output at index 1
        ]
      );
      const parentTxid = getTxId(parent);

      // Child only spends the regular output, NOT the ephemeral dust
      const child = createTestTx(
        [{ txid: parentTxid, vout: 1 }], // only spends regular output
        [{ value: 99000n }]
      );

      const result = checkEphemeralSpends([parent, child], new Map());
      expect(result.valid).toBe(false);
      expect(result.error).toContain("did not spend parent's ephemeral dust");
    });

    test("rejects when child partially spends dust (multiple dust outputs)", () => {
      // Parent with multiple ephemeral dust outputs
      const parent = createTestTx(
        [{ txid: Buffer.alloc(32, 0xff), vout: 0 }],
        [
          { value: 0n }, // ephemeral dust at index 0
          { value: 0n }, // ephemeral dust at index 1
          { value: 100000n }, // regular output at index 2
        ]
      );
      const parentTxid = getTxId(parent);

      // Child only spends one of the dust outputs
      const child = createTestTx(
        [
          { txid: parentTxid, vout: 0 }, // spends first dust
          { txid: parentTxid, vout: 2 }, // spends regular output
          // MISSING: vout 1 (second dust)
        ],
        [{ value: 99000n }]
      );

      const result = checkEphemeralSpends([parent, child], new Map());
      expect(result.valid).toBe(false);
    });

    test("accepts when no parent has ephemeral dust", () => {
      // Parent without ephemeral dust
      const parent = createTestTx(
        [{ txid: Buffer.alloc(32, 0xff), vout: 0 }],
        [{ value: 100000n }] // regular output
      );
      const parentTxid = getTxId(parent);

      const child = createTestTx(
        [{ txid: parentTxid, vout: 0 }],
        [{ value: 99000n }]
      );

      const result = checkEphemeralSpends([parent, child], new Map());
      expect(result.valid).toBe(true);
    });
  });

  describe("submitPackage with ephemeral anchors", () => {
    test("rejects parent with ephemeral dust alone", async () => {
      const inputTxid = Buffer.alloc(32, 0xaa);
      await setupUTXO(inputTxid, 0, 100000n);

      // Parent with ephemeral dust, no child
      const parent = createTestTx(
        [{ txid: inputTxid, vout: 0 }],
        [
          { value: 0n, scriptPubKey: P2A_SCRIPT }, // P2A anchor (0-value)
          { value: 100000n }, // regular output (pays all input, 0 fee)
        ]
      );

      const result = await mempool.submitPackage([parent]);
      expect(result.result).toBe(PackageValidationResult.PCKG_POLICY);
      expect(result.message).toContain("ephemeral");
    });

    test("accepts parent with ephemeral dust when child spends it", async () => {
      const inputTxid = Buffer.alloc(32, 0xaa);
      await setupUTXO(inputTxid, 0, 100000n);

      // Parent with ephemeral dust (0-fee since outputs = input)
      const parent = createTestTx(
        [{ txid: inputTxid, vout: 0 }],
        [
          { value: 0n, scriptPubKey: P2A_SCRIPT }, // P2A anchor
          { value: 100000n }, // regular output
        ]
      );
      const parentTxid = getTxId(parent);

      // Child spends the ephemeral dust and provides fees
      const child = createTestTx(
        [
          { txid: parentTxid, vout: 0 }, // spends P2A anchor
          { txid: parentTxid, vout: 1 }, // spends regular output
        ],
        [{ value: 99000n }] // fee = 100000 - 99000 = 1000
      );

      const result = await mempool.submitPackage([parent, child]);
      expect(result.result).toBe(PackageValidationResult.PCKG_RESULT_UNSET);
      expect(result.message).toBe("success");

      // Both should be in mempool
      expect(mempool.hasTransaction(parentTxid)).toBe(true);
      expect(mempool.hasTransaction(getTxId(child))).toBe(true);
    });

    test("child eviction cascades to ephemeral parent", async () => {
      const inputTxid = Buffer.alloc(32, 0xaa);
      await setupUTXO(inputTxid, 0, 100000n);

      // Parent with ephemeral dust
      const parent = createTestTx(
        [{ txid: inputTxid, vout: 0 }],
        [
          { value: 0n, scriptPubKey: P2A_SCRIPT }, // P2A anchor
          { value: 100000n }, // regular output
        ]
      );
      const parentTxid = getTxId(parent);

      // Child spends the ephemeral dust
      const child = createTestTx(
        [
          { txid: parentTxid, vout: 0 }, // spends P2A anchor
          { txid: parentTxid, vout: 1 },
        ],
        [{ value: 99000n }]
      );
      const childTxid = getTxId(child);

      // Submit package successfully
      const result = await mempool.submitPackage([parent, child]);
      expect(result.result).toBe(PackageValidationResult.PCKG_RESULT_UNSET);
      expect(mempool.hasTransaction(parentTxid)).toBe(true);
      expect(mempool.hasTransaction(childTxid)).toBe(true);

      // Remove the child
      mempool.removeTransaction(childTxid, true);

      // Parent should also be removed due to ephemeral cascade
      expect(mempool.hasTransaction(childTxid)).toBe(false);
      expect(mempool.hasTransaction(parentTxid)).toBe(false);
    });

    test("rejects package when child doesn't spend all ephemeral dust", async () => {
      const inputTxid = Buffer.alloc(32, 0xaa);
      await setupUTXO(inputTxid, 0, 100000n);

      // Parent with ephemeral dust
      const parent = createTestTx(
        [{ txid: inputTxid, vout: 0 }],
        [
          { value: 0n, scriptPubKey: P2A_SCRIPT }, // P2A anchor at index 0
          { value: 100000n }, // regular output at index 1
        ]
      );
      const parentTxid = getTxId(parent);

      // Child only spends regular output, NOT the anchor
      const child = createTestTx(
        [{ txid: parentTxid, vout: 1 }], // only spends index 1
        [{ value: 99000n }]
      );

      const result = await mempool.submitPackage([parent, child]);
      expect(result.result).toBe(PackageValidationResult.PCKG_POLICY);
      expect(result.message).toContain("ephemeral");
    });

    test("rejects tx with dust and non-zero fee", async () => {
      const inputTxid = Buffer.alloc(32, 0xaa);
      await setupUTXO(inputTxid, 0, 100000n);

      // Parent with dust output but also pays fee (input > outputs)
      const parent = createTestTx(
        [{ txid: inputTxid, vout: 0 }],
        [
          { value: 0n }, // dust
          { value: 99000n }, // regular output; fee = 100000 - 99000 = 1000
        ]
      );
      const parentTxid = getTxId(parent);

      // Child spends the dust
      const child = createTestTx(
        [
          { txid: parentTxid, vout: 0 },
          { txid: parentTxid, vout: 1 },
        ],
        [{ value: 98000n }]
      );

      const result = await mempool.submitPackage([parent, child]);
      expect(result.result).toBe(PackageValidationResult.PCKG_POLICY);
      expect(result.message).toContain("0-fee");
    });
  });

  describe("P2A-specific behavior", () => {
    test("P2A script is correctly identified", () => {
      expect(isP2A(P2A_SCRIPT)).toBe(true);
      expect(P2A_SCRIPT.length).toBe(4);
      expect(P2A_SCRIPT[0]).toBe(0x51); // OP_1
    });

    test("P2A with non-zero value is still standard but not ephemeral", () => {
      const txWithP2A = createTestTx(
        [{ txid: Buffer.alloc(32, 0x01), vout: 0 }],
        [
          { value: 1000n, scriptPubKey: P2A_SCRIPT }, // P2A with value
          { value: 100000n },
        ]
      );

      // Not ephemeral dust (has value)
      expect(hasEphemeralDust(txWithP2A)).toBe(false);

      // But still may be dust depending on threshold
      // P2A is witness v1, so threshold is lower
    });
  });
});
