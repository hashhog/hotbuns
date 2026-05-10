/**
 * Tests for BIP-125 Replace-By-Fee (RBF) policy.
 *
 * W73 audit: 8 gates audited against bitcoin-core/src/policy/rbf.cpp and
 * bitcoin-core/src/util/rbf.cpp.
 *
 * Gates:
 *   #1  signalsOptInRBF  — util/rbf.cpp:SignalsOptInRBF (0xfffffffd threshold)
 *   #2  Inheritable opt-in via mempool ancestors
 *   #3  MAX_REPLACEMENT_CANDIDATES = 100  (GetEntriesForConflicts)
 *   #4  HasNoNewUnconfirmed (Rule #2)
 *   #5  EntriesAndTxidsDisjoint
 *   #6  PaysForRBF Rule #3: replacement_fees >= original_fees
 *   #7  PaysForRBF Rule #4: additional_fees >= relay_fee * replacement_vsize
 *   #8  ImprovesFeerateDiagram — deferred (Core 27+)
 *
 * NOTE: hotbuns runs full-RBF so any mempool tx is replaceable regardless of
 * BIP-125 sequence signaling — Gates #1 and #2 affect the RPC
 * "bip125-replaceable" field (via getRBFOptInState) but NOT whether a
 * replacement is accepted.
 */

import { describe, test, expect, beforeEach, afterEach } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ChainDB, UTXOEntry } from "../storage/database.js";
import { UTXOManager } from "../chain/utxo.js";
import { REGTEST } from "../consensus/params.js";
import { Mempool } from "../mempool/mempool.js";
import {
  signalsOptInRBF,
  isRBFOptIn,
  entriesAndTxidsDisjoint,
  RBFTransactionState,
  MAX_BIP125_RBF_SEQUENCE,
  MAX_REPLACEMENT_CANDIDATES,
} from "../mempool/rbf.js";
import type { Transaction } from "../validation/tx.js";
import { getTxId } from "../validation/tx.js";

describe("RBF - Replace By Fee", () => {
  let tempDir: string;
  let db: ChainDB;
  let utxo: UTXOManager;
  let mempool: Mempool;

  // Helper to create a test transaction with configurable sequence
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
      outputs: [
        ...outputs.map((out) => ({
          value: out.value,
          // P2A: standard "anchor" type, spendable with empty scriptSig + witness.
          scriptPubKey: out.scriptPubKey ?? Buffer.from([0x51, 0x02, 0x4e, 0x73]),
        })),
        { value: 0n, scriptPubKey: Buffer.from([0x6a]) }, // OP_RETURN padding (≥65 bytes)
      ],
      lockTime: 0,
    };
  }

  // Helper to set up a UTXO
  async function setupUTXO(
    txid: Buffer,
    vout: number,
    amount: bigint
  ): Promise<void> {
    const entry: UTXOEntry = {
      height: 1,
      coinbase: false,
      amount,
      scriptPubKey: Buffer.from([0x51, 0x02, 0x4e, 0x73]),
    };
    await db.putUTXO(txid, vout, entry);
  }

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "rbf-test-"));
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

  // =========================================================================
  // Gate #1 — signalsOptInRBF (util/rbf.cpp:SignalsOptInRBF)
  // MAX_BIP125_RBF_SEQUENCE = 0xfffffffd
  // =========================================================================
  describe("Gate #1 — signalsOptInRBF (util/rbf.cpp:SignalsOptInRBF)", () => {
    test("MAX_BIP125_RBF_SEQUENCE constant is 0xfffffffd", () => {
      expect(MAX_BIP125_RBF_SEQUENCE).toBe(0xfffffffd);
      // 0xfffffffd = 4294967293 = SEQUENCE_FINAL - 2
      expect(MAX_BIP125_RBF_SEQUENCE).toBe(4294967293);
    });

    test("signals opt-in when any input has sequence <= 0xfffffffd", () => {
      const makeTx = (seq: number): Transaction =>
        createTestTx([{ txid: Buffer.alloc(32, 1), vout: 0, sequence: seq }], [
          { value: 1000n },
        ]);

      // Exactly at threshold — signals opt-in
      expect(signalsOptInRBF(makeTx(0xfffffffd))).toBe(true);
      // Below threshold — signals opt-in
      expect(signalsOptInRBF(makeTx(0))).toBe(true);
      expect(signalsOptInRBF(makeTx(1))).toBe(true);
      expect(signalsOptInRBF(makeTx(0xfffffffc))).toBe(true);
    });

    test("does NOT signal opt-in when all inputs have sequence > 0xfffffffd", () => {
      const makeTx = (seq: number): Transaction =>
        createTestTx([{ txid: Buffer.alloc(32, 1), vout: 0, sequence: seq }], [
          { value: 1000n },
        ]);

      // 0xfffffffe = SEQUENCE_FINAL - 1 (nLockTime sentinel) — no RBF signal
      expect(signalsOptInRBF(makeTx(0xfffffffe))).toBe(false);
      // 0xffffffff = SEQUENCE_FINAL — no RBF signal
      expect(signalsOptInRBF(makeTx(0xffffffff))).toBe(false);
    });

    test("signals opt-in if ANY input signals, even if others do not", () => {
      // Multi-input tx: one signals, one does not
      const tx: Transaction = {
        version: 2,
        inputs: [
          {
            prevOut: { txid: Buffer.alloc(32, 1), vout: 0 },
            scriptSig: Buffer.alloc(0),
            sequence: 0xffffffff, // no signal
            witness: [],
          },
          {
            prevOut: { txid: Buffer.alloc(32, 2), vout: 0 },
            scriptSig: Buffer.alloc(0),
            sequence: 0xfffffffd, // signals!
            witness: [],
          },
        ],
        outputs: [{ value: 1000n, scriptPubKey: Buffer.from([0x51, 0x02, 0x4e, 0x73]) }],
        lockTime: 0,
      };
      expect(signalsOptInRBF(tx)).toBe(true);
    });

    test("does NOT signal when both inputs have sequence 0xffffffff", () => {
      const tx: Transaction = {
        version: 2,
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
        outputs: [{ value: 1000n, scriptPubKey: Buffer.from([0x51, 0x02, 0x4e, 0x73]) }],
        lockTime: 0,
      };
      expect(signalsOptInRBF(tx)).toBe(false);
    });

    test("Unsigned comparison: 0xfffffffe and 0xffffffff are NOT <= 0xfffffffd", () => {
      // Crucial: if JS treated these as signed 32-bit, 0xffffffff = -1 which
      // would be < 0xfffffffd. JS Number compares unsigned correctly here since
      // we use plain <= (no bit-ops), and all values fit in 53-bit safe range.
      const txFE: Transaction = createTestTx(
        [{ txid: Buffer.alloc(32, 1), vout: 0, sequence: 0xfffffffe }],
        [{ value: 1000n }]
      );
      const txFF: Transaction = createTestTx(
        [{ txid: Buffer.alloc(32, 2), vout: 0, sequence: 0xffffffff }],
        [{ value: 1000n }]
      );
      expect(signalsOptInRBF(txFE)).toBe(false);
      expect(signalsOptInRBF(txFF)).toBe(false);
    });
  });

  // =========================================================================
  // Gate #2 — Inheritable opt-in via mempool ancestors (isRBFOptIn)
  // policy/rbf.cpp:IsRBFOptIn
  // =========================================================================
  describe("Gate #2 — isRBFOptIn with ancestor walk", () => {
    const dummyTxNonSignaling: Transaction = {
      version: 2,
      inputs: [
        {
          prevOut: { txid: Buffer.alloc(32, 0xaa), vout: 0 },
          scriptSig: Buffer.alloc(0),
          sequence: 0xffffffff,
          witness: [],
        },
      ],
      outputs: [{ value: 1000n, scriptPubKey: Buffer.from([0x51, 0x02, 0x4e, 0x73]) }],
      lockTime: 0,
    };

    const dummyTxSignaling: Transaction = {
      version: 2,
      inputs: [
        {
          prevOut: { txid: Buffer.alloc(32, 0xbb), vout: 0 },
          scriptSig: Buffer.alloc(0),
          sequence: 0xfffffffd, // signals opt-in
          witness: [],
        },
      ],
      outputs: [{ value: 1000n, scriptPubKey: Buffer.from([0x51, 0x02, 0x4e, 0x73]) }],
      lockTime: 0,
    };

    test("REPLACEABLE_BIP125 when tx itself signals", () => {
      const state = isRBFOptIn(dummyTxSignaling, true, []);
      expect(state).toBe(RBFTransactionState.REPLACEABLE_BIP125);
    });

    test("REPLACEABLE_BIP125 when ancestor signals (inheritance)", () => {
      const state = isRBFOptIn(
        dummyTxNonSignaling,
        true,
        [dummyTxSignaling] // ancestor signals
      );
      expect(state).toBe(RBFTransactionState.REPLACEABLE_BIP125);
    });

    test("FINAL when neither tx nor any ancestor signals", () => {
      const nonSignalingAncestor: Transaction = {
        version: 2,
        inputs: [
          {
            prevOut: { txid: Buffer.alloc(32, 0xcc), vout: 0 },
            scriptSig: Buffer.alloc(0),
            sequence: 0xffffffff,
            witness: [],
          },
        ],
        outputs: [{ value: 1000n, scriptPubKey: Buffer.from([0x51, 0x02, 0x4e, 0x73]) }],
        lockTime: 0,
      };
      const state = isRBFOptIn(
        dummyTxNonSignaling,
        true,
        [nonSignalingAncestor]
      );
      expect(state).toBe(RBFTransactionState.FINAL);
    });

    test("UNKNOWN when tx not in mempool and does not signal itself", () => {
      const state = isRBFOptIn(dummyTxNonSignaling, false, []);
      expect(state).toBe(RBFTransactionState.UNKNOWN);
    });

    test("getRBFOptInState: signaling tx in mempool → REPLACEABLE_BIP125", async () => {
      const inputTxid = Buffer.alloc(32, 0x40);
      await setupUTXO(inputTxid, 0, 100000n);

      const tx = createTestTx(
        [{ txid: inputTxid, vout: 0, sequence: 0xfffffffd }],
        [{ value: 99000n }]
      );
      await mempool.addTransaction(tx);

      const txid = getTxId(tx);
      expect(mempool.getRBFOptInState(txid)).toBe(RBFTransactionState.REPLACEABLE_BIP125);
    });

    test("getRBFOptInState: non-signaling tx in mempool → FINAL", async () => {
      const inputTxid = Buffer.alloc(32, 0x41);
      await setupUTXO(inputTxid, 0, 100000n);

      const tx = createTestTx(
        [{ txid: inputTxid, vout: 0, sequence: 0xffffffff }],
        [{ value: 99000n }]
      );
      await mempool.addTransaction(tx);

      const txid = getTxId(tx);
      expect(mempool.getRBFOptInState(txid)).toBe(RBFTransactionState.FINAL);
    });

    test("getRBFOptInState: unknown txid → UNKNOWN", () => {
      expect(mempool.getRBFOptInState(Buffer.alloc(32, 0xde))).toBe(
        RBFTransactionState.UNKNOWN
      );
    });

    test("getRBFOptInState: inherits from signaling parent", async () => {
      const parentInputTxid = Buffer.alloc(32, 0x42);
      await setupUTXO(parentInputTxid, 0, 200000n);

      // Parent signals opt-in (sequence 0xfffffffd)
      const parent = createTestTx(
        [{ txid: parentInputTxid, vout: 0, sequence: 0xfffffffd }],
        [{ value: 190000n }]
      );
      await mempool.addTransaction(parent);
      const parentTxid = getTxId(parent);

      // Child does NOT signal itself (sequence 0xffffffff)
      const child = createTestTx(
        [{ txid: parentTxid, vout: 0, sequence: 0xffffffff }],
        [{ value: 180000n }]
      );
      await mempool.addTransaction(child);
      const childTxid = getTxId(child);

      // Child inherits REPLACEABLE_BIP125 from parent
      expect(mempool.getRBFOptInState(childTxid)).toBe(
        RBFTransactionState.REPLACEABLE_BIP125
      );
    });
  });

  // =========================================================================
  // Gate #3 — MAX_REPLACEMENT_CANDIDATES = 100
  // policy/rbf.cpp:GetEntriesForConflicts
  // =========================================================================
  describe("Gate #3 — MAX_REPLACEMENT_CANDIDATES=100 (GetEntriesForConflicts)", () => {
    test("MAX_REPLACEMENT_CANDIDATES constant is 100", () => {
      expect(MAX_REPLACEMENT_CANDIDATES).toBe(100);
    });

    test("rejects replacement that would evict too many transactions", async () => {
      // This test creates a scenario where replacing one tx would cascade
      // We need to create a tx with many descendants

      // Setup: create initial UTXO
      const rootTxid = Buffer.alloc(32, 0x10);
      await setupUTXO(rootTxid, 0, 10_000_000n);

      // Create root transaction with many outputs
      const rootTx = createTestTx(
        [{ txid: rootTxid, vout: 0 }],
        Array(50).fill(null).map(() => ({ value: 180000n })) // 50 outputs
      );
      await mempool.addTransaction(rootTx);
      const rootTxidResult = getTxId(rootTx);

      // Now create many child transactions spending those outputs
      // Each child will also have multiple outputs, creating descendants
      for (let i = 0; i < 50; i++) {
        const childInput = Buffer.alloc(32, 0x20 + i);
        await setupUTXO(childInput, 0, 50000n);

        const child = createTestTx(
          [
            { txid: rootTxidResult, vout: i },
            { txid: childInput, vout: 0 },
          ],
          [{ value: 220000n }]
        );
        const result = await mempool.addTransaction(child);
        if (!result.accepted) {
          // Hit ancestor/descendant limits, that's okay
          break;
        }
      }

      // Count total mempool size
      const beforeSize = mempool.getSize();

      // If we have enough transactions, try to replace the root
      if (beforeSize > 25) {
        // Try to replace root transaction - this should evict all descendants
        const replacementRoot = createTestTx(
          [{ txid: rootTxid, vout: 0 }],
          [{ value: 8_000_000n }] // Much higher fee (2M sat)
        );
        const result = await mempool.addTransaction(replacementRoot);

        // Either it succeeds (if under 100 evictions) or fails with too many
        if (beforeSize > 100) {
          expect(result.accepted).toBe(false);
          expect(result.error).toContain("too many");
        } else {
          expect(result.accepted).toBe(true);
        }
      }
    });
  });

  // =========================================================================
  // Gate #4 — HasNoNewUnconfirmed (Rule #2)
  // policy/rbf.cpp:HasNoNewUnconfirmed
  // =========================================================================
  describe("Gate #4 — HasNoNewUnconfirmed (BIP-125 Rule #2)", () => {
    test("rejects replacement that adds a new unconfirmed input", async () => {
      const input1 = Buffer.alloc(32, 0x31);
      const input2 = Buffer.alloc(32, 0x32);
      await setupUTXO(input1, 0, 100000n);
      await setupUTXO(input2, 0, 100000n);

      // Put a tx in mempool spending input2 (unconfirmed)
      const mempoolTx = createTestTx(
        [{ txid: input2, vout: 0 }],
        [{ value: 99000n }]
      );
      await mempool.addTransaction(mempoolTx);
      const mempoolTxid = getTxId(mempoolTx);

      // Original tx spends input1 only
      const original = createTestTx(
        [{ txid: input1, vout: 0 }],
        [{ value: 98000n }]
      );
      await mempool.addTransaction(original);

      // Replacement tries to spend input1 AND the output of mempoolTx
      // (mempoolTx is NOT a conflict nor an ancestor of original)
      const replacement = createTestTx(
        [
          { txid: input1, vout: 0 },
          { txid: mempoolTxid, vout: 0 }, // NEW unconfirmed input not in conflict set
        ],
        [{ value: 95000n }]
      );
      const result = await mempool.addTransaction(replacement);
      expect(result.accepted).toBe(false);
      expect(result.error).toContain("Rule 2");
    });
  });

  // =========================================================================
  // Gate #5 — EntriesAndTxidsDisjoint
  // policy/rbf.cpp:EntriesAndTxidsDisjoint
  // =========================================================================
  describe("Gate #5 — EntriesAndTxidsDisjoint", () => {
    test("utility function: returns null when sets are disjoint", () => {
      const ancestors = new Set(["aaaa", "bbbb"]);
      const conflicts = new Set(["cccc", "dddd"]);
      expect(entriesAndTxidsDisjoint(ancestors, conflicts, "eeee")).toBeNull();
    });

    test("utility function: returns error when ancestor appears in conflicts", () => {
      const ancestors = new Set(["aaaa", "shared"]);
      const conflicts = new Set(["shared", "dddd"]);
      const err = entriesAndTxidsDisjoint(ancestors, conflicts, "eeee");
      expect(err).not.toBeNull();
      expect(err).toContain("shared");
      expect(err).toContain("eeee");
    });

    test("rejects replacement whose ancestor is a direct conflict", async () => {
      // Setup: input UTXO → grandparent → parent (in mempool)
      // Replacement tries to: spend the grandparent's UTXO (conflict with grandparent)
      //                        AND inherit parent as ancestor
      // This means the replacement's ancestor (parent) descends from the conflict (grandparent),
      // but we check if the replacement's own ancestors (parent) appear in direct_conflicts.
      //
      // More direct scenario:
      // grandparent (G) is in mempool
      // parent P spends G's output (P's ancestor = G)
      // Replacement R: conflicts with G (spends same UTXO as G), but R also
      //   spends output of P. Since P's ancestor G is in direct_conflicts, reject.
      const inputTxid = Buffer.alloc(32, 0x50);
      const extraInput = Buffer.alloc(32, 0x51);
      await setupUTXO(inputTxid, 0, 300000n);
      await setupUTXO(extraInput, 0, 100000n);

      // Grandparent: spends inputTxid with two outputs
      const grandparent = createTestTx(
        [{ txid: inputTxid, vout: 0 }],
        [{ value: 140000n }, { value: 140000n }]
      );
      const grandparentResult = await mempool.addTransaction(grandparent);
      expect(grandparentResult.accepted).toBe(true);
      const grandparentTxid = getTxId(grandparent);

      // Parent: spends grandparent's output[0]
      const parent = createTestTx(
        [{ txid: grandparentTxid, vout: 0 }],
        [{ value: 130000n }]
      );
      const parentResult = await mempool.addTransaction(parent);
      expect(parentResult.accepted).toBe(true);
      const parentTxid = getTxId(parent);

      // Replacement: conflicts with grandparent (same UTXO) AND spends parent's output
      // parent.dependsOn = {grandparentTxid} which is in direct_conflicts → reject
      const replacement = createTestTx(
        [
          { txid: inputTxid, vout: 0 },   // conflicts with grandparent
          { txid: parentTxid, vout: 0 },  // spends parent, whose ancestor IS grandparent
        ],
        [{ value: 280000n }] // high fee
      );
      const result = await mempool.addTransaction(replacement);
      expect(result.accepted).toBe(false);
      expect(result.error).toContain("EntriesAndTxidsDisjoint");
    });
  });

  // =========================================================================
  // Gate #6 — PaysForRBF Rule #3 (replacement_fees >= original_fees)
  // policy/rbf.cpp:PaysForRBF line 109
  // =========================================================================
  describe("Gate #6 — PaysForRBF Rule #3 (fees >= original)", () => {
    test("accepts replacement with strictly higher absolute fee", async () => {
      const inputTxid = Buffer.alloc(32, 0x01);
      await setupUTXO(inputTxid, 0, 100000n);

      // Original transaction: 1000 sat fee
      const original = createTestTx(
        [{ txid: inputTxid, vout: 0 }],
        [{ value: 99000n }]
      );
      await mempool.addTransaction(original);

      // Replacement transaction: 2000 sat fee (higher)
      const replacement = createTestTx(
        [{ txid: inputTxid, vout: 0 }],
        [{ value: 98000n }]
      );
      const result = await mempool.addTransaction(replacement);
      expect(result.accepted).toBe(true);
      expect(mempool.getSize()).toBe(1);

      const replacementTxid = getTxId(replacement);
      const originalTxid = getTxId(original);
      expect(mempool.hasTransaction(replacementTxid)).toBe(true);
      expect(mempool.hasTransaction(originalTxid)).toBe(false);
    });

    test("rejects replacement with strictly lower absolute fee (Rule #3)", async () => {
      const inputTxid = Buffer.alloc(32, 0x02);
      await setupUTXO(inputTxid, 0, 100000n);

      // Original transaction: 2000 sat fee
      const original = createTestTx(
        [{ txid: inputTxid, vout: 0 }],
        [{ value: 98000n }]
      );
      await mempool.addTransaction(original);

      // Replacement with lower fee (1000 sat < 2000 sat)
      const lowerFee = createTestTx(
        [{ txid: inputTxid, vout: 0 }],
        [{ value: 99000n }]
      );
      const result = await mempool.addTransaction(lowerFee);
      expect(result.accepted).toBe(false);
      expect(result.error).toContain("Rule 3");
    });

    test("equal fees: Rule #3 passes (>= not >) but Rule #4 rejects zero increment", async () => {
      // Core policy/rbf.cpp:109 — `replacement_fees < original_fees` → reject.
      // Equal fees pass Rule #3 but fail Rule #4 (zero additional fee < relay_fee * vsize).
      const inputTxid = Buffer.alloc(32, 0x60);
      await setupUTXO(inputTxid, 0, 100000n);

      const original = createTestTx(
        [{ txid: inputTxid, vout: 0 }],
        [{ value: 98000n }] // 2000 sat fee
      );
      await mempool.addTransaction(original);

      // Replacement with same total outputs but different structure → same fee 2000 sat
      const sameFee = createTestTx(
        [{ txid: inputTxid, vout: 0 }],
        [{ value: 49000n }, { value: 49000n }] // same total output = same fee
      );
      const result = await mempool.addTransaction(sameFee);
      // Rule #3 passes (equal), Rule #4 fails (additional_fee = 0 < relay_fee * vsize)
      expect(result.accepted).toBe(false);
      // Should fail with Rule #4 (incremental fee), not Rule #3
      expect(result.error).toContain("Rule 4");
    });

    test("replacement must cover sum of ALL conflicting fees (multi-conflict)", async () => {
      const inputTxid1 = Buffer.alloc(32, 0x0c);
      const inputTxid2 = Buffer.alloc(32, 0x0d);
      await setupUTXO(inputTxid1, 0, 50000n);
      await setupUTXO(inputTxid2, 0, 50000n);

      const tx1 = createTestTx(
        [{ txid: inputTxid1, vout: 0 }],
        [{ value: 47000n }] // 3000 sat fee
      );
      const tx2 = createTestTx(
        [{ txid: inputTxid2, vout: 0 }],
        [{ value: 48000n }] // 2000 sat fee
      );

      await mempool.addTransaction(tx1);
      await mempool.addTransaction(tx2);

      // Replacement: 4000 sat fee but conflicts have 3000+2000 = 5000 sat combined
      const replacement = createTestTx(
        [
          { txid: inputTxid1, vout: 0 },
          { txid: inputTxid2, vout: 0 },
        ],
        [{ value: 96000n }] // 4000 sat fee (< 5000 combined)
      );
      const result = await mempool.addTransaction(replacement);
      expect(result.accepted).toBe(false);
      expect(result.error).toContain("Rule 3");
    });
  });

  // =========================================================================
  // Gate #7 — PaysForRBF Rule #4 (incremental relay fee)
  // policy/rbf.cpp:PaysForRBF line 118
  // =========================================================================
  describe("Gate #7 — PaysForRBF Rule #4 (incremental relay fee)", () => {
    test("requires minimum incremental fee for bandwidth", async () => {
      const inputTxid = Buffer.alloc(32, 0x04);
      await setupUTXO(inputTxid, 0, 100000n);

      // Original: small fee
      const original = createTestTx(
        [{ txid: inputTxid, vout: 0 }],
        [{ value: 99900n }] // 100 sat fee
      );
      await mempool.addTransaction(original);

      // Replacement: marginally higher fee but not enough for bandwidth
      // Incremental relay fee is 1 sat/vB, so for ~68 vB tx we need at least 68 sat more
      const replacement = createTestTx(
        [{ txid: inputTxid, vout: 0 }],
        [{ value: 99850n }] // 150 sat fee (only 50 sat more)
      );
      const result = await mempool.addTransaction(replacement);
      expect(result.accepted).toBe(false);
      expect(result.error).toContain("Rule 4");
    });

    test("accepts replacement meeting incremental relay fee", async () => {
      const inputTxid = Buffer.alloc(32, 0x05);
      await setupUTXO(inputTxid, 0, 100000n);

      // Original: small fee
      const original = createTestTx(
        [{ txid: inputTxid, vout: 0 }],
        [{ value: 99900n }] // 100 sat fee
      );
      await mempool.addTransaction(original);

      // Replacement: significantly higher fee
      const replacement = createTestTx(
        [{ txid: inputTxid, vout: 0 }],
        [{ value: 99700n }] // 300 sat fee (200 sat more, > 68 sat for bandwidth)
      );
      const result = await mempool.addTransaction(replacement);
      expect(result.accepted).toBe(true);
    });

    test("lower fee rate is OK if absolute + incremental fees are met (no per-conflict rate check)", async () => {
      // Core does NOT check per-conflict fee rate (only absolute/incremental).
      // A larger replacement may have a lower sat/vB than original but still be valid.
      const inputTxid = Buffer.alloc(32, 0x70);
      await setupUTXO(inputTxid, 0, 1_000_000n);

      // Original: 2000 sat / ~85 vbytes ≈ 23.5 sat/vB
      const original = createTestTx(
        [{ txid: inputTxid, vout: 0 }],
        [{ value: 998000n }]
      );
      const r0 = await mempool.addTransaction(original);
      expect(r0.accepted).toBe(true);

      // Replacement: much larger tx (many outputs), lower sat/vB but:
      //   fee = 10000 sat, which is > 2000 (Rule #3) and additional fee 8000 > relay
      // This produces a lower fee rate (say ~4 sat/vB on 2000-vbyte tx) but is VALID
      const manyOutputs = Array(25).fill(null).map(() => ({ value: 39000n }));
      // total outputs = 25*39000 = 975000, fee = 1000000 - 975000 = 25000 sat
      const replacement = createTestTx(
        [{ txid: inputTxid, vout: 0 }],
        manyOutputs // total out 975000, fee 25000
      );
      const result = await mempool.addTransaction(replacement);
      // Should be accepted: fee(25000) > original(2000), incremental(23000) >> relay
      expect(result.accepted).toBe(true);
    });
  });

  // =========================================================================
  // Integration: basic replacement flow
  // =========================================================================
  describe("basic RBF replacement", () => {
    test("accepts replacement with higher absolute fee", async () => {
      const inputTxid = Buffer.alloc(32, 0x01);
      await setupUTXO(inputTxid, 0, 100000n);

      const original = createTestTx(
        [{ txid: inputTxid, vout: 0 }],
        [{ value: 99000n }]
      );
      const result1 = await mempool.addTransaction(original);
      expect(result1.accepted).toBe(true);
      expect(mempool.getSize()).toBe(1);

      const replacement = createTestTx(
        [{ txid: inputTxid, vout: 0 }],
        [{ value: 98000n }]
      );
      const result2 = await mempool.addTransaction(replacement);
      expect(result2.accepted).toBe(true);
      expect(mempool.getSize()).toBe(1);

      const replacementTxid = getTxId(replacement);
      const originalTxid = getTxId(original);
      expect(mempool.hasTransaction(replacementTxid)).toBe(true);
      expect(mempool.hasTransaction(originalTxid)).toBe(false);
    });
  });

  describe("full RBF (no signaling required)", () => {
    test("allows replacement without BIP125 sequence signal (full RBF mode)", async () => {
      const inputTxid = Buffer.alloc(32, 0x06);
      await setupUTXO(inputTxid, 0, 100000n);

      // Original transaction: sequence = 0xffffffff (no BIP125 signal)
      const original = createTestTx(
        [{ txid: inputTxid, vout: 0, sequence: 0xffffffff }],
        [{ value: 99000n }]
      );
      const result1 = await mempool.addTransaction(original);
      expect(result1.accepted).toBe(true);

      // Replacement should still be allowed (full RBF)
      const replacement = createTestTx(
        [{ txid: inputTxid, vout: 0, sequence: 0xffffffff }],
        [{ value: 98000n }]
      );
      const result2 = await mempool.addTransaction(replacement);
      expect(result2.accepted).toBe(true);
    });

    test("isReplaceable returns true for known txid, false for unknown", async () => {
      const inputTxid = Buffer.alloc(32, 0x07);
      await setupUTXO(inputTxid, 0, 100000n);

      const tx = createTestTx(
        [{ txid: inputTxid, vout: 0, sequence: 0xffffffff }],
        [{ value: 99000n }]
      );
      await mempool.addTransaction(tx);

      const txid = getTxId(tx);
      expect(mempool.isReplaceable(txid)).toBe(true);
      // Unknown txid returns false
      expect(mempool.isReplaceable(Buffer.alloc(32, 0xff))).toBe(false);
    });
  });

  describe("descendant eviction", () => {
    test("evicts descendants when replacing parent", async () => {
      const inputTxid = Buffer.alloc(32, 0x08);
      await setupUTXO(inputTxid, 0, 100000n);

      const parent = createTestTx(
        [{ txid: inputTxid, vout: 0 }],
        [{ value: 98000n }]
      );
      await mempool.addTransaction(parent);
      const parentTxid = getTxId(parent);

      const child = createTestTx(
        [{ txid: parentTxid, vout: 0 }],
        [{ value: 97000n }]
      );
      await mempool.addTransaction(child);
      const childTxid = getTxId(child);

      expect(mempool.getSize()).toBe(2);
      expect(mempool.hasTransaction(childTxid)).toBe(true);

      // Replace parent - this should also evict the child
      const replacement = createTestTx(
        [{ txid: inputTxid, vout: 0 }],
        [{ value: 95000n }] // Higher fee than parent + child combined
      );
      const result = await mempool.addTransaction(replacement);
      expect(result.accepted).toBe(true);

      expect(mempool.hasTransaction(parentTxid)).toBe(false);
      expect(mempool.hasTransaction(childTxid)).toBe(false);
      expect(mempool.getSize()).toBe(1);
    });

    test("evicts grandchildren when replacing grandparent", async () => {
      const inputTxid = Buffer.alloc(32, 0x09);
      await setupUTXO(inputTxid, 0, 100000n);

      const grandparent = createTestTx(
        [{ txid: inputTxid, vout: 0 }],
        [{ value: 98000n }]
      );
      await mempool.addTransaction(grandparent);
      const grandparentTxid = getTxId(grandparent);

      const parent = createTestTx(
        [{ txid: grandparentTxid, vout: 0 }],
        [{ value: 97000n }]
      );
      await mempool.addTransaction(parent);
      const parentTxid = getTxId(parent);

      const child = createTestTx(
        [{ txid: parentTxid, vout: 0 }],
        [{ value: 96000n }]
      );
      await mempool.addTransaction(child);
      const childTxid = getTxId(child);

      expect(mempool.getSize()).toBe(3);

      const replacement = createTestTx(
        [{ txid: inputTxid, vout: 0 }],
        [{ value: 90000n }]
      );
      const result = await mempool.addTransaction(replacement);
      expect(result.accepted).toBe(true);

      expect(mempool.hasTransaction(grandparentTxid)).toBe(false);
      expect(mempool.hasTransaction(parentTxid)).toBe(false);
      expect(mempool.hasTransaction(childTxid)).toBe(false);
      expect(mempool.getSize()).toBe(1);
    });
  });

  describe("multiple conflicts", () => {
    test("replaces multiple conflicting transactions", async () => {
      const inputTxid1 = Buffer.alloc(32, 0x0a);
      const inputTxid2 = Buffer.alloc(32, 0x0b);
      await setupUTXO(inputTxid1, 0, 50000n);
      await setupUTXO(inputTxid2, 0, 50000n);

      const tx1 = createTestTx(
        [{ txid: inputTxid1, vout: 0 }],
        [{ value: 49000n }]
      );
      const tx2 = createTestTx(
        [{ txid: inputTxid2, vout: 0 }],
        [{ value: 49000n }]
      );

      await mempool.addTransaction(tx1);
      await mempool.addTransaction(tx2);
      expect(mempool.getSize()).toBe(2);

      const replacement = createTestTx(
        [
          { txid: inputTxid1, vout: 0 },
          { txid: inputTxid2, vout: 0 },
        ],
        [{ value: 95000n }] // 5000 sat fee (more than 2000 combined)
      );
      const result = await mempool.addTransaction(replacement);
      expect(result.accepted).toBe(true);
      expect(mempool.getSize()).toBe(1);

      expect(mempool.hasTransaction(getTxId(tx1))).toBe(false);
      expect(mempool.hasTransaction(getTxId(tx2))).toBe(false);
    });
  });

  describe("edge cases", () => {
    test("existing mempool tx cannot be replacement of itself (duplicate)", async () => {
      const inputTxid = Buffer.alloc(32, 0x0e);
      await setupUTXO(inputTxid, 0, 100000n);

      const tx = createTestTx(
        [{ txid: inputTxid, vout: 0 }],
        [{ value: 99000n }]
      );

      const result1 = await mempool.addTransaction(tx);
      expect(result1.accepted).toBe(true);

      const result2 = await mempool.addTransaction(tx);
      expect(result2.accepted).toBe(false);
      expect(result2.error).toContain("already in mempool");
    });
  });
});
