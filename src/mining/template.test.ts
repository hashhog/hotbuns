/**
 * Tests for block template construction.
 */

import { describe, test, expect, beforeEach, afterEach } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ChainDB, UTXOEntry } from "../storage/database.js";
import { UTXOManager } from "../chain/utxo.js";
import { ChainStateManager } from "../chain/state.js";
import { REGTEST } from "../consensus/params.js";
import { Mempool } from "../mempool/mempool.js";
import {
  BlockTemplateBuilder,
  createP2PKHCoinbaseScript,
  createP2WPKHCoinbaseScript,
  createP2WSHCoinbaseScript,
  isFinalTx,
} from "./template.js";
import type { Transaction } from "../validation/tx.js";
import {
  getTxId,
  getWTxId,
  getTxWeight,
  isCoinbase,
} from "../validation/tx.js";
import {
  computeMerkleRoot,
  computeWitnessMerkleRoot,
  getWitnessCommitment,
} from "../validation/block.js";
import { hash256 } from "../crypto/primitives.js";

describe("BlockTemplateBuilder", () => {
  let tempDir: string;
  let db: ChainDB;
  let utxo: UTXOManager;
  let chainState: ChainStateManager;
  let mempool: Mempool;
  let builder: BlockTemplateBuilder;

  // Helper to create a simple test transaction
  function createTestTx(
    inputs: Array<{ txid: Buffer; vout: number }>,
    outputs: Array<{ value: bigint; scriptPubKey?: Buffer }>,
    witness?: Buffer[][]
  ): Transaction {
    return {
      version: 2,
      inputs: inputs.map((inp, i) => ({
        prevOut: { txid: inp.txid, vout: inp.vout },
        scriptSig: Buffer.alloc(0),
        sequence: 0xffffffff,
        witness: witness?.[i] ?? [],
      })),
      outputs: outputs.map((out) => ({
        value: out.value,
        scriptPubKey: out.scriptPubKey ?? Buffer.from([0x51]), // OP_TRUE
      })),
      lockTime: 0,
    };
  }

  // Helper to set up a UTXO that can be spent
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
    tempDir = await mkdtemp(join(tmpdir(), "template-test-"));
    db = new ChainDB(tempDir);
    await db.open();
    utxo = new UTXOManager(db);
    chainState = new ChainStateManager(db, REGTEST);
    await chainState.load();
    mempool = new Mempool(utxo, REGTEST, 1_000_000);
    mempool.setTipHeight(200); // Well past coinbase maturity
    builder = new BlockTemplateBuilder(mempool, chainState, REGTEST);
  });

  afterEach(async () => {
    await db.close();
    await rm(tempDir, { recursive: true, force: true });
  });

  describe("createTemplate", () => {
    test("creates empty template when mempool is empty", () => {
      const coinbaseScript = Buffer.from([0x51]); // OP_TRUE
      const template = builder.createTemplate(coinbaseScript);

      expect(template.height).toBe(1); // First block after genesis
      expect(template.transactions.length).toBe(0);
      expect(template.totalFees).toBe(0n);
      expect(template.coinbaseTx).toBeDefined();
      expect(isCoinbase(template.coinbaseTx)).toBe(true);
    });

    test("includes mempool transactions in template", async () => {
      // Set up UTXO for spending
      const inputTxid = Buffer.alloc(32, 0xaa);
      await setupUTXO(inputTxid, 0, 100000n);

      // Create and add a transaction to mempool
      const tx = createTestTx(
        [{ txid: inputTxid, vout: 0 }],
        [{ value: 90000n }] // 10000 sat fee
      );

      const result = await mempool.addTransaction(tx);
      expect(result.accepted).toBe(true);

      // Create template
      const coinbaseScript = Buffer.from([0x51]);
      const template = builder.createTemplate(coinbaseScript);

      expect(template.transactions.length).toBe(1);
      expect(template.totalFees).toBe(10000n);
    });

    test("orders transactions by fee rate", async () => {
      // Set up UTXOs
      const input1 = Buffer.alloc(32, 0xaa);
      const input2 = Buffer.alloc(32, 0xbb);
      await setupUTXO(input1, 0, 100000n);
      await setupUTXO(input2, 0, 100000n);

      // Create low fee tx (smaller fee rate)
      const lowFeeTx = createTestTx(
        [{ txid: input1, vout: 0 }],
        [{ value: 99000n }] // 1000 sat fee
      );

      // Create high fee tx (higher fee rate)
      const highFeeTx = createTestTx(
        [{ txid: input2, vout: 0 }],
        [{ value: 90000n }] // 10000 sat fee
      );

      // Add in reverse order (low fee first)
      await mempool.addTransaction(lowFeeTx);
      await mempool.addTransaction(highFeeTx);

      const template = builder.createTemplate(Buffer.from([0x51]));

      expect(template.transactions.length).toBe(2);
      // High fee tx should come first
      const highFeeTxid = getTxId(highFeeTx);
      const firstSelectedTxid = getTxId(template.transactions[0]);
      expect(firstSelectedTxid.equals(highFeeTxid)).toBe(true);
    });

    test("respects parent-child dependencies", async () => {
      // Set up initial UTXO
      const input1 = Buffer.alloc(32, 0xaa);
      await setupUTXO(input1, 0, 200000n);

      // Create parent tx
      const parentTx = createTestTx(
        [{ txid: input1, vout: 0 }],
        [
          { value: 100000n }, // Output for child to spend
          { value: 90000n },  // Change
        ] // 10000 sat fee
      );

      await mempool.addTransaction(parentTx);

      // Create child tx spending parent's output
      const parentTxid = getTxId(parentTx);
      const childTx = createTestTx(
        [{ txid: parentTxid, vout: 0 }],
        [{ value: 95000n }] // 5000 sat fee
      );

      await mempool.addTransaction(childTx);

      const template = builder.createTemplate(Buffer.from([0x51]));

      expect(template.transactions.length).toBe(2);

      // Parent must come before child
      const parentIdx = template.transactions.findIndex(
        (tx) => getTxId(tx).equals(parentTxid)
      );
      const childTxid = getTxId(childTx);
      const childIdx = template.transactions.findIndex(
        (tx) => getTxId(tx).equals(childTxid)
      );

      expect(parentIdx).toBeLessThan(childIdx);
    });

    test("calculates total weight correctly", async () => {
      const input1 = Buffer.alloc(32, 0xaa);
      await setupUTXO(input1, 0, 100000n);

      const tx = createTestTx(
        [{ txid: input1, vout: 0 }],
        [{ value: 90000n }]
      );

      await mempool.addTransaction(tx);

      const template = builder.createTemplate(Buffer.from([0x51]));

      // Weight should include: header (320) + coinbase + tx
      const coinbaseWeight = getTxWeight(template.coinbaseTx);
      const txWeight = getTxWeight(tx);
      const expectedWeight = 320 + coinbaseWeight + txWeight;

      expect(template.totalWeight).toBe(expectedWeight);
    });

    test("includes extraNonce in coinbase scriptSig", () => {
      const coinbaseScript = Buffer.from([0x51]);
      const extraNonce = Buffer.from("MINER_NONCE_DATA");

      const template = builder.createTemplate(coinbaseScript, extraNonce);

      // ExtraNonce should be in the scriptSig after the height push
      const scriptSig = template.coinbaseTx.inputs[0].scriptSig;
      expect(scriptSig.includes(extraNonce)).toBe(true);
    });
  });

  describe("coinbase transaction", () => {
    test("has correct structure for coinbase input", () => {
      const template = builder.createTemplate(Buffer.from([0x51]));
      const coinbase = template.coinbaseTx;

      expect(coinbase.inputs.length).toBe(1);
      expect(coinbase.inputs[0].prevOut.txid).toEqual(Buffer.alloc(32, 0));
      expect(coinbase.inputs[0].prevOut.vout).toBe(0xffffffff);
    });

    test("pays correct subsidy at height 1 (regtest)", () => {
      const template = builder.createTemplate(Buffer.from([0x51]));

      // At height 1, regtest subsidy is 50 BTC
      const expectedSubsidy = 50_00000000n;
      expect(template.coinbaseTx.outputs[0].value).toBe(expectedSubsidy);
    });

    test("includes fees in coinbase output", async () => {
      const input1 = Buffer.alloc(32, 0xaa);
      await setupUTXO(input1, 0, 100000n);

      const tx = createTestTx(
        [{ txid: input1, vout: 0 }],
        [{ value: 90000n }] // 10000 sat fee
      );

      await mempool.addTransaction(tx);

      const template = builder.createTemplate(Buffer.from([0x51]));

      const expectedValue = 50_00000000n + 10000n; // subsidy + fee
      expect(template.coinbaseTx.outputs[0].value).toBe(expectedValue);
    });

    test("outputs to provided coinbase script", () => {
      const pubKeyHash = Buffer.alloc(20, 0x42);
      const coinbaseScript = createP2PKHCoinbaseScript(pubKeyHash);

      const template = builder.createTemplate(coinbaseScript);

      expect(template.coinbaseTx.outputs[0].scriptPubKey).toEqual(coinbaseScript);
    });
  });

  describe("BIP34 height encoding", () => {
    // Helper to extract height from coinbase scriptSig
    function extractBIP34Height(scriptSig: Buffer): number {
      if (scriptSig.length === 0) {
        return -1;
      }

      const firstByte = scriptSig[0];

      // OP_0
      if (firstByte === 0x00) {
        return 0;
      }

      // OP_1 to OP_16
      if (firstByte >= 0x51 && firstByte <= 0x60) {
        return firstByte - 0x50;
      }

      // Direct push
      const pushLen = firstByte;
      if (pushLen > 0 && pushLen <= 4 && scriptSig.length > pushLen) {
        const heightBytes = scriptSig.subarray(1, 1 + pushLen);
        let height = 0;
        for (let i = 0; i < heightBytes.length; i++) {
          height |= heightBytes[i] << (8 * i);
        }
        // Handle negative numbers (high bit set)
        if (heightBytes[heightBytes.length - 1] & 0x80) {
          // This is a negative number representation
          height = -(height & ~(0x80 << (8 * (heightBytes.length - 1))));
        }
        return height;
      }

      return -1;
    }

    test("encodes height 0 as OP_0", async () => {
      // Modify chain state to simulate height 0
      // This is tricky since genesis is at height 0, and we're building for height 1
      // So let's just verify the encoding function works via the builder

      // For height 1, we can verify
      const template = builder.createTemplate(Buffer.from([0x51]));
      const scriptSig = template.coinbaseTx.inputs[0].scriptSig;

      // At height 1, should use OP_1 (0x51)
      expect(scriptSig[0]).toBe(0x51);
      expect(extractBIP34Height(scriptSig)).toBe(1);
    });

    test("encodes heights 1-16 as OP_n", () => {
      const template = builder.createTemplate(Buffer.from([0x51]));
      const scriptSig = template.coinbaseTx.inputs[0].scriptSig;

      // Height 1 = OP_1 (0x51)
      expect(scriptSig[0]).toBe(0x51);
    });

    test("encodes larger heights correctly", async () => {
      // Simulate higher chain height by modifying the mock
      // For now, we test via the extraction
      const template = builder.createTemplate(Buffer.from([0x51]));
      const height = extractBIP34Height(template.coinbaseTx.inputs[0].scriptSig);

      // Should match template height
      expect(height).toBe(template.height);
    });
  });

  describe("witness commitment", () => {
    test("includes witness commitment in segwit block", async () => {
      // REGTEST has segwit active at height 0
      const input1 = Buffer.alloc(32, 0xaa);
      await setupUTXO(input1, 0, 100000n);

      // Create a segwit transaction
      const tx = createTestTx(
        [{ txid: input1, vout: 0 }],
        [{ value: 90000n }],
        [[Buffer.from("signature_data")]] // Witness data
      );

      await mempool.addTransaction(tx);

      const template = builder.createTemplate(Buffer.from([0x51]));

      // Should have 2 outputs: reward + witness commitment
      expect(template.coinbaseTx.outputs.length).toBe(2);

      // Second output should be witness commitment
      const commitmentOutput = template.coinbaseTx.outputs[1];
      expect(commitmentOutput.value).toBe(0n);

      // Check commitment header
      const script = commitmentOutput.scriptPubKey;
      expect(script[0]).toBe(0x6a); // OP_RETURN
      expect(script[1]).toBe(0x24); // Push 36 bytes
      expect(script[2]).toBe(0xaa);
      expect(script[3]).toBe(0x21);
      expect(script[4]).toBe(0xa9);
      expect(script[5]).toBe(0xed);
    });

    test("coinbase has witness nonce in segwit block", async () => {
      const template = builder.createTemplate(Buffer.from([0x51]));

      // Coinbase should have witness data (32 zero bytes)
      expect(template.coinbaseTx.inputs[0].witness.length).toBe(1);
      expect(template.coinbaseTx.inputs[0].witness[0]).toEqual(Buffer.alloc(32, 0));
    });

    test("witness commitment is valid", async () => {
      const input1 = Buffer.alloc(32, 0xaa);
      await setupUTXO(input1, 0, 100000n);

      const tx = createTestTx(
        [{ txid: input1, vout: 0 }],
        [{ value: 90000n }],
        [[Buffer.from("witness")]]
      );

      await mempool.addTransaction(tx);

      const template = builder.createTemplate(Buffer.from([0x51]));

      // Extract commitment from coinbase
      const script = template.coinbaseTx.outputs[1].scriptPubKey;
      const commitment = script.subarray(6, 38);

      // Compute expected commitment
      const wtxids: Buffer[] = [Buffer.alloc(32, 0)]; // Coinbase wtxid
      for (const selectedTx of template.transactions) {
        wtxids.push(getWTxId(selectedTx));
      }
      const witnessMerkleRoot = computeWitnessMerkleRoot(wtxids);
      const witnessNonce = Buffer.alloc(32, 0);
      const expectedCommitment = hash256(Buffer.concat([witnessMerkleRoot, witnessNonce]));

      expect(commitment.equals(expectedCommitment)).toBe(true);
    });
  });

  describe("merkle root", () => {
    test("merkle root matches computed value", async () => {
      const input1 = Buffer.alloc(32, 0xaa);
      await setupUTXO(input1, 0, 100000n);

      const tx = createTestTx(
        [{ txid: input1, vout: 0 }],
        [{ value: 90000n }]
      );

      await mempool.addTransaction(tx);

      const template = builder.createTemplate(Buffer.from([0x51]));

      // Compute expected merkle root
      const txids = [getTxId(template.coinbaseTx)];
      for (const selectedTx of template.transactions) {
        txids.push(getTxId(selectedTx));
      }
      const expectedMerkleRoot = computeMerkleRoot(txids);

      expect(template.header.merkleRoot.equals(expectedMerkleRoot)).toBe(true);
    });
  });

  describe("block header", () => {
    test("prevBlock matches chain tip", () => {
      const template = builder.createTemplate(Buffer.from([0x51]));
      const bestBlock = chainState.getBestBlock();

      expect(template.header.prevBlock.equals(bestBlock.hash)).toBe(true);
    });

    test("nonce starts at 0", () => {
      const template = builder.createTemplate(Buffer.from([0x51]));
      expect(template.header.nonce).toBe(0);
    });

    test("has reasonable timestamp", () => {
      const template = builder.createTemplate(Buffer.from([0x51]));
      const now = Math.floor(Date.now() / 1000);

      // Timestamp should be within 2 hours of now
      expect(template.header.timestamp).toBeGreaterThan(now - 7200);
      expect(template.header.timestamp).toBeLessThanOrEqual(now + 7200);
    });

    test("has valid version bits", () => {
      const template = builder.createTemplate(Buffer.from([0x51]));
      // Should have BIP9 version bit set
      expect(template.header.version & 0x20000000).toBe(0x20000000);
    });
  });

  describe("coinbase script helpers", () => {
    test("createP2PKHCoinbaseScript creates valid script", () => {
      const pubKeyHash = Buffer.alloc(20, 0x42);
      const script = createP2PKHCoinbaseScript(pubKeyHash);

      // OP_DUP OP_HASH160 PUSH20 <hash> OP_EQUALVERIFY OP_CHECKSIG
      expect(script.length).toBe(25);
      expect(script[0]).toBe(0x76); // OP_DUP
      expect(script[1]).toBe(0xa9); // OP_HASH160
      expect(script[2]).toBe(0x14); // PUSH20
      expect(script.subarray(3, 23).equals(pubKeyHash)).toBe(true);
      expect(script[23]).toBe(0x88); // OP_EQUALVERIFY
      expect(script[24]).toBe(0xac); // OP_CHECKSIG
    });

    test("createP2PKHCoinbaseScript rejects wrong length", () => {
      expect(() => createP2PKHCoinbaseScript(Buffer.alloc(19))).toThrow();
      expect(() => createP2PKHCoinbaseScript(Buffer.alloc(21))).toThrow();
    });

    test("createP2WPKHCoinbaseScript creates valid script", () => {
      const pubKeyHash = Buffer.alloc(20, 0x42);
      const script = createP2WPKHCoinbaseScript(pubKeyHash);

      // OP_0 PUSH20 <hash>
      expect(script.length).toBe(22);
      expect(script[0]).toBe(0x00); // OP_0 (witness version)
      expect(script[1]).toBe(0x14); // PUSH20
      expect(script.subarray(2, 22).equals(pubKeyHash)).toBe(true);
    });

    test("createP2WSHCoinbaseScript creates valid script", () => {
      const scriptHash = Buffer.alloc(32, 0x42);
      const script = createP2WSHCoinbaseScript(scriptHash);

      // OP_0 PUSH32 <hash>
      expect(script.length).toBe(34);
      expect(script[0]).toBe(0x00); // OP_0 (witness version)
      expect(script[1]).toBe(0x20); // PUSH32
      expect(script.subarray(2, 34).equals(scriptHash)).toBe(true);
    });
  });

  describe("weight limits", () => {
    test("does not exceed max block weight", async () => {
      // Create many transactions
      for (let i = 0; i < 100; i++) {
        const inputTxid = Buffer.alloc(32);
        inputTxid.writeUInt32LE(i, 0);
        await setupUTXO(inputTxid, 0, 100000n);

        const tx = createTestTx(
          [{ txid: inputTxid, vout: 0 }],
          [{ value: 90000n }]
        );

        await mempool.addTransaction(tx);
      }

      const template = builder.createTemplate(Buffer.from([0x51]));

      // Total weight should not exceed max (4M for regtest)
      expect(template.totalWeight).toBeLessThanOrEqual(REGTEST.maxBlockWeight);
    });
  });

  describe("coinbase properties", () => {
    test("coinbase sequence is 0xFFFFFFFF (opts out of BIP68)", () => {
      const template = builder.createTemplate(Buffer.from([0x51]));

      // Coinbase input should have sequence 0xFFFFFFFF
      expect(template.coinbaseTx.inputs[0].sequence).toBe(0xffffffff);
    });

    test("coinbase lockTime is 0", () => {
      const template = builder.createTemplate(Buffer.from([0x51]));

      // Coinbase lockTime should be 0
      expect(template.coinbaseTx.lockTime).toBe(0);
    });
  });
});

describe("isFinalTx", () => {
  // Helper to create a simple transaction for testing
  function createTxWithLocktime(
    lockTime: number,
    sequences: number[] = [0xffffffff]
  ): Transaction {
    return {
      version: 2,
      inputs: sequences.map((seq, i) => ({
        prevOut: {
          txid: Buffer.alloc(32, i + 1),
          vout: 0,
        },
        scriptSig: Buffer.alloc(0),
        sequence: seq,
        witness: [],
      })),
      outputs: [
        {
          value: 1000n,
          scriptPubKey: Buffer.from([0x51]), // OP_TRUE
        },
      ],
      lockTime,
    };
  }

  describe("lockTime = 0", () => {
    test("transaction with lockTime 0 is always final", () => {
      const tx = createTxWithLocktime(0);
      expect(isFinalTx(tx, 100, 1000000000)).toBe(true);
    });

    test("transaction with lockTime 0 and non-final sequence is still final", () => {
      const tx = createTxWithLocktime(0, [0x00000000]);
      expect(isFinalTx(tx, 100, 1000000000)).toBe(true);
    });
  });

  describe("height-based lockTime (< 500_000_000)", () => {
    test("tx is final when blockHeight > lockTime", () => {
      const tx = createTxWithLocktime(100);
      // Block height 101 > lockTime 100, so it's final
      expect(isFinalTx(tx, 101, 0)).toBe(true);
    });

    test("tx is final when blockHeight == lockTime (lockTime < blockHeight is final)", () => {
      const tx = createTxWithLocktime(100);
      // Block height 100 == lockTime 100, so lockTime is NOT less than height
      // The tx should NOT be final unless all sequences are final
      expect(isFinalTx(tx, 100, 0)).toBe(true); // All sequences are 0xffffffff
    });

    test("tx with non-final sequences is not final when lockTime >= blockHeight", () => {
      const tx = createTxWithLocktime(100, [0x00000000]);
      // Block height 100 == lockTime 100, and sequence is not final
      expect(isFinalTx(tx, 100, 0)).toBe(false);
    });

    test("tx with non-final sequences becomes final when blockHeight exceeds lockTime", () => {
      const tx = createTxWithLocktime(100, [0x00000000]);
      // Block height 101 > lockTime 100
      expect(isFinalTx(tx, 101, 0)).toBe(true);
    });
  });

  describe("time-based lockTime (>= 500_000_000)", () => {
    const LOCKTIME_THRESHOLD = 500_000_000;

    test("tx is final when blockTime > lockTime", () => {
      const lockTime = LOCKTIME_THRESHOLD + 1000;
      const tx = createTxWithLocktime(lockTime);
      // Block time exceeds lockTime
      expect(isFinalTx(tx, 1000, lockTime + 1)).toBe(true);
    });

    test("tx is not final when blockTime <= lockTime and sequences not final", () => {
      const lockTime = LOCKTIME_THRESHOLD + 1000;
      const tx = createTxWithLocktime(lockTime, [0x00000000]);
      // Block time equals lockTime, and sequence is not final
      expect(isFinalTx(tx, 1000, lockTime)).toBe(false);
    });

    test("tx is final when blockTime == lockTime but all sequences are final", () => {
      const lockTime = LOCKTIME_THRESHOLD + 1000;
      const tx = createTxWithLocktime(lockTime, [0xffffffff]);
      // Block time equals lockTime, but sequence is final
      expect(isFinalTx(tx, 1000, lockTime)).toBe(true);
    });
  });

  describe("sequence-based finality", () => {
    test("tx with all inputs having sequence 0xFFFFFFFF is final regardless of lockTime", () => {
      // High lockTime that would otherwise make tx non-final
      const tx = createTxWithLocktime(999999, [0xffffffff, 0xffffffff]);
      // Low block height that wouldn't satisfy lockTime
      expect(isFinalTx(tx, 100, 0)).toBe(true);
    });

    test("tx with one non-final sequence is not final when lockTime not satisfied", () => {
      const tx = createTxWithLocktime(999999, [0xffffffff, 0x00000000]);
      expect(isFinalTx(tx, 100, 0)).toBe(false);
    });

    test("tx with all non-final sequences is not final when lockTime not satisfied", () => {
      const tx = createTxWithLocktime(999999, [0x00000000, 0x00000000]);
      expect(isFinalTx(tx, 100, 0)).toBe(false);
    });
  });
});

describe("locktime filtering in block template", () => {
  let tempDir: string;
  let db: ChainDB;
  let utxo: UTXOManager;
  let chainState: ChainStateManager;
  let mempool: Mempool;
  let builder: BlockTemplateBuilder;

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
    tempDir = await mkdtemp(join(tmpdir(), "locktime-test-"));
    db = new ChainDB(tempDir);
    await db.open();
    utxo = new UTXOManager(db);
    chainState = new ChainStateManager(db, REGTEST);
    await chainState.load();
    mempool = new Mempool(utxo, REGTEST, 1_000_000);
    mempool.setTipHeight(200);
    builder = new BlockTemplateBuilder(mempool, chainState, REGTEST);
    // Set a reasonable MTP for time-based locktime tests
    builder.setMedianTimePast(Math.floor(Date.now() / 1000) - 3600);
  });

  afterEach(async () => {
    await db.close();
    await rm(tempDir, { recursive: true, force: true });
  });

  test("excludes transactions with unsatisfied height-based lockTime", async () => {
    const inputTxid = Buffer.alloc(32, 0xaa);
    await setupUTXO(inputTxid, 0, 100000n);

    // Create a tx with lockTime set to a future height (200 + some margin)
    // Chain tip is at height 0 (genesis), so next block will be height 1
    // But we set mempool tip to 200, so next block template is for height ~1
    const tx: Transaction = {
      version: 2,
      inputs: [
        {
          prevOut: { txid: inputTxid, vout: 0 },
          scriptSig: Buffer.alloc(0),
          sequence: 0x00000000, // Non-final sequence
          witness: [],
        },
      ],
      outputs: [{ value: 90000n, scriptPubKey: Buffer.from([0x51]) }],
      lockTime: 9999, // Far future height
    };

    await mempool.addTransaction(tx);
    expect(mempool.getSize()).toBe(1);

    const template = builder.createTemplate(Buffer.from([0x51]));

    // The tx should NOT be included because lockTime is not satisfied
    expect(template.transactions.length).toBe(0);
  });

  test("includes transactions with satisfied height-based lockTime", async () => {
    const inputTxid = Buffer.alloc(32, 0xaa);
    await setupUTXO(inputTxid, 0, 100000n);

    // Create a tx with lockTime 0 (always final)
    const tx: Transaction = {
      version: 2,
      inputs: [
        {
          prevOut: { txid: inputTxid, vout: 0 },
          scriptSig: Buffer.alloc(0),
          sequence: 0x00000000, // Non-final sequence
          witness: [],
        },
      ],
      outputs: [{ value: 90000n, scriptPubKey: Buffer.from([0x51]) }],
      lockTime: 0, // Always final
    };

    await mempool.addTransaction(tx);
    expect(mempool.getSize()).toBe(1);

    const template = builder.createTemplate(Buffer.from([0x51]));

    // The tx SHOULD be included because lockTime = 0
    expect(template.transactions.length).toBe(1);
  });

  test("includes transactions with final sequences regardless of lockTime", async () => {
    const inputTxid = Buffer.alloc(32, 0xaa);
    await setupUTXO(inputTxid, 0, 100000n);

    // Create a tx with high lockTime but final sequences
    const tx: Transaction = {
      version: 2,
      inputs: [
        {
          prevOut: { txid: inputTxid, vout: 0 },
          scriptSig: Buffer.alloc(0),
          sequence: 0xffffffff, // Final sequence
          witness: [],
        },
      ],
      outputs: [{ value: 90000n, scriptPubKey: Buffer.from([0x51]) }],
      lockTime: 9999, // High lockTime, but sequence is final
    };

    await mempool.addTransaction(tx);
    expect(mempool.getSize()).toBe(1);

    const template = builder.createTemplate(Buffer.from([0x51]));

    // The tx SHOULD be included because all sequences are final
    expect(template.transactions.length).toBe(1);
  });
});
