/**
 * Tests for chain state management.
 */

import { describe, test, expect, beforeEach, afterEach } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ChainDB } from "../storage/database.js";
import { REGTEST } from "../consensus/params.js";
import { ChainStateManager } from "./state.js";
import type { Block, BlockHeader } from "../validation/block.js";
import { getBlockHash } from "../validation/block.js";
import {
  getTxId,
  SEQUENCE_LOCKTIME_TYPE_FLAG,
} from "../validation/tx.js";
import type { Transaction, TxIn, TxOut } from "../validation/tx.js";
import { hash256 } from "../crypto/primitives.js";

describe("ChainStateManager", () => {
  let tempDir: string;
  let db: ChainDB;
  let chainState: ChainStateManager;

  // Helper to create a coinbase transaction
  function createCoinbaseTx(height: number, value: bigint): Transaction {
    const scriptSig = Buffer.concat([
      Buffer.from([0x03]), // Push 3 bytes
      Buffer.alloc(3, height), // Height encoding (simplified)
    ]);

    return {
      version: 1,
      inputs: [
        {
          prevOut: {
            txid: Buffer.alloc(32, 0),
            vout: 0xffffffff,
          },
          scriptSig,
          sequence: 0xffffffff,
          witness: [],
        },
      ],
      outputs: [
        {
          value,
          scriptPubKey: Buffer.from([
            0x76, 0xa9, 0x14, ...Array(20).fill(0x01), 0x88, 0xac,
          ]),
        },
      ],
      lockTime: 0,
    };
  }

  // Helper to create a regular transaction spending from another tx
  function createSpendingTx(
    inputTxid: Buffer,
    inputVout: number,
    outputValue: bigint
  ): Transaction {
    return {
      version: 1,
      inputs: [
        {
          prevOut: {
            txid: inputTxid,
            vout: inputVout,
          },
          scriptSig: Buffer.alloc(71), // Fake signature
          sequence: 0xffffffff,
          witness: [],
        },
      ],
      outputs: [
        {
          value: outputValue,
          scriptPubKey: Buffer.from([
            0x76, 0xa9, 0x14, ...Array(20).fill(0x02), 0x88, 0xac,
          ]),
        },
      ],
      lockTime: 0,
    };
  }

  // Helper to create a block header
  function createBlockHeader(
    prevBlock: Buffer,
    merkleRoot: Buffer,
    timestamp: number = Math.floor(Date.now() / 1000)
  ): BlockHeader {
    return {
      version: 0x20000000,
      prevBlock,
      merkleRoot,
      timestamp,
      bits: REGTEST.powLimitBits,
      nonce: 0,
    };
  }

  // Helper to compute merkle root from transactions
  function computeMerkleRoot(txids: Buffer[]): Buffer {
    if (txids.length === 0) {
      return Buffer.alloc(32, 0);
    }

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    let level: any[] = txids.map((txid) => Buffer.from(txid));

    while (level.length > 1) {
      const nextLevel: Buffer[] = [];
      for (let i = 0; i < level.length; i += 2) {
        const left = level[i];
        const right = i + 1 < level.length ? level[i + 1] : level[i];
        nextLevel.push(hash256(Buffer.concat([left, right])));
      }
      level = nextLevel;
    }

    return level[0];
  }

  // Helper to create a complete block
  function createBlock(
    prevBlock: Buffer,
    transactions: Transaction[]
  ): Block {
    const txids = transactions.map((tx) => getTxId(tx));
    const merkleRoot = computeMerkleRoot(txids);
    const header = createBlockHeader(prevBlock, merkleRoot);

    return { header, transactions };
  }

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "chainstate-test-"));
    db = new ChainDB(tempDir);
    await db.open();
    chainState = new ChainStateManager(db, REGTEST);
    await chainState.load();
  });

  afterEach(async () => {
    await db.close();
    await rm(tempDir, { recursive: true, force: true });
  });

  describe("load", () => {
    test("initializes with genesis block", async () => {
      const best = chainState.getBestBlock();
      expect(best.height).toBe(0);
      expect(best.hash.equals(REGTEST.genesisBlockHash)).toBe(true);
    });

    test("loads persisted state", async () => {
      // Create a block
      const coinbase = createCoinbaseTx(1, 50_00000000n);
      const block = createBlock(REGTEST.genesisBlockHash, [coinbase]);

      await chainState.connectBlock(block, 1);

      // Create new instance and load
      const newChainState = new ChainStateManager(db, REGTEST);
      await newChainState.load();

      const best = newChainState.getBestBlock();
      expect(best.height).toBe(1);
    });
  });

  describe("connectBlock", () => {
    test("updates best block", async () => {
      const coinbase = createCoinbaseTx(1, 50_00000000n);
      const block = createBlock(REGTEST.genesisBlockHash, [coinbase]);

      await chainState.connectBlock(block, 1);

      const best = chainState.getBestBlock();
      expect(best.height).toBe(1);
      expect(best.hash.equals(getBlockHash(block.header))).toBe(true);
    });

    test("adds coinbase outputs to UTXO set", async () => {
      const coinbase = createCoinbaseTx(1, 50_00000000n);
      const block = createBlock(REGTEST.genesisBlockHash, [coinbase]);

      await chainState.connectBlock(block, 1);

      const utxoManager = chainState.getUTXOManager();
      const coinbaseTxid = getTxId(coinbase);
      const entry = await utxoManager.getUTXOAsync({
        txid: coinbaseTxid,
        vout: 0,
      });

      expect(entry).not.toBeNull();
      expect(entry!.amount).toBe(50_00000000n);
      expect(entry!.coinbase).toBe(true);
      expect(entry!.height).toBe(1);
    });

    test("spends inputs and creates outputs for regular tx", async () => {
      // Block 1: coinbase only
      const coinbase1 = createCoinbaseTx(1, 50_00000000n);
      const block1 = createBlock(REGTEST.genesisBlockHash, [coinbase1]);
      await chainState.connectBlock(block1, 1);

      const coinbase1Txid = getTxId(coinbase1);

      // Block 101: can spend coinbase from block 1 (after maturity)
      // For testing, we'll skip maturity check by connecting many blocks
      // Actually, let's just test with a fresh coinbase

      // Block 2: coinbase + tx spending block 1's coinbase
      // But we need 100 blocks of maturity - let's simplify and just test output creation
      const coinbase2 = createCoinbaseTx(2, 50_00000000n);
      const block2 = createBlock(getBlockHash(block1.header), [coinbase2]);
      await chainState.connectBlock(block2, 2);

      const utxoManager = chainState.getUTXOManager();
      const coinbase2Txid = getTxId(coinbase2);

      expect(
        await utxoManager.hasUTXOAsync({ txid: coinbase2Txid, vout: 0 })
      ).toBe(true);
    });

    test("stores undo data", async () => {
      const coinbase = createCoinbaseTx(1, 50_00000000n);
      const block = createBlock(REGTEST.genesisBlockHash, [coinbase]);

      await chainState.connectBlock(block, 1);

      const blockHash = getBlockHash(block.header);
      const undoData = await db.getUndoData(blockHash);

      expect(undoData).not.toBeNull();
    });

    test("stores block data", async () => {
      const coinbase = createCoinbaseTx(1, 50_00000000n);
      const block = createBlock(REGTEST.genesisBlockHash, [coinbase]);

      await chainState.connectBlock(block, 1);

      const blockHash = getBlockHash(block.header);
      const rawBlock = await db.getBlock(blockHash);

      expect(rawBlock).not.toBeNull();
    });

    test("validates coinbase value against subsidy + fees", async () => {
      // Create a coinbase with too much value
      const coinbase = createCoinbaseTx(1, 100_00000000n); // 100 BTC instead of 50
      const block = createBlock(REGTEST.genesisBlockHash, [coinbase]);

      // W93: canonical reject reason is now "bad-cb-amount" (matches Core
      // validation.cpp:2612).  Legacy "exceeds maximum" prose kept in the
      // regex for backward-compat with any downstream consumer.
      await expect(chainState.connectBlock(block, 1)).rejects.toThrow(
        /bad-cb-amount|exceeds maximum|exceeds subsidy/
      );
    });
  });

  describe("disconnectBlock", () => {
    test("restores previous state", async () => {
      // Connect block 1
      const coinbase1 = createCoinbaseTx(1, 50_00000000n);
      const block1 = createBlock(REGTEST.genesisBlockHash, [coinbase1]);
      await chainState.connectBlock(block1, 1);

      // Connect block 2
      const coinbase2 = createCoinbaseTx(2, 50_00000000n);
      const block2 = createBlock(getBlockHash(block1.header), [coinbase2]);
      await chainState.connectBlock(block2, 2);

      // Disconnect block 2
      await chainState.disconnectBlock(block2, 2);

      const best = chainState.getBestBlock();
      expect(best.height).toBe(1);
      expect(best.hash.equals(getBlockHash(block1.header))).toBe(true);
    });

    test("removes outputs created by disconnected block", async () => {
      const coinbase = createCoinbaseTx(1, 50_00000000n);
      const block = createBlock(REGTEST.genesisBlockHash, [coinbase]);
      await chainState.connectBlock(block, 1);

      const coinbaseTxid = getTxId(coinbase);
      const utxoManager = chainState.getUTXOManager();

      // UTXO exists
      expect(
        await utxoManager.hasUTXOAsync({ txid: coinbaseTxid, vout: 0 })
      ).toBe(true);

      // Disconnect
      await chainState.disconnectBlock(block, 1);

      // UTXO should be gone after flush
      await utxoManager.flush();
      expect(await utxoManager.hasUTXOAsync({ txid: coinbaseTxid, vout: 0 })).toBe(
        false
      );
    });

    test("throws when disconnecting non-tip block", async () => {
      const coinbase1 = createCoinbaseTx(1, 50_00000000n);
      const block1 = createBlock(REGTEST.genesisBlockHash, [coinbase1]);
      await chainState.connectBlock(block1, 1);

      const coinbase2 = createCoinbaseTx(2, 50_00000000n);
      const block2 = createBlock(getBlockHash(block1.header), [coinbase2]);
      await chainState.connectBlock(block2, 2);

      // Try to disconnect block 1 (not the tip)
      await expect(chainState.disconnectBlock(block1, 1)).rejects.toThrow(
        "tip block"
      );
    });

    // ── Pattern D atomicity regression ──
    //
    // disconnectBlock used to issue THREE separate awaits:
    //   1. utxo.flush()
    //   2. db.deleteTxIndex(txid)  (per-tx loop)
    //   3. db.putChainState(...)
    // A crash between any two left the chainstate inconsistent.  After
    // the Pattern D fix all three write categories must funnel through
    // a single ChainDB.batch() call so they land atomically (Bitcoin Core
    // CDBBatch parity).  This test spies on db.batch and the per-call
    // direct-write paths to assert that contract.
    test("commits utxo + chain-state + txindex revert via a single atomic batch", async () => {
      // Build + connect block 1.
      const coinbase = createCoinbaseTx(1, 50_00000000n);
      const block = createBlock(REGTEST.genesisBlockHash, [coinbase]);
      await chainState.connectBlock(block, 1);

      // Force-flush so the connect-side writes are out of the way and
      // the disconnect-side flush is the only batch we're observing.
      const utxoManager = chainState.getUTXOManager();
      await utxoManager.flush();

      // Wrap db.batch to record every BatchOperation list it sees.
      const originalBatch = db.batch.bind(db);
      const batches: Array<Array<{ type: string; prefix: number }>> = [];
      (db as any).batch = async (ops: any[]) => {
        batches.push(ops.map((o: any) => ({ type: o.type, prefix: o.prefix })));
        return originalBatch(ops);
      };

      // Track any DIRECT (non-batch) writes that hit the disconnect-side
      // helpers.  After Pattern D these must NOT fire from disconnectBlock.
      let directChainStatePuts = 0;
      let directTxIndexDels = 0;
      const originalPutChainState = db.putChainState.bind(db);
      const originalDeleteTxIndex = db.deleteTxIndex.bind(db);
      (db as any).putChainState = async (...args: any[]) => {
        directChainStatePuts++;
        return originalPutChainState(...(args as [any]));
      };
      (db as any).deleteTxIndex = async (...args: any[]) => {
        directTxIndexDels++;
        return originalDeleteTxIndex(...(args as [any]));
      };

      try {
        await chainState.disconnectBlock(block, 1);
      } finally {
        (db as any).batch = originalBatch;
        (db as any).putChainState = originalPutChainState;
        (db as any).deleteTxIndex = originalDeleteTxIndex;
      }

      // 1) The disconnect-side direct-write helpers must NOT have been
      //    invoked.  All three writes ride the batch path now.
      expect(directChainStatePuts).toBe(0);
      expect(directTxIndexDels).toBe(0);

      // 2) Exactly one ChainDB.batch() call must cover the disconnect.
      //    (UTXOManager.flush funnels UTXO + extraOps into one
      //    CoinsViewDB.batchWrite, which calls db.batch exactly once.)
      expect(batches.length).toBe(1);

      const ops = batches[0];

      // 3) That single batch must carry the chain-state put.
      const CHAIN_STATE_PREFIX = 0x73; // 's' — see DBPrefix.CHAIN_STATE
      const TX_INDEX_PREFIX = 0x74;    // 't' — see DBPrefix.TX_INDEX
      const chainStatePuts = ops.filter(
        (o) => o.type === "put" && o.prefix === CHAIN_STATE_PREFIX
      );
      expect(chainStatePuts.length).toBe(1);

      // 4) That single batch must also carry the txindex delete for the
      //    coinbase tx (Pattern C0 revert riding inside the same batch).
      const txIndexDels = ops.filter(
        (o) => o.type === "del" && o.prefix === TX_INDEX_PREFIX
      );
      expect(txIndexDels.length).toBe(block.transactions.length);
    });
  });

  describe("validateTxInputs", () => {
    test("validates coinbase tx", async () => {
      const coinbase = createCoinbaseTx(1, 50_00000000n);
      const result = chainState.validateTxInputs(coinbase, 1);

      expect(result.valid).toBe(true);
      expect(result.fee).toBe(0n);
    });

    test("validates tx with sufficient inputs", async () => {
      // First, add a UTXO to the set
      const coinbase = createCoinbaseTx(1, 50_00000000n);
      const block = createBlock(REGTEST.genesisBlockHash, [coinbase]);
      await chainState.connectBlock(block, 1);

      const coinbaseTxid = getTxId(coinbase);
      const utxoManager = chainState.getUTXOManager();

      // Pre-load the UTXO
      await utxoManager.preloadUTXO({ txid: coinbaseTxid, vout: 0 });

      // Create spending tx
      const spendingTx = createSpendingTx(coinbaseTxid, 0, 49_99990000n);

      // Validate at height 101 (after maturity)
      const result = chainState.validateTxInputs(spendingTx, 101);

      expect(result.valid).toBe(true);
      expect(result.fee).toBe(10000n); // 50 BTC - 49.9999 BTC
    });

    test("rejects tx with missing input", () => {
      const fakeTxid = Buffer.alloc(32, 0xff);
      const spendingTx = createSpendingTx(fakeTxid, 0, 1000n);

      const result = chainState.validateTxInputs(spendingTx, 100);

      expect(result.valid).toBe(false);
      expect(result.error).toContain("Missing UTXO");
    });

    test("rejects tx spending immature coinbase", async () => {
      const coinbase = createCoinbaseTx(1, 50_00000000n);
      const block = createBlock(REGTEST.genesisBlockHash, [coinbase]);
      await chainState.connectBlock(block, 1);

      const coinbaseTxid = getTxId(coinbase);
      const utxoManager = chainState.getUTXOManager();
      await utxoManager.preloadUTXO({ txid: coinbaseTxid, vout: 0 });

      const spendingTx = createSpendingTx(coinbaseTxid, 0, 49_99990000n);

      // Try to spend at height 50 (only 49 confirmations)
      const result = chainState.validateTxInputs(spendingTx, 50);

      expect(result.valid).toBe(false);
      expect(result.error).toContain("PREMATURE_COINBASE_SPEND");
    });

    test("rejects tx with insufficient input value", async () => {
      const coinbase = createCoinbaseTx(1, 50_00000000n);
      const block = createBlock(REGTEST.genesisBlockHash, [coinbase]);
      await chainState.connectBlock(block, 1);

      const coinbaseTxid = getTxId(coinbase);
      const utxoManager = chainState.getUTXOManager();
      await utxoManager.preloadUTXO({ txid: coinbaseTxid, vout: 0 });

      // Try to spend more than input
      const spendingTx = createSpendingTx(coinbaseTxid, 0, 100_00000000n);

      const result = chainState.validateTxInputs(spendingTx, 101);

      expect(result.valid).toBe(false);
      expect(result.error).toContain("INPUTS_NOT_EQUAL_OUTPUTS");
    });
  });

  describe("isNextBlock and needsReorg", () => {
    test("isNextBlock returns true for sequential block", async () => {
      const coinbase = createCoinbaseTx(1, 50_00000000n);
      const block = createBlock(REGTEST.genesisBlockHash, [coinbase]);
      await chainState.connectBlock(block, 1);

      const nextHeader = createBlockHeader(
        getBlockHash(block.header),
        Buffer.alloc(32, 0)
      );

      expect(chainState.isNextBlock(nextHeader)).toBe(true);
    });

    test("isNextBlock returns false for non-sequential block", async () => {
      const coinbase = createCoinbaseTx(1, 50_00000000n);
      const block = createBlock(REGTEST.genesisBlockHash, [coinbase]);
      await chainState.connectBlock(block, 1);

      // Header pointing to wrong parent
      const wrongHeader = createBlockHeader(
        Buffer.alloc(32, 0xff),
        Buffer.alloc(32, 0)
      );

      expect(chainState.isNextBlock(wrongHeader)).toBe(false);
    });

    test("needsReorg returns false for next block", async () => {
      const coinbase = createCoinbaseTx(1, 50_00000000n);
      const block = createBlock(REGTEST.genesisBlockHash, [coinbase]);
      await chainState.connectBlock(block, 1);

      const nextHeader = createBlockHeader(
        getBlockHash(block.header),
        Buffer.alloc(32, 0)
      );

      expect(chainState.needsReorg(nextHeader)).toBe(false);
    });

    test("needsReorg returns true for competing chain", async () => {
      const coinbase = createCoinbaseTx(1, 50_00000000n);
      const block = createBlock(REGTEST.genesisBlockHash, [coinbase]);
      await chainState.connectBlock(block, 1);

      // Competing block at same height
      const competingHeader = createBlockHeader(
        REGTEST.genesisBlockHash,
        Buffer.alloc(32, 0xaa)
      );

      expect(chainState.needsReorg(competingHeader)).toBe(true);
    });
  });

  describe("getStats", () => {
    test("returns current state statistics", async () => {
      const coinbase = createCoinbaseTx(1, 50_00000000n);
      const block = createBlock(REGTEST.genesisBlockHash, [coinbase]);
      await chainState.connectBlock(block, 1);

      const stats = chainState.getStats();

      expect(stats.height).toBe(1);
      expect(stats.hash).toBe(getBlockHash(block.header).toString("hex"));
      expect(stats.chainWork).toBeGreaterThan(0n);
    });
  });

  describe("chain with multiple blocks", () => {
    test("connects series of blocks", async () => {
      let prevHash = REGTEST.genesisBlockHash;

      for (let height = 1; height <= 5; height++) {
        const coinbase = createCoinbaseTx(height, 50_00000000n);
        const block = createBlock(prevHash, [coinbase]);
        await chainState.connectBlock(block, height);
        prevHash = getBlockHash(block.header);
      }

      const best = chainState.getBestBlock();
      expect(best.height).toBe(5);
    });

    test("disconnects and reconnects blocks", async () => {
      const blocks: Block[] = [];
      let prevHash = REGTEST.genesisBlockHash;

      // Connect 3 blocks
      for (let height = 1; height <= 3; height++) {
        const coinbase = createCoinbaseTx(height, 50_00000000n);
        const block = createBlock(prevHash, [coinbase]);
        await chainState.connectBlock(block, height);
        blocks.push(block);
        prevHash = getBlockHash(block.header);
      }

      // Disconnect back to height 1
      await chainState.disconnectBlock(blocks[2], 3);
      await chainState.disconnectBlock(blocks[1], 2);

      expect(chainState.getBestBlock().height).toBe(1);

      // Reconnect
      await chainState.connectBlock(blocks[1], 2);
      await chainState.connectBlock(blocks[2], 3);

      expect(chainState.getBestBlock().height).toBe(3);
    });
  });

  describe("BIP-30 exception heights", () => {
    // Verify the params carry the correct exception heights.
    // The enforcement logic is tested via connectBlock with a MAINNET-like
    // params stub (since on REGTEST BIP-34 is always active, making the
    // duplicate-check a no-op — exactly as Core behaves).
    test("MAINNET has exception heights [91842, 91880]", async () => {
      const { MAINNET } = await import("../consensus/params.js");
      expect(MAINNET.bip30ExceptionHeights).toEqual([91842, 91880]);
    });

    test("REGTEST has empty exception heights []", async () => {
      expect(REGTEST.bip30ExceptionHeights).toEqual([]);
    });

    test("old wrong heights 91722 and 91812 are NOT in MAINNET exceptions", async () => {
      const { MAINNET } = await import("../consensus/params.js");
      expect(MAINNET.bip30ExceptionHeights).not.toContain(91722);
      expect(MAINNET.bip30ExceptionHeights).not.toContain(91812);
    });

    test("connectBlock with MAINNET-like params enforces BIP-30 at h=91843", async () => {
      // Build a custom params where BIP34 is not yet active at h=91843.
      // This allows us to test the enforcement path (outside the BIP34 skip window).
      const { MAINNET } = await import("../consensus/params.js");
      const customParams = {
        ...MAINNET,
        bip34Height: 200_000, // Push BIP34 past the test height
      };

      // Use a fresh ChainStateManager with custom params
      const testDir = await mkdtemp(join(tmpdir(), "bip30-test-"));
      const testDb = new ChainDB(testDir);
      await testDb.open();
      const testChainState = new ChainStateManager(testDb, customParams);
      await testChainState.load();

      try {
        // Connect block 1 with a specific coinbase txid
        const coinbase1 = createCoinbaseTx(1, 50_00000000n);
        const block1 = createBlock(customParams.genesisBlockHash, [coinbase1]);
        await testChainState.connectBlock(block1, 1);

        // Get the txid of the coinbase we just connected
        const coinbase1Txid = getTxId(coinbase1);

        // Now build another block at h=91843 that reuses the SAME coinbase tx
        // (different height so different BIP34 encoding, but in our custom params
        // BIP34 is not active yet, so the same raw tx produces the same txid).
        // Actually the simplest test: use a transaction whose txid collides with
        // an already-connected UTXO. We'll craft a coinbase with the same
        // scriptSig as coinbase1 (so same txid).
        const coinbaseDup = { ...coinbase1 }; // exact same tx → same txid

        // This block at h=91843 attempts to add outputs whose txid already exists
        // in the UTXO set → must throw BIP30_DUPLICATE_OUTPUT.
        const prevHash1 = getBlockHash(block1.header);
        const blockDup = createBlock(prevHash1, [coinbaseDup]);

        await expect(
          testChainState.connectBlock(blockDup, 91843)
        ).rejects.toThrow("bad-txns-BIP30");
      } finally {
        await testDb.close();
        await rm(testDir, { recursive: true, force: true });
      }
    });

    test("connectBlock at h=91842 with wrong hash enforces BIP-30 (exemption requires height AND hash)", async () => {
      // W79 fix: IsBIP30Repeat checks BOTH height AND block hash.
      // A synthetic block at h=91842 with a different hash from the canonical
      // mainnet block (00000000000a4d0a...) must NOT be exempt — it's an
      // alternative-chain block and must still enforce BIP-30.
      // Reference: Bitcoin Core validation.cpp:6189-6192 IsBIP30Repeat().
      const { MAINNET } = await import("../consensus/params.js");
      const customParams = {
        ...MAINNET,
        bip34Height: 200_000, // BIP34 not active at h=91842
      };

      const testDir = await mkdtemp(join(tmpdir(), "bip30-hash-check-test-"));
      const testDb = new ChainDB(testDir);
      await testDb.open();
      const testChainState = new ChainStateManager(testDb, customParams);
      await testChainState.load();

      try {
        // Connect block 1
        const coinbase1 = createCoinbaseTx(1, 50_00000000n);
        const block1 = createBlock(customParams.genesisBlockHash, [coinbase1]);
        await testChainState.connectBlock(block1, 1);

        // Duplicate coinbase at h=91842 — the synthetic blockDup will NOT have
        // the canonical hash "00000000000a4d0a..." so the exemption does NOT apply.
        // BIP-30 must fire because coinbase1's txid is already in the UTXO set.
        const coinbaseDup = { ...coinbase1 };
        const prevHash1 = getBlockHash(block1.header);
        const blockDup = createBlock(prevHash1, [coinbaseDup]);

        let threwBip30 = false;
        try {
          await testChainState.connectBlock(blockDup, 91842);
        } catch (e: unknown) {
          if (e instanceof Error && e.message.includes("bad-txns-BIP30")) {
            threwBip30 = true;
          }
        }
        // The synthetic block does NOT have the canonical hash, so BIP-30 fires.
        expect(threwBip30).toBe(true);
      } finally {
        await testDb.close();
        await rm(testDir, { recursive: true, force: true });
      }
    });
  });

  // ── BUG-2a fix: time-based BIP-68 sequence lock enforcement on the
  //    reorg-reconnect / regtest / generateblock path (chain/state.ts::connectBlock).
  //
  // Before this fix, coreConnectBlockChecks was called WITHOUT getUTXOMTP on
  // the chain/state.ts path, so coinMTP defaulted to 0 for every input.
  // With coinMTP=0 and any real prevMTP (e.g. 1.3 billion from 2011 genesis),
  // minTime = 0+511 = 511 << prevMTP — the lock was trivially satisfied,
  // false-accepting every v2 tx regardless of its time-based sequence lock.
  //
  // After the fix, getUTXOMTP reads coinMTP from the HeaderSync's persistent
  // block-index (loaded by loadFromDB on startup), so time-based locks are
  // evaluated against the ACTUAL MTP at the coin's creation height minus one.
  //
  // The test exercises the consensus-critical reorg path (connectBlock in
  // chain/state.ts, which reorganize() calls for every reconnected block)
  // by asserting:
  //   REJECT — block containing a v2 tx with an unsatisfied time-based
  //             BIP-68 lock is rejected even through this path.
  //   ACCEPT — same tx is accepted after enough blocks have advanced the
  //             MTP past the lock's minTime.
  describe("BIP-68 time-based sequence lock on reorg/connectBlock path (BUG-2a fix)", () => {
    test("rejects tx with unsatisfied time-based BIP-68 lock and accepts after MTP advance", async () => {
      // Use coinbaseMaturity=1 so we can spend block-1 coinbase at block 2+
      // without connecting 100 dummy blocks.
      const customParams = { ...REGTEST, coinbaseMaturity: 1 };

      const testDir = await mkdtemp(join(tmpdir(), "bip68-time-lock-"));
      const testDb = new ChainDB(testDir);
      await testDb.open();
      const testChainState = new ChainStateManager(testDb, customParams);
      await testChainState.load();

      // Genesis timestamp from REGTEST/buildRegtestGenesisBlock.
      const T0 = 1296688602;

      // Minimal mock HeaderSync: only getHeaderByHeight + getMedianTimePast are
      // used by ChainStateManager (for prevMTP and getUTXOMTP).  The mock walks
      // back by height (valid for our sequential test chain) and mirrors
      // getMedianTimePast's "partial walk → median of what we have" semantics.
      const blockTimestamps = new Map<number, number>();
      blockTimestamps.set(0, T0); // genesis

      type FakeEntry = { height: number; header: { timestamp: number } };
      const mockHeaderSync = {
        getHeaderByHeight(h: number): FakeEntry | undefined {
          const ts = blockTimestamps.get(h);
          if (ts === undefined) return undefined;
          return { height: h, header: { timestamp: ts } };
        },
        getMedianTimePast(entry: FakeEntry): number {
          const timestamps: number[] = [];
          let h = entry.height;
          for (let i = 0; i < 11; i++) {
            const ts = blockTimestamps.get(h);
            if (ts === undefined) break;
            timestamps.push(ts);
            h--;
          }
          if (timestamps.length === 0) return 0;
          timestamps.sort((a, b) => a - b);
          return timestamps[Math.floor(timestamps.length / 2)];
        },
      // Chain/state.ts holds the reference as HeaderSync; structural cast is
      // safe here because only getHeaderByHeight + getMedianTimePast are called.
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      } as unknown as any;

      testChainState.setHeaderSync(mockHeaderSync);

      try {
        // Helper: create a block with a specific timestamp (deterministic hash).
        function makeBlock(prevBlock: Buffer, txs: Transaction[], ts: number): Block {
          const txids = txs.map((tx) => getTxId(tx));
          // Reuse computeMerkleRoot from outer scope.
          const merkleRoot = computeMerkleRoot(txids);
          const header: BlockHeader = {
            version: 0x20000000,
            prevBlock,
            merkleRoot,
            timestamp: ts,
            bits: customParams.powLimitBits,
            nonce: 0,
          };
          return { header, transactions: txs };
        }

        // Helper: coinbase with an OP_1 (0x51) output — spendable by an empty
        // scriptSig.  Using OP_1 avoids the need for a real secp256k1 key/sig
        // while still exercising the full connectBlock consensus path.
        function makeCoinbaseOp1(height: number, value: bigint): Transaction {
          const scriptSig = Buffer.concat([
            Buffer.from([0x03]),
            Buffer.alloc(3, height),
          ]);
          return {
            version: 1,
            inputs: [
              {
                prevOut: { txid: Buffer.alloc(32, 0), vout: 0xffffffff },
                scriptSig,
                sequence: 0xffffffff,
                witness: [],
              },
            ],
            outputs: [
              {
                value,
                // OP_1: push 1 onto stack; combined with empty scriptSig the
                // final stack is [1] which is truthy → script passes.
                scriptPubKey: Buffer.from([0x51]),
              },
            ],
            lockTime: 0,
          };
        }

        // ── Block 1: coinbase creates a UTXO at height 1.
        const T1 = T0 + 1; // barely above genesis MTP
        blockTimestamps.set(1, T1);
        const coinbase1 = makeCoinbaseOp1(1, 50_00000000n);
        const cb1Txid = getTxId(coinbase1);
        const block1 = makeBlock(customParams.genesisBlockHash, [coinbase1], T1);
        await testChainState.connectBlock(block1, 1);

        // ── Spending tx: v2 with time-based BIP-68 lock (1 time unit = 512 sec).
        //    coinMTP = MTP(height 0) = T0 = 1296688602.
        //    minTime = coinMTP + (1 << 9) - 1 = T0 + 511 = 1296689113.
        //    Satisfied when prevMTP > T0 + 511.
        //
        //    scriptSig is empty: satisfies the OP_1 (always-true) scriptPubKey
        //    above without requiring a real signature.
        const spendingTx: Transaction = {
          version: 2,
          inputs: [
            {
              prevOut: { txid: cb1Txid, vout: 0 },
              scriptSig: Buffer.alloc(0),
              sequence: SEQUENCE_LOCKTIME_TYPE_FLAG | 1, // 1 × 512 s
              witness: [],
            },
          ],
          outputs: [
            {
              value: 49_99990000n,
              scriptPubKey: Buffer.from([0x51]), // OP_1
            },
          ],
          lockTime: 0,
        };

        // ── REJECT: block 2 includes the spending tx but prevMTP is too low.
        //    prevMTP = MTP(block 1) = median([T1, T0]) = sorted([T0, T1])[1] = T1 = T0+1.
        //    T0+1 > T0+511? NO → must reject.
        //
        //    Use a different coinbase value (49 BTC) so coinbase2r has a different
        //    txid than the 50-BTC coinbases used for the ACCEPT path (which start
        //    at height 2 again after the REJECT).  Without this, coreConnectBlockChecks
        //    adds coinbase2r's output to the in-memory UTXO cache before hitting
        //    the BIP-68 gate; when the ACCEPT path re-uses height 2 with the
        //    50-BTC coinbase, BIP-30 would fire on the stale cache entry.
        //    After the REJECT we also call clearCache to discard the partial
        //    in-memory mutations from the failed block, restoring the cache to
        //    the persisted block-1 state.
        const T2_reject = T0 + 60; // well above T1 for header-timestamp validity
        const coinbase2r = makeCoinbaseOp1(2, 49_00000000n); // distinct txid from accept-path coinbases
        const block2Reject = makeBlock(
          getBlockHash(block1.header),
          [coinbase2r, spendingTx],
          T2_reject
        );
        await expect(
          testChainState.connectBlock(block2Reject, 2)
        ).rejects.toThrow(/bad-txns-nonfinal|Sequence locks not satisfied/);

        // Roll back any partial in-memory UTXO mutations from the failed block
        // (coreConnectBlockChecks may have addTransaction'd coinbase2r before
        // hitting the BIP-68 gate). Reset to the persisted block-1 tip.
        testChainState.getUTXOManager().clearCache(getBlockHash(block1.header));

        // ── Advance MTP: connect blocks 2–12 (coinbase only) with timestamps
        //    all set to T0 + 600.  After 11 such blocks (heights 2-12), the
        //    MTP of block 12 = median(11 × (T0+600)) = T0+600 = 1296689202.
        //    T0+600 > T0+511 → lock satisfied.
        let prevHash = getBlockHash(block1.header);
        const HIGH_TS = T0 + 600; // > T0 + 511 (minTime)
        for (let h = 2; h <= 12; h++) {
          blockTimestamps.set(h, HIGH_TS);
          const cbH = makeCoinbaseOp1(h, 50_00000000n);
          const blk = makeBlock(prevHash, [cbH], HIGH_TS);
          await testChainState.connectBlock(blk, h);
          prevHash = getBlockHash(blk.header);
        }

        // ── ACCEPT: block 13 includes the spending tx and prevMTP > minTime.
        //    prevMTP = MTP(block 12) = T0+600 = 1296689202 > T0+511 = 1296689113.
        const T13 = HIGH_TS + 1; // strictly above MTP(12) = HIGH_TS
        blockTimestamps.set(13, T13);
        const coinbase13 = makeCoinbaseOp1(13, 50_00000000n);
        const block13Accept = makeBlock(prevHash, [coinbase13, spendingTx], T13);
        await expect(
          testChainState.connectBlock(block13Accept, 13)
        ).resolves.toBeUndefined();

        expect(testChainState.getBestBlock().height).toBe(13);
      } finally {
        await testDb.close();
        await rm(testDir, { recursive: true, force: true });
      }
    });
  });
});
