/**
 * End-to-end tests for the full node in regtest mode.
 *
 * Tests the complete system:
 * 1. Start the full node in regtest mode (in-process)
 * 2. Start the RPC server
 * 3. Make RPC calls to interact with the node
 * 4. Mine blocks and submit transactions
 * 5. Verify state via RPC
 * 6. Shutdown cleanly
 */

import { describe, test, expect, beforeAll, afterAll } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ChainDB, type BlockIndexRecord } from "../storage/database.js";
import { REGTEST, getBlockSubsidy } from "../consensus/params.js";
import { ChainStateManager } from "../chain/state.js";
import { Mempool } from "../mempool/mempool.js";
import { FeeEstimator } from "../fees/estimator.js";
import { Wallet } from "../wallet/wallet.js";
import { RPCServer, type RPCServerConfig, type RPCServerDeps } from "../rpc/server.js";
import { serializeBlock, getBlockHash, computeMerkleRoot, serializeBlockHeader, deserializeBlock } from "../validation/block.js";
import { BufferReader } from "../wire/serialization.js";
import { getTxId, serializeTx } from "../validation/tx.js";
import type { Block, BlockHeader } from "../validation/block.js";
import type { Transaction } from "../validation/tx.js";
import {
  createTestBlock,
  createCoinbaseTx,
  mineRegtestBlock,
  generateTestKeyPair,
  p2wpkhScript,
} from "./helpers.js";

// Mock PeerManager for testing (no actual networking)
class MockPeerManager {
  getConnectedPeers() {
    return [];
  }
  broadcast(_msg: unknown) {
    // No-op in tests
  }
}

// Mock HeaderSync for testing
class MockHeaderSync {
  private bestHeader: { height: number; hash: Buffer; chainWork: bigint } | null = null;

  constructor(genesisHash: Buffer) {
    this.bestHeader = {
      height: 0,
      hash: genesisHash,
      chainWork: 1n,
    };
  }

  getBestHeader() {
    return this.bestHeader;
  }

  getHeader(hash: Buffer) {
    return {
      hash,
      height: 0,
      chainWork: 1n,
    };
  }

  getMedianTimePast(_entry: unknown) {
    return Math.floor(Date.now() / 1000);
  }

  updateTip(height: number, hash: Buffer, chainWork: bigint) {
    this.bestHeader = { height, hash, chainWork };
  }
}

describe("e2e regtest", () => {
  let tempDir: string;
  let db: ChainDB;
  let chainState: ChainStateManager;
  let mempool: Mempool;
  let feeEstimator: FeeEstimator;
  let wallet: Wallet;
  let rpcServer: RPCServer;
  let rpcPort: number;
  let headerSync: MockHeaderSync;
  let peerManager: MockPeerManager;

  beforeAll(async () => {
    // Create temp directory for data
    tempDir = await mkdtemp(join(tmpdir(), "hotbuns-e2e-"));

    // Initialize database
    db = new ChainDB(tempDir);
    await db.open();

    // Initialize chain state
    chainState = new ChainStateManager(db, REGTEST);
    await chainState.load();

    // Initialize UTXO manager from chain state
    const utxoManager = chainState.getUTXOManager();

    // Initialize mempool
    mempool = new Mempool(utxoManager, REGTEST);
    mempool.setTipHeight(0);

    // Initialize fee estimator
    feeEstimator = new FeeEstimator(mempool);

    // Initialize wallet
    wallet = Wallet.create({ datadir: tempDir, network: "regtest" });

    // Store genesis block and its index
    const genesisBlock = REGTEST.genesisBlock;
    const genesisReader = new BufferReader(genesisBlock);
    const parsedGenesis = deserializeBlock(genesisReader);

    await db.putBlock(REGTEST.genesisBlockHash, genesisBlock);
    const genesisRecord: BlockIndexRecord = {
      height: 0,
      header: serializeBlockHeader(parsedGenesis.header),
      nTx: parsedGenesis.transactions.length,
      status: 7,
      dataPos: 1,
    };
    await db.putBlockIndex(REGTEST.genesisBlockHash, genesisRecord);

    // Initialize mock components
    headerSync = new MockHeaderSync(REGTEST.genesisBlockHash);
    peerManager = new MockPeerManager();

    // Pick a random high port for RPC
    rpcPort = 18400 + Math.floor(Math.random() * 1000);

    // Configure and start RPC server
    const rpcConfig: RPCServerConfig = {
      port: rpcPort,
      host: "127.0.0.1",
      noAuth: true,
      // No auth for tests
    };

    const rpcDeps: RPCServerDeps = {
      chainState,
      mempool,
      peerManager: peerManager as any,
      feeEstimator,
      headerSync: headerSync as any,
      db,
      params: REGTEST,
    };

    rpcServer = new RPCServer(rpcConfig, rpcDeps);
    rpcServer.start();
  });

  afterAll(async () => {
    // Stop RPC server
    rpcServer.stop();

    // Close database
    await db.close();

    // Cleanup temp directory
    await rm(tempDir, { recursive: true, force: true });
  });

  // Helper to make RPC calls
  async function rpcCall(method: string, params: unknown[] = []): Promise<unknown> {
    const response = await fetch(`http://127.0.0.1:${rpcPort}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method,
        params,
      }),
    });

    const data = await response.json() as { result?: unknown; error?: { code: number; message: string } };

    if (data.error) {
      throw new Error(`RPC error ${data.error.code}: ${data.error.message}`);
    }

    return data.result;
  }

  // Helper to mine blocks (in-process, not via RPC)
  async function mineBlocks(count: number): Promise<void> {
    for (let i = 0; i < count; i++) {
      const height = chainState.getBestBlock().height + 1;
      const prevHash = chainState.getBestBlock().hash;

      const block = createTestBlock(prevHash, height, [], REGTEST);
      const minedBlock = mineRegtestBlock(block);

      await chainState.connectBlock(minedBlock, height);
      mempool.setTipHeight(height);

      // Store block index record for height lookup
      const hash = getBlockHash(minedBlock.header);
      const record: BlockIndexRecord = {
        height,
        header: serializeBlockHeader(minedBlock.header),
        nTx: minedBlock.transactions.length,
        status: 7,
        dataPos: 1,
      };
      await db.putBlockIndex(hash, record);

      // Update mock header sync
      headerSync.updateTip(
        height,
        hash,
        chainState.getBestBlock().chainWork
      );
    }
  }

  describe("RPC server", () => {
    test("server responds to requests", async () => {
      const response = await fetch(`http://127.0.0.1:${rpcPort}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          method: "getblockchaininfo",
          params: [],
        }),
      });

      expect(response.status).toBe(200);
    });
  });

  describe("getblockchaininfo", () => {
    test("returns chain info", async () => {
      const info = await rpcCall("getblockchaininfo") as Record<string, unknown>;

      expect(info.chain).toBe("regtest");
      expect(typeof info.blocks).toBe("number");
      expect(typeof info.headers).toBe("number");
      expect(typeof info.bestblockhash).toBe("string");
      expect(typeof info.difficulty).toBe("number");
      expect(info.pruned).toBe(false);
    });

    test("updates after mining blocks", async () => {
      const beforeInfo = await rpcCall("getblockchaininfo") as Record<string, unknown>;
      const beforeBlocks = beforeInfo.blocks as number;

      await mineBlocks(5);

      const afterInfo = await rpcCall("getblockchaininfo") as Record<string, unknown>;
      const afterBlocks = afterInfo.blocks as number;

      expect(afterBlocks).toBe(beforeBlocks + 5);
    });
  });

  describe("getblockhash", () => {
    test("returns genesis block hash at height 0", async () => {
      const hash = await rpcCall("getblockhash", [0]) as string;
      expect(hash).toBe(Buffer.from(REGTEST.genesisBlockHash).reverse().toString("hex"));
    });

    test("returns block hash for mined block", async () => {
      // Mine a block if needed
      if (chainState.getBestBlock().height < 1) {
        await mineBlocks(1);
      }

      const currentHeight = chainState.getBestBlock().height;
      const hash = await rpcCall("getblockhash", [currentHeight]) as string;

      expect(hash).toBe(Buffer.from(chainState.getBestBlock().hash).reverse().toString("hex"));
    });

    test("rejects invalid height", async () => {
      const currentHeight = chainState.getBestBlock().height;

      await expect(
        rpcCall("getblockhash", [currentHeight + 1000])
      ).rejects.toThrow(/out of range/);
    });
  });

  describe("getmempoolinfo", () => {
    test("returns mempool statistics", async () => {
      const info = await rpcCall("getmempoolinfo") as Record<string, unknown>;

      expect(info.loaded).toBe(true);
      expect(typeof info.size).toBe("number");
      expect(typeof info.bytes).toBe("number");
      expect(typeof info.maxmempool).toBe("number");
    });
  });

  describe("getrawmempool", () => {
    test("returns empty array when mempool is empty", async () => {
      mempool.clear();
      const txids = await rpcCall("getrawmempool", [false]) as string[];
      expect(Array.isArray(txids)).toBe(true);
    });
  });

  describe("getnetworkinfo", () => {
    test("returns network information", async () => {
      const info = await rpcCall("getnetworkinfo") as Record<string, unknown>;

      expect(typeof info.version).toBe("number");
      expect(typeof info.subversion).toBe("string");
      expect(typeof info.protocolversion).toBe("number");
      expect(info.networkactive).toBe(true);
    });
  });

  describe("getpeerinfo", () => {
    test("returns empty array with no peers", async () => {
      const peers = await rpcCall("getpeerinfo") as unknown[];
      expect(Array.isArray(peers)).toBe(true);
      expect(peers.length).toBe(0); // Mock peer manager has no peers
    });
  });

  describe("estimatesmartfee", () => {
    test("returns fee estimate", async () => {
      const estimate = await rpcCall("estimatesmartfee", [6]) as Record<string, unknown>;

      expect(typeof estimate.feerate).toBe("number");
      expect(typeof estimate.blocks).toBe("number");
      expect(estimate.blocks).toBeGreaterThan(0);
    });
  });

  describe("wallet operations", () => {
    test("wallet generates new address", () => {
      const address = wallet.getNewAddress();
      expect(address).toMatch(/^bcrt1/);
    });

    test("wallet tracks balance", () => {
      const balance = wallet.getBalance();
      expect(typeof balance.confirmed).toBe("bigint");
      expect(typeof balance.unconfirmed).toBe("bigint");
      expect(typeof balance.total).toBe("bigint");
    });
  });

  describe("mining and confirmation workflow", () => {
    test("mine blocks and verify chain state", async () => {
      const beforeHeight = chainState.getBestBlock().height;

      // Mine 10 blocks
      await mineBlocks(10);

      const afterHeight = chainState.getBestBlock().height;
      expect(afterHeight).toBe(beforeHeight + 10);

      // Verify via RPC
      const info = await rpcCall("getblockchaininfo") as Record<string, unknown>;
      expect(info.blocks).toBe(afterHeight);
    });

    test("mine past coinbase maturity", async () => {
      // Ensure we have at least 101 blocks for coinbase maturity
      const currentHeight = chainState.getBestBlock().height;
      if (currentHeight < 101) {
        await mineBlocks(101 - currentHeight);
      }

      expect(chainState.getBestBlock().height).toBeGreaterThanOrEqual(101);
    });
  });

  describe("transaction workflow", () => {
    test("create and verify transaction serialization", () => {
      const keyPair = generateTestKeyPair();

      const tx: Transaction = {
        version: 2,
        inputs: [
          {
            prevOut: {
              txid: Buffer.alloc(32, 0xab),
              vout: 0,
            },
            scriptSig: Buffer.alloc(0),
            sequence: 0xffffffff,
            witness: [Buffer.alloc(71), keyPair.publicKey],
          },
        ],
        outputs: [
          {
            value: 100000000n,
            scriptPubKey: p2wpkhScript(keyPair.pubKeyHash),
          },
        ],
        lockTime: 0,
      };

      const serialized = serializeTx(tx, true);
      expect(serialized.length).toBeGreaterThan(0);

      const txid = getTxId(tx);
      expect(txid.length).toBe(32);
    });
  });

  describe("block data retrieval", () => {
    test("getblock returns block data", async () => {
      // Get genesis block
      const genesisHash = REGTEST.genesisBlockHash.toString("hex");
      const block = await rpcCall("getblock", [genesisHash, 1]) as Record<string, unknown>;

      expect(block.hash).toBe(genesisHash);
      expect(block.height).toBe(0);
      expect(typeof block.version).toBe("number");
      expect(typeof block.merkleroot).toBe("string");
      expect(Array.isArray(block.tx)).toBe(true);
    });

    test("getblockheader returns header data", async () => {
      const genesisHash = REGTEST.genesisBlockHash.toString("hex");
      const header = await rpcCall("getblockheader", [genesisHash, true]) as Record<string, unknown>;

      expect(header.hash).toBe(genesisHash);
      expect(header.height).toBe(0);
      expect(typeof header.version).toBe("number");
      expect(typeof header.merkleroot).toBe("string");
      expect(typeof header.time).toBe("number");
      expect(typeof header.bits).toBe("string");
      expect(typeof header.nonce).toBe("number");
    });
  });

  describe("error handling", () => {
    test("returns error for unknown method", async () => {
      await expect(
        rpcCall("nonexistentmethod", [])
      ).rejects.toThrow(/not found/);
    });

    test("returns error for invalid block hash", async () => {
      await expect(
        rpcCall("getblock", ["invalidhash", 1])
      ).rejects.toThrow();
    });
  });

  describe("batch requests", () => {
    test("handles batch RPC requests", async () => {
      const response = await fetch(`http://127.0.0.1:${rpcPort}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify([
          { jsonrpc: "2.0", id: 1, method: "getblockchaininfo", params: [] },
          { jsonrpc: "2.0", id: 2, method: "getmempoolinfo", params: [] },
        ]),
      });

      const results = await response.json() as Array<{ id: number; result?: unknown; error?: unknown }>;

      expect(Array.isArray(results)).toBe(true);
      expect(results.length).toBe(2);
      expect(results[0].id).toBe(1);
      expect(results[1].id).toBe(2);
    });
  });
});

describe("e2e wallet integration", () => {
  let tempDir: string;
  let wallet: Wallet;

  beforeAll(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "hotbuns-wallet-e2e-"));
    wallet = Wallet.create({ datadir: tempDir, network: "regtest" });
  });

  afterAll(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  test("wallet creates multiple addresses", () => {
    const addresses: string[] = [];

    for (let i = 0; i < 5; i++) {
      const addr = wallet.getNewAddress();
      expect(addresses).not.toContain(addr);
      addresses.push(addr);
    }

    expect(addresses.length).toBe(5);
  });

  test("wallet creates change addresses", () => {
    const changeAddr1 = wallet.getChangeAddress();
    const changeAddr2 = wallet.getChangeAddress();

    expect(changeAddr1).toMatch(/^bcrt1/);
    expect(changeAddr2).toMatch(/^bcrt1/);
    expect(changeAddr1).not.toBe(changeAddr2);
  });

  test("wallet lists addresses", () => {
    const keys = wallet.listAddresses();
    expect(Array.isArray(keys)).toBe(true);
    expect(keys.length).toBeGreaterThan(0);

    for (const key of keys) {
      // Now supports multiple address types:
      // - bcrt1q... (native segwit P2WPKH)
      // - bcrt1p... (taproot P2TR)
      // - 2... (P2SH-P2WPKH)
      // - m/n... (legacy P2PKH)
      expect(key.address).toMatch(/^(bcrt1|2|m|n)/);
      expect(key.privateKey.length).toBe(32);
      expect(key.publicKey.length).toBe(33);
    }
  });

  test("wallet saves and loads", async () => {
    const password = "test-password-123";

    // Generate some addresses first
    const addr1 = wallet.getNewAddress();
    const addr2 = wallet.getNewAddress();

    // Save
    await wallet.save(password);

    // Load into new wallet instance
    const loadedWallet = await Wallet.load({ datadir: tempDir, network: "regtest" }, password);

    // Verify addresses are preserved
    expect(loadedWallet.hasAddress(addr1)).toBe(true);
    expect(loadedWallet.hasAddress(addr2)).toBe(true);
  });

  test("wallet rejects wrong password", async () => {
    await expect(
      Wallet.load({ datadir: tempDir, network: "regtest" }, "wrong-password")
    ).rejects.toThrow(/decrypt/);
  });
});
