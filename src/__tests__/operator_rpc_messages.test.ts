/**
 * Core-parity of the operator RPC rows found by tools/core-regtest (operator
 * group): getrawtransaction without -txindex, getblock verbosity, and the
 * error text / codes of getblockheader, sendrawtransaction, testmempoolaccept.
 * Expected values are what Bitcoin Core v31.1 answered in the same run.
 */

import { describe, it, expect, beforeEach, afterEach } from "bun:test";
import { RPCServer, RPCServerConfig, RPCServerDeps, RPCErrorCodes } from "../rpc/server.js";
import { REGTEST } from "../consensus/params.js";
import { serializeTx, getTxId, type Transaction } from "../validation/tx.js";
import { serializeBlock, type Block, type BlockHeader } from "../validation/block.js";
import { hash256 } from "../crypto/primitives.js";

const CORE_NO_TXINDEX =
  "No such mempool transaction. Use -txindex or provide a block hash to enable blockchain transaction queries. Use gettransaction for wallet transactions.";

function coinbase(height: number): Transaction {
  return {
    version: 1,
    inputs: [
      {
        prevOut: { txid: Buffer.alloc(32, 0), vout: 0xffffffff },
        scriptSig: Buffer.from([height & 0xff, (height >> 8) & 0xff]),
        sequence: 0xffffffff,
        witness: [],
      },
    ],
    outputs: [
      { value: 5000000000n, scriptPubKey: Buffer.from([0x76, 0xa9, 0x14, ...Buffer.alloc(20, 0x11), 0x88, 0xac]) },
    ],
    lockTime: 0,
  };
}

// Spends the coinbase's only output, so verbosity 3 has a prevout to report.
function spendOf(cb: Transaction): Transaction {
  return {
    version: 2,
    inputs: [
      { prevOut: { txid: getTxId(cb), vout: 0 }, scriptSig: Buffer.from([0x51]), sequence: 0xfffffffe, witness: [] },
    ],
    outputs: [{ value: 4999990000n, scriptPubKey: Buffer.from([0x51]) }],
    lockTime: 0,
  };
}

class MockChainState {
  getBestBlock() {
    return { hash: Buffer.alloc(32, 0), height: 100, chainWork: 1000n };
  }
}

class MockMempool {
  confirmed = false;
  addError = "";
  getInfo() {
    return { size: 0, bytes: 0, minFeeRate: 1 };
  }
  getAllTxids() {
    return [];
  }
  getTransaction(_txid: Buffer) {
    return null;
  }
  hasTransaction(_txid: Buffer) {
    return false;
  }
  async isTransactionConfirmed(_txid: Buffer) {
    return this.confirmed;
  }
  async addTransaction(_tx: Transaction, _opts?: unknown) {
    return { accepted: false, error: this.addError };
  }
}

class MockHeaderSync {
  getBestHeader() {
    return { hash: Buffer.alloc(32, 0), height: 100, chainWork: 1000n };
  }
  getHeader(_hash: Buffer) {
    return null;
  }
  getMedianTimePast(_entry: unknown) {
    return 1600000000;
  }
}

class MockDB {
  blocks = new Map<string, Buffer>();
  indexes = new Map<string, unknown>();
  txIndex = new Map<string, { blockHash: Buffer; offset: number; length: number }>();
  async getBlock(h: Buffer) {
    return this.blocks.get(h.toString("hex")) ?? null;
  }
  async getBlockIndex(h: Buffer) {
    return this.indexes.get(h.toString("hex")) ?? null;
  }
  async getBlockHashByHeight(_h: number) {
    return null;
  }
  async getTxIndex(t: Buffer) {
    return this.txIndex.get(t.toString("hex")) ?? null;
  }
  async getUndoData(_h: Buffer) {
    return null;
  }
  async getChainWork(_h: Buffer) {
    return 1000n;
  }
}

async function rpc(port: number, method: string, params: unknown[] = []): Promise<any> {
  const res = await fetch(`http://127.0.0.1:${port}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });
  return res.json();
}

const display = (b: Buffer) => Buffer.from(b).reverse().toString("hex");

let portCounter = 19750;

for (const txindex of [false, true]) {
  describe(`operator RPC Core parity (txindex=${txindex})`, () => {
    let server: RPCServer;
    let db: MockDB;
    let mempool: MockMempool;
    let port: number;
    let tx: Transaction;
    let spender: Transaction;
    let blockHash: Buffer;

    beforeEach(() => {
      port = portCounter++;
      db = new MockDB();
      mempool = new MockMempool();
      tx = coinbase(60);
      spender = spendOf(tx);
      const header: BlockHeader = {
        version: 0x20000000,
        prevBlock: Buffer.alloc(32, 0),
        merkleRoot: Buffer.alloc(32, 7),
        timestamp: 1600000000,
        bits: 0x207fffff,
        nonce: 0,
      };
      const block: Block = { header, transactions: [tx, spender] };
      const data = serializeBlock(block);
      blockHash = hash256(data.subarray(0, 80));
      db.blocks.set(blockHash.toString("hex"), data);
      db.indexes.set(blockHash.toString("hex"), {
        height: 60,
        header: data.subarray(0, 80),
        nTx: 2,
        status: 7,
        dataPos: 0,
      });
      db.txIndex.set(getTxId(tx).toString("hex"), { blockHash, offset: 0, length: 0 });

      const config: RPCServerConfig = { port, host: "127.0.0.1", noAuth: true };
      const deps: RPCServerDeps = {
        chainState: new MockChainState() as any,
        mempool: mempool as any,
        peerManager: { getConnectedPeers: () => [], broadcast() {}, listBanned: () => [] } as any,
        feeEstimator: { estimateSmartFee: (t: number) => ({ feeRate: 10, blocks: t }) } as any,
        headerSync: new MockHeaderSync() as any,
        db: db as any,
        params: REGTEST,
        txindex,
      };
      server = new RPCServer(config, deps);
      server.start();
    });

    afterEach(() => {
      server.stop();
    });

    it("getrawtransaction of a confirmed tx without a blockhash", async () => {
      const res = await rpc(port, "getrawtransaction", [display(getTxId(tx)), true]);
      if (txindex) {
        expect(res.error).toBeUndefined();
        expect(res.result.txid).toBe(display(getTxId(tx)));
      } else {
        expect(res.error.code).toBe(RPCErrorCodes.INVALID_ADDRESS_OR_KEY);
        expect(res.error.message).toBe(CORE_NO_TXINDEX);
      }
    });

    it("getrawtransaction with the blockhash works with or without txindex", async () => {
      const res = await rpc(port, "getrawtransaction", [display(getTxId(tx)), false, display(blockHash)]);
      expect(res.error).toBeUndefined();
      expect(typeof res.result).toBe("string");
    });

    it("getrawtransaction error text for an unknown txid", async () => {
      const res = await rpc(port, "getrawtransaction", ["ab".repeat(32), true]);
      expect(res.error.code).toBe(RPCErrorCodes.INVALID_ADDRESS_OR_KEY);
      expect(res.error.message).toBe(
        txindex
          ? "No such mempool or blockchain transaction. Use gettransaction for wallet transactions."
          : CORE_NO_TXINDEX,
      );
    });

    it("getrawtransaction unknown txid in a given block", async () => {
      const res = await rpc(port, "getrawtransaction", ["ab".repeat(32), true, display(blockHash)]);
      expect(res.error.code).toBe(RPCErrorCodes.INVALID_ADDRESS_OR_KEY);
      expect(res.error.message).toBe(
        "No such transaction found in the provided block. Use gettransaction for wallet transactions.",
      );
    });

    it("getindexinfo lists txindex only when it is enabled", async () => {
      const res = await rpc(port, "getindexinfo", []);
      expect(res.error).toBeUndefined();
      expect("txindex" in res.result).toBe(txindex);
    });

    it("getblock verbosity=false is the raw hex, like 0", async () => {
      const hex = (await rpc(port, "getblock", [display(blockHash), 0])).result;
      expect(typeof hex).toBe("string");
      expect((await rpc(port, "getblock", [display(blockHash), false])).result).toBe(hex);
    });

    it("getblock verbosity=true is the txid-list object, like 1", async () => {
      const res = await rpc(port, "getblock", [display(blockHash), true]);
      expect(res.result.tx).toEqual([display(getTxId(tx)), display(getTxId(spender))]);
    });

    it("getblock verbosity above 2 is the full-transaction form", async () => {
      const res = await rpc(port, "getblock", [display(blockHash), 9]);
      expect(res.error).toBeUndefined();
      expect(typeof res.result.tx[0]).toBe("object");
      expect(res.result.tx[0].txid).toBe(display(getTxId(tx)));
      expect(res.result.tx[0].vin[0].prevout).toBeUndefined();
      // Core TxVerbosity::SHOW_DETAILS_AND_PREVOUT: spent output's details.
      const prevout = res.result.tx[1].vin[0].prevout;
      expect(prevout.generated).toBe(true);
      expect(prevout.value).toBe(50);
      expect(prevout.scriptPubKey.hex).toBe(tx.outputs[0].scriptPubKey.toString("hex"));
    });

    it("getblock verbosity 2 does not report prevouts", async () => {
      const res = await rpc(port, "getblock", [display(blockHash), 2]);
      expect(res.result.tx[1].vin[0].prevout).toBeUndefined();
    });

    it("getblock verbosity below 0 is the raw hex", async () => {
      const res = await rpc(port, "getblock", [display(blockHash), -3]);
      expect(typeof res.result).toBe("string");
    });

    it("getblockheader names the parameter 'hash' in parse errors", async () => {
      const short = await rpc(port, "getblockheader", ["00"]);
      expect(short.error.code).toBe(RPCErrorCodes.INVALID_PARAMETER);
      expect(short.error.message).toBe("hash must be of length 64 (not 2, for '00')");
      const bad = await rpc(port, "getblockheader", ["zz".repeat(32)]);
      expect(bad.error.message).toBe(`hash must be hexadecimal string (not '${"zz".repeat(32)}')`);
    });

    it("sendrawtransaction of a confirmed tx says 'outputs already in utxo set'", async () => {
      mempool.confirmed = true;
      const res = await rpc(port, "sendrawtransaction", [serializeTx(tx, true).toString("hex")]);
      expect(res.error.code).toBe(RPCErrorCodes.RPC_TRANSACTION_ALREADY_IN_CHAIN);
      expect(res.error.message).toBe("Transaction outputs already in utxo set");
    });

    it("sendrawtransaction with missing inputs is -25 and the bare reason", async () => {
      mempool.addError = "bad-txns-inputs-missingorspent: 2222:1";
      const res = await rpc(port, "sendrawtransaction", [serializeTx(tx, true).toString("hex")]);
      expect(res.error.code).toBe(-25);
      expect(res.error.message).toBe("bad-txns-inputs-missingorspent");
    });

    it("sendrawtransaction with another rejection stays -26 with the detail", async () => {
      mempool.addError = "min relay fee not met";
      const res = await rpc(port, "sendrawtransaction", [serializeTx(tx, true).toString("hex")]);
      expect(res.error.code).toBe(-26);
      expect(res.error.message).toBe("min relay fee not met");
    });

    it("sendrawtransaction with a non-numeric maxfeerate is -3 'Invalid amount'", async () => {
      const res = await rpc(port, "sendrawtransaction", [serializeTx(tx, true).toString("hex"), "x"]);
      expect(res.error.code).toBe(RPCErrorCodes.TYPE_ERROR);
      expect(res.error.message).toBe("Invalid amount");
    });

    it("testmempoolaccept of an empty array is -8 with Core's package text", async () => {
      const res = await rpc(port, "testmempoolaccept", [[]]);
      expect(res.error.code).toBe(RPCErrorCodes.INVALID_PARAMETER);
      expect(res.error.message).toBe("Array must contain between 1 and 25 transactions.");
    });
  });
}
