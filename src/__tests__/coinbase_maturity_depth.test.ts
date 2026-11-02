/**
 * Coinbase maturity depth in the mempool, measured the way Core measures it.
 *
 * Core MemPoolAccept::PreChecks calls Consensus::CheckTxInputs with
 * nSpendHeight = active tip + 1 (validation.cpp:891-892: "The mempool holds
 * txs for the next block"), and CheckTxInputs rejects a coinbase spend when
 * nSpendHeight - coin.nHeight < COINBASE_MATURITY with
 * "bad-txns-premature-spend-of-coinbase" / "tried to spend coinbase at depth
 * %d" (consensus/tx_verify.cpp:179-181). So a coinbase mined at height 1 is
 * accepted into the mempool at tip 100, and at tip 99 the reject text says
 * depth 99.
 *
 * hotbuns measured from the tip itself (tipHeight - coin height), one block
 * short: tip 100 rejected with "depth 99 < 100", tip 99 said "depth 98".
 * tools/core-regtest rows (seed_|warden_)invalidated_submit/maturity/tip*.
 *
 * The block path (coreConnectBlockChecks) already passes the block's own
 * height as the spend height; the control tests below pin that a block at
 * height coin+100 connects and one at coin+99 does not.
 */

import { describe, test, expect, beforeEach, afterEach } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ChainDB } from "../storage/database.js";
import { UTXOManager } from "../chain/utxo.js";
import { REGTEST } from "../consensus/params.js";
import { Mempool } from "../mempool/mempool.js";
import { coreConnectBlockChecks } from "../consensus/connect_block.js";
import { RPCServer, type RPCServerConfig, type RPCServerDeps } from "../rpc/server.js";
import { serializeTx, type Transaction } from "../validation/tx.js";
import type { Block } from "../validation/block.js";

// OP_1 <0x4e73>: P2A anchor, standard and spendable with an empty scriptSig.
const P2A = Buffer.from([0x51, 0x02, 0x4e, 0x73]);
const COIN_HEIGHT = 1;
const COINBASE_TXID = Buffer.alloc(32, 0x5c);

function spendOfCoinbase(): Transaction {
  return {
    version: 2,
    inputs: [
      {
        prevOut: { txid: COINBASE_TXID, vout: 0 },
        scriptSig: Buffer.alloc(0),
        sequence: 0xffffffff,
        witness: [],
      },
    ],
    outputs: [
      { value: 49_99990000n, scriptPubKey: P2A },
      // Pads the non-witness size past MIN_STANDARD_TX_NONWITNESS_SIZE (65).
      { value: 0n, scriptPubKey: Buffer.from([0x6a, 0x08, ...Buffer.alloc(8, 0x01)]) },
    ],
    lockTime: 0,
  };
}

describe("mempool coinbase maturity uses spend height tip+1 (Core CheckTxInputs)", () => {
  let tempDir: string;
  let db: ChainDB;
  let utxo: UTXOManager;
  let mempool: Mempool;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "cb-maturity-depth-"));
    db = new ChainDB(tempDir);
    await db.open();
    utxo = new UTXOManager(db);
    mempool = new Mempool(utxo, REGTEST, 1_000_000);
    await db.putUTXO(COINBASE_TXID, 0, {
      height: COIN_HEIGHT,
      coinbase: true,
      amount: 50_00000000n,
      scriptPubKey: P2A,
    });
  });

  afterEach(async () => {
    await db.close();
    await rm(tempDir, { recursive: true, force: true });
  });

  test("tip 100 accepts the spend of the height-1 coinbase (depth 100)", async () => {
    mempool.setTipHeight(COIN_HEIGHT + 99);
    const result = await mempool.addTransaction(spendOfCoinbase());
    expect(result.error).toBeUndefined();
    expect(result.accepted).toBe(true);
  });

  test("tip 99 rejects with Core's reason and depth 99", async () => {
    mempool.setTipHeight(COIN_HEIGHT + 98);
    const result = await mempool.addTransaction(spendOfCoinbase());
    expect(result.accepted).toBe(false);
    expect(result.error).toBe(
      "bad-txns-premature-spend-of-coinbase, tried to spend coinbase at depth 99"
    );
  });

  describe("RPC text", () => {
    let server: RPCServer;
    let port: number;
    let nextPort = 19950;

    async function rpc(method: string, params: unknown[]): Promise<any> {
      const res = await fetch(`http://127.0.0.1:${port}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
      });
      return res.json();
    }

    beforeEach(() => {
      port = nextPort++;
      const config: RPCServerConfig = { port, host: "127.0.0.1", noAuth: true };
      const deps: RPCServerDeps = {
        chainState: {
          getBestBlock: () => ({ hash: Buffer.alloc(32, 0), height: COIN_HEIGHT + 98, chainWork: 1n }),
        } as any,
        mempool,
        peerManager: { getConnectedPeers: () => [], broadcast() {}, listBanned: () => [] } as any,
        feeEstimator: { estimateSmartFee: (t: number) => ({ feeRate: 10, blocks: t }) } as any,
        headerSync: { getBestHeader: () => null, getHeader: () => null } as any,
        db: db as any,
        params: REGTEST,
      };
      server = new RPCServer(config, deps);
      server.start();
      mempool.setTipHeight(COIN_HEIGHT + 98);
    });

    afterEach(() => {
      server.stop();
    });

    test("testmempoolaccept at tip 99: reject-reason and reject-details match Core", async () => {
      const hex = serializeTx(spendOfCoinbase(), true).toString("hex");
      const res = await rpc("testmempoolaccept", [[hex]]);
      expect(res.error ?? null).toBeNull();
      expect(res.result[0].allowed).toBe(false);
      expect(res.result[0]["reject-reason"]).toBe("bad-txns-premature-spend-of-coinbase");
      expect(res.result[0]["reject-details"]).toBe(
        "bad-txns-premature-spend-of-coinbase, tried to spend coinbase at depth 99"
      );
    });

    test("sendrawtransaction at tip 99: -26 with Core's message", async () => {
      const hex = serializeTx(spendOfCoinbase(), true).toString("hex");
      const res = await rpc("sendrawtransaction", [hex]);
      expect(res.error.code).toBe(-26);
      expect(res.error.message).toBe(
        "bad-txns-premature-spend-of-coinbase, tried to spend coinbase at depth 99"
      );
    });
  });
});

describe("block path control: coreConnectBlockChecks uses the block height", () => {
  let tempDir: string;
  let db: ChainDB;
  let utxo: UTXOManager;

  function coinbaseAt(height: number): Transaction {
    return {
      version: 2,
      inputs: [
        {
          prevOut: { txid: Buffer.alloc(32, 0), vout: 0xffffffff },
          scriptSig: Buffer.from([0x02, height & 0xff, (height >> 8) & 0xff]),
          sequence: 0xffffffff,
          witness: [],
        },
      ],
      outputs: [{ value: 50_00000000n, scriptPubKey: P2A }],
      lockTime: 0,
    };
  }

  function blockAt(height: number): Block {
    return {
      header: {
        version: 0x20000000,
        prevBlock: Buffer.alloc(32, 0x11),
        merkleRoot: Buffer.alloc(32, 0),
        timestamp: 1600000000 + height,
        bits: 0x207fffff,
        nonce: 0,
      },
      transactions: [coinbaseAt(height), spendOfCoinbase()],
    };
  }

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "cb-maturity-block-"));
    db = new ChainDB(tempDir);
    await db.open();
    utxo = new UTXOManager(db);
    const fundingCoinbase = coinbaseAt(COIN_HEIGHT);
    // The spender references COINBASE_TXID; register the coin under that id.
    utxo.addTransaction(COINBASE_TXID, fundingCoinbase, COIN_HEIGHT, true);
  });

  afterEach(async () => {
    await db.close();
    await rm(tempDir, { recursive: true, force: true });
  });

  test("a block at coin height + 100 spending the coinbase connects", async () => {
    const result = await coreConnectBlockChecks(blockAt(COIN_HEIGHT + 100), COIN_HEIGHT + 100, utxo, REGTEST);
    expect(result.ok ? "ok" : result.error).toBe("ok");
  });

  test("a block at coin height + 99 spending the coinbase is rejected as immature", async () => {
    const result = await coreConnectBlockChecks(blockAt(COIN_HEIGHT + 99), COIN_HEIGHT + 99, utxo, REGTEST);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toContain("maturity 99 < 100");
  });
});
