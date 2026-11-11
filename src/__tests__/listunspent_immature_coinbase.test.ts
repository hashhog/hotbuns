/**
 * listunspent and immature coinbase outputs (wallet cause A).
 *
 * Core leaves a coinbase output out of listunspent while it has fewer than
 * COINBASE_MATURITY + 1 = 101 confirmations, unless
 * query_options.include_immature_coinbase is true
 * (bitcoin-core/src/wallet/spend.cpp AvailableCoins: IsTxImmatureCoinBase;
 * src/wallet/rpc/coins.cpp listunspent: the option is type-checked as a
 * bool and every listed coin reports spendable: true).
 *
 * Fixture: the regtest wallet scenario after 101 blocks mined to the wallet,
 * i.e. coinbases with 101..1 confirmations, plus one ordinary payment.
 */

import { describe, it, expect, beforeEach, afterEach } from "bun:test";
import { rmSync, mkdirSync, mkdtempSync } from "fs";
import * as os from "os";
import * as path from "path";
import { RPCServer, RPCServerDeps, RPCErrorCodes } from "../rpc/server.js";
import { startTestRpc } from "../test/rpc-listen.js";
import { REGTEST } from "../consensus/params.js";
import { WalletManager, type Wallet } from "../wallet/wallet.js";
import { AddressType } from "../address/encoding.js";

class MockChainStateManager {
  getBestBlock() {
    return { hash: Buffer.alloc(32, 0), height: 101, chainWork: 1000n };
  }
  getUTXOManager() {
    return { async getUTXOAsync() { return null; } };
  }
}
class MockMempool {
  getInfo() { return { size: 0, bytes: 0, minFeeRate: 1 }; }
  getMinFee() { return 0; }
  getMinRelayFeeRate() { return 0.1; }
  getAllTxids() { return []; }
  getTransaction(_txid: Buffer) { return null; }
  hasTransaction(_txid: Buffer) { return false; }
  getSize() { return 0; }
}
class MockPeerManager {
  getConnectedPeers() { return []; }
  broadcast(_msg: any) {}
}
class MockFeeEstimator {
  estimateSmartFee() { return { feeRate: 10, blocks: 6 }; }
  getBuckets() { return []; }
}
class MockHeaderSync {
  getBestHeader() { return { hash: Buffer.alloc(32, 0), height: 101, chainWork: 1000n }; }
  getHeader(_h: Buffer) { return undefined; }
  getMedianTimePast() { return 0; }
}
class MockChainDB {
  async getBlock() { return null; }
  async getBlockIndex() { return null; }
  async getBlockHashByHeight() { return null; }
  async getChainWork(): Promise<bigint | null> { return null; }
  async getChainState() { return { bestBlockHash: Buffer.alloc(32, 0), bestHeight: 101 }; }
  async getUTXO() { return null; }
}

async function rpc(port: number, method: string, params: any[] = []): Promise<any> {
  const r = await fetch(`http://127.0.0.1:${port}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });
  return r.json();
}

/** Coinbases at heights 1..101 (confirmations 101..1) and one payment. */
function fundWallet(wallet: Wallet): void {
  const addr = wallet.getNewAddress("bech32");
  const key = wallet.getKey(addr)!;
  for (let conf = 1; conf <= 101; conf++) {
    const txid = Buffer.alloc(32, 0);
    txid.writeUInt32BE(conf, 0);
    wallet.addUTXO({
      outpoint: { txid, vout: 0 },
      amount: 5_000_000_000n,
      address: addr,
      keyPath: key.path,
      confirmations: conf,
      addressType: AddressType.P2WPKH,
      isCoinbase: true,
      height: 102 - conf,
    });
  }
  wallet.addUTXO({
    outpoint: { txid: Buffer.alloc(32, 0xaa), vout: 1 },
    amount: 100_000_000n,
    address: addr,
    keyPath: key.path,
    confirmations: 1,
    addressType: AddressType.P2WPKH,
    isCoinbase: false,
    height: 101,
  });
}

describe("listunspent immature coinbase (Core AvailableCoins)", () => {
  let server: RPCServer;
  let port: number;
  let caseDir: string;

  beforeEach(async () => {
    caseDir = mkdtempSync(path.join(os.tmpdir(), "hotbuns-listunspent-immature-"));
    mkdirSync(`${caseDir}/wallets`, { recursive: true });
    const manager = new WalletManager(caseDir, "regtest");
    await manager.createWallet("default", {});
    fundWallet(manager.getWallet("default")!);
    const deps: RPCServerDeps = {
      chainState: new MockChainStateManager() as any,
      mempool: new MockMempool() as any,
      peerManager: new MockPeerManager() as any,
      feeEstimator: new MockFeeEstimator() as any,
      headerSync: new MockHeaderSync() as any,
      db: new MockChainDB() as any,
      params: REGTEST,
      walletManager: manager,
    };
    const started = startTestRpc(deps);
    server = started.server;
    port = started.port;
  });

  afterEach(() => {
    server.stop();
    try {
      rmSync(caseDir, { recursive: true, force: true });
    } catch {
      /* persist may still be flushing */
    }
  });

  it("default listunspent skips the 100 immature coinbases", async () => {
    const r = await rpc(port, "listunspent", []);
    expect(r.error).toBeUndefined();
    const confs = r.result.map((u: any) => u.confirmations).sort((a: number, b: number) => a - b);
    // The mature coinbase (101 confirmations) and the ordinary payment.
    expect(confs).toEqual([1, 101]);
    for (const u of r.result) {
      expect([u.spendable, u.solvable, u.safe]).toEqual([true, true, true]);
    }
  });

  it("query_options.include_immature_coinbase=false is the default", async () => {
    const r = await rpc(port, "listunspent", [1, 9999999, null, true, { include_immature_coinbase: false }]);
    expect(r.error).toBeUndefined();
    expect(r.result.length).toBe(2);
  });

  it("query_options.include_immature_coinbase=true lists them, spendable and safe", async () => {
    const r = await rpc(port, "listunspent", [1, 9999999, null, true, { include_immature_coinbase: true }]);
    expect(r.error).toBeUndefined();
    expect(r.result.length).toBe(102);
    for (const u of r.result) {
      expect(u.spendable).toBe(true);
      expect(u.safe).toBe(true);
    }
  });

  it("non-bool include_immature_coinbase is RPC_TYPE_ERROR (-3)", async () => {
    const r = await rpc(port, "listunspent", [1, 9999999, null, true, { include_immature_coinbase: "yes" }]);
    expect(r.error).toBeDefined();
    expect(r.error.code).toBe(RPCErrorCodes.TYPE_ERROR);
    expect(r.error.message).toBe(
      "JSON value of type string for field include_immature_coinbase is not of expected type bool"
    );
  });

  it("null include_immature_coinbase is RPC_TYPE_ERROR (-3) from Core's get_bool()", async () => {
    // RPCTypeCheckObj allows null, but the key exists, so get_bool() throws
    // UniValue::type_error, which rpc/server.cpp:512 reports as RPC_TYPE_ERROR.
    const r = await rpc(port, "listunspent", [1, 9999999, null, true, { include_immature_coinbase: null }]);
    expect(r.error).toBeDefined();
    expect(r.error.code).toBe(RPCErrorCodes.TYPE_ERROR);
    expect(r.error.message).toBe("JSON value of type null is not of expected type bool");
  });

  it("minconf 101 lists exactly the one mature coinbase (control)", async () => {
    const r = await rpc(port, "listunspent", [101]);
    expect(r.error).toBeUndefined();
    expect(r.result.map((u: any) => u.confirmations)).toEqual([101]);
  });
});
