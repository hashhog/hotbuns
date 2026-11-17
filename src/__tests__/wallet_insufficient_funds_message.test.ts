/**
 * A wallet spend the coins cannot cover fails with Core's bare
 * "Insufficient funds".
 *
 * Core: CreateTransactionInternal returns util::Error{_("Insufficient funds")}
 * when coin selection finds no solution (bitcoin-core/src/wallet/spend.cpp:1234),
 * and sendtoaddress / send hand that text to the caller unchanged
 * (SendMoney -> JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS,
 * util::ErrorString(res).original), wallet/rpc/spend.cpp). An empty wallet takes
 * the same path. hotbuns' wallet threw "Insufficient funds: need <sats>, only
 * have <sats>" (and "No confirmed UTXOs available" for no spendable coins),
 * which the RPC layer passed through: core-regtest row
 * wallet/error/insufficient:message.
 */

import { describe, it, expect, beforeEach, afterEach } from "bun:test";
import { rmSync, mkdirSync, mkdtempSync } from "fs";
import * as os from "os";
import * as path from "path";
import { RPCServer, RPCServerDeps } from "../rpc/server.js";
import { startTestRpc } from "../test/rpc-listen.js";
import { REGTEST } from "../consensus/params.js";
import { WalletManager, type Wallet } from "../wallet/wallet.js";
import { AddressType } from "../address/encoding.js";

const DEST = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";

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

/** One spendable 1 BTC payment (as in the regtest scenario's post-send wallet). */
function fundOneBtc(wallet: Wallet): void {
  const addr = wallet.getNewAddress("bech32");
  const key = wallet.getKey(addr)!;
  wallet.addUTXO({
    outpoint: { txid: Buffer.alloc(32, 0xaa), vout: 1 },
    amount: 100_000_000n,
    address: addr,
    keyPath: key.path,
    confirmations: 6,
    addressType: AddressType.P2WPKH,
    isCoinbase: false,
    height: 96,
  });
}

const CORE_ERROR = { code: -6, message: "Insufficient funds" };

describe("wallet spend short of funds says Core's \"Insufficient funds\"", () => {
  let server: RPCServer;
  let port: number;
  let caseDir: string;
  let manager: WalletManager;

  beforeEach(async () => {
    caseDir = mkdtempSync(path.join(os.tmpdir(), "hotbuns-insufficient-funds-"));
    mkdirSync(`${caseDir}/wallets`, { recursive: true });
    manager = new WalletManager(caseDir, "regtest");
    await manager.createWallet("default", {});
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

  it("sendtoaddress for more than the wallet holds", async () => {
    fundOneBtc(manager.getWallet("default")!);
    const r = await rpc(port, "sendtoaddress", [DEST, 1000]);
    expect(r.error).toEqual(CORE_ERROR);
  });

  it("send for more than the wallet holds", async () => {
    fundOneBtc(manager.getWallet("default")!);
    const r = await rpc(port, "send", [{ [DEST]: 1000 }]);
    expect(r.error).toEqual(CORE_ERROR);
  });

  it("sendtoaddress from a wallet with no spendable coins", async () => {
    const r = await rpc(port, "sendtoaddress", [DEST, 1]);
    expect(r.error).toEqual(CORE_ERROR);
  });

  it("control: a spend the coins cover still succeeds in coin selection", () => {
    const wallet = manager.getWallet("default")!;
    fundOneBtc(wallet);
    const tx = wallet.createTransaction([{ address: DEST, amount: 10_000_000n }], 1);
    expect(tx.inputs.length).toBe(1);
  });
});
