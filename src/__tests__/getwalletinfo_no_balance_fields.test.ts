/**
 * getwalletinfo has no balance fields (wallet cause B).
 *
 * Core v31 getwalletinfo (bitcoin-core/src/wallet/rpc/wallet.cpp) returns
 * walletname, walletversion, format, txcount, keypoolsize, unlocked_until,
 * private_keys_enabled, avoid_reuse, scanning, descriptors, external_signer,
 * blank, birthtime, flags and lastprocessedblock. Balances come from
 * getbalances / getbalance.
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

describe("getwalletinfo has no balance fields (Core v31)", () => {
  let server: RPCServer;
  let port: number;
  let caseDir: string;

  beforeEach(async () => {
    caseDir = mkdtempSync(path.join(os.tmpdir(), "hotbuns-getwalletinfo-nobal-"));
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

  it("getwalletinfo does not report balance, immature_balance or unconfirmed_balance", async () => {
    const r = await rpc(port, "getwalletinfo", []);
    expect(r.error).toBeUndefined();
    for (const f of ["balance", "immature_balance", "unconfirmed_balance"]) {
      expect(Object.prototype.hasOwnProperty.call(r.result, f)).toBe(false);
    }
  });

  it("getwalletinfo keeps the fields Core returns (control)", async () => {
    const r = await rpc(port, "getwalletinfo", []);
    expect(r.error).toBeUndefined();
    for (const f of [
      "walletname", "walletversion", "format", "txcount", "keypoolsize",
      "private_keys_enabled", "avoid_reuse", "scanning", "descriptors",
      "external_signer", "blank", "flags", "lastprocessedblock",
    ]) {
      expect(r.result).toHaveProperty(f);
    }
    expect(r.result.walletname).toBe("default");
    expect(typeof r.result.txcount).toBe("number");
  });

  it("getbalances still reports the balances (control)", async () => {
    const r = await rpc(port, "getbalances", []);
    expect(r.error).toBeUndefined();
    expect(r.result.mine.immature).toBeGreaterThan(0);
  });
});
