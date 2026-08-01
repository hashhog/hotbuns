/**
 * Focused functional test for the `fundrawtransaction` RPC.
 *
 * fundrawtransaction is the raw-tx sibling of walletcreatefundedpsbt: it
 * decodes an existing raw tx (keeping its outputs), then funds it by adding
 * wallet inputs + a change output via the SAME coin-selection engine
 * (`Wallet.selectCoinsAdvanced`). It returns { hex, fee, changepos }.
 *
 * Strategy mirrors wallet_psbt_rpc.test.ts: stand up a real RPCServer over a
 * real WalletManager with a confirmed UTXO injected directly (regtest funded
 * wallet), build a raw tx with `createrawtransaction` (1 output, no inputs),
 * fund it, and assert the funded tx is genuinely valid:
 *   - inputs were added (vin non-empty),
 *   - a change output exists (changepos consistent with the returned hex),
 *   - fee > 0,
 *   - sum(selected input values) >= sum(outputs) + fee, with
 *     change == inputs - outputs - fee.
 *
 * Reference: bitcoin-core/src/wallet/rpc/spend.cpp::fundrawtransaction (:706),
 * FundTransaction (:470).
 */

import { describe, it, expect, beforeEach, afterEach, beforeAll } from "bun:test";
import { rmSync, mkdirSync } from "fs";
import { RPCServer, RPCServerConfig, RPCServerDeps, RPCErrorCodes } from "../rpc/server.js";
import { REGTEST } from "../consensus/params.js";
import { WalletManager } from "../wallet/wallet.js";
import { AddressType } from "../address/encoding.js";
import { deserializeTx } from "../validation/tx.js";
import { BufferReader } from "../wire/serialization.js";

const TEST_DATADIR = "/tmp/hotbuns-fundrawtx-rpc-test";

// Randomised per-process port band (mirrors the 26682fc watchonly
// fix): each test file draws from a distinct band plus a random
// offset. Every band must stay BELOW the Linux client ephemeral
// range (ip_local_port_range 32768-60999) — a band inside it can
// collide with a kernel-assigned fetch() client socket and fail
// EADDRINUSE (observed on CI: ports 39450, 59180).
let portCounter = 32000 + Math.floor(Math.random() * 500);
function getTestPort(): number {
  return portCounter++;
}

class FakeUTXOManager {
  private utxos = new Map<string, { scriptPubKey: Buffer; amount: bigint; height: number; coinbase: boolean }>();
  async getUTXOAsync(outpoint: { txid: Buffer; vout: number }) {
    const key = `${outpoint.txid.toString("hex")}:${outpoint.vout}`;
    return this.utxos.get(key) ?? null;
  }
}

class MockChainStateManager {
  private bestBlock = { hash: Buffer.alloc(32, 0), height: 100, chainWork: 1000n };
  utxoMgr = new FakeUTXOManager();
  getBestBlock() { return { ...this.bestBlock }; }
  getUTXOManager() { return this.utxoMgr; }
}

class MockMempool {
  getInfo() { return { size: 0, bytes: 0, minFeeRate: 1 }; }
  getAllTxids() { return []; }
  getTransaction(_txid: Buffer) { return null; }
  hasTransaction(_txid: Buffer) { return false; }
  async addTransaction(_tx: any) { return { accepted: true }; }
  removeTransaction(_txid: Buffer) {}
  async isTransactionConfirmed(_txid: Buffer): Promise<boolean> { return false; }
  isReplaceable(_txid: Buffer): boolean { return true; }
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
  getBestHeader() { return { hash: Buffer.alloc(32, 0), height: 100, chainWork: 1000n }; }
  getHeader(_h: Buffer) { return undefined; }
  getMedianTimePast() { return 0; }
}
class MockChainDB {
  async getBlock() { return null; }
  async getBlockIndex() { return null; }
  async getBlockHashByHeight() { return null; }
  async getChainWork(): Promise<bigint | null> { return null; }
  async getChainState() { return { bestBlockHash: Buffer.alloc(32, 0), bestHeight: 100 }; }
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

function makeServer(opts?: { walletManager?: any }): { server: RPCServer; port: number } {
  const port = getTestPort();
  const chainState = new MockChainStateManager();
  const config: RPCServerConfig = { port, host: "127.0.0.1", noAuth: true };
  const deps: RPCServerDeps = {
    chainState: chainState as any,
    mempool: new MockMempool() as any,
    peerManager: new MockPeerManager() as any,
    feeEstimator: new MockFeeEstimator() as any,
    headerSync: new MockHeaderSync() as any,
    db: new MockChainDB() as any,
    params: REGTEST,
    walletManager: opts?.walletManager,
  };
  const server = new RPCServer(config, deps);
  server.start();
  return { server, port };
}

/** Sum the output values (sats) of a decoded raw tx. */
function sumOutputs(hex: string): bigint {
  const tx = deserializeTx(new BufferReader(Buffer.from(hex, "hex")));
  return tx.outputs.reduce((acc, o) => acc + o.value, 0n);
}

describe("fundrawtransaction RPC", () => {
  beforeAll(() => {
    mkdirSync(TEST_DATADIR, { recursive: true });
    mkdirSync(`${TEST_DATADIR}/wallets`, { recursive: true });
  });

  let server: RPCServer;
  let port: number;
  let manager: WalletManager;

  beforeEach(async () => {
    rmSync(TEST_DATADIR, { recursive: true, force: true });
    mkdirSync(`${TEST_DATADIR}/wallets`, { recursive: true });
    manager = new WalletManager(TEST_DATADIR, "regtest");
    await manager.createWallet("default", {});
    const out = makeServer({ walletManager: manager });
    server = out.server;
    port = out.port;
  });

  afterEach(async () => {
    server.stop();
    // Drain any debounced wallet flush before the next case (same
    // 250ms-debounce race class as wallet_psbt_rpc).
    await manager.flushAll();
  });

  it("funds a raw tx (no inputs) with real inputs, change, and fee", async () => {
    const wallet = manager.getWallet("default")!;
    const sourceAddr = wallet.getNewAddress("bech32");
    const sourceKey = wallet.getKey(sourceAddr)!;

    // 1 BTC confirmed UTXO under wallet control (same fixture shape as the
    // walletcreatefundedpsbt test).
    wallet.addUTXO({
      outpoint: { txid: Buffer.alloc(32, 0x33), vout: 0 },
      amount: 100_000_000n,
      address: sourceAddr,
      keyPath: sourceKey.path,
      confirmations: 50,
      addressType: AddressType.P2WPKH,
      isCoinbase: false,
    });

    // Build a raw tx with ONE output (0.4 BTC to a fresh address) and NO inputs.
    const destAddr = wallet.getNewAddress("bech32");
    const created = await rpc(port, "createrawtransaction", [
      [],
      [{ [destAddr]: 0.4 }],
    ]);
    expect(created.error).toBeUndefined();
    expect(typeof created.result).toBe("string");
    const rawHex = created.result as string;

    // Pre-fund: no inputs. createrawtransaction emits a legacy (non-witness)
    // tx whose input-count byte is 0x00; the segwit-aware deserializeTx would
    // misread that as a witness marker (the exact ambiguity fundrawtransaction
    // handles), so assert the no-input shape on the raw bytes directly:
    // version(4 bytes) then input-count varint == 0x00.
    const rawBytes = Buffer.from(rawHex, "hex");
    expect(rawBytes[4]).toBe(0x00);

    // Fund it at 1 sat/vB.
    const r = await rpc(port, "fundrawtransaction", [rawHex, { fee_rate: 1 }]);
    expect(r.error).toBeUndefined();

    const { hex, fee, changepos } = r.result;
    expect(typeof hex).toBe("string");
    expect(typeof fee).toBe("number");
    expect(typeof changepos).toBe("number");

    // Fee is genuine and positive.
    expect(fee).toBeGreaterThan(0);

    // The returned hex decodes to the funded tx.
    const funded = deserializeTx(new BufferReader(Buffer.from(hex, "hex")));

    // Inputs were added.
    expect(funded.inputs.length).toBeGreaterThanOrEqual(1);

    // The 0.4 BTC dest output is preserved.
    const destOut = funded.outputs.find((o) => o.value === 40_000_000n);
    expect(destOut).toBeDefined();

    // A change output exists and changepos points at it, consistent with the
    // returned hex (1 BTC funding 0.4 BTC at 1 sat/vB leaves a large change).
    expect(changepos).toBeGreaterThanOrEqual(0);
    expect(changepos).toBeLessThan(funded.outputs.length);
    const changeOut = funded.outputs[changepos];
    expect(changeOut).toBeDefined();
    expect(changeOut.value).toBeGreaterThan(0n);

    // The funded tx is valid: sum(selected inputs) == sum(outputs) + fee.
    // We have one 1 BTC input; outputs = dest + change.
    const feeSats = BigInt(Math.round(fee * 100_000_000));
    const inputValueSats = 100_000_000n * BigInt(funded.inputs.length);
    const outputSum = sumOutputs(hex);
    expect(inputValueSats).toBe(outputSum + feeSats);

    // change == inputs - outputs(non-change, i.e. dest) - fee.
    expect(changeOut.value).toBe(inputValueSats - 40_000_000n - feeSats);

    // Input value covers outputs + fee.
    expect(inputValueSats >= outputSum + feeSats).toBe(true);
  });

  it("fails with insufficient funds when the wallet has no UTXOs", async () => {
    const wallet = manager.getWallet("default")!;
    const dest = wallet.getNewAddress("bech32");
    const created = await rpc(port, "createrawtransaction", [
      [],
      [{ [dest]: 0.1 }],
    ]);
    expect(created.error).toBeUndefined();

    const r = await rpc(port, "fundrawtransaction", [created.result, { fee_rate: 1 }]);
    expect(r.error).toBeDefined();
    expect(r.error.code).toBe(RPCErrorCodes.WALLET_INSUFFICIENT_FUNDS);
  });

  it("rejects a non-hex / undecodable hexstring with -22", async () => {
    const r = await rpc(port, "fundrawtransaction", ["not-a-tx"]);
    expect(r.error).toBeDefined();
    expect(r.error.code).toBe(-22);
  });
});
