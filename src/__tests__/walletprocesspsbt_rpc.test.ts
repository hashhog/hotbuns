/**
 * walletprocesspsbt RPC — focused functional test (hotbuns).
 *
 * Covers the UPDATER + SIGNER + FINALIZER roles wired into
 * `RPCServer.walletProcessPSBT` (src/rpc/server.ts). The handler reuses the
 * existing PSBT signer engine (convertToPSBT / updateInputUTXO / signPSBTInput
 * / finalizePSBT / extractTransaction in src/wallet/psbt.ts) — the same code
 * signrawtransactionwithwallet drives — so this test exercises that path
 * end-to-end against a real RPCServer.
 *
 * Reference: bitcoin-core/src/wallet/rpc/spend.cpp::walletprocesspsbt
 *   - Params: "psbt" ( sign sighashtype bip32derivs finalize )
 *   - Result: { psbt: <base64>, complete: <bool> } + { hex } WHEN complete.
 *
 * The decisive assertion (c) does NOT just check a sig field is non-empty: it
 * decodes the finalized network tx and re-verifies every input through the
 * impl's OWN script interpreter (verifyAllInputsSequential), so a fabricated /
 * wrong-sighash signature would fail.
 *
 * Run: bun test src/__tests__/walletprocesspsbt_rpc.test.ts
 */

import { describe, it, expect, beforeEach, afterEach } from "bun:test";
import { rmSync, mkdirSync } from "fs";
import { RPCServer, RPCServerConfig, RPCServerDeps, RPCErrorCodes } from "../rpc/server.js";
import { REGTEST } from "../consensus/params.js";
import { WalletManager } from "../wallet/wallet.js";
import {
  decodePSBTBase64,
} from "../wallet/psbt.js";
import {
  deserializeTx,
  verifyAllInputsSequential,
  type Transaction,
} from "../validation/tx.js";
import type { UTXOEntry } from "../storage/database.js";
import { hash160 } from "../crypto/primitives.js";
import { BufferReader } from "../wire/serialization.js";

const TEST_DATADIR = "/tmp/hotbuns-walletprocesspsbt-rpc-test";

// Randomised per-process port band (mirrors the 26682fc watchonly
// fix): each test file draws from a distinct band plus a random
// offset. Every band must stay BELOW the Linux client ephemeral
// range (ip_local_port_range 32768-60999) — a band inside it can
// collide with a kernel-assigned fetch() client socket and fail
// EADDRINUSE (observed on CI: ports 39450, 59180).
let portCounter = 21000 + Math.floor(Math.random() * 1000);
function getTestPort(): number {
  return portCounter++;
}

/** Minimal chainstate UTXO store the handler's UPDATER reads from. */
class FakeUTXOManager {
  private utxos = new Map<string, UTXOEntry>();
  setUTXO(txid: Buffer, vout: number, entry: UTXOEntry) {
    this.utxos.set(`${txid.toString("hex")}:${vout}`, entry);
  }
  async getUTXOAsync(outpoint: { txid: Buffer; vout: number }) {
    return this.utxos.get(`${outpoint.txid.toString("hex")}:${outpoint.vout}`) ?? null;
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
class MockPeerManager { getConnectedPeers() { return []; } broadcast(_m: any) {} }
class MockFeeEstimator { estimateSmartFee() { return { feeRate: 10, blocks: 6 }; } getBuckets() { return []; } }
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

/** P2WPKH scriptPubKey (OP_0 <hash160(pubkey)>) for a wallet pubkey. */
function p2wpkhScript(pubkey: Buffer): Buffer {
  return Buffer.concat([Buffer.from([0x00, 0x14]), hash160(pubkey)]);
}

describe("walletprocesspsbt RPC", () => {
  let server: RPCServer;
  let port: number;
  let chainState: MockChainStateManager;
  let manager: WalletManager;

  beforeEach(async () => {
    rmSync(TEST_DATADIR, { recursive: true, force: true });
    mkdirSync(`${TEST_DATADIR}/wallets`, { recursive: true });
    manager = new WalletManager(TEST_DATADIR, "regtest");
    await manager.createWallet("default", {});

    port = getTestPort();
    chainState = new MockChainStateManager();
    const config: RPCServerConfig = { port, host: "127.0.0.1", noAuth: true };
    const deps: RPCServerDeps = {
      chainState: chainState as any,
      mempool: new MockMempool() as any,
      peerManager: new MockPeerManager() as any,
      feeEstimator: new MockFeeEstimator() as any,
      headerSync: new MockHeaderSync() as any,
      db: new MockChainDB() as any,
      params: REGTEST,
      walletManager: manager,
    };
    server = new RPCServer(config, deps);
    server.start();
  });

  afterEach(async () => {
    server.stop();
    // Drain any debounced wallet flush before the next case (same
    // 250ms-debounce race class as wallet_psbt_rpc).
    await manager.flushAll();
  });

  it("updates + signs + finalizes a single wallet-input PSBT, and the sig VERIFIES", async () => {
    const wallet = manager.getWallet("default")!;
    const srcAddr = wallet.getNewAddress("bech32");
    const srcKey = wallet.getKey(srcAddr)!;
    const srcSpk = p2wpkhScript(srcKey.publicKey);

    // A confirmed 1-BTC P2WPKH UTXO owned by the wallet, sitting in chainstate.
    // The handler's UPDATER role looks it up by outpoint and attaches it to the
    // PSBT — the PSBT itself starts with NO utxo data (textual createpsbt).
    const prevTxidLE = Buffer.alloc(32, 0x77);
    const prevVout = 0;
    chainState.utxoMgr.setUTXO(prevTxidLE, prevVout, {
      height: 50,
      coinbase: false,
      amount: 100_000_000n,
      scriptPubKey: srcSpk,
    });

    // Build an unsigned PSBT spending that UTXO to a fresh wallet address.
    const destAddr = wallet.getNewAddress("bech32");
    const prevTxidBE = Buffer.from(prevTxidLE).reverse().toString("hex");
    const created = await rpc(port, "createpsbt", [
      [{ txid: prevTxidBE, vout: prevVout }],
      [{ [destAddr]: 0.999 }], // 1 BTC in, ~0.001 BTC fee
      0,
    ]);
    expect(created.error).toBeUndefined();
    const unsignedPsbtB64: string = created.result;

    // Sanity: the unsigned PSBT has NO utxo data and NO partial sig.
    const before = decodePSBTBase64(unsignedPsbtB64);
    expect(before.inputs[0].witnessUtxo).toBeUndefined();
    expect(before.inputs[0].nonWitnessUtxo).toBeUndefined();
    expect(before.inputs[0].partialSigs.size).toBe(0);

    // ── walletprocesspsbt: sign + finalize (Core defaults).
    const r = await rpc(port, "walletprocesspsbt", [unsignedPsbtB64]);
    expect(r.error).toBeUndefined();

    // (b) complete=true for a single wallet-input PSBT.
    expect(r.result.complete).toBe(true);

    // (a) returned psbt is valid base64 that round-trips.
    expect(typeof r.result.psbt).toBe("string");
    const back = decodePSBTBase64(r.result.psbt);
    expect(back.inputs.length).toBe(1);
    // The UPDATER attached the witness UTXO; the SIGNER finalized the input.
    expect(back.inputs[0].witnessUtxo).toBeDefined();
    expect(back.inputs[0].witnessUtxo!.value).toBe(100_000_000n);
    expect(back.inputs[0].finalScriptWitness).toBeDefined();

    // Core v31.99 emits `hex` (the finalized network tx) WHEN complete.
    expect(typeof r.result.hex).toBe("string");

    // (c) ⭐ DECODE the finalized tx and re-verify the produced signature
    // through the impl's OWN script interpreter against the real prevout
    // scriptPubKey + value. A fabricated / wrong-sighash sig fails here.
    const finalTx: Transaction = deserializeTx(new BufferReader(Buffer.from(r.result.hex, "hex")));
    expect(finalTx.inputs.length).toBe(1);
    // The witness must carry a real <sig> <pubkey> (P2WPKH spend).
    expect(finalTx.inputs[0].witness.length).toBe(2);
    expect(finalTx.inputs[0].witness[0].length).toBeGreaterThan(0); // DER sig + sighash byte
    expect(finalTx.inputs[0].witness[0][finalTx.inputs[0].witness[0].length - 1]).toBe(0x01); // SIGHASH_ALL

    const prevOuts: UTXOEntry[] = [{
      height: 50,
      coinbase: false,
      amount: 100_000_000n,
      scriptPubKey: srcSpk,
    }];
    const verdict = verifyAllInputsSequential(finalTx, prevOuts);
    expect(verdict.valid).toBe(true);
  });

  it("sign=false leaves the input unsigned: complete=false, no hex", async () => {
    const wallet = manager.getWallet("default")!;
    const srcAddr = wallet.getNewAddress("bech32");
    const srcKey = wallet.getKey(srcAddr)!;
    const srcSpk = p2wpkhScript(srcKey.publicKey);

    const prevTxidLE = Buffer.alloc(32, 0x88);
    chainState.utxoMgr.setUTXO(prevTxidLE, 0, {
      height: 50, coinbase: false, amount: 50_000_000n, scriptPubKey: srcSpk,
    });

    const destAddr = wallet.getNewAddress("bech32");
    const prevTxidBE = Buffer.from(prevTxidLE).reverse().toString("hex");
    const created = await rpc(port, "createpsbt", [
      [{ txid: prevTxidBE, vout: 0 }],
      [{ [destAddr]: 0.4999 }],
      0,
    ]);
    expect(created.error).toBeUndefined();

    // sign=false → UPDATER still runs (fills witness UTXO), but no signature.
    const r = await rpc(port, "walletprocesspsbt", [created.result, false]);
    expect(r.error).toBeUndefined();
    expect(r.result.complete).toBe(false);
    expect(r.result.hex).toBeUndefined();
    const back = decodePSBTBase64(r.result.psbt);
    // UPDATER attached the UTXO data the wallet knows, even with sign=false.
    expect(back.inputs[0].witnessUtxo).toBeDefined();
    expect(back.inputs[0].witnessUtxo!.value).toBe(50_000_000n);
    // But no partial sig and not finalized.
    expect(back.inputs[0].partialSigs.size).toBe(0);
    expect(back.inputs[0].finalScriptWitness).toBeUndefined();
  });

  it("finalize=false signs but does not collapse: complete=false, partial sig present", async () => {
    const wallet = manager.getWallet("default")!;
    const srcAddr = wallet.getNewAddress("bech32");
    const srcKey = wallet.getKey(srcAddr)!;
    const srcSpk = p2wpkhScript(srcKey.publicKey);

    const prevTxidLE = Buffer.alloc(32, 0x99);
    chainState.utxoMgr.setUTXO(prevTxidLE, 0, {
      height: 50, coinbase: false, amount: 70_000_000n, scriptPubKey: srcSpk,
    });

    const destAddr = wallet.getNewAddress("bech32");
    const prevTxidBE = Buffer.from(prevTxidLE).reverse().toString("hex");
    const created = await rpc(port, "createpsbt", [
      [{ txid: prevTxidBE, vout: 0 }],
      [{ [destAddr]: 0.6999 }],
      0,
    ]);

    // sign=true, finalize=false → a partial sig is attached but not collapsed.
    const r = await rpc(port, "walletprocesspsbt", [created.result, true, "ALL", true, false]);
    expect(r.error).toBeUndefined();
    expect(r.result.complete).toBe(false);
    expect(r.result.hex).toBeUndefined();
    const back = decodePSBTBase64(r.result.psbt);
    expect(back.inputs[0].partialSigs.size).toBe(1);
    expect(back.inputs[0].finalScriptWitness).toBeUndefined();
  });

  it("rejects an invalid sighashtype string with -8", async () => {
    const wallet = manager.getWallet("default")!;
    const destAddr = wallet.getNewAddress("bech32");
    const created = await rpc(port, "createpsbt", [
      [{ txid: Buffer.alloc(32, 0x55).reverse().toString("hex"), vout: 0 }],
      [{ [destAddr]: 0.1 }],
      0,
    ]);
    const r = await rpc(port, "walletprocesspsbt", [created.result, true, "BOGUS"]);
    expect(r.error).toBeDefined();
    expect(r.error.code).toBe(RPCErrorCodes.INVALID_PARAMS);
  });

  it("rejects a non-string psbt param", async () => {
    const r = await rpc(port, "walletprocesspsbt", [12345]);
    expect(r.error).toBeDefined();
    expect(r.error.code).toBe(RPCErrorCodes.INVALID_PARAMS);
  });
});
