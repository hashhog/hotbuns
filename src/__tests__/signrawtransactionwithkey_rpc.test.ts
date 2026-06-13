/**
 * Focused functional test for the wallet-LESS signrawtransactionwithkey RPC.
 *
 * Core ref: bitcoin-core/src/rpc/rawtransaction.cpp::signrawtransactionwithkey.
 *
 * The handler builds a temporary keystore from the explicit WIF keys, merges
 * prevout info from the prevtxs array, and reuses the SAME BIP-143/ECDSA signer
 * (convertToPSBT/updateInputUTXO/signPSBTInput/finalizePSBT) that
 * signrawtransactionwithwallet uses. This test proves:
 *   (a) signing a P2WPKH input with the provided key returns {hex, complete:true};
 *   (b) the produced witness signature VERIFIES against the prevout scriptPubKey
 *       via the impl's OWN script verifier (verifyInputSignature → the full
 *       interpreter + BIP-143 sighash), not merely "witness is non-empty";
 *   (c) an input whose key is NOT provided yields complete:false + an errors[]
 *       entry with Core's TransactionError shape.
 *
 * Unique temp datadir per run; the RPC server is stopped in afterEach. No wallet
 * is created — the method is registered in the non-wallet RPC section.
 */

import { describe, it, expect, beforeEach, afterEach } from "bun:test";
import { rmSync, mkdirSync } from "fs";
import { RPCServer, RPCServerConfig, RPCServerDeps, RPCErrorCodes } from "../rpc/server.js";
import { REGTEST } from "../consensus/params.js";
import {
  deserializeTx,
  serializeTx,
  verifyInputSignature,
  type Transaction,
  type TxOut,
  type SigHashCache,
} from "../validation/tx.js";
import { BufferReader } from "../wire/serialization.js";
import { privateKeyToPublicKey, hash160 } from "../crypto/primitives.js";
import { base58CheckEncode } from "../address/encoding.js";
import type { UTXOEntry } from "../storage/database.js";

const TEST_DATADIR = `/tmp/hotbuns-srtwk-rpc-test-${process.pid}-${Date.now()}`;

let portCounter = 29671;
function getTestPort(): number {
  return portCounter++;
}

class FakeUTXOManager {
  async getUTXOAsync(_outpoint: { txid: Buffer; vout: number }) {
    return null; // Force the handler to rely on the prevtxs array.
  }
}

class MockChainStateManager {
  private bestBlock = { hash: Buffer.alloc(32, 0), height: 100, chainWork: 1000n };
  utxoMgr = new FakeUTXOManager();
  getBestBlock() {
    return { ...this.bestBlock };
  }
  getUTXOManager() {
    return this.utxoMgr;
  }
}

class MockMempool {
  getTransaction(_txid: Buffer) {
    return null;
  }
}
class MockPeerManager {
  getConnectedPeers() {
    return [];
  }
}
class MockFeeEstimator {
  estimateSmartFee() {
    return { feeRate: 10, blocks: 6 };
  }
}
class MockHeaderSync {
  getBestHeader() {
    return { hash: Buffer.alloc(32, 0), height: 100, chainWork: 1000n };
  }
}
class MockChainDB {}

async function rpc(port: number, method: string, params: any[] = []): Promise<any> {
  const r = await fetch(`http://127.0.0.1:${port}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });
  return r.json();
}

/** Encode a 32-byte private key as a compressed regtest WIF (version 0xef). */
function toWIF(privkey: Buffer): string {
  return base58CheckEncode(0xef, Buffer.concat([privkey, Buffer.from([0x01])]));
}

/** Build a P2WPKH scriptPubKey (OP_0 <20-byte pubkeyhash>) for a pubkey. */
function p2wpkhScript(pubkey: Buffer): Buffer {
  return Buffer.concat([Buffer.from([0x00, 0x14]), hash160(pubkey)]);
}

describe("signrawtransactionwithkey (wallet-less)", () => {
  let server: RPCServer;
  let port: number;

  beforeEach(() => {
    rmSync(TEST_DATADIR, { recursive: true, force: true });
    mkdirSync(TEST_DATADIR, { recursive: true });
    port = getTestPort();
    const config: RPCServerConfig = { port, host: "127.0.0.1", noAuth: true };
    const deps: RPCServerDeps = {
      chainState: new MockChainStateManager() as any,
      mempool: new MockMempool() as any,
      peerManager: new MockPeerManager() as any,
      feeEstimator: new MockFeeEstimator() as any,
      headerSync: new MockHeaderSync() as any,
      db: new MockChainDB() as any,
      params: REGTEST,
    };
    server = new RPCServer(config, deps);
    server.start();
  });

  afterEach(() => {
    server.stop();
    rmSync(TEST_DATADIR, { recursive: true, force: true });
  });

  it("signs a P2WPKH input with the provided key; the signature verifies through the impl's own verifier", async () => {
    // Deterministic test key (not real funds).
    const privkey = Buffer.from(
      "1111111111111111111111111111111111111111111111111111111111111111",
      "hex"
    );
    const pubkey = privateKeyToPublicKey(privkey, true);
    const spk = p2wpkhScript(pubkey);
    const prevAmount = 100_000n; // satoshis

    // Fake prevout the tx spends.
    const prevTxidLE = Buffer.alloc(32, 0xab);
    const prevTxidBE = Buffer.from(prevTxidLE).reverse().toString("hex");
    const prevVout = 0;

    // Raw 1-in/1-out spending tx (paying a dummy output). Unsigned: no witness.
    const unsignedTx: Transaction = {
      version: 2,
      inputs: [
        {
          prevOut: { txid: prevTxidLE, vout: prevVout },
          scriptSig: Buffer.alloc(0),
          sequence: 0xffffffff,
          witness: [],
        },
      ],
      outputs: [{ value: 90_000n, scriptPubKey: spk }],
      lockTime: 0,
    };
    const rawHex = serializeTx(unsignedTx, false).toString("hex");

    const res = await rpc(port, "signrawtransactionwithkey", [
      rawHex,
      [toWIF(privkey)],
      [
        {
          txid: prevTxidBE,
          vout: prevVout,
          scriptPubKey: spk.toString("hex"),
          amount: 0.001, // 100_000 sat
        },
      ],
    ]);

    // (a) {hex, complete:true}
    expect(res.error).toBeUndefined();
    expect(res.result.complete).toBe(true);
    expect(typeof res.result.hex).toBe("string");
    expect(res.result.errors).toBeUndefined();

    // (b) Decode the signed tx and verify the input through the impl's OWN
    //     script verifier (full interpreter + BIP-143 sighash) — not just a
    //     non-empty-witness assertion.
    const signedTx = deserializeTx(new BufferReader(Buffer.from(res.result.hex, "hex")));
    expect(signedTx.inputs[0].witness.length).toBe(2); // <sig> <pubkey>

    const utxo: UTXOEntry = {
      height: 1,
      coinbase: false,
      amount: prevAmount,
      scriptPubKey: spk,
    };
    const cache: SigHashCache = {};
    const verify = verifyInputSignature(signedTx, 0, utxo, cache, [utxo]);
    expect(verify.valid).toBe(true);
  });

  it("returns complete:false + an errors[] entry for an input whose key is not provided", async () => {
    // Key A is provided; key B (a second input) is NOT.
    const privA = Buffer.from(
      "2222222222222222222222222222222222222222222222222222222222222222",
      "hex"
    );
    const privB = Buffer.from(
      "3333333333333333333333333333333333333333333333333333333333333333",
      "hex"
    );
    const pubA = privateKeyToPublicKey(privA, true);
    const pubB = privateKeyToPublicKey(privB, true);
    const spkA = p2wpkhScript(pubA);
    const spkB = p2wpkhScript(pubB);

    const prevTxidLE_A = Buffer.alloc(32, 0xa1);
    const prevTxidLE_B = Buffer.alloc(32, 0xb2);
    const prevTxidBE_A = Buffer.from(prevTxidLE_A).reverse().toString("hex");
    const prevTxidBE_B = Buffer.from(prevTxidLE_B).reverse().toString("hex");

    const unsignedTx: Transaction = {
      version: 2,
      inputs: [
        {
          prevOut: { txid: prevTxidLE_A, vout: 0 },
          scriptSig: Buffer.alloc(0),
          sequence: 0xffffffff,
          witness: [],
        },
        {
          prevOut: { txid: prevTxidLE_B, vout: 0 },
          scriptSig: Buffer.alloc(0),
          sequence: 0xfffffffe,
          witness: [],
        },
      ],
      outputs: [{ value: 150_000n, scriptPubKey: spkA }],
      lockTime: 0,
    };
    const rawHex = serializeTx(unsignedTx, false).toString("hex");

    const res = await rpc(port, "signrawtransactionwithkey", [
      rawHex,
      [toWIF(privA)], // only key A — input B cannot be signed
      [
        { txid: prevTxidBE_A, vout: 0, scriptPubKey: spkA.toString("hex"), amount: 0.001 },
        { txid: prevTxidBE_B, vout: 0, scriptPubKey: spkB.toString("hex"), amount: 0.001 },
      ],
    ]);

    expect(res.error).toBeUndefined();
    expect(res.result.complete).toBe(false);
    expect(Array.isArray(res.result.errors)).toBe(true);
    expect(res.result.errors.length).toBe(1);
    const err = res.result.errors[0];
    // Core TransactionError shape: txid, vout, witness, scriptSig, sequence, error.
    expect(err.txid).toBe(prevTxidBE_B);
    expect(err.vout).toBe(0);
    expect(err.sequence).toBe(0xfffffffe);
    expect(Array.isArray(err.witness)).toBe(true);
    expect(typeof err.scriptSig).toBe("string");
    expect(typeof err.error).toBe("string");
  });

  it("rejects an invalid WIF private key with -5", async () => {
    const unsignedTx: Transaction = {
      version: 2,
      inputs: [
        {
          prevOut: { txid: Buffer.alloc(32, 0xcc), vout: 0 },
          scriptSig: Buffer.alloc(0),
          sequence: 0xffffffff,
          witness: [],
        },
      ],
      outputs: [{ value: 1n, scriptPubKey: Buffer.from([0x6a]) }],
      lockTime: 0,
    };
    const rawHex = serializeTx(unsignedTx, false).toString("hex");
    const res = await rpc(port, "signrawtransactionwithkey", [rawHex, ["not-a-wif"], []]);
    expect(res.error).toBeDefined();
    expect(res.error.code).toBe(RPCErrorCodes.INVALID_ADDRESS_OR_KEY);
  });
});
