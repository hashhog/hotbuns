/**
 * DIV-hotbuns-044 live-shaped probe: taproot key-path spend through the
 * real RPC wire path (sendrawtransaction → ATMP → getrawmempool).
 *
 * Runs a regtest-params node core (real ChainDB + UTXOManager + Mempool +
 * RPCServer over HTTP on an off-default port), creates and funds a P2TR
 * output, spends it via `sendrawtransaction` with a BIP-341 key-path
 * signature, and asserts:
 *   1. sendrawtransaction returns the txid (accepted, no -26 rejection);
 *   2. getrawmempool contains the txid;
 *   3. an invalid schnorr sig is rejected with RPC code -26 and a
 *      SCHNORR_SIG reason — a clean rejection, not a connection-killing /
 *      log-flooding unhandled throw (the 2026-07-10 incident mode);
 *   4. the RPC server still answers after the rejection (event loop alive).
 *
 * Usage:  bun run src/test/taproot_mempool_probe.ts [port]
 * Exit 0 = PASS, non-zero = FAIL. Intended as redeploy-closure evidence for
 * hotbuns#6 (the differential harness only checks BLOCK decisions; this
 * exercises the MEMPOOL path end-to-end).
 *
 * NOTE: the mempool derives script flags from tipHeight via
 * getStandardFlags()/getConsensusFlags(), which gate verifyTaproot on the
 * MAINNET BIP-341 activation height (709632) regardless of network params
 * (pre-existing wart; the block path got per-network flags in the
 * BUG-11/BUG-30 fix, the mempool did not). The probe pins
 * tipHeight = 900_000 to reproduce the live-mainnet flag configuration in
 * which DIV-hotbuns-044 fires; at a natural regtest height the taproot
 * branch is never reached and P2TR inputs are not verified at all.
 */

import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ChainDB, type UTXOEntry } from "../storage/database.js";
import { UTXOManager } from "../chain/utxo.js";
import { REGTEST } from "../consensus/params.js";
import { Mempool } from "../mempool/mempool.js";
import { RPCServer, type RPCServerConfig, type RPCServerDeps } from "../rpc/server.js";
import type { Transaction } from "../validation/tx.js";
import {
  getTxId,
  serializeTx,
  sigHashTaprootKeyPath,
} from "../validation/tx.js";
import {
  taggedHash,
  privateKeyToXOnlyPubKey,
  tweakPrivateKey,
  tweakPublicKey,
  schnorrSign,
} from "../crypto/primitives.js";

const PORT = Number(process.argv[2] ?? 28461); // off-default (regtest RPC is 18443)
const TIP_HEIGHT = 900_000;
const UTXO_VALUE = 100_000n;
const FEE = 10_000n;

let failures = 0;
function check(label: string, ok: boolean, detail?: string): void {
  const status = ok ? "PASS" : "FAIL";
  console.log(`[${status}] ${label}${detail ? ` — ${detail}` : ""}`);
  if (!ok) failures++;
}

async function rpc(method: string, params: unknown[] = []): Promise<any> {
  const response = await fetch(`http://127.0.0.1:${PORT}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });
  return response.json();
}

async function main(): Promise<void> {
  const tempDir = await mkdtemp(join(tmpdir(), "taproot-probe-"));
  const db = new ChainDB(tempDir);
  await db.open();
  const utxo = new UTXOManager(db);
  const mempool = new Mempool(utxo, REGTEST, 5_000_000);
  mempool.setTipHeight(TIP_HEIGHT);

  // --- create + fund a P2TR output (BIP-341 key-path, no script tree) ---
  const internalPriv = Buffer.alloc(32, 0x2a);
  const internalPub = privateKeyToXOnlyPubKey(internalPriv);
  const tweak = taggedHash("TapTweak", internalPub);
  const outputKey = tweakPublicKey(internalPub, tweak);
  const outputPriv = tweakPrivateKey(internalPriv, tweak);
  const spk = Buffer.concat([Buffer.from([0x51, 0x20]), outputKey]);

  const fundingTxid = Buffer.alloc(32, 0xf1);
  const entry: UTXOEntry = {
    height: TIP_HEIGHT - 1000,
    coinbase: false,
    amount: UTXO_VALUE,
    scriptPubKey: spk,
  };
  await db.putUTXO(fundingTxid, 0, entry);

  // --- minimal RPC server around the REAL mempool ---
  const noPeers = { getConnectedPeers: () => [] };
  const config: RPCServerConfig = { port: PORT, host: "127.0.0.1", noAuth: true };
  const deps = {
    chainState: {} as any,
    mempool,
    peerManager: noPeers as any,
    feeEstimator: {} as any,
    headerSync: {} as any,
    db,
    params: REGTEST,
  } satisfies RPCServerDeps;
  const server = new RPCServer(config, deps);
  server.start();

  try {
    // --- build + sign the key-path spend ---
    const buildSpend = (): Transaction => ({
      version: 2,
      inputs: [
        {
          prevOut: { txid: fundingTxid, vout: 0 },
          scriptSig: Buffer.alloc(0),
          sequence: 0xfffffffd,
          witness: [],
        },
      ],
      outputs: [
        { value: UTXO_VALUE - FEE, scriptPubKey: Buffer.from([0x51, 0x02, 0x4e, 0x73]) },
        { value: 0n, scriptPubKey: Buffer.from([0x6a]) }, // min-size pad
      ],
      lockTime: 0,
    });

    const tx = buildSpend();
    const prevOuts = [{ scriptPubKey: spk, value: UTXO_VALUE }];
    const sighash = sigHashTaprootKeyPath(tx, 0, prevOuts, 0x00, undefined, {});
    tx.inputs[0].witness = [schnorrSign(sighash, outputPriv)];
    const txHex = serializeTx(tx, true).toString("hex");
    const txidHex = Buffer.from(getTxId(tx)).reverse().toString("hex");

    // 1. sendrawtransaction accepts the key-path spend.
    const sendRes = await rpc("sendrawtransaction", [txHex]);
    check(
      "sendrawtransaction accepts P2TR key-path spend",
      sendRes.result === txidHex,
      sendRes.error ? `rpc error ${sendRes.error.code}: ${sendRes.error.message}` : `txid ${sendRes.result}`
    );

    // 2. getrawmempool contains it.
    const mempoolRes = await rpc("getrawmempool", []);
    check(
      "getrawmempool contains the txid",
      Array.isArray(mempoolRes.result) && mempoolRes.result.includes(txidHex),
      JSON.stringify(mempoolRes.result)
    );

    // 3. Invalid schnorr sig → clean -26 rejection with SCHNORR_SIG reason.
    const fundingTxid2 = Buffer.alloc(32, 0xf2);
    await db.putUTXO(fundingTxid2, 0, entry);
    const badTx = buildSpend();
    badTx.inputs[0].prevOut = { txid: fundingTxid2, vout: 0 };
    const badSighash = sigHashTaprootKeyPath(badTx, 0, prevOuts, 0x00, undefined, {});
    const badSig = schnorrSign(badSighash, outputPriv);
    badSig[10] ^= 0xff;
    badTx.inputs[0].witness = [badSig];
    const badRes = await rpc("sendrawtransaction", [serializeTx(badTx, true).toString("hex")]);
    check(
      "invalid schnorr sig rejected with RPC -26 + SCHNORR_SIG reason",
      badRes.error?.code === -26 && String(badRes.error?.message).includes("SCHNORR_SIG"),
      badRes.error ? `code ${badRes.error.code}: ${badRes.error.message}` : `unexpectedly accepted: ${badRes.result}`
    );

    // 4. RPC still alive after the rejection (2026-07-10 failure mode was a
    //    starved event loop / unresponsive RPC).
    const aliveRes = await rpc("getrawmempool", []);
    check(
      "RPC responsive after rejection; valid tx still in mempool",
      Array.isArray(aliveRes.result) && aliveRes.result.includes(txidHex) && aliveRes.result.length === 1,
      JSON.stringify(aliveRes.result)
    );
  } finally {
    server.stop();
    await db.close();
    await rm(tempDir, { recursive: true, force: true });
  }

  console.log(failures === 0 ? "PROBE RESULT: PASS" : `PROBE RESULT: FAIL (${failures} check(s) failed)`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error("PROBE RESULT: FAIL (unhandled error)", e);
  process.exit(2);
});
