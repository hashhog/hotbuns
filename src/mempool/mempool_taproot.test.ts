/**
 * DIV-hotbuns-044 regression tests: mempool admission of taproot spends.
 *
 * INCIDENT
 * --------
 * The mempool's ATMP script check (`addTransaction` → `verifyAllInputs`)
 * called `verifyScript(..., sigHasher, undefined, ...)` — the 6th (taproot
 * context) argument was literally `undefined`, and the local sigHasher only
 * dispatched legacy + witness-v0 sighash. Every P2TR key-path spend arriving
 * via live P2P tx relay therefore threw
 * SCRIPT_ERR_TAPROOT_CONTEXT_MISSING out of `verifyTaprootKeyPath`
 * (interpreter.ts) and was dropped from the mempool — 8720 occurrences in
 * the final 5MB of the 2026-07-10 mainnet restart.log. Block validation was
 * NOT affected (validation/tx.ts builds a proper TaprootContext), so this
 * was a relay-layer gap, not a block-accept divergence.
 *
 * FIX
 * ---
 * `mempool.ts` now gathers all-prevouts (scriptPubKey, amount) — already
 * resolved during input lookup — and builds the same BIP-341 TaprootContext
 * the block path uses (shared `buildTaprootContext` in validation/tx.ts),
 * passing it through `verifyScript`. Script errors are caught and mapped to
 * a clean reject reason. Mirrors Bitcoin Core, where mempool and block
 * paths share PrecomputedTransactionData: CheckInputScripts gathers every
 * spent coin into `txdata.Init(tx, spent_outputs)`
 * (validation.cpp:2086-2097) before SignatureHashSchnorr consumes the
 * all-prevouts hashes (interpreter.cpp:1447-1449, 1483-1503).
 *
 * These tests drive the MEMPOOL entry point (`mempool.addTransaction`) with
 * fully-signed taproot spends — the differential harness only checks BLOCK
 * decisions, so this is the path no other test covered. All three tests
 * FAIL at the parent commit (key/script-path: unhandled
 * TAPROOT_CONTEXT_MISSING throw; invalid-sig: throw instead of clean
 * reject) and PASS with the fix.
 *
 * NOTE on tip height: the mempool derives script flags from tipHeight via
 * getStandardFlags()/getConsensusFlags(), which gate verifyTaproot on the
 * mainnet BIP-341 activation height (709632). The tests pin
 * tipHeight = 900_000 to reproduce the live-mainnet configuration where the
 * bug fires; below that height P2TR inputs are not taproot-verified at all.
 */

import { describe, test, expect, beforeEach, afterEach } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ChainDB, type UTXOEntry } from "../storage/database.js";
import { UTXOManager } from "../chain/utxo.js";
import { REGTEST } from "../consensus/params.js";
import { Mempool } from "./mempool.js";
import type { Transaction } from "../validation/tx.js";
import {
  getTxId,
  sigHashTaprootKeyPath,
  sigHashTaprootScriptPath,
} from "../validation/tx.js";
import {
  taggedHash,
  privateKeyToXOnlyPubKey,
  tweakPrivateKey,
  tweakPublicKey,
  schnorrSign,
} from "../crypto/primitives.js";

// BIP-342 tapscript leaf version.
const TAPROOT_LEAF_TAPSCRIPT = 0xc0;
// Live-mainnet-shaped heights (see file header NOTE).
const TIP_HEIGHT = 900_000;
const UTXO_HEIGHT = 800_000;
const UTXO_VALUE = 100_000n;
const FEE = 10_000n;

function makeP2TR(xonly: Buffer): Buffer {
  if (xonly.length !== 32) throw new Error("expected 32B x-only key");
  return Buffer.concat([Buffer.from([0x51, 0x20]), xonly]);
}

function encodeCompactSize(n: number): Buffer {
  if (n < 0xfd) return Buffer.from([n]);
  throw new Error("compact size >= 0xfd not needed here");
}

describe("Mempool taproot admission (DIV-hotbuns-044)", () => {
  let tempDir: string;
  let db: ChainDB;
  let utxo: UTXOManager;
  let mempool: Mempool;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "mempool-taproot-test-"));
    db = new ChainDB(tempDir);
    await db.open();
    utxo = new UTXOManager(db);
    mempool = new Mempool(utxo, REGTEST, 1_000_000);
    mempool.setTipHeight(TIP_HEIGHT);
  });

  afterEach(async () => {
    await db.close();
    await rm(tempDir, { recursive: true, force: true });
  });

  async function fundP2TR(prevTxid: Buffer, scriptPubKey: Buffer): Promise<void> {
    const entry: UTXOEntry = {
      height: UTXO_HEIGHT,
      coinbase: false,
      amount: UTXO_VALUE,
      scriptPubKey,
    };
    await db.putUTXO(prevTxid, 0, entry);
  }

  /** Single-input spend of (prevTxid, 0); witness attached after signing. */
  function buildSpend(prevTxid: Buffer): Transaction {
    return {
      version: 2,
      inputs: [
        {
          prevOut: { txid: prevTxid, vout: 0 },
          scriptSig: Buffer.alloc(0),
          sequence: 0xfffffffd,
          witness: [],
        },
      ],
      outputs: [
        // P2A (anchor) output — standard, no signing material needed.
        { value: UTXO_VALUE - FEE, scriptPubKey: Buffer.from([0x51, 0x02, 0x4e, 0x73]) },
        // Bare OP_RETURN pad: keeps non-witness size >= 65 bytes
        // (MIN_STANDARD_TX_NONWITNESS_SIZE, CVE-2017-12842 gate).
        { value: 0n, scriptPubKey: Buffer.from([0x6a]) },
      ],
      lockTime: 0,
    };
  }

  test("valid P2TR key-path spend is ACCEPTED into the mempool", async () => {
    // BIP-341 key-path: Q = P + hash_TapTweak(x(P))*G, sign with tweaked key.
    const internalPriv = Buffer.alloc(32, 7);
    const internalPub = privateKeyToXOnlyPubKey(internalPriv);
    const tweak = taggedHash("TapTweak", internalPub); // no script tree
    const outputKey = tweakPublicKey(internalPub, tweak);
    const outputPriv = tweakPrivateKey(internalPriv, tweak);
    const spk = makeP2TR(outputKey);

    const prevTxid = Buffer.alloc(32, 0xa1);
    await fundP2TR(prevTxid, spk);

    const tx = buildSpend(prevTxid);
    const prevOuts = [{ scriptPubKey: spk, value: UTXO_VALUE }];
    // SIGHASH_DEFAULT (0x00) → 64-byte signature, no explicit hashtype byte.
    const sighash = sigHashTaprootKeyPath(tx, 0, prevOuts, 0x00, undefined, {});
    tx.inputs[0].witness = [schnorrSign(sighash, outputPriv)];

    const result = await mempool.addTransaction(tx);
    expect(result.error).toBeUndefined();
    expect(result.accepted).toBe(true);
    expect(mempool.getSize()).toBe(1);
    // getrawmempool-visible: the tx is retrievable by txid.
    expect(mempool.hasTransaction(getTxId(tx))).toBe(true);
  });

  test("valid P2TR script-path (tapscript CHECKSIG) spend is ACCEPTED into the mempool", async () => {
    const internalPriv = Buffer.alloc(32, 9);
    const internalPub = privateKeyToXOnlyPubKey(internalPriv);
    const leafPriv = Buffer.alloc(32, 11);
    const leafPub = privateKeyToXOnlyPubKey(leafPriv);

    // Leaf: <32B pubkey> OP_CHECKSIG — exercises scriptPathSigHasher.
    const leafScript = Buffer.concat([
      Buffer.from([0x20]),
      leafPub,
      Buffer.from([0xac]),
    ]);
    const leafHash = taggedHash(
      "TapLeaf",
      Buffer.concat([
        Buffer.from([TAPROOT_LEAF_TAPSCRIPT]),
        encodeCompactSize(leafScript.length),
        leafScript,
      ])
    );
    const tweak = taggedHash("TapTweak", Buffer.concat([internalPub, leafHash]));
    const outputKey = tweakPublicKey(internalPub, tweak);
    const spk = makeP2TR(outputKey);

    const prevTxid = Buffer.alloc(32, 0xa2);
    await fundP2TR(prevTxid, spk);

    const tx = buildSpend(prevTxid);
    const prevOuts = [{ scriptPubKey: spk, value: UTXO_VALUE }];
    const sighash = sigHashTaprootScriptPath(
      tx, 0, prevOuts, 0x00, undefined, leafHash, 0xffffffff, {}
    );
    const sig = schnorrSign(sighash, leafPriv);

    // tweakPublicKey yields only the x-coordinate; the control block commits
    // to the output key's Y parity. Try both — exactly one matches (the
    // other is cleanly rejected with WITNESS_PROGRAM_MISMATCH).
    let accepted = false;
    let lastError: string | undefined;
    for (const parity of [0, 1]) {
      tx.inputs[0].witness = [
        sig,
        leafScript,
        Buffer.concat([Buffer.from([TAPROOT_LEAF_TAPSCRIPT | parity]), internalPub]),
      ];
      const result = await mempool.addTransaction(tx);
      if (result.accepted) {
        accepted = true;
        break;
      }
      lastError = result.error;
    }
    expect(accepted).toBe(true);
    expect(mempool.getSize()).toBe(1);
    expect(mempool.hasTransaction(getTxId(tx))).toBe(true);
    void lastError;
  });

  test("P2TR key-path spend with invalid schnorr sig is REJECTED with a clean reason (no throw)", async () => {
    const internalPriv = Buffer.alloc(32, 13);
    const internalPub = privateKeyToXOnlyPubKey(internalPriv);
    const tweak = taggedHash("TapTweak", internalPub);
    const outputKey = tweakPublicKey(internalPub, tweak);
    const outputPriv = tweakPrivateKey(internalPriv, tweak);
    const spk = makeP2TR(outputKey);

    const prevTxid = Buffer.alloc(32, 0xa3);
    await fundP2TR(prevTxid, spk);

    const tx = buildSpend(prevTxid);
    const prevOuts = [{ scriptPubKey: spk, value: UTXO_VALUE }];
    const sighash = sigHashTaprootKeyPath(tx, 0, prevOuts, 0x00, undefined, {});
    const sig = schnorrSign(sighash, outputPriv);
    sig[10] ^= 0xff; // corrupt the signature
    tx.inputs[0].witness = [sig];

    // Must resolve to a rejection — NOT reject the promise. Pre-fix this
    // threw SCRIPT_ERR_TAPROOT_CONTEXT_MISSING out of addTransaction (the
    // unhandled-rejection flood of 2026-07-10).
    const result = await mempool.addTransaction(tx);
    expect(result.accepted).toBe(false);
    expect(result.error).toContain("SCHNORR_SIG");
    expect(mempool.getSize()).toBe(0);
    expect(mempool.hasTransaction(getTxId(tx))).toBe(false);
  });
});
