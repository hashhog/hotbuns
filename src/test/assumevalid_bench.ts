/**
 * Microbenchmark: assumevalid skip path vs script-verify path.
 *
 * Measures the cost of:
 *  A) VERIFY path: evaluating shouldSkipScripts() → false, then running
 *     verifyScript (secp256k1 ECDSA) for each input.
 *  B) SKIP path: evaluating shouldSkipScripts() → true, returning early
 *     without calling verifyScript.
 *
 * Since hotbuns's IBD path does not currently invoke script verification
 * (P2-OPT-ROUND-2 gap), we cannot measure an IBD speedup directly.
 * Instead, this benchmark exercises the verifyScript / shouldSkipScripts
 * paths directly and asserts that the skip path is materially faster.
 *
 * Expected result: skip path should be >50x faster than verify path,
 * since verifyScript involves secp256k1 EC operations (libsecp256k1 FFI)
 * while shouldSkipScripts is a handful of map lookups and integer comparisons.
 */

import {
  shouldSkipScripts,
  type AssumeValidContext,
  type AssumeValidBlockEntry,
} from "../consensus/assumevalid.js";
import {
  verifyScript,
  getConsensusFlags,
} from "../script/interpreter.js";
import { ecdsaSign, hash160 } from "../crypto/primitives.js";
import { sigHashLegacy } from "../validation/tx.js";
import type { Transaction } from "../validation/tx.js";
import { secp256k1 } from "@noble/curves/secp256k1.js";

// ---------------------------------------------------------------------------
// Build a valid P2PKH scriptSig/scriptPubKey pair for verifyScript benchmarks
// ---------------------------------------------------------------------------

const privKey = Buffer.alloc(32, 0x42);

// Derive compressed public key.
const privKeyBigInt = BigInt("0x" + privKey.toString("hex"));
const pubKeyPoint = secp256k1.Point.BASE.multiply(privKeyBigInt);
const pubKey = Buffer.from(pubKeyPoint.toBytes(true)); // 33 bytes compressed

// Build P2PKH scriptPubKey.
const h160 = hash160(pubKey);
const scriptPubKey = Buffer.concat([
  Buffer.from([0x76, 0xa9, 0x14]),  // OP_DUP OP_HASH160 OP_PUSH20
  h160,
  Buffer.from([0x88, 0xac]),         // OP_EQUALVERIFY OP_CHECKSIG
]);

// Build a minimal transaction.
const prevTxHash = Buffer.alloc(32, 0xab);
const tx: Transaction = {
  version: 1,
  inputs: [
    {
      prevOut: { txid: prevTxHash, vout: 0 },
      scriptSig: Buffer.alloc(0),
      sequence: 0xffffffff,
      witness: [],
    },
  ],
  outputs: [
    {
      value: 50_00000000n,
      scriptPubKey,
    },
  ],
  lockTime: 0,
};

// Build the subscript and sign.
const subscript = Buffer.concat([
  Buffer.from([0x76, 0xa9, 0x14]),
  h160,
  Buffer.from([0x88, 0xac]),
]);
const sighash = sigHashLegacy(tx, 0, subscript, 0x01);
const derSig = ecdsaSign(sighash, privKey); // returns DER-encoded Buffer
const derSigWithType = Buffer.concat([derSig, Buffer.from([0x01])]); // SIGHASH_ALL

// Build scriptSig: OP_DATA<sig> OP_DATA<pubkey>
const scriptSig = Buffer.concat([
  Buffer.from([derSigWithType.length]),
  derSigWithType,
  Buffer.from([pubKey.length]),
  pubKey,
]);

const witness: Buffer[] = [];
const flags = getConsensusFlags(500000);
const sigHasher = (sub: Buffer, ht: number) => sigHashLegacy(tx, 0, sub, ht);

// Verify the fixture is actually valid before benchmarking.
const fixtureValid = verifyScript(scriptSig, scriptPubKey, witness, flags, sigHasher);
if (!fixtureValid) {
  console.error("ERROR: P2PKH fixture failed verification — fixture construction bug");
  process.exit(1);
}

// ---------------------------------------------------------------------------
// Build assumevalid contexts
// ---------------------------------------------------------------------------

const TWO_WEEKS_PLUS = 60 * 60 * 24 * 7 * 2 + 1;
const AV_HASH = "aaaa000000000000000000000000000000000000000000000000000000000001";
const AV_HEIGHT = 938343;
const ANCESTOR_HASH = "bbbb000000000000000000000000000000000000000000000000000000000002";
const ANCESTOR_HEIGHT = 500_000;

const BLOCK_INDEX = new Map<string, AssumeValidBlockEntry>([
  [AV_HASH, { hash: AV_HASH, height: AV_HEIGHT, chainWork: 1000n }],
  [ANCESTOR_HASH, { hash: ANCESTOR_HASH, height: ANCESTOR_HEIGHT, chainWork: 600n }],
]);

const CANONICAL_BY_HEIGHT = new Map<number, AssumeValidBlockEntry>([
  [ANCESTOR_HEIGHT, { hash: ANCESTOR_HASH, height: ANCESTOR_HEIGHT, chainWork: 600n }],
  [AV_HEIGHT, { hash: AV_HASH, height: AV_HEIGHT, chainWork: 1000n }],
]);

const BEST_HEADER: AssumeValidBlockEntry = {
  hash: "dddd000000000000000000000000000000000000000000000000000000000004",
  height: 950_000,
  chainWork: 9999n,
};

const PINDEX_TS = 1_600_000_000;
const BEST_HEADER_TS = PINDEX_TS + TWO_WEEKS_PLUS;

/**
 * SKIP context: shouldSkipScripts → true (all six conditions satisfied).
 * pindex is ANCESTOR of AV_HASH, best-header chainwork > min, 2-week guard clears.
 */
const SKIP_CTX: AssumeValidContext = {
  pindex: { hash: ANCESTOR_HASH, height: ANCESTOR_HEIGHT, chainWork: 600n },
  assumedValidHash: AV_HASH,
  getBlockByHash: (h) => BLOCK_INDEX.get(h) ?? null,
  getBlockAtHeight: (h) => CANONICAL_BY_HEIGHT.get(h) ?? null,
  bestHeader: BEST_HEADER,
  minimumChainWork: 100n,
  pindexTimestamp: PINDEX_TS,
  bestHeaderTimestamp: BEST_HEADER_TS,
};

/**
 * VERIFY context: shouldSkipScripts → false (no assumedValidHash).
 * Simulates regtest / assumevalid=0.
 */
const VERIFY_CTX: AssumeValidContext = {
  ...SKIP_CTX,
  assumedValidHash: undefined,
};

// Sanity-check contexts before running benchmark.
const skipSanity = shouldSkipScripts(SKIP_CTX);
const verifySanity = shouldSkipScripts(VERIFY_CTX);
if (!skipSanity.skip) {
  console.error(`ERROR: SKIP_CTX should give skip=true, got: ${skipSanity.reason}`);
  process.exit(1);
}
if (verifySanity.skip) {
  console.error(`ERROR: VERIFY_CTX should give skip=false, got: ${verifySanity.reason}`);
  process.exit(1);
}

// ---------------------------------------------------------------------------
// Benchmark
// ---------------------------------------------------------------------------

const WARMUP = 100;
const ITERS = 2000;

console.log("[secp256k1 FFI] Validating P2PKH fixture...");
console.log("Fixture valid:", fixtureValid);
console.log();
console.log("=== hotbuns assumevalid microbenchmark ===");
console.log();
console.log("NOTE: hotbuns's IBD path (BlockSync.connectBlock) does not currently");
console.log("invoke script verification — this is the P2-OPT-ROUND-2 gap:");
console.log('"hotbuns has verifyAllInputsParallel defined but never imported;');
console.log('script verification absent from IBD path".');
console.log();
console.log("This benchmark exercises the verifyScript and shouldSkipScripts");
console.log("paths directly to assert the skip-path performance advantage.");
console.log();

// Warmup
for (let i = 0; i < WARMUP; i++) {
  shouldSkipScripts(SKIP_CTX);
  shouldSkipScripts(VERIFY_CTX);
  verifyScript(scriptSig, scriptPubKey, witness, flags, sigHasher);
}

// -----------------------------------------------------------------------
// Benchmark A: VERIFY path (shouldSkipScripts=false → run verifyScript)
// -----------------------------------------------------------------------
const verifyStart = performance.now();
for (let i = 0; i < ITERS; i++) {
  const { skip } = shouldSkipScripts(VERIFY_CTX);
  if (!skip) {
    verifyScript(scriptSig, scriptPubKey, witness, flags, sigHasher);
  }
}
const verifyMs = performance.now() - verifyStart;
const verifyUsPerOp = (verifyMs / ITERS) * 1000;
const verifyOpsPerSec = Math.round(ITERS / (verifyMs / 1000));

// -----------------------------------------------------------------------
// Benchmark B: SKIP path (shouldSkipScripts=true → no verifyScript call)
// -----------------------------------------------------------------------
const skipStart = performance.now();
for (let i = 0; i < ITERS; i++) {
  const { skip } = shouldSkipScripts(SKIP_CTX);
  if (!skip) {
    // Never fires: all six conditions satisfied in SKIP_CTX.
    verifyScript(scriptSig, scriptPubKey, witness, flags, sigHasher);
  }
}
const skipMs = performance.now() - skipStart;
const skipUsPerOp = (skipMs / ITERS) * 1000;
const skipOpsPerSec = Math.round(ITERS / (skipMs / 1000));

const speedup = verifyMs / skipMs;

// -----------------------------------------------------------------------
// Output
// -----------------------------------------------------------------------
console.log(`Iterations: ${ITERS}`);
console.log();
console.log(`VERIFY path (assumevalid=0, scripts run each iteration):`);
console.log(`  Total:      ${verifyMs.toFixed(2)} ms`);
console.log(`  Per-op:     ${verifyUsPerOp.toFixed(2)} µs`);
console.log(`  Throughput: ${verifyOpsPerSec.toLocaleString()} ops/sec`);
console.log();
console.log(`SKIP path (all 6 conditions → skip=true, no verifyScript):`);
console.log(`  Total:      ${skipMs.toFixed(2)} ms`);
console.log(`  Per-op:     ${skipUsPerOp.toFixed(2)} µs`);
console.log(`  Throughput: ${skipOpsPerSec.toLocaleString()} ops/sec`);
console.log();
console.log(`Speedup (verify / skip): ${speedup.toFixed(1)}x`);
console.log();

const SPEEDUP_THRESHOLD = 10;
if (speedup < SPEEDUP_THRESHOLD) {
  console.error(`FAIL: expected skip path >= ${SPEEDUP_THRESHOLD}x faster than verify path`);
  console.error(`      (got ${speedup.toFixed(1)}x)`);
  process.exit(1);
} else {
  console.log(`PASS: skip path is ${speedup.toFixed(1)}x faster than verify path`);
  console.log(`      (threshold: ${SPEEDUP_THRESHOLD}x)`);
}
