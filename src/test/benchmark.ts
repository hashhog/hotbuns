/**
 * Performance benchmarks for hotbuns Bitcoin node.
 *
 * Measures throughput for critical operations:
 * - Block deserialization
 * - UTXO cache operations
 * - Signature verification
 * - Merkle root computation
 *
 * Target metrics:
 * - Block deserialization: > 10,000 blocks/sec
 * - UTXO cache lookups: > 1,000,000 ops/sec
 * - Signature verification: > 5,000 sigs/sec (single thread)
 * - Merkle root computation: > 50,000 txs/sec
 */

import { createTestDB, createTestBlock, mineRegtestBlock, generateTestKeyPair } from "./helpers.js";
import { UTXOManager, type UTXOCacheStats } from "../chain/utxo.js";
import { BufferPool, BufferWriter, BufferReader } from "../wire/serialization.js";
import { serializeBlock, deserializeBlock, computeMerkleRoot } from "../validation/block.js";
import {
  sigHashWitnessV0,
  sigHashWitnessV0Cached,
  type SigHashCache,
  type Transaction,
} from "../validation/tx.js";
import { ecdsaSign, ecdsaVerify, hash256 } from "../crypto/primitives.js";
import { REGTEST } from "../consensus/params.js";

interface BenchmarkResult {
  name: string;
  opsPerSecond: number;
  totalOps: number;
  durationMs: number;
}

/**
 * Run a benchmark function and measure performance.
 */
async function benchmark(
  name: string,
  iterations: number,
  fn: () => void | Promise<void>
): Promise<BenchmarkResult> {
  // Warmup
  for (let i = 0; i < Math.min(100, iterations / 10); i++) {
    await fn();
  }

  // Timed run
  const start = performance.now();
  for (let i = 0; i < iterations; i++) {
    await fn();
  }
  const end = performance.now();

  const durationMs = end - start;
  const opsPerSecond = (iterations / durationMs) * 1000;

  return {
    name,
    opsPerSecond,
    totalOps: iterations,
    durationMs,
  };
}

/**
 * Format a number with commas for readability.
 */
function formatNumber(n: number): string {
  return n.toLocaleString("en-US", { maximumFractionDigits: 0 });
}

/**
 * Print benchmark result.
 */
function printResult(result: BenchmarkResult, target?: number): void {
  const status = target ? (result.opsPerSecond >= target ? "PASS" : "FAIL") : "";
  const targetStr = target ? ` (target: ${formatNumber(target)})` : "";
  console.log(
    `  ${result.name}: ${formatNumber(result.opsPerSecond)} ops/sec${targetStr} ${status}`
  );
  console.log(
    `    ${formatNumber(result.totalOps)} ops in ${result.durationMs.toFixed(2)}ms`
  );
}

/**
 * Benchmark block deserialization throughput.
 */
export async function benchDeserializeBlocks(): Promise<BenchmarkResult> {
  console.log("\n=== Block Deserialization Benchmark ===");

  // Create test blocks of varying sizes
  const prevHash = Buffer.alloc(32, 0);
  const blocks: Buffer[] = [];

  for (let i = 0; i < 100; i++) {
    const block = createTestBlock(prevHash, i);
    const mined = mineRegtestBlock(block);
    blocks.push(serializeBlock(mined));
  }

  // Benchmark deserialization
  let blockIndex = 0;
  const result = await benchmark("block deserialize", 10000, () => {
    const data = blocks[blockIndex % blocks.length];
    const reader = new BufferReader(data);
    deserializeBlock(reader);
    blockIndex++;
  });

  printResult(result, 10000);
  return result;
}

/**
 * Benchmark UTXO cache operations (insert, lookup, delete).
 */
export async function benchUTXOCache(entryCount: number = 100000): Promise<BenchmarkResult[]> {
  console.log("\n=== UTXO Cache Benchmark ===");

  const { db, cleanup } = await createTestDB();
  const cache = new UTXOManager(db);

  // Pre-generate test data
  const txids: Buffer[] = [];
  for (let i = 0; i < 1000; i++) {
    const txid = Buffer.alloc(32);
    txid.writeUInt32LE(i, 0);
    txids.push(txid);
  }

  const mockTx: Transaction = {
    version: 2,
    inputs: [],
    outputs: [
      { value: 100000n, scriptPubKey: Buffer.alloc(25, 0x76) },
      { value: 200000n, scriptPubKey: Buffer.alloc(25, 0x76) },
    ],
    lockTime: 0,
  };

  // Benchmark inserts
  let insertIndex = 0;
  const insertResult = await benchmark("UTXO insert", entryCount, () => {
    const txid = txids[insertIndex % txids.length];
    cache.addTransaction(txid, mockTx, insertIndex, false);
    insertIndex++;
  });
  printResult(insertResult, 500000);

  // Benchmark lookups
  let lookupIndex = 0;
  const lookupResult = await benchmark("UTXO lookup", entryCount, () => {
    const txid = txids[lookupIndex % txids.length];
    cache.getUTXO({ txid, vout: lookupIndex % 2 });
    lookupIndex++;
  });
  printResult(lookupResult, 1000000);

  // Benchmark has checks
  let hasIndex = 0;
  const hasResult = await benchmark("UTXO has", entryCount, () => {
    const txid = txids[hasIndex % txids.length];
    cache.hasUTXO({ txid, vout: hasIndex % 2 });
    hasIndex++;
  });
  printResult(hasResult, 1000000);

  // Print cache stats
  const stats = cache.getStats();
  console.log(`  Cache stats: ${formatNumber(stats.hits)} hits, ${formatNumber(stats.misses)} misses`);
  console.log(`  Evictions: ${formatNumber(stats.evictions)}, Flushes: ${stats.flushes}`);

  await cleanup();
  return [insertResult, lookupResult, hasResult];
}

/**
 * Benchmark signature verification throughput.
 */
export async function benchSigVerify(count: number = 5000): Promise<BenchmarkResult> {
  console.log("\n=== Signature Verification Benchmark ===");

  // Pre-generate keys and signatures
  const testData: { msgHash: Buffer; signature: Buffer; publicKey: Buffer }[] = [];

  for (let i = 0; i < Math.min(100, count); i++) {
    const { privateKey, publicKey } = generateTestKeyPair();
    const msgHash = hash256(Buffer.from(`test message ${i}`));
    const signature = ecdsaSign(msgHash, privateKey);
    testData.push({ msgHash, signature, publicKey });
  }

  // Benchmark verification
  let verifyIndex = 0;
  const result = await benchmark("sig verify", count, () => {
    const { msgHash, signature, publicKey } = testData[verifyIndex % testData.length];
    ecdsaVerify(signature, msgHash, publicKey);
    verifyIndex++;
  });

  printResult(result, 5000);
  return result;
}

/**
 * Benchmark merkle root computation.
 */
export async function benchMerkleRoot(txCount: number = 50000): Promise<BenchmarkResult> {
  console.log("\n=== Merkle Root Benchmark ===");

  // Pre-generate txids
  const txids: Buffer[] = [];
  for (let i = 0; i < 1000; i++) {
    const txid = Buffer.alloc(32);
    txid.writeUInt32LE(i, 0);
    txid.writeUInt32LE(i * 7, 16);
    txids.push(txid);
  }

  // Benchmark with varying transaction counts
  const txCounts = [10, 100, 500, 1000];
  const results: BenchmarkResult[] = [];

  for (const count of txCounts) {
    const subset = txids.slice(0, count);
    const iterations = Math.floor(txCount / count);

    const result = await benchmark(`merkle root (${count} txs)`, iterations, () => {
      computeMerkleRoot(subset);
    });

    // Report as txs/sec
    const txsPerSec = result.opsPerSecond * count;
    console.log(`  merkle root (${count} txs): ${formatNumber(txsPerSec)} txs/sec`);
    results.push(result);
  }

  // Overall throughput estimate
  const avgTxsPerSec = results.reduce((sum, r, i) => sum + r.opsPerSecond * txCounts[i], 0) / results.length;
  console.log(`  Average throughput: ${formatNumber(avgTxsPerSec)} txs/sec (target: 50,000)`);

  return results[results.length - 1];
}

/**
 * Benchmark sighash computation with and without caching.
 */
export async function benchSigHashCache(count: number = 10000): Promise<void> {
  console.log("\n=== SigHash Cache Benchmark ===");

  // Create a test transaction
  const tx: Transaction = {
    version: 2,
    inputs: [],
    outputs: [],
    lockTime: 0,
  };

  // Add multiple inputs
  for (let i = 0; i < 10; i++) {
    tx.inputs.push({
      prevOut: { txid: Buffer.alloc(32, i), vout: i },
      scriptSig: Buffer.alloc(0),
      sequence: 0xffffffff,
      witness: [],
    });
  }

  // Add outputs
  for (let i = 0; i < 10; i++) {
    tx.outputs.push({
      value: BigInt(i * 1000),
      scriptPubKey: Buffer.alloc(25, 0x76),
    });
  }

  const subscript = Buffer.alloc(25, 0x76);
  const value = 100000n;

  // Benchmark without cache
  let uncachedIndex = 0;
  const uncachedResult = await benchmark("sighash uncached", count, () => {
    sigHashWitnessV0(tx, uncachedIndex % tx.inputs.length, subscript, value, 0x01);
    uncachedIndex++;
  });
  printResult(uncachedResult);

  // Benchmark with cache
  let cachedIndex = 0;
  const cache: SigHashCache = {};
  const cachedResult = await benchmark("sighash cached", count, () => {
    sigHashWitnessV0Cached(tx, cachedIndex % tx.inputs.length, subscript, value, 0x01, cache);
    cachedIndex++;
  });
  printResult(cachedResult);

  const speedup = cachedResult.opsPerSecond / uncachedResult.opsPerSecond;
  console.log(`  Cache speedup: ${speedup.toFixed(2)}x`);
}

/**
 * Benchmark buffer pool.
 */
export async function benchBufferPool(count: number = 100000): Promise<void> {
  console.log("\n=== Buffer Pool Benchmark ===");

  const pool = new BufferPool();

  // Benchmark pooled allocation
  const pooledResult = await benchmark("pooled alloc+release", count, () => {
    const buf = pool.acquire(32);
    pool.release(buf);
  });
  printResult(pooledResult);

  // Benchmark direct allocation
  const directResult = await benchmark("direct alloc", count, () => {
    Buffer.alloc(32);
  });
  printResult(directResult);

  const speedup = pooledResult.opsPerSecond / directResult.opsPerSecond;
  console.log(`  Pool speedup: ${speedup.toFixed(2)}x`);

  const stats = pool.getStats();
  console.log(`  Pool stats: ${stats.acquired} acquired, ${stats.released} released, ${stats.pooled} pooled`);
}

/**
 * Run all benchmarks.
 */
async function runAllBenchmarks(): Promise<void> {
  console.log("======================================");
  console.log("  hotbuns Performance Benchmarks");
  console.log("======================================");

  const memBefore = process.memoryUsage();
  console.log(`\nMemory usage before: ${Math.round(memBefore.heapUsed / 1024 / 1024)} MB`);

  try {
    await benchDeserializeBlocks();
    await benchUTXOCache(100000);
    await benchSigVerify(5000);
    await benchMerkleRoot(50000);
    await benchSigHashCache(10000);
    await benchBufferPool(100000);
  } catch (error) {
    console.error("Benchmark error:", error);
  }

  const memAfter = process.memoryUsage();
  console.log(`\nMemory usage after: ${Math.round(memAfter.heapUsed / 1024 / 1024)} MB`);
  console.log(`Memory delta: ${Math.round((memAfter.heapUsed - memBefore.heapUsed) / 1024 / 1024)} MB`);

  console.log("\n======================================");
  console.log("  Benchmark Complete");
  console.log("======================================\n");
}

// Run benchmarks if this file is executed directly
if (import.meta.main) {
  runAllBenchmarks();
}
