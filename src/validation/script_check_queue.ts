/**
 * CCheckQueue equivalent: block-level script verification on a Bun Worker pool.
 *
 * Bitcoin Core enqueues one CScriptCheck per input during ConnectBlock, then
 * Wait()s after the UTXO loop so every check in the block can run on the
 * script-check threads (validation.cpp ConnectBlock + checkqueue.h).
 *
 * hotbuns previously called verifyAllInputsParallel per transaction, and that
 * helper was Promise.all over already-resolved synchronous ECDSA — one JS
 * thread, and no parallelism across the common 1-input-tx case.
 *
 * This module:
 *   - clamps thread count to MAX_SCRIPTCHECK_THREADS (Core: 15)
 *   - treats 0 / undefined as auto (hardware concurrency)
 *   - consults globalSigCache on the main thread before dispatch
 *   - runs remaining checks on a persistent Worker pool (or serial fallback)
 *   - drains a bounded FIFO (SCRIPTCHECK_BATCH_SIZE=128, Core nBatchSize)
 *     so in-flight wire is O(workers) not O(block inputs)
 *
 * Reference: bitcoin-core/src/checkqueue.h, src/validation.h MAX_SCRIPTCHECK_THREADS,
 *            src/node/chainstatemanager_args.h DEFAULT_SCRIPTCHECK_THREADS.
 */

import type { UTXOEntry } from "../storage/database.js";
import {
	buildWireBatch,
	encodePackedBatch,
	estimateWireBatchBytes,
	scriptCheckWireBudget,
	type WorkerOut,
} from "./script_check_wire.js";
import { globalSigCache } from "./sig_cache.js";
import type { Transaction } from "./tx.js";
import {
	computeInputSigCacheKey,
	type SigHashCache,
	type TaprootSigHashCache,
	verifyInputSignature,
} from "./tx.js";

/** Core validation.h:90 */
export const MAX_SCRIPTCHECK_THREADS = 15;

/** Core DEFAULT_SCRIPTCHECK_THREADS = 0 (auto-detect). */
export const DEFAULT_SCRIPTCHECK_THREADS = 0;

/**
 * Core CCheckQueue nBatchSize (validation.cpp:6136). Workers drain at most
 * this many checks per postMessage so in-flight wire is O(workers), not
 * O(inputs in the block).
 */
export const SCRIPTCHECK_BATCH_SIZE = 128;

/**
 * Below this many cache-miss jobs, dispatch overhead dominates libsecp256k1
 * verify (~30–100 µs). Serial on the main thread is faster.
 */
export const MIN_JOBS_FOR_POOL = 8;

/**
 * Per-chunk bound on a worker result. A lost postMessage / silent worker
 * death used to hang `Promise.all` forever and stall IBD. On timeout the
 * pool throws and `verifyScriptChecks` falls back to sequential.
 */
export const SCRIPT_CHECK_RESULT_TIMEOUT_MS = 30_000;

let resultTimeoutMs = SCRIPT_CHECK_RESULT_TIMEOUT_MS;
let workerUrlForTests: URL | null = null;

/** Test-only: shorten the worker result timeout. */
export function setScriptCheckResultTimeoutForTests(ms: number): void {
	resultTimeoutMs = ms;
}

/** Test-only: point the pool at a hang/crash worker. */
export function setScriptCheckWorkerUrlForTests(url: URL | null): void {
	workerUrlForTests = url;
}

export interface ScriptCheckJob {
	tx: Transaction;
	inputIndex: number;
	utxos: UTXOEntry[];
	flags: number;
	/** Display/error helper; not consensus-critical. */
	txidHex?: string;
}

export interface ScriptCheckResult {
	valid: boolean;
	error?: string;
	failedInput?: number;
	failedTxidHex?: string;
}

/**
 * RSS we budget per script-check isolate (tx.ts + interpreter + bun:ffi).
 * Used to cap worker count from --dbcache so 15 isolates cannot dominate a
 * small cache. 2560 MiB / 64 MiB = 40 → still 15; 32 MiB → 1.
 */
export const SCRIPT_WORKER_RSS_BUDGET = 64 * 1024 * 1024;

export function clampScriptThreads(
	n: number | undefined,
	cacheBytes?: number,
): number {
	let threads = n;
	if (threads === undefined || threads <= 0) {
		const hw =
			typeof navigator !== "undefined" && navigator.hardwareConcurrency > 0
				? navigator.hardwareConcurrency
				: 4;
		threads = hw;
	}
	threads = Math.max(1, Math.min(Math.floor(threads), MAX_SCRIPTCHECK_THREADS));
	if (typeof cacheBytes === "number" && Number.isFinite(cacheBytes) && cacheBytes > 0) {
		const maxByCache = Math.max(
			1,
			Math.floor(cacheBytes / SCRIPT_WORKER_RSS_BUDGET),
		);
		threads = Math.min(threads, maxByCache);
	}
	return threads;
}

function hardwareThreads(): number {
	return clampScriptThreads(0);
}

interface Inflight {
	resolve: (results: WorkerOut) => void;
	reject: (err: Error) => void;
}

class VerifyPool {
	readonly size: number;
	private workers: Worker[] = [];
	private ready!: Promise<void>;
	private nextId = 1;
	private inflight = new Map<number, Inflight>();
	private readyCount = 0;
	private readyResolve: (() => void) | null = null;
	private failed: Error | null = null;

	constructor(size: number) {
		this.size = size;
		this.ready = new Promise<void>((resolve, reject) => {
			const timer = setTimeout(() => {
				if (this.readyCount < this.size) {
					reject(
						new Error(
							`script-check workers ready timeout (${this.readyCount}/${this.size})`,
						),
					);
				}
			}, 20_000);
			this.readyResolve = () => {
				clearTimeout(timer);
				resolve();
			};
		});

		const url =
			workerUrlForTests ?? new URL("./script_check_worker.ts", import.meta.url);
		for (let i = 0; i < size; i++) {
			const worker = new Worker(url);
			// Bun Worker: unref so the pool does not keep the process alive.
			(worker as Worker & { unref?: () => void }).unref?.();
			worker.onmessage = (ev: MessageEvent<WorkerOut>) =>
				this.onMessage(ev.data);
			worker.onerror = (ev: ErrorEvent) => {
				this.failed = new Error(ev.message || "script-check worker error");
				for (const p of this.inflight.values()) p.reject(this.failed);
				this.inflight.clear();
			};
			this.workers.push(worker);
		}
	}

	private onMessage(msg: WorkerOut): void {
		if (msg.kind === "ready") {
			this.readyCount++;
			if (this.readyCount >= this.size) {
				this.readyResolve?.();
				this.readyResolve = null;
			}
			return;
		}
		const pending = this.inflight.get(msg.id);
		if (!pending) return;
		this.inflight.delete(msg.id);
		pending.resolve(msg);
	}

	async waitReady(): Promise<void> {
		await this.ready;
		if (this.failed) throw this.failed;
	}

	async verify(
		jobs: ScriptCheckJob[],
		wireBudgetBytes?: number,
		threadLimit?: number,
	): Promise<ScriptCheckResult> {
		await this.waitReady();
		if (this.failed) throw this.failed;
		if (jobs.length === 0) return { valid: true };

		const budget = wireBudgetBytes ?? scriptCheckWireBudget();
		const n = Math.max(
			1,
			Math.min(threadLimit ?? this.size, this.size, jobs.length),
		);
		return this.drain(jobs, n, budget);
	}

	/**
	 * CCheckQueue-style drain: a bounded FIFO of per-input jobs, at most
	 * `nWorkers` in-flight batches of SCRIPTCHECK_BATCH_SIZE (and never more
	 * than `budget` bytes each). On the first failure we stop dispatching
	 * later-index jobs but wait for in-flight work, then return the
	 * earliest-index failure so the reject reason does not depend on the
	 * split. Core's queue is LIFO; we FIFO so serial and N-worker paths
	 * report the same first failure without racing a later-index job.
	 */
	private async drain(
		jobs: ScriptCheckJob[],
		nWorkers: number,
		budget: number,
	): Promise<ScriptCheckResult> {
		peakInFlightJobs = 0;
		peakInFlightBytes = 0;
		lastDispatchWorkers = 0;

		let qHead = 0;
		let earliestFailIndex = Number.POSITIVE_INFINITY;
		let failResult: ScriptCheckResult | null = null;
		let inFlightJobs = 0;
		let inFlightBytes = 0;
		const used = new Set<number>();

		const takeBatch = (): {
			items: ScriptCheckJob[];
			origIndices: number[];
			bytes: number;
		} | null => {
			const items: ScriptCheckJob[] = [];
			const origIndices: number[] = [];
			const remaining = jobs.length - qHead;
			if (remaining <= 0) return null;
			// Core: nNow = max(1, min(nBatchSize, queue / (nTotal+nIdle+1))).
			// Split leftover work across the pool so a 256-input block still
			// uses all requested workers instead of two 128-job chunks.
			const adaptive = Math.max(1, Math.ceil(remaining / nWorkers));
			const cap = Math.min(SCRIPTCHECK_BATCH_SIZE, adaptive);
			while (qHead < jobs.length && items.length < cap) {
				const origIndex = qHead;
				if (origIndex >= earliestFailIndex) {
					qHead = jobs.length;
					break;
				}
				const job = jobs[origIndex]!;
				if (items.length > 0) {
					const bytes = estimateWireBatchBytes(
						buildWireBatch(0, [...items, job]),
					);
					if (bytes > budget) break;
				}
				items.push(job);
				origIndices.push(origIndex);
				qHead++;
			}
			if (items.length === 0) return null;
			return {
				items,
				origIndices,
				bytes: estimateWireBatchBytes(buildWireBatch(0, items)),
			};
		};

		const workerLoop = async (w: number): Promise<void> => {
			while (true) {
				const batch = takeBatch();
				if (!batch) return;
				used.add(w);
				inFlightJobs += batch.items.length;
				inFlightBytes += batch.bytes;
				if (inFlightJobs > peakInFlightJobs) peakInFlightJobs = inFlightJobs;
				if (inFlightBytes > peakInFlightBytes) peakInFlightBytes = inFlightBytes;
				try {
					const out = await this.sendChunk(this.workers[w]!, batch.items);
					if (out.kind === "crash") {
						throw new Error(out.error);
					}
					if (out.kind !== "result") {
						throw new Error(`unexpected worker message ${out.kind}`);
					}
					for (const item of out.results) {
						if (item.valid) continue;
						const origIndex = batch.origIndices[item.jobIndex]!;
						if (origIndex >= earliestFailIndex) continue;
						const job = batch.items[item.jobIndex]!;
						earliestFailIndex = origIndex;
						failResult = {
							valid: false,
							error: item.error ?? "Input verification failed",
							failedInput: job.inputIndex,
							failedTxidHex: job.txidHex,
						};
					}
				} finally {
					inFlightJobs -= batch.items.length;
					inFlightBytes -= batch.bytes;
				}
			}
		};

		const settled = await Promise.allSettled(
			Array.from({ length: nWorkers }, (_, w) => workerLoop(w)),
		);
		lastDispatchWorkers = used.size;
		const rejected = settled.find((s) => s.status === "rejected");
		if (rejected && rejected.status === "rejected") {
			throw rejected.reason;
		}
		return failResult ?? { valid: true };
	}

	private sendChunk(
		worker: Worker,
		chunk: ScriptCheckJob[],
	): Promise<WorkerOut> {
		const id = this.nextId++;
		const batch = buildWireBatch(id, chunk);
		const packed = encodePackedBatch(batch);
		return new Promise<WorkerOut>((resolve, reject) => {
			const timer = setTimeout(() => {
				this.inflight.delete(id);
				reject(
					new Error(
						`script-check worker result timeout (id=${id}, jobs=${chunk.length})`,
					),
				);
			}, resultTimeoutMs);
			this.inflight.set(id, {
				resolve: (msg) => {
					clearTimeout(timer);
					resolve(msg);
				},
				reject: (err) => {
					clearTimeout(timer);
					reject(err);
				},
			});
			try {
				worker.postMessage(packed, [packed]);
			} catch (e) {
				clearTimeout(timer);
				this.inflight.delete(id);
				reject(e instanceof Error ? e : new Error(String(e)));
			}
		});
	}

	shutdown(): void {
		for (const w of this.workers) {
			try {
				w.postMessage({ kind: "stop" });
				w.terminate();
			} catch {
				// already dead
			}
		}
		this.workers = [];
		for (const p of this.inflight.values()) {
			p.reject(new Error("script-check pool shutdown"));
		}
		this.inflight.clear();
	}
}

let globalPool: VerifyPool | null = null;
let creating: Promise<VerifyPool> | null = null;

export function scriptCheckPoolSize(): number {
	return globalPool?.size ?? 0;
}

let peakInFlightJobs = 0;
let peakInFlightBytes = 0;
let lastDispatchWorkers = 0;

export function scriptCheckPeakInFlightJobs(): number {
	return peakInFlightJobs;
}

export function scriptCheckPeakInFlightBytes(): number {
	return peakInFlightBytes;
}

export function scriptCheckLastDispatchWorkers(): number {
	return lastDispatchWorkers;
}

export function scriptCheckResetStats(): void {
	peakInFlightJobs = 0;
	peakInFlightBytes = 0;
	lastDispatchWorkers = 0;
}

export async function shutdownScriptCheckPool(): Promise<void> {
	globalPool?.shutdown();
	globalPool = null;
	creating = null;
}

async function getPool(size: number): Promise<VerifyPool> {
	if (globalPool && globalPool.size >= size) {
		await globalPool.waitReady();
		return globalPool;
	}
	if (creating) {
		const pending = await creating;
		if (pending.size >= size) return pending;
	}
	creating = (async () => {
		globalPool?.shutdown();
		const pool = new VerifyPool(size);
		await pool.waitReady();
		globalPool = pool;
		return pool;
	})();
	try {
		return await creating;
	} finally {
		creating = null;
	}
}

function verifySequential(jobs: ScriptCheckJob[]): ScriptCheckResult {
	const caches = new Map<
		Transaction,
		{ sig: SigHashCache; tap: TaprootSigHashCache }
	>();
	for (const job of jobs) {
		let cache = caches.get(job.tx);
		if (!cache) {
			cache = { sig: {}, tap: {} };
			caches.set(job.tx, cache);
		}
		const utxo = job.utxos[job.inputIndex]!;
		const result = verifyInputSignature(
			job.tx,
			job.inputIndex,
			utxo,
			cache.sig,
			job.utxos,
			cache.tap,
			job.flags,
		);
		if (!result.valid) {
			return {
				valid: false,
				error: result.error ?? "Input verification failed",
				failedInput: job.inputIndex,
				failedTxidHex: job.txidHex,
			};
		}
	}
	return { valid: true };
}

/**
 * Verify every collected input script for a block (or a single tx).
 *
 * Cache hits on globalSigCache are skipped. Remaining jobs run on the
 * worker pool when `threads > 1` and there are enough of them; otherwise
 * they run serially on this thread (the -par=1 path, and tiny blocks).
 */
export async function verifyScriptChecks(
	jobs: ScriptCheckJob[],
	threads?: number,
	cacheBytes?: number,
): Promise<ScriptCheckResult> {
	if (jobs.length === 0) return { valid: true };

	const n = clampScriptThreads(threads ?? hardwareThreads(), cacheBytes);
	const usePool = n > 1 && jobs.length >= MIN_JOBS_FOR_POOL;

	if (!usePool) {
		return verifySequential(jobs);
	}

	const pending: ScriptCheckJob[] = [];
	for (const job of jobs) {
		const utxo = job.utxos[job.inputIndex];
		if (!utxo) {
			return {
				valid: false,
				error: "UTXO count mismatch",
				failedInput: job.inputIndex,
				failedTxidHex: job.txidHex,
			};
		}
		const key = computeInputSigCacheKey(
			job.tx,
			job.inputIndex,
			utxo,
			job.flags,
		);
		if (!globalSigCache.lookup(key)) {
			pending.push(job);
		}
	}
	if (pending.length === 0) return { valid: true };

	try {
		const pool = await getPool(n);
		const result = await pool.verify(
			pending,
			scriptCheckWireBudget(cacheBytes),
			n,
		);
		if (result.valid) {
			for (const job of pending) {
				const utxo = job.utxos[job.inputIndex]!;
				globalSigCache.insert(
					computeInputSigCacheKey(job.tx, job.inputIndex, utxo, job.flags),
				);
			}
		}
		return result;
	} catch (e) {
		console.warn(
			`[script-check] worker pool failed (${e instanceof Error ? e.message : String(e)}); falling back to sequential`,
		);
		return verifySequential(pending);
	}
}
