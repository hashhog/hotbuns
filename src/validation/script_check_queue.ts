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
	encodePackedJobs,
	PACKED_HEADER_BYTES,
	PACKED_JOB_BYTES,
	packedTxBytes,
	packedUtxosBytes,
	scriptCheckWireBudget,
	type WorkerOut,
} from "./script_check_wire.js";
import { globalSigCache } from "./sig_cache.js";
import { SystemFaultError } from "../chain/fatal.js";
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

/** An open CCheckQueue stream on the pool (see VerifyPool.openStream). */
interface ScriptCheckStream {
	/** Queue jobs; full batches go to idle workers immediately. */
	push(jobs: ScriptCheckJob[]): void;
	/** No more jobs: dispatch the rest and wait for every result. */
	close(): Promise<ScriptCheckResult>;
	/** Stop dispatching and wait for in-flight batches; results are dropped. */
	cancel(): Promise<void>;
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

	/** Every worker is up and none has failed (no await needed). */
	isReady(): boolean {
		return this.readyCount >= this.size && this.failed === null;
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
	 * CCheckQueue-style drain of a complete job list: a stream that is closed
	 * as soon as every job is queued.
	 */
	private async drain(
		jobs: ScriptCheckJob[],
		nWorkers: number,
		budget: number,
	): Promise<ScriptCheckResult> {
		const stream = this.openStream(nWorkers, budget);
		stream.push(jobs);
		return stream.close();
	}

	/**
	 * Open a CCheckQueue-style stream: a bounded FIFO of per-input jobs fed
	 * WHILE the caller is still collecting them, at most `nWorkers` in-flight
	 * batches of SCRIPTCHECK_BATCH_SIZE (and never more than `budget` bytes
	 * each).
	 *
	 * ConnectBlock used to collect every job of the block and only then hand
	 * them to the pool, so the workers sat idle for the whole tx loop
	 * (ARCH-2.5: script wait 31% of block time at 900k, workers ~50% used).
	 * Core's CCheckQueueControl::Add hands checks to the threads as the loop
	 * produces them. Here `push` dispatches synchronously (postMessage) to any
	 * idle worker once a full batch is queued, so the workers run while the
	 * main thread continues the loop; `close` dispatches the remainder split
	 * across the pool and waits.
	 *
	 * On the first failure we stop dispatching later-index jobs but wait for
	 * in-flight work, then return the earliest-index failure so the reject
	 * reason does not depend on the split or on when jobs were pushed. Core's
	 * queue is LIFO; we FIFO so serial and N-worker paths report the same
	 * first failure without racing a later-index job.
	 */
	openStream(nWorkers: number, budget: number): ScriptCheckStream {
		peakInFlightJobs = 0;
		peakInFlightBytes = 0;
		lastDispatchWorkers = 0;

		const jobs: ScriptCheckJob[] = [];
		let qHead = 0;
		let closed = false;
		let cancelled = false;
		let earliestFailIndex = Number.POSITIVE_INFINITY;
		let failResult: ScriptCheckResult | null = null;
		let fault: unknown = null;
		let inFlightBatches = 0;
		let inFlightJobs = 0;
		let inFlightBytes = 0;
		const used = new Set<number>();
		const idle: number[] = [];
		for (let w = nWorkers - 1; w >= 0; w--) idle.push(w);
		let settle: ((r: ScriptCheckResult) => void) | null = null;
		let fail: ((e: unknown) => void) | null = null;
		const done = new Promise<ScriptCheckResult>((resolve, reject) => {
			settle = resolve;
			fail = reject;
		});

		// Per-tx packed size (tx + its UTXO vector), computed once per stream.
		// takeBatch used to rebuild and re-measure the whole candidate batch
		// for every job it appended — O(batch²) wire conversions per batch on
		// the main thread. Sizes are now exact and accumulated incrementally.
		const txBytes = new Map<Transaction, number>();
		const txCost = (job: ScriptCheckJob): number => {
			let b = txBytes.get(job.tx);
			if (b === undefined) {
				b = packedTxBytes(job.tx) + packedUtxosBytes(job.utxos);
				txBytes.set(job.tx, b);
			}
			return b;
		};

		const takeBatch = (): {
			items: ScriptCheckJob[];
			origIndices: number[];
			bytes: number;
		} | null => {
			if (cancelled || fault !== null) return null;
			const items: ScriptCheckJob[] = [];
			const origIndices: number[] = [];
			const remaining = jobs.length - qHead;
			if (remaining <= 0) return null;
			// While the caller is still pushing, send only full batches; once
			// closed, Core's nNow = max(1, min(nBatchSize, queue /
			// (nTotal+nIdle+1))) splits the leftover across the pool so a
			// 256-input block still uses all requested workers instead of two
			// 128-job chunks.
			let cap: number;
			if (closed) {
				const adaptive = Math.max(1, Math.ceil(remaining / nWorkers));
				cap = Math.min(SCRIPTCHECK_BATCH_SIZE, adaptive);
			} else {
				if (remaining < SCRIPTCHECK_BATCH_SIZE) return null;
				cap = SCRIPTCHECK_BATCH_SIZE;
			}
			const inBatch = new Set<Transaction>();
			let bytes = PACKED_HEADER_BYTES;
			while (qHead < jobs.length && items.length < cap) {
				const origIndex = qHead;
				if (origIndex >= earliestFailIndex) {
					qHead = jobs.length;
					break;
				}
				const job = jobs[origIndex]!;
				const add =
					PACKED_JOB_BYTES + (inBatch.has(job.tx) ? 0 : txCost(job));
				if (items.length > 0 && bytes + add > budget) break;
				bytes += add;
				inBatch.add(job.tx);
				items.push(job);
				origIndices.push(origIndex);
				qHead++;
			}
			if (items.length === 0) return null;
			return { items, origIndices, bytes };
		};

		const onResult = (
			batch: { items: ScriptCheckJob[]; origIndices: number[] },
			out: WorkerOut,
		): void => {
			if (out.kind === "crash") {
				throw new Error(out.error);
			}
			if (out.kind !== "result") {
				throw new Error(`unexpected worker message ${out.kind}`);
			}
			// One verdict per job, each job exactly once. A short or garbled
			// list must not read as "no failures": a job without a verdict was
			// never verified. Treated as a worker fault, so the caller re-runs
			// the same jobs on this thread.
			const n = batch.items.length;
			if (out.results.length !== n) {
				throw new Error(
					`script-check worker returned ${out.results.length} results for ${n} jobs`,
				);
			}
			const seen = new Uint8Array(n);
			for (const item of out.results) {
				const j = item.jobIndex;
				if (!Number.isInteger(j) || j < 0 || j >= n || seen[j] === 1) {
					throw new Error(`script-check worker returned bad jobIndex ${j} for ${n} jobs`);
				}
				seen[j] = 1;
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
		};

		const pump = (): void => {
			while (idle.length > 0) {
				const batch = takeBatch();
				if (!batch) break;
				const w = idle.pop()!;
				used.add(w);
				inFlightBatches++;
				inFlightBatchesNow++;
				inFlightJobs += batch.items.length;
				inFlightBytes += batch.bytes;
				if (inFlightJobs > peakInFlightJobs) peakInFlightJobs = inFlightJobs;
				if (inFlightBytes > peakInFlightBytes) peakInFlightBytes = inFlightBytes;
				this.sendChunk(this.workers[w]!, batch.items)
					.then((out) => onResult(batch, out))
					.catch((e) => {
						if (fault === null) fault = e;
					})
					.finally(() => {
						inFlightBatches--;
						inFlightBatchesNow--;
						inFlightJobs -= batch.items.length;
						inFlightBytes -= batch.bytes;
						idle.push(w);
						pump();
					});
			}
			if (!closed || inFlightBatches > 0) return;
			if (fault === null && !cancelled && qHead < jobs.length) return;
			lastDispatchWorkers = used.size;
			const s = settle;
			const f = fail;
			settle = null;
			fail = null;
			if (fault !== null && !cancelled) f?.(fault);
			else s?.(failResult ?? { valid: true });
		};

		return {
			push: (more: ScriptCheckJob[]): void => {
				if (closed) throw new Error("script-check stream already closed");
				for (const j of more) jobs.push(j);
				pump();
			},
			close: (): Promise<ScriptCheckResult> => {
				closed = true;
				pump();
				return done;
			},
			cancel: async (): Promise<void> => {
				cancelled = true;
				closed = true;
				pump();
				await done.catch(() => {});
			},
		};
	}

	private sendChunk(
		worker: Worker,
		chunk: ScriptCheckJob[],
	): Promise<WorkerOut> {
		const id = this.nextId++;
		const packed = encodePackedJobs(id, chunk);
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
let inFlightBatchesNow = 0;

/** Batches posted to a worker whose result has not settled yet (tests). */
export function scriptCheckInFlightBatches(): number {
	return inFlightBatchesNow;
}

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
	// Keys of the cache-miss jobs, kept so a valid block inserts them without
	// rebuilding each one (two SHA-256 passes per input on this thread).
	const pendingKeys: ReturnType<typeof computeInputSigCacheKey>[] = [];
	for (const job of jobs) {
		const utxo = job.utxos[job.inputIndex];
		if (!utxo) {
			// Gate 6: a job without its prevout is a broken caller invariant —
			// no script was evaluated, so it cannot be a script-failure verdict.
			throw new SystemFaultError(
				`script check job has no prevout (input ${job.inputIndex} of ${job.txidHex ?? "?"})`,
			);
		}
		const key = computeInputSigCacheKey(
			job.tx,
			job.inputIndex,
			utxo,
			job.flags,
		);
		if (!globalSigCache.lookup(key)) {
			pending.push(job);
			pendingKeys.push(key);
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
			for (const key of pendingKeys) globalSigCache.insert(key);
		}
		return result;
	} catch (e) {
		// A worker that crashed, timed out or produced no result is a fault of
		// this node, not of the block (gate 6): re-run the SAME jobs once,
		// sequentially on this thread. A system fault there propagates out of
		// verifyScriptChecks (verifyInputSignature re-throws it) and the caller
		// retries the block / halts — it never becomes a script verdict.
		console.warn(
			`[script-check] worker pool failed (${e instanceof Error ? e.message : String(e)}); re-running sequentially`,
		);
		return verifySequential(pending);
	}
}

/**
 * Block-level script checks fed during ConnectBlock's tx loop (Core
 * CCheckQueueControl: Add() per tx, Wait() after the loop).
 *
 * Same decisions as {@link verifyScriptChecks} over the full job list:
 * threads <= 1 or fewer than MIN_JOBS_FOR_POOL jobs run serially at
 * `finish`; otherwise sig-cache hits are skipped and the misses run on the
 * pool, with the same earliest-index failure and the same sequential re-run
 * if the pool faults. The difference is WHEN the pool sees them: once
 * SCRIPTCHECK_BATCH_SIZE cache misses are queued, full batches are posted
 * to idle workers from inside `add`, so the workers verify while the main
 * thread is still in the tx loop.
 */
export interface ScriptCheckSession {
	/** Queue one transaction's input checks (in block order). */
	add(jobs: ScriptCheckJob[]): void;
	/** Every job is queued: wait for the verdict. */
	finish(): Promise<ScriptCheckResult>;
	/** The block failed another check first: drop the jobs, quiesce. */
	abandon(): Promise<void>;
}

export function beginScriptChecks(
	threads?: number,
	cacheBytes?: number,
): ScriptCheckSession {
	const n = clampScriptThreads(threads ?? hardwareThreads(), cacheBytes);
	const all: ScriptCheckJob[] = [];
	const pending: ScriptCheckJob[] = [];
	const pendingKeys: ReturnType<typeof computeInputSigCacheKey>[] = [];
	let fault: SystemFaultError | null = null;
	let stream: ScriptCheckStream | null = null;
	let opening: Promise<void> | null = null;
	let streamFault: unknown = null;
	let fed = 0; // pending[0..fed) went to the stream

	const feed = (): void => {
		if (!stream || fed >= pending.length) return;
		stream.push(pending.slice(fed));
		fed = pending.length;
	};

	const open = (): Promise<void> => {
		// The pool is long-lived: once it is up, open the stream in this tick
		// so the first full batch leaves inside add(). Waiting on getPool()
		// would defer it to the loop's next await, and a block whose inputs
		// are all cached may have none before finish().
		if (!opening && globalPool && globalPool.size >= n && globalPool.isReady()) {
			stream = globalPool.openStream(n, scriptCheckWireBudget(cacheBytes));
			feed();
			opening = Promise.resolve();
		}
		if (!opening) {
			opening = getPool(n)
				.then((pool) => {
					stream = pool.openStream(n, scriptCheckWireBudget(cacheBytes));
					feed();
				})
				.catch((e) => {
					streamFault = e;
				});
		}
		return opening;
	};

	const sequentialRerun = (e: unknown): ScriptCheckResult => {
		// Same as verifyScriptChecks: a worker that crashed, timed out or
		// produced no result is a fault of this node, not of the block
		// (gate 6) — re-run the SAME jobs once, on this thread.
		console.warn(
			`[script-check] worker pool failed (${e instanceof Error ? e.message : String(e)}); re-running sequentially`,
		);
		return verifySequential(pending);
	};

	return {
		add(jobs: ScriptCheckJob[]): void {
			for (const job of jobs) all.push(job);
			if (n <= 1 || fault !== null) return;
			for (const job of jobs) {
				const utxo = job.utxos[job.inputIndex];
				if (!utxo) {
					// Gate 6 (as verifyScriptChecks): a job without its prevout
					// is a broken caller invariant, reported at finish().
					fault = new SystemFaultError(
						`script check job has no prevout (input ${job.inputIndex} of ${job.txidHex ?? "?"})`,
					);
					return;
				}
				const key = computeInputSigCacheKey(
					job.tx,
					job.inputIndex,
					utxo,
					job.flags,
				);
				if (!globalSigCache.lookup(key)) {
					pending.push(job);
					pendingKeys.push(key);
				}
			}
			if (stream) feed();
			else if (pending.length >= SCRIPTCHECK_BATCH_SIZE) void open();
		},

		async finish(): Promise<ScriptCheckResult> {
			if (all.length === 0) return { valid: true };
			const usePool = n > 1 && all.length >= MIN_JOBS_FOR_POOL;
			if (!usePool) return verifySequential(all);
			if (fault !== null) {
				await this.abandon();
				throw fault;
			}
			if (!stream && !opening && pending.length === 0) return { valid: true };
			await open();
			if (!stream) return sequentialRerun(streamFault);
			feed();
			try {
				const result = await (stream as ScriptCheckStream).close();
				if (result.valid) {
					for (const key of pendingKeys) globalSigCache.insert(key);
				}
				return result;
			} catch (e) {
				return sequentialRerun(e);
			}
		},

		async abandon(): Promise<void> {
			if (opening) await opening;
			if (stream) await (stream as ScriptCheckStream).cancel();
		},
	};
}
