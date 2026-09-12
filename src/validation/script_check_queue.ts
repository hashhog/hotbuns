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
 *
 * Reference: bitcoin-core/src/checkqueue.h, src/validation.h MAX_SCRIPTCHECK_THREADS,
 *            src/node/chainstatemanager_args.h DEFAULT_SCRIPTCHECK_THREADS.
 */

import type { UTXOEntry } from "../storage/database.js";
import {
	toWireTx,
	toWireUtxo,
	type WireBatch,
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

export function clampScriptThreads(n: number | undefined): number {
	let threads = n;
	if (threads === undefined || threads <= 0) {
		const hw =
			typeof navigator !== "undefined" && navigator.hardwareConcurrency > 0
				? navigator.hardwareConcurrency
				: 4;
		threads = hw;
	}
	return Math.max(1, Math.min(Math.floor(threads), MAX_SCRIPTCHECK_THREADS));
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

	async verify(jobs: ScriptCheckJob[]): Promise<ScriptCheckResult> {
		await this.waitReady();
		if (this.failed) throw this.failed;
		if (jobs.length === 0) return { valid: true };

		const n = Math.min(this.size, jobs.length);
		const chunkSize = Math.ceil(jobs.length / n);
		const waves: Promise<{ start: number; out: WorkerOut }>[] = [];

		for (let w = 0; w < n; w++) {
			const start = w * chunkSize;
			const chunk = jobs.slice(start, start + chunkSize);
			if (chunk.length === 0) break;
			waves.push(
				this.sendChunk(this.workers[w]!, chunk).then((out) => ({ start, out })),
			);
		}

		const parts = await Promise.all(waves);
		for (const { start, out } of parts) {
			if (out.kind === "crash") {
				throw new Error(out.error);
			}
			if (out.kind !== "result") {
				throw new Error(`unexpected worker message ${out.kind}`);
			}
			for (const item of out.results) {
				if (!item.valid) {
					const job = jobs[start + item.jobIndex]!;
					return {
						valid: false,
						error: item.error ?? "Input verification failed",
						failedInput: job.inputIndex,
						failedTxidHex: job.txidHex,
					};
				}
			}
		}
		return { valid: true };
	}

	private sendChunk(
		worker: Worker,
		chunk: ScriptCheckJob[],
	): Promise<WorkerOut> {
		const id = this.nextId++;
		const txMap = new Map<Transaction, number>();
		const txs = [];
		const wireJobs = [];
		for (const job of chunk) {
			let txi = txMap.get(job.tx);
			if (txi === undefined) {
				txi = txs.length;
				txMap.set(job.tx, txi);
				txs.push(toWireTx(job.tx));
			}
			wireJobs.push({
				txi,
				inputIndex: job.inputIndex,
				utxos: job.utxos.map(toWireUtxo),
				flags: job.flags,
			});
		}
		const batch: WireBatch = { kind: "batch", id, txs, jobs: wireJobs };
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
				worker.postMessage(batch);
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
): Promise<ScriptCheckResult> {
	if (jobs.length === 0) return { valid: true };

	const n = clampScriptThreads(threads ?? hardwareThreads());
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
		const result = await pool.verify(pending);
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
