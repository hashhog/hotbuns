/**
 * ConnectBlock feeds the script-check workers during its tx loop (ARCH-2.5).
 *
 * The time split at 900k had script wait at 31% of block time with the
 * workers ~50% used: coreConnectBlockChecks collected every input check of
 * the block and handed the list to the pool only after the tx loop, the
 * sigops ceiling and the coinbase check. Core's CCheckQueueControl::Add
 * gives the threads each tx's checks as the loop produces them and Wait()s
 * after the loop (validation.cpp ConnectBlock).
 *
 * Now beginScriptChecks().add() posts full SCRIPTCHECK_BATCH_SIZE batches to
 * idle workers from inside the loop. What must NOT change: the verdict is
 * read only at Wait(), so a block with both a non-script failure and a bad
 * script still reports the non-script reason, and the earliest-index script
 * failure wins whatever the split.
 *
 * Control: HOTBUNS_UNIT_CHILD=1 bun test ./src/validation/script-check-stream.test.ts
 */
import { afterAll, afterEach, beforeAll, describe, expect, it } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { UTXOManager } from "../chain/utxo.js";
import { coreConnectBlockChecks } from "../consensus/connect_block.js";
import { getBlockSubsidy, REGTEST } from "../consensus/params.js";
import { ChainDB } from "../storage/database.js";
import type { Block } from "./block.js";
import {
	SCRIPTCHECK_BATCH_SIZE,
	scriptCheckInFlightBatches,
	scriptCheckPeakInFlightJobs,
	scriptCheckResetStats,
	setScriptCheckResultTimeoutForTests,
	setScriptCheckWorkerUrlForTests,
	shutdownScriptCheckPool,
	verifyScriptChecks,
} from "./script_check_queue.js";
import { globalSigCache } from "./sig_cache.js";
import {
	getTxId,
	SEQUENCE_LOCKTIME_TYPE_FLAG,
	type Transaction,
} from "./tx.js";

const HEIGHT = 1_000; // past regtest CSV / segwit activation
const OP_TRUE = Buffer.from([0x51]);
const OP_FALSE = Buffer.from([0x00]);
const AMOUNT = 10_000n;
const THREADS = 4;
const WIDE = 2 * SCRIPTCHECK_BATCH_SIZE; // inputs of the first spend

let dir: string;
let db: ChainDB;
let uniq = 0;

beforeAll(async () => {
	dir = await mkdtemp(join(tmpdir(), "hotbuns-script-check-stream-"));
	db = new ChainDB(dir);
	await db.open();
});
afterAll(async () => {
	await db.close();
	await rm(dir, { recursive: true, force: true });
});
afterEach(async () => {
	globalSigCache.clear();
	await shutdownScriptCheckPool();
	setScriptCheckWorkerUrlForTests(null);
	setScriptCheckResultTimeoutForTests(30_000);
});

function coinbase(value: bigint): Transaction {
	return {
		version: 1,
		inputs: [
			{
				prevOut: { txid: Buffer.alloc(32, 0), vout: 0xffffffff },
				scriptSig: Buffer.from([0x02, HEIGHT & 0xff, (HEIGHT >> 8) & 0xff, 0x51]),
				sequence: 0xffffffff,
				witness: [],
			},
		],
		outputs: [{ value, scriptPubKey: OP_TRUE }],
		lockTime: 0,
	};
}

/** A fresh coin in `utxo`'s cache, locked by `spk`. */
function fund(utxo: UTXOManager, spk: Buffer, coinHeight = 1): { txid: Buffer; vout: number } {
	const txid = Buffer.alloc(32, 0);
	txid.writeUInt32LE(++uniq, 0);
	txid.writeUInt32LE(0x5eed, 28);
	utxo.getCoinsViewCache().addCoin(
		{ txid, vout: 0 },
		{ txOut: { value: AMOUNT, scriptPubKey: spk }, height: coinHeight, isCoinbase: false },
		false,
	);
	return { txid, vout: 0 };
}

/** Re-add the coin `fund` created at `prevOut` (same txid, same coin). */
function fundAt(
	utxo: UTXOManager,
	prevOut: { txid: Buffer; vout: number },
	spk: Buffer,
	coinHeight = 1,
): void {
	utxo.getCoinsViewCache().addCoin(
		prevOut,
		{ txOut: { value: AMOUNT, scriptPubKey: spk }, height: coinHeight, isCoinbase: false },
		false,
	);
}

function spend(
	prevOuts: { txid: Buffer; vout: number }[],
	outValue: bigint,
	sequence = 0xffffffff,
): Transaction {
	return {
		version: 2,
		inputs: prevOuts.map((prevOut) => ({
			prevOut,
			scriptSig: Buffer.alloc(0),
			sequence,
			witness: [],
		})),
		outputs: [{ value: outValue, scriptPubKey: OP_TRUE }],
		lockTime: 0,
	};
}

function block(txs: Transaction[]): Block {
	return {
		header: {
			version: 0x20000000,
			prevBlock: Buffer.alloc(32, 0xcd),
			merkleRoot: getTxId(txs[0]!),
			timestamp: 1_700_000_000,
			bits: REGTEST.powLimitBits,
			nonce: 0,
		},
		transactions: txs,
	};
}

/** Start the pool and wait until every worker is up (production steady state). */
async function warmPool(): Promise<void> {
	const utxo = new UTXOManager(db);
	const jobs = [];
	for (let i = 0; i < 16; i++) {
		const tx = spend([fund(utxo, OP_TRUE)], AMOUNT);
		jobs.push({
			tx,
			inputIndex: 0,
			utxos: [{ height: 1, coinbase: false, amount: AMOUNT, scriptPubKey: OP_TRUE }],
			flags: 0,
			txidHex: `warm${i}`,
		});
	}
	const r = await verifyScriptChecks(jobs, THREADS);
	expect(r.valid).toBe(true);
	globalSigCache.clear();
}

describe("script checks are fed to the workers during the tx loop", () => {
	it(
		"the workers hold checks of an earlier tx while the loop is still on a later tx",
		async () => {
			await warmPool();
			const utxo = new UTXOManager(db);
			const wide = spend(
				Array.from({ length: WIDE }, () => fund(utxo, OP_TRUE)),
				AMOUNT * BigInt(WIDE),
			);
			// One input with a time-based relative lock (1 x 512 s): the loop
			// asks getUTXOMTP for its coin, which is our probe inside the loop.
			const probeCoinHeight = 7;
			const late = spend(
				[fund(utxo, OP_TRUE, probeCoinHeight)],
				AMOUNT,
				SEQUENCE_LOCKTIME_TYPE_FLAG | 1,
			);
			const cb = coinbase(getBlockSubsidy(HEIGHT, REGTEST));
			let inFlightAtProbe = -1;
			scriptCheckResetStats();
			const res = await coreConnectBlockChecks(block([cb, wide, late]), HEIGHT, utxo, REGTEST, {
				scriptThreads: THREADS,
				enforceBIP68: true,
				prevMTP: 1_700_000_000,
				getUTXOMTP: (h: number) => {
					if (h === probeCoinHeight) inFlightAtProbe = scriptCheckPeakInFlightJobs();
					return 0;
				},
			});
			expect(res.ok).toBe(true);
			// master: 0, nothing reaches a worker until after the loop.
			expect(inFlightAtProbe).toBeGreaterThan(0);
		},
		{ timeout: 60_000 },
	);

	it(
		"a non-script failure still wins over a bad script that was already dispatched",
		async () => {
			await warmPool();
			const utxo = new UTXOManager(db);
			const prevOuts = Array.from({ length: WIDE }, (_, i) =>
				fund(utxo, i === 5 ? OP_FALSE : OP_TRUE),
			);
			const wide = spend(prevOuts, AMOUNT * BigInt(WIDE));
			// Coinbase pays 1 sat too much: Core rejects bad-cb-amount before
			// it Wait()s for the script threads.
			const cb = coinbase(getBlockSubsidy(HEIGHT, REGTEST) + 1n);
			const res = await coreConnectBlockChecks(block([cb, wide]), HEIGHT, utxo, REGTEST, {
				scriptThreads: THREADS,
			});
			expect(res.ok).toBe(false);
			expect(res.ok ? "" : res.error).toMatch(/^bad-cb-amount/);
			// The abandoned stream drained before returning, and recorded
			// nothing in the sig cache, not even the good inputs it had sent.
			expect(scriptCheckInFlightBatches()).toBe(0);
			expect(globalSigCache.size).toBe(0);
			// The next block on the same pool: that same bad script, with a
			// correct coinbase, is still a script failure.
			const utxo2 = new UTXOManager(db);
			for (const p of prevOuts) {
				fundAt(utxo2, p, p === prevOuts[5] ? OP_FALSE : OP_TRUE);
			}
			const res2 = await coreConnectBlockChecks(
				block([coinbase(getBlockSubsidy(HEIGHT, REGTEST)), wide]),
				HEIGHT,
				utxo2,
				REGTEST,
				{ scriptThreads: THREADS },
			);
			expect(res2.ok).toBe(false);
			expect(res2.ok ? "" : res2.error).toContain(
				`Script verification failed in tx ${getTxId(wide).toString("hex").slice(0, 16)}`,
			);
			expect(res2.ok ? "" : res2.error).toContain("(input 5)");
			expect(globalSigCache.size).toBe(0);
		},
		{ timeout: 60_000 },
	);

	it(
		"streamed and serial connects report the same earliest script failure",
		async () => {
			const errors: string[] = [];
			for (const threads of [1, THREADS]) {
				if (threads > 1) await warmPool();
				const utxo = new UTXOManager(db);
				const prevOuts = Array.from({ length: 3 * SCRIPTCHECK_BATCH_SIZE }, (_, i) =>
					fund(utxo, i === 140 || i === 300 ? OP_FALSE : OP_TRUE),
				);
				const txs = [coinbase(getBlockSubsidy(HEIGHT, REGTEST))];
				// One input per tx so the failing tx id says which index failed.
				for (const p of prevOuts) txs.push(spend([p], AMOUNT));
				const res = await coreConnectBlockChecks(block(txs), HEIGHT, utxo, REGTEST, {
					scriptThreads: threads,
				});
				expect(res.ok).toBe(false);
				const err = res.ok ? "" : res.error;
				// prevOuts[140] is spent by txs[141]; the txids differ per run.
				const first = getTxId(txs[141]!).toString("hex").slice(0, 16);
				expect(err).toContain(first);
				errors.push(err.replace(first, "<txs[141]>"));
				globalSigCache.clear();
			}
			expect(errors[1]).toBe(errors[0]);
		},
		{ timeout: 60_000 },
	);
});

/** Error prefix of a script failure in `tx` (as coreConnectBlockChecks names it). */
function scriptFailIn(tx: Transaction): string {
	return `Script verification failed in tx ${getTxId(tx).toString("hex").slice(0, 16)}`;
}

/**
 * One single-input tx per coin, so the failing tx says which input failed.
 * Coins at `bad` are locked by OP_FALSE. `refund` re-adds the same coins to
 * another view, so the same block can be connected again.
 */
function oneInputTxs(
	utxo: UTXOManager,
	n: number,
	bad: Set<number>,
): { txs: Transaction[]; refund: (u: UTXOManager) => void } {
	const txs = [coinbase(getBlockSubsidy(HEIGHT, REGTEST))];
	const coins: Array<{ p: { txid: Buffer; vout: number }; spk: Buffer }> = [];
	for (let i = 0; i < n; i++) {
		const spk = bad.has(i) ? OP_FALSE : OP_TRUE;
		const p = fund(utxo, spk);
		coins.push({ p, spk });
		txs.push(spend([p], AMOUNT));
	}
	return { txs, refund: (u) => coins.forEach((c) => fundAt(u, c.p, c.spk)) };
}

// Sig-cache accounting in these tests. Two writers exist on the main thread:
//  - beginScriptChecks().finish() inserts the keys of every cache miss it
//    sent to the workers, and only when the whole block's scripts are valid;
//  - verifyInputSignature (the serial path, and the sequential re-run after
//    a worker fault) inserts one input's key when THIS thread has just
//    verified that input valid (master behaviour; the workers' own caches
//    are private and never reach the main thread).
// So a rejected block may leave exactly the inputs that were verified valid
// here before the first failure, and never a key from the workers' batches.

describe("script-check stream: batch tail, worker faults, exceptions, sig cache", () => {
	it(
		"a bad script in the short tail batch is rejected, streamed and serial alike",
		async () => {
			// BATCH_SIZE + 1 cache misses: one full batch leaves from inside the
			// loop, the last job only at close(). Its script is the only bad one.
			const n = SCRIPTCHECK_BATCH_SIZE + 1;
			const errors: string[] = [];
			for (const threads of [1, THREADS]) {
				if (threads > 1) await warmPool();
				const utxo = new UTXOManager(db);
				const { txs, refund } = oneInputTxs(utxo, n, new Set([n - 1]));
				const last = txs[n]!;
				const res = await coreConnectBlockChecks(block(txs), HEIGHT, utxo, REGTEST, {
					scriptThreads: threads,
				});
				expect(res.ok).toBe(false);
				const err = res.ok ? "" : res.error;
				expect(err).toContain(scriptFailIn(last));
				errors.push(err.replace(getTxId(last).toString("hex").slice(0, 16), "<last>"));
				// Serial: the n - 1 good inputs it verified; streamed: none.
				expect([threads, globalSigCache.size]).toEqual([threads, threads === 1 ? n - 1 : 0]);
				// The bad input was not cached: the same block fails again.
				const again = new UTXOManager(db);
				refund(again);
				const res2 = await coreConnectBlockChecks(block(txs), HEIGHT, again, REGTEST, {
					scriptThreads: threads,
				});
				expect(res2.ok ? "" : res2.error).toContain(scriptFailIn(last));
				globalSigCache.clear();
			}
			expect(errors[1]).toBe(errors[0]);
		},
		{ timeout: 60_000 },
	);

	const faults: Array<{ name: string; worker: string; timeoutMs?: number }> = [
		{ name: 'a worker answering kind:"crash"', worker: "./script_check_crash_worker.ts" },
		{ name: "a worker that never answers (result timeout)", worker: "./script_check_hang_worker.ts", timeoutMs: 250 },
		{ name: "a worker whose result list is one short", worker: "./script_check_short_worker.ts" },
	];
	for (const f of faults) {
		it(
			`${f.name}: the same jobs are re-run here and the bad script rejects the block`,
			async () => {
				if (f.timeoutMs !== undefined) setScriptCheckResultTimeoutForTests(f.timeoutMs);
				setScriptCheckWorkerUrlForTests(new URL(f.worker, import.meta.url));
				await shutdownScriptCheckPool();
				await warmPool(); // these workers verify nothing: warm-up re-runs serially
				const utxo = new UTXOManager(db);
				// The bad script sits in the first full batch, sent from the loop.
				const n = 2 * SCRIPTCHECK_BATCH_SIZE;
				const { txs, refund } = oneInputTxs(utxo, n, new Set([5]));
				scriptCheckResetStats();
				const res = await coreConnectBlockChecks(block(txs), HEIGHT, utxo, REGTEST, {
					scriptThreads: THREADS,
				});
				// The jobs did reach the faulty pool (this is the stream path).
				expect(scriptCheckPeakInFlightJobs()).toBeGreaterThan(0);
				expect(res.ok).toBe(false);
				expect(res.ok ? "" : res.error).toContain(scriptFailIn(txs[6]!));
				// Only the sequential re-run's own verdicts: inputs 0..4, verified
				// valid here before input 5 failed. None of the 2 x 128 keys the
				// faulty batches carried.
				expect(globalSigCache.size).toBe(5);
				expect(scriptCheckInFlightBatches()).toBe(0);
				// The same block on the same faulty pool still fails.
				const again = new UTXOManager(db);
				refund(again);
				const res2 = await coreConnectBlockChecks(block(txs), HEIGHT, again, REGTEST, {
					scriptThreads: THREADS,
				});
				expect(res2.ok ? "" : res2.error).toContain(scriptFailIn(txs[6]!));
			},
			{ timeout: 60_000 },
		);
	}

	it(
		"a throw from the tx loop after a full batch is in flight stays a throw, drains, and the next bad block still fails",
		async () => {
			await warmPool();
			const utxo = new UTXOManager(db);
			const prevOuts = Array.from({ length: WIDE }, (_, i) =>
				fund(utxo, i === 5 ? OP_FALSE : OP_TRUE),
			);
			const wide = spend(prevOuts, AMOUNT * BigInt(WIDE));
			const probeCoinHeight = 7;
			const late = spend(
				[fund(utxo, OP_TRUE, probeCoinHeight)],
				AMOUNT,
				SEQUENCE_LOCKTIME_TYPE_FLAG | 1,
			);
			const cb = coinbase(getBlockSubsidy(HEIGHT, REGTEST));
			let inFlightAtThrow = -1;
			await expect(
				coreConnectBlockChecks(block([cb, wide, late]), HEIGHT, utxo, REGTEST, {
					scriptThreads: THREADS,
					enforceBIP68: true,
					prevMTP: 1_700_000_000,
					getUTXOMTP: (h: number) => {
						if (h === probeCoinHeight) {
							inFlightAtThrow = scriptCheckInFlightBatches();
							throw new Error("probe: header store unavailable");
						}
						return 0;
					},
				}),
			).rejects.toThrow("probe: header store unavailable");
			// A batch holding the bad script was with a worker when it threw.
			expect(inFlightAtThrow).toBeGreaterThan(0);
			// ...and had settled by the time the throw reached us.
			expect(scriptCheckInFlightBatches()).toBe(0);
			expect(globalSigCache.size).toBe(0);

			// Next block on the same pool: a new bad script at a cache miss.
			const utxo2 = new UTXOManager(db);
			const { txs } = oneInputTxs(utxo2, 2 * SCRIPTCHECK_BATCH_SIZE, new Set([200]));
			const res = await coreConnectBlockChecks(block(txs), HEIGHT, utxo2, REGTEST, {
				scriptThreads: THREADS,
			});
			expect(res.ok).toBe(false);
			expect(res.ok ? "" : res.error).toContain(scriptFailIn(txs[201]!));
			expect(globalSigCache.size).toBe(0);
		},
		{ timeout: 60_000 },
	);

	it(
		"a script-invalid block inserts no sig-cache entry, and the same bad script fails again",
		async () => {
			await warmPool();
			const prevOuts: { txid: Buffer; vout: number }[] = [];
			const scratch = new UTXOManager(db);
			for (let i = 0; i < WIDE; i++) prevOuts.push(fund(scratch, OP_TRUE));
			const spk = (i: number) => (i === 140 ? OP_FALSE : OP_TRUE);
			const txs = [coinbase(getBlockSubsidy(HEIGHT, REGTEST))];
			for (const p of prevOuts) txs.push(spend([p], AMOUNT));
			for (let round = 0; round < 2; round++) {
				const utxo = new UTXOManager(db);
				prevOuts.forEach((p, i) => fundAt(utxo, p, spk(i)));
				const res = await coreConnectBlockChecks(block(txs), HEIGHT, utxo, REGTEST, {
					scriptThreads: THREADS,
				});
				expect([round, res.ok]).toEqual([round, false]);
				expect(res.ok ? "" : res.error).toContain(scriptFailIn(txs[141]!));
				expect([round, globalSigCache.size]).toEqual([round, 0]);
			}
		},
		{ timeout: 60_000 },
	);

	it(
		"a valid streamed block caches its inputs; next time they are skipped and a new bad script at a miss still fails",
		async () => {
			await warmPool();
			const scratch = new UTXOManager(db);
			const prevOuts = Array.from({ length: WIDE }, () => fund(scratch, OP_TRUE));
			const goodTxs = prevOuts.map((p) => spend([p], AMOUNT));
			const cb = coinbase(getBlockSubsidy(HEIGHT, REGTEST));

			const utxo1 = new UTXOManager(db);
			for (const p of prevOuts) fundAt(utxo1, p, OP_TRUE);
			const ok = await coreConnectBlockChecks(block([cb, ...goodTxs]), HEIGHT, utxo1, REGTEST, {
				scriptThreads: THREADS,
			});
			expect(ok.ok).toBe(true);
			expect(globalSigCache.size).toBe(WIDE);

			// Same txs (all hits) plus MIN_JOBS_FOR_POOL-sized group of new
			// inputs, the last of which is bad.
			const utxo2 = new UTXOManager(db);
			for (const p of prevOuts) fundAt(utxo2, p, OP_TRUE);
			const fresh = 16;
			const newTxs: Transaction[] = [];
			for (let i = 0; i < fresh; i++) {
				newTxs.push(spend([fund(utxo2, i === fresh - 1 ? OP_FALSE : OP_TRUE)], AMOUNT));
			}
			scriptCheckResetStats();
			const res = await coreConnectBlockChecks(
				block([cb, ...goodTxs, ...newTxs]),
				HEIGHT,
				utxo2,
				REGTEST,
				{ scriptThreads: THREADS },
			);
			expect(res.ok).toBe(false);
			expect(res.ok ? "" : res.error).toContain(scriptFailIn(newTxs[fresh - 1]!));
			// Only the misses went to the workers.
			expect(scriptCheckPeakInFlightJobs()).toBeGreaterThan(0);
			expect(scriptCheckPeakInFlightJobs()).toBeLessThanOrEqual(fresh);
			// Nothing new was cached for the invalid block.
			expect(globalSigCache.size).toBe(WIDE);
		},
		{ timeout: 60_000 },
	);
});

