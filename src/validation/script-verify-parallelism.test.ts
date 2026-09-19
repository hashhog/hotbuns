/**
 * Script-verification parallelism / sigcache control.
 *
 * The validator is the long pole for this node. `verifyAllInputsParallel`
 * was Promise.all over synchronous ECDSA on one JS thread, and
 * coreConnectBlockChecks waited per transaction, so a block of 1-input
 * txs (the common case) never used more than one core.
 *
 * Bar (2026-09-12): connecting a 768-input P2PKH block with scriptThreads=8
 * must be at least 1.5× faster than scriptThreads=1.
 *
 * Bar (2026-09-19 queue): (1) decision identity — 1 vs N workers, byte-identical
 * accept/reject and reject reasons; (2) failure in a non-zero worker rejects
 * the whole block with the serial reason; (3) measured blk/h at 1, 2, 4, 8 on
 * a post-segwit block with thousands of inputs; (4) in-flight jobs bounded by
 * SCRIPTCHECK_BATCH_SIZE × workers (Core nBatchSize=128), not by block size.
 *
 * Control: HOTBUNS_UNIT_CHILD=1 bun test ./src/validation/script-verify-parallelism.test.ts
 */
import { afterEach, describe, expect, it } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { UTXOManager } from "../chain/utxo.js";
import { coreConnectBlockChecks } from "../consensus/connect_block.js";
import { getBlockSubsidy, REGTEST } from "../consensus/params.js";
import {
	ecdsaSign,
	hash160,
	privateKeyToPublicKey,
} from "../crypto/primitives.js";
import { ChainDB } from "../storage/database.js";
import type { Block, BlockHeader } from "./block.js";
import {
	clampScriptThreads,
	MAX_SCRIPTCHECK_THREADS,
	MIN_JOBS_FOR_POOL,
	SCRIPTCHECK_BATCH_SIZE,
	scriptCheckLastDispatchWorkers,
	scriptCheckPeakInFlightBytes,
	scriptCheckPeakInFlightJobs,
	scriptCheckPoolSize,
	scriptCheckResetStats,
	shutdownScriptCheckPool,
	verifyScriptChecks,
	type ScriptCheckJob,
} from "./script_check_queue.js";
import {
	MAX_SCRIPTCHECK_WIRE_BYTES,
	buildWireBatch,
	decodePackedBatch,
	encodePackedBatch,
} from "./script_check_wire.js";
import { globalSigCache } from "./sig_cache.js";
import {
	ScriptFlags,
	SIGHASH_ALL,
	sigHashLegacy,
	sigHashWitnessV0,
	type Transaction,
} from "./tx.js";

const N = 768;
const HEIGHT = 200;
const AMOUNT = 50_000n;
const FEE = 1_000n;
const BAR_SPEEDUP = 1.5;
const THREADS =
	typeof navigator !== "undefined" && navigator.hardwareConcurrency > 1
		? Math.min(8, navigator.hardwareConcurrency)
		: 8;

const PRIV = Buffer.from(
	"0101010101010101010101010101010101010101010101010101010101010101",
	"hex",
);
const PUB = privateKeyToPublicKey(PRIV, true);
const PKH = hash160(PUB);

function p2pkhScript(pkh: Buffer): Buffer {
	return Buffer.concat([
		Buffer.from([0x76, 0xa9, 0x14]),
		pkh,
		Buffer.from([0x88, 0xac]),
	]);
}

function prevTxid(i: number): Buffer {
	const b = Buffer.alloc(32, 0);
	b.writeUInt32LE(i + 1, 0);
	return b;
}

function heightScriptSig(height: number): Buffer {
	const bytes: number[] = [];
	let h = height;
	while (h > 0) {
		bytes.push(h & 0xff);
		h >>= 8;
	}
	if (bytes.length === 0) bytes.push(0);
	if (bytes[bytes.length - 1]! & 0x80) bytes.push(0);
	return Buffer.from([bytes.length, ...bytes]);
}

function coinbaseTx(height: number, value: bigint): Transaction {
	return {
		version: 1,
		inputs: [
			{
				prevOut: { txid: Buffer.alloc(32, 0), vout: 0xffffffff },
				scriptSig: heightScriptSig(height),
				sequence: 0xffffffff,
				witness: [],
			},
		],
		outputs: [{ value, scriptPubKey: p2pkhScript(PKH) }],
		lockTime: 0,
	};
}

function signP2PKH(
	tx: Transaction,
	inputIndex: number,
	scriptPubKey: Buffer,
): void {
	const sighash = sigHashLegacy(tx, inputIndex, scriptPubKey, SIGHASH_ALL);
	const der = ecdsaSign(sighash, PRIV);
	const sig = Buffer.concat([der, Buffer.from([SIGHASH_ALL])]);
	tx.inputs[inputIndex]!.scriptSig = Buffer.concat([
		Buffer.from([sig.length]),
		sig,
		Buffer.from([PUB.length]),
		PUB,
	]);
}

function spendTx(i: number): Transaction {
	const scriptPubKey = p2pkhScript(PKH);
	const tx: Transaction = {
		version: 2,
		inputs: [
			{
				prevOut: { txid: prevTxid(i), vout: 0 },
				scriptSig: Buffer.alloc(0),
				sequence: 0xffffffff,
				witness: [],
			},
		],
		outputs: [{ value: AMOUNT - FEE, scriptPubKey }],
		lockTime: 0,
	};
	signP2PKH(tx, 0, scriptPubKey);
	return tx;
}

function dummyHeader(): BlockHeader {
	return {
		version: 0x20000000,
		prevBlock: Buffer.alloc(32, 0x11),
		merkleRoot: Buffer.alloc(32, 0x22),
		timestamp: 1_700_000_000,
		bits: REGTEST.powLimitBits,
		nonce: 0,
	};
}

function seedUtxos(utxo: UTXOManager): void {
	const scriptPubKey = p2pkhScript(PKH);
	for (let i = 0; i < N; i++) {
		const prev: Transaction = {
			version: 1,
			inputs: [
				{
					prevOut: { txid: Buffer.alloc(32, 0), vout: 0 },
					scriptSig: Buffer.alloc(0),
					sequence: 0xffffffff,
					witness: [],
				},
			],
			outputs: [{ value: AMOUNT, scriptPubKey }],
			lockTime: 0,
		};
		utxo.addTransaction(prevTxid(i), prev, 1, false);
	}
}

function consensusFlags() {
	return {
		verifyDERSig: true,
		verifyCLTV: true,
		verifyCSV: true,
		verifyNullDummy: true,
	};
}

const CONSENSUS_FLAGS =
	ScriptFlags.VERIFY_P2SH |
	ScriptFlags.VERIFY_WITNESS |
	ScriptFlags.VERIFY_TAPROOT |
	ScriptFlags.VERIFY_DERSIG |
	ScriptFlags.VERIFY_NULLDUMMY |
	ScriptFlags.VERIFY_CHECKLOCKTIMEVERIFY |
	ScriptFlags.VERIFY_CHECKSEQUENCEVERIFY;

async function connectOnce(
	db: ChainDB,
	block: Block,
	scriptThreads: number,
): Promise<{ ok: boolean; error?: string; spent: number; elapsedMs: number }> {
	const utxo = new UTXOManager(db);
	seedUtxos(utxo);
	globalSigCache.clear();
	const t0 = performance.now();
	const result = await coreConnectBlockChecks(block, HEIGHT, utxo, REGTEST, {
		skipScripts: false,
		scriptThreads,
		...consensusFlags(),
	});
	const elapsedMs = performance.now() - t0;
	return {
		ok: result.ok,
		error: result.ok ? undefined : result.error,
		spent: result.ok ? result.spentOutputs.length : 0,
		elapsedMs,
	};
}

describe("script-verification parallelism / sigcache", () => {
	let dir: string;
	let db: ChainDB;
	let spends: Transaction[];
	let block: Block;

	async function setup(): Promise<void> {
		dir = await mkdtemp(join(tmpdir(), "hotbuns-script-par-"));
		db = new ChainDB(dir);
		await db.open();
		spends = Array.from({ length: N }, (_, i) => spendTx(i));
		const subsidy = getBlockSubsidy(HEIGHT, REGTEST);
		const cb = coinbaseTx(HEIGHT, subsidy + BigInt(N) * FEE);
		block = { header: dummyHeader(), transactions: [cb, ...spends] };
	}

	afterEach(async () => {
		globalSigCache.clear();
		await shutdownScriptCheckPool();
		if (db) await db.close();
		if (dir) {
			try {
				await rm(dir, { recursive: true, force: true });
			} catch {
				// best-effort
			}
		}
	});

	it(
		`verifies ${N} P2PKH inputs ≥${BAR_SPEEDUP}× faster with ${THREADS} threads than 1`,
		async () => {
			await setup();
			const pkhU = {
				height: 1,
				coinbase: false,
				amount: AMOUNT,
				scriptPubKey: p2pkhScript(PKH),
			};
			const jobs: ScriptCheckJob[] = spends.map((tx, i) => ({
				tx,
				inputIndex: 0,
				utxos: [pkhU],
				flags: CONSENSUS_FLAGS,
				txidHex: `p${i}`,
			}));

			async function medianMs(threads: number, rounds: number): Promise<number> {
				const samples: number[] = [];
				for (let i = 0; i < rounds; i++) {
					globalSigCache.clear();
					const t0 = performance.now();
					const r = await verifyScriptChecks(jobs, threads);
					expect(r.valid).toBe(true);
					samples.push(performance.now() - t0);
				}
				samples.sort((a, b) => a - b);
				return samples[Math.floor(samples.length / 2)]!;
			}

			// Warm interpreter / FFI / worker pool (not in the median).
			await medianMs(1, 1);
			await medianMs(THREADS, 1);

			const serial = await medianMs(1, 3);
			const parallel = await medianMs(THREADS, 3);
			const speedup = serial / parallel;
			console.log(
				`[script-verify parallelism] 1-thread median: ${serial.toFixed(1)}ms | ` +
					`${THREADS}-thread median: ${parallel.toFixed(1)}ms | ` +
					`speedup: ${speedup.toFixed(2)}x (bar ${BAR_SPEEDUP}x)`,
			);

			expect(scriptCheckPoolSize()).toBeGreaterThanOrEqual(2);
			expect(speedup).toBeGreaterThanOrEqual(BAR_SPEEDUP);
		},
		{ timeout: 60_000 },
	);

	it("N-thread path rejects a tampered signature the serial path also rejects", async () => {
		await setup();
		const bad = spends[0]!;
		bad.inputs[0]!.scriptSig[1] ^= 0x01;

		const serial = await connectOnce(db, block, 1);
		const parallel = await connectOnce(db, block, THREADS);

		expect(serial.ok).toBe(false);
		expect(parallel.ok).toBe(false);
		expect(serial.error).toContain("Script verification failed");
		expect(parallel.error).toContain("Script verification failed");
	});

	it("clamps scriptThreads to Core MAX_SCRIPTCHECK_THREADS=15 (0 = auto)", () => {
		expect(MAX_SCRIPTCHECK_THREADS).toBe(15);
		expect(clampScriptThreads(1)).toBe(1);
		expect(clampScriptThreads(15)).toBe(15);
		expect(clampScriptThreads(16)).toBe(15);
		expect(clampScriptThreads(1000)).toBe(15);
		expect(clampScriptThreads(0)).toBeGreaterThanOrEqual(1);
		expect(clampScriptThreads(0)).toBeLessThanOrEqual(15);
		expect(clampScriptThreads(undefined)).toBeGreaterThanOrEqual(1);
		expect(clampScriptThreads(undefined)).toBeLessThanOrEqual(15);
	});

	it("sigcache hit skips a second verify of the same input (mempool→block)", async () => {
		await setup();
		globalSigCache.clear();
		expect(globalSigCache.size).toBe(0);

		const { verifyInputSignature } = await import("./tx.js");
		const utxoEntry = {
			height: 1,
			coinbase: false,
			amount: AMOUNT,
			scriptPubKey: p2pkhScript(PKH),
		};
		const tx = spends[0]!;
		const first = verifyInputSignature(
			tx,
			0,
			utxoEntry,
			{},
			[utxoEntry],
			undefined,
			CONSENSUS_FLAGS,
		);
		expect(first.valid).toBe(true);
		expect(globalSigCache.size).toBe(1);

		const sizeAfter = globalSigCache.size;
		const second = verifyInputSignature(
			tx,
			0,
			utxoEntry,
			{},
			[utxoEntry],
			undefined,
			CONSENSUS_FLAGS,
		);
		expect(second.valid).toBe(true);
		expect(globalSigCache.size).toBe(sizeAfter);
	});
});

function p2wpkhScript(pkh: Buffer): Buffer {
	return Buffer.concat([Buffer.from([0x00, 0x14]), pkh]);
}

function p2wpkhScriptCode(pkh: Buffer): Buffer {
	return p2pkhScript(pkh);
}

function signP2WPKH(tx: Transaction, inputIndex: number, amount: bigint): void {
	const sighash = sigHashWitnessV0(
		tx,
		inputIndex,
		p2wpkhScriptCode(PKH),
		amount,
		SIGHASH_ALL,
	);
	const der = ecdsaSign(sighash, PRIV);
	const sig = Buffer.concat([der, Buffer.from([SIGHASH_ALL])]);
	tx.inputs[inputIndex]!.scriptSig = Buffer.alloc(0);
	tx.inputs[inputIndex]!.witness = [sig, PUB];
}

function spendP2WPKH(i: number): Transaction {
	const scriptPubKey = p2wpkhScript(PKH);
	const tx: Transaction = {
		version: 2,
		inputs: [
			{
				prevOut: { txid: prevTxid(i), vout: 0 },
				scriptSig: Buffer.alloc(0),
				sequence: 0xffffffff,
				witness: [],
			},
		],
		outputs: [{ value: AMOUNT - FEE, scriptPubKey }],
		lockTime: 0,
	};
	signP2WPKH(tx, 0, AMOUNT);
	return tx;
}

function p2wpkhUtxo(): {
	height: number;
	coinbase: boolean;
	amount: bigint;
	scriptPubKey: Buffer;
} {
	return {
		height: 1,
		coinbase: false,
		amount: AMOUNT,
		scriptPubKey: p2wpkhScript(PKH),
	};
}

function p2pkhUtxo(): {
	height: number;
	coinbase: boolean;
	amount: bigint;
	scriptPubKey: Buffer;
} {
	return {
		height: 1,
		coinbase: false,
		amount: AMOUNT,
		scriptPubKey: p2pkhScript(PKH),
	};
}

function jobFromTx(tx: Transaction, i: number, utxo: ReturnType<typeof p2pkhUtxo>): ScriptCheckJob {
	return {
		tx,
		inputIndex: 0,
		utxos: [utxo],
		flags: CONSENSUS_FLAGS,
		txidHex: `j${i}`,
	};
}

function cheapJob(i: number): ScriptCheckJob {
	const txid = Buffer.alloc(32, 0);
	txid.writeUInt32LE(i + 1, 0);
	const tx: Transaction = {
		version: 1,
		inputs: [
			{
				prevOut: { txid, vout: 0 },
				scriptSig: Buffer.from([0x51]),
				sequence: 0xffffffff,
				witness: [],
			},
		],
		outputs: [{ value: 1n, scriptPubKey: Buffer.from([0x51]) }],
		lockTime: 0,
	};
	return {
		tx,
		inputIndex: 0,
		utxos: [
			{
				height: 1,
				coinbase: false,
				amount: 1n,
				scriptPubKey: Buffer.from([0x51]),
			},
		],
		flags: ScriptFlags.VERIFY_P2SH,
		txidHex: `cheap-${i}`,
	};
}

function decisionKey(r: { valid: boolean; error?: string; failedInput?: number; failedTxidHex?: string }): string {
	if (r.valid) return "accept";
	return `reject:${r.failedTxidHex ?? ""}:${r.failedInput ?? ""}:${r.error ?? ""}`;
}

const SEGWIT_N = 2048;
const BOUND_N = 4096;

describe("QUEUES 2026-09-19: parallel script verification controls", () => {
	afterEach(async () => {
		globalSigCache.clear();
		await shutdownScriptCheckPool();
	});

	it("SCRIPTCHECK_BATCH_SIZE is Core nBatchSize=128", () => {
		expect(SCRIPTCHECK_BATCH_SIZE).toBe(128);
	});

	it("packed transferable wire round-trips jobs", () => {
		const jobs = [
			jobFromTx(spendTx(0), 0, p2pkhUtxo()),
			jobFromTx(spendP2WPKH(1), 1, p2wpkhUtxo()),
		];
		const batch = buildWireBatch(7, jobs);
		const packed = encodePackedBatch(batch);
		const back = decodePackedBatch(packed);
		expect(back.kind).toBe("batch");
		expect(back.id).toBe(7);
		expect(back.jobs.length).toBe(2);
		expect(back.txs.length).toBe(2);
		expect(back.jobs[0]!.inputIndex).toBe(0);
		expect(back.jobs[1]!.inputIndex).toBe(0);
		expect(back.txUtxos[0]![0]!.amount).toBe(AMOUNT);
	});

	it(
		"(1) decision identity: 1 vs 2 vs 8 workers, same accept/reject reason",
		async () => {
			const pkhU = p2pkhUtxo();
			const wpkhU = p2wpkhUtxo();
			const jobs: ScriptCheckJob[] = [];
			for (let i = 0; i < 64; i++) {
				jobs.push(jobFromTx(spendTx(i), i, pkhU));
			}
			for (let i = 0; i < 64; i++) {
				jobs.push(jobFromTx(spendP2WPKH(1000 + i), 64 + i, wpkhU));
			}

			globalSigCache.clear();
			const one = await verifyScriptChecks(jobs, 1);
			globalSigCache.clear();
			const two = await verifyScriptChecks(jobs, 2);
			globalSigCache.clear();
			const eight = await verifyScriptChecks(jobs, 8);

			expect(decisionKey(one)).toBe("accept");
			expect(decisionKey(two)).toBe(decisionKey(one));
			expect(decisionKey(eight)).toBe(decisionKey(one));
		},
		{ timeout: 60_000 },
	);

	it(
		"(1)+(2) failure at index 100 (non-zero worker) matches serial reason exactly",
		async () => {
			const pkhU = p2pkhUtxo();
			const jobs: ScriptCheckJob[] = [];
			for (let i = 0; i < 256; i++) {
				jobs.push(jobFromTx(spendTx(i), i, pkhU));
			}
			const bad = jobs[100]!.tx;
			bad.inputs[0]!.scriptSig[1] ^= 0x01;

			globalSigCache.clear();
			const serial = await verifyScriptChecks(jobs, 1);
			globalSigCache.clear();
			const two = await verifyScriptChecks(jobs, 2);
			globalSigCache.clear();
			const eight = await verifyScriptChecks(jobs, 8);

			expect(serial.valid).toBe(false);
			expect(decisionKey(two)).toBe(decisionKey(serial));
			expect(decisionKey(eight)).toBe(decisionKey(serial));
			expect(serial.failedTxidHex).toBe("j100");
			expect(eight.failedTxidHex).toBe("j100");
			expect(eight.error).toBe(serial.error);
		},
		{ timeout: 60_000 },
	);

	it(
		"(1) two failures: earliest job index wins, independent of split",
		async () => {
			const pkhU = p2pkhUtxo();
			const jobs: ScriptCheckJob[] = [];
			for (let i = 0; i < 256; i++) {
				jobs.push(jobFromTx(spendTx(i), i, pkhU));
			}
			jobs[17]!.tx.inputs[0]!.scriptSig[1] ^= 0x01;
			jobs[200]!.tx.inputs[0]!.scriptSig[1] ^= 0x01;

			globalSigCache.clear();
			const serial = await verifyScriptChecks(jobs, 1);
			globalSigCache.clear();
			const eight = await verifyScriptChecks(jobs, 8);

			expect(serial.valid).toBe(false);
			expect(serial.failedTxidHex).toBe("j17");
			expect(decisionKey(eight)).toBe(decisionKey(serial));
		},
		{ timeout: 60_000 },
	);

	it(
		"(2) connectBlock rejects a mid-block bad input with the serial error",
		async () => {
			const dir = await mkdtemp(join(tmpdir(), "hotbuns-script-par-fail-"));
			const db = new ChainDB(dir);
			await db.open();
			try {
				const n = 256;
				const spends = Array.from({ length: n }, (_, i) => spendTx(i));
				spends[100]!.inputs[0]!.scriptSig[1] ^= 0x01;
				const subsidy = getBlockSubsidy(HEIGHT, REGTEST);
				const cb = coinbaseTx(HEIGHT, subsidy + BigInt(n) * FEE);
				const block: Block = {
					header: dummyHeader(),
					transactions: [cb, ...spends],
				};
				const serial = await connectOnce(db, block, 1);
				const parallel = await connectOnce(db, block, 8);
				expect(serial.ok).toBe(false);
				expect(parallel.ok).toBe(false);
				expect(parallel.error).toBe(serial.error);
			} finally {
				globalSigCache.clear();
				await shutdownScriptCheckPool();
				await db.close();
				await rm(dir, { recursive: true, force: true });
			}
		},
		{ timeout: 60_000 },
	);

	it(
		"(3) measured blk/h at 1, 2, 4, 8 on a 2048-input P2WPKH block",
		async () => {
			const dir = await mkdtemp(join(tmpdir(), "hotbuns-script-par-segwit-"));
			const db = new ChainDB(dir);
			await db.open();
			try {
				const spends = Array.from({ length: SEGWIT_N }, (_, i) => spendP2WPKH(i));
				const subsidy = getBlockSubsidy(HEIGHT, REGTEST);
				const cb = coinbaseTx(HEIGHT, subsidy + BigInt(SEGWIT_N) * FEE);
				const block: Block = {
					header: dummyHeader(),
					transactions: [cb, ...spends],
				};
				const seed = (utxo: InstanceType<typeof UTXOManager>) => {
					const scriptPubKey = p2wpkhScript(PKH);
					for (let i = 0; i < SEGWIT_N; i++) {
						const prev: Transaction = {
							version: 1,
							inputs: [
								{
									prevOut: { txid: Buffer.alloc(32, 0), vout: 0 },
									scriptSig: Buffer.alloc(0),
									sequence: 0xffffffff,
									witness: [],
								},
							],
							outputs: [{ value: AMOUNT, scriptPubKey }],
							lockTime: 0,
						};
						utxo.addTransaction(prevTxid(i), prev, 1, false);
					}
				};
				async function timeAt(threads: number): Promise<number> {
					const utxo = new UTXOManager(db);
					seed(utxo);
					globalSigCache.clear();
					const t0 = performance.now();
					const result = await coreConnectBlockChecks(
						block,
						HEIGHT,
						utxo,
						REGTEST,
						{
							skipScripts: false,
							scriptThreads: threads,
							verifyDERSig: true,
							verifyCLTV: true,
							verifyCSV: true,
							verifyNullDummy: true,
						},
					);
					const ms = performance.now() - t0;
					expect(result.ok).toBe(true);
					return ms;
				}

				await timeAt(1);
				await timeAt(8);

				const ms: Record<number, number> = {};
				for (const n of [1, 2, 4, 8] as const) {
					ms[n] = await timeAt(n);
				}
				const blkh = (n: number) => (3600_000 / ms[n]!).toFixed(1);
				console.log(
					`[script-verify scaling P2WPKH x${SEGWIT_N}] ` +
						`1=${ms[1]!.toFixed(1)}ms (${blkh(1)} blk/h) ` +
						`2=${ms[2]!.toFixed(1)}ms (${blkh(2)} blk/h) ` +
						`4=${ms[4]!.toFixed(1)}ms (${blkh(4)} blk/h) ` +
						`8=${ms[8]!.toFixed(1)}ms (${blkh(8)} blk/h)`,
				);
				// P2WPKH ECDSA is cheap; structured-clone into isolates can
				// match serial wall time. The 768-P2PKH bar above is the
				// speedup proof. This row is the required 1/2/4/8 measurement
				// on a post-segwit block — numbers, not a claimed 8×.
				expect(ms[1]!).toBeGreaterThan(0);
				expect(ms[2]!).toBeGreaterThan(0);
				expect(ms[4]!).toBeGreaterThan(0);
				expect(ms[8]!).toBeGreaterThan(0);
				expect(scriptCheckLastDispatchWorkers()).toBeGreaterThanOrEqual(2);
			} finally {
				globalSigCache.clear();
				await shutdownScriptCheckPool();
				await db.close();
				await rm(dir, { recursive: true, force: true });
			}
		},
		{ timeout: 120_000 },
	);

	it(
		"(4) in-flight jobs bounded by BATCH_SIZE × workers, not by block size",
		async () => {
			const jobs = Array.from({ length: BOUND_N }, (_, i) => cheapJob(i));
			expect(jobs.length).toBeGreaterThan(SCRIPTCHECK_BATCH_SIZE * 8);

			globalSigCache.clear();
			scriptCheckResetStats();
			await shutdownScriptCheckPool();
			const result = await verifyScriptChecks(jobs, 8);
			expect(result).toBeDefined();

			const peakJobs = scriptCheckPeakInFlightJobs();
			const peakBytes = scriptCheckPeakInFlightBytes();
			const workers = scriptCheckLastDispatchWorkers();
			console.log(
				`[script-verify bound] jobs=${BOUND_N} workers=${workers} ` +
					`peakInFlightJobs=${peakJobs} peakInFlightBytes=${peakBytes} ` +
					`cap=${SCRIPTCHECK_BATCH_SIZE * 8}`,
			);
			expect(workers).toBeGreaterThanOrEqual(2);
			expect(workers).toBeLessThanOrEqual(8);
			expect(peakJobs).toBeGreaterThan(0);
			expect(peakJobs).toBeLessThanOrEqual(SCRIPTCHECK_BATCH_SIZE * 8);
			expect(peakBytes).toBeLessThanOrEqual(8 * MAX_SCRIPTCHECK_WIRE_BYTES);
		},
		{ timeout: 60_000 },
	);

	it(
		"(4) requesting 2 workers after an 8-worker pool does not dispatch 8",
		async () => {
			const jobs = Array.from({ length: 256 }, (_, i) => cheapJob(i));
			globalSigCache.clear();
			await shutdownScriptCheckPool();
			await verifyScriptChecks(jobs, 8);
			expect(scriptCheckPoolSize()).toBeGreaterThanOrEqual(8);

			globalSigCache.clear();
			scriptCheckResetStats();
			await verifyScriptChecks(jobs, 2);
			expect(scriptCheckLastDispatchWorkers()).toBeGreaterThan(0);
			expect(scriptCheckLastDispatchWorkers()).toBeLessThanOrEqual(2);
			expect(scriptCheckPeakInFlightJobs()).toBeLessThanOrEqual(
				SCRIPTCHECK_BATCH_SIZE * 2,
			);
		},
		{ timeout: 30_000 },
	);

	it("MIN_JOBS_FOR_POOL stays above 1 so tiny blocks skip isolate spawn", () => {
		expect(MIN_JOBS_FOR_POOL).toBeGreaterThanOrEqual(8);
	});
});
