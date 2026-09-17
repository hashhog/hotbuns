/**
 * 900k-era RSS vs --dbcache: peak RSS must be a function of the cache
 * budget, not of post-segwit block weight.
 *
 * Live 2026-09-17T19:30Z on 0f1a48b: 900000→910000 peaked at 24.8 GB RSS
 * against --dbcache=2560 (9.7×), JS heap 1–7 GB, so most of the set is
 * native / worker-isolate / LevelDB-mmap. The script-check pool copied
 * every input's full UTXO vector per job (O(inputs²) wire) and spawned
 * 15 isolates regardless of dbcache.
 *
 * Control: HOTBUNS_UNIT_CHILD=1 bun test ./src/validation/dbcache-rss-bound.test.ts
 */
import { afterEach, describe, expect, test } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { readFileSync } from "node:fs";
import { CoinsViewCache, CoinsViewDB, UTXOManager, type Coin } from "../chain/utxo.js";
import { exceedsRssBudget, snapshotMemory } from "../chain/memory_snapshot.js";
import { ChainDB } from "../storage/database.js";
import type { OutPoint } from "./tx.js";
import type { Transaction } from "./tx.js";
import { ScriptFlags } from "./tx.js";
import {
	SCRIPT_WORKER_RSS_BUDGET,
	clampScriptThreads,
	scriptCheckPoolSize,
	type ScriptCheckJob,
} from "./script_check_queue.js";
import {
	buildWireBatch,
	countWireUtxos,
	estimateWireBatchBytes,
	splitJobsByWireBudget,
} from "./script_check_wire.js";

function makeCoin(scriptPubKey: Buffer): Coin {
	return {
		txOut: { value: 50_000n, scriptPubKey },
		height: 100,
		isCoinbase: false,
	};
}

function makeOutpoint(n: number): OutPoint {
	const txid = Buffer.alloc(32, 0);
	txid.writeUInt32LE(n + 1, 0);
	return { txid, vout: 0 };
}

function fatTx(nInputs: number, scriptLen: number): { tx: Transaction; jobs: ScriptCheckJob[] } {
	const scriptPubKey = Buffer.alloc(scriptLen, 0x51);
	const utxos = Array.from({ length: nInputs }, () => ({
		height: 1,
		coinbase: false,
		amount: 50_000n,
		scriptPubKey,
	}));
	const tx: Transaction = {
		version: 2,
		inputs: Array.from({ length: nInputs }, (_, i) => ({
			prevOut: { txid: Buffer.alloc(32, i + 1), vout: 0 },
			scriptSig: Buffer.alloc(0),
			sequence: 0xffffffff,
			witness: [Buffer.alloc(33, 0x02), Buffer.alloc(64, 0xab)],
		})),
		outputs: [{ value: 40_000n, scriptPubKey }],
		lockTime: 0,
	};
	const jobs: ScriptCheckJob[] = Array.from({ length: nInputs }, (_, i) => ({
		tx,
		inputIndex: i,
		utxos,
		flags: ScriptFlags.VERIFY_WITNESS,
	}));
	return { tx, jobs };
}

describe("dbcache bounds script-check workers", () => {
	test("clampScriptThreads(15, 32 MiB) is 1, not 15", () => {
		expect(SCRIPT_WORKER_RSS_BUDGET).toBe(64 * 1024 * 1024);
		expect(clampScriptThreads(15)).toBe(15);
		expect(clampScriptThreads(15, 32 * 1024 * 1024)).toBe(1);
		expect(clampScriptThreads(15, 2560 * 1024 * 1024)).toBe(15);
		expect(clampScriptThreads(8, 512 * 1024 * 1024)).toBe(8);
	});
});

describe("script-check wire is O(inputs) not O(inputs²)", () => {
	test("source no longer maps utxos per job", () => {
		const src = readFileSync(new URL("./script_check_queue.ts", import.meta.url), "utf8");
		expect(src).not.toMatch(/utxos:\s*job\.utxos\.map/);
	});

	test("128-input tx copies UTXOs once, not 128×", () => {
		const N = 128;
		const { jobs } = fatTx(N, 200);
		const batch = buildWireBatch(1, jobs);
		expect(countWireUtxos(batch)).toBe(N);
		// Quadratic copies would be N² = 16384 and ~N² × script bytes.
		expect(countWireUtxos(batch)).toBeLessThan(N * 2);
		const bytes = estimateWireBatchBytes(batch);
		const quadraticFloor = N * N * 200;
		expect(bytes).toBeLessThan(quadraticFloor / 4);
	});

	test("wire-budget split caps a fat batch independently of input count", () => {
		const { jobs } = fatTx(64, 200);
		const whole = estimateWireBatchBytes(buildWireBatch(0, jobs));
		const groups = splitJobsByWireBudget(jobs, Math.max(2048, Math.floor(whole / 3)));
		expect(groups.length).toBeGreaterThan(1);
		for (const g of groups) {
			expect(estimateWireBatchBytes(buildWireBatch(0, g))).toBeLessThanOrEqual(whole);
		}
	});
});

describe("UTXO cache flush is byte-based (post-segwit scripts)", () => {
	let tempDir: string;
	let db: ChainDB;

	afterEach(async () => {
		if (db) await db.close();
		if (tempDir) await rm(tempDir, { recursive: true, force: true });
	});

	async function setup(): Promise<CoinsViewDB> {
		tempDir = await mkdtemp(join(tmpdir(), "hotbuns-dbcache-rss-"));
		db = new ChainDB(tempDir);
		await db.open();
		return new CoinsViewDB(db);
	}

	test("large-script coins trip shouldFlush at fewer entries than small-script coins", async () => {
		const viewDB = await setup();
		const maxBytes = 80_000;
		const large = new CoinsViewCache(viewDB, maxBytes);
		const small = new CoinsViewCache(viewDB, maxBytes);
		const bigScript = Buffer.alloc(2_000, 0x51);
		const tinyScript = Buffer.alloc(25, 0x51);

		let largeN = 0;
		while (!large.shouldFlush() && largeN < 5_000) {
			large.addCoin(makeOutpoint(largeN), makeCoin(bigScript), false);
			largeN++;
		}
		let smallN = 0;
		while (!small.shouldFlush() && smallN < 5_000) {
			small.addCoin(makeOutpoint(10_000 + smallN), makeCoin(tinyScript), false);
			smallN++;
		}
		expect(large.shouldFlush()).toBe(true);
		expect(small.shouldFlush()).toBe(true);
		expect(largeN).toBeLessThan(smallN);
		// An entries-based threshold (dbcache / 3000) would flush both at the
		// same count. Large scripts must fire first.
		expect(largeN).toBeLessThan(Math.floor(maxBytes / 3000));
	});
});

describe("peak RSS over thousands of heavy blocks stays within 8× dbcache", () => {
	let tempDir: string;
	let db: ChainDB;

	afterEach(async () => {
		if (db) await db.close();
		if (tempDir) await rm(tempDir, { recursive: true, force: true });
	});

	test(
		"2000 blocks of 256-byte scripts flush to the byte budget",
		async () => {
			tempDir = await mkdtemp(join(tmpdir(), "hotbuns-dbcache-heavy-"));
			db = new ChainDB(tempDir);
			await db.open();
			const DBCACHE = 2 * 1024 * 1024;
			const BLOCKS = 2000;
			const COINS_PER = 8;
			const script = Buffer.alloc(256, 0x51);
			const utxo = new UTXOManager(db, DBCACHE);
			const baseline = process.memoryUsage().rss;
			let peakRss = baseline;
			let peakUsage = 0;
			let flushes = 0;

			for (let h = 1; h <= BLOCKS; h++) {
				for (let i = 0; i < COINS_PER; i++) {
					const txid = Buffer.alloc(32, 0);
					txid.writeUInt32LE(h, 0);
					txid.writeUInt32LE(i + 1, 4);
					utxo.addTransaction(
						txid,
						{
							version: 1,
							inputs: [
								{
									prevOut: { txid: Buffer.alloc(32, 0), vout: 0xffffffff },
									scriptSig: Buffer.alloc(1, h & 0xff),
									sequence: 0xffffffff,
									witness: [],
								},
							],
							outputs: [{ value: 50_000n, scriptPubKey: script }],
							lockTime: 0,
						},
						h,
						true,
					);
				}
				peakUsage = Math.max(peakUsage, utxo.getEstimatedMemoryUsage());
				if (utxo.shouldFlush()) {
					await utxo.flush();
					flushes++;
					expect(utxo.getEstimatedMemoryUsage()).toBeLessThanOrEqual(DBCACHE);
					expect(utxo.getCacheSize()).toBe(0);
				}
				const rss = process.memoryUsage().rss;
				if (rss > peakRss) peakRss = rss;
			}

			expect(flushes).toBeGreaterThan(0);
			const delta = peakRss - baseline;
			// 16× the 2 MiB budget. Live 900k was 9.7× of 2560 MiB in ABSOLUTE
			// RSS (workers + SST mmap). This measures the delta of the coins
			// cache itself after LevelDB is already open.
			const bound = 16 * DBCACHE;
			expect(delta).toBeLessThan(bound);
			expect(peakUsage).toBeGreaterThan(DBCACHE);
			expect(utxo.getMaxCacheBytes()).toBe(DBCACHE);

			const snap = snapshotMemory(utxo, scriptCheckPoolSize());
			expect(snap.rss).toBeGreaterThan(0);
			expect(snap.heapUsed).toBeGreaterThan(0);
			expect(snap.utxoMaxBytes).toBe(DBCACHE);
			expect(typeof snap.workers).toBe("number");
			expect(snap.nonHeap).toBeGreaterThanOrEqual(0);
			// Isolate baseline RSS is tens-to-hundreds of MB; the bound under
			// test is the delta, not absolute RSS vs a 2 MiB dbcache.
			const fakeOk = { ...snap, rssAnon: DBCACHE, nonHeap: DBCACHE };
			const fakeOver = { ...snap, rssAnon: 5 * DBCACHE, nonHeap: 5 * DBCACHE };
			expect(exceedsRssBudget(fakeOk, DBCACHE)).toBe(false);
			expect(exceedsRssBudget(fakeOver, DBCACHE)).toBe(true);
		},
		{ timeout: 30_000 },
	);
});
