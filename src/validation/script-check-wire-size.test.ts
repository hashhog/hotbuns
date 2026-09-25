/**
 * Packed script-check wire: the size the encoder allocates must be the size
 * it writes.
 *
 * R4 slice 515000 (2026-09-24) logged "[script-check] worker pool failed (Out
 * of bounds access); falling back to sequential" on 23,914 of ~34,000 blocks.
 * packedSize() was an ESTIMATE (40 B/input, witness items without their
 * 4-byte length prefix) + 256 B of slack; a tx with more than ~50 two-item
 * witness inputs overran it, encodePackedBatch threw, and the whole block's
 * script checks re-ran serially on the main thread. The existing parallelism
 * tests only built 1-input transactions, so none of them reached the overrun.
 *
 * Control: HOTBUNS_UNIT_CHILD=1 bun test ./src/validation/script-check-wire-size.test.ts
 */
import { afterEach, describe, expect, it } from "bun:test";
import {
	ecdsaSign,
	hash160,
	privateKeyToPublicKey,
} from "../crypto/primitives.js";
import {
	scriptCheckLastDispatchWorkers,
	shutdownScriptCheckPool,
	verifyScriptChecks,
	type ScriptCheckJob,
} from "./script_check_queue.js";
import {
	buildWireBatch,
	decodePackedBatch,
	encodePackedBatch,
	encodePackedJobs,
	estimateWireBatchBytes,
} from "./script_check_wire.js";
import { globalSigCache } from "./sig_cache.js";
import {
	ScriptFlags,
	SIGHASH_ALL,
	setInputSigCacheEnabled,
	sigHashWitnessV0,
	type Transaction,
	verifyInputSignature,
} from "./tx.js";

const PRIV = Buffer.from(
	"0202020202020202020202020202020202020202020202020202020202020202",
	"hex",
);
const PUB = privateKeyToPublicKey(PRIV, true);
const PKH = hash160(PUB);
const AMOUNT = 100_000n;
const FLAGS =
	ScriptFlags.VERIFY_P2SH |
	ScriptFlags.VERIFY_WITNESS |
	ScriptFlags.VERIFY_DERSIG |
	ScriptFlags.VERIFY_NULLDUMMY |
	ScriptFlags.VERIFY_CHECKLOCKTIMEVERIFY |
	ScriptFlags.VERIFY_CHECKSEQUENCEVERIFY;

const p2wpkh = (pkh: Buffer) =>
	Buffer.concat([Buffer.from([0x00, 0x14]), pkh]);
const p2pkh = (pkh: Buffer) =>
	Buffer.concat([Buffer.from([0x76, 0xa9, 0x14]), pkh, Buffer.from([0x88, 0xac])]);

/** One P2WPKH tx spending `nIn` coins — the shape that overran the old sizer. */
function manyInputTx(nIn: number): { tx: Transaction; jobs: ScriptCheckJob[] } {
	const tx: Transaction = {
		version: 2,
		inputs: Array.from({ length: nIn }, (_, i) => {
			const txid = Buffer.alloc(32, 0);
			txid.writeUInt32LE(i + 7, 0);
			return {
				prevOut: { txid, vout: i & 3 },
				scriptSig: Buffer.alloc(0),
				sequence: 0xfffffffd,
				witness: [] as Buffer[],
			};
		}),
		outputs: [{ value: AMOUNT * BigInt(nIn) - 5_000n, scriptPubKey: p2wpkh(PKH) }],
		lockTime: 0,
	};
	for (let i = 0; i < nIn; i++) {
		const sighash = sigHashWitnessV0(tx, i, p2pkh(PKH), AMOUNT, SIGHASH_ALL);
		const sig = Buffer.concat([ecdsaSign(sighash, PRIV), Buffer.from([SIGHASH_ALL])]);
		tx.inputs[i]!.witness = [sig, PUB];
	}
	const utxos = Array.from({ length: nIn }, () => ({
		height: 1,
		coinbase: false,
		amount: AMOUNT,
		scriptPubKey: p2wpkh(PKH),
	}));
	const jobs = tx.inputs.map((_, i) => ({
		tx,
		inputIndex: i,
		utxos,
		flags: FLAGS,
		txidHex: "aa",
	}));
	return { tx, jobs };
}

afterEach(async () => {
	await shutdownScriptCheckPool();
});

describe("packed script-check wire sizing", () => {
	it("allocates exactly the bytes it writes, for every tx shape", () => {
		for (const nIn of [1, 2, 49, 64, 128, 300]) {
			const { jobs } = manyInputTx(nIn);
			const batch = buildWireBatch(1, jobs);
			const packed = encodePackedBatch(batch);
			expect(packed.byteLength).toBe(estimateWireBatchBytes(batch));
			const back = decodePackedBatch(packed);
			expect(back.jobs.length).toBe(nIn);
			expect(back.txs[0]!.inputs.length).toBe(nIn);
			expect(Buffer.from(back.txs[0]!.inputs[nIn - 1]!.witness[1]!).equals(PUB)).toBe(true);
		}
	});

	it("encodePackedJobs is byte-identical to encodePackedBatch(buildWireBatch)", () => {
		// Several txs, interleaved and partially covered, one coinbase-flagged
		// prevout, a non-empty scriptSig, an empty witness — every field path.
		const a = manyInputTx(5);
		const b = manyInputTx(3);
		b.tx.inputs[1]!.scriptSig = Buffer.from([0x51, 0x52, 0x53]);
		b.tx.inputs[2]!.witness = [];
		b.jobs[0]!.utxos[0] = { ...b.jobs[0]!.utxos[0]!, coinbase: true, height: 123456 };
		b.tx.version = -2;
		b.tx.lockTime = 0xfffffffe;
		const chunk = [a.jobs[4]!, b.jobs[1]!, a.jobs[0]!, b.jobs[2]!, b.jobs[0]!];
		const want = new Uint8Array(encodePackedBatch(buildWireBatch(42, chunk)));
		const got = new Uint8Array(encodePackedJobs(42, chunk));
		expect(Buffer.from(got).equals(Buffer.from(want))).toBe(true);
		for (const nIn of [1, 64, 300]) {
			const { jobs } = manyInputTx(nIn);
			expect(
				Buffer.from(encodePackedJobs(7, jobs)).equals(
					Buffer.from(encodePackedBatch(buildWireBatch(7, jobs))),
				),
			).toBe(true);
		}
	});

	it("a 200-input segwit tx verifies on the pool without the serial fallback", async () => {
		const { jobs } = manyInputTx(200);
		globalSigCache.clear();
		const warns: string[] = [];
		const orig = console.warn;
		console.warn = (...a: unknown[]) => {
			warns.push(a.map(String).join(" "));
		};
		try {
			const r = await verifyScriptChecks(jobs, 4);
			expect(r.valid).toBe(true);
		} finally {
			console.warn = orig;
		}
		expect(warns.filter((w) => w.includes("worker pool failed"))).toEqual([]);
		expect(scriptCheckLastDispatchWorkers()).toBeGreaterThan(1);
	});

	it("a bad signature deep in a 200-input tx is still reported at its index", async () => {
		const { tx, jobs } = manyInputTx(200);
		const sig = tx.inputs[170]!.witness[0]!;
		sig[10] ^= 0x01;
		globalSigCache.clear();
		const warns: string[] = [];
		const orig = console.warn;
		console.warn = (...a: unknown[]) => {
			warns.push(a.map(String).join(" "));
		};
		let r;
		try {
			r = await verifyScriptChecks(jobs, 4);
		} finally {
			console.warn = orig;
		}
		expect(r.valid).toBe(false);
		expect(r.failedInput).toBe(170);
		expect(warns.filter((w) => w.includes("worker pool failed"))).toEqual([]);
	});
});

describe("worker isolates skip the per-input sig cache", () => {
	it("same verdicts with the cache off, and nothing inserted", () => {
		const { tx, jobs } = manyInputTx(6);
		tx.inputs[4]!.witness[0]![12] ^= 0x01;
		const run = () =>
			jobs.map((j) =>
				verifyInputSignature(j.tx, j.inputIndex, j.utxos[j.inputIndex]!, {}, j.utxos, {}, j.flags).valid,
			);
		globalSigCache.clear();
		setInputSigCacheEnabled(false);
		let off: boolean[];
		try {
			off = run();
			expect(globalSigCache.size).toBe(0);
		} finally {
			setInputSigCacheEnabled(true);
		}
		globalSigCache.clear();
		const on = run();
		expect(globalSigCache.size).toBe(5);
		expect(off).toEqual([true, true, true, true, false, true]);
		expect(on).toEqual(off);
		// With the cache on, a second pass is served from it — same answers.
		expect(run()).toEqual(off);
	});
});
