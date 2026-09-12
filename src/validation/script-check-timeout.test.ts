/**
 * Worker-pool result timeout: a silent worker must not hang ConnectBlock.
 *
 * Control: `bun test src/validation/script-check-timeout.test.ts`
 */
import { afterEach, describe, expect, it } from "bun:test";
import {
	MIN_JOBS_FOR_POOL,
	setScriptCheckResultTimeoutForTests,
	setScriptCheckWorkerUrlForTests,
	shutdownScriptCheckPool,
	verifyScriptChecks,
	type ScriptCheckJob,
} from "./script_check_queue.js";
import { ScriptFlags, type Transaction } from "./tx.js";

afterEach(async () => {
	await shutdownScriptCheckPool();
	setScriptCheckWorkerUrlForTests(null);
	setScriptCheckResultTimeoutForTests(30_000);
});

function dummyJob(): ScriptCheckJob {
	const tx: Transaction = {
		version: 1,
		inputs: [
			{
				prevOut: { txid: Buffer.alloc(32, 1), vout: 0 },
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
	};
}

describe("script-check worker result timeout", () => {
	it(
		"falls back to sequential when a worker never replies",
		async () => {
			setScriptCheckResultTimeoutForTests(250);
			setScriptCheckWorkerUrlForTests(
				new URL("./script_check_hang_worker.ts", import.meta.url),
			);
			await shutdownScriptCheckPool();

			const jobs = Array.from({ length: MIN_JOBS_FOR_POOL }, () => dummyJob());
			const t0 = performance.now();
			const result = await verifyScriptChecks(jobs, 2);
			const elapsed = performance.now() - t0;

			expect(elapsed).toBeLessThan(5_000);
			expect(result).toBeDefined();
			expect(typeof result.valid).toBe("boolean");
		},
		{ timeout: 10_000 },
	);
});
