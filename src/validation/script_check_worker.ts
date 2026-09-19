/**
 * Bun Worker entrypoint for CCheckQueue-style script verification.
 *
 * Each worker has its own JS isolate and therefore its own libsecp256k1
 * FFI handle (dlopen is not portable across workers). Receives a batch of
 * per-input jobs, runs verifyInputSignature, posts results.
 *
 * Do not import this file from the main thread — load it only via `new Worker`.
 *
 * Reference: bitcoin-core/src/checkqueue.h
 */

import {
	decodePackedBatch,
	fromWireTx,
	fromWireUtxo,
	type WireBatch,
	type WireResultItem,
	type WorkerIn,
	type WorkerOut,
} from "./script_check_wire.js";
import {
	type SigHashCache,
	type TaprootSigHashCache,
	verifyInputSignature,
} from "./tx.js";
import "../crypto/secp256k1_ffi.js";

function runBatch(msg: WireBatch): void {
	try {
		const txs = msg.txs.map(fromWireTx);
		const txUtxos = (msg.txUtxos ?? []).map((arr) => arr.map(fromWireUtxo));
		const caches = new Map<
			number,
			{ sig: SigHashCache; tap: TaprootSigHashCache }
		>();
		const results: WireResultItem[] = new Array(msg.jobs.length);
		for (let i = 0; i < msg.jobs.length; i++) {
			const job = msg.jobs[i]!;
			let cache = caches.get(job.txi);
			if (!cache) {
				cache = { sig: {}, tap: {} };
				caches.set(job.txi, cache);
			}
			const tx = txs[job.txi]!;
			const utxos = txUtxos[job.txi] ?? [];
			const utxo = utxos[job.inputIndex]!;
			const result = verifyInputSignature(
				tx,
				job.inputIndex,
				utxo,
				cache.sig,
				utxos,
				cache.tap,
				job.flags,
			);
			results[i] = {
				jobIndex: i,
				valid: result.valid,
				inputIndex: result.inputIndex,
				error: result.error,
			};
		}
		postMessage({ kind: "result", id: msg.id, results } satisfies WorkerOut);
	} catch (e) {
		postMessage({
			kind: "crash",
			id: msg.id,
			error: e instanceof Error ? e.message : String(e),
		} satisfies WorkerOut);
	}
}

self.onmessage = (ev: MessageEvent<WorkerIn | ArrayBuffer>) => {
	const data = ev.data;
	if (data instanceof ArrayBuffer) {
		runBatch(decodePackedBatch(data));
		return;
	}
	if (!data || data.kind === "stop") {
		return;
	}
	if (data.kind !== "batch") {
		return;
	}
	runBatch(data);
};

postMessage({ kind: "ready" } satisfies WorkerOut);
