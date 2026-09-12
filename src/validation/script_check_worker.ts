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
	fromWireTx,
	fromWireUtxo,
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

self.onmessage = (ev: MessageEvent<WorkerIn>) => {
	const msg = ev.data;
	if (!msg || msg.kind === "stop") {
		return;
	}
	if (msg.kind !== "batch") {
		return;
	}
	try {
		const txs = msg.txs.map(fromWireTx);
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
			const utxos = job.utxos.map(fromWireUtxo);
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
};

postMessage({ kind: "ready" } satisfies WorkerOut);
