/**
 * Test worker that goes ready, then answers every batch with kind:"result"
 * and one result too few, every listed job "valid", without running any
 * script. Loaded only from script_check_queue tests via
 * setScriptCheckWorkerUrlForTests.
 */
import { decodePackedBatch, type WorkerOut } from "./script_check_wire.js";

self.onmessage = (ev: MessageEvent<unknown>) => {
	if (!(ev.data instanceof ArrayBuffer)) return;
	const { id, jobs } = decodePackedBatch(ev.data);
	const results = jobs.slice(0, -1).map((job, jobIndex) => ({
		jobIndex,
		valid: true,
		inputIndex: job.inputIndex,
	}));
	postMessage({ kind: "result", id, results } satisfies WorkerOut);
};

postMessage({ kind: "ready" } satisfies WorkerOut);
