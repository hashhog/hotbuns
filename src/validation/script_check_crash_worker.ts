/**
 * Test worker that goes ready, then answers every batch with kind:"crash".
 * Loaded only from script_check_queue tests via setScriptCheckWorkerUrlForTests.
 */
import { decodePackedBatch, type WorkerOut } from "./script_check_wire.js";

self.onmessage = (ev: MessageEvent<unknown>) => {
	if (!(ev.data instanceof ArrayBuffer)) return;
	const { id } = decodePackedBatch(ev.data);
	postMessage({ kind: "crash", id, error: "test worker crash" } satisfies WorkerOut);
};

postMessage({ kind: "ready" } satisfies WorkerOut);
