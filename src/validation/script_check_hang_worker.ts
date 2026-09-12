/**
 * Test worker that goes ready then never replies to batches.
 * Loaded only from script_check_queue tests via setScriptCheckWorkerUrlForTests.
 */
import type { WorkerOut } from "./script_check_wire.js";

self.onmessage = () => {
	/* swallow — never post a result */
};

postMessage({ kind: "ready" } satisfies WorkerOut);
