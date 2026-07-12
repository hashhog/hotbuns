/**
 * hotbuns - Bitcoin full node in TypeScript (Bun)
 */

import { main } from "./cli/cli.js";

// Defense-in-depth against event-loop starvation from rejection floods.
// The previous handler logged the raw `reason` (an Error) and `promise`, which
// makes Bun render a full stack trace with source-map code frames — synchronous
// source-file reads. Under a burst of unhandled rejections (e.g. mempool script
// validation throwing per-tx) this blocked the single-threaded event loop and
// starved the RPC server (Bun.serve), surfacing as RPC timeouts. We now log a
// compact, rate-limited one-liner (message only, never the Error object) so a
// flood can never monopolise the loop or balloon the log.
let unhandledRejCount = 0;
let unhandledRejLastLog = 0;
process.on("unhandledRejection", (reason) => {
  unhandledRejCount++;
  const now = Date.now();
  if (now - unhandledRejLastLog < 30000) return;
  const msg =
    reason instanceof Error ? reason.message : String(reason);
  console.error(
    `Unhandled rejection: ${msg} (${unhandledRejCount} since last log)`
  );
  unhandledRejLastLog = now;
  unhandledRejCount = 0;
});

process.on("uncaughtException", (err) => {
  console.error("Uncaught exception:", err);
  process.exit(1);
});

main().catch((err) => {
  console.error("Fatal error:", err);
  process.exit(1);
});
