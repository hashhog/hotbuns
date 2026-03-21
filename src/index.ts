/**
 * hotbuns - Bitcoin full node in TypeScript (Bun)
 */

import { main } from "./cli/cli.js";

process.on("unhandledRejection", (reason, promise) => {
  console.error("Unhandled rejection at:", promise, "reason:", reason);
});

process.on("uncaughtException", (err) => {
  console.error("Uncaught exception:", err);
  process.exit(1);
});

main().catch((err) => {
  console.error("Fatal error:", err);
  process.exit(1);
});
