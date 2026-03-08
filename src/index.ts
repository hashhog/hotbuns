/**
 * hotbuns - Bitcoin full node in TypeScript (Bun)
 */

import { main } from "./cli/cli.js";

main().catch((err) => {
  console.error("Fatal error:", err);
  process.exit(1);
});
