/**
 * hotbuns - Bitcoin full node in TypeScript (Bun)
 */

import * as os from "os";
import * as path from "path";

function parseArgs(argv: string[]): { datadir: string } {
  const defaultDatadir = path.join(os.homedir(), ".hotbuns");
  let datadir = defaultDatadir;

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--datadir" && argv[i + 1]) {
      datadir = argv[i + 1];
      break;
    } else if (arg.startsWith("--datadir=")) {
      datadir = arg.slice("--datadir=".length);
      break;
    }
  }

  return { datadir };
}

async function main(): Promise<void> {
  console.log("hotbuns v0.1.0 starting...");

  const args = parseArgs(Bun.argv);
  console.log(`Data directory: ${args.datadir}`);
}

main().catch((err) => {
  console.error("Fatal error:", err);
  process.exit(1);
});
