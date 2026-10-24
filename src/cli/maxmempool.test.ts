/**
 * -maxmempool (Core kernel/mempool_options.h, MB = 1,000,000 bytes) must be
 * parsed, defaulted to 300 MB and handed to the Mempool, which reports it
 * in getmempoolinfo.
 */

import { describe, test, expect } from "bun:test";
import * as cli from "./cli.js";

const { parseArgs } = cli;
const mempoolMaxBytes = (c: any): number => (cli as any).mempoolMaxBytes(c);

describe("-maxmempool", () => {
  test("defaults to 300 MB", () => {
    const { config } = parseArgs(["bun", "script.ts"]);
    expect(config.maxMempoolMB).toBe(300);
    expect(mempoolMaxBytes(config)).toBe(300_000_000);
  });

  test("parses --maxmempool=5", () => {
    expect(parseArgs(["bun", "script.ts", "--maxmempool=5"]).config.maxMempoolMB).toBe(5);
    expect(mempoolMaxBytes(parseArgs(["bun", "script.ts", "--maxmempool=5"]).config)).toBe(5_000_000);
  });

  test("ignores a non-positive or malformed value", () => {
    for (const v of ["0", "-3", "abc"]) {
      expect(parseArgs(["bun", "script.ts", `--maxmempool=${v}`]).config.maxMempoolMB).toBe(300);
    }
  });
});
