/**
 * -fallbackfee startup parsing (Core ParseMoney + CWallet::Create).
 *
 * hotbuns used parseFloat and silently ignored a bad value (kept 0, started).
 * Core refuses startup with "Invalid amount for -fallbackfee=<amount>: '<v>'"
 * from the command line and from the config file, and warns (but starts) above
 * HIGH_TX_FEE_PER_KB.
 */
import { describe, it, expect } from "bun:test";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { parseMoney, parseFallbackFee } from "./fallbackfee.js";
import { parseArgs, loadConfig } from "../cli/cli.js";

const HIGH_WARNING =
  "-fallbackfee is set very high! This is the transaction fee you may pay when fee estimates are not available.";

describe("parseMoney (Core util/moneystr.cpp)", () => {
  const accepted: Array<[string, bigint]> = [
    ["0", 0n],
    ["0.0002", 20_000n],
    ["1", 100_000_000n],
    ["1.", 100_000_000n],
    [".5", 50_000_000n],
    [".", 0n],
    ["0.00000001", 1n],
    ["12345678.12345678", 1_234_567_812_345_678n],
    ["21000000", 2_100_000_000_000_000n], // MAX_MONEY
    [" 0.001 ", 100_000n], // TrimString
    ["\t1\n", 100_000_000n],
    ["0000000001", 100_000_000n], // 10 whole digits
  ];
  for (const [s, v] of accepted) {
    it(`accepts ${JSON.stringify(s)} -> ${v}`, () => {
      expect(parseMoney(s)).toBe(v);
    });
  }

  const rejected: Array<[string, string]> = [
    ["", "empty"],
    ["   ", "empty after trim"],
    ["1\0", "NUL"],
    ["\0", "NUL alone"],
    ["-1", "minus sign"],
    ["+1", "plus sign"],
    ["-0.0001", "negative"],
    ["abc", "junk"],
    ["1abc", "trailing junk"],
    ["1e-3", "exponent"],
    ["0x10", "hex"],
    ["1.2.3", "second dot"],
    ["1..2", "second dot"],
    ["1.123456789", "9th decimal"],
    ["0.000000001", "9th decimal"],
    ["1 0", "inner space"],
    ["12345678901", "11 whole digits"],
    ["21000000.00000001", "above MAX_MONEY"],
    ["99999999", "above MAX_MONEY"],
    ["Infinity", "junk"],
    ["NaN", "junk"],
  ];
  for (const [s, why] of rejected) {
    it(`rejects ${JSON.stringify(s)} (${why})`, () => {
      expect(parseMoney(s)).toBeNull();
    });
  }
});

describe("parseFallbackFee (CWallet::Create)", () => {
  it("unset is 0 = disabled", () => {
    expect(parseFallbackFee(undefined)).toEqual({ satKvB: 0 });
  });

  it("0.0002 BTC/kvB is 20000 sat/kvB, no warning", () => {
    expect(parseFallbackFee("0.0002")).toEqual({ satKvB: 20_000 });
  });

  it("exactly HIGH_TX_FEE_PER_KB (0.01) does not warn", () => {
    expect(parseFallbackFee("0.01")).toEqual({ satKvB: 1_000_000 });
  });

  it("above HIGH_TX_FEE_PER_KB still loads, with Core's warning", () => {
    expect(parseFallbackFee("0.01000001")).toEqual({ satKvB: 1_000_001, warning: HIGH_WARNING });
    expect(parseFallbackFee("1")).toEqual({ satKvB: 100_000_000, warning: HIGH_WARNING });
  });

  for (const bad of ["abc", "", "-1", "1.2.3", "0.000000001", "12345678901", "21000001"]) {
    it(`refuses ${JSON.stringify(bad)} with Core's init error`, () => {
      expect(() => parseFallbackFee(bad)).toThrow(
        `Invalid amount for -fallbackfee=<amount>: '${bad}'`
      );
    });
  }
});

describe("-fallbackfee reaches the parser verbatim", () => {
  it("CLI keeps the raw string (no parseFloat)", () => {
    expect(parseArgs(["bun", "hotbuns", "--fallbackfee=1.2.3"]).config.fallbackfee).toBe("1.2.3");
    expect(parseArgs(["bun", "hotbuns", "--fallbackfee=0.0002"]).config.fallbackfee).toBe("0.0002");
    // Bare flag: Core reads "" -> ParseMoney refuses.
    expect(parseArgs(["bun", "hotbuns", "--fallbackfee"]).config.fallbackfee).toBe("");
    expect(parseArgs(["bun", "hotbuns"]).config.fallbackfee).toBeUndefined();
  });

  it("config file keeps the raw string", async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "hotbuns-fallbackfee-"));
    try {
      fs.writeFileSync(path.join(dir, "hotbuns.conf"), "fallbackfee=abc\n");
      expect((await loadConfig(dir)).fallbackfee).toBe("abc");
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("startup refuses a bad -fallbackfee", () => {
  const entry = path.join(import.meta.dir, "..", "index.ts");

  function boot(dir: string, extra: string[]) {
    return Bun.spawnSync(
      [process.execPath, "run", entry, "--network=regtest", `--datadir=${dir}`, ...extra],
      { stdout: "pipe", stderr: "pipe", timeout: 60_000 }
    );
  }

  it("from the command line", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "hotbuns-fallbackfee-"));
    try {
      const r = boot(dir, ["--fallbackfee=1.123456789"]);
      expect(r.exitCode).toBe(1);
      expect(r.stderr.toString()).toContain(
        "Error: Invalid amount for -fallbackfee=<amount>: '1.123456789'"
      );
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  }, 70_000);

  it("from the config file", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "hotbuns-fallbackfee-"));
    try {
      fs.writeFileSync(path.join(dir, "hotbuns.conf"), "fallbackfee=-0.0001\n");
      const r = boot(dir, []);
      expect(r.exitCode).toBe(1);
      expect(r.stderr.toString()).toContain(
        "Error: Invalid amount for -fallbackfee=<amount>: '-0.0001'"
      );
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  }, 70_000);
});
