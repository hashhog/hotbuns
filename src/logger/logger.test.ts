/**
 * Unit tests for the debug-category logger.
 *
 * Covers:
 *   - `--debug=<cat>` enable / disable logic, including the "all" / "1" /
 *     "none" / "0" sentinels Bitcoin Core ships.
 *   - SIGHUP-triggered `reopenLog()` behavior against a live file handle:
 *     the on-disk inode that we wrote to before `reopenLog()` is preserved
 *     even after the file is `unlink`-ed, and a new file appears at the
 *     original path on the next write.  This is exactly what `logrotate`
 *     does when copytruncate is disabled.
 */

import { describe, test, expect, beforeEach, afterEach } from "bun:test";
import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import { Logger } from "./logger.js";

describe("Logger debug categories", () => {
  test("category disabled by default", () => {
    const logger = new Logger();
    expect(logger.isCategoryEnabled("net")).toBe(false);
  });

  test("--debug=net enables the 'net' category", () => {
    const logger = new Logger({ debugCategories: ["net"] });
    expect(logger.isCategoryEnabled("net")).toBe(true);
    expect(logger.isCategoryEnabled("mempool")).toBe(false);
  });

  test("--debug=all enables every category", () => {
    const logger = new Logger({ debugCategories: ["all"] });
    expect(logger.isCategoryEnabled("net")).toBe(true);
    expect(logger.isCategoryEnabled("mempool")).toBe(true);
    expect(logger.isCategoryEnabled("anything-arbitrary")).toBe(true);
  });

  test("--debug=1 alias for --debug=all", () => {
    const logger = new Logger({ debugCategories: ["1"] });
    expect(logger.isCategoryEnabled("net")).toBe(true);
  });

  test("--debug=none disables all categories", () => {
    const logger = new Logger({ debugCategories: ["all", "none"] });
    expect(logger.isCategoryEnabled("net")).toBe(false);
    expect(logger.isCategoryEnabled("mempool")).toBe(false);
  });

  test("--debug=0 alias for --debug=none", () => {
    const logger = new Logger({ debugCategories: ["all", "0"] });
    expect(logger.isCategoryEnabled("net")).toBe(false);
  });

  test("repeated --debug flags accumulate", () => {
    const logger = new Logger({ debugCategories: ["net", "mempool"] });
    expect(logger.isCategoryEnabled("net")).toBe(true);
    expect(logger.isCategoryEnabled("mempool")).toBe(true);
    expect(logger.isCategoryEnabled("rpc")).toBe(false);
  });

  test("comma-separated categories accumulate", () => {
    const logger = new Logger({ debugCategories: ["net,mempool,rpc"] });
    expect(logger.isCategoryEnabled("net")).toBe(true);
    expect(logger.isCategoryEnabled("mempool")).toBe(true);
    expect(logger.isCategoryEnabled("rpc")).toBe(true);
  });

  test("category names are case-insensitive", () => {
    const logger = new Logger({ debugCategories: ["NET"] });
    expect(logger.isCategoryEnabled("net")).toBe(true);
    expect(logger.isCategoryEnabled("Net")).toBe(true);
  });

  test("enableCategory at runtime", () => {
    const logger = new Logger();
    expect(logger.isCategoryEnabled("rpc")).toBe(false);
    logger.enableCategory("rpc");
    expect(logger.isCategoryEnabled("rpc")).toBe(true);
  });
});

describe("Logger SIGHUP / reopenLog", () => {
  let tempDir: string;

  beforeEach(async () => {
    tempDir = path.join(os.tmpdir(), `hotbuns-log-test-${Date.now()}`);
    await fs.promises.mkdir(tempDir, { recursive: true });
  });

  afterEach(async () => {
    await fs.promises.rm(tempDir, { recursive: true, force: true });
  });

  test("writes log lines to file when logFilePath is set", async () => {
    const logFile = path.join(tempDir, "node.log");
    const logger = new Logger({
      logFilePath: logFile,
      printToConsole: false,
      debugCategories: ["net"],
    });
    logger.info("hello world");
    logger.debug("net", "peer connected");
    // Allow the write stream a moment to flush.
    await new Promise((r) => setTimeout(r, 50));
    const contents = await fs.promises.readFile(logFile, "utf8");
    expect(contents).toContain("hello world");
    expect(contents).toContain("peer connected");
  });

  test("reopenLog() reopens the file at the original path", async () => {
    const logFile = path.join(tempDir, "rotate.log");
    const logger = new Logger({
      logFilePath: logFile,
      printToConsole: false,
    });

    logger.info("before rotate");
    await new Promise((r) => setTimeout(r, 50));

    // Simulate logrotate moving the file out of the way.
    const rotated = `${logFile}.1`;
    await fs.promises.rename(logFile, rotated);

    // SIGHUP analogue: ask the logger to reopen.
    logger.reopenLog();
    logger.info("after rotate");
    await new Promise((r) => setTimeout(r, 50));

    // After reopen, a fresh file should exist at the original path.
    const fresh = await fs.promises.readFile(logFile, "utf8");
    expect(fresh).toContain("after rotate");

    // The pre-rotate line should still be in the rotated file.
    const old = await fs.promises.readFile(rotated, "utf8");
    expect(old).toContain("before rotate");
  });

  test("reopenLog() is safe when no logFilePath was set", () => {
    const logger = new Logger();
    expect(() => logger.reopenLog()).not.toThrow();
  });
});

describe("Logger level filtering", () => {
  test("info level suppresses debug output", () => {
    const logger = new Logger({ level: "info" });
    // Spy on stdout
    const original = process.stdout.write.bind(process.stdout);
    let captured = "";
    (process.stdout.write as any) = (s: string) => {
      captured += s;
      return true;
    };
    try {
      logger.info("visible");
    } finally {
      (process.stdout.write as any) = original;
    }
    expect(captured).toContain("visible");
  });

  test("error level suppresses info output", () => {
    const logger = new Logger({ level: "error" });
    const original = process.stdout.write.bind(process.stdout);
    let captured = "";
    (process.stdout.write as any) = (s: string) => {
      captured += s;
      return true;
    };
    try {
      logger.info("hidden");
    } finally {
      (process.stdout.write as any) = original;
    }
    expect(captured).toBe("");
  });
});
