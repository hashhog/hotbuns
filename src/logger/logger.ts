/**
 * Logger with Bitcoin-Core-style debug categories and SIGHUP log reopen.
 *
 * Mirrors the surface that `bitcoin-core/src/logging.cpp` exposes:
 *   - LogDebug(category, ...) gated on a per-category bit set, controlled by
 *     `-debug=<category>` (repeatable). `-debug=1` / `-debug=all` enables
 *     every category. `-debug=0` / `-debug=none` disables all of them.
 *   - LogPrintf-style unconditional logging (info/warn/error in our taxonomy).
 *   - SIGHUP support — Core calls `LogInstance().StartLogging()` after
 *     `m_reopen_file` is set in init.cpp. Here we just reopen the underlying
 *     write stream when `reopenLog()` is invoked from the SIGHUP handler.
 *
 * Output goes to stdout/stderr when no `logFilePath` is configured (matches
 * Bitcoin Core's `-printtoconsole`). When a path is set we tee or redirect
 * (depending on `printToConsole`) into an append-mode file handle.
 */

import * as fs from "fs";

/**
 * Known debug categories. Mirrors Bitcoin Core's LogFlags enum trimmed to
 * the subsystems hotbuns currently has. "all" / "none" are aliases.
 */
export const DEBUG_CATEGORIES = [
  "net",
  "p2p",
  "mempool",
  "rpc",
  "validation",
  "bench",
  "blockstore",
  "leveldb",
  "txreconciliation",
  "rand",
  "tor",
  "addrman",
  "selectcoins",
  "reindex",
  "cmpctblock",
  "http",
  "libevent",
  "zmq",
  "estimatefee",
  "i2p",
  "scan",
  "ipc",
  "qt",
  "walletdb",
  "wallet",
  "coindb",
  "lock",
  "util",
  "blockchain",
  "sync",
  "headers",
  "blocks",
] as const;

export type DebugCategory = (typeof DEBUG_CATEGORIES)[number];

/** Special "enable everything" sentinels recognized by Bitcoin Core. */
const ALL_TOKENS = new Set(["1", "all"]);
/** Special "disable everything" sentinels. */
const NONE_TOKENS = new Set(["0", "none"]);

export interface LoggerOptions {
  /** Default level for unconditional logs ("debug" | "info" | "warn" | "error"). */
  level?: "debug" | "info" | "warn" | "error";
  /** Enabled debug categories (raw user input from `--debug=<cat>` flags). */
  debugCategories?: string[];
  /** Optional path for a log file. When unset, logs go to stdout/stderr only. */
  logFilePath?: string;
  /**
   * When a `logFilePath` is set, also mirror to console.
   * Mirrors Bitcoin Core's `-printtoconsole` (on by default when no
   * `-debuglogfile` is configured, off otherwise).
   */
  printToConsole?: boolean;
}

const LEVEL_ORDER = { debug: 10, info: 20, warn: 30, error: 40 } as const;

/**
 * Process-wide logger. We expose a singleton plus a class so tests can
 * construct isolated instances. Production code uses {@link getLogger}.
 */
export class Logger {
  private level: keyof typeof LEVEL_ORDER;
  private enabledCategories: Set<string>;
  private allEnabled: boolean;
  private logFilePath: string | null;
  private printToConsole: boolean;
  private fileStream: fs.WriteStream | null = null;

  constructor(opts: LoggerOptions = {}) {
    this.level = opts.level ?? "info";
    this.enabledCategories = new Set();
    this.allEnabled = false;
    this.logFilePath = opts.logFilePath ?? null;
    // Bitcoin Core default: when no log file is requested, logs go to
    // console. When a log file is requested, console is off unless the
    // operator opts back in via `-printtoconsole`.
    this.printToConsole = opts.printToConsole ?? this.logFilePath === null;

    for (const c of opts.debugCategories ?? []) {
      this.enableCategory(c);
    }

    if (this.logFilePath) {
      this.openFileStream();
    }
  }

  /**
   * Enable a debug category. Accepts repeated tokens, comma-separated lists,
   * "all"/"1"/"none"/"0", or a category name.
   */
  enableCategory(raw: string): void {
    const tokens = raw
      .split(",")
      .map((t) => t.trim().toLowerCase())
      .filter((t) => t.length > 0);
    for (const token of tokens) {
      if (ALL_TOKENS.has(token)) {
        this.allEnabled = true;
        continue;
      }
      if (NONE_TOKENS.has(token)) {
        this.allEnabled = false;
        this.enabledCategories.clear();
        continue;
      }
      this.enabledCategories.add(token);
    }
  }

  /** Test/operator helper: returns true if a category is currently enabled. */
  isCategoryEnabled(category: string): boolean {
    return this.allEnabled || this.enabledCategories.has(category.toLowerCase());
  }

  setLevel(level: keyof typeof LEVEL_ORDER): void {
    this.level = level;
  }

  /**
   * Reopen the underlying log file. Called from the SIGHUP handler so that
   * external log-rotation tools (logrotate, copytruncate-free rotators) can
   * move the file out of the way and have us reopen at the new inode.
   *
   * Mirrors Bitcoin Core's `BCLog::Logger::StartLogging` re-open path
   * triggered by the SIGHUP handler in `init.cpp` setting `m_reopen_file`.
   */
  reopenLog(): void {
    if (!this.logFilePath) return;
    try {
      this.fileStream?.end();
    } catch {
      // best effort
    }
    this.fileStream = null;
    this.openFileStream();
  }

  private openFileStream(): void {
    if (!this.logFilePath) return;
    this.fileStream = fs.createWriteStream(this.logFilePath, {
      flags: "a",
    });
  }

  /** Format a log line with ISO-8601 timestamp prefix (Core-style). */
  private format(prefix: string, args: unknown[]): string {
    const ts = new Date().toISOString();
    const parts = args.map((a) =>
      typeof a === "string" ? a : safeStringify(a)
    );
    return `${ts} ${prefix} ${parts.join(" ")}`;
  }

  private write(line: string, isError: boolean): void {
    if (this.printToConsole) {
      if (isError) {
        process.stderr.write(line + "\n");
      } else {
        process.stdout.write(line + "\n");
      }
    }
    if (this.fileStream) {
      this.fileStream.write(line + "\n");
    }
  }

  /** LogDebug equivalent: emitted only when the category is enabled. */
  debug(category: string, ...args: unknown[]): void {
    if (!this.isCategoryEnabled(category)) return;
    this.write(this.format(`[${category}]`, args), false);
  }

  info(...args: unknown[]): void {
    if (LEVEL_ORDER[this.level] > LEVEL_ORDER.info) return;
    this.write(this.format("[info]", args), false);
  }

  warn(...args: unknown[]): void {
    if (LEVEL_ORDER[this.level] > LEVEL_ORDER.warn) return;
    this.write(this.format("[warn]", args), true);
  }

  error(...args: unknown[]): void {
    if (LEVEL_ORDER[this.level] > LEVEL_ORDER.error) return;
    this.write(this.format("[error]", args), true);
  }
}

function safeStringify(value: unknown): string {
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}

let globalLogger: Logger = new Logger();

/** Replace the singleton logger (called from CLI startup). */
export function setLogger(logger: Logger): void {
  globalLogger = logger;
}

/** Access the singleton logger. */
export function getLogger(): Logger {
  return globalLogger;
}
