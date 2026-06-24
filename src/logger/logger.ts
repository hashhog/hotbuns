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

/** Lowercased known-category set, for membership checks. */
const KNOWN_CATEGORIES: ReadonlySet<string> = new Set(DEBUG_CATEGORIES);

/**
 * Special "enable everything" sentinels recognized by Bitcoin Core
 * (`logging.cpp` maps `"all"`, `"1"`, and the empty string `""` to the ALL
 * mask). hotbuns accepts `""` as an enable-all token too for Core parity.
 */
const ALL_TOKENS = new Set(["1", "all", ""]);
/**
 * Special "disable everything" sentinels. Core itself only documents
 * `all`/`1`/`""` (DisableCategory with any of those clears every bit, which is
 * how `logging [], ["all"]` turns everything off); hotbuns additionally
 * recognizes `none`/`0` as clear tokens (its `-debug` CLI already does).
 */
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
   * "all"/"1"/""/"none"/"0", or a category name.
   *
   * "all"/"1"/"" expand to EVERY known category (and also flip `allEnabled`,
   * so an arbitrary not-in-table name like a future subsystem still logs while
   * ALL is on — matches Core's whole-bitmask semantics). A bare category name
   * sets just that bit. This mutates the live mask in place; because
   * {@link debug} consults {@link isCategoryEnabled} on every record, a toggle
   * here takes effect immediately with no restart (no snapshot trap).
   */
  enableCategory(raw: string): void {
    // Core's empty-string ALL token: `EnableCategory("")` enables the whole
    // mask. An empty/whitespace `raw` splits to nothing below, so handle it
    // up front rather than letting the empty-filter swallow it.
    if (raw.trim() === "") {
      this.allEnabled = true;
      for (const c of DEBUG_CATEGORIES) this.enabledCategories.add(c);
      return;
    }
    const tokens = raw
      .split(",")
      .map((t) => t.trim().toLowerCase())
      .filter((t) => t.length > 0);
    for (const token of tokens) {
      if (ALL_TOKENS.has(token)) {
        this.allEnabled = true;
        for (const c of DEBUG_CATEGORIES) this.enabledCategories.add(c);
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

  /**
   * Disable a debug category — the inverse of {@link enableCategory}, used by
   * the `logging` RPC's exclude slot. "all"/"1"/""/"none"/"0" clear EVERY
   * category (Core's DisableCategory("all") clears the whole bitmask). A bare
   * category name clears just that bit; clearing one bit while ALL was on
   * also drops `allEnabled` so the per-category map reflects the exclusion
   * (e.g. `logging [["all"],["net"]]` -> every key true except net). Live —
   * takes effect immediately on the running logger.
   */
  disableCategory(raw: string): void {
    // Core's empty-string ALL token in the exclude slot clears the whole mask.
    if (raw.trim() === "") {
      this.allEnabled = false;
      this.enabledCategories.clear();
      return;
    }
    const tokens = raw
      .split(",")
      .map((t) => t.trim().toLowerCase())
      .filter((t) => t.length > 0);
    for (const token of tokens) {
      if (ALL_TOKENS.has(token) || NONE_TOKENS.has(token)) {
        this.allEnabled = false;
        this.enabledCategories.clear();
        continue;
      }
      // Clearing one specific bit while ALL was on: drop the umbrella flag so
      // arbitrary/unknown names stop logging too, then keep every OTHER known
      // category on (the map must show all-true-except-this).
      if (this.allEnabled) {
        this.allEnabled = false;
        for (const c of DEBUG_CATEGORIES) this.enabledCategories.add(c);
      }
      this.enabledCategories.delete(token);
    }
  }

  /** Test/operator helper: returns true if a category is currently enabled. */
  isCategoryEnabled(category: string): boolean {
    return this.allEnabled || this.enabledCategories.has(category.toLowerCase());
  }

  /**
   * Snapshot the live per-category enable state as a plain `{name: bool}`
   * object covering EXACTLY the known {@link DEBUG_CATEGORIES}, with keys in
   * ascending alphabetical order (Core iterates a `std::map`; the RPC's
   * `logging` result is byte-stable that way). Special tokens
   * ("all"/"1"/""/"none"/"0") are never keys. Read from the live set, so it
   * reflects every prior enable/disable.
   */
  getCategoryStatusMap(): Record<string, boolean> {
    const out: Record<string, boolean> = {};
    for (const cat of [...DEBUG_CATEGORIES].sort()) {
      out[cat] = this.isCategoryEnabled(cat);
    }
    return out;
  }

  /** Returns true iff `name` is one of the exposed {@link DEBUG_CATEGORIES}. */
  isKnownCategory(name: string): boolean {
    return KNOWN_CATEGORIES.has(name.toLowerCase());
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
