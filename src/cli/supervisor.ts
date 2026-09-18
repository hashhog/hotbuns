/**
 * Parent-process supervisor for a Bun-hosted node.
 *
 * A SIGSEGV inside Bun is a process death, not a stall. Range 388364→419311
 * died at tip 401723 with:
 *
 *   panic: Segmentation fault at address 0x800000001A
 *   bun.report: JSC::MarkedBlock::aboutToMark
 *               → JSCommonJSModule::visitChildren
 *               → ParallelHelperPool GC thread
 *
 * That is a Bun 1.3.11 JSC GC race (same class as the 340890 crash at
 * 0x401FFFFFFBE), not a poison block. Anything that only polls RPC reports
 * the gap as "behind" / STALLED and wastes the next hour hunting a sync bug.
 *
 * This parent:
 *   1. spawns the node as a child
 *   2. classifies SIGSEGV/SIGILL/SIGABRT/SIGBUS (and Bun's panic banner) as
 *      CRASHED immediately
 *   3. restarts the child so it resumes from the datadir (opt-in bound)
 *
 * Opt-in: `--supervise` or HOTBUNS_SUPERVISE=1. Not a consensus change.
 */

export const FATAL_SIGNALS = new Set([
  "SIGSEGV",
  "SIGILL",
  "SIGABRT",
  "SIGBUS",
  "SIGFPE",
]);

/** 128+signal for the fatal set: ILL=4, ABRT=6, BUS=7, FPE=8, SEGV=11 */
const FATAL_EXIT_CODES = new Set([132, 134, 135, 136, 139]);

const BUN_PANIC_RE =
  /Segmentation fault|Bun has crashed|panic:\s*Segmentation/i;

export function isHardCrash(opts: {
  signalCode: string | null;
  exitCode: number | null;
  logSnippet?: string;
}): boolean {
  if (opts.signalCode && FATAL_SIGNALS.has(opts.signalCode)) return true;
  if (opts.exitCode != null && FATAL_EXIT_CODES.has(opts.exitCode)) return true;
  if (opts.logSnippet && BUN_PANIC_RE.test(opts.logSnippet)) return true;
  return false;
}

export function formatCrashLine(opts: {
  pid: number;
  signalCode: string | null;
  exitCode: number | null;
  logSnippet?: string;
  restart?: { attempt: number; max: number };
}): string {
  const sig =
    opts.signalCode ??
    (opts.exitCode != null ? `exit ${opts.exitCode}` : "unknown");
  const snippet = (opts.logSnippet ?? "")
    .replace(/\u001b\[[0-9;]*m/g, "")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, 160);
  let line = `CRASHED — child pid=${opts.pid} died signal=${sig}`;
  if (snippet) line += ` — ${snippet}`;
  if (opts.restart) {
    line += ` — restarting ${opts.restart.attempt}/${opts.restart.max} to resume from datadir`;
  } else {
    line += " — process is dead";
  }
  return line;
}

export function childArgvFromSupervised(argv: string[]): string[] {
  const bunExe = argv[0] || process.execPath;
  const scriptPath = argv[1] || "src/index.ts";
  const rest = argv.slice(2).filter((arg) => {
    if (arg === "--supervise" || arg.startsWith("--supervise=")) return false;
    if (arg === "--internal-supervised-child") return false;
    if (arg.startsWith("--supervise-restarts")) return false;
    return true;
  });
  rest.push("--internal-supervised-child");
  return [bunExe, "run", scriptPath, ...rest];
}

export interface SuperviseSink {
  write: (chunk: Uint8Array | string) => unknown;
}

export interface SuperviseOpts {
  cmd: string[];
  maxRestarts?: number;
  restartBackoffMs?: number;
  log?: (line: string) => void;
  env?: Record<string, string | undefined>;
  cwd?: string;
  forwardStdout?: SuperviseSink;
  forwardStderr?: SuperviseSink;
  onSpawn?: (pid: number) => void;
}

async function teeCapture(
  stream: ReadableStream<Uint8Array> | number | undefined | null,
  dest?: SuperviseSink,
): Promise<string> {
  if (!stream || typeof stream === "number") return "";
  const reader = stream.getReader();
  const dec = new TextDecoder();
  let text = "";
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    if (value) {
      dest?.write(value);
      text += dec.decode(value, { stream: true });
      if (text.length > 64_000) text = text.slice(-32_000);
    }
  }
  return text;
}

/**
 * Watch `cmd` until it exits. Hard crashes are logged as CRASHED (never
 * "behind") and optionally restarted.
 */
export async function superviseChild(opts: SuperviseOpts): Promise<number> {
  const maxRestarts = opts.maxRestarts ?? 0;
  const backoff = opts.restartBackoffMs ?? 1000;
  const log = opts.log ?? ((line: string) => console.error(line));
  let attempt = 0;

  const env: Record<string, string> = {};
  const src = opts.env ?? process.env;
  for (const [k, v] of Object.entries(src)) {
    if (typeof v === "string") env[k] = v;
  }
  // Child must not wrap itself if the operator exported HOTBUNS_SUPERVISE=1.
  env.HOTBUNS_SUPERVISE = "0";

  for (;;) {
    const child = Bun.spawn(opts.cmd, {
      stdin: "ignore",
      stdout: "pipe",
      stderr: "pipe",
      cwd: opts.cwd,
      env,
    });
    const pid = child.pid;
    opts.onSpawn?.(pid);
    const [stdoutText, stderrText, code] = await Promise.all([
      teeCapture(child.stdout, opts.forwardStdout),
      teeCapture(child.stderr, opts.forwardStderr),
      child.exited,
    ]);
    const signalCode = child.signalCode;
    const exitCode = child.exitCode;
    const snippet = `${stderrText}\n${stdoutText}`;

    if (signalCode === "SIGTERM" || signalCode === "SIGINT") {
      return code;
    }

    if (
      isHardCrash({
        signalCode,
        exitCode,
        logSnippet: snippet,
      })
    ) {
      const canRestart = attempt < maxRestarts;
      log(
        formatCrashLine({
          pid,
          signalCode,
          exitCode: exitCode ?? code,
          logSnippet: snippet,
          restart: canRestart
            ? { attempt: attempt + 1, max: maxRestarts }
            : undefined,
        }),
      );
      if (canRestart) {
        attempt++;
        await Bun.sleep(backoff);
        continue;
      }
      return exitCode ?? code ?? 139;
    }

    if (code === 0) return 0;

    log(
      `EXIT — child pid=${pid} status=${code} signal=${signalCode ?? "none"} — process is dead`,
    );
    return code;
  }
}

export async function runSupervisorFromArgv(
  argv: string[],
  opts?: { maxRestarts?: number },
): Promise<number> {
  return superviseChild({
    cmd: childArgvFromSupervised(argv),
    maxRestarts: opts?.maxRestarts ?? 3,
    restartBackoffMs: 1000,
  });
}
