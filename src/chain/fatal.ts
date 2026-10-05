/**
 * Process-wide fatal latch — hotbuns' Bitcoin Core AbortNode / FatalError —
 * and the system-fault classifier the validation layer uses to keep a
 * resource failure from ever becoming a consensus verdict.
 *
 * Gate 6 (docs/RELEASE-CHECKLIST.md): OOM, I/O errors, a dead worker, a
 * timeout lead to retry or halt, never to a reject or an accept. Core's
 * answer to a fault it cannot retry past is FatalError -> AbortNode
 * (validation.cpp:2136, node/abort.cpp): stop connecting, mark nothing,
 * punish nobody, skip the shutdown flush, exit non-zero.
 *
 * Once {@link abortNode} has run:
 *   - block sync connects nothing more (processOrderedBlocks returns early);
 *   - submitblock answers RPC_VERIFY_ERROR (-25), never a BIP-22 token;
 *   - the mempool accepts nothing;
 *   - the shutdown path skips the UTXO-cache flush (the in-memory view may be
 *     exactly the state that could not be made durable) and exits 1, so
 *     systemd's Restart=on-failure brings the node back to its last durable
 *     state.
 *
 * The latch is one-way for the life of the process. `abortAction` turns it
 * into a shutdown: production (cli.ts) installs "stop the node and exit 1";
 * tests leave it unset so the latch can be asserted without killing the
 * test runner.
 */

/** Prefix of every error produced by (or while) the latch is set. Never a verdict. */
export const FATAL_ERROR_TOKEN = "fatal-error";

let fatal = false;
let fatalReason = "";
let abortAction: ((reason: string) => void) | null = null;

export function isFatal(): boolean {
  return fatal;
}

export function fatalMessage(): string {
  return fatalReason;
}

/** The error string a chain-changing entry returns while latched. */
export function fatalRefusal(): string {
  return `${FATAL_ERROR_TOKEN}: node is shutting down after a fatal error (${fatalReason})`;
}

export function setAbortAction(action: ((reason: string) => void) | null): void {
  abortAction = action;
}

/** Latch the fatal state (first caller wins) and request shutdown. */
export function abortNode(reason: string): void {
  if (fatal) return;
  fatal = true;
  fatalReason = reason;
  console.error(
    `\n*** FATAL (AbortNode): ${reason} ***\n` +
      `A system fault left the chainstate unable to advance safely: refusing to ` +
      `connect blocks, NOT marking any block invalid, NOT punishing any peer; ` +
      `exiting without flushing the UTXO cache.\n`,
  );
  const action = abortAction;
  if (action !== null) {
    try {
      action(reason);
    } catch (e) {
      console.error(
        `[fatal] abort action failed: ${e instanceof Error ? e.message : String(e)}`,
      );
    }
  }
}

/** Tests only: clear the latch between cases. */
export function resetFatalForTest(): void {
  fatal = false;
  fatalReason = "";
}

/**
 * An explicit system fault raised by hotbuns itself: an invariant a caller
 * broke, a worker that produced no result, a native buffer that could not be
 * pinned. Never a statement about a block or a transaction.
 */
export class SystemFaultError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SystemFaultError";
  }
}

/** errno / abstract-level codes that identify an environment fault. */
const SYSTEM_ERROR_CODES = new Set([
  "ENOSPC", "EIO", "EMFILE", "ENFILE", "ENOMEM", "EACCES", "EPERM", "EROFS",
  "EBADF", "EAGAIN", "EBUSY", "EDQUOT", "EFBIG", "ENODEV", "ENXIO", "ESTALE",
  "ETIMEDOUT", "EPIPE", "ECANCELED",
]);

/**
 * True when `e` is a fault of this node (its memory, its disk, its runtime),
 * as opposed to a consensus failure of the script / block being checked.
 *
 * The script interpreter reports consensus failures as `ScriptError` or a
 * plain `Error` (script-number / script-parse failures); everything that
 * the JS runtime raises on its own — RangeError (incl. "Out of memory" and
 * "Maximum call stack size exceeded"), TypeError, ReferenceError — and every
 * I/O error (errno / LEVEL_* codes) is a system fault. Only those are
 * re-thrown by the validation layer; anything else keeps today's
 * consensus-failure meaning.
 */
export function isSystemFault(e: unknown): boolean {
  if (e instanceof SystemFaultError) return true;
  if (
    e instanceof RangeError ||
    e instanceof TypeError ||
    e instanceof ReferenceError ||
    e instanceof SyntaxError ||
    e instanceof EvalError
  ) {
    return true;
  }
  const code = (e as { code?: unknown } | null)?.code;
  if (typeof code === "string") {
    if (SYSTEM_ERROR_CODES.has(code)) return true;
    if (code.startsWith("LEVEL_")) return true;
  }
  return false;
}

/**
 * Narrower than {@link isSystemFault}: the runtime itself ran out of a
 * resource (heap, stack) or hotbuns raised a SystemFaultError. Used where a
 * third-party library (e.g. @noble/curves) reports bad INPUT with its own
 * error types, so only exhaustion can be told apart from a verdict.
 */
export function isResourceExhaustion(e: unknown): boolean {
  if (e instanceof SystemFaultError) return true;
  if (e instanceof RangeError) {
    return /out of memory|call stack|allocation|memory/i.test(e.message);
  }
  return false;
}
