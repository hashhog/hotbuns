/**
 * cffix-hotbuns-ispushonly-pushdata4-loop
 *
 * Every raw-script walker read the OP_PUSHDATA4 length as a SIGNED int32
 * (`b0 | b1<<8 | b2<<16 | b3<<24`). `4e fb ff ff ff` then gives len = -5, the
 * bounds check (which assumes len >= 0) passes, and `i += 4 + len` moves the
 * cursor back to 0: the loop never ends. isPushOnly is reached from the
 * mempool IsStandardTx scriptSig gate for any relayed tx >= 65 bytes, before
 * any UTXO lookup, on the main thread — one unauthenticated tx hung the node.
 *
 * Core (script/script.cpp GetScriptOp) reads nSize with ReadLE32 into an
 * unsigned int and fails when `(unsigned)(end - pc) < nSize`, so the same bytes
 * are a truncated push: IsPushOnly returns false and the scan stops.
 *
 * A synchronous infinite loop cannot be interrupted by bun's per-test timeout
 * from inside the same thread, so each case runs in a child `bun` process with
 * a hard kill timeout. On the base commit the child is killed and the test
 * fails by name; with the fix the child returns the Core answer.
 */
import { describe, test, expect } from "bun:test";
import { join } from "node:path";

const SRC = join(import.meta.dir, "..");
const CHILD_TIMEOUT_MS = 10_000;
// bun's per-test timeout must outlast the child's kill timeout so a hang is
// reported by the assertion, and so a loaded box does not flake the controls.
const TEST_TIMEOUT_MS = 30_000;

/** Run `body` (an async function body that returns a JSON-able value) in a child bun. */
function runIsolated(body: string): { timedOut: boolean; value: unknown; stderr: string } {
  const code = `
    const SRC = ${JSON.stringify(SRC)};
    const main = async () => { ${body} };
    main().then(
      (v) => { process.stdout.write("RESULT:" + JSON.stringify(v) + "\\n"); process.exit(0); },
      (e) => { process.stderr.write(String(e && e.stack || e)); process.exit(2); },
    );
  `;
  const start = Date.now();
  const proc = Bun.spawnSync({
    cmd: [process.execPath, "-e", code],
    stdout: "pipe",
    stderr: "pipe",
    timeout: CHILD_TIMEOUT_MS,
    env: { ...process.env, HOTBUNS_UNIT_CHILD: "1" },
  });
  const elapsed = Date.now() - start;
  const out = proc.stdout.toString();
  const stderr = proc.stderr.toString();
  const line = out.split("\n").find((l) => l.startsWith("RESULT:"));
  const timedOut = line === undefined && (proc.signalCode != null || elapsed >= CHILD_TIMEOUT_MS);
  return { timedOut, value: line ? JSON.parse(line.slice(7)) : undefined, stderr };
}

// 4e = OP_PUSHDATA4, fb ff ff ff = 0xfffffffb (unsigned) / -5 (signed).
const NEG5 = "4efbffffff";
// ff ff ff ff = 0xffffffff (unsigned) / -1 (signed): moves the cursor back by one.
const NEG1 = "4effffffff";

describe("cffix: OP_PUSHDATA4 length is unsigned in every script walker", () => {
  test("isPushOnly(4e fb ff ff ff) returns false instead of looping forever", () => {
    const r = runIsolated(`
      const { isPushOnly } = await import(SRC + "/script/interpreter.ts");
      return isPushOnly(Buffer.from(${JSON.stringify(NEG5)}, "hex"));
    `);
    expect(r.timedOut).toBe(false);
    expect(r.value).toBe(false);
  }, TEST_TIMEOUT_MS);

  test("isPushOnly(4e ff ff ff ff) returns false (truncated push, Core GetOp fails)", () => {
    const r = runIsolated(`
      const { isPushOnly } = await import(SRC + "/script/interpreter.ts");
      return isPushOnly(Buffer.from(${JSON.stringify(NEG1)}, "hex"));
    `);
    expect(r.timedOut).toBe(false);
    expect(r.value).toBe(false);
  }, TEST_TIMEOUT_MS);

  test("isPushOnly still accepts a well-formed PUSHDATA4 push (control)", () => {
    const r = runIsolated(`
      const { isPushOnly } = await import(SRC + "/script/interpreter.ts");
      return isPushOnly(Buffer.from("4e02000000aabb51", "hex"));
    `);
    expect(r.timedOut).toBe(false);
    expect(r.value).toBe(true);
  }, TEST_TIMEOUT_MS);

  test("mempool rejects a 65+ byte tx with scriptSig 4e fb ff ff ff as scriptsig-not-pushonly", () => {
    const r = runIsolated(`
      const { mkdtemp, rm } = await import("node:fs/promises");
      const { tmpdir } = await import("node:os");
      const { join } = await import("node:path");
      const { ChainDB } = await import(SRC + "/storage/database.ts");
      const { UTXOManager } = await import(SRC + "/chain/utxo.ts");
      const { REGTEST } = await import(SRC + "/consensus/params.ts");
      const { Mempool } = await import(SRC + "/mempool/mempool.ts");
      const { serializeTx } = await import(SRC + "/validation/tx.ts");
      const dir = await mkdtemp(join(tmpdir(), "cffix-pushdata4-"));
      const db = new ChainDB(dir);
      await db.open();
      try {
        const mempool = new Mempool(new UTXOManager(db), REGTEST, 1_000_000);
        mempool.setTipHeight(200);
        const P2A = Buffer.from([0x51, 0x02, 0x4e, 0x73]);
        const tx = {
          version: 2,
          inputs: [{
            prevOut: { txid: Buffer.alloc(32, 0xab), vout: 0 },
            scriptSig: Buffer.from(${JSON.stringify(NEG5)}, "hex"),
            sequence: 0xffffffff,
            witness: [],
          }],
          outputs: [
            { value: 9_000_000n, scriptPubKey: P2A },
            { value: 0n, scriptPubKey: Buffer.from([0x6a]) },
          ],
          lockTime: 0,
        };
        const size = serializeTx(tx, false).length;
        const res = await mempool.addTransaction(tx);
        return { size, accepted: res.accepted, error: res.error ?? "" };
      } finally {
        await db.close();
        await rm(dir, { recursive: true, force: true });
      }
    `);
    expect(r.timedOut).toBe(false);
    const v = r.value as { size: number; accepted: boolean; error: string };
    expect(v.size).toBeGreaterThanOrEqual(65);
    expect(v.accepted).toBe(false);
    expect(v.error).toContain("scriptsig-not-pushonly");
  }, TEST_TIMEOUT_MS);

  test("removeCodeSeparators(4e fb ff ff ff) terminates and keeps the bytes", () => {
    const r = runIsolated(`
      const { removeCodeSeparators } = await import(SRC + "/validation/tx.ts");
      return removeCodeSeparators(Buffer.from(${JSON.stringify(NEG5)} + "ab", "hex")).toString("hex");
    `);
    expect(r.timedOut).toBe(false);
    // The truncated PUSHDATA4 swallows the rest of the script (Core's GetOp
    // fails there), so the trailing 0xab is inside it and is kept.
    expect(r.value).toBe(NEG5 + "ab");
  }, TEST_TIMEOUT_MS);

  test("removeCodeSeparators still strips a separator after a short push (control)", () => {
    const r = runIsolated(`
      const { removeCodeSeparators } = await import(SRC + "/validation/tx.ts");
      return removeCodeSeparators(Buffer.from("01aaab51", "hex")).toString("hex");
    `);
    expect(r.timedOut).toBe(false);
    expect(r.value).toBe("01aa51");
  }, TEST_TIMEOUT_MS);

  test("tx.ts findAndDelete(4e fb ff ff ff, needle) terminates without deleting", () => {
    const r = runIsolated(`
      const { findAndDelete } = await import(SRC + "/validation/tx.ts");
      return findAndDelete(Buffer.from(${JSON.stringify(NEG5)} + "01cc", "hex"), Buffer.from("01cc", "hex")).toString("hex");
    `);
    expect(r.timedOut).toBe(false);
    // 01cc sits inside the (truncated) PUSHDATA4 payload, not at an opcode
    // boundary, so it is not deleted.
    expect(r.value).toBe(NEG5 + "01cc");
  }, TEST_TIMEOUT_MS);

  test("tx.ts findAndDelete still deletes at an opcode boundary (control)", () => {
    const r = runIsolated(`
      const { findAndDelete } = await import(SRC + "/validation/tx.ts");
      return findAndDelete(Buffer.from("5101cc51", "hex"), Buffer.from("01cc", "hex")).toString("hex");
    `);
    expect(r.timedOut).toBe(false);
    expect(r.value).toBe("5151");
  }, TEST_TIMEOUT_MS);
});
