/**
 * No require() on the block-validation hot path.
 *
 * Bun (1.3.11 .. at least 1.4.2, oven-sh/bun#43279) appends to the
 * requiring module's native JSCommonJSModule::m_children vector on EVERY
 * require() of an already-cached module, never deduplicating, and the GC
 * marker walks that vector (JSCommonJSModule::visitChildren). tx.ts used
 * to require("../script/interpreter.js") once per verified input, on the
 * main thread and in all 15 script-check workers. Measured on bun 1.3.11
 * (8M calls): +~350 MB RSS and full GC 1 ms -> 60-120 ms; hoisted: flat.
 * The 401723 R4 Bun segfault faulted in
 * JSCommonJSModule::visitChildrenImpl -> appendValues.
 *
 * Pin: the validation/script/consensus/crypto modules contain no require()
 * except tx.ts's single once-per-isolate cache, and the second test proves
 * the cache returns the same module object every call.
 *
 * Negative control: restoring a per-call `require(...)` in
 * verifyInputScript makes the first test fail (2 requires in tx.ts / one
 * not behind `??=`).
 */
import { describe, expect, test } from "bun:test";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

const SRC = join(import.meta.dir, "..");
const HOT_DIRS = ["validation", "script", "consensus", "crypto"];
const HOT_FILES = ["chain/utxo.ts", "chain/state.ts", "sync/blocks.ts", "storage/database.ts"];

function codeLines(path: string): string[] {
  return readFileSync(path, "utf8")
    .split("\n")
    .filter((l) => !/^\s*(\/\/|\*|\/\*)/.test(l));
}

describe("no per-call require() on the validation hot path", () => {
  test("only tx.ts's once-cache calls require()", () => {
    const files: string[] = [];
    for (const d of HOT_DIRS) {
      for (const f of readdirSync(join(SRC, d))) {
        if (f.endsWith(".ts") && !f.endsWith(".test.ts")) files.push(join(d, f));
      }
    }
    files.push(...HOT_FILES);
    const hits: string[] = [];
    for (const rel of files) {
      for (const l of codeLines(join(SRC, rel))) {
        if (/\brequire\(/.test(l)) hits.push(`${rel}: ${l.trim()}`);
      }
    }
    expect(files.length).toBeGreaterThan(20); // denominator: the scan saw the tree
    expect(hits.length).toBe(1);
    expect(hits[0]).toStartWith("validation/tx.ts:");
    expect(hits[0]).toContain("??= require(");
  });

  test("verifyInputScript paths resolve the interpreter to one module object", async () => {
    const tx = await import("./tx.js");
    const interp = await import("../script/interpreter.js");
    // Exercise the public entry repeatedly; the cache must hand back the
    // same namespace the static import sees.
    const get = (tx as unknown as { __interpreterModuleForTest?: () => unknown })
      .__interpreterModuleForTest;
    expect(typeof get).toBe("function");
    const a = get!();
    const b = get!();
    expect(a).toBe(b);
    expect((a as typeof interp).verifyTaproot).toBe(interp.verifyTaproot);
  });
});
