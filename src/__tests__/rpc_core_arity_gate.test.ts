/**
 * #103 -- Core's central argument-count gate.
 *
 * Core validates argument COUNT in one place, after the method lookup and
 * before any handler runs (rpc/util.cpp:644 -> IsValidNumArgs, :733):
 *
 *     num_required <= n <= num_declared
 *
 * A violation throws the help text, which surfaces as error -1. hotbuns went
 * straight from `this.methods.get(...)` into `handler(params)`, so a surplus
 * positional argument was silently dropped -- even though handlers in
 * src/rpc/server.ts already documented the behaviour they expected from the
 * dispatcher ("Params: NONE. Any argument is a dispatcher arity error.", the
 * `ping` handler, :7962).
 *
 * Verified read-only against the live Core oracle on 2026-08-31:
 *   getblockhash []            -> code=-1  "getblockhash height"
 *   getblockcount ["surplus"]  -> code=-1  "getblockcount"
 *   getblockhash [1]           -> OK (control)
 */

import { describe, expect, test } from "bun:test";
import { coreArityFor } from "../rpc/server";

describe("#103 core arity table", () => {
  test("is populated (guards every assertion below)", () => {
    // A table that failed to load returns undefined for everything, which
    // makes the gate fail open and every other test here vacuous.
    expect(coreArityFor("savemempool")).toEqual({ required: 0, declared: 0 });
    expect(coreArityFor("clearbanned")).toEqual({ required: 0, declared: 0 });
    expect(coreArityFor("gettxout")).toEqual({ required: 2, declared: 3 });
    expect(coreArityFor("sendrawtransaction")).toEqual({
      required: 1,
      declared: 3,
    });
  });

  test("CONTROL: an unlisted method fails OPEN", () => {
    // Coverage is 87 of 103. Treating an unlisted method as zero-arg would
    // reject calls Core accepts -- worse than the gap being open.
    expect(coreArityFor("definitely-not-an-rpc")).toBeUndefined();
  });
});

function violates(method: string, n: number): boolean {
  const a = coreArityFor(method);
  if (!a) throw new Error(`${method} missing from the table`);
  return n < a.required || n > a.declared;
}

describe("#103 out-of-range counts are violations", () => {
  for (const [method, n] of [
    ["savemempool", 1], // Core's savemempool takes NO arguments
    ["clearbanned", 1],
    ["getblockcount", 1],
    ["gettxout", 1], // one too few
    ["gettxout", 4], // one too many
    ["sendrawtransaction", 0], // missing the required hexstring
    ["getblockhash", 0],
    ["getblockhash", 2],
  ] as [string, number][]) {
    test(`${method} with ${n} arg(s)`, () => {
      expect(violates(method, n)).toBe(true);
    });
  }
});

describe("#103 CONTROL: every legal count is accepted", () => {
  // Without these, a gate that refused everything would satisfy the block
  // above. Every count from required..declared inclusive must be allowed.
  for (const [method, n] of [
    ["savemempool", 0],
    ["clearbanned", 0],
    ["getblockcount", 0],
    ["gettxout", 2], // required
    ["gettxout", 3], // declared
    ["sendrawtransaction", 1],
    ["sendrawtransaction", 2],
    ["sendrawtransaction", 3],
    ["getblockhash", 1],
  ] as [string, number][]) {
    test(`${method} with ${n} arg(s)`, () => {
      expect(violates(method, n)).toBe(false);
    });
  }
});
