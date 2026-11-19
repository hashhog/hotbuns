/**
 * cffix-hotbuns-tapscript-condstack — the IF/ELSE/ENDIF condition stack must
 * be O(1) per opcode.
 *
 * Tapscript (BIP-342) has no 201-opcode limit and no script-size limit, so a
 * standard-weight transaction can carry a ~400 kB tapscript. Before this fix
 * executeScript recomputed `condStack.every(v => v)` for EVERY opcode and
 * allocated `condStack.slice(0, -1)` on every OP_ELSE, so deep OP_IF nesting
 * followed by many opcodes cost O(depth * ops) on the validation thread
 * (mempool acceptance and block connect).
 *
 * Core (src/script/interpreter.cpp, class ConditionStack) keeps only
 * m_stack_size and m_first_false_pos, making empty()/all_true()/push_back()/
 * pop_back()/toggle_top() all O(1). These tests pin both the cost and the
 * semantics (Core script_tests.json IF/NOTIF/ELSE vectors as controls).
 */

import { describe, expect, test } from "bun:test";
import {
  Opcode,
  parseScript,
  executeScript,
  scriptNumEncode,
  type ScriptFlags,
  type ExecutionContext,
  SigVersion,
} from "../script/interpreter.js";

function flags(): ScriptFlags {
  return {
    verifyP2SH: true,
    verifyWitness: true,
    verifyTaproot: true,
    verifyStrictEncoding: true,
    verifyDERSignatures: true,
    verifyLowS: false,
    verifyNullDummy: false,
    verifyNullFail: false,
    verifyCheckLockTimeVerify: false,
    verifyCheckSequenceVerify: false,
    verifyWitnessPubkeyType: false,
  };
}

function ctx(sigVersion: SigVersion, stack: Buffer[] = []): ExecutionContext {
  return {
    stack,
    altStack: [],
    flags: flags(),
    sigHasher: () => Buffer.alloc(32),
    sigVersion,
    taprootSigHasher: () => Buffer.alloc(32),
    sigopsBudget: 1_000_000,
  };
}

function castToBool(b: Buffer): boolean {
  for (let i = 0; i < b.length; i++) {
    if (b[i] !== 0) return !(i === b.length - 1 && b[i] === 0x80);
  }
  return false;
}

function run(raw: Buffer, c: ExecutionContext): boolean {
  try {
    return executeScript(parseScript(raw), c);
  } catch {
    return false;
  }
}

describe("tapscript condition stack is O(1) per opcode", () => {
  const N = 50_000;
  // 50,000 x (OP_1 OP_IF), 50,000 x OP_NOP, 50,000 x OP_ENDIF, then OP_1.
  const parts: number[] = [];
  for (let i = 0; i < N; i++) parts.push(Opcode.OP_1, Opcode.OP_IF);
  for (let i = 0; i < N; i++) parts.push(Opcode.OP_NOP);
  for (let i = 0; i < N; i++) parts.push(Opcode.OP_ENDIF);
  parts.push(Opcode.OP_1);
  const raw = Buffer.from(parts);

  test(
    "50k-deep OP_IF nesting + 50k OP_NOP + 50k OP_ENDIF finishes within 1 s",
    () => {
      const c = ctx(SigVersion.TAPSCRIPT);
      const t0 = performance.now();
      const ok = run(raw, c);
      const ms = performance.now() - t0;
      expect(ok).toBe(true);
      expect(c.stack.length).toBe(1);
      expect(ms).toBeLessThan(1000);
    },
    1000,
  );

  test(
    "50k-deep nesting with 50k OP_ELSE toggles finishes within 1 s",
    () => {
      // Nest 50k executing IFs and toggle the innermost one 50k times; each
      // OP_ELSE used to allocate and scan a 50k-element slice.
      const p: number[] = [];
      for (let i = 0; i < N; i++) p.push(Opcode.OP_1, Opcode.OP_IF);
      for (let i = 0; i < N; i++) p.push(Opcode.OP_ELSE);
      // N toggles (even) => innermost branch is executing again.
      for (let i = 0; i < N; i++) p.push(Opcode.OP_ENDIF);
      p.push(Opcode.OP_1);
      const c = ctx(SigVersion.TAPSCRIPT);
      const t0 = performance.now();
      const ok = run(Buffer.from(p), c);
      const ms = performance.now() - t0;
      expect(ok).toBe(true);
      expect(c.stack.length).toBe(1);
      expect(ms).toBeLessThan(1000);
    },
    1000,
  );
});

describe("condition stack semantics (Core ConditionStack)", () => {
  const cases: Array<[string, number[], Buffer[] | null]> = [
    // executing outer, toggled inner
    ["1 IF 0 IF 2 ELSE 3 ENDIF ENDIF", [Opcode.OP_1, Opcode.OP_IF, Opcode.OP_0, Opcode.OP_IF, Opcode.OP_2, Opcode.OP_ELSE, Opcode.OP_3, Opcode.OP_ENDIF, Opcode.OP_ENDIF], [scriptNumEncode(3)]],
    // dead outer: inner ELSE must not make anything execute
    ["0 IF 0 IF 2 ELSE 3 ENDIF ELSE 4 ENDIF", [Opcode.OP_0, Opcode.OP_IF, Opcode.OP_0, Opcode.OP_IF, Opcode.OP_2, Opcode.OP_ELSE, Opcode.OP_3, Opcode.OP_ENDIF, Opcode.OP_ELSE, Opcode.OP_4, Opcode.OP_ENDIF], [scriptNumEncode(4)]],
    // dead outer, inner true IF opened while dead stays dead
    ["0 IF 1 IF 2 ENDIF 5 ENDIF 6", [Opcode.OP_0, Opcode.OP_IF, Opcode.OP_1, Opcode.OP_IF, Opcode.OP_2, Opcode.OP_ENDIF, Opcode.OP_5, Opcode.OP_ENDIF, Opcode.OP_6], [scriptNumEncode(6)]],
    // multiple ELSE on the same IF (Core allows; toggles each time)
    ["1 IF 2 ELSE 3 ELSE 4 ENDIF", [Opcode.OP_1, Opcode.OP_IF, Opcode.OP_2, Opcode.OP_ELSE, Opcode.OP_3, Opcode.OP_ELSE, Opcode.OP_4, Opcode.OP_ENDIF], [scriptNumEncode(2), scriptNumEncode(4)]],
    // first false at depth 2 of 3; pop of the false entry restores execution
    ["1 IF 0 IF 1 IF 7 ENDIF ENDIF 8 ENDIF", [Opcode.OP_1, Opcode.OP_IF, Opcode.OP_0, Opcode.OP_IF, Opcode.OP_1, Opcode.OP_IF, Opcode.OP_7, Opcode.OP_ENDIF, Opcode.OP_ENDIF, Opcode.OP_8, Opcode.OP_ENDIF], [scriptNumEncode(8)]],
    // ELSE with an empty condition stack fails
    ["ELSE", [Opcode.OP_ELSE], null],
    // ENDIF with an empty condition stack fails
    ["ENDIF", [Opcode.OP_ENDIF], null],
    // unbalanced at end fails
    ["1 IF", [Opcode.OP_1, Opcode.OP_IF], null],
  ];
  for (const sv of [SigVersion.BASE, SigVersion.WITNESS_V0, SigVersion.TAPSCRIPT]) {
    for (const [name, ops, want] of cases) {
      test(`sigversion ${sv}: ${name}`, () => {
        const c = ctx(sv);
        const ok = run(Buffer.from(ops), c);
        if (want === null) {
          expect(ok).toBe(false);
        } else {
          expect(ok).toBe(true);
          expect(c.stack.map((b) => b.toString("hex"))).toEqual(want.map((b) => b.toString("hex")));
        }
      });
    }
  }
});

// Core src/test/data/script_tests.json — every vector whose scriptSig and
// scriptPubKey use IF/NOTIF/ELSE together with only plain numbers and the
// opcodes below, flags in {"", P2SH, STRICTENC, P2SH,STRICTENC}.
// Format: [scriptSig asm, scriptPubKey asm, expected result].
const CORE_VECTORS: Array<[string, string, string]> = [
  ["1", "DUP IF ENDIF", "OK"],
  ["1", "IF 1 ENDIF", "OK"],
  ["1", "DUP IF ELSE ENDIF", "OK"],
  ["1", "IF 1 ELSE ENDIF", "OK"],
  ["0", "IF ELSE 1 ENDIF", "OK"],
  ["1 1", "IF IF 1 ELSE 0 ENDIF ENDIF", "OK"],
  ["1 0", "IF IF 1 ELSE 0 ENDIF ENDIF", "OK"],
  ["1 1", "IF IF 1 ELSE 0 ENDIF ELSE IF 0 ELSE 1 ENDIF ENDIF", "OK"],
  ["0 0", "IF IF 1 ELSE 0 ENDIF ELSE IF 0 ELSE 1 ENDIF ENDIF", "OK"],
  ["1 0", "NOTIF IF 1 ELSE 0 ENDIF ENDIF", "OK"],
  ["1 1", "NOTIF IF 1 ELSE 0 ENDIF ENDIF", "OK"],
  ["1 0", "NOTIF IF 1 ELSE 0 ENDIF ELSE IF 0 ELSE 1 ENDIF ENDIF", "OK"],
  ["0 1", "NOTIF IF 1 ELSE 0 ENDIF ELSE IF 0 ELSE 1 ENDIF ENDIF", "OK"],
  ["0", "IF 0 ELSE 1 ELSE 0 ENDIF", "OK"],
  ["1", "IF 1 ELSE 0 ELSE ENDIF", "OK"],
  ["1", "IF ELSE 0 ELSE 1 ENDIF", "OK"],
  ["1", "IF 1 ELSE 0 ELSE 1 ENDIF ADD 2 EQUAL", "OK"],
  ["1", "NOTIF 0 ELSE 1 ELSE 0 ENDIF", "OK"],
  ["0", "NOTIF 1 ELSE 0 ELSE ENDIF", "OK"],
  ["0", "NOTIF ELSE 0 ELSE 1 ENDIF", "OK"],
  ["0", "NOTIF 1 ELSE 0 ELSE 1 ENDIF ADD 2 EQUAL", "OK"],
  ["0", "IF 1 IF RETURN ELSE RETURN ELSE RETURN ENDIF ELSE 1 IF 1 ELSE RETURN ELSE 1 ENDIF ELSE RETURN ENDIF ADD 2 EQUAL", "OK"],
  ["1", "NOTIF 0 NOTIF RETURN ELSE RETURN ELSE RETURN ENDIF ELSE 0 NOTIF 1 ELSE RETURN ELSE 1 ENDIF ELSE RETURN ENDIF ADD 2 EQUAL", "OK"],
  ["0", "IF RETURN ENDIF 1", "OK"],
  ["1", "IF 1 ENDIF", "OK"],
  ["0", "NOTIF 1 ENDIF", "OK"],
  ["1 IF", "1 ENDIF", "UNBALANCED_CONDITIONAL"],
  ["1 IF 0 ENDIF", "1 ENDIF", "UNBALANCED_CONDITIONAL"],
  ["1 ELSE 0 ENDIF", "1", "UNBALANCED_CONDITIONAL"],
  ["0 NOTIF", "123", "UNBALANCED_CONDITIONAL"],
  ["0", "DUP IF ENDIF", "EVAL_FALSE"],
  ["0", "IF 1 ENDIF", "EVAL_FALSE"],
  ["0", "DUP IF ELSE ENDIF", "EVAL_FALSE"],
  ["0", "IF 1 ELSE ENDIF", "EVAL_FALSE"],
  ["0", "NOTIF ELSE 1 ENDIF", "EVAL_FALSE"],
  ["0 1", "IF IF 1 ELSE 0 ENDIF ENDIF", "EVAL_FALSE"],
  ["0 0", "IF IF 1 ELSE 0 ENDIF ENDIF", "EVAL_FALSE"],
  ["1 0", "IF IF 1 ELSE 0 ENDIF ELSE IF 0 ELSE 1 ENDIF ENDIF", "EVAL_FALSE"],
  ["0 1", "IF IF 1 ELSE 0 ENDIF ELSE IF 0 ELSE 1 ENDIF ENDIF", "EVAL_FALSE"],
  ["0 0", "NOTIF IF 1 ELSE 0 ENDIF ENDIF", "EVAL_FALSE"],
  ["0 1", "NOTIF IF 1 ELSE 0 ENDIF ENDIF", "EVAL_FALSE"],
  ["1 1", "NOTIF IF 1 ELSE 0 ENDIF ELSE IF 0 ELSE 1 ENDIF ENDIF", "EVAL_FALSE"],
  ["0 0", "NOTIF IF 1 ELSE 0 ENDIF ELSE IF 0 ELSE 1 ENDIF ENDIF", "EVAL_FALSE"],
  ["1", "IF RETURN ELSE ELSE 1 ENDIF", "OP_RETURN"],
  ["1", "IF 1 ELSE ELSE RETURN ENDIF", "OP_RETURN"],
  ["1", "ELSE ENDIF", "UNBALANCED_CONDITIONAL"],
  ["1", "ENDIF ELSE", "UNBALANCED_CONDITIONAL"],
  ["1", "ENDIF ELSE IF", "UNBALANCED_CONDITIONAL"],
  ["1", "IF ELSE ENDIF ELSE", "UNBALANCED_CONDITIONAL"],
  ["1", "IF ELSE ENDIF ELSE ENDIF", "UNBALANCED_CONDITIONAL"],
  ["1", "IF ENDIF ENDIF", "UNBALANCED_CONDITIONAL"],
  ["1", "IF ELSE ELSE ENDIF ENDIF", "UNBALANCED_CONDITIONAL"],
  ["1", "DUP IF RETURN ENDIF", "OP_RETURN"],
  ["0 IF", "RETURN ENDIF 1", "UNBALANCED_CONDITIONAL"],
  ["1", "IF 1", "UNBALANCED_CONDITIONAL"],
  ["1 IF 1", "ENDIF", "UNBALANCED_CONDITIONAL"],
  ["NOP", "IF 1 ENDIF", "INVALID_STACK_OPERATION"],
  ["NOP", "NOTIF 1 ENDIF", "INVALID_STACK_OPERATION"]
];

const NAMED: Record<string, number> = {
  IF: Opcode.OP_IF, NOTIF: Opcode.OP_NOTIF, ELSE: Opcode.OP_ELSE, ENDIF: Opcode.OP_ENDIF,
  NOP: Opcode.OP_NOP, DROP: Opcode.OP_DROP, DUP: Opcode.OP_DUP, VERIFY: Opcode.OP_VERIFY,
  RETURN: Opcode.OP_RETURN, EQUAL: Opcode.OP_EQUAL, EQUALVERIFY: Opcode.OP_EQUALVERIFY,
  ADD: Opcode.OP_ADD, SUB: Opcode.OP_SUB, DEPTH: Opcode.OP_DEPTH, TRUE: Opcode.OP_1,
  FALSE: Opcode.OP_0, NOT: Opcode.OP_NOT, "1ADD": Opcode.OP_1ADD, "2DUP": Opcode.OP_2DUP,
  SWAP: Opcode.OP_SWAP, "0NOTEQUAL": Opcode.OP_0NOTEQUAL,
};

function asm(s: string): Buffer {
  const out: number[] = [];
  for (const tok of s.split(/\s+/).filter((t) => t.length > 0)) {
    if (/^-?\d+$/.test(tok)) {
      const n = Number(tok);
      if (n === 0) out.push(Opcode.OP_0);
      else if (n === -1) out.push(Opcode.OP_1NEGATE);
      else if (n >= 1 && n <= 16) out.push(Opcode.OP_1 + n - 1);
      else {
        const e = scriptNumEncode(n);
        out.push(e.length, ...e);
      }
    } else {
      const op = NAMED[tok];
      if (op === undefined) throw new Error(`unknown token ${tok}`);
      out.push(op);
    }
  }
  return Buffer.from(out);
}

describe("Core script_tests.json IF/NOTIF/ELSE vectors (controls)", () => {
  test("vector set is non-trivial", () => {
    expect(CORE_VECTORS.length).toBeGreaterThanOrEqual(50);
  });
  for (const [sig, pk, res] of CORE_VECTORS) {
    test(`[${sig}] [${pk}] => ${res}`, () => {
      const c = ctx(SigVersion.BASE);
      // Core VerifyScript: scriptSig and scriptPubKey run as separate
      // EvalScript calls sharing the stack; success needs a true top.
      const ok =
        run(asm(sig), c) &&
        run(asm(pk), c) &&
        c.stack.length > 0 &&
        castToBool(c.stack[c.stack.length - 1]);
      expect(ok).toBe(res === "OK");
    });
  }
});
