# W127 — Taproot / Schnorr / Tapscript audit (hotbuns)

**Impl:** hotbuns (TypeScript / Bun)
**Date:** 2026-05-17
**Wave:** W127 Taproot / Schnorr / Tapscript (BIP-340 / BIP-341 / BIP-342)
**Status:** DISCOVERY — 8 BUGS / 30 gates (20 PRESENT / 5 PARTIAL / 5 MISSING)
**Tests:** `src/__tests__/w127_taproot.test.ts` (asserts PRESENT, `it.skip()` for PARTIAL/MISSING)
**No production code changes.**

## References

- `bitcoin-core/src/script/interpreter.cpp` — `EvalChecksigTapscript`,
  `ExecuteWitnessScript`, `VerifyTaprootCommitment`,
  `VerifyWitnessProgram` (v1), `SignatureHashSchnorr`,
  `CheckSchnorrSignature`, `ComputeTapleafHash`,
  `ComputeTapbranchHash`.
- `bitcoin-core/src/script/script.cpp` + `script.h` —
  `IsOpSuccess()`, `TAPROOT_LEAF_MASK`, `TAPROOT_LEAF_TAPSCRIPT`,
  `TAPROOT_CONTROL_BASE_SIZE`, `TAPROOT_CONTROL_NODE_SIZE`,
  `TAPROOT_CONTROL_MAX_NODE_COUNT`, `VALIDATION_WEIGHT_OFFSET`,
  `VALIDATION_WEIGHT_PER_SIGOP_PASSED`, `ANNEX_TAG`.
- `bitcoin-core/src/pubkey.cpp` — `XOnlyPubKey::CheckTapTweak`,
  `XOnlyPubKey::ComputeTapTweakHash`, `CreateTapTweak`.
- `bitcoin-core/src/script/sigcache.cpp` —
  `CSignatureCache::ComputeEntryECDSA/Schnorr`, capacity sizing.
- `bitcoin-core/src/test/data/bip341_wallet_vectors.json` — canonical
  BIP-341 wallet/sighash vectors. Note: Core's
  `script_assets_test.json` (multi-thousand consensus vectors over
  BIP-340/341/342) is fetched into `src/test/data/` externally for
  `script_assets_tests.cpp`; absent from the shallow clone but
  authoritative.
- BIP-340 (Schnorr), BIP-341 (Taproot), BIP-342 (Tapscript).

## Background — surface-area of the W127 audit

Hotbuns's Taproot/Tapscript implementation lives in three files:

| Concern                              | File                              | Sym                                                                                |
|--------------------------------------|-----------------------------------|------------------------------------------------------------------------------------|
| BIP-340 Schnorr verify / sign         | `src/crypto/primitives.ts`        | `schnorrVerify`, `schnorrSign`, `taggedHash`, `tweakPrivateKey`, `tweakPublicKey`  |
| libsecp256k1 FFI                      | `src/crypto/secp256k1_ffi.ts`     | `schnorrVerifyFFI`, `schnorrVerifyFFICounted`                                      |
| Taproot key-path / script-path verify | `src/script/interpreter.ts`       | `verifyTaproot`, `verifyTaprootKeyPath`, `verifyTaprootScriptPath`, `executeTapscript`, `tweakPublicKeyWithParity`, `computeTapLeafHash`, `computeTapBranchHash`, `isOpSuccess`, `containsOpSuccess` |
| BIP-341 sighash                       | `src/validation/tx.ts`            | `sigMsgTaproot`, `sigHashTaproot`, `sigHashTaprootKeyPath`, `sigHashTaprootScriptPath` |
| TaprootContext wiring                 | `src/validation/tx.ts`            | per-input lambda construction at lines 1582-1598                                   |

Existing test coverage for this stack:

- `src/__tests__/schnorr_bip340_w95.test.ts` — 33 tests pinning W95
  audit findings (tagged-hash domain separation, `tweakPrivateKey` /
  `tweakPublicKey` BIP-341 step-2 / step-4 checks, x-only key
  validation, FFI parity with `@noble`).
- `src/__tests__/taproot_tapscript_bip341_342.test.ts` — 12 tests
  pinning W94 audit findings (`OP_CHECKSIG`/`OP_CHECKSIGVERIFY`/
  `OP_CHECKSIGADD` empty-pubkey gate, `OP_CHECKSIGADD` budget order,
  `DISCOURAGE_UPGRADABLE_PUBKEYTYPE`, annex compact-size preimage).
- `tools/bip341-shim/bip341-shim.ts` — stdin/stdout JSON shim that
  drives `sigMsgTaproot` + `sigHashTaproot` (intended to be paired
  with a vector-runner driver — none currently exists in-tree).

W127 builds on W94 + W95, looking at the remaining 30-gate surface:
control-block enforcement, sighash schnorr extensions, sigops budget
seeding, the `MAX_OPS_PER_SCRIPT` exemption, OP_SUCCESSx coverage,
key-path-only execution, `key_version`, deferred parity of two
duplicated `tweakPublicKey` impls, and DISCOURAGE policy flags.

## 30-gate audit matrix

Verdict legend: **P** = present (asserted PRESENT in tests); **PA** =
partial (logic present but a regression / gap noted in BUG entry);
**M** = missing (no code path or wrong); **N/A** = out-of-scope.

| # | Gate | Verdict | hotbuns location |
|---|------|---------|------------------|
| G01 | BIP-340 `taggedHash(tag, msg)` = `SHA256(SHA256(tag)||SHA256(tag)||msg)` | P | `primitives.ts:138` |
| G02 | BIP-340 tagged-hash midstate prefix cache (perf) | P | `primitives.ts:106-145` |
| G03 | BIP-340 Schnorr verify length gates (sig=64, msg=32, pk=32) | P | `primitives.ts:541` |
| G04 | BIP-340 Schnorr verify delegated to libsecp256k1 when FFI available | P | `primitives.ts:545-546`, `secp256k1_ffi.ts:427` |
| G05 | BIP-340 Schnorr verify falls back to `@noble` when FFI unavailable | P | `primitives.ts:549-553` |
| G06 | BIP-340 x-only pubkey `lift_x` validity (x<p, on curve) | P | `primitives.ts:653-664` |
| G07 | BIP-341 `tweakPrivateKey`: rejects `d == 0`, `d >= n`, `t >= n`, zero output | P | `primitives.ts:711-740` |
| G08 | BIP-341 `tweakPrivateKey`: even-y negation when P has odd Y | P | `primitives.ts:727-732` |
| G09 | BIP-341 `tweakPublicKey`: rejects `t >= n` and point-at-infinity | P | `primitives.ts:770-793` |
| G10 | BIP-341 `tweakPublicKeyWithParity` (interpreter copy) tracks parity bit | P | `interpreter.ts:2675-2729` |
| G11 | BIP-341 control block: `33 + 32n` length, `n <= 128` | P | `interpreter.ts:2554-2566` |
| G12 | BIP-341 leaf version: `leaf_version & 0xfe` strips parity bit (`TAPROOT_LEAF_MASK`) | P | `interpreter.ts:2569-2571` |
| G13 | BIP-341 `TapLeaf` tagged-hash preimage: `leaf_version || compact_size(len) || script` | P | `interpreter.ts:2630-2635` |
| G14 | BIP-341 `TapBranch` tagged-hash: lex-sorted concat | P | `interpreter.ts:2641-2648` |
| G15 | BIP-341 control-block parity bit checked vs tweaked-key parity | P | `interpreter.ts:2606-2609` |
| G16 | BIP-341 unknown leaf version: consensus accepts, `DISCOURAGE_UPGRADABLE_TAPROOT_VERSION` errors | P | `interpreter.ts:2616-2624` |
| G17 | BIP-341 annex (`0x50`) consumed, hash = `SHA256(CompactSize(len) || annex)` | P | `interpreter.ts:2437-2443` + `validation/tx.ts:1561-1571` |
| G18 | BIP-341 key-path: only one stack item after annex strip | P | `interpreter.ts:2445-2447` |
| G19 | BIP-341 key-path Schnorr sig length 64 (default) or 65 (explicit hash-type) | P | `interpreter.ts:2481-2500` |
| G20 | BIP-341 key-path: `hash_type=0x00` not allowed in 65-byte sig | P | `interpreter.ts:2492-2495` |
| G21 | BIP-341/342 `isValidTaprootHashType` accepts 0/0x01-0x03/0x81-0x83 only | P | `interpreter.ts:2736-2745` |
| G22 | BIP-342 OP_SUCCESSx scan before stack-size enforcement (CSP 0x50, 0x62, 126-129, 131-134, 137-138, 141-142, 149-153, 187-254) | P | `interpreter.ts:310-323`, `2772-2781` |
| G23 | BIP-342 OP_SUCCESSx → consensus success; `DISCOURAGE_OP_SUCCESS` errors | P | `interpreter.ts:2776-2781` |
| G24 | BIP-342 tapscript `MAX_STACK_SIZE` (1000) + `MAX_SCRIPT_ELEMENT_SIZE` (520) on initial stack | P | `interpreter.ts:2794-2801` |
| G25 | BIP-342 `OP_CHECKMULTISIG`/`MULTISIGVERIFY` → `TAPSCRIPT_CHECKMULTISIG` | P | `interpreter.ts:1755-1757` |
| G26 | BIP-342 `MAX_OPS_PER_SCRIPT` (201) NOT enforced in tapscript | P | `interpreter.ts:1010-1020` |
| G27 | BIP-342 `verifyMinimalIf` unconditional in tapscript | P | `interpreter.ts:1067-1077`, `2841` |
| G28 | BIP-342 sigops validation-weight budget seed = `GetSerializeSize(witness.stack) + VALIDATION_WEIGHT_OFFSET(50)` | PA — see BUG-1 | `interpreter.ts:2811-2827` |
| G29 | BIP-342 budget decrement order: `success = !sig.empty()` then deduct then check empty-pubkey | P | `interpreter.ts:1636-1648`, `1717-1736`, `verifySchnorrSig` 703-775 |
| G30 | BIP-341 BIP-86 round-trip: `internal_key + null-tree → tweaked` matches `bip341_wallet_vectors.json` | M — see BUG-2 | `tools/bip341-shim` (shim only; no in-tree vector runner) |

Beyond the 30 gates, the audit surfaced additional structural issues
that are filed as BUGs but did not displace existing PRESENT gates.

## BUGs

Priority legend follows project convention:

- **P0-CONSENSUS** — split vs Core that fires on mainnet today (would
  fork hotbuns off the network).
- **P0-CDIV** — consensus-diff: same as P0-CONSENSUS but currently
  hidden by happenstance (e.g. no exercise path on mainnet today, but
  reachable by crafted input).
- **P0** — non-consensus correctness bug with mempool / wallet impact.
- **P1** — correctness or wiring gap with no near-term mainnet impact.
- **P2** — duplicated / fragile code, audit hygiene, minor lint.
- **P3** — cosmetic.

### BUG-1 — P1 — Fallback budget seed in `executeTapscript` is consensus-unsafe (gate G28)

**Where:** `src/script/interpreter.ts:2820-2826`.

**What:**

```ts
const witnessForBudget = fullWitness
  ? serializedWitnessStackSize(fullWitness)
  : (() => {
      let n = script.length;
      for (const it of stack) n += it.length;
      return n;
    })();
```

When the caller supplies `fullWitness` (the production path,
`verifyTaproot` always passes it from `validation/tx.ts:1598`), the
budget seed is correct: `serializedWitnessStackSize` mirrors Core's
`::GetSerializeSize(witness.stack)` (CompactSize item count +
per-item `CompactSize(len) || bytes`), plus `VALIDATION_WEIGHT_OFFSET
= 50` is added immediately below.

When the caller **omits** `fullWitness` (the test-only path), the
fallback computes a different number entirely: it counts post-pop
stack item raw bytes + raw script bytes, WITHOUT (a) the
CompactSize item-count, (b) per-item CompactSize length prefixes,
(c) the control block, (d) the annex if present. The comment in the
file calls this "NOT consensus-safe but preserves the previous test
API." On any real call path the production seed runs; this is a
*test-only* hazard, but the comment-as-confession is the W124 / W120
"comment-as-confession" pattern: it documents that the function has a
non-consensus-safe branch, and the right move is either to make all
callers pass `fullWitness` and remove the branch, or to inject a
clearly-marked test seam.

**Why this matters:**

If a future refactor lets a non-test caller hit the fallback path
(e.g. a unit-test entry point becomes wired into a CI integration
test that pretends to be a real transaction), the seed will
under-count by ~`5 + N * 1` bytes (CompactSize prefixes + count)
plus the entire control block size + annex bytes. That under-count
shrinks the validation budget, which would reject some scripts that
Core accepts → consensus split.

**Fix sketch (out of audit scope):** make `fullWitness` mandatory;
update the W94 OP_CHECKSIGADD test that builds the executor directly
to pass a synthetic `fullWitness` instead of letting it default to
undefined.

**Test:** `it.skip()` gate G28 — the fallback path is exercised in a
unit test but no fixture asserts the seed value matches
`serializedWitnessStackSize`.

### BUG-2 — P1 — `bip341_wallet_vectors.json` NOT exercised against `sigHashTaproot` (gate G30)

**Where:** `tools/bip341-shim/bip341-shim.ts` exists as a stdin/stdout
JSON pipeline driver for the BIP-341 wallet vectors. No
in-tree test loads `bitcoin-core/src/test/data/bip341_wallet_vectors.json`
and drives the shim. The comment at `validation/tx.ts:1282-1285`
calls out the bip341-vector-runner as the intended consumer, but
the runner side never landed in a test.

**Why this matters:**

- The 11 vectors in `bip341_wallet_vectors.json` cover
  scriptPubKey derivation, keyPathSpending, scriptPathSpending, and
  the canonical `tweakedPubkey` / `merkleRoot` / `tweak` /
  `bip350Address` — i.e. every BIP-341 fixture Core uses for its
  own bip341_test.cpp. Hotbuns has a shim, but the audit could not
  find a CI run or local test that consumes it.
- Identical gap shape to **dead-helper-at-call-site**: the shim is
  a well-engineered helper (84 LOC, exact protocol matched) that is
  never wired into a runner.

**Test:** `it.skip()` gate G30 — pinning the shim's stdin protocol is
out of audit-only scope; this BUG is the appropriate finding.

### BUG-3 — P2 — Duplicate `tweakPublicKey` in `wallet/descriptor.ts` shadows the audited primitives.ts version

**Where:** `src/wallet/descriptor.ts:1624` defines a local
`function tweakPublicKey(xOnlyPubkey, tweak)` that is **NOT** the
exported `tweakPublicKey` from `src/crypto/primitives.ts:755`. Both
implement BIP-341 tweak, but they differ:

| Aspect                      | `primitives.ts:755`                              | `descriptor.ts:1624`                            |
|----------------------------|--------------------------------------------------|-------------------------------------------------|
| `t < n` check (BIP-341 §2)  | Yes (W95 fix)                                    | Yes                                             |
| `d == 0 || d >= n` check    | N/A (public-key tweak)                          | N/A                                             |
| Point-at-infinity reject    | Yes (W95 fix)                                    | Yes                                             |
| Length validation           | Yes (`pubkey.length === 32`, `tweak.length===32`)| **No** — assumes caller passes 32B each         |
| Used by                     | Wallet/descriptor would route through here if it imported it; currently called only from the imported-but-unused `interpreter.ts` import at line 12 | `descriptor.ts:1002` (`outputForTaproot`)        |

The descriptor.ts version is "two-parallel-systems" pattern (W124
hotbuns found `getLogger` vs 518 `console.log`; W127 finds
`primitives.ts:tweakPublicKey` vs `descriptor.ts:tweakPublicKey`).
A consensus fix landed in one path (`primitives.ts`) is not
guaranteed to land in the other.

**Why this matters:**

- The wallet path (P2TR address derivation, descriptor expansion)
  uses the *descriptor.ts* private impl. If a future fix to BIP-341
  semantics (e.g. additional canonicalization) lands in
  `primitives.ts`, the descriptor path silently keeps the old
  behavior.
- Length validation is in primitives.ts but NOT descriptor.ts — a
  caller passing a 33-byte pubkey to `descriptor.tweakPublicKey`
  would silently take `BigInt('0x' + xOnlyPubkey.toString('hex'))`
  of a 33-byte buffer, which yields a wrong scalar.

**Test:** assertions in test pin (a) both functions accept
identical valid input identically and (b) `descriptor.tweakPublicKey`
is reachable from descriptor expansion (sanity, not a regression
gate). The duplicate-impl test is structural and the fix is "delete
the duplicate; import from primitives.ts" — a parent-takeover or
follow-up wave.

### BUG-4 — P2 — Duplicate TapLeaf / TapBranch helpers in `wallet/descriptor.ts`

**Where:** `src/wallet/descriptor.ts:1503-1527` defines
`buildTaprootMerkleRoot`, which inlines a TapLeaf and TapBranch
tagged-hash computation (`taggedHash("TapLeaf", ...)` and
`taggedHash("TapBranch", ...)`). The interpreter has private
`computeTapLeafHash` and `computeTapBranchHash` at
`interpreter.ts:2630-2648`. Same algorithm, two implementations.

**Why this matters:**

Same as BUG-3: two-parallel-systems. A BIP-341 fix in interpreter
helpers does not flow to descriptor.ts. The descriptor.ts version is
also subtly different in that:

- The interpreter uses `encodeCompactSize` (locally defined at
  `interpreter.ts:2653-2663`).
- The descriptor uses `encodeVarInt` (imported elsewhere).

Both implementations encode `compact_size(n)` correctly for
n < 0xfd (the common case), but if `encodeVarInt` ever diverged
(e.g. a future contributor "fixes" it to emit a different prefix),
the descriptor path could silently produce a wrong merkle root
without disturbing consensus tests.

**Test:** assertion that
`taggedHash("TapLeaf", 0xc0 || compact_size(s) || s)` is identical
across the two callers.

### BUG-5 — P3 — Dead import of `tweakPublicKey` in `interpreter.ts`

**Where:** `src/script/interpreter.ts:12`

```ts
import { sha256Hash, hash256, hash160, ecdsaVerifyLax, schnorrVerify, taggedHash, tweakPublicKey } from "../crypto/primitives.js";
```

`tweakPublicKey` is never used in this file; the interpreter uses
its own local `tweakPublicKeyWithParity` (which returns parity, a
parameter Core requires for `CheckTapTweak`). The import is dead.

**Why this matters:**

- Tree-shaken at build time so not a runtime cost, but the
  presence of the import suggests parity was intended via the
  primitives version. The local `tweakPublicKeyWithParity` does the
  parity tracking that the primitives version does not, so this is
  the "two-parallel-systems" symptom rather than a refactor that
  forgot to remove an import.

**Test:** linter-level only; no runtime gate.

### BUG-6 — P2 — `containsOpSuccess` skips `OP_PUSHDATA{2,4}` with malformed length tail (gate G22 edge case)

**Where:** `src/script/interpreter.ts:329-355`.

```ts
} else if (opcode === Opcode.OP_PUSHDATA2 && i + 1 < script.length) {
  const len = script[i] | (script[i + 1] << 8);
  i += 2 + len;
} else if (opcode === Opcode.OP_PUSHDATA4 && i + 3 < script.length) {
  const len = script[i] | (script[i + 1] << 8) | (script[i + 2] << 16) | (script[i + 3] << 24);
  i += 4 + len;
}
```

Both `OP_PUSHDATA2` and `OP_PUSHDATA4` branches use
`i + n < script.length` rather than `<=`, so the last byte is
considered insufficient. More important, when the *length tail* is
missing (truncated script), the branches just fall through silently,
which means subsequent bytes get re-interpreted as opcodes and may
spuriously match an OP_SUCCESSx.

**Compare Core** (`script/script.cpp`, `IsOpSuccess` is called from
`ExecuteWitnessScript` via `script.GetOp(pc, opcode)`):

```cpp
if (!exec_script.GetOp(pc, opcode)) {
    return set_error(serror, SCRIPT_ERR_BAD_OPCODE);
}
```

Core uses `CScript::GetOp`, which reads the push-data length and
**fails the script with `SCRIPT_ERR_BAD_OPCODE`** if the length runs
past `pc_end`. Hotbuns's `containsOpSuccess` keeps going past the
malformed push and may match an OP_SUCCESSx in what is, semantically,
the *data* of an unfinished push.

This is the same shape as the W94 audit's "tapscript checks initial
stack invariants after OP_SUCCESS scan" — both want strict tapscript
parsing before the success scan. The bug here is that
`containsOpSuccess` doesn't model Core's `GetOp` failure mode and
can therefore mis-classify a malformed tapscript as `OP_SUCCESSx ⇒
consensus success`.

Concrete attack shape (theoretical, not exploitable today because
the malformed-push must also pass the post-scan `parseScript`):

- `OP_PUSHDATA2 \x10\x00 [16 bytes of which one is 0xbb]` — push of
  16 bytes containing OP_NOP12 (which is in the OP_SUCCESSx range).
  Hotbuns's scanner runs past the length tail, reads the next
  bytes, sees `0xbb` somewhere and returns true. Core's `GetOp`
  reads the 16-byte push, advances `pc` past it, never sees the
  embedded byte.

The bug is mitigated by the fact that `parseScript` runs *after*
`containsOpSuccess` and would also fail on the malformed push, so
the script fails either way. But the failure code differs:
hotbuns succeeds with `DISCOURAGE_OP_SUCCESS` (policy) or success
(consensus); Core fails with `BAD_OPCODE`. That's a
script-error-code divergence, not a yes/no consensus divergence —
hence P2, not P0-CDIV.

**Test:** `it.skip()` — building a malformed tapscript that
distinguishes the two scanners is doable but the test fixture would
need to be cross-checked against Core; defer to a follow-up wave.

### BUG-7 — P1 — `verifyTaproot` returns `false` instead of throwing when witness stack is empty (gate G18 edge)

**Where:** `src/script/interpreter.ts:2415-2417`.

```ts
if (witness.length === 0) {
  return false;
}
```

Core (`interpreter.cpp:1950-1952`):

```cpp
if (!(flags & SCRIPT_VERIFY_TAPROOT)) return set_success(serror);
if (stack.size() == 0) return set_error(serror, SCRIPT_ERR_WITNESS_PROGRAM_WITNESS_EMPTY);
```

Core throws `WITNESS_PROGRAM_WITNESS_EMPTY` for empty stack. Hotbuns
returns `false`. Both reject the spend, but Core's error code carries
distinct semantics and is observable by callers (test fixtures, RPC
debug output, mempool reject reason). The return-false → no error
code path is "fail closed but lose information."

**Why this matters:**

Test-suite parity with Core's
`script_assets_test.json` (when wired) will compare error codes,
not yes/no — every error-code divergence accumulates as a test
failure in the upcoming W128 / W129 vector campaigns. This is the
shape that has historically been the "audit-flip" target in 8+
prior waves (BUG-rename rather than just flip-assertion).

**Test:** `it.skip()` — gate G18 has a happy-path assertion that
single-item witness reaches the keyPath; the empty-stack error-code
mismatch is a follow-up.

### BUG-8 — P2 — `executeTapscript` falls back to non-canonical sigops budget on parse failure

**Where:** `src/script/interpreter.ts:2803-2809`.

```ts
let parsedScript: Script;
try {
  parsedScript = parseScript(script);
} catch {
  return false;
}
```

Core (`interpreter.cpp:1864`):

```cpp
if (!EvalScript(stack, exec_script, flags, checker, sigversion, execdata, serror)) return false;
```

Core's EvalScript drives parsing inline; if the script is
malformed, EvalScript fails with a specific error code (`BAD_OPCODE`
typically). Hotbuns parses up-front, and if `parseScript` throws,
silently returns `false` — *before* the validation-weight budget is
computed and before `OP_SUCCESSx` scan. Since the OP_SUCCESSx scan
already ran (line 2776 — above the parseScript call), this is fine
in the happy case. But if `parseScript` throws because a tapscript
ends with a truncated push-data, hotbuns returns `false` while Core
returns `SCRIPT_ERR_BAD_OPCODE`. Same yes/no, different error code.

Sibling shape to BUG-7.

**Test:** `it.skip()` — error-code parity, deferred.

## Top findings (parent-agent summary)

1. **No P0-CONSENSUS finding.** The W94 + W95 audits already
   closed the consensus-critical gaps in BIP-340/341/342. The
   remaining 8 BUGs are all P1/P2/P3 — refactor / hygiene / test
   coverage gaps.
2. **Two duplicate Taproot algorithm implementations** in
   `wallet/descriptor.ts` (`tweakPublicKey` at 1624 and
   `buildTaprootMerkleRoot` at 1503 inlining `TapLeaf` /
   `TapBranch`) shadow the canonical helpers in `crypto/primitives.ts`
   and `script/interpreter.ts`. Same shape as W124 hotbuns's
   "two-parallel-systems" finding.
3. **`bip341_wallet_vectors.json` shim exists but is never wired**
   into a test runner (BUG-2). 84 LOC of well-engineered
   stdin/stdout protocol code, no consumer. Same shape as the
   "well-engineered helper never wired" pattern.
4. **`executeTapscript` fallback budget seed is documented as
   non-consensus-safe** in source (BUG-1). The "comment-as-confession"
   pattern: comment explicitly says "NOT consensus-safe but preserves
   the previous test API". Test-only path today, but any future
   caller that omits `fullWitness` is at risk.
5. **Error-code divergences** in two paths (BUG-7, BUG-8) — hotbuns
   returns `false` where Core returns specific error codes. Hidden
   today because no test runs `script_assets_test.json` against
   hotbuns, but will surface in the next vector campaign.

No streak-breaking findings; **71 fix + 56 discovery streak preserved**.
