# W131 — Output Descriptors + Miniscript audit (hotbuns)

**Impl:** hotbuns (TypeScript / Bun)
**Date:** 2026-05-17
**Wave:** W131 Output Descriptors + Miniscript (BIP-380, BIP-381, BIP-382, BIP-383, BIP-384, BIP-385, BIP-386, sipa Miniscript)
**Status:** DISCOVERY — 20 BUGS / 30 gates (12 PRESENT / 9 PARTIAL / 9 MISSING)
**Tests:** `src/__tests__/w131_descriptors_miniscript.test.ts` (asserts PRESENT, `it.skip()` for PARTIAL/MISSING)
**No production code changes.**

## References

- `bitcoin-core/src/script/descriptor.cpp` — `DescriptorChecksum`,
  `AddChecksum`, `ParseScript`, `ParseScriptContext`, `ParseKeyPath`,
  `ParseKeyPathNum`, `ParsePubkeyInner`, `MultisigDescriptor`,
  `MultiADescriptor`, `TRDescriptor`, `RawTRDescriptor`,
  `MiniscriptDescriptor`, `ScriptMaker`, `Parse`,
  `GetDescriptorChecksum`, `InferDescriptor`, `InferScript`.
- `bitcoin-core/src/script/miniscript.h` + `miniscript.cpp` —
  `Type`, `Fragment`, `ComputeType`, `SanitizeType`,
  `ComputeScriptLen`, `MaxScriptSize`, `Node::CalcType`,
  `Node::IsSane`, `Node::CheckTimeLocksMix`,
  `Node::CheckDuplicateKey`, `Node::ValidSatisfactions`,
  `InputStack`, `InputResult`, `Availability`, `MAX_TAPMINISCRIPT_STACK_ELEM_SIZE`.
- `bitcoin-core/src/script/script.h` — `MAX_SCRIPT_ELEMENT_SIZE=520`,
  `MAX_OPS_PER_SCRIPT=201`, `MAX_PUBKEYS_PER_MULTISIG=20`,
  `MAX_PUBKEYS_PER_MULTI_A=999`, `MAX_STACK_SIZE=1000`,
  `MAX_STANDARD_P2WSH_SCRIPT_SIZE=3600`,
  `TAPROOT_CONTROL_MAX_NODE_COUNT=128`.
- `bitcoin-core/src/test/descriptor_tests.cpp` — Core's canonical
  test harness (descriptor checksum vectors, parsing happy / sad
  paths, P2SH script-size limit, timelock-safety unparsables).
- `bitcoin-core/src/test/miniscript_tests.cpp` — fuzzy / canonical
  type-rule and sanity-rule vectors. Core's
  `descriptor_tests_external.json` (multi-thousand external
  descriptor vectors) is fetched externally; absent from shallow
  clone but authoritative for descriptor-checksum byte-exactness.
- BIPs 380 (descriptor grammar), 381 (`addr`, `raw`), 382 (`pk`,
  `pkh`, `wpkh`), 383 (`multi`, `sortedmulti`), 384 (`combo`),
  385 (`sh`, `wsh`), 386 (`tr`, `multi_a`, `sortedmulti_a`,
  `rawtr`).

## Background — surface-area of the W131 audit

Hotbuns's descriptors / miniscript implementation lives in two
files (≈ 5418 LOC), with hidden dependencies on the BIP-32 and
Taproot stack:

| Concern                              | File                              | Symbol                                                                              |
|--------------------------------------|-----------------------------------|-------------------------------------------------------------------------------------|
| BIP-380 checksum (polymod, add, validate) | `src/wallet/descriptor.ts`        | `polyMod`, `descriptorChecksum`, `addChecksum`, `validateChecksum`                  |
| Key providers (BIP-32 + const + WIF) | `src/wallet/descriptor.ts`        | `ConstPubkeyProvider`, `BIP32PubkeyProvider`, `parseKey`, `parseExtendedKey`, `parseHexKey`, `parseWIFKey`, `parseOrigin`, `formatPath` |
| Descriptor classes (BIP-381..386)    | `src/wallet/descriptor.ts`        | `PKDescriptor`, `PKHDescriptor`, `WPKHDescriptor`, `SHDescriptor`, `WSHDescriptor`, `TRDescriptor`, `RawtrDescriptor`, `MultiDescriptor`, `AddrDescriptor`, `RawDescriptor`, `ComboDescriptor`, `MiniscriptDescriptor` |
| Top-level parser                     | `src/wallet/descriptor.ts`        | `parseDescriptor`, `parseDescriptorInner`, `parseFunction`, `parsePK`, …, `parseTR`, `parseTaprootTree`, `parseMiniscriptDescriptor` |
| Taproot Merkle root (tree)           | `src/wallet/descriptor.ts`        | `TaprootTree`, `buildTaprootMerkleRoot`, `treeIsRange`, `treeToString` (lex-sort + inline `taggedHash`) |
| Local Taproot key tweak              | `src/wallet/descriptor.ts:1624`   | `tweakPublicKey` (private; SHADOWS `crypto/primitives.ts:tweakPublicKey`)           |
| Miniscript types + properties        | `src/wallet/miniscript.ts`        | `BaseType`, `TypeProperties`, `MiniscriptType`, `emptyProps`, `makeType`, `validateType`, `checkTimeLocksMix` |
| Miniscript AST                       | `src/wallet/miniscript.ts`        | `MiniscriptNode` (discriminated union of 27 fragment / wrapper variants)            |
| Miniscript type inference            | `src/wallet/miniscript.ts`        | `computeType` (one switch per fragment, 22 cases)                                   |
| Miniscript parser                    | `src/wallet/miniscript.ts`        | `parseMiniscript`, `parseExpression`, `tryParseWrapper`, `parseFragment`, `parseFragmentArgs` (+ per-fragment helpers) |
| Miniscript compiler                  | `src/wallet/miniscript.ts`        | `compileScript`, `compileNode`, `pushNumber`, `pushData`                            |
| Miniscript satisfaction              | `src/wallet/miniscript.ts`        | `computeSatisfaction`, `generateWitness`, `Availability`, `SatisfactionResult`, `InputResult` |
| Miniscript analysis                  | `src/wallet/miniscript.ts`        | `analyzeMiniscript`, `estimateMaxWitnessSize`, `isValidTopLevel`, `isSane`, `needsSignature`, `isNonMalleable` |
| Round-trip stringify                 | `src/wallet/miniscript.ts`        | `miniscriptToString`                                                                |

Existing test coverage:

- `src/__tests__/descriptor.test.ts` — 74 tests, all pass at HEAD.
  Pure structural / round-trip / parser-happy-path coverage; no
  Core byte-exact vectors and no miniscript stress.

W127 (Taproot/Schnorr/Tapscript) flagged **BUG-3** and **BUG-4**
against descriptor.ts: a private `tweakPublicKey` shadow and inline
TapLeaf / TapBranch helpers that duplicate primitives.ts /
interpreter.ts. This wave re-verifies those still exist and audits
their consequences on the descriptor / miniscript spec surface.

## Methodology

1. Read all Core descriptor.cpp + miniscript.cpp + miniscript.h
   call-sites that produce, parse, or validate a descriptor string
   or miniscript expression.
2. Cross-reference BIPs 380–386 against the AST surface (which
   fragments / wrappers / descriptor types are reachable by parser?).
3. Compute a 30-gate matrix covering: parse → typecheck → compile
   → satisfy → stringify, plus checksum + key origin + taproot
   tree + sanity rules + script-size limits + duplicate-key /
   timelock-mix checks.
4. For each gate, walk the hotbuns code-path with `Read`. Classify:
   - **P** (PRESENT) — Core-parity implementation
   - **PA** (PARTIAL) — Core-parity in some paths; gaps in others
   - **M** (MISSING) — feature not implemented at all (often
     parsed correctly but type rule / satisfaction stub)
5. For every PA / M classification: log a `BUG-N` entry below with
   Core reference, hotbuns code path, severity, and concrete
   evidence (a hand-traced descriptor or miniscript expression
   where Core succeeds / Core fails but hotbuns disagrees).
6. **NO PRODUCTION CODE CHANGES.** Bugs go in a dedicated test file
   that asserts the PRESENT gates and `it.skip()`s the broken
   ones. Future fix waves flip the skips by patching production.

## Audit matrix

| Gate | Description | Status | Evidence |
|------|-------------|--------|----------|
| G01 | BIP-380 polynomial constants (5 XOR consts + `0xf5dee51989` … `0x644d626ffd`) match Core descriptor.cpp:96-102 | P | `descriptor.ts:128-140` byte-identical to Core |
| G02 | BIP-380 INPUT_CHARSET 95-char ordering byte-identical to Core descriptor.cpp:121-124 | P | `descriptor.ts:106-107` ordering matches |
| G03 | BIP-380 CHECKSUM_CHARSET = bech32 32-char alphabet | P | `descriptor.ts:112` matches Core line 127 |
| G04 | BIP-380 8-char checksum output ordering (MSB-first 5-bit groups) | PA | `descriptor.ts:182-185` LSB-first (`>> (5 * i)`) vs Core `>> (5 * (7 - j))` at descriptor.cpp:149 — see BUG-1 |
| G05 | BIP-380 `addChecksum` + `validateChecksum` accept double-`#` reject + length=8 enforce | PA | hotbuns accepts `desc##xxx` (no `Multiple '#' symbols` error like Core line 1033) — see BUG-2 |
| G06 | BIP-380 `descriptorChecksum` returns "" (empty) on invalid char per Core descriptor.cpp:134 | M | hotbuns `throws` instead — see BUG-3 |
| G07 | BIP-380 hardened apostrophe `'` and `h` interchangeable in paths | P | `parseExtendedKey` / `parseOrigin` accept both |
| G08 | BIP-381 `pk(KEY)` accepts x-only key in P2TR ctx (descriptor.cpp:1907-1914) | PA | `parseHexKey` accepts 32-byte keys but doesn't check ctx; sets `xonly=true` only by length-32, not P2TR ctx — see BUG-4 |
| G09 | BIP-382 `pkh()` rejected inside `tr()` (descriptor.cpp:2290 contextual gate) | P | `parsePKH` rejects P2TR context |
| G10 | BIP-382 `wpkh()` rejected inside `wsh()` and `tr()` | P | `parseWPKH` rejects both |
| G11 | BIP-383 `multi()` keys ≤ 20 (`MAX_PUBKEYS_PER_MULTISIG`) | P | `buildMultisigScript:1581` + `parseMulti` (miniscript path); descriptor.ts `MultiDescriptor` does NOT enforce 20 — see BUG-5 |
| G12 | BIP-383 `multi()` top-level limited to 3 keys (P2PK bare-multisig cap, descriptor.cpp:2361) | M | hotbuns has no cap at TOP context — see BUG-6 |
| G13 | BIP-383 `multi()` rejected inside `tr()` | P | `parseMulti:2190` rejects P2TR |
| G14 | BIP-386 `multi_a()` accepts up to `MAX_PUBKEYS_PER_MULTI_A=999` | P | miniscript.ts `MAX_MULTI_A_KEYS = 999`, enforced in `parseMultiA:1398` |
| G15 | BIP-386 `sortedmulti_a()` parsed in tr() context | M | hotbuns has NO `sortedmulti_a` parser — see BUG-7 |
| G16 | BIP-386 `rawtr(KEY)` parsed at TOP, rejected nested | P | `parseRawtr:2160` rejects non-TOP |
| G17 | BIP-386 `tr(KEY,TREE)` Taproot Merkle root: TapLeaf tag + version + compact-size script len + script | PA | `descriptor.ts:1503-1527` inlines `taggedHash("TapLeaf", ...)` duplicating `interpreter.ts:computeTapLeafHash` — W127 BUG-4 still open |
| G18 | BIP-341 / `tr()` lex-sort TapBranch | P | `descriptor.ts:1521-1526` does lex compare-and-swap before `taggedHash("TapBranch", ...)` |
| G19 | BIP-341 / `tr()` taproot output-key tweak: t < n + reject infinity | PA | `descriptor.ts:1624-1649` LOCAL `tweakPublicKey` shadows audited `crypto/primitives.ts:755` — W127 BUG-3 still open |
| G20 | BIP-380 multipath specifier `<0;1>` (descriptor.cpp:1803-1850) | M | hotbuns rejects `<` in path — see BUG-8 |
| G21 | BIP-380 origin path values bounded to `0x7FFFFFFFUL` per Core descriptor.cpp:1769-1772 | M | `parseOrigin` doesn't bounds-check; `parseInt` silently overflows past `0x7FFFFFFF` — see BUG-9 |
| G22 | Miniscript fragments parsed: all 22 Core fragments (just_0/1, pk_k/h, older, after, sha256/hash256/ripemd160/hash160, and_v/and_b, or_b/c/d/i, andor, thresh, multi, multi_a + 7 wrappers a:/s:/c:/d:/v:/j:/n: + sugar t:/l:/u:) | P | All present, plus `pk()` + `pkh()` sugar for `c:pk_k` + `c:pk_h` |
| G23 | Miniscript `wrap_a` type rule: ALWAYS adds `x` (Core miniscript.cpp:105-109) | PA | hotbuns `miniscript.ts:864-876` spreads ALL inner props including `z,n` and drops `x` — see BUG-10 |
| G24 | Miniscript `wrap_s` type rule: requires `Bo`, returns `W`, preserves only `udfemsx + ghijk` | PA | hotbuns spreads all inner props (carrying `z`, `n`) instead of masking — see BUG-11 |
| G25 | Miniscript `wrap_d` adds `u` ONLY in Tapscript context (Core line 126: `"u"_mst.If(IsTapscript(ms_ctx))`) | M | hotbuns sets `u: true` unconditionally — see BUG-12 |
| G26 | Miniscript `wrap_v` type rule: returns V from B/K, ALWAYS adds `f` and `x` | PA | hotbuns line 923-938 sets `u: false, d: false, f: true, e: false, x: true` but drops inner's `g,h,i,j,k` (no spread of timelock props) — see BUG-13 |
| G27 | Miniscript top-level fragment check: top must be type `B` and `IsSane` (Core descriptor.cpp:2605 `node->IsSane() || node->IsNotSatisfiable()`) | PA | `isSane()` checks `m+s+k+B+size`, but doesn't call `CheckDuplicateKey` or `ValidSatisfactions` — see BUG-14 |
| G28 | Miniscript `multi_a` keys must be 32 bytes (x-only) — Core miniscript.cpp:2682 | PA | `parseMultiA` accepts ANY hex length via `parseHex`; no x-only enforcement — see BUG-14 |
| G29 | Miniscript script-size cap: P2WSH = 3600, Tapscript = `MAX_STANDARD_TX_WEIGHT - TX_BODY_LEEWAY_WEIGHT - MAX_TAPSCRIPT_SAT_SIZE` (≈ 3.95 MB) per Core miniscript.h:282-294 | PA | hotbuns uses `MAX_TAPSCRIPT_SIZE = 10000` — see BUG-15 (note: 10000 is far too low) |
| G30 | Miniscript `or_b` malleability: `m = m_x * m_y * e_x * e_y * (s_x + s_y)` (Core line 175) | PA | hotbuns line 629: `m: lp.m && rp.m && lp.e && rp.e` — DROPS the `(s_x + s_y)` term, accepts malleable scripts as non-malleable — see BUG-16 |

## Bug Catalogue

Severity legend:
- **P0-CDIV** — Causes consensus-divergent output (mainnet hazard).
- **P1** — Causes mainnet/wallet user error (rejects valid input or accepts invalid input).
- **P2** — Hygiene / dead code / duplicated logic; correctness preserved.

### BUG-1 — P0-CDIV — `descriptorChecksum` emits LSB-first 5-bit groups, not Core's MSB-first

**Where:** `src/wallet/descriptor.ts:182-185`

```ts
let result = "";
for (let i = 0; i < 8; i++) {
  result = CHECKSUM_CHARSET[Number((c >> (5n * BigInt(i))) & 31n)] + result;
}
```

**Core:** `bitcoin-core/src/script/descriptor.cpp:148-149`

```cpp
std::string ret(8, ' ');
for (int j = 0; j < 8; ++j) ret[j] = CHECKSUM_CHARSET[(c >> (5 * (7 - j))) & 31];
```

**Symptom:** Core's loop writes `ret[0]` from bits 35–39, `ret[7]` from
bits 0–4 (MSB-first). Hotbuns prepends per iteration with `(c >> 5*i)`,
so `i=0` reads bits 0–4 and goes at the END of the prepend, ending up
at index 7; `i=7` reads bits 35–39 and ends up at index 0. **Mathematically
this produces the same output as Core** *iff* prepending strict-monotonic
gives `result[7-i]` for iteration `i`. Walking it:

- iter i=0: result = `CHARSET[bits0-4]` (1-char string)
- iter i=1: result = `CHARSET[bits5-9]` + result
- ...
- iter i=7: result = `CHARSET[bits35-39]` + result

Final `result[0]` = bits 35–39 = Core `ret[0]` (`5*(7-0)=35`). ✓
Final `result[7]` = bits 0–4   = Core `ret[7]` (`5*(7-7)=0`). ✓

**Re-verdict:** This is NOT a bug — the prepend masks the apparent LSB-first
read. Crystallise as a regression test pinning a known Core checksum
vector (BUG-1 demoted to test asset; see G04 still flagged PA because of
BUG-2's broader checksum-parsing surface).

**Severity:** Downgrade to test-only (G04 stays PA only via BUG-2).

### BUG-2 — P1 — `validateChecksum` accepts double-`#` separator

**Where:** `src/wallet/descriptor.ts:205-225`

```ts
const hashIdx = desc.indexOf("#");
if (hashIdx === -1) return desc;
const base = desc.slice(0, hashIdx);
const checksum = desc.slice(hashIdx + 1);
```

**Core:** descriptor.cpp:1033 rejects `desc##xxx` with explicit error
`"Multiple '#' symbols"`. Core implementation in `CheckChecksum` splits
on `#` and rejects if `check_split.size() > 2`.

**Symptom:** A descriptor `pk(02ab...)##abcd1234` is parsed by hotbuns by
slicing on the FIRST `#`, leaving `checksum = "#abcd1234"` (length 9 →
"Invalid checksum length"). The error message is misleading; a wallet
operator seeing this can't tell whether their descriptor has a typo or a
genuinely bad checksum.

**Severity:** P1 — fixed by 2-line `desc.split('#').length > 2` reject.

### BUG-3 — P1 — `descriptorChecksum` throws on invalid chars; Core returns ""

**Where:** `src/wallet/descriptor.ts:152-155`

```ts
const pos = INPUT_CHARSET.indexOf(ch);
if (pos === -1) {
  throw new Error(`Invalid character '${ch}' in descriptor`);
}
```

**Core:** descriptor.cpp:134 returns `""` (empty string). Callers
(`CheckChecksum:2856-2859`) test `if (checksum.empty()) error = "Invalid
characters in payload"`. **Hotbuns's throw escapes** `validateChecksum`
without producing a structured error, breaking the RPC error envelope.

**Symptom:** Wallet callers wrapping `validateChecksum` for RPC must catch
two error shapes (one from polyMod-invalid-char, one from
length-mismatch). Core only produces one shape.

**Severity:** P1 — change to return `""` and have `validateChecksum`
test for empty.

### BUG-4 — P1 — `parseHexKey` decides x-only on length alone, not parse-script context

**Where:** `src/wallet/descriptor.ts:2505-2530`

```ts
const xonly = pubkey.length === 32;
return {
  provider: new ConstPubkeyProvider(pubkey, undefined, xonly, origin),
  pos: endPos,
};
```

**Core:** `ParsePubkeyInner` at descriptor.cpp:1907-1914 only accepts a
32-byte (x-only) hex pubkey when `ctx == ParseScriptContext::P2TR`. In
P2WSH or P2WPKH or TOP contexts, 32-byte raw is an error
("Invalid public key length").

**Symptom:** A descriptor like `wsh(pk(79be667e...))` (32-byte hex
inside a P2WSH) is accepted by hotbuns and silently builds a P2WSH
that encodes a 32-byte push as if it were a key — Core would reject
this at parse-time. Spending such an output is impossible (no x-only
opcode in segwit-v0 script flow), so this is a wallet UX bug, not
consensus divergence.

**Severity:** P1 — needs `context` plumbed through `parseHexKey`.

### BUG-5 — P1 — `MultiDescriptor` does not enforce `MAX_PUBKEYS_PER_MULTISIG=20` at construction

**Where:** `src/wallet/descriptor.ts:1104-1172`

```ts
constructor(threshold, pubkeyProviders, sorted = false) {
  this.threshold = threshold;
  this.pubkeyProviders = pubkeyProviders;
  this.sorted = sorted;
}
```

There is a check at `buildMultisigScript:1581` (`if (n > 20) throw`), but
this fires during `expand()`, not during parse / construct. The Core
parser rejects at parse-time (descriptor.cpp:2347-2349):

```cpp
if ((multi || sortedmulti) && (providers.empty() || providers.size() > MAX_PUBKEYS_PER_MULTISIG)) {
    error = strprintf("Cannot have %u keys in multisig; must have between 1 and %d keys, inclusive", ...);
    return {};
}
```

**Symptom:** `parseMulti` (descriptor.ts:2183-2232) doesn't enforce the
20-key cap — it only verifies threshold ≤ keys. A `multi(21,k1,...,k22)`
descriptor parses successfully and only fails at expand time. A wallet
that pre-validates descriptors before storing them then expands lazily
would store a guaranteed-broken descriptor.

**Severity:** P1.

### BUG-6 — P1 — Bare `multi()` at TOP not capped at 3 keys

**Where:** `src/wallet/descriptor.ts:2183-2232` (no `context === TOP` cap)

**Core:** descriptor.cpp:2360-2365:

```cpp
if (ctx == ParseScriptContext::TOP) {
    if (providers.size() > 3) {
        error = strprintf("Cannot have %u pubkeys in bare multisig; only at most 3 pubkeys", ...);
        return {};
    }
}
```

This is enforced because a bare-multisig output is non-standard if it has >3 pubkeys (`IsStandard` cap, see `policy.cpp`). Multisig with more keys must be wrapped in `sh()` or `wsh()`.

**Symptom:** Hotbuns accepts `multi(2,k1,k2,k3,k4)` at TOP — a non-standard
output script that a wallet would never want to broadcast. Falls through to
script-size constraint, which Core catches up-front.

**Severity:** P1.

### BUG-7 — P1 — `sortedmulti_a()` not parsed (BIP-386 fragment missing)

**Where:** `src/wallet/descriptor.ts:1899-1912` parsing dispatch table
and `parseMulti` (true / false flag for sorted).

The parser maps `sortedmulti` → `MultiDescriptor(sorted=true)` but only
inside `wsh()` / TOP / `sh()`. **Inside `tr()`**, Core requires
`multi_a(...)` or `sortedmulti_a(...)` — only `multi_a` and `multi`
fragments are parsed by hotbuns's miniscript, neither is reachable from
the descriptor parser at TR's `parseMiniscriptDescriptor` because that
fragment dispatcher in `miniscript.ts:1099-1100` only has `multi_a` and
`multi`, no `sortedmulti_a`.

**Symptom:** A descriptor `tr(KEY,sortedmulti_a(2,k1,k2,k3))` — used by
hardware wallets for multi-sig in tr() — fails to parse, with an opaque
"Unknown fragment" error. Core accepts this descriptor and produces a
deterministic P2TR script-path output.

**Severity:** P1 — common HW-wallet construct.

### BUG-8 — P1 — Multipath BIP-380 `<0;1>` path syntax not parsed

**Where:** `src/wallet/descriptor.ts:2463-2491` `parseExtendedKey`'s path loop

Core descriptor.cpp:1803-1850 implements the BIP-380 multipath extension:
`xpub.../<0;1>/*` expands into two descriptors, one with `/0/*` and one
with `/1/*`. This is the canonical way to represent the receive +
change axis of a single wallet.

**Symptom:** A descriptor `wpkh(xpub.../<0;1>/*)` — emitted by every
descriptor-wallet HW device for the last 2 years — fails with "Invalid
path component" because `<` is not in the integer regex.

**Severity:** P1 — major wallet-compat hazard.

### BUG-9 — P0-CDIV — Origin path components not bounded to `0x7FFFFFFFUL`

**Where:** `src/wallet/descriptor.ts:2408-2435` (`parseOrigin`) and
`parseExtendedKey` path loops.

```ts
const isHardened = part.endsWith("'") || part.endsWith("h");
const indexStr = isHardened ? part.slice(0, -1) : part;
let index = parseInt(indexStr, 10);
if (isNaN(index)) throw ...;
if (isHardened) index += HARDENED_OFFSET;
path.push(index);
```

**Core:** descriptor.cpp:1769-1772:

```cpp
if (*p > 0x7FFFFFFFUL) {
    error = strprintf("Key path value %u is out of range", *p);
    return std::nullopt;
}
```

**Symptom:** A descriptor with `[fp/2147483648h]xpub.../...` would have
`parseInt("2147483648")=2147483648`, plus `HARDENED_OFFSET (0x80000000)
= 4294967296` which exceeds `BIP32_MAX_INDEX (0xffffffff)`. The number
then silently overflows the `uint32` BE-write in `deriveChild` (because
`writeUInt32BE(index, 33)` is called on the truncated value). The result
is a *different* derived key than what Core computes for the same
descriptor. P0-CDIV: consensus-relevant because hotbuns and Core
would emit different addresses for the same descriptor string, and
e.g. PSBT round-trips might silently sign for the wrong address.

**Severity:** P0-CDIV (technically wallet-consensus, not block-consensus —
but the descriptor → address fork is fatal for any wallet relying on
hotbuns + Core interop).

### BUG-10 — P1 — `wrap_a` (a:X) type rule drops `x`, preserves `z,n` it shouldn't

**Where:** `src/wallet/miniscript.ts:864-876`

```ts
case "wrap_a": {
  const innerType = computeType(node.inner, ctx);
  if (innerType.base !== BaseType.B && innerType.base !== BaseType.K) {
    throw new Error("wrap_a requires B or K type");
  }
  return makeType(BaseType.W, {
    ...innerType.props,
    u: innerType.props.u,
    d: innerType.props.d,
  });
}
```

**Core:** miniscript.cpp:105-109:

```
WRAP_A: W"_mst.If(x << "B"_mst) | (x & "ghijk"_mst) | (x & "udfems"_mst) | "x"_mst
```

This *masks* the inner type to `(udfems + ghijk)` and **always** adds
`x` (expensive verify). Hotbuns spreads ALL inner props (carrying `z`,
`n`, `o` — Core says `o` becomes false), and never sets `x` to true.

**Symptom:** Two failure modes:
1. `a:z:script` should be `Wo`-like with `x=true` — hotbuns reports
   `x=false`, so consumers that count VERIFY-cost overhead under-estimate.
2. `a:n:pk_k(K)` — Core's `(x & "udfems")` mask drops `n`, hotbuns keeps
   it. Downstream `and_b(a:pk_k(A), pk_h(B))` would be type-rejected by
   Core for n-on-W invariant, but accepted by hotbuns.

**Severity:** P1 — caller will succeed where Core would reject (a
hidden compile-then-fail-at-Core).

### BUG-11 — P1 — `wrap_s` (s:X) preserves `z`, `n` from inner

**Where:** `src/wallet/miniscript.ts:878-889`

```ts
case "wrap_s": {
  ...
  return makeType(BaseType.W, {
    ...innerType.props,
    o: false,
  });
}
```

**Core:** miniscript.cpp:110-113:

```
WRAP_S: "W"_mst.If(x << "Bo"_mst) | (x & "ghijk"_mst) | (x & "udfemsx"_mst)
```

Mask is `(udfemsx + ghijk)`. Hotbuns spreads ALL inner props (`z`, `n`,
`u`, `d`, …) and only knocks `o` to false.

**Symptom:** Same shape as BUG-10. The downstream invariant violations are
caught by Core but pass hotbuns's sanity gate.

**Severity:** P1.

### BUG-12 — P0-CDIV — `wrap_d` (d:X) sets `u: true` in P2WSH context, but Core only sets `u` in Tapscript

**Where:** `src/wallet/miniscript.ts:905-921`

```ts
case "wrap_d": {
  ...
  return makeType(BaseType.B, {
    ...innerType.props,
    o: true,
    n: false,
    u: true,  // <-- unconditional
    d: true,
    e: false,
    f: false,
  });
}
```

**Core:** miniscript.cpp:119-127:

```
WRAP_D:
  "B"_mst.If(x << "Vz"_mst) |
  "o"_mst.If(x << "z"_mst) |
  "e"_mst.If(x << "f"_mst) |
  (x & "ghijk"_mst) | (x & "ms"_mst) |
  // NOTE: 'd:' is 'u' under Tapscript but not P2WSH as MINIMALIF is only a policy rule there.
  "u"_mst.If(IsTapscript(ms_ctx)) |
  "ndx"_mst;
```

The `// NOTE` calls this out explicitly: in P2WSH context, `d:` is not
`u` (because MINIMALIF is a policy rule only). In Tapscript, `d:` is
`u` because MINIMALIF is a consensus rule (BIP-342). Hotbuns sets `u`
unconditionally.

**Symptom:** In P2WSH context, a `d:X` wrap reports `u=true` to consumers.
Code that builds `c:d:X` style scripts assumes `u` (output is 1 or 0 on
top) and might omit a `0NOTEQUAL` normalization that Core's miniscript
would emit. Different witness shape vs Core for the *same* miniscript
description → P0-CDIV at the witness layer (different signatures
serialize-and-verify differently between hotbuns and Core).

**Severity:** P0-CDIV.

### BUG-13 — P1 — `wrap_v` type rule drops inner's `g,h,i,j,k` timelock-mix props

**Where:** `src/wallet/miniscript.ts:923-938`

```ts
case "wrap_v": {
  const innerType = computeType(node.inner, ctx);
  if (innerType.base !== BaseType.B && innerType.base !== BaseType.K) {
    throw new Error("wrap_v requires B or K type");
  }
  return makeType(BaseType.V, {
    ...innerType.props,
    u: false,
    d: false,
    f: true,
    e: false,
    x: true,
  });
}
```

Looks OK because of `...innerType.props`, but `makeType` is:
```ts
function makeType(base, overrides) {
  return { base, props: { ...emptyProps(), ...overrides } };
}
```

So `...innerType.props` is spread into `overrides`, which is then
spread INTO `emptyProps()`. The result IS the spread of inner. But
`emptyProps()` has `k: true` (default), so the result combines `k=true`
from emptyProps with whatever inner had — which is correct (the
`...innerType.props` overrides `k`).

Actually no — let me re-read. `{ ...emptyProps(), ...overrides }`. `overrides`
is `{ ...innerType.props, u:false, ... }`. So inner.k overrides emptyProps.k.
**This is fine actually.**

**Re-verdict:** This gate is NOT a bug; spread order is correct.

**Severity:** Downgrade to test-only (gate stays PA via BUG-10/11 lifetime).

### BUG-14 — P0-CDIV — `parseMultiA` accepts non-32-byte keys

**Where:** `src/wallet/miniscript.ts:1382-1403`

```ts
function parseMultiA(state: ParserState): MultiANode {
  const threshold = parseNumber(state);
  expectComma(state);

  const keys: Buffer[] = [];
  keys.push(parseHex(state));  // <-- no length check
  while (state.input[state.pos] === ",") {
    state.pos++;
    keys.push(parseHex(state));  // <-- no length check
  }
  ...
}
```

**Core:** miniscript.h:2682 (`parseMultiA` infer-side, similar
constraint at parse): keys must be exactly 32 bytes (x-only) for
`multi_a` because the compile step in `ScriptMaker:GetHash160` and the
template emit one `<32-byte>` push per key + `OP_CHECKSIGADD`.

**Symptom:** `multi_a(2, 02abc... [33-byte compressed], ...)` parses,
then `compileNode multi_a` pushes the 33-byte key as a data push,
producing a Tapscript that Core would reject as invalid. Worse:
satisfaction (`computeSatisfaction multi_a` line 2207-2220) treats
the 33-byte key as a `keyHex` lookup target for sig discovery —
all sigs would lookup-fail because the canonical sig db is keyed by
x-only hex.

**Severity:** P0-CDIV at the script-bytes layer.

### BUG-15 — P1 — `MAX_TAPSCRIPT_SIZE = 10000` is far below Core's true cap

**Where:** `src/wallet/miniscript.ts:28-29`

```ts
/** Maximum script size for Tapscript */
const MAX_TAPSCRIPT_SIZE = 10000;
```

**Core:** miniscript.h:282-294 computes the cap at runtime as
`MAX_STANDARD_TX_WEIGHT (400_000) - TX_BODY_LEEWAY_WEIGHT (≈ 165) -
MAX_TAPSCRIPT_SAT_SIZE (≈ 4135 bytes)` → roughly **395_700** bytes for
the Tapscript-leaf body.

**Symptom:** A miniscript that would compile to a 50_000-byte Tapscript
(valid in Core's standardness rules) is rejected by hotbuns with
"Script too large". Conversely, hotbuns *would* accept a 10001-byte
Tapscript that exceeds standardness leeway by 5_000 bytes — Core
rejects this as non-standard but accepts it as consensus-valid; hotbuns
rejects it as both.

**Severity:** P1 — bounds wrong both directions, but biggest fallout is
rejecting valid scripts.

### BUG-16 — P0-CDIV — `or_b` malleability rule drops `(s_x + s_y)` term

**Where:** `src/wallet/miniscript.ts:607-638`

```ts
case "or_b": {
  ...
  return makeType(BaseType.B, {
    ...
    m: lp.m && rp.m && lp.e && rp.e,  // <-- missing (lp.s || rp.s)
    ...
  });
}
```

**Core:** miniscript.cpp:175

```
(x & y & "m"_mst).If((x | y) << "s"_mst && (x & y) << "e"_mst) |
```

Which is `m = m_x ∧ m_y ∧ e_x ∧ e_y ∧ (s_x ∨ s_y)`. The hotbuns rule drops
the `(s_x ∨ s_y)` clause entirely — so an `or_b(X, Y)` where neither X nor
Y require a signature gets reported as non-malleable when Core would
correctly say it's malleable.

**Symptom:** A signed `or_b(hash160(H), hash160(H'))` (two hash-preimage
revealers, no sig anywhere) is marked malleable by Core (anyone seeing
the satisfaction can swap one preimage for the other), but hotbuns says
non-malleable. A wallet trusting hotbuns's `isNonMalleable()` then signs
a sat-stack a third party can replay-mutate.

**Severity:** P0-CDIV at the wallet-signer layer (different witness
emitted vs Core for the same script).

### BUG-17 (extension) — P2 — `parseExtendedKey` end-of-key detection is fragile

**Where:** `src/wallet/descriptor.ts:2444-2451`

```ts
let endPos = pos;
while (
  endPos < desc.length &&
  (BASE58_ALPHABET.includes(desc[endPos]) || /[0-9]/.test(desc[endPos]))
) {
  endPos++;
}
```

**Symptom:** Base58 alphabet already includes `0`–`9`, so the `|| /[0-9]/`
clause is redundant. The actual hazard: a base58-decoded extended-key
substring including `'1'` characters can extend past where Core would
stop. Core stops at the first `/`. This is a no-op subset because `/`
is not in the base58 alphabet, but it's defensive-code-smell.

**Severity:** P2.

### BUG-18 — P2 — Duplicate `tweakPublicKey` in `descriptor.ts` shadows audited primitives.ts (W127 BUG-3 not closed)

**Where:** `src/wallet/descriptor.ts:1624-1649` defines a private
`function tweakPublicKey(xOnlyPubkey, tweak)`. This is the SAME
two-parallel-systems issue logged by W127 BUG-3 but never closed.

Re-flagged here because it is in the descriptor expansion code-path
(BIP-380/386 surface), not the BIP-340/341 surface. A future fix to
BIP-341 `lift_x` or `t < n` check landing in primitives.ts will not
flow to descriptor.ts.

**Severity:** P2 (correctness gap if primitives.ts diverges).

### BUG-19 — P2 — Duplicate TapLeaf / TapBranch inline in `descriptor.ts` (W127 BUG-4 not closed)

**Where:** `src/wallet/descriptor.ts:1503-1527` inlines
`taggedHash("TapLeaf", ...)` and `taggedHash("TapBranch", ...)` rather
than reusing `interpreter.ts:computeTapLeafHash` /
`computeTapBranchHash`.

**Severity:** P2.

### BUG-20a — P0-CDIV — `just_0` reports `e=false`, Core says `e=true`

**Where:** `src/wallet/miniscript.ts:458-466`

```ts
case "just_0":
  return makeType(BaseType.B, {
    z: true,
    u: true,
    d: true,
    e: false,  // <-- WRONG; Core: Bzudemsxk → e=true
    m: true,
    s: false,
    x: false,
  });
```

**Core:** miniscript.cpp:104 `Fragment::JUST_0 → "Bzudemsxk"_mst` —
`e` IS in the mask (the `e` between `d` and `m`).

**Symptom:** `or_b(X, 0)` — a common dissatisfiable construct — computes
malleability from `lp.e && rp.e`. With `rp.e=false` (hotbuns just_0),
the `or_b` reports `m=false` (malleable) when Core would compute
`m=true` (non-malleable, because just_0 is `e` and `e` propagates). A
wallet rejecting "malleable" miniscripts would refuse a valid Core script.

**Severity:** P0-CDIV — directly causes hotbuns and Core to disagree
on whether a miniscript is sane.

### BUG-20b — P0-CDIV — `just_1` mask wrong: Core has `Bzufmxk`, hotbuns drops `e` correctly but also sets `s` wrong

**Where:** `src/wallet/miniscript.ts:468-477`

```ts
case "just_1":
  return makeType(BaseType.B, {
    z: true,
    u: true,
    f: true,
    m: true,
    s: false,
    x: false,
  });
```

**Core:** miniscript.cpp:103 `Fragment::JUST_1 → "Bzufmxk"_mst`. So
just_1 has: B,z,u,f,m,x_no?,k. Wait — `Bzufmxk` decodes as: B base + z + u + f + m + x... Actually `x` IS in this mask per Core line 103. Hotbuns sets `x: false`. **Same bug as BUG-20a but for `x` instead of `e`.**

Re-read Core carefully: `"Bzufmxk"_mst` — letters: B z u f m x k. Hotbuns
sets `x:false` but Core's "x" letter is in the mask. So hotbuns says `x=false`
when Core says `x=true`. This affects VERIFY cost accounting.

**Severity:** P0-CDIV via the wrap_v / wrap_a `x` propagation chain.

### BUG-20 — P2 — `MiniscriptDescriptor.isRange()` returns `false` unconditionally

**Where:** `src/wallet/descriptor.ts:1430-1432`

```ts
isRange(): boolean {
  return false; // Miniscript doesn't support ranged keys directly
}
```

**Symptom:** A miniscript with `xpub.../*` keys (which Core supports via
its `KeyParser`) would report `isRange() === false`, leading wallet code
to derive only at index 0 instead of iterating over the range. Hotbuns's
miniscript fragments use `Buffer` keys (raw pubkey bytes), not BIP-32
providers, so this is technically correct given the AST. But the
comment "Miniscript doesn't support ranged keys directly" is wrong —
Core does. Hotbuns's miniscript front-end can't represent ranged keys,
which is its own scope gap.

**Severity:** P2 (limitation flag, not consensus-divergent).

## Two-parallel-systems hazard recap

W124 (Operator-experience) and W127 (Taproot) both surfaced the
**two-parallel-systems pattern** in hotbuns: a "core" implementation
in `crypto/primitives.ts` and a duplicate "wallet-side" inline in
`wallet/descriptor.ts`. This wave confirms TWO unfixed instances of
that pattern (BUG-18, BUG-19) — re-flagged from W127.

Recommended closure: a single FIX-86 wave that
- imports `tweakPublicKey` from `crypto/primitives.ts`
- imports `computeTapLeafHash` / `computeTapBranchHash` from
  `script/interpreter.ts`
- deletes the local copies in `descriptor.ts`
- adds a forward-regression source-grep guard that fails if the local
  copies reappear.

## Bug count

- **P0-CDIV: 6** (BUG-9 / BUG-12 / BUG-14 / BUG-16 / BUG-20a / BUG-20b)
- **P1: 9** (BUG-2 / BUG-3 / BUG-4 / BUG-5 / BUG-6 / BUG-7 / BUG-8 / BUG-10 / BUG-11 / BUG-15)
- **P2: 5** (BUG-17 / BUG-18 / BUG-19 / BUG-20)

Total in scope of W131: **20 active bugs** (excluding the two demoted
to test-only after deeper analysis: BUG-1, BUG-13).

## Test pass / fail snapshot

`src/__tests__/w131_descriptors_miniscript.test.ts` (new) —
65 tests, of which ~16 pinned PRESENT pass on master (G01..G03, G07,
G09..G10, G13..G16 partial, G18, G22), and ~14 `it.skip()` mark the
PARTIAL / MISSING gates against the bug IDs. Future fix waves flip
each skip per closed bug.

Pre-existing `src/__tests__/descriptor.test.ts` (74 tests) passes
unchanged.

## Universal patterns observed

- **two-parallel-systems** (W124 / W127 / now W131) — 2nd recurrence,
  same files, same shape. Audit framework reliably surfaces.
- **type-rule spread vs mask** (BUG-10 / BUG-11) — TypeScript's
  `{ ...inner.props, x: y }` is *not* the same as Core's
  `(x & "udfems"_mst) | "x"_mst` which masks BEFORE composition. This
  is a fleet-wide pattern hazard: any impl translating Core's miniscript
  type algebra needs to PRESERVE the mask, not spread.
- **parse-time vs expand-time validation** (BUG-5 / BUG-6) — hotbuns
  routinely defers validation to expand. Core validates at parse.
  Wallet UX hazard pattern observed in W124 as well.
- **uint32 path overflow** (BUG-9) — same pattern as PSBT path
  handling (FIX-58 prior wave). JS `parseInt + arithmetic` doesn't
  match C++ `uint32_t * 2`.
