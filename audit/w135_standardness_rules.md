# W135 — Standardness rules (IsStandardTx) — hotbuns

**Scope:** Bitcoin Core's transaction-standardness layer, the set of policy
gates a tx must pass to be admitted to a Core mempool / relayed to peers
(but not the consensus gates that decide validity in a block). Specifically:

- `bitcoin-core/src/policy/policy.{h,cpp}` — `IsStandardTx`,
  `IsStandard` (scriptPubKey solver wrapper), `IsWitnessStandard`,
  `ValidateInputsStandardness`, `GetDust`, `GetDustThreshold`,
  the script-verify-flag bundles (`MANDATORY_SCRIPT_VERIFY_FLAGS`,
  `STANDARD_SCRIPT_VERIFY_FLAGS`).
- `bitcoin-core/src/script/solver.{h,cpp}` — the `Solver()` /
  `TxoutType` classification used by `IsStandard`.
- `bitcoin-core/src/policy/truc_policy.{h,cpp}` — TRUC (v3) per-tx
  shape constraints reachable from `IsStandardTx` via the version
  range and the v3 weight/ancestor checks.
- `bitcoin-core/src/consensus/tx_check.cpp` — `CheckTransaction`
  consensus skeleton (referenced for reasons that re-appear on the
  standardness path, e.g. `bad-txns-oversize`).
- `bitcoin-core/src/policy/ephemeral_policy.{h,cpp}` — adjacent
  `PreCheckEphemeralTx` / `CheckEphemeralSpends`; these are NOT part
  of `IsStandardTx` proper but they share `GetDust` / dust-relay-fee
  state and are routinely conflated with the dust gate.

**Out of scope:** RBF rules (W120, W130), package-relay TRUC rules
beyond per-tx (W120), feebumper (W130), descriptors / Miniscript (W131),
nSequence/CSV/MTP (W132), index databases (W133), BIP-152 compact-block
shape (W126), BIP-158 codec (W121/W122). We touch script-verify-flag
bundles here only because `STANDARD_SCRIPT_VERIFY_FLAGS` is referenced
by `IsStandardTx` callers — the full per-flag opcode coverage is a
separate concern.

**Hotbuns refs:**

- `src/mempool/mempool.ts`:
  - Constants: `TX_MIN_STANDARD_VERSION` / `TX_MAX_STANDARD_VERSION`
    (lines 100-110), `MIN_STANDARD_TX_NONWITNESS_SIZE` (117),
    `MAX_STANDARD_SCRIPTSIG_SIZE` (123), `MAX_OP_RETURN_RELAY` (130),
    `MAX_STANDARD_P2WSH_*` (141-153), `MAX_STANDARD_TAPSCRIPT_*` (159),
    `MAX_STANDARD_TX_SIGOPS_COST` (182), `MAX_P2SH_SIGOPS` (210),
    `MAX_DUST_OUTPUTS_PER_TX` (94), `TRUC_*` (508-516),
    `MAX_STANDARD_TX_WEIGHT` (540), `DUST_RELAY_FEE` (88).
  - Helpers: `evalPushOnlyScriptSig` (224-274), `isWitnessStandard`
    (296-406), `validateInputsStandardness` (430-477),
    `getDustThreshold` (703-732), `isDust` (737), `getDustOutputs`
    (752-761), `preCheckEphemeralTx` (789-814), `checkEphemeralSpends`
    (837+).
  - `IsStandardTx` body (in-band): `addTransaction()` block at
    lines 1365-1485 (version + weight + non-witness size + scriptSig
    + per-output spk gates), and downstream gates at 1657-1680
    (sigops-cost), 1698-1702 (dust-fee), 1985-2007
    (`validateInputsStandardness` + `isWitnessStandard`), 2019-2023
    (`checkEphemeralSpends`), 2772+ (TRUC v3).
- `src/script/interpreter.ts`:
  - `getScriptType` (2107-2128) — the `Solver()` analogue.
  - `getBareMultisigParams` (1958-1988) — multisig validator.
  - `isP2A` (2008-2016), `isWitnessProgram` (2134-2144),
    `isPushOnly` (858+), `isP2PK` (1939-1946),
    `isP2PKH` / `isP2SH` / `isP2WPKH` / `isP2WSH` / `isP2TR`.
  - `getConsensusFlags` (3021-3036) and `getStandardFlags`
    (3083-3092) — the flag bundles.
  - `TxoutType` enum (2037-2048).

**Methodology:** Read Core refs end-to-end, then bucket hotbuns code
against a 30-gate matrix. Each gate has a status — **PASS** (Core-
parity), **BUG-N** (deviation classified P0/P1/P2/P3), or **N/A**
(Core feature deliberately out of hotbuns scope).

> **HEADLINE.** Hotbuns's `IsStandardTx` body is structured and
> behaves correctly for the version/weight/scriptSig/script-type
> trunk, but it deviates from Core on five distinct axes:
> (1) the dust-output cap (`GetDust(tx).size() > 1`) is enforced
> only via `preCheckEphemeralTx` and only when the tx ALSO has a
> non-zero fee — Core's `IsStandardTx` checks the dust-cap
> unconditionally (BUG-1);
> (2) `getStandardFlags` returns only 4 of the 10 policy-only
> `STANDARD_SCRIPT_VERIFY_FLAGS` extras — MINIMALDATA, MINIMALIF,
> CLEANSTACK, CONST_SCRIPTCODE, and all four DISCOURAGE_* upgradeable
> flags are absent (BUG-9, P1);
> (3) the `permit_bare_multisig` knob does not exist anywhere
> — bare multisig n>3 is always rejected, bare multisig n∈[1,3] is
> always accepted, no operator switch (BUG-3);
> (4) `getDustThreshold` mis-computes the segwit input-vsize
> contribution: hotbuns uses `26n` for sig/4 instead of Core's
> `107/4 == 26` truncation that also includes the +4 sequence —
> bottom line the constant `inputSize = 67` from Core comes out as
> `67n` for non-witness but the segwit branch evaluates
> `(32+4+1+26+4) = 67` and skips the `IsUnspendable` short-circuit
> for non-OP_RETURN unspendables (BUG-7 + BUG-8);
> (5) `MAX_OP_RETURN_RELAY` is hard-coded `100_000` instead of
> being computed from `MAX_STANDARD_TX_WEIGHT / WITNESS_SCALE_FACTOR`,
> so the co-binding to weight is lost if either constant ever drifts
> (BUG-19, P3).
>
> In addition: TRUC v3 is wired into the mempool path BUT not
> reflected in the v3 portion of the `IsStandardTx` boundary —
> `IsStandardTx` itself only enforces `version ∈ [1,3]`; the v3
> weight cap (`TRUC_MAX_VSIZE`) is in `checkTRUCPolicy` further
> down the pipeline. This matches Core (Core's `IsStandardTx`
> also defers to `SingleTRUCChecks`), so we mark this PASS,
> but it produces a subtle BUG-2 on ordering described below.

---

## Audit matrix (30 gates)

Gate IDs use the prefix `W135-G##`. BUG severity: **P0** =
consensus/wire-divergent, **P1** = correctness-bearing for users
(relay diverges, RPC rejects when Core would accept or vice-versa),
**P2** = operator-experience / footgun, **P3** = cosmetic but
Core-divergent.

| Gate | Subject | Status |
|------|---------|--------|
| G01 | `IsStandardTx`: `tx.version ∈ [TX_MIN, TX_MAX]` (1..3) | PASS |
| G02 | `IsStandardTx`: weight ≤ `MAX_STANDARD_TX_WEIGHT` (400 000 WU) | PASS |
| G03 | `IsStandardTx`: non-witness size ≥ `MIN_STANDARD_TX_NONWITNESS_SIZE` (65 B) | PASS |
| G04 | `IsStandardTx`: per-input scriptSig ≤ `MAX_STANDARD_SCRIPTSIG_SIZE` (1650 B) | PASS |
| G05 | `IsStandardTx`: per-input scriptSig `IsPushOnly()` | PASS |
| G06 | `IsStandardTx`: per-output `IsStandard(scriptPubKey)` rejects `NONSTANDARD` | PASS |
| G07 | `IsStandardTx`: per-output rejects `WITNESS_UNKNOWN` (v2-v16) | PASS |
| G08 | `IsStandardTx`: bare multisig `MULTISIG` requires `n ∈ [1,3]`, `m ∈ [1,n]` | PASS |
| G09 | `IsStandardTx`: `permit_bare_multisig` knob (default `true`, operator-tunable) | **BUG-3** P2 |
| G10 | `IsStandardTx`: NULL_DATA cumulative carrier-byte budget | PASS |
| G11 | `IsStandardTx`: NULL_DATA budget tracker (`datacarrier_bytes_left -= size`) decrement, NOT cumulative add | **BUG-4** P3 |
| G12 | `IsStandardTx`: `max_datacarrier_bytes` operator knob (Core `std::optional<unsigned>`, sentinel = disable carrier) | **BUG-5** P2 |
| G13 | `IsStandardTx`: dust-cap gate `GetDust(tx).size() > MAX_DUST_OUTPUTS_PER_TX` runs unconditionally | **BUG-1** P1 |
| G14 | `IsStandardTx` reason codes EXACTLY = Core ("version", "tx-size", "tx-size-small", "scriptsig-size", "scriptsig-not-pushonly", "scriptpubkey", "bare-multisig", "datacarrier", "dust") | **BUG-6** P3 |
| G15 | `IsWitnessStandard`: 6 gates (P2A reject / P2SH evalSig / non-witness w/ witness / P2WSH limits / P2TR limits / coinbase exempt) | PASS |
| G16 | `ValidateInputsStandardness`: `nonstandard` + `witness_unknown` + P2SH redeem-sigops ≤ 15 | PASS |
| G17 | `ValidateInputsStandardness`: BIP-54 non-witness sigops ≤ `MAX_TX_LEGACY_SIGOPS` (2500) per tx | **BUG-2** P0 |
| G18 | `GetDustThreshold`: `IsUnspendable()` short-circuit returns 0 for non-OP_RETURN unspendables too | **BUG-7** P2 |
| G19 | `GetDustThreshold`: segwit branch uses `+ (32+4+1+(107/4)+4)` = +67 (integer truncation) | **BUG-8** P3 |
| G20 | `MAX_OP_RETURN_RELAY` derived from `MAX_STANDARD_TX_WEIGHT / WITNESS_SCALE_FACTOR` (not magic-numbered) | **BUG-19** P3 |
| G21 | `STANDARD_SCRIPT_VERIFY_FLAGS` includes all 10 policy-only flags (MINIMALDATA, CLEANSTACK, MINIMALIF, NULLFAIL, LOW_S, STRICTENC, WITNESS_PUBKEYTYPE, CONST_SCRIPTCODE, DISCOURAGE_*×4) | **BUG-9** P1 |
| G22 | `MANDATORY_SCRIPT_VERIFY_FLAGS` set: P2SH, DERSIG, NULLDUMMY, CLTV, CSV, WITNESS, TAPROOT | PASS |
| G23 | `Solver()` returns `ANCHOR` for P2A; `getScriptType` returns `"anchor"` (NOT P2TR) and ordering is correct (P2A before P2TR) | PASS |
| G24 | `Solver()` accepts uncompressed 65-byte P2PK pubkeys | PASS |
| G25 | `Solver()` MULTISIG: `m`/`n` must be minimally-encoded (Core's `GetScriptNumber` via `CheckMinimalPush`) | **BUG-10** P3 |
| G26 | `IsStandardTx` ordering matches Core: version → tx-size → per-input → per-output → dust | **BUG-1** P1 (dust missing entirely) |
| G27 | `IsStandardTx` runs BEFORE `ValidateInputsStandardness` / `IsWitnessStandard` (Core ATMP order) | PASS |
| G28 | `TX_MIN/MAX_STANDARD_VERSION` import path = `policy.h` (not `validation.cpp`) — comment ref accuracy | **BUG-11** P3 |
| G29 | `IsStandardTx` coinbase-exempt path: a coinbase tx is REJECTED before `IsStandardTx` (mempool refuses coinbase) | PASS |
| G30 | `getStandardFlags(height)` uses BIP-66 height for STRICTENC / LOW_S (mempool gate uses ACTIVE, not consensus-only) | PASS |

**Total: 11 BUGs / 30 gates** (19 PASS).

Severity breakdown: **P0** = 1 (BUG-2, BIP-54 missing).
**P1** = 3 (BUG-1, BUG-9, plus BUG-3 sometimes-P1 depending on relay
fleet posture). **P2** = 3 (BUG-5, BUG-7, BUG-12 omitted as a P2
under-count — see Cross-cutting). **P3** = 5 (BUG-4, BUG-6, BUG-8,
BUG-10, BUG-11, BUG-19).

---

## Bug detail

### BUG-1 P1 — `IsStandardTx` does NOT enforce the dust-cap unconditionally

**Core** `policy.cpp:158-162`:

```cpp
// Only MAX_DUST_OUTPUTS_PER_TX dust is permitted(on otherwise valid ephemeral dust)
if (GetDust(tx, dust_relay_fee).size() > MAX_DUST_OUTPUTS_PER_TX) {
    reason = "dust";
    return false;
}
```

Core runs this gate as part of `IsStandardTx` itself, the LAST step
of the function, with reason string `"dust"`. The gate fires
whenever a tx has more than one (`MAX_DUST_OUTPUTS_PER_TX = 1`)
dust output, regardless of fee.

**Hotbuns** `mempool.ts:1431-1485` (the `IsStandardTx` block) does
NOT include this gate. The closest analogue is
`preCheckEphemeralTx(tx, fee)` at line 1698, which checks the dust
cap ONLY when `fee !== 0n`:

```ts
// 8a. PreCheckEphemeralTx: a tx with dust outputs must have 0 fee...
const ephemeralPreCheck = preCheckEphemeralTx(tx, fee);
if (!ephemeralPreCheck.valid) {
  return { accepted: false, error: ephemeralPreCheck.error };
}
```

and `preCheckEphemeralTx` at 789-814:

```ts
if (fee !== 0n) {
  return { valid: false, error: "tx with dust output must be 0-fee" };
}
if (dustOutputs.length > MAX_DUST_OUTPUTS_PER_TX) {
  return { valid: false, error: `too many dust outputs: ${dustOutputs.length} > ${MAX_DUST_OUTPUTS_PER_TX}` };
}
```

The `MAX_DUST_OUTPUTS_PER_TX` check is reached only when `fee === 0`.
Consequence: a tx with 2 dust outputs AND a non-zero fee is rejected
by Core for reason `"dust"` (`IsStandardTx` line 159), but is rejected
by hotbuns for reason `"tx with dust output must be 0-fee"`
(`preCheckEphemeralTx` line 801). The decision is the same (REJECT
in both), but the reason string and the policy gate that fired differ.

**More important:** Core's `PreCheckEphemeralTx` (policy/ephemeral_policy.cpp:23-31)
runs only for txs with ephemeral (0-value) dust outputs — its
ASSUMPTION is that the dust-cap was already enforced earlier in
`IsStandardTx`. In hotbuns these are conflated: `preCheckEphemeralTx`
is doing BOTH jobs, and it does the wrong one when fee > 0 with 2+ dust.

Fix: add a gate at the end of the `IsStandardTx` block (after the
per-output loop, line ~1484) that mirrors Core's
`GetDust(tx).size() > MAX_DUST_OUTPUTS_PER_TX`, emitting reason
`"dust"`. Move the 0-fee assertion into `preCheckEphemeralTx`
strictly (its current pre-existing role).

Severity P1 because:
- relay decisions diverge from Core on the reason code (which RPC
  callers and log scrapers pin on),
- a tx with multiple dust outputs AND positive fee gets the wrong
  rejection,
- this is a Core-default gate, no operator override.

### BUG-2 P0 — `ValidateInputsStandardness` does NOT enforce BIP-54 non-witness sigops cap

**Core** `policy.cpp:170-194` adds a `CheckSigopsBIP54()` helper:

```cpp
static bool CheckSigopsBIP54(const CTransaction& tx, const CCoinsViewCache& inputs)
{
    Assert(!tx.IsCoinBase());

    unsigned int sigops{0};
    for (const auto& txin: tx.vin) {
        const auto& prev_txo{inputs.AccessCoin(txin.prevout).out};
        sigops += txin.scriptSig.GetSigOpCount(/*fAccurate=*/true);
        sigops += prev_txo.scriptPubKey.GetSigOpCount(txin.scriptSig);
        if (sigops > MAX_TX_LEGACY_SIGOPS) {
            return false;
        }
    }
    return true;
}
```

and calls it from `ValidateInputsStandardness` at policy.cpp:221-224:

```cpp
if (!CheckSigopsBIP54(tx, mapInputs)) {
    state.Invalid(TxValidationResult::TX_INPUTS_NOT_STANDARD,
                  "bad-txns-nonstandard-inputs",
                  "non-witness sigops exceed bip54 limit");
    return state;
}
```

This bounds the per-tx legacy + P2SH-redeem sigop count at
`MAX_TX_LEGACY_SIGOPS = 2500` (policy.h:46). BIP-54 ratifies this
as a future consensus rule, currently enforced as policy.

**Hotbuns** `mempool.ts:430-477` (`validateInputsStandardness`) walks
each input, checks `nonstandard` / `witness_unknown` / P2SH-redeem
sigops ≤ 15, but does NOT accumulate per-tx legacy sigops against
`MAX_TX_LEGACY_SIGOPS = 2500`. There is no
`MAX_TX_LEGACY_SIGOPS` constant in `mempool.ts` at all — `grep`
for it returns no hits.

Consequence: a tx with 30 P2SH inputs each carrying a redeemScript
with 14 sigops (under the per-input cap of 15) totals 420 P2SH
sigops, well under 2500. But a real attacker can produce a tx with
many large legacy scriptSigs whose accurate sigop count individually
sums above 2500 yet each below 15. Core rejects; hotbuns admits.

Severity P0 because:
- BIP-54 is on the path to becoming consensus,
- hotbuns admits txs that Core rejects, so a hotbuns-mined block
  could contain a tx that Core nodes will (eventually) reject,
- the cap is independent of every other sigop gate hotbuns enforces
  (`MAX_STANDARD_TX_SIGOPS_COST = 16_000` is a weighted-sigops cap,
  not the legacy-only cap), so the BIP-54 gate is genuinely absent
  not just renamed.

Fix: implement `checkSigopsBIP54(tx, inputUtxos)` mirroring the Core
helper, add `MAX_TX_LEGACY_SIGOPS = 2500` constant, call from
`validateInputsStandardness` before the per-input loop.

### BUG-3 P2 — `permit_bare_multisig` knob does not exist

**Core** `policy.cpp:152-155`:

```cpp
} else if ((whichType == TxoutType::MULTISIG) && (!permit_bare_multisig)) {
    reason = "bare-multisig";
    return false;
}
```

with `DEFAULT_PERMIT_BAREMULTISIG = true` (policy.h:52). Operators
can launch with `-permitbaremultisig=0` to reject ALL bare multisig
outputs, not just `n > 3`.

**Hotbuns** has no `permit_bare_multisig` / `permitBaremultisig`
variable, no CLI flag, no Mempool constructor knob. Bare multisig
with `n ∈ [1,3]` is always accepted; bare multisig with `n > 3` is
always rejected. The default behavior matches Core's default, but
the operator switch is absent.

Severity P2 because:
- a node operator who runs Core with `-permitbaremultisig=0` cannot
  reproduce that posture on hotbuns,
- relay fleet behavior is identical to Core defaults, so DoS / spam
  posture is identical by default,
- this is a known operator-controlled knob (Bitcoin Core release
  notes have changed the default; hotbuns inherits no knob to
  follow whatever default Core lands on next).

Fix: add `Mempool` constructor option `permitBareMultisig?: boolean`
(default `true`), thread through to the per-output gate, emit reason
`"bare-multisig"` (not `"scriptpubkey: ... bare multisig exceeds
x-of-3 standard limit"`) when the gate fires due to the flag.

### BUG-4 P3 — NULL_DATA budget tracked as cumulative add, not Core's decrement

**Core** `policy.cpp:137,146-151`:

```cpp
unsigned int datacarrier_bytes_left = max_datacarrier_bytes.value_or(0);
...
if (whichType == TxoutType::NULL_DATA) {
    unsigned int size = txout.scriptPubKey.size();
    if (size > datacarrier_bytes_left) {
        reason = "datacarrier";
        return false;
    }
    datacarrier_bytes_left -= size;
}
```

Core models the budget as a remaining-bytes counter that starts at
`max_datacarrier_bytes.value_or(0)` and decrements per nulldata
output. Critically, if `max_datacarrier_bytes` is `std::nullopt`
(operator-disabled), `value_or(0)` makes the budget 0, and ANY
nulldata output of size > 0 is rejected.

**Hotbuns** `mempool.ts:1442,1473-1483`:

```ts
let datacarrierBytesUsed = 0;
...
if (scriptType === "nulldata") {
  datacarrierBytesUsed += spk.length;
  if (datacarrierBytesUsed > MAX_OP_RETURN_RELAY) {
    return { accepted: false, error: `datacarrier: cumulative OP_RETURN data ${datacarrierBytesUsed} > ${MAX_OP_RETURN_RELAY} bytes` };
  }
}
```

Same outcome for the default case (no operator knob, budget always
`MAX_OP_RETURN_RELAY = 100_000`), but the structure can't represent
the "carrier disabled" state (which Core does via
`max_datacarrier_bytes = std::nullopt → 0`). The single-output
boundary is also different: Core would accept a tx with one
nulldata of exactly `100_000` bytes; hotbuns accepts the same.
Core rejects a tx with two nulldata outputs summing 100_001 bytes;
hotbuns rejects the same. Boundary parity holds — this is purely
the model shape.

Severity P3 cosmetic but Core-divergent. Tied to BUG-12 below
(no operator knob to disable carrier).

Fix: change `datacarrierBytesUsed: number` to
`datacarrierBytesLeft: number = MAX_OP_RETURN_RELAY` and decrement
in the per-output check. Sets up BUG-12 fix cleanly.

### BUG-5 P2 — `-datacarrier` / `-datacarriersize` operator knobs absent

**Core** `policy.h:80-84`:

```cpp
static const bool DEFAULT_ACCEPT_DATACARRIER = true;
static const unsigned int MAX_OP_RETURN_RELAY = MAX_STANDARD_TX_WEIGHT / WITNESS_SCALE_FACTOR;
```

`IsStandardTx` is called by `MemPoolAccept` with `max_datacarrier_bytes`
sourced from `m_opts.max_datacarrier_bytes`. Operators set
`-datacarrier=0` to disable carrier acceptance (sentinel: pass
`std::nullopt` to `IsStandardTx`, budget = 0), or
`-datacarriersize=N` to set the per-tx ceiling.

**Hotbuns** has no `acceptDatacarrier` / `maxDatacarrierBytes` /
`-datacarrier` / `-datacarriersize` CLI flag. The budget is the
hard-coded constant `100_000` always.

Severity P2 (operator footgun; identical to BUG-3 reasoning).

### BUG-6 P3 — `IsStandardTx` reason codes diverge from Core canonical strings

**Core** uses these exact reason strings (`policy.cpp`):
- `"version"`
- `"tx-size"`
- `"scriptsig-size"`
- `"scriptsig-not-pushonly"`
- `"scriptpubkey"`
- `"datacarrier"`
- `"bare-multisig"` (when `permit_bare_multisig = false`)
- `"dust"` (the GetDust-cap gate, BUG-1)

`validation.cpp` adds `"tx-size-small"` (the 65-byte gate).

**Hotbuns** produces:
- `"version: tx version 0 out of standard range [1,3]"` (extra
  formatting + lead context — Core is bare `"version"`),
- `"tx-size: weight 400001 exceeds standard limit 400000"` (extra),
- `"tx-size-small: non-witness size 61 < 65 bytes"` (extra),
- `"scriptsig-size: input 0 scriptSig 1651 > 1650 bytes"` (extra),
- `"scriptsig-not-pushonly: input 0 scriptSig contains non-push opcodes"` (extra),
- `"scriptpubkey: output 0 uses non-standard script type"` (extra),
- `"scriptpubkey: output 0 uses undefined witness program version"` (this
  is the `witness_unknown` case — Core also says `"scriptpubkey"` but with
  no qualifier),
- `"scriptpubkey: output 0 bare multisig exceeds x-of-3 standard limit"`
  (Core says `"bare-multisig"` ONLY when the `permit_bare_multisig=false`
  knob is set — and uses `"scriptpubkey"` only for the `IsStandard`-fail
  case where `n > 3 → return false` propagates back to `IsStandardTx`
  as the `if (!::IsStandard(...))` branch with reason `"scriptpubkey"`.
  Hotbuns picks `"scriptpubkey"` correctly but the trailing free-text
  is divergent.),
- `"datacarrier: cumulative OP_RETURN data 100001 > 100000 bytes"`
  (Core is bare `"datacarrier"`).

The diff is purely the prefix-then-detail framing. RPC callers that
parse reason strings for the exact Core token will fail.

Severity P3 cosmetic but RPC-observable. `sendrawtransaction`'s
error JSON would surface these strings; an RPC client doing
`reason == "tx-size"` would not match.

Fix: emit the EXACT Core reason as the first colon-separated token,
keep detail after a `:` separator (already the pattern). Update
existing `IsStandardTx` tests to match.

### BUG-7 P2 — `getDustThreshold` does NOT short-circuit non-OP_RETURN unspendables

**Core** `policy.cpp:43-44`:

```cpp
if (txout.scriptPubKey.IsUnspendable())
    return 0;
```

Core's `IsUnspendable()` (script.h) returns true if:
1. the script starts with `OP_RETURN`, OR
2. the script size is greater than 10000 bytes (`MAX_SCRIPT_SIZE`).

So a 10001-byte garbage scriptPubKey is unspendable AND treated as
dust-threshold-zero.

**Hotbuns** `mempool.ts:703-707`:

```ts
export function getDustThreshold(scriptPubKey: Buffer): bigint {
  // OP_RETURN is unspendable, dust threshold is 0
  if (scriptPubKey.length > 0 && scriptPubKey[0] === 0x6a) {
    return 0n;
  }
  ...
}
```

Only the `OP_RETURN` case short-circuits. A scriptPubKey > 10000
bytes (`MAX_SCRIPT_SIZE`) is computed through the
"is this segwit?" branch — which will return `false` (segwit
requires length 2 + pushlen, pushlen ≤ 40) — and fall through to
the non-segwit branch, returning `(scriptLen + 1 + 8 + 148) *
3000 / 1000` satoshis. For a 10001-byte script this is
`10158 * 3 = 30474` sats, which is non-zero. Hotbuns considers
the output dust if its value is below 30474; Core considers it
NOT dust (threshold = 0, never below 0).

Consequence: hotbuns rejects (or flags as ephemeral-dust) outputs
that Core admits. The output is consensus-invalid for a different
reason (oversize scriptPubKey), but the dust gate disagrees on
the relay decision.

Severity P2 because the scriptPubKey > 10000 path is itself
nonstandard via the per-output `IsStandard()` check (G06 — would
be classified as `nonstandard` since none of the standard types
match length-wise), so the tx is rejected for `"scriptpubkey"`
before the dust gate fires. The bug is reachable only via a
direct call to `getDustThreshold()` from outside the
`addTransaction` pipeline (RPC `gettxout` consumers, wallet
coin-selection feasibility, etc.).

Fix: add the second `IsUnspendable` clause (size > 10000) to the
short-circuit at line 705. Alternatively (cleaner) call a shared
`isUnspendable(spk)` helper.

### BUG-8 P3 — `getDustThreshold` non-segwit branch off-by-one against Core

**Core** `policy.cpp:55-61`:

```cpp
if (txout.scriptPubKey.IsWitnessProgram(witnessversion, witnessprogram)) {
    // 75% segwit discount applied to the script size.
    nSize += (32 + 4 + 1 + (107 / WITNESS_SCALE_FACTOR) + 4);
} else {
    nSize += (32 + 4 + 1 + 107 + 4); // the 148 mentioned above
}
return dustRelayFeeIn.GetFee(nSize);
```

For segwit: `32 + 4 + 1 + (107/4) + 4 = 32 + 4 + 1 + 26 + 4 = 67`
(integer truncation: 107/4 = 26). For non-segwit: 148.

**Hotbuns** `mempool.ts:715-731`:

```ts
if (isWitness) {
  const outputSize = BigInt(scriptPubKey.length + 8 + 1);
  const inputSize = 32n + 4n + 1n + 26n + 4n;  // = 67
  return ((outputSize + inputSize) * BigInt(DUST_RELAY_FEE)) / 1000n;
} else {
  const outputSize = BigInt(scriptPubKey.length + 8 + 1);
  const inputSize = 32n + 4n + 1n + 107n + 4n; // = 148
  return ((outputSize + inputSize) * BigInt(DUST_RELAY_FEE)) / 1000n;
}
```

Hotbuns computes `inputSize` correctly (67 segwit, 148
non-segwit), so the segwit branch matches Core. **However:** the
comment on lines 720-721 says `(107/4)` and `26n` — the `26n` is
right because Core's integer truncation gives 26, not 26.75. The
comment then says `26n; // prevout + vout + scriptLen + sig/4 +
sequence` which is misleading because Core's expansion is
`32 + 4 + 1 + (107/4) + 4`, where the `+ 1` is `scriptLen` (1 byte)
and the `+ 4` at the end is `sequence`. Hotbuns writes
`32n + 4n + 1n + 26n + 4n` — the `1n` is scriptLen, the `26n` is
`107/4` (the sig discount), the trailing `4n` is sequence. Same
arithmetic, mis-labelled comment. Not a behavior bug; tagging as
P3 doc-fidelity.

The actual subtle Core deviation: Core uses `GetSerializeSize(txout)`
to derive `nSize` (the value+scriptLen+script triple), which is
`8 + GetSizeOfCompactSize(script.size()) + script.size()`. Hotbuns
uses `script.length + 8 + 1` — fixed compact-size of 1 byte. For
scripts > 252 bytes the compact-size grows to 3 (varint encoding),
so hotbuns under-counts `outputSize` by 2 for the script-size range
[253, 65535] and by 4 for [65536, ...). This shifts the dust
threshold for unusually large scriptPubKeys downward — by a fee
amount of `2 * 3000 / 1000 = 6 sats` for a >252-byte script. A
547-sat output at a 250-byte spk would be dust under Core but
admitted by hotbuns when the spk grows to 253 bytes (one extra
varint byte in serialization).

In practice the standard script types (P2PKH 25 / P2SH 23 / P2WPKH
22 / P2WSH 34 / P2TR 34 / P2A 4) are all ≤ 34 bytes, so the
compact-size is 1 in every case relevant to standardness — the bug
is unreachable on a Core-standard scriptPubKey. P3.

Fix: replace `+ 8 + 1` with a `GetSerializeSize(txout)` analogue
that handles varint scriptLen.

### BUG-9 P1 — `getStandardFlags` misses 6 of 10 `STANDARD_SCRIPT_VERIFY_FLAGS` extras

**Core** `policy.h:119-132`:

```cpp
static constexpr script_verify_flags STANDARD_SCRIPT_VERIFY_FLAGS{
    MANDATORY_SCRIPT_VERIFY_FLAGS |
    SCRIPT_VERIFY_STRICTENC |
    SCRIPT_VERIFY_MINIMALDATA |
    SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS |
    SCRIPT_VERIFY_CLEANSTACK |
    SCRIPT_VERIFY_MINIMALIF |
    SCRIPT_VERIFY_NULLFAIL |
    SCRIPT_VERIFY_LOW_S |
    SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM |
    SCRIPT_VERIFY_WITNESS_PUBKEYTYPE |
    SCRIPT_VERIFY_CONST_SCRIPTCODE |
    SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION |
    SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS |
    SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_PUBKEYTYPE};
```

That's `MANDATORY` (7 flags) + 10 policy-only extras.

**Hotbuns** `interpreter.ts:3083-3092`:

```ts
export function getStandardFlags(height: number): ScriptFlags {
  const flags = getConsensusFlags(height);
  return {
    ...flags,
    verifyNullFail: height >= 481824,          // policy: BIP 146
    verifyWitnessPubkeyType: height >= 481824, // policy: BIP 141 standardness
    verifyStrictEncoding: height >= 363725,    // policy: BIP 66 standardness
    verifyLowS: height >= 363725,              // policy: BIP 62 rule 5
  };
}
```

Only 4 policy extras (NULLFAIL, WITNESS_PUBKEYTYPE, STRICTENC,
LOW_S). **Missing:**
- `verifyMinimalData` (BIP-62 rule 3) — pushes must use minimal
  encoding,
- `verifyMinimalIf` (BIP-141 policy for witness v0; consensus for
  tapscript) — OP_IF/NOTIF stack-top must be 0/1,
- `verifyCleanStack` (BIP-62 rule 6) — stack must have exactly one
  element after execution,
- `verifyDiscourageUpgradableNops` — unknown NOPs (NOP1..NOP10
  except NOP2/3) must error in policy,
- `verifyDiscourageUpgradableWitnessProgram` — unknown witness
  versions (v2-v16) must error in policy,
- `verifyDiscourageUpgradableTaprootVersion` — unknown taproot leaf
  versions must error in policy,
- `verifyDiscourageOpSuccess` — `OP_SUCCESSx` opcodes in tapscript
  must error in policy,
- `verifyDiscourageUpgradablePubkeyType` — unknown tapscript pubkey
  types must error in policy.
- `verifyConstScriptCode` — `OP_CODESEPARATOR` + `FindAndDelete`
  combinations must error in policy (no symbol exists in hotbuns).

The `ScriptFlags` interface (interpreter.ts:245-253) HAS fields for
all of these — the gap is `getStandardFlags` not setting them.

Consequence: a tx whose scriptSig pushes `01` (one byte 0x01) via
`OP_PUSHBYTES_1 0x01` instead of the minimal `OP_1` opcode would
be rejected by Core's relay (MINIMALDATA) but admitted by hotbuns.
Same for sub-optimal pushes in general. Similarly, a tapscript
spending a leaf version other than 0xc0 would be admitted to
hotbuns's mempool (no discouraged-version check) and forwarded.

Severity P1 because:
- relay diverges from Core for any tx that exercises one of the
  missing flags (and these are common in practice — wallet
  bugs / handcrafted txs / experimental script paths),
- a hotbuns peer relaying a non-MINIMALDATA tx to a Core peer would
  see that peer reject the relay, breaking transitive propagation,
- this is a long-standing standardness invariant; hotbuns has been
  shipping it incomplete since the policy-flag introduction.

Fix: extend `getStandardFlags` with the 6 missing booleans at the
height of their respective BIP activations (MINIMALDATA at 363725
since it's bundled with BIP-66; CLEANSTACK / MINIMALIF / DISCOURAGE
flags from their respective BIP heights; DISCOURAGE_OP_SUCCESS and
DISCOURAGE_UPGRADABLE_PUBKEYTYPE / TAPROOT_VERSION from 709632).
Then audit the interpreter's existing dispatch to confirm each
flag is actually consulted (the field exists, but the dispatch
site may also be missing).

### BUG-10 P3 — bare-multisig `m`/`n` not minimally-encoded per Core's `GetScriptNumber`

**Core** `solver.cpp:66-83` (`GetScriptNumber`) requires both the
`m` push and the `n` push to be minimally-encoded if they arrive
as a `PUSHDATA` (rather than `OP_1`..`OP_16`):

```cpp
static std::optional<int> GetScriptNumber(opcodetype opcode, valtype data, int min, int max)
{
    if (IsSmallInteger(opcode)) { count = CScript::DecodeOP_N(opcode); }
    else if (IsPushdataOp(opcode)) {
        if (!CheckMinimalPush(data, opcode)) return {};
        ...
        count = CScriptNum(data, /* fRequireMinimal = */ true).getint();
    }
    ...
}
```

So a multisig script using `OP_PUSHBYTES_1 0x02` for `n=2` is
NONSTANDARD (Core rejects via `MULTISIG → MatchMultisig → return
false`).

**Hotbuns** `interpreter.ts:1958-1988` only accepts `OP_1..OP_16`
encoded `m`/`n`:

```ts
const nOpcode = script[script.length - 2];
if (nOpcode < 0x51 || nOpcode > 0x60) return null;
const n = nOpcode - 0x50;
const mOpcode = script[0];
if (mOpcode < 0x51 || mOpcode > 0x60) return null;
const m = mOpcode - 0x50;
```

That means hotbuns _also_ rejects non-minimal pushes (Core's
gate is "must accept OP_n OR must be minimal-encoded push", but
hotbuns's gate is "must be OP_n exactly"). For `n ∈ [1,16]` and
`m ∈ [1,16]` the OP_n encoding IS the minimal one, so the rejection
parity holds. For `n = 17..20` (`MAX_PUBKEYS_PER_MULTISIG`), Core
accepts a minimal push `OP_PUSHBYTES_1 0x11..0x14`; hotbuns rejects.

But the standard policy IsStandard cap is `n ≤ 3` (G08), so this
divergence is unreachable from a STANDARD multisig. Bare multisig
with `n ∈ [4..20]` would be `IsStandard = false` and would be
rejected for `"scriptpubkey"` anyway. Hotbuns gets the standardness
decision right.

The divergence matters only if `getBareMultisigParams` is called
from a non-IsStandard context (Solver, address classification, etc.).
Grep shows the only consumer is `getScriptType` for the multisig
type-tag and the per-output gate at mempool.ts:1464 — both
boundary-checking against `n > 3`, so practical impact is zero.

Severity P3 cosmetic but Core-divergent at the `Solver()` boundary.

Fix: extend `getBareMultisigParams` to accept push-form `m`/`n`
encodings 0x01..0x14 (per Core's `GetScriptNumber`), and add a
minimal-push check (`CheckMinimalPush` analogue) for those.

### BUG-11 P3 — `MIN_STANDARD_TX_NONWITNESS_SIZE` comment cites `validation.cpp`

**Core** declares `MIN_STANDARD_TX_NONWITNESS_SIZE` in `policy.h:40`
(line 39-40):

```cpp
/** The minimum non-witness size for transactions we're willing to relay/mine: one larger than 64 */
static constexpr unsigned int MIN_STANDARD_TX_NONWITNESS_SIZE{65};
```

It is also USED in `validation.cpp` (the call site), but the
constant's DEFINITION is in `policy.h`.

**Hotbuns** `mempool.ts:113-117`:

```ts
/**
 * Minimum non-witness serialized size for a standard transaction (65 bytes).
 * Mitigates CVE-2017-12842 (64-byte transaction / merkle-branch confusion).
 * Bitcoin Core: validation.cpp MIN_STANDARD_TX_NONWITNESS_SIZE = 65.
 */
export const MIN_STANDARD_TX_NONWITNESS_SIZE = 65;
```

The comment says `validation.cpp` — wrong source file. Should be
`policy.h:40`. Pure doc-fidelity bug.

Severity P3.

Fix: update comment to `policy.h:40`.

### BUG-19 P3 — `MAX_OP_RETURN_RELAY` magic-numbered, not derived from `MAX_STANDARD_TX_WEIGHT`

**Core** `policy.h:84`:

```cpp
static const unsigned int MAX_OP_RETURN_RELAY = MAX_STANDARD_TX_WEIGHT / WITNESS_SCALE_FACTOR;
```

The two constants are co-bound: a tx that exceeds the datacarrier
budget is by construction at-or-near the standard weight cap. If
either constant ever moves, the other automatically follows.

**Hotbuns** `mempool.ts:127-130`:

```ts
export const MAX_OP_RETURN_RELAY = 100_000;
```

Hard-coded literal. The comment correctly notes the derivation, but
the value is independent of `MAX_STANDARD_TX_WEIGHT`. If a future
hotbuns change bumps `MAX_STANDARD_TX_WEIGHT` to e.g. 800 000 (Core
hypothesis under BIP-339-style proposals), `MAX_OP_RETURN_RELAY`
would stay at 100 000 unless the maintainer remembers to update both.

Severity P3 footgun-bait but currently no observed divergence.

Fix:

```ts
export const MAX_OP_RETURN_RELAY = Number(MAX_STANDARD_TX_WEIGHT) / WITNESS_SCALE_FACTOR;
```

(Beware the bigint/number boundary: `MAX_STANDARD_TX_WEIGHT` is a
bigint per the existing comment "Stored as a bigint because the
rest of hotbuns's serialization layer uses bigints for 64-bit
values"; the conversion to `number` is safe for any value ≤ 2^53.)

---

## Cross-cutting / meta observations

### Reason-code consistency

All 11 bugs taken together: 6 are about Core parity at the
**reason-code / error-string boundary** (BUG-1, BUG-4, BUG-5,
BUG-6, BUG-11, BUG-19). This is consistent with the W125 RPC
error parity wave's findings — hotbuns formats reason strings
with leading-context-then-detail framing while Core uses bare
canonical tokens. RPC consumers that pattern-match the Core
canonical strings (which BIP-152 / Bitcoin Core release notes /
mining template tooling all do) will mis-fire.

### Standardness vs consensus boundary

BUG-2 (BIP-54) is the only **P0** in this wave. It is the only
gate where hotbuns admits a tx that Core rejects (rather than the
other direction). All other bugs either match the decision
(reason diff only) or hotbuns rejects more strictly than Core
(BUG-3 always-reject n>3 means hotbuns matches default Core; but
under `-permitbaremultisig=0` Core rejects MORE strictly than
hotbuns, which hotbuns has no way to express). The classic
"divergent admittance" risk is BUG-2 only.

### Operator-knob gap

BUG-3 and BUG-5 share a structural pattern: hotbuns has Core's
DEFAULT behavior right but has not implemented the OPERATOR KNOB
that lets a relay diverge from default. This is consistent with
W124 (operator experience) — hotbuns is "Core-default-only" by
shape. A future wave should systematically enumerate every
`policy.h` knob (`-permitbaremultisig`, `-datacarrier`,
`-datacarriersize`, `-bytespersigop`, `-minrelaytxfee`,
`-incrementalrelayfee`, `-dustrelayfee`, `-mempoolexpiry`,
`-mempoolfullrbf`, `-limitancestorcount`, ...) and audit the
coverage. The narrow standardness wave here flags two; the
full sweep is W124-class.

### `IsStandardTx` shape correctness

The **good news:** hotbuns's `IsStandardTx`-equivalent
(the `addTransaction` block 1365-1485) preserves Core's GATE ORDER
correctly through the dust-cap-missing gap. The version-then-weight-
then-size-then-scriptSig-then-output structure mirrors `policy.cpp:
102-156` line-for-line. Adding the dust-cap gate (BUG-1 fix) is a
single ~5-line addition at the end of the block, no structural
rework.

### Test coverage

Existing tests `isstandard_gates.test.ts` (W71, 26 tests) and
`iswitness_standard_gates.test.ts` (W72, 26 tests) cover gates
G01..G08, G10 (default budget), G15..G16. They DO NOT cover:
G13 (BUG-1 dust-cap), G17 (BUG-2 BIP-54), G09 (BUG-3 permit_bare),
G18 (BUG-7 IsUnspendable cap), G21 (BUG-9 script-verify-flag
extras). The W135 test file adds gates targeting all 11 BUGs.

### Comparison with other impls (informational)

Per W118 wallet audit context, hotbuns's mempool layer is more
mature than its wallet layer. The W135 findings are mostly
**already correct shape with last-mile gaps**, not foundational
absence. That's a different profile from e.g. W117 (BIP-155
addrv2) where the helper functions themselves were absent fleet-wide.

---

## Suggested fix sequence

If the user wants a follow-on FIX wave:

1. **FIX-A (P0 BUG-2)** — wire BIP-54 sigops cap (`checkSigopsBIP54`
   in `validateInputsStandardness`). ~30 LOC, one new constant,
   one helper, 3 tests.

2. **FIX-B (P1 BUG-1 + BUG-9 bundle)** — add the dust-cap gate at
   the end of the `IsStandardTx` block (reason `"dust"`), AND
   extend `getStandardFlags` with the 6 missing policy flags
   (MINIMALDATA / MINIMALIF / CLEANSTACK / DISCOURAGE_*×4 /
   CONST_SCRIPTCODE — verify each is dispatched in the interpreter
   before claiming the fix is effective). ~80 LOC. **Must use
   `verify-fix.sh`** — dispatch sites for the discourage flags
   may already be dead code, in which case the test will pass
   pre- and post-fix and the fix will be NO-OP.

3. **FIX-C (P2 BUG-3 + BUG-5)** — operator-knob bundle:
   `permitBareMultisig` and `acceptDatacarrier` /
   `maxDatacarrierBytes` constructor options on `Mempool`, CLI
   wiring optional (can defer to W124 ops audit). ~50 LOC.

4. **FIX-D (P3 cosmetic bundle)** — BUG-4 + BUG-6 + BUG-7 + BUG-8 +
   BUG-10 + BUG-11 + BUG-19. Pure surface fixes, single PR.
   ~40 LOC.

Total scope ~200 LOC of changes for full Core parity on the
standardness boundary.
