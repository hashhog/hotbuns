# W130 — BIP-125 feebumper Rule 3 audit (hotbuns)

**Impl:** hotbuns (TypeScript / Bun)
**Date:** 2026-05-17
**Status:** DISCOVERY — 24 BUGS / 30 gates (4 PRESENT / 6 PARTIAL / 20 MISSING)
**Tests:** `src/__tests__/w130_bip125_feebumper_rule3.test.ts` (assertion-only, no
production code changes)
**No production code changes in this wave.**

## Reference

- `bitcoin-core/src/wallet/feebumper.cpp` — `CreateRateBumpTransaction`,
  `PreconditionChecks`, `CheckFeeRate`, `EstimateFeeRate`,
  `CommitTransaction`, `SignTransaction`, `SignatureWeights`.
- `bitcoin-core/src/wallet/feebumper.h` — `feebumper::Result` enum,
  `SignatureWeightChecker`, `WALLET_INCREMENTAL_RELAY_FEE` defaults.
- `bitcoin-core/src/policy/rbf.cpp` + `policy/rbf.h` — `PaysForRBF`
  (Rule #3 + Rule #4), `IsRBFOptIn`, `SignalsOptInRBF`,
  `EntriesAndTxidsDisjoint`, `GetEntriesForConflicts`,
  `ImprovesFeerateDiagram`, `MAX_REPLACEMENT_CANDIDATES = 100`.
- `bitcoin-core/src/policy/feerate.cpp` + `policy/feerate.h` —
  `CFeeRate::GetFee(int32_t virtual_bytes)` integer math (sat/kvB ×
  vsize ÷ 1000 with `EvaluateFeeUp` rounding up to the nearest sat).
- `bitcoin-core/src/validation.cpp` — context for ATMP / RBF integration.
- BIP-125 — opt-in full-replace-by-fee signaling and the five rules.

## Background — Core's bumpfee architecture

Core's `feebumper::CreateRateBumpTransaction` in
`wallet/feebumper.cpp:159-328` is the canonical entry point for both
`bumpfee` and `psbtbumpfee` RPCs. The two RPCs share **the entire body**
of this function; the only difference is at the RPC layer
(`wallet/rpc/spend.cpp`), where `psbtbumpfee` strips signatures
post-build and returns a base64 PSBT.

The function performs the following operations, in order:

1. **`PreconditionChecks` (feebumper.cpp:23-57)** — five gates:
   - `HasWalletSpend(wtx.tx)` — refuse if the tx has any wallet
     descendants (wallet can't bump a tx that has been spent by
     another wallet tx).
   - `wallet.chain().hasDescendantsInMempool(wtx.GetHash())` —
     refuse if the tx has any mempool descendants (would orphan them).
   - `wallet.GetTxDepthInMainChain(wtx) != 0` — refuse if confirmed
     (or conflicted with a confirmed tx).
   - `wtx.mapValue.contains("replaced_by_txid")` — refuse if already
     bumped (prevents the "bump A→A2 and A→A3" double-spend
     scenario per BIP-125's "wallet rule").
   - If `require_mine`: `AllInputsMine(wallet, *wtx.tx)` — every
     input must be funded by a UTXO the wallet has the key for.

2. **Coin selection (feebumper.cpp:188-231)** — Loads every input's
   `Coin` via `wallet.chain().findCoins(coins)`. For external inputs
   (not `wallet.IsMine`), computes the maximum signature weight via
   `SignatureWeights / SignatureWeightChecker`
   (feebumper.h:75-122), since signature sizes vary by up to 1 byte
   per ECDSA signature and the bump fee must cover the worst case.

3. **`CheckFeeRate` (feebumper.cpp:60-117)** — six gates on the
   replacement feerate:
   - `newFeerate < mempoolMinFee` → reject (Rule #4 prerequisite).
   - `wallet.chain().calculateCombinedBumpFee(reused_inputs,
     newFeerate)` returns `nullopt` → reject (unconfirmed-ancestor
     cluster too large).
   - **The Rule 3 precise invariant:**
     `new_total_fee = newFeerate.GetFee(maxTxSize) +
     combined_bump_fee.value()`
     and `minTotalFee = old_fee + incrementalRelayFee.GetFee(maxTxSize)`
     `new_total_fee < minTotalFee` → reject.
   - `new_total_fee < GetRequiredFee(wallet, maxTxSize)` → reject.
   - `new_total_fee > m_default_max_tx_fee` → reject (default
     `DEFAULT_TRANSACTION_MAXFEE = 0.1 BTC = 10_000_000 sat`).

4. **`EstimateFeeRate` (feebumper.cpp:119-144)** — if the caller did
   NOT supply a `coin_control.m_feerate`, Core estimates one:
   `feerate = oldFee/oldVsize + 1 sat/vB`,
   then `feerate += max(node_incremental_relay_fee,
   wallet_incremental_relay_fee)`, where the wallet const is
   `WALLET_INCREMENTAL_RELAY_FEE = 5000 sat/kvB = 5 sat/vB`,
   then `feerate = max(feerate, GetMinimumFeeRate)`.

5. **Per-input preservation (feebumper.cpp:299-308)** — Core
   `Select()`s every original input into `coin_control` (BIP-125
   wallet rule comment block at lines 300-305: "very important for
   wallets to make sure that happens" — prevents A→A2,A→A3 double-pay).
   Critically also sets `m_allow_other_inputs = true` so coin
   selection can pull in additional UTXOs to cover the fee delta,
   and `m_min_depth = 1` so it can only pull confirmed coins
   (BIP-125 Rule 2).

6. **`CreateTransaction` (feebumper.cpp:314-318)** — runs the
   full coin-selection pipeline (BnB → Knapsack → SRD → CoinGrinder,
   per W129). The replacement may have **different inputs and
   different outputs** than the original.

7. **`CommitTransaction` (feebumper.cpp:350-382)** —
   - Re-runs `PreconditionChecks(require_mine=false)` (anti-TOCTOU
     guard: another wallet tx might have just spent the original's
     output, or the original might have been mined while the bump was
     being built).
   - Sets `mapValue["replaces_txid"] = oldWtx.GetHash().ToString()`
     on the replacement.
   - Calls `wallet.CommitTransaction()` to write the replacement and
     submit it to the mempool.
   - Calls `wallet.MarkReplaced(oldWtx.GetHash(), bumped_txid)` which
     sets `mapValue["replaced_by_txid"]` on the original — this is
     the *exact field* checked in `PreconditionChecks` to prevent
     bump-A-twice.

## Hotbuns architecture

Hotbuns's `Wallet.bumpFee` lives in `src/wallet/wallet.ts:1179-1306`
and `Wallet.psbtBumpFee` at `src/wallet/wallet.ts:1325-1372`. The
implementation is intentionally minimal — pre-W118 it didn't exist at
all (W118 G19/G20 expected MISSING), and FIX-61 added it as a
**signed-tx-in / signed-tx-out** shape with the following pipeline:

1. Look up the original tx in `this.outgoingTxs.Map<txid, OutgoingTx>`
   (populated only by `createTransaction()` — does NOT cover txs
   loaded from disk on wallet reload, or external txs the wallet is
   merely watching).

2. Check `out.confirmed` (which is only set by `processBlock` when
   the tx appears in a connected block — there is no
   `hasDescendantsInMempool` or `HasWalletSpend` check).

3. Check `out.tx.inputs.some(i => i.sequence < 0xfffffffe)` (BIP-125
   signaling).

4. Check `this.keys.has(u.address)` for every input
   (`AllInputsMine`).

5. Reject if `out.changeIndex < 0` (no change output to reduce).

6. Compute `oldVSize = 10 + 68 * inputs + 31 * outputs` (fixed
   estimate; assumes every input is P2WPKH-shaped).

7. `targetRate = newFeeRate ?? oldFeeRate + 1` — the *fallback*
   path adds 1 sat/vB regardless of `incrementalRelayFee`.

8. Reject if `targetRate <= oldFeeRate`.

9. Compute `newFee = ceil(oldVSize * targetRate)`. Reject if
   `newFee <= out.fee`.

10. Reduce the change output by `feeDelta = newFee - out.fee`.
    Reject if `newChange <= 546n` (dust).

11. Build new inputs preserving sequence (forced to `0xfffffffd` if
    the original was `>= 0xfffffffe`, even though step 3 would have
    already rejected that case — dead branch).

12. Re-sign every input via `signInput()`.

13. Insert the replacement into `outgoingTxs` (so it can be chained).

`Wallet.psbtBumpFee` (lines 1325-1372) builds on `bumpFee` by
calling it and then stripping signatures, but with the wrinkle that
it has to **delete** the newly-inserted `outgoingTxs` entry to
prevent the wallet from offering to chain-bump an unsigned PSBT.

The RPC layer at `src/rpc/server.ts:7663-7733` (`bumpfee`) and
`7747-7813` (`psbtbumpfee`) is a thin wrapper that maps wallet errors
to `WALLET_ERROR` and broadcasts the signed replacement via
`sendRawTransaction`. No `replaceable`, `conf_target`, `estimate_mode`,
`outputs`, or `original_change_index` parameter is honored (only
`fee_rate`).

The minimum-fee enforcement in hotbuns is split between the wallet
(implicit Rule 3 via `targetRate > oldFeeRate`) and the mempool RBF
gate (`src/mempool/mempool.ts:1866-1882`), which enforces the
absolute-fee Rule 3 (`fee < totalConflictingFee`) and the
incremental Rule 4 (`additionalFee < ceil(incrementalRelayFee * vsize)`)
using a `number` (float) `incrementalRelayFee` per
`src/mempool/mempool.ts:1157,1224` (default 0.1 sat/vB).

## Audit summary

Total: **24 BUGS / 30 gates** in four priority bands.

- **P0-CDIV (correctness divergence)** — 5 bugs (G3, G5, G9, G11, G16).
  Behaviour differs from Core in a way that yields a different fee,
  rejects a valid bump, or accepts an invalid one on identical input.
- **P1-API (missing parameter / behaviour)** — 13 bugs (G6, G7, G8,
  G10, G12, G13, G14, G15, G18, G20, G21, G22, G24, G26).
  Core honours an input parameter or surface that hotbuns silently
  ignores or hard-codes.
- **P1-WIRE (wrong shape across the call surface)** — 4 bugs (G4,
  G19, G27, G29).
  Result-object or RPC-method-shape divergence (no `errors` array
  semantics, no `psbt+complete` pair, no `Result::INVALID_PARAMETER /
  INVALID_ADDRESS_OR_KEY / MISC_ERROR / WALLET_ERROR` distinct mapping).
- **P2-CONSISTENCY (internal cleanups)** — 2 bugs (G17, G30).
  Hotbuns-internal inconsistencies (e.g. dead branch, comment lies).

## Gate map (G1–G30) and findings

### Universal constants

#### G1 — `MAX_BIP125_RBF_SEQUENCE = 0xfffffffd`
**Status: PRESENT.** `src/wallet/wallet.ts:86` defines
`BIP125_RBF_SEQUENCE = 0xfffffffd` and `src/mempool/rbf.ts:30`
defines `MAX_BIP125_RBF_SEQUENCE = 0xfffffffd`. Matches Core
`util/rbf.h::MAX_BIP125_RBF_SEQUENCE`. The wallet name disagrees with
the spec name (Core says MAX_BIP125_RBF_SEQUENCE, hotbuns wallet says
BIP125_RBF_SEQUENCE) — flag for renaming consistency in a later
wave, but not a bug per se.

#### G2 — `MAX_REPLACEMENT_CANDIDATES = 100`
**Status: PRESENT.** `src/mempool/rbf.ts:37` defines
`MAX_REPLACEMENT_CANDIDATES = 100`. Matches Core
`policy/rbf.h:MAX_REPLACEMENT_CANDIDATES`.

### `PreconditionChecks` gates

#### G3 — `HasWalletSpend` (wallet-descendant guard)
**Status: MISSING — BUG-1 (P0-CDIV).** Core
`feebumper.cpp:25-28` checks `wallet.HasWalletSpend(wtx.tx)` to
prevent bumping a tx that has already been spent by another wallet
tx (which would orphan the descendant). Hotbuns has no equivalent
check. If the user calls `bumpfee` on a parent tx whose change output
has already been re-spent by another `createTransaction`, hotbuns
will happily replace the parent — orphaning the child, which would
then fail to relay. Severity: **P0-CDIV** because the child's funds
can become unrecoverable until the child is re-built and resent.

#### G4 — `hasDescendantsInMempool` (mempool-descendant guard)
**Status: MISSING — BUG-2 (P1-WIRE).** Core
`feebumper.cpp:31-34` calls
`wallet.chain().hasDescendantsInMempool(wtx.GetHash())`. Hotbuns has
no equivalent on the wallet-mempool interface. Distinct from G3:
G3 catches wallet-originated descendants, G4 catches external
descendants (e.g. CPFP spends submitted by other wallets). Hotbuns
will let you orphan in-mempool descendants of an external relayer.

#### G5 — `GetTxDepthInMainChain != 0` (confirmed-tx guard)
**Status: PARTIAL — BUG-3 (P0-CDIV).** Hotbuns's check
`if (out.confirmed) throw` at `wallet.ts:1184-1188` is logically
correct but relies on `processBlock` having flagged the
`OutgoingTx.confirmed` boolean. Core's check at `feebumper.cpp:37`
uses `GetTxDepthInMainChain != 0`, which also flags **conflicted**
txs (depth = -1). Hotbuns has no conflicted-with-mined-tx detection
on the OutgoingTx record. If the wallet is offline when a competing
tx confirms, then comes back online and the user calls bumpfee
before processBlock has caught up, hotbuns will let the bump proceed
on a tx that is *already double-spent on-chain*. The replacement
will then fail at the mempool layer (which sees the confirmed
conflict in chainstate), but hotbuns will have moved the
`outgoingTxs` slot to the replacement — the original is now
unrecoverable from hotbuns's bookkeeping.

#### G6 — `replaced_by_txid` (already-bumped guard)
**Status: MISSING — BUG-4 (P1-API).** Core
`feebumper.cpp:42-45` rejects with the message "Cannot bump
transaction X which was already bumped by transaction Y" when the
original carries `wtx.mapValue["replaced_by_txid"]`. This is the
exact field set by `MarkReplaced` in `CommitTransaction` to prevent
the bump-A-twice-to-A2-and-A3 double-pay scenario described in the
BIP-125 "wallet rule" comment at feebumper.cpp:300-305. Hotbuns has
**no `replaced_by_txid` or `replaces_txid` field on `OutgoingTx`**
(`wallet.ts:217-230`). After a bump, the original's `OutgoingTx`
slot is still present in `outgoingTxs` and a second call to
`bumpFee(origTxid, higherRate)` will succeed, producing a second
replacement that double-spends the original's inputs. Both
replacements use the same input set so only one can win the race,
but the wallet's books will track two outstanding replacements as
if both were live. Severity: P1-API rather than P0-CDIV because the
mempool RBF gate will reject one of them, but the wallet bookkeeping
is wrong either way.

#### G7 — `require_mine` parameter
**Status: MISSING — BUG-5 (P1-API).** Core's
`CreateRateBumpTransaction` takes a `bool require_mine` parameter
(feebumper.h:49-58) that lets the RPC layer skip the
`AllInputsMine` check (used by `psbtbumpfee` when bumping a tx with
non-wallet inputs that an external signer will handle). Hotbuns's
`bumpFee(txid, newFeeRate?)` signature (`wallet.ts:1179`) has no
require_mine — `AllInputsMine` is always enforced.

### `CheckFeeRate` gates (Rule 3 + Rule 4 precise math)

#### G8 — `mempoolMinFee` check
**Status: MISSING — BUG-6 (P1-API).** Core
`feebumper.cpp:67-75` checks
`newFeerate.GetFeePerK() < minMempoolFeeRate.GetFeePerK()` and
rejects with "New fee rate (X) is lower than the minimum fee rate
(Y) to get into the mempool". Hotbuns has no
`wallet.chain().mempoolMinFee()` plumbing; the wallet has no view
into mempool min fee at all. A user-supplied `fee_rate` below the
mempool's current floor will build a replacement that the local
mempool will reject — wallet bumpfee silently builds + broadcasts,
RPC returns the broadcast error in the `errors` array (`server.ts:7719-7724`),
but the wallet's `outgoingTxs` is already updated, leaving stale
state.

#### G9 — `calculateCombinedBumpFee` (unconfirmed-ancestor cluster)
**Status: MISSING — BUG-7 (P0-CDIV).** Core
`feebumper.cpp:83-87` requires
`wallet.chain().calculateCombinedBumpFee(reused_inputs, newFeerate)`
to return a value. If the original tx has unconfirmed ancestors
(common CPFP scenario), Core adds the cumulative ancestor bump cost
to `new_total_fee` so the Rule 3 invariant covers the entire
ancestor chain. Hotbuns ignores ancestors entirely — the replacement
fee is computed only against the replacement's own size, so an RBF
replacement of a tx that's currently anchoring a child via CPFP can
silently underpay relative to the child's fee floor. Severity:
**P0-CDIV** because the resulting replacement may not actually
improve the cluster's feerate and would be evicted on the next
mempool churn.

#### G10 — `GetRequiredFee` minimum check
**Status: MISSING — BUG-8 (P1-API).** Core
`feebumper.cpp:101-106` rejects when
`new_total_fee < GetRequiredFee(wallet, maxTxSize)` —
`GetRequiredFee` is the wallet's `minRelayTxFee` floor at
`wallet/fees.cpp::GetRequiredFee`. Hotbuns has no
`getRequiredFee()` method; the only minimum is the implicit
`targetRate > oldFeeRate` (Rule 3) check.

#### G11 — `incrementalRelayFee.GetFee(maxTxSize)` PRECISE INVARIANT (Rule 3)
**Status: PARTIAL — BUG-9 (P0-CDIV).** This is the **W130
headline gate**. Core `feebumper.cpp:93-99` enforces:
```
minTotalFee = old_fee + incrementalRelayFee.GetFee(maxTxSize)
if new_total_fee < minTotalFee:
    reject
```
where `incrementalRelayFee.GetFee(n)` is integer arithmetic:
`EvaluateFeeUp(n)` rounds **up** (`feerate.cpp:24`). At the default
`DEFAULT_INCREMENTAL_RELAY_FEE = 1000 sat/kvB = 1 sat/vB`, this
means `minTotalFee = oldFee + ceil(1 sat/vB * maxTxSize)`.

Hotbuns enforces something **different** at `wallet.ts:1221-1235`:
```
targetRate = newFeeRate ?? oldFeeRate + 1
if targetRate <= oldFeeRate: reject
newFee = ceil(oldVSize * targetRate)
if newFee <= oldFee: reject
```
Three semantic divergences:

1. **Hotbuns asserts on `targetRate` (sat/vB) vs `oldFeeRate`,**
   not on the absolute fee delta vs `incrementalRelayFee *
   maxTxSize`. For a 250-vB tx where Core would accept a 10-sat
   bump (incrementalRelayFee 1 sat/vB × 250 vB = 250 sat... wait,
   Core would require *250* sat extra here, not 10), hotbuns would
   accept any positive rate increment. Wait — Core's
   `incrementalRelayFee` at the default 1 sat/vB on a 250-vB tx
   requires `additional_fee >= 250 sat`. Hotbuns's "rate must be
   strictly greater" with the `+ 1 sat/vB` fallback approximates
   this only when the fallback path is taken. **For the
   user-supplied path** (the common case from RPC), hotbuns accepts
   `newFeeRate = oldFeeRate + 0.001` (a 1/1000th sat/vB bump), which
   would give an `additional_fee` of essentially zero — wildly below
   Core's Rule 3 + Rule 4 floor.

2. **The wallet uses float arithmetic** (`Number(out.fee) / oldVSize`
   at line 1220; `Math.ceil(oldVSize * targetRate)` at line 1231).
   Core uses pure integer arithmetic via FeeFrac. For
   adversarial-precision feerates that straddle a half-sat boundary
   the JS float will round-trip differently than Core's
   `EvaluateFeeUp`. The Rule 3 invariant is a STRICT integer
   inequality in Core; in hotbuns it is a "close to" float
   inequality.

3. **`oldVSize = 10 + 68 * inputs + 31 * outputs` is wrong** for
   non-P2WPKH input sets. A P2PKH input is ~148 vB, not 68; a P2SH-
   P2WPKH input is ~91 vB, not 68; a P2TR key-path input is ~57.5
   vB, not 68. For a mixed-input wallet, `oldFeeRate` is therefore
   *meaningless* — hotbuns would compute an incorrect `oldFeeRate`,
   then enforce a Rule 3 boundary that bears no relation to the
   actual replacement's vsize. Severity: **P0-CDIV** because for
   any non-P2WPKH wallet, the rule-3 boundary is silently wrong.

Defensible direction:
- Lift `incrementalRelayFee` (an `Int64` constant, not a
  configurable) onto the Wallet class.
- Replace `oldFeeRate + 1` with `oldFeeRate + max(incrementalRelayFee,
  WALLET_INCREMENTAL_RELAY_FEE)` per Core's `EstimateFeeRate`.
- Replace `targetRate <= oldFeeRate` check with the absolute fee
  inequality `newFee - oldFee < incrementalRelayFee.GetFee(newVsize)`.

#### G12 — `m_default_max_tx_fee` cap (maxtxfee)
**Status: MISSING — BUG-10 (P1-API).** Core
`feebumper.cpp:109-114` checks `new_total_fee > max_tx_fee` and
rejects with "Specified or calculated fee X is too high (cannot be
higher than -maxtxfee Y)". The default
`DEFAULT_TRANSACTION_MAXFEE = 0.1 BTC` is the user-visible safety
limit. Hotbuns has no `-maxtxfee` knob; an `fee_rate=10000` (10k
sat/vB) on a 250-vB tx would build a 2.5M-sat fee silently. The
user can be defended against only by the RPC's `fee_rate > 0` check,
which is a much weaker bound.

### `EstimateFeeRate` gates (fallback path)

#### G13 — `feerate = oldFee/oldVsize + 1 sat/vB`
**Status: PARTIAL — BUG-11 (P1-API).** Hotbuns line 1221:
`targetRate = newFeeRate ?? oldFeeRate + 1` matches Core's
*shape* (`feebumper.cpp:124-126`: `CFeeRate feerate(old_fee, txSize);
feerate += CFeeRate(1)`). But hotbuns uses **JS float** for the +1
(`oldFeeRate` is a number) and **never** adds the
`WALLET_INCREMENTAL_RELAY_FEE` term that Core adds in the next
statement.

#### G14 — `WALLET_INCREMENTAL_RELAY_FEE = 5000 sat/kvB`
**Status: MISSING — BUG-12 (P1-API).** Core
`feebumper.cpp:135-137` adds `max(node_incremental_relay_fee,
wallet_incremental_relay_fee)` to the fallback feerate, where
`WALLET_INCREMENTAL_RELAY_FEE = 5000 sat/kvB = 5 sat/vB` (defined
in `wallet/fees.h`). This is the wallet-conservative incremental
fee, deliberately higher than the default node incremental relay fee
to future-proof against changes to relay policy. Hotbuns has no
such constant and no such bump.

#### G15 — `feerate = max(feerate, GetMinimumFeeRate)`
**Status: MISSING — BUG-13 (P1-API).** Core
`feebumper.cpp:140-143` floors the fallback feerate to
`GetMinimumFeeRate(wallet, coin_control, /*feeCalc=*/nullptr)` — the
wallet's `payTxFee`/`minTxFee` baseline. Hotbuns has no such floor.

### Coin selection / output reconstruction gates

#### G16 — Coin selection re-runs (`m_allow_other_inputs = true`, `m_min_depth = 1`)
**Status: MISSING — BUG-14 (P0-CDIV).** Core
`feebumper.cpp:299-312` re-runs coin selection over a coin-control
where every original input is `Select()`ed (`for (const auto& inputs
: wtx.tx->vin) new_coin_control.Select(...)`) AND
`m_allow_other_inputs = true` so additional UTXOs can be pulled in,
AND `m_min_depth = 1` so only confirmed coins are added (BIP-125
Rule 2). Hotbuns **does no coin selection at all** in `bumpFee` —
it simply reuses the original input set and reduces the change
output by `feeDelta`. If `feeDelta > origChange - 546n` (dust),
hotbuns rejects (`wallet.ts:1244-1248`). Core would have pulled in
another confirmed UTXO to cover the delta. Severity: **P0-CDIV**
because Core *succeeds* on inputs where hotbuns fails, on identical
wallet state — and the user can't bump as much as Core can.

#### G17 — `original_change_index` parameter
**Status: MISSING — BUG-15 (P1-API).** Core
`feebumper.cpp:181-184` lets the RPC caller specify
`original_change_index` to designate which output is the change
output (otherwise `OutputIsChange(wallet, output)` is auto-detected).
Hotbuns hard-codes `out.changeIndex` from the OutgoingTx record
(`wallet.ts:1210`) — there's no way for the caller to override.

#### G18 — `outputs` parameter (output replacement)
**Status: MISSING — BUG-16 (P1-API).** Core
`feebumper.cpp:251-263` lets the caller specify a *complete
replacement output set* (`const std::vector<CTxOut>& outputs`), so a
wallet can change the destination/amount of a bumped tx. Hotbuns
copies the original outputs verbatim (`wallet.ts:1250-1254`); no
way to replace.

#### G19 — `SignatureWeights` / `SignatureWeightChecker`
**Status: MISSING — BUG-17 (P1-WIRE).** Core
`feebumper.cpp:212-231` computes input weights for *external*
inputs (`new_coin_control.IsExternalSelected`) using
`SignatureWeights` (feebumper.h:75-104) and a custom
`SignatureWeightChecker` (lines 106-122) that runs the script with
`MissingDataBehavior::FAIL` to record observed sig sizes, then adds
the weight-diff-to-max (72-byte sig). This is essential for psbt-
bumpfee with non-wallet inputs (e.g. multisig co-signers). Hotbuns
doesn't even have a notion of "external input" — every input must
be `AllInputsMine`. The W129 audit also flagged this surface (G18
BUG-3 P1-WIRE) for a separate reason.

#### G20 — Re-run coin selection with full Core algorithm chain
**Status: MISSING — BUG-18 (P1-API).** Per W129, hotbuns has only
BnB + Knapsack + largest_first fallback (no SRD, no CoinGrinder, no
waste metric). Even if G16 (re-run coin selection) were fixed,
`bumpFee` would not have the full Core selection chain. Inherited
defect from coin selection layer.

### `CommitTransaction` gates

#### G21 — Anti-TOCTOU re-`PreconditionChecks` at commit
**Status: MISSING — BUG-19 (P1-API).** Core
`feebumper.cpp:364-367` re-runs `PreconditionChecks(require_mine=false)`
at commit time to catch the race where the original is mined or
double-spent between the `CreateRateBumpTransaction` and the
`CommitTransaction` calls. Hotbuns has a single `bumpFee` that
builds and signs in one shot, then the RPC layer broadcasts —
there is no equivalent second check. The mempool layer will reject
the broadcast if the original is already replaced, but at that point
hotbuns has already updated `outgoingTxs` and the user sees a
half-applied state.

#### G22 — `mapValue["replaces_txid"]` on replacement
**Status: MISSING — BUG-20 (P1-API).** Core
`feebumper.cpp:371-372` writes `mapValue["replaces_txid"] =
oldWtx.GetHash().ToString()` on the replacement so downstream
tooling (e.g. wallet RPCs `gettransaction`) can show "this is a
bump of X". Hotbuns's `OutgoingTx` (wallet.ts:217-230) has no
`replacesTxid` field.

#### G23 — `MarkReplaced` / `mapValue["replaced_by_txid"]` on original
**Status: MISSING — BUG-21 (P1-API).** Counterpart of G22 — Core
`feebumper.cpp:377-380` writes `mapValue["replaced_by_txid"] =
bumped_txid` on the *original* tx. This is the field PreconditionChecks
inspects to prevent double-bump (G6). Hotbuns has neither the
field nor the inspect step.

### RPC surface gates

#### G24 — `conf_target` / `estimate_mode` parameters
**Status: MISSING — BUG-22 (P1-API).** Core's `bumpfee` RPC
accepts `conf_target` (target confirmation in blocks) and
`estimate_mode` (`unset|economical|conservative`) and feeds them
into `EstimateSmartFee` (via `CCoinControl::m_confirm_target` +
`m_fee_estimate_mode`). Hotbuns's RPC at `server.ts:7679-7691` only
parses `fee_rate` / `feeRate` (line 7681); the docstring
acknowledges "most Core fields are tolerated but only fee_rate is
honored" (line 7659).

#### G25 — `replaceable` parameter
**Status: PARTIAL — BUG-23 (P1-API).** Core's `bumpfee` RPC
accepts `replaceable: bool` (default true) — the replacement may
opt OUT of further RBF if `replaceable: false`. Hotbuns hard-codes
`sequence: i.sequence < 0xfffffffe ? i.sequence : BIP125_RBF_SEQUENCE`
at `wallet.ts:1261`, so the replacement's sequence is inherited
from the original (always BIP-125 since the original had to be
BIP-125 to reach this code path). No way to opt out.

#### G26 — `psbtbumpfee` returns `{psbt, complete, ...}` not `{psbt, ...}`
**Status: PARTIAL — BUG-24 (P1-WIRE).** Core's `psbtbumpfee` RPC
result includes a `complete: bool` field
(wallet/rpc/spend.cpp::psbtbumpfee) indicating whether the PSBT is
fully signed (when the wallet has an external signer that
auto-signed). Hotbuns's RPC at `server.ts:7807-7812` returns only
`{psbt, origfee, fee, errors}` — no `complete` field. Hotbuns
strips signatures so `complete` would always be `false`, but the
field is part of the documented shape and tooling will look for it.

#### G27 — `errors` array semantics
**Status: PARTIAL — BUG-25 (P1-WIRE).** Core returns `errors` as a
non-empty array only on failure paths. Hotbuns at
`server.ts:7727-7732` always returns `errors: []` on the success
path and `errors: [msg]` on broadcast-fail (lines 7719-7724) —
shape parity is close. **However**: the broadcast-fail path returns
HTTP 200 with `txid: ""` and `errors: [msg]`, whereas Core throws a
JSON-RPC error in the same scenario (the original is preserved in
the wallet). Returning a "successful" result with an empty txid is
a wire-shape divergence.

#### G28 — `feebumper::Result` enum mapping
**Status: PARTIAL — BUG-26 (P1-API).** Core distinguishes 6 result
codes (feebumper.h:24-31): OK, INVALID_ADDRESS_OR_KEY,
INVALID_REQUEST, INVALID_PARAMETER, WALLET_ERROR, MISC_ERROR.
Hotbuns maps **every** wallet-layer error to `WALLET_ERROR` at
`server.ts:7707`. A "txid not 64 hex chars" returns `INVALID_PARAMS`
but a "txid is valid hex but unknown to wallet" returns `WALLET_ERROR`
where Core would return `INVALID_ADDRESS_OR_KEY`. Tooling that
distinguishes "user error" from "wallet error" by RPC code will
behave differently against hotbuns.

### Wallet bookkeeping gates

#### G29 — `outgoingTxs` survives wallet reload
**Status: MISSING — BUG-27 (P1-WIRE).** Core's `mapWallet`
(the wallet tx index) is persisted to disk via the wallet DB on
every `CommitTransaction`. Hotbuns's `outgoingTxs` is an in-memory
`Map<string, OutgoingTx>` (wallet.ts:330) populated only by
`createTransaction()`. There is no `saveWallet` path for
`outgoingTxs`; on wallet reload, **every previously-broadcast
unconfirmed tx becomes unbumpable**. Severity: P1-WIRE because the
loss is silent (no error on bumpfee — just "no such wallet
transaction"), and the user has no in-band recovery.

#### G30 — Replacement signature size estimation
**Status: PARTIAL — BUG-28 (P2-CONSISTENCY).** When hotbuns
re-signs the replacement at `wallet.ts:1280-1287`, the resulting
witness may differ in size from the original (ECDSA signatures are
71 or 72 bytes; the wallet doesn't know which until after signing).
The recorded `newFee` was computed from the pre-signing `oldVSize`
estimate. If the replacement turns out to weigh 1 byte more per
input (worst case: 72-byte sigs everywhere), the actual feerate is
fractionally lower than computed. Core uses
`CalculateMaximumSignedTxSize` (feebumper.cpp:289) to estimate the
max-signed size BEFORE the fee math, so its Rule 3 boundary is
conservative. Hotbuns's boundary uses the average-sized estimate.
At default 1 sat/vB this is a fraction-of-a-sat boundary error;
flagged P2.

## Bug inventory

| ID | Gate | Severity | Status | Hotbuns location |
|----|------|----------|--------|------------------|
| BUG-1 | G3 | P0-CDIV | MISSING | wallet.ts:1179 (no HasWalletSpend) |
| BUG-2 | G4 | P1-WIRE | MISSING | wallet.ts:1179 (no hasDescendantsInMempool plumbing) |
| BUG-3 | G5 | P0-CDIV | PARTIAL | wallet.ts:1184-1188 (depth=-1 not detected) |
| BUG-4 | G6 | P1-API | MISSING | wallet.ts:217-230 (no replaced_by_txid) |
| BUG-5 | G7 | P1-API | MISSING | wallet.ts:1179 (no require_mine param) |
| BUG-6 | G8 | P1-API | MISSING | wallet.ts:1179 (no mempoolMinFee plumbing) |
| BUG-7 | G9 | P0-CDIV | MISSING | wallet.ts:1179 (no combinedBumpFee) |
| BUG-8 | G10 | P1-API | MISSING | wallet.ts:1179 (no getRequiredFee) |
| BUG-9 | G11 | P0-CDIV | PARTIAL | wallet.ts:1218-1235 (Rule 3 imprecise; vsize wrong) |
| BUG-10 | G12 | P1-API | MISSING | wallet.ts:1179 (no maxtxfee cap) |
| BUG-11 | G13 | P1-API | PARTIAL | wallet.ts:1221 (float arithmetic) |
| BUG-12 | G14 | P1-API | MISSING | wallet.ts:1179 (no WALLET_INCREMENTAL_RELAY_FEE) |
| BUG-13 | G15 | P1-API | MISSING | wallet.ts:1179 (no GetMinimumFeeRate floor) |
| BUG-14 | G16 | P0-CDIV | MISSING | wallet.ts:1238-1253 (no coin re-select) |
| BUG-15 | G17 | P1-API | MISSING | wallet.ts:1179 (no original_change_index) |
| BUG-16 | G18 | P1-API | MISSING | wallet.ts:1179 (no outputs param) |
| BUG-17 | G19 | P1-WIRE | MISSING | wallet.ts:1179 (no SignatureWeights) |
| BUG-18 | G20 | P1-API | MISSING | wallet.ts (no SRD/CoinGrinder per W129) |
| BUG-19 | G21 | P1-API | MISSING | server.ts:7700-7733 (no re-Precondition) |
| BUG-20 | G22 | P1-API | MISSING | wallet.ts:1291-1298 (no replacesTxid) |
| BUG-21 | G23 | P1-API | MISSING | wallet.ts:1179 (no MarkReplaced) |
| BUG-22 | G24 | P1-API | MISSING | server.ts:7679-7691 (no conf_target) |
| BUG-23 | G25 | P1-API | PARTIAL | wallet.ts:1261 (no replaceable knob) |
| BUG-24 | G26 | P1-WIRE | PARTIAL | server.ts:7807-7812 (no complete field) |
| BUG-25 | G27 | P1-WIRE | PARTIAL | server.ts:7719-7724 (HTTP 200 on broadcast fail) |
| BUG-26 | G28 | P1-API | PARTIAL | server.ts:7707 (all → WALLET_ERROR) |
| BUG-27 | G29 | P1-WIRE | MISSING | wallet.ts:330 (in-memory only) |
| BUG-28 | G30 | P2-CONSISTENCY | PARTIAL | wallet.ts:1218 (fixed vsize estimate) |

## Cross-impl pattern candidates

Per W129's "audit framework requires byte-exact not SHA256d-only"
pattern, this audit deliberately probes the **integer-vs-float
arithmetic boundary** for `incrementalRelayFee.GetFee(maxTxSize)`
because Core's `EvaluateFeeUp` rounding semantics (`feerate.cpp:24`,
`m_feerate.EvaluateFeeUp(virtual_bytes)`) are an integer-arithmetic
invariant that JS's `Math.ceil(float * vsize)` does NOT preserve
across all sat-boundary cases. The first cross-impl pattern from
this audit is:

> **"float feerate arithmetic in a TS impl deviates from Core's
> EvaluateFeeUp at sat-boundary fee rates"** — flagged for the
> cross-impl audit corpus. lunarblock (LuaJIT) and ouroboros (Python)
> have similar pitfalls; the byte-exact integer test in W130 G11
> should be promoted.

A second cross-impl pattern: **"`bumpfee` without `outgoingTxs`
persistence is silently broken across wallet restarts"** — applies
to any TS/JS/Python impl that uses an in-memory `Map` for the wallet
tx index. Note W129 hotbuns finding referenced
`walletcreatefundedpsbt` having a similar stub
("Manual inputs aren't supported yet"); hotbuns's `bumpfee`
similarly only handles the wallet-shaped subset of the surface.

## Out of scope

- TRUC (v3) bumpfee semantics (BIP-431). Core has TRUC-specific
  ancestor/descendant counting that interacts with feebumper; covered
  in a future TRUC audit wave.
- Cluster-mempool feerate diagram for the bumped replacement. The
  mempool already enforces this at acceptance (W120 G8) so it's
  out-of-scope for the wallet-layer audit.
- Hardware-signer / external-signer bumpfee. Core's `psbtbumpfee`
  has special handling for `WALLET_FLAG_EXTERNAL_SIGNER` in
  `SignTransaction`; hotbuns has no external-signer concept.

## Methodology footnote

This audit followed the W##-discovery framework:
1. Read Core refs (`feebumper.cpp`, `rbf.cpp`, `feerate.cpp`).
2. Synthesise 30 gates from Core surface (PreconditionChecks → 5
   gates; CheckFeeRate → 6 gates; EstimateFeeRate → 3 gates; coin
   selection re-run → 5 gates; CommitTransaction → 3 gates;
   RPC surface → 5 gates; bookkeeping → 3 gates).
3. Classify each against hotbuns source (`grep` + line-ranges).
4. Catalogue BUG-N per partial/missing gate.
5. Write `src/__tests__/w130_bip125_feebumper_rule3.test.ts`.

No production code changes in this wave.
