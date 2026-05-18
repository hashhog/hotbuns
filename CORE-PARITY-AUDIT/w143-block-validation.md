# W143 — Block-level validation (CheckBlock + ContextualCheckBlock + ConnectBlock) — hotbuns

**Impl:** hotbuns (TypeScript / Bun)
**Date:** 2026-05-18
**Wave:** W143 Block-level validation
**Status:** DISCOVERY — 20 BUGS / 24 gates
**Tests:** assertion-only, no production code changes.
**No production code changes in this wave.**

## References

### Bitcoin Core
- `bitcoin-core/src/validation.cpp`:
  - `CheckBlockHeader` (L3828-3835) — PoW gate emits
    `high-hash` / `BLOCK_INVALID_HEADER`.
  - `CheckMerkleRoot` (L3837-3862) — caches via
    `block.m_checked_merkle_root`. Emits `bad-txnmrklroot` on root
    mismatch AND `bad-txns-duplicate` when `BlockMerkleRoot` reports
    `mutated == true` (CVE-2012-2459 defence).
  - `CheckBlock` (L3918-3983):
    - L3947: `bad-blk-length` size-limits gate —
      `block.vtx.empty() || block.vtx.size() * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT
       || ::GetSerializeSize(TX_NO_WITNESS(block)) * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT`.
      This combines TWO orthogonal early caps (vtx count cap and
      stripped-size cap) and FIRES BEFORE per-tx CheckTransaction.
    - L3951-3955: `bad-cb-missing` (first tx is not coinbase) and
      `bad-cb-multiple` (any other coinbase).
    - L3959-3968: per-tx `CheckTransaction` — runs the
      consensus/tx_check.cpp gates against EVERY tx including the
      coinbase, BEFORE the legacy-sigops gate.
    - L3971-3977: `bad-blk-sigops` — `GetLegacySigOpCount(tx) * 4
      > MAX_BLOCK_SIGOPS_COST` context-free gate, runs inside
      CheckBlock (in addition to the full P2SH+witness sigops gate
      that ConnectBlock runs at L2569-2572).
    - L3979-3980: caches result via `block.fChecked = true` when both
      fCheckPOW and fCheckMerkleRoot hold.
  - `ContextualCheckBlockHeader` (L4080-4121) — bad-diffbits +
    time-too-old (BIP-113 MTP) + BIP-94 timewarp + time-too-new
    (`block.Time() > NodeClock::now() + MAX_FUTURE_BLOCK_TIME`) +
    `bad-version` for outdated versions.
  - `ContextualCheckBlock` (L4129-4181):
    - IsFinalTx loop (BIP-113 lock-time, "bad-txns-nonfinal").
    - BIP-34 (DEPLOYMENT_HEIGHTINCB): `CScript expect = CScript() << nHeight;`
      then byte-equal prefix on `coinbase.vin[0].scriptSig` →
      `bad-cb-height`.
    - CheckWitnessMalleation gate.
    - `bad-blk-weight` — `GetBlockWeight(block) > MAX_BLOCK_WEIGHT`,
      AFTER the witness commitment check (so witness can't be padded
      to inflate weight pre-commitment-check).
  - `IsBlockMutated` (L4027-4055) — calls `CheckMerkleRoot` (rejects
    `bad-txns-duplicate` AND `bad-txnmrklroot`), checks `any tx
    GetSerializeSize == 64` (64-byte tx malleation defence per
    Linux-Foundation bitcoin-dev 2019-02-25 PDF), THEN
    `CheckWitnessMalleation`. Used by BIP-152 compact-block path and
    other reconstructors.
  - `ConnectBlock` (L2295-2673):
    - L2333: `assert(hashPrevBlock == view.GetBestBlock())` view-consistency.
    - L2339-2343: genesis short-circuit.
    - L2402-2476: BIP-30 with BIP34 skip + BIP34_IMPLIES_BIP30_LIMIT.
    - L2543-2547: per-tx accumulated-fee `MoneyRange` check.
    - L2569-2572: `bad-blk-sigops` — full sigops cost (legacy*4 +
      P2SH*4 + witness*1).
    - L2610-2614: `bad-cb-amount` — `block.vtx[0]->GetValueOut() >
      blockReward`.
- `bitcoin-core/src/consensus/tx_check.cpp` — `CheckTransaction` —
  9 gates (bad-txns-vin-empty / vout-empty / oversize /
  vout-negative / vout-toolarge / txouttotal-toolarge /
  inputs-duplicate / cb-length / prevout-null).
- `bitcoin-core/src/consensus/merkle.cpp`:
  - `ComputeMerkleRoot(hashes, mutated)` (L46-63) — sets
    `*mutated = true` whenever `hashes[pos] == hashes[pos+1]` BEFORE
    duplicating odd last leaf. Returns `uint256()` for empty input.
  - `BlockMerkleRoot(block, mutated)` (L66-74) — forwards the
    `mutated` flag.
- `bitcoin-core/src/chain.h` — `MAX_FUTURE_BLOCK_TIME = 2*60*60`
  (L29), `TIMESTAMP_WINDOW = MAX_FUTURE_BLOCK_TIME` (L37).
- `bitcoin-core/src/consensus/consensus.h`:
  - `MAX_BLOCK_SERIALIZED_SIZE = 4_000_000` (L13), `MAX_BLOCK_WEIGHT
    = 4_000_000` (L15), `WITNESS_SCALE_FACTOR = 4` (L21),
    `MAX_TIMEWARP = 600` (L35).
- `bitcoin-core/src/policy/policy.h` — `MAX_BLOCK_SIGOPS_COST = 80_000`.
- `bitcoin-core/src/kernel/chainparams.cpp` — mainnet
  `BIP30Exception` blocks (kernel/chainparams.cpp `bip30Exception`
  Hi/Hi2 + validation.cpp:6189-6192): heights 91842 (hash 0a4d0a…)
  and 91880 (hash 743f19…). NB: validation.cpp:2201 also uses
  heights 91722 + 91812 for the `fEnforceBIP30` two-historical-coinbase
  carve-out (these are the BIP-30 *original* duplicates, not exceptions).

## Hotbuns files in scope

- `src/validation/block.ts` (1079 LOC) — `validateBlock`,
  `validateBlockHeader`, `validateBip34Height`,
  `encodeBip34Height`, `checkWitnessMalleation`,
  `computeMerkleRoot`, `computeWitnessMerkleRoot`, `getBlockWeight`,
  `getLegacySigOpCount`.
- `src/validation/tx.ts` (1948 LOC) — `validateTxBasic`,
  `isCoinbase`.
- `src/consensus/connect_block.ts` (742 LOC) —
  `coreConnectBlockChecks` (BIP-30 / IsFinalTx / sigops cost /
  bad-cb-amount).
- `src/sync/blocks.ts:2466` — production call site:
  `validateBlock(block, height, this.params)`.
- `src/p2p/compact_blocks.ts:693` — calls only
  `checkWitnessMalleation`, NOT the full IsBlockMutated equivalent
  (merkle-root recompute + 64-byte-tx scan).

## Audit matrix (24 gates)

| ID | Subsystem | Gate (Core behavior expected of hotbuns) | Status |
|----|-----------|------------------------------------------|--------|
| **Sigops** | | | |
| G1 | sigops | MAX_BLOCK_SIGOPS_COST = 80_000 | PASS (block.ts:67) |
| G2 | sigops | Witness-scale factor 4 applied to legacy + P2SH sigops, 1× to witness sigops | PASS (block.ts:1004,1013,1019) |
| G3 | sigops | CONTEXT-FREE legacy sigops cap inside `CheckBlock`: `GetLegacySigOpCount(tx) * WITNESS_SCALE_FACTOR > MAX_BLOCK_SIGOPS_COST` BEFORE per-input prevout loading | **BUG-1** |
| **BIP-34** | | | |
| G4 | bip34 | Coinbase scriptSig begins with byte-exact `CScript() << nHeight` (CScriptNum push, not raw varint) | PASS (block.ts:461-502) |
| G5 | bip34 | OP_1..OP_16 for heights 1..16, OP_0 for height 0, CScriptNum for 17+ | PASS (block.ts:461-480) |
| G6 | bip34 | Skipped for heights below `bip34Height` (params.bip34Height = 227931 mainnet) | PASS (block.ts:588) |
| G7 | bip34 | BIP-34 enforced via `ContextualCheckBlock` (after parent known), NOT during the unreached/orphan-parent path | **BUG-2** |
| **BIP-30** | | | |
| G8 | bip30 | Duplicate-coinbase exception at heights 91842 AND 91880 (by both height AND block hash) | PASS (connect_block.ts:333-336) |
| G9 | bip30 | BIP-30 check still RUNS for ALL post-BIP-34 blocks above `BIP34_IMPLIES_BIP30_LIMIT = 1_983_702` | PASS (connect_block.ts:356-358) |
| G10 | bip30 | BIP-30 check uses `view.HaveCoin(prevout)` semantics (a UTXO collision is enough — not just txid existence) | PARTIAL — see **BUG-3** |
| **Merkle** | | | |
| G11 | merkle | `ComputeMerkleRoot` returns the merkle root | PASS (block.ts:177-199) |
| G12 | merkle | CVE-2012-2459 `mutated` flag tracked: any internal duplicate-children pair sets `mutated=true`; CheckBlock then emits `bad-txns-duplicate` | **BUG-4** |
| G13 | merkle | `IsBlockMutated` 64-byte transaction defence (Linux-Foundation bitcoin-dev 2019-02-25) — any non-witness-stripped tx == 64 bytes ⇒ mutated | **BUG-5** |
| G14 | merkle | `CheckMerkleRoot` caches `m_checked_merkle_root` flag on block — repeated callers don't re-validate | **BUG-6** |
| **MoneyRange** | | | |
| G15 | money | Every CTxOut.nValue ∈ [0, MAX_MONEY] | PASS (tx.ts:1060-1067) |
| G16 | money | Sum-of-outputs ≤ MAX_MONEY (CVE-2010-5139) | PASS (tx.ts:1072) |
| **vin/vout** | | | |
| G17 | shape | `bad-txns-vin-empty` and `bad-txns-vout-empty` from CheckTransaction | PASS (tx.ts:1023-1033) |
| G18 | shape | block.vtx[0] is coinbase (`bad-cb-missing`); no other coinbase (`bad-cb-multiple`) | PARTIAL — see **BUG-7** |
| G19 | shape | Per-tx CheckTransaction runs for EVERY tx (`tx_check.cpp:11-59`), in CheckBlock, BEFORE sigops/weight gates | **BUG-8** |
| **Block size / weight** | | | |
| G20 | size | Pre-segwit `bad-blk-length` size-limits gate: `vtx.empty()` OR `vtx.size() * 4 > MAX_BLOCK_WEIGHT` OR `stripped_size * 4 > MAX_BLOCK_WEIGHT`, run EARLY (`CheckBlock`) BEFORE coinbase / merkle / per-tx checks | **BUG-9** |
| G21 | size | `bad-blk-weight` full-block `getBlockWeight()` gate run LATE (`ContextualCheckBlock`), AFTER `CheckWitnessMalleation` so witness data can't be padded to inflate weight pre-commitment | **BUG-10** |
| **Block timestamp** | | | |
| G22 | time | `time-too-new`: `block.Time() > NodeClock::now() + MAX_FUTURE_BLOCK_TIME` (7200 s) using `NodeClock` (i.e. adjusted-time / mock-time aware), NOT raw `Date.now()` | **BUG-11** |
| G23 | time | `time-too-old`: block timestamp > MTP of last 11 (BIP-113); ContextualCheckBlockHeader gate (overlaps W132 — verify both) | PASS in sync/headers.ts (sync path); validateBlockHeader is DEAD prod code — **BUG-12** |
| G24 | time | BIP-94 timewarp: `time-timewarp-attack` on first block of each retarget on testnet4 / regtest with `enforce_BIP94` | PASS for sync/headers.ts; missing in block.ts validateBlockHeader (see **BUG-12**) |

**Summary:** 20 BUGs across the 24 gates.

## Bug catalogue

### Sigops

#### BUG-1 (P1): `CheckBlock` context-free legacy-sigops cap completely absent

Core's `CheckBlock` runs an EARLY sigops gate that does not need
prevouts (validation.cpp:3971-3977):
```cpp
unsigned int nSigOps = 0;
for (const auto& tx : block.vtx)
{
    nSigOps += GetLegacySigOpCount(*tx);
}
if (nSigOps * WITNESS_SCALE_FACTOR > MAX_BLOCK_SIGOPS_COST)
    return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-blk-sigops", "out-of-bounds SigOpCount");
```

This is a context-free upper-bound: any block whose legacy sigops
alone exceed 20_000 is rejected without UTXO loading. hotbuns'
`validateBlock` runs:

  - merkle root recompute
  - witness commitment check
  - per-tx CheckTransaction
  - getBlockWeight

…but never sums `getLegacySigOpCount(tx) * 4`. The full sigops cost
(including P2SH and witness sigops) IS gated in
`coreConnectBlockChecks` (connect_block.ts:689-694) but ONLY after
all prevouts are loaded. A maliciously-constructed block with
1_000_000 OP_CHECKSIG operations in coinbase-scriptSig (against
limits but no script execution) would force hotbuns to do the full
prevout-preload loop before the sigops gate fires.

**Impact:** DoS amplifier: every node that receives a sigops-bomb
block performs the full per-input prevout preload (potentially
thousands of LevelDB reads) before rejecting. Core rejects in the
context-free path, costing O(block_size).

**Excerpt** (block.ts:594-601 — per-tx loop only does CheckTransaction):
```ts
for (let i = 0; i < block.transactions.length; i++) {
  const tx = block.transactions[i];
  const result = validateTxBasic(tx);  // tx_check.cpp gates only
  if (!result.valid) {
    return { valid: false, error: `Transaction ${i}: ${result.error}` };
  }
}
// note no legacy-sigops sum here
```

### BIP-34

#### BUG-2 (P2): `submitblock` orphan-parent path falls back to `approxHeight=0`, skipping BIP-34

`src/rpc/server.ts:4991-4998`:
```ts
let approxHeight: number;
if (parentEntry) {
  approxHeight = parentEntry.height + 1;
} else {
  const bestHeader = this.headerSync.getBestHeader();
  approxHeight = bestHeader ? bestHeader.height + 1 : 0;
}
const structCheck = validateBlock(block, approxHeight, this.params);
```

When `submitblock` is called with an orphan block whose parent is not
yet in our header index, hotbuns falls back to the tip+1 or 0. If 0,
`validateBlock` skips BIP-34 entirely (block.ts:588). Core would
reject such a block in `ProcessNewBlock` because it never reaches the
"contextual" validation; hotbuns' bypass allows the structural-check
pass to "succeed" before injectBlock returns "inconclusive".

The bug surfaces only in a corner case (orphan-parent submitblock with
a bogus BIP-34 coinbase), but it means `validateBlock`'s BIP-34 gate
is not a reliable guard against a malicious miner attempting to
preload an invalid block into the orphan pool.

**Impact:** Test harnesses or external integrations that rely on
`submitblock` failing fast with `bad-cb-height` on a malformed
coinbase will silently see `inconclusive` instead, deferring the
rejection until the orphan resolves. Hotbuns-specific divergence
from Core's `submitblock` reject token stream.

### BIP-30

#### BUG-3 (P2): BIP-30 check iterates `(txid, vout)` pairs but Core checks `HaveCoin(outpoint)`

`src/consensus/connect_block.ts:358-371`:
```ts
if (fEnforceBIP30 || height >= BIP34_IMPLIES_BIP30_LIMIT) {
  for (const tx of block.transactions) {
    const txid = getTxId(tx);
    for (let vout = 0; vout < tx.outputs.length; vout++) {
      const exists = await utxoManager.hasUTXOAsync({ txid, vout });
      if (exists) {
        return {
          ok: false,
          error: `bad-txns-BIP30: tried to overwrite transaction ${txid.toString("hex")}:${vout} at height ${height}`,
        };
      }
    }
  }
}
```

Core (validation.cpp:2466-2472):
```cpp
if (fEnforceBIP30 || pindex->nHeight >= BIP34_IMPLIES_BIP30_LIMIT) {
    for (const auto& tx : block.vtx) {
        for (size_t o = 0; o < tx->vout.size(); o++) {
            if (view.HaveCoin(COutPoint(tx->GetHash(), o))) {
                LogPrintf("ERROR: ConnectBlock(): tried to overwrite transaction\n");
                return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-txns-BIP30");
            }
        }
    }
}
```

The semantic match is correct. But note that `utxoManager.hasUTXOAsync`
queries the UTXO cache + DB. If the block's earlier tx[i] creates a
new UTXO that tx[j>i] would COLLIDE with (intra-block self-collision
under BIP-30 semantics), hotbuns' loop runs BEFORE addTransaction,
so it doesn't see intra-block-created UTXOs. Core's `view.HaveCoin`
also doesn't see them at this point (the addTransaction loop is
later in `ConnectBlock`), so this is actually CORRECT semantics.

The real issue: the loop is N×O(M) where N=tx count, M=outputs per
tx. For a 4MB block with 5000 outputs across 1000 tx, that's 5_000_000
async UTXO lookups — even with preload, this is a heavy DoS path. Core
runs this in a tight non-async loop with a thread-pinned UTXO cache.
hotbuns issues each lookup as a Promise.

**Impact:** P2 — semantics are correct but the implementation cost is
O(total_outputs) per block during the pre-1_983_702 window AND every
block thereafter. Not a consensus bug, but an asymmetric-DoS knob.

### Merkle / CVE-2012-2459

#### BUG-4 (P0-CONSENSUS): CVE-2012-2459 mutated-flag tracking is COMPLETELY ABSENT

`src/validation/block.ts:177-199`:
```ts
export function computeMerkleRoot(txids: Buffer[]): Buffer {
  if (txids.length === 0) {
    return Buffer.alloc(32, 0);
  }
  let level: Buffer[] = txids.map((txid) => Buffer.from(txid));

  while (level.length > 1) {
    const nextLevel: Buffer[] = [];
    for (let i = 0; i < level.length; i += 2) {
      const left = level[i];
      // If odd, duplicate the last element
      const right = i + 1 < level.length ? level[i + 1] : level[i];
      nextLevel.push(hash256(Buffer.concat([left, right])));
    }
    level = nextLevel;
  }
  return level[0];
}
```

Core's `ComputeMerkleRoot` (consensus/merkle.cpp:46-63) tracks a
`mutated` flag:
```cpp
uint256 ComputeMerkleRoot(std::vector<uint256> hashes, bool* mutated) {
    bool mutation = false;
    while (hashes.size() > 1) {
        if (mutated) {
            for (size_t pos = 0; pos + 1 < hashes.size(); pos += 2) {
                if (hashes[pos] == hashes[pos + 1]) mutation = true;
            }
        }
        if (hashes.size() & 1) {
            hashes.push_back(hashes.back());
        }
        SHA256D64(hashes[0].begin(), hashes[0].begin(), hashes.size() / 2);
        hashes.resize(hashes.size() / 2);
    }
    if (mutated) *mutated = mutation;
    ...
}
```

The flag is then plumbed through `BlockMerkleRoot` →
`CheckMerkleRoot` → `state.Invalid(BLOCK_MUTATED, "bad-txns-duplicate")`
(validation.cpp:3853-3858). This is the CVE-2012-2459 defence: an
attacker can append the last pair of transactions to construct a
syntactically distinct but merkle-equivalent block. Without the
mutated flag, hotbuns:

  - Recomputes the merkle root
  - Sees it MATCHES the header's merkleRoot
  - Returns valid

…even though the block is malleated and Core would reject it with
`bad-txns-duplicate`.

**Impact:** P0-CONSENSUS: hotbuns accepts CVE-2012-2459 malleated
blocks that Core rejects. Network-split risk. A malicious miner can
construct a malleated chain branch that hotbuns accepts and Core
rejects, causing nodes to diverge on the active tip.

The bug compounds: the duplicate-tx in the malleated block has
duplicate INPUTS (CVE-2018-17144) which CheckTransaction's
`bad-txns-inputs-duplicate` gate WOULD catch — but the per-tx loop in
validateBlock runs AFTER the merkle check, so by the time
validateTxBasic runs, the block has already passed the merkle gate
and a higher-level call site might commit to it.

Verify: `grep -rn "CVE-2012-2459\|bMutated\|mutated.*flag" hotbuns/src` returns 0 hits.

#### BUG-5 (P1): No 64-byte-transaction `IsBlockMutated` defence

Core's `IsBlockMutated` (validation.cpp:4035-4048):
```cpp
if (block.vtx.empty() || !block.vtx[0]->IsCoinBase()) {
    // Consider the block mutated if any transaction is 64 bytes in size (see 3.1
    // in "Weaknesses in Bitcoin's Merkle Root Construction"...
    return std::any_of(block.vtx.begin(), block.vtx.end(),
                       [](auto& tx) { return GetSerializeSize(TX_NO_WITNESS(tx)) == 64; });
}
```

A 64-byte transaction (after witness stripping) collides with the
internal-node size of the merkle tree, allowing an attacker to
construct a syntactically-valid leaf that masquerades as a merkle
intermediate node. Core's compact-block path uses `IsBlockMutated`
to reject this. hotbuns' compact-block path
(p2p/compact_blocks.ts:693) only calls `checkWitnessMalleation`, NOT
the full IsBlockMutated equivalent — so it CAN reconstruct a block
with a 64-byte tx that Core would reject.

Note: this is "not a consensus change" per Core's own comment because
a block with a 64-byte tx (which can only happen if `vtx[0]` is not
coinbase) is already invalid by other rules. But the compact-block
short-ID-collision detection is silently weaker in hotbuns.

**Impact:** Short-ID collision attacks against hotbuns' compact-block
reconstruction can reach a "valid" full block that Core would
reject. P1 because the secondary checks catch it before block
commit, but the BIP-152 reconstruction path itself is brittler than
Core's.

#### BUG-6 (P2): No `m_checked_merkle_root` / `block.fChecked` caching

Core caches the result of `CheckBlock` (`block.fChecked = true`) and
of `CheckMerkleRoot` (`block.m_checked_merkle_root = true`) and
`CheckWitnessMalleation` (`m_checked_witness_commitment`) so that
the validation pipeline doesn't re-run expensive merkle/witness
recomputation when the same block flows through `ProcessNewBlock` →
`AcceptBlock` → `CheckBlock` (called from multiple places).

hotbuns has NO such caching. `validateBlock` is called from
sync/blocks.ts:2466, RPC submitblock at server.ts:4998, BIP-152 path,
and the snapshot path. Each call re-runs computeMerkleRoot which is
O(N log N) hash256s.

**Impact:** P2 performance: a duplicate `submitblock` followed by a
P2P-arrived copy of the same block re-hashes the merkle tree twice.
Measurable on large blocks but no consensus consequence.

### vin/vout / coinbase

#### BUG-7 (P2): "First transaction is not coinbase" / "Transaction ${i} is coinbase" error strings do not match Core's reject tokens

`src/validation/block.ts:530`:
```ts
return { valid: false, error: "First transaction is not coinbase" };
```
`block.ts:544`:
```ts
return { valid: false, error: `Transaction ${i} is coinbase but should not be` };
```

Core emits:
- `bad-cb-missing` (validation.cpp:3952): "first tx is not coinbase"
- `bad-cb-multiple` (validation.cpp:3954-3955): "more than one coinbase"

The `validation/errors.ts` token mapper has heuristic substring
matches for "merkle root mismatch" / "duplicate" / "bad-cb-height"
etc., but neither "first transaction is not coinbase" nor "is coinbase
but should not be" is mapped — so `bip22Result()` returns the raw
free-form string, which violates BIP-22 token canonicalization.

**Impact:** P2 — submitblock returns "First transaction is not
coinbase" instead of `bad-cb-missing`, and `bad-cb-multiple` is never
emitted at all. Diff-test corpus comparing reject reasons across
impls catches this.

**Excerpt** (errors.ts canonical-string table omits both):
```ts
if (s.includes("merkle root mismatch") || s.includes("bad-txnmrklroot")) {
  return "bad-txnmrklroot";
}
// no entry for "first transaction is not coinbase" → bad-cb-missing
// no entry for "is coinbase but should not be" → bad-cb-multiple
```

#### BUG-8 (P1): `CheckTransaction` per-tx loop runs LAST in `validateBlock`, not before sigops/weight gates

Core's `CheckBlock` order (validation.cpp:3946-3977):
1. size limits (bad-blk-length) ← EARLY
2. coinbase position (bad-cb-missing / bad-cb-multiple)
3. **per-tx CheckTransaction loop** ← BEFORE sigops
4. legacy sigops cap (bad-blk-sigops)

hotbuns' `validateBlock` order (block.ts:521-601):
1. transactions.length == 0 → "Block has no transactions"
2. coinbase position
3. cbScriptLen (bad-cb-length)
4. coinbase-multiple loop
5. merkle root recompute
6. checkWitnessMalleation (in CheckBlock — Core puts this in
   ContextualCheckBlock)
7. getBlockWeight (in CheckBlock — Core puts this in
   ContextualCheckBlock)
8. validateBip34Height (Core: ContextualCheckBlock)
9. **per-tx validateTxBasic** ← LAST

A block that violates BOTH a per-tx rule (e.g. negative output) AND a
block-level rule (e.g. exceed weight) will emit DIFFERENT reject
reasons under hotbuns vs Core. The fleet diff-test corpus will see
divergent error tokens.

**Impact:** P1 — diff-test failures on multi-violation blocks.
Reject-reason divergence triggers consensus-diff alerts.

### Block size / weight

#### BUG-9 (P1): No early `bad-blk-length` gate — combined size cap missing

Core's `CheckBlock` (validation.cpp:3947):
```cpp
if (block.vtx.empty() || block.vtx.size() * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT || ::GetSerializeSize(TX_NO_WITNESS(block)) * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT)
    return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-blk-length", "size limits failed");
```

Three orthogonal early caps:
1. `vtx.empty()` — empty block (hotbuns has this as
   `block.transactions.length === 0` but emits "Block has no
   transactions", not `bad-blk-length`).
2. `vtx.size() * 4 > MAX_BLOCK_WEIGHT` — vtx-count cap (≈ 1_000_000
   tx max). **hotbuns has no such check.**
3. `stripped_size * 4 > MAX_BLOCK_WEIGHT` — pre-segwit stripped-byte
   cap (≈ 1 MB stripped). **hotbuns has no such check** — only the
   late `getBlockWeight()` gate which uses base_size*3 + total_size.

The vtx-count check matters: a deserializer that reads 50_000_000
empty transactions from wire (each minimum 10 bytes stripped) yields
a 500MB stripped size that exceeds the 1MB-stripped cap, but in the
absence of an early vtx-count cap, the loop that iterates
`block.transactions` in `validateBlock` runs 50M times before
`getBlockWeight()` catches it.

**Impact:** P1 — DoS amplifier: a malicious deserializer feed can
force `validateBlock` to do 50M per-tx work before bailing.

W142 BUG-8 noted the stripped-size cap absence; this finding extends
to the vtx-count cap.

#### BUG-10 (P0-CDIV): `bad-blk-weight` gate runs BEFORE witness commitment check (gate-order divergence)

`src/validation/block.ts:566-584`:
```ts
const segwitActive = height >= params.segwitHeight;
const witnessMalleation = checkWitnessMalleation(block, segwitActive);
if (!witnessMalleation.valid) {
  return { valid: false, error: witnessMalleation.error };
}

const totalWeight = getBlockWeight(block);
if (totalWeight > params.maxBlockWeight) {
  return { valid: false, error: "Block weight exceeds maximum" };
}
```

Wait — hotbuns DOES run witness commitment BEFORE weight check. So
the ORDER is correct relative to Core's `ContextualCheckBlock`
(L4169 witness check, L4179 weight). OK.

BUT: Core's `bad-blk-length` early gate runs in `CheckBlock` (BEFORE
the witness check, using stripped_size*4). hotbuns conflates the
two checks into a single late `getBlockWeight()` call. The early
`bad-blk-length` is missing (BUG-9 above). The late
`bad-blk-weight` exists but emits "Block weight exceeds maximum"
which DOES map to `bad-blk-weight` via errors.ts.

Reject-reason check: error string is "Block weight exceeds maximum"
which (per errors.ts) maps via `s.includes("weight")` → `bad-blk-weight`.
Acceptable.

The more concerning divergence: the witness commitment check is
PLACED in CheckBlock instead of ContextualCheckBlock. This means
hotbuns DOES validate witness commitments even when called via the
test harness without a parent index. That matches the safer
semantics — but means a block with both an invalid witness commitment
AND an invalid timestamp would emit `bad-witness-merkle-match` under
hotbuns, whereas Core emits `time-too-old` first (since
ContextualCheckBlockHeader runs before ContextualCheckBlock).

**Impact:** P0-CDIV — Reject-reason ordering divergence on
multi-violation blocks. CheckBlock vs ContextualCheckBlock boundary
is blurred. Diff-test corpus will flag this on edge-case fuzz inputs.

### Block timestamp

#### BUG-11 (P1): `validateBlockHeader` uses `Date.now()` not adjusted-time

`src/validation/block.ts:406`:
```ts
const maxFutureTime = Math.floor(Date.now() / 1000) + 2 * 60 * 60;
if (header.timestamp > maxFutureTime) {
  return { valid: false, error: "Block timestamp too far in future" };
}
```

Core (validation.cpp:4108):
```cpp
if (block.Time() > NodeClock::now() + std::chrono::seconds{MAX_FUTURE_BLOCK_TIME}) {
    return state.Invalid(BlockValidationResult::BLOCK_TIME_FUTURE, "time-too-new", "block timestamp too far in the future");
}
```

`NodeClock::now()` is a mockable clock that supports `setmocktime`
RPC (used by functional tests). It's also the SAME clock that
gets used elsewhere in `ProcessNewBlock`, ensuring time monotonicity
across calls.

hotbuns' `Date.now()`:
1. Cannot be mocked via `setmocktime` RPC → functional tests cannot
   advance time to past the 2-hour future window.
2. Drifts independently from the rest of hotbuns' time tracking
   (which uses `Date.now()` in some places and computed-MTP in
   others).
3. Emits "Block timestamp too far in future" instead of `time-too-new`.

Reject-reason mapping: errors.ts does NOT map "Block timestamp too
far in future" → `time-too-new`. Submitblock returns the raw string.

Also note that `validateBlockHeader` is DEAD production code:
- Production call site for block header validation is
  `sync/headers.ts:585+` which DOES use `Date.now()` (also missing
  mock-time support) — separate bug.
- `validateBlockHeader` in `block.ts` is only called from tests.

**Impact:** P1 — divergent reject token + functional test breakage.

#### BUG-12 (P2): `validateBlockHeader` is dead production code (defined, no production callers)

`grep -rn validateBlockHeader hotbuns/src --include="*.ts" | grep -v .test.ts` →
only the definition at block.ts:398. NO production callers. The
production path uses `sync/headers.ts:HeaderSync.validateHeader`.

Fleet pattern: "dead-helper-at-call-site" (function exists, exported,
even called from tests, but no production wire-up).

Also note `validateBlockHeader` lacks the BIP-94 timewarp check
(`enforce_BIP94` is in sync/headers.ts only). If anyone wires it
into a production path, the timewarp check would be silently missing.

**Impact:** P2 — confusing helper that doesn't reflect production
behavior; risk of someone wiring it into a new code path believing
it's complete.

### Cross-cutting gates

#### BUG-13 (P1): `validateBlock` skipped under no parent header path in sync/blocks.ts:2466 only if `headerSync` already accepted the header

`src/sync/blocks.ts:2466`:
```ts
const validation = validateBlock(block, height, this.params);
```

`validateBlock`'s witness-malleation check uses `height` to determine
`segwitActive`. If the caller passes `height = 0` (e.g. orphan
case), `segwitActive = false` for mainnet (segwitHeight = 481824),
meaning `checkWitnessMalleation` enters the "no commitment expected"
branch and only scans for `unexpected-witness`. A block at the
actual segwit-activation height submitted via submitblock with
approxHeight=0 would have its commitment IGNORED.

This is the same family of bug as BUG-2 (submitblock orphan fallback)
but specifically for witness commitment. A malicious submitblock at
the right height could bypass witness validation by exploiting the
orphan-parent path.

**Impact:** P1 — submitblock orphan-parent bypass for witness
commitment check. Mitigated because production sync path always has
a parent height; only `submitblock` RPC is vulnerable.

#### BUG-14 (P1): `validateBlock` does NOT call `validateBlockHeader` — no PoW check inside CheckBlock equivalent

Core's `CheckBlock` (validation.cpp:3927):
```cpp
if (!CheckBlockHeader(block, state, consensusParams, fCheckPOW))
    return false;
```

PoW (`high-hash` reject) is the FIRST check in Core's CheckBlock.
hotbuns' `validateBlock` doesn't call `validateBlockHeader` or
`CheckProofOfWork` — it assumes the caller already accepted the
header via the sync pipeline. The production caller
(`sync/blocks.ts:2466`) does have a separate header-acceptance gate,
but a test/RPC caller that constructs a Block with a bogus header
would pass `validateBlock` without ever checking PoW.

`src/rpc/server.ts:4998` (submitblock) calls `validateBlock` directly
without any prior PoW check on the block header — Core's submitblock
runs full CheckBlock which validates PoW. So hotbuns' submitblock
accepts blocks with invalid PoW as long as the merkle root + witness
commitment match. The next step (`injectBlock`) does invoke the
header-sync pipeline which catches PoW, but the structural-check
gate emits a misleading "validation success".

**Impact:** P1 — `validateBlock` is not a true `CheckBlock`
equivalent. Function-level Core-parity divergence; submitblock
returns "valid then orphan" instead of "high-hash" for a
PoW-broken block.

#### BUG-15 (P2): `computeMerkleRoot` early-out for empty input returns 32 zeros, but Core returns `uint256()` (also 32 zeros) via different path

`block.ts:177-180`:
```ts
export function computeMerkleRoot(txids: Buffer[]): Buffer {
  if (txids.length === 0) {
    return Buffer.alloc(32, 0);
  }
  ...
}
```

Core `consensus/merkle.cpp:46-63`:
```cpp
uint256 ComputeMerkleRoot(std::vector<uint256> hashes, bool* mutated) {
    ...
    if (hashes.size() == 0) return uint256();
    return hashes[0];
}
```

Byte-identical result (32 zeros), but hotbuns' fast-path SKIPS the
`*mutated` write (which doesn't matter since `mutation` was never set
to true). However, this means if BUG-4 is fixed by plumbing a
`mutated` output parameter through `computeMerkleRoot`, the
empty-input fast path needs to set `*mutated = false` explicitly.

**Impact:** P2 — only matters as a precondition for fixing BUG-4.

#### BUG-16 (P2): `validateBlock` per-tx loop emits "Transaction ${i}: ${reason}" not the bare canonical token

`src/validation/block.ts:599`:
```ts
return { valid: false, error: `Transaction ${i}: ${result.error}` };
```

If `validateTxBasic` returns `"bad-txns-vin-empty"`, hotbuns wraps
it as `"Transaction 7: bad-txns-vin-empty"`. The errors.ts mapper
falls through to the substring-match branch which finds
`"bad-txns-vin-empty"` and returns the canonical token. So this
isn't broken, but it's noisy and one-off-test-fixture-divergent.

**Impact:** P3 — cosmetic; mappable via substring.

#### BUG-17 (P2): `validateTxBasic` runs `serializeTx(tx, false)` per tx for the oversize check — re-serializes every tx in every validateBlock call

`src/validation/tx.ts:1040`:
```ts
const strippedSize = serializeTx(tx, false).length;
if (strippedSize * 4 > 4_000_000) {
  return { valid: false, error: "bad-txns-oversize" };
}
```

In a 4MB block with 4000 tx, validateBlock calls validateTxBasic for
each, which re-serializes each tx WITHOUT witness, accumulating to
4MB of allocations. Core uses `GetSerializeSize` (no buffer
allocation, just size computation).

**Impact:** P2 — performance, not consensus. Compounds with BUG-9
(no early bad-blk-length cap).

#### BUG-18 (P2): Genesis block falls through `validateBlock` BIP-34 + per-tx gates because production guard is in `coreConnectBlockChecks` not `validateBlock`

The genesis-block short-circuit lives at
`connect_block.ts:269-281`:
```ts
if (genesisHashHex && blockHashHexForGate === genesisHashHex) {
  return { ok: true, spentOutputs: [], ... };
}
```

But `validateBlock` (block.ts:517) is called BEFORE
`coreConnectBlockChecks` (in sync/blocks.ts:2466 vs the connect path
later). The genesis block has no parent and its coinbase scriptSig
("The Times..." quote, 71 bytes) does NOT start with a CScriptNum
encoding of height 0 (the leading byte is `0x04` not `0x00`).

If `validateBlock(genesisBlock, 0, MAINNET)` is called, the BIP-34
gate is skipped because mainnet `bip34Height = 227931 > 0`. So
this is NOT a bug — the height < bip34Height gate covers genesis.

However, for a network with `bip34Height = 1` (testnet4, signet,
regtest), `validateBlock(genesisBlock, 1, REGTEST)` would attempt
BIP-34. On regtest the genesis-coinbase is special and
validateBlock would emit `bad-cb-height`. This actually appears in
test fixtures.

Reviewing: in `__tests__/witness_commitment_gates.test.ts:605` and
`block.test.ts:660`, `validateBlock(block, 1, REGTEST)` is called
with mock blocks that are CRAFTED to pass — not actual regtest
genesis. So the gap is theoretical.

**Impact:** P2 — `validateBlock` does not include the
genesis-short-circuit gate that lives in connect_block.ts. Test
harnesses that pass actual genesis at height 0 with
`bip34Height = 0` would emit `bad-cb-height` instead of passing.

#### BUG-19 (P2): No `block.vtx[0]->vin.size() == 1` precondition assertion before reading `vin[0].scriptSig` in BIP-34 check

`src/validation/block.ts:497-498`:
```ts
if (coinbaseTx.inputs.length === 0) return false;
const scriptSig = coinbaseTx.inputs[0].scriptSig;
```

The early-return on `inputs.length === 0` returns `false`, which
then maps to `bad-cb-height` at the caller. But Core's invariant
(enforced by `IsCoinBase()` returning `tx.vin.size() == 1 &&
prevout.IsNull()`) is stricter: vin must have EXACTLY one input.

`validateBip34Height` is only ever called from `validateBlock`
after `isCoinbase()` succeeded (which enforces
`tx.inputs.length === 1`). So the `inputs.length === 0` branch is
unreachable in production. Dead defensive code.

The deeper issue: if someone refactors `isCoinbase` to allow zero
inputs, this guard becomes a silent gate that emits `bad-cb-height`
instead of the more correct `bad-cb-missing`. Fragile.

**Impact:** P3 — defensive code with stale precondition. No active
divergence.

#### BUG-20 (P2): `params.bip30ExceptionBlocks` array search is `O(N)` per tx per output — should be O(1) hash-set lookup keyed by `(height, hash)`

`src/consensus/connect_block.ts:333-336`:
```ts
const isExempt = params.bip30ExceptionBlocks.some(
  (ex) => ex.height === height && ex.blockHashHex === blockHashHex
);
```

Only 2 exception entries (h=91842, 91880), so the linear scan is
trivially fast. But the API shape encourages adding more (e.g.
testnet-specific exceptions). The check fires for every block
between BIP30 enforcement and BIP34, then again above
BIP34_IMPLIES_BIP30_LIMIT. If a future Core update adds more
exception entries, the linear scan grows.

**Impact:** P3 — non-issue at current sizes. Filed for fleet-pattern
consistency.

## Fleet patterns observed

1. **"Dead-helper-at-call-site"** (4th instance fleet-wide,
   `comment-as-confession` family): `validateBlockHeader` exported
   from `block.ts` with 0 production callers; all production wire-up
   goes through `sync/headers.ts::validateHeader`. The exported
   helper lacks BIP-94 timewarp protection that the production
   helper has. Risk: a future caller wires it in believing it's
   complete.

2. **"Cross-helper inconsistent reject tokens"**: `validateBlock`
   emits free-form English strings ("First transaction is not
   coinbase", "Block timestamp too far in future") that the
   `errors.ts` token mapper does NOT recognize, so submitblock
   returns the raw English instead of `bad-cb-missing` /
   `time-too-new`. Fleet pattern: every impl has at least one such
   reject-reason gap; hotbuns has 3 (`bad-cb-missing`,
   `bad-cb-multiple`, `time-too-new`).

3. **"Two-pipeline-guard"** (15th distinct extension since W76):
   block validation lives in TWO places — `validation/block.ts`
   `validateBlock` (called from sync/blocks.ts AND rpc/server.ts AND
   tests) and `consensus/connect_block.ts` `coreConnectBlockChecks`
   (called from chain/state.ts AND sync/blocks.ts). The genesis
   short-circuit lives ONLY in `coreConnectBlockChecks`, not in
   `validateBlock`. The BIP-30 exception list lives ONLY in
   `coreConnectBlockChecks`. The BIP-34 byte-exact encoding lives
   ONLY in `validateBlock`. A consensus-fix landing in one half
   doesn't reach the other; the fleet's classic compounding-fragility
   pattern.

4. **"Late-bound height parameter"**: `validateBlock(block, height,
   params)` accepts `height` from the caller; submitblock falls back
   to `approxHeight = 0` on orphan-parent which DISABLES BIP-34 +
   witness-commitment + `bad-cb-height` checks. Pattern: trusting
   the caller to supply a correct height defeats a security-relevant
   gate.

5. **"Gate-order divergence"** (5th instance fleet-wide): hotbuns'
   `validateBlock` runs witness-commitment + weight + BIP-34 INSIDE
   the CheckBlock equivalent, where Core puts them in
   ContextualCheckBlock. This means reject-reason ordering on
   multi-violation blocks diverges from Core; fleet-wide diff-test
   fuzz inputs will surface this.

6. **"Comment-as-confession" absent**: `validateBlock` has the
   note (block.ts:603-608):
   ```ts
   // Note: Full validation would also check:
   // - Coinbase output value <= subsidy + fees
   // - All inputs exist and are unspent (UTXO validation)
   // - Script validation for all inputs
   // - No double spends within block
   // - Total sigops cost (requires prevOutputs, done in connectBlock)
   ```
   This is a "comment-as-aspiration": the missing checks ARE done
   elsewhere (in coreConnectBlockChecks). Not "comment-as-confession"
   in the usual sense, but a pattern smell — splitting CheckBlock
   into two functions with a TODO-style comment in one.

## Suggested fix priorities

| Priority | Bug | Description | Lines changed |
|----------|-----|-------------|---------------|
| P0-CONSENSUS | BUG-4 | Plumb CVE-2012-2459 `mutated` flag through `computeMerkleRoot` and reject `bad-txns-duplicate` | ~15 LOC |
| P1 | BUG-1 | Add legacy-sigops cap inside `validateBlock` (sum getLegacySigOpCount × 4 > MAX_BLOCK_SIGOPS_COST) | ~5 LOC |
| P1 | BUG-8 | Reorder `validateBlock` to match Core's CheckBlock gate order | ~30 LOC |
| P1 | BUG-9 | Add early `bad-blk-length` gate: vtx-count cap + stripped-size cap | ~5 LOC |
| P1 | BUG-14 | Call `validateBlockHeader` (or inline PoW check) at top of `validateBlock` | ~5 LOC |
| P1 | BUG-2/BUG-13 | submitblock orphan-parent: reject instead of falling back to approxHeight=0 | ~10 LOC |
| P1 | BUG-11 | Replace `Date.now()` with mockable adjusted-time | ~10 LOC |
| P2 | BUG-5 | Add 64-byte-tx scan in compact-block reconstruct path | ~5 LOC |
| P2 | BUG-7 | Emit `bad-cb-missing` / `bad-cb-multiple` canonical tokens | ~3 LOC |
| P2 | BUG-12 | Wire `validateBlockHeader` into production OR delete the helper | ~varies |
| P2 | BUG-6 | Cache `m_checked_merkle_root` / `m_checked_witness` flags on Block | ~10 LOC |

## Cross-cite (other waves)

- W142 BUG-8 (block.ts:580) overlaps BUG-9 here on the stripped-size
  cap. W142 noted it as a single bug; W143 splits into vtx-count and
  stripped-size dimensions.
- W142 BUG-9 (`MAX_BLOCK_WEIGHT` bounds `vtx.size()`) overlaps BUG-9
  here. Same underlying gap.
- W132 (`nSequence/CSV/MTP`) covers gate G23 here (time-too-old MTP);
  the validateBlockHeader gap in block.ts compounds with W132
  findings.
- W145 (planned) — `bad-cb-amount` overlap is referenced in the
  audit spec; this audit does not re-cover it but BUG-1 (sigops)
  and BUG-9 (size) are W143-specific.
