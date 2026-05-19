# W154 — CreateNewBlock + BlockAssembler + block template construction (hotbuns)

**Wave:** W154 — `BlockAssembler::CreateNewBlock`, `addChunks`,
`TestChunkBlockLimits`, `TestChunkTransactions`, `AddToBlock`,
`resetBlock`, `ClampOptions`, `ApplyArgsManOptions`, `GetMinimumTime`,
`UpdateTime`, `RegenerateCommitments`, `GenerateCoinbaseCommitment`,
`AddMerkleRootAndCoinbase`, `getblocktemplate`, `getmininginfo`,
`generatetoaddress`, `generatetodescriptor`, `generateblock`,
`submitblock`, `submitheader`, `prioritisetransaction`,
`getprioritisedtransactions`, `getnetworkhashps`, BIP-22 / BIP-23 /
BIP-141 / BIP-152 / BIP-9, `MAX_BLOCK_WEIGHT=4_000_000`,
`MAX_BLOCK_SIGOPS_COST=80_000`, `WITNESS_SCALE_FACTOR=4`,
`DEFAULT_BLOCK_RESERVED_WEIGHT=8000`,
`MINIMUM_BLOCK_RESERVED_WEIGHT=2000`,
`DEFAULT_COINBASE_OUTPUT_MAX_ADDITIONAL_SIGOPS=400`,
`MAX_SEQUENCE_NONFINAL=0xFFFFFFFE`, `MAX_TIMEWARP=600`.

**Scope:** discovery only — no production code changes.

## Bitcoin Core references

- `bitcoin-core/src/node/miner.h:42-159` — `CBlockTemplate`,
  `BlockAssembler`, `Options { nBlockMaxWeight, blockMinFeeRate,
  test_block_validity, print_modified_fee }`, `m_last_block_num_txs`,
  `m_last_block_weight`, `RegenerateCommitments`,
  `ApplyArgsManOptions`, `AddMerkleRootAndCoinbase`,
  `GetMinimumTime(pindexPrev, difficulty_adjustment_interval)`,
  `UpdateTime(pblock, params, pindexPrev)`, `GetTip`,
  `WaitAndCreateNewBlock`.
- `bitcoin-core/src/node/miner.cpp:36-65` — `GetMinimumTime` (MTP+1 OR
  parent_time - MAX_TIMEWARP at retarget boundary; comment: "Account for
  BIP94 timewarp rule on **all networks**. This makes future activation
  safer.") + `UpdateTime`.
- `bitcoin-core/src/node/miner.cpp:67-77` — `RegenerateCommitments` —
  pops witness-commitment output, re-invokes `GenerateCoinbaseCommitment`,
  reruns `BlockMerkleRoot(block)`.
- `bitcoin-core/src/node/miner.cpp:79-88` — `ClampOptions`:
  `block_reserved_weight ∈ [MINIMUM_BLOCK_RESERVED_WEIGHT,
  MAX_BLOCK_WEIGHT]`; `coinbase_output_max_additional_sigops ∈ [0,
  MAX_BLOCK_SIGOPS_COST]`; `nBlockMaxWeight ∈ [block_reserved_weight,
  MAX_BLOCK_WEIGHT]`.
- `bitcoin-core/src/node/miner.cpp:98-109` — `ApplyArgsManOptions`:
  parses `-blockmaxweight`, `-blockmintxfee`, `-printpriority`,
  `-blockreservedweight`.
- `bitcoin-core/src/node/miner.cpp:111-120` — `resetBlock`:
  `nBlockWeight = block_reserved_weight`,
  `nBlockSigOpsCost = coinbase_output_max_additional_sigops`,
  `nBlockTx = 0`, `nFees = 0`.
- `bitcoin-core/src/node/miner.cpp:122-237` — `CreateNewBlock`:
  - L131-133 dummy coinbase pushed at index 0 (skipped by GBT).
  - L138 `nHeight = pindexPrev->nHeight + 1`.
  - L140 `pblock->nVersion = ComputeBlockVersion(pindexPrev, ...)`.
  - L143-145 regtest override: `-blockversion=N` allowed.
  - L147 `pblock->nTime = NodeClock::now()` (initial).
  - L148 `m_lock_time_cutoff = pindexPrev->GetMedianTimePast()`.
  - L150-155 `addChunks()` under `m_mempool->cs`.
  - L159-160 record `m_last_block_num_txs` + `m_last_block_weight`.
  - L162-199 build coinbase: `vin[0].prevout.SetNull()`,
    `vin[0].nSequence = MAX_SEQUENCE_NONFINAL`, `vout[0].nValue = nFees
    + GetBlockSubsidy(nHeight, ...)`, `vin[0].scriptSig = CScript() <<
    nHeight`; if `include_dummy_extranonce` append `OP_0`;
    `nLockTime = static_cast<uint32_t>(nHeight - 1)`.
  - L200 `GenerateCoinbaseCommitment(*pblock, pindexPrev)`.
  - L202-213 set `coinbase_tx.witness` (if HasWitness),
    `coinbase_tx.required_outputs` (the commitment OP_RETURN output).
  - L218 `pblock->hashPrevBlock = pindexPrev->GetBlockHash()`.
  - L219 `UpdateTime(pblock, consensus, pindexPrev)`.
  - L220 `pblock->nBits = GetNextWorkRequired(pindexPrev, pblock,
    consensus)`.
  - L221 `pblock->nNonce = 0`.
  - L223-227 if `m_options.test_block_validity` call
    `TestBlockValidity(check_pow=false, check_merkle_root=false)` —
    throws on failure.
- `bitcoin-core/src/node/miner.cpp:239-248` — `TestChunkBlockLimits`:
  `nBlockWeight + chunk_feerate.size >= m_options.nBlockMaxWeight` →
  reject; `nBlockSigOpsCost + chunk_sigops_cost >= MAX_BLOCK_SIGOPS_COST`
  → reject. **Both use `>=`** (rejects exact-equality).
- `bitcoin-core/src/node/miner.cpp:250-260` — `TestChunkTransactions`:
  walks every selected tx through `IsFinalTx(tx, nHeight,
  m_lock_time_cutoff)`. **Belt-and-suspenders** check — should always
  succeed but Core keeps the gate as defensive coding.
- `bitcoin-core/src/node/miner.cpp:262-277` — `AddToBlock`: appends
  shared-ptr to `block.vtx`, pushes `vTxFees` + `vTxSigOpsCost`,
  increments `nBlockWeight`, `nBlockTx`, `nBlockSigOpsCost`, `nFees`.
- `bitcoin-core/src/node/miner.cpp:279-360` — `addChunks` greedy
  package-feerate selector with `MAX_CONSECUTIVE_FAILURES = 1000` +
  `BLOCK_FULL_ENOUGH_WEIGHT_DELTA = 4000` early-exit:
  `if (nConsecutiveFailed > MAX_CONSECUTIVE_FAILURES && nBlockWeight +
   BLOCK_FULL_ENOUGH_WEIGHT_DELTA > m_options.nBlockMaxWeight) break`.
  Uses cluster mempool's `m_mempool->GetBlockBuilderChunk(...)` which
  hands back the next-best **chunk** (package, not single tx).
- `bitcoin-core/src/validation.cpp:3997-4019` — `GenerateCoinbaseCommitment`:
  no-op if commitment output already present; else build 38-byte
  scriptPubKey `OP_RETURN (0x6a) | PUSH36 (0x24) | 0xaa21a9ed | <32-byte
  hash256(BlockWitnessMerkleRoot || ret={0,32})>` and append to
  coinbase.vout.
- `bitcoin-core/src/validation.cpp:4093-4105` — `ContextualCheckBlockHeader`
  BIP-94 timewarp check gated on `consensusParams.enforce_BIP94`. Only
  fires at `nHeight % DifficultyAdjustmentInterval() == 0`. Compares
  `block.GetBlockTime() < pindexPrev->GetBlockTime() - MAX_TIMEWARP`.
- `bitcoin-core/src/policy/policy.h:25-36` —
  `DEFAULT_BLOCK_MAX_WEIGHT{MAX_BLOCK_WEIGHT=4_000_000}`,
  `DEFAULT_BLOCK_RESERVED_WEIGHT{8000}`,
  `DEFAULT_COINBASE_OUTPUT_MAX_ADDITIONAL_SIGOPS{400}`,
  `MINIMUM_BLOCK_RESERVED_WEIGHT{2000}`,
  `DEFAULT_BLOCK_MIN_TX_FEE{1}`.
- `bitcoin-core/src/consensus/consensus.h` — `MAX_BLOCK_WEIGHT=4_000_000`,
  `MAX_BLOCK_SIGOPS_COST=80_000`, `WITNESS_SCALE_FACTOR=4`,
  `MAX_TIMEWARP=600`.
- `bitcoin-core/src/rpc/mining.cpp:` — `getblocktemplate` (BIP-22/23
  rules+vbavailable+vbrequired+default_witness_commitment),
  `getmininginfo` (currentblockweight, currentblocktx, blockmintxfee,
  networkhashps, **next.bits via NextEmptyBlockIndex + GetNextWorkRequired**),
  `submitblock`, `submitheader`, `prioritisetransaction`,
  `getprioritisedtransactions`, `getnetworkhashps`, `generatetoaddress`,
  `generatetodescriptor`, `generateblock`.
- `bitcoin-core/src/consensus/tx_check.cpp:48-51` — `bad-cb-length`:
  coinbase scriptSig must be `2 ≤ len ≤ 100`.
- `bitcoin-core/src/script/script.h:433-448` — BIP-34
  `CScript() << nHeight`: 0 → OP_0; 1..16 → OP_1..OP_16; else
  length-prefixed minimal CScriptNum.

## Files audited

- `src/mining/template.ts` — `BlockTemplateBuilder` (685 LOC), W14/W63
  fixed but **NEVER instantiated by the production RPC entry points**
  (33rd-consecutive "dead-helper at the call-site" wave; pre-existing
  W123 BUG-21).
- `src/mining/template.test.ts` — 62 passing tests against the unused
  helper.
- `src/rpc/server.ts:5021-5259` — `getBlockTemplate` (BIP-22/23 GBT)
  re-implemented from scratch.
- `src/rpc/server.ts:5269-5303` — `generateToAddress` regtest miner.
- `src/rpc/server.ts:5314-5367` — `generateToDescriptor`.
- `src/rpc/server.ts:5377-5469` — `generateBlock`.
- `src/rpc/server.ts:5474-5487` — `generateBlocks` loop.
- `src/rpc/server.ts:5492-5619` — `generateSingleBlock` — the actual
  block-builder used by every regtest mining RPC.
- `src/rpc/server.ts:5624-5693` — `buildCoinbaseTx` /
  `buildCoinbaseTxWithWitnessCommitment` (the bad coinbase builders).
- `src/rpc/server.ts:5698-5744` — `encodeBIP34Height` /
  `encodeScriptNum`.
- `src/rpc/server.ts:7476-7502` — `getMiningInfo` RPC.
- `src/rpc/server.ts:4912-5013` — `submitBlock` RPC + BIP-22 string
  returns (`high-hash`, `time-too-old`, `rejected`, `inconclusive`).
- `src/rpc/server.ts:5789-5799` — `getBlockSubsidy` (HARDCODED 210_000
  halving interval — collides with `consensus/params.ts::getBlockSubsidy`
  which is params-aware; also a W145 BUG-1 carry-forward).
- `src/chain/state.ts:286-473` — `connectBlock` consumed by the
  generate*RPCs (full validation: `assumeValid: false,
  skipScripts: false`); does NOT run `checkWitnessMalleation` /
  `validateBlock` structural gate.
- `src/consensus/connect_block.ts:416-480` — assume-valid scope-creep
  fast path (W145 BUG-2..6 carry-forward; never triggered by the miner
  side because state.ts pins assumeValid=false, but the IBD path
  remains broken).
- `src/script/interpreter.ts:3053-3072` — `scriptFlagsFromBitmask`
  (W144 BUG-3 carry-forward: still derives 4 consensus bits from
  `verifyWitness` instead of their own bits — affects miner via
  `verifyInputSignature`).
- `src/validation/block.ts:398-449` — `validateBlockHeader` (W143
  BUG-10 carry-forward: zero production callers).
- `src/validation/block.ts:517-611` — `validateBlock` (called from
  `submitBlock` ONLY; **NOT** from `generateSingleBlock`).
- `src/consensus/params.ts:393, 1002, 1046-1062` —
  `subsidyHalvingInterval` per-network + `getBlockSubsidy`.
- `src/sync/headers.ts:572-583` — BIP-94 timewarp enforcement on the
  validator side (gated on `enforce_BIP94`, i.e. testnet4/regtest only).
- `src/sync/blocks.ts:2383+` — `BlockSync.connectBlock` (IBD-side; W153
  BUG-12 carry-forward: still NEVER emits `blockConnected`; miner-side
  uses chain/state.ts:471 which DOES emit, so this is asymmetric).
- `src/mempool/mempool.ts:2608-2615` — `getTransactionsByFeeRate`
  (cluster-mempool returns a flat fee-rate sort, not chunk-feerate
  packages — comment claims it but it's a per-tx sort).
- `src/__tests__/w123_mining_gbt.test.ts` — prior 30-gate audit (22
  BUGs; STILL VALID — re-anchored below as confirmed-carry-forwards).
- `audit/w123_mining_gbt.md` — W123 audit document.

---

## Gate matrix (36 sub-gates / 14 behaviours)

| # | Behaviour | Sub-gate | Verdict |
|---|-----------|----------|---------|
| 1 | CreateNewBlock entry-point routing | G1: production GBT calls BlockTemplateBuilder | **BUG-1 (P0-DEAD)** — `import { BlockTemplateBuilder }` exists (server.ts:44) but **no `new BlockTemplateBuilder(` anywhere in server.ts**. The 685-LOC helper plus 62 unit tests is pure dead weight; getBlockTemplate + generateSingleBlock duplicate the logic by hand (33rd consecutive "dead-helper at the call-site" instance; W123 BUG-21 re-anchored — still unfixed after 5 weeks) |
| 1 | … | G2: generateSingleBlock calls validateBlock before connectBlock | **BUG-2 (P0-CDIV)** — `generateSingleBlock` (server.ts:5492-5619) builds the block and pipes it straight into `chainState.connectBlock` with **zero structural validation**. `validateBlock` is called ONLY from `submitBlock` (server.ts:4998). The mining path bypasses merkle-root recompute, BIP-34 height check, coinbase-scriptSig 2..100 bytes, weight gate, **and `checkWitnessMalleation`** — so a freshly mined block with a malformed witness commitment (or no commitment at all when segwit is active) is silently accepted by the local node and broadcast to peers (who reject it). Same shape as ouroboros W143 BUG-7 "ships HALF-FINISHED pipeline". |
| 2 | resetBlock budget initialisation | G3: nBlockWeight starts at DEFAULT_BLOCK_RESERVED_WEIGHT=8000 | PARTIAL — present in `mining/template.ts:350` (dead helper), MISSING in `getBlockTemplate` (`let totalWeight = 0` at server.ts:5069). **BUG-3 (P0-RPC, W123 BUG-3 re-anchored, still unfixed)** |
| 2 | … | G4: nBlockSigOpsCost starts at DEFAULT_COINBASE_OUTPUT_MAX_ADDITIONAL_SIGOPS=400 | PARTIAL — same dead-helper-only situation. `let totalSigOps = 0` (server.ts:5070) (W123 BUG-3 cross-cite) |
| 2 | … | G5: MINIMUM_BLOCK_RESERVED_WEIGHT=2000 floor | **BUG-4 (P1)** — constant absent. `ClampOptions` (`node/miner.cpp:82`) refuses to start `BlockAssembler` if `block_reserved_weight < MINIMUM_BLOCK_RESERVED_WEIGHT`. hotbuns has no equivalent; `-blockreservedweight` is not parsed (cf. BUG-5) so this is currently unreachable, but the floor is a Core sanity invariant. |
| 3 | ApplyArgsManOptions CLI plumbing | G6: -blockmaxweight parsed | **BUG-5 (P0-RPC)** — operator cannot tune block weight. Neither `cli/cli.ts` nor any other file parses `-blockmaxweight`. `params.maxBlockWeight = 4_000_000` is the only path. Core: `args.GetIntArg("-blockmaxweight", options.nBlockMaxWeight)` at `node/miner.cpp:101`. Affects pool operators who want smaller blocks for propagation. |
| 3 | … | G7: -blockmintxfee parsed | **BUG-6 (P0-RPC, W123 BUG-22 re-anchored)** — `getmininginfo` returns hardcoded `blockmintxfee: 0.00001000`; no `-blockmintxfee` parsing anywhere in `cli/cli.ts`. Cross-cite W153 BUG-5 (DEFAULT_MIN_RELAY_TX_FEE absent). |
| 3 | … | G8: -blockreservedweight parsed | **BUG-7 (P1)** — operator cannot override the 8000-WU reservation when running with `-blockmaxweight` close to MAX_BLOCK_WEIGHT (where the default reservation leaves too little tx space). Core: `node/miner.cpp:107`. |
| 3 | … | G9: -printpriority parsed | **BUG-8 (P2)** — debug helper absent. Core: `node/miner.cpp:105`. |
| 3 | … | G10: -blockversion=N regtest override | **BUG-9 (P1)** — Core allows `-blockversion=N` on regtest for fork-testing (`node/miner.cpp:143-145`); hotbuns hardcodes via `computeNextBlockVersion`. Affects `forknotify`-style consensus regression tests. |
| 4 | addChunks selection algorithm | G11: per-tx isFinalTx check (TestChunkTransactions) | PARTIAL — `mining/template.ts:376` (dead helper) checks. **BUG-10 (P0-CDIV, W123 BUG-1 re-anchored)** — getBlockTemplate RPC iterates `mempool.getAllTxids()` without finality check; a time-locked tx that's NOT yet final at the new block's MTP gets included → naive miner produces `bad-txns-nonfinal` block rejected by every peer. |
| 4 | … | G12: MAX_BLOCK_WEIGHT gate uses `>=` | PARTIAL — `mining/template.ts:400` correct (helper). **BUG-11 (P0-CDIV, W123 BUG-2 re-anchored)** — getBlockTemplate RPC has NO weight gate at all (only sigops); a fat mempool produces > 4_000_000 WU template. |
| 4 | … | G13: MAX_BLOCK_SIGOPS_COST gate uses `>=` | **BUG-12 (P0-CDIV, W123 BUG-4 re-anchored)** — server.ts:5081 uses `>` not `>=`. A tx that pushes total sigops to exactly 80_000 is admitted; Core (`node/miner.cpp:244`) rejects equality. Hotbuns blocks the network rejects. |
| 4 | … | G14: MAX_CONSECUTIVE_FAILURES=1000 + BLOCK_FULL_ENOUGH_WEIGHT_DELTA=4000 early-exit | PARTIAL — present in helper. **BUG-13 (P1, W123 BUG-5 re-anchored)** — getBlockTemplate RPC has NO early-exit; on a 50k-entry mempool every entry is tried. |
| 4 | … | G15: cluster-mempool chunk-feerate selection (GetBlockBuilderChunk) | **BUG-14 (P1)** — `mempool.getTransactionsByFeeRate()` (`mempool.ts:2608-2615`) returns `Array.from(this.entries.values()).sort((a,b) => b.feeRate - a.feeRate)` — a flat single-tx fee-rate sort. Core's `GetBlockBuilderChunk` returns the next-best **chunk** (package linearization), not the next-best single tx. Result: a tx with a high-feerate child and a low-feerate parent gets included separately, breaking package-feerate ordering. Effective revenue loss vs Core on competitive mempools. |
| 5 | Coinbase construction | G16: `vin[0].nSequence == MAX_SEQUENCE_NONFINAL (0xFFFFFFFE)` | PARTIAL — helper correct. **BUG-15 (P0-CDIV, W123 BUG-5 re-anchored)** — `generateSingleBlock`'s `buildCoinbaseTx` / `buildCoinbaseTxWithWitnessCommitment` use `sequence: 0xffffffff`. With SEQUENCE_FINAL, IsFinalTx ignores nLockTime; the BIP-34 height timelock has no effect. Core comment at `node/miner.cpp:171`: "Make sure timelock is enforced." |
| 5 | … | G17: `nLockTime == nHeight - 1` | PARTIAL — helper correct. **BUG-16 (P0-CDIV, W123 BUG-6 re-anchored)** — `generateSingleBlock`'s coinbase builders set `lockTime: 0` (server.ts:5647, 5691). Core (`node/miner.cpp:196`): `coinbaseTx.nLockTime = static_cast<uint32_t>(nHeight - 1)`. |
| 5 | … | G18: include_dummy_extranonce OP_0 for h ≤ 16 | **BUG-17 (P1, W123 BUG-20 re-anchored)** — neither helper nor RPC appends `OP_0` to the scriptSig when h ≤ 16. Core scriptSig is `CScript() << nHeight` which is exactly 1 byte for height 1..16, so without the dummy `OP_0` push the coinbase fails `bad-cb-length` (min 2 bytes). Regtest test-suites that mine from genesis trip this on block 1..16. |
| 5 | … | G19: scriptSig length 2..100 bytes enforced | PASS — `validation/block.ts:537` enforces, but only on `submitBlock` path (cf. BUG-2). |
| 5 | … | G20: `vout[0].nValue == nFees + GetBlockSubsidy(nHeight, params)` (params-aware) | **BUG-18 (P0-CDIV)** — `getBlockSubsidy` at `server.ts:5789-5799` hardcodes `HALVING_INTERVAL = 210_000` instead of consulting `this.params.subsidyHalvingInterval`. On regtest (`subsidyHalvingInterval = 150`) the RPC computes the WRONG subsidy past h=150; `coinbasevalue` in GBT is also wrong; `generateSingleBlock` at server.ts:5502 happens to use the CORRECT params-aware `getBlockSubsidy(height, this.params)` import, so the two callsites disagree. This is **W145 BUG-1 carry-forward** at the RPC layer (the validator-side `consensus/params.ts:getBlockSubsidy` IS params-aware; the RPC's private helper is not — classic "two-pipeline guard" pattern: 17th distinct extension across fleet). |
| 5 | … | G21: BIP-34 minimal CScriptNum encoding | PASS — `encodeBIP34Height` at server.ts:5698-5717 matches Core. |
| 5 | … | G22: witness nonce = 32 zero bytes | PASS — server.ts:5537, helper:244. |
| 6 | GenerateCoinbaseCommitment (BIP-141) | G23: OP_RETURN PUSH36 0xaa21a9ed marker | PASS — `0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed` in helper (template.ts:145, 515) AND RPC (server.ts:5252, 5664). |
| 6 | … | G24: commitment = hash256(BlockWitnessMerkleRoot || witness_nonce) | PASS — implemented in both paths. **BUT** cross-cite BUG-2: `generateSingleBlock` does not call `validateBlock` so a producer that builds the wrong commitment would NOT be detected locally before broadcast. |
| 6 | … | G25: idempotent — skip if commitment already present | **BUG-19 (P1)** — `RegenerateCommitments` analog absent. Core's `node/miner.cpp:67-77` `RegenerateCommitments(block, chainman)` is what `submitheader`/external miner-pool integration uses to swap in a different coinbase scriptSig and rebuild the commitment + merkle root. hotbuns has no exported function with this contract; `getBlockTemplate` returns the commitment as a hex string and trusts the miner to splice it correctly. |
| 7 | UpdateTime / GetMinimumTime | G26: timestamp = max(now, MTP+1) | PARTIAL — helper (template.ts:265-267) correct. `getBlockTemplate` (server.ts:5145-5147) correct (`mintime = MTP + 1`). **BUG-20 (P0-CDIV, W123 BUG-19 re-anchored)** — `generateSingleBlock` (server.ts:5565) uses `Math.floor(Date.now() / 1000)` with **NO MTP+1 floor**. On a fresh regtest chain whose tip was produced ahead of wall-clock (rare but possible with `-mocktime`), the next-block timestamp is < MTP+1 and the block is rejected with `time-too-old`. |
| 7 | … | G27: BIP-94 timewarp clamp `parent_time - MAX_TIMEWARP` at retarget boundary, **on all networks** | **BUG-21 (P0-CDIV, W123 BUG-15 re-anchored)** — neither mining path applies the `min_time = max(min_time, parent->GetBlockTime() - MAX_TIMEWARP)` clamp at `height % difficulty_adjustment_interval == 0`. The validator side enforces BIP-94 in `sync/headers.ts:572-583` but **only when `params.enforce_BIP94 == true`** (testnet4 / regtest with the flag). Core's MINER side applies the clamp on ALL networks (`node/miner.cpp:41-44` comment: "Account for BIP94 timewarp rule on all networks. This makes future activation safer"). hotbuns may produce mainnet retarget-boundary blocks with timestamp violations after some future soft-fork activates BIP-94 on mainnet. Cross-cite W143 BUG-10 (`validateBlockHeader` DEAD production code also lacks the clamp). |
| 7 | … | G28: GetMinimumTime exported as standalone API | **BUG-22 (P1)** — Core exports `GetMinimumTime(pindexPrev, difficulty_adjustment_interval)` (miner.h:130) so the mintime calculation can be shared between `BlockAssembler::CreateNewBlock`, `WaitAndCreateNewBlock`, and the RPC `getblocktemplate`. hotbuns recomputes mintime in two places (template.ts:265-267 and server.ts:5145-5147) with subtly different boundary conditions (helper falls back to `medianTimePast`, RPC falls back to `curtime`). |
| 8 | nVersion derivation | G29: BIP-9 ComputeBlockVersion(pindexPrev, params) | PARTIAL — `computeNextBlockVersion(height)` is wired at server.ts:5153 + 5559 and template.ts:274-281. **BUT** the helper signature passes only `parentHeight` not `pindexPrev`; deployment STARTED bits may compute incorrectly mid-fork-window when ancestor lookup is needed for `getStateFor`. Helper falls back to VERSIONBITS_TOP_BITS when `getHeaderByHeight` is undefined. |
| 9 | submitblock + BIP-22 strings | G30: submitblock returns BIP-22 strings (high-hash, time-too-old, rejected, inconclusive, duplicate) | PASS — server.ts:4912-5013 covers high-hash, time-too-old, rejected; `sync/blocks.ts:844,896,906` covers inconclusive + duplicate. Cross-cite BUG-2: validateBlock runs only here, not on mined blocks. |
| 9 | … | G31: submitheader RPC | **BUG-23 (P1, W123 BUG-12 re-anchored)** — `submitheader` is not a registered RPC method. External miner pools and `bitcoin-cli submitheader` operations against hotbuns return method-not-found. |
| 10 | prioritisetransaction / getprioritisedtransactions | G32: prioritisetransaction RPC | **BUG-24 (P1, W123 BUG-13 re-anchored)** — not registered. Mempool entries have no `feeDelta` field (`mempool/persist.ts:301` candidly notes "hotbuns lacks a tx-level feeDelta"); operator cannot pin or de-prioritise a tx in the next block template. |
| 10 | … | G33: getprioritisedtransactions RPC | **BUG-25 (P1, W123 BUG-14 re-anchored)** — not registered. |
| 11 | getmininginfo fields | G34: currentblockweight + currentblocktx (m_last_block_weight / m_last_block_num_txs) | **BUG-26 (P1, W123 BUG-10 re-anchored)** — both fields absent. Core (`rpc/mining.cpp:467-468`) publishes these after every `CreateNewBlock`; consumers (pools' getmininginfo dashboards) cannot see the last assembled block's stats. Root cause: no equivalent of `BlockAssembler::m_last_block_weight` static. |
| 11 | … | G35: networkhashps delegates to getnetworkhashps | **BUG-27 (P1, W123 BUG-9 re-anchored)** — server.ts:7491 returns `networkhashps: 0` hardcoded. `getNetworkHashPS` is implemented but unwired. |
| 11 | … | G36: next.bits / next.target via NextEmptyBlockIndex + GetNextWorkRequired (the NEXT block's target, not the tip's) | **BUG-28 (P0-CDIV, W123 BUG-8 re-anchored)** — `getmininginfo` reports the TIP's bits/target as `next.bits` / `next.target` (server.ts:7496-7498). Operators rely on this to decide whether to call `getblocktemplate`; a miner who keys off `getmininginfo.next.bits` would mine at the wrong difficulty for the next block (relevant at retarget boundary blocks 2016, 4032, …). |

(Behaviours 12-14 below — pre-submit, BIP-22 mode=proposal, BIP-22 longpoll, template caching — covered by W123 carry-forwards BUG-29..32.)

| 12 | BIP-22 mode=proposal | G37: getblocktemplate accepts `mode=proposal` for offline block validation | **BUG-29 (P1, W123 BUG-11 re-anchored)** — server.ts:5048 explicitly throws "Only 'template' mode is supported". |
| 12 | … | G38: BIP-22 longpoll honored on subsequent calls (waitTipChanged / nTransactionsUpdatedLast) | **BUG-30 (P1, W123 BUG-17 re-anchored)** — `longpollid` is emitted but the RPC returns immediately; no wait loop. |
| 12 | … | G39: template caching when pindexPrev == tip AND mempool unchanged | **BUG-31 (P1, W123 BUG-18 re-anchored)** — getBlockTemplate rebuilds from scratch every call. Core caches via `block_template` + `nTransactionsUpdatedLast`. On a chain at IBD-recovery tip with high mempool churn, a busy pool's repeated GBT calls hit the worst-case O(N) mempool walk every time. |
| 13 | Pre-submit RPC guards | G40: getblocktemplate refuses while in IBD (RPC_CLIENT_IN_INITIAL_DOWNLOAD) | **BUG-32 (P0-RPC, W123 BUG-16 re-anchored)** — no `isInitialBlockDownload` check; a node in IBD would happily emit a template based on the in-progress headers. Core: `rpc/mining.cpp` `RPC_CLIENT_IN_INITIAL_DOWNLOAD` early-rejects. |
| 13 | … | G41: getblocktemplate refuses with 0 peers (RPC_CLIENT_NOT_CONNECTED) | **BUG-32 cross-cite** — also missing. |

---

## BUG-1 (P0-DEAD, re-anchored) — `BlockTemplateBuilder` is dead code

**Severity:** P0-DEAD. `src/mining/template.ts` is 685 lines and 62
passing tests, all targeted at the correctly-W14/W63-fixed
`BlockTemplateBuilder.createTemplate`. The two production RPC entry
points (`getBlockTemplate` and `generateSingleBlock` in
`src/rpc/server.ts`) re-implement the logic by hand and bring back
every W14/W63 bug. **33rd-consecutive audit wave to find this exact
pattern**; W123 BUG-21 was the first explicit catalogue, **still
unfixed after ~5 weeks** (W123 was 2026-05-17; today is 2026-05-18 but
the carry-forward dates W123→W154 across multiple intervening waves).

```
$ grep -c "new BlockTemplateBuilder" src/rpc/server.ts
0
$ grep -c "from \"../mining/template" src/rpc/server.ts
1                     # import line exists; constructor never invoked
$ wc -l src/mining/template.ts
685 src/mining/template.ts
$ grep -c "describe\|it(\|test(" src/mining/template.test.ts
62
```

Impact: every single production mining call (`getblocktemplate`,
`generatetoaddress`, `generatetodescriptor`, `generateblock`) hits the
buggy hand-rolled path, never the correct helper. The unit-test
coverage is real but exercises no production code path.

**Cross-cite fleet pattern:** "test-suite-shape-masks-production-bug"
(W153 NEW); "wiring-look-but-no-wire" (5+ hotbuns instances).

---

## BUG-2 (P0-CDIV) — `generateSingleBlock` ships a HALF-FINISHED pipeline; no structural validation before connectBlock

**Severity:** P0-CDIV. The regtest mining RPCs (`generatetoaddress`,
`generatetodescriptor`, `generateblock`) build a block locally and pipe
it straight into `chainState.connectBlock` without running
`validateBlock`. The structural gates (merkle-root recompute, BIP-34
height encoding, coinbase scriptSig 2..100 bytes, block weight,
`checkWitnessMalleation`) ALL run only inside `validateBlock`
(`validation/block.ts:517-611`), which is invoked exclusively from
`submitBlock` (`server.ts:4998`).

**File:** `src/rpc/server.ts:5492-5619` — `generateSingleBlock`. Builds
header at L5561, hashes the coinbase (with possibly malformed witness
commitment) at L5523-5550, then `await this.chainState.connectBlock(block, height)`
at L5598. Note `chainState.connectBlock` itself (chain/state.ts:286-473)
runs `coreConnectBlockChecks` but ALSO skips `validateBlock` /
`checkWitnessMalleation` — those are upstream-only gates expected to
have run in the caller.

```ts
// src/rpc/server.ts:5586-5618 (current)
const block: Block = {
  header,
  transactions: allTxs,
};

// ... mine nonce ...

if (submit) {
  // NO validateBlock(block, height, this.params) call here.
  await this.chainState.connectBlock(block, height);
  // ...
  this.broadcastBlockInv(blockHash);
  ...
}
```

```ts
// src/rpc/server.ts:4997-5002 (submitBlock — the other entry-point — DOES validate)
const structCheck = validateBlock(block, approxHeight, this.params);
if (!structCheck.valid) {
  const reason = structCheck.error ?? "rejected";
  return bip22Result(reason);
}
```

**Core ref:** Core's `BlockAssembler::CreateNewBlock` calls
`TestBlockValidity(check_pow=false, check_merkle_root=false)` at
`node/miner.cpp:225-227` and throws on failure. hotbuns's miner-side
has no equivalent.

**Impact:**

1. A bug in `buildCoinbaseTxWithWitnessCommitment` (e.g. wrong
   `0xaa21a9ed` marker bytes) would NOT be caught locally before
   `broadcastBlockInv` fan-out — peers reject the block but the local
   node already advanced its tip via `connectBlock`. Result: local +
   remote view of the chain DIVERGE silently for the freshly-mined
   block until a competing block displaces it.
2. The dummy-extranonce omission (BUG-17) means generate*RPCs at h=1..16
   produce a 1-byte scriptSig that submitBlock would reject as
   `bad-cb-length`, but the miner-side accepts it locally — a
   self-contradicting node.
3. Same shape as **ouroboros W143 BUG-7** "ships HALF-FINISHED
   pipeline (BIP-34/30/weight/sigops/CheckTx all missing)" — extends
   the fleet pattern.
4. The fleet **"Reorg-skips-CheckBlock"** archetype (lunarblock W143
   BUG-3) generalises to **"Mine-side-skips-CheckBlock"** here.

---

## BUG-18 (P0-CDIV) — Two parallel `getBlockSubsidy` implementations diverge on `subsidyHalvingInterval`

**Severity:** P0-CDIV (W145 BUG-1 carry-forward at the RPC layer — **17th
distinct "two-pipeline guard" instance** across the fleet tracking).

There are two implementations of `getBlockSubsidy` in hotbuns:

1. **`src/consensus/params.ts:1046-1062`** — the canonical, params-aware
   helper. Reads `params.subsidyHalvingInterval` (mainnet=210_000,
   regtest=150). Correctly used by `generateSingleBlock` (server.ts:5502)
   AND `consensus/connect_block.ts:462`.

2. **`src/rpc/server.ts:5789-5799`** — a hardcoded private helper used
   by `getBlockTemplate` (server.ts:5116):
   ```ts
   private getBlockSubsidy(height: number): bigint {
     const INITIAL_SUBSIDY = 5_000_000_000n; // 50 BTC in satoshis
     const HALVING_INTERVAL = 210_000;       // ← HARDCODED, IGNORES params
     ...
   }
   ```

**Impact:** On regtest (`subsidyHalvingInterval = 150`), after height
150 the `coinbasevalue` field in `getblocktemplate` is **wrong**
(reports 25 BTC when the next block should pay only 25 BTC at h=150 but
12.5 BTC at h=300, etc.; the hardcoded path still reports 50 BTC). A
pool that trusts the GBT `coinbasevalue` and constructs the coinbase
accordingly would produce a block that fails `bad-cb-amount` at
`connectBlock` time. Pre-existing W145 BUG-1 in blockbrew is the same
class — that carry-forward has been open ~3 weeks; here it's still
fresh at the hotbuns RPC layer.

**Two-pipeline guard:** the `coreConnectBlockChecks` validator path
uses (1); the RPC GBT path uses (2). Different answers for the same
height once past `params.subsidyHalvingInterval` if that ≠ 210_000.

---

## BUG-21 (P0-CDIV) — Miner does not enforce BIP-94 timewarp clamp on any network

**Severity:** P0-CDIV (W123 BUG-15 re-anchored, still unfixed; cross-cite
W143 BUG-10 — `validateBlockHeader` DEAD production code).

Core's miner enforces `min_time = max(min_time, parent->GetBlockTime() -
MAX_TIMEWARP)` at `height % DifficultyAdjustmentInterval() == 0` on
**ALL networks**, with explicit comment:

```cpp
// node/miner.cpp:41-44
// Account for BIP94 timewarp rule on all networks. This makes future
// activation safer.
if (height % difficulty_adjustment_interval == 0) {
    min_time = std::max<int64_t>(min_time, pindexPrev->GetBlockTime() - MAX_TIMEWARP);
}
```

hotbuns has the constant `MAX_TIMEWARP = 600` ONLY in `sync/headers.ts:575`,
gated on `this.params.enforce_BIP94` (i.e. testnet4 / regtest with the
flag). Neither mining path (template.ts:265-267 or server.ts:5145-5147)
applies the clamp.

**Impact:** when BIP-94 activates on mainnet (currently slated for a
future soft-fork), every hotbuns miner will produce mainnet retarget-
boundary blocks (heights 2016, 4032, …) that violate the clamp if the
operator's wall-clock drifts < parent_time - 600. The Core comment
explicitly flags this as a forward-compat issue: the clamp is
unconditional in Core's miner precisely so existing pools don't ship a
buggy first block when BIP-94 lights up.

---

## Carry-forward catalogue (W123 / W144 / W145 / W153 prior bugs RE-CONFIRMED)

This audit re-anchors prior findings as still-unfixed at HEAD. Numbering
in parens is the original wave's bug index.

### From W123 (mining/GBT, 2026-05-17 — primary source)

- W123 BUG-1 (no isFinalTx in getBlockTemplate) → W154 BUG-10 ✘
- W123 BUG-2 (no MAX_BLOCK_WEIGHT gate in getBlockTemplate) → W154 BUG-11 ✘
- W123 BUG-3 (BLOCK_RESERVED_WEIGHT=8000 not applied in getBlockTemplate) → W154 BUG-3 ✘
- W123 BUG-4 (sigops gate uses `>` not `>=`) → W154 BUG-12 ✘
- W123 BUG-5 (generateSingleBlock sequence=SEQUENCE_FINAL) → W154 BUG-15 ✘
- W123 BUG-6 (generateSingleBlock lockTime=0) → W154 BUG-16 ✘
- W123 BUG-7 (generateSingleBlock target=powLimit not getNextTarget) → folded into W154 BUG-2 ✘
- W123 BUG-8 (getmininginfo next.bits = tip.bits) → W154 BUG-28 ✘
- W123 BUG-9 (getmininginfo networkhashps=0) → W154 BUG-27 ✘
- W123 BUG-10 (currentblockweight/tx missing) → W154 BUG-26 ✘
- W123 BUG-11 (mode=proposal rejected) → W154 BUG-29 ✘
- W123 BUG-12 (submitheader RPC missing) → W154 BUG-23 ✘
- W123 BUG-13 (prioritisetransaction RPC missing) → W154 BUG-24 ✘
- W123 BUG-14 (getprioritisedtransactions RPC missing) → W154 BUG-25 ✘
- W123 BUG-15 (BIP-94 timewarp clamp absent in miner) → W154 BUG-21 ✘
- W123 BUG-16 (no IBD/peer guard on GBT) → W154 BUG-32 ✘
- W123 BUG-17 (longpoll not honored) → W154 BUG-30 ✘
- W123 BUG-18 (no template caching) → W154 BUG-31 ✘
- W123 BUG-19 (generateSingleBlock timestamp lacks MTP+1 floor) → W154 BUG-20 ✘
- W123 BUG-20 (no OP_0 dummy for h≤16) → W154 BUG-17 ✘
- W123 BUG-21 (BlockTemplateBuilder is dead code) → W154 BUG-1 ✘
- W123 BUG-22 (-blockmintxfee not parsed) → W154 BUG-6 ✘

**Carry-forward count: 22 of 22 still present.** Pure re-anchor wave.

### From W144 (script-verify flags, 2026-05-18)

- **W144 BUG-3** scriptFlagsFromBitmask derives DERSIG/CLTV/CSV/NULLDUMMY
  from `verifyWitness` bit instead of their own bits. **STILL UNFIXED**
  at `src/script/interpreter.ts:3062-3065`. Miner side is affected when
  `verifyInputSignature` is called from `coreConnectBlockChecks`: on
  mainnet replay, h=363,725..481,823 (after BIP-66 / before SegWit)
  has `verifyWitness=false` ⇒ DERSIG bypassed ⇒ 118k-block IBD
  divergence. Mining-side (`generateSingleBlock` → `chainState.connectBlock`
  → `coreConnectBlockChecks` with `verifyWitness = height >= params.segwitHeight`)
  is exposed if anyone re-validates mined blocks via the IBD path
  (e.g. backfill, reindex). On REGTEST this doesn't fire because
  `segwitHeight=0` ⇒ `verifyWitness=true` always. Mainnet relay only.

### From W145 (subsidy/fees/MAX_MONEY, 2026-05-18)

- **W145 BUG-2..6 (Assume-valid scope creep)** — origin pattern:
  `coreConnectBlockChecks` (connect_block.ts:411-480) under `assumeValid`
  skips **maturity checks, BIP-68, sigops counting, script verification,
  AND** the per-tx CheckTxInputs gates (MoneyRange on coin.out.nValue,
  MoneyRange on accumulated nValueIn, bad-txns-in-belowout,
  bad-txns-fee-outofrange). Core assume-valid skips ONLY `fScriptChecks`
  (signature verification). **STILL UNFIXED.** Mining-side
  (chain/state.ts:344-353) pins `assumeValid: false, skipScripts: false`
  so miner-side itself is safe, BUT the IBD path
  (sync/blocks.ts:2477-2588) sets `assumeValid = height <= assumeValidHeight`
  and the broken assume-valid fast path fires whenever IBD crosses an
  AssumeValid-marked block. The hotbuns-named "Assume-valid scope creep"
  pattern from W145 remains an active P0-SEC.

### From W153 (mempool eviction / min-relay, 2026-05-18)

- **W153 BUG-5** `DEFAULT_MIN_RELAY_TX_FEE = 0` (zero floor). Confirmed
  not present anywhere in hotbuns source (`grep DEFAULT_MIN_RELAY_TX_FEE`
  returns no matches). Affects miner via BUG-6 above (`-blockmintxfee`
  not parsed) AND via `getmempoolinfo` reporting `minrelaytxfee: 0.00001`
  hardcoded. A miner using `getblocktemplate` to pick transactions has
  no floor to skip dust-fee txs.

- **W153 BUG-12** `sync/blocks.ts::connectBlock` NEVER emits
  `blockConnected`. Confirmed: `grep -n "blockConnected\|notificationEmitter"
  src/sync/blocks.ts` returns ZERO matches. Mining-side
  (chain/state.ts:471) DOES emit `blockConnected`. **Asymmetric** — the
  test-suite path (which exercises chain/state.ts via generateblock)
  sees the event; production IBD never does. Same fleet pattern as
  "test-suite-shape-masks-production-bug" (W153 NEW). Affects ZMQ
  consumers (electrs, fulcrum, mempool.space, nbxplorer) during IBD —
  they never get `hashblock`/`rawblock` notifications until the operator
  manually triggers a generateblock or until IBD completes and a peer
  pushes a fresh block via the mining-side path. Crosses W141 (ZMQ /
  REST / notify) territory.

### From W143 (block validation, 2026-05-18)

- **W143 BUG-10** `validateBlockHeader` DEAD production code lacks
  BIP-94 timewarp. Confirmed: production callers count = 0 (only
  `block.test.ts` references it). The check IS implemented in
  `sync/headers.ts:572-583` (HeaderSync.processHeader path), so the
  reject side is covered — but the standalone exported
  `validateBlockHeader` is unused. The MINER does not run
  `validateBlockHeader` on candidate headers; cross-cite W154 BUG-2
  (no validateBlock either).

---

## Fleet-pattern checklist (this audit)

| Pattern | Instance in W154 |
|---------|------------------|
| **dead-helper at the call-site** | BUG-1 (33rd consecutive wave; W123 BUG-21 still unfixed at 30 days) |
| **two-pipeline guard** | BUG-18 (`getBlockSubsidy` hardcoded RPC vs params-aware validator — **17th distinct** fleet instance) |
| **three-pipeline drift** | (none new this wave — but BUG-18 + helper + validator = 3 callsites for the same computation) |
| **comment-as-confession** | template.ts:262-264 "Bug fix 7: block timestamp must be >= MTP+1 ... `node/miner.cpp:36-47`" — the helper has the citation but the production RPC `generateSingleBlock` doesn't apply the rule (BUG-20). 12th hotbuns instance. |
| **wiring-look-but-no-wire** | BUG-1 — import line exists, no constructor call (5th+ hotbuns). |
| **Mine-side-skips-CheckBlock** (NEW) | BUG-2 — generalises lunarblock W143 "Reorg-skips-CheckBlock" to the mining side. Both share the shape "production callsite bypasses the shared CheckBlock gate that other callsites use". |
| **test-suite-shape-masks-production-bug** | BUG-1 (62 tests against dead helper) + W153 BUG-12 carry-forward + BUG-2 (validateBlock tests run on `submitBlock`-path blocks not `generateBlock`-path blocks). 4th hotbuns confirmation since W153. |
| **regression-as-fix** (W153 NEW) | (none new; W153 origin pattern was sync/blocks.ts hot-path) |
| **Assume-valid scope creep** | W145 BUG-2..6 carry-forward — still unfixed. Mining-side immune (state.ts pins assumeValid=false) but IBD path remains broken. |
| **carry-forward re-anchor** | 22 of 22 W123 bugs still present; pure re-anchor wave (W123 was DISCOVERY too). The fix-wave never landed. |
| **decoder accepts superset-of-encoder** | (none new this wave) |
| **asymmetric defensive depth** | BUG-2 (submitBlock DOES validateBlock; generateBlock DOES NOT — same node, two different entry points to the chain) |
| **shape-gated NOT flag-gated** | W144 BUG-3 carry-forward, see above |
| **reject-string wire-parity slippage** | (none new this wave) |
| **dead-data BIP9 plumbing** | (covered by BUG-9 `-blockversion` regtest-only override not wired) |
| **CheckTransaction-not-replayed-at-cache-mutation** | (no cache-mutation paths in miner side) |
| **docstring-contradicts-Core** | (none new this wave) |
| **BLOCK_MUTATED vs BLOCK_CONSENSUS distinction lost** | BUG-2 indirectly — no MUTATED detection on freshly mined block (CVE-2012-2459 class) |
| **code-duplication smell — byte-identical helpers** | BUG-1 (`buildCoinbaseTx` + `buildCoinbaseTxWithWitnessCommitment` in server.ts duplicate `mining/template.ts:buildCoinbase`) |
| **exception-map short-circuit elides Core fall-through** | (none new — script flag exceptions live in W144) |
| **scan-direction-reversed-with-correct-constants** | (none new) |
| **default-install-X** patterns | BUG-5 (-blockmaxweight not parsed → default 4_000_000 with no operator override). |

---

## Severity / priority summary

- **P0-CDIV (consensus-divergent on production code path)**: 10
  - BUG-2 (no validateBlock on mined blocks; merkle/witness/coinbase
    structural gates bypassed)
  - BUG-10, BUG-11, BUG-12 (W123 carry-forwards in getBlockTemplate
    selection)
  - BUG-15, BUG-16 (W123 carry-forwards in coinbase
    sequence/lockTime)
  - BUG-18 (two-pipeline `getBlockSubsidy`)
  - BUG-20 (timestamp lacks MTP+1)
  - BUG-21 (no BIP-94 clamp in miner)
  - BUG-28 (getmininginfo next.bits returns tip.bits)
- **P0-DEAD (dead-code with hidden non-parity)**: 1
  - BUG-1 (BlockTemplateBuilder)
- **P0-RPC (RPC contract / operator-experience)**: 3
  - BUG-3 (BLOCK_RESERVED_WEIGHT not applied)
  - BUG-5 (-blockmaxweight not parsed)
  - BUG-6 (-blockmintxfee not parsed)
  - BUG-32 (no IBD/peer guard on GBT — W123 BUG-16)
- **P1**: 14
  - BUG-4 (MINIMUM_BLOCK_RESERVED_WEIGHT floor)
  - BUG-7 (-blockreservedweight not parsed)
  - BUG-9 (-blockversion regtest override)
  - BUG-13 (MAX_CONSECUTIVE_FAILURES early-exit in RPC)
  - BUG-14 (cluster-mempool chunk-feerate selection)
  - BUG-17 (no OP_0 dummy h≤16)
  - BUG-19 (no RegenerateCommitments analog)
  - BUG-22 (GetMinimumTime not exported standalone)
  - BUG-23 (submitheader missing)
  - BUG-24, BUG-25 (prioritise* RPCs missing)
  - BUG-26 (currentblockweight/tx missing)
  - BUG-27 (networkhashps hardcoded 0)
  - BUG-29 (mode=proposal rejected)
  - BUG-30 (longpoll not honored)
  - BUG-31 (no template caching)
- **P2**: 1
  - BUG-8 (-printpriority not parsed)

**Total: 32 NEW + RE-ANCHORED bugs catalogued.**

(Net new findings this wave: 10 — BUG-1 [re-anchor of W123 BUG-21],
BUG-2 [NEW: no validateBlock on mined blocks], BUG-4, BUG-5, BUG-7,
BUG-8, BUG-9, BUG-14, BUG-19, BUG-22.

Pure carry-forwards: 22 of W123, 1 of W144 [scoped to miner side], 5 of
W145 [scoped to miner side], 2 of W153, 1 of W143.)

---

## Priority fix recommendations (Top 5)

1. **BUG-1 (BlockTemplateBuilder dead-helper)** — wire the production
   RPCs to the existing helper. Closes BUG-3, BUG-10, BUG-11, BUG-12,
   BUG-13, BUG-20, BUG-15, BUG-16 simultaneously (each is a "RPC path
   reimplements logic the helper already has correctly"). Estimated
   diff: ~40 LOC across `getBlockTemplate` + `generateSingleBlock`.
   This is the single highest-leverage fix in this audit.
2. **BUG-2 (no validateBlock before connectBlock on mined blocks)** —
   one-line insert `const v = validateBlock(block, height, this.params);
   if (!v.valid) throw rpcError(...);` immediately before
   `chainState.connectBlock`. Closes the "local accepts, peers reject"
   asymmetry; surfaces witness-commitment and merkle bugs at submit time
   instead of after broadcast.
3. **BUG-18 (two-pipeline getBlockSubsidy)** — delete the hardcoded
   `getBlockSubsidy` private helper in server.ts (lines 5789-5799) and
   import the params-aware `consensus/params.ts::getBlockSubsidy`.
   1-line fix. Closes W145 BUG-1 at the RPC layer.
4. **BUG-28 (getmininginfo next.bits returns tip.bits)** — wire the
   existing `headerSync.getNextTarget(parentEntry, curtime)` (already
   used by `getBlockTemplate` at server.ts:5132) into `getMiningInfo`
   for the `next` sub-object. ~5 LOC.
5. **BUG-21 (BIP-94 timewarp clamp absent in miner on all networks)** —
   add the `min_time = max(min_time, parent_time - MAX_TIMEWARP)` clamp
   in `getBlockTemplate`'s `mintime` computation (and helper's
   timestamp computation) when `height % difficultyAdjustmentInterval == 0`,
   on all networks. Forward-compat with mainnet BIP-94 activation. ~10
   LOC.

---

## Audit confidence + open questions

- All 22 W123 carry-forwards verified at HEAD by `grep` + line-number
  checks against `src/rpc/server.ts` and `src/mining/template.ts`.
- BUG-2 verified by `grep -n "validateBlock\b" src/rpc/server.ts` →
  only one production callsite (`submitBlock` at line 4998), zero in
  `generateSingleBlock` (lines 5492-5619).
- BUG-18 verified by reading both `consensus/params.ts:1046-1062`
  (params-aware) AND `rpc/server.ts:5789-5799` (hardcoded 210_000); the
  RPC `getBlockTemplate` (server.ts:5116) calls `this.getBlockSubsidy`
  not the imported one.
- BUG-21 verified by `grep -rn "MAX_TIMEWARP" src/` → only `sync/headers.ts`
  (header-validator) instance, gated on `enforce_BIP94`. Neither
  `mining/template.ts` nor `rpc/server.ts` has the constant.
- W144 BUG-3 carry-forward verified by reading
  `src/script/interpreter.ts:3053-3072` — `verifyDERSignatures`,
  `verifyCheckLockTimeVerify`, `verifyCheckSequenceVerify`,
  `verifyNullDummy` all set from `verifyWitness` not from their own
  bitmask bits.
- W145 BUG-2..6 carry-forward verified by reading
  `src/consensus/connect_block.ts:411-480` — assume-valid fast path
  still skips maturity, BIP-68, sigops, scripts, and per-coin/per-tx
  CheckTxInputs gates. Mining side is currently immune because
  `chain/state.ts:344-353` pins `assumeValid: false`.
- W153 BUG-12 carry-forward verified by `grep -n "blockConnected\|
  notificationEmitter" src/sync/blocks.ts` → zero matches.

**Open question for fix-wave planner:** the W123 → W154 carry-forward
list (22 bugs) is identical at HEAD. Either (a) W123 was a pure
discovery wave with no follow-up fix, or (b) intermediate fix waves
W124-W153 deliberately skipped mining/GBT as low-priority pre-mainnet.
Recommend a dedicated W155-FIX wave to land BUG-1 (which automatically
closes 8 of the W123 carry-forwards).
