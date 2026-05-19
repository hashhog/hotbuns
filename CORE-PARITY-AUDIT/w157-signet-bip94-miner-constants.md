# W157 — Signet block solution + BIP-94 timewarp + miner-side header constants (hotbuns)

**Wave:** W157 — `CheckSignetBlockSolution`, `SIGNET_HEADER (0xecc7daa2)`,
`FetchAndClearCommitmentSection`, `SignetTxs::Create`, `signet_challenge`
consensus parameter, `signet_blocks` flag, `MAX_TIMEWARP = 600` (consensus.h:35),
`enforce_BIP94` (consensus/params.h:121), `GetMinimumTime`
(node/miner.cpp:36-47) miner-side BIP-94 clamp, `UpdateTime`, `nVersion`
BIP-9 signaling at the miner, `nBits` retarget at the miner side, signet
default challenge.

**Scope:** discovery only — no production code changes.

**Bitcoin Core references**
- `bitcoin-core/src/signet.cpp:28` — `SIGNET_HEADER[4] = {0xec, 0xc7, 0xda, 0xa2}`.
- `bitcoin-core/src/signet.cpp:30` — `BLOCK_SCRIPT_VERIFY_FLAGS = P2SH | WITNESS | DERSIG | NULLDUMMY`
  for signet block-solution script verification (intentionally NOT the same
  bitmask as consensus-mode script verification).
- `bitcoin-core/src/signet.cpp:32-57` — `FetchAndClearCommitmentSection(header, witness_commitment, result)`
  walks the witness-commitment scriptPubKey, finds the first push that begins
  with `SIGNET_HEADER`, extracts the trailing bytes as `result`, and rewrites
  `witness_commitment` with the header+payload stripped from that push so the
  modified-merkle hash commits to the block AS IF the signature had not been
  added.
- `bitcoin-core/src/signet.cpp:59-67` — `ComputeModifiedMerkleRoot(modified_cb, block)`:
  rebuilds the merkle tree with the modified coinbase at index 0 and all other
  txids unchanged.
- `bitcoin-core/src/signet.cpp:70-123` — `SignetTxs::Create(block, challenge)`:
  builds `tx_to_spend` (version=0, prevout=null, vout = challenge script) and
  `tx_to_sign` (version=0, vin[0] populated from `signet_solution` parsed as
  CTxIn::scriptSig + CScriptWitness::stack via `SpanReader`, vout = OP_RETURN);
  returns nullopt on coinbase absence, missing witness commitment, or extraneous
  data after the parsed sig+witness.
- `bitcoin-core/src/signet.cpp:126-153` — `CheckSignetBlockSolution(block, consensusParams)`:
  genesis-shortcircuit (always valid), else builds `SignetTxs` from
  `params.signet_challenge`, runs `VerifyScript` with `BLOCK_SCRIPT_VERIFY_FLAGS`
  + `TransactionSignatureChecker` against the modified to-spend/to-sign pair.
- `bitcoin-core/src/signet.h:18-21` — interface signature
  `bool CheckSignetBlockSolution(const CBlock&, const Consensus::Params&)`.
- `bitcoin-core/src/consensus/params.h:121` — `bool enforce_BIP94;`
  (testnet4-only as of v25; design intent is fleet-wide future activation).
- `bitcoin-core/src/consensus/params.h:139-140` —
  `bool signet_blocks{false}; std::vector<uint8_t> signet_challenge;`
  (default-signet challenge is hardcoded in `SigNetParams`; custom challenges
  passed via `-signetchallenge` CLI).
- `bitcoin-core/src/consensus/consensus.h:35` —
  `static constexpr int64_t MAX_TIMEWARP = 600;`
- `bitcoin-core/src/validation.cpp:4097-4105` — consensus-side
  `time-timewarp-attack` rejection: gated on `consensusParams.enforce_BIP94`,
  fires only at heights where `nHeight % DifficultyAdjustmentInterval() == 0`,
  rejects blocks whose `GetBlockTime() < pindexPrev->GetBlockTime() - MAX_TIMEWARP`.
- `bitcoin-core/src/node/miner.cpp:36-47` — `GetMinimumTime(pindexPrev, difficulty_adjustment_interval)`:
  returns `max(pindexPrev->GetMedianTimePast() + 1, pindexPrev->GetBlockTime() - MAX_TIMEWARP)`
  AT every difficulty-adjustment boundary, **on ALL networks** (the comment
  explicitly states "to make future activation safer"). The miner-side clamp
  is NOT gated on `enforce_BIP94`, even though the consensus-side rejection is.
  This is the asymmetric defense-in-depth the W143 BUG-10 cross-cite calls out.
- `bitcoin-core/src/node/miner.cpp:49-65` — `UpdateTime(pblock, consensusParams, pindexPrev)`:
  `nNewTime = max(GetMinimumTime(...), TicksSinceEpoch(NodeClock::now()))`;
  also calls `GetNextWorkRequired` if `fPowAllowMinDifficultyBlocks` to recompute
  `nBits` after a time bump (testnet 20-min rule chain reaction).
- `bitcoin-core/src/pow.cpp:14-48` — `GetNextWorkRequired(pindexLast, pblock, params)`:
  the canonical retargeting entry. BIP-94 retargets from the FIRST block of the
  period when `enforce_BIP94`, otherwise from the LAST block (parent).
- `bitcoin-core/src/kernel/chainparams.cpp:417-453` — default signet `signet_challenge`
  = `512103ad5e0e...86be430210359ef5...f5189f2e6c452ae` (2-of-2 multisig of
  hardcoded developer pubkeys); messageStart derived as first 4 bytes of
  `SHA256d(signet_challenge)` (NOT a hardcoded constant).
- `bitcoin-core/src/kernel/chainparams.cpp:484-487` — default signet genesis
  hash `00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6`.
- `bitcoin-core/src/kernel/chainparams.cpp:464` — signet `enforce_BIP94 = false`.

**Files audited**
- `src/consensus/params.ts` — `ConsensusParams` interface (lines 15-142),
  `SIGNET` const (lines 948-990), `signetGenesisBlock`/`signetGenesisHash`
  (lines 941-942), `buildSignetGenesisBlock()` (lines 889-939),
  `enforce_BIP94` field (line 34), `nMinimumChainWork` for signet (line 987).
- `src/consensus/pow.ts` — `getNextWorkRequired` (lines 56-128),
  `calculateNextWorkRequired` (lines 144-202), BIP-94 first-block lookup
  (lines 173-186), `checkProofOfWork` (lines 280-297).
- `src/consensus/connect_block.ts` — `coreConnectBlockChecks` (lines 241-741);
  no signet hook anywhere in the consensus-validation kernel.
- `src/sync/headers.ts` — `HeaderSync.validateHeader` (lines 512-628);
  consensus-side BIP-94 timewarp check at lines 562-583 (gated on
  `enforce_BIP94`); MTP at line 554; `getMedianTimePast` (lines 634-654).
- `src/validation/block.ts` — `validateBlockHeader` (lines 398-449,
  **DEAD**; only called from `src/validation/block.test.ts` per W143 BUG-10),
  `validateBlock` (lines 517-611), `checkWitnessMalleation` (lines 313-366).
- `src/validation/errors.ts` — `time-timewarp-attack` mapping (lines 265-269,
  consumer-side; no producer wire-string for signet errors).
- `src/mining/template.ts` — `BlockTemplateBuilder` (line 154), `createTemplate`
  (lines 216-309), miner-side `minTime = MTP + 1` at line 266 (no BIP-94 clamp),
  `buildCoinbase` (lines 470-528). Per W155 BUG-31 and W123/W154 carry-forward,
  this entire class is dead-helper at the production layer: `grep -c "new
  BlockTemplateBuilder" src/rpc/server.ts → 0`.
- `src/rpc/server.ts` — `getBlockTemplate` (lines 5021-5259), `generateBlock`
  (lines 5377-5469), `generateSingleBlock` (lines 5492-5619), `submitBlock`
  (lines 4912-5014), `chain="signet"` magic-match branch (line 2174 inside
  `getblockchaininfo`).
- `src/cli/cli.ts` — `NodeConfig.network` type union (line 46);
  `parseArgs` network parse (lines 338-341); `getParams` (lines 800-811);
  `getDefaultRpcPort` (lines 280-294); `getDefaultP2PPort` (lines 296-310).

---

## Gate matrix (37 sub-gates / 13 behaviours)

| # | Behaviour | Sub-gate | Verdict |
|---|-----------|----------|---------|
| 1 | CheckSignetBlockSolution exists | G1: function `CheckSignetBlockSolution(block, params)` defined | **BUG-1 (P0-CONS-signet, carry-forward W155 BUG-25)** — entirely absent. Grep over `src/validation/`, `src/consensus/`, `src/sync/` for `CheckSignet`, `SignetTxs`, `signet_challenge`, `signetChallenge`, `FetchAndClear`, `SIGNET_HEADER` returns ZERO hits outside `src/consensus/params.ts:889-902` (genesis-block builder) |
| 1 | … | G2: SIGNET_HEADER constant `{0xec, 0xc7, 0xda, 0xa2}` defined | **BUG-2 (P0-CONS-signet)** absent — no such constant. There is no producer of the four bytes; on signet a block-solution push that begins with `0xecc7daa2` is never recognised |
| 1 | … | G3: FetchAndClearCommitmentSection helper present | **BUG-3 (P0-CONS-signet)** absent |
| 1 | … | G4: SignetTxs::Create-style modified-coinbase + modified-merkle | **BUG-4 (P0-CONS-signet)** absent |
| 1 | … | G5: ComputeModifiedMerkleRoot present | **BUG-5 (P0-CONS-signet)** absent |
| 2 | signet_challenge consensus parameter | G6: `signet_challenge: Buffer` field exists in `ConsensusParams` | **BUG-6 (P0-CONS-signet)** — `ConsensusParams` (params.ts:15-142) does not include any signet-related field at all. There is no `signet_challenge`, no `signet_blocks`, no `signetBlocks`. Field absent at the type level |
| 2 | … | G7: default signet challenge wired (Core 2-of-2 multisig) | **BUG-7 (P0-CONS-signet)** — no default `signet_challenge` anywhere. The default-signet network is unselectable AND unverifiable |
| 2 | … | G8: `signet_blocks: bool` flag present (Core consensus/params.h:139) | **BUG-8 (P1)** absent |
| 2 | … | G9: `-signetchallenge` CLI override accepted | **BUG-9 (P1)** — `cli.ts:283-310` enumerates default ports / network selectors and has no `signetchallenge` case |
| 3 | Signet network selectable | G10: `NodeConfig.network` type union includes `"signet"` | **BUG-10 (P0-CONS-signet, "advertisement-as-lie")** — `cli.ts:46`: `network: "mainnet" \| "testnet" \| "testnet4" \| "regtest";`. Signet is NOT in the union. A user passing `--network=signet` triggers the validator at cli.ts:339 (`if (value === "mainnet" \|\| value === "testnet" \|\| value === "testnet4" \|\| value === "regtest")`) — every other value is silently dropped, leaving `config.network` at the default `"mainnet"`. The SIGNET params object exists (params.ts:948) but is unreachable from the CLI |
| 3 | … | G11: `getParams(network)` has `case "signet":` | **BUG-11 (P0-CONS-signet)** — `cli.ts:800-811`: only mainnet/testnet/testnet4/regtest; default falls through to MAINNET. Even if the CLI parser DID accept `--network=signet`, `getParams` would silently return MAINNET. Two-pipeline guard 18th distinct extension (network-name accepted in one place, switch-case missing in the other) |
| 3 | … | G12: signet default ports (38333 RPC, 38332 / 38333 P2P) | **BUG-12 (P1)** — `cli.ts:283-310` has no `case "signet":`. `getDefaultRpcPort("signet")` returns 8332 (mainnet); `getDefaultP2PPort("signet")` returns 8333 (mainnet). Operator who tries to colocate a hotbuns signet node with a Core signet node on the same host gets a port collision and silent network selection on mainnet |
| 3 | … | G13: signet RPC `chain="signet"` reported by getblockchaininfo | PASS (server.ts:2174-2176 maps magic `0x0a03cf40` → "signet"). However the magic is unreachable via the CLI, so this branch is dead-on-arrival |
| 4 | Signet genesis correctness | G14: signet `genesisBlockHash` matches Core `0000000881987...3bee1ef6` | LIKELY-PASS — `buildSignetGenesisBlock` (params.ts:889-939) builds (version=1, prev=0, merkle=`3ba3edfd...4b1e5e4a`, time=1598918400, bits=0x1e0377ae, nonce=52613770) which is Core's exact signet genesis. Hash is computed at build-time but not asserted against Core's expected value |
| 4 | … | G15: networkMagic derived from `SHA256d(signet_challenge)` | **BUG-13 (P0-CONS-signet)** — `SIGNET.networkMagic = 0x0a03cf40` is hardcoded (params.ts:950). Core derives `pchMessageStart[0..3] = SHA256d(signet_challenge).first(4)` (kernel/chainparams.cpp:476-479). With a custom `-signetchallenge` the magic changes; hotbuns has no challenge-aware magic derivation. (The hardcoded value also bears verifying against Core's actual computed magic; comment in code claims "signet magic" without source citation) |
| 5 | BIP-94 consensus side (testnet4 only) | G16: `enforce_BIP94` field present | PASS (params.ts:34, set on TESTNET4 only at params.ts:847) |
| 5 | … | G17: `time-timewarp-attack` rejection fires at retarget boundaries | PASS (headers.ts:562-583); matches Core validation.cpp:4097-4105 |
| 5 | … | G18: rejection runs in production validation path | PASS — `HeaderSync.validateHeader` is the production entry; called from `processHeaders` (line 373) |
| 6 | BIP-94 in DEAD `validateBlockHeader` (W143 BUG-10 carry-forward) | G19: `src/validation/block.ts::validateBlockHeader` is wired into production | **BUG-14 (P0-DEAD, W143 BUG-10 5+ weeks carry-forward)** — `validateBlockHeader` (block.ts:398-449) is **NOT** called from any production path. `grep -rn "validateBlockHeader" src/ \| grep -v test \| grep -v index.js` returns ZERO production hits. The only callers are `src/validation/block.test.ts` (6 cases). The function lacks the BIP-94 timewarp check entirely (line 403-449 has no `enforce_BIP94` reference). If a future refactor accidentally wires this dead helper into production (e.g. via grep-and-grab "the obvious validator"), the BIP-94 check disappears. W143 BUG-10 anchor confirms this is a **35th-consecutive carry-forward** of the same dead-helper class as `BlockTemplateBuilder` |
| 6 | … | G20: dead `validateBlockHeader` documents the BIP-94 omission | **BUG-15 (P1)** — function header comment (block.ts:384-397) lists "Timestamp not too far in future", "Timestamp > MTP-of-11", "Target does not exceed powLimit", "Proof of work", "prevBlock matches" — five checks. No mention of BIP-94 timewarp. The omission is invisible to the reader |
| 7 | MAX_TIMEWARP constant | G21: `MAX_TIMEWARP = 600` defined as a top-level constant in `consensus/pow.ts` or `consensus/params.ts` | **BUG-16 (P1)** — `MAX_TIMEWARP = 600` appears as a **local const** inside `HeaderSync.validateHeader` (headers.ts:575) and as a numeric literal in the test fixture (`__tests__/mtp_contextual_check.test.ts:297`). Not exported, not shared. If a future caller (the miner-side clamp, the dead `validateBlockHeader`) needs it, they will hardcode their own copy. Two-pipeline guard precursor |
| 8 | Miner-side BIP-94 clamp (GetMinimumTime) | G22: `getMinimumTime(parent, difficulty_adjustment_interval)` helper exists | **BUG-17 (P0-CONS-miner)** — there is no `getMinimumTime` helper anywhere. `BlockTemplateBuilder.createTemplate` (template.ts:266) does `const minTime = this.medianTimePast + 1; const timestamp = Math.max(nowSecs, minTime)`. The Core clamp at retarget boundaries (`min_time = max(min_time, parent.GetBlockTime() - MAX_TIMEWARP)`) is **MISSING**. A hotbuns miner at a retarget block can produce a timestamp >= MTP+1 but < parent.timestamp - 600, which would be **rejected as `time-timewarp-attack`** by Core (and by hotbuns's own validateHeader if `enforce_BIP94`). **NEW PATTERN "Defense-in-depth missing at the producer"** |
| 8 | … | G23: clamp applied on ALL networks, not gated on `enforce_BIP94` | **BUG-17 cross-cite** — even if a hotbuns dev later adds the clamp, gating it on `enforce_BIP94` would mirror Core's miner side which does NOT gate. The Core comment explicitly says "to make future activation safer" (node/miner.cpp:41-42). Any gate at the miner side reverses Core's intent |
| 8 | … | G24: `generateSingleBlock` (regtest mining RPC) clamps timestamp | **BUG-18 (P0-CONS-miner)** — `generateSingleBlock` (server.ts:5565) uses `Math.floor(Date.now() / 1000)` raw — no MTP+1 clamp, no BIP-94 clamp. Worse than `BlockTemplateBuilder.createTemplate` which at least clamps to MTP+1. Regtest generate-loops that fire blocks faster than wall-clock seconds will produce blocks with timestamps `<=` MTP, getting `time-too-old` rejected after being mined. The function lacks even the basic MTP+1 floor |
| 8 | … | G25: `getblocktemplate.mintime` field returns GetMinimumTime semantics | **BUG-19 (P0-RPC)** — `getBlockTemplate` (server.ts:5145-5147) returns `mintime = parentEntry ? this.headerSync.getMedianTimePast(parentEntry) + 1 : curtime`. Equals `MTP+1` always. Core's `mintime` is `GetMinimumTime` which includes the BIP-94 clamp. A pool driven by hotbuns GBT on a `enforce_BIP94=true` chain (testnet4) at a retarget boundary will pick mintime, set nTime ≈ mintime, mine — then submit and have the block rejected by Core peers as `time-timewarp-attack`. Cross-cite W155 fleet pattern "advertisement-as-lie" |
| 9 | Miner-side nVersion BIP-9 signaling | G26: `computeNextBlockVersion` consults BIP-9 deployment state | PASS — `RPCServer.computeNextBlockVersion` (server.ts:590-621) uses `VersionBitsCache.computeBlockVersion`. `BlockTemplateBuilder.createTemplate` (template.ts:274-281) also wires it for the (dead) helper path |
| 9 | … | G27: BIP-9 deployments include taproot/csv on signet | **BUG-20 (P1)** — `taproot` deployment activation is height-based (`params.taprootHeight`), set to 1 for SIGNET (params.ts:965). `gbtRules` push (server.ts:5160-5167) emits "taproot" when `height >= params.taprootHeight`. For signet that's height ≥ 1 — correct. However the `vDeployments` BIP-9 table itself is empty for signet; the only deployment hotbuns plumbs is `DEPLOYMENT_TESTDUMMY` per Core line 468. **BUG-20** is the absence of `versionBitsDeployments` for SIGNET that would let testdummy ever signal |
| 10 | Miner-side nBits at retarget | G28: `getblocktemplate.bits` calls full `getNextWorkRequired` | PASS (server.ts:5128-5138). The early bug per the line-148 comment ("Bug fix: was hardcoded powLimit") is fixed for the GBT path |
| 10 | … | G29: `generateSingleBlock` (regtest RPC) uses powLimit, not retarget | PARTIAL — `generateSingleBlock` (server.ts:5554) sets `const target = this.params.powLimit` directly. On regtest this is correct (`fPowNoRetargeting=true`). On any other network this would be wrong; the function is gated to regtest at line 5391 so safe in practice. The lack of a path-aware retarget call means this code cannot be re-used for signet or testnet block generation. **BUG-21 (P1)** — refactor hazard |
| 11 | fPowAllowMinDifficultyBlocks behaviour on signet | G30: signet `fPowAllowMinDifficultyBlocks = false` | PASS (params.ts:956) |
| 11 | … | G31: regtest behaviour does not leak into signet | PASS (each network object overrides explicitly) |
| 12 | Default signet vs custom signet | G32: when `signet_challenge` is custom (-signetchallenge), `nMinimumChainWork = 0` | **BUG-22 (P1)** — Core (chainparams.cpp:434-437) clears `nMinimumChainWork` AND `defaultAssumeValid` when a custom challenge is supplied (because the custom-signet chain has no known reference work). hotbuns has neither the `-signetchallenge` flag (BUG-9) nor the clearing logic. If hotbuns ever adds custom-signet support, the chainwork floor will reject the custom-signet's genesis-only chain |
| 12 | … | G33: when `signet_challenge` is custom, magic is recomputed | **BUG-13 cross-cite** — see above; magic is hardcoded |
| 13 | Signet block-validation pipeline integration | G34: `validateBlock` / `coreConnectBlockChecks` calls `CheckSignetBlockSolution` when `signet_blocks` is true | **BUG-23 (P0-CONS-signet)** — `validateBlock` (block.ts:517-611) has no signet branch. `coreConnectBlockChecks` (connect_block.ts:241-741) has no signet branch. Even if CheckSignetBlockSolution were implemented (BUG-1), nothing would call it. The structural validation path runs merkle root, BIP-34, weight, sigops, BIP-30 — and stops |
| 13 | … | G35: submitblock rejects signet blocks with bad block-solution | **BUG-24 (P0-CONS-signet, W155 BUG-25 carry-forward)** — `submitBlock` (server.ts:4912-5014) runs `validateBlock` (line 4998), `checkProofOfWork` (line 4955), MTP check (line 4965). NO signet block-solution check. A submitblock on signet with a non-signet-signed block is admitted with NO solution check; chain forks from real signet at block 1 |
| 13 | … | G36: GBT response includes `signet_challenge` field for signet networks | **BUG-25 (P1, tests/w108_gbt.test.ts:850 pinned-as-broken)** — `tests/w108_gbt.test.ts:861` explicitly asserts `expect(resultKeys).not.toContain("signet_challenge")` — a test that PINS the missing-field bug. Per Core mining.cpp:1024-1026 `if (consensusParams.signet_blocks) result.pushKV("signet_challenge", HexStr(consensusParams.signet_challenge))`. **NEW PATTERN "test pinning a missing field"** — the absence is documented as the expected behaviour, making the bug invisible to test runs |
| 13 | … | G37: nVersion BIP-9 deployment state for `signet` rule emits correct GBT `rules`/`vbavailable` | **BUG-26 (P1)** — `gbtRules` array (server.ts:5160-5167) hard-codes the rule names ("csv", "!segwit", "taproot") based on height gates. The Core mechanism is to enumerate `consensusParams.vDeployments` and emit `gbtstatus.signalling + locked_in`. On any future signet-specific deployment, hotbuns will not emit it. Fleet pattern carry-forward of the BIP-9 plumbing gap (W144 BUG-1 / ouroboros BUG-1 cluster) |

---

## BUG-1 (P0-CONS-signet, W155 BUG-25 carry-forward) — `CheckSignetBlockSolution` entirely absent

**Severity:** P0-CONS-signet. Signet (BIP-325) replaces hash-based PoW
with a **block-solution signature**: each block's coinbase carries a
push that begins with `0xecc7daa2 (SIGNET_HEADER)` followed by a
serialised CTxIn::scriptSig + CScriptWitness::stack constituting a
signature against a special transaction pair that commits to the block
contents (header + modified-merkle root). Core's
`CheckSignetBlockSolution` (signet.cpp:126-153) verifies that signature
against the configured `signet_challenge` script using
`VerifyScript(...)`. A signet block with a missing or invalid solution
is consensus-invalid.

hotbuns contains no equivalent function. `grep -rn "CheckSignet\|
SignetTxs\|FetchAndClearCommitmentSection\|signet_challenge\|
signetChallenge\|SIGNET_HEADER\|0xecc7daa2" src/` returns **zero
matches** outside of:
1. `src/consensus/params.ts:889-902` — the signet genesis-block raw
   builder (no validation), and
2. `src/rpc/server.ts:2174-2176` — a `chain="signet"` magic-match
   branch inside `getblockchaininfo` (RPC label only, no validation).

The structural `validateBlock` (block.ts:517-611) and the consensus
kernel `coreConnectBlockChecks` (connect_block.ts:241-741) both
unconditionally accept any PoW-valid block. On signet, where the
"PoW" target is meaningfully low (~`0x1e0377ae`), generating a
solution-less block is trivial.

**File:** absent everywhere; would need `src/consensus/signet.ts` or
`src/validation/signet.ts` and call sites in `src/sync/blocks.ts`,
`src/rpc/server.ts::submitBlock`, and `src/validation/block.ts::validateBlock`.

**Core ref:** `bitcoin-core/src/signet.cpp:126-153`
(`CheckSignetBlockSolution`), `bitcoin-core/src/signet.cpp:70-123`
(`SignetTxs::Create`), `bitcoin-core/src/validation.cpp` (called from
the structural validation path before script verification).

**Impact:** **fleet P0-CONS-signet, second confirmed instance** —
identical shape to blockbrew W143 BUG-9. A hotbuns signet node
accepts any PoW-valid block as valid signet. Chain forks from real
signet at block 1. Direct cross-cite W155 BUG-25; **carry-forward
through W156 unaddressed**. (The W155 audit landed this finding via
the GBT/submitblock pathway; W157 confirms it survives an audit
focused on the consensus side and broadens the finding to the
five-helper-absent constellation — BUG-1..BUG-5.)

---

## BUG-2..BUG-5 (P0-CONS-signet cluster) — Entire SignetTxs helper family absent

**Severity:** P0-CONS-signet (cluster). Implementing
CheckSignetBlockSolution requires four helpers:

- `SIGNET_HEADER` constant (`{0xec, 0xc7, 0xda, 0xa2}`) — **absent**.
- `FetchAndClearCommitmentSection(witness_commitment, signet_solution)`
  — walks the coinbase's witness-commitment script, finds the first
  push starting with `SIGNET_HEADER`, splits it into header+payload,
  rewrites the script with header+payload elided — **absent**.
- `ComputeModifiedMerkleRoot(modified_cb, block)` — recomputes the
  block-merkle root with the modified coinbase (post-solution-strip)
  at index 0 — **absent**. Note: hotbuns's `computeMerkleRoot`
  (block.ts:177-199) is a generic helper but is not callable from a
  signet path that doesn't yet exist.
- `SignetTxs::Create(block, challenge)` — builds the `tx_to_spend` /
  `tx_to_sign` pair with the modified-merkle commitment — **absent**.

The bug cluster mirrors the W155 BUG-25 finding; W157 enumerates each
absent helper individually so that the implementation effort is
visible (~80 LOC port from Core's `signet.cpp`).

**File:** absent.

**Core ref:** `bitcoin-core/src/signet.cpp:28-123`.

**Impact:** see BUG-1.

---

## BUG-6..BUG-9 (P0/P1) — `signet_challenge` / `signet_blocks` consensus parameter absent

**Severity:** P0-CONS-signet (BUG-6 / BUG-7) + P1 (BUG-8 / BUG-9).
Core's `Consensus::Params` (consensus/params.h:139-140) carries:

```cpp
bool signet_blocks{false};
std::vector<uint8_t> signet_challenge;
```

`signet_blocks` toggles the entire signet block-solution machinery on;
`signet_challenge` is the scriptPubKey of the to-spend output (i.e.,
the public-key script that must sign each block). Core's default
signet challenge is the 2-of-2 multisig at chainparams.cpp:418:

```
512103ad5e0edad18cb1f0fc0d28a3d4f1f3e445640337489abb10404f2d1e086be430
210359ef5021964fe22d6f8e05b2463c9540ce96883fe3b278760f048f5189f2e6c45
2ae
```

hotbuns's `ConsensusParams` interface (params.ts:15-142) lists 35
fields including `bip30ExceptionBlocks`, `bip30DisconnectExceptionBlocks`,
`bip30ExceptionHeights`, `bip34Hash`, `assumedValid`, `assumeutxo` — none
of which are signet-related. There is no `signet_challenge`, no
`signet_blocks`, no `signetBlocks`. The SIGNET object literal
(params.ts:948-990) likewise has no signet-specific fields beyond
network magic.

Even if the field were added, there is no `-signetchallenge` CLI knob
(BUG-9, `cli.ts` does not register one) and no `getParams` case
(BUG-11). The custom-signet flow that Core supports via `-signetchallenge`
is completely inaccessible.

**File:** `src/consensus/params.ts:15-142` (interface), `:948-990`
(SIGNET literal), `src/cli/cli.ts:283-310` (port defaults).

**Core ref:** `bitcoin-core/src/consensus/params.h:139-140`,
`bitcoin-core/src/kernel/chainparams.cpp:417-453`.

**Impact:** **without `signet_challenge` carried in the consensus
params, even a correctly-ported `CheckSignetBlockSolution` cannot
verify against the right script**. The bug is structural: signet
validation requires the challenge as an input. The data is absent
from the type system entirely.

---

## BUG-10 (P0-CONS-signet, "advertisement-as-lie") — Signet not in `NodeConfig.network` union

**Severity:** P0-CONS-signet ("advertisement-as-lie", W155 NEW pattern).
hotbuns's `NodeConfig.network` type (cli.ts:46) is:

```ts
network: "mainnet" | "testnet" | "testnet4" | "regtest";
```

The validator at `cli.ts:339`:

```ts
if (value === "mainnet" || value === "testnet" ||
    value === "testnet4" || value === "regtest") {
  config.network = value;
}
```

Any other value is silently dropped (no log, no error). The user runs:

```
$ hotbuns --network=signet --datadir=/tmp/hb-signet
```

`config.network` stays at the DEFAULT_CONFIG value, which is
`"mainnet"` (cli.ts:263). The node starts on mainnet, opens RPC port
8332 (the mainnet default per BUG-12), and the operator believes
they are running a signet node. The on-disk RPC handshake will reveal
the chain-name "main" (or "signet" if the magic check passes —
unreachable in this path), but the operator typically discovers the
mismatch only after wasting hours diagnosing why the chain hash
doesn't match Core's signet.

Compounding evidence: server.ts:2174 has a `case 0x0a03cf40: chain =
"signet"` branch in getblockchaininfo — the code self-advertises
signet support that the CLI rejects. The contradiction is the
"advertisement-as-lie" archetype.

**File:** `src/cli/cli.ts:46, 339`, `src/cli/cli.ts:263` (default).

**Core ref:** `bitcoin-core/src/common/args.cpp` (`-chain=signet`
parse; `-signet` shortcut; `ChainType::SIGNET` enum).

**Impact:** signet network is unreachable from the CLI, regardless of
what other signet machinery exists. The SIGNET params object
(params.ts:948-990), the chain-name branch (server.ts:2174), and
even the W155 BUG-25 reference — all are dead-on-arrival.

---

## BUG-11 (P0-CONS-signet, two-pipeline guard 18th distinct extension) — `getParams` lacks signet case

**Severity:** P0-CONS-signet. `cli.ts:800-811`:

```ts
function getParams(network: string): ConsensusParams {
  switch (network) {
    case "testnet":
      return TESTNET;
    case "testnet4":
      return TESTNET4;
    case "regtest":
      return REGTEST;
    default:
      return MAINNET;
  }
}
```

Even if the CLI parser (BUG-10) accepted `--network=signet`,
`getParams("signet")` would silently return MAINNET via the
default-branch fall-through. The SIGNET object is exported from
params.ts:948 but no production path imports it for params-selection.

**Two-pipeline guard 18th distinct extension** — the network-name is
accepted in `parseArgs` only after passing a string union, and the
network-name is consumed in `getParams` only after passing a switch.
Either side could be plumbed-through-to-signet alone and the bug
would still bite; both sides have to be aligned. The
"asymmetric-defensive-depth" pattern (W145 NEW) is exactly this
case: same `network: string` value, two consumers with different
acceptance sets.

**File:** `src/cli/cli.ts:800-811`.

**Core ref:** `bitcoin-core/src/kernel/chainparams.cpp` (factory
function for each `ChainType`).

**Impact:** even if CLI added `"signet"` to the union, getParams would
return MAINNET. Two independent fixes required to enable signet.

---

## BUG-12 (P1) — `getDefaultRpcPort` / `getDefaultP2PPort` miss signet case

**Severity:** P1. `cli.ts:283-310` enumerates ports for mainnet,
testnet, testnet4, regtest. Signet's canonical port (38333 P2P, 38332
RPC) is absent. An operator who works around BUG-10/BUG-11 by
explicitly passing `--rpcport=38332 --port=38333` is unaffected; an
operator who relies on defaults gets port-collision-on-mainnet.

**File:** `src/cli/cli.ts:283-310`.

**Core ref:** `bitcoin-core/src/kernel/chainparams.cpp:481` (signet
`nDefaultPort = 38333`).

**Impact:** ports.

---

## BUG-13 (P0-CONS-signet) — Signet `networkMagic` hardcoded, not derived from `signet_challenge`

**Severity:** P0-CONS-signet. Core derives signet's `pchMessageStart`
as the first four bytes of `SHA256d(signet_challenge)`
(chainparams.cpp:476-479):

```cpp
HashWriter h{};
h << consensus.signet_challenge;
uint256 hash = h.GetHash();
std::copy_n(hash.begin(), 4, pchMessageStart.begin());
```

This means each custom signet (different `-signetchallenge`) has a
different network magic, which prevents accidental cross-talk between
two private signets and between any signet and the default signet.

hotbuns hardcodes `SIGNET.networkMagic = 0x0a03cf40` (params.ts:950).
The comment says "signet magic" without a source citation. Two
problems:

1. The hardcoded value bears verifying against Core's actual computed
   magic for the default challenge. Per Core source, the default
   signet `signet_challenge` SHA256d produces messageStart bytes that
   need spot-checking against `0x0a03cf40`'s byte representation
   (`[0x40, 0xcf, 0x03, 0x0a]` in little-endian).
2. Even if the default magic is correct, **any custom signet would
   collide** on `0x0a03cf40` because hotbuns cannot recompute it.

Combined with BUG-9 (no `-signetchallenge` flag), custom signet is
unreachable, but the magic-hardcoding remains a latent footgun for any
future flag addition.

**File:** `src/consensus/params.ts:950`.

**Core ref:** `bitcoin-core/src/kernel/chainparams.cpp:476-479`.

**Impact:** custom signets impossible without re-deriving magic.

---

## BUG-14 (P0-DEAD, W143 BUG-10 carry-forward, 35th-consecutive dead-helper instance) — `validateBlockHeader` in `validation/block.ts` is dead code lacking BIP-94

**Severity:** P0-DEAD. `src/validation/block.ts::validateBlockHeader`
(line 398-449) is the obvious-looking validator that any new developer
would grep for first. Its production callers, per
`grep -rn "validateBlockHeader" src/ | grep -v ".test.ts" | grep -v
"index.js"`, are **ZERO**. The actual production header validator is
`src/sync/headers.ts::HeaderSync.validateHeader` (line 512-628).

The dead `validateBlockHeader` lacks the BIP-94 timewarp check
entirely — its header comment lists "Timestamp not too far in future,
Timestamp > MTP-of-11, Target does not exceed powLimit, Proof of work,
prevBlock matches"; five gates, no BIP-94. If a future refactor
accidentally wires this dead helper into a production path — e.g., by
choosing the "obvious-looking" exported function — BIP-94 silently
disappears.

**Cross-cite chain:**

- W143 BUG-10 (Hotbuns block-validation audit) first identified the
  dead helper.
- **5+ weeks open**, untouched.
- W155 BUG-31 / W123 BUG-21 / W154 BUG-1 anchor the same
  dead-helper-class pattern for `BlockTemplateBuilder`. W157 finds
  the consensus-side equivalent. **35th-consecutive carry-forward
  finding** across all hotbuns audits.

**File:** `src/validation/block.ts:398-449`.

**Core ref:** N/A (the issue is structural, not a divergence).

**Impact:** future-refactor footgun; bug already-present-but-dormant.

---

## BUG-15 (P1) — Dead `validateBlockHeader` header comment hides the BIP-94 omission

**Severity:** P1 ("comment-as-confession" 13th distinct hotbuns
instance — but inverted: the comment OMITS the truth rather than
admitting it). `block.ts:384-397` documents the five checks the dead
helper runs. Anyone reading the comment without cross-referencing
Core's `ContextualCheckBlockHeader` (validation.cpp:4080-4121) would
assume the helper is complete. The reality — BIP-94 timewarp check
absent — is invisible.

This is the "comment-as-confession" pattern's mirror: rather than the
comment admitting the bug ("// We do X for performance"), the comment
implies a completeness that is false ("Checks: ... five things,
period."). The fleet has not previously catalogued this inverted
form; W157 introduces it.

**File:** `src/validation/block.ts:384-397`.

**Impact:** documentation-as-misleading; aids the carry-forward
failure mode of BUG-14.

---

## BUG-16 (P1, two-pipeline guard precursor) — `MAX_TIMEWARP = 600` declared as a function-local const, not exported

**Severity:** P1. `MAX_TIMEWARP = 600` appears in hotbuns at:

1. `src/sync/headers.ts:575` — local `const MAX_TIMEWARP = 600;` inside
   `validateHeader`.
2. `src/__tests__/mtp_contextual_check.test.ts:297` — local
   `const MAX_TIMEWARP = 600;` inside the test fixture.

Not exported, not shared, not centralised. The miner-side clamp
(missing per BUG-17) would, when added, almost certainly inline a third
copy. The validation kernel (`coreConnectBlockChecks`) does not import
the value at all because BIP-94 fires at header-time not connect-time.

The fleet pattern is to declare consensus magic numbers in
`src/consensus/params.ts` or a sibling consensus-constants module. The
W155 BUG-29 / W156 BUG-21 cluster have flagged similar
hardcoded-magic-numbers in the past (e.g. `BIP34_IMPLIES_BIP30_LIMIT
= 1_983_702` at connect_block.ts:328).

**File:** `src/sync/headers.ts:575`,
`src/__tests__/mtp_contextual_check.test.ts:297`.

**Core ref:** `bitcoin-core/src/consensus/consensus.h:35` —
`static constexpr int64_t MAX_TIMEWARP = 600;` declared in a shared
header so every consumer pulls from one source.

**Impact:** correctness-neutral today (one consumer + one test);
becomes a two-pipeline guard 19th distinct extension if BUG-17 is
ever fixed without also hoisting the constant.

---

## BUG-17 (P0-CONS-miner, NEW PATTERN "Defense-in-depth missing at the producer") — `BlockTemplateBuilder.createTemplate` lacks BIP-94 timewarp clamp on `nTime`

**Severity:** P0-CONS-miner. Bitcoin Core's `GetMinimumTime`
(node/miner.cpp:36-47) is the **single source of truth for the
miner-side minimum block time**:

```cpp
int64_t GetMinimumTime(const CBlockIndex* pindexPrev,
                       const int64_t difficulty_adjustment_interval) {
    int64_t min_time{pindexPrev->GetMedianTimePast() + 1};
    const int height{pindexPrev->nHeight + 1};
    // Account for BIP94 timewarp rule on all networks. This makes future
    // activation safer.
    if (height % difficulty_adjustment_interval == 0) {
        min_time = std::max<int64_t>(min_time,
                                     pindexPrev->GetBlockTime() - MAX_TIMEWARP);
    }
    return min_time;
}
```

Two non-obvious properties:

1. **The clamp fires at difficulty-adjustment boundaries on ALL
   networks**, regardless of `enforce_BIP94`. The Core comment
   explicitly states the reasoning: "to make future activation safer"
   — Core's miner pre-emptively obeys BIP-94 before consensus
   requires it, so a node that later flips `enforce_BIP94` on does
   not have its own miners producing future-rejected blocks.
2. **The clamp uses `parent.GetBlockTime()` (the parent block's nTime
   field), not `parent.GetMedianTimePast()`**. These differ
   substantially; using MTP would not match the consensus side's
   BIP-94 check.

hotbuns's `BlockTemplateBuilder.createTemplate` (template.ts:261-267):

```ts
// Bug fix 7: block timestamp must be >= MTP+1 (GetMinimumTime in
//   Core miner.cpp:36-47).
// Core's UpdateTime() does max(GetMinimumTime(pindexPrev,...), now).
// GetMinimumTime returns max(MTP+1, ...). So: timestamp = max(now, MTP+1).
// Reference: node/miner.cpp:52-53.
const nowSecs = Math.floor(Date.now() / 1000);
const minTime = this.medianTimePast + 1;
const timestamp = Math.max(nowSecs, minTime);
```

The comment **explicitly cites GetMinimumTime** and claims to mirror
it — but the implementation only applies MTP+1. The BIP-94 clamp
(`max(min_time, parent.GetBlockTime() - 600)` at retarget boundaries)
is missing. **Comment-as-confession 14th distinct hotbuns instance**
— the inline citation admits the function it is mirroring includes
the clamp, then omits the clamp.

**Impact:**

- On testnet4 (the only network with `enforce_BIP94 = true`), at every
  2016-block retarget boundary, a hotbuns miner can produce a block
  with `nTime = MTP + 1` which may be < `parent.nTime - 600` if the
  parent timestamp was a future-bumped one. That block will be
  rejected by every BIP-94-aware node (including hotbuns's own
  HeaderSync) as `time-timewarp-attack`. **Self-inflicted DoS** for
  any pool driven by hotbuns GBT on testnet4.
- On all other networks (mainnet, testnet3, signet, regtest) the
  clamp is missing per Core's future-activation-safer design. If
  BIP-94 ever activates fleet-wide, hotbuns miners will start
  producing rejected blocks at retarget boundaries with no node-level
  reconfiguration.

**NEW PATTERN "Defense-in-depth missing at the producer"** — the
consensus-side check is correctly present and gated on `enforce_BIP94`
(headers.ts:572-583), but the producer-side clamp that would prevent
honest miners from ever triggering the consensus rejection is
missing. The asymmetry is the same shape as W145 NEW
"asymmetric-defensive-depth" but applied to the consumer-side full,
producer-side absent.

**File:** `src/mining/template.ts:261-267`.

**Core ref:** `bitcoin-core/src/node/miner.cpp:36-47`
(`GetMinimumTime`), `bitcoin-core/src/node/miner.cpp:49-65`
(`UpdateTime`, the wrapper).

---

## BUG-18 (P0-CONS-miner) — `generateSingleBlock` (regtest mining RPC) sets `timestamp = Date.now()` raw

**Severity:** P0-CONS-miner. `RPCServer.generateSingleBlock`
(server.ts:5492-5619) is the regtest mining RPC used by
`generatetoaddress` and `generate` (legacy). Line 5561-5568:

```ts
let header: BlockHeader = {
  version: genToAddrVersion,
  prevBlock: bestBlock.hash,
  merkleRoot: computeMerkleRoot(txids),
  timestamp: Math.floor(Date.now() / 1000),    // <-- raw wall-clock
  bits,
  nonce: 0,
};
```

Worse than `BlockTemplateBuilder.createTemplate`: no MTP+1 floor at
all, no BIP-94 clamp, no `GetMinimumTime` invocation. The fast-loop
regtest test pattern of:

```
for i in {1..200}; do bitcoin-cli generatetoaddress 1 $ADDR; done
```

will produce ~200 blocks within seconds. If wall-clock ticks faster
than 1Hz between blocks, two blocks share a timestamp; if
wall-clock ticks slower (rare but possible under load), block N+1
can have `timestamp = block N's timestamp - 1`, which is `<= MTP` and
gets `time-too-old` rejected by `validateHeader`. The result is
flaky regtest tests that mine N blocks but only N-k get accepted.

The proximate fix is the same `max(MTP+1, now)` floor used in
`BlockTemplateBuilder.createTemplate` (template.ts:267) — but that
helper is itself buggy per BUG-17.

**File:** `src/rpc/server.ts:5565`.

**Core ref:** `bitcoin-core/src/node/miner.cpp:36-47, 49-65`.

**Impact:** regtest flakiness (block N+1 rejected); cross-cite W156
companion regression in the `generatetoaddress` path on regtest.

---

## BUG-19 (P0-RPC) — `getblocktemplate.mintime` returns `MTP+1`, missing BIP-94 clamp

**Severity:** P0-RPC. `RPCServer.getBlockTemplate` (server.ts:5021-5259)
returns the `mintime` field at line 5145-5147:

```ts
const mintime = parentEntry
  ? this.headerSync.getMedianTimePast(parentEntry) + 1
  : curtime;
```

Equals `MTP+1` always. Core's `mintime` is the return of
`GetMinimumTime` which includes the BIP-94 clamp:

```
mintime = max(MTP + 1, parent.GetBlockTime() - 600)   at retarget boundary
mintime = MTP + 1                                      otherwise
```

A pool driven by hotbuns GBT on testnet4 (`enforce_BIP94 = true`) at
a retarget boundary will choose `nTime ≈ mintime`, mine, submit —
and have the block rejected by every BIP-94-aware peer as
`time-timewarp-attack`. The pool's loss of revenue is paid in real BTC
per orphaned block.

Compounded by BUG-17 (the `BlockTemplateBuilder.createTemplate`
helper that exposed `getBlockTemplate.mintime` would also need
fixing), and BUG-26 (vbavailable/rules absence for signet).

**File:** `src/rpc/server.ts:5145-5147`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp` (BlockMiningInfo
construction calling `node::GetMinimumTime`),
`bitcoin-core/src/node/miner.cpp:36-47`.

**Impact:** "advertisement-as-lie" 6th hotbuns instance — GBT's
`mintime` is an explicit promise to pools about the minimum-acceptable
block time, broken on testnet4 retarget boundaries (and fleet-wide
after any future BIP-94 activation).

---

## BUG-20 (P1) — Signet `vDeployments` BIP-9 plumbing absent (TESTDUMMY signal would never fire)

**Severity:** P1. Core (chainparams.cpp:468-473) populates
`consensus.vDeployments[DEPLOYMENT_TESTDUMMY]` on signet so that
test-only deployments can signal. hotbuns's `SIGNET` (params.ts:948)
inherits its deployment table via `...MAINNET` spread but the
SIGNET-specific deployment table is not declared anywhere in
`ConsensusParams`. The
`RPCServer.getVersionBitsDeployments` (server.ts:573-576) walks the
table that doesn't have a signet-specific entry, so any TESTDUMMY
signalling test on signet would silently produce empty `vbavailable`
in GBT.

**File:** `src/consensus/params.ts:948-990`,
`src/rpc/server.ts:5169-5202`.

**Core ref:** `bitcoin-core/src/kernel/chainparams.cpp:468-473`.

**Impact:** signet-deployment testing impossible from hotbuns
(another dead-on-arrival capability per BUG-10).

---

## BUG-21 (P1) — `generateSingleBlock` regtest-only target derivation cannot be reused for signet/testnet

**Severity:** P1. `generateSingleBlock` (server.ts:5554):

```ts
const target = this.params.powLimit;
const bits = bigIntToCompact(target);
```

Hardcodes the powLimit target. On regtest (`fPowNoRetargeting=true`)
this is correct because the chain never retargets. The function is
gated to regtest at line 5391:

```ts
if (!this.params.fPowNoRetargeting) {
  throw this.rpcError(MISC_ERROR, "generateblock is only available
                                   in regtest mode");
}
```

so a hotbuns operator cannot accidentally use it on testnet/signet
today. But the function is THE template for any future signet or
testnet block-generation RPC — and the template skips the proper
retarget call. Refactor hazard: copy-paste this function for
`generatesignetblock` and PoW will be wrong.

The right pattern is `getNextWorkRequired(parent, blockTimestamp, ...)`
as used in `getBlockTemplate` (server.ts:5128-5138).

**File:** `src/rpc/server.ts:5554`.

**Impact:** refactor-hazard; no current consensus risk.

---

## BUG-22 (P1) — Custom-signet `nMinimumChainWork=0`, `defaultAssumeValid=zero` clearing missing

**Severity:** P1. Core (chainparams.cpp:434-443) handles the
custom-signet case (when `-signetchallenge=<hex>` is set):

```cpp
} else {  // custom challenge
    bin = *options.challenge;
    consensus.nMinimumChainWork = uint256{};
    consensus.defaultAssumeValid = uint256{};
    m_assumed_blockchain_size = 0;
    m_assumed_chain_state_size = 0;
    chainTxData = ChainTxData{ 0, 0, 0 };
    LogInfo("Signet with challenge %s", HexStr(bin));
}
```

The reason: a custom signet's chain has no a-priori-known work or
assumed-valid block; using the default-signet values would prevent
the custom-signet from ever exiting IBD (BUG-22's symptom).

hotbuns has no `-signetchallenge` flag (BUG-9), so the clearing logic
is moot today. Listed for parity-completeness: if BUG-9 is fixed,
BUG-22's clearing logic must also land. Otherwise a custom-signet
fresh from genesis will be stuck in IBD because `nMinimumChainWork`
keeps the default-signet value `0x0...0b463ea0a4b8`, unreachable on
the custom chain.

**File:** would need a `SignetOptions` analogue in
`src/consensus/params.ts`.

**Core ref:** `bitcoin-core/src/kernel/chainparams.cpp:434-443`.

**Impact:** custom-signet future-blocker.

---

## BUG-23 (P0-CONS-signet) — Production validation pipeline lacks any signet branch

**Severity:** P0-CONS-signet. Even if BUG-1..BUG-5 were fixed by
adding `CheckSignetBlockSolution` and helpers, nothing in the
production pipeline calls it. The two validation entry points are:

1. `src/validation/block.ts::validateBlock` (lines 517-611) — runs
   merkle root, BIP-30, BIP-34, weight, witness commitment, sigops.
   No `if (params.signet_blocks) checkSignetBlockSolution(block, params)`
   branch.
2. `src/consensus/connect_block.ts::coreConnectBlockChecks` (lines
   241-741) — runs BIP-30, IsFinalTx, UTXO preload, script verify,
   sigops, coinbase value. No signet branch.

Cross-fleet: blockbrew's W143 BUG-9 had the same shape (missing
function AND missing call site). The fix has to land in TWO places.

**File:** `src/validation/block.ts:517-611`,
`src/consensus/connect_block.ts:241-741`.

**Core ref:** `bitcoin-core/src/validation.cpp::CheckBlock` calls
`CheckSignetBlockSolution` (called from within the structural
validation step on signet chains).

**Impact:** see BUG-1 — signet block-solution check absent at every
layer.

---

## BUG-24 (P0-CONS-signet, W155 BUG-25 direct carry-forward) — `submitblock` accepts non-signet-signed signet blocks

**Severity:** P0-CONS-signet. `RPCServer.submitBlock` (server.ts:4912-5014)
runs:

- `deserializeBlock` (line 4934)
- `getBlockHash` (line 4946)
- `getNextTarget` + high-hash gate (lines 4952-4957) — returns
  `"high-hash"` on PoW fail
- MTP check (line 4965) — returns `"time-too-old"`
- `validateBlock` (line 4998) — structural checks
- `blockSync.injectBlock` (line 5010) — full consensus

No signet block-solution check. The W155 BUG-25 finding is the same
gap viewed from the GBT/submitblock angle; W157 confirms the gap
persists at the submitblock-handler level.

Direct cross-cite: **W155 BUG-25 P0-CONS-signet 1-day carry-forward**
(W155 landed `3f3ef30`-bracketed, W156 landed `d251a65`-bracketed;
W157 confirms the bug is unaddressed in either wave).

**File:** `src/rpc/server.ts:4912-5014`.

**Core ref:** `bitcoin-core/src/signet.cpp::CheckSignetBlockSolution`
called via `validation.cpp::ContextualCheckBlock` →
`CheckBlock`.

**Impact:** see BUG-1.

---

## BUG-25 (P1, NEW PATTERN "test pinning a missing field") — `tests/w108_gbt.test.ts:861` pins the GBT `signet_challenge` field as absent

**Severity:** P1 (test-pinning). `tests/w108_gbt.test.ts:850-861`:

```ts
// G21 — GBT signet_challenge absent (signet chain support missing)
describe("G21 — GBT signet_challenge absent ...", () => {
  test("no signet_challenge field in GBT response for signet networks", () => {
    // Core: if (consensusParams.signet_blocks) result.pushKV("signet_challenge", ...)
    // hotbuns: result object in getBlockTemplate never includes signet_challenge.
    ...
    expect(resultKeys).not.toContain("signet_challenge");
  });
});
```

The test explicitly **pins the missing-field bug as the expected
behaviour**. Anyone running the test suite will see all-green and
assume signet works. The bug is documented in the test as a known gap,
but the test pretends the gap is desirable. The "test pinning a
missing field" pattern is the **inverted form** of the
test-suite-shape-masks-production-bug fleet pattern (4+ hotbuns
instances):

- Original form: tests use a shape that hides a production bug (e.g.,
  mock-out-the-bug, restructure-the-test-around-the-bug).
- This form: tests explicitly assert the bug's behaviour.

A future fleet sweep that fixes BUG-1..BUG-9 will see this test
**fail** and may be tempted to "fix" the test rather than the bug.

The right move is to delete the test (or convert it to a `.skip`)
when the underlying GBT signet support is added.

**File:** `tests/w108_gbt.test.ts:850-861`.

**Impact:** test-pinning a P0-class missing capability as "expected
behaviour". Documentation-by-test pattern that obscures the gap.

---

## BUG-26 (P1, BIP-9 plumbing gap fleet carry-forward) — `gbtRules` hard-codes rule names, ignores `vDeployments` table

**Severity:** P1. `RPCServer.getBlockTemplate` (server.ts:5160-5167):

```ts
const gbtRules: string[] = ["csv"];
const fPreSegWit = height < this.params.segwitHeight;
if (!fPreSegWit) {
  gbtRules.push("!segwit");
  if (height >= this.params.taprootHeight) {
    gbtRules.push("taproot");
  }
}
```

The rule names are hardcoded based on height-gates. Core's analogue
walks `consensusParams.vDeployments`, emits the deployment NAME for
each STARTED / LOCKED_IN entry, and inserts `!` prefix for those that
the client did not opt into via the `rules` array. The hotbuns shape
covers only the buried deployments (csv/segwit/taproot), missing:

- Any future BIP-9 deployment (e.g., the next consensus change after
  taproot).
- Signet-specific deployments (none exist today, but the absence is
  structural — the table is empty per BUG-20).

The W144 BUG-1 / ouroboros BUG-1 cluster catalogued the same
"BIP-9 plumb-but-don't-emit" pattern. W157 carries it forward.

**File:** `src/rpc/server.ts:5160-5167`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:953-984` (gbtRules
construction from `vDeployments` enumeration).

**Impact:** signet-deployment GBT signalling impossible (BUG-20
cross-cite); future-deployment GBT signalling will require code
change rather than chainparams change.

---

## Summary

**Bug count:** 26 (BUG-1 through BUG-26).

**Severity distribution:**
- **P0-CONS-signet:** 13 (BUG-1, BUG-2, BUG-3, BUG-4, BUG-5, BUG-6,
  BUG-7, BUG-10, BUG-11, BUG-13, BUG-23, BUG-24)
- **P0-CONS-miner:** 2 (BUG-17, BUG-18)
- **P0-RPC:** 1 (BUG-19)
- **P0-DEAD:** 1 (BUG-14)
- **P1:** 9 (BUG-8, BUG-9, BUG-12, BUG-15, BUG-16, BUG-20, BUG-21,
  BUG-22, BUG-25, BUG-26)

Total: 13 + 2 + 1 + 1 + 9 = 26. ✓

**P0-class:** 17 (13 P0-CONS-signet + 2 P0-CONS-miner + 1 P0-RPC + 1
P0-DEAD).

**Fleet patterns confirmed:**
- **signet-CheckSignetBlockSolution-absent (W143 W155 confirmed
  fleet-wide)** — 13 P0-CONS-signet findings cluster around the
  missing block-solution path, the missing helpers, the missing
  consensus-params fields, and the missing CLI plumbing. Fleet
  instance #2 anchored against blockbrew W143 BUG-9.
- **Advertisement-as-lie (W155 NEW)** — BUG-10 (CLI says signet not
  supported, RPC reports `chain="signet"` magic-match); BUG-19
  (`getblocktemplate.mintime` advertises a value Core's GBT does
  NOT mean). Two new instances; W155 first instance + W157
  instances 5-6.
- **Comment-as-confession (13+ hotbuns, this wave's instance #14)**
  — BUG-17 inline citation to `node/miner.cpp:36-47` GetMinimumTime
  while the implementation only mirrors half of it.
- **two-pipeline guard 18th distinct extension** — BUG-11 (CLI
  accepts "signet" via union, getParams switch-case missing).
- **Carry-forward dead-helper (35th-consecutive instance)** — BUG-14
  (`validateBlockHeader` dead-helper in `validation/block.ts` lacks
  BIP-94, W143 BUG-10 5+ weeks open).
- **Carry-forward dead-helper (W155 BUG-31 / W123 BUG-21
  BlockTemplateBuilder)** — implicit cross-cite. BUG-17 mentions the
  same dead-builder. **35th-consecutive instance crossed in W155;
  W157 confirms continued non-fix.**
- **Defense-in-depth missing at the producer (NEW PATTERN)** —
  BUG-17 / BUG-18 / BUG-19 cluster. Consensus side correctly enforces
  BIP-94; producer side (miner/GBT) does NOT pre-emptively clamp.
  The asymmetry mirrors W145 NEW "asymmetric-defensive-depth" but
  with the asymmetry between consumer-and-producer rather than
  between multiple variants of one function.
- **Test pinning a missing field (NEW PATTERN)** — BUG-25
  `tests/w108_gbt.test.ts:861` explicitly asserts `not.toContain
  ("signet_challenge")`. Inverted form of
  test-suite-shape-masks-production-bug.
- **Hardcoded magic numbers not centralised (W155 BUG-29 carry-forward)**
  — BUG-16 (MAX_TIMEWARP=600 local-const, not exported).

**P0-CONS concentration:** 13 P0-CONS-signet + 2 P0-CONS-miner = **15
P0-CONS-class findings in one wave**. Comparable to W155 (1
P0-CONS-signet) but vastly more dense because W157 enumerates each
absent helper individually rather than rolling them into one finding.
The same architectural gap (signet support entirely absent) is the
proximate cause for 13 of the 15.

**Top three findings:**

1. **BUG-1 + cluster (P0-CONS-signet, W155 BUG-25 carry-forward) —
   CheckSignetBlockSolution + helpers entirely absent.** The signet
   network is unreachable from the CLI (BUG-10/BUG-11), but even if
   it were reachable, every signet block would be admitted without
   block-solution verification (BUG-23/BUG-24). The implementation
   gap spans 13 P0-CONS-signet findings clustered around one
   architectural absence. Direct cross-cite blockbrew W143 BUG-9 +
   hotbuns W155 BUG-25 (1-day carry-forward); fleet-pattern second
   confirmation. **Recommend fleet-wide sweep after the hotbuns +
   blockbrew P0-CONS-signet finding constitutes #2 of #3 — the third
   would consummate "fleet-wide CVE-class" status.**

2. **BUG-17 (P0-CONS-miner, NEW PATTERN "Defense-in-depth missing
   at the producer") — `BlockTemplateBuilder.createTemplate` lacks
   BIP-94 timewarp clamp.** The miner exposes a self-inflicted DoS
   path on testnet4 at every retarget boundary: produce a block
   with `nTime = MTP+1` which may be `< parent.nTime - 600`,
   self-rejected by the impl's own HeaderSync as
   `time-timewarp-attack`. The inline comment cites
   `node/miner.cpp:36-47` (GetMinimumTime) yet implements only half
   of it — **14th comment-as-confession hotbuns instance**. Cross-cite
   BUG-18 (the regtest mining path has no clamp at all) and BUG-19
   (the GBT.mintime field returns the wrong value, "advertisement-as-lie"
   5th instance).

3. **BUG-14 (P0-DEAD, W143 BUG-10 35th-consecutive carry-forward) —
   `validateBlockHeader` in `validation/block.ts` is dead code
   missing the BIP-94 check.** 5+ weeks open. The function looks
   obvious-to-grep-for; a future refactor that wires it into a
   production path will silently lose BIP-94 enforcement. The header
   comment "Checks: ..." lists five gates with no BIP-94 mention,
   compounding the carry-forward failure mode (BUG-15). Same
   structural pattern as W155 BUG-31 / W123 BUG-21 / W154 BUG-1
   `BlockTemplateBuilder` dead-helper that has now reached 35
   consecutive audits without resolution.
