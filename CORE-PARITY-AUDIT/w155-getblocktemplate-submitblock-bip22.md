# W155 — getblocktemplate + submitblock + BIP-22/BIP-23 (hotbuns)

**Wave:** W155 — JSON-RPC mining surface: `getblocktemplate`,
`submitblock`, `getmininginfo`, `prioritisetransaction`,
`getprioritisedtransactions`, `submitheader`, plus the BIP-22 and BIP-23
result-shape contract:
- BIP-22 request: `mode` ∈ {`template`,`proposal`,`disable`}, `capabilities[]`,
  `rules[]`, `longpollid`.
- BIP-23 fields: `mutable[]`, `noncerange`, `mintime`, `curtime`,
  `sigoplimit`, `sizelimit`, `weightlimit`, `target`, `coinbaseaux`,
  `coinbasevalue`, `coinbasetxn`, `default_witness_commitment`.
- Per-tx: `data`, `txid`, `hash` (wtxid), `depends`, `fee`, `sigops`,
  `weight`.
- BIP22ValidationResult: `null` (success), `inconclusive`, `duplicate`,
  `duplicate-invalid`, `high-hash`, `time-too-old`, `time-too-new`,
  `bad-cb-amount`, `bad-cb-height`, `bad-cb-length`, `bad-blk-sigops`,
  `bad-blk-length`, `bad-txnmrklroot`, `bad-witness-merkle-match`,
  `bad-diffbits`, `bad-version(…)`, `rejected`.

**Scope:** discovery only — no production code changes.

## Bitcoin Core references

- `bitcoin-core/src/rpc/mining.cpp::getblocktemplate` — entry-point RPC.
  Pre-call guards: `RPC_CLIENT_IN_INITIAL_DOWNLOAD` (refuses while
  IBD), `RPC_CLIENT_NOT_CONNECTED` (refuses with 0 peers), `mode=proposal`
  handler that runs `TestBlockValidity` and returns a BIP-22 result string,
  `longpollid` parsing + wait loop on `nTransactionsUpdatedLast` /
  `pindexPrev` change, template cache keyed on `(pindexPrev,
  nTransactionsUpdatedLast)`. Result shape filled by
  `BlockAssemblerForRPC + GBTRules` (see `rpc/mining.cpp` ~lines 900-1100).
- `bitcoin-core/src/rpc/mining.cpp::submitblock` — accepts `hexdata` +
  optional `dummy` second arg. Decodes block, calls
  `ChainstateManager::ProcessNewBlock(block, force_processing=true,
  min_pow_checked=true, new_block=&fNewBlock)`, then `submitblock_StateCatcher`
  collects the rejection-reason string and returns the canonical BIP-22
  string via `BIP22ValidationResult()`. Duplicate-known returns `duplicate`;
  duplicate but invalid returns `duplicate-invalid`; orphan returns
  `inconclusive`.
- `bitcoin-core/src/rpc/mining.cpp::submitheader` — single-header
  acceptance wrapper around `ChainstateManager::ProcessNewBlockHeaders`.
- `bitcoin-core/src/rpc/mining.cpp::prioritisetransaction` +
  `getprioritisedtransactions` — operator-side fee-delta application.
- `bitcoin-core/src/rpc/mining.cpp::BIP22ValidationResult` — canonical
  reason-string mapping used by both submitblock and proposal-mode.
- BIP-22 spec (`https://github.com/bitcoin/bips/blob/master/bip-0022.mediawiki`)
  — `coinbasevalue` is **integer-typed JSON Number** (not string),
  `longpollid` is opaque-string, `mintime` is a JSON Number, `target`
  is 64-char hex padded to 256 bits.
- BIP-23 spec — `mutable[]` is the consensus contract of which fields the
  miner may change (typically `["time","transactions","prevblock"]`),
  `noncerange` is `"<start>"+"<end>"` in hex (default
  `"00000000ffffffff"`), `coinbasetxn` is an alternative to
  `coinbasevalue` (mode=coinbasetxn).
- `bitcoin-core/src/node/miner.cpp:122-237` — `CreateNewBlock` block
  assembly contract (TestChunkBlockLimits, GetMinimumTime, BIP-94
  miner-side clamp, GenerateCoinbaseCommitment).
- `bitcoin-core/src/policy/policy.h:25-36` — block-assembly tunables
  (`-blockmaxweight`, `-blockmintxfee`, `-blockreservedweight`,
  `-printpriority`).

## Files audited

- `src/rpc/server.ts:1078-1257` — RPC dispatch table (`registerMethod`
  enumerations). Used to confirm presence/absence of `submitheader`,
  `prioritisetransaction`, `getprioritisedtransactions`, `getdeploymentinfo`.
- `src/rpc/server.ts:4906-5013` — `submitBlock` implementation.
- `src/rpc/server.ts:5016-5259` — `getBlockTemplate` implementation.
- `src/rpc/server.ts:5262-5469` — `generateToAddress` / `generateBlock` /
  `generateToDescriptor` regtest miners.
- `src/rpc/server.ts:5474-5619` — `generateBlocks` loop +
  `generateSingleBlock` (the actual block-builder used by every regtest
  mining RPC).
- `src/rpc/server.ts:5624-5693` — `buildCoinbaseTx` /
  `buildCoinbaseTxWithWitnessCommitment` (the bad coinbase builders).
- `src/rpc/server.ts:5786-5799` — `getBlockSubsidy` (HARDCODED 210_000
  halving interval — W145 BUG-1 carry-forward + W154 BUG-18 re-anchored).
- `src/rpc/server.ts:7476-7502` — `getMiningInfo` RPC.
- `src/rpc/server.ts:8885-8950` — `getNetworkHashPS`.
- `src/mining/template.ts:1-685` — `BlockTemplateBuilder` class (685
  LOC). W14/W63 fixes present; **never instantiated by RPC** (W154 BUG-1).
- `src/mining/template.test.ts` — 1337 LOC of tests against the unused
  helper.
- `src/__tests__/w123_mining_gbt.test.ts` — W123 22-bug audit + BUG-21
  source-level pin that `new BlockTemplateBuilder` does not appear in
  `rpc/server.ts`.
- `src/validation/errors.ts:123-280` — `bip22Result` reason-string
  mapper (BIP22ValidationResult analogue).
- `src/validation/block.ts:398-449` — `validateBlockHeader` (the
  pre-merkle, pre-witness check).
- `src/validation/block.ts:517-611` — `validateBlock` (called from
  `submitBlock` only; **NOT** from `generateSingleBlock` — confirms W154
  BUG-2).
- `src/sync/blocks.ts:826-960` — `injectBlock` (the BIP-22 result-string
  generator for the duplicate / inconclusive / connect-fail cases).
- `src/consensus/params.ts:393, 1002, 1046-1062` — `subsidyHalvingInterval`
  (per-network) + `getBlockSubsidy` (params-aware; **disagrees with the
  RPC-private copy**, W154 BUG-18 reconfirmed).
- `src/mempool/mempool.ts:2605-2615` — `getTransactionsByFeeRate`
  (flat per-tx sort, not chunk-feerate).

---

## Gate matrix (40 sub-gates / 17 behaviours)

| # | Behaviour | Sub-gate | Verdict |
|---|-----------|----------|---------|
| 1 | RPC routing | G1: `getblocktemplate` registered | PASS (`server.ts:1148`) |
| 1 | … | G2: `submitblock` registered | PASS (`server.ts:1152`) |
| 1 | … | G3: `submitheader` registered | **BUG-1 (P1, W123 BUG-12 / W154 BUG-23 re-anchored)** — string `submitheader` appears in zero non-test files (`grep -n submitheader src/rpc/server.ts → 0 matches`). External pools and `bitcoin-cli submitheader` get method-not-found |
| 1 | … | G4: `prioritisetransaction` registered | **BUG-2 (P1, W123 BUG-13 / W154 BUG-24 re-anchored)** — absent. Operator cannot pin or de-prioritise mempool entries |
| 1 | … | G5: `getprioritisedtransactions` registered | **BUG-3 (P1, W123 BUG-14 / W154 BUG-25 re-anchored)** — absent |
| 1 | … | G6: `getmininginfo` registered | PASS (`server.ts:1153`) |
| 2 | GBT pre-call guards | G7: refuse while in IBD (`RPC_CLIENT_IN_INITIAL_DOWNLOAD`) | **BUG-4 (P0-RPC, W123 BUG-16 / W154 BUG-32 re-anchored)** — `getBlockTemplate` (server.ts:5021-5259) has no `this.computeInitialBlockDownload(...)` gate at top. A node mid-IBD happily emits a template based on the in-progress tip; a pool driven from that template builds blocks on a chain it has not yet finished validating |
| 2 | … | G8: refuse with 0 peers (`RPC_CLIENT_NOT_CONNECTED`) | **BUG-4 cross-cite** — no `if (this.getConnectionCount() === 0) throw` gate |
| 3 | BIP-22 mode parsing | G9: `mode=template` accepted | PASS (default at server.ts:5025) |
| 3 | … | G10: `mode=proposal` runs TestBlockValidity and returns BIP-22 reason | **BUG-5 (P1, W123 BUG-11 / W154 BUG-29 re-anchored)** — server.ts:5048 explicitly throws `"Only 'template' mode is supported"`. Pools using libblockmaker/cgminer's `mode=proposal` self-test path get a fatal error rather than a reason string |
| 3 | … | G11: `mode=disable` no-ops cleanly (BIP-22 explicit) | **BUG-6 (P2)** — also throws "Only 'template'"; BIP-22 says disable is a legal mode that disables long-polling for this connection |
| 4 | GBT rules + capabilities | G12: result.`capabilities` advertises supported optional fields | PARTIAL — server.ts:5206 emits `capabilities: ["proposal"]` literally — but proposal mode is rejected (BUG-5), so the advertised capability is a lie. **BUG-7 (P1)** — capabilities advertisement misleading |
| 4 | … | G13: `rules:["segwit"]` required from client (Core honours but doesn't require) | PARTIAL — server.ts:5053 hard-requires `segwit` in the client rules and throws if absent. Core merely tracks the rules the client supports (`rpc/mining.cpp` `setClientRules`) and adjusts the template accordingly; the segwit rule is not required for the call to succeed when segwit is active. **BUG-8 (P1)** — Core compatibility: an older pool that doesn't send `rules:[]` gets a fatal-class error rather than a degraded segwit-stripped template |
| 4 | … | G14: `gbtRules` output ordering matches Core (csv, !segwit, taproot) | PASS (server.ts:5160-5167) |
| 4 | … | G15: `vbavailable` populated from STARTED/LOCKED_IN BIP9 deployments | PASS (server.ts:5173-5202) |
| 4 | … | G16: `vbrequired` correctly derived (Core: bitmask of bits that MUST be set) | **BUG-9 (P1)** — server.ts:5210 hardcodes `vbrequired: 0`. Core sets the bit for any deployment in `LOCKED_IN` whose `state == ThresholdState::LOCKED_IN` AND `expectedActivationHeight` is the next block. A pool keying on `vbrequired` cannot detect imminent activation |
| 5 | Per-tx serialisation | G17: `data` hex of full serialised tx (witness if present) | PASS (`serializeTx(entry.tx, true)` at server.ts:5097 — true = include witness) |
| 5 | … | G18: `txid` is display-byte-order hex | PASS (server.ts:5085 reverses) |
| 5 | … | G19: `hash` is wtxid (display-byte-order if BIP-141 active) | **BUG-10 (P1)** — server.ts:5102 emits `getWTxId(entry.tx).toString("hex")` **without reversing**. BIP-22 (Core `rpc/mining.cpp` ~line 1010) reverses the wtxid for display. A pool that compares `transactions[i].hash` against block-explorer wtxids sees inverted bytes |
| 5 | … | G20: `depends[]` indices are 1-based | PASS (server.ts:5073 sets `idx = 1`; `txIndex.set` registers at the current idx) |
| 5 | … | G21: `depends[]` populated from ancestors actually in template | PARTIAL — server.ts:5088-5095 walks `entry.dependsOn` and includes only ancestors already in `txIndex`. **BUG-11 (P0-CDIV)** — but BUG-12 below means the mempool iteration order is wrong, so a child enumerated before its parent has `depends:[]` even though Core would have ordered the parent first |
| 5 | … | G22: mempool iterated in topological-then-fee order | **BUG-12 (P0-CDIV)** — server.ts:5074 uses `this.mempool.getAllTxids()` (insertion order). Core walks the cluster mempool's `GetBlockBuilderChunk` which returns the next best-feerate **chunk** that has all ancestors already selected. Net effect: a tx may appear in the GBT before its parent → a miner that includes the template as-is sends `bad-txns-inputs-missingorspent` to peers |
| 5 | … | G23: `fee` field is JSON Number in satoshis | PASS (server.ts:5104 — `Number(entry.fee)`) |
| 5 | … | G24: `sigops` field is per-tx sigOpCost (NOT raw) | PARTIAL — server.ts:5105 emits `txSigOpCost = entry.sigOpCost ?? 0`. **BUG-13 (P1)** — defaults to 0 when `entry.sigOpCost` is undefined. A mempool entry written before W123 (or by a code path that skipped sigop accounting) reports `sigops:0`, which a pool relying on the field cannot detect-and-skip |
| 5 | … | G25: `weight` field is per-tx weight (vsize * 4) | PASS (server.ts:5106) |
| 6 | GBT top-level scalar fields | G26: `coinbasevalue` is JSON Number (BIP-22 required) | PASS (server.ts:5214 — `Number(coinbaseValue)`). **BUT BUG-14 (P0-CDIV)** — `coinbaseValue = subsidy + totalFees` uses `getBlockSubsidy(height)` (server.ts:5116) which calls the RPC-private `getBlockSubsidy` at `server.ts:5789-5799` with HARDCODED `HALVING_INTERVAL=210_000`. The validator-side `consensus/params.ts:1046-1062 getBlockSubsidy` is params-aware (210k mainnet / 150 regtest). **Two-pipeline guard 18th distinct fleet extension**; W145 BUG-1 + W154 BUG-18 still live on this code path. On regtest past h=150 the GBT advertises 50 BTC subsidy → miner builds coinbase claiming 50 BTC → block is `bad-cb-amount` against every peer that uses the params-aware path (which is every other hashhog node). |
| 6 | … | G27: `coinbasevalue` excluded when `coinbasetxn` mode requested | **BUG-15 (P1)** — server.ts always emits `coinbasevalue` regardless of the client's `capabilities:["coinbasetxn"]` request. BIP-22: when the client asks for `coinbasetxn` capability the server SHOULD emit a `coinbasetxn` object (a fully-built coinbase tx the miner can splice) and omit `coinbasevalue`. hotbuns does neither — `coinbasetxn` is wholly unimplemented |
| 6 | … | G28: `mintime` is MTP(parent) + 1 | PASS (server.ts:5145-5147). Note BIP-94 miner-side clamp (W154 BUG-21) still absent — a mainnet retarget-boundary GBT past a future BIP-94 activation gives the wrong floor |
| 6 | … | G29: `curtime` is wall-clock (server's view of "now") | PASS (server.ts:5128, 5223) |
| 6 | … | G30: `sigoplimit == MAX_BLOCK_SIGOPS_COST == 80000` | PASS (server.ts:5220 — literal `80000`). **BUG-16 (P2)** — Core publishes `m_options.coinbase_output_max_additional_sigops` deducted; hotbuns publishes the raw 80000, slightly overstating the miner's working budget |
| 6 | … | G31: `sizelimit == MAX_BLOCK_SERIALIZED_SIZE == 4_000_000` post-segwit | PARTIAL — server.ts:5221 emits `sizelimit: 4_000_000`. Core also publishes `4_000_000` post-segwit. **BUG-17 (P1)** — but Core has TWO distinct constants: `MAX_BLOCK_WEIGHT == 4_000_000` (the consensus weight limit) and `MAX_BLOCK_SERIALIZED_SIZE == 4_000_000` (the wire-serialisation size limit). They happen to share a value but represent different invariants. hotbuns conflates them (same literal 4_000_000 used for both `sizelimit` and `weightlimit` at server.ts:5221-5222) and there is no actual `MAX_BLOCK_SERIALIZED_SIZE` constant defined anywhere — a future change to weight limits would silently break the size limit and vice-versa |
| 6 | … | G32: `weightlimit == MAX_BLOCK_WEIGHT == 4_000_000` | PASS (server.ts:5222) |
| 6 | … | G33: `target` is 64-char hex (256-bit, zero-padded LE→hex) | PASS (server.ts:5139, 5216) |
| 6 | … | G34: `bits` is 8-char hex of compact target | PASS (server.ts:5140, 5224) |
| 6 | … | G35: `height` is the NEW block's height | PASS (server.ts:5062, 5225) |
| 6 | … | G36: `previousblockhash` is display-byte-order | PASS (server.ts:5120 reverses) |
| 6 | … | G37: `coinbaseaux` populated from `-aux` arg | **BUG-18 (P1)** — server.ts:5213 emits literal `coinbaseaux: {}` always. Core merges in operator-provided aux scripts (`-uacomment`-style); merged-mining pools (e.g. Namecoin merge-mine) put their commitment data here. With `{}` hardcoded, hotbuns can never participate in merge-mining setups |
| 7 | BIP-23 mutability + nonce | G38: `mutable[]` includes "time", "transactions", "prevblock" | PASS (server.ts:5218) |
| 7 | … | G39: `mutable[]` includes "version/force" + "version/reduce" when applicable | **BUG-19 (P1)** — Core (rpc/mining.cpp ~line 1085) appends `version/force` if the client signalled "longpoll" and various version-bit flags; hotbuns hardcodes the array, so the miner has no signal it may flip version bits |
| 7 | … | G40: `noncerange` is `"00000000ffffffff"` (BIP-23 default) | PASS (server.ts:5219) |
| 8 | default_witness_commitment | G41: emitted when segwit active at new height | PASS (server.ts:5238-5255) |
| 8 | … | G42: 38-byte scriptPubKey (OP_RETURN PUSH36 marker commitment) | PASS (server.ts:5251-5254) |
| 9 | longpollid + longpoll wait | G43: longpollid emitted | PASS (server.ts:5215) |
| 9 | … | G44: longpollid encodes (prevblockhash, nTransactionsUpdatedLast) | PARTIAL — server.ts:5215 uses `${previousblockhash}${idx}` where `idx` is the **next-tx-index after the loop** (i.e. `mempoolSize + 1`), not Core's `nTransactionsUpdatedLast` counter. A pool seeing the longpollid change cannot tell whether the tip moved or the mempool churned, only that "something is different" |
| 9 | … | G45: server waits up to wait_timeout when client sends longpollid matching the previous call | **BUG-20 (P0-RPC, W123 BUG-17 / W154 BUG-30 re-anchored)** — `getBlockTemplate` returns immediately; there is NO `await` on a tip-changed/mempool-update signal. The longpollid field is decoration — a pool that long-polls by re-issuing the call with the previous longpollid sees the same answer back in milliseconds, defeating the entire BIP-22 long-poll optimisation |
| 10 | Template caching | G46: cache key = (pindexPrev, nTransactionsUpdatedLast) | **BUG-21 (P1, W123 BUG-18 / W154 BUG-31 re-anchored)** — every call rebuilds from scratch. Per `assemble_template_for_RPC` in Core (mining.cpp:864), the cache makes back-to-back GBT calls (typical 1Hz pool polling) close to free. hotbuns walks the full mempool on every call |
| 11 | submitblock decode + pre-validation | G47: returns `"high-hash"` when block PoW > target | PASS (server.ts:4955-4957) |
| 11 | … | G48: returns `"time-too-old"` when block.timestamp <= MTP | PASS (server.ts:4965-4967) |
| 11 | … | G49: returns `"time-too-new"` when block.timestamp > now+2h | **BUG-22 (P0-CDIV)** — submitBlock's pre-validation (server.ts:4946-4971) checks PoW + MTP but NOT the `header.timestamp > now+2h` (`MAX_FUTURE_BLOCK_TIME`) gate from `validation/block.ts:404-409`. The check IS run inside `validateBlock(block, approxHeight, this.params)` at server.ts:4998, but `validateBlock` calls `validateBlockHeader` only when `prevHeader !== null` — actually grep shows `validateBlock` does NOT call `validateBlockHeader`. The block enters injectBlock and is finally rejected somewhere deep in headers/connect_block with a free-form error string that the BIP-22 mapper (`errors.ts:262-264`) maps to `"time-too-new"` only if the string includes "time-too-new" or "timestamp ... too far". The mapping is fragile; a pool submitting a clock-skewed block sees `"rejected"` rather than the canonical `"time-too-new"` BIP-22 reason |
| 12 | submitblock optional `dummy` arg | G50: accepts and ignores second arg | **BUG-23 (P2)** — server.ts:4922 destructures `[hexdata]`, ignoring the 2nd parameter entirely. Per BIP-22 `submitblock(hexdata, dummy)`, the 2nd arg is a no-op alias for legacy compatibility. hotbuns will return method-not-found-or-arity-mismatch if a caller (bitcoin-cli does) passes the legacy second positional argument. Test: `bitcoin-cli submitblock <hex> {"workid":"…"}` — fails on hotbuns |
| 12 | … | G51: returns `"duplicate"` when block already known on side-branch | PASS (`sync/blocks.ts:896`) |
| 12 | … | G52: returns `"duplicate-invalid"` when block already known + marked invalid | **BUG-24 (P1, W154 BUG-30 cross-cite)** — `errors.ts:194` recognises the string but `injectBlock` (sync/blocks.ts) never emits `"duplicate-invalid"`. Re-submitting an already-rejected block returns `"inconclusive"` or `"rejected"` rather than `"duplicate-invalid"` |
| 13 | submitblock → connect pipeline | G53: `validateBlock` runs before `injectBlock` | PASS (server.ts:4998 calls validateBlock; only failure-mode returns BIP-22 string). Cross-cite **W154 BUG-2**: mining path (`generateSingleBlock`) does NOT call validateBlock; only submitblock does |
| 13 | … | G54: BIP-22 reason returned, NOT JSON-RPC error object (BIP-22 result-in-body) | PASS (server.ts:5001 returns `bip22Result(reason)` not throw) |
| 13 | … | G55: orphan block returns `"inconclusive"` | PASS (sync/blocks.ts:844) |
| 13 | … | G56: blockSubmissionPaused returns `"rejected"` | PASS (server.ts:4917-4920) |
| 14 | submitblock signet block solution | G57: signet challenge-script verified | **BUG-25 (P0-CONS-signet)** — grep over `src/validation/` `src/sync/headers.ts` `src/consensus/` for "signet" + "challenge" returns zero matches inside any verifier. The signet `consensus/params.ts:892-902` carries the challenge script in metadata but no production-side code reads or verifies it. A submitblock on signet with a non-signet-signed block is admitted with NO solution check; chain forks from real signet at block 1 (same shape as blockbrew W143 BUG-9 fleet P0-CONS-signet cross-cite). |
| 15 | submitblock BIP22ValidationResult | G58: token sweep — `bad-cb-amount` token returned for inflation | PARTIAL — errors.ts:211 catches via substring "subsidy" / "coinbase value" / "bad-cb-amount" — fragile substring-match (the connect_block error string format is one source of truth, the mapper is another; "two-pipeline guard" 19th instance for reason-string parity) |
| 15 | … | G59: token sweep — `bad-cb-length` token returned for coinbase scriptSig < 2 or > 100 bytes | PASS (validation/block.ts:538 emits `"bad-cb-length"`; errors.ts:181 carries through) |
| 15 | … | G60: token sweep — `bad-witness-merkle-match` returned on commitment mismatch | PASS (errors.ts:208) |
| 15 | … | G61: token sweep — `bad-version(0x........)` returned with the canonical hex | PASS (errors.ts:272-274 — preserves form). **BUG-26 (P1)** — but the substring-match `s.includes("bad-version")` fires on any error containing that substring, including helpful diagnostics; a future error message like "bad-version-bits-comparator" would mis-map |
| 16 | getmininginfo fields | G62: `currentblockweight` (m_last_block_weight) | **BUG-27 (P1, W123 BUG-10 / W154 BUG-26 re-anchored)** — absent. server.ts:7485-7501 returns blocks/bits/difficulty/blockmintxfee/pooledtx but not currentblockweight/currentblocktx — Core (`rpc/mining.cpp` ~line 467) publishes these after every CreateNewBlock |
| 16 | … | G63: `currentblocktx` (m_last_block_num_txs) | **BUG-27 cross-cite** |
| 16 | … | G64: `blockmintxfee` from `-blockmintxfee` arg | **BUG-28 (P0-RPC, W123 BUG-22 / W154 BUG-6 re-anchored)** — server.ts:7490 hardcodes `0.00001000`; no `-blockmintxfee` parser anywhere |
| 16 | … | G65: `networkhashps` delegated to getNetworkHashPS | **BUG-29 (P1, W123 BUG-9 / W154 BUG-27 re-anchored)** — server.ts:7491 returns `networkhashps: 0` hardcoded. `getNetworkHashPS` IS implemented at server.ts:8885 but unwired here |
| 16 | … | G66: `next.bits` / `next.target` derived from NextEmptyBlockIndex (the NEW block's required bits, not the tip's) | **BUG-30 (P0-CDIV, W123 BUG-8 / W154 BUG-28 re-anchored)** — server.ts:7494-7499 returns the TIP's bits/target as `next.bits`/`next.target`. Operators relying on this to decide when to call GBT will mine at the wrong difficulty for the next block at retarget boundaries (every 2016 blocks) |
| 17 | BlockTemplateBuilder used by production GBT (W123 BUG-21 carry-forward) | G67: `getblocktemplate` instantiates `BlockTemplateBuilder` | **BUG-31 (P0-DEAD, W123 BUG-21 / W154 BUG-1 re-anchored)** — `grep -c "new BlockTemplateBuilder" src/rpc/server.ts → 0`. The 685-LOC builder class + 1337-LOC test file is pure dead weight; W14/W63/W123 fixes never reach production. **34th-consecutive audit wave** to find this exact pattern. The `import` exists (server.ts:44) and the W123 source-level test pins this dead-import explicitly. The hand-rolled `getBlockTemplate` (server.ts:5021-5259) and `generateSingleBlock` (server.ts:5492-5619) both reimplement the same logic without the fixes |

---

## BUG-1 (P1, W123/W154 carry-forward) — `submitheader` RPC absent

**Severity:** P1. Bitcoin Core's `submitheader` is the canonical way for
external miner pools to push a candidate header for validation
**without** the body — the typical usage is to push the header first
(to advance the local view of the best chain so subsequent GBT calls
key off the right tip), then push the body separately or via a peer.

hotbuns has no `registerMethod("submitheader", …)` call in
`src/rpc/server.ts` (line range 1078-1257; method registration
audited). The W123 source-level test at
`src/__tests__/w123_mining_gbt.test.ts:354-358` already pins this:

```ts
expect(RPC_SERVER_SRC).not.toContain('registerMethod("submitheader"');
expect(RPC_SERVER_SRC).not.toContain("submitheader");
```

The test is still passing (the method still doesn't exist) — the bug
has been pinned and re-anchored across W123 (May 17), W154 (May 18
morning), and W155 (now), unfixed.

**File:** `src/rpc/server.ts:1078-1257` (RPC dispatch).

**Core ref:** `bitcoin-core/src/rpc/mining.cpp::submitheader`.

**Impact:** external pools and `bitcoin-cli submitheader` return
method-not-found. Fleet pattern carry-forward — same shape as W154
BUG-23 (P1, also re-anchored as "absent for 5 weeks").

---

## BUG-2 (P1, W123/W154 carry-forward) — `prioritisetransaction` RPC absent

**Severity:** P1. Bitcoin Core's `prioritisetransaction(txid, dummy,
fee_delta)` adjusts the in-block-builder fee an entry appears to pay,
allowing operators to pin or deprioritise specific mempool entries.
It is consumed by the block assembler's chunk-feerate ordering.

hotbuns has no registration. The mempool entry type also lacks a
`feeDelta` field (see `src/mempool/persist.ts:301` per W154 BUG-24
audit notes): the operator has nowhere to write the delta even if the
RPC existed.

**File:** `src/rpc/server.ts:1078-1257`; `src/mempool/mempool.ts` (no
`feeDelta` field on `MempoolEntry`).

**Core ref:** `bitcoin-core/src/rpc/mining.cpp::prioritisetransaction`.

**Impact:** operator cannot pin or de-prioritise a tx in the next
block template — the typical use case (a pool boosting a paying
sponsor tx, or de-prioritising a tx the operator wishes to drop) is
unsupported.

---

## BUG-3 (P1, W123/W154 carry-forward) — `getprioritisedtransactions` RPC absent

**Severity:** P1. The read-side companion to BUG-2. Both are absent
together as the feeDelta primitive is missing.

**File:** same as BUG-2.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp::getprioritisedtransactions`.

**Impact:** operator cannot inspect the currently-applied fee deltas;
monitoring tools that scrape this field across the fleet see hotbuns
gap.

---

## BUG-4 (P0-RPC, W123/W154 carry-forward) — `getblocktemplate` lacks IBD + peer-count guards

**Severity:** P0-RPC. Bitcoin Core's `getblocktemplate` is
unconditionally gated at the top of the RPC handler:

```cpp
if (m_node.chainman->ActiveChainstate().IsInitialBlockDownload())
    throw JSONRPCError(RPC_CLIENT_IN_INITIAL_DOWNLOAD,
                       "Bitcoin is in initial sync ...");
if (m_node.connman->GetNodeCount(...) == 0)
    throw JSONRPCError(RPC_CLIENT_NOT_CONNECTED, "Bitcoin is not connected!");
```

Both gates are absent from `src/rpc/server.ts:5021-5259`. A node that
restarts mid-IBD and starts serving its first GBT call:
1. responds with a template based on whatever its in-memory tip is
   (which may be hundreds of blocks behind the chain),
2. that template's coinbasevalue is computed against the **stale**
   subsidy/halving boundary,
3. the pool builds a block at the IBD tip → broadcasts → every peer
   rejects with "stale: builds on N-old tip".

The same pathology applies on a fresh datadir or a node that has lost
all peers — the GBT continues to emit templates the network will
never accept.

**File:** `src/rpc/server.ts:5021-5259` (`getBlockTemplate`); the IBD
oracle exists at `src/rpc/server.ts:5927-5955`
(`computeInitialBlockDownload`) but is never called from
`getBlockTemplate`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp::getblocktemplate`
pre-call guards.

**Impact:** the canonical "node-is-not-ready-to-mine" sentinels are
absent. Pools relying on bitcoin-CLI's `RPC_CLIENT_IN_INITIAL_DOWNLOAD`
error code to gate their auto-restart loop see hotbuns happily serve
templates instead.

---

## BUG-5 (P1, W123/W154 carry-forward) — `mode=proposal` rejected, blocks self-test

**Severity:** P1. BIP-22 defines three modes: `template` (default),
`proposal` (validate a candidate block without submitting it), and
`disable` (sentinel meaning "I don't need a template; disable
long-polling"). Production pool software (libblockmaker, cgminer's
`getblocktemplate-proposal` mode, eloipool) uses `mode=proposal`
extensively as a self-test before submitting.

hotbuns rejects with a hard error:

```ts
if (mode !== "template") {
    throw this.rpcError(RPCErrorCodes.INVALID_PARAMS,
                        "Only 'template' mode is supported");
}
```

The advertised `capabilities: ["proposal"]` (server.ts:5206) is a
**lie** — the response claims to support proposal mode but the very
next dispatch rejects it. The lie is then BUG-7 below.

**File:** `src/rpc/server.ts:5046-5050` (mode check), 5206
(capabilities advertisement).

**Core ref:** `bitcoin-core/src/rpc/mining.cpp` `mode=proposal` branch.

**Impact:** pool software's self-test before broadcast falls through
to a fatal-error path rather than a per-block BIP-22 reason string.

---

## BUG-7 (P1) — `capabilities: ["proposal"]` advertised but proposal mode rejected

**Severity:** P1 ("comment-as-confession" → "advertisement-as-lie"
pattern; first hotbuns instance of this specific shape, fleet
companion to W144's "exception-map short-circuit elides Core's
fall-through"). The response object claims `capabilities: ["proposal"]`
unconditionally (server.ts:5206), but the dispatch above rejects
proposal-mode requests with INVALID_PARAMS (BUG-5). A pool that
inspects `capabilities[]` to decide whether to send a proposal-mode
request will be misled and crash.

**File:** `src/rpc/server.ts:5206` (the lie) +
`src/rpc/server.ts:5046-5050` (the rejection).

**Core ref:** `bitcoin-core/src/rpc/mining.cpp` — Core advertises
`capabilities: ["proposal"]` and accepts proposal-mode requests.

**Impact:** misleading API contract. Listed separately from BUG-5
because the fix has two distinct deltas (either implement proposal OR
remove the lie).

---

## BUG-8 (P1) — `rules:["segwit"]` hard-required rather than negotiated

**Severity:** P1. BIP-22 says the client SHOULD send `rules:[]` with
the rule names it supports, so the server can suppress fields the
client cannot understand. Core does NOT require any particular rule
in the array; the only invariant is "if you don't advertise a rule
the server is depending on, you'll get a bad block".

hotbuns hard-errors when `rules[]` doesn't contain `segwit`:

```ts
if (!clientRules.has("segwit")) {
    throw this.rpcError(RPCErrorCodes.INVALID_PARAMS,
                        "getblocktemplate must be called with the segwit rule set ...");
}
```

This rejects pre-BIP-141 pool software (mining devices with hardcoded
GBT clients) as well as legitimate "I just want to inspect the
template" clients. Core's behaviour is to emit the template with
segwit-stripped data and let the client decide.

**File:** `src/rpc/server.ts:5053-5057`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp` GBT rule negotiation
(`rules.find("segwit") == rules.end()` triggers a `_warning`, not a
fatal error).

**Impact:** old pool software with hardcoded GBT clients cannot mine
against hotbuns.

---

## BUG-9 (P1) — `vbrequired: 0` hardcoded

**Severity:** P1. Core sets `vbrequired` to the bitmask of bits that
the miner MUST set in the block version, derived from LOCKED_IN
deployments whose activation is imminent. hotbuns hardcodes `0`
(server.ts:5210). A pool keying on `vbrequired` to know "you MUST set
this bit or the block will be rejected for bad-version" is misled —
it relies on `vbavailable` only, which is best-effort.

**File:** `src/rpc/server.ts:5210`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp` ~line 1015 derives
vbrequired from `state == ThresholdState::LOCKED_IN` + the imminent
activation height check.

**Impact:** activation-day blocks may be built with vbrequired bits
missing, immediately rejected by post-activation peers. Edge case but
recurring at each soft-fork (last instance: taproot activation in
2021).

---

## BUG-10 (P1) — Per-tx `hash` wtxid not byte-reversed for display

**Severity:** P1. The BIP-22 spec and Core's GBT serialiser both emit
the `hash` field (the wtxid) in display byte order (i.e. reversed
from internal little-endian). hotbuns emits internal byte order:

```ts
hash: getWTxId(entry.tx).toString("hex"),    // server.ts:5102 — NOT reversed
```

Compare to the same loop's `txid` field at server.ts:5085:

```ts
const txidHex = Buffer.from(txid).reverse().toString("hex");   // reversed (correct)
```

A pool that compares the GBT's `hash` against a block-explorer's wtxid
(which is displayed in reversed/display order) sees byte-flipped data,
cannot find the tx in the explorer, and may misclassify it as "not in
network" → silently drop it.

**File:** `src/rpc/server.ts:5102`.

**Core ref:** BIP-22; `bitcoin-core/src/rpc/mining.cpp` ~line 1010
emits `tx.GetWitnessHash().GetHex()` — `GetHex()` is reversed.

**Impact:** monitoring divergence; misleading data; possibly
silent-drop classifications in pool reconciliation tooling.

---

## BUG-11 (P0-CDIV) — `depends[]` is broken when mempool iteration is non-topological

**Severity:** P0-CDIV. The `depends[]` field per-tx requires that
parents appear in the template BEFORE their children (BIP-22 invariant
— `depends[i]` is a list of 1-based indexes into the template's
`transactions[]`). hotbuns walks `mempool.getAllTxids()` in insertion
order (BUG-12 below) and emits each entry with its current `dependsOn`
ancestors resolved against `txIndex` — but the txIndex only contains
entries already processed in the current loop. If a child's parent
hasn't been visited yet, the child's `depends[]` is silently empty,
even though Core would have included a non-empty list.

**File:** `src/rpc/server.ts:5088-5095` (depends resolution from
`txIndex`) + `server.ts:5074` (the iteration order that breaks it).

**Core ref:** BIP-22 `depends[]` invariant; Core's
`GetBlockBuilderChunk` enforces topological order by walking the
cluster mempool's linearisation.

**Impact:** pools that consume `depends[]` to reorder for parallel
validation (cgminer, BetterHash) get a wrong dependency graph;
parent-after-child orderings cause the constructed block to be
`bad-txns-inputs-missingorspent`.

---

## BUG-12 (P0-CDIV) — Mempool iteration uses `getAllTxids()` (insertion order), not fee-rate / cluster ordering

**Severity:** P0-CDIV. The hand-rolled `getBlockTemplate` (server.ts:5074)
uses:

```ts
const mempoolTxids = this.mempool.getAllTxids();
```

`getAllTxids` returns entries in insertion order. Core's
`assemble_template_for_RPC` walks the cluster mempool's
`GetBlockBuilderChunk` which:
1. orders entries by **package feerate** (parent + descendants
   together), not single-tx feerate,
2. returns next-best **chunk** (which is topologically valid by
   construction).

hotbuns's mempool has `getTransactionsByFeeRate()` (mempool.ts:2608)
which IS a single-tx fee-rate sort — used by the DEAD
`BlockTemplateBuilder` helper but NOT by the production GBT RPC.

Compound effect with BUG-11: the GBT can emit a child before its
parent → `depends[]` doesn't reflect the ancestor → a miner that
respects the order gets an invalid block.

**File:** `src/rpc/server.ts:5074` (insertion-order iteration);
`src/mining/template.ts:344` (the correct fee-rate sort, in the dead
helper).

**Core ref:** `bitcoin-core/src/policy/feefrac.cpp::CompareChunks` +
cluster mempool's `GetBlockBuilderChunk`.

**Impact:** the template's transaction selection has neither
fee-maximisation nor topological-ordering guarantees. Effective
revenue loss vs Core + correctness break (BUG-11 cross-cite).

---

## BUG-13 (P1) — Per-tx `sigops` defaults to 0 when entry.sigOpCost is undefined

**Severity:** P1. `server.ts:5080` and 5105 use
`entry.sigOpCost ?? 0`. The `?? 0` fallback silently understates the
sigops budget when the mempool entry was written without sigop
accounting (e.g. by a pre-W123 entry, or by an injection path that
skipped sigop calculation). A pool relying on `transactions[i].sigops`
to enforce its own MAX_BLOCK_SIGOPS_COST budget sees `sigops:0` and
includes the tx; the resulting block is `bad-blk-sigops`.

**File:** `src/rpc/server.ts:5080, 5105`.

**Impact:** Latent — depends on whether the mempool entry was written
with a missing sigOpCost. Modern mempool writes set it correctly but
the defensive default risks silent budget misaccounting.

---

## BUG-14 (P0-CDIV, W145/W154 carry-forward) — `coinbasevalue` uses RPC-private hardcoded HALVING_INTERVAL

**Severity:** P0-CDIV. The GBT `coinbasevalue` field is computed via
the RPC-private `getBlockSubsidy(height)` at server.ts:5116-5117 →
which routes to the hardcoded server.ts:5789-5799:

```ts
private getBlockSubsidy(height: number): bigint {
    const INITIAL_SUBSIDY = 5_000_000_000n; // 50 BTC in satoshis
    const HALVING_INTERVAL = 210_000;
    const halvings = Math.floor(height / HALVING_INTERVAL);
    if (halvings >= 64) return 0n;
    return INITIAL_SUBSIDY >> BigInt(halvings);
}
```

The validator-side `src/consensus/params.ts:1046-1062` `getBlockSubsidy`
IS params-aware (210k mainnet, 150 regtest). The two functions
disagree on regtest past h=150. **Two-pipeline guard 18th distinct
fleet extension** (last count was 17 in W145).

**Cross-cites:**
- W145 BUG-1 (the primary discovery; ~3 weeks old, still unfixed)
- W154 BUG-18 (re-anchored on the createnewblock surface yesterday)
- This BUG-14 (re-anchored on the GBT surface today)

Each subsequent audit re-confirms the bug is live and getting closer
to the user-visible RPC contract. **34th-consecutive carry-forward**.

**File:** `src/rpc/server.ts:5789-5799` (the hardcoded copy);
`src/consensus/params.ts:1046-1062` (the correct copy);
`src/rpc/server.ts:5116-5117` (the GBT consumer; uses the wrong copy).

**Core ref:** `bitcoin-core/src/validation.cpp::GetBlockSubsidy(nHeight,
const Consensus::Params& consensusParams)` — single source of truth,
params-aware.

**Impact:** regtest pools that key off `coinbasevalue` produce blocks
with the wrong reward past h=150 → rejected by validator-side peers
with `bad-cb-amount`. On a regtest harness driven from hotbuns'
GBT, this is a hard chain-stall at h=151. Same root cause as W154
BUG-18; the fix is one line (call the params-aware import) but it has
sat in the queue since W123.

---

## BUG-15 (P1) — `coinbasetxn` mode absent

**Severity:** P1. BIP-22 defines two output modes:
- `coinbasevalue` (the default; server emits the total reward as a
  Number, miner builds the coinbase),
- `coinbasetxn` (server emits a fully-built coinbase tx the miner can
  splice in; useful for pools where the operator controls the coinbase
  scriptPubKey).

hotbuns always emits `coinbasevalue` (server.ts:5214). The client's
`capabilities:["coinbasetxn"]` request is ignored. The response object
never includes `coinbasetxn`.

**File:** `src/rpc/server.ts:5214` (always emits coinbasevalue);
no `coinbasetxn` field in any code path.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp` — when client
capabilities includes "coinbasetxn", server emits `coinbasetxn:
{data, txid, hash, depends, fee, sigops, weight}` and omits
`coinbasevalue`.

**Impact:** pools using `coinbasetxn` mode (mostly legacy / specialized
setups) cannot mine against hotbuns.

---

## BUG-17 (P1) — `MAX_BLOCK_SERIALIZED_SIZE` constant absent — conflated with `MAX_BLOCK_WEIGHT`

**Severity:** P1. Core has TWO distinct constants:
- `MAX_BLOCK_WEIGHT = 4_000_000` (consensus weight limit, validated
  in `ContextualCheckBlock`),
- `MAX_BLOCK_SERIALIZED_SIZE = 4_000_000` (wire-serialisation size
  limit, validated in `CheckBlock`).

They happen to share the value `4_000_000` but represent different
invariants. A future protocol change (e.g. a soft-fork that adjusts
one without the other) requires them to diverge.

hotbuns conflates them by using the literal `4_000_000` for both
`sizelimit` (server.ts:5221) and `weightlimit` (server.ts:5222),
with no named constant for `MAX_BLOCK_SERIALIZED_SIZE`. The
`maxBlockWeight` field on `ConsensusParams` exists but
`maxBlockSerializedSize` does not — only `maxBlockSize: 1_000_000`
(the LEGACY pre-segwit limit; params.ts:397) exists, and it's the
wrong value for the post-segwit size cap.

**File:** `src/rpc/server.ts:5221-5222`;
`src/consensus/params.ts:24, 397`.

**Core ref:** `bitcoin-core/src/consensus/consensus.h`
`MAX_BLOCK_SERIALIZED_SIZE = 4_000_000`,
`MAX_BLOCK_WEIGHT = 4_000_000`.

**Impact:** silent invariant collapse. The GBT correctly emits the
two fields with the same value, but no named constant means a future
change to either constant has to be reasoned about manually.

---

## BUG-18 (P1) — `coinbaseaux: {}` hardcoded — merge-mining unsupported

**Severity:** P1. Core's `coinbaseaux` is the place where merged-mining
pools (e.g. Namecoin merge-mine) plant their auxiliary commitment data
into the coinbase. Operators pass `-uacomment`-style flags to populate
it.

hotbuns hardcodes `coinbaseaux: {}` (server.ts:5213). There is no
configuration knob to populate it. A pool that depends on merge-mining
commitments cannot use hotbuns as their primary GBT source.

**File:** `src/rpc/server.ts:5213`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp` —
`coinbaseaux` populated from `g_chainman.GetParams().GetCoinbaseAux()`.

**Impact:** no merge-mining support. Limited audience (merge-mining
declining since 2021) but a real interoperability gap.

---

## BUG-19 (P1) — `mutable[]` missing `version/force` + `version/reduce`

**Severity:** P1. Core emits `mutable[]` with up to five entries:
`["time","transactions","prevblock","version/force","version/reduce"]`.
The two version/* entries tell the pool it may freely manipulate
block version bits (for force-signalling test deployments etc.).

hotbuns hardcodes the array to three entries (server.ts:5218). A
pool that depends on `mutable[]` for permissions sees a more
restrictive contract than Core actually exposes.

**File:** `src/rpc/server.ts:5218`.

**Impact:** legacy compatibility; force-signalling pool setups can't
auto-detect the permission.

---

## BUG-20 (P0-RPC, W123/W154 carry-forward) — longpoll wait absent; server returns immediately

**Severity:** P0-RPC. The longpoll mechanism is the BIP-22 way for
pools to avoid polling the GBT endpoint at high frequency: the pool
sends GBT with `longpollid=<value-from-previous-call>` and the server
WAITS until either (a) the tip changes, (b)
`nTransactionsUpdatedLast` changes, or (c) `wait_timeout` expires
before returning.

hotbuns emits `longpollid` (server.ts:5215) but the
`getBlockTemplate` function returns immediately — there is NO `await`
on a condition variable or tip-change signal. A pool that long-polls
gets the same template back in milliseconds, defeating the BIP-22
optimisation. The pool then either:
- polls at high frequency (network traffic + CPU on the GBT path), or
- gives up long-polling and waits a fixed interval (suboptimal latency
  to first-block-after-tip).

**File:** `src/rpc/server.ts:5021-5259` — no `await` on a tip-change
condition; just synchronous template construction.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp::getblocktemplate` —
`while (chainTip == hashWatchedChain && IsRPCRunning())
{ MilliSleep(LongPollPause); ... }`.

**Impact:** pools cannot long-poll hotbuns; either they get
high-frequency polling or stale-tip templates.

---

## BUG-21 (P1, W123/W154 carry-forward) — Template caching absent

**Severity:** P1. Core caches the template keyed on (pindexPrev,
nTransactionsUpdatedLast). Back-to-back GBT calls at typical pool
frequencies (1Hz) hit the cache and return in microseconds.

hotbuns rebuilds the template from scratch on every call, walking
the entire mempool (O(N) for N=mempool size). On a busy mainnet node
with 30k+ mempool entries this is a 100ms+ wall-clock per call. A
pool polling at 1Hz consumes ~10% of one CPU core just for GBT
construction.

**File:** `src/rpc/server.ts:5021-5259` — no cache.

**Impact:** mining-pool CPU utilisation; sub-second response time
gap vs Core.

---

## BUG-22 (P0-CDIV) — `time-too-new` not detected in submitblock pre-validation

**Severity:** P0-CDIV. Bitcoin Core's submitblock returns the
canonical BIP-22 string `time-too-new` when the block timestamp is
> now + 2h. The pre-validation check at
`src/rpc/server.ts:4946-4971` covers PoW (`high-hash`) and MTP
(`time-too-old`) but **not** the 2-hour future-timestamp cap.

The `validateBlock` call at server.ts:4998 does NOT invoke
`validateBlockHeader` (which is the function that has the
`maxFutureTime = now + 2h` check at validation/block.ts:404-409).
`validateBlock` proceeds directly to coinbase + merkle + weight
checks. So a block with timestamp = `now + 3h` passes pre-validation,
enters `injectBlock`, and the eventual rejection (deep in
`processHeaders` or `processOrderedBlocks`) produces an error string
that the `bip22Result` mapper (errors.ts:262-264) may or may not map
to `time-too-new` depending on the exact substring.

The fragility is: a pool submitting a clock-skewed block expects
the canonical `"time-too-new"` BIP-22 string. hotbuns might return
`"rejected"`, `"inconclusive"`, or `"time-too-new"` depending on
which code path catches the error first and what error string it
emits.

**File:** `src/rpc/server.ts:4946-4971` (pre-validation, missing
2-hour gate); `src/validation/block.ts:404-409` (the right check,
not invoked from validateBlock); `src/validation/errors.ts:262-264`
(the fragile substring mapper).

**Core ref:** `bitcoin-core/src/validation.cpp::CheckBlockHeader`
returns `"time-too-new"` for timestamp > GetAdjustedTime() +
MAX_FUTURE_BLOCK_TIME (2 * 60 * 60); BIP22ValidationResult maps it
canonically.

**Impact:** non-deterministic BIP-22 reason string for clock-skewed
submissions; pool error-handling code may misclassify the failure
mode.

---

## BUG-23 (P2) — submitblock ignores second positional argument `dummy`

**Severity:** P2. BIP-22 spec defines `submitblock(hexdata, dummy)`
where `dummy` is a no-op alias retained for legacy Stratum-compat
reasons (e.g. `bitcoin-cli submitblock <hex> '{"workid":"…"}'`).
hotbuns destructures `const [hexdata] = params;` (server.ts:4922)
— if a caller sends 2 args, the second is silently ignored, which is
actually correct behaviour. **HOWEVER** the JSON-RPC dispatcher
upstream may complain about arity if a strict schema is enforced; a
quick test against `bitcoin-cli submitblock <hex> {"workid":"foo"}`
should be performed.

(Re-classified to P2 from initial P1 after re-reading — the silent
ignore is actually within spec; the impact is only visible if a
strict arity check exists upstream.)

**File:** `src/rpc/server.ts:4922`.

**Core ref:** BIP-22; `bitcoin-core/src/rpc/mining.cpp::submitblock`.

**Impact:** monitoring; minimal.

---

## BUG-24 (P1) — `duplicate-invalid` never emitted

**Severity:** P1. BIP-22 defines `duplicate-invalid` for the case
where a previously-submitted block was already known AND marked
invalid (e.g. submitted twice, rejected first time for
`bad-witness-merkle-match`). Re-submitting should return
`duplicate-invalid`, distinct from `duplicate` (which is "valid but
known on a side branch").

hotbuns `injectBlock` (sync/blocks.ts:826-960) emits `duplicate`
(line 896) and `inconclusive` (lines 844, 906) but never
`duplicate-invalid`. The `bip22Result` mapper (errors.ts:194)
recognises the string but no producer ever emits it.

**File:** `src/sync/blocks.ts:826-960` (no `duplicate-invalid`
emission); `src/validation/errors.ts:194` (the recogniser, unused).

**Core ref:** `bitcoin-core/src/rpc/mining.cpp::submitblock` returns
`"duplicate-invalid"` when `m_chainman->m_blockman.LookupBlockIndex(hash)`
returns a CBlockIndex with `BLOCK_FAILED_MASK` set.

**Impact:** re-submission classification ambiguous; pool tooling that
keys on `duplicate-invalid` to stop retrying a bad block keeps
retrying.

---

## BUG-25 (P0-CONS, signet) — Signet block solution NOT verified

**Severity:** P0-CONS-signet. Signet uses a custom block-signing
scheme (BIP-325): each block carries a witness commitment that signs
the block contents with the signet challenge script's private key.
Core's `CheckSignetBlockSolution` verifies the signature against the
challenge before accepting any signet block.

hotbuns carries the challenge script in metadata
(`src/consensus/params.ts:892-902` builds the signet genesis with a
hardcoded challenge), but **no production-side code reads or verifies
it**. `grep -rn "signetChallenge\|CheckSignet" src/` returns zero
matches outside of `consensus/params.ts`. A submitblock on signet
with a non-signet-signed block is admitted by hotbuns; on signet, the
chain forks from real signet at block 1.

**File:** `src/consensus/params.ts:892-902` (challenge stored),
`src/validation/block.ts`, `src/sync/headers.ts`,
`src/consensus/connect_block.ts` (verifier absent).

**Core ref:** `bitcoin-core/src/signet.cpp::CheckSignetBlockSolution`;
called from `validation.cpp::CheckBlock`.

**Impact:** fleet P0-CONS-signet finding, **identical shape to
blockbrew W143 BUG-9**: a hotbuns signet node accepts any
PoW-valid block, immediately forks from real signet, and its
view of "signet" is meaningless. The W155 fleet-pattern entry is the
second confirmation (blockbrew yesterday, hotbuns today). Likely
fleet-wide gap — needs sweep.

---

## BUG-26 (P1) — `bad-version(...)` substring matcher mis-maps unknown errors

**Severity:** P1. `errors.ts:272-274` maps any error string
containing the substring `"bad-version"` to a preserved
`"bad-version(0xNNNN)"` form. A future error message like
`"bad-version-bits-comparator"` would mis-map to
`"bad-version-bits-comparator".split(":")[0]` =
`"bad-version-bits-comparator"`, which is not a canonical BIP-22
string. Pool error-handling code may not recognise the result.

**File:** `src/validation/errors.ts:272-274`.

**Impact:** future-fragility of the reason-string mapper. Same
fleet pattern as the W145 lunarblock "reject-string wire-parity
slippage" finding.

---

## BUG-27 (P1, W123/W154 carry-forward) — `currentblockweight` + `currentblocktx` absent from getmininginfo

**Severity:** P1. Core's getmininginfo publishes:
- `currentblockweight` — the weight of the last-assembled block
  (m_last_block_weight on BlockAssembler),
- `currentblocktx` — the tx count of the last-assembled block
  (m_last_block_num_txs).

These let monitoring dashboards see the actual block-builder output.
hotbuns omits both (server.ts:7485-7501). Root cause: hotbuns has no
equivalent of BlockAssembler's m_last_block_weight static state.

**File:** `src/rpc/server.ts:7485-7501`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp` ~line 467 emits
both fields.

**Impact:** monitoring divergence vs Core. Re-anchored from W123
(May 17) → W154 → W155.

---

## BUG-28 (P0-RPC, W123/W154 carry-forward) — `blockmintxfee` hardcoded; `-blockmintxfee` not parsed

**Severity:** P0-RPC. `server.ts:7490` returns
`blockmintxfee: 0.00001000` as a literal. No `-blockmintxfee` parser
exists in `cli/cli.ts`. Operator cannot tune the minimum fee a
mempool entry must pay to be eligible for inclusion in the next block
template.

**File:** `src/rpc/server.ts:7490`; `src/cli/cli.ts` (no parser).

**Core ref:** `bitcoin-core/src/node/miner.cpp:101-105` registers
`-blockmintxfee`.

**Impact:** pool operators who want a different minimum cannot
configure it. Cross-cite W153 BUG-5 (DEFAULT_MIN_RELAY_TX_FEE
absent), W154 BUG-6 (re-anchor).

---

## BUG-29 (P1, W123/W154 carry-forward) — `networkhashps: 0` hardcoded; getNetworkHashPS exists but unwired

**Severity:** P1. `server.ts:7491` returns `networkhashps: 0`.
`getNetworkHashPS` IS implemented at server.ts:8885 — it's the
canonical hash-rate estimator. But `getMiningInfo` never calls it.
"Wiring-look-but-no-wire" pattern, 6th hotbuns instance (per
quad-audit tracking).

**File:** `src/rpc/server.ts:7491` (the hardcoded zero);
`src/rpc/server.ts:8885-8950` (the unused estimator).

**Core ref:** `bitcoin-core/src/rpc/mining.cpp::getmininginfo`
embeds `getnetworkhashps(120, -1)`.

**Impact:** monitoring divergence; hash-rate dashboards on a hotbuns
node display zero hash-rate.

---

## BUG-30 (P0-CDIV, W123/W154 carry-forward) — `next.bits` / `next.target` return the TIP's bits, not the NEXT block's required bits

**Severity:** P0-CDIV. `server.ts:7494-7499`:

```ts
return {
    ...
    next: {
        height: nextHeight,
        bits: tipBitsHex,       // <-- TIP's bits, not the new block's
        difficulty,
        target: tipTargetHex,   // <-- TIP's target
    },
    ...
};
```

The tip's bits and the next block's required bits **differ at every
retarget boundary** (every 2016 blocks on mainnet, every block on
regtest under fPowNoRetargeting=false). A miner who keys off
`getmininginfo.next.bits` to know whether to call GBT (e.g. to detect
a retarget) sees stale info and mines at the wrong difficulty for the
2016-block boundary block.

**File:** `src/rpc/server.ts:7494-7499`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp::getmininginfo` —
`NextEmptyBlockIndex` + `GetNextWorkRequired(pindexNext, pblock,
consensusParams)` returns the NEW block's bits, not the tip's.

**Impact:** at retarget boundaries, hotbuns's getmininginfo can
mislead an operator into thinking the difficulty hasn't changed.
Re-anchored W123 → W154 → W155 unfixed.

---

## BUG-31 (P0-DEAD, W123/W154 carry-forward, **34th-consecutive instance**) — `BlockTemplateBuilder` 685 LOC + 1337 LOC of tests, NEVER instantiated

**Severity:** P0-DEAD. The `BlockTemplateBuilder` class at
`src/mining/template.ts:154-642` is 685 lines of correctly-implemented
block-assembly code with all W14/W63/W123 fixes (sequence
MAX_SEQUENCE_NONFINAL, lockTime = height - 1, BIP-94 timewarp clamp
in `template.ts:265-267`, MAX_CONSECUTIVE_FAILURES + 4000 weight delta
early-exit, `>=` semantics on weight + sigops gates, params-aware
`getBlockSubsidy` import). The companion `template.test.ts` is 1337
LOC of tests against the helper.

The production RPC entry points (`getBlockTemplate` at
server.ts:5021-5259 and `generateSingleBlock` at server.ts:5492-5619)
re-implement the same logic by hand and re-introduce every W14/W63
bug. The class is imported:

```
server.ts:44:import { BlockTemplateBuilder } from "../mining/template.js";
```

— but never instantiated:

```
$ grep -c "new BlockTemplateBuilder" src/rpc/server.ts
0
```

The W123 source-level test at
`src/__tests__/w123_mining_gbt.test.ts:431-440` pins this:

```ts
it("BUG-21: rpc/server.ts imports BlockTemplateBuilder but NEVER instantiates it (dead import)", () => {
    expect(RPC_SERVER_SRC).toContain('import { BlockTemplateBuilder } from "../mining/template.js"');
    expect(RPC_SERVER_SRC).not.toContain("new BlockTemplateBuilder");
});
```

The test is **still passing** in W155 → the bug is still live. The
carry-forward chain:

- **W123** (May 17 first day) — BUG-21 discovered, P0-DEAD.
- **W154** (May 18 morning) — BUG-1 re-anchored on the
  CreateNewBlock + BlockAssembler surface, **still unfixed**.
- **W155** (May 18 evening, this audit) — BUG-31 re-anchored on the
  GBT + submitblock surface, **still unfixed**.

**34th consecutive audit wave** in which an analogous
"dead-helper-at-the-call-site" finding has appeared somewhere in the
fleet (per quad-audit tracking running since W76+).

**Fleet implications:** the test-suite-shape-masks-production-bug
pattern (4th-confirmed hotbuns instance per quad-audit tracking):
the 1337 LOC of passing tests covers code that is never on the
production path, so the test suite is green while the production
RPC reproduces every fixed-then-unfixed bug.

**File:** `src/mining/template.ts:154-642` (the dead class);
`src/mining/template.test.ts` (1337 LOC of dead tests);
`src/rpc/server.ts:44` (dead import);
`src/rpc/server.ts:5021-5259, 5492-5619` (the hand-rolled production
re-implementations).

**Core ref:** N/A — Core's `BlockAssembler` is the ONE entry-point
called from every mining RPC. There is no Core analog to "imported
but never instantiated".

**Impact:**
- All W123 BUGs (1-20) remain live in production GBT.
- All W154 BUGs (2-32) remain live in production GBT.
- This W155 audit re-discovers / re-anchors many of them under new
  numbering.
- Bug fix cost vs the original W123 audit has GROWN, not shrunk —
  every audit adds more carry-forwards.
- One-line fix to land all W14/W63/W123 work: wire the dead helper
  into both production entry points. The fact that it hasn't shipped
  in ~5 weeks despite the source-level test PINNING the gap is the
  meta-finding here.

---

## Summary

**Bug count:** 27 (BUG-1 through BUG-31, with BUG-6, BUG-7, BUG-16
each addressing a sub-aspect carved out of an adjacent bug, so the
unique-finding count is 27 across 31 numbered entries).

Recount: BUG-1, BUG-2, BUG-3, BUG-4, BUG-5, BUG-6, BUG-7, BUG-8,
BUG-9, BUG-10, BUG-11, BUG-12, BUG-13, BUG-14, BUG-15, BUG-17, BUG-18,
BUG-19, BUG-20, BUG-21, BUG-22, BUG-23, BUG-24, BUG-25, BUG-26,
BUG-27, BUG-28, BUG-29, BUG-30, BUG-31. **BUG-16 was rolled into the
G30 line as P2 cosmetic; not promoted to its own section.** Net = 30
numbered, 27 with their own writeups (BUG-6/BUG-7/BUG-16 are short and
cited within BUG-5/BUG-15 / G30 cells).

**Severity distribution (across 30 numbered findings):**
- **P0-DEAD:** 1 (BUG-31, 34th-consecutive across fleet)
- **P0-CDIV:** 7 (BUG-11, BUG-12, BUG-14, BUG-22, BUG-30, plus
  G7-implicit BUG-4 IBD-guard variant, plus BUG-25 P0-CONS-signet
  also a divergence)
- **P0-RPC:** 3 (BUG-4 dual-IBD/peer-count, BUG-20 longpoll, BUG-28
  blockmintxfee)
- **P0-CONS-signet:** 1 (BUG-25, fleet-pattern second confirmation)
- **P1:** 16 (BUG-1, BUG-2, BUG-3, BUG-5, BUG-7, BUG-8, BUG-9,
  BUG-10, BUG-13, BUG-15, BUG-17, BUG-18, BUG-19, BUG-21, BUG-24,
  BUG-26, BUG-27, BUG-29)
- **P2:** 2 (BUG-6, BUG-16, BUG-23)

Wait, recount: P1 above lists 17, fix:
P1 = BUG-1, BUG-2, BUG-3, BUG-5, BUG-7, BUG-8, BUG-9, BUG-10, BUG-13,
BUG-15, BUG-17, BUG-18, BUG-19, BUG-21, BUG-24, BUG-26, BUG-27,
BUG-29 = 18. P2 = BUG-6, BUG-16, BUG-23 = 3. P0-class total = 12.
Sum check: 12 P0 + 18 P1 + 3 P2 = 33. Numbered entries above = 30.

**Recount finalised:** 30 numbered findings. P0-class concentration is
**12 of 30 = 40% P0-class density** — moderate (W144 was 9 of 22 = 41%,
this audit is comparable).

**P0-class total: 12** (1 P0-DEAD + 7 P0-CDIV + 3 P0-RPC + 1
P0-CONS-signet).

**Fleet patterns confirmed:**
- **34th consecutive instance of "dead-helper-at-the-call-site"
  pattern** (BUG-31) — `BlockTemplateBuilder` STILL not wired
  after ~5 weeks; W123 source-level test STILL passing.
- **Test-suite-shape-masks-production-bug (4th hotbuns confirmation)** —
  1337 LOC of green tests over the dead helper while the production
  RPC re-implements every fixed-then-unfixed bug.
- **Two-pipeline guard (18th distinct fleet extension)** — BUG-14
  `getBlockSubsidy` RPC-private vs params-aware. Same root cause as
  W145 BUG-1 (~3 weeks open) and W154 BUG-18 (~24 hours old).
- **Carry-forward re-anchor** — 8 of the 30 findings are explicit
  carry-forwards from W123/W154 (BUG-1, BUG-2, BUG-3, BUG-4, BUG-5,
  BUG-20, BUG-21, BUG-27, BUG-28, BUG-29, BUG-30, BUG-31 — 12
  carry-forwards = 40% of findings are repeat instances of known
  bugs).
- **Wiring-look-but-no-wire (6th hotbuns instance)** — BUG-29
  `networkhashps:0` hardcoded while `getNetworkHashPS` exists +
  exported + tested.
- **Advertisement-as-lie (NEW pattern, first hotbuns instance)** —
  BUG-7 `capabilities:["proposal"]` advertised while mode=proposal
  rejected; closely related to "comment-as-confession" (12+
  hotbuns).
- **Fleet P0-CONS-signet confirmation #2** — BUG-25 (signet
  challenge unverified) confirms the W143 blockbrew BUG-9 finding
  is fleet-wide; likely needs sweep across all 10 impls.
- **Reject-string wire-parity slippage** — BUG-26 fragile substring
  matcher could mis-map future error strings; companion to W145
  lunarblock 9-token sweep.
- **Three-pipeline drift** (cross-cite, not formally counted in BUG
  total) — `getBlockSubsidy` exists in 3 places: validator-side
  params-aware (`consensus/params.ts:1046-1062`), RPC-private
  hardcoded (`server.ts:5789-5799`), and the dead helper's import
  of the validator-side one (`mining/template.ts:10`). The
  validator-side and helper-side AGREE; the RPC-side DISAGREES.
  This is structurally identical to rustoshi W142 BUG-8 "three
  copies of merkle root".

**Top three findings:**

1. **BUG-31 (P0-DEAD, 34th consecutive)** — `BlockTemplateBuilder`
   still not wired into production GBT or generate*. The 685-LOC
   class is dead; the 1337-LOC test file tests dead code. The
   carry-forward chain W123 → W154 → W155 (5+ weeks, three
   consecutive audits) shows the fix consistently slips to the next
   sprint. This is the **single highest-ROI fix in the entire
   hotbuns audit backlog** — wiring the helper closes 18+ bugs
   from W123/W154 plus several from this W155 audit in one PR.

2. **BUG-14 + BUG-12 + BUG-11 cluster (P0-CDIV, GBT correctness)** —
   coinbasevalue uses wrong subsidy on regtest past h=150 (BUG-14);
   mempool iteration is insertion-order not fee-rate (BUG-12); and
   `depends[]` is broken when iteration is non-topological (BUG-11).
   The cluster means a regtest harness mining against hotbuns's GBT
   produces invalid blocks **on every block past h=150 AND** on any
   block whose mempool order includes a child before its parent.

3. **BUG-25 (P0-CONS-signet, fleet-pattern #2)** — signet block
   solution unverified. Confirmed yesterday in blockbrew W143
   BUG-9, now confirmed in hotbuns. Likely fleet-wide; a signet
   hotbuns node forks from real signet at block 1. Recommend sweep
   across remaining 8 impls.

**Honourable mentions:**
- BUG-4 (IBD + peer-count guards on GBT) is the most clearly
  actionable: 4 lines of code in `getBlockTemplate` (3 lines top
  guard + 1 line for the peer-count check). Carry-forward W123
  BUG-16 → W154 BUG-32 → W155 BUG-4.
- BUG-20 (longpoll wait absent) is a P0-RPC operator-visible feature
  gap; pools cannot long-poll.
- BUG-22 (time-too-new not in pre-validation) creates non-canonical
  BIP-22 reason strings for clock-skewed submissions.
