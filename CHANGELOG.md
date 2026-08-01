# Changelog

All notable changes to hotbuns are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-07-31

First stable release of hotbuns, a Bitcoin full node implementation in
TypeScript running on [Bun](https://bun.sh).

### Highlights

- Full block and transaction validation (SegWit, Taproot, BIP68 sequence
  locks, sigop counting with witness discount)
- Script interpreter (P2PKH, P2SH, P2WPKH, P2WSH, P2TR, P2A anchors,
  NULLFAIL, WITNESS_PUBKEYTYPE, MINIMALIF, FindAndDelete, OP_CODESEPARATOR)
- Header-first sync with anti-DoS (PRESYNC/REDOWNLOAD strategy, PoW
  verification, checkpoint enforcement) and parallel block download with
  stall detection
- UTXO set with layered CoinsView cache (dirty/fresh flags, batch flush,
  undo data)
- Cluster mempool (union-find clustering, linearization, mining scores,
  cluster-based eviction, full RBF, package relay, CPFP, v3/TRUC policy,
  ephemeral anchors)
- BIP-324 v2 encrypted transport, BIP-152 compact blocks, BIP-330 Erlay,
  BIP-133 feefilter, BIP-155 ADDRv2
- HD wallet (BIP-32/44/49/84/86, BnB+Knapsack coin selection, encrypted
  storage), multi-wallet RPCs, PSBT (BIP-174/370), output descriptors
  (BIP380-386), Miniscript
- assumeUTXO (snapshot serialization, dual chainstate, background
  validation), block pruning, txindex / BIP-157-158 blockfilterindex /
  coinstatsindex
- Fee estimation, block template construction (getblocktemplate), ZMQ
  notifications, REST API, Tor/I2P proxy, regtest mode, chain-management
  RPCs (invalidateblock / reconsiderblock / preciousblock)

### Fixed

- IBD connect-failure circuit breaker: a deterministic block-validation
  failure at a fixed height (e.g. "Missing UTXO") was discarded and
  re-requested forever (275k+ identical retries observed at one height).
  Sync now hard-halts with a classified `[SYNC-HALTED]` error after
  `MAX_CONSECUTIVE_CONNECT_FAILURES` (10) consecutive failures at one
  height; RPC stays up for triage (`src/sync/blocks.ts`).
- Consensus: honour `SCRIPT_VERIFY_TAPROOT` in the P2TR fast path
  (12c6a7b).
- Consensus: unconditional P2SH|WITNESS|TAPROOT script-flag combination +
  Core's replace-then-OR flag derivation (c4a7fb7).
- Policy: Core v31 cluster mempool limits — weight units, >404000
  cluster-weight, >64 cluster-size (bce6893).
- Policy: feefilter tracks Core v31 relay-fee defaults (bc155ff).
- P2P: O(1) `AlreadyHaveTx` — killed the O(mempool) rescan on every tx
  inv (4cbe342).
- Storage: size the LevelDB table cache to the actual table count; pin
  maxFileSize/maxOpenFiles to Core's matched pair (037a687, 50aba0d).
- Crypto: validate hybrid pubkeys (0x06/0x07) — stop false-accepts
  (32be80d).
- Crypto: libsecp256k1 FFI loader probes a SONAME list
  (.so.2/.so.6/.so.5/.so.1/.so.0/.so) instead of hardcoding
  `libsecp256k1.so.2`, which left the FFI unavailable (silently falling
  back to @noble) on systems shipping a different SONAME.
- Mempool: admit taproot spends — BIP-341 all-prevouts context for ATMP
  script checks (e2a70b5); bound mempool by real heap usage (76975fa).
- Wallet: honor `getnewaddress` address_type + taproot key-path signing
  (687f1a1); `walletcreatefundedpsbt` manual-input support + full-vsize
  fee (1e84984).
- RPC: Core-exact reject tokens (0a30333); stop taproot-throw
  unhandled-rejection flood (f76cfae).
- Wire: `readBytes` returns a copy, not a subarray view (OOM leak root
  cause, 146f315).

### Tests / CI / hygiene

- Fixed all TypeScript typecheck errors in the test suite (API drift:
  `BlockHeader.prevBlock`, `DescriptorType`, `ScriptFlags`,
  `test.todo` signature).
- Refreshed stale BIP-34 coinbase fixtures to canonical `CScript() <<
  nHeight` encoding; adjudicated txindex disconnect tests to Core parity
  (TxIndex has no `CustomRemove` override — entries for orphaned blocks
  are kept, bitcoin-core/src/index/base.h:136).
- Updated stale policy expectations to Core v31 defaults (100 sat/kvB
  min-relay / incremental-relay fee), Core wallet coinbase maturity
  (depth >= 101, GetTxBlocksToMaturity), witness-v0 MINIMALIF
  flag-gating, `block-script-verify-flag-failed` BIP-22 strings, and
  `WriteHDKeypath` 'h' suffix.
- Converted 63 forward-looking AddrMan gate tests (tests/w104) to
  `test.failing` xfails that keep their G## gap IDs; converted
  audit-artifact status-summary tests to skips; rewrote fixed-bug
  sentinels (P2TR PSBT signing, walletcreatefundedpsbt manual inputs,
  per-coin MTP, BIP-68 assumevalid fast path) as regression tests.
- Fixed a wallet test-isolation race: debounced wallet flush firing into
  the next test's datadir wipe is now drained via `flushAll()` in
  teardown. Randomised RPC test port bases (EADDRINUSE collisions between
  parallel test files) and made the addrman persist round-trip test
  deterministic (promote the first-inserted address; a later one can lose
  its bucket draw under a random nKey).
- Re-enabled the GitHub Actions CI workflow (`ci.yml`), including the
  typecheck job.
- Removed the committed 1.7 MB `src/index.js` build artifact and
  gitignored it.
- Bumped version to 1.0.0 (package.json, CLI banner, P2P user agent
  `/hotbuns:1.0.0/`).
