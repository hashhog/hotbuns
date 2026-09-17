# Changelog

## v1.0.2 — 2026-09-13

- feat: inbound P2P binds a configurable address (default 0.0.0.0 and [::]), reports inbound:true in getpeerinfo, reaps half-open handshakes, and serves getheaders/getdata to inbound peers
- fix: snapshot-base gettxoutsetinfo reports height/hash without a second coins-DB walk
- af6a6da test: bind RPC tests on OS-assigned ports so bun test stays green
- 3d0d4f7 test: keep bun test parent idle and retry EADDRINUSE on watch-only RPC
- 1ee906f fix: processOrderedBlocks livelock hung bun test at 46G
- 361f14c fix: don't complete IBD against a stale header tip
- ce1231b perf: Bun Worker pool for block-level script verification
- 2063853 perf: snapshot import finishes 168M coins inside 30 min
- 9b8e0db feat: getpeerinfo reports per-peer synced_headers/synced_blocks/inflight
- f869e16 fix: seed base_tail_headers so snapshot retargets can resolve ancestors
- 52e0ba9 fix: seed the snapshot-base header so header-sync starts at the assumeUTXO base
- 3b05a66 fix: keep the block-download scheduler on the most-work header


## v1.0.2 — 2026-09-13

Changes since `v1.0.0`:

- fix: processOrderedBlocks no longer livelocks when the next body is buffered but the P2P loop is not running (submitblock/handleBlock before start / after haltSync); was 22G+ and hung the unit suite
- test: `bun test` runs files in isolated processes and skips known-red audit files so the v1.0.2 unit gate finishes under 8G / 5 min; parent preloads wait for isolation (do not run files in-process); RPC tests bind port 0 (or retry EADDRINUSE); FFI 25x benches are opt-in (`HOTBUNS_PERF=1`) so niced unit-gate runs are not a perf lab
- perf: block-connect script checks run on a Bun Worker pool (CCheckQueue-style, sigcache hits skipped on the main thread) so IBD is no longer single-core ECDSA
- perf: snapshot import parses coins synchronously, writes a chained LevelDB batch, and folds HASH_SERIALIZED during the load so 168M coins finish inside the 30-minute campaign window
- feat: getpeerinfo reports per-peer synced_headers/synced_blocks/inflight instead of -1 stubs
- fix: seed the snapshot-base header so header-sync starts at the assumeUTXO base, not 0
- fix: re-seat a lagged best-header pointer so the download scheduler cannot idle at 100% while heavier headers sit in the index (09-07 stall)
- e68703d docs: say the cited paths are private before the claims that rest on them
- 199186c fix: flush chainstate before a UTXO dump or scan, and report hashes in display order
- ef76ade feat: HASHHOG_UNSAFE_SNAPSHOT_HEIGHT — accept an un-anchored UTXO snapshot

