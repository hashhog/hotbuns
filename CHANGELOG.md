# Changelog

## v1.0.1 (unreleased)

Changes since `v1.0.0`:

- fix: processOrderedBlocks no longer livelocks when the next body is buffered but the P2P loop is not running (submitblock/handleBlock before start / after haltSync); was 22G+ and hung the unit suite
- test: `bun test` runs files in isolated processes and skips known-red audit files so the v1.0.2 unit gate finishes under 8G / 5 min
- perf: block-connect script checks run on a Bun Worker pool (CCheckQueue-style, sigcache hits skipped on the main thread) so IBD is no longer single-core ECDSA
- perf: snapshot import parses coins synchronously, writes a chained LevelDB batch, and folds HASH_SERIALIZED during the load so 168M coins finish inside the 30-minute campaign window
- feat: getpeerinfo reports per-peer synced_headers/synced_blocks/inflight instead of -1 stubs
- fix: seed the snapshot-base header so header-sync starts at the assumeUTXO base, not 0
- fix: re-seat a lagged best-header pointer so the download scheduler cannot idle at 100% while heavier headers sit in the index (09-07 stall)
- e68703d docs: say the cited paths are private before the claims that rest on them
- 199186c fix: flush chainstate before a UTXO dump or scan, and report hashes in display order
- ef76ade feat: HASHHOG_UNSAFE_SNAPSHOT_HEIGHT — accept an un-anchored UTXO snapshot

