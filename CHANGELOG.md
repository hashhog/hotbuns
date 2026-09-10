# Changelog

## v1.0.1 (unreleased)

Changes since `v1.0.0`:

- fix: re-seat a lagged best-header pointer so the download scheduler cannot idle at 100% while heavier headers sit in the index (09-07 stall)
- e68703d docs: say the cited paths are private before the claims that rest on them
- 199186c fix: flush chainstate before a UTXO dump or scan, and report hashes in display order
- ef76ade feat: HASHHOG_UNSAFE_SNAPSHOT_HEIGHT — accept an un-anchored UTXO snapshot

