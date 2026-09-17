# hotbuns proof bundle

A skeptical Bitcoin engineer should be able to check this node without
trusting a narrative. This directory is that check: every claim below
names a file in this directory, and `bash proof/verify.sh` re-checks
those files (and re-runs the in-repo controls).

It claims **only what the included files show.**

## How to check

From the hotbuns repository root:

```
bash proof/verify.sh
```

That is the control. It exits 0 only if every claim in `claims.json`
matches a file here, R4 stays UNPROVEN (no C(H) capture, snapshot-booted
ranges refused), the 250k ledger is marked disconfirmed, the production
source tree matches `runnable-tree.sha256`, and the in-repo BIP-66
height-gate test is green.

Re-running the heavy instruments (from-genesis IBD, full R2 corpus, live
R5 probe) needs the commands in `r4/command.txt`, `r1/command.txt`,
`r2/command.txt`, `r5/command.txt`. Those take days / hours / a running
node. The files here are the captured results of those commands.

## What each file proves

### Provenance — `provenance.txt` and `runnable-tree.sha256`

hotbuns is interpreted. `promote_mainnet.sh` refuses this node: there is
no `deploy/hotbuns/MANIFEST`. `start_mainnet.sh` launches
`bun run src/index.ts` from this working directory. The attested artifact
is therefore:

- the production source tree hashed in `runnable-tree.sha256` (every
  `src/**/*.ts` / `src/**/*.js` except tests, plus `package.json`,
  `bun.lock`, `bunfig.toml`, `tsconfig.json`)
- the bun runtime recorded in `provenance.txt` (`bun 1.3.11`,
  sha256 `6d5bb405b1d037a2a466b92757de7e47e4369930fa94bd42f8ff44ba49de6c57`)

`verify.sh` re-hashes the source tree. A one-byte edit of a production
file fails the bundle. **Does not prove** a live PID matches these bytes
today: the mainnet unit has been maintenance-paused since 2026-09-10.

### R4 from-genesis lineage — `r4/` — UNPROVEN

TRUST-ANCHOR rule, applied without weakening: a reproduction of C(H)
counts only if the chainstate at H descends from a genesis→H validation
with scripts on (`assumevalid=0`) executed by this node's own validation
code. **Snapshot-booted lineages do not count.**

This node has no such capture. `r4/status.json` says `UNPROVEN`.

| file | what it proves | what it does not prove |
|---|---|---|
| `r4/status.json` | The claim: R4 is UNPROVEN. `snapshot_booted_does_not_count=true`, `range_counts_as_r4=false`, the 250k ledger is disconfirmed. | A C(H) hash. There isn't one. |
| `r4/no-genesis-unit.txt` | There is no genesis-IBD unit and no `/home/work/genesis-ibd/hotbuns` datadir. A lineage log starting at height 0 cannot be produced from this host today. | That a from-genesis run is impossible in principle. It is a hardware/time blocker. |
| `r4/command.txt` | What a real R4 receipt would take. | That anyone has done it. |
| `r4/av0-250000-ledger.txt` and `r4/av0-250000-ledger.jsonl` | A **contested** AV=0 genesis→250,000 replay: 11 checkpoints, terminal UTXO hash `dd8e8cfd6fe67f59f1dce40e43cd5b36ad3661f574a9d5c8c4a089048bbd649c`, 6,802,755 txouts, `overall=ALL-PASS`. | R4. See `r4/disconfirmation.txt`. |
| `r4/disconfirmation.txt` | On 2026-08-20 an AV=0 rig **rejected real mainnet block 124276** (`SCRIPT_ERR_SIG_DER`) inside that ALL-PASS range. Strict DER is BIP-66 (height 363,725). Fixed in `1e516d5b80f4`. | That the rest of the 250k ledger is now trustworthy. The run was taken with the bug in place. |
| `r4/range-coverage.txt` and `r4/range-rows.json` | Snapshot-booted ladder coverage: 20 CLOSED / 357,409 blocks (36.99%), including 340000→363708 CLOSED on `280c6f02ebe5` (`utxo_hash a742c2a04c54f5e5…`, `scripts_ack yes`). Remaining holes: NO-ORACLE-SURFACE 363708→388364, STALLED 900000→910000. Both files say `counts_as_r4=false`. | From-genesis UTXO-hash identity with Core. These boots start from a Core-format snapshot. |
| `r4/segfault-340890.txt` | The one-shot Bun SIGSEGV at height 340890 (`0x401FFFFFFBE` on `280c6f02ebe5`) is **UNEXPLAINED**. The same range CLOSED on that same commit with zero crashes, so `0f1a48b` cannot be the SIGSEGV fix. | That the fault is gone. A fault that did not recur is not a closed fault. |

### R1 interpreter — `r1/`

Core's script/tx/sighash vectors through hotbuns' own `verifyScript` /
CheckTransaction / legacy SignatureHash.

| file | what it proves | what it does not prove |
|---|---|---|
| `r1/results.json` | script 1222/1222, tx_valid 121/121, tx_invalid 93/93, sighash 500/500, 0 divergences. CHARTER 1,936 vectors, 1,936 decided. | Reason-string parity with Core. |
| `r1/script.txt`, `r1/tx.txt`, `r1/sighash.txt` | The raw harness summaries that `r1/results.json` was taken from. script: in-repo `bun tests/script_vectors.ts` (51 comment rows skipped). tx: phaseb shim `--txvectors`. sighash: `bun tests/sighash_vectors.ts`. | A stranger's re-run of the phaseb tx arm — that needs the meta-repo shim; see `r1/command.txt`. |

### R2 validator — `r2/`

Adversarial corpus, accept/reject vs live `bitcoind`.

| file | what it proves | what it does not prove |
|---|---|---|
| `r2/results.json` | 368 PASS / 2 FAIL / 0 ERR of the nightly 370-entry sweep (99.5%). Both FAILs are reject-vs-reject (`weight-one-over-limit`: Core `bad-blk-weight`, hotbuns `bad-blk-length`). `consensus_splits_accept_vs_reject: 0`. | Error-code / reject-token identity with Core. |
| `r2/nightly-report-excerpt.txt` | The nightly table those numbers were copied from (`hotbuns         368      2`). | A clean classifier: the 10-impl report has an accounting gap on split counts; the two hotbuns FAIL logs were read directly. |
| `r2/tws-fail-excerpt.txt` | The two FAIL log lines, both reject-vs-reject. | A live re-sweep. That is `r2/command.txt`. |

### R5 operator RPC — `r5/`

| file | what it proves | what it does not prove |
|---|---|---|
| `r5/live-20260901T182642Z.json` | Live lane 2026-09-01T18:26Z: T1 41/46, T2 15/41. Four T1 FAILs (`addnode`, `getblocktemplate`, `sendrawtransaction`, `testmempoolaccept`). T3 is SKIP-REGTEST on this lane. | The pin running that probe is this commit. It is not. The mainnet unit has been paused since 2026-09-10; later probes are connection-refused. |
| `r5/scorecard.json` | The numbers above in one place, each pointing at the artifact. T3 marked UNPROVEN (no regtest-lane artifact in this bundle). | Anything not in those artifacts. A live `r5_probe.py` going green. That needs the unit started, which this run does not do. |

## What is NOT proven here

- **R4 from-genesis C(H).** UNPROVEN. Named blocker: no genesis→H
  `hash_serialized_3` capture; the 250k ledger is disconfirmed; R4 is
  not reachable on this hardware at IBD speed. Snapshot-booted
  range-runner CLOSED rows are not a substitute.
- **Tip parity is not consensus evidence.** Even when the live node
  matches Core's tip it proves serialization, PoW, headers-first sync
  and UTXO bookkeeping on the assumevalid-skipped prefix. R1/R2/R4
  are the consensus proof, and R4 is missing.
- **Blocks after 250,000** have no from-genesis UTXO-hash capture, and
  the 250k capture itself does not count.
- **T3 wallet.** UNPROVEN. Live lane SKIP-REGTEST; no regtest artifact
  in this bundle.
- **That a live PID is running these bytes.** The unit is paused.
- **Fund custody.** Do not send money to this node. See `SECURITY.md`.

## TRUST-ANCHOR, applied

A snapshot-booted range (`range-runner.sh` CLOSED rows in
`r4/range-rows.json`) is **not** R4 evidence. Those boots start from a
Core-format UTXO snapshot; counting them as from-genesis would be
circular. This bundle includes them so the coverage holes are visible
and so `verify.sh` can fail if anyone later flips `range_counts_as_r4`
to true without a lineage log.
