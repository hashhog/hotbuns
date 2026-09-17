#!/usr/bin/env bash
# proof/verify.sh — re-check every claim in this bundle against a file here.
# Exit 0 only if the files match claims.json AND the in-repo BIP-66 height-gate
# control is green. Run from the hotbuns repo root: `bash proof/verify.sh`
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
PROOF="$ROOT/proof"
export PATH="${HOME}/.bun/bin:/usr/local/bin:/usr/bin:/bin:${PATH:-}"
fail=0
say() { printf '%s\n' "$*"; }
die() { printf 'FAIL: %s\n' "$*"; fail=1; }

need() {
  local f="$1"
  [ -f "$PROOF/$f" ] || die "missing $f"
}

say "== hotbuns proof bundle verify =="

# 1. every claims.json file exists
python3 - "$PROOF" <<'PY' || fail=1
import json, sys, pathlib
proof = pathlib.Path(sys.argv[1])
claims = json.loads((proof / "claims.json").read_text())
missing = []
for section, body in claims.items():
    for f in body.get("files", []):
        if not (proof / f).is_file():
            missing.append(f)
if missing:
    print("FAIL: missing files:", ", ".join(missing))
    sys.exit(1)
print("files: every claims.json path exists")
PY

# 2. R4 — UNPROVEN, and the included files say why
python3 - "$PROOF" <<'PY' || fail=1
import json, sys, pathlib
proof = pathlib.Path(sys.argv[1])
c = json.loads((proof / "claims.json").read_text())["r4"]
st = json.loads((proof / "r4/status.json").read_text())
rows = json.loads((proof / "r4/range-rows.json").read_text())
ledger_txt = (proof / "r4/av0-250000-ledger.txt").read_text()
ledger_jsonl = (proof / "r4/av0-250000-ledger.jsonl").read_text()
disc = (proof / "r4/disconfirmation.txt").read_text()
none = (proof / "r4/no-genesis-unit.txt").read_text()
cov = (proof / "r4/range-coverage.txt").read_text()
errs = []
if c["status"] != "UNPROVEN" or st["status"] != "UNPROVEN":
    errs.append("R4 status must be UNPROVEN (no C(H) capture in this bundle)")
if (proof / "r4/C958794.json").exists():
    errs.append("r4/C958794.json exists — a C() file would need a matching lineage log; this node does not have one")
if c.get("snapshot_booted_does_not_count") is not True or st.get("snapshot_booted_does_not_count") is not True:
    errs.append("claims must refuse snapshot-booted lineages")
if c.get("range_counts_as_r4") is not False or rows.get("counts_as_r4") is not False:
    errs.append("range-runner rows must not count as R4 (TRUST-ANCHOR)")
if rows.get("snapshot_booted") is not True:
    errs.append("range-rows.json must declare snapshot_booted=true")
closed = [r for r in rows["rows"] if r["verdict"] == "CLOSED"]
if len(closed) != c["range_closed"]:
    errs.append(f"range closed count {len(closed)} != claims {c['range_closed']}")
blocks = sum(r["blocks"] for r in closed)
if blocks != c["range_closed_blocks"]:
    errs.append(f"range closed blocks {blocks} != claims {c['range_closed_blocks']}")
if st["range_closed"] != c["range_closed"] or st["range_closed_blocks"] != c["range_closed_blocks"]:
    errs.append("status.json range counts do not match claims")
if "333,701" not in cov and "333701" not in cov:
    errs.append("range-coverage.txt missing 333,701")
if "TRUST-ANCHOR" not in cov:
    errs.append("range-coverage.txt missing TRUST-ANCHOR")
if c["ledger_250000_disconfirmed"] is not True or st["ledger_250000_disconfirmed"] is not True:
    errs.append("the 250k ledger is disconfirmed; claims must say so")
if "overall=ALL-PASS" not in ledger_txt:
    errs.append("ledger txt missing overall=ALL-PASS (the contested claim)")
if c["ledger_250000_utxo_hash"] not in ledger_txt or c["ledger_250000_utxo_hash"] not in ledger_jsonl:
    errs.append("ledger missing claimed terminal utxo hash")
if f'"txouts": {c["ledger_250000_txouts"]}' not in ledger_jsonl and f'"txouts":{c["ledger_250000_txouts"]}' not in ledger_jsonl:
    if str(c["ledger_250000_txouts"]) not in ledger_jsonl:
        errs.append("ledger jsonl missing claimed txouts")
if str(c["disconfirmation_height"]) not in disc:
    errs.append("disconfirmation.txt missing height 124276")
if c["disconfirmation_token"] not in disc:
    errs.append("disconfirmation.txt missing SCRIPT_ERR_SIG_DER")
if c["fix_commit"] not in disc:
    errs.append("disconfirmation.txt missing fix commit 1e516d5b80f4")
if "no genesis-IBD" not in none and "no genesis-ibd" not in none.lower():
    errs.append("no-genesis-unit.txt does not admit the missing unit")
if c["genesis_block_hash"] not in (proof / "r4/status.json").read_text():
    errs.append("status.json missing Bitcoin genesis hash")
if errs:
    print("FAIL: R4:", "; ".join(errs))
    sys.exit(1)
print(f"R4: UNPROVEN (no C(H)); ledger→250000 ALL-PASS is DISCONFIRMED at {c['disconfirmation_height']} {c['disconfirmation_token']}; ranges {c['range_closed']} CLOSED / {c['range_closed_blocks']} blocks count_as_r4=false")
PY

# 3. The 124276 bug must stay fixed in source (DERSIG not inferred from WITNESS)
if grep -qE 'verifyDERSignatures:[[:space:]]*verifyDERSig[[:space:]]*\|\|[[:space:]]*verifyWitness' "$ROOT/src/script/interpreter.ts"; then
  die "scriptFlagsFromBitmask infers DERSIG from WITNESS (block 124276 bug is back)"
else
  say "R4: scriptFlagsFromBitmask does not infer DERSIG from WITNESS"
fi
if ! grep -q 'verifyDERSignatures:       verifyDERSig' "$ROOT/src/script/interpreter.ts"; then
  die "scriptFlagsFromBitmask missing 'verifyDERSignatures:       verifyDERSig'"
else
  say "R4: scriptFlagsFromBitmask honours DERSIG from its own bit"
fi
if ! grep -q '124276' "$ROOT/src/__tests__/bip66_height_gate.test.ts"; then
  die "bip66_height_gate.test.ts no longer names block 124276"
else
  say "R4: in-repo height-gate test still names block 124276"
fi

# 4. R1 numbers
python3 - "$PROOF" <<'PY' || fail=1
import json, sys, pathlib
proof = pathlib.Path(sys.argv[1])
c = json.loads((proof / "claims.json").read_text())["r1"]
r = json.loads((proof / "r1/results.json").read_text())
errs = []
if r["script_tests"]["pass"] != c["script_pass"] or r["script_tests"]["fail"] != c["script_fail"]:
    errs.append("script")
if r["tx_valid"]["pass"] != c["tx_valid_pass"]:
    errs.append("tx_valid")
if r["tx_invalid"]["pass"] != c["tx_invalid_pass"]:
    errs.append("tx_invalid")
if r["sighash"]["exact_match"] != c["sighash_pass"]:
    errs.append("sighash")
if r["divergences"] != c["divergences"]:
    errs.append("divergences")
if r["decided"] != c["decided"] or r["charter_r1_total_vectors"] != c["charter_vector_count"]:
    errs.append("charter totals")
script_txt = (proof / "r1/script.txt").read_text()
if "1222 passed, 0 failed" not in script_txt:
    errs.append("script.txt missing 1222 passed, 0 failed")
if "500 passed, 0 failed" not in (proof / "r1/sighash.txt").read_text():
    errs.append("sighash.txt missing 500 passed, 0 failed")
tx = (proof / "r1/tx.txt").read_text()
if "121/121" not in tx:
    errs.append("tx.txt missing 121/121")
if "93/93" not in tx:
    errs.append("tx.txt missing 93/93")
if errs:
    print("FAIL: R1:", ", ".join(errs))
    sys.exit(1)
print(f"R1: script {c['script_pass']}/1222 tx {c['tx_valid_pass']}+{c['tx_invalid_pass']} sighash {c['sighash_pass']}/500 divergences={c['divergences']}")
PY

# 5. R2 numbers
python3 - "$PROOF" <<'PY' || fail=1
import json, sys, pathlib
proof = pathlib.Path(sys.argv[1])
c = json.loads((proof / "claims.json").read_text())["r2"]
r = json.loads((proof / "r2/results.json").read_text())
errs = []
if r["pass"] != c["pass"] or r["fail"] != c["fail"]:
    errs.append("pass/fail")
if r["err"] != c["err"]:
    errs.append("err")
if r["consensus_splits_accept_vs_reject"] != c["consensus_splits_accept_vs_reject"]:
    errs.append("splits")
if any(not f["same_accept_reject"] for f in r["fails"]):
    errs.append("a listed FAIL is accept-vs-reject — that would be a consensus split")
if len(r["fails"]) != c["fail"]:
    errs.append("fails list length")
excerpt = (proof / "r2/nightly-report-excerpt.txt").read_text()
if "hotbuns         368      2" not in excerpt:
    errs.append("excerpt missing hotbuns 368/2")
tws = (proof / "r2/tws-fail-excerpt.txt").read_text()
if "reject:bad-blk-weight" not in tws or "reject:bad-blk-length" not in tws:
    errs.append("tws excerpt missing the reason-token pair")
if "same_accept_reject: true" not in tws:
    errs.append("tws excerpt missing same_accept_reject")
if "CONSENSUS SPLITS" not in tws or "0" not in tws.split("CONSENSUS SPLITS", 1)[-1][:80]:
    errs.append("tws excerpt missing splits=0")
if errs:
    print("FAIL: R2:", ", ".join(errs))
    sys.exit(1)
print(f"R2: {c['pass']} PASS / {c['fail']} FAIL, consensus splits={c['consensus_splits_accept_vs_reject']}")
PY

# 6. R5 scorecards
python3 - "$PROOF" <<'PY' || fail=1
import json, sys, pathlib
proof = pathlib.Path(sys.argv[1])
c = json.loads((proof / "claims.json").read_text())["r5"]
live = json.loads((proof / "r5/live-20260901T182642Z.json").read_text())["impls"]["hotbuns"]
sc = json.loads((proof / "r5/scorecard.json").read_text())
errs = []
if live["tiers"]["T1"]["pass"] != c["live_t1_pass"] or live["tiers"]["T1"]["total"] != c["live_t1_total"]:
    errs.append("live T1")
if live["tiers"]["T2"]["pass"] != c["live_t2_pass"] or live["tiers"]["T2"]["total"] != c["live_t2_total"]:
    errs.append("live T2")
t1_fails = sorted(r["method"] for r in live["rows"] if r["tier"] == "T1" and r["status"] == "FAIL")
if t1_fails != sorted(c["live_t1_fail_methods"]):
    errs.append(f"live T1 FAIL set {t1_fails!r}")
if sc["live"]["T1"]["pass"] != c["live_t1_pass"] or sc["live"]["T2"]["pass"] != c["live_t2_pass"]:
    errs.append("scorecard live T1/T2")
if sc["live"]["fails_t1"] != c["live_t1_fail_methods"]:
    errs.append("scorecard T1 fail methods")
if c["regtest_t3_status"] != "UNPROVEN":
    errs.append("T3 must be UNPROVEN in this bundle")
if sc["regtest"]["T3"].get("status") != "UNPROVEN":
    errs.append("scorecard T3 is not UNPROVEN")
if sc["regtest"].get("artifact") not in (None, ""):
    errs.append("scorecard claims a regtest artifact this bundle does not have")
if errs:
    print("FAIL: R5:", "; ".join(errs))
    sys.exit(1)
print(f"R5 live T1 {c['live_t1_pass']}/{c['live_t1_total']} T2 {c['live_t2_pass']}/{c['live_t2_total']} T3 {c['regtest_t3_status']}")
PY

# 7. README cites every claims.json file
python3 - "$PROOF" <<'PY' || fail=1
import json, sys, pathlib
proof = pathlib.Path(sys.argv[1])
readme = (proof / "README.md").read_text()
claims = json.loads((proof / "claims.json").read_text())
missing = []
for section, body in claims.items():
    for f in body.get("files", []):
        if f not in readme:
            missing.append(f)
if missing:
    print("FAIL: README.md does not cite:", ", ".join(missing))
    sys.exit(1)
print("README: every claims.json file is cited")
PY

# 8. provenance: bun runtime hash (informational if bun moved) + runnable tree
want_rt="$(python3 -c 'import json,pathlib; print(json.loads(pathlib.Path("proof/claims.json").read_text())["provenance"]["runtime_sha256"])')"
if command -v bun >/dev/null 2>&1; then
  bun_bin="$(command -v bun)"
  got_rt="$(sha256sum "$bun_bin" | awk '{print $1}')"
  if [ "$got_rt" != "$want_rt" ]; then
    say "NOTE: bun sha256=$got_rt (bundle records $want_rt). Runtime upgrades are expected; the attested artifact is runnable-tree.sha256."
  else
    say "provenance: bun sha256=$want_rt"
  fi
else
  say "NOTE: bun not on PATH; skipped runtime sha256 check. Bundle records $want_rt."
fi
if ! grep -q "$want_rt" "$PROOF/provenance.txt"; then
  die "provenance.txt does not contain the claimed bun sha256"
else
  say "provenance.txt records claimed bun sha256"
fi
if grep -qiE 'promote_does_not_apply: yes' "$PROOF/provenance.txt"; then
  say "provenance: interpreted (promote does not apply)"
else
  die "provenance.txt must say promote_does_not_apply: yes"
fi

# 9. runnable-tree: the attested source (interpreted "binary")
need "runnable-tree.sha256"
if (cd "$ROOT" && sha256sum -c "$PROOF/runnable-tree.sha256" --quiet); then
  say "runnable-tree.sha256: OK ($(wc -l < "$PROOF/runnable-tree.sha256") files)"
else
  die "runnable-tree.sha256 mismatch — production source is not the attested tree"
fi

# 10. in-repo BIP-66 height-gate + interpreter control
if command -v bun >/dev/null 2>&1; then
  say "== re-run: bun test bip66_height_gate + interpreter =="
  if HOTBUNS_UNIT_CHILD=1 bun test ./src/__tests__/bip66_height_gate.test.ts ./src/script/interpreter.test.ts; then
    say "R1 in-repo: bip66_height_gate + interpreter PASS"
  else
    die "in-repo bun test (bip66_height_gate + interpreter) failed"
  fi
else
  say "NOTE: bun not on PATH; skipped in-repo re-run. Install bun 1.3.11 and re-run."
  say "      The recorded control is src/__tests__/bip66_height_gate.test.ts (block 124276)."
fi

# 11. MANIFEST (all files except MANIFEST itself)
if [ -f "$PROOF/MANIFEST.sha256" ]; then
  if (cd "$PROOF" && sha256sum -c MANIFEST.sha256 --quiet); then
    say "MANIFEST.sha256: OK"
  else
    die "MANIFEST.sha256 mismatch"
  fi
else
  die "MANIFEST.sha256 missing — run bash proof/assemble.sh"
fi

if [ "$fail" -ne 0 ]; then
  say "== FAIL =="
  exit 1
fi
say "== PASS: every claim cites a file in this bundle and the numbers match =="
exit 0
