#!/usr/bin/env bash
# proof/assemble.sh — refresh provenance + runnable-tree + MANIFEST.
# Frozen evidence (R1/R2/R4/R5 artifacts) is already in proof/ and is not
# regenerated from outside this repository.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
PROOF="$ROOT/proof"

list_runnable() {
  {
    find src -type f \( -name '*.ts' -o -name '*.js' \) \
      ! -name '*.test.ts' \
      ! -path 'src/__tests__/*' \
      ! -path 'src/test/*'
    printf '%s\n' package.json bun.lock bunfig.toml tsconfig.json
  } | LC_ALL=C sort -u
}

# Hash the production source this node would run. This is the interpreted
# analogue of nimrod's bin/nimrod sha256: there is no promote/deploy pin.
list_runnable | xargs -d '\n' sha256sum > "$PROOF/runnable-tree.sha256"

BUN_BIN="$(command -v bun 2>/dev/null || true)"
if [ -z "$BUN_BIN" ] && [ -x "$HOME/.bun/bin/bun" ]; then
  BUN_BIN="$HOME/.bun/bin/bun"
fi

{
  echo "# Provenance — hotbuns proof bundle"
  echo "assembled_utc: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "repo: https://github.com/hashhog/hotbuns"
  echo "branch: $(git rev-parse --abbrev-ref HEAD)"
  echo "commit: $(git rev-parse HEAD)"
  echo "commit_short: $(git rev-parse --short=12 HEAD)"
  echo "subject: $(git log -1 --format=%s | cut -c1-120)"
  echo "tree_clean: $([ -z "$(git status --porcelain)" ] && echo yes || echo NO)"
  echo "interpreted: yes"
  echo "promote_does_not_apply: yes (start_mainnet.sh runs bun run src/index.ts from this tree)"
  echo "launch: bun run src/index.ts"
  echo "runnable_tree: proof/runnable-tree.sha256"
  echo "runnable_files: $(wc -l < "$PROOF/runnable-tree.sha256")"
  if [ -n "$BUN_BIN" ] && [ -x "$BUN_BIN" ]; then
    echo "runtime: $BUN_BIN"
    echo "runtime_version: $("$BUN_BIN" --version 2>/dev/null | head -1)"
    echo "runtime_sha256: $(sha256sum "$BUN_BIN" | awk '{print $1}')"
  else
    echo "runtime: bun (not on PATH)"
    echo "runtime_sha256: (install bun 1.3.11 to check the recorded sha256)"
  fi
  echo "target: Linux amd64"
  echo "unit: hashhog-hotbuns-mainnet (maintenance-paused since 2026-09-10; no live PID)"
  echo
  echo "# Honest caveats"
  echo "hotbuns is interpreted. There is no deploy/hotbuns/MANIFEST: promote_mainnet.sh"
  echo "refuses this node. The attested artifact is the production source tree hashed"
  echo "in runnable-tree.sha256 plus the bun runtime. start_mainnet.sh launches"
  echo "'bun run src/index.ts' from this working directory; that is what would run."
  echo "The mainnet unit is maintenance-paused, so this bundle does not claim a live"
  echo "PID matches these bytes today."
  echo "This script refreshes provenance + runnable-tree + MANIFEST only. Frozen"
  echo "evidence in r1/ r2/ r4/ r5/ is not regenerated from outside this repository."
} > "$PROOF/provenance.txt"

# Hash every file except MANIFEST itself, stable order.
( cd "$PROOF" && find . -type f ! -name MANIFEST.sha256 | sed 's|^\./||' | LC_ALL=C sort \
    | xargs -d '\n' sha256sum > MANIFEST.sha256 )

echo "assemble: $PROOF"
echo "  files: $(find "$PROOF" -type f | wc -l)"
echo "  manifest: $(wc -l < "$PROOF/MANIFEST.sha256") hashes"
echo "  runnable: $(wc -l < "$PROOF/runnable-tree.sha256") source files"
