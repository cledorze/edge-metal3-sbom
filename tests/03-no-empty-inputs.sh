#!/usr/bin/env bash
# Test 3: every per-layer SBOM has at least one package (runbook, section 8 checklist).
# An empty input is a scan that failed silently (a binary that is not an image, a registry pull that returned nothing).
# Usage: tests/03-no-empty-inputs.sh [WORK]
set -euo pipefail
WORK="${1:-${WORK:-$PWD}}"
cd "$WORK"

n=0
empty=0
for f in */sbom-os.spdx.json */images/*.spdx.json; do
  [ -e "$f" ] || continue
  n=$((n + 1))
  if [ "$(jq '.packages | length' "$f")" -gt 0 ]; then
    continue
  fi
  echo "EMPTY $f"
  empty=$((empty + 1))
done

echo "inputs checked: $n, empty: $empty"
if [ "$n" -eq 0 ]; then
  echo "FAIL: no per-layer SBOM found under $WORK (expected */sbom-os.spdx.json and */images/*.spdx.json)"
  exit 2
fi
if [ "$empty" -eq 0 ]; then
  echo "PASS: no empty input"
else
  echo "FAIL: $empty empty input(s)"
  exit 1
fi
