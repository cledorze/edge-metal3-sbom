#!/usr/bin/env bash
# Test 2: NTIA minimum elements of the global SBOM (runbook, section 7).
# ntia-checker is an offline check of the 2021 NTIA minimum elements; it is not a test of any consumer tool.
# Usage: tests/02-ntia-conformance.sh [WORK]
# Env:   SBOMVAL = bin directory of the validation venv (default: $HOME/sbomval/bin)
set -euo pipefail
WORK="${1:-${WORK:-$PWD}}"
SBOMVAL="${SBOMVAL:-$HOME/sbomval/bin}"
F="$WORK/sbom-global.spdx.json"

if [ ! -s "$F" ]; then
  echo "FAIL: $F missing or empty"
  exit 2
fi

OUT=$(mktemp)
rc=0
"$SBOMVAL/ntia-checker" "$F" > "$OUT" 2>&1 || rc=$?
cat "$OUT"
echo "ntia rc=$rc"

if [ "$rc" -eq 0 ] && grep -q '^Conformant: True' "$OUT"; then
  echo "PASS: NTIA minimum elements, Conformant: True"
  rm -f "$OUT"
else
  echo "FAIL: ntia-checker rc=$rc or Conformant line not True"
  rm -f "$OUT"
  exit 1
fi
