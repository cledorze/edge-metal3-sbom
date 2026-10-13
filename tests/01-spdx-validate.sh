#!/usr/bin/env bash
# Test 1: SPDX validity of the global SBOM (runbook, section 7).
# pyspdxtools prints nothing and returns 0 when the document is valid; errors are listed otherwise.
# Usage: bash tests/01-spdx-validate.sh [WORK]   (WORK = output directory of the runbook, default: $PWD)
# Env:   SBOMVAL = bin directory of the validation venv (default: $HOME/sbomval/bin)
set -euo pipefail
WORK="${1:-${WORK:-$PWD}}"
SBOMVAL="${SBOMVAL:-$HOME/sbomval/bin}"
F="$WORK/sbom-global.spdx.json"

if [ ! -s "$F" ]; then
  echo "FAIL: $F missing or empty"
  exit 2
fi

start=$(date +%s)
rc=0
"$SBOMVAL/pyspdxtools" -i "$F" || rc=$?
echo "pyspdxtools rc=$rc ($(( $(date +%s) - start )) s, $(stat -c %s "$F" 2>/dev/null || stat -f %z "$F") bytes)"

if [ "$rc" -eq 0 ]; then
  echo "PASS: $F is a valid SPDX document"
else
  echo "FAIL: pyspdxtools rc=$rc"
  exit 1
fi
