#!/usr/bin/env bash
# Runs tests 1 to 5 on the output directory of the runbook, then test 6 on the sample SBOM.
# Usage: tests/run-all.sh [WORK]
# Env:   SBOMVAL = bin directory of the validation venv (default: $HOME/sbomval/bin)
# Tests 1 and 2 take long on a whole-stack document (47 min and 14 min on a 107 MB file, 2026-10-12).
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
WORK="${1:-${WORK:-$PWD}}"
export SBOMVAL="${SBOMVAL:-$HOME/sbomval/bin}"

results=()
for t in 03-no-empty-inputs 04-roots-equal-inputs 05-no-host-paths 01-spdx-validate 02-ntia-conformance; do
  echo "=== $t ($(date +%T))"
  if bash "$HERE/$t.sh" "$WORK"; then results+=("PASS $t"); else results+=("FAIL $t"); fi
done
echo "=== 06-validators-negative-control ($(date +%T))"
if bash "$HERE/06-validators-negative-control.sh"; then results+=("PASS 06-validators-negative-control"); else results+=("FAIL 06-validators-negative-control"); fi

echo
echo "=== summary ($(date +%T))"
printf '%s\n' "${results[@]}"
printf '%s\n' "${results[@]}" | grep -q '^FAIL' && exit 1
exit 0
