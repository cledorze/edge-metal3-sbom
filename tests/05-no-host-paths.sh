#!/usr/bin/env bash
# Test 5: the global SBOM carries no host name or path of the build host (runbook, section 8).
# Two checks, as on the page: the text of the document, and the names of the roots. An OS layer scanned
# without --source-name is named after its mount point, and its SPDX identifier repeats the path in every
# relationship of that layer (observed on the 2026-10-09 document: 1 and 1; on the replayed one: 0 and 0).
# Usage: tests/05-no-host-paths.sh [WORK]
set -euo pipefail
WORK="${1:-${WORK:-$PWD}}"
cd "$WORK"

G=sbom-global.spdx.json
if [ ! -s "$G" ]; then
  echo "FAIL: $G missing or empty"
  exit 2
fi

# grep -c exits 1 when the count is 0: capture the count, ignore the exit code.
text=$(grep -c -F -e "$(hostname)" -e "/mnt/" -e "$HOME" "$G" || true)
roots=$(jq -r '.packages[] | select(.SPDXID | test("DocumentRoot")) | .name' "$G" | grep -c '^/' || true)

echo "lines with the host name, /mnt/ or \$HOME: $text"
echo "roots named after a path: $roots"
if [ "$text" -eq 0 ] && [ "$roots" -eq 0 ]; then
  echo "PASS: no host name or build path in the document"
else
  echo "FAIL: build-host traces in the document (rescan the OS layer with --source-name, runbook section 2.1)"
  exit 1
fi
