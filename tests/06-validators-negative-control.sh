#!/usr/bin/env bash
# Test 6: negative control of the two validators on a small per-image SBOM.
# Proves that tests 1 and 2 can fail: the untouched copy passes both, a broken relationship target fails
# pyspdxtools, and three packages without supplier fail the NTIA check. Run on 2026-10-12 on the nginx
# image SBOM of the Edge 3.5.2 bench (89 packages): untouched rc=0 / Conformant: True, broken relationship
# rc=1 "The document is invalid", suppliers removed Conformant: False rc=1.
# Usage: tests/06-validators-negative-control.sh [SBOM]
#   SBOM = a per-image SPDX JSON (default: the nginx sample shipped under examples/)
# Env:   SBOMVAL = bin directory of the validation venv (default: $HOME/sbomval/bin)
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
F="${1:-$HERE/../examples/edge-3.5.2-bench-2026-10-12/sbom-samples/sbom-registry.suse.com_suse_nginx_1.27.spdx.json}"
SBOMVAL="${SBOMVAL:-$HOME/sbomval/bin}"

if [ ! -s "$F" ]; then
  echo "FAIL: $F missing or empty"
  exit 2
fi

D=$(mktemp -d)
trap 'rm -rf "$D"' EXIT
cp "$F" "$D/ok.json"
echo "control file: $(basename "$F") ($(jq '.packages | length' "$F") packages, $(jq '.relationships | length' "$F") relationships)"
fail=0

# 1. untouched copy: both validators must pass
rc=0; "$SBOMVAL/pyspdxtools" -i "$D/ok.json" > "$D/ok-spdx.out" 2>&1 || rc=$?
echo "untouched: pyspdxtools rc=$rc"
[ "$rc" -eq 0 ] || fail=1
rc=0; "$SBOMVAL/ntia-checker" "$D/ok.json" > "$D/ok-ntia.out" 2>&1 || rc=$?
echo "untouched: ntia rc=$rc $(grep -m1 'Conformant:' "$D/ok-ntia.out")"
{ [ "$rc" -eq 0 ] && grep -q '^Conformant: True' "$D/ok-ntia.out"; } || fail=1

# 2. broken relationship target: pyspdxtools must fail
jq '.relationships[1].relatedSpdxElement = "SPDXRef-DOES-NOT-EXIST"' "$D/ok.json" > "$D/badrel.json"
rc=0; "$SBOMVAL/pyspdxtools" -i "$D/badrel.json" > "$D/badrel.out" 2>&1 || rc=$?
echo "broken relationship: pyspdxtools rc=$rc ; $(head -1 "$D/badrel.out" | cut -c1-160)"
[ "$rc" -ne 0 ] || fail=1

# 3. supplier removed on 3 packages: ntia must report non-conformant
jq '.packages[0:3] |= map(del(.supplier))' "$D/ok.json" > "$D/nosup.json"
rc=0; "$SBOMVAL/ntia-checker" "$D/nosup.json" > "$D/nosup.out" 2>&1 || rc=$?
echo "3 suppliers removed: ntia rc=$rc ; $(grep -E 'Conformant:|suppliers' "$D/nosup.out" | tr -s ' ' | tr '\n' ';')"
grep -q '^Conformant: False' "$D/nosup.out" || fail=1

if [ "$fail" -eq 0 ]; then
  echo "PASS: both validators discriminate"
else
  echo "FAIL: a validator did not behave as expected (see lines above)"
  exit 1
fi
