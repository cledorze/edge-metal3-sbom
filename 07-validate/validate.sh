#!/usr/bin/env bash
# Step 7: the five checks of the runbook on $WORK, each one PASS or FAIL, exit 1 if any fails.
#   1. no empty per-layer SBOM                      (section 8 checklist)
#   2. DESCRIBES roots = distinct roots of the inputs (section 8 checklist)
#   3. no host name or build path in the document   (section 8)
#   4. pyspdxtools rc=0, SPDX validity               (section 7, 47 min on a 107 MB document)
#   5. ntia-checker Conformant: True                 (section 7, 40 min on the same document)
# Needs the variables of step 1 (WORK, SBOMVAL).
#   bash 07-validate/validate.sh [WORK]          QUICK=1 skips checks 4 and 5
set -uo pipefail
WORK="${1:-$WORK}"
cd "$WORK"
G=sbom-global.spdx.json
[ -s "$G" ] || { echo "FAIL: $WORK/$G missing or empty"; exit 2; }
fail=0

echo "== 1. empty inputs ($(date +%T))"
n=0; empty=0
for f in */sbom-os.spdx.json */images/*.spdx.json; do
  [ -e "$f" ] || continue
  n=$((n + 1))
  c=$(jq '.packages | length' "$f" 2>/dev/null || echo 0)
  [ "${c:-0}" -gt 0 ] || { echo "EMPTY $f"; empty=$((empty + 1)); }
done
echo "inputs: $n, empty: $empty"
[ "$n" -gt 0 ] && [ "$empty" -eq 0 ] && echo "PASS" || { echo "FAIL"; fail=1; }

echo "== 2. roots ($(date +%T))"
INPUTS=$(ls mgmt/sbom-os.spdx.json mgmt/images/*.spdx.json downstream/sbom-os.spdx.json downstream/images/*.spdx.json workload/images/*.spdx.json 2>/dev/null)
distinct=$(jq -r '.relationships[] | select(.spdxElementId == "SPDXRef-DOCUMENT" and .relationshipType == "DESCRIBES") | .relatedSpdxElement' $INPUTS | sort -u | wc -l | tr -d ' ')
roots=$(jq '[.relationships[] | select(.relationshipType == "DESCRIBES")] | length' "$G")
echo "distinct input roots: $distinct, DESCRIBES roots in the global document: $roots, packages: $(jq '.packages | length' "$G")"
[ "$roots" -eq "$distinct" ] && echo "PASS" || { echo "FAIL"; fail=1; }

echo "== 3. host traces ($(date +%T))"
text=$(grep -c -F -e "$(hostname)" -e "/mnt/" -e "$HOME" "$G" || true)
paths=$(jq -r '.packages[] | select(.SPDXID | test("DocumentRoot")) | .name' "$G" | grep -c '^/' || true)
echo "lines with the host name, /mnt/ or \$HOME: $text; roots named after a path: $paths"
[ "$text" -eq 0 ] && [ "$paths" -eq 0 ] && echo "PASS" || { echo "FAIL (rescan the OS layer with --source-name, step 2)"; fail=1; }

if [ "${QUICK:-0}" = "1" ]; then echo "== 4 and 5 skipped (QUICK=1)"; echo "== done ($(date +%T))"; exit $fail; fi

echo "== 4. pyspdxtools ($(date +%T))"
start=$(date +%s); rc=0
"$SBOMVAL/pyspdxtools" -i "$G" || rc=$?
echo "pyspdxtools rc=$rc ($(( $(date +%s) - start )) s)"
[ "$rc" -eq 0 ] && echo "PASS" || { echo "FAIL"; fail=1; }

echo "== 5. ntia-checker ($(date +%T))"
OUT=$(mktemp); rc=0
"$SBOMVAL/ntia-checker" "$G" > "$OUT" 2>&1 || rc=$?
cat "$OUT"; echo "ntia rc=$rc"
[ "$rc" -eq 0 ] && grep -q '^Conformant: True' "$OUT" && echo "PASS" || { echo "FAIL"; fail=1; }
rm -f "$OUT"

echo "== done ($(date +%T))"
exit $fail
