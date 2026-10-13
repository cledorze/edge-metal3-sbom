#!/usr/bin/env bash
# Test 4: the DESCRIBES roots of the global SBOM = the distinct roots of its inputs (runbook, section 8 checklist).
# An image scanned in two clusters has the same root identifier in both SBOMs and counts once after the merge:
# on the Edge 3.5.2 bench, 50 inputs gave 43 roots (7 images shared by the management and downstream clusters).
# Usage: tests/04-roots-equal-inputs.sh [WORK]
set -euo pipefail
WORK="${1:-${WORK:-$PWD}}"
cd "$WORK"

G=sbom-global.spdx.json
if [ ! -s "$G" ]; then
  echo "FAIL: $G missing or empty"
  exit 2
fi

# Same input list as the merge of section 6.
INPUTS=$(ls mgmt/sbom-os.spdx.json mgmt/images/*.spdx.json downstream/sbom-os.spdx.json downstream/images/*.spdx.json workload/images/*.spdx.json 2>/dev/null)
inputs=$(echo $INPUTS | wc -w | tr -d ' ')
distinct=$(jq -r '.relationships[] | select(.spdxElementId == "SPDXRef-DOCUMENT" and .relationshipType == "DESCRIBES") | .relatedSpdxElement' $INPUTS | sort -u | wc -l | tr -d ' ')
roots=$(jq '[.relationships[] | select(.relationshipType == "DESCRIBES")] | length' "$G")
packages=$(jq '.packages | length' "$G")

echo "inputs: $inputs, distinct input roots: $distinct, DESCRIBES roots in global: $roots, packages in global: $packages"
if [ "$inputs" -eq 0 ]; then
  echo "FAIL: no input found under $WORK"
  exit 2
fi
if [ "$roots" -eq "$distinct" ]; then
  echo "PASS: every input root is described once in the global document"
else
  echo "FAIL: $roots roots in the global document, $distinct distinct roots in the inputs"
  exit 1
fi
