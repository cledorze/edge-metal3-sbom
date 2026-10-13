#!/usr/bin/env bash
# Step 6: merge the per-layer SBOMs of $WORK into one SPDX 2.3 document, sbom-global.spdx.json, with its sha256.
# Needs the variables of step 1. Accepts any subset of the directories (a workload alone, for instance).
#   bash 06-merge/merge.sh
set -euo pipefail
cd "$WORK"
INPUTS=$(ls mgmt/sbom-os.spdx.json mgmt/images/*.spdx.json downstream/sbom-os.spdx.json downstream/images/*.spdx.json workload/images/*.spdx.json 2>/dev/null)
jq -s --arg name "edge-${EDGE_VERSION}-metal3-stack" \
      --arg ns "https://spdx.org/spdxdocs/edge-${EDGE_VERSION}-metal3-stack-$(cat /proc/sys/kernel/random/uuid)" '
  . as $docs
  | {
      spdxVersion: "SPDX-2.3",
      dataLicense: "CC0-1.0",
      SPDXID: "SPDXRef-DOCUMENT",
      name: $name,
      documentNamespace: $ns,
      creationInfo: { created: (now | strftime("%Y-%m-%dT%H:%M:%SZ")), creators: ["Tool: jq"] },
      packages: ([$docs[].packages[]?] | unique_by(.SPDXID)),
      files: ([$docs[].files[]?] | unique_by(.SPDXID)),
      hasExtractedLicensingInfos: ([$docs[].hasExtractedLicensingInfos[]?] | unique_by(.licenseId)),
      relationships: (
        ([$docs[].relationships[]?] | map(select(.spdxElementId != "SPDXRef-DOCUMENT")))
        + [ $docs[].relationships[]?
            | select(.spdxElementId == "SPDXRef-DOCUMENT" and .relationshipType == "DESCRIBES") ]
        | unique )
    }' $INPUTS > sbom-global.spdx.json
echo "inputs:          $(echo $INPUTS | wc -w)"
echo "sum of inputs:   $(jq -s '[.[].packages | length] | add' $INPUTS)"
echo "global packages: $(jq '.packages | length' sbom-global.spdx.json)"
echo "DESCRIBES roots: $(jq '[.relationships[] | select(.relationshipType=="DESCRIBES")] | length' sbom-global.spdx.json)"
sha256sum sbom-global.spdx.json > sbom-global.spdx.json.sha256
