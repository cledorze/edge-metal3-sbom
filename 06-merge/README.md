# Step 6: merge into one global SBOM

Script: `bash 06-merge/merge.sh` runs the merge below and writes `sbom-global.spdx.json.sha256`.
## 6. Merge into one global SBOM

One SPDX document per stack: packages, files and extracted licences are deduplicated by their SPDX identifier, every relationship of the inputs is kept, and the `DESCRIBES` relationships of each input are re-hung on the new document, so each layer keeps its root and every package can be traced back to the image or OS it came from.

```bash
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
echo "empty inputs:    $(for f in $INPUTS; do [ "$(jq '.packages | length' "$f" 2>/dev/null || echo 0)" -gt 0 ] || echo "$f"; done | wc -l)"
sha256sum sbom-global.spdx.json > sbom-global.spdx.json.sha256
```

Observed, 2026-10-09, management cluster only (OS plus the 35 running images):

```
inputs:          36
sum of inputs:   9455
global packages: 8482
DESCRIBES roots: 36
```

The file weighs 100 MB.

Observed, 2026-10-12, whole stack (management cluster scans of 2026-10-09, downstream cluster and workload of 2026-10-12):

```
inputs:          50
sum of inputs:   13509
global packages: 9374
DESCRIBES roots: 43
```

The file weighs 107 MB.

Replayed on 2026-10-12 from an empty directory, with the shipped set of the management cluster:

```
inputs:          69
sum of inputs:   15708
global packages: 11409
DESCRIBES roots: 58
```

One of the 69 inputs is the empty `hauler` scan of section 2.2 and ten are images shared between layers; the file weighs 112 MB.

The number of roots equals the number of distinct inputs: an image scanned for two clusters under the same name keeps one root (seven of the 50 inputs above are such repeats, hence 43 roots). Two names for the same image, such as `index.docker.io/rancher/hardened-etcd` and `rancher/hardened-etcd`, give two roots: hence the `sed` of section 3.2.

