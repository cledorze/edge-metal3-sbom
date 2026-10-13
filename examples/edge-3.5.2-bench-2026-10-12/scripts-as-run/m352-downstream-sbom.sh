#!/bin/bash
set +e
B=/var/lib/libvirt/images/metal3-edge352
SYFT=$HOME/.local/bin/syft
WORK=$B/sbom
EDGE_VERSION=3.5.2
scan_list() {
  while IFS= read -r IMG; do
    [ -z "$IMG" ] && continue
    SAFE=$(printf '%s' "$IMG" | tr '/:@' '___')
    "$SYFT" -q "registry:${IMG}" --source-supplier SUSE -o spdx-json > "images/sbom-${SAFE}.spdx.json" < /dev/null
    printf '%6s  %s\n' "$(jq '.packages | length' "images/sbom-${SAFE}.spdx.json" 2>/dev/null)" "$IMG"
  done < all-images.txt
}
export KUBECONFIG=$WORK/downstream/kubeconfig
cd $WORK/downstream; mkdir -p images
echo "== $(date +%T) downstream, section 3.2"
kubectl get pods -A -o jsonpath='{range .items[*]}{range .spec.containers[*]}{.image}{"\n"}{end}{range .spec.initContainers[*]}{.image}{"\n"}{end}{end}' | sort -u > running-images.txt
kubectl get pods -A -o jsonpath='{range .items[*]}{range .status.containerStatuses[*]}{.imageID}{"\n"}{end}{range .status.initContainerStatuses[*]}{.imageID}{"\n"}{end}{end}' | sort -u > running-image-digests.txt
BUILD=$(ls -d $B/work/eib/metal3/_build/build-* | tail -1)
ls "$BUILD"/helm/*/*.tgz 2>/dev/null | sed "s|$BUILD/||" > eib-charts.txt
ls "$BUILD"/artefacts/registry/ 2>/dev/null | sed 's/-registry\.tar\.zst$//' | tr '_' '/' > eib-embedded-images.txt
: > eib-rke2-bundle-images.txt
for F in "$BUILD"/artefacts/kubernetes/images/*.tar.zst; do [ -f "$F" ] || continue; echo "# $(basename "$F")"; zstd -dc "$F" | tar -xO manifest.json | jq -r '.[].RepoTags[]'; done >> eib-rke2-bundle-images.txt
cat running-images.txt eib-embedded-images.txt eib-rke2-bundle-images.txt | grep -v '^#' | sed -E 's#^(index\.)?docker\.io/##' | sort -u > all-images.txt
wc -l running-images.txt eib-embedded-images.txt eib-rke2-bundle-images.txt all-images.txt
echo "== $(date +%T) downstream, section 3.3"
scan_list
cd $WORK/workload; mkdir -p images
echo "== $(date +%T) workload, section 5"
WL_NS=sample-workload
kubectl -n "$WL_NS" get pods -o jsonpath='{range .items[*]}{range .spec.containers[*]}{.image}{"\n"}{end}{range .spec.initContainers[*]}{.image}{"\n"}{end}{end}' | sed -E 's#^(index\.)?docker\.io/##' | sort -u > all-images.txt
cat all-images.txt
scan_list
cd $WORK
echo "== $(date +%T) section 6, merge"
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
sha256sum sbom-global.spdx.json | tee sbom-global.spdx.json.sha256
ls -la sbom-global.spdx.json
echo "MERGE_DONE $(date +%T)"
