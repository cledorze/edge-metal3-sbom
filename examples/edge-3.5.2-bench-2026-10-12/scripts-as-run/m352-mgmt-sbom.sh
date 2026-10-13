#!/bin/bash
# Management-cluster SBOM collection, Edge 3.5.2 Metal3/CAPI bench (m352), scenario 06 layers.
set -u
export KUBECONFIG=$HOME/.kube/m352.config
SYFT=$HOME/.local/bin/syft
B=/var/lib/libvirt/images/metal3-edge352
O=$B/sbom/mgmt
EIB=registry.suse.com/edge/3.5/edge-image-builder:1.3.3
mkdir -p $O/images
cd $O
echo "== start $(date -u +%T) syft $($SYFT version | awk '/^Version/{print $2}')"

echo "== layer 1: OS of the management image"
RAW=$B/work/eib/mgmt/SL-Micro.x86_64-6.2-Base-GM.mgmt.raw
sudo mkdir -p /mnt/m352-os
LOOP=$(sudo losetup -fP --show -r "$RAW")
sudo mount -o ro "${LOOP}p3" /mnt/m352-os
grep -E '^(SUSE_PRETTY_NAME|VERSION_ID)=' /mnt/m352-os/etc/os-release
sudo $SYFT -q dir:/mnt/m352-os --select-catalogers rpm --source-version 3.5.2 --source-supplier SUSE \
  -o spdx-json > sbom-os.spdx.json
sudo umount /mnt/m352-os; sudo losetup -d "$LOOP"
echo "os packages: $(jq '.packages | length' sbom-os.spdx.json)"

echo "== layer 2: EIB tool image (build provenance, not in the global SBOM)"
$SYFT -q "registry:${EIB}" --source-supplier SUSE -o spdx-json > sbom-eib-tool.spdx.json < /dev/null
echo "eib tool packages: $(jq '.packages | length' sbom-eib-tool.spdx.json)"

echo "== layer 3: RKE2"
kubectl get nodes -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.status.nodeInfo.kubeletVersion}{"\t"}{.status.nodeInfo.osImage}{"\n"}{end}'
RKE2=$(kubectl get nodes -o jsonpath='{.items[0].status.nodeInfo.kubeletVersion}')
curl -sSfL "https://github.com/rancher/rke2/releases/download/${RKE2/+/%2B}/rke2-images-all.linux-amd64.txt" > rke2-images-all.txt
echo "rke2 release image list: $(wc -l < rke2-images-all.txt)"

echo "== layer 4: Helm releases"
helm list -A -o json | jq -r '.[] | [.namespace, .name, .chart, .app_version, .status] | @tsv' | tee helm-releases.tsv

echo "== layer 6: CAPI and Metal3 CRDs and controllers"
kubectl get crds -o name | grep -E 'metal3|cluster.x-k8s.io|rke2|turtles' | sort > capi-crds.txt
echo "crds: $(wc -l < capi-crds.txt)"
kubectl get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}{"\t"}{range .spec.containers[*]}{.image}{" "}{end}{"\n"}{end}' \
  | grep -E 'capi|capm3|rke2-bootstrap|rke2-control-plane|turtles|metal3' | sort -u > capi-controllers.tsv
cat capi-controllers.tsv

echo "== layer 5: container images of every running and init container"
kubectl get pods -A -o jsonpath='{range .items[*]}{range .spec.containers[*]}{.image}{"\n"}{end}{range .spec.initContainers[*]}{.image}{"\n"}{end}{end}' \
  | sort -u > MASTER-image-list.txt
echo "images: $(wc -l < MASTER-image-list.txt)"
while IFS= read -r IMG; do
  SAFE=$(printf '%s' "$IMG" | tr '/:@' '___')
  $SYFT -q "registry:${IMG}" --source-supplier SUSE -o spdx-json > "images/sbom-${SAFE}.spdx.json" < /dev/null
  printf '%6s  %s\n' "$(jq '.packages | length' "images/sbom-${SAFE}.spdx.json" 2>/dev/null)" "$IMG"
done < MASTER-image-list.txt

echo "== global SBOM: OS + images (merge of scenario 7, section 6)"
jq -s --arg name "edge352-metal3-mgmt-global" \
      --arg ns "https://spdx.org/spdxdocs/edge352-metal3-mgmt-global-$(cat /proc/sys/kernel/random/uuid)" '
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
    }' sbom-os.spdx.json images/sbom-*.spdx.json > sbom-global.spdx.json
echo "sum of inputs:   $(jq -s '[.[].packages | length] | add' sbom-os.spdx.json images/sbom-*.spdx.json)"
echo "global packages: $(jq '.packages | length' sbom-global.spdx.json)"
echo "DESCRIBES roots: $(jq '[.relationships[] | select(.relationshipType=="DESCRIBES")] | length' sbom-global.spdx.json) (inputs: $(ls sbom-os.spdx.json images/sbom-*.spdx.json | wc -l))"
echo "empty inputs:    $(for f in sbom-os.spdx.json images/*.spdx.json; do [ "$(jq '.packages | length' "$f" 2>/dev/null || echo 0)" -gt 0 ] || echo "$f"; done | wc -l)"
ls -la sbom-global.spdx.json
echo "MGMT_SBOM_DONE $(date -u +%T)"
