#!/bin/bash
# Replay of scenario 6 from an empty directory, blocks extracted from lab-pro/security commit b63ed1d.
# Deviations: install block skipped (syft 1.42.3, jq, zstd already present; validators run on the laptop),
# /mnt/m352-os replaced by /mnt/m352-os (bench perimeter), air-gap alternative and validation blocks skipped.
set +e
echo "== $(date +%T) REPLAY START"
# --- section 1, variables (bench values) ---
SYFT="$HOME/.local/bin/syft"
EDGE_VERSION=3.5.2
EIB_IMAGE=registry.suse.com/edge/3.5/edge-image-builder:1.3.3
EIB_MGMT_DIR="/var/lib/libvirt/images/metal3-edge352/work/eib/mgmt"
EIB_DS_DIR="/var/lib/libvirt/images/metal3-edge352/work/eib/metal3"
MGMT_RAW="$EIB_MGMT_DIR/SL-Micro.x86_64-6.2-Base-GM.mgmt.raw"
DS_RAW="$EIB_DS_DIR/SL-Micro.x86_64-6.2-Base-GM.metal3.raw"
MGMT_KUBECONFIG="$HOME/.kube/m352.config"
WORK="/var/lib/libvirt/images/metal3-edge352/sbom/replay-20261012"
mkdir -p "$WORK/mgmt/images" "$WORK/downstream/images" "$WORK/workload/images"
"$SYFT" version | head -2
echo "== $(date +%T) management, block 03"
cd "$WORK/mgmt"
sudo mkdir -p /mnt/m352-os
LOOP=$(sudo losetup -fP --show -r "$MGMT_RAW")
sudo mount -o ro "${LOOP}p3" /mnt/m352-os
grep -E '^(SUSE_PRETTY_NAME|VERSION_ID)=' /mnt/m352-os/etc/os-release
sudo "$SYFT" -q dir:/mnt/m352-os --select-catalogers rpm \
  --source-name "$(basename "$MGMT_RAW")" --source-version "$EDGE_VERSION" --source-supplier SUSE \
  -o spdx-json > sbom-os.spdx.json
sudo umount /mnt/m352-os && sudo losetup -d "$LOOP"
jq '.packages | length' sbom-os.spdx.json
echo "== $(date +%T) management, block 04"
cd "$WORK/mgmt"
BUILD=$(ls -d "$EIB_MGMT_DIR"/_build/build-* | tail -1)
ls "$BUILD"/helm/*/*.tgz | sed "s|$BUILD/||" | tee eib-charts.txt
ls "$BUILD"/artefacts/registry/ | sed 's/-registry\.tar\.zst$//' | tr '_' '/' | tee eib-embedded-images.txt
for F in "$BUILD"/artefacts/kubernetes/images/*.tar.zst; do
  echo "# $(basename "$F")"
  zstd -dc "$F" | tar -xO manifest.json | jq -r '.[].RepoTags[]'
done | tee eib-rke2-bundle-images.txt
echo "== $(date +%T) management, block 05"
cd "$WORK"
"$SYFT" -q "registry:$EIB_IMAGE" --source-supplier SUSE -o spdx-json > sbom-eib-tool.spdx.json
jq '.packages | length' sbom-eib-tool.spdx.json
echo "== $(date +%T) management, block 06"
export KUBECONFIG="$MGMT_KUBECONFIG"
cd "$WORK/mgmt"
kubectl get nodes -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.status.nodeInfo.kubeletVersion}{"\t"}{.status.nodeInfo.osImage}{"\n"}{end}' | tee nodes.tsv
helm list -A -o json | jq -r '.[] | [.namespace, .name, .chart, .app_version, .status] | @tsv' | tee helm-releases.tsv
kubectl get crds -o name | grep -E 'metal3|cluster.x-k8s.io|rke2|turtles' | sort > capi-crds.txt; wc -l < capi-crds.txt
kubectl get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}{"\t"}{range .spec.containers[*]}{.image}{" "}{end}{"\n"}{end}' \
  | grep -E 'capi|capm3|rke2-bootstrap|rke2-control-plane|turtles|metal3' | sort -u | tee capi-controllers.tsv
echo "== $(date +%T) management, block 07"
kubectl get pods -A -o jsonpath='{range .items[*]}{range .spec.containers[*]}{.image}{"\n"}{end}{range .spec.initContainers[*]}{.image}{"\n"}{end}{end}' \
  | sort -u > running-images.txt
kubectl get pods -A -o jsonpath='{range .items[*]}{range .status.containerStatuses[*]}{.imageID}{"\n"}{end}{range .status.initContainerStatuses[*]}{.imageID}{"\n"}{end}{end}' \
  | sort -u > running-image-digests.txt
cat running-images.txt eib-embedded-images.txt eib-rke2-bundle-images.txt \
  | grep -v '^#' | sed -E 's#^(index\.)?docker\.io/##' | sort -u > all-images.txt
wc -l running-images.txt all-images.txt
echo "== $(date +%T) management, block 08"
while IFS= read -r IMG; do
  SAFE=$(printf '%s' "$IMG" | tr '/:@' '___')
  "$SYFT" -q "registry:${IMG}" --source-supplier SUSE -o spdx-json > "images/sbom-${SAFE}.spdx.json" < /dev/null
  printf '%6s  %s\n' "$(jq '.packages | length' "images/sbom-${SAFE}.spdx.json")" "$IMG"
done < all-images.txt
echo "== $(date +%T) downstream, block 10 (kubeconfig)"
DS_CLUSTER=sample-cluster
DS_NS=default
export KUBECONFIG="$MGMT_KUBECONFIG"
kubectl -n "$DS_NS" get secret "${DS_CLUSTER}-kubeconfig" -o jsonpath='{.data.value}' | base64 -d > "$WORK/downstream/kubeconfig"
chmod 600 "$WORK/downstream/kubeconfig"
echo "== $(date +%T) downstream, block 03"
cd "$WORK/downstream"
sudo mkdir -p /mnt/m352-os
LOOP=$(sudo losetup -fP --show -r "$DS_RAW")
sudo mount -o ro "${LOOP}p3" /mnt/m352-os
grep -E '^(SUSE_PRETTY_NAME|VERSION_ID)=' /mnt/m352-os/etc/os-release
sudo "$SYFT" -q dir:/mnt/m352-os --select-catalogers rpm \
  --source-name "$(basename "$DS_RAW")" --source-version "$EDGE_VERSION" --source-supplier SUSE \
  -o spdx-json > sbom-os.spdx.json
sudo umount /mnt/m352-os && sudo losetup -d "$LOOP"
jq '.packages | length' sbom-os.spdx.json
echo "== $(date +%T) downstream, block 04"
cd "$WORK/downstream"
BUILD=$(ls -d "$EIB_DS_DIR"/_build/build-* | tail -1)
ls "$BUILD"/helm/*/*.tgz | sed "s|$BUILD/||" | tee eib-charts.txt
ls "$BUILD"/artefacts/registry/ | sed 's/-registry\.tar\.zst$//' | tr '_' '/' | tee eib-embedded-images.txt
for F in "$BUILD"/artefacts/kubernetes/images/*.tar.zst; do
  echo "# $(basename "$F")"
  zstd -dc "$F" | tar -xO manifest.json | jq -r '.[].RepoTags[]'
done | tee eib-rke2-bundle-images.txt
echo "== $(date +%T) downstream, block 06"
export KUBECONFIG="$WORK/downstream/kubeconfig"
cd "$WORK/downstream"
kubectl get nodes -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.status.nodeInfo.kubeletVersion}{"\t"}{.status.nodeInfo.osImage}{"\n"}{end}' | tee nodes.tsv
helm list -A -o json | jq -r '.[] | [.namespace, .name, .chart, .app_version, .status] | @tsv' | tee helm-releases.tsv
kubectl get crds -o name | grep -E 'metal3|cluster.x-k8s.io|rke2|turtles' | sort > capi-crds.txt; wc -l < capi-crds.txt
kubectl get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}{"\t"}{range .spec.containers[*]}{.image}{" "}{end}{"\n"}{end}' \
  | grep -E 'capi|capm3|rke2-bootstrap|rke2-control-plane|turtles|metal3' | sort -u | tee capi-controllers.tsv
echo "== $(date +%T) downstream, block 07"
kubectl get pods -A -o jsonpath='{range .items[*]}{range .spec.containers[*]}{.image}{"\n"}{end}{range .spec.initContainers[*]}{.image}{"\n"}{end}{end}' \
  | sort -u > running-images.txt
kubectl get pods -A -o jsonpath='{range .items[*]}{range .status.containerStatuses[*]}{.imageID}{"\n"}{end}{range .status.initContainerStatuses[*]}{.imageID}{"\n"}{end}{end}' \
  | sort -u > running-image-digests.txt
cat running-images.txt eib-embedded-images.txt eib-rke2-bundle-images.txt \
  | grep -v '^#' | sed -E 's#^(index\.)?docker\.io/##' | sort -u > all-images.txt
wc -l running-images.txt all-images.txt
echo "== $(date +%T) downstream, block 08"
while IFS= read -r IMG; do
  SAFE=$(printf '%s' "$IMG" | tr '/:@' '___')
  "$SYFT" -q "registry:${IMG}" --source-supplier SUSE -o spdx-json > "images/sbom-${SAFE}.spdx.json" < /dev/null
  printf '%6s  %s\n' "$(jq '.packages | length' "images/sbom-${SAFE}.spdx.json")" "$IMG"
done < all-images.txt
echo "== $(date +%T) workload, block 11 + 08"
export KUBECONFIG="$WORK/downstream/kubeconfig"
cd "$WORK/workload"
WL_NS=sample-workload
kubectl -n "$WL_NS" get pods -o jsonpath='{range .items[*]}{range .spec.containers[*]}{.image}{"\n"}{end}{range .spec.initContainers[*]}{.image}{"\n"}{end}{end}' \
  | sed -E 's#^(index\.)?docker\.io/##' | sort -u > all-images.txt
while IFS= read -r IMG; do
  SAFE=$(printf '%s' "$IMG" | tr '/:@' '___')
  "$SYFT" -q "registry:${IMG}" --source-supplier SUSE -o spdx-json > "images/sbom-${SAFE}.spdx.json" < /dev/null
  printf '%6s  %s\n' "$(jq '.packages | length' "images/sbom-${SAFE}.spdx.json")" "$IMG"
done < all-images.txt
echo "== $(date +%T) merge, block 12"
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
echo "== $(date +%T) hand-over check, block 14"
grep -c -F -e "$(hostname)" -e "/mnt/" -e "$HOME" sbom-global.spdx.json
echo "REPLAY_DONE $(date +%T)"
