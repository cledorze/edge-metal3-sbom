#!/usr/bin/env bash
# Sections 2 to 6 and 8 of docs/runbook.md in one script: the OS and embedded images of the management
# image, the EIB tool image (kept apart), the management cluster at runtime, the downstream cluster, the
# workload, the merge into one global SBOM, the hand-over check.
#
# Provenance: the blocks of the runbook, in the order of the page. The same sequence, with the bench paths
# of the Edge 3.5.2 bench, was run from an empty directory on 2026-10-12 (examples/.../scripts-as-run/
# replay-20261012.sh, log in examples/.../logs/replay-20261012.log). This generic version, with the
# variables of section 1, has not been run as such.
#
# Prerequisites (runbook, section 1): syft, jq, zstd, kubectl, helm; sudo for the loop mount of the raw
# images. The validation (section 7) is not run here: see tests/run-all.sh.
#
# Usage: set the variables below in the environment (or edit them), then
#   bash scripts/run-scenario-6.sh 2>&1 | tee "$WORK.log"
set -euo pipefail

# --- section 1, variables -------------------------------------------------------------------------
SYFT="${SYFT:-$HOME/.local/bin/syft}"
EDGE_VERSION="${EDGE_VERSION:-3.5.2}"
EIB_IMAGE="${EIB_IMAGE:-registry.suse.com/edge/3.5/edge-image-builder:1.3.3}"
EIB_MGMT_DIR="${EIB_MGMT_DIR:-$HOME/eib/mgmt}"            # EIB definition directory of the management image
EIB_DS_DIR="${EIB_DS_DIR:-$HOME/eib/metal3}"              # EIB definition directory of the downstream image
MGMT_RAW="${MGMT_RAW:-$EIB_MGMT_DIR/SL-Micro.x86_64-6.2-Base-GM.mgmt.raw}"
DS_RAW="${DS_RAW:-$EIB_DS_DIR/SL-Micro.x86_64-6.2-Base-GM.metal3.raw}"
MGMT_KUBECONFIG="${MGMT_KUBECONFIG:-$HOME/.kube/mgmt.config}"
WORK="${WORK:-$HOME/metal3-sbom}"
DS_CLUSTER="${DS_CLUSTER:-sample-cluster}"                # Cluster name (section 4)
DS_NS="${DS_NS:-default}"                                 # namespace of the Cluster object (section 4)
WL_NS="${WL_NS:-my-app}"                                  # workload namespace (section 5)
MNT=/mnt/eib-os

for t in "$SYFT" jq zstd kubectl helm; do
  command -v "$t" > /dev/null 2>&1 || { echo "missing tool: $t"; exit 1; }
done
mkdir -p "$WORK/mgmt/images" "$WORK/downstream/images" "$WORK/workload/images"
echo "== $(date +%T) start, syft $("$SYFT" version 2>/dev/null | awk '/^Version:/ {print $2}')"

# --- section 2.1, OS packages of an EIB image (one call per image) ---------------------------------
scan_os() {   # $1 = raw image, $2 = output directory
  local RAW=$1 OUT=$2 LOOP
  cd "$OUT"
  sudo mkdir -p "$MNT"
  LOOP=$(sudo losetup -fP --show -r "$RAW")
  sudo mount -o ro "${LOOP}p3" "$MNT"
  grep -E '^(SUSE_PRETTY_NAME|VERSION_ID)=' "$MNT/etc/os-release"
  sudo "$SYFT" -q dir:"$MNT" --select-catalogers rpm \
    --source-name "$(basename "$RAW")" --source-version "$EDGE_VERSION" --source-supplier SUSE \
    -o spdx-json > sbom-os.spdx.json
  sudo umount "$MNT" && sudo losetup -d "$LOOP"
  echo "os packages: $(jq '.packages | length' sbom-os.spdx.json)"
}

# --- section 2.2, images embedded by EIB ------------------------------------------------------------
list_embedded() {   # $1 = EIB definition directory, run in the output directory
  local BUILD
  BUILD=$(ls -d "$1"/_build/build-* | tail -1)
  ls "$BUILD"/helm/*/*.tgz 2>/dev/null | sed "s|$BUILD/||" | tee eib-charts.txt
  ls "$BUILD"/artefacts/registry/*-registry.tar.zst 2>/dev/null | xargs -n1 basename | sed 's/-registry\.tar\.zst$//' | tr '_' '/' | tee eib-embedded-images.txt
  for F in "$BUILD"/artefacts/kubernetes/images/*.tar.zst; do
    [ -e "$F" ] || continue
    echo "# $(basename "$F")"
    zstd -dc "$F" | tar -xO manifest.json | jq -r '.[].RepoTags[]'
  done | tee eib-rke2-bundle-images.txt
  touch eib-charts.txt eib-embedded-images.txt eib-rke2-bundle-images.txt
}

# --- sections 3.1 to 3.3, a cluster at runtime (KUBECONFIG set by the caller) ----------------------
scan_cluster() {   # run in the output directory
  kubectl get nodes -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.status.nodeInfo.kubeletVersion}{"\t"}{.status.nodeInfo.osImage}{"\n"}{end}' | tee nodes.tsv
  helm list -A -o json | jq -r '.[] | [.namespace, .name, .chart, .app_version, .status] | @tsv' | tee helm-releases.tsv
  kubectl get crds -o name | grep -E 'metal3|cluster.x-k8s.io|rke2|turtles' | sort > capi-crds.txt || true; wc -l < capi-crds.txt
  kubectl get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}{"\t"}{range .spec.containers[*]}{.image}{" "}{end}{"\n"}{end}' \
    | grep -E 'capi|capm3|rke2-bootstrap|rke2-control-plane|turtles|metal3' | sort -u | tee capi-controllers.tsv || true
  kubectl get pods -A -o jsonpath='{range .items[*]}{range .spec.containers[*]}{.image}{"\n"}{end}{range .spec.initContainers[*]}{.image}{"\n"}{end}{end}' \
    | sort -u > running-images.txt
  kubectl get pods -A -o jsonpath='{range .items[*]}{range .status.containerStatuses[*]}{.imageID}{"\n"}{end}{range .status.initContainerStatuses[*]}{.imageID}{"\n"}{end}{end}' \
    | sort -u > running-image-digests.txt
  cat running-images.txt eib-embedded-images.txt eib-rke2-bundle-images.txt \
    | grep -v '^#' | sed -E 's#^(index\.)?docker\.io/##' | sort -u > all-images.txt
  wc -l running-images.txt all-images.txt
  scan_images
}

scan_images() {   # section 3.3, run in the output directory, reads all-images.txt
  while IFS= read -r IMG; do
    SAFE=$(printf '%s' "$IMG" | tr '/:@' '___')
    "$SYFT" -q "registry:${IMG}" --source-supplier SUSE -o spdx-json > "images/sbom-${SAFE}.spdx.json" < /dev/null
    printf '%6s  %s\n' "$(jq '.packages | length' "images/sbom-${SAFE}.spdx.json")" "$IMG"
  done < all-images.txt
}

# --- management image and cluster ------------------------------------------------------------------
echo "== $(date +%T) management image, section 2.1"
scan_os "$MGMT_RAW" "$WORK/mgmt"
echo "== $(date +%T) management image, section 2.2"
cd "$WORK/mgmt" && list_embedded "$EIB_MGMT_DIR"
echo "== $(date +%T) EIB tool image, section 2.3 (kept apart)"
cd "$WORK"
"$SYFT" -q "registry:$EIB_IMAGE" --source-supplier SUSE -o spdx-json > sbom-eib-tool.spdx.json
echo "eib tool packages: $(jq '.packages | length' sbom-eib-tool.spdx.json)"
echo "== $(date +%T) management cluster, sections 3.1 to 3.3"
export KUBECONFIG="$MGMT_KUBECONFIG"
cd "$WORK/mgmt" && scan_cluster

# --- downstream cluster, section 4 -----------------------------------------------------------------
echo "== $(date +%T) downstream cluster, section 4"
export KUBECONFIG="$MGMT_KUBECONFIG"
kubectl -n "$DS_NS" get secret "${DS_CLUSTER}-kubeconfig" -o jsonpath='{.data.value}' | base64 -d > "$WORK/downstream/kubeconfig"
chmod 600 "$WORK/downstream/kubeconfig"
scan_os "$DS_RAW" "$WORK/downstream"
cd "$WORK/downstream" && list_embedded "$EIB_DS_DIR"
export KUBECONFIG="$WORK/downstream/kubeconfig"
cd "$WORK/downstream" && scan_cluster

# --- workload, section 5 ---------------------------------------------------------------------------
echo "== $(date +%T) workload, section 5 (namespace $WL_NS)"
export KUBECONFIG="$WORK/downstream/kubeconfig"
cd "$WORK/workload"
kubectl -n "$WL_NS" get pods -o jsonpath='{range .items[*]}{range .spec.containers[*]}{.image}{"\n"}{end}{range .spec.initContainers[*]}{.image}{"\n"}{end}{end}' \
  | sed -E 's#^(index\.)?docker\.io/##' | sort -u > all-images.txt
scan_images

# --- merge, section 6 ------------------------------------------------------------------------------
echo "== $(date +%T) merge, section 6"
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

# --- hand-over check, section 8 (the validation of section 7 is tests/run-all.sh) ------------------
echo "== $(date +%T) hand-over check, section 8"
echo "lines with the host name, /mnt/ or \$HOME: $(grep -c -F -e "$(hostname)" -e "/mnt/" -e "$HOME" sbom-global.spdx.json || true)"
echo "roots named after a path: $(jq -r '.packages[] | select(.SPDXID | test("DocumentRoot")) | .name' sbom-global.spdx.json | grep -c '^/' || true)"
echo "== $(date +%T) done: $WORK/sbom-global.spdx.json ; next: tests/run-all.sh $WORK"
