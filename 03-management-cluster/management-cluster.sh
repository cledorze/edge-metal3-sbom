#!/usr/bin/env bash
# Step 3: a cluster at runtime: inventories (3.1), master image list (3.2), one SBOM per image (3.3).
# Needs the variables of step 1 and the eib-*.txt lists of step 2 in the output directory.
#   bash 03-management-cluster/management-cluster.sh                      # management cluster, into $WORK/mgmt
#   bash 03-management-cluster/management-cluster.sh KUBECONFIG OUT       # another cluster (step 4 uses it for the downstream cluster)
set -euo pipefail
export KUBECONFIG="${1:-$MGMT_KUBECONFIG}"
OUT="${2:-$WORK/mgmt}"
cd "$OUT"
mkdir -p images

# 3.1 Node, RKE2 version and inventories
kubectl get nodes -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.status.nodeInfo.kubeletVersion}{"\t"}{.status.nodeInfo.osImage}{"\n"}{end}' | tee nodes.tsv
helm list -A -o json | jq -r '.[] | [.namespace, .name, .chart, .app_version, .status] | @tsv' | tee helm-releases.tsv
kubectl get crds -o name | grep -E 'metal3|cluster.x-k8s.io|rke2|turtles' | sort > capi-crds.txt || true; wc -l < capi-crds.txt
kubectl get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}{"\t"}{range .spec.containers[*]}{.image}{" "}{end}{"\n"}{end}' \
  | grep -E 'capi|capm3|rke2-bootstrap|rke2-control-plane|turtles|metal3' | sort -u | tee capi-controllers.tsv || true

# 3.2 Master image list: shipped and running
kubectl get pods -A -o jsonpath='{range .items[*]}{range .spec.containers[*]}{.image}{"\n"}{end}{range .spec.initContainers[*]}{.image}{"\n"}{end}{end}' \
  | sort -u > running-images.txt
kubectl get pods -A -o jsonpath='{range .items[*]}{range .status.containerStatuses[*]}{.imageID}{"\n"}{end}{range .status.initContainerStatuses[*]}{.imageID}{"\n"}{end}{end}' \
  | sort -u > running-image-digests.txt
cat running-images.txt eib-embedded-images.txt eib-rke2-bundle-images.txt \
  | grep -v '^#' | sed -E 's#^(index\.)?docker\.io/##' | sort -u > all-images.txt
wc -l running-images.txt all-images.txt

# 3.3 Scan every image
while IFS= read -r IMG; do
  SAFE=$(printf '%s' "$IMG" | tr '/:@' '___')
  "$SYFT" -q "registry:${IMG}" --source-supplier SUSE -o spdx-json > "images/sbom-${SAFE}.spdx.json" < /dev/null
  printf '%6s  %s\n' "$(jq '.packages | length' "images/sbom-${SAFE}.spdx.json")" "$IMG"
done < all-images.txt
