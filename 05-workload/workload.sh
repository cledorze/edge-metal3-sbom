#!/usr/bin/env bash
# Step 5: the workload alone, from the namespace WL_NS of the downstream cluster, into $WORK/workload.
# Needs the variables of step 1 and the downstream kubeconfig of step 4.
#   bash 05-workload/workload.sh
set -euo pipefail
export KUBECONFIG="$WORK/downstream/kubeconfig"
cd "$WORK/workload"
mkdir -p images
kubectl -n "$WL_NS" get pods -o jsonpath='{range .items[*]}{range .spec.containers[*]}{.image}{"\n"}{end}{range .spec.initContainers[*]}{.image}{"\n"}{end}{end}' \
  | sed -E 's#^(index\.)?docker\.io/##' | sort -u > all-images.txt

# the scan loop of section 3.3
while IFS= read -r IMG; do
  SAFE=$(printf '%s' "$IMG" | tr '/:@' '___')
  "$SYFT" -q "registry:${IMG}" --source-supplier SUSE -o spdx-json > "images/sbom-${SAFE}.spdx.json" < /dev/null
  printf '%6s  %s\n' "$(jq '.packages | length' "images/sbom-${SAFE}.spdx.json")" "$IMG"
done < all-images.txt
