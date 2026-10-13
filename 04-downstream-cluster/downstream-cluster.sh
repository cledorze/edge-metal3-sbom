#!/usr/bin/env bash
# Step 4: the downstream cluster: its kubeconfig from the management cluster, then step 2 on the downstream
# image and step 3 on the downstream cluster, into $WORK/downstream. Needs the variables of step 1.
#   bash 04-downstream-cluster/downstream-cluster.sh
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$WORK/downstream/images"

export KUBECONFIG="$MGMT_KUBECONFIG"
kubectl -n "$DS_NS" get secret "${DS_CLUSTER}-kubeconfig" -o jsonpath='{.data.value}' | base64 -d > "$WORK/downstream/kubeconfig"
chmod 600 "$WORK/downstream/kubeconfig"

bash "$HERE/../02-build-time-layers/build-time-layers.sh" "$DS_RAW" "$EIB_DS_DIR" "$WORK/downstream"
bash "$HERE/../03-management-cluster/management-cluster.sh" "$WORK/downstream/kubeconfig" "$WORK/downstream"
