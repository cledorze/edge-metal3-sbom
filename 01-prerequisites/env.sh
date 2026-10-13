#!/usr/bin/env bash
# Step 1: the variables of the runbook, to source once per shell before the scripts of steps 2 to 7.
#   source 01-prerequisites/env.sh
# The values are those of the bench; adapt the paths to your deployment or set them in the environment first.

export SYFT="${SYFT:-$HOME/.local/bin/syft}"
export EDGE_VERSION="${EDGE_VERSION:-3.5.2}"
export EIB_IMAGE="${EIB_IMAGE:-registry.suse.com/edge/3.5/edge-image-builder:1.3.3}"
export EIB_MGMT_DIR="${EIB_MGMT_DIR:-$HOME/eib/mgmt}"          # EIB definition directory of the management image (the -v $DIR:/eib of the build)
export EIB_DS_DIR="${EIB_DS_DIR:-$HOME/eib/metal3}"            # EIB definition directory of the downstream image
export MGMT_RAW="${MGMT_RAW:-$EIB_MGMT_DIR/SL-Micro.x86_64-6.2-Base-GM.mgmt.raw}"
export DS_RAW="${DS_RAW:-$EIB_DS_DIR/SL-Micro.x86_64-6.2-Base-GM.metal3.raw}"
export MGMT_KUBECONFIG="${MGMT_KUBECONFIG:-$HOME/.kube/mgmt.config}"
export WORK="${WORK:-$HOME/metal3-sbom}"                       # output directory of the runbook
export SBOMVAL="${SBOMVAL:-$HOME/sbomval/bin}"                 # validation venv of step 1 (step 7)
export DS_CLUSTER="${DS_CLUSTER:-sample-cluster}"              # Cluster name (step 4)
export DS_NS="${DS_NS:-default}"                               # namespace of the Cluster object (step 4)
export WL_NS="${WL_NS:-my-app}"                                # workload namespace (step 5)
mkdir -p "$WORK/mgmt/images" "$WORK/downstream/images" "$WORK/workload/images"
