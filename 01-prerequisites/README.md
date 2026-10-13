# Step 1: prerequisites and variables

Script: `source 01-prerequisites/env.sh` exports the variables below (and creates the output directories) for the scripts of steps 2 to 7.
## 1. Prerequisites and variables

Everything runs on the build host: the machine where EIB built the images and where the management kubeconfig is. Root is needed once per image, to mount it.

```bash
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b "$HOME/.local/bin" v1.42.3
python3 -m venv "$HOME/sbomval"
"$HOME/sbomval/bin/pip" install -q spdx-tools==0.8.5 ntia-conformance-checker==6.0.0
sudo zypper -n in jq zstd
```

Set the variables once per shell. The values are those of the bench; adapt the five paths to your deployment.

```bash
SYFT="$HOME/.local/bin/syft"
EDGE_VERSION=3.5.2
EIB_IMAGE=registry.suse.com/edge/3.5/edge-image-builder:1.3.3
EIB_MGMT_DIR="$HOME/eib/mgmt"           # EIB definition directory of the management image (the -v $DIR:/eib of the build)
EIB_DS_DIR="$HOME/eib/metal3"           # EIB definition directory of the downstream image
MGMT_RAW="$EIB_MGMT_DIR/SL-Micro.x86_64-6.2-Base-GM.mgmt.raw"
DS_RAW="$EIB_DS_DIR/SL-Micro.x86_64-6.2-Base-GM.metal3.raw"
MGMT_KUBECONFIG="$HOME/.kube/mgmt.config"
WORK="$HOME/metal3-sbom"                # output directory of this page
mkdir -p "$WORK/mgmt/images" "$WORK/downstream/images" "$WORK/workload/images"
```

