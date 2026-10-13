# Scenario 6: Full SBOM of a SUSE Edge Metal3/CAPI stack

**Question:** How do I produce one complete SBOM of a Metal3/CAPI deployment, from the EIB images to the workloads of the downstream clusters, that a reader can validate with standard tools?

**Tools:** syft 1.42.3, jq, zstd, kubectl, helm, python3 (spdx-tools 0.8.5 and ntia-conformance-checker 6.0.0 for the validation)

**Result:** one SPDX 2.3 JSON document, `sbom-global.spdx.json`, merged from one SBOM per layer, that passes `pyspdxtools` (SPDX validity) and `ntia-checker` (NTIA minimum elements), plus the per-layer SBOMs and the inventories it was built from.

**Scope:** a stack built with Edge Image Builder (EIB) and provisioned with Metal3 and Cluster API (CAPI) as described in the [Metal3 quickstart](https://documentation.suse.com/suse-edge/3.5/html/edge/quickstart-metal3.html): a management cluster (RKE2, Rancher, Metal3, CAPI providers) and the downstream clusters it provisions. Replayed on SUSE Edge 3.5.2. The [per-release page](edge-release-values.md) gives the Edge 3.6.1 values, which have not been replayed. The analysis of the SBOM (CVEs, licences, drift, signing, air-gap) is in [part 2](analysis-cve-licences-signing.md); nothing there is needed to produce it.

## Status

| Section | Replayed | Where and when |
|---|---|---|
| 2. Build-time layers: OS of the management image, images embedded by EIB, EIB tool | Yes | Edge 3.5.2 bench, 2026-10-09; offline scan of an embedded image on 2026-10-12 |
| 3. Management cluster at runtime | Yes | Edge 3.5.2 bench, 2026-10-09 |
| 4. Downstream cluster and 5. workload | Yes | Edge 3.5.2 bench, 2026-10-12, after the downstream image was rebuilt as in the product definition (section 9, item 1) |
| 6. Merge and 7. validation, management cluster alone | Yes | 2026-10-09: 36 inputs, 8482 packages, `pyspdxtools` rc=0, `ntia-checker` Conformant: True |
| 6. Merge, whole stack (management, downstream, workload) | Yes | 2026-10-12: 50 inputs, 9374 packages, 43 roots |
| 7. Validation, whole stack | Yes | 2026-10-12: 9374 packages, 107 MB, `pyspdxtools` rc=0 in 47 min 16 s, `ntia-checker` Conformant: True |
| Replay of the whole page from an empty directory (sections 2 to 6 and 8) | Yes | 2026-10-12, 15:27 to 15:33 on the bench, blocks of commit b63ed1d: 69 inputs (one empty, see 2.2), 11409 packages, 58 roots, 112 MB; `pyspdxtools` rc=0 in 50 min 56 s, `ntia-checker` Conformant: True |
| Edge 3.6.1 values | No | release notes and registry only |

Every example output below is marked **Observed** with its date, or **Not replayed**. A command block that carries no observed output has not been run on the bench.

**Tested setup.** A libvirt bench built with the `metal3-demo` playbooks of the suse-edge project (sushy-tools as Redfish BMC, one management VM, two downstream VMs), base image `SL-Micro.x86_64-6.2-Base-GM.raw`, EIB `registry.suse.com/edge/3.5/edge-image-builder:1.3.3`, RKE2 `v1.34.4+rke2r1`, Rancher 2.13.3, Metal3 chart `305.0.23+up0.13.1`, rancher-turtles-providers `305.0.5+up0.25.4`, cert-manager 1.19.2, syft 1.42.3. The commands of this page do not depend on the bench tooling: they read the EIB definition directories, the EIB build directory `_build/` and the kubeconfigs, which exist in any deployment that follows the product documentation. The whole page was replayed from an empty directory on 2026-10-12 (sections 2 to 6 and 8, with the variables of section 1 set to the bench paths and a bench-specific mount point; the install block was skipped because the tools were present, and the validation ran on a laptop).

Two notes on versions:

- Scenarios 7 and 8 (single node, phone home) use syft 1.52.0. Package counts differ between syft versions: do not compare counts across pages.
- The Edge 3.5 quickstart page, read on 2026-10-12, documents a later 3.5 z-release than the bench (`edge/3.5/edge-image-builder:1.3.3.1`, RKE2 `v1.34.7+rke2r1`). Set the variables of section 1 to the versions you deploy.

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

## 2. Build-time layers (no cluster needed)

### 2.1 OS packages of an EIB image

The RPM database of the image is read by mounting the raw image: partition 3 is the root file system of a SUSE Linux Micro raw image, and the RPM database is at `/usr/lib/sysimage/rpm`, which syft finds by itself. `--source-name`, `--source-version` and `--source-supplier` fill the name, version and supplier of the SBOM root: without them the root has no version and the RPM packages no supplier, and the NTIA check fails (observed on scenarios 7 and 8 before the fix). syft writes the `Organization:` prefix itself; the supplier recorded is the distributor of the packages, SUSE, not the upstream authors.

```bash
cd "$WORK/mgmt"
sudo mkdir -p /mnt/eib-os
LOOP=$(sudo losetup -fP --show -r "$MGMT_RAW")
sudo mount -o ro "${LOOP}p3" /mnt/eib-os
grep -E '^(SUSE_PRETTY_NAME|VERSION_ID)=' /mnt/eib-os/etc/os-release
sudo "$SYFT" -q dir:/mnt/eib-os --select-catalogers rpm \
  --source-name "$(basename "$MGMT_RAW")" --source-version "$EDGE_VERSION" --source-supplier SUSE \
  -o spdx-json > sbom-os.spdx.json
sudo umount /mnt/eib-os && sudo losetup -d "$LOOP"
jq '.packages | length' sbom-os.spdx.json
```

Observed, management image, 2026-10-09:

```
VERSION_ID="16.0"
SUSE_PRETTY_NAME="SUSE Linux Micro 6.2"
555
```

The 2026-10-09 run on the management image did not pass `--source-name`, so its root was named after the mount point. The flag was added afterwards and replayed on the downstream image on 2026-10-12: root `SL-Micro.x86_64-6.2-Base-GM.metal3.raw`, version `3.5.2`, supplier `Organization: SUSE`, 555 packages, and no line of the document carries the mount point.

The same block with `DS_RAW`, run in `$WORK/downstream`, gives the OS SBOM of the downstream image (section 4).

If the management image is an ISO rather than a raw image (the telco guide builds `eib-mgmt-cluster-image.iso`), there is no partition to mount: copy the syft binary to the installed node and run `syft dir:/ --select-catalogers rpm` there with the same `--source-*` flags. Not replayed.

### 2.2 Images embedded in the EIB images

EIB keeps what it embeds under `_build/build-<timestamp>/` of the definition directory, one directory per build: the Helm charts it pulled (`helm/<chart>/<chart>-<version>.tgz`), the container images of those charts and of the `embeddedArtifactRegistry` section (`artefacts/registry/<reference>-registry.tar.zst`, one OCI image layout per file, zstd-compressed, with `/` written as `_` in the file name) and the RKE2 image bundles (`artefacts/kubernetes/images/rke2-images-<set>.linux-amd64.tar.zst`, Docker archives of several images each). EIB 1.3.3 produces no package list file: the RPM list comes from section 2.1.

```bash
cd "$WORK/mgmt"
BUILD=$(ls -d "$EIB_MGMT_DIR"/_build/build-* | tail -1)
ls "$BUILD"/helm/*/*.tgz | sed "s|$BUILD/||" | tee eib-charts.txt
ls "$BUILD"/artefacts/registry/*-registry.tar.zst | xargs -n1 basename | sed 's/-registry\.tar\.zst$//' | tr '_' '/' | tee eib-embedded-images.txt
for F in "$BUILD"/artefacts/kubernetes/images/*.tar.zst; do
  echo "# $(basename "$F")"
  zstd -dc "$F" | tar -xO manifest.json | jq -r '.[].RepoTags[]'
done | tee eib-rke2-bundle-images.txt
```

Observed, management image build of 2026-10-09 (listing read on 2026-10-12):

```
helm/cert-manager/cert-manager-v1.19.2.tgz
helm/metal3/metal3-305.0.23+up0.13.1.tgz
helm/rancher/rancher-2.13.3.tgz
helm/rancher-turtles-providers/rancher-turtles-providers-305.0.5+up0.25.4.tgz
quay.io/jetstack/cert-manager-cainjector:v1.19.2
quay.io/jetstack/cert-manager-controller:v1.19.2
quay.io/jetstack/cert-manager-startupapicheck:v1.19.2
quay.io/jetstack/cert-manager-webhook:v1.19.2
registry.rancher.com/rancher/rancher:v2.13.3
registry.rancher.com/rancher/shell:v0.6.2
registry.suse.com/edge/3.5/baremetal-operator:0.11.2.0
registry.suse.com/edge/3.5/ironic-ipa-downloader:3.0.11
registry.suse.com/edge/3.5/ironic:32.0.0.1
# rke2-images-core.linux-amd64.tar.zst
rancher/hardened-addon-resizer:1.8.23-build20260206
rancher/hardened-cluster-autoscaler:v1.10.3-build20260206
rancher/hardened-coredns:v1.14.1-build20260206
rancher/hardened-dns-node-cache:1.26.7-build20260206
rancher/hardened-etcd:v3.6.7-k3s1-build20260126
rancher/hardened-k8s-metrics-server:v0.8.1-build20260206
rancher/hardened-kubernetes:v1.34.4-rke2r1-build20260210
rancher/hardened-snapshot-controller:v8.4.0-build20260205
rancher/klipper-helm:v0.9.14-build20260210
rancher/klipper-lb:v0.4.14
rancher/mirrored-ingress-nginx-kube-webhook-certgen:v1.6.7
rancher/mirrored-pause:3.6
rancher/nginx-ingress-controller:v1.14.3-hardened2
rancher/rke2-cloud-provider:v1.34.4-0.20260211145917-c6017918a65c-build20260211
rancher/rke2-runtime:v1.34.4-rke2r1
# rke2-images-calico.linux-amd64.tar.zst
docker.io/rancher/mirrored-calico-apiserver:v3.31.3
docker.io/rancher/mirrored-calico-cni:v3.31.3
docker.io/rancher/mirrored-calico-csi:v3.31.3
docker.io/rancher/mirrored-calico-ctl:v3.31.3
docker.io/rancher/mirrored-calico-envoy-gateway:v3.31.3
docker.io/rancher/mirrored-calico-envoy-proxy:v3.31.3
docker.io/rancher/mirrored-calico-envoy-ratelimit:v3.31.3
docker.io/rancher/mirrored-calico-goldmane:v3.31.3
docker.io/rancher/mirrored-calico-kube-controllers:v3.31.3
docker.io/rancher/mirrored-calico-node-driver-registrar:v3.31.3
docker.io/rancher/mirrored-calico-node:v3.31.3
docker.io/rancher/mirrored-calico-operator:v1.40.3
docker.io/rancher/mirrored-calico-pod2daemon-flexvol:v3.31.3
docker.io/rancher/mirrored-calico-typha:v3.31.3
docker.io/rancher/mirrored-calico-whisker-backend:v3.31.3
docker.io/rancher/mirrored-calico-whisker:v3.31.3
```

The `artefacts/registry/` directory also holds the `hauler` binary that EIB uses to pull the images (180 MB on the bench); the glob above keeps the archives only. The replay of 2026-10-12 ran an earlier form of the command without the glob, scanned a non-existent image called `hauler` and produced one empty input, which the merge ignores and which the `empty inputs` line of section 6 reports.

The embedded set is larger than the running set: the management node runs 6 of the 16 calico images and 9 of the 15 core images, and `cert-manager-startupapicheck` only runs once as a Job. The bundles are what the image ships; the running list of section 3 is what the cluster uses. Both go into the master image list, so that every shipped image is scanned.

The chart tarballs carry upstream defaults for images (`quay.io/metal3-io/cluster-api-provider-metal3:main`, `registry.opensuse.org/...`): the images that run come from the cluster (section 3), never from a grep of the tarballs.

A downstream image built as in the product definition, without a `kubernetes:` section, embeds nothing. Observed on 2026-10-12 on the rebuilt downstream image of the bench: its build directory holds the RPMs of `packageList` under `artefacts/rpms/` and no chart, registry archive or RKE2 bundle. RKE2 and its images are pulled at first boot by the CAPI bootstrap, and section 3 captures them on the running cluster.

### 2.3 EIB tool image (build provenance, kept apart)

```bash
cd "$WORK"
"$SYFT" -q "registry:$EIB_IMAGE" --source-supplier SUSE -o spdx-json > sbom-eib-tool.spdx.json
jq '.packages | length' sbom-eib-tool.spdx.json
```

Observed, 2026-10-09: `1584` packages (356 rpm, 950 golang, 276 cargo, 2 other). This SBOM is not merged into the global one: the build tool is not shipped with the stack.

SUSE publishes an SBOM attestation for its own container images (sigstore attestation, SPDX 2.0), retrievable with `crane digest --platform linux/amd64 <image>` then `cosign verify-attestation --type spdxjson --key /usr/share/pki/containers/suse-container-key.pem <image>@<digest> | jq '.payload | @base64d | fromjson | .predicate'`, as described in [SUSE Linux Enterprise and SBOM support](https://www.suse.com/support/security/sbom/). Observed on 2026-10-12 with cosign and the key `suse-container-key.pem` copied from a SUSE host: the command verifies the attestation of `registry.suse.com/suse/sle15:15.4` (SPDX-2.3, 137 packages, creator `Tool: obs_build_generate_sbom-1.0`). On `registry.suse.com/edge/3.5/ironic:32.0.0.1` and `registry.suse.com/edge/3.5/baremetal-operator:0.11.2.0` an attestation is present but signed with a key that is none of the three keys shipped under `/usr/share/pki/containers/` (`suse-container-key.pem`, `suse-container-key-old.pem`, `opensuse-container-key-2023.pem`); `registry.suse.com/rancher/cluster-api-provider-metal3:v1.10.4` carries no attestation. Which key signs the Edge images is an open question for the Edge team; until it is answered, syft is the source on this page. The same SUSE page says that the SBOMs of the product media (ISO images) are on the download website in SPDX 2.0 and CycloneDX at RPM level; it gives no URL pattern, and an EIB image is customised anyway, so section 2.1 is the source for the OS layer.

## 3. Management cluster at runtime

### 3.1 Node, RKE2 version and inventories

```bash
export KUBECONFIG="$MGMT_KUBECONFIG"
cd "$WORK/mgmt"
kubectl get nodes -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.status.nodeInfo.kubeletVersion}{"\t"}{.status.nodeInfo.osImage}{"\n"}{end}' | tee nodes.tsv
helm list -A -o json | jq -r '.[] | [.namespace, .name, .chart, .app_version, .status] | @tsv' | tee helm-releases.tsv
kubectl get crds -o name | grep -E 'metal3|cluster.x-k8s.io|rke2|turtles' | sort > capi-crds.txt; wc -l < capi-crds.txt
kubectl get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}{"\t"}{range .spec.containers[*]}{.image}{" "}{end}{"\n"}{end}' \
  | grep -E 'capi|capm3|rke2-bootstrap|rke2-control-plane|turtles|metal3' | sort -u | tee capi-controllers.tsv
```

Observed, 2026-10-09:

```
management-cluster	v1.34.4+rke2r1	SUSE Linux Enterprise Server 16.0
cert-manager	cert-manager	cert-manager-v1.19.2	v1.19.2	deployed
cattle-fleet-system	fleet	fleet-108.0.3+up0.14.3	0.14.3	deployed
cattle-fleet-local-system	fleet-agent-local	fleet-agent-local-v0.0.0+s-dfbc90355965a055db28e012dee44ed27d8a676bab05578c0095ddf628771		deployed
cattle-fleet-system	fleet-crd	fleet-crd-108.0.3+up0.14.3	0.14.3	deployed
metal3-system	metal3	metal3-305.0.23+up0.13.1	0.13.0	deployed
cattle-system	rancher	rancher-2.13.3	v2.13.3	deployed
cattle-turtles-system	rancher-turtles	rancher-turtles-108.0.4+up0.25.4	0.25.4	deployed
cattle-turtles-system	rancher-turtles-providers	rancher-turtles-providers-305.0.5+up0.25.4	0.25.4	deployed
cattle-system	rancher-webhook	rancher-webhook-108.0.3+up0.9.3	0.9.3	deployed
kube-system	rke2-calico	rke2-calico-v3.31.300	v3.31.3	deployed
kube-system	rke2-calico-crd	rke2-calico-crd-v3.31.300		deployed
kube-system	rke2-coredns	rke2-coredns-1.45.201	1.13.1	deployed
kube-system	rke2-ingress-nginx	rke2-ingress-nginx-4.14.302	1.14.3	deployed
kube-system	rke2-metrics-server	rke2-metrics-server-3.13.007	0.8.0	deployed
kube-system	rke2-runtimeclasses	rke2-runtimeclasses-0.1.000	0.1.0	deployed
kube-system	rke2-snapshot-controller	rke2-snapshot-controller-4.2.001	v8.4.0	deployed
kube-system	rke2-snapshot-controller-crd	rke2-snapshot-controller-crd-4.2.001	v8.4.0	deployed
cattle-system	system-upgrade-controller	system-upgrade-controller-108.0.0	v0.17.0	deployed
41
capm3-system	registry.suse.com/rancher/cluster-api-provider-metal3:v1.10.4
cattle-capi-system	registry.rancher.com/rancher/cluster-api-controller:v1.10.6
cattle-turtles-system	registry.rancher.com/rancher/turtles:v0.25.4
metal3-ipam-system	registry.rancher.com/rancher/ip-address-manager:v1.10.4
metal3-system	registry.suse.com/edge/3.5/baremetal-operator:0.11.2.0
metal3-system	registry.suse.com/edge/3.5/ironic:32.0.0.1 registry.suse.com/edge/3.5/ironic:32.0.0.1 registry.suse.com/edge/3.5/ironic:32.0.0.1
rke2-bootstrap-system	registry.suse.com/rancher/cluster-api-provider-rke2-bootstrap:v0.21.1
rke2-control-plane-system	registry.suse.com/rancher/cluster-api-provider-rke2-controlplane:v0.21.1
```

The kubelet reports the OS as `SUSE Linux Enterprise Server 16.0`; the image's `os-release` says `SUSE Linux Micro 6.2` with `VERSION_ID="16.0"` (section 2.1). The three inventory files are for the reader of the SBOM (which chart, which controller, which CRDs); the packages come from the image scans below. The quickstart also installs MetalLB for the Ironic IP; the bench used a static Ironic IP without MetalLB, which is why no `metallb` release appears above. Whatever the choice, the running list below captures it.

### 3.2 Master image list: shipped and running

```bash
kubectl get pods -A -o jsonpath='{range .items[*]}{range .spec.containers[*]}{.image}{"\n"}{end}{range .spec.initContainers[*]}{.image}{"\n"}{end}{end}' \
  | sort -u > running-images.txt
kubectl get pods -A -o jsonpath='{range .items[*]}{range .status.containerStatuses[*]}{.imageID}{"\n"}{end}{range .status.initContainerStatuses[*]}{.imageID}{"\n"}{end}{end}' \
  | sort -u > running-image-digests.txt
cat running-images.txt eib-embedded-images.txt eib-rke2-bundle-images.txt \
  | grep -v '^#' | sed -E 's#^(index\.)?docker\.io/##' | sort -u > all-images.txt
wc -l running-images.txt all-images.txt
```

The `sed` strips the `docker.io/` and `index.docker.io/` prefixes, which the bundles and the kubelet write differently for the same image; without it the same image is scanned twice under two names and gets two roots in the global SBOM.

Observed, 2026-10-09, management cluster: 35 running images (list in appendix A); `all-images.txt` and `running-image-digests.txt` were added afterwards, and on that cluster the shipped set counts 52 images (35 running, `cert-manager-startupapicheck`, 6 core and 10 calico images not running). Observed, 2026-10-12, downstream cluster: 12 running images, nothing embedded, `all-images.txt` of 12 lines (appendix A).

Replayed on 2026-10-12 from an empty directory: 35 running images on the management cluster again, but three of them differ from 2026-10-09 (`turtles:v0.25.4` replaced by `v0.25.8` by a Rancher system-chart upgrade one hour after the first scan, a `rancher-agent` pod of a Rancher CronJob alive at scan time, the one-off `shell` pod gone), and 53 shipped images in `all-images.txt` (54 lines with the `hauler` entry of section 2.2). A running list is a snapshot: CronJob pods and system-chart upgrades move it between two runs, which is why the shipped set and the digests are recorded next to it (section 9, item 9).

### 3.3 Scan every image

```bash
while IFS= read -r IMG; do
  SAFE=$(printf '%s' "$IMG" | tr '/:@' '___')
  "$SYFT" -q "registry:${IMG}" --source-supplier SUSE -o spdx-json > "images/sbom-${SAFE}.spdx.json" < /dev/null
  printf '%6s  %s\n' "$(jq '.packages | length' "images/sbom-${SAFE}.spdx.json")" "$IMG"
done < all-images.txt
```

`registry:` pulls from the registry without a container engine; an image name without a registry (`rancher/klipper-helm:...`) resolves to `docker.io`. Observed, 2026-10-09, on the 35 running images of the management cluster, and on 2026-10-12 on the 12 images of the downstream cluster: every scan returned a non-empty SBOM; the counts per image are in appendix A (from 6 packages for `mirrored-calico-pod2daemon-flexvol` to 2025 for `rancher`).

On an air-gapped host, scan the images embedded by EIB from their archive instead of the registry:

```bash
F="$BUILD/artefacts/registry/$(printf '%s' "$IMG" | tr '/' '_')-registry.tar.zst"
zstd -dc "$F" > "$WORK/image.oci.tar"
"$SYFT" -q oci-archive:"$WORK/image.oci.tar" --source-name "${IMG%%:*}" --source-version "${IMG##*:}" --source-supplier SUSE \
  -o spdx-json > "images/sbom-${SAFE}.spdx.json"
rm -f "$WORK/image.oci.tar"
```

Observed, 2026-10-12, on `ghcr.io/kube-vip/kube-vip:v0.8.0` from the downstream build: 97 packages, the same package list as the registry scan of the same tag; without `--source-name` the root is named after the tar file and its version is the manifest digest. The RKE2 bundles hold several images per archive: load them with `podman load` and scan each with `syft podman:<image>`. Not replayed.

## 4. Downstream cluster

The downstream cluster is created as in the quickstart (BareMetalHost, Cluster, RKE2ControlPlane, Metal3MachineTemplate, MachineDeployment). CAPI writes the kubeconfig of each cluster in the secret `<cluster>-kubeconfig` of the Cluster's namespace (`default` in the quickstart):

```bash
DS_CLUSTER=sample-cluster
DS_NS=default
export KUBECONFIG="$MGMT_KUBECONFIG"
kubectl -n "$DS_NS" get secret "${DS_CLUSTER}-kubeconfig" -o jsonpath='{.data.value}' | base64 -d > "$WORK/downstream/kubeconfig"
chmod 600 "$WORK/downstream/kubeconfig"
```

Then, in `$WORK/downstream`:

1. the OS of the downstream image: section 2.1 with `DS_RAW`;
2. the images embedded by the downstream build: section 2.2 with `EIB_DS_DIR`;
3. the inventories, the master list and the scans: sections 3.1 to 3.3 with `KUBECONFIG="$WORK/downstream/kubeconfig"`.

Observed, 2026-10-12, on the bench (one control-plane node and one worker, RKE2 `v1.34.4+rke2r1`, both with a `metal3://` provider ID): the secret decodes to a 5607-byte kubeconfig; `nodes.tsv` lists the two nodes; `helm-releases.tsv` lists the seven RKE2 releases (`rke2-canal` as CNI, coredns, ingress-nginx, metrics-server, runtimeclasses, snapshot-controller and its CRDs); `capi-crds.txt` and `capi-controllers.tsv` are empty, as expected on a downstream cluster; the OS SBOM of the downstream image counts 555 packages; the 12 running images are listed in appendix A. The first downstream build of the bench, made with the `metal3-demo` template, embedded `ghcr.io/kube-vip/kube-vip:v0.8.0` and the RKE2 bundles `core` and `cilium`; the image rebuilt as in the product definition embeds nothing (section 2.2).

## 5. Workload

The workload images are already in the downstream list of section 4. This section produces a separate SBOM of the workload alone, the one a customer extends and hands over for their own application. Same commands restricted to the workload namespaces:

```bash
export KUBECONFIG="$WORK/downstream/kubeconfig"
cd "$WORK/workload"
WL_NS=my-app
kubectl -n "$WL_NS" get pods -o jsonpath='{range .items[*]}{range .spec.containers[*]}{.image}{"\n"}{end}{range .spec.initContainers[*]}{.image}{"\n"}{end}{end}' \
  | sed -E 's#^(index\.)?docker\.io/##' | sort -u > all-images.txt
```

Then the scan loop of section 3.3. The merge of section 6 accepts any subset of directories, so the workload SBOM can be merged alone or with the rest of the stack.

Observed, 2026-10-12: namespace `sample-workload`, deployment `web` with two replicas of `registry.suse.com/suse/nginx:1.27`, one pod per node; `all-images.txt` holds that one image and its scan returns 89 packages.

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

## 7. Validate

```bash
cd "$WORK"
time "$HOME/sbomval/bin/pyspdxtools" -i sbom-global.spdx.json; echo "pyspdxtools rc=$?"
"$HOME/sbomval/bin/ntia-checker" sbom-global.spdx.json; echo "ntia rc=$?"
```

Observed, 2026-10-09, on the management cluster SBOM above (validation run on a laptop; the 100 MB file takes `pyspdxtools` 41 min 43 s):

```
pyspdxtools rc=0
2021 NTIA SBOM Minimum Elements Conformance Results

Conformant: True

Requirement                                    | Status
-------------------------------------------------------
All component names provided?                  | True
All component versions provided?               | True
All component identifiers provided?            | True
All component suppliers provided?              | True
SBOM author name provided?                     | True
SBOM creation timestamp provided?              | True
Dependency relationships provided?             | True

ntia rc=0
```

Observed, 2026-10-12, on the whole-stack SBOM of section 6 (50 inputs, 9374 packages, 107 MB, same laptop): `pyspdxtools` rc=0 after 47 min 16 s, `ntia-checker` Conformant: True on the seven requirements, rc=0, same output as above. Observed the same day on the replayed document (69 inputs, 11409 packages, 112 MB): `pyspdxtools` rc=0 after 50 min 56 s, `ntia-checker` Conformant: True, rc=0.

`pyspdxtools` prints nothing when the document is valid and returns 0; errors are listed otherwise. `ntia-checker` is an offline check of the NTIA minimum elements, not a test of any given consumer tool; a SBOM platform may still reject a document that passes it.

## 8. Hand-over

Deliver, for each stack:

- `sbom-global.spdx.json` and its `.sha256`;
- the per-layer SBOMs: `mgmt/sbom-os.spdx.json`, `mgmt/images/*.spdx.json`, the same under `downstream/` and `workload/`;
- the inventories: `nodes.tsv`, `helm-releases.tsv`, `capi-crds.txt`, `capi-controllers.tsv`, `eib-charts.txt`, `all-images.txt`, `running-image-digests.txt`;
- `sbom-eib-tool.spdx.json`, apart, as build provenance;
- the tool versions (`syft version`, `"$HOME/sbomval/bin/pip" freeze`) and the output of section 7.

Before sharing, check that the document carries no host name or path of the build host, in its text or in the name of a root:

```bash
grep -c -F -e "$(hostname)" -e "/mnt/" -e "$HOME" sbom-global.spdx.json
jq -r '.packages[] | select(.SPDXID | test("DocumentRoot")) | .name' sbom-global.spdx.json | grep -c '^/'
```

Observed on the 2026-10-09 document and on the whole-stack document of section 6, both built from the management OS SBOM scanned without `--source-name`: 1 and 1, the OS root named `/mnt/m352-os`; its identifier `SPDXRef-DocumentRoot-Directory--mnt-m352-os` carries the path too and is repeated by the 556 relationships of that layer. `--source-name` of section 2.1 removes all of it. Observed on the replayed document of 2026-10-12: 0 and 0.

Checklist:

- [ ] one `sbom-os.spdx.json` per EIB image (management, downstream)
- [ ] `all-images.txt` = running images plus the images embedded by EIB, one `images/sbom-*.spdx.json` per line, none empty: `for f in */images/*.spdx.json; do [ "$(jq '.packages | length' "$f")" -gt 0 ] || echo "EMPTY $f"; done`
- [ ] `DESCRIBES` roots in the global document = number of distinct inputs (an image repeated across clusters counts once)
- [ ] `pyspdxtools` rc=0 and `ntia-checker` Conformant: True
- [ ] no host name or mount path of the build host in the global document

## 9. Deviations observed on the bench, and limitations

1. **Downstream image built with a `kubernetes:` section (bench deviation, blocks section 4).** The `metal3-demo` EIB template of the downstream image sets `kubernetes.version`, so EIB installs RKE2 at build time with its own `/etc/rancher/rke2/config.yaml`. The product definition of the downstream image (quickstart 3.5, section 1.4.4.1.1 `downstream-cluster-config.yaml`; telco guide 3.6, section 49.2.1) has no `kubernetes:` key: RKE2 is installed at first boot by the CAPI bootstrap (`rke2-install.service`), with the configuration that carries `provider-id=metal3://<BareMetalHost UUID>`. Observed on 2026-10-09: the node came up with providerID `rke2://<node name>`, the CAPM3 controller logged `could not find node with label: metal3.io/uuid=...` and the Machine stayed in `Provisioning`, although the BareMetalHost was `provisioned` and the node `Ready`. Replayed on 2026-10-12: the downstream image was rebuilt from the same definition without the `kubernetes:` section (build of 78 s, no embedded artefact), the control-plane Machine reached `Running` 3 min 49 s after `kubectl apply`, with the provider ID `metal3://<BareMetalHost UUID>`, and the worker 3 min 51 s after its manifest.
2. **Tags versus digests.** The lists carry tags; `running-image-digests.txt` records what actually ran. A re-run weeks later can scan a different image under the same tag: compare digests before comparing package lists.
3. **Chart tarballs are not an image source.** They carry upstream defaults (`quay.io/metal3-io/cluster-api-provider-metal3:main`); the bench runs `registry.suse.com/rancher/cluster-api-provider-metal3:v1.10.4`. The running list is the source.
4. **Licence coverage.** syft declares a licence for 554 of 555 RPM packages of the OS, and for about 5 of 100 packages of the Go-based controller images. Numbers per image in part 2.
5. **ISO-based management image.** See section 2.1; not replayed.
6. **No package list file from EIB 1.3.3.** Checked on both builds of the bench; the RPM list comes from the mounted image.
7. **Reproducibility.** The merged document changes at every run (namespace, timestamp); compare the package lists reduced to name, version and purl, per layer, not the files.
8. **Control-plane endpoint without a VIP.** The quickstart assumes that the control-plane BareMetalHost owns the endpoint IP. On the bench the libvirt network reserves that IP for the control-plane node by DHCP; the `metal3-demo` template provided it with kube-vip, which the product definition does not include.
9. **The running list is a snapshot.** Between 2026-10-09 and 2026-10-12 the management cluster changed three of its 35 running images without any action on the bench: Rancher upgraded its `rancher-turtles` system chart from `108.0.4+up0.25.4` to `108.0.8+up0.25.8` one hour after the first scan (image `turtles:v0.25.8`), a Rancher CronJob (`rke2-machineconfig-cleanup-cronjob`, image `rancher-agent:v2.13.3`) had a pod alive at scan time, and the one-off `shell` pod was gone. The package lists of the 34 images present in both runs were identical, as was the OS layer: the method is stable, the system moves. Record the digests and date the document.
10. **Artefacts that are neither RPM packages nor container images are absent from the document.** Observed on the bench: the RKE2 distribution that EIB embeds in the management image (`artefacts/kubernetes/install/rke2.linux-amd64.tar.gz`, 38 MB, installed at first boot by `rke2_installer.sh`; its binaries are not in the RPM database read in section 2.1), and the Ironic Python Agent kernel and initramfs that the `ironic` pod serves to the hosts during inspection and provisioning (`/shared/html/images/ironic-python-agent_x86_64.initramfs`, 535 MB, unpacked by the `ironic-ipa-downloader` init container; the SBOM of that image lists its RPMs, not the content of the initramfs). Neither was scanned: the tarball can be given to syft as an archive, the initramfs has to be unpacked first; not tested.

## Appendix A: observed values, Edge 3.5.2 management cluster (2026-10-09, syft 1.42.3)

Running images and package count per image:

```
   183  docker.io/rancher/mirrored-calico-cni:v3.31.3
   144  docker.io/rancher/mirrored-calico-kube-controllers:v3.31.3
   214  docker.io/rancher/mirrored-calico-node:v3.31.3
   161  docker.io/rancher/mirrored-calico-operator:v1.40.3
     6  docker.io/rancher/mirrored-calico-pod2daemon-flexvol:v3.31.3
    87  docker.io/rancher/mirrored-calico-typha:v3.31.3
    98  index.docker.io/rancher/hardened-etcd:v3.6.7-k3s1-build20260126
   876  index.docker.io/rancher/hardened-kubernetes:v1.34.4-rke2r1-build20260210
   174  index.docker.io/rancher/rke2-cloud-provider:v1.34.4-0.20260211145917-c6017918a65c-build20260211
    77  quay.io/jetstack/cert-manager-cainjector:v1.19.2
   168  quay.io/jetstack/cert-manager-controller:v1.19.2
    97  quay.io/jetstack/cert-manager-webhook:v1.19.2
    47  rancher/hardened-cluster-autoscaler:v1.10.3-build20260206
   247  rancher/hardened-coredns:v1.14.1-build20260206
    98  rancher/hardened-k8s-metrics-server:v0.8.1-build20260206
    97  rancher/hardened-snapshot-controller:v8.4.0-build20260205
   363  rancher/klipper-helm:v0.9.14-build20260210
   296  rancher/nginx-ingress-controller:v1.14.3-hardened2
   106  registry.rancher.com/rancher/cluster-api-controller:v1.10.6
   213  registry.rancher.com/rancher/fleet-agent:v0.14.3
   504  registry.rancher.com/rancher/fleet:v0.14.3
    92  registry.rancher.com/rancher/ip-address-manager:v1.10.4
  2025  registry.rancher.com/rancher/rancher:v2.13.3
   113  registry.rancher.com/rancher/rancher-webhook:v0.9.3
    82  registry.rancher.com/rancher/scc-operator:v0.3.1
   698  registry.rancher.com/rancher/shell:v0.6.2
    68  registry.rancher.com/rancher/system-upgrade-controller:v0.17.0
   124  registry.rancher.com/rancher/turtles:v0.25.4
   182  registry.suse.com/edge/3.5/baremetal-operator:0.11.2.0
   683  registry.suse.com/edge/3.5/ironic:32.0.0.1
    71  registry.suse.com/edge/3.5/ironic-ipa-downloader:3.0.11
   179  registry.suse.com/rancher/cluster-api-addon-provider-fleet:v0.12.0
    99  registry.suse.com/rancher/cluster-api-provider-metal3:v1.10.4
   114  registry.suse.com/rancher/cluster-api-provider-rke2-bootstrap:v0.21.1
   114  registry.suse.com/rancher/cluster-api-provider-rke2-controlplane:v0.21.1
```

Running images of the downstream cluster (2026-10-12, one control-plane node, one worker, workload included) and package count per image:

```
   885  rancher/hardened-calico:v3.31.3-build20260206
    47  rancher/hardened-cluster-autoscaler:v1.10.3-build20260206
   247  rancher/hardened-coredns:v1.14.1-build20260206
    98  rancher/hardened-etcd:v3.6.7-k3s1-build20260126
   140  rancher/hardened-flannel:v0.28.1-build20260206
    98  rancher/hardened-k8s-metrics-server:v0.8.1-build20260206
   876  rancher/hardened-kubernetes:v1.34.4-rke2r1-build20260210
    97  rancher/hardened-snapshot-controller:v8.4.0-build20260205
   363  rancher/klipper-helm:v0.9.14-build20260210
   296  rancher/nginx-ingress-controller:v1.14.3-hardened2
   174  rancher/rke2-cloud-provider:v1.34.4-0.20260211145917-c6017918a65c-build20260211
    89  registry.suse.com/suse/nginx:1.27
```

Components, as deployed:

| Layer | Component | Observed value |
|---|---|---|
| OS | SUSE Linux Micro | 6.2 (`VERSION_ID="16.0"`), 555 RPM packages in the management image |
| Build tool | EIB | `registry.suse.com/edge/3.5/edge-image-builder:1.3.3`, 1584 packages |
| Kubernetes | RKE2 | `v1.34.4+rke2r1`, CNI calico `v3.31.3` |
| Charts | cert-manager, metal3, rancher, rancher-turtles, rancher-turtles-providers | `v1.19.2`, `305.0.23+up0.13.1`, `2.13.3`, `108.0.4+up0.25.4`, `305.0.5+up0.25.4` |
| Metal3 | baremetal-operator, ironic, ironic-ipa-downloader | `0.11.2.0`, `32.0.0.1`, `3.0.11` (`registry.suse.com/edge/3.5/`) |
| CAPI | cluster-api-controller, turtles, addon-provider-fleet | `v1.10.6`, `v0.25.4`, `v0.12.0` |
| CAPI providers | cluster-api-provider-metal3, ip-address-manager, rke2-bootstrap, rke2-controlplane | `v1.10.4`, `v1.10.4`, `v0.21.1`, `v0.21.1` |
