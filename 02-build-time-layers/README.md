# Step 2: build-time layers

Script: `bash 02-build-time-layers/build-time-layers.sh` runs 2.1, 2.2 and 2.3 on the management image into `$WORK/mgmt`; with `RAW EIB_DIR OUT` as arguments it runs 2.1 and 2.2 on another image (step 4).
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

