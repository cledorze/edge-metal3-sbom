# Step 3: management cluster at runtime

Script: `bash 03-management-cluster/management-cluster.sh` runs 3.1 to 3.3 on the management cluster into `$WORK/mgmt`; with `KUBECONFIG OUT` as arguments it runs them on another cluster (step 4).
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

