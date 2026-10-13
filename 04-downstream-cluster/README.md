# Step 4: downstream cluster

Script: `bash 04-downstream-cluster/downstream-cluster.sh` writes the downstream kubeconfig, then calls the scripts of steps 2 and 3 with the downstream image, EIB directory and kubeconfig, into `$WORK/downstream`.
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

