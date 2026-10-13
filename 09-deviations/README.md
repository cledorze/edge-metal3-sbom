# Step 9: deviations observed on the bench, limitations, observed values

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
