# Full SBOM of a SUSE Edge Metal3/CAPI stack

**Question:** how to produce one complete SBOM of a Metal3/CAPI deployment, from the EIB images to the workloads of the downstream clusters, that a reader can validate with standard tools.

**Result:** one SPDX 2.3 document, `sbom-global.spdx.json`, merged from one SBOM per layer, that passes `pyspdxtools` (SPDX validity) and `ntia-checker` (NTIA minimum elements), plus the per-layer SBOMs and the inventories it was built from.

**Scope:** a stack built with Edge Image Builder (EIB) and provisioned with Metal3 and Cluster API (CAPI) as in the [Metal3 quickstart](https://documentation.suse.com/suse-edge/3.5/html/edge/quickstart-metal3.html): a management cluster (RKE2, Rancher, Metal3, CAPI providers) and the downstream clusters it provisions. Replayed on SUSE Edge 3.5.2; the Edge 3.6.1 values are listed in [analysis/edge-release-values.md](analysis/edge-release-values.md) and have not been run on a bench.

**Tools:** syft 1.42.3, jq, zstd, kubectl, helm, python3 with spdx-tools 0.8.5 and ntia-conformance-checker 6.0.0 for the validation.

## Steps, in the order of the collection

Each directory holds the section of the runbook as its README and the script that runs its commands. Every example output is marked **Observed** with its date, or **Not replayed**. Source the variables of step 1 once, then run the scripts in order on the build host.

| Step | Directory | Does | Script |
|---|---|---|---|
| 1 | [01-prerequisites](01-prerequisites/README.md) | tools and variables | `env.sh`, to source |
| 2 | [02-build-time-layers](02-build-time-layers/README.md) | OS packages of the EIB image, images embedded by EIB, EIB tool image kept apart | `build-time-layers.sh` |
| 3 | [03-management-cluster](03-management-cluster/README.md) | inventories, master image list, one SBOM per running image | `management-cluster.sh` |
| 4 | [04-downstream-cluster](04-downstream-cluster/README.md) | kubeconfig of the downstream cluster, then steps 2 and 3 on it | `downstream-cluster.sh` |
| 5 | [05-workload](05-workload/README.md) | the workload alone | `workload.sh` |
| 6 | [06-merge](06-merge/README.md) | one global SPDX document with its sha256 | `merge.sh` |
| 7 | [07-validate](07-validate/README.md) | SPDX validity, NTIA conformance, the hand-over checks | `validate.sh` |
| 8 | [08-hand-over](08-hand-over/README.md) | what to deliver | |
| 9 | [09-deviations](09-deviations/README.md) | deviations observed on the bench, limitations, observed values | |

```bash
source 01-prerequisites/env.sh
bash 02-build-time-layers/build-time-layers.sh
bash 03-management-cluster/management-cluster.sh
bash 04-downstream-cluster/downstream-cluster.sh
bash 05-workload/workload.sh
bash 06-merge/merge.sh
bash 07-validate/validate.sh
```

## Status on the Edge 3.5.2 bench

| Section | Replayed | Where and when |
|---|---|---|
| 2. Build-time layers | Yes | Edge 3.5.2 bench, 2026-10-09; offline scan of an embedded image on 2026-10-12 |
| 3. Management cluster at runtime | Yes | Edge 3.5.2 bench, 2026-10-09 |
| 4. Downstream cluster and 5. workload | Yes | Edge 3.5.2 bench, 2026-10-12, after the downstream image was rebuilt as in the product definition (step 9, item 1) |
| 6. Merge and 7. validation, management cluster alone | Yes | 2026-10-09: 36 inputs, 8482 packages, `pyspdxtools` rc=0, `ntia-checker` Conformant: True |
| 6. Merge and 7. validation, whole stack | Yes | 2026-10-12: 50 inputs, 9374 packages, 43 roots, 107 MB, `pyspdxtools` rc=0 in 47 min, `ntia-checker` Conformant: True |
| Replay of the whole page from an empty directory | Yes | 2026-10-12: 69 inputs, 11409 packages, 58 roots, 112 MB, `pyspdxtools` rc=0 in 51 min, `ntia-checker` Conformant: True |
| Edge 3.6.1 values | No | release notes and registry only |

The scripts of steps 2 to 7 carry the blocks of their README; the same sequence, with the bench paths, was run from an empty directory on 2026-10-12 ([examples/.../scripts-as-run/replay-20261012.sh](examples/edge-3.5.2-bench-2026-10-12/scripts-as-run/replay-20261012.sh)). The scripts as split here have not been run as such. Package counts depend on the syft version: do not compare them across versions.

## Other material

- [analysis/](analysis/): what to do with the SBOM (CVEs against the SUSE OVAL feeds, licences per layer, drift, air-gap, cosign attestations), the Edge 3.5.2 and 3.6.1 values side by side, and why Grype and Trivy are silent on SL Micro 6.x and SLES 16 RPMs. Nothing there is needed to produce the SBOM.
- [examples/edge-3.5.2-bench-2026-10-12/](examples/edge-3.5.2-bench-2026-10-12/README.md): outputs of the three bench runs (logs, validation logs, inventories, scripts as run, four sample per-image SBOMs, package counts of all 126 SBOMs, checksums of the two global documents). [examples/collect-metal3-sbom.sh](examples/collect-metal3-sbom.sh) is an older per-layer collector that produces an index, not a merged document.

Product references: [SUSE Edge 3.5 Metal3 quickstart](https://documentation.suse.com/suse-edge/3.5/html/edge/quickstart-metal3.html), [SUSE Linux Enterprise and SBOM support](https://www.suse.com/support/security/sbom/).
