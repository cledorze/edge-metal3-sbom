# Full SBOM of a SUSE Edge Metal3/CAPI stack

One SPDX 2.3 document for a whole Metal3/CAPI deployment, from the Edge Image Builder (EIB) images to the
workloads of the downstream clusters, merged from one SBOM per layer and validated with standard tools
(`pyspdxtools` for SPDX validity, `ntia-checker` for the NTIA minimum elements).

Replayed on SUSE Edge 3.5.2 (management cluster on 2026-10-09, downstream cluster and workload on
2026-10-12, whole page from an empty directory on 2026-10-12). The Edge 3.6.1 values are listed but
have not been run on a bench.

## Layout

| Directory | Content |
|---|---|
| [`docs/runbook.md`](docs/runbook.md) | The procedure: prerequisites, build-time layers, management cluster, downstream cluster, workload, merge, validation, hand-over, deviations observed on the bench. Every example output is marked **Observed** with its date, or **Not replayed**. |
| [`docs/edge-release-values.md`](docs/edge-release-values.md) | Edge 3.5.2 and 3.6.1 values side by side (EIB, RKE2, charts, images), with the evidence of each value. |
| [`docs/analysis-cve-licences-signing.md`](docs/analysis-cve-licences-signing.md) | What to do with the SBOM: CVEs against the SUSE OVAL feeds, licences per layer, drift, air-gap, cosign attestations. Nothing there is needed to produce the SBOM. |
| [`docs/cve-databases-comparison.md`](docs/cve-databases-comparison.md) | Why Grype and Trivy are silent on SL Micro 6.x and SLES 16 RPMs, and which feeds are authoritative. |
| [`scripts/run-scenario-6.sh`](scripts/run-scenario-6.sh) | Sections 2 to 6 and 8 of the runbook in one script, variables of section 1 in the environment. |
| [`scripts/collect-metal3-sbom.sh`](scripts/collect-metal3-sbom.sh) | Older per-layer collector (OS, EIB, RKE2 bundles, charts, images, CAPI) that reads a `metal3-demo` working directory; it redacts the SCC registration code of the rendered EIB definition. Kept for the index it produces; the merged document comes from the runbook. |
| [`tests/`](tests/README.md) | One script per check of the runbook (SPDX validity, NTIA conformance, no empty input, roots = inputs, no build-host path) plus a negative control of the validators. `bash tests/run-all.sh WORK` runs them. |
| [`examples/edge-3.5.2-bench-2026-10-12/`](examples/edge-3.5.2-bench-2026-10-12/README.md) | Outputs of the three bench runs: logs, validation logs, inventories, scripts as run, four sample per-image SBOMs, package counts of all 126 SBOMs, checksums of the two global documents. |

## Quick start

On the build host (where EIB built the images and where the management kubeconfig is):

```bash
# tools (runbook, section 1)
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b "$HOME/.local/bin" v1.42.3
python3 -m venv "$HOME/sbomval"
"$HOME/sbomval/bin/pip" install -q spdx-tools==0.8.5 ntia-conformance-checker==6.0.0
sudo zypper -n in jq zstd

# variables (runbook, section 1): adapt the paths to your deployment
export EDGE_VERSION=3.5.2
export EIB_IMAGE=registry.suse.com/edge/3.5/edge-image-builder:1.3.3
export EIB_MGMT_DIR="$HOME/eib/mgmt"
export EIB_DS_DIR="$HOME/eib/metal3"
export MGMT_RAW="$EIB_MGMT_DIR/SL-Micro.x86_64-6.2-Base-GM.mgmt.raw"
export DS_RAW="$EIB_DS_DIR/SL-Micro.x86_64-6.2-Base-GM.metal3.raw"
export MGMT_KUBECONFIG="$HOME/.kube/mgmt.config"
export WORK="$HOME/metal3-sbom"
export DS_CLUSTER=sample-cluster DS_NS=default WL_NS=my-app

# produce (sections 2 to 6 and 8), then validate (section 7 and the hand-over checklist)
bash scripts/run-scenario-6.sh 2>&1 | tee "$WORK.log"
bash tests/run-all.sh "$WORK"
```

The result is `$WORK/sbom-global.spdx.json` with its `.sha256`, the per-layer SBOMs under
`$WORK/{mgmt,downstream,workload}/`, the inventories next to them, and `$WORK/sbom-eib-tool.spdx.json`
kept apart as build provenance. Section 8 of the runbook lists what to hand over.

## Figures observed on the Edge 3.5.2 bench

| Document | Inputs | Packages | Roots | Size | `pyspdxtools` | `ntia-checker` |
|---|---|---|---|---|---|---|
| management cluster, 2026-10-09 | 36 | 8482 | 36 | 100 MB | rc=0, 41 min 43 s | Conformant: True |
| whole stack, 2026-10-12 | 50 | 9374 | 43 | 107 MB | rc=0, 47 min 16 s | Conformant: True |
| replay from an empty directory, 2026-10-12 | 69 | 11409 | 58 | 112 MB | rc=0, 50 min 56 s | Conformant: True |

Package counts depend on the syft version (1.42.3 here); do not compare them with documents produced by
another version.

## Known limitations

From section 9 of the runbook: the running image list is a snapshot (CronJob pods and Rancher system-chart
upgrades move it between two runs; record the digests and date the document); the merged document
changes at every run (namespace, timestamp), compare package lists, not files; artefacts that are neither
RPM packages nor container images (the RKE2 tarball embedded by EIB, the Ironic Python Agent kernel and
initramfs served by the `ironic` pod) are not in the document; an ISO-based management image has no
partition to mount, scan the installed node instead (not replayed).

## Provenance

Extracted from the scenario 6 pages of a private presales repository, as replayed on the Edge 3.5.2 bench
between 2026-10-09 and 2026-10-12. The product references are the
[SUSE Edge 3.5 Metal3 quickstart](https://documentation.suse.com/suse-edge/3.5/html/edge/quickstart-metal3.html)
and [SUSE Linux Enterprise and SBOM support](https://www.suse.com/support/security/sbom/).
