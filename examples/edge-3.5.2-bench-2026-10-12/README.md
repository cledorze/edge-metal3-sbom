# Example outputs: Edge 3.5.2 Metal3/CAPI bench, 2026-10-09 and 2026-10-12

Outputs of the runbook on a libvirt bench built with the `metal3-demo` playbooks of the suse-edge
project: one management VM (RKE2 `v1.34.4+rke2r1`, Rancher 2.13.3, Metal3 chart `305.0.23+up0.13.1`,
rancher-turtles-providers `305.0.5+up0.25.4`, cert-manager 1.19.2), one downstream cluster
`sample-cluster` (one control-plane node, one worker) provisioned by Metal3/CAPI, one workload
(`registry.suse.com/suse/nginx:1.27`, two replicas). syft 1.42.3. Validation on a laptop with
spdx-tools 0.8.5 and ntia-conformance-checker 6.0.0.

Three runs are recorded:

| Run | Date | Scope | Global SBOM |
|---|---|---|---|
| management cluster | 2026-10-09 | sections 2 and 3 | 36 inputs, 8482 packages, 36 roots (`logs/mgmt.log`) |
| whole stack | 2026-10-12 | sections 4 to 6 added to the 2026-10-09 management outputs | 50 inputs, 9374 packages, 43 roots, 107 MB, sha256 `3fa6ace3…` (`logs/downstream.log`, `logs/validate-full.log`) |
| replay from an empty directory | 2026-10-12, 15:27 to 15:33 | sections 2 to 6 and 8, blocks of the page | 69 inputs (one empty, the `hauler` binary of the EIB registry archive), 11409 packages, 58 roots, 112 MB, sha256 `4b89e56a…` (`logs/replay-20261012.log`, `logs/validate-replay.log`) |

The 2026-10-09 OS scan ran without `--source-name`; the 2026-10-12 replay has it (runbook section 2.1 and
8). The difference between 50 and 69 inputs is the shipped set of section 3.2 (images embedded by EIB
that were not running) and the three running images that moved between the two days (runbook section
9, item 9).

## Layout

- `logs/`: the script outputs and the two validation logs (`pyspdxtools` rc and time, `ntia-checker` table).
- `scripts-as-run/`: the three scripts exactly as executed on the bench, with the bench paths
  (`/var/lib/libvirt/images/metal3-edge352/...`, mount point `/mnt/m352-os`). `replay-20261012.sh` is
  the page from an empty directory; the two `m352-*` scripts are the first runs of 2026-10-09 and 2026-10-12.
- `mgmt/`, `downstream/`, `workload/`: the inventories of the whole-stack run (`nodes.tsv`,
  `helm-releases.tsv`, `capi-crds.txt`, `capi-controllers.tsv`, `eib-*.txt`, `running-images.txt`,
  `running-image-digests.txt`, `all-images.txt`). `mgmt/` is the 2026-10-09 layout
  (`MASTER-image-list.txt`, `rke2-images-all.txt`), before the page settled on `all-images.txt`.
- `replay-20261012/`: the same inventories for the replay, in the final layout of the page.
- `sbom-samples/`: four per-image SBOMs, small enough for git: the workload image (`nginx:1.27`, 89
  packages, the control file of the negative control of step 7), the smallest management
  image (`mirrored-calico-pod2daemon-flexvol`, 6 packages), and the pair of the offline scan of runbook
  section 3.3 (`kube-vip:v0.8.0` from the EIB registry archive and from the registry, 97 packages each,
  same package list).
- `package-counts.tsv`: package count and `DESCRIBES` roots of every SBOM of the three runs (126 files),
  computed with `jq` on the bench copy.
- `sbom-global.spdx.json.sha256` and `replay-20261012/sbom-global.spdx.json.sha256`: checksums of the
  two whole-stack documents.

## Not in the repository

- The global SBOMs (100 to 112 MB each), the OS SBOMs (15 MB each), the EIB tool SBOM (14 MB) and the
  other per-image SBOMs (up to 30 MB for `ironic`): 589 MB in all. They stay on the bench and on the
  laptop copy; `package-counts.tsv` carries their counts and the `.sha256` files their checksums.
- `downstream/kubeconfig`, written by runbook section 4: cluster credentials, excluded by `.gitignore`.
