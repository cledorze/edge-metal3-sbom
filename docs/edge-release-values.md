# Scenario 6 for Edge 3.5 and Edge 3.6

[Scenario 6](runbook.md) describes the full SBOM collection for a Metal3/CAPI
stack; its commands and example outputs carry the Edge 3.5.2 values observed on its bench. This page
gives the values of Edge 3.5.2 and Edge 3.6.1 side by side, and the places where the release notes
and the registry disagree. Every step of scenario 6 not listed here applies unchanged.

Sources, read on 2026-09-23:

- [SUSE Edge 3.5 release notes](https://documentation.suse.com/suse-edge/3.5/html/edge/release-notes.html), section "Release 3.5.2", "Component Versions"
- [SUSE Edge 3.6 release notes](https://documentation.suse.com/suse-edge/3.6/html/edge/release-notes.html), section 41.3 "Release 3.6.1", 41.3.4 "Component Versions"
- The charts themselves, pulled from `oci://registry.suse.com/edge/charts/` (image references read from the chart values)

Evidence legend: **registry** = manifest HEAD returned 200 on 2026-09-23 (anonymous SCC token);
**chart** = read from the chart tarball; **notes** = read from the release notes only;
**bench** = observed on the Edge 3.5.2 management cluster of the scenario 6 bench on 2026-10-09.
The 3.5.2 column was replayed on that bench (management cluster on 2026-10-09, downstream cluster
on 2026-10-12); the 3.6.1 column has not been run on a bench.

## Version matrix

| Layer | Component | Edge 3.5.2 | Edge 3.6.1 | Evidence |
|---|---|---|---|---|
| 1 | SUSE Linux Micro | 6.2 | 6.2 | notes |
| 2 | EIB image | `registry.suse.com/edge/3.5/edge-image-builder:1.3.3` | `registry.suse.com/edge/3.6/edge-image-builder:1.3.3.1` | registry, bench |
| 3 | RKE2 | v1.34.4+rke2r1 | v1.35.4+rke2r1 | notes, bench (`v1.34.4+rke2r1` observed) |
| 4 | cert-manager chart | not in the 3.5.2 table (1.19.2 deployed) | 1.20.1 | notes, bench |
| 4 | Rancher Prime chart | 2.13.3 | 2.14.2 | notes, bench |
| 4 | Metal3 chart | 305.0.23+up0.13.1 | 306.0.29+up0.15.0 | registry, bench |
| 4 | MetalLB chart | 305.0.1+up0.15.2 | 306.0.2+up0.15.3 | registry |
| 4 | rancher-turtles-providers chart | 305.0.5+up0.25.4 | 306.0.7+up0.26.2 | registry, bench |
| 4 | Elemental operator chart | 1.8.1 | 1.9.0 | registry |
| 5 | baremetal-operator | `edge/3.5/baremetal-operator:0.11.2.0` | `edge/3.6/baremetal-operator:0.12.3.0` | registry, bench |
| 5 | ironic | `edge/3.5/ironic:32.0.0.1` | `edge/3.6/ironic:35.0.0.2` | registry, bench |
| 5 | ironic-ipa-downloader | `edge/3.5/ironic-ipa-downloader:3.0.11` | `edge/3.6/ironic-ipa-downloader:3.1.1` | registry, bench |
| 5 | ironic-python-agent | not shipped | `edge/3.6/ironic-python-agent:3.0.9` | registry |
| 5 | mariadb | `suse/mariadb:10.11` | `suse/mariadb:10.11` | chart + registry; no mariadb pod on the bench |
| 6 | CAPI RKE2 bootstrap / control plane | v0.21.1 | v0.24.4 (chart) / v0.24.3 (notes) | chart, bench (3.5.2); see below |
| 6 | CAPM3 controller | `rancher/cluster-api-provider-metal3:v1.10.4` | `rancher/cluster-api-provider-metal3:v1.12.3` | chart (3.5 also registry), bench |
| 6 | IPAM controller | `registry.rancher.com/rancher/ip-address-manager:v1.10.4` | `rancher/ip-address-manager:v1.12.3` | chart, bench (3.5.2 runs it from `registry.rancher.com`) |
| 6 | CAPI add-on provider Fleet | v0.12.0 | v0.14.1 | chart, bench |

Unqualified image paths are on `registry.suse.com`.

## Variables per release

Set these once, then run the commands of scenario 6 with the variables in place of the literal
versions.

```bash
# Edge 3.5.2
EDGE_VERSION=3.5
EIB_IMAGE=registry.suse.com/edge/3.5/edge-image-builder:1.3.3
RKE2_VERSION=v1.34.4+rke2r1
METAL3_CHART=305.0.23+up0.13.1
TURTLES_PROVIDERS_CHART=305.0.5+up0.25.4
SLMICRO_VERSION=6.2
```

```bash
# Edge 3.6.1
EDGE_VERSION=3.6
EIB_IMAGE=registry.suse.com/edge/3.6/edge-image-builder:1.3.3.1
RKE2_VERSION=v1.35.4+rke2r1
METAL3_CHART=306.0.29+up0.15.0
TURTLES_PROVIDERS_CHART=306.0.7+up0.26.2
SLMICRO_VERSION=6.2
```

`examples/collect-metal3-sbom.sh` reads `EDGE_VERSION` (default `3.5`) to pick the EIB image of
Layer 2. `EIB_CONTAINER_IMAGE` still overrides it.

## Changes per layer

### Layer 1 / Base OS

Both releases ship SL Micro 6.2, so the OVAL feed is the same file for both:
`https://ftp.suse.com/pub/projects/security/oval/suse.linux.micro.6.2-patch.xml.bz2` (HTTP 200 on
2026-09-23). The Grype/Trivy blind spot on SL Micro 6.x RPMs applies to both releases.

### Layer 2 / EIB tool image

```bash
syft "registry:${EIB_IMAGE}" --source-supplier SUSE -o spdx-json > "sbom-eib-tool-${EDGE_VERSION}.spdx.json"
```

The tag listing of 2026-09-23 showed no `sha256-<digest>.att` or `.sbom` tag for the images of the
matrix. On 2026-10-12, `cosign verify-attestation --type spdxjson` did find an attestation on
`edge/3.5/ironic:32.0.0.1` and `edge/3.5/baremetal-operator:0.11.2.0` (none on
`rancher/cluster-api-provider-metal3:v1.10.4`; the EIB images were not tested), signed with a key
that matches none of the three keys shipped under `/usr/share/pki/containers/`; the same command
and the SLE key verify `registry.suse.com/suse/sle15:15.4`. Use the syft output until the signing
key of the Edge images is known.

### Layer 3 / RKE2

```bash
curl -sSL "https://github.com/rancher/rke2/releases/download/${RKE2_VERSION/+/%2B}/rke2-images-all.linux-amd64.txt"
```

Both lists answer and count 67 lines each (checked from the NUE Lab jumpbox on 2026-09-23).

### Layer 4 / Helm charts

Pull the charts from `oci://registry.suse.com/edge/charts/<name>`, for both releases:

```bash
helm pull oci://registry.suse.com/edge/charts/metal3 --version "${METAL3_CHART}"
helm pull oci://registry.suse.com/edge/charts/rancher-turtles-providers --version "${TURTLES_PROVIDERS_CHART}"
```

Two traps, both observed on 2026-09-23:

1. **Tag separator.** OCI tags cannot contain `+`. Helm converts `+` to `_` on push and pull, so
   `helm pull --version 306.0.29+up0.15.0` works, but a direct registry or `crane` query must use
   `306.0.29_up0.15.0`.
2. **3.6.1 chart paths in the release notes.** The notes give
   `registry.suse.com/edge/3.6/metal3-chart`, `edge/3.6/metallb-chart` and
   `edge/3.6/rancher-turtles-providers-chart`. All three return 404, with `+` or `_`. The same
   tags answer 200 under `edge/charts/metal3`, `edge/charts/metallb` and
   `edge/charts/rancher-turtles-providers`.

### Layer 5 / Container images

- **ironic-python-agent** is a new image in 3.6. Add it to the master image list.
- **mariadb**: the 3.5.2 release notes list `registry.suse.com/edge/mariadb:10.11`, which returns
  404 (that repository only holds `10.6.15.1`). The Metal3 chart of both releases references
  `registry.suse.com/suse/mariadb:10.11`, which returns 200. Scan the chart reference.
- The Metal3 charts also carry `registry.opensuse.org/isv/suse/edge/...` references (build
  defaults). Take the image list from the running cluster or from the rendered manifest, not from
  a plain grep of the tarball.

### Layer 6 / CAPI controllers

- **3.5.2, CAPM3.** The release notes list
  `registry.rancher.com/rancher/cluster-api-metal3-controller:v1.10.4` and
  `.../cluster-api-metal3-ipam-controller:v1.10.4`. Both return 404 on `registry.rancher.com` and on
  `registry.suse.com` (the rancher.com repository stops at `v1.8.2`). The chart
  `305.0.5+up0.25.4` deploys `registry.suse.com/rancher/cluster-api-provider-metal3:v1.10.4`
  (200) and `registry.rancher.com/rancher/ip-address-manager:v1.10.4`. Scan what the chart deploys.
- **3.6.1, RKE2 providers.** The release notes give `cluster-api-provider-rke2-*:v0.24.3`
  (registry 200). The values of chart `306.0.7+up0.26.2` set `v0.24.4`. Which one runs has to be
  read on a cluster: `kubectl get pods -A -o jsonpath=...` as in scenario 6, Layer 6.
- Both charts still carry `quay.io/metal3-io/cluster-api-provider-metal3:main` as an upstream
  default. The same caveat as Layer 5 applies.

## Open points

- The 3.5.2 management cluster ran on the scenario 6 bench on 2026-10-09 and its downstream cluster
  on 2026-10-12 (rows marked **bench**); the 3.6.1 column has not been run on a bench.
- The Edge 3.5 quickstart page read on 2026-10-12 shows `registry.suse.com/edge/3.5/edge-image-builder:1.3.3.1`
  and RKE2 `v1.34.7+rke2r1`, a later 3.5 z-release than 3.5.2; this page stays on 3.5.2.
- The management cluster of the bench also runs `registry.rancher.com/rancher/cluster-api-controller:v1.10.6`
  and `registry.rancher.com/rancher/turtles:v0.25.4`, which the release notes do not list.
- The RKE2 provider version actually deployed by 3.6.1 (v0.24.3 or v0.24.4).
- The 3.6.1 chart paths and the 3.5.2 mariadb and CAPM3 references are release-note defects to
  report to the Edge docs team.
