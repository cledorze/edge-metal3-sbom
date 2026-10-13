#!/usr/bin/env bash
# collect-metal3-sbom.sh — Build-time SBOM collection for a Metal3/CAPI deployment
#
# Collects SBOMs from every layer of the SUSE Edge Metal3 stack:
#   Layer 1: Base OS image (RPM packages)
#   Layer 2: EIB tool + embedded container images
#   Layer 3: RKE2 distribution (bundled system images)
#   Layer 4: Helm charts (cert-manager, Metal3, Rancher, Turtles)
#   Layer 5: All container images (SPDX JSON per image)
#   Layer 6: CAPI controllers and CRDs
#
# Usage:
#   ./collect-metal3-sbom.sh <metal3-demo-working-dir>
#
# Example:
#   ./collect-metal3-sbom.sh ~/metal3-demo-files
#   EDGE_VERSION=3.6 ./collect-metal3-sbom.sh ~/metal3-demo-files
#
# Prerequisites: syft, jq, helm (optional), kubectl (optional)
# Install:  zypper in jq  &&  curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b ~/.local/bin

set -euo pipefail

# ---------------------------------------------------------------------------
# Arguments and setup
# ---------------------------------------------------------------------------
WORKING_DIR="${1:?Usage: $0 <metal3-demo-working-dir>}"
SBOM_DIR="${WORKING_DIR}/sbom"
TIMESTAMP=$(date -u +%Y%m%dT%H%M%SZ)

mkdir -p "${SBOM_DIR}"/{os,rke2,helm,containers,capi,aggregate}

echo "============================================================"
echo "  Metal3/CAPI SBOM Collection — ${TIMESTAMP}"
echo "  Working dir: ${WORKING_DIR}"
echo "  Output:      ${SBOM_DIR}"
echo "============================================================"

# ---------------------------------------------------------------------------
# Helper: check required tools
# ---------------------------------------------------------------------------
for tool in syft jq; do
  command -v "$tool" >/dev/null 2>&1 || { echo "ERROR: $tool not found in PATH"; exit 1; }
done

# Detect cluster availability once
CLUSTER_UP=false
if command -v kubectl >/dev/null 2>&1 && kubectl get nodes >/dev/null 2>&1; then
  CLUSTER_UP=true
fi

# ---------------------------------------------------------------------------
# Layer 1: Base OS image — RPM manifest from EIB build artefacts
# ---------------------------------------------------------------------------
echo ""
echo ">>> Layer 1: Base OS image (RPM packages)"

# EIB _build/ directory contains the RPM artefacts and combustion scripts
OS_RPMS_FOUND=false
for build_dir in "${WORKING_DIR}"/eib/*/_build/build-*/; do
  [ -d "${build_dir}" ] || continue
  img_type=$(basename "$(dirname "$(dirname "${build_dir}")")")

  # Check for RPM repo metadata (lists packages EIB installed)
  rpm_repo="${build_dir}/artefacts/rpms/rpm-repo"
  if [ -d "${rpm_repo}" ]; then
    echo "  Found RPM artefacts for: ${img_type}"
    cp -r "${rpm_repo}" "${SBOM_DIR}/os/${img_type}-rpm-repo" 2>/dev/null || true
    OS_RPMS_FOUND=true
  fi

  # Copy the build log (contains full EIB output including package list)
  if [ -f "${build_dir}/eib-build.log" ]; then
    cp "${build_dir}/eib-build.log" "${SBOM_DIR}/os/${img_type}-eib-build.log"
    echo "  Captured build log: ${img_type}"
  fi
done

# Also look for .packages files (some EIB versions produce them)
PACKAGES_FILES=$(find "${WORKING_DIR}/eib" -name "*.packages" -type f 2>/dev/null || true)
if [ -n "${PACKAGES_FILES}" ]; then
  for pkg_file in ${PACKAGES_FILES}; do
    fname=$(basename "${pkg_file}")
    cp "${pkg_file}" "${SBOM_DIR}/os/${fname}"
    echo "  Copied: ${fname} ($(wc -l < "${pkg_file}" | tr -d ' ') packages)"
    OS_RPMS_FOUND=true
  done
fi

if [ "${OS_RPMS_FOUND}" = false ]; then
  echo "  WARN: No RPM artefacts found. To get OS SBOM, mount the raw image:"
  echo "        sudo losetup -fP image.raw && sudo mount /dev/loop0p3 /mnt"
  echo "        syft dir:/mnt --catalogers rpm-db -o spdx-json > sbom-os.spdx.json"
fi

# Capture EIB configs for traceability.
# The rendered definition carries the SCC registration code (sccRegistrationCode) and password
# hashes: redact them, the SBOM output directory is meant to be handed over.
for cfg in "${WORKING_DIR}"/eib/mgmt/config-eib.yaml "${WORKING_DIR}"/eib/metal3/config-eib.yaml; do
  [ -f "${cfg}" ] || continue
  img_type=$(basename "$(dirname "${cfg}")")
  sed -E 's/^([[:space:]]*(sccRegistrationCode|encryptedPassword):).*/\1 REDACTED/' "${cfg}" \
    > "${SBOM_DIR}/os/${img_type}-eib-config.yaml"
  echo "  Captured EIB config (secrets redacted): ${img_type}"
done

# ---------------------------------------------------------------------------
# Layer 2: EIB tool image + embedded container images from build
# ---------------------------------------------------------------------------
echo ""
echo ">>> Layer 2: EIB tool + embedded container images"

# Detect EIB image from podman history or metal3-demo defaults
# The EIB config does NOT contain the tool image ref — it's in the Ansible role defaults
# EDGE_VERSION picks the EIB image of the latest z-release (see
# scenarios/06-full-sbom-metal3-stack-edge35-edge36.md). EIB_CONTAINER_IMAGE wins.
EDGE_VERSION="${EDGE_VERSION:-3.5}"
case "${EDGE_VERSION}" in
  3.5) EIB_DEFAULT="registry.suse.com/edge/3.5/edge-image-builder:1.3.3" ;;
  3.6) EIB_DEFAULT="registry.suse.com/edge/3.6/edge-image-builder:1.3.3.1" ;;
  *) echo "ERROR: EDGE_VERSION must be 3.5 or 3.6 (got ${EDGE_VERSION})"; exit 1 ;;
esac
EIB_IMAGE="${EIB_CONTAINER_IMAGE:-${EIB_DEFAULT}}"

SAFE=$(echo "${EIB_IMAGE}" | tr '/:@' '___')
echo "  Scanning EIB tool: ${EIB_IMAGE}..."
syft "registry:${EIB_IMAGE}" -o spdx-json="${SBOM_DIR}/containers/sbom-${SAFE}.spdx.json" -q 2>/dev/null && \
  echo "  OK" || echo "  WARN: Could not pull ${EIB_IMAGE}"

# Extract embedded container images from EIB build artefacts (hauler/registry tarballs)
echo "  Extracting embedded image list from build artefacts..."
EMBEDDED_IMAGES="${SBOM_DIR}/containers/embedded-images-from-build.txt"
> "${EMBEDDED_IMAGES}"
find "${WORKING_DIR}/eib" -path "*/artefacts/registry/*" -name "*.tar.zst" 2>/dev/null | while read -r tarball; do
  # Filename format: registry_image_name:tag-registry.tar.zst
  img_ref=$(basename "${tarball}" | sed 's/-registry\.tar\.zst$//' | tr '_' '/')
  echo "${img_ref}" >> "${EMBEDDED_IMAGES}"
done
# Also check for RKE2 images
find "${WORKING_DIR}/eib" -path "*/artefacts/kubernetes/images/*" -name "*.tar.zst" 2>/dev/null | while read -r tarball; do
  echo "rke2-bundle:$(basename "${tarball}")" >> "${EMBEDDED_IMAGES}"
done

if [ -s "${EMBEDDED_IMAGES}" ]; then
  echo "  Embedded images found: $(wc -l < "${EMBEDDED_IMAGES}" | tr -d ' ')"
  cat "${EMBEDDED_IMAGES}"
else
  echo "  No embedded image artefacts found"
fi

# ---------------------------------------------------------------------------
# Layer 3: RKE2 distribution
# ---------------------------------------------------------------------------
echo ""
echo ">>> Layer 3: RKE2 distribution"

RKE2_VERSION=$(grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+\+rke2r[0-9]+' "${WORKING_DIR}"/eib/mgmt/config-eib.yaml 2>/dev/null | head -1 || echo "unknown")
echo "  RKE2 version: ${RKE2_VERSION}"
echo "${RKE2_VERSION}" > "${SBOM_DIR}/rke2/rke2-version.txt"

if [ "${CLUSTER_UP}" = true ]; then
  echo "  Cluster reachable — extracting live image list..."
  kubectl get pods -A -o jsonpath='{range .items[*]}{range .spec.containers[*]}{.image}{"\n"}{end}{range .spec.initContainers[*]}{.image}{"\n"}{end}{end}' \
    | sort -u > "${SBOM_DIR}/rke2/cluster-running-images.txt"
  echo "  Running images: $(wc -l < "${SBOM_DIR}/rke2/cluster-running-images.txt" | tr -d ' ')"

  kubectl get pods -n kube-system -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{range .spec.containers[*]}{.image}{"\n"}{end}{end}' \
    > "${SBOM_DIR}/rke2/rke2-system-pods.txt"
else
  echo "  Cluster not reachable — using EIB build artefacts"
fi

# ---------------------------------------------------------------------------
# Layer 4: Helm charts
# ---------------------------------------------------------------------------
echo ""
echo ">>> Layer 4: Helm charts"

if [ "${CLUSTER_UP}" = true ] && command -v helm >/dev/null 2>&1; then
  helm list -A -o json 2>/dev/null | jq -r '.[] | select(.status=="deployed") | "\(.namespace)\t\(.name)\t\(.chart)\t\(.app_version)"' \
    > "${SBOM_DIR}/helm/helm-releases.txt"
  echo "  Deployed releases: $(wc -l < "${SBOM_DIR}/helm/helm-releases.txt" | tr -d ' ')"

  ALL_HELM_IMAGES="${SBOM_DIR}/helm/all-helm-images.txt"
  > "${ALL_HELM_IMAGES}"

  for NS_RELEASE in $(helm list -A -o json 2>/dev/null | jq -r '.[] | select(.status=="deployed") | "\(.namespace)/\(.name)"'); do
    NS=$(echo "$NS_RELEASE" | cut -d/ -f1)
    REL=$(echo "$NS_RELEASE" | cut -d/ -f2)
    helm get manifest "$REL" -n "$NS" 2>/dev/null \
      | grep -E '^\s*image:' | sed 's/.*image:[[:space:]]*//' | tr -d '"'"'" | sed 's/^[[:space:]]*//' \
      >> "${ALL_HELM_IMAGES}"
  done
  sort -u -o "${ALL_HELM_IMAGES}" "${ALL_HELM_IMAGES}"
  echo "  Unique images in Helm manifests: $(wc -l < "${ALL_HELM_IMAGES}" | tr -d ' ')"
else
  # Offline: parse chart info from EIB config (under kubernetes.helm.charts)
  echo "  Extracting chart versions from EIB config..."
  CHARTS_FILE="${SBOM_DIR}/helm/helm-charts-from-eib.txt"
  > "${CHARTS_FILE}"
  python3 - "${WORKING_DIR}/eib/mgmt/config-eib.yaml" "${CHARTS_FILE}" << 'PYEOF'
import sys, re
config_file = sys.argv[1]
out_file = sys.argv[2]
in_charts = False
with open(config_file) as f:
    for line in f:
        if 'charts:' in line:
            in_charts = True
            continue
        if in_charts:
            if line.strip().startswith('repositories:') or (not line.startswith(' ') and line.strip()):
                if 'repositories:' in line:
                    break
            name_match = re.search(r'name:\s*(\S+)', line)
            ver_match = re.search(r'version:\s*(\S+)', line)
            ns_match = re.search(r'targetNamespace:\s*(\S+)', line)
            if name_match or ver_match or ns_match:
                with open(out_file, 'a') as o:
                    o.write(line)
PYEOF
  if [ -s "${CHARTS_FILE}" ]; then
    echo "  Charts from EIB config:"
    cat "${CHARTS_FILE}"
  fi
fi

# ---------------------------------------------------------------------------
# Layer 5: Container images — SPDX SBOM per image
# ---------------------------------------------------------------------------
echo ""
echo ">>> Layer 5: Container image SBOMs"

MASTER_LIST="${SBOM_DIR}/containers/MASTER-image-list.txt"
> "${MASTER_LIST}"

# From running cluster
[ -f "${SBOM_DIR}/rke2/cluster-running-images.txt" ] && \
  cat "${SBOM_DIR}/rke2/cluster-running-images.txt" >> "${MASTER_LIST}"

# From Helm manifests
[ -f "${SBOM_DIR}/helm/all-helm-images.txt" ] && \
  cat "${SBOM_DIR}/helm/all-helm-images.txt" >> "${MASTER_LIST}"

# From embedded images in EIB build
[ -f "${EMBEDDED_IMAGES}" ] && [ -s "${EMBEDDED_IMAGES}" ] && \
  grep -v '^rke2-bundle:' "${EMBEDDED_IMAGES}" >> "${MASTER_LIST}" 2>/dev/null || true

# Normalize: strip index.docker.io prefix, deduplicate, remove empty lines
sed 's|^index\.docker\.io/||' "${MASTER_LIST}" | grep -v '^$' | sort -u > "${MASTER_LIST}.tmp" 2>/dev/null || true
mv "${MASTER_LIST}.tmp" "${MASTER_LIST}" 2>/dev/null || true

TOTAL=$(wc -l < "${MASTER_LIST}" 2>/dev/null | tr -d ' ')
echo "  Total unique images to scan: ${TOTAL}"

if [ "${TOTAL}" -eq 0 ]; then
  echo "  WARN: No images to scan (cluster not up and no embedded images found)"
  echo "  Re-run this script after launching the management cluster (step 04)"
else
  COUNT=0
  FAILED=""

  while IFS= read -r IMG; do
    [ -z "${IMG}" ] && continue
    COUNT=$((COUNT+1))
    SAFE=$(echo "${IMG}" | tr '/:@' '___')
    OUTFILE="${SBOM_DIR}/containers/sbom-${SAFE}.spdx.json"

    # Skip if already scanned
    if [ -f "${OUTFILE}" ] && [ -s "${OUTFILE}" ]; then
      echo "  [${COUNT}/${TOTAL}] SKIP (cached): ${IMG}"
      continue
    fi

    # Determine full registry ref
    if echo "${IMG}" | grep -qE '^(registry\.|quay\.|nvcr\.|ghcr\.|harbor\.)'; then
      PULL_REF="${IMG}"
    else
      PULL_REF="docker.io/${IMG}"
    fi

    echo "  [${COUNT}/${TOTAL}] Scanning ${IMG}..."

    if syft "registry:${PULL_REF}" -o "spdx-json=${OUTFILE}" -q 2>/dev/null; then
      if [ -s "${OUTFILE}" ]; then
        PKG_COUNT=$(jq '.packages | length' "${OUTFILE}" 2>/dev/null || echo 0)
        echo "           OK (${PKG_COUNT} packages)"
      else
        FAILED="${FAILED}\n${IMG} (empty output)"
      fi
    else
      echo "           FAILED — trying trivy fallback..."
      if command -v trivy >/dev/null 2>&1; then
        trivy image --format spdx-json --output "${OUTFILE}" "${IMG}" -q 2>/dev/null && \
          echo "           OK (trivy)" || { FAILED="${FAILED}\n${IMG}"; echo "           FAILED"; }
      else
        FAILED="${FAILED}\n${IMG}"
        echo "           FAILED (trivy not available)"
      fi
    fi
  done < "${MASTER_LIST}"
fi

# ---------------------------------------------------------------------------
# Layer 6: CAPI controllers and CRDs
# ---------------------------------------------------------------------------
echo ""
echo ">>> Layer 6: CAPI/Metal3 controllers"

if [ "${CLUSTER_UP}" = true ]; then
  kubectl get crds 2>/dev/null | grep -E 'metal3|cluster.x-k8s.io|rke2|turtles|elemental' \
    > "${SBOM_DIR}/capi/capi-crds.txt" 2>/dev/null || true

  kubectl get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}/{.metadata.name}{"\t"}{range .spec.containers[*]}{.image}{"\n"}{end}{end}' 2>/dev/null \
    | grep -E 'capi|capm3|rke2|turtles|elemental|metal3' \
    > "${SBOM_DIR}/capi/capi-controller-images.txt" 2>/dev/null || true

  echo "  CRDs: $(wc -l < "${SBOM_DIR}/capi/capi-crds.txt" 2>/dev/null | tr -d ' ')"
  echo "  Controller pods: $(wc -l < "${SBOM_DIR}/capi/capi-controller-images.txt" 2>/dev/null | tr -d ' ')"
else
  echo "  Cluster not reachable — CAPI inventory skipped (re-run after step 04)"
fi

# ---------------------------------------------------------------------------
# Aggregate: build the master SBOM index
# ---------------------------------------------------------------------------
echo ""
echo ">>> Generating aggregate SBOM index"

python3 - "${SBOM_DIR}" "${TIMESTAMP}" "${RKE2_VERSION}" << 'PYEOF'
import json, os, sys, glob

SBOM_DIR = sys.argv[1]
TIMESTAMP = sys.argv[2]
RKE2_VERSION = sys.argv[3]

os_packages = 0
for f in glob.glob(os.path.join(SBOM_DIR, "os/*.packages")):
    with open(f) as fh:
        os_packages += sum(1 for line in fh if line.strip())
for f in glob.glob(os.path.join(SBOM_DIR, "os/*.spdx.json")):
    try:
        d = json.load(open(f))
        os_packages += len(d.get("packages", []))
    except:
        pass

helm_count = 0
helm_file = os.path.join(SBOM_DIR, "helm/helm-releases.txt")
if os.path.exists(helm_file):
    with open(helm_file) as f:
        helm_count = sum(1 for line in f if line.strip())

container_sboms = []
total_pkgs = 0
for f in sorted(glob.glob(os.path.join(SBOM_DIR, "containers/sbom-*.spdx.json"))):
    try:
        d = json.load(open(f))
        pkgs = len(d.get("packages", []))
        total_pkgs += pkgs
        container_sboms.append({
            "image": d.get("name", os.path.basename(f)),
            "packages": pkgs,
            "file": os.path.relpath(f, SBOM_DIR)
        })
    except:
        container_sboms.append({"image": os.path.basename(f), "packages": 0, "error": "parse failed"})

capi_crds = 0
crd_file = os.path.join(SBOM_DIR, "capi/capi-crds.txt")
if os.path.exists(crd_file):
    with open(crd_file) as f:
        capi_crds = sum(1 for line in f if line.strip())

embedded_count = 0
emb_file = os.path.join(SBOM_DIR, "containers/embedded-images-from-build.txt")
if os.path.exists(emb_file):
    with open(emb_file) as f:
        embedded_count = sum(1 for line in f if line.strip())

aggregate = {
    "metadata": {
        "generated": TIMESTAMP,
        "format": "SPDX-2.3 (per-image) + aggregate index",
        "tools": "syft, trivy (fallback), helm, kubectl",
        "rke2_version": RKE2_VERSION
    },
    "summary": {
        "os_packages": os_packages,
        "helm_charts": helm_count,
        "embedded_images": embedded_count,
        "container_images_scanned": len(container_sboms),
        "total_container_packages": total_pkgs,
        "capi_crds": capi_crds
    },
    "container_sboms": container_sboms
}

out = os.path.join(SBOM_DIR, "aggregate", f"SBOM-AGGREGATE-{TIMESTAMP}.json")
with open(out, "w") as f:
    json.dump(aggregate, f, indent=2)

summary = os.path.join(SBOM_DIR, "aggregate", "SUMMARY.txt")
with open(summary, "w") as f:
    f.write(f"SUSE Edge Metal3/CAPI Stack — SBOM Summary\n")
    f.write(f"Generated: {TIMESTAMP}\n")
    f.write(f"RKE2: {RKE2_VERSION}\n\n")
    f.write(f"OS packages:        {os_packages}\n")
    f.write(f"Embedded images:    {embedded_count}\n")
    f.write(f"Helm charts:        {helm_count}\n")
    f.write(f"Container images:   {len(container_sboms)}\n")
    f.write(f"Container packages: {total_pkgs}\n")
    f.write(f"CAPI CRDs:          {capi_crds}\n\n")
    if container_sboms:
        f.write("Container image details:\n")
        f.write(f"{'Image':<70} {'Pkgs':>6}\n")
        f.write("-" * 78 + "\n")
        for s in sorted(container_sboms, key=lambda x: x["image"]):
            f.write(f"{s['image'][:68]:<70} {s['packages']:>6}\n")

print(f"  Aggregate: {out}")
print(f"  Summary:   {summary}")
print(f"  OS packages:      {os_packages}")
print(f"  Embedded images:  {embedded_count}")
print(f"  Helm charts:      {helm_count}")
print(f"  Container images: {len(container_sboms)}")
print(f"  Total packages:   {total_pkgs}")
PYEOF

# ---------------------------------------------------------------------------
# Final report
# ---------------------------------------------------------------------------
echo ""
echo "============================================================"
echo "  SBOM Collection Complete"
echo "  Output: ${SBOM_DIR}/"
echo "  Files:  $(find "${SBOM_DIR}" -type f | wc -l | tr -d ' ')"
echo "  Size:   $(du -sh "${SBOM_DIR}" | cut -f1)"
if [ -n "${FAILED:-}" ]; then
  echo ""
  echo "  FAILED images:"
  echo -e "${FAILED}"
fi
echo "============================================================"
