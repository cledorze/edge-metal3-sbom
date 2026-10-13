#!/usr/bin/env bash
# Step 2: OS packages of an EIB image (2.1), images embedded by EIB (2.2), EIB tool image (2.3).
# Needs the variables of step 1 (source 01-prerequisites/env.sh) and sudo for the loop mount.
#   bash 02-build-time-layers/build-time-layers.sh                       # management image, into $WORK/mgmt
#   bash 02-build-time-layers/build-time-layers.sh RAW EIB_DIR OUT       # another image (step 4 uses it for the downstream image)
# Section 2.3 runs only for the management image: the EIB tool SBOM is kept apart, in $WORK.
set -euo pipefail
RAW="${1:-$MGMT_RAW}"
EIB_DIR="${2:-$EIB_MGMT_DIR}"
OUT="${3:-$WORK/mgmt}"
MNT=/mnt/eib-os
mkdir -p "$OUT/images"

# 2.1 OS packages of the EIB image
cd "$OUT"
sudo mkdir -p "$MNT"
LOOP=$(sudo losetup -fP --show -r "$RAW")
sudo mount -o ro "${LOOP}p3" "$MNT"
grep -E '^(SUSE_PRETTY_NAME|VERSION_ID)=' "$MNT/etc/os-release"
sudo "$SYFT" -q dir:"$MNT" --select-catalogers rpm \
  --source-name "$(basename "$RAW")" --source-version "$EDGE_VERSION" --source-supplier SUSE \
  -o spdx-json > sbom-os.spdx.json
sudo umount "$MNT" && sudo losetup -d "$LOOP"
jq '.packages | length' sbom-os.spdx.json

# 2.2 Images embedded in the EIB image
BUILD=$(ls -d "$EIB_DIR"/_build/build-* | tail -1)
ls "$BUILD"/helm/*/*.tgz 2>/dev/null | sed "s|$BUILD/||" | tee eib-charts.txt
ls "$BUILD"/artefacts/registry/*-registry.tar.zst 2>/dev/null | xargs -n1 basename | sed 's/-registry\.tar\.zst$//' | tr '_' '/' | tee eib-embedded-images.txt
for F in "$BUILD"/artefacts/kubernetes/images/*.tar.zst; do
  [ -e "$F" ] || continue
  echo "# $(basename "$F")"
  zstd -dc "$F" | tar -xO manifest.json | jq -r '.[].RepoTags[]'
done | tee eib-rke2-bundle-images.txt
touch eib-charts.txt eib-embedded-images.txt eib-rke2-bundle-images.txt

# 2.3 EIB tool image (build provenance, kept apart), management image only
if [ "$OUT" = "$WORK/mgmt" ]; then
  cd "$WORK"
  "$SYFT" -q "registry:$EIB_IMAGE" --source-supplier SUSE -o spdx-json > sbom-eib-tool.spdx.json
  jq '.packages | length' sbom-eib-tool.spdx.json
fi
