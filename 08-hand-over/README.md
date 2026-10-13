# Step 8: hand-over

## 8. Hand-over

Deliver, for each stack:

- `sbom-global.spdx.json` and its `.sha256`;
- the per-layer SBOMs: `mgmt/sbom-os.spdx.json`, `mgmt/images/*.spdx.json`, the same under `downstream/` and `workload/`;
- the inventories: `nodes.tsv`, `helm-releases.tsv`, `capi-crds.txt`, `capi-controllers.tsv`, `eib-charts.txt`, `all-images.txt`, `running-image-digests.txt`;
- `sbom-eib-tool.spdx.json`, apart, as build provenance;
- the tool versions (`syft version`, `"$HOME/sbomval/bin/pip" freeze`) and the output of section 7.

