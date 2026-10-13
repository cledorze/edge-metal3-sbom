# Step 7: validate

Script: `bash 07-validate/validate.sh [WORK]` runs the two validators of section 7 and the three checks of section 8 (no empty input, roots = inputs, no host trace), PASS or FAIL each; `QUICK=1` skips the two validators (minutes to an hour on a whole-stack document).
## 7. Validate

```bash
cd "$WORK"
time "$HOME/sbomval/bin/pyspdxtools" -i sbom-global.spdx.json; echo "pyspdxtools rc=$?"
"$HOME/sbomval/bin/ntia-checker" sbom-global.spdx.json; echo "ntia rc=$?"
```

Observed, 2026-10-09, on the management cluster SBOM above (validation run on a laptop; the 100 MB file takes `pyspdxtools` 41 min 43 s):

```
pyspdxtools rc=0
2021 NTIA SBOM Minimum Elements Conformance Results

Conformant: True

Requirement                                    | Status
-------------------------------------------------------
All component names provided?                  | True
All component versions provided?               | True
All component identifiers provided?            | True
All component suppliers provided?              | True
SBOM author name provided?                     | True
SBOM creation timestamp provided?              | True
Dependency relationships provided?             | True

ntia rc=0
```

Observed, 2026-10-12, on the whole-stack SBOM of section 6 (50 inputs, 9374 packages, 107 MB, same laptop): `pyspdxtools` rc=0 after 47 min 16 s, `ntia-checker` Conformant: True on the seven requirements, rc=0, same output as above. Observed the same day on the replayed document (69 inputs, 11409 packages, 112 MB): `pyspdxtools` rc=0 after 50 min 56 s, `ntia-checker` Conformant: True, rc=0.

`pyspdxtools` prints nothing when the document is valid and returns 0; errors are listed otherwise. `ntia-checker` is an offline check of the NTIA minimum elements, not a test of any given consumer tool; a SBOM platform may still reject a document that passes it.

## 8. Hand-over checks

Before sharing, check that the document carries no host name or path of the build host, in its text or in the name of a root:

```bash
grep -c -F -e "$(hostname)" -e "/mnt/" -e "$HOME" sbom-global.spdx.json
jq -r '.packages[] | select(.SPDXID | test("DocumentRoot")) | .name' sbom-global.spdx.json | grep -c '^/'
```

Observed on the 2026-10-09 document and on the whole-stack document of section 6, both built from the management OS SBOM scanned without `--source-name`: 1 and 1, the OS root named `/mnt/m352-os`; its identifier `SPDXRef-DocumentRoot-Directory--mnt-m352-os` carries the path too and is repeated by the 556 relationships of that layer. `--source-name` of section 2.1 removes all of it. Observed on the replayed document of 2026-10-12: 0 and 0.

Checklist:

- [ ] one `sbom-os.spdx.json` per EIB image (management, downstream)
- [ ] `all-images.txt` = running images plus the images embedded by EIB, one `images/sbom-*.spdx.json` per line, none empty: `for f in */images/*.spdx.json; do [ "$(jq '.packages | length' "$f")" -gt 0 ] || echo "EMPTY $f"; done`
- [ ] `DESCRIBES` roots in the global document = number of distinct inputs (an image repeated across clusters counts once)
- [ ] `pyspdxtools` rc=0 and `ntia-checker` Conformant: True
- [ ] no host name or mount path of the build host in the global document

## Negative control of the validators

Observed, 2026-10-12, on the workload image SBOM (`registry.suse.com/suse/nginx:1.27`, 89 packages, 4921 relationships; the file is under `examples/edge-3.5.2-bench-2026-10-12/sbom-samples/`): the untouched copy passes both validators; a relationship pointing to a missing element fails `pyspdxtools`; three packages without supplier fail the NTIA check. The validators discriminate.

```bash
cp sbom-registry.suse.com_suse_nginx_1.27.spdx.json ok.json
"$SBOMVAL/pyspdxtools" -i ok.json; echo "untouched: pyspdxtools rc=$?"
"$SBOMVAL/ntia-checker" ok.json | grep -m1 Conformant
jq '.relationships[1].relatedSpdxElement = "SPDXRef-DOES-NOT-EXIST"' ok.json > badrel.json
"$SBOMVAL/pyspdxtools" -i badrel.json; echo "broken relationship: pyspdxtools rc=$?"
jq '.packages[0:3] |= map(del(.supplier))' ok.json > nosup.json
"$SBOMVAL/ntia-checker" nosup.json | grep -E 'Conformant|suppliers'
```

```
untouched: pyspdxtools rc=0
Conformant: True
ERROR:root:The document is invalid. The following issues have been found:
broken relationship: pyspdxtools rc=1
Conformant: False
All component suppliers provided?              | False
```
