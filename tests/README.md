# Tests

Each script is one check of section 7 or 8 of the [runbook](../docs/runbook.md), with the same
commands. Each one prints `PASS` or `FAIL` on its last line and exits 0 or 1 (2 when the input is
missing). They read the output directory of the runbook (`WORK`, section 1), given as the first
argument or taken from `$PWD`.

| Test | What it checks | Runbook | Observed on the Edge 3.5.2 bench |
|---|---|---|---|
| `01-spdx-validate.sh` | `sbom-global.spdx.json` is a valid SPDX 2.3 document (`pyspdxtools`) | 7 | rc=0, 47 min 16 s on 107 MB (2026-10-12) |
| `02-ntia-conformance.sh` | NTIA minimum elements (`ntia-checker`), `Conformant: True` | 7 | rc=0, seven requirements True (2026-10-12) |
| `03-no-empty-inputs.sh` | every per-layer SBOM has at least one package | 8, checklist | 0 empty on 50 inputs (2026-10-12) |
| `04-roots-equal-inputs.sh` | `DESCRIBES` roots of the global document = distinct roots of the inputs | 8, checklist | 50 inputs, 43 roots (2026-10-12) |
| `05-no-host-paths.sh` | no host name, mount path or `$HOME` in the text, no root named after a path | 8 | 0 and 0 on the replayed document (2026-10-12) |
| `06-validators-negative-control.sh` | the two validators fail on a broken document (control of tests 1 and 2) | 7 | rc=1 and `Conformant: False` on the nginx image SBOM (2026-10-12) |

`run-all.sh` runs 3, 4, 5 first (seconds), then 1 and 2 (minutes to an hour on a whole-stack
document), then 6 on the sample SBOM shipped under `examples/`.

Requirements: `jq`, and the validation venv of runbook section 1
(`spdx-tools==0.8.5`, `ntia-conformance-checker==6.0.0`), located by `SBOMVAL`
(default `$HOME/sbomval/bin`).

```bash
python3 -m venv "$HOME/sbomval"
"$HOME/sbomval/bin/pip" install -q spdx-tools==0.8.5 ntia-conformance-checker==6.0.0
tests/run-all.sh "$HOME/metal3-sbom"
```

Test 6 runs without any SBOM of your own:

```bash
tests/06-validators-negative-control.sh
```
