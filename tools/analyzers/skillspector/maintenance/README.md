# SkillSpector TP4 maintenance build

This is a Scan-maintained source build of NVIDIA SkillSpector 2.13.7, not an upstream
release. `artifact.json` binds its full distinct version and reproducible wheel SHA-256.
The version digest binds the upstream commit/archive, capacity patch, runtime lock,
separate build-tool lock and the reviewed builder recipe's canonical LF-byte SHA-256.
Changing the recipe therefore changes the version and wheel identity without depending
on checkout line endings. Original Apache-2.0 license/provenance stays in the source
archive and wheel. No installed package is patched.

## 2.13.7 patch review

The 2.13.6 maintenance patch was compared with the official `v2.13.7` tag at commit
`c323ad4c43e3c8f2de051572cc25b2711d11e648`. The patch context preserves the upstream
MCP Tool Poisoning tag change to `AML.T0110`. The capacity and report behavior is unchanged.

| Patch behavior | Disposition | Why |
| --- | --- | --- |
| `SKILLSPECTOR_TP4_MAX_FILES` | Retained | The maintenance build keeps its reviewed 1–4096 bound, 128 default and warning-without-echo behavior. The bound stays below the 10000-record report bound. |
| `SKILLSPECTOR_TP4_MAX_FINDINGS` | Retained | Upstream 2.13.7 fixes TP4 findings at 64. |
| Existing `SKILLSPECTOR_TP4_MAX_BATCHES` support | Retained unchanged | Upstream already supplies this control, its 256 default and 1–4096 validation. The patch does not replace it. |
| Upstream TP4 byte capacities (`SKILLSPECTOR_TP4_MAX_TOTAL_CODE_BYTES`, `_TOTAL_INPUT_BYTES`, `_FILE_CODE_BYTES`) | Retained upstream | Prepared profiles omit these settings, and static runs scrub them. |
| `metadata.aih_scan_tp4_limits` in JSON reports | Retained unchanged | Scan must compare the producer's resolved numeric file/finding/batch capacities with the requested configuration before accepting observations. Upstream does not emit this maintenance metadata. |
| `soft_wrap=True` for `--version` | Retained in `skillspector/cli_entry.py` | The full bound maintenance version must remain on one line for Scan's executable probe. |
| Upstream source and runtime inputs | Replaced | The source and runtime lock match the standard 2.13.7 runtime. The separately locked builder uses Hatchling 1.31.0, and the artifact receipt binds the new inputs. |
| Prior maintenance identities | Historical | New observations require the exact 2.13.7 producer and wheel. Public readers keep each historical observation's original identity. |

No new defaults, provider/model/reasoning selections, budget overrides, deadline changes or
report-bound changes were added.

## Reproduce and install

Acquire `https://codeload.github.com/NVIDIA/SkillSpector/tar.gz/c323ad4c43e3c8f2de051572cc25b2711d11e648`
and retain the downloaded archive. The builder authenticates its SHA-256 before extracting
only ordinary files/directories, applies the checked patch to a new source directory and
builds a wheel with locked Hatchling and fixed timestamps:

```sh
python tools/analyzers/skillspector/maintenance/build.py --source source.tar.gz --out new-build
```

`new-build` must not exist. Compare its canonical LF `receipt.json` byte-for-byte with
`artifact.json`, including the wheel SHA-256, before installation. Independent clean builds
from the same archive and reviewed patch/locks/recipe must give identical receipt and wheel
bytes; a changed hash or recipe needs review and a new bound identity. This command installs
only the isolated builder dependencies, not the analyzer runtime.

Provision a separate analyzer environment with the existing runtime lock (see
`docs/analyzers.md`), then install this exact wheel using `uv pip install --no-deps
--python <environment-python> <wheel>`. Dependencies stay on the original runtime lock;
do not run another dependency resolver. Verify the installed wheel payload before use:

```sh
<environment-python> -I tools/analyzers/skillspector/maintenance/verify.py <wheel> <wheel-sha256> <full-version>
```

The verifier requires the exact package file/directory set and compares every wheel payload
file against the installed distribution. Extra shadow modules, bytecode carriers and
directory/file symlinks are refused, without importing analyzer code; installed RECORD
differs because installation adds entry points. It rejects changed wheel bytes, installed
version or installed payload. Set `PYTHONDONTWRITEBYTECODE=1` before running the maintenance
executable directly, including a version check, to keep verification reproducible.
Prepared maintenance profiles run this check again before
scan or checkpoint reuse. Keep the reviewed wheel available through
`AIH_SCAN_SKILLSPECTOR_WHEEL`, and select its absolute installed `skillspector` executable
via `AIH_SCAN_SKILLSPECTOR`.

## Capacity and producer identity

The patch supports import-time `SKILLSPECTOR_TP4_MAX_FILES` and
`SKILLSPECTOR_TP4_MAX_FINDINGS`, each decimal 1–4096. With
`SKILLSPECTOR_TP4_MAX_BATCHES`, unset/blank values keep upstream defaults 128/64/256;
invalid values warn without echoing input and keep those defaults. The upper bound matches
the existing 4096-batch ceiling and stays below the 10000-record report bound.
Batch/source/prompt bytes, tokens, concurrency, timeouts, findings, score and partial
ledger behavior remain in force. Raising file capacity can expose these other limits;
complete inspection must still be proved. Raising finding retention alone adds no requests,
but more sources and batches can increase requests, tokens, memory and cost. Do not infer
costs from HTTP counts.

The JSON report records the actual version and resolved numeric TP4 capacities; Scan checks
these against configured values and refuses a mismatch. Static Scan runs retain upstream
defaults and scrub ambient capacity controls. Prepared AI profiles make all three capacities
explicit and bind them, the exact maintenance version and wheel into the checkpoint
configuration. Changing any of them creates a separate resume namespace; returning to the
same reviewed profile reuses only its own completed observations.

This capability does not change provider/model/reasoning choices or make an incomplete
assessment eligible. Larger limits do not guarantee complete inspection.

Completed historical summaries and findings, including those naming the previous 2.13.3,
2.13.4 and 2.13.6 maintenance producers, remain readable under their original identities through the existing
public readers. Historical readability does not admit the old wheels for new scans or
prepared profiles. Existing evidence keeps its recorded producer identity.
