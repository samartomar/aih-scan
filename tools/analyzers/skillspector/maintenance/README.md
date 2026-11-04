# SkillSpector TP4 maintenance build

This is a Scan-maintained source build of NVIDIA SkillSpector 2.13.3, not an upstream
release. `artifact.json` binds its full distinct version and reproducible wheel SHA-256.
The version digest binds the upstream commit/archive, capacity patch, unchanged runtime
lock and separate build-tool lock. Original Apache-2.0 license/provenance stays in the
source archive and wheel. No installed package is patched.

Acquire `https://codeload.github.com/NVIDIA/SkillSpector/tar.gz/38a1dfe93325d2f8bfcd4f8d0241eed706334915`
and retain the downloaded archive. The builder authenticates its SHA-256 before extracting
only ordinary files/directories, applies the checked patch to a new source directory and
builds a wheel with locked Hatchling and fixed timestamps:

```sh
python tools/analyzers/skillspector/maintenance/build.py --source source.tar.gz --out new-build
```

`new-build` must not exist. Compare its `receipt.json` to `artifact.json`, including the
wheel SHA-256, before installation. Independent clean builds must give the same hash;
a changed hash or recipe needs review and a new bound identity. This command installs
only the isolated builder dependencies, not the analyzer runtime.

Provision a separate analyzer environment with the existing runtime lock (see
`docs/analyzers.md`), then install this exact wheel using `uv pip install --no-deps
--python <environment-python> <wheel>`. Dependencies stay on the original runtime lock;
do not run another dependency resolver. Verify installed wheel payload before use:

```sh
<environment-python> -I tools/analyzers/skillspector/maintenance/verify.py <wheel> <wheel-sha256> <full-version>
```

The verifier compares every wheel payload file against the installed distribution,
without importing analyzer code; installed RECORD differs because installation adds
entry points. It rejects changed wheel bytes, installed version or installed payload.
Prepared maintenance profiles run this check again before scan or checkpoint reuse.
Keep the reviewed wheel available through `AIH_SCAN_SKILLSPECTOR_WHEEL`, and select its
absolute installed `skillspector` executable via `AIH_SCAN_SKILLSPECTOR`.

The patch supports import-time `SKILLSPECTOR_TP4_MAX_FILES` and
`SKILLSPECTOR_TP4_MAX_FINDINGS`, each decimal 1–4096. Unset/blank keeps 128/64; invalid
values warn without echoing input and keep defaults. The upper bound matches the existing
4096-batch ceiling and stays below the 10000-record report bound. Batch/source/prompt
bytes, tokens, concurrency, timeouts, findings, score and partial ledger behavior remain
in force. Raising file capacity can expose these other limits; complete inspection must
still be proved. Raising finding retention alone adds no requests, but more sources and
batches can increase requests, tokens, memory and cost. Do not infer costs from HTTP counts.
The JSON report records the actual version and resolved numeric TP4 capacities; Scan
checks these against configured values and refuses a mismatch. This capability does not
change provider/model/reasoning or make an incomplete assessment eligible.
