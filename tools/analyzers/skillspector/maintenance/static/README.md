# Reviewed static parser build

Scan maintains this optional build of SkillSpector 2.13.7 for static inspections. It includes two changes to the upstream parser. One recognizes quoted property names in complete literal JSON examples. The other recognizes closing TypeScript template delimiters in complete Markdown code fences. Each patch carries its regression tests. The wheel retains the upstream license.

The [upstream JSON change](https://github.com/NVIDIA/SkillSpector/pull/1211) and both checked-in patches can be reviewed independently. The source revision, patch order and digests, runtime and build locks, build recipes, full distribution version and expected wheel digest are recorded in [artifact.json](artifact.json).

## Build and verify

From the Scan repository root, download the [pinned upstream source archive](https://codeload.github.com/NVIDIA/SkillSpector/tar.gz/c323ad4c43e3c8f2de051572cc25b2711d11e648). Use Python 3.12 or 3.13, Git and uv. The output directory must be new. The same files and digests apply on Windows and Linux.

```sh
python tools/analyzers/skillspector/maintenance/static/build.py --source source.tar.gz --out parser-build
```

Compare the complete generated `parser-build/receipt.json` with the checked-in `artifact.json`. Install the built wheel into a separate environment using the standard SkillSpector runtime lock. The example below uses a POSIX shell.

```sh
UV_PROJECT_ENVIRONMENT="$PWD/parser-runtime" uv sync --project tools/analyzers/skillspector --locked --no-install-project
uv pip install --python parser-runtime/bin/python --no-deps parser-build/wheels/*.whl
parser-runtime/bin/python -I -B tools/analyzers/skillspector/maintenance/verify.py parser-build/wheels/*.whl <wheelSha256> <version>
```

Supply the exact `wheelSha256` and `version` from the checked-in artifact record. On Windows, use `parser-runtime/Scripts/python.exe` and the full wheel filename. See [Scan's analyzer guide](../../../../../docs/analyzers.md) for selecting a static analyzer. A new producer emits new evidence for the original source files, with its own version recorded in each report.
