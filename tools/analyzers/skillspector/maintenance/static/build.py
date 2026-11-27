"""Reproduce the Scan-maintained static parser wheel from the locked upstream archive."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile

HERE = Path(__file__).resolve().parent
BUILDER = HERE.parent
sys.path.insert(0, str(BUILDER))
from build import SOURCE_SHA256, UPSTREAM, canonical_wheel, digest, recipe_digest

PATCHES = ("literal-json.patch", "fenced-typescript.patch")
PATCHED_MODULES = {
    "src/skillspector/nodes/analyzers/static_patterns_tool_misuse.py":
        "6af25304aa79a191aeff65212ab4d7e6b22c8146b301e6523c5484baf35fc57b",
    "src/skillspector/security_reconstruction.py":
        "e535759a154d352165fa45ef090b78b71cffb629facd992f58ee6d6ca6656a2e",
}


def identity():
    inputs = {
        "upstream": UPSTREAM,
        "sourceSha256": SOURCE_SHA256,
        "patches": [{"name": name, "sha256": digest(HERE / name)} for name in PATCHES],
        "runtimeLockSha256": digest(BUILDER.parent / "uv.lock"),
        "buildLockSha256": digest(BUILDER / "uv.lock"),
        "buildProjectSha256": digest(BUILDER / "pyproject.toml"),
        "sharedBuilderSha256": recipe_digest(BUILDER / "build.py"),
        "builderRecipeSha256": recipe_digest(HERE / "build.py"),
    }
    encoded = json.dumps(inputs, sort_keys=True, separators=(",", ":")).encode()
    return {**inputs, "version": "2.13.7+aih.static.1." + hashlib.sha256(encoded).hexdigest()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--identity", action="store_true")
    args = parser.parse_args()
    provenance = identity()
    if args.identity:
        print(json.dumps(provenance, indent=2))
        return
    if args.source is None or args.out is None:
        parser.error("--source and --out required")
    if digest(args.source) != SOURCE_SHA256:
        raise ValueError("Upstream source archive digest mismatch")
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    source = out / ("SkillSpector-" + UPSTREAM)
    with tarfile.open(args.source) as archive:
        for member in archive:
            if not (member.isfile() or member.isdir()) or Path(member.name).parts[:1] != (source.name,):
                raise ValueError("Unexpected upstream archive member")
        archive.extractall(out, filter="data")
    # git apply can skip every hunk when it discovers an enclosing checkout.
    patch_env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    patch_env["GIT_CEILING_DIRECTORIES"] = str(out)
    for name in PATCHES:
        subprocess.run(["git", "-c", "core.autocrlf=false", "apply", str(HERE / name)],
                       cwd=source, env=patch_env, check=True)
    for path, expected in PATCHED_MODULES.items():
        if digest(source / path) != expected:
            raise ValueError(f"Reviewed parser source mismatch: {path}")
    project = source / "pyproject.toml"
    text = project.read_text(encoding="utf-8")
    if text.count('version = "2.13.7"') != 1:
        raise ValueError("Unexpected upstream version")
    project.write_text(text.replace('version = "2.13.7"', f'version = "{provenance["version"]}"'),
                       encoding="utf-8", newline="\n")
    (source / "src/skillspector/aih-scan-build.json").write_text(
        json.dumps(provenance, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    environment = {**os.environ, "SOURCE_DATE_EPOCH": "1793599200", "UV_PROJECT_ENVIRONMENT": str(out / "builder")}
    subprocess.run(["uv", "sync", "--project", str(BUILDER), "--locked", "--no-install-project"], env=environment, check=True)
    python = out / "builder" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    subprocess.run(["uv", "build", "--wheel", "--no-build-isolation", "--python", str(python),
                    "--out-dir", str(out / "wheels"), str(source)], env=environment, check=True)
    wheel, = (out / "wheels").glob("*.whl")
    canonical_wheel(wheel)
    receipt = {**provenance, "wheel": wheel.name, "wheelSha256": digest(wheel)}
    (out / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8", newline="\n")


if __name__ == "__main__":
    main()
