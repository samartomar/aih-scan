"""Build a distinct maintenance wheel from authenticated upstream source, never site-packages."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tarfile

HERE = Path(__file__).resolve().parent
UPSTREAM = "38a1dfe93325d2f8bfcd4f8d0241eed706334915"
SOURCE_SHA256 = "c503337dd2e0e3a600149a6ab33a7cfa3d88e9869c2cfaff3eb1dbb77e68e29e"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def identity():
    inputs = {"upstream": UPSTREAM, "sourceSha256": SOURCE_SHA256,
              "patchSha256": digest(HERE / "capacity.patch"),
              "runtimeLockSha256": digest(HERE.parent / "uv.lock"),
              "buildLockSha256": digest(HERE / "uv.lock")}
    build_id = hashlib.sha256(json.dumps(inputs, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return {**inputs, "version": "2.13.3+aih.1." + build_id}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, help="Exact upstream codeload .tar.gz (no downloads performed)")
    parser.add_argument("--out", type=Path, help="New build directory; must not exist")
    parser.add_argument("--identity", action="store_true")
    args = parser.parse_args()
    expected = identity()
    if args.identity:
        print(json.dumps(expected, indent=2))
        return
    if args.source is None or args.out is None:
        parser.error("--source and --out required")
    if digest(args.source) != SOURCE_SHA256:
        raise ValueError("Upstream source archive digest mismatch")
    args.out = args.out.resolve()
    args.out.mkdir(parents=True, exist_ok=False)
    with tarfile.open(args.source) as archive:
        for member in archive.getmembers():
            if not (member.isfile() or member.isdir()):
                raise ValueError("Source archive contains a link or special entry")
            if member.name != "SkillSpector-" + UPSTREAM and not member.name.startswith("SkillSpector-" + UPSTREAM + "/"):
                raise ValueError("Unexpected upstream archive root")
        archive.extractall(args.out, filter="data")
    source = args.out / ("SkillSpector-" + UPSTREAM)
    subprocess.run(["git", "apply", "--check", str(HERE / "capacity.patch")], cwd=source, check=True)
    subprocess.run(["git", "apply", str(HERE / "capacity.patch")], cwd=source, check=True)
    project = source / "pyproject.toml"
    text = project.read_text()
    if text.count('version = "2.13.3"') != 1:
        raise ValueError("Unexpected upstream version source")
    project.write_text(text.replace('version = "2.13.3"', 'version = "' + expected["version"] + '"'))
    (source / "src/skillspector/aih-scan-build.json").write_text(json.dumps(expected, sort_keys=True) + "\n")
    environment = {**os.environ, "UV_PROJECT_ENVIRONMENT": str(args.out / "builder"), "SOURCE_DATE_EPOCH": "1793599200"}
    subprocess.run(["uv", "sync", "--project", str(HERE), "--locked", "--no-install-project"], env=environment, check=True)
    python = args.out / "builder" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    subprocess.run(["uv", "build", "--wheel", "--no-build-isolation", "--python", str(python), "--out-dir", str(args.out / "wheels"), str(source)], env=environment, check=True)
    wheels = list((args.out / "wheels").glob("*.whl"))
    if len(wheels) != 1:
        raise ValueError("Unexpected wheel set")
    (args.out / "receipt.json").write_text(json.dumps({**expected, "wheel": wheels[0].name, "wheelSha256": digest(wheels[0])}, indent=2) + "\n")
    print((args.out / "receipt.json").read_text())


if __name__ == "__main__":
    main()
