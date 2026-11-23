"""Build a distinct maintenance wheel from authenticated upstream source, never site-packages."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import tarfile

HERE = Path(__file__).resolve().parent
UPSTREAM = "e2674da339b0bddc6e565d059c0577c6d9cd25da"
SOURCE_SHA256 = "678f5dd59b5dff0c62181c045e15e8411727cc425c653a793b36e60fb50b11e1"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def recipe_digest(path):
    return hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()


def identity():
    inputs = {"upstream": UPSTREAM, "sourceSha256": SOURCE_SHA256,
              "patchSha256": digest(HERE / "capacity.patch"),
              "runtimeLockSha256": digest(HERE.parent / "uv.lock"),
              "buildLockSha256": digest(HERE / "uv.lock"),
              "builderRecipeSha256": recipe_digest(HERE / "build.py")}
    build_id = hashlib.sha256(json.dumps(inputs, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return {**inputs, "version": "2.13.6+aih.1." + build_id}


def canonical_wheel(path):
    data = bytearray(path.read_bytes())
    end = data.rfind(b"PK\x05\x06")
    if end < 0 or end + 22 != len(data):
        raise ValueError("Unexpected maintenance wheel directory")
    central_size = struct.unpack_from("<I", data, end + 12)[0]
    offset = struct.unpack_from("<I", data, end + 16)[0]
    if offset + central_size != end:
        raise ValueError("Unexpected maintenance wheel directory size")
    while offset < end:
        if data[offset:offset + 4] != b"PK\x01\x02":
            raise ValueError("Unexpected maintenance wheel entry")
        data[offset + 5] = 0
        name, extra, comment = struct.unpack_from("<HHH", data, offset + 28)
        offset += 46 + name + extra + comment
    if offset != end:
        raise ValueError("Unexpected maintenance wheel entries")
    path.write_bytes(data)


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
    subprocess.run(["git", "-c", "core.autocrlf=false", "-c", "core.eol=lf", "apply", "--check", str(HERE / "capacity.patch")], cwd=source, check=True)
    subprocess.run(["git", "-c", "core.autocrlf=false", "-c", "core.eol=lf", "apply", str(HERE / "capacity.patch")], cwd=source, check=True)
    project = source / "pyproject.toml"
    text = project.read_text()
    if text.count('version = "2.13.6"') != 1:
        raise ValueError("Unexpected upstream version source")
    project.write_text(text.replace('version = "2.13.6"', 'version = "' + expected["version"] + '"'))
    (source / "src/skillspector/aih-scan-build.json").write_text(json.dumps(expected, sort_keys=True) + "\n", newline="\r\n")
    environment = {**os.environ, "UV_PROJECT_ENVIRONMENT": str(args.out / "builder"), "SOURCE_DATE_EPOCH": "1793599200"}
    subprocess.run(["uv", "sync", "--project", str(HERE), "--locked", "--no-install-project"], env=environment, check=True)
    python = args.out / "builder" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    subprocess.run(["uv", "build", "--wheel", "--no-build-isolation", "--python", str(python), "--out-dir", str(args.out / "wheels"), str(source)], env=environment, check=True)
    wheels = list((args.out / "wheels").glob("*.whl"))
    if len(wheels) != 1:
        raise ValueError("Unexpected wheel set")
    canonical_wheel(wheels[0])
    (args.out / "receipt.json").write_text(json.dumps({**expected, "wheel": wheels[0].name, "wheelSha256": digest(wheels[0])}, indent=2) + "\n", newline="\n")
    print((args.out / "receipt.json").read_text())


if __name__ == "__main__":
    main()
