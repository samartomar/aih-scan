"""Verify a reviewed wheel's exact installed payload without importing analyzer code."""
import hashlib
from importlib.metadata import distribution
from pathlib import Path, PurePosixPath
import sys
import zipfile

wheel = Path(sys.argv[1])
expected_hash, expected_version = sys.argv[2:4]
if hashlib.sha256(wheel.read_bytes()).hexdigest() != expected_hash:
    raise ValueError("Maintenance wheel digest mismatch")
installed = distribution("skillspector")
if installed.version != expected_version:
    raise ValueError("Installed maintenance version mismatch")
with zipfile.ZipFile(wheel) as archive:
    for entry in archive.infolist():
        path = PurePosixPath(entry.filename)
        if path.is_absolute() or ".." in path.parts or entry.is_dir():
            raise ValueError("Unexpected maintenance wheel path")
        if path.name == "RECORD":
            continue  # Installation adds launcher records; payload bytes below are authoritative.
        actual = Path(installed.locate_file(entry.filename))
        if not actual.is_file() or actual.is_symlink() or actual.read_bytes() != archive.read(entry):
            raise ValueError("Installed maintenance payload differs from reviewed wheel")
print("Verified maintenance wheel and installed payload")
