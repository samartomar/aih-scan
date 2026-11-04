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
    expected_files = {
        PurePosixPath(entry.filename) for entry in archive.infolist()
        if PurePosixPath(entry.filename).parts[0] == "skillspector" and not entry.is_dir()
    }
    expected_dirs = {parent for path in expected_files for parent in path.parents if str(parent) != "."}
    package = Path(installed.locate_file("skillspector"))
    if not expected_files or package.is_symlink() or not package.is_dir():
        raise ValueError("Installed maintenance package root differs from reviewed wheel")
    actual_files, actual_dirs = set(), {PurePosixPath("skillspector")}
    for actual in package.rglob("*"):
        relative = PurePosixPath("skillspector") / actual.relative_to(package).as_posix()
        if actual.is_symlink():
            raise ValueError("Installed maintenance package contains a link")
        if actual.is_file():
            actual_files.add(relative)
        elif actual.is_dir():
            actual_dirs.add(relative)
        else:
            raise ValueError("Installed maintenance package contains a special entry")
    if actual_files != expected_files or actual_dirs != expected_dirs:
        raise ValueError("Installed maintenance package file set differs from reviewed wheel")
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
