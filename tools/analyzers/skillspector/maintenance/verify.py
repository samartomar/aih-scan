"""Verify a reviewed wheel's exact installed payload without importing analyzer code."""
import hashlib
from importlib.metadata import distribution
from importlib.util import find_spec
from io import BytesIO
from pathlib import Path, PurePosixPath
import sys
import zipfile

wheel = Path(sys.argv[1])
expected_hash, expected_version = sys.argv[2:4]
static = len(sys.argv) > 4
if static and (not wheel.is_absolute() or wheel.is_symlink() or not wheel.is_file() or
               wheel.stat().st_size > 32 * 1024 * 1024):
    raise ValueError("Invalid reviewed static wheel file")
wheel_bytes = wheel.read_bytes()
if hashlib.sha256(wheel_bytes).hexdigest() != expected_hash:
    raise ValueError("Maintenance wheel digest mismatch")
installed = distribution("skillspector")
if installed.version != expected_version:
    raise ValueError("Installed maintenance version mismatch")
with zipfile.ZipFile(BytesIO(wheel_bytes)) as archive:
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
if not static:
    print("Verified maintenance wheel and installed payload")
else:
    # The console launcher is used only to locate the locked environment. Verify
    # the package Python will import and run it in this same isolated interpreter.
    spec = find_spec("skillspector")
    if spec is None or spec.origin is None or Path(spec.origin).resolve() != (package / "__init__.py").resolve():
        raise ValueError("SkillSpector import origin differs from reviewed wheel")
    if sys.argv[4:] == ["--static-probe"]:
        print("Verified static wheel and installed payload")
    elif sys.argv[4:6] == ["--static-scan", "scan"] and "--no-llm" in sys.argv[6:]:
        from skillspector.cli_entry import app

        sys.argv = ["skillspector", *sys.argv[5:]]
        app()
    else:
        raise ValueError("Invalid reviewed static analyzer invocation")
