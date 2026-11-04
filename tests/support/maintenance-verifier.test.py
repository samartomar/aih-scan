"""Exercise the installed-wheel verifier with isolated synthetic distributions, never analyzer code."""
import hashlib
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import zipfile

VERIFIER = Path(__file__).resolve().parents[2] / "tools/analyzers/skillspector/maintenance/verify.py"
VERSION = "2.13.3+fixture"


class InstalledPayloadTest(unittest.TestCase):
    def test_exact_payload_and_shadow_carriers(self):
        for extra in (None, "shadow-package", "sourceless-bytecode", "cache-bytecode", "directory-link"):
            with self.subTest(extra=extra), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                installed = root / "installed"
                installed.mkdir()
                wheel = root / "fixture.whl"
                payload = {
                    "skillspector/__init__.py": b"",
                    "skillspector/nodes/analyzers/mcp_tool_poisoning.py": b"raise AssertionError('must never import')\n",
                    "skillspector-2.13.3+fixture.dist-info/METADATA": b"Metadata-Version: 2.1\nName: skillspector\nVersion: 2.13.3+fixture\n",
                }
                with zipfile.ZipFile(wheel, "w") as archive:
                    for path, content in payload.items():
                        archive.writestr(path, content)
                        target = installed / path
                        target.parent.mkdir(parents=True, exist_ok=True)
                        target.write_bytes(content)
                package = installed / "skillspector/nodes/analyzers"
                if extra == "shadow-package":
                    carrier = package / "mcp_tool_poisoning/__init__.py"
                    carrier.parent.mkdir()
                    carrier.write_text("raise AssertionError('shadow')\n")
                elif extra == "sourceless-bytecode":
                    (package / "mcp_tool_poisoning.pyc").write_bytes(b"alternate bytecode")
                elif extra == "cache-bytecode":
                    cache = package / "__pycache__"
                    cache.mkdir()
                    (cache / "mcp_tool_poisoning.cpython-313.pyc").write_bytes(b"alternate bytecode")
                elif extra == "directory-link":
                    moved = root / "moved"
                    package.rename(moved)
                    try:
                        package.symlink_to(moved, target_is_directory=True)
                    except OSError:
                        continue  # Host cannot create symlinks; the other carriers still execute.
                command = [sys.executable, "-I", "-c", "import runpy,sys; sys.path.insert(0,sys.argv[1]); sys.argv=sys.argv[2:]; runpy.run_path(sys.argv[0],run_name='__main__')",
                           str(installed), str(VERIFIER), str(wheel), hashlib.sha256(wheel.read_bytes()).hexdigest(), VERSION]
                result = subprocess.run(command, capture_output=True, text=True, timeout=30)
                if extra is None:
                    self.assertEqual(result.returncode, 0, result.stderr)
                else:
                    self.assertNotEqual(result.returncode, 0, f"Accepted {extra}")
                    self.assertIn("Installed maintenance", result.stderr)


if __name__ == "__main__":
    unittest.main()
