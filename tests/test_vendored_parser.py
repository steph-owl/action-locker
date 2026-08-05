"""The authoritative parser is reproducible and independent of site-packages."""

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

import action_locker
import ruamel.yaml


ROOT = Path(__file__).resolve().parents[1]


def test_stable_import_is_exactly_the_vendored_pin():
    assert action_locker.stable_backend_available()
    assert ruamel.yaml.__version__ == action_locker.STABLE_RUAMEL_PIN
    Path(ruamel.yaml.__file__).resolve().relative_to(
        (ROOT / "_vendor").resolve()
    )


def test_vendored_manifest_and_provenance_are_current():
    completed = subprocess.run(
        [sys.executable, "scripts/vendor_ruamel.py", "--check"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr


def test_runtime_integrity_rejects_modified_or_extra_parser_files(tmp_path):
    shutil.copytree(ROOT / "_vendor", tmp_path / "_vendor")
    vendor = tmp_path / "_vendor" / "ruamel" / "yaml"
    assert action_locker._vendored_parser_integrity_valid(vendor, tmp_path)

    anchor = vendor / "anchor.py"
    original = anchor.read_bytes()
    anchor.write_bytes(original + b"# modified\n")
    assert not action_locker._vendored_parser_integrity_valid(vendor, tmp_path)

    anchor.write_bytes(original)
    (vendor / "unexpected.py").write_text("pass\n")
    assert not action_locker._vendored_parser_integrity_valid(vendor, tmp_path)


def test_parser_works_with_site_packages_disabled():
    program = r"""
from pathlib import Path
import tempfile
import action_locker

assert action_locker.stable_backend_available()
with tempfile.TemporaryDirectory() as directory:
    root = Path(directory)
    path = root / '.github/workflows/ci.yml'
    path.parent.mkdir(parents=True)
    path.write_text('jobs:\n  test:\n    steps:\n      - uses: actions/checkout@v4\n')
    result = action_locker.StructuralYamlBackend().parse_file(root, path)
    assert result.accepted
    assert [ref.raw_target for ref in result.references] == ['actions/checkout@v4']
"""
    completed = subprocess.run(
        [sys.executable, "-S", "-c", program],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr


def test_stable_is_the_command_default(monkeypatch):
    monkeypatch.delenv("ACTION_LOCKER_PARSER", raising=False)
    args = argparse.Namespace(parser_backend=None)
    assert action_locker._command_parser_name(args) == "stable"
