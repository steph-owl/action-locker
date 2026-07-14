"""Reviewed differential results over commit-pinned public workflows."""

import json
import subprocess
import sys
from pathlib import Path

import pytest

import action_locker


ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "tests" / "fixtures" / "external_parser_corpus"
EXPECTATIONS = json.loads((CORPUS / "EXPECTATIONS.json").read_text())


def test_external_corpus_provenance_and_hashes_are_current():
    completed = subprocess.run(
        [
            sys.executable,
            "scripts/update_external_parser_corpus.py",
            "--check",
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr


@pytest.mark.parametrize("filename", sorted(EXPECTATIONS))
def test_external_corpus_has_reviewed_differential_result(filename):
    expected = EXPECTATIONS[filename]
    path = CORPUS / filename
    stable = action_locker.StructuralYamlBackend().parse_file(CORPUS, path)
    lab = action_locker.LegacyRegexBackend().parse_file(CORPUS, path)

    assert stable.accepted is expected["stable_accepted"]
    assert len(stable.references) == expected["stable_references"]
    assert lab.accepted is expected["lab_accepted"]
    assert len(lab.references) == expected["lab_references"]
    assert action_locker._compare_file(stable, lab) == expected["disagreements"]

    if filename == "python-cpython-build.yml":
        assert [
            (diagnostic.code, diagnostic.line) for diagnostic in lab.diagnostics
        ] == [("LAB_UNSUPPORTED_SYNTAX", 577)]

