"""Differential `compare` mode tests (ADR 0001 PR 2, final piece).

compare runs lab/0 and the authoritative stable backend over the same bytes
and diffs their normalized results. It needs ruamel (via stable), so the
module skips when ruamel is absent.

The distinction under test is the one that makes compare useful without
becoming false confidence: an EXPECTED disagreement (stable reads what lab
deliberately fails closed on) versus an ACTIONABLE one (lab accepting what
stable rejects, or the two accepting DIFFERENT references — a real bug in
one backend). Everything here is offline.
"""

import argparse
import json
from pathlib import Path

import pytest

pytest.importorskip("ruamel.yaml")

import action_locker
from action_locker import (
    ParseResult,
    WorkflowReference,
    _compare_file,
    cmd_scan,
)


def res(backend, accepted, refs=(), diags=()):
    return ParseResult(backend, tuple(refs), tuple(diags), accepted)


def ref(path, kind="external-action", target="a/b@v1", action="a/b", r="v1"):
    return WorkflowReference("f", path, kind, target, action, r, 1, 1)


def classes(dis):
    return [(d["class"], d["expected"]) for d in dis]


@pytest.fixture(autouse=True)
def _quiet(monkeypatch):
    monkeypatch.setenv("ACTION_LOCKER_PARSER_LAB_CI", "1")


# --- the comparison core ---

class TestCompareFile:
    def test_identical_results_agree(self):
        s = res("stable", True, [ref("jobs.a.steps[0].uses")])
        l = res("lab/0", True, [ref("jobs.a.steps[0].uses")])
        assert _compare_file(s, l) == []

    def test_both_rejected_is_agreement(self):
        assert _compare_file(res("stable", False), res("lab/0", False)) == []

    def test_stable_accepts_lab_rejects_is_expected(self):
        s = res("stable", True, [ref("jobs.a.steps[0].uses")])
        l = res("lab/0", False)
        assert classes(_compare_file(s, l)) == [("ACCEPTANCE_MISMATCH", True)]

    def test_lab_accepts_stable_rejects_is_actionable(self):
        s = res("stable", False)
        l = res("lab/0", True, [ref("jobs.a.steps[0].uses")])
        (d,) = _compare_file(s, l)
        assert d["class"] == "ACCEPTANCE_MISMATCH" and d["expected"] is False

    def test_acceptance_gate_ignores_rejecting_sides_partial_refs(self):
        """A rejected result can still carry PARTIAL references (a backend
        appends a step's `uses` before hitting a later malformed step and
        failing closed). The acceptance gate must diff nothing against that
        untrustworthy list — even when the partial refs DIFFER from the
        accepting side's — emitting only ACCEPTANCE_MISMATCH. Tested both
        directions so no path-level class can leak from a rejected map."""
        # lab rejects but carries a differing partial ref
        s1 = res("stable", True, [ref("jobs.a.steps[0].uses", target="a/b@v1")])
        l1 = res("lab/0", False, [ref("jobs.a.steps[0].uses", target="other@v9")])
        assert [d["class"] for d in _compare_file(s1, l1)] == ["ACCEPTANCE_MISMATCH"]
        # stable rejects mid-walk with a differing partial ref; lab accepts
        s2 = res("stable", False, [ref("jobs.a.steps[0].uses", target="a/b@v1")])
        l2 = res("lab/0", True, [ref("jobs.a.steps[0].uses", target="other@v9")])
        d2 = _compare_file(s2, l2)
        assert [d["class"] for d in d2] == ["ACCEPTANCE_MISMATCH"]
        assert d2[0]["expected"] is False  # lab accepts what stable rejects

    def test_target_mismatch_when_both_accept(self):
        s = res("stable", True, [ref("jobs.a.steps[0].uses", target="a/b@v5", r="v5")])
        l = res("lab/0", True, [ref("jobs.a.steps[0].uses", target="a/b@v4", r="v4")])
        (d,) = _compare_file(s, l)
        assert d["class"] == "TARGET_MISMATCH" and d["expected"] is False
        assert d["stable"] == "a/b@v5" and d["lab"] == "a/b@v4"

    def test_kind_mismatch_same_path_and_target(self):
        t = "o/r/.github/workflows/w.yml@v1"
        s = res("stable", True, [ref("jobs.a.uses", kind="reusable-workflow", target=t)])
        l = res("lab/0", True, [ref("jobs.a.uses", kind="external-action", target=t)])
        (d,) = _compare_file(s, l)
        assert d["class"] == "KIND_MISMATCH"
        assert d["stable"] == "reusable-workflow" and d["lab"] == "external-action"

    def test_missing_reference_lab_underscanned(self):
        s = res("stable", True, [ref("jobs.a.steps[0].uses"),
                                 ref("jobs.a.steps[1].uses", target="c/d@v2")])
        l = res("lab/0", True, [ref("jobs.a.steps[0].uses")])
        (d,) = _compare_file(s, l)
        assert d["class"] == "MISSING_REFERENCE"
        assert d["semantic_path"] == "jobs.a.steps[1].uses"
        assert d["stable"] == "c/d@v2" and d["lab"] is None

    def test_extra_reference_lab_overscanned(self):
        s = res("stable", True, [ref("jobs.a.steps[0].uses")])
        l = res("lab/0", True, [ref("jobs.a.steps[0].uses"),
                                ref("jobs.a.steps[1].uses", target="c/d@v2")])
        (d,) = _compare_file(s, l)
        assert d["class"] == "EXTRA_REFERENCE" and d["lab"] == "c/d@v2"

    def test_duplicate_path_detected_per_backend(self):
        s = res("stable", True, [ref("jobs.a.uses"), ref("jobs.a.uses", target="c/d@v2")])
        l = res("lab/0", True, [ref("jobs.a.uses")])
        codes = classes(_compare_file(s, l))
        assert ("DUPLICATE_PATH", False) in codes

    def test_line_column_never_cause_disagreement(self):
        """Identity is (kind, raw_target) — positions differ between
        backends and must not register as a disagreement."""
        s = ParseResult("stable", (WorkflowReference(
            "f", "jobs.a.steps[0].uses", "external-action", "a/b@v1", "a/b", "v1",
            4, 15),), (), True)
        l = ParseResult("lab/0", (WorkflowReference(
            "f", "jobs.a.steps[0].uses", "external-action", "a/b@v1", "a/b", "v1",
            9, 2),), (), True)
        assert _compare_file(s, l) == []

    def test_disagreements_sort_by_class_priority(self):
        # Within a file, more-actionable classes come first (TARGET before
        # MISSING). (ACCEPTANCE_MISMATCH can't co-occur — it returns early
        # as the sole disagreement — so cross-class-with-acceptance ordering
        # isn't reachable and isn't asserted here.)
        s = res("stable", True, [
            ref("jobs.a.steps[0].uses", target="a/b@v5", r="v5"),   # target mismatch
            ref("jobs.a.steps[1].uses", target="c/d@v2"),           # missing in lab
        ])
        l = res("lab/0", True, [ref("jobs.a.steps[0].uses", target="a/b@v4", r="v4")])
        order = [d["class"] for d in _compare_file(s, l)]
        assert order.index("TARGET_MISMATCH") < order.index("MISSING_REFERENCE")


# --- the CLI ---

class TestCompareCli:
    def run(self, repo_root, fmt="json"):
        args = argparse.Namespace(parser_backend="compare", format=fmt)
        with pytest.raises(SystemExit) as exc:
            cmd_scan(args, repo_root)
        return exc.value.code

    def _wf(self, tmp_path, name, content):
        wf = tmp_path / ".github" / "workflows"
        wf.mkdir(parents=True, exist_ok=True)
        (wf / name).write_text(content)

    def test_agreement_exits_0(self, owl_repo, capsys):
        assert self.run(owl_repo) == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["agreement"] is True
        assert payload["actionable"] is False
        assert payload["authoritative_backend"] == "stable"
        assert payload["backends"] == {"stable": "stable", "lab": "lab/0"}
        assert all(f["agreement"] for f in payload["files"])

    def test_expected_disagreement_exits_3_but_flagged_expected(self, tmp_path, capsys):
        # An anchor: stable resolves it, lab fails closed. Disagreement, but
        # the benign kind.
        self._wf(tmp_path, "ci.yml",
                 "jobs:\n  a:\n    steps:\n"
                 "      - &s\n        uses: actions/checkout@v4\n      - *s\n")
        assert self.run(tmp_path) == 3
        payload = json.loads(capsys.readouterr().out)
        assert payload["agreement"] is False
        assert payload["actionable"] is False   # nothing to act on
        (f,) = payload["files"]
        (d,) = f["disagreements"]
        assert d["class"] == "ACCEPTANCE_MISMATCH" and d["expected"] is True

    def test_actionable_disagreement_sets_actionable_flag(self, tmp_path, monkeypatch, capsys):
        # Force a genuine both-accept divergence (rare in the wild — that's
        # the point) by making lab report a different target.
        self._wf(tmp_path, "ci.yml",
                 "jobs:\n  a:\n    steps:\n      - uses: actions/checkout@v4\n")
        real = action_locker.LegacyRegexBackend.parse_file

        def skew(self, repo_root, path):
            r = real(self, repo_root, path)
            if r.references:
                bad = action_locker.WorkflowReference(
                    r.references[0].file, r.references[0].semantic_path,
                    "external-action", "actions/checkout@v999", "actions/checkout",
                    "v999", 1, 1)
                return action_locker.ParseResult(r.backend, (bad,), r.diagnostics, True)
            return r

        monkeypatch.setattr(action_locker.LegacyRegexBackend, "parse_file", skew)
        assert self.run(tmp_path) == 3
        payload = json.loads(capsys.readouterr().out)
        assert payload["agreement"] is False and payload["actionable"] is True
        (d,) = payload["files"][0]["disagreements"]
        assert d["class"] == "TARGET_MISMATCH" and d["expected"] is False

    def test_both_reject_agrees_but_authoritative_rejected_exits_1(self, tmp_path, capsys):
        # Multiple documents: both backends reject. They AGREE (no
        # disagreement) but the authoritative parser rejected -> exit 1.
        self._wf(tmp_path, "ci.yml",
                 "jobs:\n  a:\n    steps:\n      - uses: a/b@v1\n"
                 "---\njobs:\n  b:\n    steps:\n      - uses: c/d@v2\n")
        assert self.run(tmp_path) == 1
        payload = json.loads(capsys.readouterr().out)
        assert payload["agreement"] is True
        assert payload["files"][0]["stable"]["accepted"] is False
        assert payload["files"][0]["lab"]["accepted"] is False

    def test_text_format_has_disagreement_header(self, tmp_path, capsys):
        self._wf(tmp_path, "ci.yml",
                 "jobs:\n  a:\n    steps:\n"
                 "      - &s\n        uses: actions/checkout@v4\n      - *s\n")
        assert self.run(tmp_path, fmt="text") == 3
        out = capsys.readouterr().out
        assert "PARSER DISAGREEMENT" in out
        assert "ACCEPTANCE_MISMATCH (expected)" in out

    def test_deterministic_json(self, owl_repo, capsys):
        assert self.run(owl_repo) == 0
        first = capsys.readouterr().out
        assert self.run(owl_repo) == 0
        assert first == capsys.readouterr().out

    def test_unavailable_ruamel_exits_4(self, owl_repo, monkeypatch, capsys):
        monkeypatch.setattr(action_locker, "stable_backend_available", lambda: False)
        assert self.run(owl_repo) == 4
        assert "ruamel.yaml" in capsys.readouterr().err

    def test_env_var_selects_compare(self, owl_repo, monkeypatch, capsys):
        monkeypatch.setenv("ACTION_LOCKER_PARSER", "compare")
        args = argparse.Namespace(parser_backend=None, format="json")
        with pytest.raises(SystemExit) as exc:
            cmd_scan(args, owl_repo)
        assert exc.value.code == 0
        assert json.loads(capsys.readouterr().out)["authoritative_backend"] == "stable"

    def test_compare_is_read_only(self, owl_repo, capsys):
        wf_dir = owl_repo / ".github" / "workflows"
        before = {p.name: p.read_bytes() for p in wf_dir.iterdir()}
        self.run(owl_repo)
        after = {p.name: p.read_bytes() for p in wf_dir.iterdir()}
        assert before == after
        capsys.readouterr()

    def test_empty_repo_agrees(self, tmp_path, capsys):
        (tmp_path / ".github" / "workflows").mkdir(parents=True)
        assert self.run(tmp_path) == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["agreement"] is True and payload["files"] == []
