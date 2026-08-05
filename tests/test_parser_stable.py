"""Structural `stable` backend tests (ADR 0001 PR 2).

`stable` is the authoritative backend built on Action Locker's pinned,
vendored ruamel.yaml closure. Everything here is offline — ruamel parses
bytes from a path, with no network or ambient package dependency.

Two things are under test: (1) stable's own structural contract — it walks
only the two `uses` slots and fails closed on malformed containers on that
path; and (2) that stable, reading real YAML, correctly handles constructs
lab/0 deliberately refuses (the disagreements compare mode will later
formalize).
"""

import argparse
import json
import sys
from pathlib import Path

import pytest

import action_locker
from action_locker import (
    LegacyRegexBackend,
    StructuralYamlBackend,
    cmd_scan,
)

FIXTURES = Path(__file__).parent / "fixtures" / "parser_lab"


def stable(tmp_path, content, name="ci.yml"):
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True, exist_ok=True)
    (wf / name).write_text(content)
    return StructuralYamlBackend().parse_file(tmp_path, wf / name)


def stable_bytes(tmp_path, raw, name="ci.yml"):
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True, exist_ok=True)
    (wf / name).write_bytes(raw)
    return StructuralYamlBackend().parse_file(tmp_path, wf / name)


def paths_of(r):
    return [x.semantic_path for x in r.references]


def codes_of(r):
    return {d.code for d in r.diagnostics}


@pytest.fixture(autouse=True)
def _quiet(monkeypatch):
    monkeypatch.setenv("ACTION_LOCKER_PARSER_LAB_CI", "1")


# --- canonical discovery ---

class TestStableFinds:
    def test_matches_reviewed_weird_valid_fixture(self):
        r = StructuralYamlBackend().parse_file(FIXTURES, FIXTURES / "weird-valid.yml")
        expected = json.loads((FIXTURES / "weird-valid.expected.json").read_text())
        assert r.accepted is expected["accepted"]
        assert r.diagnostics == ()
        got = [
            {"semantic_path": x.semantic_path, "kind": x.kind,
             "raw_target": x.raw_target, "action": x.action, "ref": x.ref}
            for x in r.references
        ]
        want = sorted(expected["references"], key=lambda r: r["semantic_path"])
        assert got == want

    def test_step_and_job_level_uses(self, tmp_path):
        r = stable(
            tmp_path,
            "jobs:\n"
            "  build:\n    steps:\n      - uses: actions/checkout@v4\n"
            "  shared:\n    uses: org/repo/.github/workflows/x.yml@main\n",
        )
        assert r.accepted and r.backend == "stable"
        by_path = {x.semantic_path: x for x in r.references}
        assert by_path["jobs.build.steps[0].uses"].kind == "external-action"
        assert by_path["jobs.build.steps[0].uses"].action == "actions/checkout"
        assert by_path["jobs.shared.uses"].kind == "reusable-workflow"
        assert by_path["jobs.shared.uses"].action == "org/repo/.github/workflows/x.yml"

    def test_positions_are_one_based(self, tmp_path):
        r = stable(
            tmp_path,
            "jobs:\n  a:\n    steps:\n      - uses: actions/checkout@v4\n",
        )
        (ref,) = r.references
        # `uses:` value begins at column 15 on line 4 — same as lab/0.
        assert (ref.line, ref.column) == (4, 15)

    def test_quoted_and_commented_values(self, tmp_path):
        r = stable(
            tmp_path,
            "jobs:\n  a:\n    steps:\n"
            "      - uses: 'actions/checkout@v4'\n"
            "      - uses: \"actions/setup-python@v5\"  # pinned\n",
        )
        assert r.accepted
        assert [x.raw_target for x in r.references] == [
            "actions/checkout@v4",
            "actions/setup-python@v5",
        ]

    def test_local_and_docker_kinds(self, tmp_path):
        r = stable(
            tmp_path,
            "jobs:\n  a:\n    steps:\n"
            "      - uses: ./local\n"
            "      - uses: docker://alpine:3.20\n",
        )
        assert [x.kind for x in r.references] == ["local-action", "docker-image"]

    def test_no_jobs_is_clean_accept(self, tmp_path):
        r = stable(tmp_path, "name: x\non: push\n")
        assert r.accepted and r.references == () and r.diagnostics == ()

    def test_empty_jobs_mapping_accepts(self, tmp_path):
        r = stable(tmp_path, "jobs: {}\n")
        assert r.accepted and r.references == ()

    def test_bom_and_crlf(self, tmp_path):
        raw = "\ufeffjobs:\r\n  a:\r\n    steps:\r\n      - uses: a/b@v1\r\n".encode()
        r = stable_bytes(tmp_path, raw)
        assert r.accepted
        assert paths_of(r) == ["jobs.a.steps[0].uses"]

    def test_deterministic_sorted_references(self, tmp_path):
        r = stable(
            tmp_path,
            "jobs:\n"
            "  z:\n    steps:\n      - uses: a/b@v1\n"
            "  a:\n    steps:\n      - uses: c/d@v2\n",
        )
        assert paths_of(r) == sorted(paths_of(r))


# --- structural diagnostics: fail closed on the path to `uses` ---

class TestStableDiagnostics:
    def assert_closed(self, r, code):
        assert not r.accepted
        assert code in codes_of(r)
        assert any(d.severity == "error" for d in r.diagnostics)

    def test_yaml_parse_error(self, tmp_path):
        r = stable(tmp_path, "jobs:\n  a:\n  - broken: [unclosed\n")
        self.assert_closed(r, "YAML_PARSE_ERROR")
        assert r.references == ()

    def test_duplicate_key(self, tmp_path):
        r = stable(
            tmp_path,
            "jobs:\n  a:\n    steps:\n"
            "      - uses: a/b@v1\n"
            "        uses: c/d@v2\n",
        )
        self.assert_closed(r, "DUPLICATE_KEY")

    def test_multiple_documents(self, tmp_path):
        r = stable(
            tmp_path,
            "jobs:\n  a:\n    steps:\n      - uses: a/b@v1\n"
            "---\njobs:\n  b:\n    steps:\n      - uses: c/d@v2\n",
        )
        self.assert_closed(r, "MULTIPLE_DOCUMENTS")

    def test_root_not_mapping(self, tmp_path):
        r = stable(tmp_path, "- just\n- a\n- list\n")
        self.assert_closed(r, "ROOT_NOT_MAPPING")

    def test_jobs_not_mapping(self, tmp_path):
        r = stable(tmp_path, "jobs:\n  - a\n  - b\n")
        self.assert_closed(r, "JOBS_NOT_MAPPING")

    def test_job_not_mapping(self, tmp_path):
        r = stable(tmp_path, "jobs:\n  a: just-a-string\n")
        self.assert_closed(r, "JOB_NOT_MAPPING")

    def test_steps_not_sequence(self, tmp_path):
        r = stable(tmp_path, "jobs:\n  a:\n    steps:\n      not: a-list\n")
        self.assert_closed(r, "STEPS_NOT_SEQUENCE")

    def test_step_not_mapping(self, tmp_path):
        r = stable(
            tmp_path,
            "jobs:\n  a:\n    steps:\n      - just-a-string\n",
        )
        self.assert_closed(r, "STEP_NOT_MAPPING")

    def test_uses_not_string_rejects(self, tmp_path):
        for val in ("null", "123", "true", "[a, b]", "{x: 1}"):
            r = stable(
                tmp_path,
                f"jobs:\n  a:\n    steps:\n      - uses: {val}\n",
            )
            self.assert_closed(r, "USES_NOT_STRING")

    def test_invalid_target_is_warning_not_rejection(self, tmp_path):
        r = stable(
            tmp_path,
            "jobs:\n  a:\n    steps:\n      - uses: actions/checkout\n",
        )
        assert r.accepted  # structure was clear; only the value is off
        (ref,) = r.references
        assert (ref.action, ref.ref) == (None, None)
        (d,) = r.diagnostics
        assert d.code == "INVALID_USES_TARGET" and d.severity == "warning"

    def test_malformed_field_off_the_uses_path_is_ignored(self, tmp_path):
        """A broken field that is NOT on the path to a `uses` (here a
        scalar `env`) must not sink the whole scan — that's actionlint's
        job. The real reference is still found and the file accepted."""
        r = stable(
            tmp_path,
            "jobs:\n  a:\n    env: not-a-mapping\n"
            "    steps:\n      - uses: actions/checkout@v4\n",
        )
        assert r.accepted
        assert paths_of(r) == ["jobs.a.steps[0].uses"]


# --- fail-open regressions (found by adversarial review) ---

class TestStableFailClosedRegressions:
    """Every case here was, in a first draft, either a fail-open (accepted
    with a missed/wrong `uses`) or an uncaught crash. All must now fail
    closed: accepted=False, a diagnostic, and no crash."""

    def assert_closed(self, r, code):
        assert not r.accepted
        assert code in codes_of(r)
        assert any(d.severity == "error" for d in r.diagnostics)

    def test_tagged_uses_key_in_step_is_not_a_fail_open(self, tmp_path):
        # `!!str uses` decodes to the key `uses` and RUNS on GitHub, but
        # ruamel gives a TaggedScalar that dodges `"uses" in step`. Must
        # reject, never return accepted=True with zero references.
        r = stable(
            tmp_path,
            "jobs:\n  a:\n    steps:\n      - !!str uses: attacker/exfil@main\n",
        )
        self.assert_closed(r, "NON_STRING_KEY")
        assert r.references == ()

    def test_tagged_uses_key_at_job_level(self, tmp_path):
        r = stable(
            tmp_path,
            "jobs:\n  a:\n    !!str uses: attacker/wf/.github/workflows/w.yml@v1\n",
        )
        self.assert_closed(r, "NON_STRING_KEY")

    def test_tagged_jobs_key_at_root(self, tmp_path):
        r = stable(
            tmp_path,
            "!!str jobs:\n  a:\n    steps:\n      - uses: attacker/exfil@main\n",
        )
        self.assert_closed(r, "NON_STRING_KEY")

    def test_tagged_key_does_not_mask_via_valid_siblings(self, tmp_path):
        """The insidious case: a clean step plus a tag-hidden step. The
        whole file must be rejected, not returned as a tidy one-ref scan."""
        r = stable(
            tmp_path,
            "jobs:\n  b:\n    steps:\n"
            "      - uses: actions/checkout@v4\n"
            "      - !!str uses: attacker/exfil@main\n",
        )
        assert not r.accepted
        assert "NON_STRING_KEY" in codes_of(r)

    def test_non_string_job_id_fails_closed(self, tmp_path):
        for jid in ("1", "true", "~"):
            r = stable(
                tmp_path,
                f"jobs:\n  {jid}:\n    steps:\n      - uses: a/b@v1\n",
            )
            self.assert_closed(r, "NON_STRING_KEY")

    def test_recursion_bomb_fails_closed_not_crash(self, tmp_path):
        # A ~1 KB nesting bomb must not abort the scan with an uncaught
        # RecursionError — it must reject THIS file and let siblings scan.
        r = stable(tmp_path, "jobs: " + "[" * 400 + "]" * 400 + "\n")
        self.assert_closed(r, "YAML_PARSE_ERROR")

    def test_recursion_bomb_does_not_abort_whole_scan(self, tmp_path):
        """cmd_scan parses every file in one generator; one bomb must not
        take the rest down."""
        wf = tmp_path / ".github" / "workflows"
        wf.mkdir(parents=True)
        (wf / "aaa_bomb.yml").write_text("jobs: " + "[" * 400 + "]" * 400 + "\n")
        (wf / "bbb_good.yml").write_text(
            "jobs:\n  a:\n    steps:\n      - uses: actions/checkout@v4\n"
        )
        args = argparse.Namespace(parser_backend="stable", format="json")
        with pytest.raises(SystemExit) as exc:
            cmd_scan(args, tmp_path)
        assert exc.value.code == 1  # rejected, cleanly — not a crash

    def test_yaml_version_directive_fails_closed(self, tmp_path):
        # `%YAML 1.3` trips ruamel's version assert (an AssertionError, not
        # a YAMLError) — must be caught and rejected.
        r = stable(
            tmp_path,
            "%YAML 1.3\n---\njobs:\n  a:\n    steps:\n      - uses: a/b@v1\n",
        )
        self.assert_closed(r, "YAML_PARSE_ERROR")

    def test_unconstructable_standard_tags_fail_closed(self, tmp_path):
        # ruamel constructors raise bare ValueError/KeyError/etc. (not
        # YAMLError) on these — must fail closed, never crash.
        for tag in ("!!int a/b@v1", "!!bool a/b@v1", "!!omap x", "!!float true"):
            r = stable(
                tmp_path,
                f"jobs:\n  a:\n    steps:\n      - uses: {tag}\n",
            )
            assert not r.accepted
            assert codes_of(r) & {"YAML_PARSE_ERROR", "USES_NOT_STRING"}

    def test_oversize_input_fails_closed(self, tmp_path):
        import action_locker
        wf = tmp_path / ".github" / "workflows"
        wf.mkdir(parents=True)
        big = "# " + "x" * (action_locker.STABLE_MAX_BYTES + 10) + "\njobs: {}\n"
        (wf / "ci.yml").write_text(big)
        r = StructuralYamlBackend().parse_file(tmp_path, wf / "ci.yml")
        self.assert_closed(r, "YAML_PARSE_ERROR")

    def test_merge_key_resolves_and_stays_accepted(self, tmp_path):
        # ruamel resolves `<<` — the merged `uses` IS visible, so this is a
        # correct accept, not a miss. Locks in that merge keys aren't a
        # fail-open.
        r = stable(
            tmp_path,
            "jobs:\n  a:\n    steps:\n"
            "      - <<: &base\n          uses: actions/checkout@v4\n"
            "        name: checkout\n",
        )
        assert r.accepted
        assert paths_of(r) == ["jobs.a.steps[0].uses"]
        assert r.references[0].raw_target == "actions/checkout@v4"

    def test_duplicate_semantic_path_invariant_enforced(self, tmp_path, monkeypatch):
        """The DUPLICATE_PATH guard is a backstop. Force a collision by
        making classification emit a fixed path, and confirm it's caught."""
        import action_locker
        real = action_locker._stable_emit

        def collide(rel, path, value, job_level, line, col, refs, diag):
            real(rel, "jobs.x.uses", value, job_level, line, col, refs, diag)

        monkeypatch.setattr(action_locker, "_stable_emit", collide)
        r = stable(
            tmp_path,
            "jobs:\n"
            "  a:\n    steps:\n      - uses: a/b@v1\n"
            "  b:\n    steps:\n      - uses: c/d@v2\n",
        )
        assert not r.accepted
        assert "DUPLICATE_PATH" in codes_of(r)


# --- security: round-trip mode constructs no Python objects ---

class TestStableSafety:
    def test_python_tag_does_not_execute_and_fails_closed(self, tmp_path):
        sentinel = tmp_path / "PWNED"
        r = stable(
            tmp_path,
            "jobs:\n  a:\n    steps:\n"
            f"      - uses: !!python/object/apply:os.system ['touch {sentinel}']\n",
        )
        assert not sentinel.exists()          # never executed
        assert not r.accepted                 # tagged node is not a string
        assert "USES_NOT_STRING" in codes_of(r)

    def test_undecodable_bytes_fail_closed(self, tmp_path):
        r = stable_bytes(tmp_path, b"\xff\xfe jobs:\n")
        assert not r.accepted
        assert r.references == ()


# --- differential: stable handles what lab/0 refuses ---

class TestStableVsLab:
    """Both backends are 'safe' — neither silently pins the wrong thing —
    but stable reads real YAML where lab/0 fails closed. These are the
    disagreements compare mode (next) will formalize into fixtures."""

    def _both(self, tmp_path, content):
        wf = tmp_path / ".github" / "workflows"
        wf.mkdir(parents=True, exist_ok=True)
        (wf / "ci.yml").write_text(content)
        p = wf / "ci.yml"
        return (
            StructuralYamlBackend().parse_file(tmp_path, p),
            LegacyRegexBackend().parse_file(tmp_path, p),
        )

    def test_anchor_alias_resolved_by_stable_refused_by_lab(self, tmp_path):
        content = (
            "jobs:\n  a:\n    steps:\n"
            "      - &s\n        uses: actions/checkout@v4\n"
            "      - *s\n"
        )
        s, lab = self._both(tmp_path, content)
        # stable resolves the alias into a second, identical step.
        assert s.accepted
        assert paths_of(s) == ["jobs.a.steps[0].uses", "jobs.a.steps[1].uses"]
        assert {x.raw_target for x in s.references} == {"actions/checkout@v4"}
        # lab/0 refuses anchors rather than guess — fail closed, not empty.
        assert not lab.accepted

    def test_multiline_flow_step_read_by_stable_refused_by_lab(self, tmp_path):
        content = (
            "jobs:\n  build:\n    steps:\n"
            "      - { name: checkout,\n"
            "          uses: actions/checkout@v4 }\n"
        )
        s, lab = self._both(tmp_path, content)
        assert s.accepted
        (ref,) = s.references
        assert ref.raw_target == "actions/checkout@v4"  # no glued `}`
        assert not lab.accepted

    def test_agreement_on_ordinary_workflow(self, tmp_path):
        content = (
            "jobs:\n"
            "  build:\n    steps:\n"
            "      - uses: actions/checkout@v4\n"
            "      - name: setup\n        uses: actions/setup-python@v5\n"
            "  shared:\n    uses: org/repo/.github/workflows/x.yml@main\n"
        )
        s, lab = self._both(tmp_path, content)
        assert s.accepted and lab.accepted

        def norm(r):
            return {(x.semantic_path, x.kind, x.raw_target) for x in r.references}

        assert norm(s) == norm(lab)


# --- the scan command with --parser stable ---

class TestScanStableCli:
    def run(self, repo_root, fmt="json", parser="stable"):
        args = argparse.Namespace(parser_backend=parser, format=fmt)
        with pytest.raises(SystemExit) as exc:
            cmd_scan(args, repo_root)
        return exc.value.code

    def test_scan_stable_exit_0_and_backend_name(self, owl_repo, capsys):
        assert self.run(owl_repo) == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["backend"] == "stable"
        assert payload["schema_version"] == 1
        assert payload["accepted"] is True

    def test_scan_stable_rejects_with_exit_1(self, tmp_path, capsys):
        wf = tmp_path / ".github" / "workflows"
        wf.mkdir(parents=True)
        (wf / "bad.yml").write_text("jobs:\n  a:\n    steps:\n      - uses: 123\n")
        assert self.run(tmp_path) == 1
        payload = json.loads(capsys.readouterr().out)
        assert payload["accepted"] is False
        codes = {d["code"] for f in payload["files"] for d in f["diagnostics"]}
        assert "USES_NOT_STRING" in codes

    def test_env_var_selects_stable(self, owl_repo, monkeypatch, capsys):
        monkeypatch.setenv("ACTION_LOCKER_PARSER", "stable")
        args = argparse.Namespace(parser_backend=None, format="json")
        with pytest.raises(SystemExit) as exc:
            cmd_scan(args, owl_repo)
        assert exc.value.code == 0
        assert json.loads(capsys.readouterr().out)["backend"] == "stable"

    def test_unavailable_ruamel_exits_4_not_1(self, owl_repo, monkeypatch, capsys):
        """If the optional dep is missing, stable is UNAVAILABLE (4), never
        a silent fall back to another backend or a rejection (1)."""
        monkeypatch.setattr(action_locker, "stable_backend_available", lambda: False)
        assert self.run(owl_repo) == 4
        assert "ruamel.yaml" in capsys.readouterr().err

    def test_scan_stable_is_read_only(self, owl_repo, capsys):
        wf_dir = owl_repo / ".github" / "workflows"
        before = {p.name: p.read_bytes() for p in wf_dir.iterdir()}
        assert self.run(owl_repo) == 0
        after = {p.name: p.read_bytes() for p in wf_dir.iterdir()}
        assert before == after
        capsys.readouterr()
