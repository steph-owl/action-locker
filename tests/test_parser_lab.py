"""Parser-lab PR 1 tests: the lab/0 backend and the `scan` command.

Everything here is offline. The corpus fixture weird-valid.yml comes from
the parser-lab design bundle (ADR 0001); its expected results are the
hand-reviewed weird-valid.expected.json next to it.

The lab/0 contract under test: every `uses:`-shaped line is either emitted
as a reference with a semantic path, safely excluded (full-line comment or
block-scalar body), or reported as an error diagnostic with accepted=False.
Uncertainty must never look like "no references".
"""

import argparse
import json
import sys
import time
from pathlib import Path

import pytest

import action_locker
from action_locker import (
    LegacyRegexBackend,
    classify_uses_target,
    cmd_scan,
    parse_workflows,
)

FIXTURES = Path(__file__).parent / "fixtures" / "parser_lab"


def scan_text(tmp_path, content, name="ci.yml"):
    """Write one workflow into a tmp repo and parse it with lab/0."""
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True, exist_ok=True)
    (wf / name).write_text(content)
    return LegacyRegexBackend().parse_file(tmp_path, wf / name)


def paths_of(result):
    return [r.semantic_path for r in result.references]


def codes_of(result):
    return {d.code for d in result.diagnostics}


def run_scan(repo_root, fmt="json", parser="lab"):
    args = argparse.Namespace(parser_backend=parser, format=fmt)
    with pytest.raises(SystemExit) as exc:
        cmd_scan(args, repo_root)
    return exc.value.code


@pytest.fixture(autouse=True)
def _quiet_lab_warning(monkeypatch):
    """Keep the experimental-backend stderr note out of most tests; the
    warning itself is asserted explicitly in TestScanCli."""
    monkeypatch.setenv("ACTION_LOCKER_PARSER_LAB_CI", "1")


# --- the reviewed corpus fixture ---

class TestWeirdValidFixture:
    def test_matches_reviewed_expected_results(self):
        result = LegacyRegexBackend().parse_file(
            FIXTURES, FIXTURES / "weird-valid.yml"
        )
        expected = json.loads(
            (FIXTURES / "weird-valid.expected.json").read_text()
        )
        assert result.accepted is expected["accepted"]
        assert result.diagnostics == ()
        got = [
            {
                "semantic_path": r.semantic_path,
                "kind": r.kind,
                "raw_target": r.raw_target,
                "action": r.action,
                "ref": r.ref,
            }
            for r in result.references
        ]
        want = sorted(expected["references"], key=lambda r: r["semantic_path"])
        assert got == want


# --- canonical discovery ---

class TestLabFinds:
    def test_step_level_plain_uses(self, tmp_path):
        r = scan_text(
            tmp_path,
            "jobs:\n  build:\n    steps:\n      - uses: actions/checkout@v4\n",
        )
        assert r.accepted
        assert r.backend == "lab/0"
        (ref,) = r.references
        assert ref.semantic_path == "jobs.build.steps[0].uses"
        assert ref.kind == "external-action"
        assert ref.raw_target == "actions/checkout@v4"
        assert (ref.action, ref.ref) == ("actions/checkout", "v4")
        assert (ref.line, ref.column) == (4, 15)
        assert (ref.end_line, ref.end_column) == (None, None)

    def test_job_level_reusable_workflow(self, tmp_path):
        r = scan_text(
            tmp_path,
            "jobs:\n  shared:\n"
            "    uses: org/repo/.github/workflows/x.yml@main\n",
        )
        assert r.accepted
        (ref,) = r.references
        assert ref.semantic_path == "jobs.shared.uses"
        assert ref.kind == "reusable-workflow"
        assert ref.action == "org/repo/.github/workflows/x.yml"
        assert ref.ref == "main"

    def test_quoted_values_and_trailing_comments(self, tmp_path):
        r = scan_text(
            tmp_path,
            "jobs:\n  a:\n    steps:\n"
            "      - uses: 'actions/checkout@v4'\n"
            "      - uses: \"actions/setup-python@v5\"  # pinned later\n"
            "      - uses: dorny/paths-filter@v3  # v3\n",
        )
        assert r.accepted
        assert [ref.raw_target for ref in r.references] == [
            "actions/checkout@v4",
            "actions/setup-python@v5",
            "dorny/paths-filter@v3",
        ]

    def test_sha_pinned_ref_with_comment(self, tmp_path):
        sha = "34e114876b0b11c390a56381ad16ebd13914f8d5"
        r = scan_text(
            tmp_path,
            f"jobs:\n  a:\n    steps:\n      - uses: actions/checkout@{sha}  # v4\n",
        )
        (ref,) = r.references
        assert ref.ref == sha
        assert ref.raw_target == f"actions/checkout@{sha}"

    def test_step_indices_skip_comments_and_count_non_uses_steps(self, tmp_path):
        r = scan_text(
            tmp_path,
            "jobs:\n  a:\n    steps:\n"
            "      # a full-line comment is not a step\n"
            "      - name: scripted\n"
            "        run: echo hello\n"
            "      - uses: actions/checkout@v4\n",
        )
        assert r.accepted
        assert paths_of(r) == ["jobs.a.steps[1].uses"]

    def test_lone_dash_and_items_at_steps_key_indent(self, tmp_path):
        r = scan_text(
            tmp_path,
            "jobs:\n"
            "  a:\n"
            "    steps:\n"
            "    - name: one\n"
            "      run: echo hi\n"
            "    -\n"
            "      uses: actions/checkout@v4\n",
        )
        assert r.accepted
        assert paths_of(r) == ["jobs.a.steps[1].uses"]

    def test_multiple_jobs_reset_state(self, tmp_path):
        r = scan_text(
            tmp_path,
            "jobs:\n"
            "  one:\n    steps:\n      - uses: a/b@v1\n"
            "  two:\n    uses: c/d/.github/workflows/w.yml@v2\n"
            "  three:\n    steps:\n      - uses: e/f@v3\n",
        )
        assert r.accepted
        assert sorted(paths_of(r)) == [
            "jobs.one.steps[0].uses",
            "jobs.three.steps[0].uses",
            "jobs.two.uses",
        ]

    def test_local_and_docker_not_lockable_external(self, tmp_path):
        r = scan_text(
            tmp_path,
            "jobs:\n  a:\n    steps:\n"
            "      - uses: ./local/action\n"
            "      - uses: docker://alpine:3.20\n",
        )
        assert r.accepted
        kinds = [ref.kind for ref in r.references]
        assert kinds == ["local-action", "docker-image"]
        assert all(ref.action is None and ref.ref is None for ref in r.references)

    def test_crlf_and_bom_tolerated(self, tmp_path):
        wf = tmp_path / ".github" / "workflows"
        wf.mkdir(parents=True)
        content = "jobs:\r\n  a:\r\n    steps:\r\n      - uses: a/b@v1\r\n"
        (wf / "ci.yml").write_bytes(b"\xef\xbb\xbf" + content.encode())
        r = LegacyRegexBackend().parse_file(tmp_path, wf / "ci.yml")
        assert r.accepted
        assert paths_of(r) == ["jobs.a.steps[0].uses"]

    def test_no_references_is_a_clean_accept(self, tmp_path):
        r = scan_text(tmp_path, "name: nothing\non: push\njobs: {}\n")
        assert r.accepted
        assert r.references == ()
        assert r.diagnostics == ()


# --- safe exclusions ---

class TestLabExclusions:
    def test_full_line_comment_ignored(self, tmp_path):
        r = scan_text(
            tmp_path,
            "jobs:\n  a:\n    steps:\n"
            "      # uses: fake/comment@v1\n"
            "      - uses: real/action@v1\n",
        )
        assert r.accepted
        assert [ref.raw_target for ref in r.references] == ["real/action@v1"]

    def test_block_scalar_body_ignored(self, tmp_path):
        r = scan_text(
            tmp_path,
            "jobs:\n  a:\n    steps:\n"
            "      - name: misleading\n"
            "        run: |\n"
            "          echo 'uses: fake/script@v2'\n"
            "          cat <<'EOF'\n"
            "          - uses: fake/heredoc@v3\n"
            "          EOF\n"
            "      - uses: real/action@v1\n",
        )
        assert r.accepted
        assert paths_of(r) == ["jobs.a.steps[1].uses"]
        assert [ref.raw_target for ref in r.references] == ["real/action@v1"]

    def test_folded_and_chomped_block_scalars(self, tmp_path):
        for header in (">", ">-", "|-", "|+"):
            r = scan_text(
                tmp_path,
                "jobs:\n  a:\n    steps:\n"
                f"      - run: {header}\n"
                "          uses: fake/x@v1\n"
                "      - uses: real/action@v1\n",
            )
            assert r.accepted, header
            assert paths_of(r) == ["jobs.a.steps[1].uses"], header

    def test_comment_looking_line_inside_block_is_content(self, tmp_path):
        r = scan_text(
            tmp_path,
            "jobs:\n  a:\n    steps:\n"
            "      - run: |\n"
            "          # uses: fake/x@v1\n"
            "\n"
            "          echo 'uses: fake/y@v2'\n"
            "      - uses: real/action@v1\n",
        )
        assert r.accepted
        assert paths_of(r) == ["jobs.a.steps[1].uses"]

    def test_sibling_key_after_block_scalar_is_live(self, tmp_path):
        """A `uses:` at the SAME indent as the block key ends the block —
        it is executable and must be found, not swallowed as content."""
        r = scan_text(
            tmp_path,
            "jobs:\n  a:\n    steps:\n"
            "      - run: |\n"
            "          echo hi\n"
            "        uses: real/action@v1\n",
        )
        assert r.accepted
        assert paths_of(r) == ["jobs.a.steps[0].uses"]


# --- fail closed: uncertainty is never absence ---

class TestLabFailClosed:
    def assert_rejected(self, result, code):
        assert not result.accepted
        assert code in codes_of(result)
        errors = [d for d in result.diagnostics if d.severity == "error"]
        assert errors, "a rejected file must explain itself"

    def test_plain_scalar_mentioning_uses_rejects_file(self, tmp_path):
        r = scan_text(
            tmp_path,
            "jobs:\n  a:\n    steps:\n      - run: echo 'uses: fake/x@v1'\n",
        )
        self.assert_rejected(r, "LAB_UNCLASSIFIED_USES")

    def test_uses_outside_jobs_rejects(self, tmp_path):
        r = scan_text(tmp_path, "on: push\nuses: evil/x@v1\n")
        self.assert_rejected(r, "LAB_UNCLASSIFIED_USES")
        assert r.references == ()

    def test_uses_under_with_rejects_but_keeps_real_reference(self, tmp_path):
        r = scan_text(
            tmp_path,
            "jobs:\n  a:\n    steps:\n"
            "      - uses: real/action@v1\n"
            "        with:\n"
            "          uses: not-executable\n",
        )
        self.assert_rejected(r, "LAB_UNCLASSIFIED_USES")
        # The confidently-classified reference is still reported alongside
        # the rejection: rejection means "incomplete", not "empty".
        assert [ref.raw_target for ref in r.references] == ["real/action@v1"]

    def test_quoted_uses_key_rejects(self, tmp_path):
        """`"uses":` is a real executable key on GitHub but invisible to the
        legacy regex — lab/0 must at least refuse to claim a complete scan."""
        r = scan_text(
            tmp_path,
            'jobs:\n  a:\n    steps:\n      - "uses": evil/x@v1\n',
        )
        self.assert_rejected(r, "LAB_UNSUPPORTED_SYNTAX")
        assert r.references == ()

    def test_escaped_quoted_uses_key_rejects(self, tmp_path):
        """The critical fail-open the adversarial review found: a step key
        written `"us\\u0065s":` decodes to `uses` and RUNS on GitHub, but
        shares no literal bytes with `uses`, so a name-based net can't see
        it. lab/0 must reject the file (accepted=False), never claim a
        clean empty scan. Covers step-level, job-level, and the insidious
        mixed-file case where real refs mask the hidden one."""
        # On disk the key line is: - "uses": evil/pwn@v1
        r = scan_text(
            tmp_path,
            'jobs:\n  a:\n    steps:\n'
            '      - "us\\u0065s": evil/pwn@v1\n',
        )
        self.assert_rejected(r, "LAB_UNSUPPORTED_SYNTAX")
        assert r.references == ()

        job = scan_text(
            tmp_path,
            'jobs:\n  a:\n'
            '    "us\\u0065s": evil/pwn/.github/workflows/w.yml@v1\n',
            name="job.yml",
        )
        self.assert_rejected(job, "LAB_UNSUPPORTED_SYNTAX")

        mixed = scan_text(
            tmp_path,
            'jobs:\n  build:\n    steps:\n'
            '      - uses: actions/checkout@v4\n'
            '      - "us\\u0065s": evil/pwn@v1\n',
            name="mixed.yml",
        )
        # A populated, legitimate-looking list must NOT come back accepted
        # while an executable ref is silently dropped.
        assert not mixed.accepted

    def test_single_quoted_uses_key_rejects(self, tmp_path):
        r = scan_text(
            tmp_path,
            "jobs:\n  a:\n    steps:\n      - 'uses': evil/x@v1\n",
        )
        self.assert_rejected(r, "LAB_UNSUPPORTED_SYNTAX")

    def test_quoted_scalar_step_and_matrix_items_not_misread_as_keys(self, tmp_path):
        """A quoted scalar in SEQUENCE position (no trailing colon) is a
        value, not a key — the quoted-key guard must not reject it, or
        every matrix version list would fail. Here the matrix items are
        accepted (ignored, not a uses slot) and the real ref is found."""
        r = scan_text(
            tmp_path,
            "jobs:\n"
            "  a:\n"
            "    strategy:\n"
            "      matrix:\n"
            "        python:\n"
            '          - "3.9"\n'
            '          - "3.10"\n'
            "    steps:\n"
            "      - uses: actions/checkout@v4\n",
        )
        assert r.accepted
        assert paths_of(r) == ["jobs.a.steps[0].uses"]

    def test_multiline_flow_step_rejects(self, tmp_path):
        """A `{ ... }` flow-mapping step spanning lines: the closing `}`
        was being glued onto raw_target/ref while the file was accepted.
        Now the open flow is detected and the file rejected."""
        r = scan_text(
            tmp_path,
            "jobs:\n  build:\n    steps:\n"
            "      - { name: checkout,\n"
            "          uses: actions/checkout@v4 }\n",
        )
        assert not r.accepted
        assert "LAB_UNSUPPORTED_SYNTAX" in codes_of(r)
        # The `}`-glued target must never appear as a clean reference.
        assert all("}" not in ref.raw_target for ref in r.references)

    def test_multiline_flow_job_value_rejects(self, tmp_path):
        r = scan_text(
            tmp_path,
            "jobs:\n  a: {\n"
            "      uses: x/y/.github/workflows/w.yml@v1 }\n",
        )
        assert not r.accepted
        assert "LAB_UNSUPPORTED_SYNTAX" in codes_of(r)

    def test_balanced_single_line_flow_stays_accepted(self, tmp_path):
        """A one-line balanced flow collection (matrix list) nets to zero
        flow depth and must not trip the multi-line-flow rejection."""
        r = scan_text(
            tmp_path,
            "jobs:\n  a:\n"
            "    strategy:\n"
            "      matrix: {os: [ubuntu, macos]}\n"
            "    steps:\n"
            "      - uses: actions/checkout@v4\n",
        )
        assert r.accepted
        assert paths_of(r) == ["jobs.a.steps[0].uses"]

    def test_plain_scalar_fold_rejects(self, tmp_path):
        """A `uses:` plain scalar continued on a deeper next line folds into
        one value on GitHub; lab/0 was reading only the first line and
        accepting a truncated raw_target. Now the continuation line is
        recognized as unmodeled and the file is rejected."""
        r = scan_text(
            tmp_path,
            "jobs:\n  a:\n    steps:\n"
            "      - uses: owner/repo@v1\n"
            "          suffix\n",
        )
        assert not r.accepted
        assert "LAB_UNSUPPORTED_SYNTAX" in codes_of(r)

    def test_plain_scalar_fold_job_level_rejects(self, tmp_path):
        r = scan_text(
            tmp_path,
            "jobs:\n  a:\n"
            "    uses: octo/repo/.github/workflows/x.yml@v1\n"
            "      extra\n",
        )
        assert not r.accepted
        assert "LAB_UNSUPPORTED_SYNTAX" in codes_of(r)

    def test_unterminated_quote_rejects(self, tmp_path):
        r = scan_text(
            tmp_path,
            "jobs:\n  a:\n    steps:\n      - uses: 'actions/checkout@v4\n",
        )
        self.assert_rejected(r, "LAB_UNCLASSIFIED_USES")

    def test_uses_with_no_inline_value_rejects(self, tmp_path):
        r = scan_text(
            tmp_path,
            "jobs:\n  a:\n    steps:\n      - uses:\n          actions/checkout@v4\n",
        )
        self.assert_rejected(r, "LAB_UNCLASSIFIED_USES")

    def test_uses_block_scalar_value_rejects(self, tmp_path):
        r = scan_text(
            tmp_path,
            "jobs:\n  a:\n    steps:\n      - uses: |\n          actions/checkout@v4\n",
        )
        self.assert_rejected(r, "LAB_UNCLASSIFIED_USES")

    def test_flow_style_steps_reject(self, tmp_path):
        r = scan_text(
            tmp_path,
            "jobs:\n  a:\n    steps: [{uses: evil/x@v1}]\n",
        )
        assert not r.accepted
        assert codes_of(r) & {"LAB_UNSUPPORTED_SYNTAX", "LAB_UNCLASSIFIED_USES"}

    def test_flow_uses_value_rejects(self, tmp_path):
        r = scan_text(
            tmp_path,
            "jobs:\n  a:\n    steps:\n      - uses: [not, a, scalar]\n",
        )
        self.assert_rejected(r, "LAB_UNCLASSIFIED_USES")

    def test_anchor_and_alias_in_jobs_reject(self, tmp_path):
        for snippet in (
            "jobs:\n  a: &tpl\n    uses: x/y/.github/workflows/w.yml@v1\n",
            "jobs:\n  a:\n    steps: *shared\n",
            "jobs:\n  a:\n    steps:\n      - *sharedstep\n",
            "jobs:\n  a:\n    steps:\n      - uses: &anchor x/y@v1\n",
        ):
            r = scan_text(tmp_path, snippet)
            assert not r.accepted, snippet
            assert codes_of(r) & {
                "LAB_UNSUPPORTED_SYNTAX",
                "LAB_UNCLASSIFIED_USES",
            }, snippet

    def test_merge_key_in_job_rejects(self, tmp_path):
        r = scan_text(
            tmp_path,
            "jobs:\n  a:\n    <<: *base\n    steps:\n      - uses: a/b@v1\n",
        )
        self.assert_rejected(r, "LAB_UNSUPPORTED_SYNTAX")

    def test_multiple_documents_reject(self, tmp_path):
        r = scan_text(
            tmp_path,
            "---\njobs:\n  a:\n    steps:\n      - uses: a/b@v1\n"
            "---\njobs:\n  b:\n    steps:\n      - uses: c/d@v2\n",
        )
        self.assert_rejected(r, "LAB_UNSUPPORTED_SYNTAX")

    def test_leading_document_marker_alone_is_fine(self, tmp_path):
        r = scan_text(
            tmp_path,
            "---\njobs:\n  a:\n    steps:\n      - uses: a/b@v1\n",
        )
        assert r.accepted
        assert paths_of(r) == ["jobs.a.steps[0].uses"]

    def test_tab_indentation_rejects(self, tmp_path):
        r = scan_text(
            tmp_path,
            "jobs:\n\ta:\n\t\tsteps:\n\t\t\t- uses: a/b@v1\n",
        )
        self.assert_rejected(r, "LAB_UNSUPPORTED_SYNTAX")

    def test_explicit_block_indent_indicator_rejects(self, tmp_path):
        r = scan_text(
            tmp_path,
            "jobs:\n  a:\n    steps:\n"
            "      - run: |2\n"
            "          echo hi\n"
            "      - uses: a/b@v1\n",
        )
        self.assert_rejected(r, "LAB_UNSUPPORTED_SYNTAX")

    def test_block_scalar_dedent_below_first_content_rejects(self, tmp_path):
        r = scan_text(
            tmp_path,
            "jobs:\n  a:\n    steps:\n"
            "      - run: |\n"
            "            echo hi\n"
            "          uses: sneaky/x@v1\n",
        )
        self.assert_rejected(r, "LAB_UNSUPPORTED_SYNTAX")
        assert r.references == ()

    def test_duplicate_uses_in_one_step_rejects(self, tmp_path):
        r = scan_text(
            tmp_path,
            "jobs:\n  a:\n    steps:\n"
            "      - uses: a/b@v1\n"
            "        uses: c/d@v2\n",
        )
        self.assert_rejected(r, "DUPLICATE_PATH")

    def test_duplicate_job_id_rejects(self, tmp_path):
        r = scan_text(
            tmp_path,
            "jobs:\n"
            "  a:\n    steps:\n      - uses: a/b@v1\n"
            "  a:\n    steps:\n      - uses: c/d@v2\n",
        )
        self.assert_rejected(r, "LAB_UNSUPPORTED_SYNTAX")

    def test_duplicate_top_level_jobs_rejects(self, tmp_path):
        r = scan_text(
            tmp_path,
            "jobs:\n  a:\n    steps:\n      - uses: a/b@v1\n"
            "jobs:\n  b:\n    steps:\n      - uses: c/d@v2\n",
        )
        self.assert_rejected(r, "LAB_UNSUPPORTED_SYNTAX")

    def test_undecodable_file_rejects(self, tmp_path):
        wf = tmp_path / ".github" / "workflows"
        wf.mkdir(parents=True)
        (wf / "ci.yml").write_bytes(b"\xff\xfe\x00jobs:\n")
        r = LegacyRegexBackend().parse_file(tmp_path, wf / "ci.yml")
        assert not r.accepted
        assert codes_of(r) == {"LAB_IO_ERROR"}
        assert r.references == ()

    def test_rejection_carries_position_and_no_line_content(self, tmp_path):
        """Diagnostics locate the problem without echoing the line (run
        scripts may embed secrets)."""
        secret_line = "      - run: echo 'uses: fake/x@v1' \"$SUPER_SECRET\"\n"
        r = scan_text(tmp_path, "jobs:\n  a:\n    steps:\n" + secret_line)
        (d,) = [d for d in r.diagnostics if d.severity == "error"]
        assert d.line == 4
        assert "SUPER_SECRET" not in d.message
        assert "fake/x" not in d.message


# --- target classification and validation ---

class TestTargetClassification:
    def test_classification_order(self):
        assert classify_uses_target("docker://alpine:3.20", False)[0] == "docker-image"
        assert classify_uses_target("./x", False)[0] == "local-action"
        assert classify_uses_target("./x", True)[0] == "local-action"
        assert classify_uses_target("a/b@v1", True)[0] == "reusable-workflow"
        assert classify_uses_target("a/b@v1", False)[0] == "external-action"

    def test_split_at_final_at(self):
        kind, action, ref, problem = classify_uses_target("a/b@x@y", False)
        assert problem is not None  # `a/b@x` is not a valid action shape
        kind, action, ref, problem = classify_uses_target(
            "org/repo/path/to/action@v1.2.3", False
        )
        assert (action, ref, problem) == ("org/repo/path/to/action", "v1.2.3", None)

    def test_external_without_ref_flagged_not_dropped(self, tmp_path):
        r = scan_text(
            tmp_path,
            "jobs:\n  a:\n    steps:\n      - uses: actions/checkout\n",
        )
        assert r.accepted  # a warning, not a rejection: structure was clear
        (ref,) = r.references
        assert ref.kind == "external-action"
        assert ref.raw_target == "actions/checkout"
        assert (ref.action, ref.ref) == (None, None)
        (d,) = r.diagnostics
        assert d.code == "INVALID_USES_TARGET"
        assert d.severity == "warning"

    def test_ref_values_are_not_prefiltered(self, tmp_path):
        """The parser reports structure; ref hygiene stays with policy.
        The legacy production scanner still drops `-`-prefixed refs before
        they can reach git — both behaviors are asserted here."""
        content = (
            "jobs:\n  a:\n    steps:\n"
            "      - uses: evil/repo@--upload-pack=/tmp/x\n"
        )
        r = scan_text(tmp_path, content)
        assert r.accepted
        (ref,) = r.references
        assert (ref.action, ref.ref) == ("evil/repo", "--upload-pack=/tmp/x")
        legacy = parse_workflows(tmp_path)
        assert legacy == {}


# --- production path unchanged (PR 1 guarantee) ---

class TestLegacyPathUntouched:
    def test_legacy_scanner_still_matches_inside_run_blocks(self, tmp_path, capsys):
        """parse_workflows keeps its known false positive on `uses:` text
        inside `run: |` blocks. That is intentional in PR 1: production
        The private legacy compatibility scanner sees this script text while
        lab/0 excludes it. This test preserves the historical distinction;
        production commands now use stable."""
        content = (
            "jobs:\n  a:\n    steps:\n"
            "      - run: |\n"
            "          echo 'uses: fake/script@v2'\n"
        )
        wf = tmp_path / ".github" / "workflows"
        wf.mkdir(parents=True)
        (wf / "ci.yml").write_text(content)

        legacy = parse_workflows(tmp_path)
        assert "fake/script@v2" in legacy  # unchanged legacy behavior

        lab = LegacyRegexBackend().parse_file(tmp_path, wf / "ci.yml")
        assert lab.accepted
        assert lab.references == ()  # lab/0 knows it is script text


# --- the scan command ---

class TestScanCli:
    def test_json_deterministic_versioned_and_sorted(self, owl_repo, capsys):
        assert run_scan(owl_repo) == 0
        first = capsys.readouterr().out
        assert run_scan(owl_repo) == 0
        second = capsys.readouterr().out
        assert first == second
        payload = json.loads(first)
        assert payload["schema_version"] == 1
        assert payload["backend"] == "lab/0"
        assert payload["accepted"] is True
        assert [f["path"] for f in payload["files"]] == sorted(
            f["path"] for f in payload["files"]
        )

    def test_scan_finds_owl_repo_references(self, owl_repo, capsys):
        assert run_scan(owl_repo) == 0
        payload = json.loads(capsys.readouterr().out)
        refs = [
            (r["semantic_path"], r["kind"], r["raw_target"])
            for f in payload["files"]
            for r in f["references"]
        ]
        assert (
            "jobs.pre-commit.uses",
            "reusable-workflow",
            "Old-Well-Labs/infrastructure/.github/workflows/shared-pre-commit.yml@main",
        ) in refs
        assert (
            "jobs.test.steps[3].uses",
            "local-action",
            "./.github/actions/run-regression",
        ) in refs
        assert (
            "jobs.migrations.uses",
            "local-action",
            "./.github/workflows/run-migrations.yml",
        ) in refs

    def test_exit_1_and_accepted_false_on_unclassified(self, tmp_path, capsys):
        wf = tmp_path / ".github" / "workflows"
        wf.mkdir(parents=True)
        (wf / "bad.yml").write_text(
            "jobs:\n  a:\n    steps:\n      - run: echo 'uses: fake/x@v1'\n"
        )
        assert run_scan(tmp_path) == 1
        payload = json.loads(capsys.readouterr().out)
        assert payload["accepted"] is False
        codes = {
            d["code"] for f in payload["files"] for d in f["diagnostics"]
        }
        assert "LAB_UNCLASSIFIED_USES" in codes

    def test_text_format_reports_paths_and_kinds(self, owl_repo, capsys):
        assert run_scan(owl_repo, fmt="text") == 0
        out = capsys.readouterr().out
        assert "jobs.test.steps[0].uses" in out
        assert "external-action" in out
        assert "backend lab/0" in out

    def test_compare_without_stable_is_unavailable(self, owl_repo, monkeypatch, capsys):
        # compare needs the stable backend; without ruamel it is a clean
        # "unavailable" (4), never a crash or a single-backend fallback.
        # (compare's full behavior is covered in test_parser_compare.py.)
        monkeypatch.setattr(action_locker, "stable_backend_available", lambda: False)
        assert run_scan(owl_repo, parser="compare") == 4
        assert "ruamel.yaml" in capsys.readouterr().err

    def test_env_var_selects_backend(self, owl_repo, monkeypatch, capsys):
        monkeypatch.setenv("ACTION_LOCKER_PARSER", "lab")
        assert run_scan(owl_repo, parser=None) == 0
        capsys.readouterr()

    def test_invalid_env_backend_exits_2(self, owl_repo, monkeypatch, capsys):
        monkeypatch.setenv("ACTION_LOCKER_PARSER", "regex-classic")
        assert run_scan(owl_repo, parser=None) == 2
        assert "unknown parser backend" in capsys.readouterr().err

    def test_explicit_parser_beats_env(self, owl_repo, monkeypatch, capsys):
        monkeypatch.setenv("ACTION_LOCKER_PARSER", "regex-classic")
        assert run_scan(owl_repo, parser="lab") == 0
        capsys.readouterr()

    def test_experimental_warning_suppressible(self, owl_repo, monkeypatch, capsys):
        monkeypatch.delenv("ACTION_LOCKER_PARSER_LAB_CI", raising=False)
        assert run_scan(owl_repo) == 0
        assert "experimental" in capsys.readouterr().err
        monkeypatch.setenv("ACTION_LOCKER_PARSER_LAB_CI", "1")
        assert run_scan(owl_repo) == 0
        assert "experimental" not in capsys.readouterr().err

    def test_scan_is_read_only(self, owl_repo, capsys):
        wf_dir = owl_repo / ".github" / "workflows"
        before = {p.name: p.read_bytes() for p in wf_dir.iterdir()}
        assert run_scan(owl_repo) == 0
        after = {p.name: p.read_bytes() for p in wf_dir.iterdir()}
        assert before == after
        capsys.readouterr()

    def test_empty_repo_scans_clean(self, tmp_path, capsys):
        assert run_scan(tmp_path) == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["files"] == []
        assert payload["accepted"] is True

    def test_main_dispatches_scan(self, owl_repo, monkeypatch, capsys):
        monkeypatch.chdir(owl_repo)
        monkeypatch.setattr(
            sys, "argv", ["action-locker", "scan", "--format", "json"]
        )
        with pytest.raises(SystemExit) as exc:
            action_locker.main()
        assert exc.value.code == 0
        assert json.loads(capsys.readouterr().out)["schema_version"] == 1


# --- regex safety ---

class TestRegexSafety:
    def test_very_long_plain_target_completes(self, tmp_path):
        target = "a/" + "b" * 200_000 + "@v1"
        start = time.monotonic()
        r = scan_text(
            tmp_path, f"jobs:\n  a:\n    steps:\n      - uses: {target}\n"
        )
        assert time.monotonic() - start < 2.0
        (ref,) = r.references
        assert ref.raw_target == target

    def test_very_long_unterminated_quote_completes(self, tmp_path):
        start = time.monotonic()
        r = scan_text(
            tmp_path,
            "jobs:\n  a:\n    steps:\n      - uses: '" + "x" * 200_000 + "\n",
        )
        assert time.monotonic() - start < 2.0
        assert not r.accepted

    def test_very_long_block_scalar_completes(self, tmp_path):
        body = "".join(
            f"          echo line {i} uses: fake/x@v{i}\n" for i in range(2_000)
        )
        start = time.monotonic()
        r = scan_text(
            tmp_path,
            "jobs:\n  a:\n    steps:\n      - run: |\n" + body,
        )
        assert time.monotonic() - start < 2.0
        assert r.accepted
        assert r.references == ()
