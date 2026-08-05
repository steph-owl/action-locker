"""Structural, atomic workflow rewriting (ADR 0001 PR 4)."""

import argparse

import pytest

import action_locker
from conftest import entry, write_lockfile


SHA = "7" * 40


def workflow(repo, content, name="ci.yml", raw=False):
    directory = repo / ".github" / "workflows"
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / name
    if raw:
        path.write_bytes(content)
    else:
        path.write_text(content)
    return path


def locked(repo, selected=None):
    value = entry("x/y", SHA, "v1")
    if selected:
        value["selected"] = selected
    write_lockfile(repo, {"x/y@v1": value})


def rewrite(repo, parser="stable"):
    return action_locker.cmd_rewrite(
        argparse.Namespace(parser_backend=parser), repo
    )


class TestStructuralRewritePreservation:
    def test_only_target_scalar_and_tag_comment_change(self, tmp_path):
        source = (
            "# heading\n"
            "jobs:\n"
            "  build:\n"
            "    steps:\n"
            "      - run: |\n"
            "          echo 'uses: attacker/fake@main'\n"
            "      - uses: x/y@v1\n"
            "        with:\n"
            "          message: 'keep: exactly'\n"
        )
        path = workflow(tmp_path, source)
        locked(tmp_path)

        rewrite(tmp_path)

        expected = source.replace("uses: x/y@v1", f"uses: x/y@{SHA}  # v1")
        assert path.read_text() == expected

    @pytest.mark.parametrize(
        ("old", "new"),
        [
            ("'x/y@v1'", f"'x/y@{SHA}'  # v1"),
            ('"x/y@v1"', f'"x/y@{SHA}"  # v1'),
        ],
    )
    def test_quote_style_is_preserved(self, tmp_path, old, new):
        source = f"jobs:\n  a:\n    steps:\n      - uses: {old}\n"
        path = workflow(tmp_path, source)
        locked(tmp_path)

        rewrite(tmp_path)

        assert path.read_text() == source.replace(old, new)

    def test_existing_comment_is_preserved_byte_for_byte(self, tmp_path):
        source = "jobs:\n  a:\n    steps:\n      - uses: x/y@v1   # human note\n"
        path = workflow(tmp_path, source)
        locked(tmp_path)

        rewrite(tmp_path)

        assert path.read_text() == source.replace("x/y@v1", f"x/y@{SHA}")

    def test_flow_mapping_preserves_delimiters_without_eol_comment(self, tmp_path):
        source = "jobs:\n  a:\n    steps:\n      - {uses: x/y@v1, name: exact}\n"
        path = workflow(tmp_path, source)
        locked(tmp_path)

        rewrite(tmp_path)

        assert path.read_text() == source.replace("x/y@v1", f"x/y@{SHA}")

    def test_utf8_bom_and_crlf_are_preserved(self, tmp_path):
        source = (
            b"\xef\xbb\xbfjobs:\r\n  a:\r\n    steps:\r\n"
            b"      - uses: x/y@v1\r\n"
        )
        path = workflow(tmp_path, source, raw=True)
        locked(tmp_path)

        rewrite(tmp_path)

        expected = source.replace(b"x/y@v1", f"x/y@{SHA}  # v1".encode())
        assert path.read_bytes() == expected

    def test_step_anchor_aliases_share_one_safe_source_edit(self, tmp_path):
        source = (
            "jobs:\n  a:\n    steps:\n"
            "      - &shared\n        uses: x/y@v1\n"
            "      - *shared\n"
        )
        path = workflow(tmp_path, source)
        locked(tmp_path)

        rewrite(tmp_path)

        assert path.read_text() == source.replace(
            "uses: x/y@v1", f"uses: x/y@{SHA}  # v1"
        )
        result = action_locker.StructuralYamlBackend().parse_file(tmp_path, path)
        assert result.accepted
        assert [r.raw_target for r in result.references] == [
            f"x/y@{SHA}", f"x/y@{SHA}"
        ]

    def test_scalar_alias_is_replaced_only_at_executable_slot(self, tmp_path):
        source = (
            "defaults:\n  action: &action x/y@v1\n"
            "jobs:\n  a:\n    steps:\n      - uses: *action\n"
        )
        path = workflow(tmp_path, source)
        locked(tmp_path)

        rewrite(tmp_path)

        expected = source.replace("uses: *action", f"uses: x/y@{SHA}  # v1")
        assert path.read_text() == expected


class TestStructuralRewriteFailureSafety:
    def test_parser_rejection_leaves_original_bytes(self, tmp_path):
        source = b"jobs:\n  a:\n    steps: [unterminated\n"
        path = workflow(tmp_path, source, raw=True)
        locked(tmp_path)

        with pytest.raises(SystemExit) as exc:
            rewrite(tmp_path)

        assert exc.value.code == 1
        assert path.read_bytes() == source

    def test_failed_postcondition_leaves_original_bytes(self, tmp_path, monkeypatch):
        source = b"jobs:\n  a:\n    steps:\n      - uses: x/y@v1\n"
        path = workflow(tmp_path, source, raw=True)
        locked(tmp_path)

        def reject(*args, **kwargs):
            raise action_locker.StructuralRewriteError("forced postcondition")

        monkeypatch.setattr(action_locker, "_validate_rewrite_candidate", reject)
        with pytest.raises(SystemExit) as exc:
            rewrite(tmp_path)

        assert exc.value.code == 1
        assert path.read_bytes() == source

    def test_all_files_validate_before_first_commit(self, tmp_path, monkeypatch):
        first = workflow(
            tmp_path,
            "jobs:\n  a:\n    steps:\n      - uses: x/y@v1\n",
            "a.yml",
        )
        second = workflow(
            tmp_path,
            "jobs:\n  b:\n    steps:\n      - uses: x/y@v1\n",
            "b.yml",
        )
        originals = (first.read_bytes(), second.read_bytes())
        locked(tmp_path)
        real = action_locker._validate_rewrite_candidate
        calls = {"count": 0}

        def fail_second(*args, **kwargs):
            calls["count"] += 1
            if calls["count"] == 2:
                raise action_locker.StructuralRewriteError("second candidate")
            return real(*args, **kwargs)

        monkeypatch.setattr(
            action_locker, "_validate_rewrite_candidate", fail_second
        )
        with pytest.raises(SystemExit):
            rewrite(tmp_path)

        assert (first.read_bytes(), second.read_bytes()) == originals

    def test_atomic_commit_failure_rolls_back_prior_files(self, tmp_path, monkeypatch):
        first = workflow(
            tmp_path,
            "jobs:\n  a:\n    steps:\n      - uses: x/y@v1\n",
            "a.yml",
        )
        second = workflow(
            tmp_path,
            "jobs:\n  b:\n    steps:\n      - uses: x/y@v1\n",
            "b.yml",
        )
        originals = (first.read_bytes(), second.read_bytes())
        locked(tmp_path)
        real = action_locker._atomic_write_bytes
        failed = {"done": False}

        def fail_once(path, content):
            if path == second and not failed["done"]:
                failed["done"] = True
                raise OSError("forced replace failure")
            return real(path, content)

        monkeypatch.setattr(action_locker, "_atomic_write_bytes", fail_once)
        with pytest.raises(SystemExit):
            rewrite(tmp_path)

        assert (first.read_bytes(), second.read_bytes()) == originals


class TestStructuralRewriteParserModes:
    def test_compare_rewrites_ordinary_workflow(self, tmp_path):
        path = workflow(
            tmp_path,
            "jobs:\n  a:\n    steps:\n      - uses: x/y@v1\n",
        )
        locked(tmp_path)

        rewrite(tmp_path, parser="compare")

        assert f"x/y@{SHA}" in path.read_text()

    def test_compare_disagreement_does_not_mutate(self, tmp_path):
        source = (
            "jobs:\n  a:\n    steps:\n"
            "      - &shared\n        uses: x/y@v1\n"
            "      - *shared\n"
        )
        path = workflow(tmp_path, source)
        locked(tmp_path)

        with pytest.raises(SystemExit) as exc:
            rewrite(tmp_path, parser="compare")

        assert exc.value.code == 3
        assert path.read_text() == source

    def test_lab_is_scan_only(self, tmp_path):
        path = workflow(
            tmp_path,
            "jobs:\n  a:\n    steps:\n      - uses: x/y@v1\n",
        )
        locked(tmp_path)
        before = path.read_bytes()

        with pytest.raises(SystemExit) as exc:
            rewrite(tmp_path, parser="lab")

        assert exc.value.code == 2
        assert path.read_bytes() == before
