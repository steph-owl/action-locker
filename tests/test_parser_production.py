"""Production-command parser integration (ADR 0001 PR 3)."""

import argparse

import pytest

import action_locker
from conftest import entry, write_lockfile


def parser_args(name):
    return argparse.Namespace(parser_backend=name)


def workflow(repo, content, name="ci.yml"):
    directory = repo / ".github" / "workflows"
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / name
    path.write_text(content)
    return path


def run_verify(repo, parser="stable"):
    with pytest.raises(SystemExit) as exc:
        action_locker.cmd_verify(parser_args(parser), repo)
    return exc.value.code


class TestProductionDiscovery:
    def test_stable_builds_legacy_compatibility_shape(self, tmp_path):
        sha = "a" * 40
        workflow(
            tmp_path,
            "jobs:\n  build:\n    steps:\n"
            "      - uses: actions/checkout@v4\n"
            f"      - uses: owner/repo/path@{sha}\n",
        )

        actions = action_locker.discover_workflow_actions(
            tmp_path, parser_args("stable")
        )

        assert actions == {
            "actions/checkout@v4": [(".github/workflows/ci.yml", 4)],
            f"owner/repo/path@{sha}": [(".github/workflows/ci.yml", 5)],
        }

    def test_stable_ignores_fake_reference_in_block_scalar(self, tmp_path, capsys):
        sha = "b" * 40
        workflow(
            tmp_path,
            "jobs:\n  build:\n    steps:\n"
            "      - run: |\n          uses: attacker/fake@main\n"
            f"      - uses: actions/checkout@{sha}\n",
        )
        write_lockfile(
            tmp_path,
            {"actions/checkout@v4": entry("actions/checkout", sha, "v4")},
        )

        assert run_verify(tmp_path) == 0
        assert "attacker/fake" not in capsys.readouterr().out

    def test_stable_rejection_aborts_before_policy(self, tmp_path, capsys):
        workflow(tmp_path, "jobs:\n  build:\n    steps: [unterminated\n")

        assert run_verify(tmp_path) == 1
        err = capsys.readouterr().err
        assert "YAML_PARSE_ERROR" in err
        assert "No lockfile found" not in err

    def test_invalid_target_is_policy_error_not_silent_omission(
        self, tmp_path, capsys
    ):
        workflow(
            tmp_path,
            "jobs:\n  build:\n    steps:\n      - uses: not-a-reference\n",
        )

        with pytest.raises(SystemExit) as exc:
            action_locker.discover_workflow_actions(
                tmp_path, parser_args("stable")
            )

        assert exc.value.code == 1
        assert "INVALID_USES_TARGET" in capsys.readouterr().err

    def test_local_and_docker_references_are_not_lockfile_subjects(
        self, tmp_path, capsys
    ):
        workflow(
            tmp_path,
            "jobs:\n  build:\n    steps:\n"
            "      - uses: ./.github/actions/local\n"
            "      - uses: docker://alpine:3.20\n"
            "      - uses: actions/checkout@v4\n",
        )

        actions = action_locker.discover_workflow_actions(
            tmp_path, parser_args("stable")
        )

        assert set(actions) == {"actions/checkout@v4"}
        assert "docker://" in capsys.readouterr().err


class TestProductionParserSelection:
    def test_explicit_parser_beats_environment(self, tmp_path, monkeypatch):
        workflow(
            tmp_path,
            "jobs:\n  build:\n    steps:\n      - uses: actions/checkout@v4\n",
        )
        monkeypatch.setenv("ACTION_LOCKER_PARSER", "lab")

        actions = action_locker.discover_workflow_actions(
            tmp_path, parser_args("stable")
        )

        assert set(actions) == {"actions/checkout@v4"}

    def test_environment_selects_stable(self, tmp_path, monkeypatch):
        workflow(
            tmp_path,
            "jobs:\n  build:\n    steps:\n      - uses: actions/checkout@v4\n",
        )
        monkeypatch.setenv("ACTION_LOCKER_PARSER", "stable")

        actions = action_locker.discover_workflow_actions(
            tmp_path, parser_args(None)
        )

        assert set(actions) == {"actions/checkout@v4"}

    def test_unknown_environment_parser_exits_2(self, tmp_path, monkeypatch):
        workflow(tmp_path, "jobs: {}\n")
        monkeypatch.setenv("ACTION_LOCKER_PARSER", "mystery")

        with pytest.raises(SystemExit) as exc:
            action_locker.discover_workflow_actions(tmp_path, parser_args(None))

        assert exc.value.code == 2

    def test_unavailable_stable_exits_4(self, tmp_path, monkeypatch):
        workflow(tmp_path, "jobs: {}\n")
        monkeypatch.setattr(
            action_locker, "stable_backend_available", lambda: False
        )

        with pytest.raises(SystemExit) as exc:
            action_locker.discover_workflow_actions(
                tmp_path, parser_args("stable")
            )

        assert exc.value.code == 4

    def test_compare_disagreement_aborts_without_mutation(self, tmp_path):
        path = workflow(
            tmp_path,
            "jobs:\n  build:\n    steps:\n"
            "      - &checkout\n        uses: actions/checkout@v4\n"
            "      - *checkout\n",
        )
        before = path.read_bytes()

        with pytest.raises(SystemExit) as exc:
            action_locker.discover_workflow_actions(
                tmp_path, parser_args("compare")
            )

        assert exc.value.code == 3
        assert path.read_bytes() == before

    def test_lab_rejection_is_not_empty_success(self, tmp_path):
        workflow(
            tmp_path,
            "jobs:\n  build:\n    steps:\n"
            "      - &checkout\n        uses: actions/checkout@v4\n",
        )

        with pytest.raises(SystemExit) as exc:
            action_locker.discover_workflow_actions(tmp_path, parser_args("lab"))

        assert exc.value.code == 1
