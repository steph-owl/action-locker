"""Shared fixtures: a synthetic repo modeled on real production workflows.

The workflow content below mirrors the `uses:` patterns we actually run at
Old Well Labs: third-party actions on mutable tags, SHA-pinned release
actions, commented-out leftovers, local composite actions, and internal
reusable workflows on @main.
"""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

ON_PUSH_YML = """\
name: On Push
on: push
jobs:
  pre-commit:
    uses: Old-Well-Labs/infrastructure/.github/workflows/shared-pre-commit.yml@main
  changes:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dorny/paths-filter@v3
        id: filter
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - name: Configure AWS credentials
        uses: aws-actions/configure-aws-credentials@v4
      - name: Regression
        uses: ./.github/actions/run-regression
  migrations:
    uses: ./.github/workflows/run-migrations.yml
"""

RELEASE_YML = """\
name: Release
on:
  push:
    tags: ["v*"]
jobs:
  build:
    uses: Old-Well-Labs/infrastructure/.github/workflows/shared-build.yml@main
  release:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Create tag
        uses: rickstaa/action-create-tag@a1c7777fcb2fee4f19b0f283ba888afa11678b72
      - name: GH release
        uses: softprops/action-gh-release@3bb12739c298aeb8a4eeaf626c5b8d85266b0e65
#        uses: softprops/action-gh-release@v2
"""


@pytest.fixture
def owl_repo(tmp_path):
    """A repo whose workflows mirror real OWL `uses:` patterns."""
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    (wf_dir / "on_push.yml").write_text(ON_PUSH_YML)
    (wf_dir / "release.yml").write_text(RELEASE_YML)
    return tmp_path


def write_lockfile(repo_root, locked, trusted_prefixes=None):
    data = {"version": 1, "locked": locked}
    if trusted_prefixes is not None:
        data["trusted_prefixes"] = trusted_prefixes
    (repo_root / "action-lock.json").write_text(json.dumps(data, indent=2))
    return data


def entry(repo, sha, tag=None):
    return {
        "resolved": sha,
        "tag": tag,
        "repo": repo,
        "locked_at": "2026-06-11T00:00:00+00:00",
        "locations": [],
    }
