"""Network integration tests: resolve real refs via git ls-remote.

Opt-in: run with `pytest -m network`. Skipped by default so unit tests
stay fast and offline (CI verify job doesn't need network either).
"""

import argparse
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import action_locker
from action_locker import cmd_lock, load_lockfile, resolve_ref_to_sha

pytestmark = pytest.mark.network

# Known-stable mapping (actions/checkout v4 tag as of 2026-06)
CHECKOUT_V4_SHA = "34e114876b0b11c390a56381ad16ebd13914f8d5"


def test_resolve_tag_to_sha():
    sha = resolve_ref_to_sha("actions/checkout", "v4")
    assert sha == CHECKOUT_V4_SHA


def test_resolve_branch_to_sha():
    sha = resolve_ref_to_sha("actions/checkout", "main")
    assert sha and action_locker.is_sha(sha)


def test_resolve_sha_passthrough():
    assert resolve_ref_to_sha("actions/checkout", CHECKOUT_V4_SHA) == CHECKOUT_V4_SHA


def test_resolve_nonexistent_ref_returns_none():
    assert resolve_ref_to_sha("actions/checkout", "no-such-ref-xyz") is None


def test_commit_age_of_old_release_passes_floor():
    """checkout v4's commit is long past any reasonable age floor."""
    age = action_locker.commit_age_days("actions/checkout", CHECKOUT_V4_SHA)
    if age is None:
        pytest.skip("api.github.com unreachable (rate limit or network policy)")
    assert age > action_locker.MIN_COMMIT_AGE_DAYS


def test_lock_owl_shaped_repo(owl_repo, capsys):
    """End-to-end: lock the OWL-shaped fixture repo against live GitHub.

    The internal Old-Well-Labs reusable workflow can't resolve without org
    credentials, and `lock` now exits 1 on any failure — so expect the
    SystemExit and assert the partial lock still captured the public refs.
    """
    with pytest.raises(SystemExit):
        cmd_lock(argparse.Namespace(force=False), owl_repo)
    lockdata = load_lockfile(owl_repo)
    assert lockdata["locked"]["actions/checkout@v4"]["resolved"] == CHECKOUT_V4_SHA
    # Internal reusable workflow on @main resolves to a branch SHA
    key = "Old-Well-Labs/infrastructure/.github/workflows/shared-build.yml@main"
    if key in lockdata["locked"]:  # private repo; only resolvable with org creds
        assert action_locker.is_sha(lockdata["locked"][key]["resolved"])
