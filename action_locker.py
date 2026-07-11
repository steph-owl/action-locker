#!/usr/bin/env python3
"""
action-locker: Pin and vendor GitHub Actions for supply chain security.

Protects against both malicious tag mutation AND upstream disappearance.
"""

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import shutil
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Tuple

__version__ = "0.9.0"


# --- Constants ---

LOCKFILE_NAME = "action-lock.json"
LOCKFILE_VERSION = 1
VENDOR_DIR = ".github/vendored-actions"
META_FILE = ".action-lock-meta.json"

# Supply-chain quarantine: refuse to lock 3rd-party commits younger than this.
# Compromised actions are usually caught within days of the malicious commit —
# a brief age floor keeps you out of the blast window. trusted_prefixes are
# exempt. Age source is a trust ladder (see ref_age_days): immutable-release
# published_at, else earliest merged-PR date (both server-side, trusted),
# else the commit's committer date (git metadata, backdatable — heuristic,
# not a wall). Unknown age fails closed.
MIN_COMMIT_AGE_DAYS = 5

# Matches: uses: owner/repo@ref  or  uses: owner/repo/path@ref
USES_PATTERN = re.compile(
    r'uses:\s*["\']?(?P<action>[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+(?:/[a-zA-Z0-9_./%-]+)?)@(?P<ref>[a-zA-Z0-9._/-]+)["\']?'
)

# A full SHA-1 is 40 hex chars
SHA_PATTERN = re.compile(r'^[0-9a-f]{40}$')


# --- Color ---

def _use_color():
    """Color when a human is looking: a TTY, or GitHub Actions logs (which
    render ANSI), or FORCE_COLOR. NO_COLOR always wins (no-color.org)."""
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR") or os.environ.get("GITHUB_ACTIONS") == "true":
        return True
    return sys.stdout.isatty()


def _paint(text, code):
    return f"\x1b[{code}m{text}\x1b[0m" if _use_color() else text


def red(text):
    return _paint(text, "31")


def green(text):
    return _paint(text, "32")


def yellow(text):
    return _paint(text, "33")


# --- Helpers ---

def find_repo_root():
    """Walk up from cwd to find a .github/workflows/ directory."""
    current = Path.cwd()
    while current != current.parent:
        if (current / ".github" / "workflows").is_dir():
            return current
        current = current.parent
    # Fall back to cwd
    return Path.cwd()


def parse_workflows(repo_root):
    """Extract all `uses:` references from workflow files."""
    workflows_dir = repo_root / ".github" / "workflows"
    if not workflows_dir.exists():
        print(f"No workflows found at {workflows_dir}", file=sys.stderr)
        return {}

    actions = {}  # key: "owner/repo@ref", value: list of (file, line_num)

    for wf_file in sorted(workflows_dir.glob("*.yml")) + sorted(workflows_dir.glob("*.yaml")):
        with open(wf_file) as f:
            for line_num, line in enumerate(f, 1):
                # Skip commented-out lines (real workflows have e.g.
                # "#  uses: softprops/action-gh-release@v2" left behind)
                if line.lstrip().startswith("#"):
                    continue
                # docker:// images live in a different supply chain (a
                # registry, not a git repo) — action-locker does not manage
                # them. Pin those by digest (@sha256:...) yourself.
                if "docker://" in line:
                    print(
                        f"Note: skipping docker:// ref "
                        f"({wf_file.relative_to(repo_root)}:{line_num}) — "
                        f"not managed by action-locker; pin images by digest",
                        file=sys.stderr,
                    )
                    continue
                match = USES_PATTERN.search(line)
                if match:
                    action = match.group("action")
                    ref = match.group("ref")
                    # A ref starting with '-' is never a valid git ref and could
                    # be parsed as an option by downstream git invocations.
                    if ref.startswith("-"):
                        print(
                            f"Warning: ignoring invalid ref {action}@{ref} "
                            f"({wf_file.relative_to(repo_root)}:{line_num}) — "
                            f"refs must not start with '-'",
                            file=sys.stderr,
                        )
                        continue
                    key = f"{action}@{ref}"
                    if key not in actions:
                        actions[key] = []
                    actions[key].append((str(wf_file.relative_to(repo_root)), line_num))

    return actions


def is_sha(ref):
    """Check if a ref is a full SHA."""
    return bool(SHA_PATTERN.match(ref))


def resolve_ref_to_sha(repo, ref, token=None):
    """Resolve a ref (tag/branch) to a commit SHA. Tries git ls-remote first (no auth needed
    for public repos), falls back to GitHub API."""

    # If it's already a SHA, just return it
    if is_sha(ref):
        return ref

    # Refuse refs that could be parsed as options by git or the GitHub API.
    if ref.startswith("-"):
        return None

    # Method 1: git ls-remote (works without auth for public repos, handles dereferencing)
    # "--" terminates option parsing so the ref can never be treated as a git option.
    try:
        result = subprocess.run(
            ["git", "ls-remote", "--tags", "--refs", "--", f"https://github.com/{repo}.git", ref],
            capture_output=True, text=True, timeout=15,
        )
        if result.returncode == 0 and result.stdout.strip():
            # Format: "sha\trefs/tags/ref"
            sha = result.stdout.strip().split()[0]
            if is_sha(sha):
                return sha

        # Also try as a branch
        result = subprocess.run(
            ["git", "ls-remote", "--heads", "--", f"https://github.com/{repo}.git", ref],
            capture_output=True, text=True, timeout=15,
        )
        if result.returncode == 0 and result.stdout.strip():
            sha = result.stdout.strip().split()[0]
            if is_sha(sha):
                return sha

        # Try with full tag dereferencing (annotated tags show as tag^{})
        result = subprocess.run(
            ["git", "ls-remote", "--", f"https://github.com/{repo}.git", ref, f"{ref}^{{}}"],
            capture_output=True, text=True, timeout=15,
        )
        if result.returncode == 0 and result.stdout.strip():
            lines = result.stdout.strip().split("\n")
            # Prefer the dereferenced version (the ^{} line points to the commit)
            for line in reversed(lines):
                sha = line.split()[0]
                if is_sha(sha):
                    return sha

    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    # Method 2: GitHub API (needs auth but handles more edge cases)
    import urllib.request
    import urllib.error

    headers = {"Accept": "application/vnd.github.v3+json"}
    if token:
        headers["Authorization"] = f"token {token}"

    for ref_type in [f"tags/{ref}", f"heads/{ref}"]:
        url = f"https://api.github.com/repos/{repo}/git/ref/{ref_type}"
        req = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(req) as resp:
                data = json.loads(resp.read())
                sha = data["object"]["sha"]
                if data["object"]["type"] == "tag":
                    tag_url = data["object"]["url"]
                    tag_req = urllib.request.Request(tag_url, headers=headers)
                    with urllib.request.urlopen(tag_req) as tag_resp:
                        tag_data = json.loads(tag_resp.read())
                        sha = tag_data["object"]["sha"]
                # Never return an unvalidated value from the API response —
                # downstream callers interpolate this into URLs.
                if is_sha(sha):
                    return sha
        except urllib.error.HTTPError:
            continue

    return None


def get_commit_date(repo, sha, token=None):
    """Return the committer date of a commit as an aware datetime, or None.

    `sha` is re-validated locally (defense in depth): it is interpolated
    into the commits URL, so we never trust the caller to have validated it.

    Note: committer dates are git metadata, settable by whoever made the
    commit — treat the result as a heuristic, not proof of public existence.
    """
    if not is_sha(sha):
        return None

    import urllib.request
    import urllib.error

    headers = {"Accept": "application/vnd.github.v3+json"}
    if token:
        headers["Authorization"] = f"token {token}"

    url = f"https://api.github.com/repos/{repo}/commits/{sha}"
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
        date_str = data["commit"]["committer"]["date"]
        return datetime.fromisoformat(date_str.replace("Z", "+00:00"))
    except (urllib.error.URLError, KeyError, TypeError, ValueError, TimeoutError):
        return None


def commit_age_days(repo, sha, token=None):
    """Age of a commit in days (float), or None if the date can't be determined."""
    commit_date = get_commit_date(repo, sha, token)
    if commit_date is None:
        return None
    return (datetime.now(timezone.utc) - commit_date).total_seconds() / 86400


def get_release_published_at(repo, tag, token=None):
    """`published_at` of an IMMUTABLE release for `tag`, else None.

    Immutable releases freeze the tag→commit binding and `published_at` is
    set by GitHub's servers — an attacker can neither backdate it nor move
    the tag afterward, so it's a *trusted* age signal. A mutable release's
    published_at proves nothing (the tag can move after publication — that
    is exactly the tj-actions attack), so those are ignored.
    """
    if not tag:
        return None

    import urllib.request
    import urllib.error
    import urllib.parse

    headers = {"Accept": "application/vnd.github.v3+json"}
    if token:
        headers["Authorization"] = f"token {token}"

    url = f"https://api.github.com/repos/{repo}/releases/tags/{urllib.parse.quote(tag, safe='')}"
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
        if data.get("immutable") is True and data.get("published_at"):
            return datetime.fromisoformat(data["published_at"].replace("Z", "+00:00"))
    except (urllib.error.URLError, KeyError, TypeError, ValueError, TimeoutError):
        return None
    return None


def get_earliest_merged_pr_date(repo, sha, token=None):
    """Earliest server-side `merged_at` among PRs containing this commit,
    or None.

    A merge timestamp is recorded by GitHub's servers: an attacker can't
    retroactively insert a new commit into an old merged PR, and merging a
    fresh PR stamps `merged_at` = now. `created_at` is deliberately NOT
    used (an old open PR can receive new commits). Unmerged PRs are skipped.
    """
    if not is_sha(sha):
        return None

    import urllib.request
    import urllib.error

    headers = {"Accept": "application/vnd.github.v3+json"}
    if token:
        headers["Authorization"] = f"token {token}"

    url = f"https://api.github.com/repos/{repo}/commits/{sha}/pulls"
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
        dates = [
            datetime.fromisoformat(pr["merged_at"].replace("Z", "+00:00"))
            for pr in data
            if isinstance(pr, dict) and pr.get("merged_at")
        ]
        return min(dates) if dates else None
    except (urllib.error.URLError, KeyError, TypeError, ValueError, TimeoutError):
        return None


def list_series_tags(repo, ref, token=None):
    """Tags in `ref`'s release series, newest first, as [(tag, commit_sha)].

    Series = the tag itself or `ref.`-prefixed descendants, so `v4` matches
    `v4.3.0` but never `v40` (boundary-safe). Prerelease-looking tags
    (containing '-') are skipped unless the ref itself has one. One
    `git ls-remote --tags` call; annotated tags use their peeled (^{})
    commit SHA. Ordering is a tolerant version sort — good enough to walk
    a series newest-first, not a full semver implementation.

    Returns [] for branch refs, exact-version refs with no descendants,
    and unreachable repos — callers treat that as "no series to hold back
    through."
    """
    try:
        result = subprocess.run(
            ["git", "ls-remote", "--tags", "--", f"https://github.com/{repo}.git"],
            capture_output=True, text=True, timeout=15,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return []
    if result.returncode != 0:
        return []

    plain, peeled = {}, {}
    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) != 2:
            continue
        sha, refname = parts
        if not refname.startswith("refs/tags/") or not is_sha(sha):
            continue
        name = refname[len("refs/tags/"):]
        if name.endswith("^{}"):
            peeled[name[:-3]] = sha
        else:
            plain[name] = sha

    series = {}
    for name, sha in plain.items():
        if name != ref and not name.startswith(ref + "."):
            continue
        if "-" in name and "-" not in ref:
            continue  # prerelease-ish; hold back to real releases only
        series[name] = peeled.get(name, sha)

    def version_key(tag):
        key = []
        for chunk in re.split(r"[.\-]", tag):
            bare = chunk.lstrip("v")
            if bare.isdigit():
                key.append((0, int(bare), ""))
            else:
                key.append((1, 0, chunk))
        return key

    ordered = sorted(series, key=version_key, reverse=True)
    return [(t, series[t]) for t in ordered]


def select_aged_target(repo, ref, resolved_sha, min_age, require_trusted,
                       allow_fallback, token=None, max_candidates=8):
    """Pick the newest target for `ref` that clears the age floor.

    Candidate 0 is the ref's current target; when fallback is allowed and
    the ref is a tag, older tags in the same series follow. This is what
    keeps a 5-day quarantine livable: instead of failing CI on a fresh
    release (and training everyone to reach for --allow-fresh), lock rides
    the release series N days behind the edge.

    Returns a dict:
      ok:       True/False
      sha, tag, age, source:  the chosen target        (ok=True)
      held:     True when an older tag was chosen over the current target
      newest_age, newest_source:  candidate 0's age     (for messages)
      reason:   "fresh" | "unknown"                     (ok=False)
    """
    candidates = []
    if resolved_sha:
        candidates.append((ref, resolved_sha))
    if allow_fallback and not is_sha(ref):
        seen = {sha for _, sha in candidates}
        for tag, sha in list_series_tags(repo, ref, token):
            if sha not in seen:
                candidates.append((tag, sha))
                seen.add(sha)
            if len(candidates) >= max_candidates:
                break

    newest_age = newest_source = None
    any_unknown = False
    for i, (cand_tag, cand_sha) in enumerate(candidates):
        tag_arg = None if is_sha(cand_tag) else cand_tag
        age, source, trusted_src = ref_age_days(repo, cand_sha, tag_arg, token)
        if i == 0:
            newest_age, newest_source = age, source
        if age is None:
            any_unknown = True
            continue
        if require_trusted and not trusted_src:
            continue
        if age >= min_age:
            return {
                "ok": True, "sha": cand_sha, "tag": cand_tag, "age": age,
                "source": source, "held": i > 0,
                "newest_age": newest_age, "newest_source": newest_source,
            }
    return {
        "ok": False, "held": False,
        "reason": "unknown" if (any_unknown and newest_age is None) else "fresh",
        "newest_age": newest_age, "newest_source": newest_source,
    }


def ref_age_days(repo, sha, tag=None, token=None):
    """Best-available age of a ref in days: (age, source, trusted) or
    (None, None, False).

    Trust ladder:
      1. Immutable-release `published_at` (server clock, tag frozen) —
         when the ref came from a tag that has one. TRUSTED.
      2. Earliest merged-PR `merged_at` containing the commit (server
         clock). TRUSTED.
      3. Commit committer date (git metadata — heuristic, backdatable).
         NOT trusted; accepted unless policy says require_trusted_age.
    """
    date = get_release_published_at(repo, tag, token)
    source, trusted = "immutable release", True
    if date is None:
        date = get_earliest_merged_pr_date(repo, sha, token)
        source, trusted = "merged pull request", True
    if date is None:
        date = get_commit_date(repo, sha, token)
        source, trusted = "committer date", False
    if date is None:
        return None, None, False
    return (datetime.now(timezone.utc) - date).total_seconds() / 86400, source, trusted


def load_lockfile(repo_root):
    """Load existing lockfile or return empty structure."""
    lockfile_path = repo_root / LOCKFILE_NAME
    if lockfile_path.exists():
        with open(lockfile_path) as f:
            return json.load(f)
    return {"version": LOCKFILE_VERSION, "locked": {}}


def save_lockfile(repo_root, lockdata):
    """Write lockfile."""
    lockfile_path = repo_root / LOCKFILE_NAME
    lockdata["version"] = LOCKFILE_VERSION
    with open(lockfile_path, "w") as f:
        json.dump(lockdata, f, indent=2, sort_keys=True)
        f.write("\n")
    print(f"Wrote {lockfile_path}")


def get_github_token():
    """Try to get a GitHub token from environment."""
    for var in ["GITHUB_TOKEN", "GH_TOKEN", "GITHUB_TOKEN_RO"]:
        token = os.environ.get(var)
        if token:
            return token
    # Try gh CLI
    try:
        result = subprocess.run(
            ["gh", "auth", "token"], capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return None


def normalize_trusted_prefixes(prefixes):
    """Validate and normalize trusted_prefixes from the lockfile.

    A prefix must contain a '/' so it can never match across an owner
    boundary (e.g. "actions" would otherwise trust "actions-evil/foo").
    Prefixes are normalized to end in '/' and matched against the action
    reference with a trailing '/' appended, so both owner prefixes
    ("your-org/") and full-repo prefixes ("aws-actions/configure-aws-credentials")
    match exactly at path-segment boundaries.

    Returns (normalized_prefixes, errors).
    """
    normalized = []
    errors = []
    for p in prefixes:
        if "/" not in p:
            errors.append(
                f"INVALID trusted_prefixes entry `{p}`: must contain '/' "
                f"(e.g. `{p}/`) — owner-boundary matching requires it"
            )
            continue
        normalized.append(p if p.endswith("/") else p + "/")
    return normalized, errors


def is_trusted(action, trusted_prefixes):
    """Check a (normalized) trusted prefix list against an action reference,
    matching only at full path-segment boundaries."""
    return any((action + "/").startswith(p) for p in trusted_prefixes)


def normalize_policy(lockdata):
    """Validate and normalize the lockfile `policy` block.

    Shape (all keys optional):

      "policy": {
        "min_age_days": 5,
        "require_trusted_age": false,
        "overrides": [
          {"prefix": "your-org/hot-repo", "min_age_days": 0},
          {"prefix": "somevendor/", "require_trusted_age": true}
        ]
      }

    Policy lives in the lockfile ON PURPOSE: it's PR-reviewed and
    CODEOWNERS-able, unlike org/repo/env variables, whose precedence lets
    anyone with repo write silently override what an org admin set.

    Unknown keys are ERRORS, not warnings — a typo like "min_age_dayz"
    must not silently weaken the floor. Prefixes follow the same
    owner-boundary rules as trusted_prefixes. Returns (policy, errors)
    where policy = {"min_age_days": float, "require_trusted_age": bool,
    "overrides": [(prefix, {...}), ...] sorted most-specific-first}.
    """
    default = {
        "min_age_days": float(MIN_COMMIT_AGE_DAYS),
        "require_trusted_age": False,
        "fallback": True,
        "overrides": [],
    }
    raw = lockdata.get("policy")
    if raw is None:
        return default, []
    errors = []
    if not isinstance(raw, dict):
        return default, ["POLICY: `policy` must be an object"]

    def check_keys(obj, allowed, where):
        for k in obj:
            if k not in allowed:
                errors.append(
                    f"POLICY: unknown key `{k}` in {where} — "
                    f"a typo here would silently weaken the age floor"
                )

    def check_age(value, where):
        if not isinstance(value, (int, float)) or isinstance(value, bool) or value < 0:
            errors.append(f"POLICY: `min_age_days` in {where} must be a number >= 0")
            return None
        return float(value)

    def check_flag(value, name, where):
        if not isinstance(value, bool):
            errors.append(f"POLICY: `{name}` in {where} must be true/false")
            return None
        return value

    check_keys(raw, {"min_age_days", "require_trusted_age", "fallback", "overrides"}, "policy")
    policy = dict(default)
    if "min_age_days" in raw:
        v = check_age(raw["min_age_days"], "policy")
        if v is not None:
            policy["min_age_days"] = v
    if "require_trusted_age" in raw:
        v = check_flag(raw["require_trusted_age"], "require_trusted_age", "policy")
        if v is not None:
            policy["require_trusted_age"] = v
    if "fallback" in raw:
        v = check_flag(raw["fallback"], "fallback", "policy")
        if v is not None:
            policy["fallback"] = v

    overrides = []
    raw_overrides = raw.get("overrides", [])
    if not isinstance(raw_overrides, list):
        errors.append("POLICY: `overrides` must be a list")
        raw_overrides = []
    for i, ov in enumerate(raw_overrides):
        where = f"policy.overrides[{i}]"
        if not isinstance(ov, dict):
            errors.append(f"POLICY: {where} must be an object")
            continue
        check_keys(ov, {"prefix", "min_age_days", "require_trusted_age", "fallback"}, where)
        prefix = ov.get("prefix")
        if not isinstance(prefix, str) or "/" not in prefix:
            errors.append(
                f"POLICY: {where} needs a `prefix` containing '/' "
                f"(owner-boundary matching requires it)"
            )
            continue
        normalized = prefix if prefix.endswith("/") else prefix + "/"
        entry = {}
        if "min_age_days" in ov:
            v = check_age(ov["min_age_days"], where)
            if v is not None:
                entry["min_age_days"] = v
        if "require_trusted_age" in ov:
            v = check_flag(ov["require_trusted_age"], "require_trusted_age", where)
            if v is not None:
                entry["require_trusted_age"] = v
        if "fallback" in ov:
            v = check_flag(ov["fallback"], "fallback", where)
            if v is not None:
                entry["fallback"] = v
        overrides.append((normalized, entry))

    # Most-specific prefix wins, independent of file order
    overrides.sort(key=lambda item: len(item[0]), reverse=True)
    policy["overrides"] = overrides
    return policy, errors


def effective_policy(action, policy):
    """(min_age_days, require_trusted_age, fallback) for one action
    reference, applying the most specific matching override."""
    for prefix, ov in policy["overrides"]:
        if (action + "/").startswith(prefix):
            return (
                ov.get("min_age_days", policy["min_age_days"]),
                ov.get("require_trusted_age", policy["require_trusted_age"]),
                ov.get("fallback", policy["fallback"]),
            )
    return policy["min_age_days"], policy["require_trusted_age"], policy["fallback"]


def owner_repo_of(action):
    """Extract owner/repo from an action reference like 'owner/repo/subpath'."""
    parts = action.split("/")
    return f"{parts[0]}/{parts[1]}"


def vendor_dir_name(action, sha):
    """Directory name for a vendored action: owner--repo@shortsha
    ('--' instead of '/' for filesystem safety)."""
    return action.replace("/", "--") + f"@{sha[:10]}"


def tree_hash(root):
    """Deterministic content hash of a directory tree.

    sha256 over "relpath\\0filehash" lines (paths sorted, '/' separators).
    Regular files hash their bytes; symlinks hash their target string.
    Empty directories and file modes are not represented. The vendor
    metadata file (.action-lock-meta.json) is excluded so recording the
    hash doesn't change it.

    GitHub's archive tarballs are NOT byte-stable across time (compression
    metadata changes — see the Jan 2023 codeload checksum incident), so we
    hash extracted file contents, never the tarball itself.
    """
    root = Path(root)
    entries = []
    for path in sorted(root.rglob("*"), key=lambda p: p.relative_to(root).as_posix()):
        rel = path.relative_to(root).as_posix()
        if rel == META_FILE:
            continue
        if path.is_symlink():
            h = hashlib.sha256(b"symlink:" + os.readlink(path).encode()).hexdigest()
        elif path.is_file():
            h = hashlib.sha256(path.read_bytes()).hexdigest()
        else:
            continue  # directories are implied by the paths under them
        entries.append(f"{rel}\0{h}")
    digest = hashlib.sha256("\n".join(entries).encode()).hexdigest()
    return f"sha256:{digest}"


# --- Parser lab (experimental; ADR 0001) ---
#
# Workflow discovery is moving behind parser backends that can be compared
# differentially (docs/adr/0001-workflow-parser-backends.md and
# docs/parser-lab/IMPLEMENTATION.md). The legacy scanner above
# (parse_workflows) remains THE production path for lock/verify/rewrite —
# nothing below changes its behavior. The `lab/0` backend is that same
# line-oriented idea made explicit and honest: it assigns semantic paths,
# classifies reference kinds, excludes comments and block-scalar bodies,
# and reports what it cannot classify instead of returning nothing.
#
# The safety rule for every backend: ambiguity or parser failure must
# surface as diagnostics with accepted=False — never as an empty success.

PARSER_LAB_SCHEMA_VERSION = 1

REFERENCE_KINDS = (
    "external-action",
    "reusable-workflow",
    "local-action",
    "docker-image",
)


@dataclass(frozen=True, order=True)
class WorkflowReference:
    """One executable `uses:` slot in a workflow file.

    `semantic_path` (jobs.<job_id>.uses or jobs.<job_id>.steps[<i>].uses)
    is comparison identity across backends; line/column are diagnostics
    only. `raw_target` is the scalar without quotes or trailing comment.
    External/reusable targets split at the FINAL `@`; a target that cannot
    be split is still returned, with action=None/ref=None plus an
    INVALID_USES_TARGET diagnostic — the parser reports structure, policy
    judges validity. Positions are 1-based; end positions are None when
    unknown (lab/0 never fabricates rewrite spans from line matching).
    """
    file: str
    semantic_path: str
    kind: str
    raw_target: str
    action: Optional[str]
    ref: Optional[str]
    line: int
    column: int
    end_line: Optional[int] = None
    end_column: Optional[int] = None


@dataclass(frozen=True)
class ParseDiagnostic:
    """A parser finding. severity `error` means the scan cannot be trusted
    as complete (the owning ParseResult must carry accepted=False);
    `warning`/`note` are advisory. Messages never quote arbitrary workflow
    line content (scripts may embed secrets) — only positions, codes, and
    `uses` target values."""
    file: str
    code: str
    message: str
    severity: str
    line: Optional[int] = None
    column: Optional[int] = None


@dataclass(frozen=True)
class ParseResult:
    """What one backend concluded about one file. accepted=False means
    "this scan is not evidence of absence": callers must treat the file
    as unverified, never as reference-free."""
    backend: str
    references: Tuple[WorkflowReference, ...]
    diagnostics: Tuple[ParseDiagnostic, ...]
    accepted: bool


# Same owner/repo[/subpath] shape the legacy USES_PATTERN accepts.
_ACTION_SHAPE = re.compile(
    r"^[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+(?:/[a-zA-Z0-9_./%-]+)?$"
)


def classify_uses_target(raw_target, job_level):
    """Classify a `uses` scalar -> (kind, action, ref, problem).

    Order per IMPLEMENTATION.md: docker:// first, then local paths, then
    job-level reusable workflows, then step-level external actions.
    `problem` explains a target that cannot be split into action@ref (the
    caller emits INVALID_USES_TARGET); the reference is still returned —
    never dropped — so downstream policy sees it. Ref VALUES are not
    filtered here: mutability and validity are verify's job, not the
    parser's.
    """
    if raw_target.startswith("docker://"):
        return "docker-image", None, None, None
    if raw_target.startswith("./") or raw_target.startswith("../"):
        return "local-action", None, None, None
    kind = "reusable-workflow" if job_level else "external-action"
    action, sep, ref = raw_target.rpartition("@")
    if not sep or not action or not ref:
        return kind, None, None, "target has no @ref"
    if not _ACTION_SHAPE.match(action):
        return kind, None, None, "target is not owner/repo[/subpath]@ref"
    if re.search(r"\s", ref):
        return kind, None, None, "ref contains whitespace"
    return kind, action, ref, None


class WorkflowParserBackend:
    """Contract: parse exactly one workflow file into a ParseResult.

    Backends are offline and deterministic: no network, no YAML includes,
    no reading beyond the given path, no mutation. A backend may support
    less YAML than GitHub accepts, but it must say so (diagnostics plus
    accepted=False) rather than return a silently incomplete scan.
    """

    name = "abstract"

    def parse_file(self, repo_root, path):
        raise NotImplementedError


# Lab v0 line shapes. Every pattern is single-pass with no nested
# unbounded quantifiers (see the long-line regression tests).
_LAB_KEY_LINE = re.compile(
    r"^(?P<key>[A-Za-z_][A-Za-z0-9_.-]*)\s*:(?:[ \t]+(?P<value>.*))?$"
)
# Any `uses:`-shaped key (quoted or not) that the scanner did not
# positively classify or safely exclude must reject the file.
_LAB_SUSPECT_USES = re.compile(r"""(?<![\w-])["']?uses["']?\s*:""")
_LAB_BLOCK_HEADER = re.compile(r"^[|>][0-9+-]{0,2}[ \t]*(?:#.*)?$")
_LAB_JOB_ID = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]*$")
_LAB_SQUOTED = re.compile(r"^'(?P<body>(?:[^']|'')*)'[ \t]*(?:#.*)?$")
_LAB_DQUOTED = re.compile(r'^"(?P<body>(?:[^"\\]|\\.)*)"[ \t]*(?:#.*)?$')
# A mapping key written as a QUOTED scalar, e.g. `"uses":` or `'uses':`.
# lab/0 does not model quoted keys, and — crucially — a quoted key can hide
# an executable `uses` from a name-based scan: `"uses":` decodes to
# `uses` on GitHub but shares no literal bytes with `uses`. Any quoted key
# in the jobs section is therefore rejected outright (fail closed), not
# guessed. The alternation is linear (no nested unbounded quantifiers).
_LAB_QUOTED_KEY = re.compile(
    r"""^(?:"(?:[^"\\]|\\.)*"|'(?:[^']|'')*')[ \t]*:"""
)


def _flow_delta(line):
    """Net flow-collection nesting change on one line: +1 per unmatched
    `[`/`{`, -1 per `]`/`}`, ignoring delimiters inside quotes or after a
    `#` comment. lab/0 does not model flow collections that span lines; the
    scanner uses this only to notice it is INSIDE an open one and fail
    closed, never to interpret the flow. Single pass, no backtracking."""
    depth = 0
    quote = None
    i = 0
    n = len(line)
    while i < n:
        c = line[i]
        if quote == "'":
            if c == "'":
                if i + 1 < n and line[i + 1] == "'":
                    i += 2
                    continue
                quote = None
        elif quote == '"':
            if c == "\\":
                i += 2
                continue
            if c == '"':
                quote = None
        else:
            if c == "#" and (i == 0 or line[i - 1] in " \t"):
                break
            if c in "'\"":
                quote = c
            elif c in "[{":
                depth += 1
            elif c in "]}":
                depth -= 1
        i += 1
    return depth


def _lab_scalar(value):
    """Extract the text of an inline YAML scalar -> (text, problem).

    Handles plain, single-quoted, and double-quoted scalars with trailing
    comments. Anything else (anchors, aliases, tags, flow collections,
    block headers, unterminated quotes, escape sequences) returns
    (None, why) so the caller fails closed with LAB_UNCLASSIFIED_USES.
    """
    if value.startswith("'"):
        m = _LAB_SQUOTED.match(value)
        if not m:
            return None, "unterminated or malformed single-quoted scalar"
        return m.group("body").replace("''", "'"), None
    if value.startswith('"'):
        m = _LAB_DQUOTED.match(value)
        if not m:
            return None, "unterminated or malformed double-quoted scalar"
        body = m.group("body")
        if "\\" in body:
            return None, "double-quoted escapes are outside lab/0's language"
        return body, None
    if value[:1] in "&*!":
        return None, "anchors, aliases and tags are outside lab/0's language"
    if value[:1] in "[{":
        return None, "flow collections are outside lab/0's language"
    if value[:1] == "#":
        return None, "empty scalar"
    if _LAB_BLOCK_HEADER.match(value):
        return None, "block scalars are outside lab/0's language for `uses`"
    text = re.split(r"[ \t]+#", value, maxsplit=1)[0].rstrip()
    if not text:
        return None, "empty scalar"
    return text, None


def _lab_scan(rel_file, lines):
    """Scan decoded workflow lines -> (references, diagnostics, accepted).

    Fail-closed invariants: every `uses:`-shaped line is either emitted as
    a reference, safely excluded (full-line comment or block-scalar body),
    or reported as LAB_UNCLASSIFIED_USES with accepted=False. YAML the
    tracker does not model on a jobs path — anchors/aliases/merge
    keys/tags in the jobs section, flow-style steps, extra documents, tab
    indentation, explicit block-scalar indentation — is
    LAB_UNSUPPORTED_SYNTAX with accepted=False. A repeated semantic path
    is DUPLICATE_PATH with accepted=False.
    """
    references = []
    diagnostics = []
    state = {"accepted": True}
    seen_paths = set()

    def diag(code, message, severity="error", line=None, column=None):
        diagnostics.append(
            ParseDiagnostic(rel_file, code, message, severity, line, column)
        )
        if severity == "error":
            state["accepted"] = False

    def emit(path, lineno, key_col, value, value_col, job_level):
        """Record one `uses` reference; any doubt becomes a diagnostic."""
        if value is None:
            diag(
                "LAB_UNCLASSIFIED_USES",
                "`uses:` has no inline scalar value",
                line=lineno, column=key_col + 1,
            )
            return
        scalar, problem = _lab_scalar(value)
        if scalar is None:
            diag(
                "LAB_UNCLASSIFIED_USES",
                f"`uses:` value not classifiable: {problem}",
                line=lineno, column=value_col + 1,
            )
            return
        if path in seen_paths:
            diag(
                "DUPLICATE_PATH",
                f"semantic path {path} occurs more than once",
                line=lineno, column=key_col + 1,
            )
            return
        seen_paths.add(path)
        kind, action, ref, problem = classify_uses_target(scalar, job_level)
        if problem:
            diag(
                "INVALID_USES_TARGET",
                f"`{scalar}`: {problem}",
                severity="warning", line=lineno, column=value_col + 1,
            )
        references.append(WorkflowReference(
            file=rel_file, semantic_path=path, kind=kind, raw_target=scalar,
            action=action, ref=ref, line=lineno, column=value_col + 1,
        ))

    block = None            # {"key_indent": int, "content_indent": int|None}
    doc_started = False     # any structural content seen yet
    doc_marker = False      # a leading `---` seen
    top_keys_seen = set()
    jobs_open = False       # inside a block-mapping `jobs:` section
    job_indent = None       # indent of job-id keys
    job_ids = set()
    cur_job = None
    job_child_indent = None  # indent of keys inside the current job
    in_steps = False
    steps_key_indent = None
    item_indent = None      # dash column of step items
    step_index = -1
    step_key_indent = None  # key column inside the current step item
    flow_depth = 0          # open [ ] / { } nesting carried across lines

    for lineno, raw in enumerate(lines, 1):
        line = raw.rstrip("\r")

        # Block-scalar bodies are opaque text: nothing inside one can be
        # an executable `uses` — and nothing inside one may leak out as a
        # fake reference either.
        if block is not None:
            if not line.strip():
                continue
            body_indent = len(line) - len(line.lstrip(" "))
            if body_indent > block["key_indent"]:
                if block["content_indent"] is None:
                    block["content_indent"] = body_indent
                elif body_indent < block["content_indent"]:
                    diag(
                        "LAB_UNSUPPORTED_SYNTAX",
                        "block scalar dedents below its first content line",
                        line=lineno,
                    )
                continue
            block = None  # this line ends the block; process it normally

        stripped = line.strip()
        if not stripped:
            continue
        indent = len(line) - len(line.lstrip(" "))
        if line[indent:indent + 1] == "\t":
            diag("LAB_UNSUPPORTED_SYNTAX", "tab indentation", line=lineno)
            continue
        if stripped.startswith("#"):
            continue  # full-line comments are structure-free by definition
        if stripped.startswith("%") and not doc_started:
            diag(
                "LAB_UNSUPPORTED_SYNTAX",
                "YAML directives are outside lab/0's language",
                line=lineno,
            )
            continue
        if stripped == "---" or stripped.startswith("--- "):
            if doc_started or doc_marker or stripped != "---":
                diag(
                    "LAB_UNSUPPORTED_SYNTAX",
                    "multiple YAML documents (or content after `---`)",
                    line=lineno,
                )
            doc_marker = True
            continue
        if stripped == "..." or stripped.startswith("... "):
            diag("LAB_UNSUPPORTED_SYNTAX", "document end marker", line=lineno)
            continue
        doc_started = True

        # Flow collections that span lines defeat the block tracker: a
        # continuation line (e.g. the second half of `- { name: x,` \n
        # `uses: a/b@v1 }`) looks like an ordinary mapping key and would be
        # emitted with the closing `}` glued onto its target. lab/0 does
        # not model multi-line flow — once one is open, every line inside
        # it is rejected. Balanced single-line flow (a matrix `[a, b]`)
        # nets to zero and is unaffected; a `uses` lookalike on such a line
        # is still caught by the suspicion net. The depth update runs
        # before any downstream `continue` so it can never be skipped.
        if flow_depth > 0:
            diag(
                "LAB_UNSUPPORTED_SYNTAX",
                "multi-line flow collection is outside lab/0's language",
                line=lineno,
            )
            flow_depth = max(0, flow_depth + _flow_delta(line))
            continue
        flow_depth = max(0, flow_depth + _flow_delta(line))

        # Split leading sequence dashes off the line (`- uses: x`,
        # `- - x`, a lone `-`), tracking the column where content starts.
        rest = line[indent:]
        col = indent
        dash_cols = []
        while rest == "-" or rest.startswith("- "):
            dash_cols.append(col)
            if rest == "-":
                col += 1
                rest = ""
                break
            advance = 1
            while advance < len(rest) and rest[advance] == " ":
                advance += 1
            col += advance
            rest = rest[advance:]

        key = value = None
        value_col = col
        km = _LAB_KEY_LINE.match(rest)
        if km:
            key = km.group("key")
            value = km.group("value")
            if value is not None:
                if not value.strip() or value.lstrip().startswith("#"):
                    value = None
                else:
                    value_col = col + km.start("value")
                    value = value.rstrip()

        # A QUOTED mapping key in the jobs section is not modeled — and is
        # a fail-open risk the name-based suspicion net cannot cover: a key
        # written `"uses":` (or with an escape, `"uses":`) executes as
        # `uses` on GitHub while sharing no literal bytes with `uses`. So a
        # quoted key inside `jobs:` is rejected outright rather than
        # guessed. At column 0 it is instead a new top-level section
        # (unusual, but `"on":` is legal), which simply ends the jobs block.
        if jobs_open and km is None and _LAB_QUOTED_KEY.match(rest):
            if indent == 0 and not dash_cols:
                jobs_open = False
                job_indent = cur_job = job_child_indent = None
                in_steps = False
                steps_key_indent = item_indent = step_key_indent = None
                step_index = -1
                continue
            diag(
                "LAB_UNSUPPORTED_SYNTAX",
                "quoted mapping key in the jobs section is outside lab/0's "
                "language (a quoted key can hide an executable `uses`)",
                line=lineno,
            )
            continue

        # Merge keys and complex keys inside jobs can inject steps the
        # tracker cannot see — fail closed.
        if jobs_open and (
            rest.startswith("<<") or rest == "?" or rest.startswith("? ")
        ):
            diag(
                "LAB_UNSUPPORTED_SYNTAX",
                "merge/complex keys are outside lab/0's language",
                line=lineno,
            )
            continue

        # Does this line open a block scalar? (Its body is opaque text.)
        opens_block = None
        if key is not None and value is not None and _LAB_BLOCK_HEADER.match(value):
            opens_block = {"key_indent": col, "content_indent": None}
        elif dash_cols and rest and _LAB_BLOCK_HEADER.match(rest):
            opens_block = {"key_indent": dash_cols[-1], "content_indent": None}
        if opens_block is not None and re.search(r"\d", (value or rest)[:3]):
            diag(
                "LAB_UNSUPPORTED_SYNTAX",
                "explicit block-scalar indentation indicator",
                line=lineno,
            )

        handled = False

        if key is not None and not dash_cols and indent == 0:
            # A top-level section key. Duplicates are duplicate YAML keys
            # (GitHub rejects the file) and would corrupt path identity.
            if key in top_keys_seen:
                diag(
                    "LAB_UNSUPPORTED_SYNTAX",
                    f"duplicate top-level key `{key}`",
                    line=lineno,
                )
            top_keys_seen.add(key)
            jobs_open = key == "jobs" and value is None and opens_block is None
            job_indent = None
            cur_job = None
            job_child_indent = None
            in_steps = False
            steps_key_indent = None
            item_indent = None
            step_index = -1
            step_key_indent = None
            # `jobs:` with an inline value (flow mapping, anchor, alias)
            # is outside the modeled language; any `uses:` under it falls
            # through to the suspicion net below.
        elif jobs_open and key is not None and not dash_cols:
            # A mapping key somewhere inside the `jobs:` block.
            if value is not None and value[:1] in "&*!":
                diag(
                    "LAB_UNSUPPORTED_SYNTAX",
                    "anchor/alias/tag in the jobs section",
                    line=lineno,
                )
                handled = True
            elif job_indent is None or indent == job_indent:
                job_indent = indent
                cur_job = key
                job_child_indent = None
                in_steps = False
                steps_key_indent = None
                item_indent = None
                step_index = -1
                step_key_indent = None
                if not _LAB_JOB_ID.match(key):
                    diag(
                        "LAB_UNSUPPORTED_SYNTAX",
                        "job id does not fit lab/0's path grammar",
                        line=lineno,
                    )
                elif key in job_ids:
                    diag(
                        "LAB_UNSUPPORTED_SYNTAX",
                        f"duplicate job id `{key}`",
                        line=lineno,
                    )
                job_ids.add(key)
            elif indent < job_indent:
                diag(
                    "LAB_UNSUPPORTED_SYNTAX",
                    "unexpected dedent inside `jobs:`",
                    line=lineno,
                )
            elif cur_job is None:
                diag(
                    "LAB_UNSUPPORTED_SYNTAX",
                    "mapping nested under `jobs:` without a job id",
                    line=lineno,
                )
            else:
                if job_child_indent is None:
                    job_child_indent = indent
                if indent == job_child_indent:
                    in_steps = False
                    if key == "steps":
                        if value is not None or opens_block is not None:
                            diag(
                                "LAB_UNSUPPORTED_SYNTAX",
                                "`steps:` with an inline or block value",
                                line=lineno,
                            )
                            handled = True
                        else:
                            in_steps = True
                            steps_key_indent = indent
                            item_indent = None
                            step_index = -1
                            step_key_indent = None
                    elif key == "uses":
                        emit(
                            f"jobs.{cur_job}.uses", lineno, col,
                            value, value_col, job_level=True,
                        )
                        handled = True
                elif indent > job_child_indent:
                    if in_steps and item_indent is not None and step_index >= 0:
                        if step_key_indent is None and indent > item_indent:
                            step_key_indent = indent
                        if indent == step_key_indent and key == "uses":
                            emit(
                                f"jobs.{cur_job}.steps[{step_index}].uses",
                                lineno, col, value, value_col,
                                job_level=False,
                            )
                            handled = True
                    # Otherwise: nested config under a job or step key —
                    # not a `uses` slot; the suspicion net still applies.
                else:
                    diag(
                        "LAB_UNSUPPORTED_SYNTAX",
                        f"unexpected dedent inside job `{cur_job}`",
                        line=lineno,
                    )
        elif jobs_open and dash_cols:
            if not in_steps or cur_job is None:
                # A sequence outside steps (matrix values, branch lists…)
                # cannot hold an executable `uses` — the net still looks.
                pass
            else:
                d = dash_cols[0]
                if item_indent is None:
                    if d >= steps_key_indent:
                        item_indent = d
                    else:
                        diag(
                            "LAB_UNSUPPORTED_SYNTAX",
                            "sequence item left of its `steps:` key",
                            line=lineno,
                        )
                        handled = True
                if item_indent is not None and d == item_indent:
                    if len(dash_cols) > 1:
                        diag(
                            "LAB_UNSUPPORTED_SYNTAX",
                            "nested sequence in `steps`",
                            line=lineno,
                        )
                        handled = True
                    else:
                        step_index += 1
                        step_key_indent = None
                        if rest == "":
                            pass  # a lone dash; keys follow on later lines
                        elif key is not None:
                            step_key_indent = col
                            if value is not None and value[:1] in "&*!":
                                diag(
                                    "LAB_UNSUPPORTED_SYNTAX",
                                    "anchor/alias/tag in the jobs section",
                                    line=lineno,
                                )
                                handled = True
                            elif key == "uses":
                                emit(
                                    f"jobs.{cur_job}.steps[{step_index}].uses",
                                    lineno, col, value, value_col,
                                    job_level=False,
                                )
                                handled = True
                        elif rest[:1] in "&*!":
                            diag(
                                "LAB_UNSUPPORTED_SYNTAX",
                                "anchor/alias/tag step item",
                                line=lineno,
                            )
                            handled = True
                        # else: a scalar step — GitHub rejects those; the
                        # suspicion net still guards `uses:` lookalikes.
                elif item_indent is not None and d > item_indent:
                    pass  # a sequence inside a step field — net applies
                elif item_indent is not None:
                    diag(
                        "LAB_UNSUPPORTED_SYNTAX",
                        "unexpected sequence dedent inside `steps`",
                        line=lineno,
                    )
                    handled = True

        # The suspicion net: a `uses:`-shaped token anywhere on a line the
        # scanner did not positively classify or safely exclude is
        # uncertainty, and uncertainty is never reported as absence.
        if not handled:
            suspect = _LAB_SUSPECT_USES.search(line)
            if suspect:
                diag(
                    "LAB_UNCLASSIFIED_USES",
                    "`uses:`-shaped text the scanner cannot place at "
                    "jobs.<job>.uses or jobs.<job>.steps[<i>].uses",
                    line=lineno, column=suspect.start() + 1,
                )
            elif jobs_open and key is None and not dash_cols:
                # Inside a block mapping, every line is a `key:`, a `- item`,
                # a comment, or blank. A bare scalar line is none of those:
                # it is a multi-line plain-scalar CONTINUATION that folds
                # into the previous value on GitHub (so a `uses:` already
                # emitted from that value's first line is truncated). lab/0
                # does not model line folding — fail closed rather than
                # trust a half-read scalar.
                diag(
                    "LAB_UNSUPPORTED_SYNTAX",
                    "unrecognized line in the jobs section — multi-line "
                    "scalars and other unmodeled constructs are outside "
                    "lab/0's language",
                    line=lineno,
                )

        if opens_block is not None:
            block = opens_block

    return references, diagnostics, state["accepted"]


class LegacyRegexBackend(WorkflowParserBackend):
    """Lab v0 (`lab/0`): the legacy line scanner behind the backend seam.

    A minimal indentation-aware tracker assigns each accepted `uses:` a
    semantic path (jobs.<job>.uses or jobs.<job>.steps[<i>].uses),
    excludes full-line comments and block-scalar bodies, and REJECTS the
    file (accepted=False — never an empty success) whenever it meets
    syntax it does not model safely. Scan-only: it never rewrites, never
    touches the network, and reads only the file it was given.

    Known, intentional differences from the legacy parse_workflows scanner
    (which production commands still use, unchanged): lab/0 excludes fake
    `uses:` inside block scalars instead of matching them, returns local
    and docker references as classified kinds instead of skipping them,
    and does not pre-filter ref values (policy's job). Compare mode
    (ADR 0001 PR 2) exists to measure exactly these gaps.
    """

    name = "lab/0"

    def parse_file(self, repo_root, path):
        """Parse one workflow file. I/O or decoding failure is reported as
        LAB_IO_ERROR with accepted=False — never as an empty result."""
        path = Path(path)
        repo_root = Path(repo_root)
        try:
            rel = path.resolve().relative_to(repo_root.resolve()).as_posix()
        except ValueError:
            rel = path.as_posix()
        try:
            text = path.read_bytes().decode("utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            note = ParseDiagnostic(
                rel, "LAB_IO_ERROR",
                f"cannot read workflow as UTF-8 text: {exc.__class__.__name__}",
                "error", None, None,
            )
            return ParseResult(self.name, (), (note,), accepted=False)
        if text.startswith("\ufeff"):
            text = text[1:]
        references, diagnostics, accepted = _lab_scan(rel, text.split("\n"))
        return ParseResult(
            backend=self.name,
            references=tuple(sorted(references)),
            diagnostics=tuple(diagnostics),
            accepted=accepted,
        )


PARSER_BACKENDS = {"lab": LegacyRegexBackend}


def _reference_as_json(ref):
    return {
        "semantic_path": ref.semantic_path,
        "kind": ref.kind,
        "raw_target": ref.raw_target,
        "action": ref.action,
        "ref": ref.ref,
        "line": ref.line,
        "column": ref.column,
        "end_line": ref.end_line,
        "end_column": ref.end_column,
    }


def _diagnostic_as_json(diagnostic):
    return {
        "code": diagnostic.code,
        "message": diagnostic.message,
        "severity": diagnostic.severity,
        "line": diagnostic.line,
        "column": diagnostic.column,
    }


# --- Commands ---

def cmd_lock(args, repo_root):
    """Resolve all action refs to SHAs and write lockfile."""
    actions = parse_workflows(repo_root)
    if not actions:
        print("No actions found in workflows.")
        return

    token = get_github_token()
    if not token:
        print("Warning: No GitHub token found. API rate limits will apply.", file=sys.stderr)
        print("Set GITHUB_TOKEN or run `gh auth login`.", file=sys.stderr)

    lockdata = load_lockfile(repo_root)
    trusted_prefixes, prefix_errors = normalize_trusted_prefixes(
        lockdata.get("trusted_prefixes", [])
    )
    for e in prefix_errors:
        print(f"Warning: {e}", file=sys.stderr)
    # A malformed policy must stop the lock, not silently lose its floors.
    policy, policy_errors = normalize_policy(lockdata)
    if policy_errors:
        for e in policy_errors:
            print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    # Programmatic callers (tests, other tools) may pass a bare Namespace —
    # default the age-floor knobs instead of raising AttributeError. The CLI
    # always sets both. An explicit --min-age-days beats lockfile policy.
    allow_fresh = getattr(args, "allow_fresh", False)
    min_age_cli = getattr(args, "min_age_days", None)
    updated = 0
    failed = 0
    refused = 0

    for action_ref, locations in sorted(actions.items()):
        action, ref = action_ref.rsplit("@", 1)
        or_key = owner_repo_of(action)

        # Already locked at this exact ref?
        if action_ref in lockdata["locked"]:
            existing = lockdata["locked"][action_ref]
            if not args.force:
                print(f"  {action_ref} -> {existing['resolved'][:12]} (already locked)")
                continue

        # A SHA ref already covered by another entry (typically the tag-keyed
        # entry that `rewrite` pinned it from) must not spawn a duplicate —
        # otherwise every lock-after-rewrite doubles the lockfile with
        # tagless, update-untrackable entries. Applies even under --force:
        # force re-resolves refs; the covering entry is the one to force.
        if is_sha(ref):
            covered_by = next(
                (
                    key for key, e in lockdata["locked"].items()
                    if key != action_ref
                    and e["repo"] == action
                    and e["resolved"] == ref
                ),
                None,
            )
            if covered_by:
                print(f"  {action_ref[:60]}... (covered by {covered_by})"
                      if len(action_ref) > 63 else
                      f"  {action_ref} (covered by {covered_by})")
                continue

        print(f"  Resolving {action_ref}...", end=" ", flush=True)

        sha = resolve_ref_to_sha(or_key, ref, token)
        if not sha:
            print(red("FAILED (could not resolve)"))
            failed += 1
            continue

        # Age floor: quarantine fresh 3rd-party commits (see MIN_COMMIT_AGE_DAYS).
        # Trusted prefixes (internal actions) are exempt. Instead of refusing
        # a fresh target outright, hold back to the newest release in the
        # same series that clears the floor — a quarantine that fails CI
        # just trains everyone to reach for --allow-fresh.
        selected_tag = None
        if not allow_fresh and not is_trusted(action, trusted_prefixes):
            eff_min, eff_require, eff_fallback = effective_policy(action, policy)
            min_age = min_age_cli if min_age_cli is not None else eff_min
            fallback_on = eff_fallback and not getattr(args, "no_fallback", False)
            pick = select_aged_target(
                or_key, ref, sha, min_age, eff_require, fallback_on, token
            )
            if not pick["ok"]:
                if pick["reason"] == "unknown":
                    print(red(
                        f"FAILED (could not determine commit age for {sha[:12]}; "
                        f"use --allow-fresh to skip the age check)"
                    ))
                else:
                    newest = (
                        f"newest is {pick['newest_age']:.1f}d old by {pick['newest_source']}"
                        if pick["newest_age"] is not None else "ages undeterminable"
                    )
                    print(yellow(
                        f"REFUSED (nothing in the `{ref}` series clears the "
                        f"{min_age}-day age floor"
                        f"{' with a trusted age source' if eff_require else ''}; "
                        f"{newest}; use --allow-fresh to override)"
                    ))
                    refused += 1
                failed += 1
                continue
            if pick["held"]:
                sha = pick["sha"]
                selected_tag = pick["tag"]

        new_entry = {
            "resolved": sha,
            "tag": ref if not is_sha(ref) else None,
            "repo": action,
            "locked_at": datetime.now(timezone.utc).isoformat(),
            "locations": [{"file": f, "line": l} for f, l in locations],
        }
        if selected_tag:
            # The tracked channel stays `tag` (so update keeps riding it);
            # `selected` records the series release actually locked.
            new_entry["selected"] = selected_tag
        # A re-lock that resolves to the same SHA doesn't invalidate the
        # vendored content — carry the integrity hash forward.
        prev = lockdata["locked"].get(action_ref)
        if prev and prev.get("resolved") == sha and prev.get("integrity"):
            new_entry["integrity"] = prev["integrity"]
        lockdata["locked"][action_ref] = new_entry
        if selected_tag:
            newest_desc = (
                f"{pick['newest_age']:.1f}d old"
                if pick["newest_age"] is not None else "of unknown age"
            )
            print(
                green(sha[:12])
                + yellow(
                    f"  (held back to {selected_tag}: `{ref}` target is "
                    f"{newest_desc}, floor is {min_age}d)"
                )
            )
        else:
            print(green(sha[:12]))
        updated += 1

    # Refresh provenance breadcrumbs. `locations` are documentation, not
    # identity — verify re-parses workflows fresh and never reads them —
    # but stale line numbers lie to humans, so every lock re-derives them:
    # an entry's locations are wherever its own ref OR its resolved SHA
    # appears now (post-`rewrite`, that's the pinned lines).
    refreshed = 0
    for key, e in lockdata["locked"].items():
        key_ref = key.rsplit("@", 1)[1]
        locs = []
        for aref, alocs in actions.items():
            a, r = aref.rsplit("@", 1)
            if a == e["repo"] and r in (key_ref, e["resolved"]):
                for f, l in alocs:
                    loc = {"file": f, "line": l}
                    if loc not in locs:
                        locs.append(loc)
        # An entry absent from workflows keeps its last-known locations
        # (verify already warns STALE for those).
        if locs and e.get("locations") != locs:
            e["locations"] = locs
            refreshed += 1
    if refreshed:
        print(f"  (refreshed usage locations for {refreshed} entries)")

    save_lockfile(repo_root, lockdata)
    print(f"\nLocked {updated} actions ({failed} failed, {len(lockdata['locked']) - updated} unchanged)")
    if refused:
        print(yellow(
            "hint: REFUSED is the quarantine working — nothing in that release\n"
            "series has aged past the floor yet. Options: wait it out, review\n"
            "the commit and re-run with --allow-fresh, or add a lockfile policy\n"
            "override for that prefix (see README: Policy)."
        ))
    if failed:
        # A partial lock must not look like success in CI.
        sys.exit(1)


def cmd_verify(args, repo_root):
    """Verify all workflow refs match the lockfile."""
    actions = parse_workflows(repo_root)
    lockdata = load_lockfile(repo_root)

    if not lockdata["locked"]:
        print("No lockfile found. Run `action-locker lock` first.", file=sys.stderr)
        sys.exit(1)

    errors = []
    warnings = []

    # Trusted prefixes (e.g. "your-org/") may use mutable refs like @main.
    # Typical use: internal reusable workflows where SHA-pinning would mean a
    # cross-repo update on every shared-workflow change. Warned, not errored.
    # Prefixes are validated to contain '/' — a bare "actions" entry would
    # otherwise also trust "actions-evil/foo". Invalid entries fail verify.
    trusted_prefixes, prefix_errors = normalize_trusted_prefixes(
        lockdata.get("trusted_prefixes", [])
    )
    errors.extend(prefix_errors)

    # Validate the policy block too: verify is the gate where a malformed
    # policy (which would weaken the NEXT lock/update) gets caught in CI.
    _, policy_errors = normalize_policy(lockdata)
    errors.extend(policy_errors)

    for action_ref, locations in sorted(actions.items()):
        action, ref = action_ref.rsplit("@", 1)

        # Check: is the ref a mutable tag?
        if not is_sha(ref):
            if is_trusted(action, trusted_prefixes):
                for f, line in locations:
                    warnings.append(
                        f"TRUSTED MUTABLE: {f}:{line} uses `{action_ref}` (allowed by trusted_prefixes)"
                    )
            else:
                for f, line in locations:
                    errors.append(
                        f"MUTABLE REF: {f}:{line} uses `{action_ref}` — must pin to SHA"
                    )
            continue

        # Check: is this in the lockfile?
        found = False
        for locked_ref, entry in lockdata["locked"].items():
            if entry["resolved"] == ref and entry["repo"] == action:
                found = True
                break

        if not found:
            for f, line in locations:
                errors.append(
                    f"UNLOCKED: {f}:{line} uses `{action_ref}` — not in lockfile"
                )

    # Check for lockfile entries that are no longer used
    used_shas = set()
    for action_ref in actions:
        action, ref = action_ref.rsplit("@", 1)
        if is_sha(ref):
            used_shas.add((action, ref))

    for locked_ref, entry in lockdata["locked"].items():
        key = (entry["repo"], entry["resolved"])
        if key not in used_shas:
            warnings.append(f"STALE: {locked_ref} is locked but not used in any workflow")

    # Check vendored copies against recorded integrity hashes.
    # Vendoring is optional ("vendor critical, pin everything"), so a locked
    # action with no vendored copy is fine. But if a copy exists it must
    # match the lockfile, and no unexplained directories may appear — an
    # unrecognized directory in the vendor tree is exactly the kind of thing
    # a malicious PR would add.
    vendor_path = repo_root / VENDOR_DIR
    known_dirs = {
        vendor_dir_name(entry["repo"], entry["resolved"]): (locked_ref, entry)
        for locked_ref, entry in lockdata["locked"].items()
    }
    if vendor_path.is_dir():
        for d in sorted(vendor_path.iterdir()):
            if not d.is_dir():
                continue
            if d.name not in known_dirs:
                errors.append(
                    f"UNKNOWN VENDOR: {VENDOR_DIR}/{d.name} matches no lockfile entry "
                    f"— stale after an update (remove it) or unexpected (investigate)"
                )
                continue
            locked_ref, entry = known_dirs[d.name]
            expected = entry.get("integrity")
            if not expected:
                warnings.append(
                    f"NO INTEGRITY: {locked_ref} is vendored but the lockfile has no "
                    f"integrity hash — run `action-locker vendor --force` to record one"
                )
                continue
            actual = tree_hash(d)
            if actual != expected:
                errors.append(
                    f"INTEGRITY MISMATCH: {VENDOR_DIR}/{d.name} content does not match "
                    f"lockfile ({actual} != {expected})"
                )

    # Report
    if warnings:
        print(yellow("Warnings:"))
        for w in warnings:
            print(yellow(f"  {w}"))
        print()

    if errors:
        print(red("Errors:"))
        for e in errors:
            print(red(f"  {e}"))
        print(red(f"\n{len(errors)} error(s) found."))
        sys.exit(1)
    else:
        print(green(f"All {len(actions)} action references verified."))
        sys.exit(0)


def cmd_vendor(args, repo_root):
    """Download locked actions into the vendor directory."""
    lockdata = load_lockfile(repo_root)
    if not lockdata["locked"]:
        print("No lockfile found. Run `action-locker lock` first.", file=sys.stderr)
        sys.exit(1)

    token = get_github_token()
    vendor_path = repo_root / VENDOR_DIR
    vendor_path.mkdir(parents=True, exist_ok=True)

    vendored = 0
    skipped = 0
    failed = 0
    lockfile_dirty = False

    for action_ref, entry in sorted(lockdata["locked"].items()):
        action = entry["repo"]
        sha = entry["resolved"]
        short_sha = sha[:10]

        dir_name = vendor_dir_name(action, sha)
        dest = vendor_path / dir_name

        if dest.exists() and not args.force:
            print(f"  {dir_name} (already vendored)")
            skipped += 1
            continue

        print(f"  Vendoring {action}@{short_sha}...", end=" ", flush=True)

        or_key = owner_repo_of(action)
        parts = action.split("/", 2)
        subpath = parts[2] if len(parts) == 3 else None

        # Download the archive at the exact SHA
        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                # Use the public codeload URL — no auth needed for public repos
                archive_url = f"https://github.com/{or_key}/archive/{sha}.tar.gz"
                archive_path = os.path.join(tmpdir, "archive.tar.gz")

                # --fail: exit non-zero on HTTP errors instead of saving the error page
                result = subprocess.run(
                    ["curl", "-sL", "--fail", archive_url, "-o", archive_path],
                    capture_output=True, timeout=60
                )
                if result.returncode != 0 or not os.path.exists(archive_path) or os.path.getsize(archive_path) < 100:
                    print(red("FAILED (download)"))
                    failed += 1
                    continue

                # Extract
                result = subprocess.run(
                    ["tar", "xzf", archive_path, "-C", tmpdir],
                    capture_output=True, timeout=30
                )
                if result.returncode != 0:
                    print(red("FAILED (extract)"))
                    failed += 1
                    continue

                # Find the extracted directory (GitHub names it repo-fullsha/)
                extracted = [d for d in Path(tmpdir).iterdir()
                           if d.is_dir()]
                if not extracted:
                    print(red("FAILED (no content)"))
                    failed += 1
                    continue

                source = extracted[0]
                if subpath:
                    source = source / subpath
                    if not source.exists():
                        print(red(f"FAILED (subpath {subpath} not found)"))
                        failed += 1
                        continue

                # Copy to vendor directory
                if dest.exists():
                    shutil.rmtree(dest)
                shutil.copytree(source, dest)

                # Record content integrity in the lockfile so `verify` can
                # detect tampering with the vendored copy — offline, forever.
                integrity = tree_hash(dest)
                entry["integrity"] = integrity
                lockfile_dirty = True

                # Write a metadata file (excluded from the tree hash)
                meta = {
                    "action": action,
                    "sha": sha,
                    "tag": entry.get("tag"),
                    "vendored_at": datetime.now(timezone.utc).isoformat(),
                    "integrity": integrity,
                }
                with open(dest / META_FILE, "w") as f:
                    json.dump(meta, f, indent=2)
                    f.write("\n")

                print(green(f"OK ({integrity[:19]}...)"))
                vendored += 1

        except (subprocess.TimeoutExpired, OSError) as e:
            # Expected I/O failures (network timeout, disk, permissions).
            # Anything else is a bug and should surface, not be swallowed.
            print(red(f"FAILED ({e})"))
            failed += 1
            continue

    if lockfile_dirty:
        save_lockfile(repo_root, lockdata)

    print(f"\nVendored {vendored} actions ({skipped} already present, {failed} failed)")
    print(f"Vendor directory: {vendor_path}")
    if failed:
        print(f"ERROR: {failed} action(s) failed to vendor.", file=sys.stderr)
        sys.exit(1)


def cmd_update(args, repo_root):
    """Check for updates to locked actions."""
    lockdata = load_lockfile(repo_root)
    if not lockdata["locked"]:
        print("No lockfile found. Run `action-locker lock` first.", file=sys.stderr)
        sys.exit(1)

    token = get_github_token()
    updates = []

    for action_ref, entry in sorted(lockdata["locked"].items()):
        action = entry["repo"]
        tag = entry.get("tag")
        current_sha = entry["resolved"]

        if not tag:
            # Can't check for updates without a tag to track
            continue

        or_key = owner_repo_of(action)
        print(f"  Checking {action}@{tag}...", end=" ", flush=True)

        new_sha = resolve_ref_to_sha(or_key, tag, token)
        if not new_sha:
            print(red("UNAVAILABLE (repo may be gone!)"))
            updates.append({"action": action, "status": "unavailable", "ref": action_ref})
            continue

        if new_sha == current_sha:
            print(green("up to date"))
        else:
            print(yellow(f"UPDATE AVAILABLE ({current_sha[:12]} -> {new_sha[:12]})"))
            updates.append({
                "action": action,
                "status": "outdated",
                "ref": action_ref,
                "current": current_sha,
                "latest": new_sha,
                "tag": tag,
            })

    if not updates:
        print("\nAll actions are up to date.")
        return

    # Summary
    print("\n--- Update Summary ---")
    unavailable = [u for u in updates if u["status"] == "unavailable"]
    outdated = [u for u in updates if u["status"] == "outdated"]

    if unavailable:
        print(f"\n{len(unavailable)} UNAVAILABLE (upstream may be gone):")
        for u in unavailable:
            entry = lockdata["locked"][u["ref"]]
            dest = repo_root / VENDOR_DIR / vendor_dir_name(u["action"], entry["resolved"])
            status = "vendored copy exists" if dest.exists() else "NOT VENDORED — run `action-locker vendor` while you still can"
            print(f"  {u['action']} ({status})")

    if outdated:
        print(f"\n{len(outdated)} updates available:")
        for u in outdated:
            print(f"  {u['action']}@{u['tag']}: {u['current'][:12]} -> {u['latest'][:12]}")

        if args.apply:
            # Surface invalid trusted_prefixes entries just like cmd_lock():
            # silently dropping one would remove the trusted exemption and
            # cause unexplained age-floor skips.
            trusted_prefixes, prefix_errors = normalize_trusted_prefixes(
                lockdata.get("trusted_prefixes", [])
            )
            for e in prefix_errors:
                print(f"Warning: {e}", file=sys.stderr)
            policy, policy_errors = normalize_policy(lockdata)
            if policy_errors:
                for e in policy_errors:
                    print(f"Error: {e}", file=sys.stderr)
                sys.exit(1)
            allow_fresh = getattr(args, "allow_fresh", False)
            min_age_cli = getattr(args, "min_age_days", None)
            print("\nApplying updates...")
            applied = 0
            revendor_needed = False
            for u in outdated:
                # Same age floor as `lock`, same hold-back: don't move a pin
                # onto a fresh 3rd-party commit; ride the newest release in
                # the series that clears the floor instead.
                target_sha, held_note = u["latest"], None
                selected_tag = None
                if not allow_fresh and not is_trusted(u["action"], trusted_prefixes):
                    eff_min, eff_require, eff_fallback = effective_policy(u["action"], policy)
                    min_age = min_age_cli if min_age_cli is not None else eff_min
                    fallback_on = eff_fallback and not getattr(args, "no_fallback", False)
                    pick = select_aged_target(
                        owner_repo_of(u["action"]), u["tag"], u["latest"],
                        min_age, eff_require, fallback_on, token,
                    )
                    if not pick["ok"]:
                        newest = (
                            f"{pick['newest_age']:.1f} days old by {pick['newest_source']}"
                            if pick["newest_age"] is not None else "of unknown age"
                        )
                        print(yellow(
                            f"  SKIPPED {u['action']}: nothing in the `{u['tag']}` series "
                            f"clears the {min_age}-day age floor (newest is {newest}; "
                            f"--allow-fresh to override)"
                        ))
                        continue
                    target_sha = pick["sha"]
                    newest_desc = (
                        f"{pick['newest_age']:.1f}d old"
                        if pick["newest_age"] is not None else "of unknown age"
                    )
                    if pick["sha"] == u["current"]:
                        print(yellow(
                            f"  HELD {u['action']}: already at the newest release "
                            f"clearing the {min_age}-day floor "
                            f"(`{u['tag']}` target is {newest_desc})"
                        ))
                        continue
                    if pick["held"]:
                        selected_tag = pick["tag"]
                        held_note = (
                            f" (held back to {pick['tag']}: `{u['tag']}` target is "
                            f"{newest_desc})"
                        )
                entry = lockdata["locked"][u["ref"]]
                entry["resolved"] = target_sha
                entry["locked_at"] = datetime.now(timezone.utc).isoformat()
                if selected_tag:
                    entry["selected"] = selected_tag
                else:
                    entry.pop("selected", None)
                # The recorded integrity belongs to the OLD sha's content.
                # (Only for entries actually applied — a SKIPPED action keeps
                # its pin AND its integrity hash.)
                if entry.get("integrity"):
                    entry["integrity"] = None
                    revendor_needed = True
                print(green(f"  Updated {u['action']} -> {target_sha[:12]}")
                      + (yellow(held_note) if held_note else ""))
                applied += 1
            if applied:
                save_lockfile(repo_root, lockdata)
            else:
                print("No updates applied.")
            if revendor_needed:
                print(
                    "\nNote: integrity hashes were cleared for updated actions.\n"
                    "Run `action-locker vendor --force` to refresh vendored copies,\n"
                    "and remove the old vendor directories (verify will flag them)."
                )
        else:
            print("\nRun `action-locker update --apply` to apply these updates.")


def cmd_rewrite(args, repo_root):
    """Rewrite workflow files to use pinned SHAs from the lockfile."""
    lockdata = load_lockfile(repo_root)
    if not lockdata["locked"]:
        print("No lockfile found. Run `action-locker lock` first.", file=sys.stderr)
        sys.exit(1)

    # Build a lookup: action@mutable_ref -> sha. The pinned comment shows
    # `selected` when the entry was held back — the comment tells the truth
    # about what you actually got (and it's what Dependabot reads).
    ref_map = {}
    for action_ref, entry in lockdata["locked"].items():
        action, ref = action_ref.rsplit("@", 1)
        if not is_sha(ref):
            ref_map[(action, ref)] = (entry["resolved"], entry.get("selected") or ref)

    if not ref_map:
        print("No mutable refs to rewrite (everything is already pinned).")
        return

    workflows_dir = repo_root / ".github" / "workflows"
    rewrites = 0

    for wf_file in sorted(workflows_dir.glob("*.yml")) + sorted(workflows_dir.glob("*.yaml")):
        lines = wf_file.read_text().splitlines(keepends=True)
        modified = False

        for i, line in enumerate(lines):
            match = USES_PATTERN.search(line)
            if match:
                action = match.group("action")
                ref = match.group("ref")

                if (action, ref) in ref_map:
                    sha, tag = ref_map[(action, ref)]
                    old = f"{action}@{ref}"
                    new = f"{action}@{sha}  # {tag}"
                    lines[i] = line.replace(old, new)
                    modified = True
                    rewrites += 1

        if modified:
            wf_file.write_text("".join(lines))
            print(f"  Rewrote {wf_file.relative_to(repo_root)}")

    print(f"\n{rewrites} reference(s) rewritten to pinned SHAs.")


def cmd_scan(args, repo_root):
    """Structurally scan workflows with an experimental parser backend.

    Read-only and fully offline: parses workflow bytes, prints results,
    touches nothing. Production commands (lock/verify/rewrite) do NOT use
    this path yet — see ADR 0001.

    Exit codes (docs/parser-lab/IMPLEMENTATION.md): 0 = parsed cleanly;
    1 = a file was rejected (parser uncertainty is an error, never an
    empty result); 2 = invalid configuration; 4 = requested backend
    unavailable.
    """
    requested = (
        args.parser_backend
        or os.environ.get("ACTION_LOCKER_PARSER")
        or "lab"
    )
    if requested not in ("lab", "stable", "compare"):
        print(
            f"Error: unknown parser backend `{requested}` "
            f"(from --parser or ACTION_LOCKER_PARSER)",
            file=sys.stderr,
        )
        sys.exit(2)
    if requested not in PARSER_BACKENDS:
        print(
            f"Error: parser backend `{requested}` is not implemented yet "
            f"(see docs/parser-lab/IMPLEMENTATION.md); available: "
            f"{', '.join(sorted(PARSER_BACKENDS))}",
            file=sys.stderr,
        )
        sys.exit(4)
    backend = PARSER_BACKENDS[requested]()
    if not os.environ.get("ACTION_LOCKER_PARSER_LAB_CI"):
        print(
            yellow(
                f"note: `{backend.name}` is an experimental parser backend; "
                f"production commands still use the built-in scanner "
                f"(ADR 0001). Set ACTION_LOCKER_PARSER_LAB_CI=1 to silence."
            ),
            file=sys.stderr,
        )

    workflows_dir = repo_root / ".github" / "workflows"
    wf_files = []
    if workflows_dir.is_dir():
        wf_files = sorted(workflows_dir.glob("*.yml")) + sorted(
            workflows_dir.glob("*.yaml")
        )
    results = sorted(
        (
            (f.relative_to(repo_root).as_posix(), backend.parse_file(repo_root, f))
            for f in wf_files
        ),
        key=lambda item: item[0],
    )
    all_accepted = all(r.accepted for _, r in results)

    if args.format == "json":
        payload = {
            "schema_version": PARSER_LAB_SCHEMA_VERSION,
            "backend": backend.name,
            "accepted": all_accepted,
            "files": [
                {
                    "path": rel,
                    "accepted": r.accepted,
                    "references": [_reference_as_json(x) for x in r.references],
                    "diagnostics": [_diagnostic_as_json(d) for d in r.diagnostics],
                }
                for rel, r in results
            ],
        }
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        total_refs = 0
        for rel, r in results:
            if r.accepted:
                print(f"{rel} ({len(r.references)} reference(s))")
            else:
                print(red(f"REJECTED {rel}"))
            for x in r.references:
                total_refs += 1
                print(f"  {x.semantic_path}  {x.kind}  {x.raw_target}")
            for d in r.diagnostics:
                paint = red if d.severity == "error" else yellow
                where = f" line {d.line}" if d.line else ""
                print(paint(f"  {d.severity}[{d.code}]{where}: {d.message}"))
        if not results:
            print(f"No workflow files found under {workflows_dir}")
        summary = (
            f"\n{len(results)} file(s), {total_refs} reference(s), "
            f"backend {backend.name}"
        )
        if all_accepted:
            print(green(summary))
        else:
            print(red(summary + " — rejected file(s) present"))

    sys.exit(0 if all_accepted else 1)


# --- CLI ---

def main():
    parser = argparse.ArgumentParser(
        prog="action-locker",
        description="Pin and vendor GitHub Actions for supply chain security.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # lock
    lock_parser = subparsers.add_parser("lock", help="Resolve action refs to SHAs and write lockfile")
    lock_parser.add_argument("--force", action="store_true", help="Re-resolve already locked actions")
    lock_parser.add_argument(
        "--min-age-days", type=float, default=None, metavar="N",
        help=f"Refuse to lock 3rd-party commits younger than N days "
             f"(default: lockfile policy, else {MIN_COMMIT_AGE_DAYS})",
    )
    lock_parser.add_argument(
        "--allow-fresh", action="store_true",
        help="Skip the commit age floor (use only when you've reviewed the commit)",
    )
    lock_parser.add_argument(
        "--no-fallback", action="store_true",
        help="Never hold back to an older release; refuse fresh targets outright",
    )

    # verify
    subparsers.add_parser("verify", help="Check that all workflow refs match the lockfile")

    # vendor
    vendor_parser = subparsers.add_parser("vendor", help="Download locked actions into vendor directory")
    vendor_parser.add_argument("--force", action="store_true", help="Re-vendor already vendored actions")

    # update
    update_parser = subparsers.add_parser("update", help="Check for updates to locked actions")
    update_parser.add_argument("--apply", action="store_true", help="Apply available updates to lockfile")
    update_parser.add_argument(
        "--min-age-days", type=float, default=None, metavar="N",
        help=f"Refuse to update onto 3rd-party commits younger than N days "
             f"(default: lockfile policy, else {MIN_COMMIT_AGE_DAYS})",
    )
    update_parser.add_argument(
        "--allow-fresh", action="store_true",
        help="Skip the commit age floor (use only when you've reviewed the commit)",
    )
    update_parser.add_argument(
        "--no-fallback", action="store_true",
        help="Never hold back to an older release; refuse fresh targets outright",
    )

    # rewrite
    subparsers.add_parser("rewrite", help="Rewrite workflow files to use pinned SHAs from lockfile")

    # scan (experimental parser lab — ADR 0001)
    scan_parser = subparsers.add_parser(
        "scan",
        help="(experimental) structurally scan workflows for `uses` references",
    )
    scan_parser.add_argument(
        "--parser", dest="parser_backend",
        choices=["lab", "stable", "compare"], default=None,
        help="parser backend (default: ACTION_LOCKER_PARSER env var, else `lab`)",
    )
    scan_parser.add_argument(
        "--format", choices=["text", "json"], default="text",
        help="output format (json is deterministic and schema-versioned)",
    )

    args = parser.parse_args()
    repo_root = find_repo_root()

    commands = {
        "lock": cmd_lock,
        "verify": cmd_verify,
        "vendor": cmd_vendor,
        "update": cmd_update,
        "rewrite": cmd_rewrite,
        "scan": cmd_scan,
    }

    commands[args.command](args, repo_root)


if __name__ == "__main__":
    main()
