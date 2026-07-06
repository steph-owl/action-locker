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
from datetime import datetime, timezone
from pathlib import Path

__version__ = "0.9.0"


# --- Constants ---

LOCKFILE_NAME = "action-lock.json"
LOCKFILE_VERSION = 1
VENDOR_DIR = ".github/vendored-actions"
META_FILE = ".action-lock-meta.json"

# Supply-chain quarantine: refuse to lock 3rd-party commits younger than this.
# Compromised actions are usually caught within days of the malicious commit —
# a brief age floor keeps you out of the blast window. trusted_prefixes are
# exempt. Age source is a trust ladder (see ref_age_days): an immutable
# release's server-side published_at when the tag has one (trusted — can't
# be backdated, tag can't move), else the commit's committer date (git
# metadata, backdatable — heuristic, not a wall). Unknown age fails closed.
MIN_COMMIT_AGE_DAYS = 5

# Matches: uses: owner/repo@ref  or  uses: owner/repo/path@ref
USES_PATTERN = re.compile(
    r'uses:\s*["\']?(?P<action>[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+(?:/[a-zA-Z0-9_./%-]+)?)@(?P<ref>[a-zA-Z0-9._/-]+)["\']?'
)

# A full SHA-1 is 40 hex chars
SHA_PATTERN = re.compile(r'^[0-9a-f]{40}$')


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

    def check_flag(value, where):
        if not isinstance(value, bool):
            errors.append(f"POLICY: `require_trusted_age` in {where} must be true/false")
            return None
        return value

    check_keys(raw, {"min_age_days", "require_trusted_age", "overrides"}, "policy")
    policy = dict(default)
    if "min_age_days" in raw:
        v = check_age(raw["min_age_days"], "policy")
        if v is not None:
            policy["min_age_days"] = v
    if "require_trusted_age" in raw:
        v = check_flag(raw["require_trusted_age"], "policy")
        if v is not None:
            policy["require_trusted_age"] = v

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
        check_keys(ov, {"prefix", "min_age_days", "require_trusted_age"}, where)
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
            v = check_flag(ov["require_trusted_age"], where)
            if v is not None:
                entry["require_trusted_age"] = v
        overrides.append((normalized, entry))

    # Most-specific prefix wins, independent of file order
    overrides.sort(key=lambda item: len(item[0]), reverse=True)
    policy["overrides"] = overrides
    return policy, errors


def effective_policy(action, policy):
    """(min_age_days, require_trusted_age) for one action reference,
    applying the most specific matching override."""
    for prefix, ov in policy["overrides"]:
        if (action + "/").startswith(prefix):
            return (
                ov.get("min_age_days", policy["min_age_days"]),
                ov.get("require_trusted_age", policy["require_trusted_age"]),
            )
    return policy["min_age_days"], policy["require_trusted_age"]


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

    for action_ref, locations in sorted(actions.items()):
        action, ref = action_ref.rsplit("@", 1)
        or_key = owner_repo_of(action)

        # Already locked at this exact ref?
        if action_ref in lockdata["locked"]:
            existing = lockdata["locked"][action_ref]
            if not args.force:
                print(f"  {action_ref} -> {existing['resolved'][:12]} (already locked)")
                continue

        print(f"  Resolving {action_ref}...", end=" ", flush=True)

        sha = resolve_ref_to_sha(or_key, ref, token)
        if not sha:
            print("FAILED (could not resolve)")
            failed += 1
            continue

        # Age floor: quarantine fresh 3rd-party commits (see MIN_COMMIT_AGE_DAYS).
        # Trusted prefixes (internal actions) are exempt.
        if not allow_fresh and not is_trusted(action, trusted_prefixes):
            eff_min, eff_require = effective_policy(action, policy)
            min_age = min_age_cli if min_age_cli is not None else eff_min
            tag_name = ref if not is_sha(ref) else None
            age, age_source, age_trusted = ref_age_days(or_key, sha, tag_name, token)
            if age is None:
                print(
                    f"FAILED (could not determine commit age for {sha[:12]}; "
                    f"use --allow-fresh to skip the age check)"
                )
                failed += 1
                continue
            if eff_require and not age_trusted:
                print(
                    f"REFUSED ({sha[:12]} age comes from {age_source} — policy "
                    f"requires a trusted source (immutable release or merged PR); "
                    f"vendor + review then --allow-fresh, or fix upstream)"
                )
                failed += 1
                continue
            if age < min_age:
                print(
                    f"REFUSED ({sha[:12]} is {age:.1f} days old by {age_source}, "
                    f"below the {min_age}-day age floor; use --allow-fresh to override)"
                )
                failed += 1
                continue

        new_entry = {
            "resolved": sha,
            "tag": ref if not is_sha(ref) else None,
            "repo": action,
            "locked_at": datetime.now(timezone.utc).isoformat(),
            "locations": [{"file": f, "line": l} for f, l in locations],
        }
        # A re-lock that resolves to the same SHA doesn't invalidate the
        # vendored content — carry the integrity hash forward.
        prev = lockdata["locked"].get(action_ref)
        if prev and prev.get("resolved") == sha and prev.get("integrity"):
            new_entry["integrity"] = prev["integrity"]
        lockdata["locked"][action_ref] = new_entry
        print(f"{sha[:12]}")
        updated += 1

    save_lockfile(repo_root, lockdata)
    print(f"\nLocked {updated} actions ({failed} failed, {len(lockdata['locked']) - updated} unchanged)")
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
        print("Warnings:")
        for w in warnings:
            print(f"  {w}")
        print()

    if errors:
        print("Errors:")
        for e in errors:
            print(f"  {e}")
        print(f"\n{len(errors)} error(s) found.")
        sys.exit(1)
    else:
        print(f"All {len(actions)} action references verified.")
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
                    print("FAILED (download)")
                    failed += 1
                    continue

                # Extract
                result = subprocess.run(
                    ["tar", "xzf", archive_path, "-C", tmpdir],
                    capture_output=True, timeout=30
                )
                if result.returncode != 0:
                    print("FAILED (extract)")
                    failed += 1
                    continue

                # Find the extracted directory (GitHub names it repo-fullsha/)
                extracted = [d for d in Path(tmpdir).iterdir()
                           if d.is_dir()]
                if not extracted:
                    print("FAILED (no content)")
                    failed += 1
                    continue

                source = extracted[0]
                if subpath:
                    source = source / subpath
                    if not source.exists():
                        print(f"FAILED (subpath {subpath} not found)")
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

                print(f"OK ({integrity[:19]}...)")
                vendored += 1

        except (subprocess.TimeoutExpired, OSError) as e:
            # Expected I/O failures (network timeout, disk, permissions).
            # Anything else is a bug and should surface, not be swallowed.
            print(f"FAILED ({e})")
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
            print("UNAVAILABLE (repo may be gone!)")
            updates.append({"action": action, "status": "unavailable", "ref": action_ref})
            continue

        if new_sha == current_sha:
            print("up to date")
        else:
            print(f"UPDATE AVAILABLE ({current_sha[:12]} -> {new_sha[:12]})")
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
                # Same age floor as `lock`: don't move a pin onto a fresh
                # 3rd-party commit.
                if not allow_fresh and not is_trusted(u["action"], trusted_prefixes):
                    eff_min, eff_require = effective_policy(u["action"], policy)
                    min_age = min_age_cli if min_age_cli is not None else eff_min
                    age, age_source, age_trusted = ref_age_days(
                        owner_repo_of(u["action"]), u["latest"], u.get("tag"), token
                    )
                    if eff_require and age is not None and not age_trusted:
                        print(
                            f"  SKIPPED {u['action']}: age source is {age_source} — "
                            f"policy requires a trusted source (immutable release "
                            f"or merged PR); --allow-fresh to override"
                        )
                        continue
                    if age is None or age < min_age:
                        age_desc = (
                            f"{age:.1f} days old by {age_source}"
                            if age is not None else "of unknown age"
                        )
                        print(
                            f"  SKIPPED {u['action']}: {u['latest'][:12]} is {age_desc} "
                            f"(below {min_age}-day age floor; --allow-fresh to override)"
                        )
                        continue
                entry = lockdata["locked"][u["ref"]]
                entry["resolved"] = u["latest"]
                entry["locked_at"] = datetime.now(timezone.utc).isoformat()
                # The recorded integrity belongs to the OLD sha's content.
                # (Only for entries actually applied — a SKIPPED action keeps
                # its pin AND its integrity hash.)
                if entry.get("integrity"):
                    entry["integrity"] = None
                    revendor_needed = True
                print(f"  Updated {u['action']} -> {u['latest'][:12]}")
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

    # Build a lookup: action@mutable_ref -> sha
    ref_map = {}
    for action_ref, entry in lockdata["locked"].items():
        action, ref = action_ref.rsplit("@", 1)
        if not is_sha(ref):
            ref_map[(action, ref)] = (entry["resolved"], ref)

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

    # rewrite
    subparsers.add_parser("rewrite", help="Rewrite workflow files to use pinned SHAs from lockfile")

    args = parser.parse_args()
    repo_root = find_repo_root()

    commands = {
        "lock": cmd_lock,
        "verify": cmd_verify,
        "vendor": cmd_vendor,
        "update": cmd_update,
        "rewrite": cmd_rewrite,
    }

    commands[args.command](args, repo_root)


if __name__ == "__main__":
    main()
