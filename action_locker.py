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
                return sha
        except urllib.error.HTTPError:
            continue

    return None


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
    ("Old-Well-Labs/") and full-repo prefixes ("aws-actions/configure-aws-credentials")
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


def cmd_verify(args, repo_root):
    """Verify all workflow refs match the lockfile."""
    actions = parse_workflows(repo_root)
    lockdata = load_lockfile(repo_root)

    if not lockdata["locked"]:
        print("No lockfile found. Run `action-locker lock` first.", file=sys.stderr)
        sys.exit(1)

    errors = []
    warnings = []

    # Trusted prefixes (e.g. "Old-Well-Labs/") may use mutable refs like @main.
    # Typical use: internal reusable workflows where SHA-pinning would mean a
    # cross-repo update on every shared-workflow change. Warned, not errored.
    # Prefixes are validated to contain '/' — a bare "actions" entry would
    # otherwise also trust "actions-evil/foo". Invalid entries fail verify.
    trusted_prefixes, prefix_errors = normalize_trusted_prefixes(
        lockdata.get("trusted_prefixes", [])
    )
    errors.extend(prefix_errors)

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
            print("\nApplying updates...")
            revendor_needed = False
            for u in outdated:
                entry = lockdata["locked"][u["ref"]]
                entry["resolved"] = u["latest"]
                entry["locked_at"] = datetime.now(timezone.utc).isoformat()
                # The recorded integrity belongs to the OLD sha's content.
                if entry.get("integrity"):
                    entry["integrity"] = None
                    revendor_needed = True
                print(f"  Updated {u['action']} -> {u['latest'][:12]}")
            save_lockfile(repo_root, lockdata)
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

    # verify
    subparsers.add_parser("verify", help="Check that all workflow refs match the lockfile")

    # vendor
    vendor_parser = subparsers.add_parser("vendor", help="Download locked actions into vendor directory")
    vendor_parser.add_argument("--force", action="store_true", help="Re-vendor already vendored actions")

    # update
    update_parser = subparsers.add_parser("update", help="Check for updates to locked actions")
    update_parser.add_argument("--apply", action="store_true", help="Apply available updates to lockfile")

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
