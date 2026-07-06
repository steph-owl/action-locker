# action-locker

A **lockfile** for your GitHub Actions — and a **locker** for the ones you
can't afford to lose. Pin, verify, and vendor, so your CI survives both
supply chain attacks and upstream disappearance.

![demo](demo/action-locker.gif)

## The problem

When you write `uses: some-org/cool-action@v1` in a workflow, you're trusting that:

1. The tag won't be moved to point at malicious code. It can be — that's
   exactly what happened to `tj-actions/changed-files` (CVE-2025-30066) in
   March 2025, when an attacker retagged every release of an action used by
   23,000+ repositories. Users pinned to a full commit SHA were unaffected.
2. The repo will still exist (and still be the same repo) tomorrow.
   Repos get archived, deleted, renamed, transferred, and lawyered every
   year — LocalStack's went read-only overnight in March 2026. Deletion is
   rarer than retagging, but when it happens, pinning alone leaves you with
   a 40-character hash pointing at nothing.
3. You'll get a say before new code runs in a context that holds your
   deploy credentials.

`action-locker` addresses all three: **pin** everything to immutable SHAs,
**verify** it stays that way (including the content of vendored copies),
and **vendor** a local snapshot of the actions you can't afford to lose.

The whole tool is a single stdlib-only Python file. A supply-chain tool
should not arrive with its own supply chain — you can read every line of
`action_locker.py` before trusting it, and we encourage you to.

## How it works

### 1. Lock (`action-locker lock`)

Scans `.github/workflows/*.yml`, resolves every `uses:` reference to an
immutable commit SHA, and writes an `action-lock.json` lockfile recording
the SHA, the tag it came from, when it was locked, and where it's used:

```json
{
  "version": 1,
  "locked": {
    "actions/checkout@v4": {
      "resolved": "b4ffde65f46336ab88eb53be808477a3936bae11",
      "tag": "v4.1.1",
      "repo": "actions/checkout",
      "locked_at": "2026-03-23T19:00:00Z",
      "integrity": "sha256:…",
      "locations": [{"file": ".github/workflows/ci.yml", "line": 12}]
    }
  }
}
```

### 2. Rewrite (`action-locker rewrite`)

Rewrites your workflow files to use the pinned SHAs, keeping the human-readable
tag as a comment (the same convention Dependabot understands):

```yaml
- uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11  # v4.1.1
```

### 3. Vendor (`action-locker vendor`)

Downloads a snapshot of each locked action into `.github/vendored-actions/`
and records a deterministic content hash (`integrity`) in the lockfile.
This is your insurance against upstream disappearance: if the action's repo
vanishes, you still have the exact code you audited, ready to fork or
reference locally.

```
.github/vendored-actions/
├── actions--checkout@b4ffde65f4/
│   ├── action.yml
│   ├── .action-lock-meta.json
│   └── ...
└── softprops--action-gh-release@153bb8e044/
    └── ...
```

Vendoring is per-action insurance, not a requirement: **vendor critical,
pin everything.**

### 4. Verify (`action-locker verify`)

The CI gate. Fully offline (parses workflows + lockfile + vendored trees —
no network, no tokens), so it's fast and adds no rate-limit concerns:

- Every `uses:` must be pinned to a full SHA (no `@v1`-style mutable refs)
- Every pinned SHA must be in the lockfile
- Every vendored copy must match its recorded `integrity` hash — a single
  modified, added, or renamed file fails the build
- No unexplained directories in the vendor tree
- Warns on stale lockfile entries and un-hashed vendored copies

### 5. Update (`action-locker update [--apply]`)

Checks upstream for new releases of everything in the lockfile. Nothing
moves without a human seeing it:

```
  Checking actions/checkout@v4... UPDATE AVAILABLE (b4ffde65f463 -> 34e114876b0b)
  Checking gone-org/gone-action@v2... UNAVAILABLE (repo may be gone!)
```

`--apply` updates the lockfile (and clears integrity hashes so you're
reminded to re-vendor). `update` is also your dead-upstream detector: it
tells you an action vanished *while you still have a vendored copy*.

## What it protects against — and what it doesn't

Honest threat model. Protects against:

| Threat | Mitigation |
|---|---|
| Tag retargeting (the tj-actions attack) | Workflows reference SHAs only; `verify` fails on any mutable ref |
| Upstream deletion / disappearance | Vendored snapshot, content-hashed in the lockfile |
| Tampered vendored copies (e.g. via a sneaky PR) | `integrity` tree hash checked on every `verify` |
| Silent version drift | Updates only via explicit `update --apply`, auditable in the lockfile diff |

Does **not** protect against:

- **Malicious code already at the SHA you pinned.** Pinning freezes what you
  chose; it doesn't review it for you. Vendoring at least gives you the full
  tree to audit.
- **Transitive references inside a pinned action.** A composite action you
  pinned may internally call `other/action@v1`. Your pin freezes that
  *reference*, not its target. Transitive resolution is on the roadmap;
  today, vendoring makes those internal references visible for audit.
- **Code an action downloads at runtime** (installers, `node_modules`
  fetched in a post step, etc.).
- **`docker://` images** — different supply chain; pin those by digest
  (`@sha256:…`) and action-locker will stay out of your way.

## Who pins the pinner?

Turtles all the way down, addressed explicitly:

- The composite action: consume it at a SHA like everything else —
  `uses: Old-Well-Labs/action-locker@<sha>`. It's one file; audit it first.
- The reusable workflow checks out the tool at `job.workflow_sha` — the
  exact commit *you* pinned when you wrote
  `uses: Old-Well-Labs/action-locker/.github/workflows/verify-action-locker.yml@<sha>`.
  There is no mutable `@v1` hop hiding in the middle.
- This repo's own CI runs `action_locker.py verify` on itself; its workflows
  are SHA-pinned and locked in its own `action-lock.json`.

## Prior art (and why this exists anyway)

This space got real attention after the tj-actions attack, and you should
know your options:

- [pinact](https://github.com/suzuki-shunsuke/pinact),
  [ratchet](https://github.com/sethvargo/ratchet),
  [frizbee](https://github.com/stacklok/frizbee) — rewrite refs to SHAs.
  Pinners, not lockfiles: no record of provenance, no verification of
  content, no disappearance story.
- [gh-actions-lockfile](https://github.com/gjtorikian/gh-actions-lockfile),
  [ghasum](https://github.com/chains-project/ghasum) — proper lockfiles with
  integrity hashing (and transitive resolution, which action-locker doesn't do
  yet). Neither vendors, and neither handles reusable workflows
  (`uses: org/repo/.github/workflows/x.yml@ref`) — action-locker does both.
- **Dependabot / Renovate** — keep pinned SHAs fresh via PRs. Complementary:
  use them alongside action-locker (`rewrite` emits the `# tag` comments they
  understand).
- **GitHub native**: immutable releases went GA in late 2025, and the 2026
  Actions security roadmap includes workflow dependency locking. Both are
  good news, and neither helps when upstream *disappears* — an immutable
  release of a deleted repo is still deleted, and a native lockfile still
  points at a repo you don't control.

The one-line positioning: **everyone else answers "is this the code I
chose?" — action-locker also answers "do I still have the code I chose?"**

## Install

It's one file. Choose your ritual:

```bash
# Copy it into your repo (recommended — then it's pinned too, by your own git history)
curl -o action_locker.py https://raw.githubusercontent.com/Old-Well-Labs/action-locker/<sha>/action_locker.py

# Or run from a clone
python3 action_locker.py --help
```

Requires Python 3.8+ and `git` (plus `curl`/`tar` for `vendor`). No pip
packages, no lockfile for the lockfile tool.

## Usage

```bash
python3 action_locker.py lock      # resolve refs -> action-lock.json
python3 action_locker.py rewrite   # pin workflow files to locked SHAs
python3 action_locker.py vendor    # snapshot locked actions + record integrity
python3 action_locker.py verify    # the CI gate (offline)
python3 action_locker.py update    # check upstream; --apply to accept
```

## Trusted prefixes

Internal reusable workflows (e.g.
`your-org/infrastructure/.github/workflows/shared-build.yml@main`) often
intentionally track `@main` — SHA-pinning them would require a cross-repo
update on every shared-workflow change, and you already control both sides.
Add a `trusted_prefixes` list to the lockfile to downgrade those from
errors to warnings in `verify`:

```json
{
  "version": 1,
  "trusted_prefixes": ["your-org/"],
  "locked": { }
}
```

Prefixes must contain a `/` and match only at path-segment boundaries, so
`your-org/` can never be satisfied by `your-org-evil/anything`. Invalid
prefixes fail `verify` rather than silently trusting nothing (or worse,
something).

Note: `rewrite` still pins trusted refs if they're in the lockfile — delete
them from `locked` first if you want them left on `@main`.

## CI integration

Simplest — the composite action, pinned by SHA:

```yaml
jobs:
  action-locker:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<sha>              # v4
      - uses: Old-Well-Labs/action-locker@<sha>     # runs `action-locker verify`
```

Or the reusable workflow (self-pins via `job.workflow_sha`; not available
on GitHub Enterprise Server — use the composite action there):

```yaml
on:
  pull_request:
  push:
    branches: [main]
  repository_dispatch:
    types: [action-lock-reverify]   # optional: accept push re-verification

jobs:
  action-locker:
    uses: Old-Well-Labs/action-locker/.github/workflows/verify-action-locker.yml@<sha>  # v1
```

### Push re-verification (repository_dispatch)

For orgs running many consumer repos: when `action_locker.py` or the reusable
verify workflow changes on `main`, the `dispatch-reverify` workflow sends a
`repository_dispatch` event (`action-lock-reverify`) to every repo listed
in `subscribers.txt`, so consumers re-check their lockfiles without waiting
for their next PR. It can also be run manually via `workflow_dispatch`
(optionally targeting one repo).

Requires the `ACTION_LOCK_DISPATCH_TOKEN` repo secret — a token with access
to the subscriber repos; the default `GITHUB_TOKEN` cannot dispatch
cross-repo. The job fails loudly if the secret is missing.

## Tests

```bash
python3 -m pytest            # offline unit tests (fixtures modeled on real production workflows)
python3 -m pytest -m network # live integration tests (git ls-remote against GitHub)
```

## Design principles

- **No tag refs, ever.** Tags are mutable. SHAs are not.
- **Vendor critical, pin everything.** Not every action needs vendoring,
  but every action must be pinned.
- **Updates are explicit.** No silent version bumps. Every change is
  auditable in a lockfile diff.
- **Verification is offline.** CI gates shouldn't depend on the network
  being honest.
- **Simple files, no magic.** The lockfile is JSON. The vendored actions
  are directories. `cat` and `ls` are your debuggers.
- **One file, stdlib only.** The tool that pins your dependencies has no
  dependencies of its own.

## Roadmap

- **A GitHub App** with permissions scoped to exactly one file — the
  lockfile — able to open re-lock/re-verify PRs across consumer repos
  without a broad PAT (replacing the `ACTION_LOCK_DISPATCH_TOKEN` pattern).
- **Transitive resolution**: surface and pin the `uses:` references inside
  vendored composite actions.
- **SBOM output** for your Actions dependency tree.

See the [demo repo](https://github.com/Old-Well-Labs/action-locker-demo) for
a worked example: a small app with pinned workflows, a lockfile, vendored
actions, and the CI wiring.

## About OWL
s
Built at [Old Well Labs](https://oldwell-labs.com) by Steph Prime (hn: sudosteph)

We're a fintech startup, we're growing fast, and **we are actively hiring Software Engineers** and **Data Engieneers** to join us in our **Charlotte NC** office (hybrid WFH). So if massive data sets don't scare you, if you've got a "bias for action" bent, and if you are cool with Charlotte but looking for something more exciting than a big bank - [apply now](https://jobs.ashbyhq.com/old-well-labs). 

Licensed under [Apache-2.0](LICENSE).
