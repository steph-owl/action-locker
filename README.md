# action-locker

_Created by Steph Prime at Old Well Labs_

## Who doesn't like demo gifs?
### Lock that SHA up!

`action-locker` is a **lockfile** for your GitHub Actions and a **locker** for the ones you
can't afford to lose. 

Pin to a sha, verify the sha, and vendor critical repos, so your CI survives both
supply chain attacks and upstream disappearance. 

![lock that sha up!](gifs/adopt.gif)

### Minimum age: Let other people be the beta testers for new releases

`action-locker` has configurable settings for setting minimum age of actions to lock.
If it's too new - it will find the newest one that is compliant and use that automatically.
You can modify these settings to override age requirements for repos you own and trust.

![age-gate-demo](gifs/quarantine.gif)

### Vendoring Actions - Content Integrity Verification

![protect](gifs/protect.gif)


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
should not arrive with its own supply chain. You can read every line of
`action_locker.py` before trusting it. Or ask a model to if that's your vibe.

## How it works

### 1. Lock (`action-locker lock`)

Scans `.github/workflows/` (both `*.yml` and `*.yaml`), resolves every
`uses:` reference to an immutable commit SHA, and writes an
`action-lock.json` lockfile recording
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

A note on `locations`: they're provenance for humans, **not identity**.
Verification is content-based — `verify` re-parses your workflows fresh
every run and matches on (action, resolved SHA), so inserting lines,
reordering steps, or reformatting YAML can never confuse it. Each `lock`
re-derives the breadcrumbs so they stay truthful after edits and after
`rewrite`.

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

## Commit age floor (supply-chain quarantine)

`lock` and `update --apply` won't pin a 3rd-party action to a commit less
than **5 days old**. Supply chain attacks on popular actions are usually
caught within days of the malicious commit landing — a brief quarantine
keeps you out of the blast window. (The tj-actions compromise was public
for well under a day before detection.)

But a quarantine that fails your build just trains everyone to reach for
the override — so instead of refusing, action-locker **holds back**: when
a tag's current target is too fresh, it walks the same release series
(`v4` → `v4.3.0`, `v4.2.1`, …) and locks the newest release that clears
the floor. CI stays green; you permanently ride N days behind the edge;
`update` slides the window forward as releases age past it. The lockfile
records the truth — the tracked channel stays in `tag`, the release you
actually got lands in `selected`, and `rewrite` puts it in the pinned
comment:

```yaml
- uses: aws-actions/configure-aws-credentials@<sha>  # v4.3.0
```

REFUSED still exists — it now means *nothing in that series has aged past
the floor* (brand-new repos, or a floor cranked high), which is rare and
worth a human look. That's a quarantine you never learn to bypass.

- Set the window in the lockfile `policy` block (per-prefix overrides
  supported — see **Policy** below), tune per-invocation with
  `--min-age-days N`, or bypass with `--allow-fresh` (only after actually
  reviewing the commit).
- Disable hold-back with `--no-fallback` or `"fallback": false` in policy
  if you'd rather see refusals than ride behind.
- If no candidate's age can be determined (API unreachable, rate-limited),
  it **fails closed** rather than pinning blind — set `GITHUB_TOKEN` for
  busy repos, since age lookups use the GitHub API.
- Actions matched by `trusted_prefixes` are exempt. Exact-version refs
  (`@v4.3.1`) are never substituted — you named a version, you get it or
  a refusal.

**Where the date comes from (trust ladder):**

1. If the tag has an **immutable release**, the age is GitHub's server-side
   `published_at` — an attacker can neither backdate it nor move the tag
   afterward. *Trusted.* One more reason to love actions that publish
   immutable releases.
2. Otherwise, the earliest **merged-PR date** containing the commit —
   `merged_at` is stamped by GitHub's servers, and you can't retroactively
   insert a new commit into a PR that merged a month ago. Merging a fresh
   PR with your malicious commit stamps it *now*, which fails the floor.
   *Trusted.* (Unmerged PRs are ignored; an old open PR can receive new
   commits, so `created_at` proves nothing.)
3. Otherwise, the commit's **committer date** — git metadata the committer
   chose, so an attacker can backdate it. A heuristic, not a wall. Set
   `require_trusted_age` in the policy block to refuse this rung entirely.

A *mutable* release's `published_at` is deliberately ignored: the tag can
move after publication (that's exactly the tj-actions attack). And commit
*signatures* don't help here either — the signature covers the
attacker-chosen date; it proves who, not when.

## What it protects against — and what it doesn't

Honest threat model. Protects against:

| Threat | Mitigation |
|---|---|
| Tag retargeting (the tj-actions attack) | Workflows reference SHAs only; `verify` fails on any mutable ref |
| Upstream deletion / disappearance | Vendored snapshot, content-hashed in the lockfile |
| Tampered vendored copies (e.g. via a sneaky PR) | `integrity` tree hash checked on every `verify` |
| Silent version drift | Updates only via explicit `update --apply`, auditable in the lockfile diff |
| Adopting a just-compromised release | 5-day commit age floor on `lock`/`update` (heuristic — see caveat in that section) |

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

## Fun fact

- This repo's own CI runs `action_locker.py verify` on itself; its workflows
  are SHA-pinned and locked in its own `action-lock.json`.

## Prior art (and why this exists anyway)

We all know by now how insecure GHA is by default. But you gotta make your devs happy - and this was my design solution to that. Now I can set "Require actions to be pinned to a full-length commit SHA" to `true` and my devs just see another pre-commit hook.

There are other options in this problem space: [pinact](https://github.com/suzuki-shunsuke/pinact), [ratchet](https://github.com/sethvargo/ratchet), and [frizbee](https://github.com/stacklok/frizbee) rewrite tags to SHAs (pinners — no lockfile, nothing verified after the fact); [gh-actions-lockfile](https://github.com/gjtorikian/gh-actions-lockfile) and [ghasum](https://github.com/chains-project/ghasum) are real lockfiles with integrity hashing (and transitive resolution, which I don't do yet) — but none of them vendor, and the lockfile tools don't handle reusable workflows. Dependabot and Renovate keep pins fresh and pair nicely with the `# tag` comments `rewrite` leaves behind. And GitHub says they're going to do locking natively eventually — which still won't help when upstream disappears.

But I've been using this pattern for a while now, and have been happy with it. The vendoring was important to me and it seemed differentiated enough to make this worth sharing.

## Install

It's one file. 

```bash
# run from a clone (or just copy action_locker.py into your repo)
python3 action_locker.py --help
```

Requires Python 3.9+ and `git` (plus `curl`/`tar` for `vendor`). No pip
packages, no lockfile for the lockfile tool. (There's a `pyproject.toml`,
but only so the pre-commit hook can install it — `dependencies = []`.)

## Usage

```bash
python3 action_locker.py lock      # resolve refs -> action-lock.json
python3 action_locker.py rewrite   # pin workflow files to locked SHAs
python3 action_locker.py vendor    # snapshot locked actions + record integrity
python3 action_locker.py verify    # the CI gate (offline)
python3 action_locker.py update    # check upstream; --apply to accept
```

### Experimental: `scan` (the parser lab)

```bash
python3 action_locker.py scan --parser lab --format json
```

A read-only, offline structural scan of your workflows: every `uses:` gets
a semantic path (`jobs.build.steps[2].uses`), a kind (external action,
reusable workflow, local, docker), and — crucially — anything the scanner
*can't* confidently classify is reported as a rejection, never silently
skipped. This is the first piece of the parser-backend work described in
[ADR 0001](docs/adr/0001-workflow-parser-backends.md): the longtime regex
scanner is now also an explicit, differential-testable backend (`lab/0`).
Production `lock`/`verify`/`rewrite` behavior is unchanged; they don't use
this path yet.

`lab/0` deliberately models a *subset* of YAML and **fails closed** on the
rest: multi-line (folded) scalars, flow collections that span lines,
quoted mapping keys, anchors/aliases/merge keys, tabs, and multiple
documents all produce `accepted: false` with a diagnostic rather than a
guess. That's the point — a scanner making a security claim must say "I
can't read this" instead of silently reporting zero references.

The `stable` backend reads full YAML through a pinned `ruamel.yaml` in
1.2 round-trip mode, so it handles the constructs lab/0 refuses (anchors,
flow collections, folded scalars) while walking only the two executable
`uses` slots. It's an **optional** install — the default tool stays
stdlib-only:

```bash
pip install 'action-locker[stable]'
python3 action_locker.py scan --parser stable --format json
```

Without it, `scan --parser stable` reports the backend as unavailable
(exit 4) rather than falling back — a scanner must answer with the engine
you asked for.

`compare` mode runs both backends over the same bytes and diffs their
normalized results — `(kind, raw_target)` keyed by semantic path, never
line numbers:

```bash
python3 action_locker.py scan --parser compare --format text
```

`stable` is authoritative; compare measures where the experimental `lab/0`
agrees with it. It separates **expected** disagreements (stable reads a
construct lab deliberately fails closed on — the normal migration state)
from **actionable** ones (lab accepting what stable rejects, or the two
reading *different* references for the same slot — a real bug in one
backend). Exit `3` on any disagreement, `1` if they agree but the
authoritative parser rejected a workflow, `0` on full agreement. One
caveat worth stating plainly: compare measures *consistency*, not
*correctness* — two backends can agree and both be wrong. Agreement is a
signal, not a proof; the fuzz-vs-oracle corpus is what checks truth.

## Trusted prefixes

Internal reusable workflows (e.g.
`your-org/your-repo/.github/workflows/shared-build.yml@main`) often
intentionally track `@main` and SHA-pinning them would require a cross-repo
update on every shared-workflow change. 

If that's an issue, and you do not care about enabling the
`Require actions to be pinned to a full-length commit SHA`, add a `trusted_prefixes` list to the lockfile to downgrade those from errors to warnings in `verify`:

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

## Policy

Age-floor policy lives in the lockfile — on purpose. GitHub org/repo/env
variables have the wrong precedence for security config (repo and
environment variables override org ones, so anyone with repo write can
quietly weaken what an org admin set), and variable changes never show up
in a PR diff. The lockfile is reviewed, diffable, and CODEOWNERS-able.

```json
{
  "version": 1,
  "policy": {
    "min_age_days": 5,
    "require_trusted_age": false,
    "overrides": [
      {"prefix": "steph-owl/action-locker", "min_age_days": 0},
      {"prefix": "somevendor/", "require_trusted_age": true}
    ]
  },
  "locked": { }
}
```

- `min_age_days` — the default floor for everything not otherwise matched.
- `require_trusted_age` — refuse the committer-date rung of the ladder:
  only immutable-release or merged-PR dates are accepted. Upstreams that
  provide neither can still be adopted deliberately: vendor + review, then
  `--allow-fresh`. (Hold-back respects this too: it skips candidates whose
  age isn't server-attested.)
- `fallback` — set `false` to disable hold-back (see the age floor
  section) and get hard refusals instead.
- `overrides` — per-prefix exceptions; the most specific matching prefix
  wins, regardless of order. Same owner-boundary rules as
  `trusted_prefixes` (`steph-owl/` can never match `steph-owl-evil/x`).
  The first example above is the "my own repo, adopted immediately —
  *just that repo*" case: still SHA-pinned, still locked, still verified,
  just no cooldown.

Unknown policy keys are hard errors in `lock`, `update`, and `verify` — a
typo like `min_age_dayz` must fail the build, not silently weaken the
floor. An explicit `--min-age-days` on the command line beats policy for
that invocation.

## CI integration

Simplest — the composite action, pinned by SHA:

```yaml
jobs:
  action-locker:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<sha>              # v4
      - uses: steph-owl/action-locker@<sha>       # runs `action-locker verify`
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
    uses: steph-owl/action-locker/.github/workflows/verify-action-locker.yml@<sha>  # v1
```

### Pre-commit hook

Catch unpinned refs (and tampered vendored files) locally, before they
ever reach CI. In a consumer repo's `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/steph-owl/action-locker
    rev: <pinned SHA>   # yes, pin the pinning tool too
    hooks:
      - id: action-locker
```

The hook runs `action-locker verify` whenever workflow files, the
lockfile, or anything under `vendored-actions/` changes. It's offline and
stdlib-only, so installs are instant. Run on demand with:

```bash
pre-commit run action-locker --all-files
```

### Push re-verification (repository_dispatch)

For orgs running many consumer repos: when `action_locker.py` or the reusable
verify workflow changes on `main`, the `dispatch-reverify` workflow sends a
`repository_dispatch` event (`action-lock-reverify`) to every repo listed
in `subscribers.txt`, so consumers re-check their lockfiles without waiting
for their next PR. It can also be run manually via `workflow_dispatch`
(optionally targeting one repo).

The feature is opt-in via `subscribers.txt`: with no active entries the
job is a green no-op (fresh forks stay green). Once you list subscribers,
the `ACTION_LOCK_DISPATCH_TOKEN` secret becomes required — a fine-grained
PAT with Contents read/write on the subscriber repos; the default
`GITHUB_TOKEN` cannot dispatch cross-repo. Subscribers-without-token fails
loudly on purpose: "consumers silently stopped being re-verified" is the
false-confidence failure this workflow exists to prevent.

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

## Hardening the locker (for org admins)

The lockfile is the policy, so whoever can merge changes to it *is* the
policy. action-locker can't be bulletproof against someone with write
access — no in-repo tool can — but you can make the review gate strong:

1. **Fork or copy this repo into your org** and consume your own copy —
   your supply chain shouldn't include our push access either.
2. **CODEOWNERS the control surfaces** in every consumer repo:
   `action-lock.json`, `.github/workflows/`, and
   `.github/vendored-actions/` should require review from a security/admin
   team. This is what stops "person B with repo write turns the cooldown
   down to zero and sneaks something in."
3. **Branch protection / rulesets** on the default branch: require the
   `action-locker` verify job as a required status check, require review,
   and (if your plan has push rulesets) restrict direct pushes to those
   paths entirely.
4. **Org settings that stack with this tool**: "Require actions to be
   pinned to a full-length commit SHA" (both these repos comply), and an
   Actions allow-list if you want a hard ceiling on which owners are
   usable at all.
5. **The dispatch token** (`ACTION_LOCK_DISPATCH_TOKEN`) should be a
   fine-grained PAT scoped to Contents on subscriber repos only.

Know what the tool can't see: a reviewer who approves a bad lockfile
change, and anything with admin rights to the repo. The floor, the
ladder, and the hashes narrow the attack to "get a malicious change
through your review" — the rest is your review culture.

## Roadmap

- **A GitHub App** with permissions scoped to exactly one file,
  `action-lock.json`. It will be able to open re-lock/re-verify PRs across consumer repos without a broad PAT (replacing the `ACTION_LOCK_DISPATCH_TOKEN` pattern).
- **Transitive resolution**: surface and pin the `uses:` references inside
  vendored composite actions. 
- **Local quarantine**: a cooldown measured from *your own* `locked_at` —
  a date in your git history that no upstream can fake. Deliberately not
  built yet: it would make `verify` time-dependent, and verify's
  determinism is a design principle we'd rather not trade quietly.

See the [demo repo](https://github.com/steph-owl/action-locker-demo) for
a working example: a small app with pinned workflows, a lockfile, vendored
actions, and the CI wiring.

## About 

`action-locker` was built by Steph Prime at [Old Well Labs](https://oldwell-labs.com)

We're a fintech startup, we're growing fast, and **we are actively hiring Software Engineers** and **Data Engineers** to join us in our **Charlotte NC** office (hybrid WFH). So if massive data sets don't scare you, if you've got a "bias for action" bent, and if you are cool with Charlotte but looking for something more exciting than a big bank - [apply now](https://jobs.ashbyhq.com/old-well-labs). 

Licensed under [Apache-2.0](LICENSE).
