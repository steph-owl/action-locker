# Contributing

Thanks for your interest!

## Ground rules

- **The tool stays one file.** `action_locker.py`, stdlib only. Auditability
  is the point: anyone adopting a supply-chain tool should be able to read
  the whole thing in one sitting. PRs that add runtime dependencies or
  split the tool across modules will be declined (tests are exempt — they
  use pytest).
- **Every behavior change needs a test.** The offline suite
  (`python3 -m pytest`) must pass without network access.
- **Security-relevant changes** (parsing, ref resolution, subprocess
  invocation, integrity hashing) get extra scrutiny — please explain your
  threat model in the PR description.

## Running tests

```bash
python3 -m pytest             # offline unit tests
python3 -m pytest -m network  # opt-in: live integration tests against GitHub
```

## Before you open a PR

Run the tool on itself from the repo root — CI does:

```bash
python3 action_locker.py verify
```
