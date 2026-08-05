# Contributing

Thanks for your interest!

## Ground rules

- **The shipping artifact stays self-contained and auditable.** Production
  commands use the precisely pinned parser closure under `_vendor/`. Ambient
  runtime installs, unpinned dependencies, and unnecessary module sprawl will
  be declined. Parser updates must use `scripts/vendor_ruamel.py` and include
  reviewed provenance, license, and manifest changes.
- **Every behavior change needs a test.** The offline suite
  (`python3 -m pytest`) must pass without network access.
- **Security-relevant changes** (parsing, ref resolution, subprocess
  invocation, integrity hashing) get extra scrutiny — please explain your
  threat model in the PR description.

## Running tests

Use Python 3.10+ for the pinned test toolchain (CI currently uses 3.12). The
production CLI remains compatible with Python 3.9.

```bash
python3 -m venv .venv
.venv/bin/pip install pytest==9.1.1
.venv/bin/python scripts/vendor_ruamel.py --check
.venv/bin/python scripts/update_external_parser_corpus.py --check
.venv/bin/python -m pytest                    # offline unit tests, including stable
.venv/bin/python action_locker.py scan --parser compare
.venv/bin/python -m pytest -m network         # opt-in: live tests against GitHub
```

## Before you open a PR

Run the tool on itself from the repo root — CI does:

```bash
.venv/bin/python action_locker.py verify
```
