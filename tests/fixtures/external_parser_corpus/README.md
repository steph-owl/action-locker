# External workflow parser corpus

These are byte-for-byte snapshots of four public GitHub Actions workflows,
pinned to immutable source commits. They represent an action project, a Python
web project, a large Rust/Python project, and CPython itself (about 90 KiB and
167 executable `uses` slots in total).

`PROVENANCE.json` records each source URL, commit, path, SHA-256, and license.
The source projects retain copyright under the listed MIT, BSD-3-Clause, and
Python-2.0 licenses. Run the offline integrity check with:

```bash
python3 scripts/update_external_parser_corpus.py --check
```

Refreshing snapshots is an explicit reviewed operation. Update the pins and
hashes in the script, then run it with `--update`; never follow moving branch
names in CI.

The reviewed comparison expectation is in `EXPECTATIONS.json`. Three files
produce exact stable/lab agreement. CPython's build workflow is accepted by
stable and intentionally rejected by lab/0 at line 577 because it uses a
multi-line plain `run` scalar outside lab/0's declared language. That single
`ACCEPTANCE_MISMATCH` is expected and does not affect stable's authoritative
26-reference result.
