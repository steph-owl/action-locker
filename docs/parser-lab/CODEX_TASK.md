# Coding-agent task: Parser Lab PR 1

Implement **PR 1: Contract and compare harness** from `docs/parser-lab/IMPLEMENTATION.md`.

## Goal

Turn the current regex workflow scanner into an explicit experimental backend called `lab/0`, introduce a canonical parse result model, and add a read-only `scan` command. Do not add ruamel.yaml, Go, Nix, Lean, TLA+, or rewriting changes in this PR.

The result should be a small architectural seam with no production behavior change.

## Repository constraints

- Preserve Python 3.9 compatibility.
- Keep the current normal `lock`, `rewrite`, `vendor`, `verify`, and `update` behavior unchanged.
- Keep the offline test suite offline.
- Do not perform network access in parser code or tests.
- Do not split the production implementation into multiple Python modules in this PR unless the maintainer explicitly chooses to relax the current one-file rule first.
- Every new behavior needs tests.
- Do not silently catch parser errors and return an empty result.

## Required implementation

### 1. Add canonical immutable types

Add `WorkflowReference`, `ParseDiagnostic`, and `ParseResult` as frozen dataclasses, following `IMPLEMENTATION.md`.

Source positions exposed by the legacy scanner should be one-based. If the current scanner does not know a column or end position, use the first non-whitespace column for `line`, set a best-effort `column`, and leave end positions `None`.

### 2. Add a backend abstraction

Introduce a minimal parser backend protocol/base class with:

```python
name: str
parse_file(repo_root: Path, path: Path) -> ParseResult
```

Implement `LegacyRegexBackend` with public name `lab/0` by adapting the existing line scanner.

Do not delete `parse_workflows`. Refactor it to call the selected backend or add a compatibility wrapper so existing commands and tests retain behavior.

### 3. Produce semantic paths

For Lab v0, infer paths only where the line-oriented scanner can do so confidently. A minimal indentation-aware tracker is allowed for identifying:

```text
jobs.<job_id>.steps[<index>].uses
jobs.<job_id>.uses
```

When the scanner finds a `uses`-looking line but cannot determine one of those paths confidently, emit diagnostic `LAB_UNCLASSIFIED_USES` and mark the file `accepted=False` rather than treating it as absent.

Do not claim support for arbitrary YAML in this PR.

### 4. Add target classification

Return these kinds:

- `docker-image`
- `local-action`
- `reusable-workflow`
- `external-action`

For external targets, split on the final `@`. Preserve the complete scalar text.

### 5. Add `scan`

Add:

```text
python3 action_locker.py scan --parser lab [--format text|json]
```

For PR 1, `lab` is the only real backend. It is acceptable for `stable` and `compare` to return a clear `backend unavailable` diagnostic/exit code, or to omit those choices until PR 2. Prefer designing the argument parser so adding them later is local.

JSON output must be deterministic (`sort_keys=True`, stable list ordering) and include `schema_version: 1`.

The scan command is read-only and fully offline.

### 6. Preserve old command output

Existing commands may continue using the compatibility shape:

```python
{
    "owner/repo@ref": [(file, line), ...]
}
```

Build this shape from Lab v0 results so the refactor does not alter output or lockfile behavior.

### 7. Add fixtures and tests

At minimum add tests proving Lab v0:

- finds canonical plain step-level `uses`;
- finds canonical job-level reusable workflow `uses`;
- ignores a full-line YAML comment;
- ignores fake `uses` inside a `run: |` block, or rejects the file explicitly if Lab v0 cannot do this safely;
- classifies local and Docker references without returning them as lockable external actions;
- emits stable JSON ordering;
- returns nonzero for `LAB_UNCLASSIFIED_USES`;
- does not change existing lock/verify/rewrite tests.

Use the provided fixture as one test input. Add smaller unit fixtures when failure isolation benefits.

## Explicit non-goals

Do not:

- install or vendor ruamel.yaml;
- implement structural rewriting;
- invoke actionlint;
- invent a runtime LLM integration;
- change lockfile schema;
- change the default parser for existing commands;
- weaken any current SHA or policy checks;
- claim the lab parser is complete.

## Quality bar

- Functions have short docstrings that state security-relevant failure behavior.
- Parser ambiguity is represented in data, not only printed.
- All output paths are repository-relative.
- Tests assert semantic paths, kinds, target strings, and diagnostics—not merely total counts.
- Regexes avoid nested unbounded quantifiers and are exercised with a long-line regression test.

## Validation commands

```bash
python3 -m pytest
python3 action_locker.py scan --parser lab --format text
python3 action_locker.py scan --parser lab --format json | python3 -m json.tool >/dev/null
python3 action_locker.py verify
```

## Expected final response from the coding agent

Report:

1. Files changed.
2. New CLI behavior.
3. Security/fail-closed choices.
4. Tests added and commands run.
5. Known Lab v0 limitations that PR 2's structural parser will expose through compare mode.
