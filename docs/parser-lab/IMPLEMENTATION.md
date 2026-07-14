# Parser Lab implementation specification

This document turns ADR 0001 into staged work. It is intentionally organized so each pull request leaves Action Locker usable and reviewable.

**Implementation status (2026-07-14):** PR-equivalent stages 1 through 5 are
complete and `stable` is the production default. The delivery sequence below
is retained as design history. Optional Nix packaging and the PR 6+ research
track remain future work; neither is an ADR promotion gate.

## One-sentence architecture

Keep the Python policy engine, place workflow discovery behind a backend contract, make a structural parser authoritative, and evolve the existing regex scanner as a differential-tested lab implementation.

## Safety rule

A parser backend may return references, diagnostics, or an explicit unsupported result. It must never convert ambiguity or parser failure into an empty successful result.

## Canonical data model

Use immutable value objects. Names may change to match repository style, but the fields and semantics should remain.

```python
from dataclasses import dataclass
from typing import Literal, Optional, Tuple

ReferenceKind = Literal[
    "external-action",
    "reusable-workflow",
    "local-action",
    "docker-image",
]

DiagnosticSeverity = Literal["error", "warning", "note"]


@dataclass(frozen=True, order=True)
class WorkflowReference:
    file: str
    semantic_path: str
    kind: ReferenceKind
    raw_target: str
    action: Optional[str]
    ref: Optional[str]
    line: int
    column: int
    end_line: Optional[int] = None
    end_column: Optional[int] = None


@dataclass(frozen=True)
class ParseDiagnostic:
    file: str
    code: str
    message: str
    severity: DiagnosticSeverity
    line: Optional[int] = None
    column: Optional[int] = None


@dataclass(frozen=True)
class ParseResult:
    backend: str
    references: Tuple[WorkflowReference, ...]
    diagnostics: Tuple[ParseDiagnostic, ...]
    accepted: bool
```

### Field invariants

- `semantic_path` uniquely identifies one executable `uses` slot in a file.
- `raw_target` is the complete scalar value, without quote characters or comments.
- External targets are split at the final `@` into `action` and `ref`.
- `action` retains an optional action subpath, for example `owner/repo/path`.
- `ref` is not pre-filtered by the parser. Reference validation remains a separate policy concern.
- Source positions are one-based in the public model.
- Results are sorted by `(file, semantic_path)` before comparison or serialization.
- Duplicate semantic paths are an error.

## Backend interface

```python
class WorkflowParserBackend:
    name: str

    def parse_file(self, repo_root: Path, path: Path) -> ParseResult:
        ...
```

Keep filesystem discovery outside the backend. The existing workflow globbing remains responsible for selecting `.github/workflows/*.yml` and `*.yaml` files. The backend receives one exact file at a time.

The backend must parse bytes from the supplied path. It must not follow YAML includes, execute expressions, contact the network, or read unrelated files.

## Target classification

Classify in this order:

1. `docker://...` -> `docker-image`
2. `./...` or `../...` -> `local-action` (`../` should later be rejected by policy)
3. Job-level `uses` -> `reusable-workflow`
4. Step-level `uses` -> `external-action`

An external target without a final `@` is still returned as a reference with `action=None`, `ref=None`, plus diagnostic `INVALID_USES_TARGET`. The parser reports structure; policy reports mutability and validity.

## CLI contract

Add a development-facing `scan` command before changing existing command defaults:

```text
action-locker scan [--parser stable|lab|compare] [--format text|json]
```

Then add `--parser` to commands that discover workflows:

```text
action-locker lock    --parser ...
action-locker verify  --parser ...
action-locker rewrite --parser ...
```

Resolution order:

1. Explicit `--parser`
2. `ACTION_LOCKER_PARSER`
3. Command default

During migration the command default remains the existing implementation. After promotion it becomes `stable`.

### Exit codes for `scan`

- `0`: parsing succeeded; compare mode agrees
- `1`: authoritative parser rejected the workflow
- `2`: invalid CLI/configuration
- `3`: parser disagreement
- `4`: requested backend unavailable

Existing command exit-code behavior does not need to change in the first PR.

## Comparison behavior

Normalize each accepted result into a map:

```text
semantic_path -> (kind, raw_target)
```

Report these disagreement classes:

- `ACCEPTANCE_MISMATCH`: one backend accepts and another rejects
- `MISSING_REFERENCE`: stable found a path lab did not
- `EXTRA_REFERENCE`: lab found a path stable did not
- `TARGET_MISMATCH`: same path, different scalar value
- `KIND_MISMATCH`: same path and value, different classification
- `DUPLICATE_PATH`: one backend emitted a semantic path more than once

Do not compare line or column values for equality.

JSON output should be stable and versioned:

```json
{
  "schema_version": 1,
  "agreement": false,
  "authoritative_backend": "stable",
  "files": [
    {
      "path": ".github/workflows/ci.yml",
      "stable": {"accepted": true, "references": [], "diagnostics": []},
      "lab": {"accepted": true, "references": [], "diagnostics": []},
      "disagreements": []
    }
  ]
}
```

## Stable backend requirements

Use a pinned `ruamel.yaml` version in YAML 1.2 round-trip mode.

Configuration requirements:

- round-trip loader/dumper;
- YAML version 1.2;
- preserve quotes;
- duplicate keys rejected;
- exactly one YAML document;
- no unsafe/custom Python object construction.

The walker only inspects these shapes:

```text
root.jobs.<job_id>.steps[<index>].uses
root.jobs.<job_id>.uses
```

### Structural diagnostics

At minimum implement:

- `YAML_PARSE_ERROR`
- `MULTIPLE_DOCUMENTS`
- `DUPLICATE_KEY`
- `ROOT_NOT_MAPPING`
- `JOBS_NOT_MAPPING`
- `JOB_NOT_MAPPING`
- `STEPS_NOT_SEQUENCE`
- `STEP_NOT_MAPPING`
- `USES_NOT_STRING`
- `INVALID_USES_TARGET`

A malformed job unrelated to `uses` may be left to actionlint, but any malformed container on the path to a possible `uses` must fail closed.

### Source positions

Use parser-provided location metadata where available. If exact end positions are unavailable, populate start line/column and leave end positions unset. Do not infer rewrite spans from line numbers alone.

## Lab backend requirements

### Lab v0

Wrap the current regex scanner behind the backend interface. Preserve its behavior except:

- emit canonical `WorkflowReference` values;
- emit explicit diagnostics for patterns it cannot classify;
- never silently skip a suspicious line containing `uses` outside a comment or known block scalar;
- expose backend version in debug output, for example `lab/0`.

### Lab v1 state model

Replace line-only matching incrementally with explicit states:

```text
NORMAL
SINGLE_QUOTED
DOUBLE_QUOTED
FLOW_SEQUENCE
FLOW_MAPPING
BLOCK_SCALAR_LITERAL
BLOCK_SCALAR_FOLDED
COMMENT
```

The implementation also tracks:

- indentation stack;
- current semantic path;
- sequence indices;
- block scalar parent indentation;
- quote escapes;
- flow nesting depth.

Regexes may recognize tokens inside a state. Regexes must not be the state model.

### Fail-closed rules

The lab returns `accepted=False` when it encounters syntax it does not model safely. Examples include an unterminated quote, inconsistent indentation that affects semantic path, or an unsupported YAML feature on a path that could contain `uses`.

It is acceptable for the lab to support less YAML than stable. It is not acceptable for it to claim a complete scan of syntax it skipped.

## Rewriting plan

Do not migrate rewrite in the parser-interface PR.

The later structural rewrite must:

1. Parse the original bytes with stable.
2. Select references by semantic path.
3. Produce replacement scalars in memory.
4. Preserve original scalar quote style where possible.
5. Preserve unrelated comments and block scalars.
6. Parse the candidate bytes again with stable.
7. Assert every intended semantic path now contains the expected SHA.
8. In compare mode, parse with lab and report disagreements.
9. Atomically replace the file only after all checks pass.
10. Leave the original file untouched on any failure.

The rewrite must never locate a replacement by searching every line for a matching substring.

## Optional Go/actionlint oracle protocol

This is a later PR and a development dependency only.

Executable name:

```text
action-locker-actionlint-oracle
```

Input on stdin:

```json
{
  "schema_version": 1,
  "path": ".github/workflows/ci.yml",
  "source": "name: CI\n..."
}
```

Output on stdout uses the same reference and diagnostic model as Python. The helper calls `actionlint.Parse` and walks action steps and reusable workflow calls. It performs no network access and no mutation.

The Python harness treats a missing helper as `backend unavailable`, not parser agreement.

## Corpus layout

```text
tests/fixtures/parser_lab/
  valid/
    <case>.yml
    <case>.expected.json
  invalid/
    <case>.yml
    <case>.expected.json
  disagreements/
    <minimized-case>.yml
    <minimized-case>.json
```

Expected files contain semantic references and expected diagnostics, not complete round-tripped YAML unless the test is specifically for rewriting.

## Corpus categories

At minimum cover:

- comments containing fake `uses`;
- literal and folded block scalars containing fake `uses`;
- single-quoted, double-quoted, and plain `uses` values;
- job-level reusable workflow calls;
- local actions and Docker references;
- flow mappings and flow sequences;
- blank lines and comments between mapping keys;
- anchors, aliases, and YAML merge keys;
- duplicate keys;
- multiple YAML documents;
- CRLF, UTF-8 BOM, and non-ASCII comments;
- valid ref characters currently rejected by the legacy regex;
- malformed and unterminated quotes;
- very long lines and block scalars;
- misleading strings such as `echo 'uses: owner/repo@v1'`;
- repeated references at distinct semantic paths;
- files with no references.

## Generated testing

Generation is development-time only.

Use three independent sources:

1. Handwritten adversarial fixtures.
2. Grammar-aware mutations of valid workflows.
3. LLM-generated specimens prompted to maximize disagreement, followed by deterministic validation and minimization.

LLM output is input data, never expected truth. The expected result comes from a reviewed fixture or independent parser agreement.

Useful mutations include:

- quote/unquote scalars;
- change block scalar chomping and indentation indicators;
- move between block and flow style;
- insert comments at token boundaries;
- duplicate or reorder jobs and steps;
- vary line endings;
- add anchors and aliases;
- mutate ref character classes;
- insert fake references into every scalar context.

## Mismatch minimizer

Add a deterministic delta-debugging tool after compare mode exists.

Given a workflow and a disagreement predicate, it repeatedly removes ranges or simplifies nodes while retaining the same disagreement class. Output:

```text
<case>.min.yml
<case>.min.json
```

Metadata records:

- backend versions;
- original SHA-256;
- minimized SHA-256;
- disagreement class;
- exact command to reproduce;
- whether stable/actionlint accepted the minimized file.

Never auto-commit minimized cases from untrusted PR execution.

## Observability

Text diagnostics should read like:

```text
PARSER DISAGREEMENT .github/workflows/ci.yml
  MISSING_REFERENCE jobs.build.steps[2].uses
    stable: actions/setup-python@v5
    lab:    <absent>
```

With `ACTIONS_STEP_DEBUG=true` or a local `--debug`, print backend names/versions and parse duration. Do not print workflow contents by default because scripts may contain secrets or sensitive literals.

## Performance envelope

Parsing should be linear enough for normal workflow sizes. Initial non-binding targets:

- under 100 ms per typical workflow for stable on a developer laptop;
- under 50 MiB peak memory for a 1 MiB workflow;
- explicit maximum input size before parsing, configurable later;
- no catastrophic regex backtracking in lab.

Performance failures are diagnostics, not permission to fall back silently to another backend.

## Delivery sequence

### PR 1: Contract and compare harness

- Add canonical data classes and backend protocol.
- Wrap the existing scanner as `lab/0` without changing normal command behavior.
- Add `scan --parser lab --format json`.
- Add comparison/reporting infrastructure with a test double for stable.
- Add the initial corpus and expected results.

**Definition of done:** existing tests pass; scan output is deterministic; no production command behavior changes.

### PR 2: Structural backend

- Add ruamel-based `stable` backend as an optional development dependency first.
- Implement structural walking and diagnostics.
- Enable `scan --parser stable|compare`.
- Differential-test stable and lab across the corpus.

**Definition of done:** all corpus cases have reviewed expected results; every disagreement is explained.

### PR 3: Opt-in lock and verify

- Add `--parser` to `lock` and `verify`.
- Keep current default during the migration.
- Run compare mode in Action Locker's own non-required CI job.
- Add JSON disagreement artifacts on failure.

**Definition of done:** opt-in stable verification passes on Action Locker and the demo repository.

### PR 4: Structural rewrite

- Implement source-aware/round-trip rewrite.
- Add atomic write and post-parse assertions.
- Snapshot-test minimal diffs.

**Definition of done:** all accepted rewrite fixtures remain syntactically valid and only intended semantic values/comments change.

### PR 5: Package and promote

- Pin and vendor the parser with license and update metadata.
- Add optional Nix flake/lock packaging.
- Make `stable` the default.
- Make compare mode a required check for Action Locker itself if its reliability is acceptable.
- Update README, CONTRIBUTING, and security documentation to reflect the one-artifact principle.

**Definition of done:** a clean checkout can run the default verifier without ambient `pip install`; migration criteria in ADR 0001 are met.

### PR 6+: Research track

- Evolve `lab/0` into an explicit lexer/state machine.
- Add actionlint Go oracle.
- Add minimizer and generated corpus jobs.
- Start Lean proofs over the lab's declared subset.
- Model transactional Action Locker mutations in TLA+.

None of these block the practical production parser.
