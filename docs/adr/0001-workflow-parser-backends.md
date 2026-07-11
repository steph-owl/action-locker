# ADR 0001: Structural workflow parsing with an experimental parser lab

- **Status:** Proposed
- **Date:** 2026-07-11
- **Owner:** Steph Prime
- **Decision scope:** Discovery and rewriting of GitHub Actions `uses` references

## Context

Action Locker currently discovers GitHub Actions references with a line-oriented regular expression. That implementation is small, auditable, and useful, but its security contract is stronger than the mechanism can justify: a valid executable `uses` reference may be expressed in YAML syntax the scanner does not recognize, while text inside comments or block scalars may resemble a reference without being executable.

The repository has two goals that pull in different directions:

1. The production security path should be boring, deterministic, and fail closed.
2. The project should remain a place to explore whether a small, purpose-built scanner can become surprisingly capable through differential testing, generated corpora, and formal reasoning.

GitHub's repository or organization setting that requires full-length SHA references is an important independent guardrail, especially when paired with required status checks. It is not the parser's specification or proof: enforcement occurs when affected workflows run, and reusable workflow references are not covered by the full-SHA requirement in the same way as action references.

## Decision

Action Locker will support parser backends behind a common result model.

### Production backend: `stable`

`stable` is a structural YAML parser intended to become the default security path. The first implementation will use a pinned, vendored `ruamel.yaml` distribution in YAML 1.2 round-trip mode.

The stable backend is authoritative for production decisions. It must:

- structurally visit only `jobs.<job_id>.steps[<index>].uses` and `jobs.<job_id>.uses`;
- distinguish external actions, reusable workflows, local actions, and `docker://` references;
- reject malformed YAML, duplicate keys, multiple YAML documents, and non-scalar `uses` values;
- preserve enough source metadata for precise diagnostics and later source-range rewriting;
- fail closed when the input cannot be classified safely.

Vendoring a parser changes the existing "stdlib-only" implementation constraint. The retained invariant is instead:

> A user receives one pinned, auditable Action Locker artifact and does not perform an ambient runtime package installation.

Nix may package the exact Python and parser closure, but Nix is an optional distribution path rather than the parser or the only supported runtime.

### Experimental backend: `lab`

`lab` is a purpose-built Python lexer/state machine. Regular expressions may be used for token recognition, but the backend must represent structural state explicitly, including indentation, quoting, comments, flow collections, and block scalar boundaries.

The current regex scanner becomes **Lab v0**. It is not discarded; it is moved behind the backend interface and becomes the first implementation measured by the parser lab.

The lab backend:

- is deterministic and offline;
- never invokes an LLM at runtime;
- may reject syntax outside its declared language;
- must report rejection as uncertainty, never as "zero references";
- is not the default production security claim before an explicit future ADR promotes it.

### Differential mode: `compare`

`compare` runs `stable` and `lab` over the same bytes and compares normalized semantic results.

During migration, compare mode is observational unless explicitly requested as a required CI check. After the stable backend is production-ready, compare mode should fail on disagreement in the parser-lab CI job.

The stable result remains authoritative for normal Action Locker behavior. A disagreement produces a machine-readable report and a human-readable diff. Every confirmed disagreement should become a minimized regression fixture.

### Optional independent oracle: `actionlint`

A small Go helper using `actionlint.Parse` may be added as a third opinion for development and CI. It is not required for Action Locker's normal Python runtime.

The helper communicates through versioned JSON over standard input/output. It must not mutate workflows. Its job is to expose the actionlint AST's step-action and reusable-workflow references for corpus comparison.

### Rewriting boundary

Scanning and rewriting are separate capabilities.

The stable scanner may ship before the structural rewriter. The production default must not switch until rewriting can target a structurally identified scalar without searching arbitrary lines.

Initial rules:

- `lab` is scan-only.
- `stable` may scan before it can rewrite.
- `compare` rewriting, once implemented, rewrites through `stable`, reparses the resulting bytes with all enabled backends, and commits the file only after postconditions pass.
- Mutations are prepared in memory or a temporary file and replaced atomically.

### Formal methods

Formal work is encouraged but is not a 1.0 release gate.

- **Lean** is the likely tool for proving properties of the lab scanner's bounded input language: termination, block-scalar exclusion, comment exclusion, and exactly-once discovery for accepted `uses` forms.
- **TLA+** is the likely tool for Action Locker's higher-level mutation lifecycle: lock, rewrite, vendor, update, rollback, and verify transitions.

No documentation will claim proof of equivalence with every workflow GitHub accepts unless that equivalence has actually been specified and established.

## Parser modes

The intended user-facing modes are:

```text
action-locker scan   --parser stable
action-locker scan   --parser lab
action-locker scan   --parser compare
action-locker verify --parser stable
action-locker verify --parser compare
```

`stable` becomes the default only after the migration gates in the implementation spec are met. `lab` always prints an experimental warning unless an environment variable intended for parser-lab CI suppresses it.

## Normalized comparison identity

Backends compare references by semantic identity rather than line number:

```text
(file, semantic_path, reference_kind, raw_target)
```

Examples of semantic paths:

```text
jobs.build.steps[0].uses
jobs.release.steps[3].uses
jobs.shared.uses
```

Line and column positions are diagnostics. They are not comparison identity because parsers may report source positions differently.

## Consequences

### Positive

- Production correctness no longer depends on recognizing YAML with one regex.
- The existing implementation becomes a useful experimental baseline instead of throwaway work.
- Parser disagreements become concrete learning artifacts.
- The project can use LLMs aggressively for corpus generation, mutation, triage, and minimization without making runtime verification probabilistic.
- The Go/actionlint experiment stays narrow and does not force a rewrite of the Python policy engine.

### Negative

- The repository gains third-party source code and a documented parser update process.
- The "one stdlib-only Python file" principle must be restated as a one-artifact/auditable-closure principle.
- Round-trip YAML rewriting still requires careful tests; structural parsing alone does not guarantee minimal diffs.
- Supporting multiple backends increases test and diagnostic surface area.

## Non-goals

This decision does not attempt to:

- validate every GitHub Actions expression, input, runner label, or permission;
- resolve transitive `uses` references inside actions;
- use an LLM as a runtime parser or security oracle;
- prove that GitHub's undocumented parser behavior is identical to YAML 1.2;
- make Nix mandatory for Action Locker users;
- rewrite the policy engine in Go.

## Promotion criteria for `stable`

The structural backend may become the default when all of the following are true:

1. Existing tests pass through the backend interface.
2. The adversarial corpus passes.
3. Duplicate keys, multiple documents, and invalid `uses` values fail closed.
4. `lock` and `verify` use the same normalized result model.
5. Rewriting uses structural identity/source spans and reparses successfully before replacing files.
6. Unrelated block scalars, comments, quoting, and workflow content remain unchanged or changes are documented and snapshot-tested.
7. The parser dependency is pinned, vendored, licensed, hashed, and updated through a documented process.
8. Compare mode has run against the repository corpus and a representative external corpus with all disagreements triaged.

## References

- ruamel.yaml documentation: <https://yaml.dev/doc/ruamel.yaml/>
- actionlint repository: <https://github.com/rhysd/actionlint>
- actionlint Go package: <https://pkg.go.dev/github.com/rhysd/actionlint>
- YAML 1.2.2 specification: <https://yaml.org/spec/1.2.2/>
- TLA+ high-level overview: <https://lamport.azurewebsites.net/tla/high-level-view.html>
