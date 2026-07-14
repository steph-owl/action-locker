# Stable release readiness

This checklist is the working definition of "ready for 1.0". It complements
[ADR 0001](adr/0001-workflow-parser-backends.md): the ADR defines the parser
architecture; this document records the remaining release work.

## Current baseline

- Package version: `0.9.0`
- Production parser: pinned, vendored structural `stable` backend
- Structural parser: default for `lock`, `verify`, `rewrite`, and `scan`
- Differential parser: available through `scan --parser compare`
- Consumer model: any unrelated repository may call the composite action,
  reusable workflow, pre-commit hook, or an external checkout of the CLI
- Private ownership model: independent private/internal copy with an
  `upstream` remote; a public GitHub fork cannot be made private

## ADR 0001 promotion gates

| Gate | State | Evidence |
| --- | --- | --- |
| Existing behavior passes through the backend interface | Implemented | All workflow-discovering production commands use the canonical backend contract. |
| Adversarial corpus passes | Implemented | Handwritten cases and the commit-pinned public corpus run in the mandatory offline suite. |
| Invalid YAML and unsafe `uses` values fail closed | Implemented | Duplicate keys, multiple documents, malformed containers, invalid targets, and parser uncertainty are tested. |
| `lock` and `verify` share the normalized result model | Implemented | Both consume `WorkflowReference` results from the same default stable discovery path. |
| Rewriting uses structural identity and reparses before replacement | Implemented | Source scalar locations drive in-memory edits; stable/compare postconditions precede atomic replacement. |
| Unrelated YAML content is preserved and snapshot-tested | Implemented | Exact-byte tests cover comments, blocks, quotes, aliases, flow YAML, BOM/CRLF, rollback, and multi-file validation. |
| Parser dependency is pinned, vendored, licensed, hashed, and maintainable | Implemented | `scripts/vendor_ruamel.py`, `third_party/ruamel.yaml/`, and CI enforce the exact closure and provenance. |
| Compare mode is triaged on repository and external corpora | Implemented | Repository workflows agree; four public projects/167 references have recorded expectations and one explained lab rejection. |

Stable promotion is complete. Remaining items below are release-engineering
work for the 1.0 candidate, not parser correctness gates.

## Release engineering

- [ ] Decide the supported Python matrix and test its oldest and newest
  versions in CI.
- [ ] Add a changelog and document the versioning policy.
- [ ] Add a release workflow or a written manual release procedure.
- [ ] Produce a reviewed release commit and immutable tag.
- [ ] Document artifact hashes and dependency/source provenance.
- [ ] Test composite-action and reusable-workflow adoption from an unrelated
  consumer repository, including a private tool repository.
- [ ] Exercise install, lock, rewrite, verify, vendor, and update from a clean
  checkout using only documented commands.
- [ ] Review README claims against the final dependency and parser defaults.
- [ ] Review `SECURITY.md`, supported versions, and vulnerability reporting
  before tagging 1.0.

## Recommended release order

1. Decide and enforce the supported Python matrix.
2. Exercise the documented install-to-update lifecycle from a clean checkout.
3. Add changelog, versioning, and release procedure documentation.
4. Test unrelated public/private consumers against a release candidate.
5. Review the release commit and cut an immutable candidate tag.
