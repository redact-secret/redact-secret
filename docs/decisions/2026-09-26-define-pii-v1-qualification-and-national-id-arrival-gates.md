---
decision_id: decision-define-pii-v1-qualification-and-national-id-arrival-gates
status: accepted
scope: workspace
title: Define pii-v1 qualification and national-ID arrival gates
decided_at: 2026-09-26
spec: evidence-and-gates
---

# Define pii-v1 qualification and national-ID arrival gates

## Context

Issues [#578](https://github.com/redact-secret/redact-secret/issues/578) and
[#795](https://github.com/redact-secret/redact-secret/issues/795) require PII
support claims and future national-ID contributions to use evidence appropriate
to structured personal data rather than credential-only provenance or cheap
checksum twins.

## Decision

### Typed authority and safe data

Every normative PII assertion records `sourceKind` (`standard` or
`public-authority`), stable `sourceId`, section or clause `locator`, edition or
immutable `revision`, and what it supports (`lexical`, `validation`,
`allocation`, `reserved-control`, or `sensitivity`). At least one such source
is required for positive identity. Blogs, scanners, implementations, and
examples may corroborate but do not satisfy the gate. Credential `provider`
provenance is unchanged.

No fixture, corpus, log, snapshot, issue, generated evidence, or agent context
contains real-person PII. Use official reserved/test namespaces or a recorded
deterministic synthetic generator and seed with no real-world provenance.

### Shared registry and qualification states

PII uses the shared support registry. A row carries `family`, `category: pii`,
scope, `qualificationProfile: pii-v1`, status, authority provenance, family
contract version, context obligation, activation availability, and evidence
reasons. Public projections display the qualification profile wherever status
appears.

- `pending` means a required contract, safe fixture plan, executable
  evaluation path, or evidence input is absent. A proposal starts here.
- `provisional` means the detector works end to end and has typed authority,
  safe fixtures, validator checks, authored benign axes, semantic/collision
  controls, domain accounting, and benchmark evidence, but at least one stable
  gate remains incomplete.
- `stable` means every `pii-v1` gate passes on the named activation identity:
  separate identity and sensitivity accounting, declared context obligation,
  cross-surface determinism, protected holdout, semantic collision and
  benign-axis diversity, plus runtime and package-cost evidence.

Mechanical checksum negatives test validator correctness but cannot alone
satisfy stable discrimination. Stable evidence includes valid-shape semantic
collisions and authored axes: `reserved`, `documentation`, `test-value`,
`public-identifier`, `operational-non-personal`, `near-miss`, `placeholder`,
and `context-negative`. Credential peer-scanner differential is explicitly
`not-applicable`, never a vacuous pass; authority, collision, diversity, and
holdout evidence replace it. Exact thresholds and schema/evaluator
implementation belong to `redact-secret-benchmarks`.

### Future national-ID arrival gate

A future family remains `pending` while its proposal supplies:

1. canonical family id, jurisdiction, display name, and authority;
2. typed sources for grammar, allocation, validator, reserved values, and
   unsupported variants;
3. reserved/test fixtures or a deterministic no-real-world generator;
4. candidate grammar, bounded built-in validator identity, context obligation,
   sensitivity semantics, formats, and exclusions;
5. mechanical negatives plus semantic, ordinary-number, reference,
   existing-family, and cross-jurisdiction collision controls;
6. authored benign axes, accounting population, protected partitions, and a
   benchmark counterpart under `pii-v1`;
7. performance, package/WASM size, activation, and availability impact; and
8. a shared-registry row with evidence reasons.

Only after the detector, validator, product-side accounting, and actual
benchmark-side schema/evaluator/evidence gates exist and pass may the row move
to `provisional`. This record does not claim those benchmark contracts already
exist. The validator follows #792's bounded built-in registry contract and does
not widen declarative credential rulesets into a PII programming language.

A proposal may be accepted, covered by an existing family, rejected for
insufficient authority or deterministic discrimination, or deferred for cost
or precision. No broad country survey or detector implementation is required
to close the proposal process.

## Consequences

Detector existence and checksum validity cannot become support claims. #795's
product arrival checklist is decided here, but its end-to-end transition to
`provisional` cannot yet be demonstrated and the issue remains open on the
missing product and benchmark dependencies. #578 likewise remains open until
benchmark-owned schema, evaluator, partitions, shared-registry projection,
qualification thresholds, and end-to-end evidence are implemented and
reconciled with this product contract.
