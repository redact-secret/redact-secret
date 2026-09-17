# Detector/finding-type/policy/consumer coverage baseline

The deterministic baseline issue [#101](https://github.com/redact-secret/redact-secret/issues/101)
(tracking-key `dacd-f1-t1`, under Epic [#96](https://github.com/redact-secret/redact-secret/issues/96))
asks for: one inventory row per built-in detector and emitted finding type,
each distinguished as `supported`, `intentionally-unsupported`,
`not-applicable`, or `unresolved`, without treating a raw fixture count as
sufficient coverage evidence.

## Files

- [`detector-inventory.json`](./detector-inventory.json) — the hand-authored
  declared baseline: every finding type the built-in registry
  (`crates/secret-scan-core/src/detectors`) can emit, its owning detector id,
  its default-policy classification (`crates/secret-scan-core/src/policy.rs`),
  its accepted schemes where the finding type has any, and a
  `reconciliationTrigger` synthetic input already shipped verbatim elsewhere
  in the crate's own source. Reconciled against the real registry and
  `DefaultPolicy` — through the crate's public API only — by
  `crates/secret-scan-core/tests/detector_inventory.rs`
  (`cargo test -p redact-secret --test detector_inventory`). Edit this file
  when a detector, its finding type(s), or its policy class changes; the
  Rust test fails the next `cargo test` run if this file falls out of sync.
- [`inventory-report.json`](./inventory-report.json) — the generated join of
  the baseline above with the canonical corpus
  (`conformance/fixtures/synchronous-corpus.json`) and the declared runtime
  consumers, produced by
  [`scripts/generate-coverage-inventory.py`](../../scripts/generate-coverage-inventory.py).
  Regenerate it after changing either input:

  ```sh
  python3 -B scripts/generate-coverage-inventory.py --out docs/coverage/inventory-report.json
  ```

  The generator is deterministic (sorted keys, no timestamps, no fixture
  `input` or matched values) and exits non-zero only on structural drift — a
  declared detector missing from the corpus, a corpus detector missing from
  the declaration, or a declared consumer path that no longer exists.
  Reporting a row as `unresolved` is not an error: it is the baseline
  honestly stating that a reachable finding type or scheme currently has no
  positive corpus evidence and no documented reason to be exempt. No row is
  currently `unresolved` — `authorization_credential` was the last one,
  closed by issue #105; the remaining evidence-*breadth* gaps
  (`coverage-declarations.json`'s `pending` dimension cells, below) are
  tracked as
  [`docs/audits/detection-assurance-residual-evidence-backlog.md`](../audits/detection-assurance-residual-evidence-backlog.md).
  Issue [#136](https://github.com/redact-secret/redact-secret/issues/136)
  closed the historical tracking artifact; its exit work was split across
  [#186](https://github.com/redact-secret/redact-secret/issues/186),
  [#187](https://github.com/redact-secret/redact-secret/issues/187),
  [#188](https://github.com/redact-secret/redact-secret/issues/188),
  [#189](https://github.com/redact-secret/redact-secret/issues/189), and
  [#190](https://github.com/redact-secret/redact-secret/issues/190). All five
  historical breadth gaps now have reproducible resolution evidence.

Tests: `python3 -B -m unittest discover -s scripts/tests -p 'test_generate_coverage_inventory.py'`.

- [`coverage-declarations.json`](./coverage-declarations.json) — the
  evidence-requirements model (below) encoded and machine-validated: one
  `CanonicalCoverageDeclaration` row per declared finding type, the
  cross-cutting `incremental` surface, and each declared consumer, with every
  evidence dimension resolved to `supported`, `not-applicable`, or `pending`
  per `evidence-requirements.md`'s requirement matrix and bounded exception
  codes (issue [#103](https://github.com/redact-secret/redact-secret/issues/103),
  tracking-key `dacd-f1-t3`). Produced deterministically by
  [`scripts/generate-coverage-declarations.py`](../../scripts/generate-coverage-declarations.py)
  from `detector-inventory.json` and the canonical corpus — the same "migrate
  the existing fixture files into the new schema without hand-authored
  duplication" approach `conformance/convert.ts` used for the UTF-16 → UTF-8
  migration. Regenerate it after changing any input:

  ```sh
  python3 -B scripts/generate-coverage-declarations.py --out docs/coverage/coverage-declarations.json
  ```

  The declarations validate against
  [`conformance/schema.ts`](../../conformance/schema.ts)'s
  `validateCanonicalCoverageDeclarations`, which rejects an unknown detector
  or type, a row missing a dimension its behavior class requires, a stale
  evidence id, a contradictory state/exception pairing, and an exception
  whose reference does not resolve to a real, itself-`supported` dimension.

  Tests: `python3 -B -m unittest discover -s scripts/tests -p 'test_generate_coverage_declarations.py'`
  and `npx vitest run conformance/schema.test.ts` (also validates every other
  canonical fixture file against the schema, and re-runs the generator twice
  to prove the migration is deterministic).

- [`coverage-report.md`](./coverage-report.md) — the reviewable coverage
  report (issue [#104](https://github.com/redact-secret/redact-secret/issues/104),
  tracking-key `dacd-f1-t4`): the two machine-oriented documents above,
  summarized by detector, finding type, scheme, evidence dimension, and
  unresolved/pending state, for a human reviewer to scan in one pass.
  Produced deterministically by
  [`scripts/generate-coverage-report.py`](../../scripts/generate-coverage-report.py)
  from `inventory-report.json` and `coverage-declarations.json` only — it
  never reads the corpus or the registry directly, so it can carry nothing
  those two documents did not already sanitize (no fixture `input`, no
  matched value). Regenerate it after regenerating either input:

  ```sh
  python3 -B scripts/generate-coverage-report.py --out docs/coverage/coverage-report.md
  ```

  The generator's own exit code reflects a second, independent
  reconciliation: every finding type declared in `inventory-report.json` must
  appear in `coverage-declarations.json` with the same detector, and vice
  versa — defense in depth against the two documents drifting from each
  other even when each is independently in sync with the registry and corpus.

  Tests: `python3 -B -m unittest discover -s scripts/tests -p 'test_generate_coverage_report.py'`.

- [`fp-fn-summary.json`](./fp-fn-summary.json) — the per-detector false-
  positive/false-negative guard summary requested by issue
  [#316](https://github.com/redact-secret/redact-secret/issues/316): for each
  reported detector, the `kind: "negative"` fixture count and ids (each one a
  guard the detector must produce zero findings for) and the `kind:
  "positive"` fixture count and ids (each one a guard the detector must still
  fire for), plus the union of `contexts` those fixtures exercise. It reports
  design intent only — whether the real detector actually meets every guard
  is asserted independently by
  `crates/secret-scan-core/tests/canonical_corpus.rs::scan_matches_the_canonical_synchronous_corpus`,
  named in the file's own `provenance.enforcedBy` field, so an actual false
  positive or false negative among these fixtures is a build failure, not a
  number this document could mis-report. Produced by
  [`scripts/generate-fp-fn-summary.py`](../../scripts/generate-fp-fn-summary.py)
  from the canonical corpus only (never a fixture's `input` or a matched
  value). Defaults to `stripe-token`, `shopify-token`, and `supabase-token`;
  pass `--detector <id>` (repeatable) to report on others:

  ```sh
  python3 -B scripts/generate-fp-fn-summary.py --out docs/coverage/fp-fn-summary.json
  ```

  Tests: `python3 -B -m unittest discover -s scripts/tests -p 'test_generate_fp_fn_summary.py'`.

## Coverage drift is a CI failure

`npm run ci` runs `npm run coverage:check`, which fails the build if:

- the built-in detector registry or `DefaultPolicy` disagrees with
  `detector-inventory.json` (`cargo test -p redact-secret --test
  detector_inventory`, part of the `rust-native` CI job);
- `inventory-report.json` or `coverage-declarations.json` is out of date with
  the real registry and corpus (`coverage:check`'s committed-baseline-
  freshness tests);
- `coverage-report.md` is out of date with those two documents, or they
  disagree with each other about which finding types are declared
  (`coverage:check`'s freshness and reconciliation tests); or
- `coverage-declarations.json` fails `conformance/schema.ts`'s
  `validateCanonicalCoverageDeclarations` (`vitest run
  conformance/schema.test.ts`, also part of `coverage:check`).

Adding or removing a built-in capability — a detector, a finding type, a
scheme — without regenerating and committing the affected documents above
fails one of these checks. See `scripts/generate-coverage-inventory.py`,
`scripts/generate-coverage-declarations.py`, and
`scripts/generate-coverage-report.py`'s regeneration commands, above, to
reconcile.

## Scope

This is the baseline, the evidence model that defines what a row needs to
resolve honestly, and that model encoded as data:

- [`evidence-requirements.md`](./evidence-requirements.md) — the minimum
  evidence dimensions per behavior class and the bounded-rationale exception
  rule (issue [#102](https://github.com/redact-secret/redact-secret/issues/102)),
  applied against every row of `detector-inventory.json` and `consumers`.
- [`host-context-classes.md`](./host-context-classes.md) — the lexical
  classification `evidence-requirements.md` §3 relies on to avoid a
  detector-by-context Cartesian product (issue
  [#110](https://github.com/redact-secret/redact-secret/issues/110)): the five
  representative classes, their justification against quoting, escaping,
  comments, assignment separators, headers, URLs, prose, and structured-data
  boundaries, each class's named representative context(s), and the
  reconciliation of every declared `CanonicalHostContext` value and current
  corpus fixture against it.
- `coverage-declarations.json` and `conformance/schema.ts`'s coverage-
  declaration types (above) — that model, machine-validated (issue #103).
- `coverage-report.md` and "Coverage drift is a CI failure" (above) — that
  baseline and model, summarized for review and enforced in CI (issue #104).
- [`docs/audits/detection-assurance-closeout-audit.md`](../audits/detection-assurance-closeout-audit.md) —
  the Epic [#95](https://github.com/redact-secret/redact-secret/issues/95) closeout
  (issue #118): coverage by capability and risk dimension, the classification
  and ownership of every currently `pending` cell, and confirmation that
  public documentation matches this baseline.
