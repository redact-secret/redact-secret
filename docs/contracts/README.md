# Live contracts

Every file in this directory is a **live contract**: a script or CI reads it
at run time, so per
[`decision-decide-artifact-taxonomy-spec-routing-and-evidence-placement`](../decisions/2026-09-22-decide-artifact-taxonomy-spec-routing-and-evidence-placement.md)
it lives outside `docs/audits/`, where only temporary, non-live reviews
belong (see
[`decision-retire-historical-audit-bodies-before-release-qualification`](../decisions/2026-10-06-retire-historical-audit-bodies-before-release-qualification.md)). Nothing here changes what a detector does at scan time — the Rust
core remains the only authoritative implementation
(`ARCHITECTURE.md`, deliberate exclusions).

## Files

- [`precision/precision-contracts.json`](precision/precision-contracts.json)
  — the reviewed lexical contract (prefix, segment grammar, lengths,
  alphabets, markers, boundary rule, evidence tier, and cited sources) for
  each of the seven provider families issue
  [#367](https://github.com/redact-secret/redact-secret/issues/367) froze:
  OpenAI, DigitalOcean, Docker, Slack, Hugging Face, Cloudflare, and Linear.
  Read by `scripts/audit-precision-contracts.py` (`npm run
  precision-contracts:check`, part of `npm run ci`), which derives and
  checks the beta.4 twin baseline below and the generated
  [`corpus audit`](../coverage/precision-corpus-audit.json). The review
  narrative, source ledger, and beta.4 measurement provenance this contract
  was reviewed against remain in
  [`docs/audits/evidence/367/`](https://github.com/redact-secret/redact-secret/blob/2816897f96c405c3eb8c87a0c70eba5df273c121/docs/audits/evidence/367/README.md) while the
  audit archive is retired. Moved here from the evidence archive by
  [#596](https://github.com/redact-secret/redact-secret/issues/596) (DS4).
- [`precision/beta4-twin-baseline.json`](precision/beta4-twin-baseline.json)
  — the 24 must-not-flag twins and their 24 paired positives from the beta.4
  `common-formats` snapshot, each frozen by construction recipe, content
  SHA-256, byte length, expected ranges and the ranges beta.4 produced. It is
  both the input and the checked output of the same recipe
  (`scripts/audit-precision-contracts.py --check` regenerates the derived
  `contractView` and fails on any byte difference) and the baseline
  `scripts/generate-precision-context-matrix.py` reads. The values are
  reconstructed from the recipe against the recorded beta.4 corpus and run
  provenance, not an independent measurement taken here. Moved from
  `docs/audits/evidence/367/` by
  [#1262](https://github.com/redact-secret/redact-secret/issues/1262) with
  its bytes unchanged.
- [`precision/shape-inventory.json`](precision/shape-inventory.json) — the
  reviewed inventory of valid-but-non-secret shapes the `generic-token`,
  `bearer-token`, `connection-string` and `jwt` detectors recognize, each
  citing its code or decision basis and the paired negative, positive and
  boundary fixtures in `conformance/fixtures/synchronous-corpus.json`.
  `scripts/check-shape-inventory.py` (`npm run shape-inventory:check`, part
  of `npm run ci`) fails when a cited fixture, detector, kind, implementation
  file or decision document no longer matches. A new exclusion or accepted
  tradeoff for one of these detectors adds its shape here
  ([`conformance/README.md`](../../conformance/README.md#negative-coverage-shape-tracking)).
  Moved from `docs/audits/evidence/475/` by
  [#1262](https://github.com/redact-secret/redact-secret/issues/1262); one
  note was corrected to cite the live contract path, and the data is
  unchanged.
- [`scoring/shadow-scoring-artifact.json`](scoring/shadow-scoring-artifact.json)
  and its schema
  [`scoring/shadow-scoring-artifact.schema.json`](scoring/shadow-scoring-artifact.schema.json)
  — the reviewed scoring artifact of the beta.9 shadow evidence scorer
  (issue [#798](https://github.com/redact-secret/redact-secret/issues/798)):
  feature schema, aggregation model, calibration and tuning provenance, and
  review method. Read by `scripts/check-scoring-artifact.py` (`npm run
  scoring-artifact:check`, part of `npm run ci`, and the pull-request job
  `scoring-artifact-identity`), which fails when it and the compiled scorer
  drift apart. Nothing loads it at runtime and no package ships it; it is
  not public API. The rules are in
  [`docs/specs/engine.md`, "Shadow scoring artifact"](../specs/engine.md#shadow-scoring-artifact).
- [`pii/pii-context-v2.json`](pii/pii-context-v2.json) and its schema
  [`pii/pii-context-v2.schema.json`](pii/pii-context-v2.schema.json) — the
  live contract-only English/Korean PII context vocabulary, including
  normalization, bounded candidate association, precedence, synthetic examples,
  and benign ambiguity controls. `scripts/generate-pii-context-table.py`
  compiles it into the core, and `scripts/check-pii-context-contract.py`
  validates it in `npm run pii-context:check`. Nothing loads it at runtime and
  no package ships it; the governing rules are in
  [`docs/specs/contextual-detection.md`](../specs/contextual-detection.md).
  v2 ([#924](https://github.com/redact-secret/redact-secret/issues/924))
  changed how equidistance is judged for field labels; before any release
  carried it, it was amended in place so a `|` delimiter bounds a positive
  field label ([#940](https://github.com/redact-secret/redact-secret/issues/940)).
- [`site-feed/v1/feed.json`](site-feed/v1/feed.json) and its schema
  [`site-feed/v1/feed.schema.json`](site-feed/v1/feed.schema.json) — the
  public site feed (`redact-secret.site-feed/v1`, issue
  [#945](https://github.com/redact-secret/redact-secret/issues/945)): release
  identity and support status a public site may claim, generated from the
  latest `docs/releases/<version>/manifest.json` and
  `benchmarks/support-matrix.json` by `scripts/generate-site-feed.py` (`npm
  run site-feed:generate`). `npm run site-feed:check`, part of `npm run ci`,
  fails when it is stale or schema-invalid. `redact-secret-www` reads it at
  an exact commit from
  `https://raw.githubusercontent.com/redact-secret/redact-secret/<40-hex commit>/docs/contracts/site-feed/v1/feed.json`.
  No package ships it. The contract and its compatibility policy are in
  [`docs/specs/distribution.md`](../specs/distribution.md) and
  [`decision-publish-a-commit-bound-public-site-feed`](../decisions/2026-09-28-publish-a-commit-bound-public-site-feed.md).
- [`pii/pii-context-v1.json`](pii/pii-context-v1.json) and its schema
  [`pii/pii-context-v1.schema.json`](pii/pii-context-v1.schema.json) — the
  `pii-context/v1` vocabulary defined for issue
  [#793](https://github.com/redact-secret/redact-secret/issues/793) and
  compiled into beta.10, kept unchanged as that release's record. No check
  or build reads it any more.
