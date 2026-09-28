# Live contracts

Every file in this directory is a **live contract**: a script or CI reads it
at run time, so per
[`decision-decide-artifact-taxonomy-spec-routing-and-evidence-placement`](../decisions/2026-09-22-decide-artifact-taxonomy-spec-routing-and-evidence-placement.md)
it lives outside `docs/audits/evidence/`, where only frozen, non-live records
belong. Nothing here changes what a detector does at scan time — the Rust
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
  checks the beta.4 twin baseline and corpus audit still frozen at
  [`docs/audits/evidence/367/`](../audits/evidence/367/README.md) — that
  directory carries the full review narrative, source ledger, and beta.4
  measurement provenance this contract was reviewed against. Moved here from
  the evidence archive by
  [#596](https://github.com/redact-secret/redact-secret/issues/596) (DS4).
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
- [`pii/pii-context-v1.json`](pii/pii-context-v1.json) and its schema
  [`pii/pii-context-v1.schema.json`](pii/pii-context-v1.schema.json) — the
  `pii-context/v1` vocabulary defined for issue
  [#793](https://github.com/redact-secret/redact-secret/issues/793) and
  compiled into beta.10, kept unchanged as that release's record. No check
  or build reads it any more.
