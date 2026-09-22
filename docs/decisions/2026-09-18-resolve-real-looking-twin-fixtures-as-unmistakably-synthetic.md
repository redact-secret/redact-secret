---
decision_id: decision-resolve-real-looking-twin-fixtures-as-unmistakably-synthetic
status: accepted
scope: workspace
title: Resolve real-looking twin fixtures as unmistakably synthetic
decided_at: 2026-09-18
spec: evidence-and-gates
---

# Resolve real-looking twin fixtures as unmistakably synthetic

## Context

Issue [#419](https://github.com/redact-secret/redact-secret/issues/419),
found by the beta.5 pre-release review, identified that the paired-twin
fixtures carried over from issues #368 (`openai.rs`, legacy/`sk-proj-`/
`sk-svcacct-` keys) and #371 (`slack.rs`, an `xoxb-` bot token) — plus the
same values duplicated into `conformance/fixtures/synchronous-corpus.json`
and `incremental-corpus.json` — were full-shape, random-looking values with
no synthetic marker. `AGENTS.md` and `conformance/README.md`'s [Fixture
safety review](../../conformance/README.md#fixture-safety-review) require
every corpus `input` to be unmistakably synthetic or revoked. A lower-severity
instance of the same defect existed in the `DigitalOcean` v1 token's 64-byte
hex bodies (`additional_providers.rs`, `tests/digitalocean_precision.rs`,
`conformance/fixtures/digitalocean-v1-mutations.ts`), which come from a
seeded generator and were never issued, but read as plausible random hex.

## Decision

Regenerate every listed value in place with a visible, unmistakably
constructed marker, rather than record a provenance-only exception. The
detector contracts described in
[`2026-09-17-freeze-precision-contracts-for-seven-provider-families.md`](2026-09-17-freeze-precision-contracts-for-seven-provider-families.md)
are unchanged; only fixture bytes moved, following the corpus's textual-splice
procedure and keeping every value's byte length exactly as reviewed, so every
existing byte-range assertion stays correct by construction:

- **Alphabet grammars that admit letters** (OpenAI's legacy/`proj`/`svcacct`
  segments, Slack's bot secret section): reuse this file's own established
  idiom — a `SYNTHETIC…`/`SYNTHETIC_REVOKED…` label cycled to the exact
  documented segment length — the same construction `openai.rs`'s
  `LEGACY_KEY`/`PROJECT_KEY`/`SERVICE_ACCOUNT_KEY` and `slack.rs`'s
  `BOT_POSITIVE` already use elsewhere in the same files. Each negative twin
  keeps the exact structural defect the issue reproduced (a one-byte-mutated
  marker, a contracted segment length, or a missing section separator).
- **Hex-only grammars that admit no letters beyond `a`–`f`** (DigitalOcean's
  64-byte body): a `SYNTHETIC` marker cannot be spelled, so each body becomes
  an unmistakably patterned, non-random hex run — the same counting idiom
  `datadog.rs`'s `APPLICATION_KEY` and `new_relic.rs`'s `LICENSE_KEY` already
  use for their own hex-only bodies — instead of a provenance-only exception.
  The three DigitalOcean bodies use distinct ascending, descending, and
  rotated-ascending hex counters so the personal-access, OAuth-access, and
  OAuth-refresh fixtures stay distinguishable from one another.

This decision does not add a convention-level exception to
[`conventions/synthetic-secret-regressions.md`](../../conventions/synthetic-secret-regressions.md):
seeded-generator provenance remains documentation, not a substitute for a
visibly synthetic value, whenever the grammar's alphabet admits one.

## Consequences

Every fixture flagged by issue #419 — and every place its value was
duplicated (registry inventory reconciliation, doc-coverage triggers, the
`digitalocean-v1` mutation-family generator and its corpus-derived variants)
— now reads as unmistakably synthetic on sight, with no detector, byte-range,
or grammar change. A reader or third-party scanner cannot mistake any of
these values for an issued credential.
