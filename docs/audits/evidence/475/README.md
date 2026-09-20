# Issue #475 — shape inventory for the structural/contextual detectors

[Audit archive](../../README.md) ·
[Issue #475](https://github.com/redact-secret/redact-secret/issues/475)

Issue #475 found that the negative corpus's coverage is concentrated on
provider-format detectors, whose valid-but-non-secret shapes were surveyed
under [#367's precision-contract review](../367/README.md), while
`generic-token`, `bearer-token`, `connection-string`, and `jwt` — the
detectors whose value has no grammar to tighten — had accumulated fixtures
issue by issue rather than by a surveyed input space. Five classes probed by
hand-testing `0.1.0-beta.4` produced live false positives with zero
corresponding fixtures (#467, #468, #469, #472, #473); by the time this issue
was picked up, #467, #468, and #472 already had committed fixture pairs from
their own fixing PRs, but #469 and #473 shipped with Rust unit tests only —
no corpus evidence at all.

## Files

| File | Contents | Maintained by |
| --- | --- | --- |
| [`shape-inventory.json`](shape-inventory.json) | One row per valid-but-non-secret shape the four detectors recognize: its description, its evidentiary basis (a cited exclusion function or an accepted ADR), and the negative/positive (and, for one boundary case, `boundary`) fixture ids in `conformance/fixtures/synchronous-corpus.json` that prove it. Comparable in form to [`precision-contracts.json`](../367/precision-contracts.json), adapted to detectors with no provider grammar to enumerate. | hand-authored review |

There is no automated `--check` regeneration for this file the way
`scripts/audit-precision-contracts.py` provides for #367 — every id it cites
was verified against the live corpus by hand at review time (see below), and
`crates/secret-scan-core/tests/canonical_corpus.rs` is the actual enforcement
boundary: an id in this document that stopped matching its cited detector,
kind, or expected result would be a Rust test failure, not a silent drift
this document could introduce.

## What changed under this issue

- **#469** (connection-string `$VAR`/interpolation passwords) and **#473**
  (prose mentioning `secret=`/`api_key:`) each gained their first corpus
  fixtures: 17 new `connection-string` fixtures (the six #469 reference forms
  plus the pre-existing braced `${...}` form, three "still detected"
  boundary controls, and three realistic multi-line host pairs) and 2 new
  `generic-token` fixtures pinning the #473 accepted-tradeoff Warn/Medium
  outcome the ADR already recorded.
- **Context coverage**: before this issue, `bearer-token` and `jwt` had zero
  `dotenv`, `yaml`, or `markdown` fixtures — only a single-line `json`
  positive each — despite both carrying host-sensitive exclusions (repeated-
  character filler and placeholder vocabulary for `bearer-token`; the
  Supabase legacy-anon payload carve-out for `jwt`). Six new fixtures per
  detector (one negative/positive pair per context) close that gap, reusing
  the shapes that already exist rather than inventing new detector behavior.
- **#467, #468, #472** already had committed fixture pairs from their own
  fixing PRs (471, 476, 478) before this issue started; `shape-inventory.json`
  catalogs them rather than re-adding them.

## Method

Every referenced fixture id was cross-checked programmatically against
`conformance/fixtures/synchronous-corpus.json` for existence, detector, and
`kind` agreement (a `"negative"` row must cite a `kind: "negative"` fixture
with `expected: []`; a `"positive"` row must cite a `kind: "positive"`
fixture with a non-empty `expected`). Every new fixture's `expected` field
was derived by running the fixture's literal `input` through the built
`redact-secret-cli --json`, not hand-computed, so the corpus and the
document agree with the actual compiled detector rather than with an
independent understanding of it.

## What this evidence does not claim

It does not assert that these four detectors' exclusion surface is complete
or that no further false-positive class exists; it records what the shipped
`0.1.0-beta.4`+ detectors actually do, with a fixture proving each claim. A
`basis.kind: "code"` row is unconditional detector behavior; a
`basis.kind: "decision"` row is a tradeoff this project chose and can revisit
through its own ADR.
