---
decision_id: decision-freeze-notion-integration-token-grammar
status: accepted
scope: workspace
title: Freeze the Notion integration token grammar as two exact-length prefixed shapes
decided_at: 2026-09-16
spec: detector-families
---

# Freeze the Notion integration token grammar as two exact-length prefixed shapes

## Decision

Add a dedicated `notion-token` detector
(`crates/secret-scan-core/src/detectors/notion.rs`) for issue #300,
recognizing a Notion integration token by either of two shapes, both bounded
on both sides by a byte outside `[A-Za-z0-9_]` or the edge of input:

```
secret_<43 bytes from [A-Za-z0-9]>          (legacy, 50 bytes total)
ntn_<11 ASCII digits><35 bytes from [A-Za-z0-9]>   (current, 50 bytes total)
```

Confidence is `High` and specificity is `Provider`; the default policy
always redacts a match (`notion_integration_token` in
`ALWAYS_REDACT_TYPES`, `crates/secret-scan-core/src/policy.rs`), the same
class every other dedicated provider detector in this registry gets. No
surrounding context (`NOTION_TOKEN=`, `Authorization: Bearer`, ...) is
required to classify a match, matching how every other
`Specificity::Provider` detector in this module works.

Known unsupported variants, all deliberately out of scope:

- The OAuth refresh-token shape (`nrt_` prefix). Notion's own authorization
  guide shows exactly one example value and no published grammar; the
  digit-run length in that single sample (13 digits) does not even match the
  current integration-token shape's 11, so there is nothing reliable to
  freeze. Neither external reference scanner below has a rule for it either.
- OAuth access tokens issued through the public-integration flow. Notion's
  docs show only opaque/temporary example values with no stable documented
  or community-converged prefix.
- Notion page, database, and block IDs and share-URL identifiers (UUID
  shapes, dashed or undashed). These are public identifiers, not secrets,
  per the issue's explicit scope note, and carry neither of the two prefixes
  above so this detector never matches them regardless.
- A `secret_` value whose suffix is not exactly 43 bytes, or an `ntn_` value
  whose digit run is not exactly 11 digits or whose total suffix is not
  exactly 46 bytes. These are intentional false negatives, not fuzzy
  matches, matching this registry's `sendgrid-token` and
  `github_pat_`-segment precedent for exact-length documented shapes.

## Rationale

Notion's developer documentation
(`https://developers.notion.com/guides/get-started/authorization`,
`https://developers.notion.com/reference/create-a-token`) describes how
integration tokens are created and retrieved but does not publish a
grammar for the token string itself. Notion's own API changelog, however,
does confirm the load-bearing fact needed to freeze two shapes instead of
one:

> Starting September 25, 2024, newly generated Public API tokens will
> automatically use the `ntn_` prefix instead of the `secret_` prefix...
> Existing tokens with the `secret_` prefix remain functional with no
> required updates.

Issue #300's acceptance criteria require freezing "the supported grammar,
confidence, action, and known unsupported variants... before
implementation" and note that "ambiguous unprefixed values require reliable
context." Both shapes here carry a vendor-confirmed literal prefix, so
neither is an unprefixed/ambiguous case in that sense; what is missing from
Notion's own docs is only the exact suffix length and alphabet, which this
freeze sources from external behavioral references per `AGENTS.md` (no code
copied from either, consistent with the issue's explicit instruction not to
copy TruffleHog implementation code):

- trufflehog's `notion` detector: `\b(secret_[A-Za-z0-9]{43})\b`.
- gitleaks 8.30.1's `notion-api-token` rule:
  `\b(ntn_[0-9]{11}[A-Za-z0-9]{32}[A-Za-z0-9]{3})(?:[\x60'"\s;]|\\[nr]|$)`,
  i.e. `ntn_` followed by 11 digits and 35 further alphanumeric bytes (the
  `{32}`/`{3}` split is a source-formatting artifact, not a semantic
  boundary within the suffix).

Both independently-converged shapes total exactly 50 bytes including the
prefix, which corroborates that Notion kept the overall token length
constant across the September 2024 prefix change rather than redesigning
the suffix. Because two independent, widely-deployed scanners converged on
the same suffix lengths from real-world samples without needing surrounding
context to disambiguate, this detector treats each prefix-plus-exact-length
shape as itself "reliable context" in the sense the acceptance criteria
mean it, the same trust every other literal-prefixed provider detector in
`additional_providers.rs`/`shopify.rs`/`sendgrid.rs` gets. This is
consistent with Notion's changelog guidance to treat tokens as "opaque
strings" for API-side validation purposes; that guidance is about the
provider's own runtime token validation, not about whether a fixed,
externally-corroborated shape is specific enough for a secret scanner to
flag deterministically, which is the same class of judgment call this
registry already makes for `microsoft-entra-client-secret`'s undocumented
`<digit>Q~` shape (see
`2026-09-16-freeze-microsoft-entra-client-secret-grammar.md`).

## Consequences

- `crates/secret-scan-core/src/detectors/mod.rs` registers the new detector
  after `microsoft-entra-client-secret` and before `jwt`; overlap
  resolution's registration-order tie-break is unaffected in practice since
  this grammar cannot overlap another built-in provider's shape.
- `docs/coverage/detector-inventory.json` gains a `notion_integration_token`
  row (`always-redact`); `docs/coverage/coverage-declarations.json`,
  `inventory-report.json`, and `coverage-report.md` are regenerated from it
  and `conformance/fixtures/synchronous-corpus.json`, not hand-edited.
- New corpus fixtures cover both prefix shapes: bare positives, a generic
  contextual-assignment overlap, an adversarial long-padding input, boundary
  cases (below-minimum and above-maximum suffix length for each shape, a
  non-digit byte in the `ntn_` digit run, an invalid-alphabet byte, a
  too-short prefix run), and negatives (a page-ID-shaped UUID, an OAuth
  refresh-token-shaped `nrt_` value, and documentation placeholder/masked
  text).
- The `nrt_`-prefixed OAuth refresh-token shape, any OAuth access token, and
  any `secret_`/`ntn_`-adjacent value that does not match the exact frozen
  suffix length go undetected by this dedicated detector. A
  `NOTION_TOKEN=`/`apiKey:`-style assignment carrying one of those
  unsupported shapes can still surface as a lower-confidence,
  lower-specificity `contextual_secret` finding through the existing
  generic-token path, independent of this detector.
- A benign string that happens to contain `secret_` or `ntn_` immediately
  followed by a run of the right length and alphabet would false-positive;
  this is accepted as the same class of risk every other provider-prefixed
  detector in this registry already carries, bounded by requiring the exact
  literal prefix and an exact suffix length rather than an open-ended
  minimum.
