---
decision_id: decision-exclude-filler-and-placeholder-bearer-values
status: accepted
scope: workspace
title: Exclude repeated-character filler and whole-value placeholder vocabulary from bearer-token
decided_at: 2026-09-20
---

# Exclude repeated-character filler and whole-value placeholder vocabulary from bearer-token

## Decision

Give `bearer-token` (`crates/secret-scan-core/src/detectors/bearer_token.rs`)
the same two non-secret-value exclusions `generic-token` already applies to
the `Basic`/`Token` authorization schemes:

- **Repeated-character filler.** `is_repeated_character_filler`
  (`super::text`, shared with `connection-string`, `datadog`, and `twilio`)
  excludes a value made of one character repeated three or more times
  (`xxxxxxxxxxxxxxxxxxxx`, `00000000000000000000`, `--------------------`).
- **Whole-value placeholder vocabulary.** A local `is_non_secret_bearer_value`
  calls the shared `matches_placeholder_vocabulary` (`super::text`) against a
  `bearer_token`-local copy of `generic-token`'s `PLACEHOLDER_WORDS` /
  `DIGIT_SUFFIX_PLACEHOLDER_WORDS` (`example`, `sample`, `placeholder`,
  `redacted`, `changeme`, `password`, `secret`, `replaceme`), excluding a
  value where every token, split on non-alphanumeric separators, is itself a
  listed word (`PASSWORD_SECRET_EXAMPLE`).

The word list is kept as a local copy in `bearer_token.rs` rather than a
cross-module import from `generic_token`, matching how `connection-string`
already keeps its own local list rather than depending on `generic-token`:
`bearer-token` and `generic-token` are independent detectors in the
registry, one applying to the `Bearer` scheme and the other to `Basic`/
`Token`/contextual assignments, with no existing dependency edge between
them; adding one for two constants would couple otherwise-independent
detector modules for a list of eight words. Both exclusions apply before the
existing identifier-boundary check, against the credential run before any
trailing `=` padding (`MAX_TRAILING_EQUALS`) is appended -- padding is not
part of the value the filler and placeholder predicates judge.

## Rationale

Issue #468 is the same shape as #264: `generic-token` reaches
`is_repeated_character_filler` and `is_generic_placeholder_word` through
`is_non_secret_reference`, which its `authorization_candidates` path applies
to `Basic` and `Token` header values, but `bearer-token`'s `detect` had no
equivalent call. The result was an inconsistency inside a single header
family -- the same masked or placeholder value was clean under `Basic`/
`Token` and redacted under `Bearer`, purely because `bearer-token`'s
acceptance rule was `match_scheme_at` + a 16-character token-alphabet run
with no further check.

The `bearer_token.rs:262` prose-tradeoff test
(`ordinary_prose_usage_of_bearer_is_safe_but_a_long_incidental_word_is_an_accepted_tradeoff`)
records a different, narrower tradeoff: `bearer` used as an ordinary English
noun followed by an incidentally long word is accepted as indistinguishable
from a real credential at the character-grammar level. That reasoning does
not extend to a value that already carries a structural non-secret signal
this codebase's own predicates recognize; the accepted tradeoff is about the
*scheme* word being ambiguous prose, not about a value already provably safe
by the same lights the sibling schemes are judged by. The test is unaffected
by this change (neither of its inputs is filler or listed-placeholder
vocabulary) and needs no update.

**Accepted false-negative risk, matching #264 and #257.** Only whole-value
placeholder vocabulary is excluded, not compound forms that mix a listed
word with an unlisted one: `EXAMPLE_TOKEN_VALUE`, `DUMMY_TOKEN_VALUE`, and
`YOUR_ACCESS_TOKEN_HERE` from #468's own reproduction table stay detected,
because `TOKEN`, `VALUE`, `DUMMY`, `YOUR`, `ACCESS`, and `HERE` are not on
`PLACEHOLDER_WORDS`. Extending the vocabulary to compound forms was
considered and rejected for this issue: it is a broader change than the
inconsistency #468 reports, and a token like `TOKEN` or `VALUE` recurs
inside real (if weakly named) credential-bearing identifiers often enough
that adding it to the exact-word list risks new false negatives on real
secrets, not just on placeholders. This mirrors `generic-token`'s own
accepted gap for the identical values under `Basic`/`Token` -- `#468`
narrows an inconsistency between the two, it does not raise either
detector's placeholder recall. A follow-up issue can revisit compound
placeholder matching for both detectors together if warranted.

## Consequences

- `bearer_token.rs` gains `PLACEHOLDER_WORDS`, `DIGIT_SUFFIX_PLACEHOLDER_WORDS`,
  and `is_non_secret_bearer_value`, and imports `is_repeated_character_filler`
  and `matches_placeholder_vocabulary` from `super::text`.
- Every scheme in the `Authorization` header family now agrees on a masked
  or placeholder value: `bearer-negative-repeated-character-filler-run-of-x`
  /`-run-of-zero`/`-run-of-dash`, `bearer-negative-placeholder-whole-value`,
  and the paired `authorization-negative-basic-*`/`authorization-negative-
  token-*` fixtures in `conformance/fixtures/synchronous-corpus.json` pin
  this across all three schemes. `bearer-positive-near-miss-repeated-
  character-filler` and `bearer-positive-compound-placeholder-not-excluded`
  pin that a near-miss filler value and a compound placeholder value both
  stay detected at high confidence, alongside the pre-existing
  `bearer-positive-scheme` fixture for an ordinary real-looking value.
  `common-profile-expectations.json` is regenerated to match the larger
  corpus; no pre-existing fixture's expectation changed.
- `conformance/fixtures/incremental-corpus.json` gains
  `bearer-token-filler-and-placeholder-exclusion-boundary`, pairing an
  excluded filler value with a detected credential across a line boundary,
  so every UTF-8 partition boundary -- including one that falls inside the
  filler run -- must reproduce the whole-input reference.
- Since the exclusion lives in the shared Rust core detector, all five
  public surfaces (Rust core, the Node native addon and its WebAssembly
  fallback, the browser/Workers WebAssembly build, the Python binding, and
  the CLI) inherit it without surface-specific changes.
