---
decision_id: decision-match-placeholder-words-on-token-boundaries
status: accepted
scope: workspace
title: Match placeholder words on token boundaries, not exact-string equality
decided_at: 2026-09-15
---

# Match placeholder words on token boundaries, not exact-string equality

## Decision

Replace whole-value, case-insensitive exact-string equality in
`generic-token`'s `is_generic_placeholder_word`
(`crates/secret-scan-core/src/detectors/generic_token.rs`) and
`connection-string`'s `is_placeholder`
(`crates/secret-scan-core/src/detectors/connection_string.rs`) with a shared
token-boundary matcher, `matches_placeholder_vocabulary`
(`crates/secret-scan-core/src/detectors/text.rs`), used by both.

A value is split into maximal runs of ASCII alphanumeric characters — every
other byte (whitespace, `-`, `_`, quotes, ...) is a token separator. The
value is excluded when either holds:

- the tokens, concatenated in order with no separator, spell out exactly one
  listed word (`replace_me`, `my-secret-password` -> `replaceme`,
  `mysecretpassword`); or
- every token is itself a listed word, or, once a trailing run of ASCII
  digits is stripped, a word on a second, smaller list of words distinctive
  enough to tolerate an appended digit (`changeme2` -> `changeme`;
  `REDACTED-EXAMPLE` -> `redacted` + `example`).

The digit-suffix list is a strict subset of the full word list. Generic role
names — `password`, `secret` (and, for `connection-string`, the vendor
default `mysecretpassword`/`supersecretpassword` only insofar as they are
compounds of those words) — are **not** on it: `password1` and `secret01`
are common real, if weak, credential shapes, not placeholder text, and the
canonical conformance corpus already has a fixture
(`contextual-positive-minimum-length-is-medium-confidence`, value
`SECRET01`) asserting they keep being reported.

This is not raw substring containment: a listed word embedded inside a
larger, unrelated alphanumeric run (`mySecretKeyAbc123`) is never split out
of that run, and every token in the value — not just one — must resolve to
a listed word, so `password_over_there` (a word list entry plus unrelated
tokens) is still reported.

Issue #257's own reproduction hyphenates three words
(`REDACTED-EXAMPLE-VALUE`); `value` is not itself a listed placeholder word,
so the committed regression fixture uses the two-word `REDACTED-EXAMPLE`
instead, per the issue's "or the maintainers' chosen equivalent minimal set"
allowance. Keeping the "every token must be listed" requirement (rather than
"any token is listed") is what keeps this substitution meaningful: a real
high-entropy secret coincidentally prefixed with a hyphenated placeholder
word would still be reported.

## Rationale

The prior exact-string check suppressed the intended vocabulary only for the
literal, unpadded value. A single leading/trailing separator, an appended
digit, or joining two already-excluded words with `-`/`_` all defeated it in
both independently-implemented detectors, while being trivial variants of
values the maintainers had already judged non-secret enough to hardcode.
Token-boundary matching closes those variants deterministically without
resorting to substring containment, which would risk suppressing a real
secret that happens to contain a listed word as a substring (e.g. a
high-entropy value coincidentally containing the run `secret`).

## Consequences

- `generic_token.rs` and `connection_string.rs` each now declare two word
  lists (the full list and the digit-suffix-tolerant subset) instead of one,
  and both call the shared `matches_placeholder_vocabulary` in
  `detectors/text.rs`.
- A real secret shaped exactly like `<digit-suffix word>` + only digits
  (e.g. `changeme482910`) is now a false negative by design; this is judged
  low-to-moderate risk per the issue's own analysis, and is bounded to the
  small digit-suffix word list, not the full vocabulary.
- Negative regression fixtures for both detectors cover the leading
  separator, appended digit, and hyphenated-compound variants; positive
  regression fixtures assert a listed word embedded in a larger high-entropy
  value, and a listed word alongside unrelated tokens, both keep being
  reported.
