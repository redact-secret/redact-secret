---
decision_id: decision-warn-unconditionally-on-high-signal-contextual-names
status: accepted
scope: workspace
title: Warn unconditionally on high-signal contextual-name assignments despite prose false positives
decided_at: 2026-09-20
---

# Warn unconditionally on high-signal contextual-name assignments despite prose false positives

## Decision

`assignment_confidence` (`crates/secret-scan-core/src/detectors/generic_token.rs:774-800`)
keeps returning `Some(Confidence::High | Medium)` unconditionally for every
`HIGH_SIGNAL_NAMES` match whose value clears the shared length bound
(`MIN_CONTEXT_VALUE_LENGTH`..=`MAX_CONTEXT_VALUE_LENGTH`) and is not already
excluded by `is_non_secret_reference` — entropy and length choose only between
`High` and `Medium`, never `None`, for a `HIGH_SIGNAL_NAMES` match. Ordinary
documentation or README prose that names a credential parameter
(`secret=`, `api_key:`, `password= `) followed by an ordinary English word is
therefore still reported as a `contextual_secret` finding at `Confidence::Medium`
/ `Action::Warn` (issue #473). No code change accompanies this record; it
documents the tradeoff the way `bearer_token.rs`'s
`ordinary_prose_usage_of_bearer_is_safe_but_a_long_incidental_word_is_an_accepted_tradeoff`
test documents the equivalent tradeoff for that detector, and adds the same
kind of test here:
`generic_token.rs`'s `high_signal_names_warn_on_ordinary_prose_as_an_accepted_precision_tradeoff`.

## Rationale

A real weak credential of the high-signal-name shape classifies identically to
the prose false positives it sits next to:

```
medium/warn   password=hunter2xyz          <- real credential, must keep
medium/warn   password= followed           <- prose, false positive
medium/warn   secret: something            <- prose, false positive
```

Both populations are short (below `MIN_HIGH_ENTROPY_LENGTH`, so entropy cannot
promote them to `High`), low-entropy (natural-language words are neither
high-entropy nor placeholder-shaped), and syntactically identical unquoted
single-token values immediately after the assignment delimiter. There is no
threshold on length, entropy, or confidence that separates them: raising the
bar enough to drop `followed` also drops `hunter2xyz`, trading a `warn`-level
false positive for a false negative on a real, if weak, credential — a worse
outcome, because `warn` never rewrites anything (`default_action_for` in
`crates/secret-scan-core/src/policy.rs` only escalates to `Action::Redact` at
`Confidence::High`).

The only signal that actually separates the two populations is lexical: the
captured values in the prose cases are common English words (`parameter`,
`followed`, `obtained`, `whichever`, `configuration`), while real credentials,
even weak ones, are not. A bundled wordlist would work but is a real increase
in surface area and opens a new false-negative axis of its own: a real
passphrase built from whole words (the same tension
`is_snake_case_attribute_chain`'s doc comment already flags for
`my.pass.word`) would newly go undetected. A cheaper structural alternative —
reject a captured value when it is followed by more prose rather than a
value-terminating boundary, so `secret: whichever value your provider issued.`
does not qualify while `secret: whichever` alone still does — was considered
and rejected for the same reason: "more prose follows" and "the sentence
continues after the real assignment on the same line" are not reliably
distinguishable without the same kind of lexical judgment, and a wrong guess
in either direction reproduces one of the two failure modes above.

`private_key` and the always-redact types the `password`/`secret` etc. names
in `HIGH_SIGNAL_NAMES` deliberately are not: they land at `warn`, not
`redact`, when confidence is `Medium`, which is why this record accepts the
tradeoff rather than treating it as equivalent in severity to a redaction bug.
This mirrors the precedent already accepted for `bearer_token.rs`'s
ordinary-English-noun-usage case: a short, low-entropy, structurally
indistinguishable match stays classified, and the token-length/shape grammar
— not language awareness — is what the detector relies on to stay safe in the
common case.

## Consequences

- No detection logic changes. The ten minimized prose reproducers from issue
  #473 continue to produce a `contextual_secret` finding at `Confidence::Medium`
  / `Action::Warn`.
- `generic_token.rs` gains a test,
  `high_signal_names_warn_on_ordinary_prose_as_an_accepted_precision_tradeoff`,
  that pins all ten reproducers alongside a real weak credential
  (`password=hunter2xyz`) classifying identically, documenting why this is a
  deliberate recall choice rather than an oversight — the same role
  `bearer_token.rs:262`'s test plays for that detector.
- Documentation and README scanning remains a stated use case with a known,
  accepted noise cost at `warn` severity: nothing is rewritten, and a reviewer
  can dismiss the finding, but any prose mentioning a high-signal credential
  parameter name followed by a short, low-entropy word will keep surfacing a
  finding.
- Revisiting this tradeoff (for example, via a bundled wordlist or a
  precision/recall-scored heuristic) is left open for a future issue if the
  noise proves costlier in practice than accepted here; it is out of scope for
  #473.
