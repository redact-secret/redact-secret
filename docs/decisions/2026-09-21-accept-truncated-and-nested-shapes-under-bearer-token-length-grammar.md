---
decision_id: decision-accept-truncated-and-nested-shapes-under-bearer-token-length-grammar
status: accepted
scope: workspace
title: Accept a truncated or nested-provider Bearer value under bearer-token's length-and-alphabet grammar
decided_at: 2026-09-21
spec: detector-families
---

# Accept a truncated or nested-provider Bearer value under bearer-token's length-and-alphabet grammar

## Decision

`bearer_token.rs`'s `detect` (`crates/secret-scan-core/src/detectors/bearer_token.rs:181`)
keeps classifying a `Bearer`-scheme value at `Confidence::High` / `Action::Redact`
whenever the run of `is_token_char` bytes starting right after `Bearer\s+`
reaches `MIN_TOKEN_LEN` (16), with no further requirement that:

- the run consume the *entire* mutated or embedded value up to its next
  whitespace/line boundary — a single non-alphabet byte partway through a
  longer value simply ends the run early, and the run up to that point is
  still classified if it alone clears 16 bytes; or
- the run's internal structure match a narrower, provider-specific grammar
  (segment count, separators, exact segment lengths) that a *different*
  detector enforces for that provider's own credential shape.

No code changes accompany this record; `is_token_char`, `MIN_TOKEN_LEN`, and
the rest of `detect`'s structure are unchanged. It documents an existing,
already-shipped tradeoff the way
`ordinary_prose_usage_of_bearer_is_safe_but_a_long_incidental_word_is_an_accepted_tradeoff`
(`bearer_token.rs:307`) already documents the equivalent ordinary-English-word
tradeoff for this same detector, and adds the same kind of pinning test:
`bearer_token.rs`'s
`a_mid_value_alphabet_break_or_an_embedded_narrower_provider_shape_still_clears_the_length_floor`.

## Rationale

Issue #553 found five `redact-secret-benchmarks` twin fixtures reported as
`flagged:1` (a discrimination failure) that reduce to this one mechanism, not
five independent bugs:

```
detector-coverage--bearer-token-header-bare-twin           bearer-token   (alphabet break mid-value)
detector-coverage--bearer-token-header-quoted-twin          bearer-token   (alphabet break mid-value)
detector-coverage--bearer-token-header-unicode-crlf-twin    bearer-token   (alphabet break mid-value)
sendgrid-regressions--base62-bearer-twin                    bearer-token   (embedded narrower shape)
```

(The fifth, `sendgrid-regressions--base62-generic-key-twin`, is unrelated —
see "What this record does not decide" below.)

**The `bearer-token-header` twins.** The fixture takes a 40-byte synthetic
Bearer value and replaces the byte at index 20 with `!`, a character outside
both the RFC 6750 `b64token` alphabet and this detector's own `is_token_char`
set, expecting the mutation to defeat detection entirely. Reconstructing the
exact fixture bytes with the same seeded generator
(`redact-secret-benchmarks`' `fixtures/generated/build.mjs` `synthetic()`)
and running them through this branch's CLI confirms the actual output:

```
$ redact-secret --json /tmp/bearer_bare.txt
detector=bearer-token confidence=high action=redact start=22 end=42
```

`ascii_run_len` (`bearer_token.rs:167`) stops the token run at the `!`, at
byte 20 — but 20 already clears `MIN_TOKEN_LEN` (16), so the truncated prefix
alone is classified. This is not a bug in the alphabet check: `!` correctly
ends the run exactly where it appears. It is a consequence of `MIN_TOKEN_LEN`
being well under half of the fixture's 40-byte value — no single mid-value
byte mutation on a value of this length can produce a negative under the
documented 16-byte floor, because whichever side of the break is longer is
still ≥16 (a break at index 20 of 40 leaves 20 and 19 respectively). The
fixture's own premise — "one alphabet-violating byte anywhere in the value
defeats detection" — does not hold given the grammar as already documented in
this file's module comment: "Requires the explicit `Bearer` scheme and a
token of at least 16 characters... intentionally misses short development
tokens." The converse of that same sentence is what the twin encountered: it
does *not* intentionally miss a long-enough one, truncated or not.

**`sendgrid-regressions--base62-bearer-twin`.** This fixture wraps a
one-byte-short SendGrid-shaped value (`SG.<22-byte id>.<42-byte secret>`,
contracted from the documented 43) in an `Authorization: Bearer ` header.
`sendgrid.rs`'s own detector correctly declines it — `sendgrid.rs:18`'s doc
comment states plainly that "a shorter or longer segment... is an
intentional false negative rather than a fuzzy match", and the exact-length
check (`ID_LEN`/`SECRET_LEN`) enforces that. But the fixture's `Bearer `
context is also, independently, a valid `bearer-token` candidate: the whole
`SG.<id>.<42-byte secret>` run is 67 bytes of `is_token_char` bytes (`.` is
in the token alphabet), comfortably over 16, so `bearer-token` classifies it
on its own terms:

```
$ redact-secret --json /tmp/sendgrid_bearer.txt
detector=bearer-token confidence=high action=redact start=22 end=90
```

`bearer-token` was never validating against SendGrid's specific
two-segment/43-byte contract — it has no reason to, and no existing decision
asks it to. The twin's premise — "sendgrid-token's own exact-length rejection
should silence the whole file" — conflates the two detectors: `sendgrid.rs`'s
decline is correct and unaffected; the file is still flagged by a different,
independently-correct detector reading the identical bytes as a generic
long-enough Bearer credential, which — one byte short of a real SendGrid key
or not — is not meaningfully safer to leave unredacted.

**Why this generalizes, not just patches five fixtures.** Nothing in
`bearer-token`'s contract validates whole-value alphabet purity beyond the
first `is_token_char` run, and nothing makes it aware of any other
detector's narrower, provider-specific grammar. Both are true by design: the
module doc's own stated tradeoff is length/alphabet structure only, matching
the same "grammar, not language or format awareness, is what keeps this
detector safe" precedent already recorded in
[`2026-09-20-warn-unconditionally-on-high-signal-contextual-names.md`](2026-09-20-warn-unconditionally-on-high-signal-contextual-names.md)
for `generic-token`'s equivalent structural tradeoff, and consistent with
[`2026-09-20-exclude-filler-and-placeholder-bearer-values.md`](2026-09-20-exclude-filler-and-placeholder-bearer-values.md),
which narrowed `bearer-token`'s exclusions to exactly two structurally
provable non-secret shapes (repeated-character filler, whole-value
placeholder vocabulary) and deliberately went no further into alphabet-purity
or nested-shape validation.

## Consequences

- No detection logic changes in `bearer_token.rs` or `sendgrid.rs`.
- `bearer_token.rs` gains
  `a_mid_value_alphabet_break_or_an_embedded_narrower_provider_shape_still_clears_the_length_floor`,
  pinning both reproduced cases (a `!`-broken 40-byte value truncating to a
  still-classified 20-byte prefix, and a one-byte-short SendGrid-shaped value
  under `Authorization: Bearer`) alongside the existing
  `ordinary_prose_usage_of_bearer_is_safe_but_a_long_incidental_word_is_an_accepted_tradeoff`
  test this record follows the same pattern as.
- The four `redact-secret-benchmarks` fixtures cited above encode a
  discrimination expectation this detector's documented, already-shipped
  contract does not support; correcting them (construct the alphabet-break
  mutation within 16 bytes of an edge, or accept co-detection by
  `bearer-token` as expected for the SendGrid twin) is
  `redact-secret-benchmarks` work, tracked via
  `redact-secret/redact-secret-benchmarks#66`, and out of this repository's
  boundary (`AGENTS.md`) the same way `docs/audits/evidence/552/README.md`
  already established for four unrelated families' stale fixtures.
- No true positive is lost: `bearer_token.rs`'s full test suite and the
  workspace suite both pass unchanged (see `docs/audits/evidence/553/README.md`).

## What this record does not decide

- It does not cover `sendgrid-regressions--base62-generic-key-twin`, the
  fifth fixture from issue #553. That fixture's `api_key=` context is a
  `generic-token` `HIGH_SIGNAL_NAMES` match already governed by the standing
  [`2026-09-20-warn-unconditionally-on-high-signal-contextual-names.md`](2026-09-20-warn-unconditionally-on-high-signal-contextual-names.md)
  decision; no new decision is needed for it, and none is created here.
- It does not reopen `sendgrid.rs`'s exact-length contract or
  `bearer-token`'s filler/placeholder exclusions; both are unaffected and
  correct as shipped.
