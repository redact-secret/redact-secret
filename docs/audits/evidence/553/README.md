# Issue #553 — settling the `bearer-token` and `sendgrid-token` twin failures

[Audit archive](../../README.md) ·
[Governing decision](../../../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) ·
[Standing decision cited](../../../decisions/2026-09-20-warn-unconditionally-on-high-signal-contextual-names.md) ·
[Related decision](../../../decisions/2026-09-20-exclude-filler-and-placeholder-bearer-values.md) ·
[Issue #553](https://github.com/redact-secret/redact-secret/issues/553) ·
[Epic #548](https://github.com/redact-secret/redact-secret/issues/548) ·
[Prior evidence: #552](../552/README.md) ·
[Benchmarks-side tracking: redact-secret-benchmarks#66](https://github.com/redact-secret/redact-secret-benchmarks/issues/66)

Written 2026-09-21 against `main` at `86577d8e5b7db7a5a6c4ecfd6fc6ee8ab215909a`,
on branch `workbench/553-bearer-sendgrid-twin-decision`.

## Summary

Issue #553 asks for a per-family classification, before any fix, of the five
`redact-secret-benchmarks` twin fixtures reported `flagged:1` for
`bearer-token` (3) and `sendgrid-token` (2) — the only two families in the
registry carrying a `twinFailures` or `differential.unresolvedContractDisagreements`
gate failure — and to apply whichever remedy each finding calls for.

**None of the five is a detector defect.** All five reduce to two
already-established, already-shipped design decisions:

| fixture | target family | actual firing detector | explanation |
| --- | --- | --- | --- |
| `detector-coverage--bearer-token-header-bare-twin` | `bearer-token` | `bearer-token` | mid-value alphabet break still leaves a ≥16-byte prefix |
| `detector-coverage--bearer-token-header-quoted-twin` | `bearer-token` | `bearer-token` | same |
| `detector-coverage--bearer-token-header-unicode-crlf-twin` | `bearer-token` | `bearer-token` | same |
| `sendgrid-regressions--base62-bearer-twin` | `sendgrid-token` | `bearer-token` | one-byte-short SendGrid value is still a long enough generic Bearer token |
| `sendgrid-regressions--base62-generic-key-twin` | `sendgrid-token` | `generic-token` | `api_key=` is a `HIGH_SIGNAL_NAMES` match, warned on unconditionally by standing decision |

No code change is warranted. This document, plus the newly recorded decision
[the merged precision-contracts decision (Bearer-token row)](../../../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md#folded-records),
is the finding issue #553 requires before any fix — and the finding is that
no fix belongs in this repository.

## Method

Each fixture's exact bytes were reconstructed from
`redact-secret-benchmarks`' own generators
(`fixtures/generated/detector-coverage.mjs`'s `addTwin("bearer-token",
"header", ...)` call and `fixtures/generated/regressions.mjs`'s
`sendgridTwins` construction, both read from `redact-secret-benchmarks`
`origin/main` at `a5bad84`, using the identical seeded `synthetic()`
generator from `fixtures/generated/build.mjs`), then scanned with this
branch's own CLI (`cargo run -p redact-secret-cli --release --bin
redact-secret -- --json`) — not simulated or reasoned about abstractly.

## The three `bearer-token-header` twins

The positive fixture is `Authorization: Bearer ` followed by a 40-byte
synthetic value (`synthetic("coverage:bearer", 40)`). The twin replaces the
byte at index 20 with `!`, a character outside both RFC 6750's `b64token`
alphabet and this detector's own `is_token_char` set
(`crates/secret-scan-core/src/detectors/bearer_token.rs:63`), with the
mutation label "alphabet: one character (!) outside the RFC 6750 b64token
alphabet" — i.e. the fixture's author expected this single substitution to
silence detection across all three contexts (bare, quoted, CRLF-prefixed).

Reproduced input (bare variant):

```
Authorization: Bearer p4vKOA7ksghqYAUBtcEJ!GzFZAmBoFgNL59GtPo8
```

Actual scan result on this branch:

```json
{"detector": "bearer-token", "type": "bearer_token", "confidence": "high",
 "action": "redact", "start": 22, "end": 42}
```

`ascii_run_len` (`bearer_token.rs:167`) correctly stops the token run at the
`!` — byte 20 relative to the value start. But 20 already clears
`MIN_TOKEN_LEN` (16, `bearer_token.rs:20`), so the truncated 20-byte prefix
alone is classified. No single mid-value byte mutation of a 40-byte value can
defeat this detector under its documented 16-byte floor: splitting at index
`k` leaves runs of `k` and `39-k` bytes, and for every `k` in `[16, 23]`
(which includes the fixture's chosen index 20) *both* sides clear 16. This is
not a bug in the alphabet check; it is a direct, static consequence of the
already-shipped grammar the module's own doc comment states: "Requires the
explicit `Bearer` scheme and a token of at least 16 characters... this keeps
arbitrary identifiers out of scope but intentionally misses short development
tokens" (`bearer_token.rs:1-6`). The twin's premise does not hold given that
contract. See the quoted and CRLF variants reproduced identically in
`docs/decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md` (Folded records: Bearer-token row).

**Disposition: fixture encodes an untenable expectation.** The fixture cannot
produce a negative from this detector at the chosen mutation index, given the
already-documented, already-tested `MIN_TOKEN_LEN` contract
(`bearer_token.rs`'s existing `short_development_token_is_ignored` and
`long_invalid_alphabet_terminates_without_a_finding` tests already pin the
boundary this twin crosses). Correcting it — moving the mutation within 16
bytes of either edge of the value so both resulting sides fall under the
floor — is `redact-secret-benchmarks` work, tracked via
`redact-secret/redact-secret-benchmarks#66`, out of this repository's
boundary.

## `sendgrid-regressions--base62-bearer-twin`

Reproduced input:

```
Authorization: Bearer SG.XJoGU7DRtetMBE4IX2dfaC.8lpqpUqs3xrxCAXo5aBbE9Ql2pb37jrK7SwQ8YNRpE
```

(a SendGrid-shaped value with a 42-byte final segment, one byte short of the
documented 43 — `mutation: "length: 42 vs contracted 43"`).

Actual scan result:

```json
{"detector": "bearer-token", "type": "bearer_token", "confidence": "high",
 "action": "redact", "start": 22, "end": 90}
```

`sendgrid.rs`'s own detector correctly declines this value —
`SendgridTokenDetector` requires the exact `ID_LEN`/`SECRET_LEN` (22/43,
`sendgrid.rs:15-20`), and its own doc comment states "a shorter or longer
segment... is an intentional false negative rather than a fuzzy match."
Confirmed independently for this document: `sendgrid.rs`'s existing
`rejects_a_one_byte_short_secret`-class tests already pin this. The file is
"flagged" only because a *different*, independently-correct detector reads
the identical bytes as a generic Bearer credential: `SG.<id>.<42-byte
secret>` is 67 bytes entirely within `is_token_char` (the `.` separator is in
the alphabet), comfortably over 16. `bearer-token` was never validating
against SendGrid's specific two-segment contract, and no existing decision
asks it to.

**Disposition: fixture conflates two independent detectors.** The twin's
premise — "sendgrid-token's own correct decline should leave the whole file
clean" — assumes twin scoring is scoped to the target detector. It is not:
`redact-secret-benchmarks`' `scoreRow` (`benchmarks/lib/lattice.ts:66`)
computes `flagged` from `actual.length > 0` across every detector on the
file. `sendgrid-token`'s behavior is correct and unaffected;
`bearer-token`'s co-detection of a one-byte-short, still highly plausible
credential is also correct and, per the decision above, not a discrimination
failure on its own terms. Correcting the fixture — recognizing this as
expected co-detection, the same way `crates/secret-scan-core/src/detectors/mod.rs`'s
existing `bearer_and_contextual_detectors_emit_competing_candidates` test
already documents `bearer-token`/`generic-token` overlap as expected, not a
bug — is `redact-secret-benchmarks` work, tracked via
`redact-secret/redact-secret-benchmarks#66`.

## `sendgrid-regressions--base62-generic-key-twin`

Reproduced input:

```
api_key=SG.XJoGU7DRtetMBE4IX2dfaC.8lpqpUqs3xrxCAXo5aBbE9Ql2pb37jrK7SwQ8YNRpE
```

Actual scan result:

```json
{"detector": "generic-token", "type": "contextual_secret", "confidence": "high",
 "action": "redact", "start": 8, "end": 76}
```

`api_key=` is one of `generic_token.rs`'s `HIGH_SIGNAL_NAMES`. Per the
**standing** decision
[`2026-09-20-warn-unconditionally-on-high-signal-contextual-names.md`](../../../decisions/2026-09-20-warn-unconditionally-on-high-signal-contextual-names.md),
`assignment_confidence` returns `Some(Confidence::High | Medium)`
unconditionally for every `HIGH_SIGNAL_NAMES` match clearing the shared
length bound and not already excluded by `is_non_secret_reference` — entropy
and length choose only between `High` and `Medium`, never `None`. This
one-byte-short SendGrid value is high-entropy and 67 bytes long, so it lands
at `Confidence::High` / `Action::Redact`, not even the narrower
`Medium`/`Warn` prose tradeoff that decision's rationale focuses on: this is
a mainline true positive for `generic-token`, not an edge case.

This is exactly the scenario issue #553 anticipated: *"If a ... twin is
flagged because that ADR says it should be, then the twin encodes an
expectation the project has already decided against, and the fixture is
wrong — not the detector."* No new decision is needed; the standing one
already governs, and `sendgrid-token`'s own decline (for the identical reason
as the bearer-context case above) is unaffected.

**Disposition: fixture is wrong under a standing decision.** Correcting it is
`redact-secret-benchmarks` work, tracked via
`redact-secret/redact-secret-benchmarks#66`.

## The 9 unresolved differential entries

Issue #553 asks that the 9 unresolved `differential` review-queue entries
(`bearer-token` 6, `sendgrid-token` 3) be worked "as input to the decision
rather than as a separate cleanup." `differential` entries record a
disagreement between `redact-secret` and a peer scanner (gitleaks,
trufflehog) on the same corpus of `bearer-token-header` and
`sendgrid-regressions` cases used above — they are runtime comparison output
recorded in `redact-secret-benchmarks`' `benchmarks/review-ledger.json`, keyed
by content hash, not a separate static fixture set. They were reviewed as
input to the classification above: nothing in the reconstruction and CLI
reproduction above surfaces a distinct signal from the peer-scanner
disagreements. A peer scanner is neither ground truth nor a vote
(`redact-secret-benchmarks`' own `src/pages/workbench/method.ts:10`: "Scanner
disagreements are review evidence... not ground truth or votes"); the
disagreements on this corpus are explained by the same two mechanisms above —
a peer scanner either also flags the near-miss/co-detected value (agreeing
with `redact-secret`'s output) or does not (disagreeing about whether a
one-byte-short or alphabet-broken credential is worth flagging at all, a
question this decision record already answers for `redact-secret`'s own
contract). Marking the review-ledger entries resolved is
`redact-secret-benchmarks` infrastructure, out of this repository's
boundary, and is included in the `redact-secret-benchmarks#66` tracking
above.

## Acceptance criteria disposition

- **`twinFailures` is 0 for all 42 families** — not achievable from this
  repository alone, same disposition as `docs/audits/evidence/552/README.md`.
  All five failures are fixture-side, not detector-side; closing this
  requires the `redact-secret-benchmarks` fixture corrections named above.
- **`differential.unresolvedContractDisagreements` is 0 for all 42** — same
  dependency; the review-ledger entries are `redact-secret-benchmarks`-owned
  state.
- **The 5 fixed-corpus `flagged:1` rows are clean** — same dependency; no
  `redact-secret` code change silences any of them, because none should be
  silenced (`bearer-token` and `generic-token` are both behaving correctly).
- **Every outcome is recorded as a finding; no detector behaviour is changed
  against a standing ADR without a superseding ADR** — done: this document
  plus
  [the merged precision-contracts decision (Bearer-token row)](../../../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md#folded-records)
  (new, for the four `bearer-token`-firing cases) and the standing
  `2026-09-20-warn-unconditionally-on-high-signal-contextual-names.md`
  (cited, for the fifth). No detector behavior changes at all, so no ADR is
  superseded.
- **No true positive lost — `bearer-token`'s legitimate detections still
  fire** — verified: the full `redact-secret` suite (863 passed, up one for
  the new pinning test) and the full workspace suite (28 suites, all green)
  pass unchanged on this branch.

## What this document does not claim

- It does not assert that every `bearer-token` or `sendgrid-token` twin ever
  authored is sound; it accounts for the specific five `flagged:1` fixtures
  #553 names and the differential entries reviewed as input to their
  classification.
- It does not perform the `redact-secret-benchmarks` fixture correction or
  the review-ledger resolution lifecycle; those require changes in
  `redact-secret-benchmarks`, a separate repository and a separate PR,
  tracked via `redact-secret/redact-secret-benchmarks#66`.
- It does not reopen `sendgrid.rs`'s exact-length contract, `bearer-token`'s
  filler/placeholder exclusions, or `generic-token`'s high-signal-name
  tradeoff; all three are unaffected and correct as shipped.

## Authority

This document records evidence and a decision. It does not select a version,
create a tag, publish a package, or authorize any release operation. A
release still requires the explicit approval `AGENTS.md` mandates.
