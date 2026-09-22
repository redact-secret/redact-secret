---
decision_id: decision-resolve-overlap-precedence-by-resolved-action-severity
status: accepted
scope: workspace
title: Resolve overlap precedence by resolved-action severity
decided_at: 2026-09-19
spec: engine
---

# Resolve overlap precedence by resolved-action severity

## Context

Issue [#450](https://github.com/redact-secret/redact-secret/issues/450)
identified that overlap resolution's ranking
(`crates/secret-scan-core/src/pipeline.rs`, `RankedCandidate::priority`) does
not know what [`Action`] the candidate it selects will eventually resolve to,
because policy runs strictly after overlap resolution in the pipeline
(`detection -> overlap -> policy -> redaction`). Ranking by specificity,
confidence, span width, registration order, and emission order picks the
candidate with the most specific *evidence*, not the one with the strongest
eventual *enforcement outcome*. When a higher-specificity candidate resolves
to a weaker action than an overlapping lower-specificity one, the tool
redacts less than it would have with less evidence — backwards for a tool
whose value is failing closed.

This reproduced concretely with `new_relic_license_key`: it is
[`Specificity::Provider`], which outranks [`Specificity::Structural`] and
[`Specificity::Contextual`] regardless of confidence, but its only emission
path (`crates/secret-scan-core/src/detectors/new_relic.rs`) is a keyword-
cooccurrence heuristic that always reports [`Confidence::Medium`] and is not
in `ALWAYS_REDACT_TYPES`, so [`DefaultPolicy`] warns rather than redacts it.
The conformance corpus already contained the exact failure shape, committed
and passing, without anyone noticing it was a security defect: fixture
`new-relic-license-key-overlap-beats-bearer-token`
(`conformance/fixtures/synchronous-corpus.json`) asserted that
`new_relic_license_key` won an overlap against a `bearer_token` candidate
for `newrelic Authorization: Bearer <value>` — a structural `Bearer`
candidate that always redacts, displaced by a medium-confidence candidate
that only warns, on the strength of specificity alone. This is not issue
[#440](https://github.com/redact-secret/redact-secret/issues/440)'s algorithm
change ([#451](https://github.com/redact-secret/redact-secret/issues/451),
replacing the greedy accept pass with optimal weighted-interval selection):
the two candidates here occupy the same interval, so no disjointness rule
selects both, and the defect is in the ranking objective, not the selection
strategy.

### The survey

A `(type, specificity, confidence) -> action` combination "permits an
inversion" when its specificity claims [`Specificity::Provider`],
[`Specificity::Structural`], or [`Specificity::PrivateKey`]-grade evidence —
which already outranks [`Specificity::Contextual`] and
[`Specificity::Entropy`] unconditionally — but its [`DefaultPolicy`]
classification is confidence-gated (redacts only at
[`Confidence::High`], warns otherwise) rather than always-redact or block.
Auditing every built-in detector
(`docs/coverage/detector-inventory.json`'s `policyClass` field, cross-checked
against each detector's actual `Specificity`/`Confidence` emissions) found
**five** such types, not only `new_relic_license_key`: `twilio_auth_token`,
`twilio_api_key_secret`, `datadog_api_key`, and `datadog_application_key`
share the identical shape — a specific-marker path at
[`Confidence::High`] and a bare keyword-cooccurrence path at
[`Confidence::Medium`], both [`Specificity::Provider`]. The corpus already
had a `-overlap-beats-bearer-token` fixture for all five, and all five
mismatched the same way (see Consequences). Every other declared type at
these three specificity tiers is already always-redact or block, and no
built-in detector emits [`Specificity::Entropy`] (the omitted-specificity
default exists only for third-party/custom detectors).

### These five types are deliberately confidence-gated, and stay that way

Unlike a gap left by oversight, each of the five is confidence-gated by a
prior, reasoned decision that this change does not revisit:
`decision-freeze-new-relic-user-api-key-license-key-grammar`,
`decision-freeze-twilio-auth-token-api-key-secret-grammar`, and
`decision-freeze-datadog-api-application-key-grammar` all explicitly weigh
and accept the false-positive risk of a benign opaque value (a commit SHA,
a digest, an unrelated hex blob) sharing a line with a bare vendor keyword,
and choose to warn rather than redact at that confidence tier *precisely to
avoid escalating that risk to redaction*. Adding these five types to
`ALWAYS_REDACT_TYPES` would silently overturn that reasoning for every input
where they are the *only* candidate — not just the overlap case issue #450
reported — trading a false-negative fix for a false-positive regression
nobody asked to make. This decision does not touch `ALWAYS_REDACT_TYPES` or
any detector's confidence classification.

## Decision

**Resolved-action severity participates in overlap precedence, as the first,
dominant key**, ahead of specificity:

```rust
fn priority(&self, other: &Self) -> Ordering {
    other.resolved_severity.cmp(&self.resolved_severity)
        .then_with(|| other.specificity.cmp(&self.specificity))
        .then_with(|| other.confidence.cmp(&self.confidence))
        .then_with(|| self.range.len().cmp(&other.range.len()))
        .then_with(|| self.detector_order.cmp(&other.detector_order))
        .then_with(|| self.candidate_order.cmp(&other.candidate_order))
}
```

`resolved_severity` is [`Action::overlap_resolution_severity`]
(`Block(3) > Redact(2) > Warn(1) > Allow(0)`, crate-internal and not a public
`Action` ordering) applied to `crate::policy::default_action_for(type_name,
confidence)` — the same classification [`DefaultPolicy`] uses, extracted so
`crate::pipeline` can call it directly on a candidate's already-known
metadata instead of constructing a placeholder [`DetectedFinding`] just to
read an action back out of one. A candidate that would resolve to a weaker
action can no longer displace an overlapping candidate that would resolve to
a stricter one, regardless of specificity. When two candidates would resolve
the *same* severity — the common case, and every case among today's built-in
detectors that does not involve one of the five confidence-gated types above
— severity ties and specificity decides exactly as before, so this key
changes no built-in detector's output except where two candidates already
disagreed on both specificity and severity.

### Layer boundary: a fixed internal classification, never the active `Policy`

Severity comes from the crate's own fixed default classification, **not**
the caller's active [`Policy`]. This is forced by where overlap resolution
sits in the pipeline, not merely preferred:

- `run_detector_pipeline` does not receive a `Policy` at all — `scan` and its
  siblings apply one only after overlap resolution has already produced the
  final [`DetectedFinding`] set. Threading the active policy into ranking
  would mean evaluating it against *every* ranked candidate, including ones
  about to be rejected, not just the survivors it is documented to see.
- [`PolicyContext`] carries a finding's index and the whole-session finding
  count, neither of which exists until overlap resolution has finished and
  finding IDs are assigned. For an incremental session in particular,
  `ARCHITECTURE.md` guarantees policy is "evaluated exactly once after a
  finding becomes final" — evaluating it earlier, speculatively, to rank a
  candidate that might not survive, would break that guarantee outright.
- A custom `Policy` can be an arbitrary closure. Calling it once per
  candidate during ranking — rather than once per final finding, as
  documented — would be a different, larger contract than the one
  `ARCHITECTURE.md`'s "Detection and policy separation" section describes.

Consulting a fixed internal notion of severity instead of the active policy
keeps detection and policy independent exactly as documented: detection (and
the overlap resolution built on it) answers what a range appears to be and
how much that should matter, entirely from immutable candidate metadata;
policy independently chooses `redact`/`block`/`warn`/`allow` from the
finalized finding. **Consequence:** which candidate wins an overlap is
identical under every [`Policy`] for the same input — a stricter or weaker
consumer policy changes the *enforcement* of the winning candidate, never
*which* candidate wins. A consumer whose custom policy inverts the default
classification (e.g. treats a `Provider`-specificity type as low-priority)
is not helped by this key, which is a fixed, best-effort default rather than
a per-policy-aware ranking; that tradeoff is accepted because a per-policy
ranking is not implementable at this pipeline stage (above) without
weakening the incremental "exactly once, after final" guarantee.

### No `ALWAYS_REDACT_TYPES` change, and no per-type guard

The ranking fix alone closes every inversion the survey found, for the exact
reason the survey exists: it is a property of the *mechanism*
(`RankedCandidate::priority`), not of any per-type declaration, so it
protects every current and future detector uniformly, including the five
confidence-gated types this decision deliberately leaves unchanged, without
reopening their false-positive tradeoff. Consequently, no static per-type
guard (for example, "no `Provider`-specificity type may be declared
confidence-gated") is added: such a guard would be both unnecessary
(the ranking mechanism already makes the outcome it would police
impossible) and actively wrong (it would forbid the five legitimate,
deliberately confidence-gated types this decision preserves, and any future
one like them). The regression coverage lives instead in
`crates/secret-scan-core/tests/pipeline.rs`, as synthetic-candidate unit
tests over the general property — `resolved_action_severity_outranks_specificity`
and `a_blocking_candidate_outranks_a_higher_specificity_non_blocking_one`
— that would fail if `priority` ever regressed to specificity-first
ordering, for *any* type, without depending on which types happen to be
declared confidence-gated today.

### Determinism

`resolved_severity` is a pure function of a candidate's already-validated
`type_name` and `confidence`, computed once per candidate in
`validate_candidate` alongside its other ranking keys. It adds no new source
of nondeterminism: `detector_order` and `candidate_order` remain the final,
already-unique tie breakers, so the ordering stays total.

## Consequences

- `ARCHITECTURE.md`'s "Canonical processing pipeline" section is updated to
  list resolved-action severity as the first ranking key, and its "Detection
  and policy separation" section notes that overlap resolution consults a
  fixed internal classification rather than the active policy.
- `conformance/fixtures/synchronous-corpus.json` needed exactly three
  fixtures corrected, each a rename plus an `expected`/`note` update, not a
  full regeneration: `twilio-auth-token-overlap-beats-bearer-token`,
  `twilio-api-key-secret-overlap-beats-bearer-token`, and
  `new-relic-license-key-overlap-beats-bearer-token` become
  `bearer-token-overlap-beats-twilio-auth-token`,
  `-twilio-api-key-secret`, and `-new-relic-license-key` respectively, each
  now expecting the `bearer_token` winner their `note` explains. A
  script-driven diff of the full corpus against `scan`'s actual output
  (every fixture, not just these three) confirmed these are the *only*
  fixtures whose expected winner changes — consistent with "no built-in
  detector's output changes except where severity and specificity already
  disagreed" above. Renaming each fixture's `id` meant regenerating
  `conformance/fixtures/common-profile-expectations.json`
  (`REDACT_SECRET_UPDATE_COMMON_EXPECTATIONS=1`); its own three touched rows
  are otherwise byte-identical, confirming the `common` detector profile
  (which excludes these three provider detectors) was never affected by the
  bug. Each rename also cost that type its own `overlap`-kind coverage
  evidence (`docs/coverage/`'s generators attribute evidence by
  `expected[].type`, not the fixture's nominal `detector`), so three new
  fixtures — `twilio-auth-token-overlap-generic-context`,
  `twilio-api-key-secret-overlap-generic-context`, and
  `new-relic-license-key-overlap-generic-context` — restore it with a
  same-severity contextual competitor (a low-entropy `api_key=` assignment,
  medium confidence either way), so specificity alone decides and each type
  still demonstrates winning an overlap on its own evidence.
  `docs/coverage/inventory-report.json`, `coverage-declarations.json`, and
  `coverage-report.md` are regenerated from the corrected corpus; none
  reports a new `unresolved` or `pending` state.
- `crates/secret-scan-core/tests/detectors_conformance.rs` gains
  `bearer_token_overlap_winner_redacts_the_new_relic_license_key_shape`,
  asserting through `scan_and_redact` that the exact shape the issue
  reported (`newrelic Authorization: Bearer <value>`) now redacts instead of
  leaving the value in plaintext output — the conformance case issue #450's
  acceptance criteria ask for, using the corpus's own pre-existing
  reproduction rather than a newly invented one.
- This is a narrow behavior change: it affects only inputs where a
  confidence-gated `Provider`-specificity candidate (the five types above)
  overlaps another candidate that would resolve a stricter action. No
  standalone (non-overlapping) detection changes action, and no new type
  joins `ALWAYS_REDACT_TYPES`; `CHANGELOG.md` records this precisely so it
  is not mistaken for the broader change of reclassifying those five types.

[`Action`]: ../../crates/secret-scan-core/src/types.rs
[`Action::overlap_resolution_severity`]: ../../crates/secret-scan-core/src/types.rs
[`Specificity::Provider`]: ../../crates/secret-scan-core/src/types.rs
[`Specificity::Structural`]: ../../crates/secret-scan-core/src/types.rs
[`Specificity::PrivateKey`]: ../../crates/secret-scan-core/src/types.rs
[`Specificity::Contextual`]: ../../crates/secret-scan-core/src/types.rs
[`Specificity::Entropy`]: ../../crates/secret-scan-core/src/types.rs
[`Confidence::High`]: ../../crates/secret-scan-core/src/types.rs
[`Confidence::Medium`]: ../../crates/secret-scan-core/src/types.rs
[`DefaultPolicy`]: ../../crates/secret-scan-core/src/policy.rs
[`Policy`]: ../../crates/secret-scan-core/src/types.rs
[`PolicyContext`]: ../../crates/secret-scan-core/src/types.rs
[`DetectedFinding`]: ../../crates/secret-scan-core/src/types.rs
