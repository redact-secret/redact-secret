---
decision_id: decision-freeze-the-shadow-evidence-score-and-confidence-contract
status: accepted
scope: workspace
title: Freeze the shadow evidence score and confidence contract
decided_at: 2026-09-25
spec: engine
---

# Freeze the shadow evidence score and confidence contract

## Context

Epic [#767](https://github.com/redact-secret/redact-secret/issues/767) adds an
explainable statistical evidence layer in beta.9. It combines several weak
signals (randomness, lexical shape, context, validation, negative evidence)
into one internal result for ambiguous candidates, starting with
`generic-token` ([#771](https://github.com/redact-secret/redact-secret/issues/771)).
Issue [#768](https://github.com/redact-secret/redact-secret/issues/768) asks
for the contract to be frozen before feature extraction
([#769](https://github.com/redact-secret/redact-secret/issues/769)),
aggregation ([#770](https://github.com/redact-secret/redact-secret/issues/770))
and the scoring artifact ([#798](https://github.com/redact-secret/redact-secret/issues/798))
are built on it.

Today a detector emits a `Candidate` with a `Confidence` (`low < medium <
high`), an optional `Specificity` (`entropy < contextual < structural <
provider < private-key`), a range, and internal signal labels that never
reach public results. Overlap resolution ranks candidates by resolved-action
severity, specificity, confidence, span width and registration and emission
order
([`decision-resolve-overlap-precedence-by-resolved-action-severity`](2026-09-19-resolve-overlap-precedence-by-resolved-action-severity.md),
[`decision-select-optimal-disjoint-candidates-by-total-evidence-weight`](2026-09-19-select-optimal-disjoint-candidates-by-total-evidence-weight.md)).
`generic-token` already reads Shannon entropy as `f64` against fixed
thresholds (`HIGH_ENTROPY_THRESHOLD`, `AMBIGUOUS_ENTROPY_THRESHOLD`). The
architecture already says entropy supports a decision and is never enough on
its own for aggressive classification.

The following were fixed product decisions for beta.9 before this record,
and this record keeps them:

- beta.9 exposes no probability or raw evidence score through the public API;
- beta.9 does not let the scorer change default detection, `Confidence`, or
  policy actions;
- the public `Finding` contract does not change;
- calibration detail may exist in maintainer-local benchmark evidence and is
  not a public security API.

Redact Secret is open source, so an attacker can read the scorer. This record
assumes they do.

## Decision

### 1. Evidence score and calibrated probability are different things

- An **evidence score** is an internal, unitless, ordinal integer that the
  product computes deterministically from one candidate. A larger score means
  more evidence that the candidate is a credential. It is not a probability
  and is never called one, in code, documentation, diagnostics or benchmark
  output.
- A **calibrated probability estimate** is a benchmark-side research
  artifact. It maps scores to observed frequencies on one stated, stratified
  population
  ([redact-secret-benchmarks#255](https://github.com/redact-secret/redact-secret-benchmarks/issues/255)).
  It is only valid for that population, and the product never computes,
  ships or reports it. A value that has not been calibrated is never labelled
  a probability.

### 2. The shadow evidence result

For a candidate the scorer is allowed to evaluate (see section 5), it
produces one **shadow evidence result**:

- the capped contribution of each evidence group (section 3), as integers;
- the evidence score, the sum of those group contributions;
- a **shadow band**, one of `none < low < medium < high`;
- safe reason codes (section 8).

A shadow band means "the scorer would propose this `Confidence`". It does not
mean "the probability that this is a secret is at least p". Band cut-offs
are integer thresholds that strictly increase (`t_low < t_medium < t_high`).
The reviewed scoring artifact fixes their values (#798), and benchmark
calibration derives them (benchmarks#255). The band is a separate internal
type, not `Confidence`, so it cannot reach a `Finding` by accident.

In beta.9 the shadow result is compared with the legacy result and nothing
more. It never changes a candidate's `Confidence`, `Specificity`, range,
type, obfuscation flag, overlap weight or resolved action, or any finding,
placeholder or policy input. Beta.9 can ship with the whole scorer
shadow-only, and that is the expected outcome.

### 3. Evidence groups and the anti-double-counting rule

Each signal belongs to exactly one group:

| Group | Direction | Examples |
| --- | --- | --- |
| `randomness` | positive | Shannon entropy, min-entropy, information bits, repetition and periodicity |
| `lexical` | positive | length, alphabet and class distribution, prefix or segment shape |
| `contextual` | positive | credential-bearing name, header, or surrounding syntax |
| `validation` | positive | checksum, parser or known structural validation |
| `negative` | negative | placeholders, references, reserved and documentation shapes, known benign structures, each under an explicit exclusion contract (section 6) |

Signals in the same group measure related properties, so they are never
summed linearly:

- **Within a group**, sort the non-negative integer signal contributions in
  descending order. The group contribution is `min(cap_g, c1 + (c2 >> 1) +
  (c3 >> 2) + ...)`: each further signal counts half as much as the one
  before it, and the group can never exceed its cap `cap_g`. Many correlated
  randomness measurements are worth at most one capped randomness
  contribution.
- **Across groups**, positive group contributions add, and the `negative`
  group's contribution is subtracted. The score saturates at zero.
- **No single positive group reaches `high` on its own**: every `cap_g <
  t_high`.
- **`randomness` and `lexical` together do not reach `high`**: `cap_randomness
  + cap_lexical < t_high`. A `high` shadow band needs `contextual` or
  `validation` evidence. This carries forward the existing rule that entropy
  alone never justifies aggressive classification.

The exact caps and weights belong to the reviewed scoring artifact (#798).
These inequalities belong to this contract, and #770 tests them.

### 4. Monotonicity

For the scorer, with every other input held fixed:

- raising any positive signal never lowers the score;
- raising the negative contribution never raises the score;
- adding a signal to a group, or a positive group to a candidate, never lowers
  the score;
- the band is a non-decreasing step function of the score.

#770 adds property tests for each of these. A scoring artifact that breaks
one of them is invalid, whatever its benchmark results.

### 5. Specificity authority and overlap resolution

The existing specificity ordering stays authoritative:

- **`private-key`, `provider`, `structural`**: the scorer is not consulted.
  The shadow result records `authority: deterministic` and a band equal to the
  legacy `Confidence`. Statistical evidence cannot lower these candidates in
  shadow or in any later promotion, whatever the input's entropy, repetition
  or surroundings.
- **`contextual`, `entropy`** (including an unset specificity): the scorer
  may compute a band. In beta.9 that band is only recorded.
- **Statistical evidence never turns a deterministic positive into a
  non-finding in beta.9.** Once a detector has emitted a candidate, no shadow
  result, however low, removes it, narrows it, or changes its action.
  Allowing a later release to do that needs a new decision, and that
  decision cannot weaken this record's section 5 rules for
  `private-key`/`provider`/`structural`.

Overlap resolution stays as it is. `EvidenceWeight` and resolved-action
severity use the legacy keys only, and the shadow band is not one of them.
The scorer evaluates each candidate independently, from the candidate's own
range and bounded local context in the scan copy. So a candidate's shadow
result does not depend on which other candidates exist or on how the input
was split into incremental units, and whole-input and incremental paths give
equal shadow results. Shadow results are kept only for the candidates
overlap resolution selects. A losing candidate's result is thrown away, so
shadow scoring cannot bring a suppressed candidate back or re-rank one.

### 6. Negative evidence is structurally bounded

A negative signal applies only when the **whole** candidate value matches a
named, reviewed exclusion grammar. Examples are a value fully delimited by
`{{` and `}}`
([`decision-exclude-fully-delimited-template-references`](2026-09-15-exclude-fully-delimited-template-references.md)),
a complete environment or command-substitution reference, or a value built
entirely from the reviewed placeholder vocabulary. A prefix, suffix,
substring, edit-distance or other fuzzy resemblance to a placeholder or
reference is never negative evidence. Negative evidence may only lower the
shadow band of a `contextual` or `entropy` candidate, and in beta.9 it
suppresses nothing (section 5). An attacker who wraps real secret material
in placeholder-looking text therefore gains nothing from the scorer.

### 7. Deterministic numeric behavior

Every host (native Rust, the Node native addon, WebAssembly, Python) runs the
same Rust core, but a host's `libm` can round transcendental functions such
as `log2` differently in the last place. The scorer therefore uses **integer
fixed-point arithmetic only**:

- no `f32`/`f64` value and no floating-point `libm` call appears between
  feature extraction, score and band;
- a feature that needs a logarithm (entropy, min-entropy, information bits)
  computes it from integer symbol counts using a committed integer lookup
  table or an exact integer algorithm, at a fixed-point scale the scoring
  artifact declares;
- arithmetic saturates rather than wraps, and division rounds toward zero;
- the scorer bounds the input length it reads, and states that bound in the
  artifact.

The existing `f64` `shannon_entropy` and the legacy `generic-token`
thresholds do not change, because they are legacy detection behavior. #769
"reuses" Shannon entropy in the sense of the same definition over the same
symbol counts, computed in fixed point for the scorer. The legacy `f64`
value never enters the score. Cross-runtime qualification
([#772](https://github.com/redact-secret/redact-secret/issues/772)) requires
identical integer scores and bands across hosts for the conformance corpus.

### 8. Safe maintainer diagnostics

Maintainers may inspect these, in tests and in the maintainer-local
evaluation path #798 defines: signal identifiers from a closed, static set;
group identifiers; integer group contributions, score and band; the legacy
`Confidence` and specificity; candidate type, byte length and range; and
reason codes.

Maintainers may not inspect these, anywhere: matched bytes or any substring
of them, any character-class run that reconstructs them, or any hash or
digest of a matched value (a short or low-entropy secret can be recovered by
brute force from its hash). Shadow diagnostics never appear in a `Finding`,
an error, a log, a placeholder or a policy callback. There is no telemetry.
The core declares no Cargo features (`scripts/check-rust-workspace.py`,
check 8), so whatever export mechanism #798 chooses cannot be a
feature-gated public API of the published core.

### 9. No public score surface

No public Rust item or field in the core crate or in any binding, and no
public JavaScript, Python or CLI field, carries a score, probability,
threshold, weight, band or contribution in beta.9. Two checks enforce this:
`core-public-api` (check 6 of `scripts/check-rust-workspace.py`), and check 10
of the same script, which rejects any plainly `pub` name containing `score`,
`probabilit` or `calibrat` in `crates/secret-scan-core/src` or
`bindings/*/src`. Scorer items are `pub(crate)` or narrower.

### 10. Versioning and invalidation

The shadow scorer's behavior is observable, versioned behavior. The
scoring artifact (#798) carries one model identity that covers feature
semantics, group membership, caps, weights, band thresholds, fixed-point
scale and rounding, and the scorer's input bound. Changing any of them
creates a new model identity. A new identity makes stale every piece of
qualification, calibration and holdout evidence keyed to the old one, and
it needs a new candidate identity. The benchmark side enforces this for
tuning and holdout in
[redact-secret-benchmarks#256](https://github.com/redact-secret/redact-secret-benchmarks/issues/256):
a tuning manifest binds the model identity, and holdout evidence for one
identity is never carried over to another.

### 11. Forbidden from public benchmark projection

Public benchmark output never contains:

- per-candidate raw scores or feature vectors;
- band thresholds, caps or weights as fitted values;
- per-feature or per-group contributions;
- successful score-evasion recipes or other mutation detail aimed at a
  bypass
  ([redact-secret-benchmarks#289](https://github.com/redact-secret/redact-secret-benchmarks/issues/289)).

Public projection may report aggregate security outcomes per stratum, plus
identities and hashes. The scorer's source code is public anyway. The point
of this rule is that the benchmark does not publish a ready-made map of the
decision boundary. Security never depends on these values staying secret.

### 12. Examples

The shapes below are described, not quoted. Every concrete value used in
tests follows the synthetic-fixture rules.

| Evidence | Candidate shape | Legacy result | Shadow result (beta.9) |
| --- | --- | --- | --- |
| Provider | `ghp_` followed by the contracted 36-character body | `provider`, `high`, redact | scorer not consulted; `authority: deterministic`, band `high`. Repeating characters inside the body does not change this. |
| Private key | a complete PEM private-key block | `private-key`, `high`, block | scorer not consulted; band `high` |
| Structural | `Authorization: Bearer <token>`, or a connection URL's password | `structural`, per the detector | scorer not consulted; band equals the legacy `Confidence` |
| Contextual | `API_KEY=` followed by a random-looking 32-character value | `contextual`, `high`, redact | `contextual` and `randomness` contribute. The band may reach `high` because `contextual` is present. The legacy result stands either way. |
| Statistical only | a bare, random-looking value with no credential-bearing context | legacy `generic-token` result, if any | only `randomness` and `lexical` contribute. By the cap rule the band is at most `medium`, and it is only recorded. |
| Correlated signals | a value that scores high on entropy, min-entropy and class balance together | unchanged | the `randomness` group is capped once. Stacking correlated signals cannot produce `high`. |
| Negative, full match | `API_KEY={{ secrets.API_KEY }}` (a fully delimited template reference) | already excluded by the legacy detector | if the scorer sees it, `negative` applies because the full grammar matches |
| Negative, lookalike | `API_KEY=` followed by `EXAMPLE` and then real-looking random material | legacy result unchanged | no negative evidence, because only part of the value resembles a placeholder. The band is computed from positive groups alone. |

## Consequences

- #769 implements features to section 7, #770 implements aggregation to
  sections 3, 4 and 6, #798 records caps, weights, thresholds and the model
  identity to section 10, and #771 records shadow results to sections 2, 5
  and 8. #772 checks cross-runtime equality under section 7.
- The public API, the `Finding` schema, the conformance expectations and the
  default policy do not change. Check 10 of
  `scripts/check-rust-workspace.py` makes a public score-named item a CI
  failure.
- The benchmark repository applies the same identity and projection rules
  to tuning and holdout (benchmarks#254, #255, #256, #289), and the beta.9
  qualification record binds them together
  ([redact-secret-benchmarks#282](https://github.com/redact-secret/redact-secret-benchmarks/issues/282)).
- Integer fixed-point arithmetic makes feature code more work than calling
  `f64::log2`. That is the price of exact cross-runtime equality. If a later
  change moves any part of the scorer to floating point, it needs a new
  decision.
- Trade-offs. The cap rules mean a candidate whose only evidence is a very
  random-looking body cannot reach a `high` shadow band, which is a possible
  false-negative cost if a future release promotes the scorer. Section 6
  gives up any shadow benefit from fuzzy placeholder resemblance, which is a
  possible false-positive cost, so that negative evidence cannot become a
  bypass. Neither trade-off changes shipped behavior in beta.9.
