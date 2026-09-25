# Engine

Rules governing the shared Rust core's detection pipeline, plugin/profile contract, and cross-language binding architecture.

> Generated for [issue #597](https://github.com/redact-secret/redact-secret/issues/597) (DS6a). Each rule
> below states current behavior in the present tense and links the ADR
> (`docs/decisions/`) that decided it. An ADR records why and when; this file
> records what is true now. Per
> [`decision-decide-artifact-taxonomy-spec-routing-and-evidence-placement`](../decisions/2026-09-22-decide-artifact-taxonomy-spec-routing-and-evidence-placement.md),
> a decision that applies an existing policy to one more provider family or
> one more instance is a row here plus its supporting evidence, not a new
> ADR.

## Rules

| Rule | Governing ADR |
| --- | --- |
| One Rust core crate is shared by every language binding (JavaScript, Python, CLI) through a monorepo layout. | [Adopt a Rust-core monorepo](../decisions/2026-09-09-adopt-rust-core-monorepo.md) |
| Each language binding is a thin host adapter over the shared Rust core, not an independent reimplementation. | [Define runtime bindings](../decisions/2026-09-09-define-runtime-bindings.md) |
| Every binding is held to the same conformance corpus so detection behavior does not drift by language. | [Govern cross-language conformance](../decisions/2026-09-09-govern-cross-language-conformance.md) |
| Detector selection is scoped by a profile/pack contract (for example `full`, `common`), not by ad hoc per-caller filtering. | [Define the detector profile and pack contract](../decisions/2026-09-18-define-detector-profile-and-pack-contract.md) |
| Whole-input scan and redact operations carry an explicit default bound on buffered bytes and finding count, overridable by the caller. | [Bound whole-input operations by default](../decisions/2026-09-19-bound-whole-input-operations-by-default.md) |
| An organization may register additional detectors through a declarative ruleset contract; this narrows, but does not replace, the profile/pack contract's Non-goal on dynamic plugin loading. | [Define the declarative detector ruleset contract](../decisions/2026-09-19-define-declarative-detector-ruleset-contract.md) |
| Default-ignorable and other invisible Unicode code points are normalized out of the input before detection runs, using a generated table pinned to a fixed UCD version. | [Normalize invisible characters before detection](../decisions/2026-09-19-normalize-invisible-characters-before-detection.md) |
| When candidate findings overlap, the one with the more severe resolved policy action wins, not first-match or longest-match order. | [Resolve overlap precedence by resolved-action severity](../decisions/2026-09-19-resolve-overlap-precedence-by-resolved-action-severity.md) |
| Among overlapping candidates, the disjoint subset with the greatest total evidence weight is selected. | [Select optimal disjoint candidates by total evidence weight](../decisions/2026-09-19-select-optimal-disjoint-candidates-by-total-evidence-weight.md) |
| Base64, percent-encoded, and backslash-escaped input is not decoded before detection; decoding stays out of scope. | [Defer encoded-input decoding out of scope, with reasoning](../decisions/2026-09-20-defer-encoded-input-decoding.md) |

| The beta.9 evidence scorer is shadow-only. It computes an internal integer evidence score and a shadow band (`none < low < medium < high`) for `contextual` and `entropy` candidates, and neither value is ever a probability. It never changes a candidate's `Confidence`, specificity, range, overlap weight or action, never removes a deterministic positive, and is not consulted for `private-key`, `provider` or `structural` candidates. | [Freeze the shadow evidence score and confidence contract](../decisions/2026-09-25-freeze-the-shadow-evidence-score-and-confidence-contract.md) |
| Evidence signals belong to five groups (`randomness`, `lexical`, `contextual`, `validation`, `negative`). A group's signals combine with halving diminishing returns under a cap, no single group and not `randomness` plus `lexical` can reach `high`, and negative evidence applies only when the whole value matches a reviewed exclusion grammar. The scorer is monotone in its signals. | [Freeze the shadow evidence score and confidence contract](../decisions/2026-09-25-freeze-the-shadow-evidence-score-and-confidence-contract.md) |
| Scorer arithmetic from features to band is integer fixed-point with no floating point or `libm` calls, so every host produces identical scores and bands. Maintainer diagnostics carry signal and group identifiers and integer values only, never matched bytes or hashes of them. No public item, field or benchmark projection carries a score, probability, threshold, weight or contribution (`scripts/check-rust-workspace.py` check 10), and changing the scoring model's identity invalidates evidence keyed to the old one. | [Freeze the shadow evidence score and confidence contract](../decisions/2026-09-25-freeze-the-shadow-evidence-score-and-confidence-contract.md) |
