# Evidence and gates

Rules governing CI gates, evaluation protocol, and how evidence (SAST, benchmarks, twin fixtures, support-matrix drift) blocks or unblocks a release.

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
| OpenGrep SAST scanning is a required, SARIF-integrated CI gate. | [Enforce OpenGrep in CI as a required, SARIF-integrated gate](../decisions/2026-09-10-enforce-opengrep-in-ci-as-a-required-gate.md) |
| OpenGrep runs at a pinned version against a reviewed baseline, not a floating version. | [Pin OpenGrep and establish a reviewed SAST baseline](../decisions/2026-09-10-pin-opengrep-and-establish-a-reviewed-sast-baseline.md) |
| Every binding is evaluated against the same cross-language protocol before a behavior change is accepted. | [Define the cross-language evaluation protocol](../decisions/2026-09-12-define-cross-language-evaluation-protocol.md) |
| JavaScript performance is measured by an external harness, not by in-repo microbenchmarks alone. | [Measure JavaScript performance externally](../decisions/2026-09-12-measure-javascript-performance-externally.md) |
| A beta.5-class release is gated on measured precision gains plus preservation of existing true positives. | [Gate beta.5 on precision gains and positive preservation](../decisions/2026-09-18-gate-beta5-on-precision-gains-and-positive-preservation.md) |
| A regression found by `redact-secret-benchmarks` is promoted into a product fix through a defined lifecycle, not fixed ad hoc from a single benchmark run. | [Govern benchmark-originated product regressions](../decisions/2026-09-18-govern-benchmark-regression-promotion.md) |
| A benign twin fixture that looks like a real credential is rewritten to be unmistakably synthetic, never a plausible real secret. | [Resolve real-looking twin fixtures as unmistakably synthetic](../decisions/2026-09-18-resolve-real-looking-twin-fixtures-as-unmistakably-synthetic.md) |
| A release is blocked on support-matrix drift unless the drift is explicitly acknowledged and overridden. | [Gate release qualification on support-matrix drift, with recorded acknowledgement to override](../decisions/2026-09-21-gate-releases-on-support-matrix-drift.md) |
| Every committed document or generated file has exactly one taxonomy kind (live contract, generated, final evidence, iterative log, settled-record detail, or release record), which fixes where it lives. | [Decide the artifact taxonomy, spec routing, and evidence placement](../decisions/2026-09-22-decide-artifact-taxonomy-spec-routing-and-evidence-placement.md) |
| Performance results, RC acceptance criteria, and pass/fail judgement live in `redact-secret-benchmarks`, not committed in this repository. | [Move performance results, criteria, and judgement to redact-secret-benchmarks](../decisions/2026-09-22-move-performance-results-criteria-and-judgement-to-benchmarks.md) |

