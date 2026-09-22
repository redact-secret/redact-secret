# Detection reliability

[Documentation home](../README.md) · [Detection coverage and limits](detection.md)

Redact Secret detects the credential grammars and contexts listed in the
[coverage report](../coverage/coverage-report.md). An empty finding list does
not prove that input is secret-free. `supported` in that report means a
finding-type inventory row has positive conformance evidence; it is not a
precision, recall, or detector-count claim.

## Measured corpus and artifact identity

The committed [v4 assessment](../../assessment/results/complete-v4/summary.json)
contains 18 hand-reviewed synthetic whole-input fixtures, 26 expected findings,
and 3 expected-empty fixtures. All five surfaces (Rust, Python, Node, browser
WebAssembly, CLI) produced the same accuracy result. This is evidence from
source `944341903d5b85686a056d3218f4c33110d7d57b`, not a measurement of any
published package. Accuracy corpus version `3` has SHA-256
`438df062ddde47dcb32ae0aefc4297ed8b8c9e2c3270778c2b1f8809e40bd0dd`.

| Result | Count / denominator | Interpretation |
| --- | ---: | --- |
| Exact true positives | 21 / 26 expected | Detector, type, and source range matched |
| False negatives | 5 / 26 expected | No exact detector/type/range match |
| False positives | 1 / 22 emitted | One emitted range disagreed with the label |
| Policy mismatches | 0 / 21 exact matches | Policy agreed on evaluable matches |
| Expected-empty fixtures with findings | 0 / 3 | No ordinary-negative false positive observed |

The one extra Bearer finding covers the credential value, while the expected
range includes the `Bearer` scheme. This single range disagreement contributes
both one FP and one FN; it is not a false alarm in an ordinary-negative file.
The [safe mismatch records](../../assessment/results/complete-v4/rust-core/accuracy-corpus-mismatches.json)
contain only metadata and offsets.

The remaining misses are two shortened GitHub tokens, a shortened AWS access
key, and the unsupported contextual setting name `seed`. Their
[dispositions](../../assessment/results/beta.2/README.md) remain documented
scope and contract choices. Labels were not changed to improve the score.

These fractions are not precision, recall, or accuracy estimates for production
traffic or arbitrary secrets. The fixtures were selected for reviewable boundary
cases, not sampled from a target population. They do not justify confidence
intervals or a universal detection percentage. Strict prefixes and contextual
exclusions reduce noise while missing short, new, encoded, or unsupported shapes.

## Redaction and performance are separate evidence

The accuracy adapter checks emitted findings; it does not establish a universal
redaction-success rate. CLI additionally compares `--redact` output with the
placeholders implied by its emitted findings. Python checks whole-input and
incremental output equivalence. Neither detects a secret the scanner missed.
The [canonical conformance review](../audits/public-contract-cross-runtime-conformance.md)
owns redaction correctness for supported behavior.

Historical Rust timing in
[`complete`](https://github.com/redact-secret/redact-secret/tree/6cd5f2c58e527396563d86d8caba98104a93a17c/assessment/results/complete)
and
[`complete-v3`](https://github.com/redact-secret/redact-secret/tree/6cd5f2c58e527396563d86d8caba98104a93a17c/assessment/results/complete-v3)
(pruned from the working tree by
[#594](https://github.com/redact-secret/redact-secret/issues/594)) used a
debug build and is unsuitable for optimized cross-runtime comparison. The
[corrected release-build run](../../assessment/results/release-profile/baseline.md)
records a separate current-checkout measurement; see its source and artifact
provenance before comparing it with historical accuracy. CLI performance is
check mode; the other surfaces scan and redact. Timing is environment-bound
and is not detection reliability.

## Historical evidence and reproduction

The earlier [9-fixture audit](../audits/evidence/200/verification-summary.json)
is preserved for its original revision. It does not describe the current v3
corpus. That audit does not claim that those artifacts were published and does
not authorize a release.

Build all real artifacts from one checkout, then run:

```bash
npm run assessment:all -- --python .venv/bin/python --runs 5 --output-dir assessment-output
```

Use a new output directory and follow the [build protocol](../../assessment/README.md#complete-reproducible-evaluation).
Missing, failed, invalid, or identity-mismatched surfaces make the aggregate
incomplete. The Rust performance runner requires `--release`; accuracy labels
and old results remain unchanged.
