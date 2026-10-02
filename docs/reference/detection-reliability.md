# Detection reliability

[Documentation home](../README.md) · [Detection coverage and limits](detection.md)

Redact Secret detects the credential grammars and contexts listed in the
[coverage report](../coverage/coverage-report.md). An empty finding list does
not prove that input is secret-free. `supported` in that report means a
finding-type inventory row has positive conformance evidence; it is not a
precision, recall, or detector-count claim.

## DRAFT: v0.1.0 reliability contract

> **DRAFT.** The v0.1.0 candidate source revision is not frozen, so nothing in
> this section is a release claim. It becomes one only when the identity table
> below is filled from the frozen candidate and a reviewed pull request removes
> this banner. Tracking: [#1067](https://github.com/redact-secret/redact-secret/issues/1067),
> epic [#1065](https://github.com/redact-secret/redact-secret/issues/1065),
> reconciling [#200](https://github.com/redact-secret/redact-secret/issues/200).

### Identity this contract will bind

| Item | At freeze | Working value (development, not a claim) |
| --- | --- | --- |
| Candidate source revision | `<frozen candidate SHA>` | audited `57a0dca9478c83e2c59caf9f9d7b467273d7e615` |
| Benchmarks revision that produced the matrix | `<sourceReport.revision of the matrix re-pinned for the candidate>` | `e8f73bfd7241845ef9fb75574a72b135aa777ba6` |
| Product commit that matrix measured | must equal the candidate source revision | `4227160c4dac402d7add53d3f8fe990f693912c1` (Beta.12): **not** the audited source |
| Corpus identity | fixture count and fixture-index digest from the matrix | 5950 fixtures, digest `58f09c3544bf7238dcd076a7c1379681a302adef9ba66ee14dc801f95cfdbbdd` |
| PII qualification candidate | the frozen candidate | Beta.11 core `8b6a5fde52ecb4dfce13f09c7a947062d21483c7`, benchmarks revision `be0fb9f35045bf05e5b999a2c0ed368541f9e963` (bound in [`pii-family-status.json`](../coverage/pii-family-status.json) and gated by `npm run pii-family-status:check`); email, IBAN, phone, payment-card, SSN and the shared PII code changed after it |

A count in this contract is valid only if the matrix's measured product commit
equals the candidate source revision. If it does not, the page must say which
families were measured on an earlier build instead of presenting the count as
current.

### Denominators

Working counts at the audited source (regenerate with
`python3 -B scripts/report-detection-support.py`; method and full tables in the
[#1067 evidence record](../audits/evidence/1067/README.md)):

- 110 shipped credential detectors emit 141 finding types; 6 opt-in PII
  families also ship. These are the denominators.
- The pinned matrix has 173 credential families: 144 stable, 7 provisional,
  5 pending, 17 unsupported. Twenty-one of those families (17 unsupported, 4
  pending) have no shipped detector.
- Counted by weakest listed family, the 110 detectors are 102 stable, 7
  provisional, 1 pending, 0 unsupported, and **0 shipped without a matrix
  family**.
- The 6 PII families are **not in the matrix**
  ([`redact-secret/redact-secret-benchmarks#647`](https://github.com/redact-secret/redact-secret-benchmarks/issues/647)
  tracks moving them in). Their statuses (five `provisional`, US SSN
  `pending`) are stated in the [Opt-in PII table](detection.md#opt-in-pii-availability-is-not-support),
  checked by a gate that fails when a shipped PII family has no status row, and
  were measured on the Beta.11 candidate, not on the audited source.

"144 stable" counts matrix families, not detectors, and no stable family means
a detector finds every credential its provider issues.

### Provisional families carried into the contract

Four `generic:*` families are `provisional` in the pinned matrix and are
carried into the v0.1.0 contract as **provisional**, not stable:
`generic:bearer-token`, `generic:connection-string-password`,
`generic:otp-seed` and `generic:unclassified-assignment-literal`. The reason is
the matrix's own: their protected holdout is `not-run` and needs a pass on a
frozen candidate; the matrix measured Beta.12 and the code behind all four has
changed since. `generic:unclassified-assignment-literal` (detector
`generic-token`) additionally records one exact-span miss and one leaked span
among 76 positive cases. A recheck on current main from public fixtures
reproduces none of the four (every public conformance fixture for the four
detectors matches its declared span exactly), but the recorded case is not
named in the pinned matrix, so its absence is not shown and the family stays
provisional. Per-family result and method:
[#1187 recheck](../audits/evidence/1067/README.md#generic-family-recheck-on-current-main-1187).

### Known false-positive classes

- Synthetic or documentation text that has the shape of a supported
  credential. Detection cannot establish that a value is real.
- A harmless assignment to a credential-like name, classified from context.
- Keyword-gated provider keys without their own marker, which are claimed only
  beside a provider name, host or SDK call, and can fire on that context alone
  for a look-alike value.
- PII: a well-formed identifier under a reviewed field label that is not
  personal (each family's contract lists its named non-sensitive classes).

### Known false-negative classes

- Truncated, unusually short, new, or differently formatted credentials.
- Credentials not in the support matrix, including the 17 `unsupported`
  families listed there with reasons.
- Encoded, wrapped, or split values; input is not generally decoded.
- Contextual assignments whose value is not on the same line as the name, apart
  from the documented multi-line layouts.
- A bare base32 OTP seed, Azure Storage `AccountKey`, and query or property
  passwords in connection strings.
- The generic name `token` alone, which is deliberately ignored.
- Anything not covered by one of the six PII contracts: names, postal
  addresses, dates of birth, free-text personal data, phone numbers outside
  `+1` / NANP, and every national identifier other than a US SSN.

An empty finding list does not show that text is secret-free.

### Per-family status

The per-family status table is the generated
[support matrix](../support-matrix.md) for credential families and the
[Opt-in PII table](detection.md#opt-in-pii-availability-is-not-support) for
PII. The per-detector join of both against the shipped code is
[`detector-support-join.md`](../audits/evidence/1067/detector-support-join.md).
At freeze, that file is regenerated for the candidate and linked from here by
commit permalink, and this section's counts are replaced by its totals.

### What this contract does not claim

- No precision, recall, or accuracy percentage for production traffic.
- No independent validation. Corroboration columns and any scanner comparison
  are project-collected evidence, recorded so a reader can check it, and the
  peer rules they cite often copy one another.
- No support for a PII family merely because it can be activated; activation is
  availability, and only the `pii-v1` status is support.

### Binding at freeze

The code and the ruleset contract are frozen for 0.1.x (see
[Stable contract 1](api-contract.md#stable-contract-1)); only the identity
below is left. The remaining steps, in order:

1. Choose the candidate source revision (the merged `main` commit that the
   release is qualified from) and write its full SHA into the identity table.
2. Re-pin `benchmarks/support-matrix.json` (and its pin files) from
   `redact-secret/redact-secret-benchmarks` for that candidate, after the
   benchmarks follow-ups
   [`redact-secret/redact-secret-benchmarks#647`](https://github.com/redact-secret/redact-secret-benchmarks/issues/647)
   and
   [`redact-secret/redact-secret-benchmarks#648`](https://github.com/redact-secret/redact-secret-benchmarks/issues/648)
   have landed. The matrix's `sourceReport.product.sourceCommit` must equal the
   candidate SHA, and its `sourceReport.revision` goes in the second row.
3. Run `python3 -B scripts/check-detector-family-coverage.py --strict` and the
   report script; both must show 0 shipped-but-unmeasured credential detectors.
4. Replace every working value above with the frozen identity (candidate SHA,
   benchmarks revision, measured product commit, corpus count and digest),
   link the regenerated join by permalink, and record the PII statuses measured
   on the candidate in `pii-family-status.json` (`npm run pii-family-status:check`
   binds them).
5. Remove the DRAFT banner in a reviewed pull request. A release still needs
   explicit approval under the
   [release authority](../../AGENTS.md#release-authority).

The sections below are the earlier bounded assessment and are not the
v0.1.0 contract.

## Measured corpus and artifact identity

The [v4 assessment](https://github.com/redact-secret/redact-secret/blob/de6add470321f40d7b1cb36808d9f4559e6c2e99/assessment/results/complete-v4/summary.json)
(removed from the working tree by [#603](https://github.com/redact-secret/redact-secret/issues/603);
performance results, criteria, and judgement now belong to
`redact-secret-benchmarks`) contains 18 hand-reviewed synthetic whole-input
fixtures, 26 expected findings, and 3 expected-empty fixtures. All five
surfaces (Rust, Python, Node, browser WebAssembly, CLI) produced the same
accuracy result. This is evidence from source
`944341903d5b85686a056d3218f4c33110d7d57b`, not a measurement of any
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
The [safe mismatch records](https://github.com/redact-secret/redact-secret/blob/de6add470321f40d7b1cb36808d9f4559e6c2e99/assessment/results/complete-v4/rust-core/accuracy-corpus-mismatches.json)
contain only metadata and offsets.

The remaining misses are two shortened GitHub tokens, a shortened AWS access
key, and the unsupported contextual setting name `seed`. Their
[dispositions](https://github.com/redact-secret/redact-secret/blob/de6add470321f40d7b1cb36808d9f4559e6c2e99/assessment/results/beta.2/README.md)
remain documented scope and contract choices. Labels were not changed to
improve the score.

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
[corrected release-build run](https://github.com/redact-secret/redact-secret/blob/de6add470321f40d7b1cb36808d9f4559e6c2e99/assessment/results/release-profile/baseline.md)
(removed by [#603](https://github.com/redact-secret/redact-secret/issues/603))
records a separate current-checkout measurement; see its source and artifact
provenance before comparing it with historical accuracy. CLI performance is
check mode; the other surfaces scan and redact. Timing is environment-bound
and is not detection reliability. Performance results, criteria, and
judgement now belong to
[`redact-secret-benchmarks`](https://github.com/redact-secret/redact-secret-benchmarks).

## Historical evidence and reproduction

The earlier [9-fixture audit](../audits/evidence/200/verification-summary.json)
is preserved for its original revision. It does not describe the current v3
corpus. That audit does not claim that those artifacts were published.

Build all real artifacts from one checkout, then run:

```bash
npm run assessment:all -- --python .venv/bin/python --runs 5 --output-dir assessment-output
```

Use a new output directory and follow the [build protocol](../../assessment/README.md#complete-reproducible-evaluation).
Missing, failed, invalid, or identity-mismatched surfaces make the aggregate
incomplete. The Rust performance runner requires `--release`; accuracy labels
and old results remain unchanged.
