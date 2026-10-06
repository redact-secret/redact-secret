# Detection reliability

[Documentation home](../README.md) · [Detection coverage and limits](detection.md)

Redact Secret detects the credential grammars and contexts listed in the
[coverage report](../coverage/coverage-report.md). An empty finding list does
not prove that input is secret-free. `supported` in that report means a
finding-type inventory row has positive conformance evidence; it is not a
precision, recall, or detector-count claim.

## v0.1.0 reliability contract

> **Bound to the Beta.13 candidate; not yet a release claim.** The identity,
> denominators and per-family counts below are bound to the exact candidate and
> benchmarks revision in the identity table. Nothing here approves a release;
> the [release authority](../../AGENTS.md#release-authority) still applies.
> Tracking: [#1067](https://github.com/redact-secret/redact-secret/issues/1067),
> epic [#1065](https://github.com/redact-secret/redact-secret/issues/1065),
> reconciling [#200](https://github.com/redact-secret/redact-secret/issues/200).
>
> **Still pending, and not claimed:**
>
> - The US SSN custodian run
>   [`redact-secret/redact-secret-benchmarks#667`](https://github.com/redact-secret/redact-secret-benchmarks/issues/667):
>   a new corpus and one protected run on the Beta.13 candidate. Until it is
>   recorded, `pii:us:ssn` stays `pending`.
> - The protected holdout of the four `generic:*` families below, which the
>   matrix records as `not-run (requires pass on frozen candidate)`. They stay
>   `provisional`.
> - The performance evaluation against the final release source commit, which
>   the owner dispatches. No performance, memory or size claim is made here.
> - PII re-qualification. The PII statuses are the Beta.11 qualification, not
>   re-qualified on this candidate.
> - Owner approval of the release.

### Identity this contract binds

| Item | Value |
| --- | --- |
| Candidate source revision (the commit the matrix measured) | `fe6e9234d40e7d5964de27d00d33544f9c621dbf` (`0.1.0-beta.13`) |
| Benchmarks revision that produced the matrix | `573e128863e0543133e5ccbd513216d19513b7da` (`sourceReport.revision`; also `benchmarks/pin-source.json`) |
| Product commit that matrix measured | `fe6e9234d40e7d5964de27d00d33544f9c621dbf`: equals the candidate source revision |
| Candidate artifacts | `@redact-secret/core` tarball SHA-256 `8e281e2932b245c8d238f52076c08e6c00859edafdb3e1e202500bc176a73cec`; Node addon (`darwin-arm64`) `d84e31859c72fd046810bb3370df0e61376f5266969ec86b4bd9837437409083`; WebAssembly `f19919458494de3c7210edae7099a47f380191debc956618a37963fc9ef5e1fb` |
| Measurement | formal candidate run, full suite (5950 of 5950 fixtures), clean source, no failures; scanner `trufflehog` 3.97.4 |
| Corpus identity | 5950 fixtures, digest `58f09c3544bf7238dcd076a7c1379681a302adef9ba66ee14dc801f95cfdbbdd` |
| PII qualification | Beta.11 core `8b6a5fde52ecb4dfce13f09c7a947062d21483c7`, benchmarks revision `be0fb9f35045bf05e5b999a2c0ed368541f9e963`, state `not-requalified` (read from the matrix `piiQualification`, bound in [`pii-family-status.json`](../coverage/pii-family-status.json), gated by `npm run pii-family-status:check`); email, IBAN, phone, payment-card, SSN and the shared PII code changed after it |

The candidate commit is the commit the matrix measured. The release is
published from a later commit on `main`: the commits after the candidate change
only documentation, the vendored benchmark evidence and the text generated from
it, and leave `crates/`, `packages/`, `bindings/` and
`conformance/` unchanged, which `git diff fe6e9234d40e7d5964de27d00d33544f9c621dbf
HEAD -- crates packages bindings conformance` shows to be empty. The release
manifest records the source commit actually published.

A count in this contract is valid only if the matrix's measured product commit
equals the candidate source revision. If it does not, the page must say which
families were measured on an earlier build instead of presenting the count as
current.

### Denominators

Counts at the candidate (regenerate with
`python3 -B scripts/report-detection-support.py --source-revision fe6e9234d40e7d5964de27d00d33544f9c621dbf`;
method in the [#1067 evidence record](https://github.com/redact-secret/redact-secret/blob/2816897f96c405c3eb8c87a0c70eba5df273c121/docs/audits/evidence/1067/README.md), the
Beta.13 per-detector join snapshot in
[`detector-support-join.md`](https://github.com/redact-secret/redact-secret/blob/2816897f96c405c3eb8c87a0c70eba5df273c121/docs/audits/evidence/1067/detector-support-join.md)):

- 110 shipped credential detectors emit 141 finding types; 6 opt-in PII
  families also ship. These are the denominators.
- The pinned matrix has 173 credential families: 144 stable, 7 provisional,
  5 pending, 17 unsupported. Twenty-one of those families (17 unsupported, 4
  pending) have no shipped detector.
- Counted by weakest listed family, the 110 detectors are 102 stable, 7
  provisional, 1 pending, 0 unsupported, and **0 shipped without a matrix
  family**.
- The 6 PII families are carried in the matrix apart from the credential
  families, as `piiFamilies` with their own `piiDistribution` (five
  `provisional`, one `pending`, none `stable`); they are not part of the 173
  credential families or of the 144 stable. Their statuses are stated in the
  [Opt-in PII table](detection.md#opt-in-pii-availability-is-not-support),
  which a gate checks against the matrix, and they are the **Beta.11
  qualification, not re-qualified** on this candidate (core `8b6a5fde`,
  benchmarks `be0fb9f3`).

"144 stable" counts matrix families, not detectors, and no stable family means
a detector finds every credential its provider issues.

### Provisional families carried into the contract

Four `generic:*` families are `provisional` in the pinned matrix and are
carried into the v0.1.0 contract as **provisional**, not stable:
`generic:bearer-token`, `generic:connection-string-password`,
`generic:otp-seed` and `generic:unclassified-assignment-literal`. The reason is
the matrix's own: their protected holdout is `not-run` and needs a pass on a
frozen candidate, and the formal run on the candidate did not include it. `generic:unclassified-assignment-literal` (detector
`generic-token`) additionally records one exact-span miss and one leaked span
among 76 positive cases. The candidate run still records that miss and that leaked span. A recheck on
current main from public fixtures reproduces none of the four (every public conformance fixture for the four
detectors matches its declared span exactly), but the recorded case is not
named in the pinned matrix, so its absence is not shown and the family stays
provisional. Per-family result and method:
[#1187 recheck](https://github.com/redact-secret/redact-secret/blob/2816897f96c405c3eb8c87a0c70eba5df273c121/docs/audits/evidence/1067/README.md#generic-family-recheck-on-current-main-1187).

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
PII. The per-detector join of both against the shipped code is produced on
demand by `python3 -B scripts/report-detection-support.py --source-revision
<sha>`, which writes to standard output. The join for the candidate named in the
identity table is the Beta.13 snapshot
[`detector-support-join.md`](https://github.com/redact-secret/redact-secret/blob/2816897f96c405c3eb8c87a0c70eba5df273c121/docs/audits/evidence/1067/detector-support-join.md).

### What this contract does not claim

- No precision, recall, or accuracy percentage for production traffic.
- No independent validation. Corroboration columns and any scanner comparison
  are project-collected evidence, recorded so a reader can check it, and the
  peer rules they cite often copy one another.
- No support for a PII family merely because it can be activated; activation is
  availability, and only the `pii-v1` status is support.

### Binding at freeze

The code and the ruleset contract are frozen for 0.1.x (see
[Stable contract 1](api-contract.md#stable-contract-1)). State of the steps
that bind this page to a candidate:

1. Candidate source revision chosen and written into the identity table: done
   (`fe6e9234d40e7d5964de27d00d33544f9c621dbf`).
2. `benchmarks/support-matrix.json` and its pin files re-pinned from
   `redact-secret/redact-secret-benchmarks` revision `573e1288`, after
   [`redact-secret/redact-secret-benchmarks#647`](https://github.com/redact-secret/redact-secret-benchmarks/issues/647)
   and
   [`redact-secret/redact-secret-benchmarks#648`](https://github.com/redact-secret/redact-secret-benchmarks/issues/648)
   landed: done. The matrix's `sourceReport.product.sourceCommit` equals the
   candidate SHA.
3. `python3 -B scripts/check-detector-family-coverage.py --strict` and the
   report script show 0 shipped-but-unmeasured credential detectors: done.
4. Identity values, the regenerated join and the PII statuses recorded and
   gated (`npm run pii-family-status:check`): done, with the PII statuses
   explicitly not re-qualified.
5. Open, and not part of this page: the US SSN custodian run
   ([`redact-secret/redact-secret-benchmarks#667`](https://github.com/redact-secret/redact-secret-benchmarks/issues/667)),
   the performance evaluation against the final release source commit, and
   explicit owner approval under the
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
The [canonical conformance review](https://github.com/redact-secret/redact-secret/blob/2816897f96c405c3eb8c87a0c70eba5df273c121/docs/audits/public-contract-cross-runtime-conformance.md)
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

The earlier [9-fixture audit](https://github.com/redact-secret/redact-secret/blob/2816897f96c405c3eb8c87a0c70eba5df273c121/docs/audits/evidence/200/verification-summary.json)
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
