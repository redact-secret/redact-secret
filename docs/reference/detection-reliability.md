# Detection reliability

[Documentation home](../README.md) · [Detection coverage and limits](detection.md)

Redact Secret detects the credential grammars and contexts listed in the
[coverage report](../coverage/coverage-report.md). It does not claim universal
secret detection, and an empty finding list does not prove that input is
secret-free. Strict prefixes, length bounds, contextual allowlists, and exact
source ranges favor predictable, lower-noise behavior at the cost of missing
truncated, new, encoded, or otherwise unsupported credential shapes.

## What the published assessment measures

The committed [cross-language assessment](../../assessment/README.md) uses a
small, hand-reviewed synthetic corpus. It is separate from the canonical
conformance contract and from real-world prevalence data. Version 1 contains 9
whole-input fixtures: 3 logs, 2 source-code, 2 chat, and 2 negative-text
fixtures. Six fixtures contain one expected finding and 3 are expected empty.

The durable complete run evaluated the Rust crate, installed Python package,
Node package, browser WebAssembly package in Chromium, and CLI from source
revision `a356e702e59b03cf297e0af15ba0423bc8466d48`. Every surface used accuracy
corpus version `1`, SHA-256
`9c72ab77bb1ee54c6912592c2ce3de72c0c152356283d620498aac5fe08c26d9`.
The [machine-readable rollup](../../assessment/results/complete/summary.json),
[consolidated baseline](../../assessment/results/complete/baseline.md), and
[issue #200 verification summary](../audits/evidence/200/verification-summary.json)
are the inspectable evidence.

## Detection and range results

All five surfaces produced the same result on this corpus.

| Result | Count / denominator | Meaning |
| --- | ---: | --- |
| Exact true positives | 1 / 6 expected findings | Detector, type, and source range all matched |
| False negatives | 5 / 6 expected findings | No exact detector/type/range match |
| False positives | 1 / 2 actual findings | One emitted finding did not exactly match an expectation |
| Incorrect ranges | 1 / 6 expected; 1 / 2 actual | One missing/extra pair had the same detector and type but different ranges |
| Policy-correct findings | 1 / 1 evaluable exact match | The action matched on the exact-range true positive |
| Expected-empty fixtures with findings | 0 / 3 | No finding appeared in the three ordinary-negative fixtures |

The false-positive and false-negative counts are not independent errors: the
single range disagreement contributes one of each because the scorer requires
an exact range. It is therefore inaccurate to say that this corpus observed an
ordinary-negative false positive. It observed zero findings in 3 expected-empty
fixtures and one range-disagreeing finding among 2 actual findings.

These fractions describe only these 9 synthetic fixtures. They are not
precision, recall, or accuracy estimates for production traffic, provider
inventories, repositories, or arbitrary secrets. The corpus was selected for
reviewable boundary cases, not sampled from a target population; no confidence
interval or universal detection percentage is justified.

## Redaction results

The same complete Testbed recorded successful whole-input and incremental
processing for Rust, Python, Node, and browser WebAssembly using identical
workload-profile identity. Those performance paths invoke `scanAndRedact`,
`scan_and_redact`, or the bounded incremental sanitizer. The CLI performance
runner instead exercises check mode over its standard-input boundary. These
results prove that the real artifacts completed the stated paths; they are not
a redaction-accuracy rate.

The CLI accuracy adapter additionally compares `--redact` output byte-for-byte
with the placeholders implied by every emitted `redact` or `block` finding and
emits no result if that check fails. The installed Python adapter compares
whole-input and one-code-point incremental sanitized output across all 9
fixtures. The Testbed does not publish a cross-surface denominator for exact
assessment-corpus redaction, so this page does not invent one.

Redaction correctness is instead owned by the canonical conformance contract.
The [public-contract review](../audits/public-contract-cross-runtime-conformance.md)
records actual-artifact redaction checks for Rust, Python, Node, browser
WebAssembly, and CLI at revision
`5607de8973ddb83f9b61f840f67eb8534d5cea0d`, synchronous-corpus SHA-256
`27beff0ae10480c0e10f840be56f9cf07a2f76fa3a94b4af3c91d68ac0cc30a5`.
That evidence shows supported findings are replaced according to policy; it
does not turn the assessment score into a universal redaction-success
percentage or same-revision evidence for the older Testbed result.

## Known limitations and dispositions

The five missed exact matches and the range disagreement have explicit
dispositions in the
[beta.2 assessment](../../assessment/results/beta.2/README.md):

- two fixtures use a shortened classic GitHub-token shape;
- one uses a shortened AWS access-key shape;
- one uses the unsupported contextual setting name `seed`; and
- the Bearer case expects the scheme and value while the stable detector
  contract deliberately selects and redacts only the credential value.

These are documented precision/recall and contract-boundary choices, not five
newly confirmed detector defects. The reviewed assessment labels remain
unchanged, and no detector was broadened to improve the score. If a currently
unsupported shape becomes a product requirement, it needs a synthetic Rust-core
regression and an explicit false-positive tradeoff.

Further evidence limits remain linked to owners:

- [#203](https://github.com/redact-secret/redact-secret/issues/203) owns the
  formal same-revision, full-platform release-candidate artifact inventory;
- [#224](https://github.com/redact-secret/redact-secret/issues/224) owns replay
  of every canonical incremental fixture through installed Node and browser
  artifacts; and
- [#180](https://github.com/redact-secret/redact-secret/issues/180) and its
  completed children own the underlying detector-coverage closeouts.

The committed complete run is a macOS arm64 observation using Node 22, CPython
3.14, and Chromium. Its timing and sampled-memory values are environment-bound
and must not be read as detection reliability. Candidate package manifest
identities are `0.1.0-beta.1`; the evidence does not claim that those artifacts
were published, approve a release, or substitute for #203's formal RC run.

## Reproduce and inspect

Build the real artifacts and run the bounded five-surface suite as documented
in the [assessment protocol](../../assessment/README.md#complete-reproducible-evaluation):

```bash
npm run assessment:all -- --python .venv/bin/python --output-dir assessment-output
```

Use a new output directory. A missing, failed, invalid, skipped, identity-mismatched,
or incomplete surface makes the aggregate status incomplete. Timing samples may
vary; the source revision, corpus/profile hashes, surface inventory, and
repetition count are the reproducible contract.
