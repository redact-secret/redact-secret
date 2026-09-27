# Payment-card v1 product evidence (#877)

This record freezes the product judgement for `pii:global:payment-card`. It is
not benchmark evidence and makes no provisional or stable support claim.

## Judgement

- Use ISO/IEC 7812-1:2017 for PAN/IIN structure and the existing `luhn` v1
  validator for checksum evidence; do not alter the validator in this issue.
- Limit issuer-range evidence to the payment-brand ranges and lengths published
  by Visa Acceptance Solutions and read on 2026-09-27. Do not imply access to
  the ISO IIN register or assignment/issuer breadth beyond those ranges.
- Require a reviewed high-signal payment-card field for sensitivity.
- Treat only the frozen complete values for the contract's supported brands
  in the named Visa Acceptance test-card suite as non-sensitive test data.
  Omitted brands such as Maestro stay unsupported; similarity and mechanical
  Luhn failures are not negative precision evidence.

The exact sources, frozen ranges, context forms, safe-fixture provenance, and
false-positive/false-negative trade-offs are recorded in
[`docs/contracts/pii/payment-card-v1.md`](../../../contracts/pii/payment-card-v1.md).

## Verification boundary

Product verification covers detector behavior, original-input ranges,
activation identity, selectors, overlap, PII-off invariance, Unicode offsets,
all incremental partitions, and Rust/Node/Wasm/Python/CLI conformance. The
benchmark counterpart is
[`redact-secret-benchmarks#390`](https://github.com/redact-secret/redact-secret-benchmarks/issues/390);
its exact-artifact collision, benign-heavy, holdout, and cost evidence remains
outside this repository.
