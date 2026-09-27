# Issue #880 product judgement evidence

## Judgement

Ship a deliberately narrow, context-required `pii:global:phone` family for the
`+1` / NANP subset. Keep it `pending` until benchmark issue
`redact-secret-benchmarks#393` binds and evaluates the exact merged artifact.

## Frozen evidence

- [`docs/contracts/pii/phone-v1.md`](../../../contracts/pii/phone-v1.md)
  records the typed ITU-T/NANPA authority, exact country-code/display/extension
  subset, whole-candidate `555-01xx` control, context semantics, safe fixture
  plan, and accepted false-positive/false-negative costs.
- [`conformance/fixtures/pii-phone-v1.json`](../../../../conformance/fixtures/pii-phone-v1.json)
  is the safe executable corpus used by Rust, Node, browser Wasm, Python, and
  CLI surfaces. It contains no claimed subscriber or real-person data.
- `crates/secret-scan-core/src/pii/pii_phone.rs` is the bounded,
  side-effect-free implementation under the one `pii-domain` adapter.

## Placement and limits

This directory freezes the product judgement only. Benchmark measurements,
raw scanner output, population results, and generated support projection
belong in `redact-secret-benchmarks#393` and are not copied here. This record
does not promote the family, authorize a release, or claim support outside the
frozen subset.
