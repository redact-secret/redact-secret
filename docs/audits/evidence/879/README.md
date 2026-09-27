# US SSN v1 product evidence (#879)

This record freezes the product judgement for `pii:us:ssn`. It is not
benchmark evidence and makes no `provisional` or `stable` support claim.

## Judgement

- Use SSA POMS and the SSA randomization record for the nine-digit lexical
  structure and current structural exclusions.
- Register one bounded `us-ssn-allocation` v1 validator that rejects only area
  `000`, `666`, `900`–`999`, group `00`, and serial `0000`.
- Do not apply the pre-2011 High Group List, historic state allocation,
  issuance order, common-placeholder lists, or a network lookup as validity.
- Require a reviewed SSN-specific English or Korean field label for
  sensitivity. Generic identifier, tax, number, order, and reference labels
  carry no sensitivity authority.
- Treat SSA's `000`-area display controls as identity-unmatched. There is no
  structurally valid official non-sensitive namespace to invent.
- Confine the raw positive candidate to the safe conformance fixture, generated
  from a fixed seed with no person, issuance, registry, or lookup provenance.

The exact typed sources, grammar, validator, context forms, safe generator,
and false-positive/false-negative trade-offs are recorded in
[`docs/contracts/pii/us-ssn-v1.md`](../../../contracts/pii/us-ssn-v1.md).

## Verification boundary

Product verification covers detector/validator behavior, original-input
ranges, activation identity, exact and jurisdiction closure, global exclusion,
ordinary overlap, PII-off invariance, and astral UTF-16/code-point conversion.
The shared Rust core and installed Python binding replay every fixture case at
every valid partition; the installed Node addon and browser Wasm artifact cover
representative exact, jurisdiction, and PII-off inputs at every valid UTF-16
partition; and the CLI replays every fixture case through streamed stdin and
whole-file paths, including a PII-off control. No exhaustive claim is made for
operating-system pipe chunk boundaries.

Benchmark counterpart
[`redact-secret-benchmarks#392`](https://github.com/redact-secret/redact-secret-benchmarks/issues/392)
owns the exact-artifact protected partitions, authority projection,
identity/sensitivity accounting, collision/benign axes, both population views,
runtime, Wasm/package-size, activation, availability, and generated support
row. #795 and #879 remain open unless that exact full arrival package passes
and generated reporting emits `provisional`.
