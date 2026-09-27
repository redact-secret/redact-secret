# Issue #878 — IBAN family contract v1

This is the frozen product judgment for the first global IBAN PII family. It
applies the accepted PII domain, structured-validator, and `pii-v1`
qualification policies. It neither creates new workspace policy nor claims
qualified support.

## Typed identity provenance

| Field | Frozen value |
| --- | --- |
| Family | `pii:global:iban` |
| Category and scope | `pii`, `global` |
| Family contract | `1` |
| Identity domain | `iban` |
| Exact selector | `pii:family:global:iban` |
| Public type | `pii_global_iban` |
| Adapter | `pii-domain` (the single PII detector slot) |
| Qualification profile | `pii-v1` version 1 |
| Context obligation | `required-for-sensitive-classification` |
| Activation availability | `full` and `common`, explicit opt-in only |
| Country authority | ISO 13616 IBAN Registry, SWIFT Release 103, 17 September 2026 |
| Validator provenance | built-in `iban-mod97`, version `1` |
| Initial status | `pending` |

[SWIFT is the ISO 13616 registration authority](https://www.swift.com/standards/data-standards/iban-international-bank-account-number)
and publishes the
[IBAN Registry](https://www.swift.com/swift-resource/9606/download). Release
103 supplies the frozen country-code/exact-length pairs, and nothing else is
copied from it. The complete derived 89-row table and executable contract are
in the [IBAN family contract](../../../contracts/pii/iban-v1.md). Runtime
validation uses only that compile-time table plus the already-versioned mod-97
validator: no registry, bank, ownership, or account-status lookup occurs.

## Product judgment

An uppercase compact candidate, or its exact four-character ASCII-space print
grouping, establishes identity only when its prefix exists in Release 103, its
normalized length equals that row, and `iban-mod97` v1 succeeds. Normalization
uses a fixed 34-byte stack buffer and preserves the exact original range.
Unknown prefixes and checksum-valid values at a country's wrong length are
unmatched. A checksum-valid exact-length collision without reviewed IBAN
context is identity-only and produces no public finding.

Sensitivity requires an associated high-signal English or Korean IBAN label.
Only the named whole documentation/example labels are occurrence-level
negative evidence. That narrow rule limits suppression by resemblance, but it
can miss a real value deliberately placed in a field labelled as documentation
or an example.

## Fixture and trade-off boundary

The conformance fixture derives check digits deterministically from a recorded
seed and a BBAN beginning with the explicit `SYNX` marker followed by zeros.
It performs no lookup and has no asserted account, bank, or person provenance;
expected findings contain metadata only.

A false positive remains possible when unrelated uppercase text has a Release
103 prefix and length, a valid mod-97 remainder, and reviewed IBAN context. The
accepted false negatives include registry changes after Release 103, lowercase
or locally formatted values, national BBAN variants outside the uppercase
alphanumeric primitive, hidden-character obfuscation, unreviewed context, and
the narrow documentation/example suppression. The detector is bounded and
side-effect free.

Exact-product-candidate measurement and the generated shared support row belong
to `redact-secret-benchmarks#391`. That work must bind this product commit and
repeat the country-length, validator, collision, benign-heavy, partition, and
cost evidence. Until all applicable `pii-v1` gates pass, status stays `pending`
with explicit reasons.
