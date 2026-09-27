# IBAN family contract v1

This contract applies the accepted `pii-v1` domain policy to one family. It is
the product-side contract for issue #878, not a claim of benchmark
qualification or stable support.

The supporting product judgment and typed source provenance are frozen in
[`docs/audits/evidence/878/README.md`](../../audits/evidence/878/README.md).

## Identity and activation

| Field | Value |
| --- | --- |
| Family | `pii:global:iban` |
| Exact selector | `pii:family:global:iban` |
| Identity domain | `iban` |
| Public finding type | `pii_global_iban` |
| Detector | `pii-domain` |
| Family-contract version | `1` |
| Qualification profile | `pii-v1` |
| Context requirement | `required-for-sensitive-classification` |
| Initial status | `pending` until exact-artifact benchmark evidence is reviewed |

`pii:global` closes over this family. An empty selector list remains byte-for-
byte credential-only behavior.

## Frozen identity contract

The typed authorities are ISO 13616 and the SWIFT ISO 13616 IBAN Registry,
Release 103, published 17 September 2026. SWIFT is the ISO registration
authority and publishes the country formats. The detector pins only the
country-code and exact electronic-form length needed at runtime:

```text
AD24 AE23 AL28 AT20 AZ28 BA20 BE16 BG22 BH22 BI27 BR29 BY28
CH21 CR22 CY28 CZ24 DE22 DJ27 DK18 DO28 EE20 EG29 ES24 FI18
FK18 FO18 FR27 GB22 GE22 GI23 GL18 GR27 GT28 HN28 HR21
HU28 IE22 IL23 IQ23 IS26 IT27 JO30 KW30 KZ20 LB28 LC32 LI21
LT20 LU20 LV21 LY25 MC27 MD24 ME22 MK19 MN20 MR27 MT31 MU30
NI28 NL18 NO15 OM23 PK24 PL28 PS29 PT25 QA29 RO24 RS22 RU33
SA24 SC31 SD18 SE24 SI19 SK24 SM27 SO23 ST25 SV28 TL23 TN24
TR26 UA29 VA22 VG24 XK20 YE30
```

The detector accepts either:

- the electronic form: 15–34 uppercase ASCII letters/digits with two leading
  letters and two check digits; or
- the print form: the same electronic characters grouped from the left in
  groups of four, separated by exactly one ASCII space, with a final group of
  one to four characters.

The country prefix must be in the pinned table and the normalized electronic
length must exactly equal that row. An unknown prefix or a wrong country
length is `identity: unmatched`, even when some differently sized string has a
valid mod-97 remainder. The detector removes print-form spaces into a fixed
34-byte stack buffer and calls the existing `iban-mod97` version 1 registry
entry. It does not widen that validator's uppercase, no-separator, 15–34-byte
contract, allocate in proportion to input, or perform filesystem, network,
bank, registry, ownership, or account-status lookups.

Lowercase, tabs, non-breaking spaces, hyphens, repeated spaces, mixed compact
and print grouping, governed invisible characters, alphanumeric/underscore/
percent/Unicode-mark adjacency, and whole `{{...}}`, `${...}`, or `<...>`
references are excluded. A match range is always the exact original compact
form or the full print form, including its internal spaces and no surrounding
characters. Redaction therefore removes neither adjacent punctuation nor
unrelated whitespace.

This v1 contract validates country length and the ISO mod-97 check only. It
does not reproduce each country's BBAN sub-field grammar or domestic checksum.

## Sensitivity and negative evidence

A correct country length plus `iban-mod97` v1 establishes IBAN identity, not
sensitivity. Without context, a checksum-valid collision remains
`sensitivity: not-established` and produces no public finding. The shared
context matcher establishes sensitivity only when it associates the reviewed
high-signal field forms `iban`, `international bank account number`, or
`국제 계좌번호` with the candidate.

Only `en-example-label` and `ko-example-label` are named occurrence-level
negative evidence. After positive context, an associated whole `example`,
`documentation`, or `예시` label makes the occurrence non-sensitive. This is
deliberately narrow: resemblance and unlisted words never suppress. A real
IBAN placed in a field explicitly labelled as documentation or an example can
therefore be missed; that accepted false-negative cost keeps committed docs
and examples from being treated as personal data by default.

## Deterministic safe fixture generator

The conformance fixture records generator
`iban-v1-uppercase-bban-check-digits` with seed
`redact-secret-iban-v1-fixture-878`. For each recorded country and unmistakably
synthetic uppercase BBAN, it appends the country and `00`, maps `A`–`Z` to
`10`–`35`, computes the integer remainder one decimal digit at a time, and
sets the two check digits to `98 - remainder`. It performs no random, registry,
bank, or account lookup. `SYNX` and all-zero account material are fixture
markers, not an assertion that an account or bank exists. Tests regenerate
the electronic value and fail on drift. Expected metadata never copies a
matched value.

## Trade-offs

False positives remain possible when unrelated uppercase text has a registered
country prefix, the exact country length, a valid mod-97 remainder, and a
reviewed IBAN field label. Requiring context prevents a checksum-valid
collision by itself from becoming a public finding, but cannot prove that a
context-qualified value belongs to a person or live account.

False negatives include registry changes after Release 103, national BBAN
variants outside the uppercase alphanumeric validator, lowercase or locally
formatted forms, alternate whitespace, hidden-character obfuscation, malformed
grouping, values without reviewed high-signal context, and the narrow named
documentation/example suppression above.
