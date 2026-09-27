# Phone family contract v1

This contract applies the accepted `pii-v1` domain policy to one deliberately
narrow phone family. It is the product-side contract for issue #880, not a
claim of benchmark qualification or comprehensive international support.

## Identity, activation, and support row

| Field | Value |
| --- | --- |
| Family | `pii:global:phone` |
| Category / scope | `pii` / `global` |
| Exact selector | `pii:family:global:phone` |
| Identity domain | `phone` |
| Public finding type | `pii_global_phone` |
| Detector | `pii-domain` |
| Family-contract version | `1` |
| Qualification profile | `pii-v1` |
| Context requirement | `required-for-sensitive-classification` |
| Activation availability | `available` |
| Typed authority | ITU-T E.164 (02/2026); NANPA number structure, central-office status, and 555-line controls |
| Initial status | `pending` |
| Evidence reasons | `benchmark-counterpart-unmerged`, `exact-artifact-not-measured` |

`pii:global` closes over this family. An empty selector list remains byte-for-
byte credential-only behavior. Generated reporting may change this row to
`provisional` only after the exact product artifact clears every applicable
`pii-v1` gate; this contract cannot make that support claim.

## Frozen identity grammar

V1 supports country code `+1` only. The `global` scope means the family is not
selected by a jurisdiction selector; it does not mean every national numbering
plan is recognized. A full candidate contains a NANP `NPA-NXX-XXXX`, where
each `N` is ASCII `2` through `9` and each `X` is ASCII `0` through `9`.
Actual `N11` area and central-office codes are excluded because NANPA governs
them as abbreviated/special codes. `988` is not an `N11` code and remains
structurally accepted; its separate abbreviated-dialing role does not change
the `NXX` grammar or imply allocation.

The exact accepted displays are:

- `+1NXXNXXXXXX`, `+1 NXX NXX XXXX`, and `+1-NXX-NXX-XXXX`;
- `NXXNXXXXXX`, `NXX NXX XXXX`, `NXX-NXX-XXXX`, and `(NXX) NXX-XXXX`; and
- local-only `NXX-XXXX`, which receives medium identity confidence because no
  area code is present. Compact seven-digit local forms are excluded.

A full form may append exactly one ASCII-space-delimited lowercase extension: `ext`,
`ext.`, or `extension`, another ASCII space, and 1–6 ASCII digits. The reported
range includes it. Local forms, zero or seven-plus extension digits, `x`, `#`,
`;ext=`, newlines, or missing spaces are excluded. Parsing is capped before
allocation. A second extension-like continuation after an otherwise valid
extension invalidates the whole candidate; no first-extension substring is
recovered. Continuation markers require an exact marker boundary and an
extension-shaped payload, so ordinary following prose whose word begins with
`ext` or `x` does not suppress the preceding candidate. ASCII dot or slash
displays, mixed separators, dialing prefixes,
vanity letters, Unicode digits/punctuation, RFC 3966 `tel:` / `sms:` URIs,
governed invisibles, and adjacent identifier, percent, combining-mark, or
phone-punctuation characters are excluded. No substring of a malformed larger
display is recovered as a candidate.

Normative typed sources:

- ITU-T E.164 (02/2026), Annex A §A.3.1.1 (`standard`, revision `2026-02`,
  lexical): <https://www.itu.int/rec/T-REC-E.164-202602-I/en>. It fixes the
  international-number structure and 15-digit maximum; v1 deliberately takes
  only its `+1` / NANP-compatible subset.
- NANPA, “About the North American Numbering Plan” (`public-authority`,
  retrieved `2026-09-27`, lexical): <https://www.nanpa.com/about>. It states
  country code `1`, the ten-digit address, and `NXX-NXX-XXXX` grammar.
- NANPA, “CO Codes/Thousands-Blocks” and “Central Office Code Assignment
  Records” (`public-authority`, retrieved `2026-09-27`, validation):
  <https://www.nanpa.com/numbering/co-codesthousands-blocks> and
  <https://www.nanpa.com/reports/co-code-reports/cocodes_assign>. They define
  the central-office `NXX` field and identify `N11` as unavailable/special.
  This detector never infers whether another code or number is assigned.
- NANPA, “555 Line Numbers” (`public-authority`, retrieved `2026-09-27`,
  reserved-control): <https://www.nanpa.com/numbering/555-line-numbers>.

## Sensitivity and negative evidence

Structure establishes identity only. A public finding requires an associated
high-signal entry under the shared bounded context rules. English phone fields
are `phone`, `phone number`, `telephone`, and `telephone number`; Korean phone
fields are `전화번호` and `휴대전화번호`. The shared natural-language phrase
`contact details` remains high-signal only when its normal distance, logical-
line, intervening-candidate, and tie rules associate it. English `contact` and
Korean `연락처` remain ambiguous and cannot establish sensitivity.

After positive context, a normalized NANP exchange plus line number from
`555-0100` through `555-0199` is non-sensitive only when it belongs to the
accepted whole candidate. An accepted extension is ignored for this exact
comparison. A prefix, suffix, substring, nearby value, or the token `555` has
no negative authority. The family names only `en-example-label` and
`ko-example-label` as occurrence exclusions.

## Safe fixtures and trade-offs

The reserved `555-01xx` grammar supplies authoritative non-sensitive controls.
Sensitive fixtures are deterministic, syntactically valid constructions from
the recorded seed `redact-secret-phone-v1-fixture-880`; they have no person,
assignment, subscriber, routing, or real-world provenance. Expected metadata
contains only safe type/action/range fields. Tests cover extension bounds,
N11/988 boundaries, versions, dates, addresses, order/reference numbers,
unsupported country codes, URI/vanity syntax, context negatives, multiple
candidates and equidistant non-association, Unicode offsets, governed
invisibles, exact/global closure, and every incremental partition.

False positives remain possible when a syntactically valid NANP-shaped order,
reference, or other identifier appears under an approved phone label. Exact
layouts, NXX checks, required context, and reserved controls reduce but cannot
remove that collision. False negatives are intentionally severe: every
country code other than `+1` (including `+82`), most international/national
display variants, compact local numbers, mixed punctuation, extensions outside
the narrow subset, vanity numbers, URI forms, context-free values, and values
under ambiguous or named-negative context are missed. The detector performs no
locale, language, geolocation, allocation, routing, activity, ownership,
carrier, network, filesystem, environment, or libphonenumber lookup.
