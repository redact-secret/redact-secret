# US SSN family contract v1

This contract applies the accepted `pii-v1` domain and national-identifier
arrival policy to one jurisdictional family. It is the product-side contract
for issue #879, not a benchmark qualification or support-promotion claim.

The frozen product judgement is recorded in
[`docs/audits/evidence/879/README.md`](../../audits/evidence/879/README.md).

## Identity, activation, and support row

| Field | Value |
| --- | --- |
| Family | `pii:us:ssn` |
| Category / scope | `pii` / `jurisdiction:US` |
| Exact selector | `pii:family:us:ssn` |
| Jurisdiction selector | `pii:us` (this family plus every available global family) |
| Identity domain | `national-id` |
| Public finding type | `pii_jurisdiction_us_ssn` |
| Detector | `pii-domain` |
| Family-contract version | `1` |
| Validator | `us-ssn-allocation` version `1` |
| Qualification profile | `pii-v1` |
| Context requirement | `required-for-sensitive-classification` |
| Activation availability | `available` |
| Initial status | `pending` |
| Evidence reasons | `benchmark-counterpart-unmerged`, `exact-artifact-not-measured` |

`pii:global` does not select this jurisdictional family. The exact-family
selector does not gain global families. An empty selector list remains byte-
for-byte credential-only behavior. Only benchmark counterpart
[`redact-secret-benchmarks#392`](https://github.com/redact-secret/redact-secret-benchmarks/issues/392)
may project `provisional`, after binding the exact product artifact and passing
every applicable `pii-v1` arrival gate. This product record leaves #795 open.

## Typed authority

| Assertion | `sourceKind` | `sourceId` | Locator | Revision | Supports |
| --- | --- | --- | --- | --- | --- |
| An SSN has nine digits arranged as area, group, and serial components; the pre-randomization meanings no longer apply after 2011-06-25. | `public-authority` | `SSA-POMS-RM-10201.030` | RM 10201.030, opening and sections A–C | TN 2 (06-11), 2011-06-23 | `lexical`, `allocation` |
| Randomization removed geographic area significance and High Group significance and introduced previously unused areas except the excluded areas. | `public-authority` | `SSA-SSN-RANDOMIZATION` | “Social Security Number Randomization,” change list | implementation 2011-06-25; retrieved 2026-09-27 | `allocation` |
| Area `000`, `666`, and `900`–`999`, group `00`, and serial `0000` are invalid because SSA never assigns them. | `public-authority` | `SSA-POMS-RM-10201.035` | RM 10201.035 sections A–B | TN 2 (06-11), 2011-06-23 | `validation`, `allocation` |
| A display replica should use `000-00-0000` or another `000`-area combination to avoid displaying a potentially valid SSN. | `public-authority` | `SSA-POMS-RM-10201.020` | RM 10201.020 | Basic (08-09), 2009-08-28 | `reserved-control` |
| The SSN is among the most sensitive personal information in SSA records. | `public-authority` | `SSA-POMS-GN-03325.002` | GN 03325.002 section A | TN 9 (04-24) | `sensitivity` |

Authoritative sources:

- <https://secure.ssa.gov/poms.nsf/lnx/0110201030>
- <https://www.ssa.gov/employer/randomization.html>
- <https://secure.ssa.gov/poms.nsf/lnx/0110201035>
- <https://secure.ssa.gov/poms.nsf/lnx/0110201020>
- <https://secure.ssa.gov/poms.nsf/lnx/0203325002>

The validator implements only the structural exclusions SSA publishes. It
does not query Numident, claim assignment or identity ownership, or apply the
frozen High Group List, historic state areas, issuance order, or common
placeholder folklore as current validity rules.

## Frozen identity grammar and validator

The detector accepts one complete ASCII candidate in exactly one form:

- compact: nine digits, `AAAGGSSSS`; or
- display: three digits, one ASCII hyphen, two digits, one ASCII hyphen, and
  four digits, `AAA-GG-SSSS`.

It normalizes only the two display hyphens into a fixed nine-byte stack buffer.
The reported range remains the exact original compact or display form. The
crate-private `us-ssn-allocation` version 1 validator then requires nine ASCII
digits and rejects area `000`, `666`, or `900`–`999`, group `00`, and serial
`0000`. Those failures establish no identity. There is no checksum.

Spaces, Unicode digits, Unicode dash characters, other punctuation, missing or
repeated hyphens, partial prefixes or suffixes, alphanumeric/underscore/percent
adjacency, Unicode-mark adjacency, governed invisibles, and whole `{{...}}`,
`${...}`, or `<...>` references are excluded. Scanning and validation are
constant-bounded per candidate and perform no I/O or candidate-proportional
allocation.

## Sensitivity and negative evidence

Valid structure establishes identity only. A public finding is emitted only
when the shared context matcher associates a reviewed high-signal field label:

- English: `ssn`, `social security number`;
- Korean: `사회보장번호`, `사회 보장 번호`, `미국 사회보장번호`.

These are bounded field labels, not free-prose substring matches. Generic
`id`, `national id`, `tax id`, `number`, order, invoice, account, or reference
language has no sensitivity authority. Context never establishes identity.

There is no structurally valid official non-sensitive SSN namespace. The SSA
display controls have an excluded area and remain identity-unmatched rather
than being admitted as non-sensitive identifiers. The family names
`en-example-label`, `ko-example-label`, `en-us-ssn-negation`, and
`ko-us-ssn-negation` as occurrence exclusions; an associated whole `example`,
`documentation`, `예시`, `not ssn`, or `사회보장번호 아님` label wins after
positive context. The longer negated form wins lexical overlap against the
embedded positive field label. Similarity, `test`, or an unlisted placeholder
word does not suppress.

## Safe fixture plan

The committed cross-runtime corpus is the only place that contains its raw
positive candidate. It records generator `us-ssn-v1-fnv1a32-components`, seed
`redact-secret-us-ssn-v1-fixture-879`, and
`deterministic-no-real-world-provenance`. The generator:

1. computes 32-bit FNV-1a over the UTF-8 seed;
2. maps the hash deterministically into areas `001`–`899` while skipping
   `666`, groups `01`–`99`, and serials `0001`–`9999`; and
3. performs no person, SSA, registry, network, filesystem, assignment, or
   verification lookup.

This records provenance, not an issuance claim. The value is synthetic input
created solely to exercise the structurally admissible path; it is not sourced
from or attributed to any person. Official `000`-area controls and every SSA
structural exclusion supply safe negative fixtures. Diagnostics and expected
evidence contain case ids, types, actions, and ranges, never candidate text.

The corpus covers compact/display forms, English/Korean field labels, ordinary
order/reference/invoice collisions, ambiguous labels, official controls,
placeholders, all structural exclusions, malformed and adjacent forms,
governed invisibles, Unicode offsets, exact/jurisdiction/global closure,
and PII-off invariance. The shared Rust core and installed Python binding replay
every fixture case at every valid partition. The installed Node addon and
browser WebAssembly artifact check representative exact, jurisdiction, and
PII-off inputs at every valid UTF-16 partition. The CLI replays every fixture
case through both streamed stdin and whole-file paths, including a PII-off
control; its operating-system pipe chunk boundaries are not claimed as an
exhaustive partition set.

## Trade-offs

False positives remain possible when an unrelated nine-digit reference obeys
the SSA structural exclusions and is placed under an SSN-specific field label.
The detector proves neither assignment, activity, ownership, nor that the
occurrence belongs to a person. Required high-signal context and strict whole-
candidate boundaries reduce that risk.

False negatives include alternate punctuation or spacing, Unicode digits and
dashes, masked or last-four-only values, malformed values, candidates without
reviewed field context, and values under the narrow documentation/example
exclusions. Historical pre-randomization allocation could reject additional
never-issued combinations, but applying those rules without an issuance date
would incorrectly reject numbers that became assignable after randomization;
v1 deliberately does not do so. Runtime Numident verification, partial
masking, and stable support promotion are outside this issue.
