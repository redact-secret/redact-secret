# Payment-card family contract v1

This contract applies the accepted `pii-v1` domain policy to one family. It is
the product-side contract for issue #877, not a claim of benchmark
qualification or stable support.

## Identity, activation, and support row

| Field | Value |
| --- | --- |
| Family | `pii:global:payment-card` |
| Category / scope | `pii` / `global` |
| Exact selector | `pii:family:global:payment-card` |
| Identity domain | `payment-card` |
| Public finding type | `pii_global_payment_card` |
| Detector | `pii-domain` |
| Family-contract version | `1` |
| Qualification profile | `pii-v1` |
| Context requirement | `required-for-sensitive-classification` |
| Activation availability | `available` |
| Typed authority | ISO/IEC 7812 structure; Visa Acceptance payment-brand ranges; PCI SSC PAN meaning and Luhn guidance |
| Initial status | `pending` |
| Evidence reasons | `benchmark-counterpart-unmerged`, `exact-artifact-not-measured` |

`pii:global` closes over this family. An empty selector list remains byte-for-
byte credential-only behavior. Generated reporting may change this row to
`provisional` only after the exact product artifact clears every applicable
`pii-v1` gate; this product contract cannot make that support claim.

## Frozen identity grammar

The detector accepts one complete PAN candidate only when all of these hold:

- Detector-owned normalization removes ASCII space or `-` display separators.
  A separated form uses one separator kind and one of the two layouts shown in
  the frozen Visa Acceptance test documentation: `4-4-4-4` or American
  Express `4-6-5`. Other supported lengths are compact only. The reported
  range remains the exact original range, including separators.
- The normalized candidate has 10–19 ASCII digits. Unicode decimal digits,
  masking characters, tabs, newlines, other punctuation, mixed separators,
  partial prefixes/suffixes, governed invisibles, and adjacent identifier,
  percent, or Unicode-mark characters are excluded.
- The normalized candidate is in one of these payment-brand scopes, frozen
  from the Visa Acceptance Solutions card-type table retrieved 2026-09-27:

  | Scope | Accepted length and prefix |
  | --- | --- |
  | American Express | 15 digits; `34` or `37` |
  | Discover | 16 digits; `601100–601109`, `601120–601149`, `601174`, `601177–601179`, `601186–601199`, or `644000–659999` |
  | JCB | 16–19 digits; `3528–3589` |
  | Mastercard | 16 digits; `510000–559999` or `222100–272099` |
  | Visa | 10–19 digits; leading `4` |

- The normalized candidate passes the already-registered structured validator
  identified exactly as `luhn` version `1`. This issue does not modify that
  validator's lexical contract, bounds, algorithm, failure classes, or
  provenance.

ISO/IEC 7812-1:2017 edition 5 (confirmed current by ISO in 2022) is the
authoritative structural source for the IIN/PAN numbering system. ISO's public
revision notice pins the eight-digit IIN transition and 10–19 digit PAN range.
The Visa row combines that ISO minimum with the Visa Acceptance card-type
table's leading `4` and stated maximum of 19 digits; it does not infer an
unpublished issuer assignment.
The American Bankers Association, the ISO/IEC 7812 Registration Authority,
confirms that IIN assignment is a managed registry. The product deliberately
does not bundle or infer that non-public registry: matching one of the frozen
brand ranges is structural type evidence, not a claim that a particular
eight-digit IIN is assigned, issued, active, or owned by a named issuer.

Normative and typed sources:

- ISO/IEC 7812-1:2017, edition 5, confirmed 2022 (`standard`, structural,
  revision `2017`): <https://www.iso.org/standard/70484.html>
- ISO, “Changes to the Issuer Identification Number (IIN) standard,”
  2016-11-21 (`standard-owner guidance`, structural revision notice):
  <https://www.iso.org/news/2016/11/Ref2146.html>
- American Bankers Association, “Issuer Identification Numbers”
  (`registration-authority`, assignment semantics, retrieved 2026-09-27):
  <https://www.aba.com/about-us/our-story/issuer-identification-numbers>
- Visa Acceptance Solutions, “Credit Card Account Number Verification — Card
  Type Identification” (`payment-processor documentation`, lexical/IIN ranges,
  retrieved 2026-09-27):
  <https://developer.cybersource.com/docs/cybs/en-us/test-data/developer/all/so/test-data/best_practices_intro/card_type_id.html>
- PCI SSC FAQ 1137 (`industry-authority guidance`, Luhn meaning):
  <https://www.pcisecuritystandards.org/faqs/1137/>

The PCI SSC guidance is explicit that a Luhn pass establishes only a possible
valid number, not issuance or activity. Mechanical checksum-failure neighbors
therefore test validator correctness but are not precision evidence.

## Sensitivity and negative evidence

PAN structure establishes identity only. A public finding is emitted only when
the shared context matcher associates a reviewed high-signal payment-card field
label with the candidate. V1 English forms are `payment card`, `card number`,
`credit card number`, `debit card number`, and `pan`; Korean forms are
`결제 카드`, `카드 번호`, `신용 카드 번호`, and `직불 카드 번호`, plus, since
`pii-context/v2` ([#927](https://github.com/redact-secret/redact-secret/issues/927)),
the unspaced `카드번호`, `신용카드번호`, and `직불카드번호`. Generic `card`,
`number`, `account`, `order`, and `reference` language has no sensitivity
authority. `pan` participates only through the shared bounded field-label
association (`before`, at most 16 normalized scalars, separators/quotes-only
gap); the free-prose word “pan” has no effect. Finding severity and the default
`redact` action come from the shared PII substrate's high-confidence policy,
not an unconditional detector-local `ALWAYS_REDACT` rule.

After positive context, only the frozen supported-brand subset of exact whole
normalized PANs published by Visa Acceptance Solutions for its test services
is non-sensitive. The subset contains the documented American Express,
Discover, JCB, Mastercard, and Visa controls used by this contract; test-suite
entries for unsupported brands such as Maestro are deliberately omitted and
do not expand identity support. The frozen subset comes from “Testing the
Payment Services — Test Card Numbers,” retrieved
2026-09-27:
<https://developer.visaacceptance.com/docs/vas/en-us/payments/developer/fiservrc/rest/payments/payments-intro/payments-testing-services/payments-testing-cards.html>.
Prefixes, suffixes, substrings, a neighboring value, a shared BIN/IIN, or the
word `test` do not inherit this negative authority. The family also names only
`en-example-label` and `ko-example-label` as occurrence-level exclusions.
An exact published test PAN is admitted solely so this authoritative negative
control can be classified even when its prefix falls outside the positive
brand-range table above; no neighboring value or shared prefix gains support.

## Safe fixture plan

- Official test-service PANs exercise identity-valid, whole-candidate negative
  evidence without representing cardholder data.
- Sensitive-path fixtures are deterministic Luhn-valid constructions from the
  recorded seed `redact-secret-payment-card-v1-fixture-877`. They have no
  cardholder, issuer-assignment, issuance, or real-world provenance.
- Deterministic cases cover every supported brand boundary, 10/19-digit length
  bounds, checksum neighbors, malformed and mixed separators, semantic
  collisions (order/reference/account numbers), context negatives, overlap,
  Unicode offsets, governed invisibles, exact/global closure, and every
  incremental partition.

Expected metadata and diagnostics never reproduce a candidate. Partial masking
or last-four preservation is outside this issue.

## Trade-offs

False positives remain possible when a Luhn-valid order, reference, loyalty, or
bank-account number also lies in a frozen payment-brand range and appears under
a high-signal payment-card field. Whole-candidate parsing, brand-range limits,
Luhn, required context, and exact test-value negatives reduce but cannot remove
that collision.

False negatives include unsupported payment brands and range revisions,
otherwise valid PANs outside the frozen ranges or display grammar, masked or
truncated PANs, candidates without reviewed high-signal context, and candidates
under named negative context. URL query syntax does not turn a query key into a
field-label occurrence because `?`/`&` are outside the frozen context-token
separator grammar. The detector performs no issuer-registry lookup,
network authorization, account validation, ownership check, decoding, or
Unicode digit normalization.


## Evidence handoff boundary

The [family handoff](https://github.com/redact-secret/redact-secret/issues/1294#issuecomment-6082141341) reviews the
[immutable pii-evidence candidate](https://github.com/redact-secret/pii-evidence/blob/841bad92c3af75199088fda55b12a36b6f197808/docs/research/snapshot-v2-handoff.json)
`public-pii-phi/2026-10-08/ee61c7afc32d`. At the #1293 review this candidate
was unregistered and unpublished; that historical review did not adopt it as
an active qualification snapshot.
Its project-maintained research dispositions are not independent validation.

Issue #1299 has a no-code deferred disposition: the candidate contains no
accepted payment-card cases. Public-safe source redistribution and accepted
carrier/grouping semantics remain unresolved in pii-evidence. This deferral
applies to additional hardening under epic #1293, not removal of the existing
family contract or its conformance controls. No issuer/network rule, test-value
exclusion or sensitivity change is inferred from Luhn or scanner output.
Reopen hardening after a source-backed handoff includes this family.

## Active-v2 disposition

Epic [#1303](https://github.com/redact-secret/redact-secret/issues/1303) revisits
the released active snapshot `public-pii-phi/2026-10-08/ee61c7afc32d` at
[pii-evidence source](https://github.com/redact-secret/pii-evidence/blob/e22bbc16cb9009de1a6a91e97e7322ebbc32bcf0/docs/research/snapshot-v2-handoff.json).
The current comparison uses `pii-v1` revision 3, artifact schema 1.5, mapping
revision 3 and population version 3. Context and identity are retained by
that mapping; the earlier mapping-loss rationale is historical. Canonical
reported outcomes remain evidence-owned and are not rewritten by the product
disposition. The [active-v2 case ledger](https://github.com/redact-secret/redact-secret/issues/1305#issuecomment-6089713572)
records each applicability ruling and its source lineage.

Issue #1309 retains a no-code evidence-gap disposition. The active snapshot
contains no accepted materialized payment-card cases; taxonomy or excluded
source material does not establish coverage. The existing grammar, Luhn
validator, test-service controls and product conformance remain unchanged.
This is unmeasured hardening, not a scanner pass. Reassess when accepted
source-backed evidence includes this family.
