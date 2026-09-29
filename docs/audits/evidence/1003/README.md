# #1003 — us-ssn identity-only mismatch: public investigation

Product judgement. Final record for the public-evidence half of #1003. The
protected case was not opened, and nothing here was tuned against it.

## Question

The Beta.11 protected run reported `identity-failures:1` for `pii:us:ssn`. Can an
identity-only outcome (a structurally valid SSN under non-establishing or
negative context) disagree between the product identity seam
(`crates/secret-scan-core/examples/pii_identity_evaluation.rs`) and the oracle,
using public inputs only?

## Method

- Seam: the release build of `pii_identity_evaluation`, run with
  `--family pii:us:ssn`.
- Oracle: the #910 definition (apply the SSA assignment rules to the authored
  candidate; `valid` if and only if `established`), reimplemented as a small
  reference script. The script was throwaway and is not kept in the repository.
- Inputs: 19 synthetic SSN values (areas `000`, `666`, `900`, `999`, group `00`,
  serial `0000`, `123-45-6789`, `078-05-1120`, `219-09-9999`, repeated digits,
  and ordinary valid values) × 7 separator forms (compact, hyphen, space, dot,
  underscore, slash, en dash) × 35 contexts (English and Korean labels, example
  and negation words, tab, NBSP, full-width forms) = 4,655 cases.

## Result

No publicly reproducible product defect.

- SSA structural exclusions, placeholder values, repeated digits, separator
  variants and example or negation context: 0 mismatches.
- 110 mismatches, all a valid compact or hyphenated SSN adjacent to a boundary
  character:
  1. a Korean particle glued to the number (`사회보장번호는 <value>입니다`),
     which `blocks_boundary` in `pii_us_ssn.rs` treats as alphanumeric;
  2. a hyphen before or after the number;
  3. a no-break space before the number (already pinned by the
     `us-ssn-adjacent-unicode-space-prefix/suffix` fixtures).
- These follow the contract's alphanumeric-adjacency exclusion and are
  intended. The `phone`, `payment-card` and `email` families behave the same way
  next to a Korean particle, so this is the shared boundary policy, not an
  us-ssn defect. Allowing particle adjacency would be a cross-family policy
  change that needs its own decision.

## Reading for the next epoch

The cause of the one protected disagreement is **not reproducible from public
evidence**. One unverified hypothesis: the protected case has a boundary shape
like the ones above, where the authored label says `valid` and the seam reports
`unmatched`. Verifying it would require the protected case, which stays
unopened. When authoring the new-seed corpus, keep the characters around each
authored candidate to ASCII whitespace, punctuation or a string edge, and check
the case against the public oracle before sealing.
