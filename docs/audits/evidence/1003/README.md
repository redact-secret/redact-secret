---
owner: #1003
reviewed_source: 40822967a1249b39c9c1f01f70b4020d05dbf0d1
status: deferred
retire_on: after-issue:#1003
---

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

## Committed probe and a contract-text gap

[`probe.py`](probe.py) keeps a deterministic, stdlib-only subset of this
matrix (318 probes) so the check can be repeated: build the example and run
`python3 -B probe.py emit | <example-binary> --family pii:us:ssn > out.jsonl` and then `python3 -B probe.py check out.jsonl [--all]`. Its expectation encodes the adjacency
set the code enforces, so it reports 0 identity disagreements; the mismatches
above are the boundary shapes where an expectation taken from the contract
text alone would differ.

The contract's exclusion list names alphanumeric, underscore, percent, mark
and invisible adjacency. `blocks_boundary` also blocks an adjacent ASCII
hyphen, any non-ASCII whitespace and Unicode dashes. Unicode space and dash
adjacency are pinned by public fixtures, but ASCII-hyphen adjacency
(`ssn: 1-890-62-6879`, `890-62-6879-1`) has no dedicated fixture and is
implied only by "partial prefixes or suffixes". Sensitivity probes with
free-prose labels (`Social Security Number is`, `미국 사회보장번호는`) report
`not-established`, which matches the contract's bounded field-label rule.

Proposed narrow follow-up (docs and fixtures, no detector change): state the
full adjacency set in `us-ssn-v1.md`, and add public conformance twins for
ASCII-hyphen prefix and suffix and for NBSP and ideographic-space adjacency.
This is a hypothesis about a class of disagreement, not evidence about the
protected case.

## Reading for the next epoch

The cause of the one protected disagreement is **not reproducible from public
evidence**. One unverified hypothesis: the protected case has a boundary shape
like the ones above, where the authored label says `valid` and the seam reports
`unmatched`. Verifying it would require the protected case, which stays
unopened. When authoring the new-seed corpus, keep the characters around each
authored candidate to ASCII whitespace, punctuation or a string edge, and check
the case against the public oracle before sealing.

## Implementation (#1188)

Docs and fixtures only; no detector change. Before writing the text, each
claimed blocking class was confirmed against `blocks_boundary` in
`crates/secret-scan-core/src/pii/pii_us_ssn.rs` and with the identity seam: the
committed `probe.py` matrix still reports `cases=318 disagreements=0`, and a
12-shape control run (`ssn=<X>890-62-6879<X>`) gave `unmatched` for NBSP,
U+3000, ASCII hyphen, U+3030, U+FF0D and a Korean particle, and `established`
for ASCII space, tab, line feed, `:`/`,` and `.`. No claimed class differed
from the code, so the stop condition did not trigger.

- `docs/contracts/pii/us-ssn-v1.md` now has an "Adjacency set" subsection that
  lists every blocking class (alphanumeric, `_`, `%`, ASCII hyphen, combining
  mark, non-ASCII whitespace, listed Unicode dashes, governed invisibles) and
  the non-blocking ones (ASCII whitespace, other ASCII punctuation, string
  edge).
- Eight new twins in `conformance/fixtures/pii-us-ssn-v1.json`, all
  `expected: []`: `us-ssn-adjacent-ascii-hyphen-{prefix,suffix}`
  (`ssn: 1-890-62-6879`, `ssn: 890-62-6879-1`),
  `us-ssn-adjacent-ascii-hyphen-compact-{prefix,suffix}`,
  `us-ssn-adjacent-nbsp-compact-{prefix,suffix}` and
  `us-ssn-adjacent-ideographic-space-{prefix,suffix}`. Display-form NBSP
  adjacency was already pinned by `us-ssn-adjacent-unicode-space-*`, so the NBSP
  twins use the compact form.
- Observation, not pinned or claimed: U+2212 MINUS SIGN is not in the code's
  dash list and does not block adjacency.
- Cross-repo follow-up: the changed fixture file's SHA-256 is part of the
  conformance corpus identity that releases record. See the pull request for
  any pin follow-up in `redact-secret-benchmarks`.
