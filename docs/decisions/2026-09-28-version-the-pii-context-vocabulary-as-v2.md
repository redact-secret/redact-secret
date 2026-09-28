---
decision_id: decision-version-the-pii-context-vocabulary-as-v2
status: accepted
scope: workspace
title: Version the PII context vocabulary as pii-context/v2 so a field label associates only forward
decided_at: 2026-09-28
spec: contextual-detection
---

# Version the PII context vocabulary as pii-context/v2 so a field label associates only forward

## Context

[`decision-define-the-pii-context-vocabulary-contract`](2026-09-26-define-the-pii-context-vocabulary-contract.md)
defined `pii-context/v1`: a `field-label` entry precedes its candidate, and "a
context match equidistant from two candidates associates with neither". It
also says a semantic schema or matching change requires a new version.

Benchmark evidence on the released beta.10 candidate
(redact-secret-benchmarks#424 and #425) showed what the literal equidistance
rule costs on dense single-line records. In `email: A phone: B`,
`ip=A card_number=B`, or `ip: A ip: B`, the second label sits one normalized
scalar after `A` and one before `B`, so it is discarded and `B` stays in
plain text ([#924](https://github.com/redact-secret/redact-secret/issues/924)).
A field label can never associate with `A`: it only associates forward. The
earlier candidate was therefore never a competing target, and the rule gave
an ambiguity verdict where there was no ambiguity. Whether a value was found
also depended on which other families were selected, and on accidents such as
`client_ip` being rescued by its own shorter `ip` form.

## Decision

The live context contract is
[`docs/contracts/pii/pii-context-v2.json`](../contracts/pii/pii-context-v2.json),
compiled as `pii-context/v2`. Every activation identity names it
(`vocabulary=pii-context/v2`). The `pii-context/v1` file stays unchanged as
the record of what beta.10 compiled.

v2 changes one matching rule. Equidistance is judged only among the
candidates an occurrence could associate with:

- a `field-label` match (`association.fieldLabel.equidistanceAmong:
  following-candidates`) counts only candidates after it, so an earlier
  candidate on the same line never makes it equidistant; and
- a `natural-language-label` match, which may associate on either side,
  keeps the two-sided rule (`candidates-on-either-side`), so
  `A contact details B` still associates with neither.

Alternatives of different identity domains at one exact range are one
occurrence, not two candidates
([#922](https://github.com/redact-secret/redact-secret/issues/922)). Every
other v1 rule stands: normalization, the 16- and 64-scalar bounds, the
field-gap rule, candidate barriers, domain filtering, and precedence.

## Consequences

- False negatives removed: every labelled value after the first on a logfmt,
  `k: v k: v`, or `a=… b=…` line, within and across families.
- False positives: association alone adds none. Each value still needs its
  own family's reviewed high-signal label directly in front of it, separated
  only by declared separators and quotes, and a label of another domain
  still cannot reach it.
- The activation identity changes for every PII selection, so a benchmark or
  consumer that pinned `vocabulary=pii-context/v1` sees the change instead of
  a silent behaviour difference. Credential-only activation (`selectors=off`)
  carries the new vocabulary string but scans exactly as before.
