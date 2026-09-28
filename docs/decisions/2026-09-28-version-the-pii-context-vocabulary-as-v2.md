---
decision_id: decision-version-the-pii-context-vocabulary-as-v2
status: accepted
scope: workspace
title: Version the PII context vocabulary as pii-context/v2 with forward-only field labels and ASCII case folding in every language
decided_at: 2026-09-28
spec: contextual-detection
---

# Version the PII context vocabulary as pii-context/v2 with forward-only field labels and ASCII case folding in every language

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

v2 changes two matching rules. First, equidistance is judged only among the
candidates an occurrence could associate with:

- a `field-label` match (`association.fieldLabel.equidistanceAmong:
  following-candidates`) counts only candidates after it, so an earlier
  candidate on the same line never makes it equidistant; and
- a `natural-language-label` match, which may associate on either side,
  keeps the two-sided rule (`candidates-on-either-side`), so
  `A contact details B` still associates with neither.

Second, the comparison view folds ASCII case in every language
(`normalization.koreanCase: ascii-lower`), not only in English
([#927](https://github.com/redact-secret/redact-secret/issues/927)). Hangul
has no case, so Korean text is unchanged, but the ASCII part of a Korean form
(`ip 주소`, `클라이언트 ip`, `iban`) now matches `IP 주소` or `클라이언트_IP`.
Under v1 the same label matched only in lowercase.

v2 also adds reviewed forms as ordinary vocabulary data: `email address`,
`e-mail address`, `이메일 주소`, and the unspaced Korean card labels
`카드번호`, `신용카드번호`, and `직불카드번호`. Additions like these would be
additive data under any version; they are listed here because they arrive
with v2.

Alternatives of different identity domains at one exact range are one
occurrence, not two candidates
([#922](https://github.com/redact-secret/redact-secret/issues/922)). Every
other v1 rule stands: normalization, the 16- and 64-scalar bounds, the
field-gap rule, candidate barriers, domain filtering, and precedence.
Normalization is still comparison-only: candidate bytes, ranges, and
identifier grammar never change.

## Consequences

- False negatives removed: every labelled value after the first on a logfmt,
  `k: v k: v`, or `a=… b=…` line, within and across families.
- False positives: association alone adds none. Each value still needs its
  own family's reviewed high-signal label directly in front of it, separated
  only by declared separators and quotes, and a label of another domain
  still cannot reach it.
- Case folding and the added forms remove the false negatives of common
  spellings (`IP 주소:`, `email address:`, `카드번호:`) and add no new
  authority: each form is a positive high-signal field label of exactly one
  domain, bounded by the same field-gap and distance rules, and identity is
  still required.
- The activation identity changes for every PII selection, so a benchmark or
  consumer that pinned `vocabulary=pii-context/v1` sees the change instead of
  a silent behaviour difference. Credential-only activation (`selectors=off`)
  carries the new vocabulary string but scans exactly as before.
