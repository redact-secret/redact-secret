---
decision_id: decision-define-the-pii-context-vocabulary-contract
status: accepted
scope: workspace
title: Define the versioned English and Korean PII context vocabulary contract
decided_at: 2026-09-26
spec: contextual-detection
---

# Define the versioned English and Korean PII context vocabulary contract

## Context

Issue [#793](https://github.com/redact-secret/redact-secret/issues/793)
requires English and Korean context to share one evidence contract without
making language part of identifier grammar or adding a Korean-only engine.
Keywords can reinforce or negate sensitivity only after identity evidence has
associated a candidate.

## Decision

The live `pii-context/v1` contract is
[`docs/contracts/pii/pii-context-v1.json`](../contracts/pii/pii-context-v1.json),
validated against its adjacent schema by
`scripts/check-pii-context-contract.py`. It contains the initial synthetic
English and Korean vocabulary, normalization and association fixtures, and
benign ambiguity controls. It is contract/evaluation input only; no runtime
detector loads it yet.

Every entry declares language (`en` or `ko`), kind (`field-label` or
`natural-language-label`), semantic class (`positive`, `neutral`, or
`negative`), strength (`high-signal` or `ambiguous`), applicable identity
domains, authored forms, and provenance. Both languages feed the shared
`contextual` evidence group. A match never establishes identity, and an
ambiguous match cannot alone change sensitivity from `not-established`.

Matching uses a context-only view: remove governed invisible characters,
normalize to NFC, ASCII-case-fold English, and tokenize on whitespace,
underscore, hyphen, colon, and equals. Korean has no case transform. Candidate
bytes, ranges, and identifier grammar never change.

Association is bounded to one logical line and 64 Unicode scalar values in the
normalized comparison view from the nearest candidate boundary. It never
crosses another PII candidate.
`field-label` entries precede the candidate, are at most 16 scalars away, and
permit only declared separators and quotes in the gap. `natural-language-label`
entries may occur on either side within the 64-scalar window. A context match
equidistant from two candidates associates with neither.

Overlapping vocabulary matches use longest normalized span measured in Unicode
scalars, then `high-signal` over `ambiguous`, then `negative` over `positive`
over `neutral`, then lexical entry id. Non-overlapping matches are retained;
this precedence chooses a lexical match and does not override aggregation.

Future languages are additive reviewed `pii-context/v1` data. A contribution
must add positive, benign/ambiguity, normalization, separator, and no-real-PII
fixtures and prove identifier type semantics are unchanged. It adds no scoring
engine, translation service, automatic language detection, or locale-specific
detector fork. A semantic schema or matching change requires a new version.

## Consequences

English and Korean now have an inspectable shared contract and deterministic
synthetic examples, while runtime use remains blocked on detector and engine
implementation. Korean vocabulary does not imply Korean national-ID support,
and a national-ID family does not imply language detection.
