---
decision_id: decision-normalize-invisible-characters-before-detection
status: accepted
scope: workspace
title: Normalize invisible characters before detection
decided_at: 2026-09-19
---

# Normalize invisible characters before detection

## Context

Issue [#438](https://github.com/redact-secret/redact-secret/issues/438)
identified that a credential split by zero-width or other invisible code
points (`ghp_SYNTHETIC<ZWNJ>REVOKED…`) defeats every detector grammar in this
crate, because `ARCHITECTURE.md:147-149` states the core does not normalize
or decode input before detection. The design research behind this decision
(recorded in the issue #438 discussion) found that the reference competitor
this product tracks parity against normalizes exactly five code points
(`U+200B U+200C U+200D U+2060 U+FEFF`) and that no other secret scanner in
that survey normalizes at all. It also found a documented, actively exploited
attack class — ASCII smuggling via the Unicode Tags block, reported by
Microsoft as reaching millions of messages per day — that a five-code-point
set does not cover, alongside Trojan Source bidi controls, variation
selectors, and Hangul filler characters.

This record exists to fix the architecture and the decision *before* any
implementation lands, per this repository's convention that a reversal of a
stated architectural decision needs its ADR first. It does not itself change
code; issue #438 implements it.

## Decision

The core removes zero-rendering and format code points into a scan copy
before detection and reports every range into the original input. It does
not case-fold, apply NFKC, decode, or unescape.

### The code-point set is derived, not curated

The removed set is `Default_Ignorable_Code_Point ∪ Cf`, generated from a
pinned Unicode Character Database (UCD) version — UCD 17.0.0, the latest
stable release available when this decision was made — rather than an
enumerated list. An enumerated list is a standing precision argument that has
to be relitigated every time another invisible character is found; a derived
set is a property of the standard, auditable and reproducible from a version
number, and it moves the maintenance burden to a UCD version bump instead of
a design discussion.

The UCD derivation for `Default_Ignorable_Code_Point` is:

```
Default_Ignorable_Code_Point =
    Other_Default_Ignorable_Code_Point
  + Cf (Format)
  + Variation_Selector
  - White_Space
  - FFF9..FFFB          (interlinear annotation)
  - 13430..1343F        (Egyptian hieroglyph format controls)
  - Prepended_Concatenation_Mark
```

Taking the union with `Cf` adds back the three subtracted format classes, so
the result is exactly "every code point that renders nothing, plus every
format control." It is a strict superset of the reference competitor's
five-code-point set and includes, among others, the Trojan Source bidi
controls (`U+061C`, `U+200E..200F`, `U+202A..202E`, `U+2066..2069`), the
Unicode Tags block used for ASCII smuggling (`U+E0000..E007F`), variation
selectors (`U+FE00..FE0F`, `U+E0100..E01EF`), and the Hangul filler
characters (`U+115F`, `U+1160`, `U+3164`, `U+FFA0`).

The removed set is derived from a pinned UCD snapshot checked into the core
crate as generated data, consistent with the crate's zero-runtime-dependency
policy (`docs/rust-workspace.md`); it is not fetched or computed against a
Unicode library at build or run time.

### v1 exclusions, and why

The following are explicitly out of scope for this decision, each for a
distinct reason:

- **`U+00A0` and the space family (`U+2000..U+200A`, `U+3000`)** — these
  render as space. Folding them into an ASCII space changes `name = value`
  tokenization and is a whitespace-folding decision, not an invisibility
  decision. It needs its own precision review.
- **`U+2800 BRAILLE PATTERN BLANK`** — renders blank but its General
  Category is `So` (Symbol, other), not `Cf` or `Default_Ignorable`.
  Including it by exception would break the "derived, not curated" property
  for the sake of one character. It is considered and excluded, not
  overlooked.
- **Confusables and homoglyphs (UTS #39)** — a skeleton-matching problem,
  not a removal problem, with its own false-positive cost. It needs its own
  design and issue, and supersedes the `google-boundary-unicode-lookalike-prefix`
  fixture presently marked `intentionally-unsupported`.
- **NFKC normalization, case folding, and base64/percent/backslash
  decoding** — unchanged. None of these are invisibility; each changes
  lexical meaning in ways this decision does not cover.

### Span translation rule

A finding's range is translated from normalized coordinates back to the
original input by mapping `start` to the original offset of the same
character, and `end` to the original offset immediately after the last
*included* character. Because removal is monotonic and order-preserving,
this makes any removed character strictly *inside* a match automatically
part of the reported span: `ghp_SYNTHETIC<ZWNJ>REVOKED…` redacts as one
placeholder, with no orphaned invisible character left in the output.

Removed characters merely *adjacent* to a match boundary (for example,
`Bearer <ZWSP>SYNTHETIC…`) are **not** absorbed into the span in v1.
Absorbing them would widen spans in a way that could change the
narrower-span overlap tie-break the core already uses to resolve competing
candidates, and would weaken the invariant that redaction replaces exactly
the reported range. A stray invisible character next to a placeholder is a
minor residual, not a correctness defect, and closing it is left to a
separate future option rather than folded into this decision.

### `redact()` with caller-supplied ranges

Unchanged, and explicitly reaffirmed here: ranges supplied directly to the
redaction API are interpreted against the **original** input, exactly as
today. A caller-supplied range that starts or ends on a removed character is
still a valid, character-aligned range into the original string, so no new
validation or error path is introduced by this decision.

### Incremental sanitization

Normalization must not change which chunk boundaries are safe to emit at.
No code point in the removed set is `\n` or `\r`, and the incremental
sanitizer only normalizes and scans a complete retained unit at a boundary
it has already decided is safe on other grounds — so normalization cannot
move, create, or destroy a unit boundary, and partition equivalence (the
same findings regardless of how input is chunked) holds by construction. The
one place this requires care rather than being automatic is buffered-but-not-yet-scanned
lookahead: whether a still-open lexical construct is recognized as open must
use the same normalized view of the retained text that the eventual scan
will use, or a construct split by an invisible character at a chunk boundary
could be judged closed too early.

## Consequences

This decision supersedes the "does not normalize or decode" paragraph at
`ARCHITECTURE.md:147-149` and the pipeline diagram it sits under; both are
updated in this same change. It authorizes, but does not itself perform, the
implementation in issue #438: a new zero-dependency `normalize` module in
`crates/secret-scan-core`, a generated and checked-in code-point range table
pinned to UCD 17.0.0, translation of every candidate range back to original
coordinates before ranking and redaction, an `Obfuscation` signal on findings
when a removed character falls strictly inside a reported range, and
conformance fixtures — including incremental fixtures with a removed code
point at a chunk boundary, and negative controls for legitimate use of
`U+200C`/`U+200D` in Persian and Hindi text and `U+00AD` in hyphenated HTML —
covering all of the above. Detectors themselves do not change: they continue
to run unmodified against a normalized scan copy.
