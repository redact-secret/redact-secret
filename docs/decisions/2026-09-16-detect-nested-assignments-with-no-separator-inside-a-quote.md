---
decision_id: decision-detect-nested-assignments-with-no-separator-inside-a-quote
status: accepted
scope: workspace
title: Detect a nested contextual assignment with no separator inside an enclosing quote
decided_at: 2026-09-16
---

# Detect a nested contextual assignment with no separator inside an enclosing quote

## Decision

`generic-token`'s contextual-assignment scan (`crates/secret-scan-core/src/detectors/generic_token.rs`)
now treats a raw `"`/`'` as an assignment-prefix boundary
(`is_prefix_boundary_char`) and as a valid trailing boundary after a quoted
value's own closing quote (`is_quoted_value_boundary`), alongside the
existing whitespace and structural characters.

This is a deliberate scope decision for raw, malformed text carrying
unescaped nested quotes -- not a claim that the outer text is valid JSON,
YAML, or shell syntax. Given `value="api_key="TOKEN""`, the detector no
longer requires a separator (whitespace, `;`, `,`, `{`) between the
enclosing value's opening quote and the nested key, and no longer requires
whitespace or a structural character after the nested value's own closing
quote. The nested `api_key="TOKEN"` is recognized as its own contextual
assignment and reported at its exact inner range, the same way it already
was when a separator was present (`nested_assignments_emit_overlapping_contextual_candidates`,
`client_secret="...; api_key=..."`).

The outer `value=` wrapper is not itself a credential name, so it produces
no finding whether or not its own value-scan succeeds; the fix's effect is
scoped to the nested key by construction, not by suppressing the outer
candidate.

## Rationale

`generic-token`'s hand-ported `ASSIGNMENT_PREFIX_PATTERN` grammar requires
`(?:^|[\s{,;])` immediately before a candidate name, and its quoted-value
scan (`quoted_assignment_value`) requires whitespace or a structural
character immediately after a value's closing quote. Neither alternative
included a bare quote character. A nested key with no separator from its
enclosing quote -- the shape the daily false-positive evaluator's benchmark
exercises (redact-secret/redact-secret#294) -- therefore matched neither
rule: the nested key was never reached as a prefix, and even where it was,
its value's close was rejected because the next character was the enclosing
quote rather than whitespace.

A bare quote is already a value boundary in the immediately adjacent
`is_unquoted_value_boundary`, on the same reasoning: an unquoted value
cannot legitimately contain a stray quote, so a quote character always ends
it. Extending that reasoning to the prefix side and to the quoted-value close
is a narrow generalization, not a new heuristic: a `"`/`'` already acts as a
value delimiter throughout this detector's target syntaxes (shell quoting,
JSON string boundaries), so treating it as a legitimate place for one value
to end and the next key to begin is consistent with how `;`/`,`/`{` are
already handled.

Widening this narrowly, rather than adding a special case that recognizes
only the exact `value="key="TOKEN""` shape, keeps the fix general: it also
covers doubly-quoted values embedded without a separator in other positions,
while every existing value-content exclusion (masked/filler values, template
references, placeholder words, entropy bounds) still applies unchanged to
whatever value the wider prefix/boundary rules land on. AC2 of #294
requires this -- retaining valid quoted assignments, non-secret references,
and masked values rather than widening an *exclusion*. Regression coverage
(`a_plain_quoted_assignment_with_no_nesting_is_unaffected`,
`a_masked_value_nested_with_no_separator_inside_an_enclosing_quote_stays_excluded`,
`a_template_reference_nested_with_no_separator_inside_an_enclosing_quote_stays_excluded`)
confirms the widening only adds detection surface; it does not exclude
anything additional.

## Consequences

- A nested key immediately following a raw quote, with no separator, is now
  detected identically to the same key preceded by `;`/`,`/`{` followed by
  whitespace.
- A quoted value's own close is now valid even when immediately followed by
  another quote rather than whitespace or a structural character -- the same
  adjacency `is_unquoted_value_boundary` already treats as a boundary for
  unquoted values.
- An ordinary quoted assignment with no nested quote inside it is
  unaffected: the new prefix/boundary characters only change behavior when a
  quote is adjacent to a candidate name or a value's close, which does not
  happen for a value with no embedded `"`/`'`.
- The full behavioral surface (scan, redact, and incremental-partition
  equivalence at every byte and char boundary) is asserted against the
  canonical corpus (`decision-govern-cross-language-conformance`); no
  binding-specific or incremental-only behavior was introduced.
