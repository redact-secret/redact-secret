---
decision_id: decision-contextual-assignment-stops-at-the-line
status: accepted
scope: workspace
title: A contextual assignment's value never crosses a line terminator
decided_at: 2026-09-15
---

# A contextual assignment's value never crosses a line terminator

## Decision

`generic-token`'s hand-ported `ASSIGNMENT_PREFIX_PATTERN` grammar
(`parse_name_and_operator`,
`crates/secret-scan-core/src/detectors/generic_token.rs`) no longer mirrors
the ECMAScript oracle's `\s*` literally for the whitespace run *after* the
`=`/`:` operator. That run now uses a new `is_horizontal_js_whitespace`
predicate (`detectors/text.rs`) — everything `is_js_whitespace` matches
except a line terminator (`\n`, `\r`, `U+2028`, `U+2029`) — instead of
`is_js_whitespace` itself. The whitespace run *before* the operator (between
the name and the operator) is unchanged and still crosses line terminators:
an incremental caller's chunk boundary can legitimately fall between a name
and its operator (`api_key\n` held open, `=SYNTHETIC_...\n` resolving it,
asserted by `crates/secret-scan-core/tests/incremental.rs`'s
`a_contextual_assignment_name_without_its_operator_stays_open`), and that
shape is unrelated to this bug: the value in that case still lands entirely
on the operator's own physical line.

An operator's value stays on the operator's own physical line. A key with no
value before end-of-line — a YAML key opening a nested block
(`secret:\n  secretName: ...`), an interactive `Password:` prompt with no
value at all — no longer walks onto the next line's first token and reports
it as the "value".

## Rationale

`is_js_whitespace` includes `\n`/`\r` because it mirrors ECMAScript's `\s`
class outside Unicode mode, which the rest of this hand-written grammar
otherwise faithfully ports. But `\s*` crossing a line terminator here is not
a faithful port of anything meaningful: no valid YAML scalar, JSON value, or
shell/env assignment places its value on the line after `:`/`=`. The daily
false-positive evaluator (run 2026-09-15, categories: YAML configuration,
terminal output) found this produced real findings — `medium`/`warn` up to
`high`/`redact` — against Kubernetes `secret:` volume blocks, OpenAPI
`password:` properties followed by a nested `description:`, and `docker
login`/`ssh` transcripts where a `Password:` prompt is followed by the
program's own denial message on the next line. None of the three carry any
credential; the captured "value" was always a subsequent line's key name or
diagnostic text (redact-secret/redact-secret#262).

The same over-eager skip was also a *recall* bug (redact-secret/redact-secret#265):
consuming through the next line's key text advanced the scan cursor past
that key's own boundary character, so `database:\n  password: <value>` never
matched `password` as its own assignment and produced no finding at all.
Stopping the skip at the line terminator fixes both: the outer key's
value-scan now fails immediately (the first character it would consume is
the line terminator itself, which is already a value-boundary character), so
the cursor is left where it was, and the nested `password:` key is reached
and matched normally on a later iteration.

## Consequences

- A contextual-assignment value can never span a line terminator, in both
  whole-input and incremental scanning (incremental mode eventually runs the
  same whole-input grammar over its retained buffer once a unit closes, so
  no separate fix was needed there).
- `password: <value>` and other same-line forms are unaffected: horizontal
  whitespace (spaces, tabs, and other non-line-terminator `White_Space` code
  points) after the operator still skips exactly as before, and the
  whitespace run before the operator is untouched.
- False-negative risk is low and intentional: a credential is never validly
  expressed on the line after its key in any of the source formats this
  detector targets. Committed cross-language negative fixtures cover the
  YAML nested-block, blank-line, CRLF, and login/ssh-prompt shapes; a
  positive regression fixture covers the nested-key recall case.
