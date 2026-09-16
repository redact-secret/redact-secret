---
decision_id: decision-exclude-interpolation-command-substitution-references
status: accepted
scope: workspace
title: Exclude interpolation and command-substitution references beyond `${...}`, `$name`, and `{{...}}`
decided_at: 2026-09-16
---

# Exclude interpolation and command-substitution references beyond `${...}`, `$name`, and `{{...}}`

## Decision

Add `is_interpolation_reference` to `generic-token`'s non-secret reference
exclusions (`crates/secret-scan-core/src/detectors/generic_token.rs`,
alongside `is_template_reference` and `is_secret_manager_reference` in
`is_non_secret_reference`). A value is excluded when it is fully delimited by
one of these syntaxes end to end, matching `is_template_reference`'s
whole-value shape rather than a prefix check:

| Syntax | Grammar | Example |
| --- | --- | --- |
| POSIX/shell, Makefile, Kustomize variable or command substitution | `$( ... )` | `$(registryPassword)`, `$(pass show db/prod)` |
| Azure Pipelines runtime expression | `$[ ... ]` | `$[variables.x]` |
| Ruby string interpolation | `#{ ... }` | `#{ENV['DB_PASSWORD']}` |
| opencode config substitution | `{env: ... }` / `{file: ... }` | `{env:ANTHROPIC_API_KEY}` |
| Backtick command substitution / JS template literal | `` ` ... ` `` | `` `${process.env.X}` ``, `` `date +%s` `` |

As with `{{...}}`, a value that only starts with an opener, or that carries a
delimited pair embedded inside a larger string, does not satisfy the
whole-value check and stays detected.

### Delimited-span scanning

Two of these closing delimiters (`)`,`]`) or lack of one (a backtick is not a
generic boundary character at all) interact badly with
`unquoted_assignment_value`'s existing boundary scan, which stops at `}` or
`]` as a generic value terminator (issue #266) and does not treat a backtick
as a value character with any special meaning. Scanning
`$[variables.x]` or `` `${process.env.X}` `` unquoted with that scan alone
truncates the captured value one byte short of its real close (before the
`]`, or before the closing backtick, respectively), so the whole-value check
never sees the true end and never excludes it.

`unquoted_assignment_value` now tries `delimited_reference_value` first: if
the value opens with `$(`, `$[`, `#{`, `{env:`, `{file:`, or a backtick, it
scans to that opener's matching close (honoring nesting for the
bracket/brace/paren forms, so `$(echo $(date))` resolves to its outer close;
honoring backslash-escaped backticks by parity, like `quoted_assignment_value`
already does for `"`/`'`) instead of stopping at the first generic boundary
character. `{env:...}`/`{file:...}` are exempt from the existing
`{`/`[`-opens-a-flow-structure guard (issue #266) for the same reason: their
delimited scan already establishes they are a bounded reference, not an
opened YAML/JSON flow structure. If the delimited scan does not find a
balanced close before a line terminator or the shared length bound, it falls
through to the plain boundary scan unchanged, so a truncated or unterminated
opener behaves exactly as it did before this change.

A quoted value (`"..."`/`'...'`) never needed this: `quoted_assignment_value`
already scans to the real closing quote regardless of `}`/`]` appearing
inside, so none of the four reproducers in issue #279 that happen to be
quoted were ever truncated.

## Rationale

The detector already treated `${...}`, `$VAR`, `process.env.*`,
`import.meta.env.*`, `<...>`, `{{...}}`, and a set of secret-manager
reference schemes as pointers to a runtime-resolved value rather than secret
content. The daily false-positive evaluator (2026-09-16) found the same
class of false positive for five more interpolation/command-substitution
syntaxes, all at high confidence with the default `redact` action —
rewriting Azure Pipelines definitions, shell scripts, Ruby/Rails configs,
opencode tool configs, and JS source.

Requiring the whole value (not merely the start) keeps the false-negative
risk low, exactly as for `{{...}}`: a real secret happening to both open and
close with one of these delimiter pairs across its entire span is rare,
whereas a prefix-only check would silently exclude any secret value an
attacker or config author padded with a leading `$(`, `#{`, or similar.

Octopus's `#{Name}#` token-replacement syntax (opening `#{`, closing `}#`)
and `%VAR%` cmd-style substitution are intentionally out of scope here: they
were observed in the same corpus but are not part of this issue's
reproducers, and adding them is deferred to a follow-up so each new grammar
gets its own explicit fixture coverage rather than being folded in
implicitly.

## Consequences

- `generic_token.rs` gains `is_interpolation_reference` (and its five
  constituent checks), called from `is_non_secret_reference` alongside the
  template and secret-manager checks.
- `unquoted_assignment_value` gains a delimited-span pre-scan
  (`delimited_reference_value`, `scan_nested_delimiter`,
  `scan_backtick_delimiter`) so `$[...]` and backtick-quoted values are
  captured to their true close instead of a generic boundary character.
- A value assigned to any contextual credential name (`password`, `api_key`,
  `client_secret`, ...) that is fully delimited by one of the five syntaxes
  above is no longer reported or redacted, quoted or unquoted, across all
  five public surfaces (Rust core, CLI, Python wheel, Node addon, browser
  WebAssembly), since they all share the Rust core detector.
- Negative regression fixtures cover all four `#279` reproducers plus the
  `$[...]` and backtick forms that exercise the span fix, including CRLF,
  tab-after-operator, and a JSON-escaped-quote variant. Positive regression
  fixtures assert a value that only starts with a delimiter, or that carries
  one embedded inside a larger value, keeps being reported.
