---
decision_id: decision-exclude-windows-env-and-sql-bind-parameter-references
status: accepted
scope: workspace
title: Exclude cmd-style Windows environment references (`%VAR%`) and SQL named bind parameters (`:identifier`)
decided_at: 2026-09-16
---

# Exclude cmd-style Windows environment references (`%VAR%`) and SQL named bind parameters (`:identifier`)

## Decision

Add `is_windows_env_reference` and `is_sql_bind_parameter` to `generic-token`'s
non-secret reference exclusions
(`crates/secret-scan-core/src/detectors/generic_token.rs`, called from
`is_non_secret_reference` alongside the existing template, interpolation, and
secret-manager checks). Unlike those checks, which allow arbitrary content
between their delimiters, both new checks require the delimited content to
satisfy `is_env_var_identifier`'s identifier shape:

| Syntax | Grammar | Example |
| --- | --- | --- |
| cmd.exe/batch Windows environment-variable expansion | `%IDENTIFIER%` | `%DB_PASSWORD%` |
| SQL named bind parameter | `:IDENTIFIER` | `:new_password_hash` |

`%` and `:` are common punctuation on their own (a percentage-bounded range,
a URL port, a prose colon), so a bare delimiter-pair check like
`is_template_reference`'s would exclude values that merely start and end with
one. Requiring the content to look like an identifier keeps that risk low
while still matching the two reproducers in issue #292.

A value missing either delimiter, or one that carries the pair embedded
inside a larger value, does not satisfy the whole-value check and stays
detected — the same requirement `is_template_reference` and
`is_interpolation_reference` already apply.

## Rationale

`docs/decisions/2026-09-16-exclude-interpolation-command-substitution-references.md`
observed `%VAR%` cmd-style substitution in the same corpus as the
interpolation/command-substitution syntaxes it addressed, but deferred it (and
did not consider SQL bind parameters at all) so each new grammar gets its own
explicit fixture coverage rather than being folded in implicitly. Issue #292
measured both `%VAR%` and `:identifier` as contextual-secret false positives
against the published `0.1.0-beta.3` package and is the deferred follow-up.

## Consequences

- `generic_token.rs` gains `is_windows_env_reference` and
  `is_sql_bind_parameter`, called from `is_non_secret_reference`.
- A value assigned to any contextual credential name (`password`, `api_key`,
  `client_secret`, ...) that is exactly `%IDENTIFIER%` or `:IDENTIFIER` is no
  longer reported or redacted, quoted or unquoted, across all five public
  surfaces (Rust core, CLI, Python wheel, Node addon, browser WebAssembly),
  since they all share the Rust core detector. No incremental-scanner change
  was needed: `has_open_contextual_assignment`'s end-of-chunk retention hint
  only looks at the pending name/operator, not the value shape, so it is
  unaffected by which value syntaxes `is_non_secret_reference` excludes.
- Negative regression fixtures (`crates/secret-scan-core/src/detectors/generic_token.rs`)
  cover both #292 reproducers, quoted and unquoted, plus CRLF, a tab after
  the operator, and a multi-byte Unicode prefix before the assignment
  (exercising byte-offset rather than char-count boundary handling). Positive
  regression fixtures assert a value missing either delimiter, a delimited
  pair embedded in a larger value, a `%...%` value whose content is not
  identifier-shaped, and a bare identifier missing its leading colon all stay
  reported.
- Scope not covered here, left for an explicitly reviewed follow-up if
  evidenced: positional SQL bind parameters (`$1`, `?`), SQL Server-style
  `@identifier` binds, and Octopus's `#{Name}#` token-replacement syntax.
