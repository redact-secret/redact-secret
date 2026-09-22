---
decision_id: decision-share-non-secret-reference-exclusions-with-connection-string
status: accepted
scope: workspace
title: Share generic-token's interpolation and environment-reference exclusions with connection-string's password check
decided_at: 2026-09-20
spec: contextual-detection
---

# Share generic-token's interpolation and environment-reference exclusions with connection-string's password check

## Decision

Move the non-secret-reference predicates `generic-token` already applies to a
contextual `password = "..."` assignment into `super::text` as `pub(super)`
functions, and call the relevant subset from
`connection_string::is_placeholder`:

| Predicate | Syntax | Example |
| --- | --- | --- |
| `starts_with_bare_dollar_reference` (new, split out of `starts_with_env_reference`) | `$IDENTIFIER` | `$DB_PASSWORD`, `$env:DB_PASSWORD` (PowerShell's `env:` provider is itself a valid identifier-start run) |
| `is_command_substitution_reference` | `$( ... )` | `$(db_password)` |
| `is_template_reference` | `{{ ... }}` | `{{ db_password }}` |
| `is_ruby_interpolation_reference` | `#{ ... }` | `#{ENV['DB_PASSWORD']}` |
| `is_opencode_reference` | `{env: ... }` / `{file: ... }` | `{env:DB_PASSWORD}` |
| `is_windows_env_reference` | `%IDENTIFIER%` | `%DB_PASSWORD%` |

`connection_string.rs` keeps its own existing `${...}` whole-value check
(requiring a closing `}`) unchanged rather than adopting
`starts_with_env_reference`'s looser `${`-prefix branch, so this does not
broaden that already-correct behavior.

`text.rs` also gains `is_fully_delimited`, `OPENCODE_REFERENCE_KINDS`, and
`is_env_var_identifier` as the shared building blocks these predicates and
`generic_token`'s remaining local checks (`is_runtime_expression_reference`,
`is_backtick_reference`, `is_sql_bind_parameter`) depend on.

## Rationale

`connection_string::is_placeholder` recognized only the braced `${...}`
interpolation form. `generic-token` already excluded the bare shell form
(`$DB_PASSWORD`), the command-substitution form (`$(...)`), and the
PowerShell form (`$env:VAR`) for the identical value assigned to a
`password` field (issues #279, #292) — but `connection-string` has its own
hardcoded placeholder logic and never reached those predicates. A connection
URL whose password is an environment-variable reference (the default idiom
in `docker-compose.yml`, `.env` templates, Kubernetes manifests, and CI
configuration) was classified `high` and redacted, rewriting working
configuration (issue #469).

Several other forms (`{{...}}`, `#{...}`, `{env:...}`, `%VAR%`) already
produced no finding, but only by accident: `has_valid_userinfo_encoding`
rejects `{`, `}`, and an invalid `%` escape, and `#` is an authority
terminator that truncates the scan before it ever reaches `@`. A future
change to userinfo parsing or percent-encoding tolerance could silently turn
any of these into false positives without a single test failing, since
nothing currently asserts the exclusion is intentional. Sharing the same
predicates `generic-token` already maintains, rather than reimplementing an
independent subset, closes that gap and keeps the two detectors from
drifting on what counts as a non-secret reference for the identical value
shape.

Sharing through `super::text` (already how `is_repeated_character_filler`
and `matches_placeholder_vocabulary` are shared between these two detectors,
see #256/#264) was chosen over duplicating the predicates in
`connection_string.rs`, so a future change to any of these grammars only
needs to happen once.

## Consequences

- `text.rs` gains `is_fully_delimited`, `is_template_reference`,
  `is_command_substitution_reference`, `is_ruby_interpolation_reference`,
  `OPENCODE_REFERENCE_KINDS`, `is_opencode_reference`,
  `starts_with_bare_dollar_reference`, `is_env_var_identifier`, and
  `is_windows_env_reference`, all `pub(super)` (or `pub(super) const` for
  `OPENCODE_REFERENCE_KINDS`, which `generic_token::starts_with_opencode_prefix`
  also reads directly).
- `generic_token.rs`'s `starts_with_env_reference`, `is_interpolation_reference`,
  and the windows-env/SQL-bind-parameter exclusions now call the shared
  functions instead of defining them locally; behavior is unchanged, and its
  own regression tests (`interpolation_and_command_substitution_references_are_excluded`,
  `windows_env_and_sql_bind_parameter_references_are_excluded`, and their
  CRLF/tab/Unicode variants) still pass unmodified.
- `connection_string.rs` gains `is_interpolation_or_env_reference`, called
  from `is_placeholder` alongside the existing `${...}`, repeated-character-
  filler, and fill-in-prose checks. A password that is `$VAR`, `$(...)`,
  `$env:VAR`, `{{...}}`, `#{...}`, `{env:...}`/`{file:...}`, or `%VAR%` is no
  longer reported or redacted, across all five public surfaces (Rust core,
  CLI, Python wheel, Node addon, browser WebAssembly), since they all share
  this Rust core detector.
- Negative unit-test fixtures in `crates/secret-scan-core/src/detectors/connection_string.rs`
  cover every row of issue #469's reproduction table, including the four
  forms that were previously clean only by parse-failure accident. Paired
  positive fixtures assert a real-looking password, a password starting with
  `$` but not shaped like a recognized reference (a digit rather than an
  identifier-start character after it), a password merely containing `$`,
  and an unterminated `$(...)` opener all stay reported. A byte-by-byte
  incremental-vs-whole-input parity test
  (`connection_string_interpolation_references_agree_between_whole_input_and_incremental`,
  `crates/secret-scan-core/tests/incremental.rs`) covers the new exclusions;
  `connection_string` has no incremental-specific retention hint comparable
  to `generic_token`'s `has_open_contextual_assignment`, so no incremental
  wiring change was needed for this to hold.
- **Accepted false-negative risk**, unchanged from what `generic-token`
  already accepts for the identical values: a literal password that happens
  to both open and close one of these delimiter pairs across its entire span
  is rare and judged an acceptable tradeoff; a password merely starting with
  `$`, or containing one of these delimiters without spanning the whole
  value, stays detected. The `$(...)` form carries marginally more risk than
  bare `$VAR` since a real password could contain parentheses, but it must
  *begin* with `$(` and *end* with `)` to qualify.
- **Known residual, out of scope.** `#{...}` and `{{...}}`/`{env:...}` (when
  the password contains no embedded `@`) reach `is_placeholder` and are now
  excluded there explicitly, but a password containing `#` as its very first
  character still cannot reach `is_placeholder` for a different structural
  reason: `is_authority_terminator` treats `#` as an authority terminator, so
  the authority scan truncates before it ever finds the credential's `@`.
  That boundary predates this issue and is unrelated to placeholder
  detection; widening it is not part of this change.
