---
decision_id: decision-exclude-fully-delimited-template-references
status: accepted
scope: workspace
title: Exclude a value fully delimited by `{{` and `}}` as a template reference
decided_at: 2026-09-15
spec: contextual-detection
aliases: decision-match-placeholder-words-on-token-boundaries, decision-contextual-assignment-stops-at-the-line, decision-exclude-unquoted-source-code-expressions-as-contextual-values, decision-exclude-secret-manager-references, decision-exclude-interpolation-command-substitution-references, decision-exclude-windows-env-and-sql-bind-parameter-references, decision-bound-azure-keyvault-secreturi-host-by-shape, decision-detect-nested-assignments-with-no-separator-inside-a-quote, decision-exclude-closed-call-code-expressions-as-contextual-values, decision-share-non-secret-reference-exclusions-with-connection-string, decision-exclude-filler-and-placeholder-bearer-values, decision-connection-string-and-jwt-need-no-retention-hint
---

# Exclude a value fully delimited by `{{` and `}}` as a template reference

This record is the representative ADR for the contextual-exclusion cluster
(issue [#599](https://github.com/redact-secret/redact-secret/issues/599),
DS6c, under epic [#591](https://github.com/redact-secret/redact-secret/issues/591)).
Its whole-value rule -- a value is excluded as a non-secret reference only
when the *entire* value satisfies a reference shape, never because it merely
starts with a marker -- is the policy every later exclusion in this cluster
applies to one more syntax, detector, or scanning boundary.
[Folded records](#folded-records) lists the 12 decisions merged into this one
under
[`decision-decide-artifact-taxonomy-spec-routing-and-evidence-placement`](2026-09-22-decide-artifact-taxonomy-spec-routing-and-evidence-placement.md)'s
Merge grade; each one's `decision_id` is preserved in this record's
`aliases:` field above, and its full original text stays reachable at its
permalink. The current, present-tense rules for every exclusion live in
[`docs/specs/contextual-detection.md`](../specs/contextual-detection.md), not
here; this record and the ones it folds explain why and when each rule was
decided. The separate warning policy,
[`decision-warn-unconditionally-on-high-signal-contextual-names`](2026-09-20-warn-unconditionally-on-high-signal-contextual-names.md),
is not folded here.

## Decision

Add `is_template_reference` to `generic-token`'s non-secret reference
exclusions (`crates/secret-scan-core/src/detectors/generic_token.rs`,
alongside `starts_with_env_reference` and `starts_with_angle_bracket_reference`
in `is_non_secret_reference`). A value is excluded when it is fully delimited
by `{{` and `}}` — `^\{\{.*\}\}$` on the whole (already quote-stripped)
assignment value, matching `{{ vault_db_password }}`,
`{{ lookup('env', 'DB_PASSWORD') }}`, `{{ pillar["postgres"]["password"] }}`,
`{{ .Values.postgresql.auth.password }}` (Helm), and `{{ .ClientSecretRef }}`
(Go templates) — the idiomatic way Ansible, Helm, Salt, and Go templates
reference a vaulted or injected value.

This mirrors the existing `${...}` and `<...>` reference exclusions in shape
(a value that is *only* a reference marker, not real content) but differs in
where the check is anchored: the env and angle-bracket exclusions are
prefix checks (`starts_with_*`), because `${VAR}` and `<placeholder>` are
already unambiguous as soon as they open. `{{` alone is not — Jinja math and
comparison expressions, Go template pipelines, and control structures also
open with `{{`, so a value must close with the matching `}}` at its exact
end, not merely start with `{{`, to be treated as a bare reference. A value
that only starts with `{{` (no closing `}}` before the value ends), or that
contains a `{{...}}` pair inside a larger string, does not satisfy the
whole-value check and stays detected.

## Rationale

The detector already treated `${...}`, `$VAR`, `process.env.*`,
`import.meta.env.*`, and `<...>` as reference syntax rather than secret
content. `{{ ... }}` is structurally the same thing for a different template
family, and was the one common form left unrecognized: a quoted Jinja/Helm/Go
reference to a vaulted value was reported as a high-confidence
`contextual_secret`, and the default `redact` policy action would rewrite the
literal template placeholder in a playbook or chart, silently corrupting it.
Unquoted `{{ ... }}` and GitHub Actions' `${{ secrets.X }}` were already
clean before this change — GitHub Actions is delimited by `${{` immediately
matching the existing `${` prefix check — so only the quoted plain-`{{ ... }}`
form needed a new exclusion.

Requiring the whole value (not merely the start) keeps the false-negative
risk low: a real secret happening to both start with `{{` and end with `}}`
across its entire span is rare, whereas a prefix-only check would have
silently excluded any secret value an attacker or template author padded
with a leading `{{`.

## Consequences

- `generic_token.rs` gains `is_template_reference`, called from
  `is_non_secret_reference` alongside the env and angle-bracket checks.
- A quoted, fully-delimited `{{ ... }}` value assigned to any contextual
  credential name (`password`, `api_key`, `client_secret`, ...) is no longer
  reported or redacted, across all five public surfaces (Rust core, CLI,
  Python wheel, Node addon, browser WebAssembly), since they all share the
  Rust core detector.
- Negative regression fixtures cover the quoted Jinja, Salt, Helm, and Go
  forms; positive regression fixtures assert a value that only starts with
  `{{`, and a value with `{{...}}` embedded inside a larger high-entropy
  string, both keep being reported.

## Folded records

Each row is a decision merged into this one (Merge grade). The `decision_id`
column is preserved verbatim in this record's `aliases:` frontmatter field so
an old reference still resolves; the permalink is the folded record's last
text on `main` before this merge, at
`ed80bc8aaa5058e11bf8b6fc43214b0194de886a`.

| Original `decision_id` | Date | Issue | Decision | Full record |
| --- | --- | --- | --- | --- |
| `decision-match-placeholder-words-on-token-boundaries` | 2026-09-15 | [#257](https://github.com/redact-secret/redact-secret/issues/257) | Match placeholder vocabulary on alphanumeric token boundaries, shared by `generic-token` and `connection-string`, with a smaller digit-suffix-tolerant word list. | [full record](https://github.com/redact-secret/redact-secret/blob/ed80bc8aaa5058e11bf8b6fc43214b0194de886a/docs/decisions/2026-09-15-match-placeholder-words-on-token-boundaries.md) |
| `decision-contextual-assignment-stops-at-the-line` | 2026-09-15 | [#262](https://github.com/redact-secret/redact-secret/issues/262), [#265](https://github.com/redact-secret/redact-secret/issues/265) | The whitespace run after a contextual assignment's operator never crosses a line terminator, so a value stays on its operator's line. | [full record](https://github.com/redact-secret/redact-secret/blob/ed80bc8aaa5058e11bf8b6fc43214b0194de886a/docs/decisions/2026-09-15-contextual-assignment-stops-at-the-line.md) |
| `decision-exclude-unquoted-source-code-expressions-as-contextual-values` | 2026-09-16 | [#278](https://github.com/redact-secret/redact-secret/issues/278) | Exclude four narrow source-code expression shapes: a listed reference root, a snake_case attribute chain, generic/subscript syntax, and a call cut short at a string literal. | [full record](https://github.com/redact-secret/redact-secret/blob/ed80bc8aaa5058e11bf8b6fc43214b0194de886a/docs/decisions/2026-09-16-exclude-unquoted-source-code-expressions-as-contextual-values.md) |
| `decision-exclude-secret-manager-references` | 2026-09-16 | [#280](https://github.com/redact-secret/redact-secret/issues/280) | Exclude seven secret-manager reference grammars (1Password, LiteLLM, GCP, vals, bank-vaults, AWS ARN, Azure Key Vault), each matched on its whole-value shape, never a bare scheme prefix. | [full record](https://github.com/redact-secret/redact-secret/blob/ed80bc8aaa5058e11bf8b6fc43214b0194de886a/docs/decisions/2026-09-16-exclude-secret-manager-references.md) |
| `decision-exclude-interpolation-command-substitution-references` | 2026-09-16 | [#279](https://github.com/redact-secret/redact-secret/issues/279) | Exclude fully delimited `$(...)`, `$[...]`, `#{...}`, `{env:...}`/`{file:...}`, and backtick values, scanning an unquoted value to its delimiter's balanced close. | [full record](https://github.com/redact-secret/redact-secret/blob/ed80bc8aaa5058e11bf8b6fc43214b0194de886a/docs/decisions/2026-09-16-exclude-interpolation-command-substitution-references.md) |
| `decision-exclude-windows-env-and-sql-bind-parameter-references` | 2026-09-16 | [#292](https://github.com/redact-secret/redact-secret/issues/292) | Exclude `%IDENTIFIER%` and `:IDENTIFIER` only when the delimited content is identifier-shaped. | [full record](https://github.com/redact-secret/redact-secret/blob/ed80bc8aaa5058e11bf8b6fc43214b0194de886a/docs/decisions/2026-09-16-exclude-windows-env-and-sql-bind-parameter-references.md) |
| `decision-bound-azure-keyvault-secreturi-host-by-shape` | 2026-09-16 | [#293](https://github.com/redact-secret/redact-secret/issues/293) | Accept any FQDN-shaped host in a Key Vault `SecretUri=` reference instead of the literal `.vault.azure.net` suffix. | [full record](https://github.com/redact-secret/redact-secret/blob/ed80bc8aaa5058e11bf8b6fc43214b0194de886a/docs/decisions/2026-09-16-bound-azure-keyvault-secreturi-host-by-shape.md) |
| `decision-detect-nested-assignments-with-no-separator-inside-a-quote` | 2026-09-16 | [#294](https://github.com/redact-secret/redact-secret/issues/294) | Treat a raw quote as an assignment-prefix boundary and as a valid close after a quoted value, so a nested assignment inside an enclosing quote is detected. | [full record](https://github.com/redact-secret/redact-secret/blob/ed80bc8aaa5058e11bf8b6fc43214b0194de886a/docs/decisions/2026-09-16-detect-nested-assignments-with-no-separator-inside-a-quote.md) |
| `decision-exclude-closed-call-code-expressions-as-contextual-values` | 2026-09-20 | [#467](https://github.com/redact-secret/redact-secret/issues/467) | Exclude a complete identifier-chain call expression, and (unquoted only) a call cut short inside its arguments. | [full record](https://github.com/redact-secret/redact-secret/blob/ed80bc8aaa5058e11bf8b6fc43214b0194de886a/docs/decisions/2026-09-20-exclude-closed-call-code-expressions-as-contextual-values.md) |
| `decision-share-non-secret-reference-exclusions-with-connection-string` | 2026-09-20 | [#469](https://github.com/redact-secret/redact-secret/issues/469) | Move `generic-token`'s interpolation and environment-reference predicates into `super::text` and apply them to `connection-string`'s password. | [full record](https://github.com/redact-secret/redact-secret/blob/ed80bc8aaa5058e11bf8b6fc43214b0194de886a/docs/decisions/2026-09-20-share-non-secret-reference-exclusions-with-connection-string.md) |
| `decision-exclude-filler-and-placeholder-bearer-values` | 2026-09-20 | [#468](https://github.com/redact-secret/redact-secret/issues/468) | Apply repeated-character filler and whole-value placeholder vocabulary exclusions to `bearer-token`, matching `Basic`/`Token`. | [full record](https://github.com/redact-secret/redact-secret/blob/ed80bc8aaa5058e11bf8b6fc43214b0194de886a/docs/decisions/2026-09-20-exclude-filler-and-placeholder-bearer-values.md) |
| `decision-connection-string-and-jwt-need-no-retention-hint` | 2026-09-20 | [#480](https://github.com/redact-secret/redact-secret/issues/480) | `connection-string` and `jwt` get no incremental retention hint: their excluded values cannot span a line, and detection only runs on closed lines. | [full record](https://github.com/redact-secret/redact-secret/blob/ed80bc8aaa5058e11bf8b6fc43214b0194de886a/docs/decisions/2026-09-20-connection-string-and-jwt-need-no-retention-hint.md) |
