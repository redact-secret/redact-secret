---
decision_id: decision-exclude-fully-delimited-template-references
status: accepted
scope: workspace
title: Exclude a value fully delimited by `{{` and `}}` as a template reference
decided_at: 2026-09-15
---

# Exclude a value fully delimited by `{{` and `}}` as a template reference

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
