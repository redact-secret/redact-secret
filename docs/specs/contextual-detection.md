# Contextual detection

Rules governing how a contextual assignment (`name = value`) is parsed, scoped, and excluded from generic-token and related context-driven detectors.

> Generated for [issue #597](https://github.com/redact-secret/redact-secret/issues/597) (DS6a). Each rule
> below states current behavior in the present tense and links the ADR
> (`docs/decisions/`) that decided it. An ADR records why and when; this file
> records what is true now. Per
> [`decision-decide-artifact-taxonomy-spec-routing-and-evidence-placement`](../decisions/2026-09-22-decide-artifact-taxonomy-spec-routing-and-evidence-placement.md),
> a decision that applies an existing policy to one more provider family or
> one more instance is a row here plus its supporting evidence, not a new
> ADR.

## Rules

| Rule | Governing ADR |
| --- | --- |
| A contextual assignment's value never crosses a line terminator. | [A contextual assignment's value never crosses a line terminator](../decisions/2026-09-15-contextual-assignment-stops-at-the-line.md) |
| A value fully delimited by `{{` and `}}` is excluded as a template reference, not flagged as a literal secret. | [Exclude a value fully delimited by `{{` and `}}` as a template reference](../decisions/2026-09-15-exclude-fully-delimited-template-references.md) |
| Placeholder vocabulary (for example `changeme`, `xxxx`) is matched on token boundaries, not by exact-string equality against the whole value. | [Match placeholder words on token boundaries, not exact-string equality](../decisions/2026-09-15-match-placeholder-words-on-token-boundaries.md) |
| An Azure Key Vault `SecretUri` reference is excluded by host shape, not by exact domain identity. | [Bound the Azure Key Vault SecretUri reference by host shape, not domain identity](../decisions/2026-09-16-bound-azure-keyvault-secreturi-host-by-shape.md) |
| A nested contextual assignment with no separator, inside an enclosing quote, is still detected. | [Detect a nested contextual assignment with no separator inside an enclosing quote](../decisions/2026-09-16-detect-nested-assignments-with-no-separator-inside-a-quote.md) |
| Interpolation and command-substitution references beyond `${...}`, `$name`, and `{{...}}` are excluded as contextual values. | [Exclude interpolation and command-substitution references beyond `${...}`, `$name`, and `{{...}}`](../decisions/2026-09-16-exclude-interpolation-command-substitution-references.md) |
| A reference string that a secret manager resolves at runtime, not a literal secret, is excluded. | [Exclude secret-manager reference strings resolved at runtime](../decisions/2026-09-16-exclude-secret-manager-references.md) |
| An unquoted source-code expression is excluded from generic-token's contextual values. | [Exclude unquoted source-code expressions from generic-token's contextual values](../decisions/2026-09-16-exclude-unquoted-source-code-expressions-as-contextual-values.md) |
| A Windows cmd-style environment reference (`%VAR%`) and a SQL named bind parameter (`:identifier`) are excluded. | [Exclude cmd-style Windows environment references (`%VAR%`) and SQL named bind parameters (`:identifier`)](../decisions/2026-09-16-exclude-windows-env-and-sql-bind-parameter-references.md) |
| A closed-call source-code expression is excluded from generic-token's contextual values. | [Exclude closed-call source-code expressions from generic-token's contextual values](../decisions/2026-09-20-exclude-closed-call-code-expressions-as-contextual-values.md) |
| generic-token's interpolation and environment-reference exclusions are shared with connection-string's password check. | [Share generic-token's interpolation and environment-reference exclusions with connection-string's password check](../decisions/2026-09-20-share-non-secret-reference-exclusions-with-connection-string.md) |
| A high-signal contextual name (for example `password =`, `api_key =`) still warns unconditionally, even though it costs some prose false positives. | [Warn unconditionally on high-signal contextual-name assignments despite prose false positives](../decisions/2026-09-20-warn-unconditionally-on-high-signal-contextual-names.md) |

