---
decision_id: decision-exclude-secret-manager-references
status: accepted
scope: workspace
title: Exclude secret-manager reference strings resolved at runtime
decided_at: 2026-09-16
---

# Exclude secret-manager reference strings resolved at runtime

## Decision

Add `is_secret_manager_reference` to `generic-token`'s non-secret reference
exclusions (`crates/secret-scan-core/src/detectors/generic_token.rs`,
alongside `starts_with_env_reference` and `is_template_reference` in
`is_non_secret_reference`). A value is excluded when it satisfies one of
seven per-scheme grammars, each requiring the *whole* value to match that
scheme's actual reference shape rather than merely start with its prefix:

| Scheme | Grammar | Example |
| --- | --- | --- |
| 1Password | `op://<vault>/<item>/<field>` — exactly three non-empty, path-safe segments | `op://Engineering/db-prod/password` |
| LiteLLM | `os.environ/<VAR_NAME>` — a bare environment-variable identifier | `os.environ/ANTHROPIC_API_KEY` |
| GCP Secret Manager | `projects/<id>/secrets/<name>(/versions/<v>)?` — a valid project id, secret-id charset, and `<v>` either `latest` or digits-only | `projects/example-project/secrets/api-key/versions/latest` |
| vals | `ref+<backend>://<path>#<key>` — a lowercase/digit/hyphen backend name, then a `#`-delimited path and key | `ref+vault://secret/data/db-prod#/password` |
| bank-vaults / Vault Agent injector | `vault:<path>#<key>(#<version>)?` | `vault:secret/data/db-prod#password` |
| AWS Secrets Manager | `arn:aws(-cn\|-us-gov):secretsmanager:<region>:<12-digit account id>:secret:<name>` | `arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/db/password-Ab12Cd` |
| Azure App Service / Functions Key Vault | `@Microsoft.KeyVault(SecretUri=<https vault URI>)` or `@Microsoft.KeyVault(VaultName=...;SecretName=...[;SecretVersion=...])` | `@Microsoft.KeyVault(SecretUri=https://myvault.vault.azure.net/secrets/mysecret/abc123)` |

An absolute SSM parameter path (`/prod/app/db/password`) needed no new
exclusion: it was already covered by the existing `starts_with_path_like`
check.

## Rationale

Each of these values names *where* a secret lives at runtime — a pointer
`op run`, LiteLLM, `vals`, the bank-vaults injector, or a cloud secret
manager's own client resolves — rather than containing one. None of them can
authenticate anything on their own. The detector already excluded other
non-secret reference syntax (`${...}`, `<...>`, `{{...}}`); this is the same
class of false positive for a different family of runtime indirection,
reported by the daily false-positive evaluator (source commit
`6bdcee39e668d96150c5d1ff431df74245de7b0e`, `0.1.0-beta.2`; issue #280).

A bare scheme-prefix allowlist (matching any value starting with `op://`)
was rejected: it would exclude any value an attacker or careless author
prefixed with that scheme, defeating detection for exactly the values this
detector exists to catch. Each grammar instead requires the whole value to
satisfy that scheme's real reference shape — segment counts, character
sets, and required delimiters drawn from each ecosystem's own documented
syntax — so a scheme-like prefix on a value that does not otherwise conform
(no vault/item/field segmentation, an account id that is not 12 digits, a
`vault:` value with no `#` key selector, and so on) stays detected. This
mirrors `decision-exclude-fully-delimited-template-references`'s choice to
anchor the `{{...}}` exclusion to the whole value rather than merely its
start.

## Consequences

- `generic_token.rs` gains `is_secret_manager_reference` and seven
  supporting grammar functions, called from `is_non_secret_reference`
  alongside the env, path-like, and template-reference checks.
- A value satisfying one of the seven grammars above, assigned to any
  contextual credential name (`password`, `api_key`, `secret`, ...), is no
  longer reported or redacted, across all five public surfaces (Rust core,
  CLI, Python wheel, Node addon, browser WebAssembly), since they all share
  the Rust core detector and the canonical conformance corpus
  (`conformance/fixtures/synchronous-corpus.json`).
- Negative regression fixtures cover all seven schemes
  (`contextual-negative-onepassword-secret-reference`,
  `contextual-negative-litellm-os-environ-reference`,
  `contextual-negative-gcp-secret-reference-with-version` and
  `-no-version`, `contextual-negative-vals-vault-reference`,
  `contextual-negative-bank-vaults-injector-reference`,
  `contextual-negative-aws-secretsmanager-arn`,
  `contextual-negative-azure-keyvault-secreturi-reference` and
  `-vaultname-reference`); positive regression fixtures assert that a
  scheme-like prefix on a value that does not satisfy its grammar (wrong
  segment count, an invalid identifier, a missing delimiter, a
  non-conforming account id or key-vault field list) keeps being reported.
- A real secret happening to satisfy one of these grammars in full — for
  example, a 12-digit account id and every other ARN field, or three
  slash-separated segments after `op://` — would go undetected. This is the
  same false-negative trade-off the existing `${...}`/`{{...}}` exclusions
  already accept, bounded by requiring the whole value to match a specific,
  documented reference shape rather than a loose prefix.
