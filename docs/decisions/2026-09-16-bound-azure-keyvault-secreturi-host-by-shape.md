---
decision_id: decision-bound-azure-keyvault-secreturi-host-by-shape
status: accepted
scope: workspace
title: Bound the Azure Key Vault SecretUri reference by host shape, not domain identity
decided_at: 2026-09-16
spec: contextual-detection
---

# Bound the Azure Key Vault SecretUri reference by host shape, not domain identity

## Decision

Amend `is_azure_keyvault_secret_uri` (`crates/secret-scan-core/src/detectors/generic_token.rs`,
introduced by `decision-exclude-secret-manager-references`) to accept any
syntactically well-formed HTTPS hostname in a `SecretUri=<uri>` field,
instead of requiring the host to end with the literal `.vault.azure.net`
suffix. A host is now valid when it is an FQDN shape: two or more
dot-separated DNS labels (`is_dns_label`: 1-63 ASCII letters, digits, or
`-`, neither leading nor trailing with `-`), at most 255 bytes overall. The
`/secrets/<name>(/<version>)?` path requirement, the `@Microsoft.KeyVault(...)`
wrapper, and the `VaultName=...;SecretName=...` field form are unchanged.

## Rationale

`decision-exclude-secret-manager-references` anchored the `SecretUri=` grammar
to the public-cloud `*.vault.azure.net` domain, mirroring the AWS partition
check's closed enum (`aws` | `aws-cn` | `aws-us-gov`). That anchor was too
narrow in two ways the daily false-positive evaluator's beta.3 benchmark
surfaced (issue #293, a beta.4 follow-up to #280):

- Azure Key Vault is also reachable under sovereign-cloud suffixes
  (`vault.usgovcloudapi.net`, `vault.azure.cn`, `vault.microsoftazure.de`)
  and Private Link hostnames, none of which share a fixed, enumerable
  suffix the way AWS's three partitions do. A literal-suffix check
  under-recognizes real, complete references.
- The benchmark's own fixture convention constructs external-host examples
  under an RFC 2606 reserved TLD (`example.invalid`) rather than a domain
  a real organization owns, consistent with this repo's synthetic-example
  policy. A literal-suffix check rejects those as if they were malformed,
  when the value is structurally a complete, well-formed reference.

Every sibling grammar in this family (GCP project id, AWS account id and
secret name, the `op://`/`vals`/`vault:` path and key segments) already
validates *shape* — a charset and segment-count pattern — rather than
identity: none checks a value against a real, known GCP project id or AWS
account. The literal Azure domain suffix was the one outlier that checked
identity instead of shape. Bounding the host to an FQDN shape brings it in
line with that family-wide precedent, rather than introducing a new kind of
check.

This does not reopen `decision-exclude-secret-manager-references`'s
rejected "bare scheme-prefix allowlist": the exclusion still requires the
whole value to satisfy the `@Microsoft.KeyVault(SecretUri=https://<host>/secrets/<segment>)`
shape in full. What changes is only which strings satisfy `<host>`. A
malformed lookalike — no `/secrets/` segment, a value not wrapped in
`@Microsoft.KeyVault(...)` at all, a single-label host with no dot, or a
host containing a byte outside the DNS label charset (for example `_`) —
stays detected.

## Consequences

- `generic_token.rs` gains `is_dns_label` and `is_https_hostname`;
  `is_azure_keyvault_secret_uri` calls `is_https_hostname(host)` in place
  of the `.vault.azure.net` suffix check.
- A `SecretUri=` value with any FQDN-shaped host — a sovereign-cloud
  domain, an `.invalid` benchmark placeholder, or any other syntactically
  valid host — is no longer reported or redacted, across all five public
  surfaces (Rust core, CLI, Python wheel, Node addon, browser WebAssembly),
  since they all share the Rust core detector and the canonical
  conformance corpus (`conformance/fixtures/synchronous-corpus.json`).
- A single-label host (no dot), an empty host, and a host containing a
  character outside the DNS label charset stay detected as malformed
  lookalikes; regression fixtures cover all three alongside the existing
  "neither `SecretUri=` nor `Key=value;...` fields" malformed case.
- New corpus fixtures: `contextual-negative-azure-keyvault-secreturi-non-azure-host`,
  `contextual-negative-azure-keyvault-secreturi-sovereign-host`,
  `contextual-negative-azure-keyvault-secreturi-crlf`,
  `contextual-negative-azure-keyvault-vaultname-unicode-prefix`, and
  `contextual-positive-azure-keyvault-single-label-host-detected`.
- A real secret that happens to be composed entirely of ASCII letters,
  digits, and `-`, arranged as two or more dot-separated labels, and
  wrapped in the full `@Microsoft.KeyVault(SecretUri=https://.../secrets/...)`
  shape would go undetected. This is the same false-negative trade-off
  `decision-exclude-secret-manager-references` already accepts for its
  other six grammars, and the DNS label charset excludes the underscore,
  `+`, `/`, and `=` characters common to most real credential formats
  (base64, JWT, provider-prefixed tokens).
