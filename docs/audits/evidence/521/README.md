# Issue #521 — Terraform Cloud/Enterprise token detection

[Audit archive](../../README.md) ·
[Decision: Add Terraform Cloud/Enterprise API token detection](../../../decisions/2026-09-21-add-terraform-cloud-enterprise-token-detection.md) ·
[Issue #521](https://github.com/redact-secret/redact-secret/issues/521) ·
[Issue #501 (epic)](https://github.com/redact-secret/redact-secret/issues/501)

Reviewed 2026-09-21 against this repository's `main`. Adds one new detector
(`terraform-cloud-token`), backed by new conformance fixtures.

## Summary

Issue #521 (B3b, under Epic #501) scopes this to "the Terraform
Cloud/Enterprise token families (user, team and organization tokens) where
provider evidence supports a lexical shape, including the credential-file
context they typically appear in."

| Family | Disposition | Tier | Basis |
| --- | --- | --- | --- |
| User / team / organization API token (`<14>.atlasv1.<67>`) | **new detector**, `terraform-cloud-token` | T1 (provider-documented; corroborated by three independent HCP Terraform API-reference pages) | HashiCorp's own `user-tokens`/`organization-tokens`/`team-tokens` API docs, all showing the identical exact-width example shape |
| Agent-pool token | supported, unchanged (same shape) | T1 (subsumed) | Same `.atlasv1.` shape; not separately audited, no evidence of a distinct grammar |
| Terraform Enterprise (self-hosted) token | supported, unchanged (same shape) | T1 (subsumed) | The mirrored Enterprise API-reference page publishes the identical example and structure |

One shape covers every named class in scope; there is no sub-family here
that lacks evidence and needs a `pending`/`unsupported` disposition.

## Family 1 — User/team/organization API token: new detector

**Supported, new.** `crates/secret-scan-core/src/detectors/terraform.rs`
adds `terraform-cloud-token` for the shape:

```
[A-Za-z0-9]{14}.atlasv1.[A-Za-z0-9]{67}
```

Evidence, T1 (provider-documented): three independent pages of HCP
Terraform's own API reference documentation, all observed 2026-09-21, each
publish a full example token value:

- `developer.hashicorp.com/terraform/cloud-docs/api-docs/user-tokens`:
  `6tL24nM38M7XWQ.atlasv1.KmWckRfzeNmUVFNvpvwUEChKaLGznCSD6fPf3VPzqMMVzmSxFU0p2Ibzpo2h5eTGwPU`
- `.../organization-tokens`:
  `ZgqYdzuvlv8Iyg.atlasv1.6nV7t1OyFls341jo1xdZTP72fN0uu9VL55ozqzekfmToGFbhoFvvygIRy2mwVAXomOE`
- `.../team-tokens`:
  `QnbSxjjhVMHJgw.atlasv1.gxZnWIjI5j752DGqdwEUVLOFf0mtyaQ00H9bA1j90qWb254lEkQyOdfqqcq9zZL7Sm0`

Every example is exactly 14 bytes before the `.atlasv1.` marker and exactly
67 bytes after it — agreement across three independently authored
documentation pages, not a single incidental mention. Neither page
documents a checksum or any marker beyond the literal `.atlasv1.` version
tag itself.

Two tools corroborate the family without agreeing with each other on the
exact width: gitleaks 8.30.1 (observed 2026-09-21) contracts a looser
60-70-byte range over a wider tail alphabet
(`[a-z0-9]{14}\.atlasv1\.[a-z0-9\-_=]{60,70}`, case-insensitive), while
trufflehog 3.97.4's `terraformcloudpersonaltoken` detector (observed
2026-09-21) contracts the exact width this module adopts
(`[A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9]{67}`), matching all three official
examples exactly. The tighter, provider-confirmed width is frozen, per
`docs/decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-
families.md`'s precedent for preferring an exact contract over a looser
single-tool range once provider evidence pins the real width.

`Confidence::High`, `Specificity::Provider`, `policy::ALWAYS_REDACT_TYPES`.
Registered after `firebase-server-key` and before `jwt`.

### New corpus fixtures (`conformance/fixtures/synchronous-corpus.json`)

| Fixture | Purpose |
| --- | --- |
| `terraform-cloud-token-positive-bare` | The shape alone, no surrounding context |
| `terraform-cloud-token-positive-cli-credentials-hcl` | The documented CLI `credentials "app.terraform.io" { token = "..." }` block |
| `terraform-cloud-token-positive-cli-credentials-json` | The JSON form of the CLI credentials file (`credentials.tfrc.json`) |
| `terraform-cloud-token-positive-dotenv` | The documented `TF_TOKEN_<host>` environment-variable convention |
| `terraform-cloud-token-positive-github-actions` | A CI workflow env block assigning the variable a bare literal value |
| `terraform-cloud-token-positive-log` | Plain log/source text with no key=value structure |
| `terraform-cloud-token-overlap-generic-context` | Qualified provider evidence wins over `generic-token`'s `token=` contextual heuristic |
| `terraform-cloud-token-boundary-prefix-short` | Prefix one byte short of 14: rejected |
| `terraform-cloud-token-boundary-suffix-short` | Suffix one byte short of 67: rejected |
| `terraform-cloud-token-boundary-wrong-marker` | `.atlasv2.` instead of the documented `.atlasv1.`: rejected |
| `terraform-cloud-token-negative-masked` | An all-asterisk suffix: wrong alphabet |
| `terraform-cloud-token-negative-env-var-reference` | An unexpanded `${TF_TOKEN_...}` shell reference |
| `terraform-cloud-token-negative-doc-placeholder` | HashiCorp's own CLI-config doc placeholder `xxxxxx.atlasv1.zzzzzzzzzzzzz`, far short of the documented widths |
| `terraform-cloud-token-negative-embedded-wider-identifier` | The shape embedded in a wider identifier on either side |
| `terraform-cloud-token-negative-workspace-and-org-ids` | Benign control: `ws-`/`org-` prefixed resource identifiers |
| `terraform-cloud-token-negative-provider-version-constraint` | Benign control: an ordinary `required_version`/`required_providers` block |
| `terraform-cloud-token-negative-state-file-identifier` | Benign control: a `terraform.tfstate`-shaped `lineage`/`serial` pair |
| `terraform-cloud-token-adversarial-near-miss-suffix` | A long run of one-byte-short near misses stays linear and bounded, with one real match at the end |
| `terraform-cloud-token-positive-crlf-unicode-prefix` | CRLF line endings and a multi-byte Unicode prefix shift only the byte offsets |

`conformance/fixtures/common-profile-expectations.json` is regenerated:
every new fixture resolves empty under the `common` profile
(`Pack::Provider`-only), the same as the rest of this family.

## Family 2 — Agent-pool token and Terraform Enterprise (self-hosted)

**Supported, unchanged (same shape).** HashiCorp's own documentation shows
the identical `.atlasv1.` structure for these; they are not a distinct
grammar and are covered by `terraform-cloud-token` incidentally, with no
separate code path. Not audited as an independent family because no
evidence of a differing shape was found.
