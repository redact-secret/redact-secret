---
decision_id: decision-add-terraform-cloud-enterprise-token-detection
status: accepted
scope: workspace
title: Add Terraform Cloud/Enterprise API token detection
decided_at: 2026-09-21
spec: detector-families
---

# Add Terraform Cloud/Enterprise API token detection

## Decision

For issue #521 (B3b, under Epic #501), a new `terraform-cloud-token`
detector (`crates/secret-scan-core/src/detectors/terraform.rs`) for HCP
Terraform's (formerly "Terraform Cloud") and Terraform Enterprise's API
token:

```
[A-Za-z0-9]{14}.atlasv1.[A-Za-z0-9]{67}
```

Exactly 14 alphanumeric bytes, then the literal `.atlasv1.` version marker,
then exactly 67 alphanumeric bytes, for 90 bytes total. `Confidence::High`
unconditionally, `Specificity::Provider`, listed in
`policy::ALWAYS_REDACT_TYPES`, registered after `firebase-server-key` and
before `jwt`.

## Rationale

### Grammar evidence: T1, provider-documented

HCP Terraform's own API reference documentation publishes a full example
token value in three independent pages, all observed 2026-09-21:

| Page | Example |
| --- | --- |
| `developer.hashicorp.com/terraform/cloud-docs/api-docs/user-tokens` | `6tL24nM38M7XWQ.atlasv1.KmWckRfzeNmUVFNvpvwUEChKaLGznCSD6fPf3VPzqMMVzmSxFU0p2Ibzpo2h5eTGwPU` |
| `.../organization-tokens` | `ZgqYdzuvlv8Iyg.atlasv1.6nV7t1OyFls341jo1xdZTP72fN0uu9VL55ozqzekfmToGFbhoFvvygIRy2mwVAXomOE` |
| `.../team-tokens` | `QnbSxjjhVMHJgw.atlasv1.gxZnWIjI5j752DGqdwEUVLOFf0mtyaQ00H9bA1j90qWb254lEkQyOdfqqcq9zZL7Sm0` |

Every one of these three examples is exactly 14 bytes before the `.atlasv1.`
marker and exactly 67 bytes after it. The mirrored Terraform Enterprise page
(`.../terraform/enterprise/api-docs/organization-tokens`) publishes the
identical shape and the identical organization-token example, confirming
"Cloud/Enterprise" is one grammar, not two, and that a self-hosted
Enterprise installation issues tokens indistinguishable in shape from HCP
Terraform's own. Neither page documents a checksum, or any marker beyond
the literal `.atlasv1.` version tag itself.

This is provider evidence corroborated across three independent official
pages agreeing on the exact width, not a single mention — the strongest
form of T1 evidence this crate's evidence tiers recognize
(`docs/support-matrix.md`'s tier legend: T1 "provider-documented," T2
"tool-corroborated," T0 "no positive").

**Tool corroboration, not adopted over the provider's own width.** Two
independent tools recognize the family without agreeing with each other on
the exact width: gitleaks 8.30.1's `config/gitleaks.toml` (observed
2026-09-21) uses `(?i)[a-z0-9]{14}\.(?-i:atlasv1)\.[a-z0-9\-_=]{60,70}` — a
looser 60-70-byte range over a wider `[A-Za-z0-9_=-]` tail alphabet — while
trufflehog 3.97.4's `terraformcloudpersonaltoken` detector (observed
2026-09-21) uses `\b[A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9]{67}\b`, matching
all three official examples exactly. This module freezes the tighter,
provider-confirmed exact width (matching trufflehog, not gitleaks' looser
range), the same precedent
`docs/decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-
families.md` set for preferring an exact, provider-backed contract over a
looser single-tool range once the provider's own documentation pins the
real width.

### Scope: one shape, no sub-family left unevidenced

Issue #521 scopes this to "user, team and organization tokens." HashiCorp's
own documentation shows one identical grammar for all three — "type is not
distinguishable from shape" — so a single detector and finding type
(`terraform_cloud_token`) covers the full named scope with no branching
logic. The same shape incidentally also covers agent-pool tokens and
Terraform Enterprise's self-hosted tokens, since the provider's own
reference documents the identical structure for those too. There is no
in-scope sub-family here that lacks evidence and needs a
`pending`/`unsupported` disposition, unlike issue #520's audit of the
several distinct Firebase credential shapes.

### Detection is shape-only, not context-gated

The same posture [`super::vault`] and [`super::firebase`] already take: a
bare value matching the grammar is reported wherever it appears, with no
special-casing per host context. This is sufficient to cover every context
the issue names without extra code:

- **CLI credential JSON**: `~/.terraform.d/credentials.tfrc.json`.
- **CLI credential file (HCL)**: the `credentials "app.terraform.io" {
  token = "..." }` block documented at
  `developer.hashicorp.com/terraform/cli/config/config-file` (observed
  2026-09-21).
- **Env files / CI configuration**: the documented `TF_TOKEN_<host>`
  environment-variable convention (periods in the hostname encoded as
  underscores; supported since Terraform 1.2.0), assigned directly rather
  than through a secrets reference.
- **Source/log text**: the shape alone is sufficient with no surrounding
  key=value structure required, the same as every other fixed-shape
  provider grammar in this crate.

### What stays a documented false negative

A token whose prefix or suffix segment is one byte short or long, whose
marker is malformed (`.atlasv2.`, `atlasv1.` with no leading dot,
`.ATLASV1.`), or whose alphabet is violated (a masked run of `*`) is
rejected rather than fuzzy-matched. HashiCorp's own CLI-configuration
documentation shows a doc-style placeholder,
`xxxxxx.atlasv1.zzzzzzzzzzzzz` — a 6-byte prefix and 13-byte suffix, both
far short of the documented 14/67 widths — which this contract correctly
does not classify; `terraform-cloud-token-negative-doc-placeholder` pins
this as a deliberate, evidenced negative rather than an oversight.

## Consequences

- `crates/secret-scan-core/src/detectors/mod.rs` registers
  `terraform-cloud-token` after `firebase-server-key` and before `jwt`;
  `scripts/measure-detector-cost.mjs`'s `CANONICAL_IDS`/`GROUPS` mirror is
  updated in the same commit.
- `docs/coverage/detector-inventory.json` gains a `terraform_cloud_token`
  row with `always-redact` policy class; coverage declarations, the
  inventory report, and the coverage report are regenerated from that row
  and the conformance corpus.
- New conformance fixtures cover `terraform-cloud-token` across bare,
  CLI-credentials (HCL and JSON), dotenv, GitHub Actions, and log contexts;
  an overlap case against `generic-token`'s `token=` assignment heuristic;
  one-byte-short boundaries for both segments and a malformed marker; a
  masked value, an unexpanded environment-variable reference, and the
  official documentation placeholder above as negatives; workspace/
  organization-ID, provider-version-constraint, and state-file-identifier
  benign controls; a CRLF/Unicode-prefix regression; and an adversarial
  bounded-work stress input.
- `conformance/fixtures/common-profile-expectations.json` is regenerated:
  every new fixture resolves empty under the `common` profile (`Pack::
  Provider`-only), the same as the rest of this family.
- A token whose prefix or suffix segment is malformed as described above is
  a documented, known false negative — the same tradeoff every other
  fixed-shape provider grammar in this crate makes.
