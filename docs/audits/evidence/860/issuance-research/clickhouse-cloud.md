# #860 issuance research: `clickhouse-cloud:api-key`

[Issuance research index](README.md) ·
[Handoff](../clickhouse-cloud.md) ·
[Rulings R9–R10](https://github.com/redact-secret/redact-secret/issues/860#issuecomment-5880547337)

Frozen 2026-09-28. Desk research only: no key was issued, and no issued or
leaked credential is evidence.

**Gated property:** the secret body length after `4b1d` (38, for 42 in
total, against a 39-character total knowledge-base example), and whether the
2025-04 staff statement is still current.

**Research verdict: NARROWED.** The 42-versus-39 contradiction resolves under
R3 date ordering. The 39-character example dates from 2023-09, is older than
the 2025-04 staff statement, and is a single hand-written docs sample against
every other provider sample. No newer provider source establishes currentness
past 2025-04. New finding: the provider API accepts caller-supplied pre-hashed
keys, so not every valid secret has the generated shape (a false negative
only).

**Maintainer disposition (2026-09-28): closed by research under the existing
rulings.** `4b1d` + 38 `[A-Za-z0-9]` (42 in total), T1 as of 2025-04-16.

## Sources

| # | Source | Date | Class | Ruling | Statement |
|---|---|---|---|---|---|
| 1 | [gitleaks PR #1826](https://github.com/gitleaks/gitleaks/pull/1826), rule at [`clickhouse.go` L15 @ 9bc7257](https://github.com/gitleaks/gitleaks/blob/9bc725786d1874bf7d468e492c6e150f49739e1e/cmd/generate/config/rules/clickhouse.go#L15) | 2025-04-16 | provider-staff-authored scanner regex and statement | R2 T1; R3 T1 as of 2025-04 | `` \b(4b1d[A-Za-z0-9]{38})\b ``; "we specifically choose a prefix (4b1d...)". The rule file is unchanged since (HEAD checked 2026-09-28) |
| 2 | [terraform-provider-clickhouse `examples/provider/provider.tf` L16 @ cfa09c8](https://github.com/ClickHouse/terraform-provider-clickhouse/blob/cfa09c82da2856dc163ddf1529ea7ef7a3e76fe7/examples/provider/provider.tf#L16) (and about 40 `variables.tfvars.sample` files, `docs/index.md`) | value since [49af62f](https://github.com/ClickHouse/terraform-provider-clickhouse/commit/49af62f49b8cea70a51ea0fa075daed9da7a56d6) (2023-05-12); still shipped at HEAD 2026-09-28 | provider example | R5 example shape | one sample value: `4b1d` + 38 mixed-case alphanumerics (42 in total) |
| 3 | [terraform-provider-clickhouse `internal/api/client_test.go` L20](https://github.com/ClickHouse/terraform-provider-clickhouse/blob/cfa09c82da2856dc163ddf1529ea7ef7a3e76fe7/internal/api/client_test.go#L20) | added [a23aeda](https://github.com/ClickHouse/terraform-provider-clickhouse/commit/a23aeda9705060df1e04d467959b6b2f9c7354e9) (2024-07-30) | provider unit-test fixture | R5 example shape (no format assertion) | a second, distinct `4b1d` + 38 mixed-case alphanumerics (42 in total) |
| 4 | clickhouse-docs KB `knowledgebase/terraform_example.md`, [9e2d29b](https://github.com/ClickHouse/clickhouse-docs/commit/9e2d29b311f26d87543b39bd586dceb5cb73f6ba); now `ClickHouse/ClickHouse` `docs/resources/support-center/knowledge-base/integrations/terraform-example.mdx` (moved 2026-07-03, value unchanged) | 2023-09-02 | provider docs example | R5 example shape; R3: older than #1 | the 39-character `4b1d` `token_secret` (35 after the prefix); `token_key` has 17 characters. The only 39-character instance found in the ClickHouse org |
| 5 | Live OpenAPI `https://api.clickhouse.cloud/v1` (`ApiKeyPostResponse.keySecret`, `ApiKeyHashData`) | fetched 2026-09-28 | provider API spec | R1-adjacent (provider API contract) | no pattern, length or example for `keySecret`. `keySecretHash`: "Hash of the key secret. Algorithm: echo -n \"yourpassword\" \| sha256sum …"; `keySecret` is "Provided only if there was no 'hashData' in the request." |
| 6 | [ClickHouse/clickhousectl README L2882 @ a8a5cc0](https://github.com/ClickHouse/clickhousectl/blob/a8a5cc03925c908aa655463759a4d2ba1af2091f/README.md#L2882) (official CLI, Rust) | 2026-09-27 | provider CLI | R1 | "--hash-key-id/--hash-key-id-suffix/--hash-key-secret submit a pre-hashed key; no secret is returned". No secret format validation anywhere in the crates; test fixtures are word placeholders |
| 7 | clickhousectl README near L1195 | 2026-09-27 | provider CLI docs | — | Query API endpoints are called with "the bound key's `keyId` and `keySecret` (the credentials returned at key creation…)". Query-endpoint keys are ordinary org API keys, so the handoff's "query-endpoint keys unverified" exclusion collapses into the same shape |
| 8 | GitHub secret-scanning partner list | 2026-09-28 | — | — | ClickHouse is not a partner; no provider-registered pattern |

## Resulting contract

`4b1d` + exactly 38 `[A-Za-z0-9]` (42 in total), mixed case; T1 as of
2025-04-16 (staff regex), consistent with provider samples from 2023-05 and
2024-07. The 39-character KB example is treated as a pre-statement hand
sample (R3: the newer provider source wins). See the
[handoff](../clickhouse-cloud.md).

## Residual risk

- **False negatives:** secrets created through `hashData` (caller-chosen, any
  shape): new, and not fixable by shape; a post-2025-04 width change (what an
  issuance check would still rule out); an all-lowercase generated body under
  the policy uppercase guard (about 1e-9).
- **False positives:** unchanged: a mixed-case 42-character alphanumeric run
  starting `4b1d` at a boundary. Rare.
- Still open only if a 2026 date stamp is wanted: one issued key (length
  only).
