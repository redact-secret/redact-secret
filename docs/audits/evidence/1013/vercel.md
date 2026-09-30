# #1013 evidence: Vercel token families

[Index](README.md) ·
[Issue #1013](https://github.com/redact-secret/redact-secret/issues/1013) ·
[#858 record](../858/README.md) ·
[Benchmarks dossier at `5380aa3a`](https://github.com/redact-secret/redact-secret-benchmarks/blob/5380aa3a421555883225a62358fa40f81dcd2baa/benchmarks/support/dossiers/vercel.md)

Covers `vercel:personal-access-token` (`vcp_`), `vercel:integration-token`
(`vci`), `vercel:app-access-token` (`vca_`), `vercel:app-refresh-token`
(`vcr_`), `vercel:api-key` (`vck_`) and `vercel:access-token` in one record,
because the evidence is shared.

Frozen 2026-09-29. Desk research only: no token was issued, and no issued or
leaked credential is evidence. Provider examples are described by length
and alphabet, never reproduced.

**Status (pin at `b9e90915`):** all pending, T0 (#858: the markers are
provider-backed, no body grammar). The benchmarks dossier, re-researched the
same day, calls all five `ready` T2 with `<marker>_` + 56. This record
verified that pass source by source and disagrees on two classes.

## Verdict

| Family | Verdict | Grammar | Why |
| --- | --- | --- | --- |
| `vercel:personal-access-token` | **READY-T2** | `vcp_` + 56 `[A-Za-z0-9]` (60) | provider example (P3) + three peer owners (S1, S2, S3) |
| `vercel:app-access-token` | **READY-T2** (thin) | `vca_` + 56 `[A-Za-z0-9]` | provider example (P2) + two peer owners; both peer rules copy the provider value |
| `vercel:app-refresh-token` | **READY-T2** (thin) | `vcr_` + 56 `[A-Za-z0-9]` | as `vca_`; the docs reuse the `vca_` body, so no independent `vcr_` body |
| `vercel:integration-token` | **STILL-BLOCKED** | — | no provider source writes `vci_` with the underscore; the length rests on the peer class only (3 references, 3 owners, 1 class) |
| `vercel:api-key` | **STILL-BLOCKED** on length | marker `vck_` is provider-backed | no full-length provider value; the length rests on the peer class only |
| `vercel:access-token` | **not a family** | — | the product's compatibility aggregate for `vercel-token`; nothing to corroborate. The legacy unprefixed 24-character form is a separate candidate |

No class is READY-T1: no Vercel code generates or validates a length,
alphabet or checksum (searched: vercel/vercel, turborepo, vercel/ai,
vercel/sdk, vercel-plugin, terraform-provider-vercel,
vercel-azure-devops-extension). Vercel code only discriminates by prefix.

## Findings that change the dossier

1. **The 50 + 6 checksum is provider-backed on one value.** The `vca_`
   example on the Sign in with Vercel Tokens page passes Kingfisher's
   check: the last 6 characters equal base62 (`0-9A-Za-z`) of the CRC-32 of
   the 50 before them. A chance match is about 1 in 5.7×10¹⁰, so the value
   came from a real generator. Vercel's OpenAPI spec calls the `tokenSuffix`
   field "The token checksum suffix."
2. **The `vca_`/`vcr_` example predates the changelog.** It is in the
   Wayback snapshot of 2025-11-28; the changelog is 2026-02-09.
3. **The CLI `vcp_` example is hand-written.** Its body ends in a literal
   English word and fails the checksum. It is one value printed twice,
   first seen 2026-05-10. It still shows a 56-character body, as an example
   shape.
4. **Peer rules are less independent than counted.** Kingfisher's `vca_` and
   `vcr_` examples are copies of the Vercel docs value; its `vcp_`, `vci_`
   and `vck_` examples are synthetic values that pass its own checksum;
   betterleaks copies all six Kingfisher examples. CredSweeper's `vcp_`
   samples fail the checksum, so CredSweeper is independent of Kingfisher.
5. **No provider source writes `vci_`.** Not the docs (the full
   `llms-full.txt` has no `vci` at all), not the OpenAPI enums (`vcp_`,
   `vca_`, `vcr_` only), not the SDK, not org code. For `vck_` the
   underscore is provider-backed (docs, CLI, AI SDK and Terraform tests).
6. **Provider masking regexes admit `_` and `-`** (Azure DevOps extension:
   `vcp_[A-Za-z0-9_-]+`, `vca_[A-Za-z0-9_-]+`; CLI eval `vcp_[A-Za-z0-9_]+`).
   They are maskers with no length, so the alphabet question stays bounded,
   not settled.

## Sources

All read 2026-09-29. Line dates from blame at the pinned commit.

| # | Source | Date | Owner | Class | Statement (shape only) |
| --- | --- | --- | --- | --- | --- |
| P1 | vercel.com/changelog/new-token-formats-and-secret-scanning | 2026-02-09 | Vercel | provider changelog | T1 marker stems `vcp`, `vci`, `vca`, `vcr`, `vck`; no underscore, no length |
| P2 | vercel.com/docs/sign-in-with-vercel/tokens | updated 2026-03-30; value present 2025-11-28 | Vercel | provider-example | "Access Tokens use an opaque format … server side validation"; `vca_` + 56 `[A-Za-z0-9]` (checksum-valid); `vcr_` + the same body |
| P3 | vercel.com/docs/cli/global-options | updated 2026-05-28; first seen 2026-05-10 | Vercel | provider-example | `--token` and `VERCEL_TOKEN`: one `vcp_` + 56 alphanumeric value, hand-written (fails the checksum) |
| P4 | vercel.com/docs/accounts/access-tokens | updated 2026-09-08 | Vercel | provider docs | T1 marker: "Personal access tokens begin with the prefix `vcp_`"; the masked filler is a placeholder |
| P5 | openapi.vercel.sh (v0.0.1) | fetched 2026-09-29 | Vercel | provider spec | `tokenPrefix` enum `vcp_` ("safe checksum-style fingerprint"); `tokenSuffix` "The token checksum suffix."; `vca_` and `vcr_` enums |
| P6 | vercel.com/docs/ai-gateway/authentication-and-byok/api-keys; docs/cli/ai-gateway | updated 2026-09-08 | Vercel | provider-example (marker, mask) | `vck_...`; mask `vck_` + 4 dots + 4 digits |
| P7 | vercel.com/docs/sign-in-with-vercel/authorization-server-api | updated 2026-08-21 | Vercel | provider-example (marker) | `vca_...`, `vcr_...` |
| P8 | vercel.com/docs/rest-api/authentication/create-an-auth-token | undated; 2021 timestamps in the example | Vercel | provider-example | unprefixed 24-character `bearerToken` beside `"prefix": "vcp_"` |
| C1 | [vercel/vercel `commands/tokens/add.ts#L36-L41`](https://github.com/vercel/vercel/blob/c628be7835e03a965b93e9cf9e2bd5ac2acbf5eb/packages/cli/src/commands/tokens/add.ts#L36-L41) | 2026-04-02 | Vercel | provider-owned-code (help text) | some `vcp_` tokens cannot mint tokens |
| C2 | [vercel/vercel `evals/project/list/implicit/EVAL.ts#L29`](https://github.com/vercel/vercel/blob/c628be7835e03a965b93e9cf9e2bd5ac2acbf5eb/packages/cli/evals/evals/project/list/implicit/EVAL.ts#L29) | 2026-05-16 | Vercel | provider-owned-code | `/\bvcp_[A-Za-z0-9_]+\b/`: marker only |
| C3 | [vercel/vercel `test/unit/util/login/token-refresh.test.ts#L115-L125`](https://github.com/vercel/vercel/blob/c628be7835e03a965b93e9cf9e2bd5ac2acbf5eb/packages/cli/test/unit/util/login/token-refresh.test.ts#L115-L125) | 2026-07-24 | Vercel | provider-owned-code | `vca_`/`vcr_` short dummies: marker and role |
| C4 | [vercel/vercel `coding-agents-setup.test.ts#L90`](https://github.com/vercel/vercel/blob/c628be7835e03a965b93e9cf9e2bd5ac2acbf5eb/packages/cli/test/unit/commands/ai-gateway/coding-agents-setup.test.ts#L90) | 2026-07-11 | Vercel | provider-owned-code | `vck_` short dummy: marker |
| C5 | [vercel/turborepo `turborepo-auth/src/auth/mod.rs#L361`](https://github.com/vercel/turborepo/blob/07ee4185589823c984ea9f28d1f8480b60d6374f/crates/turborepo-auth/src/auth/mod.rs#L361); [`turborepo-api-client/src/lib.rs#L190`](https://github.com/vercel/turborepo/blob/07ee4185589823c984ea9f28d1f8480b60d6374f/crates/turborepo-api-client/src/lib.rs#L190) | 2026-04-15/16 | Vercel | provider-owned-code (discriminator) | `starts_with("vca_")`; "Vercel App token (prefixed "vca_")" |
| C6 | [vercel/vercel-plugin `benchmark-sandbox/SKILL.md#L144`](https://github.com/vercel/vercel-plugin/blob/c632a50838a47a639a160baff8411eb9c6af22bf/.claude/skills/benchmark-sandbox/SKILL.md#L144) | 2026-03-10 | Vercel | provider-owned docs | `vck_*` AI Gateway, `vca_*` token |
| C7 | [vercel/vercel-azure-devops-extension `src/index.ts#L37-L38`](https://github.com/vercel/vercel-azure-devops-extension/blob/24183cd1671cdb451e22a20634c2bb19e3478870/vercel-deployment-task-source/src/index.ts#L37-L38) | 2026-04-27 | Vercel | provider-owned-code (masker) | `vcp_[A-Za-z0-9_-]+`, `vca_[A-Za-z0-9_-]+` |
| S1 | [mongodb/kingfisher `vercel.yml#L46-L299`](https://github.com/mongodb/kingfisher/blob/88d3f780fad83960aaddfcf732a690049853ccc9/crates/kingfisher-rules/data/rules/vercel.yml#L46-L299) | 2026-02-11 | MongoDB | peer-scanner-rule | `vc[pikar]_` + 50 `[A-Za-z0-9_-]` + 6 `[A-Za-z0-9]`, "Base62(CRC32(body)) padded to 6" |
| S2 | [betterleaks `vercel.go#L46-L212`](https://github.com/betterleaks/betterleaks/blob/2a387a5bad4290a84b9a1eb679bffe70611218cc/cmd/generate/config/rules/vercel.go#L46-L212) | 2026-02-25 | betterleaks | peer-scanner-rule (derived from S1) | `vc[pikar]_` + 56 `[A-Za-z0-9_-]` |
| S3 | [Samsung/CredSweeper `config.yaml#L1995-L2007`](https://github.com/Samsung/CredSweeper/blob/1aa60465c4ec064357ead06f5b4da7c3adbce7a8/credsweeper/rules/config.yaml#L1995-L2007) | 2026-02-17 | Samsung | peer-scanner-rule | `vcp_` + exactly 56 `[0-9A-Za-z]`, `vcp_` only |
| S4 | [secretlint `secretlint-rule-vercel/src/index.ts#L27-L58`](https://github.com/secretlint/secretlint/blob/e8fc91351add9eebfd5eec5bdd7cd0d551d5e42a/packages/@secretlint/secretlint-rule-vercel/src/index.ts#L27-L58) | 2026-03-30 / 2026-04-12 | secretlint | peer-scanner-rule | `(vcp\|vci\|vca\|vcr\|vck)_` + 20–60 alphanumerics: marker and class only |
| S5 | docs.github.com supported secret-scanning patterns; github.blog changelog 2026-03-10 | 2026-03-10 | GitHub | peer (type names only) | six Vercel types; push protection by default on all but `vercel_app_refresh_token`; no validity checks |

Searched with no further result: trufflehog (legacy 24-character pattern
only), gitleaks, noseyparker, detect-secrets, osv-scalibr, Microsoft
security-utilities (no prefixed-format rule); GitGuardian (`Prefixed:
False`, legacy detector); Vercel community (one staff reply on integration
token lifetime, no format); web search for `vci_`, `vck_`, the length and
the checksum (no staff statement).

## Corroborated-route counts

Full grammar (marker with underscore + 56). References / owners /
non-summary classes.

| Family | Counted | Result |
| --- | --- | --- |
| `vcp_` | P3, S1, S2, S3: 4 / 4 / 2 (3 / 3 / 2 without S2) | clears |
| `vca_` | P2, S1, S2: 3 / 3 / 2 | clears on paper; one provider value, copied by S1 and again by S2 |
| `vcr_` | P2, S1, S2: 3 / 3 / 2 | clears on paper; same caveat plus a shared body |
| `vci_` | S1, S2, S4: 3 / 3 / 1 | fails classes; the underscore is not provider-stated |
| `vck_` | S1, S2 (S4 marker only): 3 / 3 / 1 | fails classes for the length |

## Contradictions

| Statement | Proposed status | Basis |
| --- | --- | --- |
| REST unprefixed 24-character `bearerToken` beside `prefix: "vcp_"` (P8) | bounded | the legacy unprefixed form is excluded from all five families |
| `_` and `-` in the body (S1, S2, C7 admit; every provider example and S3 do not) | bounded | leave `_` and `-` out of the body; maskers are not validators |
| Checksum (S1 only, now with provider support on P2 and P5) | not a contradiction; not frozen | backed on one provider value; not required for `vcp_`, `vci_` or `vck_` |
| Masked `vcp_` filler of 24 `x` (P4) | not counted | a placeholder |

## Maintainer ruling that would unblock `vci_` and `vck_`

Q-VC: treat the five classes as one generator family, so that the
provider-backed structure on `vca_` (checksum-valid 56-character body) and
`vcp_` (56-character example) extends to `vci_` and `vck_`. Without it,
each needs one issued value.

## Issuance checks

- `vck_` (cheap): create one AI Gateway API key in the dashboard.
- `vci_`: create an integration and run the OAuth code exchange to receive
  an integration token.

For each, structure only: starts with the marker including `_`; total
length 60; body only `[A-Za-z0-9]` or includes `_`/`-`; whether the last 6
characters equal base62(CRC-32 of the previous 50). Revoke afterwards. Do
not use the AI Gateway's compromised-secret reporting route with any real
value.
