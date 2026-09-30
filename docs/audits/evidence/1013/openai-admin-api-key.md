# #1013 evidence: `openai:admin-api-key`

[Index](README.md) ·
[Issue #1013](https://github.com/redact-secret/redact-secret/issues/1013) ·
[#863 record](../863/README.md) ·
[Spec: detector families](../../../specs/detector-families.md)

Frozen 2026-09-29. Desk research only: no key was issued, and no issued or
leaked credential is evidence. Shapes only.

**Contract under test (#863, T2):** `sk-admin-` + 58 or 74 `[A-Za-z0-9_-]`
+ `T3BlbkFJ` + 58 or 74 `[A-Za-z0-9_-]`; the marker is required, and a
marker-less body is out of contract.

**Matrix blocker (pin at `b9e90915`):** corroborated route 0 / 0 / 0 (no
ledger record for this family) and 16 unresolved differential
disagreements.

**Verdict: READY-T2 for the 58/58 width** (133 characters). The 74/74 admin
width is not observed anywhere; see the recommendation below.

## Sources

All read 2026-09-29.

| # | Source | Date | Owner | Class | Statement (shape only) |
| --- | --- | --- | --- | --- | --- |
| 1 | [trufflehog `pkg/detectors/openaiadmin/openaiadmin.go#L26-L29`](https://github.com/trufflesecurity/trufflehog/blob/363923b901c911a9164f50b6c423f47c15372b1c/pkg/detectors/openaiadmin/openaiadmin.go#L26-L29) (v3.97.4) | 2026-02-11 (PR #4689); in the v3.97.4 default detector list | Truffle Security | peer-scanner-rule | "Admin keys follow the format: sk-admin-{58 chars}T3BlbkFJ{58 chars} / Total length: 133 chars"; `\b(sk-admin-[A-Za-z0-9_-]{58}T3BlbkFJ[A-Za-z0-9_-]{58})\b`. Ten test positives, all 58/58; a marker-less 124-byte body is a test negative |
| 2 | [gitleaks `cmd/generate/config/rules/openai.go#L14`](https://github.com/gitleaks/gitleaks/blob/83d9cd684c87d95d656c1458ef04895a7f1cbd8e/cmd/generate/config/rules/openai.go#L14) (v8.30.1) | admin branch 2025-03-27 (PR #1780, test keys described as revoked) | gitleaks | peer-scanner-rule | `sk-(proj\|svcacct\|admin)-` + 74 or 58 + `T3BlbkFJ` + 74 or 58; three admin vectors, all 58/58 |
| 3 | [projectdiscovery/nuclei-templates `openai-admin-api-key.yaml#L23`](https://github.com/projectdiscovery/nuclei-templates/blob/02b06eb813310376e9a29543fd63a53f0dd3d4b3/http/exposures/tokens/openai/openai-admin-api-key.yaml#L23) | 2025-10-09 | ProjectDiscovery | peer-scanner-rule | `sk-admin-[A-Za-z0-9_-]{58}T3BlbkFJ[A-Za-z0-9_-]{58}` |
| 4 | [ghostsecurity/poltergeist `pkg/rules/openai.yaml#L36`](https://github.com/ghostsecurity/poltergeist/blob/e071ca2d15f652c6e87e63a64716144a9383c3b2/pkg/rules/openai.yaml#L36) | 2025-08-13 | Ghost Security | peer-scanner-rule | `sk-admin-` + 58 + `T3BlbkFJ` + 58 (case-insensitive class) |
| 5 | [openai/codex `credential_broker/providers/openai.rs#L13-L22`](https://github.com/openai/codex/blob/bd4204efc24a888c6671681f5cd41fbf9377c163/codex-rs/network-proxy/src/credential_broker/providers/openai.rs#L13-L22) | `sk-admin-` and watermark first present 2026-09-09 | OpenAI | provider-owned-code (recognizer) | prefixes include `sk-admin-`; `credential_watermark` `T3BlbkFJ`; minimum length 51. It neither generates nor validates the width, so it is not T1 (R9 needs a generator or validator) |
| 6 | [openai/openai-openapi `openapi.yaml#L11043`](https://github.com/openai/openai-openapi/blob/fe524f2c56edfe59cde878b8d2d8b07c2b5371ef/openapi.yaml#L11043) (also L10945, L38256) | current HEAD | OpenAI | provider-example | placeholders only: `sk-admin-` + 8 characters, and a `redacted_value` of `sk-admin` + `...` + 3. Prefix only |
| 7 | [aquasecurity/trivy `builtin-rules.go#L1034`](https://github.com/aquasecurity/trivy/blob/3a1b311e63a1b64ab3221bf52683581b77187198/pkg/fanal/secret/builtin-rules.go#L1034) | 2026-06-08 | Aqua | peer-scanner-rule | `sk-admin-` + 20–100 + marker + 20–100 (loose) |
| 8 | betterleaks v1.9.0 [`openai.go#L15`](https://github.com/betterleaks/betterleaks/blob/81aff7a638638aae3a659845d089043e1d8fe9ac/cmd/generate/config/rules/openai.go#L15); secretlint [`index.ts#L25`](https://github.com/secretlint/secretlint/blob/0001184f56165e7db7ab1b3adc1f957911c78f46/packages/@secretlint/secretlint-rule-openai/src/index.ts#L25) | 2026-02-03 fork; 2025-04-01 | betterleaks; secretlint | peer-scanner-rule (derived from #2) | the gitleaks grammar; not independent of #2 |
| 9 | GitGuardian detector page `openai_admin_apikey` | "last updated Sep 25, 2026" | GitGuardian | peer (unpinned doc) | `Prefixed: True`; no regex or example published. Not counted |
| 10 | [trufflehog issue #4698](https://github.com/trufflesecurity/trufflehog/issues/4698) | 2026-01-26 | a trufflehog user | feature request | `sk-admin-` + 124 with no marker, no reference given. Not counted |

Searched with no admin-shape result: OpenAI repos (python, node, go, java,
ruby, cli, cookbook, openapi; placeholders only), platform.openai.com (403),
developers.openai.com (placeholders), the OpenAI community forum, the GitHub
secret-scanning pattern list (only `openai_api_key`), osv-scalibr (generic
`sk-…T3BlbkFJ…` rule), noseyparker v0.24.0, Kingfisher (imports), CredSweeper,
Microsoft security-utilities. No independent implementation validates the
admin width.

## Corroborated-route count

For the 58/58 shape: #1, #2, #3, #4 (four peer owners, pinned) and #5
(OpenAI, provider-owned-code, pinned). That is 5 references, 5 owners and
2 non-summary classes. The provider class backs only the prefix and marker;
the 58/58 width rests on peer consensus and gitleaks' revoked vectors.

## Contradictions

| Statement | Proposed status | Basis |
| --- | --- | --- |
| "trufflehog 3.97.4 explicitly excludes admin keys" (dossier) | resolved: a misreading | the `openai` detector's comment excludes `sk-admin-` because PR #4689 moved admin keys to the dedicated `openaiadmin` detector (#1), which ships in v3.97.4 and requires marker + 58/58. trufflehog corroborates the contract |
| trufflehog #4698: marker-less `sk-admin-` + 124 | bounded | already out of contract (#863); trufflehog's own detector treats that shape as a negative |
| 74/74 admin width (the shared gitleaks union) | recommend bound | no source anywhere shows a 74/74 admin value; the 74 branch is shared with `sk-proj-`/`sk-svcacct-` |

## Recommendation for the ledger

Freeze the admin positive set at 58/58 and record 74/74 as outside the
claim (no fixture asserts it either way), the same treatment the
`openai-token` record gives undecided service-account widths. The detector
may keep accepting 74/74.

## Out of scope

The 16 unresolved differential disagreements and the missing `mode`,
`uncertainty` and `supportedContexts` fields are ledger work. The first
contradiction above explains at least part of the differential set:
trufflehog's generic `openai` detector declines `sk-admin-` by design.
