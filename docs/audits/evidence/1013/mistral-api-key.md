# #1013 evidence: `mistral:api-key`

[Index](README.md) ·
[Issue #1013](https://github.com/redact-secret/redact-secret/issues/1013) ·
[Spec: keyword-gated provider keys (#868)](../../../specs/detector-families.md#keyword-gated-provider-keys-868)

Frozen 2026-09-29. Desk research only: no key was issued, and no issued or
leaked credential is evidence. Shapes only.

**Contract under test (#868, context-constrained):** exactly 32
`[A-Za-z0-9]`, claimed only beside a same-line Mistral name, host or
constructor. Never bare.

**Matrix blocker (pin at `b9e90915`):** corroborated route classes 1 < 2
(ledger: osv-scalibr, betterleaks, #781; all peer or summary).

**Verdict: READY-T2.** The missing second class is now supplied twice: a
provider example and an independent validator.

## Sources

All read 2026-09-29.

| # | Source | Date | Owner | Class | Statement (shape only) |
| --- | --- | --- | --- | --- | --- |
| 1 | [mistralai/platform-docs-public `openapi-public-doc.yaml#L33436-L33455`](https://github.com/mistralai/platform-docs-public/blob/ecac75b617af32e87a6d59c5d9e39e7029fc35db/openapi-public-doc.yaml#L33436-L33455), schema `APIKeyExtendedOUT`; rendered on docs.mistral.ai `api/endpoint/beta/admin/api-keys` | 2026-07-24 (commit `220f18c8`, "sync docs to v1.3.0") | Mistral AI | provider-example (R5) | field `key`, "Plaintext API key value. Only returned at creation time.", example: one full-length value, 32 `[A-Za-z0-9]` with upper, lower and digits, no prefix. `hidden_key` shows 4 + `...` + 4. **New** |
| 2 | [gitkraken/vscode-gitlens `mistralProvider.ts#L156-L159`](https://github.com/gitkraken/vscode-gitlens/blob/6492b560fd704d62fc6e0bd4f86c4daa06a4d8e1/packages/plus/ai/src/providers/mistralProvider.ts#L156-L159), enforced at [`openAICompatibleProviderBase.ts#L85-L92`](https://github.com/gitkraken/vscode-gitlens/blob/6492b560fd704d62fc6e0bd4f86c4daa06a4d8e1/packages/plus/ai/src/providers/openAICompatibleProviderBase.ts#L85-L92) | 2025-05-27 ("Adds Mistral support") | GitKraken | independent-implementation (validates the key on entry) | `keyValidator: /^[a-zA-Z0-9]{32}$/`. **New** |
| 3 | [Zaki-1052/GPTPortal `ValidationUtils.js#L150`](https://github.com/Zaki-1052/GPTPortal/blob/eb320cd2763afc7dcf0c290029fc499b43444666/src/server/utils/ValidationUtils.js#L150) | 2025-05-23 | Zaki-1052 | independent-implementation | `/^[A-Za-z0-9]{32}$/` |
| 4 | [juspay/neurolink `providerConfig.ts#L51`](https://github.com/juspay/neurolink/blob/4d034813e71eae2f04fe189df3b2fc162e063aa4/src/lib/utils/providerConfig.ts#L51) | 2025-07-30 | Juspay | independent-implementation | `/^[A-Za-z0-9]{32}$/` |
| 5 | osv-scalibr veles `mistralapikey` at `6eb351350a6c` (ledger) | — | Google | peer-scanner-rule | 32 alphanumerics beside Mistral context |
| 6 | betterleaks `mistral.go` at `2a387a5bad42` (ledger) | — | betterleaks | peer-scanner-rule | Mistral keyword + 32 `[A-Z0-9]`, case-insensitive |
| 7 | [redact-secret#781](https://github.com/redact-secret/redact-secret/issues/781) (ledger) | 2026-09-26 | redact-secret | independent-research (summary) | — |

Also seen with the same shape, not needed for the count: gpt-home,
llm-key-validator, prompt-evaluator, keyledger, titus and poltergeist rules.
Searched with no shape statement: Mistral repos (client-python, client-ts,
mistral-vibe, cli, mistral-common, cookbook, zed-extensions); the Mistral
docs pages on API keys and Vibe key profiles; GitHub's secret-scanning list
(`mistral_ai_api_key`, with validity checks, format unpublished).

## Corroborated-route count

7 references, 7 owners, 3 non-summary classes (peer-scanner-rule,
provider-example, independent-implementation). The bar is 3 / 3 / 2.

## Contradictions

| Statement | Proposed status | Basis |
| --- | --- | --- |
| GitGuardian's `mistralai_apikey` page (updated 2026-09-28) lists a second type, "Mistral AI API Key v2", `Prefixed: True`, prefix undisclosed | bounded | no Mistral source mentions a prefixed key; the contract covers only the unprefixed context-gated shape and asserts nothing on a prefixed one. **Follow-up:** a prefixed Mistral key may exist; worth one look in the console |
| elizaOS validator accepts 20 or more alphanumerics | no contradiction | a looser floor |
| Codestral key and realtime `rt_` token (existing, bounded) | bounded (unchanged) | separate credentials |

## Out of scope

The matrix also lists 14 metamorphic critical failures, 2 unresolved
critical mutation findings and 3 unresolved differential disagreements for
this family. They are detector and fixture findings, not evidence gaps, and
must clear separately before `stable`.
