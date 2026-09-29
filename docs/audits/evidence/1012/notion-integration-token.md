# #1012 research: `notion:integration-token` (`ntn_`)

[Research index](README.md) ·
[Issue #1012](https://github.com/redact-secret/redact-secret/issues/1012) ·
[#642 evidence (Notion prefix)](../642/README.md) ·
[Benchmarks research #225](https://github.com/redact-secret/redact-secret-benchmarks/issues/225)

Frozen 2026-09-29. Desk research only: no key was issued, and no issued or
leaked credential is evidence. Sources were accessed on 2026-09-29.

**Verdict: BLOCKED (body).** The `ntn_` prefix is T1 (changelog, and a new
@NotionHQ statement). The body (11 digits then 35 alphanumerics, 50 in
total) rests on peer scanner rules alone, one corroboration class, so the
T2 route fails. A new peer rule (CredSweeper) contradicts the 11-digit run.
Notion itself says not to validate tokens with a regex.

## Current product behaviour

`notion-token` (`crates/secret-scan-core/src/detectors/notion.rs`) claims
`ntn_` + exactly 11 ASCII digits + exactly 35 `[A-Za-z0-9]`, and legacy
`secret_` + 43. The support-matrix reason: "the ntn_ prefix is
provider-documented, the 11-digit + 35-character body is tool-only and
provisional".

## Sources

| # | Source | Date | Class | Ruling | Statement |
|---|---|---|---|---|---|
| 1 | [Notion developers changelog](https://developers.notion.com/page/changelog) (entry of 2024-09-11) | 2024-09-11 | provider changelog | T1 (prefix) | "newly generated Public API tokens will automatically use the ntn_ prefix"; "We strongly advise against using regular expressions (regex) to identify or validate Notion Public API tokens. The token format may change over time" |
| 2 | [@NotionHQ on X, status 1914437336789553311](https://x.com/NotionHQ/status/1914437336789553311) (new) | 2025-04-21 | provider statement off the docs domain | R3 = T1 (prefix) | "The ntn_ format is our current standard for integration tokens". No length or alphabet |
| 3 | [makenotion/notion-mcp-server `src/openapi-mcp-server/mcp/token.ts` L21-L32 @ 730ae78](https://github.com/makenotion/notion-mcp-server/blob/730ae781ba28beeaf0865025a3f2ed4c25ea2387/src/openapi-mcp-server/mcp/token.ts#L21-L32) | 2026-06-17 | provider code | R6 (prefix); comment T2 | accepts `ntn_` and `secret_`; length 8–300 only, avoiding "coupling to an exact server-side length we don't control" |
| 4 | [makenotion/notion-skills-github-sync `setup/steps/credentials.ts` L172-L175 @ 2e882e4](https://github.com/makenotion/notion-skills-github-sync/blob/2e882e4ecff7629a5213ba585fe438347f8f2666/setup/steps/credentials.ts#L172-L175) (new) | 2026-08-11 | provider code | R6 (prefix) | accepts `ntn_`, `secret_` and `development_ntn_`; its log redactor uses a floor of 20 `[A-Za-z0-9]` |
| 5 | [makenotion/lore `src/auth/token-prefix.ts` L6-L44 @ 6e741b1](https://github.com/makenotion/lore/blob/6e741b1bb91a36b47213f4d3af5bbdfaa2f2081d/src/auth/token-prefix.ts#L6-L44) | 2026-05-12 | provider code | R6 (prefix, role) | `ntn_` is a production PAT or `ntn` bot token; `development_ntn_` is development; `secret_` is an integration |
| 6 | [gitleaks `config/gitleaks.toml` L2652-L2656 @ b58d3f1](https://github.com/gitleaks/gitleaks/blob/b58d3f102cf3a2c84cb7f923d05c25c9b1aed84b/config/gitleaks.toml#L2652-L2656) | 2025-06-08 | peer scanner rule | T2 input | `ntn_[0-9]{11}[A-Za-z0-9]{32}[A-Za-z0-9]{3}`; betterleaks and Kingfisher carry the same rule (one lineage) |
| 7 | [secretlint `secretlint-rule-notion/src/index.ts` L38-L50 @ 0001184](https://github.com/secretlint/secretlint/blob/0001184f56165e7db7ab1b3adc1f957911c78f46/packages/%40secretlint/secretlint-rule-notion/src/index.ts#L38-L50) | 2026-04-11 | peer scanner rule | T2 input | `ntn_[0-9]{11}[A-Za-z0-9]{35}` |
| 8 | [CredSweeper `config.yaml` L1630-L1644 @ f21ab2f](https://github.com/Samsung/CredSweeper/blob/f21ab2f2553eea288a72273b9658cd297ab1d11f/credsweeper/rules/config.yaml#L1630-L1644) (new) | 2025-12-17 | peer scanner rule | contradicts #6, #7 | `ntn_[0-9]{9}[0-9A-Za-z_-]{36,255}`; its test samples are 50 characters with a 9-digit lead followed by a letter |

Searched, nothing further: `developers.notion.com/llms-full.txt` (placeholders
only); notion-sdk-js and notion-sdk-py (no validation); `ntn_` in
`org:makenotion` (prefix checks only); trufflehog (`secret_` only),
noseyparker, osv-scalibr (no Notion rule). GitHub's pattern list names
`notion_api_token` and `notion_integration_token` without a regex.

## Exact missing evidence

- **Digit run:** 11 (gitleaks, secretlint, product) or 9 (CredSweeper
  samples). No provider source.
- **Body alphabet:** `[A-Za-z0-9]` or with `_`/`-` (CredSweeper). No provider
  source.
- **Total length:** 50 in every rule sample; no provider statement.
- A second corroboration class (a provider example, provider code or an
  independent implementation) for the body would open the T2 route; none
  exists.

## Structure-only issuance check

Issue one internal-integration token and one personal access token. For
each record: total length (50?), count of leading digits after `ntn_` (11 or
9?), whether the rest is only `[A-Za-z0-9]`, and whether the two tokens share
the digit run (is it an ID?). `rawValueRetained: false`, then revoke.

## Residual risk

- **False negatives (today):** a 9-digit-lead token, if CredSweeper's samples
  reflect real issuance; any format change Notion warns about.
- **Roles:** `ntn_` covers internal-integration tokens, PATs and bot tokens
  (#5); a contract should be role-agnostic. `development_ntn_` stays out (the
  leading boundary rejects it).
