# Issue #653 — T1 provider evidence for `generic:unclassified-assignment-literal`

[Audit archive](../../README.md) ·
[Issue #653](https://github.com/redact-secret/redact-secret/issues/653) ·
[Epic A #575](https://github.com/redact-secret/redact-secret/issues/575) ·
[Research pass 2](https://github.com/redact-secret/redact-secret/issues/653#issuecomment-5784935109) ·
[Broad-discovery pass](https://github.com/redact-secret/redact-secret/issues/653#issuecomment-5785503304) ·
[Warn on high-signal names ADR](../../../decisions/2026-09-20-warn-unconditionally-on-high-signal-contextual-names.md) ·
[Bare vendor-prefixed policy layer ADR](../../../decisions/2026-09-21-govern-bare-vendor-prefixed-policy-layer.md)

Written 2026-09-23 on branch `milocosmopolitan/beta7-research`. The two
iterative passes stay in the linked issue comments and are not restated here.

## Verdict: NOT FOUND — EXHAUSTIVE as of 2026-09-23, for the scored span

No provider-domain or RFC source defines a lexical shape for this family, and
none can: the family has no provider, and every applicable RFC grammar allows
any printable value. This matches the tier the benchmarks already record.

| property | provable at T1 | basis |
| --- | --- | --- |
| prefix / namespace | no | none exists; no provider (`"provider": null` in `benchmarks/support/taxonomy.json`) |
| length | no | RFC 6749 `client-secret = *VSCHAR` (zero or more); RFC 8265 `password = 1*(freepoint)`; NIST SP 800-63B gives minimums only |
| alphabet | no | RFC 6749 `VSCHAR = %x20-7E` (any printable ASCII); RFC 8265 allows the PRECIS FreeformClass (Unicode) |
| delimiter / marker / checksum | no | none in any RFC, spec, or tool; tools describe the class as having none |
| sensitive field name (context, not value) | partly | `client_secret`, `access_token`, `refresh_token` are RFC 6749 parameter names; the rest are convention. A name documents the context property the twins vary, not the value shape |

## The source

No source meets the bar. The load-bearing negative sources, re-fetched
2026-09-23 (`observedAt` 2026-09-23):

- `https://www.rfc-editor.org/rfc/rfc6749.txt`, Appendix A.2:
  > `client-secret = *VSCHAR`

  with Appendix A `VSCHAR = %x20-7E`; `access-token` and `refresh-token` are
  `1*VSCHAR` (A.12, A.17).
- `https://www.rfc-editor.org/rfc/rfc8265.txt`, §4.1:
  > `password   = 1*(freepoint)`
- `https://www.rfc-editor.org/rfc/rfc7591.txt`, §2: `client_secret` is
  "OAuth 2.0 client secret string" with no syntax beyond that.
- Corroboration only (not provider domain, not T1):
  `https://docs.github.com/en/code-security/secret-scanning/copilot-secret-scanning/responsible-ai-generic-secrets`
  describes this class as "unstructured secrets in source code that
  deterministic pattern matching cannot find"; Nosey Parker `generic.yml`
  L1-7: "there isn't some notable prefix to search for, nor is there a fixed
  length and alphabet for the secret content".

## Proposed `covers` sentence

None. The family stays T3 with `references: []`. The existing review note in
`benchmarks/lib/assessment.ts` ("An arbitrary literal in a sensitive field is a
masking-policy case, not a provider-format ground truth") and the context-twin
decision (`redact-secret-benchmarks` `docs/decisions/2026-09-20-extend-twins-to-assignment-context.md`,
"no provider exists for an arbitrary literal") remain accurate.

## Contradictions with the current contract

None. There is no lexical contract to contradict:

- `docs/contracts/precision/precision-contracts.json` has no `generic-token`
  entry (its families are openai, digitalocean, docker, slack, huggingface,
  cloudflare, linear, google-api-key, notion, vercel).
- The benchmarks contract is `generic-token: { tier: 'T3', references: [] }`,
  pattern "none (keyword-gated / structural)", and `detector-coverage`
  fixtures for it route to `policy(...)` (`assessment.ts` L73, L139).
- The detector (`crates/secret-scan-core/src/detectors/generic_token.rs`)
  gates on an exact normalized name in `HIGH_SIGNAL_NAMES` (14) or
  `AMBIGUOUS_NAMES` (5), `=`/`:` assignment, and a value of 8–4096 bytes
  (`MIN_CONTEXT_VALUE_LENGTH`, `MAX_CONTEXT_VALUE_LENGTH`); entropy (3.0 / 3.5
  at ≥16 bytes) selects confidence only. The RFC grammars neither support nor
  contradict these bounds; they are project policy.

Differences from tool consensus (exact-name matching, operator set, 4096 cap,
keyword list) are recorded in the
[broad-discovery pass](https://github.com/redact-secret/redact-secret/issues/653#issuecomment-5785503304).
They are tuning differences, not contradictions with an authoritative source.

## Sources checked

The issue's "Done when" lists provider-domain source classes. This family has
no provider, so each class is mapped to its nearest non-provider analogue.
Full URL-level tables: [research pass 2](https://github.com/redact-secret/redact-secret/issues/653#issuecomment-5784935109)
(RFCs, specs, 2026-09-22) and [broad-discovery pass](https://github.com/redact-secret/redact-secret/issues/653#issuecomment-5785503304)
(tools, vendor docs, community, 2026-09-22).

| source class | result |
| --- | --- |
| product docs and API reference, incl. OpenAPI/JSON schemas | No provider. Nearest analogues: RFC 6749, 7591, 8265, 7617, 9110, 6750, 3986; NIST SP 800-63B; OpenAPI 3.1 §4.8.27 (`apiKey` defines location only); YAML 1.2.2, TOML 1.0, POSIX shell, `java.util.Properties`. None defines a value shape. RFC 6749, 7591, 8265, 7617 and NIST re-fetched 2026-09-23 |
| changelog / release notes | No provider changelog exists. Nearest analogue, the RFC update chain: datatracker lists RFC 6749 as "Updated by RFC 8252, RFC 8996, RFC 9700". All three fetched 2026-09-23; none contains a `VSCHAR` or `client-secret =` production, so none changes the value grammar |
| engineering / security blog | No provider blog. Vendor detector docs (GitGuardian generic HES and generic password, 2026-09-07) and HN/SO/GitHub-issue discussion: keyword + operator + bounded value run only |
| secret-scanning partner pages | GitHub `supported-secret-scanning-patterns` (re-fetched 2026-09-23): "Generic password" is listed under AI-detected patterns, not as a regex or partner pattern; no partner format exists for a provider-less class. IANA HTTP auth-scheme registry (re-fetched 2026-09-23): `Token` is not a registered scheme |
| SDK / CLI docs on the provider domain | No provider SDK. Config-key docs such as AWS CLI `cli-configure-files` name keys (`aws_secret_access_key`) whose value shape belongs to the aws family |

Blocked or partial, recorded as such:

- `platform.openai.com/docs/api-reference/authentication`: HTTP 403 again on
  2026-09-23. This covers only the bare `sk-` policy layer, which has no
  fixtures in this family and belongs to `openai:secret-api-key` (#657). It
  is "not read", not "not found", and does not affect this verdict.
- Reddit: partially read (403/429 on search APIs). Cannot meet the T1 bar.
- Xygeni and Microsoft CredScan not reached. Tool sources, cannot meet the bar.

## Open items

- None for T1. The family cannot enter the T1 re-tier batch; reaching
  `stable` needs a change to how #575 counts provider-less policy families,
  which is outside this issue.
- Optional, not T1: the five synthetic-input behaviour checks (compound names,
  operators, weak passwords, base64 values, 200-byte cap) listed in the
  [broad-discovery pass](https://github.com/redact-secret/redact-secret/issues/653#issuecomment-5785503304).
  They measure tool-parity divergence and need no real credential.

## What this document does not do

It changes no detector, contract, fixture, or tier.
`docs/contracts/precision/precision-contracts.json` and
`benchmarks/lib/assessment.ts` are untouched. It contains no credential and no
full example value.

## Authority

This document records evidence. It does not select a version, create a tag,
publish a package, or authorize any release operation.
