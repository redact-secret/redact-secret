# #1013 evidence: `mistral:realtime-client-token`

[Index](README.md) ·
[Issue #1013](https://github.com/redact-secret/redact-secret/issues/1013) ·
[Beta.10 research #780](https://github.com/redact-secret/redact-secret/issues/780)

Frozen 2026-09-29. Desk research only: no token was minted, and no issued or
leaked credential is evidence.

**Status (pin at `b9e90915`):** pending, no corpus. #780 found only the `rt_`
prefix and the two carriers.

**Verdict: STILL-BLOCKED.** Nothing beyond the prefix exists in any source
found. Only hands-on minting by the maintainer can close it.

## Sources

All read 2026-09-29.

| # | Source | Date | Owner | Class | Statement |
| --- | --- | --- | --- | --- | --- |
| 1 | [mistralai/platform-docs-public `realtime_transcription/client_auth/page.mdx#L51`](https://github.com/mistralai/platform-docs-public/blob/ecac75b617af32e87a6d59c5d9e39e7029fc35db/src/content/en/docs/studio/audio/speech_to_text/realtime_transcription/client_auth/page.mdx#L51) (also L68, L76-L86) | 2026-07-15 (commit `2f0dd463`, first with `rt_`) | Mistral AI | provider docs | T1 for the prefix: `"value": "rt_..."`; table "Prefix `rt_`", "Lifetime ~900 seconds", "Scope Single model", "Reusable Yes, until expiry". No body length or alphabet |
| 2 | [same repo `openapi-public-doc.yaml#L14278-L14292`](https://github.com/mistralai/platform-docs-public/blob/ecac75b617af32e87a6d59c5d9e39e7029fc35db/openapi-public-doc.yaml#L14278-L14292) | same | Mistral AI | provider spec | `ClientSecret.value`: `type: string`, `format: password`; no pattern, length or example |
| 3 | [same repo `api/endpoint/realtime/sessions/page.mdx#L341-L343`](https://github.com/mistralai/platform-docs-public/blob/ecac75b617af32e87a6d59c5d9e39e7029fc35db/src/content/en/api/endpoint/realtime/sessions/page.mdx#L341-L343) | same | Mistral AI | provider example | `client_secret.value` is a placeholder word, not a token shape |
| 4 | client-python [`models/clientsecret.py`](https://github.com/mistralai/client-python/blob/e8dfa1c8a2d0975cebfc0136b2d9060ff555494d/src/mistralai/client/models/clientsecret.py); client-ts [`clientsecret.ts#L13-L20`](https://github.com/mistralai/client-ts/blob/d8f2d2539cf00d13d429653ab891b66a3524a2a9/src/models/components/clientsecret.ts#L13-L20) | — | Mistral AI | generated SDK types | plain string, no constraint |

Searched with no body evidence: client-python, client-ts, cookbook and
mistral-vibe for `rt_` values; GitHub code search for `v1/client/sessions`,
`Sec-WebSocket-Protocol` with realtime, and `rt_` with realtime (Mistral's own
repos, gateways and doc mirrors, none with a token shape); every locally
cloned scanner (none has an `rt_` rule).

## Issuance check (the only way to close this)

Needs a Studio key with the `create_client_session` permission. Mint at
least two tokens through `POST /v1/client/sessions` and record from
`client_secret.value`, structure only: prefix case (`rt_`); total length and
whether it is the same across mints; body alphabet (hex, base62 or
base64url); whether the body contains `_`, `-` or `.`; whether `Bearer rt_…`
is accepted. Tokens expire in about 900 seconds; no revocation step is
documented.

## Why no contract is proposed

`rt_` is a common identifier prefix (`rt_config`, `rt_timeout`), so a
prefix-only rule would be imprecise. Keyed environment and `Bearer`
contexts are already redacted by generic paths; the JSON `client_secret`
and WebSocket subprotocol carriers remain a generic-carrier question (#780).
