# #1014 handoff: `paddle:api-key`

[#1014 index](README.md) · rank 8 ·
[Research table #42](https://github.com/redact-secret/redact-secret/issues/1014#issuecomment-5900447820)

**Readiness: READY.** **Route:** new detector `paddle-api-key`, finding type
`paddle_api_key`.

## Role and blast radius

A Paddle Billing API key (`PADDLE_API_KEY`, `Authorization: Bearer`) is a
server-side credential for a merchant-of-record billing account. With full
permissions it reads and changes customers, subscriptions, transactions,
prices and adjustments (refunds and credits). Sandbox keys act on the sandbox
environment only.

## Supported shape

Source: Paddle docs, "API keys",
<https://developer.paddle.com/api-reference/about/api-keys>, observed and
re-checked 2026-09-29. The page states:

- the parts: `pdl_` identifies a Paddle API key; `live_` or `sdbx_` names the
  environment; `apikey_` differentiates it from client-side tokens; then a
  26-character alphanumeric string, and the key;
- "They're 69 characters in length and always contain five underscores. You
  can use regex to match API keys:
  `^pdl_(live|sdbx)_apikey_[a-z\d]{26}_[a-zA-Z\d]{22}_[a-zA-Z\d]{3}$`";
- "API keys are case-sensitive";
- keys created before May 6, 2025 are legacy keys: "a random string of 50
  characters. They contain only lowercase letters and numbers", with no
  secret-scanning support.

Paddle's Node SDK notification mocks carry a masked key and an `apikey_`
id in the same layout
([paddle-node-sdk mock](https://github.com/PaddleHQ/paddle-node-sdk/blob/651261beddfc65ba5f861729dca17044cbeffb5f/src/__tests__/mocks/notifications/api-key-created.mock.ts),
2026-08-24).

| Part | Grammar | Provenance | Tier |
| --- | --- | --- | --- |
| Prefix | `pdl_live_apikey_` or `pdl_sdbx_apikey_` | docs regex | T1 |
| Id segment | exactly 26 `[a-z0-9]` | docs regex | T1 |
| Separator | `_` | docs regex | T1 |
| Secret segment | exactly 22 `[A-Za-z0-9]` | docs regex | T1 |
| Separator | `_` | docs regex | T1 |
| Suffix | exactly 3 `[A-Za-z0-9]` | docs regex | T1 |

Total length 69, stated by the docs.

## Excluded shapes

| Shape | Why excluded |
| --- | --- |
| Legacy keys (before 2025-05-06): 50 `[a-z0-9]`, no prefix | no distinctive shape; generic context covers `PADDLE_API_KEY=` |
| API key id `apikey_` + 26 | a non-secret identifier returned by the API and in webhooks |
| Client-side tokens (Paddle.js) | a separate, frontend credential by design |
| Paddle Classic vendor auth codes | a different product and shape |

## Tier rationale

T1 for every part: the provider docs publish the full regex and the total
length. betterleaks copies the same regex; it is not needed.

## Overlap and output policy

- **Existing detectors.** None claims `pdl_`. Measured on `main` `b9e9091`: a
  bare key in prose is missed; `PADDLE_API_KEY=` gives `contextual_secret`;
  chat and JSON `"token"` are missed.
- **Key id.** The `apikey_` + 26 id inside the key is not reported on its own.
  A bare id (without `pdl_…_` before it and the two trailing segments) is
  never claimed.
- **New output.** Provider type, high confidence, always redact, for live and
  sandbox alike (a sandbox key can still read and change sandbox data and is
  a policy violation to commit).

## Implementation notes

`KnownFormatProviderDetector` with two literal prefixes and a fixed 53-byte
tail check (26 `[a-z0-9]`, `_`, 22 `[A-Za-z0-9]`, `_`, 3 `[A-Za-z0-9]`).
Boundary `[A-Za-z0-9_-]`. Signals: `paddle-documented-regex`.

## Test axes

**Positives:** every #860 index context; `PADDLE_API_KEY=` in `.env`; a
`new Paddle(…)` constructor argument; `Authorization: Bearer`; a sandbox key.

**Near-miss twins:** id segment of 25 or 27, or with an uppercase byte;
secret segment of 21 or 23; suffix of 2 or 4; `pdl_test_apikey_`; a missing
`apikey_`; a `-` in place of a separator `_`; a leading glue byte and a
trailing glue byte.

**Benign:** a bare `apikey_` + 26 id in a webhook payload; a legacy-shaped
50-byte value; `PADDLE_API_KEY=${PADDLE_API_KEY}`; the docs' regex text
itself.

## False-positive / false-negative boundary

- **Accepted false negatives:** legacy keys outside named contexts.
- **Accepted false positives:** none known for this 69-byte layout.

## Issuance checklist (optional confirmation; structure only)

For one sandbox key: total length (expect 69), underscore count (expect 5)
and positions, per-segment alphabet classes, `rawValueRetained: false` and
revoked.
