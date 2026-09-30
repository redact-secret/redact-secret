# #1014 handoff: `polar:organization-access-token`

[#1014 index](README.md) · rank 2 ·
[Research table #48](https://github.com/redact-secret/redact-secret/issues/1014#issuecomment-5900447820)

**Readiness: READY.** **Route:** new detector `polar-token`, finding types
`polar_organization_access_token` (`polar_oat_`) and `polar_api_credential`
(the other API roles below).

## Role and blast radius

Polar.sh is a payments and billing platform for developers. An organization
access token (`POLAR_ACCESS_TOKEN`, sent as `Authorization: Bearer`) acts on
the organization's products, checkouts, customers, subscriptions and orders
within its scopes. Personal access tokens and OAuth access and refresh tokens
act for a user or an organization, and the OAuth client secret lets an
integration mint tokens.

## Supported shape

Sources: `polarsource/polar` server code at
[`6a4f2f6`](https://github.com/polarsource/polar/tree/6a4f2f6d6083ef503cd23cb7f432ab2c60515973/server/polar),
re-checked 2026-09-29.

- `server/polar/kit/crypto.py`
  ([L11–L32](https://github.com/polarsource/polar/blob/6a4f2f6d6083ef503cd23cb7f432ab2c60515973/server/polar/kit/crypto.py#L11-L32)),
  current since
  [`80fae7f`](https://github.com/polarsource/polar/commit/80fae7fc98), 2025-01-02:
  37 characters from `string.ascii_letters + string.digits`, then the CRC32 of
  those 37 bytes in base62 (`0-9A-Za-z` digit order), zero-padded to 6.
- Before 2025-01-02, the same function returned
  `prefix + secrets.token_urlsafe()`: 32 random bytes as unpadded URL-safe
  Base64, which is 43 `[A-Za-z0-9_-]` with no checksum.
- Prefix constants: `organization_access_token/service.py`
  ([L42](https://github.com/polarsource/polar/blob/6a4f2f6d6083ef503cd23cb7f432ab2c60515973/server/polar/organization_access_token/service.py#L42),
  `polar_oat_`), `personal_access_token/service.py` (`polar_pat_`),
  `oauth2/constants.py`
  ([L5–L16](https://github.com/polarsource/polar/blob/6a4f2f6d6083ef503cd23cb7f432ab2c60515973/server/polar/oauth2/constants.py#L5-L16)).
- The organization access token service was added on 2025-02-05
  ([`4639cb7`](https://github.com/polarsource/polar/commit/4639cb7efd)),
  after the checksum era began, so every `polar_oat_` token has the
  alphanumeric-plus-checksum body.

| Role | Prefix | Body | Eras | Tier |
| --- | --- | --- | --- | --- |
| Organization access token | `polar_oat_` | exactly 43 `[A-Za-z0-9]` (37 + 6-char checksum) | one | T1 (R1, R9) |
| Personal access token | `polar_pat_` | exactly 43 `[A-Za-z0-9_-]` | both (the service no longer mints new ones; existing tokens are still accepted) | T1 (R1, R9) |
| OAuth access token | `polar_at_u_`, `polar_at_o_` | exactly 43 `[A-Za-z0-9_-]` | both | T1 |
| OAuth refresh token | `polar_rt_u_`, `polar_rt_o_` | exactly 43 `[A-Za-z0-9_-]` | both | T1 |
| OAuth client secret | `polar_cs_` | exactly 43 `[A-Za-z0-9_-]` | both | T1 |
| Client registration token | `polar_crt_` | exactly 43 `[A-Za-z0-9_-]` | both | T1 |

For the roles with two eras, the grammar is the union of the two issued
grammars: an era-1 body is 43 URL-safe bytes, and an era-2 body is 43
alphanumerics, which is a subset.

## Excluded shapes

| Shape | Why excluded |
| --- | --- |
| `polar_ci_` OAuth client id | public identifier by design |
| `polar_c_`, `polar_cl_` checkout and checkout-link client secrets | handed to the browser checkout by design; not a server credential |
| `polar_us_`, `polar_cst_`, `polar_mst_` session tokens; `polar_ac_` authorization codes; `polar_ev_`, `polar_cev_` email verification; `polar_oauth2_`, `polar_auth_session_` state | short-lived or single-use. They are credentials, so a later extension may claim them with the same body grammar; they are out of this contract to keep it to API roles |
| Webhook secret `whsec_` + 43 | the same generator with the prefix `whsec_`. Measured on `main`, `stripe-token` already reports it as `stripe_webhook_signing_secret` (redacted, attributed to Stripe). Polar cannot claim a prefix Stripe owns; the misattribution is accepted and recorded here |

## Tier rationale

T1 under R1 and R9: the prefix constants, the body length, the alphabet and
the era change all come from the provider's server code, dated by its commit
history. Betterleaks' `polar_(oat|pat|at)_[A-Za-z0-9_-]{20,100}` is looser and
is not used.

## Overlap and output policy

- **Existing detectors.** None claims `polar_`. Measured on `main`
  `b9e9091`: `POLAR_ACCESS_TOKEN=` gives `contextual_secret`; bare, chat and
  JSON `"token"` are missed.
- **Checksum.** For `polar_oat_` only, the CRC32 check could reject a
  43-alphanumeric run whose last 6 bytes are not the checksum. This depends
  on ruling Q1 in the index. Without Q1, the lexical grammar alone is the
  contract. The checksum must not be applied to the other roles, because an
  era-1 body is all-alphanumeric about a quarter of the time and has no
  checksum.
- **New output.** Two provider types, high confidence, always redact.

## Implementation notes

`KnownFormatProviderDetector` with `PrefixShape::exact("polar_oat_", 43,
is_alnum, …)` and one `PrefixShape::exact(prefix, 43, <[A-Za-z0-9_-] predicate>,
…)` per other prefix. Put `polar_at_u_`/`polar_at_o_` before any shorter
`polar_` prefix. Boundary `[A-Za-z0-9_-]`. Optional Q1 post-check via
`with_post_check` on the `polar_oat_` shape only. Signals:
`polar-generator-prefix`, `polar-generator-length`.

## Test axes

**Positives:** every #860 index context for `polar_oat_`, and one per other
role; `POLAR_ACCESS_TOKEN=` in `.env`; `Polar(access_token=…)` and
`new Polar({ accessToken })`; an MCP server config `env` block; an era-1
`polar_pat_` body containing `-` and `_`.

**Near-miss twins:**

- a body of 42 or 44;
- `polar_oat_` with a `-` or `_` in the body;
- `polar_at_` without the `u_`/`o_` sub-type;
- `POLAR_OAT_` uppercase;
- a leading glue byte (`xpolar_oat_…`) and a trailing glue byte.

**Benign:** `polar_ci_` + 43; `polar_c_` + 43; `polar_oat_`/`polar_pat_`
placeholders shorter than 43; `POLAR_ACCESS_TOKEN=${POLAR_ACCESS_TOKEN}`;
identifiers such as `polar_access_token_id`.

## False-positive / false-negative boundary

- **Accepted false negatives:** short-lived session and single-use tokens
  outside named contexts; a future generator change; a webhook secret stays
  attributed to Stripe.
- **Accepted false positives:** an unrelated `polar_<role>_` + exactly 43
  URL-safe bytes; none is known.

## Issuance checklist (optional confirmation; structure only)

For one organization access token:

- total length (expect 53) and body length (expect 43);
- alphabet classes (expect alphanumeric only, no `-` or `_`);
- `rawValueRetained: false` and revoked.
