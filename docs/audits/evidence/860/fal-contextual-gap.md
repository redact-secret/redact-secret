# #860 note: the `fal:api-key` generic gap (contextual extension, not a family)

[Tier B re-rank](tier-b-rerank.md) ·
[Research table #03](https://github.com/redact-secret/redact-secret/issues/860#issuecomment-5852386450)

**Disposition: generic-coverage gap.** This is a contextual-extension
question for `generic-token` and `bearer-token`, not a provider family.
There is no fal provider anchor. The only T1 fact is the `key_id:key_secret`
colon join from fal's SDKs, CLI and Platform API docs. The UUID + 32-hex
halves are community-only.

## Step 2's diagnosis, corrected

Step 2 read the probe as "the colon-joined pair defeats generic assignment".
Re-measured on `main`
[`9ab0fa0`](https://github.com/redact-secret/redact-secret/commit/9ab0fa02f2aeeda16a2c99e04862ebb0f0e9b5e7)
(CLI release build, synthetic values generated at run time, metadata only),
the cause is the **variable name**, not the value.

| Input shape | Finding today |
| --- | --- |
| `FAL_KEY=<uuid>:<hex32>` (plain and `export`) | **none** |
| `FAL_KEY=<neutral 32-byte random>` | **none**: the name alone is enough to miss |
| `API_KEY=<uuid>:<hex32>` | `contextual_secret`, high, **full span**: the colon is fine |
| `SECRET=<uuid>:<hex32>` | `contextual_secret`, high, full span |
| `FAL_KEY_SECRET=<neutral>` | `contextual_secret`, high, full span |
| `X-API-Key: <uuid>:<hex32>`, JSON `api_key`, `Client(api_key="…")` | `contextual_secret`, high, full span |
| `Authorization: Key <uuid>:<hex32>` (fal's own scheme) | **none** |
| `Authorization: Bearer <uuid>:<hex32>` | `bearer_token` over the **first 36 bytes only**: the secret half stays in clear |
| bare, chat, JSON `"token"` | none |

**Root cause 1 (name vocabulary).** `generic-token`'s high-signal names are
`api_key`, `secret_key`, `private_key`, `*_token` and the like, and
`signing_key` is ambiguous. A bare `*_KEY` suffix is deliberately not in the
vocabulary: `SORT_KEY`, `CACHE_KEY`, `PRIMARY_KEY`, `PARTITION_KEY` and
`IDEMPOTENCY_KEY` all hold non-secrets. `FAL_KEY` is the provider's
documented and only credential variable, so fal's canonical form is
invisible.

The same gap hits Convex (`CONVEX_DEPLOY_KEY`,
`CONVEX_SELF_HOSTED_ADMIN_KEY`); see [convex.md](convex.md).

**Root cause 2 (scheme).** The `Authorization` credential path recognizes
`Basic` and `Token`, and `bearer-token` recognizes `Bearer`. fal's
documented `Authorization: Key <id>:<secret>` is none of these.

**Root cause 3 (exact span, general).** `bearer-token` stops at the first
byte outside the RFC 6750 `b64token` alphabet and emits the prefix it has
read. For an `id:secret` or `name|secret` value, that means it redacts the
non-secret left half and leaves the secret right half in clear. This is not
fal-specific: the Convex self-hosted admin key shows the same thing (18 of
93 bytes).

## Options

| Option | What changes | False-positive cost | False-negative cost | Recommendation |
| --- | --- | --- | --- | --- |
| A. Exact high-signal names | add `fal_key` to `EXACT_HIGH_SIGNAL_NAMES` (the #823 `db_pass` mechanism): the whole normalized name only, never as a suffix | a non-secret under a variable named exactly `FAL_KEY`: none known | none added | **yes**. It is value-agnostic, so it needs no T1 value grammar |
| B. Generic `*_key` suffix | treat every `<prefix>_key` as high-signal | high: sort, cache, primary, partition and object keys | — | **no** |
| C. `Authorization: Key` scheme | add `Key` to the authorization-credential schemes, whole value through the next whitespace | a non-credential `Key` header value. `Key` is rare as an auth scheme; it is fal's and the legacy FCM `key=` form | — | yes, as a second step, with the #818 mid-line rules unchanged |
| D. `bearer-token` whole-token span | when the `b64token` run is followed immediately by `:` or `\|` and more non-space bytes, either extend the span to the next whitespace or emit nothing | extending may over-redact prose | emitting nothing loses the partial redaction | separate issue; prefer extension, because a partial span that leaves the secret visible is the worse outcome |
| E. Keyword-gated fal row (#868 style) | a `fal` keyword + `<uuid>:<hex32>` value row in `keyword_gated_keys` | low | — | **no**: its value grammar would be T3 (community-only), and A already covers the named case |

## Recommendation

- Open **one** generic issue for A and C, with a scoped Convex addendum.
  - Name: `fal_key` and, for Convex, `convex_deploy_key` and
    `convex_self_hosted_admin_key` as exact names.
  - The Convex names matter until the gated `eyJ2` shape clears, because the
    provider detector's hex-body shapes do not cover cloud keys.
- Open **one** separate issue for D. It is an exact-span defect in a
  shipped policy-based contract (`generic:bearer-token`) and needs its own
  fixture and conformance-corpus update.

Neither issue is a provider family or support-status change.

**Out of scope here.** The fal id half alone (`FAL_KEY_ID`) is public-ish
(the gRPC `auth-key-id` header, `fal keys list`). The secret half alone
(`FAL_KEY_SECRET`) is already redacted.
