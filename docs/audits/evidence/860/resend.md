# #860 handoff: `resend:api-key`

[Tier B re-rank](tier-b-rerank.md) ·
[Research table #02](https://github.com/redact-secret/redact-secret/issues/860#issuecomment-5852386450)

**Readiness: READY.** **Route:** new detector `resend-api-key`, finding type
`resend_api_key`.

## Role and blast radius

A Resend API key (`RESEND_API_KEY`, sent as `Authorization: Bearer`) sends
email as the account's verified domains. A `full_access` key also manages
domains, API keys and audiences. A leaked key enables phishing from a trusted
domain and exposes contact lists. Agents often hold it as a transactional
email tool.

## Supported shape

Sources:

- **Prefix.** The provider CLI rejects a key that does not
  `startsWith('re_')`
  ([`resend-cli` login](https://github.com/resend/resend-cli#authentication):
  "Your key must start with `re_`"). T1, provider code and docs.
- **Segments and separator.** The create-API-key response example on
  [resend.com/docs](https://resend.com/docs/api-reference/api-keys/create-api-key)
  shows a token of `re_` + 8 + `_` + 24.
- **The same shape in SDK fixtures.** The same value appears in the Go and
  Python SDK test fixtures. Two more, distinct values with the same shape
  appear in the Node SDK test client and the .NET example README. That is
  three distinct provider-authored values, one of them on the provider's
  docs domain.
  Maintainer ruling R5
  ([2026-09-28](https://github.com/redact-secret/redact-secret/issues/860#issuecomment-5871306275))
  gives provider test fixtures the weight of a docs example under the #655
  example-shape precedent.

**Re-checked 2026-09-28.** The live docs example was measured by script, with
no value retained:

- 36 characters in total;
- segments of 8 and 24 after `re_`, joined by one `_`;
- no `0`, `O`, `I` or `l` in either segment.

| Part | Grammar | Provenance | Tier |
| --- | --- | --- | --- |
| Prefix | `re_` | provider CLI code + README | T1 |
| Segment 1 | exactly 8 | docs response example + SDK fixtures (R5) | T1 by example |
| Separator | `_` at offset 11 | same | T1 by example |
| Segment 2 | exactly 24 | same | T1 by example |
| Alphabet | `[A-Za-z0-9]` in both segments | every provider example is alphanumeric; the superset is chosen deliberately (next paragraph) | by example (#655 treatment) |

Total length 36.

**Alphabet: superset, not base58.** trufflehog uses base58, and the three
provider values are consistent with base58. But three samples prove what is
present, not what is excluded; the #655 Entra row made the same call. The
contract takes the alphanumeric superset, so a real key containing `0`, `O`,
`I` or `l` is not a false negative. The cost is negligible, because the
exact 8/`_`/24 layout already does the discriminating.

## The short-prefix guard

`re_` is very short, and it ends many identifiers (`are_`, `pre_`, `score_`)
and Python `re_` names. The leading boundary (`[A-Za-z0-9_-]` before `re_`
rejects the match) removes glued cases. A standalone `re_` + 8 letters + `_`
+ 24 letters snake/camel identifier is still possible (for example a
`re_` + verb + `_` + 24-letter camelCase run).

The recommended post check matches Tier A's Composio `ak_` guard: the 32 body
bytes must contain **at least one uppercase and at least one lowercase
letter**. For a uniform body over the alphanumeric alphabet (26 upper, 36
non-upper), P(no uppercase) = (36/62)^32 ≈ 2.8e-8. P(no lowercase) is the
same, so the false-negative cost is about 6e-8. Every all-lowercase
identifier is removed. The residual is a camelCase identifier of exactly
that layout, recorded as an accepted false positive.

## Excluded shapes

| Shape | Why excluded |
| --- | --- |
| `re_` + GUID (the .NET mock API server) | a test stub generator, not the issuer; a dashed body fails the layout |
| `re_` + 36 lowercase alphanumerics (the Go webhook example) | an illustrative placeholder that contradicts the docs example; fails the layout |
| `re_123`, `re_123456789`, `re_xxxx…`, `re_yourkey`, `re_...`, `re_*********` | placeholders and masks; fail the layout or the mixed-case guard |
| API key object IDs (UUIDs) | not secret |
| Webhook signing secret `whsec_…` | Svix scheme; a separate family, not researched here |

## Overlap and output policy

- **Existing detectors.** None claims `re_`. Measured on `main`:
  - env, `export`, `X-API-Key`, JSON `api_key` and the SDK keyword argument
    give `contextual_secret`, high;
  - Bearer gives `bearer_token`, high;
  - bare, chat and JSON `"token"` are missed.
- **Shared-prefix check.** No other issuer using `re_` was found.
- **New output.** Provider type, `Confidence::High`, `ALWAYS_REDACT_TYPES`.
  `full_access` and `sending_access` keys share one shape, so they share one
  type.
- **`generic-token` deferral.** `resend` is not added (Tier A shared rule).

## Implementation notes

Use `KnownFormatProviderDetector` with
`PrefixShape::exact("re_", 33, pattern::is_alnum_underscore, …)` and a post
check. The post check requires the `_` at body offset 8, no other `_`, and
the mixed-case guard. The boundary is `[A-Za-z0-9_-]`.

Signals: `resend-cli-enforced-prefix`, `resend-example-layout`.

## Test axes

**Positives:**

- every context in the re-rank's probe list;
- `RESEND_API_KEY=` in `.env`;
- `new Resend("…")` and `resend.api_key = "…"`;
- an MCP server `env` block;
- a curl `Authorization: Bearer` line.

**Near-miss twins:**

- segment 1 of 7 or 9;
- segment 2 of 23 or 25;
- `-` in place of the separator `_`;
- a second `_` inside segment 2;
- an all-lowercase body (guard);
- `RE_` uppercase prefix;
- a leading glue byte (`are_…`, `_re_…`) and a trailing glue byte.

**Benign:**

- the placeholders listed above;
- Python `re_compile`, `re_pattern_cache` names;
- `pre_process_all_inputs_now`;
- `RESEND_API_KEY=${RESEND_API_KEY}`;
- a `whsec_` value.

## False-positive / false-negative boundary

- **Accepted false negatives:**
  - a key whose body is all one letter case (about 6e-8);
  - any future layout change;
  - a key glued to an identifier.
- **Accepted false positives:** a mixed-case `re_` + 8 + `_` + 24
  alphanumeric identifier with clean boundaries.

## Issuance checklist (optional confirmation; structure only)

For one `full_access` and one `sending_access` key, record:

- total length (expect 36);
- segment lengths (expect 8 and 24) and the separator position;
- alphabet classes, and whether any of `0 O I l` appear;
- `rawValueRetained: false`, revoked.
