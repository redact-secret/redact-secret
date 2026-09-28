# #860 handoff: `helicone:api-key`

[#860 handoff index](README.md) ·
[Research table #34](https://github.com/redact-secret/redact-secret/issues/860#issuecomment-5852386967)

**Readiness: READY.** **Route:** new detector `helicone-api-key` with two
finding types. **`pk-` is detected and redacted as its own type.**

## Role and blast radius

Helicone is an LLM gateway and observability proxy that sits in agent traffic
(`Helicone-Auth: Bearer <key>`).

- **`sk-` (read-write) key:** reads all logged prompts and responses and
  administers the org.
- **`pk-` (write-only) key:** can only send requests and logs into the org.
  The docs allow placing it in a URL path for clients that cannot set headers.

## Decision: `pk-` policy

`pk-` is a credential, not a public identifier, so it is **detected and
redacted** under its own type:

- Helicone documents it as an API key with write permission. No provider
  source says it is safe to publish. That is the difference from PostHog
  `phc_` ("ok to be public") and Stripe `pk_` ("publishable").
- A leaked write key lets a third party inject requests and logs into the org
  (log poisoning, and usage billed to the org).
- Putting it in a URL path is a transport convenience. It does not make the
  key public.
- A separate type lets a user policy downgrade `pk-` to `warn` without
  touching `sk-`. The default follows the security-first rule: an unexplained
  credential is redacted.

| Prefix | Finding type |
| --- | --- |
| `sk-helicone-`, `sk-helicone-eu-`, `sk-helicone-rl-`, `sk-helicone-eu-rl-`, `sk-helicone-proxy-` | `helicone_api_key` |
| `pk-helicone-`, `pk-helicone-eu-`, `pk-helicone-rl-`, `pk-helicone-eu-rl-` | `helicone_write_api_key` |

## Supported shapes

Sources, provider code at
[`067d929`](https://github.com/Helicone/helicone/tree/067d9290acb4f1fc9320e902fc67b4b399b50363):

- the worker validation regexes (`worker/src/lib/util/apiKeyRegex.ts`,
  duplicated in the Jawn server), which reject any other key as "not well
  formed";
- the dashboard generator (`web/utils/generateAPIKeyHelper.ts`) and the server
  generator (`valhalla/jawn/src/managers/apiKeys/KeyManager.ts`, which also
  builds the proxy key);
- the docs, for the `sk`/`pk`/`eu` roles.

**Re-checked 2026-09-28:** `apiKeyRegex.ts` was last changed 2025-04-29
([`2d92b7e`](https://github.com/Helicone/helicone/commit/2d92b7e92c2518a4bbc2ed6cefa1b8737bb9de82)),
before the research's pinned tree, and its regex list is unchanged.

| Part | Grammar | Provenance | Tier |
| --- | --- | --- | --- |
| Role prefix | `sk` or `pk` | worker regex + docs | T1 |
| Provider segment | `-helicone` | worker regex + generators | T1 |
| Optional segments, in order | `-eu`, then `-rl` | worker regex (`-rl` added 2025-04-29) | T1 |
| Body | `-` + four groups of exactly 7 `[a-z0-9]`, joined by `-` | worker regex + generator (base32, lowercased) | T1 |
| Proxy key (`sk` only) | `sk-helicone-proxy-` + the same four groups + `-` + a lowercase 8-4-4-4-12 UUID | server generator `KeyManager.ts` (R1) | T1 |

Lengths:

- standard key: 43;
- `-eu` or `-rl`: 46;
- `-eu-rl`: 49;
- proxy key: 86.

The alphabet is the provider's own `[a-z0-9]`. The generator's third-party
library emits RFC 4648 base32 (`[a-z2-7]`, final byte of each group in
{a,i,q,y}). Maintainer ruling R8
([2026-09-28](https://github.com/redact-secret/redact-secret/issues/860#issuecomment-5871306275))
rejects alphabet narrowing from a third-party library, so the narrower class
is **not** enforced: a change of library must not become a false negative. It
may still be used as a test-generator hint.

## Excluded shapes

| Shape | Why excluded |
| --- | --- |
| Legacy bare `sk-` + 4×7 (34 bytes, no `helicone`) | still accepted by the validator, but carries no provider token. It overlaps the generic `sk-` space and is not attributable. Named contexts are covered by generic detection |
| Customer-portal `sk-cp-`, `sk-eu-cp-`, `pk-…-cp-` | no provider token; same reason |
| `-gov` combinations | produced by the dashboard generator but matched by no worker regex. Whether they are accepted is unresolved (see checklist) |
| Groups using `_` (the catch-all `\w{7}` regex) | the catch-all form only covers the unattributable legacy and `cp` shapes above |
| Uppercase keys | the generator lowercases the whole key |

## Tier rationale

T1 for prefix, segments, group structure and alphabet: the provider's own
validator states them as regexes, and the generators agree. The proxy-key
shape is T1 under R1 (server generator). The base32 narrowing is not T1 (R8:
no) and is not used.

## Overlap and output policy

- **Existing detectors.** `vendor_prefixed_credential` matches `sk-` plus 48
  alphanumerics only. A Helicone key has `-` inside and is not claimed.
  OpenAI's `openai-token` requires its marker, and Anthropic/OpenRouter use
  other literal segments. Measured on `main`: named contexts
  `contextual_secret`, Bearer `bearer_token`; bare, chat and JSON `"token"`
  are missed.
- **New output.** Two provider types, high confidence, always redact.
- **URL path.** A `pk-` key inside `https://gateway.helicone.ai/<key>/v1/` is
  delimited by `/`, which the boundary allows, so it is claimed.

## Implementation notes

`KnownFormatProviderDetector` table:

- one prefix per supported segment combination (longest prefix wins, so
  `sk-helicone-eu-rl-` is tried before `sk-helicone-eu-`);
- each followed by an exact 31-byte run over `[a-z0-9-]`, with a post check
  that `-` sits exactly at offsets 7, 15 and 23;
- the proxy key as its own shape: an exact 68-byte run with a post check for
  the groups and the UUID dashes.

Boundary `[A-Za-z0-9_-]`, so a fifth group or a glued suffix is rejected.
Signals: `helicone-documented-prefix`, `helicone-validator-groups`.

## Test axes

**Positives:**

- all nine prefixes, plus a proxy key;
- every index context plus `Helicone-Auth: Bearer`, the gateway URL-path form,
  an OpenAI-client `default_headers` dict, and `HELICONE_API_KEY=`.

**Near-miss twins:**

- a group of 6 or 8;
- three or five groups;
- `_` in place of `-`;
- an uppercase byte;
- a byte outside `[a-z0-9]`;
- segment order `-rl-eu-`;
- `sk-heliconeX-`;
- a leading glue byte (`xsk-helicone-…`) and a trailing glue byte;
- a proxy key with a malformed UUID.

**Benign** (unclaimed by the new detector):

- `sk-helicone-xxxxxxx-xxxxxxx-xxxxxxx-xxxxxxx` and `sk-helicone-...`
  placeholders. The all-`x` placeholder has the exact shape and **is
  claimed**, per the #867 placeholder precedent; the test records that as the
  accepted behavior, not as benign;
- the legacy bare `sk-` 4×7 and `sk-cp-` forms (unclaimed by this detector);
- `helicone.ai` URLs;
- `HELICONE_API_KEY=${…}`.

## False-positive / false-negative boundary

- **Accepted false negatives:**
  - legacy bare `sk-` and customer-portal keys outside named contexts;
  - `-gov` keys;
  - any future segment.
- **Accepted false positives:**
  - an exact-width documentation placeholder made of alphabet bytes;
  - a non-Helicone string with the literal `-helicone-` segment and four
    7-byte groups. None is known.

## Issuance checklist (optional confirmation; structure only)

- For one `sk-` key and one `pk-` key (EU org if available): total length,
  group lengths, alphabet classes.
- If governance keys can be issued: whether `-gov` appears and where.
- `rawValueRetained: false` and revoked.

The research also notes Helicone may be in maintenance mode. Detection is
still worth having for existing keys; issuance may be impossible, which does
not block this READY contract.
