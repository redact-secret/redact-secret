# #860 handoff: `firecrawl:api-key`

[#860 handoff index](README.md) ·
[Research table #04](https://github.com/redact-secret/redact-secret/issues/860#issuecomment-5852386450)

**Readiness: READY.** **Route:** new detector `firecrawl-api-key`, finding
type `firecrawl_api_key`.

## Role and blast radius

A Firecrawl API key (`FIRECRAWL_API_KEY`, `Authorization: Bearer`) spends the
team's crawl and scrape credits. It is commonly configured in agent web tools
and MCP servers.

## Supported shape

Sources:

- the prefix from provider docs, and from the MCP server and SDK code
  (`startsWith('fc-')`);
- the body from provider server code at
  [`f75a8d4`](https://github.com/firecrawl/firecrawl/tree/f75a8d40b103129f56f947418bfa06a04a9ad5b0):
  - `apps/api/src/lib/parseApi.ts` strips `fc-` and re-inserts dashes 8-4-4-4-12
    "based on the uuidv4 format";
  - `apps/api/src/db/schema/public.ts` defines `api_keys.key` as
    `uuid("key").defaultRandom()`, a Postgres random UUIDv4;
  - `apps/api/src/controllers/auth.ts` rejects anything failing `UUID_RE`;
  - `apiKeyToFcApiKey` (2025-12-02) builds `fc-` + the dashless UUID.

**Re-checked 2026-09-28:** `parseApi.ts` was last changed 2026-05-15
([`9893e78`](https://github.com/firecrawl/firecrawl/commit/9893e784098a2bc48323cc77567382cc31d9d12e)),
before the pinned tree. The `fc-` strip, dash reinsertion and legacy
passthrough are unchanged.

| Part | Grammar | Provenance | Tier |
| --- | --- | --- | --- |
| Prefix | `fc-` | provider docs + SDK/MCP code | T1 |
| Body | exactly 32 lowercase hex: a dashless UUID | server normalizer + DB schema (R1) | T1 |
| Version / variant | body byte 12 is `4`; byte 16 is one of `8 9 a b` | DB default is a random UUIDv4 (R1) | T1 |
| Separators / checksum | none after the prefix | — | — |

Total length 35.

Enforcing the version and variant nibbles is justified by the T1 source (every
issued key is a Postgres random UUIDv4). It rejects 63 of 64 arbitrary 32-hex
strings, such as an `fc-` followed by an MD5 digest, at no false-negative cost
for issued keys.

## Excluded shapes

| Shape | Why excluded |
| --- | --- |
| Legacy bare dashed UUID (keys before 2024-04-16, still accepted by `parseApi`) | a plain UUID is not attributable to Firecrawl. Generic context covers named assignments. Stays **out**, as the step-2 selection required |
| `fc-` + 32 hex with another version nibble, or a non-RFC variant | the server's `UUID_RE` would accept versions 1–8, but issued keys are v4 |
| `fc-` + dashed UUID | not an issued form (the dashes are re-inserted server-side) |
| `fco_` OAuth access token | opaque, introspected, no documented shape |
| `fcmcp_` MCP delegated credential (HMAC, base64url, ≤ 2048) | no fixed grammar. It wraps a key; a follow-up if wanted |
| Uppercase hex body | the database renders lowercase |

## Tier rationale

Prefix T1 from docs. Body length, alphabet and UUIDv4 structure T1 under R1
(the provider's server normalizer, schema default and validator). The Dify
report of dashboard keys without `fc-` (2024-06) concerns the legacy form this
contract excludes.

## Overlap and output policy

- **Existing detectors.** None claims `fc-`. Pinecone's legacy-UUID rule
  (#702) claims only a dashed UUID under a Pinecone name, so there is no
  overlap. Measured on `main`: named contexts `contextual_secret`, Bearer
  `bearer_token`; bare, chat and JSON `"token"` are missed.
- **New output.** Provider type, high confidence, always redact.

## Implementation notes

`KnownFormatProviderDetector` with one
`PrefixShape::exact("fc-", 32, is_lower_hex, …).with_post_check(uuid_v4_nibbles)`
and the `[A-Za-z0-9_-]` boundary. A leading boundary matters here because
`fc-` is short: `xfc-`, `_fc-`, and CSS or calendar class names such as
`fc-daygrid-day` are either glued or fail the body.
Signals: `firecrawl-documented-prefix`, `uuidv4-body`.

## Test axes

**Positives:**

- every index context;
- `FIRECRAWL_API_KEY=`;
- `FirecrawlApp(api_key=…)` / `new Firecrawl({ apiKey })`;
- an MCP `env` block;
- a curl `Authorization: Bearer`.

**Near-miss twins:**

- body of 31 or 33;
- version nibble `1`, `7` or `0`;
- variant nibble `c` or `7`;
- an uppercase hex byte;
- a `g` in the body;
- a dashed UUID after `fc-`;
- `FC-` / `fc_`;
- a leading glue byte and a trailing glue byte.

**Benign:**

- `fc-YOUR-API-KEY`, `fc-test`, `fc-xxx`, `fc-your-api-key` placeholders;
- CSS classes (`fc-event`, `fc-daygrid-day`);
- a bare dashed UUID (not claimed by this detector);
- `fc-` + 32 hex that fails the v4 nibble.

## False-positive / false-negative boundary

- **Accepted false negatives:**
  - legacy dashed-UUID keys outside named contexts;
  - self-hosted instances with DB authentication off, where any string is
    accepted as a key;
  - `fco_` and `fcmcp_` credentials.
- **Accepted false positives:** an unrelated `fc-` + dashless lowercase UUIDv4
  (for example an `fc-`-prefixed record id minted from a v4 UUID). This is
  plausible but rare; the cost is redacting an identifier.

## Issuance checklist (optional confirmation; structure only)

For one dashboard key:

- total length (expect 35);
- alphabet classes (expect lowercase hex);
- body byte 12 = `4` and byte 16 in {8, 9, a, b} — a structural bit check, not
  the value;
- whether the dashboard still shows any unprefixed key;
- `rawValueRetained: false` and revoked.
