# Evidence: #1229, Group D role, confidentiality and family-modelling contract (23 rows)

**Result:** the class-level, per-row conditional product contract for the 23
Group D roles. The mapping of each role is decided separately from the
source-neutral family records, from the options the issue lists (provider family
or alias, shared generic detection, metadata-only role, bounded composite or
secret-part claim, unresolved). The central decision is a new cross-family one
and has its own record,
[`decision-keep-credential-role-facts-out-of-detection-attribution-and-default-action`](../../../decisions/2026-10-06-keep-credential-role-facts-out-of-detection-attribution-and-default-action.md):
role and confidentiality facts do not select detection, attribution or the
default action. A search-only or read-only credential in a read carrier is not
silent, no role is attributed from a shared key shape, the default action is a
function of finding type and confidence alone, and a user override stays
possible. No row is claimed covered, passing or ready, no expectation is taken
from current output or scanner majority, and no carrier, field name, prefix,
width or alphabet is invented. No detector, registry entry, vocabulary name or
type changes; five boundaries are pinned by
`crates/secret-scan-core/tests/group_d_role_facts_1229.rs`. The independent
baseline (benchmarks
[#753](https://github.com/redact-secret/redact-secret-benchmarks/issues/753)) does
not exist yet.

Issue [#1229](https://github.com/redact-secret/redact-secret/issues/1229);
evidence epic [credential-evidence#237](https://github.com/redact-secret/credential-evidence/issues/237)
(children [#242](https://github.com/redact-secret/credential-evidence/issues/242),
[#243](https://github.com/redact-secret/credential-evidence/issues/243),
[#244](https://github.com/redact-secret/credential-evidence/issues/244), all
closed). Shared rules for the three groups (evidence classes, one origin per
copied rule, the five kinds, preconditions) are in
[#1228](../1228/README.md#disposition-kinds-and-the-rules-that-bind-every-row);
siblings [#1230](../1230/README.md) and Batch 2 [#1223](../1223/README.md).

## Sources

| Role | Source |
| --- | --- |
| Role and carrier facts (pending inputs, never decided here) | The handoffs [D1](https://github.com/redact-secret/credential-evidence/blob/522e079512f94930b053dc2fe5561dd63818f715/docs/handoffs/d1-242-algolia-contentful-roles.md), [D2](https://github.com/redact-secret/credential-evidence/blob/522e079512f94930b053dc2fe5561dd63818f715/docs/handoffs/d2-243-shared-carrier-roles.md) and [D3](https://github.com/redact-secret/credential-evidence/blob/522e079512f94930b053dc2fe5561dd63818f715/docs/handoffs/d3-244-transient-composite-roles.md), merged as credential-evidence PR #253 (read at head `522e0795`). Project-authored, not independent validation; every contract is `draft`, `period: proposed`, never reviewed. All 23 role records keep their IDs: none was merged or split, and no grammar was forced. |
| Independent baseline and replay | benchmarks [#753](https://github.com/redact-secret/redact-secret-benchmarks/issues/753) (open); its [status comment](https://github.com/redact-secret/redact-secret-benchmarks/issues/753#issuecomment-6015539568) records no accepted contract, no frozen case and nothing measured. It will measure masking and role attribution separately, with default and override actions taken from the accepted core policy and never inferred from "public" or "read-only". |
| Product policy (this record) | The decision record above; the Batch 2 class contract ([#1223](../1223/README.md)); the #1241 deviation ([#1241](../1241/README.md)); the #1225 whole-name admission rule ([#1225](../1225/README.md)); `decision-defer-encoded-input-decoding`; the percent decision; the user action configuration epic ([#1216](https://github.com/redact-secret/redact-secret/issues/1216) to #1222, open). |

## Class decisions

**1. Roles are metadata; detection reads carriers.** The product's finding has no
role field and the registry gains no per-role type. Role facts (admin,
search-only, write, analytics, monitoring, usage, read-only, preview, plan, CLI,
service account, app auth, transient, derived) stay in the evidence repository.
Algolia search-only and Contentful Delivery or Preview frontend, public or
read-only facts therefore **neither justify silence nor an administrative
attribution**: the same header, Bearer slot or credential-named field is read
the same way for every role that shares it. Algolia documents a search-only key
as safe in frontend code and as scrapable and floodable; Contentful's pages do
not say whether a Delivery token may be public. Silence would assert a
confidentiality fact the sources do not settle.

**2. Default action tradeoffs, frozen independently of role facts.**

| Carrier reading | Type | Default action |
| --- | --- | --- |
| Credential-named field, assignment, form, JSON member, header name read as a credential name | `contextual_secret` | `redact` at high confidence; `warn` at medium (a short or low-entropy literal) |
| Explicit `Authorization:` or `Proxy-Authorization:` Bearer value | `bearer_token` | `redact` always |
| `Authorization: Basic`, `ApiKey`, `Token` or `Key` envelope | `authorization_credential` | `redact` always, whole undecoded value |
| A JWT, in any carrier | `jwt` | `redact`, one final finding |

| Option for a public-by-design or read-only role | Why not adopted, or why adopted |
| --- | --- |
| Warn or silence by role | Needs a role in the finding, which means attributing a role from a shared carrier. A warn also leaves the value in the output. Rejected. |
| A provider type or alias per role | No grammar separates any of the 23 roles. Rejected. |
| **Role-neutral detection, type-based default, user override** | Adopted. The cost is a masked documented-public key; the user lowers the action with the action configuration (policy callback today, declarative overlay when #1216 to #1222 land). Detection stays separate from action. |

One open question is handed to the configuration design (#1217 and #1218), not
decided here: findings carry no role, so a user cannot select "search-only keys"
in a policy, only a type, a detector, a confidence or a range.

**3. Shared-carrier subtype ambiguity.** The Elastic `encoded` form, the
`X-Figma-Token` header, the HubSpot, Dropbox and Zoom Bearer slots, the Algolia
`x-algolia-api-key` header, the Instagram `client_secret` field and the Asana
Bearer slot each carry more than one role. No subtype, alias or family is
inferred from the carrier, and the product does not decide whether two role
records are one family. Elastic Serverless is not aliased to the stack personal
key; the HubSpot static-auth token is not aliased to the private-app token; the
Instagram app secret is not aliased to the Meta app secret; the Asana service
account token is not aliased to the personal access token. Each stays an
evidence role and a shared generic reading.

**4. Meta composite envelope and secret spans.** `{app-id}|{app-secret}` under
`access_token` is one carrier value, so it is one finding over the **whole
composite**, the public app-id half included, in a query, a form, a JSON member
and a Bearer header. A secret-only span is not adopted: splitting at the pipe
needs a composite grammar no source states, and the whole span cannot leave the
secret half readable. It reopens only if Meta states the pair's classification
and a baseline needs the narrower span. The finding is generic; neither
`meta:app-secret` nor `meta:app-access-token` is attributed. The generated
app access token has an unknown response member and format and is unassertable.

**5. X OAuth 1.0 halves.** The token and the token secret are two fields and two
spans, each read by its own name (`oauth_token` by the #1241 default, redacted;
`oauth_token_secret` by the field grammar). `oauth_signature` and the other
signed-request parameters stay silent; the signed `Authorization: OAuth` header
carries only the token half, so only that value is read there. The consumer
secret is a signing-key input that is not transported. No composite signing-key
claim is made and the token half is not attributed to X.

**6. Canva transient authorization-code context.** `code` is an ambiguous query
or form name: a 16-byte-or-longer, high-entropy value is `contextual_secret`,
`medium`, `warn`, text unchanged, and is never redacted by default because no
Canva page states the code's confidentiality or single use (the only single-use
rule on the pages is for refresh tokens). `code_verifier` is a high-signal name
and redacts. Whether the code alone is exchangeable is an inference (it needs the
verifier and client authentication), not a Canva statement, and it is not
claimed. No Canva type is added and no must-flag expectation exists for the code.

**7. Zoom signing secret versus signature output.** `x-zm-signature`
(`v0=` plus a keyed hash of the body) and the `encryptedToken` challenge reply
are derived outputs, not the secret token. The `x-zm-signature` header is silent
(the `*_signature` names stay unmatched, as in #1223). A derived value under a
prefixed `_token` name, `plainToken` or `encryptedToken`, is read by that name
as `contextual_secret`, `redact` at high confidence: an **intentional policy
deviation from the evidence role**, the #1241 mechanism, recorded here. The
evidence Case for the webhook rows is a must-not-flag control over derived
values; a benchmark may score those two members as `policy: redacted` or leave
them unscored, and must not count them as false positives of a secret-token
span. The secret token's own carrier is an unresolved documentation conflict
(sent versus hash) and nothing is asserted for it.

## Per-row tables

For every row the handoff is **closed and merged, records draft and unreviewed**.
The preconditions to start are **P1** a reviewed layout (the evidence contract
reviewed; today draft) and **P2** the independent baseline (benchmarks #753; none
exists). **P3** marks a row whose carrier the evidence has not yet named, so a
layout must be named before P1 can hold. No row is marked covered or ready. "No
repair predicted" is not a coverage claim: it says only that the carrier is read
today as observed and that no change is proposed. Contract links are at
credential-evidence `522e0795` (`@1` unless stated).

### D1: Algolia and Contentful (9 rows)

Handoff [D1](https://github.com/redact-secret/credential-evidence/blob/522e079512f94930b053dc2fe5561dd63818f715/docs/handoffs/d1-242-algolia-contentful-roles.md).

| Row | Mapping | Role fact the mapping does not use | Carrier named by the evidence and observed reading | Precondition and repair candidate |
| --- | --- | --- | --- | --- |
| `algolia:admin-api-key` ([contract](https://github.com/redact-secret/credential-evidence/blob/522e079512f94930b053dc2fe5561dd63818f715/records/contracts/algolia/admin-api-key@1.json)) | Shared generic detection; role is metadata only | Access to everything in the account; never for any app or production | `x-algolia-api-key` beside `x-algolia-application-id`, shared by every role; header read, application id beside it silent | P1, P2. No repair predicted. |
| `algolia:search-only-api-key` ([contract](https://github.com/redact-secret/credential-evidence/blob/522e079512f94930b053dc2fe5561dd63818f715/records/contracts/algolia/search-only-api-key@1.json)) | Shared generic detection; no silence | Documented safe in frontend code and also scrapable and floodable; index names public | same header; read like the admin key (same type, action, confidence, span) | P1, P2. No repair predicted; a user who embeds it lowers the action. |
| `algolia:secured-api-key` ([contract](https://github.com/redact-secret/credential-evidence/blob/522e079512f94930b053dc2fe5561dd63818f715/records/contracts/algolia/secured-api-key@1.json)) | Shared generic detection; derived value, not decoded | Derived from a parent key by HMAC-SHA256 over URL-encoded parameters, base64; the parent is the secret input | same header; a base64 value in a credential-named variable is read whole | P1, P2. No repair predicted; layout is partly unresolved (encoding, whether the parent is recoverable). |
| `algolia:write-api-key` ([contract](https://github.com/redact-secret/credential-evidence/blob/522e079512f94930b053dc2fe5561dd63818f715/records/contracts/algolia/write-api-key@1.json)) | Shared generic detection; ACL role is metadata | Write capability stated only through the ACL list | same header | P1, P2. No repair predicted. |
| `algolia:analytics-api-key` ([contract](https://github.com/redact-secret/credential-evidence/blob/522e079512f94930b053dc2fe5561dd63818f715/records/contracts/algolia/analytics-api-key@1.json)) | Shared generic detection; whether it is a distinct key kind or an ACL profile is unresolved, so no alias | Any key with the `analytics` ACL is accepted; data sensitivity unresolved | same header, regional analytics hosts | P1, P2. No repair predicted. |
| `algolia:monitoring-api-key` ([contract](https://github.com/redact-secret/credential-evidence/blob/522e079512f94930b053dc2fe5561dd63818f715/records/contracts/algolia/monitoring-api-key@1.json)) | Shared generic detection; role is metadata only | Infrastructure endpoints only; confidentiality unresolved | same header | P1, P2. No repair predicted. |
| `algolia:usage-api-key` ([contract](https://github.com/redact-secret/credential-evidence/blob/522e079512f94930b053dc2fe5561dd63818f715/records/contracts/algolia/usage-api-key@1.json)) | Shared generic detection; the deprecation of the Monitoring usage endpoints is undated, so no era | `usage` ACL, Premium or Enterprise add-on | same header | P1, P2. No repair predicted. |
| `contentful:delivery-api-access-token` ([contract](https://github.com/redact-secret/credential-evidence/blob/522e079512f94930b053dc2fe5561dd63818f715/records/contracts/contentful/delivery-api-access-token@1.json)) | Shared generic detection; public or confidential status unresolved, so no silence | Read-only, environment-scoped, created in a pair with a Preview key | `Authorization: Bearer`, the `access_token` query parameter, and the `accessToken` property of the key resource; all three read | P1, P2. No repair predicted. |
| `contentful:preview-api-access-token` ([contract](https://github.com/redact-secret/credential-evidence/blob/522e079512f94930b053dc2fe5561dd63818f715/records/contracts/contentful/preview-api-access-token@1.json)) | Shared generic detection; distinct from Delivery by host and context only | Exists to avoid leaking unpublished content; never in the preview URL | same carriers; read exactly like the Delivery token | P1, P2. No repair predicted; Delivery and Preview are not separable by value. |

### D2: shared-carrier roles (9 rows)

Handoff [D2](https://github.com/redact-secret/credential-evidence/blob/522e079512f94930b053dc2fe5561dd63818f715/docs/handoffs/d2-243-shared-carrier-roles.md).

| Row | Mapping | Role fact the mapping does not use | Carrier named by the evidence and observed reading | Precondition and repair candidate |
| --- | --- | --- | --- | --- |
| `asana:service-account-token` ([contract](https://github.com/redact-secret/credential-evidence/blob/522e079512f94930b053dc2fe5561dd63818f715/records/contracts/asana/service-account-token@1.json)) | Shared generic detection; no alias to the PAT (Asana's audit page calls it a personal access token of a service account) | Org-wide, scope-limited, long-lived; required for audit log, exports and SCIM | An Authorization header is documented for PATs and OAuth tokens only; no service-account example exists, so the carrier is unconfirmed. A Bearer value and a `*_TOKEN` name are read generically. | P1, P2, P3 (carrier). No repair predicted. |
| `dropbox:app-auth-token` ([contract](https://github.com/redact-secret/credential-evidence/blob/522e079512f94930b053dc2fe5561dd63818f715/records/contracts/dropbox/app-auth-token@1.json)) | Shared generic detection; the substitute-for-the-secret reading is an inference and not claimed | Output of `client_credentials` from the app key and secret; usable only on App Authentication endpoints | `Authorization: Bearer`; read as `bearer_token`. The Basic envelope over app key and secret is read whole. | P1, P2. No repair predicted; response format and lifetime unresolved. |
| `elastic:cross-cluster-api-key` ([contract](https://github.com/redact-secret/credential-evidence/blob/522e079512f94930b053dc2fe5561dd63818f715/records/contracts/elastic/cross-cluster-api-key@1.json)) | Shared generic detection where the carrier is shared; unresolved for its own carrier | `cross_cluster` key, refused on the REST interface, carried in the local cluster keystore | The keystore is not a wire carrier: a keystore command and value are silent. The create response shares the stack key's members: `api_key` is read, `encoded` (Base64 of `id:api_key`, which contains the secret) is not a read name. | P1, P2, P3 (carrier). The `encoded` member is a disclosed blind spot; the name is too generic for a vocabulary entry without a decision of its own. |
| `elastic:serverless-project-api-key` ([contract](https://github.com/redact-secret/credential-evidence/blob/522e079512f94930b053dc2fe5561dd63818f715/records/contracts/elastic/serverless-project-api-key@1.json)) | Shared generic detection; issuance-context role kept, **no alias** to the stack key (Elastic calls it the equivalent) | Personal key of a Serverless project | `Authorization: ApiKey` over the undecoded value, `authorization_credential`, redacted, no Elastic attribution (the #1212 reading) | P1, P2. No repair predicted. |
| `figma:plan-access-token` ([contract](https://github.com/redact-secret/credential-evidence/blob/522e079512f94930b053dc2fe5561dd63818f715/records/contracts/figma/plan-access-token@1.json)) | Shared generic detection; no PAT subtype; era-specific (generally available 2026-07-23) | Plan-scoped, administrator-created, up to 365 days, 24-hour overlap on refresh | `X-Figma-Token`, shared with PATs; read as `contextual_secret` (the #1209 reading). A bare `figd_`-prefixed value is silent. | P1, P2. No repair predicted. |
| `figma:cli-plan-access-token` ([contract](https://github.com/redact-secret/credential-evidence/blob/522e079512f94930b053dc2fe5561dd63818f715/records/contracts/figma/cli-plan-access-token@1.json)) | Metadata-only role (a fixed scope set); carrier unresolved | Plan-wide, no scope selection, same lifecycle as the plan token | The CLI and npm-registry carriers are unstated; `X-Figma-Token` is documented for the personal token only. | P1, P2, P3 (carrier). No repair predicted. |
| `hubspot:static-auth-access-token` ([contract](https://github.com/redact-secret/credential-evidence/blob/522e079512f94930b053dc2fe5561dd63818f715/records/contracts/hubspot/static-auth-access-token@1.json)) | Shared generic detection; **not** aliased to `hubspot:private-app-access-token` (no HubSpot page relates them) | Single-account token for an app with `auth.type: static` | `Authorization: Bearer`, shared with OAuth and private-app tokens; read as `bearer_token` | P1, P2. No repair predicted. |
| `jfrog:pairing-token` ([contract](https://github.com/redact-secret/credential-evidence/blob/522e079512f94930b053dc2fe5561dd63818f715/records/contracts/jfrog/pairing-token@1.json)) | Unresolved (string form inferred, not stated); a JWT-shaped value is one `jwt` finding, not a JFrog type | Signed, short-lived (300 s default), at-most-once; the result is a master token | Carrier unresolved. A JWT-shaped value, in a field or bare, is read as `jwt`, `redact`; a non-JWT form is unassertable. Short lifetime does not justify silence. | P1, P2, P3. No repair predicted. |
| `meta:instagram-app-secret` ([contract](https://github.com/redact-secret/credential-evidence/blob/522e079512f94930b053dc2fe5561dd63818f715/records/contracts/meta/instagram-app-secret@1.json)) | Shared generic detection; whether the value equals the Meta app secret is unstated, so **no alias** | Instagram App Secret beside a separate Instagram App ID; server-side only | `client_secret` in a POST form and a GET query; read as `contextual_secret` | P1, P2. No repair predicted. |

### D3: transient, composite, OAuth 1.0 and Zoom (5 rows)

Handoff [D3](https://github.com/redact-secret/credential-evidence/blob/522e079512f94930b053dc2fe5561dd63818f715/docs/handoffs/d3-244-transient-composite-roles.md).

| Row | Mapping | Role fact the mapping does not use | Carrier named by the evidence and observed reading | Precondition and repair candidate |
| --- | --- | --- | --- | --- |
| `canva:authorization-code` ([contract](https://github.com/redact-secret/credential-evidence/blob/522e079512f94930b053dc2fe5561dd63818f715/records/contracts/canva/authorization-code@1.json)) | Shared generic detection at the ambiguity tier (decision 6); confidentiality metadata-only | Transient; useless without the code verifier and client authentication (an inference); lifetime and single use unstated | The `code` redirect query parameter and the `code` form field: `medium`, `warn`, text unchanged. `code_verifier` redacts. | P1, P2. No repair predicted; no must-flag expectation exists for the code. |
| `meta:app-access-token` ([contract](https://github.com/redact-secret/credential-evidence/blob/522e079512f94930b053dc2fe5561dd63818f715/records/contracts/meta/app-access-token@1.json)) | Bounded composite claim for the pair (decision 4); the generated token is unresolved | The pair is a carrier form of the app secret (an inference); the client-token pair is documented not secret | `access_token` as `{app-id}\|{app-secret}`: one span over the whole composite in query, form, JSON and Bearer. A generated token under `access_token` is read as a field value. | P1, P2. No repair predicted; the generated token's response member and format are unassertable. |
| `x:oauth1-access-token` ([contract](https://github.com/redact-secret/credential-evidence/blob/522e079512f94930b053dc2fe5561dd63818f715/records/contracts/x/oauth1-access-token@1.json)) | Shared generic detection, the #1241 default; halves are separate spans (decision 5) | Request and access tokens share `oauth_token` (X's own table); sensitivity of the token half unresolved | `oauth_token` and `oauth_token_secret` as two spans in a request-token response; only `oauth_token` in a signed `Authorization: OAuth` header | P1, P2. No repair predicted; the token half's redaction is a recorded policy deviation. |
| `zoom:build-platform-api-key` ([contract](https://github.com/redact-secret/credential-evidence/blob/522e079512f94930b053dc2fe5561dd63818f715/records/contracts/zoom/build-platform-api-key@1.json)) | Shared generic detection; the Bearer slot is shared with a JWT, so no attribution | `x-api-key` is API-key-only; Bearer carries a key or a JWT; the key ID is a different value | `x-api-key` header read as `contextual_secret`; Bearer read as `bearer_token`; a JWT in either is `jwt` | P1, P2. No repair predicted; key-and-secret pair versus one string is unresolved. |
| `zoom:webhook-secret-token` ([contract](https://github.com/redact-secret/credential-evidence/blob/522e079512f94930b053dc2fe5561dd63818f715/records/contracts/zoom/webhook-secret-token@1.json)) | Metadata-only role for the derived outputs (decision 7); the secret token's carrier is unresolved | The secret token is the HMAC key; `x-zm-signature`, `plainToken` and `encryptedToken` are derived | `x-zm-signature` silent; `plainToken` and `encryptedToken` read by name, redacted (a recorded deviation) | P1, P2, P3 (the documentation says both "sends the secret token" and "sends a hash"). No repair predicted. |

## Product observations

Product observations at core `01740490` (CLI `0.1.0-beta.13` line, debug build of
this commit, check mode, UTF-8 byte ranges, `--json`), on small synthetic inputs
written for this record. Not benchmark results, not coverage claims, not a
baseline and not an expectation; the inputs were not authored against any
reviewed layout, and the variable names are the product's reading of a name, not
names the evidence reviewed. Values are invented runs of 22 to 88 bytes and are
not shown.

| Input (synthetic) | Observed finding |
| --- | --- |
| `x-algolia-api-key` header with 32 hex, and `ALGOLIA_ADMIN_API_KEY=`, `ALGOLIA_SEARCH_ONLY_API_KEY=`, a JSON `apiKey` member, a base64 secured key in a credential variable | `contextual_secret`, high, redact, over the value only, the same for every role |
| `x-algolia-application-id` and `ALGOLIA_APPLICATION_ID=` (10 characters) | silent |
| `ALGOLIA_SEARCH_KEY=`; `algoliasearch(<app>, <key>)` positional arguments; 32 hex bare | silent (a `*_key` suffix name is not broadened; an SDK positional argument is an explicit limit) |
| Contentful `Authorization: Bearer`; `access_token=` query; `CONTENTFUL_DELIVERY_TOKEN=`; `CONTENTFUL_PREVIEW_ACCESS_TOKEN=`; `accessToken: '<43>'` | `bearer_token` or `contextual_secret`, high, redact, over the value only, identical for Delivery and Preview |
| a space and an environment id (`space=`, `environment=`) | silent |
| Asana `ASANA_SERVICE_ACCOUNT_TOKEN=` and a Bearer value of the `n/..:..` shape | `contextual_secret`, high, redact; `bearer_token`, high, redact |
| Dropbox `DROPBOX_APP_AUTH_TOKEN=`, a Bearer value, a Basic envelope of 24 bytes | `contextual_secret`; `bearer_token`; `authorization_credential`, all high, redact |
| `Authorization: ApiKey` over a 64-byte value | `authorization_credential`, high, redact, whole value |
| JSON `{"id", "name", "api_key", "encoded"}` | `api_key` member read (`contextual_secret`, high, redact); the `encoded` member and an `encoded`-only object silent |
| a keystore command line followed by a 64-byte value | silent |
| `X-Figma-Token`, `FIGMA_PLAN_ACCESS_TOKEN=`; `figd_` + 40 bare | `contextual_secret`, high, redact; silent |
| HubSpot-style Bearer value | `bearer_token`, high, redact |
| `pairing_token=` + a JWT-shaped value; the same bare | `jwt`, high, redact (exact JWT bytes) |
| `INSTAGRAM_APP_SECRET=` and a form `client_secret` with 32 hex | `contextual_secret`, high, redact, exact value; the `code` in the same form is a separate medium `warn` |
| `?code=` and form `code=` with 64 bytes | `contextual_secret`, medium, warn, text unchanged |
| `code_verifier=` with 64 bytes; `authorization_code=` with 64 bytes | `contextual_secret`, high, redact; silent |
| `access_token=` + app id + `\|` + 32 bytes in a query, form, JSON and Bearer | one finding over the whole composite (`contextual_secret` high redact, `bearer_token` high redact) |
| the composite under an `FB_APP_CREDENTIAL=` name | `contextual_secret`, medium, warn (`credential` is an ambiguous name) |
| `oauth_token=` + `oauth_token_secret=`; a signed `Authorization: OAuth` header | two `contextual_secret` spans, high, redact; only the `oauth_token` value in the header |
| `x-api-key` header with 40 bytes; a 40-byte Bearer value | `contextual_secret`, high, redact; `bearer_token`, high, redact |
| `ZOOM_WEBHOOK_SECRET_TOKEN=` + 22 bytes | `contextual_secret`, high, redact |
| `x-zm-signature: v0=` + 64 hex; `appsecret_proof=` + 64 hex | silent |
| JSON `plainToken` (22 bytes) and `encryptedToken` (64 hex) | two `contextual_secret`, high, redact, over each value |

## Gates of the issue

| Gate | State |
| --- | --- |
| For every candidate, review the handoff and freeze supported, unsupported and unknown shape, role, temporal boundary and disposition, preserving source-tier attribution | Met by this record: the class decisions and the three per-row tables freeze them conditionally; no grammar is claimed from project policy; unresolved rows stay unresolved. |
| Final judgement under `docs/audits/evidence/<issue>/` plus spec rows; action, overlap, attribution and FP/FN explicit | Met: this record, the decision record, the Group D rows of the [detector-families spec](../../../specs/detector-families.md#groups-c-d-and-e-conditional-contracts-1228-to-1230) and a row in the [contextual-detection spec](../../../specs/contextual-detection.md). Overlap as in #1223: a provider detector on the same bytes keeps precedence. |
| Independently authored benchmark cases from the accepted contract, frozen before execution | Open: benchmarks #753; this contract is the input. |
| Measure published and candidate coverage before implementation; route no-code results | Open: no baseline exists; the observations above are not it. |
| Meaningful conformance (exact span, complete redaction, type and action, overlap, controls) | Open for the rows. Five boundaries are pinned by `group_d_role_facts_1229.rs` (whole input, every two-chunk byte partition, per-line session). |
| Preserve canonical Rust, runtime neutrality, whole and stream behaviour; verify Node, WASM, Python, Rust, CLI for behaviour changes | Met: no behaviour changed; a Rust test and documents only. |
| Candidate source revision and digests to benchmark replay; unchanged controls show no regression | Open: there is no candidate change. |
| Every row visible as measured-ready, no-code, policy-limited, historical-only or unresolved; unresolved is not support | Met for visibility. All 23 rows are listed. None is marked measured-ready or no-code. The rows whose carrier the evidence has not named (P3) and the rows with an unresolved attribution are unresolved. |
| No release, tag, automatic promotion or owner acceptance | Met: none. |

## Tradeoffs

* **A documented-public credential is redacted.** An Algolia search-only key or a
  Contentful Delivery token embedded in frontend code by design is masked at high
  confidence. Silence would trust a confidentiality fact the sources leave open
  (Algolia calls the key floodable; Contentful is silent), and the finding has no
  role to key a downgrade on. The user lowers the action.
* **A derived or transient value under a credential name is read.** `plainToken`
  and `encryptedToken` are masked though neither is the secret token; a `code` is
  warned and not redacted. Both follow existing name rules and are recorded
  deviations from the evidence role.
* **A composite hides its public half.** The Meta app id goes with the secret,
  by the same construction as a Basic envelope.
* **Blind spots stay stated.** The Elastic `encoded` member, an SDK positional
  argument, a keystore, a `*_key` suffix name and a bare provider-shaped value
  are not read.

## Tests

`crates/secret-scan-core/tests/group_d_role_facts_1229.rs` (5 tests): six
role-named Algolia variables, the shared `x-algolia-api-key` header and a secured
key are read identically, and the Delivery and Preview tokens are read alike in
the named Contentful carriers; a Meta composite is one span in a query, form, JSON member and Bearer
header; a `code` is a medium warn with the text unchanged and a `code_verifier`
redacts; a signature header and a keyed proof are silent while `plainToken` and
`encryptedToken` are read by name. Every case asserts whole input equals every
two-chunk UTF-8 byte partition equals a per-line session.

No pin, version or release change.
