# Evidence: #1230, Group E historical and current-source contract (9 rows)

**Result:** the class-level, per-row conditional product contract for the 9
Group E rows. Current and historical claims are stated separately for every row.
The central decision is a new cross-family one with its own record,
[`decision-keep-credential-lifecycle-era-out-of-detection-and-preserve-backward-redaction`](../../../decisions/2026-10-06-keep-credential-lifecycle-era-out-of-detection-and-preserve-backward-redaction.md):
a retired, deprecated or superseded credential is detected like a current one in
the same carrier, provider shutdown does not make it benign, deprecation is not
shutdown, version-scoped variants are never merged, and backward redaction is
preserved. No dedicated historical detector is adopted or mandatory: the generic
PEM private-key, Bearer, Basic, JWT and credential-field readings are the
contract for a retired form that rides one of those carriers, and the one
carrier that is not read today for a documented field (HubSpot `hapikey`) has a
pre-decided repair route if a baseline shows the gap. Zendesk gets an explicit
exact-span policy. No row is claimed covered, passing or ready, no expectation is
taken from current output, and no carrier, field name, prefix, width or alphabet
is invented. No detector, registry entry, vocabulary name or type changes; five
boundaries are pinned by
`crates/secret-scan-core/tests/group_e_era_and_envelopes_1230.rs`. The
independent baseline (benchmarks
[#754](https://github.com/redact-secret/redact-secret-benchmarks/issues/754)) does
not exist yet.

Issue [#1230](https://github.com/redact-secret/redact-secret/issues/1230);
evidence epic [credential-evidence#238](https://github.com/redact-secret/credential-evidence/issues/238)
(children [#245](https://github.com/redact-secret/credential-evidence/issues/245),
[#246](https://github.com/redact-secret/credential-evidence/issues/246),
[#247](https://github.com/redact-secret/credential-evidence/issues/247), all
closed). Shared rules (evidence classes, one origin per copied rule, the five
kinds, preconditions) are in
[#1228](../1228/README.md#disposition-kinds-and-the-rules-that-bind-every-row);
siblings [#1229](../1229/README.md) and Batch 2 [#1223](../1223/README.md).

## Sources

| Role | Source |
| --- | --- |
| Era, carrier and role facts (pending inputs, never decided here) | The handoffs [E1](https://github.com/redact-secret/credential-evidence/blob/522e079512f94930b053dc2fe5561dd63818f715/docs/handoffs/e1-245-retired-eras.md), [E2](https://github.com/redact-secret/credential-evidence/blob/522e079512f94930b053dc2fe5561dd63818f715/docs/handoffs/e2-246-jfrog-zendesk-deprecation.md) and [E3](https://github.com/redact-secret/credential-evidence/blob/522e079512f94930b053dc2fe5561dd63818f715/docs/handoffs/e3-247-reddit-current-carriers.md), merged as credential-evidence PR #253 (read at head `522e0795`). Project-authored, not independent validation; every contract is `draft`, `period: proposed`, never reviewed; every date is bound to a pinned capture or a page read on the date the handoff states. The four Zendesk and JFrog Cases of E2 are `maintainer-only`, basis `project-policy`, and never `reviewed`. |
| Independent baseline and replay | benchmarks [#754](https://github.com/redact-secret/redact-secret-benchmarks/issues/754) (open); its [status comment](https://github.com/redact-secret/redact-secret-benchmarks/issues/754#issuecomment-6015539840) records no accepted contract, no frozen case and nothing measured. |
| Product policy (this record) | The decision record above; the Batch 2 class contract ([#1223](../1223/README.md)) and its Basic rule; `decision-defer-encoded-input-decoding` (#491); the percent decision; the #1225 whole-name admission rule ([#1225](../1225/README.md), [#1233](../1233/README.md)); the disclosed curl `--user` blind spot of [#1226](../1226/README.md); the user action configuration epic ([#1216](https://github.com/redact-secret/redact-secret/issues/1216) to #1222, open). |

## Class decisions

**1. Separate current and historical claims.** Each row below carries what the
provider supports now (a claim read on a live page) apart from what a form was
during a dated period (a claim bound to a pinned capture). Dates are provider
announcements that the provider revised (Adobe changed its end-of-life date
twice), not retrospective validity intervals; the contracts keep `validity` null.

**2. A historical credential is not benign.** The evidence says a credential of
these eras found in logs or configuration remains a redaction concern whatever
the date. The product agrees and has no temporal exclusion: an era word near a
value (`legacy`, `deprecated`, `retired`, `sunset`) changes nothing, pinned by
the tests. There is no shutdown-date table because no finding carries an era.

**3. No dedicated historical detector is mandatory, and backward redaction is
preserved.** The generic readings suffice where a documented carrier is one they
read. The existing legacy detectors and contracts (`heroku_api_key_legacy`,
`datadog_application_key_legacy`, `confluent_cloud_api_secret_legacy`, the legacy
Pinecone UUID rule, the `ApiKey`, Basic and Bearer readings) are untouched, and
nothing in this record narrows one.

**4. JFrog deprecation is not authentication shutdown.** JFrog's pages state the
API key's deprecation, an End of Life notice (end of Q4 2024, on the page by the
2025-05-20 capture), a block on creating new keys (from 7.98), and a block on
using existing keys that is an administrator opt-in, off by default (cloud 7.107.1;
a self-hosted flag from 7.84.x). No page says authentication ends. The product
treats the key as possibly live. The two variants stay separate: the `AKCp` +
69-alphanumeric form (73 characters; introduced in Artifactory 4.4.3, deprecated
from 7.47.x) has a provider-stated pattern, a provider-maintained client that
agrees (`AKCp8` and at least 73, one origin with the documentation) and two
consistent rule artifacts; the 44-character unprefixed sample on the reference
page (unchanged since 2025-09-06) has none. Which belongs to which release is
unresolved, no union is formed, and the unprefixed variant carries no bare claim.

**5. HubSpot developer `hapikey` is not retired account keys.** HubSpot's own 2022
page says the developer and account keys differ only by the account type they
reach and travel in the same `hapikey` parameter; the developer key is still in
use and the account key was announced for sunset on 2022-11-30 (no new keys from
2022-07-15), with the consequence worded two ways. The product classes a value in
`hapikey` by neither era nor account type. The rows `hubspot:legacy-api-key`,
`hubspot:private-app-access-token`, `hubspot:static-auth-access-token` and
`hubspot:personal-access-key` stay four roles, none merged.

**6. Zendesk exact-span policy.** The credential string is `{email}/token` as the
user and the token as the password, in a Basic header (composition documented
unchanged since 2022-12-03).

| Layout | Span, type, action | State |
| --- | --- | --- |
| Basic envelope (raw HTTP, quoted curl `-H`, JSON header map) | The **whole encoded envelope**, `authorization_credential`, `redact` always; the email and the token are both inside; never decoded and never split | Contract: the Batch 2 Basic rule applied |
| A credential-named field (`ZENDESK_API_TOKEN` and the like) | Exactly the value, `contextual_secret`, `redact` at high confidence, `warn` at medium | Contract: the existing field grammar, once a reviewed layout names the field |
| A raw delimited credential string (`{email}/token:{token}` as a `curl -u` argument) | Not read today. If a reviewed layout ever adds a reader, the span is the **password component only** (the token); the email and the `/token` literal stay outside, as the password component of a URI userinfo is | Conditional; a shared carrier, see the next section |
| A component-level claim inside an encoded envelope (flag only the token within the base64) | Not claimed: decoding is deferred (#491) | Out of contract |
| JSON `{"email": ..., "token": ...}` | The bare `token` name stays unmatched (#702); nothing is asserted | Stated blind spot |

No source calls the email non-secret, so it is not a benign sibling; the whole
envelope hides it with the token by construction.

**7. Reddit stays historical and unresolved for current claims.** E3 changed one
thing: Reddit's current Help page (updated 2026-05-11) requires OAuth and links
the archived `reddit-archive/reddit` wiki as its technical guidance, so the
archived carriers are Reddit-pointed and no longer merely historical. It did not
verify any archived statement as current: app types, the one-hour lifetime,
permanent refresh tokens, registration, installed-app secrets and all formats stay
unresolved, and two archived statements conflict (installed-app secret presence;
the unit of `expires_in`). The product reads the three documented carriers
generically and adopts no Reddit type, no lifetime and no format.

## Per-row tables

For every row the handoff is **closed and merged, records draft and unreviewed**.
Preconditions to start: **P1** a reviewed layout (the contract reviewed; today
draft) and **P2** the independent baseline (benchmarks #754; none exists).
**P3** marks a row whose carrier the evidence names only in passing or whose
format is the open question, so a layout must be named before P1 can hold. No row
is marked covered or ready. Contract links are at credential-evidence `522e0795`.

### Current and historical claims

| Row | Current claim (read on a live page) | Historical claim (pinned capture) | Still unresolved |
| --- | --- | --- | --- |
| `adobe:service-account-jwt-private-key` ([`@1`](https://github.com/redact-secret/credential-evidence/blob/522e079512f94930b053dc2fe5561dd63818f715/records/contracts/adobe/service-account-jwt-private-key@1.json)) | The credential is retired: end of life 2025-06-30, conversion at certificate expiry or 2026-03-01 at the latest | Generated locally with an OpenSSL command (2048-bit RSA, `private.key`), never uploaded; signs the RS256 `jwt_token` assertion; announced 2023-05-01, no new credentials after 2024-06-03; three captures state three end-of-life dates | Encoding, label and length of the key file; any Adobe marker; the introduction date; whether any key still works |
| `airtable:legacy-api-key` ([`@1`](https://github.com/redact-secret/credential-evidence/blob/522e079512f94930b053dc2fe5561dd63818f715/records/contracts/airtable/legacy-api-key@1.json)) | The current reference names a legacy `api_key` URL parameter, only in a sentence saying it is unsupported | Deprecation period from 2023-01-18; no new keys after 2023-08-01; existing keys cannot call the API after 2024-02-01 (provider statement); all-or-nothing account-wide access | Prefix, alphabet, length; how a key was presented; whether one authenticated after 2024-02-01 |
| `dropbox:legacy-long-lived-access-token` ([`@1`](https://github.com/redact-secret/credential-evidence/blob/522e079512f94930b053dc2fe5561dd63818f715/records/contracts/dropbox/legacy-long-lived-access-token@1.json)) | The current response example for the legacy form has no `expires_in` and no `refresh_token` member | Creation retirement announced for 2021-09-30; an undated note says no new long-lived tokens are offered; the guide says "until mid 2021" | Which date applies; whether existing tokens still authenticate; any format; separation from short-lived tokens by shape |
| `hubspot:legacy-api-key` ([`@1`](https://github.com/redact-secret/credential-evidence/blob/522e079512f94930b053dc2fe5561dd63818f715/records/contracts/hubspot/legacy-api-key@1.json)) | The developer API key uses the `hapikey` parameter and is in use | Account key: announced 2022-06-01, no new keys from 2022-07-15, sunset 2022-11-30 (consequence worded two ways) | Format; which credential the UUID-shaped lead describes; whether a key authenticated after 2022-11-30 |
| `jfrog:api-key` ([`@1`](https://github.com/redact-secret/credential-evidence/blob/522e079512f94930b053dc2fe5561dd63818f715/records/contracts/jfrog/api-key@1.json)) | Deprecated from 7.47.x; End of Life notice end of Q4 2024; creation blocked from 7.98; usage block opt-in, default off; `X-JFrog-Art-API` header or basic-authentication password; the reference sample is 44 characters with no prefix | `AKCp` + 69 alphanumerics introduced in 4.4.3; the notice and the sample as captured on 2025-05-20 and 2025-09-06 | Which form applies to which release; final authentication shutdown; release dates |
| `zendesk:api-token` ([`@1`](https://github.com/redact-secret/credential-evidence/blob/522e079512f94930b053dc2fe5561dd63818f715/records/contracts/zendesk/api-token@1.json)) | Labelled deprecated; 2026-07-28 inactivity deactivation and new accounts blocked, 2026-10-27 no new tokens for existing accounts, 2027-04-30 final deactivation; existing tokens work until then; Basic composition | Same composition on 2022-12-03; the schedule a week earlier (2026-09-24); recommended and not labelled deprecated on 2026-04-21 | Token prefix, alphabet, length; whether phase 1 was applied; the announcement date |
| `reddit:app-client-secret` ([`@1`](https://github.com/redact-secret/credential-evidence/blob/522e079512f94930b053dc2fe5561dd63818f715/records/contracts/reddit/app-client-secret@1.json)) | OAuth with a registered client is required; rate limits per client id; the terms forbid sharing tokens, keys, passwords and login credentials; the Help page points to the archived wiki | Archived (Reddit-pointed): the Basic password beside the client id for the code, refresh, client-credentials and revoke requests; never shared; web and script apps hold one | Format; whether registration still shows a secret; installed-app secret (two archived pages conflict); rotation |
| `reddit:oauth-access-token` ([`@1`](https://github.com/redact-secret/credential-evidence/blob/522e079512f94930b053dc2fe5561dd63818f715/records/contracts/reddit/oauth-access-token@1.json)) | The live API reference labels endpoints with OAuth scopes; Reddit can revoke tokens | Archived (Reddit-pointed): JSON `access_token` member, URL fragment (implicit flow), `Authorization: bearer` to the OAuth host; revocable at `revoke_token` | The one-hour lifetime as a current fact; `expires_in` unit (conflict); format |
| `reddit:oauth-refresh-token` ([`@1`](https://github.com/redact-secret/credential-evidence/blob/522e079512f94930b053dc2fe5561dd63818f715/records/contracts/reddit/oauth-refresh-token@1.json)) | Reddit can revoke tokens | Archived (Reddit-pointed): issued only for `duration=permanent` in the code flow; POST body field with the same Basic client authentication; revocation cascades | Whether permanent tokens are still issued; lifetime and rotation; format |

### Disposition and next step

| Row | Disposition | Observed reading of the documented carrier | Handoff; repair candidate only if a baseline shows a gap |
| --- | --- | --- | --- |
| `adobe:service-account-jwt-private-key` | Historical-only role; shared generic detection (the PEM private-key path); encoding unresolved | A PEM block of either label is one `private_key` finding, `block`, whole block, no Adobe type; the same block JSON-escaped on one line is read; the public certificate block is silent; the `jwt_token` assertion is a separate `jwt`; the `client_secret` beside it is a separate field | [E1](https://github.com/redact-secret/credential-evidence/blob/522e079512f94930b053dc2fe5561dd63818f715/docs/handoffs/e1-245-retired-eras.md); P1, P2, P3 (encoding). None predicted: no Adobe marker exists to attribute. |
| `airtable:legacy-api-key` | Historical-only; bounded-context fallback; format unresolved | `api_key` as a URL parameter or variable and a Bearer value are read generically | E1; P1, P2, P3 (presentation form). None predicted. |
| `dropbox:legacy-long-lived-access-token` | Historical-only (conflicting retirement dates); bounded-context fallback; tie to [#1228](../1228/README.md) | The `access_token` JSON member and a Bearer value are read; a bare value is silent; not separable from short-lived tokens by shape | E1; P1, P2, P3 (format). None predicted. |
| `hubspot:legacy-api-key` | Historical-only account key plus a current developer key in one carrier; bounded-context fallback **not available today**; format unresolved | A `hapikey` query parameter and a `HAPIKEY=` variable are **silent**; `HUBSPOT_API_KEY=` is read; a masked or `{YOUR_DEVELOPER_API_KEY}` placeholder is silent | E1; P1, P2. **Strongest candidate:** one whole-name vocabulary entry `hapikey` under the #1225 and #1233 rule (the evidence names the exact field as provider-documented), reading both key kinds with no HubSpot attribution and no era, with the placeholder and mask exclusions; no UUID bare grammar. FP cost: a non-secret literal of 8 bytes or more under the exact name; FN cost: a bare UUID, another name. |
| `jfrog:api-key` | Era-specific, unresolved; no shutdown claim; AKCp variant separate from the unprefixed sample | The documented `X-JFrog-Art-API` header (raw and quoted curl `-H`), a `curl -u` basic password and a bare `AKCp8` value are **silent**; `password=` is read | [E2](https://github.com/redact-secret/credential-evidence/blob/522e079512f94930b053dc2fe5561dd63818f715/docs/handoffs/e2-246-jfrog-zendesk-deprecation.md); P1, P2, P3. Candidates in order: (a) a whole-name entry for the documented header, shared with the JFrog reference token and attributing neither; (b) only after (a), and only with its own adoption decision, an era-specific bare claim for the provider-stated `AKCp` + 69 pattern alone. The 44-character variant gets no bare claim. Neither is mandatory. |
| `zendesk:api-token` | Era-specific lifecycle; bounded-context fallback; grammar unresolved; exact-span policy above | The Basic envelope is one `authorization_credential` span; a named field is read; a `curl -u 'email/token:...'` string and a JSON `token` member are **silent** | E2; P1, P2, P3 (grammar). A shared `curl -u` reader would be a cross-provider decision, not a Zendesk repair (see below). |
| `reddit:app-client-secret` | Historical-only for current claims, Reddit-pointed carriers; bounded-context fallback; format unresolved | The Basic envelope is one `authorization_credential` span (an installed app's empty-password envelope is redacted too: nothing is decoded); `client_secret` and `REDDIT_CLIENT_SECRET` are read | [E3](https://github.com/redact-secret/credential-evidence/blob/522e079512f94930b053dc2fe5561dd63818f715/docs/handoffs/e3-247-reddit-current-carriers.md); P1, P2, P3 (current registration and app types). None predicted. |
| `reddit:oauth-access-token` | Same; bounded-context fallback | The JSON `access_token`, the URL fragment and a lower-case `bearer` header are read | E3; P1, P2, P3. None predicted. |
| `reddit:oauth-refresh-token` | Same; a token-endpoint field, never a resource Bearer credential | The `refresh_token` body field is read | E3; P1, P2, P3. None predicted. |

**A shared `curl -u` carrier (maintainer decision, not made here).** A credential
passed as `curl -u user:secret` (or `--user`) is silent today, for the Zendesk
and JFrog rows above and for the Atlas Digest layout that
[#1226](../1226/README.md) already discloses. Reading it would be one
cross-provider carrier decision with its own false-positive corpus (every
`user:password` pair on a command line), not a per-row repair, and it is not part
of this record. Until it is made, a Zendesk or JFrog credential in that layout is
a stated false negative and the Zendesk raw-component span above stays
conditional.

## Product observations

Product observations at core `01740490` (CLI `0.1.0-beta.13` line, debug build of
this commit, check mode, UTF-8 byte ranges, `--json`), on small synthetic inputs
written for this record. Not benchmark results, not coverage claims, not a
baseline and not an expectation; the inputs were not authored against any
reviewed layout. Values are invented runs of 17 bytes to 1.7 KB and are not shown.

| Input (synthetic) | Observed finding |
| --- | --- |
| A 26-line `-----BEGIN PRIVATE KEY-----` block and the same with `RSA PRIVATE KEY` | `private_key`, high, `block`, over the whole block (0-1743, 0-1751) |
| The key as a JSON string with `\n` escapes | `private_key`, high, `block`, over the block inside the string (16-202) |
| A `-----BEGIN CERTIFICATE-----` block | silent |
| A `jwt_token=` form field with a JWT-shaped value beside `client_secret=` | `jwt`, high, redact, exact value; `contextual_secret` for the client secret |
| `api_key=` as a URL parameter, `AIRTABLE_API_KEY=`, a Bearer value (17 bytes each) | `contextual_secret`, high, redact; `contextual_secret`, high, redact; `bearer_token`, high, redact |
| JSON `access_token` (64 bytes, no `expires_in`), Bearer 64 bytes; the 64-byte value bare | `contextual_secret`, high, redact; `bearer_token`, high, redact; silent |
| `?hapikey=` + UUID, a request line with `hapikey=` + UUID, `HAPIKEY=` + UUID | silent (3 inputs) |
| `HUBSPOT_API_KEY=` + UUID | `contextual_secret`, high, redact |
| `hapikey={YOUR_DEVELOPER_API_KEY}`; `hapikey=` + 36 `*` | silent |
| `X-JFrog-Art-API` header with `AKCp8` + 68 (raw and in a quoted curl `-H`), with a 44-byte unprefixed value; `curl -u admin:` + `AKCp8` + 68; `AKCp8` + 68 bare | silent (5 inputs) |
| `password=` + `AKCp8` + 68 | `contextual_secret`, high, redact |
| A Basic header over `agent@example.test/token:` + 40 bytes (88 encoded bytes) | `authorization_credential`, high, redact, over the 88-byte envelope (56-144) |
| A Basic header over the email and `/token:` with an empty token | `authorization_credential`, high, redact, whole envelope |
| `curl ... -u 'agent@example.test/token:` + 40 + `'`; JSON `{"email", "token"}` | silent (2 inputs) |
| `ZENDESK_API_TOKEN=` + 40 bytes; `-u 'agent@example.test/token:YOUR_API_TOKEN'` | `contextual_secret`, high, redact; silent |
| A Basic header over `<14 bytes>:<27 bytes>` | `authorization_credential`, high, redact, whole envelope (56-112) |
| A Basic header over `<14 bytes>:` (empty password) | `authorization_credential`, high, redact, whole envelope (21-41) |
| `client_secret=` + 27 bytes; `REDDIT_CLIENT_SECRET=` + 27 | `contextual_secret`, high, redact, exact value |
| `refresh_token=` + 40 bytes; JSON `access_token` (35 bytes); `Authorization: bearer` + 35 bytes; `#access_token=` + 41 bytes | `contextual_secret`, high, redact; `contextual_secret`, high, redact; `bearer_token`, high, redact; `contextual_secret`, high, redact |
| `device_id=DO_NOT_TRACK_THIS_DEVICE` | silent |

## Gates of the issue

| Gate | State |
| --- | --- |
| For every candidate, review the handoff and freeze supported, unsupported and unknown shape, role, temporal boundary and disposition, preserving source-tier attribution | Met by this record: the current and historical claim table, the dispositions and the class decisions freeze them conditionally; no grammar is claimed from project policy; unresolved rows stay unresolved. |
| Final judgement under `docs/audits/evidence/<issue>/` plus spec rows; action, overlap, attribution and FP/FN explicit | Met: this record, the decision record, the Group E rows of the [detector-families spec](../../../specs/detector-families.md#groups-c-d-and-e-conditional-contracts-1228-to-1230) and a row in the same spec's Rules table. Overlap as in #1223. |
| Independently authored benchmark cases from the accepted contract, frozen before execution | Open: benchmarks #754; this contract is the input. |
| Measure published and candidate coverage before implementation; route no-code results | Open: no baseline exists; the observations above are not it. |
| Meaningful conformance (exact span, complete redaction, type and action, overlap, controls) | Open for the rows. Five boundaries are pinned by `group_e_era_and_envelopes_1230.rs` (whole input, every two-chunk byte partition, per-line session). |
| Preserve canonical Rust, runtime neutrality, whole and stream behaviour; verify Node, WASM, Python, Rust, CLI for behaviour changes | Met: no behaviour changed; a Rust test and documents only. |
| Candidate source revision and digests to benchmark replay; unchanged controls show no regression | Open: there is no candidate change. |
| Every row visible as measured-ready, no-code, policy-limited, historical-only or unresolved; unresolved is not support | Met for visibility. All 9 rows are listed. All nine are historical-only or era-specific (the three Reddit rows with Reddit-pointed archived carriers), none is marked measured-ready or no-code, and the format of all nine is unresolved; the HubSpot and JFrog rows also have a documented carrier that is not read today. |
| No release, tag, automatic promotion or owner acceptance | Met: none. |

## Tradeoffs

* **A retired credential is still reported.** A long-dead key or a documentation
  example of one is masked in a fixture or a log. The alternative leaves a
  possibly live credential in the output because a provider announced a date.
* **A Basic envelope hides the email.** For Zendesk and Reddit the whole encoded
  envelope is masked, so the public half goes with the secret, and an
  installed-app envelope with an empty password is masked though it holds no
  secret once decoded.
* **Four documented carriers are not read.** The HubSpot `hapikey` parameter, the
  JFrog header, a `curl -u` credential string and a bare Zendesk `token` member
  are false negatives, stated, with the repair route above for the first two and
  a maintainer decision for the third.
* **Era-specific claims wait.** A JFrog `AKCp` detector is not adopted: the
  documented pattern is one era of a family whose other variant is unresolved.

## Tests

`crates/secret-scan-core/tests/group_e_era_and_envelopes_1230.rs` (5 tests): an
era word near a value never silences an `access_token` field or a Bearer value;
a generic PEM key of either label is one `private_key` `block` finding over the
whole block and a certificate block is silent; a signed assertion is a separate
`jwt` finding beside `client_secret`; a Basic envelope built over a Zendesk
credential string, a Reddit client id and secret and an installed-app empty
password is one `authorization_credential` span in raw HTTP and a quoted curl
`-H`; the three Reddit carriers are read generically. Every case asserts whole
input equals every two-chunk UTF-8 byte partition equals a per-line session.

No pin, version or release change.

## Round-1 measurement addendum: final dispositions of the measured rows

The independent baseline of Group E ([benchmarks#754](https://github.com/redact-secret/redact-secret-benchmarks/issues/754),
measured at core `e1284537`, report [round 1](https://github.com/redact-secret/redact-secret-benchmarks/blob/c1837c240a9eb4ec43bfa6abc6e2e3d7f34c7291/evidence/groups-cde/round1/report.md)) is the
measurement this record's "baseline open" gate waited for, and it confirms the
`hapikey` gap this record named as pre-decided. The dispositions follow its gap
groups and nothing else; "fixed" means the product behaviour changed with a
deterministic test and an evidence addendum, confirmed only by a replay at a
commit carrying the fix, which has not run. No row is claimed covered, passing or
ready by this addendum. Group E measured 343 positives (182 exact, 151 misses) and
186 controls (2 flagged).

| Row | Measured | Disposition |
| --- | --- | --- |
| `adobe:service-account-jwt-private-key` | no positive; 1 control flagged (`<contents of private.key>`) | fixed (spaced angle placeholder, [#1234 addendum](../1234/addendum-brace-angle-mask-placeholders.md)) |
| `airtable:legacy-api-key` | 27 of 28 exact; 1 miss (`query-shape-digits24`); 1 control flagged (brace placeholder) | digits-only: fixed ([addendum](addendum-digits-only-values.md)); brace placeholder: fixed |
| `dropbox:legacy-long-lived-access-token` | 24 of 25 exact; 1 miss (`member-shape-digits24`) | fixed ([digits-only addendum](addendum-digits-only-values.md)) |
| `hubspot:legacy-api-key` | 0 of 32; 32 misses (`hapikey`) | fixed, the whole-name entry this record pre-decided ([addendum](addendum-hapikey.md)); the digits-only case follows the digits-only addendum |
| `jfrog:api-key` | 0 of 40; 40 misses | the `X-JFrog-Art-Api` header cases: fixed ([addendum](../1228/addendum-jfrog-art-api-header.md)), `header-shape-digits24` through the digits-only addendum; the `curl -u user:<secret>` cases (`basic-*`): **deferred to issue #1247**, a stated false negative |
| `reddit:oauth-access-token` | 59 of 86 exact; 27 misses: 24 revoke `token=`, 3 digits-only | `token=`: **partly fixed, partly policy-limited**: read where the request names a revoke or introspect endpoint or carries `token_type_hint=` ([addendum](addendum-revoke-token-parameter.md)), the context-free layouts are recorded false negatives; the digits-only member and fragment cases are fixed ([digits-only addendum](addendum-digits-only-values.md)) |
| `reddit:oauth-refresh-token` | 46 of 48 exact; 2 misses (digits-only) | fixed ([digits-only addendum](addendum-digits-only-values.md)) |
| `reddit:app-client-secret` | 0 of 26; 26 misses | **deferred to issue #1247**: every case is the `curl -u` or `--user` password slot, not read; a stated false negative |
| `zendesk:api-token` | 26 of 58 exact; 22 misses and 10 over-wide (a whole-string `warn` that left the token in the output), 1 masked display flagged | fixed, a reader anchored on `/token:` with a token-only `redact` span ([addendum](addendum-zendesk-email-token-credential.md)); the `curl -u` argument cases are read by the literal as a consequence |

### Deferred, not fixed

* **The `curl -u` / `--user` password slot** (JFrog API key and reference token,
  Reddit client secret): issue #1247, with the policy for a literal user part. About
  80 of the measured positives are in this slot.
* **A bare `token=`** with no revoke context, and the corpus layouts of the Reddit
  group that hold none: a recorded policy limit under the accepted rule for the
  bare `token` name ([#1241](../1241/README.md)).

No pin, version or release change.

## Final state (round 3, candidate c6dd6859), 2026-10-06

This section supersedes the round-1 measurement addendum above wherever the two
differ. Superseded statements are marked below; the round-1 text is kept as the
record of that round. The placeholder that the round-1 addendum carried for its
report is replaced there by the [round-1 report](https://github.com/redact-secret/redact-secret-benchmarks/blob/c1837c240a9eb4ec43bfa6abc6e2e3d7f34c7291/evidence/groups-cde/round1/report.md).

Measured at the final candidate redact-secret `c6dd685974b8df6a84514e07e41e35afa711a2ac`
(core `e1284537` plus the nine round-1 fixes plus the two round-2 fixes
`c8d661b3` and `c6dd6859`; declared 0.1.0-beta.14, not published). Frozen
corpora digests: C (#752, errata-1, 646 cases)
`16036d043fc0dad0e45ec42e2513d2ffec2020da3458a95ed57f09f44fb0e02d` (the original
freeze digest was `f216ca0a72c52d2b268924662d7f4ab66372c9820d0cfe386e3eefa0110dc37d`;
errata-1 made the nine `code=` controls observed-only), D (#753, 868 cases)
`aa173111a8b7142dc4f378ebd29875605658112eae6553dcfce6287cbaf8e72e`, E (#754, 767
cases) `6aa6221022b94418183f706f8034705d8c6050b5c657e309980832f6231691aa`. 2,281
cases on four surfaces (Node, WASM, Python, CLI), each whole and in 7-byte and
1-byte chunks. Against the baseline (beta.13), round 1 and round 2: 0
regressions; 0 parity divergences; 0 open product gaps. Of the 119 scored
failures across the three groups, all are recorded policy cases: 59 `curl -u`
password slot (#1247), 15 Contentful lone `token` member (#1256, rule #1241), 2
Reddit `token=` without revoke context (#1241), 1 Elastic `encoded` alone, 36
Meta `APP_ID|SECRET` whole-pair redaction (recorded deviation a), 6 `x-api-key`
Adobe client-id controls (recorded deviation b). Final dispositions of all 43
rows: 16 fully covered (C 4, D 7, E 5), 5 covered with recorded deviation, 6
policy-limited, 16 carrier unresolved (observed only), 0 open product gaps.

Sources, all at benchmarks commit `c1837c240a9eb4ec43bfa6abc6e2e3d7f34c7291` (PR #799):
[round-3 report](https://github.com/redact-secret/redact-secret-benchmarks/blob/c1837c240a9eb4ec43bfa6abc6e2e3d7f34c7291/evidence/groups-cde/round3/report.md) (per-row table: [section 6](https://github.com/redact-secret/redact-secret-benchmarks/blob/c1837c240a9eb4ec43bfa6abc6e2e3d7f34c7291/evidence/groups-cde/round3/report.md#6-final-disposition-of-all-43-rows); regressions: [section 2](https://github.com/redact-secret/redact-secret-benchmarks/blob/c1837c240a9eb4ec43bfa6abc6e2e3d7f34c7291/evidence/groups-cde/round3/report.md#2-regressions); residual groups: [section 4](https://github.com/redact-secret/redact-secret-benchmarks/blob/c1837c240a9eb4ec43bfa6abc6e2e3d7f34c7291/evidence/groups-cde/round3/report.md#4-round-2-residual-groups-and-what-still-fails)),
[round-3 scores](https://github.com/redact-secret/redact-secret-benchmarks/blob/c1837c240a9eb4ec43bfa6abc6e2e3d7f34c7291/evidence/groups-cde/round3/scores.json),
[round-3 identity](https://github.com/redact-secret/redact-secret-benchmarks/blob/c1837c240a9eb4ec43bfa6abc6e2e3d7f34c7291/evidence/groups-cde/round3/identity.json),
[round-2 report](https://github.com/redact-secret/redact-secret-benchmarks/blob/c1837c240a9eb4ec43bfa6abc6e2e3d7f34c7291/evidence/groups-cde/round2/report.md),
[round-1 report](https://github.com/redact-secret/redact-secret-benchmarks/blob/c1837c240a9eb4ec43bfa6abc6e2e3d7f34c7291/evidence/groups-cde/round1/report.md) and
[freeze record](https://github.com/redact-secret/redact-secret-benchmarks/blob/c1837c240a9eb4ec43bfa6abc6e2e3d7f34c7291/benchmarks/FREEZE-groups-cde.md).

Final disposition of the 9 rows of Group E (round-3 report, section 6; row names exact):

| Row | Final disposition | Open cases and the policy that explains them |
| --- | --- | --- |
| `adobe:service-account-jwt-private-key` | carrier unresolved (observed only) | no scored positive; 17 controls, 0 flagged. Not covered |
| `airtable:legacy-api-key` | fully covered | 28/28 positives exact, 18 controls clean |
| `dropbox:legacy-long-lived-access-token` | fully covered | 25/25 positives exact, 16 controls clean |
| `hubspot:legacy-api-key` | fully covered | 32/32 positives exact, 19 controls clean (the `YOUR_HAPIKEY` control flagged on round 2 is clean) |
| `jfrog:api-key` | policy-limited | 18 open: the `curl -u user:<password>` password slot is not read; stated false negative, #1247 (deviation c) |
| `reddit:oauth-access-token` | policy-limited | 2 open (`form-utf8-before-after`, `form-repeat`): `token=` with no revoke or introspect endpoint and no `token_type_hint` is not read; bare-`token` rule #1241 |
| `reddit:oauth-refresh-token` | fully covered | 48/48 positives exact, 20 controls clean |
| `reddit:app-client-secret` | policy-limited | 26 open: every case is the `curl -u` / `--user` password slot, not read; #1247 (deviation c) |
| `zendesk:api-token` | fully covered | 58/58 positives exact, 21 controls clean |

Group E totals at round 3: 343 positives (297 exact, 297 fully covered, 46
misses) and 186 controls (0 flagged), against 182 exact and 151 misses on the
baseline. The 46 misses are 18 JFrog and 26 Reddit-secret `curl -u` cases plus the
2 Reddit `token=` cases.

Superseded by this section: the round-1 statement that the `X-JFrog-Art-Api`,
`hapikey`, digits-only, Zendesk and revoke `token=` fixes were unconfirmed is
replaced by the round-3 replay: none of the 46 open cases belongs to those fixes
(they are the `curl -u` slot and the context-free `token=`). The round-1
statement that "about 80" measured positives sit in the `curl -u` slot is not
reconfirmed by the final report; the final count of open `curl -u` cases across
Groups C and E is 59 (15 JFrog reference token in C, 18 JFrog API key and 26
Reddit client secret in E).

Follow-ups that explain the policy-limited rows: curl `-u` password slot
[redact-secret#1247](https://github.com/redact-secret/redact-secret/issues/1247); JFrog `AKCp` bare reader, deferred
[redact-secret#1248](https://github.com/redact-secret/redact-secret/issues/1248); bare `token` member of the Contentful create
response [redact-secret#1256](https://github.com/redact-secret/redact-secret/issues/1256) under the bare-`token` rule
[#1241](../1241/README.md); existing Case contradictions
[credential-evidence#264](https://github.com/redact-secret/credential-evidence/issues/264); percent-escaped X layout confirmation
[credential-evidence#265](https://github.com/redact-secret/credential-evidence/issues/265).

Honest limits (round-3 report, section 8):

* Project-authored, maintainer-only evidence, not independent validation. The
  corpora derive from the maintainers' credential-evidence snapshot and were
  frozen before any scan; agreement shows consistency with the maintainers' own
  contract and nothing more. The policy dispositions are the maintainers' own
  decisions, recorded and not validated by the measurement.
* One host (darwin-arm64, Node v22.16.0), not a linux-x64 official run. Peers
  were not run. The candidate is unpublished (a branch commit declaring
  0.1.0-beta.14).
* The fixes target the measured failures on these same corpora, so no
  generalisation to unseen carriers is claimed. The false-positive cost on real
  traffic of the 16+ digit rule and of the placeholder grammar (`{name}`,
  `[name]`, `YOUR_<slot>`, pipe composites) is not measured by these corpora.
* A "fully covered" row means every frozen scored case passes; it does not
  promote support, change an official run, repin or release anything. A
  carrier-unresolved row has no scored positive (its controls are clean and
  nothing more) and a policy-limited row is not covered.

No pin, version or release change.
