# Evidence: #1228, Group C format-conflict contract (11 rows)

**Result:** the class-level, per-row conditional product contract for the 11
Group C rows. It states what the product will do once a row's reviewed layout
and an independent baseline exist; it claims no row covered, passing or ready,
sets no expectation from current product output or scanner majority, and invents
no carrier, field name, prefix, width or alphabet. Every row has a disposition
kind stated on the evidence handoff, and every property the handoff leaves
unresolved stays unresolved (11 of 11 have an unresolved bare-value grammar; the cross-track
ties to Groups D and E are listed below). No new bare detector is adopted: a distinctive prefix alone does not
prove the body that follows. No detector, registry entry, vocabulary name or type
changes; the four decided boundaries that are cheap to pin are pinned by
`crates/secret-scan-core/tests/group_c_opaque_values_1228.rs`. The independent
baseline (benchmarks [#752](https://github.com/redact-secret/redact-secret-benchmarks/issues/752))
does not exist yet, so no gate that needs it is met.

Issue [#1228](https://github.com/redact-secret/redact-secret/issues/1228);
evidence epic [credential-evidence#236](https://github.com/redact-secret/credential-evidence/issues/236)
(children [#239](https://github.com/redact-secret/credential-evidence/issues/239),
[#240](https://github.com/redact-secret/credential-evidence/issues/240),
[#241](https://github.com/redact-secret/credential-evidence/issues/241), all
closed); inventory
[#231](https://github.com/redact-secret/credential-evidence/issues/231). Sibling
records: [#1229](../1229/README.md) (Group D) and [#1230](../1230/README.md)
(Group E). Batch 2 precedent: [#1223](../1223/README.md).

## Sources

| Role | Source |
| --- | --- |
| Provider and source facts (pending inputs, never decided here) | The evidence handoffs [C1](https://github.com/redact-secret/credential-evidence/blob/522e079512f94930b053dc2fe5561dd63818f715/docs/handoffs/c1-adobe-prefix-subtype.md), [C2](https://github.com/redact-secret/credential-evidence/blob/522e079512f94930b053dc2fe5561dd63818f715/docs/handoffs/c2-opaque-token-shapes.md) and [C3](https://github.com/redact-secret/credential-evidence/blob/522e079512f94930b053dc2fe5561dd63818f715/docs/handoffs/c3-lexical-conflicts.md), merged as credential-evidence PRs #249, #250 and #251 (read at head `522e0795`). They are project-authored, not independent validation, and every record they describe is `draft` with `period: proposed`; none is reviewed and no family `currentContract` is set. Their dispositions are evidence-side facts, not product status. |
| Independent baseline and replay | benchmarks [#752](https://github.com/redact-secret/redact-secret-benchmarks/issues/752) (open). Its [status comment](https://github.com/redact-secret/redact-secret-benchmarks/issues/752#issuecomment-6015539311) records that no row has an accepted contract, no case is frozen and nothing is measured; this record is the contract it waits for. |
| Product policy (this record) | Built only from existing records: `decision-redact-provider-named-credential-assignments` and the Batch 2 class contract ([#1223](../1223/README.md)), the authorization grammar ([#1212](../1212/README.md)), `decision-defer-encoded-input-decoding` (#491), `decision-define-fragmented-credentials-as-outside-the-raw-input-contract`, `decision-keep-percent-containing-and-escaped-credential-representations-outside-the-raw-input-contract`, the #1225 vocabulary-admission rule ([#1225](../1225/README.md), [#1233](../1233/README.md)), the #1241 default ([#1241](../1241/README.md)) and the user-owned action configuration epic ([#1216](https://github.com/redact-secret/redact-secret/issues/1216) to #1222, open). |

## Disposition kinds and the rules that bind every row

A row's disposition is one of the five kinds the issue lists. A row can carry
one kind for its **carrier** (a documented slot: a field, a header, an envelope)
and another for its **bare value** (the credential with no slot around it).

| Kind | Meaning here | Precondition |
| --- | --- | --- |
| New detector | A provider-specific grammar on bare bytes. | A provider-documented grammar, or independent origins stating prefix, body alphabet, length and separator, in a *reviewed* contract, plus its own adoption decision. **None of the 11 rows meets it.** |
| Existing-family extension | A new form of a family the product already reports. | A reviewed layout naming the form. Not used: none of the 11 families exists in the registry. |
| Bounded-context fallback | The existing generic reading of a documented slot: `contextual_secret` for a credential-named field, `bearer_token` for an explicit Bearer header, `authorization_credential` for a Basic envelope, spanning exactly the value or the whole undecoded envelope, no provider type. | A reviewed layout that names the slot (the [#1223](../1223/README.md) class rule). |
| Era-specific contract | A rule scoped to a dated or version-scoped form. | A reviewed contract whose revision or variant carries the period. |
| Unresolved | The handoff leaves the property open. Nothing is asserted; the row is not covered and not a miss. | What would settle it is recorded per row by the handoff. |

Rules for all 11 rows:

* **Evidence classes stay separate.** A fact is frozen under the class the
  handoff gave it: *provider-documented* (a provider page or API specification),
  *SDK source* (a provider-maintained repository), *scanner-derived* (a rule
  artifact of a peer tool; consistency only), *project policy* (a decision of
  this repository). A scanner-derived fact never becomes provider validity, and
  project policy never becomes a provider-proven grammar.
* **A distinctive prefix alone does not prove every following body.** A prefix
  seen in rule artifacts or sample code is a context hint at most. It does not
  admit a bare value, and it is not a reason to change a carrier grammar.
* **Tools that copied one rule are one origin.** A rule set that imports
  another's rules (Kingfisher imports Gitleaks), a catalog generated from
  another's expression, or an expression copied verbatim counts once. Two rule
  artifacts of unstated basis are recorded as two artifacts with undemonstrated
  independence, and the contract draws nothing from them.
* **Provider opacity constrains; scanner widths never override it.** Where the
  provider says the token is opaque and of variable length (Airtable, Dropbox),
  no minimum or maximum above the generic floors is adopted from a tool. The
  product reads a slot value at any length ([pinned](#tests)).
* **No bare detector is mandatory.** The product's default for a bare value of
  an unproven grammar is silence, the stated, unassertable limit, never a miss
  and never a pass. A generic bare reading would collide with every digest,
  UUID and identifier of the same width.
* **A distinct credential keeps a distinct role.** A shared carrier proves no
  provider and no subtype, so a row is never attributed from its carrier. The
  evidence IDs stay separate, and merging or splitting a family is not decided
  here.
* **Encoded and escaped representations stay outside the raw-input contract**
  (#491 and the percent decision). A Basic envelope is never decoded, so it is
  one span over the whole encoded value, public client id half included.
* **Actions are defaults.** The defaults are those of the finding type;
  `bearer_token` and `authorization_credential` always redact, and
  `contextual_secret` redacts at high confidence and warns at medium. A user
  action policy replaces a default exactly as before (the custom policy callback
  today; the declarative overlay when #1216 to #1222 land).

## Per-row table

The state of every row is the same: the evidence handoff is **closed and merged,
records draft and unreviewed**, so the row's **reviewed layout is missing**, and
the **independent baseline is missing** (benchmarks #752 has no baseline). That
is the precondition to start for all 11; the last column names what could be
done after a baseline shows a gap. No row is marked covered or ready. Contract
links are at credential-evidence `522e0795`.

| Row (contract) | Carrier disposition | Bare-value disposition | Handoff and tie | Plausible repair only if a baseline shows a gap in the documented layout |
| --- | --- | --- | --- | --- |
| `adobe:oauth-server-to-server-client-secret` ([`@2`](https://github.com/redact-secret/credential-evidence/blob/522e079512f94930b053dc2fe5561dd63818f715/records/contracts/adobe/oauth-server-to-server-client-secret@2.json)) | Bounded-context fallback: the `client_secret` form or query parameter of the `client_credentials` request. | Unresolved: `p8e-` and a 32-character body rest on two rule artifacts of unstated basis, naming no type; hyphen in the body unresolved. | [C1](https://github.com/redact-secret/credential-evidence/blob/522e079512f94930b053dc2fe5561dd63818f715/docs/handoffs/c1-adobe-prefix-subtype.md); subtype tie to Group D | None predicted: the documented slot is read today (see observations). |
| `adobe:oauth-web-app-client-secret` ([`@1`](https://github.com/redact-secret/credential-evidence/blob/522e079512f94930b053dc2fe5561dd63818f715/records/contracts/adobe/oauth-web-app-client-secret@1.json)) | Bounded-context fallback: the `Authorization: Basic` envelope of the token, refresh and revoke requests, whole undecoded value. | Unresolved: no grammar recorded; subtype unattributed. | C1; subtype tie to Group D | None predicted. |
| `adobe:enterprise-web-app-client-secret` ([`@1`](https://github.com/redact-secret/credential-evidence/blob/522e079512f94930b053dc2fe5561dd63818f715/records/contracts/adobe/enterprise-web-app-client-secret@1.json)) | Bounded-context fallback: the `client_secret` form parameter beside `org_id`. | Unresolved: no grammar recorded; subtype unattributed. | C1; subtype tie to Group D | None predicted. |
| `airtable:personal-access-token` ([`@1`](https://github.com/redact-secret/credential-evidence/blob/522e079512f94930b053dc2fe5561dd63818f715/records/contracts/airtable/personal-access-token@1.json)) | Bounded-context fallback: the `Authorization: Bearer` header (the `api_key` URL parameter is documented as unsupported). | Unresolved: opaque by provider statement; the `pat` + 14 + `.` + 64 hex layout is two maintainers' artifacts, consistency only, and constrains nothing. | [C2](https://github.com/redact-secret/credential-evidence/blob/522e079512f94930b053dc2fe5561dd63818f715/docs/handoffs/c2-opaque-token-shapes.md); format may change for new tokens | None predicted. |
| `dropbox:access-token` ([`@1`](https://github.com/redact-secret/credential-evidence/blob/522e079512f94930b053dc2fe5561dd63818f715/records/contracts/dropbox/access-token@1.json)) | Bounded-context fallback: the `Authorization: Bearer` header and the `access_token` response member. | Unresolved: opaque, may exceed 1 KB; `sl.` and a 130-plus run are three maintainers' artifacts with different bounds (Kingfisher counted once). | C2; legacy and current tie to [Group E](../1230/README.md) | None predicted. Any bare `sl.` claim would be a project-policy decision with no maximum width. |
| `hubspot:private-app-access-token` ([`@1`](https://github.com/redact-secret/credential-evidence/blob/522e079512f94930b053dc2fe5561dd63818f715/records/contracts/hubspot/private-app-access-token@1.json)) | Bounded-context fallback: the `Authorization: Bearer` header; the `tokenKey` body field of the token-information request. | Unresolved: `pat-na1-` and `pat-eu1-` are one maintainer's artifact (not counted); the UUID shape names no credential. Era-limited: creation of new legacy private apps is being disabled. | C2; private-app versus static-auth mapping tie to [Group D](../1229/README.md) | A whole-name `tokenKey` vocabulary entry under the #1225 rule, only if the baseline's benign controls separate it from other `tokenKey` uses. The Bearer path is read today. |
| `contentful:cma-personal-access-token` ([`@2`](https://github.com/redact-secret/credential-evidence/blob/522e079512f94930b053dc2fe5561dd63818f715/records/contracts/contentful/cma-personal-access-token@2.json)) | Bounded-context fallback: `Authorization: Bearer` on the creation endpoint's documented form. | Unresolved: `CFPAT-` begins provider-maintained placeholders (a leading string only); length is 43 versus at least 40 versus a 64-hex API example; the second artifact may derive from the first. | [C3](https://github.com/redact-secret/credential-evidence/blob/522e079512f94930b053dc2fe5561dd63818f715/docs/handoffs/c3-lexical-conflicts.md) | None predicted. A prefix-only claim needs its own decision and a settled era question. |
| `jfrog:reference-token` ([`@2`](https://github.com/redact-secret/credential-evidence/blob/522e079512f94930b053dc2fe5561dd63818f715/records/contracts/jfrog/reference-token@2.json)) | Era-specific, unresolved: the `X-JFrog-Art-Api` header or the basic-authentication password. The header is not a read name today (see observations). | Unresolved: two current provider statements, 64 characters (`cmVmd` + 59) and 128 (from Artifactory 7.38.4), kept apart with page dates; 7.38.4 versus 7.38.10. | C3; era tie to [Group E](../1230/README.md) | A whole-name entry for the documented header, shared with the JFrog API key and attributing neither; no bare claim. |
| `meta:app-secret` ([`@2`](https://github.com/redact-secret/credential-evidence/blob/522e079512f94930b053dc2fe5561dd63818f715/records/contracts/meta/app-secret@2.json)) | Bounded-context fallback: the `client_secret` parameter; the `{app-id}\|{app-secret}` composite is decided in [Group D](../1229/README.md). | Unresolved: 32 characters is artifact scope, the alphabet is not settled, and a 32-character value collides with digests and identifiers, so a bare value is never attributable. | C3; composite tie to Group D | None predicted. |
| `salesforce:oauth-refresh-token` ([`@2`](https://github.com/redact-secret/credential-evidence/blob/522e079512f94930b053dc2fe5561dd63818f715/records/contracts/salesforce/oauth-refresh-token@2.json)) | Bounded-context fallback: the `refresh_token` request parameter and response member (a token-endpoint field, never a resource Bearer credential). | Unresolved: `5Aep861` rests on two artifacts of unconfirmed independence with remainders of 80 versus 40 (others 60 and 20), and the prefix is not provider-stated or attributable to refresh tokens. | C3 | None predicted. |
| `x:oauth1-consumer-secret` ([`@2`](https://github.com/redact-secret/credential-evidence/blob/522e079512f94930b053dc2fe5561dd63818f715/records/contracts/x/oauth1-consumer-secret@2.json)) | Unresolved: the secret is a signing-key input and no transported carrier is named; a percent-containing form stays outside the raw-input contract. | Unresolved: 50 characters is two maintainers' artifacts, 35 to 44 one artifact, and the provider's 43-character example is an example. | C3; the token half is [Group D](../1229/README.md) | None predicted: no layout to measure until the evidence names a carrier. |

## Facts by evidence class

Only what the handoffs record. "Origins" counts a copied rule once. Nothing in
the scanner column is a provider statement.

| Row | Provider-documented | SDK source | Scanner-derived | Project policy (this record) |
| --- | --- | --- | --- | --- |
| Adobe S2S client secret | `client_secret` form or query parameter, body recommended; documentation shows only placeholders and no format. | none | `p8e-` and a 32-character body: Gitleaks `adobe.go` and Nosey Parker `adobe.yml`, different maintainers, no type named, basis unstated (independence undemonstrated). | A distinctive prefix is not subtype attribution; `p8e-` is not removed or added to any grammar. |
| Adobe Web App client secret | Basic over client id and client secret; public clients send `client_id`; metadata lists `client_secret_basic` and `client_secret_post`, only Basic documented. | none | none recorded for this subtype | The Basic envelope is one span over the undecoded value. |
| Adobe Enterprise client secret | `grant_type`, `client_id`, `client_secret`, `scope`, `org_id` form parameters; UI rotation only. | none | none recorded | `org_id` and the client id stay outside a field span. |
| Airtable PAT | Prefixed with its ID, otherwise opaque and variable-length; format change for new tokens not breaking; Bearer header; shown once; no expiry. | none | `pat` + 14 + `.` + 64 lowercase hex (two maintainers, consistency only). | No tool layout is a provider validity; the slot value is read at any length. |
| Dropbox access token | Opaque, may exceed 1 KB, no size or composition guarantee; Bearer; `access_token` member. | none | `sl.` + 130-plus run: fixed 135, 130 to 152, and 130 minimum with no maximum (three maintainers, Kingfisher counted once); `sl.u.` handled by one artifact. | No width is adopted; a tool range is never a validity interval. |
| HubSpot private-app token | Per-app token, Bearer, `tokenKey` request field, rotation (about 7 days overlap), built on OAuth, new legacy private app creation disabled from 2026-09-28 and 2026-10-26. | none | UUID 8-4-4-4-12 near a HubSpot keyword (two maintainers, names no credential); `pat-na1-` and `pat-eu1-` (one maintainer, not counted). | The private-app token is not merged with the static-auth token. |
| Contentful CMA PAT | Created in the web app or by `POST /users/me/access_tokens`, Bearer, shown once; two provider repositories write a placeholder beginning `CFPAT-`. | Provider-maintained placeholders begin `CFPAT-` (a leading string only). | `CFPAT-` + letters, digits, `_` and `-`: 43 exactly versus at least 40 (the second may derive from the first). | The 64-hex API example and a 2018 recording lead are era evidence, not a union. |
| JFrog reference token | `cmVmd` + 59 alphanumerics, "short (64 characters)" (Identity Tokens, updated 2026-08-13); "shortened, 128-character key" from 7.38.4 (Access Tokens, updated 2026-07-06); header or basic password; stored hashed. | none | 64 total in a Gitleaks rule (generic, keyword-gated) and a TruffleHog rule (`cmVmdGtu` + 56); none gives 128. | The two statements are kept apart; the 128 is not discarded. |
| Meta app secret | Dashboard reset only; `client_secret` of the app access token call; `{app-id}\|{app-secret}` as `access_token`; `appsecret_proof` is a keyed hash output; the client token is documented not secret. | none | Exactly 32 captured after a facebook-related word in Gitleaks, TruffleHog and Nosey Parker; alphabets differ. | A bare 32-character value is never attributable. |
| Salesforce refresh token | Optional `refresh_token` response member, "This value is a secret"; `refresh_token` parameter of `POST /services/oauth2/token`; not in a GET query. | none | `5Aep861` in TruffleHog and Vulnetix; remainder 80 versus 40; `=` versus `-`; independence unconfirmed. | The prefix is an artifact scope, not a Salesforce statement. |
| X OAuth 1.0 consumer secret | "API Key Secret", shown once; signing key input; `oauth_signature` is a base64 HMAC-SHA1 output and not the secret; a 2011 worked example uses 22, 43 and 41 characters. | none | Gitleaks and TruffleHog capture 50; Nosey Parker 35 to 44 (single artifact lead). | No union of lengths; the signature output is not the secret. |

## Product observations

Product observations at core `01740490` (CLI `0.1.0-beta.13` line, debug build of
this commit, check mode, UTF-8 byte ranges, `--json`), on small synthetic inputs
written for this record, to ground the statements above. Not benchmark results,
not coverage claims, not a baseline, and not an expectation: the inputs were
not authored against any reviewed layout. Values are invented runs of 12 to 150
bytes and are not shown. "Silent" means no finding.

| Input (synthetic) | Observed finding |
| --- | --- |
| `p8e-` + 32 bytes, bare in a sentence, and with a hyphen inside the body | silent |
| form body with `client_secret` = `p8e-` + 32 beside `client_id`, `grant_type`, `scope` | `contextual_secret`, high, redact, over the value only (57-93) |
| form body with a 32-byte `client_secret` without a prefix and `org_id` | `contextual_secret`, high, redact, over the value only |
| `Authorization: Basic` + a 64-byte base64-alphabet value | `authorization_credential`, high, redact, over the whole value (49-113) |
| `pat` + 14 + `.` + 64 hex, bare | silent |
| the same behind `Authorization: Bearer`; or `AIRTABLE_API_KEY=` | `bearer_token`, high, redact, whole value; `contextual_secret`, high, redact |
| a 40-byte opaque run, bare | silent |
| `sl.` + 136, `sl.u.` + 136, `sl.` + 400, bare | silent (3 inputs) |
| `sl.` + 136 behind Bearer; JSON `access_token` with an 80-byte opaque value and with `sl.` + 136 | `bearer_token`, high, redact; `contextual_secret`, high, redact, exact value (both lengths) |
| `pat-na1-` or `pat-eu1-` + UUID, bare; a bare UUID | silent (3 inputs) |
| `pat-na1-` + UUID behind Bearer | `bearer_token`, high, redact, whole value |
| JSON `{"tokenKey": ...}`, and `tokenKey=` assignment | silent |
| `CFPAT-` + 43, bare | silent |
| `CFPAT-` + 43 behind Bearer; `CONTENTFUL_MANAGEMENT_TOKEN=`; 64 hex behind Bearer | `bearer_token`, high, redact; `contextual_secret`, high, redact; `bearer_token`, high, redact |
| `AKCp8` + 68, `cmVmdGtu` + 56, bare; the same and `cmVmd` + 59 and + 123 in an `X-JFrog-Art-Api` header (raw and quoted curl `-H`) | silent |
| `cmVmd` + 59 behind Bearer; `password=` + `AKCp8` + 68 | `bearer_token`, high, redact; `contextual_secret`, high, redact |
| 32 hex bare; `app_secret=`, `client_secret=` and `FACEBOOK_APP_SECRET=` with 32 bytes | silent; `contextual_secret`, high, redact, exact value (3 inputs) |
| `appsecret_proof=` + 64 hex | silent |
| `5Aep861` + 80, bare | silent |
| `refresh_token=` + `5Aep861` + 80; the JSON `refresh_token` member | `contextual_secret`, high, redact, exact value (the JSON also reports its 60-byte `access_token`) |
| `consumer_secret=` + 50, `TWITTER_CONSUMER_SECRET=` + 50, `oauth_consumer_secret=` + 43; a 50-byte run, bare | `contextual_secret`, high, redact, exact value (3 inputs); silent |

Two observations bound what this record may later claim. First, the documented
`X-JFrog-Art-Api` header is not a read name, so a JFrog value in its own
documented carrier gets no finding today; the same holds for the HubSpot
`tokenKey` field. They are candidates only if a baseline shows the gap, not a
repair made here. Second, every `contextual_secret` and `bearer_token` above is
generic: no provider type, and the prefix changes neither span nor type.

## Cross-track ties (kept open, not decided here)

* **Adobe subtype** (Group D): `p8e-` is not attributed to any of the three
  credential types by any source read. The three rows keep three roles and three
  IDs. The product claims no Adobe type and the carrier decides the reading
  (field for S2S and Enterprise, Basic envelope for Web App).
* **HubSpot private-app versus static-auth** (Group D): no HubSpot page relates
  the two. They stay two roles; the product reads both through the Bearer path
  with no HubSpot attribution, and `hubspot:legacy-api-key`,
  `hubspot:personal-access-key` and the OAuth rows are not merged with either.
* **Dropbox legacy versus current** (Group E): the long-lived token is a separate
  family with a conflicting retirement date; the two are not separable by shape,
  so the product reads both through the same Bearer and `access_token` slots.
* **JFrog eras** (Group E): the 64 versus 128 conflict and the AKCp variants are
  era questions recorded in [#1230](../1230/README.md); this record adopts no
  length.

## Gates of the issue

| Gate | State |
| --- | --- |
| For every candidate, review the handoff and freeze supported, unsupported and unknown shape, role, temporal boundary and disposition, preserving source-tier attribution | Met by this record: the per-row and per-class tables freeze them conditionally, separated by evidence class, with no provider grammar claimed from project policy. |
| Final judgement under `docs/audits/evidence/<issue>/` plus spec rows; action, overlap, attribution and FP/FN explicit | Met: this record, the Group C rows of the [detector-families spec](../../../specs/detector-families.md#groups-c-d-and-e-conditional-contracts-1228-to-1230), the defaults above, overlap as in #1223 (a provider detector on the same bytes keeps precedence, the generic finding is the fallback). |
| Independently authored benchmark cases from the accepted contract, frozen before execution | Open: benchmarks #752. This contract is the input; nothing is authored here. |
| Measure published and candidate coverage before any implementation; route no-code results | Open: no baseline exists. The observations above are not it. |
| Meaningful conformance (exact span, complete redaction, type and action, overlap, controls) | Open for the rows. The four pinned boundaries are checked by `group_c_opaque_values_1228.rs` (whole input, every two-chunk byte partition, per-line session). |
| Preserve canonical Rust, runtime neutrality, whole and stream behaviour; verify Node, WASM, Python, Rust, CLI for behaviour changes | Met: no behaviour changed, only a Rust test was added. Nothing to verify on the other surfaces. |
| Candidate source revision and digests to benchmark replay; unchanged controls show no regression | Open: there is no candidate change. If a baseline later forces a repair, the merge commit of that change is the identity to replay. |
| Every row visible as measured-ready, no-code, policy-limited, historical-only or unresolved; unresolved is not support | Met for visibility: all 11 rows are listed, none is marked measured-ready or no-code (that needs a baseline), and the bare-value disposition of every row is `unresolved`. |
| No release, tag, automatic promotion or owner acceptance | Met: none. |

## Tradeoffs

* **A bare provider-shaped value is not read.** A real Adobe, Airtable, Dropbox,
  HubSpot, Contentful, Salesforce, Meta or X secret that appears with no slot
  around it (a prose paste, an unnamed argument) is a false negative, stated and
  not repaired. The alternative, a bare prefix detector, would rest on a tool
  width or one origin that the handoffs call unresolved, and a prefix-only match
  would redact every value that happens to start the same way.
* **A slot value is read generically.** A non-secret literal of 8 bytes or more
  placed in a credential slot is redacted at high confidence or warned at
  medium, with the Batch 2 tradeoff, and no provider attribution results.
* **An envelope hides the public half.** A Basic envelope is one credential, so
  the Adobe Web App client id goes with the secret.

## Tests

`crates/secret-scan-core/tests/group_c_opaque_values_1228.rs` (5 tests): the
prefix shapes of the 11 rows, built from a fixed pseudo-random walk, are silent
bare; the same values behind `access_token=` and `Authorization: Bearer` are one
`contextual_secret` or `bearer_token` over exactly the value; an opaque
`sl.`-prefixed value is read whole at 20 to 1500 bytes; an Adobe form
`client_secret` ends at its delimiter with the client id, scope and `org_id`
outside; a Basic envelope is one `authorization_credential` span. Every case
asserts whole input equals every two-chunk UTF-8 byte partition equals a
per-line session. The product observations above are pinned by this record only,
and the independent measurement is the benchmarks side's.

No pin, version or release change.

## Round-1 measurement addendum: final dispositions of the measured rows

The independent baseline of Group C ([benchmarks#752](https://github.com/redact-secret/redact-secret-benchmarks/issues/752),
measured at core `e1284537`, report [round 1](https://github.com/redact-secret/redact-secret-benchmarks/blob/c1837c240a9eb4ec43bfa6abc6e2e3d7f34c7291/evidence/groups-cde/round1/report.md)) is the
first measurement this record's "no gate that needs it is met" waited for. The
dispositions below follow its gap groups and nothing else; "fixed" means the
product behaviour changed with a deterministic test and an evidence addendum, and
that the replay at a commit carrying the fix is what confirms it, which has not
run. No row is claimed covered, passing or ready by this addendum. Group C
measured 277 positives (197 exact, 65 misses) and 251 controls (36 flagged).

| Row | Measured | Disposition |
| --- | --- | --- |
| `adobe:oauth-server-to-server-client-secret`, `adobe:enterprise-web-app-client-secret` | 24 and 21 positives exact; 8 controls flagged each: 3 brace placeholders, 2 `x-api-key` public client ids, 3 OAuth `code=` | brace placeholders: fixed ([#1234 addendum](../1234/addendum-brace-angle-mask-placeholders.md)); `x-api-key` public client id: **deliberate policy deviation**, below; `code=`: a corpus erratum candidate of the measurement (the generic `code` rule reads an authorization code as a `warn`), no product change |
| `adobe:oauth-web-app-client-secret` | 16 positives exact; 5 controls flagged: 2 `x-api-key`, 3 `code=` | the same two dispositions |
| `airtable:personal-access-token`, `dropbox:access-token`, `salesforce:oauth-refresh-token` | all positives exact; no control flagged | none |
| `contentful:cma-personal-access-token` | 18 of 33 exact; 15 misses (the `token` member of the create response); 5 controls flagged (documented masks) | `token` member: **policy-limited**, a sibling reader for the documented `sys` and `scopes` members is implemented and the measured layouts (the member alone, or beside `name`) are not read, with the choices and their cost recorded ([addendum](addendum-contentful-create-response-token.md)); masks `CFPAT-xxx` and `CFPAT-123...789`: fixed ([#1234 addendum](../1234/addendum-brace-angle-mask-placeholders.md)) |
| `hubspot:private-app-access-token` | 18 of 35 exact; 17 misses (the `tokenKey` member) | fixed, a scoped reader (quoted member only; [addendum](addendum-token-key-member.md)); the Bearer path was already read |
| `jfrog:reference-token` | 0 of 33; 33 misses | the `X-JFrog-Art-Api` header cases: fixed ([addendum](addendum-jfrog-art-api-header.md)); the `curl -u user:<secret>` password cases: **deferred to issue #1247**, a stated false negative |
| `meta:app-secret` | 7 exact and 22 fully covered (15 over-wide pipe cases, no byte uncovered); 10 controls flagged (brace placeholders) | over-wide pipe: **deliberate policy deviation**, below; brace placeholders: fixed |
| `x:oauth1-consumer-secret` | no positive; no control flagged | none |

### Deliberate policy deviations from the Cases (not product defects)

* **The Meta `APP_ID|SECRET` composite is redacted whole.** The Case expects the
  span after the pipe only (`meta-app-secret-in-app-id-pipe-access-token`); the
  product reports one `contextual_secret` or `bearer_token` over the whole pair,
  the public app id included (decision 4 of the [Group D record](../1229/README.md)).
  Basis: a secret-only span needs a composite grammar no source states, and the
  whole span cannot leave the secret half readable (no byte of the secret is
  uncovered in any of the 36 measured pipe cases). Product: unchanged, the app id
  half is over-redacted. Benchmarks: score these cases on full coverage
  (`fullyCovered`), or freeze the whole pair as the expected span; they are not
  false negatives. credential-evidence: the Case's extent sentence is the
  disagreement; restating it as the whole composite, or recording the narrower span
  as a role expectation the product does not follow, resolves it.
* **An `x-api-key` header whose value is Adobe's public client id keeps being
  flagged.** The Case lists the client id as a public identifier
  (`adobe-client-secret-placeholders-references-and-public-identifiers`); a generic
  scanner cannot know that a value in `x-api-key` is Adobe's, and the slot is a
  credential slot for every other provider. Basis: the security-first default and
  the decision to keep role facts out of detection
  (`keep-credential-role-facts-out-of-detection-attribution-and-default-action`).
  Product: unchanged (`contextual_secret`, high, `redact`). Benchmarks: record the
  six measured controls as an accepted false positive or move them to observed
  only. credential-evidence: keep the identifier role as a fact; the expectation
  that the value is not flagged is not the product's behaviour.
* **The `curl -u user:<secret>` password slot is not read** for the JFrog reference
  token (the `curl-u-password-*` cases). The reader of that slot, with its policy
  for a literal user part, is issue #1247; until then the cases are stated false
  negatives of the product, not defects of the header repair.

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

Final disposition of the 11 rows of Group C (round-3 report, section 6; row names exact):

| Row | Final disposition | Open cases and the policy that explains them |
| --- | --- | --- |
| `adobe:oauth-server-to-server-client-secret` | covered with recorded policy deviation | 2 controls: `x-api-key` header holding Adobe's public client ID is flagged (accepted false positive, deviation b) |
| `adobe:enterprise-web-app-client-secret` | covered with recorded policy deviation | 2 controls, same as above (deviation b) |
| `adobe:oauth-web-app-client-secret` | covered with recorded policy deviation | 2 controls, same as above (deviation b) |
| `airtable:personal-access-token` | fully covered | 22/22 positives exact, 21 controls clean |
| `contentful:cma-personal-access-token` | policy-limited | 15 open: a lone `token` member of the create response (beside only `name`) is not read; #1256 under the bare-`token` rule #1241 |
| `dropbox:access-token` | fully covered | 36/36 positives exact, 22 controls clean |
| `hubspot:private-app-access-token` | fully covered | 35/35 positives exact, 22 controls clean |
| `jfrog:reference-token` | policy-limited | 15 open: the `curl -u user:<password>` password slot is not read; stated false negative, #1247 (deviation c) |
| `meta:app-secret` | covered with recorded policy deviation | 15 positives are fully covered but not exact: the `APP_ID\|SECRET` pair is redacted whole, public app id included; no byte uncovered (deviation a) |
| `salesforce:oauth-refresh-token` | fully covered | 35/35 positives exact, 21 controls clean |
| `x:oauth1-consumer-secret` | carrier unresolved (observed only) | no scored positive; 12 controls, 0 flagged. Not covered |

Group C totals at round 3: 277 positives (232 exact, 247 fully covered, 30
misses) and 242 controls (6 flagged), against 197 exact, 65 misses and 27 flagged
on baseline and round 1 (rescored on the errata-1 corpus). The 30 misses are the
15 Contentful `token` member cases and the 15 JFrog `curl -u` cases; the 6
flagged controls are the `x-api-key` client-id controls.

Superseded by this section: the round-1 statement that three OAuth `code=`
controls per Adobe row were flagged. Errata-1 of the corpus made the nine `code=`
controls observed-only, so they are no longer scored. The round-1 figure "251
controls (36 flagged)" is replaced by 242 controls with 6 flagged on round 3. The
round-1 statement that the replay "has not run" is replaced by the round-3
replay above; "fixed" for the brace, angle and mask placeholder controls, the
HubSpot `tokenKey` member and the JFrog `X-JFrog-Art-Api` header cases is now
confirmed on the measured cases only. The Meta pipe, Adobe `x-api-key` and
`curl -u` items remain deliberate deviations, not defects, as the round-1
addendum states.

'Covered with recorded policy deviation' means the only open cases are the accepted deviations (a) and (b), not that the Case is met as written.

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
