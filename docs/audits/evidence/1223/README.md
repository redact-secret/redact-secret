# Evidence: #1223, Batch 2 OAuth, Bearer and Basic credential paths

**Result:** the product contract for the 48 G1 to G3 rows is adopted as a
class-level, conditional policy. It states the output the product produces once
a row has a reviewed carrier layout and an independent baseline, and what is out
of contract. It claims no row covered, passing or ready, states no benchmark
result, and changes no code, detector, registry entry, vocabulary name or type.
The one policy decision this record needs beyond existing rules, how a
percent-containing or escaped representation is treated, is
[`decision-keep-percent-containing-and-escaped-credential-representations-outside-the-raw-input-contract`](../../../decisions/2026-10-05-keep-percent-containing-and-escaped-credential-representations-outside-the-raw-input-contract.md).

Issue [#1223](https://github.com/redact-secret/redact-secret/issues/1223)
(measurement children benchmarks
[#740](https://github.com/redact-secret/redact-secret-benchmarks/issues/740),
[#741](https://github.com/redact-secret/redact-secret-benchmarks/issues/741) and
[#742](https://github.com/redact-secret/redact-secret-benchmarks/issues/742)),
Batch 2 of the credential-evidence adoption inventory
([#231](https://github.com/redact-secret/credential-evidence/issues/231), handoff
[#235](https://github.com/redact-secret/credential-evidence/issues/235)). Sibling
records: #1224, #1225 and #1226 under `docs/audits/evidence/`.

## Why this is a contract and not a measurement

The benchmarks readiness inventory for the epic
([benchmarks#739](https://github.com/redact-secret/redact-secret-benchmarks/issues/739),
comment 6001345412; file `evidence/739/readiness.md` at the head `4523afb4` of
benchmarks PR #755, open when this was written) reports that the product side
has no adopted contract for any of the 58 rows (0 ready, 27 carrier-unresolved
and 31 blocked), that no independent baseline exists, and that none of the 58 evidence contracts is reviewed (all proposed or
draft, `currentContract` null). A row is `ready` for measurement only when a
reviewed evidence contract names its carrier, so a product expectation cannot be
frozen row by row yet. This record freezes what can be decided now, the class
rules that the issue text and the existing records already imply, and states for
each row the precondition under which the class rule applies. The expectation is
written before any scan of those rows, so the benchmark does not have to infer
intended output from current output.

## Sources

| Role | Source |
| --- | --- |
| Provider facts (pending inputs, never decided here) | The 58 proposed contracts of credential-evidence#235, and the evidence-owned [Batch 2 handoff](https://github.com/redact-secret/credential-evidence/blob/005a7331cf90403bd4ce4abcb93bd8b085d315a9/docs/handoffs/batch-2-bounded-carriers.md) merged as credential-evidence#248 (project-authored, not independent validation). Its `ready` and `carrier-unresolved` marks are evidence-side dispositions, not benchmark readiness and not a review of the contracts. |
| Independent baseline and replay | None exists. benchmarks#739 owns it; the readiness inventory above is its latest state. |
| Product policy (this record) | The class rules and dispositions below, built only from existing records: the `bearer-token` grammar and #818 floor, the contextual assignment grammar and its form-delimiter rule (#816), the `Basic` and `ApiKey` authorization grammar (#1212, #1213), `decision-warn-unconditionally-on-high-signal-contextual-names`, `decision-redact-provider-named-credential-assignments`, `decision-defer-encoded-input-decoding`, and the Batch 1 records [#1209](../1209/README.md) to [#1213](../1213/README.md). |

## Class contracts

A class rule applies to a row only when the row's reviewed layout names one of
the layout kinds below. Otherwise the row is carrier-unresolved and nothing is
asserted for it. Offsets are UTF-8 bytes.

| Question | Access-token rows (G1, 23) | Refresh-token rows (G2, 13) | Client and application secret rows (G3, 12) |
| --- | --- | --- | --- |
| Layout kinds in contract | A credential-named field (assignment, quoted assignment, form-body or query parameter, JSON or YAML member), and an explicit `Authorization:` or `Proxy-Authorization:` Bearer value (raw HTTP, quoted curl `-H`, JSON header map). | Field layouts only: a token-endpoint response member, a request form body, an assignment. Refresh tokens are token-endpoint fields, not resource Bearer credentials. | A credential-named field (`client_secret` assignment, form body, JSON member), and an `Authorization: Basic` envelope (raw HTTP, quoted curl `-H`, JSON header map). |
| Value admission | Field: the shared contextual grammar, 8-byte floor, reference, placeholder and mask exclusions. Bearer: RFC 6750 `b64token` alphabet with at most two trailing `=`, 12-byte floor after an explicit header and 16 bare. | As the field column. | Field: as left. Basic: the authorization value alphabet, at least 12 bytes. |
| Span and envelope | Field: exactly the value, ending at the form delimiter (`&`), at `&name=`, whitespace or the closing quote; names, `client_id`, `scope`, `token_type`, `expires_in` and delimiters stay outside. Bearer: exactly the value; the header name, scheme and space stay outside. | Exactly the value. In `refresh_token=V&client_id=x` only `V`. | Field: exactly the value. Basic: the whole encoded envelope, never decoded and never a secret-only span; it also covers the public client id half, because the encoded value is one credential. |
| Finding type | Field `contextual_secret`; Bearer `bearer_token`. Never a provider or subtype type: a Bearer header or a `*_token` name proves no provider, and Meta roles, Contentful, Salesforce and Elastic tokens are not distinguished by their carrier. | `contextual_secret`. | Field `contextual_secret`; Basic `authorization_credential`. No provider type. |
| Default action | `bearer_token` redact (always-redact). Field: redact at high confidence, warn at medium, as `decision-warn-unconditionally-on-high-signal-contextual-names` accepts. | As the field column. | Basic: redact (always-redact). Field: as left. |
| Exclusions and controls | Public ids (client, app, account, user, file and object ids), `expires_in`, `token_type`, `scope`, placeholders, references, masks, and names that are not credential names. | As left, plus `refresh_token_expires_in`. | HMAC and signature outputs (an `X-...-Signature` header, a webhook signature, an OAuth `oauth_signature`) are not an application secret; `client_id`, app and account ids; the shared exclusions. |

Rules that hold for all three classes:

* **Names are not broadened.** `access_token`, `refresh_token` and
  `client_secret` are high-signal names; a prefixed `*_token` or `*_secret` name
  is high-signal like any provider-named credential. The bare `token`,
  `csrf_token`, `*_key` and `*_signature` names stay unmatched. No vocabulary
  entry is added by this record, and no entry is added without a reviewed layout
  that names the field.
* **No registry growth.** No per-family detector, bare-prefix grammar or width
  or alphabet claim: the evidence states roles, and the same role does not imply
  the same byte grammar across providers.
* **Warn is a disposition, not a defect.** A short or non-random literal under a
  credential name lands at medium and is `warn`; the default action is not
  forced to `redact` to pass a case. A benchmark expectation for a low-entropy
  synthetic value is `medium` and `warn`. A user action policy replaces the
  default exactly as before, including the declarative overlay work of
  [#1216](https://github.com/redact-secret/redact-secret/issues/1216) to #1222
  when it lands; this contract states defaults only.
* **Unsupported layouts have a disposition.** Below the floors (8 bytes for a
  field, 12 for Bearer and Basic), a value on the line after its name or header,
  a layout the evidence does not name, a value split across lines or literals
  (`decision-define-fragmented-credentials-as-outside-the-raw-input-contract`),
  a base64 or other encoded carrier (`decision-defer-encoded-input-decoding`)
  and a percent-escaped or serialized-escaped value (the decision above) are
  documented limits: no finding, or only the contiguous prefix, never claimed
  coverage and never scored as a miss.
* **Overlap.** A provider detector on the same bytes keeps precedence through the
  existing specificity rule; the generic finding is the fallback.

## Product observations

Product observations at core `3b1a5aa9` (published CLI line `0.1.0-beta.13`,
debug build of this commit, check mode, UTF-8 byte ranges), taken on small
synthetic inputs with the public CLI to ground the statements above. They are
not benchmark results, not coverage claims and not a baseline: the inputs were
written for this record, not authored against any row's reviewed layout.
Values are 12 to 50 bytes of invented alphanumeric text and are not shown.

| Input (synthetic) | Observed finding |
| --- | --- |
| `grant_type=refresh_token&refresh_token=<20>&client_id=<12>&client_secret=<20>&scope=read` | `contextual_secret`, high, redact, at 39-59 (`refresh_token`) and 98-118 (`client_secret`); `grant_type`, `client_id` and `scope` silent |
| JSON `{"access_token":"<24>","token_type":"bearer","expires_in":3600,"refresh_token":"<20>"}` | `contextual_secret`, high, redact, at 17-41 and 100-120; `token_type` and `expires_in` silent |
| `access_token=<13, low entropy>` | `contextual_secret`, medium, warn |
| `access_token=<7 bytes>` | no finding (under the 8-byte floor) |
| `Authorization: Bearer <50>` | `bearer_token`, high, redact, at 22-74 (the value only) |
| `Authorization: Bearer <11 bytes>` and `<12 bytes>` | none, then `bearer_token` high redact at 22-34 |
| `Authorization: Basic <48 bytes>` after a request line | `authorization_credential`, high, redact, over the whole 48-byte encoded envelope (37-85) |
| 24-byte value under `token`, `some_key`, `client_id`, `csrf_token`, `authorization_signature` | no finding |
| 24-byte value under `app_secret`, `vendor_access_token` | `contextual_secret`, high, redact |
| `refresh_token_expires_in=2592000`, `access_token_type=Bearer` | no finding |
| `Authorization: Bearer <YOUR_ACCESS_TOKEN>`, `client_secret=${CLIENT_SECRET}`, `client_secret=YOUR_CLIENT_SECRET`, a `refresh_token=` mask | no finding |
| `Authorization: Bearer <24>%2B<12>`, and `<42>%2B<12>%3D` | `bearer_token`, high, redact, over the run before the `%` only (22-46, 22-64); the `%2B...` tail stays in the redacted output |
| `Authorization: Bearer <7>%2B<...>` | no finding (leading run under 12 bytes) |
| `access_token=<run>%2B<run>%3D&token_type=bearer` | `contextual_secret`, high, redact, over the whole value up to the `&` (13-61, escapes included) |

The last three rows are the Bearer-versus-field asymmetry that the percent
decision records: a form or assignment value ends at its delimiter and keeps its
escapes inside the span, while a Bearer value ends at the first byte outside its
alphabet, so a redacted prefix is not full coverage when the credential continues
with `%XX`.

## Per-row table

Legend. Layout kind, as named by the evidence handoff and not reviewed: B
explicit Bearer header, F field (assignment, form body, JSON or YAML member), BA
Basic envelope, C no layout named. Product disposition kind: *existing generic
path* means the class rule above applies unchanged once a reviewed layout names
that kind; *conditional on a reviewed layout* means nothing is asserted until
the evidence names one. **P1**: start when the evidence contract is promoted from
proposed or draft (human review event, `currentContract` set) and still names
the layout, and an independent baseline exists (the published artifact pin
resolved at execution, a separately pinned candidate, expectations frozen before
the scan). **P2**: first the provider source the evidence names (shown), then
P1. "Benchmarks inventory" is the benchmarks readiness state at credential-evidence
`c34976b`; "Evidence handoff" is the later credential-evidence#248 disposition.
No row is marked covered, and neither state is a false negative, a true negative
or passing coverage.

### G1: 23 families

| Family | Layout kind (evidence-named, unreviewed) | Product disposition kind | Benchmarks inventory | Evidence handoff | Precondition |
| --- | --- | --- | --- | --- | --- |
| `adobe:oauth-server-to-server-access-token` | F | existing generic path: field | blocked (awaiting-evidence-review) | ready | P1 |
| `airtable:oauth-access-token` | B | existing generic path: explicit Bearer | blocked (awaiting-evidence-review) | ready | P1 |
| `asana:oauth-access-token` | C | conditional on a reviewed layout | carrier-unresolved (carrier-source-missing) | carrier-unresolved | P2: Asana "Authentication" / "OAuth" pages: token response member name and the Authorization form for an OAuth access token |
| `asana:personal-access-token` | B | existing generic path: explicit Bearer | blocked (awaiting-evidence-review) | ready | P1 |
| `box:oauth-access-token` | C | conditional on a reviewed layout | blocked (awaiting-evidence-review) | carrier-unresolved | P2: Box developer docs (not readable in the first pass): authorization header form and the `access_token` member; app and developer token subtypes |
| `canva:access-token` | F | existing generic path: field | blocked (awaiting-evidence-review) | ready | P1 |
| `contentful:oauth-application-access-token` | C | conditional on a reviewed layout | carrier-unresolved (carrier-source-missing) | carrier-unresolved | P2: Contentful "Authentication" page: header form for an OAuth token and the token-response field |
| `elastic:access-token` | B | existing generic path: explicit Bearer | blocked (awaiting-evidence-review) | ready | P1 |
| `elastic:service-account-token` | B | existing generic path: explicit Bearer | blocked (awaiting-evidence-review) | ready | P1 |
| `figma:oauth-access-token` | F+B | existing generic paths: field and explicit Bearer | blocked (awaiting-evidence-review) | ready | P1 |
| `figma:scim-api-token` | B | existing generic path: explicit Bearer | blocked (awaiting-evidence-review) | ready | P1 |
| `hubspot:oauth-access-token` | B | existing generic path: explicit Bearer | blocked (awaiting-evidence-review) | ready | P1 |
| `hubspot:service-key` | B | existing generic path: explicit Bearer | blocked (awaiting-evidence-review) | ready | P1 |
| `meta:instagram-user-access-token` | C | conditional on a reviewed layout | carrier-unresolved (carrier-source-missing) | carrier-unresolved | P2: Meta developer docs: how each token kind is passed (`access_token` parameter vs Authorization header) per token kind, kept separate |
| `meta:page-access-token` | C | conditional on a reviewed layout | carrier-unresolved (carrier-source-missing) | carrier-unresolved | P2: Meta docs: carrier for a Page token; do not assume it equals the user-token carrier |
| `meta:system-user-access-token` | C | conditional on a reviewed layout | carrier-unresolved (carrier-source-missing) | carrier-unresolved | P2: Meta docs: carrier for a system user token |
| `meta:user-access-token` | C | conditional on a reviewed layout | carrier-unresolved (carrier-source-missing) | carrier-unresolved | P2: Meta docs: carrier for a user token and short-lived vs long-lived forms |
| `mongodb-atlas:service-account-access-token` | B | existing generic path: explicit Bearer | blocked (awaiting-evidence-review) | ready | P1 |
| `salesforce:oauth-access-token` | C | conditional on a reviewed layout | carrier-unresolved (carrier-source-missing) | carrier-unresolved | P2: Salesforce OAuth docs: `access_token` response member and Authorization form; subtype between connected and external client app tokens |
| `spotify:access-token` | B | existing generic path: explicit Bearer | blocked (awaiting-evidence-review) | ready | P1 |
| `x:oauth2-user-access-token` | B | existing generic path: explicit Bearer | blocked (awaiting-evidence-review) | ready | P1 |
| `zendesk:oauth-access-token` | B+F | existing generic paths: explicit Bearer and field | blocked (awaiting-evidence-review) | ready | P1 |
| `zoom:server-to-server-access-token` | B or F | existing generic path: Bearer or field, as the reviewed layout names | carrier-unresolved (carrier-source-missing) | ready | P1 |

### G2: 13 families

| Family | Layout kind (evidence-named, unreviewed) | Product disposition kind | Benchmarks inventory | Evidence handoff | Precondition |
| --- | --- | --- | --- | --- | --- |
| `adobe:oauth-user-refresh-token` | F | existing generic path: field | blocked (awaiting-evidence-review) | ready | P1 |
| `airtable:oauth-refresh-token` | C | conditional on a reviewed layout | carrier-unresolved (carrier-source-missing) | carrier-unresolved | P2: Airtable OAuth reference: token response and refresh request member names, delimiters and adjacent client_id/scope |
| `asana:oauth-refresh-token` | C | conditional on a reviewed layout | carrier-unresolved (carrier-source-missing) | carrier-unresolved | P2: Asana OAuth docs: `refresh_token` member and request form fields |
| `box:oauth-refresh-token` | C | conditional on a reviewed layout | carrier-unresolved (carrier-source-missing) | carrier-unresolved | P2: Box developer docs: `refresh_token` member and refresh request form |
| `canva:refresh-token` | F | existing generic path: field | blocked (awaiting-evidence-review) | ready | P1 |
| `dropbox:refresh-token` | C | conditional on a reviewed layout | blocked (awaiting-evidence-review) | carrier-unresolved | P2: Dropbox OAuth guide: response member name and the form body of the refresh request |
| `elastic:refresh-token` | C | conditional on a reviewed layout | carrier-unresolved (carrier-source-missing) | carrier-unresolved | P2: Elasticsearch get-token API reference: `refresh_token` response member and refresh request body |
| `figma:oauth-refresh-token` | F | existing generic path: field | blocked (awaiting-evidence-review) | ready | P1 |
| `hubspot:oauth-refresh-token` | C | conditional on a reviewed layout | carrier-unresolved (carrier-source-missing) | carrier-unresolved | P2: HubSpot OAuth docs: `refresh_token` member and the form body of the refresh request |
| `spotify:refresh-token` | F | existing generic path: field | blocked (awaiting-evidence-review) | ready | P1 |
| `x:oauth2-refresh-token` | C | conditional on a reviewed layout | carrier-unresolved (carrier-source-missing) | carrier-unresolved | P2: X OAuth 2.0 docs: refresh_token member and refresh form. The 6 month, single-use sentence is attributed to the OAuth 1.0a exchange in the claim; its scope is itself unresolved |
| `zendesk:oauth-refresh-token` | C | conditional on a reviewed layout | blocked (awaiting-evidence-review) | carrier-unresolved | P2: Zendesk OAuth docs: `refresh_token` member and refresh form fields |
| `zoom:oauth-refresh-token` | F | existing generic path: field | blocked (awaiting-evidence-review) | ready | P1 |

### G3: 12 families

| Family | Layout kind (evidence-named, unreviewed) | Product disposition kind | Benchmarks inventory | Evidence handoff | Precondition |
| --- | --- | --- | --- | --- | --- |
| `airtable:oauth-client-secret` | C | conditional on a reviewed layout | carrier-unresolved (carrier-source-missing) | carrier-unresolved | P2: Airtable OAuth reference: token request authentication form |
| `asana:oauth-client-secret` | C | conditional on a reviewed layout | carrier-unresolved (carrier-source-missing) | carrier-unresolved | P2: Asana docs: token exchange form field name |
| `box:oauth-client-secret` | C | conditional on a reviewed layout | carrier-unresolved (carrier-source-missing) | carrier-unresolved | P2: Box docs: request body field and any Basic form |
| `dropbox:app-secret` | F | existing generic path: field | blocked (awaiting-evidence-review) | ready | P1 |
| `figma:oauth-client-secret` | BA | existing generic path: Basic envelope | blocked (awaiting-evidence-review) | ready | P1 |
| `hubspot:app-client-secret` | C | conditional on a reviewed layout | carrier-unresolved (carrier-source-missing) | carrier-unresolved | P2: HubSpot OAuth docs: `client_secret` form field |
| `salesforce:external-client-app-consumer-secret` | C | conditional on a reviewed layout | carrier-unresolved (carrier-source-missing) | carrier-unresolved | P2: Salesforce docs: `client_secret` parameter and web server flow |
| `spotify:client-secret` | C | conditional on a reviewed layout | carrier-unresolved (carrier-source-missing) | carrier-unresolved | P2: Spotify authorization guide: token request header and body |
| `x:oauth2-client-secret` | BA | existing generic path: Basic envelope | blocked (awaiting-evidence-review) | ready | P1 |
| `zendesk:oauth-client-secret` | F | existing generic path: field | blocked (awaiting-evidence-review) | ready | P1 |
| `zoom:oauth-app-client-secret` | C | conditional on a reviewed layout | carrier-unresolved (carrier-source-missing) | carrier-unresolved | P2: Zoom OAuth docs: Basic header and form form |
| `zoom:server-to-server-client-secret` | C | conditional on a reviewed layout | carrier-unresolved (carrier-source-missing) | carrier-unresolved | P2: Zoom S2S docs: token request authentication form |

## Handoff

What the benchmarks side may treat as the adopted product contract:

* For any G1 to G3 row whose reviewed layout names a field or an explicit Bearer
  or Basic carrier: the span, finding type, default action and exclusions in the
  class table, as a frozen expectation to author fixtures and controls against,
  including the `warn` expectation for a low-entropy literal and the
  prefix-only expectation for a Bearer value that a percent escape ends.
* For a percent-escaped or serialized-escaped value: unsupported and
  unassertable, per the decision; not an FN, TN or pass.
* Provider attribution is never an expectation of these rows: a generic result
  is not evidence of a provider.

What stays blocked, and why: every row stays at P1 or P2 above, because no
evidence contract is reviewed and no independent baseline exists. The
carrier-unresolved rows wait for the provider source the handoff names. Exact
candidate source and digests go to benchmarks only after a gap is demonstrated
on a ready row; none is demonstrated, and none is offered here. This record
changes no pin, version or release.

## Gates of the issue

| Gate | State |
| --- | --- |
| Freeze each ready row's layout, admission, span, attribution, default action and exclusions in final product evidence and spec rows | Met at class level (this record, `docs/specs/detector-families.md` and `docs/specs/contextual-detection.md`). Per row it is conditional: no row is ready, so no row-level freeze exists. |
| Link independent baseline case ids and identities; disposition every row | Open. No baseline exists. Every row's current state is in the table, and none is yet existing coverage, a reproduced gap, an accepted policy limit or source-unresolved in the sense of the gate. |
| Repair only demonstrated in-contract leaks, spans, actions or false positives | Open, nothing demonstrated. The percent observation is an accepted, recorded limit, not a repair. |
| Deterministic conformance for changed logic | Open, no logic changed. |
| Shared parser fix once | Open, none needed so far. |
| Node/WASM, Python, Rust and CLI whole and stream behavior | Open. Only the CLI was observed, at one commit, on invented inputs. |
| Exact candidate revision and digests to benchmarks; accept independent replay | Open, conditional on a demonstrated gap. |
| Record no-code conclusions for existing coverage | Open, conditional on a baseline. |

## Tradeoffs

* The class rules are the contextual-policy tradeoff of Batch 1: a non-secret
  literal of 8 or more bytes put into an exact credential slot is redacted at
  high confidence or warned at medium; a value under the floor, on the next
  line, in an unnamed layout, encoded or escaped is a false negative, stated and
  not repaired.
* A Basic envelope hides the public client id with the secret, by construction.
* Adopting policy before a baseline means a later measurement can show a class
  rule is wrong for a row. The record then changes by a new decision, not by
  rewriting an expectation to fit output.

## Tests

None added. This is a documentation and policy record; the rules it states are
the existing, already pinned grammar (`generic_token` and `bearer_token` unit
tests, `batch1_credential_slots_1209_1213.rs`). The observations above are
pinned by this record only; a deterministic regression pin belongs with the
first row that becomes ready and shows a gap.
