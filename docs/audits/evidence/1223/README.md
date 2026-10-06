# Evidence: #1223, Batch 2 OAuth, Bearer and Basic credential paths

**Result:** the class contract for the 48 G1 to G3 rows, adopted in PR #1231 as a
conditional policy, was tested by the independent benchmarks#739 round 2 against
the published `0.1.0-beta.13` and the candidate `a148dadf`. 34 rows are existing
coverage validated by the benchmark (no code). 14 rows (G1 1, G2 6, G3 7) each
reproduced one gap, the same one: an empty form value followed by `&name=` took
the next parameter as its value (a medium `warn` over `&other=1`). One shared
parser fix, [#1232](../1232/README.md), is in this change, and the other
positives and controls of those 14 rows passed. A percent-containing or escaped
representation stays an accepted policy limit, observed and not scored
(`decision-keep-percent-containing-and-escaped-credential-representations-outside-the-raw-input-contract`).
No detector, registry entry, vocabulary name or type changes beyond that fix, and
no row is claimed covered beyond what the benchmark ledger measured. The
independent replay of the fixed candidate is open.

Issue [#1223](https://github.com/redact-secret/redact-secret/issues/1223)
(measurement children benchmarks
[#740](https://github.com/redact-secret/redact-secret-benchmarks/issues/740),
[#741](https://github.com/redact-secret/redact-secret-benchmarks/issues/741) and
[#742](https://github.com/redact-secret/redact-secret-benchmarks/issues/742)),
Batch 2 of the credential-evidence adoption inventory
([#231](https://github.com/redact-secret/credential-evidence/issues/231), handoff
[#235](https://github.com/redact-secret/credential-evidence/issues/235)). Sibling
records: #1224, #1225 and #1226 under `docs/audits/evidence/`.

## Why this was a contract first and not a measurement

*State when the contract was adopted, kept for the record; the measurement that followed is under "Independent measurement and dispositions" below.*

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
| Independent baseline and replay | benchmarks#739: [round-1 report](https://github.com/redact-secret/redact-secret-benchmarks/blob/fe7a5d1acd8ba56e4f1c537117f78a944369a9c6/evidence/739/report.md), [round-2 report](https://github.com/redact-secret/redact-secret-benchmarks/blob/fe7a5d1acd8ba56e4f1c537117f78a944369a9c6/evidence/739/round2/report.md) and [ledger](https://github.com/redact-secret/redact-secret-benchmarks/blob/fe7a5d1acd8ba56e4f1c537117f78a944369a9c6/evidence/739/ledger.json) at merge `fe7a5d1a` of PR #761 (readiness at merge `6a1a7a64` of PR #755). Identities and the local replay of this change are under "Independent measurement and dispositions". |
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

## Independent measurement and dispositions

**Independent measurement.** benchmarks
[#739](https://github.com/redact-secret/redact-secret-benchmarks/issues/739)
measured all 58 rows in two rounds (PRs
[#755](https://github.com/redact-secret/redact-secret-benchmarks/pull/755) and
[#761](https://github.com/redact-secret/redact-secret-benchmarks/pull/761), both
merged; permalinks at their merge commits `6a1a7a64` and `fe7a5d1a`): the
[readiness inventory](https://github.com/redact-secret/redact-secret-benchmarks/blob/fe7a5d1acd8ba56e4f1c537117f78a944369a9c6/evidence/739/readiness.md) (first version at merge `6a1a7a64` of PR #755), the [round-1 report](https://github.com/redact-secret/redact-secret-benchmarks/blob/fe7a5d1acd8ba56e4f1c537117f78a944369a9c6/evidence/739/report.md), the [round-2 report](https://github.com/redact-secret/redact-secret-benchmarks/blob/fe7a5d1acd8ba56e4f1c537117f78a944369a9c6/evidence/739/round2/report.md) and the [ledger](https://github.com/redact-secret/redact-secret-benchmarks/blob/fe7a5d1acd8ba56e4f1c537117f78a944369a9c6/evidence/739/ledger.json) (58 rows, schema 4). Frozen round-2
corpus sha256 `a312308a141e3157c859f62e53c5e0762ca91c2e0083d0e02497848ebee8b921`
(1935 cases; first freeze `8e447629`, three documented errata before the
re-measurement; round 1's corpus `74fed382`, 486 cases, 30 rows, is separate).
Case ids are `<family>:r2:<layout>:<kind>` in `benchmarks/batch2/corpus-r2.mjs`
(round 1: `<family>:<layout>:<kind>` in `corpus.mjs`) and are listed per row in the
ledger. Expectations were authored from credential-evidence `65602481` and the
adopted contract (PR #1231), frozen before any scan, and were not edited.

**Identities.** Published: `@redact-secret/core`, `@redact-secret/wasm` and the
darwin-arm64 addon `0.1.0-beta.13` from npm (core integrity
`sha512-qZkqRN7CIJ+pc0IteRCXSucr1l9KtTc/nJaM5wPL0NvCiZ4AGWLCyrLy8KD95a2MBgxo8vuUJ/UaKhrny7gMJQ==`),
PyPI `redact-secret` `0.1.0b13`, crates.io `redact-secret-cli` `0.1.0-beta.13`.
Candidate: the unpublished commit `a148dadf4a43b5441ed88386d055428b2e278f25`
(core main after PR #1231, no candidate package published). Surfaces: Node, WASM,
Python and the CLI (the Rust surface; no separate Rust harness), whole and
streamed at 7-byte and 1-byte chunks, darwin-arm64, Node v22.16.0; the four
surfaces agreed on every case and stream equalled whole. Peers were not run. The
fixed candidate is **not** an identity the benchmark has measured: this change
was replayed locally on the CLI surface only (see the #1223 record).

**Result by group (candidate `a148dadf`; published identical).** G1 (23 rows):
22 existing coverage, 1 gap (#1232, `meta:user-access-token`). G2 (13): 7
existing coverage, 6 gaps (#1232). G3 (12): 5 existing coverage, 7 gaps (#1232).
Every gap is a control (`<family>:r2:<name>-form-empty-null:control`); none of
the 48 rows has a positive failing and no other control was flagged. Rows that were
`carrier-unresolved` or blocked when the contract was adopted are now `ready` per
credential-evidence `65602481` (all 58 are).

**Disposition legend.** *Existing coverage, validated by the benchmark: no
code* means the row's in-contract positives and controls passed on the published
baseline and on the candidate on every surface and stream, and the record
changes nothing for it. *Reproduced gap, fixed by this PR* names the issue.
*Batch 1 fix reused* means the row fails on the published baseline and passes on
the candidate through an earlier core fix. *Accepted policy limit* and
*source-unresolved / unmeasured* are never counted as a miss, a clean result or
coverage. Variants the contract leaves unassertable (prefixed or upper-case
names, single quotes, lower-case schemes, percent values, legacy layouts) are
observed and not scored in every row. A row is not claimed covered beyond what the
ledger measured.

**Local replay of this change (CLI surface only).** The benchmark's own runner
(`scripts/measure-batch1.mjs --corpus benchmarks/batch2/corpus-r2.mjs --cli
<release build of this branch>`, 7-byte and 1-byte chunks) and scorer
(`score-r2.mjs`) were run at the merge `fe7a5d1a` of benchmarks PR #761 over all
1935 cases, whole and streamed. Result: 0 positives failing and 0 controls
flagged on every row (the candidate `a148dadf` had 8 positive cases and 16 control
cases failing). Against the
candidate's CLI observations exactly 25 cases differ: the 15 empty-form-value
controls of #1232 (now clean), the 8 HubSpot positives of #1233 (now exact), the
mongodb-atlas placeholder control of #1234 (now clean), and the unscored
`personalAccessKey-legacy-portals` observation (no finding before, a finding now:
the name is read wherever it appears; the legacy layout stays unresolved and
unasserted). Nothing else changed. This is a local diagnostic, not the
benchmark's measurement: Node, WASM and Python were not replayed with the fixed
candidate.

### G1: 23 families

| Family | Carrier layout (evidence-named, benchmark slots) | Cases r2: pos / ctl / unscored | Candidate `a148dadf` (published beta.13) | Disposition |
| --- | --- | --- | --- | --- |
| `adobe:oauth-server-to-server-access-token` | JSON/YAML member `access_token` | 14 / 8 / 6 (+ 15 round-1) | pos 0 fail, ctl 0 flagged (published: 0, 0) | Existing coverage, validated by the benchmark: no code. |
| `airtable:oauth-access-token` | explicit Bearer header | 15 / 7 / 5 (+ 17 round-1) | pos 0 fail, ctl 0 flagged (published: 0, 0) | Existing coverage, validated by the benchmark: no code. |
| `asana:oauth-access-token` | JSON/YAML member `access_token`; explicit Bearer header | 29 / 15 / 11 | pos 0 fail, ctl 0 flagged (published: 0, 0) | Existing coverage, validated by the benchmark: no code. |
| `asana:personal-access-token` | explicit Bearer header | 15 / 7 / 5 (+ 17 round-1) | pos 0 fail, ctl 0 flagged (published: 0, 0) | Existing coverage, validated by the benchmark: no code. |
| `box:oauth-access-token` | JSON/YAML member `access_token`; explicit Bearer header | 29 / 15 / 11 | pos 0 fail, ctl 0 flagged (published: 0, 0) | Existing coverage, validated by the benchmark: no code. |
| `canva:access-token` | JSON/YAML member `access_token` | 14 / 8 / 6 (+ 15 round-1) | pos 0 fail, ctl 0 flagged (published: 0, 0) | Existing coverage, validated by the benchmark: no code. |
| `contentful:oauth-application-access-token` | URL fragment parameter `access_token` | 8 / 4 / 2 | pos 0 fail, ctl 0 flagged (published: 0, 0) | Existing coverage, validated by the benchmark: no code. |
| `elastic:access-token` | explicit Bearer header | 15 / 7 / 5 (+ 17 round-1) | pos 0 fail, ctl 0 flagged (published: 0, 0) | Existing coverage, validated by the benchmark: no code. |
| `elastic:service-account-token` | explicit Bearer header | 15 / 7 / 5 (+ 17 round-1) | pos 0 fail, ctl 0 flagged (published: 0, 0) | Existing coverage, validated by the benchmark: no code. |
| `figma:oauth-access-token` | JSON/YAML member `access_token`; explicit Bearer header | 29 / 15 / 11 (+ 32 round-1) | pos 0 fail, ctl 0 flagged (published: 0, 0) | Existing coverage, validated by the benchmark: no code. |
| `figma:scim-api-token` | explicit Bearer header | 15 / 7 / 5 (+ 17 round-1) | pos 0 fail, ctl 0 flagged (published: 0, 0) | Existing coverage, validated by the benchmark: no code. |
| `hubspot:oauth-access-token` | explicit Bearer header | 15 / 7 / 5 (+ 17 round-1) | pos 0 fail, ctl 0 flagged (published: 0, 0) | Existing coverage, validated by the benchmark: no code. |
| `hubspot:service-key` | explicit Bearer header | 15 / 7 / 5 (+ 17 round-1) | pos 0 fail, ctl 0 flagged (published: 0, 0) | Existing coverage, validated by the benchmark: no code. |
| `meta:instagram-user-access-token` | JSON/YAML member `access_token` | 14 / 8 / 6 | pos 0 fail, ctl 0 flagged (published: 0, 0) | Existing coverage, validated by the benchmark: no code. |
| `meta:page-access-token` | JSON/YAML member `access_token` | 14 / 8 / 6 | pos 0 fail, ctl 0 flagged (published: 0, 0) | Existing coverage, validated by the benchmark: no code. |
| `meta:system-user-access-token` | JSON/YAML member `access_token` | 14 / 8 / 6 | pos 0 fail, ctl 0 flagged (published: 0, 0) | Existing coverage, validated by the benchmark: no code. |
| `meta:user-access-token` | assignment / form field `access_token`; JSON/YAML member `access_token` | 28 / 16 / 10 | pos 0 fail, ctl 1 flagged (published: 0, 1) | Reproduced gap (empty-form-value control), fixed by this PR (#1232); other cases covered. |
| `mongodb-atlas:service-account-access-token` | explicit Bearer header | 15 / 7 / 5 (+ 17 round-1) | pos 0 fail, ctl 0 flagged (published: 0, 0) | Existing coverage, validated by the benchmark: no code. |
| `salesforce:oauth-access-token` | JSON/YAML member `access_token`; explicit Bearer header | 29 / 15 / 11 | pos 0 fail, ctl 0 flagged (published: 0, 0) | Existing coverage, validated by the benchmark: no code. |
| `spotify:access-token` | explicit Bearer header | 15 / 7 / 5 (+ 17 round-1) | pos 0 fail, ctl 0 flagged (published: 0, 0) | Existing coverage, validated by the benchmark: no code. |
| `x:oauth2-user-access-token` | explicit Bearer header | 15 / 7 / 5 (+ 17 round-1) | pos 0 fail, ctl 0 flagged (published: 0, 0) | Existing coverage, validated by the benchmark: no code. |
| `zendesk:oauth-access-token` | explicit Bearer header | 15 / 7 / 5 (+ 17 round-1) | pos 0 fail, ctl 0 flagged (published: 0, 0) | Existing coverage, validated by the benchmark: no code. |
| `zoom:server-to-server-access-token` | explicit Bearer header | 15 / 7 / 5 (+ 17 round-1) | pos 0 fail, ctl 0 flagged (published: 0, 0) | Existing coverage, validated by the benchmark: no code. |

### G2: 13 families

| Family | Carrier layout (evidence-named, benchmark slots) | Cases r2: pos / ctl / unscored | Candidate `a148dadf` (published beta.13) | Disposition |
| --- | --- | --- | --- | --- |
| `adobe:oauth-user-refresh-token` | JSON/YAML member `refresh_token` | 14 / 8 / 6 (+ 15 round-1) | pos 0 fail, ctl 0 flagged (published: 0, 0) | Existing coverage, validated by the benchmark: no code. |
| `airtable:oauth-refresh-token` | JSON/YAML member `refresh_token`; assignment / form field `refresh_token` | 28 / 16 / 10 | pos 0 fail, ctl 1 flagged (published: 0, 1) | Reproduced gap (empty-form-value control), fixed by this PR (#1232); other cases covered. |
| `asana:oauth-refresh-token` | JSON/YAML member `refresh_token`; assignment / form field `refresh_token` | 28 / 16 / 10 | pos 0 fail, ctl 1 flagged (published: 0, 1) | Reproduced gap (empty-form-value control), fixed by this PR (#1232); other cases covered. |
| `box:oauth-refresh-token` | JSON/YAML member `refresh_token`; assignment / form field `refresh_token` | 28 / 16 / 10 | pos 0 fail, ctl 1 flagged (published: 0, 1) | Reproduced gap (empty-form-value control), fixed by this PR (#1232); other cases covered. |
| `canva:refresh-token` | JSON/YAML member `refresh_token` | 14 / 8 / 6 (+ 15 round-1) | pos 0 fail, ctl 0 flagged (published: 0, 0) | Existing coverage, validated by the benchmark: no code. |
| `dropbox:refresh-token` | JSON/YAML member `refresh_token`; assignment / form field `refresh_token` | 28 / 16 / 10 | pos 0 fail, ctl 1 flagged (published: 0, 1) | Reproduced gap (empty-form-value control), fixed by this PR (#1232); other cases covered. |
| `elastic:refresh-token` | JSON/YAML member `refresh_token` | 14 / 8 / 6 | pos 0 fail, ctl 0 flagged (published: 0, 0) | Existing coverage, validated by the benchmark: no code. |
| `figma:oauth-refresh-token` | JSON/YAML member `refresh_token` | 14 / 8 / 6 (+ 15 round-1) | pos 0 fail, ctl 0 flagged (published: 0, 0) | Existing coverage, validated by the benchmark: no code. |
| `hubspot:oauth-refresh-token` | JSON/YAML member `refresh_token`; assignment / form field `refresh_token` | 28 / 16 / 10 | pos 0 fail, ctl 1 flagged (published: 0, 1) | Reproduced gap (empty-form-value control), fixed by this PR (#1232); other cases covered. |
| `spotify:refresh-token` | JSON/YAML member `refresh_token` | 14 / 8 / 6 (+ 15 round-1) | pos 0 fail, ctl 0 flagged (published: 0, 0) | Existing coverage, validated by the benchmark: no code. |
| `x:oauth2-refresh-token` | assignment / form field `refresh_token`; JSON/YAML member `refresh_token` | 28 / 16 / 10 | pos 0 fail, ctl 1 flagged (published: 0, 1) | Reproduced gap (empty-form-value control), fixed by this PR (#1232); other cases covered. |
| `zendesk:oauth-refresh-token` | JSON/YAML member `refresh_token` | 14 / 8 / 6 | pos 0 fail, ctl 0 flagged (published: 0, 0) | Existing coverage, validated by the benchmark: no code. |
| `zoom:oauth-refresh-token` | JSON/YAML member `refresh_token` | 14 / 8 / 6 (+ 15 round-1) | pos 0 fail, ctl 0 flagged (published: 0, 0) | Existing coverage, validated by the benchmark: no code. |

### G3: 12 families

| Family | Carrier layout (evidence-named, benchmark slots) | Cases r2: pos / ctl / unscored | Candidate `a148dadf` (published beta.13) | Disposition |
| --- | --- | --- | --- | --- |
| `airtable:oauth-client-secret` | Basic envelope | 10 / 7 / 4 | pos 0 fail, ctl 0 flagged (published: 0, 0) | Existing coverage, validated by the benchmark: no code. |
| `asana:oauth-client-secret` | assignment / form field `client_secret` | 14 / 8 / 4 | pos 0 fail, ctl 1 flagged (published: 0, 1) | Reproduced gap (empty-form-value control), fixed by this PR (#1232); other cases covered. |
| `box:oauth-client-secret` | assignment / form field `client_secret` | 14 / 8 / 4 | pos 0 fail, ctl 1 flagged (published: 0, 1) | Reproduced gap (empty-form-value control), fixed by this PR (#1232); other cases covered. |
| `dropbox:app-secret` | assignment / form field `client_secret`; JSON/YAML member `client_secret` | 28 / 16 / 10 (+ 17 round-1) | pos 0 fail, ctl 1 flagged (published: 0, 1) | Reproduced gap (empty-form-value control), fixed by this PR (#1232); other cases covered. |
| `figma:oauth-client-secret` | Basic envelope | 10 / 7 / 4 (+ 14 round-1) | pos 0 fail, ctl 0 flagged (published: 0, 0) | Existing coverage, validated by the benchmark: no code. |
| `hubspot:app-client-secret` | assignment / form field `client_secret` | 14 / 8 / 4 | pos 0 fail, ctl 1 flagged (published: 0, 1) | Reproduced gap (empty-form-value control), fixed by this PR (#1232); other cases covered. |
| `salesforce:external-client-app-consumer-secret` | assignment / form field `client_secret`; Basic envelope | 24 / 15 / 8 | pos 0 fail, ctl 1 flagged (published: 0, 1) | Reproduced gap (empty-form-value control), fixed by this PR (#1232); other cases covered. |
| `spotify:client-secret` | Basic envelope | 10 / 7 / 4 | pos 0 fail, ctl 0 flagged (published: 0, 0) | Existing coverage, validated by the benchmark: no code. |
| `x:oauth2-client-secret` | Basic envelope | 10 / 7 / 4 (+ 14 round-1) | pos 0 fail, ctl 0 flagged (published: 0, 0) | Existing coverage, validated by the benchmark: no code. |
| `zendesk:oauth-client-secret` | assignment / form field `client_secret`; JSON/YAML member `client_secret` | 28 / 16 / 10 (+ 16 round-1) | pos 0 fail, ctl 1 flagged (published: 0, 1) | Reproduced gap (empty-form-value control), fixed by this PR (#1232); other cases covered. |
| `zoom:oauth-app-client-secret` | Basic envelope; assignment / form field `client_secret` | 24 / 15 / 8 | pos 0 fail, ctl 1 flagged (published: 0, 1) | Reproduced gap (empty-form-value control), fixed by this PR (#1232); other cases covered. |
| `zoom:server-to-server-client-secret` | Basic envelope | 10 / 7 / 4 | pos 0 fail, ctl 0 flagged (published: 0, 0) | Existing coverage, validated by the benchmark: no code. |

## Handoff

What the benchmarks side may now treat as final for the 48 rows: the class
contract of this record as the product expectation, validated by the
measurement for the 34 existing-coverage rows; the 14 `form-empty-null` controls
as an expectation that holds after #1232 (no finding for an empty value before
`&name=`); percent-containing and escaped values as unsupported and unassertable
(never an FN, TN or pass); and provider attribution never an expectation.

**What the benchmarks side replays (open).** Build the merge commit of this
change (the maintainer names it; not chosen here) as the fixed candidate (`npm
ci`, `npm run js:build`, the napi addon, `npm run wasm:build`, `npm pack` of core,
addon and wasm, `maturin develop --release`, `cargo build --release --locked -p
redact-secret-cli`), then run the round-2 corpus `a312308a...` (all 1935 cases) on
Node, WASM, Python and the CLI, whole and at 7-byte and 1-byte chunks, with
`scripts/measure-batch1.mjs` and `scripts/report-batch2-r2.mjs`, and the Batch 1
and round-1 corpora for regression. Expected: 0 positives failing and 0 controls
flagged on all 58 rows; observations identical to `a148dadf` except the 25 cases
listed above; stream equal to whole; the four surfaces identical.

No pin, version or release changes; this record chooses none.

## Gates of the issue

| Gate | State |
| --- | --- |
| Freeze each ready row's layout, admission, span, attribution, default action and exclusions in final product evidence and spec rows | Met. The class contract and spec rows are adopted (PR #1231) and the independent measurement tested them per row; the evidence contracts of credential-evidence remain proposed or draft, which is that repository's state, not a product gap. |
| Link independent baseline case ids and identities; disposition every row | Met. Identities and permalinks are above and every row has its disposition in the per-row table, with case ids in the ledger and the corpus. |
| Repair only demonstrated in-contract leaks, spans, actions or false positives | Met. One defect class was demonstrated (an empty value read as the next parameter, 15 cases including `x:oauth1-access-token-secret`) and repaired by [#1232](../1232/README.md); nothing else changed. The percent behaviour is an accepted, recorded limit, not a repair. |
| Deterministic conformance for changed logic | Met. `tests/batch2_gaps_1232_1234.rs` (empty value at every delimiter, a credential in the next parameter, real values unchanged, whole, every two-chunk byte partition and per-line parity). |
| Shared parser fix once | Met. One change in the shared unquoted-value scan covers all 15 families and all four name groups. |
| Node/WASM, Python, Rust and CLI whole and stream behavior | Partly. Baseline and candidate `a148dadf` were measured by the benchmark on all four surfaces, whole and 7-byte and 1-byte streamed, identical. For this change: the Rust core under whole input, every two-chunk UTF-8 byte partition and per-line sessions (`tests/batch2_gaps_1232_1234.rs`), and the CLI replay above. Open: Node, WASM and Python with the fixed candidate, which share the Rust core and are the benchmark replay. |
| Exact candidate revision and digests to benchmarks; accept independent replay | Open. The fixed candidate does not exist as a measured identity until the change is merged and built; what to replay is stated above. Offered: the merge commit and the build recipe of the benchmark README, no pin, version or release change. |
| Record no-code conclusions for existing coverage | Met for the 34 rows marked existing coverage above, as the benchmark ledger measured them (G1 22, G2 7, G3 5). The 14 gap rows are not no-code rows for their `form-empty-null` control; their other cases are existing coverage. |

## Tradeoffs

* The class rules are the contextual-policy tradeoff of Batch 1: a non-secret
  literal of 8 or more bytes put into an exact credential slot is redacted at
  high confidence or warned at medium; a value under the floor, on the next
  line, in an unnamed layout, encoded or escaped is a false negative, stated and
  not repaired.
* A Basic envelope hides the public client id with the secret, by construction.
* The #1232 fix removes a `warn` over a public parameter at the cost of one edge:
  a real password whose own first bytes read as `&name=` is no longer reported as
  that one value ([#1232](../1232/README.md#boundary-and-tradeoffs)).
* The measurement did not show a class rule wrong for any row. Adopting policy before a baseline means a later measurement can. The record then changes by a new decision, not by
  rewriting an expectation to fit output.

## Tests

`crates/secret-scan-core/tests/batch2_gaps_1232_1234.rs` pins the #1232 fix (see
[#1232](../1232/README.md#tests)); the class rules of this record are the existing
grammar pinned by the `generic_token` and `bearer_token` unit tests and
`batch1_credential_slots_1209_1213.rs`. The product observations above are pinned
by this record only. The independent measurement is the benchmarks side's, with
its own corpus and scorer.


## Final state at 4e004108 / replay accepted (2026-10-06)

Addendum. The text above is kept as written when the contract was adopted and
measured; the statements listed here no longer hold, and this section is the
current state. The other Batch 2 records ([#1224](../1224/README.md),
[#1225](../1225/README.md), [#1226](../1226/README.md),
[#1232](../1232/README.md), [#1233](../1233/README.md),
[#1234](../1234/README.md)) carry the same replay facts for their rows, and
[#1241](../1241/README.md) records the `oauth_token` decision.

### The accepted replay

benchmarks [#771](https://github.com/redact-secret/redact-secret-benchmarks/pull/771)
(merged 2026-10-06, merge commit
`74c88531f7f185e687eabe6477fff5b06f54e2e9`, the round-3 step of
[benchmarks#739](https://github.com/redact-secret/redact-secret-benchmarks/issues/739))
replayed the exact candidate **`4e0041081aad22d0101bd52db52017b67b5bd3db`**
(core main after PR #1235, which carries #1232, #1233 and #1234; declared
`0.1.0-beta.13`, not released) on Node, WASM, Python and the CLI, whole and
streamed at 7-byte and 1-byte chunks (darwin-arm64, Node v22.16.0; peers not
run). The corpora were frozen and not edited: round 2
`sha256:a312308a141e3157c859f62e53c5e0762ca91c2e0083d0e02497848ebee8b921`
(1935 cases), round 1
`sha256:74fed38245503b63d55247f0da2da8e27a271de5467b3b06146ebef0c4f7a4f1`
(486 cases) and Batch 1
`sha256:ddd709174816443e2234594f040d0dae27e3b78b5dce68f2396296bffde8708c`
(82 cases). Sources, at the merge commit:
[round-3 report](https://github.com/redact-secret/redact-secret-benchmarks/blob/74c88531f7f185e687eabe6477fff5b06f54e2e9/evidence/739/round3/report.md)
and [ledger](https://github.com/redact-secret/redact-secret-benchmarks/blob/74c88531f7f185e687eabe6477fff5b06f54e2e9/evidence/739/ledger.json)
(schema 5, 58 rows, `candidateRound3` identity `4e004108`).

| Corpus / run | Positives passing | Controls clean | Whole equals stream | Four surfaces identical |
| --- | ---: | ---: | ---: | ---: |
| round 2, `4e004108`, 7-byte chunks | 1010 / 1010 | 555 / 555 | 7740 / 7740 | 1935 / 1935 |
| round 2, `4e004108`, 1-byte chunks | 1010 / 1010 | 555 / 555 | 7740 / 7740 | 1935 / 1935 |
| round 2, previous candidate `a148dadf` (round 2) | 1002 / 1010 | 539 / 555 | 7740 / 7740 | 1935 / 1935 |
| round 1, `4e004108`, 7-byte and 1-byte chunks | 200 / 200 | 203 / 203 | 1944 / 1944 | 486 / 486 |

Batch 1 controls (82 cases, 656 entries): 0 differences against the accepted
`af1e71e0` observations at both chunk sizes. Against `a148dadf` exactly 25 cases
differ (15 empty-form-value controls, 8 HubSpot positives, 1 Atlas placeholder
control, 1 unscored HubSpot legacy-layout observation); there are 0 regressions
and 0 cases still failing or flagged. This is a local replay on one host and does
not replace a linux-x64 official run; nothing in it repins, promotes support or
releases.

### Statements superseded by the accepted replay

| Earlier statement (in this record) | State now |
| --- | --- |
| "The independent replay of the fixed candidate is open" (Result, Handoff "What the benchmarks side replays (open)") | Done and accepted: benchmarks #771, candidate `4e004108`, four surfaces, whole and 1-byte and 7-byte streams. The expected result stated in the Handoff (0 failing, 0 flagged, 25 differing cases, stream equals whole, surfaces identical) is the result the replay reports. |
| "The fixed candidate is **not** an identity the benchmark has measured" (Identities) | It is: `4e0041081aad22d0101bd52db52017b67b5bd3db` is the measured candidate identity of round 3. |
| "Node, WASM and Python were not replayed with the fixed candidate" (Local replay) | They were, by the benchmark. The local CLI-only replay above is superseded by the benchmark's own. |
| Gates "Node/WASM, Python, Rust and CLI whole and stream behavior: Partly" and "Exact candidate revision and digests to benchmarks; accept independent replay: Open" | Met, see the gate table below. |
| "the declarative overlay work of #1216 to #1222 when it lands" (Rules for all classes) | Shipped. A user action policy is a versioned declarative document loaded with the CLI `--action-policy` and compared with `--compare-action-policy`; the rows are in [`docs/specs/engine.md`](../../../specs/engine.md) and the decisions [`decision-define-the-versioned-declarative-action-policy-and-default-overlay`](../../../decisions/2026-10-06-define-the-versioned-declarative-action-policy-and-default-overlay.md) and [`decision-explain-and-compare-action-policies-over-one-detection-pass`](../../../decisions/2026-10-06-explain-and-compare-action-policies-over-one-detection-pass.md). The contract above still states defaults only. |

### Dispositions of the 48 rows, as the ledger now records them

Ledger counts for all 58 Batch 2 rows (the package records split them): 38
`already-covered / no-code`, 17 `fixed by candidate 4e004108, replay verified on
Node, WASM, Python and CLI (whole, 7-byte and 1-byte streams)`, 2 `fixed in
candidate by an existing core fix (no new gap)` (the two Elastic rows of
[#1224](../1224/README.md)) and 1 `contract-evidence conflict` (the Atlas API
private key of [#1226](../1226/README.md)). The ledger's own label for the last
one is a conflict between the evidence's `ready` mark and the contract, not a
carrier gap.

For this record's 48 rows (G1 23, G2 13, G3 12): 34 stay `already-covered /
no-code` (G1 22, G2 7, G3 5), and the 14 rows that reproduced one gap each are
now `fixed by candidate 4e004108, replay verified`, with 0 failing and 0 flagged
cases on every surface and stream. The gap in each is the control
`<family>:r2:<name>-form-empty-null:control`, fixed by [#1232](../1232/README.md):

| Group | Rows (14) |
| --- | --- |
| G1 | `meta:user-access-token` |
| G2 | `airtable:oauth-refresh-token`, `asana:oauth-refresh-token`, `box:oauth-refresh-token`, `dropbox:refresh-token`, `hubspot:oauth-refresh-token`, `x:oauth2-refresh-token` |
| G3 | `asana:oauth-client-secret`, `box:oauth-client-secret`, `dropbox:app-secret`, `hubspot:app-client-secret`, `salesforce:external-client-app-consumer-secret`, `zendesk:oauth-client-secret`, `zoom:oauth-app-client-secret` |

The 15th case of #1232, `x:oauth1-access-token-secret`, is a G5 row counted in
[#1225](../1225/README.md). The per-row tables above stay as the record of the
measurement on `a148dadf`; the case ids are in the ledger. The accepted
trade-off of #1232 was checked by the replay: the frozen corpora contain no
positive whose expected value starts with `&` (round 2 0, round 1 0, Batch 1 0),
and the 15 round-2 cases with an assignment followed directly by `&name=` are
exactly the 15 empty-value controls.

### Gates of the issue at `4e004108`

| Gate | State |
| --- | --- |
| Freeze each ready row's layout, admission, span, attribution, default action and exclusions in final product evidence and spec rows | Met (unchanged). |
| Link independent baseline case ids and identities; disposition every row | Met, now with the replay identity and the final dispositions above. |
| Repair only demonstrated in-contract leaks, spans, actions or false positives | Met (unchanged): one defect class, repaired once by #1232 and verified fixed by the replay. |
| Deterministic conformance for changed logic | Met (unchanged). |
| Shared parser fix once | Met (unchanged). |
| Node/WASM, Python, Rust and CLI whole and stream behavior | **Met.** The benchmark replayed `4e004108` on Node, WASM, Python and the CLI (the Rust surface; no separate Rust harness), whole and 7-byte and 1-byte streamed; stream equals whole on every entry and the four surfaces are identical on every case. |
| Exact candidate revision and digests to benchmarks; accept independent replay | **Met.** Candidate `4e0041081aad22d0101bd52db52017b67b5bd3db`, corpus digests above, accepted as benchmarks #771 (merge `74c88531`). No package digest is claimed: no candidate package was published for the replay. |
| Record no-code conclusions for existing coverage | Met (unchanged): 34 rows. |

### Not verified here

The replay figures above are read from the merged round-3 report and ledger. The
harness and corpora were not re-run for this addendum; the report and the ledger
are the benchmarks side's records.

## Closure statement (2026-10-06)

What this issue can honestly claim after the Groups C, D and E measurement rounds.

This issue may cite only the aggregate of the measurement. On the three corpora
(2,281 cases; four surfaces; whole, 7-byte and 1-byte) the final candidate has 0
regressions against the beta.13 baseline, round 1 and round 2, 0 parity
divergences and 0 open product gaps; positives 839 (726 exact, 762 fully covered,
77 misses), controls 779 (6 flagged). The 113 positives that are not exact are 77
policy-limited misses plus 36 fully covered over-wide Meta pipe findings. The 43
rows end as 16 fully covered, 5 covered with a recorded deviation, 6
policy-limited and 16 carrier unresolved (observed only). Carrier-unresolved and
policy-limited rows are not covered, and no row is promoted by this statement.

The closeout also added tracked policies that these records do not claim as covered:
the `curl -u` password slot ([redact-secret#1247](https://github.com/redact-secret/redact-secret/issues/1247)), the JFrog `AKCp` bare
reader, deferred ([redact-secret#1248](https://github.com/redact-secret/redact-secret/issues/1248)), the bare `token` member
([redact-secret#1256](https://github.com/redact-secret/redact-secret/issues/1256), rule [#1241](../1241/README.md)), the existing Case
contradictions ([credential-evidence#264](https://github.com/redact-secret/credential-evidence/issues/264)) and the percent-escaped X layout
confirmation ([credential-evidence#265](https://github.com/redact-secret/credential-evidence/issues/265)).

Source: the [round-3 report of Groups C, D and E](https://github.com/redact-secret/redact-secret-benchmarks/blob/c1837c240a9eb4ec43bfa6abc6e2e3d7f34c7291/evidence/groups-cde/round3/report.md) (section 7, [dispositions](https://github.com/redact-secret/redact-secret-benchmarks/blob/c1837c240a9eb4ec43bfa6abc6e2e3d7f34c7291/evidence/groups-cde/round3/report.md#6-final-disposition-of-all-43-rows)),
its [scores](https://github.com/redact-secret/redact-secret-benchmarks/blob/c1837c240a9eb4ec43bfa6abc6e2e3d7f34c7291/evidence/groups-cde/round3/scores.json) and
[identity](https://github.com/redact-secret/redact-secret-benchmarks/blob/c1837c240a9eb4ec43bfa6abc6e2e3d7f34c7291/evidence/groups-cde/round3/identity.json), at benchmarks commit
`c1837c240a9eb4ec43bfa6abc6e2e3d7f34c7291`, measuring candidate
`c6dd685974b8df6a84514e07e41e35afa711a2ac` (unpublished, 0.1.0-beta.14) on one
host. Project-authored, maintainer-only evidence, not independent validation;
the fixes target measured failures and no generalisation is claimed.
