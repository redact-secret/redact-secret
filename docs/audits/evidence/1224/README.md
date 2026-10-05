# Evidence: #1224, Batch 2 ApiKey, JWT and X encoded carriers

**Result:** the product contract for the four G4 rows is adopted as a
conditional policy, with the representation decision the benchmarks readiness
inventory was waiting on for `x:app-only-bearer-token`. In short: the Cloud
`ApiKey` layout reuses the Batch 1 implementation unchanged; ECE is not read as
Cloud by its name; a JFrog value that is a JWT is one `jwt` finding with the
exact JWT redacted and no JFrog attribution; and a percent-containing or escaped
X representation is unsupported and unassertable, with no alphabet broadened and
a redacted prefix never reported as full coverage. No row is claimed covered,
passing or ready, no benchmark result is stated, and no code, detector, registry
entry or type changes.

Issue [#1224](https://github.com/redact-secret/redact-secret/issues/1224)
(measurement child benchmarks
[#743](https://github.com/redact-secret/redact-secret-benchmarks/issues/743)),
Batch 2 of the credential-evidence adoption inventory
([#231](https://github.com/redact-secret/credential-evidence/issues/231), handoff
[#235](https://github.com/redact-secret/credential-evidence/issues/235)). The
class rules and the legend are in the [#1223 record](../1223/README.md); the
decision is
[`decision-keep-percent-containing-and-escaped-credential-representations-outside-the-raw-input-contract`](../../../decisions/2026-10-05-keep-percent-containing-and-escaped-credential-representations-outside-the-raw-input-contract.md).

## Sources

| Role | Source |
| --- | --- |
| Provider facts (pending inputs) | The four proposed contracts of credential-evidence#235 and the [Batch 2 handoff](https://github.com/redact-secret/credential-evidence/blob/005a7331cf90403bd4ce4abcb93bd8b085d315a9/docs/handoffs/batch-2-bounded-carriers.md) (credential-evidence#248, project-authored, not independent). For X it records the Bearer role, an unspecified byte format, and percent-containing shapes only as a scanner-corroborated lead (`artifacts-bearer-leading-run-and-percent`), not a provider-proven encoding. |
| Independent baseline | None. benchmarks#739 readiness (comment 6001345412): `elastic:cloud-api-key` blocked (awaiting evidence review), `x:app-only-bearer-token` blocked (`representation-policy-undecided`), `elastic:ece-api-key` and `jfrog:access-token` carrier-unresolved. |
| Product policy (this record) | `Authorization: ApiKey` grammar ([#1212](../1212/README.md)), the `bearer-token` grammar, the `jwt` detector, `decision-defer-encoded-input-decoding` and the representation decision above. |

## Adopted contracts

| Question | Decision |
| --- | --- |
| Cloud `ApiKey` (`elastic:cloud-api-key`) | Batch 1 is reused as is. For a reviewed layout that is `Authorization: ApiKey <value>` or `Proxy-Authorization: ApiKey <value>` (raw HTTP, quoted curl `-H`, JSON header map): `authorization_credential`, exactly the undecoded authorization-alphabet run (`[A-Za-z0-9+/=_-]`, at least 12 bytes, `=` padding included), always redacted. Not split into id and key, not decoded, no width or alphabet claim, no Elastic attribution. |
| ECE (`elastic:ece-api-key`) | Nothing is asserted: the carrier is unconfirmed. ECE is not read as the Cloud `ApiKey` because of its name or product family, and no scheme, header or vocabulary entry is added for it. If its reviewed carrier is the same `ApiKey` scheme, the existing path applies with no ECE attribution; any other carrier needs its own evidence first. |
| JFrog JWT and Bearer overlap (`jfrog:access-token`) | The carrier is unresolved. When a value is a JWT, the existing `jwt` detector and, behind an explicit Bearer header, the `bearer-token` detector see the same bytes; the contract is one final finding, exactly the JWT bytes, redacted, generic type, no exclusive attribution. A JWT is not an exclusive JFrog grammar, so no JFrog type is produced, nothing is decoded and no token is validated. A JFrog reference token that is not a JWT has no source-established representation and is unassertable. |
| X app-only Bearer, raw (`x:app-only-bearer-token`) | Where a reviewed layout names an explicit `Authorization: Bearer` carrier for the raw value: `bearer_token`, exactly the value, redacted, under the RFC 6750 alphabet with the 12-byte floor after an explicit header (16 bare). The provider states the format is unspecified, so no prefix, width or alphabet is claimed. |
| X, percent-containing or escaped | Unsupported and unassertable until a separate representation decision. The Bearer alphabet is not broadened to pass a generated example, nothing is decoded, and a case that needs it is not an FN, TN or pass. Where the grammar ends a value at `%`, the product redacts the prefix it read and the residual bytes stay in the output; that prefix is never reported as full credential coverage. See the decision for the trade-off and the reopening bar. |
| Exclusions and controls | Placeholders, references and masks (shared rules); bare `ApiKey` prose; `X-Authorization:` and `Authorization-Info:`; a newline between scheme and value; the consumer key and secret that generate an X bearer token (not this row's credential); JWTs of other providers. |
| Default action | `redact` for `authorization_credential`, `bearer_token` and `jwt` (always-redact); a user action policy overrides it as before. |

## Product observations

Product observations at core `3b1a5aa9` (CLI `0.1.0-beta.13` line, debug build of
this commit, check mode, UTF-8 byte ranges), small synthetic inputs, values
invented and not shown. Not benchmark results and not coverage claims.

| Input (synthetic) | Observed finding |
| --- | --- |
| `GET /x HTTP/1.1`, then `Authorization: ApiKey <47 bytes, ends in ==>` | one `authorization_credential`, high, redact, over the whole 47 bytes including `==` (38-85) |
| `Authorization: Bearer <JWT: 20 + 27 + 34 bytes, two dots>` | one `jwt` finding, high, redact, over the whole JWT (22-105); no separate `bearer_token` and no provider type |
| `jfrog token: <the same JWT>` (no Bearer header) | one `jwt` finding, high, redact, over the whole JWT (13-96) |
| `Authorization: Bearer <50 alphanumeric bytes>` | `bearer_token`, high, redact, over the value (22-74) |
| `Authorization: Bearer <24>%2B<12>` | `bearer_token`, high, redact, over the 24 bytes before `%` (22-46); `%2B` and the 12-byte tail stay in the output |
| `Authorization: Bearer <42>%2B<12>%3D` | `bearer_token`, high, redact, over the 42 bytes before the first `%` (22-64); `%2B<12>%3D` stays in the output |
| `Authorization: Bearer <7>%2B<...>` | no finding (leading run under the 12-byte floor), so the whole value stays |
| `Authorization: Bearer <42>+<12>` (literal backslash-u escape) | `bearer_token` over the 42 bytes before the backslash (22-64); the escape and tail stay |

## Per-row table

Legend as in the [#1223 record](../1223/README.md#per-row-table): layout kind AK
is the ApiKey scheme; `B / X` is a raw Bearer layout in contract with the
percent-containing and escaped forms outside it; P1 and P2 are the
preconditions defined there.

### G4: 4 families

| Family | Layout kind (evidence-named, unreviewed) | Product disposition kind | Benchmarks inventory | Evidence handoff | Precondition |
| --- | --- | --- | --- | --- | --- |
| `elastic:cloud-api-key` | AK | existing generic path: ApiKey scheme (Batch 1, #1212) | blocked (awaiting-evidence-review) | ready | P1 |
| `elastic:ece-api-key` | C | conditional on a reviewed layout; not read as Cloud ApiKey by name | carrier-unresolved (carrier-source-missing) | carrier-unresolved | P2: Elastic Cloud Enterprise API reference: authentication header for the API key |
| `jfrog:access-token` | C | conditional on a reviewed layout; a JWT value is read by the existing `jwt` detector | carrier-unresolved (carrier-source-missing) | carrier-unresolved | P2: JFrog access token docs: header and `access_token` form; representation of a reference token |
| `x:app-only-bearer-token` | B / X | raw Bearer: existing generic path; percent-containing and escaped forms: out of contract | blocked (representation-policy-undecided) | ready | P1 for the raw Bearer layout only; percent-containing and escaped forms are not startable until a separate representation decision (ADR, #491 criteria) |

## Handoff

The benchmarks side may treat as adopted: for `elastic:cloud-api-key`, once its
layout is reviewed, the ApiKey expectation above; for `x:app-only-bearer-token`,
the raw Bearer expectation once reviewed, and the percent-containing and escaped
forms as unsupported (`unassertable`, never FN, TN or pass); for
`jfrog:access-token` with a JWT value, the single `jwt` finding with exact
redaction and no JFrog attribution, as a conditional expectation pending its
carrier; and for the whole row set, no ECE-as-Cloud reading. What stays
blocked: `elastic:ece-api-key` and `jfrog:access-token` wait for the provider
sources the handoff names, `elastic:cloud-api-key` and the raw X layout wait for
a reviewed contract, and every row waits for an independent baseline. A change
to the representation stance is a new decision under the reopening bar, not an
expectation edit. No candidate source or digest is offered: no gap is
demonstrated. No pin, version or release changes.

## Gates of the issue

| Gate | State |
| --- | --- |
| Freeze layout, admission, span, attribution, default action, exclusions per ready row | Met at class level (this record and the spec rows); per row conditional, no row is ready. |
| Link baseline case ids and identities; disposition every row | Open, no baseline. |
| Repair only demonstrated gaps | Open, none demonstrated. The `%` prefix behaviour is an accepted, recorded limit. |
| Deterministic conformance for changed logic | Open, no logic changed. |
| Shared parser fix once | Open, none needed so far. |
| Node/WASM, Python, Rust and CLI whole and stream behavior | Open. Only the CLI was observed, at one commit. |
| Candidate revision and digests to benchmarks; accept replay | Open, conditional on a demonstrated gap. |
| Record no-code conclusions | Open, conditional on a baseline. |

## Tradeoffs

* Not broadening the Bearer alphabet leaves a real residual: a token whose bytes
  continue with `%XX` is partly visible in the redacted output. The alternative
  widens a grammar shared by every Bearer user to fit one scanner lead for one
  provider that documents no format. The decision records this and the reopening
  bar.
* `ApiKey` and a JWT are not unique to one provider, so nothing here attributes a
  finding to Elastic, JFrog or X; a caller that needs attribution adds it from
  its own context.
* A JWT under Bearer is one `jwt` finding. A caller that expected a
  `bearer_token` type for that value sees `jwt`; the bytes redacted are the same.

## Tests

None added: documentation and policy only. The grammar is pinned by the Batch 1
`apikey_*` tests and the `bearer-token` and `jwt` tests. The observations above
are pinned by this record only.
