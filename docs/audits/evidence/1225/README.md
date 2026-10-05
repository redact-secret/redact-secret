# Evidence: #1225, Batch 2 HubSpot CLI, MyJFrog and OAuth1 secret slots

**Result:** the product contract for the three G5 rows is adopted as a
conditional policy. OAuth 1.0a `oauth_token_secret` is the secret half and is
read by the existing field grammar; the signature outputs and the consumer
identity are not. The HubSpot CLI configuration field and the MyJFrog carrier
are unconfirmed, so no field name is invented and no vocabulary entry is added:
the only admissible addition once the evidence names a field is one tightly
bounded, documented whole-name entry. No row is claimed covered, passing or
ready, no benchmark result is stated, and no code, detector, registry entry or
type changes.

Issue [#1225](https://github.com/redact-secret/redact-secret/issues/1225)
(measurement child benchmarks
[#744](https://github.com/redact-secret/redact-secret-benchmarks/issues/744)),
Batch 2 of the credential-evidence adoption inventory
([#231](https://github.com/redact-secret/credential-evidence/issues/231), handoff
[#235](https://github.com/redact-secret/credential-evidence/issues/235)). The
class rules and the legend are in the [#1223 record](../1223/README.md).

## Sources

| Role | Source |
| --- | --- |
| Provider facts (pending inputs) | The three proposed contracts of credential-evidence#235 and the [Batch 2 handoff](https://github.com/redact-secret/credential-evidence/blob/005a7331cf90403bd4ce4abcb93bd8b085d315a9/docs/handoffs/batch-2-bounded-carriers.md) (credential-evidence#248, project-authored, not independent). It records `oauth_token_secret` as the secret half issued with `oauth_token`; for HubSpot, a key kept in a local global config file with no field name; for MyJFrog, existence only. |
| Independent baseline | None. benchmarks#739 readiness (comment 6001345412): `hubspot:personal-access-key` and `jfrog:myjfrog-api-token` carrier-unresolved, `x:oauth1-access-token-secret` blocked (awaiting evidence review). |
| Product policy (this record) | The contextual name vocabulary and its whole-name admission precedent ([#1211](../1211/README.md), [#919](../860/fal-contextual-gap.md)), `decision-redact-provider-named-credential-assignments` (a bare `token` and a bare `_key` suffix stay unmatched) and `decision-define-fragmented-credentials-as-outside-the-raw-input-contract`. |

## Adopted contracts

| Question | `x:oauth1-access-token-secret` | `hubspot:personal-access-key` | `jfrog:myjfrog-api-token` |
| --- | --- | --- | --- |
| Layout kinds in contract | A credential field named `oauth_token_secret`: assignment, quoted assignment, form body or query parameter (the token response is form-encoded), JSON or YAML member, once a reviewed layout names it. The secret never appears in an `Authorization: OAuth` header, which carries only the signature. | None until the evidence names the exact CLI configuration field and file layout. | None until the evidence names the MyJFrog header or field. If it is an explicit `Authorization: Bearer` header the existing Bearer path applies unchanged; a field is governed by the vocabulary rule below. |
| Value admission and span | The existing field grammar: 8-byte floor, shared reference, placeholder and mask exclusions, exactly the value, ending at the form delimiter. | As the vocabulary rule. | As the vocabulary rule, or the Bearer grammar. |
| Finding type and action | `contextual_secret`, redact at high confidence, warn at medium. No X or provider attribution. | Same, with no HubSpot attribution. | Same, or `bearer_token`; no JFrog attribution. |
| Excluded | `oauth_signature` (a signing output, not the secret), `oauth_consumer_key`, `oauth_nonce`, `oauth_timestamp`, `oauth_signature_method`, `oauth_version`, ids, placeholders, references, masks. | The portal and account id; other CLI configuration values; arbitrary `*key` names. | The JFrog platform access token (a different row), public ids; arbitrary `*key` names. |
| Unsupported, stated limits | A secret in another field name; a value cut across lines; an SDK call that passes it positionally. | An SDK positional argument and any configuration nesting the evidence has not contracted. | The same. |

**Vocabulary admission rule.** A credential name is added to the contextual
vocabulary only when the evidence names the exact provider-documented field, and
then as one whole normalized name (the `mac_secret_base64`, `fal_key` and
`db_pass` mechanism: it is not a prefix or suffix rule and not a `*_key` or
`*token` rule), with the shared placeholder, reference and mask exclusions kept,
a false-positive and false-negative statement, and neighbouring-name controls
(`-Id`, `-Hint`, `Length` and prefixed lookalikes stay unmatched). A name is
never derived from a credential's label ("personal access key", "API token").
This record adds no name.

**`oauth_token` is not adopted as an exclusion.** The evidence handoff lists
`oauth_token` among the public lookalikes of the secret half. The product's
accepted default reads a prefixed `_token` name as a credential (the #702 rule,
`oauth_token` named in the `auth_token` row of the contextual spec), so a random
value under `oauth_token` is `contextual_secret`, redacted, and a low-entropy one
is `warn`. This contract does not change that and asserts nothing for
`oauth_token` as part of the secret-half row; an evidence control that expects
`oauth_token` to stay clean contradicts the accepted default and needs its own
product decision, proposed as an expectation correction, not assumed.

## Product observations

Product observations at core `3b1a5aa9` (CLI `0.1.0-beta.13` line, debug build of
this commit, check mode, UTF-8 byte ranges), small synthetic inputs, values
invented and not shown. Not benchmark results and not coverage claims.

| Input (synthetic) | Observed finding |
| --- | --- |
| `oauth_consumer_key=<8>&oauth_token=<13, low entropy>&oauth_token_secret=<20>&oauth_signature=<20>%3D` | `contextual_secret`, medium, warn, over the 13-byte `oauth_token` value (40-53); `contextual_secret`, high, redact, over exactly the 20-byte `oauth_token_secret` value (73-93); `oauth_consumer_key` and `oauth_signature` silent |
| `oauth_token=<20>&oauth_token_secret=<20>&user_id=<5>` | two `contextual_secret`, high, redact, over each 20-byte value (12-32, 52-72); `user_id` silent |
| JSON `{"oauth_token":"<20>","oauth_token_secret":"<20>","oauth_callback_confirmed":"true"}` | two `contextual_secret`, high, redact (16-36, 60-80); `oauth_callback_confirmed` silent |
| `oauth_token_secret = "<20>"` and `access_token_secret: <20>` | two `contextual_secret`, high, redact, over the value only (22-42, 65-85) |
| `Authorization: OAuth oauth_consumer_key="..", oauth_nonce="..", oauth_signature="<20>%3D", oauth_signature_method="HMAC-SHA1", oauth_timestamp="..", oauth_token="<20>", oauth_version="1.0"` | one `contextual_secret`, high, redact, over the `oauth_token` value (199-219) only; the signature, nonce, consumer key, timestamp, method and version are silent |
| `personalAccessKey: <24>` and `hubspot_personal_access_key=<24>` (illustrative names, not claimed HubSpot fields) | no finding |

The last row is the stated blind spot: a value under a name outside the
vocabulary is not read, and the product does not guess HubSpot's field. It
becomes a gap, to be repaired by the vocabulary rule above, only if the evidence
names the exact field and a baseline shows the miss.

## Per-row table

Legend as in the [#1223 record](../1223/README.md#per-row-table); P1 and P2 are
the preconditions defined there.

### G5: 3 families

| Family | Layout kind (evidence-named, unreviewed) | Product disposition kind | Benchmarks inventory | Evidence handoff | Precondition |
| --- | --- | --- | --- | --- | --- |
| `hubspot:personal-access-key` | C | conditional on a reviewed layout; no vocabulary entry until evidence names the field | carrier-unresolved (carrier-source-missing) | carrier-unresolved | P2: HubSpot CLI docs and `hs` config reference: exact config field and file layout |
| `jfrog:myjfrog-api-token` | C | conditional on a reviewed layout; no vocabulary entry until evidence names the field | carrier-unresolved (carrier-source-missing) | carrier-unresolved | P2: JFrog MyJFrog API docs: header form |
| `x:oauth1-access-token-secret` | F | existing generic path: field (`oauth_token_secret`) | blocked (awaiting-evidence-review) | ready | P1 |

## Handoff

The benchmarks side may treat as adopted, once `x:oauth1-access-token-secret` has
a reviewed layout: the `oauth_token_secret` value is the secret half, spanned
exactly and redacted (`warn` at medium for a low-entropy literal), generic type,
with the signature, consumer key, nonce, timestamp, method and version silent.
For the two carrier-unresolved rows nothing is adopted beyond the vocabulary
admission rule and the stated limits: they stay carrier-unresolved, not FN, TN or
pass, until the provider sources the handoff names (the HubSpot CLI
configuration reference and the MyJFrog API header form) are recorded and
reviewed. `oauth_token` is outside the secret-half row and is not an expected
clean value. Exact candidate source and digests go to benchmarks only after a
gap is demonstrated; none is. No pin, version or release changes.

## Gates of the issue

| Gate | State |
| --- | --- |
| Freeze layout, admission, span, attribution, default action, exclusions per ready row | Met at class level (this record and the spec rows); per row conditional, no row is ready. |
| Link baseline case ids and identities; disposition every row | Open, no baseline. |
| Repair only demonstrated gaps; add only evidenced vocabulary | Open, none demonstrated and no name added. |
| Deterministic conformance for changed logic | Open, no logic changed. |
| Shared parser fix once | Open, none needed so far. |
| Node/WASM, Python, Rust and CLI whole and stream behavior | Open. Only the CLI was observed, at one commit. |
| Candidate revision and digests to benchmarks; accept replay | Open, conditional on a demonstrated gap. |
| Record no-code conclusions | Open, conditional on a baseline. |

## Tradeoffs

* A bounded whole-name entry is the cheapest repair for a missing documented
  field and its cost is the contextual one: a non-secret literal of 8 or more
  bytes in the exact slot is redacted. Waiting for the evidence to name the field
  leaves a real HubSpot or MyJFrog value unread meanwhile, stated above as a
  blind spot, instead of broadening to `*key` and redacting benign configuration.
* Reading `oauth_token` as a credential redacts a value the provider may treat
  as public. That is the security-first default of the prefixed `_token` rule and
  is kept.
* The secret half is read by name only; the same bytes in another field, an SDK
  positional argument or a split literal are not read.

## Tests

None added: documentation and policy only. The field grammar is pinned by the
`generic_token` unit tests and `batch1_credential_slots_1209_1213.rs`. The
observations above are pinned by this record only.
