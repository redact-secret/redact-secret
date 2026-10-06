# Evidence: #1241, the default reading of the OAuth 1.0 `oauth_token`

**Decision:** the accepted default is kept. A value under `oauth_token` is read
like any other prefixed `_token` name: a random value is one `contextual_secret`
finding, `redact` at high confidence, exactly the value; a low-entropy value is
`medium`, `warn`, text unchanged; a placeholder, reference or mask is silent. The
product records this as an **intentional policy deviation from the evidence
role**: credential-evidence lists `oauth_token` as a public lookalike (a control),
and the product redacts it anyway. This is option A of the issue. No code, type,
vocabulary or detector changes; the behaviour is pinned by tests so a change of
the default is visible.

Issue [#1241](https://github.com/redact-secret/redact-secret/issues/1241) (a
decision, not a defect), raised by the benchmarks Batch 2 G5 measurement
([benchmarks#744](https://github.com/redact-secret/redact-secret-benchmarks/issues/744),
epic [#739](https://github.com/redact-secret/redact-secret-benchmarks/issues/739)).
Package: [#1225](../1225/README.md); contract PR #1231.

## The disagreement

| Source | Reading of `oauth_token` |
| --- | --- |
| credential-evidence, Batch 2 handoff, family `x:oauth1-access-token-secret` | A public lookalike of the secret half, a control (it is the token identifier sent with every signed request). A factual claim about the field's role. |
| The adopted contract ([#1225](../1225/README.md)) and the product default | A credential-named field: the #702 prefixed `_token` rule reads it like `access_token`. |
| RFC 5849 | `oauth_token` is the token identifier; `oauth_token_secret` is the shared secret and the signature is derived from it. The standard does not say whether an implementation must redact the identifier. |

The benchmark does not score the field: it is recorded as a contract-evidence
conflict, observed flagged, unscored.

## Product observations

Synthetic inputs, CLI `0.1.0-beta.13` line at core `4e004108`, UTF-8 byte ranges.
Product observations, not coverage claims and not a benchmark result.

| Input | Observed finding |
| --- | --- |
| `oauth_token=<20 random>` | `contextual_secret`, high, redact, over the value (12-32) |
| `oauth_token=<numeric id>-<40 random>` | `contextual_secret`, high, redact, over the whole value |
| `oauth_token=<20>&oauth_token_secret=<44>&oauth_callback_confirmed=true` | two `contextual_secret`, high, redact (12-32, 52-96); `oauth_callback_confirmed` silent |
| `https://host/oauth/authorize?oauth_token=<20>` | one `contextual_secret`, high, redact, over the value only |
| `Authorization: OAuth oauth_consumer_key=.., oauth_nonce=.., oauth_signature=.., oauth_signature_method=.., oauth_timestamp=.., oauth_token="<id>", oauth_version=".."` | one `contextual_secret`, high, redact, over the `oauth_token` value; every other member silent |
| JSON `{"oauth_token":"<20>"}` | one `contextual_secret`, high, redact, over the value |
| `oauth_token=YOUR_OAUTH_TOKEN`, `<oauth_token>`, `${OAUTH_TOKEN}`, empty | no finding |
| `oauth_token=<12 low entropy>` | `contextual_secret`, medium, warn, text unchanged |
| `access_token=<20>` (reference) | identical to `oauth_token` |
| `token=<20>` (reference, a bare `token` name) | no finding |
| `oauth_signature`, `oauth_consumer_key`, `oauth_nonce`, `oauth_timestamp`, `oauth_version`, `oauth_signature_method` | no finding |

## Decision and basis

1. **It is the accepted rule, not a new one.** `oauth_token` is read by the
   prefixed `_token` name default that also reads `access_token` and
   `refresh_token`, and a bare `token` name stays silent ([#1203](../../../decisions/2026-10-04-settle-the-open-structured-file-url-carrier-and-control-roots-of-1203.md)).
   Carving out one prefixed name adds a vocabulary exception that no other
   OAuth field has.
2. **The alternative needs a context rule that costs more than it saves.**
   Reading `oauth_token` only when it is paired with `oauth_token_secret` or a
   signature (option B) breaks on layouts where the identifier stands alone: the
   authorize redirect URL, a log line, a form body without the secret half.
   Pairing is a new cross-field parser rule with new false negatives, for a field
   whose leak cost is the identifier of a credential pair, not the secret.
3. **A factual role claim does not decide a redaction policy.** Whether the field
   is a public identifier is a provider and standard fact that credential-evidence
   owns; whether the product redacts it is a product policy, decided under the
   security-first default. Keeping the two separate is the rule of
   credential-evidence ADR 0023 and of the Batch 2 contract. Asking the evidence
   to restate the role basis (option C) answers a question nobody disputes.
4. **Security first.** The false-positive cost is one identifier masked in a log
   or a URL; the false-negative cost is a token value left readable, and the
   numeric-prefix shape some providers issue (an account id joined to a random
   part) ties the value to an account.

## What this changes for each party

* **Product:** nothing in behaviour. The default is now an adopted decision, with
  the regression pairs of `crates/secret-scan-core/tests/oauth1_token_default_1241.rs`
  pinning it (below), and a spec row in `docs/specs/contextual-detection.md`.
* **Benchmarks:** the conflict can be removed from the ledger as a *resolved
  policy deviation*. The expectation to freeze is `policy: redacted`: a random
  value under `oauth_token` is `contextual_secret`, `redact`, exactly the value, a
  low-entropy one is `warn`. It may be scored against that expectation, or kept
  unscored deliberately; it must not be counted as a false positive, because the
  product redacts it by decision, and no benchmark expectation is rewritten to fit
  the output. Candidate identity for any replay: the merge commit of the PR that
  carries this record.
* **credential-evidence:** the role statement ("public lookalike") is not
  contradicted and needs no correction as a fact. If the evidence wants to keep
  the field as a control, it should label it as a role control that is expected to
  be flagged by default policy, not as an expected-clean value.

## Tradeoffs

* **False positive:** a value the provider treats as a public identifier is
  masked (`contextual_secret`, redact at high confidence), and a low-entropy one
  is a medium `warn`. A user who needs the identifier visible can lower the
  action for the finding type with the user action configuration
  ([#1216](https://github.com/redact-secret/redact-secret/issues/1216) to #1222); the default is not weakened for everyone.
* **False negative kept:** the identifier in a layout the grammar does not read
  (an SDK positional argument, a split literal, an encoded form) is not read, as
  for every credential name.
* **Not adopted:** a pairing rule (option B) and a name exclusion; an evidence
  restatement as the resolution (option C).

## Tests

`crates/secret-scan-core/tests/oauth1_token_default_1241.rs` (8 tests): a random
`oauth_token` is `contextual_secret`, redact, high, exactly the value, like
`access_token`, in assignment, JSON and numeric-prefix shapes; the request-token
response reports both halves as separate spans; an authorize redirect parameter is
read with no secret half nearby; only the `oauth_token` of a signed
`Authorization: OAuth` header is read; `oauth_signature`, `oauth_consumer_key`,
`oauth_nonce`, `oauth_timestamp`, `oauth_version`, `oauth_signature_method`,
`oauth_callback_confirmed` and a bare `token` stay silent; a placeholder,
reference or empty value is silent; a low-entropy value is `medium`, `warn`, text
unchanged; a multibyte prefix shifts the UTF-8 byte range. Every case asserts
whole-input equals every two-chunk UTF-8 byte partition equals a per-line session.

## Gates

| Gate of #1241 | State |
| --- | --- |
| A decision recorded in the Batch 2 contract docs naming the intended behaviour and its basis | Met: this record, linked from [#1225](../1225/README.md) and the contextual spec. |
| Benchmarks can freeze the expectation (score it or keep it unscored deliberately) and remove the conflict from the ledger | Open on the benchmarks side: this record states the expectation to freeze. |
| No benchmark expectation rewritten to fit current output | Met: none was edited. |

No release, tag, pin or version change.
