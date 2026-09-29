---
decision_id: decision-redact-provider-named-credential-assignments
status: accepted
scope: workspace
title: Redact a value assigned to a provider-named credential name
decided_at: 2026-09-24
spec: contextual-detection
---

# Redact a value assigned to a provider-named credential name

## Decision

A credential assigned to a name that says it is a credential is redacted,
whether the name is bare (`api_key`) or carries a prefix (`MYAPP_API_KEY`,
`MAILCHIMP_API_KEY`). This answers
[#702](https://github.com/redact-secret/redact-secret/issues/702) for every
family. The Pinecone decision
([`decision-claim-a-legacy-pinecone-uuid-key-only-under-its-api-key-name`](2026-09-24-claim-a-legacy-pinecone-uuid-key-only-under-its-api-key-name.md))
answered it for one family only.

1. **Keyword-gated provider detectors report a named assignment at high
   confidence.** `okta-api-token`, `mailchimp-api-key`, `mailgun-api-key`,
   `heroku-api-key-legacy`, `confluent-cloud-api-secret-legacy`,
   `datadog-api-key`, `datadog-application-key-legacy`, `twilio-auth-token`,
   `twilio-api-key-secret` and `new-relic-license-key` report high, not
   medium, in two cases. One is a value assigned to a key that names the
   provider (`MAILCHIMP_API_KEY=`, `okta.api_token:`, `"mailgunApiKey":`). The
   other is a value assigned to a high-signal key on a line that names the
   provider (`mailchimp.setConfig({ apiKey: ... })`). A key whose last segment
   names an identifier or a location does not qualify (`_id`, `_sid`, `_url`,
   `_domain`, `_region`, `_account`, ...). A provider keyword elsewhere on the
   line, with no such name, stays medium (`# Mailchimp API key <value>`).
2. **`generic-token` matches generically prefixed names.** After
   `normalize_name`, `<prefix>_<high-signal name>` is high-signal
   (`myapp_api_key`, `db_password`, `jwt_secret`), and so is a prefixed
   `_token` name (`ci_deploy_token`, `admin_token`). A request-scoped or public
   token is excluded: `csrf_token`, `xsrf_token`, `page_token`,
   `next_page_token`, `prev_page_token`, `pagination_token`,
   `continuation_token`, `cancel_token`, `cancellation_token`, `sync_token`,
   `resume_token`, `device_token` and `push_token`. A prefixed ambiguous name
   stays ambiguous, and the bare `token` name stays unmatched. The prefix does
   not qualify in two cases:
   - It names a provider that has its own built-in detector (`MAILCHIMP_`,
     `GITHUB_`, `GH_`, `DD_`, `NEW_RELIC_`, ...). That detector's contract
     decides.
   - Its first segment says the value is not the secret (`redacted_`,
     `masked_`, `hashed_`, `hash_`, `obfuscated_`, `truncated_`,
     `sanitized_`, `publishable_`).
3. **Placeholders and digests are not secrets.** `generic-token` excludes the
   following values under any name:
   - a documentation placeholder behind a short lowercase vendor prefix
     (`pplx-your-api-key-here`, `lsv2_pt_your_key_here`, `pcsk_***`,
     `xapp-<your-app-level-token>`);
   - one repeated filler character behind an optional short prefix
     (`dapixxxx...`, `PMAK-xxxx...-xxxx...`, the all-zero UUID);
   - a value that opens with a digest label (`hmac-sha256:<hex>`,
     `sha256:<hex>`).

## Rationale

- **Security first.** A missed credential is a leak. The measured gap was
  that the same Mailchimp key redacted under `api_key=` (generic, high) but
  only warned under `MAILCHIMP_API_KEY=` (provider, medium), and
  `SMTP_PASSWORD=<value>` got no finding at all. The name now decides the
  outcome, not how the name is spelled.
- **Each provider's contract stays authoritative.** The benchmark's
  malformed-by-construction controls put a truncated or mis-delimited value
  under the provider's own variable (`GITHUB_TOKEN=ghp_abc123`,
  `MAILCHIMP_API_KEY=<short hex>-us6`, `TWILIO_AUTH_TOKEN=<33 hex>`). They are
  must-not-flag because the provider's grammar says the value is not a
  credential. A first candidate that let `generic-token` claim every prefixed
  name flagged 42 of them (benchmarks `f5363ab`, product `020eb71`, run
  `b9d93685`). Deferring to the dedicated detector keeps those controls clean
  and gives the provider's own finding type to the valid values.
- **The provider finding keeps the span.** A named assignment reported at
  high confidence by the provider detector wins the overlap with a
  `generic-token` candidate on the same span on provider specificity, so the
  finding keeps its provider type and redacts.

## What this costs

- **False negatives.** A credential of a type that the provider's own
  detector does not cover, stored under that provider's name, is not
  claimed by `generic-token`. `GITHUB_CLIENT_SECRET=<40 hex>` is one example:
  `github-token` covers tokens, not OAuth client secrets. That was already
  true before this decision. Under a bare `token` name, or with no `=`/`:`
  operator (a CLI flag), a value is still not matched by name.
- **False positives.** A non-secret, high-entropy value of at least eight
  bytes under a generically prefixed credential name is now redacted. One
  example is a public key id stored as `SERVICE_API_KEY`.
- **Instructional placeholders that name a service stay detected.**
  `YOUR_SMTP_PASSWORD` is not excluded, because a word off the instructional
  lists keeps a value detected
  ([#756](https://github.com/redact-secret/redact-secret/issues/756)).

## Consequences

- `crates/secret-scan-core/src/detectors/generic_token.rs`: prefixed name
  classification, `prefix_is_generic`, `is_vendor_prefixed_placeholder`,
  `is_prefixed_filler`. The incremental retention hint and the ruleset
  reserved-name check use the same classifiers. A ruleset name that a
  prefixed built-in now covers is therefore a no-op, so the ruleset examples
  moved from `corp_token` to `corp_passphrase`.
- `crates/secret-scan-core/src/detectors/text.rs`:
  `is_provider_named_assignment`, shared by the ten keyword-gated detectors,
  and `starts_with_digest_label`.
- `conformance/fixtures/synchronous-corpus.json`: 32 keyword positives and
  overlaps go from medium to high. No negative or control fixture changes.

## Amendment: structural provider context is high (#936)

The Beta.11 family-evidence corpus recorded keyword-gated positives that were
detected exactly but reported `medium`, so the default policy only warned and
the value stayed in the sanitized output
([#936](https://github.com/redact-secret/redact-secret/issues/936)). Some of
them are the section 1 rule working as written (a keyword elsewhere on the
line). Others are read through a structure that does what a provider-named key
does: it names the value's credential slot and binds it to the provider. Under
the project's security-first default (redact over warn), those are `high`:

- **Mailchimp.** Since [#931](https://github.com/redact-secret/redact-secret/issues/931)
  the complete `<32 hex>-us<1–3 digits>` shape is evidence on its own. Outside
  a DNS label or URL path it is `high` with or without a `mailchimp` keyword;
  a keyword cannot make the same value less of a key. A DNS-label or path
  match that a same-line keyword keeps reported stays `medium`.
- **Heroku, Twilio, Confluent layouts** (#743, [#933](https://github.com/redact-secret/redact-secret/issues/933)):
  a `.netrc` `password` under a Heroku `machine` line, `heroku auth:token`
  output, the `Token:` row of `heroku authorizations:<verb>`, the `Auth Token`
  column of a `twilio` CLI table, and the secret half of `basic.auth.user.info`
  below a Confluent-named property.
- **Deepgram.** An `Authorization: Token` header on a line that names a host
  under the Deepgram API domain (`api.deepgram.com`, `api.eu.deepgram.com`):
  the value is in the key's documented slot of a request to the provider.
  With `deepgram` only as a word on the line the header stays `medium`.

Section 1's rule still holds for the other families: a provider keyword
elsewhere on the line, with no name and no such structure, stays `medium`
(`# Twilio token <value>`). Its `# Mailchimp API key <value>` example is
superseded by the Mailchimp bullet above, because that shape no longer needs
the keyword at all.

What this costs. No new value is matched: the grammars, windows and benign
twins are unchanged, and only the action changes. A non-credential value in
one of these exact slots is now redacted instead of warned: a 32-hex
region-sharded id followed by `-us<N>` in prose or a log field, or a
non-secret 32-hex cell under an `Auth Token` column. The benefit is that
seven benchmark positives (the three #931 Mailchimp forms, the three #933
layouts, and the #932 Deepgram HTTPie header) no longer leave plaintext
credentials in the output. Types stay confidence-gated; `ALWAYS_REDACT_TYPES`
is unchanged. Tests: the detector modules' unit tests and
`tests/family_evidence_gaps_379.rs`; conformance: the affected
`synchronous-corpus.json` expectations, plus five new fixtures for the
layouts and the medium twins.

## Amendment: a provider-named high-signal name falls back to `generic-token` (#948)

Amended 2026-09-29. An off-grammar value under a provider-named credential
variable got no finding at all
([#948](https://github.com/redact-secret/redact-secret/issues/948)):
`MY_API_KEY=<v>` redacted a random 32-byte value while `OPENAI_API_KEY=<v>`
or `export STRIPE_API_KEY="<v>"` reported nothing, because section 2's
provider exception disqualified the name and the provider's grammar declined
the value. Under the security-first default:

- **A provider prefix no longer disqualifies a high-signal name.**
  `OPENAI_API_KEY`, `GITHUB_TOKEN`, `DD_API_KEY` and `"huggingfaceApiKey"`
  are high-signal like `MYAPP_API_KEY`, for every
  prefix of the rule-2 list (`DEDICATED_PROVIDER_SEGMENTS`/`_PHRASES` in
  `generic_token.rs`). `generic-token` claims the value at the unchanged
  floors (8 bytes; `high` at 16 bytes and entropy 3.0, else `medium`) with
  the generic action: `high` redacts, `medium` warns.
- **The provider detector still decides an on-grammar value**, through
  overlap resolution alone: provider specificity outranks contextual, and a
  keyword-gated provider reports its own provider-named assignment `high`
  (section 1), so the value stays one typed provider finding. A
  keyword-gated grammar under *another* provider's name is `medium` there
  and yields to the `high` contextual candidate on resolved action, as it
  already did under `MYAPP_API_KEY`.
- **Unchanged.** Non-secret leads (`redacted_`, `masked_`, `publishable_`,
  ...) still disqualify a name; a provider prefix still disqualifies an
  ambiguous name (`GITHUB_CREDENTIALS`) and a request-scoped `_token` name
  stays excluded. Identifier siblings (`_id`, `_url`, `_sid`, ...), #911
  object-reference names, and the placeholder, reference, template, `$VAR`
  and filler exclusions apply exactly as for a generic name.

This supersedes section 2's provider exception for high-signal names and the
`GITHUB_CLIENT_SECRET=<40 hex>` false negative under "What this costs".

- **FN removed:** format drift, a new key generation, a legacy or sibling key
  type, and a truncated or mis-delimited paste under the provider's own
  variable name. The `common` profile, which has no provider detectors, now
  redacts every provider-named assignment.
- **FP cost:** a non-secret literal of 8+ bytes under a provider-named
  credential variable, the cost section 2 already accepted for
  `MYAPP_API_KEY`. The malformed-by-construction controls that motivated the
  exception are reported again (`GITHUB_TOKEN=ghp_abc123` warns, a
  full-length near miss redacts), and so is a public id kept under a
  provider's `_API_KEY` name (a Confluent Cloud API key id, a Datadog key
  record id).

Evidence (46 canonical fixtures, 244 common-profile expectations, 203
benchmark construction negatives, all with the same action as under
`MYAPP_`): [`docs/audits/evidence/948/README.md`](../audits/evidence/948/README.md).
Tests: `generic_token` unit tests and
`tests/provider_named_fallback_948.rs`.
