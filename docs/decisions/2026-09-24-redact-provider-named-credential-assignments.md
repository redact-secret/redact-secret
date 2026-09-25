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
