# Detection coverage and limits

[Documentation home](../README.md)

The core uses local structure and context, not provider API calls, to classify
text. It does not determine whether a credential is active, expired, or valid.

Built-in Rust detection covers these kinds of structure:

| Family | Examples of supported structure |
| --- | --- |
| Private keys | PEM-style private-key blocks |
| Provider credentials | API keys and tokens with a recognizable provider-issued format, one detector per provider family (listed below) |
| Authorization | JWT, Bearer, Basic, and Token credentials |
| Context | Credential assignments, such as an `api_key` or `password` setting, including AWS secret-access-key and session-token names |
| Connections | Credential-bearing URLs for the supported database, queue, HTTP(S), and FTP(S) schemes |
| One-time password provisioning | `otpauth://totp` and `otpauth://hotp` with base32 shared secrets |
| Opt-in structured PII | Context-required email, IBAN, canonical IPv4/IPv6, payment-card, phone, and US SSN identities. Global families use `pii:global:*`; SSN uses `pii:us:ssn`. PII defaults off and all families share one `pii-domain` slot |

Credential-family support status is stated only in the generated
[support matrix](../support-matrix.md); that matrix does not carry the opt-in
PII families, whose status is the table under
[Opt-in PII](#opt-in-pii-availability-is-not-support). Each provider family's exact frozen
grammar and the decision behind it are in the
[detector-families spec](../specs/detector-families.md); for example,
DigitalOcean tokens are `dop_v1_`/`doo_v1_`/`dor_v1_` plus exactly 64
lowercase hex bytes. `google-api-key` covers Google Cloud and Gemini keys,
`vault-token` the modern Vault token patterns, `stripe-token` qualified Stripe
credentials, and `docker-token` Docker Hub tokens.

This is a family overview, not a promise to match every token each provider
issues. Exact supported grammars and evidence are recorded in the
[coverage report](../coverage/coverage-report.md) and
[conformance corpus](../../conformance/README.md). The bounded, source-identified
[detection reliability assessment](detection-reliability.md) publishes its
denominators, results, and limitations without turning them into a universal
accuracy claim.

### Opt-in PII: availability is not support

A PII selector makes a family available: once selected, its detector runs.
That is all activation means. Qualified support is a separate `pii-v1` status
of `pending`, `provisional`, or `stable`, and only exact-artifact benchmark
evidence under the
[`pii-v1` qualification profile](../decisions/2026-09-26-define-pii-v1-qualification-and-national-id-arrival-gates.md)
can move a family past `pending`.

The Beta.11 qualification measured candidate core
`8b6a5fde52ecb4dfce13f09c7a947062d21483c7`
([final record](https://github.com/redact-secret/redact-secret-benchmarks/blob/be0fb9f35045bf05e5b999a2c0ed368541f9e963/evidence/901/428/final-core-8b6a5fde.md),
[protected disposition](https://github.com/redact-secret/redact-secret-benchmarks/blob/be0fb9f35045bf05e5b999a2c0ed368541f9e963/evidence/901/428/core-8b6a5fde52ec/pii-beta11-protected-disposition-v2.json)):

| Family | Selectors | Jurisdiction | `pii-v1` status |
| --- | --- | --- | --- |
| `pii:global:network-address` | `pii`, `pii:global`, `pii:us`, `pii:family:global:network-address` | global | `provisional` |
| `pii:global:email` | `pii`, `pii:global`, `pii:us`, `pii:family:global:email` | global | `provisional` |
| `pii:global:payment-card` | `pii`, `pii:global`, `pii:us`, `pii:family:global:payment-card` | global | `provisional` |
| `pii:global:iban` | `pii`, `pii:global`, `pii:us`, `pii:family:global:iban` | global | `provisional` |
| `pii:global:phone` | `pii`, `pii:global`, `pii:us`, `pii:family:global:phone` | global selector, `+1` / NANP numbers only | `provisional` |
| `pii:us:ssn` | `pii:us`, `pii:family:us:ssn` | United States only | `pending` |

These statuses are bound to two exact revisions: core
`8b6a5fde52ecb4dfce13f09c7a947062d21483c7` (`0.1.0-beta.11`) and
`redact-secret/redact-secret-benchmarks` revision
`be0fb9f35045bf05e5b999a2c0ed368541f9e963`, which holds the qualification
record. The PII code has changed since that core revision: `pii_email.rs`,
`pii_iban.rs` and `pii_phone.rs` (the email, IBAN and phone families) and also
`pii_payment_card.rs`, `pii_us_ssn.rs` and the shared `pii.rs`. The statuses
below were measured on the earlier code and have not been re-measured on the
current source; they are not re-qualified on any later core commit, and
re-qualification is benchmarks work. The pinned support matrix now carries
these six families as `piiFamilies`, with the qualification identity as
`piiQualification` (state `not-requalified`) and `piiDistribution`
([`redact-secret/redact-secret-benchmarks#647`](https://github.com/redact-secret/redact-secret-benchmarks/issues/647)),
apart from the credential families and never counted in their totals. The
matrix is the status source; the table above must agree with it. The gate
`npm run pii-family-status:check` fails when a shipped PII family has no row in
the matrix or here, when the two disagree, when the matrix names a different
qualification than
[`docs/coverage/pii-family-status.json`](../coverage/pii-family-status.json),
or when a recorded revision is missing.

`provisional` is not `stable`, and no family is `stable`. The five
`provisional` families met every public gate and their one sealed
protected-partition run. Their `profile-cost` gate counts as met only through
a maintainer-accepted tradeoff for the PII-on cost cells
([acceptance ledger](https://github.com/redact-secret/redact-secret-benchmarks/blob/be0fb9f35045bf05e5b999a2c0ed368541f9e963/benchmarks/accepted-pii-profile-cost.json)), accepted because PII is opt-in, and this
qualification route never assigns `stable`. US SSN stays `pending`: its
protected run missed the `identity-only-classification` gate (one of two
identity-only comparisons disagreed on sensitivity), and its single attempt is
spent. Each status covers only the family's frozen contract below, and PII
stays off unless a selector activates it. Each family's disposition is tracked
in
[redact-secret-benchmarks#428](https://github.com/redact-secret/redact-secret-benchmarks/issues/428).

The six families are `pii:global:email`, `pii:global:iban`,
`pii:global:network-address`, `pii:global:payment-card`, `pii:global:phone`,
and `pii:us:ssn`. US SSN is the only jurisdictional family, selected by
`pii:us` or `pii:family:us:ssn`. No other jurisdiction and no other national
identifier is available. These are six bounded structured families, not
general PII coverage: names, postal addresses, dates of birth, free-text
personal data, and every form a family's contract excludes stay undetected.

### Opt-in email PII

PII is off by default. The global or exact email selector registers one
`pii-domain` adapter, not one top-level detector per family. Its email family
recognizes the conservative dot-atom RFC 5322 / RFC 6531 subset frozen in the
[email family contract](../contracts/pii/email-v1.md). Structure establishes
identity only; high-signal email context establishes sensitivity, while a
whole RFC-reserved/documentation domain or a named example/documentation
context makes the occurrence non-sensitive. It does not implement quoted
local parts, comments, folding, domain literals, ordinary single-label domains,
or deliverability checks. Exact RFC 6761 single-label names are admitted only
as non-sensitive controls. The family is `provisional` under `pii-v1`, not
`stable`.

### Opt-in payment-card PII

The global or exact payment-card selector recognizes a deliberately bounded
ISO/IEC 7812 PAN subset: 10–19 ASCII digits in frozen Visa, Mastercard,
American Express, Discover, or JCB ranges, with a Luhn v1 pass and reviewed
payment-card field context. Compact values are supported; displayed values are
limited to one separator kind in `4-4-4-4` or `4-6-5` layout. Exact published
Visa Acceptance test-service numbers are whole-value non-sensitive controls.
The [payment-card family contract](../contracts/pii/payment-card-v1.md) freezes
the full ranges, context, exact spans, exclusions, and accepted false-positive
and false-negative costs. The family is `provisional` under `pii-v1`, not
`stable`.

### Opt-in phone PII

The global or exact phone selector recognizes only the frozen `+1` / NANP
subset, exact display layouts, and narrow 1–6 digit extension syntax in the
[phone family contract](../contracts/pii/phone-v1.md). Structure establishes
identity, while a reviewed English or Korean phone field (or associated shared
`contact details` phrase) is required for sensitivity. Bare values and
ambiguous `contact` / `연락처` labels do not produce findings. Exact
whole-candidate `555-0100` through `555-0199` exchange/line controls are
non-sensitive. Other country codes, including `+82`, URI/vanity forms, broad
separator variants, allocation and activity checks, and locale guessing are
unsupported. The family is `provisional` under `pii-v1`, not `stable`; the
status covers only `+1` / NANP numbers.

### Opt-in US SSN PII

The exact `pii:family:us:ssn` selector recognizes nine ASCII digits in compact
or exact ASCII `3-2-4` hyphenated form. `pii:us` closes over this family and all
available global families. The `us-ssn-allocation` v1 validator applies only
SSA-published current structural exclusions: area `000`, `666`, and `900`–`999`,
group `00`, and serial `0000`. It does not infer issuance, pre-2011 geography,
high-group allocation, or identity. Reviewed English or Korean SSN field
context is required for sensitivity; generic identifier and number labels do
not qualify. The [US SSN family contract](../contracts/pii/us-ssn-v1.md)
freezes grammar, boundaries, sources, safe fixtures, and tradeoffs. The family
remains `pending` under `pii-v1`: its Beta.11 protected run did not meet
`identity-only-classification`. It is available when selected but not
qualified.

### Opt-in IBAN PII

The global or exact IBAN selector accepts an uppercase compact IBAN or the
exact four-character ASCII-space print grouping. The country code must have a
SWIFT Registry Release 103 length row, and the value must pass `iban-mod97` v1.
Reviewed IBAN context is required for sensitivity; a checksum-valid value with
no context stays identity-only. Lowercase, tabs, hyphens, repeated or
non-breaking spaces, mixed grouping, and unknown or wrong country lengths are
excluded. It does not look up banks, account ownership, or account status. The
[IBAN family contract](../contracts/pii/iban-v1.md) freezes the rest. The
family is `provisional` under `pii-v1`, not `stable`.

### Opt-in network-address PII

The global or exact network-address selector is one family for canonical
dotted IPv4 and full, compressed, or IPv4-embedded IPv6. Zone ids and
leading-zero IPv4 octets are rejected. A reviewed network-address field label
is required for sensitivity. Only the frozen documentation, test, and
benchmarking ranges and named non-endpoint constants (such as `0.0.0.0`,
loopback, multicast, and broadcast) are non-sensitive; being private or
special-purpose alone does not make an address non-sensitive. The frozen
contract is the
[network-address evidence record](https://github.com/redact-secret/redact-secret/blob/2816897f96c405c3eb8c87a0c70eba5df273c121/docs/audits/evidence/875/README.md). The
family is `provisional` under `pii-v1`, not `stable`.

### Policy-qualified generic credentials

Four generic credential families have an explicitly bounded T3
`project-policy` contract: Bearer values, URL-userinfo passwords, OTP seeds in
`otpauth` URIs, and direct credential-assignment literals. Their complete
trigger, candidate, exact-span, action, exclusion, and blind-spot definitions
are in the
[policy-based credential contracts](../specs/detector-families.md#policy-based-credential-contracts).

If the generated support matrix labels one `Stable · Policy qualified`, that
means protected evaluation found the bounded context/span/action promise
reliable enough under its named qualification profile. It does **not** mean
the value has a provider-documented format, that arbitrary values of the same
broad kind are detected, or that the family moved from T3 to T1/T2. A family
that misses any applicable gate remains `Provisional · Project policy`, with
the failed gates recorded by the benchmark source that generated the matrix.
The generated [support matrix](../support-matrix.md), not this explanatory
section, is authoritative for the current status.

## Built-in detectors

Every detector the built-in registry ships, the finding types it emits, and
its default policy class: `block` findings are blocked, `always-redact`
findings are redacted, and `confidence-gated` findings are redacted at high
confidence and warned at medium or low confidence. See
[safe integration](../guides/safe-integration.md) for what each action means
for your host. An organization-specific format that is not listed here can be added
as a [declarative ruleset](../guides/rulesets.md).

<!-- detector-inventory:start -->
120 built-in detectors emit 160 finding types. Generated from [`detector-inventory.json`](../coverage/detector-inventory.json) by `python3 -B scripts/generate-detector-inventory-docs.py`; do not edit by hand.

| Detector | Finding types | Default policy class | Schemes |
| --- | --- | --- | --- |
| `private-key` | `private_key` | `block` | — |
| `aws-access-key` | `aws_access_key_id` | `always-redact` | — |
| `aws-bedrock-long-term-api-key` | `aws_bedrock_long_term_api_key` | `always-redact` | — |
| `aws-bedrock-short-term-api-key` | `aws_bedrock_short_term_api_key` | `always-redact` | — |
| `aws-secret-access-key` | `aws_secret_access_key` | `always-redact` | — |
| `github-token` | `github_token`, `github_oauth_token`, `github_app_user_to_server_token`, `github_app_installation_token`, `github_app_refresh_token`, `github_fine_grained_personal_access_token` | `always-redact` | — |
| `gitlab-token` | `gitlab_token` | `always-redact` | — |
| `openai-token` | `openai_api_key`, `openai_admin_api_key` | `always-redact` | — |
| `anthropic-token` | `anthropic_api_key`, `anthropic_enterprise_api_key`, `anthropic_admin_api_key` | `always-redact` | — |
| `shopify-token` | `shopify_access_token` | `always-redact` | — |
| `vault-token` | `vault_token` | `always-redact` | — |
| `stripe-token` | `stripe_webhook_signing_secret`, `stripe_credential` | `always-redact` | — |
| `slack-token` | `slack_app_level_token`, `slack_user_token`, `slack_token` | `always-redact` | — |
| `pypi-token` | `pypi_api_token` | `always-redact` | — |
| `huggingface-token` | `huggingface_token` | `always-redact` | — |
| `docker-token` | `docker_token` | `always-redact` | — |
| `cloudflare-token` | `cloudflare_api_token` | `always-redact` | — |
| `digitalocean-token` | `digitalocean_token` | `always-redact` | — |
| `linear-token` | `linear_token` | `always-redact` | — |
| `supabase-token` | `supabase_secret_key` | `always-redact` | — |
| `supabase-management-token` | `supabase_personal_access_token` | `always-redact` | — |
| `vercel-token` | `vercel_token`, `vercel_personal_access_token`, `vercel_app_access_token`, `vercel_app_refresh_token` | `always-redact` | — |
| `npm-token` | `npm_access_token` | `always-redact` | — |
| `google-api-key` | `google_api_key` | `always-redact` | — |
| `google-oauth-client-secret` | `google_oauth_client_secret` | `always-redact` | — |
| `sendgrid-token` | `sendgrid_api_key` | `always-redact` | — |
| `microsoft-entra-client-secret` | `microsoft_entra_client_secret` | `always-redact` | — |
| `azure-devops-personal-access-token` | `azure_devops_personal_access_token` | `always-redact` | — |
| `notion-token` | `notion_integration_token` | `always-redact` | — |
| `atlassian-api-token` | `atlassian_api_token` | `always-redact` | — |
| `telegram-bot-token` | `telegram_bot_token` | `always-redact` | — |
| `jwt` | `jwt` | `always-redact` | — |
| `bearer-token` | `bearer_token` | `always-redact` | — |
| `connection-string` | `connection_string_password` | `always-redact` | `postgresql`, `postgres`, `mysql`, `mariadb`, `mongodb+srv`, `mongodb`, `redis`, `rediss`, `amqp`, `amqps`, `azure` |
| `otpauth-uri` | `otpauth_secret` | `always-redact` | `totp`, `hotp` |
| `generic-token` | `contextual_secret`, `authorization_credential`, `vendor_prefixed_credential` | `confidence-gated`, `always-redact` | `basic`, `token` |
| `discord-bot-token` | `discord_bot_token` | `always-redact` | — |
| `twilio-auth-token` | `twilio_auth_token` | `confidence-gated` | — |
| `twilio-api-key-secret` | `twilio_api_key_secret` | `confidence-gated` | — |
| `datadog-api-key` | `datadog_api_key` | `confidence-gated` | — |
| `datadog-application-key` | `datadog_application_key` | `always-redact` | — |
| `datadog-application-key-legacy` | `datadog_application_key_legacy` | `confidence-gated` | — |
| `grafana-service-account-token` | `grafana_service_account_token` | `always-redact` | — |
| `grafana-cloud-access-policy-token` | `grafana_cloud_access_policy_token` | `always-redact` | — |
| `sentry-user-auth-token` | `sentry_user_auth_token` | `always-redact` | — |
| `sentry-org-auth-token` | `sentry_org_auth_token` | `always-redact` | — |
| `new-relic-user-api-key` | `new_relic_user_api_key` | `always-redact` | — |
| `new-relic-license-key` | `new_relic_license_key` | `confidence-gated` | — |
| `mailchimp-api-key` | `mailchimp_api_key` | `confidence-gated` | — |
| `mailgun-api-key` | `mailgun_api_key` | `confidence-gated` | — |
| `okta-api-token` | `okta_api_token` | `confidence-gated` | — |
| `firebase-server-key` | `firebase_server_key` | `always-redact` | — |
| `terraform-cloud-token` | `terraform_cloud_token` | `always-redact` | — |
| `pulumi-access-token` | `pulumi_access_token` | `always-redact` | — |
| `replicate-api-token` | `replicate_api_token` | `always-redact` | — |
| `groq-api-key` | `groq_api_key` | `always-redact` | — |
| `xai-api-key` | `xai_api_key` | `always-redact` | — |
| `openrouter-api-key` | `openrouter_api_key` | `always-redact` | — |
| `perplexity-api-key` | `perplexity_api_key` | `always-redact` | — |
| `fireworks-ai-api-key` | `fireworks_ai_api_key` | `always-redact` | — |
| `elevenlabs-api-key` | `elevenlabs_api_key` | `always-redact` | — |
| `together-ai-api-key` | `together_ai_api_key` | `always-redact` | — |
| `tavily-api-key` | `tavily_api_key` | `always-redact` | — |
| `pinecone-api-key` | `pinecone_api_key` | `always-redact` | — |
| `gitlab-runner-authentication-token` | `gitlab_runner_authentication_token` | `always-redact` | — |
| `databricks-personal-access-token` | `databricks_personal_access_token` | `always-redact` | — |
| `confluent-cloud-api-secret` | `confluent_cloud_api_secret` | `always-redact` | — |
| `confluent-cloud-api-secret-legacy` | `confluent_cloud_api_secret_legacy` | `confidence-gated` | — |
| `netlify-token` | `netlify_personal_access_token` | `always-redact` | — |
| `neon-api-key` | `neon_api_key` | `always-redact` | — |
| `langsmith-api-key` | `langsmith_api_key` | `always-redact` | — |
| `langfuse-secret-key` | `langfuse_secret_key` | `always-redact` | — |
| `postman-api-key` | `postman_api_key` | `always-redact` | — |
| `postman-collection-access-key` | `postman_collection_access_key` | `always-redact` | — |
| `heroku-api-key` | `heroku_api_key` | `always-redact` | — |
| `heroku-api-key-legacy` | `heroku_api_key_legacy` | `confidence-gated` | — |
| `travisci-api-token` | `travisci_api_token` | `confidence-gated` | — |
| `mistral-api-key` | `mistral_api_key` | `confidence-gated` | — |
| `cohere-api-key` | `cohere_api_key` | `confidence-gated` | — |
| `ai21-api-key` | `ai21_api_key` | `confidence-gated` | — |
| `deepgram-api-key` | `deepgram_api_key` | `confidence-gated` | — |
| `doppler-token` | `doppler_service_token`, `doppler_personal_token`, `doppler_cli_token`, `doppler_service_account_token`, `doppler_service_account_identity_token`, `doppler_scim_token`, `doppler_audit_token` | `always-redact` | — |
| `trigger-dev-token` | `trigger_dev_secret_api_key`, `trigger_dev_personal_access_token` | `always-redact` | — |
| `e2b-api-key` | `e2b_api_key` | `always-redact` | — |
| `posthog-token` | `posthog_personal_api_key`, `posthog_project_secret_api_key` | `always-redact` | — |
| `helicone-api-key` | `helicone_api_key`, `helicone_write_api_key` | `always-redact` | — |
| `firecrawl-api-key` | `firecrawl_api_key` | `always-redact` | — |
| `composio-api-key` | `composio_project_api_key`, `composio_org_api_key`, `composio_user_api_key` | `always-redact` | — |
| `convex-deployment-key` | `convex_deployment_key` | `always-redact` | — |
| `onepassword-service-account-token` | `onepassword_service_account_token` | `always-redact` | — |
| `inngest-signing-key` | `inngest_signing_key` | `always-redact` | — |
| `resend-api-key` | `resend_api_key` | `always-redact` | — |
| `apify-api-token` | `apify_api_token` | `always-redact` | — |
| `wandb-api-key` | `wandb_api_key` | `always-redact` | — |
| `daytona-api-key` | `daytona_api_key` | `always-redact` | — |
| `clickhouse-cloud-api-secret` | `clickhouse_cloud_api_secret` | `always-redact` | — |
| `nvidia-api-key` | `nvidia_api_key` | `always-redact` | — |
| `browserbase-api-key` | `browserbase_api_key` | `always-redact` | — |
| `runpod-api-key` | `runpod_api_key` | `always-redact` | — |
| `cerebras-api-key` | `cerebras_api_key` | `always-redact` | — |
| `bitwarden-secrets-manager-access-token` | `bitwarden_secrets_manager_access_token` | `always-redact` | — |
| `polar-token` | `polar_organization_access_token`, `polar_api_credential` | `always-redact` | — |
| `sonarqube-token` | `sonarqube_user_token`, `sonarqube_analysis_token` | `always-redact` | — |
| `rubygems-api-key` | `rubygems_api_key` | `always-redact` | — |
| `clojars-deploy-token` | `clojars_deploy_token` | `always-redact` | — |
| `crates-io-token` | `crates_io_api_token`, `crates_io_trusted_publishing_token` | `always-redact` | — |
| `dynatrace-token` | `dynatrace_token` | `always-redact` | — |
| `paddle-api-key` | `paddle_api_key` | `always-redact` | — |
| `honeycomb-api-key` | `honeycomb_ingest_key` | `always-redact` | — |
| `axiom-token` | `axiom_api_token`, `axiom_personal_token` | `always-redact` | — |
| `xata-api-key` | `xata_user_api_key`, `xata_organization_api_key` | `always-redact` | — |
| `sourcegraph-token` | `sourcegraph_access_token` | `always-redact` | — |
| `unkey-root-key` | `unkey_root_key` | `always-redact` | — |
| `buildkite-token` | `buildkite_api_access_token`, `buildkite_oauth_token`, `buildkite_agent_token`, `buildkite_job_token`, `buildkite_packages_token`, `buildkite_pipeline_token`, `buildkite_portal_token` | `always-redact` | — |
| `pydantic-logfire-token` | `pydantic_logfire_token` | `always-redact` | — |
| `square-token` | `square_access_token`, `square_oauth_application_secret` | `always-redact` | — |
| `mapbox-token` | `mapbox_secret_access_token` | `always-redact` | — |
| `fly-token` | `fly_access_token` | `always-redact` | — |
| `ory-token` | `ory_session_token`, `ory_oauth2_token` | `always-redact` | — |
| `baseten-api-key` | `baseten_api_key` | `always-redact` | — |
<!-- detector-inventory:end -->

## Detector profiles

`full` — every detector in the table above, the default and compatibility
baseline on every surface — stays the first and simplest path. Keep the
authoritative server boundary on `full`.

`common` is a smaller, opt-in built-in set for size- or latency-sensitive
**preventive** consumers (browser UX, small agent or tool processes): only the
structural and contextual detectors — a PEM/OpenSSH private key, an RFC 7519
JWT, an `otpauth://` URI, a credential-bearing connection URI, an HTTP
`Bearer` header, and the generic credential-assignment context detector —
not any one issuer's token format. It omits the provider credentials entirely.
Node and the browser expose it as `@redact-secret/core/common`
([JavaScript guide](../guides/javascript.md#detector-profiles)) and Rust as
`DetectorRegistry::with_common_built_in`
([Rust guide](../guides/rust.md#detector-profiles)). Switch by changing the
import, or the Rust constructor:

```ts
import { initialize, scanAndRedact } from "@redact-secret/core/common";
```

```rust
let registry = DetectorRegistry::with_common_built_in(std::iter::empty())?;
```

Python and the CLI stay `full` only — the CLI is a pre-commit/CI enforcement
tool, where a smaller profile would only weaken enforcement.

`common`'s false-negative tradeoff is on provider tokens specifically: a bare
provider token (for example a raw GitHub or AWS credential, with no
surrounding `Bearer` header or contextual assignment) is not detected at all,
and a provider token that *is* caught by a `common` detector's context is
reported under that detector's type and confidence instead of the
provider-specific one — for example `warn` where `full` would `redact`. It
adds no false positive: it only drops candidates `full` would have reported.
Measured against `full` over the whole canonical corpus, `common` saves about
30% transfer size (default builds of the Beta.12 candidate, 205,068 → 142,525 B
gzip level 9) and processes 3–6× faster in the browser, with zero new
false positives and identical findings wherever no provider detector would
have competed ([evidence](https://github.com/redact-secret/redact-secret/blob/2816897f96c405c3eb8c87a0c70eba5df273c121/docs/audits/evidence/382/README.md)).

The `@redact-secret/core/web-stream` and `@redact-secret/core/node-stream`
convenience factories always open a `full` session; a `common` byte stream
uses the `@redact-secret/core/common/web-stream` and
`@redact-secret/core/common/node-stream` subpaths instead. See
[streaming under the `common` profile](../guides/streaming.md#streaming-under-the-common-profile).

## False positives and false negatives

Strict prefixes, minimum lengths, bounded grammars, and placeholder exclusions
favor precision. Synthetic text that imitates a supported credential can still
match; detection cannot establish that it is real. A harmless assignment to a
credential-like name can also be classified from context.

Truncated, unusually short, new, unsupported, encoded, or differently formatted
credentials may be missed. Entropy is supporting evidence, never a standalone
reason to redact arbitrary random-looking text. The generic name `token` alone
is deliberately ignored. Input is not generally decoded or normalized before
detection because that would change lexical meaning and original coordinates.

An empty result means no supported pattern matched. It does not certify that
text is secret-free. This is not a general DLP or repository-history scanner.
Whole-input `scan`, `redact`, and `scan_and_redact` default to a 64 MiB input
bound and a 50,000 finding-count bound, failing closed with a fixed
`INPUT_LIMIT_EXCEEDED`/`FINDING_LIMIT_EXCEEDED` error rather than a truncated
result (`decision-bound-whole-input-operations-by-default`). A caller that
genuinely needs a wider bound raises it explicitly (`scan_with_limits` and its
siblings in Rust, a `limits` option in every binding). This is a
library-level backstop, not a substitute for host-side bounding:
authoritative servers must still bound transport bytes, decoded input,
sanitized output, concurrency, and memory before downstream use. See
[safe integration](../guides/safe-integration.md).

To report a missed detection or false positive, provide a minimal synthetic
reproducer, the runtime and product version, and expected safe metadata. Never
include an active credential in an issue, test, log, or screenshot.
