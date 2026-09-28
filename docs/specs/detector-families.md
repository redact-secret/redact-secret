# Detector families

Rules governing individual provider/credential family grammars: what a detector matches, what it excludes, and which shape is frozen as the reviewed contract.

> Generated for [issue #597](https://github.com/redact-secret/redact-secret/issues/597) (DS6a). Each rule
> below states current behavior in the present tense and links the ADR
> (`docs/decisions/`) that decided it. An ADR records why and when; this file
> records what is true now. Per
> [`decision-decide-artifact-taxonomy-spec-routing-and-evidence-placement`](../decisions/2026-09-22-decide-artifact-taxonomy-spec-routing-and-evidence-placement.md),
> a decision that applies an existing policy to one more provider family or
> one more instance is a row here plus its supporting evidence, not a new
> ADR.

## Finding types

<!-- detector-families:start -->
Generated from [`docs/coverage/detector-inventory.json`](../coverage/detector-inventory.json) by `python3 -B scripts/generate-detector-families-table.py`; the rows and the first three columns are checked against the inventory. Only the Governing ADR column is edited by hand.

| Type | Detector | Policy class | Governing ADR |
| --- | --- | --- | --- |
| `ai21_api_key` | `ai21-api-key` | `confidence-gated` | no dedicated ADR in this repository; contextual, unqualified claim stated under Keyword-gated provider keys below, per issue #868 |
| `anthropic_admin_api_key` | `anthropic-token` | `always-redact` | generic policy default, no dedicated ADR in this repository; issue #774 splits the `sk-ant-admin01-` prefix (Console Admin API key, full access to every Admin-API endpoint) out of the shared `anthropic_api_key` type, following the precedent [Map GitHub's six token families onto six independent finding types under one detector](../decisions/2026-09-20-map-github-token-families-onto-independent-finding-types.md); research in [#775](https://github.com/redact-secret/redact-secret/issues/775) |
| `anthropic_api_key` | `anthropic-token` | `always-redact` | generic policy default, no dedicated ADR in this repository; T1 provider source recorded in [#642 evidence](../audits/evidence/642/README.md); issue #862 extended `anthropic-token`'s prefix set from `sk-ant-api03-` alone to also `sk-ant-api01-` and `sk-ant-admin01-`, all under this one type at the time. Issue #774 then split those two prefixes into their own types (`anthropic_enterprise_api_key`, `anthropic_admin_api_key`); `anthropic_api_key` now covers `sk-ant-api03-` only, unchanged: the same `>= 20` byte `[A-Za-z0-9_-]` run with a left boundary, a deliberate superset of the T2 scanner shape of 93 bytes plus `AA`. False-positive tradeoff: a doc placeholder of 20 or more valid body bytes (for example a long `x` run) matches |
| `anthropic_enterprise_api_key` | `anthropic-token` | `always-redact` | generic policy default, no dedicated ADR in this repository; issue #774 splits the `sk-ant-api01-` prefix out of the shared `anthropic_api_key` type. Named for its general Enterprise organization scope (user management, Compliance, Analytics, Spend Limits — selected at creation), not "compliance": [#776](https://github.com/redact-secret/redact-secret/issues/776) records that `sk-ant-api01-` covers all of those scopes, not the Compliance Access Key alone. Follows the same split precedent as [Map GitHub's six token families onto six independent finding types under one detector](../decisions/2026-09-20-map-github-token-families-onto-independent-finding-types.md) |
| `atlassian_api_token` | `atlassian-api-token` | `always-redact` | [Freeze the Atlassian Cloud API token grammar as a minimum-length ATAT-prefixed body](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| `authorization_credential` | `generic-token` | `always-redact` | generic policy default, no dedicated ADR in this repository |
| `aws_access_key_id` | `aws-access-key` | `always-redact` | generic policy default, no dedicated ADR in this repository |
| `aws_bedrock_long_term_api_key` | `aws-bedrock-long-term-api-key` | `always-redact` | generic policy default, no dedicated ADR in this repository; grammar in `detectors::aws_bedrock`'s module doc, `ABSK` + standard Base64 with `={0,2}` padding (T1, maintainer ruling accepted 2026-09-27 on the AWS Security Blog scan pattern, [#778](https://github.com/redact-secret/redact-secret/issues/778)), 109-269 body bytes (T2), recorded in [#864 evidence](../audits/evidence/864/README.md) |
| `aws_bedrock_short_term_api_key` | `aws-bedrock-short-term-api-key` | `always-redact` | generic policy default, no dedicated ADR in this repository; two families rather than one (client-minted presigned URL vs issued credential), `bedrock-api-key-` prefix + fixed 133-byte Base64 head + standard Base64 alphabet (T1, maintainer ruling accepted 2026-09-27 on the AWS token-generator SDKs (python/js/java) plus the AWS Security Blog, [#779](https://github.com/redact-secret/redact-secret/issues/779)), tail floor and total length T2, recorded in [#864 evidence](../audits/evidence/864/README.md) |
| `azure_devops_personal_access_token` | `azure-devops-personal-access-token` | `always-redact` | [Freeze the Azure DevOps personal access token grammar as the documented 84-byte AZDO-signature shape](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md); T1 provider source recorded in [#642 evidence](../audits/evidence/642/README.md) |
| `bearer_token` | `bearer-token` | `always-redact` | [Accept a truncated or nested-provider Bearer value under bearer-token's length-and-alphabet grammar](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| `cloudflare_api_token` | `cloudflare-token` | `always-redact` | [Adopt the Cloudflare account-token prefix under the frozen cfut_ contract](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| `cohere_api_key` | `cohere-api-key` | `confidence-gated` | no dedicated ADR in this repository; contextual, unqualified claim stated under Keyword-gated provider keys below, per issue #868 |
| `confluent_cloud_api_secret` | `confluent-cloud-api-secret` | `always-redact` | generic policy default, no dedicated ADR in this repository |
| `confluent_cloud_api_secret_legacy` | `confluent-cloud-api-secret-legacy` | `confidence-gated` | generic policy default, no dedicated ADR in this repository |
| `connection_string_password` | `connection-string` | `always-redact` | [Exclude a value fully delimited by `{{` and `}}` as a template reference](../decisions/2026-09-15-exclude-fully-delimited-template-references.md#folded-records) (folded: `decision-connection-string-and-jwt-need-no-retention-hint`) |
| `contextual_secret` | `generic-token` | `confidence-gated` | generic policy default, no dedicated ADR in this repository |
| `databricks_personal_access_token` | `databricks-personal-access-token` | `always-redact` | generic policy default, no dedicated ADR in this repository |
| `datadog_api_key` | `datadog-api-key` | `confidence-gated` | [Freeze the Datadog API Key and Application Key grammar as marker-gated lowercase-hex values](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| `datadog_application_key` | `datadog-application-key` | `always-redact` | generic policy default, no dedicated ADR in this repository; current `ddapp_`-prefixed shape added by issue #671, applying the existing `confluent_cloud_api_secret` / `heroku_api_key` current/legacy split policy to this family |
| `datadog_application_key_legacy` | `datadog-application-key-legacy` | `confidence-gated` | [Freeze the Datadog API Key and Application Key grammar as marker-gated lowercase-hex values](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| `deepgram_api_key` | `deepgram-api-key` | `confidence-gated` | no dedicated ADR in this repository; contextual, unqualified claim stated under Keyword-gated provider keys below, per issue #868 |
| `digitalocean_token` | `digitalocean-token` | `always-redact` | generic policy default, no dedicated ADR in this repository |
| `discord_bot_token` | `discord-bot-token` | `always-redact` | [Freeze the Discord bot token grammar as a three-segment digit-decoding snowflake token](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| `docker_token` | `docker-token` | `always-redact` | [Freeze the Docker Hub access token grammar as two separately-sized exact-length prefixed shapes](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| `elevenlabs_api_key` | `elevenlabs-api-key` | `always-redact` | generic policy default, no dedicated ADR in this repository |
| `firebase_server_key` | `firebase-server-key` | `always-redact` | [Add Firebase FCM legacy server key detection, and discriminate the public Web SDK client config from google-api-key](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| `fireworks_ai_api_key` | `fireworks-ai-api-key` | `always-redact` | generic policy default, no dedicated ADR in this repository |
| `github_app_installation_token` | `github-token` | `always-redact` | [Map GitHub's six token families onto six independent finding types under one detector](../decisions/2026-09-20-map-github-token-families-onto-independent-finding-types.md) |
| `github_app_refresh_token` | `github-token` | `always-redact` | [Map GitHub's six token families onto six independent finding types under one detector](../decisions/2026-09-20-map-github-token-families-onto-independent-finding-types.md) |
| `github_app_user_to_server_token` | `github-token` | `always-redact` | [Map GitHub's six token families onto six independent finding types under one detector](../decisions/2026-09-20-map-github-token-families-onto-independent-finding-types.md) |
| `github_fine_grained_personal_access_token` | `github-token` | `always-redact` | [Map GitHub's six token families onto six independent finding types under one detector](../decisions/2026-09-20-map-github-token-families-onto-independent-finding-types.md) |
| `github_oauth_token` | `github-token` | `always-redact` | [Map GitHub's six token families onto six independent finding types under one detector](../decisions/2026-09-20-map-github-token-families-onto-independent-finding-types.md) |
| `github_token` | `github-token` | `always-redact` | [Map GitHub's six token families onto six independent finding types under one detector](../decisions/2026-09-20-map-github-token-families-onto-independent-finding-types.md) |
| `gitlab_runner_authentication_token` | `gitlab-runner-authentication-token` | `always-redact` | generic policy default, no dedicated ADR in this repository |
| `gitlab_token` | `gitlab-token` | `always-redact` | [Inventory the GitLab token-prefix table and contract the two undeclared prefixes; record routable tokens and the legacy runner-registration token as explicit, tracked gaps](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| `google_api_key` | `google-api-key` | `always-redact` | [Redact a Google API key inside a Firebase Web SDK client config, reversing the client-config exemption](../decisions/2026-09-24-redact-google-api-keys-inside-firebase-web-config.md); T1 provider source recorded in [#642 evidence](../audits/evidence/642/README.md) |
| `grafana_cloud_access_policy_token` | `grafana-cloud-access-policy-token` | `always-redact` | [Freeze the Grafana service account and Cloud access policy token grammar, and exclude the legacy API key](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md); T1 provider source recorded in [#642 evidence](../audits/evidence/642/README.md) |
| `grafana_service_account_token` | `grafana-service-account-token` | `always-redact` | [Freeze the Grafana service account and Cloud access policy token grammar, and exclude the legacy API key](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md); T1 provider source recorded in [#642 evidence](../audits/evidence/642/README.md) |
| `groq_api_key` | `groq-api-key` | `always-redact` | generic policy default, no dedicated ADR in this repository |
| `heroku_api_key` | `heroku-api-key` | `always-redact` | generic policy default, no dedicated ADR in this repository; issue #740 adds the documented 41-character `HRKU-` + lower-case UUID generation beside `HRKU-AA` + 58, grammar in `detectors::heroku`'s module doc |
| `heroku_api_key_legacy` | `heroku-api-key-legacy` | `confidence-gated` | generic policy default, no dedicated ADR in this repository; issue #714 excludes a UUID assigned to an identifier-shaped key (last word `id` or `uuid`, e.g. `HEROKU_APP_ID`) from the `heroku` keyword gate, grammar in `detectors::heroku`'s module doc; issue #743 also accepts two documented multi-line layouts (a Heroku `.netrc` entry's `password`, `heroku auth:token` output, held open by an incremental retention hint) and excludes a UUID that is a URL path segment |
| `huggingface_token` | `huggingface-token` | `always-redact` | [Adopt the Hugging Face organization-token prefix under hf_'s frozen body grammar, re-tiered to T2](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| `jwt` | `jwt` | `always-redact` | [Exclude a value fully delimited by `{{` and `}}` as a template reference](../decisions/2026-09-15-exclude-fully-delimited-template-references.md#folded-records) (folded: `decision-connection-string-and-jwt-need-no-retention-hint`) |
| `langfuse_secret_key` | `langfuse-secret-key` | `always-redact` | generic policy default, no dedicated ADR in this repository |
| `langsmith_api_key` | `langsmith-api-key` | `always-redact` | generic policy default, no dedicated ADR in this repository |
| `linear_token` | `linear-token` | `always-redact` | generic policy default, no dedicated ADR in this repository; T1 provider source recorded in [#642 evidence](../audits/evidence/642/README.md) |
| `mailchimp_api_key` | `mailchimp-api-key` | `confidence-gated` | no dedicated ADR in this repository; grammar frozen in `detectors::mailchimp`'s own module doc, per issue #313 |
| `mailgun_api_key` | `mailgun-api-key` | `confidence-gated` | no dedicated ADR in this repository; grammar frozen in `detectors::mailgun`'s own module doc, per issue #314 |
| `microsoft_entra_client_secret` | `microsoft-entra-client-secret` | `always-redact` | [Freeze the Microsoft Entra application client-secret grammar as an unprefixed digit-Q-tilde marker](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| `mistral_api_key` | `mistral-api-key` | `confidence-gated` | no dedicated ADR in this repository; contextual, unqualified claim stated under Keyword-gated provider keys below, per issue #868 |
| `neon_api_key` | `neon-api-key` | `always-redact` | generic policy default, no dedicated ADR in this repository |
| `netlify_personal_access_token` | `netlify-token` | `always-redact` | generic policy default, no dedicated ADR in this repository |
| `new_relic_license_key` | `new-relic-license-key` | `confidence-gated` | [Freeze the New Relic User API Key and License Key grammar as an exact-length prefixed shape and a keyword-gated bare hex shape](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| `new_relic_user_api_key` | `new-relic-user-api-key` | `always-redact` | [Freeze the New Relic User API Key and License Key grammar as an exact-length prefixed shape and a keyword-gated bare hex shape](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md); T1 provider source recorded in [#642 evidence](../audits/evidence/642/README.md) |
| `notion_integration_token` | `notion-token` | `always-redact` | [Freeze the Notion integration token grammar as two exact-length prefixed shapes](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md); T1 provider source recorded in [#642 evidence](../audits/evidence/642/README.md) |
| `npm_access_token` | `npm-token` | `always-redact` | generic policy default, no dedicated ADR in this repository |
| `okta_api_token` | `okta-api-token` | `confidence-gated` | no dedicated ADR in this repository; grammar frozen in `detectors::okta`'s own module doc, per issue #315 |
| `openai_admin_api_key` | `openai-token` | `always-redact` | generic policy default, no dedicated ADR in this repository; issue #774 splits the `sk-admin-` namespace out of the shared `openai_api_key` type (materially different blast radius: an organization Admin API key, not a project/service-account key). Grammar untouched: still the T2 marker-gated 58/74-byte contract from [#863](https://github.com/redact-secret/redact-secret/issues/863), [Freeze the OpenAI API key grammar as a marker-gated shape with exact segment lengths](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| `openai_api_key` | `openai-token` | `always-redact` | [Freeze the OpenAI API key grammar as a marker-gated shape with exact segment lengths](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| `openrouter_api_key` | `openrouter-api-key` | `always-redact` | generic policy default, no dedicated ADR in this repository |
| `otpauth_secret` | `otpauth-uri` | `always-redact` | generic policy default, no dedicated ADR in this repository |
| `perplexity_api_key` | `perplexity-api-key` | `always-redact` | generic policy default, no dedicated ADR in this repository |
| `pinecone_api_key` | `pinecone-api-key` | `always-redact` | [Claim a legacy Pinecone UUID key only under a Pinecone API-key name, and redact it](../decisions/2026-09-24-claim-a-legacy-pinecone-uuid-key-only-under-its-api-key-name.md) |
| `postman_api_key` | `postman-api-key` | `always-redact` | generic policy default, no dedicated ADR in this repository |
| `postman_collection_access_key` | `postman-collection-access-key` | `always-redact` | generic policy default, no dedicated ADR in this repository |
| `private_key` | `private-key` | `block` | generic policy default, no dedicated ADR in this repository |
| `pulumi_access_token` | `pulumi-access-token` | `always-redact` | [Freeze the Pulumi access token grammar as a documented-prefix, tool-corroborated exact-length hex shape](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| `pypi_api_token` | `pypi-token` | `always-redact` | generic policy default, no dedicated ADR in this repository |
| `replicate_api_token` | `replicate-api-token` | `always-redact` | generic policy default, no dedicated ADR in this repository |
| `sendgrid_api_key` | `sendgrid-token` | `always-redact` | generic policy default, no dedicated ADR in this repository |
| `sentry_org_auth_token` | `sentry-org-auth-token` | `always-redact` | [Freeze the Sentry user and organization auth token grammar as two unambiguous prefixed shapes](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| `sentry_user_auth_token` | `sentry-user-auth-token` | `always-redact` | [Freeze the Sentry user and organization auth token grammar as two unambiguous prefixed shapes](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| `shopify_access_token` | `shopify-token` | `always-redact` | generic policy default, no dedicated ADR in this repository |
| `slack_app_level_token` | `slack-token` | `always-redact` | generic policy default, no dedicated ADR in this repository |
| `slack_token` | `slack-token` | `always-redact` | [Freeze the Slack bot token grammar as a three-section dash-separated shape](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| `slack_user_token` | `slack-token` | `always-redact` | generic policy default, no dedicated ADR in this repository |
| `stripe_credential` | `stripe-token` | `always-redact` | generic policy default, no dedicated ADR in this repository |
| `stripe_webhook_signing_secret` | `stripe-token` | `always-redact` | generic policy default, no dedicated ADR in this repository |
| `supabase_personal_access_token` | `supabase-management-token` | `always-redact` | [Separate the Supabase management-token credential class from the secret-key class, and keep each class's evidence independent](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| `supabase_secret_key` | `supabase-token` | `always-redact` | [Separate the Supabase management-token credential class from the secret-key class, and keep each class's evidence independent](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| `tavily_api_key` | `tavily-api-key` | `always-redact` | generic policy default, no dedicated ADR in this repository; `tvly-` prefix T1 (Tavily docs), body T2, grammar and trade-offs in [Together AI and Tavily (#867)](#together-ai-and-tavily-867) |
| `telegram_bot_token` | `telegram-bot-token` | `always-redact` | [Freeze the Telegram Bot API token grammar as a minimum-length digit-colon-secret shape](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| `terraform_cloud_token` | `terraform-cloud-token` | `always-redact` | [Add Terraform Cloud/Enterprise API token detection](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| `together_ai_api_key` | `together-ai-api-key` | `always-redact` | generic policy default, no dedicated ADR in this repository; T2 (no provider source states the shape), grammar and trade-offs in [Together AI and Tavily (#867)](#together-ai-and-tavily-867) |
| `travisci_api_token` | `travisci-api-token` | `confidence-gated` | generic policy default, no dedicated ADR in this repository |
| `twilio_api_key_secret` | `twilio-api-key-secret` | `confidence-gated` | [Freeze the Twilio Auth Token and API Key Secret grammar as context-gated 32-byte values](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| `twilio_auth_token` | `twilio-auth-token` | `confidence-gated` | [Freeze the Twilio Auth Token and API Key Secret grammar as context-gated 32-byte values](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| `vault_token` | `vault-token` | `always-redact` | generic policy default, no dedicated ADR in this repository |
| `vendor_prefixed_credential` | `generic-token` | `always-redact` | [Redact a bare, marker-less OpenAI-prefixed value under a generic policy layer, beneath the frozen contract](../decisions/2026-09-21-govern-bare-vendor-prefixed-policy-layer.md) |
| `vercel_token` | `vercel-token` | `always-redact` | generic policy default, no dedicated ADR in this repository |
| `xai_api_key` | `xai-api-key` | `always-redact` | generic policy default, no dedicated ADR in this repository |
<!-- detector-families:end -->

## Policy-based credential contracts

These four generic families remain T3 with `project-policy` evidence. Their
supported promise is the bounded context, value, span, and default action
below, not a claim that the value has a provider-issued lexical identity. A
future `policy-qualified` result may make one of these families stable only by
testing this promise; it does not relabel the family T1 or T2. The generated
[support matrix](../support-matrix.md) remains the only source of each
family's current status.

| Family | Supported trigger and value | Exact span and default action | Exclusions and known blind spots | Product evidence |
| --- | --- | --- | --- | --- |
| `generic:bearer-token` | A case-insensitive `Bearer` scheme followed by SP or HTAB, either after an explicit `Authorization:` / `Proxy-Authorization:` header name or in the detector's bounded free-text carrier context. The current RFC 6750 `b64token` alphabet is accepted with at most two trailing `=` bytes. An explicit header lowers the project-policy value floor from 16 bytes to 12; the RFC defines neither floor. | The credential value only, including accepted trailing padding; `bearer_token`, high confidence, default `redact`. RFC 6750 supports the carrier and alphabet, while the floors, HTAB, padding cap, and free-text context are project policy. | Whole-value placeholders, instructional placeholders, repeated filler, wider identifiers, and a newline between scheme and value are excluded. Short values and unsupported encodings are blind spots. RFC 8959 `secret-token:` URI detection is a separate shape outside this claim. | Research [#650](../audits/evidence/650/README.md); exact-span and context cases `bearer-positive-scheme`, `bearer-positive-authorization-extra-whitespace-and-case`, `bearer-token-regression-proxy-authorization-header`; benign/boundary cases `bearer-negative-placeholder-whole-value`, `bearer-boundary-newline-separator`. |
| `generic:connection-string-password` | One case-insensitive URI scheme from `postgresql`, `postgres`, `mysql`, `mariadb`, `mongodb+srv`, `mongodb`, `redis`, `rediss`, `amqp`, `amqps`, `https`, `http`, `ftps`, or `ftp`; exactly one userinfo `@`; a valid scheme-specific host; and a non-empty password after `:`. Redis and Rediss also accept password-only userinfo. Percent escapes must be valid and are not decoded. | The original undecoded password substring only; `connection_string_password`, high confidence, default `redact`. | Empty, placeholder, filler, tutorial prose, and recognized reference/template values are excluded, as are malformed encodings or hosts, multiple `@` bytes, unsupported schemes, and over-bound authorities or values. Query/property password forms are blind spots. Azure Storage `AccountKey` is a separate semicolon-delimited grammar emitted by the same detector and is outside this userinfo claim. | Research [#651](../audits/evidence/651/README.md); exact-span and context cases `connection-positive-postgres`, `connection-positive-redis-password-only`, `connection-regression-https-userinfo-percent-encoded-password`; benign/boundary cases `connection-negative-host-only`, `connection-boundary-placeholder`, `connection-negative-malformed-percent`. |
| `generic:otp-seed` | A literal lowercase `otpauth://totp/` or `otpauth://hotp/` envelope whose first exact lowercase `secret` query parameter is an uppercase RFC 4648 Base32 run of at least 16 characters followed by optional `=` padding. The envelope and Base32 alphabet have external documentation; case, the length floor, and accepted padding are project choices. | The first secret value only, including padding; `otpauth_secret`, high confidence, default `redact`. | Bare seeds, lowercase or mixed-case values, encoded padding, an unsupported or differently cased scheme/type/key, an invalid first `secret` value, and a duplicate URI whose first `secret` is invalid are excluded or blind. The detector never falls through to a later duplicate. | Research [#652](../audits/evidence/652/README.md); exact-span and context cases `otpauth-positive-totp-minimal`, `otpauth-positive-hotp-minimal`, `otpauth-positive-duplicate-secret-first-wins`; benign/boundary cases `otpauth-negative-bare-base32-identifier-no-scheme`, `otpauth-boundary-invalid-base32-alphabet`, `otpauth-boundary-percent-encoded-padding-tradeoff`. |
| `generic:unclassified-assignment-literal` | A direct literal assigned with `=`, `:`, or `:=` to the built-in high-signal or ambiguous name vocabulary, including its documented normalization and generic-prefix rules; URL query/form names use the separately bounded query path. Values are 8–4096 bytes. This does not cover arbitrary assignments. | The value only. A high-signal name emits `contextual_secret` at high confidence and default `redact` only when the existing bounded high-confidence value contract is met; otherwise it emits medium confidence and default `warn`. An ambiguous name must meet the stronger value contract, remains medium confidence, and defaults to `warn`. `block` is never promised. | Whole-value placeholders, references/interpolations, secret-manager/keychain references, SQL binds, source-code expressions, filler and masks, public identifiers, provider-owned names, unsupported names, and non-literal expressions are excluded. Unsupported operators and a real credential under an unrecognized name remain blind spots. | Research [#653](../audits/evidence/653/README.md); exact-span/action cases `contextual-positive-assignment`, `contextual-positive-minimum-length-is-medium-confidence`, `contextual-positive-remaining-declared-names`; benign cases `contextual-negative-shell-placeholder`, `contextual-negative-django-settings-attribute-reference`, `contextual-negative-repeated-asterisk-filler`. |

The cited cases are representative, not a second corpus. They live in
[`conformance/fixtures/synchronous-corpus.json`](../../conformance/fixtures/synchronous-corpus.json),
whose exact UTF-8 spans, confidence, detector, and type feed the shared default
policy and redaction contract. The applicable Rust, Node.js, browser
WebAssembly, Python, and CLI lanes are described in the
[conformance contract](../../conformance/README.md). Existing Unicode, CRLF,
incremental, overlap, and adversarial cases continue to apply. New fixtures
belong here only for a reviewed behavior gap; benchmark-only variants and raw
qualification evidence stay in `redact-secret-benchmarks`.

## Structured PII status

The
[bounded built-in structured-validator registry](../decisions/2026-09-26-define-the-bounded-built-in-structured-validator-registry.md)
is shared core infrastructure, not a detector family. It supplies versioned
Luhn, IBAN mod-97, and US SSN allocation type-validation primitives to built-in
PII detectors. The IBAN family calls `iban-mod97` v1 after its own bounded
display normalization; US SSN calls `us-ssn-allocation` v1 on nine normalized
ASCII digits. A primitive itself still does not scan input, emit a finding,
decide sensitivity, or change a policy action. None is available through
declarative ruleset v1, and the detector inventory continues to expose the
single `pii-domain` adapter.

The false-positive boundary is deliberate: a checksum-valid value may be an
identifier-shaped coincidence, so each detector must evaluate the PII context
contract independently. The false-negative boundary is also explicit:
malformed, overlong, lower-case or separator-bearing candidates are rejected
by these v1 primitives unless a detector performs a separately specified
normalization before validation.

`pii:global:email` applies the existing PII policy through the one
`pii-domain` adapter. Its exact selector is `pii:family:global:email`, public
type is `pii_global_email`, family-contract version is `1`, and
`contextRequirement` is `required-for-sensitive-classification`. The supported
RFC 5322 / RFC 6531 subset, Unicode and byte bounds, whole-domain RFC 2606/6761
negative grammars, safe-fixture split, and false-positive/false-negative costs
are frozen in the [email family contract](../contracts/pii/email-v1.md). A
reviewed email field label glued to the address by `=` (`email=`,
`customer_email=`, `이메일=`) is split off as a label rather than read as
local part, so a logfmt or `.env` record is labelled
([#926](https://github.com/redact-secret/redact-secret/issues/926)). This
row applies the accepted cross-family PII policy to one family and therefore
does not create a new ADR. Its support state remains `pending` until the exact
merged artifact's benchmark evidence is reviewed.

`pii:global:iban` likewise uses the one `pii-domain` adapter. Its exact
selector is `pii:family:global:iban`, public type is `pii_global_iban`,
family-contract version is `1`, and `contextRequirement` is
`required-for-sensitive-classification`. The
[IBAN family contract](../contracts/pii/iban-v1.md) pins SWIFT Registry Release
103 country lengths and `iban-mod97` v1 provenance, bounded compact/print
normalization, sensitivity semantics, safe fixtures, and false-positive and
false-negative costs. This applies existing PII policy to one family and adds
no ADR. Its support state remains `pending` until exact merged-artifact
benchmark evidence is reviewed.

`pii:global:payment-card` applies the same policy through `pii-domain`. Its
exact selector is `pii:family:global:payment-card`, public type is
`pii_global_payment_card`, family-contract version is `1`, and
`contextRequirement` is `required-for-sensitive-classification`. It recognizes
the frozen ISO/IEC 7812 and payment-brand range subset only after a Luhn v1 pass
and reviewed payment-card field context. Only compact values and the explicit
`4-4-4-4` / `4-6-5` display layouts are supported; exact published test-service
PANs are whole-value non-sensitive controls. The full grammar, sources, bounded
normalization, and collision costs are frozen in the
[payment-card family contract](../contracts/pii/payment-card-v1.md). This row
applies existing policy and creates no ADR. Its support state remains `pending`
until the exact merged artifact's benchmark evidence is reviewed.

`pii:global:phone` applies the same policy through `pii-domain`. Its exact
selector is `pii:family:global:phone`, public type is `pii_global_phone`,
family-contract version is `1`, and `contextRequirement` is
`required-for-sensitive-classification`. V1 recognizes only the frozen `+1` /
NANP display and extension subset; a reviewed English/Korean phone field or
properly associated shared `contact details` phrase is required for
sensitivity. Ambiguous `contact` / `연락처` cannot promote a candidate. Exact
whole-candidate `555-01xx` exchange/line values are non-sensitive controls.
The full typed authority, grammar, safe-fixture plan, and deliberately severe
false-negative boundary are frozen in the
[phone family contract](../contracts/pii/phone-v1.md). This row applies
existing policy and creates no ADR. Its support state remains `pending` until
the exact merged artifact's benchmark evidence is reviewed.

`pii:us:ssn` applies the same policy through `pii-domain`. Its exact selector
is `pii:family:us:ssn`, public type is `pii_jurisdiction_us_ssn`,
family-contract version is `1`, and `contextRequirement` is
`required-for-sensitive-classification`. It accepts nine ASCII digits in
compact or exact ASCII-hyphenated `3-2-4` form. `us-ssn-allocation` v1 rejects
only SSA-published current structural exclusions: area `000`, `666`, and
`900`–`999`, group `00`, and serial `0000`. Issuance, pre-2011 allocation,
geography, and identity are not inferred. The
[US SSN family contract](../contracts/pii/us-ssn-v1.md) freezes sources,
boundaries, field context, safe generation, and tradeoffs. This applies
existing PII policy and creates no ADR. Its support state remains `pending`
until counterpart #392 qualifies the exact merged artifact; it does not yet
complete the `pii-v1` arrival gate.

## Evidence-backed family applications

These rows apply the existing evidence-tier policy to individual provider
families. They add no new cross-family policy and do not replace the
generated finding-type inventory above.

| Family | Applied rule | Evidence |
| --- | --- | --- |
| `datadog:api-key` | T1 on the provider-stated exact length 32 and the `DD-API-KEY` / `DD_API_KEY` marker; the alphabet stays tool-corroborated, and the key stays marker-gated. | [#644](../audits/evidence/644/README.md), [#575](../audits/evidence/575/README.md) |
| `datadog:application-key` | T1 on the provider-stated `ddapp_` prefix; the body stays tool-corroborated. | [#645](../audits/evidence/645/README.md), [#575](../audits/evidence/575/README.md) |
| `new-relic:license-key` | T1 on the provider-stated `NRAL` suffix and total length 40; `FFFF`, the hex body and `eu01xx` stay tool/provider-code corroborated. The suffixed shapes need no same-line keyword (#754). | [#656](../audits/evidence/656/README.md), [#575](../audits/evidence/575/README.md) |
| `huggingface:api-token` | T1 on the `hf_` prefix (SDK-reference type) and a length of 34 (OpenAPI example), by maintainer ruling; `api_org_` stays outside the T1 contract. | [#654](../audits/evidence/654/README.md), [#575](../audits/evidence/575/README.md) |
| `microsoft-entra:application-client-secret` | T1 on the provider-domain SDK example: 3 characters, then `8Q~`, then 34, for 40 in total, by maintainer ruling. The leading run accepts `-` (#707). | [#655](../audits/evidence/655/README.md), [#575](../audits/evidence/575/README.md) |
| `confluent:cloud-api-secret` | T1 on the provider-stated `cflt` prefix, 60-byte `[A-Za-z0-9+/]` body and checksum: the final 6 body bytes must equal the first 6 standard-Base64 characters of the little-endian IEEE CRC-32 of the 54 body bytes after `cflt` (prefix excluded), the recipe Confluent's own detection example uses. A value with any other checksum is rejected (#738). The unprefixed legacy shape has no documented checksum and stays keyword-gated. | [redact-secret-benchmarks#234](https://github.com/redact-secret/redact-secret-benchmarks/issues/234), [#738](https://github.com/redact-secret/redact-secret/issues/738) |
| `docker:personal-access-token`, `docker:oauth-access-token` | T1 on the provider-stated `dckr_pat_` / `dckr_oat_` prefixes; the OAT body is exactly 27 (the provider example) or 32 bytes (#708). | [#647](../audits/evidence/647/README.md), [#648](../audits/evidence/648/README.md), [#575](../audits/evidence/575/README.md) |
| `elevenlabs:api-key` | `sk_` + exactly 48 lowercase hex, with an optional `_residency_<[a-z0-9]+>` suffix inside the finding span so a residency key is redacted whole. T1 on the `sk_` prefix and the suffix, maintainer ruling accepted 2026-09-27 on provider SDK code (`elevenlabs-python` `speech_engine/server.py` and `resource.py`, `elevenlabs-js` `SpeechEngineResource.ts`; the provider documents neither in prose), following the `huggingface:api-token` precedent; the 48-hex body stays T2 (trufflehog v2, betterleaks, measured public fragments) — no provider document or staff statement states its length or alphabet. Stripe `sk_live_`/`sk_test_`/`sk_org_`, Pollinations `sk_` + 32, 47/49-hex, uppercase and filler bodies and any other `_` suffix stay unclaimed; the legacy bare 32-hex form stays marker-gated under `generic-token` (`elevenlabs` is deliberately not a dedicated-provider segment). | [#865](https://github.com/redact-secret/redact-secret/issues/865), [#788](https://github.com/redact-secret/redact-secret/issues/788), [redact-secret-benchmarks#384](https://github.com/redact-secret/redact-secret-benchmarks/issues/384) |
| `supabase:secret-key` | T1 on the provider-documented `sb_secret_` + 22 + `_` + 8 base64url layout (self-hosted auth-keys page, which states hosted keys share the format, and the provider key script); the `_` is checked by position, and the checksum value is not validated because the hosted input is undocumented (#742). | [#742](https://github.com/redact-secret/redact-secret/issues/742), [redact-secret-benchmarks#231](https://github.com/redact-secret/redact-secret-benchmarks/issues/231) |
| `vercel:personal-access-token`, `vercel:integration-token`, `vercel:app-access-token`, `vercel:app-refresh-token`, `vercel:api-key` | Five independently meaningful modern credential classes are tracked separately. `vcp_`, `vca_`, `vcr_`, and `vck_` are evidence-backed literal markers; the integration source establishes only `vci`, not the underscore. All five remain pending/T0 because no complete body grammar or boundary is documented. The current aggregate `vercel_token` runtime finding and its unreviewed suffix floor do not establish these contracts. Unprefixed examples stay outside the modern contract with issuance status unresolved. | [#858](../audits/evidence/858/README.md) |

## Beta.8 arrival contracts

Issue #726 freezes these 15 contracts and their wave order before detector
implementation. A documented or empirical route is a qualification target,
not a current support-status claim. Provisional and unresolved fields are not
negative rules. The complete evidence, measured beta.7 overlap, cost estimate,
safe-observation plan and FP/FN boundary are in [#726 evidence](../audits/evidence/726/README.md).

| Wave | Family | Frozen supported contract | Qualification route |
| --- | --- | --- | --- |
| 1 | `replicate:api-token` | `r8_` + 37 from `[A-Za-z0-9_-]`; 40 total, alphabet provisional | documented |
| 1 | `groq:api-key` | `gsk_` + 52 alphanumeric | empirical |
| 1 | `xai:api-key` | `xai-` + 80 from `[A-Za-z0-9_-]`; alphabet provisional | empirical |
| 1 | `openrouter:api-key` | `sk-or-v1-` + 64 lowercase hex | documented |
| 1 | `langsmith:api-key` | `lsv2_(pt|sk)_` + 32 lowercase hex + `_` + 10 lowercase hex | empirical |
| 1 | `langfuse:secret-key` | `sk-lf-` + lowercase UUIDv4; issuer-minted keys only | empirical |
| 1 | `github:fine-grained-personal-access-token` | `github_pat_` + 22 alphanumeric + `_` + 59 alphanumeric | empirical |
| 1 | `slack:app-level-token` | `xapp-` + four digit/alphanumeric/digit/alphanumeric dash-separated sections; widths open | empirical |
| 1 | `stripe:webhook-signing-secret` | context-gated `whsec_` + 32-or-more Base64 bytes with optional padding | documented, context-constrained |
| 1 | `notion:integration-token` | `ntn_` + 11 digits + 35 alphanumeric | empirical |
| 2 | `perplexity:api-key` | `pplx-` + 48 alphanumeric | empirical |
| 2 | `fireworks-ai:api-key` | `fw_` + 22 or 24 alphanumeric; widths are provisional positive hypotheses | empirical |
| 2 | `pinecone:api-key` | `pcsk_` + 5–6 alphanumeric + `_` + 63 alphanumeric; legacy UUID only as the value of a Pinecone API-key name (#702) | empirical |
| 2 | `slack:user-token` | `xoxp-` + three numeric sections + final secret section; widths/alphabet open | documented |
| 2 | `gitlab:runner-authentication-token` | `glrt-` legacy/partitioned 20-byte body or checksum-valid routable dotted form | empirical |

### Wave-1 developer credentials (#729)

Issue [#729](https://github.com/redact-secret/redact-secret/issues/729)
implements the four developer-credential families above without changing a
frozen contract. `github:fine-grained-personal-access-token` and
`notion:integration-token` already had their own finding types and exact
grammars, so their detectors are unchanged. `slack:app-level-token` now emits
`slack_app_level_token` for the four-section anatomy, retiring the beta.4
opaque `xapp-` guard: a `_` separator, a letter in a digit section, a missing
section and a bare opaque body are no longer claimed. `stripe:webhook-signing-secret`
now emits `stripe_webhook_signing_secret`, split from `stripe_credential`, for
`whsec_` plus at least 32 Base64 bytes and up to two `=` padding bytes.
Detection stays bare rather than context-gated: Svix and Standard Webhooks
also issue `whsec_` secrets, so a bare hit is still a secret, and attributing
a value to Stripe is a benchmark scoring concept, not a detector gate. Both
families keep their detector ids (`slack-token`, `stripe-token`) and stay
empirical/documented per the freeze until the benchmark evidence gates pass.

### Wave-2 credentials (#730)

Issue [#730](https://github.com/redact-secret/redact-secret/issues/730)
implements the five second-wave families above without changing a frozen
contract; no replacement from the #523/#524 pool was needed.
`perplexity:api-key` (`pplx-` + exactly 48 alphanumeric),
`fireworks-ai:api-key` (`fw_` + 22 or 24 alphanumeric; the two widths are
positive hypotheses, so no other width is a negative rule beyond the exact
match) and `pinecone:api-key` (`pcsk_` + 5–6 alphanumeric + `_` + exactly 63
alphanumeric) each get their own detector and finding type.
`slack:user-token` now emits `slack_user_token` for
`xoxp-<digits>-<digits>-<digits>-<alnum>`, replacing #512's tool-derived
10–13 digit sections and 28-byte secret floor with the provider-stated anatomy
and no width rule, so pre-2016 short secrets are detected; the detector id
stays `slack-token`, and a `xoxp-` that is the tail of `xoxe.xoxp-` stays with
the rotation family. `gitlab:runner-authentication-token` moves `glrt-` out of
`gitlab-token` into `gitlab-runner-authentication-token`, which accepts the
exact 20-byte body (optionally after `t<hex>_`) or the routable
`<base64url>.<2 base36>.<2 base36 length><7 base36 CRC-32>` form and verifies
the length holder and the CRC-32 (over everything before it, prefix included)
offline; a routable value that fails either check, and a legacy body of any
other width, is an intentional false negative. `glrtr-`, instance-prefixed and
unversioned routable forms stay unclaimed (`glrtr-` remains under
`gitlab-token`). The legacy bare-UUID Pinecone key is claimed only as the
value of a Pinecone API-key name on the same line (#702, rule below); a bare
UUID stays unclaimed. Each family keeps
its frozen qualification route; a documented or empirical route is a target,
not a support-status promotion.

### Together AI and Tavily (#867)

Issue [#867](https://github.com/redact-secret/redact-secret/issues/867)
implements the two families researched in
[#783](https://github.com/redact-secret/redact-secret/issues/783) and
[#786](https://github.com/redact-secret/redact-secret/issues/786). Each gets
its own detector and finding type on the shared exact-length prefixed
detector, at provider specificity and high confidence, bare or in any
context. The boundary is `[A-Za-z0-9_-]`: a value that is a slice of a longer
run of those bytes is not claimed.

| Family | Contract | Tier | Evidence basis |
| --- | --- | --- | --- |
| `together-ai:api-key` | `tgp_v1_` + exactly 43 from `[A-Za-z0-9_-]` (50 total) | T2 empirical | no provider source states prefix, length or alphabet; one scanner rule (betterleaks, which Kingfisher only aliases), one community post and four code-search samples; hands-on issuance pending |
| `tavily:api-key` | `tvly-` + optional `dev-` + exactly 32 from `[A-Za-z0-9]` | prefix T1, body T2 | Tavily documents `tvly-` and shows `tvly-dev-` sample keys; the 32-byte alphanumeric body rests on one scanner rule (noseyparker, which predates `dev-`) and three observed samples |

False-positive trade-offs: both prefixes are distinctive and their exact
widths keep prose, model names, `TOGETHER_BASE_URL`, the `tvly` CLI, key names
and `YOUR_API_KEY`-style placeholders unclaimed. A placeholder padded to the
exact width with alphabet bytes (for example 32 `x` after `tvly-dev-`) is
claimed, because no length-preserving placeholder exclusion is evidenced.
`Bearer tvly-YOUR_API_KEY` is not a Tavily finding (wrong width); it was a `bearer-token` false alarm fixed by [#774](https://github.com/redact-secret/redact-secret/issues/774) (see `contextual-detection.md`).
Because a Tavily body is alphanumeric, `tvly-dev-` + 32 does not also match
the bare `tvly-` shape, so one key gives one finding.

False-negative trade-offs, each an intentional gap rather than a negative
rule: Together legacy keys (format undocumented; they stay on the generic
paths), any `tgp_v2_` or other version, and 26/31-byte bodies seen in the code
search; `tvly-prod-` (not evidenced anywhere; Vellum documents production keys
as plain `tvly-`), other Tavily body widths, a body containing `-` or `_`, and
the enterprise expiring-key body width (unshown). A lengthened or reshaped key
from either provider is missed until new evidence widens the contract.
Together's betterleaks entropy floor (3.0) is not applied, so a low-entropy
exact-shape value is still claimed. Cost is one anchored literal per family;
no incremental or WASM concern beyond the other prefixed detectors.

## Keyword-gated provider keys (#868)

Issue [#868](https://github.com/redact-secret/redact-secret/issues/868) covers
five unprefixed providers whose research (#781, #782, #784, #787, #789)
concluded that generic coverage was enough. **No provider has T1 evidence**:
no provider document, staff statement or SDK states a prefix, length or
alphabet, and none of the SDKs validates one. Each landed row is therefore a
*contextual, unqualified, T2-at-best* claim resting on scanner rules and
maintainer observation, in the Twilio mold: a value is a finding only when
provider context is adjacent on the same line, never as a bare 32/40-byte run.

| Family | Shape (scanner-inferred, not issuer-backed) | Context that qualifies the value | Status |
| --- | --- | --- | --- |
| `mistral:studio-api-key` | exactly 32 `[A-Za-z0-9]` | key name carrying `mistral`; `Mistral(...)` call argument; `mistral` then a credential key within 32 bytes | landed, `mistral-api-key` |
| `cohere:api-key` | exactly 40 `[A-Za-z0-9]` | key name carrying `cohere` or exactly `CO_API_KEY`; `cohere.ClientV2(...)` / `CohereClient(...)` argument (`api_key`, `token`) or sole positional | landed, `cohere-api-key` |
| `ai21:api-key` | exactly 32 `[A-Za-z0-9]` | key name carrying `ai21`; `AI21Client(...)` argument | landed, `ai21-api-key` |
| `deepgram:api-key` | exactly 40 `[0-9a-z]` (the wider of trufflehog `[0-9a-z]` and betterleaks hex; the docs example, 32 hex, is read as a placeholder) | key name carrying `deepgram`; `DeepgramClient(...)` argument or sole positional; `Authorization: Token <v>` on a line naming `deepgram` | landed, `deepgram-api-key` |
| `exa:api-key` | none: no source states any shape (only the key *id* is documented, as a UUID) | none | **not landed**; stays with `generic-token` (env, JSON, YAML, `x-api-key`, `Bearer`), its SDK-call keyword-argument form is read by `generic-token` since #866; a positional `Exa("...")` stays out (no credential name) |

Confidence: a named assignment (`MISTRAL_API_KEY=`, `"deepgramApiKey":`) or an
SDK constructor argument is `high` (redacted by default); a credential key
within 32 bytes after the keyword (`# Mistral API key: <v>`) or the Deepgram
`Token` header is `medium` (warned). The types are not in the always-redact
list, like `twilio_auth_token`.

Excluded on purpose: a key ending in an identifier or location segment
(`MISTRAL_KEY_ID`, `DEEPGRAM_PROJECT_ID`, `COHERE_ORG_ID`, `AI21_TEAM_ID`), a
non-credential argument (`Mistral(model="...")`), placeholders and
repeated-character filler, a value behind a hash label (`md5:`), a run of any
other length or alphabet (31/33 bytes, `_`/`-` inside, uppercase Deepgram), and
context on another line (a multi-line constructor keeps `api_key=` on a line
that names nothing; that stays a false negative, as does any provider key under
a keyword-free name such as `API_KEY=`). The bare `Bearer` header is
`bearer-token`'s and is not repeated here.

Trade-offs. False negatives: keys that differ from the inferred shape, and the
same-line rule above; under a provider-named assignment `generic-token` still
redacts a wrong-length value, so the landed rows add the typed, exact-length,
constructor-aware claim and no new silent gap. False positives: a 32/40-byte
hash or id assigned to a keyword-named credential key. Overlap: the rows are
`Provider` specificity, so overlap resolution reports one finding per span, not
one from the provider and one from `generic-token`; `generic-token` keeps its
name-driven verdicts and the provider names are deliberately *not* added to its
dedicated-provider deferral list, because deferring would silence a real key of
an unevidenced shape. Deepgram's `Authorization: Token` header was already
redacted by `generic-token` as `authorization_credential`; the row only adds the
provider type. Detection, exact spans and incremental parity are pinned by
`detectors::keyword_gated_keys` and `tests/keyword_gated_provider_keys.rs`. A
T1 promotion needs a provider document or an issuance check (the checklists in
the research comments); it is a benchmark-side qualification, not a code change.

## Rules

| Rule | Governing ADR |
| --- | --- |
| `pii:global:iban` contract v1 is exposed through `pii-domain` as `pii_global_iban`. It accepts an uppercase electronic form or exact four-character ASCII-space print grouping, requires a Release 103 country/length row and `iban-mod97` v1, and requires high-signal IBAN context for sensitivity. Checksum-valid collisions without context stay identity-only; unknown or wrong country lengths stay unmatched. Frozen contract: `docs/contracts/pii/iban-v1.md`. | no dedicated ADR; applies the existing PII domain and `pii-v1` policies to one family in issue #878 |
| `pii:global:network-address` contract v1 is one family for IPv4 and IPv6, exposed only through `pii-domain` as `pii_global_network_address`. It accepts canonical dotted IPv4 and full/compressed/IPv4-embedded IPv6, rejects zone ids and leading-zero IPv4 octets, and requires high-signal network-address context for sensitivity. Only the frozen documentation/test/benchmark ranges and named non-endpoint constants/classes are non-sensitive; IANA special-purpose status alone is not negative sensitivity evidence. Frozen contract: `docs/audits/evidence/875/README.md`. The frozen contract leaves a trailing period undecided; the rule is that one `.` directly after an address is a right boundary when it ends the input or is followed by whitespace or a closing `"`, `'`, `)`, `]`, `}` or `>`, and it stays outside the range, like a `:port` suffix. A period followed by anything else (a digit, a letter, another period) still leaves the whole dotted run unmatched ([#925](https://github.com/redact-secret/redact-secret/issues/925)). A dotted-quad version at the end of a sentence now has identity, but it still needs an adjacent network-address label to be reported. | no dedicated ADR; applies the existing PII domain and `pii-v1` policies to one family in issues #875 and #925 |
| `pii:global:payment-card` contract v1 is exposed only through `pii-domain` as `pii_global_payment_card`. It accepts the frozen 10–19-digit payment-brand subset after bounded display normalization and a Luhn v1 pass, requires a reviewed English or Korean payment-card field label for sensitivity, and excludes exact whole Visa Acceptance test-service PANs. `pan` is a label only through the shared bounded field-label grammar, never free prose. Frozen contract and evidence: `docs/contracts/pii/payment-card-v1.md` and `docs/audits/evidence/877/README.md`. | no dedicated ADR; applies the existing PII domain and `pii-v1` policies to one family in issue #877 |
| `pii:global:phone` contract v1 is exposed only through `pii-domain` as `pii_global_phone`. It accepts only the frozen `+1` / NANP displays and narrow extensions, excludes actual `N11` codes while retaining structurally valid `988`, requires reviewed high-signal phone context, and treats only exact whole-candidate `555-01xx` exchange/line values as non-sensitive. Frozen contract and evidence: `docs/contracts/pii/phone-v1.md` and `docs/audits/evidence/880/README.md`. | no dedicated ADR; applies the existing PII domain and `pii-v1` policies to one family in issue #880 |
| `pii:us:ssn` contract v1 is exposed only through `pii-domain` as `pii_jurisdiction_us_ssn`. It accepts nine ASCII digits in compact or exact ASCII-hyphenated `3-2-4` form, requires `us-ssn-allocation` v1 and a reviewed English or Korean SSN field label, and rejects only the current SSA structural exclusions. `ssn` is a label only through the bounded field-label grammar. No issuance, identity, geography, or pre-2011 allocation claim is made. Frozen contract and evidence: `docs/contracts/pii/us-ssn-v1.md` and `docs/audits/evidence/879/README.md`. | no dedicated ADR; applies the existing PII domain and `pii-v1` policies to one family in issue #879 |
| Together AI `tgp_v1_` + 43 `[A-Za-z0-9_-]` (T2) and Tavily `tvly-` + optional `dev-` + 32 alphanumeric (prefix T1, body T2) are each reported as their own finding type at provider specificity, bare or in any context; `tvly-prod-`, Together legacy keys and other widths stay unclaimed ([#867](https://github.com/redact-secret/redact-secret/issues/867), section above). | generic policy default, no dedicated ADR; applies the existing exact-length prefixed policy to two more families |
| The Atlassian Cloud API token grammar is frozen as a minimum-length `ATAT`-prefixed body. A directly following `=` plus exactly 8 uppercase hex characters is part of the token and of its span ([#741](https://github.com/redact-secret/redact-secret/issues/741)). | [Freeze the Atlassian Cloud API token grammar as a minimum-length ATAT-prefixed body](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| The Azure DevOps personal access token grammar is frozen as the documented 84-byte `AZDO`-signature shape. | [Freeze the Azure DevOps personal access token grammar as the documented 84-byte AZDO-signature shape](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| The Datadog API Key and Application Key grammar is frozen as marker-gated lowercase-hex values. | [Freeze the Datadog API Key and Application Key grammar as marker-gated lowercase-hex values](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| The Discord bot token grammar is frozen as a three-segment digit-decoding snowflake token. | [Freeze the Discord bot token grammar as a three-segment digit-decoding snowflake token](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| The Grafana service account and Cloud access policy token grammar is frozen; the legacy API key is excluded. | [Freeze the Grafana service account and Cloud access policy token grammar, and exclude the legacy API key](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| The Microsoft Entra application client-secret grammar is frozen as an unprefixed digit-`Q`-tilde marker shape. The three bytes before the digit share the suffix alphabet `[A-Za-z0-9_.~-]`, so a secret that starts with `-` is detected, and the outer boundary is unchanged ([#707](https://github.com/redact-secret/redact-secret/issues/707)). | [Freeze the Microsoft Entra application client-secret grammar as an unprefixed digit-Q-tilde marker](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| The New Relic User API Key grammar is frozen as an exact-length prefixed shape; the License Key grammar is a keyword-gated bare hex shape. The current-generation License Key (32 lowercase hex then `FFFFNRAL`, or `eu01xx` + 26 then `FFFFNRAL`) carries the provider-documented `NRAL` suffix as its own marker and needs no keyword; the gate stays on the legacy bare 40-hex shape ([#754](https://github.com/redact-secret/redact-secret/issues/754)). | [Freeze the New Relic User API Key and License Key grammar as an exact-length prefixed shape and a keyword-gated bare hex shape](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| The Notion integration token grammar is frozen as two exact-length prefixed shapes. | [Freeze the Notion integration token grammar as two exact-length prefixed shapes](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| The Sentry user and organization auth token grammar is frozen as two unambiguous prefixed shapes. | [Freeze the Sentry user and organization auth token grammar as two unambiguous prefixed shapes](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| The Telegram Bot API token grammar is frozen as a minimum-length digit-colon-secret shape. A secret segment that is exactly a canonical 8-4-4-4-12 hexadecimal UUID (an Atlassian account id) is excluded ([#747](https://github.com/redact-secret/redact-secret/issues/747)). | [Freeze the Telegram Bot API token grammar as a minimum-length digit-colon-secret shape](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| The Twilio Auth Token and API Key Secret grammar is frozen as context-gated 32-byte values. | [Freeze the Twilio Auth Token and API Key Secret grammar as context-gated 32-byte values](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| The Docker Hub access token grammar is frozen as separately-sized exact-length prefixed shapes: `dckr_pat_` takes exactly 27 bytes, and `dckr_oat_` takes exactly 27 bytes (the width in Docker's own API reference example) or exactly 32 ([#708](https://github.com/redact-secret/redact-secret/issues/708)). | [Freeze the Docker Hub access token grammar as two separately-sized exact-length prefixed shapes](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| The OpenAI API key grammar is frozen as a marker-gated shape with exact segment lengths. | [Freeze the OpenAI API key grammar as a marker-gated shape with exact segment lengths](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| The OpenAI `sk-admin-` prefix is contracted at T2 under the same marker-gated 58/74-byte grammar as `sk-proj-` and `sk-svcacct-` ([#863](https://github.com/redact-secret/redact-secret/issues/863)). A marker-less `sk-admin-` body of any length is out of `openai-token`'s contract: no source shows such a key, and admitting one would need an `sk-ant-`/`sk-or-` reject list. False negative accepted: a real marker-less key is missed when bare or in unquoted env, YAML or tool-call text (Bearer and quoted credential-named assignments still redact via generic layers). False positives avoided: placeholders, prefix prose and key ids. Evidence: `docs/audits/evidence/863/README.md`. Issue #774 later split `sk-admin-` onto its own `openai_admin_api_key` finding type, unchanged in every other respect. | [Freeze the OpenAI API key grammar as a marker-gated shape with exact segment lengths](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| Reviewed precision contracts are frozen for seven provider families, refining their default rules in place; a value matching a supported prefix but not the contracted shape stops producing a provider finding. | [Freeze reviewed precision contracts for seven provider families and refine their default rules in place](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| The Slack bot token grammar is frozen as a three-section dash-separated shape. | [Freeze the Slack bot token grammar as a three-section dash-separated shape](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| Firebase FCM legacy server key detection is added. The client-config discrimination this record also added was reversed by #749 (next row). | [Add Firebase FCM legacy server key detection, and discriminate the public Web SDK client config from google-api-key](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| A `google-api-key` `AIza` value is reported wherever it appears, including as the `apiKey` of a Firebase Web SDK client config; the config's identifier fields stay unflagged ([#749](https://github.com/redact-secret/redact-secret/issues/749)). | [Redact a Google API key inside a Firebase Web SDK client config, reversing the client-config exemption](../decisions/2026-09-24-redact-google-api-keys-inside-firebase-web-config.md) |
| The Cloudflare account-token prefix is adopted under the frozen `cfut_` contract. | [Adopt the Cloudflare account-token prefix under the frozen cfut_ contract](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| The Hugging Face organization-token prefix is adopted under `hf_`'s frozen body grammar, tiered as T2. | [Adopt the Hugging Face organization-token prefix under hf_'s frozen body grammar, re-tiered to T2](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| The Slack credential family is completed: the user-token grammar and the rotation family's version section are frozen. | [Complete the Slack credential family by freezing the user-token grammar and the rotation family's version section](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| The GitLab token-prefix table is inventoried, and its two undeclared prefixes are given a contract. | [Inventory the GitLab token-prefix table and contract the two undeclared prefixes; record routable tokens and the legacy runner-registration token as explicit, tracked gaps](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| `pinecone-api-key` reports a legacy lowercase `8-4-4-4-12` UUID as `pinecone_api_key` at high confidence only when it is the value assigned to a Pinecone API-key name on the same line: a name normalizing to `pinecone_api_key`/`pinecone_apikey`/`pinecone_key`, or to `api_key`/`apikey` on a line containing `pinecone`. A bare UUID, a UUID under an id-named key, a UUID whose name is on another line, and an all-one-digit placeholder UUID stay unclaimed ([#702](https://github.com/redact-secret/redact-secret/issues/702)). | [Claim a legacy Pinecone UUID key only under a Pinecone API-key name, and redact it](../decisions/2026-09-24-claim-a-legacy-pinecone-uuid-key-only-under-its-api-key-name.md) |
| GitHub's six token families map onto six independent finding types under one detector. | [Map GitHub's six token families onto six independent finding types under one detector](../decisions/2026-09-20-map-github-token-families-onto-independent-finding-types.md) |
| The legacy Supabase anon JWT's payload-trusting exclusion is scoped to `iss` and `role` together. | [Scope a payload-trusting exclusion for the legacy Supabase anon JWT to iss+role together](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| The Supabase management-token credential class is kept separate from the secret-key class, with independent evidence for each. | [Separate the Supabase management-token credential class from the secret-key class, and keep each class's evidence independent](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| A truncated or nested-provider Bearer value is accepted under bearer-token's length-and-alphabet grammar. | [Accept a truncated or nested-provider Bearer value under bearer-token's length-and-alphabet grammar](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| `Proxy-Authorization` is an authorization header like `Authorization` (RFC 7235). `generic-token` matches a `Basic` header mid-line after any byte that cannot continue a header name (a quoted curl argument, a JSON header map with a quoted key, a log prefix), not only at a line start; a mid-line `Token` header stays with the provider detectors that key on it (`travisci-api-token`). `bearer-token` requires 12 bytes, the `Basic`/`Token` floor, when the value follows an explicit `Authorization:`/`Proxy-Authorization:` header name, and keeps 16 for a bare `Bearer <value>`. The cost is a 12–15 byte development token after a real header, which is now reported ([#818](https://github.com/redact-secret/redact-secret/issues/818)). | [Accept a truncated or nested-provider Bearer value under bearer-token's length-and-alphabet grammar](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| `bearer-token` reports an RFC 8959 `secret-token:` URI whole, scheme included, as `bearer_token` (`secret-token-uri` signal): the scheme is matched case-insensitively at an identifier boundary, and the body is RFC 3986 `pchar` bytes except `'`, `(`, `)`, `,`, `;`, with valid `%HH` encodings, no trailing `.`/`:`, at least 8 bytes, and not placeholder vocabulary or filler. RFC 8959 permits a one-byte body; stubs under 8 bytes in documentation are the accepted false negative ([#819](https://github.com/redact-secret/redact-secret/issues/819)). | [Accept a truncated or nested-provider Bearer value under bearer-token's length-and-alphabet grammar](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| Terraform Cloud/Enterprise API token detection is added. | [Add Terraform Cloud/Enterprise API token detection](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| The Pulumi access token grammar is frozen as a documented-prefix, tool-corroborated exact-length hex shape. | [Freeze the Pulumi access token grammar as a documented-prefix, tool-corroborated exact-length hex shape](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| A bare, marker-less vendor-prefixed value (for example an unmarked OpenAI-prefixed value) is redacted under a generic `vendor_prefixed_credential` policy layer, beneath the frozen per-provider contract. | [Redact a bare, marker-less OpenAI-prefixed value under a generic policy layer, beneath the frozen contract](../decisions/2026-09-21-govern-bare-vendor-prefixed-policy-layer.md) |
