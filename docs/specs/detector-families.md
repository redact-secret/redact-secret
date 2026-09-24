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
| `anthropic_api_key` | `anthropic-token` | `always-redact` | generic policy default, no dedicated ADR in this repository; T1 provider source recorded in [#642 evidence](../audits/evidence/642/README.md) |
| `atlassian_api_token` | `atlassian-api-token` | `always-redact` | [Freeze the Atlassian Cloud API token grammar as a minimum-length ATAT-prefixed body](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| `authorization_credential` | `generic-token` | `always-redact` | generic policy default, no dedicated ADR in this repository |
| `aws_access_key_id` | `aws-access-key` | `always-redact` | generic policy default, no dedicated ADR in this repository |
| `azure_devops_personal_access_token` | `azure-devops-personal-access-token` | `always-redact` | [Freeze the Azure DevOps personal access token grammar as the documented 84-byte AZDO-signature shape](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md); T1 provider source recorded in [#642 evidence](../audits/evidence/642/README.md) |
| `bearer_token` | `bearer-token` | `always-redact` | [Accept a truncated or nested-provider Bearer value under bearer-token's length-and-alphabet grammar](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| `cloudflare_api_token` | `cloudflare-token` | `always-redact` | [Adopt the Cloudflare account-token prefix under the frozen cfut_ contract](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| `confluent_cloud_api_secret` | `confluent-cloud-api-secret` | `always-redact` | generic policy default, no dedicated ADR in this repository |
| `confluent_cloud_api_secret_legacy` | `confluent-cloud-api-secret-legacy` | `confidence-gated` | generic policy default, no dedicated ADR in this repository |
| `connection_string_password` | `connection-string` | `always-redact` | [Exclude a value fully delimited by `{{` and `}}` as a template reference](../decisions/2026-09-15-exclude-fully-delimited-template-references.md#folded-records) (folded: `decision-connection-string-and-jwt-need-no-retention-hint`) |
| `contextual_secret` | `generic-token` | `confidence-gated` | generic policy default, no dedicated ADR in this repository |
| `databricks_personal_access_token` | `databricks-personal-access-token` | `always-redact` | generic policy default, no dedicated ADR in this repository |
| `datadog_api_key` | `datadog-api-key` | `confidence-gated` | [Freeze the Datadog API Key and Application Key grammar as marker-gated lowercase-hex values](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| `datadog_application_key` | `datadog-application-key` | `always-redact` | generic policy default, no dedicated ADR in this repository; current `ddapp_`-prefixed shape added by issue #671, applying the existing `confluent_cloud_api_secret` / `heroku_api_key` current/legacy split policy to this family |
| `datadog_application_key_legacy` | `datadog-application-key-legacy` | `confidence-gated` | [Freeze the Datadog API Key and Application Key grammar as marker-gated lowercase-hex values](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| `digitalocean_token` | `digitalocean-token` | `always-redact` | generic policy default, no dedicated ADR in this repository |
| `discord_bot_token` | `discord-bot-token` | `always-redact` | [Freeze the Discord bot token grammar as a three-segment digit-decoding snowflake token](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| `docker_token` | `docker-token` | `always-redact` | [Freeze the Docker Hub access token grammar as two separately-sized exact-length prefixed shapes](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| `firebase_server_key` | `firebase-server-key` | `always-redact` | [Add Firebase FCM legacy server key detection, and discriminate the public Web SDK client config from google-api-key](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| `github_app_installation_token` | `github-token` | `always-redact` | [Map GitHub's six token families onto six independent finding types under one detector](../decisions/2026-09-20-map-github-token-families-onto-independent-finding-types.md) |
| `github_app_refresh_token` | `github-token` | `always-redact` | [Map GitHub's six token families onto six independent finding types under one detector](../decisions/2026-09-20-map-github-token-families-onto-independent-finding-types.md) |
| `github_app_user_to_server_token` | `github-token` | `always-redact` | [Map GitHub's six token families onto six independent finding types under one detector](../decisions/2026-09-20-map-github-token-families-onto-independent-finding-types.md) |
| `github_fine_grained_personal_access_token` | `github-token` | `always-redact` | [Map GitHub's six token families onto six independent finding types under one detector](../decisions/2026-09-20-map-github-token-families-onto-independent-finding-types.md) |
| `github_oauth_token` | `github-token` | `always-redact` | [Map GitHub's six token families onto six independent finding types under one detector](../decisions/2026-09-20-map-github-token-families-onto-independent-finding-types.md) |
| `github_token` | `github-token` | `always-redact` | [Map GitHub's six token families onto six independent finding types under one detector](../decisions/2026-09-20-map-github-token-families-onto-independent-finding-types.md) |
| `gitlab_token` | `gitlab-token` | `always-redact` | [Inventory the GitLab token-prefix table and contract the two undeclared prefixes; record routable tokens and the legacy runner-registration token as explicit, tracked gaps](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| `google_api_key` | `google-api-key` | `always-redact` | [Redact a Google API key inside a Firebase Web SDK client config, reversing the client-config exemption](../decisions/2026-09-24-redact-google-api-keys-inside-firebase-web-config.md); T1 provider source recorded in [#642 evidence](../audits/evidence/642/README.md) |
| `grafana_cloud_access_policy_token` | `grafana-cloud-access-policy-token` | `always-redact` | [Freeze the Grafana service account and Cloud access policy token grammar, and exclude the legacy API key](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md); T1 provider source recorded in [#642 evidence](../audits/evidence/642/README.md) |
| `grafana_service_account_token` | `grafana-service-account-token` | `always-redact` | [Freeze the Grafana service account and Cloud access policy token grammar, and exclude the legacy API key](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md); T1 provider source recorded in [#642 evidence](../audits/evidence/642/README.md) |
| `groq_api_key` | `groq-api-key` | `always-redact` | generic policy default, no dedicated ADR in this repository |
| `heroku_api_key` | `heroku-api-key` | `always-redact` | generic policy default, no dedicated ADR in this repository; issue #740 adds the documented 41-character `HRKU-` + lower-case UUID generation beside `HRKU-AA` + 58, grammar in `detectors::heroku`'s module doc |
| `heroku_api_key_legacy` | `heroku-api-key-legacy` | `confidence-gated` | generic policy default, no dedicated ADR in this repository; issue #714 excludes a UUID assigned to an identifier-shaped key (last word `id` or `uuid`, e.g. `HEROKU_APP_ID`) from the `heroku` keyword gate, grammar in `detectors::heroku`'s module doc; issue #743 also accepts two documented multi-line layouts (a Heroku `.netrc` entry's `password`, `heroku auth:token` output, held open by an incremental retention hint) and excludes a UUID that is a URL path segment |
| `huggingface_token` | `huggingface-token` | `always-redact` | [Adopt the Hugging Face organization-token prefix under hf_'s frozen body grammar, re-tiered to T2](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| `jwt` | `jwt` | `always-redact` | [Exclude a value fully delimited by `{{` and `}}` as a template reference](../decisions/2026-09-15-exclude-fully-delimited-template-references.md#folded-records) (folded: `decision-connection-string-and-jwt-need-no-retention-hint`) |
| `linear_token` | `linear-token` | `always-redact` | generic policy default, no dedicated ADR in this repository; T1 provider source recorded in [#642 evidence](../audits/evidence/642/README.md) |
| `mailchimp_api_key` | `mailchimp-api-key` | `confidence-gated` | no dedicated ADR in this repository; grammar frozen in `detectors::mailchimp`'s own module doc, per issue #313 |
| `mailgun_api_key` | `mailgun-api-key` | `confidence-gated` | no dedicated ADR in this repository; grammar frozen in `detectors::mailgun`'s own module doc, per issue #314 |
| `microsoft_entra_client_secret` | `microsoft-entra-client-secret` | `always-redact` | [Freeze the Microsoft Entra application client-secret grammar as an unprefixed digit-Q-tilde marker](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| `netlify_personal_access_token` | `netlify-token` | `always-redact` | generic policy default, no dedicated ADR in this repository |
| `new_relic_license_key` | `new-relic-license-key` | `confidence-gated` | [Freeze the New Relic User API Key and License Key grammar as an exact-length prefixed shape and a keyword-gated bare hex shape](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| `new_relic_user_api_key` | `new-relic-user-api-key` | `always-redact` | [Freeze the New Relic User API Key and License Key grammar as an exact-length prefixed shape and a keyword-gated bare hex shape](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md); T1 provider source recorded in [#642 evidence](../audits/evidence/642/README.md) |
| `notion_integration_token` | `notion-token` | `always-redact` | [Freeze the Notion integration token grammar as two exact-length prefixed shapes](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md); T1 provider source recorded in [#642 evidence](../audits/evidence/642/README.md) |
| `npm_access_token` | `npm-token` | `always-redact` | generic policy default, no dedicated ADR in this repository |
| `okta_api_token` | `okta-api-token` | `confidence-gated` | no dedicated ADR in this repository; grammar frozen in `detectors::okta`'s own module doc, per issue #315 |
| `openai_api_key` | `openai-token` | `always-redact` | [Freeze the OpenAI API key grammar as a marker-gated shape with exact segment lengths](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| `openrouter_api_key` | `openrouter-api-key` | `always-redact` | generic policy default, no dedicated ADR in this repository |
| `otpauth_secret` | `otpauth-uri` | `always-redact` | generic policy default, no dedicated ADR in this repository |
| `postman_api_key` | `postman-api-key` | `always-redact` | generic policy default, no dedicated ADR in this repository |
| `private_key` | `private-key` | `block` | generic policy default, no dedicated ADR in this repository |
| `pulumi_access_token` | `pulumi-access-token` | `always-redact` | [Freeze the Pulumi access token grammar as a documented-prefix, tool-corroborated exact-length hex shape](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| `pypi_api_token` | `pypi-token` | `always-redact` | generic policy default, no dedicated ADR in this repository |
| `replicate_api_token` | `replicate-api-token` | `always-redact` | generic policy default, no dedicated ADR in this repository |
| `sendgrid_api_key` | `sendgrid-token` | `always-redact` | generic policy default, no dedicated ADR in this repository |
| `sentry_org_auth_token` | `sentry-org-auth-token` | `always-redact` | [Freeze the Sentry user and organization auth token grammar as two unambiguous prefixed shapes](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| `sentry_user_auth_token` | `sentry-user-auth-token` | `always-redact` | [Freeze the Sentry user and organization auth token grammar as two unambiguous prefixed shapes](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| `shopify_access_token` | `shopify-token` | `always-redact` | generic policy default, no dedicated ADR in this repository |
| `slack_token` | `slack-token` | `always-redact` | [Freeze the Slack bot token grammar as a three-section dash-separated shape](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| `stripe_credential` | `stripe-token` | `always-redact` | generic policy default, no dedicated ADR in this repository |
| `supabase_personal_access_token` | `supabase-management-token` | `always-redact` | [Separate the Supabase management-token credential class from the secret-key class, and keep each class's evidence independent](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| `supabase_secret_key` | `supabase-token` | `always-redact` | [Separate the Supabase management-token credential class from the secret-key class, and keep each class's evidence independent](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| `telegram_bot_token` | `telegram-bot-token` | `always-redact` | [Freeze the Telegram Bot API token grammar as a minimum-length digit-colon-secret shape](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| `terraform_cloud_token` | `terraform-cloud-token` | `always-redact` | [Add Terraform Cloud/Enterprise API token detection](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| `twilio_api_key_secret` | `twilio-api-key-secret` | `confidence-gated` | [Freeze the Twilio Auth Token and API Key Secret grammar as context-gated 32-byte values](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| `twilio_auth_token` | `twilio-auth-token` | `confidence-gated` | [Freeze the Twilio Auth Token and API Key Secret grammar as context-gated 32-byte values](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| `vault_token` | `vault-token` | `always-redact` | generic policy default, no dedicated ADR in this repository |
| `vendor_prefixed_credential` | `generic-token` | `always-redact` | [Redact a bare, marker-less OpenAI-prefixed value under a generic policy layer, beneath the frozen contract](../decisions/2026-09-21-govern-bare-vendor-prefixed-policy-layer.md) |
| `vercel_token` | `vercel-token` | `always-redact` | generic policy default, no dedicated ADR in this repository |
| `xai_api_key` | `xai-api-key` | `always-redact` | generic policy default, no dedicated ADR in this repository |
<!-- detector-families:end -->

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
| `supabase:secret-key` | T1 on the provider-documented `sb_secret_` + 22 + `_` + 8 base64url layout (self-hosted auth-keys page, which states hosted keys share the format, and the provider key script); the `_` is checked by position, and the checksum value is not validated because the hosted input is undocumented (#742). | [#742](https://github.com/redact-secret/redact-secret/issues/742), [redact-secret-benchmarks#231](https://github.com/redact-secret/redact-secret-benchmarks/issues/231) |

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
| 2 | `pinecone:api-key` | `pcsk_` + 5–6 alphanumeric + `_` + 63 alphanumeric; legacy UUID is context-only | empirical |
| 2 | `slack:user-token` | `xoxp-` + three numeric sections + final secret section; widths/alphabet open | documented |
| 2 | `gitlab:runner-authentication-token` | `glrt-` legacy/partitioned 20-byte body or checksum-valid routable dotted form | empirical |

## Rules

| Rule | Governing ADR |
| --- | --- |
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
| Reviewed precision contracts are frozen for seven provider families, refining their default rules in place; a value matching a supported prefix but not the contracted shape stops producing a provider finding. | [Freeze reviewed precision contracts for seven provider families and refine their default rules in place](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| The Slack bot token grammar is frozen as a three-section dash-separated shape. | [Freeze the Slack bot token grammar as a three-section dash-separated shape](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| Firebase FCM legacy server key detection is added. The client-config discrimination this record also added was reversed by #749 (next row). | [Add Firebase FCM legacy server key detection, and discriminate the public Web SDK client config from google-api-key](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| A `google-api-key` `AIza` value is reported wherever it appears, including as the `apiKey` of a Firebase Web SDK client config; the config's identifier fields stay unflagged ([#749](https://github.com/redact-secret/redact-secret/issues/749)). | [Redact a Google API key inside a Firebase Web SDK client config, reversing the client-config exemption](../decisions/2026-09-24-redact-google-api-keys-inside-firebase-web-config.md) |
| The Cloudflare account-token prefix is adopted under the frozen `cfut_` contract. | [Adopt the Cloudflare account-token prefix under the frozen cfut_ contract](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| The Hugging Face organization-token prefix is adopted under `hf_`'s frozen body grammar, tiered as T2. | [Adopt the Hugging Face organization-token prefix under hf_'s frozen body grammar, re-tiered to T2](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| The Slack credential family is completed: the user-token grammar and the rotation family's version section are frozen. | [Complete the Slack credential family by freezing the user-token grammar and the rotation family's version section](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| The GitLab token-prefix table is inventoried, and its two undeclared prefixes are given a contract. | [Inventory the GitLab token-prefix table and contract the two undeclared prefixes; record routable tokens and the legacy runner-registration token as explicit, tracked gaps](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| GitHub's six token families map onto six independent finding types under one detector. | [Map GitHub's six token families onto six independent finding types under one detector](../decisions/2026-09-20-map-github-token-families-onto-independent-finding-types.md) |
| The legacy Supabase anon JWT's payload-trusting exclusion is scoped to `iss` and `role` together. | [Scope a payload-trusting exclusion for the legacy Supabase anon JWT to iss+role together](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| The Supabase management-token credential class is kept separate from the secret-key class, with independent evidence for each. | [Separate the Supabase management-token credential class from the secret-key class, and keep each class's evidence independent](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| A truncated or nested-provider Bearer value is accepted under bearer-token's length-and-alphabet grammar. | [Accept a truncated or nested-provider Bearer value under bearer-token's length-and-alphabet grammar](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| Terraform Cloud/Enterprise API token detection is added. | [Add Terraform Cloud/Enterprise API token detection](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| The Pulumi access token grammar is frozen as a documented-prefix, tool-corroborated exact-length hex shape. | [Freeze the Pulumi access token grammar as a documented-prefix, tool-corroborated exact-length hex shape](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| A bare, marker-less vendor-prefixed value (for example an unmarked OpenAI-prefixed value) is redacted under a generic `vendor_prefixed_credential` policy layer, beneath the frozen per-provider contract. | [Redact a bare, marker-less OpenAI-prefixed value under a generic policy layer, beneath the frozen contract](../decisions/2026-09-21-govern-bare-vendor-prefixed-policy-layer.md) |
