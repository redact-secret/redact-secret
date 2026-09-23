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

Generated (best-effort join by detector name) from [`docs/coverage/detector-inventory.json`](../coverage/detector-inventory.json); not machine-checked against this table.

| Type | Detector | Policy class | Governing ADR |
| --- | --- | --- | --- |
| `anthropic_api_key` | `anthropic-token` | `always-redact` | generic policy default, no dedicated ADR in this repository |
| `atlassian_api_token` | `atlassian-api-token` | `always-redact` | [Freeze the Atlassian Cloud API token grammar as a minimum-length ATAT-prefixed body](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| `authorization_credential` | `generic-token` | `always-redact` | generic policy default, no dedicated ADR in this repository |
| `aws_access_key_id` | `aws-access-key` | `always-redact` | generic policy default, no dedicated ADR in this repository |
| `azure_devops_personal_access_token` | `azure-devops-personal-access-token` | `always-redact` | [Freeze the Azure DevOps personal access token grammar as the documented 84-byte AZDO-signature shape](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| `bearer_token` | `bearer-token` | `always-redact` | [Accept a truncated or nested-provider Bearer value under bearer-token's length-and-alphabet grammar](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| `cloudflare_api_token` | `cloudflare-token` | `always-redact` | [Adopt the Cloudflare account-token prefix under the frozen cfut_ contract](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| `connection_string_password` | `connection-string` | `always-redact` | [Exclude a value fully delimited by `{{` and `}}` as a template reference](../decisions/2026-09-15-exclude-fully-delimited-template-references.md#folded-records) (folded: `decision-connection-string-and-jwt-need-no-retention-hint`) |
| `contextual_secret` | `generic-token` | `confidence-gated` | generic policy default, no dedicated ADR in this repository |
| `datadog_api_key` | `datadog-api-key` | `confidence-gated` | [Freeze the Datadog API Key and Application Key grammar as marker-gated lowercase-hex values](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| `datadog_application_key` | `datadog-application-key` | `confidence-gated` | [Freeze the Datadog API Key and Application Key grammar as marker-gated lowercase-hex values](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
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
| `google_api_key` | `google-api-key` | `always-redact` | [Add Firebase FCM legacy server key detection, and discriminate the public Web SDK client config from google-api-key](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| `grafana_cloud_access_policy_token` | `grafana-cloud-access-policy-token` | `always-redact` | [Freeze the Grafana service account and Cloud access policy token grammar, and exclude the legacy API key](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| `grafana_service_account_token` | `grafana-service-account-token` | `always-redact` | [Freeze the Grafana service account and Cloud access policy token grammar, and exclude the legacy API key](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| `huggingface_token` | `huggingface-token` | `always-redact` | [Adopt the Hugging Face organization-token prefix under hf_'s frozen body grammar, re-tiered to T2](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| `jwt` | `jwt` | `always-redact` | [Exclude a value fully delimited by `{{` and `}}` as a template reference](../decisions/2026-09-15-exclude-fully-delimited-template-references.md#folded-records) (folded: `decision-connection-string-and-jwt-need-no-retention-hint`) |
| `linear_token` | `linear-token` | `always-redact` | generic policy default, no dedicated ADR in this repository |
| `microsoft_entra_client_secret` | `microsoft-entra-client-secret` | `always-redact` | [Freeze the Microsoft Entra application client-secret grammar as an unprefixed digit-Q-tilde marker](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| `new_relic_license_key` | `new-relic-license-key` | `confidence-gated` | [Freeze the New Relic User API Key and License Key grammar as an exact-length prefixed shape and a keyword-gated bare hex shape](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| `new_relic_user_api_key` | `new-relic-user-api-key` | `always-redact` | [Freeze the New Relic User API Key and License Key grammar as an exact-length prefixed shape and a keyword-gated bare hex shape](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| `notion_integration_token` | `notion-token` | `always-redact` | [Freeze the Notion integration token grammar as two exact-length prefixed shapes](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| `npm_access_token` | `npm-token` | `always-redact` | generic policy default, no dedicated ADR in this repository |
| `openai_api_key` | `openai-token` | `always-redact` | [Freeze the OpenAI API key grammar as a marker-gated shape with exact segment lengths](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| `otpauth_secret` | `otpauth-uri` | `always-redact` | generic policy default, no dedicated ADR in this repository |
| `postman_api_key` | `postman-api-key` | `always-redact` | generic policy default, no dedicated ADR in this repository |
| `private_key` | `private-key` | `block` | generic policy default, no dedicated ADR in this repository |
| `pulumi_access_token` | `pulumi-access-token` | `always-redact` | [Freeze the Pulumi access token grammar as a documented-prefix, tool-corroborated exact-length hex shape](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| `pypi_api_token` | `pypi-token` | `always-redact` | generic policy default, no dedicated ADR in this repository |
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

## Rules

| Rule | Governing ADR |
| --- | --- |
| The Atlassian Cloud API token grammar is frozen as a minimum-length `ATAT`-prefixed body. | [Freeze the Atlassian Cloud API token grammar as a minimum-length ATAT-prefixed body](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| The Azure DevOps personal access token grammar is frozen as the documented 84-byte `AZDO`-signature shape. | [Freeze the Azure DevOps personal access token grammar as the documented 84-byte AZDO-signature shape](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| The Datadog API Key and Application Key grammar is frozen as marker-gated lowercase-hex values. | [Freeze the Datadog API Key and Application Key grammar as marker-gated lowercase-hex values](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| The Discord bot token grammar is frozen as a three-segment digit-decoding snowflake token. | [Freeze the Discord bot token grammar as a three-segment digit-decoding snowflake token](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| The Grafana service account and Cloud access policy token grammar is frozen; the legacy API key is excluded. | [Freeze the Grafana service account and Cloud access policy token grammar, and exclude the legacy API key](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| The Microsoft Entra application client-secret grammar is frozen as an unprefixed digit-`Q`-tilde marker shape. | [Freeze the Microsoft Entra application client-secret grammar as an unprefixed digit-Q-tilde marker](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| The New Relic User API Key grammar is frozen as an exact-length prefixed shape; the License Key grammar is a keyword-gated bare hex shape. | [Freeze the New Relic User API Key and License Key grammar as an exact-length prefixed shape and a keyword-gated bare hex shape](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| The Notion integration token grammar is frozen as two exact-length prefixed shapes. | [Freeze the Notion integration token grammar as two exact-length prefixed shapes](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| The Sentry user and organization auth token grammar is frozen as two unambiguous prefixed shapes. | [Freeze the Sentry user and organization auth token grammar as two unambiguous prefixed shapes](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| The Telegram Bot API token grammar is frozen as a minimum-length digit-colon-secret shape. | [Freeze the Telegram Bot API token grammar as a minimum-length digit-colon-secret shape](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| The Twilio Auth Token and API Key Secret grammar is frozen as context-gated 32-byte values. | [Freeze the Twilio Auth Token and API Key Secret grammar as context-gated 32-byte values](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| The Docker Hub access token grammar is frozen as two separately-sized exact-length prefixed shapes. | [Freeze the Docker Hub access token grammar as two separately-sized exact-length prefixed shapes](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| The OpenAI API key grammar is frozen as a marker-gated shape with exact segment lengths. | [Freeze the OpenAI API key grammar as a marker-gated shape with exact segment lengths](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| Reviewed precision contracts are frozen for seven provider families, refining their default rules in place; a value matching a supported prefix but not the contracted shape stops producing a provider finding. | [Freeze reviewed precision contracts for seven provider families and refine their default rules in place](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| The Slack bot token grammar is frozen as a three-section dash-separated shape. | [Freeze the Slack bot token grammar as a three-section dash-separated shape](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| Firebase FCM legacy server key detection is added, and the public Web SDK client config is discriminated from `google-api-key`. | [Add Firebase FCM legacy server key detection, and discriminate the public Web SDK client config from google-api-key](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
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

