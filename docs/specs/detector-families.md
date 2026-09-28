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
| `apify_api_token` | `apify-api-token` | `always-redact` | generic policy default, no dedicated ADR in this repository; T1 (Apify docs placeholder prefix, R4; provider-authored leak linter alphabet and floor, R2), grammar and trade-offs in [Tier B provider families (#860)](#tier-b-provider-families-860) |
| `atlassian_api_token` | `atlassian-api-token` | `always-redact` | [Freeze the Atlassian Cloud API token grammar as a minimum-length ATAT-prefixed body](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| `authorization_credential` | `generic-token` | `always-redact` | generic policy default, no dedicated ADR in this repository |
| `aws_access_key_id` | `aws-access-key` | `always-redact` | generic policy default, no dedicated ADR in this repository |
| `aws_bedrock_long_term_api_key` | `aws-bedrock-long-term-api-key` | `always-redact` | generic policy default, no dedicated ADR in this repository; grammar in `detectors::aws_bedrock`'s module doc, `ABSK` + standard Base64 with `={0,2}` padding (T1, maintainer ruling accepted 2026-09-27 on the AWS Security Blog scan pattern, [#778](https://github.com/redact-secret/redact-secret/issues/778)), 109-269 body bytes (T2), recorded in [#864 evidence](../audits/evidence/864/README.md) |
| `aws_bedrock_short_term_api_key` | `aws-bedrock-short-term-api-key` | `always-redact` | generic policy default, no dedicated ADR in this repository; two families rather than one (client-minted presigned URL vs issued credential), `bedrock-api-key-` prefix + fixed 133-byte Base64 head + standard Base64 alphabet (T1, maintainer ruling accepted 2026-09-27 on the AWS token-generator SDKs (python/js/java) plus the AWS Security Blog, [#779](https://github.com/redact-secret/redact-secret/issues/779)), tail floor and total length T2, recorded in [#864 evidence](../audits/evidence/864/README.md) |
| `azure_devops_personal_access_token` | `azure-devops-personal-access-token` | `always-redact` | [Freeze the Azure DevOps personal access token grammar as the documented 84-byte AZDO-signature shape](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md); T1 provider source recorded in [#642 evidence](../audits/evidence/642/README.md) |
| `bearer_token` | `bearer-token` | `always-redact` | [Accept a truncated or nested-provider Bearer value under bearer-token's length-and-alphabet grammar](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| `cloudflare_api_token` | `cloudflare-token` | `always-redact` | [Adopt the Cloudflare account-token prefix under the frozen cfut_ contract](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| `cohere_api_key` | `cohere-api-key` | `confidence-gated` | no dedicated ADR in this repository; contextual, unqualified claim stated under Keyword-gated provider keys below, per issue #868 |
| `composio_org_api_key` | `composio-api-key` | `always-redact` | generic policy default, no dedicated ADR in this repository; T1 (provider docs and a dated staff statement under R3; `uak_` width under R6), grammar and trade-offs in [Tier A provider families (#860)](#tier-a-provider-families-860) |
| `composio_project_api_key` | `composio-api-key` | `always-redact` | generic policy default, no dedicated ADR in this repository; T1 (provider docs and a dated staff statement under R3; `uak_` width under R6), grammar and trade-offs in [Tier A provider families (#860)](#tier-a-provider-families-860) |
| `composio_user_api_key` | `composio-api-key` | `always-redact` | generic policy default, no dedicated ADR in this repository; T1 (provider docs and a dated staff statement under R3; `uak_` width under R6), grammar and trade-offs in [Tier A provider families (#860)](#tier-a-provider-families-860) |
| `confluent_cloud_api_secret` | `confluent-cloud-api-secret` | `always-redact` | generic policy default, no dedicated ADR in this repository |
| `confluent_cloud_api_secret_legacy` | `confluent-cloud-api-secret-legacy` | `confidence-gated` | generic policy default, no dedicated ADR in this repository |
| `connection_string_password` | `connection-string` | `always-redact` | [Exclude a value fully delimited by `{{` and `}}` as a template reference](../decisions/2026-09-15-exclude-fully-delimited-template-references.md#folded-records) (folded: `decision-connection-string-and-jwt-need-no-retention-hint`) |
| `contextual_secret` | `generic-token` | `confidence-gated` | generic policy default, no dedicated ADR in this repository |
| `convex_deployment_key` | `convex-deployment-key` | `always-redact` | generic policy default, no dedicated ADR in this repository; T1 (provider code: backend key format and generator; hex length derived from the generator), grammar and trade-offs in [Tier B provider families (#860)](#tier-b-provider-families-860) |
| `databricks_personal_access_token` | `databricks-personal-access-token` | `always-redact` | generic policy default, no dedicated ADR in this repository |
| `datadog_api_key` | `datadog-api-key` | `confidence-gated` | [Freeze the Datadog API Key and Application Key grammar as marker-gated lowercase-hex values](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| `datadog_application_key` | `datadog-application-key` | `always-redact` | generic policy default, no dedicated ADR in this repository; current `ddapp_`-prefixed shape added by issue #671, applying the existing `confluent_cloud_api_secret` / `heroku_api_key` current/legacy split policy to this family |
| `datadog_application_key_legacy` | `datadog-application-key-legacy` | `confidence-gated` | [Freeze the Datadog API Key and Application Key grammar as marker-gated lowercase-hex values](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| `deepgram_api_key` | `deepgram-api-key` | `confidence-gated` | no dedicated ADR in this repository; contextual, unqualified claim stated under Keyword-gated provider keys below, per issue #868 |
| `digitalocean_token` | `digitalocean-token` | `always-redact` | generic policy default, no dedicated ADR in this repository |
| `discord_bot_token` | `discord-bot-token` | `always-redact` | [Freeze the Discord bot token grammar as a three-segment digit-decoding snowflake token](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| `docker_token` | `docker-token` | `always-redact` | [Freeze the Docker Hub access token grammar as two separately-sized exact-length prefixed shapes](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| `doppler_audit_token` | `doppler-token` | `always-redact` | generic policy default, no dedicated ADR in this repository; T1 (Doppler docs), one type per role per [the GitHub token-family ADR](../decisions/2026-09-20-map-github-token-families-onto-independent-finding-types.md), grammar and trade-offs in [Tier A provider families (#860)](#tier-a-provider-families-860) |
| `doppler_cli_token` | `doppler-token` | `always-redact` | generic policy default, no dedicated ADR in this repository; T1 (Doppler docs), one type per role per [the GitHub token-family ADR](../decisions/2026-09-20-map-github-token-families-onto-independent-finding-types.md), grammar and trade-offs in [Tier A provider families (#860)](#tier-a-provider-families-860) |
| `doppler_personal_token` | `doppler-token` | `always-redact` | generic policy default, no dedicated ADR in this repository; T1 (Doppler docs), one type per role per [the GitHub token-family ADR](../decisions/2026-09-20-map-github-token-families-onto-independent-finding-types.md), grammar and trade-offs in [Tier A provider families (#860)](#tier-a-provider-families-860) |
| `doppler_scim_token` | `doppler-token` | `always-redact` | generic policy default, no dedicated ADR in this repository; T1 (Doppler docs), one type per role per [the GitHub token-family ADR](../decisions/2026-09-20-map-github-token-families-onto-independent-finding-types.md), grammar and trade-offs in [Tier A provider families (#860)](#tier-a-provider-families-860) |
| `doppler_service_account_identity_token` | `doppler-token` | `always-redact` | generic policy default, no dedicated ADR in this repository; T1 (Doppler docs), one type per role per [the GitHub token-family ADR](../decisions/2026-09-20-map-github-token-families-onto-independent-finding-types.md), grammar and trade-offs in [Tier A provider families (#860)](#tier-a-provider-families-860) |
| `doppler_service_account_token` | `doppler-token` | `always-redact` | generic policy default, no dedicated ADR in this repository; T1 (Doppler docs), one type per role per [the GitHub token-family ADR](../decisions/2026-09-20-map-github-token-families-onto-independent-finding-types.md), grammar and trade-offs in [Tier A provider families (#860)](#tier-a-provider-families-860) |
| `doppler_service_token` | `doppler-token` | `always-redact` | generic policy default, no dedicated ADR in this repository; T1 (Doppler docs), one type per role per [the GitHub token-family ADR](../decisions/2026-09-20-map-github-token-families-onto-independent-finding-types.md), grammar and trade-offs in [Tier A provider families (#860)](#tier-a-provider-families-860) |
| `e2b_api_key` | `e2b-api-key` | `always-redact` | generic policy default, no dedicated ADR in this repository; T1 (provider generator code under R1), grammar and trade-offs in [Tier A provider families (#860)](#tier-a-provider-families-860) |
| `elevenlabs_api_key` | `elevenlabs-api-key` | `always-redact` | generic policy default, no dedicated ADR in this repository |
| `firebase_server_key` | `firebase-server-key` | `always-redact` | [Add Firebase FCM legacy server key detection, and discriminate the public Web SDK client config from google-api-key](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| `firecrawl_api_key` | `firecrawl-api-key` | `always-redact` | generic policy default, no dedicated ADR in this repository; prefix T1 (docs, SDK), UUIDv4 body T1 (provider server code under R1), grammar and trade-offs in [Tier A provider families (#860)](#tier-a-provider-families-860) |
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
| `helicone_api_key` | `helicone-api-key` | `always-redact` | generic policy default, no dedicated ADR in this repository; T1 (provider validator regexes and generators), `[a-z0-9]` per ruling R8, grammar and trade-offs in [Tier A provider families (#860)](#tier-a-provider-families-860) |
| `helicone_write_api_key` | `helicone-api-key` | `always-redact` | generic policy default, no dedicated ADR in this repository; T1 (provider validator regexes and generators), `[a-z0-9]` per ruling R8, grammar and trade-offs in [Tier A provider families (#860)](#tier-a-provider-families-860) |
| `heroku_api_key` | `heroku-api-key` | `always-redact` | generic policy default, no dedicated ADR in this repository; issue #740 adds the documented 41-character `HRKU-` + lower-case UUID generation beside `HRKU-AA` + 58, grammar in `detectors::heroku`'s module doc |
| `heroku_api_key_legacy` | `heroku-api-key-legacy` | `confidence-gated` | generic policy default, no dedicated ADR in this repository; issue #714 excludes a UUID assigned to an identifier-shaped key (last word `id` or `uuid`, e.g. `HEROKU_APP_ID`) from the `heroku` keyword gate, grammar in `detectors::heroku`'s module doc; issue #743 also accepts two documented multi-line layouts (a Heroku `.netrc` entry's `password`, `heroku auth:token` output, held open by an incremental retention hint) and excludes a UUID that is a URL path segment |
| `huggingface_token` | `huggingface-token` | `always-redact` | [Adopt the Hugging Face organization-token prefix under hf_'s frozen body grammar, re-tiered to T2](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| `inngest_signing_key` | `inngest-signing-key` | `always-redact` | generic policy default, no dedicated ADR in this repository; T1 (Inngest provider code constants, docs generation command and SDK fixtures), grammar and trade-offs in [Tier B provider families (#860)](#tier-b-provider-families-860) |
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
| `onepassword_service_account_token` | `onepassword-service-account-token` | `always-redact` | generic policy default, no dedicated ADR in this repository; T1 (1Password docs: prefix and Base64url encoding; the 250-byte floor is project policy), grammar and trade-offs in [Tier B provider families (#860)](#tier-b-provider-families-860) |
| `openai_admin_api_key` | `openai-token` | `always-redact` | generic policy default, no dedicated ADR in this repository; issue #774 splits the `sk-admin-` namespace out of the shared `openai_api_key` type (materially different blast radius: an organization Admin API key, not a project/service-account key). Grammar untouched: still the T2 marker-gated 58/74-byte contract from [#863](https://github.com/redact-secret/redact-secret/issues/863), [Freeze the OpenAI API key grammar as a marker-gated shape with exact segment lengths](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| `openai_api_key` | `openai-token` | `always-redact` | [Freeze the OpenAI API key grammar as a marker-gated shape with exact segment lengths](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| `openrouter_api_key` | `openrouter-api-key` | `always-redact` | generic policy default, no dedicated ADR in this repository |
| `otpauth_secret` | `otpauth-uri` | `always-redact` | generic policy default, no dedicated ADR in this repository |
| `perplexity_api_key` | `perplexity-api-key` | `always-redact` | generic policy default, no dedicated ADR in this repository |
| `pinecone_api_key` | `pinecone-api-key` | `always-redact` | [Claim a legacy Pinecone UUID key only under a Pinecone API-key name, and redact it](../decisions/2026-09-24-claim-a-legacy-pinecone-uuid-key-only-under-its-api-key-name.md) |
| `posthog_personal_api_key` | `posthog-token` | `always-redact` | generic policy default, no dedicated ADR in this repository; T1 (provider generator code and unit tests under R1), grammar and trade-offs in [Tier A provider families (#860)](#tier-a-provider-families-860) |
| `posthog_project_secret_api_key` | `posthog-token` | `always-redact` | generic policy default, no dedicated ADR in this repository; T1 (provider generator code and unit tests under R1), grammar and trade-offs in [Tier A provider families (#860)](#tier-a-provider-families-860) |
| `postman_api_key` | `postman-api-key` | `always-redact` | generic policy default, no dedicated ADR in this repository |
| `postman_collection_access_key` | `postman-collection-access-key` | `always-redact` | generic policy default, no dedicated ADR in this repository |
| `private_key` | `private-key` | `block` | generic policy default, no dedicated ADR in this repository |
| `pulumi_access_token` | `pulumi-access-token` | `always-redact` | [Freeze the Pulumi access token grammar as a documented-prefix, tool-corroborated exact-length hex shape](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| `pypi_api_token` | `pypi-token` | `always-redact` | generic policy default, no dedicated ADR in this repository |
| `replicate_api_token` | `replicate-api-token` | `always-redact` | generic policy default, no dedicated ADR in this repository |
| `resend_api_key` | `resend-api-key` | `always-redact` | generic policy default, no dedicated ADR in this repository; prefix T1 (Resend CLI), layout T1 by example (docs response example and SDK fixtures, R5), grammar and trade-offs in [Tier B provider families (#860)](#tier-b-provider-families-860) |
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
| `trigger_dev_personal_access_token` | `trigger-dev-token` | `always-redact` | generic policy default, no dedicated ADR in this repository; T1 (provider SDK regex and generator code under R1), grammar and trade-offs in [Tier A provider families (#860)](#tier-a-provider-families-860) |
| `trigger_dev_secret_api_key` | `trigger-dev-token` | `always-redact` | generic policy default, no dedicated ADR in this repository; T1 (provider SDK regex and generator code under R1), grammar and trade-offs in [Tier A provider families (#860)](#tier-a-provider-families-860) |
| `twilio_api_key_secret` | `twilio-api-key-secret` | `confidence-gated` | [Freeze the Twilio Auth Token and API Key Secret grammar as context-gated 32-byte values](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| `twilio_auth_token` | `twilio-auth-token` | `confidence-gated` | [Freeze the Twilio Auth Token and API Key Secret grammar as context-gated 32-byte values](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| `vault_token` | `vault-token` | `always-redact` | generic policy default, no dedicated ADR in this repository |
| `vendor_prefixed_credential` | `generic-token` | `always-redact` | [Redact a bare, marker-less OpenAI-prefixed value under a generic policy layer, beneath the frozen contract](../decisions/2026-09-21-govern-bare-vendor-prefixed-policy-layer.md) |
| `vercel_token` | `vercel-token` | `always-redact` | generic policy default, no dedicated ADR in this repository |
| `wandb_api_key` | `wandb-api-key` | `always-redact` | generic policy default, no dedicated ADR in this repository; prefix T1 (W&B test constant, R5), alphabet T1 (SDK validator, R1); the 64–96 band is a tolerant range around the documented width, grammar and trade-offs in [Tier B provider families (#860)](#tier-b-provider-families-860) |
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
are frozen in the [email family contract](../contracts/pii/email-v1.md). This
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

## Tier A provider families (#860)

Issue [#860](https://github.com/redact-secret/redact-secret/issues/860)
selected provider credential families whose value today was covered only
by generic detection under a credential name or a `Bearer` header, and missed
bare, in chat text, and under a JSON `"token"` key. Each landed family below
is a new detector with its own finding type(s), `Provider` specificity, high
confidence and always redacted, so overlap resolution reports one provider
finding per span over `contextual_secret`, `bearer_token` and
`authorization_credential`. The frozen contract for each family, with its
sources, tier rationale, excluded shapes and issuance checklist, is its step-3
handoff under [`docs/audits/evidence/860/`](../audits/evidence/860/README.md);
this section records only the implemented grammar and its trade-offs.

Shared rules: a value is rejected when the byte before the prefix or after the
body continues an identifier (`[A-Za-z0-9_-]`, widened per family where
noted), so an embedded, over-long or glued value is an intentional false
negative, never a truncated match. A placeholder shorter than the exact width
or with a byte outside the alphabet is unclaimed by construction; one padded
to the exact width with alphabet bytes is claimed, because no length-preserving
placeholder exclusion is evidenced (the #867 precedent). None of these
providers is added to `generic-token`'s dedicated-provider deferral list:
each has documented shapes these contracts exclude, and deferral would turn a
provider-named assignment of one into a silent miss. JWT siblings stay with
`jwt`. No row is a support-status claim; promotion stays gated on core
conformance and the benchmarks arrival and profile evidence.

| Family | Detector | Contract | Finding types | Tier |
| --- | --- | --- | --- | --- |
| `doppler:service-token` | `doppler-token` | `dp.` + `st`\|`pt`\|`ct`\|`sa`\|`said`\|`scim`\|`audit` + `.` + 40–44 `[A-Za-z0-9]`; `dp.st.` only may carry one `[a-z0-9_-]{2,35}` + `.` environment segment, inside the span. Leading boundary also rejects `.` | one per type: `doppler_service_token`, `doppler_personal_token`, `doppler_cli_token`, `doppler_service_account_token`, `doppler_service_account_identity_token`, `doppler_scim_token`, `doppler_audit_token` | T1 (Doppler token-format page, per-type regex) |
| `trigger-dev:secret-api-key` | `trigger-dev-token` | `tr_` + `dev`\|`stg`\|`prod`\|`preview` + `_sk_` + exactly 24 `[0-9A-Za-z]` (additional key); `tr_<env>_` + exactly 24 or 20 `[0-9A-Za-z]` (root key, current and legacy); `tr_pat_` + exactly 40 `[1-9a-km-z]` | `trigger_dev_secret_api_key` (root and additional); `trigger_dev_personal_access_token` | T1 (published SDK regex; provider generator code under R1) |
| `e2b:api-key` | `e2b-api-key` | `e2b_` + exactly 40 lowercase hex | `e2b_api_key` | T1 (provider key generator and seed test under R1; docs corroborate the prefix) |
| `posthog:personal-api-key` | `posthog-token` | `phx_` or `phs_` + 42–49 `[0-9A-Za-z]` (the union of the prefixed base57 and base62 generator eras); `phc_` never claimed | `posthog_personal_api_key`; `posthog_project_secret_api_key` | T1 (provider generator code and unit tests under R1; the length band is derived from the T1 algorithm) |
| `helicone:api-key` | `helicone-api-key` | `sk-` or `pk-` + `helicone` + optional `-eu` then optional `-rl` + `-` + four groups of exactly 7 `[a-z0-9]` joined by `-`; `sk-helicone-proxy-` + the four groups + `-` + a lowercase 8-4-4-4-12 UUID | `helicone_api_key` (`sk-`, read-write, and the proxy key); `helicone_write_api_key` (`pk-`, write-only, redacted) | T1 (provider worker validation regexes and generators; proxy key under R1) |
| `firecrawl:api-key` | `firecrawl-api-key` | `fc-` + exactly 32 lowercase hex forming a dashless UUIDv4 (body byte 12 is `4`, byte 16 is one of `8 9 a b`) | `firecrawl_api_key` | prefix T1 (docs, SDK and MCP code); body T1 (server normalizer, schema default and generator under R1) |
| `composio:api-key` | `composio-api-key` | `ak_` + exactly 20 `[A-Za-z0-9_-]` with at least one uppercase and one lowercase letter; `oak_` + exactly 20; `uak_` + exactly 43 | `composio_project_api_key`; `composio_org_api_key`; `composio_user_api_key` | T1 (prefixes from provider docs, `OpenAPI` and SDK; widths and alphabet from the 2026-09-17 provider-staff statement under R3; `uak_` + 43 per R6) |

Doppler ([#903](https://github.com/redact-secret/redact-secret/issues/903),
[handoff](../audits/evidence/860/doppler.md)). One type per documented role
follows
[the GitHub token-family ADR](../decisions/2026-09-20-map-github-token-families-onto-independent-finding-types.md):
a personal or CLI token acts for the user, a service token reads one config.
False negatives: a body outside 40–44, a body with `_` or `-`, a segment
outside its grammar (uppercase, 1 byte, 36+ bytes), a segment on any type but
`st`, an undocumented future type, an uppercase prefix, and a token glued to an
identifier. `dp.said.` is never read as `dp.sa.` plus a body. The CLI and
dashboard preview (`dp.st…` plus six bytes) fails the grammar. False
positives: a non-Doppler `dp.<documented type>.` plus a bounded 40–44
alphanumeric run; none is known. Cost: one literal `dp.` search, then a scan
capped at 36 segment and 45 body bytes per candidate.

Trigger.dev ([#904](https://github.com/redact-secret/redact-secret/issues/904),
[handoff](../audits/evidence/860/trigger-dev.md)). Root and additional keys
share one type because the provider documents both as the environment's
secret key with the same scope; the personal access token acts for a user and
is its own type. Longest prefix wins, so `tr_prod_sk_` is tried before
`tr_prod_`, and `tr_prod_sk_` + 21 matches neither shape. The public
`pk_<env>_` key stays unclaimed, as do `tr_oat_` (no known generator),
`tr_uat_` and public access tokens (JWTs, kept by `jwt`), `tr_proj_` refs, an
undocumented env slug, a root width other than 20 or 24, and a PAT with `0`,
`l` or uppercase. `tr_<env>_sk_` contains `sk_`, but the preceding `_` fails
the Stripe and ElevenLabs leading boundaries, so neither fires (pinned by a
registry test). False positives: an unrelated `tr_<env>_` + exactly 20 or 24
alphanumerics with no further separator; code identifiers of that shape
normally carry another `_`, which the alphabet rejects.

E2B ([#905](https://github.com/redact-secret/redact-secret/issues/905),
[handoff](../audits/evidence/860/e2b.md)). Without its prefix the body is
SHA-1 shaped, so the prefix is load-bearing. The retired `sk_e2b_` user
access token is unclaimed (the `_` before `e2b_` fails the leading boundary;
generic detection still redacts one under a credential name), as are an
uppercase-hex body (accepted by the verifier, never issued), package names
(`e2b_code_interpreter`, `e2b_desktop`), placeholders, and unprefixed 64-hex
sandbox tokens. False positives: an unrelated `e2b_` + exactly 40 lowercase
hex, such as an identifier suffixing a SHA-1; rare, and the cost is redacting
a digest.

PostHog ([#906](https://github.com/redact-secret/redact-secret/issues/906),
[handoff](../audits/evidence/860/posthog.md)). The project token `phc_` is
public by design ("ok to be public") and the detector never emits a finding
for it; a credential-named assignment of one is still `generic-token`'s
name-driven verdict, unchanged here. The alphabet is the base62 union rather
than base57 so every live era stays claimed. False negatives: base62-era keys
that rendered at 41 bytes or fewer (under 0.03% of any era), unprefixed
era-1 keys outside named contexts, OAuth `pha_`/`phr_` tokens (deferred), and
a body with `_` or `-`. False positives: an unrelated `phx_`/`phs_` + 42–49
alphanumeric value; none is known.

Helicone ([#907](https://github.com/redact-secret/redact-secret/issues/907),
[handoff](../audits/evidence/860/helicone.md)). The group alphabet is the
provider's own `[a-z0-9]`, not the generator library's base32 `[a-z2-7]`:
ruling R8 rejects alphabet narrowing from a third-party library, so a library
change cannot become a false negative. `pk-` is detected and redacted under
its own type: Helicone documents it as a write-permission API key and no
provider source says it is safe to publish (unlike PostHog `phc_` or Stripe
`pk_`), and a separate type lets a policy downgrade it without touching
`sk-`. A key in the gateway URL path is delimited by `/` and is claimed.
False negatives: the legacy bare `sk-` + 4×7 and customer-portal `-cp-`
forms (no provider token), `-gov` combinations (matched by no worker regex),
segments out of order (`-rl-eu-`), a group of 6 or 8, three or five groups,
`_` in place of `-`, uppercase, and any future segment. `vendor_prefixed_credential`
(`sk-` + 48 alphanumerics) and `openai-token` do not claim these shapes.
False positives: an all-`x` placeholder at the exact shape (claimed, the #867
precedent) and a non-Helicone string with the literal `-helicone-` segment
and four 7-byte groups; none is known.

Firecrawl ([#908](https://github.com/redact-secret/redact-secret/issues/908),
[handoff](../audits/evidence/860/firecrawl.md)). Every issued key is a
Postgres random UUIDv4, so the version and variant nibbles are enforced; that
rejects 63 of 64 arbitrary 32-hex strings (for example `fc-` + an MD5
digest) at no cost for issued keys. `fc-` is short, so the leading boundary
matters: `xfc-`, `_fc-` and CSS or calendar classes (`fc-event`,
`fc-daygrid-day`) are glued or fail the body. False negatives: legacy bare
dashed-UUID keys outside named contexts (not attributable to Firecrawl),
`fc-` + a dashed UUID, another version or variant, uppercase hex, `fco_`
OAuth and `fcmcp_` MCP credentials, and self-hosted instances with
authentication off. False positives: an unrelated `fc-` + dashless lowercase
UUIDv4, such as an `fc-`-prefixed record id minted from a v4 UUID; plausible
but rare, and the cost is redacting an identifier.

Composio ([#909](https://github.com/redact-secret/redact-secret/issues/909),
[handoff](../audits/evidence/860/composio.md)). A provider CLI code comment
showing `uak_` + 20 is T2 under ruling R6 and does not override the staff
statement, so `uak_` is 43 only; the issuance check in the handoff stays as
confirmation. `ak_` is short and its alphabet includes `_` and `-`, so an
`ak_` body must hold at least one uppercase and one lowercase letter
(maintainer-accepted guard): the false-negative cost is about 6e-5 for a
uniform nanoid body, and every all-lowercase or all-uppercase identifier
(`ak_` + a snake_case run) is removed. The body and boundary alphabets are
the same, so the exact width rejects every over-long or glued run, and a body
ending in `-` or `_` is still exact. `oak_` and `uak_` contain `ak_`, but the
preceding `o` or `u` fails the leading boundary, so no project-key finding
fires inside them (or inside `cak_`/`xak_`). False negatives: `uak_` at any
other width (including a possible legacy 20, which named contexts still
redact), `ck_` and `cak_` keys (no known shape), and single-case `ak_` bodies.
False positives: `ak_` + a 20-byte mixed-case identifier with a boundary on
both sides, and `oak_` + any 20-byte alphabet run.

## Tier B provider families (#860)

The Tier B families of issue
[#860](https://github.com/redact-secret/redact-secret/issues/860)
([re-rank](../audits/evidence/860/tier-b-rerank.md)) are each a new detector
with its own finding type, `Provider` specificity, high confidence and always
redacted, so overlap resolution reports one provider finding per span over
`contextual_secret`, `bearer_token` and `authorization_credential`. The frozen
contract for each family, with its sources, tier rationale, excluded shapes
and issuance checklist, is its step-3 handoff next to the re-rank; this
section records only the implemented grammar and its trade-offs.

Shared rules: a value is rejected when the byte before it or after it
continues an identifier (`[A-Za-z0-9_-]`, adjusted per family where noted),
so an embedded, over-long or glued value is an intentional false negative,
never a truncated match. None of these providers is added to
`generic-token`'s dedicated-provider deferral list: each has shapes these
contracts exclude, and deferral would turn a provider-named assignment of one
into a silent miss. No row is a support-status claim; promotion stays gated on
core conformance and the benchmarks arrival and profile evidence.

| Family | Detector | Contract | Finding types | Tier |
| --- | --- | --- | --- | --- |
| `convex:deployment-key` | `convex-deployment-key` | optional `prod:`/`dev:` + cloud name `[a-z]+-[a-z]+-[0-9]+`, or `preview:`/`project:` + `<slug>:<slug>`; or an untyped `[a-z0-9][a-z0-9-]{0,62}` name; then one `\|`, then `01` + lowercase hex, even length 74–96. The whole key, lead and name included, is the span. The key must start at the input start or after a byte outside `[A-Za-z0-9_:-]` | `convex_deployment_key` | T1 (backend `format_admin_key` and key broker; the 74–96 range is derived from the generator) |
| `onepassword:service-account-token` | `onepassword-service-account-token` | `ops_eyJ` + at least 250 Base64url `[A-Za-z0-9_-]` bytes, no upper bound, plus up to two `=` inside the span; after the padding the next byte must not be `[A-Za-z0-9_-]`, `+`, `/` or `=` | `onepassword_service_account_token` | T1 (provider docs: `ops_` prefix and Base64url-encoded JSON; floor is policy) |
| `inngest:signing-key` | `inngest-signing-key` | `signkey-prod-`\|`signkey-test-`\|`signkey-branch-` + exactly 64 lowercase hex | `inngest_signing_key` (raw key, rotation fallback and hashed wire form) | T1 (provider code constants; 64 from the docs `openssl rand -hex 32` and SDK fixtures, R5) |
| `resend:api-key` | `resend-api-key` | `re_` + 8 `[A-Za-z0-9]` + `_` + 24 `[A-Za-z0-9]` (36 in total), with at least one uppercase and one lowercase letter in the 32 segment bytes | `resend_api_key` | prefix T1 (CLI-enforced); layout T1 by example (docs + SDK fixtures, R5); mixed-case guard is policy |
| `apify:api-token` | `apify-api-token` | `apify_api_` + 20–128 `[A-Za-z0-9]`; a glued `_` or `-` after the run rejects the match; a body over 128 is rejected whole | `apify_api_token` | T1 (prefix R4; alphabet and 20-byte floor from the provider's own leak linter, R2); the 128 cap is policy |
| `wandb:api-key` | `wandb-api-key` | `wandb_v1_` + 64–96 `[A-Za-z0-9_]` (documented example width 77, total "about 86"); the byte before the prefix must not be `[A-Za-z0-9_]` (a `<host>-` label stays outside the span), and the byte after must not be `[A-Za-z0-9_-]` | `wandb_api_key` | prefix T1 (R5), alphabet T1 (R1); tolerant width band by orchestrator decision on #917 |

Convex ([#912](https://github.com/redact-secret/redact-secret/issues/912),
[handoff](../audits/evidence/860/convex.md)). The anchor is the `|` separator
plus the `01` hex envelope, not a leading literal, so this is a bespoke scan
(one pass over `|`, bounded left and right walks). The public name is inside
the span so a partial redaction cannot be reassembled. The cloud deploy-key
body (`eyJ2…`) is issuance-gated (ruling R4) and stays unclaimed; `convex` is
not in `generic-token`'s deferral list, so the exact names
`CONVEX_DEPLOY_KEY` and `CONVEX_SELF_HOSTED_ADMIN_KEY` (#919) keep a
contextual finding for it. False negatives: every `eyJ2` cloud key until the
gate clears, pre-0.16.0 bare keys, a name or slug outside the bounded class,
a `prod:`/`dev:` lead before a non-cloud name, uppercase hex, and any future
key version. A separator that is not a type lead (`prod;<name>|01…`) leaves an
untyped key claimed from the name on. False positives: a non-Convex
`<name>|01<74–96 even lowercase hex>` with clean boundaries; none is known.
Cost: one scan for `|`, then at most 97 bytes right and 137 bytes left per
candidate.

1Password ([#913](https://github.com/redact-secret/redact-secret/issues/913),
[handoff](../audits/evidence/860/onepassword.md)). The token is serialized
user data, so there is no fixed length (the one T1 example is 634 bytes); the
250-byte floor only rejects identifiers and placeholders and matches the
gitleaks floor. The alphabet is the provider's stated Base64url class, not
the alphanumeric samples', so a token containing `-` or `_` is never
truncated. Connect server tokens stay with `jwt`, and `op://` references stay
excluded by `generic-token`. False negatives: a token under the floor, a
future serialization without the `eyJ` lead, a token truncated below the
floor by a log line limit, and a glued standard-Base64 tail. False positives:
`ops_` + any Base64url JSON blob of 250+ bytes that is not a service-account
token; none is known. Cost: one literal search and one run per occurrence;
the scan resumes after the run, so it stays linear.

Inngest ([#914](https://github.com/redact-secret/redact-secret/issues/914),
[handoff](../audits/evidence/860/inngest.md)). One type covers the raw key,
`INNGEST_SIGNING_KEY_FALLBACK` and the hashed `Authorization: Bearer` wire
form (`signkey-<env>-` + SHA-256 hex of the key): they are lexically
identical and each authenticates. Before this, `INNGEST_SIGNING_KEY=` gave only
a medium, warned `contextual_secret` (`signing_key` is an ambiguous name); the
provider finding now wins and is redacted. `inngest` is not deferred, because
the self-hosted bare-hex key has no prefix and only generic context sees it.
False negatives: other environment labels, an uppercase-hex copy, a body
other than 64, a glued value, and self-hosted bare-hex keys outside named
contexts. False positives: `signkey-<label>-` + exactly 64 lowercase hex that
is not an Inngest key; none is known. Cost: one prefix table on the shared
known-format scan.

Resend ([#915](https://github.com/redact-secret/redact-secret/issues/915),
[handoff](../audits/evidence/860/resend.md)). The alphabet is the
alphanumeric superset of the three base58-looking provider values (the #655
precedent): samples prove what is present, not what is excluded, and the
exact 8/`_`/24 layout does the discriminating. `re_` is short and ends many
identifiers, so the leading boundary rejects `are_`, `pre_` and `_re_`, and
the mixed-case guard (the Tier A `ak_` guard) rejects every one-case
identifier of that layout. False negatives: a key whose 32 segment bytes are
all one letter case (about 6e-8 for a uniform body), a future layout change,
and a key glued to an identifier. False positives: a mixed-case `re_` + 8 +
`_` + 24 alphanumeric identifier with clean boundaries. Cost: one prefix on
the shared known-format scan plus a 32-byte post check.

Apify ([#916](https://github.com/redact-secret/redact-secret/issues/916),
[handoff](../audits/evidence/860/apify.md)). The provider's own rule is
open-ended (`apify_api_[A-Za-z0-9]{20,}`), so the contract uses it rather
than a scanner's exact 36 (T2); the 128-byte cap only bounds the run for
streaming. The body alphabet is narrower than the boundary, so
`apify_api_token_here`-style placeholders stay unclaimed. `apify_ui_` Console
tokens and the unprefixed sibling tokens have no stated shape and stay with
generic context. False negatives: a body containing `-` or `_`, a body over
128, and `apify_ui_` or sibling tokens outside named contexts. False
positives: `apify_api_` + 20–128 alphanumerics that is not a token, such as
alphanumeric placeholder filler (the #867 precedent). Cost: one prefix on the
shared known-format scan.

W&B ([#917](https://github.com/redact-secret/redact-secret/issues/917),
[handoff](../audits/evidence/860/wandb.md)). The handoff froze an exact
77-byte body, but the docs state the length only as "about 86", so the body is
a bounded tolerant band of 64–96 around it (orchestrator decision on #917):
the 9-byte prefix is itself specific, and an exact width would make any key
that is not exactly 86 a false negative in the bare, chat and JSON `"token"`
contexts generic detection misses. The floor stays far above the 27-byte Key
ID and the 44-character test constant; the cap bounds the run for streaming.
Tighten after an issuance check records the real width. The scanner-only
27/`_`/49 split is not required. Legacy 40-hex keys stay with generic
context, so `wandb` is not deferred. False negatives: a key outside 64–96, a
body with `-`, legacy 40-hex keys outside named contexts, and a future
`wandb_v2_`. False positives: `wandb_v1_` + 64–96 `[A-Za-z0-9_]` that is not a
key, such as a long snake_case identifier in that range; the prefix makes it
rare. Cost: one prefix on the shared known-format scan.

## Rules

| Rule | Governing ADR |
| --- | --- |
| `pii:global:iban` contract v1 is exposed through `pii-domain` as `pii_global_iban`. It accepts an uppercase electronic form or exact four-character ASCII-space print grouping, requires a Release 103 country/length row and `iban-mod97` v1, and requires high-signal IBAN context for sensitivity. Checksum-valid collisions without context stay identity-only; unknown or wrong country lengths stay unmatched. Frozen contract: `docs/contracts/pii/iban-v1.md`. | no dedicated ADR; applies the existing PII domain and `pii-v1` policies to one family in issue #878 |
| `pii:global:network-address` contract v1 is one family for IPv4 and IPv6, exposed only through `pii-domain` as `pii_global_network_address`. It accepts canonical dotted IPv4 and full/compressed/IPv4-embedded IPv6, rejects zone ids and leading-zero IPv4 octets, and requires high-signal network-address context for sensitivity. Only the frozen documentation/test/benchmark ranges and named non-endpoint constants/classes are non-sensitive; IANA special-purpose status alone is not negative sensitivity evidence. Frozen contract: `docs/audits/evidence/875/README.md`. | no dedicated ADR; applies the existing PII domain and `pii-v1` policies to one family in issue #875 |
| `pii:global:payment-card` contract v1 is exposed only through `pii-domain` as `pii_global_payment_card`. It accepts the frozen 10–19-digit payment-brand subset after bounded display normalization and a Luhn v1 pass, requires a reviewed English or Korean payment-card field label for sensitivity, and excludes exact whole Visa Acceptance test-service PANs. `pan` is a label only through the shared bounded field-label grammar, never free prose. Frozen contract and evidence: `docs/contracts/pii/payment-card-v1.md` and `docs/audits/evidence/877/README.md`. | no dedicated ADR; applies the existing PII domain and `pii-v1` policies to one family in issue #877 |
| `pii:global:phone` contract v1 is exposed only through `pii-domain` as `pii_global_phone`. It accepts only the frozen `+1` / NANP displays and narrow extensions, excludes actual `N11` codes while retaining structurally valid `988`, requires reviewed high-signal phone context, and treats only exact whole-candidate `555-01xx` exchange/line values as non-sensitive. Frozen contract and evidence: `docs/contracts/pii/phone-v1.md` and `docs/audits/evidence/880/README.md`. | no dedicated ADR; applies the existing PII domain and `pii-v1` policies to one family in issue #880 |
| `pii:us:ssn` contract v1 is exposed only through `pii-domain` as `pii_jurisdiction_us_ssn`. It accepts nine ASCII digits in compact or exact ASCII-hyphenated `3-2-4` form, requires `us-ssn-allocation` v1 and a reviewed English or Korean SSN field label, and rejects only the current SSA structural exclusions. `ssn` is a label only through the bounded field-label grammar. No issuance, identity, geography, or pre-2011 allocation claim is made. Frozen contract and evidence: `docs/contracts/pii/us-ssn-v1.md` and `docs/audits/evidence/879/README.md`. | no dedicated ADR; applies the existing PII domain and `pii-v1` policies to one family in issue #879 |
| Doppler `dp.<type>.` tokens (seven documented types, 40–44 alphanumeric body, optional `dp.st.` environment segment) are reported as one finding type per type at provider specificity, bare or in any context ([#903](https://github.com/redact-secret/redact-secret/issues/903), section above). | generic policy default, no dedicated ADR; applies the existing prefixed-provider policy and the GitHub one-type-per-family precedent to one more family |
| Trigger.dev `tr_<env>_sk_` + 24 and `tr_<env>_` + 24 or 20 alphanumeric secret keys (four documented env slugs), and `tr_pat_` + 40 `[1-9a-km-z]` personal access tokens, are reported as two finding types at provider specificity, bare or in any context; `pk_<env>_`, `tr_oat_` and JWT forms stay unclaimed ([#904](https://github.com/redact-secret/redact-secret/issues/904), section above). | generic policy default, no dedicated ADR; applies the existing exact-length prefixed policy to one more family |
| E2B `e2b_` + exactly 40 lowercase hex API keys are reported as `e2b_api_key` at provider specificity, bare or in any context; retired `sk_e2b_` tokens and `e2b_` module names stay unclaimed ([#905](https://github.com/redact-secret/redact-secret/issues/905), section above). | generic policy default, no dedicated ADR; applies the existing exact-length prefixed policy to one more family |
| PostHog `phx_` personal and `phs_` project secret API keys (42–49 alphanumeric) are reported as two finding types at provider specificity, bare or in any context; the public `phc_` project token is never claimed ([#906](https://github.com/redact-secret/redact-secret/issues/906), section above). | generic policy default, no dedicated ADR; applies the existing prefixed-provider policy and the public-key exclusion precedent (Stripe `pk_`) to one more family |
| Helicone `sk-`/`pk-` + `helicone` + optional `-eu`/`-rl` + four 7-byte `[a-z0-9]` groups, and the `sk-helicone-proxy-` key with a trailing UUID, are reported as `helicone_api_key` (`sk-`) and `helicone_write_api_key` (`pk-`, redacted by default) at provider specificity, bare or in any context; legacy bare `sk-`, `-cp-` and `-gov` forms stay unclaimed ([#907](https://github.com/redact-secret/redact-secret/issues/907), section above). | generic policy default, no dedicated ADR; applies the existing prefixed-provider policy to one more family, with the group alphabet fixed by ruling R8 |
| Firecrawl `fc-` + a dashless lowercase UUIDv4 (32 hex, version and variant nibbles enforced) is reported as `firecrawl_api_key` at provider specificity, bare or in any context; legacy dashed UUIDs, `fco_` and `fcmcp_` stay unclaimed ([#908](https://github.com/redact-secret/redact-secret/issues/908), section above). | generic policy default, no dedicated ADR; applies the existing exact-length prefixed policy to one more family |
| Composio `ak_` + 20 (mixed-case guard), `oak_` + 20 and `uak_` + 43 `[A-Za-z0-9_-]` keys are reported as three finding types at provider specificity, bare or in any context; `ck_`, `cak_` and `uak_` at other widths stay unclaimed ([#909](https://github.com/redact-secret/redact-secret/issues/909), section above). | generic policy default, no dedicated ADR; applies the existing exact-length prefixed policy to one more family, with the `uak_` width fixed by ruling R6 |
| Convex `<name>\|01<hex>` deployment and admin keys (typed `prod`/`dev`/`preview`/`project` lead or untyped self-hosted name; even 74–96 lowercase hex body led by `01`) are reported as `convex_deployment_key` at provider specificity over the whole key; the `eyJ2` cloud body stays unclaimed until its issuance check ([#912](https://github.com/redact-secret/redact-secret/issues/912), section above). | generic policy default, no dedicated ADR; applies the existing prefixed-provider policy to one more family |
| 1Password `ops_eyJ` service-account tokens (at least 250 Base64url bytes after the lead, up to two `=` inside the span) are reported as `onepassword_service_account_token` at provider specificity, bare or in any context ([#913](https://github.com/redact-secret/redact-secret/issues/913), section above). | generic policy default, no dedicated ADR; applies the existing prefixed-provider policy to one more family |
| Inngest `signkey-prod-`/`signkey-test-`/`signkey-branch-` + 64 lowercase hex signing keys (raw, fallback and hashed wire form) are reported as `inngest_signing_key` at provider specificity, bare or in any context ([#914](https://github.com/redact-secret/redact-secret/issues/914), section above). | generic policy default, no dedicated ADR; applies the existing prefixed-provider policy to one more family |
| Resend `re_` + 8 + `_` + 24 alphanumeric API keys with both letter cases are reported as `resend_api_key` at provider specificity, bare or in any context ([#915](https://github.com/redact-secret/redact-secret/issues/915), section above). | generic policy default, no dedicated ADR; applies the existing prefixed-provider policy to one more family |
| Apify `apify_api_` + 20–128 alphanumeric API tokens are reported as `apify_api_token` at provider specificity, bare or in any context; `apify_ui_` stays unclaimed ([#916](https://github.com/redact-secret/redact-secret/issues/916), section above). | generic policy default, no dedicated ADR; applies the existing prefixed-provider policy to one more family |
| W&B `wandb_v1_` + 64–96 `[A-Za-z0-9_]` API keys are reported as `wandb_api_key` at provider specificity, bare or in any context; a leading `<host>-` label stays outside the span, and the band is tolerant around the documented 77 until an issuance check ([#917](https://github.com/redact-secret/redact-secret/issues/917), section above). | generic policy default, no dedicated ADR; applies the existing prefixed-provider policy to one more family |
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
| `generic-token` recognizes fal's `Authorization: Key <key_id>:<key_secret>` scheme as an `authorization_credential`, beside `Basic` and `Token`, with the same 12-byte floor and entropy-based confidence. The `Key` value alphabet adds `:`, so the colon-joined secret half is inside the span, and a trailing `:` is dropped. A `Key` header is also taken mid-line after a byte that cannot continue a header name (a quoted curl `-H` argument, a JSON header map), like `Basic`: no provider detector keys on it. FP cost: a non-credential `Key` scheme value of 12+ bytes after an `Authorization:` header name (the legacy FCM `key=` form is unaffected: it has no space); FN cost: none added ([#919](https://github.com/redact-secret/redact-secret/issues/919); evidence: `docs/audits/evidence/860/fal-contextual-gap.md`). | [Accept a truncated or nested-provider Bearer value under bearer-token's length-and-alphabet grammar](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| `bearer-token` selects a value made of token runs joined by `:` or `\|` whole (`<id>:<secret>`, `<name>\|<secret>`): each directly following join plus a non-empty run, and its own `=` padding, is part of the value. The 16/12-byte floor is judged on the whole joined value, and the value is excluded as a placeholder only when every run is filler or placeholder vocabulary. A join followed by whitespace, the end of the value, or `//` (a URL) is not part of it. A value glued, directly or through one join, to an `<ANGLE>` placeholder (content `[A-Za-z0-9_-]+` with an uppercase letter, `_` or `-`), a `$VAR`/`${VAR}` reference or a `{{` template is not reported: its run is the public lead of a placeholder (`signkey-prod-<YOUR-SIGNING-KEY>`, `prod:<name>\|${CONVEX_BODY}`); an HTML tag after a real token (`</td>`, `<br>`) is not a placeholder. Before this, the span stopped at the join and left the secret half readable. FP cost: a longer span over a `:`/`\|`-joined run after `Bearer` (a timestamp, a Markdown cell written without spaces), and a short token run that now clears the floor only through its joins; FN cost: none added ([#918](https://github.com/redact-secret/redact-secret/issues/918); evidence: `docs/audits/evidence/860/fal-contextual-gap.md`). | [Accept a truncated or nested-provider Bearer value under bearer-token's length-and-alphabet grammar](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| `bearer-token` reports an RFC 8959 `secret-token:` URI whole, scheme included, as `bearer_token` (`secret-token-uri` signal): the scheme is matched case-insensitively at an identifier boundary, and the body is RFC 3986 `pchar` bytes except `'`, `(`, `)`, `,`, `;`, with valid `%HH` encodings, no trailing `.`/`:`, at least 8 bytes, and not placeholder vocabulary or filler. RFC 8959 permits a one-byte body; stubs under 8 bytes in documentation are the accepted false negative ([#819](https://github.com/redact-secret/redact-secret/issues/819)). | [Accept a truncated or nested-provider Bearer value under bearer-token's length-and-alphabet grammar](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| Terraform Cloud/Enterprise API token detection is added. | [Add Terraform Cloud/Enterprise API token detection](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| The Pulumi access token grammar is frozen as a documented-prefix, tool-corroborated exact-length hex shape. | [Freeze the Pulumi access token grammar as a documented-prefix, tool-corroborated exact-length hex shape](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| A bare, marker-less vendor-prefixed value (for example an unmarked OpenAI-prefixed value) is redacted under a generic `vendor_prefixed_credential` policy layer, beneath the frozen per-provider contract. | [Redact a bare, marker-less OpenAI-prefixed value under a generic policy layer, beneath the frozen contract](../decisions/2026-09-21-govern-bare-vendor-prefixed-policy-layer.md) |
