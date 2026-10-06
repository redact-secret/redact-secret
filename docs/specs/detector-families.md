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
| `aws_access_key_id` | `aws-access-key` | `always-redact` | generic policy default, no dedicated ADR in this repository; `AKIA` and `ASIA` + 16 `[A-Z0-9]`, the `ASIA` contract T2 in [Unsupported-variant contracts (#1012)](#unsupported-variant-contracts-1012) |
| `aws_bedrock_long_term_api_key` | `aws-bedrock-long-term-api-key` | `always-redact` | generic policy default, no dedicated ADR in this repository; grammar in `detectors::aws_bedrock`'s module doc, `ABSK` + standard Base64 with `={0,2}` padding (T1, maintainer ruling accepted 2026-09-27 on the AWS Security Blog scan pattern, [#778](https://github.com/redact-secret/redact-secret/issues/778)), 109-269 body bytes (T2), recorded in [#864 evidence](../audits/evidence/864/README.md) |
| `aws_bedrock_short_term_api_key` | `aws-bedrock-short-term-api-key` | `always-redact` | generic policy default, no dedicated ADR in this repository; two families rather than one (client-minted presigned URL vs issued credential), `bedrock-api-key-` prefix + fixed 133-byte Base64 head + standard Base64 alphabet (T1, maintainer ruling accepted 2026-09-27 on the AWS token-generator SDKs (python/js/java) plus the AWS Security Blog, [#779](https://github.com/redact-secret/redact-secret/issues/779)), tail floor and total length T2, recorded in [#864 evidence](../audits/evidence/864/README.md) |
| `aws_secret_access_key` | `aws-secret-access-key` | `always-redact` | generic policy default, no dedicated ADR in this repository; T2, context-constrained (name or adjacent `AKIA`/`ASIA` ID), grammar and trade-offs in [Unsupported-variant contracts (#1012)](#unsupported-variant-contracts-1012) |
| `axiom_api_token` | `axiom-token` | `always-redact` | generic policy default, no dedicated ADR in this repository; prefix T1 (axiom-go runtime check, R6), UUID layout and lowercase hex T1 by example (docs response example and SDK fixtures, R5), grammar and trade-offs in [Beta.12 broad-discovery families, ranks 6 to 10 (#1014)](#beta12-broad-discovery-families-ranks-6-to-10-1014) |
| `axiom_personal_token` | `axiom-token` | `always-redact` | generic policy default, no dedicated ADR in this repository; prefix T1 (axiom-go runtime check, R6), UUID layout and lowercase hex T1 by example (R5), grammar and trade-offs in [Beta.12 broad-discovery families, ranks 6 to 10 (#1014)](#beta12-broad-discovery-families-ranks-6-to-10-1014) |
| `azure_devops_personal_access_token` | `azure-devops-personal-access-token` | `always-redact` | [Freeze the Azure DevOps personal access token grammar as the documented 84-byte AZDO-signature shape](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md); T1 provider source recorded in [#642 evidence](../audits/evidence/642/README.md) |
| `bearer_token` | `bearer-token` | `always-redact` | [Accept a truncated or nested-provider Bearer value under bearer-token's length-and-alphabet grammar](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| `bitwarden_secrets_manager_access_token` | `bitwarden-secrets-manager-access-token` | `always-redact` | generic policy default, no dedicated ADR in this repository; T1 (provider parser, server generator and docs example, R1), grammar and trade-offs in [Beta.12 broad-discovery provider families (#1014)](#beta12-broad-discovery-provider-families-1014) |
| `browserbase_api_key` | `browserbase-api-key` | `always-redact` | generic policy default, no dedicated ADR in this repository; T1 (provider docs prefix; alphabet and 20-byte floor from the provider's CI gate, R2), grammar and trade-offs in [Tier B provider families (#860)](#tier-b-provider-families-860) |
| `buildkite_agent_token` | `buildkite-token` | `always-redact` | generic policy default, no dedicated ADR in this repository; T1 (provider-authored redaction rule, R2, dated 2026-09-29 under R9; prefix list cross-checked against the provider docs, R1), the 24-byte floor is the provider redactor's own and rests on the Q7 recommendation (pending ruling), grammar and trade-offs in [Beta.14 broad-discovery families, second wave (#1102 to #1105)](#beta14-broad-discovery-families-second-wave-1102-to-1105) |
| `buildkite_api_access_token` | `buildkite-token` | `always-redact` | generic policy default, no dedicated ADR in this repository; T1 (provider-authored redaction rule, R2, dated 2026-09-29 under R9; prefix list cross-checked against the provider docs, R1), the 24-byte floor is the provider redactor's own and rests on the Q7 recommendation (pending ruling), grammar and trade-offs in [Beta.14 broad-discovery families, second wave (#1102 to #1105)](#beta14-broad-discovery-families-second-wave-1102-to-1105) |
| `buildkite_job_token` | `buildkite-token` | `always-redact` | generic policy default, no dedicated ADR in this repository; T1 (provider-authored redaction rule, R2, dated 2026-09-29 under R9; prefix list cross-checked against the provider docs, R1), the 24-byte floor is the provider redactor's own and rests on the Q7 recommendation (pending ruling), grammar and trade-offs in [Beta.14 broad-discovery families, second wave (#1102 to #1105)](#beta14-broad-discovery-families-second-wave-1102-to-1105) |
| `buildkite_oauth_token` | `buildkite-token` | `always-redact` | generic policy default, no dedicated ADR in this repository; T1 (provider-authored redaction rule, R2, dated 2026-09-29 under R9; prefix list cross-checked against the provider docs, R1), the 24-byte floor is the provider redactor's own and rests on the Q7 recommendation (pending ruling), grammar and trade-offs in [Beta.14 broad-discovery families, second wave (#1102 to #1105)](#beta14-broad-discovery-families-second-wave-1102-to-1105) |
| `buildkite_packages_token` | `buildkite-token` | `always-redact` | generic policy default, no dedicated ADR in this repository; T1 (provider-authored redaction rule, R2, dated 2026-09-29 under R9; prefix list cross-checked against the provider docs, R1), the 24-byte floor is the provider redactor's own and rests on the Q7 recommendation (pending ruling), grammar and trade-offs in [Beta.14 broad-discovery families, second wave (#1102 to #1105)](#beta14-broad-discovery-families-second-wave-1102-to-1105) |
| `buildkite_pipeline_token` | `buildkite-token` | `always-redact` | generic policy default, no dedicated ADR in this repository; T1 (provider-authored redaction rule, R2, dated 2026-09-29 under R9; prefix list cross-checked against the provider docs, R1), the 24-byte floor is the provider redactor's own and rests on the Q7 recommendation (pending ruling), grammar and trade-offs in [Beta.14 broad-discovery families, second wave (#1102 to #1105)](#beta14-broad-discovery-families-second-wave-1102-to-1105) |
| `buildkite_portal_token` | `buildkite-token` | `always-redact` | generic policy default, no dedicated ADR in this repository; T1 (provider-authored redaction rule, R2, dated 2026-09-29 under R9; prefix list cross-checked against the provider docs, R1), the 24-byte floor is the provider redactor's own and rests on the Q7 recommendation (pending ruling), grammar and trade-offs in [Beta.14 broad-discovery families, second wave (#1102 to #1105)](#beta14-broad-discovery-families-second-wave-1102-to-1105) |
| `cerebras_api_key` | `cerebras-api-key` | `always-redact` | generic policy default, no dedicated ADR in this repository; T1 prefixes and width (provider validator, R1; staff statement, R3 as of 2025-10), alphabet by policy (R10), grammar and trade-offs in [Tier B provider families (#860)](#tier-b-provider-families-860) |
| `clickhouse_cloud_api_secret` | `clickhouse-cloud-api-secret` | `always-redact` | generic policy default, no dedicated ADR in this repository; T1 as of 2025-04 (provider staff statement and staff-authored regex, R2 and R3; the older 39-byte example is set aside by R3 date order), grammar and trade-offs in [Tier B provider families (#860)](#tier-b-provider-families-860) |
| `clojars_deploy_token` | `clojars-deploy-token` | `always-redact` | generic policy default, no dedicated ADR in this repository; T1 (provider generator and server validator, R1), grammar and trade-offs in [Beta.12 broad-discovery provider families (#1014)](#beta12-broad-discovery-provider-families-1014) |
| `cloudflare_api_token` | `cloudflare-token` | `always-redact` | [Adopt the Cloudflare account-token prefix under the frozen cfut_ contract](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| `cohere_api_key` | `cohere-api-key` | `confidence-gated` | no dedicated ADR in this repository; contextual, unqualified claim stated under Keyword-gated provider keys below, per issue #868 |
| `composio_org_api_key` | `composio-api-key` | `always-redact` | generic policy default, no dedicated ADR in this repository; T1 (provider docs and a dated staff statement under R3; `uak_` width under R6), grammar and trade-offs in [Tier A provider families (#860)](#tier-a-provider-families-860) |
| `composio_project_api_key` | `composio-api-key` | `always-redact` | generic policy default, no dedicated ADR in this repository; T1 (provider docs and a dated staff statement under R3; `uak_` width under R6), grammar and trade-offs in [Tier A provider families (#860)](#tier-a-provider-families-860) |
| `composio_user_api_key` | `composio-api-key` | `always-redact` | generic policy default, no dedicated ADR in this repository; T1 (provider docs and a dated staff statement under R3; `uak_` width under R6), grammar and trade-offs in [Tier A provider families (#860)](#tier-a-provider-families-860) |
| `confluent_cloud_api_secret` | `confluent-cloud-api-secret` | `always-redact` | generic policy default, no dedicated ADR in this repository |
| `confluent_cloud_api_secret_legacy` | `confluent-cloud-api-secret-legacy` | `confidence-gated` | generic policy default, no dedicated ADR in this repository; issue #933 also reads a Schema Registry `basic.auth.user.info=<key id>:<secret>` property below a Confluent-named property line (bounded, with an incremental retention hint), reported `high` (redact) since issue #936 |
| `connection_string_password` | `connection-string` | `always-redact` | [Exclude a value fully delimited by `{{` and `}}` as a template reference](../decisions/2026-09-15-exclude-fully-delimited-template-references.md#folded-records) (folded: `decision-connection-string-and-jwt-need-no-retention-hint`) |
| `contextual_secret` | `generic-token` | `confidence-gated` | generic policy default, no dedicated ADR in this repository |
| `convex_deployment_key` | `convex-deployment-key` | `always-redact` | generic policy default, no dedicated ADR in this repository; T1 (provider code: backend key format and generator; hex length derived from the generator), grammar and trade-offs in [Tier B provider families (#860)](#tier-b-provider-families-860) |
| `crates_io_api_token` | `crates-io-token` | `always-redact` | generic policy default, no dedicated ADR in this repository; T1 (crates.io server generator, R1), grammar and trade-offs in [Beta.12 broad-discovery families, ranks 6 to 10 (#1014)](#beta12-broad-discovery-families-ranks-6-to-10-1014) |
| `crates_io_trusted_publishing_token` | `crates-io-token` | `always-redact` | generic policy default, no dedicated ADR in this repository; T1 (crates.io trusted-publishing generator, R1); the check character is not a rejection gate (pending ruling Q1), grammar and trade-offs in [Beta.12 broad-discovery families, ranks 6 to 10 (#1014)](#beta12-broad-discovery-families-ranks-6-to-10-1014) |
| `databricks_personal_access_token` | `databricks-personal-access-token` | `always-redact` | generic policy default, no dedicated ADR in this repository |
| `datadog_api_key` | `datadog-api-key` | `confidence-gated` | [Freeze the Datadog API Key and Application Key grammar as marker-gated lowercase-hex values](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| `datadog_application_key` | `datadog-application-key` | `always-redact` | generic policy default, no dedicated ADR in this repository; current `ddapp_`-prefixed shape added by issue #671, applying the existing `confluent_cloud_api_secret` / `heroku_api_key` current/legacy split policy to this family |
| `datadog_application_key_legacy` | `datadog-application-key-legacy` | `confidence-gated` | [Freeze the Datadog API Key and Application Key grammar as marker-gated lowercase-hex values](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| `daytona_api_key` | `daytona-api-key` | `always-redact` | generic policy default, no dedicated ADR in this repository; T1 as of v0.190.0 (provider generator, R1; dated provider code, R9), grammar and trade-offs in [Tier B provider families (#860)](#tier-b-provider-families-860) |
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
| `dynatrace_token` | `dynatrace-token` | `always-redact` | generic policy default, no dedicated ADR in this repository; T1 (Dynatrace docs for structure and lengths; base32 alphabet from the provider's `dttoken` generator, R1), grammar and trade-offs in [Beta.12 broad-discovery families, ranks 6 to 10 (#1014)](#beta12-broad-discovery-families-ranks-6-to-10-1014) |
| `e2b_api_key` | `e2b-api-key` | `always-redact` | generic policy default, no dedicated ADR in this repository; T1 (provider generator code under R1), grammar and trade-offs in [Tier A provider families (#860)](#tier-a-provider-families-860) |
| `elevenlabs_api_key` | `elevenlabs-api-key` | `always-redact` | generic policy default, no dedicated ADR in this repository |
| `firebase_server_key` | `firebase-server-key` | `always-redact` | [Add Firebase FCM legacy server key detection, and discriminate the public Web SDK client config from google-api-key](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| `firecrawl_api_key` | `firecrawl-api-key` | `always-redact` | generic policy default, no dedicated ADR in this repository; prefix T1 (docs, SDK), UUIDv4 body T1 (provider server code under R1), grammar and trade-offs in [Tier A provider families (#860)](#tier-a-provider-families-860) |
| `fireworks_ai_api_key` | `fireworks-ai-api-key` | `always-redact` | generic policy default, no dedicated ADR in this repository |
| `fly_access_token` | `fly-token` | `always-redact` | generic policy default, no dedicated ADR in this repository; T1 (the `superfly/macaroon` wire format, R1, and flyctl's own redaction rule, R2), the 64-byte first-member floor is derived from the wire format rather than provider-stated and rests on the Q7 recommendation (pending ruling), a standalone `fo1_` is unclaimed on the Q9 recommendation (pending ruling), the `FlyV1 ` scheme is outside the span, grammar and trade-offs in [Beta.14 broad-discovery families, third wave (#1106 to #1109)](#beta14-broad-discovery-families-third-wave-1106-to-1109) |
| `github_app_installation_token` | `github-token` | `always-redact` | [Map GitHub's six token families onto six independent finding types under one detector](../decisions/2026-09-20-map-github-token-families-onto-independent-finding-types.md) |
| `github_app_refresh_token` | `github-token` | `always-redact` | [Map GitHub's six token families onto six independent finding types under one detector](../decisions/2026-09-20-map-github-token-families-onto-independent-finding-types.md) |
| `github_app_user_to_server_token` | `github-token` | `always-redact` | [Map GitHub's six token families onto six independent finding types under one detector](../decisions/2026-09-20-map-github-token-families-onto-independent-finding-types.md) |
| `github_fine_grained_personal_access_token` | `github-token` | `always-redact` | [Map GitHub's six token families onto six independent finding types under one detector](../decisions/2026-09-20-map-github-token-families-onto-independent-finding-types.md) |
| `github_oauth_token` | `github-token` | `always-redact` | [Map GitHub's six token families onto six independent finding types under one detector](../decisions/2026-09-20-map-github-token-families-onto-independent-finding-types.md) |
| `github_token` | `github-token` | `always-redact` | [Map GitHub's six token families onto six independent finding types under one detector](../decisions/2026-09-20-map-github-token-families-onto-independent-finding-types.md) |
| `gitlab_runner_authentication_token` | `gitlab-runner-authentication-token` | `always-redact` | generic policy default, no dedicated ADR in this repository |
| `gitlab_token` | `gitlab-token` | `always-redact` | [Inventory the GitLab token-prefix table and contract the two undeclared prefixes; record routable tokens and the legacy runner-registration token as explicit, tracked gaps](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md); the routable `glpat-` form is reported whole since [#1022](https://github.com/redact-secret/redact-secret/issues/1022) (T1), grammar in [Unsupported-variant contracts (#1012)](#unsupported-variant-contracts-1012) |
| `google_api_key` | `google-api-key` | `always-redact` | [Redact a Google API key inside a Firebase Web SDK client config, reversing the client-config exemption](../decisions/2026-09-24-redact-google-api-keys-inside-firebase-web-config.md); T1 provider source recorded in [#642 evidence](../audits/evidence/642/README.md) |
| `google_oauth_client_secret` | `google-oauth-client-secret` | `always-redact` | generic policy default, no dedicated ADR in this repository; T2, grammar and trade-offs in [Unsupported-variant contracts (#1012)](#unsupported-variant-contracts-1012) |
| `grafana_cloud_access_policy_token` | `grafana-cloud-access-policy-token` | `always-redact` | [Freeze the Grafana service account and Cloud access policy token grammar, and exclude the legacy API key](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md); T1 provider source recorded in [#642 evidence](../audits/evidence/642/README.md) |
| `grafana_service_account_token` | `grafana-service-account-token` | `always-redact` | [Freeze the Grafana service account and Cloud access policy token grammar, and exclude the legacy API key](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md); T1 provider source recorded in [#642 evidence](../audits/evidence/642/README.md) |
| `groq_api_key` | `groq-api-key` | `always-redact` | generic policy default, no dedicated ADR in this repository |
| `helicone_api_key` | `helicone-api-key` | `always-redact` | generic policy default, no dedicated ADR in this repository; T1 (provider validator regexes and generators), `[a-z0-9]` per ruling R8, grammar and trade-offs in [Tier A provider families (#860)](#tier-a-provider-families-860) |
| `helicone_write_api_key` | `helicone-api-key` | `always-redact` | generic policy default, no dedicated ADR in this repository; T1 (provider validator regexes and generators), `[a-z0-9]` per ruling R8, grammar and trade-offs in [Tier A provider families (#860)](#tier-a-provider-families-860) |
| `heroku_api_key` | `heroku-api-key` | `always-redact` | generic policy default, no dedicated ADR in this repository; issue #740 adds the documented 41-character `HRKU-` + lower-case UUID generation beside `HRKU-AA` + 58, grammar in `detectors::heroku`'s module doc |
| `heroku_api_key_legacy` | `heroku-api-key-legacy` | `confidence-gated` | generic policy default, no dedicated ADR in this repository; issue #714 excludes a UUID assigned to an identifier-shaped key (last word `id` or `uuid`, e.g. `HEROKU_APP_ID`) from the `heroku` keyword gate, grammar in `detectors::heroku`'s module doc; issue #743 also accepts two documented multi-line layouts (a Heroku `.netrc` entry's `password`, `heroku auth:token` output, held open by an incremental retention hint) and excludes a UUID that is a URL path segment; issue #934 excludes an all-one-digit UUID placeholder (`00000000-0000-0000-0000-000000000000`); issue #933 adds a third multi-line layout, the `Token:` row of `heroku authorizations:<verb>` table output; issue #936 reports a UUID read through any of the three layouts at `high` (redact), the same-line keyword path staying `medium` unless the key names Heroku |
| `honeycomb_ingest_key` | `honeycomb-api-key` | `always-redact` | generic policy default, no dedicated ADR in this repository; T1 (Honeycomb docs prefix; provider SDK regex, length gate and fixtures, R1 and R5); management keys stay issuance-gated and unclaimed, grammar and trade-offs in [Beta.12 broad-discovery families, ranks 6 to 10 (#1014)](#beta12-broad-discovery-families-ranks-6-to-10-1014) |
| `huggingface_token` | `huggingface-token` | `always-redact` | [Adopt the Hugging Face organization-token prefix under hf_'s frozen body grammar, re-tiered to T2](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| `inngest_signing_key` | `inngest-signing-key` | `always-redact` | generic policy default, no dedicated ADR in this repository; T1 (Inngest provider code constants, docs generation command and SDK fixtures), grammar and trade-offs in [Tier B provider families (#860)](#tier-b-provider-families-860) |
| `jwt` | `jwt` | `always-redact` | [Exclude a value fully delimited by `{{` and `}}` as a template reference](../decisions/2026-09-15-exclude-fully-delimited-template-references.md#folded-records) (folded: `decision-connection-string-and-jwt-need-no-retention-hint`) |
| `langfuse_secret_key` | `langfuse-secret-key` | `always-redact` | generic policy default, no dedicated ADR in this repository |
| `langsmith_api_key` | `langsmith-api-key` | `always-redact` | generic policy default, no dedicated ADR in this repository |
| `linear_token` | `linear-token` | `always-redact` | generic policy default, no dedicated ADR in this repository; T1 provider source recorded in [#642 evidence](../audits/evidence/642/README.md) |
| `mailchimp_api_key` | `mailchimp-api-key` | `confidence-gated` | no dedicated ADR in this repository; grammar frozen in `detectors::mailchimp`'s own module doc, per issue #313; issue #931 relaxes the #313 same-line `mailchimp` keyword gate for the complete shape only (32 hex, `-us`, 1–3 digit datacenter): a keyword-free match that is a DNS label or URL path segment is not reported; issue #936 raises the complete shape outside a DNS label or URL path to `high` (redact) with or without a keyword, so only a keyword-kept DNS-label or path match stays `medium` (warn) |
| `mailgun_api_key` | `mailgun-api-key` | `confidence-gated` | no dedicated ADR in this repository; grammar frozen in `detectors::mailgun`'s own module doc, per issue #314 |
| `mapbox_secret_access_token` | `mapbox-token` | `always-redact` | generic policy default, no dedicated ADR in this repository; T1 (provider docs and the provider's token parser, R1; signature width by R5), the payload floor of 20 is derived rather than provider-stated and rests on the Q7 recommendation (pending ruling), `pk.` is public and never claimed, `tk.` is unclaimed on the Q9 recommendation (pending ruling), grammar and trade-offs in [Beta.14 broad-discovery families, third wave (#1106 to #1109)](#beta14-broad-discovery-families-third-wave-1106-to-1109) |
| `microsoft_entra_client_secret` | `microsoft-entra-client-secret` | `always-redact` | [Freeze the Microsoft Entra application client-secret grammar as an unprefixed digit-Q-tilde marker](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| `mistral_api_key` | `mistral-api-key` | `confidence-gated` | no dedicated ADR in this repository; contextual, unqualified claim stated under Keyword-gated provider keys below, per issue #868 |
| `neon_api_key` | `neon-api-key` | `always-redact` | generic policy default, no dedicated ADR in this repository |
| `netlify_personal_access_token` | `netlify-token` | `always-redact` | generic policy default, no dedicated ADR in this repository |
| `new_relic_license_key` | `new-relic-license-key` | `confidence-gated` | [Freeze the New Relic User API Key and License Key grammar as an exact-length prefixed shape and a keyword-gated bare hex shape](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| `new_relic_user_api_key` | `new-relic-user-api-key` | `always-redact` | [Freeze the New Relic User API Key and License Key grammar as an exact-length prefixed shape and a keyword-gated bare hex shape](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md); T1 provider source recorded in [#642 evidence](../audits/evidence/642/README.md) |
| `notion_integration_token` | `notion-token` | `always-redact` | [Freeze the Notion integration token grammar as two exact-length prefixed shapes](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md); T1 provider source recorded in [#642 evidence](../audits/evidence/642/README.md) |
| `npm_access_token` | `npm-token` | `always-redact` | generic policy default, no dedicated ADR in this repository |
| `nvidia_api_key` | `nvidia-api-key` | `always-redact` | generic policy default, no dedicated ADR in this repository; T1 (prefix from provider docs and the `ngcsdk` constant, R1 and R6; alphabet and 60-byte floor from a provider-authored scanning rule, R2), grammar and trade-offs in [Tier B provider families (#860)](#tier-b-provider-families-860) |
| `okta_api_token` | `okta-api-token` | `confidence-gated` | no dedicated ADR in this repository; grammar frozen in `detectors::okta`'s own module doc, per issue #315 |
| `onepassword_service_account_token` | `onepassword-service-account-token` | `always-redact` | generic policy default, no dedicated ADR in this repository; T1 (1Password docs: prefix and Base64url encoding; the 250-byte floor is project policy), grammar and trade-offs in [Tier B provider families (#860)](#tier-b-provider-families-860) |
| `openai_admin_api_key` | `openai-token` | `always-redact` | generic policy default, no dedicated ADR in this repository; issue #774 splits the `sk-admin-` namespace out of the shared `openai_api_key` type (materially different blast radius: an organization Admin API key, not a project/service-account key). Grammar untouched: still the T2 marker-gated 58/74-byte contract from [#863](https://github.com/redact-secret/redact-secret/issues/863), [Freeze the OpenAI API key grammar as a marker-gated shape with exact segment lengths](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| `openai_api_key` | `openai-token` | `always-redact` | [Freeze the OpenAI API key grammar as a marker-gated shape with exact segment lengths](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| `openrouter_api_key` | `openrouter-api-key` | `always-redact` | generic policy default, no dedicated ADR in this repository |
| `otpauth_secret` | `otpauth-uri` | `always-redact` | generic policy default, no dedicated ADR in this repository |
| `paddle_api_key` | `paddle-api-key` | `always-redact` | generic policy default, no dedicated ADR in this repository; T1 (Paddle docs publish the full regex and the 69-character length), grammar and trade-offs in [Beta.12 broad-discovery families, ranks 6 to 10 (#1014)](#beta12-broad-discovery-families-ranks-6-to-10-1014) |
| `perplexity_api_key` | `perplexity-api-key` | `always-redact` | generic policy default, no dedicated ADR in this repository |
| `pinecone_api_key` | `pinecone-api-key` | `always-redact` | [Claim a legacy Pinecone UUID key only under a Pinecone API-key name, and redact it](../decisions/2026-09-24-claim-a-legacy-pinecone-uuid-key-only-under-its-api-key-name.md) |
| `polar_api_credential` | `polar-token` | `always-redact` | generic policy default, no dedicated ADR in this repository; T1 (provider server generator and prefix constants, R1 and R9; union of the URL-safe and alphanumeric eras), grammar and trade-offs in [Beta.12 broad-discovery provider families (#1014)](#beta12-broad-discovery-provider-families-1014) |
| `polar_organization_access_token` | `polar-token` | `always-redact` | generic policy default, no dedicated ADR in this repository; T1 (provider server generator and prefix constants, R1 and R9); the CRC32 never rejects a match (ruling Q1 open), grammar and trade-offs in [Beta.12 broad-discovery provider families (#1014)](#beta12-broad-discovery-provider-families-1014) |
| `posthog_personal_api_key` | `posthog-token` | `always-redact` | generic policy default, no dedicated ADR in this repository; T1 (provider generator code and unit tests under R1), grammar and trade-offs in [Tier A provider families (#860)](#tier-a-provider-families-860) |
| `posthog_project_secret_api_key` | `posthog-token` | `always-redact` | generic policy default, no dedicated ADR in this repository; T1 (provider generator code and unit tests under R1), grammar and trade-offs in [Tier A provider families (#860)](#tier-a-provider-families-860) |
| `postman_api_key` | `postman-api-key` | `always-redact` | generic policy default, no dedicated ADR in this repository |
| `postman_collection_access_key` | `postman-collection-access-key` | `always-redact` | generic policy default, no dedicated ADR in this repository |
| `private_key` | `private-key` | `block` | generic policy default, no dedicated ADR in this repository |
| `pulumi_access_token` | `pulumi-access-token` | `always-redact` | [Freeze the Pulumi access token grammar as a documented-prefix, tool-corroborated exact-length hex shape](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| `pydantic_logfire_token` | `pydantic-logfire-token` | `always-redact` | generic policy default, no dedicated ADR in this repository; T1 (provider SDK parsers, R1, and the provider scrubber, R2), the 20-byte body floor and 16-letter region cap are narrowing policy rather than provider-stated widths and rest on the Q7 recommendation (pending ruling), grammar and trade-offs in [Beta.14 broad-discovery families, third wave (#1106 to #1109)](#beta14-broad-discovery-families-third-wave-1106-to-1109) |
| `pypi_api_token` | `pypi-token` | `always-redact` | generic policy default, no dedicated ADR in this repository |
| `replicate_api_token` | `replicate-api-token` | `always-redact` | generic policy default, no dedicated ADR in this repository |
| `resend_api_key` | `resend-api-key` | `always-redact` | generic policy default, no dedicated ADR in this repository; prefix T1 (Resend CLI), layout T1 by example (docs response example and SDK fixtures, R5), grammar and trade-offs in [Tier B provider families (#860)](#tier-b-provider-families-860) |
| `rubygems_api_key` | `rubygems-api-key` | `always-redact` | generic policy default, no dedicated ADR in this repository; T1 (provider server generator, R1), grammar and trade-offs in [Beta.12 broad-discovery provider families (#1014)](#beta12-broad-discovery-provider-families-1014) |
| `runpod_api_key` | `runpod-api-key` | `always-redact` | generic policy default, no dedicated ADR in this repository; T1 prefix and alphabet (provider blog and scrubber, R2), policy floor 31 under R10, grammar and trade-offs in [Tier B provider families (#860)](#tier-b-provider-families-860) |
| `sendgrid_api_key` | `sendgrid-token` | `always-redact` | generic policy default, no dedicated ADR in this repository |
| `sentry_org_auth_token` | `sentry-org-auth-token` | `always-redact` | [Freeze the Sentry user and organization auth token grammar as two unambiguous prefixed shapes](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| `sentry_user_auth_token` | `sentry-user-auth-token` | `always-redact` | [Freeze the Sentry user and organization auth token grammar as two unambiguous prefixed shapes](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| `shopify_access_token` | `shopify-token` | `always-redact` | generic policy default, no dedicated ADR in this repository |
| `slack_app_level_token` | `slack-token` | `always-redact` | generic policy default, no dedicated ADR in this repository |
| `slack_token` | `slack-token` | `always-redact` | [Freeze the Slack bot token grammar as a three-section dash-separated shape](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| `slack_user_token` | `slack-token` | `always-redact` | generic policy default, no dedicated ADR in this repository |
| `sonarqube_analysis_token` | `sonarqube-token` | `always-redact` | generic policy default, no dedicated ADR in this repository; T1 (provider server generator and token type enum, R1), grammar and trade-offs in [Beta.12 broad-discovery provider families (#1014)](#beta12-broad-discovery-provider-families-1014) |
| `sonarqube_user_token` | `sonarqube-token` | `always-redact` | generic policy default, no dedicated ADR in this repository; T1 (provider server generator and token type enum, R1), grammar and trade-offs in [Beta.12 broad-discovery provider families (#1014)](#beta12-broad-discovery-provider-families-1014) |
| `sourcegraph_access_token` | `sourcegraph-token` | `always-redact` | generic policy default, no dedicated ADR in this repository; T1 as of 2025-11-18 (provider generator and validator, R1; dated provider code, R9), grammar and trade-offs in [Beta.14 broad-discovery families, second wave (#1102 to #1105)](#beta14-broad-discovery-families-second-wave-1102-to-1105) |
| `square_access_token` | `square-token` | `always-redact` | generic policy default, no dedicated ADR in this repository; T1 (provider docs examples, R4 and R5, corroborated by scanner rules), exact widths rest on the Q8 recommendation (pending ruling) because the provider disclaims length validation, the conflicting `EAAl` and `EQAA` shapes are unclaimed, grammar and trade-offs in [Beta.14 broad-discovery families, third wave (#1106 to #1109)](#beta14-broad-discovery-families-third-wave-1106-to-1109) |
| `square_oauth_application_secret` | `square-token` | `always-redact` | generic policy default, no dedicated ADR in this repository; T1 (provider docs examples, R4 and R5, corroborated by scanner rules), exact widths rest on the Q8 recommendation (pending ruling) because the provider disclaims length validation, the conflicting `EAAl` and `EQAA` shapes are unclaimed, grammar and trade-offs in [Beta.14 broad-discovery families, third wave (#1106 to #1109)](#beta14-broad-discovery-families-third-wave-1106-to-1109) |
| `stripe_credential` | `stripe-token` | `always-redact` | generic policy default, no dedicated ADR in this repository; issue #934 excludes a body that is one repeated character (`sk_test_` plus a run of `x`). Organization keys: `sk_org_`, `sk_org_live_` and `sk_org_test_` each + at least 20 `[A-Za-z0-9]`, same type and action (#1030, research #1012). The prefix is T1 (Stripe docs); the `live_`/`test_` segment rests on two independent implementations that branch on it and is not provider-documented; no issued key has been observed, so body length and alphabet after the segment are unverified and the floor stays the conservative lexical one. Trade-off: no new false-positive surface worth naming (the prefix is unique); it removes a likely total false negative for org keys outside named contexts; a body that is shorter than 20, holds `_`/`-`, or uses another mode word stays unclaimed (intentional false negative), and `rk_org_` stays excluded (Stripe: no such prefix). Not a support-status claim; `docs/support-matrix.md` keeps the organization row Unsupported |
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
| `twilio_auth_token` | `twilio-auth-token` | `confidence-gated` | [Freeze the Twilio Auth Token and API Key Secret grammar as context-gated 32-byte values](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md); issue #933 also reads the `Auth Token` column of a `twilio` CLI table (bounded, with an incremental retention hint), reported `high` (redact) since issue #936 |
| `unkey_root_key` | `unkey-root-key` | `always-redact` | generic policy default, no dedicated ADR in this repository; T1 (provider design document RFC 0017, generator and handler test, R1 and R9; dashboard width and lead derived from the generator), the CRC-32C is not a rejection gate (pending ruling Q1), customer-prefixed keys are out of contract until ruling Q10, grammar and trade-offs in [Beta.14 broad-discovery families, second wave (#1102 to #1105)](#beta14-broad-discovery-families-second-wave-1102-to-1105) |
| `vault_token` | `vault-token` | `always-redact` | generic policy default, no dedicated ADR in this repository |
| `vendor_prefixed_credential` | `generic-token` | `always-redact` | [Redact a bare, marker-less OpenAI-prefixed value under a generic policy layer, beneath the frozen contract](../decisions/2026-09-21-govern-bare-vendor-prefixed-policy-layer.md) |
| `vercel_app_access_token` | `vercel-token` | `always-redact` | generic policy default, no dedicated ADR in this repository; issue #1036 splits `vca_` + exactly 56 `[A-Za-z0-9]` out of `vercel_token` (T2, one provider value), following [Map GitHub's six token families onto six independent finding types under one detector](../decisions/2026-09-20-map-github-token-families-onto-independent-finding-types.md); grammar and trade-offs in [Vercel per-class split (#1036)](#vercel-per-class-split-1036) |
| `vercel_app_refresh_token` | `vercel-token` | `always-redact` | generic policy default, no dedicated ADR in this repository; issue #1036 splits `vcr_` + exactly 56 `[A-Za-z0-9]` out of `vercel_token` (T2, body shared with the `vca_` example), following [Map GitHub's six token families onto six independent finding types under one detector](../decisions/2026-09-20-map-github-token-families-onto-independent-finding-types.md); see [Vercel per-class split (#1036)](#vercel-per-class-split-1036) |
| `vercel_personal_access_token` | `vercel-token` | `always-redact` | generic policy default, no dedicated ADR in this repository; issue #1036 splits `vcp_` + exactly 56 `[A-Za-z0-9]` out of `vercel_token` (T2), following [Map GitHub's six token families onto six independent finding types under one detector](../decisions/2026-09-20-map-github-token-families-onto-independent-finding-types.md); see [Vercel per-class split (#1036)](#vercel-per-class-split-1036) |
| `vercel_token` | `vercel-token` | `always-redact` | generic policy default, no dedicated ADR in this repository; since issue #1036 the unqualified compatibility type: every `vci_` and `vck_` match, and every `vcp_`/`vca_`/`vcr_` match off the exact-56 contract (security-first fallback), all at the unchanged pre-split `>= 20` `[A-Za-z0-9_-]` shape. It claims no grammar (pending maintainer ruling Q-VC); see [Vercel per-class split (#1036)](#vercel-per-class-split-1036) |
| `wandb_api_key` | `wandb-api-key` | `always-redact` | generic policy default, no dedicated ADR in this repository; prefix T1 (W&B test constant, R5), alphabet T1 (SDK validator, R1); the 64–96 band is a tolerant range around the documented width, grammar and trade-offs in [Tier B provider families (#860)](#tier-b-provider-families-860) |
| `xai_api_key` | `xai-api-key` | `always-redact` | generic policy default, no dedicated ADR in this repository |
| `xata_organization_api_key` | `xata-api-key` | `always-redact` | generic policy default, no dedicated ADR in this repository; T1 (provider generator and validator, R1 and R9; body width derived from the generator's encoder), the CRC32 is not a rejection gate (pending ruling Q1), grammar and trade-offs in [Beta.14 broad-discovery families, second wave (#1102 to #1105)](#beta14-broad-discovery-families-second-wave-1102-to-1105) |
| `xata_user_api_key` | `xata-api-key` | `always-redact` | generic policy default, no dedicated ADR in this repository; T1 (provider generator and validator, R1 and R9; body width derived from the generator's encoder), the CRC32 is not a rejection gate (pending ruling Q1), grammar and trade-offs in [Beta.14 broad-discovery families, second wave (#1102 to #1105)](#beta14-broad-discovery-families-second-wave-1102-to-1105) |
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
| `generic:connection-string-password` | One case-insensitive URI scheme from `postgresql`, `postgres`, `mysql`, `mariadb`, `mongodb+srv`, `mongodb`, `redis`, `rediss`, `amqp`, `amqps`, `https`, `http`, `ftps`, or `ftp`, and for the four SQL dialects a SQLAlchemy `+<driver>` suffix of 1–32 `[A-Za-z0-9_]` bytes (`postgresql+psycopg`, [#935](https://github.com/redact-secret/redact-secret/issues/935)); exactly one userinfo `@`; a valid scheme-specific host; and a non-empty password after `:`. For `mongodb` and `mongodb+srv` only, a userinfo the strict grammar declines (a malformed percent escape such as `ab%zz<v>`, `100%<v>` or a trailing `%`, a raw `@`, or a raw `/`, `?` or `#` in the password) is read over the password slot as well ([#1226](https://github.com/redact-secret/redact-secret/issues/1226); [decision](../decisions/2026-10-06-read-the-mongodb-uri-password-slot-when-the-userinfo-is-malformed.md)): the user is the non-empty run before the first `:`, the userinfo ends at the last `@` before the first `/`, `?` or `#` (the Go driver's reading; with a raw `/`, `?` or `#` that ended the authority first, at the first `@` followed by a valid host list), and the text after it up to the next `/`, `?` or `#` is a valid host list for the scheme. An unencoded `'` in the userinfo is a password byte unless a `'` immediately before the scheme opened the URL ([#1201](https://github.com/redact-secret/redact-secret/issues/1201)). Redis and Rediss also accept password-only userinfo. Percent escapes must be valid and are not decoded. | The original undecoded password substring only; `connection_string_password`, high confidence, default `redact` (the relaxed MongoDB form is `medium`, and `redact` all the same because `connection_string_password` redacts at every confidence). | Empty, placeholder, filler, tutorial prose, and recognized reference/template values are excluded, as are malformed encodings or hosts and multiple `@` bytes (except the relaxed MongoDB form above, whose placeholder, reference, host-only and host:port-before-a-raw-`/` exclusions are listed in the decision), unsupported schemes, and over-bound authorities or values. Query/property password forms are blind spots. Azure Storage `AccountKey` is a separate semicolon-delimited grammar emitted by the same detector and is outside this userinfo claim. | Research [#651](../audits/evidence/651/README.md); exact-span and context cases `connection-positive-postgres`, `connection-positive-redis-password-only`, `connection-regression-https-userinfo-percent-encoded-password`; benign/boundary cases `connection-negative-host-only`, `connection-boundary-placeholder`, `connection-negative-malformed-percent` (a postgres URI: it stays benign, the malformed-escape exclusion is not a statement about MongoDB; the two MongoDB cases that were benign for the same reason, `connection-negative-mongodb-malformed-percent` and `connection-negative-mongodb-srv-malformed-percent`, are the positives `connection-regression-mongodb-malformed-percent-password` and `connection-regression-mongodb-srv-malformed-percent-password`, medium, over the password). |
| `generic:otp-seed` | A literal lowercase `otpauth://totp/` or `otpauth://hotp/` envelope whose first exact lowercase `secret` query parameter is an uppercase RFC 4648 Base32 run of at least 16 characters followed by optional `=` padding. The envelope and Base32 alphabet have external documentation; case, the length floor, and accepted padding are project choices. | The first secret value only, including padding; `otpauth_secret`, high confidence, default `redact`. | Bare seeds, lowercase or mixed-case values, encoded padding, an unsupported or differently cased scheme/type/key, an invalid first `secret` value, and a duplicate URI whose first `secret` is invalid are excluded or blind. The detector never falls through to a later duplicate. | Research [#652](../audits/evidence/652/README.md); exact-span and context cases `otpauth-positive-totp-minimal`, `otpauth-positive-hotp-minimal`, `otpauth-positive-duplicate-secret-first-wins`; benign/boundary cases `otpauth-negative-bare-base32-identifier-no-scheme`, `otpauth-boundary-invalid-base32-alphabet`, `otpauth-boundary-percent-encoded-padding-tradeoff`. |
| `generic:unclassified-assignment-literal` | A direct literal assigned with `=`, `:`, or `:=` to the built-in high-signal or ambiguous name vocabulary, including its documented normalization and generic-prefix rules; URL query/form names use the separately bounded query path. Values are 8–4096 bytes. This does not cover arbitrary assignments. | The value only. A high-signal name emits `contextual_secret` at high confidence and default `redact` only when the existing bounded high-confidence value contract is met; otherwise it emits medium confidence and default `warn`. An ambiguous name must meet the stronger value contract, remains medium confidence, and defaults to `warn`. `block` is never promised. | Whole-value placeholders, references/interpolations, secret-manager/keychain references, SQL binds, source-code expressions, filler and masks, public identifiers, provider-prefixed ambiguous names (a provider-prefixed high-signal name is claimed since #948, and a provider finding on the same value wins overlap), unsupported names, and non-literal expressions are excluded. Unsupported operators and a real credential under an unrecognized name remain blind spots. | Research [#653](../audits/evidence/653/README.md); exact-span/action cases `contextual-positive-assignment`, `contextual-positive-minimum-length-is-medium-confidence`, `contextual-positive-remaining-declared-names`; benign cases `contextual-negative-shell-placeholder`, `contextual-negative-django-settings-attribute-reference`, `contextual-negative-repeated-asterisk-filler`. |

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
does not create a new ADR. Its `pii-v1` support state is `provisional`, not `stable`, from the Beta.11
qualification summarized below.

`pii:global:iban` likewise uses the one `pii-domain` adapter. Its exact
selector is `pii:family:global:iban`, public type is `pii_global_iban`,
family-contract version is `1`, and `contextRequirement` is
`required-for-sensitive-classification`. The
[IBAN family contract](../contracts/pii/iban-v1.md) pins SWIFT Registry Release
103 country lengths and `iban-mod97` v1 provenance, bounded compact/print
normalization, sensitivity semantics, safe fixtures, and false-positive and
false-negative costs. This applies existing PII policy to one family and adds
no ADR. Its `pii-v1` support state is `provisional`, not `stable`, from the Beta.11
qualification summarized below.

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
applies existing policy and creates no ADR. Its `pii-v1` support state is `provisional`, not `stable`, from the Beta.11
qualification summarized below.

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
existing policy and creates no ADR. Its `pii-v1` support state is `provisional`, not `stable`, from the Beta.11
qualification summarized below. It covers only the `+1` / NANP
subset.

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
existing PII policy and creates no ADR. Its support state remains `pending`:
its Beta.11 protected run did not meet `identity-only-classification`, so it
does not yet complete the `pii-v1` arrival gate.

Under `pii-v1`, the Beta.11 qualification of candidate core
`8b6a5fde52ecb4dfce13f09c7a947062d21483c7` made network-address, email,
payment-card, IBAN, and phone `provisional`; US SSN stays `pending` because its
protected run missed `identity-only-classification` and its one attempt is
spent. None is `stable`: the five met `profile-cost` only through a
maintainer-accepted tradeoff for the PII-on cost cells, and that route never
assigns `stable`. Evidence: the
[final record](https://github.com/redact-secret/redact-secret-benchmarks/blob/be0fb9f35045bf05e5b999a2c0ed368541f9e963/evidence/901/428/final-core-8b6a5fde.md),
the [protected disposition](https://github.com/redact-secret/redact-secret-benchmarks/blob/be0fb9f35045bf05e5b999a2c0ed368541f9e963/evidence/901/428/core-8b6a5fde52ec/pii-beta11-protected-disposition-v2.json),
and the [cost acceptance](https://github.com/redact-secret/redact-secret-benchmarks/blob/be0fb9f35045bf05e5b999a2c0ed368541f9e963/benchmarks/accepted-pii-profile-cost.json).
Selecting a family makes it available and is not a support claim, and PII
stays opt-in and separate from the credential detector profiles. US SSN is the
only jurisdictional family; no other jurisdiction or national identifier is
available. Each family's disposition is tracked in
[redact-secret-benchmarks#428](https://github.com/redact-secret/redact-secret-benchmarks/issues/428).

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
| `vercel:personal-access-token`, `vercel:app-access-token`, `vercel:app-refresh-token` | T2 on `vcp_` / `vca_` / `vcr_` + exactly 56 `[A-Za-z0-9]` (60 in total), no `_` or `-` in the body, no checksum requirement; each reports its own finding type (#1036). A value with the marker but another body keeps the pre-split `vercel_token` finding (security-first fallback). `vca_` and `vcr_` are thin: one checksum-valid provider value, whose body the `vcr_` example reuses. The legacy unprefixed 24-character form is excluded from all three. | [#1013 vercel](../audits/evidence/1013/vercel.md), [#858](../audits/evidence/858/README.md) |
| `vercel:integration-token`, `vercel:api-key` | Still pending, T0 on the body: `vck_` is a provider-backed marker, but no provider source writes `vci_` with the underscore, and neither has a full-length provider value. Both keep the interim `>= 20` `[A-Za-z0-9_-]` shape and the unqualified compatibility type `vercel_token`, so their redaction is not reduced; no grammar is claimed. Unblocks on maintainer ruling Q-VC (one generator family) or one issued value each. | [#1013 vercel](../audits/evidence/1013/vercel.md), [#858](../audits/evidence/858/README.md) |

## Vercel per-class split (#1036)

`vercel-token` reports one finding type per Vercel credential class
([#1036](https://github.com/redact-secret/redact-secret/issues/1036), research
[#1013](../audits/evidence/1013/vercel.md), taxonomy
[#858](../audits/evidence/858/README.md)), under one detector id, the
one-detector, several-types model of `github-token`. `Provider` specificity,
high confidence, always redacted.

Matching is unchanged: every prefix is matched exactly as before #1036, the
marker plus at least 20 `[A-Za-z0-9_-]` in one maximal run, with a
`[A-Za-z0-9_-]` boundary on both sides. Every span, and so every redaction,
equals the pre-split detector's (pinned by an oracle test against the
pre-split table). Only the finding type of a match is refined:

| Matched value | Finding type | Tier |
| --- | --- | --- |
| `vcp_` + exactly 56 `[A-Za-z0-9]` (60 in total) | `vercel_personal_access_token` | T2 (provider CLI example as a shape, CredSweeper, Kingfisher) |
| `vca_` + exactly 56 `[A-Za-z0-9]` | `vercel_app_access_token` | T2, thin (one checksum-valid provider value, copied by both peer rules) |
| `vcr_` + exactly 56 `[A-Za-z0-9]` | `vercel_app_refresh_token` | T2, thin (the provider example reuses the `vca_` body) |
| any other match: `vcp_`/`vca_`/`vcr_` off the exact contract, and every `vci_`/`vck_` | `vercel_token` | none claimed; `vci_`/`vck_` pending Q-VC |

Security-first fallback: a `vcp_`, `vca_` or `vcr_` value whose body is not
exactly 56 alphanumerics (55 or 57 bytes, a `_` or `-` in the body, a glued
`..._backup` or `...-1`) is still reported, whole and redacted, as the
unqualified `vercel_token`, in every context, bare and in prose included.
Nothing redacted before #1036 becomes unredacted. Because the run is maximal,
a typed value glued to a wider identifier is reported whole as
`vercel_token`, never truncated to a typed 60-byte span. The markers are
case-sensitive. The CRC-32/base62 tail Kingfisher checks is not required: it
is provider-backed on one `vca_` value only, and the provider's own CLI
`vcp_` example fails it. `dpl_` deployment ids, `prj_`/`team_` ids, every
other `vc?_` letter and the legacy unprefixed 24-character form stay
unclaimed. `vercel` stays in `generic-token`'s dedicated-provider deferral
list, unchanged.

`vci_` and `vck_` always report `vercel_token`, which claims no grammar for
them. The shared shape's alphabet equals its boundary, so a glued
`..._backup` is absorbed into the match, the open-floor defect #551 left out
of scope; it is kept so no redaction is lost, until Q-VC or issuance decides a
grammar.

Compatibility: `vercel_token` shipped for all five prefixes. Code that
filters, allowlists or counts findings by `vercel_token` no longer sees
exact-contract `vcp_`, `vca_` or `vcr_` values; it must also match the three
new types. `vercel_token` still reports every other match. The detector id
and the always-redact action are unchanged.

False negatives: none added; the match set is the pre-#1036 one. False
positives: unchanged in count and span. A 56-byte alphanumeric filler after a
typed marker (`vcp_` + 56 `x`) is typed as a personal access token, and the
open-floor false positives of the old shape (short, over-long or punctuated
bodies after any marker) stay, now under `vercel_token`. Cost: one byte-class
check of each matched span; prefixes, lead bytes and prefilter literals are
unchanged.

Since [#1042](https://github.com/redact-secret/redact-secret/issues/1042) a
body that is one repeated character (`vcp_` + a run of `x`, the masked filler
[#1013](../audits/evidence/1013/vercel.md) P4 names a placeholder) is not
reported under any marker, as for `stripe-token` and
`heroku-api-key-legacy` (#934), so the `vcp_` + 56 `x` false positive above
is gone. A random body is never one character; a body with any second
character is still reported.

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
| `cohere:api-key` | exactly 40 `[A-Za-z0-9]` | key name carrying `cohere` or exactly `CO_API_KEY`; `cohere.ClientV2(...)` / `CohereClient(...)` argument (`api_key`, `token`) or sole positional; a credential-named builder method, `Cohere.builder().token("...")` (#932); a credential-named key, unmasked `masked_api_key=` included, on a line naming a `cohere/<model>` route (#1018) | landed, `cohere-api-key` |
| `ai21:api-key` | exactly 32 `[A-Za-z0-9]` | key name carrying `ai21`; `AI21Client(...)` argument | landed, `ai21-api-key` |
| `deepgram:api-key` | exactly 40 `[0-9a-z]` (the wider of trufflehog `[0-9a-z]` and betterleaks hex; the docs example, 32 hex, is read as a placeholder) | key name carrying `deepgram`; `DeepgramClient(...)` argument or sole positional; the last positional literal of a `deepgram.` call, `deepgram.NewRESTWithDefaults(ctx, "...")` (#932); `Authorization: Token <v>` or HTTPie `Authorization:Token <v>` on a line naming `deepgram` (`high` when the line names a host under the `deepgram.com` API domain, #936); since #1017 the JS SDK v3 `createClient("...")` / `createClient({ key: "..." })` on a line naming `deepgram`, the WebSocket token subprotocol (`Sec-WebSocket-Protocol: token, <v>`, `["token", "<v>"]`) with the same host rule, a token header or subprotocol whose request line or `Host:` header names the API host up to 8 header lines above, and a sibling `provider: deepgram` field (same line, or up to 6 keys above in the same YAML mapping) under a credential key or `auth` | landed, `deepgram-api-key` |
| `exa:api-key` | none: no source states any shape (only the key *id* is documented, as a UUID) | none | **not landed**; stays with `generic-token` (env, JSON, YAML, `x-api-key`, `Bearer`), its SDK-call keyword-argument form is read by `generic-token` since #866; a positional `Exa("...")` stays out (no credential name) |

Confidence: a named assignment (`MISTRAL_API_KEY=`, `"deepgramApiKey":`) or an
SDK constructor argument is `high` (redacted by default); a credential key
within 32 bytes after the keyword (`# Mistral API key: <v>`) or the Deepgram
`Token` header on a line that names `deepgram` only as a word is `medium`
(warned). Since [#936](https://github.com/redact-secret/redact-secret/issues/936)
the Deepgram `Token` header is `high` (redacted) when its line names a host
under the Deepgram API domain (`api.deepgram.com`, `api.eu.deepgram.com`): the
value sits in the key's documented slot of a request to the provider, which is
as specific as a provider-named key. A look-alike host
(`api.deepgram.com.example.test`, `deepgram.company`) stays `medium`. The types are not in the always-redact
list, like `twilio_auth_token`.

Issue [#1017](https://github.com/redact-secret/redact-secret/issues/1017)
applies the same structural rule (the #936 amendment of
`decision-redact-provider-named-credential-assignments`) to more Deepgram
forms, all `high`: the `createClient` factory of `@deepgram/sdk` when the line
names `deepgram` (its import or its receiving variable); the browser WebSocket
`token` subprotocol on a request to the API host (`medium` with `deepgram`
only as a word); a token header or subprotocol whose request line or `Host:`
header names the API host on an earlier line of the same request (at most 8
header lines up, no blank or non-header line between; since
[#1046](https://github.com/redact-secret/redact-secret/issues/1046) a request
line or header indented by spaces or tabs reads as the same line unindented); and a credential key
(or `auth`) beside a `provider: <keyword>` field, on the same line
(`{"provider":"deepgram","auth":"..."}`, which `generic-token` only warned on)
or up to 6 keys above in the same YAML mapping. The sibling-field and
multi-line rules apply to all four keyword-gated families. The incremental
session holds the request block and the mapping open over exactly those
windows. FN that remains: `createClient` with Deepgram named only on another
line (an import far above), a nested key between `provider:` and the key,
and a request split by a body. FP cost: a 40-byte `[0-9a-z]` value in one of
those slots that is not a Deepgram key.

Excluded on purpose: a key ending in an identifier or location segment
(`MISTRAL_KEY_ID`, `DEEPGRAM_PROJECT_ID`, `COHERE_ORG_ID`, `AI21_TEAM_ID`), a
non-credential argument (`Mistral(model="...")`), placeholders and
repeated-character filler, a value behind a hash label (`md5:`), a run of any
other length or alphabet (31/33 bytes, `_`/`-` inside, uppercase Deepgram), and
context on another line (a multi-line constructor keeps `api_key=` on a line
that names nothing; that stays a false negative, as does any provider key under
a keyword-free name such as `API_KEY=`). One two-line layout is read since
[#1016](https://github.com/redact-secret/redact-secret/issues/1016): a
Kubernetes-style `env` entry, whose `value:` takes the name of the sibling
`name:` key on the adjacent line (`- name: DEEPGRAM_API_KEY` /
`value: "..."` is a named assignment, `high`). The bare `Bearer` header is
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
| `daytona:api-key` | `daytona-api-key` | `dtn_` + exactly 64 `[0-9a-f]` (68 in total); a `[A-Za-z0-9_-]` byte before the prefix or after the body rejects the match | `daytona_api_key` | T1 as of v0.190.0 (provider generator, R1; dated provider code, R9) |
| `clickhouse-cloud:api-key` | `clickhouse-cloud-api-secret` | `4b1d` + exactly 38 `[A-Za-z0-9]` (42 in total) with at least one uppercase letter in the body; a `[A-Za-z0-9_-]` byte before the prefix or after the body rejects the match | `clickhouse_cloud_api_secret` | T1 as of 2025-04-16 (provider staff statement and regex, R2 and R3); the uppercase guard is policy |
| `nvidia:ngc-api-key` | `nvidia-api-key` | `nvapi-` + 60–128 `[A-Za-z0-9_-]`; a `[A-Za-z0-9_-]` byte before the prefix rejects the match, and a body over 128 is rejected whole | `nvidia_api_key` | T1 (prefix R1 and R6; alphabet and 60-byte floor from the provider's own scanning rule, R2); the 128 cap is policy |
| `browserbase:api-key` | `browserbase-api-key` | `bb_live_` + 20–128 `[A-Za-z0-9]`; a glued `_` or `-` after the run rejects the match, and a body over 128 is rejected whole | `browserbase_api_key` | T1 (prefix from provider docs; alphabet and 20-byte floor from the provider's CI gate, R2); the 128 cap is policy |
| `runpod:api-key` | `runpod-api-key` | `rpa_` + 31–128 `[A-Za-z0-9]`; a glued `_` or `-` after the run rejects the match, and a body over 128 is rejected whole | `runpod_api_key` | prefix and alphabet T1 (provider blog and scrubber, R2); the 31 floor (R10, above Redirect.pizza's 30) and the 128 cap are policy |
| `cerebras:inference-api-key` | `cerebras-api-key` | `csk-` or `csk_` + exactly 48 `[A-Za-z0-9_-]` (52 in total); a `[A-Za-z0-9_-]` byte before the prefix or after the body rejects the match | `cerebras_api_key` | prefixes and width T1 (provider validator, R1; staff statement, R3 as of 2025-10); the alphabet is policy (R10) |

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

Daytona ([#970](https://github.com/redact-secret/redact-secret/issues/970),
[handoff](../audits/evidence/860/daytona.md)). The generator is `dtn_` plus 32
random bytes as hex (`daytonaio/daytona`, public up to v0.190.0, 2026-06-23).
Core development then moved to a private codebase, so under ruling R9 the
contract is T1 as of that date until a newer provider source contradicts it.
The body alphabet is lowercase hex, narrower than the boundary, so an
uppercase byte, a non-hex letter or a 65th byte rejects the match instead of
truncating it. The prefix is load-bearing: without it the body is a SHA-256
digest, which stays unclaimed. `dtn_secret_` placeholders, `dtn_artifact_`
markers, unprefixed runner keys, legacy self-hosted base64 keys and
`DAYTONA_JWT_TOKEN` (a JWT, which `jwt` keeps) stay unclaimed, and `daytona`
is not deferred by `generic-token`. False negatives: any format change after
v0.190.0 (an issuance check would detect it), the legacy and unprefixed
shapes, and caller-chosen provisioning values. False positives: `dtn_` +
exactly 64 lowercase hex that is not a key; none is known. Cost: one prefix on
the shared known-format scan.

ClickHouse Cloud ([#971](https://github.com/redact-secret/redact-secret/issues/971),
[handoff](../audits/evidence/860/clickhouse-cloud.md)). A ClickHouse employee
stated the `4b1d` prefix and wrote the rule `4b1d[A-Za-z0-9]{38}` (gitleaks PR
#1826, merged 2025-04-16), and the provider's Terraform examples carry the same
42-byte mixed-case shape. A 39-byte knowledge-base example from 2023 is older,
so R3's date order sets it aside. `4b1d` is valid hexadecimal, so the leading
`[A-Za-z0-9_-]` boundary is load-bearing: it keeps `4b1d` inside a longer hex or
base64 run and in a UUID (`-4b1d-`) from starting a match, and a 40- or
64-digit digest that begins `4b1d` fails the run length. The policy guard
requires at least one uppercase letter in the body, which removes lowercase
and all-digit identifiers that begin `4b1d` at a cost of (36/62)^38, about
1e-9, of random keys. The provider type wins the secret's span over
`connection_string_password` and `authorization_credential` in Basic-auth
forms; the key ID beside it has no marker and stays unclaimed, and
`clickhouse` is not deferred by `generic-token`. False negatives: a second
live width if one exists, secrets supplied through the pre-hashed `hashData`
route, an all-lowercase body (about 1e-9), and key IDs outside named contexts.
False positives: a mixed-case alphanumeric run of exactly 42 bytes that begins
`4b1d` at a boundary; rare. Cost: one four-byte prefix on the shared
known-format scan plus a 38-byte post check.

NVIDIA ([#972](https://github.com/redact-secret/redact-secret/issues/972),
[handoff](../audits/evidence/860/nvidia.md)). NGC Personal, NGC Service and
build.nvidia.com keys share the `nvapi-` prefix. No provider source states an
exact width, so the contract uses the provider's open-ended rule
(`nvapi-[A-Za-z0-9_\-]{60,}`, R2) and adds a 128-byte cap as project policy,
following the Apify precedent. The body alphabet equals the boundary, so the
scan takes the whole maximal run and rejects it when it is under 60 or over
128; it never truncates. A `.` is outside the alphabet: inside the first 60
body bytes it leaves two runs under the floor, and after the 60th it ends the
run as sentence punctuation does. `nvapi-` + fewer than 60 (NVAPI SDK and crate
names, short fixtures) and `nvapi-...`/`nvapi-xxxx` placeholders stay
unclaimed. `nvidia` and `ngc` are not deferred by `generic-token`, because
deferral would silence the legacy prefixless 84-character NGC key under
`NGC_API_KEY`. False negatives: a key shorter than 60 (none known), a body
with a byte outside `[A-Za-z0-9_-]`, an over-long run, and the legacy key
outside named contexts. False positives: `nvapi-` + 60–128
`[A-Za-z0-9_-]` that is not a key, such as a padded placeholder (the #867
precedent). Cost: one prefix on the shared known-format scan.

Browserbase ([#973](https://github.com/redact-secret/redact-secret/issues/973),
[handoff](../audits/evidence/860/browserbase.md)). The provider's own CI gate
accepts `bb_live_` + at least 20 alphanumerics and no source states an exact
width, so the contract uses that open-ended rule and adds a 128-byte cap as
project policy (the Apify precedent). The body alphabet is narrower than the
boundary, so `bb_live_session_...` identifiers and
`bb_live_your_api_key_here` placeholders stay unclaimed. `bb_test_` keys are
still issuance-gated, and `bb_<timestamp>` cookie names and project-ID UUIDs
are not this shape. `browserbase` is not deferred by `generic-token`, so a
`bb_test_` key keeps its contextual finding under `BROWSERBASE_API_KEY`. False
negatives: a key whose body contains `_` or `-`, a body under 20, an over-long
run, and every `bb_test_` key outside named contexts. False positives:
`bb_live_` + 20–128 alphanumerics that is not a key, such as a padded
placeholder (the #867 precedent). Cost: one prefix on the shared known-format
scan.

RunPod ([#974](https://github.com/redact-secret/redact-secret/issues/974),
[handoff](../audits/evidence/860/runpod.md)). The provider's own scrubber is
`rpa_[A-Za-z0-9]{16,}` (R2), but a floor of 16 would claim Redirect.pizza's
`rpa_` + 30 tokens, so ruling R10 fills the grammar by policy: the alphabet
stays the provider's and the floor rises to 31, the first width above that
other issuer's shape. Every RunPod width seen (46 empirical, a withdrawn 48
character docs example) is above it. The observed 46-byte 40-uppercase plus
6-mixed layout is a tool fact and not part of the contract. The 128-byte cap
bounds the run for streaming (the Apify precedent). The body alphabet is
narrower than the boundary, so `rpa_` word fixtures with `_` stay unclaimed.
`rps_` S3 secrets and unprefixed legacy keys are other shapes, so `runpod` is
not deferred by `generic-token`. False negatives: `rpa_` + 16 to 30 (no RunPod
key of that width is known), a body with `_` or `-`, an over-long run, and
legacy keys and `rps_` secrets outside named contexts. False positives:
`rpa_` + 31–128 alphanumerics that is not a RunPod key, including a longer
Redirect.pizza token (misattributed, still redacted) or a padded placeholder
(the #867 precedent). Cost: one prefix on the shared known-format scan.

Cerebras ([#975](https://github.com/redact-secret/redact-secret/issues/975),
[handoff](../audits/evidence/860/cerebras.md)). The provider's VS Code extension
validator rejects any key that does not start `csk_` or `csk-` or whose length
is not 52 (R1), so the body is exactly 48; a staff statement (2025-10, R3)
confirms both prefixes, `csk-` for new keys and `csk_` for an earlier window.
No provider source states the alphabet, so ruling R10 fills it by policy with
`[A-Za-z0-9_-]`, a superset of every class seen. The alphabet equals the
boundary, so a 49-byte or longer run is rejected whole and never truncated,
and a `.` or `+` ends the run short of 48. The leading boundary is
load-bearing: `csk` ends Pinecone's `pcsk_`, and the byte before it there is
`p`, so a real-shape `pcsk_` key stays `pinecone_api_key` only (pinned by a
full-registry test and a conformance fixture), and `xcsk-` and `_csk-` glue is
rejected the same way. Management API keys (shape unknown) and other widths
stay unclaimed, and `cerebras` is not deferred by `generic-token`. False
negatives: a future length change (the validator has been unchanged for 13
months), a body byte outside `[A-Za-z0-9_-]`, and Management API keys. False
positives: `csk-` or `csk_` + exactly 48 `[A-Za-z0-9_-]` that is not a key,
such as a snake_case identifier of exactly that width or a padded placeholder
(the #867 precedent); rare. Cost: two four-byte prefixes on the shared
known-format scan; `c` is a common lead byte, so the shared prefilter skips
the scan on input where the byte pairs of neither prefix all occur.
## Unsupported-variant contracts (#1012)

Issue [#1012](https://github.com/redact-secret/redact-secret/issues/1012)
froze contract research for the credential variants the pinned support
matrix lists as `unsupported`
([evidence](../audits/evidence/1012/README.md)). This section records the
READY outcomes and product gaps that are implemented. No row is a
support-status claim; promotion stays gated on core conformance and the
benchmarks arrival and profile evidence.

| Family | Detector | Contract | Finding types | Tier |
| --- | --- | --- | --- | --- |
| `gitlab:routable-personal-access-token` | `gitlab-token` | `glpat-` + unpadded base64url `[A-Za-z0-9_-]{27,300}` + `.` + 2 base36 version + `.` + 2 base36 payload length (equal to the payload length) + 7 base36 CRC-32 of every byte from `g` through the length holder; the whole value is the span, and a `[A-Za-z0-9_-]` byte glued after the CRC rejects the routable form | `gitlab_token` (unchanged) | T1 (GitLab generator, decoder, PAT model and design document; provider-authored rules, R2) |
| `aws:sts-temporary-access-key` | `aws-access-key` | `ASIA` + exactly 16 `[A-Z0-9]` (20 in total); a `[A-Za-z0-9]` byte before or after rejects the match; typed, actioned and bounded exactly like `AKIA` | `aws_access_key_id` (unchanged) | prefix T1 (AWS IAM identifiers docs); body T2 (AWS docs example, AWS-owned git-secrets and ferret-scan rules, four peer scanners); T1 if R2 is applied to ferret-scan |
| `aws:iam-user-secret-access-key` | `aws-secret-access-key` | exactly 40 `[A-Za-z0-9/+]` with at least one uppercase and one lowercase letter; no `[A-Za-z0-9/+]` byte before and no `[A-Za-z0-9/+=]` byte after; claimed only under an AWS secret access key name (compact name ending `secretaccesskey`, `awssecretkey` or `awssecret`, or the phrase `secret access key`, optionally followed by `for` and one to four words, then `=` or `:`) or on the line of, or directly below or above, an `AKIA`/`ASIA` access key ID | `aws_secret_access_key` | T2, context-constrained (AWS docs example, AWS-owned git-secrets and ferret-scan rules, peer scanners); T1 if R2 is applied; AWS Macie makes context T1; the name list, adjacency window and mixed-case guard are policy |
| `google:oauth2-credential` (client secret) | `google-oauth-client-secret` | `GOCSPX-` + exactly 28 `[A-Za-z0-9_-]` (35 in total); a `[A-Za-z0-9_-]` byte before or after rejects the match, and any other width is rejected whole | `google_oauth_client_secret` | T2 (Google's osv-scalibr rule, noseyparker, CredSweeper); T1 if R2 is applied to osv-scalibr |

AWS temporary access key IDs
([#1027](https://github.com/redact-secret/redact-secret/issues/1027),
[handoff](../audits/evidence/1012/aws-sts-temporary-access-key.md)).
`aws-access-key` already claimed `ASIA` beside `AKIA`; #1027 records the
contract, conformance and tests without changing the grammar. The ID is an
identifier, usable only with its secret access key and session token;
redacting a bare ID stays the product policy, as for `AKIA`. The body class
is the wider `[A-Z0-9]`, since no AWS source settles Base32. False negatives:
IDs of 17 to 128 characters or with lowercase, which the STS API allows but
no example or rule shows. False positives: a 20-character uppercase
identifier that happens to start `ASIA`. `ABIA` and `ACCA` are identifiers
(#1012) and stay unclaimed.

AWS secret access keys
([#1028](https://github.com/redact-secret/redact-secret/issues/1028),
[handoff](../audits/evidence/1012/aws-iam-user-secret-access-key.md)). The
value has no prefix, so the contract is context-constrained, as AWS's own
detectors (Macie, git-secrets, ferret-scan) are. A new detector,
`aws-secret-access-key`, reports `aws_secret_access_key` at provider
specificity, high and always redacted, so it wins the overlap with the
`contextual_secret` that `generic-token` reports under the same names. The
name is read back over at most 96 bytes of the value's line. The adjacency
rule reads the value's own line and the lines directly above and below it
([#1044](https://github.com/redact-secret/redact-secret/issues/1044) added
the line below the secret, and the phrase form `secret access key for <up to
four words>:` of a chat message). The
incremental session releases a line that carries an access key ID, with its
findings, as soon as the line closes, and scans the next unit below a copy
of it ([#1040](https://github.com/redact-secret/redact-secret/issues/1040)),
so streamed and whole-input scans agree without delaying the ID line. A
line whose 40-character run nothing on it or above it claims is held for
exactly one more line, since an ID there would claim it; when that next line
holds another such run and no ID, the earlier line is released, so a list of
such values never accumulates past two lines. The mixed-case guard
keeps a 40-hex Git SHA out. False negatives: a bare secret with no name or
ID, an ID two lines away, a 41-byte
temporary secret and a padded value (both still redacted by `generic-token`
under a name). False positives: a 40-character mixed-case Base64-alphabet
value under an AWS secret name, or on, below or above an access key ID line, that
is not a secret. The AWS documentation example secret stays exempt by exact
equality (the pipeline's vendor placeholder literals). Cost: a literal check,
one access-key-ID scan and one pass over each line's Base64 runs.

Google OAuth client secrets
([#1029](https://github.com/redact-secret/redact-secret/issues/1029),
[handoff](../audits/evidence/1012/google-oauth2-credential.md)). Google
publishes no grammar; its own osv-scalibr rule was narrowed to exactly 28
body bytes in 2025, and two peer rules agree. The detector reports the
bare value, which gave no finding before, and wins the overlap with the
`client_secret` `contextual_secret` and with `bearer_token`. `google` is not
added to `generic-token`'s dedicated-provider deferral list, so unprefixed
legacy secrets under `GOOGLE_*` names stay redacted by context. The access
token `ya29.` and the refresh token `1//` stay unclaimed (BLOCKED in #1012).
False negatives: unprefixed legacy secrets outside named contexts, a future
width change. False positives: a `GOCSPX-` + 28 value that is not a Google
client secret, none known; a padded placeholder of exactly that width is
claimed (the #867 precedent). Cost: one prefix on the shared known-format
scan.

GitLab routable personal access tokens
([#1022](https://github.com/redact-secret/redact-secret/issues/1022),
[handoff](../audits/evidence/1012/gitlab-routable-personal-access-token.md)).
Every PAT GitLab.com has issued since 2025-07-24 is routable. Before #1022
the legacy `glpat-` + 20 run stopped at the first `.`, so the
`.<version>.<length><crc>` tail stayed in plaintext after redaction. The
routable branch reuses the offline length-holder and CRC-32 check of the
routable `glrt-` form (#730) and reports the whole value. A value whose tail
does not verify (the unversioned 2024-11 to 2025-04 form, an instance or
admin-custom prefix whose CRC covers another prefix, a corrupted CRC, a
glued byte) is not reported whole, and keeps the unchanged legacy match over
the payload run, so no previously redacted byte is released. False
negatives: the tail of those non-verifying forms; a future version whose
layout changes. False positives: none known; a chance CRC match is about one
in 78 billion. Cost: one CRC-32 over at most 319 bytes, only after a
`glpat-` run that ends at `.`.

## Beta.12 broad-discovery provider families (#1014)

The families of issue
[#1014](https://github.com/redact-secret/redact-secret/issues/1014)
([ranked candidates](../audits/evidence/1014/README.md)) are each a new
detector with provider-specific finding types, `Provider` specificity, high
confidence and always redacted, so overlap resolution reports one provider
finding per span over `contextual_secret`, `bearer_token` and
`authorization_credential`. The frozen contract for each family, with its
sources, tier rationale, excluded shapes and issuance checklist, is its step-3
handoff; this section records only the implemented grammar and its
trade-offs.

Shared rules: a value is rejected when the byte before it or after it
continues an identifier (`[A-Za-z0-9_-]`, adjusted per family where noted),
so an embedded, over-long or glued value is an intentional false negative,
never a truncated match. A provider checksum never rejects a shape-valid
match: security comes first, so a failed checksum is not an intentional false
negative, and ruling Q1 of the handoff index stays open for the maintainer.
Documented-public siblings (ruling Q5) stay unclaimed. None of these
providers is added to `generic-token`'s dedicated-provider deferral list: each
has shapes these contracts exclude, and deferral would turn a provider-named
assignment of one into a silent miss. No row is a support-status claim;
promotion stays gated on core conformance and the benchmarks arrival and
profile evidence.

| Family | Detector | Contract | Finding types | Tier |
| --- | --- | --- | --- | --- |
| `bitwarden:secrets-manager-access-token` | `bitwarden-secrets-manager-access-token` | `0.` + UUID (8-4-4-4-12 hex, either case) + `.` + exactly 30 `[A-Za-z0-9]` + `:` + 22 `[A-Za-z0-9+/]` + `==` (94 in total); the byte before `0` must not be `[A-Za-z0-9._-]` and the byte after `==` must not be `[A-Za-z0-9+/=]` | `bitwarden_secrets_manager_access_token` | T1 (provider parser, server generator and docs example, R1) |
| `polar:organization-access-token` | `polar-token` | `polar_oat_` + exactly 43 `[A-Za-z0-9]`; `polar_pat_`, `polar_at_u_`, `polar_at_o_`, `polar_rt_u_`, `polar_rt_o_`, `polar_cs_` or `polar_crt_` + exactly 43 `[A-Za-z0-9_-]` | `polar_organization_access_token` (`polar_oat_`), `polar_api_credential` (the other API roles) | T1 (provider server generator and prefix constants, R1 and R9) |
| `sonarqube:token` | `sonarqube-token` | `squ_`, `sqa_` or `sqp_` + exactly 40 `[0-9a-f]` (44 in total) | `sonarqube_user_token` (`squ_`), `sonarqube_analysis_token` (`sqa_`, `sqp_`) | T1 (provider server generator and token type enum, R1) |
| `rubygems:api-key` | `rubygems-api-key` | `rubygems_` + exactly 48 `[0-9a-f]` (57 in total) | `rubygems_api_key` | T1 (provider server generator, R1) |
| `clojars:deploy-token` | `clojars-deploy-token` | `CLOJARS_` (case-sensitive) + exactly 60 `[0-9a-f]` (68 in total) | `clojars_deploy_token` | T1 (provider generator and server validator, R1) |

Bitwarden ([#1019](https://github.com/redact-secret/redact-secret/issues/1019),
[handoff](../audits/evidence/1014/bitwarden.md)). The token carries the
machine account's client secret and the key that decrypts its secrets. The
`0.` lead is too common to index, so the scan anchors on the closing `==` and
checks the fixed 94-byte layout that ends there, O(1) per `==`. The leading
boundary adds `.` so `10.<uuid>…` and `v0.<uuid>…` are not claimed; the
trailing boundary is the Base64 alphabet plus `=`. The UUID accepts both
cases because the parser does. False negatives: an unpadded key (the parser
accepts it, the generator never emits it), a future version other than `0`,
a token split across lines, and Password Manager `user.`/`organization.` API
keys, which have no token grammar and stay with generic context. False
positives: an unrelated `0.` + UUID + `.` + 30 alphanumerics + `:` + padded
16-byte Base64 value; none is known. Cost: one `==` search plus a fixed
layout check.

Polar ([#1020](https://github.com/redact-secret/redact-secret/issues/1020),
[handoff](../audits/evidence/1014/polar.md)). The generator has emitted 37
alphanumerics plus a 6-character base62 CRC32 since 2025-01-02, and 43
unpadded URL-safe Base64 bytes before that. Organization access tokens
postdate the change, so only `polar_oat_` has the alphanumeric body; the
other API roles take the union of both eras. The `polar_oat_` checksum does
not reject a shape-valid match (ruling Q1 open); it could never apply to the
other roles, whose era-1 bodies carry no checksum. Two finding types separate
the organization token from the user, OAuth and client credentials, following
the one-type-per-role precedent. The public `polar_ci_` client id (Q5),
browser-side `polar_c_`/`polar_cl_` checkout secrets and session or
single-use tokens are not prefixes here. A Polar webhook secret uses
Stripe's `whsec_` prefix and stays reported as
`stripe_webhook_signing_secret`: redacted, attributed to Stripe. False
negatives: session and single-use tokens outside named contexts, a future
generator change, and the misattributed webhook secret. False positives: an
unrelated `polar_<role>_` + exactly 43 URL-safe bytes; none is known. Cost:
eight prefixes on the shared known-format scan.

SonarQube ([#1021](https://github.com/redact-secret/redact-secret/issues/1021),
[handoff](../audits/evidence/1014/sonarqube.md)). The server generator writes
`sq` + the type letter + `_` + 20 random bytes as lowercase hex. A user
token acts as the user, administration included, and gets its own type; the
global and project analysis tokens share one. Without the prefix the body is
SHA-1 shaped, so the prefix is load-bearing and unprefixed legacy tokens
(before SonarQube 9.5) stay with generic context. `sqb_` project badge
tokens are read-only and published in badge URLs by design (Q5), so they are
never claimed. False negatives: legacy tokens outside named contexts, badge
tokens, SonarQube Cloud `sqco_` tokens and an uppercased copy. False
positives: an unrelated `squ_`/`sqa_`/`sqp_` + exactly 40 lowercase hex,
such as an identifier that suffixes a SHA-1; rare. Cost: three prefixes on
the shared known-format scan.

RubyGems ([#1023](https://github.com/redact-secret/redact-secret/issues/1023),
[handoff](../audits/evidence/1014/rubygems.md)). The server generator returns
`rubygems_` + `SecureRandom.hex(24)`; OIDC-exchanged short-lived keys come
from the same generator and are covered. RubyGems sends the key in
`Authorization` without a scheme, and the provider type wins that span.
Metadata keys such as `rubygems_version` fail the body. False negatives:
legacy unprefixed keys outside named contexts and an uppercased copy. False
positives: an unrelated `rubygems_` + exactly 48 lowercase hex; none is
known. Cost: one prefix on the shared known-format scan.

Clojars ([#1025](https://github.com/redact-secret/redact-secret/issues/1025),
[handoff](../audits/evidence/1014/clojars.md)). The generator and the server's
own validator `^CLOJARS_[0-9a-f]{60}$` agree, so the contract is exactly the
validator. Environment names such as `CLOJARS_USERNAME` and
`CLOJARS_PASSWORD` fail the body. False negatives: an uppercased copy and
legacy account passwords. False positives: none known for `CLOJARS_` +
exactly 60 lowercase hex. Cost: one prefix on the shared known-format scan.

## Beta.12 broad-discovery families, ranks 6 to 10 (#1014)

Ranks 6 to 10 of the
[#1014 broad-discovery ranking](../audits/evidence/1014/README.md) are each a
new detector with its own finding types, `Provider` specificity, high
confidence and always redacted, so overlap resolution reports one provider
finding per span over `contextual_secret`, `bearer_token` and
`authorization_credential`. The frozen contract for each family, with its
sources, tier rationale, excluded shapes and issuance checklist, is its
step-3 handoff in that folder; this section records only the implemented
grammar and its trade-offs. Before these detectors, a bare value, a chat
sentence and a JSON `"token"` value of every one of these families were
missed.

Shared rules: a value is rejected when the byte before it or after it
continues an identifier (`[A-Za-z0-9_-]`, adjusted per family where noted),
so an embedded, over-long or glued value is an intentional false negative,
never a truncated match. A provider checksum is never a rejection gate (a
shape-valid value is reported whatever its check character; maintainer
ruling Q1 on #1014 is pending). None of these providers is added to
`generic-token`'s dedicated-provider deferral list. No row is a
support-status claim; promotion stays gated on core conformance and the
benchmarks arrival and profile evidence.

| Family | Detector | Grammar | Finding type | Tier |
| --- | --- | --- | --- | --- |
| `crates-io:api-token` | `crates-io-token` | `cio` + exactly 32 `[A-Za-z0-9]` (35 in total); `cio_tp_` + exactly 32 `[A-Za-z0-9]` (39 in total), tried first | `crates_io_api_token`, `crates_io_trusted_publishing_token` | T1 (crates.io server generators, R1) |
| `dynatrace:api-token` | `dynatrace-token` | `dt0` + `c`\|`s` + 2 digits + `.` + exactly 24 `[A-Z2-7]` + `.` + exactly 64 `[A-Z2-7]` (96 in total), the whole token as the span; the byte before `dt0` must not be `[A-Za-z0-9_.-]` unless it ends a `%20`, and a `.` after the token rejects only when another `[A-Za-z0-9_-]` byte follows it | `dynatrace_token` | T1 (docs structure, lengths and prefix table; base32 alphabet from the provider generator, R1) |
| `paddle:api-key` | `paddle-api-key` | `pdl_live_apikey_`\|`pdl_sdbx_apikey_` + exactly 26 `[a-z0-9]` + `_` + exactly 22 `[A-Za-z0-9]` + `_` + exactly 3 `[A-Za-z0-9]` (69 in total, five `_`) | `paddle_api_key` | T1 (provider docs regex and length) |
| `honeycomb:api-key` (ingest only) | `honeycomb-api-key` | `hc` + one `[a-z]` + `ik_` (environment) or `ic_` (classic) + exactly 58 `[a-z0-9]` (64 in total) | `honeycomb_ingest_key` | T1 (docs prefix; SDK regex, 64-byte gate and fixtures, R1 and R5); management key issuance-gated |
| `axiom:api-token` | `axiom-token` | `xaat-` or `xapt-` + a lowercase-hex UUID (8-4-4-4-12, `-` at body offsets 8, 13, 18 and 23; 41 in total) | `axiom_api_token` (`xaat-`), `axiom_personal_token` (`xapt-`) | prefix T1 (R6); layout and alphabet T1 by example (R5) |

crates.io ([#1031](https://github.com/redact-secret/redact-secret/issues/1031),
[handoff](../audits/evidence/1014/crates-io.md)). `cio` is a 3-letter
trigram, so the exact 32-byte body and both boundaries carry the precision.
The `cio` body alphabet excludes `_`, so a trusted-publishing token is never
read as an API token. The trusted-publishing check character (XOR of the raw
bytes, modulo 62) is not verified. False negatives: a token glued to
identifier bytes, and pre-`cio` legacy tokens, which the server no longer
accepts. False positives: a standalone 35-byte alphanumeric value that starts
with `cio` (about one random run in 238,000). Cost: two prefixes on the
shared known-format scan.

Dynatrace ([#1032](https://github.com/redact-secret/redact-secret/issues/1032),
[handoff](../audits/evidence/1014/dynatrace.md)). Classic `dt0c01` access
tokens and `dt0s01`–`dt0s16` platform tokens share one type. The span is the
whole token, not only the secret portion, so the redacted output keeps no
half-token; the token identifier alone (`<prefix>.<24>`, documented as safe to
log) fails the fixed width and stays unclaimed. `Authorization: Api-Token …`
resolves to the provider type over `authorization_credential`. The leading
boundary also accepts a percent-encoded space, because Dynatrace's
OpenTelemetry exporter setup writes `Authorization=Api-Token%20<token>`; the
trailing boundary lets a sentence-ending period through. Scanners that allow
lowercase or `0`, `1`, `8`, `9` (`[a-z0-9]`, `[A-Z0-9]`) are wider than the
issued grammar and are not followed. False negatives: a lowercased copy, a
glued value, and any future format of another alphabet or width. False
positives: an unrelated `dt0[cs]NN.` + 24 + `.` + 64 base32 value; none is
known. Cost: one literal search for `dt0` and a 96-byte fixed-width check.

Paddle ([#1033](https://github.com/redact-secret/redact-secret/issues/1033),
[handoff](../audits/evidence/1014/paddle.md)). The grammar is Paddle's own
published regex. Live and sandbox keys are one type: a sandbox key still
reads and changes sandbox data and is a policy violation to commit. The
`apikey_` + 26 key id inside a key is part of the one span; on its own it is
a non-secret identifier (API responses, webhooks) and is never claimed.
False negatives: legacy keys from before 2025-05-06 (50 unprefixed
`[a-z0-9]`) outside named contexts, where generic context still covers
`PADDLE_API_KEY=`, and a glued key. False positives: none known for this
69-byte layout. Cost: two prefixes on the shared known-format scan plus a
53-byte post check.

Honeycomb ([#1034](https://github.com/redact-secret/redact-secret/issues/1034),
[handoff](../audits/evidence/1014/honeycomb.md)). Only ingest keys are
claimed. Environment (`ik`) and classic (`ic`) ingest keys are one type: the
docs define the key value as the key id and secret concatenated with no
separator, so the whole 64 bytes are the span. **Management keys
(`hc[a-z]mk_` + 26 + `:` + 32) stay unclaimed**: they are issuance-gated on
the alphabet of both segments (the docs placeholder is digits only and no
fixture exists), and `honeycomb_management_key` is added only after a
maintainer-issued key clears that gate. Key ids alone (`hc?ik_`/`hc?mk_` +
26, `hc?lk_`, `hc?en_`) are non-secret and fail the 58-byte body.
False negatives: management keys, 22-character configuration keys and
32-hex classic keys outside named contexts, and a glued key. False
positives: an unrelated `hc?ik_`/`hc?ic_` + 58 lowercase alphanumerics; none
is known. Cost: one `hc` prefix on the shared known-format scan plus a
62-byte post check.

Axiom ([#1035](https://github.com/redact-secret/redact-secret/issues/1035),
[handoff](../audits/evidence/1014/axiom.md)). API tokens and personal
access tokens are separate types: a personal token carries the user's full
console and API access. The prefix is load-bearing, so a bare UUID stays
unclaimed and the UUID body keeps the value apart from `jwt` and
`bearer_token`. The only real-shaped example is one docs response; the SDK
fixtures fix the layout with placeholder bytes, so the handoff recommends a
structure-only issuance check (basic, advanced and personal tokens) to
confirm the layout and the case. It does not block this row. False
negatives: an uppercased copy, a token outside the UUID layout, and a glued
token. False positives: an unrelated `xaat-`/`xapt-` + lowercase UUID; none is
known. Cost: two prefixes on the shared known-format scan plus a 36-byte post
check.

## Beta.14 broad-discovery families, second wave (#1102 to #1105)

The second wave of the [#1014 broad-discovery handoffs](../audits/evidence/1014/README.md)
(Xata, Sourcegraph, Unkey, Buildkite) is each a new detector with its own
finding types, `Provider` specificity, high confidence and always redacted, so
overlap resolution reports one provider finding per span over
`contextual_secret`, `bearer_token`, `authorization_credential` and `jwt`. The
frozen contract for each family, with its sources, tier rationale, excluded
shapes and issuance checklist, is its step-3 handoff in that folder; this
section records only the implemented grammar and its trade-offs. Before these
detectors, a bare value, a chat sentence and a JSON `"token"` value of every
one of these families were missed.

Shared rules: a value is rejected when the byte before it or after it
continues an identifier (`[A-Za-z0-9_-]`, adjusted per family where noted), so
an embedded, over-long or glued value is an intentional false negative, never
a truncated match (Buildkite's documented 2048-byte cap is the one stated
exception). A provider checksum is never a rejection gate (a shape-valid value
is reported whatever its check value; maintainer ruling Q1 on #1014 is
pending). None of these providers is added to `generic-token`'s
dedicated-provider deferral list. No row is a support-status claim; promotion
stays gated on core conformance and the benchmarks arrival and profile
evidence.

| Family | Detector | Grammar | Finding type | Tier |
| --- | --- | --- | --- | --- |
| `xata:api-key` | `xata-api-key` | `xau_` or `xao_` + `[0-9A-Za-z]{32,36}` (36 to 40 in total) | `xata_user_api_key` (`xau_`), `xata_organization_api_key` (`xao_`) | T1 (provider generator and validator, R1 and R9; width derived from the generator's encoder) |
| `sourcegraph:access-token` | `sourcegraph-token` | `sgp_` + optional `[A-Za-z0-9]{1,32}_` instance identifier + exactly 40 hex (44 to 77 in total) | `sourcegraph_access_token` | T1 as of 2025-11-18 (provider generator and the vendored validator, R1 and R9) |
| `unkey:root-key` | `unkey-root-key` | `unkey_` + 8 base58 + `unkeyv1` + 42 base58 (63 in total); `unkey_3Z` + 22 base58 (30 in total); base58 is `[1-9A-HJ-NP-Za-km-z]` | `unkey_root_key` | T1 (RFC 0017, generator and handler test; dashboard width and `3Z` lead derived, R1 and R9) |
| `buildkite:user-access-token` (and the other Buildkite roles) | `buildkite-token` | one of 15 prefixes (`bkua_`, `bkur_`, `bktx_`, `bkaa_`, `bkar_`, `bkct_`, `bkcqt_`, `bkaj_`, `bkjat_`, `bkpt_`, `bkrt_`, `bktr_`, `bkat_`, `bkpat_`, `bkps_`) + `[A-Za-z0-9_.-]{24,2048}`, one trailing `.` run left outside the span | `buildkite_api_access_token` (`bkua_`), `buildkite_oauth_token` (`bkur_`, `bktx_`), `buildkite_agent_token` (`bkaa_`, `bkar_`, `bkct_`, `bkcqt_`), `buildkite_job_token` (`bkaj_`, `bkjat_`), `buildkite_packages_token` (`bkpt_`, `bkrt_`), `buildkite_pipeline_token` (`bktr_`, `bkat_`), `buildkite_portal_token` (`bkpat_`, `bkps_`) | T1 (provider-authored redaction rule, R2; prefix list also in the provider docs; floor per the Q7 recommendation) |

Xata ([#1102](https://github.com/redact-secret/redact-secret/issues/1102),
[handoff](../audits/evidence/1014/xata.md)). The body is 20 random bytes plus a
little-endian CRC32 in the `jxskiss/base62` bit-packed encoding, which emits
32 to 39 characters; the contract is the 32 to 36 window the provider's own
validator can accept (`MaxLength` 40), and 99.9 percent of keys have 32 to 34.
`xau_` is a 4-byte prefix, so the leading boundary carries the precision:
`xau_` inside `maxau_...` or any longer identifier is not a key, and a run is
rejected whole when it is under 32 or over 36 bytes or when `_` or `-`
follows it. The CRC32 stays lexical (ruling Q1 recommendation); a later
post-check must decode with the non-standard bit-packed base62. False
negatives: classic-platform (pre-2026) keys, which no provider source
describes, a future generator change, and a key glued to identifier bytes.
False positives: an unrelated `xau_`/`xao_` followed by 32 to 36
alphanumerics with no `_` or `-`; none is known, but without the checksum a
random alphanumeric run after the prefix is accepted. Cost: two prefixes on
the shared known-format scan plus a 4-byte-offset width check.

Sourcegraph ([#1103](https://github.com/redact-secret/redact-secret/issues/1103),
[handoff](../audits/evidence/1014/sourcegraph.md)). The instance identifier the
generator issues is `local` or 16 hex; the detector claims the wider
alphanumeric identifier the 2025 validator accepts, capped at 32 bytes so a
long `sgp_<word>_` cannot consume a line, and takes the body in either hex case
as the validator does. A **bare 40-hex token is never claimed**: it has no
distinctive shape and collides with git SHAs (the scanners' fallback
alternative is deliberately not copied). `sgph_` (accepted by the validator,
issuer unknown) and `sgd_` + 64 hex (the Cody Gateway user key, one provider
source) are a later extension and stay unclaimed, as do `slk_` tokens. The run
after `sgp_` is rejected whole unless it has exactly the grammar: a 39- or
41-hex body, an identifier with no closing `_`, an identifier over 32 bytes, a
byte of `[A-Za-z0-9_-]` before `sgp_` and a `-` after the token are intentional
false negatives. The server repository is private, so a post-2025 generator
change cannot be ruled out; the maintained validators would have followed it.
False positives: an unrelated `sgp_<word>_` + exactly 40 hex; none is known.
Cost: one prefix on the shared known-format scan plus a linear post check over
the run.

Unkey ([#1104](https://github.com/redact-secret/redact-secret/issues/1104),
[handoff](../audits/evidence/1014/unkey.md)). Both current root-key forms are
one type: the version 1 key the RFC 0017 generator and the root-key handler
mint (the last 6 characters are a CRC-32C, which stays lexical under the Q1
recommendation) and the dashboard key the `KeyV1` encoder mints (18 bytes
whose first two are fixed, so always 24 characters beginning `3Z`). They are
constructed as one `unkey_` shape with two accepted body widths, 57 and 24,
and the longer one is tried first, so a version 1 key whose random head begins
`3Z` (about 1 in 3,400) is still one 63-byte key and never a truncated
dashboard key. The base58 alphabet has no `0`, `O`, `I`, `l` or `_`, which
keeps `unkey_`-prefixed identifiers (`unkey_root_key`, `unkey_mutations`)
unclaimed. The step-1 single `unkey_[Base58]{21,24}` window and the third-party
`unkey_[A-Za-z0-9]{20,32}` rule are not followed: the first is superseded by
the derivation, and the second misses version 1 and accepts non-base58 bytes.
**Customer-prefixed version 1 keys** (`<1 to 16 byte prefix>_` + 8 +
`unkeyv1` + 42) are credentials for the customer's own product, anchored on
the `unkeyv1` marker; claiming them as a separate type needs ruling Q10 on
#1014, which is open, so they are an explicit, bounded false negative that
stays with generic context until Q10 is ruled. Other false negatives: the
deprecated Go 21 to 22 form, root keys older than the current generators,
imported keys, and a key glued to identifier bytes. False positives: an
unrelated `unkey_3Z` + 22 base58 run; none is known (the lead is a 1 in 3,400
coincidence for a random base58 run). Cost: one prefix on the shared
known-format scan with a 7-byte marker check.

Buildkite ([#1105](https://github.com/redact-secret/redact-secret/issues/1105),
[handoff](../audits/evidence/1014/buildkite.md)). The grammar is exactly the
provider redactor's own: the 15 documented prefixes, the body alphabet
`[A-Za-z0-9_.-]` (base64url plus `.`, the separator inside organization-id and
JWT tokens), a floor of 24 and a cap of 2048. No per-type exact length is
claimed because none is stated anywhere and the open-ended body is the only
grammar that stays correct across the organization-id, base58, hex and JWT
layouts. The seven finding types are the handoff's role split; the grammar is
the same for all. The floor of 24 is the provider's `TokenBodyLengthMin`,
chosen below the real-token minimum of 38 so truncated `ps` fragments are
caught while short placeholders (`bkjat_encoded-token`, `bkua_xxx`) stay out;
using it as the T1 floor when no alphabet is narrowed is the pending Q7
recommendation, and a floor of 38 is a one-constant change. The span is the
maximal body run capped at 2048 bytes, as the provider's `{24,2048}` rule
reads it: a longer or glued run is reported up to the cap and the tail is not
part of the finding (the one exception to the shared never-truncate rule), and
one trailing run of `.` stays outside the span so sentence punctuation is not
swallowed unless that would leave the body under 24 (a period after a 23-byte
body is its 24th byte, as in the provider's rule). A `bkjat_` or `bkaj_` JWT
is one span from the prefix to the last JWT byte; the `jwt` detector cannot
start a match inside it because the `_` before `eyJ` is a token byte, and the
Bearer-header candidate over the same bytes loses to the provider type, so the
prefix always wins. Reconciling with the one peer rule that exists (third-party
`bkua_` + 40 lowercase hex): the shipped grammar is a strict superset of it, so
every value that rule reports is also reported here with the same start, and
the benchmarks co-detection scoring is a benchmarks-side follow-up. False
negatives: the unprefixed legacy agent and API tokens outside named contexts,
a prefix Buildkite adds after 2026-09-29, `bka_` + 40 alphanumerics (one
third-party rule), values under 24 body bytes, and a prefix glued to an
identifier. False positives (the main trade-off of adopting the provider's
floor): an unrelated `bkct_`-, `bkat_`- or other listed-prefix identifier whose
body is 24 or more bytes of the body alphabet, for example a snake_case
variable name; no real-world collision is known. Cost: 15 prefixes on the
shared known-format scan.

## Beta.14 broad-discovery families, third wave (#1106 to #1109)

The third wave of the [#1014 broad-discovery handoffs](../audits/evidence/1014/README.md)
(Pydantic Logfire, Square, Mapbox, Fly) follows the same route as the
[second wave](#beta14-broad-discovery-families-second-wave-1102-to-1105): each
is a new detector with its own finding types, `Provider` specificity, high
confidence and always redacted, so overlap resolution reports one provider
finding per span over `contextual_secret`, `bearer_token`,
`authorization_credential` and `jwt`. The frozen contract for each family is
its step-3 handoff in that folder; this section records only the implemented
grammar, the ruling it rests on and its trade-offs. The shared rules of the
second wave apply (identifier boundary on both sides unless a row says
otherwise, no checksum, no addition to `generic-token`'s dedicated-provider
deferral list, no support-status claim until the benchmarks arrival and profile
evidence lands). Rulings Q7 to Q10 on #1014 are all open: each row follows the
handoff's stated recommendation and records the open ruling as a bounded limit.

| Family | Detector | Grammar | Finding type | Tier |
| --- | --- | --- | --- | --- |
| `pydantic:logfire-token` (write and read tokens, API keys, AI Gateway key) | `pydantic-logfire-token` | `pylf_v` + 1 to 3 digits + `_` + `[a-z]{2,16}` region + `_` + optional 8-4-4-4-12 hex organization id (either case) + `_` + `[A-Za-z0-9]{20,}` | `pydantic_logfire_token` | T1 (SDK parsers, R1; provider scrubber, R2); the body floor and region cap are narrowing policy (pending ruling Q7, recommendation: allowed) |
| `square:access-token` (and the OAuth application secret) | `square-token` | `EAAA` + exactly 60, `sq0csp-` + 43 or 44, or `sandbox-sq0csb-` + exactly 43, all `[A-Za-z0-9_-]` | `square_access_token` (`EAAA`), `square_oauth_application_secret` (`sq0csp-`, `sandbox-sq0csb-`) | T1 (provider docs examples, R4 and R5, corroborated by scanner rules); exact widths under the Q8 recommendation (pending ruling) |
| `mapbox:secret-access-token` | `mapbox-token` | `sk.` + `eyJ` + `[A-Za-z0-9_-]{20,}` payload + `.` + exactly 22 `[A-Za-z0-9_-]` signature | `mapbox_secret_access_token` | T1 (provider docs and parser, R1; signature width by R5); the payload floor is derived (pending ruling Q7, recommendation: allowed); `tk.` unclaimed (pending ruling Q9, recommendation: unclaimed) |
| `fly:access-token` | `fly-token` | first member `fm1r_`, `fm1a_` or `fm2_` + `[A-Za-z0-9+/_-]{64,}` + `={0,2}`, then any number of `,` + `fm1r_`, `fm1a_`, `fm2_` or `fo1_` + `[A-Za-z0-9+/_-]+` + `={0,2}` members; the `FlyV1 ` scheme is outside the span | `fly_access_token` | T1 (wire-format code, R1; flyctl's own redaction rule, R2); the 64-byte floor is derived (pending ruling Q7, recommendation: allowed); a standalone `fo1_` unclaimed (pending ruling Q9, recommendation: unclaimed) |

Pydantic Logfire ([#1106](https://github.com/redact-secret/redact-secret/issues/1106),
[handoff](../audits/evidence/1014/pydantic-logfire.md)). The write token, read
token, organization or project API key and AI Gateway key share one namespace
that no text feature splits, so they are one detector and one finding type; a
v1 body is observed at exactly 44 bytes (provider fixtures and a scanner rule)
but the provider regexes have no bound, so no exact width is claimed. The floor
of 20 is below every observed token and removes the placeholders in provider
tests and docs (`..._xxx`, `..._token1`); the region cap of 16 is a policy cap
on a class the provider leaves open. Neither widens the provider grammar.
Ruling Q7 (may a narrowing policy floor serve as the T1 floor) is open; the row
follows its recommendation, and if it is refused the floor becomes `{1,}`, a
one-constant change. The whole `[A-Za-z0-9_-]` run after `pylf_v` is read and
rejected, never truncated, unless it has exactly the grammar. False negatives:
a body under 20 (the provider scrubber still redacts the bare prefix, a
stronger posture than this detector takes), legacy tokens with no `pylf_`
prefix, a non-UUID `-` or `_` in the body, `pylf_v3`/`pylf_v4` 80-byte shapes
that only a scanner fixture shows, an uppercase region and a glued value. False
positives: a hand-written placeholder with more than 19 alphanumerics after the
prefix; none is known. Cost: one prefix on the shared known-format scan plus a
linear grammar check over the run.

Square ([#1107](https://github.com/redact-secret/redact-secret/issues/1107),
[handoff](../audits/evidence/1014/square.md)). Square tells integrators not to
validate token length and its own examples disagree (an access token of 64
characters in one place and a 63-character `EAAl` form in the `ObtainToken`
reference; an application secret of 43 characters in the walkthrough and 44 in
the reference and its generated SDK fixture). Ruling Q8 (may R5 still support
an exact-width grammar when the provider disclaims length) is open; the row
follows its recommendation: the stable widths are claimed, `EAAA` + exactly 60
(four independent scanner and request sources also use 60) and the 43 or 44
union for `sq0csp-` (the era-union precedent of Polar), and every conflicting
shape is unclaimed and recorded as a bounded false negative: the `EAAl` + 59
access token and the `EQAA` + 60 refresh token (one provider example each, not
independent of the generated SDK fixture), `EAAA` and `sq0csp-` of any other
width, and `sandbox-sq0csb-` of any width but 43 (one docs example). The
structure-only issuance check that would settle the widths is a benchmarks-side
item and is pending. Both secrets and the access token share the boundary
`[A-Za-z0-9_-]` on both sides and are case-sensitive, so a longer run (a Meta
`EAAA` Graph token, a Base64 blob) or a lowercase image digest cannot match;
a `+`, `=` or `/` inside the body ends the run under the width (trufflehog's
class would accept them, Square's own example has none). JWT-format access
tokens stay with `jwt`; `sq0atp-` (scanner rules only), the `sq0cgb-`
authorization code and the public application ids (`sq0idp-`, `sq0ids-`,
`sq0idb-`, `sandbox-sq0idb-`) are unclaimed. False negatives: the above, any
future traditional-token width change, and a glued value. False positives: an
unrelated run of `EAAA` + 60 URL-safe bytes at identifier boundaries, which
includes a Base64 line made almost entirely of `A` bytes after a lone `E`; the
boundary makes this very rare, and an almost-constant-body post-check is an
option for a later issue, not part of this contract. Cost: three prefixes on
the shared known-format scan.

Mapbox ([#1108](https://github.com/redact-secret/redact-secret/issues/1108),
[handoff](../audits/evidence/1014/mapbox.md)). A Mapbox access token is
`<usage>.<payload>.<signature>` with the usage header `pk`, `sk` or `tk`; only
`sk.` is claimed, whole, as one span. The payload is the base64url of a JSON
object that begins `{"`, so it begins `eyJ`; it has no provider-stated length
(it grows with the account and token contents, a Drupal tracker records 98
characters in 2022 and later growth), so the floor of 20 characters after `eyJ`
is derived from the documented two-claim object, not stated by Mapbox, and the
22-byte signature tail (docs example plus provider fixtures, R5) is the real
anchor. Ruling Q7 (may a derived floor serve as the T1 floor) is open; the row
follows its recommendation (yes) and, if it is refused, falls back to a payload
pinned to the documented `u` claim lead, which is narrower. Ruling Q9 is also
open: `pk.` tokens are public by design and are never claimed, and `tk.`
temporary tokens (expire within an hour, richer payload) stay unclaimed until a
provider source states their length, a bounded false negative. The `jwt`
detector cannot start inside the token: it needs a three-segment `eyJ.eyJ.sig`
shape and rejects a match whose preceding byte is a token byte, `.` included,
and the byte before the payload's `eyJ` is the header's `.`. The provider type
is therefore the only finding for the span, whole-input and incremental, and
the same JWT without the `sk.` header stays a plain `jwt` finding. A signature
that itself begins `eyJ` is claimed to its 22 bytes and any further segment is
outside the span. False negatives: `tk.` tokens, a signature of any width
other than 22 (a 23rd byte rejects the whole token, never truncating it), a
payload that does not begin `eyJ`, a future signature length, `SK.`, `sk_` and
`sk-` forms and a glued value. False positives: a non-Mapbox `sk.eyJ...`
followed by exactly 22 base64url bytes; none is known. Cost: one prefix on the
shared known-format scan plus a 23-byte tail check.

Fly ([#1109](https://github.com/redact-secret/redact-secret/issues/1109),
[handoff](../audits/evidence/1014/fly.md)). The grammar is flyctl's own log
redaction rule, `(fo1_|fm1[ar]_|fm2_)[a-zA-Z0-9/+_-]+=*` (R2), read with the
`superfly/macaroon` wire format (R1): the member prefixes, an alphabet that
covers standard and URL-safe Base64, optional `=` padding (up to two bytes
here), no upper length bound, and `,` between the members of a bundle. The span
starts at the first `fm1r_`, `fm1a_` or `fm2_` member and ends at the last body
or `=` byte of the last member, so a session bundle (`fm2_...,fo1_...`) is one
finding, and the documented `FlyV1 ` scheme and its space stay in place; that
also closes the unquoted `FLY_API_TOKEN=FlyV1 fm2_...` form, which generic
context misses because the space ends the contextual value. A comma followed by
anything but a member prefix with at least one body byte ends the bundle. The
64-byte floor on the first member is derived from the wire format (a decoded
macaroon holds a 16-byte nonce and a 32-byte HMAC-SHA256 tail, 48 bytes, which
is at least 64 standard-Base64 characters), not stated by Fly. Ruling Q7 (may a
derived floor serve as the T1 floor) is open; the row follows its recommendation
(yes), and a floor of 100 is a one-constant change if it is refused. Ruling Q9 is
also open: a `fo1_` token with no `fm` member before it has no provider-stated
length (43 URL-safe bytes rests on one scanner) and stays unclaimed, as does a
`fo1_` member that precedes the first `fm` member, a bounded false negative that
stays with generic coverage. The boundary before the first prefix is
`[A-Za-z0-9_-]`; the first member's run is the maximal body-alphabet run, so a
longer run is claimed in full and never truncated, and a padded member that an
identifier continues is rejected whole. The body alphabet includes `-` and `_`,
so a delimiter glued after a token is more body, not a boundary (the provider
rule reads it the same way). False negatives: a standalone `fo1_`, a body under
64 (including the `fm2_hi` test fixtures), a future prefix (`fm3`), a separator
other than `,` between members and `FM2_`. False positives: an unrelated `fm2_`
followed by 64 or more body-alphabet bytes (a Base64 blob after a delimiter);
none is known. Cost: three prefixes on the shared known-format scan plus a
linear bundle extension.

## Batch 1 credential slots (#1209 to #1213)

Five bounded credential carriers from the credential-evidence adoption
inventory ([#232](https://github.com/redact-secret/credential-evidence/issues/232)),
measured against the independent
[benchmarks#717 corpus](https://github.com/redact-secret/redact-secret-benchmarks/blob/14271c7e85ad9300e100c6a4b5e33105e7429166/evidence/717/report.md).
Each row applies the existing contextual and authorization policy to one
documented slot. None adds a provider detector, a registry entry, a bare-prefix
grammar, decoding, a width or alphabet claim, or a provider subtype from a
shared carrier; the finding is the generic `contextual_secret` or
`authorization_credential`, redacted by default. Provider documentation
establishes the slot and role, never a universal byte shape. The accepted
false-positive tradeoff is the contextual-policy one: a non-secret literal put
into the exact credential slot is redacted by default; unsupported layouts,
excluded values and values under the 8-byte contextual floor are documented
false negatives.

| Family | Applied rule | Evidence |
| --- | --- | --- |
| `figma:personal-access-token` | The explicit `X-Figma-Token` header value (raw HTTP, quoted curl `-H`, JSON header map) is `contextual_secret`, redacted, spanning the value only, with no PAT subtype, no `figd_`/`figp_` grammar and no width claim; it was already covered through the prefixed `_token` name rule. Since #1209 `figma` is a placeholder provider word, so `YOUR_FIGMA_TOKEN` is silent. `X-Figma-Token-Id`, suffixed names, references, masks, public ids and a newline-separated value stay silent. | [#1209](../audits/evidence/1209/README.md) |
| `asana:webhook-secret` | The exact `X-Hook-Secret` header value (raw request or response header, quoted curl `-H`, JSON header map) is `contextual_secret`, redacted, spanning the value only, with no Asana attribution and no alphabet or width claim; no-code, covered through the prefixed `secret` name rule. `X-Hook-Signature` (an HMAC), `X-Hook-Secret-Id`, `X-Hook-Secrets`, placeholders, references, masks and bare strings stay silent. | [#1210](../audits/evidence/1210/README.md) |
| `airtable:webhook-mac-secret` | The whole normalized field name `macSecretBase64` (JSON, YAML and direct assignment) is a high-signal contextual name, so its complete encoded value, padding included, is `contextual_secret`, redacted, never decoded, with no width claim. Only that one name: `thumbnailBase64`, `macSecretBase64Length`, `macSecretBase64Id`, a prefixed name, the `X-Airtable-Content-MAC` HMAC header, hook and base ids, placeholders, references and masks stay silent. | [#1211](../audits/evidence/1211/README.md) |
| `elastic:elasticsearch-api-key` | `generic-token` recognizes the `ApiKey` scheme of `Authorization` and `Proxy-Authorization` (raw HTTP, quoted curl `-H`, JSON header map) as an `authorization_credential`, beside `Basic`, `Token` and `Key`: the undecoded encoded value is the span, redacted, with the 12-byte floor and entropy-based confidence of the other schemes, no id/api_key split, no alphabet or width inference and no Elastic attribution (`ApiKey` is not unique to Elastic). Taken mid-line like `Basic` and `Key`. Bare `ApiKey` prose, `X-Authorization` and `Authorization-Info`, a newline between scheme and value, placeholders, references, masks and a key id alone stay silent. | [#1212](../audits/evidence/1212/README.md) |
| `canva:client-secret` | The existing `client_secret` assignment, form-body (the span stops at the delimiter) and JSON reading is `contextual_secret`, and the `Authorization: Basic` envelope is `authorization_credential` over the encoded credential, not a decoded secret-only span; both redacted, generic, with no Canva attribution. No-code. The documented `cnvca` prefix gets no bare-prefix detector (separator, width and alphabet are undocumented): a bare `cnvca` value, `client_id`, placeholders, references, masks and prefix prose stay silent. | [#1213](../audits/evidence/1213/README.md) |

## Batch 2 credential contracts (#1223 to #1226)

Four conditional product contracts for the 58 Batch 2 families of the
credential-evidence adoption inventory
([#231](https://github.com/redact-secret/credential-evidence/issues/231), handoff
[#235](https://github.com/redact-secret/credential-evidence/issues/235)), measured
by the independent
[benchmarks#739](https://github.com/redact-secret/redact-secret-benchmarks/issues/739)
epic. Each row states, per class of rows, the output the product produces once a
row's reviewed carrier layout and an independent baseline exist, and what is out
of contract. Every row applies existing policy; none adds a provider detector, a
registry entry, a bare-prefix grammar, decoding, a width or alphabet claim, or a
provider subtype from a shared carrier. The findings are the generic
`contextual_secret`, `bearer_token`, `authorization_credential` (and the existing
`jwt` and `connection_string_password` readings), with the default action of the
accepted policy; a user action policy replaces that default exactly as before.
Provider carrier facts are owned by credential-evidence. The independent
[benchmarks#739](https://github.com/redact-secret/redact-secret-benchmarks/issues/739)
round 2 (frozen corpus sha256 `a312308a141e3157c859f62e53c5e0762ca91c2e0083d0e02497848ebee8b921`,
[report](https://github.com/redact-secret/redact-secret-benchmarks/blob/fe7a5d1acd8ba56e4f1c537117f78a944369a9c6/evidence/739/round2/report.md))
measured all 58 rows against the published `0.1.0-beta.13` and the candidate
`a148dadf`: 38 are existing coverage validated with no code, 2 are the Batch 1
`ApiKey` fix reused, 17 reproduced a gap (15 the empty form value of
[#1232](../audits/evidence/1232/README.md), 1 the HubSpot field of
[#1233](../audits/evidence/1233/README.md), 1 the `YOUR_PASSWORD` placeholder of
[#1234](../audits/evidence/1234/README.md)) fixed in this repository, and 1 has no
wire carrier and is source-unresolved. The independent replay of the fixed
candidate `4e0041081aad22d0101bd52db52017b67b5bd3db` is accepted
([benchmarks#771](https://github.com/redact-secret/redact-secret-benchmarks/pull/771),
merge `74c88531f7f185e687eabe6477fff5b06f54e2e9`,
[round-3 report](https://github.com/redact-secret/redact-secret-benchmarks/blob/74c88531f7f185e687eabe6477fff5b06f54e2e9/evidence/739/round3/report.md)):
the same 1935-case corpus gives 1010 of 1010 positives and 555 of 555 controls
on Node, WASM, Python and the CLI, whole and streamed, and the 17 reproduced-gap
rows are fixed with no regression; the ledger records 38 covered, 17 fixed, 2
fixed by an existing core fix and 1 contract-evidence conflict (the Atlas API
private key). No row is claimed covered beyond what that ledger measured. The
per-row dispositions are in each evidence record.

| Class | Applied rule | Evidence |
| --- | --- | --- |
| OAuth access-token rows (G1, 23 families) | Two layouts, each only for a row whose reviewed contract names it. A credential-named field (assignment, quoted assignment, form-body or query parameter, JSON or YAML member) is `contextual_secret` spanning the value only, ending at the form delimiter, redacted at high confidence and warned at medium (a short or low-entropy literal); neighbouring `client_id`, `scope`, `token_type` and `*_expires_in` stay outside. An explicit `Authorization:` or `Proxy-Authorization:` Bearer value is `bearer_token` spanning the value only, redacted, under the RFC 6750 alphabet with the 12-byte explicit-header floor. The carrier proves no provider or subtype (Meta roles, Contentful, Salesforce and Elastic tokens included). A layout the evidence does not name stays carrier-unresolved, and a bare `token` or `*key` name stays unmatched. | [#1223](../audits/evidence/1223/README.md) |
| OAuth refresh-token rows (G2, 13 families) | Token-endpoint fields, never resource Bearer credentials: only the field layouts above, with `refresh_token` a high-signal name, the span ending at `&` so `client_id` and `scope` stay outside, `contextual_secret`, redacted at high confidence and warned at medium. A refresh token behind a Bearer header is read by its carrier when it occurs, and is not a layout of this contract unless the evidence names it. | [#1223](../audits/evidence/1223/README.md) |
| OAuth client and application secret rows (G3, 12 families) | A `client_secret` or other credential-named field is `contextual_secret` over the value only (assignment, form body to the delimiter, JSON). An `Authorization: Basic` envelope is `authorization_credential` over the whole encoded envelope, never decoded and never a secret-only span, always redacted; it also covers the public client id half because the encoded value is one credential. Excluded: client, app, account and object ids, HMAC and signature outputs, and the other shared exclusions. | [#1223](../audits/evidence/1223/README.md) |
| `elastic:cloud-api-key` and `elastic:ece-api-key` (G4) | Cloud reuses the Batch 1 `Authorization: ApiKey` reading ([#1212](../audits/evidence/1212/README.md)) for a reviewed layout of that scheme: `authorization_credential` over the undecoded authorization-alphabet run (12 bytes or more, `=` padding included), always redacted, with no id and key split, no decoding, no width or alphabet claim and no Elastic attribution. ECE's carrier is unconfirmed, so nothing is asserted and it is not read as Cloud because of its name; if its reviewed carrier is the same scheme the same path applies without ECE attribution, and any other carrier needs its own evidence first. | [#1224](../audits/evidence/1224/README.md) |
| `jfrog:access-token` (G4) | A value that is a JWT is one final `jwt` finding, exactly the JWT bytes, redacted, whether or not a Bearer header carries it; the Bearer and JWT readings of the same bytes do not both report. A JWT is not an exclusive JFrog grammar: no JFrog type, no decoding, no validation. The JFrog carrier is unresolved and a non-JWT reference token has no source-established representation, so both are unassertable. | [#1224](../audits/evidence/1224/README.md) |
| `x:app-only-bearer-token` (G4) | Where a reviewed layout names an explicit `Authorization: Bearer` carrier, the raw value is `bearer_token` under the RFC 6750 alphabet, redacted, with no format claim (the provider states none). A percent-containing or escaped representation is unsupported and unassertable: the Bearer alphabet is not broadened, nothing is decoded, a value that the grammar ends at `%` is redacted as the prefix it read with the residual bytes left in the output, and that prefix is never full coverage (`decision-keep-percent-containing-and-escaped-credential-representations-outside-the-raw-input-contract`). | [#1224](../audits/evidence/1224/README.md) |
| `x:oauth1-access-token-secret`, `hubspot:personal-access-key` and `jfrog:myjfrog-api-token` (G5) | `oauth_token_secret`, the secret half issued with `oauth_token`, is read by the existing field grammar once a reviewed layout names it: `contextual_secret` over exactly the value (assignment, form body or response, JSON or YAML member), redacted at high confidence and warned at medium, with no X attribution; `oauth_signature`, `oauth_consumer_key`, the nonce, timestamp, method and version stay silent, and the secret never appears in an `Authorization: OAuth` header. `oauth_token` is not an exclusion: the prefixed `_token` rule keeps reporting it. The HubSpot CLI field `personalAccessKey` and variable `HUBSPOT_PERSONAL_ACCESS_KEY` are two whole-name vocabulary entries ([#1233](../audits/evidence/1233/README.md), once the evidence named the field; its basis is SDK source and the legacy `portals` layout is unresolved), reported as `contextual_secret` with no HubSpot attribution; MyJFrog is an explicit Bearer carrier read by the existing grammar. SDK positional arguments and unnamed configuration nesting are explicit limits. | [#1225](../audits/evidence/1225/README.md) |
| `mongodb-atlas:database-user-password` (G6) | The current policy is preserved where in contract: the password in `mongodb://` and `mongodb+srv://` URI userinfo is `connection_string_password` over the exact undecoded substring, redacted at any confidence, and a documented password field is `contextual_secret` over the value, redacted at high confidence and warned below 16 bytes or at low entropy. The password is user-chosen with no provider grammar: a password under the 8-byte floor, a low-entropy or short one that lands at `warn`, one in a carrier the core does not read, and one whose raw punctuation ends the carrier's value are stated blind spots, and the product does not claim every password is protected. Percent escapes inside the span are kept as written, never decoded (`decision-keep-percent-containing-and-escaped-credential-representations-outside-the-raw-input-contract`). | [#1226](../audits/evidence/1226/README.md) |
| `mongodb-atlas:programmatic-api-private-key` (G6) | The private key is the client's Digest input, not a PEM and not in the Digest `Authorization` header, which carries a hash that stays silent with `username`, `realm`, `nonce` and `cnonce`. Two plaintext slots are named by the evidence (credential-evidence#256, PR #258) and are in contract: the creation-response member `privateKey` and the Atlas CLI profile property `private_api_key`. Each falls under the existing field grammar: `contextual_secret`, exactly the value, redact at high confidence and warn at medium, with no width, alphabet, prefix or Atlas claim and no new vocabulary entry. The masked form, the 8-character public key, the credential object id and a masked later response are silent controls. An environment variable, a command-line flag, a Terraform argument and the curl `--user <public>:<private> --digest` layout are not named by the evidence, so they are not in contract and are disclosed blind spots. The benchmark has no positive for the row yet, so it is not claimed covered. | [#1226](../audits/evidence/1226/README.md) |
| `mongodb-atlas:service-account-secret` (G6) | The secret is opaque. In its reviewed `Authorization: Basic` layout it is `authorization_credential` over the whole encoded envelope, never decoded and covering the public client id half, always redacted; a `client_secret`-style field, where a reviewed layout names one, is `contextual_secret` over the value. `mdb_sa_sk_` is only a truncated example, so no prefix detector is added and a bare value outside a slot is not read; the public `mdb_sa_id_` client id, a masked or truncated display and the secret's object id are controls. | [#1226](../audits/evidence/1226/README.md) |

## Groups C, D and E conditional contracts (#1228 to #1230)

Three conditional product contracts for the 43 rows that remained after Batch 1
and Batch 2 in the credential-evidence adoption inventory
([#231](https://github.com/redact-secret/credential-evidence/issues/231); Group
C 11 rows, Group D 23, Group E 9). Each row states, per class of rows, what the
product does once a row's reviewed carrier layout and an independent baseline
exist, and what stays outside the contract. The evidence side is done (epics
[#236](https://github.com/redact-secret/credential-evidence/issues/236),
[#237](https://github.com/redact-secret/credential-evidence/issues/237) and
[#238](https://github.com/redact-secret/credential-evidence/issues/238), handoffs
read at `522e0795`), but every contract it describes is a draft and the independent
baselines (benchmarks
[#752](https://github.com/redact-secret/redact-secret-benchmarks/issues/752),
[#753](https://github.com/redact-secret/redact-secret-benchmarks/issues/753) and
[#754](https://github.com/redact-secret/redact-secret-benchmarks/issues/754)) do
not exist, so no row is claimed covered, passing or ready, and no expectation is
taken from current output or scanner majority. Every row applies existing
policy: none adds a provider detector, a registry entry, a bare-prefix grammar,
decoding, a width or alphabet claim, a vocabulary name or a provider subtype
from a shared carrier. Unresolved properties stay unresolved and an unresolved
row is not support.

| Class | Applied rule | Evidence |
| --- | --- | --- |
| Group C evidence classes (11 rows) | A fact is frozen under the class the handoff gave it: provider-documented, SDK source, scanner-derived (consistency only) or project policy. A distinctive prefix alone does not prove every following body; tools that copied one rule are one origin; provider statements of opacity and variable length (Airtable, Dropbox) constrain and are never overridden by a scanner width. No new bare detector is adopted, so a bare provider-shaped value of an unproven grammar is silent, a stated and unassertable limit and not a miss. A row's carrier and its bare value carry separate dispositions. | [#1228](../audits/evidence/1228/README.md) |
| Adobe client secrets (3 rows) | The S2S and Enterprise `client_secret` form or query parameter is `contextual_secret` over exactly the value, ending at its delimiter, with the client id, scope and `org_id` outside; the Web App `Authorization: Basic` envelope is `authorization_credential` over the whole undecoded value, public client id included. All three redact by default (`warn` at medium for the field), with no Adobe type: `p8e-` rests on two rule artifacts of unstated basis that name no credential type, and subtype attribution is a Group D question. | [#1228](../audits/evidence/1228/README.md) |
| Airtable PAT, Dropbox access token, HubSpot private-app token (3 rows) | The documented slots (Bearer header; `access_token` response member) are read generically at any length, so the provider's opaque and variable-length statements are never narrowed by a tool width. The `pat` ID and 64-hex layout, the `sl.` ranges and `pat-na1-` are context hints only; a bare value is silent. HubSpot private-app and static-auth are not merged and carry no HubSpot attribution (the Group D mapping); the `tokenKey` field is a scoped read since the round-1 baseline reproduced the gap (#1228 addendum `addendum-token-key-member.md`): a quoted JSON member only, judged as `access_token`, never a vocabulary name, with storage-key names (`accessToken`) read as references. | [#1228](../audits/evidence/1228/README.md) |
| Contentful CMA token, JFrog reference token, Meta app secret, Salesforce refresh token, X consumer secret (5 rows) | Lexical conflicts are recorded per page or artifact, never as a compromise union: JFrog 64 versus 128, Salesforce 80 versus 40, X 50 versus 35 to 44, Contentful 43 versus at least 40 versus 64 hex, Meta a 32-character value that collides with digests. Only documented slots are read generically (Contentful Bearer, and the create-token response `token` member only beside its documented `sys` or `scopes` sibling, a lone or `name`-only `token` being a recorded policy limit of the bare-`token` rule; #1228 addendum `addendum-contentful-create-response-token.md`; Meta `client_secret`; Salesforce `refresh_token`, a token-endpoint field and not a resource Bearer credential); the JFrog `X-JFrog-Art-Api` header is a whole-name read since the round-1 baseline (#1228 addendum `addendum-jfrog-art-api-header.md`), and the X consumer secret has no read layout and nothing is asserted for it. | [#1228](../audits/evidence/1228/README.md) |
| Group D roles (23 rows) | Role, confidentiality and derivation facts are evidence metadata and do not select detection, attribution or the default action. A role in a read carrier is not silent, a shared carrier (header, Bearer slot, `client_secret` field, `ApiKey` envelope) attributes no role, alias or provider type, and the default action is the carrier type's (`contextual_secret` redact at high and warn at medium; `bearer_token`, `authorization_credential`, `jwt` redact), replaced by a user action policy exactly as before. No role record is merged or split. | [#1229](../audits/evidence/1229/README.md) |
| Algolia (7 rows) and Contentful Delivery and Preview (2 rows) | Shared generic detection. The `x-algolia-api-key` header or a credential-named field is read the same for admin, search-only, write, analytics, monitoring, usage and secured keys; search-only is documented as frontend-safe and as scrapable, so it is not silent. Contentful Delivery and Preview are read alike in the Bearer header, the `access_token` query parameter and the `accessToken` property, with public or confidential status unresolved. A secured key is a derived value, never decoded. No bare 32-hex or 43-character claim. | [#1229](../audits/evidence/1229/README.md) |
| Shared-carrier roles (9 rows: Asana service account, Dropbox app auth, Elastic cross-cluster and Serverless, Figma plan and CLI plan, HubSpot static auth, JFrog pairing, Instagram app secret) | Shared generic detection through the carrier the evidence names, with no alias to the sibling family: Elastic Serverless is not the stack key, HubSpot static auth is not the private-app token, the Instagram secret is not the Meta app secret, the Asana service account token is not the personal access token. A carrier the evidence has not named (the Elastic keystore, the Figma CLI and npm registry, the Asana service account request) asserts nothing; a JFrog pairing value that is a JWT is one `jwt` finding with no JFrog type. | [#1229](../audits/evidence/1229/README.md) |
| Meta composite, X OAuth 1.0 halves, Canva code, Zoom (5 rows) | `access_token={app-id}\|{app-secret}` is one `contextual_secret` or `bearer_token` span over the whole composite, with no Meta attribution and no secret-only span. `oauth_token` and `oauth_token_secret` are two spans (the #1241 default). A Canva `code` is a medium `warn` and `code_verifier` redacts. The Zoom `x-zm-signature` header is silent; `plainToken` and `encryptedToken` are read by name and redacted, a recorded deviation from the derived-output role. | [#1229](../audits/evidence/1229/README.md) |
| Group E eras (9 rows) | Current and historical claims are stated separately and a historical form is detected like a current one in the same carrier: an era, deprecation or end-of-life word changes nothing, and provider shutdown does not make a credential benign. Deprecation is not authentication shutdown (JFrog's usage block is an opt-in, off by default). Version-scoped variants are never merged. No dedicated historical detector is mandatory and no existing legacy detector or contract is narrowed. Every format is unresolved. | [#1230](../audits/evidence/1230/README.md) |
| Adobe JWT private key, Airtable legacy key, Dropbox long-lived token, HubSpot legacy key (4 rows) | The Adobe key is a locally generated RSA key with no Adobe marker, so the generic PEM reading is the contract: one `private_key` finding over the whole block, `block`, no Adobe type, the public certificate silent and the signed `jwt_token` assertion its own `jwt`. The Airtable `api_key` and the Dropbox `access_token` and Bearer slots are read generically; the Dropbox legacy form is not separable from short-lived tokens by shape. The HubSpot `hapikey` parameter carries both the retired account key and the current developer key and is classed by neither era nor account type; it is a whole-name read since the round-1 baseline reproduced the gap (#1230 addendum `addendum-hapikey.md`: `hapikey` and a prefixed form such as `HUBSPOT_HAPIKEY`), with no UUID bare grammar and no era or key-kind attribution. | [#1230](../audits/evidence/1230/README.md) |
| JFrog API key and Zendesk API token (2 rows) | JFrog's `AKCp` + 69 form (provider-stated, version-scoped) and the unprefixed 44-character sample are separate variants with no union; the documented `X-JFrog-Art-Api` header is a whole-name read since the round-1 baseline (#1230 addendum), and an era-specific bare claim for the `AKCp` pattern alone is a later candidate, not mandatory. The Zendesk Basic envelope is one `authorization_credential` span over the whole encoded value, email and token inside, never split; a named field is read exactly; a raw `{email}/token:{token}` string is read by its `/token:` literal since the round-1 baseline (#1230 addendum `addendum-zendesk-email-token-credential.md`): the span is the token only, `redact` at high confidence, in a JSON member, an environment value and, through the literal, a `curl` Basic argument, while a masked or placeholder token is silent and a generic `curl -u user:<password>` reader stays deferred (issue #1247). | [#1230](../audits/evidence/1230/README.md) |
| Reddit client secret, access token and refresh token (3 rows) | The three carriers the archived wiki documents, which Reddit's current Help page points to, are read generically: the Basic envelope as one whole `authorization_credential` span (an installed app's empty-password envelope included, since nothing is decoded), `client_secret`, the `access_token` member, the URL fragment, a lower-case `bearer` header and the `refresh_token` body field as their generic types; the revoke request `token=` parameter (shared by access and refresh tokens) is read only where the request names a revoke or introspect endpoint or carries `token_type_hint=` (#1230 addendum `addendum-revoke-token-parameter.md`), a bare `token=` staying a recorded policy limit. App types, lifetimes, registration, installed-app secrets and every format stay historical and unresolved until a current source verifies them. | [#1230](../audits/evidence/1230/README.md) |
| JFrog `X-JFrog-Art-Api` header (reference token, API key; round-1 gap `G-jfrog`) | `x_jfrog_art_api` is one whole-name, high-signal contextual name, matched in either documented spelling and any letter case (`X-JFrog-Art-Api`, `X-JFrog-Art-API`): the value is `contextual_secret`, high at random-looking material and `warn` at medium, `redact` at high, exactly the value, in a raw HTTP header (CRLF, LF, end of input), a curl `-H` or `--header` argument and a JSON header map, whatever its shape (8 bytes or more; no prefix, width or alphabet claim, no JFrog type, no reference-token or API-key subtype). Placeholders, references, masks and empty values are silent; `X-JFrog-Art-Api-Id`, `JFrog-Art-Api`, `X-Art-Api` and a further-prefixed name are not read. Stated false negative: the `curl -u user:<secret>` Basic password slot is not read (deferred, issue [#1247](https://github.com/redact-secret/redact-secret/issues/1247)); a digits-only value is the digits-only row. FP cost: a non-secret literal of 8+ bytes in this header; FN cost: the Basic slot, a value under 8 bytes. | [#1228](../audits/evidence/1228/addendum-jfrog-art-api-header.md), [#1230](../audits/evidence/1230/README.md) |

## Rules

| Rule | Governing ADR |
| --- | --- |
| `pii:global:iban` contract v1 is exposed through `pii-domain` as `pii_global_iban`. It accepts an uppercase electronic form or exact four-character ASCII-space print grouping, requires a Release 103 country/length row and `iban-mod97` v1, and requires high-signal IBAN context for sensitivity. Checksum-valid collisions without context stay identity-only; unknown or wrong country lengths stay unmatched. Frozen contract: `docs/contracts/pii/iban-v1.md`. | no dedicated ADR; applies the existing PII domain and `pii-v1` policies to one family in issue #878 |
| `pii:global:network-address` contract v1 is one family for IPv4 and IPv6, exposed only through `pii-domain` as `pii_global_network_address`. It accepts canonical dotted IPv4 and full/compressed/IPv4-embedded IPv6, rejects zone ids and leading-zero IPv4 octets, and requires high-signal network-address context for sensitivity. Only the frozen documentation/test/benchmark ranges and named non-endpoint constants/classes are non-sensitive; IANA special-purpose status alone is not negative sensitivity evidence. Frozen contract: `docs/audits/evidence/875/README.md`. The frozen contract leaves a trailing period undecided; the rule is that one `.` directly after an address is a right boundary when it ends the input or is followed by whitespace or a closing `"`, `'`, `)`, `]`, `}` or `>`, and it stays outside the range, like a `:port` suffix. A period followed by anything else (a digit, a letter, another period) still leaves the whole dotted run unmatched ([#925](https://github.com/redact-secret/redact-secret/issues/925)). A dotted-quad version at the end of a sentence now has identity, but it still needs an adjacent network-address label to be reported. | no dedicated ADR; applies the existing PII domain and `pii-v1` policies to one family in issues #875 and #925 |
| `pii:global:payment-card` contract v1 is exposed only through `pii-domain` as `pii_global_payment_card`. It accepts the frozen 10–19-digit payment-brand subset after bounded display normalization and a Luhn v1 pass, requires a reviewed English or Korean payment-card field label for sensitivity, and excludes exact whole Visa Acceptance test-service PANs. `pan` is a label only through the shared bounded field-label grammar, never free prose. Frozen contract and evidence: `docs/contracts/pii/payment-card-v1.md` and `docs/audits/evidence/877/README.md`. | no dedicated ADR; applies the existing PII domain and `pii-v1` policies to one family in issue #877 |
| `pii:global:phone` contract v1 is exposed only through `pii-domain` as `pii_global_phone`. It accepts only the frozen `+1` / NANP displays and narrow extensions, excludes actual `N11` codes while retaining structurally valid `988`, requires reviewed high-signal phone context, and treats only exact whole-candidate `555-01xx` exchange/line values as non-sensitive. Frozen contract and evidence: `docs/contracts/pii/phone-v1.md` and `docs/audits/evidence/880/README.md`. | no dedicated ADR; applies the existing PII domain and `pii-v1` policies to one family in issue #880 |
| `pii:us:ssn` contract v1 is exposed only through `pii-domain` as `pii_jurisdiction_us_ssn`. It accepts nine ASCII digits in compact or exact ASCII-hyphenated `3-2-4` form, requires `us-ssn-allocation` v1 and a reviewed English or Korean SSN field label, and rejects only the current SSA structural exclusions. `ssn` is a label only through the bounded field-label grammar. No issuance, identity, geography, or pre-2011 allocation claim is made. Frozen contract and evidence: `docs/contracts/pii/us-ssn-v1.md` and `docs/audits/evidence/879/README.md`. | no dedicated ADR; applies the existing PII domain and `pii-v1` policies to one family in issue #879 |
| Doppler `dp.<type>.` tokens (seven documented types, 40–44 alphanumeric body, optional `dp.st.` environment segment) are reported as one finding type per type at provider specificity, bare or in any context ([#903](https://github.com/redact-secret/redact-secret/issues/903), section above). | generic policy default, no dedicated ADR; applies the existing prefixed-provider policy and the GitHub one-type-per-family precedent to one more family |
| Trigger.dev `tr_<env>_sk_` + 24 and `tr_<env>_` + 24 or 20 alphanumeric secret keys (four documented env slugs), and `tr_pat_` + 40 `[1-9a-km-z]` personal access tokens, are reported as two finding types at provider specificity, bare or in any context; `pk_<env>_`, `tr_oat_` and JWT forms stay unclaimed ([#904](https://github.com/redact-secret/redact-secret/issues/904), section above). | generic policy default, no dedicated ADR; applies the existing exact-length prefixed policy to one more family |
| E2B `e2b_` + exactly 40 lowercase hex API keys are reported as `e2b_api_key` at provider specificity, bare or in any context; retired `sk_e2b_` tokens and `e2b_` module names stay unclaimed ([#905](https://github.com/redact-secret/redact-secret/issues/905), section above). | generic policy default, no dedicated ADR; applies the existing exact-length prefixed policy to one more family |
| Vercel `vcp_`, `vca_` and `vcr_` + exactly 56 `[A-Za-z0-9]` are reported as `vercel_personal_access_token`, `vercel_app_access_token` and `vercel_app_refresh_token` at provider specificity; every other `vercel-token` match (`vci_`, `vck_`, and typed markers off the exact contract) stays `vercel_token` at the unchanged pre-split shape, so no redaction is lost ([#1036](https://github.com/redact-secret/redact-secret/issues/1036), section above). | generic policy default, no dedicated ADR; applies the GitHub one-type-per-family precedent and the existing exact-length prefixed policy to one more family |
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
| Bitwarden Secrets Manager `0.<uuid>.<30 alphanumeric>:<22 Base64>==` access tokens are reported as `bitwarden_secrets_manager_access_token` at provider specificity, bare or in any context; unpadded keys, other versions and Password Manager API keys stay unclaimed ([#1019](https://github.com/redact-secret/redact-secret/issues/1019), section above, #1014). | generic policy default, no dedicated ADR; applies the existing prefixed-provider policy to one more family |
| Polar `polar_oat_` + 43 alphanumeric organization access tokens and `polar_pat_`/`polar_at_u_`/`polar_at_o_`/`polar_rt_u_`/`polar_rt_o_`/`polar_cs_`/`polar_crt_` + 43 `[A-Za-z0-9_-]` API credentials are reported as two finding types at provider specificity, bare or in any context; the checksum never rejects a match, `polar_ci_` and checkout secrets stay unclaimed, and `whsec_` stays with Stripe ([#1020](https://github.com/redact-secret/redact-secret/issues/1020), section above, #1014). | generic policy default, no dedicated ADR; applies the existing prefixed-provider policy and the public-key exclusion precedent to one more family |
| SonarQube `squ_` user tokens and `sqa_`/`sqp_` analysis tokens (+ 40 lowercase hex) are reported as two finding types at provider specificity, bare or in any context; `sqb_` badge tokens and unprefixed legacy tokens stay unclaimed ([#1021](https://github.com/redact-secret/redact-secret/issues/1021), section above, #1014). | generic policy default, no dedicated ADR; applies the existing exact-length prefixed policy and the public-key exclusion precedent to one more family |
| RubyGems.org `rubygems_` + 48 lowercase hex API keys are reported as `rubygems_api_key` at provider specificity, bare or in any context; legacy unprefixed keys stay unclaimed ([#1023](https://github.com/redact-secret/redact-secret/issues/1023), section above, #1014). | generic policy default, no dedicated ADR; applies the existing exact-length prefixed policy to one more family |
| Clojars `CLOJARS_` + 60 lowercase hex deploy tokens are reported as `clojars_deploy_token` at provider specificity, bare or in any context; `CLOJARS_*` environment names and legacy passwords stay unclaimed ([#1025](https://github.com/redact-secret/redact-secret/issues/1025), section above, #1014). | generic policy default, no dedicated ADR; applies the existing exact-length prefixed policy to one more family |
| Daytona `dtn_` + exactly 64 lowercase-hex API keys are reported as `daytona_api_key` at provider specificity, bare or in any context ([#970](https://github.com/redact-secret/redact-secret/issues/970), section above). | generic policy default, no dedicated ADR; applies the existing prefixed-provider policy to one more family |
| ClickHouse Cloud `4b1d` + exactly 38 alphanumeric API key secrets with at least one uppercase letter are reported as `clickhouse_cloud_api_secret` at provider specificity, bare or in any context; the key ID stays unclaimed ([#971](https://github.com/redact-secret/redact-secret/issues/971), section above). | generic policy default, no dedicated ADR; applies the existing prefixed-provider policy to one more family |
| NVIDIA `nvapi-` + 60–128 `[A-Za-z0-9_-]` API keys are reported as `nvidia_api_key` at provider specificity, bare or in any context; the legacy prefixless NGC key stays unclaimed ([#972](https://github.com/redact-secret/redact-secret/issues/972), section above). | generic policy default, no dedicated ADR; applies the existing prefixed-provider policy to one more family |
| Browserbase `bb_live_` + 20–128 alphanumeric API keys are reported as `browserbase_api_key` at provider specificity, bare or in any context; `bb_test_` stays unclaimed ([#973](https://github.com/redact-secret/redact-secret/issues/973), section above). | generic policy default, no dedicated ADR; applies the existing prefixed-provider policy to one more family |
| RunPod `rpa_` + 31–128 alphanumeric API keys are reported as `runpod_api_key` at provider specificity, bare or in any context; Redirect.pizza `rpa_` + 30 and `rps_` S3 secrets stay unclaimed ([#974](https://github.com/redact-secret/redact-secret/issues/974), section above). | generic policy default, no dedicated ADR; applies the existing prefixed-provider policy to one more family |
| Cerebras `csk-` or `csk_` + exactly 48 `[A-Za-z0-9_-]` API keys are reported as `cerebras_api_key` at provider specificity, bare or in any context; Pinecone `pcsk_` keys stay `pinecone_api_key` only ([#975](https://github.com/redact-secret/redact-secret/issues/975), section above). | generic policy default, no dedicated ADR; applies the existing prefixed-provider policy to one more family |
| crates.io `cio` + 32 alphanumeric API tokens and `cio_tp_` + 32 alphanumeric trusted-publishing tokens are reported as `crates_io_api_token` and `crates_io_trusted_publishing_token` at provider specificity, bare or in any context; the trusted-publishing check character is not a rejection gate ([#1031](https://github.com/redact-secret/redact-secret/issues/1031), section above). | generic policy default, no dedicated ADR; applies the existing prefixed-provider policy to one more family |
| Dynatrace `dt0[cs]NN.` + 24 + `.` + 64 base32 access and platform tokens are reported whole as `dynatrace_token` at provider specificity, bare or in any context, including after `Api-Token%20`; the token identifier alone stays unclaimed ([#1032](https://github.com/redact-secret/redact-secret/issues/1032), section above). | generic policy default, no dedicated ADR; applies the existing prefixed-provider policy to one more family |
| Paddle `pdl_live_apikey_`/`pdl_sdbx_apikey_` + 26 + `_` + 22 + `_` + 3 API keys are reported as `paddle_api_key` at provider specificity, bare or in any context; the `apikey_` key id alone and legacy unprefixed keys stay unclaimed ([#1033](https://github.com/redact-secret/redact-secret/issues/1033), section above). | generic policy default, no dedicated ADR; applies the existing prefixed-provider policy to one more family |
| Honeycomb `hc[a-z]ik_`/`hc[a-z]ic_` + 58 lowercase alphanumeric ingest keys are reported as `honeycomb_ingest_key` at provider specificity, bare or in any context; management keys stay unclaimed until their issuance check, and key ids, configuration and classic hex keys stay unclaimed ([#1034](https://github.com/redact-secret/redact-secret/issues/1034), section above). | generic policy default, no dedicated ADR; applies the existing prefixed-provider policy to one more family |
| Axiom `xaat-` and `xapt-` + lowercase-hex UUID tokens are reported as `axiom_api_token` and `axiom_personal_token` at provider specificity, bare or in any context; placeholders and bare UUIDs stay unclaimed ([#1035](https://github.com/redact-secret/redact-secret/issues/1035), section above). | generic policy default, no dedicated ADR; applies the existing prefixed-provider policy to one more family |
| Xata `xau_` and `xao_` + 32 to 36 `[A-Za-z0-9]` API keys are reported as `xata_user_api_key` and `xata_organization_api_key` at provider specificity, bare or in any context; the CRC32 never rejects a match, and classic-platform keys stay unclaimed ([#1102](https://github.com/redact-secret/redact-secret/issues/1102), section above, #1014). | generic policy default, no dedicated ADR; applies the existing prefixed-provider policy to one more family |
| Sourcegraph `sgp_` + optional alphanumeric instance identifier + 40 hex access tokens are reported as `sourcegraph_access_token` at provider specificity, bare or in any context; bare 40-hex tokens, `sgph_` and `sgd_` stay unclaimed ([#1103](https://github.com/redact-secret/redact-secret/issues/1103), section above, #1014). | generic policy default, no dedicated ADR; applies the existing prefixed-provider policy to one more family |
| Unkey `unkey_` + 8 + `unkeyv1` + 42 base58 version 1 root keys and `unkey_3Z` + 22 base58 dashboard root keys are reported as `unkey_root_key` at provider specificity, bare or in any context; customer-prefixed version 1 keys (ruling Q10 open), the deprecated Go form and `unkey_` identifiers stay unclaimed ([#1104](https://github.com/redact-secret/redact-secret/issues/1104), section above, #1014). | generic policy default, no dedicated ADR; applies the existing prefixed-provider policy to one more family |
| Buildkite `bkua_`, `bkur_`, `bktx_`, `bkaa_`, `bkar_`, `bkct_`, `bkcqt_`, `bkaj_`, `bkjat_`, `bkpt_`, `bkrt_`, `bktr_`, `bkat_`, `bkpat_` and `bkps_` + 24 to 2048 `[A-Za-z0-9_.-]` tokens are reported as seven role finding types at provider specificity, bare or in any context, including `bkjat_`/`bkaj_` JWT bodies as one span that wins over `jwt`; the unprefixed legacy tokens and values under 24 body bytes stay unclaimed ([#1105](https://github.com/redact-secret/redact-secret/issues/1105), section above, #1014). | generic policy default, no dedicated ADR; applies the existing prefixed-provider policy to one more family |
| Together AI `tgp_v1_` + 43 `[A-Za-z0-9_-]` (T2) and Tavily `tvly-` + optional `dev-` + 32 alphanumeric (prefix T1, body T2) are each reported as their own finding type at provider specificity, bare or in any context; `tvly-prod-`, Together legacy keys and other widths stay unclaimed ([#867](https://github.com/redact-secret/redact-secret/issues/867), section above). | generic policy default, no dedicated ADR; applies the existing exact-length prefixed policy to two more families |
| Clerk `sk_live_`/`sk_test_` secret keys are reported as `stripe_credential` and stay under that type: known limitation, no Clerk family. Both providers use the same lead and a bare alphanumeric body, and neither publishes a documented body length to separate them (Stripe's is open-ended `at_least` 20 by design; Clerk's public docs show only placeholders, and no issued sample is recorded under `docs/audits/evidence/860/`), so a length or alphabet split would rest on unrecorded observation and would either leave real Stripe keys under a Clerk label or miss Clerk keys. Redaction is unaffected (both types are `always-redact`); only the type label is wrong. Revisit with an issued Clerk key body plus a recorded provider source ([#957](https://github.com/redact-secret/redact-secret/issues/957), [#860](https://github.com/redact-secret/redact-secret/issues/860) disposition row 49). | generic policy default, no dedicated ADR; records the ambiguity as a known limitation |
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
| Google OAuth client secrets `GOCSPX-` + exactly 28 `[A-Za-z0-9_-]` are reported as `google_oauth_client_secret` at provider specificity, bare or in any context; `ya29.` access tokens and `1//` refresh tokens stay unclaimed (T2, [#1029](https://github.com/redact-secret/redact-secret/issues/1029), section above). | generic policy default, no dedicated ADR; applies the existing exact-length prefixed policy to one more family |
| AWS secret access keys, exactly 40 `[A-Za-z0-9/+]` with mixed case, are reported as `aws_secret_access_key` at provider specificity only under an AWS secret access key name or on or directly below or above an `AKIA`/`ASIA` ID line (T2, context-constrained, [#1028](https://github.com/redact-secret/redact-secret/issues/1028), section above). | generic policy default, no dedicated ADR; applies the existing context-gated provider policy (the Twilio and Confluent paired-identifier precedent) to one more family |
| AWS `ASIA` + exactly 16 `[A-Z0-9]` temporary access key IDs are reported as `aws_access_key_id`, typed and actioned exactly like `AKIA` (T2, [#1027](https://github.com/redact-secret/redact-secret/issues/1027), section above). | generic policy default, no dedicated ADR; records the existing `aws-access-key` claim as a contract |
| A routable GitLab `glpat-` personal access token whose length holder and CRC-32 verify is reported as one `gitlab_token` finding through its last CRC byte; a non-verifying dotted tail keeps the legacy payload match ([#1022](https://github.com/redact-secret/redact-secret/issues/1022), section above). This closes the routable-PAT gap the GitLab inventory ADR tracked. | generic policy default, no dedicated ADR; applies the existing routable `glrt-` grammar (#730) to one more GitLab prefix |
| The GitLab token-prefix table is inventoried, and its two undeclared prefixes are given a contract. | [Inventory the GitLab token-prefix table and contract the two undeclared prefixes; record routable tokens and the legacy runner-registration token as explicit, tracked gaps](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| `pinecone-api-key` reports a legacy lowercase `8-4-4-4-12` UUID as `pinecone_api_key` at high confidence only when it is the value assigned to a Pinecone API-key name on the same line: a name normalizing to `pinecone_api_key`/`pinecone_apikey`/`pinecone_key`, or to `api_key`/`apikey` on a line containing `pinecone`. A bare UUID, a UUID under an id-named key, a UUID whose name is on another line, and an all-one-digit placeholder UUID stay unclaimed ([#702](https://github.com/redact-secret/redact-secret/issues/702)). | [Claim a legacy Pinecone UUID key only under a Pinecone API-key name, and redact it](../decisions/2026-09-24-claim-a-legacy-pinecone-uuid-key-only-under-its-api-key-name.md) |
| GitHub's six token families map onto six independent finding types under one detector. | [Map GitHub's six token families onto six independent finding types under one detector](../decisions/2026-09-20-map-github-token-families-onto-independent-finding-types.md) |
| The legacy Supabase anon JWT's payload-trusting exclusion is scoped to `iss` and `role` together. | [Scope a payload-trusting exclusion for the legacy Supabase anon JWT to iss+role together](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| The Supabase management-token credential class is kept separate from the secret-key class, with independent evidence for each. | [Separate the Supabase management-token credential class from the secret-key class, and keep each class's evidence independent](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| A truncated or nested-provider Bearer value is accepted under bearer-token's length-and-alphabet grammar. | [Accept a truncated or nested-provider Bearer value under bearer-token's length-and-alphabet grammar](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| `Proxy-Authorization` is an authorization header like `Authorization` (RFC 7235). `generic-token` matches a `Basic` header mid-line after any byte that cannot continue a header name (a quoted curl argument, a JSON header map with a quoted key, a log prefix), not only at a line start; a mid-line `Token` header stays with the provider detectors that key on it (`travisci-api-token`). `bearer-token` requires 12 bytes, the `Basic`/`Token` floor, when the value follows an explicit `Authorization:`/`Proxy-Authorization:` header name, and keeps 16 for a bare `Bearer <value>`. The cost is a 12–15 byte development token after a real header, which is now reported ([#818](https://github.com/redact-secret/redact-secret/issues/818)). | [Accept a truncated or nested-provider Bearer value under bearer-token's length-and-alphabet grammar](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| `generic-token` recognizes fal's `Authorization: Key <key_id>:<key_secret>` scheme as an `authorization_credential`, beside `Basic` and `Token`, with the same 12-byte floor and entropy-based confidence. The `Key` value alphabet adds `:`, so the colon-joined secret half is inside the span, and a trailing `:` is dropped. A `Key` header is also taken mid-line after a byte that cannot continue a header name (a quoted curl `-H` argument, a JSON header map), like `Basic`: no provider detector keys on it. FP cost: a non-credential `Key` scheme value of 12+ bytes after an `Authorization:` header name (the legacy FCM `key=` form is unaffected: it has no space); FN cost: none added ([#919](https://github.com/redact-secret/redact-secret/issues/919); evidence: `docs/audits/evidence/860/fal-contextual-gap.md`). | [Accept a truncated or nested-provider Bearer value under bearer-token's length-and-alphabet grammar](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| `bearer-token` selects a value made of token runs joined by `:` or `\|` whole (`<id>:<secret>`, `<name>\|<secret>`): each directly following join plus a non-empty run, and its own `=` padding, is part of the value. The 16/12-byte floor is judged on the whole joined value, and the value is excluded as a placeholder only when every run is filler or placeholder vocabulary. A join followed by whitespace, the end of the value, or `//` (a URL) is not part of it. A value glued, directly or through one join, to an `<ANGLE>` placeholder (content `[A-Za-z0-9_-]+` with an uppercase letter, `_` or `-`), a `$VAR`/`${VAR}` reference or a `{{` template is not reported: its run is the public lead of a placeholder (`signkey-prod-<YOUR-SIGNING-KEY>`, `prod:<name>\|${CONVEX_BODY}`); an HTML tag after a real token (`</td>`, `<br>`) is not a placeholder. Before this, the span stopped at the join and left the secret half readable. FP cost: a longer span over a `:`/`\|`-joined run after `Bearer` (a timestamp, a Markdown cell written without spaces), and a short token run that now clears the floor only through its joins; FN cost: none added ([#918](https://github.com/redact-secret/redact-secret/issues/918); evidence: `docs/audits/evidence/860/fal-contextual-gap.md`). Since [#939](https://github.com/redact-secret/redact-secret/issues/939) a join is not taken onto a run that is the key of a delimited record's next field (followed by `=` and a value byte: `<tok>\|email=<addr>`, `<tok>\|x=1`; a run followed by `:` and whitespace is not a field key, because the same bytes end the secret half of `<id>:<secret>: note`, so `<tok>\|user: alice` spans `<tok>\|user`), `=` is padding only where it ends a body (not before a value byte), and a run directly followed by `@` and a host (`Bearer svc-deploy@example.test`) is selected with the host; the floor still judges the part before `@`, so a short local part is no finding rather than a partial one. FP cost of #939: a `name@host` value after `Bearer` is redacted whole; FN cost: a secret whose joined tail looks like `key=value` is cut at the join, and `\|key= value` (space after `=`) still reads `=` as padding. | [Accept a truncated or nested-provider Bearer value under bearer-token's length-and-alphabet grammar](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| `bearer-token` reports an RFC 8959 `secret-token:` URI whole, scheme included, as `bearer_token` (`secret-token-uri` signal): the scheme is matched case-insensitively at an identifier boundary, and the body is RFC 3986 `pchar` bytes except `'`, `(`, `)`, `,`, `;`, with valid `%HH` encodings, no trailing `.`/`:`, at least 8 bytes, and not placeholder vocabulary or filler. RFC 8959 permits a one-byte body; stubs under 8 bytes in documentation are the accepted false negative ([#819](https://github.com/redact-secret/redact-secret/issues/819)). | [Accept a truncated or nested-provider Bearer value under bearer-token's length-and-alphabet grammar](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| Terraform Cloud/Enterprise API token detection is added. | [Add Terraform Cloud/Enterprise API token detection](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| The Pulumi access token grammar is frozen as a documented-prefix, tool-corroborated exact-length hex shape. | [Freeze the Pulumi access token grammar as a documented-prefix, tool-corroborated exact-length hex shape](../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) |
| A bare, marker-less vendor-prefixed value (for example an unmarked OpenAI-prefixed value) is redacted under a generic `vendor_prefixed_credential` policy layer, beneath the frozen per-provider contract. | [Redact a bare, marker-less OpenAI-prefixed value under a generic policy layer, beneath the frozen contract](../decisions/2026-09-21-govern-bare-vendor-prefixed-policy-layer.md) |
| A credential's lifecycle era is not a detection input and backward redaction is preserved ([#1230](https://github.com/redact-secret/redact-secret/issues/1230); evidence: `docs/audits/evidence/1230/README.md`). A retired, deprecated or superseded credential is detected like a current one in the same carrier (no era or deprecation word silences it), deprecation and End of Life notices are not authentication shutdown, two variants of one family are never merged into a union grammar, a shared carrier is not classed by era, and no row requires a dedicated historical detector or narrows an existing legacy one. FP cost: a long-dead credential or a documentation example of one is masked; FN cost: a retired form in a carrier the grammar does not read. Tests: `tests/group_e_era_and_envelopes_1230.rs`. | [Keep a credential's lifecycle era out of detection and preserve backward redaction](../decisions/2026-10-06-keep-credential-lifecycle-era-out-of-detection-and-preserve-backward-redaction.md) |
| A `mongodb` or `mongodb+srv` URI userinfo the strict grammar declines is read over its password slot ([#1226](https://github.com/redact-secret/redact-secret/issues/1226); evidence: `docs/audits/evidence/1226/addendum-atlas-uri-userinfo.md`): a malformed percent escape (`user:ab%zz<v>@host`, `100%<v>`, `100%%`, a password ending in `%`), a raw `@`, or a raw `/`, `?` or `#` in the password. The finding is `connection_string_password` over exactly the undecoded password, `medium` confidence and `redact` (the type redacts at every confidence). The userinfo ends at the last `@` before the first `/`, `?` or `#` (the Go driver's reading; the Node driver stops at the first `@` and `pymongo` rejects the URI); after a raw `/`, `?` or `#` that ended the authority first, at the first `@` followed by a valid host list; the text after it up to the next `/`, `?` or `#` must be a valid host list for the scheme. Host-only URIs (`mongodb://host:27017/db?x=a:b@c.example`), placeholders and references, an empty user or password, other schemes and the postgres benign case `connection-negative-malformed-percent` keep their previous result, and a digit-only password right before a raw `/` (`user:123/x@host`) reads as `host:port` and stays unread. This amends the stated blind spot of the 2026-10-05 decision for the MongoDB URI only. FN cost: the residuals above; FP cost: a redacted non-secret in a malformed MongoDB-looking run. Tests: `tests/mongodb_relaxed_userinfo_1226.rs`. | [Read the MongoDB URI password slot when the userinfo is malformed](../decisions/2026-10-06-read-the-mongodb-uri-password-slot-when-the-userinfo-is-malformed.md) |
