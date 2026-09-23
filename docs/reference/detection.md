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
| Connections | Credential-bearing PostgreSQL, MySQL, MariaDB, MongoDB, Redis, AMQP URLs |
| One-time password provisioning | `otpauth://totp` and `otpauth://hotp` with base32 shared secrets |

Per-family support status is stated only in the generated
[support matrix](../support-matrix.md). Each provider family's exact frozen
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

## Built-in detectors

Every detector the built-in registry ships, the finding types it emits, and
its default policy class: `block` findings are blocked, `always-redact`
findings are redacted, and `confidence-gated` findings are redacted at high
confidence and warned at medium or low confidence. See
[safe integration](../guides/safe-integration.md) for what each action means
for your host. An organization-specific format that is not listed here can be added
as a [declarative ruleset](../guides/rulesets.md).

<!-- detector-inventory:start -->
50 built-in detectors emit 57 finding types. Generated from [`detector-inventory.json`](../coverage/detector-inventory.json) by `python3 -B scripts/generate-detector-inventory-docs.py`; do not edit by hand.

| Detector | Finding types | Default policy class | Schemes |
| --- | --- | --- | --- |
| `private-key` | `private_key` | `block` | — |
| `aws-access-key` | `aws_access_key_id` | `always-redact` | — |
| `github-token` | `github_token`, `github_oauth_token`, `github_app_user_to_server_token`, `github_app_installation_token`, `github_app_refresh_token`, `github_fine_grained_personal_access_token` | `always-redact` | — |
| `gitlab-token` | `gitlab_token` | `always-redact` | — |
| `openai-token` | `openai_api_key` | `always-redact` | — |
| `anthropic-token` | `anthropic_api_key` | `always-redact` | — |
| `shopify-token` | `shopify_access_token` | `always-redact` | — |
| `vault-token` | `vault_token` | `always-redact` | — |
| `stripe-token` | `stripe_credential` | `always-redact` | — |
| `slack-token` | `slack_token` | `always-redact` | — |
| `pypi-token` | `pypi_api_token` | `always-redact` | — |
| `huggingface-token` | `huggingface_token` | `always-redact` | — |
| `docker-token` | `docker_token` | `always-redact` | — |
| `cloudflare-token` | `cloudflare_api_token` | `always-redact` | — |
| `digitalocean-token` | `digitalocean_token` | `always-redact` | — |
| `linear-token` | `linear_token` | `always-redact` | — |
| `supabase-token` | `supabase_secret_key` | `always-redact` | — |
| `supabase-management-token` | `supabase_personal_access_token` | `always-redact` | — |
| `vercel-token` | `vercel_token` | `always-redact` | — |
| `npm-token` | `npm_access_token` | `always-redact` | — |
| `google-api-key` | `google_api_key` | `always-redact` | — |
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
| `datadog-application-key` | `datadog_application_key` | `confidence-gated` | — |
| `grafana-service-account-token` | `grafana_service_account_token` | `always-redact` | — |
| `grafana-cloud-access-policy-token` | `grafana_cloud_access_policy_token` | `always-redact` | — |
| `sentry-user-auth-token` | `sentry_user_auth_token` | `always-redact` | — |
| `sentry-org-auth-token` | `sentry_org_auth_token` | `always-redact` | — |
| `new-relic-user-api-key` | `new_relic_user_api_key` | `always-redact` | — |
| `new-relic-license-key` | `new_relic_license_key` | `confidence-gated` | — |
| `firebase-server-key` | `firebase_server_key` | `always-redact` | — |
| `terraform-cloud-token` | `terraform_cloud_token` | `always-redact` | — |
| `pulumi-access-token` | `pulumi_access_token` | `always-redact` | — |
| `databricks-personal-access-token` | `databricks_personal_access_token` | `always-redact` | — |
| `confluent-cloud-api-secret` | `confluent_cloud_api_secret` | `always-redact` | — |
| `confluent-cloud-api-secret-legacy` | `confluent_cloud_api_secret_legacy` | `confidence-gated` | — |
| `postman-api-key` | `postman_api_key` | `always-redact` | — |
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
16% transfer size and processes 3–6× faster in the browser, with zero new
false positives and identical findings wherever no provider detector would
have competed ([evidence](../audits/evidence/382/README.md)).

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
