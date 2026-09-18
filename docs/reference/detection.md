# Detection coverage and limits

[Documentation home](../README.md)

The core uses local structure and context, not provider API calls, to classify
text. It does not determine whether a credential is active, expired, or valid.

| Family | Examples of supported structure |
| --- | --- |
| Private keys | PEM-style private-key blocks |
| Provider credentials | AWS access-key IDs; GitHub, GitLab, OpenAI, Anthropic, Shopify, modern Vault patterns |
| Additional provider formats | Qualified Stripe, Slack, PyPI, Hugging Face, Docker Hub, Cloudflare, DigitalOcean (`dop_v1_`/`doo_v1_`/`dor_v1_` plus exactly 64 lowercase hex bytes), Linear, Supabase, Vercel, npm, SendGrid, Google Cloud/Gemini, Microsoft Entra client secret, Azure DevOps personal access token, Notion, Atlassian Cloud, Twilio, Telegram Bot API, Discord bot, Sentry, Datadog, Grafana, and New Relic patterns |
| Authorization | JWT, Bearer, Basic, and Token credentials |
| Context | Credential assignments, including AWS secret-access-key and session-token names |
| Connections | Credential-bearing PostgreSQL, MySQL, MariaDB, MongoDB, Redis, AMQP URLs |
| One-time password provisioning | `otpauth://totp` and `otpauth://hotp` with base32 shared secrets |

## Detector profiles

`full` — every detector in the table above, the default and compatibility
baseline on every surface — stays the first and simplest path. `common` is a
smaller, opt-in built-in set for size- or latency-sensitive **preventive**
consumers (browser UX, small agent or tool processes): only private keys,
JWT/Bearer authorization, connections, one-time-password provisioning, and
the generic credential-assignment context detector — it omits both provider
rows (Provider credentials, Additional provider formats) entirely. Node and
the browser expose it as `@redact-secret/core/common`
([JavaScript guide](../guides/javascript.md#detector-profiles)) and Rust as
`DetectorRegistry::with_common_built_in`
([Rust guide](../guides/rust.md#detector-profiles)). Python and the CLI stay
`full` only.

`common`'s false-negative tradeoff is on provider tokens specifically: a bare
provider token (for example a raw GitHub or AWS credential, with no
surrounding `Bearer` header or contextual assignment) is not detected at all,
and a provider token that *is* caught by a `common` detector's context is
reported under that detector's type and confidence instead of the
provider-specific one — for example `warn` where `full` would `redact`. It
adds no false positive: it only drops candidates `full` would have reported.
See the [README's profile section](../../README.md#opt-in-detector-profiles)
for the measured size and latency savings.

This is a family overview, not a promise to match every token each provider
issues. Exact supported grammars and evidence are recorded in the
[coverage report](../coverage/coverage-report.md) and
[conformance corpus](../../conformance/README.md). The bounded, source-identified
[detection reliability assessment](detection-reliability.md) publishes its
denominators, results, and limitations without turning them into a universal
accuracy claim.

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
Whole-input operations have no implicit resource cap; the host must impose one.
See [safe integration](../guides/safe-integration.md).

To report a missed detection or false positive, provide a minimal synthetic
reproducer, the runtime and product version, and expected safe metadata. Never
include an active credential in an issue, test, log, or screenshot.
