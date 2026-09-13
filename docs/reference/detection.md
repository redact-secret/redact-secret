# Detection coverage and limits

[Documentation home](../README.md)

The core uses local structure and context, not provider API calls, to classify
text. It does not determine whether a credential is active, expired, or valid.

| Family | Examples of supported structure |
| --- | --- |
| Private keys | PEM-style private-key blocks |
| Provider credentials | AWS access-key IDs; GitHub, GitLab, OpenAI, Anthropic, Shopify, modern Vault patterns |
| Additional provider formats | Qualified Stripe, Slack, PyPI, Hugging Face, Docker Hub, Cloudflare, DigitalOcean, Linear, Supabase, Vercel patterns |
| Authorization | JWT, Bearer, Basic, and Token credentials |
| Context | Credential assignments, including AWS secret-access-key and session-token names |
| Connections | Credential-bearing PostgreSQL, MySQL, MariaDB, MongoDB, Redis, AMQP URLs |
| One-time password provisioning | `otpauth://totp` and `otpauth://hotp` with base32 shared secrets |

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
