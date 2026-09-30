# #1012 research: `stripe:organization-api-key` (`sk_org_`)

[Research index](README.md) ·
[Issue #1012](https://github.com/redact-secret/redact-secret/issues/1012)

Frozen 2026-09-29. Desk research only: no key was issued, and no issued or
leaked credential is evidence. Sources were accessed on 2026-09-29.

**Verdict: BLOCKED (grammar); the shipped product rule should be
revisited.** Only the `sk_org` prefix is T1. Stripe publishes no literal
organization key, and no Stripe SDK, mock or peer scanner has one. Two
independent applications branch on `sk_org_live_` and `sk_org_test_`, which
suggests a mode segment the product rule does not expect.

## Current product behaviour

`stripe-token` (`crates/secret-scan-core/src/detectors/additional_providers.rs`,
issue #513) claims `sk_org_` + at least 20 `[A-Za-z0-9]` on the docs alone,
and calls `sk_org_live_…` a hypothetical, intentional false negative. The
synthetic probe on `main`: `sk_org_live_` plus a long alphanumeric body gives
**no finding**; `sk_org_` plus the same body gives `stripe_credential`. If the mode segment is
real, today's rule misses every organization key.

## Sources

| # | Source | Date | Class | Ruling | Statement |
|---|---|---|---|---|---|
| 1 | [Stripe docs, organization API keys](https://docs.stripe.com/keys/organization-api-keys) | read 2026-09-29 | provider docs | T1 (prefix) | "Organization API keys are prefixed `sk_org`." "they support sandboxes and live mode." "Organization API keys all have the same `sk_org` prefix, regardless of their permission levels. (There's no `rk_org` prefix.)" No literal key |
| 2 | [Stripe docs, API keys](https://docs.stripe.com/keys) | read 2026-09-29 | provider docs | T1 (prefix) | "Organization API key `sk_org_...`", not safe to expose |
| 3 | [stripe/stripe-cli `pkg/cmd/listen.go` L193-L196 @ 1090068](https://github.com/stripe/stripe-cli/blob/1090068baae4c3d732fd500a9d3dbe4b94bc91a0/pkg/cmd/listen.go#L193-L196) | at HEAD | provider code | R6 (substring) | `strings.Contains(creds.Token, "sk_org")`: no grammar |
| 4 | [koki-develop/mask-go `builtin_stripe_secret_key.go` L100-L113 @ 1b861d7](https://github.com/koki-develop/mask-go/blob/1b861d7ac421b392a5bb962207fd1886b28e013e/builtin_stripe_secret_key.go#L100-L113) | 2026-08-31 | independent implementation | T2 class | accepts `sk_org_live_`/`sk_org_test_` + body and `sk_org_` + body; "No page gives a length, an alphabet or a checksum for any of them." |
| 5 | [lazyluke16-dotcom/richmond-rapid-connect `src/lib/stripe.server.ts` L12-L18 @ 5c057a9](https://github.com/lazyluke16-dotcom/richmond-rapid-connect/blob/5c057a98ccc24602917441f6c78f3a6aa15dc740/src/lib/stripe.server.ts#L12-L18) | 2026-07-23 | independent implementation | T2 class | `/^sk_org_test_/` for test mode, `/^sk_org_live_/` for live |
| 6 | [baristaze/tadas `integrations/src/tadas/integrations/settings.py` L94-L114 @ b55571c](https://github.com/baristaze/tadas/blob/b55571cd85ec5a7fe16bc463537980909f87ee4f/integrations/src/tadas/integrations/settings.py#L94-L114) | 2026-09-23 | independent implementation | T2 class; partly contradicted | lists `sk_org_live_` and `sk_org_test_`, and also `rk_org_` forms that #1 says do not exist |
| 7 | Committed `sk_org_live_` key-shaped values in unrelated public repositories (three distinct values) | 2024–2026 | observation | not evidence (withheld) | recorded only as a lead that the `live_` segment occurs; no shape is taken from them |

Searched, nothing further: 11 Stripe docs pages grepped (no `sk_org_live_` or
`sk_org_test_` literal); nine Stripe SDK and mock repositories at HEAD
(stripe-node, -python, -go, -ruby, -php, -java, -dotnet, stripe-mock,
stripe/ai: no `sk_org`); gitleaks, trufflehog, betterleaks, CredSweeper,
noseyparker, GitLab's rules (no `sk_org` rule); GitHub's pattern list (no
organization row); web search (docs only).

## Exact missing evidence

- **Mode segment:** whether `live_` or `test_` follows `sk_org_`. Stripe
  states only that org keys "support sandboxes and live mode".
- **Body:** length and alphabet.
- The T2 route counts one class (independent implementation, #4–#6); no
  provider example or peer rule exists.

## Structure-only issuance check

In a Stripe organization, create one organization API key in a sandbox (and
read a live one if available). Record: the bytes after `sk_org_` (`test_`,
`live_` or none), body length, whether the body is only `[A-Za-z0-9]`, total
length. `rawValueRetained: false`, then roll or delete the key.

## Interim option (product, not a contract)

Widen the interim rule to also claim `sk_org_(live|test)_` + at least 20
`[A-Za-z0-9]`, at the same support-policy evidence level the current rule
already uses. Trade-off: no new false-positive surface worth naming (the
prefix is unique); it removes a likely total false negative. `rk_org_` stays
excluded (#1).

## Residual risk

Until then, organization keys are redacted only in named and header
contexts (for example `STRIPE_SECRET_KEY=`).
