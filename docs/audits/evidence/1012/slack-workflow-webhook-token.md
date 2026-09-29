# #1012 research: `slack:workflow-webhook-token` (`xwfp-`)

[Research index](README.md) ·
[Issue #1012](https://github.com/redact-secret/redact-secret/issues/1012)

Frozen 2026-09-29. Desk research only: no key was issued, and no issued or
leaked credential is evidence. Sources were accessed on 2026-09-29.

**Verdict: BLOCKED (sectioned grammar).** The `xwfp-` prefix is T1. One Slack
docs example shows a full-width token with the `xoxp-` layout (three digit
sections and a 32-byte lowercase-hex section), and Slack's own SDK redactor
uses an alphabet without `_`. Both are from one owner, so the T2 route fails,
and R5 gives the example shape, not a grammar. A maintainer ruling on the
example, or one short-lived issuance, closes it.

**Naming.** `xwfp-` is Slack's **workflow token**: the short-lived bot token
given to a custom function step (`bot_access_token`). It is not a workflow
webhook; those are `hooks.slack.com/workflows/…` URLs. Suggested family name:
`slack:workflow-token`.

## Current product behaviour

`slack-token` (`crates/secret-scan-core/src/detectors/slack.rs`) keeps an
interim guard: `xwfp-` + at least 20 `[A-Za-z0-9_-]`. A synthetic value in
the docs example's layout is found as `slack_token`, full span.

## Sources

| # | Source | Date | Class | Ruling | Statement |
|---|---|---|---|---|---|
| 1 | [Slack docs, token types](https://docs.slack.dev/authentication/tokens) | read 2026-09-29 | provider docs | T1 (prefix, lifetime) | "Workflow tokens expire, but cannot be refreshed. These tokens expire either 15 minutes after being issued, or when a function step is completed successfully or returns an error—whichever occurs first. The token is then revoked immediately. Workflow token strings begin with `xwfp-`." |
| 2 | [Slack docs, `block_suggestion` payload](https://docs.slack.dev/reference/interaction-payloads/block_suggestion-payload) | present by 2023-10-07 (identical in a [Wayback snapshot](http://web.archive.org/web/20231007203546/https://api.slack.com/reference/interaction-payloads/block-suggestion)) | provider docs example | R5 (example shape) | one full-width `bot_access_token`: `xwfp-` + 13 digits + `-` + 13 digits + `-` + 13 digits + `-` + 32 lowercase hex (79 in total). Not reproduced |
| 3 | [slackapi/python-slack-sdk `slack_sdk/socket_mode/logger/messages.py` L4-L6 @ 1fe0b8e](https://github.com/slackapi/python-slack-sdk/blob/1fe0b8e708251fb4d2dc9617a774f64635098e21/slack_sdk/socket_mode/logger/messages.py#L4-L6) | 2024-06-26 | provider log redactor | R2 = T1 for what it states | `"xwfp-[A-Za-z0-9\-]+"`: no `_` |
| 4 | slackapi test fixtures in bolt-js, bolt-python, java-slack-sdk, python-slack-sdk | at HEAD | provider placeholders | R4 | short `xwfp-` placeholders, no length or sections |

Searched, nothing further: slack-cli, deno-slack-sdk, -api, -runtime, -hooks,
node-slack-sdk (no `xwfp`); gitleaks, trufflehog, CredSweeper, noseyparker,
betterleaks, GitLab's rules (no `xwfp-` rule); third-party SDK fixtures
(placeholders only). No leaked value was found, as expected for a token that
dies within 15 minutes.

## What can change now

The interim guard's `_` is wider than any provider evidence (#2, #3). Dropping
`_` from its alphabet is supported by provider code (R2) and the provider
example.

## Exact missing evidence

- The section count and widths for issued tokens. The only source is one
  example (#2); the digit sections may grow as `xoxp-` IDs do.
- Either a maintainer ruling that the provider example sets the grammar
  (an R5 exception), or one issuance.

## Structure-only issuance check

Run one Slack custom-function step (a Bolt `function_executed` handler or a
Deno workflow app) and log only the shape of `bot_access_token`: number of
`-` sections, width of each digit section, whether the last section is
exactly 32 `[0-9a-f]`, whether any `_` or uppercase appears.
`rawValueRetained: false`. The token revokes itself within 15 minutes.

## Residual risk

Low: tokens are short-lived and appear mainly in logs and payload dumps, and
the interim guard already redacts every shape seen.
