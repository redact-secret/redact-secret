# Issue #660 — T1 provider evidence for `telegram:bot-token`

[Audit archive](../../README.md) ·
[Issue #660](https://github.com/redact-secret/redact-secret/issues/660) ·
[Epic A #575](https://github.com/redact-secret/redact-secret/issues/575) ·
[Second-pass research](https://github.com/redact-secret/redact-secret/issues/660#issuecomment-5784935602) ·
[Broad-discovery pass](https://github.com/redact-secret/redact-secret/issues/660#issuecomment-5785519823) ·
[Telegram contract freeze](../../../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md)

Written 2026-09-23 on branch `milocosmopolitan/beta7-research`. The two
iterative passes stay in the linked issue comments and are not restated here.

## Verdict: NOT FOUND — EXHAUSTIVE as of 2026-09-23

No provider-domain source states a grammar for the Telegram bot token. Every
source class in the issue's "Done when" was checked (2026-09-22) and the
load-bearing pages were re-fetched 2026-09-23. Telegram's own domain gives only
example tokens introduced as "looks something like". The TDLib maintainer has
said on the provider's GitHub repo that the format is not guaranteed.

| property | provable at T1 | basis |
| --- | --- | --- |
| delimiter `:` | no | present in every provider example; no prose states it |
| numeric ID part (the bot's user ID) | no | examples only; ID bounds (> 0, < 2^54, no leading `0`) exist only in provider-authored server code on github.com |
| body length | no | all three provider examples have 34 chars; tools and community say 35; nothing provider-stated |
| body alphabet | no | examples use `[A-Za-z0-9-]`; `_` is tool/community only |
| body lead `AA` | no | two realistic provider examples start `AA`; no source states or explains it |
| total length | no | ≤ 80 in provider server code only |
| marker / checksum | no | none documented anywhere |

## The source

No source meets the bar. The closest provider-domain text, re-fetched
2026-09-23 (HTTP 200 each):

- `https://core.telegram.org/bots/api` ("Authorizing your bot"):
  > The token looks something like 123456:ABC-…

  One synthetic example: 6-digit ID, `:`, 34-char body containing `-`.
- `https://core.telegram.org/bots/features`:
  > The token is a string, like 110201543:AAH…

  9-digit ID, 34-char body starting `AA`.
- `https://core.telegram.org/bots/tutorial`:
  > Your token will look something like this: 4839574812:AAF…

  10-digit ID, 34-char body starting `AA`.

Strongest candidate below the bar: `tdlib/telegram-bot-api`
`telegram-bot-api/ClientManager.cpp` L74–84 at `e3e9dd8e5b3d7ab8537cd5a10dc31d5ffa8f82d1`
(still HEAD of `master`, re-read 2026-09-23). It rejects a token whose first
character is `0`, that is longer than 80, that contains `/`, or that lacks `:`.
It also rejects a token whose part before the first `:` does not parse as an
integer in (0, 2^54). It does not check the body. This is server acceptance
code on github.com, not documentation on Telegram's domain, so it is
corroboration only.

The provider's own disclaimer, new in this pass: in
[tdlib/telegram-bot-api#300](https://github.com/tdlib/telegram-bot-api/issues/300)
("Clarification on characters used in a Bot Token", 2022-07-24), the question
asked whether the body is a fixed 35 characters and which characters it can
use. `levlam`, the repository's principal committer (954 of its commits),
[answered](https://github.com/tdlib/telegram-bot-api/issues/300#issuecomment-1193267394):

> Everything can completely change in the future. There is no way to do a future-proof token validation.

He pointed to the same `ClientManager.cpp` check, adding that it "may change
any time without notice". `observedAt` 2026-09-23. This is provider staff on
github.com, not provider-domain documentation, so it does not meet the bar
either. It does indicate that Telegram deliberately publishes no format.

## Proposed `covers` sentence

None. No provider-domain source establishes an identifying element. The family
stays out of the T1 re-tier batch unless the maintainer sets a new precedent
that accepts provider-authored code as T1 evidence. That would be a new ADR,
not a spec row.

## Contradictions with the current contract

Contract pattern (from the issue's measurement at redact-secret-benchmarks
`30967da`): `^[0-9]{5,}:[A-Za-z0-9_-]{34,}$`. The product detector
`crates/secret-scan-core/src/detectors/telegram.rs` implements the same
grammar (`MIN_ID_LEN = 5`, `MIN_SECRET_LEN = 34`, maximal runs,
`[A-Za-z0-9_-]` body). The family has no entry in
`docs/contracts/precision/precision-contracts.json`. The spec row is
`docs/specs/detector-families.md` L78/L100.

- **No contradiction with the provider.** All three provider examples match
  the pattern.
- **Body length.** Tools and community sources say 35 and the provider
  examples show 34. `{34,}` accepts both, but with no upper bound. The
  provider's server caps the whole token at 80.
- **ID part.** `[0-9]{5,}` allows a leading `0` and more than 16 digits. The
  provider's server rejects both. The contract's minimum of 5 is project
  policy, since the server accepts 1–16 digits.
- **`AA` lead.** Most scanners key on it. The contract does not, and no
  provider source supports adding it.
- **Detector doc comment.** It says the docs give "exactly one example token".
  Telegram's domain actually has three (api, features, tutorial), all 34-char
  bodies, so the grammar is unaffected. The comment is stale and is recorded
  here, not fixed.
- **Separate credential.** `core.telegram.org/bots/serverless` states "The
  token has the form app<id>:<secret>" for the Serverless CLI token, which the
  page itself says is separate from the bot token. The `^[0-9]` pattern does
  not match it. It is a possible future family, not in scope here.

## Sources checked

Every class required by the issue was checked on 2026-09-22 (full URL-level
table in the [second-pass comment](https://github.com/redact-secret/redact-secret/issues/660#issuecomment-5784935602)).
The pages below were re-fetched 2026-09-23.

| source class | result |
| --- | --- |
| product docs and API reference (incl. schemas the docs load) | `/bots/api`, `/bots/features`, `/bots/tutorial` re-fetched 2026-09-23: examples only, no grammar. MTProto `/api`, `/api/bots`, `auth.importBotAuthorization`, `/schema` (TL schema, Telegram's JSON/OpenAPI equivalent): token typed `string`. No OpenAPI published by `tdlib`/`TelegramMessenger`. |
| changelog / release notes | `/bots/api-changelog` re-fetched 2026-09-23: the only bot-token mention is Mini App validation "without knowing the App's bot token". No format. |
| engineering / security blog | `telegram.org/blog` index and bot posts (2026-09-22): no token-format post. A broad web search on 2026-09-23 found none either. |
| secret-scanning partner pages | GitHub supported-patterns page re-fetched 2026-09-23: `telegram_bot_token`, `isPublic: false`, GHAS-only, no pattern, not on the provider's domain. No Telegram token-format announcement found. |
| SDK / CLI docs on provider domain | `core.telegram.org/tdlib` `checkAuthenticationBotToken`: `token:string`. `/bots/serverless`: separate `app<id>:<secret>` CLI token. Provider repos `tdlib/td` (opaque string) and `tdlib/telegram-bot-api` (acceptance check plus #300 disclaimer) are corroboration only. |

Broad discovery (2026-09-22/23, below the bar, not counted): Stack Overflow
61868770 (35-char body, 8–10-digit ID), trufflehog, detect-secrets, gitleaks,
betterleaks, Nosey Parker, Semgrep, secrets-patterns-db, GitGuardian
("Prefixed: True"), aiogram and pyTelegramBotAPI validators, plus several
third-party blog guides that repeat the 35-char claim. Details are in the
[broad-discovery comment](https://github.com/redact-secret/redact-secret/issues/660#issuecomment-5785519823).

Not read: Reddit. It returned 403 on 2026-09-23, and `site:reddit.com` search
returned no Reddit results. It is recorded as unchecked. Reddit is not a
required class and cannot meet the T1 bar, so the verdict is unaffected.

## Open items

- **Precedent question for the maintainer.** Should provider-authored code
  linked from the provider's domain count as T1? If it does, it would prove the
  `:` delimiter, a numeric ID with no leading `0` below 2^54, and a total
  length of at most 80, but still nothing about the body. The #300 disclaimer
  weighs against it.
- **Empirical check (34 vs 35, `AA` lead).** This needs one freshly issued
  token, per the steps in the
  [broad-discovery comment](https://github.com/redact-secret/redact-secret/issues/660#issuecomment-5785519823).
  Record counts only and revoke afterwards. It can corroborate but cannot
  create T1.
- **Twin pairs.** 0 < 5. This is independent of this research.

## What this document does not do

It changes no detector, contract, fixture, spec, or tier.
`docs/contracts/precision/precision-contracts.json` and `telegram.rs` are
untouched, including the stale doc comment. It contains no credential. Every
example token is described by structure only, and the quotes are truncated
before each body.

## Authority

This document records evidence. It does not select a version, create a tag,
publish a package, or authorize any release operation.
