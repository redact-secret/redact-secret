# Issue #646 — T1 provider evidence for `discord:bot-token`

[Audit archive](../../README.md) ·
[Issue #646](https://github.com/redact-secret/redact-secret/issues/646) ·
[Epic A #575](https://github.com/redact-secret/redact-secret/issues/575) ·
[Research pass 2](https://github.com/redact-secret/redact-secret/issues/646#issuecomment-5784912533) ·
[Broad-discovery pass](https://github.com/redact-secret/redact-secret/issues/646#issuecomment-5785350964) ·
[Web-search pass](https://github.com/redact-secret/redact-secret/issues/646#issuecomment-5786037348) ·
[False-negative note](https://github.com/redact-secret/redact-secret/issues/646#issuecomment-5786154082) ·
[Discord grammar freeze (#301)](../../../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) ·
[Detector fix #670](https://github.com/redact-secret/redact-secret/issues/670)

Written 2026-09-23 on branch `milocosmopolitan/beta7-research`. The three
iterative passes stay in the linked issue comments and are not restated here.

## Verdict: NOT FOUND — EXHAUSTIVE as of 2026-09-23

No Discord-owned page, OpenAPI spec or provider-authored docs source states a
grammar for bot tokens. Discord gives no prefix, segment count, encoding,
length or alphabet. The only lexical evidence on a provider domain is one
example header value in the API reference. An example is not a grammar.

| property | provable at T1 | basis |
| --- | --- | --- |
| prefix / fixed marker | no | none exists; `Bot` is the `Authorization` scheme word, context not token |
| three `.`-separated segments | no | provider example only (one value, legacy shape); no prose |
| segment 1 = base64url of decimal snowflake ID | no | derivable from the provider example; stated only by community sources |
| segment lengths (24 or 26 / 6 / 27 or 38) | no | provider example shows 24/6/27; 38 and 26 come from dated empirical reports and tool regexes |
| alphabet `[A-Za-z0-9_-]`, no padding | no | consistent with the example and every tool; never provider-stated |
| checksum / terminator | no | none documented anywhere (segment 3 is described as an HMAC by community sources only) |

## The source (nearest miss, does not meet the bar)

`https://docs.discord.com/developers/reference`, section Authentication.
Re-fetched 2026-09-23:

> "Using a bot token found on the Bot page within your app's settings."

followed by the heading **"Example Bot Token Authorization Header"** and one
example value. Measured 2026-09-23 from the provider-authored source
`discord/discord-api-docs` `developers/reference.mdx` L122 at `0eb8102`
(repo HEAD on 2026-09-23, unchanged since pass 2): three segments of 24, 6
and 27 characters, all `[A-Za-z0-9_-]`; segment 1 base64url-decodes to an
18-digit decimal ID. The value is not reproduced. `observedAt`: 2026-09-23
(first observed 2026-09-22).

Provider-authored OpenAPI, `discord/discord-api-spec` `specs/openapi.json` at
`bb8eb1e` (HEAD on 2026-09-23): `components.securitySchemes.BotToken` is
`{"type":"apiKey","description":"Discord bot token","name":"Authorization","in":"header"}`,
with no pattern or length.

This does not meet the T1 bar in `benchmarks/lib/assessment.ts`: there is no
provider-stated identifying element (prefix, namespace or stated structure).
The bar is unchanged.

## Proposed `covers` sentence

None. The family stays T2. If a later source is found, the sentence must say
which properties the provider states; today none are.

## Contradictions with the current contract

The contract quoted in the issue body
(`^[A-Za-z0-9_-]{24}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27}$`) is superseded:

- **Product detector.** `crates/secret-scan-core/src/detectors/discord.rs`
  (commit `f887153`, #670, on `main`) accepts 24/6/27, 24/6/38 and 26/6/38,
  and requires segment 1 to decode to ASCII digits.
- **Benchmarks contract.** `redact-secret-benchmarks`
  `benchmarks/lib/assessment.ts` L83 at `origin/main` `f57e895` (changed in
  `c301536`, 2026-09-22, benchmarks#159) is the same three-shape alternation
  plus the digit-decoding `validate`, still `tier: 'T2'`.

No provider source contradicts either one. The only provider example (24/6/27)
matches the legacy branch. Neither the provider nor either pinned scanner
supports the 38-character third segment and the 26-character first segment;
the contract records both as prose-only (tool regexes and dated empirical
reports, see the web-search pass). The spec row in
`docs/specs/detector-families.md` still cites the 2026-09-17 freeze record,
not a provider source.

Twin properties: no provider text makes prefix, length, alphabet, delimiter
or marker provable. The example supports a structural sanity check only.

## Sources checked

Every class required by the issue was checked on 2026-09-22 (pass 2 has the
full URL-level table). The load-bearing sources were re-fetched on 2026-09-23,
and a fresh broad search was run that day.

| source class | result |
| --- | --- |
| product docs and API reference (incl. OpenAPI) | reference: usage prose + one example (re-fetched 2026-09-23); `topics/oauth2`, `platform/oauth2-and-permissions`, `quick-start/getting-started`, `bots/overview` (new 2026-09-23): usage or reset steps only; whole-repo grep of `discord-api-docs`: no format wording; `discord-api-spec` `BotToken`: no pattern (re-read 2026-09-23) |
| changelog / release notes | `docs.discord.com/developers/change-log` (+ `change-log.mdx` at `0eb8102`, re-grepped 2026-09-23): bot-token mentions concern usage (Achievements, emoji, Social SDK), none concern format |
| engineering / security blog | `discord.com/blog/security-discord-and-you`, `discord.com/category/engineering` (82 posts), `site:discord.com/blog` searches: no token-format post |
| secret-scanning partner pages | GitHub supported-patterns page (re-fetched 2026-09-23): Discord Bot Token, `discord_bot_token`, partner, push protection, validity check; no regex or format; not on the provider's domain. GitHub changelog 2023-10-13 (validity checks): no format. No Discord token-format announcement found |
| SDK / CLI docs on provider domain | `discord.com/developers/docs/social-sdk/authentication.html`: token types and lifetimes only; Social SDK Bot Token Endpoint guide (new 2026-09-23): placeholder `Bot <BOT_TOKEN>` only; `discord/embedded-app-sdk`, `discord/discord-example-app`: placeholders |
| provider support docs (extra) | support-dev.discord.com (42 results) and support.discord.com (top 25 of 427) for "bot token": no format wording |

Community, tool and empirical sources (gist, Stack Overflow, detect-secrets,
gitleaks, trufflehog, Discord.Net, Oxide, and others) are tabulated with
classes in the broad-discovery and web-search passes. They are corroboration
only and cannot meet the T1 bar.

Not read, recorded as unchecked: Reddit (blocked; Google snippets only),
umod.org (Cloudflare check), one Medium post (403), the screenshot in
`discord/discord-api-docs#5009` from an org MEMBER, and the Discord
Developers server (not web-indexed). None is on a provider documentation
domain except the #5009 screenshot, and a GitHub issue reply is not provider
documentation. None of them changes the verdict.

## Open items

- The empirical check in the
  [web-search pass](https://github.com/redact-secret/redact-secret/issues/646#issuecomment-5786037348)
  (one freshly issued token: 26/6/38 for a new application, segment 1 decodes
  to the 19-digit application ID, no `=`) is still not done. It would firm up
  the T2 prose basis and would not make the family T1.
- `minimumTwinPairs: 0 < 5` is a separate `stable` gate and is out of scope here.

## What this document does not do

It changes no detector, contract, fixture or tier.
`docs/contracts/precision/precision-contracts.json` has no Discord entry and
is untouched. So is the benchmarks contract. The document contains no
credential and no full example token value.

## Authority

This document records evidence. It does not select a version, create a tag,
publish a package, or authorize any release operation.
