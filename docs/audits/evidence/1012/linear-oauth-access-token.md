# #1012 research: `linear:oauth-access-token` (`lin_oauth_`)

[Research index](README.md) ·
[Issue #1012](https://github.com/redact-secret/redact-secret/issues/1012) ·
[#642 evidence (Linear prefixes)](../642/README.md)

Frozen 2026-09-29. Desk research only: no key was issued, and no issued or
leaked credential is evidence. Sources were accessed on 2026-09-29.

**Verdict: BLOCKED (body).** The `lin_oauth_` prefix is T1. No source of any
class states the body: no peer scanner has a rule, and Linear's own OAuth
page shows only **unprefixed** 64-character example tokens.

## Current product behaviour

`linear-token` (`crates/secret-scan-core/src/detectors/linear.rs`) keeps
`lin_oauth_` as an interim guard, capped per #551. The support-matrix reason:
the benchmarks classifier routes `lin_oauth_` values to "needs a separate
format contract".

## Sources

| # | Source | Date | Class | Ruling | Statement |
|---|---|---|---|---|---|
| 1 | [Linear changelog, GitHub secret scanning](https://linear.app/changelog/2021-08-19-github-secret-scanning) | 2021-08-19 | provider changelog | T1 (prefix) | "We recently changed the format of our API keys and OAuth access tokens to include Linear specific prefixes, lin_api_ and lin_oauth_" |
| 2 | [Linear developers, OAuth 2.0 authentication](https://linear.app/developers/oauth-2-0-authentication) | read 2026-09-29 | provider docs examples | R5 | three example tokens, all **unprefixed** and 64 characters: the authorization-code access token is lowercase hex; the refresh and client-credentials tokens are `[a-z0-9]`. No `lin_` string on this page or the actor-authorization, app-manifest, GraphQL and agents pages |
| 3 | [linear/linear-solutions `integration_guides/README.md` L11-L12 @ 4529f1e](https://github.com/linear/linear-solutions/blob/4529f1e807d19e25f3c3889737f5b4bf90c242fe/integration_guides/README.md#L11-L12) (new) | 2026-01-28 | provider docs placeholder | R4 (prefix) | "OAuth \| `lin_oauth_...`"; another guide in the same repo says the token "starts with `lin_oauth_` (not `lin_api_`)" |
| 4 | Third-party redactors (29 code-search hits) | 2026 | community guesses | none | lengths disagree: `{40}`, `{40,}`, `{32,}`, `{30,}` with `_-`, `{20,}`, `{10,}`; none cites a sample |
| 5 | [koki-develop/mask-go issue #147](https://github.com/koki-develop/mask-go/issues/147) | 2026-09-05 | independent research | summary | finds no source for the body and declines to ship a rule |

Searched, nothing further: gitleaks, betterleaks, trufflehog (`linearapi`
only), noseyparker, Kingfisher, CredSweeper, secretlint, osv-scalibr (no
`lin_oauth_` rule); `linear/linear` SDK monorepo at b37823b (no `lin_oauth`
or `lin_api` string); GitHub issue search (redaction threads only). GitHub's
pattern list has `linear_oauth_access_token` without a regex.

## Exact missing evidence

- The body length and alphabet after `lin_oauth_`. There is no source at all,
  not even a single peer rule.
- The contradiction between the prefixed format (#1, #3) and the unprefixed
  examples (#2) is unresolved; only a provider example of a prefixed token,
  or issuance, settles it.
- Untested hypothesis (not evidence): `lin_oauth_` + 64 lowercase hex, since
  the unprefixed authorization-code example is 64 hex.

## Structure-only issuance check

Create an OAuth app in a free workspace. Run the authorization-code flow once
and the `client_credentials` (actor=app) flow once. For each access token
record: whether it starts `lin_oauth_`, the body length, whether the body is
only `[0-9a-f]` (any uppercase, `_`, `-`?), and whether the refresh token
carries a prefix (which one). `rawValueRetained: false`, then revoke.

## Residual risk

The interim guard stays as is. Any rule written now would be a guess; the
third-party rules above show how far guesses spread.
