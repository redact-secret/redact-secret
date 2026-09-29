# #1012 research: `npm:legacy-token`

[Research index](README.md) ·
[Issue #1012](https://github.com/redact-secret/redact-secret/issues/1012)

Frozen 2026-09-29. Desk research only: no key was issued, and no issued or
leaked credential is evidence. Sources were accessed on 2026-09-29.

**Verdict: BLOCKED as a provider family; recommend closing it as not
attributable.** The grammar is T1 (a 36-character UUID), but a bare UUID
cannot be attributed to npm, and npm permanently revoked every classic token
on 2025-12-09, so no live legacy token can leak any more.

**Product finding instead:** the canonical `.npmrc` credential line
`//registry.npmjs.org/:_authToken=<value>` gives **no finding** on `main` for
a UUID value, and `_auth=<Base64>` gives none either. A current `npm_` token
on that line is caught by `npm-token`. The gap is contextual: the leading `_`
of `_authToken`, `_auth` and `_password` keeps `generic-token` from treating
them as credential names. It affects private-registry tokens of any shape.

## Current product behaviour

`npm-token` claims `npm_` + exactly 36 `[A-Za-z0-9]`. `NPM_TOKEN=<uuid>` and
`authToken=<uuid>` give `contextual_secret`, high. The support-matrix
reason: the legacy UUID shape "is not matched by the npm_-prefixed pattern".

## Sources

| # | Source | Date | Class | Ruling | Statement |
|---|---|---|---|---|---|
| 1 | [GitHub blog, "Announcing npm's new access token format"](https://github.blog/security/announcing-npms-new-access-token-format/) | 2021-09-23 | provider announcement | T1 (legacy shape) | "Previously, the npm access tokens were created as a UUID pattern of 36 characters." |
| 2 | [GitHub changelog, classic token creation disabled](https://github.blog/changelog/2025-11-05-npm-security-update-classic-token-creation-disabled-and-granular-token-changes/) | 2025-11-05 | provider changelog | T1 (lifecycle) | "New npm classic tokens can no longer be created through the npmjs.com website, CLI, or API." |
| 3 | [GitHub changelog, classic tokens revoked](https://github.blog/changelog/2025-12-09-npm-classic-tokens-revoked-session-based-auth-and-cli-token-management-now-available/) | 2025-12-09 | provider changelog | T1 (lifecycle) | "We've permanently revoked all existing npm classic tokens. They can no longer authenticate, be recreated, or be recovered." |
| 4 | [npm/redact `lib/matchers.js` L5-L27 @ df9d4da](https://github.com/npm/redact/blob/df9d4daa4d90432a471906761890c1ada661f349/lib/matchers.js#L5-L27) | 2024-04-03, touched 2025-04-21 | provider log redactor | T2 class | redacts every UUID, not only credentials, beside `npms?_` + 36–48 |
| 5 | [trufflehog `pkg/detectors/npmtoken/npmtoken.go` L28-L34 @ 48b58d3](https://github.com/trufflesecurity/trufflehog/blob/48b58d3bf3f02ba17bf23b87f095499bc80c6fd7/pkg/detectors/npmtoken/npmtoken.go#L28-L34) | 2022-10-13 | peer scanner rule | T2 | a UUID gated by the keyword `npm` |
| 6 | [Yelp/detect-secrets `detect_secrets/plugins/npm.py` L13-L17 @ 5e14193](https://github.com/Yelp/detect-secrets/blob/5e141933554a0b74e7341841f318be21e895339c/detect_secrets/plugins/npm.py#L13-L17) | 2022-05-24 | peer scanner rule | T2 | `//<host>/:_authToken=` followed by `npm_…` or a 36-character hex-and-dash value |
| 7 | [noseyparker `rules/npm.yml` L3-L26 @ 2e6e7f3](https://github.com/praetorian-inc/noseyparker/blob/2e6e7f36ce36619852532bbe698d8cb7a26d2da7/crates/noseyparker/data/default/builtin/rules/npm.yml#L3-L26) | 2023-01-27 | peer scanner rule (deliberate non-rule) | T2 | "There are also NPM Legacy Access Tokens, which appear to be non-prefixed v4 UUIDs. Matching these would require a pattern that uses heuristics against surrounding context." |

Searched, nothing further: gitleaks (`npm_` only); Kingfisher (rules no
longer in the repository at 7433793).

## Why not attributable

- Every UUID in text has the shape; npm's own redactor (#4) blanks all UUIDs
  as log hygiene, and noseyparker (#7) declines the shape.
- The only attributable form is the `.npmrc` line (#6), and there the host,
  not the shape, decides the issuer. Private registries (Artifactory, Nexus,
  Verdaccio, GitHub Packages) use the same key with their own formats.
- All classic npmjs.org tokens are revoked (#3) and cannot be recreated (#2);
  issuance is impossible.

## Recommended follow-up (product, contextual)

Treat the `.npmrc` keys `_authToken`, `:_authToken`, `_auth` and `_password`
as credential names in `generic-token`, reported as `contextual_secret`, not
`npm_access_token`. No UUID contract is needed. The FP/FN trade-off: `.npmrc`
lines with these keys are credentials by construction; `${NPM_TOKEN}`
substitutions must stay silent (the #993 placeholder rules already cover
`${…}`).

## Residual risk

Leaked legacy UUIDs are inert. Unfixed, the `.npmrc` gap leaves live
private-registry tokens in plaintext.
