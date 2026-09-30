# #1012 research: `convex:deployment-key`, cloud `eyJ2` body (re-research of an #860 gated shape)

[Research index](README.md) ·
[Issue #1012](https://github.com/redact-secret/redact-secret/issues/1012) ·
[#860 issuance research, 2026-09-28](../860/issuance-research/convex.md) ·
[Handoff](../860/convex.md)

Frozen 2026-09-29. Desk research only: no key was issued, and no issued or
leaked credential is evidence. Sources were accessed on 2026-09-29. The
hex-body keys are already implemented (#912); this covers only the cloud
body.

**Gated property (unchanged):** the length and Base64 flavour of the body
after `<type>:<name>|`, and whether scope changes the length.

**Verdict: BLOCKED.** Nothing new states a length or alphabet.

## Sources re-checked

| # | Source | Date | Class | Ruling | Statement |
|---|---|---|---|---|---|
| 1 | get-convex/convex-backend at [aad76a4](https://github.com/get-convex/convex-backend/tree/aad76a42acb778bace620899562a866737bcc7e5), `deploy-key-types.mdx` L64, L76, L110, L122 | last changed 2026-07-01 | provider docs | R4 | truncated examples `eyJ2...` ending `0=` only |
| 2 | [convex-backend commit 64b4981](https://github.com/get-convex/convex-backend/commit/64b4981a6373de629dcecb0f8def64835dff6cab) ("Show new deploy keys in a modal") | 2026-09-29 | provider dashboard code | none | shows the new key verbatim; no format |
| 3 | `envvars.ts`, `application_auth.rs`, the OpenAPI `SerializedAccessToken` text | last changed 2026-04-16, 2026-05-30, unchanged | provider code and schema | as recorded | unchanged since the prior record |

Searched, nothing further: the dashboard and CLI (no length checks); gitleaks,
betterleaks, trufflehog, Kingfisher, noseyparker (no Convex rule; issue
search empty); code search for `eyJ2` with `CONVEX_DEPLOY_KEY` (docs copies
and user repositories only; the latter are leaks and not evidence).

## Exact missing evidence

Unchanged: the body length, the Base64 flavour (standard or URL-safe), the
count of trailing `=`, and whether scope changes the length.

## Structure-only issuance check

The handoff's checklist items 2, 4, 5 and 6: issue one production and one
preview deploy key; record body length, alphabet classes (`+`, `/`, `-`,
`_`), trailing `=` count, and whether the two lengths differ.
`rawValueRetained: false`, then revoke.

## Residual risk

Unchanged: cloud deploy keys are redacted today only in named and header
contexts.
