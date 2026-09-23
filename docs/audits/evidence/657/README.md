# Issue #657 — T1 provider evidence for `openai:secret-api-key`

[Audit archive](../../README.md) ·
[Issue #657](https://github.com/redact-secret/redact-secret/issues/657) ·
[Epic A #575](https://github.com/redact-secret/redact-secret/issues/575) ·
[Broad-discovery pass](https://github.com/redact-secret/redact-secret/issues/657#issuecomment-5785523973) ·
[Research pass 2](https://github.com/redact-secret/redact-secret/issues/657#issuecomment-5785535862) ·
[Web-search pass](https://github.com/redact-secret/redact-secret/issues/657#issuecomment-5786012751) ·
[OpenAI contract freeze (#368)](../../../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md)

Written 2026-09-23 on branch `chore/beta7-research`. The three
iterative passes stay in the linked issue comments and are not restated here.

## Verdict: NOT FOUND — EXHAUSTIVE as of 2026-09-23

No page on an OpenAI domain states a prefix, length, alphabet or marker for
secret API keys as documentation. Every source class the issue's "Done when"
lists was checked. Two near-misses are recorded below for maintainer
decision. Neither is accepted here, because the T1 bar excludes community
forums and tool rules, and both near-misses fall into one of those classes.

| property | provable at T1 | basis |
| --- | --- | --- |
| prefix `sk-proj-` | no (near-miss A) | OpenAI-staff forum post on community.openai.com; forum class is excluded by the bar |
| prefix `sk-svcacct-` | no | provider code only (near-miss B); API reference service-account example shows a bare `sk-` placeholder |
| legacy prefix `sk-` | no | placeholders only (`sk-...`); staff post A says "the previous sk- keys" |
| marker `T3BlbkFJ` | no (near-miss B) | provider code calls it `credential_watermark`; no provider document names it |
| segment lengths (20/20 legacy; 74 or 58 namespaced) | no | gitleaks 8.30.1 only; community and public-code measurements corroborate 74/74 as current |
| body alphabet | no | tool rules and community reports only |
| checksum / terminator | no | none documented; trailing `A` in most public samples is an unconfirmed heuristic |

## The source

None meets the bar. The two candidates, re-fetched 2026-09-23:

**A. OpenAI staff post (provider domain, forum class).**
`https://community.openai.com/t/1118492/2`, posted 2025-02-12 by `romainhuet`.
The topic JSON returns `user_title: "OpenAI Staff"`, `primary_group_name: Staff_1`,
`staff: true`. `observedAt` 2026-09-23:

> "sk-proj- API keys are intended to work just like the previous sk- keys"

Establishes the `sk-proj-` prefix and that earlier keys were `sk-`. Nothing on
`sk-svcacct-`, the marker, length or alphabet.

**B. Provider-authored code (github.com, not an OpenAI domain).**
`https://github.com/openai/codex/blob/1bfd383890b1bd7fab0d1b3d5e05129a9e293d8a/codex-rs/network-proxy/src/credential_broker/providers/openai.rs#L13-L23`
(the file was last changed 2026-09-09). `observedAt` 2026-09-23:

> `credential_watermark: Some("T3BlbkFJ"),`

The same lines list the prefixes `sk-proj-`, `sk-svcacct-`, `sk-admin-` and
`sk-`, and set a minimum length of 51. It is a matching rule in OpenAI's own
code, not a document on the provider's domain. The bar says tool sources are
corroboration only.

Provider-domain statement relevant to width (`observedAt` 2026-09-23):
`https://developers.openai.com/api/reference/overview` lists as
backwards-compatible "Changing the length or format of opaque strings, like
resource identifiers". It does not name keys, but any fixed width is at risk.

## Proposed `covers` sentence

None. The family stays T2. If the maintainer accepts A or B as provider
evidence, the corresponding sentences are:

- A only: "An OpenAI staff post on community.openai.com establishes the
  `sk-proj-` prefix for project API keys; the `sk-svcacct-` prefix, the
  `T3BlbkFJ` marker, the segment lengths and the alphabet remain
  tool-corroborated."
- B: "OpenAI's own `openai/codex` credential broker names the `sk-proj-`,
  `sk-svcacct-` and `sk-` prefixes and the `T3BlbkFJ` watermark; segment
  lengths and alphabet remain tool-corroborated (gitleaks 8.30.1)."

## Contradictions with the current contract

Three different OpenAI shapes are in play in this repository, and they do
not agree with each other:

| where | namespaced widths | `sk-admin-` |
| --- | --- | --- |
| pattern quoted in the issue body (benchmarks contract) | 74 only | not matched |
| `docs/contracts/precision/precision-contracts.json` (`proj`, `svcacct` variants) | 74 or 58 | `pending`, T0 |
| `crates/secret-scan-core/src/detectors/openai.rs` (`NAMESPACED_PREFIXES`, `NAMESPACED_SEGMENT_LENS`) | 74 or 58 | accepted |

Against external sources:

- **Widths.** Current keys measure 74/74 (community reports of 164 and 167
  characters; revoked samples in gitleaks#1780). 58/58 is an Aug 2024
  generation, and 20/20 `sk-proj-` is an early-2024 generation. The 74-only
  benchmarks pattern misses 58/58. No contract shape covers 20/20 `sk-proj-`.
  No provider source settles any of this.
- **Admin keys.** Provider code B lists `sk-admin-` under the same provider.
  The detector already accepts it with 74/58 widths. Community and tool
  evidence says admin keys are 58/58 (133 characters). The precision
  contract records admin as pending.
- **Other prefixes.** `sk-None-` (user keys, Jul 2024) and
  `sk-service-<name>-` come from community and public-code sources only.
  Neither is in any contract.
- **Detector comments.** The detector's doc comment says the segments are
  "of a source-documented length" and speaks of the lengths "`OpenAI` has
  documented". OpenAI documents no length. The lengths come from gitleaks.

None of these are decided here.

## Sources checked

Required classes. URL-level detail is in the three linked comments.

| source class | result | observed |
| --- | --- | --- |
| product docs and API reference, including OpenAPI | help.openai.com "Where do I find my OpenAI API Key?", "Best Practices for API Key Safety", "Managing projects in the API platform" (browser): no format. platform.openai.com auth and project-api-keys redirect to developers.openai.com: no format. developers.openai.com `llms-full.txt` exports (root, api, cookbook, blog, codex, learn; about 17 MB re-fetched): zero `svcacct`, `T3BlbkFJ` or `sk-None`, and two `sk-proj-...` placeholders in the cookbook. API reference examples: `sk-abc...def`, `sk-admin-...`, a bare `sk-` service-account placeholder. `openai/openai-openapi`: bearer scheme, no pattern | 2026-09-22; exports and reference re-fetched 2026-09-23 |
| changelog / release notes | developers.openai.com changelog, deprecations, plugins changelog: key governance only, no format | 2026-09-22 |
| engineering / security blog | openai.com/index projects announcement (2024-04-23, browser): names service-account keys, no format. openai.com/news/rss.xml (1,225 items re-fetched): no `sk-proj`, `svcacct`, `T3BlbkFJ` or "key format". openai.com/security-and-privacy and openai.com/news/security (browser, first read this pass): no key format and no key-format post | 2026-09-22; RSS, security pages 2026-09-23 |
| secret-scanning partner pages | GitHub supported-patterns lists `openai_api_key` with "Token versions" and push protection, but no pattern, and the page is not on OpenAI's domain. No OpenAI token-format announcement found | re-fetched 2026-09-23 |
| SDK / CLI docs on the provider domain | developers.openai.com libraries and openai-cli docs: `sk-...` placeholders only. Provider SDK repos (openai-cli, openai-ruby, terraform-provider-openai): placeholders or test values | 2026-09-22 |

Also checked, but outside the bar: community.openai.com (source of near-miss A),
Stack Overflow, Hacker News, GitHub issues and code search, grep.app public-code
tabulation, and the rule files of eight scanners (gitleaks, TruffleHog, betterleaks,
secretlint, Semgrep, detect-secrets, Nosey Parker, GitGuardian).

Not read: Reddit threads. reddit.com is blocked to both the fetcher and the browser
extension, so only Google `site:reddit.com` snippets were seen. `trust.openai.com`
(403 to curl, not opened in the browser). Neither can meet the T1 bar, so the
verdict does not depend on them.

## Open items

- Maintainer decision: does a staff-flagged post on community.openai.com
  (A) or provider-authored code on github.com/openai (B) count as provider
  evidence? The issue body's bar says no to forums and tools. This document
  follows that.
- Reconcile the three shapes in the contradictions table (74 only, 74 or 58,
  and admin accepted or pending). This belongs to the contract owners, not
  the T1 re-tier.
- Empirical measurement of freshly issued keys. The steps are in the
  [web-search pass](https://github.com/redact-secret/redact-secret/issues/657#issuecomment-5786012751):
  a project key, two service-account keys with names of different lengths, a
  user key if the tab still exists, and optionally an admin key. Record counts
  only, then revoke each key. This settles current widths but cannot create T1
  evidence.

## What this document does not do

It changes no detector, contract, fixture, or tier.
`docs/contracts/precision/precision-contracts.json` and
`crates/secret-scan-core/src/detectors/openai.rs` are untouched. It contains
no credential and no full example token value. The only literal shown is
the public marker `T3BlbkFJ`.

## Authority

This document records evidence. It does not select a version, create a tag,
publish a package, or authorize any release operation.
