# Issue #582 — Beta.7 detector candidate ranking: provider-documentation and generic-overlap evidence

[Audit archive](../../README.md) ·
[Issue #582](https://github.com/redact-secret/redact-secret/issues/582) ·
[Epic #574](https://github.com/redact-secret/redact-secret/issues/574) ·
[Ranking comment](https://github.com/redact-secret/redact-secret/issues/582#issuecomment-5799683784)

Written 2026-09-23 on branch `workbench/582-rank-beta7-candidates`.

## Summary

The [ranking comment](https://github.com/redact-secret/redact-secret/issues/582#issuecomment-5799683784)
selected four committed and four stretch families after all eight (#308–#315)
had already shipped, and listed three acceptance criteria as unmet. This record
closes two of them with measurement and reports a third result that the ranking
did not anticipate. It does not change any score and ships no detector change.

| Unmet criterion | Result |
|---|---|
| Current provider documentation cited with `observedAt` for all eight | Fetched for the five T2 families; **the provider documentation is silent on credential format for all five**. It is cited below as "documentation does not state", not as support; see [Broad-discovery passes](#broad-discovery-passes-2026-09-23) for the wider search. |
| Existing generic detection measured | Measured; see [Generic detection](#generic-detection-measured-not-assumed). |
| A–C (exposure, impact, usage) are judgment | Unchanged. Nothing here measures them; the maintainer can still overrule. A [proposal](#score-review-proposal-not-applied) re-reads D consistently; it is not applied. |

## Provider documentation (observedAt 2026-09-23)

Every URL below was fetched on 2026-09-23. The fetch tool summarizes pages, so
quoted text is close to verbatim, not byte-exact. `Mailgun` help articles
returned 403 and were not read.

| Family | Page | What it states | What it does not state |
|---|---|---|---|
| Postman | [API authentication](https://learning.postman.com/docs/reference/postman-api/authentication) | Key is sent in the `X-API-Key` header; expiry is set in API key settings | prefix, length, alphabet, any example shape |
| Databricks | [PAT (AWS)](https://docs.databricks.com/aws/en/dev-tools/auth/pat), [PAT (Azure)](https://learn.microsoft.com/en-us/azure/databricks/dev-tools/auth/pat) | `DATABRICKS_TOKEN` env var, `token =` in `.databrickscfg`, `Authorization: Bearer <token>`; placeholders are `<token>`-style only | the `dapi` prefix, length, alphabet |
| Okta | [Create an API token](https://developer.okta.com/docs/guides/create-an-api-token/main/), [Management API overview](https://developer.okta.com/docs/api/openapi/okta-management/guides/overview) | `Authorization: SSWS <token>`; token shown once; grants the creating admin's permissions. One elided example begins `00` and contains a hyphen | total length, alphabet, that `00` is a prefix |
| Mailchimp | [Quick start](https://mailchimp.com/developer/marketing/guides/quick-start/), [About API keys](https://mailchimp.com/help/about-api-keys/) | Basic auth with any username; data-center (`usNN`) taken from the account URL; UI shows the key's first 4 characters | 32-hex body, hyphen, `-usNN` suffix inside the key; no example key |
| Mailgun | [Authentication](https://documentation.mailgun.com/docs/mailgun/api-reference/mg-auth), [HTTP signing key](https://documentation.mailgun.com/docs/mailgun/api-reference/send/mailgun/account-management/get-v5-accounts-http_signing_key), [Securing webhooks](https://documentation.mailgun.com/docs/mailgun/user-manual/webhooks/securing-webhooks) | Basic auth with user `api`; the only key-shaped example is the signing-key response, `key-` followed by 32 lowercase hex | any format rule for the primary API key; the public validation key's format (page unreadable) |

Consequences, stated without rescoring:

- Postman, Databricks, Okta, Mailchimp and Mailgun stay **T2**. Their grammars
  rest on non-provider evidence, and this check found no provider text to
  promote them.
- Of the four committed families only Netlify has a T1 provider source. The
  ranking comment scored Postman, Databricks and Okta D=3/3/2 while they have
  none; D was defined as prefix distinctiveness *and* T1 availability. That
  definition is worth a maintainer look before the committed/stretch line is
  treated as final. The line still sits between Okta (16) and Confluent (14).
- Mailgun's only documented `key-`+32-hex shape is the **webhook signing key**,
  not the API key, so the two share a shape.

## Public identifiers and confusable values (controls)

From the pages above; none is a credential.

- **Databricks:** workspace hostnames (`dbc-…`, `adb-…`), and the `token_id`
  returned beside `token_value`.
- **Mailchimp:** the `usNN` data-center label and the 4-character key preview.
- **Mailgun:** the public validation key (format unverified here) and the
  signing key that shares the `key-` shape.
- **Okta:** none named by the fetched pages.
- **Postman:** none named by the fetched pages; workspace/collection UIDs were
  not checked.

## Generic detection (measured, not assumed)

**Method.** A throwaway in-crate test called only `generic_token_detector()`
(not the full pipeline) on synthetic values shaped like each family, wrapped
four ways: bare, `NAME=value`, `Authorization: Bearer value`, and a JSON
member. Values were synthetic; high-entropy and low-entropy variants of each
shape were run. The harness was discarded, not committed. Positive controls (a
neutral 32-character value) and a name-only control were run alongside so that
empty results could be attributed.

**Results, nine shapes** (the eight families plus Heroku's bare UUID form):

| Wrapper | Generic detector result |
|---|---|
| `API_KEY=…`, `access_token=…`, `secret=…` and JSON members with those names | Matched all nine, full value span, `contextual_secret`, High confidence, Contextual specificity |
| Bare value, no name | No match |
| `Authorization: Bearer …` | No match from the generic detector (this is the bearer detector's job; it was not exercised here) |
| Provider-named variable (`POSTMAN_API_KEY=…`) with a neutral value | **No match** — the control shows the name, not the value, is what the generic detector does not recognize |

Reading: generic detection already redacts these shapes when the surrounding
name is a recognized generic one. What only the provider detectors add is
coverage of bare values, prose, logs and provider-named variables. That is the
exposure the families are being ranked for, so this supports valuing them by
runtime exposure rather than by whether *some* detector would catch a
`API_KEY=` line. It also means a provider-named env var (`POSTMAN_API_KEY=`)
is currently uncovered by generic detection and depends entirely on the
provider detector.

**Limits.** Full-pipeline overlap is measured in the next section. Tokens were synthetic and short of real distributions. Name
recognition was probed with three names plus per-family names, not the full
generic name list.

## Full-pipeline overlap (measured)

**Method.** The built CLI (`redact-secret`, check mode, metadata output only)
scanned synthetic values wrapped six ways: bare, `NAME=` with the provider's
own variable name, `Authorization: Bearer`, `Authorization: SSWS`, a
`postgres://user:<value>@host` connection-string password, and a prose
sentence. A neutral 32-character value under `API_KEY=` served as the control.
Heroku is excluded from the conclusions: its synthetic body may not match the
detector's exact width, so its zero findings cannot be attributed.

| Family | Bare / prose | `NAME=` (provider name) | Bearer / connection string |
|---|---|---|---|
| Postman, Netlify, Databricks, Confluent (prefix-anchored) | provider type, high, redact | provider type, high, redact | provider type wins over `bearer_token` / `connection_string_password` |
| Okta, Mailchimp, Mailgun (context-gated) | **no finding** | provider type, **medium, warn** | `bearer_token` / `connection_string_password`, high, redact (generic type) |
| Okta under `SSWS` | — | — | provider type, high, redact |
| Control (`API_KEY=`, neutral) | no finding | `generic-token`, high, redact | `bearer_token` / `connection_string_password` |

Reading: for the three context-gated families the provider detector's marginal
contribution over the generic layers is the provider-named assignment
(`OKTA_API_TOKEN=…`) and, for Okta, the `SSWS` scheme. Bearer and
connection-string positions are already redacted by the generic detectors, and
a bare or prose value is not found by anything. That assignment finding is
`medium`/`warn`, not `redact`. The four prefix-anchored families are the ones
that add coverage everywhere, including bare values.

## Related research in #575

Issues #643–#662 and #694 research T1 provider evidence for #575 families.
Two bear on this record; none changes a #582 score.

- **[#694 (`okta:api-token`)](https://github.com/redact-secret/redact-secret/issues/694)**
  ran a broad-discovery pass on 2026-09-23 that goes past the official pages
  fetched above. It agrees Okta's docs show only the `SSWS` scheme and an
  elided example. It adds a provider-staff forum statement (2023) that one
  "should not assume a set structure for Okta's API tokens", 47 of 52 public
  candidates at 42 characters with no `=`, and a gitleaks/trufflehog
  disagreement on whether `=` is allowed. Okta's committed slot in the ranking
  rests on the non-provider shape only, and the provider itself declines to
  guarantee it.
- **[#650 (`generic:bearer-token`)](https://github.com/redact-secret/redact-secret/issues/650)**
  and **[#651 (`generic:connection-string-password`)](https://github.com/redact-secret/redact-secret/issues/651)**
  record why those families cannot be T1: the RFCs define the position and
  character set, not the token. That matches the overlap result above, where
  both act as position-based nets rather than shape detectors.

## Broad-discovery passes (2026-09-23)

The provider-documentation table above came from official-domain pages only.
Four follow-up passes searched without domain limits (forums, staff answers,
GitHub issues and code, scanner rules, Hacker News, Stack Overflow where
reachable) and recorded every shape claim with a source class. They follow the
Okta pass in #694 and were posted on #582 because no per-family research issue
exists. Each carries a hands-on check list for issuing one real key.

| Family | Comment | Provider doc states shape? | Findings that bear on this record |
|---|---|---|---|
| Postman | [comment](https://github.com/redact-secret/redact-secret/issues/582#issuecomment-5800541433) | No | Every scanner that states a shape gives `PMAK-` + 24 hex + `-` + 34 hex; 31 of 33 public-code candidates match, none has a 35–36 second segment. One unsourced 2026-09-22 proposal says 34–36. A second credential (`PMAT-` + 26 uppercase alphanumerics, per GitLab's rules) is outside the repo grammar. |
| Databricks | [comment](https://github.com/redact-secret/redact-secret/issues/582#issuecomment-5800564692) | No | Tools agree on `dapi` + 32 lowercase hex. The optional `-<digit>` suffix rests on four tools only. Microsoft Purview's entity page allows `A-F`, where the repo treats uppercase as an intentional false negative. GitHub's partner list has 12 Databricks secret types; the family covers `dapi` only. |
| Mailchimp | [comment](https://github.com/redact-secret/redact-secret/issues/582#issuecomment-5800553901) | Example only, and it disagrees | The provider's worked example has a 31-character body; every tool, a 2009 staff regex and 111 of 115 measured candidates use 32. A 2009 staff post warns against regex validation because keys may change. Tools split on suffix digits, uppercase hex and keyword gating. |
| Mailgun | [comment](https://github.com/redact-secret/redact-secret/issues/582#issuecomment-5800612791) | No | Three sources describe the current private API key as a prefix-less 32-hex + 8-hex + 8-hex triplet, which the module doc and the matrix treat as an unsupported legacy signing key; the `key-` + 32 grammar may be the older shape. Mailgun issues several key types and the docs never say whether they share a shape. |

Across the four: no provider prose states a length or alphabet, so none moves
off T2. Uppercase hex is disputed in Databricks and Mailchimp against the
repo's lowercase-only grammar, and the suffix digit count is disputed in both.
Public-code counts are partial (GitHub rate limits) and unverified against the
providers; Reddit was blocked for all four. Okta's equivalent pass is in
[#694](https://github.com/redact-secret/redact-secret/issues/694), where a
provider-staff post says not to assume a set structure for its tokens.

## Score review (proposal, not applied)

The ranking comment defined D as prefix/grammar distinctiveness and whether a
T1 provider source exists, but applied it unevenly: Netlify (T1) got 3, while
Postman and Databricks got 3 with no provider source and Okta got 2. Applying
one reading to all eight, as lexical distinctiveness (0–2) plus provider
grounding (1 if a T1 source exists), moves four D scores. E and G are measured
and unchanged; A–C are judgment and unchanged.

| Family | D was | D proposed | Reason | Total was → proposed |
|---|---|---|---|---|
| Netlify | 3 | 3 | Distinctive prefix and a T1 source | 17 → 17 |
| Postman | 3 | 2 | Distinctive `PMAK-` structure, but no provider text; a second credential form is uncovered | 17 → 16 |
| Databricks | 3 | 2 | Four-character prefix, disputed suffix and case, no provider text | 17 → 16 |
| Okta | 2 | 1 | `00` alone is not distinctive (the detector is context-gated) and provider staff decline to guarantee a structure | 16 → 15 |
| Confluent | 2 | 2 | Unchanged: T1 for the new format, T2 for the legacy one | 14 → 14 |
| Mailchimp | 2 | 1 | Generic 32-hex body; the provider example disagrees with the grammar | 12 → 11 |
| Heroku | 1 | 1 | Unchanged | 12 → 12 |
| Mailgun | 1 | 1 | Unchanged, but the grammar may describe the older key shape | 10 → 10 |

Effect: the order of the committed four is unchanged, and Okta's margin over
Confluent narrows from 2 to 1. If the maintainer scores Okta's D at 0
because `00` is not a prefix, Okta and Confluent tie at 14 and the
committed/stretch line becomes a maintainer decision. Confluent has a T1 source
for its new format; Okta has none and a provider statement against relying on
its shape. This is a proposal from a single reader and changes no posted score.

## What this does not do

No detector, grammar, spec row or ledger is changed. The committed/stretch
selection in the ranking comment stands as recorded. Posting the result to #574
and closing or waiving the remaining criteria is left to the maintainer.
