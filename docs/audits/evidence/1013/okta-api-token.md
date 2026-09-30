# #1013 evidence: `okta:api-token`

[Index](README.md) ·
[Issue #1013](https://github.com/redact-secret/redact-secret/issues/1013) ·
[Spec: detector families](../../../specs/detector-families.md)

Frozen 2026-09-29. Desk research only: no token was issued, and no issued or
leaked credential is evidence. Shapes only.

**Contract under test (#315, context-gated):** `00` + 40
`[A-Za-z0-9_-]`, 42 in total, beside `SSWS` or a same-line `okta` keyword;
`=` is not admitted.

**Matrix blocker (pin at `b9e90915`):** 4 unresolved contradictions in the
[benchmarks ledger](https://github.com/redact-secret/redact-secret-benchmarks/blob/5380aa3a421555883225a62358fa40f81dcd2baa/benchmarks/support/empirical-observations.json).
The corroborated route itself already clears (6 references; peer rules and
provider examples).

**Verdict: READY-T2 once the four contradictions are recorded as proposed
below.** Three are boundable on existing evidence; one (the `_` question)
is best treated as bounded, with a settlement path. No issuance is required.

## New and re-read sources

All read 2026-09-29.

| # | Source | Date | Owner | Class | Statement (shape only) |
| --- | --- | --- | --- | --- | --- |
| 1 | [devforum.okta.com "API token length"](https://devforum.okta.com/t/api-token-length/5519) | 2019-07-01 | Okta (user `dragos`; staff status from a public profile snippet, not confirmed on the forum) | provider staff statement (R3 candidate) | "Yes, the API tokens are always 42 characters in length. You can use a regular expression like … `^00[a-zA-Z0-9\-\_]{40}$`". noseyparker cites this thread |
| 2 | [devforum.okta.com "Okta API token format"](https://devforum.okta.com/t/okta-api-token-format/25375) | 2023-09-21 | Okta staff (`dzeller`, "Okta team") and a customer | provider statement and customer observation | staff: "You should not assume a set structure for Okta's API tokens. We do not currently have plans on changing this but that is not to say that it will not change in the future." Customer: 42 characters of `[A-Za-z0-9-]`, then gives the regex `00[\w\d-]{40}` (which admits `_` through `\w`). Both 2023 ledger items come from this one thread |
| 3 | [okta/okta-developer-docs `create-an-api-token/main/index.md#L32`](https://github.com/okta/okta-developer-docs/blob/8aff3329cb8e651d2182ce6dcd5ebd303b42a690/packages/@okta/vuepress-site/docs/guides/create-an-api-token/main/index.md#L32) | present at the path's oldest commit, 2021-10-15 | Okta | provider-example | elided: `SSWS 00` + 14 characters (one `-`) + `...` + 12 characters (one `-`) |
| 4 | [okta-developer-docs `oie-upgrade-api-sdk-to-oie-sdk/main/index.md#L112`](https://github.com/okta/okta-developer-docs/blob/8aff3329cb8e651d2182ce6dcd5ebd303b42a690/packages/@okta/vuepress-site/docs/guides/oie-upgrade-api-sdk-to-oie-sdk/main/index.md#L112) (ledger, at `ae696b9f`) | — | Okta | provider-example | full length: `00` + 40 alphanumeric |
| 5 | [okta/okta-management-openapi-spec `management-dev-noEnums-minimal.yaml#L60548`](https://github.com/okta/okta-management-openapi-spec/blob/74fcd17fad54332caee96ebbb11fd7f203b03e4f/dist/current/management-dev-noEnums-minimal.yaml#L60548) | path history 2025-01-10 to 2026-03-23 | Okta | provider-example | `SSWS` + one full-length value, `00` + 40 alphanumeric, distinct from #4. **New** |
| 6 | [okta-developer-docs `books/api-security/api-keys/other-options/index.md#L18`](https://github.com/okta/okta-developer-docs/blob/8aff3329cb8e651d2182ce6dcd5ebd303b42a690/packages/@okta/vuepress-site/books/api-security/api-keys/other-options/index.md#L18) | 2019-02-14 | Okta | provider-example | "Okta (with tokens that look like this …)": a third distinct `00` + 40 alphanumeric value. **New** |
| 7 | [okta-developer-docs `reference/api/authn/index.md#L186`](https://github.com/okta/okta-developer-docs/blob/8aff3329cb8e651d2182ce6dcd5ebd303b42a690/packages/@okta/vuepress-site/docs/reference/api/authn/index.md#L186) (also L1083, L6604) | 2020-03 or earlier | Okta | provider-example of **sibling** tokens (session, state, recovery) | the same `00` + 40 layout, with `_` and `-` in the body: Okta's `00` tokens use `[A-Za-z0-9_-]` |
| 8 | gitleaks v8.30.1 `okta.go#L14` with helper [`patterns.go#L27-L28`](https://github.com/gitleaks/gitleaks/blob/83d9cd684c87d95d656c1458ef04895a7f1cbd8e/cmd/generate/config/utils/patterns.go#L27-L28) | 2024-10-22/25 (PR #1599) | gitleaks | peer-scanner-rule | `00[\w=\-]{40}`: the `=` comes from the generic `AlphaNumericExtended` helper, not from Okta evidence; PR #1599: "All the tokens I've found start with `00`" |
| 9 | trufflehog v3.97.4 `okta.go#L27`; noseyparker v0.24.0 `okta.yml` (ledger) | 2022-01-19; 2023-10-31 | Truffle Security; Praetorian | peer-scanner-rule | `\b00[a-zA-Z0-9_-]{40}\b`; `00` + 39 `[a-z0-9_-]` + a final non-`-` byte, "a 40-character base-62 payload" |
| 10 | GitGuardian `okta_token` detector page | "last updated Sep 25, 2026" | GitGuardian | peer metadata | `Prefixed: False` |

Searched: local clones of okta-developer-docs, the management OpenAPI spec,
okta-sdk-python, -golang, -java, -nodejs, -dotnet and -php,
terraform-provider-okta, okta-cli, okta-powershell-cli, okta-aws-cli and
okta-jwt-verifier-golang, grepping every `SSWS` value and every `00` + 40
value. Result: thousands of `{apiToken}` placeholders, exactly three
distinct full-length API-token examples (#4, #5, #6), all `00` + 40
alphanumeric; no SDK or Terraform code validates the shape; no Okta source
contains `=` in any `00` token.

## Contradictions: proposed dispositions

| # | Ledger statement | Proposed status | Bound or basis |
| --- | --- | --- | --- |
| 1 | gitleaks/betterleaks admit `=` | **bounded** | the `=` is a generic helper artefact (#8). No Okta API-token or sibling-token example contains `=`; the 2019 staff regex (#1), trufflehog and noseyparker exclude it. Bound: the contract excludes `=` and accepts a false negative if a padded token ever appears |
| 2 | Okta staff 2023: do not assume a set structure | **bounded** | the same post says there are no plans to change it; three dated provider examples (2019, 2021-era docs, 2025–2026 spec) all match `00` + 40. Bound: the contract freezes the currently issued shape and accepts false negatives on a future format change, with a re-review trigger on any new Okta statement. No source can settle a statement about possible future change |
| 3 | 2023 customer: alphabet without `_` | **bounded** (settleable by ruling) | the customer's own regex admits `_`; the 2019 staff regex admits `_`; Okta's sibling `00` tokens (#7) contain `_`. No API-token example contains `_`, so strictly nothing settles it. Bound: the detector admits `_` (the wider, false-positive-side choice); no fixture asserts either way on `_`. Settled instead if the maintainer accepts #1 (R3) with #7 as provider-example evidence |
| 4 | GitGuardian `Prefixed: False` vs silence on a `01…` twin | **bounded** | "Prefixed: False" classifies GitGuardian's detector (two characters are not a distinctive prefix); it does not show tokens starting otherwise. Every Okta example starts `00`. Bound: the contract excludes non-`00` shapes |

## Maintainer ruling (optional)

Q-OK: accept the four dispositions above, and optionally settle #3 by R3
(the 2019 staff regex) with the sibling-token examples.

## Optional issuance check

One token from Security > API > Tokens, structure only: total length 42;
starts `00`; whether it contains `_`, `-` or `=`. It confirms length and
prefix but closes contradiction 3 only if `_` happens to appear (about a
47% chance for a random 40-byte base64url body), and cannot close 1 or 2.
It is not required for READY-T2.
