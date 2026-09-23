# Issue #642 — T1 provider sources for eight existing families

[Audit archive](../../README.md) ·
[Issue #642](https://github.com/redact-secret/redact-secret/issues/642) ·
[Epic A #575](https://github.com/redact-secret/redact-secret/issues/575) ·
[Benchmarks counterpart redact-secret-benchmarks#112](https://github.com/redact-secret/redact-secret-benchmarks/issues/112) ·
[Contract freeze (#370)](../../../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) ·
[Spec: detector families](../../../specs/detector-families.md)

Written 2026-09-23 on branch `chore/beta7-research`. This record covers the
product-repository half of #642 only. The issue had no comments when this
was written, so the issue body is the only earlier record.

## Verdict: FOUND for all eight identifying prefixes. The issue's "Done when" is not met

Every provider-domain quote in the issue table was re-fetched live on
2026-09-23 (between 19:50 and 20:00 UTC) and matched in the page text. Each one
still establishes what the issue says it does. Two URLs now redirect, and one
page has new content that bears on the google `AQ.` question (see below).

| family | detector | provider-stated at T1 | tool-corroborated only | product detector vs documented prefix |
| --- | --- | --- | --- | --- |
| `anthropic:secret-api-key` | `anthropic-token` | prefix `sk-ant-api03-` (Claude API key) | body length, alphabet, terminator | match |
| `linear:personal-api-key` | `linear-token` | prefix `lin_api_` (and `lin_oauth_` exists) | 40-char alphanumeric body | match |
| `notion:legacy-integration-token` | `notion-token` | prefix `secret_` (legacy, still valid); `ntn_` successor | 43-char alphanumeric body | match |
| `new-relic:user-api-key` | `new-relic-user-api-key` | prefix `NRAK-`, qualified by "Most" | 27-char uppercase-alphanumeric body | match (qualifier not modelled) |
| `grafana:cloud-access-policy-token` | `grafana-cloud-access-policy-token` | prefix `glc_` | base64 alphabet, 32-char floor | match |
| `grafana:service-account-token` | `grafana-service-account-token` | prefix `glsa`; a checksum exists | `_` separators, 32-char body, 8-hex checksum | match |
| `azure-devops:personal-access-token` | `azure-devops-personal-access-token` | 84 characters; `AZDO` marker position; `[A-Za-z0-9]` alphabet (Purview) | nothing beyond the provider statements | match |
| `google:generic-api-key` | `google-api-key` | prefix `AIza`, from one example (39 characters) | body length and alphabet as a grammar | match |

"match" means the product detector's literal prefix (or azure-devops's marker
and length) is exactly the provider-documented one. No mismatch was found, so
nothing needs to enter the promotion lifecycle from this check.

The issue's **Done when** requires one pinned `eval:classify` run (trufflehog
3.97.4, clean product and benchmarks mains) that reports all eight families as
`stable`. That depends on the contract edits, twin pairs and benign cases in
[redact-secret-benchmarks#112](https://github.com/redact-secret/redact-secret-benchmarks/issues/112),
which this repository cannot do. This record does not meet that condition. It
supplies the provider evidence the benchmark contracts will cite.

## Per-family sources

The `observedAt` date is 2026-09-23 for every quote. Quotes are copied exactly
from the rendered page text. Full example values are not reproduced.

### anthropic — `sk-ant-api03-`

- **URL:** `https://platform.claude.com/docs/en/manage-claude/compliance-api-access`, the "Which key do you need?" table.
- **Quote:** "Claude API key ( `sk-ant-api03-...` ) Claude Console > Settings > API keys Calling Claude models through the Claude API"
- Sibling rows on the same page: "Compliance Access Key ( `sk-ant-api01-...` )" and "Admin API key ( `sk-ant-admin01-...` )". The "Check your key's scopes" section also reads the key type from the prefix: "`sk-ant-admin01-` is an Admin API key … `sk-ant-api01-` is a Compliance Access Key".
- **Product detector:** `crates/secret-scan-core/src/detectors/anthropic.rs` matches the single prefix `sk-ant-api03-` followed by at least 20 bytes of `[A-Za-z0-9_-]`. The prefix matches. `sk-ant-api01-` and `sk-ant-admin01-` are other key types, and the product does not detect them. They are prefix-twin candidates for the benchmark, not coverage gaps in this family.
- **Difference from the proposed `covers`:** the issue's `covers` names a 93-character body and a trailing `AA`, both tool-corroborated. The product detector enforces neither; it takes an open floor of 20. `docs/contracts/precision/precision-contracts.json` has no `anthropic-token` entry. A benchmark contract that states `{93}AA` would be stricter than the product grammar. That is not a leak risk, because the product matches a superset, but the `covers` text should say the length and terminator are the benchmark contract's tool-corroborated grammar, not the product's.

### linear — `lin_api_`

- **URL:** `https://linear.app/changelog/2021-08-19-github-secret-scanning` (entry dated 2021-08-19 by its URL).
- **Quote:** "We recently changed the format of our API keys and OAuth access tokens to include Linear specific prefixes, lin_api_ and lin_oauth_ , to enable GitHub to detect them similarly to their own tokens ."
- **Product detector:** `crates/secret-scan-core/src/detectors/linear.rs` (`LINEAR`), contract `linear-token` variant `api`: `lin_api_[A-Za-z0-9]{40}` (T2). The prefix matches.
- **Contract note:** the `api` variant's prefix segment basis reads "tool-agreement; existence of the type corroborated by github-secret-scanning-patterns". This changelog is not among its `sources`. The `oauth` variant's basis says "no consulted provider or tool source shows this prefix", but this changelog names `lin_oauth_` on the provider's domain. It establishes that the prefix exists, not a grammar, so the `lin_oauth_` interim guard (T0, open 20-byte floor) is unaffected. Both notes are for the contract owner. This record changes neither.

### notion — `secret_` (legacy)

- **URL:** `https://developers.notion.com/page/changelog`, entry "September 11, 2024".
- **Quote:** "Starting September 25, 2024, newly generated Public API tokens will automatically use the ntn_ prefix instead of the secret_ prefix."
- **Quote:** "All existing tokens with the secret_ prefix will continue to work without any changes."
- **Known contradiction, confirmed live:** "We strongly advise against using regular expressions (regex) to identify or validate Notion Public API tokens. The token format may change over time, and relying on regex patterns could lead to false positives or negatives."
- **Product detector:** `crates/secret-scan-core/src/detectors/notion.rs`, contract `notion-token` variants `legacy` `secret_[A-Za-z0-9]{43}` and `current` `ntn_[0-9]{11}[A-Za-z0-9]{35}` (both T2). Both prefixes match. The provider's "format may change" statement should be recorded in the contract's `review` field, the same way vault's "opaque" statement was recorded. It covers the bodies. It does not cover the documented prefixes.

### new-relic user — `NRAK-`

- **URL:** `https://docs.newrelic.com/docs/more-integrations/terraform/terraform-intro`. It now **redirects** to `https://docs.newrelic.com/docs/infrastructure-as-code/terraform/terraform-intro/`, and the benchmark `providerSource.url` should use the final URL.
- **Quote:** "Your New Relic user key . Most user keys begin with the prefix NRAK- ."
- The same page's provider block shows `api_key = "NRAK-***"`, a masked placeholder.
- **Known contradiction, confirmed live:** the qualifier "Most" is still there. `covers` must keep it. A User API Key that does not start with `NRAK-` is a false negative the provider documents as possible, and the product accepts that.
- **Product detector:** `crates/secret-scan-core/src/detectors/new_relic.rs`, `NRAK-` plus exactly 27 bytes of `[A-Z0-9]` (`is_upper_alnum`), with a repeated-character filler rejection. The prefix matches. The detector has no path for unprefixed user keys. No precision-contract entry exists; the grammar is frozen by the #370 ADR.

### grafana cloud access policy — `glc_`

- **URL:** `https://grafana.com/docs/grafana-cloud/machine-learning/ai-observability/get-started/grafana-cloud/`. It now **redirects** to `https://grafana.com/docs/grafana-cloud/observe-and-act/agent-observability/get-started/grafana-cloud/`, and the benchmark should use the final URL.
- **Quote:** "copy the token shown once. Tokens start with glc_… ."
- **Second URL:** `https://grafana.com/docs/learning-paths/private-data-source-connect/generate-token/` (no redirect).
- **Quote:** "Enter a token you have created in the past. The token name must begin with glc_ ."
- **Wording defect in the second source:** it says the token *name* must begin with `glc_`. From context it means the token value, but read literally it is about the name. Cite the first URL as the primary source and the second as corroboration.
- **Product detector:** `crates/secret-scan-core/src/detectors/additional_providers.rs` (`GRAFANA_CLOUD`), `glc_` plus at least 32 bytes of `[A-Za-z0-9+/]` (no `=`). The prefix matches. No precision-contract entry exists.

### grafana service account — `glsa`

- **URL:** `https://grafana.com/blog/new-in-grafana-9-1-service-accounts-are-now-ga/` (Grafana-authored; `datePublished` 2022-08-25 in the page metadata).
- **Quote:** "You'll be able to identify service account tokens in specific tokens with a "glsa" prefix. We've also added a checksum to the tokens for easier verification of token validity."
- The page uses typographic quotes, shown here as ASCII. The same paragraph adds "Despite having a shorter length, this key format has the same entropy as the previous key format" and gives no length.
- **Product detector:** `crates/secret-scan-core/src/detectors/grafana.rs`, exactly `glsa_` + 32 × `[A-Za-z0-9]` + `_` + 8 × `[0-9A-Fa-f]`. The prefix `glsa` matches. The provider source does not state the trailing `_` after `glsa`, the second `_`, either segment length, or the checksum's alphabet and position. All of those are tool-corroborated. No precision-contract entry exists.

### azure-devops — 84 characters, `AZDO` marker

- **URL:** `https://learn.microsoft.com/en-us/azure/devops/organizations/accounts/use-personal-access-tokens-to-authenticate#pat-format` (served with `?view=azure-devops`; `ms.date` 2026-09-21).
- **Quote:** "PATs are 84 characters long, including 52 randomized characters. Azure DevOps PATs contain the fixed AZDO signature at positions 76 through 80."
- **URL:** `https://learn.microsoft.com/en-us/purview/sit-defn-azure-devops-personal-access-token` (`ms.date` 2025-02-07, `updated_at` 2026-06-15).
- **Quote (detailed pattern):** "Any combination of 84 characters consisting of: a-z or A-Z (case-sensitive) or 0-9 with a fixed signature AZDO at position 76-80"
- **Known contradiction, confirmed live:** the same Purview page's `Format` line reads "A combination of 84 characters consisting of letters, digits, and special characters." Cite the detailed pattern, which is `[A-Za-z0-9]`. The page's own credential example is 84 characters, all alphanumeric, with `AZDO` at 0-based offset 76, followed by 4 characters. It agrees with the detailed pattern and disagrees with the `Format` line.
- **Two more wording points found on re-fetch:**
  - "positions 76 through 80" / "position 76-80" spans five positions for a four-character signature. The only reading consistent with the Purview example is 0-based, half-open `[76, 80)`, which is offsets 76–79 as the issue's `covers` states.
  - "including 52 randomized characters" means 32 of the 84 characters are not random. Neither page says which ones or what they contain. `covers` should claim length, marker position and alphabet only, not that the other 80 characters are uniform.
- **Product detector:** `crates/secret-scan-core/src/detectors/azure_devops.rs`, exactly 76 × `[A-Za-z0-9]` + `AZDO` + 4 × `[A-Za-z0-9]`, bounded by non-alphanumerics. It matches the provider statements. No precision-contract entry exists.

#### Conformance fixture coverage (`conformance/fixtures/synchronous-corpus.json`)

13 fixtures reference the detector. Structure only (run lengths in bytes before and after `AZDO`):

| fixture id | before / after / total | expected |
| --- | --- | --- |
| `azdo-pat-positive-bare` | 76 / 4 / 84 | one 84-byte finding |
| `azdo-pat-overlap-generic-context` | 76 / 4 / 84 | one 84-byte finding (wins over generic) |
| `azdo-pat-adversarial-long-padding` | 76 / 4 / 84, then a 40 000-byte run of repeated near-miss anchors | one 84-byte finding |
| `azdo-pat-boundary-prefix-below-required` | 75 / 4 / 83 | none |
| `azdo-pat-boundary-prefix-above-required` | 77 / 4 / 85 | none |
| `azdo-pat-boundary-suffix-below-required` | 76 / 3 / 83 | none |
| `azdo-pat-boundary-suffix-above-required` | 76 / 5 / 85 | none |
| `azdo-pat-boundary-short-prefix` | 0 / 4 / 8 | none |
| `azdo-pat-boundary-broken-prefix` | non-alphanumeric byte inside the 76-byte run | none |
| `azdo-pat-negative-placeholder` | 76 / 0 (non-alphanumeric suffix) | none |
| `azdo-pat-negative-legacy-unmarked`, `…-in-context` | 52-byte legacy shape, no `AZDO` | none |
| `azdo-pat-negative-lookalike` | bare word `AZDO` in prose | none |

**Result:** the 84-length boundary (83 and 85, on both sides of the marker) and
the marker-position boundary (offset 75 and 77) are covered. One gap remains:
no fixture keeps the total at 84 while moving the marker (for example 75 / 5 /
84). The detector rejects that case through the same exact-before-length rule
the 75 / 4 / 83 fixture already exercises, so it is a redundancy gap, not an
untested code path. No fixture was added.

### google — `AIza`

- **URL:** `https://docs.cloud.google.com/docs/authentication/api-keys` (page footer "Last updated 2026-09-22 UTC"). The contract source `google-cloud-api-key-docs` uses the older `cloud.google.com` host, and both hosts serve the same page.
- **Quote:** "The API key string is an encrypted string, for example, `AIza…`" (39 characters: `AIza` plus 35 characters from `[A-Za-z0-9_-]`; the example value is not reproduced here).
- **Known contradiction, confirmed live:** this is the only statement of the format, and it is one example. The page states no prefix rule ("prefix", "begins with" and "starts with" do not occur).
- **New on this page, relevant to the `AQ.` report:** the page now says "There are two types of API keys: standard API keys, and authorization keys", and "An authorization key authenticates as a service account." It gives no string format for authorization keys, and `AQ.` does not occur on the page. So the one `AIza` example sits in a generic "API key components" section, not under either type, and the provider documents the second key type without documenting its shape. That supports tracking `AQ.` as a separate coverage question, as the issue proposes. It does not confirm the `AQ.` prefix. The product detector comment in `additional_providers.rs` already treats the reported `AQ.` shape as an intentional false negative pending authoritative documentation.
- **Product detector:** `crates/secret-scan-core/src/detectors/additional_providers.rs` (`GOOGLE`), contract `google-api-key` variant `api-key`: `AIza[A-Za-z0-9_-]{35}` (T2). The prefix and the example's length both match.

## Sources checked

| family | provider-domain source (re-fetched 2026-09-23) | HTTP | quote found |
| --- | --- | --- | --- |
| anthropic | platform.claude.com compliance-api-access | 200 | yes |
| linear | linear.app changelog 2021-08-19 | 200 | yes |
| notion | developers.notion.com changelog | 200 | yes, including the "format may change" statement |
| new-relic | docs.newrelic.com terraform-intro | 200 after redirect | yes, "Most" |
| grafana glc | grafana.com agent-observability get-started | 200 after redirect | yes |
| grafana glc | grafana.com PDC learning path, generate-token | 200 | yes ("token name" wording) |
| grafana glsa | grafana.com blog, Grafana 9.1 service accounts GA | 200 | yes |
| azure-devops | learn.microsoft.com PAT article, `#pat-format` | 200 | yes |
| azure-devops | learn.microsoft.com Purview SIT definition | 200 | yes, both lines of the inconsistency |
| google | docs.cloud.google.com api-keys | 200 | yes; no `AQ.` |

For each family this pass re-verified the source the issue's 2026-09-22
research pass named. No broad re-discovery was run: the issue asks for the
quotes to be re-fetched and contradictions settled, not for a new search, and
every family already had a provider-domain source.

## Open items

- **Done when (not met here):** the benchmark contract edits, twin pairs ≥ 5,
  benign cases and axes in redact-secret-benchmarks#112, then a single pinned
  `eval:classify` run (trufflehog 3.97.4, clean mains) that reports all eight
  families `stable` with no regression among the current 33 and a T1/T2 leaked
  span rate of 0. The run identity belongs in an addendum to this record once
  it exists.
- **Benchmark URLs:** use the post-redirect URLs for new-relic and grafana glc.
- **anthropic `covers`:** state that the 93-character body and `AA` terminator
  are tool-corroborated benchmark grammar. The product matches an open
  `{20,}` floor.
- **Contract hygiene (owner's call):** `linear-token` could add the linear
  changelog as a provider source for the `lin_api_` prefix. The `oauth`
  variant's "no consulted source shows this prefix" is contradicted by that
  changelog for the prefix's existence, though not for its grammar.
- **azure-devops fixture:** an optional 84-total marker-shift fixture
  (75 / 5 / 84), described above.
- **google `AQ.`:** track separately. The provider now documents "authorization
  keys" but gives no string format for them.

## What this document does not do

It changes no detector, contract, fixture, or tier. `docs/contracts/precision/precision-contracts.json`
and `crates/secret-scan-core/src/detectors/` are untouched. The only other
change for #642 in this repository is the Governing ADR cell of the eight rows
in `docs/specs/detector-families.md`, which links here. The row set and the
first three columns stay generated from the inventory. This document contains
no credential and no full example token value.

## Authority

This document records evidence. It does not select a version, create a tag,
publish a package, or authorize any release operation.
