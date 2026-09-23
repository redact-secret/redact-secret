# Issue #645 — T1 provider evidence for `datadog:application-key`

[Audit archive](../../README.md) ·
[Issue #645](https://github.com/redact-secret/redact-secret/issues/645) ·
[Epic A #575](https://github.com/redact-secret/redact-secret/issues/575) ·
[Research pass 2](https://github.com/redact-secret/redact-secret/issues/645#issuecomment-5784933300) ·
[Broad-discovery pass](https://github.com/redact-secret/redact-secret/issues/645#issuecomment-5785357229) ·
[False-negative measurement](https://github.com/redact-secret/redact-secret/issues/645#issuecomment-5786154856) ·
[`ddapp_` coverage (#671)](https://github.com/redact-secret/redact-secret/issues/671) ·
[Datadog contract freeze (#370)](../../../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md)

Written 2026-09-23 on branch `milocosmopolitan/beta7-research`. The iterative
passes stay in the linked issue comments and are not restated here.

## Verdict: FOUND, for the identifying element of the current `ddapp_` generation only

A provider-domain source states the `ddapp_` prefix of current-format
Application keys. Nothing on the provider domain states the body length or
alphabet of that generation. The legacy bare-hex generation has no identifying
element on the provider domain; its length (40) is stated only in the OpenAPI
spec that Datadog's docs site serves.

| property | provable at T1 | basis |
| --- | --- | --- |
| prefix `ddapp_` (current generation) | yes | comparison table, docs.datadoghq.com |
| current body length (34; 40 total) | no | Datadog-owned code on GitHub and AWS's partner doc only |
| current body alphabet `[A-Za-z0-9]` | no | same; Datadog's Agent scrubber alone admits `_` |
| marker / checksum / delimiter (current) | no | none documented for app keys (the CRC32 checksum is documented for `ddpat_` only) |
| legacy length 40 | provider domain, length only | `ApplicationKey.hash` `minLength`/`maxLength` 40 in the v1 spec served from docs.datadoghq.com |
| legacy alphabet (lowercase hex) | no | spec shows a hex example, not a pattern |
| legacy identifying element | no | none exists; the shape is keyword-gated by design |

## The source

`https://docs.datadoghq.com/account_management/personal-access-tokens/`,
the access-token comparison table; the same table appears on
`https://docs.datadoghq.com/account_management/service-access-tokens/`.
Re-fetched 2026-09-23, row `Identifiable prefix`, Application keys column:

> Identifiable prefix | ddpat_ | ddsat_ | ddapp_ (new)

(Column order is PAT, SAT, Application keys; the service-access-tokens page
orders it `ddsat_ | ddpat_ | ddapp_ (new)`.) The provider-authored markdown is
`DataDog/documentation` `hugo/content/en/account_management/personal-access-tokens.md`
and `service-access-tokens.md`, plus the ja/ko/es/fr translations.
`observedAt`: 2026-09-23 (first observed 2026-09-22). The same page documents a
full `<SECRET><CHECKSUM>` grammar with a CRC32 checksum, but for `ddpat_` only.

Supporting provider-domain source for the legacy length only:
`https://docs.datadoghq.com/resources/json/full_spec_v1.json` (the v1 spec
served by the docs site, re-fetched 2026-09-23, sha256 `6ae0e2ec…e957e`).
`components.schemas.ApplicationKey.hash`: "Hash of an application key.",
`minLength: 40`, `maxLength: 40`, 40-character lowercase-hex example. The
`CreateChildOrg` operation says to interact with the new org "by using the
`org.public_id`, `api_key.key`, and `application_key.hash`", so `hash` is the
usable key value. The v2 spec (`full_spec_v2.json`, sha256 `1615ce73…95a91`)
gives `FullApplicationKeyAttributes.key` as an untyped string plus a 4-character
`last4`. Neither spec contains `ddapp`. Earlier passes read these specs from
GitHub (`datadog-api-client-python`); that the docs domain serves them is new
in this pass.

Precedent fit: same class as `pulumi-access-token` (prose prefix on the
provider domain, body tool-corroborated) and `new-relic-user-api-key`'s prefix
twin.

## Proposed `covers` sentence

> Datadog's own documentation (docs.datadoghq.com personal-access-tokens and
> service-access-tokens comparison tables) states `ddapp_` as the identifiable
> prefix of new-format Application keys, establishing the prefix; the 34-byte
> `[A-Za-z0-9]` body (40 bytes total) is corroborated only by Datadog-owned
> code on GitHub (Agent app-key validator, CloudFormation and ARM templates)
> and AWS's Secrets Manager partner doc, not by a provider-domain page. The
> legacy bare 40-character hex generation has no provider-documented
> identifying element and stays keyword-gated.

This matches the `providerSource` the benchmarks contract already carries
(see below); it adds the docs-served v1 spec as the provider-domain basis for
the legacy length.

## Contradictions with the current contract

Issue #645's status table predates two changes. As of 2026-09-23:

- **Product.** `crates/secret-scan-core/src/detectors/datadog.rs` now splits
  the family (#671, closed 2026-09-23): `datadog-application-key` is the
  current shape, literal `ddapp_` plus exactly 34 `[A-Za-z0-9]`, no context
  (`:390-422`); `datadog-application-key-legacy` keeps the frozen 40 bare
  lowercase hex, same-line marker gated (`:218`, `:424` onward). Spec rows:
  `docs/specs/detector-families.md:34-35`.
  `docs/contracts/precision/precision-contracts.json` has no Datadog entry.
- **Benchmarks.** `benchmarks/lib/assessment.ts` on
  `redact-secret-benchmarks` `main` (merged in benchmarks PR #167,
  2026-09-23) gives `datadog-application-key` tier T1, pattern
  `^ddapp_[A-Za-z0-9]{34}$`, with the personal-access-tokens page as
  `providerSource` (observed 2026-09-22) and body length/alphabet marked
  tool-corroborated. The legacy shape stays in `CONTEXT_GATED` as policy.

No contradiction remains between the provider source and either contract. The
residual disagreements are all below T1:

- **Body alphabet.** Datadog's Agent scrubber (`pkg/util/scrubber/default.go`)
  admits `_` in the `ddapp_` body; every Datadog validator and AWS say
  alphanumeric. Both contracts follow the validators.
- **Legacy case.** The scrubber admits uppercase hex; the product rejects it
  on purpose (module doc, `datadog.rs`).
- **Tokens under an app-key marker.** Datadog lets `ddpat_`/`ddsat_` tokens be
  sent as the application key. The product records that as an intentional
  false negative for this family (`datadog.rs` module doc).
- **Twin pairs.** `minimumTwinPairs: 0 < 5` from the issue table is not
  addressed by this source beyond the prefix twin it makes provable.

## Sources checked

Done-when option 1 (source found) is met. The option-2 classes are recorded
anyway, from the linked passes and this pass's re-fetch on 2026-09-23.

| source class | result |
| --- | --- |
| product docs and API reference (OpenAPI) | PAT and SAT pages: `ddapp_ (new)` re-confirmed 2026-09-23. `api-app-keys`, `api/latest/authentication`, `api/latest/key-management`, service-accounts, getting_started/api pages: no `ddapp`, no length. Docs-served `full_spec_v1.json`: `hash` length 40; `full_spec_v2.json`: `last4` only. `DataDog/datadog-api-spec`: HTTP 404 (private or absent), not read |
| changelog / release notes | `app.datadoghq.com/release-notes` redirects to login ("Datadog: Log In") on 2026-09-23, **not read**. `DataDog/cloudformation-template` CHANGELOG 4.5.2 names `ddapp_` and the legacy 40-hex format (corroboration, GitHub) |
| engineering / security blog | `datadog-api-authentication` and `detecting-leaked-credentials` re-fetched 2026-09-23: no `ddapp`, no length; other posts per pass 2 |
| secret-scanning partner pages | GitHub supported-patterns list (2026-09-23): `datadog_app_key` with a "Token versions" note, no format, not provider domain. Datadog's own Sensitive Data Scanner library lists "Datadog Application Key Scanner" and "Datadog Prefixed Application Key Scanner" with no regex |
| SDK / CLI docs on provider domain | `developers/community/libraries` (2026-09-23): no format |
| broad discovery (web, GitHub, forums) | Web searches on 2026-09-23 return only this project's own issues, AWS's partner doc and Datadog's pages. GitHub code search `ddapp_` in org DataDog: the docs markdown plus the code files already listed in pass 2. Reddit, Stack Overflow and Hacker News: nothing on the format (broad-discovery pass) |

## Open items

- **Release notes** behind login are unread. They cannot change the verdict
  (the prefix is already provider-stated), but could state a body grammar.
- **Twin pairs** (0 of 5) remain a separate `stable` gate.
- **Empirical check** of one freshly issued key (counts and character classes
  only), as specified in the
  [broad-discovery comment](https://github.com/redact-secret/redact-secret/issues/645#issuecomment-5785357229),
  would settle the body length and alphabet that no provider page states.
- The issue body's status line still says NOT FOUND — INCOMPLETE; it should
  be updated to point here.

## What this document does not do

It changes no detector, contract, fixture, or tier. The product detector and
the benchmarks contract were changed under #671 and benchmarks #162/#167, not
here. It contains no credential and no full example token value.

## Authority

This document records evidence. It does not select a version, create a tag,
publish a package, or authorize any release operation.
