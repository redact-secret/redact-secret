# Issue #655 — T1 provider evidence for `microsoft-entra:application-client-secret`

[Audit archive](../../README.md) ·
[Issue #655](https://github.com/redact-secret/redact-secret/issues/655) ·
[Epic A #575](https://github.com/redact-secret/redact-secret/issues/575) ·
[Research pass 2](https://github.com/redact-secret/redact-secret/issues/655#issuecomment-5784996853) ·
[Broad-discovery pass](https://github.com/redact-secret/redact-secret/issues/655#issuecomment-5785640396) ·
[Web-search pass](https://github.com/redact-secret/redact-secret/issues/655#issuecomment-5786036909) ·
[False-negative probe](https://github.com/redact-secret/redact-secret/issues/655#issuecomment-5786154618) ·
[Grammar freeze (#297)](../../../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) ·
[Benchmarks intake #161](https://github.com/redact-secret/redact-secret-benchmarks/issues/161)

Written 2026-09-23 on branch `chore/beta7-research`. The three
iterative passes and the product probe stay in the linked issue comments and
are not restated here.

## Verdict: FOUND, by example only (marker and current-variant width)

A provider-domain SDK reference prints two example secrets that show the
`8Q~` marker at offset 3 and a 40-character width. No Microsoft page states
the format in prose. Whether an SDK-reference example meets the T1 bar is for
the maintainer; the precedent is `terraform-cloud-token` and
`supabase-management-token`, both accepted on provider examples. If the
example is rejected, the result is NOT FOUND — EXHAUSTIVE as of 2026-09-23:
every source class required by the issue has now been read (see below).

| property | provable at T1 | basis |
| --- | --- | --- |
| prefix | no | none exists; the first 3 characters are per-secret (Graph `hint`, "the first three characters of the password") |
| marker `Q~` at offsets 4–5 | yes, by example | both SDK examples |
| marker digit | `8` only, by example | both SDK examples; `7` appears only in Microsoft code (security-utilities, "Previous" format) and tools |
| total length | 40 for `8Q~`, by example | both SDK examples; 37 for `7Q~` is provider code only |
| alphabet | no | examples show letters, digits, `_ - . ~`; Purview SIT lists `a-z 0-9 - _ . ~` in prose but gives no `Q~` and says "up to 40" |
| checksum / terminator | no | none documented anywhere |

## The source

`https://learn.microsoft.com/en-us/powershell/module/microsoft.graph.applications/add-mgapplicationpassword?view=graph-powershell-1.0`
(Microsoft Graph PowerShell SDK reference; `ms.date` 2026-02-20, updated
2026-03-02). Re-fetched 2026-09-23. Under the headings

> Example 1: Add a password credential to an application with a six month expiry

and

> Example 2: Add a password credential to an application with a start date

the `Format-List` output prints `Hint : <3 chars>` and
`SecretText : <value>`. Measured on the live page by script (values not
reproduced): both values are 40 characters, character 4 is `8`, characters
5–6 are `Q~`, the first 3 characters equal the printed `Hint` in both, and
the non-alphanumeric characters present are `_ - . ~`. The beta mirror
(`…/microsoft.graph.beta.applications/add-mgbetaapplicationpassword?view=graph-powershell-beta`)
carries the same two values. `observedAt`: 2026-09-23 (first observed
2026-09-22).

Status of the examples: a Microsoft Graph SDK maintainer says they are "not
real secrets, they are examples in the documentation"
([msgraph-sdk-powershell#3508](https://github.com/microsoftgraph/msgraph-sdk-powershell/issues/3508),
2026-01-26), while Microsoft's internal push gate classifies the same spans
as `SEC101/156 AadClientAppIdentifiableCredentials`. They show the issued
shape; they are not issued credentials.

Corroboration, not T1: `microsoft/security-utilities` SEC101/156 (provider
code on github.com, not linked from any Microsoft docs page) accepts
`8Q~` + 34 (40 total) and `7Q~` + 31 (37 total), with `[A-Za-z0-9_.~-]` in
all positions; its 2024 history names these the "Current" and "Previous"
formats. The Azure DevOps GHAS pattern page on learn.microsoft.com lists the
rule name `SEC101/156 AadClientAppIdentifiableCredentials` without a format.

## Proposed `covers` sentence

> Microsoft Graph PowerShell's Add-MgApplicationPassword reference
> (learn.microsoft.com) prints two example SecretText values, each 3
> characters (equal to the printed 3-character Hint), the digit 8, the literal
> Q~, and 34 characters, 40 in total. The Q~ marker at offset 4 and the
> 8-variant's 40-character width come from these examples, not from a stated
> grammar. The 7Q~ 37-character previous format, the digit-to-length coupling
> and the body alphabet are corroborated only by Microsoft's security-utilities
> code (SEC101/156) and third-party tools.

## Contradictions with the current contract

Contract (benchmarks, T2): `^[A-Za-z0-9_.~]{3}\dQ~[A-Za-z0-9_.~-]{31,34}$`.
Product detector `crates/secret-scan-core/src/detectors/microsoft_entra.rs`
implements the same grammar (`is_prefix_byte` excludes `-`,
`MIN_SUFFIX_LEN = 31`, `MAX_SUFFIX_LEN = 34`, any ASCII digit). Its module
comment says Microsoft publishes no grammar; that is still true of prose, but
the SDK examples above now exist. `docs/contracts/precision/precision-contracts.json`
has no entry for this family.

- **Leading `-` (false negative).** The provider examples contain `-` in the
  body; SEC101/156, GitLab and TruffleHog v2 allow it in the first 3
  characters, and four independent field reports show issued secrets starting
  with `-` (web-search pass). The contract and detector reject them. Measured
  against 0.1.0-beta.6: a synthetic `-bc8Q~…` input yields no finding; filed
  as redact-secret-benchmarks#161.
- **Marker digit.** The contract accepts `\d`; the provider shows only `8`,
  and Microsoft code only `7|8`.
- **Digit not coupled to length.** The contract accepts 37–40 with any digit;
  Microsoft code accepts only `7Q~`/37 and `8Q~`/40.
- **Other Microsoft docs.** Graph REST `passwordCredential` / `addPassword`
  (and the msgraph-metadata OpenAPI) say "16-64 characters" and show a legacy
  32-character value with no marker; Purview SIT says "up to 40" with no `Q~`;
  Microsoft Entra PowerShell `New-EntraApplicationPasswordCredential` shows a
  29-character placeholder with no `Q~` whose first 3 characters do not match
  its `Hint`. None of these describes the current `Q~` format, and none
  contradicts the SDK examples.

Which of these to adopt is **not decided here**; it belongs to the T1 re-tier
batch and to benchmarks#161.

## Sources checked

Every class required by the issue has been read. URL-level tables for
2026-09-22 are in the three linked comments; the rows below add what was
re-fetched or newly read on 2026-09-23.

| source class | result |
| --- | --- |
| product docs and API reference (incl. OpenAPI) | Graph `passwordCredential` (re-fetched 2026-09-23: hint = "first three characters"; "16-64 characters"), `addPassword` 1.0/beta, msgraph-metadata OpenAPI v1.0/beta, Purview SIT (re-fetched: "up to 40", alphabet, 0 `Q~`), Entra identity-platform and app-management pages, Defender for Cloud pages: no `Q~` or current-format grammar |
| changelog / release notes | Entra what's-new, archive, breaking changes, identity-platform what's-new-docs: no format. SFI "What's new" (MicrosoftDocs/security `sfi/secure-future-initiative-whats-new.md`, read 2026-09-23): no format |
| engineering / security blog | devblogs CASK post (2024-09-25): no Entra format. devblogs `/identity/` and `/microsoft365dev/` (WP search "client secret", "identifiable", 2026-09-23): no format post; "Client Secret expiration now limited to a maximum of two years" (2022-02-09, read 2026-09-23): no format. MSRC blog "guidance regarding credentials leaked to GitHub Actions logs through Azure CLI" (2023-11-14, read 2026-09-23 via microsoft.com/en-us/msrc/blog): redaction targets "Microsoft-issued keys", no format. SFI trust-center page (200 on 2026-09-23; 403 on 2026-09-22) and all 33 learn.microsoft.com `security/zero-trust/sfi` pages (MicrosoftDocs/security source, 2026-09-23): no `Q~`, no "identifiable" format. Microsoft Security Blog search (2026-09-22): no relevant post |
| secret-scanning partner pages | GitHub partner list: `azure_active_directory_application_secret` name only, not provider domain. Azure DevOps GHAS pattern page (re-fetched 2026-09-23): rule name `SEC101/156` only. No Microsoft token-format announcement found |
| SDK / CLI docs on provider domain | Graph PowerShell `Add-MgApplicationPassword` v1 and beta: **the two examples above**. `Add-MgServicePrincipalPassword`, Az PowerShell `New-AzADAppCredential` / `New-AzADSpCredential`, Azure CLI `ad app credential` / `ad sp` pages: no `Q~`. Entra PowerShell `New-EntraApplicationPassword`, `New-EntraApplicationPasswordCredential`, `New-EntraServicePrincipalPasswordCredential`, `New-EntraBetaApplicationPassword` (404 on 2026-09-22 under the old path; read 2026-09-23 under `microsoft.entra.applications`): no `Q~`; one 29-character placeholder |

Not read: Reddit (blocked by every route tried; see the web-search pass). It
cannot meet the T1 bar, so it does not change the verdict.

## Open items

- Maintainer decision: accept the SDK-reference examples as the T1 source
  (then the family joins the T1 re-tier batch with the `covers` above), or
  reject them (then record "no provider-documented format as of 2026-09-23").
- Contract and detector correction for leading `-`, digit set and
  digit-to-length coupling, tracked through redact-secret-benchmarks#161;
  independent of tier.
- Empirical measurement of freshly issued secrets (digit, length, lead
  characters, alphabet, hint equality), as specified in the
  [web-search pass](https://github.com/redact-secret/redact-secret/issues/655#issuecomment-5786036909).
  Record counts and classes only; delete each secret.
- `minimumTwinPairs: 0 < 5` remains a separate failing `stable` gate.

## What this document does not do

It changes no detector, contract, fixture, or tier. The product detector and
`docs/contracts/precision/precision-contracts.json` are untouched; the
re-tier and any `covers` edit happen in the T1 re-tier batch of #575. It
contains no credential and no full example token value; the fixed infixes
`7Q~` and `8Q~` are public markers.

## Authority

This document records evidence. It does not select a version, create a tag,
publish a package, or authorize any release operation.
