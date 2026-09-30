# Issue #1012: contract research for unsupported credential variants and #860 gated candidates

[Audit archive](../../README.md) ·
[Issue #1012](https://github.com/redact-secret/redact-secret/issues/1012) ·
[#860 handoff index](../860/README.md) ·
[#860 issuance research and R9–R10](../860/issuance-research/README.md) ·
[Spec: detector families](../../../specs/detector-families.md)

Frozen record, written 2026-09-29, for Beta.12 (milestone `v0.1.0.beta.12`).
It asks, for every credential family the pinned support matrix
(`benchmarks/support-matrix.json` at `b9e9091`) lists as `unsupported`,
whether a T1 or T2 contract can be frozen now. It also retries by research
the six #860 families that stayed ISSUANCE-GATED after rulings R9–R10, and
prepares Baseten, which is date-gated until 2026-10-01 15:00 GMT.

It changes no detector, fixture, finding type, support status, package,
version or release record, and it does not authorize implementation.

No key was issued for this research. No value here is, or is derived from,
an issued or leaked credential, and no complete key-shaped example appears:
shapes are given by prefix, length, alphabet and separators only. Where a
search surfaced a committed key-shaped value, its location is withheld and
it is not counted as evidence.

## Method

Broad discovery came first: web search, GitHub code search (including
provider SDKs, CLIs, MCP servers and published npm and PyPI packages), docs
and `llms-full.txt` dumps, changelogs, forums, and peer scanner rules
(gitleaks, betterleaks, trufflehog, noseyparker, Kingfisher, CredSweeper,
secretlint, osv-scalibr, GitGuardian, GitHub's partner list). Source class
and date were labelled afterwards. Rulings R1–R10 from #860 apply as
indexed in the [#860 handoff index](../860/README.md#research-inputs); R10
remains limited to Cerebras and RunPod and is not extended here. Every
GitHub source is a 40-hex permalink; every web source was read on
2026-09-29. GitHub code search was rate-limited at times; each file lists
what was searched and what was not.

**Verdicts.**

- **READY-T1:** prefix, length (exact, or a provider floor plus a policy
  cap), alphabet and separators are all T1.
- **READY-T2:** not fully T1, but the benchmarks independently-corroborated
  route is met: at least three dated references from at least three owners
  and at least two classes other than a summary, one of them provider-owned
  or independent.
- **BLOCKED:** the exact missing property and the cheapest evidence that
  would close it are named in the family file.
- **NOT-A-SECRET / OWNED-ELSEWHERE:** confirmed with a source.

## Verdict

| Family | Verdict | Proposed grammar or missing property | Record |
| --- | --- | --- | --- |
| `gitlab:routable-personal-access-token` | **READY-T1** | `glpat-` + base64url payload 27–300 + `.` + 2 base36 version + `.` + 2 base36 payload length + 7 base36 CRC32 (provider generator and validator) | [gitlab-routable-personal-access-token.md](gitlab-routable-personal-access-token.md) |
| `aws:sts-temporary-access-key` | **READY-T2** (T1 if R2 is applied to AWS's ferret-scan rule) | `ASIA` + exactly 16 `[A-Z0-9]`; an identifier, usable only with its secret and session token | [aws-sts-temporary-access-key.md](aws-sts-temporary-access-key.md) |
| `aws:iam-user-secret-access-key` | **READY-T2, context-constrained** (T1 if R2 is applied to git-secrets and ferret-scan) | exactly 40 `[A-Za-z0-9/+]`, only under an AWS secret key name or next to an `AKIA` ID | [aws-iam-user-secret-access-key.md](aws-iam-user-secret-access-key.md) |
| `google:oauth2-credential`, client secret | **READY-T2** (T1 if R2 is applied to Google's osv-scalibr rule) | `GOCSPX-` + exactly 28 `[A-Za-z0-9_-]` | [google-oauth2-credential.md](google-oauth2-credential.md) |
| `google:oauth2-credential`, access token `ya29.` | BLOCKED | alphabet (Google's example has an interior `.` every rule excludes) and floor | same |
| `google:oauth2-credential`, refresh token `1//` | BLOCKED | lead byte and length (Google example `1//` + 43 vs peer `1//0` + 80 or more) | same |
| `aws:sts-service-bearer-token` (`ABIA`) | **NOT-A-SECRET** | the CloudTrail access key ID of a bearer token; the token itself has no documented prefix | [aws-other-iam-prefixes.md](aws-other-iam-prefixes.md) |
| `aws:context-specific-credential` (`ACCA`) | **NOT-A-SECRET** | the `ServiceSpecificCredentialId`; the secret half is unprefixed or already `ABSK…` | same |
| `notion:integration-token` (`ntn_`) | BLOCKED | body: 11-digit run (gitleaks, secretlint) vs 9 (CredSweeper); one corroboration class | [notion-integration-token.md](notion-integration-token.md) |
| `linear:oauth-access-token` (`lin_oauth_`) | BLOCKED | body length and alphabet: no source of any class; provider examples are unprefixed | [linear-oauth-access-token.md](linear-oauth-access-token.md) |
| `openrouter:management-api-key` | BLOCKED | the prefix itself: `sk-or-mgmt-` (provider statements) vs `sk-or-v1-` (three first-hand users) | [openrouter-management-api-key.md](openrouter-management-api-key.md) |
| `atlassian:access-token` (`ATCT`) | BLOCKED | body (header, length, `=` position, CRC tail): peer rules only; the prefix needs an R3 confirmation | [atlassian-access-token.md](atlassian-access-token.md) |
| `npm:legacy-token` | BLOCKED; recommend closing as not attributable | a bare UUID; every classic token was revoked on 2025-12-09 | [npm-legacy-token.md](npm-legacy-token.md) |
| `netlify:other-prefixed-tokens` | BLOCKED, per prefix | separator, body width and alphabet for `nfc_`, `nfo_`, `nfu_`, `nfb_` (prefixes and a 40-character capacity are T1) | [netlify-other-prefixed-tokens.md](netlify-other-prefixed-tokens.md) |
| `stripe:organization-api-key` (`sk_org_`) | BLOCKED | whether a `live_`/`test_` segment follows `sk_org_`; body length and alphabet | [stripe-organization-api-key.md](stripe-organization-api-key.md) |
| `slack:workflow-webhook-token` (`xwfp-`) | BLOCKED | section count and widths; one provider example only | [slack-workflow-webhook-token.md](slack-workflow-webhook-token.md) |
| `cartesia:api-key` (#860) | BLOCKED | `.` separator and segment lengths; new peer rules (undotted 20) contradict the provider fixtures | [cartesia.md](cartesia.md) |
| `arcade:api-key` `arc_proj_` (#860) | BLOCKED | sub-prefix, length, alphabet; read-only key prefix | [arcade.md](arcade.md) |
| `browserbase:api-key` `bb_test_` (#860) | BLOCKED | whether customers can get `bb_test_` keys; floor | [browserbase-bb-test.md](browserbase-bb-test.md) |
| `planetscale:service-token` (#860) | BLOCKED | today's suffix length and alphabet | [planetscale.md](planetscale.md) |
| `weaviate:cloud-api-key` (#860) | BLOCKED (support weaker) | a T1 link from console-issued keys to the open-source generator; the cited notebook is a local example | [weaviate.md](weaviate.md) |
| `convex:deployment-key` cloud body (#860) | BLOCKED | body length and Base64 flavour | [convex-cloud-body.md](convex-cloud-body.md) |
| `baseten:api-key` (#860) | DATE-GATED (prepared, not ruled) | no `b10_` key before 2026-10-01 15:00 GMT; post-date checklist prepared | [baseten.md](baseten.md) |
| `mailgun:public-validation-key` | **NOT-A-SECRET** | documented public key | [confirm-only.md](confirm-only.md) |
| `mailgun:legacy-signing-key-triplet` | **OWNED-ELSEWHERE** | `mailgun-api-key` | same |
| `pinecone:legacy-api-key` | **OWNED-ELSEWHERE** | `pinecone-api-key` | same |

**Counts:** READY-T1 1; READY-T2 3 (one of them context-constrained);
BLOCKED 16 (including the two Google token parts and `npm`); DATE-GATED 1;
NOT-A-SECRET 3; OWNED-ELSEWHERE 2.

## Rulings the maintainer may want

- **R2 for AWS- and Google-authored scanner rules.** AWS's ferret-scan
  (2026, `@amazon.com` author) and git-secrets (2015, AWS principal engineer),
  and Google's osv-scalibr `gcpoauth2client` (2025, `@google.com` authors,
  narrowed to exactly 28 in Google's own commit) are provider-authored. Their
  bodies equal older public rules, which the #860 R2 practice treated as a
  reason to keep T2. A yes moves `ASIA`, the IAM secret and `GOCSPX-` to T1.
- **R3 for community.atlassian.com "Atlassian Team" answers** (the `ATCT`
  prefix; #643 left the same thread borderline).
- **R5 exception for Slack's `xwfp-` docs example** (one full-width example
  since 2023-10-07, consistent with Slack's own redactor).
- **Relabel `ABIA` and `ACCA`** as identifiers, not redaction targets.
- **Close `npm:legacy-token`** as not attributable.

## Product findings (synthetic probe on `main`)

A CLI built from `main` at `b9e9091` scanned synthetic values generated in
memory at run time (never written to disk). Only finding metadata was kept.

| Input | Finding today | Consequence |
| --- | --- | --- |
| A routable `glpat-` value with a valid CRC | `gitlab_token` over the payload only; the `.<version>.<length><crc>` tail is left in plaintext | defect: a value truncated into a match; fixed by the READY-T1 contract |
| `//registry.npmjs.org/:_authToken=<uuid>`; `_auth=<Base64>` | none | contextual gap for `.npmrc` keys with a leading `_`; see [npm-legacy-token.md](npm-legacy-token.md) |
| `sk_org_live_` + a long alphanumeric body | none | the shipped `sk_org_` rule would miss every organization key if the mode segment is real |
| `{"SecretAccessKey": "<40 chars>"}` | none | the JSON and CloudFormation form of the AWS secret is missed; `AWS_SECRET_ACCESS_KEY=` is found |
| bare `GOCSPX-` + 28 | none | expected; the READY-T2 contract adds it |
| `xwfp-` in the docs example's layout | `slack_token`, full span | the interim guard already covers it |

## Hands-on issuance (maintainer, structure only)

Follows the [#860 issuance protocol](../860/README.md#issuance-check-protocol-structure-only):
record only lengths, classes, separator positions and fixed parts,
`rawValueRetained: false`, then revoke. The exact checks are in each file.

| Family | What to check | Cost |
| --- | --- | --- |
| Slack `xwfp-` | section count, digit-section widths, last section 32 `[0-9a-f]`, any `_` or uppercase | one function-step run; the token self-revokes in 15 minutes |
| Netlify `nfc_` | total 40, `_` at byte 4, body classes | one `netlify login` |
| OpenRouter management key | exact prefix (`sk-or-mgmt-` or `sk-or-v1-`), length, alphabet | free, one key |
| Stripe org key | `live_`/`test_` after `sk_org_`, body length, alphabet | needs a Stripe organization |
| Linear OAuth | `lin_oauth_` present, body length, hex-only | one OAuth app, two flows |
| Notion `ntn_` | total 50, leading digit count (11 or 9), body classes | one integration token, one PAT |
| Atlassian `ATCT` | header, length 192, `=` position, CRC tail | one Bitbucket repository access token |
| Cartesia | `.` presence and segment lengths, `_` | one standard and one admin key |
| Arcade | full prefix, length, alphabet; read-only prefix | one project and one read-only key |
| Browserbase `bb_test_` | whether it can be issued at all; then floor and classes | dashboard check |
| PlanetScale | suffix length and classes | one service token |
| Weaviate | length 88, `v200` suffix, classes, no `=` | one Admin and one Viewer key |
| Convex cloud body | body length, Base64 flavour, `=` count, scope effect | one production and one preview deploy key |
| Google `ya29.` / `1//` | length, interior `.`, lead `1//0` | tokens from `gcloud` and an installed-app flow |
| Netlify `nfo_`, `nfu_`, `nfb_` | as `nfc_` | an OAuth app; browser storage; a build step |
| Baseten (after 2026-10-01 15:00 GMT) | total 45, id 8, `.` at 12, secret 32, classes | three keys |

The READY families need no issuance; an optional confirmation check is
listed in each file.

## Sanitization check

Before the record was frozen, this folder was scanned twice:

- `gitleaks dir` 8.30.1 (default rules) over `docs/audits/evidence/1012/`:
  no leaks found;
- the product CLI (`redact-secret` 0.1.0-beta.11, debug build) over every
  file in the folder: 0 findings in 22 sources.

## Authority

This record freezes research for review only. It does not authorize
implementation, a support-status change, a version change, a tag,
publication or release.
