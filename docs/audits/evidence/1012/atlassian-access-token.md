# #1012 research: `atlassian:access-token` (`ATCT`)

[Research index](README.md) ·
[Issue #1012](https://github.com/redact-secret/redact-secret/issues/1012) ·
[#643 evidence (`ATAT`)](../643/README.md)

Frozen 2026-09-29. Desk research only: no key was issued, and no issued or
leaked credential is evidence. Sources were accessed on 2026-09-29.

**Verdict: BLOCKED (body).** The `ATCT` prefix is T1 under R3 **if** the
maintainer accepts an "Atlassian Team" answer on community.atlassian.com as
a staff statement (#643 treated the same thread as borderline). The body
grammar rests on two peer scanner rules, one class, so the T2 route fails.
Atlassian's own docs say API keys have variable length.

## Current product behaviour

`atlassian-api-token` claims `ATAT` API tokens only; `ATCT` and `ATBB` are
deliberately excluded. The support-matrix reason: trufflehog targets the
distinct `ATCT` family, not the `ATAT` API-token shape.

## Sources

| # | Source | Date | Class | Ruling | Statement |
|---|---|---|---|---|---|
| 1 | [Atlassian Community, "Can we confirm BitBucket's token prefixes"](https://community.atlassian.com/forums/Bitbucket-questions/Can-we-confirm-BitBucket-s-token-prefixes/qaq-p/3093481), accepted answer by an "Atlassian Team" member | 2025-08-26 | provider staff statement | R3 = T1 as of its date (prefix), pending the maintainer's confirmation | "API Token: ATAT App Password: ATBB Access Tokens (Workspace, Project, Repo): ATCT" |
| 2 | same thread, question by a customer | 2025-08-20 | customer observation | none | all three access-token kinds "appear to always have the header 'ATCTT3xFfGN0'" (not confirmed by staff) |
| 3 | [Atlassian support, manage an organization with the admin APIs](https://support.atlassian.com/organization-administration/docs/manage-an-organization-with-the-admin-apis/) | read 2026-09-29 | provider docs | T1 (negative on length) | "API keys support variable length values, not fixed length values" |
| 4 | [Atlassian developer community, "About the format of Atlassian security tokens"](https://community.developer.atlassian.com/t/about-the-format-of-atlassian-security-tokens/62553) | 2022-10-13 | provider staff statement | superseded context | "clients cannot depend on their size, structure, or format" (pre-prefix era) |
| 5 | [trufflehog `pkg/detectors/atlassian/v2/atlassian.go` L40-L48 @ 48b58d3](https://github.com/trufflesecurity/trufflehog/blob/48b58d3bf3f02ba17bf23b87f095499bc80c6fd7/pkg/detectors/atlassian/v2/atlassian.go#L40-L48) | 2024-07-17 | peer scanner rule | T2 input | `ATCTT3xFfG[A-Za-z0-9+/=_-]+=[A-Za-z0-9]{8}`; verifies against the organization admin API, so it treats `ATCTT` as an org admin API key; PR text says observed keys were 192 characters |
| 6 | [CredSweeper `config.yaml` L1095-L1106 @ f21ab2f](https://github.com/Samsung/CredSweeper/blob/f21ab2f2553eea288a72273b9658cd297ab1d11f/credsweeper/rules/config.yaml#L1095-L1106) and [`filters/value_atlassian_token_check.py` L36-L56](https://github.com/Samsung/CredSweeper/blob/f21ab2f2553eea288a72273b9658cd297ab1d11f/credsweeper/filters/value_atlassian_token_check.py#L36-L56) | 2023-05-24 | peer scanner rule | T2 input | "Bitbucket Repository Access Token": `ATCTT3xFfGN0[0-9A-Za-z_-]{80,800}` + `=` + `[A-F0-9]{8}`, with a CRC32 check of the tail |
| 7 | [betterleaks `atlassian.go` L28 @ fa62e6a](https://github.com/betterleaks/betterleaks/blob/fa62e6aaad9de6da71de49e7114234700c84006e/cmd/generate/config/rules/atlassian.go#L28) | 2026-02-03 | peer scanner rule | negative | an `ATCT` value is a false-positive test for its `ATAT` rule |

Searched, nothing further: gitleaks (`ATATT3` only), noseyparker (`ATATT3xFfGF0`
only), Kingfisher, secretlint, osv-scalibr (no `ATCT` rule); code search in
`org:atlassian` and `org:atlassian-labs` (0 hits); Atlassian support and
developer pages (variable length, no prefix); GitGuardian's "Atlassian Access
Token" page (no format). GitHub's pattern list has no `ATCT` type.

## Exact missing evidence

- **Prefix confirmation:** a maintainer ruling that #1 counts under R3.
- **Body:** length (192 observed by a peer, "variable" per the provider), the
  12-byte header (`ATCTT3xFfGN0` vs a `…GX…` variant in trufflehog's test),
  the `=` position, the 8-byte uppercase-hex CRC tail and its coverage. A
  provider example or an independent implementation would add the second
  class; none exists.
- **Role:** Bitbucket access tokens (staff) vs org admin API keys (trufflehog).
  Bounded: a contract can be "any `ATCT` token" regardless of role.

## Structure-only issuance check

Create one Bitbucket repository access token (free workspace); optionally one
organization admin API key. Record: whether it starts `ATCTT3xFfGN0`, total
length (192?), whether there is exactly one `=` and at which position,
whether the last 8 bytes are `[0-9A-F]`, whether CRC32 of the preceding bytes
equals that tail, and whether the part before `=` is only `[A-Za-z0-9_-]`.
`rawValueRetained: false`, then revoke.

## Residual risk

Today `ATCT` tokens are redacted only in named and header contexts. The CRC
tail, once confirmed, would make a bare contract very precise.
