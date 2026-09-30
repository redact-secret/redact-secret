# #1012 research: `planetscale:service-token` (re-research of an #860 gated family)

[Research index](README.md) ·
[Issue #1012](https://github.com/redact-secret/redact-secret/issues/1012) ·
[#860 issuance research, 2026-09-28](../860/issuance-research/planetscale.md)

Frozen 2026-09-29. Desk research only: no key was issued, and no issued or
leaked credential is evidence. Sources were accessed on 2026-09-29.

**Gated property (unchanged):** the suffix length after `pscale_tkn_` for
tokens issued today (the maintainer did not accept the 2022 range 32–64),
and which of `= . - _` occur.

**Verdict: BLOCKED.** New third-party material widens the doubt about a fixed
43 but no provider source speaks to it.

## New sources

| # | Source | Date | Class | Ruling | Statement |
|---|---|---|---|---|---|
| 1 | [mongodb/kingfisher PR #205](https://github.com/mongodb/kingfisher/pull/205), merged as [`data/rules/planetscale.yml` L8 @ 7be3d86](https://github.com/mongodb/kingfisher/blob/7be3d86ea04ca8d0ae5f086e96ee16edb9bcb964/data/rules/planetscale.yml#L8) | 2026-01-31 | peer scanner rule, third party | none | widened `{43}` to `pscale_tkn_[a-z0-9-_]{32,64}`: "These tokens are not consistently 43 characters in length … There seem to be some shorter, I didn't find any longer." The observation comes from leaked strings, so it is not evidence here, but it contradicts trufflehog's exact 43 |
| 2 | mongodb/kingfisher at 7433793, `crates/kingfisher-rules/generated/rules/betterleaks.yml` L64806 | 2026-09-29 | peer scanner rule (imported from betterleaks) | T2 | `pscale_tkn_(?i)[\w=\.-]{32,64}` |
| 3 | [planetscale/planetscale-go `service_tokens_test.go` @ 3187218](https://github.com/planetscale/planetscale-go/blob/31872187c4f9056e15a8549da3d1107b0b5c1303/planetscale/service_tokens_test.go) | 2021-03-18 (unchanged at HEAD) | provider test fixture | R5 | the create-response `token` is 40 lowercase hex with **no** `pscale_tkn_` prefix: the format has changed at least once |
| 4 | GitHub supported secret-scanning patterns | read 2026-09-29 | partner list | none | `planetscale_service_token`: partner, push protection; no regex published |

Searched, nothing further: planetscale/cli at b9be1d0 (`config.go` L78-L80
unchanged: prefix and the 12-character ID only); mcp-server at 2911c85
(placeholders); `planetscale.com/docs/llms-full.txt` and the OpenAPI spec
(unchanged); four PlanetScale changelog posts on service tokens (2025-12 to
2026-08; no format text); gitleaks and betterleaks (32–64 `[\w=.-]`),
trufflehog (exactly 43 `[A-Za-z0-9_]`), noseyparker (none); issue search in
four scanners (no staff statement after 2022).

## Exact missing evidence

The suffix length and alphabet of a service token issued today. Sources
disagree (43 in trufflehog; 32–64 in the 2022 staff statement and Kingfisher)
and none of them is provider code or a provider example.

## Structure-only issuance check

Create one service token. Record: the suffix length after `pscale_tkn_`,
which of uppercase, lowercase, digits, `_`, `-`, `.`, `=` appear,
`rawValueRetained: false`, then delete. One sample fixes today's issuance
only; Kingfisher's note suggests older tokens may be shorter than 43, so the
contract should state "as of the issuance date" and keep the 32–64 range
only as a documented false-negative bound, if the maintainer accepts it.

## Residual risk

Unchanged from the prior record.
