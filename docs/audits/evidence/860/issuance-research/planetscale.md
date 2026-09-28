# #860 issuance research: `planetscale:service-token`

[Issuance research index](README.md) ·
[Tier B re-rank](../tier-b-rerank.md#re-rank) ·
[Rulings R9–R10](https://github.com/redact-secret/redact-secret/issues/860#issuecomment-5880547337)

Frozen 2026-09-28. Desk research only: no key was issued, and no issued or
leaked credential is evidence.

**Gated property:** whether today's secret suffix length falls inside 32–64
(trufflehog says 43), and which of `= . - _` occur.

**Research verdict: STILL GATED.** No new T1 source for the service-token
suffix. One new provider-docs sibling example supports, but does not
establish, 43 `[A-Za-z0-9_]`. **Maintainer disposition (2026-09-28): still
gated;** the 2022 range was not accepted.

## Sources

| # | Source | Date | Class | Ruling | Statement |
|---|---|---|---|---|---|
| 1 | [gitleaks PR #874](https://github.com/gitleaks/gitleaks/pull/874) | 2022-05-22 | provider staff, off-domain (`dbussink`, @planetscale) | R3 = T1 as of 2022-05 | the length is "not guaranteed to be 43… very likely to change"; `[a-z0-9=\-_\.]{32,64}` (already known) |
| 2 | [planetscale/cli `internal/config/config.go` L78-L80 @ 033bd9d](https://github.com/planetscale/cli/blob/033bd9d0ef649f8310f6ff51697ba426fbdb1db1/internal/config/config.go#L78-L80) | 2024-12-13 | provider CLI code | R1 | `strings.HasPrefix(c.ServiceTokenID, "pscale_tkn_") && len(c.ServiceToken) == 12`: prefix and the 12-character ID only (already known) |
| 3 | `https://planetscale.com/docs/llms-full.txt` (OAuth create-token page) | read 2026-09-28 | provider docs example value (sibling) | R5 example weight, sibling only | `access_token` = `pscale_oauth_` + 43 `[A-Za-z0-9_]`; `refresh_token` = `pscale_oauth_refresh_` + 43 `[A-Za-z0-9_]` (values not reproduced) |
| 4 | `https://api.planetscale.com/v1/openapi-spec` | read 2026-09-28 | provider OpenAPI | — | `token`: "The plaintext token. Available only after create."; no pattern or example |
| 5 | [PlanetScale docs, MCP service token](https://planetscale.com/docs/connect/mcp-service-token) | read 2026-09-28 | provider docs | R4 | "It starts with `pscale_tkn_`" / `Bearer pscale_tkn_...` |

Searched with no length or alphabet result (shallow clones at HEAD
2026-09-28): planetscale/cli, mcp-server (`src/lib/auth.ts` uses the env
value verbatim), planetscale-go, terraform-provider-planetscale, docs, skills,
database-skills, the claude/codex/cursor/vscode plugins, go-logkeycheck,
heroku-migrator, onramp, psdbproxy, database-js, planetscale_rails,
setup-pscale-action, heroku-buildpack-planetscale, planetscale-node,
planetscale-ruby, psdb, ghcommit-action, create-branch-password-action,
tutorial-pulumi; GitHub issue and PR search for `pscale_tkn` (no staff
statement after 2022); code search in `org:planetscale`.

## Contract status

- **T1:** prefix `pscale_tkn_`; as of 2022-05, a suffix of 32–64
  `[A-Za-z0-9=._-]` (case-insensitive per the staff diff).
- **Not T1 for today:** exactly 43, and whether `= . -` still occur.
- Supporting inference (not T1): PlanetScale's current OAuth tokens are the
  prefix + 43 base64url characters (32 random bytes); the service token
  plausibly uses the same generator, which would match trufflehog's
  `[A-Za-z0-9_]{43}`.

The options put to the maintainer were: accept the 2022 R3 range as-is
(READY with `pscale_tkn_[A-Za-z0-9=._-]{32,64}`), or a structure-only
issuance of one service token. The range was not accepted, so issuance is
the remaining route.

## Residual risk

- If the range had been accepted: a low false-positive rate (unique prefix);
  false negatives only if tokens now exceed 64 or use other characters.
- The `pscale_oauth_` and `pscale_pw_` siblings stay out of scope
  (`pscale_pw_` also names non-secret password IDs).
