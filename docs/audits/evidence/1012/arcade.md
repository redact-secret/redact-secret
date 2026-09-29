# #1012 research: `arcade:api-key` (`arc_proj_`, re-research of an #860 gated family)

[Research index](README.md) ·
[Issue #1012](https://github.com/redact-secret/redact-secret/issues/1012) ·
[#860 issuance research, 2026-09-28](../860/issuance-research/arcade.md)

Frozen 2026-09-29. Desk research only: no key was issued, and no issued or
leaked credential is evidence. Sources were accessed on 2026-09-29.

**Gated property (unchanged):** whether a project key issued today starts
`arc_proj_`, its body length and alphabet, and the read-only key's
sub-prefix. Bare `arc_` stays not selected.

**Verdict: BLOCKED.** No new T1 fact. The new sources are one more
placeholder and a docs statement that read-only project keys exist.

## New sources

| # | Source | Date | Class | Ruling | Statement |
|---|---|---|---|---|---|
| 1 | [ArcadeAI/arcade-custom-dashboards `components/setup-modal.tsx` L89 @ 8159e8b](https://github.com/ArcadeAI/arcade-custom-dashboards/blob/8159e8b4b2f348c2499ca2a0d61216b412fd3405/components/setup-modal.tsx#L89) | 2025-11-20 | provider example placeholder | R4 (prefix) | `placeholder="arc_proj..."`, no validation |
| 2 | ArcadeAI/docs `operate/governance/tool-executions/page.mdx` L165 | repository HEAD 2026-09-28 | provider docs | T1 that the key type exists | "Arcade refuses a read-only project API key" |
| 3 | A committed key-shaped value in an Arcade example repository (bare `arc_`, localhost configuration) | 2026-02-10 | observation | not evidence (withheld) | — |

Searched, nothing further: all 88 `ArcadeAI` and 17 `arcadeai-labs`
repositories (74 and 16 in the prior pass), including the new safeword,
arcade-plugin and mastra repositories (placeholders only; the only validator
is the known `startsWith("arc_")`); npm `@arcadeai/*`, opencode-arcade and
botholomew; PyPI arcadepy, arcade-mcp, arcade-core, arcade-mcp-server,
arcade-serve, arcade-tdk (no `arc_proj`); the docs `api-keys` page (no
format); every peer scanner and GitGuardian (no rule); issue and PR search
(nothing relevant); web search (nothing).

## Exact missing evidence

Unchanged: the full prefix (any sub-prefix after `arc_`), body length and
alphabet for a project key, and the read-only project key's prefix. The
issuing engine is closed source.

## Structure-only issuance check

Issue one project key and one read-only project key. Record for each: the
full prefix up to the first byte of the random body, body length, alphabet
classes, whether `_` or `-` occurs in the body. `rawValueRetained: false`,
then revoke.

## Residual risk

Unchanged: `arc_proj` also occurs as an ordinary identifier, so no rule
without a real length floor is safe.
