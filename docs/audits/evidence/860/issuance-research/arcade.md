# #860 issuance research: `arcade:api-key` (`arc_proj_`)

[Issuance research index](README.md) ·
[Tier B re-rank](../tier-b-rerank.md#re-rank) ·
[Rulings R9–R10](https://github.com/redact-secret/redact-secret/issues/860#issuecomment-5880547337)

Frozen 2026-09-28. Desk research only: no key was issued, and no issued or
leaked credential is evidence.

**Gated property:** whether a project key issued today starts `arc_proj_`,
its body length and alphabet, and the read-only key's sub-prefix. Bare `arc_`
stays NOT SELECTED.

**Research verdict: STILL GATED** (no new T1 fact). **Maintainer
disposition (2026-09-28): still gated;** placeholders only.

## Sources (re-checked; nothing new at T1)

| # | Source | Date | Class | Ruling | Statement |
|---|---|---|---|---|---|
| 1 | ArcadeAI/arcade-mcp-agent-platform `apps/web/.env.example` L57 | 2026-09-28 | provider example-repo placeholder | R4 = prefix only | `arc_proj_` + 32 `x` (a placeholder run; no length weight) |
| 2 | ArcadeAI/arcade-mcp-agent-platform `README.md` L332 | 2026-09-28 | provider example repo | R4 | "Arcade project API key (server-side only) \| `arc_proj_...`" |
| 3 | arcadeai-labs/daytona-background-agents `onboard.sh` L23 | 2026-09-28 | provider-org example script prompt | R4 | "Arcade API key (arc_proj...)" |
| 4 | ArcadeAI/arcade-mcp `server.py` L518, arcade-mcp-ts `auth-resolution.ts` L143, mcpp `arcade_client.hpp` L33 | re-checked | executing `startsWith("arc_")` and a comment | R6 | prefix `arc_` only; no `arc_proj_` check, no length |

Searched: 74 ArcadeAI and 16 arcadeai-labs repos (shallow clones; the SDKs
arcade-py/js/go/java/dotnet, the arcade-mcp CLI, the docs repo): no
`arc_proj_` validator, regex, test fixture or length. The engine that issues
keys is closed source. The docs.arcade.dev llms-full dump has no `arc_`
token. GitHub code search for `arc_proj` finds only the two example repos
above; every other hit is an unrelated identifier. Web search: FAQ and
API-key pages without a format.

## Residual risk

- **False positives:** `arc_proj` occurs as an ordinary identifier or path
  (`arc_proj/graph.py`, `arc_project_tracking`), so a rule without a real
  length floor would claim code.
- **False negatives:** the unknown read-only key sub-prefix; legacy personal
  `arc_` keys (a bare prefix shared with Arcauthic, ArcAgent and Arcane) stay
  generic-only.

A maintainer-issued project key and read-only project key (structure only)
are still required.
