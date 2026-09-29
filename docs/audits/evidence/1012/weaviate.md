# #1012 research: `weaviate:cloud-api-key` (re-research of an #860 gated family)

[Research index](README.md) ·
[Issue #1012](https://github.com/redact-secret/redact-secret/issues/1012) ·
[#860 issuance research, 2026-09-28](../860/issuance-research/weaviate.md) ·
[Handoff](../860/weaviate.md)

Frozen 2026-09-29. Desk research only: no key was issued, and no issued or
leaked credential is evidence. Sources were accessed on 2026-09-29.

**Gated property (unchanged):** T1 proof that keys issued by the Weaviate
Cloud (WCD) console come from the open-source dynamic-user generator (88
standard Base64 characters ending in the documented `v200` suffix).

**Verdict: BLOCKED, and one piece of prior support is weaker.** The provider
notebook that showed two 88-character keys with the suffix connects to a
**local** Weaviate, not to WCD. If that is the notebook the handoff cites, it
gives no WCD link.

## New sources

| # | Source | Date | Class | Ruling | Statement |
|---|---|---|---|---|---|
| 1 | [weaviate/recipes `weaviate-features/rbac/simple-rbac.ipynb` @ bd10786](https://github.com/weaviate/recipes/blob/bd10786685151c1cf75d4268254cad4839b84bdf/weaviate-features/rbac/simple-rbac.ipynb) | last changed 2026-04-06 | provider example output | R5 (open-source example) | prints two 88-character keys ending in the suffix, but connects with `connect_to_local`: an open-source example, not WCD |
| 2 | Weaviate community forum, thread 21656 | 2025-07-14 | staff answer (the answerer's GitHub bio reads "Open Source Sourcerer @ Weaviate"; matching the forum handle to that account is an inference) | R3 = T1 for open-source keys only | describes the open-source structure (16 + 44 + `v200`, standard Base64); nothing about WCD |
| 3 | Weaviate blog, "Weaviate Authentication & Authorization" | 2026-02-18 | provider blog | T1 for what it states | "Weaviate Cloud instances come with API key authentication and customizable RBAC pre-configured"; "Manage users and API keys through the console UI". No format |
| 4 | [weaviate/weaviate `adapters/handlers/rest/db_users/handlers_db_users.go` L421-L440 @ 6aefed8](https://github.com/weaviate/weaviate/blob/6aefed87bae8d28ae6a8d0af32ee467f02939989/adapters/handlers/rest/db_users/handlers_db_users.go#L421-L440) | HEAD 2026-09-29 | provider server code | R1 | non-generated keys enter only through a root-only "import static api keys" path; the generator is unchanged |

Searched, nothing further: weaviate/docs at fa7094c (no new auth commits);
weaviate-cloud at b38ab69 (OAuth only; word fixtures); the Python client
(eb5546a), TypeScript client (75b033a), mcp-server-weaviate (2122c8f) and
weaviate-cli (0e1bc61), none of which checks key shape; gitleaks, betterleaks,
trufflehog, Kingfisher, noseyparker (no rule; issue search empty).

## Exact missing evidence

Unchanged: a T1 source that links console-issued keys to the open-source
generator. The docs establish that WCD runs dynamic database users (prior
record), but not which code path mints console keys.

## Structure-only issuance check

In WCD, create one Admin and one Viewer key. Record for each: total length
(88?), whether it ends in the documented `v200` Base64 suffix, whether only
`[A-Za-z0-9+/]` occurs, whether any `=` occurs. `rawValueRetained: false`,
then delete.

## Residual risk

Unchanged: legacy WCD keys imported into the database-user store keep their
old shape; cluster-create keys from the management plane may use another
generator.
