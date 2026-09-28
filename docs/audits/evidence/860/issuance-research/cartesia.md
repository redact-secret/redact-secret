# #860 issuance research: `cartesia:api-key`

[Issuance research index](README.md) ·
[Tier B re-rank](../tier-b-rerank.md#re-rank) ·
[Rulings R9–R10](https://github.com/redact-secret/redact-secret/issues/860#issuecomment-5880547337)

Frozen 2026-09-28. Desk research only: no key was issued, and no issued or
leaked credential is evidence.

**Gated property:** whether a key issued today contains `.`, the `<id>` and
`<secret>` segment lengths, and whether `_` appears.

**Research verdict: STILL GATED** (no new T1 fact). **Maintainer
disposition (2026-09-28): still gated;** the `<id>.<secret>` split comes from
a comment only.

## Sources (new or re-checked)

| # | Source | Date | Class | Ruling | Statement |
|---|---|---|---|---|---|
| 1 | [cartesia-ai/cartesia-mcp `cartesia_mcp/sdk_setup.py` L10 @ 9b26639](https://github.com/cartesia-ai/cartesia-mcp/blob/9b2663956fed845133a326fe5368b025d595cb78/cartesia_mcp/sdk_setup.py#L10) | added e8b09a0, 2026-06-01, by a Cartesia engineer | provider code comment, staff-authored | R6 = T2 | "Admin keys use sk_car_admin_<id>.<secret>; standard keys use sk_car_<id>.<secret>." |
| 2 | same repo `cartesia_mcp/credentials.py` L67-L68 | HEAD 2026-09-20 | executing check | R6 = T1 prefix only | `token.startswith("sk_car_") and not token.startswith("sk_car_admin_")`: no dot, length or charset check |
| 3 | same repo `tests/conftest.py` L10, `tests/test_config.py` L15-L16 | added afefbb6, 2026-06-01, same author | provider test fixtures | R5 example-shape weight | `sk_car_` + 22 + `.` + 36 (all synthetic) |
| 4 | same repo `tests/test_hosted_credentials.py`, `tests/test_oauth_store.py` | 2026-06 to 09 | provider test fixtures | R5 | conflicting shapes: short dotted word fixtures (`abc.def`-style), and undotted word fixtures with `_` bodies (`oauth_test_key`-style) |
| 5 | `https://docs.cartesia.ai/llms-full.txt` | 2026-09-28 | provider docs | R4 | only `sk_car_...`, `sk_car_admin_...` and a word placeholder |
| 6 | cartesia-python history | 2025-02 | a committed key-shaped value (withheld, already recorded in the re-rank) | not evidence | — |

Searched: all 19 cartesia-ai repos (cartesia-python, cartesia-js, line,
skills, InkIt, community-integrations, edge and others) and their full
histories for `sk_car`: only #1–#6. No public API server, no CLI with
validation, no provider scanner regex, and no changelog entry about a
key-format change. Web search: docs and third-party placeholders only.

## Why it is still gated

The only statement of the dot and the segment lengths is a T2 comment plus R5
fixtures, and the R5 fixtures in the same repo disagree (dotted 22.36, dotted
short, and undotted with `_`). The undotted OAuth fixtures also hint that the
hosted-MCP OAuth credential may be a distinct `sk_car_` shape. A
maintainer-issued standard key (structure only) still settles it.

## Residual risk if shipped on fixtures alone

- **False negatives:** a rule that requires `.` misses legacy undotted keys
  (the 2025 shape) and any OAuth-issued `sk_car_` credential.
- **False positives:** a loose `sk_car_` + `[A-Za-z0-9_.]+` rule claims
  `sk_car_admin_…` unless ordered, and short test strings.
