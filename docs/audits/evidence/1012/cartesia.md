# #1012 research: `cartesia:api-key` (re-research of an #860 gated family)

[Research index](README.md) ·
[Issue #1012](https://github.com/redact-secret/redact-secret/issues/1012) ·
[#860 issuance research, 2026-09-28](../860/issuance-research/cartesia.md)

Frozen 2026-09-29. Desk research only: no key was issued, and no issued or
leaked credential is evidence. Sources were accessed on 2026-09-29.

**Gated property (unchanged):** whether a key issued today contains `.`, the
`<id>` and `<secret>` segment lengths, and whether `_` appears.

**Verdict: BLOCKED.** This pass found four new peer and third-party rules
and one new staff statement. The rules all describe an **undotted** `sk_car_`
+ 20 (or at least 20) body. That contradicts the provider's own dotted test
fixtures, and the provider-owned sources still disagree with each other, so
the corroboration count cannot close the shape.

## New sources (items 1–5); re-checked (6–7)

| # | Source | Date | Class | Ruling | Statement |
|---|---|---|---|---|---|
| 1 | [betterleaks `cmd/generate/config/rules/cartesia.go` L14 @ fa62e6a](https://github.com/betterleaks/betterleaks/blob/fa62e6aaad9de6da71de49e7114234700c84006e/cmd/generate/config/rules/cartesia.go#L14) | added 2026-08-19 (PR #311, no Cartesia staff comment) | peer scanner rule | T2 | `sk_car_[A-Za-z0-9_]{20}` then a terminator: exactly 20, no `.` |
| 2 | [mongodb/kingfisher `rules/cartesia.yml` L8 @ 701508d](https://github.com/mongodb/kingfisher/blob/701508d529c638e6e9374d47f08e7e53004ddcf6/crates/kingfisher-rules/data/rules/cartesia.yml#L8) | 2026-07-10; deleted 2026-08-21 (Kingfisher now imports #1) | peer scanner rule (historical) | T2 | `sk_car_[A-Za-z0-9_]{20}` |
| 3 | [RedHatProductSecurity/ai-guardian `secrets.toml` L892 @ 8222a46](https://github.com/RedHatProductSecurity/ai-guardian/blob/8222a460ade9972fffe0a64182cbf05786da21e4/src/ai_guardian/patterns/data/secrets.toml#L892) | 2026-09-01 | peer scanner rule (derived from #1, per its header) | T2 | `sk_car_[A-Za-z0-9_]{20,}` |
| 4 | [JSONbored/gittensory `review-enrichment/src/analyzers/secret-scan.ts` L287-L289 @ f665d94](https://github.com/JSONbored/gittensory/blob/f665d94a751ed5374216117b469fcd7092003b23/review-enrichment/src/analyzers/secret-scan.ts#L287-L289) | 2026-07-05 | independent implementation | T2 | `sk_car_(?:admin_)?[A-Za-z0-9]{20,}`, comment "base62 body" |
| 5 | [cartesia-ai/cartesia-mcp PR #45](https://github.com/cartesia-ai/cartesia-mcp/pull/45) | 2026-07-01, by the same Cartesia engineer as the `sdk_setup.py` comment | provider staff statement | R3 = T1 on this point only | "hosted OAuth now stores `sk_car_...` API keys instead of JWTs … update OAuth store/provider tests to use `sk_car_...` credentials" |
| 6 | Cartesia docs, [`api-keys/get`](https://docs.cartesia.ai/api-reference/api-keys/get) and [`api-keys/list`](https://docs.cartesia.ai/api-reference/api-keys/list) | read 2026-09-29 | provider docs | R4 | a key's `id` "does not start with `sk_`" and is a UUID in the example; "older keys with no recorded creator" exist. Nothing about the secret |
| 7 | Prior record's sources (`sdk_setup.py` comment, `credentials.py` check, test fixtures) | re-checked | as recorded | as recorded | unchanged since 2026-09-28 |

Searched, nothing further: all 32 `cartesia-ai` repositories over full
history (19 in the prior pass); cartesia-mcp releases 0.23.0 to 0.24.1; npm
`@cartesia/cartesia-js` 4.2.0 and `cartesia` 1.0.0; PyPI `cartesia` 4.2.0,
`cartesia-line` 0.2.18, `cartesia-mcp` 0.24.1 (only the known prefix check
and comment); `docs.cartesia.ai/llms-full.txt` and the 2024–2026 changelogs
(no key-format change); gitleaks, trufflehog, noseyparker, CredSweeper,
osv-scalibr, secretlint, detect-secrets, semgrep-rules (no rule); GitGuardian
("Prefixed: True", no pattern).

## What changed since 2026-09-28

- #5 settles one open point: the undotted word-style OAuth fixtures replaced
  JWTs as placeholders. They are not a separate OAuth credential shape.
- #1–#4 add a corroborated **undotted** 20-character reading. The T2 count
  (four owners, two classes) looks met on paper, but it contradicts the
  provider's dotted fixtures (22 + `.` + 36) and cannot be adopted while
  provider-owned sources disagree.

## Exact missing evidence

Unchanged: whether issued keys contain `.`, the segment lengths, `_`
presence. Inference only: a 22-character base62 `<id>` would fit an encoded
UUID, matching the UUID key IDs in #6.

## Structure-only issuance check

Issue one standard key and one admin key. Record for each: whether `.` is
present and where; the lengths before and after it; whether `_` or `-`
appears in either part; the alphabet classes. `rawValueRetained: false`,
then delete.

## Residual risk

Unchanged from the prior record. A rule following #1 would miss every dotted
key; a rule following the fixtures would miss any undotted key.
