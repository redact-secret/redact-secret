# #860 issuance research: `browserbase:api-key`

[Issuance research index](README.md) ·
[Handoff](../browserbase.md) ·
[Rulings R9–R10](https://github.com/redact-secret/redact-secret/issues/860#issuecomment-5880547337)

Frozen 2026-09-28. Desk research only: no key was issued, and no issued or
leaked credential is evidence.

**Gated property:** body length (the earlier R2 regex floor was 5), and
whether `bb_test_` keys are issued to customers.

**Research verdict: CLOSED (open-ended) for `bb_live_`; `bb_test_` STILL
GATED.**

**Maintainer disposition (2026-09-28): closed by research under the existing
rulings.** `bb_live_` + at least 20 `[A-Za-z0-9]`, with boundaries on both
sides; the upper cap is project policy, following the Apify open-ended
precedent. `bb_test_` stays gated.

## Sources

| # | Source | Date | Class | Ruling | Statement |
|---|---|---|---|---|---|
| 1 | [browserbase/cookbook `scripts/verify.py` L383 @ eff9eca](https://github.com/browserbase/cookbook/blob/eff9eca8e61e16ea1635e9e75e043c7a765c5f88/scripts/verify.py#L383) | 2026-09-25 | provider-authored CI hygiene gate (the check fails on a match, L421-L422); author `Kylejeong2`, a public member of the `browserbase` org with about 240 org commits | R2 = T1 | `re.compile(r"(?<!\w)bb_live_[A-Za-z0-9]{20,}(?!\w)")` |
| 2 | [browserbase/cookbook `scripts/import_sources.py` L22-L31 @ eff9eca](https://github.com/browserbase/cookbook/blob/eff9eca8e61e16ea1635e9e75e043c7a765c5f88/scripts/import_sources.py#L22-L31) | 2026-09-25 | same author, import-time secret filter | R2 = T1 | `bb_live_[A-Za-z0-9]{20,}` inside `(?<![A-Za-z0-9_-])(?:…)(?![A-Za-z0-9_-])` |
| 3 | [browserbase/stagehand `packages/integrations/core/src/harness/redact.ts` L12 @ ad2bf12](https://github.com/browserbase/stagehand/blob/ad2bf12ea7abd95bb1d6f3a59600842a0954fffb/packages/integrations/core/src/harness/redact.ts#L12) | 2026-08-30 (already recorded in the re-rank; re-checked) | provider redaction regex | R2 = T1 | `bb_(?:live\|test)_[A-Za-z0-9]{4}` then `[A-Za-z0-9_-]+` |
| 4 | browserbase/sdk-functions-node `src/cli/shared/config.ts` L46-L53 (added 4e071ce, 2026-01-29) | 2026-01 | provider CLI, executing warn-only check | R6 = T1 for the prefix `bb_` only | `if (!apiKey.startsWith("bb_"))` gives a warning |
| 5 | browserbase/cookbook `integrations/examples/integrations/agno/main.py` L16 | 2026-09 | provider example comment | T2 | "Starts with "bb_live_" or "bb_test_" followed by a unique string" |

Searched, nothing further: 60 browserbase-org repos (shallow clones; every
other `bb_live_` value is an ellipsis, `x` run, word or `abcd…` placeholder,
so R4 gives the prefix only), the docs llms-full dump (`bb_live_...` only),
and web search.

## Resulting contract (`bb_live_`)

- **Prefix** `bb_live_`.
- **Body** `[A-Za-z0-9]` with a floor of 20 (#1, #2); the right boundary is
  not `[A-Za-z0-9_-]`; the cap is project policy (128), per the open-ended
  READY rule used for Apify.
- **Alphabet:** #1/#2 (stricter, alphanumeric) and #3 (allows `_`/`-` after
  four alphanumerics) are both provider-authored. The contract uses the #1
  alphanumeric class: it is the one a Browserbase CI gate enforces, and it
  keeps `bb_live_session_…` style identifiers out.

`bb_test_`: only #3 (floor 5) and the T2 comment; no floor-20 source, and
customer issuance is unconfirmed. It stays gated.

See the [handoff](../browserbase.md).

## Residual risk

- **False negatives:** if real bodies contain `_` or `-` (stagehand's class
  allows it), the alphanumeric rule misses them (the trailing boundary
  rejects rather than truncates); bodies under 20 (no evidence).
- **False positives:** a floor of 20 alphanumerics after `bb_live_` is low
  risk; identifiers with `_` break the match. `bb_<timestamp>` cookie names do
  not carry `live` or `test`.
