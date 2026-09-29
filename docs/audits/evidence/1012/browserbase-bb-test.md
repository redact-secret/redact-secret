# #1012 research: `browserbase:api-key` `bb_test_` (re-research of an #860 gated shape)

[Research index](README.md) ·
[Issue #1012](https://github.com/redact-secret/redact-secret/issues/1012) ·
[#860 issuance research, 2026-09-28](../860/issuance-research/browserbase.md) ·
[`bb_live_` handoff](../860/browserbase.md)

Frozen 2026-09-29. Desk research only: no key was issued, and no issued or
leaked credential is evidence. Sources were accessed on 2026-09-29.

**Gated property (unchanged):** a floor-20 source for `bb_test_`, and
whether `bb_test_` keys are issued to customers at all.

**Verdict: BLOCKED.** The only new length source is a peer rule that existed
from 2026-07-10 to 2026-08-21 and was then deleted. Browserbase's docs have
no test-key, sandbox or test-mode concept.

## Sources

| # | Source | Date | Class | Ruling | Statement |
|---|---|---|---|---|---|
| 1 | [mongodb/kingfisher `rules/browserbase.yml` L8 @ 5eb060e](https://github.com/mongodb/kingfisher/blob/5eb060e5a294c5a27f650b486d7d8f99e55bd382/crates/kingfisher-rules/data/rules/browserbase.yml#L8) (new) | 2026-07-10 (first `{20,}`, then exactly `{27}` the same day); deleted 2026-08-21 | peer scanner rule (historical) | T2 | `bb_(?:live\|test)_[A-Za-z0-9_-]{27}`; its references are Browserbase docs, the Node SDK auth header and the example comment below |
| 2 | stagehand `packages/integrations/core/src/harness/redact.ts` L12 | re-checked; unchanged since 2026-08-29 | provider redaction regex | R2 = T1 | floor of 5 for `bb_test_` (four alphanumerics, then `[A-Za-z0-9_-]+`) |
| 3 | [browserbase/cookbook `scripts/verify.py` L383 @ eff9eca](https://github.com/browserbase/cookbook/blob/eff9eca8e61e16ea1635e9e75e043c7a765c5f88/scripts/verify.py#L383) | re-checked | provider CI gate | R2 = T1 | covers `bb_live_` only |
| 4 | browserbase/cookbook agno example comment | 2026-09 | provider example comment | T2 | "Starts with "bb_live_" or "bb_test_" followed by a unique string" |

The #860 re-rank said Kingfisher had no Browserbase rule. That is true at its
current HEAD; the rule in #1 existed only for six weeks.

Searched, nothing further: all 67 `browserbase` repositories (60 in the prior
pass; every `bb_test` in stagehand is the literal word placeholder); npm
`@browserbasehq/*`, `browse`, `create-browser-app`; PyPI `browserbase` and
`stagehand` (only `bb_live_...` in READMEs); `docs.browserbase.com/llms-full.txt`
(no `bb_test`, no test-mode concept); betterleaks, gitleaks, trufflehog and
other peers at HEAD, and GitGuardian (no rule); web search.

## Exact missing evidence

- Whether customers can be issued `bb_test_` keys at all. Only issuance or a
  Browserbase statement settles it.
- If they can: body length (floor) and whether `_` or `-` occurs.

## Structure-only issuance check

In the Browserbase dashboard, check whether a test key can be created. If
yes, create one and record: prefix, body length, whether `_` or `-` occurs,
`rawValueRetained: false`, then revoke. If no, record that no test key can
be issued; the `bb_test_` shape is then dropped from scope.

## Residual risk

If `bb_test_` keys exist, they are redacted today only in named and Bearer
contexts. `bb_live_` is unaffected (READY since 2026-09-28).
