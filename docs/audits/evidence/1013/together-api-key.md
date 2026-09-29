# #1013 evidence: `together:api-key`

[Index](README.md) ·
[Issue #1013](https://github.com/redact-secret/redact-secret/issues/1013) ·
[Spec: Together AI and Tavily (#867)](../../../specs/detector-families.md#together-ai-and-tavily-867)

Frozen 2026-09-29. Desk research only: no key was issued, and no issued or
leaked credential is evidence. Shapes only.

**Contract under test (#867, T2):** `tgp_v1_` + exactly 43
`[A-Za-z0-9_-]`, 50 in total; identifier boundaries on both sides.

**Matrix blocker (pin at `b9e90915`):** corroborated route 2 references,
2 owners, 1 class (ledger: the betterleaks rule and #783).

**Verdict: READY-T2, conditional** on Q-TG below: the exact length 43 is
stated only by peer scanner rules (three owners). A second class confirms
the prefix and alphabet but not the length. If the maintainer requires the
second class to state the length, the family is STILL-BLOCKED on length and
only hands-on issuance closes it.

## Sources

All read 2026-09-29.

| # | Source | Date | Owner | Class | Statement (shape only) |
| --- | --- | --- | --- | --- | --- |
| 1 | [togethercomputer/together-py `src/together/lib/cli/_track_cli.py#L205`](https://github.com/togethercomputer/together-py/blob/9c9c34e47686344b996eaf19a7c470f72dcdecd6/src/together/lib/cli/_track_cli.py#L205) | 2026-04-27 (commit `4ec3f646`, absent at its parent) | Together AI | provider-owned-code (redactor) | `(?i)(?<![a-z0-9_])(tgp_[a-z0-9_-]+)(?![a-z0-9_])`: the `tgp_` prefix and a `[A-Za-z0-9_-]` body, no length. **New.** Its unit fixture is a short `tgp_v1_` dummy |
| 2 | [Samsung/CredSweeper `credsweeper/rules/config.yaml#L1814-L1827`](https://github.com/Samsung/CredSweeper/blob/f21ab2f2553eea288a72273b9658cd297ab1d11f/credsweeper/rules/config.yaml#L1814-L1827) | 2026-05-11 (commit `2e9aeef4`, #842) | Samsung | peer-scanner-rule | `tgp_v1_[0-9A-Za-z_-]{43}`, `min_line_len: 50`. **New.** Its three samples are `tgp_v1_` + 43 |
| 3 | [mongodb/kingfisher native rule `togetherai.yml#L8`](https://github.com/mongodb/kingfisher/blob/82d050530cdef9af070b8f9a75701c9c27a948c3/crates/kingfisher-rules/data/rules/togetherai.yml#L8) (v1.113.0) | added 2025-08-27; replaced by a betterleaks alias 2026-08-21 | MongoDB | peer-scanner-rule | `tgp_v1_[A-Za-z0-9_-]{43}`. This native rule predates betterleaks' and is its own lineage, correcting the ledger's "Kingfisher only aliases betterleaks" |
| 4 | betterleaks `togetherai.go` at `2a387a5bad42` (ledger) | — | betterleaks | peer-scanner-rule | `tgp_v1_` + 43 `[A-Za-z0-9_-]` |
| 5 | [OpenHands/software-agent-sdk `openhands/sdk/utils/redact.py#L357`](https://github.com/OpenHands/software-agent-sdk/blob/2b9502cee3b74e879bb23fa13d0c689c5d73931b/openhands-sdk/openhands/sdk/utils/redact.py#L357) | 2026-04-03 | OpenHands | independent-implementation (redactor) | `tgp_v1_[A-Za-z0-9_-]{20,}`: lower bound |
| 6 | [jishnu-mohan/llm-key-validator `src/providers/together.ts#L7`](https://github.com/jishnu-mohan/llm-key-validator/blob/04c822299ffa343814c7de6b3acd14e130f5273f/src/providers/together.ts#L7) | 2026-05-14 | jishnu-mohan | independent-implementation (validator) | `tgp_v\d_` + 32 or more `[A-Za-z0-9_-]`, or 64 lowercase hex (legacy) |
| 7 | [kenryu42/cc-safety-net `src/core/redaction.ts#L15`](https://github.com/kenryu42/cc-safety-net/blob/d31cf9c598fd230d29ea924df0e15b50e960be82/src/core/redaction.ts#L15) | 2026-09-06 | kenryu42 | independent-implementation (redactor) | `tgp_v1_` + 43 or more `[A-Za-z0-9_-]` |
| 8 | [redact-secret#783](https://github.com/redact-secret/redact-secret/issues/783) (ledger) | 2026-09-26 | redact-secret | independent-research (summary) | four observed bodies of 43 |

Found and not counted: praetorian titus (a copy of Kingfisher's rule, same
rule id); Nutlope/aicommits declares `apiKeyFormat: 'tgp_'` but never uses it;
RedHat ai-guardian `tgp_v1_` + 38–50 (a hedge). Searched with no shape
result: every togethercomputer repo (python, py, typescript, go, cookbook,
sandbox, skills, terraform provider; only #1 matches `tgp_`), Together docs
(authentication, multiple API keys, changelog 2026-07/08 on project keys,
expiry and legacy regeneration; no prefix, length or example), GitHub's
secret-scanning pattern list (no Together entry), trufflehog, gitleaks,
noseyparker, detect-secrets, secretlint, osv-scalibr, Microsoft
security-utilities.

## Corroborated-route count

- References and owners: #1–#8, 8 owners.
- Classes (non-summary): peer-scanner-rule, provider-owned-code,
  independent-implementation: 3.
- Exact width 43: #2, #3, #4 only (peer class, three owners). #7 gives a
  floor of 43; #1, #5 and #6 give no length or a lower floor.

## Contradictions

| Statement | Proposed status | Basis |
| --- | --- | --- |
| Legacy 64-hex keys (pleno-dlp, #6) | bounded (unchanged) | the contract excludes the legacy shape |
| #1 redacts any `tgp_` version, not only `v1` | no contradiction | a redactor, not a grammar |

## Maintainer ruling needed

Q-TG: under the corroborated route, must the second non-summary class
corroborate the exact width, or is prefix + alphabet corroboration by
provider-owned code (#1) enough when three independent peer rules agree on
the width?

## Issuance check (only if Q-TG is answered "exact width required")

One project API key: prefix is `tgp_v1_`; total length 50; whether the body
contains `_` or `-`. Structure only; revoke afterwards.
