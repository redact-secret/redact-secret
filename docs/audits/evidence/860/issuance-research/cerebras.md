# #860 issuance research: `cerebras:inference-api-key`

[Issuance research index](README.md) ·
[Handoff](../cerebras.md) ·
[Rulings R9–R10](https://github.com/redact-secret/redact-secret/issues/860#issuecomment-5880547337)

Frozen 2026-09-28. Desk research only: no key was issued, and no issued or
leaked credential is evidence.

**Gated property:** the body length after `csk-` (48?) and its alphabet.

**Research verdict: NARROWED.** The length is CLOSED at T1 (48 after a
4-character prefix). The prefix set widens to `csk-` or `csk_` through a
dated staff statement. The alphabet is STILL GATED.

**After ruling R10 (policy fill): READY.** Where the provider states a length
or floor but not the whole grammar, project policy may fill the rest, as long
as the fill is at least as wide as any provider-stated class. Contract:
`csk-` or `csk_` + exactly 48 `[A-Za-z0-9_-]`, with a leading boundary that
excludes Pinecone's `pcsk_`/`pcsk-`.

## Sources

| # | Source | Date | Class | Ruling | Statement |
|---|---|---|---|---|---|
| 1 | [Cerebras/vscode-cerebras-chat `src/provider.ts` L113 @ e03602f](https://github.com/Cerebras/vscode-cerebras-chat/blob/e03602fa96f3ddfc8122ea2655bfa39424a5d157/src/provider.ts#L113) | HEAD 2026-09-14 | provider code, executing input validator (Cerebras org; Marketplace publisher `Cerebras`) | R1 / R6 (executing check) = T1 | `if ((!value.startsWith('csk_') && !value.startsWith('csk-')) \|\| value.length !== 52)` gives "Invalid API key" |
| 2 | [same file L176 @ 9d0253c](https://github.com/Cerebras/vscode-cerebras-chat/blob/9d0253c1e071dd4d4afaad92cf5a6958bbea80eb/src/provider.ts#L176) | 2025-08-29 | the same check at introduction, by a Cerebras engineer (20 commits from a cerebras.net address) | R1 | `if (!value.startsWith('csk-') \|\| value.length !== 52)` |
| 3 | same file L96-L100 (doc comment) | 2025-08-29 to now | provider code comment | R6 = T2 (corroborates #1) | "Starts with 'csk_' or 'csk-' prefix / Is exactly 52 characters long" |
| 4 | [vscode-cerebras-chat PR #8 review comment r2462008982](https://github.com/Cerebras/vscode-cerebras-chat/pull/8#discussion_r2462008982) (merged 2025-10-25 by `joycee-cerebras`) | 2025-10-24 | dated staff statement on a provider repo | R3 = T1 as of its date | "unintentional and recent change in our service. The prefix should actually be `csk-` and new keys will have this prefix moving forward. We still want to accept both" |
| 5 | [vscode-cerebras-chat PR #8 review comment r2453931915](https://github.com/Cerebras/vscode-cerebras-chat/pull/8#discussion_r2453931915) | 2025-10-23 | same staff member | R3 | "Customers have API keys with both `csk-` and `csk_` prefixes" |
| 6 | [vscode-cerebras-chat issue #7](https://github.com/Cerebras/vscode-cerebras-chat/issues/7) | 2025-10-22 | empirical user report | context only | the validator rejected newly generated `csk_` keys (this explains the Kong docs `csk_` word placeholder) |
| 7 | inference-docs.cerebras.ai (Dify and Kong pages) | re-checked 2026-09-28 | provider docs | T1 prefix (already known) | "starts with `csk-`", consistent with #4 ("new keys ... `csk-`") |

Searched, no new alphabet fact: all 13 Cerebras-org repos (shallow clones;
only vscode-cerebras-chat mentions `csk`), both SDKs (no check), the docs
llms-full dump (4 mentions, prefix only), and GitHub code search for `csk-`
validators (about 40 hits, all third-party, so R8 makes them unusable).

## Resulting contract

- **Prefix:** `csk-` (current issuance) and `csk_` (legacy window, still
  valid per #4/#5, as of 2025-10).
- **Body:** exactly 48 characters (52 in total; the validator counts the
  prefix). T1 (#1).
- **Alphabet:** not T1. The provider validator accepts any 48 code units.
  Tool rules say `[a-z0-9]` (tool-only). R10 fills it with the policy
  class `[A-Za-z0-9_-]`, a superset of every stated class, with no narrowing
  from third parties (R8).

See the [handoff](../cerebras.md).

## Residual risk

- **False positives:** Pinecone `pcsk_` / `pcsk-` contains both `csk_` and
  `csk-`; a leading boundary (no `[A-Za-z0-9_-]` before `c`) is required for
  both variants.
- **False negatives:** a body byte outside `[A-Za-z0-9_-]`; any future length
  change (the validator is 13 months old at HEAD and unchanged).
- The Management API key (dedicated endpoints) shape is still unknown and not
  covered.
