# #860 issuance research: `runpod:api-key`

[Issuance research index](README.md) ·
[Handoff](../runpod.md) ·
[Rulings R9–R10](https://github.com/redact-secret/redact-secret/issues/860#issuecomment-5880547337)

Frozen 2026-09-28. Desk research only: no key was issued, and no issued or
leaked credential is evidence.

**Gated property:** the exact body length after `rpa_` (46?) and the
40-uppercase/6-lowercase layout, needed to separate Redirect.pizza's `rpa_` +
30.

**Research verdict: STILL GATED.** No new T1 length source. The only
provider rule remains the R2 floor of 16.

**After ruling R10 (policy fill): READY.** The provider floor is 16; project
policy sets the floor at 31, which excludes the Redirect.pizza `rpa_` + 30
shape. Contract: `rpa_` + at least 31 `[A-Za-z0-9]`.

## Sources

| # | Source | Date | Class | Ruling | Statement |
|---|---|---|---|---|---|
| 1 | [runpod/runpod-mcp `src/alp/scrub.ts` L36 @ 09a565a](https://github.com/runpod/runpod-mcp/blob/09a565a6adef8932f044dfa65243e7bc41cbdf2d/src/alp/scrub.ts#L36) | added 57b3973, 2026-09-16 (#90); the only commit touching the rule | provider-authored scrubber | R2 = T1 | `{ name: 'runpod_key', re: /\brpa_[A-Za-z0-9]{16,}\b/g }` |
| 2 | [RunPod blog, scoped API keys](https://www.runpod.io/blog/scoped-api-keys-runpod) | 2024-11 | provider blog | T1 prefix | "Any new keys will be created with an rpa_ prefix" |
| 3 | runpod/runpod-mcp tests (`install-clients.test.ts`, `specgen-alp.test.ts`, `credential-check.test.ts`) @ 09a565a | 2026-09 | provider test fixtures | R5 example weight | synthetic word and letter fixtures after `rpa_`, 1–23 characters, mixed case; they exercise the scrubber and do not describe issuance |
| 4 | runpod/flash `tests/unit/test_credentials.py` @ 4fdbb67 | 2026 | provider fixture | R5 | a word placeholder containing `_` |
| 5 | [runpod/docs PR #456](https://github.com/runpod/docs/pull/456) (removed 2026-03-20) | 2025-11-18 | provider docs example | R5 (the maintainer has not ruled on it) | 48 characters: `rpa` + 40 `[A-Z0-9]` + 5 `[a-z0-9]`, no `_` (already known; conflicts with 50) |
| 6 | [RunPod docs, API keys](https://docs.runpod.io/get-started/api-keys) | read 2026-09-28 | provider docs | — | no format stated |
| 7 | [betterleaks](https://github.com/betterleaks/betterleaks) `runpod.go` (added f64b922, 2026-07-22, by the betterleaks maintainer) | 2026-07 | tool (not provider) | T2 | `rpa_[A-Z0-9]{40}[A-Za-z0-9]{6}`; the author is the tool's maintainer, so R3 does not apply |

Searched with no length result (shallow clones at HEAD 2026-09-28):
runpod-mcp `src`, runpodctl, runpod-python, typescript-api-sdk, flash (its
logger `PREFIXED_KEY_PATTERN` does not cover `rpa_`), runpod-plugins-official
(word placeholders only), docs; code search in `org:runpod`,
`org:runpod-workers` and `org:runpod-labs`.

## Contract status

- **T1:** prefix `rpa_`; alphabet `[A-Za-z0-9]` (no `_` in the body); floor
  16 (R2).
- **Not T1:** 46, and the 40/6 layout (tool and empirical only).
- Under the open-ended READY rule, `rpa_[A-Za-z0-9]{16,}` would be READY, but
  it would claim Redirect.pizza's `rpa_` + 30, which is why the re-rank gated
  it on an exact width. R10 settles it by policy: floor 31, cap 128 (the
  Apify precedent).

See the [handoff](../runpod.md).

## Residual risk

- **At the policy floor of 31:** the Redirect.pizza false positive is gone; a
  false negative only if real keys are shorter than 31 (none known).
- A structure-only issuance of one All key and one Read Only key remains the
  way to freeze 46 and the layout, as an optional narrowing.
