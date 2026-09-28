# #860 handoff: `browserbase:api-key`

[Tier B re-rank](tier-b-rerank.md) ·
[Research table #06](https://github.com/redact-secret/redact-secret/issues/860#issuecomment-5852386450) ·
[Issuance research](issuance-research/browserbase.md)

**Readiness: READY for `bb_live_`, with an open-ended body** (closed by
research under the existing rulings, 2026-09-28; was ISSUANCE-GATED).
`bb_test_` stays ISSUANCE-GATED. **Route:** new detector
`browserbase-api-key`, finding type `browserbase_api_key`. Scheduled for
Beta.12; no detector code merges to `main` until `0.1.0-beta.11` is
released.

The provider's own grammar is a prefix, an alphabet and a floor. The
contract uses it and adds a cap as project policy, following the
[Apify precedent](apify.md).

## Role and blast radius

A Browserbase API key (`BROWSERBASE_API_KEY`, sent as the `X-BB-API-Key`
header) creates and drives headless browser sessions for a project on the
account's usage budget. It reads session recordings and logs, and it can
reuse stored browser contexts, which hold the cookies and logins of the
sites an agent visited.

## Supported shape

Sources (re-checked 2026-09-28; the full table is in the
[issuance research](issuance-research/browserbase.md)):

- **Prefix.** Docs placeholders `bb_live_...` (R4) and a provider redaction
  regex `bb_(?:live|test)_…` in `browserbase/stagehand` (R2, recorded in the
  [re-rank](tier-b-rerank.md#r2-authorship-checks)).
- **Alphabet and floor, R2.** A provider-authored CI hygiene gate in
  [browserbase/cookbook `scripts/verify.py`](https://github.com/browserbase/cookbook/blob/eff9eca8e61e16ea1635e9e75e043c7a765c5f88/scripts/verify.py#L383)
  (2026-09-25) fails the check on
  `(?<!\w)bb_live_[A-Za-z0-9]{20,}(?!\w)`. The same author's import-time
  filter in
  [`scripts/import_sources.py`](https://github.com/browserbase/cookbook/blob/eff9eca8e61e16ea1635e9e75e043c7a765c5f88/scripts/import_sources.py#L22-L31)
  uses the same body inside `[A-Za-z0-9_-]` boundaries.

**R2 authorship.** The author (`Kylejeong2`) is a public member of the
`browserbase` organization with about 240 org commits. No public scanner
(gitleaks, trufflehog, Kingfisher) has a Browserbase rule, so neither rule is
vendored.

**Alphabet choice.** Stagehand's redactor admits `_` and `-` after four
alphanumerics; the cookbook gate is alphanumeric only. Both are
provider-authored. The contract uses the alphanumeric class, which the
maintainer's disposition states: it is the class a Browserbase CI gate
enforces, and it keeps `bb_live_session_…` style identifiers out.

| Part | Grammar | Provenance | Tier |
| --- | --- | --- | --- |
| Prefix | `bb_live_` | docs placeholders (R4) + provider regexes (R2) | T1 |
| Alphabet | `[A-Za-z0-9]` | provider CI gate (R2) | T1 |
| Length | at least 20, open-ended | provider CI gate (R2) | T1 (floor) |
| Upper bound | 128 | project policy: a bounded run for streaming; no width is observed | policy |
| Separators / checksum | none | — | — |

## Excluded shapes

| Shape | Why excluded |
| --- | --- |
| `bb_test_` keys | ISSUANCE-GATED: only a floor-5 regex and a T2 comment; customer issuance is unconfirmed |
| `bb_live_...`, `bb_live_xxxx`, `bb_live_your_api_key_here` | placeholders: below the floor, or `_`/`.` breaks the run and the trailing boundary rejects |
| `bb_live_session_…` and other snake_case identifiers | the glued `_` rejects the match |
| `bb_<timestamp>` cookie names | no `live_` segment |
| Browserbase project IDs (UUIDs) | not attributable; generic context covers `BROWSERBASE_PROJECT_ID=` |
| Body over 128 bytes | over-long run: an intentional false negative, never truncated |

## Overlap and output policy

- **Existing detectors.** None claims `bb_`. Measured on `main` (the re-rank
  probe):
  - env, `export`, `X-API-Key`, JSON `api_key` and the SDK keyword argument
    give `contextual_secret`, high;
  - Bearer gives `bearer_token`, high;
  - bare, chat and JSON `"token"` are missed.
- **New output.** Provider type, `Confidence::High`, `ALWAYS_REDACT_TYPES`.
- **`generic-token` deferral.** `browserbase` is not added. Deferring would
  silence `bb_test_` keys under `BROWSERBASE_API_KEY`.

## Implementation notes

`KnownFormatProviderDetector` with
`PrefixShape::at_least("bb_live_", 20, pattern::is_alnum, …)`, plus a post
check capping the run at 128. The boundary is `[A-Za-z0-9_-]` on both sides,
so a `_` or `-` glued after the run rejects the match.

Signals: `browserbase-documented-prefix`, `browserbase-provider-gate-floor`.

## Test axes

**Positives:**

- every context in the re-rank's probe list;
- `BROWSERBASE_API_KEY=` in `.env`;
- the `X-BB-API-Key:` header;
- `Browserbase(api_key="…")` and `new Stagehand({ apiKey: "…" })`;
- body lengths 20, 32 and 128.

**Near-miss twins:**

- body of 19;
- body of 129;
- a `_` or `-` glued after the run;
- `BB_LIVE_` uppercase prefix;
- `bb-live-`;
- a leading glue byte (`xbb_live_…`, `_bb_live_…`).

**Benign:**

- the placeholders and identifiers above;
- a `bb_test_` value of any length;
- `BROWSERBASE_API_KEY=${{ secrets.BROWSERBASE_API_KEY }}`;
- `bb_live_` alone at end of line.

## False-positive / false-negative boundary

- **Accepted false negatives:**
  - a key whose body contains `_` or `-` (stagehand's class admits them);
  - a body under 20 (no evidence one exists);
  - over-long runs;
  - every `bb_test_` key outside named contexts.
- **Accepted false positives:** `bb_live_` + 20–128 alphanumerics that is not
  a key, such as a padded placeholder. That follows the #867 placeholder
  precedent.

## Issuance checklist (optional narrowing; structure only)

1. Issue one `bb_live_` key and note whether a `bb_test_` key can be
   created.
2. Record: total and body length, alphabet classes including `_` and `-`,
   `rawValueRetained: false`, revoked.
3. A `bb_test_` record with the same body grammar would let `bb_test_` join
   as a second prefix in a separate change.
