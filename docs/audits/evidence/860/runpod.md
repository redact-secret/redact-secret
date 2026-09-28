# #860 handoff: `runpod:api-key`

[Tier B re-rank](tier-b-rerank.md) ·
[Research table #09](https://github.com/redact-secret/redact-secret/issues/860#issuecomment-5852386571) ·
[Issuance research](issuance-research/runpod.md)

**Readiness: READY, with an open-ended body** (ruling R10, 2026-09-28; was
ISSUANCE-GATED). **Route:** new detector `runpod-api-key`, finding type
`runpod_api_key`. Scheduled for Beta.12; no detector code merges to `main`
until `0.1.0-beta.11` is released.

## Role and blast radius

A RunPod API key (`RUNPOD_API_KEY`, sent as `Authorization: Bearer` to the
REST and GraphQL APIs) is scoped All or Read Only. An All key creates,
stops and terminates GPU pods and serverless endpoints on the account's
balance, and reads templates, network volumes and their environment
variables. Both scopes share the `rpa_` prefix.

## Supported shape

Sources (re-checked 2026-09-28; the full table is in the
[issuance research](issuance-research/runpod.md)):

- **Prefix.** The RunPod blog on scoped keys (2024-11): "Any new keys will be
  created with an rpa_ prefix".
- **Alphabet and provider floor, R2.** A provider-authored scrubber in
  [runpod/runpod-mcp `src/alp/scrub.ts`](https://github.com/runpod/runpod-mcp/blob/09a565a6adef8932f044dfa65243e7bc41cbdf2d/src/alp/scrub.ts#L36)
  (added 2026-09-16): `\brpa_[A-Za-z0-9]{16,}\b`. Its authorship is recorded
  in the [re-rank](tier-b-rerank.md#r2-authorship-checks).
- **Policy floor, R10.** A floor of 16 would claim Redirect.pizza's
  `rpa_` + 30 tokens. R10 lets project policy fill a grammar the provider
  states only partly, as long as the fill is at least as wide as the
  provider's class. The alphabet stays the provider's `[A-Za-z0-9]`; the
  floor rises to 31, the first width above the Redirect.pizza shape. Every
  RunPod width seen (46 empirical; a withdrawn 48-character docs example)
  is above it.

| Part | Grammar | Provenance | Tier |
| --- | --- | --- | --- |
| Prefix | `rpa_` | provider blog + scrubber (R2) | T1 |
| Alphabet | `[A-Za-z0-9]` | provider scrubber (R2) | T1 |
| Length | at least 31, open-ended | provider floor 16 (R2), raised to 31 by policy (R10) | policy floor |
| Upper bound | 128 | project policy, the Apify precedent | policy |
| Separators / checksum | none | — | — |

The 46-byte body and the 40-uppercase/6-mixed layout stay tool and
empirical facts. They are not part of the contract.

## Excluded shapes

| Shape | Why excluded |
| --- | --- |
| Redirect.pizza `rpa_` + 30 | another issuer's token; below the policy floor |
| `rpa_` + 16–30 | inside the provider floor but below the policy floor: an accepted false negative (no RunPod key of that width is known) |
| RunPod S3-compatible `rps_` secrets and access keys | a different credential; no shape researched |
| Legacy unprefixed keys (before 2024-11) | no prefix; generic context covers `RUNPOD_API_KEY=` |
| `rpa_...`, `rpa_xxxx`, `rpa_your_key`, word fixtures with `_` | placeholders: below the floor, or `_`/`.` breaks the run and the trailing boundary rejects |
| Body over 128 bytes | over-long run: an intentional false negative, never truncated |

## Overlap and output policy

- **Existing detectors.** None claims `rpa_`. Measured on `main` (the
  re-rank probe):
  - env, `export`, `X-API-Key`, JSON `api_key` and the SDK keyword argument
    give `contextual_secret`, high;
  - Bearer gives `bearer_token`, high;
  - bare, chat and JSON `"token"` are missed.
- **New output.** Provider type, `Confidence::High`, `ALWAYS_REDACT_TYPES`.
  A Redirect.pizza token of 31 or more bytes, if one exists, would be
  reported as RunPod: misattributed, still redacted.
- **`generic-token` deferral.** `runpod` is not added. Deferring would
  silence legacy unprefixed keys and `rps_` secrets under `RUNPOD_*` names.

## Implementation notes

`KnownFormatProviderDetector` with
`PrefixShape::at_least("rpa_", 31, pattern::is_alnum, …)`, plus a post check
capping the run at 128. The boundary is `[A-Za-z0-9_-]` on both sides, so a
`_` or `-` glued after the run rejects the match.

Signals: `runpod-documented-prefix`, `runpod-policy-floor`.

## Test axes

**Positives:**

- every context in the re-rank's probe list;
- `RUNPOD_API_KEY=` in `.env`;
- `runpod.api_key = "…"` and `runpodctl config --apiKey …`;
- an MCP server config (`runpod-mcp` `env`);
- body lengths 31, 46 and 128, with the 40-uppercase/6-mixed layout and
  without it.

**Near-miss twins:**

- body of 30 (the Redirect.pizza width) and 129;
- a `_` or `-` glued after the run;
- `RPA_` uppercase prefix;
- `rpa-`;
- a leading glue byte (`xrpa_…`, `_rpa_…`).

**Benign:**

- `rpa_` + 30 alphanumerics;
- the placeholders above;
- `rpa_` alone at end of line.

## False-positive / false-negative boundary

- **Accepted false negatives:**
  - a RunPod key with a body of 16–30 (none known);
  - a body with `_` or `-` (the provider rule excludes them);
  - over-long runs;
  - legacy unprefixed keys and `rps_` secrets outside named contexts.
- **Accepted false positives:** `rpa_` + 31–128 alphanumerics that is not a
  RunPod key, including any longer Redirect.pizza token or a padded
  placeholder (the #867 precedent).

## Issuance checklist (optional narrowing; structure only)

For one All key and one Read Only key (optionally one S3 `rps_` secret),
record:

- body length after `rpa_` (expect 46);
- the length of the leading run with no lowercase letter, and the tail
  length and classes;
- whether `_` appears;
- `rawValueRetained: false`, revoked.

A uniform 46 would allow an exact-width contract later, as a separate
optional change.
