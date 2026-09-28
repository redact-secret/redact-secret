# #860 handoff: `cerebras:inference-api-key`

[Tier B re-rank](tier-b-rerank.md) ·
[Research table #08](https://github.com/redact-secret/redact-secret/issues/860#issuecomment-5852386450) ·
[Issuance research](issuance-research/cerebras.md)

**Readiness: READY** (ruling R10, 2026-09-28; was ISSUANCE-GATED).
**Route:** new detector `cerebras-api-key`, finding type `cerebras_api_key`.
Scheduled for Beta.12; no detector code merges to `main` until
`0.1.0-beta.11` is released.

## Role and blast radius

A Cerebras inference API key (`CEREBRAS_API_KEY`, sent as
`Authorization: Bearer`) calls the Cerebras Cloud inference API on the
account's quota and billing. The Management API key for dedicated endpoints
is a separate credential whose shape is unknown; it is not covered.

## Supported shape

Sources (re-checked 2026-09-28; the full table is in the
[issuance research](issuance-research/cerebras.md)):

- **Length, R1.** The provider's VS Code extension validator
  ([Cerebras/vscode-cerebras-chat `src/provider.ts` L113](https://github.com/Cerebras/vscode-cerebras-chat/blob/e03602fa96f3ddfc8122ea2655bfa39424a5d157/src/provider.ts#L113))
  rejects any key that does not start `csk_` or `csk-` or whose length is not
  52. The check was introduced on 2025-08-29 with `csk-` only and has kept
  the 52 since. The prefix is 4 bytes, so the body is 48.
- **Prefixes, R3.** A Cerebras staff member wrote on the provider repo on
  2025-10-23 and 2025-10-24
  ([review comment](https://github.com/Cerebras/vscode-cerebras-chat/pull/8#discussion_r2462008982)):
  customers have keys with both prefixes, `csk_` was "an unintentional and
  recent change", new keys use `csk-`, and both should be accepted. Provider
  docs state "starts with `csk-`".
- **Alphabet, R10.** No provider source states the alphabet: the validator
  accepts any 48 code units, and the `[a-z0-9]` class is tool-only. R10 lets
  project policy fill it, as long as the fill is at least as wide as any
  provider-stated class. The policy class is `[A-Za-z0-9_-]`, a superset of
  every class seen, with no narrowing from third-party rules (R8).

| Part | Grammar | Provenance | Tier |
| --- | --- | --- | --- |
| Prefix | `csk-` (current) or `csk_` (2025-10 window, still accepted) | provider validator (R1) + staff statement (R3, as of 2025-10) + docs | T1 |
| Body | exactly 48 (52 in total) | provider validator (R1) | T1 |
| Alphabet | `[A-Za-z0-9_-]` | project policy under R10 | policy |
| Separators / checksum | none | — | — |

## Excluded shapes

| Shape | Why excluded |
| --- | --- |
| Pinecone `pcsk_` / `pcsk-` | the byte before `csk` is `p`, so the leading boundary rejects it. Pinecone's own detector keeps `pcsk_` (its body is 69 or 70 bytes, so no width overlaps either) |
| `csk-` or `csk_` + a body other than 48 | not the validated width |
| `csk-your-key-here`, `csk_...`, `csk-xxxx` | placeholders below the width |
| Management API keys (dedicated endpoints) | shape unknown |
| Any byte outside `[A-Za-z0-9_-]` in the 48 | outside the policy class; the trailing boundary rejects the run |

## Overlap and output policy

- **Existing detectors.** None claims `csk-` or `csk_`. `pinecone-api-key`
  claims `pcsk_` only, and the leading boundary keeps the two disjoint.
  Measured on `main` (the re-rank probe):
  - env, `export`, `X-API-Key`, JSON `api_key` and the SDK keyword argument
    give `contextual_secret`, high;
  - Bearer gives `bearer_token`, high;
  - bare, chat and JSON `"token"` are missed.
- **New output.** Provider type, `Confidence::High`, `ALWAYS_REDACT_TYPES`.
- **`generic-token` deferral.** `cerebras` is not added. Deferring would
  silence a Management API key under `CEREBRAS_*` names.

## Implementation notes

`KnownFormatProviderDetector` with two shapes,
`PrefixShape::exact("csk-", 48, pattern::is_alnum_dash, …)` and
`PrefixShape::exact("csk_", 48, pattern::is_alnum_dash, …)`, both with the
`[A-Za-z0-9_-]` boundary on both sides. The leading boundary is what rejects
`pcsk_`; a test must pin it.

Signals: `cerebras-documented-prefix`, `cerebras-validator-length`.

## Test axes

**Positives:**

- every context in the re-rank's probe list, for both prefixes;
- `CEREBRAS_API_KEY=` in `.env`;
- `Cerebras(api_key="…")` and an OpenAI-compatible client with
  `base_url="https://api.cerebras.ai/v1"`;
- bodies that include `_` and `-`, and all-lowercase alphanumeric bodies.

**Near-miss twins:**

- body of 47 and 49;
- `CSK-` uppercase prefix;
- `csk.`;
- a leading glue byte (`pcsk_…`, `pcsk-…`, `xcsk-…`, `_csk-…`);
- a trailing glue byte;
- a `.` or `+` inside the body.

**Benign:**

- a real-shape Pinecone `pcsk_` key built at run time (must stay
  `pinecone_api_key` only);
- the placeholders above;
- `csk-` alone at end of line.

## False-positive / false-negative boundary

- **Accepted false negatives:**
  - any future length change (the validator has been unchanged for 13
    months);
  - a body byte outside `[A-Za-z0-9_-]` (none evidenced);
  - Management API keys.
- **Accepted false positives:** a `csk-` or `csk_` + exactly 48
  `[A-Za-z0-9_-]` run that is not a key, such as a snake_case identifier of
  exactly that width, or a padded placeholder (the #867 precedent). Rare.

## Issuance checklist (optional confirmation; structure only)

1. Issue one inference key; note whether the Management API key also uses
   `csk-`.
2. Record: prefix (`csk-` or `csk_`), total length (expect 52), body length
   (expect 48), alphabet classes including `_` and `-`,
   `rawValueRetained: false`, revoked.
3. An observed class narrower than the policy class does not narrow the
   contract; a byte outside it re-opens the alphabet.
