# #860 handoff: `nvidia:ngc-api-key`

[Tier B re-rank](tier-b-rerank.md) ·
[Research table #01](https://github.com/redact-secret/redact-secret/issues/860#issuecomment-5852386450) ·
[Issuance research](issuance-research/nvidia.md)

**Readiness: READY, with an open-ended body** (closed by research under the
existing rulings, 2026-09-28; was ISSUANCE-GATED). **Route:** new detector
`nvidia-api-key`, finding type `nvidia_api_key`. Scheduled for Beta.12; no
detector code merges to `main` until `0.1.0-beta.11` is released.

The provider's own grammar is a prefix, an alphabet and a floor. No provider
source states an exact width. The contract uses the provider's open-ended
rule and adds a cap as project policy, following the
[Apify precedent](apify.md).

## Role and blast radius

An NVIDIA API key (`NVIDIA_API_KEY`, `NGC_API_KEY`, sent as
`Authorization: Bearer`) is issued as an NGC Personal key, an NGC Service
key or a build.nvidia.com key. It calls hosted NIM inference endpoints on
the account's credits and, depending on its scopes, pulls private NGC
registry artifacts and manages NGC organization resources. All three share
the `nvapi-` prefix.

## Supported shape

Sources (all re-checked 2026-09-28; the full table is in the
[issuance research](issuance-research/nvidia.md)):

- **Prefix.** NVIDIA docs ("typically start with nvapi-") and the ngcsdk
  CLI constant `SCOPED_KEY_PREFIX = "nvapi-"` with an executing
  `startswith` (R1, R6).
- **Alphabet and floor, R2.** A provider-authored secret-scan rule in
  [NVIDIA-NeMo/nemo-helix `pii_scan.py`](https://github.com/NVIDIA-NeMo/nemo-helix/blob/689f7852611b0151cee2748ca2b68e8e163e3b65/plugins/nemo-agents/src/nemo_agents_plugin/skills/agents-secure/resources/pii_scan.py#L229-L232)
  (added 2026-05-21): `\bnvapi-[A-Za-z0-9_\-]{60,}\b`. A second NVIDIA rule,
  a custom gitleaks block in
  [NVIDIA/SkillEvaluator](https://github.com/NVIDIA/SkillEvaluator/blob/a2636b2f886235f974ed4329029f923a12d0328b/src/skillevaluator/validators/secrets.py#L57-L60),
  is `nvapi-[A-Za-z0-9_-]{40,}`. Every other NVIDIA redaction rule uses the
  same class with a lower floor, except one looser redaction superset that
  also admits `.`. None contradicts the 60 floor.

**R2 authorship.** Both rules are in NVIDIA-owned organizations, written by
NVIDIA contributors, and neither is a verbatim copy of a public scanner rule.
The `{60,}` floor equals the lower end of betterleaks' `{60,70}` (added
2026-02-25). The form differs (case-sensitive, no cap, a PII-scanner
entry), so R2 applies; the possible influence is recorded in the research.

| Part | Grammar | Provenance | Tier |
| --- | --- | --- | --- |
| Prefix | `nvapi-` | provider docs + ngcsdk constant (R1, R6) | T1 |
| Alphabet | `[A-Za-z0-9_-]` | provider-authored rules (R2) | T1 |
| Length | at least 60, open-ended | provider-authored rule (R2) | T1 (floor) |
| Upper bound | 128 | project policy: a bounded run for streaming; the tool-verified width is 64 | policy |
| Separators / checksum | none | — | — |

## Excluded shapes

| Shape | Why excluded |
| --- | --- |
| Legacy NGC key (84 non-space characters, no prefix; used as the password for the `$oauthtoken` registry user) | no prefix; its structure is tool-inferred. Context-anchored only; generic context covers `NGC_API_KEY=` |
| `nvapi-` + fewer than 60 bytes | below the provider floor; NVAPI SDK and crate names (`nvapi-sys`, `nvapi-rs` style) and short test fixtures live here |
| Placeholders `nvapi-...`, `nvapi-xxxx`, `nvapi-<your-key>` | below the floor, or a byte outside the alphabet |
| A body containing `.` | only one NVIDIA redaction rule admits it; the trailing boundary rejects the run rather than truncating it |
| Body over 128 bytes | over-long run: an intentional false negative, never truncated |

## Overlap and output policy

- **Existing detectors.** None claims `nvapi-`. Measured on `main` (the
  re-rank probe):
  - env, `export`, `X-API-Key`, JSON `api_key` and the SDK keyword argument
    give `contextual_secret`, high;
  - Bearer gives `bearer_token`, high;
  - bare, chat and JSON `"token"` are missed.
- **New output.** Provider type, `Confidence::High`, `ALWAYS_REDACT_TYPES`.
- **`generic-token` deferral.** `nvidia` and `ngc` are not added. Deferring
  would silence the legacy 84-character key under `NGC_API_KEY`.

## Implementation notes

`KnownFormatProviderDetector` with
`PrefixShape::at_least("nvapi-", 60, pattern::is_alnum_dash, …)`, plus a post
check capping the run at 128. The boundary is `[A-Za-z0-9_-]` on both sides;
because the body class already includes `_` and `-`, the scan takes the
whole run and rejects it when it is under 60 or over 128.

Signals: `nvidia-documented-prefix`, `nvidia-provider-rule-floor`.

## Test axes

**Positives:**

- every context in the re-rank's probe list;
- `NVIDIA_API_KEY=` and `NGC_API_KEY=` in `.env`;
- `ChatNVIDIA(api_key="…")` and an OpenAI-compatible client with
  `base_url="https://integrate.api.nvidia.com/v1"`;
- `curl -H "Authorization: Bearer …"`;
- body lengths 60, 64, 70 and 128, including bodies with `_` and `-`.

**Near-miss twins:**

- body of 59;
- body of 129;
- a `.` inside the body;
- `NVAPI-` uppercase prefix;
- `nvapi_`;
- a leading glue byte (`xnvapi-…`, `_nvapi-…`).

**Benign:**

- the placeholders and SDK names above;
- `nvapi-` alone at end of line;
- a 64-byte run under a different prefix.

## False-positive / false-negative boundary

- **Accepted false negatives:**
  - a key class shorter than 60 (none known);
  - a body with a byte outside `[A-Za-z0-9_-]`;
  - over-long runs;
  - the legacy 84-character key outside named contexts.
- **Accepted false positives:** `nvapi-` + 60–128 `[A-Za-z0-9_-]` that is not
  a key, such as a padded placeholder. That follows the #867 placeholder
  precedent.

## Issuance checklist (optional narrowing; structure only)

For one NGC Personal key, one NGC Service key and one build.nvidia.com key,
record:

- total length and body length after `nvapi-` (trufflehog expects 64);
- alphabet classes, including whether `-` or `_` appears;
- `rawValueRetained: false`, revoked.

A uniform width across all three would allow an exact-width contract later,
as a separate optional change.
