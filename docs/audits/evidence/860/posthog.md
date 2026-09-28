# #860 handoff: `posthog:personal-api-key`

[#860 handoff index](README.md) ·
[Research table #38](https://github.com/redact-secret/redact-secret/issues/860#issuecomment-5852386967)

**Readiness: READY.** **Route:** new detector `posthog-token` with two
finding types. **`phc_` stays benign.**

## Role and blast radius

A PostHog personal API key (`phx_`) acts as the user across every
organization and project that user can reach, subject to the scopes chosen at
creation. It is often pasted into agent tooling and MCP servers. A project
secret API key (`phs_`) is a project-scoped secret, used for feature-flag
evaluation, with the same body. The project token (`phc_`) is public by
design ("ok to be public").

| Prefix | Finding type | Decision |
| --- | --- | --- |
| `phx_` | `posthog_personal_api_key` | detect |
| `phs_` | `posthog_project_secret_api_key` | detect: same generator and body, a secret by the provider's docs |
| `phc_` | none | **never claimed**: public project token |
| `pha_` / `phr_` | none (deferred) | OAuth access/refresh tokens: T1 in code but short-lived and outside #860's candidate. A follow-up if wanted |

## Supported shapes

Sources:

- provider code `posthog/models/utils.py` at
  [`658715d`](https://github.com/PostHog/posthog/blob/658715dd3b434e0a5ada471981d4053b70e72034/posthog/models/utils.py):
  `PERSONAL_API_KEY_PREFIX = "phx_"`, `generate_random_token_personal()` =
  prefix + `generate_random_token(35)`, and base57 encoding of a 280-bit value
  with the top bit forced;
- the earlier eras at tags and at `d610b45e4c72` (base62, no forced bit);
- the unit tests `test_uses_base57_alphabet` and `test_exact_length`;
- provider docs for the `phx_`/`phs_`/`phc_` roles.

**Re-checked 2026-09-28:** `utils.py` was last changed 2026-09-16
([`658715d`](https://github.com/PostHog/posthog/commit/658715dd3b434e0a5ada471981d4053b70e72034)).
BASE57 (base62 minus `0 1 O I l`), the forced top bit and the 35-byte
personal-key call are unchanged.

Every issued era can still be live (rotation is optional), so the contract is
the union of the prefixed eras.

| Era | Body length | Alphabet | Source | Tier |
| --- | --- | --- | --- | --- |
| since 2026-03-30 ([PostHog PR 52495](https://github.com/PostHog/posthog/pull/52495)) | 48 or 49 (49 ≈ 2.9%) | base57 `[2-9A-HJ-NP-Za-km-z]` | generator + unit test | T1 (R1) |
| until 2026-03-30 (35-byte base62) | at most 48 (47 ≈ 88.6%, 48 ≈ 10%, 46 ≈ 1.4%, 45 ≈ 0.02%) | `[0-9A-Za-z]` | generator at `d610b45e4c72` | T1 (R1) |
| by 1.30.0 through an unpinned date (32-byte base62) | at most 43 (43 ≈ 98.4%, 42 ≈ 1.6%, 41 ≈ 0.03%) | `[0-9A-Za-z]` | generator at tags 1.30.0 and 1.43.0 | T1 (R1) |

The per-length shares are derived from the T1 algorithm (a uniform integer
of a known bit width rendered in base 62 or 57). They agree with the research
table's computation.

**Contract:** `phx_` or `phs_` + **42–49** bytes of `[0-9A-Za-z]`; no
separator, no checksum. The 42 floor keeps the ≈1.6% of 32-byte-era keys that
render at 42. Everything shorter is below 0.03% of any era's keys and is left
out. That is a deliberate precision choice: the prefix alone justifies the
band. The research's `{43,49}` union would miss the 42-byte keys.

## Excluded shapes

| Shape | Why excluded |
| --- | --- |
| `phc_` + base57/base62 body (fixed 44 in the base57 era) | public by design; **must stay benign**. GitLab's ruleset flags it, which is a false positive under this repository's policy |
| era-1 unprefixed personal keys (`token_urlsafe(32)`, 43 bytes of `[A-Za-z0-9_-]`) | no prefix, so not lexically attributable; generic context covers named assignments |
| `phx_`/`phs_` bodies of 41 or fewer, or 50 or more | below 0.03% of any era, or not issued |
| `pha_`, `phr_`, `phh_` | outside this handoff (see above) |
| `phx_` followed by `_` or `-` inside the body | not in any era's alphabet |

## Tier rationale

- Prefix: T1 from docs and code.
- Alphabet and algorithm: T1 from code and unit test (R1).
- Length band: derived from the T1 algorithm.
- The SDK error string ("These keys are prefixed with `phx_`") corroborates
  the prefix and the `phc_`/`phx_` distinction.
- Scanner rules lag the grammar and are not used: trufflehog stops at 48 and
  misses 49-byte keys; GitLab uses 43 only.

## Overlap and output policy

- **Existing detectors.** None claims `phx_`/`phs_`/`phc_`. Measured on
  `main`: named contexts `contextual_secret`, Bearer `bearer_token`; bare, chat
  and JSON `"token"` are missed. Under a credential-named key, generic
  detection also redacts a `phc_` project token today. That is
  `generic-token`'s name-driven verdict and is not changed here.
- **New output.** Two provider types, high confidence, always redact. The new
  detector itself never emits a finding for `phc_`.

## Implementation notes

`KnownFormatProviderDetector` with two shapes, `phx_` and `phs_`, each with
`OneOf([49, 48, 47, 46, 45, 44, 43, 42])` over `is_alnum` (or an equivalent
bounded-range run) and the `[A-Za-z0-9_-]` boundary, so a 50+ run is rejected
rather than truncated. Two types need two tables or a per-shape type.
Signals: `posthog-documented-prefix`, `posthog-generator-length-band`.

## Test axes

**Positives:**

- base57 bodies of 48 and 49;
- base62 bodies of 42, 43, 46, 47 and 48;
- both prefixes;
- every index context plus `POSTHOG_PERSONAL_API_KEY=`, an MCP config, and an
  `Authorization: Bearer` curl to `/api/projects/`.

**Near-miss twins:**

- body of 41 and 50;
- a `_` or `-` inside the body;
- `phx-`/`PHX_`/`ph_`/`phy_` prefixes;
- a leading glue byte (`xphx_…`) and a trailing glue byte.

**Benign** (unclaimed by the new detector):

- **`phc_` project tokens** of 43 and 44 bytes, bare, in a `posthog.init('phc_…')`
  browser snippet, and in HTML;
- `phx_...` / `phx_***1234` masked displays;
- `POSTHOG_API_KEY=${…}`;
- PostHog host URLs.

## False-positive / false-negative boundary

- **Accepted false negatives:**
  - base62-era keys that rendered at 41 bytes or fewer;
  - era-1 unprefixed keys outside named contexts;
  - OAuth and heatmap tokens;
  - self-hosted forks with changed generators.
- **Accepted false positives:** an unrelated `phx_`/`phs_` + 42–49
  alphanumeric value. No such convention was found.

## Issuance checklist (optional confirmation; structure only)

For one personal key issued today:

- body length (expect 48 or 49);
- confirm there is no `0`, `1`, `O`, `I` or `l`;
- `rawValueRetained: false` and revoked.

Optionally, the body length of a project secret key.
