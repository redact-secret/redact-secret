# #860 handoff: `composio:api-key`

[#860 handoff index](README.md) ·
[Research table #31](https://github.com/redact-secret/redact-secret/issues/860#issuecomment-5852386808)

**Readiness: READY for all three shapes** (`ak_` project key, `oak_` org key,
`uak_` user key). **Route:** new detector `composio-api-key` with three
finding types.

Step 2 marked `uak_` issuance-gated because a provider CLI code comment shows
`uak_` + 20. Maintainer ruling R6
([2026-09-28](https://github.com/redact-secret/redact-secret/issues/860#issuecomment-5871306275))
makes a code comment T2. The only T1 width for `uak_` is therefore the 43 in
the 2026-09-17 staff statement, and the conflict no longer blocks the
contract. The issuance check below is kept as confirmation. A 20-byte `uak_`
key, if one was ever issued, is an accepted false negative until that check
says otherwise. If the maintainer prefers to keep the step-2 gate, only the
`uak_` shape waits; `ak_` and `oak_` are separable and ship either way (next
section).

## Role and blast radius

Composio is an agent tool platform. Its keys authorize tool calls against
the user's connected third-party accounts (email, calendars, repositories,
CRMs):

- `ak_` — project key (`x-api-key`, `COMPOSIO_API_KEY`), full access to one
  project;
- `oak_` — organization key (`x-org-api-key`, `COMPOSIO_ORG_API_KEY`);
- `uak_` — user key (`x-user-api-key`, `COMPOSIO_USER_API_KEY`), issued by
  `composio login`.

| Prefix | Finding type | Readiness |
| --- | --- | --- |
| `ak_` | `composio_project_api_key` | READY |
| `oak_` | `composio_org_api_key` | READY |
| `uak_` | `composio_user_api_key` | READY (issuance check confirms the width) |

## Are `ak_`/`oak_` separable from `uak_`? Yes

- **Lexically disjoint.** `oak_` and `uak_` contain `ak_`, but the byte
  before that `ak_` is `o` or `u`, which fails the `[A-Za-z0-9_-]` leading
  boundary. So an `ak_` shape can never fire inside an `oak_` or `uak_` key.
  Longest prefix wins at the true start.
- **Different widths.** `ak_`/`oak_` take exactly 20 body bytes and `uak_`
  takes 43. With the trailing boundary, none of them can match a slice of
  another.
- **Independent evidence.** The `ak_` + 20 width also appears in the
  provider's own OpenAPI example (T1 under the existing example ruling). The
  former `uak_` question never touched the `ak_`/`oak_` grammar.

So `ak_`/`oak_` could ship without `uak_` if the maintainer keeps a `uak_`
gate: they would neither claim nor block a `uak_` key.

## Supported shapes

Sources:

- the provider staff statement of **2026-09-17** in
  [trufflehog#5321](https://github.com/trufflesecurity/trufflehog/issues/5321)
  and [gitleaks#2276](https://github.com/gitleaks/gitleaks/issues/2276), by
  Composio's Head of Security: "a fixed prefix followed by URL-safe nanoid
  characters `[A-Za-z0-9_-]`, no checksum: `ak_`+20, `oak_`+20, `uak_`+43"
  (T1 under R3, dated);
- the provider OpenAPI example (`ak_` + 20) and CLI redaction regexes (the
  alphabet), at
  [`3448455`](https://github.com/ComposioHQ/composio/tree/34484551843e575e79cca244d9fca3e4459f59e9);
- the provider docs for the four prefixes and headers.

**Re-checked 2026-09-28:**

- trufflehog PR #5322 (staff-authored) is still open. It was updated
  2026-09-28, and its three regexes are unchanged: 20, 20 and 43 over
  `[A-Za-z0-9_-]`, with a leading non-alphabet guard.
- gitleaks#2276 has had no activity since 2026-09-17.
- No newer provider source contradicts the statement.

| Part | `ak_` | `oak_` | `uak_` |
| --- | --- | --- | --- |
| Prefix | T1 (docs, OpenAPI, SDK) | T1 (docs, OpenAPI) | T1 (docs, SDK constant) |
| Body length | exactly 20: T1 (staff 2026-09-17 + OpenAPI example) | exactly 20: T1 (staff 2026-09-17) | exactly 43: T1 (staff 2026-09-17). A CLI code comment shows 20, which is T2 under R6 and does not override |
| Alphabet | `[A-Za-z0-9_-]` nanoid: T1 (staff + CLI redaction regex) | same | same |
| Separators / checksum | none | none | none |

## The `ak_` short-prefix guard (the one design choice to review)

`ak_` is short, and its alphabet includes `_` and `-`. Without a guard,
`ak_` + a 20-byte snake_case or kebab-case identifier would match (for
example a variable named `ak_` + a 20-letter lowercase word run). The
recommended post check for **`ak_` only**: the body must contain at least one
uppercase letter **and** at least one lowercase letter.

For a uniform 20-byte nanoid body:

- P(no uppercase) = (38/64)^20 ≈ 3.0e-5;
- P(no lowercase) is the same;
- so the false-negative cost is about 6e-5.

The guard removes every all-lowercase or all-uppercase identifier. A digit
requirement was considered and rejected, because P(no digit) ≈ 3.3%.
Residual: a mixed-case 20-byte identifier after `ak_` (camelCase) still
matches. That is recorded as an accepted false positive.

`oak_` and `uak_` are distinctive enough without the guard; applying it to
them too is harmless, at the same 6e-5 cost, if the implementer prefers one
rule.

## Excluded shapes

| Shape | Why excluded |
| --- | --- |
| `ck_` Connect consumer key / scoped project key | secret, but no length or alphabet anywhere |
| `cak_` agent key | seen only as a mock placeholder; shape unknown |
| bkend.ai `ak_` + 64 hex | a different provider. It fails the exact-20 + boundary rule by construction |
| `pr_` + 12 project ids, 12-byte org ids | non-secret identifiers |
| `ak_`/`oak_` bodies of 19 or 21+; `uak_` bodies other than 43 (including a possible legacy 20) | outside the contract |

## Tier rationale

`ak_`/`oak_`: T1 on every fact. The prefixes are on provider pages. Length and
alphabet come from a dated provider-staff statement (R3) that nothing newer
contradicts. The `ak_` width also matches the provider's OpenAPI example.

`uak_`: the prefix is T1 (docs, SDK constant with an executing `startsWith`
branch, R6). Length and alphabet are T1 from the same staff statement. The
contradicting `uak_` + 20 is a code comment (T2 under R6), in a file dated
2025-06 with the line undated. It may show an older short format or an
unrepresentative example. Either way it cannot override a T1 source; it is
recorded as the reason for the confirmation check.

The CLI telemetry redaction regexes (`\buak_[A-Za-z0-9_-]+`,
`\bak_[A-Za-z0-9_-]+`) are provider-authored code in the provider's own
repository, so they are T1 for the alphabet under R2 as well.

## Overlap and output policy

- **Existing detectors.** None claims `ak_`/`oak_`/`uak_`. The ElevenLabs
  tests already use an `ak_` value as a negative control, so no conflict.
  Measured on `main`: named contexts `contextual_secret`, Bearer
  `bearer_token`; bare, chat and JSON `"token"` are missed.
- **New output.** Provider types, high confidence, always redact.
- **Trailing `-`.** A nanoid body can end in `-` (about 1 in 64 keys). The
  exact width plus a boundary check handles it. Tests must include a body
  ending in `-` and in `_` followed by `"`, `,`, a space and end of input.

## Implementation notes

`KnownFormatProviderDetector` with:

- `PrefixShape::exact("ak_", 20, is_alnum_dash, …).with_post_check(mixed_case)`;
- `PrefixShape::exact("oak_", 20, is_alnum_dash, …)`;
- `PrefixShape::exact("uak_", 43, is_alnum_dash, …)`;
- the boundary alphabet `[A-Za-z0-9_-]`.

Three types need per-shape typing.
Signals: `composio-documented-prefix`, `composio-staff-stated-length`.

## Test axes

**Positives** (bodies from a seeded nanoid filler; include bodies starting or
ending with `-` or `_`):

- every index context;
- `x-api-key:` and `x-org-api-key:` headers;
- `Composio(api_key=…)`;
- `COMPOSIO_API_KEY=` and `COMPOSIO_ORG_API_KEY=`;
- a JSON MCP config.

**Near-miss twins:**

- body of 19 or 21;
- a byte outside the alphabet (`.`, `+`);
- an all-lowercase or all-uppercase `ak_` body (unclaimed by the guard);
- `AK_` uppercase prefix;
- `ak-`;
- `ak_` inside `oak_`/`uak_`/`cak_`/`xak_`, which must not produce an `ak_`
  finding;
- `uak_` + 20 and `uak_` + 42/44 (unclaimed);
- a trailing glue byte.

**Benign:**

- `ak_...`, `ck_...`, `ck_test_dummy`, `cak_e2e_agent`;
- bkend.ai `ak_` + 64 hex;
- snake_case identifiers `ak_<20 lowercase/underscore>`;
- `pr_` project ids.

## False-positive / false-negative boundary

- **Accepted false negatives:**
  - a `uak_` key of any width other than 43, such as a possible legacy 20
    (named contexts still redact them);
  - `ck_` and `cak_` keys;
  - `ak_` keys whose random body has no uppercase or no lowercase letter
    (about 6e-5);
  - keys glued to an identifier.
- **Accepted false positives:** `ak_` + a 20-byte mixed-case identifier with
  a boundary on both sides; `oak_` + any 20-byte alphabet run.

## Issuance checklist — confirmation for `uak_` (structure only)

1. Issue one user key with `composio login`. Record: total length, body
   length after `uak_` (**expected 43**), alphabet classes
   (letters, digits, `_`, `-`), `rawValueRetained: false`, revoked.
2. Optionally, the same for one `ak_` and one `oak_` key, to confirm 20.
3. Optionally, `ck_` body length and alphabet, so a later change can add it.

If the body is 43, the contract is confirmed. If it is 20 on a key issued
today, that is a newer provider observation that contradicts the staff
statement: record it, and change the `uak_` width through a follow-up, never
by widening to both. Any other result is recorded as a contradiction.
