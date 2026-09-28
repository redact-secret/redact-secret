# #860 handoff: `apify:api-token`

[Tier B re-rank](tier-b-rerank.md) ·
[Research table #13](https://github.com/redact-secret/redact-secret/issues/860#issuecomment-5852386571)

**Readiness: READY, with an open-ended body.** **Route:** new detector
`apify-api-token`, finding type `apify_api_token`.

The provider's own grammar is a prefix, an alphabet and a floor. No provider
source states an exact length. The contract therefore uses the provider's
open-ended rule rather than trufflehog's exact 36, which is T2. An issuance
check could later narrow it, but nothing requires that.

## Role and blast radius

An Apify API token (`APIFY_TOKEN`, sent as `Authorization: Bearer`) runs
Actors (scrapers and agent tools) on the account's compute budget. It reads
datasets, key-value stores and the account's stored integration secrets.
Personal, organization and scoped tokens share the prefix.

## Supported shape

Sources:

- **Prefix, R4 and R6.** The Apify docs placeholders are `apify_api_...`
  (`apify-docs` Hermes and OpenClaw pages). R4 makes a placeholder T1 for
  its prefix. Provider code in `apify-mcp-server` separates `apify_ui_`
  Console tokens "as opposed to `apify_api_...` API tokens". Its runtime
  check is a `startsWith(UI_TOKEN_PREFIX)` branch, which R6 makes T1 for
  `apify_ui_`. The comment naming `apify_api_` stays T2 under R6, but the
  docs placeholder already carries that prefix.
- **Alphabet and floor, R2.** The provider leak linter in
  [`apify/awesome-skills`](https://github.com/apify/awesome-skills/blob/main/scripts/lint_references.py)
  is `TOKEN_RE = re.compile(r"apify_api_[A-Za-z0-9]{20,}")`. Its
  `SECURITY.md` says CI fails on any such token.

**R2 authorship check (2026-09-28).** R2 requires that the provider wrote
the rule; a vendored public scanner rule stays T2.

- The rule was added in
  [`4ba9177`](https://github.com/apify/awesome-skills/commit/4ba9177da814)
  ("feat(ci): reference, telemetry and catalog-revalidation lints",
  2026-08-12).
- Its author is Pavel Chocholouš (`chocholous`). He is a `COLLABORATOR` on
  the repository, with about 150 commits across the `apify` organization.
- The regex matches no public scanner rule. gitleaks has no Apify rule, and
  trufflehog's is `apify\_api\_[a-zA-Z-0-9]{36}`: different class, exact
  width.

So the rule is provider-authored, and T1 under R2.

| Part | Grammar | Provenance | Tier |
| --- | --- | --- | --- |
| Prefix | `apify_api_` | docs placeholders (R4) | T1 |
| Alphabet | `[A-Za-z0-9]` | provider leak linter (R2) | T1 |
| Length | at least 20, open-ended | provider leak linter (R2) | T1 (floor) |
| Upper bound | 128 | project policy: a bounded run for streaming; the only observed width is 36 | policy |
| Separators / checksum | none | — | — |

## Excluded shapes

| Shape | Why excluded |
| --- | --- |
| `apify_ui_` Console session tokens | prefix T1 (R6), but no length or alphabet source; generic context covers the named forms. A later issuance check could add it as a second type |
| Actor Run, Integration, Webhook Dispatch API tokens | GitHub scans for them; no shape is public |
| Proxy password (14 alphanumeric, no prefix, OpenAPI example) | not attributable |
| `apify_api_YOUR_TOKEN`, `apify_api_test_token`, `apify_api_invalid_token`, `apify_api_dummy_for_smoke`, `apify_api_...` | placeholders: `_` or `.` breaks the run below 20, and the trailing boundary rejects |
| `apify_api_error`, `APIFY_API_BASE_URL` (lowercased stem) | identifiers: too short, and `APIFY_API_` does not match because the prefix is case-sensitive |
| Body over 128 bytes | over-long run: an intentional false negative, never truncated |

## Overlap and output policy

- **Existing detectors.** None claims `apify_`. Measured on `main`:
  - env, `export`, `X-API-Key`, JSON `api_key` and the SDK keyword argument
    give `contextual_secret`, high;
  - Bearer gives `bearer_token`, high;
  - bare, chat and JSON `"token"` are missed.
- **New output.** Provider type, `Confidence::High`, `ALWAYS_REDACT_TYPES`.
- **`generic-token` deferral.** `apify` is not added. Deferring would silence
  `apify_ui_` and the unprefixed sibling tokens under `APIFY_*` names.

## Implementation notes

Use `KnownFormatProviderDetector` with
`PrefixShape::at_least("apify_api_", 20, pattern::is_alnum, …)`, plus a post
check capping the run at 128. The boundary is `[A-Za-z0-9_-]`, so a `_` or
`-` glued after the run rejects the match. That is what keeps
`apify_api_token_here` unclaimed.

Signals: `apify-documented-prefix`, `apify-provider-lint-floor`.

## Test axes

**Positives:**

- every context in the re-rank's probe list;
- `APIFY_TOKEN=` in `.env`;
- `ApifyClient({ token: "…" })` and `ApifyClient("…")`;
- an MCP server config (`apify-mcp-server` `env`);
- body lengths 20, 36 and 128.

**Near-miss twins:**

- body of 19;
- body of 129;
- a `_` or `-` glued after the run;
- `APIFY_API_` uppercase prefix;
- `apify-api-`;
- a leading glue byte (`xapify_api_…`).

**Benign:**

- the placeholders and identifiers above;
- `apify_ui_test`;
- `APIFY_TOKEN=${{ secrets.APIFY_TOKEN }}`;
- `apify_api_` alone at end of line.

## False-positive / false-negative boundary

- **Accepted false negatives:**
  - a token whose body contains `-` or `_` (trufflehog's class admits `-`,
    but the provider's own rule does not);
  - over-long runs;
  - `apify_ui_` and the unprefixed sibling tokens outside named contexts.
- **Accepted false positives:** `apify_api_` + 20–128 alphanumerics that is
  not a token, such as a padded placeholder of exactly alphanumeric filler.
  That follows the #867 placeholder precedent.

## Issuance checklist (optional narrowing; structure only)

For one personal, one organization and one scoped token, record:

- total length and body length (trufflehog expects 36);
- alphabet classes, and whether `-` or `_` ever appears;
- `rawValueRetained: false`, revoked.

A uniform 36 across all three would allow an exact-width contract later.
That would be a separate, optional change.
