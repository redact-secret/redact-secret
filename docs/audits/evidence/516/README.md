# Issue #516 — Vercel credential taxonomy audit (`vcp_`, `vci_`, `vca_`, `vcr_`, `vck_`)

[Audit archive](../../README.md) ·
[Precision-contract freeze (#367)](../../../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) ·
[Precision contracts: `vercel-token` family](../../../contracts/precision/precision-contracts.json) ·
[Issue #516](https://github.com/redact-secret/redact-secret/issues/516) ·
[Issue #501 (parent epic, B1e)](https://github.com/redact-secret/redact-secret/issues/501) ·
[Issue #487 (Google OAuth, audit-only precedent)](https://github.com/redact-secret/redact-secret/issues/487)

Reviewed 2026-09-20 against this repository's `main`. This is an evidence-tier
review, not a detector change: it adds no `PrefixShape`, no new finding type,
no fixture, and no runtime code. `crates/secret-scan-core/src/detectors/additional_providers.rs`'s
`VERCEL` detector is unchanged by this issue.

## Summary

Issue #501 (Epic B, B1e) named `vercel-token` as T0: "a detector exists but
the contract does not." Issue #516 asks for the audit before any grammar
change — where the corpus's five prefixed shapes came from, what the pinned
TruffleHog detector's bare 24-character contextual rule corresponds to, and
which classes have enough lexical evidence to contract.

**Resolved, not averaged:**

- The five prefixes in the corpus (`vcp_`, `vci_`, `vca_`, `vcr_`, `vck_`) are
  **real and provider-documented**, not an invented or copied shape. They
  trace to Vercel's own changelog, "Introducing new token formats and secret
  scanning" (2026-02-09), which this project's pre-Rust `_notes/` tree already
  cited before the Rust port (`git show d1a8ed3:_notes/features/known-format-detection/README.md`).
  Reverified live today against the same changelog and three further Vercel
  documentation pages: all five prefixes still hold, unchanged.
- TruffleHog's pinned Vercel detector (`v3.97.4`, unchanged at the latest tag
  `v3.97.5`) does **not** conflict with the five prefixes by being wrong or
  stale — it targets a **different, real, currently-documented** Vercel
  credential surface: the bare, unprefixed, exactly-24-character
  `access_token`/`client_secret` pair returned by Vercel's own OAuth
  integration `code`-exchange endpoint (`POST /v2/oauth/access_token`),
  confirmed by a Vercel docs page updated 2026-09-16 — five weeks after the
  prefix rollout. Two genuinely different credential surfaces exist side by
  side; TruffleHog only covers the older, unprefixed one, and that one is
  lexically opaque (no fixed prefix) so it is not a candidate for a dedicated
  `vercel-token` shape regardless.
- GitHub's secret-scanning partner-pattern listing corroborates **six** Vercel
  token types, one more than the changelog's five: a "Vercel Support Access
  Token" with no prefix, example, or shape published anywhere consulted. This
  sixth class is recorded `unsupported` (opaque, existence-only), per #501's
  own instruction not to force a detector for an opaque credential.
- No pinned tool (gitleaks 8.30.1, TruffleHog 3.97.4/3.97.5, flare-redact
  1.6.1) registers a rule for any of the five prefixed shapes. Vercel's own
  documentation gives a literal prefix rule for `vcp_` and `vck_`, and one
  single-instance body example shared identically between `vca_` and `vcr_`;
  no source states a body length or alphabet rule in prose for any of the
  five. **All five stay pending (T0)** — the same disposition #501 already
  recorded, now for a resolved, documented reason instead of an open
  conflict. `VERCEL`'s existing `at_least(20, is_alnum_dash)` shape for each
  prefix is unchanged: it is already broader (and therefore already
  false-negative-safe) than every example this audit found, so no
  tightening or loosening is justified by this evidence.

| Class | Prefix evidence | Body evidence | Disposition |
| --- | --- | --- | --- |
| Personal access token | T1 — provider states the literal rule | none (masked placeholder only) | pending, T0 |
| Integration access token | T1 — changelog + GitHub partner listing | none found anywhere | pending, T0 |
| App (user) access token | T1 — changelog + GitHub partner listing | one single-instance doc example (56 bytes) | pending, T0 |
| App refresh token | T1 — changelog + GitHub partner listing | same single instance as above, not independent | pending, T0 |
| API key (AI Gateway) | T1 — provider example (`vck_...`) | none found anywhere | pending, T0 |
| Support access token | none — GitHub partner listing only | none | **unsupported** (opaque) |
| Bare 24-char OAuth `access_token`/`client_secret` | none — unprefixed by design | provider example + TruffleHog tool-agreement, both 24 bytes alphanumeric | **excluded** (unprefixed, indistinguishable from an arbitrary identifier; covered only incidentally by `generic-token`) |

## Provenance of the five prefixed corpus shapes

Traced through git history rather than assumed. The Rust `VERCEL` detector
was introduced verbatim by `d5d3d356` ("port known-format provider
detectors", 2026-09-09), whose issue (#17) required porting "every qualified
provider-token detector to Rust **without expanding its grammar**" — i.e. the
five prefixes predate the Rust core. The pre-Rust `_notes/features/known-format-detection/README.md`
(present through commit `d1a8ed3`, 2026-08-31, removed when `_notes/` was
retired during the Rust migration) already carried this exact row:

> Vercel | **Supported:** `vcp_`, `vci_`, `vca_`, `vcr_`, and `vck_` plus at
> least 20 alphanumeric, underscore, or hyphen characters. | The prefixes
> were introduced for visual identification and secret scanning. ... |
> [new token formats](https://vercel.com/changelog/new-token-formats-and-secret-scanning),
> [access-token example](https://vercel.com/docs/sign-in-with-vercel/tokens#access-token)

Both cited URLs are real, current Vercel-owned pages (reverified live below).
The five prefixes were not fabricated or guessed at any point in this
project's history — they were sourced from Vercel's own announcement from the
start, and this audit's job is to check whether that sourcing still holds and
whether it supports more than the existing minimum-length shape.

## Evidence, per source

### Vercel's own documentation

- **`vercel-changelog-token-formats`** (`vercel.com/changelog/new-token-formats-and-secret-scanning`,
  published 2026-02-09, reobserved 2026-09-20). States: "Each credential type
  now includes a prefix: `vcp` for Vercel personal access tokens, `vci` for
  Vercel integration tokens, `vca` for Vercel app access tokens, `vcr` for
  Vercel app refresh tokens, `vck` for Vercel API keys." Also states this
  detection "is powered by GitHub secret scanning." No length or alphabet for
  any prefix's body.
- **`vercel-docs-access-tokens`** (`vercel.com/docs/accounts/access-tokens`,
  last updated 2026-09-08). States directly, in prose: "Personal access
  tokens begin with the prefix `vcp_`" — the strongest single-property claim
  found for any of the five (T1, prefix only). Shows a masked example,
  `vcp_xxxxxxxxxxxxxxxxxxxxxxxx` (24 literal `x` filler characters after the
  prefix). This is a redaction placeholder in a `curl` snippet, not a
  generated example value — the same category of evidence this file already
  declines to treat as establishing a real length (compare the Slack
  `xoxp-111-222-333-...` numeric placeholders in `families.slack-token`,
  `doesNotEstablish: "numeric section widths (the examples use placeholders)"`).
  It is not used to fix `vcp_`'s body length here for the same reason.
- **`vercel-docs-sign-in-tokens`** (`vercel.com/docs/sign-in-with-vercel/tokens`,
  last updated 2026-03-30). Shows a real "Access Token example" (`vca_`) and
  a real "Refresh Token example" (`vcr_`), both carrying the **identical**
  56-byte mixed-case alphanumeric body `BQuu9ChDu3n6Pfh6YQnCshpoYkWDSFKogLqmBtQ0tC8NAA5rXt340sjz`
  (no `-`/`_` in this instance). Because both examples reuse the same string,
  this is one documented instance, not two independent ones, and the page
  states no length or alphabet rule in prose — the body's own basis stays
  "provider (one instance), not corroborated," parallel to how
  `families.google-api-key.variants[0]`'s `AIza` body treats its "one
  example" origin, except that entry additionally has two-tool corroboration
  this Vercel instance has none of. One instance does not promote a shape
  past T0 in this file's framework on its own.
- **`vercel-docs-ai-gateway-api-keys`** (`vercel.com/docs/ai-gateway/authentication-and-byok/api-keys`,
  last updated 2026-09-08). Confirms the `vck_` prefix via a compromised-secret
  report request body: `{ "secret": { "api_key": "vck_..." } }`. No length or
  alphabet.
- **`vercel-docs-api-integrations`** (`vercel.com/docs/integrations/create-integration/vercel-api-integrations`,
  last updated 2026-09-16 — five weeks *after* the prefix changelog). Its
  OAuth `code`-exchange example (`POST /v2/oauth/access_token`) shows a
  request with `client_secret=EOBPvZuBYAtb3SbYo8H1iWFP` (24 bytes,
  alphanumeric, no prefix) and a JSON response
  `"access_token": "xEbuzM1ZAJ46afITQlYqH605"` (24 bytes, alphanumeric, no
  prefix). This page was updated after the prefix rollout and still shows an
  unprefixed value — this is not a stale, unmaintained example; it documents
  a real, currently-supported credential surface distinct from the five
  prefixed classes, and it is the direct match for TruffleHog's rule below.
- **`vercel-rest-api-reference`** (`vercel.com/docs/rest-api`, last updated
  2026-09-21). Confirmed to be purely an endpoint index (method/path/description
  tables per resource group, including an `authentication` section listing
  only endpoint rows). No prose anywhere on the page states a token prefix,
  length, or alphabet for any credential — consistent with issue #516's own
  framing that "the Vercel REST API reference states no prefix, length or
  alphabet at all."

### Pinned tool sources

- **TruffleHog** (`pkg/detectors/vercel/vercel.go`, fetched directly at the
  pinned tag `v3.97.4` and diffed byte-for-byte against the latest tag
  `v3.97.5` — identical, unchanged): `keyPat = PrefixRegex(["vercel"]) +
  \b([a-zA-Z0-9]{24})\b`. This requires the literal keyword `vercel` nearby
  (contextual, not a fixed credential prefix) and matches a bare,
  exactly-24-character alphanumeric body. It is the exact match for
  `vercel-docs-api-integrations`'s unprefixed `access_token`/`client_secret`
  example above, and registers no rule of any kind for any of the five
  `vc*_`-prefixed shapes.
- **gitleaks** (`config/gitleaks.toml`, pinned tag `v8.30.1`, also the latest
  tag). Searched the full 3209-line file directly for `vercel`: zero matches.
  No Vercel rule of any kind exists.
- **flare-redact** (`spec/detectors.json`, pinned tag `v1.6.1`). Parsed
  directly: zero `vercel`-related detector entries.
- **GitHub secret-scanning partner patterns** (`docs.github.com/en/code-security/secret-scanning/introduction/supported-secret-scanning-patterns`,
  reobserved 2026-09-20). Lists six Vercel rows, all with push protection
  except one: Vercel API Key, Vercel App Refresh Token (no push protection),
  Vercel App User Access Token, Vercel Integration Access Token, Vercel
  Personal Access Token, and **Vercel Support Access Token**. The table gives
  type names and push-protection status only — no prefix, regex, or format
  detail for any row, the same reading this file already applies to this
  source for other providers. Five of the six names map one-to-one onto the
  changelog's five prefixes ("App User Access Token" = `vca_`'s "app access
  token," matching how `vercel-docs-sign-in-tokens` labels the same OAuth
  flow's access token). The sixth, **Support Access Token**, has no
  corresponding prefix in the changelog and no shape in any source consulted
  by this audit — existence-only corroboration, identical in kind to how this
  file already reads GitHub's Cloudflare Global User API Key row
  (`families.cloudflare-token.excluded` → `cfk_`) and Google's OAuth rows
  (`families.google-api-key.pending`).

## The TruffleHog conflict, resolved

Issue #516 frames the pinned TruffleHog rule and the corpus's five prefixes
as conflicting evidence for the same credential. They are not the same
credential. `vercel-docs-api-integrations`, updated 2026-09-16, shows the
OAuth integration `code`-exchange flow still issuing bare, unprefixed
24-character `access_token` and `client_secret` values, five weeks after the
prefix changelog shipped. TruffleHog's rule is accurate for that surface, not
stale. Reading it as evidence against the five prefixed classes would be
averaging two different questions into one; instead:

- The five prefixed classes (`vcp_`, `vci_`, `vca_`, `vcr_`, `vck_`) are
  unaffected by TruffleHog's rule one way or the other — no tool registers a
  rule for any of them, prefixed or not.
- The bare, unprefixed 24-character OAuth class TruffleHog does cover is
  **excluded**, permanently, from a lexical `vercel-token` grammar: without a
  fixed prefix it is indistinguishable from an arbitrary 24-character
  identifier, the same reasoning this file already applies to Linear's
  `unprefixed-oauth-access-token` (`families.linear-token.excluded`) and to
  Google's unprefixed OAuth candidates generally. It stays covered only
  incidentally by `generic-token`'s contextual rule when a high-signal key
  name or the literal word "vercel" triggers it — exactly the keyword gate
  TruffleHog's own rule already requires.

## Disposition

Recorded in `docs/audits/evidence/367/precision-contracts.json`'s new
`vercel-token` family:

- **`personal-access-token`** (`vcp_`), **`integration-access-token`**
  (`vci_`), **`app-access-token`** (`vca_`), **`app-refresh-token`** (`vcr_`),
  **`api-key`** (`vck_`): all `pending`, tier `T0`. Prefix existence and
  literal spelling are provider-documented (T1-quality for that one
  property), but no source — provider or tool — states a body length or
  alphabet, so none can be tightened past the existing conservative
  `at_least(20, is_alnum_dash)` floor without guessing. Unblocking condition,
  identical in kind to this file's existing Supabase/Cloudflare precedents:
  promote any one of these to a scored contract once either (a) a shipped
  gitleaks or TruffleHog release registers a rule for that specific prefix,
  or (b) Vercel's own documentation states one body length/alphabet rule in
  prose for that prefix (not a placeholder or a single reused example).
- **`support-access-token`**: `excluded`, existence-only (GitHub partner
  listing), no prefix or shape published anywhere. This is not scored as
  `pending` because there is nothing pending on — no candidate grammar of any
  kind exists to revisit later; a future Vercel documentation update naming
  its prefix would be a new fact, not a resolution of anything recorded here.
- **`bare-oauth-access-token`**: `excluded`. Unprefixed by design; not a
  candidate for a dedicated shape regardless of future tool corroboration,
  matching the Linear/Google precedent above.

## What does not change

- `crates/secret-scan-core/src/detectors/additional_providers.rs`'s `VERCEL`
  detector: unchanged. Its five `PrefixShape::at_least(_, 20, is_alnum_dash,
  ...)` shapes remain a safe floor — broader than every example this audit
  found (the one real 56-byte body example and the 24-character placeholder
  both already satisfy `>= 20`), so nothing here is loosened, tightened, or
  renamed.
- No fixture, coverage declaration, or policy entry changes; `vercel-token`'s
  coverage-report status (`supported`, per `docs/coverage/coverage-report.md`)
  is a registration-completeness measure and is unaffected by this
  evidence-tier finding.
- Per #501's own framing and this issue's acceptance criteria, any detector
  change this audit's findings might motivate (for example, if a future
  gitleaks/TruffleHog release or Vercel documentation update resolves a
  pending class to a scored contract) is scoped to a separate issue, not this
  one.
