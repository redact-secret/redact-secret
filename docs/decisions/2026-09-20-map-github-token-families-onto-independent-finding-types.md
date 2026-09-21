---
decision_id: decision-map-github-token-families-onto-independent-finding-types
status: accepted
scope: workspace
title: Map GitHub's six token families onto six independent finding types under one detector
decided_at: 2026-09-20
---

# Map GitHub's six token families onto six independent finding types under one detector

## Decision

Issue #517 (B1f, under Epic #501) asks that GitHub's credential surface be
audited "per family rather than per prefix regex," so that a future support
matrix (#500/#501, whose taxonomy is #502) can "state per-family status
rather than one `github-token` verdict." Before this decision, every one of
`github.rs`'s six documented prefixes emitted the same finding type,
`github_token`, collapsing six credentials with different issuance paths and
different blast radii into one undifferentiated row.

Applied to the six families #502's taxonomy names for GitHub:

| Family | Prefix | Finding type | Detector |
|---|---|---|---|
| Classic personal access token | `ghp_` | `github_token` (unchanged name) | `github-token` |
| OAuth access token | `gho_` | `github_oauth_token` (new) | `github-token` |
| GitHub App user-to-server token | `ghu_` | `github_app_user_to_server_token` (new) | `github-token` |
| GitHub App server-to-server (installation) token | `ghs_` | `github_app_installation_token` (new) | `github-token` |
| GitHub App refresh token | `ghr_` | `github_app_refresh_token` (new) | `github-token` |
| Fine-grained personal access token | `github_pat_` | `github_fine_grained_personal_access_token` (new) | `github-token` |

All six keep the single `github-token` detector id: this is the same "one
detector, several declared types" shape `generic-token` already uses for
`contextual_secret`/`authorization_credential`, and nothing about the family
split requires a second detector registration, a change to
`built_in_detectors()`'s canonical order, or a change to
`BUILT_IN_PACKS`/`built_in_ids()` (`crates/secret-scan-core/src/detectors/mod.rs`).

`ghp_` keeps its pre-existing type name, `github_token`, rather than being
renamed to something more parallel (e.g. `github_classic_personal_access_token`).
It is the only one of the six with prior, independently evidenced fixtures
and with generic cross-cutting infrastructure tests keyed to that literal
string (`crates/secret-scan-core/tests/{overlap_resolution,policy_redaction,
public_api}.rs`, `crates/secret-scan-core/src/{types,redact}.rs`,
`crates/secret-scan-cli/{src/report.rs,src/main.rs,src/modes.rs,tests/cli.rs}`,
`assessment/`). None of those tests assert anything GitHub-specific — `ghp_`
is simply their one example of "some provider-shaped token" — so renaming it
would touch a dozen files of unrelated infrastructure for no correctness
gain, exactly the kind of unscoped churn `decision-scope-supabase-management-
token-and-secret-key-independence.md` avoided by leaving `sb_secret_`'s type
name alone. Every other family is new-to-be-distinguished, so it gets a type
name that says what it is.

## Rationale

### Why a family split, not a name change alone

The whole point of #502's taxonomy is that a support-matrix consumer can ask
"is GitHub's OAuth token family covered?" and get an answer that is not
silently averaged with five other families' evidence. That requires the
finding *type* to vary per family (a matrix joins on type, the same way
`docs/coverage/detector-inventory.json` already keys one row per type), not
just documentation prose describing prefixes informally.

### Why the four classic-shaped prefixes still share one scan pass

GitHub's 2021-04 token-format rollout (`github.blog/2021-04-05-behind-
githubs-new-authentication-token-formats`) documents `ghp_`/`gho_`/`ghu_`/
`ghr_`/`ghs_` as one shared scheme: prefix + a 36-byte suffix carrying a
32-bit CRC32 checksum in Base62 in its last six characters, chosen
specifically so "entropy increased... all without changing the token
length." Two current, shipped, independent detectors corroborate the same
36-byte body length for the individual prefixes: gitleaks' `config/
gitleaks.toml` ships `github-pat` (`ghp_[0-9a-zA-Z]{36}`), `github-oauth`
(`gho_[0-9a-zA-Z]{36}`), `github-refresh-token` (`ghr_[0-9a-zA-Z]{36}`), and
groups `ghu_`/`ghs_` under one `github-app-token` rule with the same `{36}`
body. `docs.github.com/en/authentication/keeping-your-account-and-data-
secure/about-authentication-to-github` (observed 2026-09-20) names the same
five prefixes and their roles ("Personal access token (classic)", "OAuth
access token", "User access token for a GitHub App", "Installation access
token for a GitHub App", "Refresh token for a GitHub App") but states no
length or alphabet of its own — the length contract rests on the 2021-04
post plus the two independent detectors' agreement, not on current GitHub
docs alone.

Because `ghp_`/`gho_`/`ghu_`/`ghr_` share one grammar exactly (same prefix
length, same exact-36 run, same alphabet, same boundary), `github.rs` keeps
scanning them in a single `pattern::scan_prefixed_runs` pass for the same
reason `scan_prefixed_shapes`'s own doc comment gives for combining
same-shaped prefixes: matching them separately and merging by position is
"easy to get wrong exactly when one group's prefix is a literal substring of
another's" (`gh`, unqualified, is a literal prefix of every one of them).
`push_classic_family` (`crates/secret-scan-core/src/detectors/github.rs`)
runs that one pass, then assigns each matched range its finding type by
which literal prefix it starts with — a plain `starts_with` check per
candidate, not a second parse.

`ghs_` (installation) keeps its own, separate scan: GitHub's stateless
installation-token rollout, which the same docs page states "began [a]
staged rollout of a stateless format (`ghs_APPID_JWT`)" on 2026-04-27, can
make a `ghs_` token far longer and JWT-shaped (dot-separated), which the
existing `RunLength::AtLeast(36)` + `pattern::is_alnum_dash_dot` grammar
already accommodated before this issue; this decision does not change that
shape, only its finding type (`github_token` → `github_app_installation_token`).

`github_pat_` (fine-grained) also keeps its own scan: an independent
community reference (the widely cited `magnetikonline/073afe7909ffdd6f10
ef06a00bc3bc88` gist of GitHub token regexes) and GitGuardian's public
fine-grained-PAT detector both state the same two-segment shape this
project's `scan_fine_grained` already implemented: `github_pat_` + exactly
22 `[A-Za-z0-9]` bytes + a literal `_` + exactly 59 `[A-Za-z0-9]` bytes (93
bytes total). This decision changes only its finding type, from
`github_token` to `github_fine_grained_personal_access_token`.

### Why user-to-server and server-to-server are not merged

gitleaks itself groups `ghu_` and `ghs_` under one rule id, `github-app-
token`, because they happen to share the classic-shaped 36-byte grammar.
This project keeps them as two finding types because #502's taxonomy names
them as two families for a reason that is about the credential, not its
grammar: a user-to-server token acts as the authorizing *user* (scoped to
that user's own permissions) while a server-to-server (installation) token
acts as the *App itself* (scoped to whatever the installation granted) — two
different blast radii a matrix consumer needs to be able to state
independently, and, per the stateless-rollout note above, `ghs_` alone can
now also carry the wider JWT-shaped grammar `ghu_` never does.

### Why the refresh token gets its own type rather than reusing an access-token type

A refresh token is never itself presented to the GitHub API as a bearer
credential — GitHub App user-to-server tokens are short-lived (8 hours) and
`ghr_` is what a client exchanges for a new user-to-server/refresh pair.
Reusing `github_oauth_token` or `github_app_user_to_server_token` for it
would make the matrix's per-family status claim wrong for whichever family
it borrowed from. It gets its own type, `github_app_refresh_token`.

### Checksum verification is deliberately out of scope here

The 2021-04 post documents a CRC32-in-Base62 checksum on the last six bytes
of the four classic-shaped families' bodies. This decision does not add a
`PostCheck` verifying it. The issue's "negative twins for... checksum/marker
where evidenced" criterion is satisfied by the fine-grained family's already
-implemented separator marker (`rejects_a_fine_grained_token_with_the_wrong_
separator`); it does not itself require adding new verification machinery
where none exists today. Implementing CRC32-in-Base62 verification by hand
(the core crate may depend on no external crate) would meaningfully tighten
the classic-shaped families' contract from "documented shape" to "verified
checksum" — a real improvement, but a distinct piece of work from a family
inventory, and one this decision leaves as a **concrete unblocking
condition** for a future issue: add the `PostCheck` once that issue can also
add negative-twin fixtures proving a shape-valid-but-checksum-invalid string
is rejected, the same "adopt tool-corroborated exact contract" bar
`decision-scope-supabase-management-token-and-secret-key-independence.md`
applies to `sbp_`.

## Consequences

- `crates/secret-scan-core/src/detectors/github.rs`: `CLASSIC_PREFIXES`
  (a bare `[&str; 4]`) becomes `CLASSIC_FAMILY_PREFIXES`, an array of
  `(prefix, finding type)` pairs; `push_classic_family` scans all four in
  one pass and assigns each match's type by its own matched prefix.
  `INSTALLATION_PREFIXES`/`FINE_GRAINED_PREFIX` scans are unchanged except
  for the type each now carries (`github_app_installation_token`,
  `github_fine_grained_personal_access_token`). No detector id, no
  registration order, and no existing prefix's body grammar changed.
- `crates/secret-scan-core/src/policy.rs`'s `ALWAYS_REDACT_TYPES` gains the
  five new types: a leaked OAuth token, user-to-server token, installation
  token, refresh token, or fine-grained PAT is exactly as actionable as a
  leaked classic PAT.
- `docs/coverage/detector-inventory.json` declares five new rows, all
  `detector: "github-token"`, the same "shared detector, several types"
  shape `contextual_secret`/`authorization_credential` already establish for
  `generic-token`; `docs/coverage/inventory-report.json`, `coverage-
  declarations.json`, and `coverage-report.md` were regenerated
  (`scripts/generate-coverage-{inventory,declarations,report}.py`) rather
  than hand-edited. Every one of the six GitHub rows resolves every
  dimension `supported` — including `overlap`, which evidence-requirements
  .md's own matrix excludes from `single-detector-family` sharing ("Overlap
  is type-specific because the evidence must pin which finding type wins";
  only `malformed` and `adversarial` are shareable dimensions in the
  generator's `SHAREABLE_DIMENSIONS`), so each of the five new types carries
  its own overlap fixture rather than inheriting `github-overlap-context`'s.
- `conformance/fixtures/synchronous-corpus.json` gains 20 new fixtures: one
  near-miss-negative for an undocumented classic-family-shaped prefix
  (`ghq_`); one benign control for the `gh` CLI's own masked/redacted
  display (`gh auth status` prints `Token: ghp_***...`, replacing the body
  with asterisks no documented family's alphabet accepts); three families
  (OAuth, user-to-server, refresh) each get a plain-text positive, a
  boundary (one byte short of the exact 36-byte body), a dotenv-context
  positive, and an overlap fixture; the installation family gains a
  stateful (opaque, non-JWT) positive the corpus previously lacked (only a
  Rust unit test covered it) plus an overlap fixture; the fine-grained
  family gains an overlap fixture. Three
  pre-existing fixtures (`github-positive-installation-stateless`,
  `github-positive-fine-grained`, `github-positive-fine-grained-dotenv`)
  were retyped in place from `github_token` to their real family's type.
  `conformance/fixtures/incremental-corpus.json`'s `github-installation-
  stateless` fixture was retyped the same way.
  `conformance/fixtures/common-profile-expectations.json` was regenerated
  (`REDACT_SECRET_UPDATE_COMMON_EXPECTATIONS=1`): every new fixture is
  `Pack::Provider`-only, so each resolves empty under the `common` profile,
  the same as every other provider-only type. All fixture values are
  synthetic (`SYNTHETICREVOKED` + zero-padding, or the pre-existing
  fine-grained synthetic body), matching the classic family's own
  established convention.
- Detection behavior for the four previously-conflated classic-family
  prefixes, for `ghs_`, and for `github_pat_` is unchanged: same prefixes,
  same body grammars, same byte spans. `T1`/`T2` leaked-span counts do not
  change; only the finding `type` string attached to `gho_`/`ghu_`/`ghs_`/
  `ghr_`/`github_pat_` matches changes, plus the resulting `-token`-suffixed
  policy classification list. No existing `ghp_` fixture, test, or
  documentation example needed to change.
