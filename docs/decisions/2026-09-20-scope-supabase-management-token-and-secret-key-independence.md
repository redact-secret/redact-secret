---
decision_id: decision-scope-supabase-management-token-and-secret-key-independence
status: accepted
scope: workspace
title: Separate the Supabase management-token credential class from the secret-key class, and keep each class's evidence independent
decided_at: 2026-09-20
---

# Separate the Supabase management-token credential class from the secret-key class, and keep each class's evidence independent

## Decision

Issue #515 (B1d, under Epic #501) asks that Supabase's credential classes be
audited and treated separately, contracting only what the evidence supports.
Applied to the four classes the issue names:

- **`sb_secret_` / `sb_publishable_`** (`crates/secret-scan-core/src/detectors/additional_providers.rs`'s
  `SUPABASE`): **unchanged**. `sb_secret_` stays an `at_least(20, is_alnum_dash)`
  shape; `sb_publishable_` stays excluded by omission (no shape names it).
  See "Why `sb_secret_` stays T0-shaped" below for why this decision does not
  tighten it.
- **`sbp_` / `sbp_v0_` personal access tokens** (Management API / CLI / MCP
  server authentication): a **new**, independent detector, `SUPABASE_PAT`
  (id `supabase-management-token`, type `supabase_personal_access_token`),
  added beside `SUPABASE` in the same file. Two `PrefixShape`s over one body
  grammar: `sbp_` and the versioned `sbp_v0_`, each followed by exactly 40
  bytes from a new `pattern::is_lower_alnum` (`[a-z0-9]`) alphabet.
- **Legacy anon/service-role JWTs**: unchanged. `decision-scope-supabase-legacy-anon-jwt-exclusion.md`
  (issue #472) already resolved this class; this decision does not revisit
  it and does not use it as evidence for either new-format class, or vice
  versa.

## Rationale

### Independence is the point of #515, not a formality

The issue is explicit: "Each credential class is assessed independently; no
class is used as evidence for another." Concretely, in this codebase:

- The management-token grammar below is evidenced entirely by sources about
  `sbp_`/`sbp_v0_` itself. It is not used to justify tightening, loosening,
  or otherwise touching `SUPABASE`'s `sb_secret_` shape, and `SUPABASE`'s
  existing "the publishable prefix is a public identifier, not a secret"
  reasoning is not extended to `sbp_` (a PAT has no publishable counterpart —
  there is nothing to exclude).
- `jwt.rs`'s anon/service-role carve-out reasons about a claim inside an
  unsigned JWT payload; it shares no grammar, evidence, or exclusion logic
  with either `sb_`-prefixed class and this decision does not touch it.
- Each class keeps its own detector `id` and finding `type` (`supabase-token`/
  `supabase_secret_key` vs. `supabase-management-token`/
  `supabase_personal_access_token`) specifically so a future support-matrix
  classification (#500/#501's T0/T1/T2/`stable`/`provisional`/`pending`
  work, which lands in `redact-secret-benchmarks`) can assign each class its
  own status without one row's evidence quality being averaged into
  another's.

### Why `supabase-management-token` is added now

`docs.supabase.com/guides/platform/personal-access-tokens` documents the
`sbp_` prefix (by example only, `sbp_fc...`) and the classic-vs-scoped
distinction, but no exact body grammar — consistent with issue #515's framing
that Supabase's own docs name prefixes without specifying bodies. The body
grammar adopted here (`sbp_`/`sbp_v0_` + exactly 40 `[a-z0-9]` bytes) is
instead externally corroborated: it is the shape TruffleHog's own shipped
detector already matches for the classic `sbp_` prefix — the same reference
detector issue #515 itself names as the one this project's benchmark
evidence has historically (and, per the issue, incorrectly) pinned against
`sb_secret_`. That detector's regex is anchored to `[a-z0-9]{40}` with no
`_` in its character class, so it cannot match the versioned `sbp_v0_`
prefix the same docs page's scoped-token walkthrough names — an admitted gap
this detector closes as a second `PrefixShape` over the identical body
grammar, the same "adopt the sibling prefix, keep the body shape" move
`HUGGING_FACE`'s `api_org_` shape already makes in the same file. No
TruffleHog implementation code is used, only its published match shape, per
`AGENTS.md`.

This clears the "usage probability × secret impact × agent/dev ecosystem
relevance × format detectability" bar #501 sets for anything new: a PAT
authenticates the Supabase CLI and MCP server, both squarely in this
project's own "agent/dev ecosystem" audience, and a leaked classic-scope PAT
grants full account access across every organization and project the holder
belongs to.

### Why `sb_secret_` stays T0-shaped (the concrete unblocking condition)

Before writing this decision, `docs.supabase.com/guides/getting-started/migrating-to-new-api-keys`
was checked directly: it shows `sb_publishable_...`/`sb_secret_...` only as
placeholders, with no stated length, alphabet, or checksum. Two third-party
sources disagree on what fills that gap: one describes body generation as
`openssl rand -hex 24` (48 hex bytes); a GitHub discussion tied to
gitleaks issue #2225 describes 22 base64url bytes plus an 8-byte checksum
segment (31 bytes, `[A-Za-z0-9_-]`) instead. Neither is a shipped detector
rule — the gitleaks issue is an open proposal ("I have the rules written and
tested locally"), not merged behavior — so unlike `sbp_`'s TruffleHog-shipped
evidence above, there is no confirmed external contract to adopt, and the
two candidate contracts contradict each other on the one number (body
length) that would matter for tightening `at_least(20, ...)` to an `exact`
shape the way `DOCKER`/`DIGITALOCEAN`/`HUGGING_FACE` were tightened once
their own evidence firmed up.

Fabricating a specific length from a self-contradicting, unmerged source
would trade a broad-but-safe false-negative-leaning shape for a
narrow-but-unverified one, for a class that is already fully evidenced on
every other dimension (`docs/coverage/coverage-declarations.json`'s
`supabase_secret_key` row: `positive`, `overlap`, `adversarial`, `boundary`,
`near-miss-negative`, `malformed`, `host-context`, `range` all `supported`,
including `sb_publishable_` staying unflagged beside a paired `sb_secret_`
key per `supabase-positive-mixed-public-and-secret`). The residual gap is
narrowly the exact body grammar, not detection capability. **Concrete
unblocking condition**: tighten `SUPABASE`'s `sb_secret_` shape to an exact
length once either (a) a shipped, confirmed third-party detector (gitleaks
or TruffleHog, released rather than proposed) states one body grammar, or
(b) Supabase's own documentation states one directly — at which point this
follows the same "adopt tool-corroborated exact length" precedent this
decision already applies to `sbp_`.

## Consequences

- `crates/secret-scan-core/src/detectors/pattern.rs` gains `is_lower_alnum`
  (`[a-z0-9]`), mirroring `is_lower_hex`'s "reject a case-mangled twin"
  reasoning for a provider whose corroborated contract is lowercase-only.
- `crates/secret-scan-core/src/detectors/additional_providers.rs` gains
  `SUPABASE_PAT` (`supabase-management-token` / `supabase_personal_access_token`),
  registered in `crates/secret-scan-core/src/detectors/mod.rs`
  (`built_in_detectors`, `BUILT_IN_PACKS`, and the ordered id list both
  reference) immediately after `SUPABASE`, and added to `policy.rs`'s
  `ALWAYS_REDACT_TYPES` (a leaked account-wide token is exactly as
  actionable as a leaked project secret key).
- `docs/coverage/detector-inventory.json` declares the new row;
  `docs/coverage/inventory-report.json`, `docs/coverage/coverage-declarations.json`,
  and `docs/coverage/coverage-report.md` were regenerated
  (`scripts/generate-coverage-inventory.py`, `generate-coverage-declarations.py`,
  `generate-coverage-report.py`) rather than hand-edited; the new row
  resolves `supported` on every dimension the `provider` behavior class
  requires (`docs/coverage/evidence-requirements.md` §4), the same bar
  `supabase-token` itself already meets.
- `conformance/fixtures/synchronous-corpus.json` gains 16
  `supabase-management-*` fixtures (two positive, one per documented prefix;
  five near-miss negative; seven boundary/malformed, including the two
  prefixes' independent exact-length enforcement and the lowercase-only
  alphabet's uppercase rejection; one overlap; one bounded adversarial run
  proving the exact-length-plus-truncation rule stays deterministic over a
  homogeneous 8000-byte run). `conformance/fixtures/common-profile-expectations.json`
  was regenerated (`REDACT_SECRET_UPDATE_COMMON_EXPECTATIONS=1`): the new
  type is `Pack::Provider`-only, so every new fixture resolves empty under
  the `common` profile, the same as every other provider-only type.
  All fixture values are synthetic (`synthetic0revoked1provider2value3padding`,
  a lowercase-alnum-only marker chosen because the class's own alphabet
  excludes the uppercase `SYNTHETIC_REVOKED_` marker used elsewhere in this
  file).
