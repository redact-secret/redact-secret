---
decision_id: decision-connection-string-and-jwt-need-no-retention-hint
status: accepted
scope: workspace
title: connection-string and jwt need no incremental retention hint of their own
decided_at: 2026-09-20
spec: detector-families
---

# connection-string and jwt need no incremental retention hint of their own

## Decision

`connection-string` and `jwt` define no `has_open_*` retention hint, and
none is added. The incremental scanner
(`crates/secret-scan-core/src/incremental.rs`) only ever runs detection on a
line once it closes (`append_retained(..., closes_line = true)`); a bare,
un-terminated chunk is buffered whole and never handed to `process_unit`.
A retention hint's only job is to keep a *closed* line open past its
terminator when a construct might continue onto the next one — it has
nothing to decide about a same-line split, because the pipeline never sees a
same-line prefix in isolation to begin with.

Both detectors' whole-value exclusions —
`connection_string.rs`'s `starts_with_bare_dollar_reference` and `jwt.rs`'s
legacy-Supabase `anon`/`service_role` payload carve-out — judge a value that
cannot itself contain a line terminator: a connection-string password and a
JWT are both non-whitespace token grammars, matching
`decision-contextual-assignment-stops-at-the-line`'s existing rule that a
value never crosses a line terminator. So the value a same-line chunk split
could ever divide is always still fully present, on one physical line, by
the time detection runs on it — there is no cross-append gap for a hint to
bridge.

## Rationale

- **Scope.** Issue #480 asked this question explicitly for both detectors,
  after `generic-token`'s `has_open_contextual_assignment` and
  `bearer-token`'s `has_open_bearer_authorization` set a precedent of one
  hint per detector with an exclusion. Both existing hints exist for a
  different reason than exclusion-value completeness: they hold a line open
  when the *construct itself* — a bare key with no operator yet, or a bare
  `Authorization:` header name with no scheme yet — is still incomplete at a
  line terminator. Neither hint inspects the excluded-value predicate at
  all; `has_open_bearer_authorization` recognizes only an in-progress header
  *name*, not an in-progress filler or placeholder value.
- **Why a hint is unnecessary here anyway.** A hint would only matter if a
  detector's value grammar could span a line terminator, so a `\n` could
  close a line while the exclusion predicate had seen only part of the
  value. Neither grammar allows that: `crates/secret-scan-core/tests/incremental.rs`
  and `crates/secret-scan-core/tests/incremental_partitions.rs` exhaustively
  partition every UTF-8 byte and character boundary of a fixture, including
  mid-value splits *within* one line, and none of those partitions ever
  reaches a detector before the enclosing line closes — so a value is
  either wholly present or not yet scanned, never scanned partially.
- **Accepted risk.** If either detector's grammar ever grows a multi-line
  value form, this decision must be revisited alongside that change; nothing
  here forecloses adding a hint later.

## Evidence

- `crates/secret-scan-core/src/incremental.rs`: `append_retained` only calls
  `process_unit` when a unit closes; an un-terminated chunk accumulates in
  `self.retained` untouched.
- `crates/secret-scan-core/tests/incremental.rs`:
  `a_mid_exclusion_prefix_never_reaches_the_exclusion_predicate_early` (added
  alongside this record) appends exactly the three mid-exclusion prefixes
  issue #480 named — `secret = SecretManagerServiceClient.access_secret_`,
  `postgres://app:$DB_PASS`, and `Authorization: Bearer xxxxxxxx` — and
  asserts each releases nothing until its line closes, then reproduces the
  whole-input reference once completed.
- `docs/decisions/2026-09-15-contextual-assignment-stops-at-the-line.md`
  establishes the line-terminator boundary this decision leans on.
