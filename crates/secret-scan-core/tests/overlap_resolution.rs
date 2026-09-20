//! Overlap resolution against the exclusion shapes added by #467-#475,
//! driven through the real built-in registry rather than synthetic
//! candidates.
//!
//! `select_optimal_disjoint_set` (`src/pipeline.rs`) resolves overlaps among
//! whatever candidates the registered detectors actually emit. A value a
//! detector excludes (the closed-call code expression, filler/placeholder
//! Bearer value, `$VAR` connection password, or legacy Supabase `anon` JWT)
//! never becomes a candidate at all, so it cannot itself out-rank or shift a
//! neighboring live finding through the resolver's priority chain
//! (`RankedCandidate::priority`). What these tests actually guard is the
//! boundary behavior around that non-candidate: that a detector's own
//! grammar scan does not overrun into, or get displaced by, a genuinely
//! live neighbor on the same line.
//!
//! `detector_order` (the fourth key in `RankedCandidate::priority`, after
//! resolved-action severity, specificity, and confidence) is reached only
//! when every earlier key ties exactly, and it is a registration-order
//! index fixed by `detectors::built_in` — `DetectorRegistry::with_built_in`
//! is the only supported way to reach the built-in detectors and offers no
//! way to reverse that registration order. So "the reverse ordering of
//! each, since `detector_order` is a resolution key" (issue #480) is
//! exercised here as the reverse *textual* ordering of the excluded and
//! live values within the input, not a swap of detector registration order.
//!
//! Every input is synthetic; no test embeds a credential-shaped value.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use redact_secret::{DefaultPolicy, DetectorRegistry, scan};

const ANON_JWT: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InN5bnRocHJvaiIsInJvbGUiOiJhbm9uIiwiaWF0IjoxNzAwMDAwMDAwLCJleHAiOjE3OTk5OTk5OTl9.SYNTHETIC_REVOKED_SUPABASE_LEGACY_JWT_SIGNATURE";
const SERVICE_ROLE_JWT: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InN5bnRocHJvaiIsInJvbGUiOiJzZXJ2aWNlX3JvbGUiLCJpYXQiOjE3MDAwMDAwMDAsImV4cCI6MTc5OTk5OTk5OX0.SYNTHETIC_REVOKED_SUPABASE_LEGACY_JWT_SIGNATURE";
const CONNECTION_DOLLAR_VAR: &str = "postgres://app:$DB_PASSWORD@db.internal:5432/example";
const GITHUB_TOKEN: &str = "ghp_SYNTHETICREVOKED00000000000000000000";
const BEARER_FILLER: &str = "Authorization: Bearer xxxxxxxxxxxxxxxxxxxx";
const CONTEXTUAL_ASSIGNMENT: &str = "api_key=SYNTHETIC_REVOKED_CONTEXT_VALUE";

/// Runs `input` through the real built-in registry and default policy —
/// the same resolver path `select_optimal_disjoint_set` sits inside.
fn findings(input: &str) -> Vec<redact_secret::Finding> {
    let registry = DetectorRegistry::with_built_in([]).unwrap();
    scan(input, &registry, &DefaultPolicy).unwrap()
}

/// Asserts exactly one finding survives, at the exact byte range of `live`
/// within `input` — the range a standalone scan of `live` alone would
/// report, shifted by wherever `live` actually sits in `input`.
fn assert_only_live_survives(input: &str, live: &str, detector: &str, type_name: &str) {
    let start = input
        .find(live)
        .unwrap_or_else(|| panic!("{live:?} must appear in {input:?}"));
    let end = start + live.len();
    let found = findings(input);
    assert_eq!(
        found.len(),
        1,
        "{input:?}: expected exactly one finding, got {found:?}",
    );
    assert_eq!(found[0].detector(), detector, "{input:?}: detector");
    assert_eq!(found[0].type_name(), type_name, "{input:?}: type");
    assert_eq!(found[0].range().start(), start, "{input:?}: range start");
    assert_eq!(found[0].range().end(), end, "{input:?}: range end");
}

// ---------------------------------------------------------------------------
// a legacy Supabase anon JWT (excluded) beside a service_role JWT (live)
// ---------------------------------------------------------------------------

#[test]
fn an_excluded_anon_jwt_does_not_suppress_or_shift_an_adjacent_service_role_jwt() {
    let input = format!("{ANON_JWT} {SERVICE_ROLE_JWT}");
    assert_only_live_survives(&input, SERVICE_ROLE_JWT, "jwt", "jwt");
}

#[test]
fn the_excluded_anon_jwt_is_still_suppressed_when_it_follows_the_live_service_role_jwt() {
    let input = format!("{SERVICE_ROLE_JWT} {ANON_JWT}");
    assert_only_live_survives(&input, SERVICE_ROLE_JWT, "jwt", "jwt");
}

// ---------------------------------------------------------------------------
// a $VAR connection password (excluded) beside a real provider token (live)
// ---------------------------------------------------------------------------

#[test]
fn an_excluded_dollar_var_connection_password_does_not_suppress_a_real_provider_token() {
    let input = format!("{CONNECTION_DOLLAR_VAR} {GITHUB_TOKEN}");
    assert_only_live_survives(&input, GITHUB_TOKEN, "github-token", "github_token");
}

#[test]
fn the_excluded_dollar_var_connection_password_is_still_excluded_when_it_follows_the_live_token() {
    let input = format!("{GITHUB_TOKEN} {CONNECTION_DOLLAR_VAR}");
    assert_only_live_survives(&input, GITHUB_TOKEN, "github-token", "github_token");
}

// ---------------------------------------------------------------------------
// a repeated-character-filler Bearer value (excluded) beside a generic-token
// contextual assignment (live)
// ---------------------------------------------------------------------------

#[test]
fn an_excluded_bearer_filler_value_does_not_suppress_a_generic_token_contextual_assignment() {
    let input = format!("{BEARER_FILLER} {CONTEXTUAL_ASSIGNMENT}");
    assert_only_live_survives(
        &input,
        "SYNTHETIC_REVOKED_CONTEXT_VALUE",
        "generic-token",
        "contextual_secret",
    );
}

#[test]
fn the_excluded_bearer_filler_value_is_still_excluded_when_it_follows_the_contextual_assignment() {
    let input = format!("{CONTEXTUAL_ASSIGNMENT} {BEARER_FILLER}");
    assert_only_live_survives(
        &input,
        "SYNTHETIC_REVOKED_CONTEXT_VALUE",
        "generic-token",
        "contextual_secret",
    );
}
