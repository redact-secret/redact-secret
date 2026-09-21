//! GitHub token detection, one finding type per credential family
//! (`decision-map-github-token-families-onto-independent-finding-types`):
//! classic personal access token, OAuth access token, GitHub App
//! user-to-server token, GitHub App server-to-server (installation) token,
//! GitHub App refresh token, and fine-grained personal access token. All six
//! share this one detector id, `github-token`, the same "one detector, many
//! declared types" shape `generic-token` already uses.
//!
//! The four prefixes in [`CLASSIC_FAMILY_PREFIXES`] share one body grammar
//! (GitHub's 2021-04 token-format rollout: prefix + exactly 36
//! `[A-Za-z0-9]` bytes, unchanged since) and so share a single scan pass;
//! which literal prefix matched at each candidate's start determines its
//! finding type. Installation tokens keep their own, wider grammar because
//! GitHub's stateless installation-token rollout (started 2026-04-27) can
//! make a `ghs_` token far longer and JWT-shaped.

use crate::detectors::pattern::{self, RunLength};
use crate::error::DetectorFailure;
use crate::types::{ByteRange, Candidate, Confidence, Detector, DetectorContext, Specificity};

/// `(prefix, finding type)`. `ghp_` keeps the pre-existing `github_token`
/// type name: it is the only one of the four with prior, independently
/// evidenced fixtures and generic-infrastructure test usage, and nothing
/// about splitting the other three prefixes out requires renaming it too.
const CLASSIC_FAMILY_PREFIXES: [(&str, &str); 4] = [
    ("ghp_", "github_token"),
    ("gho_", "github_oauth_token"),
    ("ghu_", "github_app_user_to_server_token"),
    ("ghr_", "github_app_refresh_token"),
];
const INSTALLATION_PREFIX: &str = "ghs_";
const INSTALLATION_TYPE: &str = "github_app_installation_token";
const FINE_GRAINED_PREFIX: &str = "github_pat_";
const FINE_GRAINED_TYPE: &str = "github_fine_grained_personal_access_token";
const FINE_GRAINED_FIRST_LEN: usize = 22;
const FINE_GRAINED_SECOND_LEN: usize = 59;

/// Uses GitHub's documented prefixes and conservative token boundaries.
/// Installation tokens follow GitHub's rollout-safe expression so both the
/// stateful opaque and stateless JWT-shaped forms are selected in full.
pub(super) struct GitHubTokenDetector;

impl Detector for GitHubTokenDetector {
    fn id(&self) -> &'static str {
        "github-token"
    }

    fn detect(
        &self,
        input: &str,
        _context: &DetectorContext,
    ) -> Result<Vec<Candidate>, DetectorFailure> {
        // Emission order matches the historical oracle: classic family,
        // then installation, then fine-grained, each in its own
        // left-to-right pass. This order is a public contract for overlap
        // tie breaking, not just cosmetic.
        let mut candidates = Vec::new();
        push_classic_family(&mut candidates, input);
        push(
            &mut candidates,
            pattern::scan_prefixed_runs(
                input,
                &[INSTALLATION_PREFIX],
                RunLength::AtLeast(36),
                pattern::is_alnum_dash_dot,
                pattern::is_alnum_dash_dot,
            ),
            INSTALLATION_TYPE,
        );
        push(&mut candidates, scan_fine_grained(input), FINE_GRAINED_TYPE);
        Ok(candidates)
    }
}

/// Scans all four classic-family prefixes in one left-to-right pass (they
/// share a body grammar, so [`pattern::scan_prefixed_runs`] applies), then
/// assigns each matched range its finding type by which literal prefix it
/// starts with.
fn push_classic_family(candidates: &mut Vec<Candidate>, input: &str) {
    let prefixes: Vec<&str> = CLASSIC_FAMILY_PREFIXES.iter().map(|(p, _)| *p).collect();
    let ranges = pattern::scan_prefixed_runs(
        input,
        &prefixes,
        RunLength::Exact(36),
        pattern::is_alnum,
        pattern::is_alnum_underscore,
    );
    let bytes = input.as_bytes();
    for (start, end) in ranges {
        let Some(range) = ByteRange::new(start, end) else {
            continue;
        };
        // `scan_prefixed_runs` only ever returns a match starting with one of
        // the prefixes it was given, so exactly one arm always applies; a
        // range matching none falls through to the loop's next iteration
        // rather than panicking on an assumption that should always hold.
        for (prefix, type_name) in CLASSIC_FAMILY_PREFIXES {
            if bytes[start..].starts_with(prefix.as_bytes()) {
                candidates.push(
                    Candidate::new(type_name, Confidence::High, range)
                        .with_specificity(Specificity::Provider),
                );
                break;
            }
        }
    }
}

fn push(candidates: &mut Vec<Candidate>, ranges: Vec<(usize, usize)>, type_name: &'static str) {
    for (start, end) in ranges {
        let Some(range) = ByteRange::new(start, end) else {
            continue;
        };
        candidates.push(
            Candidate::new(type_name, Confidence::High, range)
                .with_specificity(Specificity::Provider),
        );
    }
}

/// `github_pat_` followed by an exact 22-byte alphanumeric run, a literal
/// `_`, and an exact 59-byte alphanumeric run. Both runs are fixed-length,
/// so unlike [`RunLength::AtLeast`] there is no single alphabet run to hand
/// to [`pattern::scan_prefixed_runs`]; the literal `_` separator between
/// them is outside the alphanumeric alphabet, so it cannot be absorbed into
/// either run.
fn scan_fine_grained(input: &str) -> Vec<(usize, usize)> {
    let bytes = input.as_bytes();
    let mut matches = Vec::new();
    let mut start = 0;
    while start < bytes.len() {
        if !bytes[start..].starts_with(FINE_GRAINED_PREFIX.as_bytes()) {
            start += 1;
            continue;
        }
        let Some(end) = fine_grained_end(bytes, start + FINE_GRAINED_PREFIX.len()) else {
            start += 1;
            continue;
        };
        if pattern::boundary_ok(bytes, start, end, pattern::is_alnum_underscore) {
            matches.push((start, end));
        }
        start = end;
    }
    matches
}

fn fine_grained_end(bytes: &[u8], first_start: usize) -> Option<usize> {
    let separator = first_start + FINE_GRAINED_FIRST_LEN;
    if !exact_run(bytes, first_start, FINE_GRAINED_FIRST_LEN) || bytes.get(separator) != Some(&b'_')
    {
        return None;
    }
    let second_start = separator + 1;
    if !exact_run(bytes, second_start, FINE_GRAINED_SECOND_LEN) {
        return None;
    }
    Some(second_start + FINE_GRAINED_SECOND_LEN)
}

/// `true` when the `len` bytes starting at `start` are all present and all
/// alphanumeric.
fn exact_run(bytes: &[u8], start: usize, len: usize) -> bool {
    bytes
        .get(start..start.saturating_add(len))
        .is_some_and(|run| run.iter().all(|&byte| pattern::is_alnum(byte)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn detect(input: &str) -> Vec<Candidate> {
        GitHubTokenDetector
            .detect(input, &DetectorContext::new(input.len()))
            .unwrap()
    }

    #[test]
    fn detects_a_classic_token() {
        let input = format!("ghp_{}", "S".repeat(36));
        let candidates = detect(&input);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].type_name(), "github_token");
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(0, input.len()).unwrap()
        );
    }

    #[test]
    fn detects_a_fine_grained_token() {
        let first = "S".repeat(FINE_GRAINED_FIRST_LEN);
        let second = "T".repeat(FINE_GRAINED_SECOND_LEN);
        let input = format!("github_pat_{first}_{second}");
        let candidates = detect(&input);
        assert_eq!(candidates.len(), 1);
        assert_eq!(
            candidates[0].type_name(),
            "github_fine_grained_personal_access_token"
        );
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(0, input.len()).unwrap()
        );
    }

    #[test]
    fn detects_a_stateful_installation_token() {
        let input = format!("ghs_{}", "S".repeat(36));
        let candidates = detect(&input);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].type_name(), "github_app_installation_token");
    }

    #[test]
    fn selects_the_complete_stateless_installation_token() {
        let token =
            "ghs_SYNTHETIC_APP_ID.eyJTWU5USEVUSUNfUkVWT0tFRF9IRUFERVI.SYNTHETIC_REVOKED_SIGNATURE";
        let input = format!("before {token} after");
        let candidates = detect(&input);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].type_name(), "github_app_installation_token");
        let start = input.find(token).unwrap();
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(start, start + token.len()).unwrap()
        );
    }

    #[test]
    fn detects_an_oauth_access_token() {
        let input = format!("gho_{}", "S".repeat(36));
        let candidates = detect(&input);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].type_name(), "github_oauth_token");
    }

    #[test]
    fn detects_a_user_to_server_token() {
        let input = format!("ghu_{}", "S".repeat(36));
        let candidates = detect(&input);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].type_name(), "github_app_user_to_server_token");
    }

    #[test]
    fn detects_a_refresh_token() {
        let input = format!("ghr_{}", "S".repeat(36));
        let candidates = detect(&input);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].type_name(), "github_app_refresh_token");
    }

    #[test]
    fn each_classic_family_prefix_keeps_its_own_type_at_a_shared_position() {
        // All four prefixes share one body grammar and one scan pass; this
        // pins that the shared pass still assigns each match its own,
        // independent family type rather than collapsing them.
        let input = format!(
            "{} {} {} {}",
            format_args!("ghp_{}", "S".repeat(36)),
            format_args!("gho_{}", "S".repeat(36)),
            format_args!("ghu_{}", "S".repeat(36)),
            format_args!("ghr_{}", "S".repeat(36)),
        );
        let candidates = detect(&input);
        let types: Vec<&str> = candidates.iter().map(Candidate::type_name).collect();
        assert_eq!(
            types,
            vec![
                "github_token",
                "github_oauth_token",
                "github_app_user_to_server_token",
                "github_app_refresh_token",
            ]
        );
    }

    #[test]
    fn rejects_short_lookalikes() {
        assert_eq!(detect("ghp_SYNTHETICSHORT").len(), 0);
        assert_eq!(detect("gho_SYNTHETICSHORT").len(), 0);
        assert_eq!(detect("ghu_SYNTHETICSHORT").len(), 0);
        assert_eq!(detect("ghr_SYNTHETICSHORT").len(), 0);
        assert_eq!(detect("ghs_SYNTHETICSHORT").len(), 0);
        let short_fine_grained = format!(
            "github_pat_{}_{}",
            "S".repeat(FINE_GRAINED_FIRST_LEN),
            "T".repeat(FINE_GRAINED_SECOND_LEN - 1)
        );
        assert_eq!(detect(&short_fine_grained).len(), 0);
    }

    #[test]
    fn rejects_an_undocumented_prefix_that_only_resembles_the_classic_family() {
        // "ghq_" is not one of GitHub's five documented classic-family
        // prefixes; a near-miss on the literal is rejected outright rather
        // than falling back to some other family's type.
        assert_eq!(detect(&format!("ghq_{}", "S".repeat(36))).len(), 0);
    }

    #[test]
    fn rejects_a_fine_grained_token_with_the_wrong_separator() {
        let first = "S".repeat(FINE_GRAINED_FIRST_LEN);
        let second = "T".repeat(FINE_GRAINED_SECOND_LEN);
        let input = format!("github_pat_{first}-{second}");
        assert_eq!(detect(&input).len(), 0);
    }

    #[test]
    fn finds_deterministic_findings_across_repeated_calls() {
        let input = format!("ghp_{}", "S".repeat(36));
        assert_eq!(detect(&input), detect(&input));
    }
}
