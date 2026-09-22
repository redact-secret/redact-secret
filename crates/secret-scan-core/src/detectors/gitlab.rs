//! GitLab token detection.
//!
//! Mirrors `src/detectors/gitlab.ts`.

use crate::detectors::pattern::{self, RunLength};
use crate::error::DetectorFailure;
use crate::types::{ByteRange, Candidate, Confidence, Detector, DetectorContext, Specificity};

const PREFIXES: [&str; 13] = [
    "glpat-", "gloas-", "gldt-", "glrt-", "glrtr-", "glcbt-", "glptt-", "glft-", "glimt-",
    "glagent-", "glwt-", "glsoat-", "glffct-",
];

/// Requires one of GitLab's documented, non-configurable token prefixes and
/// a substantial opaque suffix (`docs.gitlab.com/security/tokens/`'s "Token
/// prefixes" table, observed 2026-09-20; issue #518's inventory). `glpat-`
/// also covers impersonation, project-access, and group-access tokens, which
/// the same table gives no separate prefix for. Three gaps are intentional
/// and tracked, not silent, per
/// `docs/decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md`
/// (GitLab row):
///
/// - Personal-access-token prefixes can be customized by an administrator.
/// - `glrt-`/`glrtr-`'s "routable" variant embeds a `.`-delimited version and
///   checksum segment this scan's alnum/dash/underscore alphabet does not
///   span, and no source corroborates the base64 payload's own length, so a
///   short payload is missed entirely rather than matched at a wrong length.
/// - The legacy, unprefixed runner *registration* token (distinct from the
///   `glrt-`/`glrtr-` runner *authentication* token above) is opaque and, per
///   GitLab's own migration guide, provider-deprecated.
pub(super) struct GitlabTokenDetector;

impl Detector for GitlabTokenDetector {
    fn id(&self) -> &'static str {
        "gitlab-token"
    }

    fn detect(
        &self,
        input: &str,
        _context: &DetectorContext,
    ) -> Result<Vec<Candidate>, DetectorFailure> {
        let mut candidates = Vec::new();
        for (start, end) in pattern::scan_prefixed_runs(
            input,
            &PREFIXES,
            RunLength::AtLeast(20),
            pattern::is_alnum_dash,
            pattern::is_alnum_dash,
        ) {
            let Some(range) = ByteRange::new(start, end) else {
                continue;
            };
            candidates.push(
                Candidate::new("gitlab_token", Confidence::High, range)
                    .with_specificity(Specificity::Provider)
                    .with_signals(["gitlab-documented-prefix", "opaque-suffix"]),
            );
        }
        Ok(candidates)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn detect(input: &str) -> Vec<Candidate> {
        GitlabTokenDetector
            .detect(input, &DetectorContext::new(input.len()))
            .unwrap()
    }

    #[test]
    fn detects_every_documented_prefix() {
        for prefix in PREFIXES {
            let input = format!("{prefix}SYNTHETIC_REVOKED_PREFIX_FIXTURE");
            let candidates = detect(&input);
            assert_eq!(candidates.len(), 1, "{prefix}");
            assert_eq!(
                candidates[0].range(),
                ByteRange::new(0, input.len()).unwrap(),
                "{prefix}"
            );
        }
    }

    #[test]
    fn distinguishes_glrt_from_its_longer_glrtr_sibling() {
        let input = "glrt-SYNTHETIC_REVOKED_PREFIX_FIXTURE";
        let candidates = detect(input);
        assert_eq!(candidates.len(), 1);
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(0, input.len()).unwrap()
        );
    }

    #[test]
    fn rejects_a_short_suffix() {
        assert_eq!(detect("glpat-SYNTHETIC_SHORT").len(), 0);
    }

    #[test]
    fn rejects_an_undocumented_prefix() {
        assert_eq!(
            detect("glpersonal-SYNTHETIC_REVOKED_TOKEN_FIXTURE").len(),
            0
        );
    }

    /// A routable runner authentication token's version/checksum segment
    /// (`.0a.…`) sits outside the alnum/dash/underscore alphabet, so a
    /// sufficiently long base64 payload before the first `.` still reaches
    /// the 20-byte minimum and matches — truncated at the `.`, missing the
    /// version/checksum tail, but still flagging the credential.
    #[test]
    fn matches_a_routable_runner_token_truncated_at_its_dot_delimited_tail() {
        let input = "glrt-t3_QmFzZTY0UGF5bG9hZA.0a.SYNTHETICREVOKEDCHECKSUM";
        let candidates = detect(input);
        assert_eq!(candidates.len(), 1);
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(0, "glrt-t3_QmFzZTY0UGF5bG9hZA".len()).unwrap()
        );
    }

    /// The same routable format with a short payload (under the 20-byte
    /// floor) is missed entirely rather than partially matched. This is the
    /// documented, intentional gap (see the struct-level doc comment and
    /// `docs/decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md`,
    /// GitLab row): no
    /// source corroborates the payload's own length, so this scan cannot
    /// tighten to the `.`-delimited shape without guessing a contract.
    #[test]
    fn misses_a_routable_runner_token_with_a_short_payload() {
        assert_eq!(detect("glrt-t3_short.0a.SYNTHETICCHECKSUM").len(), 0);
    }

    /// The legacy, unprefixed runner *registration* token (distinct from the
    /// `glrt-`/`glrtr-` runner *authentication* token) carries no documented
    /// prefix and is itself provider-deprecated; it is not, and cannot be, a
    /// candidate for this prefix-anchored scan.
    #[test]
    fn does_not_match_a_legacy_unprefixed_runner_registration_token() {
        assert_eq!(detect("f7c2b1a9e4d6038f5a1c2e9b0d7f4a63").len(), 0);
    }
}
