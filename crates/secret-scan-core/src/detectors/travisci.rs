//! Travis CI API token detection (issue #523).
//!
//! ## Ranking
//!
//! Issue #523 ranks the CI-provider candidates by lexical evidence and usage,
//! and implements one. The pinned inventory
//! (`redact-secret-benchmarks` `benchmarks/detector-inventory.json`) gives:
//!
//! | candidate | gitleaks 8.30.1 | trufflehog 3.97.4 | tools |
//! | --- | --- | --- | --- |
//! | Travis CI | `travisci-access-token` | `travisci` | 2 |
//! | CircleCI | none | `circleci/v1`, `circleci/v2` | 1 |
//! | Buildkite | none | `buildkite/v1`, `buildkite/v2` | 1 |
//! | GitHub Actions | none | none | 0 |
//!
//! The maintainer chose Travis CI (2026-09-24): it is the only candidate two
//! independent tools corroborate. CircleCI and Buildkite are the next
//! candidates. Each has one corroborating tool and needs its own contract
//! issue. GitHub Actions has no token grammar in either tool.
//!
//! ## Grammar
//!
//! Travis CI's own documentation (`developer.travis-ci.com/authentication`,
//! `docs.travis-ci.com/user/triggering-builds`, observed 2026-09-24) shows
//! the token only as `xxxxxxxxxxxx` in an `Authorization: token` header and
//! states no length or alphabet. The grammar therefore rests on the two
//! tools, consulted as external behavioral references only (no code is
//! reproduced):
//!
//! - gitleaks' `travisci-access-token`: a case-insensitive `travis` keyword
//!   before an assignment operator, then `[a-z0-9]{22}` under `(?i)`, so
//!   `[A-Za-z0-9]{22}`.
//! - trufflehog's `travisci`: a `travis` keyword prefix, then
//!   `\b[a-zA-Z0-9_]{22}\b`.
//!
//! Both agree on 22 bytes and a `travis` keyword. The body alphabet is their
//! intersection, [`pattern::is_alnum`] (`[A-Za-z0-9]`). Evidence tier T2
//! (tool-corroborated).
//!
//! ## Detection
//!
//! A 22-byte [`pattern::is_alnum`] run that is not a slice of a wider
//! `[A-Za-z0-9_-]` identifier ([`BOUNDARY`]), on a line that contains
//! `travis` case-insensitively ([`CONTEXT_KEYWORD`]). The run must mix
//! letters and digits, and must not be one repeated character. A value
//! assigned to a key whose last segment names an identifier or location
//! (`TRAVIS_REPO_SLUG=`, `build_id:`) is skipped.
//!
//! Confidence follows `decision-redact-provider-named-credential-assignments`:
//! high when the value is assigned to a key that names Travis
//! (`TRAVIS_TOKEN=`, `travis.api_token:`, `"travisApiToken":`) or to a
//! high-signal key on a line that names Travis, and medium (warn) for any
//! other same-line `travis` keyword.
//!
//! ## Trade-offs
//!
//! - **False negatives.** A token with no `travis` on its own line is
//!   missed: an `Authorization: token` header whose host is on another line,
//!   or a bare `travis login` output. A token made only of letters or only of
//!   digits is also missed; about 2 % of uniformly random 22-byte tokens have
//!   no digit. Travis tokens outside 22 bytes, if any exist, are missed.
//! - **False positives.** A 22-byte mixed alphanumeric identifier on a line
//!   that mentions Travis under a non-identifier key. Such a value is rare,
//!   because Travis build, job and repository ids are numeric and commit
//!   SHAs are 40 hex bytes.

use crate::detectors::pattern::{self, Alphabet};
use crate::detectors::text;
use crate::error::DetectorFailure;
use crate::types::{ByteRange, Candidate, Confidence, Detector, DetectorContext, Specificity};

/// The tool-corroborated token length.
const TOKEN_LEN: usize = 22;

/// The keyword both corroborating tools gate on, matched case-insensitively.
const CONTEXT_KEYWORD: &str = "travis";

/// A token is never a slice of a wider `[A-Za-z0-9_-]` identifier.
const BOUNDARY: Alphabet = pattern::is_alnum_dash;

/// `true` for a byte of a wider identifier the token must not be part of:
/// [`BOUNDARY`] plus `_`.
fn is_boundary_byte(byte: u8) -> bool {
    BOUNDARY(byte) || byte == b'_'
}

/// Every line of `input` as a byte range, without its `\n`. The line is the
/// unit the incremental scanner hands a detector, so whole-input and
/// incremental scanning agree.
fn lines(input: &str) -> impl Iterator<Item = (usize, usize)> + '_ {
    let bytes = input.as_bytes();
    let mut start = 0usize;
    std::iter::from_fn(move || {
        if start > bytes.len() {
            return None;
        }
        let end = bytes[start..]
            .iter()
            .position(|&byte| byte == b'\n')
            .map_or(bytes.len(), |offset| start + offset);
        let line = (start, end);
        start = end + 1;
        Some(line)
    })
}

/// `true` when [`CONTEXT_KEYWORD`] occurs anywhere in `line`.
fn line_has_context_keyword(line: &str) -> bool {
    line.len() >= CONTEXT_KEYWORD.len()
        && (0..=line.len() - CONTEXT_KEYWORD.len())
            .any(|pos| text::starts_with_ci(line, pos, CONTEXT_KEYWORD))
}

/// `true` when `run` contains at least one ASCII letter and one digit.
fn mixes_letters_and_digits(run: &[u8]) -> bool {
    run.iter().any(u8::is_ascii_alphabetic) && run.iter().any(u8::is_ascii_digit)
}

/// Detects a Travis CI API token; see the module doc.
pub(super) struct TravisCiApiTokenDetector;

impl Detector for TravisCiApiTokenDetector {
    fn id(&self) -> &'static str {
        "travisci-api-token"
    }

    fn detect(
        &self,
        input: &str,
        _context: &DetectorContext,
    ) -> Result<Vec<Candidate>, DetectorFailure> {
        let mut candidates = Vec::new();
        for (line_start, line_end) in lines(input) {
            let line = &input[line_start..line_end];
            if !line_has_context_keyword(line) {
                continue;
            }
            let bytes = line.as_bytes();
            let ends = pattern::run_ends(bytes, pattern::is_alnum);
            let mut start = 0usize;
            while start < bytes.len() {
                if !pattern::is_alnum(bytes[start]) {
                    start += 1;
                    continue;
                }
                let end = ends[start];
                let run = &bytes[start..end];
                if end - start == TOKEN_LEN
                    && pattern::boundary_ok(bytes, start, end, is_boundary_byte)
                    && mixes_letters_and_digits(run)
                    && !text::is_repeated_character_filler(&line[start..end])
                    && !text::is_non_credential_assignment(line, start)
                    && let Some(range) = ByteRange::new(line_start + start, line_start + end)
                {
                    let (confidence, signal) =
                        if text::is_provider_named_assignment(line, start, &[CONTEXT_KEYWORD]) {
                            (Confidence::High, "travisci-named-assignment")
                        } else {
                            (Confidence::Medium, "travisci-keyword-cooccurrence")
                        };
                    candidates.push(
                        Candidate::new("travisci_api_token", confidence, range)
                            .with_specificity(Specificity::Provider)
                            .with_signals([signal, "tool-corroborated-length"]),
                    );
                }
                start = end;
            }
        }
        Ok(candidates)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Locally constructed synthetic value; never issued by Travis CI.
    const TOKEN: &str = "Syn7hRevok3dTrvCi0Tok1";
    const _: () = assert!(TOKEN.len() == TOKEN_LEN);

    fn token() -> &'static str {
        TOKEN
    }

    fn detect(input: &str) -> Vec<Candidate> {
        TravisCiApiTokenDetector
            .detect(input, &DetectorContext::new(input.len()))
            .unwrap()
    }

    fn assert_single(input: &str, confidence: Confidence) {
        let candidates = detect(input);
        assert_eq!(candidates.len(), 1, "{input}");
        assert_eq!(candidates[0].type_name(), "travisci_api_token");
        assert_eq!(candidates[0].confidence(), confidence, "{input}");
        assert_eq!(candidates[0].effective_specificity(), Specificity::Provider);
        let start = input.find(token()).unwrap();
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(start, start + TOKEN_LEN).unwrap(),
            "{input}"
        );
    }

    #[test]
    fn a_travis_named_assignment_is_high_confidence() {
        for input in [
            format!("TRAVIS_TOKEN={}", token()),
            format!("export TRAVIS_API_TOKEN=\"{}\"", token()),
            format!("travis.api_token: {}", token()),
            format!("{{\"travisApiToken\": \"{}\"}}", token()),
            format!("travis_ci_token: '{}'", token()),
        ] {
            assert_single(&input, Confidence::High);
        }
    }

    #[test]
    fn a_high_signal_key_on_a_travis_line_is_high_confidence() {
        assert_single(
            &format!("travis = TravisClient(api_key=\"{}\")", token()),
            Confidence::High,
        );
    }

    #[test]
    fn a_travis_keyword_elsewhere_on_the_line_is_medium_confidence() {
        for input in [
            format!(
                "curl -H \"Authorization: token {}\" https://api.travis-ci.com/user",
                token()
            ),
            format!("# Travis CI API token {}", token()),
            format!("travis login --api-token {}", token()),
        ] {
            assert_single(&input, Confidence::Medium);
        }
    }

    #[test]
    fn a_token_without_a_travis_keyword_on_its_line_is_not_reported() {
        assert!(detect(token()).is_empty());
        assert!(detect(&format!("TOKEN={}", token())).is_empty());
        assert!(detect(&format!("# travis\nTOKEN={}", token())).is_empty());
    }

    #[test]
    fn a_run_of_the_wrong_length_is_not_truncated_or_extended() {
        let short = &token()[..TOKEN_LEN - 1];
        let long = format!("{}9", token());
        assert!(detect(&format!("TRAVIS_TOKEN={short}")).is_empty());
        assert!(detect(&format!("TRAVIS_TOKEN={long}")).is_empty());
    }

    #[test]
    fn a_run_inside_a_wider_identifier_is_not_reported() {
        for input in [
            format!("TRAVIS_TOKEN=x_{}", token()),
            format!("TRAVIS_TOKEN={}_x", token()),
            format!("TRAVIS_TOKEN=x-{}", token()),
            format!("TRAVIS_TOKEN={}-x", token()),
        ] {
            assert!(detect(&input).is_empty(), "{input}");
        }
    }

    #[test]
    fn letter_only_digit_only_and_filler_runs_are_not_reported() {
        for value in [
            "TravisContinuousIntegr",
            "1234567890123456789012",
            "aaaaaaaaaaaaaaaaaaaaaa",
            "xxxxxxxxxxxxxxxxxxxxxx",
        ] {
            assert_eq!(value.len(), TOKEN_LEN);
            assert!(
                detect(&format!("TRAVIS_TOKEN={value}")).is_empty(),
                "{value}"
            );
        }
    }

    #[test]
    fn identifier_keys_on_a_travis_line_are_not_reported() {
        for key in [
            "TRAVIS_REPO_SLUG",
            "TRAVIS_BUILD_ID",
            "travis_job_number",
            "travisUrl",
        ] {
            let input = format!("{key}={}", token());
            assert!(detect(&input).is_empty(), "{input}");
        }
    }

    #[test]
    fn finds_a_token_across_crlf_and_a_unicode_prefix() {
        let input = format!("# \u{1F511} caf\u{e9}\r\nTRAVIS_TOKEN={}\r\n", token());
        let candidates = detect(&input);
        assert_eq!(candidates.len(), 1);
        let start = input.find(token()).unwrap();
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(start, start + TOKEN_LEN).unwrap()
        );
    }

    #[test]
    fn findings_are_deterministic_across_repeated_calls() {
        let input = format!("TRAVIS_TOKEN={}", token());
        assert_eq!(detect(&input), detect(&input));
    }
}
