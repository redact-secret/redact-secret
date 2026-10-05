//! Buildkite token detection (issue #1105, handoff
//! `docs/audits/evidence/1014/buildkite.md`).
//!
//! Buildkite issues 15 documented token prefixes. The grammar is T1 under
//! rulings R2 and R9 from the provider-authored redaction rule in
//! `buildkite/agent` (`internal/redact/redact.go`, merged 2026-09-29, PR
//! #4425, whose prefix list is kept in sync with the Buildkite server's
//! `token_prefixes.rb`) and is cross-checked against the provider docs
//! (`platform/security/tokens`):
//!
//! | Prefix | Role | Finding type |
//! | --- | --- | --- |
//! | `bkua_` | API access token | `buildkite_api_access_token` |
//! | `bkur_`, `bktx_` | OAuth refresh token, token exchange | `buildkite_oauth_token` |
//! | `bkaa_`, `bkar_`, `bkct_`, `bkcqt_` | agent access, agent registration, cluster, cluster queue | `buildkite_agent_token` |
//! | `bkaj_`, `bkjat_` | agent job, job acquisition (JWT bodies) | `buildkite_job_token` |
//! | `bkpt_`, `bkrt_` | packages temporary, packages registry | `buildkite_packages_token` |
//! | `bktr_`, `bkat_` | pipeline trigger, pipeline access | `buildkite_pipeline_token` |
//! | `bkpat_`, `bkps_` | portal token, portal secret | `buildkite_portal_token` |
//!
//! Every prefix is followed by the provider rule's body `[A-Za-z0-9_.-]`
//! (the base64url alphabet plus `.`, which separates the parts of tokens
//! that embed an organization id or are JWTs), at least 24 and at most 2048
//! bytes. The floor of 24 is the provider redactor's own `TokenBodyLengthMin`
//! (below the real-token minimum of 38 so truncated `ps` fragments are still
//! caught, above short placeholders such as `bkjat_encoded-token`); using it
//! as the T1 floor when no alphabet is narrowed is the Q7 recommendation of
//! the #1014 index, which the handoff adopts. No per-type exact length is
//! claimed: none is stated anywhere, and the open-ended body is the only
//! grammar that stays correct across the organization-id, base58, hex and
//! JWT layouts.
//!
//! ## Spans
//!
//! The body is the maximal run, capped at 2048 bytes as the provider rule's
//! `{24,2048}` is: a longer run is reported up to the cap and the tail is not
//! part of the finding. One trailing run of `.` is left outside the span so
//! sentence punctuation is not swallowed, unless that would leave the body
//! under 24 bytes. A `bkjat_` or `bkaj_` JWT is one span from the prefix to
//! the last JWT byte, so overlap resolution reports the provider type and
//! never a separate `jwt` finding for the same bytes.
//!
//! ## Boundaries and exclusions
//!
//! A byte of `[A-Za-z0-9_-]` before the prefix rejects the match (not `.`),
//! so `xbkua_...` and `my_bkua_...` are not claimed. The provider list is
//! closed: other `bk??_` prefixes, the unprefixed legacy agent and API
//! tokens, a bare 40-hex API token, `bka_` + 40 alphanumerics (one
//! third-party rule), body widths under 24, and placeholders stay with
//! generic context. The accepted false positive is an unrelated
//! `bk??_`-prefixed identifier of 24 or more body bytes, such as a `snake_case`
//! variable that begins `bkct_`.

use crate::detectors::pattern::{self, PrefixShape};
use crate::error::DetectorFailure;
use crate::types::{ByteRange, Candidate, Confidence, Detector, DetectorContext, Specificity};

pub(super) const ID: &str = "buildkite-token";

const BODY_MIN: usize = 24;
const BODY_MAX: usize = 2048;
const SIGNALS: [&str; 2] = [
    "buildkite-documented-prefix",
    "buildkite-provider-redaction-grammar",
];

const API_ACCESS: &str = "buildkite_api_access_token";
const OAUTH: &str = "buildkite_oauth_token";
const AGENT: &str = "buildkite_agent_token";
const JOB: &str = "buildkite_job_token";
const PACKAGES: &str = "buildkite_packages_token";
const PIPELINE: &str = "buildkite_pipeline_token";
const PORTAL: &str = "buildkite_portal_token";

/// Every documented prefix with the finding type of its role. No prefix is a
/// prefix of another, so at most one matches at any offset.
const ROLES: [(&str, &str); 15] = [
    ("bkua_", API_ACCESS),
    ("bkur_", OAUTH),
    ("bktx_", OAUTH),
    ("bkaa_", AGENT),
    ("bkar_", AGENT),
    ("bkct_", AGENT),
    ("bkcqt_", AGENT),
    ("bkaj_", JOB),
    ("bkjat_", JOB),
    ("bkpt_", PACKAGES),
    ("bkrt_", PACKAGES),
    ("bktr_", PIPELINE),
    ("bkat_", PIPELINE),
    ("bkpat_", PORTAL),
    ("bkps_", PORTAL),
];

/// One open-ended shape per prefix, in [`ROLES`] order; also the detector's
/// literals for the shared prefilter (`super::prefilter`, issue #983).
pub(super) const SHAPES: &[PrefixShape<'static>] = &[
    PrefixShape::at_least("bkua_", BODY_MIN, pattern::is_alnum_dash_dot, &SIGNALS),
    PrefixShape::at_least("bkur_", BODY_MIN, pattern::is_alnum_dash_dot, &SIGNALS),
    PrefixShape::at_least("bktx_", BODY_MIN, pattern::is_alnum_dash_dot, &SIGNALS),
    PrefixShape::at_least("bkaa_", BODY_MIN, pattern::is_alnum_dash_dot, &SIGNALS),
    PrefixShape::at_least("bkar_", BODY_MIN, pattern::is_alnum_dash_dot, &SIGNALS),
    PrefixShape::at_least("bkct_", BODY_MIN, pattern::is_alnum_dash_dot, &SIGNALS),
    PrefixShape::at_least("bkcqt_", BODY_MIN, pattern::is_alnum_dash_dot, &SIGNALS),
    PrefixShape::at_least("bkaj_", BODY_MIN, pattern::is_alnum_dash_dot, &SIGNALS),
    PrefixShape::at_least("bkjat_", BODY_MIN, pattern::is_alnum_dash_dot, &SIGNALS),
    PrefixShape::at_least("bkpt_", BODY_MIN, pattern::is_alnum_dash_dot, &SIGNALS),
    PrefixShape::at_least("bkrt_", BODY_MIN, pattern::is_alnum_dash_dot, &SIGNALS),
    PrefixShape::at_least("bktr_", BODY_MIN, pattern::is_alnum_dash_dot, &SIGNALS),
    PrefixShape::at_least("bkat_", BODY_MIN, pattern::is_alnum_dash_dot, &SIGNALS),
    PrefixShape::at_least("bkpat_", BODY_MIN, pattern::is_alnum_dash_dot, &SIGNALS),
    PrefixShape::at_least("bkps_", BODY_MIN, pattern::is_alnum_dash_dot, &SIGNALS),
];

/// The finding type of the role whose prefix starts at `start`.
fn type_at(bytes: &[u8], start: usize) -> Option<&'static str> {
    ROLES
        .iter()
        .find(|(prefix, _)| bytes[start..].starts_with(prefix.as_bytes()))
        .map(|&(_, type_name)| type_name)
}

/// The exclusive end of the span for a maximal body run ending at `run_end`:
/// capped at [`BODY_MAX`] body bytes, then one trailing run of `.` trimmed
/// unless that would leave the body under [`BODY_MIN`].
fn span_end(bytes: &[u8], body_start: usize, run_end: usize) -> usize {
    let capped = run_end.min(body_start + BODY_MAX);
    let mut trimmed = capped;
    while trimmed > body_start && bytes[trimmed - 1] == b'.' {
        trimmed -= 1;
    }
    if trimmed - body_start >= BODY_MIN {
        trimmed
    } else {
        capped
    }
}

/// Recognizes the 15 documented Buildkite token prefixes.
pub(super) struct BuildkiteDetector;

pub(super) const BUILDKITE: BuildkiteDetector = BuildkiteDetector;

impl Detector for BuildkiteDetector {
    fn id(&self) -> &str {
        ID
    }

    fn detect(
        &self,
        input: &str,
        _context: &DetectorContext,
    ) -> Result<Vec<Candidate>, DetectorFailure> {
        let bytes = input.as_bytes();
        let mut candidates = Vec::new();
        for (start, run_end, signals) in
            pattern::scan_prefixed_shapes(input, SHAPES, pattern::is_alnum_dash)
        {
            let Some(type_name) = type_at(bytes, start) else {
                continue;
            };
            let prefix_len = ROLES
                .iter()
                .find(|(prefix, _)| bytes[start..].starts_with(prefix.as_bytes()))
                .map_or(0, |(prefix, _)| prefix.len());
            let end = span_end(bytes, start + prefix_len, run_end);
            let Some(range) = ByteRange::new(start, end) else {
                continue;
            };
            candidates.push(
                Candidate::built_in(type_name, Confidence::High, range)
                    .with_specificity(Specificity::Provider)
                    .with_signals(signals.iter().copied()),
            );
        }
        Ok(candidates)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALNUM: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    const BODY: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-.";
    const B64URL: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-";

    /// Synthetic filler, never provider-issued.
    fn filler(alphabet: &[u8], len: usize, seed: usize) -> String {
        (0..len)
            .map(|i| char::from(alphabet[(i * 7 + seed * 13 + i / 5) % alphabet.len()]))
            .collect()
    }

    /// A body whose first and last bytes are alphanumeric, so neither a
    /// leading nor a trailing delimiter ever belongs to it.
    fn body(len: usize, seed: usize) -> String {
        let mut bytes: Vec<u8> = filler(BODY, len, seed).into_bytes();
        bytes[0] = b'B';
        bytes[len - 1] = b'z';
        String::from_utf8(bytes).unwrap()
    }

    fn jwt(seed: usize) -> String {
        format!(
            "eyJ{}.eyJ{}.{}",
            filler(B64URL, 30, seed),
            filler(B64URL, 60, seed + 1),
            filler(B64URL, 43, seed + 2)
        )
    }

    fn detect(input: &str) -> Vec<Candidate> {
        BUILDKITE
            .detect(input, &DetectorContext::new(input.len()))
            .unwrap()
    }

    fn assert_single(input: &str, token: &str, type_name: &str) {
        let candidates = detect(input);
        assert_eq!(candidates.len(), 1, "{input}");
        let start = input.find(token).unwrap();
        assert_eq!(candidates[0].type_name(), type_name, "{input}");
        assert_eq!(candidates[0].confidence(), Confidence::High);
        assert_eq!(candidates[0].effective_specificity(), Specificity::Provider);
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(start, start + token.len()).unwrap(),
            "{input}"
        );
    }

    fn contexts(token: &str) -> Vec<String> {
        vec![
            token.to_owned(),
            format!("BUILDKITE_API_ACCESS_TOKEN={token}"),
            format!("BUILDKITE_AGENT_TOKEN={token}"),
            format!("export BUILDKITE_API_TOKEN=\"{token}\""),
            format!("Authorization: Bearer {token}"),
            format!("{{\"token\": \"{token}\"}}"),
            format!("buildkite-agent start --token {token}"),
            format!("12345 buildkite-agent bootstrap --acquire-job {token} --queue default"),
            format!("Here is my token {token} can you debug this?"),
            format!("\u{d0a4}\u{1f511} 키: {token}"),
        ]
    }

    #[test]
    fn the_role_and_shape_tables_agree() {
        assert_eq!(ROLES.len(), SHAPES.len());
        for ((prefix, _), shape) in ROLES.iter().zip(SHAPES) {
            assert_eq!(*prefix, shape.prefix);
        }
        for (prefix, _) in ROLES {
            for (other, _) in ROLES {
                assert!(
                    prefix == other || !other.starts_with(prefix),
                    "{prefix} {other}"
                );
            }
        }
    }

    #[test]
    fn every_prefix_is_detected_with_its_role_in_every_context() {
        for (seed, (prefix, type_name)) in ROLES.iter().enumerate() {
            let token = format!("{prefix}{}", body(40, seed));
            for input in contexts(&token) {
                assert_single(&input, &token, type_name);
            }
        }
    }

    #[test]
    fn body_shapes_of_every_documented_layout_are_one_span() {
        let org_base58 = format!("{}.{}", filler(ALNUM, 12, 1), filler(ALNUM, 60, 2));
        let org_hex = format!("{}_{}", filler(ALNUM, 12, 3), "5e7c0ded".repeat(5));
        let hex40 = "5e7c0ded".repeat(5);
        for (prefix, token_body) in [
            ("bkaa_", org_base58.clone()),
            ("bkct_", org_base58),
            ("bkpat_", org_hex),
            ("bkua_", hex40),
            ("bkjat_", jwt(4)),
            ("bkaj_", jwt(5)),
        ] {
            let token = format!("{prefix}{token_body}");
            let type_name = type_at(token.as_bytes(), 0).unwrap();
            for input in contexts(&token) {
                assert_single(&input, &token, type_name);
            }
        }
    }

    #[test]
    fn the_floor_is_24_body_bytes() {
        for prefix in ["bkua_", "bkjat_", "bkcqt_"] {
            let at_floor = format!("{prefix}{}", body(24, 6));
            for input in contexts(&at_floor) {
                assert_single(&input, &at_floor, type_at(at_floor.as_bytes(), 0).unwrap());
            }
            let below = format!("{prefix}{}", body(23, 7));
            for input in contexts(&below) {
                assert!(detect(&input).is_empty(), "{input}");
            }
        }
    }

    #[test]
    fn the_cap_is_2048_body_bytes_and_the_tail_is_not_part_of_the_finding() {
        let at_cap = format!("bkua_{}", body(BODY_MAX, 8));
        assert_single(&at_cap, &at_cap, API_ACCESS);
        let over = format!("bkua_{}", body(BODY_MAX + 1, 9));
        let candidates = detect(&over);
        assert_eq!(candidates.len(), 1);
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(0, "bkua_".len() + BODY_MAX).unwrap()
        );
        let long = format!("bkjat_{}", body(5_000, 10));
        let candidates = detect(&long);
        assert_eq!(candidates.len(), 1);
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(0, "bkjat_".len() + BODY_MAX).unwrap()
        );
    }

    #[test]
    fn a_trailing_dot_run_is_left_outside_the_span() {
        let token = format!("bkua_{}", body(40, 11));
        for suffix in [".", "..", "...", ".\n", ". Next"] {
            assert_single(&format!("{token}{suffix}"), &token, API_ACCESS);
        }
        // A dot inside the body stays inside it.
        let dotted = format!("bkaa_{}.{}", filler(ALNUM, 12, 12), filler(ALNUM, 30, 13));
        assert_single(&format!("{dotted}."), &dotted, AGENT);
        // Trimming never takes the body under the floor.
        let short = format!("bkua_{}.", body(23, 14));
        let candidates = detect(&short);
        assert_eq!(candidates.len(), 1);
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(0, short.len()).unwrap()
        );
    }

    #[test]
    fn leading_and_trailing_delimiters_keep_the_exact_span() {
        let token = format!("bkpat_{}", body(40, 15));
        for suffix in [",", ";", ")", "\"", "'", "`", "\n", " tail", "]", "=", "/"] {
            assert_single(&format!("{token}{suffix}"), &token, PORTAL);
        }
        for prefix in ["(", "\"", "'", "`", "=", ":", " ", "\t", "[", "<", ".", "/"] {
            assert_single(&format!("{prefix}{token}"), &token, PORTAL);
        }
    }

    #[test]
    fn near_miss_twins_are_rejected() {
        let long = body(40, 16);
        let token = format!("bkua_{long}");
        for input in [
            format!("bkua_{}", &long[..23]),
            format!("bkzz_{long}"),
            format!("bkaaa_{long}"),
            format!("bka_{long}"),
            format!("BKUA_{long}"),
            format!("bkua-{long}"),
            format!("bkua.{long}"),
            format!("bkua{long}"),
            format!("xbkua_{long}"),
            format!("_{token}"),
            format!("-{token}"),
            format!("my_{token}"),
            format!("bkua_{}=padding", &long[..20]),
            format!("bkua_{}/{}", &long[..20], &long[..10]),
        ] {
            assert!(detect(&input).is_empty(), "{input}");
        }
    }

    #[test]
    fn placeholders_and_unrelated_values_are_unclaimed() {
        let hex40 = "5e7c0ded".repeat(5);
        for input in [
            "bkjat_encoded-token".to_owned(),
            "bkua_xxx".to_owned(),
            format!("bkua_{}", "*".repeat(53)),
            "BUILDKITE_AGENT_TOKEN=${BUILDKITE_AGENT_TOKEN}".to_owned(),
            "bkct_cluster_name_for_builds".to_owned(),
            format!("bka_{}", filler(ALNUM, 40, 17)),
            hex40,
            filler(ALNUM, 60, 18),
        ] {
            assert!(detect(&input).is_empty(), "{input}");
        }
    }

    #[test]
    fn repeated_tokens_are_reported_once_each_and_a_glued_run_is_one_capped_span() {
        let token = format!("bkua_{}", body(40, 19));
        assert_eq!(detect(&format!("{token} {token}")).len(), 2);
        // Glued copies are one open-ended body, as the provider's own
        // `{24,2048}` rule reads them: one span, capped, never a finding per
        // copy and never a scan that rescans the run.
        for glued in [
            token.repeat(200),
            "bkua_".repeat(10_000),
            "bkjat_bkua_".repeat(5_000),
        ] {
            let candidates = detect(&glued);
            assert_eq!(candidates.len(), 1);
            let prefix_len = glued.find('_').unwrap() + 1;
            assert_eq!(
                candidates[0].range(),
                ByteRange::new(0, prefix_len + BODY_MAX).unwrap()
            );
        }
    }
}
