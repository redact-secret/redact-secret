//! GitLab token detection.
//!
//! Mirrors `src/detectors/gitlab.ts`, plus the exact runner authentication
//! token grammar of issue #730.

use crate::detectors::pattern::{self, RunLength};
use crate::error::DetectorFailure;
use crate::types::{ByteRange, Candidate, Confidence, Detector, DetectorContext, Specificity};

/// `glrt-` is not in this table since issue #730: it has its own
/// [`GitlabRunnerAuthenticationTokenDetector`] with an exact grammar.
const PREFIXES: [&str; 12] = [
    "glpat-", "gloas-", "gldt-", "glrtr-", "glcbt-", "glptt-", "glft-", "glimt-", "glagent-",
    "glwt-", "glsoat-", "glffct-",
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
/// - `glrtr-`'s "routable" variant embeds a `.`-delimited version and
///   checksum segment this scan's alnum/dash/underscore alphabet does not
///   span, and no source corroborates the base64 payload's own length, so a
///   short payload is missed entirely rather than matched at a wrong length.
///   (`glrt-`, whose routable form is provider-code-backed, is handled by
///   [`GitlabRunnerAuthenticationTokenDetector`].)
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

const RUNNER_PREFIX: &str = "glrt-";
const RUNNER_TYPE: &str = "gitlab_runner_authentication_token";
/// Devise's `friendly_token`: `urlsafe_base64(15)`, 20 bytes.
const RUNNER_LEGACY_BODY_LEN: usize = 20;
/// Routable payload bounds: 16 random bytes plus routing lines plus a length
/// byte, base64url-encoded (27 bytes minimum), with a generous ceiling.
const ROUTABLE_PAYLOAD_MIN: usize = 27;
const ROUTABLE_PAYLOAD_MAX: usize = 300;
const ROUTABLE_VERSION_LEN: usize = 2;
const ROUTABLE_LENGTH_LEN: usize = 2;
const ROUTABLE_CRC_LEN: usize = 7;
const RUNNER_LEGACY_SIGNALS: [&str; 2] = ["gitlab-documented-prefix", "friendly-token-body"];
const RUNNER_ROUTABLE_SIGNALS: [&str; 3] = [
    "gitlab-documented-prefix",
    "routable-length-holder",
    "routable-crc32",
];

fn is_token_char(byte: u8) -> bool {
    pattern::is_alnum_dash(byte) || byte == b'_'
}

fn is_base36(byte: u8) -> bool {
    byte.is_ascii_digit() || byte.is_ascii_lowercase()
}

/// IEEE CRC-32 (reflected, polynomial `0xEDB88320`), the checksum GitLab's
/// routable-token generator computes; dependency-free and bitwise, since the
/// hashed span is at most a few hundred bytes.
fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for &byte in bytes {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = if crc & 1 == 1 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

/// `value` as base36, zero-padded on the left to `width` digits, or `None`
/// when it needs more.
fn base36_padded(mut value: u64, width: usize) -> Option<Vec<u8>> {
    let mut digits = Vec::new();
    while value > 0 {
        digits.push(b"0123456789abcdefghijklmnopqrstuvwxyz"[(value % 36) as usize]);
        value /= 36;
    }
    if digits.len() > width {
        return None;
    }
    digits.resize(width, b'0');
    digits.reverse();
    Some(digits)
}

fn parse_base36(digits: &[u8]) -> Option<u64> {
    digits.iter().try_fold(0u64, |acc, &digit| {
        let value = match digit {
            b'0'..=b'9' => digit - b'0',
            b'a'..=b'z' => digit - b'a' + 10,
            _ => return None,
        };
        acc.checked_mul(36)?.checked_add(u64::from(value))
    })
}

/// The 20-byte friendly-token body, optionally after the legacy
/// `t<hex partition>_` segment.
fn is_legacy_body(body: &[u8]) -> bool {
    if body.len() == RUNNER_LEGACY_BODY_LEN {
        return true;
    }
    let Some(separator) = body.iter().position(|&byte| byte == b'_') else {
        return false;
    };
    body.first() == Some(&b't')
        && separator >= 2
        && body[1..separator]
            .iter()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
        && body.len() - separator - 1 == RUNNER_LEGACY_BODY_LEN
}

/// The end of a routable token whose payload starts at `payload_start` and
/// ends at `payload_end` (the `.`), or `None` when the dotted tail is absent
/// or fails the offline length-holder and CRC-32 checks.
fn routable_end(
    bytes: &[u8],
    start: usize,
    payload_start: usize,
    payload_end: usize,
) -> Option<usize> {
    let payload_len = payload_end - payload_start;
    if !(ROUTABLE_PAYLOAD_MIN..=ROUTABLE_PAYLOAD_MAX).contains(&payload_len) {
        return None;
    }
    let version_start = payload_end + 1;
    let second_dot = version_start + ROUTABLE_VERSION_LEN;
    let length_start = second_dot + 1;
    let crc_start = length_start + ROUTABLE_LENGTH_LEN;
    let end = crc_start + ROUTABLE_CRC_LEN;
    let tail = bytes.get(version_start..end)?;
    if !tail[..ROUTABLE_VERSION_LEN].iter().copied().all(is_base36)
        || bytes[second_dot] != b'.'
        || !bytes[length_start..end].iter().copied().all(is_base36)
    {
        return None;
    }
    if parse_base36(&bytes[length_start..crc_start])? != payload_len as u64 {
        return None;
    }
    let expected = base36_padded(u64::from(crc32(&bytes[start..crc_start])), ROUTABLE_CRC_LEN)?;
    (bytes[crc_start..end] == expected[..]).then_some(end)
}

/// Every boundary-delimited `glrt-` runner authentication token, left to
/// right (issue #730, `docs/audits/evidence/726/README.md`): the prefix plus
/// either the exact 20-byte friendly-token body (optionally after the legacy
/// `t<hex>_` partition segment), or the routable
/// `<base64url>.<2 base36>.<2 base36 length><7 base36 CRC-32>` form whose
/// length holder and CRC-32 (over everything before it, prefix included) are
/// validated offline. `glrtr-`, instance prefixes and the unversioned
/// routable form are unclaimed, and a body of any other width is an
/// intentional false negative, never truncated.
pub(super) struct GitlabRunnerAuthenticationTokenDetector;

impl Detector for GitlabRunnerAuthenticationTokenDetector {
    fn id(&self) -> &'static str {
        "gitlab-runner-authentication-token"
    }

    fn detect(
        &self,
        input: &str,
        _context: &DetectorContext,
    ) -> Result<Vec<Candidate>, DetectorFailure> {
        let bytes = input.as_bytes();
        let run_ends = pattern::run_ends(bytes, is_token_char);
        let mut candidates = Vec::new();
        let mut start = 0;
        while start < bytes.len() {
            if !bytes[start..].starts_with(RUNNER_PREFIX.as_bytes()) {
                start += 1;
                continue;
            }
            let body_start = start + RUNNER_PREFIX.len();
            let run_end = run_ends[body_start];
            let routable = (bytes.get(run_end) == Some(&b'.'))
                .then(|| routable_end(bytes, start, body_start, run_end))
                .flatten();
            let (end, signals) = match routable {
                Some(end) => (end, RUNNER_ROUTABLE_SIGNALS.as_slice()),
                None if is_legacy_body(&bytes[body_start..run_end]) => {
                    (run_end, RUNNER_LEGACY_SIGNALS.as_slice())
                }
                None => {
                    start += 1;
                    continue;
                }
            };
            if let Some(range) = ByteRange::new(start, end)
                .filter(|_| pattern::boundary_ok(bytes, start, end, is_token_char))
            {
                candidates.push(
                    Candidate::new(RUNNER_TYPE, Confidence::High, range)
                        .with_specificity(Specificity::Provider)
                        .with_signals(signals.iter().copied()),
                );
            }
            start = end;
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
    fn leaves_glrt_to_the_runner_detector_and_keeps_its_longer_glrtr_sibling() {
        assert!(detect("glrt-SYNTHETICREVOKEDRUNN").is_empty());
        let input = "glrtr-SYNTHETIC_REVOKED_PREFIX_FIXTURE";
        assert_eq!(detect(input).len(), 1);
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

    /// The legacy, unprefixed runner *registration* token (distinct from the
    /// `glrt-`/`glrtr-` runner *authentication* token) carries no documented
    /// prefix and is itself provider-deprecated; it is not, and cannot be, a
    /// candidate for this prefix-anchored scan.
    #[test]
    fn does_not_match_a_legacy_unprefixed_runner_registration_token() {
        assert_eq!(detect("f7c2b1a9e4d6038f5a1c2e9b0d7f4a63").len(), 0);
    }

    fn runner(input: &str) -> Vec<Candidate> {
        GitlabRunnerAuthenticationTokenDetector
            .detect(input, &DetectorContext::new(input.len()))
            .unwrap()
    }

    fn runner_ranges(input: &str) -> Vec<(usize, usize)> {
        runner(input)
            .iter()
            .map(|candidate| (candidate.range().start(), candidate.range().end()))
            .collect()
    }

    // Synthetic routable values: the payload is invented text, and the length
    // holder and CRC-32 were computed over it, so none was ever issued.
    const ROUTABLE: &str = "glrt-SyntheticRevokedRunnerPayloadA1.01.0v0xy8zct";
    const ROUTABLE_DASHED: &str = "glrt-SyntheticRevokedRunnerPayloadA1_-xZZZZZZ.01.141tpsiyp";
    const LEGACY: &str = "glrt-SyntheticRevokedRun1";
    const PARTITIONED: &str = "glrt-t3_SyntheticRevokedRun1";

    #[test]
    fn crc32_matches_the_standard_check_value() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    }

    #[test]
    fn detects_legacy_partitioned_and_routable_values_with_their_own_type() {
        for (value, signal) in [
            (LEGACY, "friendly-token-body"),
            (PARTITIONED, "friendly-token-body"),
            (ROUTABLE, "routable-crc32"),
            (ROUTABLE_DASHED, "routable-crc32"),
        ] {
            assert_eq!(LEGACY.len(), 5 + RUNNER_LEGACY_BODY_LEN);
            let candidates = runner(value);
            assert_eq!(candidates.len(), 1, "{value}");
            assert_eq!(candidates[0].type_name(), RUNNER_TYPE);
            assert_eq!(candidates[0].confidence(), Confidence::High);
            assert_eq!(candidates[0].effective_specificity(), Specificity::Provider);
            assert!(
                candidates[0].signals().iter().any(|s| s == signal),
                "{value}"
            );
            assert_eq!(
                candidates[0].range(),
                ByteRange::new(0, value.len()).unwrap(),
                "{value}"
            );
        }
    }

    #[test]
    fn a_routable_value_is_retained_in_full_inside_text() {
        let input = format!("token = \"{ROUTABLE}\".");
        assert_eq!(runner_ranges(&input), vec![(9, 9 + ROUTABLE.len())]);
    }

    #[test]
    fn a_sentence_period_after_a_legacy_value_does_not_make_it_routable() {
        let input = format!("registered {LEGACY}.");
        assert_eq!(runner_ranges(&input), vec![(11, 11 + LEGACY.len())]);
    }

    #[test]
    fn a_failed_length_holder_or_checksum_is_rejected() {
        let bad_crc = ROUTABLE.replace("0v0xy8zct", "0v0xy8zcu");
        let bad_length = ROUTABLE.replace(".0v0xy8zct", ".0w0xy8zct");
        let bad_payload = ROUTABLE.replace("Synthetic", "Syntheti_");
        for input in [bad_crc, bad_length, bad_payload] {
            assert!(runner(&input).is_empty(), "{input}");
        }
    }

    #[test]
    fn a_malformed_routable_tail_is_rejected() {
        for input in [
            "glrt-SyntheticRevokedRunnerPayloadA1.01.0v0xy8zc",
            "glrt-SyntheticRevokedRunnerPayloadA1.01.0v0xy8zctx",
            "glrt-SyntheticRevokedRunnerPayloadA1.01.0v0xy8zcT",
            "glrt-SyntheticRevokedRunnerPayloadA1.0.0v0xy8zct",
            "glrt-SyntheticRevokedRunnerPayloadA1.01",
            "glrt-Short.01.050000000",
        ] {
            assert!(runner(input).is_empty(), "{input}");
        }
    }

    #[test]
    fn a_legacy_body_of_another_width_is_rejected_not_truncated() {
        for input in [
            "glrt-SyntheticRevokedRun",
            "glrt-SyntheticRevokedRun12",
            "glrt-SyntheticRevokedRunn0123456789",
            "glrt-t3_SyntheticRevokedRun",
            "glrt-tZ_SyntheticRevokedRun1",
            "glrt-T3_SyntheticRevokedRun1",
            "glrt-t_SyntheticRevokedRun1",
        ] {
            assert!(runner(input).is_empty(), "{input}");
        }
    }

    #[test]
    fn a_glued_identifier_boundary_rejects_an_embedded_value() {
        for input in [
            format!("x{LEGACY}"),
            format!("-{LEGACY}"),
            format!("{LEGACY}_backup"),
            format!("{LEGACY}-1"),
            format!("_{ROUTABLE}"),
            format!("{ROUTABLE}x"),
        ] {
            assert!(runner(&input).is_empty(), "{input}");
        }
    }

    #[test]
    fn near_miss_prefixes_and_unclaimed_siblings_are_not_claimed() {
        for input in [
            "GLRT-SyntheticRevokedRun1".to_owned(),
            "glrt_SyntheticRevokedRun1".to_owned(),
            "glrtr-SyntheticRevokedRun1".to_owned(),
            "glpat-SyntheticRevokedRun1".to_owned(),
            "gl-SyntheticRevokedRun1".to_owned(),
            "runner s_0123456789ab short sha 1a2b3c4d".to_owned(),
        ] {
            assert!(runner(&input).is_empty(), "{input}");
        }
    }

    #[test]
    fn a_repeated_value_is_reported_once_per_occurrence() {
        let input = format!("{ROUTABLE} {LEGACY}");
        assert_eq!(runner(&input).len(), 2);
    }
}
