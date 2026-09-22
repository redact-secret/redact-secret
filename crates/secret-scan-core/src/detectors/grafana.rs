//! Grafana service account token detection.
//!
//! Grafana's service-account documentation
//! (`https://grafana.com/docs/grafana/latest/administration/service-accounts/`)
//! describes a service account token only as "a generated random string";
//! it publishes no character-class grammar. Its own example request does
//! show every token beginning with the literal `glsa_`, and two independent
//! external tools -- gitleaks's `grafana-service-account-token` rule and
//! trufflehog's `grafana` detector, consulted only as behavioral references
//! per `AGENTS.md` -- both converge on the same shape: the `glsa_` prefix,
//! then exactly 32 bytes of `[A-Za-z0-9]`, then a literal `_`, then exactly
//! 8 bytes of `[A-Fa-f0-9]` (a checksum), for 46 bytes total. No code from
//! either project is reproduced here; this module's matching is authored
//! independently against that community-confirmed shape.
//!
//! This two-segment prefix-separator-segment shape does not fit
//! [`super::pattern::scan_prefixed_runs`]'s single prefix-then-run shape
//! (used by every simple known-format provider in `additional_providers.rs`),
//! so this detector walks the match by hand the way [`super::sendgrid`] does
//! for its own two-segment shape.
//!
//! ## Legacy API key: explicitly out of scope
//!
//! Grafana's legacy (pre-service-account) API keys are a bare base64 blob
//! that decodes to JSON beginning `{"k":...}`, giving them the literal
//! prefix `eyJrIjoi` once base64-encoded (gitleaks's `grafana-api-key`
//! rule uses exactly this prefix). Per issue #305's explicit instruction to
//! "explicitly decide legacy API-key support," this module does not cover
//! them: Grafana's own documentation states that service accounts "replace
//! API keys as the primary way to authenticate applications that interact
//! with Grafana," so the format is deprecated by the provider itself, and a
//! bare base64-JSON blob with no Grafana-owned structural marker beyond a
//! generic encoding convention would duplicate the false-positive risk this
//! crate's [`super::jwt`] and [`super::generic_token`] detectors already
//! carry for opaque base64/JSON-shaped values, without a documented grammar
//! to bound it. This is a deliberate scope exclusion, not an oversight; see
//! `docs/decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md`
//! (Grafana row).
//!
//! ## Action
//!
//! The finding is `Specificity::Provider` and listed in
//! `policy::ALWAYS_REDACT_TYPES`: the fixed prefix, exact two-segment
//! length, and checksum-shaped second segment are specific enough on their
//! own, the same tradeoff every other fixed-prefix provider grammar in this
//! crate already makes.

use crate::detectors::pattern::{self, is_alnum};
use crate::error::DetectorFailure;
use crate::types::{ByteRange, Candidate, Confidence, Detector, DetectorContext, Specificity};

const PREFIX: &[u8] = b"glsa_";
const BODY_LEN: usize = 32;
const SEPARATOR: u8 = b'_';
const CHECKSUM_LEN: usize = 8;

/// `[0-9A-Fa-f]`: the checksum segment's alphabet.
fn is_hex(byte: u8) -> bool {
    byte.is_ascii_hexdigit()
}

/// Requires the exact `glsa_<32 alnum>_<8 hex>` shape. A shorter or longer
/// segment, a missing or misplaced separator, a non-hex checksum, or a
/// body/checksum run embedded in a wider identifier is an intentional
/// false negative rather than a fuzzy match.
pub(super) struct GrafanaServiceAccountTokenDetector;

impl Detector for GrafanaServiceAccountTokenDetector {
    fn id(&self) -> &'static str {
        "grafana-service-account-token"
    }

    fn detect(
        &self,
        input: &str,
        _context: &DetectorContext,
    ) -> Result<Vec<Candidate>, DetectorFailure> {
        let bytes = input.as_bytes();
        let alnum_ends = pattern::run_ends(bytes, is_alnum);
        let hex_ends = pattern::run_ends(bytes, is_hex);
        let mut candidates = Vec::new();
        let mut start = 0;
        while start < bytes.len() {
            if !bytes[start..].starts_with(PREFIX) {
                start += 1;
                continue;
            }

            let Some(end) = match_at(bytes, &alnum_ends, &hex_ends, start) else {
                start += 1;
                continue;
            };

            if pattern::boundary_ok(bytes, start, end, pattern::is_alnum_dash)
                && let Some(range) = ByteRange::new(start, end)
            {
                candidates.push(
                    Candidate::new("grafana_service_account_token", Confidence::High, range)
                        .with_specificity(Specificity::Provider)
                        .with_signals(["grafana-documented-prefix", "two-segment-exact-length"]),
                );
            }
            start = end;
        }
        Ok(candidates)
    }
}

/// Attempts a `glsa_<32 alnum>_<8 hex>` match anchored exactly at `start`,
/// where `bytes[start..]` is already known to begin with [`PREFIX`].
/// Returns the exclusive end offset on success; the caller still applies
/// the boundary check.
///
/// `alnum_ends` and `hex_ends` are the precomputed maximal-run-end tables
/// from [`pattern::run_ends`], so each segment's length is a table lookup
/// rather than a rescan, keeping the whole detector linear in the input
/// length.
fn match_at(bytes: &[u8], alnum_ends: &[usize], hex_ends: &[usize], start: usize) -> Option<usize> {
    let body_start = start + PREFIX.len();
    if alnum_ends[body_start] < body_start + BODY_LEN {
        return None;
    }
    let separator = body_start + BODY_LEN;
    if bytes.get(separator) != Some(&SEPARATOR) {
        return None;
    }

    let checksum_start = separator + 1;
    if hex_ends[checksum_start] < checksum_start + CHECKSUM_LEN {
        return None;
    }

    Some(checksum_start + CHECKSUM_LEN)
}

#[cfg(test)]
mod tests {
    use super::*;

    const BODY: &str = "SYNTHETICREVOKEDGRAFANASATOKEN01";
    const CHECKSUM: &str = "deadbeef";

    fn token() -> String {
        format!("glsa_{BODY}_{CHECKSUM}")
    }

    fn detect(input: &str) -> Vec<Candidate> {
        GrafanaServiceAccountTokenDetector
            .detect(input, &DetectorContext::new(input.len()))
            .unwrap()
    }

    #[test]
    fn fixture_segments_are_exactly_documented_length() {
        assert_eq!(BODY.len(), BODY_LEN);
        assert_eq!(CHECKSUM.len(), CHECKSUM_LEN);
    }

    #[test]
    fn detects_a_synthetic_token_with_provider_specificity() {
        let value = token();
        let candidates = detect(&value);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].type_name(), "grafana_service_account_token");
        assert_eq!(candidates[0].confidence(), Confidence::High);
        assert_eq!(candidates[0].effective_specificity(), Specificity::Provider);
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(0, value.len()).unwrap()
        );
    }

    #[test]
    fn detects_the_token_bare_in_env_and_control_contexts() {
        let value = token();
        for input in [
            value.clone(),
            format!("GRAFANA_SA_TOKEN={value}"),
            format!("grafana_service_account_token: {value}"),
            format!("{{\"token\": \"{value}\"}}"),
        ] {
            let candidates = detect(&input);
            assert_eq!(candidates.len(), 1, "{input}");
            let (start, end) = (candidates[0].range().start(), candidates[0].range().end());
            assert_eq!(&input[start..end], value, "{input}");
        }
    }

    #[test]
    fn accepts_punctuation_boundaries() {
        let value = token();
        let input = format!("({value}).");
        let candidates = detect(&input);
        assert_eq!(candidates.len(), 1);
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(1, value.len() + 1).unwrap()
        );
    }

    #[test]
    fn rejects_a_truncated_body_segment() {
        let short_body = &BODY[..BODY_LEN - 1];
        assert!(detect(&format!("glsa_{short_body}_{CHECKSUM}")).is_empty());
    }

    #[test]
    fn rejects_a_truncated_checksum_segment() {
        let short_checksum = &CHECKSUM[..CHECKSUM_LEN - 1];
        assert!(detect(&format!("glsa_{BODY}_{short_checksum}")).is_empty());
    }

    #[test]
    fn rejects_a_body_segment_longer_than_documented() {
        assert!(detect(&format!("glsa_{BODY}A_{CHECKSUM}")).is_empty());
    }

    #[test]
    fn rejects_a_checksum_segment_longer_than_documented() {
        assert!(detect(&format!("glsa_{BODY}_{CHECKSUM}a")).is_empty());
    }

    #[test]
    fn rejects_a_malformed_separator() {
        assert!(detect(&format!("glsa_{BODY}.{CHECKSUM}")).is_empty());
        assert!(detect(&format!("glsa-{BODY}_{CHECKSUM}")).is_empty());
    }

    #[test]
    fn rejects_a_non_hex_checksum() {
        assert!(detect(&format!("glsa_{BODY}_SYNTHETIC")).is_empty());
    }

    #[test]
    fn rejects_the_prefix_alone() {
        assert!(detect("glsa_").is_empty());
        assert!(detect(&format!("glsa_{BODY}")).is_empty());
    }

    #[test]
    fn rejects_the_body_or_checksum_embedded_in_a_wider_identifier() {
        let value = token();
        assert!(detect(&format!("x{value}")).is_empty());
        assert!(detect(&format!("{value}x")).is_empty());
    }

    #[test]
    fn rejects_a_masked_value() {
        assert!(detect("glsa_********************************_********").is_empty());
    }

    #[test]
    fn rejects_an_environment_variable_reference() {
        assert!(detect("${GRAFANA_SA_TOKEN}").is_empty());
    }

    #[test]
    fn finds_a_match_across_crlf_and_a_unicode_prefix() {
        let value = token();
        let input = format!("# \u{1F511} caf\u{e9}\r\n{value}\r\n");
        let candidates = detect(&input);
        assert_eq!(candidates.len(), 1);
        let start = input.find(&value).unwrap();
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(start, start + value.len()).unwrap()
        );
    }

    #[test]
    fn finds_deterministic_findings_across_repeated_calls() {
        let value = token();
        assert_eq!(detect(&value), detect(&value));
    }

    #[test]
    fn stays_bounded_over_a_long_run_of_near_miss_prefixes() {
        // Every occurrence has a body one byte short of the documented
        // length, so none matches; the scan must still stay linear instead
        // of rescanning from each failed prefix position.
        let short_body = &BODY[..BODY_LEN - 1];
        let input = format!("glsa_{short_body}_{CHECKSUM} ").repeat(10_000);
        assert_eq!(detect(&input).len(), 0);
    }
}
