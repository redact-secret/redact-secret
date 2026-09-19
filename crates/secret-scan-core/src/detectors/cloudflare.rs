//! Cloudflare scannable API token detection.
//!
//! The reviewed grammar (issue #373, following the frozen precision
//! contract from issue #367, `docs/audits/evidence/367/precision-contracts.json`,
//! `families.cloudflare-token`) is `cfut_[A-Za-z0-9]{40}[0-9a-f]{8}`:
//! Cloudflare's token documentation and creation flow establish the `cfut_`
//! prefix and a 40-character alphanumeric body; trufflehog 3.97.4's
//! `cloudflareapitoken` v2 rule additionally corroborates that the body is
//! followed by an 8-character lowercase-hex checksum. The provider
//! documents that a checksum follows the body but does not publish its
//! width or alphabet, so a bare 40-byte body is malformed; the checksum's
//! width and lowercase-hex alphabet are a single-tool-corroborated
//! support-policy adoption, validated lexically only -- no checksum
//! algorithm is computed or claimed. A body one byte short of 40, or a
//! non-hex or uppercase-hex checksum, is an intentional false negative
//! rather than a match.
//!
//! Unlike [`super::grafana`] and [`super::sendgrid`], the two segments here
//! carry no literal separator. That still fits a single prefix-then-run
//! [`PrefixShape`], because the checksum's `[0-9a-f]` alphabet is a subset
//! of the body's `[A-Za-z0-9]` alphabet: the whole 48-byte suffix is one
//! contiguous alphanumeric run, so an exact-length `cfut_` shape already
//! finds its true extent (a shorter run, or a longer one the boundary check
//! would reject, both fail the same way every other exact-length provider
//! grammar in `additional_providers.rs` does). The shape's own
//! [`super::pattern::PostCheck`] carries what the run length alone cannot:
//! that the run's last 8 bytes are lowercase hex, rejecting a body-shaped
//! run whose tail is not checksum-shaped. That keeps this detector the same
//! table-driven
//! [`super::additional_providers::KnownFormatProviderDetector`] every other
//! provider in that module uses, not a bespoke `detect` body.
//!
//! Cloudflare's `cfat_` (account token) and `cfk_` (scannable global key)
//! namespaces are provider-documented with the same shape but not matched
//! by beta.4 or either consulted tool's `cfut_`-only rule; adding them is a
//! coverage change for a separate issue, recorded as a known false negative
//! (`docs/audits/evidence/367/precision-contracts.json`, `pending`). The
//! legacy unprefixed 40-character alphanumeric token and 37-45-character
//! hex Global API Key remain out of scope: both are indistinguishable from
//! ordinary opaque values without a prefix to anchor on.

use crate::detectors::additional_providers::KnownFormatProviderDetector;
use crate::detectors::pattern::{PrefixShape, is_alnum, is_alnum_dash, is_lower_hex};

const PREFIX: &str = "cfut_";
/// The documented body length.
const BODY_LEN: usize = 40;
/// The tool-corroborated checksum length.
const CHECKSUM_LEN: usize = 8;
/// The body and checksum form one contiguous `[A-Za-z0-9]` run (see the
/// module docs), so the shared shape is matched as this combined exact
/// length.
const SUFFIX_LEN: usize = BODY_LEN + CHECKSUM_LEN;

const SIGNALS: [&str; 2] = ["cloudflare-scannable-prefix", "checksum-shaped-suffix"];

/// `true` when the matched run's last [`CHECKSUM_LEN`] bytes are lowercase
/// hex — the [`PrefixShape::post_check`] this shape's exact-length body
/// alone cannot express.
fn checksum_tail_is_lower_hex(bytes: &[u8], _start: usize, end: usize) -> bool {
    let checksum_start = end - CHECKSUM_LEN;
    bytes[checksum_start..end].iter().copied().all(is_lower_hex)
}

/// Requires the exact `cfut_<40 alnum><8 lowercase-hex>` shape. A body or
/// checksum segment short of its documented length, a checksum containing a
/// non-hex or uppercase-hex byte, or a run embedded in a wider identifier is
/// an intentional false negative rather than a fuzzy match.
pub(super) const CLOUDFLARE: KnownFormatProviderDetector = KnownFormatProviderDetector::new(
    "cloudflare-token",
    "cloudflare_api_token",
    &[PrefixShape::exact(PREFIX, SUFFIX_LEN, is_alnum, &SIGNALS)
        .with_post_check(checksum_tail_is_lower_hex)],
    is_alnum_dash,
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ByteRange, Candidate, Confidence, Detector, DetectorContext, Specificity};

    const BODY: &str = "SYNTHETICREVOKEDCLOUDFLAREAPITOKENVALUE1";
    const CHECKSUM: &str = "deadbeef";

    const _: () = assert!(BODY.len() == BODY_LEN);
    const _: () = assert!(CHECKSUM.len() == CHECKSUM_LEN);

    fn token() -> String {
        format!("{PREFIX}{BODY}{CHECKSUM}")
    }

    fn detect(input: &str) -> Vec<Candidate> {
        CLOUDFLARE
            .detect(input, &DetectorContext::new(input.len()))
            .unwrap()
    }

    #[test]
    fn detects_a_synthetic_credential_with_provider_specificity() {
        let value = token();
        let candidates = detect(&value);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].type_name(), "cloudflare_api_token");
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
            format!("CLOUDFLARE_API_TOKEN={value}"),
            format!("cloudflare_api_token: {value}"),
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

    /// Issue #373: the beta.4 `cloudflare-token-user-plain-twin` regression
    /// shape -- a body one byte short of the documented 40-byte length.
    #[test]
    fn rejects_a_body_one_byte_short_of_the_documented_length() {
        let short_body = &BODY[..BODY_LEN - 1];
        assert!(detect(&format!("{PREFIX}{short_body}{CHECKSUM}")).is_empty());
    }

    #[test]
    fn rejects_a_checksum_one_byte_short_of_the_documented_length() {
        let short_checksum = &CHECKSUM[..CHECKSUM_LEN - 1];
        assert!(detect(&format!("{PREFIX}{BODY}{short_checksum} ")).is_empty());
    }

    /// A run one byte longer than the documented combined length is
    /// rejected via the boundary check rather than truncated to the
    /// documented shape, the same precedent `digitalocean-token` and
    /// `npm-token` already set for their own exact-length grammars.
    #[test]
    fn rejects_a_run_one_byte_longer_than_the_documented_length() {
        assert!(detect(&format!("{PREFIX}{BODY}{CHECKSUM}a")).is_empty());
    }

    /// Issue #373: the reproduced beta.4 regression -- a checksum whose
    /// eight bytes are alphanumeric but not hexadecimal. Retained as
    /// must-not-flag: the value carries no checksum segment of any shape a
    /// consulted source describes.
    #[test]
    fn rejects_a_non_hex_checksum() {
        assert!(detect(&format!("{PREFIX}{BODY}ghijklmn")).is_empty());
    }

    /// The checksum alphabet is `[0-9a-f]`, not `[0-9A-Fa-f]`: the single
    /// tool corroborating its shape states lowercase hex, so an
    /// uppercase-hex checksum is an intentional false negative rather than
    /// a case-insensitive match.
    #[test]
    fn rejects_an_uppercase_hex_checksum() {
        assert!(detect(&format!("{PREFIX}{BODY}DEADBEEF")).is_empty());
    }

    /// Both consulted sources agree the body excludes `_`/`-`; a byte
    /// outside `[A-Za-z0-9]` breaks the alphanumeric run before the
    /// documented combined length is reached, rather than being tolerated
    /// as it would under the retired `[A-Za-z0-9_-]` shared shape.
    #[test]
    fn rejects_a_body_containing_underscore_or_dash() {
        for byte in ['_', '-'] {
            let mut body = BODY.to_string();
            body.replace_range(4..5, &byte.to_string());
            assert!(detect(&format!("{PREFIX}{body}{CHECKSUM}")).is_empty());
        }
    }

    /// A truncated or misspelled prefix (the documented `cfut_` with its
    /// final letter dropped) never anchors a match, even with an otherwise
    /// realistic-length body and checksum following it.
    #[test]
    fn rejects_a_truncated_prefix_with_a_realistic_length_body() {
        assert!(detect(&format!("cfu_{BODY}{CHECKSUM}")).is_empty());
    }

    #[test]
    fn rejects_the_prefix_alone() {
        assert!(detect(PREFIX).is_empty());
        assert!(detect(&format!("{PREFIX}{BODY}")).is_empty());
    }

    #[test]
    fn rejects_the_body_or_checksum_embedded_in_a_wider_identifier() {
        let value = token();
        assert!(detect(&format!("x{value}")).is_empty());
        assert!(detect(&format!("{value}x")).is_empty());
    }

    #[test]
    fn rejects_a_masked_value() {
        assert!(detect(&format!("{PREFIX}{}", "*".repeat(BODY_LEN + CHECKSUM_LEN))).is_empty());
    }

    #[test]
    fn rejects_an_environment_variable_reference() {
        assert!(detect("${CLOUDFLARE_API_TOKEN}").is_empty());
    }

    /// Cloudflare's own account-scoped and zone-scoped resource identifiers
    /// are opaque hex UUID-shaped strings with no `cfut_` prefix; they must
    /// not be misread as a truncated or malformed token.
    #[test]
    fn rejects_an_ordinary_zone_resource_id() {
        assert!(detect("023e105f4ecef8ad9ca31a8372d0c353").is_empty());
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
    fn reports_a_repeated_identical_value_once_per_occurrence() {
        let value = token();
        let input = format!("{value} {value}");
        assert_eq!(detect(&input).len(), 2);
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
        let input = format!("{PREFIX}{short_body}{CHECKSUM} ").repeat(10_000);
        assert_eq!(detect(&input).len(), 0);
    }
}
