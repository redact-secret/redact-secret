//! Databricks personal access token detection.
//!
//! The reviewed grammar (issue #308, applying the existing provider-grammar
//! freeze policy recorded in `docs/specs/detector-families.md`) is
//! `dapi[a-f0-9]{32}(?:-[0-9])?`: Databricks' own documentation
//! (`docs.databricks.com/aws/en/dev-tools/auth/pat`,
//! `learn.microsoft.com/azure/databricks/dev-tools/auth/pat`, observed
//! 2026-09-22) describes how a personal access token is created and used but
//! does not publish the literal token string format. Two independently
//! maintained tools, consulted only as external behavioral references per
//! `AGENTS.md`, converge on the same shape:
//!
//! ```text
//! gitleaks 8.30.1's databricks-api-token rule:
//!   \b(dapi[a-f0-9]{32}(?:-\d)?)(?:[`'"\s;]|\\[nr]|$)
//! trufflehog 3.97.4's databrickstoken rule:
//!   \b(dapi[0-9a-f]{32}(-\d)?)\b
//! ```
//!
//! Both pin exactly 32 lowercase hexadecimal bytes after the `dapi` prefix,
//! and both independently model an optional token-rotation suffix of a
//! literal `-` followed by exactly one digit. Microsoft Purview's Azure
//! Databricks personal access token entity definition
//! (`learn.microsoft.com/purview/sit-defn-azure-databricks-personal-access-token`,
//! observed 2026-09-22) tertiarily corroborates a 32-character body and
//! lists `dapi` among its match keywords, though it does not itself state a
//! prefix-plus-body grammar. A body shorter or longer than 32 bytes, in
//! uppercase hex, or using any other undocumented character is an
//! intentional false negative rather than a fuzzy match, the same
//! exact-length precedent [`super::linear::LINEAR`]'s `lin_api_` shape
//! already set.
//!
//! **The rotation suffix.** Neither tool's suffix is a simple fixed-length
//! extension of the body's own alphabet: the literal `-` separator falls
//! outside `[a-f0-9]`, so the body and an optional rotated suffix cannot be
//! read as one exact-length run the way [`super::cloudflare::CLOUDFLARE`]'s
//! checksum tail is (that checksum shares its body's alphabet; this
//! separator does not). Matching therefore widens the run alphabet to
//! [`is_lower_hex_or_dash`] (hex or a literal dash) and takes the maximal
//! available run via [`pattern::RunLength::AtLeast`], then
//! [`databricks_body_shape`] -- this shape's own [`pattern::PostCheck`] --
//! rejects anything whose length is not exactly the bare 32-byte body or
//! exactly the 34-byte body-plus-rotation shape, and for the 34-byte case
//! additionally requires the dash to land at byte 32 and the following byte
//! to be an ASCII digit specifically (not any hex letter). A rotation
//! suffix with two or more digits, a dash with nothing after it, or a dash
//! followed by a non-digit hex letter therefore also is an intentional
//! false negative -- the run's greedy, non-backtracking match already
//! absorbed the extra bytes into a length the post-check does not accept,
//! the same "reject a longer glued run outright" precedent
//! [`super::linear::LINEAR`]'s one-byte-longer-body rejection and
//! [`super::cloudflare::CLOUDFLARE`]'s checksum-tail post-check both already
//! set.
//!
//! **Out of scope.** Workspace, cluster, and job identifiers, Databricks
//! workspace host URLs (`*.cloud.databricks.com`, `*.azuredatabricks.net`,
//! `*.gcp.databricks.com`), notebook paths, and documentation placeholders
//! carry no `dapi`-prefixed run and are excluded automatically, with no
//! special-casing needed. OAuth client secrets are a separately documented
//! scope extension (issue #308) and are not covered here.

use crate::detectors::additional_providers::KnownFormatProviderDetector;
use crate::detectors::pattern::{self, Alphabet, PrefixShape};

const PREFIX: &str = "dapi";
/// The two-tool-corroborated exact body length.
const BODY_LEN: usize = 32;
/// The body plus a `-` and a single rotation digit.
const ROTATED_LEN: usize = BODY_LEN + 2;

/// `[0-9a-f-]`: the body's lowercase-hex alphabet widened to also admit the
/// rotation suffix's literal dash, so a rotated token's dash does not itself
/// trip the boundary check before [`databricks_body_shape`] gets to accept
/// it (see the module doc).
fn is_lower_hex_or_dash(byte: u8) -> bool {
    pattern::is_lower_hex(byte) || byte == b'-'
}
const BODY_ALPHABET: Alphabet = is_lower_hex_or_dash;

const SIGNALS: [&str; 2] = [
    "databricks-documented-prefix",
    "hex-exact-length-or-rotation-suffix",
];

/// `true` when the matched run's body (excluding the `dapi` prefix) is
/// exactly 32 lowercase-hex bytes, or exactly that body followed by a
/// literal `-` and a single ASCII digit -- the [`pattern::PostCheck`] the
/// widened run alphabet alone cannot express (see the module doc).
fn databricks_body_shape(bytes: &[u8], start: usize, end: usize) -> bool {
    let body = &bytes[start + PREFIX.len()..end];
    match body.len() {
        BODY_LEN => body.iter().copied().all(pattern::is_lower_hex),
        ROTATED_LEN => {
            body[..BODY_LEN].iter().copied().all(pattern::is_lower_hex)
                && body[BODY_LEN] == b'-'
                && body[BODY_LEN + 1].is_ascii_digit()
        }
        _ => false,
    }
}

/// Requires the exact `dapi<32 lowercase-hex bytes>` shape, optionally
/// followed by a `-` and a single rotation digit. A body short of or longer
/// than the documented length, a non-hex or uppercase-hex byte, a
/// multi-digit or missing rotation suffix, or a run embedded in a wider
/// identifier is an intentional false negative rather than a fuzzy match.
pub(super) const DATABRICKS: KnownFormatProviderDetector = KnownFormatProviderDetector::new(
    "databricks-personal-access-token",
    "databricks_personal_access_token",
    &[
        PrefixShape::at_least(PREFIX, BODY_LEN, BODY_ALPHABET, &SIGNALS)
            .with_post_check(databricks_body_shape),
    ],
    pattern::is_alnum_dash,
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ByteRange, Candidate, Confidence, Detector, DetectorContext, Specificity};

    /// Exactly [`BODY_LEN`] lowercase-hex bytes. Locally constructed
    /// synthetic value; never provider-issued.
    const BODY: &str = "0123456789abcdef0123456789abcdef";
    const _: () = assert!(BODY.len() == BODY_LEN);

    fn detect(input: &str) -> Vec<Candidate> {
        DATABRICKS
            .detect(input, &DetectorContext::new(input.len()))
            .unwrap()
    }

    fn bare_token() -> String {
        format!("{PREFIX}{BODY}")
    }

    fn rotated_token() -> String {
        format!("{PREFIX}{BODY}-2")
    }

    #[test]
    fn detects_a_bare_token_with_provider_specificity() {
        let value = bare_token();
        let candidates = detect(&value);
        assert_eq!(candidates.len(), 1);
        assert_eq!(
            candidates[0].type_name(),
            "databricks_personal_access_token"
        );
        assert_eq!(candidates[0].confidence(), Confidence::High);
        assert_eq!(candidates[0].effective_specificity(), Specificity::Provider);
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(0, value.len()).unwrap()
        );
    }

    #[test]
    fn detects_a_rotated_token_with_the_same_specificity() {
        let value = rotated_token();
        let candidates = detect(&value);
        assert_eq!(candidates.len(), 1);
        assert_eq!(
            candidates[0].type_name(),
            "databricks_personal_access_token"
        );
        assert_eq!(candidates[0].confidence(), Confidence::High);
        assert_eq!(candidates[0].effective_specificity(), Specificity::Provider);
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(0, value.len()).unwrap()
        );
    }

    /// Issue #308: the documented body length is exact; one byte short is a
    /// false negative, not a fuzzy match against a minimum.
    #[test]
    fn rejects_a_body_one_byte_short_of_the_documented_length() {
        let short_body = &BODY[..BODY_LEN - 1];
        assert!(detect(&format!("{PREFIX}{short_body}")).is_empty());
    }

    /// A run one byte longer than the documented length, with no rotation
    /// dash, is rejected rather than truncated to the documented shape --
    /// the same precedent `linear-token` and `pulumi-access-token` already
    /// set for their own exact-length grammars.
    #[test]
    fn rejects_a_body_one_byte_longer_than_the_documented_length_with_no_rotation() {
        assert!(detect(&format!("{PREFIX}{BODY}a")).is_empty());
    }

    /// Both consulted tools agree the body is lowercase hex only; an
    /// uppercase hex digit or a non-hex letter inside an otherwise
    /// documented-length body is rejected rather than truncated to its
    /// longest valid-alphabet prefix.
    #[test]
    fn rejects_uppercase_hex_and_non_hex_bytes_inside_the_body() {
        for byte in ['A', 'F', 'g', 'Z'] {
            let mut body = BODY.to_string();
            body.replace_range(4..5, &byte.to_string());
            assert!(detect(&format!("{PREFIX}{body}")).is_empty(), "{byte}");
        }
    }

    /// Both tools model the rotation suffix as exactly one digit; two
    /// digits is an intentional false negative rather than a match on the
    /// first digit alone (see the module doc: the greedy run already
    /// absorbed both digits into a length the post-check does not accept).
    #[test]
    fn rejects_a_rotation_suffix_with_two_digits() {
        assert!(detect(&format!("{PREFIX}{BODY}-22")).is_empty());
    }

    /// `-a` extends the widened run alphabet past the dash (a lowercase hex
    /// letter is still `is_lower_hex_or_dash`), so the post-check sees a
    /// 34-byte body whose last byte fails the ASCII-digit check. `-A` and
    /// `-#` each stop the run at the dash instead, since neither an
    /// uppercase hex letter nor `#` is in the alphabet, leaving a 33-byte
    /// body the post-check also rejects.
    #[test]
    fn rejects_a_rotation_suffix_with_a_non_digit_after_the_dash() {
        for suffix in ["-a", "-A", "-#"] {
            assert!(
                detect(&format!("{PREFIX}{BODY}{suffix}")).is_empty(),
                "{suffix}"
            );
        }
    }

    #[test]
    fn rejects_a_bare_trailing_dash_with_nothing_after_it() {
        assert!(detect(&format!("{PREFIX}{BODY}-")).is_empty());
    }

    #[test]
    fn rejects_undocumented_near_miss_prefixes() {
        for input in [
            format!("dap{BODY}"),
            format!("dapii{BODY}"),
            format!("Dapi{BODY}"),
            format!("dap1{BODY}"),
            format!("dapi_{BODY}"),
        ] {
            assert!(detect(&input).is_empty(), "{input}");
        }
    }

    #[test]
    fn rejects_the_prefix_embedded_in_a_wider_identifier() {
        assert!(detect(&format!("legacy{}", bare_token())).is_empty());
        assert!(detect(&format!("{}_backup", bare_token())).is_empty());
        assert!(detect(&format!("{}-1extra", rotated_token())).is_empty());
    }

    #[test]
    fn rejects_a_masked_or_doc_style_placeholder_value() {
        assert!(detect(&format!("{PREFIX}{}", "*".repeat(BODY_LEN))).is_empty());
        assert!(detect(&format!("{PREFIX}${{DATABRICKS_TOKEN}}")).is_empty());
    }

    /// Benign lookalikes explicitly out of scope (issue #308): a workspace
    /// host URL and a `.databrickscfg`-style config line with no token
    /// value carry no `dapi`-prefixed run at all.
    #[test]
    fn rejects_benign_databricks_context_with_no_token_present() {
        for input in [
            "adb-1234567890123456.7.azuredatabricks.net",
            "host = https://my-workspace.cloud.databricks.com",
            "cluster_id: 0921-150000-abcd1234",
        ] {
            assert!(detect(input).is_empty(), "{input}");
        }
    }

    #[test]
    fn accepts_punctuation_and_assignment_boundaries() {
        for value in [bare_token(), rotated_token()] {
            for (input, start) in [
                (format!("({value})."), 1),
                (format!("\"{value}\""), 1),
                (
                    format!("DATABRICKS_TOKEN={value}"),
                    "DATABRICKS_TOKEN=".len(),
                ),
            ] {
                let candidates = detect(&input);
                assert_eq!(candidates.len(), 1, "{input}");
                assert_eq!(
                    candidates[0].range(),
                    ByteRange::new(start, start + value.len()).unwrap(),
                    "{input}"
                );
            }
        }
    }

    #[test]
    fn reports_a_repeated_identical_value_once_per_occurrence() {
        for value in [bare_token(), rotated_token()] {
            let input = format!("{value} {value}");
            assert_eq!(detect(&input).len(), 2, "{value}");
        }
    }

    #[test]
    fn finds_a_match_across_crlf_and_a_unicode_prefix() {
        for value in [bare_token(), rotated_token()] {
            let input = format!("# \u{1F511} caf\u{e9}\r\n{value}\r\n");
            let candidates = detect(&input);
            assert_eq!(candidates.len(), 1, "{value}");
            let start = input.find(&value).unwrap();
            assert_eq!(
                candidates[0].range(),
                ByteRange::new(start, start + value.len()).unwrap(),
                "{value}"
            );
        }
    }

    #[test]
    fn finds_deterministic_findings_across_repeated_calls() {
        let value = bare_token();
        assert_eq!(detect(&value), detect(&value));
    }

    /// A pathological run of near-miss prefixes must not make the scan
    /// quadratic: every occurrence has a body one byte short of the
    /// documented length, so none matches.
    #[test]
    fn stays_bounded_over_a_long_run_of_near_miss_prefixes() {
        let short_body = &BODY[..BODY_LEN - 1];
        let input = format!("{PREFIX}{short_body} ").repeat(10_000);
        assert_eq!(detect(&input).len(), 0);
    }
}
