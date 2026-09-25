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
//! prefix-plus-body grammar. A body shorter or longer than 32 bytes, or
//! using a non-hex character, is an intentional false negative rather than
//! a fuzzy match, the same exact-length precedent
//! [`super::linear::LINEAR`]'s `lin_api_` shape already set.
//!
//! ## Unresolved provider facts (issues #697, #698)
//!
//! No issued token has been observed and no Databricks source states either
//! property, so both stay recorded uncertainty. The grammar takes the
//! reading that misses fewer real tokens:
//!
//! - **Case (#697).** Microsoft Purview's entity definition allows `A-F`
//!   and `a-f`; gitleaks and trufflehog match lowercase only. The body
//!   accepts both cases. A `dapi` + 32 uppercase-hex run is not plausibly
//!   anything else. The benchmark's alphabet twins use a non-hex letter,
//!   which is still rejected.
//! - **Rotation suffix (#698).** gitleaks, trufflehog and betterleaks allow
//!   `-` plus one digit. Nosey Parker allows several. plenoai, `CredSweeper`
//!   and secrets-patterns-db allow no suffix. All 19 suffixed public-code
//!   candidates had one digit. The suffix accepts 1–3 digits, so a
//!   multi-digit rotation no longer loses the whole token. Four or more
//!   digits, or a non-digit after the dash, still reject.
//!
//! **The rotation suffix.** Neither tool's suffix is a simple fixed-length
//! extension of the body's own alphabet: the literal `-` separator falls
//! outside the hex alphabet, so the body and an optional rotated suffix
//! cannot be read as one exact-length run the way
//! [`super::cloudflare::CLOUDFLARE`]'s checksum tail is (that checksum shares
//! its body's alphabet; this separator does not). Matching therefore widens
//! the run alphabet to [`is_hex_or_dash`] (hex or a literal dash) and takes
//! the maximal available run via [`pattern::RunLength::AtLeast`], then
//! [`databricks_body_shape`] -- this shape's own [`pattern::PostCheck`] --
//! accepts only the bare 32-byte body or that body followed by a dash and 1
//! to [`MAX_ROTATION_DIGITS`] ASCII digits. A longer digit run, a dash with
//! nothing after it, or a dash followed by a hex letter is an intentional
//! false negative -- the run's greedy, non-backtracking match already
//! absorbed the extra bytes into a shape the post-check does not accept,
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
/// The most rotation digits accepted after the `-` (issue #698).
const MAX_ROTATION_DIGITS: usize = 3;

/// `[0-9A-Fa-f-]`: the body's hex alphabet widened to also admit the
/// rotation suffix's literal dash, so a rotated token's dash does not itself
/// trip the boundary check before [`databricks_body_shape`] gets to accept
/// it (see the module doc).
fn is_hex_or_dash(byte: u8) -> bool {
    pattern::is_hex(byte) || byte == b'-'
}
const BODY_ALPHABET: Alphabet = is_hex_or_dash;

const SIGNALS: [&str; 2] = [
    "databricks-documented-prefix",
    "hex-exact-length-or-rotation-suffix",
];

/// `true` when the matched run's body (excluding the `dapi` prefix) is
/// exactly 32 hex bytes, or exactly that body followed by a literal `-` and
/// 1 to [`MAX_ROTATION_DIGITS`] ASCII digits -- the [`pattern::PostCheck`]
/// the widened run alphabet alone cannot express (see the module doc).
fn databricks_body_shape(bytes: &[u8], start: usize, end: usize) -> bool {
    let body = &bytes[start + PREFIX.len()..end];
    if body.len() < BODY_LEN || !body[..BODY_LEN].iter().copied().all(pattern::is_hex) {
        return false;
    }
    let suffix = &body[BODY_LEN..];
    suffix.is_empty()
        || (suffix[0] == b'-'
            && (2..=MAX_ROTATION_DIGITS + 1).contains(&suffix.len())
            && suffix[1..].iter().all(u8::is_ascii_digit))
}

/// Requires the exact `dapi<32 hex bytes>` shape, optionally followed by a
/// `-` and 1 to 3 rotation digits. A body short of or longer than the
/// documented length, a non-hex byte, a longer or missing rotation suffix,
/// or a run embedded in a wider identifier is an intentional false negative
/// rather than a fuzzy match.
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

    /// Issue #697: uppercase hex is accepted (recorded uncertainty, see the
    /// module doc); a non-hex letter inside an otherwise documented-length
    /// body is still rejected rather than truncated.
    #[test]
    fn accepts_uppercase_hex_and_rejects_non_hex_bytes_inside_the_body() {
        for byte in ['A', 'F'] {
            let mut body = BODY.to_string();
            body.replace_range(4..5, &byte.to_string());
            let value = format!("{PREFIX}{body}");
            assert_eq!(detect(&value).len(), 1, "{byte}");
        }
        let upper = format!("{PREFIX}{}", BODY.to_ascii_uppercase());
        assert_eq!(detect(&upper).len(), 1);
        for byte in ['g', 'Z'] {
            let mut body = BODY.to_string();
            body.replace_range(4..5, &byte.to_string());
            assert!(detect(&format!("{PREFIX}{body}")).is_empty(), "{byte}");
        }
    }

    /// Issue #698: a rotation suffix of 1 to 3 digits is part of the token.
    #[test]
    fn accepts_a_rotation_suffix_of_up_to_three_digits() {
        for suffix in ["-22", "-123"] {
            let value = format!("{PREFIX}{BODY}{suffix}");
            let candidates = detect(&value);
            assert_eq!(candidates.len(), 1, "{suffix}");
            assert_eq!(
                candidates[0].range(),
                ByteRange::new(0, value.len()).unwrap()
            );
        }
    }

    #[test]
    fn rejects_a_rotation_suffix_with_four_digits() {
        assert!(detect(&format!("{PREFIX}{BODY}-1234")).is_empty());
    }

    /// `-a` and `-A` extend the widened run alphabet past the dash (a hex
    /// letter of either case is still `is_hex_or_dash`), so the post-check
    /// sees a suffix whose last byte fails the ASCII-digit check. `-#`
    /// stops the run at the dash instead, leaving a bare trailing dash the
    /// post-check also rejects.
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
