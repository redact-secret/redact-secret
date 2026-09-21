//! Terraform Cloud/Enterprise API token detection.
//!
//! Issue #521 (B3b, under Epic #501) scopes this to "the Terraform
//! Cloud/Enterprise token families (user, team and organization tokens)
//! where provider evidence supports a lexical shape." `HashiCorp`'s own API
//! reference documentation publishes one shape for all three, and does not
//! distinguish a token's class from its value:
//!
//! ```text
//! [A-Za-z0-9]{14}.atlasv1.[A-Za-z0-9]{67}
//! ```
//!
//! Exactly 14 alphanumeric bytes, then the literal `.atlasv1.` version
//! marker, then exactly 67 alphanumeric bytes, for 90 bytes total.
//!
//! ## Grammar evidence
//!
//! T1, provider-documented: HCP Terraform's own API reference publishes a
//! full example token value in three independent pages --
//! `developer.hashicorp.com/terraform/cloud-docs/api-docs/user-tokens`
//! (`6tL24nM38M7XWQ.atlasv1.KmWckRfzeNmUVFNvpvwUEChKaLGznCSD6fPf3VPzqMMVzmSxFU0p2Ibzpo2h5eTGwPU`),
//! `.../organization-tokens`
//! (`ZgqYdzuvlv8Iyg.atlasv1.6nV7t1OyFls341jo1xdZTP72fN0uu9VL55ozqzekfmToGFbhoFvvygIRy2mwVAXomOE`),
//! and `.../team-tokens`
//! (`QnbSxjjhVMHJgw.atlasv1.gxZnWIjI5j752DGqdwEUVLOFf0mtyaQ00H9bA1j90qWb254lEkQyOdfqqcq9zZL7Sm0`),
//! all observed 2026-09-21 -- every one exactly 14 bytes before the marker
//! and exactly 67 after it. The mirrored Terraform Enterprise page
//! (`.../terraform/enterprise/api-docs/organization-tokens`) publishes the
//! identical shape, confirming "Cloud/Enterprise" is one grammar, not two.
//! Neither page documents a checksum or any marker beyond the literal
//! `.atlasv1.` version tag itself.
//!
//! Two independent tools corroborate the shape without agreeing on its
//! exact width: gitleaks 8.30.1's `config/gitleaks.toml` (observed
//! 2026-09-21) uses
//! `(?i)[a-z0-9]{14}\.(?-i:atlasv1)\.[a-z0-9\-_=]{60,70}` -- a looser
//! 60-70-byte range over a wider `[A-Za-z0-9_=-]` tail alphabet -- while
//! trufflehog 3.97.4's `terraformcloudpersonaltoken` detector (observed
//! 2026-09-21) uses `\b[A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9]{67}\b`, matching
//! every one of the three official examples exactly. This module freezes
//! the tighter, provider-confirmed exact width, the same precedent
//! `docs/decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-
//! families.md` set for preferring an exact contract over a looser
//! single-tool range once provider evidence pins the real width.
//!
//! One shape covers user, team, and organization tokens (the issue's named
//! scope), and, incidentally, agent tokens and Terraform Enterprise's
//! self-hosted tokens, since `HashiCorp`'s own documentation shows the
//! identical grammar for those too -- there is no sub-family here that
//! lacks evidence and needs a `pending`/`unsupported` disposition.
//!
//! ## Where this appears
//!
//! Detection is shape-only, not context-gated, the same posture
//! [`super::vault`] and [`super::firebase`] take: the CLI credentials block
//! (`credentials "app.terraform.io" { token = "..." }`,
//! `~/.terraform.d/credentials.tfrc.json`), the `TF_TOKEN_<host>`
//! environment-variable convention, CI configuration, and plain source or
//! log text are all covered without special-casing any one of them.
//!
//! ## Action
//!
//! `Confidence::High` unconditionally, `Specificity::Provider`, and listed
//! in `policy::ALWAYS_REDACT_TYPES`: a Terraform Cloud/Enterprise API token
//! grants organization-wide infrastructure control, the same severity class
//! as `vault_token`.

use crate::detectors::pattern::{self, is_alnum};
use crate::error::DetectorFailure;
use crate::types::{ByteRange, Candidate, Confidence, Detector, DetectorContext, Specificity};

const PREFIX_LEN: usize = 14;
const MARKER: &[u8] = b".atlasv1.";
const SUFFIX_LEN: usize = 67;

/// Requires the exact `[A-Za-z0-9]{14}.atlasv1.[A-Za-z0-9]{67}` shape. A
/// shorter or longer segment on either side of the marker, or a segment
/// embedded in a wider identifier, is an intentional false negative rather
/// than a fuzzy match -- the same tradeoff [`super::firebase`]'s
/// `FirebaseServerKeyDetector` makes for its own two-segment exact-length
/// shape.
pub(super) struct TerraformCloudTokenDetector;

impl Detector for TerraformCloudTokenDetector {
    fn id(&self) -> &'static str {
        "terraform-cloud-token"
    }

    fn detect(
        &self,
        input: &str,
        _context: &DetectorContext,
    ) -> Result<Vec<Candidate>, DetectorFailure> {
        let bytes = input.as_bytes();
        let alnum_ends = pattern::run_ends(bytes, is_alnum);
        let mut candidates = Vec::new();
        let mut cursor = 0;
        while cursor < bytes.len() {
            let Some(marker_start) = find_marker(bytes, cursor) else {
                break;
            };

            if let Some(range) = match_at(bytes, &alnum_ends, marker_start) {
                candidates.push(
                    Candidate::new("terraform_cloud_token", Confidence::High, range)
                        .with_specificity(Specificity::Provider)
                        .with_signals(["terraform-atlasv1-marker", "documented-exact-length"]),
                );
                cursor = range.end();
                continue;
            }
            cursor = marker_start + 1;
        }
        Ok(candidates)
    }
}

/// The byte offset of the next `.atlasv1.` literal at or after `from`.
fn find_marker(bytes: &[u8], from: usize) -> Option<usize> {
    if from > bytes.len() {
        return None;
    }
    bytes[from..]
        .windows(MARKER.len())
        .position(|window| window == MARKER)
        .map(|offset| from + offset)
}

/// Attempts a `<14 alnum>.atlasv1.<67 alnum>` match anchored on the marker
/// found at `marker_start`. Returns the whole candidate's byte range on
/// success.
fn match_at(bytes: &[u8], alnum_ends: &[usize], marker_start: usize) -> Option<ByteRange> {
    if marker_start < PREFIX_LEN {
        return None;
    }
    let prefix_start = marker_start - PREFIX_LEN;
    if !bytes[prefix_start..marker_start]
        .iter()
        .all(|&b| is_alnum(b))
    {
        return None;
    }
    if prefix_start > 0 && is_alnum(bytes[prefix_start - 1]) {
        return None;
    }

    let suffix_start = marker_start + MARKER.len();
    if alnum_ends[suffix_start] < suffix_start + SUFFIX_LEN {
        return None;
    }
    let end = suffix_start + SUFFIX_LEN;
    if end < bytes.len() && is_alnum(bytes[end]) {
        return None;
    }

    ByteRange::new(prefix_start, end)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PREFIX: &str = "SYNREV0REVOKED";
    const SUFFIX: &str =
        "SYNTHETICREVOKEDTERRAFORMCLOUDTOKENFIXTUREPADDING0123456789ABCDEFGHIJKLMNOPQR";

    fn token() -> String {
        format!("{PREFIX}.atlasv1.{}", &SUFFIX[..SUFFIX_LEN])
    }

    fn detect(input: &str) -> Vec<Candidate> {
        TerraformCloudTokenDetector
            .detect(input, &DetectorContext::new(input.len()))
            .unwrap()
    }

    #[test]
    fn fixture_segments_are_exactly_documented_length() {
        assert_eq!(PREFIX.len(), PREFIX_LEN);
        assert_eq!(SUFFIX[..SUFFIX_LEN].len(), SUFFIX_LEN);
    }

    #[test]
    fn detects_a_synthetic_token_with_provider_specificity() {
        let value = token();
        let candidates = detect(&value);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].type_name(), "terraform_cloud_token");
        assert_eq!(candidates[0].confidence(), Confidence::High);
        assert_eq!(candidates[0].effective_specificity(), Specificity::Provider);
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(0, value.len()).unwrap()
        );
    }

    #[test]
    fn detects_the_token_in_a_cli_credentials_block_dotenv_and_json() {
        let value = token();
        for input in [
            value.clone(),
            format!("TF_TOKEN_app_terraform_io={value}"),
            format!("credentials \"app.terraform.io\" {{\n  token = \"{value}\"\n}}"),
            format!("{{\"credentials\": {{\"app.terraform.io\": {{\"token\": \"{value}\"}}}}}}"),
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
    fn rejects_a_truncated_prefix_segment() {
        let short_prefix = &PREFIX[1..];
        assert!(detect(&format!("{short_prefix}.atlasv1.{}", &SUFFIX[..SUFFIX_LEN])).is_empty());
    }

    #[test]
    fn rejects_a_truncated_suffix_segment() {
        let short_suffix = &SUFFIX[..SUFFIX_LEN - 1];
        assert!(detect(&format!("{PREFIX}.atlasv1.{short_suffix}")).is_empty());
    }

    #[test]
    fn rejects_a_prefix_segment_longer_than_documented() {
        assert!(detect(&format!("X{PREFIX}.atlasv1.{}", &SUFFIX[..SUFFIX_LEN])).is_empty());
    }

    #[test]
    fn rejects_a_suffix_segment_longer_than_documented() {
        assert!(detect(&format!("{PREFIX}.atlasv1.{}", &SUFFIX[..=SUFFIX_LEN])).is_empty());
    }

    #[test]
    fn rejects_a_malformed_marker() {
        assert!(detect(&format!("{PREFIX}.atlasv2.{}", &SUFFIX[..SUFFIX_LEN])).is_empty());
        assert!(detect(&format!("{PREFIX}atlasv1.{}", &SUFFIX[..SUFFIX_LEN])).is_empty());
        assert!(detect(&format!("{PREFIX}.ATLASV1.{}", &SUFFIX[..SUFFIX_LEN])).is_empty());
    }

    #[test]
    fn rejects_the_marker_alone() {
        assert!(detect(".atlasv1.").is_empty());
        assert!(detect(&format!("{PREFIX}.atlasv1.")).is_empty());
        assert!(detect(".atlasv1.SYNTHETIC").is_empty());
    }

    #[test]
    fn rejects_the_prefix_or_suffix_embedded_in_a_wider_identifier() {
        let value = token();
        assert!(detect(&format!("x{value}")).is_empty());
        assert!(detect(&format!("{value}x")).is_empty());
    }

    #[test]
    fn rejects_a_masked_value() {
        let masked_suffix = "*".repeat(SUFFIX_LEN);
        assert!(detect(&format!("{PREFIX}.atlasv1.{masked_suffix}")).is_empty());
    }

    #[test]
    fn rejects_an_environment_variable_reference() {
        assert!(detect("${TF_TOKEN_app_terraform_io}").is_empty());
    }

    /// `HashiCorp`'s own CLI-configuration documentation shows a doc-style
    /// placeholder using this exact shorter form
    /// (`developer.hashicorp.com/terraform/cli/config/config-file`, observed
    /// 2026-09-21: `xxxxxx.atlasv1.zzzzzzzzzzzzz`); its 6-byte prefix and
    /// 13-byte suffix are both far short of the documented 14/67 widths, so
    /// this extremely common copy-pasted example is not classified.
    #[test]
    fn rejects_the_official_documentation_placeholder() {
        assert!(detect("xxxxxx.atlasv1.zzzzzzzzzzzzz").is_empty());
    }

    /// Issue #320's false-positive assurance dimension, applied to
    /// Terraform: a placeholder built entirely from valid alphabet bytes at
    /// the documented length is indistinguishable from a real token and is
    /// still classified, the same accepted tradeoff [`super::vault`] and
    /// [`super::openai`] make for their own fixed-shape grammars.
    #[test]
    fn accepts_a_doc_style_placeholder_built_from_valid_alphabet_characters() {
        let input = format!(
            "{}.atlasv1.{}",
            "x".repeat(PREFIX_LEN),
            "x".repeat(SUFFIX_LEN)
        );
        assert_eq!(detect(&input).len(), 1);
    }

    #[test]
    fn a_trailing_comma_does_not_get_folded_into_or_suppress_the_match() {
        let value = token();
        let input = format!("Rotate {value}, then redeploy.");
        let candidates = detect(&input);
        assert_eq!(candidates.len(), 1);
        let start = "Rotate ".len();
        let end = start + value.len();
        assert_eq!(candidates[0].range(), ByteRange::new(start, end).unwrap());
    }

    /// An ordinary `required_providers`/`required_version` constraint and a
    /// workspace identifier carry no `.atlasv1.` marker.
    #[test]
    fn rejects_ordinary_terraform_configuration_and_workspace_identifiers() {
        let input = concat!(
            "terraform {\n",
            "  required_version = \">= 1.5.0\"\n",
            "  required_providers {\n",
            "    aws = {\n",
            "      source  = \"hashicorp/aws\"\n",
            "      version = \"~> 5.0\"\n",
            "    }\n",
            "  }\n",
            "}\n",
            "# workspace ws-SYNTHETICREVOKEDWORKSPACEID, org-SYNTHETICREVOKEDORGID\n",
        );
        assert_eq!(detect(input).len(), 0);
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
    fn reports_a_repeated_identical_value_once_per_occurrence() {
        let value = token();
        let input = format!("{value} {value}");
        assert_eq!(detect(&input).len(), 2);
    }

    #[test]
    fn stays_bounded_over_a_long_run_of_near_miss_markers() {
        // Every occurrence has a suffix one byte short of the documented
        // length, so none matches; the scan must still stay linear instead
        // of rescanning from each failed marker position.
        let short_suffix = &SUFFIX[..SUFFIX_LEN - 1];
        let input = format!("{PREFIX}.atlasv1.{short_suffix} ").repeat(2_000);
        assert_eq!(detect(&input).len(), 0);
    }
}
