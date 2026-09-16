//! Shopify token detection.
//!
//! Mirrors `src/detectors/shopify.ts`.

use crate::detectors::pattern::{self, RunLength};
use crate::error::DetectorFailure;
use crate::types::{ByteRange, Candidate, Confidence, Detector, DetectorContext, Specificity};

const PREFIXES: [&str; 2] = ["shpat_", "shppa_"];

/// Recognizes Shopify's documented Admin API and delegate access-token
/// prefixes. The suffix is opaque, so the minimum length and conservative
/// alphabet favor precision while accepting that short or newly encoded
/// values can be missed. The `shpca_` public storefront-access prefix is
/// deliberately excluded: it is a public identifier, not an elevated-access
/// secret, so matching it would be a false positive.
pub(super) struct ShopifyTokenDetector;

impl Detector for ShopifyTokenDetector {
    fn id(&self) -> &'static str {
        "shopify-token"
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
                Candidate::new("shopify_access_token", Confidence::High, range)
                    .with_specificity(Specificity::Provider)
                    .with_signals(["shopify-documented-prefix", "opaque-suffix"]),
            );
        }
        Ok(candidates)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn detect(input: &str) -> Vec<Candidate> {
        ShopifyTokenDetector
            .detect(input, &DetectorContext::new(input.len()))
            .unwrap()
    }

    #[test]
    fn detects_the_admin_api_prefix() {
        let input = "shpat_SYNTHETIC_REVOKED_SHOPIFY_TOKEN";
        let candidates = detect(input);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].type_name(), "shopify_access_token");
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(0, input.len()).unwrap()
        );
    }

    #[test]
    fn detects_the_delegate_access_prefix() {
        let input = "shppa_SYNTHETIC_REVOKED_SHOPIFY_TOKEN";
        assert_eq!(detect(input).len(), 1);
    }

    #[test]
    fn rejects_a_short_suffix() {
        assert_eq!(detect("shpat_SYNTHETIC_SHORT").len(), 0);
    }

    #[test]
    fn rejects_the_public_storefront_prefix() {
        assert_eq!(detect("shpca_SYNTHETIC_REVOKED_SHOPIFY_TOKEN").len(), 0);
    }

    /// An undocumented near-miss prefix, a public prefix surrounded by
    /// punctuation or Unicode/CRLF context, and a secret prefix followed by a
    /// redaction mask or a template interpolation reference instead of a
    /// real suffix, must all stay unclassified.
    #[test]
    fn rejects_wrong_prefix_masked_interpolated_and_contextualized_near_misses() {
        for input in [
            "shpad_SYNTHETIC_REVOKED_SHOPIFY_TOKEN",
            "(shpca_SYNTHETIC_REVOKED_SHOPIFY_TOKEN).",
            "# \u{1F511} caf\u{e9}\r\nshpca_SYNTHETIC_REVOKED_SHOPIFY_TOKEN\r\n",
            "shpat_********************",
            "shpat_${SHOPIFY_ADMIN_API_TOKEN}",
        ] {
            assert_eq!(detect(input).len(), 0, "{input}");
        }
    }

    /// A public identifier and a secret credential on adjacent lines: the
    /// public prefix never generates a candidate, while the paired secret is
    /// still classified with the correct range.
    #[test]
    fn detects_only_the_secret_half_of_a_mixed_public_and_secret_input() {
        let input = "shpca_SYNTHETIC_REVOKED_SHOPIFY_TOKEN\nshpat_SYNTHETIC_REVOKED_SHOPIFY_TOKEN";
        let candidates = detect(input);
        assert_eq!(candidates.len(), 1);
        let expected_start = input.find("shpat_").unwrap();
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(expected_start, input.len()).unwrap()
        );
    }
}
