//! `HashiCorp` Vault token detection.
//!
//! Mirrors `src/detectors/vault.ts`.

use crate::detectors::pattern::{self, RunLength};
use crate::error::DetectorFailure;
use crate::types::{ByteRange, Candidate, Confidence, Detector, DetectorContext, Specificity};

const PREFIXES: [&str; 3] = ["hvs.", "hvb.", "hvr."];

/// Recognizes modern Vault service, batch, and recovery token prefixes with
/// the documented minimum suffix length. Legacy one-letter prefixes are
/// excluded because they are too common to classify safely without added
/// context.
pub(super) struct VaultTokenDetector;

impl Detector for VaultTokenDetector {
    fn id(&self) -> &'static str {
        "vault-token"
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
            RunLength::AtLeast(24),
            pattern::is_alnum_dash,
            pattern::is_alnum_dash_dot,
        ) {
            let Some(range) = ByteRange::new(start, end) else {
                continue;
            };
            candidates.push(
                Candidate::new("vault_token", Confidence::High, range)
                    .with_specificity(Specificity::Provider)
                    .with_signals(["vault-modern-prefix", "documented-minimum-length"]),
            );
        }
        Ok(candidates)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn detect(input: &str) -> Vec<Candidate> {
        VaultTokenDetector
            .detect(input, &DetectorContext::new(input.len()))
            .unwrap()
    }

    #[test]
    fn detects_the_service_token_prefix() {
        let input = "hvs.SYNTHETIC_REVOKED_VAULT_TOKEN";
        let candidates = detect(input);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].type_name(), "vault_token");
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(0, input.len()).unwrap()
        );
    }

    #[test]
    fn detects_the_batch_and_recovery_prefixes() {
        assert_eq!(detect("hvb.SYNTHETIC_REVOKED_VAULT_TOKEN").len(), 1);
        assert_eq!(detect("hvr.SYNTHETIC_REVOKED_VAULT_TOKEN").len(), 1);
    }

    #[test]
    fn rejects_the_legacy_one_letter_prefix() {
        assert_eq!(detect("s.SYNTHETIC_REVOKED_LEGACY_VAULT_TOKEN").len(), 0);
    }

    #[test]
    fn rejects_a_short_suffix() {
        assert_eq!(detect("hvs.SYNTHETIC_SHORT").len(), 0);
    }

    #[test]
    fn a_dot_widens_the_boundary_but_not_the_matched_alphabet() {
        // The suffix alphabet excludes `.`, but the boundary check accepts a
        // wider alphabet that includes it, so a trailing dot right after an
        // otherwise-valid suffix must still reject the candidate.
        let input = "hvs.SYNTHETIC_REVOKED_VAULT_TOKEN.example";
        assert_eq!(detect(input).len(), 0);
    }

    /// Issue #320: the same false-positive assurance the earlier
    /// prefix-family issues (#316/#317) established for
    /// Stripe/Shopify/Supabase/`OpenAI`/Anthropic, applied to Vault.
    #[test]
    fn accepts_a_doc_style_placeholder_built_from_valid_alphabet_characters() {
        let input = format!("hvs.{}", "x".repeat(24));
        assert_eq!(detect(&input).len(), 1);
    }

    #[test]
    fn rejects_a_prefix_embedded_in_a_wider_benign_identifier() {
        // A leading alnum/dash byte right before `hvs.` means this is a
        // truncated slice of a longer identifier, not a boundary-delimited
        // credential.
        let input = "legacyhvs.SYNTHETIC_REVOKED_VAULT_TOKEN";
        assert_eq!(detect(input).len(), 0);
    }

    #[test]
    fn rejects_masked_and_interpolated_near_misses() {
        for input in [
            format!("hvs.{}", "*".repeat(24)),
            "hvs.${ENV_VAR}".to_string(),
        ] {
            assert_eq!(detect(&input).len(), 0, "{input}");
        }
    }

    #[test]
    fn a_trailing_comma_does_not_get_folded_into_or_suppress_the_match() {
        let token = "hvs.SYNTHETIC_REVOKED_VAULT_TOKEN";
        let input = format!("Rotate {token}, then redeploy.");
        let candidates = detect(&input);
        assert_eq!(candidates.len(), 1);
        let start = "Rotate ".len();
        let end = start + token.len();
        assert_eq!(candidates[0].range(), ByteRange::new(start, end).unwrap());
    }

    /// An ordinary Vault CLI path/namespace reference and a dotted server
    /// version string carry no modern token prefix.
    #[test]
    fn rejects_an_ordinary_vault_path_and_dotted_version_string() {
        let input =
            "vault kv get -namespace=admin secret/data/myapp/config on server v1.15.4";
        assert_eq!(detect(input).len(), 0);
    }
}
