//! Built-in detectors in canonical registration order.
//!
//! This module is private. The built-in set is reached only through
//! [`DetectorRegistry::with_built_in`](crate::DetectorRegistry::with_built_in),
//! so which detectors exist, how they are constructed, and what they retain
//! are all free to change without breaking a caller. What is public is the
//! observable consequence of the order below: it is the registry order used
//! as the fourth overlap tie breaker, so it must match the TypeScript oracle
//! and the conformance corpus.

mod additional_providers;
mod anthropic;
mod aws;
mod bearer_token;
mod connection_string;
mod generic_token;
mod github;
mod gitlab;
mod jwt;
mod microsoft_entra;
mod openai;
mod otpauth;
mod pattern;
mod private_key;
mod sendgrid;
mod shopify;
mod text;
mod vault;

use crate::types::Detector;
use connection_string::ConnectionStringDetector;
use private_key::PrivateKeyDetector;

pub(crate) use bearer_token::has_open_bearer_authorization;
pub(crate) use generic_token::has_open_contextual_assignment;
pub(crate) use private_key::PrivateKeyRetentionTracker;

/// Every built-in detector, in canonical registration order.
#[must_use]
pub(crate) fn built_in_detectors() -> Vec<Box<dyn Detector>> {
    vec![
        Box::new(PrivateKeyDetector),
        Box::new(aws::AwsAccessKeyDetector),
        Box::new(github::GitHubTokenDetector),
        Box::new(gitlab::GitlabTokenDetector),
        Box::new(openai::OpenAiTokenDetector),
        Box::new(anthropic::AnthropicTokenDetector),
        Box::new(shopify::ShopifyTokenDetector),
        Box::new(vault::VaultTokenDetector),
        Box::new(additional_providers::STRIPE),
        Box::new(additional_providers::SLACK),
        Box::new(additional_providers::PYPI),
        Box::new(additional_providers::HUGGING_FACE),
        Box::new(additional_providers::DOCKER),
        Box::new(additional_providers::CLOUDFLARE),
        Box::new(additional_providers::DIGITALOCEAN),
        Box::new(additional_providers::LINEAR),
        Box::new(additional_providers::SUPABASE),
        Box::new(additional_providers::VERCEL),
        Box::new(additional_providers::NPM),
        Box::new(sendgrid::SendgridTokenDetector),
        Box::new(microsoft_entra::MicrosoftEntraClientSecretDetector),
        jwt::jwt_detector(),
        bearer_token::bearer_token_detector(),
        Box::new(ConnectionStringDetector),
        otpauth::otpauth_detector(),
        generic_token::generic_token_detector(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::is_identifier;
    use crate::types::{Candidate, Confidence, DetectorContext, Specificity};

    #[test]
    fn built_in_ids_are_valid_and_unique() {
        let detectors = built_in_detectors();
        let mut ids: Vec<&str> = detectors.iter().map(|d| d.id()).collect();
        assert!(ids.iter().all(|id| is_identifier(id)));
        let count = ids.len();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), count);
    }

    #[test]
    fn built_in_order_matches_the_typescript_oracle() {
        let detectors = built_in_detectors();
        let ids: Vec<&str> = detectors.iter().map(|d| d.id()).collect();
        assert_eq!(
            ids,
            vec![
                "private-key",
                "aws-access-key",
                "github-token",
                "gitlab-token",
                "openai-token",
                "anthropic-token",
                "shopify-token",
                "vault-token",
                "stripe-token",
                "slack-token",
                "pypi-token",
                "huggingface-token",
                "docker-token",
                "cloudflare-token",
                "digitalocean-token",
                "linear-token",
                "supabase-token",
                "vercel-token",
                "npm-token",
                "sendgrid-token",
                "microsoft-entra-client-secret",
                "jwt",
                "bearer-token",
                "connection-string",
                "otpauth-uri",
                "generic-token",
            ]
        );
    }

    #[test]
    fn bearer_and_contextual_detectors_emit_competing_candidates() {
        let input = "auth = \"Bearer SYNTHETIC_REVOKED_BEARER_OVERLAP_1234\"";
        let context = DetectorContext::new(input.len());
        let bearer = bearer_token::bearer_token_detector()
            .detect(input, &context)
            .unwrap();
        let contextual = generic_token::generic_token_detector()
            .detect(input, &context)
            .unwrap();

        assert_eq!(bearer.len(), 1);
        assert_eq!(contextual.len(), 1);
        assert_eq!(bearer[0].type_name(), "bearer_token");
        assert_eq!(bearer[0].confidence(), Confidence::High);
        assert_eq!(bearer[0].specificity(), Some(Specificity::Structural));
        assert_eq!(bearer[0].range().start(), 15);
        assert_eq!(bearer[0].range().end(), 52);
        assert_eq!(contextual[0].type_name(), "contextual_secret");
        assert_eq!(contextual[0].specificity(), Some(Specificity::Contextual));
        assert_eq!(contextual[0].range().start(), 8);
        assert_eq!(contextual[0].range().end(), 52);
        assert!(bearer[0].range().overlaps(contextual[0].range()));
    }

    #[test]
    fn every_built_in_provider_candidate_claims_provider_specificity() {
        let pypi_input = format!("pypi-{}", "SYNTHETIC_REVOKED_".repeat(5));
        let sendgrid_input =
            "SG.SYNTHETIC_REVOKED_0000.SYNTHETIC_REVOKED_SENDGRID_SECRET_000000000";
        let cases: [(&str, &str); 20] = [
            ("aws-access-key", "AKIASYNTHETICEXAMPLE"),
            (
                "github-token",
                &"ghp_SYNTHETICREVOKEDVALUE0000000000000000"[..40],
            ),
            ("gitlab-token", "glpat-SYNTHETIC_REVOKED_TOKEN_FIXTURE"),
            ("openai-token", "sk-proj-SYNTHETIC_REVOKED_OPENAI_KEY"),
            (
                "anthropic-token",
                "sk-ant-api03-SYNTHETIC_REVOKED_ANTHROPIC_KEY",
            ),
            ("shopify-token", "shpat_SYNTHETIC_REVOKED_SHOPIFY_TOKEN"),
            ("vault-token", "hvs.SYNTHETIC_REVOKED_VAULT_TOKEN"),
            ("stripe-token", "sk_live_SYNTHETICREVOKEDPROVIDERVALUE"),
            ("slack-token", "xoxb-SYNTHETICREVOKEDPROVIDERVALUE"),
            ("pypi-token", pypi_input.as_str()),
            ("huggingface-token", "hf_SYNTHETICREVOKEDPROVIDERVALUE"),
            ("docker-token", "dckr_pat_SYNTHETICREVOKEDPROVIDERVALUE"),
            ("cloudflare-token", "cfut_SYNTHETICREVOKEDPROVIDERVALUE"),
            ("digitalocean-token", "dop_v1_SYNTHETICREVOKEDPROVIDERVALUE"),
            ("linear-token", "lin_api_SYNTHETICREVOKEDPROVIDERVALUE"),
            ("supabase-token", "sb_secret_SYNTHETICREVOKEDPROVIDERVALUE"),
            ("vercel-token", "vcp_SYNTHETICREVOKEDPROVIDERVALUE"),
            ("npm-token", "npm_SYNTHETICREVOKEDNPMACCESSTOKENVALUE1"),
            ("sendgrid-token", sendgrid_input),
            (
                "microsoft-entra-client-secret",
                "abc8Q~SYNTHETIC_REVOKED_ENTRA_SECRET_V",
            ),
        ];
        let detectors = built_in_detectors();
        for (id, input) in cases {
            let registered = detectors
                .iter()
                .find(|detector| detector.id() == id)
                .expect("every case id names a registered built-in detector");
            let context = DetectorContext::new(input.len());
            let candidates: Vec<Candidate> = registered.detect(input, &context).unwrap();
            assert_eq!(candidates.len(), 1, "{id}");
            assert_eq!(
                candidates[0].effective_specificity(),
                Specificity::Provider,
                "{id}"
            );
        }
    }
}
