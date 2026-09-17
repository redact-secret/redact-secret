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
mod atlassian;
mod aws;
mod azure_devops;
mod bearer_token;
mod connection_string;
mod datadog;
mod discord;
mod generic_token;
mod github;
mod gitlab;
mod grafana;
mod jwt;
mod microsoft_entra;
mod new_relic;
mod notion;
mod openai;
mod otpauth;
mod pattern;
mod private_key;
mod sendgrid;
mod sentry;
mod shopify;
mod telegram;
mod text;
mod twilio;
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
        Box::new(additional_providers::GOOGLE),
        Box::new(sendgrid::SendgridTokenDetector),
        Box::new(microsoft_entra::MicrosoftEntraClientSecretDetector),
        Box::new(azure_devops::AzureDevOpsPersonalAccessTokenDetector),
        Box::new(notion::NotionTokenDetector),
        Box::new(atlassian::AtlassianApiTokenDetector),
        Box::new(twilio::TwilioAuthTokenDetector),
        Box::new(twilio::TwilioApiKeySecretDetector),
        telegram::telegram_bot_token_detector(),
        Box::new(discord::DiscordBotTokenDetector),
        Box::new(sentry::SentryUserAuthTokenDetector),
        Box::new(sentry::SentryOrgAuthTokenDetector),
        Box::new(datadog::DatadogApiKeyDetector),
        Box::new(datadog::DatadogApplicationKeyDetector),
        Box::new(grafana::GrafanaServiceAccountTokenDetector),
        Box::new(additional_providers::GRAFANA_CLOUD),
        Box::new(new_relic::NewRelicUserApiKeyDetector),
        Box::new(new_relic::NewRelicLicenseKeyDetector),
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
                "google-api-key",
                "sendgrid-token",
                "microsoft-entra-client-secret",
                "azure-devops-personal-access-token",
                "notion-token",
                "atlassian-api-token",
                "twilio-auth-token",
                "twilio-api-key-secret",
                "telegram-bot-token",
                "discord-bot-token",
                "sentry-user-auth-token",
                "sentry-org-auth-token",
                "datadog-api-key",
                "datadog-application-key",
                "grafana-service-account-token",
                "grafana-cloud-access-policy-token",
                "new-relic-user-api-key",
                "new-relic-license-key",
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
    fn basic_scheme_is_excluded_from_bearer_token_but_generic_token_still_claims_it() {
        let input = "Authorization: Basic ZGVtb3VzZXI6ZGVtb3Bhc3N3b3Jk";
        let context = DetectorContext::new(input.len());
        let bearer = bearer_token::bearer_token_detector()
            .detect(input, &context)
            .unwrap();
        let contextual = generic_token::generic_token_detector()
            .detect(input, &context)
            .unwrap();

        assert!(
            bearer.is_empty(),
            "bearer-token only claims the literal 'bearer' scheme"
        );
        assert_eq!(contextual.len(), 1);
        assert_eq!(contextual[0].type_name(), "authorization_credential");
    }

    fn assert_provider_candidates(cases: &[(&str, &str)]) {
        let detectors = built_in_detectors();
        for (id, input) in cases {
            let registered = detectors
                .iter()
                .find(|detector| detector.id() == *id)
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

    #[test]
    fn established_built_in_provider_candidates_claim_provider_specificity() {
        let pypi_input = format!("pypi-{}", "SYNTHETIC_REVOKED_".repeat(5));
        let sendgrid_input =
            "SG.SYNTHETIC_REVOKED_0000.SYNTHETIC_REVOKED_SENDGRID_SECRET_000000000";
        let atlassian_input = format!(
            "ATAT{}",
            "SYNTHETIC_REVOKED_ATLASSIAN_API_TOKEN_BODY_".repeat(3)
        );
        let twilio_auth_token_input =
            "twilio AC0123456789abcdef0123456789abcde0 fedcba9876543210fedcba9876543210";
        let twilio_api_key_secret_input =
            "twilio SKaB3dE5gH7jK9mN1pQ3sT5vW7yZ9AbC3d zY9xW7vU5tS3rQ1pO9nM7lK5jI3hG1fE";
        let telegram_input = "123456:SYNTHETIC_REVOKED_TELEGRAM_BOT_TOKEN_SECRET";
        let discord_input = "MDAwMDAwMDAwMDAwMDAwMDAw.REVOKE.SYNTHETICREVOKEDBOTTOKENFIX";
        let cases = [
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
            (
                "digitalocean-token",
                "dop_v1_1f24601fd1e661dc9b0a5f6e206888cac4ba0147c46563ccd2d81004e954cad9",
            ),
            ("linear-token", "lin_api_SYNTHETICREVOKEDPROVIDERVALUE"),
            ("supabase-token", "sb_secret_SYNTHETICREVOKEDPROVIDERVALUE"),
            ("vercel-token", "vcp_SYNTHETICREVOKEDPROVIDERVALUE"),
            ("npm-token", "npm_SYNTHETICREVOKEDNPMACCESSTOKENVALUE1"),
            ("google-api-key", "AIzaSYNTHETIC_REVOKED_GOOGLE_API_KEY012"),
            ("sendgrid-token", sendgrid_input),
            (
                "microsoft-entra-client-secret",
                "abc8Q~SYNTHETIC_REVOKED_ENTRA_SECRET_V",
            ),
            (
                "azure-devops-personal-access-token",
                "SYNTHETICREVOKEDAZUREDEVOPSPATVALUEFORCONFORMANCETESTINGPADDINGFIXTUREDATAZZAZDOabcd",
            ),
            (
                "notion-token",
                "secret_SYNTHETICREVOKEDNOTIONLEGACYTOKENVALUE00000",
            ),
            ("atlassian-api-token", atlassian_input.as_str()),
            ("twilio-auth-token", twilio_auth_token_input),
            ("twilio-api-key-secret", twilio_api_key_secret_input),
            ("discord-bot-token", discord_input),
            ("telegram-bot-token", telegram_input),
        ];
        assert_provider_candidates(&cases);
    }

    #[test]
    fn recent_built_in_provider_candidates_claim_provider_specificity() {
        let sentry_user_auth_token_input = format!("sntryu_{}", "0123456789abcdef".repeat(4));
        let sentry_org_auth_token_input = format!(
            "sntrys_eyJ{}_{}",
            &"SYNTHETICREVOKEDSENTRYORGPAYLOADFIXTURE0123456789".repeat(4)[..23],
            &"SigFixSYNTHETICREVOKED0123456789".repeat(2)[..43]
        );
        let grafana_sa_input = "glsa_SYNTHETICREVOKEDGRAFANASATOKEN01_deadbeef";
        let grafana_cloud_input = "glc_SYNTHETICREVOKEDGRAFANACLOUDACCESSPOLICYTOKEN";
        let datadog_api_key_input = "DD_API_KEY=0123456789abcdef0123456789abcdef";
        let datadog_application_key_input =
            "DD_APPLICATION_KEY=0123456789abcdef0123456789abcdef01234567";
        let new_relic_user_api_key_input = "NRAK-SYNTHETICREVOKEDNEWRELICUSA";
        let new_relic_license_key_input = "newrelic 0123456789abcdef0123456789abcdef01234567";
        let cases = [
            (
                "sentry-user-auth-token",
                sentry_user_auth_token_input.as_str(),
            ),
            (
                "sentry-org-auth-token",
                sentry_org_auth_token_input.as_str(),
            ),
            ("datadog-api-key", datadog_api_key_input),
            ("datadog-application-key", datadog_application_key_input),
            ("grafana-service-account-token", grafana_sa_input),
            ("grafana-cloud-access-policy-token", grafana_cloud_input),
            ("new-relic-user-api-key", new_relic_user_api_key_input),
            ("new-relic-license-key", new_relic_license_key_input),
        ];
        assert_provider_candidates(&cases);
    }
}
