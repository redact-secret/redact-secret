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
mod cloudflare;
mod connection_string;
mod datadog;
mod discord;
mod firebase;
mod generic_token;
mod github;
mod gitlab;
mod grafana;
mod jwt;
mod linear;
mod microsoft_entra;
mod new_relic;
mod notion;
mod openai;
mod otpauth;
mod pattern;
mod private_key;
mod ruleset_adapter;
mod sendgrid;
mod sentry;
mod shopify;
mod slack;
mod telegram;
mod terraform;
mod text;
mod twilio;
mod vault;

use crate::types::Detector;
use connection_string::ConnectionStringDetector;
use private_key::PrivateKeyDetector;

pub(crate) use bearer_token::has_open_bearer_authorization;
pub(crate) use generic_token::{
    RULESET_NAMES_DETECTOR_ID, generic_token_ruleset_names_detector,
    has_open_contextual_assignment, is_reserved_name, normalize_name,
};
pub(crate) use private_key::PrivateKeyRetentionTracker;
pub(crate) use ruleset_adapter::RulesetDetector;

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
        Box::new(slack::SlackTokenDetector),
        Box::new(additional_providers::PYPI),
        Box::new(additional_providers::HUGGING_FACE),
        Box::new(additional_providers::DOCKER),
        Box::new(cloudflare::CLOUDFLARE),
        Box::new(additional_providers::DIGITALOCEAN),
        Box::new(linear::LINEAR),
        Box::new(additional_providers::SUPABASE),
        Box::new(additional_providers::SUPABASE_PAT),
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
        Box::new(firebase::FirebaseServerKeyDetector),
        Box::new(terraform::TerraformCloudTokenDetector),
        Box::new(additional_providers::PULUMI),
        jwt::jwt_detector(),
        bearer_token::bearer_token_detector(),
        Box::new(ConnectionStringDetector),
        otpauth::otpauth_detector(),
        generic_token::generic_token_detector(),
    ]
}

/// Every built-in detector the `common` profile registers, in the same
/// relative order [`built_in_detectors`] gives them.
///
/// This function is written to reference only these six constructors. A
/// `common`-only artifact links no `provider` detector's code, because
/// nothing here calls into `built_in_detectors` or any `provider` module —
/// see `decision-define-detector-profile-and-pack-contract`'s reachability
/// rule. [`BUILT_IN_PACKS`] pins, in tests, that this list is exactly the
/// `Pack::Common` members of the canonical order.
#[must_use]
pub(crate) fn common_built_in_detectors() -> Vec<Box<dyn Detector>> {
    vec![
        Box::new(PrivateKeyDetector),
        jwt::jwt_detector(),
        bearer_token::bearer_token_detector(),
        Box::new(ConnectionStringDetector),
        otpauth::otpauth_detector(),
        generic_token::generic_token_detector(),
    ]
}

/// Which profiles a built-in detector belongs to
/// (`decision-define-detector-profile-and-pack-contract`). Every built-in
/// detector has exactly one pack; `full` holds both.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Pack {
    /// Format-agnostic: a published structure or a credential-bearing
    /// context, not one issuer's token format. Ships in every profile.
    Common,
    /// One issuer's documented or reviewed token format. Ships only in
    /// `full`.
    Provider,
}

/// The canonical id and pack of every built-in detector, in canonical
/// order.
///
/// Pure data: constructing this array calls no detector constructor, so
/// referencing it — for example to compute the reserved-id set a smaller
/// profile's custom detectors must avoid — never pulls a `provider`
/// detector's code into a `common`-only artifact.
pub(crate) const BUILT_IN_PACKS: &[(&str, Pack)] = &[
    ("private-key", Pack::Common),
    ("aws-access-key", Pack::Provider),
    ("github-token", Pack::Provider),
    ("gitlab-token", Pack::Provider),
    ("openai-token", Pack::Provider),
    ("anthropic-token", Pack::Provider),
    ("shopify-token", Pack::Provider),
    ("vault-token", Pack::Provider),
    ("stripe-token", Pack::Provider),
    ("slack-token", Pack::Provider),
    ("pypi-token", Pack::Provider),
    ("huggingface-token", Pack::Provider),
    ("docker-token", Pack::Provider),
    ("cloudflare-token", Pack::Provider),
    ("digitalocean-token", Pack::Provider),
    ("linear-token", Pack::Provider),
    ("supabase-token", Pack::Provider),
    ("supabase-management-token", Pack::Provider),
    ("vercel-token", Pack::Provider),
    ("npm-token", Pack::Provider),
    ("google-api-key", Pack::Provider),
    ("sendgrid-token", Pack::Provider),
    ("microsoft-entra-client-secret", Pack::Provider),
    ("azure-devops-personal-access-token", Pack::Provider),
    ("notion-token", Pack::Provider),
    ("atlassian-api-token", Pack::Provider),
    ("twilio-auth-token", Pack::Provider),
    ("twilio-api-key-secret", Pack::Provider),
    ("telegram-bot-token", Pack::Provider),
    ("discord-bot-token", Pack::Provider),
    ("sentry-user-auth-token", Pack::Provider),
    ("sentry-org-auth-token", Pack::Provider),
    ("datadog-api-key", Pack::Provider),
    ("datadog-application-key", Pack::Provider),
    ("grafana-service-account-token", Pack::Provider),
    ("grafana-cloud-access-policy-token", Pack::Provider),
    ("new-relic-user-api-key", Pack::Provider),
    ("new-relic-license-key", Pack::Provider),
    ("firebase-server-key", Pack::Provider),
    ("terraform-cloud-token", Pack::Provider),
    ("pulumi-access-token", Pack::Provider),
    ("jwt", Pack::Common),
    ("bearer-token", Pack::Common),
    ("connection-string", Pack::Common),
    ("otpauth-uri", Pack::Common),
    ("generic-token", Pack::Common),
];

/// Every built-in id, `full`'s reserved-id set: no custom detector in any
/// profile may reuse one of these, even a `provider` id a smaller profile
/// does not itself register
/// (`decision-define-detector-profile-and-pack-contract`, "Reserved ids").
pub(crate) fn built_in_ids() -> impl Iterator<Item = &'static str> {
    BUILT_IN_PACKS.iter().map(|(id, _)| *id)
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
                "supabase-management-token",
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
                "firebase-server-key",
                "terraform-cloud-token",
                "pulumi-access-token",
                "jwt",
                "bearer-token",
                "connection-string",
                "otpauth-uri",
                "generic-token",
            ]
        );
    }

    fn ids_of(detectors: &[Box<dyn Detector>]) -> Vec<&str> {
        detectors.iter().map(|d| d.id()).collect()
    }

    #[test]
    fn built_in_packs_table_matches_the_real_full_registry() {
        let full = built_in_detectors();
        let full_ids = ids_of(&full);
        let table_ids: Vec<&str> = built_in_ids().collect();
        assert_eq!(
            table_ids, full_ids,
            "BUILT_IN_PACKS must list exactly built_in_detectors()'s ids, in the same order"
        );
        assert_eq!(BUILT_IN_PACKS.len(), full_ids.len());
    }

    #[test]
    fn common_built_in_detectors_are_exactly_the_common_pack_in_canonical_order() {
        let common = common_built_in_detectors();
        let common_ids = ids_of(&common);
        let table_common_ids: Vec<&str> = BUILT_IN_PACKS
            .iter()
            .filter(|(_, pack)| *pack == Pack::Common)
            .map(|(id, _)| *id)
            .collect();
        assert_eq!(common_ids, table_common_ids);
        assert_eq!(
            common_ids,
            vec![
                "private-key",
                "jwt",
                "bearer-token",
                "connection-string",
                "otpauth-uri",
                "generic-token",
            ]
        );

        // `common` is an order-preserving subsequence of `full`.
        let full = built_in_detectors();
        let full_ids = ids_of(&full);
        let mut cursor = 0;
        for id in &common_ids {
            let found = full_ids[cursor..]
                .iter()
                .position(|full_id| full_id == id)
                .expect("every common id must appear in full");
            cursor += found + 1;
        }
    }

    #[test]
    fn every_built_in_has_exactly_one_pack_and_no_id_repeats() {
        let mut ids: Vec<&str> = BUILT_IN_PACKS.iter().map(|(id, _)| *id).collect();
        let count = ids.len();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), count, "BUILT_IN_PACKS must not repeat an id");
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

    /// Issue #552: a genuine, marker-bearing legacy `sk-` key satisfies both
    /// `openai-token`'s reviewed contract and `generic-token`'s new bare
    /// vendor-prefixed policy layer at the identical range. The candidates
    /// compete, but never the finding: `openai-token`'s
    /// [`Specificity::Provider`] strictly dominates `generic-token`'s
    /// [`Specificity::Entropy`] in overlap resolution
    /// (`decision-resolve-overlap-precedence-by-resolved-action-severity`),
    /// so the in-contract key always keeps its own `openai_api_key` finding.
    #[test]
    fn openai_token_and_generic_token_policy_candidates_compete_and_provider_specificity_dominates()
    {
        let input = "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";
        let context = DetectorContext::new(input.len());
        let provider = openai::OpenAiTokenDetector.detect(input, &context).unwrap();
        let policy = generic_token::generic_token_detector()
            .detect(input, &context)
            .unwrap();

        assert_eq!(provider.len(), 1);
        assert_eq!(provider[0].type_name(), "openai_api_key");
        assert_eq!(provider[0].confidence(), Confidence::High);
        assert_eq!(provider[0].specificity(), Some(Specificity::Provider));

        assert_eq!(policy.len(), 1);
        assert_eq!(policy[0].type_name(), "vendor_prefixed_credential");
        assert_eq!(policy[0].confidence(), Confidence::Medium);
        assert_eq!(policy[0].specificity(), Some(Specificity::Entropy));

        assert_eq!(provider[0].range(), policy[0].range());
        assert!(Specificity::Provider > Specificity::Entropy);
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
            (
                "openai-token",
                "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",
            ),
            (
                "anthropic-token",
                "sk-ant-api03-SYNTHETIC_REVOKED_ANTHROPIC_KEY",
            ),
            ("shopify-token", "shpat_SYNTHETIC_REVOKED_SHOPIFY_TOKEN"),
            ("vault-token", "hvs.SYNTHETIC_REVOKED_VAULT_TOKEN"),
            ("stripe-token", "sk_live_SYNTHETICREVOKEDPROVIDERVALUE"),
            (
                "slack-token",
                "xoxb-1234567890123-3210987654321-SYNTHETICREVOKEDBOTSECRET1",
            ),
            ("pypi-token", pypi_input.as_str()),
            ("huggingface-token", "hf_SYNTHETICREVOKEDHUGGINGFACETOKEN01"),
            ("docker-token", "dckr_pat_SYNTHETICREVOKEDDOCKERPAT00"),
            (
                "cloudflare-token",
                "cfut_SYNTHETICREVOKEDCLOUDFLAREAPITOKENVALUE1deadbeef",
            ),
            (
                "digitalocean-token",
                "dop_v1_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            ),
            (
                "linear-token",
                "lin_api_SYNTHETICREVOKEDLINEARAPITOKENVALUE01234",
            ),
            ("supabase-token", "sb_secret_SYNTHETICREVOKEDPROVIDERVALUE"),
            (
                "supabase-management-token",
                "sbp_synthetic0revoked1provider2value3padding",
            ),
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
        let firebase_server_key_input = format!(
            "AAAA{}:{}",
            "SYNREV0",
            "SYNTHETICREVOKEDFIREBASEFCMLEGACYSERVERKEYFIXTUREPADDING0123456789SYNTHETICREVOKEDFIREBASEFCMLEGACYSERVERKEYFIXTUREPADDING0123456789ABCDWXYZ"
        );
        let terraform_cloud_token_input = format!(
            "SYNREV0REVOKED.atlasv1.{}",
            &"SYNTHETICREVOKEDTERRAFORMCLOUDTOKENFIXTUREPADDING0123456789ABCDEFGHIJKLMNOPQR"[..67]
        );
        let pulumi_access_token_input =
            format!("pul-{}", "0123456789abcdef0123456789abcdef01234567");
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
            ("firebase-server-key", firebase_server_key_input.as_str()),
            (
                "terraform-cloud-token",
                terraform_cloud_token_input.as_str(),
            ),
            ("pulumi-access-token", pulumi_access_token_input.as_str()),
        ];
        assert_provider_candidates(&cases);
    }

    /// Issue #375 checkbox 5: a contract-rejected shape from one of the
    /// seven frozen provider families must stay silent when that provider's
    /// detector runs alone (`built_in_detectors` filtered to just its id,
    /// mirroring `assert_provider_candidates` above), while the *default*
    /// registry -- the full built-in set -- still masks the same value
    /// through `bearer-token` under a `Bearer` credential. No global
    /// suppression follows from one provider's own rejection.
    #[test]
    fn provider_only_scan_stays_silent_while_the_default_registry_still_masks_the_malformed_shape()
    {
        let cases: &[(&str, &str)] = &[
            (
                "openai-token",
                // Legacy left segment one byte short of the contracted 20.
                "sk-SYNTHETIC_REVOKED_1T3BlbkFJSYNTHETIC_REVOKED_0002",
            ),
            (
                "digitalocean-token",
                // 63 lowercase-hex bytes, one short of the contracted 64.
                "dop_v1_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd",
            ),
            (
                "docker-token",
                // 26-byte PAT body, one short of the contracted 27.
                "dckr_pat_SYNTHETICREVOKEDDOCKERPA",
            ),
            (
                "slack-token",
                // The two numeric bot sections run straight into the secret
                // with no separator: the exact beta.4 shape the frozen
                // contract rejects.
                "xoxb-1234567890123-3210987654321SYNTHETICREVOKEDBOTSECRET1",
            ),
            (
                "huggingface-token",
                // 33-byte body, one short of the contracted 34.
                "hf_SyntheticRevokedHuggingFaceTokenA",
            ),
            (
                "cloudflare-token",
                // Non-hex checksum suffix.
                "cfut_SYNTHETICREVOKEDCLOUDFLAREAPITOKENVALUE1ghijklmn",
            ),
            (
                "linear-token",
                // 39-byte body, one short of the contracted 40.
                "lin_api_SyntheticRevokedLinearApiTokenABCDEF012",
            ),
        ];

        let all_detectors = built_in_detectors();
        for (id, malformed) in cases {
            let provider_only = all_detectors
                .iter()
                .find(|detector| detector.id() == *id)
                .expect("every case id names a registered built-in detector");
            let context = DetectorContext::new(malformed.len());
            let candidates = provider_only.detect(malformed, &context).unwrap();
            assert!(
                candidates.is_empty(),
                "{id}: provider-only scan of a contract-rejected shape must stay silent"
            );

            let wrapped = format!("Authorization: Bearer {malformed}");
            let default_registry = crate::DetectorRegistry::with_built_in([]).unwrap();
            let findings = crate::scan(&wrapped, &default_registry, &crate::DefaultPolicy).unwrap();
            assert_eq!(
                findings.len(),
                1,
                "{id}: the default registry must still mask the same value as a Bearer credential"
            );
            assert_eq!(findings[0].detector(), "bearer-token", "{id}");
            assert_eq!(findings[0].type_name(), "bearer_token", "{id}");
        }
    }
}
