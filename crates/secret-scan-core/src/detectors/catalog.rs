//! The emitted finding types of every built-in detector, as pure data
//! (issue #1250).
//!
//! This is the type half of the detector metadata catalog. The id, canonical
//! order and pack of every built-in detector are in
//! [`BUILT_IN_PACKS`](super::BUILT_IN_PACKS); the registration rows
//! ([`built_in_detectors`](super::built_in_detectors),
//! [`common_built_in_detectors`](super::common_built_in_detectors)) are what
//! a profile links. The artifact manifest reads the ids from the rows and the
//! pack and types from these tables, so a drift between them is caught by the
//! tests below and by `tests/artifact_manifest_1250.rs`, never silently
//! shipped.
//!
//! The tables are split by pack so a `common`-only artifact references only
//! [`COMMON_TYPES`]: the provider type names are not linked into it, the same
//! reachability rule the registration rows follow
//! (`decision-define-detector-profile-and-pack-contract`). Each entry lists
//! the types a detector can emit, sorted. The list is the reviewed declaration
//! in `docs/coverage/detector-inventory.json`, reconciled by
//! `tests/artifact_manifest_1250.rs`; it is not a closed vocabulary for the
//! whole engine, because a ruleset, a custom detector and the PII adapter
//! emit types this table does not name.
//!
//! No entry constructs a detector.

pub(crate) const COMMON_TYPES: &[(&str, &[&str])] = &[
    ("private-key", &["private_key"]),
    ("jwt", &["jwt"]),
    ("bearer-token", &["bearer_token"]),
    ("connection-string", &["connection_string_password"]),
    ("otpauth-uri", &["otpauth_secret"]),
    (
        "generic-token",
        &[
            "authorization_credential",
            "contextual_secret",
            "vendor_prefixed_credential",
        ],
    ),
];

pub(crate) const PROVIDER_TYPES: &[(&str, &[&str])] = &[
    ("aws-access-key", &["aws_access_key_id"]),
    ("aws-secret-access-key", &["aws_secret_access_key"]),
    (
        "aws-bedrock-long-term-api-key",
        &["aws_bedrock_long_term_api_key"],
    ),
    (
        "aws-bedrock-short-term-api-key",
        &["aws_bedrock_short_term_api_key"],
    ),
    (
        "github-token",
        &[
            "github_app_installation_token",
            "github_app_refresh_token",
            "github_app_user_to_server_token",
            "github_fine_grained_personal_access_token",
            "github_oauth_token",
            "github_token",
        ],
    ),
    ("gitlab-token", &["gitlab_token"]),
    ("openai-token", &["openai_admin_api_key", "openai_api_key"]),
    (
        "anthropic-token",
        &[
            "anthropic_admin_api_key",
            "anthropic_api_key",
            "anthropic_enterprise_api_key",
        ],
    ),
    ("shopify-token", &["shopify_access_token"]),
    ("vault-token", &["vault_token"]),
    (
        "stripe-token",
        &["stripe_credential", "stripe_webhook_signing_secret"],
    ),
    (
        "slack-token",
        &["slack_app_level_token", "slack_token", "slack_user_token"],
    ),
    ("pypi-token", &["pypi_api_token"]),
    ("huggingface-token", &["huggingface_token"]),
    ("docker-token", &["docker_token"]),
    ("cloudflare-token", &["cloudflare_api_token"]),
    ("digitalocean-token", &["digitalocean_token"]),
    ("linear-token", &["linear_token"]),
    ("supabase-token", &["supabase_secret_key"]),
    (
        "supabase-management-token",
        &["supabase_personal_access_token"],
    ),
    (
        "vercel-token",
        &[
            "vercel_app_access_token",
            "vercel_app_refresh_token",
            "vercel_personal_access_token",
            "vercel_token",
        ],
    ),
    ("npm-token", &["npm_access_token"]),
    ("google-api-key", &["google_api_key"]),
    (
        "google-oauth-client-secret",
        &["google_oauth_client_secret"],
    ),
    ("sendgrid-token", &["sendgrid_api_key"]),
    (
        "microsoft-entra-client-secret",
        &["microsoft_entra_client_secret"],
    ),
    (
        "azure-devops-personal-access-token",
        &["azure_devops_personal_access_token"],
    ),
    ("notion-token", &["notion_integration_token"]),
    ("atlassian-api-token", &["atlassian_api_token"]),
    ("twilio-auth-token", &["twilio_auth_token"]),
    ("twilio-api-key-secret", &["twilio_api_key_secret"]),
    ("telegram-bot-token", &["telegram_bot_token"]),
    ("discord-bot-token", &["discord_bot_token"]),
    ("sentry-user-auth-token", &["sentry_user_auth_token"]),
    ("sentry-org-auth-token", &["sentry_org_auth_token"]),
    ("datadog-api-key", &["datadog_api_key"]),
    ("datadog-application-key", &["datadog_application_key"]),
    (
        "datadog-application-key-legacy",
        &["datadog_application_key_legacy"],
    ),
    (
        "grafana-service-account-token",
        &["grafana_service_account_token"],
    ),
    (
        "grafana-cloud-access-policy-token",
        &["grafana_cloud_access_policy_token"],
    ),
    ("new-relic-user-api-key", &["new_relic_user_api_key"]),
    ("new-relic-license-key", &["new_relic_license_key"]),
    ("mailchimp-api-key", &["mailchimp_api_key"]),
    ("mailgun-api-key", &["mailgun_api_key"]),
    ("okta-api-token", &["okta_api_token"]),
    ("firebase-server-key", &["firebase_server_key"]),
    ("terraform-cloud-token", &["terraform_cloud_token"]),
    ("pulumi-access-token", &["pulumi_access_token"]),
    ("replicate-api-token", &["replicate_api_token"]),
    ("groq-api-key", &["groq_api_key"]),
    ("xai-api-key", &["xai_api_key"]),
    ("openrouter-api-key", &["openrouter_api_key"]),
    ("perplexity-api-key", &["perplexity_api_key"]),
    ("fireworks-ai-api-key", &["fireworks_ai_api_key"]),
    ("elevenlabs-api-key", &["elevenlabs_api_key"]),
    ("together-ai-api-key", &["together_ai_api_key"]),
    ("tavily-api-key", &["tavily_api_key"]),
    ("pinecone-api-key", &["pinecone_api_key"]),
    (
        "gitlab-runner-authentication-token",
        &["gitlab_runner_authentication_token"],
    ),
    (
        "databricks-personal-access-token",
        &["databricks_personal_access_token"],
    ),
    (
        "confluent-cloud-api-secret",
        &["confluent_cloud_api_secret"],
    ),
    (
        "confluent-cloud-api-secret-legacy",
        &["confluent_cloud_api_secret_legacy"],
    ),
    ("netlify-token", &["netlify_personal_access_token"]),
    ("neon-api-key", &["neon_api_key"]),
    ("langsmith-api-key", &["langsmith_api_key"]),
    ("langfuse-secret-key", &["langfuse_secret_key"]),
    ("postman-api-key", &["postman_api_key"]),
    (
        "postman-collection-access-key",
        &["postman_collection_access_key"],
    ),
    ("heroku-api-key", &["heroku_api_key"]),
    ("heroku-api-key-legacy", &["heroku_api_key_legacy"]),
    ("travisci-api-token", &["travisci_api_token"]),
    ("mistral-api-key", &["mistral_api_key"]),
    ("cohere-api-key", &["cohere_api_key"]),
    ("ai21-api-key", &["ai21_api_key"]),
    ("deepgram-api-key", &["deepgram_api_key"]),
    (
        "doppler-token",
        &[
            "doppler_audit_token",
            "doppler_cli_token",
            "doppler_personal_token",
            "doppler_scim_token",
            "doppler_service_account_identity_token",
            "doppler_service_account_token",
            "doppler_service_token",
        ],
    ),
    (
        "trigger-dev-token",
        &[
            "trigger_dev_personal_access_token",
            "trigger_dev_secret_api_key",
        ],
    ),
    ("e2b-api-key", &["e2b_api_key"]),
    (
        "posthog-token",
        &["posthog_personal_api_key", "posthog_project_secret_api_key"],
    ),
    (
        "helicone-api-key",
        &["helicone_api_key", "helicone_write_api_key"],
    ),
    ("firecrawl-api-key", &["firecrawl_api_key"]),
    (
        "composio-api-key",
        &[
            "composio_org_api_key",
            "composio_project_api_key",
            "composio_user_api_key",
        ],
    ),
    ("convex-deployment-key", &["convex_deployment_key"]),
    (
        "onepassword-service-account-token",
        &["onepassword_service_account_token"],
    ),
    ("inngest-signing-key", &["inngest_signing_key"]),
    ("resend-api-key", &["resend_api_key"]),
    ("apify-api-token", &["apify_api_token"]),
    ("wandb-api-key", &["wandb_api_key"]),
    ("daytona-api-key", &["daytona_api_key"]),
    (
        "clickhouse-cloud-api-secret",
        &["clickhouse_cloud_api_secret"],
    ),
    ("nvidia-api-key", &["nvidia_api_key"]),
    ("browserbase-api-key", &["browserbase_api_key"]),
    ("runpod-api-key", &["runpod_api_key"]),
    ("cerebras-api-key", &["cerebras_api_key"]),
    (
        "bitwarden-secrets-manager-access-token",
        &["bitwarden_secrets_manager_access_token"],
    ),
    (
        "polar-token",
        &["polar_api_credential", "polar_organization_access_token"],
    ),
    (
        "sonarqube-token",
        &["sonarqube_analysis_token", "sonarqube_user_token"],
    ),
    ("rubygems-api-key", &["rubygems_api_key"]),
    ("clojars-deploy-token", &["clojars_deploy_token"]),
    (
        "crates-io-token",
        &["crates_io_api_token", "crates_io_trusted_publishing_token"],
    ),
    ("dynatrace-token", &["dynatrace_token"]),
    ("paddle-api-key", &["paddle_api_key"]),
    ("honeycomb-api-key", &["honeycomb_ingest_key"]),
    ("axiom-token", &["axiom_api_token", "axiom_personal_token"]),
    (
        "xata-api-key",
        &["xata_organization_api_key", "xata_user_api_key"],
    ),
    ("sourcegraph-token", &["sourcegraph_access_token"]),
    ("unkey-root-key", &["unkey_root_key"]),
    (
        "buildkite-token",
        &[
            "buildkite_agent_token",
            "buildkite_api_access_token",
            "buildkite_job_token",
            "buildkite_oauth_token",
            "buildkite_packages_token",
            "buildkite_pipeline_token",
            "buildkite_portal_token",
        ],
    ),
    ("pydantic-logfire-token", &["pydantic_logfire_token"]),
    (
        "square-token",
        &["square_access_token", "square_oauth_application_secret"],
    ),
    ("mapbox-token", &["mapbox_secret_access_token"]),
    ("fly-token", &["fly_access_token"]),
];

/// The declared emitted types of the built-in detector `id`, or `None` for an
/// id that is not a built-in.
pub(crate) fn declared_types(id: &str) -> Option<&'static [&'static str]> {
    declared_common_types(id).or_else(|| {
        PROVIDER_TYPES
            .iter()
            .find(|(declared, _)| *declared == id)
            .map(|(_, types)| *types)
    })
}

/// The declared emitted types of the `common` built-in detector `id`. Names
/// only [`COMMON_TYPES`], so a `common` artifact that calls it links no
/// provider type name.
pub(crate) fn declared_common_types(id: &str) -> Option<&'static [&'static str]> {
    COMMON_TYPES
        .iter()
        .find(|(declared, _)| *declared == id)
        .map(|(_, types)| *types)
}

/// Byte-wise equality of two strings in a `const` context.
pub(crate) const fn const_str_eq(left: &str, right: &str) -> bool {
    let (left, right) = (left.as_bytes(), right.as_bytes());
    if left.len() != right.len() {
        return false;
    }
    let mut index = 0;
    while index < left.len() {
        if left[index] != right[index] {
            return false;
        }
        index += 1;
    }
    true
}

/// The declared emitted types of the built-in detector `id`, resolved when
/// the crate is compiled (issue #1253).
///
/// Evaluated in a `const` item, only the one slice it returns is linked: a
/// composed artifact carries the types of its selected detectors and no other
/// provider type name. An id with no entry fails the build of this crate, so
/// a constructor cannot be added without its catalog row.
pub(crate) const fn types_const(id: &str) -> &'static [&'static str] {
    let mut index = 0;
    while index < COMMON_TYPES.len() {
        if const_str_eq(COMMON_TYPES[index].0, id) {
            return COMMON_TYPES[index].1;
        }
        index += 1;
    }
    index = 0;
    while index < PROVIDER_TYPES.len() {
        if const_str_eq(PROVIDER_TYPES[index].0, id) {
            return PROVIDER_TYPES[index].1;
        }
        index += 1;
    }
    // Reached only when a `const` item evaluates an id that has no row:
    // that is a compile error, never a run-time path.
    #[allow(clippy::panic)]
    {
        panic!("a built-in detector has no declared types")
    }
}

#[cfg(test)]
mod tests {
    use super::super::{BUILT_IN_PACKS, Pack, built_in_detectors, common_built_in_detectors};
    use super::*;
    use crate::is_identifier;

    #[test]
    fn tables_follow_the_canonical_order_of_their_pack() {
        for (table, pack) in [
            (COMMON_TYPES, Pack::Common),
            (PROVIDER_TYPES, Pack::Provider),
        ] {
            let expected: Vec<&str> = BUILT_IN_PACKS
                .iter()
                .filter(|(_, p)| *p == pack)
                .map(|(id, _)| *id)
                .collect();
            let declared: Vec<&str> = table.iter().map(|(id, _)| *id).collect();
            assert_eq!(declared, expected);
        }
    }

    #[test]
    fn common_table_is_exactly_the_common_registration_rows() {
        let rows: Vec<&str> = common_built_in_detectors()
            .iter()
            .map(|row| row.id)
            .collect();
        let declared: Vec<&str> = COMMON_TYPES.iter().map(|(id, _)| *id).collect();
        assert_eq!(declared, rows);
    }

    #[test]
    fn every_full_registration_row_has_declared_types() {
        for row in built_in_detectors() {
            let types = declared_types(row.id).unwrap_or_default();
            assert!(!types.is_empty(), "{} declares no type", row.id);
        }
        let total = COMMON_TYPES.len() + PROVIDER_TYPES.len();
        assert_eq!(total, built_in_detectors().len());
    }

    #[test]
    fn declared_types_are_sorted_unique_identifiers() {
        for (id, types) in COMMON_TYPES.iter().chain(PROVIDER_TYPES) {
            assert!(types.windows(2).all(|pair| pair[0] < pair[1]), "{id}");
            assert!(types.iter().all(|name| is_identifier(name)), "{id}");
        }
    }

    #[test]
    fn unknown_ids_have_no_declared_types() {
        assert!(declared_types("not-a-built-in").is_none());
        assert!(declared_common_types("github-token").is_none());
        assert!(declared_common_types("jwt").is_some());
    }
}
