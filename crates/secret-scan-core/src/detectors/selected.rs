//! The per-detector public constructors of a static custom composition
//! (issue #1253, `decision-define-the-configuration-capability-ceiling-runtime-ownership-and-surface-support`).
//!
//! One function per built-in detector, named after its id with `-` written
//! `_` (`aws-access-key` is `aws_access_key`), each returning an opaque
//! [`SelectedDetector`]. A generated leaf crate calls exactly the
//! constructors a composition selects and nothing else, so link-time
//! reachability removes every other detector's code, its grammar tables and
//! its prefilter literals (the reachability rule of
//! `decision-define-detector-profile-and-pack-contract`). Nothing here
//! consults [`built_in_detectors`](super::built_in_detectors): referencing that
//! table would make every detector reachable.
//!
//! The rows below repeat the registration rows of `built_in_detectors()`; tests
//! pin each constructor to its row, its catalog types and its prefilter
//! declaration, so a drift fails here and never ships.

use std::fmt;

use super::catalog::types_const;
use super::{BuiltInDetector, Literals, RequiredLiterals, declared_literals};

/// A built-in detector chosen for a composition: its id, its detector and the
/// reviewed metadata the registry and the manifest need.
///
/// Created only by the constructors of [`composition`](crate::composition);
/// it holds no input and has no public accessor beyond [`Self::id`].
#[derive(Clone, Copy)]
pub struct SelectedDetector {
    pub(crate) id: &'static str,
    pub(crate) detector: BuiltInDetector,
    pub(crate) types: &'static [&'static str],
    pub(crate) required: Option<RequiredLiterals>,
}

impl SelectedDetector {
    /// The canonical detector id.
    #[must_use]
    pub const fn id(&self) -> &'static str {
        self.id
    }
}

impl fmt::Debug for SelectedDetector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SelectedDetector")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

macro_rules! selected {
    (@required $id:literal) => {{
        const GROUPS: Option<&[Literals]> = declared_literals($id);
        match GROUPS {
            Some(groups) => RequiredLiterals::any_of(groups),
            None => None,
        }
    }};
    (@required $id:literal, $literals:expr) => {
        RequiredLiterals::any_of($literals)
    };
    ($($name:ident = $id:literal, $detector:expr $(, common = $literals:expr)?;)*) => {
        $(
            #[doc = concat!("The `", $id, "` built-in detector.")]
            #[must_use]
            pub fn $name() -> SelectedDetector {
                static DETECTOR: BuiltInDetector = &$detector;
                const TYPES: &[&str] = types_const($id);
                SelectedDetector {
                    id: $id,
                    detector: DETECTOR,
                    types: TYPES,
                    required: selected!(@required $id $(, $literals)?),
                }
            }
        )*

        /// Every constructor with its id, in canonical order.
        #[cfg(test)]
        pub(crate) const ALL: &[(&str, fn() -> SelectedDetector)] = &[$(($id, $name)),*];
    };
}

#[cfg(test)]
mod tests;

#[rustfmt::skip]
selected! {
    private_key = "private-key", super::private_key::PrivateKeyDetector, common = super::private_key::REQUIRED_LITERALS;
    aws_access_key = "aws-access-key", super::aws::AwsAccessKeyDetector;
    aws_secret_access_key = "aws-secret-access-key", super::aws::AwsSecretAccessKeyDetector;
    aws_bedrock_long_term_api_key = "aws-bedrock-long-term-api-key", super::aws_bedrock::AwsBedrockLongTermApiKeyDetector;
    aws_bedrock_short_term_api_key = "aws-bedrock-short-term-api-key", super::aws_bedrock::AwsBedrockShortTermApiKeyDetector;
    github_token = "github-token", super::github::GitHubTokenDetector;
    gitlab_token = "gitlab-token", super::gitlab::GitlabTokenDetector;
    openai_token = "openai-token", super::openai::OpenAiTokenDetector;
    anthropic_token = "anthropic-token", super::anthropic::AnthropicTokenDetector;
    shopify_token = "shopify-token", super::shopify::ShopifyTokenDetector;
    vault_token = "vault-token", super::vault::VaultTokenDetector;
    stripe_token = "stripe-token", super::stripe::StripeTokenDetector;
    slack_token = "slack-token", super::slack::SlackTokenDetector;
    pypi_token = "pypi-token", super::additional_providers::PYPI;
    huggingface_token = "huggingface-token", super::additional_providers::HUGGING_FACE;
    docker_token = "docker-token", super::additional_providers::DOCKER;
    cloudflare_token = "cloudflare-token", super::cloudflare::CLOUDFLARE;
    digitalocean_token = "digitalocean-token", super::additional_providers::DIGITALOCEAN;
    linear_token = "linear-token", super::linear::LINEAR;
    supabase_token = "supabase-token", super::additional_providers::SUPABASE;
    supabase_management_token = "supabase-management-token", super::additional_providers::SUPABASE_PAT;
    vercel_token = "vercel-token", super::vercel::VERCEL;
    npm_token = "npm-token", super::additional_providers::NPM;
    google_api_key = "google-api-key", super::additional_providers::GOOGLE;
    google_oauth_client_secret = "google-oauth-client-secret", super::google_oauth::GOOGLE_OAUTH_CLIENT_SECRET;
    sendgrid_token = "sendgrid-token", super::sendgrid::SendgridTokenDetector;
    microsoft_entra_client_secret = "microsoft-entra-client-secret", super::microsoft_entra::MicrosoftEntraClientSecretDetector;
    azure_devops_personal_access_token = "azure-devops-personal-access-token", super::azure_devops::AzureDevOpsPersonalAccessTokenDetector;
    notion_token = "notion-token", super::notion::NotionTokenDetector;
    atlassian_api_token = "atlassian-api-token", super::atlassian::AtlassianApiTokenDetector;
    twilio_auth_token = "twilio-auth-token", super::twilio::TwilioAuthTokenDetector;
    twilio_api_key_secret = "twilio-api-key-secret", super::twilio::TwilioApiKeySecretDetector;
    telegram_bot_token = "telegram-bot-token", super::telegram::TelegramBotTokenDetector;
    discord_bot_token = "discord-bot-token", super::discord::DiscordBotTokenDetector;
    sentry_user_auth_token = "sentry-user-auth-token", super::sentry::SentryUserAuthTokenDetector;
    sentry_org_auth_token = "sentry-org-auth-token", super::sentry::SentryOrgAuthTokenDetector;
    datadog_api_key = "datadog-api-key", super::datadog::DatadogApiKeyDetector;
    datadog_application_key = "datadog-application-key", super::datadog::DATADOG_APPLICATION_KEY;
    datadog_application_key_legacy = "datadog-application-key-legacy", super::datadog::DatadogApplicationKeyLegacyDetector;
    grafana_service_account_token = "grafana-service-account-token", super::grafana::GrafanaServiceAccountTokenDetector;
    grafana_cloud_access_policy_token = "grafana-cloud-access-policy-token", super::additional_providers::GRAFANA_CLOUD;
    new_relic_user_api_key = "new-relic-user-api-key", super::new_relic::NewRelicUserApiKeyDetector;
    new_relic_license_key = "new-relic-license-key", super::new_relic::NewRelicLicenseKeyDetector;
    mailchimp_api_key = "mailchimp-api-key", super::mailchimp::MailchimpMarketingApiKeyDetector;
    mailgun_api_key = "mailgun-api-key", super::mailgun::MailgunApiKeyDetector;
    okta_api_token = "okta-api-token", super::okta::OktaApiTokenDetector;
    firebase_server_key = "firebase-server-key", super::firebase::FirebaseServerKeyDetector;
    terraform_cloud_token = "terraform-cloud-token", super::terraform::TerraformCloudTokenDetector;
    pulumi_access_token = "pulumi-access-token", super::additional_providers::PULUMI;
    replicate_api_token = "replicate-api-token", super::ai_inference::REPLICATE;
    groq_api_key = "groq-api-key", super::ai_inference::GROQ;
    xai_api_key = "xai-api-key", super::ai_inference::XAI;
    openrouter_api_key = "openrouter-api-key", super::ai_inference::OPENROUTER;
    perplexity_api_key = "perplexity-api-key", super::ai_inference::PERPLEXITY;
    fireworks_ai_api_key = "fireworks-ai-api-key", super::ai_inference::FIREWORKS;
    elevenlabs_api_key = "elevenlabs-api-key", super::elevenlabs::ElevenLabsApiKeyDetector;
    together_ai_api_key = "together-ai-api-key", super::together_tavily::TOGETHER_AI;
    tavily_api_key = "tavily-api-key", super::together_tavily::TAVILY;
    pinecone_api_key = "pinecone-api-key", super::pinecone::PineconeApiKeyDetector;
    gitlab_runner_authentication_token = "gitlab-runner-authentication-token", super::gitlab::GitlabRunnerAuthenticationTokenDetector;
    databricks_personal_access_token = "databricks-personal-access-token", super::databricks::DATABRICKS;
    confluent_cloud_api_secret = "confluent-cloud-api-secret", super::confluent::CONFLUENT_CLOUD_API_SECRET;
    confluent_cloud_api_secret_legacy = "confluent-cloud-api-secret-legacy", super::confluent::ConfluentLegacyApiSecretDetector;
    netlify_token = "netlify-token", super::netlify::NetlifyPersonalAccessTokenDetector;
    neon_api_key = "neon-api-key", super::neon::NEON;
    langsmith_api_key = "langsmith-api-key", super::langsmith::LangsmithApiKeyDetector;
    langfuse_secret_key = "langfuse-secret-key", super::langfuse::LangfuseSecretKeyDetector;
    postman_api_key = "postman-api-key", super::postman::POSTMAN;
    postman_collection_access_key = "postman-collection-access-key", super::postman::POSTMAN_COLLECTION_ACCESS_KEY;
    heroku_api_key = "heroku-api-key", super::heroku::HEROKU_API_KEY;
    heroku_api_key_legacy = "heroku-api-key-legacy", super::heroku::HerokuApiKeyLegacyDetector;
    travisci_api_token = "travisci-api-token", super::travisci::TravisCiApiTokenDetector;
    mistral_api_key = "mistral-api-key", super::keyword_gated_keys::MistralApiKeyDetector;
    cohere_api_key = "cohere-api-key", super::keyword_gated_keys::CohereApiKeyDetector;
    ai21_api_key = "ai21-api-key", super::keyword_gated_keys::Ai21ApiKeyDetector;
    deepgram_api_key = "deepgram-api-key", super::keyword_gated_keys::DeepgramApiKeyDetector;
    doppler_token = "doppler-token", super::doppler::DopplerTokenDetector;
    trigger_dev_token = "trigger-dev-token", super::trigger_dev::TRIGGER_DEV;
    e2b_api_key = "e2b-api-key", super::e2b::E2B;
    posthog_token = "posthog-token", super::posthog::POSTHOG;
    helicone_api_key = "helicone-api-key", super::helicone::HELICONE;
    firecrawl_api_key = "firecrawl-api-key", super::firecrawl::FIRECRAWL;
    composio_api_key = "composio-api-key", super::composio::COMPOSIO;
    convex_deployment_key = "convex-deployment-key", super::convex::ConvexDeploymentKeyDetector;
    onepassword_service_account_token = "onepassword-service-account-token", super::onepassword::OnePasswordServiceAccountTokenDetector;
    inngest_signing_key = "inngest-signing-key", super::inngest::INNGEST_SIGNING_KEY;
    resend_api_key = "resend-api-key", super::resend::RESEND_API_KEY;
    apify_api_token = "apify-api-token", super::apify::APIFY_API_TOKEN;
    wandb_api_key = "wandb-api-key", super::wandb::WANDB_API_KEY;
    daytona_api_key = "daytona-api-key", super::daytona::DAYTONA_API_KEY;
    clickhouse_cloud_api_secret = "clickhouse-cloud-api-secret", super::clickhouse_cloud::CLICKHOUSE_CLOUD_API_SECRET;
    nvidia_api_key = "nvidia-api-key", super::nvidia::NVIDIA_API_KEY;
    browserbase_api_key = "browserbase-api-key", super::browserbase::BROWSERBASE_API_KEY;
    runpod_api_key = "runpod-api-key", super::runpod::RUNPOD_API_KEY;
    cerebras_api_key = "cerebras-api-key", super::cerebras::CEREBRAS_API_KEY;
    bitwarden_secrets_manager_access_token = "bitwarden-secrets-manager-access-token", super::bitwarden::BitwardenSecretsManagerAccessTokenDetector;
    polar_token = "polar-token", super::polar::POLAR;
    sonarqube_token = "sonarqube-token", super::sonarqube::SONARQUBE;
    rubygems_api_key = "rubygems-api-key", super::rubygems::RUBYGEMS_API_KEY;
    clojars_deploy_token = "clojars-deploy-token", super::clojars::CLOJARS_DEPLOY_TOKEN;
    crates_io_token = "crates-io-token", super::crates_io::CRATES_IO;
    dynatrace_token = "dynatrace-token", super::dynatrace::DynatraceTokenDetector;
    paddle_api_key = "paddle-api-key", super::paddle::PADDLE_API_KEY;
    honeycomb_api_key = "honeycomb-api-key", super::honeycomb::HONEYCOMB_INGEST_KEY;
    axiom_token = "axiom-token", super::axiom::AXIOM;
    xata_api_key = "xata-api-key", super::xata::XATA;
    sourcegraph_token = "sourcegraph-token", super::sourcegraph::SOURCEGRAPH;
    unkey_root_key = "unkey-root-key", super::unkey::UNKEY;
    buildkite_token = "buildkite-token", super::buildkite::BUILDKITE;
    pydantic_logfire_token = "pydantic-logfire-token", super::pydantic_logfire::LOGFIRE;
    square_token = "square-token", super::square::SQUARE;
    mapbox_token = "mapbox-token", super::mapbox::MAPBOX;
    fly_token = "fly-token", super::fly::FLY;
    jwt = "jwt", super::jwt::JwtDetector, common = super::jwt::REQUIRED_LITERALS;
    bearer_token = "bearer-token", super::bearer_token::BearerTokenDetector;
    connection_string = "connection-string", super::connection_string::ConnectionStringDetector, common = super::connection_string::REQUIRED_LITERALS;
    otpauth_uri = "otpauth-uri", super::otpauth::OtpauthDetector, common = super::otpauth::REQUIRED_LITERALS;
    generic_token = "generic-token", super::generic_token::GENERIC_TOKEN;
}
