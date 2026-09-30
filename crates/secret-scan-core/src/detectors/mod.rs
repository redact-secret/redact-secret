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
mod ai_inference;
mod anthropic;
mod apify;
mod atlassian;
mod aws;
mod aws_bedrock;
mod axiom;
mod azure_devops;
mod bearer_token;
mod bitwarden;
mod browserbase;
mod cerebras;
mod clickhouse_cloud;
mod clojars;
mod cloudflare;
mod composio;
mod confluent;
mod connection_string;
mod convex;
mod crates_io;
mod databricks;
mod datadog;
mod daytona;
mod discord;
mod doppler;
mod dynatrace;
mod e2b;
mod elevenlabs;
mod firebase;
mod firecrawl;
mod generic_token;
mod github;
mod gitlab;
mod google_oauth;
mod grafana;
mod helicone;
mod heroku;
mod honeycomb;
mod inngest;
mod jwt;
mod keyword_gated_keys;
mod langfuse;
mod langsmith;
mod linear;
mod mailchimp;
mod mailgun;
mod microsoft_entra;
mod neon;
mod netlify;
mod new_relic;
mod notion;
mod nvidia;
mod okta;
mod onepassword;
mod openai;
mod otpauth;
mod paddle;
mod pattern;
mod pinecone;
mod polar;
mod posthog;
mod postman;
mod prefilter;
mod private_key;
mod resend;
mod rubygems;
mod ruleset_adapter;
mod runpod;
mod sendgrid;
mod sentry;
mod shopify;
mod slack;
mod sonarqube;
mod stripe;
mod telegram;
mod terraform;
mod text;
mod together_tavily;
mod travisci;
mod trigger_dev;
mod twilio;
mod vault;
mod vercel;
mod wandb;

use crate::types::Detector;
use connection_string::ConnectionStringDetector;
use private_key::PrivateKeyDetector;

use prefilter::Literals;
pub(crate) use prefilter::{PairSet, RequiredLiterals};

pub(crate) use aws::carries_aws_access_key_id;
pub(crate) use bearer_token::has_open_bearer_authorization;
pub(crate) use confluent::has_open_confluent_properties;
pub(crate) use generic_token::{
    RULESET_NAMES_DETECTOR_ID, generic_token_ruleset_names_detector,
    has_open_contextual_assignment, is_reserved_name, normalize_name,
};
pub(crate) use heroku::has_open_heroku_legacy_context;
pub(crate) use keyword_gated_keys::{has_open_deepgram_request, has_open_provider_sibling};
pub(crate) use private_key::PrivateKeyRetentionTracker;
pub(crate) use ruleset_adapter::RulesetDetector;
pub(crate) use text::has_open_list_item_pair;
pub(crate) use twilio::has_open_twilio_cli_table;

/// `true` when appending `appended` to any input leaves both
/// [`has_open_contextual_assignment`] and [`has_open_bearer_authorization`]
/// unchanged. Each first skips trailing [`text::is_js_whitespace`] and then
/// reads only what precedes it, so text made of nothing else is invisible to
/// them. The incremental session relies on this to re-evaluate the two tail
/// checks only when a line with other content closes (issue #986).
pub(crate) fn is_open_tail_neutral(appended: &str) -> bool {
    appended.chars().all(text::is_js_whitespace)
}

/// `true` when a detector can read `unit` (the scan copy of one closed
/// incremental unit) as the continuation of text on an earlier line, so
/// scanning it after that text can differ from scanning it alone. The
/// incremental session never batches such a unit with the units before it
/// (issue #985; the per-detector audit is in `docs/audits/evidence/985/`).
///
/// Two built-in grammars skip [`text::is_js_whitespace`], line terminators
/// included, between their parts:
///
/// - `generic-token`'s assignment grammar between a name and its `=`/`:`
///   operator (`parse_name_and_operator`), so a unit starting with an
///   operator can bind to a name on an earlier line;
/// - `bearer-token`'s header grammar around the `:` of `authorization:`
///   and before `bearer` (`match_scheme_at`), so a unit starting with `:` or
///   `bearer` can complete a header begun on an earlier line.
///
/// Since issue #990 their retention hints hold every such layout the
/// grammars accept in one unit (a backticked, glued or escaped quoted name,
/// a JWK member, `Proxy-Authorization:`), so a unit that closes behind one
/// no longer binds to it. The exclusion is kept as a guard: it costs a
/// batch split on rare lines, and it keeps each batch equal to per-unit
/// processing should a grammar and its hint drift apart again.
pub(crate) fn continues_previous_line(unit: &str) -> bool {
    let start = unit.trim_start_matches(text::is_js_whitespace);
    start.starts_with(['=', ':'])
        || start
            .get(..6)
            .is_some_and(|word| word.eq_ignore_ascii_case("bearer"))
}

/// Every built-in detector, in canonical registration order.
///
/// One entry per line by contract (`scripts/measure-detector-cost.mjs`
/// comments entries out by line), so the list outgrows the line lint.
#[must_use]
#[allow(clippy::too_many_lines)] // one line per built-in detector
pub(crate) fn built_in_detectors() -> Vec<Box<dyn Detector>> {
    vec![
        Box::new(PrivateKeyDetector),
        Box::new(aws::AwsAccessKeyDetector),
        Box::new(aws::AwsSecretAccessKeyDetector),
        Box::new(aws_bedrock::AwsBedrockLongTermApiKeyDetector),
        Box::new(aws_bedrock::AwsBedrockShortTermApiKeyDetector),
        Box::new(github::GitHubTokenDetector),
        Box::new(gitlab::GitlabTokenDetector),
        Box::new(openai::OpenAiTokenDetector),
        Box::new(anthropic::AnthropicTokenDetector),
        Box::new(shopify::ShopifyTokenDetector),
        Box::new(vault::VaultTokenDetector),
        Box::new(stripe::StripeTokenDetector),
        Box::new(slack::SlackTokenDetector),
        Box::new(additional_providers::PYPI),
        Box::new(additional_providers::HUGGING_FACE),
        Box::new(additional_providers::DOCKER),
        Box::new(cloudflare::CLOUDFLARE),
        Box::new(additional_providers::DIGITALOCEAN),
        Box::new(linear::LINEAR),
        Box::new(additional_providers::SUPABASE),
        Box::new(additional_providers::SUPABASE_PAT),
        Box::new(vercel::VERCEL),
        Box::new(additional_providers::NPM),
        Box::new(additional_providers::GOOGLE),
        Box::new(google_oauth::GOOGLE_OAUTH_CLIENT_SECRET),
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
        Box::new(datadog::DATADOG_APPLICATION_KEY),
        Box::new(datadog::DatadogApplicationKeyLegacyDetector),
        Box::new(grafana::GrafanaServiceAccountTokenDetector),
        Box::new(additional_providers::GRAFANA_CLOUD),
        Box::new(new_relic::NewRelicUserApiKeyDetector),
        Box::new(new_relic::NewRelicLicenseKeyDetector),
        Box::new(mailchimp::MailchimpMarketingApiKeyDetector),
        Box::new(mailgun::MailgunApiKeyDetector),
        Box::new(okta::OktaApiTokenDetector),
        Box::new(firebase::FirebaseServerKeyDetector),
        Box::new(terraform::TerraformCloudTokenDetector),
        Box::new(additional_providers::PULUMI),
        Box::new(ai_inference::REPLICATE),
        Box::new(ai_inference::GROQ),
        Box::new(ai_inference::XAI),
        Box::new(ai_inference::OPENROUTER),
        Box::new(ai_inference::PERPLEXITY),
        Box::new(ai_inference::FIREWORKS),
        Box::new(elevenlabs::ElevenLabsApiKeyDetector),
        Box::new(together_tavily::TOGETHER_AI),
        Box::new(together_tavily::TAVILY),
        Box::new(pinecone::PineconeApiKeyDetector),
        Box::new(gitlab::GitlabRunnerAuthenticationTokenDetector),
        Box::new(databricks::DATABRICKS),
        Box::new(confluent::CONFLUENT_CLOUD_API_SECRET),
        Box::new(confluent::ConfluentLegacyApiSecretDetector),
        Box::new(netlify::NetlifyPersonalAccessTokenDetector),
        Box::new(neon::NEON),
        Box::new(langsmith::LangsmithApiKeyDetector),
        Box::new(langfuse::LangfuseSecretKeyDetector),
        Box::new(postman::POSTMAN),
        Box::new(postman::POSTMAN_COLLECTION_ACCESS_KEY),
        Box::new(heroku::HEROKU_API_KEY),
        Box::new(heroku::HerokuApiKeyLegacyDetector),
        Box::new(travisci::TravisCiApiTokenDetector),
        Box::new(keyword_gated_keys::MistralApiKeyDetector),
        Box::new(keyword_gated_keys::CohereApiKeyDetector),
        Box::new(keyword_gated_keys::Ai21ApiKeyDetector),
        Box::new(keyword_gated_keys::DeepgramApiKeyDetector),
        Box::new(doppler::DopplerTokenDetector),
        Box::new(trigger_dev::TRIGGER_DEV),
        Box::new(e2b::E2B),
        Box::new(posthog::POSTHOG),
        Box::new(helicone::HELICONE),
        Box::new(firecrawl::FIRECRAWL),
        Box::new(composio::COMPOSIO),
        Box::new(convex::ConvexDeploymentKeyDetector),
        Box::new(onepassword::OnePasswordServiceAccountTokenDetector),
        Box::new(inngest::INNGEST_SIGNING_KEY),
        Box::new(resend::RESEND_API_KEY),
        Box::new(apify::APIFY_API_TOKEN),
        Box::new(wandb::WANDB_API_KEY),
        Box::new(daytona::DAYTONA_API_KEY),
        Box::new(clickhouse_cloud::CLICKHOUSE_CLOUD_API_SECRET),
        Box::new(nvidia::NVIDIA_API_KEY),
        Box::new(browserbase::BROWSERBASE_API_KEY),
        Box::new(runpod::RUNPOD_API_KEY),
        Box::new(cerebras::CEREBRAS_API_KEY),
        Box::new(bitwarden::BitwardenSecretsManagerAccessTokenDetector),
        Box::new(polar::POLAR),
        Box::new(sonarqube::SONARQUBE),
        Box::new(rubygems::RUBYGEMS_API_KEY),
        Box::new(clojars::CLOJARS_DEPLOY_TOKEN),
        Box::new(crates_io::CRATES_IO),
        Box::new(dynatrace::DynatraceTokenDetector),
        Box::new(paddle::PADDLE_API_KEY),
        Box::new(honeycomb::HONEYCOMB_INGEST_KEY),
        Box::new(axiom::AXIOM),
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

/// A built-in detector and the literals it declares for the shared
/// prefilter ([`prefilter`], issue #983).
///
/// Only [`built_in_entries`] and [`common_built_in_entries`] make one, from
/// the detectors this crate constructs, and the registry keeps the
/// declaration in a private field. It is never part of the public
/// `Detector` trait, so a custom detector neither declares nor inherits
/// one, even under a built-in id.
pub(crate) struct BuiltIn {
    pub(crate) detector: Box<dyn Detector>,
    pub(crate) required: Option<RequiredLiterals>,
}

/// [`built_in_detectors`], each with its prefilter declaration.
#[must_use]
pub(crate) fn built_in_entries() -> Vec<BuiltIn> {
    built_in_detectors()
        .into_iter()
        .map(|detector| BuiltIn {
            required: built_in_required_literals(detector.id()),
            detector,
        })
        .collect()
}

/// [`common_built_in_detectors`], each with its prefilter declaration.
#[must_use]
pub(crate) fn common_built_in_entries() -> Vec<BuiltIn> {
    common_built_in_detectors()
        .into_iter()
        .map(|detector| BuiltIn {
            required: common_required_literals(detector.id()),
            detector,
        })
        .collect()
}

/// The prefilter declarations of the declared `full` built-ins (issue
/// #983), keyed by detector id. Plain data, so the declarations add almost
/// no code to a WebAssembly build.
///
/// Every declared detector names its literals from its own grammar
/// constants: a table-driven detector's shape prefixes, or the module's
/// `REQUIRED_LITERALS`. The 17 built-ins that cannot declare a
/// case-sensitive literal every candidate needs are absent (pinned by
/// `prefilter::tests::only_the_reviewed_built_ins_run_on_every_call`).
const DECLARED_LITERALS: &[(&str, &[Literals])] = &[
    ("aws-access-key", aws::REQUIRED_LITERALS),
    ("aws-secret-access-key", aws::SECRET_REQUIRED_LITERALS),
    (
        "aws-bedrock-long-term-api-key",
        aws_bedrock::LONG_TERM_REQUIRED_LITERALS,
    ),
    (
        "aws-bedrock-short-term-api-key",
        aws_bedrock::SHORT_TERM_REQUIRED_LITERALS,
    ),
    ("github-token", github::REQUIRED_LITERALS),
    ("gitlab-token", gitlab::REQUIRED_LITERALS),
    ("openai-token", openai::REQUIRED_LITERALS),
    ("anthropic-token", anthropic::REQUIRED_LITERALS),
    ("shopify-token", shopify::REQUIRED_LITERALS),
    ("vault-token", vault::REQUIRED_LITERALS),
    ("stripe-token", stripe::REQUIRED_LITERALS),
    ("slack-token", slack::REQUIRED_LITERALS),
    ("sendgrid-token", sendgrid::REQUIRED_LITERALS),
    (
        "microsoft-entra-client-secret",
        microsoft_entra::REQUIRED_LITERALS,
    ),
    (
        "azure-devops-personal-access-token",
        azure_devops::REQUIRED_LITERALS,
    ),
    ("notion-token", notion::REQUIRED_LITERALS),
    ("atlassian-api-token", atlassian::REQUIRED_LITERALS),
    ("telegram-bot-token", telegram::REQUIRED_LITERALS),
    ("sentry-user-auth-token", sentry::USER_REQUIRED_LITERALS),
    ("sentry-org-auth-token", sentry::ORG_REQUIRED_LITERALS),
    ("grafana-service-account-token", grafana::REQUIRED_LITERALS),
    ("new-relic-user-api-key", new_relic::USER_REQUIRED_LITERALS),
    ("mailchimp-api-key", mailchimp::REQUIRED_LITERALS),
    ("mailgun-api-key", mailgun::REQUIRED_LITERALS),
    ("okta-api-token", okta::REQUIRED_LITERALS),
    ("firebase-server-key", firebase::REQUIRED_LITERALS),
    ("terraform-cloud-token", terraform::REQUIRED_LITERALS),
    ("elevenlabs-api-key", elevenlabs::REQUIRED_LITERALS),
    (
        "gitlab-runner-authentication-token",
        gitlab::RUNNER_REQUIRED_LITERALS,
    ),
    ("netlify-token", netlify::REQUIRED_LITERALS),
    ("langsmith-api-key", langsmith::REQUIRED_LITERALS),
    ("langfuse-secret-key", langfuse::REQUIRED_LITERALS),
    ("doppler-token", doppler::REQUIRED_LITERALS),
    (
        "onepassword-service-account-token",
        onepassword::REQUIRED_LITERALS,
    ),
    (
        additional_providers::PYPI.detector_id(),
        &[Literals::Shapes(additional_providers::PYPI.shapes())],
    ),
    (
        additional_providers::DOCKER.detector_id(),
        &[Literals::Shapes(additional_providers::DOCKER.shapes())],
    ),
    (
        cloudflare::CLOUDFLARE.detector_id(),
        &[Literals::Shapes(cloudflare::CLOUDFLARE.shapes())],
    ),
    (
        linear::LINEAR.detector_id(),
        &[Literals::Shapes(linear::LINEAR.shapes())],
    ),
    (
        additional_providers::SUPABASE.detector_id(),
        &[Literals::Shapes(additional_providers::SUPABASE.shapes())],
    ),
    (
        vercel::VERCEL.detector_id(),
        &[Literals::Shapes(vercel::VERCEL.shapes())],
    ),
    (
        additional_providers::NPM.detector_id(),
        &[Literals::Shapes(additional_providers::NPM.shapes())],
    ),
    (
        additional_providers::GOOGLE.detector_id(),
        &[Literals::Shapes(additional_providers::GOOGLE.shapes())],
    ),
    (
        google_oauth::GOOGLE_OAUTH_CLIENT_SECRET.detector_id(),
        &[Literals::Shapes(
            google_oauth::GOOGLE_OAUTH_CLIENT_SECRET.shapes(),
        )],
    ),
    (
        datadog::DATADOG_APPLICATION_KEY.detector_id(),
        &[Literals::Shapes(datadog::DATADOG_APPLICATION_KEY.shapes())],
    ),
    (
        additional_providers::PULUMI.detector_id(),
        &[Literals::Shapes(additional_providers::PULUMI.shapes())],
    ),
    (
        ai_inference::REPLICATE.detector_id(),
        &[Literals::Shapes(ai_inference::REPLICATE.shapes())],
    ),
    (
        ai_inference::GROQ.detector_id(),
        &[Literals::Shapes(ai_inference::GROQ.shapes())],
    ),
    (
        ai_inference::XAI.detector_id(),
        &[Literals::Shapes(ai_inference::XAI.shapes())],
    ),
    (
        ai_inference::OPENROUTER.detector_id(),
        &[Literals::Shapes(ai_inference::OPENROUTER.shapes())],
    ),
    (
        ai_inference::PERPLEXITY.detector_id(),
        &[Literals::Shapes(ai_inference::PERPLEXITY.shapes())],
    ),
    (
        ai_inference::FIREWORKS.detector_id(),
        &[Literals::Shapes(ai_inference::FIREWORKS.shapes())],
    ),
    (
        together_tavily::TOGETHER_AI.detector_id(),
        &[Literals::Shapes(together_tavily::TOGETHER_AI.shapes())],
    ),
    (
        together_tavily::TAVILY.detector_id(),
        &[Literals::Shapes(together_tavily::TAVILY.shapes())],
    ),
    (
        databricks::DATABRICKS.detector_id(),
        &[Literals::Shapes(databricks::DATABRICKS.shapes())],
    ),
    (
        neon::NEON.detector_id(),
        &[Literals::Shapes(neon::NEON.shapes())],
    ),
    (
        postman::POSTMAN.detector_id(),
        &[Literals::Shapes(postman::POSTMAN.shapes())],
    ),
    (
        heroku::HEROKU_API_KEY.detector_id(),
        &[Literals::Shapes(heroku::HEROKU_API_KEY.shapes())],
    ),
    (
        trigger_dev::TRIGGER_DEV.detector_id(),
        &[Literals::Shapes(trigger_dev::TRIGGER_DEV.shapes())],
    ),
    (
        e2b::E2B.detector_id(),
        &[Literals::Shapes(e2b::E2B.shapes())],
    ),
    (
        posthog::POSTHOG.detector_id(),
        &[Literals::Shapes(posthog::POSTHOG.shapes())],
    ),
    (
        helicone::HELICONE.detector_id(),
        &[Literals::Shapes(helicone::HELICONE.shapes())],
    ),
    (
        firecrawl::FIRECRAWL.detector_id(),
        &[Literals::Shapes(firecrawl::FIRECRAWL.shapes())],
    ),
    (
        composio::COMPOSIO.detector_id(),
        &[Literals::Shapes(composio::COMPOSIO.shapes())],
    ),
    (
        inngest::INNGEST_SIGNING_KEY.detector_id(),
        &[Literals::Shapes(inngest::INNGEST_SIGNING_KEY.shapes())],
    ),
    (
        resend::RESEND_API_KEY.detector_id(),
        &[Literals::Shapes(resend::RESEND_API_KEY.shapes())],
    ),
    (
        apify::APIFY_API_TOKEN.detector_id(),
        &[Literals::Shapes(apify::APIFY_API_TOKEN.shapes())],
    ),
    (
        wandb::WANDB_API_KEY.detector_id(),
        &[Literals::Shapes(wandb::WANDB_API_KEY.shapes())],
    ),
    (
        daytona::DAYTONA_API_KEY.detector_id(),
        &[Literals::Shapes(daytona::DAYTONA_API_KEY.shapes())],
    ),
    (
        clickhouse_cloud::CLICKHOUSE_CLOUD_API_SECRET.detector_id(),
        &[Literals::Shapes(
            clickhouse_cloud::CLICKHOUSE_CLOUD_API_SECRET.shapes(),
        )],
    ),
    (
        nvidia::NVIDIA_API_KEY.detector_id(),
        &[Literals::Shapes(nvidia::NVIDIA_API_KEY.shapes())],
    ),
    (
        browserbase::BROWSERBASE_API_KEY.detector_id(),
        &[Literals::Shapes(browserbase::BROWSERBASE_API_KEY.shapes())],
    ),
    (
        runpod::RUNPOD_API_KEY.detector_id(),
        &[Literals::Shapes(runpod::RUNPOD_API_KEY.shapes())],
    ),
    (
        cerebras::CEREBRAS_API_KEY.detector_id(),
        &[Literals::Shapes(cerebras::CEREBRAS_API_KEY.shapes())],
    ),
    (
        "bitwarden-secrets-manager-access-token",
        bitwarden::REQUIRED_LITERALS,
    ),
    ("polar-token", &[Literals::Shapes(polar::POLAR.shapes())]),
    (
        "sonarqube-token",
        &[Literals::Shapes(sonarqube::SONARQUBE.shapes())],
    ),
    (
        "rubygems-api-key",
        &[Literals::Shapes(rubygems::RUBYGEMS_API_KEY.shapes())],
    ),
    (
        "clojars-deploy-token",
        &[Literals::Shapes(clojars::CLOJARS_DEPLOY_TOKEN.shapes())],
    ),
    (
        crates_io::CRATES_IO.detector_id(),
        &[Literals::Shapes(crates_io::CRATES_IO.shapes())],
    ),
    (
        dynatrace::ID,
        &[Literals::Strs(dynatrace::REQUIRED_LITERALS)],
    ),
    (
        paddle::PADDLE_API_KEY.detector_id(),
        &[Literals::Shapes(paddle::PADDLE_API_KEY.shapes())],
    ),
    (
        honeycomb::HONEYCOMB_INGEST_KEY.detector_id(),
        &[Literals::Shapes(honeycomb::HONEYCOMB_INGEST_KEY.shapes())],
    ),
    (
        axiom::AXIOM.detector_id(),
        &[Literals::Shapes(axiom::AXIOM.shapes())],
    ),
    (
        additional_providers::HUGGING_FACE.detector_id(),
        &[Literals::Shapes(
            additional_providers::HUGGING_FACE.shapes(),
        )],
    ),
    (
        additional_providers::DIGITALOCEAN.detector_id(),
        &[Literals::Shapes(
            additional_providers::DIGITALOCEAN.shapes(),
        )],
    ),
    (
        additional_providers::SUPABASE_PAT.detector_id(),
        &[Literals::Shapes(
            additional_providers::SUPABASE_PAT.shapes(),
        )],
    ),
    (
        additional_providers::GRAFANA_CLOUD.detector_id(),
        &[Literals::Shapes(
            additional_providers::GRAFANA_CLOUD.shapes(),
        )],
    ),
    (
        confluent::CONFLUENT_CLOUD_API_SECRET.detector_id(),
        &[Literals::Shapes(
            confluent::CONFLUENT_CLOUD_API_SECRET.shapes(),
        )],
    ),
    (
        postman::POSTMAN_COLLECTION_ACCESS_KEY.detector_id(),
        &[Literals::Shapes(
            postman::POSTMAN_COLLECTION_ACCESS_KEY.shapes(),
        )],
    ),
];

/// The prefilter declaration of the built-in detector `id`, or `None` when
/// it runs on every call.
fn built_in_required_literals(id: &str) -> Option<RequiredLiterals> {
    DECLARED_LITERALS
        .iter()
        .find(|(declared, _)| *declared == id)
        .map_or_else(
            || common_required_literals(id),
            |(_, groups)| RequiredLiterals::any_of(groups),
        )
}

/// The prefilter declaration of the `common` built-in detector `id`, or
/// `None` when it runs on every call. Names only `common` modules, like
/// [`common_built_in_detectors`].
fn common_required_literals(id: &str) -> Option<RequiredLiterals> {
    match id {
        "private-key" => RequiredLiterals::any_of(private_key::REQUIRED_LITERALS),
        "jwt" => RequiredLiterals::any_of(jwt::REQUIRED_LITERALS),
        "connection-string" => RequiredLiterals::any_of(connection_string::REQUIRED_LITERALS),
        "otpauth-uri" => RequiredLiterals::any_of(otpauth::REQUIRED_LITERALS),
        _ => None,
    }
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
    ("aws-secret-access-key", Pack::Provider),
    ("aws-bedrock-long-term-api-key", Pack::Provider),
    ("aws-bedrock-short-term-api-key", Pack::Provider),
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
    ("google-oauth-client-secret", Pack::Provider),
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
    ("datadog-application-key-legacy", Pack::Provider),
    ("grafana-service-account-token", Pack::Provider),
    ("grafana-cloud-access-policy-token", Pack::Provider),
    ("new-relic-user-api-key", Pack::Provider),
    ("new-relic-license-key", Pack::Provider),
    ("mailchimp-api-key", Pack::Provider),
    ("mailgun-api-key", Pack::Provider),
    ("okta-api-token", Pack::Provider),
    ("firebase-server-key", Pack::Provider),
    ("terraform-cloud-token", Pack::Provider),
    ("pulumi-access-token", Pack::Provider),
    ("replicate-api-token", Pack::Provider),
    ("groq-api-key", Pack::Provider),
    ("xai-api-key", Pack::Provider),
    ("openrouter-api-key", Pack::Provider),
    ("perplexity-api-key", Pack::Provider),
    ("fireworks-ai-api-key", Pack::Provider),
    ("elevenlabs-api-key", Pack::Provider),
    ("together-ai-api-key", Pack::Provider),
    ("tavily-api-key", Pack::Provider),
    ("pinecone-api-key", Pack::Provider),
    ("gitlab-runner-authentication-token", Pack::Provider),
    ("databricks-personal-access-token", Pack::Provider),
    ("confluent-cloud-api-secret", Pack::Provider),
    ("confluent-cloud-api-secret-legacy", Pack::Provider),
    ("netlify-token", Pack::Provider),
    ("neon-api-key", Pack::Provider),
    ("langsmith-api-key", Pack::Provider),
    ("langfuse-secret-key", Pack::Provider),
    ("postman-api-key", Pack::Provider),
    ("postman-collection-access-key", Pack::Provider),
    ("heroku-api-key", Pack::Provider),
    ("heroku-api-key-legacy", Pack::Provider),
    ("travisci-api-token", Pack::Provider),
    ("mistral-api-key", Pack::Provider),
    ("cohere-api-key", Pack::Provider),
    ("ai21-api-key", Pack::Provider),
    ("deepgram-api-key", Pack::Provider),
    ("doppler-token", Pack::Provider),
    ("trigger-dev-token", Pack::Provider),
    ("e2b-api-key", Pack::Provider),
    ("posthog-token", Pack::Provider),
    ("helicone-api-key", Pack::Provider),
    ("firecrawl-api-key", Pack::Provider),
    ("composio-api-key", Pack::Provider),
    ("convex-deployment-key", Pack::Provider),
    ("onepassword-service-account-token", Pack::Provider),
    ("inngest-signing-key", Pack::Provider),
    ("resend-api-key", Pack::Provider),
    ("apify-api-token", Pack::Provider),
    ("wandb-api-key", Pack::Provider),
    ("daytona-api-key", Pack::Provider),
    ("clickhouse-cloud-api-secret", Pack::Provider),
    ("nvidia-api-key", Pack::Provider),
    ("browserbase-api-key", Pack::Provider),
    ("runpod-api-key", Pack::Provider),
    ("cerebras-api-key", Pack::Provider),
    ("bitwarden-secrets-manager-access-token", Pack::Provider),
    ("polar-token", Pack::Provider),
    ("sonarqube-token", Pack::Provider),
    ("rubygems-api-key", Pack::Provider),
    ("clojars-deploy-token", Pack::Provider),
    ("crates-io-token", Pack::Provider),
    ("dynatrace-token", Pack::Provider),
    ("paddle-api-key", Pack::Provider),
    ("honeycomb-api-key", Pack::Provider),
    ("axiom-token", Pack::Provider),
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
    #[allow(clippy::too_many_lines)]
    fn built_in_order_matches_the_typescript_oracle() {
        let detectors = built_in_detectors();
        let ids: Vec<&str> = detectors.iter().map(|d| d.id()).collect();
        assert_eq!(
            ids,
            vec![
                "private-key",
                "aws-access-key",
                "aws-secret-access-key",
                "aws-bedrock-long-term-api-key",
                "aws-bedrock-short-term-api-key",
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
                "google-oauth-client-secret",
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
                "datadog-application-key-legacy",
                "grafana-service-account-token",
                "grafana-cloud-access-policy-token",
                "new-relic-user-api-key",
                "new-relic-license-key",
                "mailchimp-api-key",
                "mailgun-api-key",
                "okta-api-token",
                "firebase-server-key",
                "terraform-cloud-token",
                "pulumi-access-token",
                "replicate-api-token",
                "groq-api-key",
                "xai-api-key",
                "openrouter-api-key",
                "perplexity-api-key",
                "fireworks-ai-api-key",
                "elevenlabs-api-key",
                "together-ai-api-key",
                "tavily-api-key",
                "pinecone-api-key",
                "gitlab-runner-authentication-token",
                "databricks-personal-access-token",
                "confluent-cloud-api-secret",
                "confluent-cloud-api-secret-legacy",
                "netlify-token",
                "neon-api-key",
                "langsmith-api-key",
                "langfuse-secret-key",
                "postman-api-key",
                "postman-collection-access-key",
                "heroku-api-key",
                "heroku-api-key-legacy",
                "travisci-api-token",
                "mistral-api-key",
                "cohere-api-key",
                "ai21-api-key",
                "deepgram-api-key",
                "doppler-token",
                "trigger-dev-token",
                "e2b-api-key",
                "posthog-token",
                "helicone-api-key",
                "firecrawl-api-key",
                "composio-api-key",
                "convex-deployment-key",
                "onepassword-service-account-token",
                "inngest-signing-key",
                "resend-api-key",
                "apify-api-token",
                "wandb-api-key",
                "daytona-api-key",
                "clickhouse-cloud-api-secret",
                "nvidia-api-key",
                "browserbase-api-key",
                "runpod-api-key",
                "cerebras-api-key",
                "bitwarden-secrets-manager-access-token",
                "polar-token",
                "sonarqube-token",
                "rubygems-api-key",
                "clojars-deploy-token",
                "crates-io-token",
                "dynatrace-token",
                "paddle-api-key",
                "honeycomb-api-key",
                "axiom-token",
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
        let confluent_legacy_input =
            "confluent SYNTHETIC0REVOKED0LegacyBareSecretValue0NoPrefix0ABCDEFGHIJKLMNO";
        let aws_bedrock_long_term_input = format!("ABSK{}", "U3ludGhldGljUmV2b2tlZA".repeat(6));
        let aws_bedrock_short_term_input = format!(
            "bedrock-api-key-{}{}",
            "YmVkcm9jay5hbWF6b25hd3MuY29tLz9BY3Rpb249Q2FsbFdpdGhCZWFyZXJUb2tlbiZYLUFtei1BbGdvcml0aG09QVdTNC1ITUFDLVNIQTI1NiZYLUFtei1DcmVkZW50aWFsP",
            "U3ludGhldGljUmV2b2tlZA".repeat(4)
        );
        let cases = [
            ("aws-access-key", "AKIASYNTHETICEXAMPLE"),
            (
                "aws-bedrock-long-term-api-key",
                aws_bedrock_long_term_input.as_str(),
            ),
            (
                "aws-bedrock-short-term-api-key",
                aws_bedrock_short_term_input.as_str(),
            ),
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
            (
                "supabase-token",
                "sb_secret_SYNTHETIC_REVOKED_SUPA_CHECKSUM",
            ),
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
            ("confluent-cloud-api-secret-legacy", confluent_legacy_input),
        ];
        assert_provider_candidates(&cases);
    }

    #[test]
    #[allow(clippy::too_many_lines)]
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
        let datadog_application_key_input = "ddapp_SYNTHETIC0REVOKED0AppKeyBody012345";
        let datadog_application_key_legacy_input =
            "DD_APPLICATION_KEY=0123456789abcdef0123456789abcdef01234567";
        let new_relic_user_api_key_input = "NRAK-SYNTHETICREVOKEDNEWRELICUSA";
        let new_relic_license_key_input = "newrelic 0123456789abcdef0123456789abcdef01234567";
        let mailchimp_api_key_input = "mailchimp 0123456789abcdef0123456789abcdef-us6";
        let mailgun_api_key_input = "mailgun key-abcdefghijklmnopqrstuvwxyz012345";
        let okta_api_token_input = format!(
            "Authorization: SSWS 00{}",
            &"SYNTHETICREVOKEDOKTAAPITOKENFIXTUREPADDING0123456789"[..40]
        );
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
        let databricks_personal_access_token_input =
            format!("dapi{}", "0123456789abcdef0123456789abcdef");
        let confluent_cloud_api_secret_input =
            "cfltSYNTHETIC0REVOKED0PrefixedSecretValue0ABCDEFGHIJKLMNOPn2NMow";
        let netlify_token_input = "nfp_SYNTHETIC_REVOKED_NETLIFY_PAT_BODY01";
        let neon_api_key_input = format!(
            "napi_{}",
            "SyntheticRevokedNeonApiKey0000Fixture1111Body2222Padding33334444"
        );
        let langsmith_api_key_input = "lsv2_pt_0123456789abcdef0123456789abcdef_fedcba9876";
        let langfuse_secret_key_input = "sk-lf-0a1b2c3d-4e5f-4a6b-8c7d-0e1f2a3b4c5d";
        let postman_api_key_input = format!(
            "PMAK-{}-{}",
            "0123456789abcdef01234567", "0123456789abcdef0123456789abcdef01"
        );
        let heroku_api_key_input = format!(
            "HRKU-AA{}",
            "SYNTHETIC0REVOKED0HerokuOAuthAccessTokenBodyFixture0123456"
        );
        let heroku_api_key_legacy_input = "heroku 01234567-89ab-cdef-0123-456789abcdef";
        let travisci_api_token_input = "travis Syn7hRevok3dTrvCi0Tok1";
        let mistral_api_key_input =
            format!("MISTRAL_API_KEY={}", "aB3dE5gH7jK9mN1pQ3sT5vW7yZ9xC2Lq");
        let cohere_api_key_input = format!(
            "co = cohere.ClientV2(api_key=\"{}\")",
            "zY9xW7vU5tS3rQ1pO9nM7lK5jI3hG1fEaB3dE5gH"
        );
        let ai21_api_key_input = format!(
            "AI21Client(api_key='{}')",
            "Zz9Yy8Xx7Ww6Vv5Uu4Tt3Ss2Rr1Qq0Pp"
        );
        let deepgram_api_key_input = format!(
            "DEEPGRAM_API_KEY={}",
            "q7w3e9r1t5y8u2i4o6p0a1s3d5f7g9h2j4k6l8z0"
        );
        let replicate_api_token_input = format!("r8_{}", "SYNTHETIC_REVOKED-REPLICATE-TOKEN-001");
        let groq_api_key_input = format!(
            "gsk_{}",
            "SYNTHETICREVOKEDGROQAPIKEYVALUE000000000000000000001"
        );
        let xai_api_key_input = format!("xai-{}", "0123456789".repeat(8));
        let openrouter_api_key_input = format!("sk-or-v1-{}", "0123456789abcdef".repeat(4));
        let perplexity_api_key_input = format!("pplx-{}", "0123456789".repeat(4) + "abcdefgh");
        let fireworks_ai_api_key_input = format!("fw_{}", "SyntheticRevokedFwKey1");
        let elevenlabs_api_key_input = format!("sk_{}", "0123456789abcdef".repeat(3));
        let together_ai_api_key_input =
            format!("tgp_v1_{}", "Synth-Revoked_Together0Fixture9Body-Zq7_Kd2");
        let tavily_api_key_input = format!("tvly-dev-{}", "SyntheticRevokedTavilyFixture014");
        let pinecone_api_key_input = format!(
            "pcsk_SynTh_{}",
            "0123456789abcdef".repeat(4)[..63].to_owned()
        );
        let gitlab_runner_input = "glrt-SyntheticRevokedRunnerPayloadA1.01.0v0xy8zct";
        let doppler_token_input =
            format!("dp.st.{}", "SyntheticRevokedDopplerServiceToken00000000");
        let trigger_dev_token_input = format!("tr_prod_sk_{}", "SyntheticRevokedTrigger0");
        let e2b_api_key_input = format!("e2b_{}", "0123456789abcdef0123456789abcdef01234567");
        let posthog_token_input = format!("phx_{}", "SyntheticRevokedPosthogPersonalKeyFixture01");
        let helicone_api_key_input = format!("sk-helicone-{}", "synthet-icrevok-edfixtr-helico1");
        let firecrawl_api_key_input = format!("fc-{}", "0123456789ab4def8123456789abcdef");
        let composio_api_key_input = format!("ak_{}", "Synthetic_Revoked-Ak");
        let crates_io_token_input = format!("cio{}", "SyntheticRevokedCratesIoToken000");
        let dynatrace_token_input = format!(
            "dt0c01.{}.{}",
            "SYNTHETICREVOKEDDYNATRCE",
            "SYNTHETICREVOKED".repeat(4)
        );
        let paddle_api_key_input = format!(
            "pdl_sdbx_apikey_{}_{}_{}",
            "syntheticrevokedpaddle0000", "SyntheticRevokedSecret", "X9z"
        );
        let honeycomb_api_key_input = format!(
            "hcxik_{}{}",
            "syntheticrevokedhoneycombingestkey", "0123456789abcdefghijklmn"
        );
        let axiom_token_input = format!("xaat-{}", "5e7c0ded-0000-4000-8000-deadbeef0001");
        let wandb_api_key_input = format!(
            "wandb_v1_{}",
            &"SyntheticRevokedWandbApiKeyFixture".repeat(3)[..77]
        );
        let apify_api_token_input = format!("apify_api_{}", "SyntheticRevokedApifyToken0000000000");
        let daytona_api_key_input = format!("dtn_{}", "5e7c0ded".repeat(8));
        let clickhouse_cloud_api_secret_input =
            format!("4b1d{}", "SyntheticRevokedClickhouseSecret000000");
        let nvidia_api_key_input = format!(
            "nvapi-{}End",
            "SyntheticRevokedNvidiaApiKeyFixture_".repeat(2)
        );
        let browserbase_api_key_input = format!("bb_live_{}", "SyntheticRevokedBrowserbaseKey0000");
        let runpod_api_key_input = format!("rpa_{}", "SyntheticRevokedRunpodApiKey00000000");
        let cerebras_api_key_input =
            format!("csk-{}", &"SyntheticRevokedCerebrasApiKey_".repeat(2)[..48]);
        let resend_api_key_input = format!("re_{}_{}", "Synth3ic", "RevokedResendFixtureKey0");
        let inngest_signing_key_input = format!("signkey-test-{}", "5e7c0ded".repeat(8));
        let onepassword_service_account_token_input =
            format!("ops_eyJ{}", "SyntheticRevokedOnePasswordFixture".repeat(8));
        let convex_deployment_key_input = format!("convex-self-hosted|01{}", "deadbeef".repeat(9));
        let bitwarden_secrets_manager_access_token_input = format!(
            "0.{}.{}:{}==",
            "5e7c0ded-0000-4000-8000-5e7c0ded0000",
            "SyntheticRevokedBitwardenSecre",
            "SyntheticRevokedKey000"
        );
        let polar_token_input = format!(
            "polar_oat_{}",
            "SyntheticRevokedPolarOrganizationToken00000"
        );
        let sonarqube_token_input = format!("squ_{}", "5e7c0ded".repeat(5));
        let rubygems_api_key_input = format!("rubygems_{}", "5e7c0ded".repeat(6));
        let clojars_deploy_token_input = format!("CLOJARS_{}5e7c", "5e7c0ded".repeat(7));
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
            (
                "datadog-application-key-legacy",
                datadog_application_key_legacy_input,
            ),
            ("grafana-service-account-token", grafana_sa_input),
            ("grafana-cloud-access-policy-token", grafana_cloud_input),
            ("new-relic-user-api-key", new_relic_user_api_key_input),
            ("new-relic-license-key", new_relic_license_key_input),
            ("mailchimp-api-key", mailchimp_api_key_input),
            ("mailgun-api-key", mailgun_api_key_input),
            ("okta-api-token", okta_api_token_input.as_str()),
            ("firebase-server-key", firebase_server_key_input.as_str()),
            (
                "terraform-cloud-token",
                terraform_cloud_token_input.as_str(),
            ),
            ("pulumi-access-token", pulumi_access_token_input.as_str()),
            ("replicate-api-token", replicate_api_token_input.as_str()),
            ("groq-api-key", groq_api_key_input.as_str()),
            ("xai-api-key", xai_api_key_input.as_str()),
            ("openrouter-api-key", openrouter_api_key_input.as_str()),
            ("perplexity-api-key", perplexity_api_key_input.as_str()),
            ("fireworks-ai-api-key", fireworks_ai_api_key_input.as_str()),
            ("elevenlabs-api-key", elevenlabs_api_key_input.as_str()),
            ("together-ai-api-key", together_ai_api_key_input.as_str()),
            ("tavily-api-key", tavily_api_key_input.as_str()),
            ("pinecone-api-key", pinecone_api_key_input.as_str()),
            ("gitlab-runner-authentication-token", gitlab_runner_input),
            (
                "databricks-personal-access-token",
                databricks_personal_access_token_input.as_str(),
            ),
            (
                "confluent-cloud-api-secret",
                confluent_cloud_api_secret_input,
            ),
            ("netlify-token", netlify_token_input),
            ("neon-api-key", neon_api_key_input.as_str()),
            ("langsmith-api-key", langsmith_api_key_input),
            ("langfuse-secret-key", langfuse_secret_key_input),
            ("postman-api-key", postman_api_key_input.as_str()),
            (
                "postman-collection-access-key",
                "PMAT-SynthRevoked0Postman0Pmat1",
            ),
            ("heroku-api-key", heroku_api_key_input.as_str()),
            ("heroku-api-key-legacy", heroku_api_key_legacy_input),
            ("travisci-api-token", travisci_api_token_input),
            ("mistral-api-key", mistral_api_key_input.as_str()),
            ("cohere-api-key", cohere_api_key_input.as_str()),
            ("ai21-api-key", ai21_api_key_input.as_str()),
            ("deepgram-api-key", deepgram_api_key_input.as_str()),
            ("doppler-token", doppler_token_input.as_str()),
            ("trigger-dev-token", trigger_dev_token_input.as_str()),
            ("e2b-api-key", e2b_api_key_input.as_str()),
            ("posthog-token", posthog_token_input.as_str()),
            ("helicone-api-key", helicone_api_key_input.as_str()),
            ("firecrawl-api-key", firecrawl_api_key_input.as_str()),
            ("composio-api-key", composio_api_key_input.as_str()),
            (
                "convex-deployment-key",
                convex_deployment_key_input.as_str(),
            ),
            (
                "onepassword-service-account-token",
                onepassword_service_account_token_input.as_str(),
            ),
            ("inngest-signing-key", inngest_signing_key_input.as_str()),
            ("resend-api-key", resend_api_key_input.as_str()),
            ("apify-api-token", apify_api_token_input.as_str()),
            ("wandb-api-key", wandb_api_key_input.as_str()),
            ("daytona-api-key", daytona_api_key_input.as_str()),
            (
                "clickhouse-cloud-api-secret",
                clickhouse_cloud_api_secret_input.as_str(),
            ),
            ("nvidia-api-key", nvidia_api_key_input.as_str()),
            ("browserbase-api-key", browserbase_api_key_input.as_str()),
            ("runpod-api-key", runpod_api_key_input.as_str()),
            ("cerebras-api-key", cerebras_api_key_input.as_str()),
            (
                "bitwarden-secrets-manager-access-token",
                bitwarden_secrets_manager_access_token_input.as_str(),
            ),
            ("polar-token", polar_token_input.as_str()),
            ("sonarqube-token", sonarqube_token_input.as_str()),
            ("rubygems-api-key", rubygems_api_key_input.as_str()),
            ("clojars-deploy-token", clojars_deploy_token_input.as_str()),
            ("crates-io-token", crates_io_token_input.as_str()),
            ("dynatrace-token", dynatrace_token_input.as_str()),
            ("paddle-api-key", paddle_api_key_input.as_str()),
            ("honeycomb-api-key", honeycomb_api_key_input.as_str()),
            ("axiom-token", axiom_token_input.as_str()),
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
