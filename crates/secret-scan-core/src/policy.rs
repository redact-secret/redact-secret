//! The default policy: maps finalized safe metadata to an [`Action`] without
//! inspecting the input or any matched value.

use crate::error::PolicyFailure;
use crate::types::{Action, Confidence, DetectedFinding, Policy, PolicyContext};

/// Finding types that are always redacted regardless of confidence, because
/// their format alone is specific enough to be actionable.
///
/// Not every [`Specificity::Provider`](crate::types::Specificity) type is
/// here: `twilio_auth_token`, `twilio_api_key_secret`, `datadog_api_key`,
/// `datadog_application_key`, `new_relic_license_key`,
/// `confluent_cloud_api_secret_legacy`, and `heroku_api_key_legacy` are
/// deliberately left confidence-gated (redact at [`Confidence::High`], warn
/// otherwise) even though that is a weaker action than their specificity
/// alone would suggest — each has a documented `decision-freeze-*` grammar
/// record (or, for `confluent_cloud_api_secret_legacy` and
/// `heroku_api_key_legacy`, its own module doc in `detectors::confluent` or
/// `detectors::heroku`) explaining why a bare keyword-cooccurrence match at
/// medium confidence is too weak (an opaque bare value sharing a line with a
/// vendor keyword) to redact by default; each of those legacy types only
/// ever reports [`Confidence::Medium`], so it always warns rather than
/// redacts under this default policy. Overlap resolution's resolved-action
/// severity ranking
/// (`decision-resolve-overlap-precedence-by-resolved-action-severity`)
/// exists precisely so this list does not have to be exhaustive over every
/// `Provider`/`Structural`/`PrivateKey` type for overlap resolution to stay
/// correct: a confidence-gated type here can still lose an overlap to a
/// stricter-resolving lower-specificity candidate, without needing to be
/// added to this list.
const ALWAYS_REDACT_TYPES: [&str; 51] = [
    "anthropic_api_key",
    "atlassian_api_token",
    "authorization_credential",
    "aws_access_key_id",
    "azure_devops_personal_access_token",
    "bearer_token",
    "cloudflare_api_token",
    "confluent_cloud_api_secret",
    "connection_string_password",
    "databricks_personal_access_token",
    "digitalocean_token",
    "discord_bot_token",
    "docker_token",
    "firebase_server_key",
    "github_app_installation_token",
    "github_app_refresh_token",
    "github_app_user_to_server_token",
    "github_fine_grained_personal_access_token",
    "github_oauth_token",
    "github_token",
    "gitlab_token",
    "google_api_key",
    "grafana_cloud_access_policy_token",
    "grafana_service_account_token",
    "heroku_api_key",
    "huggingface_token",
    "jwt",
    "linear_token",
    "microsoft_entra_client_secret",
    "netlify_personal_access_token",
    "new_relic_user_api_key",
    "notion_integration_token",
    "npm_access_token",
    "openai_api_key",
    "otpauth_secret",
    "postman_api_key",
    "pulumi_access_token",
    "pypi_api_token",
    "sendgrid_api_key",
    "sentry_org_auth_token",
    "sentry_user_auth_token",
    "shopify_access_token",
    "slack_token",
    "stripe_credential",
    "supabase_personal_access_token",
    "supabase_secret_key",
    "telegram_bot_token",
    "terraform_cloud_token",
    "vault_token",
    "vendor_prefixed_credential",
    "vercel_token",
];

/// Chooses the default action for a candidate identified only by `type_name`
/// and `confidence` — the metadata overlap resolution already holds before a
/// [`DetectedFinding`] exists. [`default_action`] is this crate's only other
/// caller; `crate::pipeline` calls this directly so ranking never has to
/// fabricate a placeholder finding just to read a resolved action back out
/// of one.
///
/// - `private_key` always blocks.
/// - Every type in [`ALWAYS_REDACT_TYPES`] always redacts.
/// - Everything else redacts at [`Confidence::High`] and warns otherwise.
#[must_use]
pub(crate) fn default_action_for(type_name: &str, confidence: Confidence) -> Action {
    if type_name == "private_key" {
        return Action::Block;
    }
    if ALWAYS_REDACT_TYPES.contains(&type_name) {
        return Action::Redact;
    }
    if confidence == Confidence::High {
        Action::Redact
    } else {
        Action::Warn
    }
}

/// Chooses the default action for `finding`. See [`default_action_for`].
#[must_use]
fn default_action(finding: &DetectedFinding) -> Action {
    default_action_for(finding.type_name(), finding.confidence())
}

/// The default [`Policy`]: deterministic, infallible, and independent of
/// [`PolicyContext`].
///
/// A private key is blocked, a known credential type is redacted at any
/// confidence, and anything else is redacted only at high confidence and
/// warned about otherwise. Because it ignores [`PolicyContext`], it is also
/// a valid [`IncrementalPolicy`](crate::IncrementalPolicy), which cannot
/// know the whole-session finding count.
///
/// # Examples
///
/// ```
/// use redact_secret::{Action, DefaultPolicy, DetectorRegistry, scan};
///
/// let registry = DetectorRegistry::with_built_in([])?;
/// let findings = scan("API_KEY=ghp_SYNTHETICREVOKED00000000000000000000", &registry, &DefaultPolicy)?;
/// assert_eq!(findings[0].action(), Action::Redact);
///
/// // Any `Fn(&DetectedFinding, &PolicyContext) -> Result<Action, _>` is a policy.
/// let block_all = |_: &redact_secret::DetectedFinding, _: &redact_secret::PolicyContext| {
///     Ok(Action::Block)
/// };
/// let findings = scan("API_KEY=ghp_SYNTHETICREVOKED00000000000000000000", &registry, &block_all)?;
/// assert_eq!(findings[0].action(), Action::Block);
/// # Ok::<(), redact_secret::SecretScanError>(())
/// ```
#[derive(Clone, Copy, Debug, Default)]
pub struct DefaultPolicy;

impl Policy for DefaultPolicy {
    fn evaluate(
        &self,
        finding: &DetectedFinding,
        _context: &PolicyContext,
    ) -> Result<Action, PolicyFailure> {
        Ok(default_action(finding))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ByteRange;

    fn finding(type_name: &str, confidence: Confidence) -> DetectedFinding {
        DetectedFinding::new(
            "finding-1",
            type_name,
            "fixture",
            confidence,
            ByteRange::new(0, 1).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn blocks_private_keys() {
        let context = PolicyContext::new(0, 1);
        let action = DefaultPolicy
            .evaluate(&finding("private_key", Confidence::Low), &context)
            .unwrap();
        assert_eq!(action, Action::Block);
    }

    #[test]
    fn always_redacts_known_types_at_any_confidence() {
        let context = PolicyContext::new(0, 1);
        for type_name in ALWAYS_REDACT_TYPES {
            let action = DefaultPolicy
                .evaluate(&finding(type_name, Confidence::Low), &context)
                .unwrap();
            assert_eq!(action, Action::Redact, "{type_name}");
        }
    }

    #[test]
    fn redacts_high_confidence_and_warns_otherwise() {
        let context = PolicyContext::new(0, 1);
        assert_eq!(
            DefaultPolicy
                .evaluate(&finding("contextual-secret", Confidence::High), &context)
                .unwrap(),
            Action::Redact
        );
        assert_eq!(
            DefaultPolicy
                .evaluate(&finding("contextual-secret", Confidence::Medium), &context)
                .unwrap(),
            Action::Warn
        );
        assert_eq!(
            DefaultPolicy
                .evaluate(&finding("contextual-secret", Confidence::Low), &context)
                .unwrap(),
            Action::Warn
        );
    }

    #[test]
    fn is_independent_of_policy_context() {
        let finding = finding("contextual-secret", Confidence::High);
        assert_eq!(
            DefaultPolicy
                .evaluate(&finding, &PolicyContext::new(0, 5))
                .unwrap(),
            DefaultPolicy
                .evaluate(&finding, &PolicyContext::new(4, 5))
                .unwrap()
        );
    }
}
