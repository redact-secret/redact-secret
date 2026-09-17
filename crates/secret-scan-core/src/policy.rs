//! The default policy: maps finalized safe metadata to an [`Action`] without
//! inspecting the input or any matched value.

use crate::error::PolicyFailure;
use crate::types::{Action, Confidence, DetectedFinding, Policy, PolicyContext};

/// Finding types that are always redacted regardless of confidence, because
/// their format alone is specific enough to be actionable.
const ALWAYS_REDACT_TYPES: [&str; 32] = [
    "anthropic_api_key",
    "atlassian_api_token",
    "authorization_credential",
    "aws_access_key_id",
    "azure_devops_personal_access_token",
    "bearer_token",
    "cloudflare_api_token",
    "connection_string_password",
    "digitalocean_token",
    "discord_bot_token",
    "docker_token",
    "github_token",
    "gitlab_token",
    "google_api_key",
    "huggingface_token",
    "jwt",
    "linear_token",
    "microsoft_entra_client_secret",
    "new_relic_user_api_key",
    "notion_integration_token",
    "npm_access_token",
    "openai_api_key",
    "otpauth_secret",
    "pypi_api_token",
    "sendgrid_api_key",
    "shopify_access_token",
    "slack_token",
    "stripe_credential",
    "supabase_secret_key",
    "telegram_bot_token",
    "vault_token",
    "vercel_token",
];

/// Chooses the default action for `finding`.
///
/// - `private_key` always blocks.
/// - Every type in [`ALWAYS_REDACT_TYPES`] always redacts.
/// - Everything else redacts at [`Confidence::High`] and warns otherwise.
#[must_use]
fn default_action(finding: &DetectedFinding) -> Action {
    if finding.type_name() == "private_key" {
        return Action::Block;
    }
    if ALWAYS_REDACT_TYPES.contains(&finding.type_name()) {
        return Action::Redact;
    }
    if finding.confidence() == Confidence::High {
        Action::Redact
    } else {
        Action::Warn
    }
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
