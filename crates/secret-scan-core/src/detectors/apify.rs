//! Apify API token detection (issue #916, handoff
//! [`docs/audits/evidence/860/apify.md`](https://github.com/redact-secret/redact-secret/blob/2816897f96c405c3eb8c87a0c70eba5df273c121/docs/audits/evidence/860/apify.md)).
//!
//! The Apify docs placeholders are `apify_api_...` (ruling R4: a placeholder
//! is T1 for its prefix). The provider's own leak linter in
//! `apify/awesome-skills` (`scripts/lint_references.py`, authored by an
//! Apify organization collaborator, so T1 under ruling R2) is
//! `apify_api_[A-Za-z0-9]{20,}`. No provider source states an exact length,
//! so the contract uses the provider's open-ended rule rather than a
//! scanner's exact 36 (T2).
//!
//! | Part | Grammar | Tier |
//! | --- | --- | --- |
//! | Prefix | `apify_api_` | T1 (docs placeholder) |
//! | Body | at least 20 `[A-Za-z0-9]` | T1 (provider leak linter) |
//! | Upper bound | 128 | project policy: a bounded run for streaming |
//!
//! The body alphabet is narrower than the `[A-Za-z0-9_-]` boundary, so a
//! `_` or `-` glued after the run rejects the match: that is what keeps
//! `apify_api_token_here` and similar placeholders unclaimed. A body over
//! 128 bytes is rejected whole, never truncated. `apify_ui_` Console tokens
//! and the unprefixed sibling tokens have no stated shape and stay with
//! generic context; `apify` is therefore not added to `generic-token`'s
//! dedicated-provider deferral list.

use crate::detectors::additional_providers::KnownFormatProviderDetector;
use crate::detectors::pattern::{self, PrefixShape};

const PREFIX: &str = "apify_api_";
const BODY_MIN: usize = 20;
const BODY_MAX: usize = 128;
const SIGNALS: [&str; 2] = ["apify-documented-prefix", "apify-provider-lint-floor"];

/// The open-ended run is capped at [`BODY_MAX`].
fn within_body_cap(_bytes: &[u8], start: usize, end: usize) -> bool {
    end - start - PREFIX.len() <= BODY_MAX
}

pub(super) const APIFY_API_TOKEN: KnownFormatProviderDetector = KnownFormatProviderDetector::new(
    "apify-api-token",
    "apify_api_token",
    &[
        PrefixShape::at_least(PREFIX, BODY_MIN, pattern::is_alnum, &SIGNALS)
            .with_post_check(within_body_cap),
    ],
    pattern::is_alnum_dash,
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ByteRange, Candidate, Confidence, Detector, DetectorContext, Specificity};

    /// Synthetic alphanumeric filler, never provider-issued.
    fn body(len: usize, seed: usize) -> String {
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        (0..len)
            .map(|i| char::from(ALPHABET[(i * 7 + seed * 13 + i / 5) % ALPHABET.len()]))
            .collect()
    }

    fn token(len: usize) -> String {
        format!("{PREFIX}{}", body(len, len))
    }

    fn detect(input: &str) -> Vec<Candidate> {
        APIFY_API_TOKEN
            .detect(input, &DetectorContext::new(input.len()))
            .unwrap()
    }

    fn assert_single(input: &str, token: &str) {
        let candidates = detect(input);
        assert_eq!(candidates.len(), 1, "{input}");
        let start = input.find(token).unwrap();
        assert_eq!(candidates[0].type_name(), "apify_api_token");
        assert_eq!(candidates[0].confidence(), Confidence::High);
        assert_eq!(candidates[0].effective_specificity(), Specificity::Provider);
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(start, start + token.len()).unwrap(),
            "{input}"
        );
    }

    fn contexts(token: &str) -> Vec<String> {
        vec![
            token.to_owned(),
            format!("APIFY_TOKEN={token}"),
            format!("export APIFY_TOKEN=\"{token}\""),
            format!("Authorization: Bearer {token}"),
            format!("X-API-Key: {token}"),
            format!("{{\"token\": \"{token}\"}}"),
            format!("{{\"api_key\": \"{token}\"}}"),
            format!("const client = new ApifyClient({{ token: '{token}' }});"),
            format!("client = ApifyClient(\"{token}\")"),
            format!("Here is my key {token} can you debug this?"),
            format!("The token is {token}."),
        ]
    }

    #[test]
    fn tokens_are_detected_at_every_width_in_every_context() {
        for len in [BODY_MIN, 36, BODY_MAX] {
            let token = token(len);
            for input in contexts(&token) {
                assert_single(&input, &token);
            }
        }
        assert_eq!(APIFY_API_TOKEN.id(), "apify-api-token");
    }

    #[test]
    fn near_miss_twins_are_rejected() {
        let value = body(36, 1);
        for input in [
            token(BODY_MIN - 1),
            token(BODY_MAX + 1),
            format!("{PREFIX}{value}_x"),
            format!("{PREFIX}{value}-1"),
            format!("APIFY_API_{value}"),
            format!("apify-api-{value}"),
            format!("x{PREFIX}{value}"),
            format!("_{PREFIX}{value}"),
        ] {
            assert!(detect(&input).is_empty(), "{input}");
        }
    }

    #[test]
    fn benign_apify_text_is_not_claimed() {
        for input in [
            "APIFY_TOKEN=apify_api_YOUR_TOKEN",
            "token: apify_api_test_token",
            "token: apify_api_invalid_token",
            "token: apify_api_dummy_for_smoke",
            "APIFY_TOKEN=apify_api_...",
            "if err == apify_api_error {}",
            "APIFY_API_BASE_URL=https://api.apify.com",
            "APIFY_TOKEN=apify_ui_test",
            "APIFY_TOKEN=${{ secrets.APIFY_TOKEN }}",
            "the prefix is apify_api_",
            "token: apify_api_token_here_SyntheticRevoked0",
        ] {
            assert!(detect(input).is_empty(), "{input}");
        }
    }

    #[test]
    fn repeated_tokens_are_reported_once_each_and_a_glued_run_never() {
        let token = token(36);
        assert_eq!(detect(&format!("{token} {token}")).len(), 2);
        assert!(detect(&format!("{token}_{token}")).is_empty());
        assert!(detect(&PREFIX.repeat(20_000)).is_empty());
    }
}
