//! `PostHog` personal and project secret API key detection (issue #906,
//! handoff `docs/audits/evidence/860/posthog.md`).
//!
//! | Prefix | Finding type | Decision |
//! | --- | --- | --- |
//! | `phx_` | `posthog_personal_api_key` | detect |
//! | `phs_` | `posthog_project_secret_api_key` | detect: same generator and body |
//! | `phc_` | none | never claimed: the project token is public by design |
//!
//! Body: 42–49 bytes of `[0-9A-Za-z]`, no separator, no checksum. The band is
//! the union of every prefixed generator era, derived from provider code and
//! its unit tests (T1 under R1): base57 since 2026-03-30 (48 or 49 bytes),
//! 35-byte base62 before it (at most 48), and 32-byte base62 earlier still
//! (at most 43). The floor of 42 keeps the ≈1.6% of 32-byte-era keys that
//! render at 42; shorter renderings are under 0.03% of any era and are an
//! accepted false negative. The alphabet is the base62 union, not base57, so
//! older live keys stay claimed.
//!
//! OAuth `pha_`/`phr_` tokens are out of scope. Boundary `[A-Za-z0-9_-]`: a
//! 50+ byte run is rejected, never truncated.

use crate::detectors::additional_providers::TypedKnownFormatProviderDetector;
use crate::detectors::pattern::{self, PrefixShape};

/// Every accepted body width, longest first.
const BODY_LENS: [usize; 8] = [49, 48, 47, 46, 45, 44, 43, 42];

/// `[A-Za-z0-9_-]`: the boundary alphabet.
fn is_token_char(byte: u8) -> bool {
    pattern::is_alnum_dash(byte) || byte == b'_'
}

const SIGNALS: [&str; 2] = ["posthog-documented-prefix", "posthog-generator-length-band"];

pub(super) const POSTHOG: TypedKnownFormatProviderDetector = TypedKnownFormatProviderDetector::new(
    "posthog-token",
    &[
        PrefixShape::one_of("phx_", &BODY_LENS, pattern::is_alnum, &SIGNALS),
        PrefixShape::one_of("phs_", &BODY_LENS, pattern::is_alnum, &SIGNALS),
    ],
    &["posthog_personal_api_key", "posthog_project_secret_api_key"],
    is_token_char,
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ByteRange, Candidate, Confidence, Detector, DetectorContext, Specificity};

    const TYPES: [(&str, &str); 2] = [
        ("phx_", "posthog_personal_api_key"),
        ("phs_", "posthog_project_secret_api_key"),
    ];

    /// Synthetic filler, never provider-issued.
    fn body(len: usize, seed: usize) -> String {
        const ALNUM: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        (0..len)
            .map(|i| char::from(ALNUM[(i * 7 + seed * 13 + i / 5) % ALNUM.len()]))
            .collect()
    }

    fn detect(input: &str) -> Vec<Candidate> {
        POSTHOG
            .detect(input, &DetectorContext::new(input.len()))
            .unwrap()
    }

    fn contexts(token: &str) -> Vec<String> {
        vec![
            token.to_owned(),
            format!("POSTHOG_PERSONAL_API_KEY={token}"),
            format!("export POSTHOG_PERSONAL_API_KEY=\"{token}\""),
            format!(
                "curl -H \"Authorization: Bearer {token}\" https://app.posthog.com/api/projects/"
            ),
            format!("X-API-Key: {token}"),
            format!("{{\"token\": \"{token}\"}}"),
            format!("{{\"api_key\": \"{token}\"}}"),
            format!(
                "{{\"mcpServers\": {{\"posthog\": {{\"env\": {{\"POSTHOG_API_KEY\": \"{token}\"}}}}}}}}"
            ),
            format!("client = Posthog(personal_api_key=\"{token}\")"),
            format!("Here is my key {token} can you debug this?"),
            format!("The key is {token}."),
        ]
    }

    #[test]
    fn both_prefixes_are_detected_at_every_width_in_every_context() {
        for (prefix, type_name) in TYPES {
            for len in BODY_LENS {
                let token = format!("{prefix}{}", body(len, len));
                for input in contexts(&token) {
                    let candidates = detect(&input);
                    assert_eq!(candidates.len(), 1, "{input}");
                    let start = input.find(&token).unwrap();
                    assert_eq!(candidates[0].type_name(), type_name);
                    assert_eq!(candidates[0].confidence(), Confidence::High);
                    assert_eq!(candidates[0].effective_specificity(), Specificity::Provider);
                    assert_eq!(
                        candidates[0].range(),
                        ByteRange::new(start, start + token.len()).unwrap()
                    );
                }
            }
        }
        assert_eq!(POSTHOG.id(), "posthog-token");
    }

    #[test]
    fn width_alphabet_and_prefix_twins_are_rejected() {
        let value = body(47, 1);
        let mut twins = vec![
            format!("phx_{}", body(41, 1)),
            format!("phx_{}", body(50, 1)),
            format!("phs_{}", body(41, 1)),
            format!("phs_{}", body(50, 1)),
        ];
        for byte in ["_", "-", "."] {
            let mut dashed = value.clone();
            dashed.replace_range(20..21, byte);
            twins.push(format!("phx_{dashed}"));
        }
        for prefix in [
            "phx-", "PHX_", "ph_", "phy_", "Phx_", "phc_", "pha_", "phr_",
        ] {
            twins.push(format!("{prefix}{value}"));
        }
        for input in twins {
            assert!(detect(&input).is_empty(), "{input}");
        }
    }

    #[test]
    fn glued_values_are_rejected() {
        let token = format!("phx_{}", body(49, 2));
        for input in [
            format!("x{token}"),
            format!("_{token}"),
            format!("-{token}"),
            format!("{token}a"),
            format!("{token}_x"),
            format!("{token}-1"),
        ] {
            assert!(detect(&input).is_empty(), "{input}");
        }
    }

    #[test]
    fn project_tokens_placeholders_and_hosts_are_not_claimed() {
        for input in [
            format!("phc_{}", body(43, 3)),
            format!("phc_{}", body(44, 3)),
            format!(
                "posthog.init('phc_{}', {{ api_host: 'https://us.i.posthog.com' }})",
                body(44, 4)
            ),
            format!("<script>posthog.init(\"phc_{}\")</script>", body(43, 5)),
            "POSTHOG_PERSONAL_API_KEY=phx_...".to_owned(),
            "key: phx_***1234".to_owned(),
            "POSTHOG_API_KEY=${POSTHOG_API_KEY}".to_owned(),
            "POSTHOG_HOST=https://eu.posthog.com".to_owned(),
        ] {
            assert!(detect(&input).is_empty(), "{input}");
        }
    }

    #[test]
    fn repeated_values_are_reported_once_each_and_a_glued_run_never() {
        let token = format!("phx_{}", body(48, 6));
        assert_eq!(detect(&format!("{token} {token}")).len(), 2);
        assert!(detect(&token.repeat(200)).is_empty());
    }
}
