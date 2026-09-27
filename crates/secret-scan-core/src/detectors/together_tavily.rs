//! Together AI and Tavily API key detection (issue #867, research #783/#786).
//!
//! Both families are one fixed prefix plus an exact-length run on the shared
//! [`KnownFormatProviderDetector`]: deterministic, offline, no context state.
//! Only what the research evidences is encoded.
//!
//! | Family | Shape | Tier |
//! | --- | --- | --- |
//! | `together-ai:api-key` | `tgp_v1_` + 43 from `[A-Za-z0-9_-]` (50 total) | T2 empirical |
//! | `tavily:api-key` | `tvly-` + optional `dev-` + 32 from `[A-Za-z0-9]` | prefix T1, body T2 |
//!
//! Together publishes no prefix, length or alphabet; the grammar comes from
//! one scanner rule (betterleaks), one community post and four code-search
//! samples, so it is T2 pending hands-on issuance. Legacy Together keys (format
//! undocumented), any `tgp_v2_` version and other body widths stay unclaimed.
//!
//! Tavily documents the `tvly-` prefix and shows `tvly-dev-` sample keys; the
//! 32-character alphanumeric body rests on one scanner rule (noseyparker) and
//! three observed samples. `tvly-prod-` is not evidenced and is not claimed;
//! a `tvly-dev-` key does not also match the bare `tvly-` shape because `-`
//! is outside the Tavily body alphabet. Placeholders (`tvly-YOUR_API_KEY`,
//! `tvly-dev-xxxx...`) never reach the exact width.
//!
//! Boundary: the whole value must not be a slice of a longer
//! `[A-Za-z0-9_-]` run, so an embedded or over-long value is an intentional
//! false negative. Each candidate is `Specificity::Provider` at high
//! confidence, so it wins overlaps against generic, bearer and vendor-prefix
//! policy findings.

use crate::detectors::additional_providers::KnownFormatProviderDetector;
use crate::detectors::pattern::{self, PrefixShape};

const TOGETHER_BODY_LEN: usize = 43;
const TAVILY_BODY_LEN: usize = 32;

/// `[A-Za-z0-9_-]`: the Together body alphabet and the boundary alphabet.
fn is_token_char(byte: u8) -> bool {
    pattern::is_alnum_dash(byte) || byte == b'_'
}

const TOGETHER_SIGNALS: [&str; 2] = [
    "together-ai-tool-corroborated-prefix",
    "exact-length-suffix",
];
const TAVILY_SIGNALS: [&str; 2] = ["tavily-documented-prefix", "observed-length-suffix"];

pub(super) const TOGETHER_AI: KnownFormatProviderDetector = KnownFormatProviderDetector::new(
    "together-ai-api-key",
    "together_ai_api_key",
    &[PrefixShape::exact(
        "tgp_v1_",
        TOGETHER_BODY_LEN,
        is_token_char,
        &TOGETHER_SIGNALS,
    )],
    is_token_char,
);

pub(super) const TAVILY: KnownFormatProviderDetector = KnownFormatProviderDetector::new(
    "tavily-api-key",
    "tavily_api_key",
    &[
        PrefixShape::exact(
            "tvly-dev-",
            TAVILY_BODY_LEN,
            pattern::is_alnum,
            &TAVILY_SIGNALS,
        ),
        PrefixShape::exact("tvly-", TAVILY_BODY_LEN, pattern::is_alnum, &TAVILY_SIGNALS),
    ],
    is_token_char,
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ByteRange, Candidate, Confidence, Detector, DetectorContext, Specificity};

    // Independently authored synthetic bodies, never provider-issued.
    const TOGETHER_BODY: &str = "Synth-Revoked_Together0Fixture9Body-Zq7_Kd2";
    const _: () = assert!(TOGETHER_BODY.len() == TOGETHER_BODY_LEN);
    const TAVILY_BODY: &str = "SyntheticRevokedTavilyFixture014";
    const _: () = assert!(TAVILY_BODY.len() == TAVILY_BODY_LEN);

    fn detect(detector: &KnownFormatProviderDetector, input: &str) -> Vec<Candidate> {
        detector
            .detect(input, &DetectorContext::new(input.len()))
            .unwrap()
    }

    fn together() -> String {
        format!("tgp_v1_{TOGETHER_BODY}")
    }

    fn tavily_dev() -> String {
        format!("tvly-dev-{TAVILY_BODY}")
    }

    fn tavily_bare() -> String {
        format!("tvly-{TAVILY_BODY}")
    }

    fn assert_single(
        detector: &KnownFormatProviderDetector,
        type_name: &str,
        input: &str,
        token: &str,
    ) {
        let candidates = detect(detector, input);
        assert_eq!(candidates.len(), 1, "{input}");
        let start = input.find(token).unwrap();
        assert_eq!(candidates[0].type_name(), type_name);
        assert_eq!(candidates[0].confidence(), Confidence::High);
        assert_eq!(candidates[0].effective_specificity(), Specificity::Provider);
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(start, start + token.len()).unwrap()
        );
    }

    fn contexts(token: &str) -> Vec<String> {
        vec![
            token.to_owned(),
            format!("2026-09-27 INFO using key {token} for request"),
            format!("API_KEY={token}"),
            format!("export API_KEY=\"{token}\""),
            format!("api_key: {token}"),
            format!("api_key: '{token}'"),
            format!("{{\"api_key\": \"{token}\"}}"),
            format!("{{\"env\": {{\"KEY\": \"{token}\"}}}}"),
            format!("client = Client(api_key=\"{token}\")"),
            format!("const c = new Client({{ apiKey: '{token}' }});"),
            format!("Authorization: Bearer {token}"),
            format!("curl -H \"Authorization: Bearer {token}\" https://example.invalid"),
            format!("{{\"name\": \"search\", \"arguments\": {{\"api_key\": \"{token}\"}}}}"),
            format!("https://example.invalid/mcp?key={token}&x=1"),
            format!("{token}\n"),
        ]
    }

    #[test]
    fn together_detects_the_exact_shape_in_every_context() {
        let token = together();
        for input in contexts(&token) {
            assert_single(&TOGETHER_AI, "together_ai_api_key", &input, &token);
        }
        assert_eq!(TOGETHER_AI.id(), "together-ai-api-key");
    }

    #[test]
    fn tavily_detects_both_prefix_forms_in_every_context() {
        for token in [tavily_dev(), tavily_bare()] {
            for input in contexts(&token) {
                assert_single(&TAVILY, "tavily_api_key", &input, &token);
            }
        }
        assert_eq!(TAVILY.id(), "tavily-api-key");
    }

    #[test]
    fn a_dev_key_yields_one_finding_covering_the_dev_segment() {
        let token = tavily_dev();
        let candidates = detect(&TAVILY, &token);
        assert_eq!(candidates.len(), 1);
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(0, token.len()).unwrap()
        );
    }

    #[test]
    fn together_admits_dash_and_underscore_in_the_body() {
        assert!(TOGETHER_BODY.contains('-') && TOGETHER_BODY.contains('_'));
        assert_eq!(detect(&TOGETHER_AI, &together()).len(), 1);
    }

    #[test]
    fn wrong_length_bodies_are_intentional_false_negatives() {
        for body in [
            TOGETHER_BODY[..42].to_owned(),
            format!("{TOGETHER_BODY}0"),
            TOGETHER_BODY[..31].to_owned(),
        ] {
            let input = format!("tgp_v1_{body}");
            assert!(detect(&TOGETHER_AI, &input).is_empty(), "{input}");
        }
        for body in [
            TAVILY_BODY[..31].to_owned(),
            format!("{TAVILY_BODY}0"),
            TAVILY_BODY[..16].to_owned(),
        ] {
            for prefix in ["tvly-", "tvly-dev-"] {
                let input = format!("{prefix}{body}");
                assert!(detect(&TAVILY, &input).is_empty(), "{input}");
            }
        }
    }

    #[test]
    fn wrong_alphabet_is_rejected() {
        for byte in ["+", "/", ".", "=", "~", " "] {
            let mut together_body = TOGETHER_BODY.to_owned();
            together_body.replace_range(10..11, byte);
            let input = format!("tgp_v1_{together_body}");
            assert!(detect(&TOGETHER_AI, &input).is_empty(), "{input}");
        }
        // Tavily bodies are alphanumeric: `-` and `_` inside the body are not.
        for byte in ["-", "_", "+", "."] {
            let mut body = TAVILY_BODY.to_owned();
            body.replace_range(10..11, byte);
            for prefix in ["tvly-", "tvly-dev-"] {
                let input = format!("{prefix}{body}");
                assert!(detect(&TAVILY, &input).is_empty(), "{input}");
            }
        }
    }

    #[test]
    fn embedded_or_glued_values_are_rejected() {
        for input in [
            format!("x{}", together()),
            format!("-{}", together()),
            format!("_{}", together()),
            format!("{}_backup", together()),
            format!("{}-1", together()),
            format!("{}A", together()),
        ] {
            assert!(detect(&TOGETHER_AI, &input).is_empty(), "{input}");
        }
        for token in [tavily_dev(), tavily_bare()] {
            for input in [
                format!("a{token}"),
                format!("-{token}"),
                format!("_{token}"),
                format!("{token}_backup"),
                format!("{token}-1"),
                format!("{token}A"),
            ] {
                assert!(detect(&TAVILY, &input).is_empty(), "{input}");
            }
        }
    }

    #[test]
    fn wrong_prefixes_are_rejected() {
        for prefix in ["tgp_v2_", "TGP_v1_", "tgp-v1-", "gp_v1_", "tgp_v1"] {
            let input = format!("{prefix}{TOGETHER_BODY}");
            assert!(detect(&TOGETHER_AI, &input).is_empty(), "{input}");
        }
        for prefix in [
            "tvly_",
            "TVLY-",
            "tvly-prod-",
            "tvly-Dev-",
            "vly-",
            "tvly-dev_",
        ] {
            let input = format!("{prefix}{TAVILY_BODY}");
            assert!(detect(&TAVILY, &input).is_empty(), "{input}");
        }
    }

    #[test]
    fn the_families_do_not_claim_each_others_values() {
        assert!(detect(&TAVILY, &together()).is_empty());
        assert!(detect(&TOGETHER_AI, &tavily_dev()).is_empty());
        assert!(detect(&TOGETHER_AI, &tavily_bare()).is_empty());
    }

    #[test]
    fn placeholders_and_public_lookalikes_are_not_claimed() {
        for input in [
            "TOGETHER_API_KEY=tgp_v1_your_api_key_here",
            "TOGETHER_API_KEY=tgp_v1_...",
            "TOGETHER_API_KEY=tgp_v1_********************************************",
            "key looks like tgp_v1_ followed by the secret",
            "TOGETHER_BASE_URL=https://api.together.xyz/v1",
            "model: meta-llama/Llama-3.3-70B-Instruct-Turbo",
            "TAVILY_API_KEY=tvly-YOUR_API_KEY",
            "Authorization: Bearer tvly-YOUR_API_KEY",
            "TAVILY_API_KEY=tvly-dev-xxxxxxxxxxxxxxxxxxxxxxxx",
            "TAVILY_API_KEY=tvly-...",
            "$ tvly search \"query\"",
            "TAVILY_API_KEY=tvly-dev-********************************",
            "key name: development-never-#1",
        ] {
            assert!(detect(&TOGETHER_AI, input).is_empty(), "{input}");
            assert!(detect(&TAVILY, input).is_empty(), "{input}");
        }
    }

    #[test]
    fn an_exact_width_placeholder_is_a_known_false_positive() {
        // No length-preserving placeholder exclusion is evidenced, so a
        // placeholder padded to the exact width is claimed (spec trade-off).
        let input = format!("TAVILY_API_KEY=tvly-dev-{}", "x".repeat(TAVILY_BODY_LEN));
        assert_eq!(detect(&TAVILY, &input).len(), 1);
    }

    #[test]
    fn a_repeated_value_is_reported_once_per_occurrence() {
        let token = tavily_dev();
        assert_eq!(detect(&TAVILY, &format!("{token} {token}")).len(), 2);
        let token = together();
        assert_eq!(detect(&TOGETHER_AI, &format!("{token} {token}")).len(), 2);
    }
}
