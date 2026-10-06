//! Firecrawl API key detection (issue #908, handoff
//! [`docs/audits/evidence/860/firecrawl.md`](https://github.com/redact-secret/redact-secret/blob/2816897f96c405c3eb8c87a0c70eba5df273c121/docs/audits/evidence/860/firecrawl.md)).
//!
//! The grammar is `fc-` + exactly 32 lowercase hex forming a dashless UUID v4:
//! body byte 12 is `4` (the version nibble) and body byte 16 is one of
//! `8 9 a b` (the RFC variant). The prefix is T1 from the provider docs and
//! SDK/MCP code; the body is T1 under ruling R1 from provider server code
//! (the normalizer strips `fc-` and re-inserts the UUID dashes, the key column
//! is a Postgres random UUID v4, and the generator builds `fc-` + the dashless
//! UUID). Enforcing the version and variant nibbles rejects 63 of 64
//! arbitrary 32-hex strings, such as `fc-` + an MD5 digest, at no cost for
//! issued keys.
//!
//! Unclaimed: legacy bare dashed UUIDs (not attributable to Firecrawl), a
//! dashed UUID after `fc-`, another UUID version or variant, uppercase hex,
//! `fco_` OAuth tokens and `fcmcp_` MCP credentials. `fc-` is short, so the leading
//! boundary matters: `xfc-`, `_fc-` and CSS or calendar class names such as
//! `fc-daygrid-day` are glued or fail the body. Boundary `[A-Za-z0-9_-]`.

use crate::detectors::additional_providers::KnownFormatProviderDetector;
use crate::detectors::pattern::{self, PrefixShape};

const PREFIX: &str = "fc-";
const BODY_LEN: usize = 32;
const VERSION_OFFSET: usize = 12;
const VARIANT_OFFSET: usize = 16;

/// `[A-Za-z0-9_-]`: the boundary alphabet.
fn is_token_char(byte: u8) -> bool {
    pattern::is_alnum_dash(byte) || byte == b'_'
}

/// The body is a dashless UUID v4: version nibble `4`, variant `8`–`b`.
fn uuid_v4_nibbles(bytes: &[u8], _start: usize, end: usize) -> bool {
    let body = &bytes[end - BODY_LEN..end];
    body[VERSION_OFFSET] == b'4' && matches!(body[VARIANT_OFFSET], b'8' | b'9' | b'a' | b'b')
}

const SIGNALS: [&str; 2] = ["firecrawl-documented-prefix", "uuidv4-body"];

pub(super) const FIRECRAWL: KnownFormatProviderDetector = KnownFormatProviderDetector::new(
    "firecrawl-api-key",
    "firecrawl_api_key",
    &[
        PrefixShape::exact(PREFIX, BODY_LEN, pattern::is_lower_hex, &SIGNALS)
            .with_post_check(uuid_v4_nibbles),
    ],
    is_token_char,
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ByteRange, Candidate, Confidence, Detector, DetectorContext, Specificity};

    /// A synthetic dashless UUID v4, never provider-issued.
    const BODY: &str = "0123456789ab4def8123456789abcdef";
    const _: () = assert!(BODY.len() == BODY_LEN);

    fn key() -> String {
        format!("{PREFIX}{BODY}")
    }

    fn with_byte(offset: usize, byte: &str) -> String {
        let mut body = BODY.to_owned();
        body.replace_range(offset..=offset, byte);
        format!("{PREFIX}{body}")
    }

    fn detect(input: &str) -> Vec<Candidate> {
        FIRECRAWL
            .detect(input, &DetectorContext::new(input.len()))
            .unwrap()
    }

    #[test]
    fn detects_the_exact_shape_in_every_context() {
        let token = key();
        for input in [
            token.clone(),
            format!("FIRECRAWL_API_KEY={token}"),
            format!("export FIRECRAWL_API_KEY=\"{token}\""),
            format!(
                "curl -H \"Authorization: Bearer {token}\" https://api.firecrawl.dev/v1/scrape"
            ),
            format!("X-API-Key: {token}"),
            format!("{{\"token\": \"{token}\"}}"),
            format!("{{\"api_key\": \"{token}\"}}"),
            format!("app = FirecrawlApp(api_key=\"{token}\")"),
            format!("const fc = new Firecrawl({{ apiKey: '{token}' }});"),
            format!(
                "{{\"mcpServers\": {{\"firecrawl\": {{\"env\": {{\"FIRECRAWL_API_KEY\": \"{token}\"}}}}}}}}"
            ),
            format!("Here is my key {token} can you debug this?"),
            format!("The key is {token}."),
        ] {
            let candidates = detect(&input);
            assert_eq!(candidates.len(), 1, "{input}");
            let start = input.find(&token).unwrap();
            assert_eq!(candidates[0].type_name(), "firecrawl_api_key");
            assert_eq!(candidates[0].confidence(), Confidence::High);
            assert_eq!(candidates[0].effective_specificity(), Specificity::Provider);
            assert_eq!(
                candidates[0].range(),
                ByteRange::new(start, start + token.len()).unwrap()
            );
        }
        assert_eq!(FIRECRAWL.id(), "firecrawl-api-key");
    }

    #[test]
    fn every_rfc_variant_nibble_is_accepted() {
        for variant in ["8", "9", "a", "b"] {
            assert_eq!(detect(&with_byte(VARIANT_OFFSET, variant)).len(), 1);
        }
    }

    #[test]
    fn one_property_twins_are_rejected() {
        let mut twins = vec![
            format!("{PREFIX}{}", &BODY[..31]),
            format!("{PREFIX}{BODY}0"),
            format!("FC-{BODY}"),
            format!("fc_{BODY}"),
            format!("{PREFIX}01234567-89ab-4def-8123-456789abcdef"),
            format!("{PREFIX}{}", BODY.to_uppercase()),
            format!("x{}", key()),
            format!("_{}", key()),
            format!("-{}", key()),
            format!("{}a", key()),
            format!("{}_x", key()),
            format!("{}-1", key()),
        ];
        for version in ["1", "7", "0"] {
            twins.push(with_byte(VERSION_OFFSET, version));
        }
        for variant in ["c", "7"] {
            twins.push(with_byte(VARIANT_OFFSET, variant));
        }
        twins.push(with_byte(3, "A"));
        twins.push(with_byte(3, "g"));
        for input in twins {
            assert!(detect(&input).is_empty(), "{input}");
        }
    }

    #[test]
    fn placeholders_and_css_classes_are_not_claimed() {
        for input in [
            "FIRECRAWL_API_KEY=fc-YOUR-API-KEY",
            "FIRECRAWL_API_KEY=fc-your-api-key",
            "api_key=fc-test",
            "api_key=fc-xxx",
            "<div class=\"fc-event fc-daygrid-day\"></div>",
            "legacy key 01234567-89ab-4def-8123-456789abcdef",
            "fc-0123456789abcdef0123456789abcdef",
        ] {
            assert!(detect(input).is_empty(), "{input}");
        }
    }

    #[test]
    fn repeated_values_are_reported_once_each_and_a_glued_run_never() {
        let token = key();
        assert_eq!(detect(&format!("{token} {token}")).len(), 2);
        assert!(detect(&token.repeat(300)).is_empty());
    }
}
