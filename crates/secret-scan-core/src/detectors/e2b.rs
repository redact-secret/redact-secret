//! E2B API key detection (issue #905, handoff
//! [`docs/audits/evidence/860/e2b.md`](https://github.com/redact-secret/redact-secret/blob/2816897f96c405c3eb8c87a0c70eba5df273c121/docs/audits/evidence/860/e2b.md)).
//!
//! The grammar is `e2b_` + exactly 40 lowercase hex, all T1 under ruling R1:
//! the provider's key package sets `ApiKeyPrefix = "e2b_"` and generates
//! `keyLength = 20` random bytes rendered with Go's `hex.EncodeToString`
//! (lowercase), and the local-dev seed test asserts `len(prefix) + 2*20`.
//! The docs name `E2B_API_KEY` and show `e2b_…` placeholders only.
//!
//! Without its prefix the 40-hex body is SHA-1 shaped, so the prefix is
//! load-bearing. The retired `sk_e2b_` user access token is never claimed:
//! the byte before `e2b_` inside it is `_`, which the leading boundary
//! rejects. An uppercase-hex body (accepted by the verifier but never
//! issued), package names such as `e2b_code_interpreter`, and placeholders
//! fail the exact 40-lowercase-hex body. Boundary `[A-Za-z0-9_-]`: an
//! embedded, over-long or glued value is an intentional false negative.

use crate::detectors::additional_providers::KnownFormatProviderDetector;
use crate::detectors::pattern::{self, PrefixShape};

const BODY_LEN: usize = 40;

/// `[A-Za-z0-9_-]`: the boundary alphabet.
fn is_token_char(byte: u8) -> bool {
    pattern::is_alnum_dash(byte) || byte == b'_'
}

const SIGNALS: [&str; 2] = ["e2b-documented-prefix", "e2b-generator-length"];

pub(super) const E2B: KnownFormatProviderDetector = KnownFormatProviderDetector::new(
    "e2b-api-key",
    "e2b_api_key",
    &[PrefixShape::exact(
        "e2b_",
        BODY_LEN,
        pattern::is_lower_hex,
        &SIGNALS,
    )],
    is_token_char,
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ByteRange, Candidate, Confidence, Detector, DetectorContext, Specificity};

    /// Synthetic lowercase-hex filler, never provider-issued.
    fn hex(len: usize, seed: usize) -> String {
        const HEX: &[u8] = b"0123456789abcdef";
        (0..len)
            .map(|i| char::from(HEX[(i * 7 + seed * 3 + i / 5) % HEX.len()]))
            .collect()
    }

    fn key() -> String {
        format!("e2b_{}", hex(BODY_LEN, 1))
    }

    fn detect(input: &str) -> Vec<Candidate> {
        E2B.detect(input, &DetectorContext::new(input.len()))
            .unwrap()
    }

    #[test]
    fn detects_the_exact_shape_in_every_context() {
        let token = key();
        for input in [
            token.clone(),
            format!("E2B_API_KEY={token}"),
            format!("export E2B_API_KEY=\"{token}\""),
            format!("Authorization: Bearer {token}"),
            format!("curl -H \"X-API-Key: {token}\" https://api.example.invalid/sandboxes"),
            format!("{{\"token\": \"{token}\"}}"),
            format!("{{\"api_key\": \"{token}\"}}"),
            format!("sbx = Sandbox.create(api_key=\"{token}\")"),
            format!("const sbx = await Sandbox.create({{ apiKey: '{token}' }});"),
            format!(
                "{{\"mcpServers\": {{\"e2b\": {{\"env\": {{\"E2B_API_KEY\": \"{token}\"}}}}}}}}"
            ),
            format!("Here is my key {token} can you debug this?"),
            format!("The key is {token}."),
        ] {
            let candidates = detect(&input);
            assert_eq!(candidates.len(), 1, "{input}");
            let start = input.find(&token).unwrap();
            assert_eq!(candidates[0].type_name(), "e2b_api_key");
            assert_eq!(candidates[0].confidence(), Confidence::High);
            assert_eq!(candidates[0].effective_specificity(), Specificity::Provider);
            assert_eq!(
                candidates[0].range(),
                ByteRange::new(start, start + token.len()).unwrap()
            );
        }
        assert_eq!(E2B.id(), "e2b-api-key");
    }

    #[test]
    fn one_property_twins_are_rejected() {
        let body = hex(BODY_LEN, 1);
        let mut twins = vec![
            format!("e2b_{}", &body[..39]),
            format!("e2b_{body}0"),
            format!("E2B_{body}"),
            format!("e2b-{body}"),
            format!("sk_e2b_{body}"),
            format!("xe2b_{body}"),
            format!("_e2b_{body}"),
            format!("e2b_{body}a"),
            format!("e2b_{body}_x"),
            format!("e2b_{}", body.to_uppercase()),
        ];
        for byte in ["A", "g", "-"] {
            let mut value = body.clone();
            value.replace_range(12..13, byte);
            twins.push(format!("e2b_{value}"));
        }
        for input in twins {
            assert!(detect(&input).is_empty(), "{input}");
        }
    }

    #[test]
    fn benign_e2b_text_is_not_claimed() {
        for input in [
            "from e2b_code_interpreter import Sandbox".to_owned(),
            "import e2b_desktop".to_owned(),
            "E2B_API_KEY=e2b_...".to_owned(),
            "E2B_API_KEY=e2b_***".to_owned(),
            "E2B_API_KEY=${E2B_API_KEY}".to_owned(),
            format!("commit {}", hex(BODY_LEN, 2)),
            format!("envd token {}", hex(64, 3)),
        ] {
            assert!(detect(&input).is_empty(), "{input}");
        }
    }

    #[test]
    fn repeated_values_are_reported_once_each_and_a_glued_run_never() {
        let token = key();
        assert_eq!(detect(&format!("{token} {token}")).len(), 2);
        assert!(detect(&token.repeat(250)).is_empty());
    }
}
