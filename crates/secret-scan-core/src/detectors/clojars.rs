//! Clojars deploy token detection (issue #1025, handoff
//! [`docs/audits/evidence/1014/clojars.md`](https://github.com/redact-secret/redact-secret/blob/2816897f96c405c3eb8c87a0c70eba5df273c121/docs/audits/evidence/1014/clojars.md)).
//!
//! The grammar is `CLOJARS_` + exactly 60 lowercase hex, all T1 under ruling
//! R1 from `clojars-web` (`src/clojars/db.clj`, re-checked 2026-09-29):
//! `generate-deploy-token` returns `(str "CLOJARS_" (hexadecimalize
//! (generate-secure-token 30)))`, `hexadecimalize` lowercases its output,
//! and the server's own shape check `is-deploy-token?` is
//! `#"^CLOJARS_[0-9a-f]{60}$"`.
//!
//! The prefix is case-sensitive. Environment names such as
//! `CLOJARS_USERNAME`, `CLOJARS_PASSWORD` and `CLOJARS_ENVIRONMENT`, legacy
//! account passwords and uppercase-hex bodies (the validator rejects them)
//! fail the grammar. Boundary `[A-Za-z0-9_-]`: a 59- or 61-byte body, an
//! uppercase or non-hex byte, a lowercase prefix and a glued value are
//! intentional false negatives.

use crate::detectors::additional_providers::KnownFormatProviderDetector;
use crate::detectors::pattern::{self, PrefixShape};

const BODY_LEN: usize = 60;
const SIGNALS: [&str; 2] = ["clojars-validator-shape", "clojars-generator-length"];

pub(super) const CLOJARS_DEPLOY_TOKEN: KnownFormatProviderDetector =
    KnownFormatProviderDetector::new(
        "clojars-deploy-token",
        "clojars_deploy_token",
        &[PrefixShape::exact(
            "CLOJARS_",
            BODY_LEN,
            pattern::is_lower_hex,
            &SIGNALS,
        )],
        pattern::is_alnum_dash,
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

    fn token() -> String {
        format!("CLOJARS_{}", hex(BODY_LEN, 1))
    }

    fn detect(input: &str) -> Vec<Candidate> {
        CLOJARS_DEPLOY_TOKEN
            .detect(input, &DetectorContext::new(input.len()))
            .unwrap()
    }

    #[test]
    fn the_validator_shape_is_detected_in_every_context() {
        let token = token();
        assert_eq!(token.len(), 68);
        for input in [
            token.clone(),
            format!("CLOJARS_PASSWORD={token}"),
            format!(
                "{{#\"https://repo.clojars.org\" {{:username \"alice\" :password \"{token}\"}}}}"
            ),
            format!("<password>{token}</password>"),
            format!("{{\"token\": \"{token}\"}}"),
            format!("Here is my token {token} can you debug this?"),
            format!("The token is {token}."),
        ] {
            let candidates = detect(&input);
            assert_eq!(candidates.len(), 1, "{input}");
            let start = input.find(&token).unwrap();
            assert_eq!(candidates[0].type_name(), "clojars_deploy_token");
            assert_eq!(candidates[0].confidence(), Confidence::High);
            assert_eq!(candidates[0].effective_specificity(), Specificity::Provider);
            assert_eq!(
                candidates[0].range(),
                ByteRange::new(start, start + token.len()).unwrap(),
                "{input}"
            );
        }
    }

    #[test]
    fn near_miss_twins_and_env_names_are_rejected() {
        let body = hex(BODY_LEN, 2);
        let token = format!("CLOJARS_{body}");
        let mut upper = body.clone();
        upper.replace_range(5..6, "A");
        let mut non_hex = body.clone();
        non_hex.replace_range(5..6, "g");
        for input in [
            format!("CLOJARS_{}", &body[..59]),
            format!("CLOJARS_{body}0"),
            format!("CLOJARS_{upper}"),
            format!("CLOJARS_{non_hex}"),
            format!("clojars_{body}"),
            format!("X{token}"),
            format!("_{token}"),
            format!("{token}_"),
            format!("{token}-x"),
            "CLOJARS_USERNAME=alice".to_owned(),
            "CLOJARS_PASSWORD=${CLOJARS_PASSWORD}".to_owned(),
            "CLOJARS_ENVIRONMENT=production".to_owned(),
        ] {
            assert!(detect(&input).is_empty(), "{input}");
        }
    }

    #[test]
    fn repeated_tokens_are_reported_once_each_and_a_glued_run_never() {
        let token = token();
        assert_eq!(detect(&format!("{token} {token}")).len(), 2);
        assert!(detect(&token.repeat(200)).is_empty());
    }
}
