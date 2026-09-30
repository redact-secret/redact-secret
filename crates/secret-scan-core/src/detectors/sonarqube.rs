//! `SonarQube` Server user and analysis token detection (issue #1021, handoff
//! `docs/audits/evidence/1014/sonarqube.md`).
//!
//! Every fact is T1 under ruling R1, from the provider's own server code
//! (`SonarSource/sonarqube`, re-checked 2026-09-29): `TokenGeneratorImpl`
//! builds `"sq"` + the token type identifier + `_` + `Hex.encodeHexString`
//! of 20 `SecureRandom` bytes (Commons Codec emits lowercase), and
//! `TokenType` names the identifiers `u` (user), `a` (global analysis), `b`
//! (project badge) and `p` (project analysis).
//!
//! | Prefix | Body | Finding type |
//! | --- | --- | --- |
//! | `squ_` | exactly 40 `[0-9a-f]` | `sonarqube_user_token` |
//! | `sqa_`, `sqp_` | exactly 40 `[0-9a-f]` | `sonarqube_analysis_token` |
//!
//! A user token acts as the user, including administration; the two
//! analysis tokens submit analysis for any project or for one, so they share
//! a type.
//!
//! `sqb_` project badge tokens are read-only and published in README badge
//! URLs by design (ruling Q5), so they are never claimed. Without the prefix
//! the body is SHA-1 shaped, so unprefixed legacy tokens (before `SonarQube`
//! 9.5) stay with generic context. `SonarQube` Cloud `sqco_` tokens are another
//! product. Boundary `[A-Za-z0-9_-]`: an uppercase or non-hex byte, a 39- or
//! 41-byte body, an unknown type letter, an uppercase prefix and a glued
//! value are intentional false negatives, never a truncated match.

use crate::detectors::additional_providers::TypedKnownFormatProviderDetector;
use crate::detectors::pattern::{self, PrefixShape};

const BODY_LEN: usize = 40;
const SIGNALS: [&str; 2] = ["sonarqube-generator-prefix", "sonarqube-generator-length"];
const USER: &str = "sonarqube_user_token";
const ANALYSIS: &str = "sonarqube_analysis_token";

pub(super) const SONARQUBE: TypedKnownFormatProviderDetector =
    TypedKnownFormatProviderDetector::new(
        "sonarqube-token",
        &[
            PrefixShape::exact("squ_", BODY_LEN, pattern::is_lower_hex, &SIGNALS),
            PrefixShape::exact("sqa_", BODY_LEN, pattern::is_lower_hex, &SIGNALS),
            PrefixShape::exact("sqp_", BODY_LEN, pattern::is_lower_hex, &SIGNALS),
        ],
        &[USER, ANALYSIS, ANALYSIS],
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

    fn detect(input: &str) -> Vec<Candidate> {
        SONARQUBE
            .detect(input, &DetectorContext::new(input.len()))
            .unwrap()
    }

    fn assert_single(input: &str, token: &str, type_name: &str) {
        let candidates = detect(input);
        assert_eq!(candidates.len(), 1, "{input}");
        let start = input.find(token).unwrap();
        assert_eq!(candidates[0].type_name(), type_name, "{input}");
        assert_eq!(candidates[0].confidence(), Confidence::High);
        assert_eq!(candidates[0].effective_specificity(), Specificity::Provider);
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(start, start + token.len()).unwrap(),
            "{input}"
        );
    }

    #[test]
    fn every_type_is_detected_in_every_context() {
        for (prefix, type_name) in [("squ_", USER), ("sqa_", ANALYSIS), ("sqp_", ANALYSIS)] {
            let token = format!("{prefix}{}", hex(BODY_LEN, prefix.len()));
            assert_eq!(token.len(), 44);
            for input in [
                token.clone(),
                format!("SONAR_TOKEN={token}"),
                format!("sonar-scanner -Dsonar.token={token}"),
                format!("sonar-scanner -Dsonar.login={token}"),
                format!("systemProp.sonar.token={token}"),
                format!("{{\"token\": \"{token}\"}}"),
                format!("Here is my token {token} can you debug this?"),
                format!("The token is {token}."),
            ] {
                assert_single(&input, &token, type_name);
            }
        }
    }

    #[test]
    fn near_miss_twins_are_rejected() {
        let body = hex(BODY_LEN, 1);
        let token = format!("squ_{body}");
        let mut upper = body.clone();
        upper.replace_range(3..4, "A");
        let mut non_hex = body.clone();
        non_hex.replace_range(3..4, "g");
        for input in [
            format!("squ_{}", &body[..39]),
            format!("squ_{body}0"),
            format!("squ_{upper}"),
            format!("squ_{non_hex}"),
            format!("sqx_{body}"),
            format!("SQU_{body}"),
            format!("x{token}"),
            format!("_{token}"),
            format!("{token}_"),
            format!("{token}-1"),
        ] {
            assert!(detect(&input).is_empty(), "{input}");
        }
    }

    #[test]
    fn badge_tokens_and_bare_shas_are_not_claimed() {
        let body = hex(BODY_LEN, 2);
        for input in [
            format!(
                "![Quality Gate](https://sonar.example.invalid/api/project_badges/measure?project=app&metric=alert_status&token=sqb_{body})"
            ),
            format!("commit {body}"),
            format!("sqco_{body}"),
            "SONAR_TOKEN=${{ secrets.SONAR_TOKEN }}".to_owned(),
            "SONAR_TOKEN=squ_xxxxxxxx".to_owned(),
        ] {
            assert!(detect(&input).is_empty(), "{input}");
        }
    }

    #[test]
    fn repeated_tokens_are_reported_once_each_and_a_glued_run_never() {
        let token = format!("sqa_{}", hex(BODY_LEN, 3));
        assert_eq!(detect(&format!("{token} {token}")).len(), 2);
        assert!(detect(&token.repeat(200)).is_empty());
    }
}
