//! Sourcegraph personal access token detection (issue #1103, handoff
//! [`docs/audits/evidence/1014/sourcegraph.md`](https://github.com/redact-secret/redact-secret/blob/2816897f96c405c3eb8c87a0c70eba5df273c121/docs/audits/evidence/1014/sourcegraph.md)).
//!
//! A Sourcegraph access token (`SRC_ACCESS_TOKEN`, sent as
//! `Authorization: token`) acts as the user on a Sourcegraph instance. The
//! facts are T1 as of 2025-11-18 under rulings R1 and R9: the generator in
//! `sourcegraph-public-snapshot` (`internal/accesstoken`, 2024-05/2024-08)
//! emits `sgp_<instance-identifier>_<token>` with 20 random bytes as 40
//! hex, and the validator the maintained `src-cli` vendored on 2025-11-18 is
//! `^(?:(?:sgp_|sgph_)(?:[a-zA-Z0-9]+_)?)?([a-fA-F0-9]{40})$`.
//!
//! | Form | Grammar |
//! | --- | --- |
//! | Instance-bound | `sgp_` + `[A-Za-z0-9]+` (1 to 32) + `_` + exactly 40 hex |
//! | No identifier | `sgp_` + exactly 40 hex |
//!
//! The generator issues `local` or 16 hex as the identifier; the detector
//! claims the validator's wider alphanumeric identifier, capped at 32 bytes
//! (twice the issued width) so a long `sgp_<word>_` cannot consume a line.
//! The hex body accepts both cases, as the validator does.
//!
//! ## Exclusions
//!
//! A bare 40-hex legacy token is never claimed: it has no distinctive shape
//! and collides with git SHAs. `sgph_` (accepted by the validator, issuer
//! unknown) and `sgd_` + 64 hex (the Cody Gateway user key, one provider
//! source) are a later extension and stay unclaimed, as do `slk_`
//! license-key tokens and `sgp_`-plus-`x` help-text placeholders.
//!
//! ## Boundaries
//!
//! The run after `sgp_` is the maximal `[A-Za-z0-9_]` run and is rejected,
//! never truncated, unless it has exactly the grammar above. A byte of
//! `[A-Za-z0-9_-]` before `sgp_`, a `-` after the token, an identifier longer
//! than 32 bytes, an identifier with no closing `_`, and a body of 39 or 41
//! hex are intentional false negatives.

use crate::detectors::additional_providers::KnownFormatProviderDetector;
use crate::detectors::pattern::{self, PrefixShape};

const PREFIX: &str = "sgp_";
const TOKEN_LEN: usize = 40;
const INSTANCE_MAX: usize = 32;
const SIGNALS: [&str; 2] = [
    "sourcegraph-documented-prefix",
    "sourcegraph-validator-grammar",
];

/// Whether the maximal `[A-Za-z0-9_]` run after `sgp_` is `<token>` or
/// `<instance-identifier>_<token>`, with the token exactly 40 hex.
fn has_grammar(bytes: &[u8], start: usize, end: usize) -> bool {
    let body = &bytes[start + PREFIX.len()..end];
    let Some(head_len) = body.len().checked_sub(TOKEN_LEN) else {
        return false;
    };
    let (head, token) = body.split_at(head_len);
    if !token.iter().all(u8::is_ascii_hexdigit) {
        return false;
    }
    match head {
        [] => true,
        [identifier @ .., b'_'] => {
            !identifier.is_empty()
                && identifier.len() <= INSTANCE_MAX
                && identifier.iter().all(u8::is_ascii_alphanumeric)
        }
        _ => false,
    }
}

pub(super) const SOURCEGRAPH: KnownFormatProviderDetector = KnownFormatProviderDetector::new(
    "sourcegraph-token",
    "sourcegraph_access_token",
    &[
        PrefixShape::at_least(PREFIX, TOKEN_LEN, pattern::is_alnum_underscore, &SIGNALS)
            .with_post_check(has_grammar),
    ],
    pattern::is_alnum_dash,
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ByteRange, Candidate, Confidence, Detector, DetectorContext, Specificity};

    const HEX: &[u8] = b"0123456789abcdef";
    const ALNUM: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

    /// Synthetic filler, never provider-issued.
    fn filler(alphabet: &[u8], len: usize, seed: usize) -> String {
        (0..len)
            .map(|i| char::from(alphabet[(i * 7 + seed * 13 + i / 5) % alphabet.len()]))
            .collect()
    }

    fn hex(seed: usize) -> String {
        filler(HEX, TOKEN_LEN, seed)
    }

    fn detect(input: &str) -> Vec<Candidate> {
        SOURCEGRAPH
            .detect(input, &DetectorContext::new(input.len()))
            .unwrap()
    }

    fn assert_single(input: &str, token: &str) {
        let candidates = detect(input);
        assert_eq!(candidates.len(), 1, "{input}");
        let start = input.find(token).unwrap();
        assert_eq!(candidates[0].type_name(), "sourcegraph_access_token");
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
            format!("SRC_ACCESS_TOKEN={token}"),
            format!("export SRC_ACCESS_TOKEN=\"{token}\""),
            format!("Authorization: token {token}"),
            format!("{{\"token\": \"{token}\"}}"),
            format!("src login -endpoint https://sourcegraph.example.test -token {token}"),
            format!("Here is my token {token} can you debug this?"),
            format!("The token is {token}."),
            format!("\u{d0a4}\u{1f511} 키: {token}"),
        ]
    }

    fn forms() -> Vec<String> {
        vec![
            format!("sgp_{}", hex(1)),
            format!("sgp_local_{}", hex(2)),
            format!("sgp_{}_{}", filler(HEX, 16, 3), hex(4)),
            format!("sgp_{}_{}", filler(ALNUM, 16, 5), hex(6)),
            format!("sgp_{}_{}", filler(ALNUM, INSTANCE_MAX, 7), hex(8)),
            format!("sgp_{}", hex(9).to_uppercase()),
            format!("sgp_a_{}", hex(10)),
        ]
    }

    #[test]
    fn every_documented_form_is_detected_in_every_context() {
        for token in forms() {
            for input in contexts(&token) {
                assert_single(&input, &token);
            }
        }
    }

    #[test]
    fn near_miss_twins_are_rejected() {
        let body = hex(11);
        let long_identifier = filler(ALNUM, INSTANCE_MAX + 1, 12);
        let mut non_hex = body.clone();
        non_hex.replace_range(39..40, "g");
        let token = format!("sgp_{body}");
        for input in [
            format!("sgp_{}", &body[..39]),
            format!("sgp_{body}a"),
            format!("sgp_{non_hex}"),
            format!("sgp_local_{}", &body[..39]),
            format!("sgp_local_{body}0"),
            format!("sgp_local{body}"),
            format!("sgp_abc{body}"),
            format!("sgp__{body}"),
            format!("sgp_{long_identifier}_{body}"),
            format!("sgp_a-b_{body}"),
            format!("SGP_{body}"),
            format!("sgp-{body}"),
            format!("sgp{body}"),
            format!("xsgp_{body}"),
            format!("_{token}"),
            format!("-{token}"),
            format!("{token}_"),
            format!("{token}-x"),
            format!("{token}_tail"),
            format!("sgp_{body}{body}"),
        ] {
            assert!(detect(&input).is_empty(), "{input}");
        }
    }

    #[test]
    fn trailing_delimiters_and_adjacent_text_keep_the_exact_span() {
        let token = format!("sgp_local_{}", hex(13));
        for suffix in [
            ".", ",", ";", ")", "\"", "'", "`", "\n", " tail", ".\n", "]",
        ] {
            assert_single(&format!("{token}{suffix}"), &token);
        }
        for prefix in ["(", "\"", "'", "`", "=", ":", " ", "\t", "[", "<"] {
            assert_single(&format!("{prefix}{token}"), &token);
        }
    }

    #[test]
    fn excluded_shapes_and_benign_text_are_unclaimed() {
        let sha = hex(14);
        for input in [
            sha.clone(),
            format!("commit {sha}"),
            format!("sgph_{sha}"),
            format!("sgph_local_{sha}"),
            format!("sgd_{}", filler(HEX, 64, 15)),
            format!("slk_{sha}"),
            format!("sgp_{}", "x".repeat(40)),
            "sgp_token".to_owned(),
            "SRC_ACCESS_TOKEN=${SRC_ACCESS_TOKEN}".to_owned(),
            "SRC_ACCESS_TOKEN=sgp_xxxxxxxx".to_owned(),
        ] {
            assert!(detect(&input).is_empty(), "{input}");
        }
    }

    #[test]
    fn repeated_tokens_are_reported_once_each_and_a_glued_run_never() {
        let token = format!("sgp_{}", hex(16));
        assert_eq!(detect(&format!("{token} {token}")).len(), 2);
        assert!(detect(&token.repeat(200)).is_empty());
        assert!(detect(&"sgp_".repeat(10_000)).is_empty());
        assert!(detect(&format!("sgp_{}", "a_".repeat(5_000))).is_empty());
    }
}
