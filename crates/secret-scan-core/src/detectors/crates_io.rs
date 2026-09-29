//! crates.io API token and trusted-publishing token detection (issue #1031,
//! handoff `docs/audits/evidence/1014/crates-io.md`).
//!
//! | Shape | Finding type | Evidence |
//! | --- | --- | --- |
//! | `cio` + exactly 32 `[A-Za-z0-9]` (35 in total) | `crates_io_api_token` | `rust-lang/crates.io` `token.rs`: `TOKEN_PREFIX = "cio"`, `TOKEN_LENGTH = 32`, `Alphanumeric` (T1, R1) |
//! | `cio_tp_` + exactly 32 `[A-Za-z0-9]` (39 in total) | `crates_io_trusted_publishing_token` | `crates_io_trustpub` `access_token.rs`: `PREFIX = "cio_tp_"`, 31 alphanumerics + 1 check character (T1, R1) |
//!
//! An API token publishes, yanks and changes owners within its scopes; a
//! trusted-publishing token is minted from a CI OIDC exchange and publishes
//! for its short lifetime. Both are supply-chain credentials, so they are
//! separate types.
//!
//! Longest prefix wins at a shared position, so `cio_tp_` is tried before
//! `cio`; the `cio` body alphabet excludes `_`, so a trusted-publishing
//! token is never read as an API token, and `cio_tp_` + 31 matches neither.
//!
//! `cio` is a 3-letter trigram: the exact 32-byte body and the
//! `[A-Za-z0-9_-]` boundary on both sides carry the precision. A standalone
//! 35-byte alphanumeric value that happens to start with `cio` (about one
//! random run in 238,000) is the accepted false positive; a token glued to
//! identifier bytes is the accepted false negative.
//!
//! The trusted-publishing check character (XOR of the 31 raw bytes, modulo
//! 62) is **not** used to reject a match: a shape-valid token is reported
//! whether or not its check character agrees (the security-first standing
//! decision; checksum use is pending maintainer ruling Q1 on #1014).

use crate::detectors::additional_providers::TypedKnownFormatProviderDetector;
use crate::detectors::pattern::{self, PrefixShape};

const BODY_LEN: usize = 32;

const API_TOKEN: &str = "crates_io_api_token";
const TRUSTED_PUBLISHING_TOKEN: &str = "crates_io_trusted_publishing_token";

const SIGNALS: [&str; 2] = ["crates-io-generator-prefix", "crates-io-generator-length"];

pub(super) const CRATES_IO: TypedKnownFormatProviderDetector =
    TypedKnownFormatProviderDetector::new(
        "crates-io-token",
        &[
            PrefixShape::exact("cio_tp_", BODY_LEN, pattern::is_alnum, &SIGNALS),
            PrefixShape::exact("cio", BODY_LEN, pattern::is_alnum, &SIGNALS),
        ],
        &[TRUSTED_PUBLISHING_TOKEN, API_TOKEN],
        pattern::is_alnum_dash,
    );

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ByteRange, Candidate, Confidence, Detector, DetectorContext, Specificity};

    const ALNUM: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

    /// Synthetic low-entropy filler, never provider-issued.
    fn filler(len: usize, seed: usize) -> String {
        (0..len)
            .map(|i| char::from(ALNUM[(i * 7 + seed * 13 + i / 5) % ALNUM.len()]))
            .collect()
    }

    fn api_token() -> String {
        format!("cio{}", filler(BODY_LEN, 1))
    }

    fn trusted_publishing_token() -> String {
        format!("cio_tp_{}", filler(BODY_LEN, 2))
    }

    fn detect(input: &str) -> Vec<Candidate> {
        CRATES_IO
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

    fn contexts(token: &str) -> Vec<String> {
        vec![
            token.to_owned(),
            format!("CARGO_REGISTRY_TOKEN={token}"),
            format!("export CARGO_REGISTRY_TOKEN=\"{token}\""),
            format!("[registry]\ntoken = \"{token}\"\n"),
            format!("cargo publish --token {token}"),
            format!("Authorization: {token}"),
            format!("{{\"token\": \"{token}\"}}"),
            format!("{{\"api_key\": \"{token}\"}}"),
            format!("env:\n  CARGO_REGISTRY_TOKEN: {token}\n"),
            format!("Here is my token {token} can you debug this?"),
            format!("The token is {token}."),
        ]
    }

    #[test]
    fn both_shapes_are_detected_in_every_context() {
        let api = api_token();
        let trusted = trusted_publishing_token();
        assert_eq!(api.len(), 35);
        assert_eq!(trusted.len(), 39);
        for input in contexts(&api) {
            assert_single(&input, &api, API_TOKEN);
        }
        for input in contexts(&trusted) {
            assert_single(&input, &trusted, TRUSTED_PUBLISHING_TOKEN);
        }
        assert_eq!(CRATES_IO.id(), "crates-io-token");
    }

    #[test]
    fn a_wrong_check_character_is_still_reported() {
        // The check character is corroboration at most (pending ruling Q1),
        // so every final alphanumeric byte is accepted.
        for last in ["A", "z", "0", "9"] {
            let token = format!("cio_tp_{}{last}", filler(31, 2));
            assert_single(&token, &token, TRUSTED_PUBLISHING_TOKEN);
        }
    }

    #[test]
    fn near_miss_twins_are_rejected() {
        let body = filler(BODY_LEN, 1);
        let mut dashed = body.clone();
        dashed.replace_range(10..11, "-");
        let mut underscored = body.clone();
        underscored.replace_range(10..11, "_");
        let api = api_token();
        let trusted = trusted_publishing_token();
        for input in [
            format!("cio{}", filler(31, 1)),
            format!("cio{}", filler(33, 1)),
            format!("cio{dashed}"),
            format!("cio{underscored}"),
            format!("CIO{body}"),
            format!("cio_tp_{}", filler(31, 2)),
            format!("cio_tp_{}", filler(33, 2)),
            format!("CIO_TP_{body}"),
            format!("cio_tp-{body}"),
            format!("x{api}"),
            format!("_{api}"),
            format!("-{api}"),
            format!("{api}x"),
            format!("{api}_x"),
            format!("x{trusted}"),
            format!("{trusted}-1"),
        ] {
            assert!(detect(&input).is_empty(), "{input}");
        }
    }

    #[test]
    fn benign_cio_text_is_not_claimed() {
        for input in [
            "the ciound buffer".to_owned(),
            "cio_config = load()".to_owned(),
            "CARGO_REGISTRY_TOKEN=${{ secrets.CRATES_TOKEN }}".to_owned(),
            "cargo publish --token cio...".to_owned(),
            format!("hash=cio{}", filler(61, 3)),
            format!("{}cio{}", filler(16, 4), filler(BODY_LEN, 4)),
        ] {
            assert!(detect(&input).is_empty(), "{input}");
        }
    }

    #[test]
    fn repeated_tokens_are_reported_once_each_and_a_glued_run_never() {
        let api = api_token();
        assert_eq!(detect(&format!("{api} {api}")).len(), 2);
        assert!(detect(&api.repeat(200)).is_empty());
        assert!(detect(&"cio".repeat(20_000)).is_empty());
        assert!(detect(&"cio_tp_".repeat(10_000)).is_empty());
    }
}
