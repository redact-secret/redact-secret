//! Xata API key detection (issue #1102, handoff
//! `docs/audits/evidence/1014/xata.md`).
//!
//! Xata is a hosted Postgres platform. Every fact is T1 under rulings R1 and
//! R9 from the provider's open-sourced server code (`xataio/xata`,
//! `internal/api/key/key.go`, re-checked 2026-09-30): the generator reads 20
//! random bytes, appends the little-endian CRC32 (IEEE) of those bytes, and
//! encodes the 24 bytes with the `jxskiss/base62` bit-packed encoder over
//! the alphabet `0-9a-zA-Z`; the key is `xau` or `xao`, `_`, then that
//! encoding. The validator caps the whole key at `MaxLength = 40`.
//!
//! The encoder reads the bytes as a bit stream in 6-bit groups and emits a
//! 5-bit group when the top four bits of a group are set, so the body is
//! 32 characters (no 5-bit group) up to 39. The width was derived by
//! porting the encoder (13.5 percent at 32, 86.2 percent at 33, 0.31
//! percent at 34, 4e-8 at 35, 1e-14 at 36); the provider's test fixture
//! (33) and the CLI mask (33) agree. The contract is the window the
//! validator can accept after `xau_`/`xao_`: 32 to 36.
//!
//! | Prefix | Body | Finding type |
//! | --- | --- | --- |
//! | `xau_` | `[0-9A-Za-z]{32,36}` | `xata_user_api_key` |
//! | `xao_` | `[0-9A-Za-z]{32,36}` | `xata_organization_api_key` |
//!
//! ## Checksum
//!
//! The CRC32 is offline-verifiable but is never used to reject a shape-valid
//! match: ruling Q1 of the #1014 index stays open, and the Polar and
//! crates.io precedent keeps the lexical grammar as the contract. A later
//! post-check must decode with the non-standard bit-packed base62, not the
//! big-integer base62.
//!
//! ## Boundaries
//!
//! The prefix is 4 bytes, so the leading boundary `[A-Za-z0-9_-]` is
//! load-bearing: `xau_` inside `maxau_...` or any longer identifier is not a
//! key. The run is maximal and rejected whole, never truncated, when it is
//! under 32 or over 36 bytes or when `_` or `-` follows it. Classic-platform
//! (pre-2026) keys have no source and stay with generic context.

use crate::detectors::additional_providers::TypedKnownFormatProviderDetector;
use crate::detectors::pattern::{self, PrefixShape};

const BODY_MIN: usize = 32;
const BODY_MAX: usize = 36;
const PREFIX_LEN: usize = 4;
const SIGNALS: [&str; 2] = ["xata-generator-prefix", "xata-generator-width"];
const USER: &str = "xata_user_api_key";
const ORGANIZATION: &str = "xata_organization_api_key";

/// The run is maximal, so a body over [`BODY_MAX`] must fail whole.
fn within_body_cap(_bytes: &[u8], start: usize, end: usize) -> bool {
    end - start - PREFIX_LEN <= BODY_MAX
}

pub(super) const XATA: TypedKnownFormatProviderDetector = TypedKnownFormatProviderDetector::new(
    "xata-api-key",
    &[
        PrefixShape::at_least("xau_", BODY_MIN, pattern::is_alnum, &SIGNALS)
            .with_post_check(within_body_cap),
        PrefixShape::at_least("xao_", BODY_MIN, pattern::is_alnum, &SIGNALS)
            .with_post_check(within_body_cap),
    ],
    &[USER, ORGANIZATION],
    pattern::is_alnum_dash,
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ByteRange, Candidate, Confidence, Detector, DetectorContext, Specificity};

    const ALNUM: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

    /// Synthetic filler, never provider-issued.
    fn filler(len: usize, seed: usize) -> String {
        (0..len)
            .map(|i| char::from(ALNUM[(i * 7 + seed * 13 + i / 5) % ALNUM.len()]))
            .collect()
    }

    fn key(prefix: &str, len: usize) -> String {
        format!("{prefix}{}", filler(len, len))
    }

    fn detect(input: &str) -> Vec<Candidate> {
        XATA.detect(input, &DetectorContext::new(input.len()))
            .unwrap()
    }

    fn assert_single(input: &str, key: &str, type_name: &str) {
        let candidates = detect(input);
        assert_eq!(candidates.len(), 1, "{input}");
        let start = input.find(key).unwrap();
        assert_eq!(candidates[0].type_name(), type_name, "{input}");
        assert_eq!(candidates[0].confidence(), Confidence::High);
        assert_eq!(candidates[0].effective_specificity(), Specificity::Provider);
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(start, start + key.len()).unwrap(),
            "{input}"
        );
    }

    fn contexts(key: &str) -> Vec<String> {
        vec![
            key.to_owned(),
            format!("XATA_API_KEY={key}"),
            format!("export XATA_API_KEY=\"{key}\""),
            format!("Authorization: Bearer {key}"),
            format!("{{\"token\": \"{key}\"}}"),
            format!(
                "{{\"mcpServers\": {{\"xata\": {{\"env\": {{\"XATA_API_KEY\": \"{key}\"}}}}}}}}"
            ),
            format!("Here is my key {key} can you debug this?"),
            format!("The key is {key}."),
            // A multibyte lead keeps byte offsets distinct from char offsets.
            format!("\u{d0a4}\u{d0a4}\u{1f511} {key}"),
        ]
    }

    #[test]
    fn both_roles_are_detected_at_every_width_in_every_context() {
        for (prefix, type_name) in [("xau_", USER), ("xao_", ORGANIZATION)] {
            for len in [BODY_MIN, 33, 34, 35, BODY_MAX] {
                let key = key(prefix, len);
                assert_eq!(key.len(), PREFIX_LEN + len);
                for input in contexts(&key) {
                    assert_single(&input, &key, type_name);
                }
            }
        }
    }

    #[test]
    fn near_miss_twins_are_rejected() {
        let body = filler(33, 2);
        let key = format!("xau_{body}");
        let mut dashed = body.clone();
        dashed.replace_range(10..11, "-");
        let mut underscored = body.clone();
        underscored.replace_range(10..11, "_");
        for input in [
            format!("xau_{}", &body[..31]),
            format!("xao_{}", &body[..31]),
            format!("xau_{}", filler(37, 3)),
            format!("xao_{}", filler(37, 3)),
            format!("xau_{dashed}"),
            format!("xau_{underscored}"),
            format!("XAU_{body}"),
            format!("xat_{body}"),
            format!("xau-{body}"),
            format!("xau{body}"),
            format!("maxau_{body}"),
            format!("x{key}"),
            format!("_{key}"),
            format!("-{key}"),
            format!("{key}_"),
            format!("{key}-x"),
            format!("{key}_x"),
        ] {
            assert!(detect(&input).is_empty(), "{input}");
        }
    }

    #[test]
    fn trailing_delimiters_and_adjacent_text_keep_the_exact_span() {
        let key = key("xao_", 34);
        for suffix in [
            ".", ",", ";", ")", "\"", "'", "`", "\n", " tail", ".\n", "]",
        ] {
            assert_single(&format!("{key}{suffix}"), &key, ORGANIZATION);
        }
        for prefix in ["(", "\"", "'", "`", "=", ":", " ", "\t", "[", "<"] {
            assert_single(&format!("{prefix}{key}"), &key, ORGANIZATION);
        }
    }

    #[test]
    fn placeholders_and_benign_identifiers_are_unclaimed() {
        for input in [
            "xau_test",
            "xau_redacted",
            "xau_some_key",
            "xau_test123",
            "XATA_API_KEY=${XATA_API_KEY}",
            "XATA_API_KEY=xau_****",
            "xau_snake_case_identifier_name",
            "xao_snake_case_identifier_name_x",
        ] {
            assert!(detect(input).is_empty(), "{input}");
        }
        let masked = format!("xau_{}", "*".repeat(33));
        assert!(detect(&masked).is_empty());
    }

    #[test]
    fn repeated_tokens_are_reported_once_each_and_a_glued_run_never() {
        let key = key("xau_", 33);
        assert_eq!(detect(&format!("{key} {key}")).len(), 2);
        assert!(detect(&key.repeat(200)).is_empty());
        assert!(detect(&"xau_".repeat(10_000)).is_empty());
    }
}
