//! `ClickHouse` Cloud API key secret detection (issue #971, handoff
//! [`docs/audits/evidence/860/clickhouse-cloud.md`](https://github.com/redact-secret/redact-secret/blob/2816897f96c405c3eb8c87a0c70eba5df273c121/docs/audits/evidence/860/clickhouse-cloud.md)).
//!
//! A `ClickHouse` employee stated the prefix in gitleaks PR #1826 (merged
//! 2025-04-16: "we specifically choose a prefix (4b1d...)") and authored the
//! rule `4b1d[A-Za-z0-9]{38}`; the provider-owned Terraform examples since
//! 2023 carry the same 42-byte mixed-case shape. That is T1 as of 2025-04
//! under ruling R3. A 39-byte knowledge-base example from 2023-09 is older,
//! so R3's date order sets it aside.
//!
//! | Part | Grammar | Tier |
//! | --- | --- | --- |
//! | Prefix | `4b1d` | T1 as of 2025-04 (provider staff statement) |
//! | Body | exactly 38 `[A-Za-z0-9]` | T1 as of 2025-04-16 (staff-authored regex) |
//! | Case guard | at least one uppercase letter in the body | project policy |
//!
//! `4b1d` is also valid hexadecimal, so two things keep hex out. The leading
//! boundary is `[A-Za-z0-9_-]`: the byte before the prefix must not be one,
//! so `4b1d` inside a longer hex or base64 run, or in a UUID (`-4b1d-`), is
//! never a start, and a 40- or 64-digit digest that begins `4b1d` fails the
//! trailing boundary (or the 38-byte run) as well. The case guard removes the
//! remaining 42-byte lowercase or all-digit identifiers that happen to begin
//! `4b1d`, at a cost of (36/62)^38, about 1e-9, of uniformly random keys.
//!
//! Left unclaimed: the key ID (the Basic-auth username, which has no
//! marker), secrets a caller supplies as a pre-hashed `hashData` value, the
//! 39-byte knowledge-base shape, and `mykeysecret`-style placeholders.
//! `clickhouse` is not added to `generic-token`'s dedicated-provider
//! deferral list, so the key ID and the other credentials keep contextual
//! detection under `CLICKHOUSE_*` names.

use crate::detectors::additional_providers::KnownFormatProviderDetector;
use crate::detectors::pattern::{self, PrefixShape};

const PREFIX: &str = "4b1d";
const BODY_LEN: usize = 38;
const SIGNALS: [&str; 3] = [
    "clickhouse-staff-stated-prefix",
    "clickhouse-staff-regex-length",
    "clickhouse-mixed-case-guard",
];

/// The body holds at least one uppercase letter, which every provider
/// example and the staff regex's mixed-case values have and a hex digest or
/// lowercase identifier never has.
fn body_has_uppercase(bytes: &[u8], start: usize, end: usize) -> bool {
    bytes[start + PREFIX.len()..end]
        .iter()
        .any(u8::is_ascii_uppercase)
}

pub(super) const CLICKHOUSE_CLOUD_API_SECRET: KnownFormatProviderDetector =
    KnownFormatProviderDetector::new(
        "clickhouse-cloud-api-secret",
        "clickhouse_cloud_api_secret",
        &[
            PrefixShape::exact(PREFIX, BODY_LEN, pattern::is_alnum, &SIGNALS)
                .with_post_check(body_has_uppercase),
        ],
        pattern::is_alnum_dash,
    );

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ByteRange, Candidate, Confidence, Detector, DetectorContext, Specificity};

    /// Synthetic mixed-case alphanumeric filler, never provider-issued.
    fn body(len: usize, seed: usize) -> String {
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        (0..len)
            .map(|i| char::from(ALPHABET[(i * 7 + seed * 13 + i / 5) % ALPHABET.len()]))
            .collect()
    }

    fn secret(len: usize) -> String {
        format!("{PREFIX}{}", body(len, 1))
    }

    fn detect(input: &str) -> Vec<Candidate> {
        CLICKHOUSE_CLOUD_API_SECRET
            .detect(input, &DetectorContext::new(input.len()))
            .unwrap()
    }

    fn assert_single(input: &str, secret: &str) {
        let candidates = detect(input);
        assert_eq!(candidates.len(), 1, "{input}");
        let start = input.find(secret).unwrap();
        assert_eq!(candidates[0].type_name(), "clickhouse_cloud_api_secret");
        assert_eq!(candidates[0].confidence(), Confidence::High);
        assert_eq!(candidates[0].effective_specificity(), Specificity::Provider);
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(start, start + secret.len()).unwrap(),
            "{input}"
        );
    }

    fn contexts(secret: &str) -> Vec<String> {
        vec![
            secret.to_owned(),
            format!("CLICKHOUSE_CLOUD_API_SECRET={secret}"),
            format!("export CLICKHOUSE_CLOUD_API_SECRET=\"{secret}\""),
            format!("token_secret = \"{secret}\""),
            format!("curl --user $KEY_ID:{secret} https://api.clickhouse.cloud/v1/organizations"),
            format!("https://KEYID:{secret}@api.clickhouse.cloud/v1/organizations"),
            format!("Authorization: Bearer {secret}"),
            format!("{{\"token\": \"{secret}\"}}"),
            format!("{{\"keySecret\": \"{secret}\"}}"),
            format!("Here is my secret {secret} can you debug this?"),
            format!("The secret is {secret}."),
        ]
    }

    #[test]
    fn the_exact_shape_is_detected_in_every_context() {
        let secret = secret(BODY_LEN);
        assert_eq!(secret.len(), 42);
        for input in contexts(&secret) {
            assert_single(&input, &secret);
        }
        assert_eq!(
            CLICKHOUSE_CLOUD_API_SECRET.id(),
            "clickhouse-cloud-api-secret"
        );
    }

    #[test]
    fn near_miss_twins_are_rejected() {
        let value = body(BODY_LEN, 2);
        let lower = value.to_ascii_lowercase();
        let hex: String = value
            .bytes()
            .map(|byte| char::from(b"0123456789abcdef"[usize::from(byte) % 16]))
            .collect();
        let dashed = format!("{}-{}", &value[..20], &value[21..]);
        for input in [
            secret(BODY_LEN - 1),
            secret(BODY_LEN + 1),
            // The 39-byte knowledge-base shape: 35 bytes after the prefix.
            secret(35),
            format!("{PREFIX}{lower}"),
            format!("{PREFIX}{hex}"),
            format!("{PREFIX}{dashed}"),
            format!("4B1D{value}"),
            format!("4b1c{value}"),
            format!("a{PREFIX}{value}"),
            format!("_{PREFIX}{value}"),
            format!("-{PREFIX}{value}"),
            format!("{PREFIX}{value}a"),
            format!("{PREFIX}{value}_"),
            format!("{PREFIX}{value}-1"),
        ] {
            assert!(detect(&input).is_empty(), "{input}");
        }
    }

    #[test]
    fn hex_digests_and_uuids_are_not_claimed() {
        let sha1 = format!("{PREFIX}{}", "0123456789abcdef0123456789abcdef0123");
        let sha256 = format!("{PREFIX}{}", "0123456789abcdef".repeat(4)[..60].to_owned());
        assert_eq!(sha1.len(), 40);
        assert_eq!(sha256.len(), 64);
        // An uppercase hex digest has uppercase letters, so only the run
        // length and boundaries stand between it and a match.
        let upper_sha256 = sha256.to_ascii_uppercase().replacen("4B1D", PREFIX, 1);
        for input in [
            sha1,
            sha256,
            upper_sha256,
            "123e4567-4b1d-12d3-a456-426614174000".to_owned(),
            "123e4567-e89b-4b1d-a456-426614174000".to_owned(),
            "urn:uuid:4b1d0000-0000-4000-8000-000000000000".to_owned(),
        ] {
            assert!(detect(&input).is_empty(), "{input}");
        }
    }

    #[test]
    fn benign_clickhouse_text_is_not_claimed() {
        for input in [
            "key_secret = \"mykeysecret\"",
            "key_id = \"mykeyid\"",
            "CLICKHOUSE_CLOUD_API_SECRET=${CLICKHOUSE_CLOUD_API_SECRET}",
            "the prefix is 4b1d",
            "CLICKHOUSE_CLOUD_API_KEY_ID=SyntheticRevokedKeyId",
        ] {
            assert!(detect(input).is_empty(), "{input}");
        }
    }

    #[test]
    fn repeated_secrets_are_reported_once_each_and_a_glued_run_never() {
        let secret = secret(BODY_LEN);
        assert_eq!(detect(&format!("{secret} {secret}")).len(), 2);
        assert!(detect(&format!("{secret}_{secret}")).is_empty());
        assert!(detect(&PREFIX.repeat(20_000)).is_empty());
        assert!(detect(&format!("{PREFIX}{}", "aB3".repeat(7_000))).is_empty());
    }
}
