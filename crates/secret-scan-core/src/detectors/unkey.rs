//! Unkey root key detection (issue #1104, handoff
//! [`docs/audits/evidence/1014/unkey.md`](https://github.com/redact-secret/redact-secret/blob/2816897f96c405c3eb8c87a0c70eba5df273c121/docs/audits/evidence/1014/unkey.md)).
//!
//! An Unkey root key authorizes the Unkey management API for a workspace.
//! Both grammars are T1 under rulings R1 and R9 from the provider's own
//! design document and code (`unkeyed/unkey`, re-checked 2026-09-30):
//!
//! | Form | Grammar | Source |
//! | --- | --- | --- |
//! | Version 1 root key | `unkey_` + 8 base58 + `unkeyv1` + 42 base58 (63 in total) | RFC 0017 (its GitHub regex), `create_v1.go`, and the root-key handler test |
//! | Dashboard root key | `unkey_3Z` + 22 base58 (30 in total) | `createRootKey.ts` and `keys/v1.ts`, width and lead derived |
//!
//! Base58 is the Bitcoin alphabet `[1-9A-HJ-NP-Za-km-z]`: no `0`, `O`, `I`,
//! `l` and no `_`. The last 6 characters of a version 1 key are a CRC-32C;
//! it is never used to reject a shape-valid match (ruling Q1 of the #1014
//! index stays open). The dashboard form encodes `[0x01, 0x10, 16 random
//! bytes]`, so it is exactly 24 characters and always begins `3Z`. A version
//! 1 head may itself begin `3Z`, so both forms are one `unkey_` shape with
//! two accepted body widths (57 and 24) and the longer one is tried first: a
//! version 1 key is never read as a dashboard key.
//!
//! ## Exclusions
//!
//! Customer-prefixed version 1 keys (`<1 to 16 byte prefix>_` + 8 +
//! `unkeyv1` + 42) are credentials for the customer's own product, not
//! Unkey root keys; claiming them needs ruling Q10 on #1014, which is open,
//! so they are a bounded false negative here. The deprecated Go
//! `unkey_` + 21 or 22 form, root keys older than the current generators,
//! imported keys, `unkey_<word>` identifiers and `key_`/`api_` ids stay
//! unclaimed.
//!
//! ## Boundaries
//!
//! Boundary `[A-Za-z0-9_-]` on both sides. A body of 56 or 58 bytes (or any
//! width other than 57 and 24), a marker other than `unkeyv1` at body offset
//! 8, a dashboard form without the `3Z` lead and a glued value are
//! intentional false negatives, never a truncated match.

use crate::detectors::additional_providers::KnownFormatProviderDetector;
use crate::detectors::pattern::{self, PrefixShape};

const PREFIX: &str = "unkey_";
const MARKER: &[u8] = b"unkeyv1";
const MARKER_OFFSET: usize = 8;
const DASHBOARD_LEAD: &[u8] = b"3Z";
/// 8 random + `unkeyv1` + 42 random.
const V1_BODY_LEN: usize = MARKER_OFFSET + 7 + 42;
/// `3Z` + 22 random.
const DASHBOARD_BODY_LEN: usize = 24;
const SIGNALS: [&str; 2] = ["unkey-rfc0017-marker", "unkey-generator-prefix"];

/// `[1-9A-HJ-NP-Za-km-z]`, the Bitcoin base58 alphabet.
fn is_base58(byte: u8) -> bool {
    matches!(
        byte,
        b'1'..=b'9' | b'A'..=b'H' | b'J'..=b'N' | b'P'..=b'Z' | b'a'..=b'k' | b'm'..=b'z'
    )
}

/// The body of an accepted width carries its form's fixed part: the marker
/// for version 1, the `3Z` lead for the dashboard form.
fn has_form(bytes: &[u8], start: usize, end: usize) -> bool {
    let body = &bytes[start + PREFIX.len()..end];
    match body.len() {
        V1_BODY_LEN => body[MARKER_OFFSET..MARKER_OFFSET + MARKER.len()] == *MARKER,
        DASHBOARD_BODY_LEN => body.starts_with(DASHBOARD_LEAD),
        _ => false,
    }
}

pub(super) const UNKEY: KnownFormatProviderDetector = KnownFormatProviderDetector::new(
    "unkey-root-key",
    "unkey_root_key",
    &[PrefixShape::one_of(
        PREFIX,
        &[V1_BODY_LEN, DASHBOARD_BODY_LEN],
        is_base58,
        &SIGNALS,
    )
    .with_post_check(has_form)],
    pattern::is_alnum_dash,
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ByteRange, Candidate, Confidence, Detector, DetectorContext, Specificity};

    const BASE58: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    /// Synthetic base58 filler, never provider-issued.
    fn filler(len: usize, seed: usize) -> String {
        (0..len)
            .map(|i| char::from(BASE58[(i * 7 + seed * 13 + i / 5) % BASE58.len()]))
            .collect()
    }

    /// A version 1 shaped key with filler random parts and the marker.
    fn v1(seed: usize) -> String {
        format!("unkey_{}unkeyv1{}", filler(8, seed), filler(42, seed + 1))
    }

    /// A dashboard shaped key: `3Z` + 22 base58.
    fn dashboard(seed: usize) -> String {
        format!("unkey_3Z{}", filler(22, seed))
    }

    fn detect(input: &str) -> Vec<Candidate> {
        UNKEY
            .detect(input, &DetectorContext::new(input.len()))
            .unwrap()
    }

    fn assert_single(input: &str, key: &str) {
        let candidates = detect(input);
        assert_eq!(candidates.len(), 1, "{input}");
        let start = input.find(key).unwrap();
        assert_eq!(candidates[0].type_name(), "unkey_root_key");
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
            format!("UNKEY_ROOT_KEY={key}"),
            format!("export UNKEY_ROOT_KEY=\"{key}\""),
            format!("Authorization: Bearer {key}"),
            format!("{{\"token\": \"{key}\"}}"),
            format!("const unkey = new Unkey({{ rootKey: \"{key}\" }});"),
            format!("Here is my key {key} can you debug this?"),
            format!("The key is {key}."),
            format!("\u{d0a4}\u{1f511} 키: {key}"),
        ]
    }

    #[test]
    fn both_forms_are_detected_in_every_context() {
        let keys = [v1(1), dashboard(2)];
        assert_eq!(keys[0].len(), 63);
        assert_eq!(keys[1].len(), 30);
        for key in keys {
            for input in contexts(&key) {
                assert_single(&input, &key);
            }
        }
    }

    #[test]
    fn a_version_1_head_that_begins_3z_is_still_a_version_1_key() {
        let key = format!("unkey_3Z{}unkeyv1{}", filler(6, 3), filler(42, 4));
        assert_eq!(key.len(), 63);
        for input in contexts(&key) {
            assert_single(&input, &key);
        }
    }

    #[test]
    fn near_miss_twins_are_rejected() {
        let tail = filler(42, 5);
        let head = filler(8, 6);
        let key = v1(7);
        let dash = dashboard(8);
        let with = |offset: usize, byte: char| {
            let mut copy = key.clone();
            copy.replace_range(offset..=offset, &byte.to_string());
            copy
        };
        let mut twins = vec![
            format!("unkey_{head}unkeyv1{}", &tail[..41]),
            format!("unkey_{head}unkeyv1{tail}A"),
            format!("unkey_{head}unkeyv2{tail}"),
            format!("unkey_{head}Unkeyv1{tail}"),
            format!("unkey_{}unkeyv1{tail}", &head[..7]),
            format!("unkey_{head}9unkeyv1{tail}"),
            format!("unkey_{head}{tail}{head}"),
            format!("unkey_3Y{}", filler(22, 9)),
            format!("unkey_3Z{}", filler(21, 10)),
            format!("unkey_3Z{}", filler(23, 11)),
            format!("UNKEY_{}", &key[6..]),
            format!("unkey-{}", &key[6..]),
            format!("unkey{}", &key[6..]),
            format!("x{key}"),
            format!("_{key}"),
            format!("-{key}"),
            format!("{key}_"),
            format!("{key}-x"),
            format!("x{dash}"),
            format!("{dash}_"),
            format!("{dash}-x"),
            format!("my_{key}"),
        ];
        // A byte outside base58 in a random part of either form.
        for offset in [6, 13, 30, 62] {
            for bad in ['0', 'O', 'I', 'l', '_'] {
                twins.push(with(offset, bad));
            }
        }
        for offset in [8, 20, 29] {
            for bad in ['0', 'O', 'I', 'l'] {
                let mut copy = dash.clone();
                copy.replace_range(offset..=offset, &bad.to_string());
                twins.push(copy);
            }
        }
        for input in twins {
            assert!(detect(&input).is_empty(), "{input}");
        }
    }

    #[test]
    fn customer_prefixed_version_1_keys_are_an_explicit_false_negative() {
        for prefix in ["acme", "my_product", "a", "sixteen_chars_pfx"] {
            let key = format!("{prefix}_{}unkeyv1{}", filler(8, 12), filler(42, 13));
            for input in contexts(&key) {
                assert!(detect(&input).is_empty(), "{input}");
            }
        }
    }

    #[test]
    fn trailing_delimiters_and_adjacent_text_keep_the_exact_span() {
        for key in [v1(14), dashboard(15)] {
            for suffix in [
                ".", ",", ";", ")", "\"", "'", "`", "\n", " tail", ".\n", "]",
            ] {
                assert_single(&format!("{key}{suffix}"), &key);
            }
            for prefix in ["(", "\"", "'", "`", "=", ":", " ", "\t", "[", "<"] {
                assert_single(&format!("{prefix}{key}"), &key);
            }
        }
    }

    #[test]
    fn identifiers_placeholders_and_references_are_unclaimed() {
        for input in [
            "unkey_root_key",
            "unkey_mutations",
            "unkey_api_id",
            "key_3ZsyntheticRevokedKeyId",
            "api_3ZsyntheticRevokedApiId",
            "unkey_xxxxxxxxxxxxxxxxxxxxxxxx",
            "UNKEY_ROOT_KEY=${UNKEY_ROOT_KEY}",
            "unkey_abcdefghijkmnopqrstuvwx",
        ] {
            assert!(detect(input).is_empty(), "{input}");
        }
        // 24 lowercase letters without the `3Z` lead.
        let lower = format!("unkey_{}", "abcdefghijkmnopqrstuvwxy");
        assert!(detect(&lower).is_empty());
    }

    #[test]
    fn repeated_keys_are_reported_once_each_and_a_glued_run_never() {
        let key = v1(16);
        assert_eq!(detect(&format!("{key} {key}")).len(), 2);
        assert!(detect(&key.repeat(100)).is_empty());
        assert!(detect(&"unkey_".repeat(10_000)).is_empty());
        let dash = dashboard(17);
        assert_eq!(detect(&format!("{dash} {key} {dash}")).len(), 3);
    }
}
