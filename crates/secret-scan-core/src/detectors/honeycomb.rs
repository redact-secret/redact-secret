//! Honeycomb ingest key detection (issue #1034, handoff
//! `docs/audits/evidence/1014/honeycomb.md`).
//!
//! | Key | Grammar | Evidence |
//! | --- | --- | --- |
//! | Environment ingest | `hc` + one `[a-z]` + `ik_` + exactly 58 `[a-z0-9]` | prefix: Honeycomb docs; length: docs placeholder, libhoney-go 64-byte gate and fixtures (R5); alphabet: SDK fixtures (R5). T1 |
//! | Classic environment ingest | `hc` + one `[a-z]` + `ic_` + exactly 58 `[a-z0-9]` | `^hc[a-z]ic_[a-z0-9]{58}$` in libhoney-py and libhoney-go (R1). T1 |
//!
//! Both are 64 bytes in total and one type: an ingest key writes (or
//! spoofs) telemetry into one environment. The docs say the key value is
//! the key id and the secret concatenated with no separator, so the whole
//! 64 bytes are the span.
//!
//! **Management keys stay unclaimed.** `hc[a-z]mk_` + 26 + `:` + 32 is
//! issuance-gated on the alphabet of both segments (the docs placeholder is
//! digits only and no fixture exists); `honeycomb_management_key` is added
//! only after a maintainer-issued key clears that gate. Key ids alone
//! (`hc?ik_`/`hc?mk_` + 26, `hc?lk_`, `hc?en_` environment ids) are
//! non-secret and fail the 58-byte body; 22-character configuration keys and
//! 32-hex classic keys have no distinctive shape and stay with generic
//! context.
//!
//! Boundary `[A-Za-z0-9_-]`: a glued key is an accepted false negative; an
//! unrelated `hc?ik_`/`hc?ic_` + 58 lowercase alphanumerics is the accepted
//! false positive (none is known).

use crate::detectors::additional_providers::KnownFormatProviderDetector;
use crate::detectors::pattern::{self, PrefixShape};

const PREFIX: &str = "hc";
const SECRET_LEN: usize = 58;
/// Type letter, `ik`/`ic`, `_`, then the 58-byte key id and secret.
const BODY_LEN: usize = 1 + 2 + 1 + SECRET_LEN;
const SIGNALS: [&str; 2] = ["honeycomb-documented-prefix", "honeycomb-sdk-length"];

/// One `[a-z]` type letter, `ik_` or `ic_`, then 58 `[a-z0-9]`.
fn has_ingest_layout(bytes: &[u8], _start: usize, end: usize) -> bool {
    let body = &bytes[end - BODY_LEN..end];
    let (head, secret) = body.split_at(4);
    head[0].is_ascii_lowercase()
        && matches!(&head[1..], b"ik_" | b"ic_")
        && secret.iter().copied().all(pattern::is_lower_alnum)
}

pub(super) const HONEYCOMB_INGEST_KEY: KnownFormatProviderDetector =
    KnownFormatProviderDetector::new(
        "honeycomb-api-key",
        "honeycomb_ingest_key",
        &[
            PrefixShape::exact(PREFIX, BODY_LEN, pattern::is_alnum_underscore, &SIGNALS)
                .with_post_check(has_ingest_layout),
        ],
        pattern::is_alnum_dash,
    );

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ByteRange, Candidate, Confidence, Detector, DetectorContext, Specificity};

    const LOWER_ALNUM: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";

    /// Synthetic low-entropy filler, never provider-issued.
    fn filler(len: usize, seed: usize) -> String {
        (0..len)
            .map(|i| char::from(LOWER_ALNUM[(i * 7 + seed * 13 + i / 5) % LOWER_ALNUM.len()]))
            .collect()
    }

    fn key_with(letter: char, kind: &str, len: usize) -> String {
        format!("hc{letter}{kind}_{}", filler(len, 1))
    }

    fn key(letter: char, kind: &str) -> String {
        key_with(letter, kind, SECRET_LEN)
    }

    fn detect(input: &str) -> Vec<Candidate> {
        HONEYCOMB_INGEST_KEY
            .detect(input, &DetectorContext::new(input.len()))
            .unwrap()
    }

    fn assert_single(input: &str, key: &str) {
        let candidates = detect(input);
        assert_eq!(candidates.len(), 1, "{input}");
        let start = input.find(key).unwrap();
        assert_eq!(candidates[0].type_name(), "honeycomb_ingest_key");
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
            format!("HONEYCOMB_API_KEY={key}"),
            format!("X-Honeycomb-Team: {key}"),
            format!("OTEL_EXPORTER_OTLP_HEADERS=x-honeycomb-team={key}"),
            format!("exporters:\n  otlp:\n    headers:\n      x-honeycomb-team: {key}\n"),
            format!("{{\"token\": \"{key}\"}}"),
            format!("libhoney.Init(libhoney.Config{{APIKey: \"{key}\"}})"),
            format!("Here is my key {key} can you debug this?"),
            format!("The key is {key}."),
        ]
    }

    #[test]
    fn ingest_and_classic_ingest_keys_are_detected_in_every_context() {
        for (letter, kind) in [('x', "ik"), ('x', "ic"), ('a', "ik"), ('z', "ic")] {
            let key = key(letter, kind);
            assert_eq!(key.len(), 64);
            for input in contexts(&key) {
                assert_single(&input, &key);
            }
        }
        assert_eq!(HONEYCOMB_INGEST_KEY.id(), "honeycomb-api-key");
    }

    #[test]
    fn near_miss_twins_are_rejected() {
        let good = key('x', "ik");
        let mut upper = good.clone();
        upper.replace_range(30..31, "Q");
        let mut dashed = good.clone();
        dashed.replace_range(30..31, "-");
        for input in [
            key_with('x', "ik", SECRET_LEN - 1),
            key_with('x', "ik", SECRET_LEN + 1),
            upper,
            dashed,
            format!("hcik_{}", filler(SECRET_LEN + 1, 1)),
            format!("hcAik_{}", filler(SECRET_LEN, 1)),
            key('x', "mk"),
            key('x', "lk"),
            key('x', "en"),
            format!("x{good}"),
            format!("_{good}"),
            format!("{good}x"),
            format!("{good}_x"),
        ] {
            assert!(detect(&input).is_empty(), "{input}");
        }
    }

    #[test]
    fn benign_honeycomb_text_is_not_claimed() {
        for input in [
            format!("{{\"id\": \"hcxik_{}\"}}", filler(26, 2)),
            format!("{{\"id\": \"hcxmk_{}\"}}", filler(26, 2)),
            format!("environment hcxen_{}", filler(26, 3)),
            format!("HONEYCOMB_API_KEY={}", filler(32, 4)),
            format!("hcxmk_{}:{}", filler(26, 5), filler(32, 6)),
            "HONEYCOMB_API_KEY=${HONEYCOMB_API_KEY}".to_owned(),
            "the archcode chchcx hcxik_ prefix".to_owned(),
        ] {
            assert!(detect(&input).is_empty(), "{input}");
        }
    }

    #[test]
    fn repeated_keys_are_reported_once_each_and_a_glued_run_never() {
        let key = key('x', "ic");
        assert_eq!(detect(&format!("{key} {key}")).len(), 2);
        assert!(detect(&key.repeat(100)).is_empty());
        assert!(detect(&"hc".repeat(30_000)).is_empty());
        assert!(detect(&"hcxik_".repeat(10_000)).is_empty());
    }
}
