//! Cerebras inference API key detection (issue #975, handoff
//! [`docs/audits/evidence/860/cerebras.md`](https://github.com/redact-secret/redact-secret/blob/2816897f96c405c3eb8c87a0c70eba5df273c121/docs/audits/evidence/860/cerebras.md)).
//!
//! The provider's VS Code extension validator
//! (`Cerebras/vscode-cerebras-chat`, `src/provider.ts`) rejects any key that
//! does not start `csk_` or `csk-` or whose length is not 52; that check has
//! kept the 52 since 2025-08-29 (ruling R1), so the body is exactly 48. A
//! Cerebras staff member wrote on 2025-10-23 and 2025-10-24 that customers
//! have keys with both prefixes, that `csk_` was "an unintentional and recent
//! change", that new keys use `csk-`, and that both should be accepted
//! (ruling R3, as of 2025-10). No provider source states the alphabet, so
//! ruling R10 lets project policy fill it with `[A-Za-z0-9_-]`, a superset of
//! every class seen.
//!
//! | Part | Grammar | Tier |
//! | --- | --- | --- |
//! | Prefix | `csk-` or `csk_` | T1 (provider validator, staff statement, docs) |
//! | Body | exactly 48 `[A-Za-z0-9_-]` | width T1 (R1); alphabet is policy (R10) |
//!
//! The boundary is `[A-Za-z0-9_-]` on both sides, and it is the same as the
//! body alphabet, so a run of 49 or more body bytes is rejected whole, never
//! truncated. The leading boundary is load-bearing: `csk` ends Pinecone's
//! `pcsk_`, and the byte before it there is `p`, so a Pinecone key (whose own
//! detector keeps `pcsk_`) is never a Cerebras start, and `xcsk-` and `_csk-`
//! glue is rejected the same way. A `.` or `+` is outside the alphabet and
//! ends the run short of 48.
//!
//! Left unclaimed: Management API keys (shape unknown), `csk-your-key-here`
//! and `csk-xxxx` placeholders, and any other width. `cerebras` is not added
//! to `generic-token`'s dedicated-provider deferral list, because deferral
//! would silence a Management API key under `CEREBRAS_*` names.

use crate::detectors::additional_providers::KnownFormatProviderDetector;
use crate::detectors::pattern::{self, PrefixShape};

const BODY_LEN: usize = 48;
const SIGNALS: [&str; 2] = ["cerebras-documented-prefix", "cerebras-validator-length"];

pub(super) const CEREBRAS_API_KEY: KnownFormatProviderDetector = KnownFormatProviderDetector::new(
    "cerebras-api-key",
    "cerebras_api_key",
    &[
        PrefixShape::exact("csk-", BODY_LEN, pattern::is_alnum_dash, &SIGNALS),
        PrefixShape::exact("csk_", BODY_LEN, pattern::is_alnum_dash, &SIGNALS),
    ],
    pattern::is_alnum_dash,
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ByteRange, Candidate, Confidence, Detector, DetectorContext, Specificity};

    const PREFIXES: [&str; 2] = ["csk-", "csk_"];

    /// Synthetic filler over `[A-Za-z0-9_-]`, never provider-issued. The
    /// first and last bytes are alphanumeric so a glued run stays visible.
    fn body(len: usize, seed: usize) -> String {
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-";
        let mut body: Vec<u8> = (0..len)
            .map(|i| ALPHABET[(i * 7 + seed * 13 + i / 5) % ALPHABET.len()])
            .collect();
        body[0] = b'N';
        body[len - 1] = b'z';
        String::from_utf8(body).unwrap()
    }

    fn key(prefix: &str, len: usize) -> String {
        format!("{prefix}{}", body(len, len))
    }

    fn detect(input: &str) -> Vec<Candidate> {
        CEREBRAS_API_KEY
            .detect(input, &DetectorContext::new(input.len()))
            .unwrap()
    }

    fn assert_single(input: &str, key: &str) {
        let candidates = detect(input);
        assert_eq!(candidates.len(), 1, "{input}");
        let start = input.find(key).unwrap();
        assert_eq!(candidates[0].type_name(), "cerebras_api_key");
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
            format!("CEREBRAS_API_KEY={key}"),
            format!("export CEREBRAS_API_KEY=\"{key}\""),
            format!("Authorization: Bearer {key}"),
            format!("X-API-Key: {key}"),
            format!("{{\"token\": \"{key}\"}}"),
            format!("{{\"api_key\": \"{key}\"}}"),
            format!("client = Cerebras(api_key=\"{key}\")"),
            format!("client = OpenAI(base_url=\"https://api.cerebras.ai/v1\", api_key=\"{key}\")"),
            format!("Here is my key {key} can you debug this?"),
            format!("The key is {key}."),
        ]
    }

    #[test]
    fn keys_of_both_prefixes_are_detected_in_every_context() {
        for prefix in PREFIXES {
            let key = key(prefix, BODY_LEN);
            assert_eq!(key.len(), 52);
            for input in contexts(&key) {
                assert_single(&input, &key);
            }
        }
        // An all-lowercase alphanumeric body is inside the policy class.
        let lower = format!(
            "csk-{}",
            "abcdefghij0123456789".repeat(3)[..BODY_LEN].to_owned()
        );
        for input in contexts(&lower) {
            assert_single(&input, &lower);
        }
        assert_eq!(CEREBRAS_API_KEY.id(), "cerebras-api-key");
    }

    #[test]
    fn near_miss_twins_are_rejected() {
        let value = body(BODY_LEN, 1);
        let dotted = format!("{}.{}", &value[..20], &value[21..]);
        let plus = format!("{}+{}", &value[..20], &value[21..]);
        for prefix in PREFIXES {
            for input in [
                key(prefix, BODY_LEN - 1),
                key(prefix, BODY_LEN + 1),
                format!("{prefix}{dotted}"),
                format!("{prefix}{plus}"),
                format!("x{prefix}{value}"),
                format!("_{prefix}{value}"),
                format!("-{prefix}{value}"),
                format!("p{prefix}{value}"),
            ] {
                assert!(detect(&input).is_empty(), "{input}");
            }
        }
        for input in [
            format!("CSK-{value}"),
            format!("CSK_{value}"),
            format!("csk.{value}"),
            format!("csk{value}"),
        ] {
            assert!(detect(&input).is_empty(), "{input}");
        }
    }

    #[test]
    fn a_pinecone_key_is_not_a_cerebras_start() {
        let value = body(BODY_LEN, 2);
        // `pcsk_` and `pcsk-` followed by a 48-byte run: the byte before
        // `csk` is `p`.
        assert!(detect(&format!("pcsk_{value}")).is_empty());
        assert!(detect(&format!("pcsk-{value}")).is_empty());
        // A real-shape Pinecone key: a 5-byte label, `_`, a 63-byte secret.
        let pinecone = format!(
            "pcsk_SynTh_{}",
            "SyntheticRevokedPineconeSecretValue0000000000000000000000000001"
        );
        assert!(detect(&pinecone).is_empty());
        assert!(detect(&format!("PINECONE_API_KEY={pinecone}")).is_empty());
    }

    #[test]
    fn benign_cerebras_text_is_not_claimed() {
        for input in [
            "CEREBRAS_API_KEY=csk-your-key-here",
            "CEREBRAS_API_KEY=csk_...",
            "CEREBRAS_API_KEY=csk-xxxx",
            "CEREBRAS_API_KEY=${{ secrets.CEREBRAS_API_KEY }}",
            "the prefix is csk-",
            "the disks and tasks were csk_ named",
        ] {
            assert!(detect(input).is_empty(), "{input}");
        }
    }

    #[test]
    fn repeated_keys_are_reported_once_each_and_a_glued_run_never() {
        let key = key("csk-", BODY_LEN);
        assert_eq!(detect(&format!("{key} {key}")).len(), 2);
        assert!(detect(&format!("{key}_{key}")).is_empty());
        assert!(detect(&"csk-".repeat(20_000)).is_empty());
        assert!(detect(&"csk_".repeat(20_000)).is_empty());
        assert!(detect(&format!("csk-{}", "aB3_-".repeat(4_000))).is_empty());
    }
}
