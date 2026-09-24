//! Pinecone API key detection (issue #730, Beta.8 wave 2).
//!
//! Frozen by issue #726 (`docs/audits/evidence/726/README.md`): the current
//! key shape is `pcsk_<label>_<secret>` with a 5-6 byte `[A-Za-z0-9]` label
//! and an exact 63 byte `[A-Za-z0-9]` secret (T2: the prefix and segmenting
//! are provider code, the widths are tool-corroborated). It is one
//! [`PrefixShape`] on the shared [`KnownFormatProviderDetector`]: the body is
//! scanned as `[A-Za-z0-9_]` at the only two total widths the grammar admits
//! (69 or 70 bytes), and [`separator_is_at_the_label_end`] then requires the
//! single `_` to sit exactly after the 5- or 6-byte label, so the run cannot
//! be split any other way.
//!
//! Not claimed, on purpose: the documented `pckey_` prefix (contradicted by
//! every `pcsk_` observation, so neither positive nor negative), and a
//! *bare* legacy UUID key, which is lexically identical to Pinecone's own
//! project, key and service-account identifiers. Index hosts, environment
//! names and masked `pcsk_***` values never reach the width and stay clean.
//!
//! Boundary: the value must not be a slice of a longer `[A-Za-z0-9_-]`
//! identifier.
//!
//! ## Legacy UUID key: a name-gated context path (issue #702)
//!
//! Before `pcsk_`, Pinecone issued API keys as a bare lowercase
//! `8-4-4-4-12` hex UUID. A UUID alone proves nothing, so the legacy key is
//! claimed only as the *value assigned to a Pinecone API-key name* on the
//! same line ([`legacy_candidates`]):
//!
//! - a Pinecone-qualified key name, [`PINECONE_KEY_NAMES`] after
//!   [`normalize_name`] (`PINECONE_API_KEY`, `pinecone_api_key`,
//!   `pinecone.api_key`, `PINECONE_KEY`), which names the provider itself; or
//! - a bare API-key name, [`API_KEY_NAMES`] (`api_key`, `apiKey`, `Api-Key`),
//!   when the same line also names `pinecone` (`pinecone.init(api_key=...)`,
//!   an `Api-Key:` header to a `pinecone.io` host).
//!
//! The key and the value are joined only by whitespace, quotes and at least
//! one `=` or `:` ([`assigned_key`]). This is an allow-list of credential
//! names, stricter than `heroku-api-key-legacy`'s keyword co-occurrence: a
//! UUID under a Pinecone project, index, database or service-account id name
//! (`PINECONE_PROJECT_ID`, `project_id=`, `X-Project-Id:`) is never claimed,
//! nor is a bare UUID, a UUID in prose, or a placeholder UUID whose hex
//! digits are all one character (`00000000-0000-...`).
//!
//! Confidence is [`Confidence::High`] with the `pinecone_api_key` type,
//! which the default policy always redacts. The name is the same evidence
//! `generic-token` already redacts at high confidence for a UUID under
//! `apiKey:` or `Api-Key:`, so every spelling of a Pinecone API-key
//! assignment now gets the same action (issue #702 records the decision).
//! The false-negative tradeoff: a legacy key under any other name, or on a
//! different line from its name, stays unclaimed.

use crate::detectors::additional_providers::KnownFormatProviderDetector;
use crate::detectors::generic_token::normalize_name;
use crate::detectors::pattern::{self, PrefixShape};
use crate::detectors::text;
use crate::error::DetectorFailure;
use crate::types::{ByteRange, Candidate, Confidence, Detector, DetectorContext, Specificity};

const PREFIX: &str = "pcsk_";
const SECRET_LEN: usize = 63;
/// Label 5 or 6, the separating `_`, then the secret.
const BODY_LENS: &[usize] = &[5 + 1 + SECRET_LEN, 6 + 1 + SECRET_LEN];
const SIGNALS: [&str; 2] = ["pinecone-provider-code-prefix", "segmented-suffix"];

/// `[A-Za-z0-9_-]`: a value is never a slice of a wider identifier.
fn is_token_char(byte: u8) -> bool {
    pattern::is_alnum_dash(byte) || byte == b'_'
}

/// The body after `pcsk_` holds exactly one `_`, and it is the label
/// separator: at index `len - 64` (5 for a 69 byte body, 6 for a 70 byte one),
/// leaving an all-alphanumeric label and a 63 byte all-alphanumeric secret.
fn separator_is_at_the_label_end(bytes: &[u8], start: usize, end: usize) -> bool {
    let body = &bytes[start + PREFIX.len()..end];
    let separator = body.len() - SECRET_LEN - 1;
    body[separator] == b'_'
        && body
            .iter()
            .enumerate()
            .all(|(index, &byte)| index == separator || pattern::is_alnum(byte))
}

pub(super) const PINECONE: KnownFormatProviderDetector = KnownFormatProviderDetector::new(
    "pinecone-api-key",
    "pinecone_api_key",
    &[
        PrefixShape::one_of(PREFIX, BODY_LENS, pattern::is_alnum_underscore, &SIGNALS)
            .with_post_check(separator_is_at_the_label_end),
    ],
    is_token_char,
);

/// Normalized key names that name the Pinecone API key by themselves.
const PINECONE_KEY_NAMES: &[&str] = &["pinecone_api_key", "pinecone_apikey", "pinecone_key"];

/// Normalized key names that name an API key, accepted only on a line that
/// also names `pinecone`.
const API_KEY_NAMES: &[&str] = &["api_key", "apikey"];

/// The line keyword that qualifies an [`API_KEY_NAMES`] key.
const CONTEXT_KEYWORD: &str = "pinecone";

/// `8 + 1 + 4 + 1 + 4 + 1 + 4 + 1 + 12`.
const LEGACY_UUID_LEN: usize = 36;

/// The dash offsets a standard UUID fixes, counted from the run's own start.
const UUID_DASH_OFFSETS: [usize; 4] = [8, 13, 18, 23];

const LEGACY_SIGNALS: [&str; 2] = ["pinecone-api-key-name", "legacy-uuid-shape"];

/// `true` for a lowercase `8-4-4-4-12` hex UUID whose hex digits are not all
/// the same character (`00000000-0000-0000-0000-000000000000` is a
/// placeholder).
fn is_legacy_uuid(run: &[u8]) -> bool {
    let shaped = run.len() == LEGACY_UUID_LEN
        && run.iter().enumerate().all(|(offset, &byte)| {
            if UUID_DASH_OFFSETS.contains(&offset) {
                byte == b'-'
            } else {
                pattern::is_lower_hex(byte)
            }
        });
    let first = run[0];
    shaped && run.iter().any(|&byte| byte != b'-' && byte != first)
}

/// `true` for a byte of a key name: `[A-Za-z0-9_.-]`.
fn is_key_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-')
}

/// The key a value starting at `value_start` of `line` is assigned to: the
/// run of [`is_key_byte`] bytes left of a gap of spaces, tabs, quotes and at
/// least one `=` or `:`. `None` when no such operator joins them.
fn assigned_key(line: &[u8], value_start: usize) -> Option<&[u8]> {
    let mut end = value_start;
    let mut has_operator = false;
    while end > 0 && matches!(line[end - 1], b' ' | b'\t' | b'"' | b'\'' | b'=' | b':') {
        has_operator |= matches!(line[end - 1], b'=' | b':');
        end -= 1;
    }
    let mut start = end;
    while start > 0 && is_key_byte(line[start - 1]) {
        start -= 1;
    }
    (has_operator && start < end).then_some(&line[start..end])
}

/// `true` when `line` contains `needle` (ASCII, case-insensitive).
fn line_contains_ci(line: &str, needle: &str) -> bool {
    line.len() >= needle.len()
        && (0..=line.len() - needle.len()).any(|pos| text::starts_with_ci(line, pos, needle))
}

/// `true` when `key` names the Pinecone API key on `line`.
fn is_pinecone_key_name(key: &[u8], line: &str) -> bool {
    let Ok(key) = std::str::from_utf8(key) else {
        return false;
    };
    let normalized = normalize_name(key);
    PINECONE_KEY_NAMES.contains(&normalized.as_str())
        || (API_KEY_NAMES.contains(&normalized.as_str()) && line_contains_ci(line, CONTEXT_KEYWORD))
}

/// Legacy UUID keys assigned to a Pinecone API-key name; see the module doc.
fn legacy_candidates(input: &str) -> Vec<Candidate> {
    let mut candidates = Vec::new();
    let mut line_start = 0usize;
    for line in input.split('\n') {
        let bytes = line.as_bytes();
        let ends = pattern::run_ends(bytes, pattern::is_hex_or_dash);
        let mut start = 0usize;
        while start < bytes.len() {
            if !pattern::is_hex_or_dash(bytes[start]) {
                start += 1;
                continue;
            }
            let end = ends[start];
            if is_legacy_uuid(&bytes[start..end])
                && pattern::boundary_ok(bytes, start, end, is_token_char)
                && assigned_key(bytes, start).is_some_and(|key| is_pinecone_key_name(key, line))
                && let Some(range) = ByteRange::new(line_start + start, line_start + end)
            {
                candidates.push(
                    Candidate::new("pinecone_api_key", Confidence::High, range)
                        .with_specificity(Specificity::Provider)
                        .with_signals(LEGACY_SIGNALS),
                );
            }
            start = end;
        }
        line_start += line.len() + 1;
    }
    candidates
}

/// The `pinecone-api-key` detector: the context-free `pcsk_` shape
/// ([`PINECONE`]) plus the name-gated legacy UUID path
/// ([`legacy_candidates`]).
pub(super) struct PineconeApiKeyDetector;

impl Detector for PineconeApiKeyDetector {
    fn id(&self) -> &'static str {
        "pinecone-api-key"
    }

    fn detect(
        &self,
        input: &str,
        context: &DetectorContext,
    ) -> Result<Vec<Candidate>, DetectorFailure> {
        let mut candidates = PINECONE.detect(input, context)?;
        candidates.extend(legacy_candidates(input));
        Ok(candidates)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LABEL: &str = "SynTh";
    const LONG_LABEL: &str = "SynThe";
    const SECRET: &str = "SyntheticRevokedPineconeSecretValue0000000000000000000000000001";
    const _: () = assert!(SECRET.len() == SECRET_LEN);

    fn detect(input: &str) -> Vec<Candidate> {
        PINECONE
            .detect(input, &DetectorContext::new(input.len()))
            .unwrap()
    }

    /// Locally constructed synthetic lowercase UUID; never provider-issued.
    const LEGACY: &str = "5e7a1c0d-0b9e-4f3a-8d2c-6a1b0c9d8e7f";
    const _: () = assert!(LEGACY.len() == LEGACY_UUID_LEN);

    fn detect_all(input: &str) -> Vec<Candidate> {
        PineconeApiKeyDetector
            .detect(input, &DetectorContext::new(input.len()))
            .unwrap()
    }

    fn token(label: &str) -> String {
        format!("pcsk_{label}_{SECRET}")
    }

    #[test]
    fn detects_both_label_widths_at_provider_specificity() {
        for label in [LABEL, LONG_LABEL] {
            let token = token(label);
            let candidates = detect(&token);
            assert_eq!(candidates.len(), 1, "{token}");
            assert_eq!(PINECONE.id(), "pinecone-api-key");
            assert_eq!(candidates[0].type_name(), "pinecone_api_key");
            assert_eq!(candidates[0].confidence(), Confidence::High);
            assert_eq!(candidates[0].effective_specificity(), Specificity::Provider);
            assert_eq!(
                candidates[0].range(),
                ByteRange::new(0, token.len()).unwrap()
            );
        }
    }

    #[test]
    fn the_range_covers_exactly_the_key_inside_surrounding_text() {
        let token = token(LABEL);
        let input = format!("PINECONE_API_KEY=\"{token}\", next");
        let candidates = detect(&input);
        assert_eq!(candidates.len(), 1);
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(18, 18 + token.len()).unwrap()
        );
    }

    #[test]
    fn a_label_or_secret_of_another_width_is_rejected() {
        for input in [
            token("Syn"),
            token("SynThes"),
            token(""),
            format!("pcsk_{LABEL}_{}", &SECRET[1..]),
            format!("pcsk_{LABEL}_{SECRET}0"),
            format!("pcsk_{LABEL}{SECRET}"),
            format!("pcsk_{LABEL}-{SECRET}"),
        ] {
            assert!(detect(&input).is_empty(), "{input}");
        }
    }

    #[test]
    fn a_second_separator_or_a_dash_inside_a_segment_is_rejected() {
        let mut secret = SECRET.to_owned();
        secret.replace_range(10..11, "_");
        let mut dashed = SECRET.to_owned();
        dashed.replace_range(10..11, "-");
        for input in [
            format!("pcsk_{LABEL}_{secret}"),
            format!("pcsk_{LABEL}_{dashed}"),
            format!("pcsk_Sy_Th_{}", &SECRET[..62]),
        ] {
            assert!(detect(&input).is_empty(), "{input}");
        }
    }

    #[test]
    fn a_glued_identifier_boundary_rejects_an_embedded_key() {
        let token = token(LABEL);
        for input in [
            format!("x{token}"),
            format!("-{token}"),
            format!("_{token}"),
            format!("{token}_backup"),
            format!("{token}-1"),
        ] {
            assert!(detect(&input).is_empty(), "{input}");
        }
    }

    #[test]
    fn near_miss_prefixes_and_the_unresolved_pckey_prefix_are_not_claimed() {
        for input in [
            format!("PCSK_{LABEL}_{SECRET}"),
            format!("pcsk-{LABEL}_{SECRET}"),
            format!("pckey_{LABEL}_{SECRET}"),
            format!("csk_{LABEL}_{SECRET}"),
        ] {
            assert!(detect(&input).is_empty(), "{input}");
        }
    }

    #[test]
    fn identifiers_hosts_and_masks_stay_clean() {
        for input in [
            "PINECONE_API_KEY=pcsk_***",
            "index host: my-index-1a2b3c4.svc.aped-4627-b74a.pinecone.io",
            "project id 123e4567-e89b-12d3-a456-426614174000",
            "environment: us-east-1-aws",
        ] {
            assert!(detect(input).is_empty(), "{input}");
        }
    }

    #[test]
    fn a_repeated_key_is_reported_once_per_occurrence() {
        let token = token(LABEL);
        let candidates = detect(&format!("{token} {token}"));
        assert_eq!(candidates.len(), 2);
    }

    #[test]
    fn the_detector_keeps_the_pcsk_shape() {
        let token = token(LABEL);
        let candidates = detect_all(&format!("PINECONE_API_KEY={token}"));
        assert_eq!(candidates.len(), 1);
        assert_eq!(PineconeApiKeyDetector.id(), "pinecone-api-key");
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(17, 17 + token.len()).unwrap()
        );
    }

    // --- issue #702: the name-gated legacy UUID path.

    #[test]
    fn a_legacy_uuid_under_a_pinecone_api_key_name_is_claimed() {
        for (before, after) in [
            ("PINECONE_API_KEY=", "\nPINECONE_ENVIRONMENT=us-west1-gcp\n"),
            ("export PINECONE_API_KEY=\"", "\"\n"),
            (
                "import pinecone\n\npinecone.init(api_key=\"",
                "\", environment=\"us-west1-gcp\")\n",
            ),
            (
                "curl https://idx.svc.us-west1-gcp.pinecone.io/query -H \"Api-Key: ",
                "\"\n",
            ),
            (
                "await pinecone.init({ apiKey: \"",
                "\", environment: \"us-west4-gcp\" });\n",
            ),
            ("vectorstore:\n  pinecone_api_key: ", "\n"),
            ("jobs:\n  ingest:\n    env:\n      PINECONE_API_KEY: ", "\n"),
            (
                "services:\n  r:\n    environment:\n      - PINECONE_API_KEY=",
                "\n",
            ),
            (
                "PineconeVectorStore(index_name=\"docs\", pinecone_api_key=\"",
                "\")\n",
            ),
            ("$ terraform output\npinecone_api_key = \"", "\"\n"),
            (
                "{\"type\": \"pineconeApi\", \"data\": {\"apiKey\": \"",
                "\"}}\n",
            ),
            ("export PINECONE_KEY=", "\n"),
            ("pinecone.api_key = '", "'\r\n"),
        ] {
            let input = format!("{before}{LEGACY}{after}");
            let candidates = detect_all(&input);
            assert_eq!(candidates.len(), 1, "{input:?}");
            assert_eq!(candidates[0].type_name(), "pinecone_api_key");
            assert_eq!(candidates[0].confidence(), Confidence::High);
            assert_eq!(candidates[0].effective_specificity(), Specificity::Provider);
            assert_eq!(
                candidates[0].range(),
                ByteRange::new(before.len(), before.len() + LEGACY.len()).unwrap(),
                "{input:?}"
            );
        }
    }

    #[test]
    fn a_legacy_uuid_under_an_identifier_or_unrelated_name_is_not_claimed() {
        for before in [
            "PINECONE_PROJECT_ID=",
            "export PINECONE_INDEX_ID=\"",
            "pinecone.init(project_id=\"",
            "curl https://idx.svc.us-west1-gcp.pinecone.io/query -H \"X-Project-Id: ",
            "await pinecone.init({ projectId: \"",
            "  pinecone_project_id: ",
            "      - PINECONE_SERVICE_ACCOUNT_ID=",
            "pinecone_index_id = \"",
            "{\"type\": \"pineconeApi\", \"data\": {\"indexId\": \"",
            "export PINECONE_UUID=",
            // An API-key name with no `pinecone` on the line.
            "api_key=",
            "OPENAI_API_KEY=",
            // No assignment operator between the name and the value.
            "PINECONE_API_KEY ",
            // Prose and a bare value.
            "the pinecone key is ",
            "",
        ] {
            let input = format!("{before}{LEGACY}\n");
            assert!(detect_all(&input).is_empty(), "{input:?}");
        }
    }

    #[test]
    fn a_pinecone_name_on_another_line_does_not_gate_a_uuid() {
        let input = format!("# pinecone settings\napi_key={LEGACY}\n");
        assert!(detect_all(&input).is_empty());
    }

    #[test]
    fn placeholders_and_near_miss_uuids_are_not_claimed() {
        let upper = LEGACY.to_ascii_uppercase();
        let long = format!("{LEGACY}0");
        let dashless = LEGACY.replace('-', "0");
        for value in [
            "00000000-0000-0000-0000-000000000000",
            "ffffffff-ffff-ffff-ffff-ffffffffffff",
            "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
            upper.as_str(),
            &LEGACY[..35],
            long.as_str(),
            &dashless[..36],
        ] {
            let input = format!("PINECONE_API_KEY={value}\n");
            assert!(detect_all(&input).is_empty(), "{input:?}");
        }
        for input in [
            format!("PINECONE_API_KEY=x{LEGACY}"),
            format!("PINECONE_API_KEY={LEGACY}_backup"),
            "PINECONE_API_KEY=${PINECONE_API_KEY}".to_owned(),
        ] {
            assert!(detect_all(&input).is_empty(), "{input:?}");
        }
    }
}
