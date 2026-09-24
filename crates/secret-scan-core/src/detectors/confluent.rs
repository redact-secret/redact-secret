//! Confluent Cloud API secret detection.
//!
//! The reviewed grammar (issue #309, applying the existing provider-grammar
//! freeze policy recorded in `docs/specs/detector-families.md`) covers two
//! generations of one credential, both documented by Confluent itself
//! (`docs.confluent.io/cloud/current/security/authenticate/workload-identities/service-accounts/api-keys/overview.html`,
//! observed 2026-09-22):
//!
//! - **Current (created on or after 2026-07-30).** The literal `cflt`
//!   prefix followed by exactly 60 bytes of the standard base64 body
//!   alphabet ([`pattern::is_base64_body`], `[A-Za-z0-9+/]`), 64 bytes
//!   total. Confluent's own documentation states the final 6 of those 60
//!   bytes carry a base64-encoded CRC32 checksum of the rest, but does not
//!   publish the exact byte range or encoding padding rule the checksum
//!   covers precisely enough to recompute independently, and the checksum
//!   shares its enclosing body's alphabet, so (matching
//!   [`super::cloudflare::CLOUDFLARE`]'s and [`super::additional_providers::GRAFANA_CLOUD`]'s
//!   same "no distinguishing shape to check" precedent) this detector
//!   validates the `cflt`-prefixed exact length only, not the checksum
//!   value. A `cflt`-prefixed body that is not a genuine checksum is
//!   therefore an intentional false positive already accepted for every
//!   shape-only checksum precedent in this crate.
//! - **Legacy (created before 2026-07-30).** The same documentation states
//!   older secrets "may lack the `cflt` prefix but remain valid" -- a bare
//!   64-byte run of the same alphabet, with no marker of its own. This
//!   shape is indistinguishable by structure alone from any other opaque
//!   base64 blob, so it is never reported without same-line corroboration,
//!   the same reasoning [`super::twilio`] already documents for its own
//!   unmarked Auth Token and API Key Secret bodies. Two independently
//!   maintained tools, consulted only as external behavioral references per
//!   `AGENTS.md`, converge on requiring a case-insensitive `confluent`
//!   substring alongside this exact bare shape and never emit it
//!   unconditionally:
//!
//!   ```text
//!   gitleaks 8.30.1's confluent-secret-key rule (keyword-gated, `[a-z0-9]{64}` body):
//!     (?i)[\w.-]{0,50}?(?:confluent)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9]{64})(?:[\x60'"\s;]|\\[nr]|$)
//!   trufflehog 3.97.4's confluent detector (keyword-gated, `[a-zA-Z0-9+/]{64}` body):
//!     confluent\b...\b[a-zA-Z0-9+/]{64}\b
//!   ```
//!
//!   This detector follows the same corroborated policy: a bare 64-byte
//!   [`pattern::is_base64_body`] run is reported only when its line also
//!   carries a case-insensitive `confluent` substring, at
//!   [`Confidence::Medium`] -- the same weaker-heuristic tier
//!   [`super::twilio`]'s own keyword-only path uses, and, like that path,
//!   deliberately left out of [`policy::ALWAYS_REDACT_TYPES`] rather than
//!   promoted to an unconditional redact. gitleaks additionally requires
//!   the same keyword gate on the Access Token (Key ID) half of the pair;
//!   this detector does not emit any Key ID finding at all (see "Out of
//!   scope" below), so that half of its rule has no analog here.
//!
//!   A legacy candidate introduced by a hash-algorithm label
//!   ([`text::is_labelled_digest`]: `@sha256:`, `sha512=`, ...) is never
//!   reported (issue #744): `image: confluentinc/cp-server@sha256:<64 hex>`
//!   names Confluent but carries a container image digest, and Confluent
//!   documents no form in which an API secret follows such a label.
//!
//! No code from either tool is reproduced here; this module's matching and
//! context-gating logic is authored independently.
//!
//! ## Out of scope
//!
//! The API Key ID (the public, non-secret half of the pair -- Confluent's
//! own overview page states "It is not considered secret information",
//! example `ABCD1234567890AB`) is never itself a finding, matching the
//! issue's explicit scope: "Distinguish key identifiers from secret
//! values; do not classify cluster IDs, bootstrap hosts, or arbitrary
//! base64 as credentials." Confluent's documentation gives no published
//! character-class grammar for the Key ID beyond that one example; unlike
//! [`super::twilio`]'s Account SID and API Key SID, it is not used here even
//! as an internal context signal, since two tools' community-observed
//! shapes (`[A-Za-z0-9]{16}`) are a materially weaker evidence bar than
//! Twilio's own well-documented SID format. Cluster IDs (`lkc-...`),
//! Schema Registry and ksqlDB resource IDs (`lsrc-...`, `lksqlc-...`), and
//! bootstrap host strings all carry a `-` outside this module's alphabets
//! and are excluded automatically, with no special-casing needed.

use crate::detectors::additional_providers::KnownFormatProviderDetector;
use crate::detectors::pattern::{self, Alphabet, PrefixShape};
use crate::detectors::text;
use crate::error::DetectorFailure;
use crate::types::{ByteRange, Candidate, Confidence, Detector, DetectorContext, Specificity};

const SECRET_PREFIX: &str = "cflt";
/// The documented exact body length following the `cflt` prefix.
const PREFIXED_BODY_LEN: usize = 60;
/// The documented exact length of a legacy, unprefixed secret.
const LEGACY_SECRET_LEN: usize = 64;
const CONTEXT_KEYWORD: &str = "confluent";

/// [`pattern::is_base64_body`] widened to also admit `_` and `-`, so a
/// directly-glued wider identifier or a token-adjacent separator still
/// rejects a truncated candidate the way every other exact-length base64
/// shape in this crate's boundary checks does; see
/// [`pattern::RunLength::Exact`]'s own doc on the trailing check this
/// depends on.
fn is_confluent_secret_boundary(byte: u8) -> bool {
    pattern::is_base64_body(byte) || byte == b'_' || byte == b'-'
}

const PREFIXED_SIGNALS: [&str; 2] = ["confluent-documented-prefix", "base64-exact-length"];

/// The `cflt`-prefixed current-format secret: an exact `cflt` + 60-byte
/// base64-body shape, unconditionally [`Confidence::High`] and
/// [`Specificity::Provider`] -- no context needed, matching
/// [`super::additional_providers::NPM`] and
/// [`super::additional_providers::DIGITALOCEAN`]'s own "documented literal
/// prefix is evidence enough by itself" precedent.
pub(super) const CONFLUENT_CLOUD_API_SECRET: KnownFormatProviderDetector =
    KnownFormatProviderDetector::new(
        "confluent-cloud-api-secret",
        "confluent_cloud_api_secret",
        &[PrefixShape::exact(
            SECRET_PREFIX,
            PREFIXED_BODY_LEN,
            pattern::is_base64_body,
            &PREFIXED_SIGNALS,
        )],
        is_confluent_secret_boundary,
    );

/// Every line of `input` as a byte range excluding the terminating `\n`
/// (a trailing `\r` stays part of the line). Mirrors
/// [`super::twilio::lines`]; duplicated rather than shared, since neither
/// module depends on the other and each keeps its own context-gating logic
/// self-contained.
fn lines(input: &str) -> impl Iterator<Item = (usize, usize)> + '_ {
    let bytes = input.as_bytes();
    let mut start = 0usize;
    std::iter::from_fn(move || {
        if start > bytes.len() {
            return None;
        }
        let end = bytes[start..]
            .iter()
            .position(|&byte| byte == b'\n')
            .map_or(bytes.len(), |offset| start + offset);
        let line = (start, end);
        start = end + 1;
        Some(line)
    })
}

/// `true` when `needle` (ASCII, case-insensitive) occurs anywhere in `line`.
fn line_contains_ci(line: &str, needle: &str) -> bool {
    let bytes = line.as_bytes();
    needle.len() <= bytes.len()
        && (0..=bytes.len() - needle.len()).any(|pos| text::starts_with_ci(line, pos, needle))
}

/// Every non-overlapping, boundary-checked bare run of exactly
/// [`LEGACY_SECRET_LEN`] `alphabet` bytes, left to right.
fn scan_bare_legacy_runs(
    input: &str,
    alphabet: Alphabet,
    boundary: Alphabet,
) -> Vec<(usize, usize)> {
    let bytes = input.as_bytes();
    let ends = pattern::run_ends(bytes, alphabet);
    let mut matches = Vec::new();
    let mut start = 0;
    while start < bytes.len() {
        if !alphabet(bytes[start]) {
            start += 1;
            continue;
        }
        let run_end = ends[start];
        if run_end - start == LEGACY_SECRET_LEN
            && pattern::boundary_ok(bytes, start, run_end, boundary)
        {
            matches.push((start, run_end));
        }
        start = run_end;
    }
    matches
}

/// Detects a legacy (pre-`cflt`) Confluent Cloud API secret: a bare 64-byte
/// base64-body run on the same line as a case-insensitive `confluent`
/// substring. Never emitted without that context; see the module doc.
pub(super) struct ConfluentLegacyApiSecretDetector;

impl Detector for ConfluentLegacyApiSecretDetector {
    fn id(&self) -> &'static str {
        "confluent-cloud-api-secret-legacy"
    }

    fn detect(
        &self,
        input: &str,
        _context: &DetectorContext,
    ) -> Result<Vec<Candidate>, DetectorFailure> {
        let mut candidates = Vec::new();
        for (line_start, line_end) in lines(input) {
            let line = &input[line_start..line_end];
            let raw_matches =
                scan_bare_legacy_runs(line, pattern::is_base64_body, is_confluent_secret_boundary);
            if raw_matches.is_empty() || !line_contains_ci(line, CONTEXT_KEYWORD) {
                continue;
            }
            for (relative_start, relative_end) in raw_matches {
                if text::is_repeated_character_filler(&line[relative_start..relative_end])
                    || text::is_labelled_digest(line, relative_start)
                {
                    continue;
                }
                let Some(range) =
                    ByteRange::new(line_start + relative_start, line_start + relative_end)
                else {
                    continue;
                };
                candidates.push(
                    Candidate::new(
                        "confluent_cloud_api_secret_legacy",
                        Confidence::Medium,
                        range,
                    )
                    .with_specificity(Specificity::Provider)
                    .with_signals(["confluent-keyword-cooccurrence"]),
                );
            }
        }
        Ok(candidates)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Exactly [`PREFIXED_BODY_LEN`] base64-body bytes. Locally constructed
    /// synthetic value; never provider-issued.
    const PREFIXED_BODY: &str = "SYNTHETIC0REVOKED0PrefixedSecretValue0ABCDEFGHIJKLMNOPQRSTUV";
    const _: () = assert!(PREFIXED_BODY.len() == PREFIXED_BODY_LEN);

    /// Exactly [`LEGACY_SECRET_LEN`] base64-body bytes, carrying no
    /// `confluent` substring of its own so keyword-gating tests are clean.
    /// Locally constructed synthetic value; never provider-issued.
    const LEGACY_BODY: &str = "SYNTHETIC0REVOKED0LegacyBareSecretValue0NoPrefix0ABCDEFGHIJKLMNO";
    const _: () = assert!(LEGACY_BODY.len() == LEGACY_SECRET_LEN);

    /// A synthetic Confluent Cloud API Key ID (the non-secret half of the
    /// pair): 16 bytes, matching the documented example's shape. Never
    /// itself a finding; see the module doc.
    const KEY_ID: &str = "SYNTHETICKEYID01";
    const _: () = assert!(KEY_ID.len() == 16);

    fn prefixed_secret() -> String {
        format!("{SECRET_PREFIX}{PREFIXED_BODY}")
    }

    fn detect_prefixed(input: &str) -> Vec<Candidate> {
        CONFLUENT_CLOUD_API_SECRET
            .detect(input, &DetectorContext::new(input.len()))
            .unwrap()
    }

    fn detect_legacy(input: &str) -> Vec<Candidate> {
        ConfluentLegacyApiSecretDetector
            .detect(input, &DetectorContext::new(input.len()))
            .unwrap()
    }

    // -- Structural (`cflt`-prefixed) detector -----------------------------

    #[test]
    fn detects_a_prefixed_secret_with_no_context_needed() {
        let value = prefixed_secret();
        let candidates = detect_prefixed(&value);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].type_name(), "confluent_cloud_api_secret");
        assert_eq!(candidates[0].confidence(), Confidence::High);
        assert_eq!(candidates[0].effective_specificity(), Specificity::Provider);
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(0, value.len()).unwrap()
        );
    }

    #[test]
    fn rejects_a_prefixed_body_one_byte_short_of_the_documented_length() {
        let short_body = &PREFIXED_BODY[..PREFIXED_BODY_LEN - 1];
        assert!(detect_prefixed(&format!("{SECRET_PREFIX}{short_body}")).is_empty());
    }

    #[test]
    fn rejects_a_prefixed_body_one_byte_longer_than_the_documented_length() {
        assert!(detect_prefixed(&format!("{SECRET_PREFIX}{PREFIXED_BODY}a")).is_empty());
    }

    #[test]
    fn rejects_undocumented_near_miss_prefixes() {
        for input in [
            format!("clft{PREFIXED_BODY}"),
            format!("Cflt{PREFIXED_BODY}"),
            format!("cfltx{PREFIXED_BODY}"),
            format!("cfl{PREFIXED_BODY}"),
        ] {
            assert!(detect_prefixed(&input).is_empty(), "{input}");
        }
    }

    #[test]
    fn rejects_the_prefix_embedded_in_a_wider_identifier() {
        assert!(detect_prefixed(&format!("legacy_{}", prefixed_secret())).is_empty());
        assert!(detect_prefixed(&format!("{}_backup", prefixed_secret())).is_empty());
    }

    #[test]
    fn rejects_a_doc_style_placeholder_value() {
        assert!(detect_prefixed(&format!("{SECRET_PREFIX}${{CONFLUENT_API_SECRET}}")).is_empty());
    }

    #[test]
    fn never_flags_a_bare_key_id_by_itself() {
        assert!(detect_prefixed(KEY_ID).is_empty());
        assert!(detect_legacy(&format!("confluent {KEY_ID}")).is_empty());
    }

    #[test]
    fn rejects_benign_confluent_context_with_no_secret_present() {
        for input in [
            "bootstrap.servers=pkc-abc123.us-east-1.aws.confluent.cloud:9092",
            "cluster_id: lkc-abc123",
            "schema.registry.url=https://lsrc-abc123.us-east-1.aws.confluent.cloud",
        ] {
            assert!(detect_prefixed(input).is_empty(), "{input}");
            assert!(detect_legacy(input).is_empty(), "{input}");
        }
    }

    #[test]
    fn rejects_a_hash_algorithm_labelled_legacy_shaped_digest() {
        // Issue #744: a container image digest on a line naming Confluent.
        for input in [
            format!("image: confluentinc/cp-server@sha256:{LEGACY_BODY}"),
            format!("image: confluentinc/cp-server@SHA256:{LEGACY_BODY}"),
            format!("confluent-7.6.0.tar.gz sha256={LEGACY_BODY}"),
            format!("confluent checksum sha-256: {LEGACY_BODY}"),
        ] {
            assert!(detect_legacy(&input).is_empty(), "{input}");
        }
    }

    #[test]
    fn a_digest_label_does_not_hide_a_legacy_secret_after_an_ordinary_name() {
        let input = format!("CONFLUENT_API_SECRET={LEGACY_BODY}");
        let candidates = detect_legacy(&input);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].range().start(), 21);
        assert_eq!(candidates[0].range().end(), 85);
        let input = format!("confluent image@sha256:abc api_secret={LEGACY_BODY}");
        assert_eq!(detect_legacy(&input).len(), 1);
    }

    #[test]
    fn accepts_env_json_yaml_and_quoted_contexts() {
        let value = prefixed_secret();
        for input in [
            format!("CONFLUENT_CLOUD_API_SECRET={value}"),
            format!("{{\"apiSecret\": \"{value}\"}}"),
            format!("sasl.password: {value}"),
            format!("sasl.password=\"{value}\""),
        ] {
            let candidates = detect_prefixed(&input);
            assert_eq!(candidates.len(), 1, "{input}");
            let start = input.rfind(&value).unwrap();
            assert_eq!(
                candidates[0].range(),
                ByteRange::new(start, start + value.len()).unwrap(),
                "{input}"
            );
        }
    }

    #[test]
    fn finds_a_match_across_crlf_and_a_unicode_prefix() {
        let value = prefixed_secret();
        let input = format!("# \u{1F511} caf\u{e9}\r\n{value}\r\n");
        let candidates = detect_prefixed(&input);
        assert_eq!(candidates.len(), 1);
        let start = input.find(&value).unwrap();
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(start, start + value.len()).unwrap()
        );
    }

    #[test]
    fn finds_deterministic_findings_across_repeated_calls() {
        let value = prefixed_secret();
        assert_eq!(detect_prefixed(&value), detect_prefixed(&value));
    }

    #[test]
    fn reports_a_repeated_identical_value_once_per_occurrence() {
        let value = prefixed_secret();
        let input = format!("{value} {value}");
        assert_eq!(detect_prefixed(&input).len(), 2);
    }

    #[test]
    fn stays_bounded_over_a_long_run_of_near_miss_prefixes() {
        let short_body = &PREFIXED_BODY[..PREFIXED_BODY_LEN - 1];
        let input = format!("{SECRET_PREFIX}{short_body} ").repeat(10_000);
        assert_eq!(detect_prefixed(&input).len(), 0);
    }

    // -- Legacy (bare, keyword-gated) detector ------------------------------

    #[test]
    fn detects_a_legacy_secret_alongside_the_confluent_keyword_at_medium_confidence() {
        let input = format!("CONFLUENT_API_SECRET={LEGACY_BODY}");
        let candidates = detect_legacy(&input);
        assert_eq!(candidates.len(), 1);
        assert_eq!(
            candidates[0].type_name(),
            "confluent_cloud_api_secret_legacy"
        );
        assert_eq!(candidates[0].confidence(), Confidence::Medium);
        assert_eq!(candidates[0].effective_specificity(), Specificity::Provider);
        let start = input.rfind(LEGACY_BODY).unwrap();
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(start, start + LEGACY_BODY.len()).unwrap()
        );
    }

    #[test]
    fn rejects_a_bare_legacy_secret_with_no_context() {
        assert!(detect_legacy(LEGACY_BODY).is_empty());
    }

    #[test]
    fn rejects_a_legacy_secret_whose_context_is_on_a_different_line() {
        let input = format!("# confluent cluster credentials\n{LEGACY_BODY}\n");
        assert!(detect_legacy(&input).is_empty());
    }

    #[test]
    fn rejects_a_legacy_body_one_byte_short_or_long() {
        assert!(
            detect_legacy(&format!(
                "confluent {}",
                &LEGACY_BODY[..LEGACY_SECRET_LEN - 1]
            ))
            .is_empty()
        );
        assert!(detect_legacy(&format!("confluent {LEGACY_BODY}a")).is_empty());
    }

    #[test]
    fn rejects_a_repeated_character_filler_value() {
        assert!(detect_legacy(&format!("confluent {}", "a".repeat(LEGACY_SECRET_LEN))).is_empty());
    }

    #[test]
    fn rejects_an_environment_variable_reference() {
        assert!(detect_legacy("confluent CONFLUENT_API_SECRET=${CONFLUENT_API_SECRET}").is_empty());
    }

    #[test]
    fn matches_confluent_keyword_case_insensitively() {
        for keyword in ["Confluent", "CONFLUENT", "confluent"] {
            let input = format!("{keyword}_SECRET={LEGACY_BODY}");
            assert_eq!(detect_legacy(&input).len(), 1, "{keyword}");
        }
    }

    #[test]
    fn finds_a_qualified_legacy_match_across_crlf_and_a_unicode_prefix() {
        let input = format!("# \u{1F511} caf\u{e9}\r\nconfluent {LEGACY_BODY}\r\n");
        let candidates = detect_legacy(&input);
        assert_eq!(candidates.len(), 1);
        let start = input.rfind(LEGACY_BODY).unwrap();
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(start, start + LEGACY_BODY.len()).unwrap()
        );
    }

    #[test]
    fn finds_deterministic_legacy_findings_across_repeated_calls() {
        let input = format!("confluent {LEGACY_BODY}");
        assert_eq!(detect_legacy(&input), detect_legacy(&input));
    }

    #[test]
    fn stays_bounded_over_a_long_context_free_line_packed_with_candidates() {
        let input = format!("{LEGACY_BODY} ").repeat(10_000);
        assert_eq!(detect_legacy(&input).len(), 0);
    }
}
