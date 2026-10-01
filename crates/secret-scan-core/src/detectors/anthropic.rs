//! Anthropic token detection.
//!
//! Mirrors `src/detectors/anthropic.ts`.

use crate::detectors::pattern::{self, RunLength};
use crate::detectors::prefilter::Literals;
use crate::error::DetectorFailure;
use crate::types::{ByteRange, Candidate, Confidence, Detector, DetectorContext, Specificity};

/// `(prefix, finding type)`. `sk-ant-api03-` keeps the pre-existing
/// `anthropic_api_key` type name: it is the only one of the three with
/// prior, independently evidenced fixtures, so splitting the other two
/// prefixes into their own types does not rename it too (the same rationale
/// `decision-map-github-token-families-onto-independent-finding-types` uses
/// for `ghp_`/`github_token`).
const PREFIXES: [(&str, &str); 3] = [
    ("sk-ant-api03-", "anthropic_api_key"),
    ("sk-ant-api01-", "anthropic_enterprise_api_key"),
    ("sk-ant-admin01-", "anthropic_admin_api_key"),
];

/// Requires one of three provider-documented versioned Anthropic key prefixes
/// and a substantial suffix. This prioritizes precision; older, shortened, or
/// newly versioned formats are intentionally false negatives until their exact
/// shape is supported.
///
/// - `sk-ant-api03-`: Claude API key. Finding type `anthropic_api_key`.
/// - `sk-ant-api01-`: Claude Enterprise organization key for any scope set
///   selected at creation (user management, Compliance, Analytics, Spend
///   Limits — Compliance Access Key is one such scope, not the whole type);
///   the finding type names the general Enterprise class, not one scope.
///   Finding type `anthropic_enterprise_api_key`.
/// - `sk-ant-admin01-`: Console Admin API key, full access to every
///   Admin-API endpoint. Finding type `anthropic_admin_api_key`.
///
/// The prefixes are provider documented (T1). The body grammar is not: the
/// `>= 20` byte `[A-Za-z0-9_-]` floor is a deliberate superset of the
/// scanner-corroborated 93 bytes plus `AA` (T2), applied identically to all
/// three prefixes, and no length or `AA` tail is asserted. Each prefix maps
/// to its own finding type (issues #775, #776, #862) so policy can treat the
/// admin and enterprise classes differently from the plain API key.
pub(super) struct AnthropicTokenDetector;

impl Detector for AnthropicTokenDetector {
    fn id(&self) -> &'static str {
        "anthropic-token"
    }

    fn detect(
        &self,
        input: &str,
        _context: &DetectorContext,
    ) -> Result<Vec<Candidate>, DetectorFailure> {
        let mut candidates = Vec::new();
        let prefixes: Vec<&str> = PREFIXES.iter().map(|(prefix, _)| *prefix).collect();
        let ranges = pattern::scan_prefixed_runs(
            input,
            &prefixes,
            RunLength::AtLeast(20),
            pattern::is_alnum_dash,
            pattern::is_alnum_dash,
        );
        let bytes = input.as_bytes();
        for (start, end) in ranges {
            let Some(range) = ByteRange::new(start, end) else {
                continue;
            };
            // `scan_prefixed_runs` only ever returns a match starting with
            // one of the prefixes it was given, so exactly one arm always
            // applies; a range matching none falls through to the loop's
            // next iteration rather than panicking on an assumption that
            // should always hold.
            for (prefix, type_name) in PREFIXES {
                if bytes[start..].starts_with(prefix.as_bytes()) {
                    candidates.push(
                        Candidate::built_in(type_name, Confidence::High, range)
                            .with_specificity(Specificity::Provider)
                            .with_signal_pack(crate::types::signal_pack!(
                                "anthropic-versioned-prefix",
                                "opaque-suffix"
                            )),
                    );
                    break;
                }
            }
        }
        Ok(candidates)
    }
}

/// The literals one of which every `anthropic-token` candidate contains, for the
/// shared prefilter (`super::prefilter`, issue #983).
pub(super) const REQUIRED_LITERALS: &[Literals] = &[Literals::Prefixes(&PREFIXES)];

#[cfg(test)]
mod tests {
    use super::*;

    fn detect(input: &str) -> Vec<Candidate> {
        AnthropicTokenDetector
            .detect(input, &DetectorContext::new(input.len()))
            .unwrap()
    }

    #[test]
    fn detects_the_synthetic_fixture() {
        let input = "sk-ant-api03-SYNTHETIC_REVOKED_ANTHROPIC_KEY";
        let candidates = detect(input);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].type_name(), "anthropic_api_key");
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(0, input.len()).unwrap()
        );
    }

    #[test]
    fn rejects_an_unsupported_version_prefix() {
        assert_eq!(
            detect("sk-ant-api02-SYNTHETIC_REVOKED_ANTHROPIC_KEY").len(),
            0
        );
    }

    #[test]
    fn rejects_a_short_suffix() {
        assert_eq!(detect("sk-ant-api03-short").len(), 0);
    }

    #[test]
    fn accepts_a_doc_style_placeholder_built_from_valid_alphabet_characters() {
        let input = format!("sk-ant-api03-{}", "x".repeat(20));
        assert_eq!(detect(&input).len(), 1);
    }

    #[test]
    fn rejects_a_prefix_embedded_in_a_wider_benign_identifier() {
        // A leading alnum/dash byte right before `sk-ant-api03-` means this
        // is a truncated slice of a longer identifier, not a
        // boundary-delimited credential.
        let input = format!("mysk-ant-api03-{}", "SYNTHETIC_REVOKED_ANTHROPIC_KEY");
        assert_eq!(detect(&input).len(), 0);
    }

    #[test]
    fn a_trailing_comma_does_not_get_folded_into_or_suppress_the_match() {
        let token = format!("sk-ant-api03-{}", "SYNTHETIC_REVOKED_KEY_VALUE");
        let input = format!("Rotate {token}, then redeploy.");
        let candidates = detect(&input);
        assert_eq!(candidates.len(), 1);
        let start = "Rotate ".len();
        let end = start + token.len();
        assert_eq!(candidates[0].range(), ByteRange::new(start, end).unwrap());
    }

    #[test]
    fn an_unversioned_prefix_is_a_documented_false_negative() {
        // No detector claims this: openai-token excludes the whole
        // `sk-ant-` namespace and anthropic-token requires the versioned
        // prefix. See the module doc comment for the accepted tradeoff.
        let input = "sk-ant-SYNTHETIC_REVOKED_LEGACY_ANTHROPIC_KEY_VALUE";
        assert_eq!(detect(input).len(), 0);
    }

    #[test]
    fn rejects_a_future_version_marker_not_yet_documented() {
        // Only the exact `api03` segment is supported; a plausible future
        // version is not speculatively accepted alongside it.
        let input = format!("sk-ant-api04-{}", "SYNTHETIC_REVOKED_ANTHROPIC_KEY");
        assert_eq!(detect(&input).len(), 0);
    }

    #[test]
    fn rejects_a_near_prefix_variant_using_underscore_instead_of_dash() {
        // Prose about the shape of the prefix, not the literal
        // dash-delimited prefix itself, must not be classified.
        let input = format!("sk_ant_api03_{}", "SYNTHETIC_REVOKED_ANTHROPIC_KEY");
        assert_eq!(detect(&input).len(), 0);
    }

    #[test]
    fn reports_each_occurrence_of_a_repeated_value_independently() {
        let token = format!("sk-ant-api03-{}", "SYNTHETIC_REVOKED_KEY_VALUE");
        let input = format!("{token} {token}");
        let candidates = detect(&input);
        assert_eq!(candidates.len(), 2);
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(0, token.len()).unwrap()
        );
        let second_start = token.len() + 1;
        assert_eq!(
            candidates[1].range(),
            ByteRange::new(second_start, second_start + token.len()).unwrap()
        );
    }

    // Deterministic synthetic body built at runtime so no realistic-looking
    // literal key sits in source. 93 alphabet bytes plus `AA`, the scanner
    // shape; independently generated, never derived from a real key.
    fn synthetic_body() -> String {
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-";
        let mut state: u32 = 0x5EED_0862;
        let mut body = String::new();
        for _ in 0..93 {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            body.push(ALPHABET[(state >> 24) as usize % ALPHABET.len()] as char);
        }
        body.push_str("AA");
        body
    }

    /// `(prefix, finding type)`, the two prefixes split from the shared
    /// `anthropic_api_key` type (issues #775, #776).
    const NEW_PREFIXES: [(&str, &str); 2] = [
        ("sk-ant-api01-", "anthropic_enterprise_api_key"),
        ("sk-ant-admin01-", "anthropic_admin_api_key"),
    ];

    fn assert_single_exact_typed(input: &str, token: &str, expected_type: &str) {
        let candidates = detect(input);
        assert_eq!(candidates.len(), 1, "input: {input}");
        assert_eq!(candidates[0].type_name(), expected_type);
        let start = input.find(token).unwrap();
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(start, start + token.len()).unwrap()
        );
    }

    fn assert_single_exact(input: &str, token: &str) {
        assert_single_exact_typed(input, token, "anthropic_api_key");
    }

    #[test]
    fn detects_each_new_prefix_in_every_context_with_exact_spans() {
        for (prefix, expected_type) in NEW_PREFIXES {
            let token = format!("{prefix}{}", synthetic_body());
            let contexts = [
                token.clone(),
                format!("ANTHROPIC_ADMIN_KEY={token}\n"),
                format!("export ANTHROPIC_COMPLIANCE_ACCESS_KEY=\"{token}\"\n"),
                format!("anthropic_admin_key: {token}\n"),
                format!("{{\"admin_api_key\": \"{token}\"}}"),
                format!("client = Anthropic(api_key=\"{token}\")"),
                format!("const c = new Anthropic({{ apiKey: '{token}' }});"),
                format!("2026-09-27T00:00:00Z INFO org sync key={token} status=200"),
                format!(
                    "{{\"tool\":\"bash\",\"input\":{{\"command\":\"curl -H 'x-api-key: {token}' https://example.invalid\"}}}}"
                ),
                format!("Rotate {token}, then redeploy."),
                format!("({token})"),
            ];
            for input in &contexts {
                assert_single_exact_typed(input, &token, expected_type);
            }
        }
    }

    #[test]
    fn new_prefixes_accept_the_same_twenty_byte_floor_as_api03() {
        for (prefix, _) in NEW_PREFIXES {
            assert_eq!(detect(&format!("{prefix}{}", "A".repeat(20))).len(), 1);
            assert_eq!(detect(&format!("{prefix}{}", "A".repeat(19))).len(), 0);
        }
    }

    #[test]
    fn new_prefixes_reject_a_short_body_placeholders_and_prose() {
        for (prefix, _) in NEW_PREFIXES {
            assert_eq!(detect(&format!("{prefix}short")).len(), 0);
            assert_eq!(detect(&format!("{prefix}...")).len(), 0);
            assert_eq!(detect(&format!("{prefix}<YOUR_KEY>")).len(), 0);
            assert_eq!(detect(&format!("the {prefix} prefix")).len(), 0);
        }
    }

    #[test]
    fn new_prefixes_reject_wrong_prefix_twins() {
        let body = synthetic_body();
        for prefix in [
            "sk-ant-admin02-",
            "sk-ant-admin-",
            "sk-ant-api02-",
            "sk-ant-oat01-",
            "sk-ant-ort01-",
            "sk_ant_admin01_",
            "sk_ant_api01_",
            "SK-ANT-ADMIN01-",
            "SK-ANT-API01-",
        ] {
            assert_eq!(detect(&format!("{prefix}{body}")).len(), 0, "{prefix}");
        }
    }

    #[test]
    fn new_prefixes_reject_embedding_in_a_longer_token() {
        let body = synthetic_body();
        for (prefix, _) in NEW_PREFIXES {
            assert_eq!(detect(&format!("my{prefix}{body}")).len(), 0);
            assert_eq!(detect(&format!("x-{prefix}{body}")).len(), 0);
        }
    }

    #[test]
    fn a_trailing_alphabet_run_stays_part_of_the_span_and_a_delimiter_ends_it() {
        for (prefix, expected_type) in NEW_PREFIXES {
            let token = format!("{prefix}{}", synthetic_body());
            let longer = format!("{token}extra");
            assert_single_exact_typed(&longer, &longer, expected_type);
            let delimited = format!("{token}.tail");
            assert_single_exact_typed(&delimited, &token, expected_type);
        }
    }

    #[test]
    fn a_body_with_a_character_outside_the_alphabet_ends_the_span_there() {
        for (prefix, expected_type) in NEW_PREFIXES {
            let head = "A".repeat(25);
            let input = format!("{prefix}{head}!{}", "B".repeat(25));
            assert_single_exact_typed(&input, &format!("{prefix}{head}"), expected_type);
        }
    }

    #[test]
    fn the_three_prefixes_are_reported_independently_in_one_input() {
        let body = synthetic_body();
        let a = format!("sk-ant-api03-{body}");
        let b = format!("sk-ant-api01-{body}");
        let c = format!("sk-ant-admin01-{body}");
        let input = format!("{a} {b} {c}");
        let candidates = detect(&input);
        assert_eq!(candidates.len(), 3);
        let mut start = 0;
        let expected_types = [
            "anthropic_api_key",
            "anthropic_enterprise_api_key",
            "anthropic_admin_api_key",
        ];
        for ((candidate, token), expected_type) in
            candidates.iter().zip([&a, &b, &c]).zip(expected_types)
        {
            assert_eq!(candidate.type_name(), expected_type);
            assert_eq!(
                candidate.range(),
                ByteRange::new(start, start + token.len()).unwrap()
            );
            start += token.len() + 1;
        }
    }

    #[test]
    fn api03_behavior_is_unchanged_for_the_full_scanner_shape() {
        let token = format!("sk-ant-api03-{}", synthetic_body());
        assert_single_exact(&token, &token);
        assert_eq!(detect(&format!("sk-ant-api03-{}", "A".repeat(19))).len(), 0);
        assert_eq!(detect(&format!("sk-ant-api03-{}", "A".repeat(20))).len(), 1);
    }
}
