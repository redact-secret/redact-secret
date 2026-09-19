//! `OpenAI` API key detection.
//!
//! Every key `OpenAI` issues carries the literal marker `T3BlbkFJ` (the
//! base64 encoding of the ASCII text `OpenAI`) between two opaque segments
//! of a source-documented length. Issue #368 froze that shape as the default
//! contract (`docs/decisions/2026-09-17-freeze-openai-api-key-grammar.md`),
//! replacing the earlier "recognized prefix plus a 20-byte minimum suffix"
//! rule that accepted any long enough `sk-` value:
//!
//! ```text
//! sk-<20 [A-Za-z0-9]>T3BlbkFJ<20 [A-Za-z0-9]>                     legacy
//! sk-proj-<74|58 [A-Za-z0-9_-]>T3BlbkFJ<74|58 [A-Za-z0-9_-]>     project
//! sk-svcacct-<74|58 [A-Za-z0-9_-]>T3BlbkFJ<74|58 [A-Za-z0-9_-]>  service account
//! sk-admin-<74|58 [A-Za-z0-9_-]>T3BlbkFJ<74|58 [A-Za-z0-9_-]>    admin
//! ```
//!
//! Each variant is validated on its own: an explicit `proj-`/`svcacct-`/
//! `admin-` namespace owns the value outright, so a malformed namespaced
//! body is rejected rather than re-read as a legacy key. Anthropic's
//! `sk-ant-` namespace is excluded explicitly (its `-` already breaks the
//! legacy alphabet) so the more specific detector keeps owning it. The
//! `regex` crate cannot be used here — this crate is dependency-free — so
//! [`scan`] composes the shape from the shared `pattern` primitives.

use crate::detectors::pattern::{self, Alphabet};
use crate::error::DetectorFailure;
use crate::types::{ByteRange, Candidate, Confidence, Detector, DetectorContext, Specificity};

const PREFIX: &str = "sk-";
/// base64 of the ASCII text `OpenAI`, present in every issued key.
const MARKER: &str = "T3BlbkFJ";
const ANTHROPIC_PREFIX: &str = "ant-";
/// Namespaces that share the 74/58-byte segmented body grammar.
const NAMESPACED_PREFIXES: [&str; 3] = ["proj-", "svcacct-", "admin-"];
const LEGACY_SEGMENT_LENS: [usize; 1] = [20];
/// Tried in this order, the same order the reference rule lists them.
const NAMESPACED_SEGMENT_LENS: [usize; 2] = [74, 58];
const LEGACY_ALPHABET: Alphabet = pattern::is_alnum;
const NAMESPACED_ALPHABET: Alphabet = pattern::is_alnum_dash;
/// A key is never a slice of a wider `[A-Za-z0-9_-]` identifier.
const BOUNDARY: Alphabet = pattern::is_alnum_dash;

/// Requires a recognized `sk-` form whose body is `<segment>T3BlbkFJ<segment>`
/// with both segments at a documented length for that form. A value that
/// merely starts with `sk-` and is long enough is not classified; a
/// contextual assignment carrying one can still surface through
/// `generic-token`. Future prefixes and lengths `OpenAI` has not documented
/// are missed until the contract is revised.
pub(super) struct OpenAiTokenDetector;

impl Detector for OpenAiTokenDetector {
    fn id(&self) -> &'static str {
        "openai-token"
    }

    fn detect(
        &self,
        input: &str,
        _context: &DetectorContext,
    ) -> Result<Vec<Candidate>, DetectorFailure> {
        let mut candidates = Vec::new();
        for (start, end) in scan(input) {
            let Some(range) = ByteRange::new(start, end) else {
                continue;
            };
            candidates.push(
                Candidate::new("openai_api_key", Confidence::High, range)
                    .with_specificity(Specificity::Provider)
                    .with_signals(["openai-prefix", "openai-marker"]),
            );
        }
        Ok(candidates)
    }
}

/// Every boundary-delimited key, left to right. A failed attempt advances by
/// one byte; a shape-complete attempt advances past the whole value whether
/// or not the boundary check keeps it, so a wider identifier that embeds a
/// key never yields a second, shorter reading of the same bytes.
fn scan(input: &str) -> Vec<(usize, usize)> {
    let bytes = input.as_bytes();
    let legacy_ends = pattern::run_ends(bytes, LEGACY_ALPHABET);
    let namespaced_ends = pattern::run_ends(bytes, NAMESPACED_ALPHABET);
    let mut matches = Vec::new();
    let mut start = 0;
    while start < bytes.len() {
        if !bytes[start..].starts_with(PREFIX.as_bytes()) {
            start += 1;
            continue;
        }
        let body_start = start + PREFIX.len();
        let Some(end) = variant_end(bytes, &legacy_ends, &namespaced_ends, body_start) else {
            start += 1;
            continue;
        };
        if pattern::boundary_ok(bytes, start, end, BOUNDARY) {
            matches.push((start, end));
        }
        start = end;
    }
    matches
}

/// The end of the key whose body starts at `body_start`, validated under
/// exactly one variant's grammar: the explicit namespace when one is
/// present, otherwise the legacy form. There is no fallback between them.
fn variant_end(
    bytes: &[u8],
    legacy_ends: &[usize],
    namespaced_ends: &[usize],
    body_start: usize,
) -> Option<usize> {
    for literal in NAMESPACED_PREFIXES {
        if bytes[body_start..].starts_with(literal.as_bytes()) {
            return segmented_end(
                bytes,
                namespaced_ends,
                body_start + literal.len(),
                &NAMESPACED_SEGMENT_LENS,
            );
        }
    }

    if bytes[body_start..].starts_with(ANTHROPIC_PREFIX.as_bytes()) {
        return None;
    }
    segmented_end(bytes, legacy_ends, body_start, &LEGACY_SEGMENT_LENS)
}

/// `<left>T3BlbkFJ<right>` where the whole body is one maximal run of the
/// variant's alphabet (the marker's own bytes belong to every alphabet), the
/// left segment is one of `lens`, and whatever the run leaves after the
/// marker is also one of `lens`. Because the run is maximal, a body whose
/// right segment is followed by more alphabet bytes has the wrong right
/// length and is rejected, never truncated to fit.
fn segmented_end(bytes: &[u8], ends: &[usize], body_start: usize, lens: &[usize]) -> Option<usize> {
    let body_end = ends[body_start];
    for &left in lens {
        let marker_start = body_start + left;
        let marker_end = marker_start + MARKER.len();
        if marker_end > body_end {
            continue;
        }
        if &bytes[marker_start..marker_end] != MARKER.as_bytes() {
            continue;
        }
        let right = body_end - marker_end;
        if lens.contains(&right) {
            return Some(body_end);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `(benchmark id suffix, input, expected ranges)`.
    type Case = (&'static str, String, Vec<(usize, usize)>);

    /// A `len`-byte segment that cycles `label`, unmistakably synthetic and
    /// entirely inside the namespaced alphabet.
    fn segment(label: &str, len: usize) -> String {
        label.chars().cycle().take(len).collect()
    }

    fn legacy(left: &str, right: &str) -> String {
        format!("{PREFIX}{left}{MARKER}{right}")
    }

    fn namespaced(namespace: &str, left: &str, right: &str) -> String {
        format!("{PREFIX}{namespace}{left}{MARKER}{right}")
    }

    /// The canonical synthetic keys, written out verbatim so
    /// `docs/coverage/detector-inventory.json` and the registry tests can
    /// quote the same bytes.
    const LEGACY_KEY: &str = "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";
    const PROJECT_KEY: &str = "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";
    const SERVICE_ACCOUNT_KEY: &str = "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";
    const ADMIN_KEY: &str = "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";

    const LEGACY_LEFT: &str = "SYNTHETICREVOKED0001";
    const LEGACY_RIGHT: &str = "SYNTHETICREVOKED0002";
    const LEFT_LABEL: &str = "SYNTHETIC_REVOKED_LEFT_";
    const RIGHT_LABEL: &str = "SYNTHETIC_REVOKED_RIGHT_";

    fn left(len: usize) -> String {
        segment(LEFT_LABEL, len)
    }

    fn right(len: usize) -> String {
        segment(RIGHT_LABEL, len)
    }

    fn detect(input: &str) -> Vec<Candidate> {
        OpenAiTokenDetector
            .detect(input, &DetectorContext::new(input.len()))
            .unwrap()
    }

    fn ranges(input: &str) -> Vec<(usize, usize)> {
        detect(input)
            .iter()
            .map(|candidate| (candidate.range().start(), candidate.range().end()))
            .collect()
    }

    #[test]
    fn the_canonical_literals_are_the_documented_shapes() {
        assert_eq!(LEGACY_KEY, legacy(LEGACY_LEFT, LEGACY_RIGHT));
        assert_eq!(LEGACY_KEY.len(), 3 + 20 + 8 + 20);
        assert_eq!(PROJECT_KEY, namespaced("proj-", &left(74), &right(74)));
        assert_eq!(PROJECT_KEY.len(), 8 + 74 + 8 + 74);
        assert_eq!(
            SERVICE_ACCOUNT_KEY,
            namespaced("svcacct-", &left(74), &right(74))
        );
        assert_eq!(SERVICE_ACCOUNT_KEY.len(), 11 + 74 + 8 + 74);
        assert_eq!(ADMIN_KEY, namespaced("admin-", &left(74), &right(74)));
        assert_eq!(ADMIN_KEY.len(), 9 + 74 + 8 + 74);
    }

    #[test]
    fn detects_the_legacy_form_with_exact_metadata() {
        let candidates = detect(LEGACY_KEY);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].type_name(), "openai_api_key");
        assert_eq!(candidates[0].confidence(), Confidence::High);
        assert_eq!(candidates[0].effective_specificity(), Specificity::Provider);
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(0, LEGACY_KEY.len()).unwrap()
        );
    }

    #[test]
    fn detects_each_namespaced_form_independently() {
        for key in [PROJECT_KEY, SERVICE_ACCOUNT_KEY, ADMIN_KEY] {
            assert_eq!(ranges(key), vec![(0, key.len())], "{key}");
        }
    }

    #[test]
    fn detects_every_variant_in_the_same_input_without_one_suppressing_another() {
        let input = format!("{LEGACY_KEY}\n{PROJECT_KEY}\n{SERVICE_ACCOUNT_KEY}\n{ADMIN_KEY}");
        let mut cursor = 0;
        let mut expected = Vec::new();
        for key in [LEGACY_KEY, PROJECT_KEY, SERVICE_ACCOUNT_KEY, ADMIN_KEY] {
            expected.push((cursor, cursor + key.len()));
            cursor += key.len() + 1;
        }
        assert_eq!(ranges(&input), expected);
    }

    #[test]
    fn accepts_58_byte_segments_and_mixed_segment_lengths() {
        for (left_len, right_len) in [(58, 58), (74, 58), (58, 74)] {
            let key = namespaced("proj-", &left(left_len), &right(right_len));
            assert_eq!(ranges(&key), vec![(0, key.len())], "{left_len}/{right_len}");
        }
    }

    #[test]
    fn rejects_a_mutated_marker() {
        let mutated = LEGACY_KEY.replace(MARKER, "T3BlbkFK");
        assert_ne!(mutated, LEGACY_KEY);
        assert!(ranges(&mutated).is_empty());
        let lowercased = PROJECT_KEY.replace(MARKER, &MARKER.to_ascii_lowercase());
        assert!(ranges(&lowercased).is_empty());
    }

    #[test]
    fn rejects_a_legacy_segment_one_byte_off_on_either_side() {
        for (left_len, right_len) in [(19, 20), (21, 20), (20, 19), (20, 21)] {
            let key = legacy(
                &segment(LEGACY_LEFT, left_len),
                &segment(LEGACY_RIGHT, right_len),
            );
            assert!(ranges(&key).is_empty(), "{left_len}/{right_len}");
        }
    }

    #[test]
    fn rejects_a_legacy_segment_containing_an_underscore_or_dash() {
        // The legacy alphabet is `[A-Za-z0-9]` only.
        for byte in ['_', '-'] {
            let mut left = LEGACY_LEFT.to_owned();
            left.replace_range(5..6, &byte.to_string());
            assert!(ranges(&legacy(&left, LEGACY_RIGHT)).is_empty(), "{byte}");
        }
    }

    #[test]
    fn rejects_a_namespaced_segment_one_byte_off_from_either_documented_length() {
        for (left_len, right_len) in [
            (73, 74),
            (75, 74),
            (74, 73),
            (74, 75),
            (57, 58),
            (59, 58),
            (58, 57),
            (58, 59),
        ] {
            for namespace in NAMESPACED_PREFIXES {
                let key = namespaced(namespace, &left(left_len), &right(right_len));
                assert!(ranges(&key).is_empty(), "{namespace}{left_len}/{right_len}");
            }
        }
    }

    #[test]
    fn an_explicit_namespace_never_falls_back_to_the_legacy_branch() {
        // A legacy-shaped body under an explicit namespace is malformed for
        // that namespace and is not re-read as `sk-` + legacy body.
        for namespace in NAMESPACED_PREFIXES {
            let key = namespaced(namespace, LEGACY_LEFT, LEGACY_RIGHT);
            assert!(ranges(&key).is_empty(), "{namespace}");
        }
    }

    #[test]
    fn rejects_the_marker_less_broad_shapes_the_previous_rule_accepted() {
        for input in [
            "sk-proj-SYNTHETIC_REVOKED_CONFORMANCE_KEY",
            "sk-SYNTHETIC_REVOKED_CONFORMANCE_KEY",
            "sk-svcacct-SYNTHETIC_REVOKED_CONFORMANCE_KEY",
            "sk-proj-xxxxxxxxxxxxxxxxxxxx",
        ] {
            assert!(ranges(input).is_empty(), "{input}");
        }
    }

    #[test]
    fn a_placeholder_built_entirely_from_valid_bytes_in_the_documented_shape_is_still_classified() {
        // Indistinguishable from a real key's shape: an accepted tradeoff.
        let key = namespaced("proj-", &"x".repeat(74), &"x".repeat(74));
        assert_eq!(ranges(&key), vec![(0, key.len())]);
    }

    #[test]
    fn excludes_the_anthropic_namespace() {
        for input in [
            format!("sk-ant-{}", "SYNTHETIC_REVOKED_ANTHROPIC_LOOKALIKE"),
            format!("sk-ant-api03-{}", "SYNTHETIC_REVOKED_ANTHROPIC_KEY"),
            // Even a marker-bearing body under `sk-ant-` stays Anthropic's.
            format!(
                "sk-ant-{}{MARKER}{}",
                segment("SYNTHETICREVOKED", 16),
                LEGACY_RIGHT
            ),
        ] {
            assert!(ranges(&input).is_empty(), "{input}");
        }
    }

    #[test]
    fn does_not_exclude_a_legacy_key_that_merely_starts_with_ant_without_the_dash() {
        let key = legacy(&format!("ant{}", &LEGACY_LEFT[3..]), LEGACY_RIGHT);
        assert_eq!(ranges(&key), vec![(0, key.len())]);
    }

    #[test]
    fn the_single_source_service_namespace_is_unsupported() {
        let key = namespaced("service-", &left(74), &right(74));
        assert!(ranges(&key).is_empty());
    }

    #[test]
    fn rejects_a_key_embedded_in_a_wider_identifier_on_either_side() {
        for input in [
            format!("legacy{PROJECT_KEY}"),
            format!("{PROJECT_KEY}-tail"),
            format!("{PROJECT_KEY}_tail"),
            format!("{PROJECT_KEY}0"),
            format!("x{LEGACY_KEY}"),
            format!("{LEGACY_KEY}-x"),
            format!("{LEGACY_KEY}_x"),
            format!("{LEGACY_KEY}0"),
        ] {
            assert!(ranges(&input).is_empty(), "{input}");
        }
    }

    #[test]
    fn punctuation_and_quotes_bound_the_match_without_being_folded_into_it() {
        let input = format!("Rotate {PROJECT_KEY}, then redeploy.");
        assert_eq!(ranges(&input), vec![(7, 7 + PROJECT_KEY.len())]);
        let quoted = format!("{{\"apiKey\": \"{LEGACY_KEY}\"}}");
        assert_eq!(ranges(&quoted), vec![(12, 12 + LEGACY_KEY.len())]);
    }

    #[test]
    fn rejects_near_prefix_and_case_variants() {
        let underscored = PROJECT_KEY.replacen("sk-proj-", "sk_proj_", 1);
        assert!(ranges(&underscored).is_empty());
        let uppercased = PROJECT_KEY.replacen("sk-proj-", "SK-PROJ-", 1);
        assert!(ranges(&uppercased).is_empty());
    }

    #[test]
    fn reports_each_occurrence_of_a_repeated_value_independently() {
        let input = format!("{LEGACY_KEY} {LEGACY_KEY}");
        let second = LEGACY_KEY.len() + 1;
        assert_eq!(
            ranges(&input),
            vec![(0, LEGACY_KEY.len()), (second, second + LEGACY_KEY.len())]
        );
    }

    #[test]
    fn unicode_and_crlf_surroundings_shift_only_the_byte_offsets() {
        let input = format!("# \u{1F511} reviewed format\r\n{SERVICE_ACCOUNT_KEY}\n\r\n");
        let start = "# \u{1F511} reviewed format\r\n".len();
        assert_eq!(start, 24);
        assert_eq!(
            ranges(&input),
            vec![(start, start + SERVICE_ACCOUNT_KEY.len())]
        );
    }

    /// The shapes issue #368 attached, with the ranges it expects: each
    /// negative twin differs from its paired positive in one structural
    /// property (the marker, or the left segment's length). Issue #419
    /// replaced the original snapshot's real-looking random bytes with the
    /// same `SYNTHETIC…`-marked construction already used by the canonical
    /// literals above, keeping every byte length exactly as reviewed.
    #[test]
    fn issue_368_twins_are_rejected_and_their_paired_positives_preserved() {
        const UNICODE_CRLF: &str = "# \u{1F511} reviewed format\r\n";
        let legacy_positive = LEGACY_KEY.to_string();
        let legacy_twin = format!("{PREFIX}{LEGACY_LEFT}T3BlbkFK{LEGACY_RIGHT}");
        let project_positive = PROJECT_KEY.to_string();
        let project_twin = format!("{PREFIX}proj-{}{MARKER}{}", left(73), right(74));
        let service_positive = SERVICE_ACCOUNT_KEY.to_string();
        let service_twin = format!("{PREFIX}svcacct-{}{MARKER}{}", left(73), right(74));

        let cases: [Case; 12] = [
            (
                "legacy-plain",
                format!("{legacy_positive}\n\n"),
                vec![(0, 51)],
            ),
            ("legacy-plain-twin", format!("{legacy_twin}\n\n"), vec![]),
            (
                "legacy-unicode-crlf",
                format!("{UNICODE_CRLF}{legacy_positive}\n\r\n"),
                vec![(24, 75)],
            ),
            (
                "legacy-unicode-crlf-twin",
                format!("{UNICODE_CRLF}{legacy_twin}\n\r\n"),
                vec![],
            ),
            (
                "proj-plain",
                format!("{project_positive}\n\n"),
                vec![(0, 164)],
            ),
            ("proj-plain-twin", format!("{project_twin}\n\n"), vec![]),
            (
                "proj-unicode-crlf",
                format!("{UNICODE_CRLF}{project_positive}\n\r\n"),
                vec![(24, 188)],
            ),
            (
                "proj-unicode-crlf-twin",
                format!("{UNICODE_CRLF}{project_twin}\n\r\n"),
                vec![],
            ),
            (
                "svcacct-plain",
                format!("{service_positive}\n\n"),
                vec![(0, 167)],
            ),
            ("svcacct-plain-twin", format!("{service_twin}\n\n"), vec![]),
            (
                "svcacct-unicode-crlf",
                format!("{UNICODE_CRLF}{service_positive}\n\r\n"),
                vec![(24, 191)],
            ),
            (
                "svcacct-unicode-crlf-twin",
                format!("{UNICODE_CRLF}{service_twin}\n\r\n"),
                vec![],
            ),
        ];
        for (id, input, expected) in cases {
            assert_eq!(ranges(&input), expected, "openai-token-{id}");
        }
    }
}
