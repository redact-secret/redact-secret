//! Replicate, Groq, xAI and `OpenRouter` inference API credential detection
//! (issue #727, Beta.8 wave 1).
//!
//! The grammars are frozen by issue #726
//! (`docs/audits/evidence/726/README.md`, `docs/specs/detector-families.md`);
//! this module implements those contracts and nothing broader. Every family is
//! one fixed prefix plus an exact-length run, so each is a single
//! [`PrefixShape::exact`] on the shared [`KnownFormatProviderDetector`]:
//! deterministic, offline, no context state, no checksum.
//!
//! | Family | Frozen shape | Route |
//! | --- | --- | --- |
//! | `replicate:api-token` | `r8_` + 37 from `[A-Za-z0-9_-]` (40 total) | documented |
//! | `groq:api-key` | `gsk_` + 52 from `[A-Za-z0-9]` | empirical |
//! | `xai:api-key` | `xai-` + 80 from `[A-Za-z0-9_-]` | empirical |
//! | `openrouter:api-key` | `sk-or-v1-` + 64 lowercase hex (73 total) | documented |
//!
//! The Replicate and xAI body alphabets are the provisional union
//! `[A-Za-z0-9_-]` (a `-` or `_` inside the body is therefore not a negative
//! twin); Groq's internal `WGdyb3FY` segment is deliberately not required.
//! `sk-or-mgmt-` (`OpenRouter` management keys), uppercase-hex `OpenRouter`
//! bodies, and any other width are intentional false negatives: a frozen
//! exact width buys precision, and format drift is recorded as a gap rather
//! than absorbed into a broader match.
//!
//! Bare matching is supported for all four: each prefix plus an exact width is
//! independently discriminative. The trade-off is that a value drawn from the
//! same alphabet and width but issued by another party is classified by prefix
//! alone; prefix-only lookalikes (`r8.im/` registry paths, model IDs, masks)
//! never reach the exact width and stay unclassified.
//!
//! Boundary: the whole value must not be a slice of a longer
//! `[A-Za-z0-9_-]` identifier. The shared boundary elsewhere is
//! `[A-Za-z0-9-]`; these prefixes contain `_`, and for the exact-width
//! alphanumeric bodies a glued `_suffix` is the wider-identifier case, so the
//! boundary here also includes `_`.
//!
//! Overlap: each candidate is [`Specificity::Provider`] at
//! [`Confidence::High`], so it wins overlaps against the generic, bearer and
//! vendor-prefix policy findings without any change to them.

use crate::detectors::additional_providers::KnownFormatProviderDetector;
use crate::detectors::pattern::{self, PrefixShape};

const REPLICATE_BODY_LEN: usize = 37;
const GROQ_BODY_LEN: usize = 52;
const XAI_BODY_LEN: usize = 80;
const OPENROUTER_BODY_LEN: usize = 64;

/// `[A-Za-z0-9_-]`: the Replicate and xAI body alphabet, and the boundary
/// alphabet: a value is never a slice of a wider identifier.
fn is_token_char(byte: u8) -> bool {
    pattern::is_alnum_dash(byte) || byte == b'_'
}

const REPLICATE_SIGNALS: [&str; 2] = ["replicate-documented-prefix", "exact-length-suffix"];
const GROQ_SIGNALS: [&str; 2] = ["groq-tool-corroborated-prefix", "exact-length-suffix"];
const XAI_SIGNALS: [&str; 2] = ["xai-documented-prefix", "exact-length-suffix"];
const OPENROUTER_SIGNALS: [&str; 2] = ["openrouter-documented-prefix", "lowercase-hex-suffix"];

pub(super) const REPLICATE: KnownFormatProviderDetector = KnownFormatProviderDetector::new(
    "replicate-api-token",
    "replicate_api_token",
    &[PrefixShape::exact(
        "r8_",
        REPLICATE_BODY_LEN,
        is_token_char,
        &REPLICATE_SIGNALS,
    )],
    is_token_char,
);

pub(super) const GROQ: KnownFormatProviderDetector = KnownFormatProviderDetector::new(
    "groq-api-key",
    "groq_api_key",
    &[PrefixShape::exact(
        "gsk_",
        GROQ_BODY_LEN,
        pattern::is_alnum,
        &GROQ_SIGNALS,
    )],
    is_token_char,
);

pub(super) const XAI: KnownFormatProviderDetector = KnownFormatProviderDetector::new(
    "xai-api-key",
    "xai_api_key",
    &[PrefixShape::exact(
        "xai-",
        XAI_BODY_LEN,
        is_token_char,
        &XAI_SIGNALS,
    )],
    is_token_char,
);

pub(super) const OPENROUTER: KnownFormatProviderDetector = KnownFormatProviderDetector::new(
    "openrouter-api-key",
    "openrouter_api_key",
    &[PrefixShape::exact(
        "sk-or-v1-",
        OPENROUTER_BODY_LEN,
        pattern::is_lower_hex,
        &OPENROUTER_SIGNALS,
    )],
    is_token_char,
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ByteRange, Candidate, Confidence, Detector, DetectorContext, Specificity};

    // Unmistakably synthetic bodies, none ever provider-issued. Each has the
    // exact frozen width; the const assertions keep them honest.
    const REPLICATE_BODY: &str = "SYNTHETIC_REVOKED-REPLICATE-TOKEN-001";
    const _: () = assert!(REPLICATE_BODY.len() == REPLICATE_BODY_LEN);
    const GROQ_BODY: &str = "SYNTHETICREVOKEDGROQAPIKEYVALUE000000000000000000001";
    const _: () = assert!(GROQ_BODY.len() == GROQ_BODY_LEN);
    const XAI_BODY: &str =
        "SYNTHETIC_REVOKED-XAI-API-KEY-VALUE-00000000000000000000000000000000000000000001";
    const _: () = assert!(XAI_BODY.len() == XAI_BODY_LEN);
    const OPENROUTER_BODY: &str =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const _: () = assert!(OPENROUTER_BODY.len() == OPENROUTER_BODY_LEN);

    fn detect(detector: &KnownFormatProviderDetector, input: &str) -> Vec<Candidate> {
        detector
            .detect(input, &DetectorContext::new(input.len()))
            .unwrap()
    }

    struct Family {
        detector: &'static KnownFormatProviderDetector,
        id: &'static str,
        type_name: &'static str,
        prefix: &'static str,
        body: &'static str,
    }

    const FAMILIES: [Family; 4] = [
        Family {
            detector: &REPLICATE,
            id: "replicate-api-token",
            type_name: "replicate_api_token",
            prefix: "r8_",
            body: REPLICATE_BODY,
        },
        Family {
            detector: &GROQ,
            id: "groq-api-key",
            type_name: "groq_api_key",
            prefix: "gsk_",
            body: GROQ_BODY,
        },
        Family {
            detector: &XAI,
            id: "xai-api-key",
            type_name: "xai_api_key",
            prefix: "xai-",
            body: XAI_BODY,
        },
        Family {
            detector: &OPENROUTER,
            id: "openrouter-api-key",
            type_name: "openrouter_api_key",
            prefix: "sk-or-v1-",
            body: OPENROUTER_BODY,
        },
    ];

    #[test]
    fn every_family_detects_the_exact_frozen_shape_at_provider_specificity() {
        for family in &FAMILIES {
            let token = format!("{}{}", family.prefix, family.body);
            let candidates = detect(family.detector, &token);
            assert_eq!(candidates.len(), 1, "{}", family.id);
            assert_eq!(family.detector.id(), family.id);
            assert_eq!(candidates[0].type_name(), family.type_name);
            assert_eq!(candidates[0].confidence(), Confidence::High);
            assert_eq!(candidates[0].effective_specificity(), Specificity::Provider);
            assert_eq!(
                candidates[0].range(),
                ByteRange::new(0, token.len()).unwrap()
            );
        }
    }

    #[test]
    fn the_range_covers_exactly_the_credential_inside_surrounding_text() {
        for family in &FAMILIES {
            let token = format!("{}{}", family.prefix, family.body);
            let input = format!("KEY=\"{token}\", next");
            let candidates = detect(family.detector, &input);
            assert_eq!(candidates.len(), 1, "{}", family.id);
            assert_eq!(
                candidates[0].range(),
                ByteRange::new(5, 5 + token.len()).unwrap(),
                "{}",
                family.id
            );
        }
    }

    #[test]
    fn a_body_one_byte_short_or_long_is_an_intentional_false_negative() {
        for family in &FAMILIES {
            let short = format!("{}{}", family.prefix, &family.body[..family.body.len() - 1]);
            let long = format!("{}{}0", family.prefix, family.body);
            assert!(detect(family.detector, &short).is_empty(), "{short}");
            assert!(detect(family.detector, &long).is_empty(), "{long}");
        }
    }

    #[test]
    fn a_glued_identifier_boundary_rejects_an_embedded_credential() {
        for family in &FAMILIES {
            let token = format!("{}{}", family.prefix, family.body);
            for input in [
                format!("x{token}"),
                format!("-{token}"),
                format!("_{token}"),
                format!("{token}_backup"),
                format!("{token}-1"),
            ] {
                assert!(detect(family.detector, &input).is_empty(), "{input}");
            }
        }
    }

    #[test]
    fn near_miss_prefixes_are_rejected() {
        for family in &FAMILIES {
            let prefix = family.prefix;
            let swapped: String = prefix
                .chars()
                .map(|c| match c {
                    '_' => '-',
                    '-' => '_',
                    other => other,
                })
                .collect();
            for input in [
                format!("{}{}", prefix.to_uppercase(), family.body),
                format!("{swapped}{}", family.body),
                format!("{}{}", &prefix[1..], family.body),
            ] {
                assert!(detect(family.detector, &input).is_empty(), "{input}");
            }
        }
    }

    #[test]
    fn replicate_and_xai_admit_dash_and_underscore_inside_the_body() {
        for family in [&FAMILIES[0], &FAMILIES[2]] {
            let mut body = family.body.to_owned();
            body.replace_range(4..6, "-_");
            let token = format!("{}{body}", family.prefix);
            assert_eq!(detect(family.detector, &token).len(), 1, "{token}");
        }
    }

    #[test]
    fn groq_rejects_dash_and_underscore_inside_the_body() {
        for byte in ["-", "_", "+", "/", "."] {
            let mut body = GROQ_BODY.to_owned();
            body.replace_range(4..5, byte);
            let token = format!("gsk_{body}");
            assert!(detect(&GROQ, &token).is_empty(), "{token}");
        }
    }

    #[test]
    fn openrouter_requires_lowercase_hex() {
        let upper = format!("sk-or-v1-{}", OPENROUTER_BODY.to_uppercase());
        let mut non_hex = OPENROUTER_BODY.to_owned();
        non_hex.replace_range(10..11, "g");
        let non_hex = format!("sk-or-v1-{non_hex}");
        for input in [upper, non_hex] {
            assert!(detect(&OPENROUTER, &input).is_empty(), "{input}");
        }
    }

    #[test]
    fn openrouter_management_keys_stay_unclaimed() {
        let input = format!("sk-or-mgmt-{OPENROUTER_BODY}");
        assert!(detect(&OPENROUTER, &input).is_empty());
    }

    #[test]
    fn public_lookalikes_and_placeholders_are_not_claimed() {
        for input in [
            "docker pull r8.im/owner/model@sha256:0123456789abcdef",
            "model: xai-grok-4-fast-reasoning",
            "model = \"gsk_model_name\"",
            "GROQ_API_KEY=gsk_********************************",
            "OPENROUTER_API_KEY=sk-or-v1-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
            "REPLICATE_API_TOKEN=r8_your_token_here",
            "XAI_API_KEY=xai-your-api-key-here",
        ] {
            for family in &FAMILIES {
                assert!(detect(family.detector, input).is_empty(), "{input}");
            }
        }
    }

    #[test]
    fn a_repeated_value_is_reported_once_per_occurrence() {
        for family in &FAMILIES {
            let token = format!("{}{}", family.prefix, family.body);
            let input = format!("{token} {token}");
            let candidates = detect(family.detector, &input);
            assert_eq!(candidates.len(), 2, "{}", family.id);
            let second = token.len() + 1;
            assert_eq!(
                candidates[1].range(),
                ByteRange::new(second, second + token.len()).unwrap()
            );
        }
    }

    #[test]
    fn the_families_do_not_claim_each_others_values() {
        for owner in &FAMILIES {
            let token = format!("{}{}", owner.prefix, owner.body);
            for other in &FAMILIES {
                if other.id != owner.id {
                    assert!(detect(other.detector, &token).is_empty(), "{}", other.id);
                }
            }
        }
    }
}
