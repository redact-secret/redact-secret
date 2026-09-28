//! Composio API key detection (issue #909, handoff
//! `docs/audits/evidence/860/composio.md`).
//!
//! | Shape | Finding type |
//! | --- | --- |
//! | `ak_` + exactly 20 `[A-Za-z0-9_-]`, at least one uppercase and one lowercase letter | `composio_project_api_key` |
//! | `oak_` + exactly 20 `[A-Za-z0-9_-]` | `composio_org_api_key` |
//! | `uak_` + exactly 43 `[A-Za-z0-9_-]` | `composio_user_api_key` |
//!
//! Prefixes are T1 from provider docs, the `OpenAPI` spec and SDK constants.
//! Widths and the nanoid alphabet are T1 from a dated provider-staff
//! statement (2026-09-17, ruling R3) that nothing newer contradicts; the
//! `ak_` + 20 width also matches the provider's `OpenAPI` example, and the
//! provider CLI's own redaction regexes corroborate the alphabet (R2). A CLI
//! code comment showing `uak_` + 20 is T2 under ruling R6 and does not
//! override the staff statement, so `uak_` is 43 only.
//!
//! ## The `ak_` short-prefix guard
//!
//! `ak_` is short and its alphabet includes `_` and `-`, so `ak_` plus a
//! 20-byte `snake_case` or kebab-case identifier would otherwise match. An
//! `ak_` body must contain at least one uppercase and one lowercase letter
//! (maintainer-accepted): for a uniform nanoid body the false-negative cost
//! is about 6e-5, and every all-lowercase or all-uppercase identifier is
//! removed. A mixed-case 20-byte identifier after `ak_` still matches (an
//! accepted false positive). `oak_` and `uak_` are distinctive enough without
//! the guard.
//!
//! ## Boundaries
//!
//! The boundary alphabet `[A-Za-z0-9_-]` equals the body alphabet, so an exact
//! width plus the boundary rejects every over-long or glued run. `oak_` and
//! `uak_` contain `ak_`, but the byte before that `ak_` is `o` or `u`, which
//! fails the leading boundary, and longest prefix wins at the true start, so an
//! `ak_` finding never fires inside an `oak_`, `uak_`, `cak_` or `xak_` value.
//! A nanoid body may begin or end in `-` or `_`; the exact width handles it.
//! Unclaimed: `ck_` and `cak_` keys (no known shape), bkend.ai's `ak_` + 64
//! hex, and `uak_` at any width but 43.

use crate::detectors::additional_providers::TypedKnownFormatProviderDetector;
use crate::detectors::pattern::{self, PrefixShape};

const KEY_LEN: usize = 20;
const USER_KEY_LEN: usize = 43;

/// `[A-Za-z0-9_-]`: the nanoid body alphabet and the boundary alphabet.
fn is_nanoid_char(byte: u8) -> bool {
    pattern::is_alnum_dash(byte) || byte == b'_'
}

/// The `ak_` guard: the body holds at least one uppercase and one lowercase
/// letter.
fn mixed_case(bytes: &[u8], _start: usize, end: usize) -> bool {
    let body = &bytes[end - KEY_LEN..end];
    body.iter().any(u8::is_ascii_uppercase) && body.iter().any(u8::is_ascii_lowercase)
}

const SIGNALS: [&str; 2] = ["composio-documented-prefix", "composio-staff-stated-length"];

pub(super) const COMPOSIO: TypedKnownFormatProviderDetector = TypedKnownFormatProviderDetector::new(
    "composio-api-key",
    &[
        PrefixShape::exact("ak_", KEY_LEN, is_nanoid_char, &SIGNALS).with_post_check(mixed_case),
        PrefixShape::exact("oak_", KEY_LEN, is_nanoid_char, &SIGNALS),
        PrefixShape::exact("uak_", USER_KEY_LEN, is_nanoid_char, &SIGNALS),
    ],
    &[
        "composio_project_api_key",
        "composio_org_api_key",
        "composio_user_api_key",
    ],
    is_nanoid_char,
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ByteRange, Candidate, Confidence, Detector, DetectorContext, Specificity};

    // Independently authored synthetic bodies, never provider-issued.
    const PROJECT_BODY: &str = "Synthetic_Revoked-Ak";
    const ORG_BODY: &str = "Synthetic_Revoked-Oa";
    const USER_BODY: &str = "Synthetic_Revoked-ComposioUserKeyFixture-01";
    const _: () = assert!(PROJECT_BODY.len() == KEY_LEN);
    const _: () = assert!(ORG_BODY.len() == KEY_LEN);
    const _: () = assert!(USER_BODY.len() == USER_KEY_LEN);

    const TYPES: [(&str, &str, &str); 3] = [
        ("ak_", PROJECT_BODY, "composio_project_api_key"),
        ("oak_", ORG_BODY, "composio_org_api_key"),
        ("uak_", USER_BODY, "composio_user_api_key"),
    ];

    fn detect(input: &str) -> Vec<Candidate> {
        COMPOSIO
            .detect(input, &DetectorContext::new(input.len()))
            .unwrap()
    }

    fn assert_single(input: &str, token: &str, type_name: &str) {
        let candidates = detect(input);
        assert_eq!(candidates.len(), 1, "{input}");
        let start = input.find(token).unwrap();
        assert_eq!(candidates[0].type_name(), type_name, "{input}");
        assert_eq!(candidates[0].confidence(), Confidence::High);
        assert_eq!(candidates[0].effective_specificity(), Specificity::Provider);
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(start, start + token.len()).unwrap(),
            "{input}"
        );
    }

    fn contexts(token: &str) -> Vec<String> {
        vec![
            token.to_owned(),
            format!("COMPOSIO_API_KEY={token}"),
            format!("COMPOSIO_ORG_API_KEY={token}"),
            format!("export COMPOSIO_API_KEY=\"{token}\""),
            format!("Authorization: Bearer {token}"),
            format!("x-api-key: {token}"),
            format!("x-org-api-key: {token}"),
            format!("{{\"token\": \"{token}\"}}"),
            format!("{{\"api_key\": \"{token}\"}}"),
            format!("composio = Composio(api_key=\"{token}\")"),
            format!(
                "{{\"mcpServers\": {{\"composio\": {{\"env\": {{\"COMPOSIO_API_KEY\": \"{token}\"}}}}}}}}"
            ),
            format!("Here is my key {token} can you debug this?"),
            format!("The key is {token}."),
        ]
    }

    #[test]
    fn every_prefix_is_detected_in_every_context() {
        for (prefix, body, type_name) in TYPES {
            let token = format!("{prefix}{body}");
            for input in contexts(&token) {
                assert_single(&input, &token, type_name);
            }
        }
        assert_eq!(COMPOSIO.id(), "composio-api-key");
    }

    #[test]
    fn bodies_starting_or_ending_in_dash_or_underscore_are_exact() {
        for edge in ["-", "_"] {
            for (prefix, body, type_name) in TYPES {
                let ending = format!("{prefix}{}{edge}", &body[..body.len() - 1]);
                let starting = format!("{prefix}{edge}{}", &body[1..]);
                for token in [ending, starting] {
                    for input in [
                        format!("\"{token}\""),
                        format!("{token},"),
                        format!("{token} next"),
                        token.clone(),
                    ] {
                        assert_single(&input, &token, type_name);
                    }
                }
            }
        }
    }

    #[test]
    fn width_and_alphabet_twins_are_rejected() {
        let mut twins = Vec::new();
        for (prefix, body, _) in TYPES {
            twins.push(format!("{prefix}{}", &body[..body.len() - 1]));
            twins.push(format!("{prefix}{body}0"));
            for byte in [".", "+"] {
                let mut value = body.to_owned();
                value.replace_range(5..6, byte);
                twins.push(format!("{prefix}{value}"));
            }
        }
        // `uak_` is 43 only: a 20-byte or 42/44-byte body is unclaimed.
        twins.push(format!("uak_{PROJECT_BODY}"));
        twins.push(format!("uak_{USER_BODY}x"));
        for input in twins {
            assert!(detect(&input).is_empty(), "{input}");
        }
    }

    #[test]
    fn the_ak_guard_rejects_single_case_bodies_only_for_ak() {
        let lower = "synthetic_revoked-ak";
        let upper = "SYNTHETIC_REVOKED-AK";
        assert!(detect(&format!("ak_{lower}")).is_empty());
        assert!(detect(&format!("ak_{upper}")).is_empty());
        assert!(detect("ak_0123456789-0123456").is_empty());
        // `oak_` has no guard.
        assert_eq!(detect(&format!("oak_{lower}")).len(), 1);
    }

    #[test]
    fn ak_never_fires_inside_a_longer_prefix() {
        for prefix in ["oak_", "uak_", "cak_", "xak_", "AK_", "ak-", "_ak_", "-ak_"] {
            let input = format!("{prefix}{PROJECT_BODY}");
            let candidates = detect(&input);
            assert!(
                candidates
                    .iter()
                    .all(|c| c.type_name() != "composio_project_api_key"),
                "{input}"
            );
        }
        let org = format!("oak_{ORG_BODY}");
        let candidates = detect(&org);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].type_name(), "composio_org_api_key");
    }

    #[test]
    fn benign_values_are_not_claimed() {
        for input in [
            "COMPOSIO_API_KEY=ak_...".to_owned(),
            "ck_...".to_owned(),
            "ck_test_dummy".to_owned(),
            "cak_e2e_agent".to_owned(),
            format!("ak_{}", "0123456789abcdef".repeat(4)),
            "let ak_session_token_value_x = 1;".to_owned(),
            "project pr_abcdefghijkl".to_owned(),
        ] {
            assert!(detect(&input).is_empty(), "{input}");
        }
    }

    #[test]
    fn repeated_values_are_reported_once_each_and_a_glued_run_never() {
        let token = format!("ak_{PROJECT_BODY}");
        assert_eq!(detect(&format!("{token} {token}")).len(), 2);
        assert!(detect(&token.repeat(300)).is_empty());
    }
}
