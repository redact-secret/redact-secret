//! Axiom API token and personal access token detection (issue #1035,
//! handoff `docs/audits/evidence/1014/axiom.md`).
//!
//! | Shape | Finding type | Evidence |
//! | --- | --- | --- |
//! | `xaat-` + lowercase-hex UUID (8-4-4-4-12, 41 in total) | `axiom_api_token` | `axiom-go` `IsAPIToken` runtime `HasPrefix` (R6); UUID layout and lowercase hex from a docs response example and SDK fixtures (R5). T1 |
//! | `xapt-` + the same UUID body | `axiom_personal_token` | `axiom-go` `IsPersonalToken` (R6); same layout (R5). T1 |
//!
//! An API token ingests or queries datasets depending on how it was
//! created; a personal access token has the user's full console and API
//! access, so it is its own type (the GitHub one-type-per-family
//! precedent).
//!
//! The prefix is load-bearing: a bare UUID is never claimed. An uppercase
//! UUID body was not observed in any provider source and is an accepted
//! false negative, as is a token that does not follow the UUID layout; the
//! handoff recommends (but does not require) a structure-only issuance check
//! to settle both. `xaat-your-api-token` and other placeholders fail the
//! layout. Boundary `[A-Za-z0-9_-]`: a glued token is an accepted false
//! negative; an unrelated `xaat-`/`xapt-` + lowercase UUID is the accepted
//! false positive (none is known).

use crate::detectors::additional_providers::TypedKnownFormatProviderDetector;
use crate::detectors::pattern::{self, PrefixShape};

const UUID_LEN: usize = 36;
/// Body offsets of the four UUID group separators.
const DASHES: [usize; 4] = [8, 13, 18, 23];

const API_TOKEN: &str = "axiom_api_token";
const PERSONAL_TOKEN: &str = "axiom_personal_token";

const SIGNALS: [&str; 2] = ["axiom-sdk-prefix", "axiom-documented-layout"];

/// The body is a lowercase-hex UUID: `-` exactly at the group separators,
/// `[0-9a-f]` everywhere else.
fn has_uuid_layout(bytes: &[u8], _start: usize, end: usize) -> bool {
    bytes[end - UUID_LEN..end]
        .iter()
        .enumerate()
        .all(|(offset, &byte)| {
            if DASHES.contains(&offset) {
                byte == b'-'
            } else {
                pattern::is_lower_hex(byte)
            }
        })
}

pub(super) const AXIOM: TypedKnownFormatProviderDetector = TypedKnownFormatProviderDetector::new(
    "axiom-token",
    &[
        PrefixShape::exact("xaat-", UUID_LEN, pattern::is_hex_or_dash, &SIGNALS)
            .with_post_check(has_uuid_layout),
        PrefixShape::exact("xapt-", UUID_LEN, pattern::is_hex_or_dash, &SIGNALS)
            .with_post_check(has_uuid_layout),
    ],
    &[API_TOKEN, PERSONAL_TOKEN],
    pattern::is_alnum_dash,
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ByteRange, Candidate, Confidence, Detector, DetectorContext, Specificity};

    const LOWER_HEX: &[u8] = b"0123456789abcdef";

    /// Synthetic low-entropy hex filler, never provider-issued.
    fn filler(len: usize, seed: usize) -> String {
        (0..len)
            .map(|i| char::from(LOWER_HEX[(i * 7 + seed * 13 + i / 5) % LOWER_HEX.len()]))
            .collect()
    }

    fn uuid_with(groups: [usize; 5], seed: usize) -> String {
        groups
            .iter()
            .enumerate()
            .map(|(i, &len)| filler(len, seed + i))
            .collect::<Vec<_>>()
            .join("-")
    }

    fn uuid(seed: usize) -> String {
        uuid_with([8, 4, 4, 4, 12], seed)
    }

    fn detect(input: &str) -> Vec<Candidate> {
        AXIOM
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
            format!("AXIOM_TOKEN={token}"),
            format!("export AXIOM_TOKEN=\"{token}\""),
            format!("Authorization: Bearer {token}"),
            format!("{{\"token\": \"{token}\"}}"),
            format!("[sinks.axiom]\ntype = \"axiom\"\ntoken = \"{token}\"\n"),
            format!("password: {token}"),
            format!("Here is my token {token} can you debug this?"),
            format!("The token is {token}."),
        ]
    }

    #[test]
    fn api_and_personal_tokens_are_detected_in_every_context() {
        let api = format!("xaat-{}", uuid(1));
        let personal = format!("xapt-{}", uuid(2));
        assert_eq!(api.len(), 41);
        for input in contexts(&api) {
            assert_single(&input, &api, API_TOKEN);
        }
        for input in contexts(&personal) {
            assert_single(&input, &personal, PERSONAL_TOKEN);
        }
        assert_eq!(AXIOM.id(), "axiom-token");
    }

    #[test]
    fn near_miss_twins_are_rejected() {
        let body = uuid(3);
        let good = format!("xaat-{body}");
        let mut upper = good.clone();
        upper.replace_range(10..11, "A");
        let mut non_hex = good.clone();
        non_hex.replace_range(10..11, "g");
        for input in [
            format!("xaat-{}", uuid_with([7, 4, 4, 4, 12], 3)),
            format!("xaat-{}", uuid_with([8, 4, 4, 4, 13], 3)),
            format!("xaat-{}", uuid_with([8, 5, 4, 4, 11], 3)),
            format!("xaat-{}", body.replace('-', "")),
            upper,
            non_hex,
            format!("xaat_{body}"),
            format!("xabt-{body}"),
            format!("XAAT-{body}"),
            format!("x{good}"),
            format!("_{good}"),
            format!("{good}x"),
            format!("{good}-1"),
        ] {
            assert!(detect(&input).is_empty(), "{input}");
        }
    }

    #[test]
    fn benign_axiom_text_is_not_claimed() {
        for input in [
            "AXIOM_TOKEN=xaat-your-api-token".to_owned(),
            "AXIOM_TOKEN=xaat-xxxxxxxxxx-xxxxxxxxx-xxxxxxx".to_owned(),
            format!("request id {}", uuid(4)),
            "AXIOM_TOKEN=${AXIOM_TOKEN}".to_owned(),
            "AXIOM_ORG_ID=acme-corp-a1b2".to_owned(),
        ] {
            assert!(detect(&input).is_empty(), "{input}");
        }
    }

    #[test]
    fn repeated_tokens_are_reported_once_each_and_a_glued_run_never() {
        let token = format!("xapt-{}", uuid(5));
        assert_eq!(detect(&format!("{token} {token}")).len(), 2);
        assert!(detect(&token.repeat(200)).is_empty());
        assert!(detect(&"xaat-".repeat(10_000)).is_empty());
    }
}
