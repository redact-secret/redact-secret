//! Helicone API key detection (issue #907, handoff
//! [`docs/audits/evidence/860/helicone.md`](https://github.com/redact-secret/redact-secret/blob/2816897f96c405c3eb8c87a0c70eba5df273c121/docs/audits/evidence/860/helicone.md)).
//!
//! | Prefix | Finding type |
//! | --- | --- |
//! | `sk-helicone-`, `sk-helicone-eu-`, `sk-helicone-rl-`, `sk-helicone-eu-rl-`, `sk-helicone-proxy-` | `helicone_api_key` (read-write) |
//! | `pk-helicone-`, `pk-helicone-eu-`, `pk-helicone-rl-`, `pk-helicone-eu-rl-` | `helicone_write_api_key` (write-only) |
//!
//! Body: four groups of exactly 7 `[a-z0-9]` joined by `-` (31 bytes). The
//! proxy key appends `-` and a lowercase-hex 8-4-4-4-12 UUID (68 bytes). All
//! T1: the provider's worker validation regexes state prefix, segments and
//! groups, and the dashboard and server generators agree (the proxy key under
//! R1). The generator's base32 library narrows each group to `[a-z2-7]`, but
//! ruling R8 rejects narrowing from a third-party library, so the provider's
//! own `[a-z0-9]` is enforced.
//!
//! `pk-` is a credential, not a public identifier: it writes requests and logs
//! into the org, and no provider source says it is safe to publish, so it is
//! redacted under its own type (a policy can downgrade it without touching
//! `sk-`). Longest prefix wins, so `sk-helicone-eu-rl-` is tried before
//! `sk-helicone-eu-`, and the reversed `-rl-eu-` order fails the group check.
//!
//! Unclaimed: the legacy bare `sk-` + 4×7 and customer-portal `-cp-` forms
//! (no provider token), `-gov` combinations (accepted by no worker regex),
//! uppercase keys, and a fifth group or glued suffix (boundary
//! `[A-Za-z0-9_-]`). A key inside the gateway URL path is delimited by `/`,
//! so it is claimed.

use crate::detectors::additional_providers::TypedKnownFormatProviderDetector;
use crate::detectors::pattern::{self, PrefixShape};

const GROUP_LEN: usize = 7;
const GROUPS: usize = 4;
/// Four groups plus three joining dashes.
const BODY_LEN: usize = GROUPS * GROUP_LEN + GROUPS - 1;
/// The body, a dash, and a 36-byte UUID.
const PROXY_BODY_LEN: usize = BODY_LEN + 1 + 36;

const KEY: &str = "helicone_api_key";
const WRITE_KEY: &str = "helicone_write_api_key";

/// `[A-Za-z0-9_-]`: the boundary alphabet.
fn is_token_char(byte: u8) -> bool {
    pattern::is_alnum_dash(byte) || byte == b'_'
}

/// `[a-z0-9-]`: the body run alphabet; the post checks place the dashes.
fn is_body_char(byte: u8) -> bool {
    pattern::is_lower_alnum(byte) || byte == b'-'
}

/// Four `[a-z0-9]{7}` groups joined by `-`.
fn groups_ok(body: &[u8]) -> bool {
    body.len() == BODY_LEN
        && body.iter().enumerate().all(|(index, &byte)| {
            if index % (GROUP_LEN + 1) == GROUP_LEN {
                byte == b'-'
            } else {
                pattern::is_lower_alnum(byte)
            }
        })
}

/// A lowercase-hex 8-4-4-4-12 UUID.
fn uuid_ok(uuid: &[u8]) -> bool {
    uuid.len() == 36
        && uuid.iter().enumerate().all(|(index, &byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                pattern::is_lower_hex(byte)
            }
        })
}

fn key_body_ok(bytes: &[u8], _start: usize, end: usize) -> bool {
    groups_ok(&bytes[end - BODY_LEN..end])
}

fn proxy_body_ok(bytes: &[u8], _start: usize, end: usize) -> bool {
    let body = &bytes[end - PROXY_BODY_LEN..end];
    groups_ok(&body[..BODY_LEN]) && body[BODY_LEN] == b'-' && uuid_ok(&body[BODY_LEN + 1..])
}

const SIGNALS: [&str; 2] = ["helicone-documented-prefix", "helicone-validator-groups"];

const fn key(prefix: &'static str) -> PrefixShape<'static> {
    PrefixShape::exact(prefix, BODY_LEN, is_body_char, &SIGNALS).with_post_check(key_body_ok)
}

pub(super) const HELICONE: TypedKnownFormatProviderDetector = TypedKnownFormatProviderDetector::new(
    "helicone-api-key",
    &[
        key("sk-helicone-"),
        key("sk-helicone-eu-"),
        key("sk-helicone-rl-"),
        key("sk-helicone-eu-rl-"),
        PrefixShape::exact("sk-helicone-proxy-", PROXY_BODY_LEN, is_body_char, &SIGNALS)
            .with_post_check(proxy_body_ok),
        key("pk-helicone-"),
        key("pk-helicone-eu-"),
        key("pk-helicone-rl-"),
        key("pk-helicone-eu-rl-"),
    ],
    &[
        KEY, KEY, KEY, KEY, KEY, WRITE_KEY, WRITE_KEY, WRITE_KEY, WRITE_KEY,
    ],
    is_token_char,
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ByteRange, Candidate, Confidence, Detector, DetectorContext, Specificity};

    const SEGMENTS: [&str; 4] = ["", "eu-", "rl-", "eu-rl-"];

    /// Synthetic `[a-z0-9]` filler, never provider-issued.
    fn group(seed: usize) -> String {
        const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
        (0..GROUP_LEN)
            .map(|i| char::from(ALPHABET[(i * 7 + seed * 11) % ALPHABET.len()]))
            .collect()
    }

    fn body() -> String {
        (0..GROUPS).map(group).collect::<Vec<_>>().join("-")
    }

    const UUID: &str = "0a1b2c3d-4e5f-4a6b-8c7d-0e1f2a3b4c5d";

    fn detect(input: &str) -> Vec<Candidate> {
        HELICONE
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
            format!("HELICONE_API_KEY={token}"),
            format!("export HELICONE_API_KEY=\"{token}\""),
            format!("Helicone-Auth: Bearer {token}"),
            format!("Authorization: Bearer {token}"),
            format!("X-API-Key: {token}"),
            format!("{{\"token\": \"{token}\"}}"),
            format!("{{\"api_key\": \"{token}\"}}"),
            format!("client = OpenAI(default_headers={{\"Helicone-Auth\": \"Bearer {token}\"}})"),
            format!("https://gateway.helicone.ai/{token}/v1/chat/completions"),
            format!("Here is my key {token} can you debug this?"),
            format!("The key is {token}."),
        ]
    }

    #[test]
    fn every_prefix_and_the_proxy_key_are_detected_in_every_context() {
        for (role, type_name) in [("sk", KEY), ("pk", WRITE_KEY)] {
            for segment in SEGMENTS {
                let token = format!("{role}-helicone-{segment}{}", body());
                for input in contexts(&token) {
                    assert_single(&input, &token, type_name);
                }
            }
        }
        let token = format!("sk-helicone-proxy-{}-{UUID}", body());
        assert_eq!(token.len(), 86);
        for input in contexts(&token) {
            assert_single(&input, &token, KEY);
        }
        assert_eq!(HELICONE.id(), "helicone-api-key");
    }

    #[test]
    fn group_twins_are_rejected() {
        let g: Vec<String> = (0..GROUPS).map(group).collect();
        let mut twins = vec![
            format!("{}-{}-{}-{}", &g[0][..6], g[1], g[2], g[3]),
            format!("{}0-{}-{}-{}", g[0], g[1], g[2], g[3]),
            format!("{}-{}-{}", g[0], g[1], g[2]),
            format!("{}-{}-{}-{}-{}", g[0], g[1], g[2], g[3], g[0]),
            format!("{}_{}_{}_{}", g[0], g[1], g[2], g[3]),
            format!("{}-{}-{}-{}", g[0].to_uppercase(), g[1], g[2], g[3]),
            format!(
                "{}-{}-{}-{}",
                g[0].replace(&g[0][..1], "!"),
                g[1],
                g[2],
                g[3]
            ),
        ];
        twins = twins
            .into_iter()
            .flat_map(|b| [format!("sk-helicone-{b}"), format!("pk-helicone-{b}")])
            .collect();
        let body = body();
        twins.extend([
            format!("sk-helicone-rl-eu-{body}"),
            format!("sk-heliconeX-{body}"),
            format!("SK-HELICONE-{body}"),
            format!("sk-helicone-gov-{body}"),
            format!("sk-helicone-cp-{body}"),
            format!("sk-{body}"),
            format!("sk-cp-{body}"),
            format!("xsk-helicone-{body}"),
            format!("sk-helicone-{body}a"),
            format!("sk-helicone-{body}_x"),
            format!("sk-helicone-proxy-{body}-0a1b2c3d-4e5f-4a6b-8c7d-0e1f2a3b4c5"),
            format!("sk-helicone-proxy-{body}-0A1B2C3D-4E5F-4A6B-8C7D-0E1F2A3B4C5D"),
            format!("sk-helicone-proxy-{body}-0a1b2c3d4e5f-4a6b-8c7d-0e1f2a3b4c5d0"),
            format!("pk-helicone-proxy-{body}-{UUID}"),
        ]);
        for input in twins {
            assert!(detect(&input).is_empty(), "{input}");
        }
    }

    #[test]
    fn placeholders_urls_and_env_references_are_not_claimed() {
        for input in [
            "HELICONE_API_KEY=sk-helicone-...",
            "HELICONE_API_KEY=${HELICONE_API_KEY}",
            "base_url=\"https://oai.helicone.ai/v1\"",
            "see https://docs.helicone.ai/helicone-headers/header-directory",
        ] {
            assert!(detect(input).is_empty(), "{input}");
        }
    }

    #[test]
    fn an_exact_width_placeholder_is_a_known_false_positive() {
        let input = "sk-helicone-xxxxxxx-xxxxxxx-xxxxxxx-xxxxxxx";
        assert_eq!(detect(input).len(), 1);
    }

    #[test]
    fn repeated_values_are_reported_once_each_and_a_glued_run_never() {
        let token = format!("pk-helicone-eu-{}", body());
        assert_eq!(detect(&format!("{token} {token}")).len(), 2);
        assert!(detect(&token.repeat(200)).is_empty());
    }
}
