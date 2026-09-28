//! Convex deployment and admin key detection (issue #912, handoff
//! `docs/audits/evidence/860/convex.md`).
//!
//! Convex's Apache-2.0 backend (`get-convex/convex-backend` at `032e81e`)
//! is the issuer for self-hosted deployments and fixes the key layout:
//! `format_admin_key` builds `<name>|<encrypted part>`, and the dashboard
//! may add a "superficial" `<type>:` lead. The encrypted part is the
//! version byte `01`, a nonce, the AES-GCM-SIV ciphertext of a small proto
//! and a tag, hex-encoded with `const_hex::encode`: lowercase hex, always
//! even, and 74–96 characters for every proto the generator can produce.
//!
//! | Part | Grammar |
//! | --- | --- |
//! | Typed lead (optional) | `prod:` or `dev:` + a cloud name `[a-z]+-[a-z]+-[0-9]+`; or `preview:` / `project:` + `<slug>:<slug>` |
//! | Untyped name | `[a-z0-9][a-z0-9-]{0,62}` (self-hosted instance name, default `convex-self-hosted`) |
//! | Separator | exactly one `\|` |
//! | Body | `01` + lowercase hex, even length 74–96 in total |
//!
//! One finding type, `convex_deployment_key`, spans the whole key, lead and
//! name included: the name is public, but it is part of the one string the
//! CLI consumes, and redacting it too means the key cannot be reassembled
//! from a partial redaction.
//!
//! The current cloud deploy-key body (`eyJ2…`) is issuance-gated (ruling R4:
//! a truncated docs example fixes the prefix only) and is deliberately not
//! claimed yet. `convex` is not in `generic-token`'s dedicated-provider
//! deferral list, so `CONVEX_DEPLOY_KEY=` keeps its contextual finding for
//! that shape (issue #919).
//!
//! The anchor is the `|` separator plus the body, not a leading literal, so
//! this is a bespoke scan rather than a [`super::pattern::PrefixShape`]
//! table:
//!
//! 1. find each `|` directly followed by `01`;
//! 2. read the lowercase-hex run after it (capped at 97 bytes), require an
//!    even length of 74–96 and no `[A-Za-z0-9_-]` byte after it;
//! 3. walk left over the name, then optionally over a typed lead; the key
//!    must start at the input start or after a byte outside
//!    `[A-Za-z0-9_:-]`.
//!
//! A walk that reaches no valid start yields no finding: a glued lead
//! (`xprod:`), an underscore name (`bold_hyena_681`), a `prod:` or `dev:`
//! lead before a non-cloud name, and a slug outside the bounded class are
//! intentional false negatives. A separator that is not a type lead
//! (`prod;<name>|01…`) leaves the name unprefixed, so the key is still
//! claimed as an untyped key, from the name on.
//!
//! Cost: one scan for `|`, then a right walk of at most 97 bytes and a left
//! walk of at most 8 + 64 + 1 + 64 bytes per candidate, so a whole scan
//! stays linear with no per-line state.

use crate::error::DetectorFailure;
use crate::types::{ByteRange, Candidate, Confidence, Detector, DetectorContext, Specificity};

const TYPE_NAME: &str = "convex_deployment_key";
const BODY_LEAD: &[u8] = b"01";
const BODY_MIN: usize = 74;
const BODY_MAX: usize = 96;
/// `[a-z0-9][a-z0-9-]{0,62}`: the bounded instance-name and slug class.
const NAME_MAX: usize = 63;

const SEPARATOR_SIGNAL: &str = "convex-documented-separator";
const BODY_SIGNAL: &str = "convex-generator-hex-envelope";
const TYPED_SIGNAL: &str = "convex-typed-lead";

/// `[a-z0-9-]`: bytes a name or slug run is read over.
fn is_name_byte(byte: u8) -> bool {
    byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'
}

/// `[A-Za-z0-9_:-]`: bytes that make a key start part of a wider token.
fn is_leading_glue(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b':' | b'-')
}

/// `[A-Za-z0-9_-]`: bytes that make the body part of a wider identifier.
fn is_trailing_glue(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-')
}

fn is_lower_hex(byte: u8) -> bool {
    byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
}

/// `true` when the key may start at `start`: the input start, or after a
/// byte outside `[A-Za-z0-9_:-]`.
fn starts_cleanly(bytes: &[u8], start: usize) -> bool {
    start == 0 || !is_leading_glue(bytes[start - 1])
}

/// The start of the maximal `[a-z0-9-]` run ending at `end`, reading at
/// most `NAME_MAX + 1` bytes, or `None` when the run is empty, longer than
/// [`NAME_MAX`], or starts with `-`.
fn name_start(bytes: &[u8], end: usize) -> Option<usize> {
    let len = bytes[..end]
        .iter()
        .rev()
        .take(NAME_MAX + 1)
        .take_while(|&&byte| is_name_byte(byte))
        .count();
    if len == 0 || len > NAME_MAX {
        return None;
    }
    let start = end - len;
    (bytes[start] != b'-').then_some(start)
}

/// `[a-z]+-[a-z]+-[0-9]+`: a Convex cloud deployment name.
fn is_cloud_name(name: &[u8]) -> bool {
    let mut parts = name.split(|&byte| byte == b'-');
    let (Some(first), Some(second), Some(third), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    !first.is_empty()
        && first.iter().all(u8::is_ascii_lowercase)
        && !second.is_empty()
        && second.iter().all(u8::is_ascii_lowercase)
        && !third.is_empty()
        && third.iter().all(u8::is_ascii_digit)
}

/// The start of a typed lead whose `:` sits at `colon`, before the name at
/// `name_from..separator`, or `None`.
fn typed_start(bytes: &[u8], colon: usize, name_from: usize, separator: usize) -> Option<usize> {
    // The type word (`prod`, `dev`) or the team slug, under the name bound.
    let word_start = name_start(bytes, colon)?;
    let word = &bytes[word_start..colon];
    if matches!(word, b"prod" | b"dev") {
        return (is_cloud_name(&bytes[name_from..separator]) && starts_cleanly(bytes, word_start))
            .then_some(word_start);
    }
    // `preview:` / `project:` + `<team-slug>:<project-slug>`: `word` is the
    // team slug and the name is the project slug.
    let type_colon = word_start.checked_sub(1)?;
    if bytes[type_colon] != b':' {
        return None;
    }
    let type_start = bytes[..type_colon]
        .iter()
        .rev()
        .take(b"project".len() + 1)
        .take_while(|&&byte| byte.is_ascii_lowercase())
        .count();
    let type_start = type_colon - type_start;
    (matches!(&bytes[type_start..type_colon], b"preview" | b"project")
        && starts_cleanly(bytes, type_start))
    .then_some(type_start)
}

/// `(start, end, typed)` of a key whose `|` sits at `separator`, or `None`.
fn match_at(bytes: &[u8], separator: usize) -> Option<(usize, usize, bool)> {
    let body_start = separator + 1;
    if !bytes.get(body_start..)?.starts_with(BODY_LEAD) {
        return None;
    }
    let body_len = bytes[body_start..]
        .iter()
        .take(BODY_MAX + 1)
        .take_while(|&&byte| is_lower_hex(byte))
        .count();
    if !(BODY_MIN..=BODY_MAX).contains(&body_len) || body_len % 2 != 0 {
        return None;
    }
    let end = body_start + body_len;
    if bytes.get(end).copied().is_some_and(is_trailing_glue) {
        return None;
    }

    let name_from = name_start(bytes, separator)?;
    if starts_cleanly(bytes, name_from) {
        return Some((name_from, end, false));
    }
    if bytes[name_from - 1] != b':' {
        return None;
    }
    let start = typed_start(bytes, name_from - 1, name_from, separator)?;
    Some((start, end, true))
}

/// Recognizes Convex `<name>|01<hex>` deployment and admin keys, with an
/// optional typed lead.
pub(super) struct ConvexDeploymentKeyDetector;

impl Detector for ConvexDeploymentKeyDetector {
    fn id(&self) -> &'static str {
        "convex-deployment-key"
    }

    fn detect(
        &self,
        input: &str,
        _context: &DetectorContext,
    ) -> Result<Vec<Candidate>, DetectorFailure> {
        let bytes = input.as_bytes();
        let mut candidates = Vec::new();
        let mut cursor = 0;
        while let Some(offset) = input[cursor..].find('|') {
            let separator = cursor + offset;
            cursor = separator + 1;
            let Some((start, end, typed)) = match_at(bytes, separator) else {
                continue;
            };
            if let Some(range) = ByteRange::new(start, end) {
                let mut signals = vec![SEPARATOR_SIGNAL, BODY_SIGNAL];
                if typed {
                    signals.push(TYPED_SIGNAL);
                }
                candidates.push(
                    Candidate::new(TYPE_NAME, Confidence::High, range)
                        .with_specificity(Specificity::Provider)
                        .with_signals(signals),
                );
            }
            cursor = end;
        }
        Ok(candidates)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Synthetic lowercase hex, never provider-issued: `01` plus a seeded
    /// walk, `len` bytes in total.
    fn body(len: usize, seed: usize) -> String {
        let tail: String = (0..len - 2)
            .map(|i| char::from(b"0123456789abcdef"[(i * 7 + seed * 11 + i / 3) % 16]))
            .collect();
        format!("01{tail}")
    }

    fn detect(input: &str) -> Vec<Candidate> {
        ConvexDeploymentKeyDetector
            .detect(input, &DetectorContext::new(input.len()))
            .unwrap()
    }

    fn assert_single(input: &str, key: &str, typed: bool) {
        let candidates = detect(input);
        assert_eq!(candidates.len(), 1, "{input}");
        let start = input.find(key).unwrap();
        assert_eq!(candidates[0].type_name(), TYPE_NAME);
        assert_eq!(candidates[0].confidence(), Confidence::High);
        assert_eq!(candidates[0].effective_specificity(), Specificity::Provider);
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(start, start + key.len()).unwrap(),
            "{input}"
        );
        assert_eq!(
            candidates[0].signals().iter().any(|s| s == TYPED_SIGNAL),
            typed,
            "{input}"
        );
    }

    fn keys() -> Vec<(String, bool)> {
        vec![
            (format!("convex-self-hosted|{}", body(74, 1)), false),
            (format!("happy-otter-123|{}", body(76, 2)), false),
            (format!("prod:happy-otter-123|{}", body(96, 3)), true),
            (format!("dev:brave-lynx-7|{}", body(80, 4)), true),
            (format!("preview:acme-team:web-app|{}", body(74, 5)), true),
            (format!("project:acme:api|{}", body(90, 6)), true),
        ]
    }

    fn contexts(key: &str) -> Vec<String> {
        vec![
            key.to_owned(),
            format!("CONVEX_DEPLOY_KEY={key}"),
            format!("export CONVEX_SELF_HOSTED_ADMIN_KEY=\"{key}\""),
            format!("Authorization: Bearer {key}"),
            format!("Authorization: Convex {key}"),
            format!("X-API-Key: {key}"),
            format!("{{\"token\": \"{key}\"}}"),
            format!("{{\"api_key\": \"{key}\"}}"),
            format!("client = Client(api_key=\"{key}\")"),
            format!("Here is my key {key} can you debug this?"),
            format!("environment:\n  CONVEX_SELF_HOSTED_ADMIN_KEY: {key}\n"),
            format!("The key is {key}."),
            format!("curl -H 'Authorization: Convex {key}' https://example.invalid"),
        ]
    }

    #[test]
    fn every_shape_is_detected_whole_in_every_context() {
        for (key, typed) in keys() {
            for input in contexts(&key) {
                assert_single(&input, &key, typed);
            }
        }
    }

    #[test]
    fn body_width_parity_and_lead_twins_are_rejected() {
        for body in [
            body(72, 1),
            body(98, 1),
            body(75, 1),
            body(97, 1),
            format!("02{}", &body(76, 1)[2..]),
        ] {
            let input = format!("convex-self-hosted|{body}");
            assert!(detect(&input).is_empty(), "{input}");
        }
    }

    #[test]
    fn alphabet_twins_are_rejected() {
        for byte in ["A", "g"] {
            let mut value = body(76, 2);
            value.replace_range(40..41, byte);
            let input = format!("prod:happy-otter-123|{value}");
            assert!(detect(&input).is_empty(), "{input}");
        }
    }

    #[test]
    fn separator_and_lead_twins_are_rejected() {
        let value = body(76, 3);
        for input in [
            format!("convex-self-hosted||{value}"),
            format!("prod:bold_hyena_681|{value}"),
            format!("bold_hyena_681|{value}"),
            format!("xprod:happy-otter-123|{value}"),
            format!("_prod:happy-otter-123|{value}"),
            format!("prod:convex-self-hosted|{value}"),
            format!("preview:acme_team:web|{value}"),
            format!("staging:acme:web|{value}"),
            format!("Convex-Self-Hosted|{value}"),
            format!("convex-self-hosted|{value}x"),
            format!("convex-self-hosted|{value}-1"),
            format!("{}|{value}", "a".repeat(NAME_MAX + 1)),
            format!("-leading-dash|{value}"),
        ] {
            assert!(detect(&input).is_empty(), "{input}");
        }
    }

    #[test]
    fn a_non_type_separator_leaves_an_untyped_key() {
        let value = body(76, 4);
        let key = format!("happy-otter-123|{value}");
        assert_single(&format!("prod;{key}"), &key, false);
        let key = format!("{}|{value}", "a".repeat(NAME_MAX));
        assert_single(&key, &key, false);
    }

    #[test]
    fn benign_convex_text_is_not_claimed() {
        let digest: String = (0..74)
            .map(|i| char::from(b"0123456789abcdef"[(i * 5 + 3) % 16]))
            .collect();
        for input in [
            "CONVEX_DEPLOYMENT=dev:happy-otter-123".to_owned(),
            "CONVEX_DEPLOYMENT=prod:happy-otter-123".to_owned(),
            "CONVEX_URL=https://happy-otter-123.convex.cloud".to_owned(),
            "CONVEX_DEPLOY_KEY=prod:your-deployment-name|your-admin-key".to_owned(),
            "prod:adjective-animal-123|super-secret-key".to_owned(),
            "prod:happy-otter-123|${CONVEX_BODY}".to_owned(),
            format!("| {} | value |", body(76, 5)),
            format!("sha|{digest}"),
            "prod:happy-otter-123|eyJ2SyntheticGatedCloudBodyNotClaimedYet0=".to_owned(),
        ] {
            assert!(detect(&input).is_empty(), "{input}");
        }
    }

    #[test]
    fn repeated_keys_are_reported_once_each_and_long_runs_stay_linear() {
        let key = format!("convex-self-hosted|{}", body(76, 6));
        assert_eq!(detect(&format!("{key} {key}")).len(), 2);
        assert!(detect(&key.repeat(200)).is_empty());
        assert!(detect(&"|01".repeat(50_000)).is_empty());
        assert!(detect(&format!("{}|{}", "a-".repeat(50_000), body(76, 6))).is_empty());
    }
}
