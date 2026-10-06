//! Bitwarden Secrets Manager access token detection (issue #1019, handoff
//! [`docs/audits/evidence/1014/bitwarden.md`](https://github.com/redact-secret/redact-secret/blob/2816897f96c405c3eb8c87a0c70eba5df273c121/docs/audits/evidence/1014/bitwarden.md)).
//!
//! A machine-account access token carries both the client secret and the
//! symmetric key that decrypts the account's secrets. Every fact is T1 under
//! ruling R1, re-checked 2026-09-29: the `bitwarden/sdk-internal` parser
//! (`access_token.rs`, version `"0"`, a UUID id, a key that decodes to 16
//! bytes), the server generator (`CreateAccessTokenCommand`, a 30-byte
//! `SecureRandomString` whose default alphabet is `[A-Za-z0-9]`), and the
//! docs example, which has the same segment lengths.
//!
//! | Part | Grammar |
//! | --- | --- |
//! | Version | literal `0` |
//! | Token id | `.` + UUID, 8-4-4-4-12 hex (either case) |
//! | Client secret | `.` + exactly 30 `[A-Za-z0-9]` |
//! | Encryption key | `:` + 22 `[A-Za-z0-9+/]` + `==` (16 bytes, padded) |
//!
//! The token is 94 bytes. The literal lead `0.` is far too common to index,
//! so the scan anchors on the closing `==` and checks the fixed layout that
//! ends there: O(1) per `==`, linear overall.
//!
//! ## Boundaries
//!
//! The byte before `0` must not be `[A-Za-z0-9._-]`, so `10.<uuid>…` and
//! `v0.<uuid>…` are not claimed. The byte after `==` must not be
//! `[A-Za-z0-9+/=]`. An unpadded key (the parser accepts it, the generator
//! never emits it), a version other than `0`, and a token missing its
//! `:<key>` half are intentional false negatives. Password Manager
//! `user.`/`organization.` API key client ids are a different credential
//! with no token grammar and stay with generic context.

use crate::detectors::prefilter::Literals;
use crate::error::DetectorFailure;
use crate::types::{ByteRange, Candidate, Confidence, Detector, DetectorContext, Specificity};

const VERSION: &[u8] = b"0.";
const UUID_LEN: usize = 36;
const UUID_DASHES: [usize; 4] = [8, 13, 18, 23];
const CLIENT_SECRET_LEN: usize = 30;
const KEY_BODY_LEN: usize = 22;
const PADDING: &str = "==";
/// `0.` + UUID + `.` + secret + `:` + key body + `==`.
const TOKEN_LEN: usize =
    VERSION.len() + UUID_LEN + 1 + CLIENT_SECRET_LEN + 1 + KEY_BODY_LEN + PADDING.len();
const SIGNALS: [&str; 2] = ["bitwarden-parser-layout", "bitwarden-generator-length"];

/// `[A-Za-z0-9._-]`: bytes that make the `0.` lead part of a wider token.
fn is_leading_glue(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')
}

/// `[A-Za-z0-9+/=]`: bytes that make the padded key part of a wider run.
fn is_trailing_glue(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'=')
}

fn is_uuid(bytes: &[u8]) -> bool {
    bytes.len() == UUID_LEN
        && bytes.iter().enumerate().all(|(index, &byte)| {
            if UUID_DASHES.contains(&index) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        })
}

/// Whether `token` (exactly [`TOKEN_LEN`] bytes) has the access-token layout.
fn has_layout(token: &[u8]) -> bool {
    let Some(rest) = token.strip_prefix(VERSION) else {
        return false;
    };
    let (uuid, rest) = rest.split_at(UUID_LEN);
    let Some((&b'.', rest)) = rest.split_first() else {
        return false;
    };
    let (secret, rest) = rest.split_at(CLIENT_SECRET_LEN);
    let Some((&b':', rest)) = rest.split_first() else {
        return false;
    };
    let (key, padding) = rest.split_at(KEY_BODY_LEN);
    is_uuid(uuid)
        && secret.iter().all(u8::is_ascii_alphanumeric)
        && key
            .iter()
            .all(|&byte| byte.is_ascii_alphanumeric() || byte == b'+' || byte == b'/')
        && padding == PADDING.as_bytes()
}

/// Start of a token whose padding begins at `padding_start`, or `None`.
fn match_ending_at(bytes: &[u8], padding_start: usize) -> Option<usize> {
    let end = padding_start + PADDING.len();
    let start = end.checked_sub(TOKEN_LEN)?;
    if start > 0 && is_leading_glue(bytes[start - 1]) {
        return None;
    }
    if bytes.get(end).is_some_and(|&next| is_trailing_glue(next)) {
        return None;
    }
    has_layout(&bytes[start..end]).then_some(start)
}

/// Recognizes Bitwarden Secrets Manager machine-account access tokens.
pub(super) struct BitwardenSecretsManagerAccessTokenDetector;

impl Detector for BitwardenSecretsManagerAccessTokenDetector {
    fn id(&self) -> &'static str {
        "bitwarden-secrets-manager-access-token"
    }

    fn detect(
        &self,
        input: &str,
        _context: &DetectorContext,
    ) -> Result<Vec<Candidate>, DetectorFailure> {
        let bytes = input.as_bytes();
        let mut candidates = Vec::new();
        let mut cursor = 0;
        while let Some(offset) = input[cursor..].find(PADDING) {
            let padding_start = cursor + offset;
            let Some(start) = match_ending_at(bytes, padding_start) else {
                cursor = padding_start + 1;
                continue;
            };
            let end = padding_start + PADDING.len();
            if let Some(range) = ByteRange::new(start, end) {
                candidates.push(
                    Candidate::built_in(
                        "bitwarden_secrets_manager_access_token",
                        Confidence::High,
                        range,
                    )
                    .with_specificity(Specificity::Provider)
                    .with_signals(SIGNALS),
                );
            }
            cursor = end;
        }
        Ok(candidates)
    }
}

/// The literal every candidate contains, for the shared prefilter
/// (`super::prefilter`, issue #983): the key's `==` padding, which is rarer
/// in prose than the `0.` lead.
pub(super) const REQUIRED_LITERALS: &[Literals] = &[Literals::Strs(&[PADDING])];

#[cfg(test)]
mod tests {
    use super::*;

    const ALNUM: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    const BASE64: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    /// Synthetic filler, never provider-issued.
    fn filler(alphabet: &[u8], len: usize, seed: usize) -> String {
        (0..len)
            .map(|i| char::from(alphabet[(i * 7 + seed * 13 + i / 5) % alphabet.len()]))
            .collect()
    }

    fn uuid() -> String {
        "5e7c0ded-0000-4000-8000-5e7c0ded0000".to_owned()
    }

    fn token_from(uuid: &str, secret: &str, key: &str) -> String {
        format!("0.{uuid}.{secret}:{key}")
    }

    fn token() -> String {
        token_from(
            &uuid(),
            &filler(ALNUM, CLIENT_SECRET_LEN, 1),
            &format!("{}==", filler(BASE64, KEY_BODY_LEN, 2)),
        )
    }

    fn detect(input: &str) -> Vec<Candidate> {
        BitwardenSecretsManagerAccessTokenDetector
            .detect(input, &DetectorContext::new(input.len()))
            .unwrap()
    }

    fn assert_single(input: &str, token: &str) {
        let candidates = detect(input);
        assert_eq!(candidates.len(), 1, "{input}");
        let start = input.find(token).unwrap();
        assert_eq!(
            candidates[0].type_name(),
            "bitwarden_secrets_manager_access_token"
        );
        assert_eq!(candidates[0].confidence(), Confidence::High);
        assert_eq!(candidates[0].effective_specificity(), Specificity::Provider);
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(start, start + token.len()).unwrap(),
            "{input}"
        );
    }

    #[test]
    fn the_parser_layout_is_detected_in_every_context() {
        let token = token();
        assert_eq!(token.len(), TOKEN_LEN);
        assert_eq!(TOKEN_LEN, 94);
        for input in [
            token.clone(),
            format!("BWS_ACCESS_TOKEN={token}"),
            format!("export BWS_ACCESS_TOKEN=\"{token}\""),
            format!("bws secret list --access-token {token}"),
            format!("{{\"token\": \"{token}\"}}"),
            format!("Here is my token {token} can you debug this?"),
            format!("The token is {token}."),
            format!("with:\n  access_token: {token}\n"),
        ] {
            assert_single(&input, &token);
        }
        let upper = token_from(
            &uuid().to_uppercase(),
            &filler(ALNUM, CLIENT_SECRET_LEN, 1),
            &format!("{}==", filler(BASE64, KEY_BODY_LEN, 2)),
        );
        assert_single(&upper, &upper);
    }

    #[test]
    fn near_miss_twins_are_rejected() {
        let uuid = uuid();
        let secret = filler(ALNUM, CLIENT_SECRET_LEN, 1);
        let key_body = filler(BASE64, KEY_BODY_LEN, 2);
        let key = format!("{key_body}==");
        let token = token();
        let mut dashed = secret.clone();
        dashed.replace_range(5..6, "-");
        let mut underscored = secret.clone();
        underscored.replace_range(5..6, "_");
        let mut bad_uuid = uuid.clone();
        bad_uuid.replace_range(0..1, "g");
        for input in [
            token_from(&uuid, &filler(ALNUM, 29, 1), &key),
            token_from(&uuid, &filler(ALNUM, 31, 1), &key),
            token_from(&uuid, &dashed, &key),
            token_from(&uuid, &underscored, &key),
            token_from(&uuid, &secret, &format!("{}==", filler(BASE64, 21, 2))),
            token_from(&uuid, &secret, &format!("{}==", filler(BASE64, 23, 2))),
            token_from(&uuid, &secret, &format!("{key_body}=")),
            token_from(&uuid, &secret, &key_body),
            token_from(&uuid.replace('-', ""), &secret, &key),
            token_from(&bad_uuid, &secret, &key),
            format!("1.{uuid}.{secret}:{key}"),
            format!("0.{uuid}.{secret}.{key}"),
            format!("1{token}"),
            format!("v{token}"),
            format!("x{token}"),
            format!(".{token}"),
            format!("{token}="),
            format!("{token}A"),
            format!("{token}/"),
        ] {
            assert!(detect(&input).is_empty(), "{input}");
        }
    }

    #[test]
    fn benign_text_is_not_claimed() {
        let uuid = uuid();
        for input in [
            format!("Released 0.{uuid} today"),
            format!("0.{uuid}.json"),
            format!("client_id: user.{uuid}"),
            "BWS_ACCESS_TOKEN=${BWS_ACCESS_TOKEN}".to_owned(),
            "if a == b { return 0.5 }".to_owned(),
        ] {
            assert!(detect(&input).is_empty(), "{input}");
        }
    }

    #[test]
    fn repeated_tokens_are_reported_once_each_and_a_padding_run_stays_linear() {
        let token = token();
        assert_eq!(detect(&format!("{token} {token}")).len(), 2);
        assert!(detect(&"=".repeat(50_000)).is_empty());
        // Glued copies continue into the next token's `0`, so only the last
        // copy, which ends the input, keeps its trailing boundary.
        assert_eq!(detect(&token.repeat(50)).len(), 1);
    }
}
